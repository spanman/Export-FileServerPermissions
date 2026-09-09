<#
Converts one ADSI SearchResult (from Get-FsAdObjectsBySid / Get-FsAdObjectsByDn) into a New-FsPrincipal object.

Property access always goes through Get-FsAdSearchResultValue / Get-FsAdSearchResultList (Ad.Searcher.ps1), which
already normalizes byte[] SIDs to SID strings, IADsLargeInteger COM wrappers to [long], and datetimes to UTC.
Because that helper explicitly supports a plain IDictionary as -Result (in addition to a real SearchResult), a
hashtable shaped like { objectSid = '...'; objectClass = @('user'); sAMAccountName = '...' ; ... } is enough to
exercise this function on Linux without ever touching System.DirectoryServices.
#>

function ConvertFrom-FsAdResult {
    <#
    .SYNOPSIS
        Builds a New-FsPrincipal record (User, Computer, Group or Foreign) from one AD search result.
    .PARAMETER Result
        One value from the `Found` dictionary returned by Get-FsAdObjectsBySid / Get-FsAdObjectsByDn.
    .PARAMETER Context
        Scan context (used for DomainSids, DomainTable and stamping FetchedAt / SourceScanId).
    #>
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)] $Result,
        [Parameter(Mandatory)] [hashtable] $Context
    )

    $sid = [string](Get-FsAdSearchResultValue -Result $Result -Name 'objectSid')
    $dn = [string](Get-FsAdSearchResultValue -Result $Result -Name 'distinguishedName')
    $sam = [string](Get-FsAdSearchResultValue -Result $Result -Name 'sAMAccountName')
    $name = $sam
    if (-not $name) { $name = [string](Get-FsAdSearchResultValue -Result $Result -Name 'name') }
    if (-not $name) { $name = [string](Get-FsAdSearchResultValue -Result $Result -Name 'cn') }
    $displayName = [string](Get-FsAdSearchResultValue -Result $Result -Name 'displayName')

    $classes = @(Get-FsAdSearchResultList -Result $Result -Name 'objectClass' | ForEach-Object { [string]$_ })
    $kind = 'User'
    if ($classes -contains 'computer') { $kind = 'Computer' }
    elseif ($classes -contains 'group') { $kind = 'Group' }
    elseif ($classes -contains 'foreignSecurityPrincipal') { $kind = 'Foreign' }
    elseif ($classes -contains 'user') { $kind = 'User' }

    $domainSids = @($Context.DomainSids)
    $domain = Get-FsAdConvertDomain -Context $Context -Sid $sid
    $wellKnownName = Get-FsWellKnownName -Sid $sid -DomainSids $domainSids
    $isWellKnown = [bool]$wellKnownName
    $isBroad = Test-FsBroadSid -Sid $sid -DomainSids $domainSids

    $ad = $null
    $membershipResolved = $null
    if ($kind -eq 'Group') {
        $groupTypeRaw = Get-FsAdSearchResultValue -Result $Result -Name 'groupType'
        $gt = ConvertFrom-FsGroupType -GroupType $groupTypeRaw
        $managedByDn = [string](Get-FsAdSearchResultValue -Result $Result -Name 'managedBy')
        $ad = [ordered]@{
            description       = [string](Get-FsAdSearchResultValue -Result $Result -Name 'description')
            groupType         = $(if ($null -ne $groupTypeRaw) { [int]$groupTypeRaw } else { $null })
            groupCategory     = $gt.Category
            groupScope        = $gt.Scope
            mail              = [string](Get-FsAdSearchResultValue -Result $Result -Name 'mail')
            whenCreated       = Get-FsAdConvertIsoDate -Value (Get-FsAdSearchResultValue -Result $Result -Name 'whenCreated')
            managedBy         = $(if ($managedByDn) { @{ dn = $managedByDn; sam = $null; sid = $null } } else { $null })
            distinguishedName = $dn
        }
        $membershipResolved = $false
    }
    elseif ($kind -eq 'User' -or $kind -eq 'Computer') {
        $uac = Get-FsAdSearchResultValue -Result $Result -Name 'userAccountControl'
        $managerDn = [string](Get-FsAdSearchResultValue -Result $Result -Name 'manager')
        $pgidRaw = Get-FsAdSearchResultValue -Result $Result -Name 'primaryGroupID'
        $ad = [ordered]@{
            userPrincipalName  = [string](Get-FsAdSearchResultValue -Result $Result -Name 'userPrincipalName')
            mail               = [string](Get-FsAdSearchResultValue -Result $Result -Name 'mail')
            enabled            = -not (Test-FsUacDisabled $uac)
            userAccountControl = $(if ($null -ne $uac) { [int]$uac } else { $null })
            lastLogonTimestamp = ConvertFrom-FsFileTime -Value (Get-FsAdSearchResultValue -Result $Result -Name 'lastLogonTimestamp')
            pwdLastSet         = ConvertFrom-FsFileTime -Value (Get-FsAdSearchResultValue -Result $Result -Name 'pwdLastSet')
            accountExpires     = ConvertFrom-FsFileTime -Value (Get-FsAdSearchResultValue -Result $Result -Name 'accountExpires')
            department         = [string](Get-FsAdSearchResultValue -Result $Result -Name 'department')
            title              = [string](Get-FsAdSearchResultValue -Result $Result -Name 'title')
            description        = [string](Get-FsAdSearchResultValue -Result $Result -Name 'description')
            manager            = $(if ($managerDn) { @{ dn = $managerDn; sam = $null; sid = $null } } else { $null })
            whenCreated        = Get-FsAdConvertIsoDate -Value (Get-FsAdSearchResultValue -Result $Result -Name 'whenCreated')
            distinguishedName  = $dn
            primaryGroupId     = $(if ($null -ne $pgidRaw) { [int]$pgidRaw } else { $null })
        }
    }
    # Foreign (foreignSecurityPrincipal stub objects) carry no normal attributes; $ad stays $null.

    $resolution = if ($kind -eq 'Foreign') { 'Foreign' } else { 'Resolved' }

    return New-FsPrincipal -Id $sid -Kind $kind -Sid $sid -Domain $domain -Name $name -DisplayName $displayName `
        -Resolution $resolution -IsWellKnown $isWellKnown -IsBroad $isBroad -Ad $ad -MembershipResolved $membershipResolved `
        -FetchedAt (Get-FsContextNow) -SourceScanId $Context.Snapshot.scanId
}

function Get-FsAdConvertDomain {
    <# NetBIOS name of the domain owning a SID's S-1-5-21 prefix, per the context's domain table; $null when unknown. #>
    [OutputType([string])]
    param([Parameter(Mandatory)] [hashtable] $Context, [AllowNull()] [string] $Sid)
    if (-not $Sid -or -not $Context.DomainTable) { return $null }
    $prefix = Get-FsSidPrefix -Sid $Sid
    if ($prefix -and $Context.DomainTable.Domains.Contains($prefix)) { return [string]$Context.DomainTable.Domains[$prefix].netbios }
    return $null
}

function Get-FsAdConvertIsoDate {
    <# Normalizes a whenCreated-shaped value ([datetime], ISO string, or $null) to an ISO-8601 UTC string. #>
    [OutputType([string])]
    param([AllowNull()] $Value)
    if ($null -eq $Value) { return $null }
    if ($Value -is [datetime]) { return $Value.ToString('o') }
    return [string]$Value
}
