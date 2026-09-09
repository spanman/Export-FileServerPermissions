<#
Principal identity, classification and well-known SID tables.

Stable principal id scheme:
  - Domain, well-known and orphaned principals:  the SID string
  - Server-local groups/users (incl. BUILTIN\*):  "SERVER\Name"  (BUILTIN SIDs are identical on every
                                                  machine but membership is per-machine)
Kinds: User | Group | Computer | LocalGroup | LocalUser | WellKnown | Foreign | OrphanedSid
#>

$script:FsWellKnownSids = @{
    'S-1-0-0'      = 'Nobody'
    'S-1-1-0'      = 'Everyone'
    'S-1-2-0'      = 'LOCAL'
    'S-1-2-1'      = 'CONSOLE LOGON'
    'S-1-3-0'      = 'CREATOR OWNER'
    'S-1-3-1'      = 'CREATOR GROUP'
    'S-1-3-4'      = 'OWNER RIGHTS'
    'S-1-5-1'      = 'DIALUP'
    'S-1-5-2'      = 'NETWORK'
    'S-1-5-3'      = 'BATCH'
    'S-1-5-4'      = 'INTERACTIVE'
    'S-1-5-6'      = 'SERVICE'
    'S-1-5-7'      = 'ANONYMOUS LOGON'
    'S-1-5-9'      = 'ENTERPRISE DOMAIN CONTROLLERS'
    'S-1-5-10'     = 'SELF'
    'S-1-5-11'     = 'Authenticated Users'
    'S-1-5-12'     = 'RESTRICTED'
    'S-1-5-13'     = 'TERMINAL SERVER USER'
    'S-1-5-14'     = 'REMOTE INTERACTIVE LOGON'
    'S-1-5-15'     = 'This Organization'
    'S-1-5-17'     = 'IUSR'
    'S-1-5-18'     = 'SYSTEM'
    'S-1-5-19'     = 'LOCAL SERVICE'
    'S-1-5-20'     = 'NETWORK SERVICE'
    'S-1-5-32-544' = 'Administrators'
    'S-1-5-32-545' = 'Users'
    'S-1-5-32-546' = 'Guests'
    'S-1-5-32-547' = 'Power Users'
    'S-1-5-32-548' = 'Account Operators'
    'S-1-5-32-549' = 'Server Operators'
    'S-1-5-32-550' = 'Print Operators'
    'S-1-5-32-551' = 'Backup Operators'
    'S-1-5-32-552' = 'Replicator'
    'S-1-5-32-554' = 'Pre-Windows 2000 Compatible Access'
    'S-1-5-32-555' = 'Remote Desktop Users'
    'S-1-5-32-556' = 'Network Configuration Operators'
    'S-1-5-32-558' = 'Performance Monitor Users'
    'S-1-5-32-559' = 'Performance Log Users'
    'S-1-5-32-562' = 'Distributed COM Users'
    'S-1-5-32-568' = 'IIS_IUSRS'
    'S-1-5-32-569' = 'Cryptographic Operators'
    'S-1-5-32-573' = 'Event Log Readers'
    'S-1-5-32-574' = 'Certificate Service DCOM Access'
    'S-1-5-32-578' = 'Hyper-V Administrators'
    'S-1-5-32-580' = 'Remote Management Users'
    'S-1-5-32-583' = 'Device Owners'
    'S-1-5-80-0'   = 'ALL SERVICES'
    'S-1-15-2-1'   = 'ALL APPLICATION PACKAGES'
    'S-1-15-2-2'   = 'ALL RESTRICTED APPLICATION PACKAGES'
}

# Domain-relative RIDs (the domain SID must be known to recognize these)
$script:FsDomainRids = @{
    500 = 'Administrator'; 501 = 'Guest'; 502 = 'krbtgt'
    512 = 'Domain Admins'; 513 = 'Domain Users'; 514 = 'Domain Guests'; 515 = 'Domain Computers'
    516 = 'Domain Controllers'; 517 = 'Cert Publishers'; 518 = 'Schema Admins'; 519 = 'Enterprise Admins'
    520 = 'Group Policy Creator Owners'; 521 = 'Read-only Domain Controllers'; 522 = 'Cloneable Domain Controllers'
    525 = 'Protected Users'; 526 = 'Key Admins'; 527 = 'Enterprise Key Admins'
    553 = 'RAS and IAS Servers'; 571 = 'Allowed RODC Password Replication Group'; 572 = 'Denied RODC Password Replication Group'
}

# "Broad" = grants to these mean effectively any (authenticated) account
$script:FsBroadSids = @('S-1-1-0', 'S-1-5-11', 'S-1-5-2', 'S-1-5-4', 'S-1-5-7', 'S-1-5-32-545', 'S-1-5-32-546', 'S-1-5-14')
$script:FsBroadRids = @(513, 514, 515)

# Default admin allowlist (excluded from over-permission reports)
$script:FsAdminSids = @('S-1-5-32-544', 'S-1-5-18', 'S-1-3-0', 'S-1-5-32-551', 'S-1-5-32-549')
$script:FsAdminRids = @(500, 512, 518, 519)

function Get-FsSidClass {
    <#
    .SYNOPSIS
        Classifies a SID string: WellKnown | Builtin | DomainAccount | MachineAccount | Capability | Service | Unknown
    .PARAMETER DomainSids
        Known domain SIDs (S-1-5-21-...). A S-1-5-21 SID whose prefix matches is DomainAccount; when MachineSid
        matches it is MachineAccount; otherwise it is still DomainAccount (unknown domain).
    #>
    [OutputType([string])]
    param(
        [Parameter(Mandatory)] [string] $Sid,
        [string[]] $DomainSids = @(),
        [string] $MachineSid
    )
    if ($script:FsWellKnownSids.ContainsKey($Sid)) { return $(if ($Sid -like 'S-1-5-32-*') { 'Builtin' } else { 'WellKnown' }) }
    if ($Sid -like 'S-1-5-32-*') { return 'Builtin' }
    if ($Sid -like 'S-1-15-*') { return 'Capability' }
    if ($Sid -like 'S-1-5-80-*' -or $Sid -like 'S-1-5-82-*' -or $Sid -like 'S-1-5-83-*' -or $Sid -like 'S-1-5-90-*' -or $Sid -like 'S-1-5-96-*') { return 'Service' }
    if ($Sid -like 'S-1-5-21-*') {
        $prefix = Get-FsSidPrefix $Sid
        if ($MachineSid -and $prefix -eq $MachineSid) { return 'MachineAccount' }
        return 'DomainAccount'
    }
    if ($Sid -match '^S-1-5-\d+$' -or $Sid -match '^S-1-[0-3]-\d+$') { return 'WellKnown' }
    return 'Unknown'
}

function Get-FsSidPrefix {
    <# S-1-5-21-a-b-c-rid -> S-1-5-21-a-b-c ; returns $null for non-account SIDs #>
    [OutputType([string])]
    param([Parameter(Mandatory)] [string] $Sid)
    $m = [regex]::Match($Sid, '^(S-1-5-21-\d+-\d+-\d+)-(\d+)$')
    if ($m.Success) { return $m.Groups[1].Value }
    return $null
}

function Get-FsSidRid {
    [OutputType([System.Nullable[int]])]
    param([Parameter(Mandatory)] [string] $Sid)
    $m = [regex]::Match($Sid, '^S-1-5-21-\d+-\d+-\d+-(\d+)$')
    if ($m.Success) { return [int]$m.Groups[1].Value }
    return $null
}

function Get-FsWellKnownName {
    <# Display name for a well-known SID or domain-relative RID, else $null. #>
    [OutputType([string])]
    param([Parameter(Mandatory)] [string] $Sid, [string[]] $DomainSids = @())
    if ($script:FsWellKnownSids.ContainsKey($Sid)) { return $script:FsWellKnownSids[$Sid] }
    $rid = Get-FsSidRid $Sid
    if ($null -ne $rid -and $script:FsDomainRids.ContainsKey($rid)) {
        $prefix = Get-FsSidPrefix $Sid
        if ($DomainSids.Count -eq 0 -or $DomainSids -contains $prefix) { return $script:FsDomainRids[$rid] }
    }
    return $null
}

function Test-FsBroadSid {
    <# True for Everyone, Authenticated Users, NETWORK, INTERACTIVE, BUILTIN\Users/Guests, Domain Users/Guests/Computers. #>
    [OutputType([bool])]
    param([Parameter(Mandatory)] [string] $Sid, [string[]] $DomainSids = @())
    if ($script:FsBroadSids -contains $Sid) { return $true }
    $rid = Get-FsSidRid $Sid
    if ($null -ne $rid -and $script:FsBroadRids -contains $rid) {
        $prefix = Get-FsSidPrefix $Sid
        return ($DomainSids.Count -eq 0 -or $DomainSids -contains $prefix)
    }
    return $false
}

function Test-FsAdminSid {
    <# Default admin allowlist membership. #>
    [OutputType([bool])]
    param([Parameter(Mandatory)] [string] $Sid, [string[]] $DomainSids = @())
    if ($script:FsAdminSids -contains $Sid) { return $true }
    $rid = Get-FsSidRid $Sid
    if ($null -ne $rid -and $script:FsAdminRids -contains $rid) {
        $prefix = Get-FsSidPrefix $Sid
        return ($DomainSids.Count -eq 0 -or $DomainSids -contains $prefix)
    }
    return $false
}

function Get-FsPrincipalId {
    <#
    .SYNOPSIS
        Builds the stable principal id: "SERVER\Name" for server-local accounts, otherwise the SID.
    #>
    [OutputType([string])]
    param(
        [Parameter(Mandatory)] [string] $Sid,
        [bool] $IsLocal = $false,
        [string] $Server,
        [string] $Name
    )
    if ($IsLocal) {
        if (-not $Server) { throw 'Get-FsPrincipalId: -Server is required for local principals.' }
        $n = if ($Name) { $Name } elseif ($script:FsWellKnownSids.ContainsKey($Sid)) { $script:FsWellKnownSids[$Sid] } else { $Sid }
        return "$($Server.ToUpperInvariant())\$n"
    }
    return $Sid
}

function Test-FsLocalPrincipalId {
    [OutputType([bool])]
    param([Parameter(Mandatory)] [string] $Id)
    return ($Id -notmatch '^S-1-' -and $Id -match '^[^\\]+\\.+$')
}

function New-FsPrincipal {
    <#
    .SYNOPSIS
        Factory for a principal record (PSCustomObject, PSTypeName Fs.Principal).
    #>
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)] [string] $Id,
        [Parameter(Mandatory)] [ValidateSet('User', 'Group', 'Computer', 'LocalGroup', 'LocalUser', 'WellKnown', 'Foreign', 'OrphanedSid')] [string] $Kind,
        [AllowNull()] [string] $Sid,
        [AllowNull()] [string] $Domain,
        [AllowNull()] [string] $Name,
        [AllowNull()] [string] $DisplayName,
        [AllowNull()] [string] $Server,
        [ValidateSet('Resolved', 'Orphaned', 'LookupFailed', 'Foreign', 'WellKnown', 'Local')] [string] $Resolution = 'Resolved',
        [AllowNull()] [string] $ResolutionError,
        [bool] $IsWellKnown = $false,
        [bool] $IsBroad = $false,
        [AllowNull()] [hashtable] $Ad,
        [AllowNull()] [hashtable] $Local,
        [System.Nullable[int]] $MemberCount,
        [System.Nullable[bool]] $MembershipResolved,
        [AllowNull()] [string] $MembershipNote,
        [AllowNull()] [string] $FetchedAt,
        [AllowNull()] [string] $SourceScanId
    )
    $ntAccount = if ($Domain -and $Name) { "$Domain\$Name" } elseif ($Name) { $Name } else { $null }
    $p = [ordered]@{
        PSTypeName         = 'Fs.Principal'
        id                 = $Id
        kind               = $Kind
        sid                = $Sid
        domain             = $Domain
        name               = $Name
        ntAccount          = $ntAccount
        displayName        = $(if ($DisplayName) { $DisplayName } else { $Name })
        server             = $Server
        isWellKnown        = $IsWellKnown
        isBroad            = $IsBroad
        resolution         = $Resolution
        resolutionError    = $ResolutionError
        memberCount        = $MemberCount
        membershipResolved = $MembershipResolved
        membershipNote     = $MembershipNote
        fetchedAt          = $(if ($FetchedAt) { $FetchedAt } else { (Get-Date).ToUniversalTime().ToString('o') })
        sourceScanId       = $SourceScanId
        ad                 = $Ad
        local              = $Local
    }
    return [pscustomobject]$p
}

function Get-FsPrincipalKindLabel {
    <# Short lowercase label for tables/tags. #>
    [OutputType([string])]
    param([Parameter(Mandatory)] [string] $Kind)
    switch ($Kind) {
        'User' { 'user' }
        'Group' { 'group' }
        'Computer' { 'computer' }
        'LocalGroup' { 'local-group' }
        'LocalUser' { 'local-user' }
        'WellKnown' { 'well-known' }
        'Foreign' { 'foreign' }
        'OrphanedSid' { 'orphaned' }
        default { $Kind.ToLowerInvariant() }
    }
}

function Test-FsGroupKind {
    [OutputType([bool])]
    param([Parameter(Mandatory)] [string] $Kind)
    return ($Kind -in 'Group', 'LocalGroup', 'WellKnown')
}

function Test-FsUserKind {
    [OutputType([bool])]
    param([Parameter(Mandatory)] [string] $Kind)
    return ($Kind -in 'User', 'LocalUser', 'Computer')
}

function ConvertFrom-FsFileTime {
    <# Int64 FILETIME -> ISO-8601 UTC string; 0 and MaxValue -> $null ("never"). #>
    [OutputType([string])]
    param([AllowNull()] $Value)
    if ($null -eq $Value) { return $null }
    $v = [long]$Value
    if ($v -le 0 -or $v -ge 0x7FFFFFFFFFFFFFFF) { return $null }
    try { return [DateTime]::FromFileTimeUtc($v).ToString('o') } catch { return $null }
}

function Test-FsUacDisabled {
    [OutputType([bool])]
    param([AllowNull()] $UserAccountControl)
    if ($null -eq $UserAccountControl) { return $false }
    return (([int]$UserAccountControl -band 0x2) -ne 0)
}

function ConvertFrom-FsGroupType {
    <# groupType int -> @{ Category = Security|Distribution; Scope = Global|DomainLocal|Universal|BuiltinLocal } #>
    [OutputType([hashtable])]
    param([AllowNull()] $GroupType)
    if ($null -eq $GroupType) { return @{ Category = $null; Scope = $null } }
    $gt = [long]$GroupType
    $u = [uint32]($gt -band $script:FsMask32)
    $category = if ($u -band 0x80000000) { 'Security' } else { 'Distribution' }
    $scope = if ($u -band 0x2) { 'Global' } elseif ($u -band 0x4) { 'DomainLocal' } elseif ($u -band 0x8) { 'Universal' } elseif ($u -band 0x1) { 'BuiltinLocal' } else { $null }
    return @{ Category = $category; Scope = $scope }
}
