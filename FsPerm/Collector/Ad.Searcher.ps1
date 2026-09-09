<#
Active Directory access through System.DirectoryServices (ADSI; no RSAT required).

A "searcher" here is a hashtable wrapper:
  @{ Searcher (DirectorySearcher); Root (DirectoryEntry); Server; Credential; DomainSid; DomainDn; NetBios; Dns }

Windows-only types are referenced inside function bodies only, so this file loads on Linux; the pure helpers
(ConvertTo-FsLdapSidFilter, ConvertTo-FsLdapEscapedValue, Get-FsAdRangeInfo, Get-FsAdSearchResultValue on
dictionaries) are unit-tested in the container.
#>

$script:FsAdPropertiesToLoad = @(
    'objectSid', 'objectClass', 'distinguishedName', 'sAMAccountName', 'name', 'cn', 'displayName', 'description',
    'userPrincipalName', 'mail', 'userAccountControl', 'lastLogonTimestamp', 'pwdLastSet', 'accountExpires',
    'department', 'title', 'manager', 'whenCreated', 'primaryGroupID',
    'groupType', 'managedBy', 'dNSHostName'
)

function ConvertTo-FsLdapSidFilter {
    <# SID string -> hex-escaped binary form usable in an LDAP filter, e.g. \01\05\00\00\00\00\00\05\15... #>
    [OutputType([string])]
    param([Parameter(Mandatory)] [string] $Sid)
    $sidObj = [System.Security.Principal.SecurityIdentifier]::new($Sid)
    $bytes = [byte[]]::new($sidObj.BinaryLength)
    $sidObj.GetBinaryForm($bytes, 0)
    $sb = [System.Text.StringBuilder]::new($bytes.Length * 3)
    foreach ($b in $bytes) { [void]$sb.Append('\').Append($b.ToString('x2')) }
    return $sb.ToString()
}

function ConvertTo-FsLdapEscapedValue {
    <# RFC 4515 escaping of an attribute value used inside an LDAP filter: \ * ( ) NUL #>
    [OutputType([string])]
    param([AllowNull()] [AllowEmptyString()] [string] $Value)
    if ($null -eq $Value) { return '' }
    return $Value.Replace('\', '\5c').Replace('*', '\2a').Replace('(', '\28').Replace(')', '\29').Replace("`0", '\00')
}

function ConvertTo-FsAdsPathDn {
    <# Escapes a DN for use inside an ADsPath (forward slashes are path separators there). #>
    [OutputType([string])]
    param([Parameter(Mandatory)] [string] $Dn)
    return $Dn.Replace('/', '\/')
}

function ConvertTo-FsDomainDn {
    <# contoso.local -> DC=contoso,DC=local #>
    [OutputType([string])]
    param([Parameter(Mandatory)] [string] $DnsName)
    return (($DnsName.Trim('.').Split('.') | ForEach-Object { "DC=$_" }) -join ',')
}

function Get-FsDnDomainPart {
    <# CN=x,OU=y,DC=contoso,DC=local -> DC=contoso,DC=local (ordinal-lowercase for matching) #>
    [OutputType([string])]
    param([Parameter(Mandatory)] [string] $Dn)
    $i = $Dn.IndexOf('DC=', [System.StringComparison]::OrdinalIgnoreCase)
    if ($i -lt 0) { return $null }
    return $Dn.Substring($i)
}

function Get-FsAdRangeInfo {
    <#
    .SYNOPSIS
        Parses a ranged-retrieval property name ("member;range=0-1499", "member;range=1500-*", or plain "member").
    .OUTPUTS
        @{ IsMatch; Low; High (nullable); IsLast } — IsLast is true for "...-*" and for the plain attribute name.
    #>
    [OutputType([hashtable])]
    param([Parameter(Mandatory)] [string] $PropertyName, [string] $Attribute = 'member')
    $rx = [regex]::new('^' + [regex]::Escape($Attribute) + '(?:;range=(\d+)-(\d+|\*))?$', [System.Text.RegularExpressions.RegexOptions]::IgnoreCase)
    $m = $rx.Match($PropertyName)
    if (-not $m.Success) { return @{ IsMatch = $false; Low = $null; High = $null; IsLast = $false } }
    if (-not $m.Groups[1].Success) { return @{ IsMatch = $true; Low = 0; High = $null; IsLast = $true } }
    $low = [int]$m.Groups[1].Value
    $highText = $m.Groups[2].Value
    if ($highText -eq '*') { return @{ IsMatch = $true; Low = $low; High = $null; IsLast = $true } }
    return @{ IsMatch = $true; Low = $low; High = [int]$highText; IsLast = $false }
}

function ConvertFrom-FsAdValue {
    <# Normalizes one ADSI value: byte[] SIDs -> SID string, other byte[] -> base64, DateTime -> UTC DateTime. #>
    [OutputType([object])]
    param([AllowNull()] $Value, [string] $Name)
    if ($null -eq $Value) { return $null }
    if ($Value -is [byte[]]) {
        if ($Name -match '^(objectSid|securityIdentifier|sidHistory)$' -or ($Value.Length -ge 8 -and $Value[0] -eq 1)) {
            try { return ([System.Security.Principal.SecurityIdentifier]::new($Value, 0)).Value } catch { return [Convert]::ToBase64String($Value) }
        }
        return [Convert]::ToBase64String($Value)
    }
    if ($Value -is [datetime]) {
        if ($Value.Kind -eq [System.DateTimeKind]::Local) { return $Value.ToUniversalTime() }
        return [datetime]::SpecifyKind($Value, [System.DateTimeKind]::Utc)
    }
    if ($Value.GetType().FullName -eq 'System.__ComObject') {
        # IADsLargeInteger (only when values arrive through DirectoryEntry rather than DirectorySearcher). Compared
        # by type name rather than "-is [System.__ComObject]": that type literal does not resolve on non-Windows
        # runtimes (no COM interop support), which would throw here for every plain scalar value on Linux.
        try {
            $high = [int64]$Value.GetType().InvokeMember('HighPart', 'GetProperty', $null, $Value, $null)
            $low = [int64]$Value.GetType().InvokeMember('LowPart', 'GetProperty', $null, $Value, $null)
            return ($high -shl 32) -bor ($low -band 0xFFFFFFFFL)
        }
        catch { return $null }
    }
    return $Value
}

function Get-FsAdSearchResultList {
    <# All values of a property as an array (SearchResult, DirectoryEntry-like or dictionary input). #>
    [OutputType([object[]])]
    param([Parameter(Mandatory)] $Result, [Parameter(Mandatory)] [string] $Name)
    $raw = $null
    if ($Result -is [System.Collections.IDictionary]) {
        foreach ($k in $Result.Keys) { if ([string]$k -ieq $Name) { $raw = $Result[$k]; break } }
    }
    else {
        $props = $Result.Properties
        if ($null -eq $props) { return @() }
        if ($props -is [System.Collections.IDictionary]) {
            foreach ($k in $props.Keys) { if ([string]$k -ieq $Name) { $raw = $props[$k]; break } }
        }
        elseif ($props.Contains($Name.ToLowerInvariant())) { $raw = $props[$Name.ToLowerInvariant()] }
        elseif ($props.Contains($Name)) { $raw = $props[$Name] }
    }
    if ($null -eq $raw) { return @() }
    if ($raw -is [string] -or $raw -is [byte[]]) { return @(, (ConvertFrom-FsAdValue -Value $raw -Name $Name)) }
    if ($raw -is [System.Collections.IEnumerable]) {
        $out = [System.Collections.Generic.List[object]]::new()
        foreach ($v in $raw) { $out.Add((ConvertFrom-FsAdValue -Value $v -Name $Name)) }
        return @($out)
    }
    return @(, (ConvertFrom-FsAdValue -Value $raw -Name $Name))
}

function Get-FsAdSearchResultValue {
    <# First value of a property or $null. byte[] SIDs become SID strings. #>
    [OutputType([object])]
    param([Parameter(Mandatory)] $Result, [Parameter(Mandatory)] [string] $Name)
    $list = @(Get-FsAdSearchResultList -Result $Result -Name $Name)
    if ($list.Count -eq 0) { return $null }
    return $list[0]
}

function New-FsAdEntry {
    <# DirectoryEntry for an LDAP path (DN or full LDAP:// path), honoring -Server and -Credential. #>
    [OutputType([object])]
    param([Parameter(Mandatory)] [string] $Path, [AllowNull()] [string] $Server, [AllowNull()] [pscredential] $Credential)
    $p = $Path
    if ($p -notmatch '^(LDAP|GC)://') { $p = 'LDAP://' + (ConvertTo-FsAdsPathDn -Dn $p) }
    if ($Server) {
        $m = [regex]::Match($p, '^(LDAP|GC)://(.*)$', [System.Text.RegularExpressions.RegexOptions]::IgnoreCase)
        $scheme = $m.Groups[1].Value
        $rest = $m.Groups[2].Value
        # "server/DN" already present when the first segment has no '=' and is followed by '/'
        $hasServer = ($rest -match '^[^/=,]+/')
        if (-not $hasServer) { $p = '{0}://{1}/{2}' -f $scheme, $Server, $rest }
    }
    # Secure only - not `-bor Signing -bor Sealing`. That combination demands a fully negotiated,
    # encrypted SASL channel for every real LDAP operation; a real production run showed it let a
    # lightweight RootDSE property read succeed while every actual search/refresh (a different DN's
    # DirectoryEntry.RefreshCache, and DirectorySearcher.FindAll for both the domain object and a
    # completely unrelated crossRef subtree search) failed uniformly with LDAP's generic "An
    # operations error occurred" - the classic symptom of this exact combination failing to negotiate
    # (VPN/NAT paths and Kerberos encryption-type mismatches are the usual causes). Secure alone still
    # authenticates (NTLM/Kerberos, not anonymous) and is the standard, broadly-compatible ADSI bind.
    $authType = [System.DirectoryServices.AuthenticationTypes]::Secure
    if ($Credential) {
        return New-Object System.DirectoryServices.DirectoryEntry($p, $Credential.UserName, $Credential.GetNetworkCredential().Password, $authType)
    }
    return New-Object System.DirectoryServices.DirectoryEntry($p, $null, $null, $authType)
}

function New-FsAdSearcher {
    <#
    .SYNOPSIS
        Creates a DirectorySearcher wrapper (PageSize 1000, explicit PropertiesToLoad) rooted at a domain DN or LDAP path.
    .PARAMETER LdapPath
        Search root: a DN ("DC=contoso,DC=local") or an LDAP:// path.
    .PARAMETER DomainSid
        Recorded on the wrapper (used for RID/domain matching); no lookup is performed.
    #>
    [OutputType([hashtable])]
    param(
        [Parameter(Mandatory)] [string] $LdapPath,
        [AllowNull()] [string] $Server,
        [AllowNull()] [pscredential] $Credential,
        [AllowNull()] [string] $DomainSid,
        [AllowNull()] [string] $NetBios,
        [AllowNull()] [string] $Dns,
        [string[]] $PropertiesToLoad = $script:FsAdPropertiesToLoad,
        [int] $PageSize = 1000
    )
    $root = New-FsAdEntry -Path $LdapPath -Server $Server -Credential $Credential
    $searcher = New-Object System.DirectoryServices.DirectorySearcher($root)
    $searcher.PageSize = $PageSize
    $searcher.SearchScope = [System.DirectoryServices.SearchScope]::Subtree
    $searcher.CacheResults = $false
    $searcher.ReferralChasing = [System.DirectoryServices.ReferralChasingOption]::None
    $searcher.PropertiesToLoad.Clear()
    foreach ($p in $PropertiesToLoad) { [void]$searcher.PropertiesToLoad.Add($p) }
    $dn = if ($LdapPath -match '^(LDAP|GC)://') { ($LdapPath -replace '^(LDAP|GC)://([^/]+/)?', '') } else { $LdapPath }
    return @{
        Searcher = $searcher; Root = $root; Server = $Server; Credential = $Credential
        DomainSid = $DomainSid; DomainDn = $dn; NetBios = $NetBios; Dns = $Dns; PropertiesToLoad = @($PropertiesToLoad)
    }
}

function Invoke-FsAdSearch {
    <# Runs a filter on a searcher wrapper and returns the SearchResult objects (FindAll disposed). #>
    [OutputType([object[]])]
    param(
        [Parameter(Mandatory)] [hashtable] $Searcher,
        [Parameter(Mandatory)] [string] $Filter,
        [string[]] $PropertiesToLoad,
        [int] $SizeLimit = 0
    )
    $ds = $Searcher.Searcher
    $ds.Filter = $Filter
    $ds.SizeLimit = $SizeLimit
    if ($PropertiesToLoad) {
        $ds.PropertiesToLoad.Clear()
        foreach ($p in $PropertiesToLoad) { [void]$ds.PropertiesToLoad.Add($p) }
    }
    $out = [System.Collections.Generic.List[object]]::new()
    $results = $ds.FindAll()
    try { foreach ($r in $results) { $out.Add($r) } }
    finally {
        $results.Dispose()
        if ($PropertiesToLoad) {
            $ds.PropertiesToLoad.Clear()
            foreach ($p in $Searcher.PropertiesToLoad) { [void]$ds.PropertiesToLoad.Add($p) }
        }
    }
    return @($out)
}

function Get-FsAdDomainTable {
    <#
    .SYNOPSIS
        Discovers the primary domain (RootDSE) and its trusted domains (CN=System trustedDomain objects).
    .OUTPUTS
        @{ Primary = <entry>; Domains = ordered sid -> entry; ForestDomains = string[] (dns) }
        entry: @{ sid; netbios; dns; dn; isPrimary; source; trustDirection; trustPartner }
    #>
    [OutputType([hashtable])]
    param([AllowNull()] [string] $Server, [AllowNull()] [pscredential] $Credential)
    try {
        $rootDse = New-FsAdEntry -Path 'LDAP://RootDSE' -Server $Server -Credential $Credential
        $defaultNc = [string]$rootDse.Properties['defaultNamingContext'].Value
        $configNc = [string]$rootDse.Properties['configurationNamingContext'].Value
        $dnsHostName = [string]$rootDse.Properties['dnsHostName'].Value
    }
    catch {
        throw "Could not bind to LDAP://RootDSE$(if ($Server) { " on $Server" }) - AD is unreachable from here (off VPN? DNS/firewall issue?). Re-run with -SkipAdEnrichment to scan shares and NTFS ACLs without resolving any principal to a name, or with -AdServer pointing at a reachable domain controller. Original error: $($_.Exception.Message)"
    }
    if (-not $defaultNc) { throw 'RootDSE returned no defaultNamingContext; is the workstation domain-joined / is -AdServer reachable?' }

    # Everything from here on is either derived purely from the (already-successful) RootDSE bind or wrapped
    # in its own guard: a real AD directory can return sparse/unreadable attributes for reasons outside this
    # tool's control (ACLs, GC vs. DC quirks, forest topology), and one missing attribute should degrade to
    # "domain name known, SID unknown" rather than aborting domain discovery entirely.
    $dnsRoot = (($defaultNc -split ',') | Where-Object { $_ -like 'DC=*' } | ForEach-Object { $_.Substring(3) }) -join '.'
    # Never $null: it becomes a dictionary key at $domains[$domainSid] below, and dictionary keys can't be null.
    $domainSid = $defaultNc
    $domainSidDegraded = $false
    $resolved = $null
    # Two independent attempts, since a real production domain was seen to defeat each of these
    # individually - every domain-scoped SID classification and batched AD lookup downstream keys off
    # this value, so a silent miss here caused (almost) every principal to fall through to the
    # Foreign/OrphanedSid classification instead of resolving as a real User/Group. $diag records
    # precisely what each attempt observed (threw vs. silently empty vs. zero results) since two prior
    # fix attempts against the same real domain failed identically with no way to tell why - this is
    # surfaced into the scan's errors[] below so the next failure is diagnosable without guessing.
    $diag = [System.Collections.Generic.List[string]]::new()
    try {
        # Attempt 1: explicit RefreshCache(@('objectSid')) on the raw DirectoryEntry - the same technique
        # already used (for OTHER domains) by Get-FsAdSearcherForDomain below, because a DirectoryEntry's
        # lazily-cached Properties collection was observed, against this domain, to simply not contain
        # objectSid without an explicit refresh request (no exception - the value came back $null).
        $domainEntry = New-FsAdEntry -Path $defaultNc -Server $Server -Credential $Credential
        [void]$domainEntry.RefreshCache(@('objectSid'))
        $sidBytes = $domainEntry.Properties['objectSid'].Value
        if ($null -eq $sidBytes) { $diag.Add('RefreshCache: bind+refresh succeeded but Properties[objectSid].Value is null.') }
        else {
            $resolved = [string](ConvertFrom-FsAdValue -Value $sidBytes -Name 'objectSid')
            if (-not $resolved) { $diag.Add("RefreshCache: objectSid bytes present (length $($sidBytes.Length)) but conversion to a SID string produced an empty result.") }
        }
    }
    catch { $diag.Add("RefreshCache: threw $($_.Exception.GetType().Name): $($_.Exception.Message)") }
    if (-not $resolved) {
        try {
            # Attempt 2: a Base-scoped DirectorySearcher with an explicit PropertiesToLoad, PageSize
            # forced to 0. PageSize must be 0 (disable the paged-results LDAP control) for a Base-scoped
            # search: real Active Directory silently returns zero entries for a paged Base search instead
            # of erroring, and New-FsAdSearcher's default PageSize (1000, meant for the Subtree searches
            # below) would otherwise still be active.
            $domainSearcher = New-FsAdSearcher -LdapPath $defaultNc -Server $Server -Credential $Credential -PropertiesToLoad @('objectSid')
            $domainSearcher.Searcher.SearchScope = [System.DirectoryServices.SearchScope]::Base
            $domainSearcher.Searcher.PageSize = 0
            $domainResults = @(Invoke-FsAdSearch -Searcher $domainSearcher -Filter '(objectClass=*)')
            if ($domainResults.Count -eq 0) { $diag.Add('BaseSearch: executed without throwing but returned 0 results for (objectClass=*) at the domain DN.') }
            else {
                $resolved = [string](Get-FsAdSearchResultValue -Result $domainResults[0] -Name 'objectSid')
                if (-not $resolved) { $diag.Add("BaseSearch: $($domainResults.Count) result(s) returned but objectSid was empty/missing on the first one.") }
            }
        }
        catch { $diag.Add("BaseSearch: threw $($_.Exception.GetType().Name): $($_.Exception.Message)") }
    }
    if ($resolved) { $domainSid = $resolved }
    else {
        $domainSidDegraded = $true
        Write-Verbose "'$defaultNc' returned no objectSid via either lookup method; using its DN as a stand-in key. Domain-relative RID matching (Domain Users/Admins/...) will be unavailable."
    }
    $netbios = $null

    $domains = [ordered]@{}
    $forest = [System.Collections.Generic.List[string]]::new()
    try {
        $partitions = New-FsAdSearcher -LdapPath "CN=Partitions,$configNc" -Server $Server -Credential $Credential -PropertiesToLoad @('nCName', 'nETBIOSName', 'dnsRoot')
        $crossRefResults = @(Invoke-FsAdSearch -Searcher $partitions -Filter '(&(objectClass=crossRef)(nETBIOSName=*))')
        # One more data point for $diag: does ANY subtree search return results at all, or is it just
        # the domain-object Base search that comes back empty? Distinguishes "this one query is broken"
        # from "every AD query from this identity/connection silently returns nothing."
        $diag.Add("crossRef enumeration: $($crossRefResults.Count) result(s).")
        foreach ($r in $crossRefResults) {
            $nc = [string](Get-FsAdSearchResultValue -Result $r -Name 'nCName')
            $nb = [string](Get-FsAdSearchResultValue -Result $r -Name 'nETBIOSName')
            $dr = [string](Get-FsAdSearchResultValue -Result $r -Name 'dnsRoot')
            if ($dr) { $forest.Add($dr) }
            if ($nc -and $nc -ieq $defaultNc) { $netbios = $nb }
        }
    }
    catch {
        $diag.Add("crossRef enumeration: threw $($_.Exception.GetType().Name): $($_.Exception.Message)")
        Write-Verbose "crossRef enumeration failed: $($_.Exception.Message)"
    }
    if (-not $netbios) { $netbios = ($dnsRoot.Split('.')[0]).ToUpperInvariant() }

    $primary = @{ sid = $domainSid; netbios = $netbios; dns = $dnsRoot; dn = $defaultNc; isPrimary = $true; source = 'RootDSE'; trustDirection = $null; trustPartner = $null; server = $dnsHostName; sidDegraded = $domainSidDegraded; sidDiagnostics = @($diag) }
    $domains[$domainSid] = $primary

    try {
        $trustSearcher = New-FsAdSearcher -LdapPath "CN=System,$defaultNc" -Server $Server -Credential $Credential -PropertiesToLoad @('securityIdentifier', 'flatName', 'trustPartner', 'trustDirection', 'trustType', 'trustAttributes')
        foreach ($r in Invoke-FsAdSearch -Searcher $trustSearcher -Filter '(objectClass=trustedDomain)') {
            $tsid = [string](Get-FsAdSearchResultValue -Result $r -Name 'securityIdentifier')
            $flat = [string](Get-FsAdSearchResultValue -Result $r -Name 'flatName')
            $partner = [string](Get-FsAdSearchResultValue -Result $r -Name 'trustPartner')
            $dir = Get-FsAdSearchResultValue -Result $r -Name 'trustDirection'
            if (-not $tsid -or $domains.Contains($tsid)) { continue }
            $domains[$tsid] = @{
                sid = $tsid; netbios = $flat; dns = $partner; dn = $(if ($partner -match '\.') { ConvertTo-FsDomainDn -DnsName $partner } else { $null })
                isPrimary = $false; source = 'trustedDomain'; trustDirection = $dir; trustPartner = $partner; server = $null
            }
        }
    }
    catch { Write-Verbose "trustedDomain enumeration failed: $($_.Exception.Message)" }

    return @{ Primary = $primary; Domains = $domains; ForestDomains = @($forest) }
}

function Get-FsAdSearcherForDomain {
    <#
    .SYNOPSIS
        Returns (and caches on the context) a searcher for the domain owning a SID prefix; $null when the domain
        is unknown or cannot be bound. -AdServer is used only for the primary domain.
    #>
    [OutputType([hashtable])]
    param([Parameter(Mandatory)] [hashtable] $Context, [Parameter(Mandatory)] [string] $DomainSid)
    if ($Context.AdSearchers.ContainsKey($DomainSid)) { return $Context.AdSearchers[$DomainSid] }
    $table = $Context.DomainTable
    if ($null -eq $table) { return $null }
    $entry = $null
    if ($table.Domains.Contains($DomainSid)) { $entry = $table.Domains[$DomainSid] }
    if ($null -eq $entry -or -not $entry.dn) { $Context.AdSearchers[$DomainSid] = $null; return $null }
    $server = if ($entry.isPrimary) { $Context.Options.AdServer } else { $null }
    try {
        $s = New-FsAdSearcher -LdapPath $entry.dn -Server $server -Credential $Context.Options.AdCredential -DomainSid $DomainSid -NetBios $entry.netbios -Dns $entry.dns
        # touch the root so an unreachable domain fails here, once, instead of on every batch
        [void]$s.Root.RefreshCache(@('objectSid'))
        $Context.AdSearchers[$DomainSid] = $s
        return $s
    }
    catch {
        Add-FsScanError -Context $Context -Phase AdResolve -Scope $entry.netbios -Kind Directory -Message "Cannot bind to domain $($entry.dns) ($DomainSid): $($_.Exception.Message)" -ExceptionType $_.Exception.GetType().FullName | Out-Null
        $Context.AdSearchers[$DomainSid] = $null
        return $null
    }
}

function Get-FsAdSearcherForDn {
    <# Picks the cached domain searcher whose DN is the suffix of the given DN; falls back to the primary domain. #>
    [OutputType([hashtable])]
    param([Parameter(Mandatory)] [hashtable] $Context, [Parameter(Mandatory)] [string] $Dn)
    $domainPart = Get-FsDnDomainPart -Dn $Dn
    $table = $Context.DomainTable
    if ($null -eq $table) { return $null }
    if ($domainPart) {
        foreach ($sid in @($table.Domains.Keys)) {
            $e = $table.Domains[$sid]
            if ($e.dn -and ($e.dn -ieq $domainPart)) { return (Get-FsAdSearcherForDomain -Context $Context -DomainSid $sid) }
        }
    }
    return (Get-FsAdSearcherForDomain -Context $Context -DomainSid $table.Primary.sid)
}

function Get-FsAdObjectsBySid {
    <#
    .SYNOPSIS
        Batched objectSid lookup: (|(objectSid=\01..)(objectSid=..)) 100 per query; a failing batch is retried per SID.
    .OUTPUTS
        @{ Found = hashtable sid -> SearchResult; Errors = list of @{ sid; message; exceptionType } }
    #>
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseSingularNouns', '', Justification = 'Name fixed by the collector contract')]
    [OutputType([hashtable])]
    param([Parameter(Mandatory)] [hashtable] $Searcher, [Parameter(Mandatory)] [AllowEmptyCollection()] [string[]] $Sid, [int] $BatchSize = 100)
    $found = [System.Collections.Generic.Dictionary[string, object]]::new([System.StringComparer]::OrdinalIgnoreCase)
    $errors = [System.Collections.Generic.List[object]]::new()
    $unique = @($Sid | Where-Object { $_ } | Select-Object -Unique)
    $runBatch = {
        param([string[]] $batch)
        $filter = '(|' + (($batch | ForEach-Object { '(objectSid=' + (ConvertTo-FsLdapSidFilter -Sid $_) + ')' }) -join '') + ')'
        foreach ($r in Invoke-FsAdSearch -Searcher $Searcher -Filter $filter) {
            $rs = [string](Get-FsAdSearchResultValue -Result $r -Name 'objectSid')
            if ($rs) { $found[$rs] = $r }
        }
    }
    for ($i = 0; $i -lt $unique.Count; $i += $BatchSize) {
        $batch = @($unique[$i..([Math]::Min($i + $BatchSize, $unique.Count) - 1)])
        try { & $runBatch $batch }
        catch {
            Write-Verbose "SID batch of $($batch.Count) failed ($($_.Exception.Message)); retrying per SID."
            foreach ($one in $batch) {
                try { & $runBatch @($one) }
                catch { $errors.Add(@{ sid = $one; message = $_.Exception.Message; exceptionType = $_.Exception.GetType().FullName }) }
            }
        }
    }
    return @{ Found = $found; Errors = $errors }
}

function Get-FsAdObjectsByDn {
    <#
    .SYNOPSIS
        Batched distinguishedName lookup with RFC 4515 escaping; a failing batch is retried per DN.
    .OUTPUTS
        @{ Found = dictionary dn -> SearchResult (case-insensitive); Errors = list of @{ dn; message; exceptionType } }
    #>
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseSingularNouns', '', Justification = 'Name fixed by the collector contract')]
    [OutputType([hashtable])]
    param([Parameter(Mandatory)] [hashtable] $Searcher, [Parameter(Mandatory)] [AllowEmptyCollection()] [string[]] $Dn, [int] $BatchSize = 100)
    $found = [System.Collections.Generic.Dictionary[string, object]]::new([System.StringComparer]::OrdinalIgnoreCase)
    $errors = [System.Collections.Generic.List[object]]::new()
    $unique = @($Dn | Where-Object { $_ } | Select-Object -Unique)
    $runBatch = {
        param([string[]] $batch)
        $filter = '(|' + (($batch | ForEach-Object { '(distinguishedName=' + (ConvertTo-FsLdapEscapedValue -Value $_) + ')' }) -join '') + ')'
        foreach ($r in Invoke-FsAdSearch -Searcher $Searcher -Filter $filter) {
            $rdn = [string](Get-FsAdSearchResultValue -Result $r -Name 'distinguishedName')
            if ($rdn) { $found[$rdn] = $r }
        }
    }
    for ($i = 0; $i -lt $unique.Count; $i += $BatchSize) {
        $batch = @($unique[$i..([Math]::Min($i + $BatchSize, $unique.Count) - 1)])
        try { & $runBatch $batch }
        catch {
            Write-Verbose "DN batch of $($batch.Count) failed ($($_.Exception.Message)); retrying per DN."
            foreach ($one in $batch) {
                try { & $runBatch @($one) }
                catch { $errors.Add(@{ dn = $one; message = $_.Exception.Message; exceptionType = $_.Exception.GetType().FullName }) }
            }
        }
    }
    return @{ Found = $found; Errors = $errors }
}

function Get-FsAdRangedAttribute {
    <#
    .SYNOPSIS
        Reads a multi-valued attribute (default: member) with ranged retrieval, looping until the server returns
        the "<attr>;range=N-*" terminal page.
    .OUTPUTS
        string[] of values.
    #>
    [OutputType([string[]])]
    param(
        [Parameter(Mandatory)] [hashtable] $Searcher,
        [Parameter(Mandatory)] [string] $Dn,
        [string] $Attribute = 'member',
        [int] $Step = 1500
    )
    $entry = New-FsAdEntry -Path $Dn -Server $Searcher.Server -Credential $Searcher.Credential
    $ds = New-Object System.DirectoryServices.DirectorySearcher($entry)
    $ds.SearchScope = [System.DirectoryServices.SearchScope]::Base
    $ds.Filter = '(objectClass=*)'
    $ds.CacheResults = $false
    $values = [System.Collections.Generic.List[string]]::new()
    $low = 0
    $guard = 0
    try {
        while ($true) {
            $guard++
            if ($guard -gt 10000) { throw "Ranged retrieval of $Attribute on $Dn did not terminate." }
            $ds.PropertiesToLoad.Clear()
            [void]$ds.PropertiesToLoad.Add(('{0};range={1}-{2}' -f $Attribute, $low, ($low + $Step - 1)))
            $r = $ds.FindOne()
            if ($null -eq $r) { break }
            $pageName = $null
            foreach ($pn in $r.Properties.PropertyNames) {
                $info = Get-FsAdRangeInfo -PropertyName ([string]$pn) -Attribute $Attribute
                if ($info.IsMatch) { $pageName = [string]$pn; break }
            }
            if (-not $pageName) { break }     # attribute empty / not present
            $info = Get-FsAdRangeInfo -PropertyName $pageName -Attribute $Attribute
            $count = 0
            foreach ($v in $r.Properties[$pageName]) { $values.Add([string]$v); $count++ }
            if ($info.IsLast -or $count -eq 0) { break }
            $low = $info.High + 1
        }
    }
    finally { $ds.Dispose(); $entry.Dispose() }
    return [string[]]@($values)
}
