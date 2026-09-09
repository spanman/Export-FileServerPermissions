<#
Per-user reach table for the over-permission reports, built with the inverted per-resource loop:
for every grant point, the candidate users are the transitive user members of the non-broad Allow ACE
principals (plus directly named users); only those candidates are evaluated. Broad principals are never
expanded, so a user reachable *only* through Everyone / Authenticated Users / Domain Users does not
appear here (that exposure is report 01's job).
#>

function Get-FsCandidateUsers {
    <# User ids an ACE principal stands for: itself when a user, its transitive users when a non-broad group, nothing when broad. Cached. #>
    [OutputType([string[]])]
    param([Parameter(Mandatory)] [System.Collections.IDictionary] $Model, [Parameter(Mandatory)] [string] $PrincipalId)
    $cache = Get-FsCacheTable -Model $Model -Name 'candidateUsers'
    if ($cache.Contains($PrincipalId)) { return $cache[$PrincipalId] }
    $result = [string[]]@()
    if (-not (Test-FsBroadPrincipal -Model $Model -PrincipalId $PrincipalId)) {
        $kind = Get-FsPrincipalKind -Model $Model -Id $PrincipalId
        if (Test-FsUserKind -Kind $kind) { $result = [string[]]@($PrincipalId) }
        elseif (Test-FsGroupKind -Kind $kind) { $result = [string[]]@(Get-FsTransitiveMembers -Model $Model -GroupId $PrincipalId -UsersOnly) }
    }
    $cache[$PrincipalId] = $result
    return $result
}

function Get-FsUserReachTable {
    <#
    .SYNOPSIS
        userId -> rows @{ resourceId resourceKind server path shareId level shareLevel ntfsLevel via layer acePrincipalId hasDeny }
        for every grant point the user reaches through a specific (non-broad) Allow ACE principal. Cached.
    #>
    [OutputType([hashtable])]
    param([Parameter(Mandatory)] [System.Collections.IDictionary] $Model)
    $cache = Get-FsCacheTable -Model $Model -Name 'reach'
    if ($cache.Contains('users')) { return $cache['users'] }
    $levelCache = Get-FsCacheTable -Model $Model -Name 'effectiveLevel'
    $table = @{}
    foreach ($gp in @(Get-FsGrantPointIds -Model $Model)) {
        $ev = Get-FsResourceEvaluation -Model $Model -ResourceId $gp
        if ($null -eq $ev) { continue }
        $allows = [System.Collections.Generic.List[object]]::new()
        if ($null -ne $ev.ntfsBuckets) { foreach ($e in $ev.ntfsBuckets.allows) { $allows.Add($e) } }
        if ($ev.kind -eq 'Share' -and $null -ne $ev.shareBuckets) { foreach ($e in $ev.shareBuckets.allows) { $allows.Add($e) } }
        if ($allows.Count -eq 0) { continue }
        $candidates = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
        foreach ($e in $allows) { foreach ($u in @(Get-FsCandidateUsers -Model $Model -PrincipalId $e.p)) { [void]$candidates.Add($u) } }
        foreach ($u in $candidates) {
            $token = Get-FsToken -Model $Model -PrincipalId $u
            $key = "$u|$gp"
            if ($levelCache.Contains($key)) { $eff = $levelCache[$key] }
            else { $eff = Resolve-FsEffectiveLevel -Evaluation $ev -Token $token; $levelCache[$key] = $eff }
            if ($eff.level -eq 'None') { continue }
            $matches = [System.Collections.Generic.List[object]]::new()
            foreach ($e in $allows) { if ($token.Contains($e.p)) { $matches.Add(@{ p = $e.p; level = $e.level; layer = $e.layer }) } }
            $via = Select-FsBestVia -Model $Model -PrincipalId $u -Matches @($matches)
            if (-not $table.Contains($u)) { $table[$u] = [System.Collections.Generic.List[object]]::new() }
            $table[$u].Add(@{
                    resourceId     = $gp
                    resourceKind   = $ev.kind
                    server         = $ev.server
                    path           = $ev.path
                    shareId        = $ev.shareId
                    level          = $eff.level
                    shareLevel     = $eff.shareLevel
                    ntfsLevel      = $eff.ntfsLevel
                    hasDeny        = $eff.hasDeny
                    via            = [string[]]$via.via
                    layer          = $via.layer
                    acePrincipalId = $via.acePrincipalId
                })
        }
    }
    foreach ($u in @($table.Keys)) { $table[$u] = @(Get-FsSorted -InputObject @($table[$u]) -Property 'server', 'path', 'resourceId') }
    $cache['users'] = $table
    return $table
}

function Get-FsReachSummary {
    <# Counts over a set of reach rows: @{ total full modifyPlus servers(string[]) highest } #>
    [OutputType([hashtable])]
    param([AllowNull()] [AllowEmptyCollection()] [object[]] $Rows)
    $full = 0; $mod = 0; $highest = 0
    $servers = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    foreach ($r in @($Rows)) {
        if ($null -eq $r) { continue }
        $o = Get-FsLevelOrdinal ([string]$r.level)
        if ($o -ge 5) { $full++ }
        if ($o -ge 4) { $mod++ }
        if ($o -gt $highest) { $highest = $o }
        if ($r.server) { [void]$servers.Add([string]$r.server) }
    }
    return @{ total = @($Rows | Where-Object { $null -ne $_ }).Count; full = $full; modifyPlus = $mod; servers = [string[]]@(Get-FsSorted -InputObject @($servers)); highest = (Get-FsLevelName $highest) }
}
