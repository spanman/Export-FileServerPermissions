<#
Group-membership closure over the merged model's direct edges ($Model.index.groupsByMember / membersByGroup).
AD allows cycles, so every walk uses a visited set. Results are memoized in $Model.cache.

Broad principals (Everyone, Authenticated Users, Domain Users, ...) are never expanded downward into
"all users"; Get-FsTransitiveMembers stops at them.
#>

function Get-FsTransitiveGroups {
    <# Group ids reachable upward from a principal (excluding itself), ordinal-sorted. #>
    [OutputType([string[]])]
    param([Parameter(Mandatory)] [System.Collections.IDictionary] $Model, [Parameter(Mandatory)] [string] $PrincipalId)
    $cache = Get-FsCacheTable -Model $Model -Name 'transitiveGroups'
    if ($cache.Contains($PrincipalId)) { return $cache[$PrincipalId] }
    $up = $Model.index.groupsByMember
    $visited = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    $queue = [System.Collections.Generic.Queue[string]]::new()
    [void]$visited.Add($PrincipalId); $queue.Enqueue($PrincipalId)
    while ($queue.Count -gt 0) {
        $cur = $queue.Dequeue()
        if (-not $up.Contains($cur)) { continue }
        foreach ($g in @($up[$cur])) { if ($visited.Add($g)) { $queue.Enqueue($g) } }
    }
    [void]$visited.Remove($PrincipalId)
    $result = [string[]]@(Get-FsSorted -InputObject @($visited))
    $cache[$PrincipalId] = $result
    return $result
}

function Get-FsGroupChainParents {
    <# BFS parent pointers (child id -> the id it was discovered from) for shortest upward paths from a principal. Cached. #>
    [OutputType([hashtable])]
    param([Parameter(Mandatory)] [System.Collections.IDictionary] $Model, [Parameter(Mandatory)] [string] $PrincipalId)
    $cache = Get-FsCacheTable -Model $Model -Name 'chainParents'
    if ($cache.Contains($PrincipalId)) { return $cache[$PrincipalId] }
    $up = $Model.index.groupsByMember
    $parents = @{}
    $parents[$PrincipalId] = $null
    $queue = [System.Collections.Generic.Queue[string]]::new()
    $queue.Enqueue($PrincipalId)
    while ($queue.Count -gt 0) {
        $cur = $queue.Dequeue()
        if (-not $up.Contains($cur)) { continue }
        # groupsByMember lists are ordinal-sorted, so ties resolve deterministically
        foreach ($g in @($up[$cur])) {
            if ($parents.Contains($g)) { continue }
            $parents[$g] = $cur
            $queue.Enqueue($g)
        }
    }
    $cache[$PrincipalId] = $parents
    return $parents
}

function Get-FsGroupChain {
    <# Shortest path of ids from a principal to a group it belongs to (both inclusive), or @() when unreachable. #>
    [OutputType([string[]])]
    param(
        [Parameter(Mandatory)] [System.Collections.IDictionary] $Model,
        [Parameter(Mandatory)] [string] $PrincipalId,
        [Parameter(Mandatory)] [string] $GroupId
    )
    if ($PrincipalId -eq $GroupId) { return [string[]]@($PrincipalId) }
    $parents = Get-FsGroupChainParents -Model $Model -PrincipalId $PrincipalId
    if (-not $parents.Contains($GroupId)) { return [string[]]@() }
    $path = [System.Collections.Generic.List[string]]::new()
    $cur = $GroupId
    while ($null -ne $cur) {
        $path.Add($cur)
        $cur = $parents[$cur]
    }
    $path.Reverse()
    return [string[]]$path.ToArray()
}

function Get-FsTransitiveMembers {
    <#
    .SYNOPSIS
        Member ids reachable downward from a group (excluding itself), ordinal-sorted. Broad principals are listed but not expanded.
    .PARAMETER UsersOnly
        Only User / LocalUser / Computer kinds.
    #>
    [OutputType([string[]])]
    param(
        [Parameter(Mandatory)] [System.Collections.IDictionary] $Model,
        [Parameter(Mandatory)] [string] $GroupId,
        [switch] $UsersOnly
    )
    $cacheName = $(if ($UsersOnly) { 'transitiveUsers' } else { 'transitiveMembers' })
    $cache = Get-FsCacheTable -Model $Model -Name $cacheName
    if ($cache.Contains($GroupId)) { return $cache[$GroupId] }
    $all = $null
    $allCache = Get-FsCacheTable -Model $Model -Name 'transitiveMembers'
    if ($allCache.Contains($GroupId)) { $all = $allCache[$GroupId] }
    else {
        $down = $Model.index.membersByGroup
        $broad = Get-FsBroadPrincipalSet -Model $Model
        $visited = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
        $queue = [System.Collections.Generic.Queue[string]]::new()
        [void]$visited.Add($GroupId); $queue.Enqueue($GroupId)
        while ($queue.Count -gt 0) {
            $cur = $queue.Dequeue()
            if ($cur -ne $GroupId -and $broad.Contains($cur)) { continue }   # never expand a broad group into "all users"
            if (-not $down.Contains($cur)) { continue }
            foreach ($m in @($down[$cur])) { if ($visited.Add($m)) { $queue.Enqueue($m) } }
        }
        [void]$visited.Remove($GroupId)
        $all = [string[]]@(Get-FsSorted -InputObject @($visited))
        $allCache[$GroupId] = $all
    }
    if (-not $UsersOnly) { return $all }
    $users = foreach ($id in $all) { if (Test-FsUserPrincipal -Model $Model -Id $id) { $id } }
    $cache[$GroupId] = [string[]]@($users)
    return $cache[$GroupId]
}

function Get-FsGroupNestingDepth {
    <# Longest simple upward path through parent groups (0 = no parents), capped at 20. #>
    [OutputType([int])]
    param([Parameter(Mandatory)] [System.Collections.IDictionary] $Model, [Parameter(Mandatory)] [string] $GroupId)
    $cache = Get-FsCacheTable -Model $Model -Name 'nestingDepth'
    if ($cache.Contains($GroupId)) { return $cache[$GroupId] }
    $onPath = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    $hit = [ref]$false
    return (Get-FsNestingDepthCore -Model $Model -GroupId $GroupId -OnPath $onPath -Cache $cache -HitCycle $hit)
}

function Get-FsNestingDepthCore {
    <# Recursive worker for Get-FsGroupNestingDepth; only memoizes subtrees that did not touch a cycle. #>
    [OutputType([int])]
    param(
        [Parameter(Mandatory)] [System.Collections.IDictionary] $Model,
        [Parameter(Mandatory)] [string] $GroupId,
        [Parameter(Mandatory)] [AllowEmptyCollection()] [System.Collections.Generic.HashSet[string]] $OnPath,
        [Parameter(Mandatory)] [hashtable] $Cache,
        [Parameter(Mandatory)] [ref] $HitCycle
    )
    if ($Cache.Contains($GroupId)) { return $Cache[$GroupId] }
    if ($OnPath.Count -ge 20) { $HitCycle.Value = $true; return 0 }
    [void]$OnPath.Add($GroupId)
    $best = 0
    $localHit = $false
    $up = $Model.index.groupsByMember
    if ($up.Contains($GroupId)) {
        foreach ($parent in @($up[$GroupId])) {
            if ($OnPath.Contains($parent)) { $localHit = $true; continue }
            $sub = [ref]$false
            $d = 1 + (Get-FsNestingDepthCore -Model $Model -GroupId $parent -OnPath $OnPath -Cache $Cache -HitCycle $sub)
            if ($sub.Value) { $localHit = $true }
            if ($d -gt $best) { $best = $d }
        }
    }
    [void]$OnPath.Remove($GroupId)
    if ($best -gt 20) { $best = 20 }
    if (-not $localHit) { $Cache[$GroupId] = $best }
    if ($localHit) { $HitCycle.Value = $true }
    return $best
}

function Get-FsGroupCycles {
    <# Membership cycles as string[] chains, each rotated to start at its ordinal-smallest id, deduplicated and sorted. #>
    [OutputType([object[]])]
    param([Parameter(Mandatory)] [System.Collections.IDictionary] $Model)
    $cache = Get-FsCacheTable -Model $Model -Name 'cycles'
    if ($cache.Contains('all')) { return $cache['all'] }
    $up = $Model.index.groupsByMember
    $color = @{}
    $path = [System.Collections.Generic.List[string]]::new()
    $found = @{}
    $cmp = [System.StringComparer]::OrdinalIgnoreCase
    $visit = $null
    $visit = {
        param($node)
        $color[$node] = 1
        $path.Add($node)
        if ($up.Contains($node)) {
            foreach ($next in @($up[$node])) {
                $c = $color[$next]
                if ($null -eq $c) { & $visit $next }
                elseif ($c -eq 1) {
                    $start = $path.IndexOf($next)
                    if ($start -ge 0) {
                        $cycle = @($path.GetRange($start, $path.Count - $start))
                        $minIdx = 0
                        for ($i = 1; $i -lt $cycle.Count; $i++) { if ($cmp.Compare($cycle[$i], $cycle[$minIdx]) -lt 0) { $minIdx = $i } }
                        $rotated = [string[]]@($cycle[$minIdx..($cycle.Count - 1)] + $(if ($minIdx -gt 0) { $cycle[0..($minIdx - 1)] } else { @() }))
                        $found[($rotated -join '|')] = $rotated
                    }
                }
            }
        }
        $path.RemoveAt($path.Count - 1)
        $color[$node] = 2
    }
    $nodes = [System.Collections.Generic.HashSet[string]]::new($cmp)
    foreach ($k in $up.Keys) { [void]$nodes.Add($k) }
    foreach ($k in $Model.index.membersByGroup.Keys) { [void]$nodes.Add($k) }
    foreach ($n in @(Get-FsSorted -InputObject @($nodes))) { if ($null -eq $color[$n]) { & $visit $n } }
    $cycles = @(foreach ($k in Get-FsSortedKeys $found) { , $found[$k] })
    $cache['all'] = [object[]]$cycles
    return $cache['all']
}

function Get-FsBroadPrincipalSet {
    <#
    .SYNOPSIS
        HashSet of broad principal ids plus every group that transitively contains one. Cached.
    .DESCRIPTION
        Never returns $null: a per-principal failure (malformed record, unresolved sid, etc. - real AD data
        is far messier than the fixtures) is recorded and skipped rather than aborting the whole set, since
        every caller assumes a valid HashSet is always available.
    #>
    [OutputType([System.Collections.Generic.HashSet[string]])]
    param([Parameter(Mandatory)] [System.Collections.IDictionary] $Model)
    $cache = Get-FsCacheTable -Model $Model -Name 'broad'
    if ($cache.Contains('set') -and $null -ne $cache['set']) { return , $cache['set'] }
    $set = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    try {
        $domainSids = [string[]]@($Model['domainSids'])
        $seeds = [System.Collections.Generic.List[string]]::new()
        foreach ($id in Get-FsSortedKeys $Model.principals) {
            try {
                $p = $Model.principals[$id]
                $sid = [string](Get-FsValue $p 'sid')
                if ([bool](Get-FsValue $p 'isBroad') -or ($sid -and (Test-FsBroadSid -Sid $sid -DomainSids $domainSids))) { $seeds.Add($id) }
            }
            catch { Write-Verbose "Get-FsBroadPrincipalSet: skipping principal '$id' ($($_.Exception.Message))" }
        }
        # ids referenced by ACEs or memberships without a principal record
        foreach ($id in @($Model.index.groupsByMember.Keys) + @($Model.index.referencedPrincipalIds)) {
            try {
                if ($id -match '^S-1-' -and -not $Model.principals.Contains($id) -and (Test-FsBroadSid -Sid $id -DomainSids $domainSids)) { $seeds.Add($id) }
            }
            catch { Write-Verbose "Get-FsBroadPrincipalSet: skipping referenced id '$id' ($($_.Exception.Message))" }
        }
        foreach ($id in $seeds) {
            try {
                [void]$set.Add($id)
                foreach ($g in @(Get-FsTransitiveGroups -Model $Model -PrincipalId $id)) { [void]$set.Add($g) }
            }
            catch { Write-Verbose "Get-FsBroadPrincipalSet: skipping closure for '$id' ($($_.Exception.Message))" }
        }
    }
    catch { Write-Warning "Get-FsBroadPrincipalSet: continuing with a partial broad-principal set ($($_.Exception.Message))" }
    $cache['set'] = $set
    # ,$set (not bare $set): PowerShell enumerates a returned collection onto the pipeline as
    # separate objects, so a bare `return $set` for an EMPTY HashSet emits zero objects and the
    # caller's `$broad = Get-FsBroadPrincipalSet ...` captures $null instead of an empty set - the
    # exact crash this function's docstring says it prevents. The comma stops the unroll.
    return , $set
}

function Get-FsBroadPrincipalIds {
    <# Sorted ids of broad principals plus groups that transitively contain one (e.g. FS01\Users contains Authenticated Users). #>
    [OutputType([string[]])]
    param([Parameter(Mandatory)] [System.Collections.IDictionary] $Model)
    return [string[]]@(Get-FsSorted -InputObject @(Get-FsBroadPrincipalSet -Model $Model))
}

function Test-FsBroadPrincipal {
    [OutputType([bool])]
    param([Parameter(Mandatory)] [System.Collections.IDictionary] $Model, [Parameter(Mandatory)] [string] $PrincipalId)
    return (Get-FsBroadPrincipalSet -Model $Model).Contains($PrincipalId)
}
