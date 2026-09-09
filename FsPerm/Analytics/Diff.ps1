<#
Change tracking between two snapshots of the same server.

Compare-FsSnapshots works directly on raw snapshot hashtables (the shape Import-FsSnapshot returns, and
what $Model.snapshots[server] holds per entry - see Merge-FsModel), not on the merged $Model. This keeps a
diff a pure function of exactly the two snapshots being compared, independent of what else has been
scanned. It is deliberately re-derivable on every run: nothing here is stateful, so re-rendering the vault
never needs to parse or preserve prior output (see the Changelog note in the renderer).

Row shape: ordered hashtables with a 'verdict' column; Principal/Resource cells are New-FsRef (resolved by
the renderer against $Model, not here), paths/rights are New-FsCode.
#>

# ---------------------------------------------------------------- scope alignment

function Get-FsSnapshotDepth {
    [OutputType([int])]
    param([Parameter(Mandatory)] [System.Collections.IDictionary] $Snapshot)
    $d = Get-FsValue $Snapshot 'scope.depth'
    return $(if ($null -eq $d) { 0 } else { [int]$d })
}

function Test-FsShareNameInScope {
    <# Whether a share name passes one snapshot's -IncludeShare / -ExcludeShare wildcard filters. #>
    [OutputType([bool])]
    param([Parameter(Mandatory)] [string] $ShareName, [System.Collections.IDictionary] $Scope)
    if ($null -eq $Scope) { return $true }
    $includes = @(Get-FsValue $Scope 'includeShare')
    $excludes = @(Get-FsValue $Scope 'excludeShare')
    if ($includes.Count -gt 0) {
        $match = $false
        foreach ($pattern in $includes) { if ($ShareName -like $pattern) { $match = $true; break } }
        if (-not $match) { return $false }
    }
    foreach ($pattern in $excludes) { if ($ShareName -like $pattern) { return $false } }
    return $true
}

function Get-FsShareIdentityKey {
    [OutputType([string])]
    param([Parameter(Mandatory)] [System.Collections.IDictionary] $Share)
    return '{0}|{1}' -f ([string](Get-FsValue $Share 'server')), ([string](Get-FsValue $Share 'name')).ToLowerInvariant()
}

function Get-FsFolderIdentityKey {
    [OutputType([string])]
    param([Parameter(Mandatory)] [System.Collections.IDictionary] $Folder)
    return '{0}|{1}' -f ([string](Get-FsValue $Folder 'server')), (ConvertTo-FsNormalizedPath ([string](Get-FsValue $Folder 'localPath')))
}

# ---------------------------------------------------------------- shares / folders

function Compare-FsKeyedRecords {
    <#
    .SYNOPSIS
        Generic Added/Removed/Modified diff over two lists keyed by -KeyScript, comparing the fields in -Compare.
    .PARAMETER InScope
        Optional predicate; a record failing it in either snapshot is skipped entirely (out of the comparable scope).
    #>
    [OutputType([object[]])]
    param(
        [Parameter(Mandatory)] [AllowEmptyCollection()] [object[]] $Previous,
        [Parameter(Mandatory)] [AllowEmptyCollection()] [object[]] $Latest,
        [Parameter(Mandatory)] [scriptblock] $KeyScript,
        [Parameter(Mandatory)] [string[]] $Compare,
        [scriptblock] $InScope,
        [Parameter(Mandatory)] [string] $RefKind
    )
    $prevByKey = @{}; $latestByKey = @{}
    foreach ($r in @($Previous)) { if ($InScope -and -not (& $InScope $r)) { continue }; $prevByKey[(& $KeyScript $r)] = $r }
    foreach ($r in @($Latest)) { if ($InScope -and -not (& $InScope $r)) { continue }; $latestByKey[(& $KeyScript $r)] = $r }
    $keys = @($prevByKey.Keys) + @($latestByKey.Keys) | Get-FsSorted -Unique
    $rows = [System.Collections.Generic.List[object]]::new()
    foreach ($key in $keys) {
        $p = $prevByKey[$key]; $l = $latestByKey[$key]
        if ($null -eq $p) {
            $rows.Add([ordered]@{ verdict = 'Added'; ref = (New-FsRef -Kind $RefKind -Id ([string](Get-FsValue $l 'id'))); record = $l; changes = @() })
        }
        elseif ($null -eq $l) {
            $rows.Add([ordered]@{ verdict = 'Removed'; ref = (New-FsRef -Kind $RefKind -Id ([string](Get-FsValue $p 'id'))); record = $p; changes = @() })
        }
        else {
            $changes = [System.Collections.Generic.List[object]]::new()
            foreach ($field in $Compare) {
                $before = Get-FsValue $p $field; $after = Get-FsValue $l $field
                if ([string]$before -ne [string]$after) { $changes.Add(@{ field = $field; before = $before; after = $after }) }
            }
            if ($changes.Count -gt 0) {
                $rows.Add([ordered]@{ verdict = 'Modified'; ref = (New-FsRef -Kind $RefKind -Id ([string](Get-FsValue $l 'id'))); record = $l; changes = @($changes) })
            }
        }
    }
    return @($rows)
}

function Compare-FsShares {
    [OutputType([object[]])]
    param([System.Collections.IDictionary[]] $Previous, [System.Collections.IDictionary[]] $Latest)
    $rows = Compare-FsKeyedRecords -Previous $Previous -Latest $Latest -RefKind Resource -Compare 'localPath', 'description' -KeyScript { param($s) Get-FsShareIdentityKey $s }
    return @(foreach ($r in $rows) {
            [ordered]@{
                Server      = [string](Get-FsValue $r.record 'server')
                Share       = $r.ref
                Verdict     = $r.verdict
                Path        = New-FsCode ([string](Get-FsValue $r.record 'localPath'))
                Description = [string](Get-FsValue $r.record 'description')
                Changes     = [string[]]@($r.changes | ForEach-Object { '{0}: {1} -> {2}' -f $_.field, $_.before, $_.after })
            }
        })
}

function Compare-FsFolders {
    [OutputType([object[]])]
    param(
        [System.Collections.IDictionary[]] $Previous, [System.Collections.IDictionary[]] $Latest,
        [Parameter(Mandatory)] [int] $EffDepth,
        [Parameter(Mandatory)] [AllowEmptyCollection()] [System.Collections.Generic.HashSet[string]] $ExcludedShareKeys
    )
    $inScope = {
        param($f)
        if ([int](Get-FsValue $f 'depth') -gt $EffDepth) { return $false }
        foreach ($name in @(Get-FsValue $f 'shareNames')) {
            $k = '{0}|{1}' -f ([string](Get-FsValue $f 'server')), ([string]$name).ToLowerInvariant()
            if ($ExcludedShareKeys.Contains($k)) { return $false }
        }
        return $true
    }
    $rows = Compare-FsKeyedRecords -Previous $Previous -Latest $Latest -RefKind Resource -Compare 'isProtected', 'ownerPrincipalId' -InScope $inScope -KeyScript { param($f) Get-FsFolderIdentityKey $f }
    return @(foreach ($r in $rows) {
            $verdict = switch ($r.verdict) { 'Added' { 'NewlyDivergent' } 'Removed' { 'NoLongerDivergent' } default { 'Modified' } }
            [ordered]@{
                Server  = [string](Get-FsValue $r.record 'server')
                Folder  = $r.ref
                Verdict = $verdict
                Changes = [string[]]@($r.changes | ForEach-Object { '{0}: {1} -> {2}' -f $_.field, $_.before, $_.after })
            }
        })
}

# ---------------------------------------------------------------- ACEs

function Get-FsSnapshotAceGroups {
    <# resourceId|principalId|accessType|isInherited -> @{ resourceId server path layer principalId type isInherited tuples(sorted string[]) rightsTexts(sorted string[]) } #>
    [OutputType([hashtable])]
    param([Parameter(Mandatory)] [System.Collections.IDictionary] $Snapshot)
    $groups = @{}
    $addAce = {
        param($resourceId, $server, $path, $layer, $ace)
        $principalId = [string](Get-FsValue $ace 'principalId')
        $type = [string](Get-FsValue $ace 'accessControlType')
        $inherited = [bool](Get-FsValue $ace 'isInherited')
        $mask = Get-FsAceMask $ace
        $inh = [string](Get-FsValue $ace 'inheritanceFlags')
        $prop = [string](Get-FsValue $ace 'propagationFlags')
        $key = '{0}|{1}|{2}|{3}' -f $resourceId, $principalId, $type, $inherited
        if (-not $groups.Contains($key)) {
            $groups[$key] = @{ resourceId = $resourceId; server = $server; path = $path; layer = $layer; principalId = $principalId; type = $type; isInherited = $inherited
                tuples = [System.Collections.Generic.List[string]]::new(); rightsTexts = [System.Collections.Generic.List[string]]::new() }
        }
        $groups[$key].tuples.Add("$mask|$inh|$prop")
        $groups[$key].rightsTexts.Add((Get-FsAceRightsText $ace))
    }
    foreach ($share in @(Get-FsValue $Snapshot 'shares')) {
        $sid = [string](Get-FsValue $share 'id'); $server = [string](Get-FsValue $share 'server'); $path = [string](Get-FsValue $share 'uncPath')
        foreach ($ace in @(Get-FsValue $share 'aces')) { & $addAce $sid $server $path 'Share' $ace }
    }
    foreach ($folder in @(Get-FsValue $Snapshot 'folders')) {
        $fid = [string](Get-FsValue $folder 'id'); $server = [string](Get-FsValue $folder 'server'); $path = [string](Get-FsValue $folder 'uncPath')
        foreach ($ace in @(Get-FsValue $folder 'aces')) { & $addAce $fid $server $path 'NTFS' $ace }
    }
    return $groups
}

function Compare-FsAces {
    [OutputType([object[]])]
    param(
        [Parameter(Mandatory)] [System.Collections.IDictionary] $Previous, [Parameter(Mandatory)] [System.Collections.IDictionary] $Latest,
        [Parameter(Mandatory)] [AllowEmptyCollection()] [System.Collections.Generic.HashSet[string]] $ExcludedResourceIds
    )
    $prevGroups = Get-FsSnapshotAceGroups -Snapshot $Previous
    $latestGroups = Get-FsSnapshotAceGroups -Snapshot $Latest
    $keys = @($prevGroups.Keys) + @($latestGroups.Keys) | Get-FsSorted -Unique
    $rows = [System.Collections.Generic.List[object]]::new()
    foreach ($key in $keys) {
        $p = $prevGroups[$key]; $l = $latestGroups[$key]
        $resourceId = $(if ($l) { $l.resourceId } else { $p.resourceId })
        if ($ExcludedResourceIds.Contains($resourceId)) { continue }
        if ($null -eq $p) {
            $rows.Add([ordered]@{ Server = $l.server; Resource = (New-FsRef -Kind Resource -Id $resourceId); Layer = $l.layer
                    Principal = (New-FsRef -Kind Principal -Id $l.principalId); Type = $l.type; Inherited = $l.isInherited
                    Verdict = 'Added'; Before = ''; After = ($l.rightsTexts | Get-FsSorted -Unique) -join ', ' })
        }
        elseif ($null -eq $l) {
            $rows.Add([ordered]@{ Server = $p.server; Resource = (New-FsRef -Kind Resource -Id $resourceId); Layer = $p.layer
                    Principal = (New-FsRef -Kind Principal -Id $p.principalId); Type = $p.type; Inherited = $p.isInherited
                    Verdict = 'Removed'; Before = ($p.rightsTexts | Get-FsSorted -Unique) -join ', '; After = '' })
        }
        else {
            $sigBefore = (@($p.tuples) | Get-FsSorted) -join '||'
            $sigAfter = (@($l.tuples) | Get-FsSorted) -join '||'
            if ($sigBefore -ne $sigAfter) {
                $rows.Add([ordered]@{ Server = $l.server; Resource = (New-FsRef -Kind Resource -Id $resourceId); Layer = $l.layer
                        Principal = (New-FsRef -Kind Principal -Id $l.principalId); Type = $l.type; Inherited = $l.isInherited
                        Verdict = 'Modified'; Before = ($p.rightsTexts | Get-FsSorted -Unique) -join ', '; After = ($l.rightsTexts | Get-FsSorted -Unique) -join ', ' })
            }
        }
    }
    return @(Get-FsSorted -InputObject @($rows) -Property 'Server', 'Verdict')
}

# ---------------------------------------------------------------- memberships and principals

function Compare-FsMemberships {
    [OutputType([object[]])]
    param([Parameter(Mandatory)] [System.Collections.IDictionary] $Previous, [Parameter(Mandatory)] [System.Collections.IDictionary] $Latest)
    $key = { param($m) '{0}|{1}|{2}' -f (Get-FsValue $m 'groupId'), (Get-FsValue $m 'memberId'), (Get-FsValue $m 'kind') }
    $prevSet = @{}; foreach ($m in @(Get-FsValue $Previous 'memberships')) { $prevSet[(& $key $m)] = $m }
    $latestSet = @{}; foreach ($m in @(Get-FsValue $Latest 'memberships')) { $latestSet[(& $key $m)] = $m }
    $keys = @($prevSet.Keys) + @($latestSet.Keys) | Get-FsSorted -Unique
    $latestAces = Get-FsSnapshotAceGroups -Snapshot $Latest
    $rows = [System.Collections.Generic.List[object]]::new()
    foreach ($k in $keys) {
        $inPrev = $prevSet.Contains($k); $inLatest = $latestSet.Contains($k)
        if ($inPrev -eq $inLatest) { continue }
        $m = $(if ($inLatest) { $latestSet[$k] } else { $prevSet[$k] })
        $groupId = [string](Get-FsValue $m 'groupId')
        $affected = @($latestAces.Values | Where-Object { $_.principalId -eq $groupId -and $_.type -eq 'Allow' } | Select-Object -ExpandProperty resourceId -Unique).Count
        $rows.Add([ordered]@{
                Group             = (New-FsRef -Kind Principal -Id $groupId)
                Member            = (New-FsRef -Kind Principal -Id ([string](Get-FsValue $m 'memberId')))
                Kind              = [string](Get-FsValue $m 'kind')
                Verdict           = $(if ($inLatest) { 'Added' } else { 'Removed' })
                ResourcesAffected = $affected
            })
    }
    return @(Get-FsSorted -InputObject @($rows) -Property 'Verdict', 'Group')
}

$script:FsPrincipalDiffFields = 'ad.enabled', 'name', 'ad.department', 'ad.title', 'ad.manager.sid', 'ad.description', 'ad.accountExpires', 'ad.managedBy.sid', 'ad.groupType'

function Get-FsSnapshotReferencedPrincipalIds {
    <# Ids referenced by at least one ACE (share or folder), membership edge, or folder owner in a raw snapshot. #>
    [OutputType([System.Collections.Generic.HashSet[string]])]
    param([Parameter(Mandatory)] [System.Collections.IDictionary] $Snapshot)
    $set = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    foreach ($share in @(Get-FsValue $Snapshot 'shares')) { foreach ($ace in @(Get-FsValue $share 'aces')) { [void]$set.Add([string](Get-FsValue $ace 'principalId')) } }
    foreach ($folder in @(Get-FsValue $Snapshot 'folders')) {
        foreach ($ace in @(Get-FsValue $folder 'aces')) { [void]$set.Add([string](Get-FsValue $ace 'principalId')) }
        $owner = Get-FsValue $folder 'ownerPrincipalId'; if ($owner) { [void]$set.Add([string]$owner) }
    }
    foreach ($m in @(Get-FsValue $Snapshot 'memberships')) {
        [void]$set.Add([string](Get-FsValue $m 'groupId')); [void]$set.Add([string](Get-FsValue $m 'memberId'))
    }
    # ,$set (not bare $set): PowerShell enumerates a returned collection onto the pipeline as
    # separate objects, so an EMPTY HashSet returned bare emits zero objects and the caller
    # captures $null instead of an empty set.
    return , $set
}

function Compare-FsPrincipals {
    [OutputType([object[]])]
    param([Parameter(Mandatory)] [System.Collections.IDictionary] $Previous, [Parameter(Mandatory)] [System.Collections.IDictionary] $Latest)
    $prevP = Get-FsValue $Previous 'principals'; $latestP = Get-FsValue $Latest 'principals'
    $prevRef = Get-FsSnapshotReferencedPrincipalIds -Snapshot $Previous
    $latestRef = Get-FsSnapshotReferencedPrincipalIds -Snapshot $Latest
    $ids = @($prevP.Keys) + @($latestP.Keys) | Get-FsSorted -Unique
    $rows = [System.Collections.Generic.List[object]]::new()
    foreach ($id in $ids) {
        $inPrev = $prevP.Contains($id); $inLatest = $latestP.Contains($id)
        if ($inPrev -and $inLatest) {
            foreach ($field in $script:FsPrincipalDiffFields) {
                $before = Get-FsValue $prevP[$id] $field; $after = Get-FsValue $latestP[$id] $field
                if ([string]$before -ne [string]$after) {
                    $rows.Add([ordered]@{ Principal = (New-FsRef -Kind Principal -Id $id); Verdict = 'AttributeChanged'; Attribute = $field; Before = $before; After = $after })
                }
            }
        }
        elseif ($inLatest -and -not $inPrev -and $latestRef.Contains($id)) {
            $rows.Add([ordered]@{ Principal = (New-FsRef -Kind Principal -Id $id); Verdict = 'NewlyReferenced'; Attribute = ''; Before = ''; After = '' })
        }
        elseif ($inPrev -and -not $inLatest -and $prevRef.Contains($id) -and -not $latestRef.Contains($id)) {
            $rows.Add([ordered]@{ Principal = (New-FsRef -Kind Principal -Id $id); Verdict = 'NoLongerReferenced'; Attribute = ''; Before = ''; After = '' })
        }
    }
    return @(Get-FsSorted -InputObject @($rows) -Property 'Verdict', 'Attribute')
}

# ---------------------------------------------------------------- entry points

function Compare-FsSnapshots {
    <#
    .SYNOPSIS
        Diffs two raw snapshots of the same server (see Import-FsSnapshot / $Model.snapshots[server]).
        Returns $null when -Previous is $null (first scan; nothing to compare).
    #>
    [OutputType([hashtable])]
    param([AllowNull()] [System.Collections.IDictionary] $Previous, [Parameter(Mandatory)] [System.Collections.IDictionary] $Latest)
    if ($null -eq $Previous) { return $null }

    $prevDepth = Get-FsSnapshotDepth $Previous
    $latestDepth = Get-FsSnapshotDepth $Latest
    $effDepth = [Math]::Min($prevDepth, $latestDepth)
    $banners = [System.Collections.Generic.List[string]]::new()

    $prevShareNames = @(@(Get-FsValue $Previous 'shares') | ForEach-Object { [string](Get-FsValue $_ 'name') })
    $latestShareNames = @(@(Get-FsValue $Latest 'shares') | ForEach-Object { [string](Get-FsValue $_ 'name') })
    $allShareNames = @($prevShareNames + $latestShareNames | Get-FsSorted -Unique)
    $excludedShareKeys = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    $excludedShareNames = [System.Collections.Generic.List[string]]::new()
    foreach ($name in $allShareNames) {
        $inBoth = (Test-FsShareNameInScope -ShareName $name -Scope (Get-FsValue $Previous 'scope')) -and (Test-FsShareNameInScope -ShareName $name -Scope (Get-FsValue $Latest 'scope'))
        if (-not $inBoth) {
            $server = [string](Get-FsValue $Latest 'server.name')
            [void]$excludedShareKeys.Add(('{0}|{1}' -f $server, $name.ToLowerInvariant()))
            $excludedShareNames.Add($name)
        }
    }
    if ($excludedShareNames.Count -gt 0) {
        $banners.Add("Share filter differs between scans: excluded from this diff: $($excludedShareNames -join ', ')")
    }

    $inScopeShares = { -not $excludedShareKeys.Contains((Get-FsShareIdentityKey $_)) }
    $prevSharesInScope = @(@(Get-FsValue $Previous 'shares') | Where-Object $inScopeShares)
    $latestSharesInScope = @(@(Get-FsValue $Latest 'shares') | Where-Object $inScopeShares)
    $shares = Compare-FsShares -Previous $prevSharesInScope -Latest $latestSharesInScope

    $removedOrAddedShareResourceIds = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    foreach ($s in $shares) { if ($s.Verdict -ne 'Modified') { [void]$removedOrAddedShareResourceIds.Add([string]$s.Share.id) } }

    $folders = Compare-FsFolders -Previous @(Get-FsValue $Previous 'folders') -Latest @(Get-FsValue $Latest 'folders') -EffDepth $effDepth -ExcludedShareKeys $excludedShareKeys
    $excludedResourceIds = [System.Collections.Generic.HashSet[string]]::new($removedOrAddedShareResourceIds, [System.StringComparer]::OrdinalIgnoreCase)
    foreach ($f in $folders) { if ($f.Verdict -ne 'Modified') { [void]$excludedResourceIds.Add([string]$f.Folder.id) } }
    # Folders deeper than effDepth never entered the folders comparison at all (out of scope, not "added"/"removed"),
    # so their ACEs must be excluded here explicitly or a depth mismatch would surface as ACE noise.
    foreach ($f in @(Get-FsValue $Previous 'folders') + @(Get-FsValue $Latest 'folders')) {
        if ([int](Get-FsValue $f 'depth') -gt $effDepth) { [void]$excludedResourceIds.Add([string](Get-FsValue $f 'id')) }
    }

    if ($prevDepth -ne $latestDepth) {
        $deeper = @(@(Get-FsValue $Latest 'folders') | Where-Object { [int](Get-FsValue $_ 'depth') -gt $effDepth }).Count
        $banners.Add("Depth differs (previous scan depth $prevDepth, latest $latestDepth): folder and ACE comparison limited to depth <= $effDepth; $deeper deeper folder(s) in the latest scan were not compared.")
    }

    $aces = Compare-FsAces -Previous $Previous -Latest $Latest -ExcludedResourceIds $excludedResourceIds
    $memberships = Compare-FsMemberships -Previous $Previous -Latest $Latest
    $principals = Compare-FsPrincipals -Previous $Previous -Latest $Latest

    $summary = [ordered]@{
        sharesAdded            = @($shares | Where-Object Verdict -eq 'Added').Count
        sharesRemoved          = @($shares | Where-Object Verdict -eq 'Removed').Count
        sharesModified         = @($shares | Where-Object Verdict -eq 'Modified').Count
        foldersNewlyDivergent  = @($folders | Where-Object Verdict -eq 'NewlyDivergent').Count
        foldersNoLongerDivergent = @($folders | Where-Object Verdict -eq 'NoLongerDivergent').Count
        foldersModified        = @($folders | Where-Object Verdict -eq 'Modified').Count
        acesAdded              = @($aces | Where-Object Verdict -eq 'Added').Count
        acesRemoved            = @($aces | Where-Object Verdict -eq 'Removed').Count
        acesModified           = @($aces | Where-Object Verdict -eq 'Modified').Count
        membershipsAdded       = @($memberships | Where-Object Verdict -eq 'Added').Count
        membershipsRemoved     = @($memberships | Where-Object Verdict -eq 'Removed').Count
        principalsChanged      = @($principals | Where-Object Verdict -eq 'AttributeChanged').Count
        principalsNew          = @($principals | Where-Object Verdict -eq 'NewlyReferenced').Count
        principalsRemoved      = @($principals | Where-Object Verdict -eq 'NoLongerReferenced').Count
    }
    $summaryText = '+{0}/-{1} grants ({2} changed), +{3}/-{4} shares, +{5}/-{6} folders, +{7}/-{8} members, +{9}/-{10} principals' -f `
        $summary.acesAdded, $summary.acesRemoved, $summary.acesModified, `
        $summary.sharesAdded, $summary.sharesRemoved, `
        $summary.foldersNewlyDivergent, $summary.foldersNoLongerDivergent, `
        $summary.membershipsAdded, $summary.membershipsRemoved, `
        $summary.principalsNew, $summary.principalsRemoved

    return @{
        server         = [string](Get-FsValue $Latest 'server.name')
        fromScanId     = [string](Get-FsValue $Previous 'scanId')
        toScanId       = [string](Get-FsValue $Latest 'scanId')
        fromTimestamp  = [string](Get-FsValue $Previous 'timestamp')
        toTimestamp    = [string](Get-FsValue $Latest 'timestamp')
        depthCompared  = $effDepth
        banners        = [string[]]@($banners)
        summary        = $summary
        summaryText    = $summaryText
        shares         = $shares
        folders        = $folders
        aces           = $aces
        memberships    = $memberships
        principals     = $principals
    }
}

function Get-FsChangeSets {
    <#
    .SYNOPSIS
        Diffs for every consecutive snapshot pair per server (newest pair first). Memoized on $Model.
    .OUTPUTS
        hashtable server -> object[] of Compare-FsSnapshots results (never $null entries; a server with only
        one snapshot gets an empty array).
    #>
    [OutputType([hashtable])]
    param([Parameter(Mandatory)] [System.Collections.IDictionary] $Model)
    $cache = Get-FsCacheTable -Model $Model -Name 'changeSets'
    if ($cache.Contains('all')) { return $cache['all'] }
    $out = @{}
    foreach ($server in Get-FsSortedKeys $Model.snapshots) {
        $snaps = @($Model.snapshots[$server])
        $diffs = [System.Collections.Generic.List[object]]::new()
        for ($i = 0; $i -lt $snaps.Count - 1; $i++) {
            $d = Compare-FsSnapshots -Previous $snaps[$i + 1] -Latest $snaps[$i]
            if ($null -ne $d) { $diffs.Add($d) }
        }
        $out[$server] = @($diffs)
    }
    $cache['all'] = $out
    return $out
}

function Get-FsChangedEntityIds {
    <#
    .SYNOPSIS
        Ids of every share/folder/principal appearing in the newest change set of any server (drives the
        'changed' tag). Combined across all servers.
    #>
    [OutputType([System.Collections.Generic.HashSet[string]])]
    param([Parameter(Mandatory)] [System.Collections.IDictionary] $Model)
    $set = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    $sets = Get-FsChangeSets -Model $Model
    foreach ($server in $sets.Keys) {
        $diffs = @($sets[$server])
        if ($diffs.Count -eq 0) { continue }
        $latest = $diffs[0]
        foreach ($row in @($latest.shares)) { [void]$set.Add([string]$row.Share.id) }
        foreach ($row in @($latest.folders)) { [void]$set.Add([string]$row.Folder.id) }
        foreach ($row in @($latest.aces)) { [void]$set.Add([string]$row.Resource.id); [void]$set.Add([string]$row.Principal.id) }
        foreach ($row in @($latest.memberships)) { [void]$set.Add([string]$row.Group.id); [void]$set.Add([string]$row.Member.id) }
        foreach ($row in @($latest.principals)) { [void]$set.Add([string]$row.Principal.id) }
    }
    # ,$set (not bare $set): PowerShell enumerates a returned collection onto the pipeline as
    # separate objects, so an EMPTY HashSet returned bare emits zero objects and the caller
    # captures $null instead of an empty set (harmless here since the only caller uses foreach,
    # which no-ops over $null, but every other Get-Fs*Set function in this codebase honors its
    # declared HashSet OutputType, so this one should too).
    return , $set
}
