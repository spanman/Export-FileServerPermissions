<#
03 Inheritance Broken — protected folders compared with the nearest captured ancestor (nearest divergent
ancestor, else the share root): which inheritable ACEs disappeared, which were added, which changed rights,
and whether the protection is redundant (identical ACL).
#>

function Get-FsReportInheritanceBroken {
    [OutputType([hashtable])]
    param(
        [Parameter(Mandatory)] [System.Collections.IDictionary] $Model,
        [Parameter(Mandatory)] [System.Collections.IDictionary] $Options,
        [Parameter(Mandatory)] $Definition
    )
    $items = [System.Collections.Generic.List[object]]::new()
    $redundant = 0
    $labelFor = {
        param($principalId, $type)
        $label = Get-FsPrincipalName -Model $Model -Id $principalId
        if ($type -eq 'Deny') { $label += ' (Deny)' }
        New-FsRef -Kind Principal -Id $principalId -Label $label
    }
    $aceSet = {
        # (principal|type) -> sorted list of rights strings
        param($aces, [bool] $inheritableOnly)
        $set = @{}
        foreach ($ace in @($aces)) {
            if ($null -eq $ace) { continue }
            if ($inheritableOnly -and ([string](Get-FsValue $ace 'inheritanceFlags')) -notmatch 'ContainerInherit') { continue }
            $k = '{0}|{1}' -f [string](Get-FsValue $ace 'principalId'), [string](Get-FsValue $ace 'accessControlType')
            if (-not $set.Contains($k)) { $set[$k] = [System.Collections.Generic.List[string]]::new() }
            $set[$k].Add((Get-FsAceRightsText $ace))
        }
        foreach ($k in @($set.Keys)) { $set[$k] = @(Get-FsSorted -InputObject @($set[$k])) -join ', ' }
        return $set
    }
    foreach ($fid in Get-FsSortedKeys $Model.folders) {
        $f = $Model.folders[$fid]
        if (-not [bool](Get-FsValue $f 'isProtected')) { continue }
        $info = Get-FsResourceInfo -Model $Model -ResourceId $fid
        $ancestorId = [string](Get-FsValue $f 'nearestDivergentAncestorId')
        if (-not $ancestorId -or -not $Model.folders.Contains($ancestorId)) {
            $ancestorId = $null
            if ($info.shareId -and $Model.index.rootFolderByShare.Contains($info.shareId)) {
                $root = [string]$Model.index.rootFolderByShare[$info.shareId]
                if ($root -ne $fid -and $Model.folders.Contains($root)) { $ancestorId = $root }
            }
        }
        $mine = & $aceSet @($f['aces']) $false
        $theirs = if ($ancestorId) { & $aceSet @($Model.folders[$ancestorId]['aces']) $true } else { @{} }
        $removed = [System.Collections.Generic.List[object]]::new(); $added = [System.Collections.Generic.List[object]]::new(); $changed = [System.Collections.Generic.List[object]]::new()
        foreach ($k in Get-FsSortedKeys $theirs) {
            $p, $t = $k.Split('|', 2)
            if (-not $mine.Contains($k)) { $removed.Add((& $labelFor $p $t)) }
            elseif ($mine[$k] -ne $theirs[$k]) { $changed.Add((New-FsRef -Kind Principal -Id $p -Label ('{0}: {1} -> {2}' -f (Get-FsPrincipalName -Model $Model -Id $p), $theirs[$k], $mine[$k]))) }
        }
        foreach ($k in Get-FsSortedKeys $mine) {
            $p, $t = $k.Split('|', 2)
            if (-not $theirs.Contains($k)) { $added.Add((& $labelFor $p $t)) }
        }
        $isRedundant = ($null -ne $ancestorId -and $removed.Count -eq 0 -and $added.Count -eq 0 -and $changed.Count -eq 0)
        if ($isRedundant) { $redundant++ }
        $owner = [string](Get-FsValue $f 'ownerPrincipalId')
        $row = [ordered]@{
            Server          = (New-FsRef -Kind Server -Id $info.server)
            Resource        = (New-FsRef -Kind Resource -Id (Get-FsGrantPointRefId -Model $Model -ResourceId $fid))
            Path            = (New-FsCode $info.path)
            Owner           = $(if ($owner) { New-FsRef -Kind Principal -Id $owner } else { '' })
            'Compared with' = $(if ($ancestorId) { New-FsRef -Kind Resource -Id (Get-FsGrantPointRefId -Model $Model -ResourceId $ancestorId) } else { '' })
            Removed         = @($removed)
            Added           = @($added)
            Changed         = @($changed)
            'Explicit ACEs' = [int](Get-FsValue $f 'explicitAceCount')
            Redundant       = (ConvertTo-FsYesNo $isRedundant)
        }
        $items.Add(@{ server = $info.server; path = $info.path; row = $row })
    }
    $rows = Select-FsSortedRows -Items @($items) -Property 'server', 'path'
    $summary = '{0} protected folder(s); {1} redundant (ACL identical to the ancestor).' -f $rows.Count, $redundant
    return New-FsReportResult -Columns @('Server', 'Resource', 'Path', 'Owner', 'Compared with', 'Removed', 'Added', 'Changed', 'Explicit ACEs', 'Redundant') -Rows $rows -Summary $summary
}
