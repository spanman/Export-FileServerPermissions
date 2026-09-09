<#
07 Orphaned and Unresolved Principals — every ACE and membership edge that references a SID which no longer
resolves (Orphaned) or belongs to an unreachable / foreign domain (Unresolved).
#>

function Get-FsReportOrphanedPrincipals {
    [OutputType([hashtable])]
    param(
        [Parameter(Mandatory)] [System.Collections.IDictionary] $Model,
        [Parameter(Mandatory)] [System.Collections.IDictionary] $Options,
        [Parameter(Mandatory)] $Definition
    )
    $categoryOf = {
        param($id)
        $p = Get-FsModelPrincipal -Model $Model -Id $id
        $kind = [string](Get-FsValue $p 'kind'); $res = [string](Get-FsValue $p 'resolution')
        if ($kind -eq 'OrphanedSid' -or $res -eq 'Orphaned') { return 'Orphaned' }
        if ($kind -eq 'Foreign' -or $res -eq 'LookupFailed' -or (Get-FsValue $p '_synthetic') -eq $true) { return 'Unresolved' }
        return $null
    }
    $items = [System.Collections.Generic.List[object]]::new()
    $principals = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    $orphaned = 0; $unresolved = 0
    $add = {
        param($category, $id, $context, $server, $whereRef, $path, $layer, $rights, $type, $inherited, $sortPath)
        $p = Get-FsModelPrincipal -Model $Model -Id $id
        $row = [ordered]@{
            Category   = $category
            Principal  = (New-FsRef -Kind Principal -Id $id)
            SID        = (New-FsCode ([string](Get-FsValue $p 'sid')))
            Resolution = [string](Get-FsValue $p 'resolution')
            Error      = [string](Get-FsValue $p 'resolutionError')
            Context    = $context
            Server     = $(if ($server) { New-FsRef -Kind Server -Id $server } else { '' })
            Where      = $whereRef
            Path       = (New-FsCode $path)
            Layer      = $layer
            Rights     = (New-FsCode $rights)
            Type       = $type
            Inherited  = $inherited
        }
        $items.Add(@{ cat = $(if ($category -eq 'Orphaned') { 0 } else { 1 }); principalId = $id; ctx = $(if ($context -eq 'ACE') { 0 } else { 1 }); server = [string]$server; path = $sortPath; row = $row })
        if ($principals.Add($id)) { if ($category -eq 'Orphaned') { $orphaned++ } else { $unresolved++ } }
    }
    foreach ($e in @(Get-FsAceEntries -Model $Model)) {
        $cat = & $categoryOf $e.principalId
        if (-not $cat) { continue }
        & $add $cat $e.principalId 'ACE' $e.server (New-FsRef -Kind Resource -Id $e.refId) $e.path $e.layer $e.rights $e.type (ConvertTo-FsYesNo $e.isInherited) $e.path
    }
    foreach ($m in @($Model.memberships)) {
        $g = [string](Get-FsValue $m 'groupId'); $mem = [string](Get-FsValue $m 'memberId')
        foreach ($id in @($g, $mem)) {
            $cat = & $categoryOf $id
            if (-not $cat) { continue }
            $other = if ($id -eq $mem) { $g } else { $mem }
            $src = [string](Get-FsValue $m 'source')
            $server = if ($src -like 'Local:*') { $src.Substring(6) } else { '' }
            & $add $cat $id 'Membership' $server (New-FsRef -Kind Principal -Id $other) '' 'Membership' ([string](Get-FsValue $m 'kind')) $(if ($id -eq $mem) { 'member of' } else { 'contains' }) '' (Get-FsPrincipalName -Model $Model -Id $other)
        }
    }
    $rows = Select-FsSortedRows -Items @($items) -Property 'cat', 'principalId', 'ctx', 'server', 'path'
    $summary = '{0} orphaned and {1} unresolved principal(s) referenced in {2} place(s).' -f $orphaned, $unresolved, $rows.Count
    return New-FsReportResult -Columns @('Category', 'Principal', 'SID', 'Resolution', 'Error', 'Context', 'Server', 'Where', 'Path', 'Layer', 'Rights', 'Type', 'Inherited') -Rows $rows -Summary $summary
}
