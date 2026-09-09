<#
09 Over-permissioned Groups — non-broad groups ranked by the resources they grant (Full / Modify+ / total,
evaluated with the group's own token) and how many users that reaches. Admin-allowlisted groups go to the appendix.
#>

function Get-FsReportOverPermissionedGroups {
    [OutputType([hashtable])]
    param(
        [Parameter(Mandatory)] [System.Collections.IDictionary] $Model,
        [Parameter(Mandatory)] [System.Collections.IDictionary] $Options,
        [Parameter(Mandatory)] $Definition
    )
    $broad = Get-FsBroadPrincipalSet -Model $Model
    $items = [System.Collections.Generic.List[object]]::new()
    $appendix = [System.Collections.Generic.List[object]]::new()
    foreach ($gid in @(Get-FsGroupPrincipalIds -Model $Model)) {
        if ($broad.Contains($gid)) { continue }
        $rows = @(Get-FsEffectiveAccess -Model $Model -PrincipalId $gid -ExcludeBroad)
        if ($rows.Count -eq 0) { continue }
        $sum = Get-FsReachSummary -Rows $rows
        $users = @(Get-FsTransitiveMembers -Model $Model -GroupId $gid -UsersOnly)
        $g = $Model.principals[$gid]
        $row = [ordered]@{
            Rank              = 0
            Group             = (New-FsRef -Kind Principal -Id $gid)
            Kind              = (Get-FsPrincipalKindLabel -Kind ([string](Get-FsValue $g 'kind')))
            Users             = $users.Count
            Full              = $sum.full
            'Modify+'         = $sum.modifyPlus
            'Total resources' = $sum.total
            'Highest level'   = $sum.highest
            Servers           = @($sum.servers | ForEach-Object { New-FsRef -Kind Server -Id $_ })
            Resources         = @($rows | ForEach-Object { New-FsRef -Kind Resource -Id $_.resourceId })
        }
        $item = @{ full = -$sum.full; mod = -$sum.modifyPlus; total = -$sum.total; users = -$users.Count; name = (Get-FsPrincipalName -Model $Model -Id $gid); principalId = $gid; row = $row }
        if (Test-FsAdminPrincipal -Model $Model -Options $Options -PrincipalId $gid) { $appendix.Add($item) } else { $items.Add($item) }
    }
    $sortBy = 'full', 'mod', 'total', 'users', 'name', 'principalId'
    $ranked = @(Select-FsSortedRows -Items @($items) -Property $sortBy)
    $top = [int]$Options['TopN']
    if ($top -gt 0 -and $ranked.Count -gt $top) { $ranked = @($ranked[0..($top - 1)]) }
    for ($i = 0; $i -lt $ranked.Count; $i++) { $ranked[$i]['Rank'] = $i + 1 }
    $appendixRows = @(Select-FsSortedRows -Items @($appendix) -Property $sortBy)
    for ($i = 0; $i -lt $appendixRows.Count; $i++) { $appendixRows[$i]['Rank'] = $i + 1 }
    $summary = 'Top {0} of {1} group(s) granting access; {2} admin-allowlisted group(s) listed in the appendix.' -f $ranked.Count, $items.Count, $appendixRows.Count
    return New-FsReportResult -Columns @('Rank', 'Group', 'Kind', 'Users', 'Full', 'Modify+', 'Total resources', 'Highest level', 'Servers', 'Resources') -Rows $ranked -Summary $summary -AppendixTitle 'Admin allowlist (excluded from the ranking)' -AppendixRows $appendixRows
}
