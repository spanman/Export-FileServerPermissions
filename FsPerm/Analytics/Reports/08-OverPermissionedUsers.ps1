<#
08 Over-permissioned Users — top TopN users by Full / Modify+ / total reach through specific (non-broad)
grants, from the inverted per-resource reach table. Admin-allowlisted users go to the appendix.
#>

function Get-FsReportOverPermissionedUsers {
    [OutputType([hashtable])]
    param(
        [Parameter(Mandatory)] [System.Collections.IDictionary] $Model,
        [Parameter(Mandatory)] [System.Collections.IDictionary] $Options,
        [Parameter(Mandatory)] $Definition
    )
    $reach = Get-FsUserReachTable -Model $Model
    $items = [System.Collections.Generic.List[object]]::new()
    $appendix = [System.Collections.Generic.List[object]]::new()
    foreach ($uid in Get-FsSortedKeys $reach) {
        $rows = @($reach[$uid])
        if ($rows.Count -eq 0) { continue }
        $sum = Get-FsReachSummary -Rows $rows
        $s = Get-FsUserStatus -Model $Model -Options $Options -PrincipalId $uid
        $firstHops = @(Get-FsSorted -InputObject @($rows | ForEach-Object { if ($_.via.Count -gt 0) { $_.via[0] } }) -Unique)
        $row = [ordered]@{
            Rank              = 0
            User              = (New-FsRef -Kind Principal -Id $uid)
            Enabled           = (ConvertTo-FsYesNo $s.enabled)
            Department        = $s.department
            Full              = $sum.full
            'Modify+'         = $sum.modifyPlus
            'Total resources' = $sum.total
            'Highest level'   = $sum.highest
            Servers           = @($sum.servers | ForEach-Object { New-FsRef -Kind Server -Id $_ })
            'Via groups'      = @($firstHops | ForEach-Object { New-FsRef -Kind Principal -Id $_ })
        }
        $item = @{ full = -$sum.full; mod = -$sum.modifyPlus; total = -$sum.total; name = (Get-FsPrincipalName -Model $Model -Id $uid); principalId = $uid; row = $row }
        if (Test-FsAdminPrincipal -Model $Model -Options $Options -PrincipalId $uid) { $appendix.Add($item) } else { $items.Add($item) }
    }
    $sortBy = 'full', 'mod', 'total', 'name', 'principalId'
    $ranked = @(Select-FsSortedRows -Items @($items) -Property $sortBy)
    $top = [int]$Options['TopN']
    if ($top -gt 0 -and $ranked.Count -gt $top) { $ranked = @($ranked[0..($top - 1)]) }
    for ($i = 0; $i -lt $ranked.Count; $i++) { $ranked[$i]['Rank'] = $i + 1 }
    $appendixRows = @(Select-FsSortedRows -Items @($appendix) -Property $sortBy)
    for ($i = 0; $i -lt $appendixRows.Count; $i++) { $appendixRows[$i]['Rank'] = $i + 1 }
    $summary = 'Top {0} of {1} user(s) with specific grants; {2} admin-allowlisted user(s) listed in the appendix.' -f $ranked.Count, $items.Count, $appendixRows.Count
    return New-FsReportResult -Columns @('Rank', 'User', 'Enabled', 'Department', 'Full', 'Modify+', 'Total resources', 'Highest level', 'Servers', 'Via groups') -Rows $ranked -Summary $summary -AppendixTitle 'Admin allowlist (excluded from the ranking)' -AppendixRows $appendixRows
}
