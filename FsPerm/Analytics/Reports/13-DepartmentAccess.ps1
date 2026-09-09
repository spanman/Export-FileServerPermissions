<#
13 Department Access — for each AD department and share: how many of its users reach the share (or a folder
under it) through specific grants, how many with Modify or more, and the highest level. Long form (one row
per department x share) so it renders and exports as a plain table.
#>

function Get-FsReportDepartmentAccess {
    [OutputType([hashtable])]
    param(
        [Parameter(Mandatory)] [System.Collections.IDictionary] $Model,
        [Parameter(Mandatory)] [System.Collections.IDictionary] $Options,
        [Parameter(Mandatory)] $Definition
    )
    $reach = Get-FsUserReachTable -Model $Model
    $deptSize = @{}
    $deptOf = @{}
    foreach ($uid in @(Get-FsUserPrincipalIds -Model $Model)) {
        $d = [string](Get-FsValue $Model.principals[$uid] 'ad.department')
        if (-not $d) { $d = '(none)' }
        $deptOf[$uid] = $d
        $deptSize[$d] = 1 + $(if ($deptSize.Contains($d)) { $deptSize[$d] } else { 0 })
    }
    $cells = @{}   # "dept|shareId" -> @{ dept shareId users(HashSet) modify(HashSet) highest }
    foreach ($uid in $reach.Keys) {
        $dept = if ($deptOf.Contains($uid)) { $deptOf[$uid] } else { '(none)' }
        foreach ($r in @($reach[$uid])) {
            $shareId = if ($r.resourceKind -eq 'Share') { $r.resourceId } else { [string]$r.shareId }
            if (-not $shareId) { continue }
            $k = "$dept|$shareId"
            if (-not $cells.Contains($k)) { $cells[$k] = @{ dept = $dept; shareId = $shareId; users = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase); modify = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase); highest = 0 } }
            $c = $cells[$k]
            [void]$c.users.Add($uid)
            $o = Get-FsLevelOrdinal ([string]$r.level)
            if ($o -ge 4) { [void]$c.modify.Add($uid) }
            if ($o -gt $c.highest) { $c.highest = $o }
        }
    }
    $items = [System.Collections.Generic.List[object]]::new()
    foreach ($k in $cells.Keys) {
        $c = $cells[$k]
        $share = if ($Model.shares.Contains($c.shareId)) { $Model.shares[$c.shareId] } else { $null }
        $server = [string](Get-FsValue $share 'server')
        $row = [ordered]@{
            Department          = $c.dept
            'Department users'  = $(if ($deptSize.Contains($c.dept)) { $deptSize[$c.dept] } else { 0 })
            Server              = (New-FsRef -Kind Server -Id $server)
            Share               = (New-FsRef -Kind Resource -Id $c.shareId)
            Path                = (New-FsCode ([string](Get-FsValue $share 'uncPath')))
            'Users with access' = $c.users.Count
            'Users (Modify+)'   = $c.modify.Count
            'Highest level'     = (Get-FsLevelName $c.highest)
        }
        $items.Add(@{ dept = $c.dept; server = $server; share = [string](Get-FsValue $share 'name'); shareId = $c.shareId; row = $row })
    }
    $rows = Select-FsSortedRows -Items @($items) -Property 'dept', 'server', 'share', 'shareId'
    $depts = @(Get-FsSorted -InputObject @($items | ForEach-Object { $_.dept }) -Unique)
    $summary = '{0} department(s) reach {1} share(s) through specific grants.' -f $depts.Count, @(Get-FsSorted -InputObject @($items | ForEach-Object { $_.shareId }) -Unique).Count
    return New-FsReportResult -Columns @('Department', 'Department users', 'Server', 'Share', 'Path', 'Users with access', 'Users (Modify+)', 'Highest level') -Rows $rows -Summary $summary
}
