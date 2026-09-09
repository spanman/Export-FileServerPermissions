<#
11 Full Control Anywhere — users whose effective level (share cap applied) is Full on any grant point,
through specific grants, with the group chain that gets them there. Admin-allowlisted users go to the appendix.
#>

function Get-FsReportFullControl {
    [OutputType([hashtable])]
    param(
        [Parameter(Mandatory)] [System.Collections.IDictionary] $Model,
        [Parameter(Mandatory)] [System.Collections.IDictionary] $Options,
        [Parameter(Mandatory)] $Definition
    )
    $reach = Get-FsUserReachTable -Model $Model
    $items = [System.Collections.Generic.List[object]]::new()
    $appendix = [System.Collections.Generic.List[object]]::new()
    $users = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    foreach ($uid in Get-FsSortedKeys $reach) {
        $isAdmin = Test-FsAdminPrincipal -Model $Model -Options $Options -PrincipalId $uid
        $s = $null
        foreach ($r in @($reach[$uid])) {
            if ($r.level -ne 'Full') { continue }
            if ($null -eq $s) { $s = Get-FsUserStatus -Model $Model -Options $Options -PrincipalId $uid }
            $row = [ordered]@{
                User          = (New-FsRef -Kind Principal -Id $uid)
                Enabled       = (ConvertTo-FsYesNo $s.enabled)
                Department    = $s.department
                Server        = (New-FsRef -Kind Server -Id $r.server)
                Resource      = (New-FsRef -Kind Resource -Id $r.resourceId)
                Path          = (New-FsCode $r.path)
                Via           = @($r.via | ForEach-Object { New-FsRef -Kind Principal -Id $_ })
                Direct        = (ConvertTo-FsYesNo ($r.via.Count -eq 0))
                'Share level' = $r.shareLevel
                'NTFS level'  = $r.ntfsLevel
            }
            $item = @{ name = (Get-FsPrincipalName -Model $Model -Id $uid); principalId = $uid; server = $r.server; path = $r.path; row = $row }
            if ($isAdmin) { $appendix.Add($item) } else { $items.Add($item); [void]$users.Add($uid) }
        }
    }
    $sortBy = 'name', 'principalId', 'server', 'path'
    $rows = Select-FsSortedRows -Items @($items) -Property $sortBy
    $summary = '{0} user(s) hold effective Full Control on {1} grant point(s); admin-allowlisted users are in the appendix.' -f $users.Count, $rows.Count
    return New-FsReportResult -Columns @('User', 'Enabled', 'Department', 'Server', 'Resource', 'Path', 'Via', 'Direct', 'Share level', 'NTFS level') -Rows $rows -Summary $summary -AppendixTitle 'Admin allowlist (excluded from the table above)' -AppendixRows (Select-FsSortedRows -Items @($appendix) -Property $sortBy)
}
