<#
06 Disabled and Stale Accounts with Access — users that are disabled, expired, stale (no logon within
StaleDays), never logged on, or have a password older than PasswordAgeDays, and still reach at least one
resource. Reach is shown twice: through specific grants only, and including broad grants.
#>

function Get-FsReportDormantAccounts {
    [OutputType([hashtable])]
    param(
        [Parameter(Mandatory)] [System.Collections.IDictionary] $Model,
        [Parameter(Mandatory)] [System.Collections.IDictionary] $Options,
        [Parameter(Mandatory)] $Definition
    )
    $order = @{ 'Disabled' = 0; 'Expired' = 1; 'Stale' = 2; 'Never logged on' = 3; 'Stale password' = 4 }
    $items = [System.Collections.Generic.List[object]]::new()
    $counts = [ordered]@{ 'Disabled' = 0; 'Expired' = 0; 'Stale' = 0; 'Never logged on' = 0; 'Stale password' = 0 }
    foreach ($uid in @(Get-FsUserPrincipalIds -Model $Model)) {
        $s = Get-FsUserStatus -Model $Model -Options $Options -PrincipalId $uid
        if ($s.statuses.Count -eq 0) { continue }
        $all = @(Get-FsEffectiveAccess -Model $Model -PrincipalId $uid)
        if ($all.Count -eq 0) { continue }
        $specific = @(Get-FsEffectiveAccess -Model $Model -PrincipalId $uid -ExcludeBroad)
        $sumAll = Get-FsReachSummary -Rows $all
        $primary = [string]$s.statuses[0]
        foreach ($st in $s.statuses) { $counts[$st]++ }
        $row = [ordered]@{
            Status                = $primary
            User                  = (New-FsRef -Kind Principal -Id $uid)
            Flags                 = ($s.statuses -join ', ')
            Enabled               = (ConvertTo-FsYesNo $s.enabled)
            'Last logon'          = (ConvertTo-FsDateText $s.lastLogon)
            'Password set'        = (ConvertTo-FsDateText $s.pwdLastSet)
            Created               = (ConvertTo-FsDateText $s.created)
            Expires               = (ConvertTo-FsDateText $s.accountExpires)
            Department            = $s.department
            Title                 = $s.title
            'Reach (specific)'    = $specific.Count
            'Reach (incl. broad)' = $all.Count
            'Highest level'       = $sumAll.highest
            Servers               = @($sumAll.servers | ForEach-Object { New-FsRef -Kind Server -Id $_ })
        }
        $items.Add(@{ status = $order[$primary]; reach = -$specific.Count; name = (Get-FsPrincipalName -Model $Model -Id $uid); principalId = $uid; row = $row })
    }
    $rows = Select-FsSortedRows -Items @($items) -Property 'status', 'reach', 'name', 'principalId'
    $parts = foreach ($k in $counts.Keys) { '{0} {1}' -f $counts[$k], $k.ToLowerInvariant() }
    $summary = '{0} dormant account(s) with access ({1}).' -f $rows.Count, ($parts -join ', ')
    return New-FsReportResult -Columns @('Status', 'User', 'Flags', 'Enabled', 'Last logon', 'Password set', 'Created', 'Expires', 'Department', 'Title', 'Reach (specific)', 'Reach (incl. broad)', 'Highest level', 'Servers') -Rows $rows -Summary $summary
}
