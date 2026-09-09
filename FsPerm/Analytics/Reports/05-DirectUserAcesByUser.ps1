<#
05 Direct User ACEs by User — report 04 pivoted per user.
#>

function Get-FsReportDirectUserAcesByUser {
    [OutputType([hashtable])]
    param(
        [Parameter(Mandatory)] [System.Collections.IDictionary] $Model,
        [Parameter(Mandatory)] [System.Collections.IDictionary] $Options,
        [Parameter(Mandatory)] $Definition
    )
    $byUser = @{}
    foreach ($e in @(Get-FsDirectUserAceEntries -Model $Model)) {
        if (-not $byUser.Contains($e.principalId)) { $byUser[$e.principalId] = [System.Collections.Generic.List[object]]::new() }
        $byUser[$e.principalId].Add($e)
    }
    $items = [System.Collections.Generic.List[object]]::new()
    foreach ($uid in Get-FsSortedKeys $byUser) {
        $entries = @($byUser[$uid])
        $s = Get-FsUserStatus -Model $Model -Options $Options -PrincipalId $uid
        $resourceIds = @(Get-FsSorted -InputObject @($entries | ForEach-Object { $_.refId }) -Unique)
        $servers = @(Get-FsSorted -InputObject @($entries | ForEach-Object { $_.server }) -Unique)
        $highest = 0; $denies = 0
        foreach ($e in $entries) {
            if ($e.type -eq 'Deny') { $denies++; continue }
            $o = Get-FsLevelOrdinal $e.level
            if ($o -gt $highest) { $highest = $o }
        }
        $row = [ordered]@{
            User            = (New-FsRef -Kind Principal -Id $uid)
            Kind            = (Get-FsPrincipalKindLabel -Kind (Get-FsPrincipalKind -Model $Model -Id $uid))
            Enabled         = (ConvertTo-FsYesNo $s.enabled)
            Stale           = (ConvertTo-FsYesNo $s.stale)
            'Last logon'    = (ConvertTo-FsDateText $s.lastLogon)
            Department      = $s.department
            Resources       = $resourceIds.Count
            ACEs            = $entries.Count
            'Deny ACEs'     = $denies
            'Highest level' = (Get-FsLevelName $highest)
            Servers         = @($servers | ForEach-Object { New-FsRef -Kind Server -Id $_ })
            'Resource list' = @($resourceIds | ForEach-Object { New-FsRef -Kind Resource -Id $_ })
        }
        $items.Add(@{ resources = -$resourceIds.Count; name = (Get-FsPrincipalName -Model $Model -Id $uid); principalId = $uid; row = $row })
    }
    $rows = Select-FsSortedRows -Items @($items) -Property 'resources', 'name', 'principalId'
    $summary = '{0} user(s) hold direct ACEs.' -f $rows.Count
    return New-FsReportResult -Columns @('User', 'Kind', 'Enabled', 'Stale', 'Last logon', 'Department', 'Resources', 'ACEs', 'Deny ACEs', 'Highest level', 'Servers', 'Resource list') -Rows $rows -Summary $summary
}
