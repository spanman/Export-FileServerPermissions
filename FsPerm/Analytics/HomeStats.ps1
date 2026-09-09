<#
Aggregate counts and top lists for Home.md and Dashboard.canvas. Everything here is a thin read over
Invoke-FsReports's results and the model indexes built by Common.ps1 / Reach.ps1 / Diff.ps1 / Reports/16 -
no new analysis, just assembly for the renderer.
#>

function Get-FsServerHealthRow {
    <# Home.md's per-server row: Server(ref) Status Shares Folders Errors Truncated AgeDays. Thin wrapper over Get-FsServerHealth (Reports/16-ScanHealth.ps1), which is the source of truth for these facts. #>
    [OutputType([hashtable])]
    param(
        [Parameter(Mandatory)] [System.Collections.IDictionary] $Model,
        [Parameter(Mandatory)] [System.Collections.IDictionary] $Options,
        [Parameter(Mandatory)] [string] $Server
    )
    $h = Get-FsServerHealth -Model $Model -Options $Options -Server $Server
    return [ordered]@{
        Server      = New-FsRef -Kind Server -Id $Server
        LastScanned = [string]$h.lastScanned
        AgeDays     = $h.ageDays
        Shares      = $h.shares
        Folders     = $h.folders
        Errors      = $h.errors
        Truncated   = $h.truncated
        Status      = $h.status
    }
}

function Get-FsTopRows {
    <# First -Count rows of a report's rows, or @() when the report is missing/empty. #>
    [OutputType([object[]])]
    param([System.Collections.IDictionary] $Reports, [Parameter(Mandatory)] [string] $Key, [int] $Count = 5)
    if ($null -eq $Reports -or -not $Reports.Contains($Key)) { return @() }
    return @(@($Reports[$Key].rows) | Select-Object -First $Count)
}

function Get-FsHomeStats {
    <#
    .SYNOPSIS
        Coverage counts, per-server health, per-report summary, top-5 lists and recent-changes summaries
        for the Home note and dashboard canvas.
    .PARAMETER Reports
        Result of Invoke-FsReports. Computed automatically when omitted.
    #>
    [OutputType([hashtable])]
    param(
        [Parameter(Mandatory)] [System.Collections.IDictionary] $Model,
        [System.Collections.IDictionary] $Reports,
        [System.Collections.IDictionary] $Options
    )
    if ($null -eq $Options) { $Options = Get-FsAnalysisOptions -Model $Model }
    if ($null -eq $Reports) { $Reports = Invoke-FsReports -Model $Model -Options $Options }

    $aceEntries = Get-FsAceEntries -Model $Model
    $reach = Get-FsUserReachTable -Model $Model
    $disabledWithAccess = 0; $staleWithAccess = 0
    foreach ($uid in Get-FsUserPrincipalIds -Model $Model) {
        if (-not $reach.Contains($uid) -or @($reach[$uid]).Count -eq 0) { continue }
        $status = Get-FsUserStatus -Model $Model -Options $Options -PrincipalId $uid
        if ($status.disabled) { $disabledWithAccess++ }
        if ($status.stale) { $staleWithAccess++ }
    }

    $counts = [ordered]@{
        servers                  = $Model.servers.Count
        shares                   = $Model.shares.Count
        divergentFolders         = @($Model.folders.Values | Where-Object { -not [bool](Get-FsValue $_ 'isShareRoot') }).Count
        users                    = @(Get-FsUserPrincipalIds -Model $Model).Count
        groups                   = @(Get-FsGroupPrincipalIds -Model $Model | Where-Object { -not [bool](Get-FsValue $Model.principals[$_] 'isWellKnown') }).Count
        localGroups              = @($Model.principals.Values | Where-Object { [string](Get-FsValue $_ 'kind') -eq 'LocalGroup' }).Count
        wellKnown                = @($Model.principals.Values | Where-Object { [bool](Get-FsValue $_ 'isWellKnown') }).Count
        orphaned                 = @($Model.principals.Values | Where-Object { [string](Get-FsValue $_ 'kind') -in 'OrphanedSid', 'Foreign' }).Count
        memberships              = $Model.memberships.Count
        shareAces                = @($aceEntries | Where-Object { $_.layer -eq 'Share' }).Count
        ntfsAces                 = @($aceEntries | Where-Object { $_.layer -eq 'NTFS' }).Count
        denyAces                 = @($aceEntries | Where-Object { $_.type -eq 'Deny' }).Count
        disabledUsersWithAccess  = $disabledWithAccess
        staleUsersWithAccess     = $staleWithAccess
    }

    $servers = @(foreach ($s in Get-FsSortedKeys $Model.servers) { Get-FsServerHealthRow -Model $Model -Options $Options -Server $s })

    $reportRows = @(foreach ($def in Get-FsReportCatalog) {
            $r = $(if ($Reports.Contains($def.key)) { $Reports[$def.key] } else { $null })
            [ordered]@{
                Key      = $def.key
                Number   = $def.number
                Title    = $def.title
                Severity = $def.severity
                Rows     = $(if ($r) { $r.rowCount } else { 0 })
                Ref      = New-FsRef -Kind Report -Id $def.key -Label $def.fileName
            }
        })

    $changeSets = Get-FsChangeSets -Model $Model
    $recentChanges = @(foreach ($server in Get-FsSortedKeys $Model.servers) {
            $diffs = @($changeSets[$server])
            if ($diffs.Count -eq 0) {
                [ordered]@{ Server = New-FsRef -Kind Server -Id $server; HasBaseline = $false; Summary = 'Baseline scan - no prior snapshot to compare.' }
            }
            else {
                [ordered]@{ Server = New-FsRef -Kind Server -Id $server; HasBaseline = $true; Summary = $diffs[0].summaryText }
            }
        })

    return @{
        counts        = $counts
        servers       = $servers
        reports       = $reportRows
        topUsers      = Get-FsTopRows -Reports $Reports -Key 'over-permissioned-users' -Count $Options['TopN']
        topGroups     = Get-FsTopRows -Reports $Reports -Key 'over-permissioned-groups' -Count $Options['TopN']
        topBroad      = Get-FsTopRows -Reports $Reports -Key 'broad-exposure' -Count 5
        topFullControl = Get-FsTopRows -Reports $Reports -Key 'full-control' -Count 5
        recentChanges = $recentChanges
        footnotes     = Get-FsReportFootnotes
    }
}
