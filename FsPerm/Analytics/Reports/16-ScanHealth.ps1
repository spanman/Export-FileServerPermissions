<#
16 Scan Health — per server: freshness, duration, depth, coverage, access-denied errors, truncated walks,
unresolved principals and an Ok / Warn status.
#>

function Get-FsServerHealth {
    <# Facts used by report 16 and Home: @{ server lastScanned duration depth shares folders foldersVisited accessDenied truncated errors unresolved ageDays snapshots partial status } #>
    [OutputType([hashtable])]
    param(
        [Parameter(Mandatory)] [System.Collections.IDictionary] $Model,
        [Parameter(Mandatory)] [System.Collections.IDictionary] $Options,
        [Parameter(Mandatory)] [string] $Server
    )
    $s = $Model.servers[$Server]
    $shareIds = @(Get-FsValue $s 'shareIds')
    $visited = 0; $truncated = 0
    foreach ($sid in $shareIds) {
        if (-not $Model.shares.Contains($sid)) { continue }
        $w = Get-FsValue $Model.shares[$sid] 'walk'
        $v = Get-FsValue $w 'foldersVisited'
        if ($null -ne $v) { $visited += [int][double]$v }
        if ([bool](Get-FsValue $w 'truncated')) { $truncated++ }
    }
    $folders = 0
    foreach ($fid in $Model.folders.Keys) { if (([string](Get-FsValue $Model.folders[$fid] 'server')) -eq $Server) { $folders++ } }
    $accessDenied = 0; $errors = 0
    foreach ($e in @($Model.errors)) {
        if (([string](Get-FsValue $e 'server')) -ne $Server) { continue }
        $errors++
        if (([string](Get-FsValue $e 'kind')) -eq 'AccessDenied') { $accessDenied++ }
    }
    $unresolved = 0
    foreach ($id in $Model.principals.Keys) {
        $p = $Model.principals[$id]
        if (@(Get-FsValue $p '_servers') -contains $Server -and ([string](Get-FsValue $p 'resolution')) -in 'Orphaned', 'LookupFailed') { $unresolved++ }
    }
    $age = Get-FsAgeDays -Value (Get-FsValue $s 'lastScanned') -Now ([datetime]$Options['Now'])
    $partial = [bool](Get-FsValue $s 'status.partial')
    $warn = ($errors -gt 0 -or $truncated -gt 0 -or $partial -or ($null -ne $age -and $age -gt [int]$Options['SnapshotAgeWarnDays']))
    return @{
        server         = $Server
        lastScanned    = (Get-FsValue $s 'lastScanned')
        duration       = (Get-FsValue $s 'durationSeconds')
        depth          = (Get-FsValue $s 'scope.depth')
        shares         = $shareIds.Count
        folders        = $folders
        foldersVisited = $visited
        accessDenied   = $accessDenied
        truncated      = $truncated
        errors         = $errors
        unresolved     = $unresolved
        ageDays        = $age
        snapshots      = (Get-FsValue $s 'snapshotCount')
        partial        = $partial
        status         = $(if ($warn) { 'Warn' } else { 'Ok' })
    }
}

function Get-FsReportScanHealth {
    [OutputType([hashtable])]
    param(
        [Parameter(Mandatory)] [System.Collections.IDictionary] $Model,
        [Parameter(Mandatory)] [System.Collections.IDictionary] $Options,
        [Parameter(Mandatory)] $Definition
    )
    $items = [System.Collections.Generic.List[object]]::new()
    $warn = 0
    foreach ($srv in Get-FsSortedKeys $Model.servers) {
        $h = Get-FsServerHealth -Model $Model -Options $Options -Server $srv
        if ($h.status -eq 'Warn') { $warn++ }
        $row = [ordered]@{
            Server                  = (New-FsRef -Kind Server -Id $srv)
            Status                  = $h.status
            Scanned                 = (ConvertTo-FsDateTimeText $h.lastScanned)
            'Snapshot age (days)'   = $h.ageDays
            'Duration (s)'          = $h.duration
            Depth                   = $h.depth
            Shares                  = $h.shares
            'Folders visited'       = $h.foldersVisited
            'Folders captured'      = $h.folders
            'Access denied'         = $h.accessDenied
            'Truncated shares'      = $h.truncated
            Errors                  = $h.errors
            'Unresolved principals' = $h.unresolved
            Snapshots               = $h.snapshots
            Partial                 = (ConvertTo-FsYesNo $h.partial)
        }
        $items.Add(@{ server = $srv; row = $row })
    }
    $rows = Select-FsSortedRows -Items @($items) -Property 'server'
    $summary = '{0} server(s) scanned; {1} with warnings.' -f $rows.Count, $warn
    return New-FsReportResult -Columns @('Server', 'Status', 'Scanned', 'Snapshot age (days)', 'Duration (s)', 'Depth', 'Shares', 'Folders visited', 'Folders captured', 'Access denied', 'Truncated shares', 'Errors', 'Unresolved principals', 'Snapshots', 'Partial') -Rows $rows -Summary $summary
}
