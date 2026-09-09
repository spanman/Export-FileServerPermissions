<#
Change-tracking notes: Reports/Changes - <server>.md (latest vs previous snapshot) and Reports/Changelog.md
(every consecutive snapshot pair per server, newest first). Built from Compare-FsSnapshots / Get-FsChangeSets
(FsPerm/Analytics/Diff.ps1). Both are skipped by Export-Vault.ps1 when those functions are not defined.
#>

function Get-FsDiffTableColumns {
    <# Column names for one of a diff's row collections, or $null when it has none. #>
    [OutputType([string[]])]
    param([AllowNull()] [AllowEmptyCollection()] [object[]] $Rows)
    if (-not $Rows -or @($Rows).Count -eq 0) { return $null }
    return [string[]]@($Rows[0].Keys)
}

function Add-FsDiffSection {
    <# Appends "### Title" + a capped table for one of a diff's row collections, when it has rows. #>
    param(
        [Parameter(Mandatory)] [System.Text.StringBuilder] $Builder,
        [Parameter(Mandatory)] [string] $Title,
        [AllowNull()] [AllowEmptyCollection()] [object[]] $Rows,
        [Parameter(Mandatory)] [scriptblock] $Resolve,
        [int] $MaxRows = 200
    )
    $rows = @($Rows | Where-Object { $null -ne $_ })
    if ($rows.Count -eq 0) { return }
    $columns = Get-FsDiffTableColumns -Rows $rows
    Add-FsLine $Builder ('### {0} ({1})' -f $Title, $rows.Count)
    Add-FsLine $Builder (Format-FsMdTable -Columns $columns -Rows $rows -Resolve $Resolve -MaxRows $MaxRows)
    Add-FsLine $Builder ''
}

function New-FsChangesNote {
    <#
    .SYNOPSIS
        Reports/Changes - <server>.md: latest-vs-previous diff for one server (Get-FsChangeSets[$Server][0]).
    #>
    [OutputType([string])]
    param(
        [Parameter(Mandatory)] [System.Collections.IDictionary] $Model,
        [Parameter(Mandatory)] [hashtable] $Context,
        [Parameter(Mandatory)] [scriptblock] $Resolve,
        [Parameter(Mandatory)] [string] $Server,
        [AllowNull()] [AllowEmptyCollection()] [object[]] $Diffs
    )
    $diffs = @($Diffs | Where-Object { $null -ne $_ })
    $b = New-FsNoteBuilder
    Add-FsLine $b (ConvertTo-FsFrontmatter -Properties ([ordered]@{
                type      = 'report'
                generated = $true
                id        = 'changes-' + $Server
                tags      = (Merge-FsTags 'report')
                report    = 'changes-' + $Server
                severity  = 'info'
                servers   = [string[]]@($Server)
                rows      = $(if ($diffs.Count -gt 0) { @($diffs[0].shares).Count + @($diffs[0].folders).Count + @($diffs[0].aces).Count + @($diffs[0].memberships).Count + @($diffs[0].principals).Count } else { 0 })
            }))
    Add-FsLine $b ('# Changes - {0}' -f $Server)
    Add-FsLine $b ''
    if ($diffs.Count -eq 0) {
        Add-FsLine $b '## Summary'
        Add-FsLine $b '_No previous snapshot to compare yet; this is the baseline scan._'
        return (Get-FsNoteText -Builder $b)
    }
    $d = $diffs[0]
    Add-FsLine $b '## Summary'
    Add-FsLine $b ('{0} -> {1}: {2}' -f (Format-FsMdDateTime -Value ([string]$d.fromTimestamp)), (Format-FsMdDateTime -Value ([string]$d.toTimestamp)), [string]$d.summaryText)
    if (@($d.banners).Count -gt 0) { Add-FsLine $b ''; Add-FsLine $b (New-FsCallout -Type warning -Title 'Scope' -Lines ([string[]]$d.banners)) }
    Add-FsLine $b ''
    Add-FsDiffSection -Builder $b -Title 'Shares' -Rows $d.shares -Resolve $Resolve
    Add-FsDiffSection -Builder $b -Title 'Folders' -Rows $d.folders -Resolve $Resolve
    Add-FsDiffSection -Builder $b -Title 'ACEs' -Rows $d.aces -Resolve $Resolve
    Add-FsDiffSection -Builder $b -Title 'Memberships' -Rows $d.memberships -Resolve $Resolve
    Add-FsDiffSection -Builder $b -Title 'Principals' -Rows $d.principals -Resolve $Resolve
    return (Get-FsNoteText -Builder $b)
}

function New-FsChangelogNote {
    <#
    .SYNOPSIS
        Reports/Changelog.md: every consecutive snapshot pair per server, newest first, derived fresh each run.
    #>
    [OutputType([string])]
    param(
        [Parameter(Mandatory)] [System.Collections.IDictionary] $Model,
        [Parameter(Mandatory)] [hashtable] $Context,
        [Parameter(Mandatory)] [scriptblock] $Resolve,
        [Parameter(Mandatory)] [System.Collections.IDictionary] $ChangeSets
    )
    $b = New-FsNoteBuilder
    $totalPairs = 0
    foreach ($k in $ChangeSets.Keys) { $totalPairs += @($ChangeSets[$k]).Count }
    Add-FsLine $b (ConvertTo-FsFrontmatter -Properties ([ordered]@{
                type      = 'report'
                generated = $true
                id        = 'changelog'
                tags      = (Merge-FsTags 'report')
                report    = 'changelog'
                severity  = 'info'
                servers   = [string[]]@(Get-FsSortedKeys $ChangeSets)
                rows      = $totalPairs
            }))
    Add-FsLine $b '# Changelog'
    Add-FsLine $b ''
    Add-FsLine $b '## Summary'
    if ($totalPairs -eq 0) {
        Add-FsLine $b '_No server has more than one snapshot yet; nothing to compare._'
        return (Get-FsNoteText -Builder $b)
    }
    $overview = foreach ($server in Get-FsSortedKeys $ChangeSets) {
        $diffs = @($ChangeSets[$server])
        [ordered]@{ Server = (New-FsRef -Kind Server -Id $server); Pairs = $diffs.Count; Latest = $(if ($diffs.Count -gt 0) { $diffs[0].summaryText } else { '_none_' }) }
    }
    Add-FsLine $b (Format-FsMdTable -Columns 'Server', 'Pairs', 'Latest' -Rows $overview -Resolve $Resolve)
    Add-FsLine $b ''
    foreach ($server in Get-FsSortedKeys $ChangeSets) {
        $diffs = @($ChangeSets[$server])
        if ($diffs.Count -eq 0) { continue }
        Add-FsLine $b ('## {0}' -f $server)
        for ($i = 0; $i -lt $diffs.Count; $i++) {
            $d = $diffs[$i]
            Add-FsLine $b ('- {0} -> {1}: {2}' -f (Format-FsMdDateTime -Value ([string]$d.fromTimestamp)), (Format-FsMdDateTime -Value ([string]$d.toTimestamp)), [string]$d.summaryText)
        }
        Add-FsLine $b ''
    }
    return (Get-FsNoteText -Builder $b)
}
