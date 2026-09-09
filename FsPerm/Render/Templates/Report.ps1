<#
Report note: Reports/NN Title.md, one per Get-FsReportCatalog entry, built from Invoke-FsReports's matching
result. The '## Summary' heading is stable so other notes can embed '#Summary'.
#>

function New-FsReportNote {
    [OutputType([string])]
    param(
        [Parameter(Mandatory)] [System.Collections.IDictionary] $Model,
        [Parameter(Mandatory)] [hashtable] $Context,
        [Parameter(Mandatory)] [scriptblock] $Resolve,
        [Parameter(Mandatory)] [System.Collections.IDictionary] $Definition,
        [Parameter(Mandatory)] [System.Collections.IDictionary] $Result
    )
    $key = [string]$Definition['key']
    $severity = [string]$Definition['severity']

    $b = New-FsNoteBuilder
    Add-FsLine $b (ConvertTo-FsFrontmatter -Properties ([ordered]@{
                type      = 'report'
                generated = $true
                id        = $key
                tags      = (Merge-FsTags 'report' ('sev/' + $severity))
                report    = $key
                severity  = $severity
                rows      = [int]$Result['rowCount']
                servers   = [string[]]@(Get-FsSortedKeys $Model.servers)
                scanIds   = [string[]]@(Get-FsSorted -InputObject @($Model['scanIds']) -Unique)
                generated_at = [string]$Model['generatedAt']
            }))
    Add-FsLine $b ('# {0:00} {1}' -f [int]$Definition['number'], [string]$Definition['title'])
    Add-FsLine $b ''
    Add-FsLine $b ('_{0}_' -f [string]$Definition['question'])
    Add-FsLine $b ''

    Add-FsLine $b '## Summary'
    Add-FsLine $b $(if ([string]$Result['summary']) { [string]$Result['summary'] } else { '_no rows._' })
    Add-FsLine $b ''

    $columns = [string[]]$Result['columns']
    $rows = @($Result['rows'])
    Add-FsLine $b (Format-FsMdTable -Columns $columns -Rows $rows -Resolve $Resolve -EmptyText '_none_')
    if ([bool]$Result['truncated']) {
        Add-FsLine $b ''
        Add-FsLine $b ('_Showing the first {0} of {1} row(s); the full set is in `_meta/exports/`._' -f $rows.Count, @($Result['csvRows']).Count)
    }
    Add-FsLine $b ''

    $appendixRows = @($Result['appendixRows'])
    if ($appendixRows.Count -gt 0) {
        Add-FsLine $b ('## {0}' -f $(if ([string]$Result['appendixTitle']) { [string]$Result['appendixTitle'] } else { 'Appendix' }))
        Add-FsLine $b (Format-FsMdTable -Columns $columns -Rows $appendixRows -Resolve $Resolve -EmptyText '_none_')
        Add-FsLine $b ''
    }

    $footnotes = [string[]]$Result['footnotes']
    if ($footnotes.Count -gt 0) { Add-FsLine $b (New-FsCallout -Type note -Title 'Notes' -Lines $footnotes) }
    return (Get-FsNoteText -Builder $b)
}
