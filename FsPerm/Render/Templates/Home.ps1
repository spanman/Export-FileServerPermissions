<#
Home.md: the vault's landing page. Coverage per server, a findings summary table, a couple of top-5 lists
pulled from report rows, and the effective-rights caveats verbatim. No delta column yet: Get-FsHomeStats /
Compare-FsSnapshots do not exist (see Export-Vault.ps1's adapter comment).
#>

function New-FsHomeNote {
    [OutputType([string])]
    param(
        [Parameter(Mandatory)] [System.Collections.IDictionary] $Model,
        [Parameter(Mandatory)] [hashtable] $Context,
        [Parameter(Mandatory)] [scriptblock] $Resolve,
        [Parameter(Mandatory)] [System.Collections.IDictionary] $Reports,
        [Parameter(Mandatory)] [System.Collections.IDictionary] $Options
    )
    $b = New-FsNoteBuilder
    Add-FsLine $b (ConvertTo-FsFrontmatter -Properties ([ordered]@{
                type        = 'home'
                generated   = $true
                id          = 'home'
                tags        = (Merge-FsTags 'home')
                generatedAt = [string]$Model['generatedAt']
                servers     = [string[]]@(Get-FsSortedKeys $Model.servers)
                scanIds     = [string[]]@(Get-FsSorted -InputObject @($Model['scanIds']) -Unique)
            }))
    Add-FsLine $b '# Home'
    Add-FsLine $b ''
    Add-FsLine $b ('Generated {0} across {1} server(s), {2} share(s), {3} folder(s), {4} principal(s).' -f `
        (Format-FsMdDateTime -Value ([string]$Model['generatedAt'])), $Model.servers.Count, $Model.shares.Count, `
            @($Model.folders.Values | Where-Object { -not [bool](Get-FsValue $_ 'isShareRoot') }).Count, $Model.principals.Count)
    Add-FsLine $b ''

    Add-FsLine $b '## Coverage'
    $coverageRows = foreach ($srv in Get-FsSortedKeys $Model.servers) {
        $h = Get-FsServerHealth -Model $Model -Options $Options -Server $srv
        [ordered]@{
            Server            = (New-FsRef -Kind Server -Id $srv)
            Status            = $h.status
            Scanned           = (ConvertTo-FsDateTimeText $h.lastScanned)
            'Snapshot age (d)' = $h.ageDays
            Shares            = $h.shares
            Folders           = $h.folders
            Errors            = $h.errors
            Unresolved        = $h.unresolved
        }
    }
    Add-FsLine $b (Format-FsMdTable -Columns 'Server', 'Status', 'Scanned', 'Snapshot age (d)', 'Shares', 'Folders', 'Errors', 'Unresolved' -Rows $coverageRows -Resolve $Resolve)
    Add-FsLine $b ''

    Add-FsLine $b '## Findings summary'
    $findingRows = foreach ($def in Get-FsReportCatalog) {
        $r = $Reports[$def.key]
        [ordered]@{
            Report   = (New-FsRef -Kind Report -Id $def.key)
            Severity = $def.severity
            Rows     = $(if ($r) { $r.rowCount } else { 0 })
        }
    }
    Add-FsLine $b (Format-FsMdTable -Columns 'Report', 'Severity', 'Rows' -Rows $findingRows -Resolve $Resolve)
    Add-FsLine $b ''

    foreach ($pair in @(@{ key = 'over-permissioned-users'; title = 'Top over-permissioned users' }, @{ key = 'full-control'; title = 'Full control anywhere' })) {
        $r = $Reports[$pair.key]
        if (-not $r) { continue }
        Add-FsLine $b ('## {0}' -f $pair.title)
        $top = @($r.rows | Select-Object -First 5)
        Add-FsLine $b (Format-FsMdTable -Columns $r.columns -Rows $top -Resolve $Resolve -EmptyText '_none_')
        Add-FsLine $b ('_See {0} for the full list._' -f (& $Resolve (New-FsRef -Kind Report -Id $pair.key) $false))
        Add-FsLine $b ''
    }

    Add-FsLine $b '## Recent changes'
    if (Get-Command -Name 'Get-FsChangeSets' -CommandType Function -ErrorAction SilentlyContinue) {
        Add-FsLine $b (New-FsEmbed -Path (Get-FsNotePath -Context $Context -Kind Report -Id 'Changelog') -Heading 'Summary')
    }
    else {
        Add-FsLine $b '_Change tracking is not available yet (no previous snapshot, or Compare-FsSnapshots has not been wired in). Re-run after a second scan._'
    }
    Add-FsLine $b ''

    Add-FsLine $b (New-FsCallout -Type info -Title 'Effective-rights caveats' -Lines (Get-FsReportFootnotes))
    return (Get-FsNoteText -Builder $b)
}
