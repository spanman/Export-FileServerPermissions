<#
Export-FsVault: the single public entry point of the Render layer. Merges the model, runs every report
once, stages every generated note, seeds .obsidian/ on a new vault, and syncs the staging folder into the
vault with minimal churn.

Adapter note: Compare-FsSnapshots / Get-FsChangeSets / Get-FsChangedEntityIds / Get-FsHomeStats (Analytics/
Diff.ps1, HomeStats.ps1) did not exist when this file was first written, so every place that uses them is
guarded with `Get-Command <name> -ErrorAction SilentlyContinue`. They now exist and are wired in: the
`changed` tag is added from Get-FsChangedEntityIds, and "Reports/Changes - <server>.md" / "Reports/Changelog.md"
are rendered from Get-FsChangeSets (Server.ps1 / Home.ps1 already embed them conditionally). If those
functions are ever absent again (e.g. an older Analytics build), this function still falls back to a plain
sentence in both places and renders a complete, self-consistent vault without them.
#>

function Export-FsVault {
    <#
    .SYNOPSIS
        Renders the merged model into an Obsidian vault at -VaultPath.
    .OUTPUTS
        @{ written; skipped; deleted; warnings } — written/skipped/deleted are counts, warnings a string[].
    #>
    [CmdletBinding(SupportsShouldProcess)]
    [OutputType([System.Collections.Specialized.OrderedDictionary])]
    param(
        [Parameter(Mandatory)] [System.Collections.IDictionary] $Model,
        [Parameter(Mandatory)] [string] $VaultPath,
        [System.Collections.IDictionary] $Options,
        [AllowNull()] [string] $PrimaryDomain
    )
    if (-not (Test-Path -LiteralPath $VaultPath)) { New-Item -ItemType Directory -Path $VaultPath -Force | Out-Null }
    if ($null -eq $Options) { $Options = Get-FsAnalysisOptions -Model $Model }

    $context = New-FsNameContext -Model $Model -PrimaryDomain $PrimaryDomain
    $reports = Invoke-FsReports -Model $Model -Options $Options
    $tags = Get-FsInsightTags -Model $Model -Options $Options
    $hasDiff = [bool](Get-Command -Name 'Get-FsChangeSets' -CommandType Function -ErrorAction SilentlyContinue)
    $changeSets = $null
    if ($hasDiff) {
        $changeSets = Get-FsChangeSets -Model $Model
        foreach ($changedId in (Get-FsChangedEntityIds -Model $Model)) {
            $existing = if ($tags.Contains($changedId)) { @($tags[$changedId]) } else { @() }
            $tags[$changedId] = (Merge-FsTags $existing 'changed')
        }
    }
    $context['tags'] = $tags
    $resolve = _New-FsPrincipalResolver -Model $Model -Context $context

    $staging = New-FsVaultStaging
    $warnings = [System.Collections.Generic.List[string]]::new()

    try {
        # ---- Servers
        foreach ($srv in Get-FsSortedKeys $Model.servers) {
            $text = New-FsServerNote -Model $Model -Context $context -Resolve $resolve -Options $Options -Server $Model.servers[$srv]
            Write-FsVaultFile -Root $staging -RelativePath (Get-FsNotePath -Context $context -Kind Server -Id $srv -Extension 'md') -Content $text | Out-Null
        }

        # ---- Shares
        foreach ($sid in Get-FsSortedKeys $Model.shares) {
            $text = New-FsShareNote -Model $Model -Context $context -Resolve $resolve -Options $Options -Share $Model.shares[$sid]
            Write-FsVaultFile -Root $staging -RelativePath (Get-FsNotePath -Context $context -Kind Share -Id $sid -Extension 'md') -Content $text | Out-Null
        }

        # ---- Folders (share-root folders carry no note of their own)
        foreach ($fid in Get-FsSortedKeys $Model.folders) {
            if ([bool](Get-FsValue $Model.folders[$fid] 'isShareRoot')) { continue }
            $text = New-FsFolderNote -Model $Model -Context $context -Resolve $resolve -Options $Options -Folder $Model.folders[$fid]
            Write-FsVaultFile -Root $staging -RelativePath (Get-FsNotePath -Context $context -Kind Folder -Id $fid -Extension 'md') -Content $text | Out-Null
        }

        # ---- Principals, routed by kind
        foreach ($pid_ in Get-FsSortedKeys $Model.principals) {
            $p = $Model.principals[$pid_]
            $kind = [string](Get-FsValue $p 'kind')
            $text = switch ($kind) {
                { $_ -in 'User', 'Computer', 'LocalUser' } { New-FsUserNote -Model $Model -Context $context -Resolve $resolve -Options $Options -Principal $p }
                { $_ -in 'Group', 'LocalGroup' } { New-FsGroupNote -Model $Model -Context $context -Resolve $resolve -Options $Options -Principal $p }
                'WellKnown' { New-FsWellKnownNote -Model $Model -Context $context -Resolve $resolve -Principal $p }
                default { New-FsOrphanedNote -Model $Model -Context $context -Resolve $resolve -Principal $p }
            }
            Write-FsVaultFile -Root $staging -RelativePath (Get-FsNotePath -Context $context -Kind Principal -Id $pid_ -Extension 'md') -Content $text | Out-Null
        }

        # ---- Reports
        foreach ($def in Get-FsReportCatalog) {
            $result = $reports[$def.key]
            $text = New-FsReportNote -Model $Model -Context $context -Resolve $resolve -Definition $def -Result $result
            Write-FsVaultFile -Root $staging -RelativePath (Get-FsNotePath -Context $context -Kind Report -Id $def.fileName -Extension 'md') -Content $text | Out-Null
        }
        $indexText = New-FsReportsIndexNote -Model $Model -Context $context -Resolve $resolve -Reports $reports
        Write-FsVaultFile -Root $staging -RelativePath (Get-FsNotePath -Context $context -Kind Report -Id '00 Reports Index' -Extension 'md') -Content $indexText | Out-Null

        # ---- Change tracking (Reports/Changes - <server>.md, Reports/Changelog.md), when Diff.ps1 is available
        if ($hasDiff) {
            foreach ($srv in Get-FsSortedKeys $Model.servers) {
                # Note: assign through an intermediate [object[]] variable, not a $(if...) subexpression —
                # when the chosen branch is itself an empty array, a subexpression assignment collapses to
                # $null instead of staying an empty array (0 pipeline objects flow out of the subexpression).
                [object[]] $diffs = @()
                if ($changeSets.Contains($srv)) { $diffs = [object[]]@($changeSets[$srv]) }
                $changesText = New-FsChangesNote -Model $Model -Context $context -Resolve $resolve -Server $srv -Diffs $diffs
                Write-FsVaultFile -Root $staging -RelativePath (Get-FsNotePath -Context $context -Kind Report -Id ('Changes - ' + $srv) -Extension 'md') -Content $changesText | Out-Null
            }
            $changelogText = New-FsChangelogNote -Model $Model -Context $context -Resolve $resolve -ChangeSets $changeSets
            Write-FsVaultFile -Root $staging -RelativePath (Get-FsNotePath -Context $context -Kind Report -Id 'Changelog' -Extension 'md') -Content $changelogText | Out-Null
        }

        # ---- Home + Dashboard
        $homeText = New-FsHomeNote -Model $Model -Context $context -Resolve $resolve -Reports $reports -Options $Options
        Write-FsVaultFile -Root $staging -RelativePath (Get-FsNotePath -Context $context -Kind Home -Extension 'md') -Content $homeText | Out-Null

        $canvasText = New-FsDashboardCanvas -Model $Model -Context $context -Reports $reports
        Write-FsVaultFile -Root $staging -RelativePath (Get-FsNotePath -Context $context -Kind Canvas -Extension 'canvas') -Content $canvasText | Out-Null

        # ---- Bases
        $bases = Get-FsDefaultBases
        foreach ($name in $bases.Keys) {
            Write-FsVaultFile -Root $staging -RelativePath $name -Content $bases[$name] | Out-Null
        }

        # ---- .obsidian seeding (writes only what's absent; never touches existing files)
        Initialize-FsObsidianConfig -VaultPath $VaultPath -WhatIf:$WhatIfPreference | Out-Null

        foreach ($w in $context.warnings) { $warnings.Add($w) }
        if (-not $hasDiff) {
            $warnings.Add('Change tracking is not available (Compare-FsSnapshots/Get-FsChangeSets/Get-FsHomeStats are not defined): Server/Home change sections render placeholders and no entity carries the "changed" tag.')
        }

        # ---- sync
        $manifest = New-FsVaultManifest -PrimaryDomain ([string]$context.primaryDomain) -GeneratedAt ([string]$Model['generatedAt']) -ScanIds ([string[]]@($Model['scanIds']))
        $previous = Read-FsVaultManifest -VaultPath $VaultPath
        $syncResult = Sync-FsVaultOutput -Staging $staging -VaultPath $VaultPath -Manifest $manifest -PreviousManifest $previous -WhatIf:$WhatIfPreference
        foreach ($w in $syncResult.warnings) { $warnings.Add($w) }

        return [ordered]@{
            written = $syncResult.counts.written
            skipped = $syncResult.counts.skipped
            deleted = $syncResult.counts.deleted
            warnings = [string[]]$warnings.ToArray()
        }
    }
    finally {
        if (Test-Path -LiteralPath $staging) { Remove-Item -LiteralPath $staging -Recurse -Force -ErrorAction SilentlyContinue }
    }
}
