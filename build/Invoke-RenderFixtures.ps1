#Requires -Version 7.0
<#
.SYNOPSIS
    Renders the fixture snapshots into build/out/fixture-vault so the output can be linted, Mermaid-checked,
    or opened in Obsidian for a visual check. Runs inside the container or locally.
#>
[CmdletBinding()]
param([string] $OutputPath)
$ErrorActionPreference = 'Stop'
$repo = Split-Path -Parent $PSScriptRoot
Import-Module (Join-Path $repo 'FsPerm/FsPerm.psd1') -Force
$env:FSPERM_REPO = $repo
. (Join-Path $repo 'tests/TestHelpers.ps1')

if (-not $OutputPath) { $OutputPath = Join-Path $repo 'build/out/fixture-vault' }
if (Test-Path $OutputPath) { Remove-Item -LiteralPath $OutputPath -Recurse -Force }
New-Item -ItemType Directory -Path $OutputPath -Force | Out-Null

$model = Get-FixtureModel
$options = Get-FsAnalysisOptions -Model $model
$result = Export-FsVault -Model $model -VaultPath $OutputPath -Options $options -PrimaryDomain CONTOSO
Write-Host ("fixture vault rendered to {0}: written {1}, skipped {2}, deleted {3}, warnings {4}" -f $OutputPath, $result.written, $result.skipped, $result.deleted, @($result.warnings).Count)
foreach ($w in @($result.warnings)) { Write-Warning $w }
