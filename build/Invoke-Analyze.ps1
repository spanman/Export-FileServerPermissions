#Requires -Version 7.0
<# Runs PSScriptAnalyzer over the module, entry script, tests and build scripts. Fails on any Error/Warning. #>
[CmdletBinding()]
param()
$ErrorActionPreference = 'Stop'
$repo = Split-Path -Parent $PSScriptRoot
Import-Module PSScriptAnalyzer -ErrorAction Stop
$settings = Join-Path $repo 'PSScriptAnalyzerSettings.psd1'
$targets = @('FsPerm', 'tests', 'build', 'Export-FileServerPermissions.ps1') | ForEach-Object { Join-Path $repo $_ } | Where-Object { Test-Path $_ }
$results = foreach ($t in $targets) { Invoke-ScriptAnalyzer -Path $t -Settings $settings -Recurse -ErrorAction Continue }
$results = @($results)
if ($results.Count -eq 0) { Write-Host 'PSScriptAnalyzer: no findings' -ForegroundColor Green; exit 0 }
$results | Sort-Object Severity, ScriptName, Line | Format-Table -AutoSize Severity, ScriptName, Line, RuleName, Message | Out-String -Width 220 | Write-Host
Write-Host "PSScriptAnalyzer: $($results.Count) finding(s)" -ForegroundColor Red
exit 1
