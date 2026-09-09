#Requires -Version 7.0
<#
.SYNOPSIS
    Runs the Pester 5 suite. Intended to run inside the fsperm-test container (see build/build.ps1).
.PARAMETER Path
    Test file(s) or folder. Default: tests/
.PARAMETER Tag / ExcludeTag
    Pester tags. On Linux, WindowsOnly is excluded automatically.
.PARAMETER Coverage
    Enable code coverage over FsPerm/ (slower).
#>
[CmdletBinding()]
param(
    [string[]] $Path,
    [string[]] $Tag,
    [string[]] $ExcludeTag,
    [switch] $Coverage,
    [ValidateSet('None', 'Normal', 'Detailed', 'Diagnostic')] [string] $Verbosity = 'Normal',
    [switch] $CI
)
$ErrorActionPreference = 'Stop'
$repo = Split-Path -Parent $PSScriptRoot
if (-not $Path) { $Path = @((Join-Path $repo 'tests')) }

Import-Module Pester -MinimumVersion 5.5.0 -MaximumVersion 5.99.99 -ErrorAction Stop
$pester = Get-Module Pester
if ($pester.Version.Major -ne 5) { throw "Pester 5.x required, found $($pester.Version)" }

$cfg = New-PesterConfiguration
$cfg.Run.Path = $Path
$cfg.Run.Exit = $true
$cfg.Run.PassThru = $true
$cfg.Output.Verbosity = $Verbosity
$cfg.Should.ErrorAction = 'Continue'
if ($Tag) { $cfg.Filter.Tag = $Tag }
$exclude = @($ExcludeTag)
if (-not $IsWindows) { $exclude += 'WindowsOnly' }
if ($exclude) { $cfg.Filter.ExcludeTag = $exclude }

$resultsDir = Join-Path $repo 'test-results'
if (-not (Test-Path $resultsDir)) { New-Item -ItemType Directory -Path $resultsDir | Out-Null }
$cfg.TestResult.Enabled = $true
$cfg.TestResult.OutputFormat = 'NUnitXml'
$cfg.TestResult.OutputPath = Join-Path $resultsDir 'pester.xml'

if ($Coverage) {
    $cfg.CodeCoverage.Enabled = $true
    $cfg.CodeCoverage.Path = @((Join-Path $repo 'FsPerm'))
    $cfg.CodeCoverage.OutputPath = Join-Path $repo 'coverage/coverage.xml'
    $cfg.CodeCoverage.OutputFormat = 'JaCoCo'
}

$env:FSPERM_REPO = $repo
$result = Invoke-Pester -Configuration $cfg
if ($result.FailedCount -gt 0) { exit 1 }
