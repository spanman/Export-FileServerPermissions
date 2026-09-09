#Requires -Version 7.0
<#
.SYNOPSIS
    Build entry point. Runs tasks inside the fsperm-test Docker image (Linux pwsh + Pester 5 + PSScriptAnalyzer)
    unless -Local is given.

.EXAMPLE
    ./build/build.ps1 -Task Test
    ./build/build.ps1 -Task All
    ./build/build.ps1 -Task Test -Local          # requires Pester 5 installed locally
    ./build/build.ps1 -Task Fixtures             # regenerate tests/fixtures/*.json
#>
[CmdletBinding()]
param(
    [ValidateSet('Test', 'Analyze', 'Lint', 'Mermaid', 'Fixtures', 'RenderFixtures', 'Image', 'All')] [string] $Task = 'Test',
    [switch] $Local,
    [string[]] $TestPath,
    [switch] $Coverage
)
$ErrorActionPreference = 'Stop'
$repo = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
$image = 'fsperm-test'

function Invoke-InContainer {
    param([string[]] $PwshArgs, [string] $Mount = $repo, [string] $ImageName = $image, [string[]] $ExtraDockerArgs = @())
    $mountArg = "${Mount}:/work"
    & docker run --rm @ExtraDockerArgs -v $mountArg -w /work $ImageName @PwshArgs
    if ($LASTEXITCODE -ne 0) { throw "Task failed in container (exit $LASTEXITCODE)" }
}

function Ensure-Image {
    $exists = docker image inspect $image 2>$null
    if (-not $exists) { Write-Host "Building $image ..." -ForegroundColor Cyan; docker build -t $image -f (Join-Path $PSScriptRoot 'Dockerfile.test') $PSScriptRoot; if ($LASTEXITCODE) { throw 'image build failed' } }
}

function Run-Test {
    $testArgs = @('-File', './build/Invoke-Tests.ps1')
    if ($TestPath) { $testArgs += '-Path'; $testArgs += ($TestPath -join ',') }
    if ($Coverage) { $testArgs += '-Coverage' }
    if ($Local) { & pwsh -NoProfile @testArgs; if ($LASTEXITCODE) { throw 'tests failed' } }
    else { Ensure-Image; Invoke-InContainer -PwshArgs $testArgs }
}
function Run-Analyze {
    $a = @('-File', './build/Invoke-Analyze.ps1')
    if ($Local) { & pwsh -NoProfile @a; if ($LASTEXITCODE) { throw 'analyzer failed' } } else { Ensure-Image; Invoke-InContainer -PwshArgs $a }
}
function Run-Fixtures {
    $a = @('-File', './tests/fixtures/New-Fixtures.ps1')
    if ($Local) { & pwsh -NoProfile @a } else { Ensure-Image; Invoke-InContainer -PwshArgs $a }
}
function Run-RenderFixtures {
    $a = @('-File', './build/Invoke-RenderFixtures.ps1')
    if ($Local) { & pwsh -NoProfile @a } else { Ensure-Image; Invoke-InContainer -PwshArgs $a }
}
function Run-Lint {
    Run-RenderFixtures
    $vault = Join-Path $repo 'build/out/fixture-vault'
    & docker run --rm -v "${vault}:/work:ro" -v "${repo}/.markdownlint-cli2.jsonc:/work/.markdownlint-cli2.jsonc:ro" davidanson/markdownlint-cli2:latest '**/*.md'
    if ($LASTEXITCODE -ne 0) { throw 'markdownlint reported problems' }
}
function Run-Mermaid {
    Run-RenderFixtures
    $a = @('-File', './build/Invoke-MermaidCheck.ps1')
    if ($Local) { & pwsh -NoProfile @a } else { Ensure-Image; Invoke-InContainer -PwshArgs $a -ExtraDockerArgs @('-v', '/var/run/docker.sock:/var/run/docker.sock') }
}

switch ($Task) {
    'Image' { docker build -t $image -f (Join-Path $PSScriptRoot 'Dockerfile.test') $PSScriptRoot }
    'Test' { Run-Test }
    'Analyze' { Run-Analyze }
    'Fixtures' { Run-Fixtures }
    'RenderFixtures' { Run-RenderFixtures }
    'Lint' { Run-Lint }
    'Mermaid' { Run-Mermaid }
    'All' { Run-Analyze; Run-Test; Run-Lint; Run-Mermaid }
}
