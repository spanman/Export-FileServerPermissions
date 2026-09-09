<#
Shared test setup. Dot-source from BeforeAll in each *.Tests.ps1:

    BeforeAll { . (Join-Path $PSScriptRoot 'TestHelpers.ps1') }

Provides: $script:Repo, Import of FsPerm, Get-FixtureModel, Get-FixturePath, Get-VaultLinks.
#>

$script:Repo = if ($env:FSPERM_REPO) { $env:FSPERM_REPO } else { Split-Path -Parent $PSScriptRoot }
Import-Module (Join-Path $script:Repo 'FsPerm/FsPerm.psd1') -Force

function Get-FixturePath {
    param([string] $Name)
    $dir = Join-Path $script:Repo 'tests/fixtures'
    if ($Name) { return Join-Path $dir $Name }
    return $dir
}

function Get-FixtureHistory {
    <# server -> snapshots newest first, from tests/fixtures/*.json (filename pattern <SERVER>-<yyyyMMdd>-<id8>.json) #>
    param([string[]] $Server)
    $hist = [ordered]@{}
    $files = Get-ChildItem -Path (Get-FixturePath) -Filter '*.json' -File | Sort-Object -Property Name
    foreach ($f in $files) {
        $snap = Import-FsSnapshot -Path $f.FullName
        $srv = [string]$snap['server']['name']
        if ($Server -and $Server -notcontains $srv) { continue }
        if (-not $hist.Contains($srv)) { $hist[$srv] = [System.Collections.Generic.List[object]]::new() }
        $hist[$srv].Add($snap)
    }
    foreach ($k in @($hist.Keys)) { $hist[$k] = @($hist[$k] | Get-FsSorted -Property '-timestamp') }
    return $hist
}

function Get-FixtureModel {
    param([string[]] $Server, [datetime] $Now = [datetime]'2026-09-09T12:00:00Z')
    return Merge-FsModel -History (Get-FixtureHistory -Server $Server) -Now $Now
}

function Get-VaultLinks {
    <# All [[target]] / [[target|alias]] / [[target#heading]] / ![[embed]] wikilink targets in a vault folder, with source file. #>
    param([Parameter(Mandatory)] [string] $VaultPath)
    $rx = [regex]'!?\[\[([^\]\|#]+)(?:#[^\]\|]*)?(?:\|[^\]]*)?\]\]'
    foreach ($f in Get-ChildItem -Path $VaultPath -Recurse -File -Include '*.md', '*.canvas', '*.base') {
        $text = [System.IO.File]::ReadAllText($f.FullName)
        foreach ($m in $rx.Matches($text)) {
            [pscustomobject]@{ Source = $f.FullName; Target = $m.Groups[1].Value.Trim() }
        }
    }
}
