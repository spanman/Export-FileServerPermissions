#Requires -Version 7.0
<#
.SYNOPSIS
    Extracts every ```mermaid block from a rendered vault and validates each with mermaid-cli (mmdc) running in
    the minlag/mermaid-cli container. Advisory: Obsidian bundles its own Mermaid version, so treat failures as
    "probably broken" rather than proof.
.PARAMETER VaultPath
    Defaults to build/out/fixture-vault.
#>
[CmdletBinding()]
param(
    [string] $VaultPath,
    [string] $MermaidImage = 'minlag/mermaid-cli:11.4.2'
)
$ErrorActionPreference = 'Stop'
$repo = Split-Path -Parent $PSScriptRoot
if (-not $VaultPath) { $VaultPath = Join-Path $repo 'build/out/fixture-vault' }
$outDir = Join-Path $repo 'build/out/mermaid'
if (Test-Path $outDir) { Remove-Item -LiteralPath $outDir -Recurse -Force }
New-Item -ItemType Directory -Path $outDir -Force | Out-Null

$rx = [regex]'(?ms)^```mermaid\s*\n(.*?)\n```'
$count = 0
foreach ($f in Get-ChildItem -Path $VaultPath -Recurse -Filter '*.md' -File) {
    $text = [System.IO.File]::ReadAllText($f.FullName)
    $i = 0
    foreach ($m in $rx.Matches($text)) {
        $i++; $count++
        $name = ($f.FullName.Substring($VaultPath.Length).Trim('\', '/') -replace '[\\/]', '__' -replace '\.md$', '') + "-$i.mmd"
        [System.IO.File]::WriteAllText((Join-Path $outDir $name), $m.Groups[1].Value + "`n", [System.Text.UTF8Encoding]::new($false))
    }
}
Write-Host "Extracted $count mermaid block(s) to $outDir"
if ($count -eq 0) { exit 0 }

$puppeteer = Join-Path $PSScriptRoot 'puppeteer-config.json'
Copy-Item -LiteralPath $puppeteer -Destination (Join-Path $outDir 'puppeteer-config.json') -Force
$failed = 0
foreach ($mmd in Get-ChildItem -Path $outDir -Filter '*.mmd') {
    $svg = $mmd.Name -replace '\.mmd$', '.svg'
    & docker run --rm -v "${outDir}:/data" $MermaidImage -p /data/puppeteer-config.json -i "/data/$($mmd.Name)" -o "/data/$svg" 2>&1 | Out-Null
    if ($LASTEXITCODE -ne 0) { $failed++; Write-Host "  FAIL $($mmd.Name)" -ForegroundColor Red }
}
Write-Host ("Mermaid check: {0} ok, {1} failed" -f ($count - $failed), $failed) -ForegroundColor $(if ($failed) { 'Red' } else { 'Green' })
if ($failed) { exit 1 }
