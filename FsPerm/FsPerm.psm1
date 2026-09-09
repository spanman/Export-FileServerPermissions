#Requires -Version 7.0
Set-StrictMode -Version 1.0

# Every file under the layer folders defines functions only; nothing executes at import.
# The manifest exports '*', so no Export-ModuleMember call is needed here.
$script:FsPermRoot = $PSScriptRoot
$script:FsPermVersion = (Import-PowerShellDataFile -Path (Join-Path $PSScriptRoot 'FsPerm.psd1')).ModuleVersion

foreach ($layer in 'Model', 'Analytics', 'Analytics/Reports', 'Render', 'Render/Templates', 'Collector') {
    $dir = Join-Path $PSScriptRoot $layer
    if (-not (Test-Path -LiteralPath $dir)) { continue }
    foreach ($file in @(Get-ChildItem -LiteralPath $dir -Filter '*.ps1' -File | Sort-Object -Property Name)) {
        . $file.FullName
    }
}
