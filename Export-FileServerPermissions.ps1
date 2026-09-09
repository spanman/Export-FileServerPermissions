#Requires -Version 7.0
<#
.SYNOPSIS
    Scans a Windows file server's share and NTFS permissions, maps Active Directory group membership,
    and renders everything into an Obsidian vault with reports, a dashboard and change tracking.

.DESCRIPTION
    Two phases, both on by default:

      1. Scan    Connects to -ServerName over WinRM with -Credential (prompted when omitted), enumerates shares,
                 share ACLs and NTFS ACLs down to -Depth (recording only folders whose ACL diverges from the parent),
                 resolves every principal in Active Directory via ADSI, and expands group membership (direct, nested,
                 primary group, and server-local groups). The result is saved as a gzipped JSON snapshot under
                 <VaultPath>\_meta\snapshots\<SERVER>\.

      2. Render  Merges every snapshot in the vault (all servers, newest per server) and regenerates the Obsidian notes:
                 Servers/, Shares/, Folders/, Users/, Groups/, WellKnown/, Orphaned/, Effective/, Reports/, Home.md,
                 Dashboard.canvas and the Bases views. Existing user notes under Notes/ are never touched.

    Open <VaultPath> in Obsidian as a vault. Start at Home.md.

.PARAMETER ServerName
    File server to scan (NetBIOS or FQDN; FQDN preferred for Kerberos). Required unless -RenderOnly.

.PARAMETER Credential
    Account used for the WinRM session to the file server. Must be a local Administrator or Backup Operator on the
    server. Prompted with Get-Credential when omitted. AD lookups run as the logged-on user unless -AdCredential is given.

.PARAMETER VaultPath
    Obsidian vault folder. Default: .\vault next to this script. Created when missing.

.PARAMETER Depth
    How many folder levels below each share root to walk (0 = share root only). Default 1.

.PARAMETER IncludeShare / ExcludeShare
    Wildcard filters on share names, e.g. -IncludeShare 'Finance','HR*'.

.PARAMETER DryRun
    Enumerate shares and share ACLs only (no folder walk). Still resolves principals and writes a snapshot flagged dryRun.

.PARAMETER SkipRender
    Scan and save the snapshot, but do not regenerate the vault.

.PARAMETER RenderOnly
    Do not scan; regenerate the vault from the snapshots already in <VaultPath>\_meta\snapshots.

.PARAMETER StaleDays
    Users whose lastLogonTimestamp is older than this are tagged stale (default 90).

.EXAMPLE
    .\Export-FileServerPermissions.ps1 -ServerName fs01.par.com
    Prompts for server credentials, scans FS01 one level deep, renders .\vault.

.EXAMPLE
    .\Export-FileServerPermissions.ps1 -ServerName fs01.par.com -Depth 3 -IncludeShare Finance -DryRun -Verbose

.EXAMPLE
    $cred = Get-Credential PAR\svc_scan
    'fs01.par.com','fs02.par.com' | ForEach-Object { .\Export-FileServerPermissions.ps1 -ServerName $_ -Credential $cred -SkipRender }
    .\Export-FileServerPermissions.ps1 -RenderOnly
#>
[CmdletBinding(DefaultParameterSetName = 'Scan')]
param(
    [Parameter(Mandatory, ParameterSetName = 'Scan', Position = 0)]
    [string] $ServerName,

    [Parameter(ParameterSetName = 'Scan')]
    [System.Management.Automation.PSCredential] $Credential,

    [string] $VaultPath = (Join-Path $PSScriptRoot 'vault'),

    [Parameter(ParameterSetName = 'Scan')] [ValidateRange(0, 32)] [int] $Depth = 1,
    [Parameter(ParameterSetName = 'Scan')] [string[]] $IncludeShare,
    [Parameter(ParameterSetName = 'Scan')] [string[]] $ExcludeShare,
    [Parameter(ParameterSetName = 'Scan')] [switch] $IncludeHiddenShares,
    [Parameter(ParameterSetName = 'Scan')] [int] $MaxFoldersPerShare = 100000,
    [Parameter(ParameterSetName = 'Scan')] [switch] $NoGroupExpansion,
    [Parameter(ParameterSetName = 'Scan')] [int] $MaxGroupDepth = 10,
    [Parameter(ParameterSetName = 'Scan')] [switch] $SkipAdEnrichment,
    [Parameter(ParameterSetName = 'Scan')] [string] $AdServer,
    [Parameter(ParameterSetName = 'Scan')] [System.Management.Automation.PSCredential] $AdCredential,
    [Parameter(ParameterSetName = 'Scan')] [switch] $DryRun,
    [Parameter(ParameterSetName = 'Scan')] [int] $TimeoutSeconds = 600,
    [Parameter(ParameterSetName = 'Scan')] [switch] $SkipRender,
    [Parameter(ParameterSetName = 'Scan')] [switch] $NoSeed,
    [Parameter(ParameterSetName = 'Scan')] [int] $SeedMaxAgeHours = 24,

    [Parameter(Mandatory, ParameterSetName = 'RenderOnly')] [switch] $RenderOnly,

    # Render options
    [string] $PrimaryDomain,
    [int] $StaleDays = 90,
    [int] $PasswordAgeDays = 365,
    [int] $NestingDepthThreshold = 3,
    [int] $TopN = 25,
    [int] $RowCap = 500,
    [int] $LargeGroupThreshold = 500,
    [string[]] $AdminPrincipal,
    [int] $MaxHistory = 10,
    [switch] $InstallPlugins
)

$ErrorActionPreference = 'Stop'
Import-Module (Join-Path $PSScriptRoot 'FsPerm/FsPerm.psd1') -Force

$snapshotRoot = Join-Path $VaultPath '_meta/snapshots'
if (-not (Test-Path -LiteralPath $VaultPath)) { New-Item -ItemType Directory -Path $VaultPath -Force | Out-Null }
if ($VaultPath -match 'OneDrive') {
    Write-Warning 'The vault is inside a OneDrive folder. Regenerating thousands of notes there can hit sync locks; a local path is faster and quieter.'
}

Write-Host ''
Write-Host '=== Export-FileServerPermissions ===' -ForegroundColor Cyan
Write-Host "Vault: $VaultPath" -ForegroundColor Yellow

# ------------------------------------------------------------------ 1. scan
if ($PSCmdlet.ParameterSetName -eq 'Scan') {
    if (-not $Credential) {
        $Credential = Get-Credential -Message "Credentials for $ServerName (must be a local Administrator or Backup Operator on the server)"
        if (-not $Credential) { throw 'No credential supplied.' }
    }

    $seed = @()
    if (-not $NoSeed) {
        # Reuse principals already resolved in earlier snapshots so AD is queried once per fleet run.
        $seed = @(Get-FsSnapshotIndex -Root $snapshotRoot | Get-FsSorted -Property '-timestamp' | Select-Object -First 3 | ForEach-Object path)
    }

    $scanParams = @{
        ServerName          = $ServerName
        Credential          = $Credential
        Depth               = $Depth
        IncludeHiddenShares = $IncludeHiddenShares
        MaxFoldersPerShare  = $MaxFoldersPerShare
        NoGroupExpansion    = $NoGroupExpansion
        MaxGroupDepth       = $MaxGroupDepth
        SkipAdEnrichment    = $SkipAdEnrichment
        DryRun              = $DryRun
        TimeoutSeconds      = $TimeoutSeconds
    }
    if ($IncludeShare) { $scanParams.IncludeShare = $IncludeShare }
    if ($ExcludeShare) { $scanParams.ExcludeShare = $ExcludeShare }
    if ($AdServer) { $scanParams.AdServer = $AdServer }
    if ($AdCredential) { $scanParams.AdCredential = $AdCredential }
    if ($seed.Count) { $scanParams.SeedSnapshot = $seed; $scanParams.SeedMaxAgeHours = $SeedMaxAgeHours }

    Write-Host "Scanning $ServerName as $($Credential.UserName) (depth $Depth$(if ($DryRun) { ', dry run' }))" -ForegroundColor Green
    $snapshot = Invoke-FsScan @scanParams
    $file = Export-FsSnapshot -Snapshot $snapshot -Directory $snapshotRoot
    Write-Host "Snapshot saved: $($file.FullName) ($([math]::Round($file.Length / 1KB)) KB)" -ForegroundColor Green
    Get-FsScanSummary -Snapshot $snapshot | ForEach-Object { Write-Host "  $_" -ForegroundColor Gray }

    if ($SkipRender) { Write-Host "`nRender skipped. Run with -RenderOnly to regenerate the vault." -ForegroundColor Yellow; return }
}

# ------------------------------------------------------------------ 2. render
Write-Host "`nRendering vault from snapshots in $snapshotRoot" -ForegroundColor Green
$history = Import-FsSnapshotHistory -Root $snapshotRoot -MaxHistory $MaxHistory
if ($history.Count -eq 0) { throw "No snapshots found under $snapshotRoot. Run a scan first." }
$model = Merge-FsModel -History $history

$optParams = @{
    Model                 = $model
    StaleDays             = $StaleDays
    PasswordAgeDays       = $PasswordAgeDays
    NestingDepthThreshold = $NestingDepthThreshold
    TopN                  = $TopN
    RowCap                = $RowCap
    LargeGroupThreshold   = $LargeGroupThreshold
}
if ($AdminPrincipal) { $optParams.AdminPrincipalIds = $AdminPrincipal }
$options = Get-FsAnalysisOptions @optParams

$exportParams = @{ Model = $model; VaultPath = $VaultPath; Options = $options }
if ($PrimaryDomain) { $exportParams.PrimaryDomain = $PrimaryDomain }
$result = Export-FsVault @exportParams

if ($InstallPlugins) {
    Write-Host 'Installing optional Obsidian community plugins (Dataview)...' -ForegroundColor Green
    Install-FsObsidianPlugin -VaultPath $VaultPath -PluginId dataview
}

Write-Host ''
Write-Host '=== Done ===' -ForegroundColor Cyan
Write-Host ("  Servers: {0}   Shares: {1}   Folders: {2}   Users: {3}   Groups: {4}" -f $model.servers.Count, $model.shares.Count,
    @($model.folders.Values | Where-Object { -not $_['isShareRoot'] }).Count,
    @($model.principals.Values | Where-Object { $_['kind'] -eq 'User' }).Count,
    @($model.principals.Values | Where-Object { $_['kind'] -in 'Group', 'LocalGroup' }).Count) -ForegroundColor Gray
Write-Host ("  Notes written: {0}   unchanged: {1}   removed: {2}   warnings: {3}" -f $result.written, $result.skipped, $result.deleted, @($result.warnings).Count) -ForegroundColor Gray
foreach ($w in @($result.warnings) | Select-Object -First 10) { Write-Warning $w }
Write-Host "`nOpen this folder in Obsidian as a vault and start at Home.md:" -ForegroundColor Green
Write-Host "  $VaultPath`n" -ForegroundColor Yellow
