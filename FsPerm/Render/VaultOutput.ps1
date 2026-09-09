<#
Vault write/sync strategy (plan, Phase 5).

Render everything into a temp staging folder, then Sync-FsVaultOutput compares sha256 hashes against the
previous _meta/manifest.json and copies only changed files (minimal OneDrive/git churn). Files that were
generated last time but not this time are deleted only when they sit inside a tool-owned root and (for .md)
carry `generated: true`. Notes/ and .obsidian/ are never touched. Unexpected files in owned folders are
reported, not deleted. The manifest is written last.
#>

$script:FsVaultOwnedRoots = @('Servers', 'Shares', 'Folders', 'Users', 'Groups', 'WellKnown', 'Orphaned', 'Effective', 'Reports', '_meta')
$script:FsVaultOwnedTopLevel = @('Home.md', 'Dashboard.canvas', '*.base')
$script:FsVaultIgnoredPrefixes = @('_meta/snapshots/', '_meta/manifest.json')
$script:FsVaultManifestPath = '_meta/manifest.json'
$script:FsVaultManifestVersion = 1
$script:FsUtf8NoBom = [System.Text.UTF8Encoding]::new($false)

# ---------------------------------------------------------------- primitives

function Invoke-FsIoRetry {
    <# Runs $Action up to $Attempts times, backing off on IOException / UnauthorizedAccessException (OneDrive, AV scanners). #>
    param(
        [Parameter(Mandatory)] [scriptblock] $Action,
        [int] $Attempts = 3,
        [int] $InitialDelayMs = 200,
        [string] $Description = 'file operation'
    )
    $delay = $InitialDelayMs
    for ($i = 1; ; $i++) {
        try { return (& $Action) }
        catch [System.IO.IOException], [System.UnauthorizedAccessException] {
            if ($i -ge $Attempts) { throw }
            Write-Verbose "Retrying $Description after error: $($_.Exception.Message)"
            Start-Sleep -Milliseconds $delay
            $delay *= 3
        }
    }
}

function New-FsVaultStaging {
    <# Creates and returns an empty temp folder for rendering into. #>
    [OutputType([string])]
    param()
    $path = Join-Path ([System.IO.Path]::GetTempPath()) ('fsperm-stage-' + [guid]::NewGuid().ToString('n'))
    New-Item -ItemType Directory -Path $path -Force | Out-Null
    return $path
}

function Get-FsVaultFullPath {
    <# Joins a '/'-separated vault-relative path onto a root using the platform separator. #>
    [OutputType([string])]
    param([Parameter(Mandatory)] [string] $Root, [Parameter(Mandatory)] [string] $RelativePath)
    $p = $Root
    foreach ($seg in ($RelativePath -split '[\\/]+')) { if ($seg -ne '') { $p = Join-Path $p $seg } }
    return $p
}

function Write-FsVaultFile {
    <#
    .SYNOPSIS
        Writes text as UTF-8 without BOM with LF endings, creating directories; retries on IO errors. Returns the full path.
    #>
    [OutputType([string])]
    param(
        [Parameter(Mandatory)] [string] $Root,
        [Parameter(Mandatory)] [string] $RelativePath,
        [AllowNull()] [AllowEmptyString()] [string] $Content
    )
    $full = Get-FsVaultFullPath -Root $Root -RelativePath $RelativePath
    $dir = [System.IO.Path]::GetDirectoryName($full)
    if ($dir -and -not (Test-Path -LiteralPath $dir)) { New-Item -ItemType Directory -Path $dir -Force | Out-Null }
    $text = if ($null -eq $Content) { '' } else { $Content.Replace("`r`n", "`n").Replace("`r", "`n") }
    Invoke-FsIoRetry -Description "write $RelativePath" -Action { [System.IO.File]::WriteAllText($full, $text, $script:FsUtf8NoBom) } | Out-Null
    return $full
}

function Get-FsFileSha256 {
    <# Lowercase hex SHA-256 of a file's bytes. #>
    [OutputType([string])]
    param([Parameter(Mandatory)] [string] $Path)
    $sha = [System.Security.Cryptography.SHA256]::Create()
    try {
        $stream = Invoke-FsIoRetry -Description "hash $Path" -Action { [System.IO.File]::OpenRead($Path) }
        try { $hash = $sha.ComputeHash($stream) } finally { $stream.Dispose() }
    }
    finally { $sha.Dispose() }
    return [System.BitConverter]::ToString($hash).Replace('-', '').ToLowerInvariant()
}

function Get-FsRelativeVaultPath {
    <# '/'-separated path of $FullPath relative to $Root. #>
    [OutputType([string])]
    param([Parameter(Mandatory)] [string] $Root, [Parameter(Mandatory)] [string] $FullPath)
    return ([System.IO.Path]::GetRelativePath($Root, $FullPath)).Replace('\', '/')
}

function Get-FsVaultFileList {
    <# Sorted '/'-relative paths of all files under a folder (recursively); @() when the folder is missing. #>
    [OutputType([string[]])]
    param([Parameter(Mandatory)] [string] $Root)
    if (-not (Test-Path -LiteralPath $Root)) { return @() }
    $rels = foreach ($f in @(Get-ChildItem -LiteralPath $Root -Recurse -File -Force)) { Get-FsRelativeVaultPath -Root $Root -FullPath $f.FullName }
    return [string[]]@(Get-FsSorted -InputObject @($rels))
}

function Test-FsVaultOwnedPath {
    <#
    .SYNOPSIS
        True when a vault-relative path is inside a tool-owned root folder, or is a top-level Home.md / Dashboard.canvas / *.base.
    #>
    [OutputType([bool])]
    param(
        [Parameter(Mandatory)] [string] $RelativePath,
        [string[]] $OwnedRoots = $script:FsVaultOwnedRoots
    )
    $rel = $RelativePath.Replace('\', '/').TrimStart('/')
    $slash = $rel.IndexOf('/')
    if ($slash -gt 0) {
        $first = $rel.Substring(0, $slash)
        foreach ($r in $OwnedRoots) { if ($first.Equals($r, [System.StringComparison]::OrdinalIgnoreCase)) { return $true } }
        return $false
    }
    foreach ($pattern in $script:FsVaultOwnedTopLevel) { if ($rel -like $pattern) { return $true } }
    return $false
}

function Test-FsVaultIgnoredPath {
    <# Paths the sync neither deletes nor reports: snapshots and the manifest itself. #>
    [OutputType([bool])]
    param([Parameter(Mandatory)] [string] $RelativePath)
    $rel = $RelativePath.Replace('\', '/')
    foreach ($p in $script:FsVaultIgnoredPrefixes) {
        if ($rel.StartsWith($p, [System.StringComparison]::OrdinalIgnoreCase)) { return $true }
    }
    return $false
}

function Test-FsGeneratedNote {
    <# True when the first 512 bytes of a file contain 'generated: true' (frontmatter marker of generated notes). #>
    [OutputType([bool])]
    param([Parameter(Mandatory)] [string] $Path)
    if (-not (Test-Path -LiteralPath $Path)) { return $false }
    $stream = [System.IO.File]::OpenRead($Path)
    try {
        $buffer = [byte[]]::new(512)
        $read = $stream.Read($buffer, 0, 512)
    }
    finally { $stream.Dispose() }
    $head = [System.Text.Encoding]::UTF8.GetString($buffer, 0, $read)
    return ($head -match '(?m)^generated:\s*true\s*$')
}

# ---------------------------------------------------------------- manifest

function New-FsVaultManifest {
    <# Manifest skeleton: version, primaryDomain, generatedAt (ISO string from the model), scanIds, files (filled by Sync). #>
    [OutputType([System.Collections.Specialized.OrderedDictionary])]
    param(
        [AllowNull()] [string] $PrimaryDomain,
        [AllowNull()] [string] $GeneratedAt,
        [AllowNull()] [string[]] $ScanIds,
        [AllowNull()] [System.Collections.IDictionary] $Files
    )
    # Named $sortedFiles, NOT $files: PowerShell variable names are case-insensitive, so a local $files would
    # silently reassign the -Files PARAMETER (case difference notwithstanding) to {} before it is ever read,
    # discarding every entry the caller passed in.
    $sortedFiles = [ordered]@{}
    if ($Files) { foreach ($k in Get-FsSortedKeys $Files) { $sortedFiles[$k] = [string]$Files[$k] } }
    return [ordered]@{
        version       = $script:FsVaultManifestVersion
        primaryDomain = $PrimaryDomain
        generatedAt   = $GeneratedAt
        scanIds       = [string[]]@(Get-FsSorted -InputObject @($ScanIds | Where-Object { -not [string]::IsNullOrEmpty($_) }) -Unique)
        files         = $sortedFiles
    }
}

function Read-FsVaultManifest {
    <# The previous manifest as a hashtable, or $null when absent or unreadable (a warning is written). #>
    [OutputType([System.Collections.IDictionary])]
    param([Parameter(Mandatory)] [string] $VaultPath)
    $path = Get-FsVaultFullPath -Root $VaultPath -RelativePath $script:FsVaultManifestPath
    if (-not (Test-Path -LiteralPath $path)) { return $null }
    try {
        $m = ConvertFrom-Json -InputObject ([System.IO.File]::ReadAllText($path)) -AsHashtable -Depth 8
        if ($null -eq $m['files']) { $m['files'] = @{} }
        # ConvertFrom-Json auto-detects ISO-8601-looking JSON string values and silently returns them as
        # [datetime] instead of the string that was written; generatedAt must stay the plain string it was.
        if ($m['generatedAt'] -is [datetime]) { $m['generatedAt'] = ([datetime]$m['generatedAt']).ToString('o') }
        return $m
    }
    catch {
        Write-Warning "Read-FsVaultManifest: '$path' is unreadable ($($_.Exception.Message)); treating the vault as new."
        return $null
    }
}

function Write-FsVaultManifest {
    <# Writes _meta/manifest.json (files sorted by path). Returns the full path. #>
    [OutputType([string])]
    param(
        [Parameter(Mandatory)] [string] $VaultPath,
        [Parameter(Mandatory)] [System.Collections.IDictionary] $Manifest
    )
    $normalized = New-FsVaultManifest -PrimaryDomain ([string]$Manifest['primaryDomain']) -GeneratedAt ([string]$Manifest['generatedAt']) -ScanIds ([string[]]@($Manifest['scanIds'])) -Files $Manifest['files']
    return (Write-FsVaultFile -Root $VaultPath -RelativePath $script:FsVaultManifestPath -Content (ConvertTo-FsJsonText -Value $normalized -Depth 6))
}

# ---------------------------------------------------------------- sync

function Sync-FsVaultOutput {
    <#
    .SYNOPSIS
        Copies a rendered staging folder into the vault with minimal churn, removes stale generated files, writes the manifest.
    .DESCRIPTION
        1. Hashes every staged file into $Manifest.files.
        2. Copies a staged file when it is missing in the vault, its hash differs from the previous manifest, or the
           destination length differs (a file with no previous manifest entry is hashed directly for comparison).
        3. Deletes files listed in the previous manifest but not staged now — only inside owned roots, never under
           Notes/ or .obsidian/, and only .md files whose first 512 bytes contain 'generated: true'.
        4. Reports (never deletes) unexpected files in owned roots that are in neither manifest, and previously generated
           files that lost their marker.
        5. Removes empty directories under owned roots, writes the manifest last, deletes the staging folder.
        -WhatIf reports every action without touching the vault (staging is still removed unless -KeepStaging).
    .OUTPUTS
        Ordered hashtable: written, skipped, deleted, unexpected, warnings (string lists), counts, manifest, dryRun.
    #>
    [CmdletBinding(SupportsShouldProcess)]
    [OutputType([System.Collections.Specialized.OrderedDictionary])]
    param(
        [Parameter(Mandatory)] [string] $Staging,
        [Parameter(Mandatory)] [string] $VaultPath,
        [Parameter(Mandatory)] [System.Collections.IDictionary] $Manifest,
        [AllowNull()] [System.Collections.IDictionary] $PreviousManifest,
        [string[]] $OwnedRoots = $script:FsVaultOwnedRoots,
        [switch] $KeepStaging
    )
    $written = [System.Collections.Generic.List[string]]::new()
    $skipped = [System.Collections.Generic.List[string]]::new()
    $deleted = [System.Collections.Generic.List[string]]::new()
    $unexpected = [System.Collections.Generic.List[string]]::new()
    $warnings = [System.Collections.Generic.List[string]]::new()
    $dryRun = [bool]$WhatIfPreference

    if (-not (Test-Path -LiteralPath $Staging)) { throw "Sync-FsVaultOutput: staging folder '$Staging' does not exist." }
    if (-not (Test-Path -LiteralPath $VaultPath)) {
        if ($PSCmdlet.ShouldProcess($VaultPath, 'Create vault folder')) { New-Item -ItemType Directory -Path $VaultPath -Force | Out-Null }
    }
    if (-not $PSBoundParameters.ContainsKey('PreviousManifest')) { $PreviousManifest = Read-FsVaultManifest -VaultPath $VaultPath }
    $prevFiles = if ($PreviousManifest -and $PreviousManifest['files']) { $PreviousManifest['files'] } else { @{} }
    if ($PreviousManifest -and $PreviousManifest['primaryDomain'] -and $Manifest['primaryDomain'] -and
        -not ([string]$PreviousManifest['primaryDomain']).Equals([string]$Manifest['primaryDomain'], [System.StringComparison]::OrdinalIgnoreCase)) {
        $warnings.Add(("Primary domain changed from '{0}' to '{1}'; principal note paths may have moved." -f $PreviousManifest['primaryDomain'], $Manifest['primaryDomain']))
    }

    # 1. hash staging
    $newFiles = [ordered]@{}
    foreach ($rel in Get-FsVaultFileList -Root $Staging) {
        $newFiles[$rel] = Get-FsFileSha256 -Path (Get-FsVaultFullPath -Root $Staging -RelativePath $rel)
    }
    $Manifest['files'] = $newFiles
    $newLookup = [System.Collections.Generic.HashSet[string]]::new([string[]]@($newFiles.Keys), [System.StringComparer]::OrdinalIgnoreCase)
    $prevLookup = [System.Collections.Generic.HashSet[string]]::new([string[]]@($prevFiles.Keys), [System.StringComparer]::OrdinalIgnoreCase)

    # 2. copy changed
    foreach ($rel in $newFiles.Keys) {
        $src = Get-FsVaultFullPath -Root $Staging -RelativePath $rel
        $dest = Get-FsVaultFullPath -Root $VaultPath -RelativePath $rel
        $needs = $false
        if (-not (Test-Path -LiteralPath $dest)) { $needs = $true }
        else {
            $prevHash = if ($prevFiles.Contains($rel)) { [string]$prevFiles[$rel] } else { $null }
            if ($null -eq $prevHash) { $prevHash = Get-FsFileSha256 -Path $dest }
            if ($prevHash -ne $newFiles[$rel]) { $needs = $true }
            elseif ((Get-Item -LiteralPath $dest).Length -ne (Get-Item -LiteralPath $src).Length) { $needs = $true }
        }
        if (-not $needs) { $skipped.Add($rel); continue }
        if ($PSCmdlet.ShouldProcess($rel, 'Write')) {
            $dir = [System.IO.Path]::GetDirectoryName($dest)
            if ($dir -and -not (Test-Path -LiteralPath $dir)) { New-Item -ItemType Directory -Path $dir -Force | Out-Null }
            Invoke-FsIoRetry -Description "copy $rel" -Action { [System.IO.File]::Copy($src, $dest, $true) } | Out-Null
        }
        $written.Add($rel)
    }

    # 3. delete stale generated files
    foreach ($rel in @(Get-FsSorted -InputObject @($prevFiles.Keys))) {
        if ($newLookup.Contains($rel)) { continue }
        if (Test-FsVaultIgnoredPath $rel) { continue }
        if (-not (Test-FsVaultOwnedPath -RelativePath $rel -OwnedRoots $OwnedRoots)) { continue }
        $dest = Get-FsVaultFullPath -Root $VaultPath -RelativePath $rel
        if (-not (Test-Path -LiteralPath $dest)) { continue }
        if ($rel -like '*.md' -and -not (Test-FsGeneratedNote -Path $dest)) {
            $unexpected.Add($rel)
            $warnings.Add(("'{0}' was generated previously but no longer carries 'generated: true'; left in place." -f $rel))
            continue
        }
        if ($PSCmdlet.ShouldProcess($rel, 'Delete stale generated file')) {
            Invoke-FsIoRetry -Description "delete $rel" -Action { [System.IO.File]::Delete($dest) } | Out-Null
        }
        $deleted.Add($rel)
    }

    # 4. unexpected files in owned roots
    $unexpectedSet = [System.Collections.Generic.HashSet[string]]::new([string[]]@($unexpected), [System.StringComparer]::OrdinalIgnoreCase)
    foreach ($rel in Get-FsVaultFileList -Root $VaultPath) {
        if ($newLookup.Contains($rel) -or $prevLookup.Contains($rel)) { continue }
        if (Test-FsVaultIgnoredPath $rel) { continue }
        if (-not (Test-FsVaultOwnedPath -RelativePath $rel -OwnedRoots $OwnedRoots)) { continue }
        if ($unexpectedSet.Add($rel)) {
            $unexpected.Add($rel)
            $warnings.Add(("Unexpected file in a generated folder: '{0}' (not deleted; move your notes to Notes/)." -f $rel))
        }
    }

    # 5. empty directories under owned roots
    foreach ($root in $OwnedRoots) {
        $rootPath = Join-Path $VaultPath $root
        if (-not (Test-Path -LiteralPath $rootPath)) { continue }
        $dirs = @(Get-ChildItem -LiteralPath $rootPath -Recurse -Directory -Force | ForEach-Object { $_.FullName })
        $dirs = @(Get-FsSorted -InputObject $dirs -Key { param($d) $d.Length } -Descending)
        foreach ($d in $dirs) {
            if (@(Get-ChildItem -LiteralPath $d -Force).Count -eq 0) {
                if ($PSCmdlet.ShouldProcess((Get-FsRelativeVaultPath -Root $VaultPath -FullPath $d), 'Remove empty directory')) { Remove-Item -LiteralPath $d -Force }
            }
        }
    }

    # 6. manifest last
    if ($PSCmdlet.ShouldProcess($script:FsVaultManifestPath, 'Write manifest')) { Write-FsVaultManifest -VaultPath $VaultPath -Manifest $Manifest | Out-Null }

    if (-not $KeepStaging) { Remove-Item -LiteralPath $Staging -Recurse -Force -ErrorAction SilentlyContinue -WhatIf:$false -Confirm:$false }

    return [ordered]@{
        written    = [string[]]$written.ToArray()
        skipped    = [string[]]$skipped.ToArray()
        deleted    = [string[]]$deleted.ToArray()
        unexpected = [string[]]$unexpected.ToArray()
        warnings   = [string[]]$warnings.ToArray()
        counts     = [ordered]@{ written = $written.Count; skipped = $skipped.Count; deleted = $deleted.Count; unexpected = $unexpected.Count; warnings = $warnings.Count }
        manifest   = $Manifest
        dryRun     = $dryRun
    }
}
