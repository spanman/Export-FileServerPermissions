<#
Note names and vault-relative note paths.

Every generated note lives at a deterministic path derived from the entity id and the merged
model. Wikilinks always use the full vault path ("Users/jsmith", never a bare name), so this
file is the single source of truth for where an entity's note is.

Filename rules (plan, Phase 5):
  - replace  # ^ [ ] | \ / : * ? " < >  and control characters with '_'
  - collapse whitespace, trim, strip trailing '.' and spaces, leading '.' -> '_'
  - Windows reserved device names and names longer than -MaxLength get " ~<6 hex>" (sha1 of the identity)

Path table:
  Server                       Servers/FS01
  Share                        Shares/FS01 - Finance             (share-root folders map here too)
  Folder                       Folders/FS01/Finance/Budgets - 2024   (relativePath, '\' -> ' - ')
  User/Computer, primary dom.  Users/jsmith
  User/Computer, other domain  Users/CORP - jsmith
  Group, primary domain        Groups/Finance-RW
  Group, other domain          Groups/CORP - Finance-RW
  LocalGroup                   Groups/FS01 - Power Users         (incl. BUILTIN groups seen on a server)
  LocalUser                    Users/FS01 - Administrator
  WellKnown                    WellKnown/Authenticated Users ; BUILTIN SIDs -> WellKnown/BUILTIN - Administrators
  OrphanedSid / Foreign        Orphaned/S-1-5-21-...
  Effective                    Effective/<path of the principal or share>
  Report                       Reports/<file name>
  Home / Canvas                Home / Dashboard
#>

$script:FsNoteIllegalChars = [regex]'[#^\[\]|\\/:*?"<>\x00-\x1F\x7F]'
$script:FsNoteReservedNames = [regex]'^(?i:CON|PRN|AUX|NUL|COM[1-9]|LPT[1-9])$'
$script:FsNoteHashSuffixLength = 8   # " ~" + 6 hex

function Get-FsShortHash {
    <#
    .SYNOPSIS
        First 6 lowercase hex characters of the SHA-1 of a string (UTF-8). Used for name disambiguation.
    #>
    [OutputType([string])]
    param([Parameter(Mandatory)] [AllowEmptyString()] [string] $Text)
    return (Get-FsHexHash -Text $Text -Length 6)
}

function Get-FsHexHash {
    <# Lowercase hex prefix of the SHA-1 of a UTF-8 string. #>
    [OutputType([string])]
    param([Parameter(Mandatory)] [AllowEmptyString()] [string] $Text, [int] $Length = 6)
    $sha = [System.Security.Cryptography.SHA1]::Create()
    try {
        $bytes = $sha.ComputeHash([System.Text.Encoding]::UTF8.GetBytes($Text))
    }
    finally { $sha.Dispose() }
    $hex = [System.BitConverter]::ToString($bytes).Replace('-', '').ToLowerInvariant()
    return $hex.Substring(0, [Math]::Min($Length, $hex.Length))
}

function Get-FsSafeNoteName {
    <#
    .SYNOPSIS
        Turns arbitrary text into a legal, deterministic Obsidian/Windows file name (no extension).
    .PARAMETER Name
        The desired name.
    .PARAMETER Identity
        Text hashed for the " ~xxxxxx" suffix when one is needed (default: the original Name).
    .PARAMETER MaxLength
        Maximum length of the returned name, including any hash suffix.
    .OUTPUTS
        The safe name. Use Test-FsNoteNameChanged to learn whether characters were replaced.
    #>
    [OutputType([string])]
    param(
        [Parameter(Mandatory)] [AllowEmptyString()] [string] $Name,
        [AllowNull()] [string] $Identity,
        [int] $MaxLength = 100
    )
    $result = Get-FsSafeNoteNameInfo -Name $Name -Identity $Identity -MaxLength $MaxLength
    return $result.name
}

function Get-FsSafeNoteNameInfo {
    <#
    .SYNOPSIS
        Get-FsSafeNoteName plus diagnostics: @{ name; changed (chars replaced or trimmed); hashed (suffix added) }.
    #>
    [OutputType([hashtable])]
    param(
        [Parameter(Mandatory)] [AllowEmptyString()] [string] $Name,
        [AllowNull()] [string] $Identity,
        [int] $MaxLength = 100
    )
    if ([string]::IsNullOrEmpty($Identity)) { $Identity = $Name }
    $original = $Name
    $n = $script:FsNoteIllegalChars.Replace($Name, '_')
    $n = [regex]::Replace($n, '\s+', ' ').Trim()
    $n = $n.TrimEnd('.', ' ')
    if ($n.StartsWith('.')) { $n = '_' + $n.Substring(1) }
    $changed = ($n -ne $original)
    $hashed = $false
    if ($n.Length -eq 0) { $n = '_'; $hashed = $true }
    if ($script:FsNoteReservedNames.IsMatch($n)) { $hashed = $true }
    if ($n.Length -gt $MaxLength) {
        $keep = [Math]::Max(1, $MaxLength - $script:FsNoteHashSuffixLength)
        $n = $n.Substring(0, $keep).TrimEnd('.', ' ')
        $hashed = $true
    }
    if ($hashed) { $n = '{0} ~{1}' -f $n, (Get-FsShortHash -Text $Identity) }
    return @{ name = $n; changed = ($changed -or $hashed); hashed = $hashed }
}

function Get-FsPrimaryDomain {
    <#
    .SYNOPSIS
        Picks the primary (NetBIOS) domain for note naming: -Requested, else the most common principal
        domain in the model, else $env:USERDOMAIN, else 'DOMAIN'.
    #>
    [OutputType([string])]
    param(
        [Parameter(Mandatory)] [System.Collections.IDictionary] $Model,
        [AllowNull()] [string] $Requested
    )
    if (-not [string]::IsNullOrWhiteSpace($Requested)) { return $Requested.Trim() }
    $counts = [System.Collections.Generic.Dictionary[string, int]]::new([System.StringComparer]::OrdinalIgnoreCase)
    $display = @{}
    if ($Model.Contains('principals') -and $Model.principals) {
        foreach ($id in Get-FsSortedKeys $Model.principals) {
            $p = $Model.principals[$id]
            $kind = [string](Get-FsValue $p 'kind')
            if ($kind -notin 'User', 'Group', 'Computer') { continue }
            $dom = [string](Get-FsValue $p 'domain')
            if ([string]::IsNullOrWhiteSpace($dom)) { continue }
            if (-not $counts.ContainsKey($dom)) { $counts[$dom] = 0; $display[$dom.ToUpperInvariant()] = $dom }
            $counts[$dom]++
        }
    }
    if ($counts.Count -gt 0) {
        $best = $null; $bestCount = -1
        foreach ($dom in Get-FsSorted -InputObject @($counts.Keys)) {
            if ($counts[$dom] -gt $bestCount) { $best = $dom; $bestCount = $counts[$dom] }
        }
        return $display[$best.ToUpperInvariant()]
    }
    if ($Model.Contains('domains') -and $Model.domains -and $Model.domains.Count -gt 0) {
        return [string]$Model.domains[(Get-FsSortedKeys $Model.domains)[0]]
    }
    if (-not [string]::IsNullOrWhiteSpace($env:USERDOMAIN)) { return $env:USERDOMAIN }
    return 'DOMAIN'
}

function New-FsNameContext {
    <#
    .SYNOPSIS
        Creates the naming context used by Get-FsNotePath: primary domain, memo tables and collision registry.
    .OUTPUTS
        Hashtable: primaryDomain, model, paths (memo "Kind|Id" -> path), owners (path -> "Kind|Id", case-insensitive),
        warnings (List[string]).
    #>
    [OutputType([hashtable])]
    param(
        [Parameter(Mandatory)] [System.Collections.IDictionary] $Model,
        [AllowNull()] [string] $PrimaryDomain
    )
    return @{
        primaryDomain = (Get-FsPrimaryDomain -Model $Model -Requested $PrimaryDomain)
        model         = $Model
        paths         = [System.Collections.Generic.Dictionary[string, string]]::new([System.StringComparer]::Ordinal)
        owners        = [System.Collections.Generic.Dictionary[string, string]]::new([System.StringComparer]::OrdinalIgnoreCase)
        warnings      = [System.Collections.Generic.List[string]]::new()
    }
}

function Register-FsNotePath {
    <#
    .SYNOPSIS
        Records that <Kind|Id> owns a vault path. When a different entity already owns the same path
        (case-insensitively, since Windows/OneDrive are case-insensitive) the path gets a " ~hash" suffix
        on its last segment and a warning is recorded in $Context.warnings.
    .OUTPUTS
        The (possibly suffixed) path.
    #>
    [OutputType([string])]
    param(
        [Parameter(Mandatory)] [hashtable] $Context,
        [Parameter(Mandatory)] [string] $Path,
        [Parameter(Mandatory)] [string] $Owner,
        [Parameter(Mandatory)] [AllowEmptyString()] [string] $HashIdentity
    )
    if ($Context.owners.ContainsKey($Path)) {
        $existing = $Context.owners[$Path]
        if ($existing -eq $Owner) { return $Path }
        $suffixed = '{0} ~{1}' -f $Path, (Get-FsShortHash -Text $HashIdentity)
        $Context.warnings.Add(("Note path collision: '{0}' is used by {1}; {2} renamed to '{3}'." -f $Path, $existing, $Owner, $suffixed))
        $Path = $suffixed
        if ($Context.owners.ContainsKey($Path) -and $Context.owners[$Path] -ne $Owner) {
            # Two hash collisions in a row: extend with the full 16-hex hash (practically unreachable).
            $Path = '{0} ~{1}' -f $Path, (Get-FsHexHash -Text $HashIdentity -Length 16)
        }
    }
    $Context.owners[$Path] = $Owner
    return $Path
}

function Get-FsNotePath {
    <#
    .SYNOPSIS
        Vault-relative note path (forward slashes, no extension) for an entity. Memoized per context.
    .PARAMETER Kind
        Server | Share | Folder | Principal | Effective | Report | Home | Canvas
    .PARAMETER Id
        Entity id: server name, share id, folder id, principal id, report file name (without extension).
        For Effective: a principal id or a share id.
    .PARAMETER Extension
        Optional extension to append ('md', '.md', 'canvas'). Omit for wikilinks.
    #>
    [OutputType([string])]
    param(
        [Parameter(Mandatory)] [hashtable] $Context,
        [Parameter(Mandatory)] [ValidateSet('Server', 'Share', 'Folder', 'Principal', 'Effective', 'Report', 'Home', 'Canvas')] [string] $Kind,
        [AllowEmptyString()] [string] $Id = '',
        [AllowNull()] [string] $Extension
    )
    $memoKey = '{0}|{1}' -f $Kind, $Id
    if ($Context.paths.ContainsKey($memoKey)) { $path = $Context.paths[$memoKey] }
    else {
        # Aliases (Effective companions, share-root folders) reuse another entity's path and are not registered as owners.
        $register = ($Kind -ne 'Effective')
        if ($Kind -eq 'Folder' -and $Context.model.folders -and $Context.model.folders.Contains($Id) -and (Get-FsValue $Context.model.folders[$Id] 'isShareRoot')) {
            $register = $false
        }
        $path = switch ($Kind) {
            'Home' { 'Home' }
            'Canvas' { 'Dashboard' }
            'Server' { 'Servers/' + (Get-FsSafeNoteName -Name $Id.ToUpperInvariant() -Identity $Id) }
            'Report' { 'Reports/' + (Get-FsSafeNoteName -Name $Id -Identity $Id) }
            'Share' { Get-FsSharePath -Context $Context -ShareId $Id }
            'Folder' { Get-FsFolderPath -Context $Context -FolderId $Id }
            'Principal' { Get-FsPrincipalPath -Context $Context -PrincipalId $Id }
            'Effective' { Get-FsEffectivePath -Context $Context -Id $Id }
        }
        if ($register) { $path = Register-FsNotePath -Context $Context -Path $path -Owner $memoKey -HashIdentity $Id }
        $Context.paths[$memoKey] = $path
    }
    if (-not [string]::IsNullOrEmpty($Extension)) { $path += '.' + $Extension.TrimStart('.') }
    return $path
}

function Split-FsShareId {
    <# "FS01\Finance" -> @{ server = 'FS01'; name = 'Finance' } (share ids are SERVER\Name). #>
    [OutputType([hashtable])]
    param([Parameter(Mandatory)] [string] $ShareId)
    $i = $ShareId.IndexOf('\')
    if ($i -lt 0) { return @{ server = ''; name = $ShareId } }
    return @{ server = $ShareId.Substring(0, $i); name = $ShareId.Substring($i + 1) }
}

function Get-FsSharePath {
    [OutputType([string])]
    param([Parameter(Mandatory)] [hashtable] $Context, [Parameter(Mandatory)] [string] $ShareId)
    $model = $Context.model
    $server = $null; $name = $null
    if ($model.shares -and $model.shares.Contains($ShareId)) {
        $share = $model.shares[$ShareId]
        $server = [string](Get-FsValue $share 'server'); $name = [string](Get-FsValue $share 'name')
    }
    if ([string]::IsNullOrEmpty($name)) { $parts = Split-FsShareId $ShareId; $server = $parts.server; $name = $parts.name }
    $server = $server.ToUpperInvariant()
    return 'Shares/' + (Get-FsSafeNoteName -Name ('{0} - {1}' -f $server, $name) -Identity $ShareId)
}

function Get-FsFolderPath {
    [OutputType([string])]
    param([Parameter(Mandatory)] [hashtable] $Context, [Parameter(Mandatory)] [string] $FolderId)
    $model = $Context.model
    $folder = if ($model.folders -and $model.folders.Contains($FolderId)) { $model.folders[$FolderId] } else { $null }
    if ($null -ne $folder) {
        if (Get-FsValue $folder 'isShareRoot') { return Get-FsNotePath -Context $Context -Kind Share -Id ([string](Get-FsValue $folder 'primaryShareId')) }
        $server = [string](Get-FsValue $folder 'server')
        $shareParts = Split-FsShareId ([string](Get-FsValue $folder 'primaryShareId'))
        $shareName = $shareParts.name
        $rel = [string](Get-FsValue $folder 'relativePath')
    }
    else {
        # Unknown folder id "SERVER:X:\path": fall back to server + leaf, hashed for uniqueness.
        $colon = $FolderId.IndexOf(':')
        $server = if ($colon -gt 0) { $FolderId.Substring(0, $colon) } else { 'UNKNOWN' }
        $shareName = '_unknown'
        $rel = Get-FsPathLeaf -Path $(if ($colon -ge 0) { $FolderId.Substring($colon + 1) } else { $FolderId })
    }
    $serverSeg = Get-FsSafeNoteName -Name $server.ToUpperInvariant() -Identity $server
    $shareSeg = Get-FsSafeNoteName -Name $shareName -Identity $shareName
    $needsHash = ($null -eq $folder)
    $segments = foreach ($c in ($rel -split '\\+')) {
        if ($c -eq '') { continue }
        $info = Get-FsSafeNoteNameInfo -Name $c -Identity $c -MaxLength 1000
        if ($info.changed -or $c.Contains(' - ')) { $needsHash = $true }
        $info.name
    }
    $leaf = (@($segments) -join ' - ')
    if ($leaf.Length -eq 0) { $leaf = '_'; $needsHash = $true }
    $maxLeaf = 100
    if ($leaf.Length -gt $maxLeaf - $script:FsNoteHashSuffixLength) {
        $leaf = $leaf.Substring(0, $maxLeaf - $script:FsNoteHashSuffixLength).TrimEnd('.', ' ', '-')
        $needsHash = $true
    }
    if ($script:FsNoteReservedNames.IsMatch($leaf)) { $needsHash = $true }
    if ($needsHash) { $leaf = '{0} ~{1}' -f $leaf, (Get-FsShortHash -Text $FolderId) }
    return 'Folders/{0}/{1}/{2}' -f $serverSeg, $shareSeg, $leaf
}

function Get-FsPrincipalPath {
    [OutputType([string])]
    param([Parameter(Mandatory)] [hashtable] $Context, [Parameter(Mandatory)] [string] $PrincipalId)
    $p = Get-FsModelPrincipal -Model $Context.model -Id $PrincipalId
    $kind = [string](Get-FsValue $p 'kind')
    $name = [string](Get-FsValue $p 'name')
    if ([string]::IsNullOrWhiteSpace($name)) { $name = [string](Get-FsValue $p 'displayName') }
    if ([string]::IsNullOrWhiteSpace($name)) { $name = $PrincipalId }
    $domain = [string](Get-FsValue $p 'domain')
    $server = [string](Get-FsValue $p 'server')
    if ([string]::IsNullOrWhiteSpace($server) -and (Test-FsLocalPrincipalId $PrincipalId)) { $server = $PrincipalId.Split('\')[0] }
    $sid = [string](Get-FsValue $p 'sid')
    $primary = [string]$Context.primaryDomain

    switch ($kind) {
        { $_ -in 'User', 'Computer', 'Group' } {
            $folder = if ($kind -eq 'Group') { 'Groups' } else { 'Users' }
            $isPrimary = [string]::IsNullOrWhiteSpace($domain) -or $domain.Equals($primary, [System.StringComparison]::OrdinalIgnoreCase)
            $leaf = if ($isPrimary) { $name } else { '{0} - {1}' -f $domain.ToUpperInvariant(), $name }
            return '{0}/{1}' -f $folder, (Get-FsSafeNoteName -Name $leaf -Identity $PrincipalId)
        }
        'LocalGroup' { return 'Groups/' + (Get-FsSafeNoteName -Name ('{0} - {1}' -f $server.ToUpperInvariant(), $name) -Identity $PrincipalId) }
        'LocalUser' { return 'Users/' + (Get-FsSafeNoteName -Name ('{0} - {1}' -f $server.ToUpperInvariant(), $name) -Identity $PrincipalId) }
        'WellKnown' {
            $leaf = if ($sid -like 'S-1-5-32-*' -or $domain -eq 'BUILTIN') { 'BUILTIN - ' + $name } else { $name }
            return 'WellKnown/' + (Get-FsSafeNoteName -Name $leaf -Identity $PrincipalId)
        }
        default { return 'Orphaned/' + (Get-FsSafeNoteName -Name $PrincipalId -Identity $PrincipalId) }
    }
}

function Get-FsEffectivePath {
    <# Effective/<Users|Groups|WellKnown|Orphaned|Shares|Folders>/<same leaf as the primary note>. #>
    [OutputType([string])]
    param([Parameter(Mandatory)] [hashtable] $Context, [Parameter(Mandatory)] [string] $Id)
    $model = $Context.model
    $base = if ($model.shares -and $model.shares.Contains($Id)) { Get-FsNotePath -Context $Context -Kind Share -Id $Id }
    elseif ($model.folders -and $model.folders.Contains($Id)) { Get-FsNotePath -Context $Context -Kind Folder -Id $Id }
    else { Get-FsNotePath -Context $Context -Kind Principal -Id $Id }
    return 'Effective/' + $base
}

function Get-FsDisplayName {
    <#
    .SYNOPSIS
        Alias text used after '|' in wikilinks: principals -> name (local accounts "Name (SERVER)"),
        shares -> \\SERVER\Share, folders -> relativePath with backslashes, servers -> name, reports -> title.
    #>
    [OutputType([string])]
    param(
        [Parameter(Mandatory)] [System.Collections.IDictionary] $Model,
        [Parameter(Mandatory)] [ValidateSet('Server', 'Share', 'Folder', 'Principal', 'Report', 'Home', 'Canvas')] [string] $Kind,
        [AllowEmptyString()] [string] $Id = ''
    )
    switch ($Kind) {
        'Home' { return 'Home' }
        'Canvas' { return 'Dashboard' }
        'Report' { return $Id }
        'Server' { return $Id.ToUpperInvariant() }
        'Share' {
            if ($Model.shares -and $Model.shares.Contains($Id)) {
                $unc = [string](Get-FsValue $Model.shares[$Id] 'uncPath')
                if ($unc) { return $unc }
            }
            $parts = Split-FsShareId $Id
            return Join-FsUnc -Server $parts.server.ToUpperInvariant() -Share $parts.name
        }
        'Folder' {
            if ($Model.folders -and $Model.folders.Contains($Id)) {
                $f = $Model.folders[$Id]
                if (Get-FsValue $f 'isShareRoot') { return Get-FsDisplayName -Model $Model -Kind Share -Id ([string](Get-FsValue $f 'primaryShareId')) }
                $rel = [string](Get-FsValue $f 'relativePath')
                if ($rel) { return $rel }
                return [string](Get-FsValue $f 'uncPath')
            }
            return $Id
        }
        'Principal' {
            $p = Get-FsModelPrincipal -Model $Model -Id $Id
            # Named $principalKind, NOT $kind: PowerShell variable names are case-insensitive, so a local
            # $kind would silently reassign the validated -Kind parameter (case difference notwithstanding)
            # and re-trigger its [ValidateSet] check against the principal's own kind (e.g. 'LocalGroup'),
            # which is not one of the note-entity kinds and would throw.
            $principalKind = [string](Get-FsValue $p 'kind')
            $name = [string](Get-FsValue $p 'name')
            if ([string]::IsNullOrWhiteSpace($name)) { $name = [string](Get-FsValue $p 'displayName') }
            if ([string]::IsNullOrWhiteSpace($name)) { return $Id }
            if ($principalKind -in 'LocalGroup', 'LocalUser') {
                $server = [string](Get-FsValue $p 'server')
                if ([string]::IsNullOrWhiteSpace($server) -and (Test-FsLocalPrincipalId $Id)) { $server = $Id.Split('\')[0] }
                if ($server) { return '{0} ({1})' -f $name, $server.ToUpperInvariant() }
            }
            return $name
        }
    }
}
