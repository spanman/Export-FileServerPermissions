<#
UNC and Windows path string helpers.

Split-Path and [IO.Path] treat '\' as an ordinary character on Linux, where the test
container runs, so the renderer and analytics must only ever use these helpers on
path *data*. Filesystem output paths still go through Join-Path.
#>

function ConvertTo-FsNormalizedPath {
    <# Lowercase, strip the \\?\ long-path prefix, collapse doubled separators (except a UNC lead), trim a trailing '\'. #>
    [OutputType([string])]
    param([AllowEmptyString()] [string] $Path)
    if ([string]::IsNullOrWhiteSpace($Path)) { return '' }
    $p = $Path.Trim()
    if ($p.StartsWith('\\?\UNC\', [System.StringComparison]::OrdinalIgnoreCase)) { $p = '\\' + $p.Substring(8) }
    elseif ($p.StartsWith('\\?\')) { $p = $p.Substring(4) }
    $isUnc = $p.StartsWith('\\')
    $body = $p.TrimStart('\') -replace '\\{2,}', '\'
    $body = $body.TrimEnd('\')
    $result = if ($isUnc) { '\\' + $body } else { $body }
    return $result.ToLowerInvariant()
}

function Split-FsUnc {
    <#
    .SYNOPSIS
        Splits \\Server\Share\a\b into its parts. Returns $null for a non-UNC string.
    #>
    [OutputType([hashtable])]
    param([Parameter(Mandatory)] [string] $Path)
    $m = [regex]::Match($Path.Trim(), '^\\\\(?<server>[^\\]+)\\(?<share>[^\\]+)(?:\\(?<rel>.*))?$')
    if (-not $m.Success) { return $null }
    $rel = $m.Groups['rel'].Value.Trim('\')
    $segments = if ($rel) { @($rel -split '\\+' | Where-Object { $_ -ne '' }) } else { @() }
    return @{
        Server   = $m.Groups['server'].Value
        Share    = $m.Groups['share'].Value
        Relative = ($segments -join '\')
        Segments = $segments
        Depth    = $segments.Count
    }
}

function Join-FsUnc {
    [OutputType([string])]
    param(
        [Parameter(Mandatory)] [string] $Server,
        [Parameter(Mandatory)] [string] $Share,
        [AllowEmptyString()] [string] $Relative = ''
    )
    $u = "\\$Server\$Share"
    if ($Relative) { $u += '\' + $Relative.Trim('\') }
    return $u
}

function Get-FsPathLeaf {
    <# Last segment of a backslash path. #>
    [OutputType([string])]
    param([Parameter(Mandatory)] [AllowEmptyString()] [string] $Path)
    $t = $Path.TrimEnd('\')
    $i = $t.LastIndexOf('\')
    return $(if ($i -ge 0) { $t.Substring($i + 1) } else { $t })
}

function Get-FsPathParent {
    <# Parent of a backslash path, or $null at the root (drive root, share root or bare UNC). #>
    [OutputType([string])]
    param([Parameter(Mandatory)] [AllowEmptyString()] [string] $Path)
    $t = $Path.TrimEnd('\')
    $i = $t.LastIndexOf('\')
    if ($i -le 0) { return $null }
    $parent = $t.Substring(0, $i)
    if ($parent -eq '\' -or $parent -match '^[A-Za-z]:$' -or $parent -eq '\\') { return $null }
    if ($t.StartsWith('\\') -and ($parent.TrimStart('\') -notmatch '\\')) { return $null }  # \\server alone
    return $parent
}

function Get-FsRelativePath {
    <# Path of $Child relative to $Root (both backslash paths, case-insensitive). '' when equal, $null when not under root. #>
    [OutputType([string])]
    param([Parameter(Mandatory)] [string] $Root, [Parameter(Mandatory)] [string] $Child)
    $r = (ConvertTo-FsNormalizedPath $Root)
    $c = (ConvertTo-FsNormalizedPath $Child)
    if ($c -eq $r) { return '' }
    if ($c.StartsWith($r + '\')) { return $Child.TrimEnd('\').Substring($r.Length + 1) }
    return $null
}

function Test-FsPathUnder {
    <# True when $Child equals $Root or is nested under it (segment-aligned). #>
    [OutputType([bool])]
    param([Parameter(Mandatory)] [string] $Root, [Parameter(Mandatory)] [string] $Child)
    return ($null -ne (Get-FsRelativePath -Root $Root -Child $Child))
}
