<#
JSON Canvas 1.0 (https://jsoncanvas.org/spec/1.0/) helpers for Dashboard.canvas.

Node and edge ids are 16 hex characters derived from a stable key (sha1), so re-renders produce identical
files. Nodes and edges are emitted sorted by id; the JSON is pretty-printed with 2-space indent and LF.
#>

function Get-FsCanvasId {
    <# 16-hex id from a stable key. Returns the key unchanged when it already is a 16-hex id. #>
    [OutputType([string])]
    param([Parameter(Mandatory)] [string] $Key)
    if ($Key -match '^[0-9a-f]{16}$') { return $Key }
    return (Get-FsHexHash -Text $Key -Length 16)
}

function New-FsCanvasNode {
    <#
    .SYNOPSIS
        Canvas node. -Kind text needs -Text; file needs -File (vault path WITH extension, optional -Subpath '#Heading');
        group takes an optional -Label. -Color is a preset "1".."6" or "#rrggbb".
    #>
    [OutputType([System.Collections.Specialized.OrderedDictionary])]
    param(
        [Parameter(Mandatory)] [ValidateSet('text', 'file', 'group')] [string] $Kind,
        [Parameter(Mandatory)] [string] $Key,
        [Parameter(Mandatory)] [int] $X,
        [Parameter(Mandatory)] [int] $Y,
        [Parameter(Mandatory)] [int] $Width,
        [Parameter(Mandatory)] [int] $Height,
        [AllowNull()] [string] $Text,
        [AllowNull()] [string] $File,
        [AllowNull()] [string] $Subpath,
        [AllowNull()] [string] $Color,
        [AllowNull()] [string] $Label
    )
    $node = [ordered]@{
        id     = Get-FsCanvasId -Key $Key
        type   = $Kind
        x      = $X
        y      = $Y
        width  = $Width
        height = $Height
    }
    if (-not [string]::IsNullOrEmpty($Color)) { $node['color'] = $Color }
    switch ($Kind) {
        'text' { $node['text'] = $(if ($null -eq $Text) { '' } else { $Text.Replace("`r`n", "`n") }) }
        'file' {
            if ([string]::IsNullOrEmpty($File)) { throw 'New-FsCanvasNode: -File is required for file nodes.' }
            $node['file'] = $File
            if (-not [string]::IsNullOrEmpty($Subpath)) { $node['subpath'] = $(if ($Subpath.StartsWith('#')) { $Subpath } else { '#' + $Subpath }) }
        }
        'group' { if (-not [string]::IsNullOrEmpty($Label)) { $node['label'] = $Label } }
    }
    return $node
}

function New-FsCanvasEdge {
    <#
    .SYNOPSIS
        Canvas edge between two nodes. -From/-To accept node ids (from New-FsCanvasNode .id) or the node keys.
    #>
    [OutputType([System.Collections.Specialized.OrderedDictionary])]
    param(
        [Parameter(Mandatory)] [string] $Key,
        [Parameter(Mandatory)] [string] $From,
        [Parameter(Mandatory)] [string] $To,
        [ValidateSet('top', 'right', 'bottom', 'left')] [string] $FromSide = 'right',
        [ValidateSet('top', 'right', 'bottom', 'left')] [string] $ToSide = 'left',
        [AllowNull()] [string] $Label,
        [AllowNull()] [string] $Color
    )
    $edge = [ordered]@{
        id       = Get-FsCanvasId -Key $Key
        fromNode = Get-FsCanvasId -Key $From
        fromSide = $FromSide
        toNode   = Get-FsCanvasId -Key $To
        toSide   = $ToSide
    }
    if (-not [string]::IsNullOrEmpty($Color)) { $edge['color'] = $Color }
    if (-not [string]::IsNullOrEmpty($Label)) { $edge['label'] = $Label }
    return $edge
}

function ConvertTo-FsCanvasJson {
    <#
    .SYNOPSIS
        JSON Canvas document text {"nodes":[...],"edges":[...]} — 2-space indent, LF, sorted by id, trailing newline.
    #>
    [OutputType([string])]
    param(
        [AllowNull()] [AllowEmptyCollection()] [object[]] $Nodes,
        [AllowNull()] [AllowEmptyCollection()] [object[]] $Edges
    )
    $doc = [ordered]@{
        nodes = @(Get-FsSorted -InputObject @($Nodes | Where-Object { $null -ne $_ }) -Property 'id')
        edges = @(Get-FsSorted -InputObject @($Edges | Where-Object { $null -ne $_ }) -Property 'id')
    }
    return (ConvertTo-FsJsonText -Value $doc -Depth 6)
}

function ConvertTo-FsJsonText {
    <# ConvertTo-Json with the newline/format normalization every generated JSON file uses (2-space indent, LF, trailing newline). #>
    [OutputType([string])]
    param([Parameter(Mandatory)] $Value, [int] $Depth = 10)
    $json = ConvertTo-Json -InputObject $Value -Depth $Depth
    $json = $json.Replace("`r`n", "`n")
    return ($json.TrimEnd("`n") + "`n")
}
