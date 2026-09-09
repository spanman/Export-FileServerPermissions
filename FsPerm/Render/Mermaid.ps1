<#
Mermaid flowchart generation for note bodies (share folder trees, user access paths, group nesting).

Node ids are never taken from data: nodes are renumbered n1, n2, ... in ordinal id order so output is
deterministic and free of Mermaid keywords ('end', 'graph', ...). Labels are always quoted and escaped.
Caps: 60 nodes / 80 edges by default, with an italic footnote when truncated.
#>

$script:FsMermaidDefaultClasses = [ordered]@{
    'user'        = 'fill:#c8e6c9,stroke:#2e7d32,color:#1b1b1b'
    'group'       = 'fill:#bbdefb,stroke:#1565c0,color:#1b1b1b'
    'local-group' = 'fill:#b3e5fc,stroke:#0277bd,color:#1b1b1b'
    'share'       = 'fill:#ffe0b2,stroke:#ef6c00,color:#1b1b1b'
    'folder'      = 'fill:#fff9c4,stroke:#f9a825,color:#1b1b1b'
    'protected'   = 'fill:#fff59d,stroke:#f57f17,stroke-width:2px,stroke-dasharray:4 2,color:#1b1b1b'
    'deny'        = 'fill:#ffcdd2,stroke:#c62828,stroke-width:2px,color:#1b1b1b'
    'well-known'  = 'fill:#e1bee7,stroke:#6a1b9a,color:#1b1b1b'
    'server'      = 'fill:#ef9a9a,stroke:#b71c1c,color:#1b1b1b'
    'orphaned'    = 'fill:#f8bbd0,stroke:#ad1457,color:#1b1b1b'
    'computer'    = 'fill:#dcedc8,stroke:#558b2f,color:#1b1b1b'
}

function Format-FsMermaidLabel {
    <#
    .SYNOPSIS
        Escapes text for use inside a quoted Mermaid label: # -> #35; " -> #quot; < -> #lt; > -> #gt;
        Newlines become spaces. Brackets, parentheses and braces are safe inside quotes and kept.
    #>
    [OutputType([string])]
    param([AllowNull()] [string] $Text)
    if ([string]::IsNullOrEmpty($Text)) { return '' }
    $t = [regex]::Replace($Text, '\r\n|\r|\n', ' ')
    $t = $t.Replace('#', '#35;')
    $t = $t.Replace('"', '#quot;')
    $t = $t.Replace('<', '#lt;').Replace('>', '#gt;')
    return $t
}

function Get-FsMermaidClassName {
    <# Mermaid class identifiers: letters, digits and underscore only. #>
    [OutputType([string])]
    param([Parameter(Mandatory)] [string] $Name)
    $n = [regex]::Replace($Name, '[^A-Za-z0-9_]', '_')
    if ($n -match '^\d') { $n = '_' + $n }
    return $n
}

function New-FsMermaidFlowchart {
    <#
    .SYNOPSIS
        Fenced ```mermaid flowchart block.
    .PARAMETER Nodes
        Objects/dictionaries with id, label, class (class optional; must be a key of the class table).
        Input order decides which nodes survive -MaxNodes (first N kept); ids are assigned in ordinal id order.
    .PARAMETER Edges
        Objects/dictionaries with from, to (node ids), optional label and style ('solid' default | 'dashed').
        Edges to dropped nodes are dropped; duplicates removed; sorted by from, to, label.
    .PARAMETER Subgraphs
        Objects/dictionaries with id, title, nodeIds. A node belongs to at most one subgraph (first wins).
    .PARAMETER Classes
        Hashtable class name -> style, merged over the defaults (user, group, local-group, share, folder, protected,
        deny, well-known, server, orphaned, computer).
    .OUTPUTS
        The fenced block, followed by an italic "_… +N more nodes not shown_" line when truncated.
    #>
    [OutputType([string])]
    param(
        [ValidateSet('LR', 'TB', 'BT', 'RL')] [string] $Direction = 'LR',
        [AllowNull()] [AllowEmptyCollection()] [object[]] $Nodes,
        [AllowNull()] [AllowEmptyCollection()] [object[]] $Edges,
        [AllowNull()] [System.Collections.IDictionary] $Classes,
        [AllowNull()] [AllowEmptyCollection()] [object[]] $Subgraphs,
        [int] $MaxNodes = 60,
        [int] $MaxEdges = 80
    )
    # ---- nodes: dedupe by id (first wins), cap in input order, then number in ordinal order
    $seen = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::Ordinal)
    $unique = [System.Collections.Generic.List[object]]::new()
    foreach ($n in @($Nodes)) {
        if ($null -eq $n) { continue }
        $id = [string](Get-FsValue $n 'id')
        if ([string]::IsNullOrEmpty($id)) { continue }
        if ($seen.Add($id)) { $unique.Add($n) }
    }
    $totalNodes = $unique.Count
    $kept = if ($MaxNodes -gt 0 -and $unique.Count -gt $MaxNodes) { @($unique.GetRange(0, $MaxNodes)) } else { @($unique) }
    $sorted = @(Get-FsSorted -InputObject $kept -Property 'id')
    $idMap = [System.Collections.Generic.Dictionary[string, string]]::new([System.StringComparer]::Ordinal)
    $i = 0
    foreach ($n in $sorted) { $i++; $idMap[[string](Get-FsValue $n 'id')] = 'n{0}' -f $i }

    # ---- edges: keep those between kept nodes, dedupe, sort
    $edgeKeys = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::Ordinal)
    $edgeList = [System.Collections.Generic.List[object]]::new()
    $droppedByNode = 0
    foreach ($e in @($Edges)) {
        if ($null -eq $e) { continue }
        $from = [string](Get-FsValue $e 'from'); $to = [string](Get-FsValue $e 'to')
        if (-not $idMap.ContainsKey($from) -or -not $idMap.ContainsKey($to)) { $droppedByNode++; continue }
        $label = [string](Get-FsValue $e 'label')
        $style = [string](Get-FsValue $e 'style'); if ($style -ne 'dashed') { $style = 'solid' }
        $key = '{0}|{1}|{2}|{3}' -f $from, $to, $label, $style
        if ($edgeKeys.Add($key)) { $edgeList.Add([ordered]@{ from = $from; to = $to; label = $label; style = $style }) }
    }
    $sortedEdges = @(Get-FsSorted -InputObject @($edgeList) -Property 'from', 'to', 'label')
    $totalEdges = $sortedEdges.Count
    if ($MaxEdges -gt 0 -and $sortedEdges.Count -gt $MaxEdges) { $sortedEdges = @($sortedEdges[0..($MaxEdges - 1)]) }

    # ---- class table
    $classTable = [ordered]@{}
    foreach ($k in $script:FsMermaidDefaultClasses.Keys) { $classTable[$k] = $script:FsMermaidDefaultClasses[$k] }
    if ($Classes) { foreach ($k in $Classes.Keys) { $classTable[[string]$k] = [string]$Classes[$k] } }
    $usedClasses = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::Ordinal)

    $nodeLine = {
        param($n)
        $id = [string](Get-FsValue $n 'id')
        $label = [string](Get-FsValue $n 'label'); if ([string]::IsNullOrEmpty($label)) { $label = $id }
        $cls = [string](Get-FsValue $n 'class')
        $line = '{0}["{1}"]' -f $idMap[$id], (Format-FsMermaidLabel $label)
        if ($cls -and $classTable.Contains($cls)) { $line += ':::' + (Get-FsMermaidClassName $cls); [void]$usedClasses.Add($cls) }
        return $line
    }

    $out = [System.Collections.Generic.List[string]]::new()
    $out.Add('```mermaid')
    $out.Add('flowchart ' + $Direction)

    # ---- subgraphs
    $inSubgraph = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::Ordinal)
    $sgIndex = 0
    foreach ($sg in @(Get-FsSorted -InputObject @($Subgraphs | Where-Object { $null -ne $_ }) -Property 'id')) {
        $members = @()
        foreach ($nid in @(Get-FsValue $sg 'nodeIds')) {
            $s = [string]$nid
            if ($idMap.ContainsKey($s) -and -not $inSubgraph.Contains($s)) { $members += $s }
        }
        if ($members.Count -eq 0) { continue }
        $sgIndex++
        $title = [string](Get-FsValue $sg 'title'); if ([string]::IsNullOrEmpty($title)) { $title = [string](Get-FsValue $sg 'id') }
        $out.Add(('    subgraph sg{0}["{1}"]' -f $sgIndex, (Format-FsMermaidLabel $title)))
        foreach ($n in $sorted) {
            $nid = [string](Get-FsValue $n 'id')
            if ($members -contains $nid) { [void]$inSubgraph.Add($nid); $out.Add('        ' + (& $nodeLine $n)) }
        }
        $out.Add('    end')
    }
    foreach ($n in $sorted) {
        if ($inSubgraph.Contains([string](Get-FsValue $n 'id'))) { continue }
        $out.Add('    ' + (& $nodeLine $n))
    }

    # ---- edges
    foreach ($e in $sortedEdges) {
        $a = $idMap[$e.from]; $b = $idMap[$e.to]
        $lbl = Format-FsMermaidLabel $e.label
        $arrow = if ($e.style -eq 'dashed') {
            if ($lbl) { '-. "{0}" .->' -f $lbl } else { '-.->' }
        }
        else {
            if ($lbl) { '-- "{0}" -->' -f $lbl } else { '-->' }
        }
        $out.Add(('    {0} {1} {2}' -f $a, $arrow, $b))
    }

    # ---- classDefs (only those used)
    foreach ($k in $classTable.Keys) {
        if ($usedClasses.Contains($k)) { $out.Add(('    classDef {0} {1}' -f (Get-FsMermaidClassName $k), $classTable[$k])) }
    }
    $out.Add('```')

    $hiddenNodes = $totalNodes - $kept.Count
    $hiddenEdges = ($totalEdges - $sortedEdges.Count) + $droppedByNode
    if ($hiddenNodes -gt 0 -and $hiddenEdges -gt 0) { $out.Add(''); $out.Add(('_… +{0} more nodes and +{1} more edges not shown_' -f $hiddenNodes, $hiddenEdges)) }
    elseif ($hiddenNodes -gt 0) { $out.Add(''); $out.Add(('_… +{0} more nodes not shown_' -f $hiddenNodes)) }
    elseif ($hiddenEdges -gt 0) { $out.Add(''); $out.Add(('_… +{0} more edges not shown_' -f $hiddenEdges)) }
    return ($out -join "`n")
}
