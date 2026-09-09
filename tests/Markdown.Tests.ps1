#Requires -Modules @{ ModuleName = 'Pester'; ModuleVersion = '5.5.0' }
<# Markdown cells/tables/callouts, frontmatter quoting, Mermaid, Canvas JSON, Bases YAML. #>

BeforeAll {
    . (Join-Path $PSScriptRoot 'TestHelpers.ps1')
}

Describe 'Links' {
    It 'builds wikilinks with full paths and escapes the alias separator in tables' {
        New-FsLink -Path 'Users/alice' -Alias 'alice' | Should -Be '[[Users/alice|alice]]'
        New-FsLink -Path 'Users/alice' -Alias 'alice' -InTable | Should -Be '[[Users/alice\|alice]]'
        New-FsLink -Path 'Users/alice' | Should -Be '[[Users/alice]]'
        New-FsLink -Path 'Shares/FS01 - HR' -Alias '\\FS01\HR' -InTable | Should -Be '[[Shares/FS01 - HR\|\\FS01\HR]]'
    }
    It 'builds embeds with heading anchors' {
        New-FsEmbed -Path 'Effective/Users/alice' -Heading 'Effective access' | Should -Be '![[Effective/Users/alice#Effective access]]'
        New-FsEmbed -Path 'Reports/Changes - FS01' | Should -Be '![[Reports/Changes - FS01]]'
        Format-FsHeadingAnchor -Heading '  Summary  #1 | x ' | Should -Be 'Summary 1 x'
    }
}

Describe 'Format-FsMdCell' {
    It 'escapes pipes and newlines in scalars' {
        Format-FsMdCell -Value "a|b`r`nc" -InTable | Should -Be 'a\|b<br>c'
        Format-FsMdCell -Value '  padded  ' | Should -Be 'padded'
    }
    It 'renders New-FsCode as code spans, keeping backslashes and escaping pipes in tables' {
        Format-FsMdCell -Value (New-FsCode '\\FS01\HR\Payroll') -InTable | Should -Be '`\\FS01\HR\Payroll`'
        Format-FsMdCell -Value (New-FsCode 'a|b') -InTable | Should -Be '`a\|b`'
        Format-FsMdCell -Value (New-FsCode 'a|b') | Should -Be '`a|b`'
        Format-FsMdCell -Value (New-FsCode 'tick`inside') | Should -Be '`` tick`inside ``'
        Format-FsMdCell -Value (New-FsCode '\') | Should -Be '`\`'
        Format-FsMdCell -Value (New-FsCode '') | Should -Be ''
    }
    It 'renders booleans, nulls, dates and numbers' {
        Format-FsMdCell -Value $true | Should -Be 'yes'
        Format-FsMdCell -Value $false | Should -Be 'no'
        Format-FsMdCell -Value $null | Should -Be ''
        Format-FsMdCell -Value 42 | Should -Be '42'
        Format-FsMdCell -Value ([datetime]'2026-09-06T08:12:44') | Should -Be '2026-09-06 08:12'
        Format-FsMdCell -Value '2026-09-06T08:12:44.0000000Z' | Should -Be '2026-09-06 08:12'
        Format-FsMdCell -Value '2026-09-06T08:12:44+02:00' | Should -Be '2026-09-06 08:12'
        Format-FsMdCell -Value 'not a date 2026' | Should -Be 'not a date 2026'
    }
    It 'joins arrays with a comma or <br>' {
        Format-FsMdCell -Value @('a', 'b|c', $null) -InTable | Should -Be 'a, b\|c'
        Format-FsMdCell -Value @('a', 'b') -Multiline | Should -Be 'a<br>b'
        Format-FsMdCell -Value @() | Should -Be ''
    }
    It 'resolves refs through the resolver and falls back to the label/id' {
        $ref = New-FsRef -Kind Principal -Id 'S-1-5-11' -Label 'Authenticated Users'
        $resolver = { param($r, $inTable) New-FsLink -Path ('WellKnown/' + $r.label) -Alias $r.label -InTable:$inTable }
        Format-FsMdCell -Value $ref -InTable -Resolve $resolver | Should -Be '[[WellKnown/Authenticated Users\|Authenticated Users]]'
        Format-FsMdCell -Value $ref -Resolve $resolver | Should -Be '[[WellKnown/Authenticated Users|Authenticated Users]]'
        Format-FsMdCell -Value $ref | Should -Be 'Authenticated Users'
        Format-FsMdCell -Value (New-FsRef -Kind Server -Id 'FS01') | Should -Be 'FS01'
        Format-FsMdCell -Value @($ref, (New-FsCode 'x')) -InTable -Resolve $resolver | Should -Be '[[WellKnown/Authenticated Users\|Authenticated Users]], `x`'
    }
}

Describe 'Format-FsMdTable' {
    It 'renders header, separator and rows with refs via the resolver' {
        $rows = @(
            [ordered]@{ Principal = (New-FsRef -Kind Principal -Id 'a' -Label 'alice'); Rights = (New-FsCode 'Modify'); Deny = $false },
            [ordered]@{ Principal = 'plain|text'; Rights = $null }
        )
        $t = Format-FsMdTable -Columns 'Principal', 'Rights', 'Deny' -Rows $rows -Resolve { param($r, $it) New-FsLink -Path "Users/$($r.id)" -Alias $r.label -InTable:$it }
        $lines = $t -split "`n"
        $lines[0] | Should -Be '| Principal | Rights | Deny |'
        $lines[1] | Should -Be '| --- | --- | --- |'
        $lines[2] | Should -Be '| [[Users/a\|alice]] | `Modify` | no |'
        $lines[3] | Should -Be '| plain\|text |  |  |'
        $lines.Count | Should -Be 4
    }
    It 'returns the empty text when there are no rows' {
        Format-FsMdTable -Columns 'A' -Rows @() | Should -Be '_none_'
        Format-FsMdTable -Columns 'A' -Rows $null -EmptyText '_nothing_' | Should -Be '_nothing_'
    }
    It 'truncates at MaxRows with a "more" line' {
        $rows = 1..5 | ForEach-Object { [ordered]@{ N = $_ } }
        $t = Format-FsMdTable -Columns 'N' -Rows $rows -MaxRows 2
        $t | Should -Match '\| 2 \|'
        $t | Should -Not -Match '\| 3 \|'
        ($t -split "`n")[-1] | Should -Be '_… 3 more_'
    }
}

Describe 'New-FsCallout' {
    It 'emits an Obsidian callout' {
        New-FsCallout -Type warning -Title 'Findings' -Lines @('one', "two`nthree") | Should -Be "> [!warning] Findings`n> one`n> two`n> three"
        New-FsCallout -Type info -Lines $null | Should -Be '> [!info]'
        New-FsCallout -Type note -Title 'T' -Collapsed | Should -Be '> [!note]- T'
    }
}

Describe 'ConvertTo-FsFrontmatter' {
    It 'wraps properties in --- fences with LF' {
        ConvertTo-FsFrontmatter -Properties ([ordered]@{ type = 'user' }) | Should -Be "---`ntype: user`n---`n"
    }
    It 'omits null, empty strings and empty arrays' {
        $fm = ConvertTo-FsFrontmatter -Properties ([ordered]@{ a = $null; b = ''; c = @(); d = 'kept'; e = @($null, '') })
        $fm | Should -Be "---`nd: kept`n---`n"
    }
    It 'renders booleans bare' {
        ConvertTo-FsFrontmatter -Properties ([ordered]@{ generated = $true; enabled = $false }) | Should -Be "---`ngenerated: true`nenabled: false`n---`n"
    }
    It 'renders numbers bare' {
        ConvertTo-FsFrontmatter -Properties ([ordered]@{ depth = 2; big = [long]5000000000; ratio = 1.5 }) | Should -Be "---`ndepth: 2`nbig: 5000000000`nratio: 1.5`n---`n"
    }
    It 'formats [datetime] values as yyyy-MM-ddTHH:mm:ss without offset' {
        ConvertTo-FsFrontmatter -Properties ([ordered]@{ lastLogon = [datetime]'2026-09-06T08:12:44' }) | Should -Be "---`nlastLogon: 2026-09-06T08:12:44`n---`n"
    }
    It 'converts ISO-8601 strings to UTC and drops the Z' {
        ConvertTo-FsFrontmatter -Properties ([ordered]@{ a = '2026-09-06T08:12:44.0000000Z'; b = '2026-09-06T10:12:44+02:00' }) | Should -Be "---`na: 2026-09-06T08:12:44`nb: 2026-09-06T08:12:44`n---`n"
    }
    It 'single-quotes strings containing risky characters, doubling single quotes' {
        ConvertTo-FsFrontmatter -Properties ([ordered]@{ p = 'D:\Shares\HR' }) | Should -Be "---`np: 'D:\Shares\HR'`n---`n"
        ConvertTo-FsFrontmatter -Properties ([ordered]@{ p = "O'Brien: #1, [x] {y}" }) | Should -Be "---`np: 'O''Brien: #1, [x] {y}'`n---`n"
        ConvertTo-FsFrontmatter -Properties ([ordered]@{ p = 'say "hi"' }) | Should -Be ('---' + "`n" + 'p: ''say "hi"''' + "`n" + '---' + "`n")
    }
    It 'single-quotes strings starting with YAML indicator characters' {
        foreach ($s in '-dash', '*star', '&amp', '!bang', '%pct', '@at', '`tick', '?q', '|pipe', '[bracket', '>gt') {
            ConvertTo-FsFrontmatter -Properties ([ordered]@{ p = $s }) | Should -Be "---`np: '$s'`n---`n"
        }
    }
    It 'single-quotes strings that look like numbers, booleans, null or dates' {
        foreach ($s in '42', '1.5', '1e3', '0x1F', 'true', 'False', 'yes', 'no', 'null', '~', '2026-09-09', '2026-1-1 stuff') {
            ConvertTo-FsFrontmatter -Properties ([ordered]@{ p = $s }) | Should -Be "---`np: '$s'`n---`n"
        }
    }
    It 'leaves plain strings bare' {
        ConvertTo-FsFrontmatter -Properties ([ordered]@{ p = 'Alice Anders'; q = 'HR-Share-RW'; r = 'fs01.contoso.local' }) | Should -Be "---`np: Alice Anders`nq: HR-Share-RW`nr: fs01.contoso.local`n---`n"
    }
    It 'double-quotes wikilink values and escapes backslashes and quotes' {
        ConvertTo-FsFrontmatter -Properties ([ordered]@{ manager = '[[Users/dave|dave]]' }) | Should -Be "---`nmanager: `"[[Users/dave|dave]]`"`n---`n"
        ConvertTo-FsFrontmatter -Properties ([ordered]@{ share = '[[Shares/FS01 - HR|\\FS01\HR]]' }) | Should -Be "---`nshare: `"[[Shares/FS01 - HR|\\\\FS01\\HR]]`"`n---`n"
    }
    It 'renders arrays as block sequences with the same scalar rules' {
        $fm = ConvertTo-FsFrontmatter -Properties ([ordered]@{ memberOf = @('[[Groups/HR-All|HR-All]]', 'plain', 'a: b', $null) })
        $fm | Should -Be "---`nmemberOf:`n  - `"[[Groups/HR-All|HR-All]]`"`n  - plain`n  - 'a: b'`n---`n"
    }
    It 'always renders tags and aliases as lists' {
        ConvertTo-FsFrontmatter -Properties ([ordered]@{ tags = 'user'; aliases = 'Alice' }) | Should -Be "---`ntags:`n  - user`naliases:`n  - Alice`n---`n"
    }
    It 'renders one level of nested dictionaries as indented maps' {
        $fm = ConvertTo-FsFrontmatter -Properties ([ordered]@{ stats = [ordered]@{ folders = 3; note = 'x: y'; empty = $null; list = @('a') } })
        $fm | Should -Be "---`nstats:`n  folders: 3`n  note: 'x: y'`n  list:`n    - a`n---`n"
    }
    It 'omits dictionaries whose values are all empty' {
        ConvertTo-FsFrontmatter -Properties ([ordered]@{ a = [ordered]@{ x = $null }; b = 1 }) | Should -Be "---`nb: 1`n---`n"
    }
    It 'double-quotes strings containing control characters' {
        ConvertTo-FsFrontmatter -Properties ([ordered]@{ d = "line1`nline2" }) | Should -Be "---`nd: `"line1\nline2`"`n---`n"
    }
    It 'quotes non-identifier keys' {
        ConvertTo-FsFrontmatter -Properties ([ordered]@{ 'odd key' = 1; 'yes' = 2 }) | Should -Be "---`n'odd key': 1`n'yes': 2`n---`n"
    }
}

Describe 'Note builder' {
    It 'normalizes line endings, collapses blank runs and ends with one newline' {
        $b = New-FsNoteBuilder
        Add-FsLine -Builder $b -Text "# Title`r`n"
        Add-FsLine -Builder $b -Text $null
        Add-FsLine -Builder $b -Text $null
        Add-FsLine -Builder $b -Text @('a', 'b')
        Get-FsNoteText -Builder $b | Should -Be "# Title`n`na`nb`n"
    }
}

Describe 'Mermaid' {
    It 'escapes labels' {
        Format-FsMermaidLabel -Text 'Say "hi" #1 <b> [x] (y) {z}' | Should -Be 'Say #quot;hi#quot; #35;1 #lt;b#gt; [x] (y) {z}'
        Format-FsMermaidLabel -Text "a`nb" | Should -Be 'a b'
    }
    It 'renders a flowchart with sanitized deterministic ids, classes and edge styles' {
        $nodes = @(
            @{ id = 'end'; label = 'End "node"'; class = 'folder' },
            @{ id = 'S-1-5-21-1'; label = 'alice'; class = 'user' },
            @{ id = 'FS01\HR'; label = '\\FS01\HR'; class = 'share' }
        )
        $edges = @(
            @{ from = 'S-1-5-21-1'; to = 'FS01\HR'; label = 'via HR-All' },
            @{ from = 'FS01\HR'; to = 'end'; style = 'dashed' },
            @{ from = 'FS01\HR'; to = 'end'; style = 'dashed' },
            @{ from = 'S-1-5-21-1'; to = 'missing' }
        )
        $t = New-FsMermaidFlowchart -Direction LR -Nodes $nodes -Edges $edges
        $lines = $t -split "`n"
        $lines[0] | Should -Be '```mermaid'
        $lines[1] | Should -Be 'flowchart LR'
        # ids are assigned in ordinal order of the original ids: 'end' < 'FS01\HR' < 'S-1-5-21-1'
        $lines[2] | Should -Be '    n1["End #quot;node#quot;"]:::folder'
        $lines[3] | Should -Be '    n2["\\FS01\HR"]:::share'
        $lines[4] | Should -Be '    n3["alice"]:::user'
        $t | Should -Match '    n2 -\.-> n1'
        $t | Should -Match '    n3 -- "via HR-All" --> n2'
        ($t -split "`n" | Where-Object { $_ -match '-\.->' }).Count | Should -Be 1
        $t | Should -Match 'classDef user fill:#c8e6c9'
        $t | Should -Match 'classDef share '
        $t | Should -Not -Match 'classDef group '
        # The 'S-1-5-21-1' -> 'missing' edge references a node id that isn't in -Nodes: per the documented
        # "edges to dropped nodes are dropped" behavior, it is silently omitted and counted in the footnote,
        # which appears as a blank line then the note, after the closing fence.
        $lines[-1] | Should -Be '_… +1 more edges not shown_'
        $lines[-2] | Should -Be ''
        $lines[-3] | Should -Be '```'
        $t | Should -Not -Match '\bend\b\s*$'
    }
    It 'caps nodes and edges and appends a truncation footnote' {
        $nodes = 1..70 | ForEach-Object { @{ id = 'n' + $_.ToString('000'); label = "Node $_"; class = 'group' } }
        $edges = 1..69 | ForEach-Object { @{ from = 'n' + $_.ToString('000'); to = 'n' + ($_ + 1).ToString('000') } }
        $t = New-FsMermaidFlowchart -Nodes $nodes -Edges $edges -MaxNodes 60 -MaxEdges 80
        ($t -split "`n" | Where-Object { $_ -match '^\s+n\d+\["' }).Count | Should -Be 60
        ($t -split "`n")[-1] | Should -Be '_… +10 more nodes and +10 more edges not shown_'
        $t2 = New-FsMermaidFlowchart -Nodes $nodes -Edges $edges -MaxNodes 100 -MaxEdges 50
        ($t2 -split "`n")[-1] | Should -Be '_… +19 more edges not shown_'
    }
    It 'is deterministic regardless of input order and supports subgraphs' {
        $a = @(@{ id = 'x'; label = 'X' }, @{ id = 'y'; label = 'Y' })
        $b = @(@{ id = 'y'; label = 'Y' }, @{ id = 'x'; label = 'X' })
        $sg = @(@{ id = 'srv'; title = 'FS01 "prod"'; nodeIds = @('y') })
        $t1 = New-FsMermaidFlowchart -Nodes $a -Edges @(@{ from = 'x'; to = 'y' }) -Subgraphs $sg
        $t2 = New-FsMermaidFlowchart -Nodes $b -Edges @(@{ from = 'x'; to = 'y' }) -Subgraphs $sg
        $t1 | Should -Be $t2
        $t1 | Should -Match '    subgraph sg1\["FS01 #quot;prod#quot;"\]\n        n2\["Y"\]\n    end'
        $t1 | Should -Match '    n1\["X"\]'
    }
    It 'sanitizes class names with hyphens' {
        $t = New-FsMermaidFlowchart -Nodes @(@{ id = 'a'; label = 'A'; class = 'local-group' }, @{ id = 'b'; label = 'B'; class = 'well-known' })
        $t | Should -Match 'n1\["A"\]:::local_group'
        $t | Should -Match 'classDef local_group '
        $t | Should -Match 'classDef well_known '
    }
}

Describe 'Canvas' {
    It 'produces JSON Canvas with 16-hex ids, sorted, 2-space indented, LF' {
        $n1 = New-FsCanvasNode -Kind file -Key 'server:FS01' -X 0 -Y 0 -Width 400 -Height 200 -File 'Servers/FS01.md' -Color '1'
        $n2 = New-FsCanvasNode -Kind text -Key 'report:01' -X 500 -Y 0 -Width 400 -Height 200 -Text "**Broad Exposure**`r`n12 rows"
        $g = New-FsCanvasNode -Kind group -Key 'group:reports' -X 480 -Y -20 -Width 440 -Height 240 -Label 'Reports'
        $e = New-FsCanvasEdge -Key 'edge:1' -From 'server:FS01' -To $n2.id -Label '+4 / -1'
        $json = ConvertTo-FsCanvasJson -Nodes @($n2, $g, $n1) -Edges @($e)
        $json | Should -Not -Match "`r"
        $json | Should -Match '^\{\n  "nodes": \['
        $json.EndsWith("`n") | Should -BeTrue
        $doc = ConvertFrom-Json -InputObject $json -AsHashtable
        $doc.nodes.Count | Should -Be 3
        $doc.edges.Count | Should -Be 1
        foreach ($n in $doc.nodes) { $n.id | Should -Match '^[0-9a-f]{16}$' }
        $doc.edges[0].fromNode | Should -Be $n1.id
        $doc.edges[0].toNode | Should -Be $n2.id
        $doc.edges[0].fromSide | Should -Be 'right'
        $doc.edges[0].toSide | Should -Be 'left'
        $doc.edges[0].label | Should -Be '+4 / -1'
        ($doc.nodes | Where-Object type -eq 'file').file | Should -Be 'Servers/FS01.md'
        ($doc.nodes | Where-Object type -eq 'text').text | Should -Be "**Broad Exposure**`n12 rows"
        ($doc.nodes | Where-Object type -eq 'group').label | Should -Be 'Reports'
        # sorted by id and stable
        $ids = @($doc.nodes | ForEach-Object id)
        ($ids -join ',') | Should -Be ((Get-FsSorted -InputObject $ids) -join ',')
        (ConvertTo-FsCanvasJson -Nodes @($n1, $n2, $g) -Edges @($e)) | Should -Be $json
    }
    It 'derives ids from keys deterministically' {
        (Get-FsCanvasId -Key 'abc') | Should -Be (Get-FsCanvasId -Key 'abc')
        (Get-FsCanvasId -Key 'abc') | Should -Not -Be (Get-FsCanvasId -Key 'abd')
        (Get-FsCanvasId -Key '0123456789abcdef') | Should -Be '0123456789abcdef'
    }
}

Describe 'Bases' {
    It 'emits filters and views YAML' {
        $t = New-FsBase -Filters 'file.hasTag("user")' -Views @(
            [ordered]@{ type = 'table'; name = 'All users'; order = @('file.name', 'department'); sort = @((New-FsBaseSort 'department' 'DESC')) },
            [ordered]@{ name = 'Disabled'; filters = 'enabled == false'; limit = 50 }
        )
        $t | Should -Match '^filters:\n  and:\n    - ''file\.hasTag\("user"\)''\n'
        $t | Should -Match "`nviews:`n  - type: table`n    name: All users`n    order:`n      - file.name`n      - department`n    sort:`n      - property: department`n        direction: DESC`n"
        $t | Should -Match "  - type: table`n    name: Disabled`n    filters:`n      and:`n        - enabled == false`n    limit: 50`n"
        $t.EndsWith("`n") | Should -BeTrue
    }
    It 'provides the five default bases' {
        $bases = Get-FsDefaultBases
        @($bases.Keys) | Should -Be @('Users.base', 'Groups.base', 'Folders.base', 'Shares.base', 'Reports.base')
        foreach ($k in $bases.Keys) {
            $bases[$k] | Should -Match '^filters:'
            $bases[$k] | Should -Match "`nviews:`n  - type: table"
        }
        $bases['Users.base'] | Should -Match 'file\.hasTag\("user"\)'
        $bases['Reports.base'] | Should -Match 'severity'
    }
}
