<#
Markdown, wikilink, table, callout and YAML frontmatter helpers for Obsidian notes.

Conventions (plan, Phase 5):
  - every link is a full vault path: [[Users/jsmith|jsmith]]; inside tables the alias separator is '\|'
  - table cells: '|' -> '\|', newlines -> '<br>', paths/rights in code spans
  - frontmatter: omit absent values (never null), wikilink values double-quoted, risky strings single-quoted
  - notes are built in a StringBuilder and written once, LF endings
#>

$script:FsIsoDateTimeRegex = [regex]'^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}(:\d{2}(\.\d+)?)?(Z|[+-]\d{2}:?\d{2})?$'
$script:FsYamlRiskyChars = [regex]'[:#\[\]{},''"\\]'
$script:FsYamlRiskyStart = [regex]'^[\-*&!%@`?|>''"{\[\s]|^---'
$script:FsYamlNumberLike = [regex]'^[-+]?(\.\d+|\d[\d_]*(\.\d*)?)([eE][-+]?\d+)?$|^0[xX][0-9a-fA-F]+$|^0[oO][0-7]+$|^[-+]?\.(?i:inf)$|^\.(?i:nan)$'
$script:FsYamlWordLike = [regex]'^(?i:true|false|yes|no|on|off|null|~|y|n)$'
$script:FsYamlDateLike = [regex]'^\d{4}-\d{1,2}-\d{1,2}'
$script:FsYamlPlainKey = [regex]'^[A-Za-z_][A-Za-z0-9_.-]*$'

# ---------------------------------------------------------------- links

function New-FsLink {
    <#
    .SYNOPSIS
        [[path|alias]] wikilink. -InTable escapes the separator as '\|' so the table does not break.
    #>
    [OutputType([string])]
    param(
        [Parameter(Mandatory)] [string] $Path,
        [AllowNull()] [string] $Alias,
        [switch] $InTable
    )
    if ([string]::IsNullOrEmpty($Alias)) { return '[[{0}]]' -f $Path }
    $sep = if ($InTable) { '\|' } else { '|' }
    $a = ($Alias -replace '[\r\n]+', ' ').Replace('|', '/').Replace(']]', ') )')
    return '[[{0}{1}{2}]]' -f $Path, $sep, $a
}

function New-FsEmbed {
    <# ![[path#Heading]] transclusion. #>
    [OutputType([string])]
    param([Parameter(Mandatory)] [string] $Path, [AllowNull()] [string] $Heading)
    if ([string]::IsNullOrEmpty($Heading)) { return '![[{0}]]' -f $Path }
    return '![[{0}#{1}]]' -f $Path, (Format-FsHeadingAnchor -Heading $Heading)
}

function Format-FsHeadingAnchor {
    <# Heading text as used after '#' in a link: trimmed, whitespace collapsed, link-breaking characters removed. #>
    [OutputType([string])]
    param([Parameter(Mandatory)] [AllowEmptyString()] [string] $Heading)
    $h = $Heading -replace '[#|\[\]^]', ''
    return ([regex]::Replace($h, '\s+', ' ')).Trim()
}

# ---------------------------------------------------------------- cells

function Format-FsMdText {
    <# Plain text for a markdown cell/paragraph: trimmed, newlines -> <br>, '|' -> '\|'. #>
    [OutputType([string])]
    param([AllowNull()] [string] $Text)
    if ([string]::IsNullOrEmpty($Text)) { return '' }
    $t = $Text.Trim()
    $t = [regex]::Replace($t, '\r\n|\r|\n', '<br>')
    return $t.Replace('|', '\|')
}

function Format-FsMdCode {
    <#
    .SYNOPSIS
        Inline code span. Uses double backticks when the text contains a backtick; escapes '|' inside tables.
    #>
    [OutputType([string])]
    param([AllowNull()] [string] $Text, [switch] $InTable)
    if ([string]::IsNullOrEmpty($Text)) { return '' }
    $t = [regex]::Replace($Text, '\r\n|\r|\n', ' ')
    if ($InTable) { $t = $t.Replace('|', '\|') }
    if ($t.Contains('`')) { return '`` {0} ``' -f $t }
    return '`{0}`' -f $t
}

function Format-FsMdDateTime {
    <# yyyy-MM-dd HH:mm from a [datetime] or an ISO-8601 string; clock value used as given (no zone conversion). Returns $null when not a date. #>
    [OutputType([string])]
    param([AllowNull()] $Value)
    if ($null -eq $Value) { return $null }
    if ($Value -is [datetime]) { return $Value.ToString('yyyy-MM-dd HH:mm', [cultureinfo]::InvariantCulture) }
    if ($Value -is [datetimeoffset]) { return $Value.DateTime.ToString('yyyy-MM-dd HH:mm', [cultureinfo]::InvariantCulture) }
    if ($Value -is [string] -and $script:FsIsoDateTimeRegex.IsMatch($Value.Trim())) {
        $dto = [datetimeoffset]::MinValue
        if ([datetimeoffset]::TryParse($Value.Trim(), [cultureinfo]::InvariantCulture, [System.Globalization.DateTimeStyles]::AssumeUniversal, [ref]$dto)) {
            return $dto.DateTime.ToString('yyyy-MM-dd HH:mm', [cultureinfo]::InvariantCulture)
        }
    }
    return $null
}

function Format-FsMdCell {
    <#
    .SYNOPSIS
        Renders any cell value as markdown text.
    .DESCRIPTION
        $null -> ''; booleans -> yes/no; dates -> yyyy-MM-dd HH:mm; New-FsCode -> code span; New-FsRef -> the
        result of -Resolve (a scriptblock receiving the ref and $InTable, expected to return a wikilink), or the
        ref's label/id as text when no resolver is given; arrays -> items joined with ', ' (or '<br>' with -Multiline);
        everything else -> escaped text.
    #>
    [OutputType([string])]
    param(
        [AllowNull()] $Value,
        [switch] $InTable,
        [switch] $Multiline,
        [AllowNull()] [scriptblock] $Resolve
    )
    if ($null -eq $Value) { return '' }
    if (Test-FsRef $Value) {
        if ($Resolve) { return [string](& $Resolve $Value $InTable.IsPresent) }
        $label = if ($Value['label']) { $Value['label'] } else { $Value['id'] }
        return Format-FsMdText -Text ([string]$label)
    }
    if (Test-FsCode $Value) { return Format-FsMdCode -Text ([string]$Value['_code']) -InTable:$InTable }
    if ($Value -is [bool]) { return $(if ($Value) { 'yes' } else { 'no' }) }
    if ($Value -is [datetime] -or $Value -is [datetimeoffset]) { return Format-FsMdDateTime -Value $Value }
    if ($Value -is [string]) {
        $d = Format-FsMdDateTime -Value $Value
        if ($null -ne $d) { return $d }
        return Format-FsMdText -Text $Value
    }
    if ($Value -is [System.Collections.IDictionary]) { return Format-FsMdText -Text ([string]$Value) }
    if ($Value -is [System.Collections.IEnumerable]) {
        $parts = foreach ($item in $Value) {
            $s = Format-FsMdCell -Value $item -InTable:$InTable -Multiline:$Multiline -Resolve $Resolve
            if ($s -ne '') { $s }
        }
        $sep = if ($Multiline) { '<br>' } else { ', ' }
        return (@($parts) -join $sep)
    }
    return Format-FsMdText -Text ([string]$Value)
}

# ---------------------------------------------------------------- tables and callouts

function Format-FsMdTable {
    <#
    .SYNOPSIS
        Markdown table from column names and rows (dictionaries or objects keyed by column).
    .PARAMETER MaxRows
        When set and exceeded, only the first MaxRows rows are shown and a MoreText line is appended.
    .PARAMETER MoreText
        Format string for the truncation line; {0} = number of hidden rows.
    .PARAMETER EmptyText
        Returned instead of a table when there are no rows.
    #>
    [OutputType([string])]
    param(
        [Parameter(Mandatory)] [AllowEmptyCollection()] [string[]] $Columns,
        [AllowNull()] [AllowEmptyCollection()] [object[]] $Rows,
        [AllowNull()] [scriptblock] $Resolve,
        [int] $MaxRows = 0,
        [string] $MoreText = '_… {0} more_',
        [string] $EmptyText = '_none_',
        [switch] $Multiline
    )
    $rows = @($Rows | Where-Object { $null -ne $_ })
    if ($rows.Count -eq 0) { return $EmptyText }
    $lines = [System.Collections.Generic.List[string]]::new()
    $lines.Add('| ' + (@($Columns | ForEach-Object { Format-FsMdText -Text $_ }) -join ' | ') + ' |')
    $lines.Add('| ' + (@($Columns | ForEach-Object { '---' }) -join ' | ') + ' |')
    $shown = if ($MaxRows -gt 0 -and $rows.Count -gt $MaxRows) { $MaxRows } else { $rows.Count }
    for ($i = 0; $i -lt $shown; $i++) {
        $row = $rows[$i]
        $cells = foreach ($c in $Columns) { Format-FsMdCell -Value (Get-FsValue -Object $row -Name $c) -InTable -Multiline:$Multiline -Resolve $Resolve }
        $lines.Add('| ' + (@($cells) -join ' | ') + ' |')
    }
    if ($shown -lt $rows.Count) {
        $lines.Add('')
        $lines.Add(($MoreText -f ($rows.Count - $shown)))
    }
    return ($lines -join "`n")
}

function New-FsCallout {
    <#
    .SYNOPSIS
        Obsidian callout block: > [!type] Title / > line ...
    #>
    [OutputType([string])]
    param(
        [Parameter(Mandatory)] [ValidateSet('info', 'warning', 'danger', 'quote', 'note', 'tip', 'success', 'question', 'failure', 'bug', 'example', 'abstract', 'todo')] [string] $Type,
        [AllowNull()] [string] $Title,
        [AllowNull()] [AllowEmptyCollection()] [string[]] $Lines,
        [switch] $Collapsed
    )
    $fold = if ($Collapsed) { '-' } else { '' }
    $out = [System.Collections.Generic.List[string]]::new()
    $head = '> [!{0}]{1}' -f $Type, $fold
    if (-not [string]::IsNullOrWhiteSpace($Title)) { $head += ' ' + $Title.Trim() }
    $out.Add($head)
    foreach ($l in @($Lines | Where-Object { $null -ne $_ })) {
        foreach ($sub in ([string]$l -split '\r\n|\r|\n')) { $out.Add(('> ' + $sub).TrimEnd()) }
    }
    return ($out -join "`n")
}

# ---------------------------------------------------------------- YAML / frontmatter

function Test-FsYamlNeedsQuote {
    [OutputType([bool])]
    param([Parameter(Mandatory)] [AllowEmptyString()] [string] $Text)
    if ($Text.Length -eq 0) { return $true }
    if ($script:FsYamlRiskyChars.IsMatch($Text)) { return $true }
    if ($script:FsYamlRiskyStart.IsMatch($Text)) { return $true }
    if ($Text -ne $Text.Trim()) { return $true }
    if ($script:FsYamlNumberLike.IsMatch($Text)) { return $true }
    if ($script:FsYamlWordLike.IsMatch($Text)) { return $true }
    if ($script:FsYamlDateLike.IsMatch($Text)) { return $true }
    return $false
}

function Format-FsYamlScalar {
    <#
    .SYNOPSIS
        YAML scalar text for a value, or $null when the value should be omitted (null / empty string).
    .DESCRIPTION
        bool -> true/false; numbers bare; [datetime] -> yyyy-MM-ddTHH:mm:ss (as given); ISO-8601 strings -> converted
        to UTC, same format, no Z; strings starting with '[[' -> double-quoted; strings that could be misread by a YAML
        parser (contain : # [ ] { } , ' " \ ; start with - * & ! % @ ` ? | > ; look like numbers/booleans/null/dates)
        -> single-quoted with ' doubled; strings with control characters -> double-quoted with escapes.
    #>
    [OutputType([string])]
    param([AllowNull()] $Value)
    if ($null -eq $Value) { return $null }
    if (Test-FsCode $Value) { $Value = [string]$Value['_code'] }
    elseif (Test-FsRef $Value) { $Value = [string]$(if ($Value['label']) { $Value['label'] } else { $Value['id'] }) }
    if ($Value -is [bool]) { return $(if ($Value) { 'true' } else { 'false' }) }
    if ($Value -is [datetime]) { return $Value.ToString('yyyy-MM-ddTHH:mm:ss', [cultureinfo]::InvariantCulture) }
    if ($Value -is [datetimeoffset]) { return $Value.UtcDateTime.ToString('yyyy-MM-ddTHH:mm:ss', [cultureinfo]::InvariantCulture) }
    if ($Value -is [byte] -or $Value -is [int16] -or $Value -is [int] -or $Value -is [long] -or $Value -is [uint16] -or $Value -is [uint32] -or $Value -is [uint64] -or $Value -is [sbyte]) {
        return $Value.ToString([cultureinfo]::InvariantCulture)
    }
    if ($Value -is [double] -or $Value -is [single] -or $Value -is [decimal]) {
        return $Value.ToString('R', [cultureinfo]::InvariantCulture)
    }
    $s = [string]$Value
    if ($s.Length -eq 0) { return $null }
    if ($script:FsIsoDateTimeRegex.IsMatch($s.Trim())) {
        $dto = [datetimeoffset]::MinValue
        if ([datetimeoffset]::TryParse($s.Trim(), [cultureinfo]::InvariantCulture, [System.Globalization.DateTimeStyles]::AssumeUniversal, [ref]$dto)) {
            return $dto.UtcDateTime.ToString('yyyy-MM-ddTHH:mm:ss', [cultureinfo]::InvariantCulture)
        }
    }
    if ($s.StartsWith('[[')) { return '"' + $s.Replace('\', '\\').Replace('"', '\"') + '"' }
    if ($s -match '[\x00-\x1F\x7F]') {
        $e = $s.Replace('\', '\\').Replace('"', '\"').Replace("`r", '\r').Replace("`n", '\n').Replace("`t", '\t')
        $e = [regex]::Replace($e, '[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]', '')
        return '"' + $e + '"'
    }
    if (Test-FsYamlNeedsQuote $s) { return "'" + $s.Replace("'", "''") + "'" }
    return $s
}

function Format-FsYamlKey {
    [OutputType([string])]
    param([Parameter(Mandatory)] [string] $Key)
    if ($script:FsYamlPlainKey.IsMatch($Key) -and -not $script:FsYamlWordLike.IsMatch($Key)) { return $Key }
    return "'" + $Key.Replace("'", "''") + "'"
}

function Test-FsYamlEmpty {
    <# True for values ConvertTo-FsFrontmatter omits: null, empty string, empty/all-empty collections. #>
    [OutputType([bool])]
    param([AllowNull()] $Value)
    if ($null -eq $Value) { return $true }
    if ($Value -is [string]) { return ($Value.Length -eq 0) }
    if (Test-FsRef $Value) { return [string]::IsNullOrEmpty([string]$(if ($Value['label']) { $Value['label'] } else { $Value['id'] })) }
    if (Test-FsCode $Value) { return [string]::IsNullOrEmpty([string]$Value['_code']) }
    if ($Value -is [System.Collections.IDictionary]) {
        foreach ($k in $Value.Keys) { if (-not (Test-FsYamlEmpty $Value[$k])) { return $false } }
        return $true
    }
    if ($Value -is [System.Collections.IEnumerable]) {
        foreach ($i in $Value) { if (-not (Test-FsYamlEmpty $i)) { return $false } }
        return $true
    }
    return $false
}

function Add-FsYamlNode {
    <#
    .SYNOPSIS
        Appends "key: value" (scalar), "key:" + block sequence (list) or "key:" + indented map (dictionary) to $Lines.
        Empty values are omitted entirely.
    #>
    param(
        [Parameter(Mandatory)] [AllowEmptyCollection()] [System.Collections.Generic.List[string]] $Lines,
        [Parameter(Mandatory)] [string] $Key,
        [AllowNull()] $Value,
        [int] $Indent = 0
    )
    if (Test-FsYamlEmpty $Value) { return }
    $pad = ' ' * $Indent
    $k = Format-FsYamlKey $Key
    if ($Value -is [System.Collections.IDictionary] -and -not (Test-FsRef $Value) -and -not (Test-FsCode $Value)) {
        $Lines.Add(('{0}{1}:' -f $pad, $k))
        $keys = if ($Value -is [System.Collections.Specialized.IOrderedDictionary]) { @($Value.Keys) } else { Get-FsSortedKeys $Value }
        foreach ($ck in $keys) { Add-FsYamlNode -Lines $Lines -Key ([string]$ck) -Value $Value[$ck] -Indent ($Indent + 2) }
        return
    }
    if ($Value -is [System.Collections.IEnumerable] -and $Value -isnot [string]) {
        $Lines.Add(('{0}{1}:' -f $pad, $k))
        Add-FsYamlSequence -Lines $Lines -Items $Value -Indent ($Indent + 2)
        return
    }
    $Lines.Add(('{0}{1}: {2}' -f $pad, $k, (Format-FsYamlScalar $Value)))
}

function Add-FsYamlSequence {
    <# Block sequence items at the given indent; dictionary items become "- key: value" maps. #>
    param(
        [Parameter(Mandatory)] [AllowEmptyCollection()] [System.Collections.Generic.List[string]] $Lines,
        [AllowNull()] $Items,
        [int] $Indent = 0
    )
    $pad = ' ' * $Indent
    foreach ($item in $Items) {
        if (Test-FsYamlEmpty $item) { continue }
        if ($item -is [System.Collections.IDictionary] -and -not (Test-FsRef $item) -and -not (Test-FsCode $item)) {
            $sub = [System.Collections.Generic.List[string]]::new()
            $keys = if ($item -is [System.Collections.Specialized.IOrderedDictionary]) { @($item.Keys) } else { Get-FsSortedKeys $item }
            foreach ($ck in $keys) { Add-FsYamlNode -Lines $sub -Key ([string]$ck) -Value $item[$ck] -Indent ($Indent + 2) }
            if ($sub.Count -eq 0) { continue }
            $sub[0] = $pad + '- ' + $sub[0].Substring($Indent + 2)
            foreach ($l in $sub) { $Lines.Add($l) }
            continue
        }
        if ($item -is [System.Collections.IEnumerable] -and $item -isnot [string]) {
            $Lines.Add($pad + '-')
            Add-FsYamlSequence -Lines $Lines -Items $item -Indent ($Indent + 2)
            continue
        }
        $Lines.Add(('{0}- {1}' -f $pad, (Format-FsYamlScalar $item)))
    }
}

function ConvertTo-FsYaml {
    <# YAML document text (no --- fences) for a dictionary, using the frontmatter scalar rules. Ends with a newline. #>
    [OutputType([string])]
    param([Parameter(Mandatory)] [System.Collections.IDictionary] $Properties)
    $lines = [System.Collections.Generic.List[string]]::new()
    $keys = if ($Properties -is [System.Collections.Specialized.IOrderedDictionary]) { @($Properties.Keys) } else { Get-FsSortedKeys $Properties }
    foreach ($k in $keys) { Add-FsYamlNode -Lines $lines -Key ([string]$k) -Value $Properties[$k] -Indent 0 }
    if ($lines.Count -eq 0) { return '' }
    return (($lines -join "`n") + "`n")
}

function ConvertTo-FsFrontmatter {
    <#
    .SYNOPSIS
        "---\n...\n---\n" frontmatter block. Omits null/empty values; 'tags' and 'aliases' are always lists.
    #>
    [OutputType([string])]
    param([Parameter(Mandatory)] [System.Collections.IDictionary] $Properties)
    $props = [ordered]@{}
    $keys = if ($Properties -is [System.Collections.Specialized.IOrderedDictionary]) { @($Properties.Keys) } else { Get-FsSortedKeys $Properties }
    foreach ($k in $keys) {
        $v = $Properties[$k]
        if (([string]$k) -in 'tags', 'aliases') {
            if ($null -ne $v -and ($v -is [string] -or $v -isnot [System.Collections.IEnumerable])) { $v = @($v) }
        }
        $props[[string]$k] = $v
    }
    return "---`n" + (ConvertTo-FsYaml -Properties $props) + "---`n"
}

# ---------------------------------------------------------------- note builder

function New-FsNoteBuilder {
    [OutputType([System.Text.StringBuilder])]
    param()
    return [System.Text.StringBuilder]::new()
}

function Add-FsLine {
    <# Appends text (or each element of an array; $null/empty = blank line) followed by LF. #>
    param(
        [Parameter(Mandatory)] [System.Text.StringBuilder] $Builder,
        [AllowNull()] [AllowEmptyString()] $Text
    )
    if ($null -eq $Text) { [void]$Builder.Append("`n"); return }
    if ($Text -is [string] -or $Text -isnot [System.Collections.IEnumerable]) {
        [void]$Builder.Append(([string]$Text).Replace("`r`n", "`n").Replace("`r", "`n")).Append("`n")
        return
    }
    foreach ($t in $Text) { Add-FsLine -Builder $Builder -Text $t }
}

function Get-FsNoteText {
    <# Final note text: LF endings, runs of blank lines collapsed to one, exactly one trailing newline. #>
    [OutputType([string])]
    param([Parameter(Mandatory)] [System.Text.StringBuilder] $Builder)
    $t = $Builder.ToString().Replace("`r`n", "`n").Replace("`r", "`n")
    $t = [regex]::Replace($t, '\n{3,}', "`n`n")
    return $t.TrimEnd("`n") + "`n"
}
