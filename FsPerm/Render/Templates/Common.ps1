<#
Shared helpers for the note templates: the principal/resource/server ref resolver, frontmatter tag
helpers, ACE table row builders and small Mermaid node factories. Every New-Fs*Note function is a pure
function of ($Model, $Context, $Resolve, $Options) plus its entity, so output is deterministic.

$Context is a Render/NoteNames.ps1 New-FsNameContext hashtable. The renderer stashes the once-computed
insight tag table on it as $Context.tags (entityId -> string[]) so templates never recompute Get-FsInsightTags.
#>

function _New-FsPrincipalResolver {
    <#
    .SYNOPSIS
        Scriptblock usable as -Resolve for Format-FsMdCell / Format-FsMdTable: turns a New-FsRef into a
        full-path wikilink using NoteNames.ps1 + Markdown.ps1. Kind Resource picks Share vs Folder by id.
    #>
    [OutputType([scriptblock])]
    param(
        [Parameter(Mandatory)] [System.Collections.IDictionary] $Model,
        [Parameter(Mandatory)] [hashtable] $Context
    )
    return {
        param($ref, $inTable)
        $refKind = [string]$ref['_ref']
        $id = [string]$ref['id']
        $label = $ref['label']
        switch ($refKind) {
            'Principal' {
                # A principal id can outlive its note too (e.g. a NoLongerReferenced row in a Changes diff,
                # or a SID that was never resolved into a principal record at all).
                if (-not $Model.principals.Contains($id)) {
                    return Format-FsMdText -Text ([string]$(if ($label) { $label } else { Get-FsDisplayName -Model $Model -Kind Principal -Id $id }))
                }
                $path = Get-FsNotePath -Context $Context -Kind Principal -Id $id
                $alias = if ($label) { [string]$label } else { Get-FsDisplayName -Model $Model -Kind Principal -Id $id }
                return New-FsLink -Path $path -Alias $alias -InTable:$inTable
            }
            'Resource' {
                # A resource id can outlive the resource itself (e.g. a Removed row in a Changes/Changelog
                # diff): the share or folder is no longer in the merged model, so it has no note to link to.
                if (-not $Model.shares.Contains($id) -and -not $Model.folders.Contains($id)) {
                    return Format-FsMdText -Text ([string]$(if ($label) { $label } else { $id }))
                }
                $noteKind = if ($Model.shares.Contains($id)) { 'Share' } else { 'Folder' }
                $path = Get-FsNotePath -Context $Context -Kind $noteKind -Id $id
                $alias = if ($label) { [string]$label } else { Get-FsDisplayName -Model $Model -Kind $noteKind -Id $id }
                return New-FsLink -Path $path -Alias $alias -InTable:$inTable
            }
            'Server' {
                $path = Get-FsNotePath -Context $Context -Kind Server -Id $id
                $alias = if ($label) { [string]$label } else { Get-FsDisplayName -Model $Model -Kind Server -Id $id }
                return New-FsLink -Path $path -Alias $alias -InTable:$inTable
            }
            'Report' {
                $fileName = $id
                $cat = @(Get-FsReportCatalog | Where-Object { $_.key -eq $id })
                $title = $id
                if ($cat.Count -gt 0) { $fileName = $cat[0].fileName; $title = $cat[0].title }
                $path = Get-FsNotePath -Context $Context -Kind Report -Id $fileName
                $alias = if ($label) { [string]$label } else { $title }
                return New-FsLink -Path $path -Alias $alias -InTable:$inTable
            }
            default {
                return Format-FsMdText -Text ([string]$(if ($label) { $label } else { $id }))
            }
        }
    }.GetNewClosure()
}

function Get-FsEntityTags {
    <# Insight tags for an entity id from the once-computed $Context.tags table (empty array when absent). #>
    [OutputType([string[]])]
    param([Parameter(Mandatory)] [hashtable] $Context, [Parameter(Mandatory)] [AllowEmptyString()] [string] $Id)
    if (-not $Context.Contains('tags') -or $null -eq $Context['tags']) { return [string[]]@() }
    $t = $Context['tags']
    if ($t.Contains($Id)) { return [string[]]@($t[$Id]) }
    return [string[]]@()
}

function Get-FsKindTag {
    <# Fixed kind-tag vocabulary for a principal kind. #>
    [OutputType([string])]
    param([Parameter(Mandatory)] [string] $Kind)
    switch ($Kind) {
        'User' { return 'user' }
        'LocalUser' { return 'user' }
        'Computer' { return 'computer' }
        'Group' { return 'group' }
        'LocalGroup' { return 'local-group' }
        'WellKnown' { return 'well-known' }
        default { return 'orphaned' }
    }
}

function Merge-FsTags {
    <# Sorted, deduplicated union of one or more tag lists. #>
    [OutputType([string[]])]
    param([Parameter(ValueFromRemainingArguments)] [object[]] $TagLists)
    $all = [System.Collections.Generic.List[string]]::new()
    foreach ($list in $TagLists) { foreach ($t in @($list)) { if ($t) { $all.Add([string]$t) } } }
    return [string[]]@(Get-FsSorted -InputObject @($all) -Unique)
}

function Get-FsFindingsCallout {
    <#
    .SYNOPSIS
        A "Findings" callout linking to every report row that referenced this entity ($Model.findings), or
        $null when there are none.
    #>
    [OutputType([string])]
    param(
        [Parameter(Mandatory)] [System.Collections.IDictionary] $Model,
        [Parameter(Mandatory)] [scriptblock] $Resolve,
        [Parameter(Mandatory)] [AllowEmptyString()] [string] $Id
    )
    $findings = $Model['findings']
    if ($null -eq $findings -or -not $findings.Contains($Id)) { return $null }
    $entries = @(Get-FsSorted -InputObject @($findings[$Id]) -Property 'number')
    if ($entries.Count -eq 0) { return $null }
    $lines = foreach ($e in $entries) {
        $link = & $Resolve (New-FsRef -Kind Report -Id ([string]$e.reportKey)) $false
        '- {0} row(s) in {1} (sev/{2})' -f $e.count, $link, $e.severity
    }
    return New-FsCallout -Type warning -Title 'Findings' -Lines $lines
}

# ---------------------------------------------------------------- ACE table rows

function Get-FsAceSortKey {
    <# Deny before Allow, then principal display name, then ACE index — used to sort ACL tables. #>
    [OutputType([object[]])]
    param([Parameter(Mandatory)] [System.Collections.IDictionary] $Model, [Parameter(Mandatory)] $Ace)
    $rank = if (([string](Get-FsValue $Ace 'accessControlType')) -eq 'Deny') { 0 } else { 1 }
    $name = Get-FsPrincipalName -Model $Model -Id ([string](Get-FsValue $Ace 'principalId'))
    $idx = Get-FsValue $Ace 'index'
    return @($rank, $name, $(if ($null -ne $idx) { [int]$idx } else { 0 }))
}

function Get-FsShareAceRows {
    <# Share ACL table rows: Principal(ref) Rights(code) Type. Deny first. #>
    [OutputType([object[]])]
    param([Parameter(Mandatory)] [System.Collections.IDictionary] $Model, [AllowNull()] [object[]] $Aces)
    $sorted = @(Get-FsSorted -InputObject @($Aces) -Key { param($a) Get-FsAceSortKey -Model $Model -Ace $a })
    return @(foreach ($a in $sorted) {
            [ordered]@{
                Principal = New-FsRef -Kind Principal -Id ([string](Get-FsValue $a 'principalId'))
                Rights    = New-FsCode ([string](Get-FsValue $a 'accessRight'))
                Type      = [string](Get-FsValue $a 'accessControlType')
            }
        })
}

function Get-FsNtfsAceRows {
    <# NTFS ACL table rows: Principal(ref) Kind Rights(code) Type Inherited 'Applies to'. Deny first. #>
    [OutputType([object[]])]
    param([Parameter(Mandatory)] [System.Collections.IDictionary] $Model, [AllowNull()] [object[]] $Aces)
    $sorted = @(Get-FsSorted -InputObject @($Aces) -Key { param($a) Get-FsAceSortKey -Model $Model -Ace $a })
    return @(foreach ($a in $sorted) {
            $pid_ = [string](Get-FsValue $a 'principalId')
            [ordered]@{
                Principal      = New-FsRef -Kind Principal -Id $pid_
                Kind           = Get-FsPrincipalKindLabel -Kind (Get-FsPrincipalKind -Model $Model -Id $pid_)
                Rights         = New-FsCode ([string](Get-FsValue $a 'rights'))
                Type           = [string](Get-FsValue $a 'accessControlType')
                Inherited      = ConvertTo-FsYesNo ([bool](Get-FsValue $a 'isInherited'))
                'Applies to'   = [string](Get-FsValue $a 'appliesTo')
            }
        })
}

function Get-FsGrantRows {
    <# Grants table rows for a principal: Resource(ref) Rights(code) Type Layer, from $Model.index.acesByPrincipal. #>
    [OutputType([object[]])]
    param([Parameter(Mandatory)] [System.Collections.IDictionary] $Model, [Parameter(Mandatory)] [string] $PrincipalId)
    $entries = if ($Model.index.acesByPrincipal.Contains($PrincipalId)) { @($Model.index.acesByPrincipal[$PrincipalId]) } else { @() }
    $items = foreach ($e in $entries) {
        $ace = $e.ace
        @{
            server = [string]$e.server
            refId  = [string]$e.resourceId
            layer  = [string]$e.layer
            row    = [ordered]@{
                Resource = New-FsRef -Kind Resource -Id ([string]$e.resourceId)
                Rights   = New-FsCode ([string](Get-FsAceRightsText $ace))
                Type     = [string](Get-FsValue $ace 'accessControlType')
                Layer    = [string]$e.layer
            }
        }
    }
    return @(Get-FsSorted -InputObject @($items) -Property 'server', 'refId', 'layer' | ForEach-Object row)
}

# ---------------------------------------------------------------- mermaid node factories

function New-FsPrincipalMermaidNode {
    [OutputType([hashtable])]
    param([Parameter(Mandatory)] [System.Collections.IDictionary] $Model, [Parameter(Mandatory)] [string] $Id)
    $kind = Get-FsPrincipalKind -Model $Model -Id $Id
    $cls = switch ($kind) {
        'User' { 'user' } 'LocalUser' { 'user' } 'Computer' { 'computer' }
        'Group' { 'group' } 'LocalGroup' { 'local-group' } 'WellKnown' { 'well-known' }
        default { 'orphaned' }
    }
    return @{ id = $Id; label = (Get-FsPrincipalName -Model $Model -Id $Id); class = $cls }
}

function New-FsResourceMermaidNode {
    [OutputType([hashtable])]
    param([Parameter(Mandatory)] [System.Collections.IDictionary] $Model, [Parameter(Mandatory)] [string] $Id)
    $info = Get-FsResourceInfo -Model $Model -ResourceId $Id
    $cls = if ($info -and $info.kind -eq 'Share') { 'share' } else { 'folder' }
    $label = if ($info) { [string]$info.path } else { $Id }
    return @{ id = $Id; label = $label; class = $cls }
}

# ---------------------------------------------------------------- report link helper (used by Home/Dashboard/Reports Index)

function New-FsReportsIndexNote {
    <# "Reports/00 Reports Index" note: catalog table linking to every generated report. #>
    [OutputType([string])]
    param(
        [Parameter(Mandatory)] [System.Collections.IDictionary] $Model,
        [Parameter(Mandatory)] [hashtable] $Context,
        [Parameter(Mandatory)] [scriptblock] $Resolve,
        [Parameter(Mandatory)] [System.Collections.IDictionary] $Reports
    )
    $rows = foreach ($def in Get-FsReportCatalog) {
        $r = $Reports[$def.key]
        [ordered]@{
            Report   = New-FsRef -Kind Report -Id $def.key
            Severity = $def.severity
            Rows     = $(if ($r) { $r.rowCount } else { 0 })
            Question = $def.question
        }
    }
    $b = New-FsNoteBuilder
    Add-FsLine $b (ConvertTo-FsFrontmatter -Properties ([ordered]@{
                type      = 'report'
                generated = $true
                id        = 'reports-index'
                tags      = (Merge-FsTags 'report')
            }))
    Add-FsLine $b '# Reports Index'
    Add-FsLine $b ''
    Add-FsLine $b (Format-FsMdTable -Columns 'Report', 'Severity', 'Rows', 'Question' -Rows $rows -Resolve $Resolve)
    return (Get-FsNoteText -Builder $b)
}
