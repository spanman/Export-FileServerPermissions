<#
Obsidian Bases (.base) files — native database views over note properties (core plugin, Obsidian 1.9+).

Schema (obsidian.md/help/bases/syntax):
  filters:            global filter — recursive and/or/not lists of expression strings
    and:
      - file.hasTag("user")
  formulas:           name -> expression
  properties:         property -> { displayName }
  views:
    - type: table | cards | list | kanban | map
      name: ...
      filters: ...     (ANDed with the global filter)
      groupBy: { property, direction }
      order: [ property, ... ]          column order
      sort: [ { property, direction: ASC|DESC }, ... ]
      limit: N
      columnSize: { property: px }
Note properties are referenced bare ("enabled == false") or as note.<name>; file.* are file metadata.
#>

function New-FsBase {
    <#
    .SYNOPSIS
        Builds .base YAML text.
    .PARAMETER Filters
        A filter expression string, an array of strings (ANDed), or a dictionary (@{ and = @(...) } / or / not).
    .PARAMETER Views
        Dictionaries with type, name and optionally filters, groupBy, order, sort, limit, columnSize.
    #>
    [OutputType([string])]
    param(
        [AllowNull()] $Filters,
        [Parameter(Mandatory)] [AllowEmptyCollection()] [object[]] $Views,
        [AllowNull()] [System.Collections.IDictionary] $Formulas,
        [AllowNull()] [System.Collections.IDictionary] $Properties
    )
    $doc = [ordered]@{}
    $f = ConvertTo-FsBaseFilter -Filters $Filters
    if ($null -ne $f) { $doc['filters'] = $f }
    if ($Formulas -and $Formulas.Count -gt 0) { $doc['formulas'] = $Formulas }
    if ($Properties -and $Properties.Count -gt 0) { $doc['properties'] = $Properties }
    $viewList = [System.Collections.Generic.List[object]]::new()
    foreach ($v in $Views) {
        if ($null -eq $v) { continue }
        $view = [ordered]@{}
        $view['type'] = $(if (Get-FsValue $v 'type') { [string](Get-FsValue $v 'type') } else { 'table' })
        $view['name'] = [string](Get-FsValue $v 'name')
        foreach ($k in 'filters', 'groupBy', 'order', 'sort', 'limit', 'columnSize', 'rowHeight', 'cardSize', 'image', 'imageFit', 'imageAspectRatio', 'summaries') {
            $val = Get-FsValue $v $k
            if ($null -eq $val) { continue }
            if ($k -eq 'filters') { $val = ConvertTo-FsBaseFilter -Filters $val; if ($null -eq $val) { continue } }
            # 'order'/'sort'/'summaries' are lists in the schema; Get-FsValue's single-element-array-unrolls-
            # to-scalar convention (see its own doc comment) means a one-item list (even one that unrolled all
            # the way to a bare hashtable, e.g. one sort criterion) must be re-wrapped here. @() on a plain
            # variable (not a piped/returned value) is safe either way: scalar/dictionary -> 1-item array,
            # already-an-array -> the same array.
            if ($k -in 'order', 'sort', 'summaries') { $val = @($val) }
            $view[$k] = $val
        }
        $viewList.Add($view)
    }
    $doc['views'] = @($viewList)
    return (ConvertTo-FsYaml -Properties $doc)
}

function ConvertTo-FsBaseFilter {
    <# Normalizes -Filters input to the and/or/not dictionary form (or $null when empty). #>
    [OutputType([System.Collections.IDictionary])]
    param([AllowNull()] $Filters)
    if ($null -eq $Filters) { return $null }
    if ($Filters -is [System.Collections.IDictionary]) { return $(if ($Filters.Count -gt 0) { $Filters } else { $null }) }
    $raw = if ($Filters -is [string]) { , $Filters } else { @($Filters) }
    $items = @($raw | Where-Object { -not [string]::IsNullOrWhiteSpace([string]$_) })
    if ($items.Count -eq 0) { return $null }
    return [ordered]@{ and = @($items | ForEach-Object { [string]$_ }) }
}

function New-FsBaseSort {
    <# @{ property; direction } entry for a view's sort list. #>
    [OutputType([System.Collections.Specialized.OrderedDictionary])]
    param([Parameter(Mandatory)] [string] $Property, [ValidateSet('ASC', 'DESC')] [string] $Direction = 'ASC')
    return [ordered]@{ property = $Property; direction = $Direction }
}

function Get-FsDefaultBases {
    <#
    .SYNOPSIS
        Name -> .base text for the vault-root bases (Users, Groups, Folders, Shares, Reports), using the
        frontmatter property names from the plan and the fixed kind tags.
    #>
    [OutputType([System.Collections.Specialized.OrderedDictionary])]
    param()
    $bases = [ordered]@{}

    $bases['Users.base'] = New-FsBase -Filters 'file.hasTag("user")' -Views @(
        [ordered]@{ type = 'table'; name = 'All users'
            order = @('file.name', 'displayName', 'department', 'title', 'enabled', 'lastLogon', 'groupCount', 'resourceCount', 'directAceCount')
            sort = @((New-FsBaseSort 'file.name')) },
        [ordered]@{ type = 'table'; name = 'By department'
            groupBy = [ordered]@{ property = 'department'; direction = 'ASC' }
            order = @('file.name', 'displayName', 'title', 'enabled', 'lastLogon', 'resourceCount')
            sort = @((New-FsBaseSort 'file.name')) },
        [ordered]@{ type = 'table'; name = 'Disabled'
            filters = 'enabled == false'
            order = @('file.name', 'displayName', 'department', 'lastLogon', 'resourceCount', 'directAceCount')
            sort = @((New-FsBaseSort 'lastLogon' 'DESC')) },
        [ordered]@{ type = 'table'; name = 'Stale or never logged on'
            filters = [ordered]@{ or = @('file.hasTag("stale")', 'neverLoggedOn == true') }
            order = @('file.name', 'displayName', 'department', 'enabled', 'lastLogon', 'whenCreated', 'resourceCount')
            sort = @((New-FsBaseSort 'lastLogon')) },
        [ordered]@{ type = 'table'; name = 'Direct ACEs'
            filters = 'directAceCount > 0'
            order = @('file.name', 'displayName', 'department', 'enabled', 'directAceCount', 'resourceCount')
            sort = @((New-FsBaseSort 'directAceCount' 'DESC')) }
    )

    $bases['Groups.base'] = New-FsBase -Filters ([ordered]@{ or = @('file.hasTag("group")', 'file.hasTag("local-group")') }) -Views @(
        [ordered]@{ type = 'table'; name = 'All groups'
            order = @('file.name', 'groupScope', 'groupCategory', 'memberCount', 'nestingDepth', 'grantCount', 'managedBy')
            sort = @((New-FsBaseSort 'file.name')) },
        [ordered]@{ type = 'table'; name = 'Granting access'
            filters = 'grantCount > 0'
            order = @('file.name', 'memberCount', 'grantCount', 'nestingDepth', 'managedBy')
            sort = @((New-FsBaseSort 'grantCount' 'DESC')) },
        [ordered]@{ type = 'table'; name = 'Empty'
            filters = 'memberCount == 0'
            order = @('file.name', 'groupScope', 'grantCount', 'managedBy')
            sort = @((New-FsBaseSort 'file.name')) },
        [ordered]@{ type = 'table'; name = 'Large or deeply nested'
            filters = [ordered]@{ or = @('file.hasTag("large-group")', 'file.hasTag("nested-deep")') }
            order = @('file.name', 'memberCount', 'nestingDepth', 'grantCount')
            sort = @((New-FsBaseSort 'memberCount' 'DESC')) },
        [ordered]@{ type = 'table'; name = 'Local groups'
            filters = 'file.hasTag("local-group")'
            order = @('file.name', 'server', 'memberCount', 'grantCount')
            sort = @((New-FsBaseSort 'file.name')) }
    )

    $bases['Folders.base'] = New-FsBase -Filters 'file.hasTag("folder")' -Views @(
        [ordered]@{ type = 'table'; name = 'All folders'
            order = @('file.name', 'server', 'share', 'depth', 'protected', 'aceCount', 'explicitAceCount', 'denyCount', 'owner')
            sort = @((New-FsBaseSort 'server'), (New-FsBaseSort 'share'), (New-FsBaseSort 'file.name')) },
        [ordered]@{ type = 'table'; name = 'By share'
            groupBy = [ordered]@{ property = 'share'; direction = 'ASC' }
            order = @('file.name', 'depth', 'protected', 'aceCount', 'denyCount')
            sort = @((New-FsBaseSort 'file.name')) },
        [ordered]@{ type = 'table'; name = 'Inheritance disabled'
            filters = 'protected == true'
            order = @('file.name', 'server', 'share', 'depth', 'aceCount', 'explicitAceCount', 'owner')
            sort = @((New-FsBaseSort 'file.name')) },
        [ordered]@{ type = 'table'; name = 'With Deny'
            filters = 'denyCount > 0'
            order = @('file.name', 'server', 'share', 'denyCount', 'aceCount')
            sort = @((New-FsBaseSort 'denyCount' 'DESC')) }
    )

    $bases['Shares.base'] = New-FsBase -Filters 'file.hasTag("share")' -Views @(
        [ordered]@{ type = 'table'; name = 'All shares'
            order = @('file.name', 'server', 'shareName', 'uncPath', 'folderCount', 'shareAceCount', 'ntfsAceCount', 'protected', 'owner')
            sort = @((New-FsBaseSort 'server'), (New-FsBaseSort 'shareName')) },
        [ordered]@{ type = 'table'; name = 'By server'
            groupBy = [ordered]@{ property = 'server'; direction = 'ASC' }
            order = @('file.name', 'shareName', 'localPath', 'folderCount', 'shareAceCount')
            sort = @((New-FsBaseSort 'shareName')) },
        [ordered]@{ type = 'table'; name = 'Broad access'
            filters = [ordered]@{ or = @('file.hasTag("broad-access")', 'file.hasTag("broad-write")') }
            order = @('file.name', 'server', 'uncPath', 'folderCount', 'shareAceCount')
            sort = @((New-FsBaseSort 'file.name')) }
    )

    $bases['Reports.base'] = New-FsBase -Filters 'file.hasTag("report")' -Views @(
        [ordered]@{ type = 'table'; name = 'All reports'
            order = @('file.name', 'severity', 'rows', 'servers', 'generatedAt')
            sort = @((New-FsBaseSort 'file.name')) },
        [ordered]@{ type = 'table'; name = 'By severity'
            groupBy = [ordered]@{ property = 'severity'; direction = 'ASC' }
            order = @('file.name', 'rows', 'servers')
            sort = @((New-FsBaseSort 'rows' 'DESC')) },
        [ordered]@{ type = 'table'; name = 'With findings'
            filters = 'rows > 0'
            order = @('file.name', 'severity', 'rows')
            sort = @((New-FsBaseSort 'rows' 'DESC')) }
    )
    return $bases
}
