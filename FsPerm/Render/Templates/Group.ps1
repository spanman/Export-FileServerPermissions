<#
Group note: Groups/<name> (Group, LocalGroup kinds). Scope/category/managedBy, members (groups first),
member-of, grants, a nesting Mermaid diagram, and a capped inline effective-members list.
#>

function New-FsGroupNote {
    [OutputType([string])]
    param(
        [Parameter(Mandatory)] [System.Collections.IDictionary] $Model,
        [Parameter(Mandatory)] [hashtable] $Context,
        [Parameter(Mandatory)] [scriptblock] $Resolve,
        [Parameter(Mandatory)] [System.Collections.IDictionary] $Options,
        [Parameter(Mandatory)] [System.Collections.IDictionary] $Principal
    )
    $id = [string]$Principal['id']
    $kind = [string]$Principal['kind']
    $tags = Merge-FsTags (Get-FsKindTag -Kind $kind) (Get-FsEntityTags -Context $Context -Id $id)

    $managedBySid = [string](Get-FsValue $Principal 'ad.managedBy.sid')
    $managedByLink = if ($managedBySid -and $Model.principals.Contains($managedBySid)) {
        New-FsLink -Path (Get-FsNotePath -Context $Context -Kind Principal -Id $managedBySid) -Alias (Get-FsDisplayName -Model $Model -Kind Principal -Id $managedBySid)
    } else { $null }

    $memberIds = if ($Model.index.membersByGroup.Contains($id)) { @($Model.index.membersByGroup[$id]) } else { @() }
    $memberOfIds = if ($Model.index.groupsByMember.Contains($id)) { @($Model.index.groupsByMember[$id]) } else { @() }
    $memberOfIds = @(Get-FsSorted -InputObject $memberOfIds -Key { param($g) Get-FsPrincipalName -Model $Model -Id $g })
    $memberOfLinks = @($memberOfIds | ForEach-Object { New-FsLink -Path (Get-FsNotePath -Context $Context -Kind Principal -Id $_) -Alias (Get-FsDisplayName -Model $Model -Kind Principal -Id $_) })
    $grants = @(Get-FsGrantRows -Model $Model -PrincipalId $id)
    $nestingDepth = Get-FsGroupNestingDepth -Model $Model -GroupId $id
    $memberCount = Get-FsValue $Principal 'memberCount'
    if ($null -eq $memberCount) { $memberCount = $memberIds.Count }

    $b = New-FsNoteBuilder
    Add-FsLine $b (ConvertTo-FsFrontmatter -Properties ([ordered]@{
                type          = $(if ($kind -eq 'LocalGroup') { 'local-group' } else { 'group' })
                generated     = $true
                id            = $id
                tags          = $tags
                aliases       = @([string]$Principal['name'])
                groupScope    = [string](Get-FsValue $Principal 'ad.groupScope')
                groupCategory = [string](Get-FsValue $Principal 'ad.groupCategory')
                managedBy     = $managedByLink
                memberCount   = $memberCount
                nestingDepth  = $nestingDepth
                memberOf      = $memberOfLinks
                grantCount    = $grants.Count
                server        = [string](Get-FsValue $Principal 'server')
            }))
    Add-FsLine $b ('# {0}' -f [string]$Principal['displayName'])
    Add-FsLine $b ''
    Add-FsLine $b ('**Scope:** {0}   **Category:** {1}   **Members:** {2}   **Nesting depth:** {3}   **Managed by:** {4}' -f `
        $(if (Get-FsValue $Principal 'ad.groupScope') { [string](Get-FsValue $Principal 'ad.groupScope') } else { '_n/a_' }), `
            $(if (Get-FsValue $Principal 'ad.groupCategory') { [string](Get-FsValue $Principal 'ad.groupCategory') } else { '_n/a_' }), `
            $memberCount, $nestingDepth, $(if ($managedByLink) { $managedByLink } else { '_none_' }))
    Add-FsLine $b ''
    $desc = [string](Get-FsValue $Principal 'ad.description')
    if ($desc) { Add-FsLine $b (New-FsCallout -Type quote -Lines @($desc)); Add-FsLine $b '' }
    $findings = Get-FsFindingsCallout -Model $Model -Resolve $Resolve -Id $id
    if ($findings) { Add-FsLine $b $findings; Add-FsLine $b '' }

    Add-FsLine $b '## Members'
    $memberRows = foreach ($m in $memberIds) {
        $mkind = Get-FsPrincipalKind -Model $Model -Id $m
        $isGroup = Test-FsGroupKind -Kind $mkind
        [ordered]@{
            _order    = $(if ($isGroup) { 0 } else { 1 })
            Member    = (New-FsRef -Kind Principal -Id $m)
            Kind      = (Get-FsPrincipalKindLabel -Kind $mkind)
            _name     = (Get-FsPrincipalName -Model $Model -Id $m)
        }
    }
    $sortedMembers = @(Get-FsSorted -InputObject $memberRows -Property '_order', '_name') | ForEach-Object { [ordered]@{ Member = $_.Member; Kind = $_.Kind } }
    Add-FsLine $b (Format-FsMdTable -Columns 'Member', 'Kind' -Rows $sortedMembers -Resolve $Resolve -MaxRows 200)
    Add-FsLine $b ''

    Add-FsLine $b '## Member of'
    if ($memberOfIds.Count -eq 0) { Add-FsLine $b '_not a member of any group_' }
    else { Add-FsLine $b @(foreach ($g in $memberOfIds) { '- {0}' -f (& $Resolve (New-FsRef -Kind Principal -Id $g) $false) }) }
    Add-FsLine $b ''

    Add-FsLine $b '## Grants'
    Add-FsLine $b (Format-FsMdTable -Columns 'Resource', 'Rights', 'Type', 'Layer' -Rows $grants -Resolve $Resolve -EmptyText '_grants no access_')
    Add-FsLine $b ''

    Add-FsLine $b '## Nesting'
    $nodes = [System.Collections.Generic.List[object]]::new()
    $edges = [System.Collections.Generic.List[object]]::new()
    $nodes.Add((New-FsPrincipalMermaidNode -Model $Model -Id $id))
    foreach ($p in $memberOfIds) { $nodes.Add((New-FsPrincipalMermaidNode -Model $Model -Id $p)); $edges.Add(@{ from = $id; to = $p }) }
    foreach ($m in $memberIds) {
        if (Test-FsGroupKind -Kind (Get-FsPrincipalKind -Model $Model -Id $m)) {
            $nodes.Add((New-FsPrincipalMermaidNode -Model $Model -Id $m)); $edges.Add(@{ from = $m; to = $id })
        }
    }
    Add-FsLine $b (New-FsMermaidFlowchart -Direction 'BT' -Nodes @($nodes) -Edges @($edges))
    Add-FsLine $b ''

    Add-FsLine $b '## Effective members'
    $effUsers = @(Get-FsTransitiveMembers -Model $Model -GroupId $id -UsersOnly)
    $effUsers = @(Get-FsSorted -InputObject $effUsers -Key { param($x) Get-FsPrincipalName -Model $Model -Id $x })
    $cap = 50
    $shown = if ($effUsers.Count -gt $cap) { @($effUsers[0..($cap - 1)]) } else { $effUsers }
    if ($shown.Count -eq 0) { Add-FsLine $b '_no effective user members_' }
    else {
        Add-FsLine $b @(foreach ($u in $shown) { '- {0}' -f (& $Resolve (New-FsRef -Kind Principal -Id $u) $false) })
        if ($effUsers.Count -gt $cap) { Add-FsLine $b ''; Add-FsLine $b ('_… {0} more effective user member(s)_' -f ($effUsers.Count - $cap)) }
    }
    return (Get-FsNoteText -Builder $b)
}
