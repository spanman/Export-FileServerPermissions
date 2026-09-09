<#
User note: Users/<name> (User, Computer, LocalUser kinds). Identity, manager, group membership (direct and
transitive), direct ACEs, effective access (broad principals excluded and named once), an access-path
Mermaid diagram, and direct reports.
#>

function New-FsUserNote {
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
    $status = Get-FsUserStatus -Model $Model -Options $Options -PrincipalId $id
    $tags = Merge-FsTags (Get-FsKindTag -Kind $kind) (Get-FsEntityTags -Context $Context -Id $id)

    $managerSid = [string](Get-FsValue $Principal 'ad.manager.sid')
    $managerLink = if ($managerSid -and $Model.principals.Contains($managerSid)) {
        New-FsLink -Path (Get-FsNotePath -Context $Context -Kind Principal -Id $managerSid) -Alias (Get-FsDisplayName -Model $Model -Kind Principal -Id $managerSid)
    } else { $null }

    $directGroups = if ($Model.index.groupsByMember.Contains($id)) { @($Model.index.groupsByMember[$id]) } else { @() }
    $directGroups = @(Get-FsSorted -InputObject $directGroups -Key { param($g) Get-FsPrincipalName -Model $Model -Id $g })
    $memberOfLinks = @($directGroups | ForEach-Object { New-FsLink -Path (Get-FsNotePath -Context $Context -Kind Principal -Id $_) -Alias (Get-FsDisplayName -Model $Model -Kind Principal -Id $_) })

    $grants = @(Get-FsGrantRows -Model $Model -PrincipalId $id)
    $directAceCount = 0
    if ($Model.index.acesByPrincipal.Contains($id)) {
        $directAceCount = @($Model.index.acesByPrincipal[$id] | Where-Object { -not [bool](Get-FsValue $_.ace 'isInherited') }).Count
    }
    $effAccessAll = @(Get-FsEffectiveAccess -Model $Model -PrincipalId $id)
    $effAccessSpecific = @(Get-FsEffectiveAccess -Model $Model -PrincipalId $id -ExcludeBroad)

    $b = New-FsNoteBuilder
    Add-FsLine $b (ConvertTo-FsFrontmatter -Properties ([ordered]@{
                type           = $(if ($kind -eq 'Computer') { 'computer' } else { 'user' })
                generated      = $true
                id             = $id
                tags           = $tags
                aliases        = @([string]$Principal['name'])
                samAccountName = [string]$Principal['name']
                domain         = [string]$Principal['domain']
                displayName    = [string]$Principal['displayName']
                upn            = [string](Get-FsValue $Principal 'ad.userPrincipalName')
                mail           = [string](Get-FsValue $Principal 'ad.mail')
                enabled        = $status.enabled
                lastLogon      = $status.lastLogon
                pwdLastSet     = $status.pwdLastSet
                whenCreated    = $status.created
                accountExpires = $status.accountExpires
                neverLoggedOn  = $status.neverLoggedOn
                department     = $status.department
                title          = $status.title
                description    = [string](Get-FsValue $Principal 'ad.description')
                manager        = $managerLink
                memberOf       = $memberOfLinks
                directAceCount = $directAceCount
                groupCount     = $directGroups.Count
                resourceCount  = $effAccessSpecific.Count
            }))
    Add-FsLine $b ('# {0}' -f [string]$Principal['displayName'])
    Add-FsLine $b ''
    $statusText = if ($status.statuses.Count -gt 0) { ($status.statuses -join ', ') } else { 'Active' }
    Add-FsLine $b ('**Account:** {0}   **Department:** {1}   **Title:** {2}   **Status:** {3}' -f `
        (Format-FsMdCode -Text ([string]$Principal['ntAccount'])), `
            $(if ($status.department) { $status.department } else { '_none_' }), `
            $(if ($status.title) { $status.title } else { '_none_' }), $statusText)
    if ($managerLink) { Add-FsLine $b ('**Manager:** {0}' -f $managerLink) }
    Add-FsLine $b ''
    $findings = Get-FsFindingsCallout -Model $Model -Resolve $Resolve -Id $id
    if ($findings) { Add-FsLine $b $findings; Add-FsLine $b '' }

    Add-FsLine $b '## Member of'
    if ($directGroups.Count -eq 0) { Add-FsLine $b '_no direct group memberships_' }
    else { Add-FsLine $b @(foreach ($g in $directGroups) { '- {0}' -f (& $Resolve (New-FsRef -Kind Principal -Id $g) $false) }) }
    Add-FsLine $b ''

    Add-FsLine $b '## Effective groups'
    $transitive = @(Get-FsTransitiveGroups -Model $Model -PrincipalId $id)
    if ($transitive.Count -eq 0) { Add-FsLine $b '_none_' }
    else {
        $lines = foreach ($g in (Get-FsSorted -InputObject $transitive -Key { param($x) Get-FsPrincipalName -Model $Model -Id $x })) {
            $chain = @(Get-FsGroupChain -Model $Model -PrincipalId $id -GroupId $g)
            $chainText = if ($chain.Count -gt 2) {
                ' (' + (($chain | ForEach-Object { Get-FsPrincipalName -Model $Model -Id $_ }) -join ' -> ') + ')'
            } else { '' }
            '- {0}{1}' -f (& $Resolve (New-FsRef -Kind Principal -Id $g) $false), $chainText
        }
        Add-FsLine $b $lines
    }
    Add-FsLine $b ''

    Add-FsLine $b '## Direct access'
    Add-FsLine $b (Format-FsMdTable -Columns 'Resource', 'Rights', 'Type', 'Layer' -Rows $grants -Resolve $Resolve -EmptyText '_no direct ACEs_')
    Add-FsLine $b ''

    Add-FsLine $b '## Effective access'
    $broadIds = @(Get-FsBroadPrincipalIds -Model $Model)
    $broadNote = if ($effAccessAll.Count -gt $effAccessSpecific.Count) {
        New-FsCallout -Type info -Title 'Broad grants excluded above' -Lines @(('{0} additional grant point(s) reach this user only through broad principals ({1}) and are omitted from the table below.' -f ($effAccessAll.Count - $effAccessSpecific.Count), (($broadIds | ForEach-Object { Get-FsPrincipalName -Model $Model -Id $_ }) -join ', ')))
    } else { $null }
    if ($broadNote) { Add-FsLine $b $broadNote; Add-FsLine $b '' }
    $effRows = foreach ($r in $effAccessSpecific) {
        [ordered]@{
            Resource = (New-FsRef -Kind Resource -Id $r.resourceId)
            Level    = $r.level
            Via      = @($r.via | ForEach-Object { New-FsRef -Kind Principal -Id $_ })
            Deny     = (ConvertTo-FsYesNo $r.hasDeny)
        }
    }
    Add-FsLine $b (Format-FsMdTable -Columns 'Resource', 'Level', 'Via', 'Deny' -Rows $effRows -Resolve $Resolve -MaxRows 300)
    Add-FsLine $b ''

    Add-FsLine $b '## Access path'
    $hubs = [System.Collections.Generic.HashSet[string]]::new([string[]]$broadIds, [System.StringComparer]::OrdinalIgnoreCase)
    $nodes = [System.Collections.Generic.List[object]]::new()
    $edges = [System.Collections.Generic.List[object]]::new()
    $nodes.Add((New-FsPrincipalMermaidNode -Model $Model -Id $id))
    foreach ($r in ($effAccessSpecific | Select-Object -First 25)) {
        $prev = $id
        foreach ($hop in $r.via) {
            if ($hubs.Contains($hop)) { continue }
            $nodes.Add((New-FsPrincipalMermaidNode -Model $Model -Id $hop))
            $edges.Add(@{ from = $prev; to = $hop })
            $prev = $hop
        }
        $nodes.Add((New-FsResourceMermaidNode -Model $Model -Id $r.resourceId))
        $edges.Add(@{ from = $prev; to = $r.resourceId; label = $r.level })
    }
    Add-FsLine $b (New-FsMermaidFlowchart -Direction 'LR' -Nodes @($nodes) -Edges @($edges))
    Add-FsLine $b ''

    $reports = @(Get-FsUserPrincipalIds -Model $Model | Where-Object { ([string](Get-FsValue $Model.principals[$_] 'ad.manager.sid')) -eq $id })
    if ($reports.Count -gt 0) {
        Add-FsLine $b '## Direct reports'
        $lines = foreach ($r in (Get-FsSorted -InputObject $reports -Key { param($x) Get-FsPrincipalName -Model $Model -Id $x })) {
            '- {0}' -f (& $Resolve (New-FsRef -Kind Principal -Id $r) $false)
        }
        Add-FsLine $b $lines
    }
    return (Get-FsNoteText -Builder $b)
}
