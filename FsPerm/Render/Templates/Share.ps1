<#
Share note: Shares/<SERVER - Name>. Carries the share-root NTFS ACL too (share-root folders get no note
of their own). Findings, share ACL, root NTFS ACL, a Mermaid tree of the share's divergent folders, a folder
link list, and "who can reach this share" (Get-FsResourceReachers when available, computed reach otherwise).
#>

function New-FsShareNote {
    [OutputType([string])]
    param(
        [Parameter(Mandatory)] [System.Collections.IDictionary] $Model,
        [Parameter(Mandatory)] [hashtable] $Context,
        [Parameter(Mandatory)] [scriptblock] $Resolve,
        [Parameter(Mandatory)] [System.Collections.IDictionary] $Options,
        [Parameter(Mandatory)] [System.Collections.IDictionary] $Share
    )
    $shareId = [string]$Share['id']
    $server = [string]$Share['server']
    $rootId = [string]$Share['rootFolderId']
    $root = if ($Model.folders.Contains($rootId)) { $Model.folders[$rootId] } else { $null }
    $tags = Merge-FsTags 'share' (Get-FsEntityTags -Context $Context -Id $shareId)

    $ownerId = $(if ($root) { [string](Get-FsValue $root 'ownerPrincipalId') } else { $null })
    $ownerName = if ($ownerId) { Get-FsPrincipalName -Model $Model -Id $ownerId } else { $null }
    $protected = $(if ($root) { [bool](Get-FsValue $root 'isProtected') } else { $false })
    $folderIds = if ($Model.index.foldersByShare.Contains($shareId)) { @($Model.index.foldersByShare[$shareId]) } else { @() }
    $ntfsAceCount = $(if ($root) { @($root['aces']).Count } else { 0 })

    $b = New-FsNoteBuilder
    Add-FsLine $b (ConvertTo-FsFrontmatter -Properties ([ordered]@{
                type          = 'share'
                generated     = $true
                id            = $shareId
                tags          = $tags
                aliases       = @([string]$Share['name'])
                server        = $server
                shareName     = [string]$Share['name']
                localPath     = [string]$Share['localPath']
                uncPath       = [string]$Share['uncPath']
                owner         = $ownerName
                protected     = $protected
                folderCount   = [Math]::Max(0, $folderIds.Count - 1)
                shareAceCount = @($Share['aces']).Count
                ntfsAceCount  = $ntfsAceCount
            }))
    Add-FsLine $b ('# {0}' -f [string]$Share['uncPath'])
    Add-FsLine $b ''
    Add-FsLine $b ('**Server:** {0}   **Local path:** {1}   **Description:** {2}' -f `
        (& $Resolve (New-FsRef -Kind Server -Id $server) $false), `
            (Format-FsMdCode -Text ([string]$Share['localPath'])), `
            $(if ([string]$Share['description']) { [string]$Share['description'] } else { '_none_' }))
    Add-FsLine $b ''
    $findings = Get-FsFindingsCallout -Model $Model -Resolve $Resolve -Id $shareId
    if ($findings) { Add-FsLine $b $findings; Add-FsLine $b '' }

    Add-FsLine $b '## Share ACL'
    Add-FsLine $b (Format-FsMdTable -Columns 'Principal', 'Rights', 'Type' -Rows (Get-FsShareAceRows -Model $Model -Aces @($Share['aces'])) -Resolve $Resolve)
    Add-FsLine $b ''

    Add-FsLine $b '## Root NTFS ACL'
    Add-FsLine $b ('**Owner:** {0}   **Inheritance:** {1}' -f `
        $(if ($ownerId) { & $Resolve (New-FsRef -Kind Principal -Id $ownerId) $false } else { '_unknown_' }), `
            $(if ($protected) { 'disabled (protected)' } else { 'enabled' }))
    Add-FsLine $b ''
    Add-FsLine $b (Format-FsMdTable -Columns 'Principal', 'Kind', 'Rights', 'Type', 'Inherited', 'Applies to' -Rows (Get-FsNtfsAceRows -Model $Model -Aces $(if ($root) { @($root['aces']) } else { @() })) -Resolve $Resolve)
    Add-FsLine $b ''

    Add-FsLine $b '## Folder tree'
    $nodes = [System.Collections.Generic.List[object]]::new()
    $edges = [System.Collections.Generic.List[object]]::new()
    $nodes.Add(@{ id = $rootId; label = [string]$Share['uncPath']; class = 'share' })
    foreach ($fid in $folderIds) {
        if ($fid -eq $rootId) { continue }
        $f = $Model.folders[$fid]
        $ftags = Get-FsEntityTags -Context $Context -Id $fid
        $cls = if ($ftags -contains 'deny') { 'deny' } elseif ([bool](Get-FsValue $f 'isProtected')) { 'protected' } else { 'folder' }
        $nodes.Add(@{ id = $fid; label = [string](Get-FsValue $f 'relativePath'); class = $cls })
        $anc = [string](Get-FsValue $f 'nearestDivergentAncestorId')
        if (-not $anc) { $anc = $rootId }
        $edges.Add(@{ from = $anc; to = $fid })
    }
    Add-FsLine $b (New-FsMermaidFlowchart -Direction 'TB' -Nodes @($nodes) -Edges @($edges))
    Add-FsLine $b ''

    Add-FsLine $b '## Folders'
    $folderLinkRows = foreach ($fid in (Get-FsSorted -InputObject @($folderIds | Where-Object { $_ -ne $rootId }) -Key { param($id) [string](Get-FsValue $Model.folders[$id] 'relativePath') })) {
        '- {0}' -f (& $Resolve (New-FsRef -Kind Resource -Id $fid) $false)
    }
    if (@($folderLinkRows).Count -eq 0) { Add-FsLine $b '_no divergent folders captured_' } else { Add-FsLine $b $folderLinkRows }
    Add-FsLine $b ''

    Add-FsLine $b '## Who can reach this share'
    $reachers = @(Get-FsResourceReachers -Model $Model -ResourceId $shareId)
    $reachRows = foreach ($r in $reachers) {
        [ordered]@{
            Principal = New-FsRef -Kind Principal -Id $r.principalId
            Kind      = Get-FsPrincipalKindLabel -Kind $r.kind
            Broad     = ConvertTo-FsYesNo $r.isBroad
            Level     = $r.effectiveLevel
            Deny      = ConvertTo-FsYesNo $r.hasDeny
            Users     = $r.userCount
        }
    }
    Add-FsLine $b (Format-FsMdTable -Columns 'Principal', 'Kind', 'Broad', 'Level', 'Deny', 'Users' -Rows $reachRows -Resolve $Resolve -MaxRows 300)
    return (Get-FsNoteText -Builder $b)
}
