<#
Folder note: Folders/<SERVER>/<Share>/<relative path>. Only created for divergent, non-share-root folders.
#>

function New-FsFolderNote {
    [OutputType([string])]
    param(
        [Parameter(Mandatory)] [System.Collections.IDictionary] $Model,
        [Parameter(Mandatory)] [hashtable] $Context,
        [Parameter(Mandatory)] [scriptblock] $Resolve,
        [Parameter(Mandatory)] [System.Collections.IDictionary] $Options,
        [Parameter(Mandatory)] [System.Collections.IDictionary] $Folder
    )
    $fid = [string]$Folder['id']
    $server = [string]$Folder['server']
    $shareId = [string]$Folder['primaryShareId']
    $ancId = [string](Get-FsValue $Folder 'nearestDivergentAncestorId')
    $ancIsRoot = (-not $ancId) -or ($Model.shares.Contains($shareId) -and $ancId -eq [string]$Model.shares[$shareId]['rootFolderId'])
    $ancName = if (-not $ancId) { '(share root)' } elseif ($Model.folders.Contains($ancId) -and -not [bool](Get-FsValue $Model.folders[$ancId] 'isShareRoot')) { [string](Get-FsValue $Model.folders[$ancId] 'relativePath') } else { '(share root)' }
    $ancPath = if ($ancId -and $Model.folders.Contains($ancId) -and -not [bool](Get-FsValue $Model.folders[$ancId] 'isShareRoot')) { [string](Get-FsValue $Model.folders[$ancId] 'relativePath') } else { '' }

    $ownerId = [string](Get-FsValue $Folder 'ownerPrincipalId')
    $ownerName = if ($ownerId) { Get-FsPrincipalName -Model $Model -Id $ownerId } else { $null }
    $aces = @($Folder['aces'])
    $denyCount = @($aces | Where-Object { ([string](Get-FsValue $_ 'accessControlType')) -eq 'Deny' }).Count
    $tags = Merge-FsTags 'folder' (Get-FsEntityTags -Context $Context -Id $fid)

    $b = New-FsNoteBuilder
    Add-FsLine $b (ConvertTo-FsFrontmatter -Properties ([ordered]@{
                type             = 'folder'
                generated        = $true
                id               = $fid
                tags             = $tags
                aliases          = @([string](Get-FsValue $Folder 'relativePath'))
                server           = $server
                share            = $(if ($Model.shares.Contains($shareId)) { [string]$Model.shares[$shareId]['name'] } else { $shareId })
                parent           = $ancName
                parentPath       = $ancPath
                uncPath          = [string]$Folder['uncPath']
                depth            = [int]$Folder['depth']
                protected        = [bool](Get-FsValue $Folder 'isProtected')
                owner            = $ownerName
                aceCount         = $aces.Count
                denyCount        = $denyCount
                explicitAceCount = [int](Get-FsValue $Folder 'explicitAceCount')
            }))
    Add-FsLine $b ('# {0}' -f [string](Get-FsValue $Folder 'relativePath'))
    Add-FsLine $b ''
    $parentLink = if ($ancIsRoot -or -not $ancId) { & $Resolve (New-FsRef -Kind Resource -Id $shareId) $false } else { & $Resolve (New-FsRef -Kind Resource -Id $ancId) $false }
    Add-FsLine $b ('**Depth:** {0}   **Share:** {1}   **Nearest captured parent:** {2}' -f `
            [int]$Folder['depth'], (& $Resolve (New-FsRef -Kind Resource -Id $shareId) $false), $parentLink)
    Add-FsLine $b ''
    $findings = Get-FsFindingsCallout -Model $Model -Resolve $Resolve -Id $fid
    if ($findings) { Add-FsLine $b $findings; Add-FsLine $b '' }

    Add-FsLine $b '## ACL'
    Add-FsLine $b (Format-FsMdTable -Columns 'Principal', 'Kind', 'Rights', 'Type', 'Inherited', 'Applies to' -Rows (Get-FsNtfsAceRows -Model $Model -Aces $aces) -Resolve $Resolve)
    Add-FsLine $b ''

    Add-FsLine $b '## Child divergent folders'
    $children = if ($Model.index.childrenByFolder.Contains($fid)) { @($Model.index.childrenByFolder[$fid]) } else { @() }
    $childRows = foreach ($cid in (Get-FsSorted -InputObject $children -Key { param($id) [string](Get-FsValue $Model.folders[$id] 'relativePath') })) {
        '- {0}' -f (& $Resolve (New-FsRef -Kind Resource -Id $cid) $false)
    }
    if (@($childRows).Count -eq 0) { Add-FsLine $b '_none_' } else { Add-FsLine $b $childRows }
    Add-FsLine $b ''

    Add-FsLine $b '## Effective access (this folder''s own ACL principals)'
    $principalIds = @(Get-FsSorted -InputObject @($aces | ForEach-Object { [string](Get-FsValue $_ 'principalId') } | Select-Object -Unique) -Key { param($id) Get-FsPrincipalName -Model $Model -Id $id })
    $effRows = foreach ($p in $principalIds) {
        $eff = Get-FsEffectiveLevel -Model $Model -PrincipalId $p -ResourceId $fid
        [ordered]@{ Principal = (New-FsRef -Kind Principal -Id $p); Level = $eff.level; 'Share level' = $eff.shareLevel; 'NTFS level' = $eff.ntfsLevel; Deny = (ConvertTo-FsYesNo $eff.hasDeny) }
    }
    Add-FsLine $b (Format-FsMdTable -Columns 'Principal', 'Level', 'Share level', 'NTFS level', 'Deny' -Rows $effRows -Resolve $Resolve)
    return (Get-FsNoteText -Builder $b)
}
