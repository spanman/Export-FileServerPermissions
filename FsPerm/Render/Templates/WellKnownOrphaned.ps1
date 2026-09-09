<#
WellKnown and Orphaned/Foreign principal notes: identity, tags, and a grants table. These principals have
no AD record and no group membership graph worth walking, so the note is deliberately small.
#>

function New-FsWellKnownNote {
    [OutputType([string])]
    param(
        [Parameter(Mandatory)] [System.Collections.IDictionary] $Model,
        [Parameter(Mandatory)] [hashtable] $Context,
        [Parameter(Mandatory)] [scriptblock] $Resolve,
        [Parameter(Mandatory)] [System.Collections.IDictionary] $Principal
    )
    $id = [string]$Principal['id']
    $tags = Merge-FsTags 'well-known' (Get-FsEntityTags -Context $Context -Id $id)
    $grants = @(Get-FsGrantRows -Model $Model -PrincipalId $id)

    $b = New-FsNoteBuilder
    Add-FsLine $b (ConvertTo-FsFrontmatter -Properties ([ordered]@{
                type      = 'well-known'
                generated = $true
                id        = $id
                tags      = $tags
                aliases   = @([string]$Principal['name'])
                sid       = [string]$Principal['sid']
                grantCount = $grants.Count
            }))
    Add-FsLine $b ('# {0}' -f [string]$Principal['displayName'])
    Add-FsLine $b ''
    Add-FsLine $b ('**SID:** {0}' -f (Format-FsMdCode -Text ([string]$Principal['sid'])))
    Add-FsLine $b ''
    $findings = Get-FsFindingsCallout -Model $Model -Resolve $Resolve -Id $id
    if ($findings) { Add-FsLine $b $findings; Add-FsLine $b '' }
    Add-FsLine $b '## Grants'
    Add-FsLine $b (Format-FsMdTable -Columns 'Resource', 'Rights', 'Type', 'Layer' -Rows $grants -Resolve $Resolve -EmptyText '_grants no access_')
    return (Get-FsNoteText -Builder $b)
}

function New-FsOrphanedNote {
    [OutputType([string])]
    param(
        [Parameter(Mandatory)] [System.Collections.IDictionary] $Model,
        [Parameter(Mandatory)] [hashtable] $Context,
        [Parameter(Mandatory)] [scriptblock] $Resolve,
        [Parameter(Mandatory)] [System.Collections.IDictionary] $Principal
    )
    $id = [string]$Principal['id']
    $tags = Merge-FsTags 'orphaned' (Get-FsEntityTags -Context $Context -Id $id)
    $grants = @(Get-FsGrantRows -Model $Model -PrincipalId $id)

    $b = New-FsNoteBuilder
    Add-FsLine $b (ConvertTo-FsFrontmatter -Properties ([ordered]@{
                type       = 'orphaned'
                generated  = $true
                id         = $id
                tags       = $tags
                aliases    = @([string]$id)
                sid        = [string](Get-FsValue $Principal 'sid')
                resolution = [string](Get-FsValue $Principal 'resolution')
                grantCount = $grants.Count
            }))
    Add-FsLine $b ('# {0}' -f $id)
    Add-FsLine $b ''
    Add-FsLine $b ('**Resolution:** {0}' -f $(if (Get-FsValue $Principal 'resolution') { [string](Get-FsValue $Principal 'resolution') } else { 'Unknown' }))
    Add-FsLine $b ''
    $findings = Get-FsFindingsCallout -Model $Model -Resolve $Resolve -Id $id
    if ($findings) { Add-FsLine $b $findings; Add-FsLine $b '' }
    Add-FsLine $b '## Grants'
    Add-FsLine $b (Format-FsMdTable -Columns 'Resource', 'Rights', 'Type', 'Layer' -Rows $grants -Resolve $Resolve -EmptyText '_grants no access_')
    return (Get-FsNoteText -Builder $b)
}
