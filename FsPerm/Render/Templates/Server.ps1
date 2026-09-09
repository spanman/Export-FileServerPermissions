<#
Server note: Servers/<NAME>. Scan metadata, a shares table (Folders/Deny/Broad columns computed from the
model so it never depends on Diff/HomeStats), local groups seen in ACLs, scan errors, and a placeholder
"Changes since previous scan" section (Compare-FsSnapshots/Get-FsChangeSets do not exist yet — see
Export-Vault.ps1's adapter comment).
#>

function New-FsServerNote {
    [OutputType([string])]
    param(
        [Parameter(Mandatory)] [System.Collections.IDictionary] $Model,
        [Parameter(Mandatory)] [hashtable] $Context,
        [Parameter(Mandatory)] [scriptblock] $Resolve,
        [Parameter(Mandatory)] [System.Collections.IDictionary] $Options,
        [Parameter(Mandatory)] [System.Collections.IDictionary] $Server
    )
    $name = [string]$Server['name']
    $tags = Merge-FsTags 'server' (Get-FsEntityTags -Context $Context -Id $name)
    $shareIds = @($Server['shareIds'])
    $broadSet = Get-FsBroadPrincipalSet -Model $Model

    $shareRows = foreach ($sid in (Get-FsSorted -InputObject $shareIds)) {
        if (-not $Model.shares.Contains($sid)) { continue }
        $share = $Model.shares[$sid]
        $folderIds = if ($Model.index.foldersByShare.Contains($sid)) { @($Model.index.foldersByShare[$sid]) } else { @() }
        $entries = @(Get-FsAceEntries -Model $Model | Where-Object { $_.shareId -eq $sid })
        $deny = @($entries | Where-Object { $_.type -eq 'Deny' }).Count
        $broad = @($entries | Where-Object { $_.type -eq 'Allow' -and -not $_.isInherited -and $broadSet.Contains($_.principalId) }).Count
        [ordered]@{
            Share   = New-FsRef -Kind Resource -Id $sid
            Folders = [Math]::Max(0, $folderIds.Count - 1)
            Deny    = $deny
            Broad   = $broad
        }
    }

    $localGroupRows = foreach ($pid_ in Get-FsSortedKeys $Model.principals) {
        $p = $Model.principals[$pid_]
        if (([string](Get-FsValue $p 'kind')) -ne 'LocalGroup') { continue }
        if (([string](Get-FsValue $p 'server')) -ne $name) { continue }
        [ordered]@{
            Group   = New-FsRef -Kind Principal -Id $pid_
            Members = (Get-FsValue $p 'memberCount')
            Grants  = @(if ($Model.index.acesByPrincipal.Contains($pid_)) { $Model.index.acesByPrincipal[$pid_] }).Count
        }
    }

    $errorRows = foreach ($e in (Get-FsSorted -InputObject @($Model.errors | Where-Object { ([string](Get-FsValue $_ 'server')) -eq $name }) -Property 'phase', 'path')) {
        [ordered]@{
            Phase   = [string](Get-FsValue $e 'phase')
            Scope   = [string](Get-FsValue $e 'scope')
            Path    = New-FsCode ([string](Get-FsValue $e 'path'))
            Kind    = [string](Get-FsValue $e 'kind')
            Message = [string](Get-FsValue $e 'message')
        }
    }

    $b = New-FsNoteBuilder
    Add-FsLine $b (ConvertTo-FsFrontmatter -Properties ([ordered]@{
                type        = 'server'
                generated   = $true
                id          = $name
                tags        = $tags
                aliases     = @($name)
                fqdn        = [string](Get-FsValue $Server 'fqdn')
                lastScanned = (Get-FsValue $Server 'lastScanned')
                scanId      = [string](Get-FsValue $Server 'scanId')
                shareCount  = $shareIds.Count
                errorCount  = [int](Get-FsValue $Server 'errorCount')
                snapshotCount = (Get-FsValue $Server 'snapshotCount')
            }))
    Add-FsLine $b ('# {0}' -f $name)
    Add-FsLine $b ''
    Add-FsLine $b ('**Last scanned:** {0}   **Depth:** {1}   **Credential user:** {2}   **Snapshots kept:** {3}' -f `
        (Format-FsMdDateTime -Value (Get-FsValue $Server 'lastScanned')), `
            [string](Get-FsValue $Server 'scope.depth'), `
        (Format-FsMdCode -Text ([string](Get-FsValue $Server 'credentialUser'))), `
            (Get-FsValue $Server 'snapshotCount'))
    Add-FsLine $b ''
    $findings = Get-FsFindingsCallout -Model $Model -Resolve $Resolve -Id $name
    if ($findings) { Add-FsLine $b $findings; Add-FsLine $b '' }

    Add-FsLine $b '## Shares'
    Add-FsLine $b (Format-FsMdTable -Columns 'Share', 'Folders', 'Deny', 'Broad' -Rows $shareRows -Resolve $Resolve)
    Add-FsLine $b ''

    Add-FsLine $b '## Local groups seen in ACLs'
    Add-FsLine $b (Format-FsMdTable -Columns 'Group', 'Members', 'Grants' -Rows $localGroupRows -Resolve $Resolve -EmptyText '_none captured_')
    Add-FsLine $b ''

    Add-FsLine $b '## Scan errors'
    Add-FsLine $b (Format-FsMdTable -Columns 'Phase', 'Scope', 'Path', 'Kind', 'Message' -Rows $errorRows -Resolve $Resolve -EmptyText '_none_' -MaxRows 100)
    Add-FsLine $b ''

    Add-FsLine $b '## Changes since previous scan'
    if (Get-Command -Name 'Get-FsChangeSets' -CommandType Function -ErrorAction SilentlyContinue) {
        Add-FsLine $b (New-FsEmbed -Path (Get-FsNotePath -Context $Context -Kind Report -Id ('Changes - ' + $name)) -Heading 'Summary')
    }
    else {
        Add-FsLine $b '_Change tracking is not available yet: this server has no previous snapshot, or Compare-FsSnapshots has not been wired in. Re-run after a second scan to see what changed._'
    }
    return (Get-FsNoteText -Builder $b)
}
