<#
Report catalog, the report runner and the small helpers every Reports/*.ps1 file uses.

Each report is a function Get-FsReport<PascalKey> -Model -Options -Definition returning
  @{ columns(string[]); rows(ordered hashtables keyed by column); summary; appendixTitle; appendixRows; footnotes }
Cells are scalars, New-FsRef refs, New-FsCode codes, or arrays of those. Rows arrive fully sorted; the runner
applies RowCap (all rows stay in csvRows) and builds $Model.findings (entityId -> @{ reportKey; count }).
#>

$script:FsReportCatalog = @(
    @{ key = 'broad-exposure'; number = 1; title = 'Broad Exposure'; question = 'Which Allow ACEs grant access to Everyone, Authenticated Users, Domain Users or groups that contain them, and what do they effectively get?'; severity = 'high' }
    @{ key = 'deny-aces'; number = 2; title = 'Deny ACEs'; question = 'Where are Deny ACEs in use, and do they conflict with an Allow for the same people (i.e. do real work)?'; severity = 'medium' }
    @{ key = 'inheritance-broken'; number = 3; title = 'Inheritance Broken'; question = 'Which folders have inheritance disabled, and what did that remove or add compared with the nearest captured ancestor?'; severity = 'medium' }
    @{ key = 'direct-user-aces-by-resource'; number = 4; title = 'Direct User ACEs by Resource'; question = 'Which resources grant users directly instead of through groups (AGDLP violations)?'; severity = 'medium' }
    @{ key = 'direct-user-aces-by-user'; number = 5; title = 'Direct User ACEs by User'; question = 'Which users hold direct ACEs, and on how many resources?'; severity = 'medium' }
    @{ key = 'dormant-accounts'; number = 6; title = 'Disabled and Stale Accounts with Access'; question = 'Which disabled, expired, stale, never-logged-on or stale-password accounts still reach data?'; severity = 'high' }
    @{ key = 'orphaned-principals'; number = 7; title = 'Orphaned and Unresolved Principals'; question = 'Which ACEs and memberships reference SIDs that no longer resolve or belong to unreachable domains?'; severity = 'low' }
    @{ key = 'over-permissioned-users'; number = 8; title = 'Over-permissioned Users'; question = 'Which users reach the most resources with Full or Modify rights (admin allowlist excluded)?'; severity = 'medium' }
    @{ key = 'over-permissioned-groups'; number = 9; title = 'Over-permissioned Groups'; question = 'Which groups grant the most Full or Modify access, and to how many users?'; severity = 'medium' }
    @{ key = 'group-hygiene'; number = 10; title = 'Group Hygiene'; question = 'Which groups are empty, single-member, deeply nested, circular, ownerless with write access, or server-local?'; severity = 'medium' }
    @{ key = 'full-control'; number = 11; title = 'Full Control Anywhere'; question = 'Which non-admin users have effective Full Control anywhere, and through which groups?'; severity = 'high' }
    @{ key = 'privileged-grants'; number = 12; title = 'Privileged Grants to Non-Admins'; question = 'Which explicit ACEs grant Full Control, Change Permissions or Take Ownership to principals outside the admin allowlist?'; severity = 'high' }
    @{ key = 'department-access'; number = 13; title = 'Department Access'; question = 'How many users of each department reach each share, and at what level?'; severity = 'info' }
    @{ key = 'share-ntfs-limiter'; number = 15; title = 'Share vs NTFS Limiter'; question = 'For each principal on each share, which layer limits access, and which share paths overlap?'; severity = 'medium' }
    @{ key = 'scan-health'; number = 16; title = 'Scan Health'; question = 'How complete and fresh is each server scan?'; severity = 'info' }
)

$script:FsReportFootnotes = @(
    'Effective rights are approximated from a pseudo-token (the principal, its transitive groups, and Everyone / Authenticated Users / NETWORK for accounts). Claims, dynamic access control, Owner Rights, and the backup/restore privilege are not modelled.'
    'Only captured folders are evaluated: share roots and folders whose ACL diverges from the parent, within the scan depth. Deeper folders inherit the nearest captured ACL.'
    'Broad principals (Everyone, Authenticated Users, NETWORK, INTERACTIVE, BUILTIN\Users, Domain Users, and groups containing them) are never expanded to individual users; per-user counts cover specific grants only.'
    'Servers are scanned at different times; group membership and account attributes are as of each server''s latest snapshot.'
)

function Get-FsReportCatalog {
    <# Ordered report definitions: @{ key number title question severity fileName } (number 14 is intentionally unused). #>
    [OutputType([object[]])]
    param()
    $out = foreach ($d in $script:FsReportCatalog) {
        [ordered]@{
            key      = $d.key
            number   = $d.number
            title    = $d.title
            question = $d.question
            severity = $d.severity
            fileName = ('{0:00} {1}' -f $d.number, $d.title)
        }
    }
    return @($out)
}

function Get-FsReportFootnotes {
    [OutputType([string[]])]
    param()
    return [string[]]$script:FsReportFootnotes
}

function ConvertTo-FsPascalKey {
    <# 'over-permissioned-users' -> 'OverPermissionedUsers' #>
    [OutputType([string])]
    param([Parameter(Mandatory)] [string] $Key)
    $parts = foreach ($p in $Key.Split('-')) { if ($p) { $p.Substring(0, 1).ToUpperInvariant() + $p.Substring(1) } }
    return ($parts -join '')
}

function New-FsReportResult {
    <# Uniform shape returned by every Get-FsReport* function. #>
    [OutputType([hashtable])]
    param(
        [Parameter(Mandatory)] [AllowEmptyCollection()] [string[]] $Columns,
        [AllowNull()] [AllowEmptyCollection()] [object[]] $Rows,
        [AllowNull()] [string] $Summary,
        [AllowNull()] [string] $AppendixTitle,
        [AllowNull()] [AllowEmptyCollection()] [object[]] $AppendixRows,
        [AllowNull()] [string[]] $Footnotes
    )
    return @{
        columns       = [string[]]$Columns
        rows          = @($Rows | Where-Object { $null -ne $_ })
        summary       = $(if ($Summary) { $Summary } else { '' })
        appendixTitle = $AppendixTitle
        appendixRows  = @($AppendixRows | Where-Object { $null -ne $_ })
        footnotes     = $(if ($null -ne $Footnotes) { [string[]]$Footnotes } else { Get-FsReportFootnotes })
    }
}

function Select-FsSortedRows {
    <# Sorts pre-row items (hashtables with scalar sort keys and a 'row' member) and returns the rows. #>
    [OutputType([object[]])]
    param([AllowNull()] [AllowEmptyCollection()] [object[]] $Items, [Parameter(Mandatory)] [string[]] $Property)
    if ($null -eq $Items -or $Items.Count -eq 0) { return @() }
    return @(Get-FsSorted -InputObject @($Items) -Property $Property | ForEach-Object { $_.row })
}

function Get-FsRowRefIds {
    <# Distinct Principal / Resource ref ids in a row (arrays of refs included). #>
    [OutputType([string[]])]
    param([Parameter(Mandatory)] [System.Collections.IDictionary] $Row)
    $ids = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    foreach ($v in $Row.Values) {
        $cells = if ($v -is [System.Collections.IDictionary]) { @($v) } elseif ($v -is [System.Collections.IEnumerable] -and $v -isnot [string]) { @($v) } else { @() }
        foreach ($c in $cells) {
            if ((Test-FsRef $c) -and $c['_ref'] -in 'Principal', 'Resource' -and $c['id']) { [void]$ids.Add([string]$c['id']) }
        }
    }
    return [string[]]@($ids)
}

function Invoke-FsReports {
    <#
    .SYNOPSIS
        Runs every catalog report and builds the findings reverse index.
    .OUTPUTS
        ordered hashtable key -> @{ definition columns rows summary appendixRows appendixTitle truncated csvRows footnotes rowCount }
        Also sets $Model.findings[entityId] = list of @{ reportKey; count } ordered by report number.
    #>
    [OutputType([System.Collections.Specialized.OrderedDictionary])]
    param(
        [Parameter(Mandatory)] [System.Collections.IDictionary] $Model,
        [System.Collections.IDictionary] $Options
    )
    if ($null -eq $Options) { $Options = Get-FsAnalysisOptions -Model $Model }
    $rowCap = [int]$Options['RowCap']
    $results = [ordered]@{}
    $findings = @{}
    foreach ($def in Get-FsReportCatalog) {
        $fn = 'Get-FsReport' + (ConvertTo-FsPascalKey $def.key)
        $cmd = Get-Command -Name $fn -CommandType Function -ErrorAction SilentlyContinue
        if ($null -eq $cmd) { throw "Report function '$fn' for report '$($def.key)' is not defined." }
        $r = & $cmd -Model $Model -Options $Options -Definition $def
        $all = @($r.rows)
        $columns = if ($r.columns) { [string[]]$r.columns } elseif ($all.Count -gt 0) { [string[]]@($all[0].Keys) } else { [string[]]@() }
        $truncated = ($rowCap -gt 0 -and $all.Count -gt $rowCap)
        # [object[]] on the LHS is required, not decorative: an if/else expression whose executing branch emits
        # a single object (a 1-row array unrolls to its lone element through the branch's own output stream)
        # would otherwise collapse $shown to a bare row hashtable instead of a 1-element array.
        [object[]] $shown = if ($truncated) { $all[0..($rowCap - 1)] } else { $all }
        $results[$def.key] = [ordered]@{
            definition    = $def
            columns       = $columns
            rows          = $shown
            summary       = [string]$r.summary
            appendixRows  = @($r.appendixRows)
            appendixTitle = $r.appendixTitle
            truncated     = $truncated
            csvRows       = $all
            footnotes     = [string[]]$r.footnotes
            rowCount      = $all.Count
        }
        $counts = @{}
        foreach ($row in $all) {
            foreach ($id in @(Get-FsRowRefIds -Row $row)) { $counts[$id] = 1 + $(if ($counts.Contains($id)) { $counts[$id] } else { 0 }) }
        }
        foreach ($id in $counts.Keys) {
            if (-not $findings.Contains($id)) { $findings[$id] = [System.Collections.Generic.List[object]]::new() }
            $findings[$id].Add(@{ reportKey = $def.key; count = $counts[$id]; number = $def.number; title = $def.title; severity = $def.severity })
        }
    }
    $Model['findings'] = $findings
    $Model['reports'] = $results
    return $results
}
