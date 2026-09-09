<#
10 Group Hygiene — categories: Empty group, Single member, Nested deep, Circular, Ownerless (no managedBy but
grants Modify or more), Local group (server-local groups that appear in ACLs).
#>

function Get-FsReportGroupHygiene {
    [OutputType([hashtable])]
    param(
        [Parameter(Mandatory)] [System.Collections.IDictionary] $Model,
        [Parameter(Mandatory)] [System.Collections.IDictionary] $Options,
        [Parameter(Mandatory)] $Definition
    )
    $order = @{ 'Empty group' = 0; 'Single member' = 1; 'Nested deep' = 2; 'Circular' = 3; 'Ownerless' = 4; 'Local group' = 5 }
    $counts = [ordered]@{ 'Empty group' = 0; 'Single member' = 0; 'Nested deep' = 0; 'Circular' = 0; 'Ownerless' = 0; 'Local group' = 0 }
    $broad = Get-FsBroadPrincipalSet -Model $Model
    $referenced = $Model.index.referencedPrincipalIds
    $acesByPrincipal = $Model.index.acesByPrincipal
    $threshold = [int]$Options['NestingDepthThreshold']
    $items = [System.Collections.Generic.List[object]]::new()

    $grantFacts = {
        param($gid)
        $count = 0; $highest = 0
        $servers = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
        if ($acesByPrincipal.Contains($gid)) {
            foreach ($entry in @($acesByPrincipal[$gid])) {
                $ace = $entry.ace
                if (([string](Get-FsValue $ace 'accessControlType')) -ne 'Allow') { continue }
                $count++
                [void]$servers.Add([string]$entry.server)
                $o = Get-FsLevelOrdinal (Get-FsMaskLevel -Mask (Get-FsAceMask $ace))
                if ($o -gt $highest) { $highest = $o }
            }
        }
        return @{ count = $count; highest = $highest; servers = @(Get-FsSorted -InputObject @($servers)) }
    }
    $add = {
        param($category, $gid, $detail)
        $g = Get-FsModelPrincipal -Model $Model -Id $gid
        $facts = & $grantFacts $gid
        $managedBy = [string](Get-FsValue $g 'ad.managedBy.sid')
        $direct = if ($Model.index.membersByGroup.Contains($gid)) { @($Model.index.membersByGroup[$gid]).Count } else { 0 }
        $row = [ordered]@{
            Category         = $category
            Group            = (New-FsRef -Kind Principal -Id $gid)
            Kind             = (Get-FsPrincipalKindLabel -Kind ([string](Get-FsValue $g 'kind')))
            'Direct members' = $direct
            'Users'          = @(Get-FsTransitiveMembers -Model $Model -GroupId $gid -UsersOnly).Count
            Depth            = (Get-FsGroupNestingDepth -Model $Model -GroupId $gid)
            'Managed by'     = $(if ($managedBy) { New-FsRef -Kind Principal -Id $managedBy } else { '' })
            Grants           = $facts.count
            'Highest grant'  = (Get-FsLevelName $facts.highest)
            Servers          = @($facts.servers | ForEach-Object { New-FsRef -Kind Server -Id $_ })
            Detail           = [string]$detail
        }
        $items.Add(@{ cat = $order[$category]; name = (Get-FsPrincipalName -Model $Model -Id $gid); principalId = $gid; row = $row })
        $counts[$category]++
    }

    foreach ($gid in @(Get-FsGroupPrincipalIds -Model $Model)) {
        $g = $Model.principals[$gid]
        $kind = [string](Get-FsValue $g 'kind')
        $isReferenced = $referenced.Contains($gid)
        $isBroad = $broad.Contains($gid)
        $users = @(Get-FsTransitiveMembers -Model $Model -GroupId $gid -UsersOnly)
        if ($isReferenced -and -not $isBroad) {
            if ($users.Count -eq 0) { & $add 'Empty group' $gid 'No user reaches this group, yet it appears in an ACL.' }
            elseif ($users.Count -eq 1) { & $add 'Single member' $gid ('Only user: {0}' -f (Get-FsPrincipalName -Model $Model -Id $users[0])) }
        }
        $depth = Get-FsGroupNestingDepth -Model $Model -GroupId $gid
        if ($depth -gt $threshold) { & $add 'Nested deep' $gid ('Nesting depth {0} exceeds threshold {1}.' -f $depth, $threshold) }
        if ($kind -eq 'Group' -and $isReferenced -and -not $isBroad) {
            $facts = & $grantFacts $gid
            if (-not [string](Get-FsValue $g 'ad.managedBy.sid') -and $facts.highest -ge 4) { & $add 'Ownerless' $gid ('No managedBy; grants {0}.' -f (Get-FsLevelName $facts.highest)) }
        }
        if ($kind -eq 'LocalGroup' -and $isReferenced) { & $add 'Local group' $gid $(if ($isBroad) { 'Server-local group containing broad principals.' } else { 'Server-local group in an ACL; membership is per machine.' }) }
    }
    foreach ($cycle in @(Get-FsGroupCycles -Model $Model)) {
        if ($cycle.Count -gt 0 -and $cycle[0] -isnot [string]) { $cycle = $cycle[0] }   # tolerate an over-wrapped single-object return
        $names = @($cycle | ForEach-Object { Get-FsPrincipalName -Model $Model -Id $_ })
        $detail = (($names + $names[0]) -join ' -> ')
        foreach ($gid in $cycle) { & $add 'Circular' $gid $detail }
    }
    $rows = Select-FsSortedRows -Items @($items) -Property 'cat', 'name', 'principalId'
    $parts = foreach ($k in $counts.Keys) { '{0} {1}' -f $counts[$k], $k.ToLowerInvariant() }
    $summary = '{0} finding(s): {1}.' -f $rows.Count, ($parts -join ', ')
    return New-FsReportResult -Columns @('Category', 'Group', 'Kind', 'Direct members', 'Users', 'Depth', 'Managed by', 'Grants', 'Highest grant', 'Servers', 'Detail') -Rows $rows -Summary $summary
}
