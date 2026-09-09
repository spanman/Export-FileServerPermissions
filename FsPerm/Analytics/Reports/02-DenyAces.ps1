<#
02 Deny ACEs — every Deny ACE (inherited included) and whether it conflicts with an Allow in the same ACL
for people who carry both principals in their token (a Deny that conflicts with nothing does no work).
#>

function Get-FsReportDenyAces {
    [OutputType([hashtable])]
    param(
        [Parameter(Mandatory)] [System.Collections.IDictionary] $Model,
        [Parameter(Mandatory)] [System.Collections.IDictionary] $Options,
        [Parameter(Mandatory)] $Definition
    )
    $broad = Get-FsBroadPrincipalSet -Model $Model
    $byResource = Get-FsAceEntriesByResource -Model $Model
    $userSets = @{}
    $usersOf = {
        # $null = "everyone" (broad principal); otherwise the HashSet of user ids the principal stands for
        param($id)
        if ($userSets.Contains($id)) { return $userSets[$id] }
        $set = $null
        if (-not $broad.Contains($id)) {
            $set = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
            foreach ($u in @(Get-FsCandidateUsers -Model $Model -PrincipalId $id)) { [void]$set.Add($u) }
        }
        $userSets[$id] = $set
        return $set
    }
    $items = [System.Collections.Generic.List[object]]::new()
    $conflicts = 0
    foreach ($e in @(Get-FsAceEntries -Model $Model)) {
        if ($e.type -ne 'Deny') { continue }
        $deniedUsers = & $usersOf $e.principalId
        $conflicting = [System.Collections.Generic.List[object]]::new()
        $seen = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
        foreach ($a in @($byResource[$e.resourceId])) {
            if ($a.type -ne 'Allow' -or $a.isInheritOnly -or $a.layer -ne $e.layer) { continue }
            if (($a.mask -band $e.mask) -eq 0) { continue }
            if (-not $seen.Add($a.principalId)) { continue }
            $allowUsers = & $usersOf $a.principalId
            $hit = $false
            if ($a.principalId -eq $e.principalId) { $hit = $true }
            elseif ($null -eq $deniedUsers) { $hit = ($null -eq $allowUsers -or $allowUsers.Count -gt 0) }
            elseif ($null -eq $allowUsers) { $hit = ($deniedUsers.Count -gt 0) }
            else { foreach ($u in $deniedUsers) { if ($allowUsers.Contains($u)) { $hit = $true; break } } }
            if ($hit) { $conflicting.Add((New-FsRef -Kind Principal -Id $a.principalId)) }
        }
        $isConflict = ($conflicting.Count -gt 0)
        if ($isConflict) { $conflicts++ }
        $row = [ordered]@{
            Server               = (New-FsRef -Kind Server -Id $e.server)
            Resource             = (New-FsRef -Kind Resource -Id $e.refId)
            Path                 = (New-FsCode $e.path)
            Layer                = $e.layer
            Principal            = (New-FsRef -Kind Principal -Id $e.principalId)
            Kind                 = (Get-FsPrincipalKindLabel -Kind (Get-FsPrincipalKind -Model $Model -Id $e.principalId))
            Rights               = (New-FsCode $e.rights)
            Level                = $e.level
            Inherited            = (ConvertTo-FsYesNo $e.isInherited)
            'Applies to'         = $e.appliesTo
            Conflict             = (ConvertTo-FsYesNo $isConflict)
            'Conflicting allows' = @($conflicting)
        }
        $items.Add(@{ inherited = $(if ($e.isInherited) { 1 } else { 0 }); server = $e.server; path = $e.path; layer = $e.layerOrder; name = (Get-FsPrincipalName -Model $Model -Id $e.principalId); principalId = $e.principalId; row = $row })
    }
    $rows = Select-FsSortedRows -Items @($items) -Property 'inherited', 'server', 'path', 'layer', 'name', 'principalId'
    $explicit = @($items | Where-Object { $_.inherited -eq 0 }).Count
    $summary = '{0} Deny ACE(s) ({1} explicit, {2} inherited); {3} conflict with an Allow for the same people.' -f $rows.Count, $explicit, ($rows.Count - $explicit), $conflicts
    return New-FsReportResult -Columns @('Server', 'Resource', 'Path', 'Layer', 'Principal', 'Kind', 'Rights', 'Level', 'Inherited', 'Applies to', 'Conflict', 'Conflicting allows') -Rows $rows -Summary $summary
}
