<#
12 Privileged Grants to Non-Admins — explicit Allow ACEs (at their origin) that grant Full Control, or
Change Permissions / Take Ownership without Full Control, to principals outside the admin allowlist.
#>

function Get-FsReportPrivilegedGrants {
    [OutputType([hashtable])]
    param(
        [Parameter(Mandatory)] [System.Collections.IDictionary] $Model,
        [Parameter(Mandatory)] [System.Collections.IDictionary] $Options,
        [Parameter(Mandatory)] $Definition
    )
    $broad = Get-FsBroadPrincipalSet -Model $Model
    $items = [System.Collections.Generic.List[object]]::new()
    $appendix = [System.Collections.Generic.List[object]]::new()
    $fullCount = 0
    foreach ($e in @(Get-FsAceEntries -Model $Model)) {
        if ($e.type -ne 'Allow' -or $e.isInherited -or $e.isInheritOnly) { continue }
        $privilege = $null
        if ($e.level -eq 'Full') { $privilege = 'Full Control' }
        elseif (Test-FsMaskWriteDacOrOwner -Mask $e.mask) {
            $bits = @()
            if ($e.mask -band 0x40000) { $bits += 'Change Permissions' }
            if ($e.mask -band 0x80000) { $bits += 'Take Ownership' }
            $privilege = ($bits -join ', ')
        }
        if (-not $privilege) { continue }
        $kind = Get-FsPrincipalKind -Model $Model -Id $e.principalId
        $isBroad = $broad.Contains($e.principalId)
        $userCount = if ($isBroad) { 'all' } elseif (Test-FsUserKind -Kind $kind) { 1 } else { @(Get-FsTransitiveMembers -Model $Model -GroupId $e.principalId -UsersOnly).Count }
        $row = [ordered]@{
            Privilege = $privilege
            Server    = (New-FsRef -Kind Server -Id $e.server)
            Resource  = (New-FsRef -Kind Resource -Id $e.refId)
            Path      = (New-FsCode $e.path)
            Layer     = $e.layer
            Principal = (New-FsRef -Kind Principal -Id $e.principalId)
            Kind      = (Get-FsPrincipalKindLabel -Kind $kind)
            Broad     = (ConvertTo-FsYesNo $isBroad)
            Rights    = (New-FsCode $e.rights)
            Level     = $e.level
            Users     = $userCount
        }
        $item = @{ priv = $(if ($privilege -eq 'Full Control') { 0 } else { 1 }); server = $e.server; path = $e.path; layer = $e.layerOrder; name = (Get-FsPrincipalName -Model $Model -Id $e.principalId); principalId = $e.principalId; row = $row }
        if (Test-FsAdminPrincipal -Model $Model -Options $Options -PrincipalId $e.principalId) { $appendix.Add($item); continue }
        $items.Add($item)
        if ($privilege -eq 'Full Control') { $fullCount++ }
    }
    $sortBy = 'priv', 'server', 'path', 'layer', 'name', 'principalId'
    $rows = Select-FsSortedRows -Items @($items) -Property $sortBy
    $summary = '{0} privileged grant(s) to non-admins ({1} Full Control, {2} Change Permissions / Take Ownership without Full).' -f $rows.Count, $fullCount, ($rows.Count - $fullCount)
    return New-FsReportResult -Columns @('Privilege', 'Server', 'Resource', 'Path', 'Layer', 'Principal', 'Kind', 'Broad', 'Rights', 'Level', 'Users') -Rows $rows -Summary $summary -AppendixTitle 'Admin allowlist (excluded from the table above)' -AppendixRows (Select-FsSortedRows -Items @($appendix) -Property $sortBy)
}
