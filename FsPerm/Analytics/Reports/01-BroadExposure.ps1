<#
01 Broad Exposure — explicit Allow ACEs (at their origin) to broad principals or groups containing them,
with the granted level and what the principal effectively gets after the other layer's cap.
#>

function Get-FsReportBroadExposure {
    [OutputType([hashtable])]
    param(
        [Parameter(Mandatory)] [System.Collections.IDictionary] $Model,
        [Parameter(Mandatory)] [System.Collections.IDictionary] $Options,
        [Parameter(Mandatory)] $Definition
    )
    $broad = Get-FsBroadPrincipalSet -Model $Model
    $items = [System.Collections.Generic.List[object]]::new()
    $appendix = [System.Collections.Generic.List[object]]::new()
    $resources = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    $writePlus = 0
    foreach ($e in @(Get-FsAceEntries -Model $Model)) {
        if ($e.type -ne 'Allow' -or $e.isInherited -or $e.isInheritOnly) { continue }
        if (-not $broad.Contains($e.principalId)) { continue }
        $eff = Get-FsEffectiveLevel -Model $Model -PrincipalId $e.principalId -ResourceId $e.resourceId
        $effOrd = Get-FsLevelOrdinal $eff.level
        $sev = if ($effOrd -ge 3) { 'high' } elseif ($effOrd -ge 1) { 'medium' } else { 'low' }
        $limiter = if ((Get-FsLevelOrdinal $eff.shareLevel) -lt (Get-FsLevelOrdinal $eff.ntfsLevel)) { 'Share' } elseif ((Get-FsLevelOrdinal $eff.ntfsLevel) -lt (Get-FsLevelOrdinal $eff.shareLevel)) { 'NTFS' } else { '' }
        $name = Get-FsPrincipalName -Model $Model -Id $e.principalId
        $row = [ordered]@{
            Severity      = $sev
            Server        = (New-FsRef -Kind Server -Id $e.server)
            Resource      = (New-FsRef -Kind Resource -Id $e.refId)
            Path          = (New-FsCode $e.path)
            Layer         = $e.layer
            Principal     = (New-FsRef -Kind Principal -Id $e.principalId)
            Kind          = (Get-FsPrincipalKindLabel -Kind (Get-FsPrincipalKind -Model $Model -Id $e.principalId))
            Granted       = $e.level
            Rights        = (New-FsCode $e.rights)
            Effective     = $eff.level
            'Share level' = $eff.shareLevel
            'NTFS level'  = $eff.ntfsLevel
            Limiter       = $limiter
        }
        $item = @{ sev = (Get-FsSeverityRank $sev); eff = -$effOrd; server = $e.server; path = $e.path; layer = $e.layerOrder; name = $name; principalId = $e.principalId; row = $row }
        if (Test-FsAdminPrincipal -Model $Model -Options $Options -PrincipalId $e.principalId) { $appendix.Add($item); continue }
        $items.Add($item)
        [void]$resources.Add($e.refId)
        if ($effOrd -ge 3) { $writePlus++ }
    }
    $sortBy = 'sev', 'eff', 'server', 'path', 'layer', 'name', 'principalId'
    $rows = Select-FsSortedRows -Items @($items) -Property $sortBy
    $summary = '{0} broad grant(s) on {1} resource(s); {2} effectively Write or higher.' -f $rows.Count, $resources.Count, $writePlus
    return New-FsReportResult -Columns @($rows.Count -gt 0 ? [string[]]$rows[0].Keys : [string[]]@('Severity', 'Server', 'Resource', 'Path', 'Layer', 'Principal', 'Kind', 'Granted', 'Rights', 'Effective', 'Share level', 'NTFS level', 'Limiter')) `
        -Rows $rows -Summary $summary -AppendixTitle 'Admin allowlist (excluded from the table above)' -AppendixRows (Select-FsSortedRows -Items @($appendix) -Property $sortBy)
}
