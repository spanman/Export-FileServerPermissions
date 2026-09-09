<#
04 Direct User ACEs by Resource — explicit ACEs (at their origin; share ACEs included) whose principal is a
user, computer or local user rather than a group.
#>

function Get-FsDirectUserAceEntries {
    <# Explicit, non-InheritOnly ACE entries naming a user-kind principal. #>
    [OutputType([object[]])]
    param([Parameter(Mandatory)] [System.Collections.IDictionary] $Model)
    $out = foreach ($e in @(Get-FsAceEntries -Model $Model)) {
        if ($e.isInherited -or $e.isInheritOnly) { continue }
        if (Test-FsUserPrincipal -Model $Model -Id $e.principalId) { $e }
    }
    return @($out)
}

function Get-FsReportDirectUserAcesByResource {
    [OutputType([hashtable])]
    param(
        [Parameter(Mandatory)] [System.Collections.IDictionary] $Model,
        [Parameter(Mandatory)] [System.Collections.IDictionary] $Options,
        [Parameter(Mandatory)] $Definition
    )
    $items = [System.Collections.Generic.List[object]]::new()
    $resources = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    $users = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    foreach ($e in @(Get-FsDirectUserAceEntries -Model $Model)) {
        $s = Get-FsUserStatus -Model $Model -Options $Options -PrincipalId $e.principalId
        $name = Get-FsPrincipalName -Model $Model -Id $e.principalId
        $row = [ordered]@{
            Server       = (New-FsRef -Kind Server -Id $e.server)
            Resource     = (New-FsRef -Kind Resource -Id $e.refId)
            Path         = (New-FsCode $e.path)
            Layer        = $e.layer
            User         = (New-FsRef -Kind Principal -Id $e.principalId)
            Kind         = (Get-FsPrincipalKindLabel -Kind (Get-FsPrincipalKind -Model $Model -Id $e.principalId))
            Rights       = (New-FsCode $e.rights)
            Level        = $e.level
            Type         = $e.type
            Enabled      = (ConvertTo-FsYesNo $s.enabled)
            'Last logon' = (ConvertTo-FsDateText $s.lastLogon)
            Stale        = (ConvertTo-FsYesNo $s.stale)
            Department   = $s.department
        }
        $items.Add(@{ server = $e.server; path = $e.path; layer = $e.layerOrder; name = $name; principalId = $e.principalId; row = $row })
        [void]$resources.Add($e.refId); [void]$users.Add($e.principalId)
    }
    $rows = Select-FsSortedRows -Items @($items) -Property 'server', 'path', 'layer', 'name', 'principalId'
    $summary = '{0} direct user ACE(s) on {1} resource(s) for {2} user(s).' -f $rows.Count, $resources.Count, $users.Count
    return New-FsReportResult -Columns @('Server', 'Resource', 'Path', 'Layer', 'User', 'Kind', 'Rights', 'Level', 'Type', 'Enabled', 'Last logon', 'Stale', 'Department') -Rows $rows -Summary $summary
}
