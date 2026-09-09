<#
Analysis options. Every threshold and the clock used by analytics live here so that output is a pure
function of (model, options).
#>

function Get-FsAnalysisOptions {
    <#
    .SYNOPSIS
        Builds the options hashtable consumed by every analytics function.
    .PARAMETER Model
        When given, -Now defaults to the model's generatedAt and the admin allowlist is derived from its principals.
    .PARAMETER AdminPrincipalIds
        Principal ids excluded from over-permission reports (shown in their appendix). Default: every principal whose
        SID passes Test-FsAdminSid, plus every server-local group named Administrators, plus the well-known admin SIDs.
    .PARAMETER Now
        The clock. Defaults to [datetime]::Parse($Model.generatedAt), else the current UTC time.
    #>
    [OutputType([System.Collections.IDictionary])]
    param(
        [System.Collections.IDictionary] $Model,
        [int] $StaleDays = 90,
        [int] $PasswordAgeDays = 365,
        [int] $NestingDepthThreshold = 3,
        [int] $TopN = 25,
        [int] $RowCap = 500,
        [int] $LargeGroupThreshold = 500,
        [string[]] $AdminPrincipalIds,
        [System.Nullable[datetime]] $Now,
        [int] $SnapshotAgeWarnDays = 14
    )
    $clock = $null
    if ($null -ne $Now) { $clock = ConvertTo-FsUtcDateTime $Now }
    elseif ($Model -and $Model.Contains('generatedAt') -and $Model['generatedAt']) { $clock = ConvertTo-FsUtcDateTime $Model['generatedAt'] }
    if ($null -eq $clock) { $clock = [datetime]::UtcNow }

    $admins = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    if ($PSBoundParameters.ContainsKey('AdminPrincipalIds') -and $null -ne $AdminPrincipalIds) {
        foreach ($id in $AdminPrincipalIds) { if ($id) { [void]$admins.Add($id) } }
    }
    else {
        foreach ($sid in $script:FsAdminSids) { [void]$admins.Add($sid) }
        if ($Model) {
            $domainSids = [string[]]@($Model['domainSids'])
            foreach ($d in $domainSids) { foreach ($rid in $script:FsAdminRids) { [void]$admins.Add("$d-$rid") } }
            foreach ($id in Get-FsSortedKeys $Model.principals) {
                $p = $Model.principals[$id]
                $sid = [string](Get-FsValue $p 'sid')
                if ($sid -and (Test-FsAdminSid -Sid $sid -DomainSids $domainSids)) { [void]$admins.Add($id) }
                if (([string](Get-FsValue $p 'kind')) -eq 'LocalGroup' -and ([string](Get-FsValue $p 'name')) -eq 'Administrators') { [void]$admins.Add($id) }
            }
        }
    }

    return [ordered]@{
        StaleDays             = $StaleDays
        PasswordAgeDays       = $PasswordAgeDays
        NestingDepthThreshold = $NestingDepthThreshold
        TopN                  = $TopN
        RowCap                = $RowCap
        LargeGroupThreshold   = $LargeGroupThreshold
        AdminPrincipalIds     = [string[]]@(Get-FsSorted -InputObject @($admins))
        Now                   = $clock
        SnapshotAgeWarnDays   = $SnapshotAgeWarnDays
    }
}
