<#
Account status and the fixed insight-tag vocabulary consumed by the renderer.

Tags (never derived from data values):
  users     disabled stale never-logged-on direct-ace
  groups    empty-group nested-deep large-group
  resources deny inheritance-broken broad-access broad-write direct-ace orphaned-ace
  servers   scan-error
#>

function Get-FsUserStatus {
    <#
    .SYNOPSIS
        Account-hygiene facts for a user principal: enabled disabled expired stale neverLoggedOn neverLoggedOnAged stalePassword
        lastLogon pwdLastSet created accountExpires (UTC datetimes or $null) and statuses(string[]).
    #>
    [OutputType([hashtable])]
    param(
        [Parameter(Mandatory)] [System.Collections.IDictionary] $Model,
        [Parameter(Mandatory)] [System.Collections.IDictionary] $Options,
        [Parameter(Mandatory)] [string] $PrincipalId
    )
    $p = Get-FsModelPrincipal -Model $Model -Id $PrincipalId
    $now = [datetime]$Options['Now']
    $ad = Get-FsValue $p 'ad'
    $local = Get-FsValue $p 'local'
    $enabled = Get-FsValue $p 'ad.enabled'
    if ($null -eq $enabled) { $enabled = Get-FsValue $p 'local.enabled' }
    if ($null -ne $enabled) { $enabled = [bool]$enabled }
    $lastLogon = ConvertTo-FsUtcDateTime (Get-FsValue $p 'ad.lastLogonTimestamp')
    $pwdLastSet = ConvertTo-FsUtcDateTime (Get-FsValue $p 'ad.pwdLastSet')
    $created = ConvertTo-FsUtcDateTime (Get-FsValue $p 'ad.whenCreated')
    $expires = ConvertTo-FsUtcDateTime (Get-FsValue $p 'ad.accountExpires')
    $hasAd = ($null -ne $ad)
    $status = @{
        enabled           = $enabled
        disabled          = ($enabled -eq $false)
        expired           = ($null -ne $expires -and $expires -lt $now)
        stale             = ($null -ne $lastLogon -and ($now - $lastLogon).TotalDays -gt [int]$Options['StaleDays'])
        neverLoggedOn     = ($hasAd -and $null -eq $lastLogon)
        neverLoggedOnAged = ($hasAd -and $null -eq $lastLogon -and ($null -eq $created -or ($now - $created).TotalDays -gt 30))
        stalePassword     = ($null -ne $pwdLastSet -and ($now - $pwdLastSet).TotalDays -gt [int]$Options['PasswordAgeDays'])
        lastLogon         = $lastLogon
        pwdLastSet        = $pwdLastSet
        created           = $created
        accountExpires    = $expires
        hasAd             = $hasAd
        isLocal           = ($null -ne $local)
        department        = [string](Get-FsValue $p 'ad.department')
        title             = [string](Get-FsValue $p 'ad.title')
    }
    $list = [System.Collections.Generic.List[string]]::new()
    if ($status.disabled) { $list.Add('Disabled') }
    if ($status.expired) { $list.Add('Expired') }
    if ($status.stale) { $list.Add('Stale') }
    if ($status.neverLoggedOn) { $list.Add('Never logged on') }
    if ($status.stalePassword) { $list.Add('Stale password') }
    $status['statuses'] = [string[]]$list.ToArray()
    return $status
}

function Get-FsInsightTags {
    <#
    .SYNOPSIS
        entityId -> sorted string[] of insight tags for users, groups, resources (share-root folders fold into their share) and servers.
    #>
    [OutputType([hashtable])]
    param(
        [Parameter(Mandatory)] [System.Collections.IDictionary] $Model,
        [System.Collections.IDictionary] $Options
    )
    if ($null -eq $Options) { $Options = Get-FsAnalysisOptions -Model $Model }
    $tags = @{}
    $tag = {
        param($id, $name)
        if (-not $id) { return }
        if (-not $tags.Contains($id)) { $tags[$id] = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::Ordinal) }
        [void]$tags[$id].Add($name)
    }
    $broad = Get-FsBroadPrincipalSet -Model $Model

    foreach ($uid in @(Get-FsUserPrincipalIds -Model $Model)) {
        $s = Get-FsUserStatus -Model $Model -Options $Options -PrincipalId $uid
        if ($s.disabled) { & $tag $uid 'disabled' }
        if ($s.stale) { & $tag $uid 'stale' }
        if ($s.neverLoggedOnAged) { & $tag $uid 'never-logged-on' }
    }

    foreach ($e in @(Get-FsAceEntries -Model $Model)) {
        $pid_ = $e.principalId
        $kind = Get-FsPrincipalKind -Model $Model -Id $pid_
        if ($e.type -eq 'Deny') { & $tag $e.refId 'deny'; & $tag $pid_ 'deny' }
        if ((Test-FsUserKind -Kind $kind) -and -not $e.isInherited) { & $tag $pid_ 'direct-ace'; & $tag $e.refId 'direct-ace' }
        if ($e.type -eq 'Allow' -and -not $e.isInherited -and -not $e.isInheritOnly -and $broad.Contains($pid_)) {
            & $tag $e.refId 'broad-access'
            if ((Get-FsLevelOrdinal $e.level) -ge 3) { & $tag $e.refId 'broad-write' }
        }
        if (Test-FsUnresolvedPrincipal -Model $Model -Id $pid_) { & $tag $e.refId 'orphaned-ace' }
    }

    foreach ($fid in Get-FsSortedKeys $Model.folders) {
        if ([bool](Get-FsValue $Model.folders[$fid] 'isProtected')) { & $tag (Get-FsGrantPointRefId -Model $Model -ResourceId $fid) 'inheritance-broken' }
    }

    $referenced = $Model.index.referencedPrincipalIds
    foreach ($gid in @(Get-FsGroupPrincipalIds -Model $Model)) {
        $g = $Model.principals[$gid]
        if ($referenced.Contains($gid) -and -not $broad.Contains($gid) -and @(Get-FsTransitiveMembers -Model $Model -GroupId $gid -UsersOnly).Count -eq 0) { & $tag $gid 'empty-group' }
        if ((Get-FsGroupNestingDepth -Model $Model -GroupId $gid) -gt [int]$Options['NestingDepthThreshold']) { & $tag $gid 'nested-deep' }
        $mc = Get-FsValue $g 'memberCount'
        if ($null -ne $mc -and [int]$mc -ge [int]$Options['LargeGroupThreshold']) { & $tag $gid 'large-group' }
    }

    foreach ($srv in Get-FsSortedKeys $Model.servers) {
        if (Test-FsServerHasScanIssue -Model $Model -Server $srv) { & $tag $srv 'scan-error' }
    }

    $out = @{}
    foreach ($k in $tags.Keys) { $out[$k] = [string[]]@(Get-FsSorted -InputObject @($tags[$k])) }
    return $out
}

function Test-FsServerHasScanIssue {
    <# Errors, a partial status, or any truncated share walk. #>
    [OutputType([bool])]
    param([Parameter(Mandatory)] [System.Collections.IDictionary] $Model, [Parameter(Mandatory)] [string] $Server)
    $s = $Model.servers[$Server]
    if ($null -eq $s) { return $false }
    if ([int](Get-FsValue $s 'errorCount') -gt 0) { return $true }
    if ([bool](Get-FsValue $s 'status.partial')) { return $true }
    foreach ($sid in @(Get-FsValue $s 'shareIds')) {
        if ($Model.shares.Contains($sid) -and [bool](Get-FsValue $Model.shares[$sid] 'walk.truncated')) { return $true }
    }
    return $false
}
