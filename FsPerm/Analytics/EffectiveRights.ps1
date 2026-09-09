<#
Effective rights.

A principal's pseudo-token is itself + its transitive groups + {Everyone, Authenticated Users, NETWORK} for
account kinds. The effective NTFS mask is a per-bit first-match walk over the ACL in canonical order:
explicit Deny, explicit Allow, inherited Deny, inherited Allow (InheritOnly ACEs never apply to the folder
itself). A bit already allowed cannot be denied later and vice versa, so an explicit Allow beats an inherited
Deny. Share ACLs go through the same function; effective level = min(share level, NTFS level).

Caveats (repeated in every report footer): no claims/DAC, owner rights or backup privilege; only captured
folders; snapshots of different servers may be days apart.
#>

$script:FsImplicitTokenSids = @('S-1-1-0', 'S-1-5-11', 'S-1-5-2')   # Everyone, Authenticated Users, NETWORK

function Get-FsToken {
    <# HashSet of ids the principal's access token would carry (self, transitive groups, implicit well-known SIDs for account kinds). Cached. #>
    [OutputType([System.Collections.Generic.HashSet[string]])]
    param([Parameter(Mandatory)] [System.Collections.IDictionary] $Model, [Parameter(Mandatory)] [string] $PrincipalId)
    # ,$x (not bare $x) throughout this function: PowerShell enumerates a returned collection onto
    # the pipeline as separate objects, so even a ONE-element HashSet unrolls to its bare element on
    # return - the caller's $token.Contains(id) would silently become String.Contains(substring)
    # instead of exact set membership. An empty set would unroll to $null instead.
    $cache = Get-FsCacheTable -Model $Model -Name 'tokens'
    if ($cache.Contains($PrincipalId)) { return , $cache[$PrincipalId] }
    $token = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    [void]$token.Add($PrincipalId)
    foreach ($g in @(Get-FsTransitiveGroups -Model $Model -PrincipalId $PrincipalId)) { [void]$token.Add($g) }
    $kind = Get-FsPrincipalKind -Model $Model -Id $PrincipalId
    if ($kind -in 'User', 'Computer', 'Group', 'LocalGroup', 'LocalUser') {
        foreach ($sid in $script:FsImplicitTokenSids) { [void]$token.Add($sid) }
    }
    $cache[$PrincipalId] = $token
    return , $token
}

function ConvertTo-FsTokenSet {
    <# Accepts a HashSet or any string collection. #>
    [OutputType([System.Collections.Generic.HashSet[string]])]
    param([AllowNull()] $Token)
    # ,$x (not bare $x): see Get-FsToken above - a bare return unrolls the HashSet's contents onto
    # the pipeline (to $null when empty, to a bare scalar when it has exactly one element).
    if ($Token -is [System.Collections.Generic.HashSet[string]]) { return , $Token }
    $set = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    foreach ($t in @($Token)) { if ($null -ne $t) { [void]$set.Add([string]$t) } }
    return , $set
}

function New-FsAceBuckets {
    <#
    Pre-sorts an ACE list into the four canonical buckets. Each entry is @{ p = principalId; m = normalized mask; level; layer }.
    InheritOnly ACEs are dropped. Share ACEs (no isInherited) count as explicit.
    #>
    [OutputType([hashtable])]
    param([AllowNull()] [object[]] $Aces, [string] $Layer = 'NTFS')
    $b = @{
        explicitDeny   = [System.Collections.Generic.List[object]]::new()
        explicitAllow  = [System.Collections.Generic.List[object]]::new()
        inheritedDeny  = [System.Collections.Generic.List[object]]::new()
        inheritedAllow = [System.Collections.Generic.List[object]]::new()
        allows         = [System.Collections.Generic.List[object]]::new()   # explicit + inherited, for candidate discovery
        denyIds        = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
        layer          = $Layer
    }
    foreach ($ace in @($Aces)) {
        if ($null -eq $ace) { continue }
        if (Test-FsAceInheritOnly -PropagationFlags ([string](Get-FsValue $ace 'propagationFlags'))) { continue }
        $mask = Get-FsAceMask $ace
        $entry = @{ p = [string](Get-FsValue $ace 'principalId'); m = $mask; level = (Get-FsMaskLevel -Mask $mask); layer = $Layer; inherited = [bool](Get-FsValue $ace 'isInherited') }
        $deny = ([string](Get-FsValue $ace 'accessControlType')) -eq 'Deny'
        if ($deny) {
            [void]$b.denyIds.Add($entry.p)
            if ($entry.inherited) { $b.inheritedDeny.Add($entry) } else { $b.explicitDeny.Add($entry) }
        }
        else {
            $b.allows.Add($entry)
            if ($entry.inherited) { $b.inheritedAllow.Add($entry) } else { $b.explicitAllow.Add($entry) }
        }
    }
    return $b
}

function Get-FsBucketMask {
    <# Per-bit first-match evaluation over pre-bucketed ACEs. #>
    [OutputType([long])]
    param([Parameter(Mandatory)] [hashtable] $Buckets, [Parameter(Mandatory)] [AllowEmptyCollection()] [System.Collections.Generic.HashSet[string]] $Token)
    [long]$allowed = 0; [long]$denied = 0
    foreach ($e in $Buckets.explicitDeny) { if ($Token.Contains($e.p)) { $denied = $denied -bor ($e.m -band (-bnot $allowed)) } }
    foreach ($e in $Buckets.explicitAllow) { if ($Token.Contains($e.p)) { $allowed = $allowed -bor ($e.m -band (-bnot $denied)) } }
    foreach ($e in $Buckets.inheritedDeny) { if ($Token.Contains($e.p)) { $denied = $denied -bor ($e.m -band (-bnot $allowed)) } }
    foreach ($e in $Buckets.inheritedAllow) { if ($Token.Contains($e.p)) { $allowed = $allowed -bor ($e.m -band (-bnot $denied)) } }
    return [long]($allowed -band $script:FsMask32)
}

function Test-FsBucketDeny {
    [OutputType([bool])]
    param([Parameter(Mandatory)] [hashtable] $Buckets, [Parameter(Mandatory)] [AllowEmptyCollection()] [System.Collections.Generic.HashSet[string]] $Token)
    foreach ($id in $Buckets.denyIds) { if ($Token.Contains($id)) { return $true } }
    return $false
}

function Get-FsEffectiveMask {
    <#
    .SYNOPSIS
        Effective access mask for a token over an ACE list (NTFS or share ACEs).
    .DESCRIPTION
        Order: explicit Deny, explicit Allow, inherited Deny, inherited Allow; InheritOnly ACEs are skipped.
        denied |= m & ~allowed ; allowed |= m & ~denied.
    #>
    [OutputType([long])]
    param([AllowNull()] [object[]] $Aces, [AllowNull()] $Token)
    $buckets = New-FsAceBuckets -Aces $Aces
    return (Get-FsBucketMask -Buckets $buckets -Token (ConvertTo-FsTokenSet $Token))
}

function Get-FsResourceEvaluation {
    <#
    Everything needed to evaluate any token against a resource, precomputed once and cached:
      @{ id kind refId server path shareId shareBuckets ntfsBuckets }
    Folder: share ACL from its primary share; Share: NTFS from its root folder. A missing layer is $null (= no cap).
    #>
    [OutputType([hashtable])]
    param([Parameter(Mandatory)] [System.Collections.IDictionary] $Model, [Parameter(Mandatory)] [string] $ResourceId)
    $cache = Get-FsCacheTable -Model $Model -Name 'resourceEval'
    if ($cache.Contains($ResourceId)) { return $cache[$ResourceId] }
    $info = Get-FsResourceInfo -Model $Model -ResourceId $ResourceId
    if ($null -eq $info) { $cache[$ResourceId] = $null; return $null }
    $shareAces = $null; $ntfsAces = $null; $shareId = $info.shareId
    if ($info.kind -eq 'Share') {
        $shareAces = @($info.record['aces'])
        $rootId = [string](Get-FsValue $info.record 'rootFolderId')
        if ($rootId -and $Model.folders.Contains($rootId)) { $ntfsAces = @($Model.folders[$rootId]['aces']) }
    }
    else {
        $ntfsAces = @($info.record['aces'])
        if ($shareId -and $Model.shares.Contains($shareId)) { $shareAces = @($Model.shares[$shareId]['aces']) } else { $shareId = $null }
    }
    $ev = @{
        id           = $ResourceId
        kind         = $info.kind
        refId        = (Get-FsGrantPointRefId -Model $Model -ResourceId $ResourceId)
        server       = $info.server
        path         = $info.path
        shareId      = $shareId
        shareBuckets = $(if ($null -ne $shareAces) { New-FsAceBuckets -Aces $shareAces -Layer 'Share' } else { $null })
        ntfsBuckets  = $(if ($null -ne $ntfsAces) { New-FsAceBuckets -Aces $ntfsAces -Layer 'NTFS' } else { $null })
    }
    $cache[$ResourceId] = $ev
    return $ev
}

function Resolve-FsEffectiveLevel {
    <# Evaluates a token against a precomputed resource evaluation. #>
    [OutputType([hashtable])]
    param([Parameter(Mandatory)] [hashtable] $Evaluation, [Parameter(Mandatory)] [AllowEmptyCollection()] [System.Collections.Generic.HashSet[string]] $Token)
    $hasDeny = $false
    if ($null -ne $Evaluation.shareBuckets) {
        $shareLevel = Get-FsMaskLevel -Mask (Get-FsBucketMask -Buckets $Evaluation.shareBuckets -Token $Token)
        if (Test-FsBucketDeny -Buckets $Evaluation.shareBuckets -Token $Token) { $hasDeny = $true }
    }
    else { $shareLevel = 'Full' }
    if ($null -ne $Evaluation.ntfsBuckets) {
        $ntfsLevel = Get-FsMaskLevel -Mask (Get-FsBucketMask -Buckets $Evaluation.ntfsBuckets -Token $Token)
        if (Test-FsBucketDeny -Buckets $Evaluation.ntfsBuckets -Token $Token) { $hasDeny = $true }
    }
    else { $ntfsLevel = 'Full' }
    return @{ level = (Get-FsMinLevel -A $shareLevel -B $ntfsLevel); shareLevel = $shareLevel; ntfsLevel = $ntfsLevel; shareId = $Evaluation.shareId; hasDeny = $hasDeny }
}

function Get-FsEffectiveLevel {
    <#
    .SYNOPSIS
        Effective level of a principal on a share or folder: @{ level; shareLevel; ntfsLevel; shareId; hasDeny }.
    #>
    [OutputType([hashtable])]
    param(
        [Parameter(Mandatory)] [System.Collections.IDictionary] $Model,
        [Parameter(Mandatory)] [string] $PrincipalId,
        [Parameter(Mandatory)] [string] $ResourceId
    )
    $cache = Get-FsCacheTable -Model $Model -Name 'effectiveLevel'
    $key = "$PrincipalId|$ResourceId"
    if ($cache.Contains($key)) { return $cache[$key] }
    $ev = Get-FsResourceEvaluation -Model $Model -ResourceId $ResourceId
    if ($null -eq $ev) { $result = @{ level = 'None'; shareLevel = 'None'; ntfsLevel = 'None'; shareId = $null; hasDeny = $false } }
    else { $result = Resolve-FsEffectiveLevel -Evaluation $ev -Token (Get-FsToken -Model $Model -PrincipalId $PrincipalId) }
    $cache[$key] = $result
    return $result
}

function Select-FsBestVia {
    <#
    Picks the chain to report for a set of matched ACE principals: non-broad first, then highest granted level,
    then shortest chain, then ordinal id. Returns @{ via = string[] (group ids after the principal; @() = direct); acePrincipalId; layer }.
    -Matches: entries @{ p; level; layer }.
    #>
    [OutputType([hashtable])]
    param(
        [Parameter(Mandatory)] [System.Collections.IDictionary] $Model,
        [Parameter(Mandatory)] [string] $PrincipalId,
        [Parameter(Mandatory)] [AllowEmptyCollection()] [object[]] $Matches
    )
    $broad = Get-FsBroadPrincipalSet -Model $Model
    $best = $null; $bestKey = $null
    $layers = [System.Collections.Generic.HashSet[string]]::new()
    foreach ($m in $Matches) {
        [void]$layers.Add([string]$m.layer)
        $chain = @(Get-FsGroupChain -Model $Model -PrincipalId $PrincipalId -GroupId $m.p)
        if ($chain.Count -eq 0) { continue }   # principal not related to this ACE principal (implicit SIDs are handled below)
        $via = if ($chain.Count -gt 1) { [string[]]@($chain[1..($chain.Count - 1)]) } else { [string[]]@() }
        $key = @($(if ($broad.Contains($m.p)) { 1 } else { 0 }), (-(Get-FsLevelOrdinal $m.level)), $via.Count, $m.p)
        if ($null -eq $best -or (Compare-FsKeyArray $key $bestKey) -lt 0) { $best = @{ via = $via; acePrincipalId = $m.p; level = $m.level }; $bestKey = $key }
    }
    if ($null -eq $best) {
        # only implicit token members (Everyone / Authenticated Users / NETWORK) matched
        foreach ($m in $Matches) {
            $key = @(1, (-(Get-FsLevelOrdinal $m.level)), 1, $m.p)
            if ($null -eq $best -or (Compare-FsKeyArray $key $bestKey) -lt 0) { $best = @{ via = [string[]]@($m.p); acePrincipalId = $m.p; level = $m.level }; $bestKey = $key }
        }
    }
    if ($null -eq $best) { $best = @{ via = [string[]]@(); acePrincipalId = $null; level = 'None' } }
    $layerList = @(Get-FsSorted -InputObject @($layers))
    $best['layer'] = $(if ($layerList.Count -gt 1) { 'Share+NTFS' } elseif ($layerList.Count -eq 1) { [string]$layerList[0] } else { '' })
    return $best
}

function Compare-FsKeyArray {
    <# Lexicographic comparison of two key arrays using Compare-FsValue. #>
    [OutputType([int])]
    param([Parameter(Mandatory)] [AllowEmptyCollection()] [object[]] $A, [Parameter(Mandatory)] [AllowEmptyCollection()] [object[]] $B)
    for ($i = 0; $i -lt [Math]::Max($A.Count, $B.Count); $i++) {
        $va = if ($i -lt $A.Count) { $A[$i] } else { $null }
        $vb = if ($i -lt $B.Count) { $B[$i] } else { $null }
        $r = Compare-FsValue $va $vb
        if ($r -ne 0) { return $r }
    }
    return 0
}

function Get-FsEffectiveAccess {
    <#
    .SYNOPSIS
        Every grant point (share or divergent folder) where the principal's token matches an Allow ACE and the effective level is above None.
    .OUTPUTS
        rows @{ resourceId resourceKind server path level shareLevel ntfsLevel via(string[]) layer hasDeny acePrincipalId broadOnly }
        sorted by server, resourceId. Share-root folder matches fold into the Share row.
    .PARAMETER ExcludeBroad
        Drop rows whose only matching ACE principals are broad (Everyone, Authenticated Users, Domain Users, groups containing them, ...).
    #>
    [OutputType([object[]])]
    param(
        [Parameter(Mandatory)] [System.Collections.IDictionary] $Model,
        [Parameter(Mandatory)] [string] $PrincipalId,
        [switch] $ExcludeBroad
    )
    $cache = Get-FsCacheTable -Model $Model -Name 'effectiveAccess'
    $key = "$PrincipalId|$([bool]$ExcludeBroad)"
    if ($cache.Contains($key)) { return $cache[$key] }
    $token = Get-FsToken -Model $Model -PrincipalId $PrincipalId
    $broad = Get-FsBroadPrincipalSet -Model $Model
    $acesByPrincipal = $Model.index.acesByPrincipal
    $byPoint = @{}
    foreach ($id in $token) {
        if (-not $acesByPrincipal.Contains($id)) { continue }
        foreach ($entry in @($acesByPrincipal[$id])) {
            $ace = $entry.ace
            if (([string](Get-FsValue $ace 'accessControlType')) -ne 'Allow') { continue }
            if (Test-FsAceInheritOnly -PropagationFlags ([string](Get-FsValue $ace 'propagationFlags'))) { continue }
            $gp = Get-FsGrantPointRefId -Model $Model -ResourceId ([string]$entry.resourceId)
            if (-not $byPoint.Contains($gp)) { $byPoint[$gp] = [System.Collections.Generic.List[object]]::new() }
            $byPoint[$gp].Add(@{ p = $id; level = (Get-FsMaskLevel -Mask (Get-FsAceMask $ace)); layer = [string]$entry.layer })
        }
    }
    $rows = [System.Collections.Generic.List[object]]::new()
    foreach ($gp in Get-FsSortedKeys $byPoint) {
        $matches = @($byPoint[$gp])
        $specific = $false
        foreach ($m in $matches) { if (-not $broad.Contains($m.p)) { $specific = $true; break } }
        if ($ExcludeBroad -and -not $specific) { continue }
        $eff = Get-FsEffectiveLevel -Model $Model -PrincipalId $PrincipalId -ResourceId $gp
        if ($eff.level -eq 'None') { continue }
        $ev = Get-FsResourceEvaluation -Model $Model -ResourceId $gp
        $via = Select-FsBestVia -Model $Model -PrincipalId $PrincipalId -Matches $matches
        $rows.Add(@{
                resourceId     = $gp
                resourceKind   = $ev.kind
                server         = $ev.server
                path           = $ev.path
                level          = $eff.level
                shareLevel     = $eff.shareLevel
                ntfsLevel      = $eff.ntfsLevel
                hasDeny        = $eff.hasDeny
                via            = [string[]]$via.via
                acePrincipalId = $via.acePrincipalId
                layer          = $via.layer
                broadOnly      = (-not $specific)
            })
    }
    $cache[$key] = @(Get-FsSorted -InputObject @($rows) -Property 'server', 'resourceId')
    return $cache[$key]
}

function Get-FsResourceReachers {
    <#
    .SYNOPSIS
        One row per distinct principal named in the resource's ACL and its share ACL, evaluated with that principal's own token.
    .OUTPUTS
        rows @{ principalId name kind isBroad shareLevel ntfsLevel effectiveLevel hasDeny via userCount layers } sorted by name.
        userCount = transitive user members (1 for a user principal, 0 for broad principals, which are not expanded).
    #>
    [OutputType([object[]])]
    param([Parameter(Mandatory)] [System.Collections.IDictionary] $Model, [Parameter(Mandatory)] [string] $ResourceId)
    $cache = Get-FsCacheTable -Model $Model -Name 'reachers'
    if ($cache.Contains($ResourceId)) { return $cache[$ResourceId] }
    $ev = Get-FsResourceEvaluation -Model $Model -ResourceId $ResourceId
    if ($null -eq $ev) { $cache[$ResourceId] = @(); return @() }
    $broad = Get-FsBroadPrincipalSet -Model $Model
    $ids = @{}
    foreach ($layer in 'shareBuckets', 'ntfsBuckets') {
        $b = $ev[$layer]
        if ($null -eq $b) { continue }
        foreach ($bucket in 'explicitDeny', 'explicitAllow', 'inheritedDeny', 'inheritedAllow') {
            foreach ($e in $b[$bucket]) {
                if (-not $ids.Contains($e.p)) { $ids[$e.p] = [System.Collections.Generic.HashSet[string]]::new() }
                [void]$ids[$e.p].Add($b.layer)
            }
        }
    }
    $rows = [System.Collections.Generic.List[object]]::new()
    foreach ($id in Get-FsSortedKeys $ids) {
        $eff = Get-FsEffectiveLevel -Model $Model -PrincipalId $id -ResourceId $ResourceId
        $kind = Get-FsPrincipalKind -Model $Model -Id $id
        $isBroad = $broad.Contains($id)
        $userCount = 0
        if (-not $isBroad) {
            if (Test-FsUserKind -Kind $kind) { $userCount = 1 }
            elseif (Test-FsGroupKind -Kind $kind) { $userCount = @(Get-FsTransitiveMembers -Model $Model -GroupId $id -UsersOnly).Count }
        }
        $layers = @(Get-FsSorted -InputObject @($ids[$id]))
        $rows.Add(@{
                principalId    = $id
                name           = (Get-FsPrincipalName -Model $Model -Id $id)
                kind           = $kind
                isBroad        = $isBroad
                shareLevel     = $eff.shareLevel
                ntfsLevel      = $eff.ntfsLevel
                effectiveLevel = $eff.level
                hasDeny        = $eff.hasDeny
                via            = [string[]]@()
                userCount      = $userCount
                layers         = $(if ($layers.Count -gt 1) { 'Share+NTFS' } else { [string]$layers[0] })
            })
    }
    $cache[$ResourceId] = @(Get-FsSorted -InputObject @($rows) -Property 'name', 'principalId')
    return $cache[$ResourceId]
}
