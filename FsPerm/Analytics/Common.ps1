<#
Shared helpers for the analytics layer: memoization under $Model.cache, date coercion (JSON import yields
[datetime] for ISO strings, Merge-FsModel writes strings), ACE flattening and grant-point resolution.

Nothing in Analytics touches the filesystem or the clock; time comes from Options.Now.
#>

function Get-FsCacheTable {
    <# Returns (creating lazily) the named memo table under $Model.cache. #>
    [OutputType([hashtable])]
    param([Parameter(Mandatory)] [System.Collections.IDictionary] $Model, [Parameter(Mandatory)] [string] $Name)
    if (-not $Model.Contains('cache') -or $null -eq $Model['cache']) { $Model['cache'] = @{} }
    $cache = $Model['cache']
    if (-not $cache.Contains($Name)) { $cache[$Name] = @{} }
    return $cache[$Name]
}

function ConvertTo-FsUtcDateTime {
    <# Coerces an ISO string, DateTime or DateTimeOffset to a UTC DateTime; $null when absent or unparseable. #>
    [OutputType([System.Nullable[datetime]])]
    param([AllowNull()] $Value)
    if ($null -eq $Value) { return $null }
    if ($Value -is [datetime]) {
        if ($Value.Kind -eq [System.DateTimeKind]::Utc) { return $Value }
        if ($Value.Kind -eq [System.DateTimeKind]::Local) { return $Value.ToUniversalTime() }
        return [datetime]::SpecifyKind($Value, [System.DateTimeKind]::Utc)
    }
    if ($Value -is [datetimeoffset]) { return $Value.UtcDateTime }
    $text = [string]$Value
    if ([string]::IsNullOrWhiteSpace($text)) { return $null }
    $parsed = [datetimeoffset]::MinValue
    $styles = [System.Globalization.DateTimeStyles]::AssumeUniversal -bor [System.Globalization.DateTimeStyles]::AdjustToUniversal
    if ([datetimeoffset]::TryParse($text, [cultureinfo]::InvariantCulture, $styles, [ref]$parsed)) { return $parsed.UtcDateTime }
    return $null
}

function ConvertTo-FsIsoString {
    <# Round-trip ISO-8601 UTC text ('o'), or $null. #>
    [OutputType([string])]
    param([AllowNull()] $Value)
    $dt = ConvertTo-FsUtcDateTime $Value
    if ($null -eq $dt) { return $null }
    return $dt.ToString('o', [cultureinfo]::InvariantCulture)
}

function ConvertTo-FsDateText {
    <# yyyy-MM-dd for table cells; '' when absent. #>
    [OutputType([string])]
    param([AllowNull()] $Value)
    $dt = ConvertTo-FsUtcDateTime $Value
    if ($null -eq $dt) { return '' }
    return $dt.ToString('yyyy-MM-dd', [cultureinfo]::InvariantCulture)
}

function ConvertTo-FsDateTimeText {
    <# yyyy-MM-dd HH:mm UTC for table cells; '' when absent. #>
    [OutputType([string])]
    param([AllowNull()] $Value)
    $dt = ConvertTo-FsUtcDateTime $Value
    if ($null -eq $dt) { return '' }
    return $dt.ToString('yyyy-MM-dd HH:mm', [cultureinfo]::InvariantCulture) + ' UTC'
}

function Get-FsAgeDays {
    <# Whole days between a timestamp and -Now; $null when the timestamp is absent. #>
    [OutputType([System.Nullable[int]])]
    param([AllowNull()] $Value, [Parameter(Mandatory)] [datetime] $Now)
    $dt = ConvertTo-FsUtcDateTime $Value
    if ($null -eq $dt) { return $null }
    return [int][Math]::Floor(($Now.ToUniversalTime() - $dt).TotalDays)
}

function ConvertTo-FsYesNo {
    [OutputType([string])]
    param([AllowNull()] $Value)
    if ($null -eq $Value) { return '' }
    return $(if ([bool]$Value) { 'yes' } else { 'no' })
}

# ---------------------------------------------------------------- principals

function Get-FsPrincipalName {
    <# Sort/label text for a principal: ntAccount, else name, else id. #>
    [OutputType([string])]
    param([Parameter(Mandatory)] [System.Collections.IDictionary] $Model, [Parameter(Mandatory)] [string] $Id)
    $p = Get-FsModelPrincipal -Model $Model -Id $Id
    foreach ($k in 'ntAccount', 'name') {
        $v = Get-FsValue $p $k
        if ($v) { return [string]$v }
    }
    return $Id
}

function Get-FsPrincipalKind {
    [OutputType([string])]
    param([Parameter(Mandatory)] [System.Collections.IDictionary] $Model, [Parameter(Mandatory)] [string] $Id)
    $k = Get-FsValue (Get-FsModelPrincipal -Model $Model -Id $Id) 'kind'
    return $(if ($k) { [string]$k } else { 'OrphanedSid' })
}

function Test-FsUserPrincipal {
    [OutputType([bool])]
    param([Parameter(Mandatory)] [System.Collections.IDictionary] $Model, [Parameter(Mandatory)] [string] $Id)
    return (Test-FsUserKind -Kind (Get-FsPrincipalKind -Model $Model -Id $Id))
}

function Test-FsUnresolvedPrincipal {
    <# OrphanedSid / Foreign kinds or Orphaned / LookupFailed resolution. #>
    [OutputType([bool])]
    param([Parameter(Mandatory)] [System.Collections.IDictionary] $Model, [Parameter(Mandatory)] [string] $Id)
    $p = Get-FsModelPrincipal -Model $Model -Id $Id
    $kind = [string](Get-FsValue $p 'kind'); $res = [string](Get-FsValue $p 'resolution')
    return ($kind -in 'OrphanedSid', 'Foreign' -or $res -in 'Orphaned', 'LookupFailed' -or (Get-FsValue $p '_synthetic') -eq $true)
}

function Get-FsUserPrincipalIds {
    <# Sorted ids of every user-kind principal (User, LocalUser, Computer). #>
    [OutputType([string[]])]
    param([Parameter(Mandatory)] [System.Collections.IDictionary] $Model)
    $cache = Get-FsCacheTable -Model $Model -Name 'principalSets'
    if ($cache.Contains('users')) { return $cache['users'] }
    $ids = foreach ($id in Get-FsSortedKeys $Model.principals) {
        if (Test-FsUserKind -Kind ([string](Get-FsValue $Model.principals[$id] 'kind'))) { $id }
    }
    $cache['users'] = [string[]]@($ids)
    return $cache['users']
}

function Get-FsGroupPrincipalIds {
    <# Sorted ids of Group and LocalGroup principals (well-known pseudo-groups excluded). #>
    [OutputType([string[]])]
    param([Parameter(Mandatory)] [System.Collections.IDictionary] $Model)
    $cache = Get-FsCacheTable -Model $Model -Name 'principalSets'
    if ($cache.Contains('groups')) { return $cache['groups'] }
    $ids = foreach ($id in Get-FsSortedKeys $Model.principals) {
        if (([string](Get-FsValue $Model.principals[$id] 'kind')) -in 'Group', 'LocalGroup') { $id }
    }
    $cache['groups'] = [string[]]@($ids)
    return $cache['groups']
}

# ---------------------------------------------------------------- admin allowlist

function Get-FsAdminIdSet {
    <# HashSet of Options.AdminPrincipalIds (memoized on the options hashtable). #>
    [OutputType([System.Collections.Generic.HashSet[string]])]
    param([Parameter(Mandatory)] [System.Collections.IDictionary] $Options)
    # ,$x (not bare $x) throughout: PowerShell enumerates a returned collection onto the pipeline
    # as separate objects, so an EMPTY HashSet returned bare emits zero objects and the caller
    # captures $null instead of an empty set.
    if ($Options.Contains('_adminSet') -and $null -ne $Options['_adminSet']) { return , $Options['_adminSet'] }
    $set = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    $ids = if ($Options.Contains('AdminPrincipalIds') -and $null -ne $Options['AdminPrincipalIds']) { @($Options['AdminPrincipalIds']) } else { @($script:FsAdminSids) }
    foreach ($id in $ids) { if ($id) { [void]$set.Add([string]$id) } }
    $Options['_adminSet'] = $set
    return , $set
}

function Test-FsAdminPrincipal {
    <# True when the principal or any group it transitively belongs to is on the admin allowlist. #>
    [OutputType([bool])]
    param(
        [Parameter(Mandatory)] [System.Collections.IDictionary] $Model,
        [Parameter(Mandatory)] [System.Collections.IDictionary] $Options,
        [Parameter(Mandatory)] [string] $PrincipalId
    )
    $set = Get-FsAdminIdSet -Options $Options
    if ($set.Contains($PrincipalId)) { return $true }
    foreach ($g in @(Get-FsTransitiveGroups -Model $Model -PrincipalId $PrincipalId)) { if ($set.Contains($g)) { return $true } }
    return $false
}

# ---------------------------------------------------------------- resources and ACEs

function Get-FsResourceInfo {
    <# Flat facts about a share or folder id: id kind server path localPath shareId name isShareRoot record; $null when unknown. #>
    [OutputType([hashtable])]
    param([Parameter(Mandatory)] [System.Collections.IDictionary] $Model, [Parameter(Mandatory)] [string] $ResourceId)
    $r = Get-FsResource -Model $Model -Id $ResourceId
    if ($null -eq $r) { return $null }
    $rec = $r.record
    if ($r.kind -eq 'Share') {
        return @{ id = $ResourceId; kind = 'Share'; server = [string](Get-FsValue $rec 'server'); path = [string](Get-FsValue $rec 'uncPath'); localPath = [string](Get-FsValue $rec 'localPath'); shareId = $ResourceId; name = [string](Get-FsValue $rec 'name'); isShareRoot = $true; record = $rec }
    }
    $rel = [string](Get-FsValue $rec 'relativePath')
    return @{ id = $ResourceId; kind = 'Folder'; server = [string](Get-FsValue $rec 'server'); path = [string](Get-FsValue $rec 'uncPath'); localPath = [string](Get-FsValue $rec 'localPath'); shareId = [string](Get-FsValue $rec 'primaryShareId'); name = $(if ($rel) { $rel } else { [string](Get-FsValue $rec 'localPath') }); isShareRoot = [bool](Get-FsValue $rec 'isShareRoot'); record = $rec }
}

function Get-FsGrantPointRefId {
    <# Share-root folders have no note of their own: refs (and grant points) use the share id instead. #>
    [OutputType([string])]
    param([Parameter(Mandatory)] [System.Collections.IDictionary] $Model, [Parameter(Mandatory)] [string] $ResourceId)
    if ($Model.folders.Contains($ResourceId)) {
        $f = $Model.folders[$ResourceId]
        $share = [string](Get-FsValue $f 'primaryShareId')
        if ([bool](Get-FsValue $f 'isShareRoot') -and $share) { return $share }
    }
    return $ResourceId
}

function Get-FsGrantPointIds {
    <# Share ids plus non-root divergent folder ids, ordered by server then UNC path. #>
    [OutputType([string[]])]
    param([Parameter(Mandatory)] [System.Collections.IDictionary] $Model)
    $cache = Get-FsCacheTable -Model $Model -Name 'grantPoints'
    if ($cache.Contains('ids')) { return $cache['ids'] }
    $items = [System.Collections.Generic.List[object]]::new()
    foreach ($sid in Get-FsSortedKeys $Model.shares) {
        $s = $Model.shares[$sid]
        $items.Add(@{ id = $sid; server = [string](Get-FsValue $s 'server'); path = [string](Get-FsValue $s 'uncPath'); order = 0 })
    }
    foreach ($fid in Get-FsSortedKeys $Model.folders) {
        $f = $Model.folders[$fid]
        if ([bool](Get-FsValue $f 'isShareRoot')) { continue }
        $items.Add(@{ id = $fid; server = [string](Get-FsValue $f 'server'); path = [string](Get-FsValue $f 'uncPath'); order = 1 })
    }
    $sorted = @(Get-FsSorted -InputObject @($items) -Property 'server', 'path', 'order', 'id')
    $cache['ids'] = [string[]]@($sorted | ForEach-Object { $_.id })
    return $cache['ids']
}

function Get-FsAceMask {
    <# Normalized access mask of an NTFS (rightsMask) or share (accessMask) ACE. #>
    [OutputType([long])]
    param([Parameter(Mandatory)] $Ace)
    $m = Get-FsValue $Ace 'rightsMask'
    if ($null -eq $m) { $m = Get-FsValue $Ace 'accessMask' }
    if ($null -eq $m) { return [long]0 }
    return (ConvertTo-FsNormalizedMask -Mask ([long]$m))
}

function Get-FsAceRightsText {
    [OutputType([string])]
    param([Parameter(Mandatory)] $Ace)
    $t = Get-FsValue $Ace 'rights'
    if (-not $t) { $t = Get-FsValue $Ace 'accessRight' }
    if (-not $t) { $t = ConvertTo-FsRightsString -Mask (Get-FsAceMask $Ace) }
    return [string]$t
}

function Get-FsAceEntries {
    <#
    .SYNOPSIS
        Every ACE in the model, flattened. Cached.
    .OUTPUTS
        hashtables: resourceId refId resourceKind server path shareId layer(Share|NTFS) index principalId type(Allow|Deny)
                    isInherited isInheritOnly mask level rights appliesTo ace
        Ordered by server, path, layer (Share before NTFS), index.
    #>
    [OutputType([object[]])]
    param([Parameter(Mandatory)] [System.Collections.IDictionary] $Model)
    $cache = Get-FsCacheTable -Model $Model -Name 'aceEntries'
    if ($cache.Contains('all')) { return $cache['all'] }
    $items = [System.Collections.Generic.List[object]]::new()
    $add = {
        param($info, $layer, $ace, $index)
        $mask = Get-FsAceMask $ace
        $items.Add(@{
                resourceId    = $info.id
                refId         = (Get-FsGrantPointRefId -Model $Model -ResourceId $info.id)
                resourceKind  = $info.kind
                server        = $info.server
                path          = $info.path
                shareId       = $info.shareId
                layer         = $layer
                layerOrder    = $(if ($layer -eq 'Share') { 0 } else { 1 })
                index         = $index
                principalId   = [string](Get-FsValue $ace 'principalId')
                type          = [string](Get-FsValue $ace 'accessControlType')
                isInherited   = [bool](Get-FsValue $ace 'isInherited')
                isInheritOnly = (Test-FsAceInheritOnly -PropagationFlags ([string](Get-FsValue $ace 'propagationFlags')))
                mask          = $mask
                level         = (Get-FsMaskLevel -Mask $mask)
                rights        = (Get-FsAceRightsText $ace)
                appliesTo     = [string](Get-FsValue $ace 'appliesTo')
                ace           = $ace
            })
    }
    foreach ($sid in Get-FsSortedKeys $Model.shares) {
        $info = Get-FsResourceInfo -Model $Model -ResourceId $sid
        $i = 0
        foreach ($ace in @($Model.shares[$sid]['aces'])) { & $add $info 'Share' $ace $i; $i++ }
    }
    foreach ($fid in Get-FsSortedKeys $Model.folders) {
        $info = Get-FsResourceInfo -Model $Model -ResourceId $fid
        $i = 0
        foreach ($ace in @($Model.folders[$fid]['aces'])) {
            $idx = Get-FsValue $ace 'index'
            if ($null -eq $idx) { $idx = $i }
            & $add $info 'NTFS' $ace ([int]$idx)
            $i++
        }
    }
    $cache['all'] = @(Get-FsSorted -InputObject @($items) -Property 'server', 'path', 'layerOrder', 'index', 'principalId')
    return $cache['all']
}

function Get-FsAceEntriesByResource {
    <# resourceId -> ACE entries (see Get-FsAceEntries). Cached. #>
    [OutputType([hashtable])]
    param([Parameter(Mandatory)] [System.Collections.IDictionary] $Model)
    $cache = Get-FsCacheTable -Model $Model -Name 'aceEntries'
    if ($cache.Contains('byResource')) { return $cache['byResource'] }
    $table = @{}
    foreach ($e in @(Get-FsAceEntries -Model $Model)) {
        if (-not $table.Contains($e.resourceId)) { $table[$e.resourceId] = [System.Collections.Generic.List[object]]::new() }
        $table[$e.resourceId].Add($e)
    }
    $cache['byResource'] = $table
    return $table
}

function Get-FsSeverityRank {
    [OutputType([int])]
    param([AllowNull()] [string] $Severity)
    switch ($Severity) { 'high' { return 0 } 'medium' { return 1 } 'low' { return 2 } default { return 3 } }
}
