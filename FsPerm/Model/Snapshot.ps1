<#
Snapshot schema v1.0, factories, gzip import/export, snapshot index and the merged model.

A snapshot is one scan of one server. The collector builds it from the factories below and
Export-FsSnapshot writes it. Everything downstream (analytics, renderer) works only on the
hashtables returned by Import-FsSnapshot / Merge-FsModel, never on live collector objects.

Ids:
  share     "FS01\Finance"
  folder    "FS01:D:\Shares\Finance\Budgets"          (server-scoped local path)
  principal SID, or "SERVER\Name" for server-local accounts (see Principal.ps1)
#>

$script:FsSnapshotSchemaVersion = '1.0'

# ---------------------------------------------------------------- factories

function New-FsSnapshot {
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)] [string] $ServerName,
        [string] $Fqdn,
        [string] $MachineSid,
        [System.Nullable[int]] $DomainRole,
        [string] $OsVersion,
        [string] $RemotePsVersion,
        [string] $DomainName,
        [string] $DomainSid,
        [string] $CredentialUser,
        [int] $Depth = 1,
        [hashtable] $Scope,
        [string] $ScanId = ([guid]::NewGuid().ToString()),
        [datetime] $Timestamp = (Get-Date),
        [string] $ToolVersion = $script:FsPermVersion
    )
    $scopeDefaults = [ordered]@{ depth = $Depth; includeShare = @(); excludeShare = @(); includeHiddenShares = $false; maxFoldersPerShare = 100000; dryRun = $false; groupExpansion = $true; maxGroupDepth = 10 }
    if ($Scope) { foreach ($k in $Scope.Keys) { $scopeDefaults[$k] = $Scope[$k] } }
    [pscustomobject][ordered]@{
        PSTypeName     = 'Fs.Snapshot'
        schemaVersion  = $script:FsSnapshotSchemaVersion
        scanId         = $ScanId
        toolVersion    = $ToolVersion
        timestamp      = $Timestamp.ToUniversalTime().ToString('o')
        completedAt    = $null
        durationSeconds = $null
        server         = [ordered]@{ name = $ServerName.ToUpperInvariant(); fqdn = $Fqdn; machineSid = $MachineSid; domainRole = $DomainRole; osVersion = $OsVersion; remotePsVersion = $RemotePsVersion; scannedFrom = $env:COMPUTERNAME }
        domain         = [ordered]@{ name = $DomainName; sid = $DomainSid }
        credentialUser = $CredentialUser
        scope          = $scopeDefaults
        status         = [ordered]@{ partial = $false; phases = [ordered]@{} }
        stats          = [ordered]@{}
        shares         = [System.Collections.Generic.List[object]]::new()
        folders        = [System.Collections.Generic.List[object]]::new()
        principals     = [ordered]@{}
        memberships    = [System.Collections.Generic.List[object]]::new()
        errors         = [System.Collections.Generic.List[object]]::new()
    }
}

function Get-FsShareId {
    [OutputType([string])]
    param([Parameter(Mandatory)] [string] $Server, [Parameter(Mandatory)] [string] $ShareName)
    return "$($Server.ToUpperInvariant())\$ShareName"
}

function Get-FsFolderId {
    [OutputType([string])]
    param([Parameter(Mandatory)] [string] $Server, [Parameter(Mandatory)] [string] $LocalPath)
    return "$($Server.ToUpperInvariant()):$($LocalPath.TrimEnd('\'))"
}

function New-FsShare {
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)] [string] $Server,
        [Parameter(Mandatory)] [string] $Name,
        [Parameter(Mandatory)] [string] $LocalPath,
        [string] $Description,
        [bool] $IsHidden = $false,
        [object[]] $Aces = @()
    )
    $srv = $Server.ToUpperInvariant()
    [pscustomobject][ordered]@{
        PSTypeName   = 'Fs.Share'
        id           = Get-FsShareId -Server $srv -ShareName $Name
        name         = $Name
        server       = $srv
        localPath    = $LocalPath.TrimEnd('\')
        uncPath      = Join-FsUnc -Server $srv -Share $Name
        description  = $Description
        isHidden     = $IsHidden
        rootFolderId = Get-FsFolderId -Server $srv -LocalPath $LocalPath
        aces         = [System.Collections.Generic.List[object]]::new([object[]]$Aces)
        walk         = [ordered]@{ foldersVisited = 0; foldersReturned = 0; truncated = $false; maxDepthReached = 0; seconds = 0.0; status = 'Pending' }
    }
}

function New-FsShareAce {
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)] [string] $PrincipalId,
        [Parameter(Mandatory)] [string] $Sid,
        [Parameter(Mandatory)] [long] $AccessMask,
        [Parameter(Mandatory)] [ValidateSet('Allow', 'Deny')] [string] $AccessControlType,
        [string] $NameOnServer
    )
    [pscustomobject][ordered]@{
        PSTypeName        = 'Fs.ShareAce'
        principalId       = $PrincipalId
        sid               = $Sid
        nameOnServer      = $NameOnServer
        accessRight       = Get-FsShareRightName -AccessMask $AccessMask
        accessMask        = [long]($AccessMask -band $script:FsMask32)
        accessControlType = $AccessControlType
    }
}

function New-FsFolder {
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)] [string] $Server,
        [Parameter(Mandatory)] [string] $LocalPath,
        [Parameter(Mandatory)] [string[]] $ShareNames,
        [Parameter(Mandatory)] [string] $ShareLocalPath,
        [int] $Depth = 0,
        [AllowNull()] [string] $ParentLocalPath,
        [AllowNull()] [string] $NearestDivergentAncestorLocalPath,
        [bool] $IsProtected = $false,
        [AllowNull()] [string] $OwnerPrincipalId,
        [int] $ChildFolderCount = 0,
        [int] $ReparsePointsSkipped = 0,
        [object[]] $Aces = @(),
        [AllowNull()] [string] $Error
    )
    $srv = $Server.ToUpperInvariant()
    $sortedShares = @(Get-FsSorted -InputObject $ShareNames)
    $primaryShare = $sortedShares[0]
    $rel = Get-FsRelativePath -Root $ShareLocalPath -Child $LocalPath
    if ($null -eq $rel) { $rel = Get-FsPathLeaf $LocalPath }
    [pscustomobject][ordered]@{
        PSTypeName                 = 'Fs.Folder'
        id                         = Get-FsFolderId -Server $srv -LocalPath $LocalPath
        server                     = $srv
        localPath                  = $LocalPath.TrimEnd('\')
        shareNames                 = $sortedShares
        primaryShareId             = Get-FsShareId -Server $srv -ShareName $primaryShare
        uncPath                    = Join-FsUnc -Server $srv -Share $primaryShare -Relative $rel
        relativePath               = $rel
        depth                      = $Depth
        parentId                   = $(if ($ParentLocalPath) { Get-FsFolderId -Server $srv -LocalPath $ParentLocalPath } else { $null })
        nearestDivergentAncestorId = $(if ($NearestDivergentAncestorLocalPath) { Get-FsFolderId -Server $srv -LocalPath $NearestDivergentAncestorLocalPath } else { $null })
        isShareRoot                = ($rel -eq '')
        isProtected                = $IsProtected
        ownerPrincipalId           = $OwnerPrincipalId
        childFolderCount           = $ChildFolderCount
        reparsePointsSkipped       = $ReparsePointsSkipped
        explicitAceCount           = @($Aces | Where-Object { -not (Get-FsValue $_ 'isInherited') }).Count
        aces                       = [System.Collections.Generic.List[object]]::new([object[]]$Aces)
        error                      = $Error
    }
}

function New-FsAce {
    <# NTFS ACE. Rights are stored as both the display string and the raw mask. #>
    [OutputType([pscustomobject])]
    param(
        [int] $Index = 0,
        [Parameter(Mandatory)] [string] $PrincipalId,
        [Parameter(Mandatory)] [string] $Sid,
        [Parameter(Mandatory)] [long] $RightsMask,
        [AllowNull()] [string] $Rights,
        [Parameter(Mandatory)] [ValidateSet('Allow', 'Deny')] [string] $AccessControlType,
        [bool] $IsInherited = $false,
        [string] $InheritanceFlags = 'None',
        [string] $PropagationFlags = 'None',
        [string] $NameOnServer
    )
    $mask = [long]($RightsMask -band $script:FsMask32)
    [pscustomobject][ordered]@{
        PSTypeName        = 'Fs.Ace'
        index             = $Index
        principalId       = $PrincipalId
        sid               = $Sid
        nameOnServer      = $NameOnServer
        rights            = $(if ($Rights) { $Rights } else { ConvertTo-FsRightsString -Mask $mask })
        rightsMask        = $mask
        simpleRights      = Get-FsMaskLevel -Mask $mask
        accessControlType = $AccessControlType
        isInherited       = $IsInherited
        inheritanceFlags  = $InheritanceFlags
        propagationFlags  = $PropagationFlags
        appliesTo         = ConvertTo-FsAppliesTo -InheritanceFlags $InheritanceFlags -PropagationFlags $PropagationFlags
    }
}

function New-FsMembership {
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)] [string] $GroupId,
        [Parameter(Mandatory)] [string] $MemberId,
        [ValidateSet('Direct', 'PrimaryGroup', 'LocalDirect')] [string] $Kind = 'Direct',
        [string] $Source = 'AD'
    )
    [pscustomobject][ordered]@{ PSTypeName = 'Fs.Membership'; groupId = $GroupId; memberId = $MemberId; kind = $Kind; source = $Source }
}

function New-FsError {
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)] [ValidateSet('Inventory', 'Walk', 'LocalGroups', 'AdResolve', 'Membership', 'Export', 'Other')] [string] $Phase,
        [AllowNull()] [string] $Scope,
        [AllowNull()] [string] $Path,
        [System.Nullable[int]] $Depth,
        [string] $Kind = 'Other',
        [Parameter(Mandatory)] [string] $Message,
        [AllowNull()] [string] $ExceptionType
    )
    [pscustomobject][ordered]@{
        PSTypeName    = 'Fs.Error'
        timestamp     = (Get-Date).ToUniversalTime().ToString('o')
        phase         = $Phase
        scope         = $Scope
        path          = $Path
        depth         = $Depth
        kind          = $Kind
        message       = $Message
        exceptionType = $ExceptionType
    }
}

# ---------------------------------------------------------------- export / import

function Get-FsSnapshotFileName {
    <# <yyyyMMdd-HHmmss>-<scanId8>.json[.gz]  (UTC timestamp) #>
    [OutputType([string])]
    param([Parameter(Mandatory)] $Snapshot, [switch] $NoCompress)
    $ts = [datetimeoffset]::Parse((Get-FsValue $Snapshot 'timestamp'), [cultureinfo]::InvariantCulture).UtcDateTime
    $id8 = ((Get-FsValue $Snapshot 'scanId') -replace '[^0-9a-fA-F]', '').Substring(0, 8).ToLowerInvariant()
    $name = '{0:yyyyMMdd-HHmmss}-{1}.json' -f $ts, $id8
    if (-not $NoCompress) { $name += '.gz' }
    return $name
}

function Export-FsSnapshot {
    <#
    .SYNOPSIS
        Serializes a snapshot to gzipped JSON. Writes to a temp file first, then moves (OneDrive-safe).
    .PARAMETER Directory
        Snapshot root; the file lands in <Directory>/<SERVER>/<timestamp>-<scanId8>.json.gz
    .PARAMETER Path
        Explicit output path instead of -Directory.
    #>
    [CmdletBinding(DefaultParameterSetName = 'Directory')]
    [OutputType([System.IO.FileInfo])]
    param(
        [Parameter(Mandatory)] $Snapshot,
        [Parameter(Mandatory, ParameterSetName = 'Directory')] [string] $Directory,
        [Parameter(Mandatory, ParameterSetName = 'Path')] [string] $Path,
        [switch] $NoCompress
    )
    if ($PSCmdlet.ParameterSetName -eq 'Directory') {
        $serverDir = Join-Path $Directory (Get-FsValue $Snapshot 'server.name')
        $Path = Join-Path $serverDir (Get-FsSnapshotFileName -Snapshot $Snapshot -NoCompress:$NoCompress)
    }
    $dir = [System.IO.Path]::GetDirectoryName([System.IO.Path]::GetFullPath($Path))
    if (-not (Test-Path -LiteralPath $dir)) { New-Item -ItemType Directory -Path $dir -Force | Out-Null }

    $json = ConvertTo-Json -InputObject $Snapshot -Depth 32 -Compress
    $tmp = "$Path.tmp"
    try {
        if ($NoCompress -or $Path -notlike '*.gz') {
            [System.IO.File]::WriteAllText($tmp, $json, [System.Text.UTF8Encoding]::new($false))
        }
        else {
            $fs = [System.IO.File]::Create($tmp)
            try {
                $gz = [System.IO.Compression.GZipStream]::new($fs, [System.IO.Compression.CompressionLevel]::Optimal)
                $writer = [System.IO.StreamWriter]::new($gz, [System.Text.UTF8Encoding]::new($false))
                $writer.Write($json); $writer.Flush(); $writer.Dispose(); $gz.Dispose()
            }
            finally { $fs.Dispose() }
        }
        Move-Item -LiteralPath $tmp -Destination $Path -Force
    }
    finally { if (Test-Path -LiteralPath $tmp) { Remove-Item -LiteralPath $tmp -Force -ErrorAction SilentlyContinue } }
    return Get-Item -LiteralPath $Path
}

function Read-FsJsonFile {
    <# Reads a .json or .json.gz file (sniffing the gzip magic bytes) and returns the text. #>
    [OutputType([string])]
    param([Parameter(Mandatory)] [string] $Path)
    $bytes = [System.IO.File]::ReadAllBytes($Path)
    if ($bytes.Length -ge 2 -and $bytes[0] -eq 0x1F -and $bytes[1] -eq 0x8B) {
        $ms = [System.IO.MemoryStream]::new($bytes)
        $gz = [System.IO.Compression.GZipStream]::new($ms, [System.IO.Compression.CompressionMode]::Decompress)
        $reader = [System.IO.StreamReader]::new($gz, [System.Text.UTF8Encoding]::new($false))
        try { return $reader.ReadToEnd() } finally { $reader.Dispose(); $gz.Dispose(); $ms.Dispose() }
    }
    return [System.Text.UTF8Encoding]::new($false).GetString($bytes).TrimStart([char]0xFEFF)
}

function Import-FsSnapshot {
    <#
    .SYNOPSIS
        Loads a snapshot file into a hashtable tree and validates the schema version.
    #>
    [OutputType([hashtable])]
    param([Parameter(Mandatory)] [string] $Path)
    $json = Read-FsJsonFile -Path $Path
    $snap = ConvertFrom-Json -InputObject $json -AsHashtable -Depth 64
    $ver = [string]$snap['schemaVersion']
    if (-not $ver) { throw "Snapshot '$Path' has no schemaVersion." }
    if ($ver.Split('.')[0] -ne $script:FsSnapshotSchemaVersion.Split('.')[0]) {
        throw "Snapshot '$Path' has schemaVersion $ver; this tool supports $script:FsSnapshotSchemaVersion."
    }
    foreach ($k in 'shares', 'folders', 'memberships', 'errors') { if ($null -eq $snap[$k]) { $snap[$k] = @() } }
    if ($null -eq $snap['principals']) { $snap['principals'] = @{} }
    $snap['_path'] = $Path
    return $snap
}

function Get-FsSnapshotIndex {
    <#
    .SYNOPSIS
        Lists snapshot files under <Root>/<SERVER>/ without reading them, newest first per server.
    .OUTPUTS
        Objects: server, path, timestamp (UTC datetime), scanId8, compressed
    #>
    [OutputType([object[]])]
    param([Parameter(Mandatory)] [string] $Root, [string] $Server)
    if (-not (Test-Path -LiteralPath $Root)) { return @() }
    $entries = foreach ($dir in Get-ChildItem -LiteralPath $Root -Directory) {
        if ($Server -and $dir.Name -ne $Server.ToUpperInvariant()) { continue }
        foreach ($f in Get-ChildItem -LiteralPath $dir.FullName -File) {
            $m = [regex]::Match($f.Name, '^(\d{8})-(\d{6})-([0-9a-f]{8})\.json(\.gz)?$')
            if (-not $m.Success) { continue }
            $ts = [datetime]::ParseExact($m.Groups[1].Value + $m.Groups[2].Value, 'yyyyMMddHHmmss', [cultureinfo]::InvariantCulture, [System.Globalization.DateTimeStyles]::AssumeUniversal -bor [System.Globalization.DateTimeStyles]::AdjustToUniversal)
            [pscustomobject]@{ server = $dir.Name; path = $f.FullName; timestamp = $ts; scanId8 = $m.Groups[3].Value; compressed = [bool]$m.Groups[4].Success; bytes = $f.Length }
        }
    }
    return @(Get-FsSorted -InputObject @($entries) -Property 'server', '-timestamp', '-scanId8')
}

function Import-FsSnapshotHistory {
    <#
    .SYNOPSIS
        Imports up to -MaxHistory snapshots per server (newest first) from a snapshot root.
    .OUTPUTS
        Hashtable: server -> object[] of snapshot hashtables, newest first.
    #>
    [OutputType([hashtable])]
    param([Parameter(Mandatory)] [string] $Root, [int] $MaxHistory = 10, [string[]] $Server)
    $byServer = [ordered]@{}
    foreach ($e in Get-FsSnapshotIndex -Root $Root) {
        if ($Server -and $Server -notcontains $e.server) { continue }
        if (-not $byServer.Contains($e.server)) { $byServer[$e.server] = [System.Collections.Generic.List[object]]::new() }
        if ($MaxHistory -gt 0 -and $byServer[$e.server].Count -ge $MaxHistory) { continue }
        $byServer[$e.server].Add((Import-FsSnapshot -Path $e.path))
    }
    return $byServer
}

# ---------------------------------------------------------------- merged model

function Merge-FsModel {
    <#
    .SYNOPSIS
        Merges snapshot history (server -> snapshots newest first) into the model used by analytics and rendering.
    .DESCRIPTION
        Facts (shares, folders, memberships) come from each server's newest snapshot. Principals merge by id
        across servers: newest fetchedAt wins, Resolved beats Orphaned/LookupFailed. Previous snapshots are kept
        per server for change tracking.
    #>
    [OutputType([hashtable])]
    param(
        [Parameter(Mandatory)] [System.Collections.IDictionary] $History,
        [datetime] $Now = (Get-Date)
    )
    $model = [ordered]@{
        generatedAt  = $Now.ToUniversalTime().ToString('o')
        servers      = [ordered]@{}
        shares       = [ordered]@{}
        folders      = [ordered]@{}
        principals   = [ordered]@{}
        memberships  = [System.Collections.Generic.List[object]]::new()
        errors       = [System.Collections.Generic.List[object]]::new()
        snapshots    = [ordered]@{}
        domainSids   = [System.Collections.Generic.List[string]]::new()
        domains      = [ordered]@{}
        machineSids  = [ordered]@{}
        scanIds      = [System.Collections.Generic.List[string]]::new()
    }
    $membershipKeys = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)

    foreach ($serverName in Get-FsSortedKeys $History) {
        $snaps = @($History[$serverName] | Get-FsSorted -Property '-timestamp')
        if ($snaps.Count -eq 0) { continue }
        $latest = $snaps[0]
        $previous = if ($snaps.Count -gt 1) { $snaps[1] } else { $null }
        $srv = [string]$latest['server']['name']
        $model.snapshots[$srv] = $snaps
        $model.scanIds.Add([string]$latest['scanId'])

        $model.servers[$srv] = [ordered]@{
            name            = $srv
            fqdn            = $latest['server']['fqdn']
            machineSid      = $latest['server']['machineSid']
            domainRole      = $latest['server']['domainRole']
            osVersion       = $latest['server']['osVersion']
            scanId          = $latest['scanId']
            lastScanned     = $latest['timestamp']
            completedAt     = $latest['completedAt']
            durationSeconds = $latest['durationSeconds']
            scope           = $latest['scope']
            status          = $latest['status']
            stats           = $latest['stats']
            credentialUser  = $latest['credentialUser']
            toolVersion     = $latest['toolVersion']
            previousScanId  = $(if ($previous) { $previous['scanId'] } else { $null })
            previousScanned = $(if ($previous) { $previous['timestamp'] } else { $null })
            snapshotCount   = $snaps.Count
            shareIds        = [System.Collections.Generic.List[string]]::new()
            errorCount      = @($latest['errors']).Count
        }
        if ($latest['server']['machineSid']) { $model.machineSids[$srv] = $latest['server']['machineSid'] }
        if ($latest['domain'] -and $latest['domain']['sid']) {
            $dsid = [string]$latest['domain']['sid']
            if (-not $model.domainSids.Contains($dsid)) { $model.domainSids.Add($dsid) }
            $model.domains[$dsid] = $latest['domain']['name']
        }

        foreach ($share in @($latest['shares'])) {
            $share['server'] = $srv
            $model.shares[[string]$share['id']] = $share
            $model.servers[$srv].shareIds.Add([string]$share['id'])
        }
        foreach ($folder in @($latest['folders'])) {
            $folder['server'] = $srv
            $model.folders[[string]$folder['id']] = $folder
        }
        foreach ($prId in @($latest["principals"].Keys)) {
            $p = $latest["principals"][$prId]
            $p['_servers'] = @($p['_servers']) + $srv
            if (-not $model.principals.Contains($prId)) { $model.principals[$prId] = $p; continue }
            $existing = $model.principals[$prId]
            $newer = ([string]$p['fetchedAt']) -gt ([string]$existing['fetchedAt'])
            $rank = @{ Resolved = 3; WellKnown = 3; Local = 3; Foreign = 2; LookupFailed = 1; Orphaned = 0 }
            $rNew = $rank[[string]$p['resolution']]; $rOld = $rank[[string]$existing['resolution']]
            if ($null -eq $rNew) { $rNew = 0 }; if ($null -eq $rOld) { $rOld = 0 }
            if ($rNew -gt $rOld -or ($rNew -eq $rOld -and $newer)) {
                $p['_servers'] = @(@($existing['_servers']) + @($p['_servers']) | Get-FsSorted -Unique)
                $model.principals[$prId] = $p
            }
            else {
                $existing['_servers'] = @(@($existing['_servers']) + $srv | Get-FsSorted -Unique)
            }
        }
        foreach ($m in @($latest['memberships'])) {
            $key = '{0}|{1}|{2}' -f $m['groupId'], $m['memberId'], $m['kind']
            if ($membershipKeys.Add($key)) { $model.memberships.Add($m) }
        }
        foreach ($e in @($latest['errors'])) {
            $e['server'] = $srv; $e['scanId'] = $latest['scanId']
            $model.errors.Add($e)
        }
    }

    Add-FsModelIndex -Model $model
    return $model
}

function Add-FsModelIndex {
    <#
    .SYNOPSIS
        Builds lookup indexes on a merged model (idempotent). All lists are ordinal-sorted for determinism.
    #>
    param([Parameter(Mandatory)] [System.Collections.IDictionary] $Model)
    $idx = [ordered]@{
        acesByPrincipal  = @{}   # principalId -> List of @{ resourceId; resourceKind; server; ace; layer }
        acesByResource   = @{}   # resourceId  -> object[] aces   (share id -> share aces; folder id -> folder aces)
        membersByGroup   = @{}   # groupId     -> string[] memberIds
        groupsByMember   = @{}   # memberId    -> string[] groupIds
        foldersByShare   = @{}   # shareId     -> string[] folderIds (all folders exposed by the share, incl. root)
        childrenByFolder = @{}   # folderId    -> string[] child divergent folder ids (by nearestDivergentAncestorId)
        rootFolderByShare = @{}  # shareId     -> folderId
        sharesByServer   = @{}   # server      -> string[] shareIds
        referencedPrincipalIds = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    }
    $addAce = {
        param($principalId, $entry)
        if (-not $idx.acesByPrincipal.ContainsKey($principalId)) { $idx.acesByPrincipal[$principalId] = [System.Collections.Generic.List[object]]::new() }
        $idx.acesByPrincipal[$principalId].Add($entry)
        [void]$idx.referencedPrincipalIds.Add($principalId)
    }
    foreach ($sid in Get-FsSortedKeys $Model.shares) {
        $share = $Model.shares[$sid]
        $srv = [string]$share['server']
        if (-not $idx.sharesByServer.ContainsKey($srv)) { $idx.sharesByServer[$srv] = [System.Collections.Generic.List[string]]::new() }
        $idx.sharesByServer[$srv].Add($sid)
        $idx.acesByResource[$sid] = @($share['aces'])
        $idx.rootFolderByShare[$sid] = [string]$share['rootFolderId']
        foreach ($ace in @($share['aces'])) {
            & $addAce ([string]$ace['principalId']) @{ resourceId = $sid; resourceKind = 'Share'; server = $srv; ace = $ace; layer = 'Share' }
        }
    }
    foreach ($fid in Get-FsSortedKeys $Model.folders) {
        $folder = $Model.folders[$fid]
        $srv = [string]$folder['server']
        $idx.acesByResource[$fid] = @($folder['aces'])
        foreach ($shareName in @($folder['shareNames'])) {
            $shareId = Get-FsShareId -Server $srv -ShareName $shareName
            if (-not $idx.foldersByShare.ContainsKey($shareId)) { $idx.foldersByShare[$shareId] = [System.Collections.Generic.List[string]]::new() }
            $idx.foldersByShare[$shareId].Add($fid)
        }
        $anc = $folder['nearestDivergentAncestorId']
        if ($anc) {
            if (-not $idx.childrenByFolder.ContainsKey($anc)) { $idx.childrenByFolder[$anc] = [System.Collections.Generic.List[string]]::new() }
            $idx.childrenByFolder[$anc].Add($fid)
        }
        foreach ($ace in @($folder['aces'])) {
            & $addAce ([string]$ace['principalId']) @{ resourceId = $fid; resourceKind = 'Folder'; server = $srv; ace = $ace; layer = 'NTFS' }
        }
        if ($folder['ownerPrincipalId']) { [void]$idx.referencedPrincipalIds.Add([string]$folder['ownerPrincipalId']) }
    }
    foreach ($m in $Model.memberships) {
        $g = [string]$m['groupId']; $mem = [string]$m['memberId']
        if (-not $idx.membersByGroup.ContainsKey($g)) { $idx.membersByGroup[$g] = [System.Collections.Generic.List[string]]::new() }
        if (-not $idx.groupsByMember.ContainsKey($mem)) { $idx.groupsByMember[$mem] = [System.Collections.Generic.List[string]]::new() }
        if (-not $idx.membersByGroup[$g].Contains($mem)) { $idx.membersByGroup[$g].Add($mem) }
        if (-not $idx.groupsByMember[$mem].Contains($g)) { $idx.groupsByMember[$mem].Add($g) }
    }
    foreach ($table in 'membersByGroup', 'groupsByMember', 'foldersByShare', 'childrenByFolder', 'sharesByServer') {
        foreach ($k in @($idx[$table].Keys)) { $idx[$table][$k] = [string[]]@(Get-FsSorted -InputObject @($idx[$table][$k]) -Unique) }
    }
    $Model['index'] = $idx
}

function Get-FsModelPrincipal {
    <# Principal record by id, or a synthetic OrphanedSid/unknown record so callers never get $null. #>
    [OutputType([System.Collections.IDictionary])]
    param([Parameter(Mandatory)] [System.Collections.IDictionary] $Model, [Parameter(Mandatory)] [string] $Id)
    if ($Model.principals.Contains($Id)) { return $Model.principals[$Id] }
    $kind = if ($Id -match '^S-1-') { 'OrphanedSid' } else { 'LocalGroup' }
    $name = if (Test-FsLocalPrincipalId $Id) { $Id.Split('\')[-1] } else { $Id }
    return [ordered]@{ id = $Id; kind = $kind; sid = $(if ($Id -match '^S-1-') { $Id } else { $null }); name = $name; displayName = $name; ntAccount = $Id; domain = $null; server = $(if (Test-FsLocalPrincipalId $Id) { $Id.Split('\')[0] } else { $null }); isWellKnown = $false; isBroad = $false; resolution = 'Unknown'; ad = $null; local = $null; _synthetic = $true }
}

function Get-FsResource {
    <# Share or folder record by id with a 'kind' hint; $null when unknown. #>
    [OutputType([hashtable])]
    param([Parameter(Mandatory)] [System.Collections.IDictionary] $Model, [Parameter(Mandatory)] [string] $Id)
    if ($Model.shares.Contains($Id)) { return @{ kind = 'Share'; record = $Model.shares[$Id] } }
    if ($Model.folders.Contains($Id)) { return @{ kind = 'Folder'; record = $Model.folders[$Id] } }
    return $null
}
