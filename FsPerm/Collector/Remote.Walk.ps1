<#
Remote NTFS walk.

$script:FsRemoteWalk runs INSIDE the WinRM session (Windows PowerShell 5.1 compatible) and streams:
  @{ type='chunk';   seq; foldersJson; count; visited }       every $ChunkSize divergent folders
  @{ type='summary'; sidTable; errorsJson; visited; returned; truncated; machineSid; psVersion; maxDepthReached; seconds }

Folder record (inside foldersJson):
  localPath, depth, parentPath, nearestDivergentAncestor, isProtected, ownerSid,
  aces[] { sid, rightsMask(int), type, isInherited, inheritanceFlags, propagationFlags },
  childFolderCount, reparsePointsSkipped, explicitAceCount

Divergence = inheritance protected OR any explicit ACE; depth 0 (the share root) is always returned.
Access rules are read with SecurityIdentifier targets so no LSA lookups happen per folder; names are
translated once per SID into sidTable.

ConvertFrom-FsRemoteFolder runs on the workstation and turns a record into New-FsFolder/New-FsAce objects.
#>

$script:FsRemoteWalk = {
    param($Root, $MaxDepth, $ChunkSize, $MaxFolders, $MachineSid, $IsDomainController)

    $sw = [System.Diagnostics.Stopwatch]::StartNew()
    $MaxDepth = [int]$MaxDepth
    $ChunkSize = [int]$ChunkSize
    if ($ChunkSize -le 0) { $ChunkSize = 1000 }
    $MaxFolders = [int]$MaxFolders
    $isDc = [bool]$IsDomainController
    $isCore = ([string]$PSVersionTable.PSEdition -eq 'Core')
    $sections = [System.Security.AccessControl.AccessControlSections]::Access -bor [System.Security.AccessControl.AccessControlSections]::Owner
    $sidType = [System.Security.Principal.SecurityIdentifier]
    $reparseFlag = [System.IO.FileAttributes]::ReparsePoint

    $errors = New-Object System.Collections.ArrayList
    $sidTable = @{}
    $buffer = New-Object System.Collections.ArrayList
    # counters live in a hashtable so nested functions mutate the shared object, not a scope-local copy
    $state = @{ seq = 0; visited = 0; returned = 0; truncated = $false; maxDepthReached = 0 }

    function Add-WalkError {
        param($Path, $Depth, $Kind, $Message, $Type)
        [void]$errors.Add(@{ path = [string]$Path; depth = $Depth; kind = [string]$Kind; message = [string]$Message; exceptionType = [string]$Type })
    }

    function Get-ErrorKind {
        param($Exception)
        if ($null -eq $Exception) { return 'Other' }
        $t = $Exception.GetType().FullName
        if ($t -like '*UnauthorizedAccess*') { return 'AccessDenied' }
        if ($t -like '*PathTooLong*') { return 'PathTooLong' }
        if ($t -like '*DirectoryNotFound*' -or $t -like '*FileNotFound*') { return 'NotFound' }
        if ($t -like '*IOException*') { return 'IO' }
        return 'Other'
    }

    function Add-SidEntry {
        param($SidObj)
        if ($null -eq $SidObj) { return $null }
        $sidString = $SidObj.Value
        if ($sidTable.ContainsKey($sidString)) { return $sidString }
        $isLocal = $false
        if (-not $isDc) {
            if ($sidString -like 'S-1-5-32-*') { $isLocal = $true }
            elseif ($MachineSid -and $SidObj.AccountDomainSid -and $SidObj.AccountDomainSid.Value -eq $MachineSid) { $isLocal = $true }
        }
        $name = $null
        try { $name = $SidObj.Translate([System.Security.Principal.NTAccount]).Value } catch { $name = $null }
        $sidTable[$sidString] = @{ name = $name; isLocal = $isLocal }
        return $sidString
    }

    function Get-DirectorySecurity {
        # DirectoryInfo.GetAccessControl is an instance method on .NET Framework and an extension method on .NET Core.
        param($DirInfo)
        if ($isCore) { return [System.IO.FileSystemAclExtensions]::GetAccessControl($DirInfo, $sections) }
        return $DirInfo.GetAccessControl($sections)
    }

    function Get-InnerException {
        # .NET exceptions surface wrapped in MethodInvocationException / PSInvalidOperation wrappers; unwrap to the real one
        param($Exception)
        $ex = $Exception
        while ($null -ne $ex -and $null -ne $ex.InnerException -and ($ex -is [System.Management.Automation.MethodInvocationException] -or $ex -is [System.Management.Automation.RuntimeException])) {
            $ex = $ex.InnerException
        }
        return $ex
    }

    function Get-DirectorySecurityWithRetry {
        # Returns @{ info; security }. Retries once with the \\?\ long-path prefix on PathTooLongException;
        # if the retry fails too, the original PathTooLongException is rethrown so the error keeps its kind.
        param($Path)
        try {
            $di = New-Object System.IO.DirectoryInfo($Path)
            return @{ info = $di; security = (Get-DirectorySecurity $di) }
        }
        catch {
            $ex = Get-InnerException $_.Exception
            if ($ex -isnot [System.IO.PathTooLongException] -or $Path.StartsWith('\\?\')) { throw $ex }
            try {
                $di2 = New-Object System.IO.DirectoryInfo('\\?\' + $Path)
                return @{ info = $di2; security = (Get-DirectorySecurity $di2) }
            }
            catch { throw $ex }
        }
    }

    function Send-Chunk {
        if ($buffer.Count -eq 0) { return }
        $state.seq = $state.seq + 1
        $json = ConvertTo-Json -InputObject @($buffer.ToArray()) -Depth 6 -Compress
        [pscustomobject]@{ type = 'chunk'; seq = $state.seq; foldersJson = $json; count = $buffer.Count; visited = $state.visited }
        $buffer.Clear()
    }

    if (-not $Root -or -not [System.IO.Directory]::Exists($Root)) {
        Add-WalkError $Root 0 'NotFound' "Share path '$Root' does not exist or is not accessible." 'System.IO.DirectoryNotFoundException'
    }
    else {
        $queue = New-Object 'System.Collections.Generic.Queue[object]'
        $queue.Enqueue(@{ path = ([string]$Root).TrimEnd('\'); depth = 0; parent = $null; nearest = $null })

        while ($queue.Count -gt 0) {
            $item = $queue.Dequeue()
            if ($MaxFolders -gt 0 -and $state.visited -ge $MaxFolders) { $state.truncated = $true; break }
            $state.visited = $state.visited + 1
            if ($item.depth -gt $state.maxDepthReached) { $state.maxDepthReached = $item.depth }

            $acl = $null
            try { $acl = Get-DirectorySecurityWithRetry $item.path }
            catch {
                $ex = Get-InnerException $_.Exception
                Add-WalkError $item.path $item.depth (Get-ErrorKind $ex) $ex.Message $ex.GetType().FullName
                if ($item.depth -eq 0) {
                    # the share root must always be present: emit a stub so the share still has a root folder record
                    [void]$buffer.Add(@{
                        localPath = $item.path; depth = 0; parentPath = $null; nearestDivergentAncestor = $null; isProtected = $false; ownerSid = $null
                        aces = @(); childFolderCount = 0; reparsePointsSkipped = 0; explicitAceCount = 0; error = $ex.Message
                    })
                    $state.returned = $state.returned + 1
                }
                continue
            }

            $sec = $acl.security
            $isProtected = [bool]$sec.AreAccessRulesProtected
            $aces = New-Object System.Collections.ArrayList
            $explicit = 0
            $rules = $sec.GetAccessRules($true, $true, $sidType)
            foreach ($rule in $rules) {
                $sidString = Add-SidEntry $rule.IdentityReference
                $inherited = [bool]$rule.IsInherited
                if (-not $inherited) { $explicit++ }
                [void]$aces.Add(@{
                    sid = $sidString; rightsMask = [int]$rule.FileSystemRights; type = $rule.AccessControlType.ToString()
                    isInherited = $inherited; inheritanceFlags = $rule.InheritanceFlags.ToString(); propagationFlags = $rule.PropagationFlags.ToString()
                })
            }
            $ownerSid = $null
            try { $ownerSid = Add-SidEntry ($sec.GetOwner($sidType)) } catch { $ownerSid = $null }

            $divergent = ($item.depth -eq 0) -or $isProtected -or ($explicit -gt 0)
            $nearestForChildren = $item.nearest
            if ($divergent) { $nearestForChildren = $item.path }

            $childCount = 0
            $reparseSkipped = 0
            $childError = $null
            try {
                $children = $acl.info.GetDirectories()
                foreach ($child in $children) {
                    if (($child.Attributes -band $reparseFlag) -eq $reparseFlag) { $reparseSkipped++; continue }
                    $childCount++
                    if ($item.depth -lt $MaxDepth) {
                        $childPath = $child.FullName
                        if ($childPath.StartsWith('\\?\')) { $childPath = $childPath.Substring(4) }
                        $queue.Enqueue(@{ path = $childPath; depth = ($item.depth + 1); parent = $item.path; nearest = $nearestForChildren })
                    }
                }
            }
            catch {
                $ex = Get-InnerException $_.Exception
                $childError = $ex.Message
                Add-WalkError $item.path $item.depth (Get-ErrorKind $ex) "Child enumeration failed: $($ex.Message)" $ex.GetType().FullName
            }

            if ($divergent) {
                [void]$buffer.Add(@{
                    localPath = $item.path; depth = $item.depth; parentPath = $item.parent; nearestDivergentAncestor = $item.nearest
                    isProtected = $isProtected; ownerSid = $ownerSid; aces = @($aces.ToArray()); childFolderCount = $childCount
                    reparsePointsSkipped = $reparseSkipped; explicitAceCount = $explicit; error = $childError
                })
                $state.returned = $state.returned + 1
                if ($buffer.Count -ge $ChunkSize) { Send-Chunk }
            }
        }
    }
    Send-Chunk

    [pscustomobject]@{
        type            = 'summary'
        sidTable        = (ConvertTo-Json -InputObject $sidTable -Depth 4 -Compress)
        errorsJson      = (ConvertTo-Json -InputObject @($errors.ToArray()) -Depth 4 -Compress)
        visited         = $state.visited
        returned        = $state.returned
        truncated       = $state.truncated
        machineSid      = $MachineSid
        psVersion       = $PSVersionTable.PSVersion.ToString()
        maxDepthReached = $state.maxDepthReached
        seconds         = [math]::Round($sw.Elapsed.TotalSeconds, 2)
    }
}

function ConvertFrom-FsRemoteFolder {
    <#
    .SYNOPSIS
        Pure conversion of one remote folder record (hashtable or ConvertFrom-Json object) into a New-FsFolder object.
    .PARAMETER SidTable
        sid -> @{ name; isLocal } (the context SidTable or any dictionary with that shape).
    #>
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)] $Record,
        [Parameter(Mandatory)] [string] $Server,
        [Parameter(Mandatory)] [string[]] $ShareName,
        [Parameter(Mandatory)] [string] $ShareLocalPath,
        [Parameter(Mandatory)] [System.Collections.IDictionary] $SidTable
    )
    $aces = [System.Collections.Generic.List[object]]::new()
    $i = 0
    foreach ($a in @(Get-FsValue $Record 'aces')) {
        $sid = [string](Get-FsValue $a 'sid')
        if (-not $sid) { continue }
        $entry = Get-FsSidTableEntry -SidTable $SidTable -Sid $sid
        $type = [string](Get-FsValue $a 'type')
        if ($type -notin 'Allow', 'Deny') { $type = 'Allow' }
        $aces.Add((New-FsAce -Index $i -PrincipalId (Get-FsSidPrincipalId -Sid $sid -SidTable $SidTable -Server $Server) -Sid $sid `
            -RightsMask ([long](Get-FsValue $a 'rightsMask')) -AccessControlType $type `
            -IsInherited ([bool](Get-FsValue $a 'isInherited')) `
            -InheritanceFlags ([string](Get-FsValue $a 'inheritanceFlags')) -PropagationFlags ([string](Get-FsValue $a 'propagationFlags')) `
            -NameOnServer ([string]$entry.name)))
        $i++
    }
    $ownerSid = [string](Get-FsValue $Record 'ownerSid')
    $ownerId = if ($ownerSid) { Get-FsSidPrincipalId -Sid $ownerSid -SidTable $SidTable -Server $Server } else { $null }
    $depth = Get-FsValue $Record 'depth'
    $childCount = Get-FsValue $Record 'childFolderCount'
    $reparse = Get-FsValue $Record 'reparsePointsSkipped'
    $err = Get-FsValue $Record 'error'
    return New-FsFolder -Server $Server -LocalPath ([string](Get-FsValue $Record 'localPath')) -ShareNames $ShareName -ShareLocalPath $ShareLocalPath `
        -Depth $(if ($null -ne $depth) { [int]$depth } else { 0 }) `
        -ParentLocalPath ([string](Get-FsValue $Record 'parentPath')) `
        -NearestDivergentAncestorLocalPath ([string](Get-FsValue $Record 'nearestDivergentAncestor')) `
        -IsProtected ([bool](Get-FsValue $Record 'isProtected')) -OwnerPrincipalId $ownerId `
        -ChildFolderCount $(if ($null -ne $childCount) { [int]$childCount } else { 0 }) `
        -ReparsePointsSkipped $(if ($null -ne $reparse) { [int]$reparse } else { 0 }) `
        -Aces @($aces) -Error $(if ($err) { [string]$err } else { $null })
}

function Get-FsSidTableEntry {
    <# Returns @{ name; isLocal } for a SID (empty entry when unknown). #>
    [OutputType([hashtable])]
    param([Parameter(Mandatory)] [System.Collections.IDictionary] $SidTable, [Parameter(Mandatory)] [string] $Sid)
    # Not .Contains($Sid)/.ContainsKey($Sid): PowerShell's late-bound method dispatch on a
    # Dictionary[string,object] resolves .Contains(x) to ICollection<KeyValuePair>.Contains(KeyValuePair),
    # not IDictionary.Contains(key) - passing a bare string then fails to bind ("Cannot find an overload for
    # 'Contains' and the argument count: 1"). And System.Collections.Specialized.OrderedDictionary (used by
    # some callers/tests) has no .ContainsKey() at all. Indexer access is forgiving across all three
    # (Hashtable, OrderedDictionary, Dictionary[K,V]) and returns $null for a missing key without throwing.
    $v = $SidTable[$Sid]
    if ($null -ne $v) { return @{ name = (Get-FsValue $v 'name'); isLocal = [bool](Get-FsValue $v 'isLocal') } }
    return @{ name = $null; isLocal = $false }
}

function Get-FsSidPrincipalId {
    <#
    .SYNOPSIS
        Principal id for a SID seen on a server: "SERVER\Name" when the server reported it as local, else the SID.
    #>
    [OutputType([string])]
    param(
        [Parameter(Mandatory)] [string] $Sid,
        [Parameter(Mandatory)] [System.Collections.IDictionary] $SidTable,
        [Parameter(Mandatory)] [string] $Server
    )
    $entry = Get-FsSidTableEntry -SidTable $SidTable -Sid $Sid
    if (-not $entry.isLocal) { return $Sid }
    $name = Get-FsAccountLeaf -Account ([string]$entry.name)
    return Get-FsPrincipalId -Sid $Sid -IsLocal $true -Server $Server -Name $name
}

function Get-FsAccountLeaf {
    <# "DOMAIN\Name" -> "Name"; $null for empty. #>
    [OutputType([string])]
    param([AllowNull()] [AllowEmptyString()] [string] $Account)
    if ([string]::IsNullOrWhiteSpace($Account)) { return $null }
    $i = $Account.LastIndexOf('\')
    if ($i -ge 0) { return $Account.Substring($i + 1) }
    return $Account
}

function Get-FsAccountDomain {
    <# "DOMAIN\Name" -> "DOMAIN"; $null when no domain part. #>
    [OutputType([string])]
    param([AllowNull()] [AllowEmptyString()] [string] $Account)
    if ([string]::IsNullOrWhiteSpace($Account)) { return $null }
    $i = $Account.IndexOf('\')
    if ($i -gt 0) { return $Account.Substring(0, $i) }
    return $null
}
