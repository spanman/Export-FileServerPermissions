<#
Remote local-group enumeration (SAM) via the WinNT:// ADSI provider.

$script:FsRemoteLocalGroups runs INSIDE the WinRM session (Windows PowerShell 5.1 compatible).
  param($Sids, $IsDomainController, $MachineSid)
  -> [pscustomobject]@{ skipped; reason; computerName; groups; edges; users; errors }   (collections are JSON strings)

  groups[] { sid, name, description, memberCount, method }
  edges[]  { groupSid, memberSid, memberClass, memberDomain, memberName, memberIsLocal, memberIsOrphan }
  users[]  { sid, name, fullName, description, disabled, userFlags, lastLogin }
  errors[] { scope, message, exceptionType }

WinNT Invoke('Members') is primary because Get-LocalGroupMember throws for the whole group when a single
member is an orphaned SID. Fallbacks: Get-LocalGroupMember -SID, then a name-only parse of `net localgroup`.
A domain controller has no local SAM: the scriptblock returns skipped=$true and BUILTIN\* groups are
resolved through AD instead.

Import-FsLocalGroupResult runs on the workstation and turns the result into LocalGroup/LocalUser principals
and LocalDirect membership edges.
#>

$script:FsRemoteLocalGroups = {
    param($Sids, $IsDomainController, $MachineSid)

    $computer = $env:COMPUTERNAME
    if ([bool]$IsDomainController) {
        return [pscustomobject]@{ skipped = $true; reason = 'DomainController'; computerName = $computer; groups = '[]'; edges = '[]'; users = '[]'; errors = '[]' }
    }

    $groups = New-Object System.Collections.ArrayList
    $edges = New-Object System.Collections.ArrayList
    $users = New-Object System.Collections.ArrayList
    $errors = New-Object System.Collections.ArrayList
    $describedUsers = @{}

    function Add-LocalGroupError {
        param($Scope, $Message, $Type)
        [void]$errors.Add(@{ scope = [string]$Scope; message = [string]$Message; exceptionType = [string]$Type })
    }
    function ConvertTo-SidString {
        param($Bytes)
        if ($null -eq $Bytes) { return $null }
        try { return (New-Object System.Security.Principal.SecurityIdentifier($Bytes, 0)).Value } catch { return $null }
    }
    function Get-ComProperty {
        param($Object, $Name)
        try { return $Object.GetType().InvokeMember($Name, 'GetProperty', $null, $Object, $null) } catch { return $null }
    }
    function Get-AdsiValue {
        param($Entry, $Name)
        try {
            $v = $Entry.InvokeGet($Name)
            if ($v -is [System.Array] -and $v.Length -gt 0) { return $v[0] }
            return $v
        }
        catch { return $null }
    }
    function Test-LocalSid {
        param($SidString)
        if (-not $SidString) { return $false }
        if ($SidString -like 'S-1-5-32-*') { return $true }
        if ($MachineSid -and $SidString -like "$MachineSid-*") { return $true }
        return $false
    }
    function Get-AdsPathDomain {
        # WinNT://DOMAIN/name -> DOMAIN ; WinNT://S-1-5-21-... -> $null
        param($AdsPath)
        if (-not $AdsPath) { return $null }
        $p = [string]$AdsPath
        if ($p.StartsWith('WinNT://', [System.StringComparison]::OrdinalIgnoreCase)) { $p = $p.Substring(8) }
        $parts = @($p.Split('/') | Where-Object { $_ -ne '' })
        if ($parts.Count -ge 2) { return $parts[$parts.Count - 2] }
        return $null
    }
    function Add-LocalUserDetail {
        param($Name, $SidString)
        if (-not $Name) { return }
        if ($describedUsers.ContainsKey($Name)) { return }
        $describedUsers[$Name] = $true
        try {
            $u = [ADSI]"WinNT://$computer/$Name,user"
            $flags = Get-AdsiValue $u 'UserFlags'
            $disabled = $false
            if ($null -ne $flags) { $disabled = (([int]$flags -band 0x2) -ne 0) }
            $lastLogin = $null
            try {
                $ll = $u.InvokeGet('LastLogin')
                if ($ll -is [datetime]) { $lastLogin = $ll.ToUniversalTime().ToString('o') }
            }
            catch { $lastLogin = $null }
            $sidHere = $SidString
            if (-not $sidHere) { $sidHere = ConvertTo-SidString (Get-AdsiValue $u 'objectSid') }
            [void]$users.Add(@{
                sid = $sidHere; name = [string]$Name; fullName = [string](Get-AdsiValue $u 'FullName'); description = [string](Get-AdsiValue $u 'Description')
                disabled = $disabled; userFlags = $flags; lastLogin = $lastLogin
            })
        }
        catch { Add-LocalGroupError "User/$Name" $_.Exception.Message $_.Exception.GetType().FullName }
    }
    function Add-Edge {
        param($GroupSid, $MemberSid, $Class, $Domain, $Name, $IsLocal, $IsOrphan)
        [void]$edges.Add(@{
            groupSid = $GroupSid; memberSid = $MemberSid; memberClass = [string]$Class; memberDomain = [string]$Domain; memberName = [string]$Name
            memberIsLocal = [bool]$IsLocal; memberIsOrphan = [bool]$IsOrphan
        })
        if ($IsLocal -and ([string]$Class) -eq 'User' -and $Name) { Add-LocalUserDetail $Name $MemberSid }
    }

    function Get-GroupMembersWinNt {
        param($GroupSid, $GroupName)
        $entry = [ADSI]"WinNT://$computer/$GroupName,group"
        $raw = $entry.Invoke('Members')
        $n = 0
        foreach ($m in @($raw)) {
            $n++
            $adsPath = [string](Get-ComProperty $m 'ADsPath')
            $mClass = [string](Get-ComProperty $m 'Class')
            $mName = [string](Get-ComProperty $m 'Name')
            $mSid = ConvertTo-SidString (Get-ComProperty $m 'objectSid')
            $domain = Get-AdsPathDomain $adsPath
            $isOrphan = $false
            if ($mName -match '^S-1-\d+(-\d+)+$') { $isOrphan = $true; if (-not $mSid) { $mSid = $mName } }
            elseif (-not $mSid) { $isOrphan = $true }
            elseif ($adsPath -match '^WinNT://S-1-\d') { $isOrphan = $true }
            $isLocal = $false
            if (-not $isOrphan) {
                if ($domain -and ([string]$domain).Equals($computer, [System.StringComparison]::OrdinalIgnoreCase)) { $isLocal = $true }
                elseif (Test-LocalSid $mSid) { $isLocal = $true }
            }
            Add-Edge $GroupSid $mSid $mClass $domain $mName $isLocal $isOrphan
        }
        return $n
    }

    function Get-GroupMembersCmdlet {
        param($GroupSid)
        $members = @(Get-LocalGroupMember -SID $GroupSid -ErrorAction Stop)
        foreach ($m in $members) {
            $mSid = $null
            if ($m.SID) { $mSid = $m.SID.Value }
            $full = [string]$m.Name
            $domain = $null; $leaf = $full
            $i = $full.IndexOf('\')
            if ($i -gt 0) { $domain = $full.Substring(0, $i); $leaf = $full.Substring($i + 1) }
            $isLocal = ([string]$m.PrincipalSource -eq 'Local') -or (Test-LocalSid $mSid)
            $isOrphan = ($leaf -match '^S-1-\d')
            Add-Edge $GroupSid $mSid ([string]$m.ObjectClass) $domain $leaf $isLocal $isOrphan
        }
        return $members.Count
    }

    function Get-GroupMembersNet {
        param($GroupSid, $GroupName)
        $lines = @(& net.exe localgroup "$GroupName" 2>&1)
        $inList = $false
        $n = 0
        foreach ($line in $lines) {
            $text = [string]$line
            if ($text -match '^-{5,}') { $inList = $true; continue }
            if (-not $inList) { continue }
            if ($text -match 'completed successfully' -or [string]::IsNullOrWhiteSpace($text)) { continue }
            $full = $text.Trim()
            $domain = $null; $leaf = $full
            $i = $full.IndexOf('\')
            if ($i -gt 0) { $domain = $full.Substring(0, $i); $leaf = $full.Substring($i + 1) }
            $mSid = $null
            try { $mSid = (New-Object System.Security.Principal.NTAccount($full)).Translate([System.Security.Principal.SecurityIdentifier]).Value } catch { $mSid = $null }
            $isOrphan = ($leaf -match '^S-1-\d')
            if ($isOrphan -and -not $mSid) { $mSid = $leaf }
            $isLocal = ($null -eq $domain) -or ([string]$domain).Equals($computer, [System.StringComparison]::OrdinalIgnoreCase) -or (Test-LocalSid $mSid)
            $class = 'Unknown'
            if ($mSid) {
                try {
                    $probe = [ADSI]"WinNT://$computer/$leaf"
                    $sc = $probe.SchemaClassName
                    if ($sc) { $class = [string]$sc }
                }
                catch { $class = 'Unknown' }
            }
            Add-Edge $GroupSid $mSid $class $domain $leaf $isLocal $isOrphan
            $n++
        }
        return $n
    }

    foreach ($sid in @($Sids)) {
        if (-not $sid) { continue }
        $nt = $null
        try { $nt = (New-Object System.Security.Principal.SecurityIdentifier([string]$sid)).Translate([System.Security.Principal.NTAccount]).Value }
        catch { Add-LocalGroupError $sid "SID translation failed: $($_.Exception.Message)" $_.Exception.GetType().FullName; continue }
        $name = $nt
        $i = $nt.LastIndexOf('\')
        if ($i -ge 0) { $name = $nt.Substring($i + 1) }

        $class = $null
        try {
            $probe = [ADSI]"WinNT://$computer/$name"
            $class = [string]$probe.SchemaClassName
        }
        catch { $class = $null }
        if (-not $class) {
            # SchemaClassName can be empty for unresolvable objects; try both explicit binds
            try { $g = [ADSI]"WinNT://$computer/$name,group"; if ($g.Name) { $class = 'Group' } } catch { $class = $null }
            if (-not $class) { try { $u = [ADSI]"WinNT://$computer/$name,user"; if ($u.Name) { $class = 'User' } } catch { $class = $null } }
        }
        if ($class -eq 'User') { Add-LocalUserDetail $name ([string]$sid); continue }
        if ($class -ne 'Group') { Add-LocalGroupError $sid "WinNT object '$name' not found or not a group/user (class '$class')" 'System.Runtime.InteropServices.COMException'; continue }

        $desc = $null
        try { $desc = [string](Get-AdsiValue ([ADSI]"WinNT://$computer/$name,group") 'Description') } catch { $desc = $null }
        $count = 0
        $method = $null
        try { $count = Get-GroupMembersWinNt ([string]$sid) $name; $method = 'WinNT' }
        catch {
            Add-LocalGroupError "Group/$name" "WinNT member enumeration failed: $($_.Exception.Message)" $_.Exception.GetType().FullName
            try { $count = Get-GroupMembersCmdlet ([string]$sid); $method = 'Get-LocalGroupMember' }
            catch {
                Add-LocalGroupError "Group/$name" "Get-LocalGroupMember failed: $($_.Exception.Message)" $_.Exception.GetType().FullName
                try { $count = Get-GroupMembersNet ([string]$sid) $name; $method = 'net localgroup' }
                catch { Add-LocalGroupError "Group/$name" "net localgroup failed: $($_.Exception.Message)" $_.Exception.GetType().FullName; $method = 'Failed' }
            }
        }
        [void]$groups.Add(@{ sid = [string]$sid; name = $name; description = $desc; memberCount = $count; method = $method })
    }

    [pscustomobject]@{
        skipped      = $false
        reason       = $null
        computerName = $computer
        groups       = (ConvertTo-Json -InputObject @($groups.ToArray()) -Depth 4 -Compress)
        edges        = (ConvertTo-Json -InputObject @($edges.ToArray()) -Depth 4 -Compress)
        users        = (ConvertTo-Json -InputObject @($users.ToArray()) -Depth 4 -Compress)
        errors       = (ConvertTo-Json -InputObject @($errors.ToArray()) -Depth 4 -Compress)
    }
}

function New-FsLocalPrincipal {
    <#
    .SYNOPSIS
        Builds a LocalGroup / LocalUser principal for a server-local SAM account.
    #>
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)] [hashtable] $Context,
        [Parameter(Mandatory)] [string] $Sid,
        [Parameter(Mandatory)] [ValidateSet('LocalGroup', 'LocalUser')] [string] $Kind,
        [AllowNull()] [string] $Name,
        [AllowNull()] [hashtable] $Local,
        [System.Nullable[int]] $MemberCount,
        [System.Nullable[bool]] $MembershipResolved,
        [AllowNull()] [string] $MembershipNote
    )
    $server = $Context.ServerName
    $isBuiltin = ($Sid -like 'S-1-5-32-*')
    if (-not $Name) { $Name = Get-FsWellKnownName -Sid $Sid }
    if (-not $Name) { $Name = $Sid }
    $id = Get-FsPrincipalId -Sid $Sid -IsLocal $true -Server $server -Name $Name
    $domain = if ($isBuiltin) { 'BUILTIN' } else { $server }
    return New-FsPrincipal -Id $id -Kind $Kind -Sid $Sid -Domain $domain -Name $Name -Server $server `
        -IsWellKnown $isBuiltin -IsBroad (Test-FsBroadSid -Sid $Sid) -Resolution Local -Local $Local `
        -MemberCount $MemberCount -MembershipResolved $MembershipResolved -MembershipNote $MembershipNote `
        -FetchedAt (Get-FsContextNow) -SourceScanId $Context.Snapshot.scanId
}

function Import-FsLocalGroupResult {
    <#
    .SYNOPSIS
        Folds the remote local-group result into the context: LocalGroup/LocalUser principals, LocalDirect edges,
        pending domain member SIDs and errors.
    .OUTPUTS
        Hashtable @{ skipped; groups; edges; users }
    #>
    [OutputType([hashtable])]
    param([Parameter(Mandatory)] [hashtable] $Context, [Parameter(Mandatory)] $Result)
    $server = $Context.ServerName
    $Context.LocalGroups = $Result
    if ([bool](Get-FsValue $Result 'skipped')) {
        Write-Verbose "Local group enumeration skipped: $(Get-FsValue $Result 'reason')"
        return @{ skipped = $true; groups = 0; edges = 0; users = 0 }
    }
    $parse = { param($json) if ([string]::IsNullOrWhiteSpace($json)) { @() } else { @(ConvertFrom-Json -InputObject ([string]$json)) } }
    $groups = & $parse (Get-FsValue $Result 'groups')
    $edges = & $parse (Get-FsValue $Result 'edges')
    $users = & $parse (Get-FsValue $Result 'users')
    $errs = & $parse (Get-FsValue $Result 'errors')

    foreach ($e in $errs) {
        Add-FsScanError -Context $Context -Phase LocalGroups -Scope ([string](Get-FsValue $e 'scope')) -Message ([string](Get-FsValue $e 'message')) -ExceptionType ([string](Get-FsValue $e 'exceptionType')) | Out-Null
    }

    foreach ($g in $groups) {
        $sid = [string](Get-FsValue $g 'sid'); $name = [string](Get-FsValue $g 'name')
        if (-not $sid) { continue }
        $Context.SidTable[$sid] = @{ name = "$server\$name"; isLocal = $true }
        $mc = Get-FsValue $g 'memberCount'
        $method = [string](Get-FsValue $g 'method')
        $resolved = ($method -and $method -ne 'Failed')
        $note = $(if ($method -eq 'net localgroup') { 'members from net localgroup (names only)' } elseif (-not $resolved) { 'member enumeration failed' } else { $null })
        $p = New-FsLocalPrincipal -Context $Context -Sid $sid -Kind LocalGroup -Name $name -Local @{ description = (Get-FsValue $g 'description'); memberSource = $method } `
            -MemberCount $(if ($null -ne $mc) { [int]$mc } else { $null }) -MembershipResolved $resolved -MembershipNote $note
        Add-FsContextPrincipal -Context $Context -Principal $p -Replace | Out-Null
    }

    foreach ($u in $users) {
        $sid = [string](Get-FsValue $u 'sid'); $name = [string](Get-FsValue $u 'name')
        if (-not $name) { continue }
        if (-not $sid) { $sid = "$server\$name" }   # never expected; keeps the id scheme intact
        else { $Context.SidTable[$sid] = @{ name = "$server\$name"; isLocal = $true } }
        $disabled = [bool](Get-FsValue $u 'disabled')
        $local = [ordered]@{ description = (Get-FsValue $u 'description'); enabled = (-not $disabled); userFlags = (Get-FsValue $u 'userFlags'); lastLogin = (Get-FsValue $u 'lastLogin'); fullName = (Get-FsValue $u 'fullName') }
        $p = New-FsLocalPrincipal -Context $Context -Sid $sid -Kind LocalUser -Name $name -Local $local
        $p.displayName = $(if ($local.fullName) { [string]$local.fullName } else { $name })
        Add-FsContextPrincipal -Context $Context -Principal $p -Replace | Out-Null
    }

    $edgeCount = 0
    foreach ($e in $edges) {
        $gSid = [string](Get-FsValue $e 'groupSid'); $mSid = [string](Get-FsValue $e 'memberSid')
        $mName = [string](Get-FsValue $e 'memberName'); $mDomain = [string](Get-FsValue $e 'memberDomain'); $mClass = [string](Get-FsValue $e 'memberClass')
        $isLocal = [bool](Get-FsValue $e 'memberIsLocal'); $isOrphan = [bool](Get-FsValue $e 'memberIsOrphan')
        if (-not $gSid) { continue }
        $groupId = Get-FsSidPrincipalId -Sid $gSid -SidTable $Context.SidTable -Server $server
        $memberId = $null
        if ($isOrphan) {
            if (-not $mSid) { Add-FsScanError -Context $Context -Phase LocalGroups -Scope $groupId -Kind Orphan -Message "Member '$mName' has no SID and cannot be recorded." | Out-Null; continue }
            $memberId = $mSid
            if (-not $Context.Principals.ContainsKey($memberId)) {
                $orphan = New-FsPrincipal -Id $mSid -Kind OrphanedSid -Sid $mSid -Resolution Orphaned -ResolutionError "Orphaned member of $groupId (SID no longer resolves on $server)" -FetchedAt (Get-FsContextNow) -SourceScanId $Context.Snapshot.scanId
                Add-FsContextPrincipal -Context $Context -Principal $orphan | Out-Null
            }
        }
        elseif ($isLocal) {
            if (-not $mSid) { Add-FsScanError -Context $Context -Phase LocalGroups -Scope $groupId -Kind Other -Message "Local member '$mName' has no SID." | Out-Null; continue }
            $Context.SidTable[$mSid] = @{ name = "$server\$mName"; isLocal = $true }
            $memberId = Get-FsPrincipalId -Sid $mSid -IsLocal $true -Server $server -Name $mName
            if (-not $Context.Principals.ContainsKey($memberId)) {
                $kind = if ($mClass -eq 'Group') { 'LocalGroup' } else { 'LocalUser' }
                Add-FsContextPrincipal -Context $Context -Principal (New-FsLocalPrincipal -Context $Context -Sid $mSid -Kind $kind -Name $mName) | Out-Null
            }
        }
        else {
            if (-not $mSid) { Add-FsScanError -Context $Context -Phase LocalGroups -Scope $groupId -Kind Other -Message "Member '$mDomain\$mName' has no SID." | Out-Null; continue }
            $memberId = $mSid
            if (-not $Context.SidTable.ContainsKey($mSid)) {
                $nt = if ($mDomain) { "$mDomain\$mName" } else { $mName }
                $Context.SidTable[$mSid] = @{ name = $nt; isLocal = $false }
            }
            [void]$Context.PendingSids.Add($mSid)
        }
        Add-FsContextMembership -Context $Context -GroupId $groupId -MemberId $memberId -Kind LocalDirect -Source "Local:$server"
        $edgeCount++
    }
    return @{ skipped = $false; groups = @($groups).Count; edges = $edgeCount; users = @($users).Count }
}
