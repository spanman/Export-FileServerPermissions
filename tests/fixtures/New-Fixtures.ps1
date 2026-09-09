#Requires -Version 7.0
<#
.SYNOPSIS
    Builds the three fixture snapshots used by the test suite and writes them as plain JSON.

    FS01-20260901 (depth 2)  previous scan of FS01
    FS01-20260908 (depth 3)  latest scan of FS01
    FS02-20260908 (depth 3)  only scan of FS02

    Domain CONTOSO  S-1-5-21-1111111111-2222222222-3333333333
    Test clock: 2026-09-09T12:00:00Z (see tests/TestHelpers.ps1)

    What the data exercises (see docs/contracts.md and the plan):
      users    alice (HR, mgr dave) · bob (disabled, direct ACE) · carol (stale 200d) · dave (mgr, local FileAdmins)
               svc_backup (pwd 2019, local Backup Operators) · erin (new, never logged on) · frank -> frank.jones (rename + dept change)
      groups   HR-Share-RW ⊃ HR-All · Finance-RO · Loop-A <-> Loop-B (cycle) · Empty-Group · Solo-Group · Deep-1..Deep-4 · Ownerless-RW
      local    FS01\FileAdmins, FS01\Users, FS01\Administrators, FS01\Backup Operators
      shares   FS01: HR (Auth Users Change), Finance (Everyone Full share / NTFS limits), Temp (previous only)
               FS02: Public (Everyone Change share / Everyone Full NTFS -> share limits), PublicArchive (nested), Finance (same name as FS01)
      folders  HR\Payroll (protected, Deny, orphan) · HR\Payroll\Archive (bob direct; Read -> Modify) · HR\Payroll\Archive\2019 (depth 3, latest only)
               HR\Legal (newly divergent) · Finance\Budgets (Empty-Group; WriteDAC without Full)
      errors   FS02 access denied on E:\Public\Private; Public walk truncated
.PARAMETER OutputDirectory
    Defaults to this script's folder.
#>
[CmdletBinding()]
param([string] $OutputDirectory = $PSScriptRoot)

$ErrorActionPreference = 'Stop'
Import-Module (Join-Path (Split-Path -Parent (Split-Path -Parent $PSScriptRoot)) 'FsPerm/FsPerm.psd1') -Force

# ---------------------------------------------------------------- constants
$D = 'S-1-5-21-1111111111-2222222222-3333333333'      # CONTOSO domain SID
$F = 'S-1-5-21-4444444444-5555555555-6666666666'      # foreign, unreachable domain
$M1 = 'S-1-5-21-7000000001-7000000002-7000000003'     # FS01 machine SID
$M2 = 'S-1-5-21-8000000001-8000000002-8000000003'     # FS02 machine SID

$FULL = 0x1F01FF; $MODIFY = 0x1301BF; $RX = 0x1200A9; $READ = 0x120089; $WRITEBITS = 0x116
$CIOI = 'ContainerInherit, ObjectInherit'

$SID = @{
    Everyone = 'S-1-1-0'; AuthUsers = 'S-1-5-11'; Network = 'S-1-5-2'; Interactive = 'S-1-5-4'; System = 'S-1-5-18'; CreatorOwner = 'S-1-3-0'
    BuiltinAdmins = 'S-1-5-32-544'; BuiltinUsers = 'S-1-5-32-545'; BackupOps = 'S-1-5-32-551'
    DomainUsers = "$D-513"; DomainAdmins = "$D-512"
    alice = "$D-1101"; bob = "$D-1102"; carol = "$D-1103"; dave = "$D-1104"; svc_backup = "$D-1105"; erin = "$D-1106"; frank = "$D-1107"
    HRShareRW = "$D-2001"; HRAll = "$D-2002"; FinanceRO = "$D-2003"; LoopA = "$D-2004"; LoopB = "$D-2005"; EmptyGroup = "$D-2006"
    SoloGroup = "$D-2007"; Deep1 = "$D-2008"; Deep2 = "$D-2009"; Deep3 = "$D-2010"; Deep4 = "$D-2011"; OwnerlessRW = "$D-2012"
    Orphan = "$D-9999"; Foreign = "$F-1001"
    FS01LocalAdmin = "$M1-500"
}

# ---------------------------------------------------------------- helpers
function Ace($principalId, $mask, $type = 'Allow', $inherited = $false, $inh = $CIOI, $prop = 'None', $index = 0) {
    $sid = if ($principalId -match '^S-1-') { $principalId } else { $script:localSid[$principalId] }
    New-FsAce -Index $index -PrincipalId $principalId -Sid $sid -RightsMask $mask -AccessControlType $type -IsInherited $inherited -InheritanceFlags $inh -PropagationFlags $prop
}
function ShareAce($principalId, $mask, $type = 'Allow') {
    $sid = if ($principalId -match '^S-1-') { $principalId } else { $script:localSid[$principalId] }
    New-FsShareAce -PrincipalId $principalId -Sid $sid -AccessMask $mask -AccessControlType $type
}
function Indexed([object[]] $aces) { $i = 0; foreach ($a in $aces) { $a.index = $i; $i++ }; return , $aces }

function AddUser($snap, $id, $name, $display, $dept, $title, $mgrId, $uac, $lastLogon, $pwdLastSet, $created, $upnName = $name) {
    $ad = [ordered]@{
        userPrincipalName = "$upnName@contoso.local"; mail = "$upnName@contoso.local"; enabled = -not (Test-FsUacDisabled $uac); userAccountControl = $uac
        lastLogonTimestamp = $lastLogon; pwdLastSet = $pwdLastSet; accountExpires = $null
        department = $dept; title = $title; description = $null
        manager = $(if ($mgrId) { @{ dn = "CN=$($snap.principals[$mgrId].name),OU=Users,DC=contoso,DC=local"; sam = $snap.principals[$mgrId].name; sid = $mgrId } } else { $null })
        whenCreated = $created; distinguishedName = "CN=$display,OU=Users,DC=contoso,DC=local"; primaryGroupId = 513
    }
    $snap.principals[$id] = New-FsPrincipal -Id $id -Kind User -Sid $id -Domain CONTOSO -Name $name -DisplayName $display -Ad $ad -FetchedAt $snap.timestamp -SourceScanId $snap.scanId
    $snap.memberships.Add((New-FsMembership -GroupId $SID.DomainUsers -MemberId $id -Kind PrimaryGroup))
}
function AddGroup($snap, $id, $name, $desc, $managedById, $memberCount, $scopeType = -2147483646, $display = $name) {
    $gt = ConvertFrom-FsGroupType $scopeType
    $ad = [ordered]@{
        description = $desc; groupType = $scopeType; groupCategory = $gt.Category; groupScope = $gt.Scope; mail = $null
        whenCreated = '2018-01-15T10:00:00.0000000Z'
        managedBy = $(if ($managedById) { @{ dn = "CN=$($snap.principals[$managedById].name),OU=Users,DC=contoso,DC=local"; sam = $snap.principals[$managedById].name; sid = $managedById } } else { $null })
        distinguishedName = "CN=$name,OU=Groups,DC=contoso,DC=local"
    }
    $snap.principals[$id] = New-FsPrincipal -Id $id -Kind Group -Sid $id -Domain CONTOSO -Name $name -DisplayName $display -Ad $ad -MemberCount $memberCount -MembershipResolved $true -FetchedAt $snap.timestamp -SourceScanId $snap.scanId
}
function WellKnown($snap, $sid, $domain, $name, $broad = $false) {
    $snap.principals[$sid] = New-FsPrincipal -Id $sid -Kind WellKnown -Sid $sid -Domain $domain -Name $name -IsWellKnown $true -IsBroad $broad -Resolution WellKnown -MembershipResolved $false -MembershipNote 'implicit membership' -FetchedAt $snap.timestamp -SourceScanId $snap.scanId
}
function DomainWellKnownGroup($snap, $sid, $name, $broad, $memberCount, $note) {
    $ad = [ordered]@{ description = "Built-in $name"; groupType = -2147483646; groupCategory = 'Security'; groupScope = 'Global'; whenCreated = '2015-06-01T00:00:00.0000000Z'; distinguishedName = "CN=$name,CN=Users,DC=contoso,DC=local"; managedBy = $null }
    $snap.principals[$sid] = New-FsPrincipal -Id $sid -Kind Group -Sid $sid -Domain CONTOSO -Name $name -IsWellKnown $true -IsBroad $broad -Ad $ad -MemberCount $memberCount -MembershipResolved (-not $broad) -MembershipNote $note -FetchedAt $snap.timestamp -SourceScanId $snap.scanId
}
function LocalGroup($snap, $server, $name, $sid, $desc, $memberCount) {
    $id = Get-FsPrincipalId -Sid $sid -IsLocal $true -Server $server -Name $name
    $script:localSid[$id] = $sid
    $domain = if ($sid -like 'S-1-5-32-*') { 'BUILTIN' } else { $server }
    $snap.principals[$id] = New-FsPrincipal -Id $id -Kind LocalGroup -Sid $sid -Domain $domain -Name $name -Server $server -IsWellKnown ($sid -like 'S-1-5-32-*') -IsBroad ($sid -eq $SID.BuiltinUsers) -Resolution Local -Local @{ description = $desc } -MemberCount $memberCount -MembershipResolved $true -FetchedAt $snap.timestamp -SourceScanId $snap.scanId
    return $id
}
function AddMember($snap, $groupId, $memberId, $kind = 'Direct', $source = 'AD') { $snap.memberships.Add((New-FsMembership -GroupId $groupId -MemberId $memberId -Kind $kind -Source $source)) }

function AddCommonPrincipals($snap) {
    WellKnown $snap $SID.Everyone 'NT AUTHORITY' 'Everyone' $true
    WellKnown $snap $SID.AuthUsers 'NT AUTHORITY' 'Authenticated Users' $true
    WellKnown $snap $SID.Network 'NT AUTHORITY' 'NETWORK' $true
    WellKnown $snap $SID.Interactive 'NT AUTHORITY' 'INTERACTIVE' $true
    WellKnown $snap $SID.System 'NT AUTHORITY' 'SYSTEM'
    WellKnown $snap $SID.CreatorOwner 'NT AUTHORITY' 'CREATOR OWNER'
    DomainWellKnownGroup $snap $SID.DomainUsers 'Domain Users' $true 7 'primary group of all users; not enumerated'
    DomainWellKnownGroup $snap $SID.DomainAdmins 'Domain Admins' $false 1 $null
}

function AddDomainPeople($snap, [switch] $Latest) {
    # managers first so the manager lookups resolve
    AddUser $snap $SID.dave 'dave' 'Dave Diaz' 'IT' 'Infrastructure Manager' $null 512 '2026-09-07T15:30:00.0000000Z' '2026-07-01T09:00:00.0000000Z' '2015-03-10T09:00:00.0000000Z'
    AddUser $snap $SID.alice 'alice' 'Alice Anders' 'HR' 'HR Specialist' $SID.dave 512 '2026-09-06T08:12:44.0000000Z' '2026-06-30T09:00:00.0000000Z' '2019-03-12T10:00:00.0000000Z'
    AddUser $snap $SID.bob 'bob' 'Bob Brown' 'Finance' 'Accountant' $SID.dave 514 '2025-11-02T17:45:00.0000000Z' '2025-05-01T09:00:00.0000000Z' '2017-08-01T10:00:00.0000000Z'
    AddUser $snap $SID.carol 'carol' 'Carol Chen' 'HR' 'Recruiter' $SID.dave 512 '2026-02-20T11:00:00.0000000Z' '2026-01-15T09:00:00.0000000Z' '2020-01-06T10:00:00.0000000Z'
    AddUser $snap $SID.svc_backup 'svc_backup' 'Backup Service' 'IT' 'Service account' $SID.dave 66048 '2026-09-08T01:00:00.0000000Z' '2019-05-01T09:00:00.0000000Z' '2019-05-01T09:00:00.0000000Z'
    AddUser $snap $SID.erin 'erin' 'Erin Evans' 'Sales' 'Account Executive' $SID.dave 512 $null '2026-08-29T09:00:00.0000000Z' '2026-08-29T09:00:00.0000000Z'
    if ($Latest) { AddUser $snap $SID.frank 'frank.jones' 'Frank Jones' 'Finance' 'Analyst' $SID.dave 512 '2026-09-05T13:00:00.0000000Z' '2026-08-01T09:00:00.0000000Z' '2021-02-01T10:00:00.0000000Z' }
    else { AddUser $snap $SID.frank 'frank' 'Frank Jones' 'Sales' 'Analyst' $SID.dave 512 '2026-08-30T13:00:00.0000000Z' '2026-08-01T09:00:00.0000000Z' '2021-02-01T10:00:00.0000000Z' }

    AddGroup $snap $SID.HRShareRW 'HR-Share-RW' 'Read/write access to the HR share' $SID.dave 2
    AddGroup $snap $SID.HRAll 'HR-All' 'Everyone in HR' $SID.dave 3
    AddGroup $snap $SID.FinanceRO 'Finance-RO' 'Read-only access to Finance' $SID.dave $(if ($Latest) { 2 } else { 1 })
    AddGroup $snap $SID.LoopA 'Loop-A' 'Nested into Loop-B (cycle)' $null 1
    AddGroup $snap $SID.LoopB 'Loop-B' 'Nested into Loop-A (cycle)' $null 1
    AddGroup $snap $SID.EmptyGroup 'Empty-Group' 'Nobody is a member' $null 0
    AddGroup $snap $SID.SoloGroup 'Solo-Group' 'One member' $null 1
    AddGroup $snap $SID.Deep1 'Deep-1' 'Nesting chain top' $null 1
    AddGroup $snap $SID.Deep2 'Deep-2' $null $null 1
    AddGroup $snap $SID.Deep3 'Deep-3' $null $null 1
    AddGroup $snap $SID.Deep4 'Deep-4' $null $null 1
    AddGroup $snap $SID.OwnerlessRW 'Ownerless-RW' 'Modify on Finance' $(if ($Latest) { $SID.dave } else { $null }) 1

    AddMember $snap $SID.HRShareRW $SID.alice
    AddMember $snap $SID.HRShareRW $SID.HRAll
    AddMember $snap $SID.HRAll $SID.alice
    AddMember $snap $SID.HRAll $SID.carol
    AddMember $snap $SID.HRAll $SID.bob
    AddMember $snap $SID.FinanceRO $SID.frank
    if ($Latest) { AddMember $snap $SID.FinanceRO $SID.alice }
    AddMember $snap $SID.LoopA $SID.LoopB
    AddMember $snap $SID.LoopB $SID.LoopA
    AddMember $snap $SID.SoloGroup $SID.carol
    AddMember $snap $SID.Deep1 $SID.Deep2
    AddMember $snap $SID.Deep2 $SID.Deep3
    AddMember $snap $SID.Deep3 $SID.Deep4
    AddMember $snap $SID.Deep4 $SID.alice
    AddMember $snap $SID.OwnerlessRW $SID.bob
    AddMember $snap $SID.DomainAdmins $SID.dave
}

function Finish($snap, $seconds) {
    $snap.completedAt = ([datetimeoffset]::Parse($snap.timestamp).UtcDateTime.AddSeconds($seconds)).ToString('o')
    $snap.durationSeconds = $seconds
    $snap.status.phases = [ordered]@{ inventory = 'Ok'; walk = $(if (@($snap.errors).Count) { 'Partial' } else { 'Ok' }); localGroups = 'Ok'; adResolve = 'Ok'; membership = 'Ok' }
    $snap.status.partial = (@($snap.errors).Count -gt 0)
    $snap.stats = [ordered]@{
        shares = $snap.shares.Count; foldersVisited = ($snap.shares | ForEach-Object { $_.walk.foldersVisited } | Measure-Object -Sum).Sum
        foldersReturned = $snap.folders.Count; principals = $snap.principals.Count; memberships = $snap.memberships.Count; errors = $snap.errors.Count
    }
}

function Write-Fixture($snap, $name) {
    $path = Join-Path $OutputDirectory "$name.json"
    Export-FsSnapshot -Snapshot $snap -Path $path -NoCompress | Out-Null
    # pretty-print for reviewable diffs
    $pretty = (Read-FsJsonFile -Path $path | ConvertFrom-Json -Depth 64) | ConvertTo-Json -Depth 64
    [System.IO.File]::WriteAllText($path, ($pretty -replace "`r`n", "`n") + "`n", [System.Text.UTF8Encoding]::new($false))
    Write-Host "wrote $path"
}

# ================================================================ FS01
function New-FS01($timestamp, $scanId, $depth, [switch] $Latest) {
    $script:localSid = @{}
    $snap = New-FsSnapshot -ServerName FS01 -Fqdn 'fs01.contoso.local' -MachineSid $M1 -DomainRole 3 -OsVersion '10.0.20348' -RemotePsVersion '5.1.20348.1' `
        -DomainName CONTOSO -DomainSid $D -CredentialUser 'CONTOSO\svc_scan' -Depth $depth -ScanId $scanId -Timestamp ([datetime]::Parse($timestamp).ToUniversalTime()) -ToolVersion '2.0.0'
    $snap.server.scannedFrom = 'WKS01'
    AddCommonPrincipals $snap
    AddDomainPeople $snap -Latest:$Latest

    $fileAdmins = LocalGroup $snap FS01 'FileAdmins' "$M1-1001" 'Server-local file administrators' 2
    $users = LocalGroup $snap FS01 'Users' $SID.BuiltinUsers 'Users are prevented from making accidental or intentional system-wide changes' 3
    $admins = LocalGroup $snap FS01 'Administrators' $SID.BuiltinAdmins 'Administrators have complete and unrestricted access to the computer' 2
    $backupOps = LocalGroup $snap FS01 'Backup Operators' $SID.BackupOps 'Backup Operators can override security restrictions for the sole purpose of backing up or restoring files' 1
    $localAdminId = Get-FsPrincipalId -Sid $SID.FS01LocalAdmin -IsLocal $true -Server FS01 -Name 'Administrator'
    $script:localSid[$localAdminId] = $SID.FS01LocalAdmin
    $snap.principals[$localAdminId] = New-FsPrincipal -Id $localAdminId -Kind LocalUser -Sid $SID.FS01LocalAdmin -Domain FS01 -Name 'Administrator' -Server FS01 -Resolution Local -Local @{ description = 'Built-in account for administering the computer'; enabled = $true } -FetchedAt $snap.timestamp -SourceScanId $snap.scanId

    AddMember $snap $fileAdmins $SID.dave 'LocalDirect' 'Local:FS01'
    AddMember $snap $fileAdmins $SID.LoopA 'LocalDirect' 'Local:FS01'
    AddMember $snap $users $SID.AuthUsers 'LocalDirect' 'Local:FS01'
    AddMember $snap $users $SID.DomainUsers 'LocalDirect' 'Local:FS01'
    AddMember $snap $users $SID.Interactive 'LocalDirect' 'Local:FS01'
    AddMember $snap $admins $SID.DomainAdmins 'LocalDirect' 'Local:FS01'
    AddMember $snap $admins $localAdminId 'LocalDirect' 'Local:FS01'
    AddMember $snap $backupOps $SID.svc_backup 'LocalDirect' 'Local:FS01'

    # orphaned SID referenced on HR\Payroll
    $snap.principals[$SID.Orphan] = New-FsPrincipal -Id $SID.Orphan -Kind OrphanedSid -Sid $SID.Orphan -Resolution Orphaned -ResolutionError 'Not found in CONTOSO; NTAccount translation failed' -FetchedAt $snap.timestamp -SourceScanId $snap.scanId

    # inherited baseline every share root gets from D:\Shares
    $inherited = @(
        (Ace $SID.System $FULL 'Allow' $true),
        (Ace $admins $FULL 'Allow' $true),
        (Ace $users $RX 'Allow' $true),
        (Ace $SID.CreatorOwner $FULL 'Allow' $true $CIOI 'InheritOnly')
    )

    # ---- HR
    $hr = New-FsShare -Server FS01 -Name HR -LocalPath 'D:\Shares\HR' -Description 'Human Resources' -Aces @((ShareAce $SID.AuthUsers $MODIFY))
    $hr.walk = [ordered]@{ foldersVisited = 41; foldersReturned = $(if ($Latest) { 5 } else { 3 }); truncated = $false; maxDepthReached = $depth; seconds = 2.1; status = 'Ok' }
    $snap.shares.Add($hr)
    $snap.folders.Add((New-FsFolder -Server FS01 -LocalPath 'D:\Shares\HR' -ShareNames HR -ShareLocalPath 'D:\Shares\HR' -OwnerPrincipalId $admins -ChildFolderCount 6 -Aces (Indexed (@(
        (Ace $SID.HRShareRW $MODIFY),
        (Ace $SID.HRAll $RX)
    ) + $inherited))))
    $snap.folders.Add((New-FsFolder -Server FS01 -LocalPath 'D:\Shares\HR\Payroll' -ShareNames HR -ShareLocalPath 'D:\Shares\HR' -Depth 1 -ParentLocalPath 'D:\Shares\HR' -NearestDivergentAncestorLocalPath 'D:\Shares\HR' -IsProtected $true -OwnerPrincipalId $SID.dave -ChildFolderCount 2 -Aces (Indexed @(
        (Ace $SID.DomainUsers $WRITEBITS 'Deny'),
        (Ace $SID.HRShareRW $FULL),
        (Ace $SID.Orphan $RX),
        (Ace $SID.System $FULL),
        (Ace $admins $FULL)
    ))))
    $bobMask = if ($Latest) { $MODIFY } else { $RX }
    $snap.folders.Add((New-FsFolder -Server FS01 -LocalPath 'D:\Shares\HR\Payroll\Archive' -ShareNames HR -ShareLocalPath 'D:\Shares\HR' -Depth 2 -ParentLocalPath 'D:\Shares\HR\Payroll' -NearestDivergentAncestorLocalPath 'D:\Shares\HR\Payroll' -OwnerPrincipalId $SID.dave -ChildFolderCount 3 -Aces (Indexed @(
        (Ace $SID.bob $bobMask 'Allow' $false 'None'),
        (Ace $SID.DomainUsers $WRITEBITS 'Deny' $true),
        (Ace $SID.HRShareRW $FULL 'Allow' $true),
        (Ace $SID.Orphan $RX 'Allow' $true),
        (Ace $SID.System $FULL 'Allow' $true),
        (Ace $admins $FULL 'Allow' $true)
    ))))
    if ($Latest) {
        $snap.folders.Add((New-FsFolder -Server FS01 -LocalPath 'D:\Shares\HR\Payroll\Archive\2019' -ShareNames HR -ShareLocalPath 'D:\Shares\HR' -Depth 3 -ParentLocalPath 'D:\Shares\HR\Payroll\Archive' -NearestDivergentAncestorLocalPath 'D:\Shares\HR\Payroll\Archive' -OwnerPrincipalId $SID.dave -ChildFolderCount 0 -Aces (Indexed @(
            (Ace $SID.Everyone $RX),
            (Ace $SID.bob $MODIFY 'Allow' $true),
            (Ace $SID.DomainUsers $WRITEBITS 'Deny' $true),
            (Ace $SID.HRShareRW $FULL 'Allow' $true),
            (Ace $SID.Orphan $RX 'Allow' $true),
            (Ace $SID.System $FULL 'Allow' $true),
            (Ace $admins $FULL 'Allow' $true)
        ))))
        $snap.folders.Add((New-FsFolder -Server FS01 -LocalPath 'D:\Shares\HR\Legal' -ShareNames HR -ShareLocalPath 'D:\Shares\HR' -Depth 1 -ParentLocalPath 'D:\Shares\HR' -NearestDivergentAncestorLocalPath 'D:\Shares\HR' -OwnerPrincipalId $admins -ChildFolderCount 1 -Aces (Indexed (@(
            (Ace $SID.SoloGroup $MODIFY),
            (Ace $SID.HRShareRW $MODIFY 'Allow' $true),
            (Ace $SID.HRAll $RX 'Allow' $true)
        ) + ($inherited | ForEach-Object { Ace $_.principalId $_.rightsMask $_.accessControlType $true $_.inheritanceFlags $_.propagationFlags })))))
    }

    # ---- Finance
    $fin = New-FsShare -Server FS01 -Name Finance -LocalPath 'D:\Shares\Finance' -Description 'Finance department' -Aces @((ShareAce $SID.Everyone $FULL))
    $fin.walk = [ordered]@{ foldersVisited = 88; foldersReturned = 2; truncated = $false; maxDepthReached = $depth; seconds = 3.4; status = 'Ok' }
    $snap.shares.Add($fin)
    $snap.folders.Add((New-FsFolder -Server FS01 -LocalPath 'D:\Shares\Finance' -ShareNames Finance -ShareLocalPath 'D:\Shares\Finance' -OwnerPrincipalId $admins -ChildFolderCount 9 -Aces (Indexed (@(
        (Ace $SID.FinanceRO $RX),
        (Ace $SID.OwnerlessRW $MODIFY)
    ) + $inherited))))
    $snap.folders.Add((New-FsFolder -Server FS01 -LocalPath 'D:\Shares\Finance\Budgets' -ShareNames Finance -ShareLocalPath 'D:\Shares\Finance' -Depth 1 -ParentLocalPath 'D:\Shares\Finance' -NearestDivergentAncestorLocalPath 'D:\Shares\Finance' -OwnerPrincipalId $admins -ChildFolderCount 4 -Aces (Indexed (@(
        (Ace $SID.EmptyGroup $MODIFY),
        (Ace $SID.FinanceRO ($RX -bor 0x40000)),
        (Ace $SID.FinanceRO $RX 'Allow' $true),
        (Ace $SID.OwnerlessRW $MODIFY 'Allow' $true)
    ) + ($inherited | ForEach-Object { Ace $_.principalId $_.rightsMask $_.accessControlType $true $_.inheritanceFlags $_.propagationFlags })))))

    # ---- Temp (previous scan only)
    if (-not $Latest) {
        $tmp = New-FsShare -Server FS01 -Name Temp -LocalPath 'D:\Shares\Temp' -Description 'Scratch' -Aces @((ShareAce $SID.AuthUsers $FULL))
        $tmp.walk = [ordered]@{ foldersVisited = 3; foldersReturned = 1; truncated = $false; maxDepthReached = 1; seconds = 0.2; status = 'Ok' }
        $snap.shares.Add($tmp)
        $snap.folders.Add((New-FsFolder -Server FS01 -LocalPath 'D:\Shares\Temp' -ShareNames Temp -ShareLocalPath 'D:\Shares\Temp' -OwnerPrincipalId $admins -ChildFolderCount 2 -Aces (Indexed (@((Ace $SID.AuthUsers $MODIFY)) + $inherited))))
    }

    Finish $snap $(if ($Latest) { 41 } else { 27 })
    return $snap
}

# ================================================================ FS02
function New-FS02($timestamp, $scanId) {
    $script:localSid = @{}
    $snap = New-FsSnapshot -ServerName FS02 -Fqdn 'fs02.contoso.local' -MachineSid $M2 -DomainRole 3 -OsVersion '10.0.17763' -RemotePsVersion '5.1.17763.5830' `
        -DomainName CONTOSO -DomainSid $D -CredentialUser 'CONTOSO\svc_scan' -Depth 3 -ScanId $scanId -Timestamp ([datetime]::Parse($timestamp).ToUniversalTime()) -ToolVersion '2.0.0'
    $snap.server.scannedFrom = 'WKS01'
    AddCommonPrincipals $snap
    AddDomainPeople $snap -Latest

    $users = LocalGroup $snap FS02 'Users' $SID.BuiltinUsers 'Users are prevented from making accidental or intentional system-wide changes' 2
    $admins = LocalGroup $snap FS02 'Administrators' $SID.BuiltinAdmins 'Administrators have complete and unrestricted access to the computer' 1
    AddMember $snap $users $SID.AuthUsers 'LocalDirect' 'Local:FS02'
    AddMember $snap $users $SID.DomainUsers 'LocalDirect' 'Local:FS02'
    AddMember $snap $admins $SID.DomainAdmins 'LocalDirect' 'Local:FS02'

    $snap.principals[$SID.Foreign] = New-FsPrincipal -Id $SID.Foreign -Kind Foreign -Sid $SID.Foreign -Resolution LookupFailed -ResolutionError 'Trusted domain S-1-5-21-4444444444-5555555555-6666666666 unreachable' -FetchedAt $snap.timestamp -SourceScanId $snap.scanId

    $inherited = @(
        (Ace $SID.System $FULL 'Allow' $true),
        (Ace $admins $FULL 'Allow' $true),
        (Ace $users $RX 'Allow' $true),
        (Ace $SID.CreatorOwner $FULL 'Allow' $true $CIOI 'InheritOnly')
    )

    # ---- Public (share Everyone Change, NTFS Everyone Full -> share is the limiter)
    $pub = New-FsShare -Server FS02 -Name Public -LocalPath 'E:\Public' -Description 'Company-wide drop folder' -Aces @((ShareAce $SID.Everyone $MODIFY))
    $pub.walk = [ordered]@{ foldersVisited = 5000; foldersReturned = 1; truncated = $true; maxDepthReached = 3; seconds = 95.0; status = 'Partial' }
    $snap.shares.Add($pub)
    $snap.folders.Add((New-FsFolder -Server FS02 -LocalPath 'E:\Public' -ShareNames Public -ShareLocalPath 'E:\Public' -OwnerPrincipalId $admins -ChildFolderCount 240 -Aces (Indexed (@((Ace $SID.Everyone $FULL)) + $inherited))))
    $snap.errors.Add((New-FsError -Phase Walk -Scope Public -Path 'E:\Public\Private' -Depth 1 -Kind AccessDenied -Message 'Access to the path is denied.' -ExceptionType 'System.UnauthorizedAccessException'))

    # ---- PublicArchive nested under Public
    $arc = New-FsShare -Server FS02 -Name PublicArchive -LocalPath 'E:\Public\Archive' -Description 'Archive of Public' -Aces @((ShareAce $SID.AuthUsers $RX))
    $arc.walk = [ordered]@{ foldersVisited = 12; foldersReturned = 1; truncated = $false; maxDepthReached = 3; seconds = 0.9; status = 'Ok' }
    $snap.shares.Add($arc)
    $snap.folders.Add((New-FsFolder -Server FS02 -LocalPath 'E:\Public\Archive' -ShareNames PublicArchive -ShareLocalPath 'E:\Public\Archive' -OwnerPrincipalId $admins -ChildFolderCount 11 -Aces (Indexed (@((Ace $SID.Everyone $FULL 'Allow' $true)) + $inherited))))

    # ---- Finance (same share name as FS01)
    $fin = New-FsShare -Server FS02 -Name Finance -LocalPath 'E:\Finance' -Description 'Finance (FS02)' -Aces @((ShareAce $SID.DomainUsers $RX))
    $fin.walk = [ordered]@{ foldersVisited = 30; foldersReturned = 1; truncated = $false; maxDepthReached = 3; seconds = 1.5; status = 'Ok' }
    $snap.shares.Add($fin)
    $snap.folders.Add((New-FsFolder -Server FS02 -LocalPath 'E:\Finance' -ShareNames Finance -ShareLocalPath 'E:\Finance' -OwnerPrincipalId $admins -ChildFolderCount 3 -Aces (Indexed (@(
        (Ace $SID.Deep1 $MODIFY),
        (Ace $SID.FinanceRO $RX),
        (Ace $SID.Foreign $RX)
    ) + $inherited))))

    Finish $snap 103
    return $snap
}

# ================================================================ write
Write-Fixture (New-FS01 '2026-09-01T02:00:00Z' 'aaaaaaaa-0000-4000-8000-000000000001' 2) 'FS01-20260901-aaaaaaaa'
Write-Fixture (New-FS01 '2026-09-08T02:00:00Z' 'bbbbbbbb-0000-4000-8000-000000000002' 3 -Latest) 'FS01-20260908-bbbbbbbb'
Write-Fixture (New-FS02 '2026-09-08T03:00:00Z' 'cccccccc-0000-4000-8000-000000000003') 'FS02-20260908-cccccccc'
