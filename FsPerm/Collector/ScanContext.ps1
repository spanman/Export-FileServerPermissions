<#
Scan context shared by every collector phase.

The context is a plain hashtable (not a class) so it can be inspected in tests and never has to
cross a remoting boundary. Everything the orchestrator learns about the server lands here first
and is assembled into the snapshot at the end of Invoke-FsScan.
#>

function New-FsScanContext {
    <#
    .SYNOPSIS
        Creates the mutable state bag used by one Invoke-FsScan run.
    .PARAMETER Options
        Hashtable of the Invoke-FsScan parameters (Depth, IncludeShare, ExcludeShare, IncludeHiddenShares,
        MaxFoldersPerShare, ChunkSize, NoGroupExpansion, MaxGroupDepth, SkipAdEnrichment, AdServer,
        AdCredential, SeedSnapshot, DryRun, TimeoutSeconds, ExpandPrimaryGroups, SeedMaxAgeHours).
    #>
    [OutputType([hashtable])]
    param(
        [Parameter(Mandatory)] [string] $ServerName,
        [AllowNull()] [pscredential] $Credential,
        [hashtable] $Options = @{}
    )
    $opts = @{
        Depth = 1; IncludeShare = @(); ExcludeShare = @(); IncludeHiddenShares = $false; MaxFoldersPerShare = 100000
        ChunkSize = 1000; NoGroupExpansion = $false; MaxGroupDepth = 10; SkipAdEnrichment = $false; AdServer = $null
        AdCredential = $null; SeedSnapshot = @(); DryRun = $false; TimeoutSeconds = 600; ExpandPrimaryGroups = $false
        SeedMaxAgeHours = 168
    }
    foreach ($k in $Options.Keys) { $opts[$k] = $Options[$k] }

    $srv = $ServerName.ToUpperInvariant()
    $scope = [ordered]@{
        depth = [int]$opts.Depth; includeShare = @($opts.IncludeShare); excludeShare = @($opts.ExcludeShare)
        includeHiddenShares = [bool]$opts.IncludeHiddenShares; maxFoldersPerShare = [int]$opts.MaxFoldersPerShare
        dryRun = [bool]$opts.DryRun; groupExpansion = -not [bool]$opts.NoGroupExpansion; maxGroupDepth = [int]$opts.MaxGroupDepth
        adEnrichment = -not [bool]$opts.SkipAdEnrichment; expandPrimaryGroups = [bool]$opts.ExpandPrimaryGroups
    }
    $credUser = if ($Credential) { $Credential.UserName } else { $null }
    $snapshot = New-FsSnapshot -ServerName $srv -CredentialUser $credUser -Depth ([int]$opts.Depth) -Scope $scope

    $cmp = [System.StringComparer]::OrdinalIgnoreCase
    return @{
        ServerName          = $srv
        Fqdn                = $ServerName
        Credential          = $Credential
        Options             = $opts
        Session             = $null
        SessionRestarts     = 0
        Inventory           = $null
        MachineSid          = $null
        IsDomainController  = $false
        Principals          = [System.Collections.Generic.Dictionary[string, object]]::new($cmp)
        SidTable            = [System.Collections.Generic.Dictionary[string, object]]::new($cmp)   # sid -> @{ name; isLocal }
        PendingSids         = [System.Collections.Generic.HashSet[string]]::new($cmp)
        PendingDns          = [System.Collections.Generic.HashSet[string]]::new($cmp)
        PendingLocal        = [System.Collections.Generic.HashSet[string]]::new($cmp)   # sids deferred to the local-groups phase
        DnToId              = [System.Collections.Generic.Dictionary[string, string]]::new($cmp)
        Memberships         = [System.Collections.Generic.List[object]]::new()
        MembershipKeys      = [System.Collections.Generic.HashSet[string]]::new($cmp)
        Errors              = [System.Collections.Generic.List[object]]::new()
        WarnedKeys          = [System.Collections.Generic.HashSet[string]]::new($cmp)
        Folders             = [System.Collections.Generic.Dictionary[string, object]]::new($cmp)   # folderId -> @{ record; shares(list) }
        LocalGroups         = $null
        DomainTable         = $null            # from Get-FsAdDomainTable
        DomainSids          = [System.Collections.Generic.List[string]]::new()
        AdSearchers         = [System.Collections.Generic.Dictionary[string, object]]::new($cmp)   # domainSid -> searcher wrapper
        AdLookups           = 0
        SeededPrincipalIds  = [System.Collections.Generic.HashSet[string]]::new($cmp)
        Stopwatch           = [System.Diagnostics.Stopwatch]::StartNew()
        Snapshot            = $snapshot
    }
}

function Add-FsScanError {
    <#
    .SYNOPSIS
        Records a non-fatal error on the context/snapshot, marks the scan partial and warns once per phase+scope.
    #>
    [CmdletBinding(DefaultParameterSetName = 'Message')]
    param(
        [Parameter(Mandatory)] [hashtable] $Context,
        [Parameter(Mandatory)] [ValidateSet('Inventory', 'Walk', 'LocalGroups', 'AdResolve', 'Membership', 'Export', 'Other')] [string] $Phase,
        [AllowNull()] [string] $Scope,
        [AllowNull()] [string] $Path,
        [System.Nullable[int]] $Depth,
        [string] $Kind = 'Other',
        [Parameter(Mandatory, ParameterSetName = 'ErrorRecord')] [System.Management.Automation.ErrorRecord] $ErrorRecord,
        [Parameter(Mandatory, ParameterSetName = 'Message')] [string] $Message,
        [AllowNull()] [string] $ExceptionType
    )
    if ($PSCmdlet.ParameterSetName -eq 'ErrorRecord') {
        $ex = $ErrorRecord.Exception
        $Message = if ($ex) { $ex.Message } else { [string]$ErrorRecord }
        if (-not $ExceptionType -and $ex) { $ExceptionType = $ex.GetType().FullName }
        if ($Kind -eq 'Other') { $Kind = Get-FsErrorKind -ExceptionType $ExceptionType -Message $Message }
    }
    if (-not $Message) { $Message = 'Unknown error' }
    $err = New-FsError -Phase $Phase -Scope $Scope -Path $Path -Depth $Depth -Kind $Kind -Message $Message -ExceptionType $ExceptionType
    $Context.Errors.Add($err)
    $Context.Snapshot.errors.Add($err)
    $Context.Snapshot.status.partial = $true

    $key = '{0}|{1}' -f $Phase, $Scope
    if ($Context.WarnedKeys.Add($key)) {
        $where = if ($Scope) { "$Phase/$Scope" } else { $Phase }
        Write-Warning ("[{0}] {1}{2}" -f $where, $(if ($Path) { "$Path : " } else { '' }), $Message)
    }
    else {
        Write-Verbose ("[{0}/{1}] {2}{3}" -f $Phase, $Scope, $(if ($Path) { "$Path : " } else { '' }), $Message)
    }
    return $err
}

function Get-FsErrorKind {
    <# Maps an exception type / message to the error kind vocabulary used in reports. #>
    [OutputType([string])]
    param([AllowNull()] [string] $ExceptionType, [AllowNull()] [string] $Message)
    $t = [string]$ExceptionType
    $m = [string]$Message
    if ($t -match 'UnauthorizedAccess' -or $m -match 'denied') { return 'AccessDenied' }
    if ($t -match 'PathTooLong' -or $m -match 'too long') { return 'PathTooLong' }
    if ($t -match 'DirectoryNotFound|FileNotFound' -or $m -match 'not found|does not exist|cannot find') { return 'NotFound' }
    if ($t -match 'PSRemotingTransport|Remoting' -or $m -match 'WinRM|remote session') { return 'Remoting' }
    if ($t -match 'DirectoryServices|COMException' -or $m -match 'server is not operational|referral') { return 'Directory' }
    if ($t -match 'TimeoutException' -or $m -match 'timed out') { return 'Timeout' }
    return 'Other'
}

function Set-FsScanPhase {
    <# Records a phase status (Ok | Partial | Failed | Skipped) on the snapshot. #>
    param(
        [Parameter(Mandatory)] [hashtable] $Context,
        [Parameter(Mandatory)] [string] $Name,
        [Parameter(Mandatory)] [ValidateSet('Ok', 'Partial', 'Failed', 'Skipped', 'Running')] [string] $Status
    )
    $Context.Snapshot.status.phases[$Name] = $Status
}

function Get-FsPhaseStatus {
    <# Ok when no error of that phase was recorded, otherwise Partial. #>
    [OutputType([string])]
    param([Parameter(Mandatory)] [hashtable] $Context, [Parameter(Mandatory)] [string] $Phase)
    $n = @($Context.Errors | Where-Object { $_.phase -eq $Phase }).Count
    if ($n -gt 0) { return 'Partial' }
    return 'Ok'
}

function Add-FsContextPrincipal {
    <# Adds a principal to the context cache unless an entry with that id already exists; returns the stored record. #>
    [OutputType([pscustomobject])]
    param([Parameter(Mandatory)] [hashtable] $Context, [Parameter(Mandatory)] $Principal, [switch] $Replace)
    $id = [string](Get-FsValue $Principal 'id')
    if ($Replace -or -not $Context.Principals.ContainsKey($id)) { $Context.Principals[$id] = $Principal }
    return $Context.Principals[$id]
}

function Add-FsContextMembership {
    <# Adds a membership edge once (groupId|memberId|kind). #>
    param(
        [Parameter(Mandatory)] [hashtable] $Context,
        [Parameter(Mandatory)] [string] $GroupId,
        [Parameter(Mandatory)] [string] $MemberId,
        [ValidateSet('Direct', 'PrimaryGroup', 'LocalDirect')] [string] $Kind = 'Direct',
        [string] $Source = 'AD'
    )
    $key = '{0}|{1}|{2}' -f $GroupId, $MemberId, $Kind
    if ($Context.MembershipKeys.Add($key)) {
        $Context.Memberships.Add((New-FsMembership -GroupId $GroupId -MemberId $MemberId -Kind $Kind -Source $Source))
    }
}

function Get-FsContextNow {
    <# ISO UTC timestamp for fetchedAt fields. #>
    [OutputType([string])]
    param()
    return (Get-Date).ToUniversalTime().ToString('o')
}
