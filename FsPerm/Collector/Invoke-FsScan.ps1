<#
Collector orchestrator: one WinRM session per server, driving inventory, the NTFS walk, local-group enumeration
and AD resolution/membership expansion in order, and assembling the result into a Fs.Snapshot object.

Phase order: (1) context, (2) session, (3) inventory + share objects, (4) domain discovery, (5) walk (skipped by
-DryRun), (6) SID classification, (7) local groups, (8) AD SID resolution, (9) group membership expansion,
(10) manager/managedBy reference resolution, (11) assemble. Steps 7-10 are skipped by -SkipAdEnrichment; step 9
is additionally skipped by -NoGroupExpansion. -DryRun stops after step 4.
#>

function Invoke-FsScan {
    <#
    .SYNOPSIS
        Scans one Windows file server's shares, NTFS ACLs and AD group membership into a snapshot object.
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)] [string] $ServerName,
        [Parameter(Mandatory)] [pscredential] $Credential,
        [ValidateRange(0, 32)] [int] $Depth = 1,
        [string[]] $IncludeShare = @(),
        [string[]] $ExcludeShare = @(),
        [switch] $IncludeHiddenShares,
        [int] $MaxFoldersPerShare = 100000,
        [int] $ChunkSize = 1000,
        [switch] $NoGroupExpansion,
        [int] $MaxGroupDepth = 10,
        [switch] $SkipAdEnrichment,
        [string] $AdServer,
        [pscredential] $AdCredential,
        [string[]] $SeedSnapshot = @(),
        [int] $SeedMaxAgeHours = 24,
        [switch] $DryRun,
        [int] $TimeoutSeconds = 600,
        [switch] $ExpandPrimaryGroups
    )

    $optionsHash = @{
        Depth = $Depth; IncludeShare = @($IncludeShare); ExcludeShare = @($ExcludeShare); IncludeHiddenShares = [bool]$IncludeHiddenShares
        MaxFoldersPerShare = $MaxFoldersPerShare; ChunkSize = $ChunkSize; NoGroupExpansion = [bool]$NoGroupExpansion; MaxGroupDepth = $MaxGroupDepth
        SkipAdEnrichment = [bool]$SkipAdEnrichment; AdServer = $AdServer; AdCredential = $AdCredential; SeedSnapshot = @($SeedSnapshot)
        SeedMaxAgeHours = $SeedMaxAgeHours
        DryRun = [bool]$DryRun; TimeoutSeconds = $TimeoutSeconds; ExpandPrimaryGroups = [bool]$ExpandPrimaryGroups
    }
    $context = New-FsScanContext -ServerName $ServerName -Credential $Credential -Options $optionsHash
    Import-FsSeedPrincipals -Context $context

    $phaseNames = 'inventory', 'walk', 'localGroups', 'adResolve', 'membership'
    $phaseIndex = 0
    function Show-FsScanPhaseProgress {
        param([Parameter(Mandatory)] [string] $Name, [Parameter(Mandatory)] [ref] $Index, [Parameter(Mandatory)] [int] $Total, [Parameter(Mandatory)] [string] $Server)
        $Index.Value++
        Write-Progress -Id 1 -Activity "Scanning $Server" -Status $Name -PercentComplete ([int](100.0 * $Index.Value / $Total))
    }

    $sessionOption = New-PSSessionOption -IdleTimeout 3600000 -OperationTimeout ([long][Math]::Max($TimeoutSeconds, 60) * 1000)
    $context.Session = New-PSSession -ComputerName $ServerName -Credential $Credential -SessionOption $sessionOption -ErrorAction Stop

    try {
        # ---- 3. inventory
        Set-FsScanPhase -Context $context -Name 'inventory' -Status Running
        Write-Progress -Id 1 -Activity "Scanning $ServerName" -Status 'inventory' -PercentComplete 0
        Write-Verbose "Collecting share inventory from $ServerName"
        $invResult = Invoke-Command -Session $context.Session -ScriptBlock $script:FsRemoteInventory -ArgumentList @([bool]$context.Options.IncludeHiddenShares) -ErrorAction Stop
        $shareInfos = Import-FsInventoryResult -Context $context -Result $invResult
        $shares = [System.Collections.Generic.List[object]]::new()
        foreach ($si in $shareInfos) {
            $aceObjs = [System.Collections.Generic.List[object]]::new()
            foreach ($a in @(Get-FsValue $si 'aces')) {
                $sidStr = [string](Get-FsValue $a 'sid')
                if (-not $sidStr) { continue }
                $entry = Get-FsSidTableEntry -SidTable $context.SidTable -Sid $sidStr
                $principalId = Get-FsSidPrincipalId -Sid $sidStr -SidTable $context.SidTable -Server $context.ServerName
                $aceObjs.Add((New-FsShareAce -PrincipalId $principalId -Sid $sidStr -AccessMask ([long](Get-FsValue $a 'accessMask')) `
                    -AccessControlType ([string](Get-FsValue $a 'accessControlType')) -NameOnServer ([string]$entry.name)))
            }
            $shares.Add((New-FsShare -Server $context.ServerName -Name ([string](Get-FsValue $si 'name')) -LocalPath ([string](Get-FsValue $si 'path')) `
                -Description ([string](Get-FsValue $si 'description')) -IsHidden ([bool](Get-FsValue $si 'isHidden')) -Aces @($aceObjs)))
        }
        Set-FsScanPhase -Context $context -Name 'inventory' -Status (Get-FsPhaseStatus -Context $context -Phase Inventory)

        # ---- 4. domain discovery
        if (-not $context.Options.SkipAdEnrichment) {
            try {
                $context.DomainTable = Get-FsAdDomainTable -Server $context.Options.AdServer -Credential $context.Options.AdCredential
                $context.Snapshot.domain.name = $context.DomainTable.Primary.dns
                $context.Snapshot.domain.sid = $context.DomainTable.Primary.sid
                foreach ($dsid in $context.DomainTable.Domains.Keys) { [void]$context.DomainSids.Add($dsid) }
                if ($context.DomainTable.Primary.sidDegraded) {
                    # A degraded domain SID (the domain's DN used as a stand-in key) breaks every downstream
                    # domain-scoped SID classification and lookup, so this is surfaced as a real scan error -
                    # not just Write-Verbose - so it shows up in Reports/16-ScanHealth and is diagnosable from
                    # the snapshot alone, without needing -Verbose output captured live.
                    $diagText = (@($context.DomainTable.Primary.sidDiagnostics) -join ' | ')
                    Add-FsScanError -Context $context -Phase AdResolve -Scope 'DomainDiscovery' -Kind Directory `
                        -Message "Could not read the domain object's objectSid for '$($context.DomainTable.Primary.dn)'; using its distinguished name as a stand-in key instead. Every principal's domain SID classification and AD lookup depends on this value being correct, so results from this scan are likely to be almost entirely unresolved (Foreign/OrphanedSid) rather than proper User/Group records. Diagnostics: $diagText" | Out-Null
                }
            }
            catch { Add-FsScanError -Context $context -Phase AdResolve -Scope 'DomainDiscovery' -ErrorRecord $_ | Out-Null }
        }

        if ($context.Options.DryRun) {
            $context.Snapshot.scope.dryRun = $true
            foreach ($p in 'walk', 'localGroups', 'adResolve', 'membership') { Set-FsScanPhase -Context $context -Name $p -Status Skipped }
        }
        else {
            # ---- 5. walk
            Set-FsScanPhase -Context $context -Name 'walk' -Status Running
            Show-FsScanPhaseProgress -Name 'walk' -Index ([ref]$phaseIndex) -Total $phaseNames.Count -Server $ServerName
            $allSidSeen = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
            foreach ($s in $context.PendingSids) { [void]$allSidSeen.Add($s) }

            $shareIdx = 0
            foreach ($share in $shares) {
                $shareIdx++
                Write-Progress -Id 2 -ParentId 1 -Activity 'Walking shares' -Status $share.name -PercentComplete ([int](100.0 * $shareIdx / [Math]::Max(@($shares).Count, 1)))
                Write-Verbose "Walking share '$($share.name)' ($($share.localPath))"
                $shareHadError = $false
                try {
                    $walkOutput = Invoke-Command -Session $context.Session -ScriptBlock $script:FsRemoteWalk `
                        -ArgumentList @($share.localPath, $context.Options.Depth, $context.Options.ChunkSize, $context.Options.MaxFoldersPerShare, $context.MachineSid, $context.IsDomainController) -ErrorAction Stop
                    foreach ($item in @($walkOutput)) {
                        $type = [string](Get-FsValue $item 'type')
                        if ($type -eq 'chunk') {
                            foreach ($rec in @(ConvertFrom-Json -InputObject ([string](Get-FsValue $item 'foldersJson')))) {
                                $localPath = [string](Get-FsValue $rec 'localPath')
                                $folderId = Get-FsFolderId -Server $context.ServerName -LocalPath $localPath
                                if ($context.Folders.ContainsKey($folderId)) {
                                    $existing = $context.Folders[$folderId]
                                    if (@($existing.shareNames) -notcontains $share.name) {
                                        $existing.shareNames = [string[]]@(Get-FsSorted -InputObject (@($existing.shareNames) + $share.name) -Unique)
                                    }
                                }
                                else {
                                    $context.Folders[$folderId] = ConvertFrom-FsRemoteFolder -Record $rec -Server $context.ServerName `
                                        -ShareName @($share.name) -ShareLocalPath $share.localPath -SidTable $context.SidTable
                                }
                                foreach ($ace in @(Get-FsValue $rec 'aces')) { $s = [string](Get-FsValue $ace 'sid'); if ($s) { [void]$allSidSeen.Add($s) } }
                                $ownerSid = [string](Get-FsValue $rec 'ownerSid'); if ($ownerSid) { [void]$allSidSeen.Add($ownerSid) }
                            }
                        }
                        elseif ($type -eq 'summary') {
                            Merge-FsSidTable -Context $context -Table (ConvertFrom-Json -InputObject ([string](Get-FsValue $item 'sidTable')))
                            foreach ($e in @(ConvertFrom-Json -InputObject ([string](Get-FsValue $item 'errorsJson')))) {
                                $shareHadError = $true
                                $d = Get-FsValue $e 'depth'
                                Add-FsScanError -Context $context -Phase Walk -Scope $share.name -Path ([string](Get-FsValue $e 'path')) `
                                    -Depth $(if ($null -ne $d) { [int]$d } else { $null }) -Kind ([string](Get-FsValue $e 'kind')) `
                                    -Message ([string](Get-FsValue $e 'message')) -ExceptionType ([string](Get-FsValue $e 'exceptionType')) | Out-Null
                            }
                            $share.walk.foldersVisited = [int](Get-FsValue $item 'visited')
                            $share.walk.foldersReturned = [int](Get-FsValue $item 'returned')
                            $share.walk.truncated = [bool](Get-FsValue $item 'truncated')
                            $share.walk.maxDepthReached = [int](Get-FsValue $item 'maxDepthReached')
                            $share.walk.seconds = [double](Get-FsValue $item 'seconds')
                            $share.walk.status = $(if ($shareHadError) { 'Partial' } else { 'Ok' })
                        }
                    }
                }
                catch {
                    Add-FsScanError -Context $context -Phase Walk -Scope $share.name -ErrorRecord $_ | Out-Null
                    $share.walk.status = 'Failed'
                    if ($context.SessionRestarts -eq 0) {
                        try {
                            Remove-PSSession -Session $context.Session -ErrorAction SilentlyContinue
                            $context.Session = New-PSSession -ComputerName $context.ServerName -Credential $context.Credential -SessionOption $sessionOption -ErrorAction Stop
                            $context.SessionRestarts++
                            Write-Verbose "Recreated the WinRM session to $($context.ServerName) after a walk failure."
                        }
                        catch { Add-FsScanError -Context $context -Phase Walk -Kind Remoting -ErrorRecord $_ | Out-Null }
                    }
                }
            }
            Write-Progress -Id 2 -ParentId 1 -Completed -Activity 'Walking shares'
            Set-FsScanPhase -Context $context -Name 'walk' -Status (Get-FsPhaseStatus -Context $context -Phase Walk)

            # ---- 6. classify every unique SID seen (share + folder ACEs, owners)
            $localSids = [System.Collections.Generic.List[string]]::new()
            $pendingDomainSids = [System.Collections.Generic.List[string]]::new()
            foreach ($s in @($allSidSeen)) {
                if ($context.Principals.ContainsKey($s)) { continue }
                $class = Get-FsSidClass -Sid $s -DomainSids @($context.DomainSids) -MachineSid $context.MachineSid
                $sidTableLocal = $context.SidTable.ContainsKey($s) -and [bool]$context.SidTable[$s].isLocal
                if ($class -in 'WellKnown', 'Capability', 'Service') { Add-FsWellKnownPrincipal -Context $context -Sid $s; continue }
                if ($class -eq 'Builtin') {
                    if ($context.IsDomainController) { Add-FsWellKnownPrincipal -Context $context -Sid $s }
                    else { [void]$context.PendingLocal.Add($s); $localSids.Add($s) }
                    continue
                }
                if ($class -eq 'MachineAccount' -or $sidTableLocal) { [void]$context.PendingLocal.Add($s); $localSids.Add($s); continue }
                $pendingDomainSids.Add($s)   # DomainAccount, or Unknown (Resolve-FsPrincipal reclassifies and falls back safely)
            }

            if (-not $context.Options.SkipAdEnrichment) {
                # ---- 7. local groups
                Set-FsScanPhase -Context $context -Name 'localGroups' -Status Running
                Show-FsScanPhaseProgress -Name 'localGroups' -Index ([ref]$phaseIndex) -Total $phaseNames.Count -Server $ServerName
                if ($context.IsDomainController) {
                    Write-Verbose 'Server is a domain controller; local-group enumeration does not apply.'
                    Set-FsScanPhase -Context $context -Name 'localGroups' -Status Skipped
                }
                elseif (@($localSids).Count -eq 0) {
                    Set-FsScanPhase -Context $context -Name 'localGroups' -Status Ok
                }
                else {
                    try {
                        $lgResult = Invoke-Command -Session $context.Session -ScriptBlock $script:FsRemoteLocalGroups `
                            -ArgumentList @($localSids.ToArray(), $context.IsDomainController, $context.MachineSid) -ErrorAction Stop
                        Import-FsLocalGroupResult -Context $context -Result $lgResult | Out-Null
                        Set-FsScanPhase -Context $context -Name 'localGroups' -Status (Get-FsPhaseStatus -Context $context -Phase LocalGroups)
                    }
                    catch {
                        Add-FsScanError -Context $context -Phase LocalGroups -ErrorRecord $_ | Out-Null
                        Set-FsScanPhase -Context $context -Name 'localGroups' -Status Partial
                    }
                }
                # local group members that are themselves domain SIDs join the domain-resolution queue
                foreach ($s in @($context.PendingSids)) {
                    if (-not $context.Principals.ContainsKey($s) -and -not $pendingDomainSids.Contains($s)) { $pendingDomainSids.Add($s) }
                }

                # ---- 8. AD SID resolution
                Set-FsScanPhase -Context $context -Name 'adResolve' -Status Running
                Show-FsScanPhaseProgress -Name 'adResolve' -Index ([ref]$phaseIndex) -Total $phaseNames.Count -Server $ServerName
                if (@($pendingDomainSids).Count -gt 0) {
                    Write-Verbose "Resolving $(@($pendingDomainSids).Count) domain SID(s) via AD."
                    Resolve-FsPrincipal -Context $context -Sid @($pendingDomainSids)
                }
                Set-FsScanPhase -Context $context -Name 'adResolve' -Status (Get-FsPhaseStatus -Context $context -Phase AdResolve)

                # ---- 9. group membership expansion
                if (-not $context.Options.NoGroupExpansion) {
                    Set-FsScanPhase -Context $context -Name 'membership' -Status Running
                    Show-FsScanPhaseProgress -Name 'membership' -Index ([ref]$phaseIndex) -Total $phaseNames.Count -Server $ServerName
                    Expand-FsGroupMembership -Context $context -MaxDepth $context.Options.MaxGroupDepth -ExpandPrimaryGroups:$context.Options.ExpandPrimaryGroups
                    Set-FsScanPhase -Context $context -Name 'membership' -Status (Get-FsPhaseStatus -Context $context -Phase Membership)
                }
                else { Set-FsScanPhase -Context $context -Name 'membership' -Status Skipped }

                # ---- 10. manager / managedBy references
                Resolve-FsManagerReferences -Context $context
            }
            else {
                foreach ($p in 'localGroups', 'adResolve', 'membership') { Set-FsScanPhase -Context $context -Name $p -Status Skipped }
            }
        }

        # ---- 11. assemble
        $snap = $context.Snapshot
        foreach ($share in (Get-FsSorted -InputObject @($shares) -Property 'name')) { $snap.shares.Add($share) }
        foreach ($fid in Get-FsSortedKeys $context.Folders) { $snap.folders.Add($context.Folders[$fid]) }
        foreach ($pid2 in Get-FsSortedKeys $context.Principals) { $snap.principals[$pid2] = $context.Principals[$pid2] }
        foreach ($m in (Get-FsSorted -InputObject @($context.Memberships) -Property 'groupId', 'memberId', 'kind')) { $snap.memberships.Add($m) }
        $snap.completedAt = (Get-Date).ToUniversalTime().ToString('o')
        $snap.durationSeconds = [math]::Round($context.Stopwatch.Elapsed.TotalSeconds, 2)
        $snap.status.partial = (@($snap.errors).Count -gt 0)
        $snap.stats = [ordered]@{
            shares          = $snap.shares.Count
            foldersVisited  = (@($snap.shares) | ForEach-Object { $_.walk.foldersVisited } | Measure-Object -Sum).Sum
            foldersReturned = $snap.folders.Count
            principals      = $snap.principals.Count
            memberships     = $snap.memberships.Count
            errors          = $snap.errors.Count
        }
        return $snap
    }
    finally {
        Write-Progress -Id 1 -Completed -Activity "Scanning $ServerName"
        if ($context.Session) { Remove-PSSession -Session $context.Session -ErrorAction SilentlyContinue }
    }
}

function Import-FsSeedPrincipals {
    <#
    .SYNOPSIS
        Preloads principals from prior snapshots (-SeedSnapshot) younger than SeedMaxAgeHours so a fleet run
        avoids re-resolving the same accounts against AD for every server.
    #>
    param([Parameter(Mandatory)] [hashtable] $Context)
    $paths = @($Context.Options.SeedSnapshot)
    if ($paths.Count -eq 0) { return }
    $cutoff = (Get-Date).ToUniversalTime().AddHours(-1 * [double]$Context.Options.SeedMaxAgeHours)
    foreach ($seedPath in $paths) {
        try {
            $seedSnap = Import-FsSnapshot -Path $seedPath
            foreach ($id in @($seedSnap.principals.Keys)) {
                if ($Context.Principals.ContainsKey($id)) { continue }
                $sp = $seedSnap.principals[$id]
                $fetchedAt = $null
                try { $fetchedAt = [datetimeoffset]::Parse([string](Get-FsValue $sp 'fetchedAt'), [cultureinfo]::InvariantCulture).UtcDateTime } catch { $fetchedAt = $null }
                if ($fetchedAt -and $fetchedAt -lt $cutoff) { continue }
                $Context.Principals[$id] = $sp
                [void]$Context.SeededPrincipalIds.Add($id)
            }
        }
        catch { Add-FsScanError -Context $Context -Phase Other -Scope 'SeedSnapshot' -Message "Failed to load seed snapshot '$seedPath': $($_.Exception.Message)" -ExceptionType $_.Exception.GetType().FullName | Out-Null }
    }
}

function Get-FsScanSummary {
    <#
    .SYNOPSIS
        Human-readable summary lines for the console after a scan (counts, duration, partial/truncated warnings).
    #>
    [OutputType([string[]])]
    param([Parameter(Mandatory)] $Snapshot)
    $lines = [System.Collections.Generic.List[string]]::new()
    $stats = Get-FsValue $Snapshot 'stats'
    $status = Get-FsValue $Snapshot 'status'
    $lines.Add(("Shares: {0}   Folders: {1}   Principals: {2}   Memberships: {3}   Errors: {4}" -f `
        (Get-FsValue $stats 'shares'), (Get-FsValue $stats 'foldersReturned'), (Get-FsValue $stats 'principals'), (Get-FsValue $stats 'memberships'), (Get-FsValue $stats 'errors')))
    $duration = Get-FsValue $Snapshot 'durationSeconds'
    if ($null -ne $duration) { $lines.Add("Duration: $([math]::Round([double]$duration, 1))s") }
    if ([bool](Get-FsValue $status 'partial')) { $lines.Add("Status: PARTIAL (see errors[] in the snapshot; $(Get-FsValue $stats 'errors') recorded)") }
    else { $lines.Add('Status: Ok') }
    foreach ($share in @(Get-FsValue $Snapshot 'shares')) {
        $walk = Get-FsValue $share 'walk'
        if ($walk -and [bool](Get-FsValue $walk 'truncated')) { $lines.Add("Truncated: share '$(Get-FsValue $share 'name')' hit its folder limit; results are incomplete.") }
    }
    if ([bool](Get-FsValue (Get-FsValue $Snapshot 'scope') 'dryRun')) { $lines.Add('Dry run: no NTFS folder walk was performed.') }
    return @($lines)
}
