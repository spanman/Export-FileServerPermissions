<#
Remote inventory: server facts + shares with SID-based share ACEs.

$script:FsRemoteInventory runs INSIDE the WinRM session and must stay Windows PowerShell 5.1
compatible (no ?? ?. ternary, no -AsHashtable, no PS7-only parameters). It returns a single
PSCustomObject whose collection-valued members are compact JSON strings, so nothing but scalars
crosses the serializer.

Import-FsInventoryResult runs on the workstation and folds the result into the scan context.
#>

$script:FsRemoteInventory = {
    param($IncludeHiddenShares)

    $errors = New-Object System.Collections.ArrayList
    function Add-InventoryError {
        param($Scope, $Message, $Type)
        [void]$errors.Add(@{ scope = $Scope; message = [string]$Message; exceptionType = [string]$Type })
    }

    # ---- computer system facts
    $cs = $null; $os = $null
    try { $cs = Get-CimInstance -ClassName Win32_ComputerSystem -ErrorAction Stop } catch { Add-InventoryError 'Win32_ComputerSystem' $_.Exception.Message $_.Exception.GetType().FullName }
    try { $os = Get-CimInstance -ClassName Win32_OperatingSystem -ErrorAction Stop } catch { Add-InventoryError 'Win32_OperatingSystem' $_.Exception.Message $_.Exception.GetType().FullName }

    $computerName = $env:COMPUTERNAME
    $domainRole = $null; $domainName = $null; $partOfDomain = $false; $fqdn = $computerName
    if ($cs) {
        $domainRole = [int]$cs.DomainRole
        $domainName = [string]$cs.Domain
        $partOfDomain = [bool]$cs.PartOfDomain
        if ($cs.DNSHostName) { $fqdn = [string]$cs.DNSHostName }
        if ($partOfDomain -and $domainName -and $fqdn -notlike "*.$domainName") { $fqdn = "$fqdn.$domainName" }
    }
    else {
        try { $fqdn = [System.Net.Dns]::GetHostEntry($computerName).HostName } catch { $fqdn = $computerName }
    }
    $osVersion = $null; $osCaption = $null
    if ($os) { $osVersion = [string]$os.Version; $osCaption = [string]$os.Caption }
    else { $osVersion = [System.Environment]::OSVersion.Version.ToString() }
    $isDc = ($domainRole -eq 4 -or $domainRole -eq 5)

    # ---- machine SID: Get-LocalUser, then WinNT provider, then Win32_UserAccount
    $machineSid = $null
    if (-not $isDc) {
        try {
            $lu = @(Get-LocalUser -ErrorAction Stop | Select-Object -First 1)
            if ($lu.Count -gt 0 -and $lu[0].SID -and $lu[0].SID.AccountDomainSid) { $machineSid = $lu[0].SID.AccountDomainSid.Value }
        }
        catch { Add-InventoryError 'MachineSid/Get-LocalUser' $_.Exception.Message $_.Exception.GetType().FullName }
        if (-not $machineSid) {
            try {
                $comp = [ADSI]"WinNT://$computerName,computer"
                foreach ($child in $comp.Children) {
                    if ($child.SchemaClassName -ne 'User') { continue }
                    $bytes = $child.InvokeGet('objectSid')
                    $sidObj = New-Object System.Security.Principal.SecurityIdentifier($bytes, 0)
                    if ($sidObj.AccountDomainSid) { $machineSid = $sidObj.AccountDomainSid.Value; break }
                }
            }
            catch { Add-InventoryError 'MachineSid/WinNT' $_.Exception.Message $_.Exception.GetType().FullName }
        }
        if (-not $machineSid) {
            try {
                $acct = @(Get-CimInstance -ClassName Win32_UserAccount -Filter 'LocalAccount=True' -ErrorAction Stop | Select-Object -First 1)
                if ($acct.Count -gt 0 -and $acct[0].SID) {
                    $sidObj = New-Object System.Security.Principal.SecurityIdentifier($acct[0].SID)
                    if ($sidObj.AccountDomainSid) { $machineSid = $sidObj.AccountDomainSid.Value }
                }
            }
            catch { Add-InventoryError 'MachineSid/Win32_UserAccount' $_.Exception.Message $_.Exception.GetType().FullName }
        }
    }
    else {
        # On a domain controller the "local" SAM is the domain itself.
        try {
            $sidObj = (New-Object System.Security.Principal.NTAccount("$domainName\Administrator")).Translate([System.Security.Principal.SecurityIdentifier])
            if ($sidObj.AccountDomainSid) { $machineSid = $sidObj.AccountDomainSid.Value }
        }
        catch { Add-InventoryError 'MachineSid/DC' $_.Exception.Message $_.Exception.GetType().FullName }
    }

    # ---- SID -> name cache (isLocal = machine SID prefix or BUILTIN, never on a DC)
    $sidTable = @{}
    function Add-SidEntry {
        param($SidString)
        if (-not $SidString) { return }
        if ($sidTable.ContainsKey($SidString)) { return }
        $name = $null
        $isLocal = $false
        try {
            $sidObj = New-Object System.Security.Principal.SecurityIdentifier($SidString)
            if (-not $isDc) {
                if ($SidString -like 'S-1-5-32-*') { $isLocal = $true }
                elseif ($machineSid -and $sidObj.AccountDomainSid -and $sidObj.AccountDomainSid.Value -eq $machineSid) { $isLocal = $true }
            }
            try { $name = $sidObj.Translate([System.Security.Principal.NTAccount]).Value } catch { $name = $null }
        }
        catch { $name = $null }
        $sidTable[$SidString] = @{ name = $name; isLocal = $isLocal }
    }

    # ---- SDDL -> ACE list
    function ConvertFrom-ShareSddl {
        param($Sddl)
        $aces = New-Object System.Collections.ArrayList
        if (-not $Sddl) { return $aces }
        $rsd = New-Object System.Security.AccessControl.RawSecurityDescriptor($Sddl)
        if ($null -eq $rsd.DiscretionaryAcl) { return $aces }
        foreach ($ace in $rsd.DiscretionaryAcl) {
            if ($ace -isnot [System.Security.AccessControl.KnownAce]) { continue }
            $qualifier = $null
            if ($ace -is [System.Security.AccessControl.QualifiedAce]) { $qualifier = $ace.AceQualifier.ToString() }
            $type = $null
            if ($qualifier -eq 'AccessAllowed') { $type = 'Allow' } elseif ($qualifier -eq 'AccessDenied') { $type = 'Deny' } else { continue }
            $sidString = $ace.SecurityIdentifier.Value
            Add-SidEntry $sidString
            [void]$aces.Add(@{ sid = $sidString; accessMask = [int64]([uint32]$ace.AccessMask); accessControlType = $type })
        }
        return $aces
    }

    # ---- shares
    $shares = New-Object System.Collections.ArrayList
    $shareSource = $null
    $smb = $null
    try { $smb = @(Get-SmbShare -ErrorAction Stop); $shareSource = 'Get-SmbShare' }
    catch { Add-InventoryError 'Get-SmbShare' $_.Exception.Message $_.Exception.GetType().FullName; $smb = $null }

    if ($null -ne $smb) {
        foreach ($s in $smb) {
            if ($s.Special) { continue }
            if ($s.ShareType -and ([string]$s.ShareType) -ne 'FileSystemDirectory') { continue }
            if (-not $s.Path) { continue }
            $hidden = [bool]($s.Name -like '*$')
            if ($hidden -and -not $IncludeHiddenShares) { continue }
            $aces = New-Object System.Collections.ArrayList
            $sddl = [string]$s.SecurityDescriptor
            try { $aces = ConvertFrom-ShareSddl $sddl } catch { Add-InventoryError "Share/$($s.Name)" "SDDL parse failed: $($_.Exception.Message)" $_.Exception.GetType().FullName }
            [void]$shares.Add(@{
                name = [string]$s.Name; path = [string]$s.Path; description = [string]$s.Description; isHidden = $hidden
                sddl = $sddl; aces = @($aces); source = 'Get-SmbShare'
            })
        }
    }
    else {
        try {
            $wmiShares = @(Get-CimInstance -ClassName Win32_Share -ErrorAction Stop)
            $shareSource = 'Win32_Share'
            foreach ($s in $wmiShares) {
                if ([int64]$s.Type -ne 0) { continue }            # 0 = disk drive; admin shares carry 0x80000000
                if (-not $s.Path) { continue }
                $hidden = [bool]($s.Name -like '*$')
                if ($hidden -and -not $IncludeHiddenShares) { continue }
                $aces = New-Object System.Collections.ArrayList
                $sddl = $null
                try {
                    $lsss = Get-CimInstance -ClassName Win32_LogicalShareSecuritySetting -Filter ("Name='{0}'" -f $s.Name.Replace("'", "\'")) -ErrorAction Stop
                    if ($lsss) {
                        $sd = (Invoke-CimMethod -InputObject $lsss -MethodName GetSecurityDescriptor -ErrorAction Stop).Descriptor
                        if ($sd -and $sd.DACL) {
                            foreach ($ace in $sd.DACL) {
                                $type = $null
                                if ([int]$ace.AceType -eq 0) { $type = 'Allow' } elseif ([int]$ace.AceType -eq 1) { $type = 'Deny' } else { continue }
                                $sidString = [string]$ace.Trustee.SIDString
                                if (-not $sidString) { continue }
                                Add-SidEntry $sidString
                                [void]$aces.Add(@{ sid = $sidString; accessMask = [int64]([uint32]$ace.AccessMask); accessControlType = $type })
                            }
                        }
                    }
                }
                catch { Add-InventoryError "Share/$($s.Name)" "Win32_LogicalShareSecuritySetting failed: $($_.Exception.Message)" $_.Exception.GetType().FullName }
                [void]$shares.Add(@{
                    name = [string]$s.Name; path = [string]$s.Path; description = [string]$s.Description; isHidden = $hidden
                    sddl = $sddl; aces = @($aces); source = 'Win32_Share'
                })
            }
        }
        catch { Add-InventoryError 'Win32_Share' $_.Exception.Message $_.Exception.GetType().FullName }
    }

    [pscustomobject]@{
        computerName = $computerName
        fqdn         = $fqdn
        machineSid   = $machineSid
        domainRole   = $domainRole
        domainName   = $domainName
        partOfDomain = $partOfDomain
        osVersion    = $osVersion
        osCaption    = $osCaption
        psVersion    = $PSVersionTable.PSVersion.ToString()
        psEdition    = [string]$PSVersionTable.PSEdition
        shareSource  = $shareSource
        shares       = (ConvertTo-Json -InputObject @($shares) -Depth 6 -Compress)
        sidTable     = (ConvertTo-Json -InputObject $sidTable -Depth 4 -Compress)
        errors       = (ConvertTo-Json -InputObject @($errors) -Depth 4 -Compress)
    }
}

function ConvertFrom-FsShareSddl {
    <#
    .SYNOPSIS
        Workstation-side SDDL parser (same rules as the remote scriptblock) used by tests and as a fallback
        when a share record carries an SDDL string but no parsed aces.
    .OUTPUTS
        Array of @{ sid; accessMask(long); accessControlType }
    #>
    [OutputType([object[]])]
    param([AllowNull()] [AllowEmptyString()] [string] $Sddl)
    $out = [System.Collections.Generic.List[object]]::new()
    if ([string]::IsNullOrWhiteSpace($Sddl)) { return @() }
    $rsd = [System.Security.AccessControl.RawSecurityDescriptor]::new($Sddl)
    if ($null -eq $rsd.DiscretionaryAcl) { return @() }
    foreach ($ace in $rsd.DiscretionaryAcl) {
        if ($ace -isnot [System.Security.AccessControl.QualifiedAce]) { continue }
        $type = switch ([string]$ace.AceQualifier) { 'AccessAllowed' { 'Allow' } 'AccessDenied' { 'Deny' } default { $null } }
        if (-not $type) { continue }
        $out.Add(@{ sid = $ace.SecurityIdentifier.Value; accessMask = [long]([uint32]$ace.AccessMask); accessControlType = $type })
    }
    return @($out)
}

function Merge-FsSidTable {
    <# Folds a sid -> @{name; isLocal} table (hashtable or ConvertFrom-Json object) into the context SidTable. #>
    param([Parameter(Mandatory)] [hashtable] $Context, [AllowNull()] $Table)
    if ($null -eq $Table) { return }
    if ($Table -is [System.Collections.IDictionary]) {
        foreach ($k in $Table.Keys) {
            $v = $Table[$k]
            $Context.SidTable[[string]$k] = @{ name = (Get-FsValue $v 'name'); isLocal = [bool](Get-FsValue $v 'isLocal') }
        }
        return
    }
    foreach ($p in $Table.PSObject.Properties) {
        $Context.SidTable[[string]$p.Name] = @{ name = (Get-FsValue $p.Value 'name'); isLocal = [bool](Get-FsValue $p.Value 'isLocal') }
    }
}

function Test-FsShareSelected {
    <# Applies -IncludeShare / -ExcludeShare wildcard filters to a share name. #>
    [OutputType([bool])]
    param([Parameter(Mandatory)] [string] $Name, [string[]] $Include = @(), [string[]] $Exclude = @())
    if ($Include -and $Include.Count -gt 0) {
        $hit = $false
        foreach ($pat in $Include) { if ($Name -like $pat) { $hit = $true; break } }
        if (-not $hit) { return $false }
    }
    foreach ($pat in @($Exclude)) { if ($pat -and $Name -like $pat) { return $false } }
    return $true
}

function Import-FsInventoryResult {
    <#
    .SYNOPSIS
        Folds the remote inventory object into the context: server facts, SID table, and the selected share list.
    .OUTPUTS
        Array of share info hashtables @{ name; path; description; isHidden; aces[] } (already filtered).
    #>
    [OutputType([object[]])]
    param([Parameter(Mandatory)] [hashtable] $Context, [Parameter(Mandatory)] $Result)
    $Context.Inventory = $Result
    $snap = $Context.Snapshot
    $snap.server.fqdn = [string](Get-FsValue $Result 'fqdn')
    $snap.server.machineSid = [string](Get-FsValue $Result 'machineSid')
    $role = Get-FsValue $Result 'domainRole'
    $snap.server.domainRole = $(if ($null -ne $role) { [int]$role } else { $null })
    $snap.server.osVersion = [string](Get-FsValue $Result 'osVersion')
    $snap.server.remotePsVersion = [string](Get-FsValue $Result 'psVersion')
    $Context.MachineSid = $snap.server.machineSid
    $Context.IsDomainController = ($null -ne $role -and ([int]$role -eq 4 -or [int]$role -eq 5))
    if (Get-FsValue $Result 'domainName') { $snap.domain.name = [string](Get-FsValue $Result 'domainName') }

    $errJson = [string](Get-FsValue $Result 'errors')
    if ($errJson) {
        foreach ($e in @(ConvertFrom-Json -InputObject $errJson)) {
            Add-FsScanError -Context $Context -Phase Inventory -Scope ([string](Get-FsValue $e 'scope')) -Message ([string](Get-FsValue $e 'message')) -ExceptionType ([string](Get-FsValue $e 'exceptionType')) | Out-Null
        }
    }
    $tableJson = [string](Get-FsValue $Result 'sidTable')
    if ($tableJson) { Merge-FsSidTable -Context $Context -Table (ConvertFrom-Json -InputObject $tableJson) }

    $shares = [System.Collections.Generic.List[object]]::new()
    $sharesJson = [string](Get-FsValue $Result 'shares')
    if ($sharesJson) {
        foreach ($s in @(ConvertFrom-Json -InputObject $sharesJson)) {
            $name = [string](Get-FsValue $s 'name')
            if (-not $name) { continue }
            if (-not (Test-FsShareSelected -Name $name -Include @($Context.Options.IncludeShare) -Exclude @($Context.Options.ExcludeShare))) {
                Write-Verbose "Share '$name' skipped by include/exclude filter."
                continue
            }
            $aces = @(Get-FsValue $s 'aces')
            if ($aces.Count -eq 0 -and (Get-FsValue $s 'sddl')) {
                try { $aces = @(ConvertFrom-FsShareSddl -Sddl ([string](Get-FsValue $s 'sddl'))) } catch { Add-FsScanError -Context $Context -Phase Inventory -Scope $name -ErrorRecord $_ | Out-Null }
            }
            $shares.Add(@{
                name        = $name
                path        = ([string](Get-FsValue $s 'path')).TrimEnd('\')
                description = [string](Get-FsValue $s 'description')
                isHidden    = [bool](Get-FsValue $s 'isHidden')
                aces        = @($aces | ForEach-Object { @{ sid = [string](Get-FsValue $_ 'sid'); accessMask = [long](Get-FsValue $_ 'accessMask'); accessControlType = [string](Get-FsValue $_ 'accessControlType') } })
            })
            foreach ($a in $aces) { $sid = [string](Get-FsValue $a 'sid'); if ($sid) { [void]$Context.PendingSids.Add($sid) } }
        }
    }
    return @(Get-FsSorted -InputObject @($shares) -Property 'name')
}
