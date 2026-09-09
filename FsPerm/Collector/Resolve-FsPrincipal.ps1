<#
Batched SID -> principal resolution.

Classification follows Get-FsSidClass. WellKnown/Capability/Service (and Builtin when the server has no local
SAM to enumerate it, i.e. a domain controller) are synthesized directly with no AD contact. MachineAccount SIDs,
and any SID the server's own sidTable already flagged isLocal, are left for the local-groups phase (Invoke-FsScan
adds them to Context.PendingLocal). Everything else is a domain SID: batched per owning domain through
Get-FsAdObjectsBySid, converted with ConvertFrom-FsAdResult, and cached. Misses fall back to NTAccount translation
(Foreign on success, OrphanedSid on failure). Every result lands in Context.Principals keyed by id.
#>

function Resolve-FsPrincipal {
    <#
    .SYNOPSIS
        Resolves a batch of SIDs into cached principals on the scan context.
    .PARAMETER Sid
        SID strings to resolve. SIDs already cached in $Context.Principals are skipped.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [hashtable] $Context,
        [Parameter(Mandatory)] [AllowEmptyCollection()] [string[]] $Sid
    )

    $toResolve = [System.Collections.Generic.List[string]]::new()
    $seen = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    foreach ($s in $Sid) {
        if (-not $s) { continue }
        if ($Context.Principals.ContainsKey($s)) { continue }
        if ($seen.Add($s)) { $toResolve.Add($s) }
    }
    if ($toResolve.Count -eq 0) { return }

    $domainBatch = [System.Collections.Generic.List[string]]::new()
    foreach ($s in $toResolve) {
        $class = Get-FsSidClass -Sid $s -DomainSids @($Context.DomainSids) -MachineSid $Context.MachineSid
        $sidTableLocal = $Context.SidTable.ContainsKey($s) -and [bool]$Context.SidTable[$s].isLocal

        if ($class -in 'WellKnown', 'Capability', 'Service') { Add-FsWellKnownPrincipal -Context $Context -Sid $s; continue }
        if ($class -eq 'Builtin') {
            if ($Context.IsDomainController) { Add-FsWellKnownPrincipal -Context $Context -Sid $s }
            else { [void]$Context.PendingLocal.Add($s) }
            continue
        }
        if ($class -eq 'MachineAccount' -or $sidTableLocal) { [void]$Context.PendingLocal.Add($s); continue }
        if ($class -eq 'DomainAccount') { $domainBatch.Add($s); continue }
        Resolve-FsUnresolvedSid -Context $Context -Sid $s   # Unknown class: no sane AD path, try NTAccount translate directly
    }

    if ($domainBatch.Count -eq 0) { return }

    $byPrefix = [ordered]@{}
    foreach ($s in $domainBatch) {
        $prefix = Get-FsSidPrefix -Sid $s
        $key = $(if ($prefix) { $prefix } else { '' })
        if (-not $byPrefix.Contains($key)) { $byPrefix[$key] = [System.Collections.Generic.List[string]]::new() }
        $byPrefix[$key].Add($s)
    }

    foreach ($prefix in $byPrefix.Keys) {
        $group = @($byPrefix[$prefix])
        $searcher = $(if ($prefix) { Get-FsAdSearcherForDomain -Context $Context -DomainSid $prefix } else { $null })
        if (-not $searcher) {
            foreach ($s in $group) { Resolve-FsUnresolvedSid -Context $Context -Sid $s }
            continue
        }
        $result = Get-FsAdObjectsBySid -Searcher $searcher -Sid $group
        foreach ($s in $group) {
            if ($result.Found.ContainsKey($s)) {
                $principal = ConvertFrom-FsAdResult -Result $result.Found[$s] -Context $Context
                Add-FsContextPrincipal -Context $Context -Principal $principal | Out-Null
            }
            else { Resolve-FsUnresolvedSid -Context $Context -Sid $s }
        }
        foreach ($e in $result.Errors) {
            Add-FsScanError -Context $Context -Phase AdResolve -Scope $prefix -Kind Directory -Message ("SID {0}: {1}" -f $e.sid, $e.message) -ExceptionType $e.exceptionType | Out-Null
        }
    }
}

function Add-FsWellKnownPrincipal {
    <# Synthesizes a WellKnown principal for a SID that needs no AD or local-SAM contact (cached once). #>
    param([Parameter(Mandatory)] [hashtable] $Context, [Parameter(Mandatory)] [string] $Sid)
    if ($Context.Principals.ContainsKey($Sid)) { return }
    $domainSids = @($Context.DomainSids)
    $name = Get-FsWellKnownName -Sid $Sid -DomainSids $domainSids
    if (-not $name) { $name = $Sid }
    $p = New-FsPrincipal -Id $Sid -Kind WellKnown -Sid $Sid -Name $name -IsWellKnown $true `
        -IsBroad (Test-FsBroadSid -Sid $Sid -DomainSids $domainSids) -Resolution WellKnown `
        -MembershipResolved $false -MembershipNote 'implicit membership' `
        -FetchedAt (Get-FsContextNow) -SourceScanId $Context.Snapshot.scanId
    Add-FsContextPrincipal -Context $Context -Principal $p | Out-Null
}

function Resolve-FsUnresolvedSid {
    <# Last resort for a SID that AD couldn't produce a result for: NTAccount translate, else OrphanedSid. #>
    param([Parameter(Mandatory)] [hashtable] $Context, [Parameter(Mandatory)] [string] $Sid)
    if ($Context.Principals.ContainsKey($Sid)) { return }
    try {
        $nt = ([System.Security.Principal.SecurityIdentifier]::new($Sid)).Translate([System.Security.Principal.NTAccount])
        $full = [string]$nt.Value
        $domain = $null; $name = $full
        $i = $full.IndexOf('\')
        if ($i -gt 0) { $domain = $full.Substring(0, $i); $name = $full.Substring($i + 1) }
        $p = New-FsPrincipal -Id $Sid -Kind Foreign -Sid $Sid -Domain $domain -Name $name -Resolution Foreign `
            -FetchedAt (Get-FsContextNow) -SourceScanId $Context.Snapshot.scanId
    }
    catch {
        $p = New-FsPrincipal -Id $Sid -Kind OrphanedSid -Sid $Sid -Resolution Orphaned -ResolutionError $_.Exception.Message `
            -FetchedAt (Get-FsContextNow) -SourceScanId $Context.Snapshot.scanId
    }
    Add-FsContextPrincipal -Context $Context -Principal $p | Out-Null
}
