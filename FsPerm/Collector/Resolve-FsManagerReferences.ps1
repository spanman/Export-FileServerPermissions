<#
Fills in the sam/sid half of every ad.manager / ad.managedBy reference (@{ dn; sam; sid }) once all principals
have been resolved. References are batch-resolved per owning domain via Get-FsAdObjectsByDn and mutated in
place; a manager that isn't already a cached principal is never force-added as one.
#>

function Resolve-FsManagerReferences {
    [CmdletBinding()]
    param([Parameter(Mandatory)] [hashtable] $Context)

    $pendingByDn = [System.Collections.Generic.Dictionary[string, object]]::new([System.StringComparer]::OrdinalIgnoreCase)
    foreach ($id in @($Context.Principals.Keys)) {
        $p = $Context.Principals[$id]
        $ad = Get-FsValue $p 'ad'
        if ($null -eq $ad -or $ad -isnot [System.Collections.IDictionary]) { continue }
        foreach ($refName in 'manager', 'managedBy') {
            if (-not $ad.Contains($refName)) { continue }
            $ref = $ad[$refName]
            if ($null -eq $ref -or $ref -isnot [System.Collections.IDictionary]) { continue }
            $dn = [string]$ref['dn']
            if (-not $dn) { continue }
            if ($ref['sam'] -or $ref['sid']) { continue }   # already filled
            if (-not $pendingByDn.ContainsKey($dn)) { $pendingByDn[$dn] = [System.Collections.Generic.List[object]]::new() }
            $pendingByDn[$dn].Add($ref)
        }
    }
    if ($pendingByDn.Count -eq 0) { return }

    $byDomain = [ordered]@{}
    foreach ($dn in $pendingByDn.Keys) {
        $domainPart = Get-FsDnDomainPart -Dn $dn
        $key = $(if ($domainPart) { $domainPart } else { '' })
        if (-not $byDomain.Contains($key)) { $byDomain[$key] = [System.Collections.Generic.List[string]]::new() }
        $byDomain[$key].Add($dn)
    }

    foreach ($key in $byDomain.Keys) {
        $dns = @($byDomain[$key])
        $searcher = Get-FsAdSearcherForDn -Context $Context -Dn $dns[0]
        if (-not $searcher) {
            foreach ($dn in $dns) { Add-FsScanError -Context $Context -Phase AdResolve -Scope 'ManagerRef' -Kind Directory -Message "No AD searcher available to resolve manager reference '$dn'." | Out-Null }
            continue
        }
        $result = Get-FsAdObjectsByDn -Searcher $searcher -Dn $dns
        foreach ($dn in $dns) {
            if (-not $result.Found.ContainsKey($dn)) { continue }
            $r = $result.Found[$dn]
            $sam = [string](Get-FsAdSearchResultValue -Result $r -Name 'sAMAccountName')
            $sid = [string](Get-FsAdSearchResultValue -Result $r -Name 'objectSid')
            foreach ($ref in $pendingByDn[$dn]) { $ref['sam'] = $sam; $ref['sid'] = $sid }
        }
        foreach ($e in $result.Errors) {
            Add-FsScanError -Context $Context -Phase AdResolve -Scope 'ManagerRef' -Kind Directory -Message ("DN {0}: {1}" -f $e.dn, $e.message) -ExceptionType $e.exceptionType | Out-Null
        }
    }
}
