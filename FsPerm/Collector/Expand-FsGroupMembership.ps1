<#
Group membership BFS.

Starts from every Group-kind principal already cached (resolved via Resolve-FsPrincipal or discovered while
nesting), reads the `member` attribute with ranged retrieval (Get-FsAdRangedAttribute), resolves the member DNs
(batched per owning domain, since nested members can come from a trusted domain) with ConvertFrom-FsAdResult,
and records Direct membership edges. Recursion stops once a node would be enqueued past -MaxDepth; the direct
members of a node are always resolved once the node itself is dequeued, regardless of depth.

Every User/Computer principal also gets an (unenumerated) PrimaryGroup edge from its primaryGroupID, because AD
never lists primary-group members in `member`. -ExpandPrimaryGroups adds one paged query per *non-standard*
primary-group RID only: 513/515/516/521 are the broad, everyone-is-a-member groups and are never enumerated.
#>

function Expand-FsGroupMembership {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [hashtable] $Context,
        [int] $MaxDepth = 10,
        [switch] $ExpandPrimaryGroups
    )

    $visited = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    $queue = [System.Collections.Generic.Queue[object]]::new()
    foreach ($id in @($Context.Principals.Keys)) {
        $p = $Context.Principals[$id]
        if ((Get-FsValue $p 'kind') -eq 'Group' -and (Get-FsValue $p 'ad.distinguishedName')) {
            $queue.Enqueue([pscustomobject]@{ Id = $id; Depth = 0 })
        }
    }

    while ($queue.Count -gt 0) {
        $item = $queue.Dequeue()
        if (-not $visited.Add($item.Id)) { continue }
        $p = $Context.Principals[$item.Id]
        if ($null -eq $p) { continue }
        $dn = [string](Get-FsValue $p 'ad.distinguishedName')
        if (-not $dn) { continue }

        $searcher = Get-FsAdSearcherForDn -Context $Context -Dn $dn
        if (-not $searcher) {
            Add-FsScanError -Context $Context -Phase Membership -Scope $item.Id -Kind Directory -Message "No AD searcher available to expand members of $($item.Id)." | Out-Null
            continue
        }

        $memberDns = @()
        try { $memberDns = @(Get-FsAdRangedAttribute -Searcher $searcher -Dn $dn -Attribute member -Step 1500) }
        catch { Add-FsScanError -Context $Context -Phase Membership -Scope $item.Id -ErrorRecord $_ | Out-Null }

        Set-FsValue -Object $p -Name 'memberCount' -Value $memberDns.Count
        Set-FsValue -Object $p -Name 'membershipResolved' -Value $true
        Set-FsValue -Object $p -Name 'membershipNote' -Value $null
        if ($memberDns.Count -eq 0) { continue }

        Resolve-FsMemberDns -Context $Context -Dn $memberDns -Scope $item.Id

        foreach ($dn2 in $memberDns) {
            if (-not $Context.DnToId.ContainsKey($dn2)) { continue }   # lookup failed; already logged
            $memberId = $Context.DnToId[$dn2]
            Add-FsContextMembership -Context $Context -GroupId $item.Id -MemberId $memberId -Kind Direct -Source AD
            $memberPrincipal = $Context.Principals[$memberId]
            if ($memberPrincipal -and (Get-FsValue $memberPrincipal 'kind') -eq 'Group' -and -not $visited.Contains($memberId) -and $item.Depth -lt $MaxDepth) {
                $queue.Enqueue([pscustomobject]@{ Id = $memberId; Depth = $item.Depth + 1 })
            }
        }
    }

    Add-FsPrimaryGroupEdges -Context $Context
    if ($ExpandPrimaryGroups) { Add-FsNonStandardPrimaryGroupMembers -Context $Context }
}

function Resolve-FsMemberDns {
    <# Resolves DNs not already in Context.DnToId into cached principals, batched per owning domain. #>
    param([Parameter(Mandatory)] [hashtable] $Context, [Parameter(Mandatory)] [string[]] $Dn, [string] $Scope)
    $unresolved = @($Dn | Where-Object { -not $Context.DnToId.ContainsKey($_) })
    if ($unresolved.Count -eq 0) { return }

    $byDomain = [ordered]@{}
    foreach ($d in $unresolved) {
        $domainPart = Get-FsDnDomainPart -Dn $d
        $key = $(if ($domainPart) { $domainPart } else { '' })
        if (-not $byDomain.Contains($key)) { $byDomain[$key] = [System.Collections.Generic.List[string]]::new() }
        $byDomain[$key].Add($d)
    }

    foreach ($key in $byDomain.Keys) {
        $dns = @($byDomain[$key])
        $searcher = Get-FsAdSearcherForDn -Context $Context -Dn $dns[0]
        if (-not $searcher) {
            foreach ($d in $dns) { Add-FsScanError -Context $Context -Phase Membership -Scope $Scope -Kind Directory -Message "No AD searcher available to resolve member '$d'." | Out-Null }
            continue
        }
        $result = Get-FsAdObjectsByDn -Searcher $searcher -Dn $dns
        foreach ($d in $dns) {
            if ($result.Found.ContainsKey($d)) {
                $principal = ConvertFrom-FsAdResult -Result $result.Found[$d] -Context $Context
                Add-FsContextPrincipal -Context $Context -Principal $principal | Out-Null
                $Context.DnToId[$d] = $principal.id
            }
        }
        foreach ($e in $result.Errors) {
            Add-FsScanError -Context $Context -Phase Membership -Scope $Scope -Kind Directory -Message ("DN {0}: {1}" -f $e.dn, $e.message) -ExceptionType $e.exceptionType | Out-Null
        }
    }
}

function Add-FsPrimaryGroupEdges {
    <# One PrimaryGroup edge per resolved User/Computer, synthesizing the (never-enumerated) group if absent. #>
    param([Parameter(Mandatory)] [hashtable] $Context)
    foreach ($id in @($Context.Principals.Keys)) {
        $p = $Context.Principals[$id]
        $kind = Get-FsValue $p 'kind'
        if ($kind -ne 'User' -and $kind -ne 'Computer') { continue }
        $rid = Get-FsValue $p 'ad.primaryGroupId'
        if ($null -eq $rid) { continue }
        $sid = [string](Get-FsValue $p 'sid')
        $prefix = Get-FsSidPrefix -Sid $sid
        if (-not $prefix) { continue }
        $groupSid = "$prefix-$rid"
        if (-not $Context.Principals.ContainsKey($groupSid)) {
            $domainSids = @($Context.DomainSids)
            $name = Get-FsWellKnownName -Sid $groupSid -DomainSids $domainSids
            if (-not $name) { $name = $groupSid }
            $gp = New-FsPrincipal -Id $groupSid -Kind Group -Sid $groupSid -Name $name -IsWellKnown $true `
                -IsBroad (Test-FsBroadSid -Sid $groupSid -DomainSids $domainSids) -Resolution WellKnown `
                -MembershipResolved $false -MembershipNote 'implicit primary-group membership; not enumerated' `
                -FetchedAt (Get-FsContextNow) -SourceScanId $Context.Snapshot.scanId
            Add-FsContextPrincipal -Context $Context -Principal $gp | Out-Null
        }
        Add-FsContextMembership -Context $Context -GroupId $groupSid -MemberId $id -Kind PrimaryGroup -Source AD
    }
}

function Add-FsNonStandardPrimaryGroupMembers {
    <# One paged (&(objectCategory=person)(primaryGroupID=<rid>)) query per non-standard RID seen; 513/515/516/521 are skipped. #>
    param([Parameter(Mandatory)] [hashtable] $Context)
    if (-not $Context.DomainTable) { return }
    $standardRids = 513, 515, 516, 521
    $rids = [System.Collections.Generic.HashSet[int]]::new()
    foreach ($id in @($Context.Principals.Keys)) {
        $p = $Context.Principals[$id]
        $kind = Get-FsValue $p 'kind'
        if ($kind -ne 'User' -and $kind -ne 'Computer') { continue }
        $ridVal = Get-FsValue $p 'ad.primaryGroupId'
        if ($null -eq $ridVal) { continue }
        $ridInt = [int]$ridVal
        if ($standardRids -contains $ridInt) { continue }
        [void]$rids.Add($ridInt)
    }
    if ($rids.Count -eq 0) { return }

    $searcher = Get-FsAdSearcherForDomain -Context $Context -DomainSid $Context.DomainTable.Primary.sid
    if (-not $searcher) { return }
    foreach ($rid in $rids) {
        $groupSid = "$($Context.DomainTable.Primary.sid)-$rid"
        try {
            $results = Invoke-FsAdSearch -Searcher $searcher -Filter "(&(objectCategory=person)(primaryGroupID=$rid))"
            foreach ($r in $results) {
                $memberSid = [string](Get-FsAdSearchResultValue -Result $r -Name 'objectSid')
                if (-not $memberSid) { continue }
                if (-not $Context.Principals.ContainsKey($memberSid)) {
                    $principal = ConvertFrom-FsAdResult -Result $r -Context $Context
                    Add-FsContextPrincipal -Context $Context -Principal $principal | Out-Null
                }
                Add-FsContextMembership -Context $Context -GroupId $groupSid -MemberId $memberSid -Kind PrimaryGroup -Source AD
            }
        }
        catch { Add-FsScanError -Context $Context -Phase Membership -Scope "PrimaryGroup/$rid" -ErrorRecord $_ | Out-Null }
    }
}

function Set-FsValue {
    <# Sets a property (PSCustomObject) or key (IDictionary) by name; used to mutate a cached principal record in place. #>
    param([Parameter(Mandatory)] $Object, [Parameter(Mandatory)] [string] $Name, $Value)
    if ($Object -is [System.Collections.IDictionary]) { $Object[$Name] = $Value; return }
    $Object.PSObject.Properties[$Name].Value = $Value
}
