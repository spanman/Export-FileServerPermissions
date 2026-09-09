BeforeAll {
    . (Join-Path $PSScriptRoot 'TestHelpers.ps1')
    $script:Model = Get-FixtureModel
    $script:SID = @{
        alice = 'S-1-5-21-1111111111-2222222222-3333333333-1101'
        LoopA = 'S-1-5-21-1111111111-2222222222-3333333333-2004'
        LoopB = 'S-1-5-21-1111111111-2222222222-3333333333-2005'
        HRShareRW = 'S-1-5-21-1111111111-2222222222-3333333333-2001'
        HRAll = 'S-1-5-21-1111111111-2222222222-3333333333-2002'
        Deep1 = 'S-1-5-21-1111111111-2222222222-3333333333-2008'
        Deep4 = 'S-1-5-21-1111111111-2222222222-3333333333-2011'
        DomainUsers = 'S-1-5-21-1111111111-2222222222-3333333333-513'
    }
}

Describe 'Get-FsTransitiveGroups / Get-FsTransitiveMembers cycle safety' {
    It 'a cycle terminates and excludes the starting node from its own closure' {
        $up = @(Get-FsTransitiveGroups -Model $Model -PrincipalId $SID.LoopA)
        $up | Should -Contain $SID.LoopB
        $up | Should -Not -Contain $SID.LoopA
        $down = @(Get-FsTransitiveMembers -Model $Model -GroupId $SID.LoopB)
        $down | Should -Contain $SID.LoopA
        $down | Should -Not -Contain $SID.LoopB
    }
    It 'memoizes: calling twice returns an equal result' {
        $a = (Get-FsTransitiveGroups -Model $Model -PrincipalId $SID.alice) -join ','
        $b = (Get-FsTransitiveGroups -Model $Model -PrincipalId $SID.alice) -join ','
        $a | Should -Be $b
    }
}

Describe 'alice reaches groups via direct, primary-group and local-group membership' {
    It 'includes HR-Share-RW, HR-All, Deep-1..4, Domain Users (primary group) and FS01\Users (local, via Domain Users)' {
        $groups = @(Get-FsTransitiveGroups -Model $Model -PrincipalId $SID.alice)
        foreach ($g in $SID.HRShareRW, $SID.HRAll, $SID.Deep1, 'S-1-5-21-1111111111-2222222222-3333333333-2009', 'S-1-5-21-1111111111-2222222222-3333333333-2010', $SID.Deep4, $SID.DomainUsers, 'FS01\Users') {
            $groups | Should -Contain $g
        }
    }
}

Describe 'Get-FsTransitiveMembers -UsersOnly' {
    It 'HR-Share-RW resolves to alice, bob and carol through HR-All' {
        $users = @(Get-FsTransitiveMembers -Model $Model -GroupId $SID.HRShareRW -UsersOnly)
        $users | Should -Contain $SID.alice
        $users | Should -Contain 'S-1-5-21-1111111111-2222222222-3333333333-1102'
        $users | Should -Contain 'S-1-5-21-1111111111-2222222222-3333333333-1103'
    }
    It 'a group that CONTAINS a broad principal does not expand past it into every user' {
        # FS01\Users has Domain Users as a direct member; its own 7 domain users must not be pulled in transitively.
        $users = @(Get-FsTransitiveMembers -Model $Model -GroupId 'FS01\Users' -UsersOnly)
        $users | Should -Not -Contain $SID.alice
    }
}

Describe 'Get-FsGroupNestingDepth' {
    It 'Deep-4 sits 3 hops below Deep-1' {
        Get-FsGroupNestingDepth -Model $Model -GroupId $SID.Deep4 | Should -Be 3
    }
    It 'Deep-1 (top of the chain) has depth 0' {
        Get-FsGroupNestingDepth -Model $Model -GroupId $SID.Deep1 | Should -Be 0
    }
}

Describe 'Get-FsGroupCycles' {
    It 'finds exactly one cycle, containing Loop-A and Loop-B, regardless of enumeration order' {
        $cycles = @(Get-FsGroupCycles -Model $Model)
        $cycles.Count | Should -Be 1
        $cycles[0] | Should -Contain $SID.LoopA
        $cycles[0] | Should -Contain $SID.LoopB
    }
}

Describe 'Get-FsBroadPrincipalIds / Test-FsBroadPrincipal' {
    It 'includes Authenticated Users and a local group that contains it (FS01\Users)' {
        $broad = @(Get-FsBroadPrincipalIds -Model $Model)
        $broad | Should -Contain 'S-1-5-11'
        $broad | Should -Contain 'FS01\Users'
    }
}

Describe 'Get-FsGroupChain' {
    # Fixture nesting is Deep-1 (top) > Deep-2 > Deep-3 > Deep-4 > {alice} (alice is a DIRECT member of Deep-4).
    It 'alice is a direct member of Deep-4 (chain length 2)' {
        $chain = @(Get-FsGroupChain -Model $Model -PrincipalId $SID.alice -GroupId $SID.Deep4)
        $chain | Should -Be @($SID.alice, $SID.Deep4)
    }
    It 'reaching Deep-1 requires the full Deep-4 -> Deep-3 -> Deep-2 -> Deep-1 chain' {
        $chain = @(Get-FsGroupChain -Model $Model -PrincipalId $SID.alice -GroupId $SID.Deep1)
        $chain[0] | Should -Be $SID.alice
        $chain[-1] | Should -Be $SID.Deep1
        $chain | Should -Contain $SID.Deep4
    }
    It 'returns an empty array when the group is unreachable' {
        @(Get-FsGroupChain -Model $Model -PrincipalId $SID.alice -GroupId 'S-1-5-21-1111111111-2222222222-3333333333-2007').Count | Should -Be 0
    }
}

Describe 'Get-FsBroadPrincipalSet against a genuinely empty model' {
    # Regression: `return $set` for an empty HashSet unrolls to zero pipeline objects, so the
    # caller's `$broad = Get-FsBroadPrincipalSet ...` captured $null - not an empty set - and
    # every report's `$broad.Contains(...)` crashed with "You cannot call a method on a null-valued
    # expression." This is exactly what happened on a real -DryRun scan against par3.par.com: no
    # NTFS walk means zero principals, zero memberships, so the broad set is legitimately empty.
    BeforeAll {
        $emptySnap = New-FsSnapshot -ServerName 'FS01' | ConvertTo-Json -Depth 20 | ConvertFrom-Json -AsHashtable -Depth 64
        $script:EmptyModel = Merge-FsModel -History @{ FS01 = @($emptySnap) }
    }
    It 'returns an empty HashSet, not $null' {
        # Not `$broad | Should ...`: piping a 0-element HashSet enumerates it into zero pipeline
        # objects, so Should would never even execute (a silent, vacuous pass) - exactly the bug
        # under test. And not `Should -Not -BeNullOrEmpty`: Pester's BeNullOrEmpty treats any
        # Count-0 collection as "empty" regardless of whether it's actually $null. So assert
        # directly against the captured variable instead of piping it anywhere.
        $broad = Get-FsBroadPrincipalSet -Model $EmptyModel
        ($null -eq $broad) | Should -BeFalse -Because 'it must be a HashSet object, even though it has zero members'
        ($broad -is [System.Collections.Generic.HashSet[string]]) | Should -BeTrue
        $broad.Count | Should -Be 0
        { $broad.Contains('S-1-1-0') } | Should -Not -Throw
    }
    It 'a second call (cache-hit path) also returns an empty HashSet, not $null' {
        $broad = Get-FsBroadPrincipalSet -Model $EmptyModel
        ($null -eq $broad) | Should -BeFalse
        $broad.Count | Should -Be 0
    }
    It 'Get-FsReportBroadExposure runs cleanly against it (the actual crash site)' {
        $options = Get-FsAnalysisOptions
        { Get-FsReportBroadExposure -Model $EmptyModel -Options $options -Definition @{ Id = '01'; Title = 'Broad Exposure' } } | Should -Not -Throw
    }
}
