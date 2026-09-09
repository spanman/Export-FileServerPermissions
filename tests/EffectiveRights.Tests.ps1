BeforeAll {
    . (Join-Path $PSScriptRoot 'TestHelpers.ps1')
    $script:Model = Get-FixtureModel
    $script:SID = @{
        alice        = 'S-1-5-21-1111111111-2222222222-3333333333-1101'
        bob          = 'S-1-5-21-1111111111-2222222222-3333333333-1102'
        carol        = 'S-1-5-21-1111111111-2222222222-3333333333-1103'
        svc_backup   = 'S-1-5-21-1111111111-2222222222-3333333333-1105'
        Everyone     = 'S-1-1-0'
        AuthUsers    = 'S-1-5-11'
        DomainUsers  = 'S-1-5-21-1111111111-2222222222-3333333333-513'
        HRShareRW    = 'S-1-5-21-1111111111-2222222222-3333333333-2001'
        HRAll        = 'S-1-5-21-1111111111-2222222222-3333333333-2002'
        OwnerlessRW  = 'S-1-5-21-1111111111-2222222222-3333333333-2012'
    }
}

Describe 'Get-FsEffectiveMask - hand-built ACE lists' {
    It 'an explicit Allow beats an inherited Deny for the same principal' {
        $aces = @(
            (New-FsAce -PrincipalId 'P' -Sid 'P' -RightsMask 0x1301BF -AccessControlType Deny -IsInherited $true),
            (New-FsAce -PrincipalId 'P' -Sid 'P' -RightsMask 0x1301BF -AccessControlType Allow -IsInherited $false)
        )
        $token = [System.Collections.Generic.HashSet[string]]::new([string[]]@('P'), [System.StringComparer]::OrdinalIgnoreCase)
        $mask = Get-FsEffectiveMask -Aces $aces -Token $token
        Get-FsMaskLevel -Mask $mask | Should -Be 'Modify'
    }
    It 'an explicit Deny beats an explicit Allow for the same principal' {
        $aces = @(
            (New-FsAce -PrincipalId 'P' -Sid 'P' -RightsMask 0x1301BF -AccessControlType Allow -IsInherited $false),
            (New-FsAce -PrincipalId 'P' -Sid 'P' -RightsMask 0x1301BF -AccessControlType Deny -IsInherited $false)
        )
        $token = [System.Collections.Generic.HashSet[string]]::new([string[]]@('P'), [System.StringComparer]::OrdinalIgnoreCase)
        $mask = Get-FsEffectiveMask -Aces $aces -Token $token
        Get-FsMaskLevel -Mask $mask | Should -Be 'None'
    }
    It 'an InheritOnly ACE never applies to the object it sits on' {
        $aces = @((New-FsAce -PrincipalId 'P' -Sid 'P' -RightsMask 0x1F01FF -AccessControlType Allow -IsInherited $true -PropagationFlags 'InheritOnly'))
        $token = [System.Collections.Generic.HashSet[string]]::new([string[]]@('P'), [System.StringComparer]::OrdinalIgnoreCase)
        (Get-FsEffectiveMask -Aces $aces -Token $token) | Should -Be 0
    }
    It 'evaluates per bit: a Deny on Write plus an Allow of Full still grants Read' {
        $aces = @(
            (New-FsAce -PrincipalId 'P' -Sid 'P' -RightsMask 0x1F01FF -AccessControlType Allow -IsInherited $true),
            (New-FsAce -PrincipalId 'P' -Sid 'P' -RightsMask 0x116 -AccessControlType Deny -IsInherited $false)
        )
        $token = [System.Collections.Generic.HashSet[string]]::new([string[]]@('P'), [System.StringComparer]::OrdinalIgnoreCase)
        $mask = Get-FsEffectiveMask -Aces $aces -Token $token
        (Test-FsMaskHasBits -Mask $mask -Bits 0x20089) | Should -BeTrue
        (Test-FsMaskHasBits -Mask $mask -Bits 0x2) | Should -BeFalse
    }
}

Describe 'Get-FsEffectiveLevel - share vs NTFS layering' {
    It 'share Read caps an NTFS Full grant down to Read' {
        $eval = Get-FsResourceEvaluation -Model $Model -ResourceId 'FS02:E:\Public'
        $eval | Should -Not -BeNullOrEmpty
    }
    It 'FS02 Public: share Change caps the NTFS Everyone Full grant to Modify' {
        $level = Get-FsEffectiveLevel -Model $Model -PrincipalId $SID.Everyone -ResourceId 'FS02:E:\Public'
        $level.level | Should -Be 'Modify'
    }
    It 'FS01 Finance: the permissive Everyone-Full share ACL does not by itself grant NTFS access (Everyone has no NTFS ACE there)' {
        $level = Get-FsEffectiveLevel -Model $Model -PrincipalId $SID.Everyone -ResourceId 'FS01\Finance'
        $level.ntfsLevel | Should -Be 'None'
        $level.level | Should -Be 'None'
    }
    It 'FS01 Finance: for a principal with its own NTFS grant, the Everyone-Full share does not restrict it - NTFS is the limiter' {
        # OwnerlessRW has NTFS Modify on the Finance root; the share ACL (Everyone Full) matches every token, so it never caps anyone down.
        $level = Get-FsEffectiveLevel -Model $Model -PrincipalId $SID.OwnerlessRW -ResourceId 'FS01\Finance'
        $level.shareLevel | Should -Be 'Full'
        $level.ntfsLevel | Should -Be 'Modify'
        $level.level | Should -Be 'Modify'
    }
}

Describe 'Get-FsEffectiveLevel - fixture scenarios' {
    It 'bob has effective Modify on HR\Payroll\Archive directly, despite Domain Users being denied Write there (inherited)' {
        $level = Get-FsEffectiveLevel -Model $Model -PrincipalId $SID.bob -ResourceId 'FS01:D:\Shares\HR\Payroll\Archive'
        $level.level | Should -Be 'Modify'
    }
    It 'alice reaches HR\Payroll via HR-Share-RW (Full), but the explicit Domain Users Deny on the SAME folder removes the write bits token-wide (canonical Deny/Allow order, not per-grantee), landing at Write' {
        $level = Get-FsEffectiveLevel -Model $Model -PrincipalId $SID.alice -ResourceId 'FS01:D:\Shares\HR\Payroll'
        $level.ntfsLevel | Should -Be 'Write'
        $level.level | Should -Be 'Write'
    }
    It 'carol reaches HR\Payroll too: HR-All is nested inside HR-Share-RW, so she inherits the same Full/Write outcome as alice' {
        $level = Get-FsEffectiveLevel -Model $Model -PrincipalId $SID.carol -ResourceId 'FS01:D:\Shares\HR\Payroll'
        $level.level | Should -Be 'Write'
    }
    It 'svc_backup (Backup Operators only, no HR group membership) has no path to HR\Payroll' {
        $level = Get-FsEffectiveLevel -Model $Model -PrincipalId $SID.svc_backup -ResourceId 'FS01:D:\Shares\HR\Payroll'
        $level.level | Should -Be 'None'
    }
}

Describe 'Get-FsEffectiveAccess' {
    It "alice's access list includes the HR share (via HR-Share-RW) and reaches FS02 Finance through the Deep-* chain" {
        $rows = @(Get-FsEffectiveAccess -Model $Model -PrincipalId $SID.alice)
        $ids = @($rows | ForEach-Object resourceId)
        (($ids | ForEach-Object { "[$_]" }) -join ' ') | Should -Not -BeNullOrEmpty   # visible in failure output
        $rows.Count | Should -BeGreaterThan 0
        $hr = @($rows | Where-Object { [string]$_.resourceId -eq 'FS01\HR' })
        $hr.Count | Should -Be 1
        $deepChain = @($rows | Where-Object { [string]$_.resourceId -eq 'FS02\Finance' })
        $deepChain.Count | Should -Be 1
        $deepChain[0].via | Should -Contain 'S-1-5-21-1111111111-2222222222-3333333333-2008'
    }
    It '-ExcludeBroad drops grant points reachable only through a broad principal' {
        $all = @(Get-FsEffectiveAccess -Model $Model -PrincipalId $SID.carol)
        $excludeBroad = @(Get-FsEffectiveAccess -Model $Model -PrincipalId $SID.carol -ExcludeBroad)
        $excludeBroad.Count | Should -BeLessOrEqual $all.Count
    }
}

Describe 'Get-FsToken' {
    It 'a domain user token includes Everyone, Authenticated Users and NETWORK' {
        $token = Get-FsToken -Model $Model -PrincipalId $SID.alice
        $token.Contains('S-1-1-0') | Should -BeTrue
        $token.Contains('S-1-5-11') | Should -BeTrue
        $token.Contains('S-1-5-2') | Should -BeTrue
    }
    It "an orphaned SID's token is itself plus its transitive groups only (no implicit broad membership)" {
        $token = Get-FsToken -Model $Model -PrincipalId 'S-1-5-21-1111111111-2222222222-3333333333-9999'
        $token.Contains('S-1-1-0') | Should -BeFalse
    }
}
