BeforeAll { . (Join-Path $PSScriptRoot 'TestHelpers.ps1') }

Describe 'Snapshot export/import round trip' {
    It 'round-trips a snapshot through gzip and back' {
        $s = New-FsSnapshot -ServerName fs99 -DomainName CONTOSO -DomainSid 'S-1-5-21-1-2-3'
        $sh = New-FsShare -Server fs99 -Name Test -LocalPath 'D:\T' -Aces @((New-FsShareAce -PrincipalId 'S-1-1-0' -Sid 'S-1-1-0' -AccessMask 0x1200A9 -AccessControlType Allow))
        $s.shares.Add($sh)
        $path = Join-Path $TestDrive 'round.json.gz'
        Export-FsSnapshot -Snapshot $s -Path $path | Out-Null
        $back = Import-FsSnapshot -Path $path
        $back['scanId'] | Should -Be $s.scanId
        $back['shares'].Count | Should -Be 1
        $back['shares'][0]['name'] | Should -Be 'Test'
    }

    It 'also round-trips uncompressed JSON' {
        $s = New-FsSnapshot -ServerName fs99 -DomainName CONTOSO -DomainSid 'S-1-5-21-1-2-3'
        $path = Join-Path $TestDrive 'round.json'
        Export-FsSnapshot -Snapshot $s -Path $path -NoCompress | Out-Null
        (Import-FsSnapshot -Path $path)['scanId'] | Should -Be $s.scanId
    }

    It 'rejects an unknown schema major version' {
        $path = Join-Path $TestDrive 'bad.json'
        '{"schemaVersion":"9.0","shares":[],"folders":[],"principals":{},"memberships":[],"errors":[]}' |
            Set-Content -LiteralPath $path -Encoding utf8
        { Import-FsSnapshot -Path $path } | Should -Throw
    }
}

Describe 'Merge-FsModel' {
    BeforeAll { $script:Model = Get-FixtureModel }

    It 'keeps one principal per id across servers, tracking every server it was seen on' {
        $alice = $Model.principals['S-1-5-21-1111111111-2222222222-3333333333-1101']
        $alice | Should -Not -BeNullOrEmpty
        $alice['_servers'] | Should -Contain 'FS01'
        $alice['_servers'] | Should -Contain 'FS02'
    }

    It 'prefers a Resolved principal over an Orphaned one and the newest attributes' {
        $frank = $Model.principals['S-1-5-21-1111111111-2222222222-3333333333-1107']
        $frank['name'] | Should -Be 'frank.jones'
        $frank['ad']['department'] | Should -Be 'Finance'
    }

    It 'unions memberships without duplicates' {
        $key = { param($m) '{0}|{1}|{2}' -f $m['groupId'], $m['memberId'], $m['kind'] }
        $keys = @($Model.memberships | ForEach-Object { & $key $_ })
        ($keys | Group-Object | Where-Object Count -gt 1).Count | Should -Be 0
    }

    It 'gives local groups a SERVER\Name id distinct across servers' {
        $Model.principals.Contains('FS01\Users') | Should -BeTrue
        $Model.principals.Contains('FS02\Users') | Should -BeTrue
        $Model.principals['FS01\Users']['id'] | Should -Not -Be $Model.principals['FS02\Users']['id']
    }

    It 'marks share-root folders and links non-root folders to their nearest divergent ancestor' {
        $root = $Model.folders['FS01:D:\Shares\HR']
        $root['isShareRoot'] | Should -BeTrue
        $payroll = $Model.folders['FS01:D:\Shares\HR\Payroll']
        $payroll['isProtected'] | Should -BeTrue
        $archive = $Model.folders['FS01:D:\Shares\HR\Payroll\Archive']
        $archive['nearestDivergentAncestorId'] | Should -Be $payroll['id']
    }

    It 'builds a reverse ACE index by principal' {
        $Model.index.acesByPrincipal.Contains('S-1-5-11') | Should -BeTrue
        @($Model.index.acesByPrincipal['S-1-5-11']).Count | Should -BeGreaterThan 0
    }
}

Describe 'Get-FsSorted' {
    It 'sorts strings ordinally, case-insensitively' {
        (Get-FsSorted -InputObject @('b', 'A', 'c')) -join ',' | Should -Be 'A,b,c'
    }
    It 'sorts by a descending property' {
        $items = @([pscustomobject]@{n = 'x'; v = 2 }, [pscustomobject]@{n = 'y'; v = 10 }, [pscustomobject]@{n = 'z'; v = 1 })
        ($items | Get-FsSorted -Property '-v' | ForEach-Object n) -join ',' | Should -Be 'y,x,z'
    }
    It 'dedupes with -Unique' {
        (Get-FsSorted -InputObject @('a', 'b', 'a', 'B') -Unique) -join ',' | Should -Be 'a,b'
    }
    It 'is stable and deterministic regardless of hashtable enumeration order' {
        $a = Get-FsSortedKeys @{ z = 1; a = 2; m = 3 }
        $b = Get-FsSortedKeys @{ m = 3; z = 1; a = 2 }
        ($a -join ',') | Should -Be ($b -join ',')
        ($a -join ',') | Should -Be 'a,m,z'
    }
}

Describe 'Unc helpers' {
    It 'splits a UNC path into server, share, relative path and depth' {
        $u = Split-FsUnc '\\FS01\Finance\Budgets\2024'
        $u.Server | Should -Be 'FS01'; $u.Share | Should -Be 'Finance'; $u.Relative | Should -Be 'Budgets\2024'; $u.Depth | Should -Be 2
    }
    It 'normalizes case, the \\?\UNC\ prefix and doubled separators' {
        ConvertTo-FsNormalizedPath '\\?\UNC\FS01\Finance\\Budgets\' | Should -Be '\\fs01\finance\budgets'
    }
    It 'computes a parent path, returning $null at a share/drive root' {
        Get-FsPathParent 'D:\Shares\Finance' | Should -Be 'D:\Shares'
        Get-FsPathParent 'D:\' | Should -BeNullOrEmpty
    }
    It 'computes a relative path or $null when not under the root' {
        Get-FsRelativePath -Root 'D:\Shares\Finance' -Child 'D:\Shares\Finance\Budgets\2024' | Should -Be 'Budgets\2024'
        Get-FsRelativePath -Root 'D:\Shares\Finance' -Child 'D:\Other' | Should -BeNullOrEmpty
    }
}

Describe 'Rights level mapping' -ForEach @(
    @{ Mask = 0x1F01FF; Expect = 'Full' }
    @{ Mask = 0x1301BF; Expect = 'Modify' }
    @{ Mask = 0x1200A9; Expect = 'Read' }
    @{ Mask = 0x116; Expect = 'Write' }
    @{ Mask = 1; Expect = 'List' }
    @{ Mask = 0; Expect = 'None' }
) {
    It "maps mask <Mask> to <Expect>" { Get-FsMaskLevel -Mask $Mask | Should -Be $Expect }
}

Describe 'Rights generic bits and applies-to text' {
    It 'expands GENERIC_ALL / GENERIC_WRITE / GENERIC_READ / GENERIC_EXECUTE to their level' {
        Get-FsMaskLevel -Mask ([long]268435456) | Should -Be 'Full'
        Get-FsMaskLevel -Mask ([long]1073741824) | Should -Be 'Write'
        Get-FsMaskLevel -Mask ([long]2147483648) | Should -Be 'Read'
    }
    It 'renders Explorer-style applies-to text' {
        ConvertTo-FsAppliesTo -InheritanceFlags 'ContainerInherit, ObjectInherit' -PropagationFlags 'None' | Should -Be 'This folder, subfolders and files'
        ConvertTo-FsAppliesTo -InheritanceFlags 'None' -PropagationFlags 'None' | Should -Be 'This folder only'
    }
}

Describe 'Principal classification' {
    BeforeAll { $script:domainSids = @('S-1-5-21-1-2-3') }
    It 'classifies well-known, builtin, capability and domain SIDs' {
        Get-FsSidClass -Sid 'S-1-5-11' | Should -Be 'WellKnown'
        Get-FsSidClass -Sid 'S-1-5-32-544' | Should -Be 'Builtin'
        Get-FsSidClass -Sid 'S-1-15-3-1' | Should -Be 'Capability'
        Get-FsSidClass -Sid 'S-1-5-21-1-2-3-1105' -DomainSids $domainSids | Should -Be 'DomainAccount'
    }
    It 'resolves domain-relative well-known RID names only for a matching domain' {
        Get-FsWellKnownName -Sid 'S-1-5-21-1-2-3-513' -DomainSids $domainSids | Should -Be 'Domain Users'
        Get-FsWellKnownName -Sid 'S-1-5-21-9-9-9-513' -DomainSids $domainSids | Should -BeNullOrEmpty
    }
    It 'flags broad and admin-allowlist SIDs' {
        Test-FsBroadSid -Sid 'S-1-5-21-1-2-3-513' -DomainSids $domainSids | Should -BeTrue
        Test-FsAdminSid -Sid 'S-1-5-21-1-2-3-512' -DomainSids $domainSids | Should -BeTrue
        Test-FsBroadSid -Sid 'S-1-5-21-1-2-3-1105' -DomainSids $domainSids | Should -BeFalse
    }
    It 'builds a SERVER\Name id for local principals' {
        Get-FsPrincipalId -Sid 'S-1-5-32-544' -IsLocal $true -Server fs01 | Should -Be 'FS01\Administrators'
    }
}
