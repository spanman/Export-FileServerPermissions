#Requires -Modules @{ ModuleName = 'Pester'; ModuleVersion = '5.5.0' }
<#
Collector layer tests. Everything here must run cross-platform (Linux container): real ADSI/WinRM calls are
mocked out, and anything that genuinely needs a Windows host or a live server is tagged WindowsOnly so
build/Invoke-Tests.ps1 skips it automatically off Windows.
#>

BeforeAll {
    . (Join-Path $PSScriptRoot 'TestHelpers.ps1')
    $script:D = 'S-1-5-21-1111111111-2222222222-3333333333'
}

Describe 'Collector source files' {
    It 'parses every .ps1 file under FsPerm/Collector with no errors' {
        $dir = Join-Path $script:Repo 'FsPerm/Collector'
        foreach ($f in Get-ChildItem -Path $dir -Filter '*.ps1' -File) {
            $tokens = $null; $errs = $null
            [System.Management.Automation.Language.Parser]::ParseFile($f.FullName, [ref]$tokens, [ref]$errs) | Out-Null
            $errs.Count | Should -Be 0 -Because "$($f.Name): $(($errs | ForEach-Object { $_.Message }) -join '; ')"
        }
    }
}

Describe 'Module import' {
    It 'imports FsPerm.psd1 with no errors, Collector functions included' {
        { Import-Module (Join-Path $script:Repo 'FsPerm/FsPerm.psd1') -Force -ErrorAction Stop } | Should -Not -Throw
        Get-Command Invoke-FsScan -ErrorAction SilentlyContinue | Should -Not -BeNullOrEmpty
        Get-Command ConvertFrom-FsAdResult -ErrorAction SilentlyContinue | Should -Not -BeNullOrEmpty
        Get-Command Resolve-FsPrincipal -ErrorAction SilentlyContinue | Should -Not -BeNullOrEmpty
        Get-Command Expand-FsGroupMembership -ErrorAction SilentlyContinue | Should -Not -BeNullOrEmpty
        Get-Command Resolve-FsManagerReferences -ErrorAction SilentlyContinue | Should -Not -BeNullOrEmpty
        Get-Command Get-FsScanSummary -ErrorAction SilentlyContinue | Should -Not -BeNullOrEmpty
    }
}

Describe 'Invoke-FsScan parameters' {
    It 'exposes the parameter names the entry script and contract expect' {
        $cmd = Get-Command Invoke-FsScan
        foreach ($p in 'ServerName', 'Credential', 'Depth', 'IncludeShare', 'ExcludeShare', 'IncludeHiddenShares', 'MaxFoldersPerShare',
            'ChunkSize', 'NoGroupExpansion', 'MaxGroupDepth', 'SkipAdEnrichment', 'AdServer', 'AdCredential', 'SeedSnapshot',
            'DryRun', 'TimeoutSeconds', 'ExpandPrimaryGroups') {
            $cmd.Parameters.Keys | Should -Contain $p
        }
    }
}

Describe 'Test-FsShareSelected' {
    It 'applies -IncludeShare / -ExcludeShare wildcards' {
        Test-FsShareSelected -Name 'Finance' -Include @('Fin*') | Should -Be $true
        Test-FsShareSelected -Name 'HR' -Include @('Fin*') | Should -Be $false
        Test-FsShareSelected -Name 'Finance$' -Exclude @('*$') | Should -Be $false
        Test-FsShareSelected -Name 'Finance' | Should -Be $true
        Test-FsShareSelected -Name 'HR' -Include @('Fin*', 'HR*') -Exclude @('*Archive') | Should -Be $true
        Test-FsShareSelected -Name 'HRArchive' -Include @('Fin*', 'HR*') -Exclude @('*Archive') | Should -Be $false
    }
}

Describe 'ConvertFrom-FsAdResult' {
    BeforeAll {
        $script:CtxAd = New-FsScanContext -ServerName TESTSRV -Credential $null -Options @{}
        $script:CtxAd.DomainTable = @{
            Primary = @{ sid = $script:D; netbios = 'CONTOSO'; dns = 'contoso.local'; dn = 'DC=contoso,DC=local' }
            Domains = [ordered]@{ ($script:D) = @{ sid = $script:D; netbios = 'CONTOSO'; dns = 'contoso.local'; dn = 'DC=contoso,DC=local' } }
        }
        [void]$script:CtxAd.DomainSids.Add($script:D)
    }

    It 'converts a user result' {
        $sid = "$script:D-1101"
        $result = @{
            objectSid = $sid; objectClass = @('top', 'person', 'organizationalPerson', 'user'); distinguishedName = 'CN=alice,OU=Users,DC=contoso,DC=local'
            sAMAccountName = 'alice'; displayName = 'Alice Anders'; userPrincipalName = 'alice@contoso.local'; mail = 'alice@contoso.local'
            # lastLogonTimestamp/pwdLastSet are Integer8 (FILETIME) attributes, not Generalized-Time: real ADSI
            # returns raw Int64 ticks for these (via IADsLargeInteger), unlike whenCreated which is a real DateTime.
            userAccountControl = 512; lastLogonTimestamp = ([datetime]'2026-09-06T08:12:44Z').ToFileTimeUtc(); pwdLastSet = ([datetime]'2026-06-30T09:00:00Z').ToFileTimeUtc()
            accountExpires = 0; department = 'HR'; title = 'HR Specialist'; description = $null; manager = 'CN=dave,OU=Users,DC=contoso,DC=local'
            whenCreated = [datetime]'2019-03-12T10:00:00Z'; primaryGroupID = 513
        }
        $p = ConvertFrom-FsAdResult -Result $result -Context $script:CtxAd
        $p.id | Should -Be $sid
        $p.kind | Should -Be 'User'
        $p.sid | Should -Be $sid
        $p.ad.enabled | Should -Be $true
        $p.ad.department | Should -Be 'HR'
        $p.ad.primaryGroupId | Should -Be 513
        $p.ad.manager.dn | Should -Be 'CN=dave,OU=Users,DC=contoso,DC=local'
        $p.ad.manager.sam | Should -BeNullOrEmpty
        $p.ad.whenCreated | Should -Match '^2019-03-12'
        $p.ad.lastLogonTimestamp | Should -Match '^2026-09-06T08:12:44'
    }

    It 'marks a disabled user (userAccountControl bit 0x2) as not enabled' {
        $sid = "$script:D-1102"
        $result = @{ objectSid = $sid; objectClass = @('user'); sAMAccountName = 'bob'; userAccountControl = 514; primaryGroupID = 513 }
        $p = ConvertFrom-FsAdResult -Result $result -Context $script:CtxAd
        $p.ad.enabled | Should -Be $false
    }

    It 'treats accountExpires 0 and max as null, same as the other FileTime fields' {
        $sid = "$script:D-1103"
        $result = @{ objectSid = $sid; objectClass = @('user'); sAMAccountName = 'carol'; userAccountControl = 512; accountExpires = 0; primaryGroupID = 513 }
        (ConvertFrom-FsAdResult -Result $result -Context $script:CtxAd).ad.accountExpires | Should -BeNullOrEmpty
        $result.accountExpires = [int64]0x7FFFFFFFFFFFFFFF
        (ConvertFrom-FsAdResult -Result $result -Context $script:CtxAd).ad.accountExpires | Should -BeNullOrEmpty
    }

    It 'converts a group result' {
        $sid = "$script:D-2001"
        $result = @{
            objectSid = $sid; objectClass = @('top', 'group'); distinguishedName = 'CN=HR-Share-RW,OU=Groups,DC=contoso,DC=local'
            sAMAccountName = 'HR-Share-RW'; groupType = -2147483646; description = 'Read/write access to the HR share'; mail = $null
            whenCreated = [datetime]'2018-01-15T10:00:00Z'; managedBy = 'CN=dave,OU=Users,DC=contoso,DC=local'
        }
        $p = ConvertFrom-FsAdResult -Result $result -Context $script:CtxAd
        $p.id | Should -Be $sid
        $p.kind | Should -Be 'Group'
        $p.ad.groupScope | Should -Be 'Global'
        $p.ad.groupCategory | Should -Be 'Security'
        $p.ad.managedBy.dn | Should -Be 'CN=dave,OU=Users,DC=contoso,DC=local'
    }

    It 'classifies a domain-relative well-known group (Domain Admins) as isWellKnown/isBroad appropriately' {
        $sid = "$script:D-512"
        $result = @{ objectSid = $sid; objectClass = @('group'); sAMAccountName = 'Domain Admins'; groupType = -2147483646 }
        $p = ConvertFrom-FsAdResult -Result $result -Context $script:CtxAd
        $p.isWellKnown | Should -Be $true
        $p.isBroad | Should -Be $false
    }

    It 'classifies a foreignSecurityPrincipal stub as Foreign with no ad payload' {
        $sid = 'S-1-5-21-4444444444-5555555555-6666666666-1001'
        $result = @{ objectSid = $sid; objectClass = @('top', 'foreignSecurityPrincipal'); distinguishedName = "CN=$sid,CN=ForeignSecurityPrincipals,DC=contoso,DC=local" }
        $p = ConvertFrom-FsAdResult -Result $result -Context $script:CtxAd
        $p.kind | Should -Be 'Foreign'
        $p.resolution | Should -Be 'Foreign'
        $p.ad | Should -BeNullOrEmpty
    }
}

Describe 'Add-FsWellKnownPrincipal' {
    It 'synthesizes a WellKnown principal with no AD contact' {
        $ctx = New-FsScanContext -ServerName TESTSRV -Credential $null -Options @{}
        Add-FsWellKnownPrincipal -Context $ctx -Sid 'S-1-1-0'
        $ctx.Principals.ContainsKey('S-1-1-0') | Should -Be $true
        $ctx.Principals['S-1-1-0'].kind | Should -Be 'WellKnown'
        $ctx.Principals['S-1-1-0'].isBroad | Should -Be $true
        $ctx.Principals['S-1-1-0'].name | Should -Be 'Everyone'
    }
}

Describe 'Resolve-FsPrincipal + Expand-FsGroupMembership (mocked AD)' {
    BeforeAll {
        $script:ParentSid = "$script:D-2001"; $script:ChildSid = "$script:D-2002"; $script:AliceSid = "$script:D-1101"
        $script:ParentDn = 'CN=ParentGroup,OU=Groups,DC=contoso,DC=local'
        $script:ChildDn = 'CN=ChildGroup,OU=Groups,DC=contoso,DC=local'
        $script:AliceDn = 'CN=alice,OU=Users,DC=contoso,DC=local'

        $script:SidResults = @{
            $script:ParentSid = @{ objectSid = $script:ParentSid; objectClass = @('group'); distinguishedName = $script:ParentDn; sAMAccountName = 'ParentGroup'; groupType = -2147483646 }
        }
        $script:DnResults = @{
            $script:ChildDn = @{ objectSid = $script:ChildSid; objectClass = @('group'); distinguishedName = $script:ChildDn; sAMAccountName = 'ChildGroup'; groupType = -2147483646 }
            $script:AliceDn = @{ objectSid = $script:AliceSid; objectClass = @('user'); distinguishedName = $script:AliceDn; sAMAccountName = 'alice'; userAccountControl = 512; primaryGroupID = 513 }
        }
        $script:MemberMap = @{ $script:ParentDn = @($script:ChildDn); $script:ChildDn = @($script:AliceDn) }
    }

    It 'resolves a nested group and its member end to end' {
        $ctx = New-FsScanContext -ServerName TESTSRV -Credential $null -Options @{}
        $ctx.DomainTable = @{
            Primary = @{ sid = $script:D; netbios = 'CONTOSO'; dns = 'contoso.local'; dn = 'DC=contoso,DC=local' }
            Domains = [ordered]@{ ($script:D) = @{ sid = $script:D; netbios = 'CONTOSO'; dns = 'contoso.local'; dn = 'DC=contoso,DC=local' } }
        }
        [void]$ctx.DomainSids.Add($script:D)

        Mock -CommandName Get-FsAdSearcherForDomain -ModuleName FsPerm { @{ Stub = $true } }
        Mock -CommandName Get-FsAdSearcherForDn -ModuleName FsPerm { @{ Stub = $true } }
        Mock -CommandName Get-FsAdObjectsBySid -ModuleName FsPerm {
            param($Searcher, $Sid, $BatchSize = 100)
            $found = [System.Collections.Generic.Dictionary[string, object]]::new([System.StringComparer]::OrdinalIgnoreCase)
            foreach ($s in $Sid) { if ($script:SidResults.ContainsKey($s)) { $found[$s] = $script:SidResults[$s] } }
            return @{ Found = $found; Errors = @() }
        }
        Mock -CommandName Get-FsAdObjectsByDn -ModuleName FsPerm {
            param($Searcher, $Dn, $BatchSize = 100)
            $found = [System.Collections.Generic.Dictionary[string, object]]::new([System.StringComparer]::OrdinalIgnoreCase)
            foreach ($d in $Dn) { if ($script:DnResults.ContainsKey($d)) { $found[$d] = $script:DnResults[$d] } }
            return @{ Found = $found; Errors = @() }
        }
        Mock -CommandName Get-FsAdRangedAttribute -ModuleName FsPerm {
            param($Searcher, $Dn, $Attribute = 'member', $Step = 1500)
            if ($script:MemberMap.ContainsKey($Dn)) { return [string[]]@($script:MemberMap[$Dn]) }
            return [string[]]@()
        }

        Resolve-FsPrincipal -Context $ctx -Sid @($script:ParentSid)
        $ctx.Principals.ContainsKey($script:ParentSid) | Should -Be $true
        $ctx.Principals[$script:ParentSid].kind | Should -Be 'Group'

        Expand-FsGroupMembership -Context $ctx -MaxDepth 10

        $ctx.Principals.ContainsKey($script:ChildSid) | Should -Be $true
        $ctx.Principals.ContainsKey($script:AliceSid) | Should -Be $true
        $ctx.Principals[$script:ChildSid].kind | Should -Be 'Group'
        $ctx.Principals[$script:AliceSid].kind | Should -Be 'User'

        @($ctx.Memberships | Where-Object { $_.groupId -eq $script:ParentSid -and $_.memberId -eq $script:ChildSid -and $_.kind -eq 'Direct' }).Count | Should -Be 1
        @($ctx.Memberships | Where-Object { $_.groupId -eq $script:ChildSid -and $_.memberId -eq $script:AliceSid -and $_.kind -eq 'Direct' }).Count | Should -Be 1

        # implicit primary-group edge (RID 513) synthesized without enumerating Domain Users
        $domainUsersId = "$script:D-513"
        @($ctx.Memberships | Where-Object { $_.groupId -eq $domainUsersId -and $_.memberId -eq $script:AliceSid -and $_.kind -eq 'PrimaryGroup' }).Count | Should -Be 1
        $ctx.Principals[$domainUsersId].membershipResolved | Should -Be $false
    }
}

Describe 'Resolve-FsManagerReferences' {
    It 'fills in sam/sid for manager references without adding the manager as a new principal' {
        $ctx = New-FsScanContext -ServerName TESTSRV -Credential $null -Options @{}
        $ctx.DomainTable = @{
            Primary = @{ sid = $script:D; netbios = 'CONTOSO'; dns = 'contoso.local'; dn = 'DC=contoso,DC=local' }
            Domains = [ordered]@{ ($script:D) = @{ sid = $script:D; netbios = 'CONTOSO'; dns = 'contoso.local'; dn = 'DC=contoso,DC=local' } }
        }
        $daveDn = 'CN=dave,OU=Users,DC=contoso,DC=local'
        $aliceSid = "$script:D-1101"
        $ctx.Principals[$aliceSid] = New-FsPrincipal -Id $aliceSid -Kind User -Sid $aliceSid -Name 'alice' -Ad ([ordered]@{ manager = @{ dn = $daveDn; sam = $null; sid = $null } })

        Mock -CommandName Get-FsAdSearcherForDn -ModuleName FsPerm { @{ Stub = $true } }
        Mock -CommandName Get-FsAdObjectsByDn -ModuleName FsPerm {
            param($Searcher, $Dn, $BatchSize = 100)
            $found = [System.Collections.Generic.Dictionary[string, object]]::new([System.StringComparer]::OrdinalIgnoreCase)
            if ($Dn -contains $daveDn) { $found[$daveDn] = @{ distinguishedName = $daveDn; sAMAccountName = 'dave'; objectSid = "$script:D-1104" } }
            return @{ Found = $found; Errors = @() }
        }

        Resolve-FsManagerReferences -Context $ctx

        $ctx.Principals[$aliceSid].ad.manager.sam | Should -Be 'dave'
        $ctx.Principals[$aliceSid].ad.manager.sid | Should -Be "$script:D-1104"
        $ctx.Principals.ContainsKey("$script:D-1104") | Should -Be $false
    }
}

Describe 'Get-FsScanSummary' {
    It 'produces non-empty lines mentioning the counts, duration and partial status' {
        $snap = New-FsSnapshot -ServerName FS99 -Depth 1
        $snap.shares.Add((New-FsShare -Server FS99 -Name Test -LocalPath 'D:\Test'))
        $snap.shares[0].walk.truncated = $true
        $snap.errors.Add((New-FsError -Phase Walk -Message 'boom'))
        $snap.status.partial = $true
        $snap.durationSeconds = 12.3
        $snap.stats = [ordered]@{ shares = 1; foldersVisited = 1; foldersReturned = 1; principals = 0; memberships = 0; errors = 1 }

        $lines = Get-FsScanSummary -Snapshot $snap
        $lines.Count | Should -BeGreaterThan 0
        $joined = $lines -join "`n"
        $joined | Should -Match 'Shares: 1'
        $joined | Should -Match 'PARTIAL'
        $joined | Should -Match 'Duration: 12\.3s'
        $joined | Should -Match "Truncated: share 'Test'"
    }
}

Describe 'Get-FsAdDomainTable' {
    BeforeEach {
        # RootDSE is read via a raw DirectoryEntry (New-FsAdEntry); the domain object's objectSid, and
        # crossRef/trustedDomain enumeration, all go through New-FsAdSearcher/Invoke-FsAdSearch instead
        # (a Base-scoped DirectorySearcher with explicit PropertiesToLoad reliably returns objectSid where
        # a bare DirectoryEntry.Properties lookup was observed, against a real domain, to silently miss it).
        # New-FsAdSearcher's return only needs a settable .Searcher.SearchScope - Get-FsAdDomainTable sets
        # that directly - everything else about the real search runs through the mocked Invoke-FsAdSearch.
        Mock -CommandName New-FsAdSearcher -ModuleName FsPerm { @{ Searcher = [pscustomobject]@{ SearchScope = $null } } }
        # Default: no results (covers crossRef/trustedDomain enumeration, exercised elsewhere as a no-op here).
        Mock -CommandName Invoke-FsAdSearch -ModuleName FsPerm { @() }
    }
    It 'builds the primary domain entry when everything resolves normally' {
        Mock -CommandName New-FsAdEntry -ModuleName FsPerm {
            param($Path, $Server, $Credential)
            return [pscustomobject]@{ Properties = @{
                defaultNamingContext = [pscustomobject]@{ Value = 'DC=contoso,DC=local' }
                configurationNamingContext = [pscustomobject]@{ Value = 'CN=Configuration,DC=contoso,DC=local' }
                dnsHostName = [pscustomobject]@{ Value = 'dc01.contoso.local' }
            } }
        }
        # Revision 1, sub-authority count 4 (21, a, b, c - a domain SID has no trailing RID), NT authority (5).
        $sidBytes = [byte[]](1, 4, 0, 0, 0, 0, 0, 5, 21, 0, 0, 0, 177, 190, 4, 173, 202, 91, 79, 24, 84, 62, 19, 190)
        Mock -CommandName Invoke-FsAdSearch -ModuleName FsPerm -ParameterFilter { $Filter -eq '(objectClass=*)' } {
            @([pscustomobject]@{ Properties = @{ objectsid = $sidBytes } })
        }
        $table = Get-FsAdDomainTable
        $table.Primary.dns | Should -Be 'contoso.local'
        $table.Primary.sidDegraded | Should -BeFalse
        # [System.Security.Principal.SecurityIdentifier] throws "not supported on this platform" under
        # Linux/pwsh (used by the Docker test container), so Get-FsAdDomainTable's underlying SID-bytes ->
        # string conversion silently falls back to base64 there while producing a real S-1-5-21-... string
        # on Windows. Compare against whatever that conversion actually produces on this platform, rather
        # than a hardcoded SID string, so the test is meaningful on both.
        $expectedSid = try { ([System.Security.Principal.SecurityIdentifier]::new($sidBytes, 0)).Value } catch { [Convert]::ToBase64String($sidBytes) }
        $table.Primary.sid | Should -Be $expectedSid
        $table.Domains.Contains($expectedSid) | Should -BeTrue
    }
    It 'degrades to the domain DN as a stand-in key when objectSid cannot be read, instead of throwing' {
        Mock -CommandName New-FsAdEntry -ModuleName FsPerm {
            param($Path, $Server, $Credential)
            return [pscustomobject]@{ Properties = @{
                defaultNamingContext = [pscustomobject]@{ Value = 'DC=contoso,DC=local' }
                configurationNamingContext = [pscustomobject]@{ Value = 'CN=Configuration,DC=contoso,DC=local' }
                dnsHostName = [pscustomobject]@{ Value = 'dc01.contoso.local' }
            } }
        }
        # BeforeEach's default Invoke-FsAdSearch mock (returns @() for every filter, including
        # '(objectClass=*)') already reproduces "the domain object search returned nothing" - no
        # override needed here.
        # Not `{ $table = ... } | Should -Not -Throw`: that scriptblock runs in its own scope,
        # so the assignment to $table would not be visible out here afterwards.
        $table = $null
        $caught = $null
        try { $table = Get-FsAdDomainTable } catch { $caught = $_ }
        $caught | Should -BeNullOrEmpty
        $table.Primary.sid | Should -Be 'DC=contoso,DC=local'
        $table.Primary.dns | Should -Be 'contoso.local'
        $table.Primary.sidDegraded | Should -BeTrue
        $table.Domains.Contains('DC=contoso,DC=local') | Should -BeTrue
    }
    It 'throws a clear, actionable error when RootDSE itself cannot be reached' {
        Mock -CommandName New-FsAdEntry -ModuleName FsPerm { throw [System.Runtime.InteropServices.COMException]::new('The server is not operational.') }
        { Get-FsAdDomainTable } | Should -Throw '*SkipAdEnrichment*'
    }
}

Describe 'Get-FsSidTableEntry' {
    <#
    Regression test: PowerShell's late-bound method dispatch on a real Dictionary[string,object] (the type
    ScanContext.ps1 actually uses for SidTable) resolves .Contains(x) to ICollection<KeyValuePair>.Contains,
    not IDictionary.Contains(key); passing a bare SID string then throws "Cannot find an overload for
    'Contains' and the argument count: 1" - only caught on a real scan, never by a mocked SidTable.
    #>
    It 'looks up a hit and a miss against a real Dictionary[string,object] without throwing' {
        $d = [System.Collections.Generic.Dictionary[string, object]]::new([System.StringComparer]::OrdinalIgnoreCase)
        $d['S-1-5-11'] = @{ name = 'NT AUTHORITY\Authenticated Users'; isLocal = $false }
        $hit = Get-FsSidTableEntry -SidTable $d -Sid 'S-1-5-11'
        $hit.name | Should -Be 'NT AUTHORITY\Authenticated Users'
        $hit.isLocal | Should -BeFalse
        $miss = Get-FsSidTableEntry -SidTable $d -Sid 'S-1-5-99'
        $miss.name | Should -BeNullOrEmpty
        $miss.isLocal | Should -BeFalse
    }
    It 'also works against an [ordered] dictionary (fixtures / tests)' {
        $o = [ordered]@{ 'S-1-1-0' = @{ name = 'Everyone'; isLocal = $false } }
        (Get-FsSidTableEntry -SidTable $o -Sid 'S-1-1-0').name | Should -Be 'Everyone'
    }
}

Describe 'Invoke-FsScan -DryRun' -Tag WindowsOnly {
    It 'connects over WinRM and returns a dry-run snapshot (needs a reachable Windows target)' {
        if (-not $IsWindows) { Set-ItResult -Skipped -Because 'requires WinRM and is excluded on Linux'; return }
        Set-ItResult -Skipped -Because 'no reachable Windows file server target is available in this environment'
    }
}
