#Requires -Modules @{ ModuleName = 'Pester'; ModuleVersion = '5.5.0' }
<# Note naming: Get-FsSafeNoteName rules, Get-FsNotePath per entity kind, collisions, primary domain. #>

BeforeAll {
    . (Join-Path $PSScriptRoot 'TestHelpers.ps1')
    $script:D = 'S-1-5-21-1111111111-2222222222-3333333333'
}

Describe 'Get-FsSafeNoteName' {
    It 'replaces illegal characters with underscores' {
        Get-FsSafeNoteName -Name 'a#b^c[d]e|f\g/h:i*j?k"l<m>n' | Should -Be 'a_b_c_d_e_f_g_h_i_j_k_l_m_n'
    }
    It 'replaces control characters and collapses whitespace' {
        Get-FsSafeNoteName -Name "tab`there   and`nnewline" | Should -Be 'tab_here and_newline'
    }
    It 'trims and strips trailing dots and spaces' {
        Get-FsSafeNoteName -Name '  Budgets 2024... ' | Should -Be 'Budgets 2024'
    }
    It 'turns a leading dot into an underscore' {
        Get-FsSafeNoteName -Name '.hidden' | Should -Be '_hidden'
    }
    It 'suffixes Windows reserved device names with a hash' {
        foreach ($n in 'CON', 'con', 'PRN', 'AUX', 'NUL', 'COM1', 'COM9', 'LPT1', 'lpt9') {
            $r = Get-FsSafeNoteName -Name $n
            $r | Should -Match ('^{0} ~[0-9a-f]{{6}}$' -f [regex]::Escape($n))
        }
        Get-FsSafeNoteName -Name 'CONSOLE' | Should -Be 'CONSOLE'
        Get-FsSafeNoteName -Name 'COM10' | Should -Be 'COM10'
    }
    It 'caps length at MaxLength including the hash suffix' {
        $long = 'x' * 150
        $r = Get-FsSafeNoteName -Name $long -MaxLength 100
        $r.Length | Should -Be 100
        $r | Should -Match '^x{92} ~[0-9a-f]{6}$'
        (Get-FsSafeNoteName -Name ('y' * 100)).Length | Should -Be 100
        (Get-FsSafeNoteName -Name ('y' * 100)) | Should -Not -Match '~'
    }
    It 'hashes the Identity, not the display name, when given' {
        $a = Get-FsSafeNoteName -Name 'CON' -Identity 'id-1'
        $b = Get-FsSafeNoteName -Name 'CON' -Identity 'id-2'
        $a | Should -Not -Be $b
        $a | Should -Be ('CON ~' + (Get-FsShortHash -Text 'id-1'))
    }
    It 'is deterministic' {
        (Get-FsSafeNoteName -Name 'Some: Name?') | Should -Be (Get-FsSafeNoteName -Name 'Some: Name?')
        (Get-FsShortHash -Text 'abc') | Should -Be 'a9993e'
    }
    It 'handles an empty result' {
        Get-FsSafeNoteName -Name '...' | Should -Match '^_ ~[0-9a-f]{6}$'
    }
}

Describe 'Get-FsPrimaryDomain' {
    BeforeAll { $script:Model = Get-FixtureModel }
    It 'detects CONTOSO from the fixture model' {
        Get-FsPrimaryDomain -Model $script:Model | Should -Be 'CONTOSO'
    }
    It 'lets -Requested win' {
        Get-FsPrimaryDomain -Model $script:Model -Requested 'CORP' | Should -Be 'CORP'
    }
    It 'falls back to a constant on an empty model' {
        $r = Get-FsPrimaryDomain -Model ([ordered]@{ principals = [ordered]@{}; domains = [ordered]@{} })
        $r | Should -Not -BeNullOrEmpty
    }
}

Describe 'Get-FsNotePath' {
    BeforeAll {
        $script:Model = Get-FixtureModel
        $script:Ctx = New-FsNameContext -Model $script:Model
    }
    It 'names primary-domain users and groups by sAMAccountName' {
        Get-FsNotePath -Context $script:Ctx -Kind Principal -Id "$script:D-1101" | Should -Be 'Users/alice'
        Get-FsNotePath -Context $script:Ctx -Kind Principal -Id "$script:D-2001" | Should -Be 'Groups/HR-Share-RW'
        Get-FsNotePath -Context $script:Ctx -Kind Principal -Id "$script:D-513" | Should -Be 'Groups/Domain Users'
    }
    It 'prefixes other-domain principals with the domain' {
        $ctx = New-FsNameContext -Model $script:Model -PrimaryDomain 'CORP'
        Get-FsNotePath -Context $ctx -Kind Principal -Id "$script:D-1101" | Should -Be 'Users/CONTOSO - alice'
        Get-FsNotePath -Context $ctx -Kind Principal -Id "$script:D-2003" | Should -Be 'Groups/CONTOSO - Finance-RO'
    }
    It 'puts server-local groups (including BUILTIN ones) under Groups/<SERVER> - <name>' {
        Get-FsNotePath -Context $script:Ctx -Kind Principal -Id 'FS01\Users' | Should -Be 'Groups/FS01 - Users'
        Get-FsNotePath -Context $script:Ctx -Kind Principal -Id 'FS01\Administrators' | Should -Be 'Groups/FS01 - Administrators'
        Get-FsNotePath -Context $script:Ctx -Kind Principal -Id 'FS02\Administrators' | Should -Be 'Groups/FS02 - Administrators'
        Get-FsNotePath -Context $script:Ctx -Kind Principal -Id 'FS01\FileAdmins' | Should -Be 'Groups/FS01 - FileAdmins'
    }
    It 'puts server-local users under Users/<SERVER> - <name>' {
        Get-FsNotePath -Context $script:Ctx -Kind Principal -Id 'FS01\Administrator' | Should -Be 'Users/FS01 - Administrator'
    }
    It 'puts well-known principals under WellKnown/' {
        Get-FsNotePath -Context $script:Ctx -Kind Principal -Id 'S-1-5-11' | Should -Be 'WellKnown/Authenticated Users'
        Get-FsNotePath -Context $script:Ctx -Kind Principal -Id 'S-1-1-0' | Should -Be 'WellKnown/Everyone'
    }
    It 'names BUILTIN well-known SIDs WellKnown/BUILTIN - <name>' {
        $m = Get-FixtureModel
        $m.principals['S-1-5-32-544'] = [ordered]@{ id = 'S-1-5-32-544'; kind = 'WellKnown'; sid = 'S-1-5-32-544'; domain = 'BUILTIN'; name = 'Administrators'; displayName = 'Administrators'; isWellKnown = $true }
        $ctx = New-FsNameContext -Model $m
        Get-FsNotePath -Context $ctx -Kind Principal -Id 'S-1-5-32-544' | Should -Be 'WellKnown/BUILTIN - Administrators'
    }
    It 'puts orphaned and foreign SIDs under Orphaned/' {
        Get-FsNotePath -Context $script:Ctx -Kind Principal -Id "$script:D-9999" | Should -Be 'Orphaned/S-1-5-21-1111111111-2222222222-3333333333-9999'
        Get-FsNotePath -Context $script:Ctx -Kind Principal -Id 'S-1-5-21-4444444444-5555555555-6666666666-1001' | Should -Be 'Orphaned/S-1-5-21-4444444444-5555555555-6666666666-1001'
    }
    It 'synthesizes a path for an unknown principal id' {
        Get-FsNotePath -Context $script:Ctx -Kind Principal -Id 'S-1-5-21-9-9-9-1' | Should -Be 'Orphaned/S-1-5-21-9-9-9-1'
        Get-FsNotePath -Context $script:Ctx -Kind Principal -Id 'FS09\Ghosts' | Should -Be 'Groups/FS09 - Ghosts'
    }
    It 'names servers, shares and same-named shares on two servers distinctly' {
        Get-FsNotePath -Context $script:Ctx -Kind Server -Id 'FS01' | Should -Be 'Servers/FS01'
        Get-FsNotePath -Context $script:Ctx -Kind Share -Id 'FS01\Finance' | Should -Be 'Shares/FS01 - Finance'
        Get-FsNotePath -Context $script:Ctx -Kind Share -Id 'FS02\Finance' | Should -Be 'Shares/FS02 - Finance'
        Get-FsNotePath -Context $script:Ctx -Kind Share -Id 'FS01\HR' -Extension md | Should -Be 'Shares/FS01 - HR.md'
    }
    It 'names folders Folders/<SERVER>/<share>/<relative path with " - ">' {
        Get-FsNotePath -Context $script:Ctx -Kind Folder -Id 'FS01:D:\Shares\HR\Payroll\Archive' | Should -Be 'Folders/FS01/HR/Payroll - Archive'
        Get-FsNotePath -Context $script:Ctx -Kind Folder -Id 'FS01:D:\Shares\HR\Payroll' | Should -Be 'Folders/FS01/HR/Payroll'
        Get-FsNotePath -Context $script:Ctx -Kind Folder -Id 'FS01:D:\Shares\Finance\Budgets' | Should -Be 'Folders/FS01/Finance/Budgets'
    }
    It 'maps share-root folders to the Share note' {
        Get-FsNotePath -Context $script:Ctx -Kind Folder -Id 'FS01:D:\Shares\HR' | Should -Be 'Shares/FS01 - HR'
        Get-FsNotePath -Context $script:Ctx -Kind Folder -Id 'FS02:E:\Public\Archive' | Should -Be 'Shares/FS02 - PublicArchive'
        $script:Ctx.warnings.Count | Should -Be 0
    }
    It 'hash-suffixes folders whose components contain " - " or replaced characters' {
        $m = Get-FixtureModel
        $f1 = New-FsFolder -Server FS01 -LocalPath 'D:\Shares\HR\Q1 - Review' -ShareNames HR -ShareLocalPath 'D:\Shares\HR' -Depth 1
        $f2 = New-FsFolder -Server FS01 -LocalPath 'D:\Shares\HR\Q1\Review' -ShareNames HR -ShareLocalPath 'D:\Shares\HR' -Depth 2
        $f3 = New-FsFolder -Server FS01 -LocalPath 'D:\Shares\HR\What?' -ShareNames HR -ShareLocalPath 'D:\Shares\HR' -Depth 1
        foreach ($f in $f1, $f2, $f3) { $m.folders[$f.id] = ConvertFrom-Json -InputObject (ConvertTo-Json -InputObject $f -Depth 10) -AsHashtable }
        $ctx = New-FsNameContext -Model $m
        $p1 = Get-FsNotePath -Context $ctx -Kind Folder -Id $f1.id
        $p2 = Get-FsNotePath -Context $ctx -Kind Folder -Id $f2.id
        $p1 | Should -Match '^Folders/FS01/HR/Q1 - Review ~[0-9a-f]{6}$'
        $p2 | Should -Be 'Folders/FS01/HR/Q1 - Review'
        $p1 | Should -Not -Be $p2
        Get-FsNotePath -Context $ctx -Kind Folder -Id $f3.id | Should -Match '^Folders/FS01/HR/What_ ~[0-9a-f]{6}$'
    }
    It 'builds Effective companion paths under Effective/' {
        Get-FsNotePath -Context $script:Ctx -Kind Effective -Id "$script:D-1101" | Should -Be 'Effective/Users/alice'
        Get-FsNotePath -Context $script:Ctx -Kind Effective -Id 'FS01\Finance' | Should -Be 'Effective/Shares/FS01 - Finance'
        Get-FsNotePath -Context $script:Ctx -Kind Effective -Id 'FS01\Users' | Should -Be 'Effective/Groups/FS01 - Users'
    }
    It 'names reports, home and canvas' {
        Get-FsNotePath -Context $script:Ctx -Kind Report -Id '01 Broad Exposure' | Should -Be 'Reports/01 Broad Exposure'
        Get-FsNotePath -Context $script:Ctx -Kind Report -Id 'Changes - FS01' | Should -Be 'Reports/Changes - FS01'
        Get-FsNotePath -Context $script:Ctx -Kind Home | Should -Be 'Home'
        Get-FsNotePath -Context $script:Ctx -Kind Canvas -Extension canvas | Should -Be 'Dashboard.canvas'
    }
    It 'memoizes and stays deterministic across contexts' {
        $ctx2 = New-FsNameContext -Model (Get-FixtureModel)
        foreach ($id in Get-FsSortedKeys $script:Model.principals) {
            (Get-FsNotePath -Context $ctx2 -Kind Principal -Id $id) | Should -Be (Get-FsNotePath -Context $script:Ctx -Kind Principal -Id $id)
        }
    }
    It 'resolves residual collisions case-insensitively with a hash suffix and a warning' {
        $m = Get-FixtureModel
        $m.principals["$script:D-7001"] = [ordered]@{ id = "$script:D-7001"; kind = 'User'; sid = "$script:D-7001"; domain = 'CONTOSO'; name = 'ALICE'; displayName = 'Other Alice' }
        $ctx = New-FsNameContext -Model $m
        Get-FsNotePath -Context $ctx -Kind Principal -Id "$script:D-1101" | Should -Be 'Users/alice'
        $other = Get-FsNotePath -Context $ctx -Kind Principal -Id "$script:D-7001"
        $other | Should -Match '^Users/ALICE ~[0-9a-f]{6}$'
        $ctx.warnings.Count | Should -Be 1
        $ctx.warnings[0] | Should -Match 'collision'
        # memoized: asking again returns the same suffixed path without a second warning
        Get-FsNotePath -Context $ctx -Kind Principal -Id "$script:D-7001" | Should -Be $other
        $ctx.warnings.Count | Should -Be 1
    }
}

Describe 'Get-FsDisplayName' {
    BeforeAll { $script:Model = Get-FixtureModel }
    It 'uses sAMAccountName for domain principals and "Name (SERVER)" for local ones' {
        Get-FsDisplayName -Model $script:Model -Kind Principal -Id "$script:D-1101" | Should -Be 'alice'
        Get-FsDisplayName -Model $script:Model -Kind Principal -Id 'FS01\FileAdmins' | Should -Be 'FileAdmins (FS01)'
        Get-FsDisplayName -Model $script:Model -Kind Principal -Id 'S-1-5-11' | Should -Be 'Authenticated Users'
        Get-FsDisplayName -Model $script:Model -Kind Principal -Id "$script:D-9999" | Should -Be "$script:D-9999"
    }
    It 'uses UNC paths for shares and relative paths for folders' {
        Get-FsDisplayName -Model $script:Model -Kind Share -Id 'FS01\Finance' | Should -Be '\\FS01\Finance'
        Get-FsDisplayName -Model $script:Model -Kind Folder -Id 'FS01:D:\Shares\HR\Payroll\Archive' | Should -Be 'Payroll\Archive'
        Get-FsDisplayName -Model $script:Model -Kind Folder -Id 'FS01:D:\Shares\HR' | Should -Be '\\FS01\HR'
        Get-FsDisplayName -Model $script:Model -Kind Server -Id 'fs01' | Should -Be 'FS01'
        Get-FsDisplayName -Model $script:Model -Kind Report -Id '01 Broad Exposure' | Should -Be '01 Broad Exposure'
    }
}
