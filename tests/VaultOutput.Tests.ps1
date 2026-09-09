#Requires -Modules @{ ModuleName = 'Pester'; ModuleVersion = '5.5.0' }
<# Staging -> vault sync: minimal churn, safe deletes, manifest, -WhatIf; .obsidian seeding. #>

BeforeAll {
    . (Join-Path $PSScriptRoot 'TestHelpers.ps1')

    function New-StagedVault {
        <# Renders a tiny fake vault into a fresh staging folder. -Without removes a relative path. #>
        param([string[]] $Without = @(), [hashtable] $Override = @{})
        $stage = New-FsVaultStaging
        $files = [ordered]@{
            'Home.md'                        = "---`ntype: home`ngenerated: true`n---`n# Home`n"
            'Dashboard.canvas'               = "{`n  `"nodes`": [],`n  `"edges`": []`n}`n"
            'Users.base'                     = "filters:`n  and:`n    - file.hasTag(`"user`")`nviews:`n  - type: table`n    name: All`n"
            'Users/alice.md'                 = "---`ntype: user`ngenerated: true`n---`n# alice`n"
            'Users/bob.md'                   = "---`ntype: user`ngenerated: true`n---`n# bob`n"
            'Shares/FS01 - HR.md'            = "---`ntype: share`ngenerated: true`n---`n# HR`n"
            'Folders/FS01/HR/Payroll.md'     = "---`ntype: folder`ngenerated: true`n---`n# Payroll`n"
            'Reports/01 Broad Exposure.md'   = "---`ntype: report`ngenerated: true`n---`n# Broad`n"
            '_meta/exports/01 Broad.csv'     = "a,b`n1,2`n"
            '_meta/README.md'                = "---`ngenerated: true`n---`n# README`n"
        }
        foreach ($k in $Override.Keys) { $files[$k] = $Override[$k] }
        foreach ($k in $files.Keys) {
            if ($Without -contains $k) { continue }
            Write-FsVaultFile -Root $stage -RelativePath $k -Content $files[$k] | Out-Null
        }
        return $stage
    }

    function New-Manifest { New-FsVaultManifest -PrimaryDomain 'CONTOSO' -GeneratedAt '2026-09-09T12:00:00Z' -ScanIds @('bbbb', 'aaaa') }
}

Describe 'Write-FsVaultFile / Get-FsFileSha256' {
    It 'writes UTF-8 without BOM with LF endings and creates directories' {
        $root = Join-Path $TestDrive 'w'
        $p = Write-FsVaultFile -Root $root -RelativePath 'a/b/c.md' -Content "x`r`ny`r`n"
        Test-Path -LiteralPath $p | Should -BeTrue
        $bytes = [System.IO.File]::ReadAllBytes($p)
        $bytes[0] | Should -Be 0x78
        [System.Text.Encoding]::UTF8.GetString($bytes) | Should -Be "x`ny`n"
        Get-FsFileSha256 -Path $p | Should -Match '^[0-9a-f]{64}$'
    }
}

Describe 'Test-FsVaultOwnedPath' {
    It 'recognizes owned roots and top-level generated files only' {
        Test-FsVaultOwnedPath 'Users/alice.md' | Should -BeTrue
        Test-FsVaultOwnedPath 'users/alice.md' | Should -BeTrue
        Test-FsVaultOwnedPath '_meta/manifest.json' | Should -BeTrue
        Test-FsVaultOwnedPath 'Home.md' | Should -BeTrue
        Test-FsVaultOwnedPath 'Dashboard.canvas' | Should -BeTrue
        Test-FsVaultOwnedPath 'Users.base' | Should -BeTrue
        Test-FsVaultOwnedPath 'Notes/mine.md' | Should -BeFalse
        Test-FsVaultOwnedPath '.obsidian/app.json' | Should -BeFalse
        Test-FsVaultOwnedPath 'README.md' | Should -BeFalse
        Test-FsVaultIgnoredPath '_meta/snapshots/FS01/x.json.gz' | Should -BeTrue
        Test-FsVaultIgnoredPath '_meta/exports/x.csv' | Should -BeFalse
    }
}

Describe 'Sync-FsVaultOutput' {
    BeforeAll {
        $script:Vault = Join-Path $TestDrive 'vault'
        New-Item -ItemType Directory -Path (Join-Path $script:Vault 'Notes') -Force | Out-Null
        New-Item -ItemType Directory -Path (Join-Path $script:Vault '.obsidian') -Force | Out-Null
        [System.IO.File]::WriteAllText((Join-Path (Join-Path $script:Vault 'Notes') 'mine.md'), "# mine`n")
        [System.IO.File]::WriteAllText((Join-Path (Join-Path $script:Vault '.obsidian') 'app.json'), "{ `"custom`": true }`n")
        New-Item -ItemType Directory -Path (Join-Path $script:Vault 'Users') -Force | Out-Null
        [System.IO.File]::WriteAllText((Join-Path (Join-Path $script:Vault 'Users') 'handwritten.md'), "---`ntype: user`n---`n# not generated`n")
    }
    It 'first sync writes every staged file and the manifest' {
        $stage = New-StagedVault
        $r = Sync-FsVaultOutput -Staging $stage -VaultPath $script:Vault -Manifest (New-Manifest)
        $r.counts.written | Should -Be 10
        $r.counts.skipped | Should -Be 0
        $r.counts.deleted | Should -Be 0
        $r.written | Should -Contain 'Users/alice.md'
        $r.written | Should -Contain 'Folders/FS01/HR/Payroll.md'
        Test-Path -LiteralPath $stage | Should -BeFalse
        Test-Path -LiteralPath (Join-Path $script:Vault 'Users/alice.md') | Should -BeTrue
        Test-Path -LiteralPath (Join-Path $script:Vault '_meta/manifest.json') | Should -BeTrue
        $r.unexpected | Should -Be @('Users/handwritten.md')
        $r.warnings.Count | Should -Be 1
    }
    It 'wrote a manifest with sorted hashed files and metadata' {
        $m = Read-FsVaultManifest -VaultPath $script:Vault
        $m.version | Should -Be 1
        $m.primaryDomain | Should -Be 'CONTOSO'
        # ConvertFrom-Json auto-detects ISO-8601 strings as [datetime]; Read-FsVaultManifest normalizes the
        # result back to a string, but not necessarily byte-identical to what was written (fractional seconds
        # may appear) - only that it parses back to the same instant.
        [datetime]$m.generatedAt | Should -Be ([datetime]'2026-09-09T12:00:00Z')
        @($m.scanIds) | Should -Be @('aaaa', 'bbbb')
        $m.files.Count | Should -Be 10
        $m.files['Users/alice.md'] | Should -Be (Get-FsFileSha256 -Path (Join-Path $script:Vault 'Users/alice.md'))
        $m.files.Keys | Should -Not -Contain '_meta/manifest.json'
        $text = [System.IO.File]::ReadAllText((Join-Path $script:Vault '_meta/manifest.json'))
        $text | Should -Not -Match "`r"
        $keys = @($m.files.Keys)
        ($keys -join '|') | Should -Be ((Get-FsSorted -InputObject $keys) -join '|')
    }
    It 'second identical sync writes nothing' {
        $stage = New-StagedVault
        $r = Sync-FsVaultOutput -Staging $stage -VaultPath $script:Vault -Manifest (New-Manifest)
        $r.counts.written | Should -Be 0
        $r.counts.skipped | Should -Be 10
        $r.counts.deleted | Should -Be 0
        $r.unexpected | Should -Be @('Users/handwritten.md')
    }
    It 'rewrites only changed files' {
        $stage = New-StagedVault -Override @{ 'Users/bob.md' = "---`ntype: user`ngenerated: true`n---`n# bob (changed)`n" }
        $r = Sync-FsVaultOutput -Staging $stage -VaultPath $script:Vault -Manifest (New-Manifest)
        $r.written | Should -Be @('Users/bob.md')
        $r.counts.skipped | Should -Be 9
    }
    It 'rewrites a file the user edited in place (hash unchanged in manifest, length differs)' {
        $alice = Join-Path $script:Vault 'Users/alice.md'
        [System.IO.File]::AppendAllText($alice, "user scribble`n")
        # Restage bob.md with the SAME "(changed)" content the previous test left in the vault/manifest,
        # so this test isolates alice's scenario instead of also re-detecting bob as changed.
        $stage = New-StagedVault -Override @{ 'Users/bob.md' = "---`ntype: user`ngenerated: true`n---`n# bob (changed)`n" }
        $r = Sync-FsVaultOutput -Staging $stage -VaultPath $script:Vault -Manifest (New-Manifest)
        $r.written | Should -Be @('Users/alice.md')
        [System.IO.File]::ReadAllText($alice) | Should -Not -Match 'scribble'
    }
    It '-WhatIf reports but deletes and writes nothing' {
        $stage = New-StagedVault -Without 'Users/bob.md', 'Folders/FS01/HR/Payroll.md' -Override @{ 'Users/alice.md' = "---`ngenerated: true`n---`n# alice v2`n" }
        $before = Read-FsVaultManifest -VaultPath $script:Vault
        $r = Sync-FsVaultOutput -Staging $stage -VaultPath $script:Vault -Manifest (New-Manifest) -WhatIf
        $r.dryRun | Should -BeTrue
        $r.deleted | Should -Be @('Folders/FS01/HR/Payroll.md', 'Users/bob.md')
        $r.written | Should -Be @('Users/alice.md')
        Test-Path -LiteralPath (Join-Path $script:Vault 'Users/bob.md') | Should -BeTrue
        Test-Path -LiteralPath (Join-Path $script:Vault 'Folders/FS01/HR/Payroll.md') | Should -BeTrue
        [System.IO.File]::ReadAllText((Join-Path $script:Vault 'Users/alice.md')) | Should -Not -Match 'v2'
        (Read-FsVaultManifest -VaultPath $script:Vault).files.Count | Should -Be $before.files.Count
        Test-Path -LiteralPath $stage | Should -BeFalse
    }
    It 'deletes stale generated files, removes empty folders, and never touches Notes/, .obsidian/ or unmarked files' {
        # a previously generated note that lost its marker must survive
        $bobPath = Join-Path $script:Vault 'Users/bob.md'
        [System.IO.File]::WriteAllText($bobPath, "---`ntype: user`n---`n# bob, now mine`n")
        $stage = New-StagedVault -Without 'Users/bob.md', 'Folders/FS01/HR/Payroll.md', '_meta/exports/01 Broad.csv'
        $r = Sync-FsVaultOutput -Staging $stage -VaultPath $script:Vault -Manifest (New-Manifest)
        # Ordinal sort: '_' (0x5F) sorts after 'F' (0x46), so Folders/... precedes _meta/...
        $r.deleted | Should -Be @('Folders/FS01/HR/Payroll.md', '_meta/exports/01 Broad.csv')
        Test-Path -LiteralPath (Join-Path $script:Vault 'Folders/FS01/HR/Payroll.md') | Should -BeFalse
        Test-Path -LiteralPath (Join-Path $script:Vault 'Folders/FS01') | Should -BeFalse
        Test-Path -LiteralPath (Join-Path $script:Vault '_meta/exports') | Should -BeFalse
        Test-Path -LiteralPath $bobPath | Should -BeTrue
        Test-Path -LiteralPath (Join-Path $script:Vault 'Notes/mine.md') | Should -BeTrue
        Test-Path -LiteralPath (Join-Path $script:Vault 'Users/handwritten.md') | Should -BeTrue
        [System.IO.File]::ReadAllText((Join-Path $script:Vault '.obsidian/app.json')) | Should -Match 'custom'
        $r.unexpected | Should -Be @('Users/bob.md', 'Users/handwritten.md')
        $r.warnings.Count | Should -Be 2
        $m = Read-FsVaultManifest -VaultPath $script:Vault
        $m.files.Keys | Should -Not -Contain 'Users/bob.md'
        $m.files.Count | Should -Be 7
    }
    It 'warns when the primary domain changes' {
        $stage = New-StagedVault -Without 'Users/bob.md', 'Folders/FS01/HR/Payroll.md', '_meta/exports/01 Broad.csv'
        $m = New-FsVaultManifest -PrimaryDomain 'CORP' -GeneratedAt '2026-09-10T12:00:00Z'
        $r = Sync-FsVaultOutput -Staging $stage -VaultPath $script:Vault -Manifest $m
        ($r.warnings -join "`n") | Should -Match 'Primary domain changed'
        (Read-FsVaultManifest -VaultPath $script:Vault).primaryDomain | Should -Be 'CORP'
    }
    It 'treats a missing vault as new and creates it' {
        $stage = New-StagedVault
        $v2 = Join-Path $TestDrive 'vault2'
        $r = Sync-FsVaultOutput -Staging $stage -VaultPath $v2 -Manifest (New-Manifest)
        $r.counts.written | Should -Be 10
        $r.counts.unexpected | Should -Be 0
        Test-Path -LiteralPath (Join-Path $v2 '_meta/manifest.json') | Should -BeTrue
    }
    It 'accepts an explicit -PreviousManifest' {
        $stage = New-StagedVault
        $v3 = Join-Path $TestDrive 'vault3'
        $r = Sync-FsVaultOutput -Staging $stage -VaultPath $v3 -Manifest (New-Manifest) -PreviousManifest $null
        $r.counts.written | Should -Be 10
    }
}

Describe 'Initialize-FsObsidianConfig' {
    BeforeAll { $script:Vault = Join-Path $TestDrive 'ovault' }
    It 'writes six files on a new vault and none the second time' {
        $written = @(Initialize-FsObsidianConfig -VaultPath $script:Vault)
        $written.Count | Should -Be 6
        $written | Should -Contain '.obsidian/app.json'
        $written | Should -Contain '.obsidian/community-plugins.json'
        @(Initialize-FsObsidianConfig -VaultPath $script:Vault).Count | Should -Be 0
    }
    It 'writes valid JSON with the planned settings' {
        $dir = Join-Path $script:Vault '.obsidian'
        $app = ConvertFrom-Json -InputObject ([System.IO.File]::ReadAllText((Join-Path $dir 'app.json'))) -AsHashtable
        $app.defaultViewMode | Should -Be 'preview'
        $app.newLinkFormat | Should -Be 'absolute'
        @($app.userIgnoreFilters) | Should -Be @('_meta/')
        $app.attachmentFolderPath | Should -Be 'Notes/attachments'

        $graph = ConvertFrom-Json -InputObject ([System.IO.File]::ReadAllText((Join-Path $dir 'graph.json'))) -AsHashtable
        $graph.search | Should -Match '-path:Folders/'
        $graph.search | Should -Match '-tag:#large-group'
        $graph.showArrow | Should -BeTrue
        $graph.colorGroups[0].query | Should -Be 'tag:#orphaned'
        $graph.colorGroups[0].color.rgb | Should -Be 16711935
        $graph.colorGroups[0].color.a | Should -Be 1
        ($graph.colorGroups | Where-Object query -eq 'path:Users/').color.rgb | Should -Be 5025616

        $types = ConvertFrom-Json -InputObject ([System.IO.File]::ReadAllText((Join-Path $dir 'types.json'))) -AsHashtable
        $types.types.enabled | Should -Be 'checkbox'
        $types.types.lastLogon | Should -Be 'datetime'
        $types.types.generated | Should -Be 'checkbox'
        $types.types.generatedAt | Should -Be 'datetime'
        $types.types.memberOf | Should -Be 'multitext'
        $types.types.tags | Should -Be 'tags'

        $core = ConvertFrom-Json -InputObject ([System.IO.File]::ReadAllText((Join-Path $dir 'core-plugins.json'))) -AsHashtable
        foreach ($p in 'graph', 'canvas', 'bases', 'properties', 'backlink', 'outgoing-link', 'tag-pane', 'file-explorer', 'global-search', 'page-preview') { $core[$p] | Should -BeTrue }
        $core['daily-notes'] | Should -BeFalse

        $ws = ConvertFrom-Json -InputObject ([System.IO.File]::ReadAllText((Join-Path $dir 'workspace.json'))) -AsHashtable
        $ws.main.children[0].children[0].state.state.file | Should -Be 'Home.md'
        $ws.main.children[0].children[0].state.state.mode | Should -Be 'preview'
        $ws.active | Should -Match '^[0-9a-f]{16}$'
        @($ws.left.children[0].children | ForEach-Object { $_.state.type }) | Should -Be @('file-explorer', 'search', 'bookmarks')
        @($ws.right.children[0].children | ForEach-Object { $_.state.type }) | Should -Be @('backlink', 'outgoing-link', 'tag', 'outline', 'all-properties')

        [System.IO.File]::ReadAllText((Join-Path $dir 'community-plugins.json')) | Should -Be "[]`n"
        foreach ($f in Get-ChildItem -LiteralPath $dir -File) { [System.IO.File]::ReadAllText($f.FullName) | Should -Not -Match "`r" }
    }
    It 'overwrites with -Force but never community-plugins.json' {
        [System.IO.File]::WriteAllText((Join-Path (Join-Path $script:Vault '.obsidian') 'community-plugins.json'), "[`"dataview`"]`n")
        $written = @(Initialize-FsObsidianConfig -VaultPath $script:Vault -Force)
        $written.Count | Should -Be 5
        [System.IO.File]::ReadAllText((Join-Path (Join-Path $script:Vault '.obsidian') 'community-plugins.json')) | Should -Match 'dataview'
    }
    It 'is deterministic' {
        $a = [System.IO.File]::ReadAllText((Join-Path (Join-Path $script:Vault '.obsidian') 'workspace.json'))
        Initialize-FsObsidianConfig -VaultPath $script:Vault -Force | Out-Null
        [System.IO.File]::ReadAllText((Join-Path (Join-Path $script:Vault '.obsidian') 'workspace.json')) | Should -Be $a
    }
}
