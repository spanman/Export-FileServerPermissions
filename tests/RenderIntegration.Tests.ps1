#Requires -Modules @{ ModuleName = 'Pester'; ModuleVersion = '5.5.0' }
<# Export-FsVault end-to-end against the fixture model: expected files exist, every link resolves, and
   rendering twice is byte-identical. #>

BeforeAll {
    . (Join-Path $PSScriptRoot 'TestHelpers.ps1')

    function Get-FsVaultLinkTargets {
        <#
        .SYNOPSIS
            [[target]] / [[target|alias]] / [[target#heading]] / ![[embed]] targets in a vault, source-tagged.
        .DESCRIPTION
            Get-VaultLinks (TestHelpers.ps1) does not account for the '\|' escaped-pipe-before-alias
            convention this vault's tables use (Format-FsMdTable / New-FsLink -InTable), so its capture group
            swallows the trailing backslash into the target. This is the same extraction with that fixed.
        #>
        param([Parameter(Mandatory)] [string] $VaultPath)
        $rx = [regex]'!?\[\[([^\]]+?)(?:\\?\|[^\]]*)?\]\]'
        foreach ($f in Get-ChildItem -Path $VaultPath -Recurse -File -Include '*.md', '*.canvas', '*.base') {
            $text = [System.IO.File]::ReadAllText($f.FullName)
            foreach ($m in $rx.Matches($text)) {
                $target = ($m.Groups[1].Value -split '#')[0].Trim()
                [pscustomobject]@{ Source = $f.FullName; Target = $target }
            }
        }
    }

    function Get-FsVaultBasenames {
        param([Parameter(Mandatory)] [string] $VaultPath)
        $set = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
        foreach ($f in Get-ChildItem -Path $VaultPath -Recurse -File -Include '*.md', '*.canvas', '*.base') {
            $rel = [System.IO.Path]::GetRelativePath($VaultPath, $f.FullName).Replace('\', '/') -replace '\.(md|canvas|base)$', ''
            [void]$set.Add($rel)
        }
        return $set
    }

    function Get-FsVaultFileHashMap {
        param([Parameter(Mandatory)] [string] $VaultPath)
        $map = @{}
        foreach ($f in Get-ChildItem -Path $VaultPath -Recurse -File) {
            $rel = [System.IO.Path]::GetRelativePath($VaultPath, $f.FullName).Replace('\', '/')
            $map[$rel] = Get-FsFileSha256 -Path $f.FullName
        }
        return $map
    }

    $script:Model = Get-FixtureModel
    $script:Options = Get-FsAnalysisOptions -Model $script:Model
}

Describe 'Export-FsVault' {
    It 'stages the expected top-level structure' {
        $vault = Join-Path $TestDrive 'vault'
        $result = Export-FsVault -Model $script:Model -VaultPath $vault -Options $script:Options -PrimaryDomain 'CONTOSO'
        $result.written | Should -BeGreaterThan 0
        $result.deleted | Should -Be 0

        foreach ($rel in 'Home.md', 'Dashboard.canvas', 'Servers/FS01.md', 'Servers/FS02.md', 'Users/alice.md',
            'Groups/HR-Share-RW.md', 'Reports/00 Reports Index.md') {
            Test-Path -LiteralPath (Join-Path $vault $rel) | Should -BeTrue -Because "$rel should be staged"
        }
        @(Get-ChildItem -Path $vault -Filter '*.base').Count | Should -BeGreaterOrEqual 1
        Test-Path -LiteralPath (Join-Path $vault '.obsidian/app.json') | Should -BeTrue
        Test-Path -LiteralPath (Join-Path $vault '_meta/manifest.json') | Should -BeTrue
    }

    It 'every [[link]] and ![[embed]] resolves to a staged note, canvas or base' {
        $vault = Join-Path $TestDrive 'vault-links'
        Export-FsVault -Model $script:Model -VaultPath $vault -Options $script:Options -PrimaryDomain 'CONTOSO' | Out-Null

        $basenames = Get-FsVaultBasenames -VaultPath $vault
        $links = @(Get-FsVaultLinkTargets -VaultPath $vault)
        $links.Count | Should -BeGreaterThan 0

        $unresolved = @($links | Where-Object { -not $basenames.Contains($_.Target) })
        if ($unresolved.Count -gt 0) {
            $detail = ($unresolved | ForEach-Object { "$($_.Source) -> [[$($_.Target)]]" }) -join "`n"
            throw "Unresolved link(s):`n$detail"
        }
        $unresolved.Count | Should -Be 0
    }

    It 'renders byte-identically on a second run against the same model' {
        $v1 = Join-Path $TestDrive 'vault-det-1'
        $v2 = Join-Path $TestDrive 'vault-det-2'
        Export-FsVault -Model $script:Model -VaultPath $v1 -Options $script:Options -PrimaryDomain 'CONTOSO' | Out-Null
        Export-FsVault -Model $script:Model -VaultPath $v2 -Options $script:Options -PrimaryDomain 'CONTOSO' | Out-Null

        $h1 = Get-FsVaultFileHashMap -VaultPath $v1
        $h2 = Get-FsVaultFileHashMap -VaultPath $v2
        (@($h1.Keys) | Sort-Object) | Should -Be (@($h2.Keys) | Sort-Object)
        foreach ($k in $h1.Keys) { $h1[$k] | Should -Be $h2[$k] -Because "content of $k should be deterministic" }
    }

    It 'a second render into the same vault writes nothing new (idempotent)' {
        $vault = Join-Path $TestDrive 'vault-idempotent'
        Export-FsVault -Model $script:Model -VaultPath $vault -Options $script:Options -PrimaryDomain 'CONTOSO' | Out-Null
        $second = Export-FsVault -Model $script:Model -VaultPath $vault -Options $script:Options -PrimaryDomain 'CONTOSO'
        $second.written | Should -Be 0
        $second.deleted | Should -Be 0
    }

    It 'omitting -Options builds them from the model' {
        $vault = Join-Path $TestDrive 'vault-default-options'
        $result = Export-FsVault -Model $script:Model -VaultPath $vault
        $result.written | Should -BeGreaterThan 0
    }

    It 'removes a stale generated note when it is no longer part of the model' {
        $vault = Join-Path $TestDrive 'vault-shrink'
        Export-FsVault -Model $script:Model -VaultPath $vault -Options $script:Options -PrimaryDomain 'CONTOSO' | Out-Null
        Test-Path -LiteralPath (Join-Path $vault 'Servers/FS02.md') | Should -BeTrue

        $slice = Get-FixtureModel -Server 'FS01'
        $result = Export-FsVault -Model $slice -VaultPath $vault -Options (Get-FsAnalysisOptions -Model $slice) -PrimaryDomain 'CONTOSO'
        $result.deleted | Should -BeGreaterThan 0
        Test-Path -LiteralPath (Join-Path $vault 'Servers/FS02.md') | Should -BeFalse
        Test-Path -LiteralPath (Join-Path $vault 'Servers/FS01.md') | Should -BeTrue
    }
}
