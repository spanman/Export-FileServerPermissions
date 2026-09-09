<#
Static checks that Model/Analytics stay pure and cross-platform, and that Render never touches
the filesystem/clock directly outside its own designated I/O helpers. Collector is exempt (it is
Windows-only by design) except for the "approved verbs" and "no `Sort-Object`" rules, which apply
everywhere.

File discovery runs at Pester DISCOVERY time (plain script code, not inside BeforeAll) because
-TestCases arrays are built during discovery, before any BeforeAll would run.
#>
$script:Repo = if ($env:FSPERM_REPO) { $env:FSPERM_REPO } else { Split-Path -Parent $PSScriptRoot }
$script:PureDirs = @('FsPerm/Model', 'FsPerm/Analytics') | ForEach-Object { Join-Path $script:Repo $_ } | Where-Object { Test-Path $_ }
$script:AllModuleFiles = @(Get-ChildItem -Path (Join-Path $script:Repo 'FsPerm') -Recurse -Filter '*.ps1' -File)
$script:PureFiles = @(foreach ($d in $script:PureDirs) { Get-ChildItem -Path $d -Recurse -Filter '*.ps1' -File })
$script:AnalyticsFiles = @(Get-ChildItem -Path (Join-Path $script:Repo 'FsPerm/Analytics') -Recurse -Filter '*.ps1' -File -ErrorAction SilentlyContinue)
$script:FunctionCases = @(
    foreach ($f in $script:AllModuleFiles) {
        foreach ($m in [regex]::Matches((Get-Content -Raw -LiteralPath $f.FullName), '(?m)^function\s+([A-Za-z][\w-]*)')) {
            @{ FileName = $f.Name; FnName = $m.Groups[1].Value }
        }
    }
)

BeforeAll {
    # Function definitions from Discovery-time script code do not carry into Pester's Run phase, so this
    # helper (needed inside It blocks) is (re)established here.
    function Remove-FsCommentsForTest {
        # Strips block comments and trailing line comments so doc-comments don't trigger the forbidden-call checks below.
        param([Parameter(Mandatory)] [string] $Text)
        $noBlock = [regex]::Replace($Text, '(?s)<#.*?#>', '')
        return [regex]::Replace($noBlock, '(?m)(?<!["''])#.*$', '')
    }
}

Describe 'Model and Analytics stay pure and cross-platform' {
    It 'contain no Windows-only or filesystem/network calls (<File>)' -TestCases (@($script:PureFiles) | ForEach-Object { @{ File = $_.FullName } }) {
        param($File)
        $text = Remove-FsCommentsForTest (Get-Content -Raw -LiteralPath $File)
        $forbidden = 'Get-CimInstance|Invoke-Command|Get-Acl\b|adsisearcher|Get-LocalGroupMember|Get-SmbShare|Get-WmiObject|New-PSSession|Get-ADUser|Get-ADGroup'
        $text | Should -Not -Match $forbidden
    }
    It 'never call Sort-Object directly - use Get-FsSorted (<File>)' -TestCases (@($script:AllModuleFiles) | ForEach-Object { @{ File = $_.FullName } }) {
        param($File)
        (Remove-FsCommentsForTest (Get-Content -Raw -LiteralPath $File)) | Should -Not -Match '(?<![\w-])Sort-Object\b'
    }
    It 'never write output files directly - Out-File/Set-Content/Add-Content are Render''s job (<File>)' -TestCases (@($script:PureFiles) | ForEach-Object { @{ File = $_.FullName } }) {
        param($File)
        (Remove-FsCommentsForTest (Get-Content -Raw -LiteralPath $File)) | Should -Not -Match 'Out-File|Set-Content|Add-Content'
    }
    It 'never reference $pid, $input or $host as a variable name (<File>)' -TestCases (@($script:AllModuleFiles) | ForEach-Object { @{ File = $_.FullName } }) {
        param($File)
        (Remove-FsCommentsForTest (Get-Content -Raw -LiteralPath $File)) | Should -Not -Match '\$(pid|input|host)\b'
    }
    It 'never call Get-Date directly - analytics take -Now / Options.Now for determinism (<File>)' -TestCases (@($script:AnalyticsFiles) | ForEach-Object { @{ File = $_.FullName } }) {
        param($File)
        (Remove-FsCommentsForTest (Get-Content -Raw -LiteralPath $File)) | Should -Not -Match '(?<![\w-])Get-Date\b'
    }
}

Describe 'Every function uses an approved PowerShell verb' {
    BeforeAll { $script:ApprovedVerbs = [System.Collections.Generic.HashSet[string]]::new([string[]](Get-Verb | ForEach-Object Verb), [System.StringComparer]::OrdinalIgnoreCase) }
    It 'uses an approved verb (<FnName> in <FileName>)' -TestCases $script:FunctionCases {
        param($FileName, $FnName)
        if ($FnName -notmatch '-') { Set-ItResult -Skipped -Because 'helper without a Verb-Noun name'; return }
        $verb = $FnName.Split('-')[0]
        $script:ApprovedVerbs.Contains($verb) | Should -BeTrue -Because "'$FnName' in $FileName uses verb '$verb'"
    }
}

Describe 'Module import' {
    BeforeAll { $script:RepoForRun = if ($env:FSPERM_REPO) { $env:FSPERM_REPO } else { Split-Path -Parent $PSScriptRoot } }
    It 'imports on this (Linux) platform with zero terminating errors' {
        { Import-Module (Join-Path $script:RepoForRun 'FsPerm/FsPerm.psd1') -Force -ErrorAction Stop } | Should -Not -Throw
    }
}
