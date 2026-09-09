#Requires -Modules @{ ModuleName = 'Pester'; ModuleVersion = '5.5.0' }
<# One New-Fs*Note function per note type, exercised against representative fixture entities. #>

BeforeAll {
    . (Join-Path $PSScriptRoot 'TestHelpers.ps1')

    $script:Model = Get-FixtureModel
    $script:Options = Get-FsAnalysisOptions -Model $script:Model
    $script:Context = New-FsNameContext -Model $script:Model -PrimaryDomain 'CONTOSO'
    $script:Context['tags'] = Get-FsInsightTags -Model $script:Model -Options $script:Options
    $script:Resolve = _New-FsPrincipalResolver -Model $script:Model -Context $script:Context
    $script:Reports = Invoke-FsReports -Model $script:Model -Options $script:Options

    function Assert-FsFrontmatter {
        <# Splits a note's leading '---' YAML block from its body; asserts fences exist and returns @{ Yaml; Body }. #>
        param([Parameter(Mandatory)] [string] $Text)
        $Text | Should -Match '^---\r?\n'
        $parts = $Text -split '(?m)^---\r?\n', 3
        # split on the fence pattern: [0]='' [1]=yaml [2]=body (since text starts with ---)
        $fenceCount = ([regex]::Matches($Text, '(?m)^---\r?\n')).Count
        $fenceCount | Should -BeGreaterOrEqual 2
        $firstFenceEnd = $Text.IndexOf("`n") + 1
        $secondFence = $Text.IndexOf("`n---`n", $firstFenceEnd)
        $yaml = $Text.Substring($firstFenceEnd, $secondFence - $firstFenceEnd)
        $body = $Text.Substring($secondFence + 5)
        return @{ Yaml = $yaml; Body = $body }
    }

    function Get-FixturePrincipal { param([string] $Name) $script:Model.principals.Values | Where-Object { ([string](Get-FsValue $_ 'name')) -eq $Name } | Select-Object -First 1 }
}

Describe 'New-FsServerNote' {
    It 'renders FS01 with metadata, its shares, and a Changes section' {
        $server = $script:Model.servers['FS01']
        $text = New-FsServerNote -Model $script:Model -Context $script:Context -Resolve $script:Resolve -Options $script:Options -Server $server
        $parts = Assert-FsFrontmatter -Text $text
        $parts.Yaml | Should -Match 'type: server'
        $parts.Yaml | Should -Match 'id: FS01'
        $parts.Yaml | Should -Match "- server"
        $text | Should -Match '# FS01'
        $text | Should -Match '## Shares'
        $text | Should -Match '\[\[Shares/FS01 - HR'
        $text | Should -Match '\[\[Shares/FS01 - Finance'
        $text | Should -Match '## Changes since previous scan'
    }
}

Describe 'New-FsShareNote' {
    It 'renders the FS01 HR share with ACL, root NTFS ACL, folder tree and reachers' {
        $share = $script:Model.shares['FS01\HR']
        $text = New-FsShareNote -Model $script:Model -Context $script:Context -Resolve $script:Resolve -Options $script:Options -Share $share
        $parts = Assert-FsFrontmatter -Text $text
        $parts.Yaml | Should -Match 'type: share'
        $parts.Yaml | Should -Match 'shareName: HR'
        $text | Should -Match '## Share ACL'
        $text | Should -Match '## Root NTFS ACL'
        $text | Should -Match '```mermaid'
        $text | Should -Match '## Who can reach this share'
        $text | Should -Match '\[\[Folders/FS01/HR/Payroll'
    }
}

Describe 'New-FsFolderNote' {
    It 'lists the Deny row before Allow rows on HR\Payroll (protected, has a Deny ACE)' {
        $folder = $script:Model.folders['FS01:D:\Shares\HR\Payroll']
        $text = New-FsFolderNote -Model $script:Model -Context $script:Context -Resolve $script:Resolve -Options $script:Options -Folder $folder
        $parts = Assert-FsFrontmatter -Text $text
        $parts.Yaml | Should -Match 'type: folder'
        $parts.Yaml | Should -Match 'protected: true'
        $aclStart = $text.IndexOf('## ACL')
        $aclTable = $text.Substring($aclStart)
        $denyIdx = $aclTable.IndexOf('| Deny |')
        $allowIdx = $aclTable.IndexOf('| Allow |')
        $denyIdx | Should -BeGreaterThan 0
        $allowIdx | Should -BeGreaterThan 0
        $denyIdx | Should -BeLessThan $allowIdx
        $text | Should -Match '## Child divergent folders'
        $text | Should -Match '## Effective access'
    }
}

Describe 'New-FsUserNote' {
    It 'renders alice with membership including Finance-RO (added per the latest scan) and an access path' {
        $alice = Get-FixturePrincipal -Name 'alice'
        $text = New-FsUserNote -Model $script:Model -Context $script:Context -Resolve $script:Resolve -Options $script:Options -Principal $alice
        $parts = Assert-FsFrontmatter -Text $text
        $parts.Yaml | Should -Match 'type: user'
        $parts.Yaml | Should -Match 'samAccountName: alice'
        $parts.Yaml | Should -Match 'department: HR'
        $text | Should -Match '## Member of'
        $text | Should -Match '\[\[Groups/Finance-RO\\?\|Finance-RO\]\]'
        $text | Should -Match '## Effective groups'
        $text | Should -Match '## Direct access'
        $text | Should -Match '## Effective access'
        $text | Should -Match '## Access path'
    }
}

Describe 'New-FsGroupNote' {
    It 'renders HR-Share-RW with members, grants and a nesting diagram' {
        $group = Get-FixturePrincipal -Name 'HR-Share-RW'
        $text = New-FsGroupNote -Model $script:Model -Context $script:Context -Resolve $script:Resolve -Options $script:Options -Principal $group
        $parts = Assert-FsFrontmatter -Text $text
        $parts.Yaml | Should -Match 'type: group'
        $parts.Yaml | Should -Match 'groupScope: Global'
        $text | Should -Match '## Members'
        $text | Should -Match '## Grants'
        $text | Should -Match '## Nesting'
        $text | Should -Match '## Effective members'
    }
}

Describe 'New-FsWellKnownNote / New-FsOrphanedNote' {
    It 'renders Authenticated Users with its SID and a grants table' {
        $wk = Get-FixturePrincipal -Name 'Authenticated Users'
        $text = New-FsWellKnownNote -Model $script:Model -Context $script:Context -Resolve $script:Resolve -Principal $wk
        $parts = Assert-FsFrontmatter -Text $text
        $parts.Yaml | Should -Match 'type: well-known'
        $parts.Yaml | Should -Match 'sid: S-1-5-11'
        $text | Should -Match '## Grants'
    }
    It 'renders the fixture''s orphaned SID' {
        $orphanId = @($script:Model.principals.Keys | Where-Object { ([string](Get-FsValue $script:Model.principals[$_] 'kind')) -eq 'OrphanedSid' })[0]
        $orphanId | Should -Not -BeNullOrEmpty
        $orphan = $script:Model.principals[$orphanId]
        $text = New-FsOrphanedNote -Model $script:Model -Context $script:Context -Resolve $script:Resolve -Principal $orphan
        $parts = Assert-FsFrontmatter -Text $text
        $parts.Yaml | Should -Match 'type: orphaned'
        $text | Should -Match '## Grants'
    }
}

Describe 'New-FsReportNote' {
    It 'renders the Broad Exposure report with a Summary heading and findings table' {
        $def = @(Get-FsReportCatalog | Where-Object key -eq 'broad-exposure')[0]
        $result = $script:Reports['broad-exposure']
        $text = New-FsReportNote -Model $script:Model -Context $script:Context -Resolve $script:Resolve -Definition $def -Result $result
        $parts = Assert-FsFrontmatter -Text $text
        $parts.Yaml | Should -Match 'type: report'
        $parts.Yaml | Should -Match 'severity: high'
        $text | Should -Match '## Summary'
    }
}

Describe 'New-FsHomeNote / New-FsDashboardCanvas / New-FsReportsIndexNote' {
    It 'renders Home with coverage, findings summary and caveats' {
        $text = New-FsHomeNote -Model $script:Model -Context $script:Context -Resolve $script:Resolve -Reports $script:Reports -Options $script:Options
        $parts = Assert-FsFrontmatter -Text $text
        $parts.Yaml | Should -Match 'type: home'
        $text | Should -Match '## Coverage'
        $text | Should -Match '## Findings summary'
        $text | Should -Match 'Effective-rights caveats'
    }
    It 'renders a valid JSON Canvas with a card per server and per report' {
        $json = New-FsDashboardCanvas -Model $script:Model -Context $script:Context -Reports $script:Reports
        $doc = ConvertFrom-Json -InputObject $json -AsHashtable
        $fileNodes = @($doc.nodes | Where-Object type -eq 'file')
        $fileNodes.Count | Should -Be (2 + (Get-FsReportCatalog).Count)
    }
    It 'renders a reports index note linking every catalog report' {
        $text = New-FsReportsIndexNote -Model $script:Model -Context $script:Context -Resolve $script:Resolve -Reports $script:Reports
        $text | Should -Match '# Reports Index'
        $text | Should -Match '\[\[Reports/01 Broad Exposure'
    }
}
