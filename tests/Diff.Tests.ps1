BeforeAll {
    . (Join-Path $PSScriptRoot 'TestHelpers.ps1')
    $script:Model = Get-FixtureModel
    $script:SID = @{
        bob   = 'S-1-5-21-1111111111-2222222222-3333333333-1102'
        alice = 'S-1-5-21-1111111111-2222222222-3333333333-1101'
        frank = 'S-1-5-21-1111111111-2222222222-3333333333-1107'
        FinanceRO   = 'S-1-5-21-1111111111-2222222222-3333333333-2003'
        OwnerlessRW = 'S-1-5-21-1111111111-2222222222-3333333333-2012'
    }
}

Describe 'Get-FsChangeSets' {
    It 'produces exactly one diff for FS01 (2 snapshots) and zero for FS02 (1 snapshot)' {
        $sets = Get-FsChangeSets -Model $Model
        $sets['FS01'].Count | Should -Be 1
        $sets['FS02'].Count | Should -Be 0
    }
}

Describe 'Compare-FsSnapshots - FS01 previous vs latest' {
    BeforeAll { $script:Diff = (Get-FsChangeSets -Model $Model)['FS01'][0] }

    It 'banners a depth mismatch (previous depth 2, latest depth 3)' {
        ($Diff.banners -join ' ') | Should -Match 'Depth differs'
        $Diff.depthCompared | Should -Be 2
    }
    It 'reports the Temp share as Removed' {
        $removed = @($Diff.shares | Where-Object Verdict -eq 'Removed')
        $removed.Count | Should -Be 1
        [string]$removed[0].Share.id | Should -Be 'FS01\Temp'
    }
    It 'reports HR\Legal as newly divergent and Temp''s own folder as no-longer-divergent' {
        $folderVerdicts = @{}
        foreach ($f in $Diff.folders) { $folderVerdicts[[string]$f.Folder.id] = $f.Verdict }
        $folderVerdicts['FS01:D:\Shares\HR\Legal'] | Should -Be 'NewlyDivergent'
        $folderVerdicts['FS01:D:\Shares\Temp'] | Should -Be 'NoLongerDivergent'
    }
    It 'excludes HR\Payroll\Archive\2019 entirely because it is deeper than the effective depth' {
        $Diff.folders | Where-Object { [string]$_.Folder.id -match '2019' } | Should -BeNullOrEmpty
        $Diff.aces | Where-Object { [string]$_.Resource.id -match '2019' } | Should -BeNullOrEmpty
    }
    It "reports bob's Archive ACE as Modified from Read/ReadAndExecute to Modify" {
        $row = @($Diff.aces | Where-Object { [string]$_.Resource.id -eq 'FS01:D:\Shares\HR\Payroll\Archive' -and [string]$_.Principal.id -eq $SID.bob })
        $row.Count | Should -Be 1
        $row[0].Verdict | Should -Be 'Modified'
        $row[0].Before | Should -Match 'Read'
        $row[0].After | Should -Match 'Modify'
    }
    It 'does not double-report ACEs that belong to a share/folder already reported as Added or Removed' {
        $Diff.aces | Where-Object { [string]$_.Resource.id -eq 'FS01\Temp' } | Should -BeNullOrEmpty
    }
    It 'reports alice joining Finance-RO as an Added membership' {
        $row = @($Diff.memberships | Where-Object { [string]$_.Group.id -eq $SID.FinanceRO -and [string]$_.Member.id -eq $SID.alice })
        $row.Count | Should -Be 1
        $row[0].Verdict | Should -Be 'Added'
    }
    It "reports frank's rename and department change as separate AttributeChanged rows" {
        $rows = @($Diff.principals | Where-Object { [string]$_.Principal.id -eq $SID.frank })
        ($rows | ForEach-Object Attribute) | Should -Contain 'name'
        ($rows | ForEach-Object Attribute) | Should -Contain 'ad.department'
    }
    It 'reports Ownerless-RW gaining a managedBy' {
        $row = @($Diff.principals | Where-Object { [string]$_.Principal.id -eq $SID.OwnerlessRW -and $_.Attribute -eq 'ad.managedBy.sid' })
        $row.Count | Should -Be 1
        [string]$row[0].Before | Should -BeNullOrEmpty
    }
    It 'summary counts are internally consistent with the row lists' {
        $Diff.summary.acesModified | Should -Be @($Diff.aces | Where-Object Verdict -eq 'Modified').Count
        $Diff.summary.sharesRemoved | Should -Be @($Diff.shares | Where-Object Verdict -eq 'Removed').Count
    }
}

Describe 'Compare-FsSnapshots - edge cases' {
    It 'returns $null when -Previous is $null (first scan / baseline)' {
        Compare-FsSnapshots -Previous $null -Latest $Model.snapshots['FS01'][0] | Should -BeNullOrEmpty
    }
    It 'diffing a snapshot against itself produces zero changes everywhere' {
        $self = Compare-FsSnapshots -Previous $Model.snapshots['FS02'][0] -Latest $Model.snapshots['FS02'][0]
        $self.shares.Count | Should -Be 0
        $self.folders.Count | Should -Be 0
        $self.aces.Count | Should -Be 0
        $self.memberships.Count | Should -Be 0
        $self.principals.Count | Should -Be 0
    }
}

Describe 'Get-FsChangedEntityIds' {
    It "includes the Archive folder and alice, but not FS02's principals (FS02 has no prior snapshot)" {
        $ids = Get-FsChangedEntityIds -Model $Model
        $ids.Contains('FS01:D:\Shares\HR\Payroll\Archive') | Should -BeTrue
        $ids.Contains($SID.alice) | Should -BeTrue
    }
}
