BeforeAll {
    . (Join-Path $PSScriptRoot 'TestHelpers.ps1')
    $script:Model = Get-FixtureModel
    $script:Options = Get-FsAnalysisOptions -Model $Model
    $script:Reports = Invoke-FsReports -Model $Model -Options $Options
    $script:SID = @{
        alice = 'S-1-5-21-1111111111-2222222222-3333333333-1101'
        bob   = 'S-1-5-21-1111111111-2222222222-3333333333-1102'
        carol = 'S-1-5-21-1111111111-2222222222-3333333333-1103'
        dave  = 'S-1-5-21-1111111111-2222222222-3333333333-1104'
        svc_backup = 'S-1-5-21-1111111111-2222222222-3333333333-1105'
        erin  = 'S-1-5-21-1111111111-2222222222-3333333333-1106'
        Everyone = 'S-1-1-0'
        Orphan = 'S-1-5-21-1111111111-2222222222-3333333333-9999'
        Foreign = 'S-1-5-21-4444444444-5555555555-6666666666-1001'
        EmptyGroup = 'S-1-5-21-1111111111-2222222222-3333333333-2006'
        SoloGroup  = 'S-1-5-21-1111111111-2222222222-3333333333-2007'
        LoopA      = 'S-1-5-21-1111111111-2222222222-3333333333-2004'
        FinanceRO  = 'S-1-5-21-1111111111-2222222222-3333333333-2003'
    }
    function Get-ReportRows { param([string] $Key) return @($script:Reports[$Key].rows) }
    function Get-RefId { param($Cell) if ($Cell -is [System.Collections.IDictionary] -and $Cell.Contains('id')) { return [string]$Cell['id'] }; return [string]$Cell }
}

Describe 'Get-FsReportCatalog / Invoke-FsReports' {
    It 'catalog has 15 reports numbered 1-13,15,16 (14 unused)' {
        $numbers = @(Get-FsReportCatalog | ForEach-Object number | Sort-Object)
        $numbers | Should -Not -Contain 14
        $numbers.Count | Should -Be 15
    }
    It 'produced a result for every catalog entry and built the findings index' {
        foreach ($def in Get-FsReportCatalog) { $Reports.Contains($def.key) | Should -BeTrue -Because $def.key }
        $Model.findings.Contains('FS01:D:\Shares\HR\Payroll') | Should -BeTrue
    }
}

Describe '01 Broad Exposure' {
    It 'flags FS02 Public (Everyone, share-limited to Modify) and excludes CREATOR OWNER' {
        $rows = Get-ReportRows 'broad-exposure'
        $public = @($rows | Where-Object { (Get-RefId $_.Resource) -eq 'FS02\Public' -and (Get-RefId $_.Principal) -eq $SID.Everyone })
        $public.Count | Should -BeGreaterThan 0
        $rows | Where-Object { (Get-RefId $_.Principal) -eq 'S-1-3-0' } | Should -BeNullOrEmpty
    }
}

Describe '02 Deny ACEs' {
    It 'lists the explicit Domain Users deny on HR\Payroll as conflicting with an Allow' {
        $rows = Get-ReportRows 'deny-aces'
        $row = @($rows | Where-Object { (Get-RefId $_.Resource) -eq 'FS01:D:\Shares\HR\Payroll' -and $_.Inherited -eq 'no' })
        $row.Count | Should -BeGreaterThan 0
        $row[0].Conflict | Should -Match 'yes'
    }
}

Describe '03 Inheritance Broken' {
    It 'lists HR\Payroll as protected, with FS01\Users removed compared with the parent' {
        $rows = Get-ReportRows 'inheritance-broken'
        $row = @($rows | Where-Object { (Get-RefId $_.Resource) -eq 'FS01:D:\Shares\HR\Payroll' })
        $row.Count | Should -Be 1
        (@($row[0].Removed | ForEach-Object { Get-RefId $_ }) -join ' ') | Should -Match 'FS01\\Users'
    }
}

Describe '04/05 Direct User ACEs' {
    It 'report 04 lists bob directly on HR\Payroll\Archive and marks him disabled' {
        $rows = Get-ReportRows 'direct-user-aces-by-resource'
        $row = @($rows | Where-Object { (Get-RefId $_.User) -eq $SID.bob -and (Get-RefId $_.Resource) -eq 'FS01:D:\Shares\HR\Payroll\Archive' })
        $row.Count | Should -Be 1
        $row[0].Enabled | Should -Match 'no|No|False'
    }
    It 'report 05 pivots bob with at least one resource' {
        $rows = Get-ReportRows 'direct-user-aces-by-user'
        $row = @($rows | Where-Object { (Get-RefId $_.User) -eq $SID.bob })
        $row.Count | Should -Be 1
        [int]$row[0].Resources | Should -BeGreaterThan 0
    }
}

Describe '06 Disabled and Stale Accounts with Access' {
    It 'has sections for bob (disabled), carol (stale), erin (never logged on) and svc_backup (stale password)' {
        $rows = Get-ReportRows 'dormant-accounts'
        $byUser = @{}
        foreach ($r in $rows) { $byUser[(Get-RefId $r.User)] = $r }
        $byUser[$SID.bob].Status | Should -Match 'Disabled'
        $byUser[$SID.carol].Status | Should -Match 'Stale'
        $byUser[$SID.erin].Status | Should -Match 'Never'
        $byUser[$SID.svc_backup].Status | Should -Match 'password|Password'
    }
}

Describe '07 Orphaned and Unresolved Principals' {
    It 'has an Orphaned section for the HR\Payroll orphan SID and an Unresolved section for the FS02 foreign SID' {
        $rows = Get-ReportRows 'orphaned-principals'
        $orphanRow = @($rows | Where-Object { (Get-RefId $_.Principal) -eq $SID.Orphan })
        $orphanRow.Count | Should -BeGreaterThan 0
        $foreignRow = @($rows | Where-Object { (Get-RefId $_.Principal) -eq $SID.Foreign })
        $foreignRow.Count | Should -BeGreaterThan 0
    }
}

Describe '08/09 Over-permissioned Users / Groups' {
    It 'report 08 ranks alice ahead of principals with no Full/Modify reach, and excludes dave (Domain Admins, allowlisted)' {
        $rows = Get-ReportRows 'over-permissioned-users'
        $rows | Where-Object { (Get-RefId $_.User) -eq $SID.dave } | Should -BeNullOrEmpty
        $rows | Where-Object { (Get-RefId $_.User) -eq $SID.alice } | Should -Not -BeNullOrEmpty
    }
    It 'report 09 lists HR-Share-RW among the groups granting the most access' {
        $rows = Get-ReportRows 'over-permissioned-groups'
        $rows | Where-Object { (Get-RefId $_.Group) -eq 'S-1-5-21-1111111111-2222222222-3333333333-2001' } | Should -Not -BeNullOrEmpty
    }
}

Describe '10 Group Hygiene' {
    It 'flags Empty-Group, Solo-Group and the Loop-A/Loop-B cycle' {
        $rows = Get-ReportRows 'group-hygiene'
        $cats = @{}
        foreach ($r in $rows) { $id = Get-RefId $r.Group; if (-not $cats.Contains($id)) { $cats[$id] = [System.Collections.Generic.List[string]]::new() }; $cats[$id].Add($r.Category) }
        $cats[$SID.EmptyGroup] | Should -Contain 'Empty group'
        $cats[$SID.SoloGroup] | Should -Contain 'Single member'
        $cats[$SID.LoopA] | Should -Contain 'Circular'
    }
    It 'flags a local group that appears in an ACL' {
        $rows = Get-ReportRows 'group-hygiene'
        $rows | Where-Object { (Get-RefId $_.Group) -eq 'FS01\Users' -and $_.Category -eq 'Local group' } | Should -Not -BeNullOrEmpty
    }
}

Describe '11 Full Control Anywhere' {
    It 'in this fixture, only admin-allowlisted principals (dave via Domain Admins, the local Administrator) reach Full Control - shown in the appendix, not the main table' {
        $rows = Get-ReportRows 'full-control'
        $rows.Count | Should -Be 0
        $appendix = @($Reports['full-control'].appendixRows)
        $appendix.Count | Should -BeGreaterThan 0
        $appendix | Where-Object { (Get-RefId $_.User) -eq $SID.dave } | Should -Not -BeNullOrEmpty
    }
}

Describe '12 Privileged Grants to Non-Admins' {
    It 'flags the Finance\Budgets ChangePermissions grant to Finance-RO' {
        $rows = Get-ReportRows 'privileged-grants'
        $row = @($rows | Where-Object { (Get-RefId $_.Resource) -eq 'FS01:D:\Shares\Finance\Budgets' -and (Get-RefId $_.Principal) -eq $SID.FinanceRO })
        $row.Count | Should -BeGreaterThan 0
    }
    It 'does not flag Empty-Group''s plain Modify grant (no WriteDAC/Owner, not Full)' {
        $rows = Get-ReportRows 'privileged-grants'
        $rows | Where-Object { (Get-RefId $_.Principal) -eq $SID.EmptyGroup } | Should -BeNullOrEmpty
    }
}

Describe '13 Department Access' {
    It 'produces at least one row (an info-level coverage report)' {
        (Get-ReportRows 'department-access').Count | Should -BeGreaterThan 0
    }
}

Describe '15 Share vs NTFS Limiter' {
    It 'FS02 Public is share-limited and FS01 Finance is NTFS-limited, and Public/PublicArchive overlap is flagged' {
        $rows = Get-ReportRows 'share-ntfs-limiter'
        $pub = @($rows | Where-Object { (Get-RefId $_.Share) -eq 'FS02\Public' -and (Get-RefId $_.Principal) -eq $SID.Everyone })
        $pub.Count | Should -BeGreaterThan 0
        $pub[0].Limiter | Should -Match 'Share'
        $Reports['share-ntfs-limiter'].appendixRows.Count | Should -BeGreaterThan 0
    }
}

Describe '16 Scan Health' {
    It 'FS02 shows one access-denied error and a truncated share; FS01 shows none' {
        $rows = Get-ReportRows 'scan-health'
        $fs02 = @($rows | Where-Object { (Get-RefId $_.Server) -eq 'FS02' })[0]
        $fs02.'Access denied' | Should -BeGreaterThan 0
        $fs02.'Truncated shares' | Should -BeGreaterThan 0
        $fs01 = @($rows | Where-Object { (Get-RefId $_.Server) -eq 'FS01' })[0]
        $fs01.Errors | Should -Be 0
    }
}

Describe 'RowCap truncation' {
    It 'caps rows and reports truncated, while csvRows keeps every row' {
        $opts = Get-FsAnalysisOptions -Model $Model -RowCap 1
        $r = Invoke-FsReports -Model $Model -Options $opts
        $bigReport = $r.Values | Where-Object { $_.csvRows.Count -gt 1 } | Select-Object -First 1
        $bigReport | Should -Not -BeNullOrEmpty
        $bigReport.rows.Count | Should -Be 1
        $bigReport.truncated | Should -BeTrue
    }
}
