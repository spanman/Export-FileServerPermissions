<#
15 Share vs NTFS Limiter — for every principal named in a share's ACL or its root NTFS ACL, which layer limits
the effective level. The appendix lists share paths nested inside another share on the same server.
#>

function Get-FsReportShareNtfsLimiter {
    [OutputType([hashtable])]
    param(
        [Parameter(Mandatory)] [System.Collections.IDictionary] $Model,
        [Parameter(Mandatory)] [System.Collections.IDictionary] $Options,
        [Parameter(Mandatory)] $Definition
    )
    $items = [System.Collections.Generic.List[object]]::new()
    $counts = [ordered]@{ Share = 0; NTFS = 0; Equal = 0; None = 0 }
    foreach ($sid in Get-FsSortedKeys $Model.shares) {
        $share = $Model.shares[$sid]
        $server = [string](Get-FsValue $share 'server'); $path = [string](Get-FsValue $share 'uncPath'); $name = [string](Get-FsValue $share 'name')
        foreach ($r in @(Get-FsResourceReachers -Model $Model -ResourceId $sid)) {
            $so = Get-FsLevelOrdinal $r.shareLevel; $no = Get-FsLevelOrdinal $r.ntfsLevel
            $limiter = if ($r.effectiveLevel -eq 'None') { 'None' } elseif ($so -lt $no) { 'Share' } elseif ($no -lt $so) { 'NTFS' } else { 'Equal' }
            $counts[$limiter]++
            $row = [ordered]@{
                Server        = (New-FsRef -Kind Server -Id $server)
                Share         = (New-FsRef -Kind Resource -Id $sid)
                Path          = (New-FsCode $path)
                Principal     = (New-FsRef -Kind Principal -Id $r.principalId)
                Kind          = (Get-FsPrincipalKindLabel -Kind $r.kind)
                Broad         = (ConvertTo-FsYesNo $r.isBroad)
                'Listed in'   = $r.layers
                'Share level' = $r.shareLevel
                'NTFS level'  = $r.ntfsLevel
                Effective     = $r.effectiveLevel
                Limiter       = $limiter
                Deny          = (ConvertTo-FsYesNo $r.hasDeny)
                Users         = $r.userCount
            }
            $items.Add(@{ server = $server; share = $name; shareId = $sid; name = $r.name; principalId = $r.principalId; row = $row })
        }
    }
    $rows = Select-FsSortedRows -Items @($items) -Property 'server', 'share', 'shareId', 'name', 'principalId'

    # overlapping share paths on the same server
    $overlaps = [System.Collections.Generic.List[object]]::new()
    foreach ($srv in Get-FsSortedKeys $Model.index.sharesByServer) {
        $ids = @($Model.index.sharesByServer[$srv])
        foreach ($outer in $ids) {
            foreach ($inner in $ids) {
                if ($inner -eq $outer) { continue }
                $op = [string](Get-FsValue $Model.shares[$outer] 'localPath'); $ip = [string](Get-FsValue $Model.shares[$inner] 'localPath')
                if (-not $op -or -not $ip) { continue }
                if ((ConvertTo-FsNormalizedPath $op) -eq (ConvertTo-FsNormalizedPath $ip)) {
                    if ([string]::CompareOrdinal($outer, $inner) -gt 0) { continue }   # report an identical pair once
                    $note = 'Both shares expose the same folder; each share ACL applies only to its own UNC path.'
                }
                elseif (Test-FsPathUnder -Root $op -Child $ip) { $note = 'Inner share path lies inside the outer share; the outer share ACL does not apply when the data is reached through the inner share.' }
                else { continue }
                $overlaps.Add(@{ server = $srv; outer = [string](Get-FsValue $Model.shares[$outer] 'name'); inner = [string](Get-FsValue $Model.shares[$inner] 'name'); row = [ordered]@{
                            Server        = (New-FsRef -Kind Server -Id $srv)
                            'Outer share' = (New-FsRef -Kind Resource -Id $outer)
                            'Outer path'  = (New-FsCode $op)
                            'Inner share' = (New-FsRef -Kind Resource -Id $inner)
                            'Inner path'  = (New-FsCode $ip)
                            Note          = $note
                        }
                    })
            }
        }
    }
    $overlapRows = Select-FsSortedRows -Items @($overlaps) -Property 'server', 'outer', 'inner'
    $summary = '{0} principal/share pair(s): share limits {1}, NTFS limits {2}, equal {3}, no access {4}; {5} overlapping share path(s).' -f $rows.Count, $counts.Share, $counts.NTFS, $counts.Equal, $counts.None, $overlapRows.Count
    return New-FsReportResult -Columns @('Server', 'Share', 'Path', 'Principal', 'Kind', 'Broad', 'Listed in', 'Share level', 'NTFS level', 'Effective', 'Limiter', 'Deny', 'Users') -Rows $rows -Summary $summary -AppendixTitle 'Overlapping share paths' -AppendixRows $overlapRows
}
