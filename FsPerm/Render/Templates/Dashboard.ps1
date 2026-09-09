<#
Dashboard.canvas: a column of server file cards next to a group of report file cards (colored by severity,
embedded at their #Summary heading). No server -> Changes edges yet: that report does not exist until
Compare-FsSnapshots lands (see Export-Vault.ps1's adapter comment).
#>

function New-FsDashboardCanvas {
    [OutputType([string])]
    param(
        [Parameter(Mandatory)] [System.Collections.IDictionary] $Model,
        [Parameter(Mandatory)] [hashtable] $Context,
        [Parameter(Mandatory)] [System.Collections.IDictionary] $Reports
    )
    $severityColor = @{ high = '1'; medium = '2'; low = '3'; info = '4' }
    $nodes = [System.Collections.Generic.List[object]]::new()
    $edges = [System.Collections.Generic.List[object]]::new()

    $y = 0
    foreach ($srv in Get-FsSortedKeys $Model.servers) {
        $path = Get-FsNotePath -Context $Context -Kind Server -Id $srv -Extension 'md'
        $nodes.Add((New-FsCanvasNode -Kind file -Key ('server:' + $srv) -X 0 -Y $y -Width 400 -Height 200 -File $path))
        $y += 240
    }

    $groupHeight = [Math]::Max(240, (Get-FsReportCatalog).Count * 130 + 40)
    $nodes.Add((New-FsCanvasNode -Kind group -Key 'group:reports' -X 480 -Y -20 -Width 460 -Height $groupHeight -Label 'Reports'))

    $ry = 0
    foreach ($def in Get-FsReportCatalog) {
        $r = $Reports[$def.key]
        $rowCount = $(if ($r) { $r.rowCount } else { 0 })
        $path = Get-FsNotePath -Context $Context -Kind Report -Id $def.fileName -Extension 'md'
        $color = $(if ($severityColor.Contains($def.severity)) { $severityColor[$def.severity] } else { '6' })
        $nodes.Add((New-FsCanvasNode -Kind file -Key ('report:' + $def.key) -X 500 -Y $ry -Width 420 -Height 120 -File $path -Subpath 'Summary' -Color $color))
        $ry += 130
    }

    return (ConvertTo-FsCanvasJson -Nodes @($nodes) -Edges @($edges))
}
