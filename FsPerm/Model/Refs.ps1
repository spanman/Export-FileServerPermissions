<#
Typed references used in report rows and note sections.

Analytics produces rows whose cells may be scalars, ref objects, or arrays of either. The renderer
turns refs into wikilinks. Keeping refs typed (instead of pre-rendered markdown) keeps analytics
free of Obsidian concerns and testable by id.
#>

function New-FsRef {
    <#
    .SYNOPSIS
        A typed reference to a principal, share, folder, server or report.
    .PARAMETER Kind
        Principal | Resource | Server | Report
    .PARAMETER Id
        Principal id, share/folder id, server name, or report key.
    .PARAMETER Label
        Optional display override.
    #>
    [OutputType([hashtable])]
    param(
        [Parameter(Mandatory)] [ValidateSet('Principal', 'Resource', 'Server', 'Report')] [string] $Kind,
        [Parameter(Mandatory)] [AllowEmptyString()] [string] $Id,
        [AllowNull()] [string] $Label
    )
    return @{ _ref = $Kind; id = $Id; label = $Label }
}

function Test-FsRef {
    [OutputType([bool])]
    param([AllowNull()] $Value)
    return ($Value -is [System.Collections.IDictionary] -and $Value.Contains('_ref'))
}

function New-FsCode {
    <# Marks a scalar to be rendered in a code span (paths, rights strings). #>
    [OutputType([hashtable])]
    param([AllowNull()] [string] $Text)
    return @{ _code = $(if ($null -eq $Text) { '' } else { $Text }) }
}

function Test-FsCode {
    [OutputType([bool])]
    param([AllowNull()] $Value)
    return ($Value -is [System.Collections.IDictionary] -and $Value.Contains('_code'))
}
