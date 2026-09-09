<#
Deterministic, culture-invariant sorting.

Sort-Object is culture-sensitive (NLS on Windows, ICU on Linux) and would make the
rendered vault differ between the workstation and the Docker test container. Every
sort in Model/, Analytics/ and Render/ must go through Get-FsSorted.
#>

function Get-FsSorted {
    <#
    .SYNOPSIS
        Stable sort using ordinal, case-insensitive string comparison.
    .PARAMETER Property
        One or more property/key names. Values that are both numeric compare numerically,
        booleans compare false < true, everything else compares as strings (ordinal, ignore case).
        Prefix a name with '-' to sort that key descending.
    .PARAMETER Key
        Alternative to -Property: a scriptblock receiving the item as $_ and returning the sort key.
    #>
    [CmdletBinding(DefaultParameterSetName = 'Property')]
    [OutputType([object[]])]
    param(
        [Parameter(ValueFromPipeline)] [AllowNull()] [object] $InputObject,
        [Parameter(Position = 0, ParameterSetName = 'Property')] [string[]] $Property,
        [Parameter(ParameterSetName = 'Key')] [scriptblock] $Key,
        [switch] $Descending,
        [switch] $Unique
    )
    begin { $items = [System.Collections.Generic.List[object]]::new() }
    process {
        if ($null -eq $InputObject) { return }
        # -InputObject bound directly (not via pipeline) with an array: treat each element as an item.
        if ($InputObject -is [System.Collections.IEnumerable] -and $InputObject -isnot [string] -and $InputObject -isnot [System.Collections.IDictionary] -and -not $PSCmdlet.MyInvocation.ExpectingInput) {
            foreach ($i in $InputObject) { if ($null -ne $i) { $items.Add($i) } }
        }
        else { $items.Add($InputObject) }
    }
    end {
        if ($items.Count -eq 0) { return @() }

        $cmp = [System.StringComparer]::OrdinalIgnoreCase
        $getKeys = {
            param($item)
            if ($Key) { return , @(& $Key $item) }
            if (-not $Property) { return , @($item) }
            $vals = foreach ($p in $Property) { Get-FsValue -Object $item -Name ($p.TrimStart('-')) }
            return , @($vals)
        }
        $desc = foreach ($p in ($Property ?? @())) { $p.StartsWith('-') }
        if (-not $Property) { $desc = @($false) }

        $keyed = [System.Collections.Generic.List[object]]::new()
        for ($i = 0; $i -lt $items.Count; $i++) {
            $keyed.Add([pscustomobject]@{ Index = $i; Item = $items[$i]; Keys = (& $getKeys $items[$i]) })
        }

        $comparison = [System.Comparison[object]] {
            param($a, $b)
            $ka = $a.Keys; $kb = $b.Keys
            for ($i = 0; $i -lt [Math]::Max($ka.Count, $kb.Count); $i++) {
                $va = if ($i -lt $ka.Count) { $ka[$i] } else { $null }
                $vb = if ($i -lt $kb.Count) { $kb[$i] } else { $null }
                $r = Compare-FsValue $va $vb $cmp
                if ($r -ne 0) {
                    $d = if ($i -lt $desc.Count) { $desc[$i] } else { $false }
                    if ($Descending) { $d = -not $d }
                    return $(if ($d) { -$r } else { $r })
                }
            }
            return $a.Index.CompareTo($b.Index)   # stable
        }
        $keyed.Sort($comparison)

        if ($Unique) {
            $seen = [System.Collections.Generic.HashSet[string]]::new($cmp)
            $out = foreach ($k in $keyed) {
                $sig = ($k.Keys | ForEach-Object { if ($null -eq $_) { '' } else { [string]$_ } }) -join "`u{1}"
                if ($seen.Add($sig)) { $k.Item }
            }
            return @($out)
        }
        # Explicit scriptblock, NOT the "ForEach-Object Item" property-shorthand form: under an ambient
        # $WhatIfPreference (inherited from an ancestor call with -WhatIf, e.g. Sync-FsVaultOutput), the
        # shorthand form emits a spurious "What if: ... Retrieve the value for property 'Item'" line per
        # item instead of just returning the value.
        return @($keyed | ForEach-Object { $_.Item })
    }
}

function Compare-FsValue {
    <# Ordinal comparison used by Get-FsSorted. Nulls sort first. #>
    [OutputType([int])]
    param($a, $b, [System.StringComparer] $Comparer = [System.StringComparer]::OrdinalIgnoreCase)
    if ($null -eq $a -and $null -eq $b) { return 0 }
    if ($null -eq $a) { return -1 }
    if ($null -eq $b) { return 1 }
    if ($a -is [bool] -and $b -is [bool]) { return ([int]$a).CompareTo([int]$b) }
    if (($a -is [ValueType]) -and ($b -is [ValueType]) -and ($a -isnot [bool]) -and ($b -isnot [bool])) {
        try { return ([double]$a).CompareTo([double]$b) } catch { }
    }
    if ($a -is [datetime] -and $b -is [datetime]) { return $a.CompareTo($b) }
    return $Comparer.Compare([string]$a, [string]$b)
}

function Get-FsValue {
    <#
    .SYNOPSIS
        Reads a property from a PSCustomObject or a key from a hashtable, returning $null when absent.
        Supports dotted paths ("ad.department").
    #>
    [OutputType([object])]
    param([AllowNull()] $Object, [Parameter(Mandatory)] [string] $Name)
    $cur = $Object
    foreach ($part in $Name.Split('.')) {
        if ($null -eq $cur) { return $null }
        if ($cur -is [System.Collections.IDictionary]) {
            if ($cur.Contains($part)) { $cur = $cur[$part] } else { return $null }
        }
        else {
            $prop = $cur.PSObject.Properties[$part]
            if ($null -eq $prop) { return $null }
            $cur = $prop.Value
        }
    }
    # Deliberately a bare `return $cur`, NOT `return ,$cur`: every caller in this codebase that expects an
    # array-valued result already wraps the call in `@(Get-FsValue ...)`, relying on PowerShell's normal
    # output-stream unrolling of a single-element array to reconstitute it through that @(). Comma-wrapping
    # here would make such callers receive a 1-element array whose one element is the array itself.
    return $cur
}

function Get-FsSortedKeys {
    <# Ordinal-sorted keys of a dictionary, so enumeration order is deterministic. #>
    [OutputType([string[]])]
    param([Parameter(Mandatory)] [System.Collections.IDictionary] $Dictionary)
    $keys = [string[]]@($Dictionary.Keys)
    [Array]::Sort($keys, [System.StringComparer]::OrdinalIgnoreCase)
    return $keys
}
