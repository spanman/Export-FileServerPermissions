<#
Access-mask interpretation shared by the collector, analytics and renderer.

Rights ordinal used everywhere:  None=0 < List=1 < Read=2 < Write=3 < Modify=4 < Full=5
#>

# PowerShell parses 0xFFFFFFFF as Int32 -1, so 32-bit masks are expressed as explicit longs.
$script:FsMask32 = [long]4294967295
$script:FsGenericAll = [long]268435456      # 0x10000000
$script:FsGenericExecute = [long]536870912  # 0x20000000
$script:FsGenericWrite = [long]1073741824   # 0x40000000
$script:FsGenericRead = [long]2147483648    # 0x80000000

$script:FsLevelNames = @('None', 'List', 'Read', 'Write', 'Modify', 'Full')
$script:FsLevelOrdinal = @{ None = 0; List = 1; Read = 2; Write = 3; Modify = 4; Full = 5 }

# FileSystemRights bits
$script:FsBits = @{
    ListDirectory          = 0x1
    ReadData               = 0x1
    WriteData              = 0x2
    AppendData             = 0x4
    ReadExtendedAttributes = 0x8
    WriteExtendedAttributes = 0x10
    ExecuteFile            = 0x20
    DeleteSubdirectoriesAndFiles = 0x40
    ReadAttributes         = 0x80
    WriteAttributes        = 0x100
    Delete                 = 0x10000
    ReadPermissions        = 0x20000
    ChangePermissions      = 0x40000
    TakeOwnership          = 0x80000
    Synchronize            = 0x100000
    FullControl            = 0x1F01FF
    Modify                 = 0x301BF
    ReadAndExecute         = 0x200A9
    Read                   = 0x20089
    Write                  = 0x116
    GenericAll             = [long]268435456
    GenericExecute         = [long]536870912
    GenericWrite           = [long]1073741824
    GenericRead            = [long]2147483648
}

# Share (SMB) access masks
$script:FsShareMasks = @{ Full = 0x1F01FF; Change = 0x1301BF; Read = 0x1200A9 }

function Get-FsLevelOrdinal {
    [OutputType([int])]
    param([Parameter(Mandatory)] [AllowEmptyString()] [string] $Level)
    if ($script:FsLevelOrdinal.ContainsKey($Level)) { return $script:FsLevelOrdinal[$Level] }
    return 0
}

function Get-FsLevelName {
    [OutputType([string])]
    param([Parameter(Mandatory)] [int] $Ordinal)
    if ($Ordinal -lt 0) { return 'None' }
    if ($Ordinal -ge $script:FsLevelNames.Count) { return 'Full' }
    return $script:FsLevelNames[$Ordinal]
}

function Get-FsMinLevel {
    <# The lower of two level names (share vs NTFS). #>
    [OutputType([string])]
    param([Parameter(Mandatory)] [string] $A, [Parameter(Mandatory)] [string] $B)
    $oa = Get-FsLevelOrdinal $A; $ob = Get-FsLevelOrdinal $B
    return Get-FsLevelName ([Math]::Min($oa, $ob))
}

function ConvertTo-FsNormalizedMask {
    <# Expands GENERIC_* bits into their specific FileSystemRights equivalents. Accepts negative int32 masks. #>
    [OutputType([long])]
    param([Parameter(Mandatory)] [long] $Mask)
    $m = [long]($Mask -band $script:FsMask32)
    $out = $m -band 0x1FFFFFF   # keep specific + standard bits
    if ($m -band $script:FsGenericAll) { $out = $out -bor 0x1F01FF }                # GENERIC_ALL
    if ($m -band $script:FsGenericRead) { $out = $out -bor 0x120089 }               # GENERIC_READ  (Read + Synchronize)
    if ($m -band $script:FsGenericWrite) { $out = $out -bor 0x120116 }              # GENERIC_WRITE (Write + ReadPermissions + Synchronize)
    if ($m -band $script:FsGenericExecute) { $out = $out -bor 0x1200A0 }            # GENERIC_EXECUTE
    return [long]$out
}

function Get-FsMaskLevel {
    <#
    .SYNOPSIS
        Maps an NTFS access mask (int) to a level name.
    #>
    [OutputType([string])]
    param([Parameter(Mandatory)] [long] $Mask)
    $m = ConvertTo-FsNormalizedMask $Mask
    if (($m -band 0x1F01FF) -eq 0x1F01FF) { return 'Full' }
    if (($m -band 0x0301BF) -eq 0x0301BF) { return 'Modify' }
    if ($m -band (0x2 -bor 0x4 -bor 0x40 -bor 0x100 -bor 0x10 -bor 0x10000)) { return 'Write' }
    if (($m -band 0x20089) -eq 0x20089) { return 'Read' }
    if ($m -band 0x1) { return 'List' }
    return 'None'
}

function Get-FsShareRightLevel {
    <# Maps a share AccessRight string (Full/Change/Read/Custom) or mask to a level name. #>
    [OutputType([string])]
    param([AllowNull()] [string] $AccessRight, [long] $AccessMask = -1)
    switch ($AccessRight) {
        'Full' { return 'Full' }
        'Change' { return 'Modify' }
        'Read' { return 'Read' }
    }
    if ($AccessMask -ge 0) { return Get-FsMaskLevel $AccessMask }
    return 'None'
}

function Get-FsShareRightName {
    <# Maps a share access mask to Full/Change/Read/Custom. #>
    [OutputType([string])]
    param([Parameter(Mandatory)] [long] $AccessMask)
    $m = $AccessMask -band 0xFFFFFFFF
    foreach ($k in 'Full', 'Change', 'Read') { if ($m -eq $script:FsShareMasks[$k]) { return $k } }
    return 'Custom'
}

function Test-FsMaskHasBits {
    [OutputType([bool])]
    param([Parameter(Mandatory)] [long] $Mask, [Parameter(Mandatory)] [long] $Bits)
    return (((ConvertTo-FsNormalizedMask $Mask) -band $Bits) -ne 0)
}

function Test-FsMaskWriteDacOrOwner {
    <# True when the mask grants ChangePermissions or TakeOwnership. #>
    [OutputType([bool])]
    param([Parameter(Mandatory)] [long] $Mask)
    return (Test-FsMaskHasBits -Mask $Mask -Bits (0x40000 -bor 0x80000))
}

function ConvertTo-FsRightsString {
    <# Human-readable rights for a mask: the composite name when exact, else a comma list of bit names. #>
    [OutputType([string])]
    param([Parameter(Mandatory)] [long] $Mask)
    $m = ConvertTo-FsNormalizedMask $Mask
    $noSync = $m -band (-bnot 0x100000)
    foreach ($name in 'FullControl', 'Modify', 'ReadAndExecute', 'Read', 'Write') {
        if ($noSync -eq $script:FsBits[$name]) { return $name }
    }
    $parts = foreach ($name in 'ReadData', 'WriteData', 'AppendData', 'ReadExtendedAttributes', 'WriteExtendedAttributes',
        'ExecuteFile', 'DeleteSubdirectoriesAndFiles', 'ReadAttributes', 'WriteAttributes', 'Delete',
        'ReadPermissions', 'ChangePermissions', 'TakeOwnership', 'Synchronize') {
        if ($m -band $script:FsBits[$name]) { $name }
    }
    if (-not $parts) { return 'None' }
    return ($parts -join ', ')
}

function ConvertTo-FsAppliesTo {
    <# Explorer-style "applies to" text from inheritance and propagation flags. #>
    [OutputType([string])]
    param([AllowNull()] [string] $InheritanceFlags, [AllowNull()] [string] $PropagationFlags)
    $ci = $InheritanceFlags -match 'ContainerInherit'
    $oi = $InheritanceFlags -match 'ObjectInherit'
    $io = $PropagationFlags -match 'InheritOnly'
    $np = $PropagationFlags -match 'NoPropagateInherit'
    $text = if ($ci -and $oi) { if ($io) { 'Subfolders and files only' } else { 'This folder, subfolders and files' } }
    elseif ($ci) { if ($io) { 'Subfolders only' } else { 'This folder and subfolders' } }
    elseif ($oi) { if ($io) { 'Files only' } else { 'This folder and files' } }
    else { 'This folder only' }
    if ($np) { $text += ' (no propagation)' }
    return $text
}

function Test-FsAceInheritOnly {
    [OutputType([bool])]
    param([AllowNull()] [string] $PropagationFlags)
    return ($PropagationFlags -match 'InheritOnly')
}
