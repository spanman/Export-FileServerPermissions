@{
    Severity     = @('Error', 'Warning')
    ExcludeRules = @(
        # We deliberately write UTF-8 without BOM for Obsidian/git friendliness.
        'PSUseBOMForUnicodeEncodedFile',
        # Entry script and collector use Write-Host for the banner and final summary only.
        'PSAvoidUsingWriteHost',
        # Remote scriptblocks legitimately use Invoke-Expression-free but positional patterns.
        'PSUseShouldProcessForStateChangingFunctions',
        # Collection-oriented domain vocabulary is deliberately plural (Get-FsChangeSets, Compare-FsShares,
        # Get-FsInsightTags, ...) - each of these genuinely operates on/returns multiple items.
        'PSUseSingularNouns'
    )
    Rules        = @{
        PSUseCompatibleSyntax = @{
            Enable         = $true
            TargetVersions = @('7.0')
        }
        PSAvoidUsingCmdletAliases = @{
            Whitelist = @()
        }
    }
}
