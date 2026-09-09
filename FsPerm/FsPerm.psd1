@{
    RootModule        = 'FsPerm.psm1'
    ModuleVersion     = '2.0.0'
    GUID              = 'b5c0a4d2-6f0e-4d4e-9c1a-2f7b8e1d3a90'
    Author            = 'Mark Spanagel'
    CompanyName       = 'PAR Systems'
    Copyright         = '(c) PAR Systems. MIT License.'
    Description       = 'Scans Windows file server share and NTFS permissions, maps AD group membership, and renders an Obsidian vault with reports.'
    PowerShellVersion = '7.0'
    FunctionsToExport = '*'
    CmdletsToExport   = @()
    VariablesToExport = @()
    AliasesToExport   = @()
    PrivateData       = @{
        PSData = @{
            Tags       = @('FileServer', 'NTFS', 'Permissions', 'ActiveDirectory', 'Obsidian', 'Audit')
            LicenseUri = 'https://opensource.org/licenses/MIT'
            ProjectUri = 'https://github.com/spanman/Export-FileServerPermissions'
        }
    }
}
