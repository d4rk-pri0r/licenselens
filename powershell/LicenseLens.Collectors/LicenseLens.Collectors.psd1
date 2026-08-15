@{
    RootModule        = 'LicenseLens.Collectors.psm1'
    ModuleVersion     = '0.1.0'
    GUID              = 'a3c8e2f1-9b4d-4e6a-8c1f-2d7e5b9a0c4e'
    Author            = 'LicenseLens'
    CompanyName       = 'LicenseLens'
    Copyright         = 'MIT'
    Description       = 'Allowlisted, read-only collector adapters for the LicenseLens PowerShell bridge.'
    PowerShellVersion = '5.1'
    FunctionsToExport = @('Invoke-LicenseLensCollectorAdapter')
    CmdletsToExport   = @()
    VariablesToExport = @()
    AliasesToExport   = @()
    PrivateData       = @{
        PSData = @{
            Tags         = @('LicenseLens', 'Security', 'ReadOnly')
            LicenseUri   = 'https://opensource.org/licenses/MIT'
            ProjectUri   = 'https://github.com/d4rk-pri0r/licenselens'
            ReleaseNotes = 'Wave 2 power-data (Power Platform + Power BI + Purview) read-only adapters.'
        }
    }
}
