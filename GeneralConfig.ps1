Configuration GeneralConfig {
    param (
        $ComputerName = "localhost"
    )

    Import-DscResource -ModuleName 'ComputerManagementDSC' -Name 'Timezone'

    Node $ComputerName {
        TimeZone "Timezone" #ResourceName
        {
            TimeZone = "Central Standard Time"
            IsSingleInstance = "Yes"
        }
    }
}

# Cleanup
Remove-Item -Path .\GeneralConfig -Force -Recurse
Remove-DscConfigurationDocument -Stage Pending,Current

#Compile MOF
GeneralConfig

# Run DSC
Start-DSCConfiguration -Wait -Path .\GeneralConfig