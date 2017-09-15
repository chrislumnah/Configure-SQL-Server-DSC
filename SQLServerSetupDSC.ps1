#Requires -Version 4
#Requires -Modules PSDesiredStateConfiguration
#Requires -Modules xSQLServer, @{ModuleName="xSQLServer";ModuleVersion="8.1.0.0"}
#At the time of this writing, xSQLServer was at 8.1.0.0. Future versions of this module could have breaking changes and will need to be retested
[CmdletBinding(DefaultParametersetName="StandAlone")] 
param
(
    # Computer name to install SQL Server On
    [Parameter(Mandatory=$true)]
    [String]
    $ComputerName,

    # Will this be a Failover Cluster Instance Install?
    [Parameter(Mandatory=$False, ParameterSetName="FCI")]
    [Switch]
    $FCI,

    # If this is an FCI install, then choose between Primary or Secondary
    #[Parameter(Mandatory=$true, ParameterSetName="FCI")]
    #[ValidateSet("Primary", "Secondary")]
    #[String]
    #$NodeRole,

    # What is the IP Address to use wtih the new clustered instance of SQL?
    #[Parameter(Mandatory=$true, ParameterSetName="FCI")]
    #[String]
    #$FailoverClusterIPAddress,

    # What is the Cluster Network Name to use wtih the new clustered instance of SQL?
    #[Parameter(Mandatory=$true, ParameterSetName="FCI")]
    #[String]
    #$FailoverClusterNetworkName,

    # Will this be a Stand Alone Install?
    [Parameter(Mandatory=$False, ParameterSetName="StandAlone")]
    [Switch]
    $StandAlone,

    # Will this be a Stand Alone Install?
    [Parameter(Mandatory=$False, ParameterSetName="StandAlone")]
    [Switch]
    $EnableAlwaysOn

)

$OutputPath = '.\sqlserversetup'
$ConfigurationFile = "SQLServerConfiguration.json"
$Configuration = (Get-Content $ConfigurationFile) -join "`n"  | ConvertFrom-Json
Import-Module .\ConfigureSQLServer -Force
#Clear-Host

Configuration SQLServerFCIInstall
{
    Import-DscResource –Module PSDesiredStateConfiguration
    Import-DscResource -Module xSQLServer

    Node $AllNodes.NodeName
    {
        # Set LCM to reboot if needed
        LocalConfigurationManager
        {
            DebugMode = "ForceModuleImport"
            RebootNodeIfNeeded = $true
        }

        WindowsFeature NET-Framework-Core
        {
            Name = "NET-Framework-Core"
            Ensure = "Present"
            IncludeAllSubFeature = $true
        }

        WindowsFeature Failover-Clustering
        {
            Name = "Failover-Clustering"
            Ensure = "Present"
            IncludeAllSubFeature = $true
        }

        if ($Node.Role -eq "Primary")
        {
            xSqlServerSetup Install_SQL
            {
                PsDscRunAsCredential = $Node.InstallerServiceAccount
                DependsOn = '[WindowsFeature]NET-Framework-Core'
                Action =  "InstallFailoverCluster"
                UpdateEnabled = $Configuration.InstallSQL.UpdateEnabled
                UpdateSource = $Configuration.InstallSQL.UpdateSource
                Features = $Configuration.InstallSQL.Features
                InstanceName = $Configuration.InstallSQL.InstanceName

                InstallSharedDir = $Configuration.InstallSQL.InstallSharedDir
                InstallSharedWOWDir = $Configuration.InstallSQL.InstallSharedWOWDir
                InstanceDir = $Configuration.InstallSQL.InstanceDir

                InstallSQLDataDir = $Configuration.InstallSQL.InstallSQLDataDir
                SQLUserDBDir = $Configuration.InstallSQL.SQLUserDBDir
                SQLUserDBLogDir = $Configuration.InstallSQL.SQLUserDBLogDir
                SQLTempDBDir = $Configuration.InstallSQL.SQLTempDBDir
                SQLTempDBLogDir = $Configuration.InstallSQL.SQLTempDBLogDir
                SQLBackupDir = $Configuration.InstallSQL.SQLBackupDir

                SecurityMode = $Configuration.InstallSQL.SecurityMode
                SAPwd = $Node.SAPwd

                AgtSvcAccount = $Node.AgtSvcAccount
                SQLSvcAccount = $Node.SQLSvcAccount
                #ISSvcAccount = $Node.ISSvcAccount
                #FTSvcAccount = $Node.FTSvcAccount

                SQLCollation = $Configuration.InstallSQL.SQLCollation
            
                SQLSysAdminAccounts = $Configuration.InstallSQL.SQLSysAdminAccounts
            
                SourcePath = $Configuration.InstallSQL.SourcePath
                SourceCredential = $Node.InstallerServiceAccount

                FailoverClusterGroupName = $Configuration.InstallSQL.FCI.FailoverClusterGroupName
                FailoverClusterIPAddress = $Node.FailoverClusterIPAddress
                FailoverClusterNetworkName = $Node.FailoverClusterNetworkName
            }
        }
        if ($Node.Role -eq "Secondary")
        {
            xSqlServerSetup Install_SQL
            {
                PsDscRunAsCredential = $Node.InstallerServiceAccount
                DependsOn = '[WindowsFeature]NET-Framework-Core'
                Action =  "AddNode"
                UpdateEnabled = $Configuration.InstallSQL.UpdateEnabled
                UpdateSource = $Configuration.InstallSQL.UpdateSource
                Features = $Configuration.InstallSQL.Features
                InstanceName = $Configuration.InstallSQL.InstanceName

                InstallSharedDir = $Configuration.InstallSQL.InstallSharedDir
                InstallSharedWOWDir = $Configuration.InstallSQL.InstallSharedWOWDir
                InstanceDir = $Configuration.InstallSQL.InstanceDir

                InstallSQLDataDir = $Configuration.InstallSQL.InstallSQLDataDir
                SQLUserDBDir = $Configuration.InstallSQL.SQLUserDBDir
                SQLUserDBLogDir = $Configuration.InstallSQL.SQLUserDBLogDir
                SQLTempDBDir = $Configuration.InstallSQL.SQLTempDBDir
                SQLTempDBLogDir = $Configuration.InstallSQL.SQLTempDBLogDir
                SQLBackupDir = $Configuration.InstallSQL.SQLBackupDir

                #SecurityMode = $Configuration.InstallSQL.SecurityMode
                #SAPwd = $Node.SAPwd
                
                AgtSvcAccount = $Node.AgtSvcAccount
                SQLSvcAccount = $Node.SQLSvcAccount
                #ISSvcAccount = $Node.ISSvcAccount
                #FTSvcAccount = $Node.FTSvcAccount

                SQLCollation = $Configuration.InstallSQL.SQLCollation
            
                SQLSysAdminAccounts = $Configuration.InstallSQL.SQLSysAdminAccounts
            
                SourcePath = $Configuration.InstallSQL.SourcePath
                SourceCredential = $Node.InstallerServiceAccount

                FailoverClusterGroupName = $Configuration.InstallSQL.FCI.FailoverClusterGroupName
                FailoverClusterIPAddress = $Node.FailoverClusterIPAddress
                FailoverClusterNetworkName = $Node.FailoverClusterNetworkName
            }
        }
    }
}
Configuration SQLServerInstall
{
    Import-DscResource –Module PSDesiredStateConfiguration
    Import-DscResource -Module xSQLServer

    Node $AllNodes.NodeName
    {
        # Set LCM to reboot if needed
        LocalConfigurationManager
        {
            DebugMode = "ForceModuleImport"
            RebootNodeIfNeeded = $true
        }

        WindowsFeature NET-Framework-Core
        {
            Name = "NET-Framework-Core"
            Ensure = "Present"
            IncludeAllSubFeature = $true
        }

        xSqlServerSetup Install_SQL
        {
            PsDscRunAsCredential = $Node.InstallerServiceAccount
            DependsOn = '[WindowsFeature]NET-Framework-Core'
            Action =  "Install"
            UpdateEnabled = $Configuration.InstallSQL.UpdateEnabled
            UpdateSource = $Configuration.InstallSQL.UpdateSource
            Features = $Configuration.InstallSQL.Features
            InstanceName = $Configuration.InstallSQL.InstanceName

            InstallSharedDir = $Configuration.InstallSQL.InstallSharedDir
            InstallSharedWOWDir = $Configuration.InstallSQL.InstallSharedWOWDir
            InstanceDir = $Configuration.InstallSQL.InstanceDir

            InstallSQLDataDir = $Configuration.InstallSQL.InstallSQLDataDir
            SQLUserDBDir = $Configuration.InstallSQL.SQLUserDBDir
            SQLUserDBLogDir = $Configuration.InstallSQL.SQLUserDBLogDir
            SQLTempDBDir = $Configuration.InstallSQL.SQLTempDBDir
            SQLTempDBLogDir = $Configuration.InstallSQL.SQLTempDBLogDir
            SQLBackupDir = $Configuration.InstallSQL.SQLBackupDir
            
            SecurityMode = $Configuration.InstallSQL.SecurityMode
            SAPwd = $Node.SAPwd
            
            AgtSvcAccount = $Node.AgtSvcAccount
            SQLSvcAccount = $Node.SQLSvcAccount
            #ISSvcAccount = $Node.ISSvcAccount
            #FTSvcAccount = $Node.FTSvcAccount

            SQLCollation = $Configuration.InstallSQL.SQLCollation
            
            SQLSysAdminAccounts = $Configuration.InstallSQL.SQLSysAdminAccounts
            
            SourcePath = $Configuration.InstallSQL.SourcePath
            SourceCredential = $Node.InstallerServiceAccount
        }
    }
}
Configuration ConfigureSQL
{
    Import-DscResource –Module PSDesiredStateConfiguration
    Import-DscResource -Module xSQLServer
    Import-DscResource -Module SecurityPolicyDsc

    Node $AllNodes.NodeName
    {
        # Set LCM to reboot if needed
        LocalConfigurationManager
        {
            DebugMode = "ForceModuleImport"
            RebootNodeIfNeeded = $true
        }
        xSQLServerNetwork ConfigureSQLNetwork
        {
            InstanceName = $Configuration.InstallSQL.InstanceName
            ProtocolName = 'Tcp'
            IsEnabled = $true
            TCPDynamicPorts = ''
            TCPPort = 1433
            RestartService = $true
        }    
        xSQLServerMemory SetMAXMemory
        {
            Ensure = "Present"
            SQLInstanceName   = $Configuration.InstallSQL.InstanceName
            #MaxMemory = $MAXMemory
            DynamicAlloc = $True
        }
        xSQLServerMaxDop SetMAXDOP
        {
            SQLInstanceName = $Configuration.InstallSQL.InstanceName
            MaxDop = $MAXDOP
        }
<#        
        xSQLServerFirewall CreateFirewallRules
        {
            #DependsOn = '[xSqlServerSetup]Install_SQL'
            Features = "SQLENGINE,IS"
            InstanceName = $Configuration.InstallSQL.InstanceName 
            Ensure = "Present"
            SourcePath = $Configuration.InstallSQL.SourcePath
            PsDscRunAsCredential = $Node.InstallerServiceAccount
        }
#>
        UserRightsAssignment PerformVolumeMaintenanceTasks
        {
            Policy = "Perform_volume_maintenance_tasks"
            Identity = "Builtin\Administrators"
        }
        UserRightsAssignment LockPagesInMemory
        {
            Policy = "Lock_pages_in_memory"
            Identity = "Builtin\Administrators"
        }
    }
}
<#    xSQLServerAlwaysOnService EnableAlwaysOn
    {
        SQLServer = $ComputerName
        SQLInstanceName = $Configuration.InstallSQL.InstanceName
        DependsOn = "[xSqlServerSetup]InstallSQL"
        Ensure = "Present"
    }


#>
$ConfigurationData = @{
    AllNodes = @(
        @{
            NodeName = "*"
            PSDscAllowPlainTextPassword = $true
            PSDscAllowDomainUser =$true
            InstallerServiceAccount = Get-Credential -UserName $Configuration.InstallSQL.SourceCredential -Message "Credentials to Install SQL Server"
            SQLSvcAccount  = Get-Credential -UserName $Configuration.InstallSQL.SQLSvcAccount -Message "Credentials to run the SQL Server Service "
            AgtSvcAccount =  Get-Credential -UserName $Configuration.InstallSQL.AgtSvcAccount -Message "Credentials used to run the SQL Agent Service"
            SAPwd  =  Get-Credential -UserName $Configuration.InstallSQL.SAPwd  -Message "Set the password to the SA account" 
        }
    )
}
              # ISSvcAccount = Get-Credential -UserName $Configuration.InstallSQL.ISSvcAccount -Message "Credentials to run the SSIS Service"
              #  FTSvcAccount = Get-Credential -UserName $Configuration.InstallSQL.FTSvcAccount -Message "Credentials to run the Full Text Indexing Service"
        

   # ForEach ($Computer in $Computers)
   # {
        #$CpuCount = 0
        #$MaxMemory = [Math]::Truncate((Get-ServerMemory -ServerName $Computer) * .8)
        #$CPUCount = Get-ProcessorCount -ServerName $Computer
        #if ($CPUCount -gt 8) { $CPUCount = 8 }
        #$CPUCount
if ($StandAlone)
{        
    $ConfigurationData.AllNodes += @{
        NodeName = $ComputerName
        Role = $Configuration.InstallSQL.FCI.NodeRole
        FailoverClusterIPAddress = $Configuration.InstallSQL.FCI.FailoverClusterIPAddress
        FailoverClusterNetworkName = $Configuration.InstallSQL.FCI.FailoverClusterNetworkName
        EnableAlwaysOn = $EnableAlwaysOn
        SQLServer = $ComputerName
    }        
}
else
{
    $ConfigurationData.AllNodes += @{
        NodeName = $ComputerName
        Role = $Configuration.InstallSQL.FCI.NodeRole
        FailoverClusterIPAddress = $Configuration.InstallSQL.FCI.FailoverClusterIPAddress
        FailoverClusterNetworkName = $Configuration.InstallSQL.FCI.FailoverClusterNetworkName
        EnableAlwaysOn = $EnableAlwaysOn
        SQLServer = $Configuration.InstallSQL.FCI.FailoverClusterNetworkName
    }   
}
$Destination = "\\" +$ComputerName +"\\c$\Program Files\WindowsPowerShell\Modules"
Copy-Item 'C:\Program Files\WindowsPowerShell\Modules\xSQLServer' -Destination $Destination -Recurse -Force 
Copy-Item 'C:\Program Files\WindowsPowerShell\Modules\SecurityPolicyDsc' -Destination $Destination -Recurse -Force
#Copy-Item 'C:\Program Files\WindowsPowerShell\Modules\xPendingReboot' -Destination $Destination -Recurse -Force

if ($FCI)
{
    SQLServerFCIInstall -ConfigurationData $ConfigurationData -OutputPath $OutputPath 
}

if ($StandAlone)
{
    SQLServerInstall -ConfigurationData $ConfigurationData -OutputPath $OutputPath 
}

    
  
    
#Push################################
#foreach($Computer in $Computers)
#{

Start-DscConfiguration -ComputerName $ComputerName -Path $OutputPath -Verbose -Wait -Force
If ($Configuration.InstallSQL.FCI.NodeRole -eq "Primary" -or ($Standalone))
{
    ConfigureSQL -ConfigurationData $ConfigurationData -OutputPath $OutputPath 
    Start-DscConfiguration  -ComputerName $ComputerName -Path $OutputPath -Verbose -Wait -Force
    New-SQLFirewallRule -ServerName $ComputerName
   
    if ($StandAlone)
    {
        Set-TempdbConfiguration -ServerName $ComputerName `
            -InstanceName $Configuration.InstallSQL.InstanceName
        Setup-DBMail -ServerName $ComputerName `
            -InstanceName $Configuration.InstallSQL.InstanceName `
            -AccountName $Configuration.InstallSQL.DatabaseMail.AccountName `
            -AccountDescription $Configuration.InstallSQL.DatabaseMail.AccountDescription `
            -OriginatingAddress $Configuration.InstallSQL.DatabaseMail.OriginatingAddress `
            -ReplyToAddress $Configuration.InstallSQL.DatabaseMail.ReplyToAddress `
            -SMTPServer $Configuration.InstallSQL.DatabaseMail.SMTPServer `
            -ProfileName $Configuration.InstallSQL.DatabaseMail.ProfileName `
            -ProfileDescription $Configuration.InstallSQL.DatabaseMail.ProfileDescription
    }
    else
    {
        Write-host "Did i get here?"
        $Configuration.InstallSQL.FCI.FailoverClusterNetworkName
        Set-TempdbConfiguration -ServerName $Configuration.InstallSQL.FCI.FailoverClusterNetworkName  -InstanceName $Configuration.InstallSQL.InstanceName  
        Setup-DBMail -ServerName $Configuration.InstallSQL.FCI.FailoverClusterNetworkName `
        -InstanceName $Configuration.InstallSQL.InstanceName `
        -AccountName $Configuration.InstallSQL.DatabaseMail.AccountName `
        -AccountDescription $Configuration.InstallSQL.DatabaseMail.AccountDescription `
        -OriginatingAddress $Configuration.InstallSQL.DatabaseMail.OriginatingAddress `
        -ReplyToAddress $Configuration.InstallSQL.DatabaseMail.ReplyToAddress `
        -SMTPServer $Configuration.InstallSQL.DatabaseMail.SMTPServer `
        -ProfileName $Configuration.InstallSQL.DatabaseMail.ProfileName `
        -ProfileDescription $Configuration.InstallSQL.DatabaseMail.ProfileDescription
    }
}
