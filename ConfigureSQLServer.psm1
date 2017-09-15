<#
	.SYNOPSIS
		Checks to see if the current Powershell session is running in administrative mode

	.DESCRIPTION
		A detailed description of the Test-IsAdmin function.

	.NOTES
		Additional information about the function.
#>
function Test-IsAdmin
{
	[OutputType([boolean])]
	param ()

	# Get the current ID and its security principal
	$windowsID = [System.Security.Principal.WindowsIdentity]::GetCurrent()
	$windowsPrincipal = new-object System.Security.Principal.WindowsPrincipal($windowsID)

	# Get the Admin role security principal
	$adminRole = [System.Security.Principal.WindowsBuiltInRole]::Administrator

	# Are we an admin role?
	if ($windowsPrincipal.IsInRole($adminRole))
	{
		$true
	}
	else
	{
		$false
	}
}
<#
.SYNOPSIS
Enables the TCP/IP Protocol for a SQL Server Instance

.DESCRIPTION
A detailed description of the Enable-TCPProtocol function.

.PARAMETER Server
A description of the Server parameter.

.PARAMETER Instance
A description of the Instance parameter.

.EXAMPLE
PS C:\> Enable-TCPProtocol -Server 'Value1' -Instance 'Value2'

.NOTES
Additional information about the function.
#>
function Enable-TCPProtocol
{
	[CmdletBinding()]
	param
	(
		[Parameter(Mandatory = $true)]
		[string]$ServerName,
		[Parameter(Mandatory = $true)]
		[string]$InstanceName
	)
	#region Enable TCP/IP
	#This example shows how to identify a server protocol using a URN object, and then enable the protocol
	#This program must run with administrator privileges.

	try
	{
		#Get a managed computer instance
		$ManagedComputer = New-Object -TypeName Microsoft.SqlServer.Management.Smo.Wmi.ManagedComputer $ServerName

		#Create a URN object that represents the TCP server protocol
		#Change 'MyPC' to the name of the your computer
		$urn = New-Object -TypeName Microsoft.SqlServer.Management.Sdk.Sfc.Urn -argumentlist "ManagedComputer[@Name='$($ServerName)']/ServerInstance[@Name='$($InstanceName)']/ServerProtocol[@Name='Tcp']"

		#Get the protocol object
		$ServerProtocol = $ManagedComputer.GetSmoObject($urn)

		#enable the protocol on the object
		$ServerProtocol.IsEnabled = $true

		#propagate back to actual service
		$ServerProtocol.Alter()
	}
	catch
	{
		$errorMessage = $_.Exception.Message
		$line = $_.InvocationInfo.ScriptLineNumber
		$script_name = $_.InvocationInfo.ScriptName
		Write-Host "Error: Occurred on line $line in script $script_name." -ForegroundColor Red
		Write-Host "Error: $ErrorMessage" -ForegroundColor Red
	}
	#endregion
}

<#
	.SYNOPSIS
		Sets the start mode to the service to disabled and then stops the service

	.DESCRIPTION
		A detailed description of the Disable-SQLService function.

	.PARAMETER ServerName
		A description of the ServerName parameter.

	.PARAMETER InstanceName
		A description of the InstanceName parameter.

	.PARAMETER ServiceName
		A description of the ServiceName parameter.

	.EXAMPLE
		PS C:\> Disable-SQLService -ServerName 'Value1' -InstanceName 'Value2'

	.NOTES
		Additional information about the function.
#>
function Disable-SQLService
{
	[CmdletBinding()]
	param
	(
		[Parameter(Mandatory = $true)]
		[string]$ServerName,
		[Parameter(Mandatory = $true)]
		[string]$InstanceName,
		[Parameter(Mandatory = $true)]
		[ValidateSet('SqlBrowser')]
		[string]$ServiceName = 'SqlBrowser'
	)

	try
	{
		#Get a managed computer instance
		$ManagedComputer = New-Object -TypeName Microsoft.SqlServer.Management.Smo.Wmi.ManagedComputer


		#Look for the service and then set the start mode to disabled
		$Service = $ManagedComputer.Services | Where-Object { $_.Name -eq $ServiceName }
		$Service.StartMode = 'Disable'
		$Service.alter() | Out-Null
		$Service.Stop() | Out-Null

	}
	catch
	{
		$errorMessage = $_.Exception.Message
		$line = $_.InvocationInfo.ScriptLineNumber
		$script_name = $_.InvocationInfo.ScriptName
		Write-Host "Error: Occurred on line $line in script $script_name." -ForegroundColor Red
		Write-Host "Error: $ErrorMessage" -ForegroundColor Red
	}
}
<#
	.SYNOPSIS
		Restarts a SQL Service

	.DESCRIPTION
		A detailed description of the Restart-Service function.

	.PARAMETER ServerName
		A description of the ServerName parameter.

	.PARAMETER InstanceName
		A description of the InstanceName parameter.

	.PARAMETER ServiceName
		A description of the ServiceName parameter.

	.NOTES
		Additional information about the function.
#>
function Restart-Service
{
	[CmdletBinding()]
	param
	(
		[Parameter(Mandatory = $true)]
		[string]$ServerName,
		[Parameter(Mandatory = $true)]
		[string]$InstanceName,
		[Parameter(Mandatory = $true)]
		[ValidateSet('SQLSERVERAGENT', 'SqlBrowser', 'ReportServer', 'MSSQLSERVER', 'MSSQLLAUNCHPAD', 'MSSQLFDLauncher', 'MsDtsServer130')]
		[string]$ServiceName = 'SqlBrowser'
	)

	try
	{
		$Service = Get-Service -ComputerName $ServerName -Name $ServiceName 
		$DependentServices = Get-Service -ComputerName $ServerName -Name $Service.ServiceName -DependentServices 
		if($Service.Status -eq 'RUNNING')
		{
			if($DependentServices -ne $null)
			{
				foreach($DependentService in $DependentServices)
				{
					Stop-Service -InputObject (Get-Service -ComputerName $ServerName -Name $DependentService.ServiceName)
				}
			}
			Stop-Service -InputObject $Service -Force
		}
		$Service.Refresh()
		while ($Service.Status -ne "Stopped")
		{
			$Service.Refresh()
			$Service.ServiceState
		}
		Start-Service -InputObject $Service
		if($DependentServices -ne $null)
		{
			foreach($DependentService in $DependentServices)
			{
				Start-Service -InputObject (Get-Service -ComputerName $ServerName -Name $DependentService.ServiceName)
			}
		}
		$Service.Refresh()
		while ($Service.Status -ne "Running")
		{
			$Service.Refresh()
			$Service.ServiceState
		}
	}
	catch
	{
		$errorMessage = $_.Exception.Message
		$line = $_.InvocationInfo.ScriptLineNumber
		$script_name = $_.InvocationInfo.ScriptName
		Write-Host "Error: Occurred on line $line in script $script_name." -ForegroundColor Red
		Write-Host "Error: $ErrorMessage" -ForegroundColor Red
	}
}

<#
	.SYNOPSIS
		Sets MAXDOP on a SQL Server Instance

	.DESCRIPTION
		A detailed description of the Set-MAXDOP function.

	.PARAMETER ServerName
		A description of the ServerName parameter.

	.PARAMETER InstanceName
		A description of the InstanceName parameter.

	.NOTES
		Additional information about the function.
#>
function Set-MAXDOP
{
	[CmdletBinding()]
	param
	(
		[Parameter(Mandatory = $true)]
		[string]$ServerName,
		[string]$InstanceName
	)

	$CPUCount = Get-ProcessorCount -ServerName $ServerName
	if ($CPUCount -gt 8) { $CPUCount = 8 }

	$query = "EXECUTE sp_configure 'show advanced options', 1"
	$query = $query + "`nGO"
	$query = $query + "`nRECONFIGURE"
	$query = $query + "`nGO"
	$query = $query + "`nEXECUTE sp_configure 'max degree of parallelism', $($CPUCount)"
	$query = $query + "`nGO"
	$query = $query + "`nRECONFIGURE"
	$query = $query + "`nGO"

	$ServerInstance = Get-SQLServerInstance -ServerName $ServerName -InstanceName $InstanceName
	try
	{
		Write-host "Setting MAXDOP to " -NoNewline; Write-Host $CPUCount -ForegroundColor Yellow
		Invoke-Sqlcmd -ServerInstance $ServerInstance -Query $query -Database "master" -ConnectionTimeout 90 -QueryTimeout 90
		Write-Host "MAXDOP now set " -NoNewline; Write-Host $CPUCount -ForegroundColor Green
	}
	catch
	{
		$errorMessage = $_.Exception.Message
		$line = $_.InvocationInfo.ScriptLineNumber
		$script_name = $_.InvocationInfo.ScriptName
		Write-Host "Error: Occurred on line $line in script $script_name." -ForegroundColor Red
		Write-Host "Error: $ErrorMessage" -ForegroundColor Red
	}
}
<#
	.SYNOPSIS
		Returns a SQL Instance Name

	.DESCRIPTION
		A detailed description of the Get-SQLServerInstance function.

	.PARAMETER ServerName
		A description of the ServerName parameter.

	.PARAMETER InstanceName
		A description of the InstanceName parameter.

	.NOTES
		Additional information about the function.
#>
function Get-SQLServerInstance
{
	[CmdletBinding()]
	[OutputType([string])]
	param
	(
		[Parameter(Mandatory = $true)]
		[string]$ServerName,
		[string]$InstanceName
	)

	if ($InstanceName -eq 'MSSQLSERVER')
	{
		$ServerInstance = $ServerName
	}
	else
	{
		$ServerInstance = "$($ServerName)\$($InstanceName)"
	}
	return $ServerInstance
}


<#
	.SYNOPSIS
		Returns teh number of processors on the server

	.DESCRIPTION
		A detailed description of the Get-ProcessorCount function.

	.PARAMETER ServerName
		A description of the ServerName parameter.

	.NOTES
		Additional information about the function.
#>
function Get-ProcessorCount
{
	[CmdletBinding()]
	[OutputType([string])]
	param
	(
		[Parameter(Mandatory = $true)]
		[string]$ServerName
	)

	try
	{
		$CpuList = @()
		get-wmiobject -class win32_processor -ComputerName $ServerName | foreach { $CpuCount += $_.NumberOfLogicalProcessors }

		#$CpuCount = $CpuList
		return $CpuCount
	}
	catch
	{
		$errorMessage = $_.Exception.Message
		$line = $_.InvocationInfo.ScriptLineNumber
		$script_name = $_.InvocationInfo.ScriptName
		Write-Host "Error: Occurred on line $line in script $script_name." -ForegroundColor Red
		Write-Host "Error: $ErrorMessage" -ForegroundColor Red
	}
}


<#
	.SYNOPSIS
		Sets the MAX Memory value on a SQL Instance

	.DESCRIPTION
		A detailed description of the Set-MAXMemory function.

	.PARAMETER ServerName
		A description of the ServerName parameter.

	.PARAMETER InstanceName
		A description of the InstanceName parameter.

	.NOTES
		Additional information about the function.
#>
function Set-MAXMemory
{
	[CmdletBinding()]
	param
	(
		[Parameter(Mandatory = $true)]
		[string]$ServerName,
		[Parameter(Mandatory = $true)]
		[string]$InstanceName
	)

	$Memory = [Math]::Truncate((Get-ServerMemory -ServerName $ServerName) * .8)

	$query = "EXECUTE sp_configure 'show advanced options', 1"
	$query = $query + "`nGO"
	$query = $query + "`nRECONFIGURE"
	$query = $query + "`nGO"
	$query = $query + "`nEXECUTE sp_configure 'max server memory (MB)', $($Memory)"
	$query = $query + "`nGO"
	$query = $query + "`nRECONFIGURE"
	$query = $query + "`nGO"

	$ServerInstance = Get-SQLServerInstance -ServerName $ServerName -InstanceName $InstanceName
	try
	{
		Write-host "Setting max memory to " -NoNewline; Write-Host $Memory -ForegroundColor Yellow
		Invoke-Sqlcmd -ServerInstance $ServerInstance -Query $query -Database "master" -ConnectionTimeout 90 -QueryTimeout 90
		Write-Host "Max memory now set " -NoNewline; Write-Host $Memory -ForegroundColor Green
	}
	catch
	{
		$errorMessage = $_.Exception.Message
		$line = $_.InvocationInfo.ScriptLineNumber
		$script_name = $_.InvocationInfo.ScriptName
		Write-Host "Error: Occurred on line $line in script $script_name." -ForegroundColor Red
		Write-Host "Error: $ErrorMessage" -ForegroundColor Red
	}
}

<#
	.SYNOPSIS
		Returns the amount of memory the computer has

	.DESCRIPTION
		A detailed description of the Get-ServerMemory function.

	.PARAMETER ServerName
		A description of the ServerName parameter.

	.NOTES
		Additional information about the function.
#>
function Get-ServerMemory
{
	[CmdletBinding()]
	[OutputType([string])]
	param
	(
		[Parameter(Mandatory = $true)]
		[string]$ServerName
	)

	try
	{
		$TotalMemory = get-wmiobject Win32_ComputerSystem -ComputerName $ServerName | %{ $_.TotalPhysicalMemory }
		# convert the memory to MBs
		$TotalMemory = $TotalMemory/1024/1024
		return $TotalMemory
	}
	catch
	{
		$errorMessage = $_.Exception.Message
		$line = $_.InvocationInfo.ScriptLineNumber
		$script_name = $_.InvocationInfo.ScriptName
		Write-Host "Error: Occurred on line $line in script $script_name." -ForegroundColor Red
		Write-Host "Error: $ErrorMessage" -ForegroundColor Red
	}
}


<#
	.SYNOPSIS
		Will run queries in the .\SurfaceArea folder to better secure SQL

	.DESCRIPTION
		A detailed description of the Set-SurfaceArea function.

	.PARAMETER ServerName
		A description of the ServerName parameter.

	.PARAMETER InstanceName
		A description of the InstanceName parameter.

	.NOTES
		Additional information about the function.
#>
function Set-SurfaceArea
{
	[CmdletBinding()]
	param
	(
		[Parameter(Mandatory = $true)]
		[string]$ServerName,
		[Parameter(Mandatory = $true)]
		[string]$InstanceName
	)

	$ServerInstance = Get-SQLServerInstance -ServerName $ServerName -InstanceName $InstanceName
	$Scripts = Get-ChildItem -Path .\SurfaceArea -Filter *.sql
	Write-Host "Attempting to reduce the surface area of $ServerInstance"-ForegroundColor Yellow
	foreach ($Script in $Scripts)
	{
		try
		{
			write-host "Applying script: "$Script.Name
			Invoke-Sqlcmd -ServerInstance $ServerInstance -InputFile $Script.FullName -Database "master" -ConnectionTimeout 90 -QueryTimeout 90 -ErrorAction Stop
			write-host "Applied script:  " $Script.Name -NoNewline; Write-host " SUCCESSFULLY!" -ForegroundColor Green
		}
		catch
		{
			$errorMessage = $_.Exception.Message
			$line = $_.InvocationInfo.ScriptLineNumber
			$script_name = $_.InvocationInfo.ScriptName
			Write-Host "Error: Occurred on line $line in script $script_name." -ForegroundColor Red
			Write-Host "Error occured when trying to run $($Script.FullName)" -ForegroundColor Red
			Write-Host "Error: $ErrorMessage" -ForegroundColor Red
			Break
		}
	}
}
function Set-BaseConfiguration
{
	[CmdletBinding()]
	param
	(
		[Parameter(Mandatory = $true)]
		[string]$ServerName,
		[Parameter(Mandatory = $true)]
		[string]$InstanceName,
		$DBATeamEmail,
        $MailServerName
	)
	$ServerInstance = Get-SQLServerInstance -ServerName $ServerName -InstanceName $InstanceName
	$Scripts = Get-ChildItem -Path .\BaseConfiguration -Filter *.sql
	Write-Host "Attempting to apply the base configuraiton to $ServerInstance"-ForegroundColor Yellow
	foreach ($Script in $Scripts)
	{
		try
		{
			switch ($Script.BaseName)
			{
				'3.ConfigureDatabaseMail'{
					$EmailDomain = $DBATeamEmail.Substring($DBATeamEmail.IndexOf("@"), ($DBATeamEmail.Length - $DBATeamEmail.IndexOf("@")))
					Get-Content -path $Script.FullName -ErrorAction Stop | Foreach-object{ $query = $query + "`n$_" }
					$Query = $query -Replace "##EmailDomain##", $EmailDomain
					$Query = $query -Replace "##DBATeamEmail##", $DBATeamEmail
                    $Query = $query -Replace "##SMTPMailServer##",  $MailServerName
                    $Query = $query -Replace "##ReplyToAddress##", "noreply$($EmailDomain)"
					write-host "Applying script: " $Script.Name
					Invoke-Sqlcmd -Query $query -server $ServerInstance -Database master -ErrorAction Stop
					write-host "Applied script:  " $Script.Name -NoNewline; Write-host " SUCCESSFULLY!" -ForegroundColor Green
				}
				default
				{
					write-host "Applying script: " $Script.Name
					Invoke-Sqlcmd -ServerInstance $ServerInstance -InputFile $Script.FullName -Database "master" -ConnectionTimeout 90 -QueryTimeout 90 -ErrorAction Stop
					write-host "Applied script:  " $Script.Name -NoNewline; Write-host " SUCCESSFULLY!" -ForegroundColor Green
				}
			}

		}
		catch
		{
			$errorMessage = $_.Exception.Message
			$line = $_.InvocationInfo.ScriptLineNumber
			$script_name = $_.InvocationInfo.ScriptName
			Write-Host "Error: Occurred on line $line in script $script_name." -ForegroundColor Red
			Write-Host "Error occured when trying to run $($Script.FullName)" -ForegroundColor Red
			Write-Host "Error: $ErrorMessage" -ForegroundColor Red
			break
		}
	}
}
function Set-ModelDatabaseSettings
{
	[CmdletBinding()]
	param
	(
		[Parameter(Mandatory = $true)]
		[string]$ServerName,
		[Parameter(Mandatory = $true)]
		[string]$InstanceName
	)
	$ServerInstance = Get-SQLServerInstance -ServerName $ServerName -InstanceName $InstanceName
	try
	{
		Write-Host "Setting Model Database File Sizes on " -NoNewline; write-host $ServerName -ForegroundColor YELLO
		Invoke-Sqlcmd -ServerInstance $ServerInstance -InputFile ".\ConfigureModel\ConfigureModelDatabase.sql" -Database "model" -ConnectionTimeout 90 -QueryTimeout 90 -ErrorAction SilentlyContinue
	}
	catch
	{
		$errorMessage = $_.Exception.Message
		$line = $_.InvocationInfo.ScriptLineNumber
		$script_name = $_.InvocationInfo.ScriptName
		Write-Host "Error: Occurred on line $line in script $script_name." -ForegroundColor Red
		Write-Host "Error: $ErrorMessage" -ForegroundColor Red
	}
}
#Requires -Version 3.0

function Install-Ola
{
	[CmdletBinding(DefaultParameterSetName = 'Default',
				   SupportsShouldProcess = $true)]
	param
	(
		[Parameter(Mandatory = $true,
				   ValueFromPipeline = $true)]
		[string]$ServerName,
		[Parameter(Mandatory = $true)]
		[string]$BackupDir,
		[int]$CleanupTime,
		[Parameter(Mandatory = $true)]
		[string]$Schedule,
		[string]$InstanceName
	)

	BEGIN
	{
		Write-Verbose "Start Loop"
		$ServerInstance = Get-SQLServerInstance -ServerName $ServerName -InstanceName $InstanceName
		[System.Reflection.Assembly]::LoadWithPartialName("Microsoft.SqlServer.Smo") | out-null
		[System.Reflection.Assembly]::LoadWithPartialName("Microsoft.SqlServer.ConnectionInfo") | out-null

		function PSScriptRoot { $MyInvocation.ScriptName | Split-Path }

		$MaintenanceSolution = "$(PSScriptRoot)\DatabaseMaintenance\MaintenanceSolution.sql"

		$script = @()
		[string]$scriptpart

		$fullscript = Get-Content $MaintenanceSolution
		foreach ($line in $fullscript)
		{
			if ($line -ne "GO")
			{
				if ($BackupDir -and $line -match "Specify the backup root directory")
				{
					$line = $line.Replace("C:\Backup", $BackupDir)
				}
				if ($CleanupTime -and $line -match "Time in hours, after which backup files are deleted")
				{
					$line = $line.Replace("NULL", $CleanupTime)
				}

				$scriptpart += $line + "`n"
			}
			else
			{
				$properties = @{ Scriptpart = $scriptpart }
				$newscript = New-Object PSObject -Property $properties
				$script += $newscript
				$scriptpart = ""
				$newscrpt = $null
			}
		}
	}

	PROCESS
	{
		$out = "Installing Maintenancesolution on server: {0}" -f $ServerInstance
		Write-Verbose $out

		$ConnectionString = "Server = $ServerInstance ; Database = master; Integrated Security = True;"
		$Connection = New-Object System.Data.SQLClient.SQLConnection
		$Connection.ConnectionString = $ConnectionString
		$Connection.Open();
		$Command = New-Object System.Data.SQLClient.SQLCommand
		$Command.Connection = $Connection


		foreach ($scriptpart in $script)
		{
			$Command.CommandText = $($scriptpart.scriptpart)
			$niks = $Command.ExecuteNonQuery();
		}
		if ($Schedule)
		{
			$Command.CommandText = get-content $Schedule
			$niks = $Command.ExecuteNonQuery();
		}

		$Connection.Close();
	}

	END
	{
		Write-Verbose "End Loop"
	}
}
function Set-TempdbConfiguration
{
	param
	(
		[Parameter(Mandatory = $true)]
		[string]$ServerName,
		[Parameter(Mandatory = $true)]
		[string]$InstanceName
	)

	$StopRetry = $false
	$RetryCount = 0
	do
	{
		$ServerInstance = Get-SQLServerInstance -ServerName $ServerName -InstanceName $InstanceName
		try
		{
			Write-Host "========================================================================================================================="
			Write-Host "Setting up TempDB based on the logic"
			Write-Host "Total SIZE OF temp db = 0.75 OF the total drive size"
			Write-Host "DATA Files = 0.8 OF the Total SIZE OF temp db"
			Write-Host "LOG files = 0.2 OF the Total SIZE OF temp db"
			$Query = "SELECT name, physical_name FROM sys.master_files WHERE database_id = DB_ID(N'tempdb') AND type = 0"
			$results = Invoke-Sqlcmd -ServerInstance $ServerInstance -Query $Query -Database "master" -Verbose -ConnectionTimeout 90 -QueryTimeout 90

			$DeviceID = $results.physical_name[0].substring(0, 2)
			if ($DeviceID -ne "C:")
			{
				$TempDBDriveSize = Get-WmiObject Win32_Volume -ComputerName $ServerName  | where {$_.name -eq ((Split-path $results.physical_name[0]) + "\")} | %{ $_.Capacity }
				
				IF (!($TempDBDriveSize))
				{
					$TempDBDriveSize = Get-WMIObject Win32_LogicalDisk -filter "DeviceID = '$DeviceID'" -ComputerName $ServerName | %{ $_.Size }
				}
				
				
				#$CpuCount = Get-ProcessorCount -ServerName $ServerName
				#As a best practice, we no longer assign the number of tempdb files to match the number of CPUs. We now just make Temdpb a total of 8 files
				#If we need to grow beyond that, we will later after proving that we need more files. If so, files will be added in groups of 4.
				$CpuCount = 8
				$TempDBDriveSize = $TempDBDriveSize/1024 # in KB
				$TempDBTotalSize = [Math]::Truncate($TempDBDriveSize * 0.85)
				$TempDBLogFileSize = [Math]::Truncate($TempDBTotalSize * 0.2)
				$TempDBDataFilesTotalSize = [Math]::Truncate($TempDBTotalSize * 0.8)
				$TempDBEachDataFileSize = [Math]::Truncate($TempDBDataFilesTotalSize/$CpuCount)
				Write-Host "On Server :: $ServerName"
				Write-Host "TempdB Drive Size (KB):: $TempDBDriveSize"
				Write-Host "TempdB Total Size (KB):: $TempDBTotalSize"
				Write-Host "TempdB Total of Data files size (KB):: $TempDBDataFilesTotalSize"
				Write-Host "TempdB Log file size (KB):: $TempDBLogFileSize"
				Write-Host "Total Number of Logical CPUs, hence total # of TempDB Data files :: $CpuCount"
				Write-Host "TempDB Each Data file Size (KB):: $TempDBEachDataFileSize"

                $x = 1
				foreach ($Result in $Results)
                {
                    $query = $null

				    Get-Content ".\ConfigureTempdb\ConfigureSizeOfTempDB.sql" -ErrorAction Stop | Foreach-object{ $query = $query + "`n$_" }
                    $query = ($query -Replace "##name##", $Result.Name)
				    $query = ($query -Replace "##newname##", "tempdev$x")

                    $query = ($query -Replace "##TempDBEachDataFileSize##", $TempDBEachDataFileSize)
				    $query = ($query -Replace "##TempDBLogFileSize##", $TempDBLogFileSize)

				    Invoke-Sqlcmd -ServerInstance $ServerInstance -Query $query -ErrorAction Stop -ConnectionTimeout 90 -QueryTimeout 999
                    $x= $x + 1
                }
				$i = $CpuCount
				Write-Host "Making sure that Tempdb has at least $CpuCount files"
				While ($i -ge $Results.Count)
				{
					$query = $null
					#$File = "\\" + $ServerName + "\" + $Results.physical_name.Replace(":\", "$\")
					#$File = Get-ItemProperty $File
					#$Path = $Results.physical_name.Replace($Results.physical_name, $Results.physical_name + "tempdev$i")
                    $Path = (Split-Path -Path $Results.physical_name[0]) + "\tempdev$i"
        
					Get-Content ".\ConfigureTempdb\ConfigureTempDBFiles.sql" -ErrorAction Stop | Foreach-object{ $query = $query + "`n$_" }
					$query = ($query -Replace "##TempDBEachDataFileSize##", $TempDBEachDataFileSize)
					$query = ($query -Replace "##tempdevi##", "tempdev$i")
					$query = ($query -Replace "##Path##", $Path)
					Invoke-Sqlcmd -ServerInstance $ServerInstance -Query $query -ErrorAction Stop -ConnectionTimeout 90 -QueryTimeout 999
					$i--
				}
				Write-Host "Tempdb set up sueccessfully"
				$StopRetry = $true
			}
			else
			{
				Write-Host "Because TempDB resides on C:, we will not change the size or the number of files Tempdb will have."
				$StopRetry = $true
			}
		}
		catch [System.Exception]
		{
			$ErrMsg = $_.Exception.Message
			Write-Host "Function ConfigureTempDB Error : $ErrMsg" -fail 1
			$RetryCount += 1
			if ($RetryCount -gt 3) { $StopRetry = $true }
		}
	}
	while ($StopRetry -eq $false)
}
<#
.SYNOPSIS
Creates a firewall rule to allow communication on ports 1433, 5022

.DESCRIPTION
A detailed description of the New-SQLFirewallRule function.

.PARAMETER Server
A description of the Server parameter.

.PARAMETER Instance
A description of the Instance parameter.

.EXAMPLE
PS C:\> New-SQLFirewallRule -ServerName 'Value1'

.NOTES
Additional information about the function.
#>
function New-SQLFirewallRule
{
	[CmdletBinding()]
	param
	(
		[Parameter(Mandatory = $true)]
		[string]$ServerName
	)
	try 
	{
		$CIMSession = New-CimSession -ComputerName $ServerName
		$FirewallRule = Get-NetFirewallRule -DisplayName 'SQL Server' -CimSession $CIMSession
		if ($FirewallRule -eq $null){New-NetFirewallRule -DisplayName 'SQL Server' -Direction Inbound -LocalPort 1433,5022 -Protocol TCP -Action Allow -CimSession $CIMSession}
		
	}
	catch
	{
		$errorMessage = $_.Exception.Message
		$line = $_.InvocationInfo.ScriptLineNumber
		$script_name = $_.InvocationInfo.ScriptName
		Write-Host "Error: Occurred on line $line in script $script_name." -ForegroundColor Red
		Write-Host "Error: $ErrorMessage" -ForegroundColor Red
	}
}
function Enable-AlwaysOn
{
	[CmdletBinding()]
	param
	(
		[Parameter(Mandatory = $true)]
		[string]$ServerName
	)
    try
    {
        Enable-SqlAlwaysOn -ServerInstance $ServerName -Force -Verbose
        Write-host "AlwaysOn has been enabled for $ServerName" -ForegroundColor Green
    }
    catch
    {
        Write-host "AlwaysOn was not enabled for $ServerName".ToUpper() -ForegroundColor Yellow
    }
}
function Setup-DBMail
{
    #Code taken from http://www.sqlservercentral.com/articles/Database+Mail/74429/. Has been modified to be made into a function
    # Step 1 - Set variables for mail options. 
    param(
        #[Parameter(AttributeValues)]
        [String]
        $ServerName,

        #[Parameter(AttributeValues)]
        [String]
        $InstanceName,

        #[Parameter(AttributeValues)]
        [String]
        $AccountName,

        #[Parameter(AttributeValues)]
        [String]
        $OriginatingAddress,

        #[Parameter(AttributeValues)]
        [String]
        $ReplyToAddress,

        #[Parameter(AttributeValues)]
        [String]
        $SMTPServer,

        #[Parameter(AttributeValues)]
        [String]
        $ProfileName,

        #[Parameter(AttributeValues)]
        [String]
        $ProfileDescription
    )
    $ServerInstance = Get-SQLServerInstance -ServerName $ServerName -InstanceName $InstanceName
<#
    $sqlServer = 'YourServerName'
    $accountName = 'dbMailDefaultAcct'
    $accountDescription = 'Default dbMail Account'
    $originatingAddress = "$sqlServer@yourDomain.com"
    $replyToAddress = 'DO_NOT_REPLY@yourDomain.com'
    $smtpServer = 'smtpServer.yourDomain.com'
    $profileName = 'dbMailDefaultProfile'
    $profileDescription = 'Default dbMail profile'
#>
    # Step 2 - Load the SMO assembly and create the server object, connecting to the server.
    [System.Reflection.Assembly]::LoadWithPartialName('Microsoft.SqlServer.SMO') | Out-Null
    $SQLServer = New-Object 'Microsoft.SqlServer.Management.SMO.Server' ($ServerInstance)

    # Step 3 - Configure the SQL Server to enable Database Mail.
    $SQLServer.Configuration.DatabaseMailEnabled.ConfigValue = 1
    $SQLServer.Configuration.Alter()

    # Step 4 - Alter mail system parameters if desired, this is an optional step.
    #$SQLServer.Mail.ConfigurationValues.Item('LoggingLevel').Value = 1
    #$SQLServer.Mail.ConfigurationValues.Item('LoggingLevel').Alter()

    # Step 5 - Create the mail account. 
    # ArgumentList contains the mail service, account name, description, 
    # display name and email address.
    $Account = New-Object -TypeName Microsoft.SqlServer.Management.SMO.Mail.MailAccount `
        -Argumentlist $SQLServer.Mail, $AccountName, $AccountDescription, $ServerInstance, $OriginatingAddress 
    $Account.ReplyToAddress = $ReplyToAddress 
    $Account.Create()

    # Step 6 - Set the mail server now that the account is created.
    $Account.MailServers.Item($ServerInstance).Rename($SMTPServer)
    $Account.Alter()

    # Step 7 - Create a public default profile. 
    # ArgumentList contains the mail service, profile name and description.
    $MailProfile = New-Object -TypeName Microsoft.SqlServer.Management.SMO.Mail.MailProfile `
        -ArgumentList $SQLServer.Mail, $ProfileName, $ProfileDescription
    $MailProfile.Create()

    # Step 8 - Associate the account to the profile and set the profile to public
    $MailProfile.AddAccount($AccountName, 0)
    $MailProfile.AddPrincipal('public', 1)
    $MailProfile.Alter()

    # Step 9 - Configure the SQL Agent to use dbMail.
    $SQLServer.JobServer.AgentMailType = 'DatabaseMail'
    $SQLServer.JobServer.DatabaseMailProfile = $ProfileName
    $SQLServer.JobServer.Alter()
}