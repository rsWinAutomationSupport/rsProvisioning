Set-ExecutionPolicy -ExecutionPolicy Bypass -Force
if([System.Diagnostics.EventLog]::SourceExists('BasePrep')) {
}
else {
   New-EventLog -LogName "DevOps" -Source BasePrep
}
Import-Module rsCommon
. (Get-rsSecrets)
$DedicatedData = Get-rsDedicatedInfo
if(Test-Path -Path $("C:\DevOps", $d.mR, 'PullServerinfo.ps1' -join '\')) {
   . "$("C:\DevOps", $d.mR, 'PullServerinfo.ps1' -join '\')"
}

##################################################################################################################################
#                                             Function - Write Event Log Entries
##################################################################################################################################
Function Write-Log {
   param([string]$value)
   $timeStamp = (get-date).ToString()
   Write-EventLog -LogName DevOps -Source BasePrep -EntryType Information -EventId 1000 -Message ($timeStamp + ":`t" + $value)
   return
}

Function Load-Globals {
   if((Get-rsRole -Value $env:COMPUTERNAME) -eq "pull") {
      if(Test-rsCloud) {
         $Global:catalog = Get-rsServiceCatalog
         $Global:AuthToken = @{"X-Auth-Token"=($Global:catalog.access.token.id)}
         $Global:defaultRegion = $Global:catalog.access.user.'RAX-AUTH:defaultRegion'
         if(($Global:catalog.access.user.roles | Where-Object name -eq "rack_connect").id.count -gt 0) { $Global:isRackConnect = $true } else { $Global:isRackConnect = $false } 
         if(($Global:catalog.access.user.roles | Where-Object name -eq "rax_managed").id.count -gt 0) { $Global:isManaged = $true } else { $Global:isManaged = $false } 
      }
      else {
         $Global:defaultRegion = (Get-rsDedicatedInfo | Where-Object {$_.name -eq $env:COMPUTERNAME}).defaultRegion
         $Global:isRackConnect = (Get-rsDedicatedInfo | Where-Object {$_.name -eq $env:COMPUTERNAME}).isRackConnect
         $Global:isManaged = $true
      }
      $Global:pullServerName = $env:COMPUTERNAME
      $Global:pullServerPublicIP = Get-rsAccessIPv4
      $Global:pullServerPrivateIP = (Get-NetAdapter | Where-Object status -eq 'up' | Get-NetIPAddress -ea 0 | Where-Object IPAddress -match '^10\.').IPAddress
      $Global:pullServerRegion = Get-rsRegion -Value $env:COMPUTERNAME
   }
   else 
   {
      $Global:pullServerName = $pullServerInfo.pullServerName
      $Global:pullServerPublicIP = $pullserverInfo.pullserverPublicIp
      $Global:pullServerPrivateIP = $pullServerInfo.pullServerPrivateIp
      $Global:isRackConnect = $pullServerInfo.isRackConnect
      $Global:isManaged = $pullServerInfo.isManaged
      $Global:defaultRegion = $pullServerInfo.defaultRegion
      $Global:pullServerRegion = $pullServerInfo.region
   }
   $currentValues = @{
    "stage" = $stage;
    "role" = (Get-rsRole -Value $env:COMPUTERNAME);
    "osVersion" = $osVersion;
    "pullServerName" = $pullServerName;
    "pullServerPublicIP" = $pullServerPublicIP;
    "pullServerPrivateIP" = $pullServerPrivateIP;
    "serverRegion" = (Get-rsRegion -Value $env:COMPUTERNAME);
    "pullServerRegion" = $pullServerRegion;
    "wmfVersion" = $wmfVersion;
    "netVersion" = $netVersion;
    } | ConvertTo-Json
   Write-EventLog -LogName DevOps -Source BasePrep -EntryType Information -EventId 1000 -Message "Current variable values during this iteration, $currentValues"
}

##################################################################################################################################
#                                             Function - Disable Client For Microsoft Networks
##################################################################################################################################
Function Set-MSN {
   param([bool][ValidateNotNull()]$Enabled)
   Write-EventLog -LogName DevOps -Source BasePrep -EntryType Information -EventId 1000 -Message "Disabling MSN on all adapters"
   (Get-NetAdapter).Name | % {Set-NetAdapterBinding -Name $_ -DisplayName "Client for Microsoft Networks" -Enabled $Enabled}
   return
}

##################################################################################################################################
#                                             Function - Edit PullServerInfo.ps1 and push to customer configuration repo
##################################################################################################################################
Function Create-PullServerInfo {
   if((Get-rsRole -Value $env:COMPUTERNAME) -eq "Pull") {
      $region = Get-rsRegion -Value $env:COMPUTERNAME
      chdir $("C:\DevOps", $d.mR -join '\')
      $pullServerName = $env:COMPUTERNAME
      $path = $("C:\DevOps" + "\" + $d.mR + "\" + "PullServerInfo.ps1")
      if(Test-Path -Path $path) {
         Remove-Item -Path $path -Force
      }
      New-Item -path $path -ItemType file
      Add-Content -Path $path -Value "`$pullServerInfo = @{"
      Add-Content -Path $path -Value "`"pullServerName`" = `"$pullServerName`""
      Add-Content -Path $path -Value "`"pullServerPrivateIp`" = `"$pullServerPrivateIp`""
      Add-Content -Path $path -Value "`"pullServerPublicIp`" = `"$pullServerPublicIp`""
      Add-Content -Path $path -Value "`"region`" = `"$(Get-rsRegion -Value $env:COMPUTERNAME)`""
      Add-Content -Path $path -Value "`"isRackConnect`" = `$$($isRackConnect.toString().toLower())"
      Add-Content -Path $path -Value "`"isManaged`" = `$$($isManaged.toString().toLower())"
      Add-Content -Path $path -Value "`"defaultRegion`" = `"$defaultRegion`""
      Add-Content -Path $path -Value "}"
      Start-Service Browser
      $trackedFiles = @()
      $fileNames = (Get-Item -Path $("C:\DevOps", $d.mR, "Certificates", '*' -join '\')).Name
      foreach($fileName in $fileNames) {
         $trackedFiles += $("C:\DevOps", $d.mR, "Certificates", $fileName -join '\')
      }
      $trackedFiles += $("C:\DevOps", $d.mR, "PullServerInfo.ps1" -join '\')
      foreach($trackedFile in $trackedFiles) {
         Start -Wait "C:\Program Files (x86)\Git\bin\git.exe" -ArgumentList "add $trackedFile"
      }
      Start -Wait "C:\Program Files (x86)\Git\bin\git.exe" -ArgumentList "commit -a -m `"$pullServerName pushing PullServerInfo.ps1`""
      Start -Wait "C:\Program Files (x86)\Git\bin\git.exe" -ArgumentList "fetch origin $($d.branch_rsConfigs)"
      Start -Wait "C:\Program Files (x86)\Git\bin\git.exe" -ArgumentList "merge remotes/origin/$($d.branch_rsConfigs)"
      Start -Wait "C:\Program Files (x86)\Git\bin\git.exe" -ArgumentList "push origin $($d.branch_rsConfigs)"
      Stop-Service Browser
   }
}
   
   
   ##################################################################################################################################
   #                                             Function - Set path variable for Git
   ##################################################################################################################################
Function Set-GitPath {
   $currentPath = (Get-ItemProperty -Path 'Registry::HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Session Manager\Environment' -Name PATH).Path
   $newPath = $currentPath + ";C:\Program Files (x86)\Git\bin\"
   Set-ItemProperty -Path 'Registry::HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Session Manager\Environment' -Name PATH -Value $newPath
}
   
Function Install-TempDSC {
   if((Get-rsRole -Value $env:COMPUTERNAME) -eq "Pull") {
      Write-EventLog -LogName DevOps -Source BasePrep -EntryType Information -EventId 1000 -Message "Installing inital temporary DSC configuration C:\DevOps\rsProvisioning\initDSC.ps1"
      try{
         Invoke-Expression "C:\DevOps\rsProvisioning\initDSC.ps1"
      }
      catch {
         Write-EventLog -LogName DevOps -Source BasePrep -EntryType Error -EventId 1002 -Message "Error initDSC.ps1`n$($_.Exception.message)"
      }
      Write-EventLog -LogName DevOps -Source BasePrep -EntryType Information -EventId 1000 -Message "Temporary DSC intallation complete"
   }
}
   
   ##################################################################################################################################
   #                                             Function - Install DSC (all nodes)
   ##################################################################################################################################
Function Install-DSC {
   Write-EventLog -LogName DevOps -Source BasePrep -EntryType Information -EventId 1000 -Message "Installing LCM"
   try{
      Invoke-Expression "C:\DevOps\rsProvisioning\rsLCM.ps1"
   }
   catch {
      Write-EventLog -LogName DevOps -Source BasePrep -EntryType Error -EventId 1002 -Message "Error in rsLCM.ps1`n$($_.Exception.message)"
   }
   if((Get-rsRole -Value $env:COMPUTERNAME) -ne "Pull") {
      powershell.exe certutil -addstore -f root $("C:\DevOps", $d.mR, "Certificates\PullServer.crt" -join '\')      
      $i = 0
      do {
         $StartConsistency = $false
         $Pending = Test-Path "C:\Windows\System32\Configuration\Pending.mof"
         $ConsistencyRunning = (Get-ScheduledTask -TaskName Consistency).State -eq "Running"
         if ( $((Get-WinEvent Microsoft-Windows-DSC/Operational | Select -First 1).id) -eq "4104" -or 
              ($Pending -and (-not $ConsistencyRunning))) {
            Get-ScheduledTask -TaskName "Consistency" | Start-ScheduledTask
            if ($Pending -and (-not $ConsistencyRunning)) 
            {
               $StartConsistency = $true
            }
         }
         if($i -gt 5 -or $StartConsistency) {
            $Message = "Waiting for Client to install DSC configuration"
            if ($StartConsistency)
            {
               $Message += "`nFound Pending.mof and Consistency task not running and therefore started Consistency Task"               
            }
            Write-EventLog -LogName DevOps -Source BasePrep -EntryType Information -EventId 1000 -Message $Message
            $i = 0
         }
         $i++
         Start-Sleep -Seconds 10
      }
      while (!(Test-Path -Path "C:\Windows\System32\Configuration\Current.mof"))
      Set-MSN -Enabled $true
   }
   Write-EventLog -LogName DevOps -Source BasePrep -EntryType Information -EventId 1000 -Message "LCM installation complete"
   ### Pullserver specific tasks, install WindowsFeature Web-Service, install SSL certificates then run rsPullServer.ps1 to install DSC
   if((Get-rsRole -Value $env:COMPUTERNAME) -eq "Pull") {
      Set-rsHash -file $("C:\DevOps", $d.mR, "rsPullServer.ps1" -join '\') -hash "C:\DevOps\rsPullServer.hash"
      Write-EventLog -LogName DevOps -Source BasePrep -EntryType Information -EventId 1000 -Message "Installing WindowsFeature Web-Server"
      Install-WindowsFeature Web-Server
      Write-EventLog -LogName DevOps -Source BasePrep -EntryType Information -EventId 1000 -Message "IIS installation Complete."
      ### Install SSL certificates on pullserver
      Install-rsCertificates
      ### Copy required files for PSDDesiredStateCofngiuration website
      if((Test-Path -Path "C:\Windows\System32\WindowsPowerShell\v1.0\Modules\PSDesiredStateConfiguration\PullServer\bin") -eq $false) {
         New-Item -ItemType directory -Path "C:\Windows\System32\WindowsPowerShell\v1.0\Modules\PSDesiredStateConfiguration\PullServer\bin"
      }
      if((test-path -Path "C:\Windows\System32\WindowsPowerShell\v1.0\Modules\PSDesiredStateConfiguration\PullServer\bin\Microsoft.Powershell.DesiredStateConfiguration.Service.dll") -eq $false) {
         Copy-Item "C:\Windows\System32\WindowsPowerShell\v1.0\Modules\PSDesiredStateConfiguration\PullServer\Microsoft.Powershell.DesiredStateConfiguration.Service.dll" -Destination "C:\Windows\System32\WindowsPowerShell\v1.0\Modules\PSDesiredStateConfiguration\PullServer\bin"
      }
      if((Test-Path "C:\Windows\System32\WindowsPowerShell\v1.0\Modules\PSDesiredStateConfiguration\PullServer\web.config") -eq $false) {
         Copy-Item "C:\Windows\System32\WindowsPowerShell\v1.0\Modules\PSDesiredStateConfiguration\PullServer\PSDSCPullServer.config" -Destination "C:\Windows\System32\WindowsPowerShell\v1.0\Modules\PSDesiredStateConfiguration\PullServer\web.config"
      }
      ### Run rsPullServer.ps1 to install DSC on pullserver
      if(Test-Path -Path "C:\Windows\System32\Configuration\Current.mof") {
         Remove-Item -Path "C:\Windows\System32\Configuration\Current.mof" -Recurse -Force
      }
      Invoke-DSC
   }
   return
}
   
   
   ##################################################################################################################################
   #                                             Function - Create reg key to track execution progress in Baseprep
   ##################################################################################################################################
Function Set-Stage {
   param ( [int]$value )
   Write-Log -value "Setting staging key to $value"
   Set-ItemProperty -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\WinDevOps" -Name "BuildScript" -Value $value -Force
   return
}
   
   
   ##################################################################################################################################
   #                                             Function - Create scheduled task to resume BasePrep after reboot
   ##################################################################################################################################
Function Create-ScheduledTask {
   Write-Log -value "Creating BasePrep.ps1 scheduled task"
   schtasks.exe /create /sc Onstart /tn BasePrep /ru System /tr "PowerShell.exe -ExecutionPolicy Bypass -file C:\DevOps\rsProvisioning\rsBasePrep.ps1"
   return
}
   
   
   ##################################################################################################################################
   #                                             Function - Disable TOE on all net adapters
   ##################################################################################################################################
Function Disable-TOE {
   Write-Log -value "disabling TOE"
   if($osVersion -gt 6.2) {
      Disable-NetAdapterChecksumOffload * -TcpIPv4 -UdpIPv4 -IpIPv4 -NoRestart
      Disable-NetAdapterLso * -IPv4 -NoRestart
      if(Test-rsCloud) {
         Set-NetAdapterAdvancedProperty * -DisplayName "Large Receive Offload (IPv4)" -DisplayValue Disabled –NoRestart
      }
      Restart-NetAdapter *
      return
   }
   if($osVersion -lt 6.2) {
      $root = 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Class\{4D36E972-E325-11CE-BFC1-08002BE10318}'
      $items = Get-ChildItem -Path Registry::$Root -Name
      Foreach ($item in $items) {
         if ($item -ne "Properties") {
            $path = $root + "\" + $item
            $DriverDesc = Get-ItemProperty -Path Registry::$path | Select-Object -expandproperty DriverDesc
            if ($DriverDesc -like "Citrix PV*") {
               Set-ItemProperty -path Registry::$path -Name *IPChecksumOffloadIPv4 -Value 0
               Set-ItemProperty -path Registry::$path -Name *TCPChecksumOffloadIPv4 -Value 0
               Set-ItemProperty -path Registry::$path -Name *UDPChecksumOffloadIPv4 -Value 0
               Set-ItemProperty -path Registry::$path -Name *LsoV2IPv4 -Value 0
               Set-ItemProperty -path Registry::$path -Name LROIPv4 -Value 0
            }
         }
      }
      $adaptors = Get-WmiObject -Class Win32_NetworkAdapter | Where-Object {$_.Name -like "Citrix*"}
      Foreach ($adaptor in $adaptors) {
         $adaptor.Disable()
         $adaptor.Enable()
      }
   }
   return
}
   
   ##################################################################################################################################
   #                                             Function - Install .NET 4.5 (if needed)
   ##################################################################################################################################
Function Install-Net45 {
   if($netVersion -lt 4.5) {
      if((Test-Path -PathType Container -Path "C:\DevOps\net45_InstallDir") -eq $false) {
         New-Item $("C:\DevOps", "net45_InstallDir" -join '\') -ItemType Directory -Force
      }
      Write-Log -value "Installing .NET 4.5"
      Get-rsFile -path "C:\DevOps", "net45_InstallDir\dotNetFx45_Full_setup.exe" -url "http://download.microsoft.com/download/B/A/4/BA4A7E71-2906-4B2D-A0E1-80CF16844F5F/dotNetFx45_Full_setup.exe"
      Start -Wait -NoNewWindow "C:\DevOps\dotNetFx45_Full_setup.exe" -ArgumentList '/q /norestart'
   }
   return
}
   
   
   ##################################################################################################################################
   #                                             Function - Install WMF4 (if needed)
   ##################################################################################################################################
Function Install-WMF4 {
   if($osVersion -lt 6.2 -and $wmfVersion -lt 4) {
      if((Test-Path -PathType Container -Path "C:\DevOps\wmf4_InstallDir") -eq $false) {
         Write-Log -value "creating directory C:\DevOps\wmf4_InstallDir"
         New-Item "C:\DevOps\wmf4_InstallDir" -ItemType Directory -Force
      }
      Write-Log -value "Installing WMF 4 on 2k8"
      Get-rsFile -path "C:\DevOps\wmf4_InstallDir\Windows6.1-KB2819745-x64-MultiPkg.msu" -url "http://download.microsoft.com/download/3/D/6/3D61D262-8549-4769-A660-230B67E15B25/Windows6.1-KB2819745-x64-MultiPkg.msu"
      Start -Wait -NoNewWindow "C:\DevOps\wmf4_InstallDir\Windows6.1-KB2819745-x64-MultiPkg.msu" -ArgumentList '/quiet'
      return
   }
   if($osVersion -gt 6.2 -and $wmfVersion -lt 4) {
      if((Test-Path -PathType Container -Path "C:\DevOps\wmf4_InstallDir") -eq $false) {
         Write-Log -value "creating directory C:\DevOps\wmf4_InstallDir"
         New-Item "C:\DevOps\wmf4_InstallDir" -ItemType Directory -Force
      }
      Write-Log -value "Installing WMF 4 on 2012"
      Get-rsFile -path "C:\DevOps\wmf4_InstallDir\Windows8-RT-KB2799888-x64.msu" -url "http://download.microsoft.com/download/3/D/6/3D61D262-8549-4769-A660-230B67E15B25/Windows8-RT-KB2799888-x64.msu"
      Start -Wait -NoNewWindow "C:\DevOps\wmf4_InstallDir\Windows8-RT-KB2799888-x64.msu" -ArgumentList '/quiet'
      return
   }
}
   
   
   
   ##################################################################################################################################
   #                                             Function - Format D Drive (perf cloud servers)
   ##################################################################################################################################
Function Set-DataDrive {
   if(Test-rsCloud) {
      Write-Log -value "Formatting D: drive"
      $partitions = gwmi Win32_DiskPartition
      $scriptdisk = $Null
      $script = $Null
      foreach ($part in $partitions){
         if ($part.Type -eq "Unknown"){
            $drivenumber = $part.DiskIndex
            $script = "select disk {0}`nattributes disk clear readonly noerr`nonline disk noerr`nclean`nattributes disk clear readonly noerr`ncreate partition primary noerr`nformat quick`n" -f $drivenumber
         }
         $drivenumber = $Null
         $scriptdisk += $script + "`n"
         $script = $Null
      }
      $scriptdisk | diskpart
      $volumes = gwmi Win32_volume | where {$_.BootVolume -ne $True -and $_.SystemVolume -ne $True -and $_.DriveType -eq "3"}
      $letters = 68..89 | ForEach-Object { ([char]$_)+":" }
      $freeletters = $letters | Where-Object { (New-Object System.IO.DriveInfo($_)).DriveType -eq 'NoRootDirectory' }
      foreach ($volume in $volumes){
         if ($volume.DriveLetter -eq $Null){
            mountvol $freeletters[0] $volume.DeviceID
         }
         $freeletters = $letters | Where-Object { (New-Object System.IO.DriveInfo($_)).DriveType -eq 'NoRootDirectory' }
      }
      return
   }
}
   
   
   ##################################################################################################################################
   #                                             Function - Update Xen Client Tools (if needed)
   ##################################################################################################################################
Function Update-XenTools {
   [System.Reflection.Assembly]::LoadWithPartialName("System.IO.Compression.FileSystem") | Out-Null
   $destination = "C:\DevOps\"
   if ( $osVersion -lt "6.2" ) {
      $path = "C:\DevOps\nova_agent_1.2.7.0.zip"
      Get-rsFile -url "http://cc527d412bd9bc2637b1-054807a7b8a5f81313db845a72a4785e.r34.cf1.rackcdn.com/nova_agent_1.2.7.0.zip" -path $path
      [System.IO.Compression.ZipFile]::ExtractToDirectory($path, $destination)
      Get-Service -DisplayName "Rackspace Cloud Servers*" | Stop-Service -Verbose
      Copy-Item "C:\DevOps\Cloud Servers\*" "C:\Program Files\Rackspace\Cloud Servers\" -recurse -force
      Remove-Item "C:\DevOps\Cloud Servers" -Force -Recurse
   }
   if($osVersion -lt "6.3") {
      
      $path = "C:\DevOps\xs-tools-6.2.0.zip"
      try{
         Get-rsFile -url "http://cc527d412bd9bc2637b1-054807a7b8a5f81313db845a72a4785e.r34.cf1.rackcdn.com/xs-tools-6.2.0.zip" -path $path
      }
      catch {
         Write-EventLog -LogName DevOps -Source BasePrep -EntryType Error -EventId 1002 -Message "Failed to Download Xentools. `n $($_.Exception.Message)"
      }
      [System.IO.Compression.ZipFile]::ExtractToDirectory($path, "$destination\xs-tools-6.2.0\")
      Write-Log -value "Installing Xen Tools 6.2"
      Start -Wait "C:\DevOps\xs-tools-6.2.0\installwizard.msi" -ArgumentList '/qn PATH="C:\Program Files\Citrix\XenTools\"'
      Write-EventLog -LogName DevOps -Source BasePrep -EntryType Information -EventId 1000 -Message "XenTools installation complete."
   }
   if($osVersion -gt "6.3") {
      Write-EventLog -LogName DevOps -Source BasePrep -EntryType Information -EventId 1000 -Message "OS version is $osVersion. No XenTools installation needed."
      ### If osversion 2012 R2 no xentools install needed and no reboot needed, setting stage to 3 and returning to start stage 3
      Set-Stage -value 3
      Restart-Computer -Force
   }
   return
}
   
   
   ##################################################################################################################################
   #                                             Function - Add pull server info to HOSTS file
   ##################################################################################################################################
Function Update-HostFile {
   . "$("C:\DevOps", $d.mR, "PullServerInfo.ps1" -join '\')"
   $pullServerRegion = $pullServerInfo.region
   $pullServerName = $pullServerInfo.pullServerName
   $pullServerPublicIP = $pullserverInfo.pullserverPublicIp
   $pullServerPrivateIP = $pullServerInfo.pullServerPrivateIp
   if((Get-rsRole -Value $env:COMPUTERNAME) -eq "pull") {
      $hostContent = ((Get-NetAdapter | Where-Object status -eq 'up' | Get-NetIPAddress -ea 0 | Where-Object IPAddress -like '10.*').IPAddress + "`t`t`t" + $env:COMPUTERNAME)
      Add-Content -Path "C:\Windows\System32\Drivers\etc\hosts" -Value $hostContent -Force
      Write-EventLog -LogName DevOps -Source BasePrep -EntryType Information -EventId 1000 -Message "Adding $hostContent to PullServer Hosts File"
      return
   }
   else {
      if($pullServerRegion -ne (Get-rsRegion -Value $env:COMPUTERNAME)) {
         $pullServerIP = $pullServerPublicIP
      }
      else {
         $pullServerIP = $pullServerPrivateIP
      }
      $hostContent = $pullServerIP + "`t`t`t" + $pullServerName
      Add-Content -Path "C:\Windows\System32\Drivers\etc\hosts" -Value $hostContent -Force
      Write-EventLog -LogName DevOps -Source BasePrep -EntryType Information -EventId 1000 -Message "PullServerRegion $pullServerRegion`nServerRegion $(Get-rsRegion -Value $env:COMPUTERNAME)"
      Write-EventLog -LogName DevOps -Source BasePrep -EntryType Information -EventId 1000 -Message "Adding $hostContent to HostsFile"
      $hostContent = ((Get-NetAdapter | Where-Object status -eq 'up' | Get-NetIPAddress -ea 0 | Where-Object IPAddress -like '10.*').IPAddress + "`t`t`t" + $env:COMPUTERNAME)
      Add-Content -Path "C:\Windows\System32\Drivers\etc\hosts" -Value $hostContent -Force
      Write-EventLog -LogName DevOps -Source BasePrep -EntryType Information -EventId 1000 -Message "Adding $hostContent to HostsFile"
      return
   }
}
   
   
   ##################################################################################################################################
   #                                             Function - Cleanup secrets file
   ##################################################################################################################################
Function Clean-Up {
   if(Test-Path -Path "C:\DevOps\xs-tools-6.2.0") { Remove-Item "C:\DevOps\xs-tools-6.2.0" -Recurse -Force }
   if(Test-Path -Path "C:\DevOps\xs-tools-6.2.0.zip") { Remove-Item "C:\DevOps\xs-tools-6.2.0.zip" -Recurse -Force }
   if(Test-Path -Path "C:\DevOps\Git-Windows-Latest.exe") { Remove-Item "C:\DevOps\Git-Windows-Latest.exe" -Recurse -Force }
   schtasks.exe /Delete /TN BasePrep /F
}
   
   
   ##################################################################################################################################
   #                                             Setting Script Wide Variables
   ##################################################################################################################################
   
if((Test-Path -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\WinDevOps") -eq $false) {
   New-Item -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE" -Name "WinDevOps" -Force
   Set-ItemProperty -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\WinDevOps" -Name "BuildScript" -Value 1 -Force
}
   $stage = (Get-ItemProperty -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\WinDevOps").BuildScript
   $role = Get-rsRole -Value $env:COMPUTERNAME
   $osVersion = (Get-WmiObject -class Win32_OperatingSystem).Version
   $currentDate = (get-date).tostring("mm_dd_yyyy-hh_mm_s")
   $wmfVersion = $PSVersionTable.PSVersion.Major
   $netVersion = (Get-ItemProperty -Path "hklm:\SOFTWARE\Microsoft\NET Framework Setup\NDP\v4\Full").Version
   ##################################################################################################################################
   
   
   ##################################################################################################################################
   #                                             Script Stages Starts Here
   ##################################################################################################################################
   
   
   
switch ($stage) {
   
   1
   {
      Set-Service Browser -StartupType Manual
      Test-rsRackConnect
      Test-rsManaged
      Load-Globals
      Write-Log -value "Starting Stage 1"
      Set-GitPath
      Update-rsGitConfig -scope system -attribute user.email -value $env:COMPUTERNAME@localhost.local
      Update-rsGitConfig -scope system -attribute user.name -value $env:COMPUTERNAME
      Load-Globals
      Disable-TOE
      Create-ScheduledTask
      Install-Net45
      Install-WMF4
      New-NetFirewallRule -DisplayName "WINRM" -Direction Inbound -Action Allow -Protocol TCP -LocalPort 5985-5986
      Set-Item WSMan:\localhost\Client\TrustedHosts * -force
      Set-Stage -value 2
      Restart-Computer -Force
   }
   
   2
   {
      Load-Globals
      Set-Stage -value 3
      Update-XenTools
   }
   3
   {
      Load-Globals
      Set-MSN -Enabled $false
      Disable-TOE
      Set-DataDrive
      Install-TempDSC
      Create-PullServerInfo
      Update-HostFile
      Install-DSC
      Set-Stage -value 4
      Restart-Computer -Force
   }
   4
   {
      Clean-Up
      Break
   }
   default
   {
      Break
   }
}
