Set-ExecutionPolicy -ExecutionPolicy Bypass -Force
if([System.Diagnostics.EventLog]::SourceExists('BasePrep')) {
}
else {
   New-EventLog -LogName "DevOps" -Source BasePrep
}
Import-Module rsCommon
. (Get-rsSecrets)
if(Test-Path -Path "C:\DevOps\dedicated.csv") {
   $DedicatedData = Import-Csv -Path "C:\DevOps\dedicated.csv"
}
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
         if(($Global:catalog.access.user.roles | ? name -eq "rack_connect").id.count -gt 0) { $Global:isRackConnect = $true } else { $Global:isRackConnect = $false } 
         if(($Global:catalog.access.user.roles | ? name -eq "rax_managed").id.count -gt 0) { $Global:isManaged = $true } else { $Global:isManaged = $false } 
      }
      else {
         $Global:defaultRegion = (Get-rsDedicatedInfo | ? {$_.name -eq $env:COMPUTERNAME}).defaultRegion
         $Global:isRackConnect = (Get-rsDedicatedInfo | ? {$_.name -eq $env:COMPUTERNAME}).isRackConnect
         $Global:isManaged = $true
      }
      $Global:pullServerName = $env:COMPUTERNAME
      $Global:pullServerPublicIP = Get-rsAccessIPv4
      $Global:pullServerPrivateIP = (Get-NetAdapter | ? status -eq 'up' | Get-NetIPAddress -ea 0 | ? IPAddress -match '^10\.').IPAddress
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
Function Disable-MSN {
   Write-EventLog -LogName DevOps -Source BasePrep -EntryType Information -EventId 1000 -Message "Disabling MSN on all adapters"
   (Get-NetAdapter).Name | % {Set-NetAdapterBinding -Name $_ -DisplayName "Client for Microsoft Networks" -Enabled $false}
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
      if(Test-rsCloud){
         Add-Content -Path $path -Value "`"region`" = `$$(Get-rsRegion -Value $env:COMPUTERNAME)"
      }
      else {
         Add-Content -Path $path -Value "`"region`" = `"$(Get-rsRegion -Value $env:COMPUTERNAME)""
      }
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
      Start -Wait "C:\Program Files (x86)\Git\bin\git.exe" -ArgumentList "pull origin $($d.branch_rsConfigs)"
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
      Invoke-Command -ScriptBlock {Start -Wait -NoNewWindow PowerShell.exe "C:\DevOps\rsProvisioning\initDSC.ps1"} -ArgumentList "-ExecutionPolicy Bypass -Force"
      Write-EventLog -LogName DevOps -Source BasePrep -EntryType Information -EventId 1000 -Message "Temporary DSC intallation complete"
   }
}
##################################################################################################################################
#                                             Function - Download rsGit Move & Run rsPlatform (pull server)
##################################################################################################################################
Function Get-TempPullDSC {
   if($role -eq "Pull") {
      Start-Service Browser
      $isDone = $false
      $timeOut = 0
      do {
         if($timeOut -ge 10) { 
            Write-EventLog -LogName DevOps -Source BasePrep -EntryType Error -EventId 1002 -Message "Retry threshold reached, stopping retry loop."
            break 
         }
         try {
            chdir "C:\Program Files\WindowsPowerShell\Modules\"
            Write-EventLog -LogName DevOps -Source BasePrep -EntryType Information -EventId 1000 -Message "Cloning https://github.com/rsWinAutomationSupport/rsGit.git"
            #### Temporary changed to forked rsGit for testing
            #Start -Wait "C:\Program Files (x86)\Git\bin\git.exe" -ArgumentList "clone  $("https://github.com", $d.gMO, "rsGit.git" -join '/')"
            ####
            #Start -Wait "C:\Program Files (x86)\Git\bin\git.exe" -ArgumentList "clone  https://github.com/rsWinAutomationSupport/rsGit.git"
            Start -Wait "C:\Program Files (x86)\Git\bin\git.exe" -ArgumentList "clone --branch $($d.ProvBr) $("https://github.com", $d.git_username, "rsGit.git" -join '/')"
            if(Test-Path -Path "C:\Program Files\WindowsPowerShell\Modules\rsGit") {
               $isDone = $true
            }
            else {
               Write-EventLog -LogName DevOps -Source BasePrep -EntryType Warning -EventId 1000 -Message "Failed to clone https://github.com/rsWinAutomationSupport/rsGit.git, sleeping for 5 seconds then trying again. `n $($_.Exception.Message)"
               $timeOut += 1
               Start-Sleep -Seconds 5
            }
         }
         catch {
            Write-EventLog -LogName DevOps -Source BasePrep -EntryType Warning -EventId 1000 -Message "Failed to clone https://github.com/rsWinAutomationSupport/rsGit.git, sleeping for 5 seconds then trying again. `n $($_.Exception.Message)"
            $timeOut += 1
            Start-Sleep -Seconds 5
         }
      }
      while ($isDone -eq $false)
      
      $isDone = $false
      $timeOut = 0
      do {
         if($timeOut -ge 10) { 
            Write-EventLog -LogName DevOps -Source BasePrep -EntryType Error -EventId 1002 -Message "Retry threshold reached, stopping retry loop."
            break 
         }
         try {
            chdir "C:\DevOps"
            Write-EventLog -LogName DevOps -Source BasePrep -EntryType Information -EventId 1000 -Message "Cloning $(("git@github.com:", $d.git_username -join ''), ($($d.mR), ".git" -join '') -join '/')"
            Start -Wait "C:\Program Files (x86)\Git\bin\git.exe" -ArgumentList "clone --branch $($d.branch_rsConfigs) $((('git@github.com:', $($d.git_username) -join ''), ($($d.mR), '.git' -join '')) -join '/')"
            if(Test-Path -Path $("C:\DevOps", $($d.mR) -join '\')) {
               $isDone = $true
            }
            else {
               Write-EventLog -LogName DevOps -Source BasePrep -EntryType Warning -EventId 1000 -Message "Failed to clone $(("git@github.com:", $d.git_username -join ''), ($($d.mR), ".git" -join '') -join '/'), sleeping for 5 seconds then trying again. `n $($_.Exception.Message)"
               $timeOut += 1
            }
         }
         catch {
            Write-EventLog -LogName DevOps -Source BasePrep -EntryType Warning -EventId 1000 -Message "Failed to clone $(("git@github.com:", $d.git_username -join ''), ($($d.mR), ".git" -join '') -join '/'), sleeping for 5 seconds then trying again. `n $($_.Exception.Message)"
            $timeOut += 1
            Start-Sleep -Seconds 5
         }
      }
      while ($isDone -eq $false)
      Stop-Service Browser
      if((Test-Path -Path "C:\Program Files\WindowsPowerShell\DscService\Modules" -PathType Container) -eq $false) {
         New-Item -Path "C:\Program Files\WindowsPowerShell\DscService\Modules" -ItemType Container
      }
      Copy-Item $("C:\DevOps", $d.mR, "rsPlatform" -join '\') "C:\Program Files\WindowsPowerShell\Modules" -Recurse
   }
   else {
      $isDone = $false
      $timeOut = 0
      do {
         if($timeOut -ge 5) { 
            Write-EventLog -LogName DevOps -Source BasePrep -EntryType Error -EventId 1002 -Message "Retry threshold reached, stopping retry loop."
            break 
         }
         try {
            chdir "C:\DevOps"
            Write-EventLog -LogName DevOps -Source BasePrep -EntryType Information -EventId 1000 -Message "Cloning $($d.mR , ".git" -join '') $((("https://", "##REDACTED_GITHUB_APIKEY##", "@github.com" -join ''), $d.git_username, $($d.mR , ".git" -join '')) -join '/')"
            Start -Wait "C:\Program Files (x86)\Git\bin\git.exe" -ArgumentList "clone --branch $($d.branch_rsConfigs) $((("https://", $d.git_Oauthtoken, "@github.com" -join ''), $d.git_username, $($d.mR , ".git" -join '')) -join '/')"
            if(Test-Path -Path $("C:\DevOps", $($d.mR) -join '\')) {
               $isDone = $true
            }
         }
         catch {
            Write-EventLog -LogName DevOps -Source BasePrep -EntryType Warning -EventId 1000 -Message "Failed to Clone $($d.mR , ".git" -join '') $((("https://", "##REDACTED_GITHUB_APIKEY##", "@github.com" -join ''), $d.git_username, $($d.mR , ".git" -join '')) -join '/'), sleeping for 30 seconds then trying again. `n $($_.Exception.Message)"
            $timeOut += 1
            Start-Sleep -Seconds 5
         }
      }
      while ($isDone -eq $false)
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
      Write-EventLog -LogName DevOps -Source BasePrep -EntryType Error -EventId 1002 -Message "Error in LCM`n$($_.Exception.message)"
   }
   if((Get-rsRole -Value $env:COMPUTERNAME) -ne "Pull") {
      $i = 0
      do {
         if ( $((Get-WinEvent Microsoft-Windows-DSC/Operational | Select -First 1).id) -eq "4104" ) {
            Get-ScheduledTask -TaskName "Consistency" | Start-ScheduledTask
         }
         if($i -gt 5) {
            Write-EventLog -LogName DevOps -Source BasePrep -EntryType Information -EventId 1000 -Message "Waiting for Client to install DSC configuration"
            $i = 0
         }
         $i++
         Start-Sleep -Seconds 10
      }
      while (!(Test-Path -Path "C:\Windows\System32\Configuration\Current.mof"))
   }
   Write-EventLog -LogName DevOps -Source BasePrep -EntryType Information -EventId 1000 -Message "LCM installation complete"
   ### Pullserver specific tasks, install WindowsFeature Web-Service, install SSL certificates then run rsPullServer.ps1 to install DSC
   if((Get-rsRole -Value $env:COMPUTERNAME) -eq "Pull") {
      Set-Content -Path $("C:\DevOps", "rsEnvironments.hash" -join '\') -Value (Get-FileHash -Path $("C:\DevOps", $d.mR, "rsPullServer.ps1" -join '\')).hash
      Write-EventLog -LogName DevOps -Source BasePrep -EntryType Information -EventId 1000 -Message "Installing WindowsFeature Web-Server"
      Install-WindowsFeature Web-Server
      Write-EventLog -LogName DevOps -Source BasePrep -EntryType Information -EventId 1000 -Message "IIS installation Complete."
      ### Install SSL certificates on pullserver
      Install-Certs
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
         Remove-Item -Path "C:\Windows\System32\Configuration\Current.mof" -Force
      }
      do {
         Write-EventLog -LogName DevOps -Source BasePrep -EntryType Information -EventId 1000 -Message "Installing DSC $("C:\DevOps", $d.mR, "rsPullServer.ps1" -join '\')"
         taskkill /F /IM WmiPrvSE.exe
         Invoke-Command -ScriptBlock { start -Wait -NoNewWindow PowerShell.exe $("C:\DevOps", $d.mR, "rsPullServer.ps1" -join '\')} -ArgumentList "-ExecutionPolicy Bypass -Force"
      }
      while (!(Test-Path -Path "C:\Windows\System32\Configuration\Current.mof"))
      Write-EventLog -LogName DevOps -Source BasePrep -EntryType Information -EventId 1000 -Message "PullServer DSC installation Complete."
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
#                                             Function - Set .NET machine keys (all nodes - required for webfarm viewstate decryption)
##################################################################################################################################
function Set-MachineKey {
   $netfx = @{
                "1x86" = "C:\WINDOWS\Microsoft.NET\Framework\v1.1.4322\CONFIG\machine.config"
                "2x86" = "C:\WINDOWS\Microsoft.NET\Framework\v2.0.50727\CONFIG\machine.config"
                "4x86" = "C:\WINDOWS\Microsoft.NET\Framework\v4.0.30319\CONFIG\machine.config"
                "2x64" = "C:\WINDOWS\Microsoft.NET\Framework64\v2.0.50727\CONFIG\machine.config"
                "4x64" = "C:\WINDOWS\Microsoft.NET\Framework64\v4.0.30319\CONFIG\machine.config"
                }
   Write-Log -value "Setting Machine Keys"
   foreach ($key in $netfx.Keys) {
      $machineConfig = $netfx[$key]
      if (Test-Path $machineConfig) {
         $xml = [xml](get-content $machineConfig)
         $xml.Save($machineConfig + "_$currentDate")
         $root = $xml.get_DocumentElement()
         $system_web = $root."system.web"
         if ($system_web.machineKey -eq $null) {
            $machineKey = $xml.CreateElement("machineKey")
            $a = $system_web.AppendChild($machineKey)
         }
         $system_web.SelectSingleNode("machineKey").SetAttribute("validationKey","$validationKey")
         $system_web.SelectSingleNode("machineKey").SetAttribute("decryptionKey","$decryptionKey")
         $a = $xml.Save($machineConfig)
      }
   }
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
         Get-rsFile -url "http://1631170f67e7daa50e95-7dd27d3f3410187707440a293c5d1c09.r5.cf1.rackcdn.com/xs-tools-6.2.0.zip" -path $path
      }
      catch {
         Write-EventLog -LogName DevOps -Source BasePrep -EntryType Error -EventId 1002 -Message "Failed to Download Xentools. `n $($_.Exception.Message)"
      }
      [System.IO.Compression.ZipFile]::ExtractToDirectory($path, $destination)
      Write-Log -value "Installing Xen Tools 6.2"
      Start -Wait "C:\DevOps\xs-tools-6.2.0\installwizard.msi" -ArgumentList '/qn PATH="C:\Program Files\Citrix\XenTools\"'
      Write-EventLog -LogName DevOps -Source BasePrep -EntryType Information -EventId 1000 -Message "XenTools installation complete."
   }
   if($osVersion -gt "6.3") {
      Write-EventLog -LogName DevOps -Source BasePrep -EntryType Information -EventId 1000 -Message "OS verision is $osVersion no XenTools installation needed."
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
      $hostContent = ((Get-NetAdapter | ? status -eq 'up' | Get-NetIPAddress -ea 0 | ? IPAddress -like '10.*').IPAddress + "`t`t`t" + $env:COMPUTERNAME)
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
      Write-EventLog -LogName DevOps -Source BasePrep -EntryType Information -EventId 1000 -Message "PullServerRegion $pullServerRegion ServerRegion $(Get-rsRegion -Value $env:COMPUTERNAME)"
      Write-EventLog -LogName DevOps -Source BasePrep -EntryType Information -EventId 1000 -Message "Adding $hostContent to HostsFile"
      $hostContent = ((Get-NetAdapter | ? status -eq 'up' | Get-NetIPAddress -ea 0 | ? IPAddress -like '10.*').IPAddress + "`t`t`t" + $env:COMPUTERNAME)
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
      Disable-MSN
      Test-rsRackConnect
      Test-rsManaged
      Load-Globals
      Write-Log -value "Starting Stage 1"
      Set-GitPath
      Update-rsKnownHostsFile
      New-rsSSHKey
      Push-rsSSHKey
      Update-rsGitConfig -scope system -attribute user.email -value $env:COMPUTERNAME@localhost.local
      Update-rsGitConfig -scope system -attribute user.name -value $env:COMPUTERNAME
      Get-TempPullDSC
      Load-Globals
      Disable-TOE
      tzutil /s "Central Standard Time"
      Create-ScheduledTask
      Install-Net45
      Install-WMF4
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
      Disable-MSN
      Disable-TOE
      Set-DataDrive
      New-NetFirewallRule -DisplayName "WINRM" -Direction Inbound -Action Allow -Protocol TCP -LocalPort 5985-5986
      set-item WSMan:\localhost\Client\TrustedHosts * -force
      Install-TempDSC
      Create-PullServerInfo
      Update-HostFile
      Install-rsCertificates
      Install-DSC
      Set-Stage -value 4
      Restart-Computer -Force
   }
   4
   {
      Load-Globals
      Clean-Up
      Break
   }
   
   default
   {
      Break
   }
}