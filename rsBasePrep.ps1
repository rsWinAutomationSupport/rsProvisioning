Set-ExecutionPolicy -ExecutionPolicy Bypass -Force

##################################################################################################################################
#                                             Start Script Functions
##################################################################################################################################


##################################################################################################################################
#                                             Function - Write Event Log Entries
##################################################################################################################################
Function Write-Log {
   param([string]$value)
   $timeStamp = (get-date).ToString()
   Write-EventLog -LogName DevOps -Source BasePrep -EntryType Information -EventId 1000 -Message ($timeStamp + ":`t" + $value)
   return
}


##################################################################################################################################
#                                             Function - Create custom Event Log for DevOps Automation
##################################################################################################################################
Function Create-Log {
   $logSources = @(
    "BasePrep", "LCM", "Verify", "PullServerDSC", "HostsFile", "rsIEEsc", "rsUAC", "RS_rsADDomain", "RS_rsADDomainController", "RS_rsADUser", "RS_rsCloudServersOpenStack", "RS_rsCluster", "RS_rsComputer",
     "RS_rsDatabase", "RS_rsDBPackage", "RS_rsDNSServerAddress", "RS_rsFirewall", "RS_rsFTP", "RS_rsGit", "RS_rsGitSSHKey", "RS_rsIISAuth", "RS_rsIPAddress", "RS_rsPullServerMonitor", "RS_rsScheduledTask",
      "RS_rsSmbShare", "RS_rsSMTP", "RS_rsSSHKnownHosts", "RS_rsWaitForADDomain", "RS_rsWaitForCluster", "RS_rsWebApplication", "RS_rsWebAppPool", "RS_rsWebConfigKeyValue", "RS_rsWebsite",
      "RS_rsWebVirtualDirectory", "RS_rsWPI", "RS_rsCloudLoadBalancers", "RS_rsRaxMon", "RS_rsClientMofs"
    )
   if((Get-EventLog -List).Log -notcontains "DevOps") {
      foreach($logSource in $logSources) {
         New-EventLog -LogName "DevOps" -Source $logSource
      }
   }
}


##################################################################################################################################
#                                             Function - Download files
##################################################################################################################################
Function Download-File {
   param ( [string]$url, [string]$path )
   $webclient = New-Object System.Net.WebClient
   $webclient.DownloadFile($url,$path)
   Write-Log -value "Downloading $url"
   return
}


##################################################################################################################################
#                                             Function - Generate Secrets file for Clients
##################################################################################################################################
Function Create-ClientData {
   if($role -eq "Pull") {
      $path = "C:\cloud-automation\secrets"
      Add-Content -Value "`$d = @{" -Path $path
      Add-Content -Value "`"br`" = `"$($d.br)`"" -Path $path
      Add-Content -Value "`"wD`" = `"$($d.wD)`"" -Path $path
      Add-Content -Value "`"mR`" = `"$($d.mR)`"" -Path $path
      Add-Content -Value "`"prov`" = `"$($d.prov)`"" -Path $path
      Add-Content -Value "`"bS`" = `"$($d.bS)`"" -Path $path
      Add-Content -Value "`"gS`" = `"$($d.gS)`"" -Path $path
      Add-Content -Value "`"gPath`" = `"$($d.gPath)`"" -Path $path
      Add-Content -Value "`"gX`" = `"$($d.gX)`"" -Path $path
      Add-Content -Value "`"gCA`" = `"$($d.gCA)`"" -Path $path
      Add-Content -Value "`"gAPI`" = `"$($d.gAPI)`"" -Path $path
      Add-Content -Value "`"gMO`" = `"$($d.gMO)`"" -Path $path
      Add-Content -Value "}" -Path $path
   }
}


##################################################################################################################################
#                                             Function - Disable Client For Microsoft Networks
##################################################################################################################################
Function Disable-MSN {
   (Get-NetAdapter).Name | % {Set-NetAdapterBinding -Name $_ -DisplayName "Client for Microsoft Networks" -Enabled $false}
   return
}


##################################################################################################################################
#                                             Function - Retrieve server role from XenStore WMI metadata
##################################################################################################################################
Function Get-Role {
   $base = gwmi -n root\wmi -cl CitrixXenStoreBase
   $sid = $base.AddSession("MyNewSession")
   $session = gwmi -n root\wmi -q "select * from CitrixXenStoreSession where SessionId=$($sid.SessionId)"
   $role = $session.GetValue("vm-data/user-metadata/Role").value -replace "`"", ""
   return $role
}


##################################################################################################################################
#                                             Function - Retrieve server region from XenStore WMI
##################################################################################################################################
Function Get-Region {
   $base = gwmi -n root\wmi -cl CitrixXenStoreBase
   $sid = $base.AddSession("MyNewSession")
   $session = gwmi -n root\wmi -q "select * from CitrixXenStoreSession where SessionId=$($sid.SessionId)"
   $region = $session.GetValue("vm-data/provider_data/region").value -replace "`"", ""
   return $region
}


##################################################################################################################################
#                                             Function - Add Github SSH keys to known hosts(all nodes). Generate server SSH key and add to Github account(pull server)
##################################################################################################################################
Function Create-SshKey {
   set-service Browser -StartupType Manual
   Start-Service Browser
   $sshPaths = @("C:\Program Files (x86)\Git\.ssh", "C:\Windows\SysWOW64\config\systemprofile\.ssh", "C:\Windows\System32\config\systemprofile\.ssh")
   foreach($sshPath in $sshPaths) {
      if(!(Test-Path -Path $sshPath)) {
         try {
            New-Item -Path $sshPath -ItemType container
         }
         catch {
            Write-EventLog -LogName DevOps -Source BasePrep -EntryType Error -EventId 1002 -Message "Failed to create directory $sshPath `n $($_.Execption.Message)"
         }
      }
      New-Item $($sshPath, "known_hosts" -join '\') -ItemType File -Force
      Add-Content $($sshPath, "known_hosts" -join '\') -Value "github.com,192.30.252.129 ssh-rsa AAAAB3NzaC1yc2EAAAABIwAAAQEAq2A7hRGmdnm9tUDbO9IDSwBK6TbQa+PXYPCPy6rbTrTtw7PHkccKrpp0yVhp5HdEIcKr6pLlVDBfOLX9QUsyCOV0wzfjIJNlGEYsdlLJizHhbn2mUjvSAHQqZETYP81eFzLQNnPHt4EVVUh7VfDESU84KezmD5QlWpXLmvU31/yMf+Se8xhHTvKSCZIFImWwoG6mbUoWf9nzpIoaSjB+weqqUUmpaaasXVal72J+UX2B+2RPW3RcT0eOzQgqlJL3RKrTJvdsjE3JEAvGq3lGHSZXy28G3skua2SmVi/w4yCE6gbODqnTWlg7+wC604ydGXA8VJiS5ap43JXiUFFAaQ=="
      Add-Content $($sshPath, "known_hosts" -join '\') -Value "192.30.252.128 ssh-rsa AAAAB3NzaC1yc2EAAAABIwAAAQEAq2A7hRGmdnm9tUDbO9IDSwBK6TbQa+PXYPCPy6rbTrTtw7PHkccKrpp0yVhp5HdEIcKr6pLlVDBfOLX9QUsyCOV0wzfjIJNlGEYsdlLJizHhbn2mUjvSAHQqZETYP81eFzLQNnPHt4EVVUh7VfDESU84KezmD5QlWpXLmvU31/yMf+Se8xhHTvKSCZIFImWwoG6mbUoWf9nzpIoaSjB+weqqUUmpaaasXVal72J+UX2B+2RPW3RcT0eOzQgqlJL3RKrTJvdsjE3JEAvGq3lGHSZXy28G3skua2SmVi/w4yCE6gbODqnTWlg7+wC604ydGXA8VJiS5ap43JXiUFFAaQ=="
      Add-Content $($sshPath, "known_hosts" -join '\') -Value "192.30.252.131 ssh-rsa AAAAB3NzaC1yc2EAAAABIwAAAQEAq2A7hRGmdnm9tUDbO9IDSwBK6TbQa+PXYPCPy6rbTrTtw7PHkccKrpp0yVhp5HdEIcKr6pLlVDBfOLX9QUsyCOV0wzfjIJNlGEYsdlLJizHhbn2mUjvSAHQqZETYP81eFzLQNnPHt4EVVUh7VfDESU84KezmD5QlWpXLmvU31/yMf+Se8xhHTvKSCZIFImWwoG6mbUoWf9nzpIoaSjB+weqqUUmpaaasXVal72J+UX2B+2RPW3RcT0eOzQgqlJL3RKrTJvdsjE3JEAvGq3lGHSZXy28G3skua2SmVi/w4yCE6gbODqnTWlg7+wC604ydGXA8VJiS5ap43JXiUFFAaQ=="
      Add-Content $($sshPath, "known_hosts" -join '\') -Value "192.30.252.130 ssh-rsa AAAAB3NzaC1yc2EAAAABIwAAAQEAq2A7hRGmdnm9tUDbO9IDSwBK6TbQa+PXYPCPy6rbTrTtw7PHkccKrpp0yVhp5HdEIcKr6pLlVDBfOLX9QUsyCOV0wzfjIJNlGEYsdlLJizHhbn2mUjvSAHQqZETYP81eFzLQNnPHt4EVVUh7VfDESU84KezmD5QlWpXLmvU31/yMf+Se8xhHTvKSCZIFImWwoG6mbUoWf9nzpIoaSjB+weqqUUmpaaasXVal72J+UX2B+2RPW3RcT0eOzQgqlJL3RKrTJvdsjE3JEAvGq3lGHSZXy28G3skua2SmVi/w4yCE6gbODqnTWlg7+wC604ydGXA8VJiS5ap43JXiUFFAaQ=="
   }
   Remove-Item "C:\Program Files (x86)\Git\.ssh\id_rsa*"
   if($role -eq "Pull") {
      # Creates Pull Server ssh key and pushes to GitHub account C:\Program Files (x86)\Git\.ssh
      Write-EventLog -LogName DevOps -Source BasePrep -EntryType Information -EventId 1000 -Message "Generating ssh Key"
      try {
         Start -Wait -NoNewWindow "C:\Program Files (x86)\Git\bin\ssh-keygen.exe" -ArgumentList "-t rsa -f 'C:\Program Files (x86)\Git\.ssh\id_rsa' -P """""
      }
      catch {
         Write-EventLog -LogName DevOps -Source BasePrep -EntryType Error -EventId 1002 -Message "Failed to generate SSH Key `n $($_.Exception.Message)"
      }
      $keys = Invoke-RestMethod -Uri "https://api.github.com/user/keys" -Headers @{"Authorization" = "token $($d.gAPI)"} -ContentType application/json -Method GET
      $pullKeys = $keys | ? title -eq $($d.DDI + "_" + $pullServerName)
      foreach($pullKey in $pullKeys) {
         Invoke-RestMethod -Uri $("https://api.github.com/user/keys/" + $pullKey.id) -Headers @{"Authorization" = "token $($d.gAPI)"} -ContentType application/json -Method DELETE
      }
      $sshKey = Get-Content -Path "C:\Program Files (x86)\Git\.ssh\id_rsa.pub"
      $json = @{"title" = "$($d.DDI + "_" + $env:COMPUTERNAME)"; "key" = "$sshKey"} | ConvertTo-Json
      Invoke-RestMethod -Uri "https://api.github.com/user/keys" -Headers @{"Authorization" = "token $($d.gAPI)"} -Body $json -ContentType application/json -Method Post
      Start -Wait "C:\Program Files (x86)\Git\bin\git.exe" -ArgumentList "config --system user.email $serverName@localhost.local"
      Start -Wait "C:\Program Files (x86)\Git\bin\git.exe" -ArgumentList "config --system user.name $serverName"
   }
   Stop-Service Browser
   return
}



##################################################################################################################################
#                                             Function - Edit PullServerInfo.ps1 and push to customer configuration repo
##################################################################################################################################
Function Create-PullServerInfo {
   if($role -eq "Pull") {
      $region = Get-Region
      chdir $($d.wD, $d.mR -join '\')
      $pullServerName = $env:COMPUTERNAME
      $path = $($d.wD + "\" + $d.mR + "\" + "PullServerInfo.ps1")
      if(Test-Path -Path $path) {
         Remove-Item -Path $path -Force
      }
      New-Item -path $path -ItemType file
      Add-Content -Path $path -Value "`$pullServerInfo = @{"
      Add-Content -Path $path -Value "`"pullServerName`" = `"$pullServerName`""
      Add-Content -Path $path -Value "`"pullServerPrivateIp`" = `"$pullServerPrivateIp`""
      Add-Content -Path $path -Value "`"pullServerPublicIp`" = `"$pullServerPublicIp`""
      Add-Content -Path $path -Value "`"region`" = `"$region`""
      Add-Content -Path $path -Value "}"
      Start-Service Browser
      Start -Wait "C:\Program Files (x86)\Git\bin\git.exe" -ArgumentList "add $($d.wD + "\" + $d.mR + "\" + "PullServerInfo.ps1")"
      Start -Wait "C:\Program Files (x86)\Git\bin\git.exe" -ArgumentList "commit -a -m `"$pullServerName pushing PullServerInfo.ps1`""
      Start -Wait "C:\Program Files (x86)\Git\bin\git.exe" -ArgumentList "pull origin $($d.br)"
      Start -Wait "C:\Program Files (x86)\Git\bin\git.exe" -ArgumentList "push origin $($d.br)"
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


##################################################################################################################################
#                                             Function - Download rsGit Move & Run rsPlatform (pull server)
##################################################################################################################################
Function Get-TempPullDSC {
   if($role -eq "Pull") {
      Start-Service Browser
      chdir "C:\Program Files\WindowsPowerShell\Modules\"
      try {
         Start -Wait $gitExe -ArgumentList "clone  $("https://github.com", $d.gMO, "rsGit.git" -join '/')"
         chdir $($d.wD)
         Start -Wait $gitExe -ArgumentList "clone  $("git@github.com:", $d.gCA , $($($d.mR), ".git" -join '') -join '/')"
      }
      catch {
         Write-EventLog -LogName DevOps -Source BasePrep -EntryType Error -EventId 1002 -Message "Failed to Clone $requiredModule `n $($_.Exception.Message)"
      }
      
      Stop-Service Browser
      if((Test-Path -Path "C:\Program Files\WindowsPowerShell\DscService\Modules" -PathType Container) -eq $false) {
         New-Item -Path "C:\Program Files\WindowsPowerShell\DscService\Modules" -ItemType Container
      }
      Copy-Item $($d.wD, $d.mR, "rsPlatform" -join '\') "C:\Program Files\WindowsPowerShell\Modules" -Recurse
      try {
         Invoke-Command -ScriptBlock { PowerShell.exe $($d.wD, $d.prov, "initDSC.ps1" -join '\')} -ArgumentList "-ExecutionPolicy Bypass -Force"
      }
      catch {
         Write-EventLog -LogName DevOps -Source BasePrep -EntryType Error -EventId 1002 -Message "Failed to install temp DSC `n $($_.Exception.Message)"
      }
   }
   else {
      chdir $($d.wD)
      Start -Wait "C:\Program Files (x86)\Git\bin\sh.exe" -ArgumentList "--login -i -c ""$($gitExe) clone $((("https://", $d.gAPI, "@github.com" -join ''), $d.gCA, $($d.mR , ".git" -join '')) -join '/')"""
      #Start -Wait $gitExe -ArgumentList "clone  $((("https://", $d.gAPI, "@github.com" -join ''), $d.gCA, $($d.mR , ".git" -join '')) -join '/') "
   }
} 

##################################################################################################################################
#                                             Function - Install DSC (all nodes)
##################################################################################################################################
Function Install-DSC {
   if($role -eq "Pull") {
      Set-Content -Path $($d.wD, "rsEnvironments.hash" -join '\') -Value (Get-FileHash -Path $($d.wD, $d.mR, "rsEnvironments.ps1" -join '\')).hash
      Install-WindowsFeature Web-Server
      Install-Certs
      Write-Log -value "Installing PullServer LCM"
      Invoke-Command -ScriptBlock { PowerShell.exe $($d.wD, $d.prov, "rsLCM.ps1" -join '\')} -ArgumentList "-ExecutionPolicy Bypass -Force"
      if((Test-Path -Path "C:\Windows\System32\WindowsPowerShell\v1.0\Modules\PSDesiredStateConfiguration\PullServer\bin") -eq $false) {
         New-Item -ItemType directory -Path "C:\Windows\System32\WindowsPowerShell\v1.0\Modules\PSDesiredStateConfiguration\PullServer\bin"
      }
      if((test-path -Path "C:\Windows\System32\WindowsPowerShell\v1.0\Modules\PSDesiredStateConfiguration\PullServer\bin\Microsoft.Powershell.DesiredStateConfiguration.Service.dll") -eq $false) {
         Copy-Item "C:\Windows\System32\WindowsPowerShell\v1.0\Modules\PSDesiredStateConfiguration\PullServer\Microsoft.Powershell.DesiredStateConfiguration.Service.dll" -Destination "C:\Windows\System32\WindowsPowerShell\v1.0\Modules\PSDesiredStateConfiguration\PullServer\bin"
      }
      if((Test-Path "C:\Windows\System32\WindowsPowerShell\v1.0\Modules\PSDesiredStateConfiguration\PullServer\web.config") -eq $false) {
         Copy-Item "C:\Windows\System32\WindowsPowerShell\v1.0\Modules\PSDesiredStateConfiguration\PullServer\PSDSCPullServer.config" -Destination "C:\Windows\System32\WindowsPowerShell\v1.0\Modules\PSDesiredStateConfiguration\PullServer\web.config"
      }
      Write-Log -value "Installing PullServer DSC"
      #Invoke-Command -ScriptBlock { PowerShell.exe $($d.wD, $d.mR, "rsEnvironments.ps1" -join '\')} -ArgumentList "-ExecutionPolicy Bypass -Force"
      #Start-Sleep 60
      & start -Wait $($d.wD, $d.mR, "rsEnvironments.ps1" -join '\')
   }
   else {
      Write-Log -value "Installing Client LCM"
      #Invoke-Command -ScriptBlock {PowerShell.exe $($d.wD, $d.prov, "rsLCM.ps1" -join '\')} -ArgumentList "-ExecutionPolicy Bypass -Force"
      & $($d.wD, $d.prov, "rsLCM.ps1" -join '\')
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
   schtasks.exe /create /sc Onstart /tn BasePrep /ru System /tr "PowerShell.exe -ExecutionPolicy Bypass -file $($d.wD, $d.prov, $d.bS -join '\')"
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
      Set-NetAdapterAdvancedProperty * -DisplayName "Large Receive Offload (IPv4)" -DisplayValue Disabled –NoRestart
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
      if((Test-Path -PathType Container -Path $($d.wD, "net45_InstallDir" -join '\')) -eq $false) {
         New-Item $($d.wD, "net45_InstallDir" -join '\') -ItemType Directory -Force
      }
      Write-Log -value "Installing .NET 4.5"
      Download-File -path $($d.wD, "net45_InstallDir", "dotNetFx45_Full_setup.exe" -join '\') -url "http://download.microsoft.com/download/B/A/4/BA4A7E71-2906-4B2D-A0E1-80CF16844F5F/dotNetFx45_Full_setup.exe"
      Start -Wait -NoNewWindow $($d.wD, "net45_InstallDir", "dotNetFx45_Full_setup.exe" -join '\') -ArgumentList '/q /norestart'
   }
   return
}


##################################################################################################################################
#                                             Function - Install WMF4 (if needed)
##################################################################################################################################
Function Install-WMF4 {
   if($osVersion -lt 6.2 -and $wmfVersion -lt 4) {
      if((Test-Path -PathType Container -Path $($d.wD, "wmf4_InstallDir" -join '\')) -eq $false) {
         Write-Log -value "creating directory $($d.wD, "wmf4_InstallDir" -join '\')"
         New-Item $($d.wD, "wmf4_InstallDir" -join '\') -ItemType Directory -Force
      }
      Write-Log -value "Installing WMF 4 on 2k8"
      Download-File -path $($d.wD, "wmf4_InstallDir", "Windows6.1-KB2819745-x64-MultiPkg.msu" -join '\') -url "http://download.microsoft.com/download/3/D/6/3D61D262-8549-4769-A660-230B67E15B25/Windows6.1-KB2819745-x64-MultiPkg.msu"
      Start -Wait -NoNewWindow $($d.wD, "wmf4_InstallDir", "Windows6.1-KB2819745-x64-MultiPkg.msu" -join '\') -ArgumentList '/quiet'
      return
   }
   if($osVersion -gt 6.2 -and $wmfVersion -lt 4) {
      if((Test-Path -PathType Container -Path $($d.wD, "wmf4_InstallDir" -join '\')) -eq $false) {
         Write-Log -value "creating directory $($d.wD, "wmf4_InstallDir" -join '\')"
         New-Item $($d.wD, "wmf4_InstallDir" -join '\') -ItemType Directory -Force
      }
      Write-Log -value "Installing WMF 4 on 2012"
      Download-File -path $($d.wD, "wmf4_InstallDir", "Windows8-RT-KB2799888-x64.msu" -join '\') -url "http://download.microsoft.com/download/3/D/6/3D61D262-8549-4769-A660-230B67E15B25/Windows8-RT-KB2799888-x64.msu"
      Start -Wait -NoNewWindow $($d.wD, "wmf4_InstallDir", "Windows8-RT-KB2799888-x64.msu" -join '\') -ArgumentList '/quiet'
      return
   }
}



##################################################################################################################################
#                                             Function - Format D Drive (perf cloud servers)
##################################################################################################################################
Function Set-DataDrive {
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


##################################################################################################################################
#                                             Function - Update Xen Client Tools (if needed)
##################################################################################################################################
Function Update-XenTools {
   [System.Reflection.Assembly]::LoadWithPartialName("System.IO.Compression.FileSystem") | Out-Null
   $destination = $($d.wD + "\")
   if ( $osVersion -lt "6.2" ) {
      $path = $($d.wD, "nova_agent_1.2.7.0.zip" -join '\')
      Download-File -url "http://cc527d412bd9bc2637b1-054807a7b8a5f81313db845a72a4785e.r34.cf1.rackcdn.com/nova_agent_1.2.7.0.zip" -path $path
      [System.IO.Compression.ZipFile]::ExtractToDirectory($path, $destination)
      Get-Service -DisplayName "Rackspace Cloud Servers*" | Stop-Service -Verbose
      Copy-Item $($d.wD, "Cloud Servers\*" -join '\') "C:\Program Files\Rackspace\Cloud Servers\" -recurse -force
      Remove-Item $($d.wD, "Cloud Servers" -join '\') -Force -Recurse
   }
   if($osVersion -lt "6.3") {
      $path = $($d.wD, "xs-tools-6.2.0.zip" -join '\')
      try{
         Download-File -url "http://1631170f67e7daa50e95-7dd27d3f3410187707440a293c5d1c09.r5.cf1.rackcdn.com/xs-tools-6.2.0.zip" -path $path
      }
      catch {
         Write-EventLog -LogName DevOps -Source BasePrep -EntryType Error -EventId 1002 -Message "Failed to Download Xentools `n $($_.Exception.Message)"
      }
      [System.IO.Compression.ZipFile]::ExtractToDirectory($path, $destination)
      Write-Log -value "Installing Xen Tools 6.2"
      Start -Wait $($d.wD, "xs-tools-6.2.0\installwizard.msi" -join '\' ) -ArgumentList '/qn PATH="C:\Program Files\Citrix\XenTools\"'
   }
   if($osVersion -gt "6.3") {
      ### If osversion 2012 R2 no xentools install needed and no reboot needed, setting stage to 3 and returning to start stage 3
      Set-Stage -value 3
      return
   }
}


##################################################################################################################################
#                                             Function - Add pull server info to HOSTS file
##################################################################################################################################
Function Update-HostFile {
   . "$($d.wD, $d.mR, "PullServerInfo.ps1" -join '\')"
   $pullServerName = $pullServerInfo.pullServerName
   $pullServerPublicIP = $pullserverInfo.pullserverPublicIp
   $pullServerPrivateIP = $pullServerInfo.pullServerPrivateIp
   if($role -eq "Pull") {
      $hostContent = ((Get-NetAdapter | ? status -eq 'up' | Get-NetIPAddress -ea 0 | ? IPAddress -like '10.*').IPAddress + "`t`t`t" + $serverName)
      Add-Content -Path "C:\Windows\System32\Drivers\etc\hosts" -Value $hostContent -Force
      return
   }
   else {
      if($pullServerRegion -ne $serverRegion) {
         $pullServerIP = $pullServerPublicIP
      }
      else {
         $pullServerIP = $pullServerPrivateIP
      }
      $hostContent = $pullServerIP + "`t`t`t" + $pullServerName
      Add-Content -Path "C:\Windows\System32\Drivers\etc\hosts" -Value $hostContent -Force
      $hostContent = ((Get-NetAdapter | ? status -eq 'up' | Get-NetIPAddress -ea 0 | ? IPAddress -like '10.*').IPAddress + "`t`t`t" + $serverName)
      Add-Content -Path "C:\Windows\System32\Drivers\etc\hosts" -Value $hostContent -Force
      return
   }
}


##################################################################################################################################
#                                             Function - Install SSL cert used for Client/Pull communications
##################################################################################################################################
Function Install-Certs {
   . "$($d.wD, $d.mR, "PullServerInfo.ps1" -join '\')"
   $pullServerName = $pullServerInfo.pullServerName
   $pullServerPublicIP = $pullserverInfo.pullserverPublicIp
   $pullServerPrivateIP = $pullServerInfo.pullServerPrivateIp
   $uri = "http://" + $pullServerName + "/" + "PullServer.cert.pfx"
   $uri_rsaPub = "http://" + $pullServerName + "/" + "id_rsa.pub"
   $uri_rsa = "http://" + $pullServerName + "/" + "id_rsa.txt"
   if($role -eq "Pull") {
      Write-Log -value "Installing Certificate"
      if(!(Test-Path -Path "C:\inetpub\wwwroot\id_rsa.txt")) {
         Copy-Item -Path "C:\Program Files (x86)\Git\.ssh\id_rsa" -Destination "C:\inetpub\wwwroot\id_rsa.txt" -Force
      }
      if(!(Test-Path -Path "C:\inetpub\wwwroot\id_rsa.pub")) {
         Copy-Item -Path "C:\Program Files (x86)\Git\.ssh\id_rsa.pub" -Destination "C:\inetpub\wwwroot\id_rsa.pub" -Force
      }
   }
   if($role -ne "Pull") {
      Download-File -url $uri -path $($d.wD, "PullServer.cert.pfx" -join '\')
      Download-File -url $uri_rsaPub -path 'C:\Program Files (x86)\Git\.ssh\id_rsa.pub'
      Download-File -url $uri_rsa -path 'C:\Program Files (x86)\Git\.ssh\id_rsa'
      powershell.exe certutil -addstore -f root $($d.wD, "PullServer.cert.pfx" -join '\')
      Remove-Item -Path $($d.wD, "PullServer.cert.pfx" -join '\') -Force
   }
}


##################################################################################################################################
#                                             Function - Cleanup secrets file
##################################################################################################################################
Function Clean-Up {
   if(Test-Path -Path ($d.wD, "xs-tools-6.2.0" -join '\')) { Remove-Item ($d.wD, "xs-tools-6.2.0" -join '\') -Recurse -Force }
   if(Test-Path -Path ($d.wD, "xs-tools-6.2.0.zip" -join '\')) { Remove-Item ($d.wD, "xs-tools-6.2.0.zip" -join '\') -Recurse -Force }
   schtasks.exe /Delete /TN BasePrep /F
}


##################################################################################################################################
#                                             Setting Script Wide Variables
##################################################################################################################################
. "C:\cloud-automation\secrets.ps1"

$gitExe = "C:\Program Files (x86)\Git\bin\git.exe"
if((Test-Path -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\WinDevOps") -eq $false) {
   New-Item -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE" -Name "WinDevOps" -Force
   Set-ItemProperty -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\WinDevOps" -Name "BuildScript" -Value 1 -Force
}
    $stage = (Get-ItemProperty -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\WinDevOps").BuildScript
    $role = Get-Role
    $serverName = $env:COMPUTERNAME
    $osVersion = (Get-WmiObject -class Win32_OperatingSystem).Version
if($role -eq "Pull") {
   $pullServerName = $env:COMPUTERNAME
   $pullServerPrivateIP = (Get-NetAdapter | ? status -eq 'up' | Get-NetIPAddress -ea 0 | ? IPAddress -match '^10\.').IPAddress
   $pullServerPublicIPS = (Get-NetIPAddress).IPv4Address | ? {$_ -notmatch '^10\.' -and $_ -notmatch '^127\.'}
   foreach($publicIP in $pullServerPublicIPS) 
   {
      if($publicIP -ne $null) 
      {
         $pullServerPublicIP = $publicIP
      }
   } 
}
else 
{
   . "$($d.wD, $d.mR, "PullServerInfo.ps1" -join '\')"
   $pullServerName = $pullServerInfo.pullServerName
   $pullServerPublicIP = $pullserverInfo.pullserverPublicIp
   $pullServerPrivateIP = $pullServerInfo.pullServerPrivateIp
}
    $serverRegion = Get-Region
    $pullServerRegion = $pullServerInfo.region
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
      Create-Log
      Write-Log -value "Starting Stage 1"
      Create-ClientData
      Set-GitPath
      Disable-MSN
      Create-SshKey
      Disable-TOE
      #Start-Sleep 10
      tzutil /s "Central Standard Time"
      Create-ScheduledTask
      Install-Net45
      Install-WMF4
      Set-Stage -value 2
      Restart-Computer -Force
   }
   
   2
   {
      Set-Stage -value 3
      Update-XenTools
   }
   3
   {
      Disable-MSN
      Disable-TOE
      Set-DataDrive
      New-NetFirewallRule -DisplayName "WINRM" -Direction Inbound -Action Allow -Protocol TCP -LocalPort 5985-5986
      set-item WSMan:\localhost\Client\TrustedHosts * -force
      Get-TempPullDSC
      Update-HostFile
      Create-PullServerInfo
      Install-Certs
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