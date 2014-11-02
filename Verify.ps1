Import-Module rsCommon
. (Get-rsSecrets)
. "$("C:\DevOps", $d.mR, "PullServerInfo.ps1" -join '\')"
New-rsEventLogSource -logSource verify

try {
   $basePrepState = (Get-ScheduledTask -TaskName "BasePrep" -ErrorAction SilentlyContinue).State
}
catch {
}
if($basePrepState -eq "Running") {
   Write-EventLog -LogName DevOps -Source Verify -EntryType Information -EventId 1000 -Message "BasePrep task is currently running, aborting Verify task"
   break
}
if((Test-Path -Path "C:\Windows\System32\Configuration\Pending.mof") -and ((Get-ScheduledTask -TaskName "Consistency").State -eq "Running")) {
   Write-EventLog -LogName DevOps -Source Verify -EntryType Information -EventId 1000 -Message "Pending MOF exists and Consistency is currently running"
   if((Test-Path -Path "C:\Windows\System32\Configuration\Current.mof")) {
      Write-EventLog -LogName DevOps -Source Verify -EntryType Information -EventId 1000 -Message "Pending MOF exists and Consistency is currently running, Current MOF exists, aborting Verify task "
   }
   break
}
## This script is executed by the PullServerDSC scheduled task
## This script will check the hash value of the PullServerDSC.ps1 config script and if it has been modified it will create a new Hash and execute the PullServerDSC.ps1 script
## to start a new DSC configuration on the PullServer
### will pull before running rsEnvironments.ps1
Function Check-Hash {
   Write-EventLog -LogName DevOps -Source Verify -EntryType Information -EventId 1000 -Message "Pulling current configurations from github"
   if((Test-Path "C:\DevOps\rsEnvironments.hash") -eq $false) {
      Write-EventLog -LogName DevOps -Source Verify -EntryType Information -EventId 1000 -Message "File C:\DevOps\rsEnvironments.hash was not found, creating hash file and executing rsEnvironments.ps1"
      Set-Content -Path "C:\DevOps\rsEnvironments.hash" -Value (Get-FileHash -Path $("C:\DevOps", $d.mR, "rsEnvironments.ps1" -join '\')).hash
      do {
         Write-EventLog -LogName DevOps -Source Verify -EntryType Information -EventId 1000 -Message "Installing DSC $("C:\DevOps", $d.mR, "rsEnvironments.ps1" -join '\')"
         taskkill /F /IM WmiPrvSE.exe
         Invoke-Command -ScriptBlock { start -Wait -NoNewWindow PowerShell.exe $("C:\DevOps", $d.mR, "rsEnvironments.ps1" -join '\')} -ArgumentList "-ExecutionPolicy Bypass -Force"
      }
      while (!(Test-Path -Path "C:\Windows\System32\Configuration\Current.mof"))
      Write-EventLog -LogName DevOps -Source Verify -EntryType Information -EventId 1000 -Message "PullServer DSC installation Complete."
   }
   $checkHash = Get-FileHash $("C:\DevOps", $d.mR, "rsEnvironments.ps1" -join '\')
   $currentHash = Get-Content "C:\DevOps\rsEnvironments.hash"
   if($checkHash.Hash -ne $currentHash) {
      Write-EventLog -LogName DevOps -Source Verify -EntryType Information -EventId 1000 -Message "rsEnvironments hash mismatch rsEnvironments has been updated, executing rsEnvironments.ps1"
      Set-Content -Path "C:\DevOps\rsEnvironments.hash" -Value (Get-FileHash -Path $("C:\DevOps", $d.mR, "rsEnvironments.ps1" -join '\')).hash
      do {
         Write-EventLog -LogName DevOps -Source Verify -EntryType Information -EventId 1000 -Message "Installing DSC $("C:\DevOps", $d.mR, "rsEnvironments.ps1" -join '\')"
         taskkill /F /IM WmiPrvSE.exe
         Invoke-Command -ScriptBlock { start -Wait -NoNewWindow PowerShell.exe $("C:\DevOps", $d.mR, "rsEnvironments.ps1" -join '\')} -ArgumentList "-ExecutionPolicy Bypass -Force"
      }
      while (!(Test-Path -Path "C:\Windows\System32\Configuration\Current.mof"))
      Write-EventLog -LogName DevOps -Source Verify -EntryType Information -EventId 1000 -Message "PullServer DSC installation Complete."
   if($checkHash.Hash -eq $currentHash) {
      if(!(Test-Path -Path "C:\Windows\System32\Configuration\Current.mof")) {
         Write-EventLog -LogName DevOps -Source Verify -EntryType Information -EventId 1000 -Message "rsEnvironments hash matches, but Current.mof does not exist, running rsEnvironments.ps1"
         do {
            Write-EventLog -LogName DevOps -Source Verify -EntryType Information -EventId 1000 -Message "Installing DSC $("C:\DevOps", $d.mR, "rsEnvironments.ps1" -join '\')"
            taskkill /F /IM WmiPrvSE.exe
            Invoke-Command -ScriptBlock { start -Wait -NoNewWindow PowerShell.exe $("C:\DevOps", $d.mR, "rsEnvironments.ps1" -join '\')} -ArgumentList "-ExecutionPolicy Bypass -Force"
         }
         while (!(Test-Path -Path "C:\Windows\System32\Configuration\Current.mof"))
         Write-EventLog -LogName DevOps -Source Verify -EntryType Information -EventId 1000 -Message "PullServer DSC installation Complete."
      }
      Write-EventLog -LogName DevOps -Source Verify -EntryType Information -EventId 1000 -Message "rsEnvironments hash matches, no changes have been made to rsEnvironments, executing consistency check"
      Get-ScheduledTask -TaskName "Consistency" | Start-ScheduledTask
   }
}
### Client tasks
Function Check-Hosts {
   Write-EventLog -LogName DevOps -Source Verify -EntryType Information -EventId 1000 -Message "Pulling current configurations from github"
   Write-EventLog -LogName DevOps -Source Verify -EntryType Information -EventId 1000 -Message "Checking hosts file entry for pullserver"
   $serverRegion = Get-rsRegion -Value $env:COMPUTERNAME
   $pullServerRegion = $pullServerInfo.region
   $pullServerName = $pullServerInfo.pullServerName
   $pullServerPublicIP = $pullserverInfo.pullserverPublicIp
   $pullServerPrivateIP = $pullServerInfo.pullServerPrivateIp
   if($pullServerRegion -ne $serverRegion) {
      $pullServerIP = $pullServerPublicIP
   }
   else {
      $pullServerIP = $pullServerPrivateIP
   }
   $hostEntry = "`n${pullServerIP}`t${pullServerName}"
   $entryExist = ((Get-Content "${env:windir}\system32\drivers\etc\hosts") -match "^[^#]*\s+$pullServerName") 
   if($entryExist) {
      $entryExist = $entryExist.Split()
      if(($entryExist[0]) -ne $pullServerIP) {
         Write-EventLog -LogName DevOps -Source Verify -EntryType Information -EventId 1000 -Message "Host file entry for pullserver does not match, updating hosts file"
         ((Get-Content "${env:windir}\system32\drivers\etc\hosts") -notmatch "^\s*$") -notmatch "^[^#]*\s+$pullServerName" | Set-Content "${env:windir}\system32\drivers\etc\hosts"
         Add-Content -Path "${env:windir}\system32\drivers\etc\hosts" -Value $hostEntry -Force -Encoding ASCII
      }
      else {
         Write-EventLog -LogName DevOps -Source Verify -EntryType Information -EventId 1000 -Message "Host file entry for pullserver matches, no changes to host file are needed."
      }
   }
   else {
      Write-EventLog -LogName DevOps -Source Verify -EntryType Information -EventId 1000 -Message "Host file entry for pullserver does not exist, creating entry for pullserver in host file."
      Add-Content -Path "${env:windir}\system32\drivers\etc\hosts" -Value $hostEntry -Force -Encoding ASCII
   }
}

Function Install-Certs {
   $pullServerName = $pullServerInfo.pullServerName
   Write-EventLog -LogName DevOps -Source Verify -EntryType Information -EventId 1000 -Message "Checking github SSH Key."
   if(!((Get-Content (Join-Path "C:\DevOps\DDI_rsConfigs\Certificates" -ChildPath "id_rsa.pub")).Split("==")[0] + "==") -eq ((Get-Content -Path (Join-Path "C:\Program Files (x86)\Git\.ssh" -ChildPath "id_rsa.pub")).Split("==")[0] + "==")) {
      Write-EventLog -LogName DevOps -Source Verify -EntryType Information -EventId 1000 -Message "SSH Key does not match, installing new SSH Key."
      Remove-Item -Path 'C:\Program Files (x86)\Git\.ssh\id_rsa*'
      Copy-Item -Path $("C:\DevOps", $d.mR, "Certificates\id_rsa.txt" -join '\') -Destination 'C:\Program Files (x86)\Git\.ssh\id_rsa'
      Copy-Item -Path $("C:\DevOps", $d.mR, "Certificates\id_rsa.pub" -join '\') -Destination 'C:\Program Files (x86)\Git\.ssh\id_rsa.pub'
   }
   else {
      Write-EventLog -LogName DevOps -Source Verify -EntryType Information -EventId 1000 -Message "SSH Key matches."
   }
   Write-EventLog -LogName DevOps -Source Verify -EntryType Information -EventId 1000 -Message "Checking pullserver certificate."
   $cN = "CN=" + $pullServerName
   if((Get-ChildItem Cert:\LocalMachine\Root\ | ? Subject -eq $cN).count -lt 1) {
      Write-EventLog -LogName DevOps -Source Verify -EntryType Information -EventId 1000 -Message "No Pullserver SSL certificate installed in trusted root, Installing new SSL certificate."
      powershell.exe certutil -addstore -f root $("C:\DevOps", $d.mR, "Certificates\PullServer.crt" -join '\')
   }
   else {
      if(((Get-ChildItem Cert:\LocalMachine\Root\ | ? Subject -eq $cN).Thumbprint) -ne $((Get-PfxCertificate -FilePath $("C:\DevOps",$d.mR,"Certificates\PullServer.crt" -join'\')).Thumbprint)) {
         Write-EventLog -LogName DevOps -Source Verify -EntryType Information -EventId 1000 -Message "Pullserver SSL does not match, Installing new SSL certificate."
         Get-ChildItem Cert:\LocalMachine\Root\ | where {$_.Subject -eq $cN} | Remove-Item
         powershell.exe certutil -addstore -f root $("C:\DevOps", $d.mR, "Certificates\PullServer.crt" -join '\')
      }
      else {
         Write-EventLog -LogName DevOps -Source Verify -EntryType Information -EventId 1000 -Message "Pullserver SSL certificate matches, nothing to be done."
      }
      
   }
   Write-EventLog -LogName DevOps -Source Verify -EntryType Information -EventId 1000 -Message "Completed client tests, starting consistency task."
   taskkill /F /IM WmiPrvSE.exe
   Get-ScheduledTask -TaskName "Consistency" | Start-ScheduledTask
}

Function Remove-UnsedCerts {
   $serversURL = ($catalog.access.serviceCatalog | Where-Object { $_.Name -eq "cloudServersOpenStack" }).endpoints.publicURL
   $activeServers = Invoke-RestMethod -Uri "$serversURL/servers" -Headers $AuthToken
   if ($activeServers) {
      $certs = (Get-ChildItem $("C:\DevOps", $d.mR, "Certificates\Credentials\*cer" -join '\')).Name | ForEach-Object { $_.Split(".")[0]}
      $unaccountedCerts =  $certs | Where-Object { -not ($activeServers.servers.id -contains $_)}
      "="*60 >> C:\cloud-automation\out.txt
      $certs -join ", " >> C:\cloud-automation\out.txt
      $unaccountedCerts -join ", " >> C:\cloud-automation\out.txt
      forEach ($cert in $unaccountedCerts) {
         "git rm Certificates\Credentials\$cert.cer" >> c:\cloud-automation\out.txt
         Start -Wait -NoNewWindow "C:\Program Files (x86)\Git\bin\git.exe" -ArgumentList "rm Certificates\Credentials\$cert.cer"
      }
      
   }
}
chdir $("C:\DevOps", $d.mR -join '\')
Start-Service Browser
Write-EventLog -LogName DevOps -Source Verify -EntryType Information -EventId 1000 -Message "Updating pullserverInfo.ps1 and pushing to github"
Start -Wait "C:\Program Files (x86)\Git\bin\git.exe" -ArgumentList "pull origin $($d.branch_rsConfigs)"
Stop-Service Browser
if((Get-rsRole -Value $env:COMPUTERNAME) -eq "pull") {
   $Global:catalog = Get-rsServiceCatalog
   $Global:AuthToken = Get-rsAuthToken
   if(Test-rsCloud) {
      $Global:defaultRegion = $catalog.access.user.'RAX-AUTH:defaultRegion'
      if(($catalog.access.user.roles | ? name -eq "rack_connect").id.count -gt 0) { $Global:isRackConnect = $true } else { $Global:isRackConnect = $false } 
      if(($catalog.access.user.roles | ? name -eq "rax_managed").id.count -gt 0) { $Global:isManaged = $true } else { $Global:isManaged = $false } 
   }
   else {
      $Global:defaultRegion = "NA"
      $Global:isRackConnect = $false
      $Global:isManaged = $false
   }
   Check-Hash
}
else {
   Check-Hosts
   Install-Certs
}
