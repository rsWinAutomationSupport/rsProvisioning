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
### will pull before running rsPullServer.ps1

Function Check-Hash {
   Write-EventLog -LogName DevOps -Source Verify -EntryType Information -EventId 1000 -Message "Checking rsPullServer hash"
   if(Test-rsHash -file $("C:\DevOps", $d.mR, "rsPullServer.ps1" -join '\') -hash "C:\DevOps\rsPullServer.hash" )
   {
      if(!(Test-Path -Path "C:\Windows\System32\Configuration\Current.mof")) {
        Write-EventLog -LogName DevOps -Source Verify -EntryType Information -EventId 1000 -Message "rsPullServer hash matches, but Current.mof does not exist, running rsPullServer.ps1"
        Invoke-DSC
      }
      else {
        Write-EventLog -LogName DevOps -Source Verify -EntryType Information -EventId 1000 -Message "rsPullServer hash matches, no changes have been made to rsPullServer, executing consistency check"
        Get-ScheduledTask -TaskName "Consistency" | Start-ScheduledTask
      }
   }
   else
   {
        Write-EventLog -LogName DevOps -Source Verify -EntryType Information -EventId 1000 -Message "File C:\DevOps\rsPullServer.hash was not found or hash mismatch, executing rsPullServer.ps1 & creating hash file"
        Invoke-DSC
        Set-rsHash -file $("C:\DevOps", $d.mR, "rsPullServer.ps1" -join '\') -hash "C:\DevOps\rsPullServer.hash"
   }
}
### Client tasks
Function Check-Hosts {
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

Function Remove-UnusedCerts {
   $activeServers = @()
   if($d.ContainsKey("rs_username") -and $d.ContainsKey("rs_apikey") ){
      $activeServers += Get-rsDetailsServers | ? {$_.metadata -match "rax_dsc_config"} | Select -Property id
   }
   if(Test-Path $('C:\DevOps',$d.mR,"dedicated.csv" -join '\')){
      $activeServers += Import-Csv -Path $('C:\DevOps',$d.mR,"dedicated.csv" -join '\') | Select id
   }
   if ($activeServers) {
      $certs = (Get-ChildItem $("C:\DevOps", $d.mR, "Certificates\Credentials\*cer" -join '\')).BaseName
      $unaccountedCerts = $certs | Where-Object { -not ($activeServers.id -contains $_)}
      forEach ($cert in $unaccountedCerts) {
         Write-EventLog -LogName DevOps -Source Verify -EntryType Information -EventId 1000 -Message "git rm Certificates\Credentials\$cert.cer"
         Start -Wait -NoNewWindow "C:\Program Files (x86)\Git\bin\git.exe" -ArgumentList "rm Certificates\Credentials\$cert.cer"
      }
      if($unaccountedCerts){
         Start -Wait -NoNewWindow "C:\Program Files (x86)\Git\bin\git.exe" -ArgumentList "commit -am `"Removing unaccounted certs`""
         Start -Wait -NoNewWindow "C:\Program Files (x86)\Git\bin\git.exe" -ArgumentList "pull origin $($d.branch_rsConfigs)"
         Start -Wait -NoNewWindow "C:\Program Files (x86)\Git\bin\git.exe" -ArgumentList "push origin $($d.branch_rsConfigs)"
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
   Remove-UnusedCerts
}
else {
   Check-Hosts
   Install-Certs
}
