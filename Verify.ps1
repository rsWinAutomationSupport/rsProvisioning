. "C:\cloud-automation\secrets.ps1"
. "$($d.wD, $d.mR, "PullServerInfo.ps1" -join '\')"

## This script is executed by the PullServerDSC scheduled task
## This script will check the hash value of the PullServerDSC.ps1 config script and if it has been modified it will create a new Hash and execute the PullServerDSC.ps1 script
## to start a new DSC configuration on the PullServer

Function Get-Region {
   $base = gwmi -n root\wmi -cl CitrixXenStoreBase
   $sid = $base.AddSession("MyNewSession")
   $session = gwmi -n root\wmi -q "select * from CitrixXenStoreSession where SessionId=$($sid.SessionId)"
   $region = $session.GetValue("vm-data/provider_data/region").value -replace "`"", ""
   return $region
}
Function Get-Role {
   $base = gwmi -n root\wmi -cl CitrixXenStoreBase
   $sid = $base.AddSession("MyNewSession")
   $session = gwmi -n root\wmi -q "select * from CitrixXenStoreSession where SessionId=$($sid.SessionId)"
   $role = $session.GetValue("vm-data/user-metadata/Role").value -replace "`"", ""
   return $role
}

Function Download-File {
   # File download function
   param ( [string]$url, [string]$path )
   $webclient = New-Object System.Net.WebClient
   $webclient.DownloadFile($url,$path)
   return
}
Function Check-Hash {
   if((Test-Path $($d.wD, "rsEnvironments.hash" -join '\')) -eq $false) {
      Set-Content -Path $($d.wD, "rsEnvironments.hash" -join '\') -Value (Get-FileHash -Path $($d.wD, $d.mR, "rsEnvironments.ps1" -join '\')).hash
      & $($d.wD, $d.mR, "rsEnvironments.ps1" -join '\') -ExecutionPolicy -Bypass -Force
   }
   $checkHash = Get-FileHash $($d.wD, $d.mR, "rsEnvironments.ps1" -join '\')
   $currentHash = Get-Content $($d.wD, "rsEnvironments.hash" -join '\')
   if($checkHash.Hash -ne $currentHash) {
      Set-Content -Path $($d.wD, "rsEnvironments.hash" -join '\') -Value (Get-FileHash -Path $($d.wD, $d.mR, "rsEnvironments.ps1" -join '\')).hash
      Create-Modules
      & $($d.wD, $d.mR, "rsEnvironments.ps1" -join '\') -ExecutionPolicy -Bypass -Force
   }
   
   else {
      & $($d.wD, $d.mR, "rsEnvironments.ps1" -join '\') -ExecutionPolicy -Bypass -Force
   }
   
   
   $pullServerName = $env:COMPUTERNAME
   $pullServerPrivateIP = (Get-NetAdapter | ? status -eq 'up' | Get-NetIPAddress -ea 0 | ? IPAddress -match '^10\.').IPAddress
   $pullServerPublicIPS = (Get-NetIPAddress).IPv4Address | ? {$_ -notmatch '^10\.' -and $_ -notmatch '^127\.'}
   foreach($publicIP in $pullServerPublicIPS) {
      if($publicIP -ne $null) {
         $pullServerPublicIp = $publicIP
      }
   } 
   $path = $($d.wD + "\" + $d.mR + "\" + "PullServerInfo.ps1")
   if(Test-Path -Path $path) {
      Remove-Item -Path $path -Force
   }
   $region = Get-Region
   chdir $($d.wD, $d.mR -join '\')
   New-Item -path $path -ItemType file
   Add-Content -Path $path -Value "`$pullServerInfo = @{"
   Add-Content -Path $path -Value "`"pullServerName`" = `"$pullServerName`""
   Add-Content -Path $path -Value "`"pullServerPrivateIp`" = `"$pullServerPrivateIp`""
   Add-Content -Path $path -Value "`"pullServerPublicIp`" = `"$pullServerPublicIp`""
   Add-Content -Path $path -Value "`"region`" = `"$region`""
   Add-Content -Path $path -Value "}"
   Set-Service Browser -startuptype "manual"
   Start-Service Browser
   Start -Wait -NoNewWindow "C:\Program Files (x86)\Git\bin\git.exe" -ArgumentList "add $($d.wD + "\" + $d.mR + "\" + "PullServerInfo.ps1")"
   Start -Wait -NoNewWindow "C:\Program Files (x86)\Git\bin\git.exe" -ArgumentList "commit -am `"$pullServerName pushing PullServerInfo.ps1`""
   Start -Wait -NoNewWindow "C:\Program Files (x86)\Git\bin\git.exe" -ArgumentList "pull origin $($d.br)"
   Start -Wait -NoNewWindow "C:\Program Files (x86)\Git\bin\git.exe" -ArgumentList "push origin $($d.br)"
   Stop-Service Browser
   
}

### Client tasks
Function Check-Hosts {
   $serverRegion = Get-Region
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
      $entryExist.Split()
      if(($entryExist[0]) -ne $pullServerIP) {
         ((Get-Content "${env:windir}\system32\drivers\etc\hosts") -notmatch "^\s*$") -notmatch "^[^#]*\s+$pullServerName" | Set-Content "${env:windir}\system32\drivers\etc\hosts"
         Add-Content -Path "${env:windir}\system32\drivers\etc\hosts" -Value $hostEntry -Force -Encoding ASCII
      }
   }
   else {
      Add-Content -Path "${env:windir}\system32\drivers\etc\hosts" -Value $hostEntry -Force -Encoding ASCII
   }
}

Function Install-Certs {
   $pullServerName = $pullServerInfo.pullServerName
   $cN = ("CN=" + $pullServerName)
   $uri = "http://" + $pullServerName + "/" + "PullServer.cert.pfx"
   $uri_rsaPub = "http://" + $pullServerName + "/" + "id_rsa.pub"
   $uri_rsa = "http://" + $pullServerName + "/" + "id_rsa.txt"
   Remove-Item -Path 'C:\Program Files (x86)\Git\.ssh\id_rsa*'
   Get-ChildItem Cert:\LocalMachine\Root\ | where {$_.Subject -eq $cN} | Remove-Item
   Download-File -url $uri -path $($d.wD, "PullServer.cert.pfx" -join '\')
   Download-File -url $uri_rsaPub -path 'C:\Program Files (x86)\Git\.ssh\id_rsa.pub'
   Download-File -url $uri_rsa -path 'C:\Program Files (x86)\Git\.ssh\id_rsa'
   powershell.exe certutil -addstore -f root $($d.wD, "PullServer.cert.pfx" -join '\')
}
$role = Get-Role
if($role -eq "Pull") {
   Check-Hash
   Get-ScheduledTask -TaskName "Consistency" | Start-ScheduledTask
}
else {
   Check-Hosts
   Install-Certs
   Get-ScheduledTask -TaskName "Consistency" | Start-ScheduledTask
}

taskkill /F /IM WmiPrvSE.exe
