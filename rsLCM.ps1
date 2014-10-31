

Configuration ClientLCM
{
   param ($Node, $pullServerUri, $ObjectGuid)
   
   Node $Node
   {
      LocalConfigurationManager
      {
         AllowModuleOverwrite = 'True'
         ConfigurationID = $ObjectGuid
         ConfigurationModeFrequencyMins = 30
         ConfigurationMode = 'ApplyAndAutoCorrect'
         RebootNodeIfNeeded = 'True'
         RefreshMode = 'Pull'
         RefreshFrequencyMins = 15
         DownloadManagerName = 'WebDownloadManager'
         DownloadManagerCustomData = (@{ServerUrl = $pullServerUri; AllowUnsecureConnection = "false"})
      }
   }
}

Configuration PullServerLCM
{
   
   Node $env:COMPUTERNAME
   {
      LocalConfigurationManager
      {
         AllowModuleOverwrite = 'True'
         ConfigurationModeFrequencyMins = 30
         ConfigurationMode = 'ApplyAndAutoCorrect'
         RebootNodeIfNeeded = 'True'
         RefreshMode = 'PUSH'
         RefreshFrequencyMins = 15
      }
   }
}

. (Get-rsSecrets)
. "$("C:\DevOps", $d.mR, 'PullServerInfo.ps1' -join '\' )"
if(Test-rsCloud) {
   $ObjectGuid = $session.GetValue("name").value -replace "instance-", ""
}
else {
   $ObjectGuid = (Get-DedicatedInfo -Value $env:COMPUTERNAME).id
}

if((Get-rsRole -Value $env:COMPUTERNAME) -eq "pull") {
   $pullServerName = $env:COMPUTERNAME
   chdir "C:\Windows\Temp"
   PullServerLCM
   Set-DscLocalConfigurationManager -Path "C:\Windows\Temp\PullServerLCM" -Verbose
   Get-ScheduledTask -TaskName "Consistency" | Start-ScheduledTask
   $result = Get-DscLocalConfigurationManager | ConvertTo-Json -Depth 4
   Write-EventLog -LogName DevOps -Source LCM -EntryType Information -EventId 1000 -Message "Applying Desired State Local Configuration $result"
}
else {
   $Node = $env:COMPUTERNAME
   chdir "C:\Windows\Temp"
   $pullServerName = Get-rsPullServerName
   $pullServerUri = "https://" + $pullServerName + ":8080/PSDSCPullServer.svc"
   ClientLCM -Node $Node -pullServerUri $pullServerUri -ObjectGuid $ObjectGuid -OutputPath "C:\Windows\Temp"
   Set-DscLocalConfigurationManager -Path "C:\Windows\Temp" -Verbose
   Get-ScheduledTask -TaskName "Consistency" | Start-ScheduledTask
   $result = Get-DscLocalConfigurationManager | ConvertTo-Json -Depth 4
   Write-EventLog -LogName DevOps -Source LCM -EntryType Information -EventId 1000 -Message "Applying Desired State Local Configuration $result"
}

