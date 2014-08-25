

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

. "C:\cloud-automation\secrets.ps1"
. "$($d.wD, $d.mR, 'PullServerInfo.ps1' -join '\' )"

    $base = gwmi -n root\wmi -cl CitrixXenStoreBase
    $sid = $base.AddSession("MyNewSession")
    $session = gwmi -n root\wmi -q "select * from CitrixXenStoreSession where SessionId=$($sid.SessionId)"
    $role = $session.GetValue("vm-data/user-metadata/Role").value -replace "`"", ""
    $ObjectGuid = $session.GetValue("name").value -replace "instance-", ""

    if($role -eq "Pull") {
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
        $pullServerName = $pullServerInfo.pullServerName
        $pullServerUri = "https://" + $pullServerName + ":8080/PSDSCPullServer.svc"
        ClientLCM -Node $Node -pullServerUri $pullServerUri -ObjectGuid $ObjectGuid -OutputPath "C:\Windows\Temp"
        Set-DscLocalConfigurationManager -Path "C:\Windows\Temp" -Verbose
        Get-ScheduledTask -TaskName "Consistency" | Start-ScheduledTask
        $result = Get-DscLocalConfigurationManager | ConvertTo-Json -Depth 4
        Write-EventLog -LogName DevOps -Source LCM -EntryType Information -EventId 1000 -Message "Applying Desired State Local Configuration $result"
    }

