

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
        $cN = "CN=" + $NodeName
        chdir "C:\Windows\Temp"
        $pullServerName = $pullServerInfo.pullServerName
        $pullServerUri = "https://" + $pullServerName + ":8080/PSDSCPullServer.svc"
        Start -Wait "C:\Program Files (x86)\Git\bin\git.exe" -ArgumentList "pull origin $($d.br)"

        if (!(Test-Path -Path $($d.wD, $d.mR, "Certificates", "Credentials" -join '\')))
        {
            New-Item -Path $($d.wD, $d.mR, "Certificates", "Credentials" -join '\') -ItemType directory
        }
        powershell.exe $($d.wD, $d.prov, "makecert.exe" -join '\') -r -pe -n $cN -sky exchange -ss my $($d.wD, $d.mR, "Certificates\Credentials","$ObjectGuid.cer"  -join '\'), -sr localmachine, -len 2048
        Start -Wait "C:\Program Files (x86)\Git\bin\git.exe" -ArgumentList "add $($d.wD, $d.mR, "Certificates\Credentials","$ObjectGuid.cer"  -join '\')"
        Start -Wait "C:\Program Files (x86)\Git\bin\git.exe" -ArgumentList "commit -a -m `"pushing $ObjectGuid.crt`""
        Start -Wait "C:\Program Files (x86)\Git\bin\git.exe" -ArgumentList "push origin $($d.br)"
        ClientLCM -Node $Node -pullServerUri $pullServerUri -ObjectGuid $ObjectGuid -OutputPath "C:\Windows\Temp"
        Set-DscLocalConfigurationManager -Path "C:\Windows\Temp" -Verbose
        Get-ScheduledTask -TaskName "Consistency" | Start-ScheduledTask
        $result = Get-DscLocalConfigurationManager | ConvertTo-Json -Depth 4
        Write-EventLog -LogName DevOps -Source LCM -EntryType Information -EventId 1000 -Message "Applying Desired State Local Configuration $result"
    }

