Import-Module rsCommon

Configuration ClientLCM
{
    param ($Node, $pullServerUri, $ObjectGuid, $CertificateID)
    
    Node $Node
    {
        LocalConfigurationManager
        {
            AllowModuleOverwrite = 'True'
            ConfigurationID = $ObjectGuid
            CertificateID = $CertificateID
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
New-rsEventLogSource -logSource LCM

if(Test-rsCloud) 
{
    $ObjectGuid = (Get-rsXenInfo -value name) -replace "instance-", ""
}
else 
{
    $ObjectGuid = ((Get-rsDedicatedInfo -Value $env:COMPUTERNAME) | ? { $_.name -eq $env:COMPUTERNAME } ).id
}

if((Get-rsRole -Value $env:COMPUTERNAME) -eq "pull") 
{
    $pullServerName = $env:COMPUTERNAME
    chdir "C:\Windows\Temp"
    PullServerLCM
    Set-DscLocalConfigurationManager -Path "C:\Windows\Temp\PullServerLCM" -Verbose
    Get-ScheduledTask -TaskName "Consistency" | Start-ScheduledTask
    $result = Get-DscLocalConfigurationManager | ConvertTo-Json -Depth 4
    Write-EventLog -LogName DevOps -Source LCM -EntryType Information -EventId 1000 -Message "Applying Desired State Local Configuration $result"
}
else 
{
    $Node = $env:COMPUTERNAME
    $cN = "CN=" + $Node + "_enc"
    Set-Location -Path ("C:\DevOps", $d.mR -join "\")
    Start -Wait "C:\Program Files (x86)\Git\bin\git.exe" -ArgumentList "fetch origin $($d.branch_rsConfigs)"
    Start -Wait "C:\Program Files (x86)\Git\bin\git.exe" -ArgumentList "merge remotes/origin/$($d.branch_rsConfigs)"
    
    if (!(Test-Path -Path $("C:\DevOps", $d.mR, "Certificates", "Credentials" -join '\')))
    {
       New-Item -Path $("C:\DevOps", $d.mR, "Certificates", "Credentials" -join '\') -ItemType directory
    }
    
    if ( -not (Get-ChildItem Cert:\LocalMachine\My | Where-Object { $_.PrivateKey.KeySize -eq 2048 -and $_.Subject -eq $cN}))
    {
        powershell.exe "C:\DevOps\rsProvisioning\makecert.exe" -r -pe -n $cN -sky exchange -ss my $("C:\DevOps", $d.mR, "Certificates\Credentials","$ObjectGuid.cer"  -join '\'), -sr localmachine, -len 2048
        Start -Wait "C:\Program Files (x86)\Git\bin\git.exe" -ArgumentList "add $("C:\DevOps", $d.mR, "Certificates\Credentials","$ObjectGuid.cer"  -join '\')"
        Start -Wait "C:\Program Files (x86)\Git\bin\git.exe" -ArgumentList "commit -a -m `"pushing $ObjectGuid.crt`""
    }
    
    # Add a random wait between cert sync attempts, if any of the git commands return a non-zero exit code
    #
    $certSyncRetries = 5
    $certSyncAttempt = 0
    $randOpt = @{
                min = 15;
                max = 120
               }
    
    Do
    {
        $gitFetch = Start-Process -PassThru -Wait "C:\Program Files (x86)\Git\bin\git.exe" -ArgumentList "fetch origin $($d.branch_rsConfigs)"
        $gitMerge = Start-Process -PassThru -Wait "C:\Program Files (x86)\Git\bin\git.exe" -ArgumentList "merge remotes/origin/$($d.branch_rsConfigs)"    
        $gitPush = Start-Process -PassThru -Wait "C:\Program Files (x86)\Git\bin\git.exe" -ArgumentList "push origin $($d.branch_rsConfigs)"
    
        if (($gitFetch.ExitCode -eq 0) -and ($gitMerge.ExitCode -eq 0) -and ($gitPush.ExitCode -eq 0))
        {
            $gitSyncSuccess = $true
        }
        else
        {
            $gitSyncSuccess = $false
            $delayRandom = (Get-Random -Minimum $randOpt.min -Maximum $randOpt.max)
            Write-EventLog -LogName DevOps -Source LCM -EntryType Warning -EventId 1000 -Message "Client certificate git push attempt failed with following exit codes: `n Git FETCH: $($gitFetch.ExitCode) `n Git MERGE: $($gitMerge.ExitCode) `n Git PUSH: $($gitPush.ExitCode) `n Attempt: $certSyncAttempt `n Retrying in $delayRandom seconds..."
            Start-Sleep -Seconds $delayRandom
        }
        $certSyncAttempt += 1
    } Until (($certSyncAttempt -eq $certSyncRetries) -or ($gitSyncSuccess))
    
    if ($gitSyncSuccess)
    {
        Write-EventLog -LogName DevOps -Source LCM -EntryType Information -EventId 1000 -Message "Client certificate push complete after $certSyncAttempt attempt(s).`n Git FETCH: $($gitFetch.ExitCode) `n Git MERGE: $($gitMerge.ExitCode) `n Git PUSH: $($gitPush.ExitCode)"
    }
    else 
    {
        Write-EventLog -LogName DevOps -Source LCM -EntryType Error -EventId 1000 -Message "Client certificate push failed after $certSyncAttempt attempts. `n Please Re-run rsLCM process manually to correct this as client MOF will not be generated for this host.`n Git FETCH: $($gitFetch.ExitCode) `n Git MERGE: $($gitMerge.ExitCode) `n Git PUSH: $($gitPush.ExitCode)"
    }
    
    chdir "C:\Windows\Temp"
    $pullServerName = $pullServerInfo.pullServerName
    $pullServerUri = "https://" + $pullServerName + ":8080/PSDSCPullServer.svc"
    $certThumbPrint = (Get-ChildItem Cert:\LocalMachine\My | Where-Object { $_.PrivateKey.KeySize -eq 2048 -and $_.Subject -eq $cN}).Thumbprint
    ClientLCM -Node $Node -pullServerUri $pullServerUri -ObjectGuid $ObjectGuid -CertificateID $certThumbPrint -OutputPath "C:\Windows\Temp"
    Set-DscLocalConfigurationManager -Path "C:\Windows\Temp" -Verbose
    Get-ScheduledTask -TaskName "Consistency" | Start-ScheduledTask
    $result = Get-DscLocalConfigurationManager | ConvertTo-Json -Depth 4
    Write-EventLog -LogName DevOps -Source LCM -EntryType Information -EventId 1000 -Message "Applying Desired State Local Configuration $result"
}

