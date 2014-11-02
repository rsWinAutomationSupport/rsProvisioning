
Import-Module rsCommon
New-rsEventLogSource -logSource ArnieTask
$verifyStatus = (Get-ScheduledTask -TaskName "Verify" -ErrorAction SilentlyContinue).State
$consistencyStatus = (Get-ScheduledTask -TaskName "Consistency" -ErrorAction SilentlyContinue).State
$arnieStatus = (Get-ScheduledTask -TaskName "Consistency" -ErrorAction SilentlyContinue).State
if($arnieStatus -eq "Running") {
   break
}
$i = 0
do {
   if(($verifyStatusState -eq "Running") -or ($consistencyStatus -eq "Running")) { 
      Write-EventLog -LogName DevOps -Source ArnieTask -EntryType Information -EventId 1000 -Message "DSC in use, waiting for verify and consistency tasks to complete before starting verify, sleeping 30 seconds"
      Start-Sleep -Seconds 30
   }
   else {
      Get-ScheduledTask -TaskName 'Verify' | Start-ScheduledTask
      break
   }
}
while($i -lt 1)