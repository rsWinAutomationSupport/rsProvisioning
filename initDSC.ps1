configuration initDSC {
   param (
      [string]$Ensure,
      [string]$Node
   )
   Import-DscResource -ModuleName rsPlatform
   Node $Node
   {
      rsPlatform Modules
      {
         Ensure          = "Present"
      }
   }
   
}

$Node = $env:COMPUTERNAME
chdir C:\Windows\Temp
initDSC -Ensure "present" -Node $Node
start-DscConfiguration -Path initDSC -wait -Verbose -Force