########## PRE SCRIPT INIT ##########
if (-NOT ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator"))  
{  
  $arguments = "& '" +$myinvocation.mycommand.definition + "'"
  Start-Process powershell -Verb runAs -ArgumentList $arguments
  Break
}

########## MAIN ##########
$RulesName = "ZS_SteamLock";
$Version = 1.1;
Write-Host "=========== [ Steam Firewall Blocking Script ver. $Version ] ==========="

$Rules = Get-NetFirewallRule | Where-Object DisplayName -Like ($RulesName + "*")
if (($Rules).Count -eq 0)
{
    Write-Error "There are no rules blocking Steam via Firewall. Please use Enable script first for install."
    break;
}

if (($Rules).Count -lt 8)
{
    Write-Error "Not enough rules for blocking Steam via Firewall. Please use Enable script for update."
}

foreach ($element in $Rules)
{
    Set-NetFirewallRule -Name $element.Name -Enabled False
}
Write-Host "Steam blocking rules are DISABLED"