########## PRE SCRIPT ARGS ##########
$SteamLocation = $null; # Place steam directory here (example: "C:\steam")

########## PRE SCRIPT INIT ##########
if (-NOT ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator"))  
{  
  $arguments = "& '" +$myinvocation.mycommand.definition + "'"
  Start-Process powershell -Verb runAs -ArgumentList $arguments
  Break
}

function Get-InstallPath
{
    [CmdletBinding()]
    [OutputType([PSCustomObject])]
    Param
    (
        [Parameter(Mandatory = $true)]
        [SupportsWildcards()]
        [string]
        $ProgramName
    )
    
    $result = @()
    if ($inst = Get-ChildItem "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Installer\UserData\*\Products\*\InstallProperties" -ErrorAction SilentlyContinue)
    {
        $inst | Where-Object {
            ($DisplayName = $_.getValue('DisplayName')) -like $ProgramName
        } |
        ForEach-Object     {
            $result += [PSCustomObject]@{
                'DisplayName' = $displayName
                'Publisher' = $_.getValue('Publisher')
                'InstallPath' = $_.getValue('InstallLocation')
            }
        }
    }
    else
    {
        Write-Error "Cannot get the InstallProperties registry keys."
    }
    
    if ($result)
    {
        return $result
    }
    else
    {
        Write-Error "Cannot get the InstallProperties registry key for $ProgramName"
    }
}

class FirewallRule
{
    [Microsoft.Management.Infrastructure.CimInstance] $Rule
    [Microsoft.Management.Infrastructure.CimInstance] $AppFilter
}

function Get-FullNetFirewallRule
{
    [CmdletBinding()]
    [OutputType([PSCustomObject])]
    Param
    (
        [Parameter(Mandatory = $true)]
        [SupportsWildcards()]
        [string]
        $RulesName
    )

    $rules = Get-NetFirewallRule | Where-Object DisplayName -Like ($RulesName + "*")
    $result = @();

    foreach ($rule in $rules)
    {
        $result += [FirewallRule]@{
            Rule = $rule
            AppFilter = (Get-NetFirewallApplicationFilter -AssociatedNetFirewallRule $rule | Select -First 1)
        }
    }

    return $result
}

########## MAIN ##########
$RulesName = "ZS_SteamLock";
$Version = 1.1;

Write-Host "=========== [ Steam Firewall Blocking Script ver. $Version ] ==========="

# Check rules creation
$NetRules = Get-FullNetFirewallRule $RulesName;

if ($NetRules.count -lt 8)
{
    if ($SteamLocation -eq $null)
    { 
        $SteamLocation = Get-InstallPath "Steam" -ErrorAction SilentlyContinue | Select InstallPath -First 1
        if ($SteamLocation -eq $null -or $SteamLocation -eq @())
        {
            Write-Error "Cannot get Steam install path, please set to variable 'SteamLocation' mannually"
            Break
        }
    }

    # Create new rules if not exists
    $Applications = @(
        ($SteamLocation + "\steam.exe")
        ("C:\Program Files (x86)\Common Files\Steam\SteamService.exe")
        ($SteamLocation + "\bin\cef\cef.win7x64\steamwebhelper.exe")
        ($SteamLocation + "\bin\steamservice.exe")
    );

    ForEach ($exe in $Applications)
    {
        if ((Get-ChildItem $exe).count -eq 0)
        {
            Write-Error "'$exe' not found!"
            continue
        }

        $appRules = $NetRules |
            Where-Object { ([FirewallRule]$_).AppFilter.Program -eq $exe }
        
        if (($appRules | Where-Object { ([FirewallRule]$_).Rule.Direction -eq "Inbound" }).count -eq 0)
        {
            New-NetFirewallRule -DisplayName $RulesName -Program $exe -Direction Inbound -Action Block
            Write-Host "Steam blocking INBOUND rule for '$exe' is CREATED"
        }

        if (($appRules | Where-Object { ([FirewallRule]$_).Rule.Direction -eq "Outbound" }).count -eq 0)
        {
            New-NetFirewallRule -DisplayName $RulesName -Program $exe -Direction Outbound -Action Block
            Write-Host "Steam blocking OUTBOUND rule for '$exe' is CREATED"
        }
    }

    $NetRules = Get-FullNetFirewallRule $RulesName;
}

# Enable rules
ForEach ($element in $NetRules)
{
    Set-NetFirewallRule -Name ([FirewallRule]$element).Rule.Name -Enabled True
}

Write-Host "Steam blocking rules are ENABLED"
