# SteamFirewallBlocker
Semi-automatic PowerShell scripts that create and control firewall rules that blocking Steam App

## Using

1. Open `EnableSteamBlockInFirewall.ps1` in editor
2. Change path in row `$SteamLocation = $null` to your steam instal location. (example: `$SteamLocation = "G:\Steam"`)
3. Save script and run. 
4. After that firewall will block all incoming and outgoind connection for Steam App
5. If you need to disable rules run `DisableSteamBlockInFirewall.ps1` script

## Uninstall
1. Open firewall control panel (<kbd>Win</kbd>+<kbd>R</kbd>, input `WF.msc` and press <kbd>Enter</kbd>)
2. Open rules for incoming connection
3. Find rules named as `ZS_SteamLock` and delete them
4. Repeat step 2 and 3 in outgoing connection tab
