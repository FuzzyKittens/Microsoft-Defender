# Device Control

## Useful Troubleshooting

The Device Control policies, whether delivered through Intune or Group Policy, can be found in XML format on the local machine in the registry at the following path:

HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows Defender\Policy Manager

In this registry key, there are 2 REG_SZ that contain the curent **PolicyGroups** and **PolicyRules** applied.  To view these quickly using PowerShell, run the following:

```powershell
$regPath = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Policy Manager'
$policyGroups = Get-ItemPropertyValue -Path $regPath -Name PolicyGroups
$policyRules = Get-ItemPropertyValue -Path $regPath -Name PolicyRules

$policyGroups | Out-File $env:TEMP\Groups.xml -Force
$policyRules | Out-File $env:TEMP\Rules.xml -Force

notepad.exe $env:TEMP\Groups.xml
notepad.exe $env:TEMP\Rules.xml
```

To see what the status is of Device Control on the endpoint and the last time it was updated, run the following:

```powershell
Get-MpComputerStatus | select DeviceControlState, DeviceControlDefaultEnforcement, DeviceControlPoliciesLastUpdated
```

For troubleshooting network config, these are the properties that are used in the check:

```powershell
Get-NetConnectionProfile 
```
