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

& notepad.exe $env:TEMP\Groups.xml
& notepad.exe $env:TEMP\Rules.xml
```

To see what the status is of Device Control on the endpoint and the last time it was updated, run the following:

```powershell
Get-MpComputerStatus | select DeviceControlState, DeviceControlDefaultEnforcement, DeviceControlPoliciesLastUpdated
```

Device Control Log location (MPDeviceControl-yyyymmdd-abcdef.log):

```
c:\ProgramData\Microsoft\Windows Defender\Support
```

For troubleshooting network config, these are the properties that are used in the check:

```powershell
Get-NetConnectionProfile 
```

For troubleshooting XML files for format errors:

```powershell
$rulesXML="C:\Policies\PolicyRules.xml"
$groupsXML="C:\Policies\Groups.xml"
$defenderPath= (Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows Defender" -Name "InstallLocation").InstallLocation

#Test PolicyRules
& $defenderPath\mpcmdrun.exe -devicecontrol -testpolicyxml $rulesXML -rules
#Test Groups
& $defenderPath\mpcmdrun.exe -devicecontrol -testpolicyxml $groupsXML -groups
```

For getting a clean report on Device Control actions from the Defender Portal using Advanced Hunting KQL:

```
//RemovableStoragePolicyTriggered: event triggered by Disk and file system level enforcement 
DeviceEvents 
| where ActionType == "RemovableStoragePolicyTriggered" 
| extend parsed=parse_json(AdditionalFields) 
| extend RemovableStorageAccess = tostring(parsed.RemovableStorageAccess) 
| extend RemovableStoragePolicyVerdict = tostring(parsed.RemovableStoragePolicyVerdict) 
| extend MediaBusType = tostring(parsed.BusType) 
| extend MediaClassGuid = tostring(parsed.ClassGuid) 
| extend MediaClassName = tostring(parsed.ClassName) 
| extend MediaDeviceId = tostring(parsed.DeviceId) 
| extend MediaInstanceId = tostring(parsed.DeviceInstanceId) 
| extend MediaName = tostring(parsed.MediaName) 
| extend RemovableStoragePolicy = tostring(parsed.RemovableStoragePolicy) 
| extend MediaProductId = tostring(parsed.ProductId) 
| extend MediaVendorId = tostring(parsed.VendorId) 
| extend MediaSerialNumber = tostring(parsed.SerialNumber) 
| distinct Timestamp, DeviceId, RemovableStoragePolicy, DeviceName, InitiatingProcessAccountName, ActionType, RemovableStorageAccess, RemovableStoragePolicyVerdict, MediaBusType, MediaClassGuid, MediaClassName, MediaDeviceId, MediaInstanceId, MediaName, MediaProductId, MediaVendorId, MediaSerialNumber, FolderPath, FileSize 
| summarize arg_max(Timestamp, *) by DeviceId, RemovableStoragePolicy, DeviceName, InitiatingProcessAccountName, ActionType, RemovableStorageAccess, RemovableStoragePolicyVerdict, MediaBusType, MediaClassGuid, MediaClassName, MediaDeviceId, MediaInstanceId, MediaName, MediaProductId, MediaVendorId, MediaSerialNumber, FolderPath, FileSize 
| project Timestamp, DeviceId, RemovableStoragePolicy, DeviceName, InitiatingProcessAccountName, ActionType, RemovableStorageAccess, RemovableStoragePolicyVerdict, MediaBusType, MediaClassGuid, MediaClassName, MediaDeviceId, MediaInstanceId, MediaName, MediaProductId, MediaVendorId, MediaSerialNumber, FolderPath, FileSize 
| order by Timestamp desc
```
