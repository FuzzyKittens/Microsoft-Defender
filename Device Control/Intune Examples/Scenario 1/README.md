# Scenario 1
## Use Cases:
1. Default Deny All
1. All users must have read access to all CDROM Devices
1. An Active Directory Group must have write access to all CDROM Devices
1. An Active Directory Group must have read access to a group of defined USB Mass Storage Devices
1. One or more Exception to Policy must allow a 1:1 ratio between an Active Directory user and a Specific Device

## Intune Custom CSP Policies:
| Policy | Description | OMA/URI | Value |
| --- | --- | --- | --- |
| 1 | Enable Device Control | ./Vendor/MSFT/Defender/Configuration/DeviceControlEnabled | 1 |
| 2 | Enable Default Deny | ./Vendor/MSFT/Defender/Configuration/DefaultEnforcement | 2 |
| 3 | Group_AllCdRomDevices | ./Vendor/MSFT/Defender/Configuration/DeviceControl/PolicyGroups/%7b6dd2869c-e369-46d2-83c0-cbc7251fd17d%7d/GroupData | [Group_AllCdRomDevices.xml](Group_AllCdRomDevices.xml) |
| 4 | Policy_AllCdRomDevices | ./Vendor/MSFT/Defender/Configuration/DeviceControl/PolicyRules/%7b28ef8811-f86e-4389-983a-524029b78370%7d/RuleData | [Policy_AllCdRomDevices.xml](Policy_AllCdRomDevices.xml) |
| 5 | Group_SpecificRemovableMediaDevices | ./Vendor/MSFT/Defender/Configuration/DeviceControl/PolicyGroups/%7b39a76f23-ccba-44ec-b131-941baf0ab689%7d/GroupData | [Group_SpecificRemovableMediaDevices.xml](Group_SpecificRemovableMediaDevices.xml) |
| 6 | Policy_SpecificRemovableMediaDevices | ./Vendor/MSFT/Defender/Configuration/DeviceControl/PolicyRules/%7b94935edf-e1d4-472b-afb0-088cee08810f%7d/RuleData | [Policy_SpecificRemovableMediaDevices.xml](Policy_SpecificRemovableMediaDevices.xml) |
| 7 | Group_ETP1_USBDevice | ./Vendor/MSFT/Defender/Configuration/DeviceControl/PolicyGroups/%7b9fb02d1c-54dd-47a8-974a-40135a2216c2%7d/GroupData | [Group_ETP1.xml](Group_ETP1.xml) |
| 8 | Policy_ETP1 | ./Vendor/MSFT/Defender/Configuration/DeviceControl/PolicyRules/%7b77ea6638-571e-4917-800c-8548ffaf6c42%7d/RuleData | [Policy_ETP1.xml](Policy_ETP1.xml) |
| 8 | Policy_AuditDefaultDeny | ./Vendor/MSFT/Defender/Configuration/DeviceControl/PolicyRules/%7b1fbdeb31-0bee-4e0a-a3f7-4ee2d85fe18e%7d/RuleData | [Policy_AuditDefaultDeny.xml](Policy_AuditDefaultDeny.xml) |
