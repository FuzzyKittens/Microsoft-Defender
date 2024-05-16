#region Windows Version

#endregion

#region Microsoft Defender for Endpoint
$mpComputerStatus = Get-MpComputerStatus

$result = [PSCustomObject]@{
    MDE_ServiceStatus = 'MsSense=' + (Get-Service -Name Sense).Status
    MDE_RealTimeProtectionEnabled = $mpComputerStatus.RealTimeProtectionEnabled
    MDE_DeviceId = (Get-ItemPropertyValue -Path 'HKLM:\SOFTWARE\Microsoft\Windows Advanced Threat Protection' -Name senseId) -replace "`n|\s"
    MDE_IsTamperProtected = $mpComputerStatus.IsTamperProtected
    MDE_RebootRequired = $mpComputerStatus.RebootRequired
}

#endregion

#region Microsoft Defender Antivirus
$mpAvStatus = Get-MpComputerStatus

$result | Add-Member -MemberType NoteProperty -Name MDAV_ServiceStatus -Value "WinDefend=$((Get-Service -Name WinDefend).Status)"
$result | Add-Member -MemberType NoteProperty -Name MDAV_Enabled -Value $mpAvStatus.AntivirusEnabled
$result | Add-Member -MemberType NoteProperty -Name MDAV_RunningMode -Value $mpAvStatus.AMRunningMode
$result | Add-Member -MemberType NoteProperty -Name MDAV_PlatformVersion -Value $mpAvStatus.AMProductVersion
$result | Add-Member -MemberType NoteProperty -Name MDAV_EngineVersion -Value $mpAvStatus.AMEngineVersion
$result | Add-Member -MemberType NoteProperty -Name MDAV_SignatureVersion -Value $mpAvStatus.AntivirusSignatureVersion
$result | Add-Member -MemberType NoteProperty -Name MDAV_SignatureLastUpdated -Value $mpAvStatus.AntivirusSignatureLastUpdated

#endregion

#region Windows Defender Firewall
$fw = Get-NetFirewallProfile

$fwProfiles = "Domain", "Private", "Public"
$fwRulesHashes = @{}
foreach ($profile in $fwProfiles) {
    $rules = Get-NetFirewallRule | Where-Object { $_.Profile -like "*$profile*" -or $_.Profile -like "*any*" }
    $bytes = [System.Text.Encoding]::UTF8.GetBytes($rules)
    $hash = (Get-FileHash -InputStream ([System.IO.MemoryStream]::new($bytes)) -Algorithm SHA1).Hash
    $fwRulesHashes[$profile] = $hash
}

foreach ($profile in $fwProfiles) {
    $result | Add-Member -MemberType NoteProperty -Name "WDFW_${profile}Profile_Enabled" -Value ($fw | Where-Object { $_.Name -eq $profile }).Enabled
    $result | Add-Member -MemberType NoteProperty -Name "WDFW_${profile}Profile_DefaultInboundAction" -Value ($fw | Where-Object { $_.Name -eq $profile }).DefaultInboundAction
    $result | Add-Member -MemberType NoteProperty -Name "WDFW_${profile}Profile_DefaultOutboundAction" -Value ($fw | Where-Object { $_.Name -eq $profile }).DefaultOutboundAction
    $result | Add-Member -MemberType NoteProperty -Name "WDFW_${profile}Profile_RulesHash" -Value $fwRulesHashes[$profile]
    $result | Add-Member -MemberType NoteProperty -Name "WDFW_${profile}Profile_AllowLocalFirewallRules" -Value ($fw | Where-Object { $_.Name -eq $profile }).AllowLocalFirewallRules
}

#endregion

#region Device Control
try {
    $policyRules = Get-ItemPropertyValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Policy Manager' -Name policyRules
    $bytes = [System.Text.Encoding]::UTF8.GetBytes($policyRules)
    $policyRulesHash = (Get-FileHash -InputStream ([System.IO.MemoryStream]::new($bytes)) -Algorithm SHA1).Hash
} catch {
    $policyRulesHash = 'Empty'
}

try {
    $policyGroups = Get-ItemPropertyValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Policy Manager' -Name policyGroups
    $bytes = [System.Text.Encoding]::UTF8.GetBytes($policyGroups)
    $policyGroupsHash = (Get-FileHash -InputStream ([System.IO.MemoryStream]::new($bytes)) -Algorithm SHA1).Hash
} catch {
    $policyGroupsHash = 'Empty'
}

$result | Add-Member -MemberType NoteProperty -Name DC_DeviceControlState -Value $mpComputerStatus.DeviceControlState
$result | Add-Member -MemberType NoteProperty -Name DC_DeviceControlDefaultEnforcement -Value $mpComputerStatus.DeviceControlDefaultEnforcement
$result | Add-Member -MemberType NoteProperty -Name DC_DeviceControlPoliciesLastUpdated -Value $mpComputerStatus.DeviceControlPoliciesLastUpdated
$result | Add-Member -MemberType NoteProperty -Name DC_PolicyRulesHash -Value $policyRulesHash
$result | Add-Member -MemberType NoteProperty -Name DC_PolicyGroupsHash -Value $policyGroupsHash

#endregion

#region Windows Defender Application Control
try {
    $wdac = (Get-CimInstance -ClassName Win32_DeviceGuard -Namespace root\Microsoft\Windows\DeviceGuard).UsermodeCodeIntegrityPolicyEnforcementStatus
    $modes = @{
        0 = 'Disabled'
        1 = 'Audit'
        2 = 'Enforced'
    }
    $wdacStatus = $modes.$wdac
} catch {
    $wdacStatus = 'Unable to retrieve'
}

$result | Add-Member -MemberType NoteProperty -Name WDAC_DefenderAppControlState -Value $wdacStatus

### get hash of policy

$singlePath = 'C:\Windows\System32\CodeIntegrity\CiPolicies'
$multiplePath = 'C:\Windows\System32\CodeIntegrity\CiPolicies\Active'

if (Test-Path -Path $singlePath) {
    $ciPolicies = Get-ChildItem -Path $singlePath -Include *.cip
    if ($ciPolicies) {
        $ciPolicyType = 'Single'
    }
    elseif (Test-Path -Path $multiplePath) {
        $ciPolicies = Get-ChildItem -Path $multiplePath -Include *.cip
        if ($ciPolicies) {
            $ciPolicyType = 'Multiple'
        }
    }
    else {
    $ciPolicies = ''
    $ciPolicyType = 'None'
    }
}

if ($ciPolicies) {
    $hashes = $ciPolicies.Hash
    $hashConcat = ''
    foreach ($hash in $hashes) {
        $hashConcat += $hash
    }
    $bytes = [System.Text.Encoding]::UTF8.GetBytes($hashConcat)
    $ciPolicyHash = (Get-FileHash -InputStream ([System.IO.MemoryStream]::new($bytes)) -Algorithm SHA1).Hash
}

$result | Add-Member -MemberType NoteProperty -Name WDAC_DefenderAppControlPolicyType -Value $ciPolicyType
$result | Add-Member -MemberType NoteProperty -Name WDAC_DefenderAppControlPolicyHash -Value $ciPolicyHash


#endregion

#region Network Protection
$np = Get-ItemPropertyValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Policy Manager' -Name EnableNetworkProtection
$modes = @{
    0 = 'Disabled'
    1 = 'Enabled'
    2 = 'Audit'
}
$result | Add-Member -MemberType NoteProperty -Name NP_NetworkProtectionState -Value $modes.$np
#endregion

#region Controlled Folder Access
$cfa = Get-ItemPropertyValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Policy Manager' -Name EnableControlledFolderAccess
$modes = @{
    0 = 'Disabled'
    1 = 'Block'
    2 = 'Audit'
    3 = 'Block disk modification only'
    4 = 'Audit disk modification only'
}
$result | Add-Member -MemberType NoteProperty -Name CFA_ControlledFolderAccessState -Value $modes.$cfa
#endregion

#region ASR Rules

try {
    $asrRules = Get-ItemPropertyValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Policy Manager' -Name ASRRules
    $bytes = [System.Text.Encoding]::UTF8.GetBytes($asrRules)
    $asrRulesHash = (Get-FileHash -InputStream ([System.IO.MemoryStream]::new($bytes)) -Algorithm SHA1).Hash
} catch {
    $asrRulesHash = 'Empty'
}

try {
    $asrOnlyExclusions = Get-ItemPropertyValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Policy Manager' -Name ASROnlyExclusions
    $bytes = [System.Text.Encoding]::UTF8.GetBytes($asrOnlyExclusions)
    $asrOnlyExclusionsHash = (Get-FileHash -InputStream ([System.IO.MemoryStream]::new($bytes)) -Algorithm SHA1).Hash
} catch {
    $asrOnlyExclusionsHash = 'Empty'
}

try {
    $asrOnlyPerRuleExclusions = Get-ItemPropertyValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Policy Manager' -Name ASROnlyPerRuleExclusions
    $bytes = [System.Text.Encoding]::UTF8.GetBytes($asrOnlyPerRuleExclusions)
    $asrOnlyPerRuleExclusionsHash = (Get-FileHash -InputStream ([System.IO.MemoryStream]::new($bytes)) -Algorithm SHA1).Hash
} catch {
    $asrOnlyPerRuleExclusionsHash = 'Empty'
}

$result | Add-Member -MemberType NoteProperty -Name ASR_ASRRulesHash -Value $asrRulesHash
$result | Add-Member -MemberType NoteProperty -Name ASR_ASROnlyExclusionsHash -Value $asrOnlyExclusionsHash
$result | Add-Member -MemberType NoteProperty -Name ASR_ASROnlyPerRuleExclusionsHash -Value $asrOnlyPerRuleExclusionsHash

#endregion

$result
