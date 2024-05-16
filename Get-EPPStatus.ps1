function Get-MDEInfo {
    $mpComputerStatus = Get-MpComputerStatus
    $windowsVersion = (Get-CimInstance -ClassName Win32_OperatingSystem).Version
    $result = [PSCustomObject]@{
        WindowsVersion = $windowsVersion
        ServiceStatus = 'MsSense=' + (Get-Service -Name Sense).Status
        RealTimeProtectionEnabled = $mpComputerStatus.RealTimeProtectionEnabled
        DeviceId = (Get-ItemPropertyValue -Path 'HKLM:\SOFTWARE\Microsoft\Windows Advanced Threat Protection' -Name senseId) -replace "`n|\s"
        IsTamperProtected = $mpComputerStatus.IsTamperProtected
        RebootRequired = $mpComputerStatus.RebootRequired
    }
    return $result
}

function Get-MDAVInfo {
    $mpAvStatus = Get-MpComputerStatus
    if ($mpAvStatus.AntivirusEnabled) {
        $mpAvState = 'Enabled'
    }
    else {
        $mpAvState = 'Disabled'
    }
    $result = [PSCustomObject]@{
        State = $mpAvState
        ServiceStatus = "WinDefend=$((Get-Service -Name WinDefend).Status)"
        RunningMode = $mpAvStatus.AMRunningMode
        PlatformVersion = $mpAvStatus.AMProductVersion
        EngineVersion = $mpAvStatus.AMEngineVersion
        SignatureVersion = $mpAvStatus.AntivirusSignatureVersion
        SignatureLastUpdated = $mpAvStatus.AntivirusSignatureLastUpdated
    }
    return $result
}

function Get-WDFWInfo {
    $fw = Get-NetFirewallProfile

    $fwProfiles = "Domain", "Private", "Public"
    $fwRulesHashes = @{}
    foreach ($profile in $fwProfiles) {
        $rules = Get-NetFirewallRule | Where-Object { $_.Profile -like "*$profile*" -or $_.Profile -like "*any*" }
        $bytes = [System.Text.Encoding]::UTF8.GetBytes($rules)
        $hash = (Get-FileHash -InputStream ([System.IO.MemoryStream]::new($bytes)) -Algorithm SHA1).Hash
        $fwRulesHashes[$profile] = $hash
    }
    $result = [PSCustomObject]@{}

    foreach ($profile in $fwProfiles) {
        if (($fw | Where-Object { $_.Name -eq $profile }).Enabled.ToString() -eq 'True') {
            $fwState = 'Enabled'
        }
        else {
            $fwState = 'Disabled'
        }
        $result | Add-Member -MemberType NoteProperty -Name "${profile}Profile_State" -Value $fwState
        $result | Add-Member -MemberType NoteProperty -Name "${profile}Profile_DefaultInboundAction" -Value ($fw | Where-Object { $_.Name -eq $profile }).DefaultInboundAction.ToString()
        $result | Add-Member -MemberType NoteProperty -Name "${profile}Profile_DefaultOutboundAction" -Value ($fw | Where-Object { $_.Name -eq $profile }).DefaultOutboundAction.ToString()
        $result | Add-Member -MemberType NoteProperty -Name "${profile}Profile_RulesHash" -Value $fwRulesHashes[$profile]
        $result | Add-Member -MemberType NoteProperty -Name "${profile}Profile_AllowLocalFirewallRules" -Value ($fw | Where-Object { $_.Name -eq $profile }).AllowLocalFirewallRules.ToString()
    }
    return $result
}

function Get-WDACInfo {
    try {
        [Int32]$wdac = (Get-CimInstance -ClassName Win32_DeviceGuard -Namespace root\Microsoft\Windows\DeviceGuard).UsermodeCodeIntegrityPolicyEnforcementStatus
        $modes = @{
            0 = 'Disabled'
            1 = 'Audit'
            2 = 'Enforced'
        }
        $wdacStatus = $modes.$wdac
    } catch {
        $wdacStatus = 'Unable to retrieve'
    }
    
    $singlePath = 'C:\Windows\System32\CodeIntegrity\CiPolicies'
    $multiplePath = 'C:\Windows\System32\CodeIntegrity\CiPolicies\Active'

    if (Test-Path -Path $singlePath) {
        $ciPolicies = Get-ChildItem -Path "$singlePath\*.cip"
        if ($ciPolicies) {
            $ciPolicyType = 'Single'
        }
        elseif (Test-Path -Path $multiplePath) {
            $ciPolicies = Get-ChildItem -Path "$multiplePath\*.cip"
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
    $result = [PSCustomObject]@{
        State=$wdacStatus
        PolicyType = $ciPolicyType
        PolicyHash = $ciPolicyHash
    }
    return $result
}

function Get-DCInfo {
    $mpComputerStatus = Get-MpComputerStatus
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
    $result = [PSCustomObject]@{
        State=$mpComputerStatus.DeviceControlState
        DefaultEnforcement=$mpComputerStatus.DeviceControlDefaultEnforcement
        PoliciesLastUpdated=$mpComputerStatus.DeviceControlPoliciesLastUpdated
        PolicyRulesHash=$policyRulesHash
        PolicyGroupsHash=$policyGroupsHash
    }
    return $result
}

function Get-NPInfo {
    $np = Get-ItemPropertyValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Policy Manager' -Name EnableNetworkProtection
    $modes = @{
        0 = 'Disabled'
        1 = 'Enabled'
        2 = 'Audit'
    }
    $result = [PSCustomObject]@{
        State=$modes.$np
    }
    return $result
}

function Get-CFAInfo {
    $cfa = Get-ItemPropertyValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Policy Manager' -Name EnableControlledFolderAccess
    $modes = @{
        0 = 'Disabled'
        1 = 'Block'
        2 = 'Audit'
        3 = 'Block disk modification only'
        4 = 'Audit disk modification only'
    }
    $result = [PSCustomObject]@{
        State=$modes.$cfa
    }
    return $result
}

function Get-ASRInfo {
    try {
        $asrRules = Get-ItemPropertyValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Policy Manager' -Name ASRRules
        $bytes = [System.Text.Encoding]::UTF8.GetBytes($asrRules)
        $asrRulesHash = (Get-FileHash -InputStream ([System.IO.MemoryStream]::new($bytes)) -Algorithm SHA1).Hash
        $asrState = 'Enabled'
    } catch {
        $asrState = 'Disabled'
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
    
    $result = [PSCustomObject]@{
        State = $asrState
        RulesHash = $asrRulesHash
        OnlyExclusionsHash = $asrOnlyExclusionsHash
        OnlyPerRuleExclusionsHash = $asrOnlyPerRuleExclusionsHash
    }
    return $result
}

function Get-EPPInfo {
    param (
        [parameter()]
        [switch]$Flat
    )
    $result = [PSCustomObject]@{
        MDE = Get-MDEInfo
        MDAV = Get-MDAVInfo
        WDFW = Get-WDFWInfo
        WDAC = Get-WDACInfo
        DC = Get-DCInfo
        NP = Get-NPInfo
        CFA = Get-CFAInfo
        ASR = Get-ASRInfo
    }
    if ($Flat) {
            $resultFlat = [PSCustomObject]@{}
            foreach ($category in $result.PSObject.Properties.Name) {
                foreach ($property in $result.$category.PSObject.Properties.Name) {
                $resultFlat | Add-Member -MemberType NoteProperty -Name "${category}_${property}" -Value $result.$category.$property
            }
        }
    return $resultFlat
    }
    return $result
}
