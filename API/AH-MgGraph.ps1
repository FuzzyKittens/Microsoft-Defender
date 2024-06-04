Import-Module Microsoft.Graph.Security

Connect-MgGraph -Environment Global -Scopes "ThreatHunting.Read.All"

$query = @'
DeviceInfo
| where Timestamp > ago(30d)
| where OnboardingStatus == "Onboarded"
| where isnotempty(OSBuild)
| summarize Count=dcount(DeviceId) by OSPlatform
| sort by OSPlatform
'@

$response = Start-MgSecurityHuntingQuery -query $query
$results = $response.Results.AdditionalProperties | ConvertTo-Json | ConvertFrom-Json
$results | Select-Object * -ExcludeProperty '*odata*' | Export-Csv -Path 'C:\SomePath\results.csv' -NoTypeInformation
