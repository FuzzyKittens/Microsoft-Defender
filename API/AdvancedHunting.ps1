#set timeout seconds, adjust as necessary
$timeoutSecs = 600

#endpoints - fill in approprate tenantIds and registered app info
$endpoints = @{
    public = @{
        tenantId   = ''
        appId      = ''
        appSecret  = ''
        appIdUri   = 'https://api.securitycenter.microsoft.com'
        oAuthUri   = 'https://login.microsoftonline.com'
        huntingUri = 'https://api.securitycenter.microsoft.com/api/advancedqueries/run'
    }
    gcc = @{
        tenantId   = ''
        appId      = ''
        appSecret  = ''
        appIdUri   = 'https://api-gcc.securitycenter.microsoft.us'
        oAuthUri   = 'https://login.microsoftonline.us'
        huntingUri = 'https://api-gcc.securitycenter.microsoft.us/api/advancedqueries/run'
    }
    gccHighDoD = @{
        tenantId   = ''
        appId      = ''
        appSecret  = ''
        appIdUri   = 'https://api-gov.securitycenter.microsoft.us'
        oAuthUri   = 'https://login.microsoftonline.us'
        huntingUri = 'https://api-gov.securitycenter.microsoft.us/api/advancedqueries/run'
    }
}

#set the environment
$environment = $endpoints.public

#the Query
$query = @"
DeviceInfo
| where Timestamp > ago(30d)
| where OnboardingStatus == "Onboarded"
| where isnotempty(OSBuild)
| summarize Count=dcount(DeviceId) by OSPlatform
| sort by OSPlatform
"@

#create auth body for token
$authBody = [Ordered] @{
    resource = "$($environment.appIdUri)"
    client_id = "$($environment.appId)"
    client_secret = "$($environment.appSecret)"
    grant_type = 'client_credentials'
}

#get token
$authResponse = Invoke-RestMethod -Method Post -Uri "$($environment.oAuthUri)/$($environment.tenantId)/oauth2/token" -Body $authBody -ErrorAction Stop
$token = $authResponse.access_token

#create auth header
$headers = @{ 
    'Content-Type' = 'application/json'
    Accept = 'application/json'
    Authorization = "Bearer $token" 
}

#create json body
$body = ConvertTo-Json -InputObject @{ 'Query' = $query }

#use native cmdlets to invoke webrequest to the api
$webResponse = Invoke-WebRequest -Method Post -Uri "$($environment.huntingUri)" -Headers $headers -Body $body -ErrorAction Stop -TimeoutSec $timeoutSecs

#get the response
$response =  $webResponse | ConvertFrom-Json

#get the results
$results = $response.Results
