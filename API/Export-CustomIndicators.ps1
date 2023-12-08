#set the path for the export
$path = 'C:\Users\KoryKliner\Documents\CustomIndicators.csv'

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
        apiUri = 'https://api-gov.securitycenter.microsoft.us/api/indicators'
    }
}

#set the environment
$environment = $endpoints.public

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

#use native cmdlets to invoke webrequest to the api
$webResponse = Invoke-WebRequest -Method Get -Uri "$($environment.apiUri)" -Headers $headers -ErrorAction Stop -TimeoutSec $timeoutSecs

#get the response
$response =  $webResponse | ConvertFrom-Json

#get the results
$results = $response.Value

#change the object properties to string
$results | ForEach-Object {$_.rbacGroupNames = ($_.rbacGroupNames -join ';'); $_.rbacGroupIds = ($_.rbacGroupIds -join ';'); $_.mitreTechniques = ($_.mitreTechniques -join ';')}

$results | Export-Csv -Path $path
