<# 
 .SYNOPSIS
  Get client secret and certificate data from App Registrations and SAML signing certificates

 .DESCRIPTION
  This script retrieves the client secret and certificate end dates (including other relevant data) from App Registrations and SAML signing certificates (Enterprise Applications)
  in an Azure tenant.
  The created hash table is then sent to the Log Analytics workspace that is linked to the Runbook's Automation account. Logs can then be scheduled to send a reminder to
  an alert group via Azure Monitor or Azure Sentinel, e.g. an email can be sent to the service desk 60 days before a certificate expires.
  This script is also useful in cleaning up obsolete App Registrations and SAML SSO connections that are no longer being used.

  The data is retrieved via Az and Azure cmdlets via Managed Identity which makes this script easy to maintain.

 .REQUIREMENTS
  The following PowerShell modules and versions need to be installed in the Azure Automation account prior to deployment.
  Az.Accounts v2.8.0, runtime 5.1 (should already be installed)
  Az.Resources v6.0.0, runtime 5.1 (should already be installed)
  Microsoft.Graph.Authentication v1.28.0, runtime 5.1 (install manually)
  Microsoft.Graph.Applications v1.28.0, runtime 5.1 (install manually)
  Newer versions of these modules might not be supported. The below script might fail.

 .PARAMETER
  None

 .EXAMPLE
  Execute within Azure Automation runbook - no interactivity

 .INPUTS 
  None

 .OUTPUTS
  Results to Log Analytics and then to Azure Monitor or Azure Sentinel

 .NOTES
  v0.6 - Adjust script to use Graph API PowerShell
  v0.5 - Add version requirement of Az modules, adjust script to be compatible with updated Az modules
  v0.4 - Add "Source" key/value pair to both hash tables to make it easier to determine the location of the expiration object (App Registration or SAML SSO)
  v0.3 - Adjust script and add integration of SAML SSO certificate expiration
  v0.2 - Fork and modify repo below to implement authentication via Managed Identity on 10/15/2021
  v0.1 - Credit goes to https://github.com/Cj-Scott/Get-AppRegistrationExpiration
#>

Function _SendToLogAnalytics{
    Param(
        [string]$customerId,
        [string]$sharedKey,
        [string]$logs,
        [string]$logType,
        [string]$timeStampField
    )
        # Generate the body for the Invoke-WebRequest
        $body = ([System.Text.Encoding]::UTF8.GetBytes($logs))
        $method = "POST"
        $contentType = "application/json"
        $resource = "/api/logs"
        $rfc1123date = [DateTime]::UtcNow.ToString("r")
        $contentLength = $body.Length

        #Create the encoded hash to be used in the authorization signature
        $xHeaders = "x-ms-date:" + $rfc1123date
        $stringToHash = $method + "`n" + $contentLength + "`n" + $contentType + "`n" + $xHeaders + "`n" + $resource
        $bytesToHash = [Text.Encoding]::UTF8.GetBytes($stringToHash)
        $keyBytes = [Convert]::FromBase64String($sharedKey)
        $sha256 = New-Object System.Security.Cryptography.HMACSHA256
        $sha256.Key = $keyBytes
        $calculatedHash = $sha256.ComputeHash($bytesToHash)
        $encodedHash = [Convert]::ToBase64String($calculatedHash)
        $authorization = 'SharedKey {0}:{1}' -f $customerId,$encodedHash

        # Create the uri for the data insertion endpoint for the Log Analytics workspace
        $uri = "https://" + $customerId + ".ods.opinsights.azure.com" + $resource + "?api-version=2016-04-01"

        # Create the headers to be used in the Invoke-WebRequest
        $headers = @{
            "Authorization" = $authorization;
            "Log-Type" = $logType;
            "x-ms-date" = $rfc1123date;
            "time-generated-field" = $timeStampField;
        }
        
        # Try to send the logs to the Log Analytics workspace
        Try{
            $response = Invoke-WebRequest `
            -Uri $uri `
            -Method $method `
            -ContentType $contentType `
            -Headers $headers `
            -Body $body `
            -UseBasicParsing `
            -ErrorAction stop
        }
        # Catch any exceptions and write them to the output 
        Catch{
            Write-Error "$($_.Exception)"
            throw "$($_.Exception)" 
        }
        # Return the status code of the web request response
        return $response
}

## Connect to the M365 Tenant using Managed Identity in Automation Account ##

Try {
    Connect-AzAccount -Identity
    $context = [Microsoft.Azure.Commands.Common.Authentication.Abstractions.AzureRmProfileProvider]::Instance.Profile.DefaultContext
    $token = [Microsoft.Azure.Commands.Common.Authentication.AzureSession]::Instance.AuthenticationFactory.Authenticate($context.Account, $context.Environment, $context.Tenant.Id.ToString(), $null, [Microsoft.Azure.Commands.Common.Authentication.ShowDialog]::Never, $null, "https://graph.microsoft.com").AccessToken
    Connect-MgGraph -AccessToken $token
} catch {
    write-error "$($_.Exception)"
    throw "$($_.Exception)"
}

Write-output 'Gathering necessary information...'

# Get all App Registrations where PasswordCredentials value is not empty.
$applications = Get-AzADApplication | Where-Object {$_.PasswordCredentials}
# Get all Enterprise Apps where Tags and KeyCredentials values are not empty (managed identities are excluded).
$SAMLApplications = Get-MgServicePrincipal -All | Where-Object {$_.Tags -and $_.KeyCredentials} | Select ObjectId, AppId, DisplayName, KeyCredentials
$timeStamp = Get-Date -format o

# Create array with client secret/certificate data of all App Registrations
$appWithCredentials = @()
$appWithCredentials += $applications | Sort-Object -Property DisplayName | % {
    $application = $_
    $application | Select-Object `
    -Property @{Name='DisplayName'; Expression={$_.DisplayName}}, `
    @{Name='ObjectId'; Expression={$_.Id}}, `
    @{Name='ApplicationId'; Expression={$_.AppId}}, `
    @{Name='KeyId'; Expression={$_.PasswordCredentials[0].KeyId}}, `
    @{Name='Source'; Expression={"App Registration"}}, `
    @{Name='StartDate'; Expression={$_.PasswordCredentials[0].StartDateTime -as [datetime]}}, `
    @{Name='EndDate'; Expression={$_.PasswordCredentials[0].EndDateTime -as [datetime]}}
  }

# Append Enterprise Registration SAML/SSO certificate data to array
$appWithCredentials += $SAMLApplications | Sort-Object -Property DisplayName | % {
    $SAMLApplication = $_
    $SAMLApplication | Select-Object `
    -Property @{Name='DisplayName'; Expression={$_.DisplayName}}, `
    @{Name='ObjectId'; Expression={$_.ObjectId}}, `
    @{Name='ApplicationId'; Expression={$_.AppId}}, `
    @{Name='KeyId'; Expression={$_.KeyCredentials[0].KeyId}}, `
    @{Name='Source'; Expression={"SAML SSO Certificate"}}, `
    @{Name='StartDate'; Expression={$_.KeyCredentials[0].StartDate -as [datetime]}},`
    @{Name='EndDate'; Expression={$_.KeyCredentials[0].EndDate -as [datetime]}}
  }

Write-output 'Validating expiration data...'
$today = (Get-Date).ToUniversalTime()
$appWithCredentials | Sort-Object EndDate | % {
        if($_.EndDate -lt $today) {
            $days= ($_.EndDate-$Today).Days
            $_ | Add-Member -MemberType NoteProperty -Name 'Status' -Value 'Expired'
            $_ | Add-Member -MemberType NoteProperty -Name 'TimeStamp' -Value "$timestamp"
            $_ | Add-Member -MemberType NoteProperty -Name 'DaysToExpiration' -Value $days
        }  else {
            $days= ($_.EndDate-$Today).Days
            $_ | Add-Member -MemberType NoteProperty -Name 'Status' -Value 'Valid'
            $_ | Add-Member -MemberType NoteProperty -Name 'TimeStamp' -Value "$timestamp"
            $_ | Add-Member -MemberType NoteProperty -Name 'DaysToExpiration' -Value $days
        }
}

$audit = $appWithCredentials | convertto-json
$customerId= Get-AutomationVariable -Name 'LogAnalyticsWorkspaceID'
$sharedKey= Get-AutomationVariable -Name 'LogAnalyticsPrimaryKey'

_SendToLogAnalytics -CustomerId $customerId `
                    -SharedKey $sharedKey `
                    -Logs $audit `
                    -LogType "AppRegistrationExpiration" `
                    -TimeStampField "TimeStamp"
Write-Output 'Done.'
