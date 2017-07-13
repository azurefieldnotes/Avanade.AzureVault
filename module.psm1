$Script:DefaultVaultDomain = 'vault.azure.net'
$Script:UnixEpoch = New-Object DateTime(1970, 1, 1, 0, 0, 0, 0, [System.DateTimeKind]::Utc)

Function Invoke-AzureVaultRequest
{
    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory = $true,ValueFromPipelineByPropertyName = $true)]
        [string]$Uri,  
        [Parameter(Mandatory = $true,ValueFromPipelineByPropertyName = $true)]
        [string]$AccessToken,
        [ValidateNotNull()]
        [Parameter(Mandatory = $false,ValueFromPipelineByPropertyName = $true)]
        [System.Collections.IDictionary]
        $AdditionalHeaders,        
        [Parameter(Mandatory = $false,ValueFromPipelineByPropertyName = $true)]
        [Microsoft.PowerShell.Commands.WebRequestMethod]
        $Method = "GET",
        [Parameter(Mandatory = $false,ValueFromPipelineByPropertyName = $true)]
        [string]$NextLinkProperty = 'nextLink',
        [Parameter(Mandatory = $false,ValueFromPipelineByPropertyName = $true)]
        [string]$ValueProperty = 'value',
        [Parameter(Mandatory = $false,ValueFromPipelineByPropertyName = $true)]
        [string]$ErrorProperty = 'error',        
        [ValidateNotNull()]
        [Parameter(Mandatory = $false,ValueFromPipelineByPropertyName = $true)]
        [string]$Body,
        [Parameter(Mandatory = $false,ValueFromPipelineByPropertyName = $true)]
        [string]$ContentType = 'application/json',        
        [Parameter(Mandatory = $false,ValueFromPipelineByPropertyName = $true)]
        [switch]$AggregateResponses,
        [Parameter(Mandatory = $false,ValueFromPipelineByPropertyName = $true)]
        [switch]$ReturnHeaders,
        [Parameter(Mandatory = $false,ValueFromPipelineByPropertyName = $true)]
        [int]$RequestDelayMilliseconds = 100
    )
    $TotalItems = 0
    $RequestHeaders = $AdditionalHeaders
    $RequestHeaders['client-request-id'] = [Guid]::NewGuid().ToString()
    $RequestHeaders['User-Agent'] = "PowerShell $($PSVersionTable.PSVersion.ToString())"
    $RequestHeaders['Authorization'] = "Bearer $AccessToken"
    $BaseUri = "$($Uri.Scheme)://$($Uri.Host)"
    $RequestParams = @{
        Headers     = $RequestHeaders;
        Uri         = $Uri;
        ContentType = $ContentType;
        Method      = $Method;
    }
    if ($Body -ne $null)
    {
        $RequestParams['Body'] = $Body
    }
    $RequestResult = $null
    try
    {
        $Response = Invoke-WebRequest @RequestParams -UseBasicParsing -ErrorAction Stop
        Write-Verbose "[InvokeVaultRequest]$Method $Uri Response:$($Response.StatusCode)-$($Response.StatusDescription) Content-Length:$($Response.RawContentLength)"
        $RequestResult = Invoke-Command -ScriptBlock $ContentAction -ArgumentList $Response.Content|ConvertFrom-Json
    }
    catch
    {
        #See if we can unwind an exception from a response
        if ($_.Exception.Response -ne $null)
        {
            $ExceptionResponse = $_.Exception.Response
            $ErrorStream = $ExceptionResponse.GetResponseStream()
            $ErrorStream.Position = 0
            $StreamReader = New-Object System.IO.StreamReader($ErrorStream)
            try
            {
                $ErrorContent = $StreamReader.ReadToEnd()
                $StreamReader.Close()
                if (-not [String]::IsNullOrEmpty($ErrorContent))
                {
                    $ErrorObject = $ErrorContent|ConvertFrom-Json
                    if (-not [String]::IsNullOrEmpty($ErrorProperty) -and $ErrorObject.PSobject.Properties.name -match $ErrorProperty)
                    {
                        $ErrorContent = ($ErrorObject|Select-Object -ExpandProperty $ErrorProperty)|ConvertTo-Json
                    }
                }
            }
            catch
            {
            }
            finally
            {
                $StreamReader.Close()
            }
            $ErrorMessage = "Error: $($ExceptionResponse.Method) $($ExceptionResponse.ResponseUri) Returned $($ExceptionResponse.StatusCode) $ErrorContent"
        }
        else
        {
            $ErrorMessage = "An error occurred $_"
        }
        Write-Verbose "[InvokeVaultRequest] $ErrorMessage"
        throw $ErrorMessage
    }
    #Should never get here null
    if ($RequestResult -ne $null)
    {
        if ($ReturnHeaders.IsPresent)
        {
            return $Response.Headers
        }
        else
        {
            if ($RequestResult.PSobject.Properties.name -match $ValueProperty)
            {
                $Result = $RequestResult|Select-Object -ExpandProperty $ValueProperty
                $TotalItems += $Result.Count
                Write-Output $Result
            }
            else
            {
                Write-Output $RequestResult
                $TotalItems++ #not sure why I am incrementing..
            }
            #Loop to aggregate OData continutation tokens
            while ($RequestResult.PSobject.Properties.name -match $NextLinkProperty)
            {
                #Throttle the requests a bit..
                Start-Sleep -Milliseconds $RequestDelayMilliseconds
                $ResultPages++
                $UriBld = New-Object System.UriBuilder($BaseUri)
                $NextUri = $RequestResult|Select-Object -ExpandProperty $NextLinkProperty
                if ($LimitResultPages -gt 0 -and $ResultPages -eq $LimitResultPages -or [String]::IsNullOrEmpty($NextUri))
                {
                    break
                }
                Write-Verbose "[InvokeVaultRequest] Item Count:$TotalItems Page:$ResultPages More Items available @ $NextUri"
                #Is this an absolute or relative uri?
                if ($NextUri -match "$BaseUri*")
                {
                    $UriBld = New-Object System.UriBuilder($NextUri)
                }
                else
                {
                    $Path = $NextUri.Split('?')|Select-Object -First 1
                    $NextQuery = [Uri]::UnescapeDataString(($NextUri.Split('?')|Select-Object -Last 1))
                    $UriBld.Path = $Path
                    $UriBld.Query = $NextQuery
                }
                try
                {
                    $RequestParams['Uri'] = $UriBld.Uri
                    $Response = Invoke-WebRequest @RequestParams -UseBasicParsing -ErrorAction Stop
                    Write-Verbose "[InvokeVaultRequest]$Method $Uri Response:$($Response.StatusCode)-$($Response.StatusDescription) Content-Length:$($Response.RawContentLength)"
                    $RequestResult = Invoke-Command -ScriptBlock $ContentAction -ArgumentList $Response.Content|ConvertFrom-Json
                    if ($RequestResult.PSobject.Properties.name -match $ValueProperty)
                    {
                        $Result = $RequestResult|Select-Object -ExpandProperty $ValueProperty
                        $TotalItems += $Result.Count
                        Write-Output $Result
                    }
                    else
                    {
                        Write-Output $RequestResult
                        $TotalItems++ #not sure why I am incrementing..
                    }
                }
                catch
                {
                    #See if we can unwind an exception from a response
                    if ($_.Exception.Response -ne $null)
                    {
                        $ExceptionResponse = $_.Exception.Response
                        $ErrorStream = $ExceptionResponse.GetResponseStream()
                        $ErrorStream.Position = 0
                        $StreamReader = New-Object System.IO.StreamReader($ErrorStream)
                        try
                        {
                            $ErrorContent = $StreamReader.ReadToEnd()
                            $StreamReader.Close()
                            if (-not [String]::IsNullOrEmpty($ErrorContent))
                            {
                                $ErrorObject = $ErrorContent|ConvertFrom-Json
                                if (-not [String]::IsNullOrEmpty($ErrorProperty) -and $ErrorObject.PSobject.Properties.name -match $ErrorProperty)
                                {
                                    $ErrorContent = ($ErrorObject|Select-Object -ExpandProperty $ErrorProperty)|ConvertTo-Json
                                }
                            }
                        }
                        catch
                        {
                        }
                        finally
                        {
                            $StreamReader.Close()
                        }
                        $ErrorMessage = "Error: $($ExceptionResponse.Method) $($ExceptionResponse.ResponseUri) Returned $($ExceptionResponse.StatusCode) $ErrorContent"
                    }
                    else
                    {
                        $ErrorMessage = "An error occurred $_"
                    }
                    Write-Verbose "[InvokeVaultRequest] $ErrorMessage"
                    throw $ErrorMessage
                }
            }            
        }
    }
}

Function New-AzureVaultKeyParameters
{
    [CmdletBinding()]
    param
    (
        [ValidateSet('EC', 'RSA', 'RSA-HSM', 'oct')]
        [Parameter(Mandatory = $false,ValueFromPipelineByPropertyName = $true)]
        [String]$KeyType = 'RSA',
        [Parameter(Mandatory = $true,ValueFromPipelineByPropertyName = $true)]
        [String]$KeyName,
        [Parameter(Mandatory = $true,ValueFromPipelineByPropertyName = $true)]
        [String[]]$KeyOperations,        
        [Parameter(Mandatory = $false,ValueFromPipelineByPropertyName = $true)]
        [datetime]$NotBefore = [datetime]::UtcNow,
        [Parameter(Mandatory = $false,ValueFromPipelineByPropertyName = $true)]
        [int]$ExpiryInDays = 365,
        [Parameter(Mandatory = $false,ValueFromPipelineByPropertyName = $true)]
        [int]$Epoch = $Script:UnixEpoch,        
        [Parameter(Mandatory = $true,ValueFromPipelineByPropertyName = $true)]
        [ValidateSet(1024,2048)]
        [int]$KeySize,
        [Parameter(Mandatory = $false,ValueFromPipelineByPropertyName = $true)]
        [System.Collections.IDictionary]$Tags        
    )
    $NewKeyType = @{
        'type' = $KeyType;
    }
    $NewKeyAttributes = New-Object PSObject -Property @{
        'enabled' = $true;
        'nbf'     = $(($NotBefore - $Epoch).TotalSeconds);
        'exp'     = $((($NotBefore.AddDays($ExpiryInDays)) - $Epoch).TotalSeconds);
    }
    $NewKeyParams = New-Object PSObject -Property @{
        'kty'        = $NewKeyType;
        'key_size'   = $KeySize;
        'attributes' = $NewKeyAttributes;
        'tags'       = $Tags;
    }
    Write-Output $NewKeyParams
}

Function New-AzureVaultCertificateParameters
{
    [CmdletBinding()]
    param
    (
        [ValidateSet('EC', 'RSA', 'RSA-HSM', 'oct')]
        [Parameter(Mandatory = $false,ValueFromPipelineByPropertyName = $true)]
        [String]$KeyType = 'RSA',        
        [Parameter(Mandatory = $true,ValueFromPipelineByPropertyName = $true)]
        [String[]]$KeyUsage,
        [Parameter(Mandatory = $false,ValueFromPipelineByPropertyName = $true)]
        [String[]]$EnhancedKeyUsage,
        #[ValidateSet('Self','Unknown','DigiCert','GlobalSign','WoSign')] 
        [Parameter(Mandatory = $false,ValueFromPipelineByPropertyName = $true)]
        [String]$Issuer = 'Self',
        [Parameter(Mandatory = $false,ValueFromPipelineByPropertyName = $true)]
        [String]$Enabled = $true,        
        [ValidateSet('OV-SSL','EV-SSL')]
        [Parameter(Mandatory = $false,ValueFromPipelineByPropertyName = $true)]
        [String]$IssuerCertType = 'OV-SSL',        
        [Parameter(Mandatory = $true,ValueFromPipelineByPropertyName = $true)]
        [String]$Subject,
        [Parameter(Mandatory = $true,ValueFromPipelineByPropertyName = $true)]
        [String[]]$SubjectAlternateNameEmails,
        [Parameter(Mandatory = $true,ValueFromPipelineByPropertyName = $true)]
        [String[]]$SubjectAlternateNameUpns,
        [Parameter(Mandatory = $true,ValueFromPipelineByPropertyName = $true)]
        [String[]]$SubjectAlternateNameDnsNames,        
        [ValidateSet('EmailContacts', 'AutoRenew')]
        [Parameter(Mandatory = $false,ValueFromPipelineByPropertyName = $true)]
        [String]$LifetimeExpireActionType = 'AutoRenew',    
        [Parameter(Mandatory = $false,ValueFromPipelineByPropertyName = $true)]
        [datetime]$NotBefore = [datetime]::UtcNow,
        [Parameter(Mandatory = $false,ValueFromPipelineByPropertyName = $true)]
        [int]$ExpiryInDays = 365,
        [Parameter(Mandatory = $false,ValueFromPipelineByPropertyName = $true)]
        [int]$Epoch = $Script:UnixEpoch,        
        [Parameter(Mandatory = $false,ValueFromPipelineByPropertyName = $true)]
        [datetime]$Exportable = $false,
        [Parameter(Mandatory = $false,ValueFromPipelineByPropertyName = $true)]
        [datetime]$ReuseKey = $true,
        [Parameter(Mandatory = $true,ValueFromPipelineByPropertyName = $true)]
        [ValidateRange(1,99)]
        [int]$LifetimeExpirePercentage = 90,
        [Parameter(Mandatory = $true,ValueFromPipelineByPropertyName = $true)]
        [ValidateRange(1,90)]
        [int]$LifetimeDaysBeforeExpire = 7,        
        [Parameter(Mandatory = $false,ValueFromPipelineByPropertyName = $true)]
        [ValidateSet(1024,2048,4096)]
        [int]$KeySize = 2048,
        [Parameter(Mandatory = $false,ValueFromPipelineByPropertyName = $true)]
        [System.Collections.IDictionary]$Tags        
    )   
    begin
    {
        $ExpireTime = $NotBefore.AddDays($ExpiryInDays)
        $ValidityInMonths = ($ExpireTime.Month - $NotBefore.Month) + (12 * ($ExpireTime.Year - $NotBefore.Year))
        $NotBeforeUnix = $(($NotBefore - $Epoch).TotalSeconds)
        $ExpiryUnix = $(($ExpireTime - $Epoch).TotalSeconds)
    }    
    process
    {
        $IssuerProperties = [ordered]@{
            'name' = $Issuer;
        }
        if ($Issuer -notin 'Self','Unknown')
        {
            $IssuerProperties['cty'] = $IssuerCertType
        }
        $X509Properties = [ordered]@{
            'subject' = $Subject;
            'ekus'    = @($EnhancedKeyUsage);
            'sans'    = [ordered]@{
                'emails'    = @($SubjectAlternateNameEmails);
                'dns_names' = @($SubjectAlternateNameDnsNames);
                'upns'      = @($SubjectAlternateNameUpns);
            }
        }
        $LifetimeActionProperties = [ordered]@{
            'trigger' = @{'lifetime_percentage' = $LifetimeExpirePercentage;'days_before_expiry' = $LifetimeDaysBeforeExpire};
            'action'  = @{'action_type' = $LifetimeExpireActionType};
        }
        $AttributeProperties = [ordered]@{
            'enabled' = $Enabled;
            'nbf'     = $NotBeforeUnix;
            'exp'     = $ExpiryUnix;
        }
        $KeyProperties = [ordered]@{
            'exportable' = $Exportable;
            'kty'        = $KeyType;
            'key_size'   = $KeySize;
            'reuse_key'  = $ReuseKey;
        }
        $PolicyProps = [ordered]@{
            'key_props'        = $KeyProperties;
            'secret_props'     = @{'contentType' = ""};
            'x509_props'       = $X509Properties;
            'key_usage'        = @($KeyUsage);
            'validity_months'  = $ValidityInMonths;
            'lifetime_actions' = $LifetimeActionProperties;
            'issuer'           = $IssuerProperties;
            'attributes'       = $AttributeProperties;
            'tags'             = $Tags;

        }
        $CertParams = New-Object psobject -Property $PolicyProps
        Write-Output $CertParams
    }
}

Function New-AzureVaultSecretParameters
{
    [CmdletBinding()]
    param
    (    
        [Parameter(Mandatory = $true,ValueFromPipelineByPropertyName = $true)]
        [string]$Value,
        [Parameter(Mandatory = $false,ValueFromPipelineByPropertyName = $true)]
        [System.Collections.IDictionary]$Tags,
        [Parameter(Mandatory = $false,ValueFromPipelineByPropertyName = $true)]
        [string]$ContentType = 'password',
        [Parameter(Mandatory = $false,ValueFromPipelineByPropertyName = $true)]
        [bool]$Enabled = $true,
        [Parameter(Mandatory = $false,ValueFromPipelineByPropertyName = $true)]
        [datetime]$NotBefore = [datetime]::UtcNow,
        [Parameter(Mandatory = $false,ValueFromPipelineByPropertyName = $true)]
        [int]$ExpiryInDays = 90,
        [Parameter(Mandatory = $false,ValueFromPipelineByPropertyName = $true)]
        [int]$Epoch = $Script:UnixEpoch                
    )
    begin
    {
        $ExpireTime = $NotBefore.AddDays($ExpiryInDays)
        $NotBeforeUnix = $(($NotBefore - $Epoch).TotalSeconds)
        $ExpiryUnix = $(($ExpireTime - $Epoch).TotalSeconds)
    }
    process
    {
        $SecretAttributeProperties = [ordered]@{
            'enabled' = $Enabled;
            'nbf'     = $NotBeforeUnix;
            'exp'     = $ExpiryUnix;
        }        
        $VaultSecretProperties = [ordered]@{
            'value'       = $Value;
            'tags'        = $Tags;
            'contentType' = $ContentType;
            'attributes'  = $SecretAttributeProperties;
        }        
        $VaultSecret = New-Object PSobject -Property $VaultSecretProperties
        Write-Output $VaultSecret
    }
}

#Get Key

Function Get-AzureVaultKey
{
    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory = $true,ValueFromPipelineByPropertyName = $true)]
        [String]$VaultName,
        [Parameter(Mandatory = $false,ValueFromPipelineByPropertyName = $true)]
        [System.Uri]$VaultDomain = $Script:DefaultVaultDomain,
        [Parameter(Mandatory = $false,ValueFromPipeline = $true,ValueFromPipelineByPropertyName = $true)]
        [String[]]$KeyName,        
        [Parameter(Mandatory = $false,ValueFromPipelineByPropertyName = $true)]
        [String]$ApiVersion = '2016-10-01',
        [Parameter(Mandatory = $true,ValueFromPipelineByPropertyName = $true)]
        [String]$AccessToken,
        [Parameter(Mandatory = $false,ValueFromPipelineByPropertyName = $true)]
        [int]$MaxResults        
    )
    BEGIN
    {
        $VaultBaseUri="https://${VaultName}.${VaultDomain}"
        $VaultUriBld = New-Object System.UriBuilder($VaultBaseUri)
        $VaultUriBld.Query = "api-version=${ApiVersion}"
        $Headers = @{Accept = 'application/json'}
        $RequestParams = @{
            Method            = 'GET'
            AdditionalHeaders = $Headers;
            ContentType       = 'application/json';
        }
        Write-Verbose "[Get-AzureVaultKey] Retrieving key(s) from ${VaultBaseUri}"
    }
    PROCESS
    {
        if ($KeyName -ne $null)
        {
            foreach ($item in $KeyName)
            {
                $VaultUriBld.Path = "/keys/${item}"
                Write-Verbose "[Get-AzureVaultKey] Retreiving Key ${VaultBaseUri} -> ${item}"
                $Result = Invoke-AzureVaultRequest @RequestParams -Uri $VaultUriBld.Uri
                if ($Result -ne $null)
                {
                    Write-Output $Result
                }
            }
        }
        else
        {
            if($MaxResults -gt 0)
            {
                Write-Verbose "[Get-AzureVaultKey] Listing All Keys ${VaultBaseUri} -> MaxResults=${MaxResults}"
            }
            else {
                Write-Verbose "[Get-AzureVaultKey] Listing All Keys ${VaultBaseUri}"
            }
            $VaultUriBld.Path = "/keys"
            $VaultUriBld.Query = "api-version=${ApiVersion}&MaxResults=${MaxResults}"
            $Result = Invoke-AzureVaultRequest @RequestParams -Uri $VaultUriBld.Uri
            if ($Result -ne $null)
            {
                Write-Output $Result
            }          
        }
    }
}

#Create Key
Function New-AzureVaultKey
{
    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory = $true,ValueFromPipelineByPropertyName = $true)]
        [String]$VaultName,
        [ValidateSet('EC', 'RSA', 'RSA-HSM', 'oct')]
        [Parameter(Mandatory = $false,ValueFromPipelineByPropertyName = $true)]
        [String]$KeyType = 'RSA',
        [Parameter(Mandatory = $true,ValueFromPipelineByPropertyName = $true)]
        [String]$KeyName,
        [Parameter(Mandatory = $true,ValueFromPipelineByPropertyName = $true)]
        [String[]]$KeyOperations,        
        [Parameter(Mandatory = $false,ValueFromPipelineByPropertyName = $true)]
        [datetime]$NotBefore = [datetime]::UtcNow,
        [Parameter(Mandatory = $false,ValueFromPipelineByPropertyName = $true)]
        [int]$ExpiryInDays = 365,    
        [Parameter(Mandatory = $true,ValueFromPipelineByPropertyName = $true)]
        [ValidateSet(1024,2048)]
        [int]$KeySize,        
        [Parameter(Mandatory = $true,ValueFromPipelineByPropertyName = $true)]
        [String]$AccessToken,
        [Parameter(Mandatory = $false,ValueFromPipelineByPropertyName = $true)]
        [System.Collections.IDictionary]$Tags,        
        [Parameter(Mandatory = $false,ValueFromPipelineByPropertyName = $true)]
        [System.Uri]$VaultDomain = $Script:DefaultVaultDomain,
        [Parameter(Mandatory = $false,ValueFromPipelineByPropertyName = $true)]
        [String]$ApiVersion = '2016-10-01'
    )
    BEGIN
    {
        $VaultUriBld = New-Object System.UriBuilder("https://${VaultName}.${VaultDomain}")
        $VaultUriBld.Query = "api-version=${ApiVersion}"
        $VaultUriBld.Path = "/keys/${KeyName}/create"
        $Headers = @{Accept = 'application/json'}
    }
    PROCESS
    {
        $NewKeyBody = New-AzureVaultKeyParameters @{
            KeyType       = $KeyType;
            KeySize       = $KeySize;
            ExpiryInDays  = $ExpiryInDays;
            KeyOperations = $KeyOperations;
            NotBefore     = $NotBefore
        }
        $RequestParams = @{
            Uri               = $VaultUriBld.Uri;
            AdditionalHeaders = $Headers;
            Body              = $($NewKeyBody|ConvertTo-Json -Depth 10);
            Method            = 'PUT';
            ContentType       = 'application/json';
            ErrorAction       = 'STOP';
            AccessToken       = $AccessToken;
        }
        $Result = Invoke-AzureVaultRequest @RequestParams
        if ($Result -ne $null)
        {
            Write-Output $Result
        }
    }
}

#Delete Key
Function Remove-AzureVaultKey
{
    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory = $true,ValueFromPipelineByPropertyName = $true)]
        [String]$VaultName,
        [Parameter(Mandatory = $false,ValueFromPipelineByPropertyName = $true)]
        [System.Uri]$VaultDomain = $Script:DefaultVaultDomain,
        [Parameter(Mandatory = $true,ValueFromPipeline = $true,ValueFromPipelineByPropertyName = $true)]
        [String[]]$KeyName,        
        [Parameter(Mandatory = $false,ValueFromPipelineByPropertyName = $true)]
        [String]$ApiVersion = '2016-10-01',
        [Parameter(Mandatory = $true,ValueFromPipelineByPropertyName = $true)]
        [String]$AccessToken             
    )
    BEGIN
    {
        $VaultBaseUri="https://${VaultName}.${VaultDomain}"
        $VaultUriBld = New-Object System.UriBuilder($VaultBaseUri)
        $VaultUriBld.Query = "api-version=${ApiVersion}"
        $RequestParams = @{
            AdditionalHeaders = @{Accept = 'application/json'}
            ContentType       = 'application/json'
            AccessToken       = $AccessToken;
            Method            = 'DELETE';
            ErrorAction       = 'Stop';
        }
        Write-Verbose "[Remove-AzureVaultKey] Removing key(s) from ${VaultBaseUri}"
    }
    PROCESS
    {
        foreach ($item in $KeyName)
        {
            $VaultUriBld.Path = "/keys/${item}"
            Write-Verbose "[Remove-AzureVaultKey] Removing key ${item} from ${VaultBaseUri}"
            $Result = Invoke-AzureVaultRequest @RequestParams -Uri $VaultUriBld.Uri
            if ($Result -ne $null)
            {
                Write-Verbose "[Remove-AzureVaultKey] Successfully Removed key ${item} from ${VaultBaseUri}!"
                Write-Output $Result
            }
        }
    }   
}

#Get Secrets
Function Get-AzureVaultSecret
{
    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory = $true,ValueFromPipelineByPropertyName = $true)]
        [String]$VaultName,
        [Parameter(Mandatory = $false,ValueFromPipelineByPropertyName = $true)]
        [System.Uri]$VaultDomain = $Script:DefaultVaultDomain,
        [Parameter(Mandatory = $false,ValueFromPipeline = $true,ValueFromPipelineByPropertyName = $true)]
        [String[]]$SecretName,        
        [Parameter(Mandatory = $false,ValueFromPipelineByPropertyName = $true)]
        [String]$ApiVersion = '2016-10-01',
        [Parameter(Mandatory = $true,ValueFromPipelineByPropertyName = $true)]
        [String]$AccessToken,
        [Parameter(Mandatory = $false,ValueFromPipelineByPropertyName = $true)]
        [int]$MaxResults        
    )
    BEGIN
    {
        $VaultBaseUri="https://${VaultName}.${VaultDomain}"
        $VaultUriBld = New-Object System.UriBuilder($VaultBaseUri)
        $VaultUriBld.Query = "api-version=${ApiVersion}"
        $Headers = @{Accept = 'application/json'}
        $RequestParams = @{
            Method            = 'GET'
            AdditionalHeaders = $Headers;
            ContentType       = 'application/json';
        }
        Write-Verbose "[Get-AzureVaultSecret] Retrieving secret(s) from ${VaultBaseUri}"
    }
    PROCESS
    {
        if ($SecretName -ne $null)
        {
            foreach ($item in $SecretName)
            {
                $VaultUriBld.Path = "/secrets/${item}"
                Write-Verbose "[Get-AzureVaultSecret] Retreiving Secret ${VaultBaseUri} -> ${item}"
                $Result = Invoke-AzureVaultRequest @RequestParams -Uri $VaultUriBld.Uri
                if ($Result -ne $null)
                {
                    Write-Output $Result
                }                    
            }    
        }
        else
        {
            if($MaxResults -gt 0)
            {
                Write-Verbose "[Get-AzureVaultSecret] Listing All Secrets ${VaultBaseUri} -> MaxResults=${MaxResults}"
            }
            else {
                Write-Verbose "[Get-AzureVaultSecret] Listing All Secrets ${VaultBaseUri}"
            }            
            $Result = Invoke-AzureVaultRequest @RequestParams -Uri $VaultUriBld.Uri
            if ($Result -ne $null)
            {
                Write-Output $Result
            }
        }
    }    
}
#Create Secret
Function New-AzureVaultSecret
{
    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory = $true,ValueFromPipelineByPropertyName = $true)]
        [String]$VaultName,
        [Parameter(Mandatory = $false,ValueFromPipelineByPropertyName = $true)]
        [System.Uri]$VaultDomain = $Script:DefaultVaultDomain,
        [Parameter(Mandatory = $true,ValueFromPipelineByPropertyName = $true)]
        [String]$SecretName,
        [Parameter(Mandatory = $true,ValueFromPipelineByPropertyName = $true)]
        [string]$Value,
        [Parameter(Mandatory = $false,ValueFromPipelineByPropertyName = $true)]
        [System.Collections.IDictionary]$Tags,
        [Parameter(Mandatory = $false,ValueFromPipelineByPropertyName = $true)]
        [string]$ContentType = 'password',
        [Parameter(Mandatory = $false,ValueFromPipelineByPropertyName = $true)]
        [bool]$Enabled = $true,
        [Parameter(Mandatory = $false,ValueFromPipelineByPropertyName = $true)]
        [datetime]$NotBefore = [datetime]::UtcNow,
        [Parameter(Mandatory = $false,ValueFromPipelineByPropertyName = $true)]
        [int]$ExpiryInDays = 90,        
        [Parameter(Mandatory = $false,ValueFromPipelineByPropertyName = $true)]
        [String]$ApiVersion = '2016-10-01',
        [Parameter(Mandatory = $true,ValueFromPipelineByPropertyName = $true)]
        [String]$AccessToken             
    )
    BEGIN
    {
        $VaultUriBld = New-Object System.UriBuilder("https://${VaultName}.${VaultDomain}")
        $VaultUriBld.Query = "api-version=${ApiVersion}"
        $VaultUriBld.Path = "/secrets/$SecretName"
        $RequestParams = @{
            Method            = 'PUT'
            AdditionalHeaders = @{Accept = 'application/json'};
            ContentType       = 'application/json';
            Uri               = $VaultUriBld.Uri;
            ErrorAction       = 'Stop';
        }        
    }
    PROCESS
    {
        #Build the object
        $SecretParams = [ordered]@{

        }
        $NewSecret = New-Object psobject -Property $SecretParams
        $RequestParams['Body'] = $NewSecret|ConvertTo-Json -Depth 10
        $Result = Invoke-AzureVaultRequest @RequestParams
        if ($Result -ne $null)
        {
            Write-Output $Result
        }
    }    
}

#Delete Secret
Function Remove-AzureVaultSecret
{
    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory = $true,ValueFromPipelineByPropertyName = $true)]
        [String]$VaultName,
        [Parameter(Mandatory = $false,ValueFromPipelineByPropertyName = $true)]
        [System.Uri]$VaultDomain = $Script:DefaultVaultDomain,
        [Parameter(Mandatory = $true,ValueFromPipeline = $true,ValueFromPipelineByPropertyName = $true)]
        [String[]]$SecretName,
        [Parameter(Mandatory = $false,ValueFromPipelineByPropertyName = $true)]
        [String]$ApiVersion = '2016-10-01',
        [Parameter(Mandatory = $true,ValueFromPipelineByPropertyName = $true)]
        [String]$AccessToken             
    )
    BEGIN
    {
        $VaultBaseUri="https://${VaultName}.${VaultDomain}"
        $VaultUriBld = New-Object System.UriBuilder($VaultBaseUri)
        $VaultUriBld.Query = "api-version=${ApiVersion}"
        $RequestParams = @{
            AdditionalHeaders = @{Accept = 'application/json'}
            ContentType       = 'application/json'
            AccessToken       = $AccessToken;
            Method            = 'DELETE';
            ErrorAction       = 'Stop';
        }
        Write-Verbose "[Remove-AzureVaultSecret] Removing secret(s) from ${VaultBaseUri}"
    }
    PROCESS
    {
        foreach ($item in $SecretName)
        {
            $VaultUriBld.Path = "/secrets/${item}"
            Write-Verbose "[Remove-AzureVaultSecret] Removing secret ${item} from ${VaultBaseUri}"
            $Result = Invoke-AzureVaultRequest @RequestParams -Uri $VaultUriBld.Uri
            if ($Result -ne $null)
            {
                Write-Verbose "[Remove-AzureVaultSecret] Successfully Removed secret ${item} from ${VaultBaseUri}!"
                Write-Output $Result
            }
        }
    }    
}

#Get Certificate
Function Get-AzureVaultCertificate
{
    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory = $true,ValueFromPipelineByPropertyName = $true)]
        [String]$VaultName,
        [Parameter(Mandatory = $false,ValueFromPipelineByPropertyName = $true)]
        [System.Uri]$VaultDomain = $Script:DefaultVaultDomain,
        [Parameter(Mandatory = $false,ValueFromPipeline = $true,ValueFromPipelineByPropertyName = $true)]
        [String[]]$CertificateName,        
        [Parameter(Mandatory = $false,ValueFromPipelineByPropertyName = $true)]
        [String]$ApiVersion = '2016-10-01',
        [Parameter(Mandatory = $true,ValueFromPipelineByPropertyName = $true)]
        [String]$AccessToken,
        [Parameter(Mandatory = $false,ValueFromPipelineByPropertyName = $true)]
        [int]$MaxResults             
    )
    BEGIN
    {
        $VaultBaseUri="https://${VaultName}.${VaultDomain}"
        $VaultUriBld = New-Object System.UriBuilder($VaultBaseUri)
        $VaultUriBld.Query = "api-version=${ApiVersion}"
        $Headers = @{Accept = 'application/json'}
        $RequestParams = @{
            Method            = 'GET'
            AdditionalHeaders = $Headers;
            ContentType       = 'application/json';
        }
        Write-Verbose "[Get-AzureVaultCertificate] Retrieving certficate(s) from ${VaultBaseUri}"
    }
    PROCESS
    {
        if ($CertificateName -ne $null)
        {
            foreach ($item in $CertificateName)
            {
                $VaultUriBld.Path = "/certificates/${item}"
                Write-Verbose "[Get-AzureVaultCertificate] Retreiving Certificate ${VaultBaseUri} -> ${item}"
                $Result = Invoke-AzureVaultRequest @RequestParams  -Uri $VaultUriBld.Uri
                if ($Result -ne $null)
                {
                    Write-Output $Result
                }
            }
        }
        else
        {
            $VaultUriBld.Path = "/certificates"
            if($MaxResults -gt 0)
            {
                Write-Verbose "[Get-AzureVaultCertificate] Listing All Certificates ${VaultBaseUri} -> MaxResults=${MaxResults}"
            }
            else {
                Write-Verbose "[Get-AzureVaultCertificate] Listing All Certificates ${VaultBaseUri}"
            }              
            $Result = Invoke-AzureVaultRequest @RequestParams  -Uri $VaultUriBld.Uri
            if ($Result -ne $null)
            {
                Write-Output $Result
            }
        }
    }
}
#Create Certificate
Function New-AzureVaultCertificate
{
    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory = $true,ValueFromPipelineByPropertyName = $true)]
        [String]$VaultName,
        [Parameter(Mandatory = $false,ValueFromPipelineByPropertyName = $true)]
        [System.Uri]$VaultDomain = $Script:DefaultVaultDomain,
        [Parameter(Mandatory = $true,ValueFromPipelineByPropertyName = $true)]
        [String]$CertificateName,
        [ValidateSet('EC', 'RSA', 'RSA-HSM', 'oct')]
        [Parameter(Mandatory = $false,ValueFromPipelineByPropertyName = $true)]
        [String]$KeyType = 'RSA',        
        [Parameter(Mandatory = $true,ValueFromPipelineByPropertyName = $true)]
        [String[]]$KeyUsage,
        [Parameter(Mandatory = $false,ValueFromPipelineByPropertyName = $true)]
        [String[]]$EnhancedKeyUsage,
        #[ValidateSet('Self','Unknown','DigiCert','GlobalSign','WoSign')] 
        [Parameter(Mandatory = $false,ValueFromPipelineByPropertyName = $true)]
        [String]$Issuer = 'Self',
        [Parameter(Mandatory = $false,ValueFromPipelineByPropertyName = $true)]
        [String]$Enabled = $true,        
        [ValidateSet('OV-SSL','EV-SSL')]
        [Parameter(Mandatory = $false,ValueFromPipelineByPropertyName = $true)]
        [String]$IssuerCertType = 'OV-SSL',        
        [Parameter(Mandatory = $true,ValueFromPipelineByPropertyName = $true)]
        [String]$Subject,
        [Parameter(Mandatory = $true,ValueFromPipelineByPropertyName = $true)]
        [String[]]$SubjectAlternateNameEmails,
        [Parameter(Mandatory = $true,ValueFromPipelineByPropertyName = $true)]
        [String[]]$SubjectAlternateNameUpns,
        [Parameter(Mandatory = $true,ValueFromPipelineByPropertyName = $true)]
        [String[]]$SubjectAlternateNameDnsNames,        
        [ValidateSet('EmailContacts', 'AutoRenew')]
        [Parameter(Mandatory = $false,ValueFromPipelineByPropertyName = $true)]
        [String]$LifetimeExpireActionType = 'AutoRenew',    
        [Parameter(Mandatory = $false,ValueFromPipelineByPropertyName = $true)]
        [datetime]$NotBefore = [datetime]::UtcNow,
        [Parameter(Mandatory = $false,ValueFromPipelineByPropertyName = $true)]
        [int]$ExpiryInDays = 365,        
        [Parameter(Mandatory = $false,ValueFromPipelineByPropertyName = $true)]
        [datetime]$Exportable = $false,
        [Parameter(Mandatory = $false,ValueFromPipelineByPropertyName = $true)]
        [datetime]$ReuseKey = $true,
        [Parameter(Mandatory = $true,ValueFromPipelineByPropertyName = $true)]
        [ValidateRange(1,99)]
        [int]$LifetimeExpirePercentage = 90,
        [Parameter(Mandatory = $true,ValueFromPipelineByPropertyName = $true)]
        [ValidateRange(1,90)]
        [int]$LifetimeDaysBeforeExpire = 7,        
        [Parameter(Mandatory = $false,ValueFromPipelineByPropertyName = $true)]
        [ValidateSet(1024,2048,4096)]
        [int]$KeySize = 2048,
        [Parameter(Mandatory = $false,ValueFromPipelineByPropertyName = $true)]
        [System.Collections.IDictionary]$Tags,        
        [Parameter(Mandatory = $false,ValueFromPipelineByPropertyName = $true)]
        [String]$ApiVersion = '2016-10-01',
        [Parameter(Mandatory = $true,ValueFromPipelineByPropertyName = $true)]
        [String]$AccessToken             
    )
    BEGIN
    {
        $VaultBaseUri="https://${VaultName}.${VaultDomain}"
        $VaultUriBld = New-Object System.UriBuilder($VaultBaseUri)
        $VaultUriBld.Query = "api-version=${ApiVersion}"
        $VaultUriBld.Path = "/certificates/$CertificateName"
        $RequestParams = @{
            Method            = 'PUT'
            AdditionalHeaders = @{Accept = 'application/json'};
            ContentType       = 'application/json';
            Uri               = $VaultUriBld.Uri;
            ErrorAction       = 'Stop';
        } 
    }
    PROCESS
    {
        # tags
        #Build the object
        $CertificateParams = [ordered]@{

        }
        $NewCertificate = New-Object psobject -Property $CertificateParams
        $RequestParams['Body'] = $NewCertificate|ConvertTo-Json -Depth 10
        $Result = Invoke-AzureVaultRequest @RequestParams
        if ($Result -ne $null)
        {
            Write-Output $Result
        }            
    }    
}

#Delete Certficate
Function Remove-AzureVaultCertificate
{
    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory = $true,ValueFromPipelineByPropertyName = $true)]
        [String]$VaultName,
        [Parameter(Mandatory = $false,ValueFromPipelineByPropertyName = $true)]
        [System.Uri]$VaultDomain = $Script:DefaultVaultDomain,
        [Parameter(Mandatory = $true,ValueFromPipeline = $true,ValueFromPipelineByPropertyName = $true)]
        [String[]]$CertificateName,    
        [Parameter(Mandatory = $false,ValueFromPipelineByPropertyName = $true)]
        [String]$ApiVersion = '2016-10-01',
        [Parameter(Mandatory = $true,ValueFromPipelineByPropertyName = $true)]
        [String]$AccessToken             
    )
    BEGIN
    {
        $VaultBaseUri="https://${VaultName}.${VaultDomain}"
        $VaultUriBld = New-Object System.UriBuilder($VaultBaseUri)
        $VaultUriBld.Query = "api-version=${ApiVersion}"
        $RequestParams = @{
            AdditionalHeaders = @{Accept = 'application/json'};
            ContentType       = 'application/json'
            AccessToken       = $AccessToken;
            Method            = 'DELETE';
            ErrorAction       = 'Stop';
        }
        Write-Verbose "[Remove-AzureVaultCertificate] Removing certificate(s) from ${VaultBaseUri}"
    }
    PROCESS
    {
        foreach ($item in $CertificateName)
        {
            $VaultUriBld.Path = "/certificates/${item}"
            Write-Verbose "[Remove-AzureVaultCertificate] Removing certificate ${item} from ${VaultBaseUri}!"
            $Result = Invoke-AzureVaultRequest @RequestParams  -Uri $VaultUriBld.Uri
            if ($Result -ne $null)
            {
                Write-Verbose "[Remove-AzureVaultCertificate] Successfully removed certificate ${item} from ${VaultBaseUri}!"
                Write-Output $Result
            }            
        }
    }    
}

#Encrypt

#Decrypt

#Sign

#Unwrap Key

#Verify

#Wrap Key