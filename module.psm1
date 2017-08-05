<#
    REST API Wrappers for the Azure Key Vault Service
#>
$Script:DefaultVaultDomain = 'vault.azure.net'
$Script:UnixEpoch = New-Object DateTime(1970, 1, 1, 0, 0, 0, 0, [System.DateTimeKind]::Utc)

$Script:KeyTypes=@{EllipticalCurve='EC';RSA='RSA';HSM='RSA-HSM';Octet='oct'}
$Script:IssuerCertTypes=@('OV-SSL','EV-SSL')
$Script:ExpirationActionTypes=@{'AutoRenew'='AutoRenew';'EmailContacts'='EmailContacts'}
$Script:KeyUsageTypes=@{
    DigitalSignature = "digitalSignature"
    NonRepudiation = "nonRepudiation"
    KeyEncipherment = "keyEncipherment"
    DataEncipherment = "dataEncipherment"
    KeyAgreement = "keyAgreement"
    KeyCertSign = "keyCertSign"
    CrlSign = "cRLSign"
    EncipherOnly = "encipherOnly"
    DecipherOnly = "decipherOnly"}
$Script:EncryptionAlgorithms=@{    
    rsa_oaep = "RSA-OAEP"
    rsa_oaep_256 = "RSA-OAEP-256"
    rsa1_5 = "RSA1_5"
}
$Script:KeyOperations=@{
    'encrypt'='encrypt';
    'decrypt'='decrypt';
    'sign'='sign';
    'verify'='verify';
    'wrapKey'='wrapKey';
    'unwrapKey'='unwrapKey'
}
$Script:SigningAlgorithms=@{
    PS256 = "PS256"
    PS384 = "PS384"
    PS512 = "PS512"
    RS256 = "RS256"
    RS384 = "RS384"
    RS512 = "RS512"
    RSNULL = "RSNULL"
}
$Global:Azure_Vault_Values=@{
    KeyTypes=$Script:KeyTypes;
    ExpirationActionTypes=$Script:ExpirationActionTypes;
    SigningAlgorithms=$Script:SigningAlgorithms;
    EncryptionAlgorithms=$Script:EncryptionAlgorithms;
    KeyOperations=$Script:KeyOperations;
}

#region Helpers

Function ConvertToBase64UrlString
{
    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory=$true,ValueFromPipelineByPropertyName=$true)]
        [byte[]]$InputObject
    )
    PROCESS
    {
        $EncodedValue=[Convert]::ToBase64String($InputObject)
        $Result=$EncodedValue.TrimEnd('=').Replace('+', '-').Replace('/', '_');
        Write-Output $Result
    }
}

Function ConvertFromBase64UrlString
{
    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory=$true,ValueFromPipeline=$true)]
        [string[]]$InputObject
    )
    PROCESS
    {
        foreach ($item in $InputObject)
        {
            $item=$item.Replace('-', '+').Replace('_', '/')
            $count = 3 - (($item.Length + 3) % 4);
            if ($count -ne 0)
            {
                $item+=New-Object string('=', $count);
            }    
            $Result=[Convert]::FromBase64String($item);
            Write-Output $Result            
        }
    }
}

<#
    .SYNOPSIS
        Generic request wrapper for the Key Vault Service API
    .PARAMETER Uri
        The full request URI
    .PARAMETER AccessToken
        The OAuth bearer token
    .PARAMETER AdditionalHeaders
        Additional Headers for the request
    .PARAMETER Method
        The method to be executed
    .PARAMETER NextLinkProperty
        The name of any OData continuation token property
    .PARAMETER ValueProperty
        The name of any OData value property 
    .PARAMETER ErrorProperty
        The name of any OData error value property
    .PARAMETER Body
        The request body object
    .PARAMETER ContentType
        The content type for the request
    .PARAMETER AggregateResponses
        Whether to Aggregate OData continuation Responses
    .PARAMETER ReturnHeaders
        Whether to return the response headers
    .PARAMETER RequestDelayMilliseconds
        The amount of time in milliseconds to wait between concurrent requests
#>
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
        [object]$Body,
        [Parameter(Mandatory = $false,ValueFromPipelineByPropertyName = $true)]
        [string]$ContentType = 'application/json',        
        [Parameter(Mandatory = $false,ValueFromPipelineByPropertyName = $true)]
        [switch]$AggregateResponses,
        [Parameter(Mandatory = $false,ValueFromPipelineByPropertyName = $true)]
        [switch]$ReturnHeaders,
        [Parameter(Mandatory = $false,ValueFromPipelineByPropertyName = $true)]
        [switch]$DontExpand,        
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
        $RequestParams['Body'] = $($Body|ConvertTo-Json -Depth 10)
    }
    $RequestResult = $null
    try
    {
        $Response = Invoke-WebRequest @RequestParams -UseBasicParsing -ErrorAction Stop
        Write-Verbose "[Invoke-AzureVaultRequest]$Method $Uri Response:$($Response.StatusCode)-$($Response.StatusDescription) Content-Length:$($Response.RawContentLength)"
        if (-not [String]::IsNullOrEmpty($Response.Content))
        {
            $RequestResult = $Response.Content|ConvertFrom-Json
        }
        if ($ReturnHeaders.IsPresent)
        {
            Write-Output $Response.Headers
        }
    }
    catch
    {
        #See if we can unwind an exception from a response
        if ($_.Exception.Response -ne $null)
        {
            Write-Verbose "[Invoke-AzureVaultRequest] Unwinding Exception Response..."
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
                Write-Warning "[Invoke-AzureVaultRequest] Error occurred reading exception stream! $_"
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
        Write-Verbose "[Invoke-AzureVaultRequest] $ErrorMessage"
        throw $ErrorMessage
    }
    #Should never get here null
    if ($RequestResult -ne $null)
    {
        if ($RequestResult.PSobject.Properties.name -match $ValueProperty -and (-not $DontExpand.IsPresent))
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
            Write-Verbose "[Invoke-AzureVaultRequest] Item Count:$TotalItems Page:$ResultPages More Items available @ $NextUri"
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
                Write-Verbose "[Invoke-AzureVaultRequest]$Method $Uri Response:$($Response.StatusCode)-$($Response.StatusDescription) Content-Length:$($Response.RawContentLength)"
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
                Write-Verbose "[Invoke-AzureVaultRequest] $ErrorMessage"
                throw $ErrorMessage
            }       
        }
    }
}

<#
	.SYNOPSIS
		Creates a parameter object for new/updated key requests
	.DESCRIPTION
		Creates a parameter object for new/updated key requests
	.PARAMETER KeyType
		The key type ('EC', 'RSA', 'RSA-HSM', 'oct')
	.PARAMETER KeyName
		The key name
	.PARAMETER AccessToken
		The OAuth bearer token
	.PARAMETER KeyOperations
		The allowed key operations
	.PARAMETER ExpiryInDays
		The vailidity length for the key
	.PARAMETER NotBefore
		The validity start date for the key
	.PARAMETER KeySize
		The KeySize (1024,2048)
	.PARAMETER Tags
		Key-value metadata pairs
#>
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
        [datetime]$Epoch = $Script:UnixEpoch,        
        [Parameter(Mandatory = $true,ValueFromPipelineByPropertyName = $true)]
        [ValidateSet(1024,2048)]
        [int]$KeySize,
        [Parameter(Mandatory = $false,ValueFromPipelineByPropertyName = $true)]
        [System.Collections.IDictionary]$Tags        
    )
    $NewKeyAttributes = New-Object PSObject -Property @{
        'enabled' = $true;
        'nbf'     = $(($NotBefore - $Epoch).TotalSeconds);
        'exp'     = $((($NotBefore.AddDays($ExpiryInDays)) - $Epoch).TotalSeconds);
    }
    $KeyProperties = [ordered]@{
        'attributes' = $NewKeyAttributes;
        'key_ops'    = $KeyOperations;
        'key_size'   = $KeySize;
        'kty'        = $KeyType;
        'tags'       = $Tags;
    }
    $NewKeyParams = New-Object PSObject -Property $KeyProperties
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
        [bool]$Enabled = $true,        
        [ValidateSet('OV-SSL','EV-SSL')]
        [Parameter(Mandatory = $false,ValueFromPipelineByPropertyName = $true)]
        [String]$IssuerCertType = 'OV-SSL',        
        [Parameter(Mandatory = $true,ValueFromPipelineByPropertyName = $true)]
        [String]$Subject,
        [Parameter(Mandatory = $false,ValueFromPipelineByPropertyName = $true)]
        [String[]]$SubjectAlternateNameEmails,
        [Parameter(Mandatory = $false,ValueFromPipelineByPropertyName = $true)]
        [String[]]$SubjectAlternateNameUpns,
        [Parameter(Mandatory = $false,ValueFromPipelineByPropertyName = $true)]
        [String[]]$SubjectAlternateNameDnsNames,        
        [ValidateSet('EmailContacts', 'AutoRenew')]
        [Parameter(Mandatory = $false,ValueFromPipelineByPropertyName = $true)]
        [String]$LifetimeExpireActionType = 'AutoRenew',    
        [Parameter(Mandatory = $false,ValueFromPipelineByPropertyName = $true)]
        [datetime]$NotBefore = [datetime]::UtcNow,
        [Parameter(Mandatory = $false,ValueFromPipelineByPropertyName = $true)]
        [int]$ExpiryInDays = 365,
        [Parameter(Mandatory = $false,ValueFromPipelineByPropertyName = $true)]
        [datetime]$Epoch = $Script:UnixEpoch,        
        [Parameter(Mandatory = $false,ValueFromPipelineByPropertyName = $true)]
        [bool]$Exportable = $false,
        [Parameter(Mandatory = $false,ValueFromPipelineByPropertyName = $true)]
        [bool]$ReuseKey = $true,
        [Parameter(Mandatory = $false,ValueFromPipelineByPropertyName = $true)]
        [ValidateRange(1,99)]
        [int]$LifetimeExpirePercentage = 90,
        [Parameter(Mandatory = $false,ValueFromPipelineByPropertyName = $true)]
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
        [datetime]$Epoch = $Script:UnixEpoch
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

#endregion

#region Keys

<#
	.SYNOPSIS
		Retrieves key(s) from the specified vault
	.DESCRIPTION
		Retrieves key(s) from the specified vault
	.PARAMETER KeyName
		The key name
	.PARAMETER MaxResults
		Limit the maximum results returned
	.PARAMETER VaultName
		The vault name
	.PARAMETER VaultDomain
		The vault FQDN
	.PARAMETER ApiVersion
		The vault api version
	.PARAMETER AccessToken
		The OAuth bearer token
#>
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
        $VaultBaseUri = "https://${VaultName}.${VaultDomain}"
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
            if ($MaxResults -gt 0)
            {
                Write-Verbose "[Get-AzureVaultKey] Listing All Keys ${VaultBaseUri} -> MaxResults=${MaxResults}"
            }
            else
            {
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

<#
	.SYNOPSIS
		Creates a new key
	.DESCRIPTION
		Creates a new key
	.PARAMETER KeyType
		The key type ('EC', 'RSA', 'RSA-HSM', 'oct')
	.PARAMETER KeyName
		The key name
	.PARAMETER KeyOperations
		The allowed key operations
	.PARAMETER ExpiryInDays
		The vailidity length for the key
	.PARAMETER NotBefore
		The validity start date for the key
	.PARAMETER KeySize
		The KeySize (1024,2048)
	.PARAMETER VaultName
		The vault name
	.PARAMETER VaultDomain
		The vault FQDN
	.PARAMETER Tags
		Key-value metadata pairs
	.PARAMETER ApiVersion
		The vault api version
	.PARAMETER AccessToken
		The OAuth bearer token
#>
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
        [Parameter(Mandatory = $false,ValueFromPipelineByPropertyName = $true)]
        [String[]]$KeyOperations = @("sign", "verify", "wrapKey", "unwrapKey", "encrypt", "decrypt"),        
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
    }
    PROCESS
    {
        $KeyParams = @{
            KeyName       = $KeyName;
            KeyType       = $KeyType;
            KeySize       = $KeySize;
            ExpiryInDays  = $ExpiryInDays;
            KeyOperations = $KeyOperations;
            NotBefore     = $NotBefore
        }
        $NewKeyBody = New-AzureVaultKeyParameters @KeyParams
        $RequestParams = @{
            Uri               = $VaultUriBld.Uri;
            AdditionalHeaders = @{Accept = 'application/json'}
            Body              = $NewKeyBody;
            Method            = 'POST';
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

<#
	.SYNOPSIS
		Removes key(s) from the specified vault
	.DESCRIPTION
		Retrieves key(s) from the specified vault
	.PARAMETER KeyName
		The key name
	.PARAMETER ApiVersion
		The vault api version
	.PARAMETER VaultName
		The vault name
	.PARAMETER VaultDomain
		The vault FQDN
	.PARAMETER AccessToken
		The OAuth bearer token
#>
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
        $VaultBaseUri = "https://${VaultName}.${VaultDomain}"
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

#Encrypt
function New-AzureVaultEncryptedValue
{
    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory = $true,ValueFromPipelineByPropertyName = $true)]
        [String]$VaultName,
        [Parameter(Mandatory = $false,ValueFromPipelineByPropertyName = $true)]
        [System.Uri]$VaultDomain = $Script:DefaultVaultDomain,        
        [Parameter(Mandatory = $true,ValueFromPipelineByPropertyName = $true)]
        [string]$KeyName,
        [Parameter(Mandatory = $false,ValueFromPipelineByPropertyName = $true)]
        [string]$KeyVersion,        
        [Parameter(Mandatory = $true,ValueFromPipelineByPropertyName = $true)]
        [byte[]]$Value,        
        [ValidateSet('RSA-OAEP', 'RSA-OAEP-256', 'RSA1_5' )]
        [Parameter(Mandatory = $false,ValueFromPipelineByPropertyName = $true)]
        [string]$Algorithm = 'RSA-OAEP256',
        [Parameter(Mandatory = $false,ValueFromPipelineByPropertyName = $true)]
        [String]$ApiVersion = '2016-10-01',        
        [Parameter(Mandatory = $true,ValueFromPipelineByPropertyName = $true)]
        [String]$AccessToken,
        [Parameter(Mandatory = $false,ValueFromPipelineByPropertyName = $true)]
        [Switch]$AsString
    )
    begin
    {
        $VaultUriBld = New-Object System.UriBuilder("https://${VaultName}.${VaultDomain}")
        $VaultUriBld.Query = "api-version=${ApiVersion}"
        if ([String]::IsNullOrEmpty($KeyVersion))
        {
            $VaultUriBld.Path = "/keys/${KeyName}/encrypt" 
        }
        else
        {
            $VaultUriBld.Path = "/keys/${KeyName}/${KeyVersion}/encrypt"
        }
        $RequestParams = @{
            Uri               = $VaultUriBld.Uri;
            Method            = 'POST';
            AdditionalHeaders = @{Accept = 'application/json; charset=utf-8'};
            AccessToken       = $AccessToken;
            ContentType       = 'application/json; charset=utf-8'
        }        
    }
    process
    {
        #$Bas64String=[Convert]::ToBase64String($Value)
        #$UrlString=$($Bas64String.TrimEnd('=').Replace('+', '-').Replace('/', '_'))
        $UrlString=ConvertToBase64UrlString -InputObject $Value
        $RequestParams['Body'] = [ordered]@{
            'alg'   = $Algorithm;
            'value' = $UrlString;
        }
        $Result = Invoke-AzureVaultRequest @RequestParams
        if ($Result -ne $null)
        {
            $ResultBytes=$Result|ConvertFromBase64UrlString
            Write-Output $ResultBytes
        }
    }
}

#Decrypt
function Get-AzureVaultDecryptedValue
{
    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory = $true,ValueFromPipelineByPropertyName = $true)]
        [String]$VaultName,
        [Parameter(Mandatory = $false,ValueFromPipelineByPropertyName = $true)]
        [System.Uri]$VaultDomain = $Script:DefaultVaultDomain,        
        [Parameter(Mandatory = $true,ValueFromPipelineByPropertyName = $true)]
        [string]$KeyName,
        [Parameter(Mandatory = $false,ValueFromPipelineByPropertyName = $true)]
        [string]$KeyVersion,        
        [Parameter(Mandatory = $true,ValueFromPipelineByPropertyName = $true)]
        [byte[]]$Value,              
        [ValidateSet('RSA-OAEP', 'RSA-OAEP-256', 'RSA1_5' )]
        [Parameter(Mandatory = $false,ValueFromPipelineByPropertyName = $true)]
        [string]$Algorithm = 'RSA-OAEP256',
        [Parameter(Mandatory = $false,ValueFromPipelineByPropertyName = $true)]
        [String]$ApiVersion = '2016-10-01',        
        [Parameter(Mandatory = $true,ValueFromPipelineByPropertyName = $true)]
        [String]$AccessToken             
    )
    begin
    {
        $VaultUriBld = New-Object System.UriBuilder("https://${VaultName}.${VaultDomain}")
        $VaultUriBld.Query = "api-version=${ApiVersion}"
        if ([String]::IsNullOrEmpty($KeyVersion))
        {
            $VaultUriBld.Path = "/keys/${KeyName}/decrypt" 
        }
        else
        {
            $VaultUriBld.Path = "/keys/${KeyName}/${KeyVersion}/decrypt"
        }
        $RequestParams = @{
            Uri               = $VaultUriBld.Uri;
            Method            = 'POST';
            AdditionalHeaders = @{Accept = 'application/json; charset=utf-8'};
            AccessToken       = $AccessToken;
            ContentType       = 'application/json; charset=utf-8'
        }
    }
    process
    {
        $UrlString=ConvertToBase64UrlString -InputObject $Value
        $RequestParams['Body'] = [ordered]@{
            'alg'   = $Algorithm;
            'value' = $UrlString;
        }
        $Result = Invoke-AzureVaultRequest @RequestParams
        if ($Result -ne $null)
        {
            $ResultBytes=$Result|ConvertFromBase64UrlString
            Write-Output $ResultBytes
        }
    }
}

#Sign
function New-AzureVaultSignedValue
{
    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory = $true,ValueFromPipelineByPropertyName = $true)]
        [String]$VaultName,
        [Parameter(Mandatory = $false,ValueFromPipelineByPropertyName = $true)]
        [System.Uri]$VaultDomain = $Script:DefaultVaultDomain,         
        [Parameter(Mandatory = $true,ValueFromPipelineByPropertyName = $true)]
        [string]$KeyName,
        [Parameter(Mandatory = $false,ValueFromPipelineByPropertyName = $true)]
        [string]$KeyVersion,        
        [Parameter(Mandatory = $true,ValueFromPipelineByPropertyName = $true)]
        [byte[]]$Value,    
        [ValidateSet('PS256', 'PS384', 'PS512', 'RS256', 'RS384', 'RS512', 'RSNULL')]
        [Parameter(Mandatory = $false,ValueFromPipelineByPropertyName = $true)]
        [string]$Algorithm = 'RS256',
        [Parameter(Mandatory = $true,ValueFromPipelineByPropertyName = $true)]        
        [String]$ApiVersion = '2016-10-01',      
        [Parameter(Mandatory = $true,ValueFromPipelineByPropertyName = $true)]
        [String]$AccessToken            
    )
    begin
    {
        $VaultUriBld = New-Object System.UriBuilder("https://${VaultName}.${VaultDomain}")
        $VaultUriBld.Query = "api-version=${ApiVersion}"
        if ([String]::IsNullOrEmpty($KeyVersion))
        {
            $VaultUriBld.Path = "/keys/${KeyName}/sign" 
        }
        else
        {
            $VaultUriBld.Path = "/keys/${KeyName}/${KeyVersion}/sign"
        }
        $RequestParams = @{
            Uri               = $VaultUriBld.Uri;
            Method            = 'POST';
            AdditionalHeaders = @{Accept = 'application/json'};
            AccessToken       = $AccessToken;
            ContentType       = 'application/json'
        }
    }
    process
    {
        $UriString=ConvertToBase64UrlString -InputObject $Value
        $RequestParams['Body'] = [ordered]@{
            'alg'   = $Algorithm;
            'value' = $UriString;
        }
        $Result = Invoke-AzureVaultRequest @RequestParams
        if ($Result -ne $null)
        {
            $ResultBytes=$Result|ConvertFromBase64UrlString
            Write-Output $ResultBytes
        }     
    }
}

#Verify
function Test-AzureVaultSignedValue
{
    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory = $true,ValueFromPipelineByPropertyName = $true)]
        [String]$VaultName,
        [Parameter(Mandatory = $false,ValueFromPipelineByPropertyName = $true)]
        [System.Uri]$VaultDomain = $Script:DefaultVaultDomain,        
        [Parameter(Mandatory = $true,ValueFromPipelineByPropertyName = $true)]
        [string]$KeyName,
        [Parameter(Mandatory = $false,ValueFromPipelineByPropertyName = $true)]
        [string]$KeyVersion,
        [Parameter(Mandatory = $true,ValueFromPipelineByPropertyName = $true)]
        [byte[]]$Value,           
        [ValidateSet('PS256', 'PS384', 'PS512', 'RS256', 'RS384', 'RS512', 'RSNULL')]
        [Parameter(Mandatory = $false,ValueFromPipelineByPropertyName = $true)]
        [string]$Algorithm = 'RS256',
        [Parameter(Mandatory = $true,ValueFromPipelineByPropertyName = $true)]        
        [String]$ApiVersion = '2016-10-01',      
        [Parameter(Mandatory = $true,ValueFromPipelineByPropertyName = $true)]
        [String]$AccessToken           
    )
    begin
    {
        $VaultUriBld = New-Object System.UriBuilder("https://${VaultName}.${VaultDomain}")
        $VaultUriBld.Query = "api-version=${ApiVersion}"
        if ([String]::IsNullOrEmpty($KeyVersion))
        {
            $VaultUriBld.Path = "/keys/${KeyName}/verify" 
        }
        else
        {
            $VaultUriBld.Path = "/keys/${KeyName}/${KeyVersion}/verify"
        }
        $RequestParams = @{
            Uri               = $VaultUriBld.Uri;
            Method            = 'POST';
            AdditionalHeaders = @{Accept = 'application/json'};
            AccessToken       = $AccessToken;
            ContentType       = 'application/json'
        }
    }
    process
    {
        $UriString=ConvertToBase64UrlString -InputObject $Value
        $RequestParams['Body'] = [ordered]@{
            'alg'   = $Algorithm;
            'value' = $UriString;
        }
        $Result = Invoke-AzureVaultRequest @RequestParams
        if ($Result -ne $null)
        {
            Write-Output $Result
        }
    }
}

#Unwrap Key
function New-AzureVaultUnwrappedKey
{
    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory = $true,ValueFromPipelineByPropertyName = $true)]
        [String]$VaultName,
        [Parameter(Mandatory = $false,ValueFromPipelineByPropertyName = $true)]
        [System.Uri]$VaultDomain = $Script:DefaultVaultDomain,        
        [Parameter(Mandatory = $true,ValueFromPipelineByPropertyName = $true)]
        [string]$KeyName,
        [Parameter(Mandatory = $false,ValueFromPipelineByPropertyName = $true)]
        [string]$KeyVersion,        
        [Parameter(Mandatory = $true,ValueFromPipelineByPropertyName = $true)]
        [byte[]]$Value,      
        [ValidateSet('RSA-OAEP', 'RSA-OAEP-256', 'RSA1_5' )]
        [Parameter(Mandatory = $false,ValueFromPipelineByPropertyName = $true)]
        [string]$Algorithm = 'RSA-OAEP256',
        [Parameter(Mandatory = $true,ValueFromPipelineByPropertyName = $true)]        
        [String]$ApiVersion = '2016-10-01',      
        [Parameter(Mandatory = $true,ValueFromPipelineByPropertyName = $true)]
        [String]$AccessToken         
    )
    begin
    {
        $VaultUriBld = New-Object System.UriBuilder("https://${VaultName}.${VaultDomain}")
        $VaultUriBld.Query = "api-version=${ApiVersion}"
        if ([String]::IsNullOrEmpty($KeyVersion))
        {
            $VaultUriBld.Path = "/keys/${KeyName}/unwrap" 
        }
        else
        {
            $VaultUriBld.Path = "/keys/${KeyName}/${KeyVersion}/unwrap"
        }
        $RequestParams = @{
            Uri               = $VaultUriBld.Uri;
            Method            = 'POST';
            AdditionalHeaders = @{Accept = 'application/json'};
            AccessToken       = $AccessToken;
            ContentType       = 'application/json'
        }
    }
    process
    {
        $UriString=ConvertToBase64UrlString -InputObject $Value
        $RequestParams['Body'] = [ordered]@{
            'alg'   = $Algorithm;
            'value' = $UriString;
        }
        $Result = Invoke-AzureVaultRequest @RequestParams
        if ($Result -ne $null)
        {
            $ResultBytes=$Result|ConvertFromBase64UrlString
            Write-Output $ResultBytes
        }
    }
}

#Wrap Key
function New-AzureVaultWrappedKey
{
    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory = $true,ValueFromPipelineByPropertyName = $true)]
        [String]$VaultName,
        [Parameter(Mandatory = $false,ValueFromPipelineByPropertyName = $true)]
        [System.Uri]$VaultDomain = $Script:DefaultVaultDomain,        
        [Parameter(Mandatory = $true,ValueFromPipelineByPropertyName = $true)]
        [string]$KeyName,
        [Parameter(Mandatory = $false,ValueFromPipelineByPropertyName = $true)]
        [string]$KeyVersion,        
        [Parameter(Mandatory = $true,ValueFromPipeline=$true,ValueFromPipelineByPropertyName = $true)]
        [string[]]$Value,        
        [ValidateSet('RSA-OAEP', 'RSA-OAEP-256', 'RSA1_5' )]
        [Parameter(Mandatory = $false,ValueFromPipelineByPropertyName = $true)]
        [string]$Algorithm = 'RSA-OAEP256',
        [Parameter(Mandatory = $true,ValueFromPipelineByPropertyName = $true)]        
        [String]$ApiVersion = '2016-10-01',      
        [Parameter(Mandatory = $true,ValueFromPipelineByPropertyName = $true)]
        [String]$AccessToken         
    )
    begin
    {
        $VaultUriBld = New-Object System.UriBuilder("https://${VaultName}.${VaultDomain}")
        $VaultUriBld.Query = "api-version=${ApiVersion}"
        if ([String]::IsNullOrEmpty($KeyVersion))
        {
            $VaultUriBld.Path = "/keys/${KeyName}/wrap" 
        }
        else
        {
            $VaultUriBld.Path = "/keys/${KeyName}/${KeyVersion}/wrap"
        }
        $RequestParams = @{
            Uri               = $VaultUriBld.Uri;
            Method            = 'POST';
            AdditionalHeaders = @{Accept = 'application/json'};
            AccessToken       = $AccessToken;
            ContentType       = 'application/json'
        }
    }
    process
    {
        foreach ($item in $Value)
        {
            $RequestParams['Body'] = [ordered]@{
                'alg'   = $Algorithm;
                'value' = $item;
            }
            $Result = Invoke-AzureVaultRequest @RequestParams
            if ($Result -ne $null)
            {
                Write-Output $Result
            }            
        }
    }
}

#endregion

#region Secrets

<#
    .SYNOPSIS
        Retrieves secret(s) from the specified vault
    .DESCRIPTION
        Retrieves secret(s) from the specified vault
    .PARAMETER VaultName
        The vault name
    .PARAMETER VaultDomain
        The vault FQDN
    .PARAMETER SecretName
        The secret name(s)
    .PARAMETER ApiVersion
        The vault api version
    .PARAMETER AccessToken
        The OAuth bearer token
    .PARAMETER MaxResults
        Limit the number of results returned
#>
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
        $VaultBaseUri = "https://${VaultName}.${VaultDomain}"
        $VaultUriBld = New-Object System.UriBuilder($VaultBaseUri)
        $VaultUriBld.Query = "api-version=${ApiVersion}"
        $Headers = @{Accept = 'application/json'}
        $RequestParams = @{
            Method            = 'GET'
            AdditionalHeaders = $Headers;
            ContentType       = 'application/json';
            AccessToken       = $AccessToken;
            ErrorAction       = 'Stop';
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
            if ($MaxResults -gt 0)
            {
                Write-Verbose "[Get-AzureVaultSecret] Listing All Secrets ${VaultBaseUri} -> MaxResults=${MaxResults}"
            }
            else
            {
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
            AccessToken       = $AccessToken;
        }        
    }
    PROCESS
    {
        #Build the object
        $SecretParams = @{
            Value        = $Value;
            ContentType  = $ContentType;
            NotBefore    = $NotBefore;
            ExpiryInDays = $ExpiryInDays;
            Tags         = $Tags;
        }
        $NewSecret = New-AzureVaultSecretParameters @SecretParams
        $RequestParams['Body'] = $NewSecret
        $Result = Invoke-AzureVaultRequest @RequestParams
        if ($Result -ne $null)
        {
            Write-Output $Result
        }
    }    
}

<#
    .SYNOPSIS
        Removes secret(s) from the specified vault
    .DESCRIPTION
        Removes secret(s) from the specified vault
    .PARAMETER VaultName
        The vault name
    .PARAMETER VaultDomain
        The vault FQDN
    .PARAMETER SecretName
        The secret name(s)
    .PARAMETER ApiVersion
        The vault api version
    .PARAMETER AccessToken
        The OAuth bearer token
#>
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
        $VaultBaseUri = "https://${VaultName}.${VaultDomain}"
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

#endregion

#region Certificates

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
        $VaultBaseUri = "https://${VaultName}.${VaultDomain}"
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
            if ($MaxResults -gt 0)
            {
                Write-Verbose "[Get-AzureVaultCertificate] Listing All Certificates ${VaultBaseUri} -> MaxResults=${MaxResults}"
            }
            else
            {
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
        [Parameter(Mandatory = $false,ValueFromPipelineByPropertyName = $true)]
        [String[]]$KeyUsage = @("sign", "verify", "wrapKey", "unwrapKey", "encrypt", "decrypt"),
        [Parameter(Mandatory = $false,ValueFromPipelineByPropertyName = $true)]
        [String[]]$EnhancedKeyUsage,
        #[ValidateSet('Self','Unknown','DigiCert','GlobalSign','WoSign')] 
        [Parameter(Mandatory = $false,ValueFromPipelineByPropertyName = $true)]
        [String]$Issuer = 'Self',
        [Parameter(Mandatory = $false,ValueFromPipelineByPropertyName = $true)]
        [bool]$Enabled = $true,        
        [ValidateSet('OV-SSL','EV-SSL')]
        [Parameter(Mandatory = $false,ValueFromPipelineByPropertyName = $true)]
        [String]$IssuerCertType = 'OV-SSL',        
        [Parameter(Mandatory = $true,ValueFromPipelineByPropertyName = $true)]
        [String]$Subject,
        [Parameter(Mandatory = $false,ValueFromPipelineByPropertyName = $true)]
        [String[]]$SubjectAlternateNameEmails,
        [Parameter(Mandatory = $false,ValueFromPipelineByPropertyName = $true)]
        [String[]]$SubjectAlternateNameUpns,
        [Parameter(Mandatory = $false,ValueFromPipelineByPropertyName = $true)]
        [String[]]$SubjectAlternateNameDnsNames,        
        [ValidateSet('EmailContacts', 'AutoRenew')]
        [Parameter(Mandatory = $false,ValueFromPipelineByPropertyName = $true)]
        [String]$LifetimeExpireActionType = 'AutoRenew',    
        [Parameter(Mandatory = $false,ValueFromPipelineByPropertyName = $true)]
        [datetime]$NotBefore = [datetime]::UtcNow,
        [Parameter(Mandatory = $false,ValueFromPipelineByPropertyName = $true)]
        [int]$ExpiryInDays = 365,        
        [Parameter(Mandatory = $false,ValueFromPipelineByPropertyName = $true)]
        [bool]$Exportable = $false,
        [Parameter(Mandatory = $false,ValueFromPipelineByPropertyName = $true)]
        [bool]$ReuseKey = $true,
        [Parameter(Mandatory = $false,ValueFromPipelineByPropertyName = $true)]
        [ValidateRange(1,99)]
        [int]$LifetimeExpirePercentage = 90,
        [Parameter(Mandatory = $false,ValueFromPipelineByPropertyName = $true)]
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
        $VaultBaseUri = "https://${VaultName}.${VaultDomain}"
        $VaultUriBld = New-Object System.UriBuilder($VaultBaseUri)
        $VaultUriBld.Query = "api-version=${ApiVersion}"
        $VaultUriBld.Path = "/certificates/${CertificateName}/create"
        $RequestParams = @{
            AdditionalHeaders = @{Accept = 'application/json'};
            Method            = 'POST';
            ContentType       = 'application/json';
            ErrorAction       = 'STOP';
            AccessToken       = $AccessToken;
            Uri               = $VaultUriBld.Uri;
        } 
    }
    PROCESS
    {
        #Build the object
        $CertificateParams = [ordered]@{
            KeyType                      = $KeyType;
            KeyUsage                     = $KeyUsage;
            KeySize                      = $KeySize;
            EnhancedKeyUsage             = $EnhancedKeyUsage;
            Issuer                       = $Issuer;
            Enabled                      = $Enabled;
            IssuerCertType               = $IssuerCertType;
            Subject                      = $Subject;
            SubjectAlternateNameEmails   = $SubjectAlternateNameEmails;
            SubjectAlternateNameUpns     = $SubjectAlternateNameUpns;
            SubjectAlternateNameDnsNames = $SubjectAlternateNameDnsNames
            LifetimeExpireActionType     = $LifetimeExpireActionType;
            LifetimeExpirePercentage     = $LifetimeExpirePercentage
            LifetimeDaysBeforeExpire     = $LifetimeDaysBeforeExpire
            NotBefore                    = $NotBefore;
            ExpiryInDays                 = $ExpiryInDays;
            Exportable                   = $Exportable;
            ReuseKey                     = $ReuseKey;
            Tags                         = $Tags;
        }
        $NewCertificate = New-AzureVaultCertificateParameters @CertificateParams
        $RequestParams['Body'] = $NewCertificate
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
        $VaultBaseUri = "https://${VaultName}.${VaultDomain}"
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

#endregion

<#
    .SYNOPSIS
        Uses a secret within the specified vault to create a securestring
    .DESCRIPTION
        Uses a secret within the specified vault to create a securestring
    .PARAMETER VaultName
        The vault name
    .PARAMETER VaultDomain
        The vault FQDN
    .PARAMETER SecretName
        The secret name(s)
    .PARAMETER ApiVersion
        The vault api version
    .PARAMETER AccessToken
        The OAuth bearer token
#>
Function ConvertFrom-AzureVaultSecretToSecureString
{
    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory = $true,ValueFromPipelineByPropertyName = $true)]
        [String]$VaultName,
        [Parameter(Mandatory = $false,ValueFromPipelineByPropertyName = $true)]
        [System.Uri]$VaultDomain = $Script:DefaultVaultDomain,
        [Parameter(Mandatory = $true,ValueFromPipelineByPropertyName = $true)]
        [String[]]$SecretName,    
        [Parameter(Mandatory = $false,ValueFromPipelineByPropertyName = $true)]
        [String]$ApiVersion = '2016-10-01',
        [Parameter(Mandatory = $true,ValueFromPipelineByPropertyName = $true)]
        [String]$AccessToken        
    )
    PROCESS
    {
        foreach ($item in $SecretName)
        {
            $SecurePassword=New-Object securestring
            $SecretParams=@{
                VaultName=$VaultName;
                VaultDomain=$VaultDomain;
                ApiVersion=$ApiVersion;
                AccessToken=$AccessToken;
                SecretName=$item;
            } 
            #Retreive the secret from the vault   
            $PasswordSecret=Get-AzureVaultSecret @SecretParams -ErrorAction Stop
            if(-not [string]::IsNullOrEmpty($PasswordSecret))
            {
                $PasswordSecret.ToCharArray()|ForEach-Object{$SecurePassword.AppendChar($_)}
            }
            Write-Output $SecurePassword
        }
    }
}

<#
    .SYNOPSIS
        Uses a secret within the specified vault to create a PSCredential
    .DESCRIPTION
        Uses a secret within the specified vault to create a PSCredential
    .PARAMETER UserName
        The username for the Credential
    .PARAMETER VaultName
        The vault name
    .PARAMETER VaultDomain
        The vault FQDN
    .PARAMETER SecretName
        The secret name(s)
    .PARAMETER ApiVersion
        The vault api version
    .PARAMETER AccessToken
        The OAuth bearer token
#>
Function ConvertTo-CredentialFromAzureVaultSecret
{
    [CmdletBinding(DefaultParameterSetName='NoUserSecret')]
    param
    (
        [Parameter(Mandatory=$true,ValueFromPipelineByPropertyName=$true,ParameterSetName='NoUserSecret')]
        [string]$UserName,
        [Parameter(Mandatory = $true,ValueFromPipelineByPropertyName = $true,ParameterSetName='UserSecret')]
        [Parameter(Mandatory = $true,ValueFromPipelineByPropertyName = $true,ParameterSetName='NoUserSecret')]
        [String]$VaultName,
        [Parameter(Mandatory = $false,ValueFromPipelineByPropertyName = $true,ParameterSetName='UserSecret')]
        [String]$UserVaultName=$VaultName,
        [Parameter(Mandatory = $false,ValueFromPipelineByPropertyName = $true,ParameterSetName='UserSecret')]
        [Parameter(Mandatory = $false,ValueFromPipelineByPropertyName = $true,ParameterSetName='NoUserSecret')]
        [System.Uri]$VaultDomain = $Script:DefaultVaultDomain,
        [Parameter(Mandatory = $true,ValueFromPipelineByPropertyName = $true,ParameterSetName='UserSecret')]
        [Parameter(Mandatory = $true,ValueFromPipelineByPropertyName = $true,ParameterSetName='NoUserSecret')]
        [String]$SecretName,
        [Parameter(Mandatory = $true,ValueFromPipelineByPropertyName = $true,ParameterSetName='UserSecret')]
        [String]$UserSecretName,
        [Parameter(Mandatory = $false,ValueFromPipelineByPropertyName = $true,ParameterSetName='UserSecret')]
        [Parameter(Mandatory = $false,ValueFromPipelineByPropertyName = $true,ParameterSetName='NoUserSecret')]
        [String]$ApiVersion = '2016-10-01',
        [Parameter(Mandatory = $false,ValueFromPipelineByPropertyName = $true,ParameterSetName='UserSecret')]
        [Parameter(Mandatory = $true,ValueFromPipelineByPropertyName = $true,ParameterSetName='NoUserSecret')]
        [String]$AccessToken        
    )
    process
    {
        if ($PSCmdlet.ParameterSetName -eq 'UserSecret') {
            $UserParams=@{
                VaultName=$UserVaultName;
                VaultDomain=$VaultDomain;
                ApiVersion=$ApiVersion;
                AccessToken=$AccessToken;
                SecretName=$UserSecretName;                
            }
            $UserName=Get-AzureVaultSecret @UserParams -ErrorAction Stop
        }
        $SecretParams=@{
            VaultName=$VaultName;
            VaultDomain=$VaultDomain;
            ApiVersion=$ApiVersion;
            AccessToken=$AccessToken;
            SecretName=$SecretName;
        }
        $SecurePassword=ConvertFrom-AzureVaultSecretToSecureString @SecretParams -ErrorAction Stop
        $Credential=New-Object PSCredential($UserName,$SecurePassword)
        Write-Output $Credential
    }
}

Function ConvertFrom-AzureVaultSecretToCertificate
{
    [OutputType([System.Security.Cryptography.X509Certificates.X509Certificate2])]
    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory = $true,ValueFromPipelineByPropertyName = $true)]
        [String]$VaultName,
        [Parameter(Mandatory = $false,ValueFromPipelineByPropertyName = $true)]
        [System.Uri]$VaultDomain = $Script:DefaultVaultDomain,
        [Parameter(Mandatory = $true,ValueFromPipelineByPropertyName = $true)]
        [String[]]$SecretName,    
        [Parameter(Mandatory = $false,ValueFromPipelineByPropertyName = $true)]
        [String]$ApiVersion = '2016-10-01',
        [Parameter(Mandatory = $true,ValueFromPipelineByPropertyName = $true)]
        [String]$AccessToken        
    )
    process
    {
        foreach ($item in $SecretName)
        {
            $SecretParams=@{
                VaultName=$VaultName;
                VaultDomain=$VaultDomain;
                ApiVersion=$ApiVersion;
                AccessToken=$AccessToken;
                SecretName=$item;
            }            
            #Retreive the secret from the vault   
            $SecretResult=Get-AzureVaultSecret @SecretParams -ErrorAction Stop
            if($SecretResult -ne $null -and (-not [string]::IsNullOrEmpty($SecretResult)))
            {
                #Convert the certficate reference...
                $SecretBytes=[Convert]::FromBase64String($SecretResult)
                $Cert=[System.Security.Cryptography.X509Certificates.X509Certificate2]::new($SecretBytes)
                Write-Output $Cert
            }            
        }
    }
}