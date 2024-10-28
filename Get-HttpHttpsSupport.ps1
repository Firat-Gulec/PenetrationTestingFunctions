function Get-HttpHttpsSupport {
    <#
.SYNOPSIS
Get-HttpHttpsSupport payload which scans website http and https support. it returns certificate informations.

.DESCRIPTION
Scan for Domain name it returns Https and https support and certificate

.PARAMETER Domain
Resolve Domain

.PARAMETER TimeOut
Time (in MilliSeconds) before TimeOut, Default set to 5000

.EXAMPLE
PS > Get-HttpHttpsSupport -domain google.com
Use above to do default timeout

.NOTES
Author: Firat Gulec
#>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true, ValueFromPipeline = $true)]
        [ValidateNotNullOrEmpty()]

        [string] $Domain,

        [int]
        $TimeOut = 5000

    )
    process {
        $HttpHttpsSupport = [PSCustomObject]@{
            Http_Status      = "-"
            Http_Redirected  = "-"
            Https_Status     = "-"
            Https_Redirected = "-"
            Certificate      = "-"
            CertificateName  = "-"
            EffectiveDate    = "-"
            Issuer           = "-"
            ProtocolVersion  = "-"
            Expiration       = "-"
            ExpiresInDays    = "-"
        }
        $redirectUrl = "NONE"
        $response = "-"
        $statusCode = "-"
        $webRequestt = [Net.WebRequest]::Create("http://$Domain")
        $webRequestt.Method = "HEAD"  
        $webRequestt.AllowAutoRedirect = $false  
        $webRequestt.Timeout = $TimeOut
        try { $response = $webRequestt.GetResponse() } catch [System.Net.WebException] { $response = $_.Exception.Response }
        If ($response.StatusCode -eq $null) {
            $responseUri = "NONE" 
            $statusCode = "NONE"
        }
        else { 
            $responseUri = $response.ResponseUri 
            $statusCode = $response.StatusCode 
        }
        if ($statusCode -eq 301 -or $statusCode -eq 302) {
            $redirectUrl = $response.Headers["Location"]
            if ($redirectUrl.StartsWith("https://")) {
                $HttpHttpsSupport.Http_Status = $statusCode
                $HttpHttpsSupport.Http_Redirected = $redirectUrl
            }
            else {
                $HttpHttpsSupport.Http_Status = $statusCode
                $HttpHttpsSupport.Http_Redirected = $redirectUrl
            }
        }
        else {
            $HttpHttpsSupport.Http_Status = $statusCode
            $HttpHttpsSupport.Http_Redirected = $responseUri #"NOT_REDIRECTED"
        }
        if ([int]$response.StatusCode -ne 0) { $response.Close() }
        $webRequest = [Net.WebRequest]::Create("https://$Domain")
        #$webRequest.Method = "HEAD"  
        $webRequest.AllowAutoRedirect = $false  
        $webRequest.Timeout = 5000
        try { $res = $webRequest.GetResponse() } catch [System.Net.WebException] { $res = $_.Exception.Response }
        If ($res.StatusCode -eq $null) {
            $responseUri = "NONE" 
            $statusCode = "NONE"
        }
        else { 
            $responseUri = $res.ResponseUri 
            $statusCode = $res.StatusCode 
        }
        if ($statusCode -eq 301 -or $statusCode -eq 302) {
            $redirectUrl = $res.Headers["Location"]
            if ($redirectUrl.StartsWith("https://")) {
                $HttpHttpsSupport.Https_Status = $statusCode
                $HttpHttpsSupport.Https_Redirected = $redirectUrl
            }
            else {
                $HttpHttpsSupport.Https_Status = $statusCode
                $HttpHttpsSupport.Https_Redirected = $redirectUrl
            }
        }
        else {
            $HttpHttpsSupport.Https_Status = $statusCode
            $HttpHttpsSupport.Https_Redirected = $redirectUrl
        }
        if (( $HttpHttpsSupport.Https_Status -eq "OK" ) -or ( $HttpHttpsSupport.Https_Status -eq "MovedPermanently" ) -or ( $HttpHttpsSupport.Https_Status -eq "Redirect" ) -or ( $HttpHttpsSupport.Https_Status -eq "TemporaryRedirect" )) {
            if ($webRequest.PSObject.Properties['ServicePoint']) {
            
                $HttpHttpsSupport.Certificate = $webRequest.ServicePoint.Certificate.GetType().Name
                $HttpHttpsSupport.CertificateName = $webRequest.ServicePoint.Certificate.GetName() 
                $tmpcertEffectiveDate = $webRequest.ServicePoint.Certificate.GetEffectiveDateString()
                $DateTimeFormat = "dd/MM/yyyy HH:mm:ss"
                $HttpHttpsSupport.EffectiveDate = [DateTime]::ParseExact($tmpcertEffectiveDate, $DateTimeFormat, [System.Globalization.CultureInfo]::InvariantCulture)
                # "$([DateTime]::ParseExact("$tmpcertEffectiveDate", $DateTimeFormat, [System.Globalization.DateTimeFormatInfo]::InvariantInfo, [System.Globalization.DateTimeStyles]::None))"
                $HttpHttpsSupport.Issuer = $webRequest.ServicePoint.Certificate.GetIssuerName()
                $tmpExpiration = $webRequest.ServicePoint.Certificate.GetExpirationDateString()
                $expiration = [DateTime]::ParseExact("$tmpExpiration", $DateTimeFormat, [System.Globalization.DateTimeFormatInfo]::InvariantInfo, [System.Globalization.DateTimeStyles]::None) 
                $HttpHttpsSupport.ProtocolVersion = $webRequest.ProtocolVersion
                $HttpHttpsSupport.Expiration = $expiration 
                $HttpHttpsSupport.ExpiresInDays = ($expiration - $(get-date)).Days
            }
        }

        if ([int]$res.StatusCode -ne 0) { $res.Close() }
        return $HttpHttpsSupport
    }
} 



Get-HttpHttpsSupport -domain google.com