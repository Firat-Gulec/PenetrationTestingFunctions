function Get-PortProtocolSupport {
    <#
.SYNOPSIS
Get-PortProtocolSupport payload which Scan Server SSL and TLS Support Sslv2, Sslv3, Tls, Tls1.1, Tls1.2

.DESCRIPTION
Scan for Domain name and open Port and timeout. it returns SSL and TLS support informations 

.PARAMETER Domain
Resolve Domain

.PARAMETER ScanPort
Perform a PortScan

.PARAMETER Ports
Perform a Port. The default values are: 80, 443, 445

.PARAMETER TimeOut
Time (in MilliSeconds) before TimeOut, Default set to 1500

.EXAMPLE
PS > Get-PortProtocolSupport -Domain google.com -ScanPort
Use above to do a port scan on default ports.

.EXAMPLE
PS > Get-PortProtocolSupport -Domain google.com -ScanPort -Port 443

.EXAMPLE
PS > Get-PortProtocolSupport -Domain google.com -ScanPort -Port 443 -TimeOut 150

.NOTES
Author: Firat Gulec
#>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true, ValueFromPipeline = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$Domain, 
        
        [switch]
        $ScanPort,

        [int[]]
        $Ports = @(80, 443, 445),
        
        [int]
        $TimeOut = 1500
    )
    process {
        $RetValue = @()
        if ($ScanPort) {
            for ($i = 1; $i -le $Ports.Count; $i++) {
                $port = $Ports[($i - 1)]
                $SSLv2 = $false
                $SSLv3 = $false
                $TLSv1_0 = $false
                $TLSv1_1 = $false
                $TLSv1_2 = $false
                $TLSv1_3 = $false
                $KeyExchange = $null
                $HashAlgorithm = $null

                # Protocols to test
                $protocols = @("Ssl2", "Ssl3", "Tls", "Tls11", "Tls12", "Tls13")
                Try {
                    foreach ($protocol in $protocols) {
                    
                        $TcpClient = New-Object Net.Sockets.TcpClient
                        $TcpClient.Connect($Domain, $port)
                        $SslStream = New-Object Net.Security.SslStream($TcpClient.GetStream())
                        $SslStream.ReadTimeout = $TimeOut 
                        $SslStream.WriteTimeout = $TimeOut 
                        try {
                            $SslStream.AuthenticateAsClient($Domain, $null, $protocol, $false)
                            $status = $true
                            $KeyExchange = $SslStream.KeyExchangeAlgorithm
                            $HashAlgorithm = $SslStream.HashAlgorithm
                        }
                        catch {
                            $status = $false
                        }
                        # Update the RetValue object based on the protocol tested
                        switch ($protocol) {
                            "Ssl2" { $SSLv2 = $status }
                            "Ssl3" { $SSLv3 = $status }
                            "Tls" { $TLSv1_0 = $status }
                            "Tls11" { $TLSv1_1 = $status }
                            "Tls12" { $TLSv1_2 = $status }
                            "Tls13" { $TLSv1_3 = $status }
                        }
                        $SslStream.Dispose()
                        $TcpClient.Dispose()
                    }
                }
                catch {
                    $status = $false
                    $port = "$($port)-(closed)"
                }
                ## Create object by ports
                $RetValue += [PSCustomObject]@{
                    Domain        = $Domain
                    Port          = $port
                    SSLv2         = $SSLv2
                    SSLv3         = $SSLv3
                    TLSv1_0       = $TLSv1_0
                    TLSv1_1       = $TLSv1_1
                    TLSv1_2       = $TLSv1_2
                    TLSv1_3       = $TLSv1_3
                    KeyExchange   = $KeyExchange
                    HashAlgorithm = $HashAlgorithm
                }
            }
            return $RetValue
        }
    }  
}

Get-PortProtocolSupport -Domain google.com -ScanPort -Ports 443