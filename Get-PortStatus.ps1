
function Get-PortStatus {
    <#
.SYNOPSIS
Get-PortStatus payload which Scan IP-Addresses, Ports and HostNames

.DESCRIPTION
Scan for IP-Addresses, HostNames and open Ports in your Network.

.PARAMETER ResolveHost
Resolve HostName

.PARAMETER ScanPort
Perform a PortScan

.PARAMETER Ports
Ports That should be scanned, default values are: 21,22,23,53,69,71,80,98,110,139,111,
389,443,445,1080,1433,2001,2049,3001,3128,5222,6667,6868,7777,7878,8080,1521,3306,3389,
5801,5900,5555,5901

.PARAMETER TimeOut
Time (in MilliSeconds) before TimeOut, Default set to 100

.EXAMPLE
PS > Get-PortStatus -Address 10.200.66.7

.EXAMPLE
PS > Get-PortStatus -Address 10.200.66.7 -ResolveHost

.EXAMPLE
PS > Get-PortStatus -Address 10.200.66.7 -ResolveHost -ScanPort
Use above to do a port scan on default ports.

.EXAMPLE
PS > Get-PortStatus -Address 10.200.66.7 -ResolveHost -ScanPort -TimeOut 500

.EXAMPLE
PS > Get-PortStatus -Address 10.200.66.7 -ResolveHost -ScanPort -Port 80

.NOTES
Author: Firat Gulec
#>
    [CmdletBinding()] Param(
        [parameter(Mandatory = $true, Position = 0)]
        [ValidatePattern("\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b")]
        [string]
        $Address,
        
        [switch]
        $ResolveHost,

        [switch]
        $ScanPort,

        [int[]]
        $Ports = @(21, 22, 23, 53, 69, 71, 80, 98, 110, 139, 111, 389, 443, 445, 1080, 1433, 2001, 2049, 3001, 3128, 5222, 6667, 6868, 7777, 7878, 8080, 1521, 3306, 3389, 5801, 5900, 5555, 5901),
        
        [int]
        $TimeOut = 100
    )  
    Begin {
        $ping = New-Object System.Net.Networkinformation.Ping
    }
    Process {
    
        write-progress -activity PingSweep -status $Address 
        $pingStatus = $ping.Send($Address, $TimeOut)
        if ($pingStatus.Status -eq "Success") {
            if ($ResolveHost) {
                write-progress -activity ResolveHost -status $Address -Id 1
                $getHostEntry = [Net.DNS]::BeginGetHostEntry($pingStatus.Address, $null, $null)
            }
            if ($ScanPort) {
                $openPorts = @()
                for ($i = 1; $i -le $ports.Count; $i++) {
                    $port = $Ports[($i - 1)]
                    write-progress -activity PortScan -status $Address  -Id 2
                    $client = New-Object System.Net.Sockets.TcpClient
                    $beginConnect = $client.BeginConnect($pingStatus.Address, $port, $null, $null)
                    if ($client.Connected) {
                        $openPorts += $port
                    }
                    else {
                        # Wait
                        Start-Sleep -Milli $TimeOut
                        if ($client.Connected) {
                            $openPorts += $port
                        }
                    }
                    $client.Close()
                }
            }
            if ($ResolveHost) {
                #  $hostName = ([Net.DNS]::EndGetHostEntry([IAsyncResult]$getHostEntry)).HostName
            }
            # Return Object
            New-Object PSObject -Property @{
                IPAddress = $Address;
                # HostName = $hostName;
                Ports     = $openPorts
            } | Select-Object IPAddress, HostName, Ports
        }
            
    }
    End {
    }
}

Get-PortStatus -Address 10.200.66.7  -ResolveHost -ScanPort -Ports 80
