function Get-DnsRecords {
    <#
.SYNOPSIS
Get-DnsRecords payload which Scan DNS Records

.DESCRIPTION
Scan for Domain name it returns DNS records

.PARAMETER Domain
Resolve Domain name

.EXAMPLE
PS > Get-DnsRecords -Domain google.com 

.NOTES
Author: Firat Gulec
#>
    param (
        [string] $domain
    )
    $result = ''
    $dnsRecords = @()
    $result = Resolve-DnsName -Name $domain -ErrorAction SilentlyContinue
    foreach ($entry in $result) {
        if ($entry.PSObject.Properties['IPAddress']) {
            if ($entry.QueryType -eq "A") {
                $dnsRecord = [PSCustomObject]@{
                    Name         = $entry.Name
                    Type         = $entry.QueryType
                    Address      = "$($entry.IPAddress)"
                    Aliases      = $null
                    MailExchange = $null
                    TextRecord   = $null
                }
            }
            if ($entry.QueryType -eq "CNAME") {
                $dnsRecord.Name = $entry.Name
                $dnsRecord.Type = $entry.QueryType
                $dnsRecord.Aliases = $entry.CName
            }
            if ($entry.QueryType -eq "MX") {
                $dnsRecord.Name = $entry.Name
                $dnsRecord.Type = $entry.QueryType
                $dnsRecord.MailExchange = $entry.MailerExchange
            }
            if ($entry.QueryType -eq "TXT") {
                $dnsRecord.Name = $entry.Name
                $dnsRecord.Type = $entry.QueryType
                $dnsRecord.TextRecord = $entry.Text
            }
            $dnsRecords += $dnsRecord
        }
    }
    return $dnsRecords
}

Get-DnsRecords -domain google.com