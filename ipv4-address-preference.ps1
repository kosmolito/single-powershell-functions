# Check if the process is running in elevated mode, if not, the scrip stops
$currentPrincipal = [System.Security.Principal.WindowsPrincipal] [System.Security.Principal.WindowsIdentity]::GetCurrent()
$isAdmin = $currentPrincipal.IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)
if (!($isAdmin)) {
Write-Error "You need to run the script as administrator!"
Pause
exit
}

# My Network Preference for each network I am connected to.
$MyNetworks = (
    @{
    ConnectedNetwork = "UNI-KOSMO30"
    IPAddress = "192.168.30.13"
    DefGateway = "192.168.30.1"
    DnsSrvAddress = "192.168.20.1"
    },
    @{
        ConnectedNetwork = "MyWorkNetwork"
        IPAddress = "192.168.1.100"
        DefGateway = "192.168.1.1"
        DnsSrvAddress = "192.168.1.1"
    },
    @{
        ConnectedNetwork = "School123"
        IPAddress = "192.168.1.10"
        DefGateway = "192.168.10.1"
        DnsSrvAddress = "192.168.10.1"
    }
)

function Set-IPV4Address {
<#
.SYNOPSIS
Changing the IPV4 Address depending on which network I am connected to

.DESCRIPTION
Long description

.PARAMETER IPAddress
The IPV4 address

.PARAMETER DefGateway
Default Gateway address

.PARAMETER DnsSrvAddress
Dns Address

.PARAMETER ConnectedNetwork
The name of the connected network. This is gathered by (Get-NetConnectionProfile).Name command

.EXAMPLE
Set-IPV4Address -ConnectedNetwork "ExampleNetworkName" -IPAddress "192.168.1.10" -DefGateway "192.168.1.1" -DnsSrvAddress "192.168.1.1"

.NOTES
General notes
#>
[CmdletBinding()]
param(
[Parameter(Mandatory)][String]$ConnectedNetwork,
[Parameter(Mandatory)][string]$IPAddress,
[Parameter(Mandatory)][string]$DefGateway,
[Parameter(Mandatory)][string]$DnsSrvAddress
)

# Retrieve the network adapter
$NetProfile = Get-NetConnectionProfile
if ($NetProfile.Count -gt 1) {
    $NetProfile | ForEach-Object {$index=0} {$_; $index++} | Format-Table -Property @{Label="Index";Expression={$index}},Name,InterfaceAlias
    $NetProfileSelected = read-host "Select the interface index, eg, 0 or 1"
    $NetProfile = $NetProfile[[int32]$NetProfileSelected]
}
$NetAdapter = Get-NetAdapter -InterfaceIndex $NetProfile.InterfaceIndex

$SubMaskBit = "24"
$IPVType = "IPv4"

if ($NetProfile.Name -like $ConnectedNetwork) {

    # Disabling IPV6
    if (($NetAdapter | Get-NetAdapterBinding -ComponentID "ms_tcpip6").Enabled -eq $true ) {
        $NetAdapter | set-NetAdapterBinding -ComponentID "ms_tcpip6" -Enabled $False
    }

    Write-Verbose "Network is [$($ConnectedNetwork)]. Setting IPv4 and DNS to static values" -Verbose

    # Remove existing IP config from the adapter.
        If (($Netadapter | Get-NetIPConfiguration).IPv4Address.IPAddress) {
        $Netadapter | Remove-NetIPAddress -AddressFamily $IPVType -Confirm:$false
        }
        If (($Netadapter | Get-NetIPConfiguration).Ipv4DefaultGateway) {
        $Netadapter | Remove-NetRoute -AddressFamily $IPVType -Confirm:$false
        }
        # Config of the IP and gateway
        $Netadapter | New-NetIPAddress `
        -AddressFamily $IPVType `
        -IPAddress $IPAddress `
        -PrefixLength $SubMaskBit `
        -DefaultGateway $DefGateway | Out-Null
        #Config the DNS
        $Netadapter | Set-DnsClientServerAddress -ServerAddresses $DnsSrvAddress
    } else {
        Write-Verbose "Network is NOT [$($ConnectedNetwork)]. Setting IPv4 and DNS by DHCP" -Verbose
            # Remove existing IP config from the adapter.
        If (($Netadapter | Get-NetIPConfiguration).IPv4Address.IPAddress) {
            $Netadapter | Remove-NetIPAddress -AddressFamily $IPVType -Confirm:$false
            }
            If (($Netadapter | Get-NetIPConfiguration).Ipv4DefaultGateway) {
            $Netadapter | Remove-NetRoute -AddressFamily $IPVType -Confirm:$false
            }
        $NetAdapter | Set-NetIPInterface -Dhcp Enabled
        $Netadapter | Set-DnsClientServerAddress -ResetServerAddresses
    }

}

# If the computer is connected to multiple profiles, you will select the network to chose.
$NetProfile = Get-NetConnectionProfile
if ($NetProfile.Count -gt 1) {
    $NetProfile | ForEach-Object {$index=0} {$_; $index++} | Format-Table -Property @{Label="Index";Expression={$index}},Name,InterfaceAlias
    $NetProfileSelected = read-host "Select the interface index, eg, 0 or 1"
    $NetProfile = $NetProfile[[int32]$NetProfileSelected]
}



# Instead of writing the parameters every time, the value of each network is stored in $MyNetworks
# This loop will look if its find any name in $MyNetworks that is matching the connected NetworkProfile
# If it find, the value will be set according to the information that is provided in the $MyNetworks variable
$NetworkFound = 0
foreach ($Network in $MyNetworks) {
    if ($NetProfile.Name -like $Network.ConnectedNetwork) {
        $NetworkFound = 1
        Set-IPV4Address @Network
        break
    }
}

# if noting found, the value ip settings will be setup from DHCP, so generic value is set here
if ($NetworkFound -eq 0) {
    Set-IPV4Address -ConnectedNetwork "---Unkown---" -IPAddress "0" -DefGateway "0" -DnsSrvAddress "0"
}