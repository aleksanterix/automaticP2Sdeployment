# Azure Point-to-Site VPN Auto-Deployment

This project provides a PowerShell script to automatically deploy Azure resources and setup a Point-to-Site (P2S) VPN connection. The script creates a Virtual Network (VNet), VPN Gateway, and a Public IP. Then, it configures a VPN connection from the local machine where the script is run.

## Prerequisites
Azure Subscription
PowerShell version 7+
Azure PowerShell module

## Resources Deployed
The following resources are created by the script:

Virtual Network (VNet)
VPN Gateway
Public IP

## Configurations

### VNet configuration:

```json
Copy code
"vnetAddressSpace": "10.0.0.0/16",
"subnetConfig": [
    {
        "name": "MainSubnet",
        "addressPrefix": "10.0.0.0/24"
    },
    {
        "name": "GatewaySubnet",
        "addressPrefix": "10.0.1.0/24"
    }
],
"gwSKU": "VpnGw1",
And, the VPN Client Configuration is as follows:
```

### Gateway configuration

```json
Copy code
"vpnClientConfiguration": {
    "vpnClientAddressPool": {
        "addressPrefixes": [
            "10.1.0.0/24"
        ]
    },
    "vpnClientRootCertificates": [
        {
            "name": "[variables('vpnClientRootCertName')]",
            "publicCertData": "[parameters('vpnClientRootCertPublicCertData')]"
        }
    ],
    "vpnClientProtocols": [
        "IkeV2"
    ]
}
```

### Usage
Clone the repository:

```bash
git clone https://github.com/aleksanterix/automaticP2Sdeployment.git
```
Navigate to the directory containing the script:

```bash
cd automaticP2Sdeployment
```

Run the script run.ps1:

```powershell
.\run.ps1
```

The script will prompt you to provide inputs as needed.

Once the script completes the Azure resource deployment, download the VPN client configuration file from the Azure portal.

Set up the VPN connection on your local machine using the downloaded configuration file.

## In Progress
Currently, the following steps are in progress:

- Automatic download of the VPN client configuration file.
- Automatic setup of the VPN connection based on the downloaded configuration file.
