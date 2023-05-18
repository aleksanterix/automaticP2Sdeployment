# Overview: This script is used to automatically generate root certificates and client certificates for the VPN deployment, and then deploy the VPN gateway and VPN client VMs based on the ARM template.
# We will use a self-signed root certificate to sign the client certificate, and upload the root certificate to Azure then use the client certificate to connect to the VPN gateway.


###! Functions

##! Greetings

function greetings {
    Write-Host "Welcome to the VPN deployment script!"
    Write-Host ""
    Write-Host "This script will deploy resources based on the azuredeploy.json and download and execute the VPN client installer."
    Write-Host ""
    Write-Host "Please ensure that you have the following prerequisites:"
    Write-Host "1. Az-Module for PowerShell installed"
    Write-Host "2. PowerShell version 5.1 or above"
    Write-Host "3. A valid Azure subscription"
    Write-Host "4. A valid Azure AD user account with permissions to create resources in the subscription"
    Write-Host "5. A valid Azure AD user account with permissions to download the VPN client configuration"
    Write-Host "NOTICE: Running this script may incur charges on your Azure subscription as it will create resources."
    Write-Host "The creator of this script is not responsible for any charges incurred."
    Write-Host "Please continue at your own risk."
    Write-Host ""
    Read-Host "Press Enter to continue"
}

##! Certificate functions
# Get certificate thumbprint
# Set certificate names by taking in a user input and appending "RootCert" and "ChildCert" to the name
function Set-CertNames {
    # Get the certificate name
    $certNaming = Read-Host "Enter the name for the certificates"
    # Make array of certificate names
    $certificates = @{
        root = @{
            Name = $certNaming + "RootCert"
        }
        child = @{
            Name = $certNaming + "ChildCert"
        }
    }

    Write-Host ""
    return $certificates
}

# Gets the thumbprint of the certificate by taking in the certificate name. This is needed for the certificate path.
function Get-Cert-Thumbprint {
    param (
        $Subject
    )
    return Get-ChildItem Cert:\CurrentUser\My\ | Where-Object -FilterScript { $_.Subject -eq "CN=$Subject"} | Select-Object -ExpandProperty Thumbprint
}

# Helper function to get the certificate path with the name of the certificate
function Get-Cert-Path {
    param (
        $Subject
    ) 
    return "Cert:\CurrentUser\My\" + (Get-Cert-Thumbprint $Subject)
}

# Check if the certificate exists by invoking the Get-Cert-Thumbprint command. If the value is null, the certificate does not exist.
function Test-Cert-Exists {
    Write-Host "Checking if the certificates already exist..."

    $existingCerts = @()
    $certExists = $false

    foreach ($certName in $certificates.Values.Name) {
        $certThumbprint = Get-Cert-Thumbprint $certName
        if ($null -eq $certThumbprint) {
        } else {
            $existingCerts += $certName
            $certExists = $true
        }
    }

    # If the array is empty, print that no certificates exist and return false. Otherwise, print the existing certificates and return true.

    if ($certExists) {
        Write-Host "The following certificates already exist:"
        foreach ($cert in $existingCerts) {
            Write-Host $cert
        }
    } else {
        Write-Host "No overlapping certificates exist."
    }

    # Check if the client certificate exists
    if (!$certExists) {
        Write-Host ""
        Write-Host "Continuing..."
        Write-Host ""
    } else {
        Write-Host ""
        $answer = Read-Host "Would you like to delete them and create new ones? (y/n)"
        if ($answer -eq "y") {
            foreach($cert in $existingCerts) {
                $certPath = Get-Cert-Path $cert
                Remove-Item -Path $certPath
            }
            Write-Host "Certificates deleted."
        } else {
            Write-Host "Please run the script again with a different certificate name."
            Write-Host "Exiting..."
            exit
        }
    }

}

# Generate root certificate and client certificate
function New-Certificates {
    param ()
    # Generate root certificate
    $rootSubject = "CN=" + $certificates.root.Name
    Write-Host "Generating root certificate..."
    $cert = New-SelfSignedCertificate -Type Custom -KeySpec Signature `
    -Subject $rootSubject -KeyExportPolicy Exportable `
    -HashAlgorithm sha256 -KeyLength 2048 `
    -CertStoreLocation "Cert:\CurrentUser\My" -KeyUsageProperty Sign -KeyUsage CertSign

    # Generate client certificate signed by root certificate
    $childSubject = "CN=" + $certificates.child.Name
    Write-Host "Generating client certificate..."
    New-SelfSignedCertificate -Type Custom -DnsName $childSubject -KeySpec Signature `
    -Subject $childSubject -KeyExportPolicy Exportable `
    -HashAlgorithm sha256 -KeyLength 2048 `
    -CertStoreLocation "Cert:\CurrentUser\My" `
    -Signer $cert -TextExtension @("2.5.29.37={text}1.3.6.1.5.5.7.3.2") > $null

    Write-Host ""
    Write-Host "Certificates generated."
    Write-Host ""
}

# Export root certificate to a Base64 file
function Set-CertificateToBase64File {
    param ()
    $rootFile = $certificates.root.Name + ".cer"
    # Define the certificate path
    $certPath = Get-Cert-Path $certificates.root.Name 
    $exportPath = Join-Path -Path $pwd -ChildPath $rootFile
    $base64Cert = $certificates.root.Name + '64.cer'
    $export64Path = Join-Path -Path $pwd -ChildPath $base64Cert

    # Export the root certificate to a file and convert it to base64
    Write-Host ""
    Write-Host "Exporting root certificate to a file..."
    Export-Certificate -Cert $certPath -FilePath $exportPath -Type CERT > $null
    certutil.exe -encode $exportPath $export64Path > $null
    Write-Host "Root certificate exported to $export64Path"

    # Remove the non-base64 certificate file
    Write-Host "Cleaning up..."
    Remove-Item $exportPath
    Write-Host "Cleanup complete."
    Write-Host "Certificate export complete."
    Write-Host ""

    return $export64Path

}
# Get the base64 string from the certificate file
function Get-Cert-Base64String {
    param ()
    ## Parse the base64 certificate file to a variable and remove -----BEGIN CERTIFICATE----- and -----END CERTIFICATE----- from the string
    # Read the certificate file content
    $certFile = Get-Content -Path $export64Path
    # Remove the BEGIN and END certificate lines
    $certFile = $certFile | Where-Object { $_ -ne '-----BEGIN CERTIFICATE-----' -and $_ -ne '-----END CERTIFICATE-----' }
    $certString = $certFile -join ''

    return $certString
}
##! Azure functions
# Set the subscription
function Set-ValueForSubscription {
    param ()
    # Get subscriptions
    $subscriptions = Get-AzSubscription

    # Present the list of subscriptions to the user and prompt for selection
    Write-Host "Available subscriptions: "
    
    # Create an array to store the subscription IDs
    $subscriptionChoiches = @()

    # Loop through the subscriptions, add to array and present them to the user
    $index = 0
    foreach ($subscription in $subscriptions) {
        Write-Host "$index. $($subscription.Name)"
        $subscriptionChoiches += $subscription.Id
        $index++
    }
    # Prompt for selection
    $selection = Read-Host "Enter the number corresponding to the desired subscription"
    $subscriptionId = $subscriptionChoiches[$selection]

    Write-Host "Setting subscription to $subscriptionId"

    Set-AzContext -SubscriptionId $subscriptionId

    Write-Host "Subscription set successfully."
}
function Set-ValueForLocation {
    param ()
    # Get locations
    Write-Host "Getting available locations for deployments..."
    $locations = Get-AzLocation | Where-Object {$_.Providers -contains "Microsoft.AppConfiguration"}

    # Present the list of locations to the user and prompt for selection
    Write-Host "Available locations: "
    $index = 0
    $locationChoiches = @()
    foreach ($location in $locations) {
        Write-Host "$index. $($location.DisplayName)"
        $locationChoiches += $location
        $index++
    }
    # Prompt for selection
    $selection = Read-Host "Enter the number corresponding to the desired location"
    $location = $locationChoiches[$selection]

    Write-Host "Location set to "$location.DisplayName" All resources will be deployed to this location."

    return $location 
}

function Set-ValueForResourceGroup {
    param ()
    # Ask for resource group name

    Write-Host "Please enter the name of the resource group to deploy to. If it doesn't exist, it will be created."
    $rg = Read-Host "Enter the name of the resource group to deploy to"

    # Check if resource group exists
    $rgExists = Get-AzResourceGroup -Name $rg -ErrorAction SilentlyContinue

    # If resource group doesn't exist, create it
    if (!$rgExists) {
        $answer = Read-Host "Resource group $rg does not exist. Would you like to create it? (y/n)"
        if ($answer -eq "y") {
            Write-Host "Creating resource group $rg in location "$location.DisplayName""
            New-AzResourceGroup -Name $rg -Location $location.Location > $null
            Write-Host ""
            Write-Host "Resource group $rg created successfully."
            Write-Host ""
        } else {
            Write-Host "Exiting..."
            exit
        }
    } else {
        Write-Host "Resource group $rg exists. Continuing..."
    }
    return $rg
}
function Get-DeploymentNames {
    $deploymentNames = @{
        VNet = @{
            Name = Read-Host "Enter the name of the VNet"
            Deployment = "VNet"
        }
        PublicIP = @{
            Name = Read-Host "Enter the name of the public IP"
            Deployment = "PublicIP"
        } 
        Gateway = @{
            Name = Read-Host "Enter the name of the VPN gateway"
            Deployment = "Gateway"
        }
    }

    return $deploymentNames
}
function Get-VpnClientConfiguration {    
    $output = ".\config.zip"
    $gw = $deployments.Gateway.Name
    #! Explanation: The process which is started in the lines below will be named after the Virtual Network, hence the $process variable is named $deployments.VNet.Name
    $process = $deployments.VNet.Name
    Write-Host ""
    Write-Host "Getting VPN client configuration download link..."
    Write-Host ""
    $p2sVpnConfigDownloadLink =  Get-AzVpnClientConfiguration -ResourceGroupName "$rg" -Name "$gw"
    Write-Host "VPN client configuration download link retrieved."
    Write-Host ""
    Write-Host "Downloading VPN client configuration..."
    Invoke-WebRequest -Uri $p2sVpnConfigDownloadLink.VpnProfileSASUrl -OutFile $output
    Write-Host ""
    Write-Host "VPN client configuration downloaded succesfully!"
    Write-Host ""
    Write-Host "Extracting VPN client configuration..."
    Expand-Archive -Path $output -DestinationPath .\config
    Write-Host "Extraction complete."
    Write-Host ""
    Write-Host "Cleaning up..."
    Remove-Item $output
    
    Write-Host ""
    Read-Host "This will now start the VPN client. Please allow the program to make changes to your computer. Press any Enter to continue."

    $file = Get-ChildItem -Path .\config\WindowsAmd64 -Filter *.exe 
    Start-Process -Path $file -Wait
    Write-Host ""
    # Wait until the VPN client is closed
    Write-Host "VPN client closed. The script will now continue."
    Write-Host "NOTICE: The script doesn't check if the VPN client was succesfully installed. If the VPN client was not installed, please install it manually."
    Write-Host ""
    Write-Host ""
}

#####! Main script !#####

## Greeting and instructions

greetings

# Check if a certificate with the same name exists. And ask if the user wants to delete the existing certificates

$certificates = Set-CertNames

Test-Cert-Exists

# ###! Certificate part !###

# Generate root certificate and client certificate, and export them to a base64 file in the current directory then get the base64 string to a variable

New-Certificates

$export64Path = Set-CertificateToBase64File

$CertString = Get-Cert-Base64String

Write-Host ""
Write-Host "Certificate generation complete."
Write-Host ""

##### Azure part #####

# Write-Host "Connecting to Azure..."

# Connect to Azure
Connect-AzAccount

# Set the subscription
Set-ValueForSubscription

# Get location for deployments
$location = Set-ValueForLocation

# Get resource group, or create it if it doesn't exist
$rg = Set-ValueForResourceGroup


## Ask names for the deployment resources

$deployments = Get-DeploymentNames

Write-Host ""
Write-Host "Deployment names set successfully."
Write-Host ""

#! Gather parameters for ARM Template deployment

$parameters = @{
    "Location" = $location.Location
    "vpnClientRootCertPublicCertData" = $certString
    "vnetName" = $deployments.VNet.Name
    "publicIPAddressName" = $deployments.PublicIP.Name
    "gatewayName" = $deployments.Gateway.Name
}


#! Deploy ARM Template

Read-Host "We will now deploy the ARM Template. Press Enter to continue or CTRL+C to cancel"

# New-AzResourceGroupDeployment -ResourceGroupName "$rg" -TemplateParameterObject $parameters

#! Download VPN client configuration, unzip it and start the VPN installer.

$vpnConfig = Get-VpnClientConfiguration