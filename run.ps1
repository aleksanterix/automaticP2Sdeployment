# Overview: This script is used to automatically generate root certificates and client certificates for the VPN deployment, and then deploy the VPN gateway and VPN client VMs based on the ARM template.
# We will use a self-signed root certificate to sign the client certificate, and then use the client certificate to connect to the VPN gateway.
# The resource group is already created in Azure.

# Tasks:
# 1. Assign variables such as resource group name, location, client certificate name,
# 2. Generate root certificate and client certificate, and export them to a file in the current directory
# 3. Extract the public key from the client certificate to a variable
# 4. Connect to Azure
# 5. Deploy the ARM Template using the public key and location as parameters
# 6. Download the VPN client configuration file to the current directory
# 7. Connect to the VPN gateway using the VPN client configuration file

#! Parameters

# param (
#     [Parameter(Mandatory=$true)]
#     [string]$rg,
#     [Parameter(Mandatory=$true)]
#     [string]$location
# )

###! Functions
##! Certificate functions
# Get certificate thumbprint
function Get-Cert-Thumbprint {
    param (
        $Subject
    )
    return Get-ChildItem Cert:\CurrentUser\My\ | Where-Object -FilterScript { $_.Subject -eq "CN=$Subject"} | Select-Object -ExpandProperty Thumbprint
}

function Get-Cert-Path {
    param (
        $Subject
    ) 
    return "Cert:\CurrentUser\My\" + (Get-Cert-Thumbprint $Subject)
}

# Check if the certificate exists by invoking the Get-Cert-Thumbprint command. If the value is null, the certificate does not exist.
function Test-Cert-Exists {
    $rootCertThumbprint = Get-Cert-Thumbprint $rootCertName
    $certThumbprint = Get-Cert-Thumbprint $certName

    Write-Host  $rootCertName
    Write-Host  $certName
    # Check if the root certificate exists
    if ($null -eq $rootCertThumbprint -or $null -eq $certThumbprint) {
        return $false
    }
    else {
        return $true
    }
}

# Generate root certificate and client certificate
function New-Certificates {
    param ()
    # Generate root certificate
    Write-Host "Generating root certificate..."
    $cert = New-SelfSignedCertificate -Type Custom -KeySpec Signature `
    -Subject "CN=$rootCertName" -KeyExportPolicy Exportable `
    -HashAlgorithm sha256 -KeyLength 2048 `
    -CertStoreLocation "Cert:\CurrentUser\My" -KeyUsageProperty Sign -KeyUsage CertSign

    # Generate client certificate signed by root certificate
    Write-Host "Generating client certificate..."
    New-SelfSignedCertificate -Type Custom -DnsName $certName -KeySpec Signature `
    -Subject "CN=$certName" -KeyExportPolicy Exportable `
    -HashAlgorithm sha256 -KeyLength 2048 `
    -CertStoreLocation "Cert:\CurrentUser\My" `
    -Signer $cert -TextExtension @("2.5.29.37={text}1.3.6.1.5.5.7.3.2")
}
# Export root certificate to a Base64 file
function Set-CertificateToBase64File {
    param ()
    # Define the certificate path
    $certThumbprint = Get-Cert-Thumbprint $rootCertName
    $certPath = "Cert:\CurrentUser\My\$certThumbprint" 
    $exportPath = Join-Path -Path $pwd -ChildPath "$rootCertName.cer"
    $base64Cert = $rootCertName + '64' + '.cer'
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

#####! Main script !#####

## Greeting and instructions
Write-Host "Welcome to the VPN deployment script."
Write-Host "This script will generate root and client certificates, deploy the VPN gateway and VPN client VMs, and connect to the VPN gateway."
Write-Host "Please follow the instructions."
Write-Host ""
Write-Host "First, I need you to give a name that will be used to generate the names for the certificates. Please enter a unique name for the certificates."
Write-Host "For example, if you enter 'test', the root certificate will be named 'testRootCert' and the client certificate will be named 'testChildCert'."
Write-Host ""
Write-Host "After this is done and the certificates are generated, the script will authenticate with Azure."
Write-Host "Then, the script will ask for you to select the subscription, location and resource group."
Write-Host "The script will then deploy the VPN gateway and VPN client VMs using the ARM template."
Read-Host "Press Enter to continue..."
Write-Host ""

## Ask for values
$certNaming = Read-Host "Enter the name for the certificates"
$rootCertName = $certNaming + "RootCert"
$certName = $certNaming + "ChildCert"

# Check if a certificate with the same name exists. And ask if the user wants to delete the existing certificates
$certExists = Test-Cert-Exists

if (!$certExists) {
    Write-Host "Certificate $rootCertName or $certName do not exist."
    Write-Host "Continuing..."
} else {
    Write-Host "Certificate $rootCertName or $certName already exist."
    $answer = Read-Host "Would you like to delete them? (y/n)"
    if ($answer -eq "y") {
        $rootThumb = Get-Cert-Thumbprint -Subject $rootCertName
        $childThumb = Get-Cert-Thumbprint -Subject $certName
        $rootPath = "Cert:\CurrentUser\My\" + $rootThumb
        $childPath = "Cert:\CurrentUser\My\" + $childThumb
        Write-Host "Deleting certificates..."
        Remove-Item -Path $rootPath
        Remove-Item -Path $childPath
        Write-Host "Certificates deleted."
    } else {
        Write-Host "Exiting..."
        exit
    }
}

###! Certificate part !###

# Generate root certificate and client certificate, and export them to a base64 file in the current directory then get the base64 string to a variable

New-Certificates

$export64Path = Set-CertificateToBase64File

$CertString = Get-Cert-Base64String

##### Azure part #####

Write-Host "Connecting to Azure..."
Write-Host "You will be prompted to login to Azure."

# Connect to Azure
Connect-AzAccount

# Set the subscription

Set-ValueForSubscription

# Get location for deployments

$location = Set-ValueForLocation

# Get resource group, or create it if it doesn't exist

$rg = Set-ValueForResourceGroup



#! Gather parameters for ARM Template deployment

$parameters = @{
    "Location" = $location.Location
    "vpnClientRootCertPublicCertData" = $certString
}

#! Deploy ARM Template

Read-Host "We will now deploy the ARM Template. Press Enter to continue or CTRL+C to cancel"

# New-AzResourceGroupDeployment -ResourceGroupName "$rg" -TemplateParameterObject $parameters
