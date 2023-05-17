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

##! Variables
$rootCertName = "P2SRootCertTEST"
$certName = "P2SChildCertTEST"
$password = ConvertTo-SecureString -String "password123" -Force -AsPlainText

##! Functions
#Function to get the certificate thumbprint in order to get the certificate path
function Get-Cert-Thumbprint {
    param (
        $Subject
    )
    return Get-ChildItem Cert:\CurrentUser\My\ | Where-Object -FilterScript { $_.Subject -eq "CN=$Subject"} | Select-Object -ExpandProperty Thumbprint
}


##! Generate root certificate and client certificate, and export them to a base64 file in the current directory
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

# Define the certificate path
$certThumbprint = Get-Cert-Thumbprint $rootCertName
$certPath = "Cert:\CurrentUser\My\$certThumbprint" 
$exportPath = Join-Path -Path $pwd -ChildPath "$rootCertName.cer"
$base64Cert = $rootCertName + '64' + '.cer'
$export64Path = Join-Path -Path $pwd -ChildPath $base64Cert

# Export the root certificate to a file and convert it to base64
Write-Host "Exporting root certificate to a file..."
Export-Certificate -Cert $certPath -FilePath $exportPath -Type CERT
certutil.exe -encode $exportPath $export64Path

# Remove the non-base64 certificate file
Write-Host "Cleaning up..."
Remove-Item $exportPath

## Parse the base64 certificate file to a variable and remove -----BEGIN CERTIFICATE----- and -----END CERTIFICATE----- from the string
# Read the certificate file content
$certFile = Get-Content -Path $export64Path
# Remove the BEGIN and END certificate lines
$certFile = $certFile | Where-Object { $_ -ne '-----BEGIN CERTIFICATE-----' -and $_ -ne '-----END CERTIFICATE-----' }
$certString = $certFile -join ''


#####! Azure part

Write-Host "Connecting to Azure..."
Write-Host "You will be prompted to login to Azure."

#! Connecting to Azure and setting the subscription
Connect-AzAccount

# Get subscriptions
$subscriptions = Get-AzSubscription

# Present the list of subscriptions to the user and prompt for selection
Write-Host "Available subscriptions: "
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


#! Get location for deployments
# Get locations
Write-Host "Getting available locations for deployments..."
$locations = Get-AzLocation | Where-Object {$_.Providers -contains "Microsoft.AppConfiguration"}

# Present the list of locations to the user and prompt for selection
Write-Host "Available locations: "
$index = 0
$locationChoiches = @()
foreach ($location in $locations) {
    Write-Host "$index. $($location.DisplayName)"
    $locationChoiches += $location.DisplayName
    $index++
}
# Prompt for selection
$selection = Read-Host "Enter the number corresponding to the desired location"
$location = $locationChoiches[$selection]

Write-Host "Location set to $location. All resources will be deployed to this location."

#! Get resource group, or create it if it doesn't exist

# Ask for resource group name

Write-Host "Please enter the name of the resource group to deploy to. If it doesn't exist, it will be created."
$rg = Read-Host "Enter the name of the resource group to deploy to"

# Check if resource group exists
$rgExists = Get-AzResourceGroup -Name $rg -ErrorAction SilentlyContinue

# If resource group doesn't exist, create it
if (!$rgExists) {
    $answer = Read-Host "Resource group $rg does not exist. Would you like to create it? (y/n)"
    if ($answer -eq "y") {
        Write-Host "Creating resource group $rg in location $location"
        New-AzResourceGroup -Name $rg -Location $location
    } else {
        Write-Host "Exiting..."
        exit
    }
} else {
    Write-Host "Resource group $rg exists. Continuing..."
}

#! Gather parameters for ARM Template deployment

$parameters = @{
    "Location" = $location
    "vpnClientRootCertPublicCertData" = $certString
}

#! Deploy ARM Template

Read-Host "We will now deploy the ARM Template. Press Enter to continue or CTRL+C to cancel."

New-AzResourceGroupDeployment -ResourceGroupName "$rg" -TemplateParameterObject $parameters
