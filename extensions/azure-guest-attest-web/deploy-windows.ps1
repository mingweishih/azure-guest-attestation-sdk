# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
#
# Deploy the Azure Guest Attestation Web UI extension to a Windows VM
# using the Azure Custom Script Extension.
#
# Prerequisites:
#   - Azure CLI (az) logged in
#   - The target VM must be running
#
# Usage:
#   .\deploy-windows.ps1 -ResourceGroup myRG -VMName myVM
#   .\deploy-windows.ps1 -ResourceGroup myRG -VMName myVM `
#       -Domain "myvm.eastus.cloudapp.azure.com" `
#       -Commit "v1.0" -Port 8443

[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)]
    [string]$ResourceGroup,

    [Parameter(Mandatory=$true)]
    [string]$VMName,

    [string]$Commit   = "main",
    [string]$Domain   = "",
    [int]   $Port     = 443,
    [string]$Bind     = "0.0.0.0",
    [string]$RepoUrl  = "https://github.com/Azure/azure-guest-attestation-sdk.git",

    # URL of the install.ps1 script — override for custom hosting
    [string]$ScriptUrl = "https://raw.githubusercontent.com/Azure/azure-guest-attestation-sdk/main/extensions/azure-guest-attest-web/windows/install.ps1"
)

$ErrorActionPreference = "Stop"

Write-Host "Deploying Azure Guest Attestation Web UI extension …"
Write-Host "  Resource Group: $ResourceGroup"
Write-Host "  VM Name:        $VMName"
Write-Host "  Commit:         $Commit"
Write-Host "  Domain:         $(if ($Domain) { $Domain } else { '(none)' })"
Write-Host "  Port:           $Port"
Write-Host ""

# ---------------------------------------------------------------------------
# Build the command that the Custom Script Extension will run inside the VM
# ---------------------------------------------------------------------------
$cmdArgs = @(
    "-Commit `"$Commit`""
    "-Port $Port"
    "-Bind `"$Bind`""
    "-RepoUrl `"$RepoUrl`""
)
if ($Domain) {
    $cmdArgs += "-Domain `"$Domain`""
}
$innerCmd = "powershell -ExecutionPolicy Bypass -File install.ps1 $($cmdArgs -join ' ')"

# ---------------------------------------------------------------------------
# Remove existing Custom Script Extension (only one allowed per VM)
# ---------------------------------------------------------------------------
Write-Host "Removing existing Custom Script Extension (if any) …"
az vm extension delete `
    --resource-group $ResourceGroup `
    --vm-name $VMName `
    --name CustomScriptExtension `
    --no-wait 2>$null

# Wait a moment for cleanup
Start-Sleep -Seconds 5

# ---------------------------------------------------------------------------
# Deploy Custom Script Extension
# ---------------------------------------------------------------------------
Write-Host "Applying Custom Script Extension …"

$settings = @{
    fileUris = @($ScriptUrl)
    commandToExecute = $innerCmd
} | ConvertTo-Json -Compress

az vm extension set `
    --resource-group $ResourceGroup `
    --vm-name $VMName `
    --name CustomScriptExtension `
    --publisher Microsoft.Compute `
    --version 1.10 `
    --settings $settings

Write-Host ""
Write-Host "Extension deployed. The VM is now building and starting the web server."
Write-Host "This may take 10-15 minutes for the initial build (includes VS Build Tools)."
Write-Host ""
Write-Host "Check status:"
Write-Host "  az vm extension show -g $ResourceGroup --vm-name $VMName --name CustomScriptExtension"
Write-Host ""
if ($Domain) {
    Write-Host "Once ready:  https://${Domain}:${Port}"
} else {
    Write-Host "Once ready:  https://<vm-public-ip>:${Port}"
}
