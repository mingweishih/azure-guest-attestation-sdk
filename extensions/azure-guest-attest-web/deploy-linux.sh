#!/usr/bin/env bash
# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
#
# Deploy the Azure Guest Attestation Web UI extension to a Linux VM
# using the Azure Custom Script Extension.
#
# Prerequisites:
#   - Azure CLI (az) logged in
#   - The target VM must be running
#
# Usage:
#   ./deploy-linux.sh --resource-group myRG --vm-name myVM
#   ./deploy-linux.sh --resource-group myRG --vm-name myVM \
#       --domain myvm.eastus.cloudapp.azure.com \
#       --commit v1.0 --port 8443

set -euo pipefail

# ---------------------------------------------------------------------------
# Defaults
# ---------------------------------------------------------------------------
RESOURCE_GROUP=""
VM_NAME=""
COMMIT="main"
DOMAIN=""
PORT="443"
BIND="0.0.0.0"
REPO_URL="https://github.com/Azure/azure-guest-attestation-sdk.git"

# The install script location — uploaded to a publicly accessible URL or
# stored in a storage account.  For simplicity, we use the raw GitHub URL.
# Replace with your fork / branch as needed.
SCRIPT_URL="https://raw.githubusercontent.com/Azure/azure-guest-attestation-sdk/main/extensions/azure-guest-attest-web/linux/install.sh"

# ---------------------------------------------------------------------------
# Parse arguments
# ---------------------------------------------------------------------------
while [[ $# -gt 0 ]]; do
    case "$1" in
        --resource-group|-g)  RESOURCE_GROUP="$2"; shift 2 ;;
        --vm-name|-n)         VM_NAME="$2";        shift 2 ;;
        --commit|-c)          COMMIT="$2";         shift 2 ;;
        --domain|-d)          DOMAIN="$2";         shift 2 ;;
        --port|-p)            PORT="$2";           shift 2 ;;
        --bind|-b)            BIND="$2";           shift 2 ;;
        --repo-url)           REPO_URL="$2";       shift 2 ;;
        --script-url)         SCRIPT_URL="$2";     shift 2 ;;
        --help|-h)
            echo "Usage: $0 --resource-group RG --vm-name VM [options]"
            echo ""
            echo "Options:"
            echo "  --resource-group, -g   Azure resource group (required)"
            echo "  --vm-name, -n          VM name (required)"
            echo "  --commit, -c           Git ref to checkout (default: main)"
            echo "  --domain, -d           Domain name for TLS SAN"
            echo "  --port, -p             HTTPS port (default: 443)"
            echo "  --bind, -b             Bind address (default: 0.0.0.0)"
            echo "  --repo-url             Repository URL to clone"
            echo "  --script-url           URL of install.sh (for custom hosting)"
            exit 0
            ;;
        *) echo "Unknown option: $1"; exit 1 ;;
    esac
done

if [[ -z "$RESOURCE_GROUP" || -z "$VM_NAME" ]]; then
    echo "Error: --resource-group and --vm-name are required"
    echo "Run with --help for usage"
    exit 1
fi

# ---------------------------------------------------------------------------
# Build settings JSON
# ---------------------------------------------------------------------------
SETTINGS=$(cat <<EOF
{
    "commit": "$COMMIT",
    "domain": "$DOMAIN",
    "port": "$PORT",
    "bind": "$BIND",
    "repoUrl": "$REPO_URL"
}
EOF
)

echo "Deploying Azure Guest Attestation Web UI extension …"
echo "  Resource Group: $RESOURCE_GROUP"
echo "  VM Name:        $VM_NAME"
echo "  Settings:       $SETTINGS"
echo ""

# ---------------------------------------------------------------------------
# Deploy via Custom Script Extension
# ---------------------------------------------------------------------------
# Remove existing extension if present (CSE allows only one instance)
az vm extension delete \
    --resource-group "$RESOURCE_GROUP" \
    --vm-name "$VM_NAME" \
    --name customScript \
    --no-wait \
    2>/dev/null || true

echo "Applying Custom Script Extension …"
az vm extension set \
    --resource-group "$RESOURCE_GROUP" \
    --vm-name "$VM_NAME" \
    --name customScript \
    --publisher Microsoft.Azure.Extensions \
    --version 2.1 \
    --settings "{
        \"fileUris\": [\"$SCRIPT_URL\"],
        \"commandToExecute\": \"bash install.sh /var/lib/waagent/custom-script/download/0/settings.json\"
    }" \
    --protected-settings "{
        \"commandToExecute\": \"echo '$SETTINGS' > /tmp/attest-web-settings.json && bash install.sh /tmp/attest-web-settings.json\"
    }"

echo ""
echo "Extension deployed. The VM is now building and starting the web server."
echo "This may take 5–10 minutes for the initial build."
echo ""
echo "Check status:"
echo "  az vm extension show -g $RESOURCE_GROUP --vm-name $VM_NAME --name customScript"
echo ""
if [[ -n "$DOMAIN" ]]; then
    echo "Once ready:  https://$DOMAIN:$PORT"
else
    echo "Once ready:  https://<vm-public-ip>:$PORT"
fi
