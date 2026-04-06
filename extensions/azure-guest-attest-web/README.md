# Azure Guest Attestation Web UI — VM Extension

Deploy the **Azure Guest Attestation Web UI** to an Azure VM with a single
command.  The extension uses Azure's Custom Script Extension to:

1. **First boot** — clone the repository, install Rust + build tools, build
   the web server in release mode, generate a persistent self-signed TLS
   certificate, and start the HTTPS server.
2. **Subsequent boots** — start the web server with the previously generated
   certificate (regenerates only if certs are missing).

Works on both **Linux** and **Windows** VMs.

---

## Quick Start

### Linux VM

```bash
./deploy-linux.sh \
    --resource-group myResourceGroup \
    --vm-name myLinuxVM \
    --domain myvm.eastus.cloudapp.azure.com
```

### Windows VM

```powershell
.\deploy-windows.ps1 `
    -ResourceGroup myResourceGroup `
    -VMName myWindowsVM `
    -Domain "myvm.eastus.cloudapp.azure.com"
```

---

## Configuration

All parameters are optional.  Defaults produce a working HTTPS server on
port 443 using the latest `main` branch.

| Parameter | Default | Description |
|-----------|---------|-------------|
| `commit`  | `main`  | Git ref (branch, tag, or SHA) to checkout |
| `domain`  | *(none)* | Domain name added as TLS SAN (e.g. `myvm.eastus.cloudapp.azure.com`) |
| `port`    | `443`   | HTTPS listen port |
| `bind`    | `0.0.0.0` | Bind address |
| `repoUrl` | GitHub repo URL | Git clone URL (use your fork if needed) |

### Deployment script options

The `deploy-*.sh` / `deploy-*.ps1` scripts accept these as CLI flags:

```bash
# Linux
./deploy-linux.sh \
    -g myRG -n myVM \
    --commit v1.0 \
    --domain myvm.eastus.cloudapp.azure.com \
    --port 8443

# Windows
.\deploy-windows.ps1 \
    -ResourceGroup myRG -VMName myVM \
    -Commit "v1.0" \
    -Domain "myvm.eastus.cloudapp.azure.com" \
    -Port 8443
```

---

## What Gets Installed

### Linux

| Item | Path |
|------|------|
| Repository clone | `/opt/azure-guest-attest-web/repo/` |
| Binary | `/usr/local/bin/azure-guest-attest-web` |
| TLS certificates | `/opt/azure-guest-attest-web/certs/` |
| Systemd service | `azure-guest-attest-web.service` |
| Install log | `/var/log/azure-guest-attest-web-install.log` |

The systemd service runs as root (required for TPM access via
`/dev/tpmrm0`), starts on boot, and auto-restarts on failure.

**Manage the service:**

```bash
sudo systemctl status azure-guest-attest-web
sudo systemctl restart azure-guest-attest-web
sudo journalctl -u azure-guest-attest-web -f
```

### Windows

| Item | Path |
|------|------|
| Repository clone | `C:\azure-guest-attest-web\repo\` |
| Binary | `C:\azure-guest-attest-web\azure-guest-attest-web.exe` |
| TLS certificates | `C:\azure-guest-attest-web\certs\` |
| Scheduled task | `AzureGuestAttestWeb` |
| Install log | `C:\azure-guest-attest-web\install.log` |

The scheduled task runs as SYSTEM at startup. A Windows Firewall rule is
automatically created for the configured port.

**Manage the service:**

```powershell
Get-ScheduledTask -TaskName AzureGuestAttestWeb
Start-ScheduledTask -TaskName AzureGuestAttestWeb
Stop-ScheduledTask -TaskName AzureGuestAttestWeb
```

---

## How It Works

### Architecture

```
┌─────────────────────────────────────────────────────┐
│  az vm extension set (Custom Script Extension)      │
│    → downloads install.sh / install.ps1             │
│    → runs on the VM as root / SYSTEM                │
├─────────────────────────────────────────────────────┤
│  install.sh / install.ps1                           │
│    1. Install prerequisites (git, Rust, build tools)│
│    2. Clone repo at configured commit               │
│    3. cargo build -p azure-guest-attest-web --release│
│    4. Register systemd service / scheduled task     │
│    5. Service starts web server with --tls-self-    │
│       signed-dir (persistent certs)                 │
├─────────────────────────────────────────────────────┤
│  azure-guest-attest-web binary                      │
│    - Loads certs from disk (or generates if missing) │
│    - Binds to configured address:port               │
│    - Serves Web UI + REST API over HTTPS            │
│    - Accesses TPM for attestation operations        │
└─────────────────────────────────────────────────────┘
```

### Boot Behaviour

```
First boot:
  Extension → install script → build → generate certs → start service

Subsequent boots:
  Systemd / Scheduled Task → start binary → load existing certs → serve
```

The web server uses `--tls-self-signed-dir` which:
- **Checks** if `cert.pem` + `key.pem` exist in the cert directory
- **Loads** them if found (no regeneration)
- **Generates** new self-signed certs only if they're missing

---

## NSG / Firewall

Make sure the VM's **Network Security Group** allows inbound TCP traffic on
the configured port (443 by default):

```bash
az network nsg rule create \
    --resource-group myRG \
    --nsg-name myNSG \
    --name AllowAttestWebHTTPS \
    --priority 1010 \
    --direction Inbound \
    --access Allow \
    --protocol Tcp \
    --destination-port-ranges 443
```

On Windows, the install script automatically creates a Windows Firewall
inbound rule.  On Linux, `iptables` / `firewalld` rules may be needed
depending on the distribution.

---

## Checking Extension Status

```bash
# Linux
az vm extension show \
    -g myResourceGroup --vm-name myVM \
    --name customScript \
    --query "{status: provisioningState, message: instanceView.statuses[0].message}"

# Windows
az vm extension show \
    -g myResourceGroup --vm-name myVM \
    --name CustomScriptExtension \
    --query "{status: provisioningState, message: instanceView.statuses[0].message}"
```

---

## Uninstalling

### Linux

```bash
sudo systemctl stop azure-guest-attest-web
sudo systemctl disable azure-guest-attest-web
sudo rm /etc/systemd/system/azure-guest-attest-web.service
sudo systemctl daemon-reload
sudo rm -rf /opt/azure-guest-attest-web
sudo rm /usr/local/bin/azure-guest-attest-web
```

### Windows (Admin PowerShell)

```powershell
Stop-ScheduledTask -TaskName AzureGuestAttestWeb
Unregister-ScheduledTask -TaskName AzureGuestAttestWeb -Confirm:$false
Remove-Item -Recurse -Force C:\azure-guest-attest-web
Remove-NetFirewallRule -DisplayName "AzureGuestAttestWeb-HTTPS-443"
```

---

## Troubleshooting

| Issue | Solution |
|-------|----------|
| Build fails (out of memory) | Use a VM size with ≥ 4 GB RAM |
| Build takes very long | First build compiles all dependencies; subsequent builds are incremental |
| "Permission denied" on TPM | Linux: service must run as root; Windows: task runs as SYSTEM |
| Port already in use | Change `--port` to a different value |
| Certs expired | Delete the cert files from the cert directory and restart the service |
| Extension timeout | Default CSE timeout is 90 min; build usually completes in 5–15 min |

---

## Files

```
extensions/azure-guest-attest-web/
├── README.md               # This file
├── deploy-linux.sh          # az-cli deployment script for Linux VMs
├── deploy-windows.ps1       # az-cli deployment script for Windows VMs
├── linux/
│   └── install.sh           # VM-side install script (Linux)
└── windows/
    └── install.ps1          # VM-side install script (Windows)
```
