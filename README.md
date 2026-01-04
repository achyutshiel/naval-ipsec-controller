# ⚓ Naval IPsec ESP/AH Security Controller
 Defence-grade secure communication controller for maritime and naval networks

---

## 📌 Project Overview

Secure communication is mission-critical in naval networks.  
This project implements a **system-level IPsec ESP supervisor** that:

✔ Initiates and maintains encrypted tunnels  
✔ Monitors health and detects failures  
✔ Automatically recovers on faults  
✔ Logs security events for audit and analysis  

It is designed for **real operational deployment** — not just a prototype.

---

## 📁 Repository Structure

```text
naval-ipsec/
│
├── build/                             # Compiled controller binary
│   └── esp_ah_controller
│
├── engine/                            # Core controller source
│   └── esp_ah_controller.c
│
├── config/                            # IPsec example configs
│   ├── ipsec.conf.example
│   └── ipsec.secrets.example
│
├── scripts/                           # Setup and demo scripts
│   ├── build_deploy.sh
│   ├── start_demo.sh
│   ├── stop_demo.sh
│   └── health_check.sh
│
├── service/
│   └── naval-ipsec.service            # systemd service
│
├── logs/
│   └── naval-ipsec.log
│
├── docs/                              # Documentation
│   ├── architecture.md
│   ├── threat_model.md
│   ├── demo_flow.md
│   └── limitations.md
│
├── Windows/                           # Windows peer setup
│   ├── ipsec_setup.ps1
│   └── README_windows.md
│
└── README.md                          # This file
```
## 🐧 Linux Setup (Controller Node)
⚙️ Requirements

  i.Linux (Kali/Ubuntu)

  ii.Root privileges
## ⚙️ Installation

### 1. Clone the Repository
```bash
https://github.com/achyutshiel/naval-ipsec-controller/
cd naval-ipsec-controller
```
### 2.Build & Install Dependencies
```bash
cd Scripts
sudo ./build_deploy.sh
```
#### This script:

i.Installs IPsec and monitoring tools

ii.Compiles the controller

iii.Sets permissions

### 3. Configure IPsec
Edit:
```bash
sudo nano /etc/ipsec.conf
```
Populate with:
```bash
conn naval-esp
    keyexchange=ikev2
    authby=psk
    left=YOUR_LINUX_IP
    right=REMOTE_IP
    ike=aes256-sha256-modp2048
    esp=aes256-sha256
    auto=add
```
Set secrets
```bsh
sudo nano /etc/ipsec.secrets
```
```bash
YOUR_LINUX_IP REMOTE_IP : PSK "navalstrongpassword123"
```
Secure the file:
```bash
sudo chmod 600 /etc/ipsec.secrets
```
### 4. RUn the Controller
```bash
sudo ./build/esp_ah_controller
```
Live status will be shown:

i.Tinnel state

ii. Failures and restart

iii. Intrusion indicators

iv. Last success time

###  Windows Setup (Peer Node)

Windows acts as a native IPsec peer:

1. Open Powershell as Administrator
2. Edit and run:
```bash
cd Windows
.\ipsec_setup.ps1
```
3. Verify:
```bash
Get-NetIPsecMainModeSA
```
### 📊 Verification

On Linux:

```bash
sudo ipsec statusall
sudo tcpdump -i any esp
```

logs:

```bash
tail -f /var/log/naval-ipsec.log
```

### 📜 Demo Flow
As an evaluator:

i. Start the controller

ii. Initiate the ESP tunnel

iii. Show recovery by stopping IPsec

iv. Show logs in naval-ipsec.log

v. Validate ESP packets via tcpdump

### 🧭 Why This Matters

This controller:

i. Integrates with real IPsec stacks

ii. Handles operational failures

iii. Suits mixed Linux/Windows nodes

iv. Matches real defence deployment expectations

### 🛡️ Licence & Disclaimer

This project is an independent submission for the Naval Hackathon. It is not affiliated with any government entity.

