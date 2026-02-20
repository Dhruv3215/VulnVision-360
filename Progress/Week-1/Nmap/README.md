# 🛡️ Nmap Automated Reconnaissance & Asset Report Generator

> A complete automated Nmap reconnaissance pipeline — from host discovery to vulnerability scanning — with a final consolidated CSV asset report.
> Note: In Week‑1, only Nmap-based reconnaissance and asset inventory are performed.

#### 📦See [INSTALLATION.MD](../INSTALL.md) for installing and set-up of GVM scanner and nmap.

---

## 📑 Table of Contents

- [Overview](#overview)
- [Phase 1 — Host Discovery (Live Hosts)](#phase-1--host-discovery-live-hosts)
- [Phase 2 — Port Scanning](#phase-2--port-scanning)
- [Phase 3 — OS Detection](#phase-3--os-detection)
- [Phase 4 — Service Version Enumeration](#phase-4--service-version-enumeration)
- [Phase 5 — Aggressive Scan](#phase-5--aggressive-scan)
- [Phase 6 — Vulnerability Script Scan](#phase-6--vulnerability-script-scan)
- [Phase 7 — Generate Consolidated CSV Report](#phase-7--generate-consolidated-csv-report)
- [All-In-One Automation Script](#all-in-one-automation-script)


---

## Overview

This project provides a **step-by-step Nmap workflow** for recon infrastructure:

1. 🔍 Discover **live hosts** from a target IP/subnet
2. 🔓 Perform **port scanning** on live hosts
3. 🖥️ Detect **operating systems**
4. 📦 Enumerate **service versions**
5. 💣 Run an **aggressive scan** (`-A`) 
6. 🐛 Execute **vulnerability scripts** (`--script vuln`)
7. 📊 Parse all results into a single **CSV asset report**

---

## Phase 1 — Host Discovery (Live Hosts)

Discover which hosts are alive on the network.

```
echo "YOUR-ACTUAL-TARGET-IP" >target.txt

# Option A: Single target / subnet
sudo nmap -sn 192.168.1.0/24 -oG - | grep "Up" | awk '{print $2}' > results/live_hosts.txt

# Option B: From a file containing multiple targets
sudo nmap -sn -iL targets.txt -oG - | grep "Up" | awk '{print $2}' > results/live_hosts.txt
```

### Explanation of Flags

| Flag  | Purpose |
|------ |---------|
| `-sn` | Ping scan only — no port scan |
| `-iL` | Input from a file |
| `-oG` | Grepable output format |

### Verify live hosts:

```
echo "[*] Total live hosts found: $(wc -l < results/live_hosts.txt)"
cat results/live_hosts.txt
```

---

## Phase 2 — Port Scanning 

Scan all **65535 ports** on discovered live hosts.

```
sudo nmap -sS -p- -T4 -iL results/live_hosts.txt -oN results/port_scan.txt -oX results/port_scan.xml
```

| Flag | Purpose |
|------|---------|
| `-sS` | TCP SYN (stealth) scan |
| `-p-` | Scan all 65535 ports |
| `-T4` | Aggressive timing (faster) |
| `-oN` | Normal text output |
| `-oX` | XML output (for parsing) |

---

## Phase 3 — OS Detection 

Detect the operating system of each live host.

```
sudo nmap -O --osscan-guess -iL results/live_hosts.txt -oN results/os_detection.txt -oX results/os_detection.xml
```

| Flag | Purpose |
|------|---------|
| `-O` | Enable OS detection |
| `--osscan-guess` | Guess OS more aggressively |

---

## Phase 4 — Service Version Enumeration 

Detect service names and versions on open ports.

```
sudo nmap -sV -iL results/live_hosts.txt -oN results/version_enum.txt -oX results/version_enum.xml
```

| Flag | Purpose |
|------|---------|
| `-sV` | Service/version detection |

---

## Phase 5 — Aggressive Scan

Combines OS detection, version detection, script scanning, and traceroute.

#### NOTE:- Phase 2,3,4 will be done by Phase 5 . Because aggressive scan covers os detection,version detection , traceroute and script execution . So final command we will use in project is :-

```
sudo nmap -A -T4 -p- -iL results/live_hosts.txt -oN results/aggressive_scan.txt -oX results/aggressive_scan.xml
```

| Flag | Purpose |
|------|---------|
| `-A` | Aggressive: `-O -sV -sC --traceroute` combined |
| `-T4` | Faster timing template |
| `-p-` | scan all 65535 ports |

---

## Phase 6 — Vulnerability Script Scan 

Run Nmap's vulnerability detection scripts against live hosts.

```
sudo nmap -sV --script vuln -iL results/live_hosts.txt -oN results/vuln_scan.txt -oX results/vuln_scan.xml
```

### Run additional specific vulnerability scripts (Optional):

```
# SMB vulnerabilities
sudo nmap --script smb-vuln* -iL results/live_hosts.txt -oN results/smb_vuln.txt

# SSL/TLS vulnerabilities
sudo nmap --script ssl* -p 443 -iL results/live_hosts.txt -oN results/ssl_vuln.txt

# HTTP vulnerabilities
sudo nmap --script http-vuln* -iL results/live_hosts.txt -oN results/http_vuln.txt

# Check SSH configuration
sudo nmap --script ssh2-enum-algos,ssh-auth-methods -p 22 192.168.100.20 192.168.100.30 -oN results/ssh_vuln.txt

# Check FTP vulnerabilities
sudo nmap --script ftp-anon,ftp-bounce,ftp-vuln* -p 21 192.168.100.20 -oN results/ftp_vuln.txt

```

---

## Phase 7 — Generate Consolidated CSV Report

Use the result file from nmap scan and make a single CSV file contain all assets,ports,os,version and more .

---

## All-In-One Automation Script

 Clone this repo for using script which will automate nmap command execution and csv file generation following by directory structure. 

### Make it executable:

```
chmod +x recon.sh
```

### Run it:

```
# Single subnet
sudo bash recon.sh 192.168.1.0/24

# From a targets file
sudo bash recon.sh targets.txt
``` 

---

### 📝 Input File Format (`targets.txt`)

```
# Single IPs
192.168.1.1
192.168.1.5
10.0.0.1

# CIDR ranges
192.168.1.0/24
10.0.0.0/16

# IP ranges
192.168.1.1-50

# Hostnames
server1.example.com
```
---

## Disclaimer

```
⚠️  LEGAL WARNING
═══════════════════════════════════════════════════════════════
This tool is intended for AUTHORIZED security testing ONLY.

Unauthorized scanning of networks you do not own or have explicit
written permission to test is ILLEGAL and may violate:

  • Computer Fraud and Abuse Act (CFAA) — United States
  • Computer Misuse Act — United Kingdom
  • IT Act 2000 — India
  • Similar laws in other jurisdictions

Always obtain proper written authorization before scanning.
The author is NOT responsible for any misuse of this tool.
═══════════════════════════════════════════════════════════════
```

---
