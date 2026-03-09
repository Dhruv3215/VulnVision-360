
# Week 1 — INSTALLATION OF NMAP AND OPENVAS - PERFORM AGGRESSIVE SCAN 
```
Lab environment :-
Target: Ubuntu 18.04 LTS
Tool: Nmap
Scan Date: March 2, 2026
IP: 192.168.91.136
```
---

## What Was Done

### Installed `OPENVAS` and `NMAP` packages on the kali machine.

1. INSTALL BOTH PACKAGES
   > sudo apt install openvas nmap xsltproc

2. SETTING UP THE OPENVAS
    > sudo gvm-setup

3. CHECKING SETUP IS DONE OR NOT
    > sudo gvm-check-setup


#### NOTE:- During this you may encounter an error called collation version mismatch 
```
Solution :- 
          Step 1: Update PostgreSQL Template Database Collations
                      sudo -u postgres psql << EOF
                      ALTER DATABASE template0 REFRESH COLLATION VERSION;
                      ALTER DATABASE template1 REFRESH COLLATION VERSION;
                      ALTER DATABASE postgres REFRESH COLLATION VERSION;
                      EOF
          Step 2: Reindex Template Databases
                      sudo -u postgres psql template1 -c "REINDEX DATABASE template1;"
                      sudo -u postgres psql postgres -c "REINDEX DATABASE postgres;"
          Step 3: Create GVM PostgreSQL Database
                      sudo runuser -u postgres -- /usr/share/gvm/create-postgresql-database
```
4. After executing this command again run step-2 and step-3

5. STARTING GVM SERVICES
   > sudo gvm-start

---

## Now we will perform aggressive scan 


1. First we will run ping sweep scan on our entire network to find target machine ip
   > nmap -sn 192.168.91.0/24 -oN live_hosts.txt

2. Now run aggressive scan on target ip 
    > nmap -A -p- -T3 --script vuln 192.168.91.136 -oN nmap_report.txt -oX nmap_report.xml

| Flag | Purpose |
|------|---------|
| `-A` | OS detection, version detection, script scanning, traceroute |
| `-p-` | Scan all 65,535 TCP ports |
| `-T3` | Timing template — controls scan speed (Normal) |
| `--script vuln` | Run Nmap NSE vulnerability detection scripts |
| `-oN` | Human-readable output |
| `-oX` | XML output (required for HTML conversion) |

3. Now convert xml into html report through online xml template
    > xsltproc -o nmap_report.html bootstrap.xsl nmap_report.xml

---

## Now i will introduce you with my automation script 

1. Download [nmap.sh](nmap.sh) and [bootstrap.xsl](bootstrap.xsl) file
2. Give my script executable permission
   > sudo chmod +x nmap.sh
3. Now run my script with sudo permission
   > sudo ./nmap.sh YOUR-NETWORK-IP-WITH-CIDR

Note :- You can use this script with file contains target ips or more.
  > sudo ./nmap.sh target.txt

### 📝 Input File  (targets.txt)
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

### 📁 What It Produces

```
Results saved in: "result/"
                        ├── live_hosts.txt          (discovered live IPs)"
                        ├── nmap_report.txt         (detailed text report)"
                        ├── nmap_report.xml         (XML for parsing/tools)"
                        └── nmap_report.html        (interactive HTML report)"
```

### Please refer detailed documentation for using my automation script here :- [CLICK HERE](README.md)


## Evidence Files

| File | Description |
|------|-------------|
| [live_hosts.txt](REPORTS/live_hosts_before.txt) | Contains live host ip in network range |
| [nmap_report.txt](REPORTS/nmap_report_before.txt) | Contain Nmap scan result in TEXT  |
| [nmap_report.html](REPORTS/nmap_report_before.html) | Contain Nmap scan result in HTML webpage  |
| [nmap_report.xml](REPORTS/nmap_report_before.xml) | Contain Nmap scan result in XML  |
| [nmap.sh](nmap.sh) | Automation script for nmap command  |
| [bootstrap.xsl](bootstrap.xsl) | Act as a template to convert xml into html page |



## Gate Check Status

| Requirement | Status |
|-------------|--------|
| Nmap and Openvas installation | ✅ Complete |
| Perform pingsweep scan on network range | ✅ Complete |
| Perform aggressive scan on target system | ✅ Complete |
| Make detailed html report on network inventory  | ✅ Complete |
| Create automation script | ✅ Complete |

---
