# Week 1 — Network Discovery & Environment Setup

> **Project Phase** : Week 1 of 4 — Vulnerability Assessment Program

> **Objective**     : Full network discovery, asset inventory, and tooling setup

> **Status**        : ✅ Complete — Gate Check Passed

---

## 📋 Table of Contents

- [Overview](#overview)


---

## Overview

Week 1 focused on establishing the vulnerability assessment infrastructureand performing comprehensive network reconnaissance. The primary goal wasto discover **100% of live assets** on the internal subnet, fingerprint their operating systems, enumerate all open ports and running services,and compile a structured inventory for use throughout the remaining assessment phases.

Two core tools were deployed:

| Tool | Purpose |
|------|---------|
| **Nmap 7.94+** | Active network scanning, host discovery, OS/service detection |
| **GVM (Greenbone/OpenVAS)** | Vulnerability scanning platform (setup for Week 2+) |

---

## Objectives

```
[✓] Install and configure Nmap on the assessment workstation
[✓] Install and configure GVM (Greenbone Vulnerability Manager / OpenVAS)
[✓] Perform a ping sweep to identify all live hosts on the target subnet
[✓] Execute an aggressive Nmap scan (-A -p-) against all discovered hosts
[✓] Extract OS fingerprints, open ports, services, and versions
[✓] Generate a structured CSV asset inventory
[✓] Obtain sign-off on the final asset inventory (Gate Check)
```

## Installation

Kindly read [INSTALL.md](https://github.com/Dhruv3215/VulnVision-360/blob/main/Progress/Week-1/INSTALL.md) for see installation process.

## Nmap Scans 

Kindly read [Nmap.md](https://github.com/Dhruv3215/VulnVision-360/blob/main/Progress/Week-1/Nmap/README.md) for see nmap commad execution.
