
## Week 2 — Vulnerability Assessment

### Objective
Conduct unauthenticated and authenticated vulnerability scans. Compare results to show the internal vs. external risk gap. Identify at least one Critical CVE (CVSS 9.0+).

### Method

**Tool:** GVM/OpenVAS (web UI)

**Step 1 — Unauthenticated Scan**  
No credentials supplied. Simulates an external attacker who has gained network access but cannot log in to the target.

**Step 2 — Authenticated Scan**  
Configure SSH/SMB credentials in GVM. Scanner logs into target and checks local software versions, service configs, and internal settings invisible at the network layer.
```
Task: INFOTACT AUTHORIZED SCAN
Date: Mon Mar 2 16:24:48 – 16:58:19 UTC 2026
Target: 192.168.91.136
Auth: SMB Success (Port 445) | SSH Login Failure (Port 22, user: sysadmin)
```

## Kindly show this video for step-by-step process for authorized and unauthorized scanning.
[![Click on image](example.png)](https://drive.google.com/file/d/13oiRit1PjAVD0P6R230T7MjyFA1VsnVy/view?usp=drive_link)


### Results — Before Remediation

| Severity | Count | Key Finding |
|----------|-------|-------------|
| **High** | 2 | SNMP Default Community Strings (CVSS 7.6), FTP Default Creds `admin:admin` (CVSS 7.5) |
| **Medium** | 7 | Telnet cleartext, FTP cleartext, HTTP TRACE, Weak SSH ciphers, Deprecated TLS 1.0/1.1, phpinfo() exposed, SSL Renegotiation DoS |
| **Low** | 3 | TCP Timestamps, Weak SSH MAC (hmac-md5), ICMP Timestamp disclosure |
| **Total** | **12** | (Before filtering: 227 results) |

**Top Risk Findings:**
1. **SNMP Default Community Strings** (`public`/`private`) — CVSS 7.6 — Write access grants remote administrative control
2. **FTP Default Credentials** (`admin:admin`) — CVSS 7.5 — Full FTP access with zero effort

## Evidence Files

| File | Description |
|------|-------------|
| [AUTHORIZED_SCAN.pdf](REPORTS/AUTHORIZED_SCAN.pdf) | Contains Authorized scan report in pdf format |
| [UNAUTHORIZED_SCAN.pdf](REPORTS/UNAUTHORIZED_SCAN.pdf) | Contains Unauthorized scan report in pdf format |
| [AUTHORIZED_SCAN.txt](REPORTS/AUTHORIZED_SCAN.txt) | Contains Authorized scan report in txt format |
| [UNAUTHORIZED_SCAN.txt](REPORTS/UNAUTHORIZED_SCAN.txt) | Contains Unauthorized scan report in txt format |
| [AUTHORIZED_SCAN.csv](REPORTS/AUTHORIZED_SCAN.csv) | Contains Authorized scan report in csv format  |
| [UNAUTHORIZED_SCAN.csv](REPORTS/UNAUTHORIZED_SCAN.csv) | Contains Unauthorized scan report in csv format |

## Gate Check Status

| Requirement | Status |
|-------------|--------|
| Unauthenticated scan | ✅ Complete |
| Authenticated scan | ✅ Partially Complete |
| Found High level vulnerability | ✅ Complete |
| Make html report  | ✅ Complete |
| Comparison between auth and unauth scan | ✅ Partially Complete |

---
