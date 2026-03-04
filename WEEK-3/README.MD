
## Week 3 — Compliance Automation

### Objective
Evaluate the target server against the CIS Benchmark Level 1 profile using OpenSCAP. Generate structured HTML reports documenting every non-compliant configuration.

### Method

**Tool:** `oscap` (OpenSCAP)  
**Profile:** `xccdf_org.ssgproject.content_profile_cis` (CIS Level 1 Server)  

### Installation of oscap and ssg security guide 

```
# Download openscap 
sudo apt install -y libopenscap8 openscap-utils openscap-scanner

# Check download properly done 
oscap --version

# Download SSG from GitHub releases
cd /tmp

# Get latest release (check https://github.com/ComplianceAsCode/content/releases)
wget https://github.com/ComplianceAsCode/content/releases/download/v0.1.72/scap-security-guide-0.1.72.zip

# Extract
unzip scap-security-guide-0.1.72.zip
cd scap-security-guide-0.1.72

# Create the standard directory and copy needed content 
sudo mkdir -p /usr/share/xml/scap/ssg/content/

sudo cp scap-security-guide-0.1.72/*.xml /usr/share/xml/scap/ssg/content/

# Set permissions
sudo chmod 644 /usr/share/xml/scap/ssg/content/*

# Verify files are there
ls /usr/share/xml/scap/ssg/content/ | grep ubuntu

# For verify cis profile
oscap info /usr/share/xml/scap/ssg/content/ssg-ubuntu1804-ds.xml

# here you can see like xccdf_org.ssgproject.content_profile_cis this profile. 
```

**Step 1 — CIS Level 1 Scan**
```
sudo oscap xccdf eval \
  --profile xccdf_org.ssgproject.content_profile_cis \
  --results /home/ubuntu/Desktop/cis_results.xml \
  --report /home/ubuntu/Desktop/cis_report.html \
  /usr/share/xml/scap/ssg/content/ssg-ubuntu1804-ds.xml
```

| Flag | Purpose |
|------|---------|
| `xccdf eval` | Evaluate system against an XCCDF checklist |
| `--profile` | Select cis_server benchmark profile  |
| `--results` | Save XML results  |
| `--report` | Generate HTML report |

**Step 2 — Standard Profile Scan **
```
sudo oscap xccdf eval \
  --profile xccdf_org.ssgproject.content_profile_standard \
  --results /home/ubuntu/Desktop/standard_results.xml \
  --report /home/ubuntu/Desktop/standard_report.html \
  /usr/share/xml/scap/ssg/content/ssg-ubuntu1804-ds.xml
```

### Key Non-Compliant Findings (Before Remediation)

**Results: 53 rules evaluated — 31 FAILED / 22 PASSED**

### 1. SSH Permitting Empty Passwords — CIS 5.2.11 ❌
```
Current:  PermitEmptyPasswords yes
Required: PermitEmptyPasswords no
Risk:     Any account without a password can authenticate over SSH with no credentials
Fix:      sed -i 's/PermitEmptyPasswords yes/PermitEmptyPasswords no/' /etc/ssh/sshd_config
```

### 2. Weak Password Hash Exposure — CIS 6.1.4 ❌
```
Current:  /etc/shadow has incorrect permissions (readable beyond root)
Required: chmod 640 /etc/shadow, owned root:shadow
Risk:     Password hashes exposed — offline cracking attack possible
Fix:      chmod 640 /etc/shadow && chown root:shadow /etc/shadow
```

### 3. Other Notable SSH Failures
| Rule | CIS ID | Current | Required |
|------|--------|---------|----------|
| Disable SSH Root Login | 5.2.10 | PermitRootLogin yes | PermitRootLogin no |
| Limit Auth Attempts | 5.2.7 | MaxAuthTries 20 | MaxAuthTries 4 |
| Enable Warning Banner | 5.2.16 | No banner | Banner /etc/issue.net |
| Disable Host-Based Auth | 5.2.9 | Not configured | HostbasedAuthentication no |
| Session Timeout | 5.2.13 | Not set | ClientAliveInterval 300 |

## Evidence Files

| File | Description |
|------|-------------|
| [cis_report.html](REPORTS/cis_report_before.html) | OpenSCAP HTML compliance report  |
| [cis_results.xml](REPORTS/cis_results_before.xml) | Raw XCCDF scan results |
| [standard_report.html](REPORTS/standard_report.html) | Standard profile scan  |
| [standard_results.xml](REPORTS/standard_results.xml) | Raw XCCDF results — standard profile |

## Gate Check Status

| Requirement | Status |
|-------------|--------|
| oscap installed on test Linux server | ✅ Complete |
| Scanned against CIS Server Level 1 & standard profile | ✅ Complete |
| Generated structured HTML compliance report | ✅ Complete |
| Found critical ssh and other vulnerability  | ✅ Confirmed (CIS 5.2.11 FAIL) |
| Found ftp and other vulnerability | ✅ Confirmed (CIS 6.1.4 FAIL) |

---
