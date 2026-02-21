
# Week 2: Vulnerability Assessment

## Assignment Objectives
1. Run **Unauthenticated Scan** (external attacker view)
2. Run **Authenticated Scan** (internal security assessment)
3. Compare and contrast results
4. **Gate Check**: Identify at least one Critical CVE (CVSS 9.0+) with remediation steps

---

## ⚠️ Current Status

**Authenticated vs Unauthenticated comparison not yet available** - Lab environment setup is currently in progress. Once complete, both scan types will be provided.

**Alternative**: Full scan results from Ubuntu server (192.168.1.120) are provided below as demonstration.

---

## Scan Summary

**Target**: 192.168.1.120 (Ubuntu OS)  
**Tool**: OpenVAS  
**Date**: February 21, 2026  
**Duration**: 38 minutes (04:44:59 - 05:23:21 UTC)  
**Total Findings**: 22 (3 shown after filtering)

| Severity | Count |
|----------|-------|
| Critical | 0 |
| High | 0 |
| Medium | 0 |
| Low | 3 |

---

## Vulnerabilities Found

### 1. ICMP Timestamp Reply (CVSS 2.1)
**CVE**: CVE-1999-0524

**Issue**: Host responds to ICMP timestamp requests, revealing uptime information.

**Fix**:
```bash
# Option 1: Firewall block
iptables -A INPUT -p icmp --icmp-type timestamp-request -j DROP

# Option 2: Disable at host level (varies by OS)
```

---

### 2. Weak SSH MAC Algorithms (CVSS 2.6)
**Weak Algorithms**: umac-64-etm@openssh.com, umac-64@openssh.com

**Issue**: SSH server supports 64-bit MAC algorithms vulnerable to collision attacks.

**Fix**:
```bash
# Edit SSH config
sudo nano /etc/ssh/sshd_config

# Add strong MACs only
MACs hmac-sha2-256-etm@openssh.com,hmac-sha2-512-etm@openssh.com

# Restart SSH
sudo systemctl restart sshd
```

---

### 3. TCP Timestamps (CVSS 2.6)
**Issue**: TCP timestamps enabled, allowing uptime calculation.

**Fix**:
```bash
# Linux
echo "net.ipv4.tcp_timestamps = 0" >> /etc/sysctl.conf
sysctl -p

# Windows
netsh int tcp set global timestamps=disabled
```

---

## Gate Check Status

❌ **No Critical CVEs found** in current scan

**Reasons**:
- Well-patched Ubuntu system
- Limited external attack surface
- Unauthenticated scan has restricted visibility

**Next Steps**:
- Run authenticated scan for deeper inspection
- Expand target scope to include older systems
- Review all findings (not just filtered results)

---

## OpenVAS Configuration

**Credentials**:
- Name: ssh cred
- Type: Username + Password  
- User: root / Pass: toor
- Port: 22

**Target**: UBUNTU OS (192.168.1.120)  
**Task**: INFOTACT (authenticated scan ready)

---

## Authenticated vs Unauthenticated (Expected Differences)

### Unauthenticated Scan
- External attacker perspective
- Limited to network services
- Finds: Open ports, service versions, network vulnerabilities

### Authenticated Scan  
- Internal security assessment
- Full system access with credentials
- Finds: Missing patches, config issues, local vulnerabilities

**Why authenticated finds more**: Direct access to installed packages, patch levels, and system configurations.

---

## Next Steps

1. ✅ Complete lab environment setup
2. ⏳ Run authenticated scan with SSH credentials
3. ⏳ Compare authenticated vs unauthenticated results
4. ⏳ Identify Critical CVE for gate check
5. ⏳ Research exploit availability and remediation

---

**Status**: Lab setup in progress - Full comparison pending  
**Last Updated**: February 21, 2026
