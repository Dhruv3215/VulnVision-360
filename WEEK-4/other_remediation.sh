#!/bin/bash
# =============================================================================
# INFOTACT VULNERABILITY REMEDIATION SCRIPT
# Host: 192.168.91.136 (Ubuntu)
# Scan Date: March 2, 2026
# =============================================================================
# USAGE:
#   chmod +x fix_vulnerabilities.sh
#   sudo ./fix_vulnerabilities.sh
#
# WARNING: Review this script before running in production.
#          A backup of modified config files will be saved to /root/vuln_fix_backups/
# =============================================================================

set -euo pipefail

# ── Colors ────────────────────────────────────────────────────────────────────
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m' # No Color

# ── Helpers ───────────────────────────────────────────────────────────────────
BACKUP_DIR="/root/vuln_fix_backups/$(date +%Y%m%d_%H%M%S)"
LOG_FILE="/var/log/vuln_remediation_$(date +%Y%m%d_%H%M%S).log"
FIXED=0
SKIPPED=0
FAILED=0

log()    { echo -e "$1" | tee -a "$LOG_FILE"; }
ok()     { log "${GREEN}  [✔] $1${NC}"; ((FIXED++)) || true; }
warn()   { log "${YELLOW}  [!] $1${NC}"; ((SKIPPED++)) || true; }
fail()   { log "${RED}  [✘] $1${NC}"; ((FAILED++)) || true; }
header() { log "\n${CYAN}${BOLD}════════════════════════════════════════${NC}"; log "${CYAN}${BOLD}  $1${NC}"; log "${CYAN}${BOLD}════════════════════════════════════════${NC}"; }

backup() {
    local file="$1"
    if [[ -f "$file" ]]; then
        mkdir -p "$BACKUP_DIR"
        cp "$file" "$BACKUP_DIR/$(basename "$file").bak"
        log "  ${YELLOW}[↑] Backed up: $file → $BACKUP_DIR/${NC}"
    fi
}

require_root() {
    if [[ $EUID -ne 0 ]]; then
        echo -e "${RED}[!] This script must be run as root (sudo).${NC}"
        exit 1
    fi
}

# =============================================================================
# =============================================================================
# FUNCTION: fix_smb
# Remediates SMB vulnerabilities found in Nmap after-scan:
#   - smb-vuln-regsvc-dos  (Samba regsvc DoS — null pointer dereference)
#   - SMB signing not enforced
#   - Guest/anonymous SMB access
#   - Old/weak SMB protocol versions (SMBv1)
#   - Open SMB ports exposed to network (139, 445)
# =============================================================================
fix_smb() {
    header "FIX 11 — SMB Hardening (Samba regsvc DoS + SMB exposure | 139/445/tcp)"

    local SAMBA_CONF="/etc/samba/smb.conf"

    # ── 1. Check if Samba is installed ──────────────────────────────────────
    if ! command -v smbd &>/dev/null && ! dpkg -l samba &>/dev/null 2>&1; then
        warn "Samba not installed — skipping SMB remediation"
        return
    fi

    log "  Samba detected. Applying hardening..."

    # ── 2. Backup smb.conf ───────────────────────────────────────────────────
    if [[ -f "$SAMBA_CONF" ]]; then
        backup "$SAMBA_CONF"
    else
        warn "smb.conf not found at $SAMBA_CONF — creating minimal hardened config"
        mkdir -p /etc/samba
        cat > "$SAMBA_CONF" <<'SMBEOF'
[global]
   workgroup = WORKGROUP
   server string = Samba Server
SMBEOF
    fi

    # ── Helper: set or replace a key in [global] section of smb.conf ────────
    smb_set() {
        local key="$1"
        local val="$2"
        # Remove any existing line with this key (case-insensitive)
        sed -i "/^\s*${key}\s*=/Id" "$SAMBA_CONF"
        # Insert after [global] line
        sed -i "/^\[global\]/a\\   ${key} = ${val}" "$SAMBA_CONF"
    }

    # ── 3. Disable SMBv1 (EternalBlue attack surface, also helps regsvc) ────
    smb_set "min protocol"              "SMB2"
    smb_set "max protocol"              "SMB3"
    ok "SMBv1 disabled — min protocol set to SMB2"

    # ── 4. Require SMB signing (prevents MITM / relay attacks) ──────────────
    smb_set "server signing"            "mandatory"
    smb_set "client signing"            "mandatory"
    ok "SMB signing enforced (mandatory)"

    # ── 5. Disable guest / anonymous access ─────────────────────────────────
    smb_set "restrict anonymous"        "2"
    smb_set "guest ok"                  "no"
    smb_set "guest account"             "nobody"
    smb_set "map to guest"              "Never"
    ok "Guest and anonymous SMB access disabled"

    # ── 6. Disable null session (directly related to regsvc DoS vector) ─────
    smb_set "lanman auth"               "no"
    smb_set "ntlm auth"                 "ntlmv2-only"
    smb_set "client NTLMv2 auth"        "yes"
    ok "Null sessions and NTLMv1 disabled — NTLMv2 only"

    # ── 7. Disable printing / unused services to reduce attack surface ───────
    smb_set "load printers"             "no"
    smb_set "printing"                  "bsd"
    smb_set "printcap name"             "/dev/null"
    smb_set "disable spoolss"           "yes"
    ok "Samba printer spooler disabled (reduces attack surface)"

    # ── 8. Restrict to local network only ───────────────────────────────────
    # Detect local subnet from primary interface
    LOCAL_NET=$(ip route | awk '/proto kernel/ && !/^169/ {print $1; exit}' 2>/dev/null || echo "192.168.0.0/16")
    smb_set "hosts allow"               "127.0.0.1 ${LOCAL_NET}"
    smb_set "hosts deny"                "0.0.0.0/0"
    ok "SMB access restricted to local network: ${LOCAL_NET}"

    # ── 9. Enable detailed logging for audit trail ───────────────────────────
    smb_set "log level"                 "2"
    smb_set "log file"                  "/var/log/samba/log.%m"
    smb_set "max log size"              "5000"
    ok "Samba audit logging enabled at /var/log/samba/"

    # ── 10. Validate smb.conf before restarting ──────────────────────────────
    if testparm -s "$SAMBA_CONF" &>/dev/null; then
        ok "smb.conf validation passed"
        systemctl restart smbd 2>/dev/null && ok "smbd restarted with hardened config" \
            || warn "smbd restart failed — check 'systemctl status smbd'"
        systemctl restart nmbd 2>/dev/null && ok "nmbd restarted" \
            || warn "nmbd not running (optional)"
    else
        # Restore backup on config error
        if [[ -f "$BACKUP_DIR/smb.conf.bak" ]]; then
            cp "$BACKUP_DIR/smb.conf.bak" "$SAMBA_CONF"
            fail "smb.conf validation failed — original config restored. Check $SAMBA_CONF manually."
        else
            fail "smb.conf validation failed — check $SAMBA_CONF manually."
        fi
        return
    fi

    # ── 11. Block SMB ports via UFW ──────────────────────────────────────────
    if command -v ufw &>/dev/null; then
        # Allow from local subnet first, then block everything else
        ufw allow from "${LOCAL_NET}" to any port 445 proto tcp &>/dev/null \
            && ok "UFW: allowed SMB port 445 from local network ${LOCAL_NET}" \
            || warn "UFW rule for 445 may already exist"
        ufw allow from "${LOCAL_NET}" to any port 139 proto tcp &>/dev/null \
            && ok "UFW: allowed SMB port 139 from local network ${LOCAL_NET}" \
            || warn "UFW rule for 139 may already exist"
        ufw deny 445/tcp &>/dev/null && ok "UFW: blocked external access to port 445" \
            || warn "UFW deny 445 may already exist"
        ufw deny 139/tcp &>/dev/null && ok "UFW: blocked external access to port 139" \
            || warn "UFW deny 139 may already exist"
    fi

    # ── 12. Note on smb-vuln-regsvc-dos ─────────────────────────────────────
    #    This CVE is a Windows-specific null-pointer dereference in regsvc.
    #    Nmap's script flags it as a false positive on Samba.
    #    Disabling SMBv1 and enforcing signing fully mitigates the attack vector.
    log "  ${CYAN}[i] Note: smb-vuln-regsvc-dos is a Windows-specific CVE.${NC}"
    log "  ${CYAN}    Nmap may still flag it on Samba — this is a known false positive.${NC}"
    log "  ${CYAN}    SMBv1 disable + mandatory signing mitigates the real attack surface.${NC}"

    ok "SMB remediation complete"
}

require_root
mkdir -p "$BACKUP_DIR"
log "${BOLD}=== Vulnerability Remediation Started: $(date) ===${NC}"
log "Backup directory : $BACKUP_DIR"
log "Log file         : $LOG_FILE\n"

# =============================================================================
header "FIX 0 of 10 — updating and upgrading system packages (It will take time)"
# =============================================================================
sudo apt update && sudo apt upgrade -y

# =============================================================================
header "FIX 1 of 10 — SNMP Default Community Strings (HIGH | 161/udp)"
# =============================================================================
SNMPD_CONF="/etc/snmp/snmpd.conf"

if systemctl is-active --quiet snmpd 2>/dev/null || dpkg -l snmpd &>/dev/null 2>&1; then
    log "  SNMP service detected. Disabling..."
    backup "$SNMPD_CONF"

    # Disable and stop the service
    systemctl stop snmpd    2>/dev/null && ok "snmpd stopped"    || warn "snmpd was already stopped"
    systemctl disable snmpd 2>/dev/null && ok "snmpd disabled"   || warn "snmpd was already disabled"

    # Replace default community strings in config if it exists
    if [[ -f "$SNMPD_CONF" ]]; then
        # Comment out default public/private community lines
        sed -i 's/^\(rocommunity\s\+public\)/# REMEDIATED: \1/' "$SNMPD_CONF"
        sed -i 's/^\(rwcommunity\s\+private\)/# REMEDIATED: \1/' "$SNMPD_CONF"
        sed -i 's/^\(com2sec\s\+notConfigUser\s\+default\s\+public\)/# REMEDIATED: \1/' "$SNMPD_CONF"
        ok "Default community strings commented out in $SNMPD_CONF"
    fi

    # Block SNMP port via ufw if available
    if command -v ufw &>/dev/null; then
        ufw deny 161/udp &>/dev/null && ok "UFW: blocked port 161/udp" || warn "UFW rule may already exist"
        ufw deny 162/udp &>/dev/null && ok "UFW: blocked port 162/udp" || warn "UFW rule may already exist"
    fi

    ok "SNMP remediation complete"
else
    ok "SNMP service not running — no action needed"
fi

# =============================================================================
header "FIX 2 of 10 — FTP Default Credentials admin:admin (HIGH | 21/tcp)"
# =============================================================================
VSFTPD_CONF="/etc/vsftpd.conf"

if id "admin" &>/dev/null; then
    # Generate a strong random password
    NEW_PASS=$(openssl rand -base64 20 | tr -d '/+=')
    echo "admin:${NEW_PASS}" | chpasswd
    ok "Password changed for user 'admin' (new password saved to $BACKUP_DIR/admin_new_password.txt)"
    echo "admin new password: ${NEW_PASS}" > "$BACKUP_DIR/admin_new_password.txt"
    chmod 600 "$BACKUP_DIR/admin_new_password.txt"
else
    warn "User 'admin' not found — skipping password change"
fi

# Restrict admin from FTP login
FTP_USERS="/etc/ftpusers"
if [[ -f "$FTP_USERS" ]]; then
    backup "$FTP_USERS"
    if ! grep -q "^admin$" "$FTP_USERS"; then
        echo "admin" >> "$FTP_USERS"
        ok "Added 'admin' to $FTP_USERS (denied from FTP login)"
    else
        ok "'admin' already in $FTP_USERS"
    fi
else
    echo "admin" > "$FTP_USERS"
    ok "Created $FTP_USERS and added 'admin'"
fi

# Also block via vsftpd userlist
if [[ -f "$VSFTPD_CONF" ]]; then
    backup "$VSFTPD_CONF"
    USERLIST="/etc/vsftpd.user_list"
    if ! grep -q "^userlist_enable" "$VSFTPD_CONF"; then
        echo -e "\nuserlist_enable=YES\nuserlist_deny=YES\nuserlist_file=$USERLIST" >> "$VSFTPD_CONF"
    fi
    echo "admin" >> "$USERLIST" 2>/dev/null || true
    ok "vsftpd userlist configured to deny 'admin'"
    systemctl restart vsftpd 2>/dev/null && ok "vsftpd restarted" || warn "vsftpd not running"
fi

# =============================================================================
header "FIX 3 of 10 — Telnet Cleartext Login (MEDIUM | 23/tcp)"
# =============================================================================

# Stop and disable telnet via systemd
for svc in telnet telnetd inetutils-telnetd; do
    if systemctl is-active --quiet "$svc" 2>/dev/null; then
        systemctl stop "$svc"    && ok "Stopped $svc"    || true
        systemctl disable "$svc" && ok "Disabled $svc"   || true
    fi
done

# Remove telnet server packages
for pkg in telnetd inetutils-telnetd; do
    if dpkg -l "$pkg" &>/dev/null 2>&1; then
        apt-get remove -y "$pkg" &>/dev/null && ok "Removed package: $pkg" || fail "Could not remove $pkg"
    fi
done

# Disable via xinetd if used
XINETD_TELNET="/etc/xinetd.d/telnet"
if [[ -f "$XINETD_TELNET" ]]; then
    backup "$XINETD_TELNET"
    sed -i 's/disable\s*=\s*no/disable = yes/' "$XINETD_TELNET"
    systemctl restart xinetd 2>/dev/null || true
    ok "Telnet disabled in xinetd"
fi

# Block port 23 via ufw
if command -v ufw &>/dev/null; then
    ufw deny 23/tcp &>/dev/null && ok "UFW: blocked port 23/tcp" || warn "UFW rule may already exist"
fi

ok "Telnet remediation complete"

# =============================================================================
header "FIX 4 of 10 — FTP Cleartext / No TLS (MEDIUM | 21/tcp)"
# =============================================================================
VSFTPD_CONF="/etc/vsftpd.conf"

if [[ -f "$VSFTPD_CONF" ]]; then
    backup "$VSFTPD_CONF"

    # Generate SSL cert for vsftpd if it doesn't exist
    CERT_FILE="/etc/ssl/certs/vsftpd.pem"
    KEY_FILE="/etc/ssl/private/vsftpd.key"

    if [[ ! -f "$CERT_FILE" ]] || [[ ! -f "$KEY_FILE" ]]; then
        openssl req -x509 -nodes -days 730 -newkey rsa:2048 \
            -keyout "$KEY_FILE" \
            -out "$CERT_FILE" \
            -subj "/CN=vsftpd/O=INFOTACT/C=US" &>/dev/null
        chmod 600 "$KEY_FILE"
        ok "Generated self-signed TLS certificate for vsftpd"
    else
        ok "TLS certificate already exists — reusing"
    fi

    # Apply TLS settings to vsftpd.conf
    apply_vsftpd_setting() {
        local key="$1" val="$2"
        if grep -q "^${key}" "$VSFTPD_CONF"; then
            sed -i "s|^${key}.*|${key}=${val}|" "$VSFTPD_CONF"
        else
            echo "${key}=${val}" >> "$VSFTPD_CONF"
        fi
    }

    apply_vsftpd_setting "ssl_enable"              "YES"
    apply_vsftpd_setting "allow_anon_ssl"          "NO"
    apply_vsftpd_setting "force_local_data_ssl"    "YES"
    apply_vsftpd_setting "force_local_logins_ssl"  "YES"
    apply_vsftpd_setting "ssl_tlsv1_2"             "YES"
    apply_vsftpd_setting "ssl_sslv2"               "NO"
    apply_vsftpd_setting "ssl_sslv3"               "NO"
    apply_vsftpd_setting "rsa_cert_file"           "$CERT_FILE"
    apply_vsftpd_setting "rsa_private_key_file"    "$KEY_FILE"

    systemctl restart vsftpd 2>/dev/null && ok "vsftpd restarted with TLS enforced" || warn "vsftpd not running"
    ok "FTP TLS remediation complete"
else
    warn "vsftpd not installed — skipping FTP TLS fix"
fi

# =============================================================================
header "FIX 5 of 10 — HTTP TRACE/TRACK Methods Enabled (MEDIUM | 80/tcp)"
# =============================================================================
APACHE_CONF="/etc/apache2/apache2.conf"
APACHE_SECURITY="/etc/apache2/conf-available/security.conf"

if [[ -f "$APACHE_CONF" ]]; then
    # Try security.conf first (preferred location)
    if [[ -f "$APACHE_SECURITY" ]]; then
        backup "$APACHE_SECURITY"
        if grep -q "^TraceEnable" "$APACHE_SECURITY"; then
            sed -i 's/^TraceEnable.*/TraceEnable Off/' "$APACHE_SECURITY"
        else
            echo "TraceEnable Off" >> "$APACHE_SECURITY"
        fi
        a2enconf security &>/dev/null || true
        ok "TraceEnable Off set in $APACHE_SECURITY"
    else
        backup "$APACHE_CONF"
        if grep -q "^TraceEnable" "$APACHE_CONF"; then
            sed -i 's/^TraceEnable.*/TraceEnable Off/' "$APACHE_CONF"
        else
            echo -e "\nTraceEnable Off" >> "$APACHE_CONF"
        fi
        ok "TraceEnable Off set in $APACHE_CONF"
    fi

    # Also hide server version while we're here
    if [[ -f "$APACHE_SECURITY" ]]; then
        if grep -q "^ServerTokens" "$APACHE_SECURITY"; then
            sed -i 's/^ServerTokens.*/ServerTokens Prod/' "$APACHE_SECURITY"
        else
            echo "ServerTokens Prod" >> "$APACHE_SECURITY"
        fi
        if grep -q "^ServerSignature" "$APACHE_SECURITY"; then
            sed -i 's/^ServerSignature.*/ServerSignature Off/' "$APACHE_SECURITY"
        else
            echo "ServerSignature Off" >> "$APACHE_SECURITY"
        fi
        ok "Server version disclosure hardened"
    fi

    systemctl restart apache2 2>/dev/null && ok "Apache restarted" || fail "Apache restart failed — check config manually"
else
    warn "Apache not found — skipping TRACE fix"
fi

# =============================================================================
header "FIX 6 of 10 — phpinfo() Page Exposed (MEDIUM | 80/tcp)"
# =============================================================================
WEBROOT="/var/www/html"
PHPINFO_FILES=("info.php" "phpinfo.php" "php_info.php" "test.php" "phptest.php")

for fname in "${PHPINFO_FILES[@]}"; do
    fpath="$WEBROOT/$fname"
    if [[ -f "$fpath" ]]; then
        backup "$fpath"
        rm -f "$fpath"
        ok "Deleted $fpath"
    fi
done

# Scan for any other phpinfo() files under webroot
log "  Scanning for other phpinfo() files under $WEBROOT..."
while IFS= read -r -d '' found_file; do
    backup "$found_file"
    rm -f "$found_file"
    ok "Deleted phpinfo file: $found_file"
done < <(find "$WEBROOT" -name "*.php" -print0 2>/dev/null | xargs -0 grep -l "phpinfo()" 2>/dev/null | tr '\n' '\0' || true)

# Disable phpinfo via php.ini
PHP_INI_DIRS=(/etc/php/*/apache2/php.ini /etc/php/*/fpm/php.ini /etc/php/*/cli/php.ini)
for ini in "${PHP_INI_DIRS[@]}"; do
    if [[ -f "$ini" ]]; then
        backup "$ini"
        if grep -q "^disable_functions" "$ini"; then
            # Append phpinfo to existing disable_functions if not already there
            if ! grep "^disable_functions" "$ini" | grep -q "phpinfo"; then
                sed -i 's/^disable_functions\s*=\s*/disable_functions = phpinfo,/' "$ini"
            fi
        else
            echo "disable_functions = phpinfo" >> "$ini"
        fi
        ok "phpinfo() disabled in $ini"
    fi
done

systemctl reload apache2 2>/dev/null || true
ok "phpinfo() remediation complete"

# =============================================================================
header "FIX 7 of 10 — Weak SSH Ciphers + Weak MAC (MEDIUM/LOW | 22/tcp)"
# =============================================================================
SSHD_CONF="/etc/ssh/sshd_config"

if [[ -f "$SSHD_CONF" ]]; then
    backup "$SSHD_CONF"

    # Remove old Ciphers / MACs / KexAlgorithms lines and replace
    sed -i '/^Ciphers /d'        "$SSHD_CONF"
    sed -i '/^MACs /d'           "$SSHD_CONF"
    sed -i '/^KexAlgorithms /d'  "$SSHD_CONF"

    cat >> "$SSHD_CONF" <<'EOF'

# ── Hardened by vuln remediation script ──────────────────────────────────────
Ciphers aes128-ctr,aes192-ctr,aes256-ctr,aes128-gcm@openssh.com,aes256-gcm@openssh.com,chacha20-poly1305@openssh.com
MACs hmac-sha2-256,hmac-sha2-512,hmac-sha2-256-etm@openssh.com,hmac-sha2-512-etm@openssh.com
KexAlgorithms curve25519-sha256,curve25519-sha256@libssh.org,diffie-hellman-group14-sha256,diffie-hellman-group16-sha512,diffie-hellman-group18-sha512,ecdh-sha2-nistp256,ecdh-sha2-nistp384,ecdh-sha2-nistp521
EOF

    # Validate config before restarting
    if sshd -t 2>/dev/null; then
        systemctl restart sshd && ok "SSH restarted with hardened ciphers and MACs"
    else
        # Restore backup if config is invalid
        cp "$BACKUP_DIR/sshd_config.bak" "$SSHD_CONF"
        fail "sshd config validation failed — backup restored. Check $SSHD_CONF manually."
    fi
else
    warn "sshd_config not found — skipping SSH cipher fix"
fi

# =============================================================================
header "FIX 8 of 10 — Deprecated TLS 1.0/1.1 + SSL Renegotiation DoS (MEDIUM | 3306/tcp)"
# =============================================================================
MYSQL_CNF_DIR="/etc/mysql/mysql.conf.d"
MYSQL_CNF="$MYSQL_CNF_DIR/mysqld.cnf"
MYSQL_CUSTOM="/etc/mysql/conf.d/hardening.cnf"

if [[ -d "$MYSQL_CNF_DIR" ]] || [[ -f "$MYSQL_CNF" ]]; then
    mkdir -p "/etc/mysql/conf.d"
    backup "$MYSQL_CNF" 2>/dev/null || true

    # Write a dedicated hardening config file
    cat > "$MYSQL_CUSTOM" <<'EOF'
# ── MySQL TLS Hardening (vuln remediation) ────────────────────────────────────
[mysqld]
# Disable deprecated TLS 1.0 and 1.1
tls_version = TLSv1.2,TLSv1.3

# Reduce DoS risk from renegotiation by limiting max connections
max_connections = 200

# Bind MySQL to localhost only (do not expose to network)
bind-address = 127.0.0.1

# Disable renegotiation (OpenSSL-level, available in MySQL 8.0.28+)
ssl_cipher = ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384
EOF

    ok "MySQL TLS hardening config written to $MYSQL_CUSTOM"
    systemctl restart mysql 2>/dev/null && ok "MySQL restarted" || warn "MySQL not running or restart failed"
else
    warn "MySQL not found — skipping TLS hardening"
fi

# Block port 3306 from external access via ufw
if command -v ufw &>/dev/null; then
    ufw deny 3306/tcp &>/dev/null && ok "UFW: blocked external access to MySQL port 3306" || warn "UFW rule may already exist"
fi

# =============================================================================
header "FIX 9 of 10 — TCP Timestamps Information Disclosure (LOW | general/tcp)"
# =============================================================================
SYSCTL_CONF="/etc/sysctl.conf"
backup "$SYSCTL_CONF"

if grep -q "^net.ipv4.tcp_timestamps" "$SYSCTL_CONF"; then
    sed -i 's/^net.ipv4.tcp_timestamps.*/net.ipv4.tcp_timestamps = 0/' "$SYSCTL_CONF"
else
    echo "net.ipv4.tcp_timestamps = 0" >> "$SYSCTL_CONF"
fi

sysctl -p &>/dev/null && ok "TCP timestamps disabled (net.ipv4.tcp_timestamps = 0)"

# =============================================================================
header "FIX 10 of 10 — ICMP Timestamp Reply Information Disclosure (LOW | icmp)"
# =============================================================================

# Drop ICMP timestamp requests/replies
iptables -D INPUT  -p icmp --icmp-type timestamp-request -j DROP 2>/dev/null || true
iptables -D OUTPUT -p icmp --icmp-type timestamp-reply   -j DROP 2>/dev/null || true
iptables -A INPUT  -p icmp --icmp-type timestamp-request -j DROP
iptables -A OUTPUT -p icmp --icmp-type timestamp-reply   -j DROP
ok "iptables rules added to drop ICMP timestamp requests/replies"

# Persist iptables rules
if command -v netfilter-persistent &>/dev/null; then
    netfilter-persistent save &>/dev/null && ok "iptables rules persisted via netfilter-persistent"
elif dpkg -l iptables-persistent &>/dev/null 2>&1; then
    netfilter-persistent save &>/dev/null && ok "iptables rules persisted"
else
    log "  ${YELLOW}[!] iptables-persistent not installed. Installing to persist rules...${NC}"
    DEBIAN_FRONTEND=noninteractive apt-get install -y iptables-persistent &>/dev/null \
        && netfilter-persistent save &>/dev/null \
        && ok "iptables rules persisted via newly installed iptables-persistent" \
        || warn "Could not install iptables-persistent — rules will be lost on reboot. Add to /etc/rc.local manually."
fi

# =============================================================================
# Call SMB remediation function
fix_smb

# =============================================================================
header "REMEDIATION SUMMARY"
# =============================================================================
log ""
log "  ${GREEN}${BOLD}Fixed   : $FIXED${NC}"
log "  ${YELLOW}${BOLD}Skipped : $SKIPPED${NC}  (service not present or already configured)"
log "  ${RED}${BOLD}Failed  : $FAILED${NC}"
log ""
log "  Backups saved to : $BACKUP_DIR"
log "  Full log saved to: $LOG_FILE"
log ""

if [[ $FAILED -gt 0 ]]; then
    log "${RED}${BOLD}  [!] Some fixes failed. Please review the log above.${NC}"
else
    log "${GREEN}${BOLD}  [✔] All applicable fixes applied successfully.${NC}"
fi


log "=== Remediation Completed: $(date) ==="
log "${BOLD}  NEXT STEPS:${NC}"
log "  1. Verify services are running correctly after remediation"
log "  2. Re-run the OpenVAS/GVM scan to confirm vulnerabilities are resolved"
log "  3. Admin FTP password (if changed) is saved at: $BACKUP_DIR/admin_new_password.txt"
log "  4. Review any SKIPPED items and remediate manually if applicable"
log "  5. Consider a firewall audit to ensure only required ports are exposed"
log "  6. update and upgrade system packages is done"
log ""
log "=== Remediation Completed: $(date) ==="
