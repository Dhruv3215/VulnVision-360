#!/bin/bash

# ---- Strict Mode ----
set -euo pipefail

# ---- Colors ----
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

SECONDS=0

# ---- Banner ----
print_banner() {
    echo -e "${CYAN}"
    echo "╔══════════════════════════════════════════════════════════╗"
    echo "║        NMAP AUTOMATED RECON & ASSET REPORTER            ║"
    echo "║                     v2.0                                ║"
    echo "╚══════════════════════════════════════════════════════════╝"
    echo -e "${NC}"
}

# ---- Logging Helpers ----
log_info()    { echo -e "${GREEN}[✓]${NC} $1"; }
log_warn()    { echo -e "${YELLOW}[!]${NC} $1"; }
log_error()   { echo -e "${RED}[✘]${NC} $1"; }
log_phase()   { echo -e "\n${YELLOW}$1${NC}"; echo "================================================================"; }

# ---- Dependency Check ----
check_dependencies() {
    local missing=()
    for cmd in nmap xsltproc awk grep sed hostname; do
        if ! command -v "$cmd" &>/dev/null; then
            missing+=("$cmd")
        fi
    done

    if [[ ${#missing[@]} -gt 0 ]]; then
        log_error "Missing required dependencies: ${missing[*]}"
        echo ""
        echo "Install with:"
        echo "  sudo apt install nmap xsltproc    # Debian/Ubuntu"
        echo "  sudo yum install nmap xsltproc    # CentOS/RHEL"
        echo ""
        exit 1
    fi
}

# ---- Cleanup on Error ----
cleanup() {
    local exit_code=$?
    if [[ $exit_code -ne 0 ]]; then
        echo ""
        log_error "Script failed with exit code $exit_code"
        log_warn "Partial results may be in: $RESULTS_DIR/"
    fi
}
trap cleanup EXIT

# ---- Main ----
print_banner

# ---- Input Validation ----
if [[ -z "${1:-}" ]]; then
    log_error "Usage: sudo bash $0 <target_ip/subnet or target_file>"
    echo ""
    echo "  Examples:"
    echo "    sudo bash $0 192.168.1.0/24"
    echo "    sudo bash $0 10.0.0.1"
    echo "    sudo bash $0 targets.txt"
    echo ""
    exit 1
fi

# ---- Root Check ----
if [[ "$EUID" -ne 0 ]]; then
    log_error "Please run as root (sudo)"
    exit 1
fi

# ---- Dependency Check ----
check_dependencies

# ---- XSL Template Check ----
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
XSL_FILE="${SCRIPT_DIR}/bootstrap.xsl"

if [[ ! -f "$XSL_FILE" ]]; then
    log_error "XSL template not found: $XSL_FILE"
    log_warn "Place 'bootstrap.xsl' in the same directory as this script."
    echo ""
    echo "  You can get one from:"
    echo "    https://github.com/honze-net/nmap-bootstrap-xsl"
    echo ""
    exit 1
fi

# ---- Setup ----
TARGET="$1"
TIMESTAMP=$(date +"%Y%m%d_%H%M%S")
RESULTS_DIR="results"

mkdir -p "$RESULTS_DIR"

# Determine if input is a file or direct target
if [[ -f "$TARGET" ]]; then
    INPUT_FLAG="-iL $TARGET"
    log_info "Target file detected: $TARGET ($(wc -l < "$TARGET") entries)"
else
    INPUT_FLAG="$TARGET"
    log_info "Target: $TARGET"
fi

echo -e "${BOLD}Results directory: ${RESULTS_DIR}/${NC}"


# ============================================================
# PHASE 1: HOST DISCOVERY
# ============================================================
log_phase "[PHASE 1/3] Host Discovery — Finding live hosts..."

nmap -sn $INPUT_FLAG -oG - 2>/dev/null | awk '/Up$/{print $2}' > "$RESULTS_DIR/discovered_hosts.txt"

# Count before filtering
DISCOVERED_COUNT=$(wc -l < "$RESULTS_DIR/discovered_hosts.txt")

if [[ "$DISCOVERED_COUNT" -eq 0 ]]; then
    log_error "No live hosts found. Exiting."
    exit 1
fi

log_info "Discovered hosts (pre-filter): $DISCOVERED_COUNT"

# ---- Filter out invalid/self IPs ----
ATTACKER_IP=$(hostname -I | awk '{print $1}')
ATTACKER_REGEX=$(echo "$ATTACKER_IP" | sed 's/\./\\./g')

log_info "Attacker IP (excluded): $ATTACKER_IP"

# Filter with fallback (grep returns 1 if no match — protect against set -e)
grep -Ev "^(${ATTACKER_REGEX}|0\.0\.0\.0|255\.255\.255\.255|127\.[0-9]+\.[0-9]+\.[0-9]+|169\.254\.[0-9]+\.[0-9]+|#.*|^$)" \
    "$RESULTS_DIR/discovered_hosts.txt" > "$RESULTS_DIR/live_hosts.txt" || true

# Remove intermediate file
rm -f "$RESULTS_DIR/discovered_hosts.txt"

# Validate we still have hosts after filtering
LIVE_COUNT=$(wc -l < "$RESULTS_DIR/live_hosts.txt")

if [[ "$LIVE_COUNT" -eq 0 ]]; then
    log_error "No valid hosts remaining after filtering. Exiting."
    exit 1
fi

log_info "Live hosts (post-filter): $LIVE_COUNT"
log_info "Saved to: $RESULTS_DIR/live_hosts.txt"
echo ""

# Display live hosts
echo -e "${BOLD}Live Hosts:${NC}"
while IFS= read -r host; do
    echo -e "  ${GREEN}▸${NC} $host"
done < "$RESULTS_DIR/live_hosts.txt"
echo ""


# ============================================================
# PHASE 2: AGGRESSIVE SCAN + VULN DETECTION
# ============================================================
log_phase "[PHASE 2/3] Aggressive Scan — Full port scan with vuln scripts (-A -p- --script vuln)..."

echo -e "${YELLOW}[*] This may take a while depending on target count and network size...${NC}"
echo ""

nmap -A -T3 -p- \
    --script vuln \
    -iL "$RESULTS_DIR/live_hosts.txt" \
    -oN "$RESULTS_DIR/nmap_report.txt" \
    -oX "$RESULTS_DIR/nmap_report.xml" \
    --stats-every 30s 2>&1 | while IFS= read -r line; do
    # Show nmap progress updates
    if [[ "$line" == *"About"*"done"* ]] || [[ "$line" == *"Stats:"* ]]; then
        echo -e "  ${CYAN}${line}${NC}"
    fi
done || true

# Validate output
if [[ ! -s "$RESULTS_DIR/nmap_report.xml" ]]; then
    log_error "Nmap scan produced no XML output!"
    log_warn "Check $RESULTS_DIR/nmap_report.txt for errors."
    exit 1
fi

log_info "Nmap scan complete"
log_info "Text report: $RESULTS_DIR/nmap_report.txt"
log_info "XML report:  $RESULTS_DIR/nmap_report.xml"


# ============================================================
# PHASE 3: GENERATE HTML REPORT
# ============================================================
log_phase "[PHASE 3/3] Report Generation — Creating HTML asset report..."

if xsltproc -o "$RESULTS_DIR/nmap_report.html" "$XSL_FILE" "$RESULTS_DIR/nmap_report.xml" 2>/dev/null; then
    log_info "HTML report generated: $RESULTS_DIR/nmap_report.html"
else
    log_warn "HTML generation failed. XML and TXT reports are still available."
fi


# ============================================================
# QUICK SUMMARY
# ============================================================
echo ""
echo -e "${BOLD}─── Quick Summary ──────────────────────────────────────${NC}"

# Extract stats from nmap text report
if [[ -f "$RESULTS_DIR/nmap_report.txt" ]]; then
    OPEN_PORTS=$(grep -c "open" "$RESULTS_DIR/nmap_report.txt" 2>/dev/null || echo "0")
    VULNS_FOUND=$(grep -ciE "(VULNERABLE|CVE-)" "$RESULTS_DIR/nmap_report.txt" 2>/dev/null || echo "0")

    echo -e "  ${GREEN}▸${NC} Hosts scanned:       $LIVE_COUNT"
    echo -e "  ${GREEN}▸${NC} Open port entries:    $OPEN_PORTS"

    if [[ "$VULNS_FOUND" -gt 0 ]]; then
        echo -e "  ${RED}▸${NC} Vulnerability hits:  $VULNS_FOUND"
    else
        echo -e "  ${GREEN}▸${NC} Vulnerability hits:  $VULNS_FOUND"
    fi
fi

echo ""


# ============================================================
# FINAL OUTPUT
# ============================================================
ELAPSED=$SECONDS
MINUTES=$((ELAPSED / 60))
SECS=$((ELAPSED % 60))

echo -e "${CYAN}╔══════════════════════════════════════════════════════════╗${NC}"
echo -e "${CYAN}║              RECONNAISSANCE COMPLETE!                    ║${NC}"
echo -e "${CYAN}╚══════════════════════════════════════════════════════════╝${NC}"
echo ""
echo -e "${GREEN}Results saved in: ${BOLD}${RESULTS_DIR}/${NC}"
echo -e "${GREEN}  ├── live_hosts.txt          ${NC}(discovered live IPs)"
echo -e "${GREEN}  ├── nmap_report.txt         ${NC}(detailed text report)"
echo -e "${GREEN}  ├── nmap_report.xml         ${NC}(XML for parsing/tools)"
echo -e "${GREEN}  └── nmap_report.html        ${NC}(interactive HTML report)"
echo ""
echo -e "${YELLOW}[*] Total scan time: ${MINUTES}m ${SECS}s${NC}"
echo ""