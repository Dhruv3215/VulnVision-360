#!/bin/bash

#====================================================
#  Nmap Automated Reconnaissance Script
#  Usage: sudo bash scripts/recon.sh <target>
#  Example: sudo bash scripts/recon.sh 192.168.1.0/24
#           sudo bash scripts/recon.sh targets.txt
#====================================================

set -e

# ---- Colors ----
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

SECONDS=0

# ---- Banner ----
echo -e "${CYAN}"
echo "╔══════════════════════════════════════════════════════╗"
echo "║       NMAP AUTOMATED RECON & ASSET REPORTER          ║"
echo "║                    v1.0                              ║"
echo "╚══════════════════════════════════════════════════════╝"
echo -e "${NC}"

# ---- Input Validation ----
if [ -z "$1" ]; then
    echo -e "${RED}[!] Usage: sudo bash $0 <target_ip/subnet or target_file>${NC}"
    echo -e "${RED}[!] Example: sudo bash $0 192.168.1.0/24${NC}"
    echo -e "${RED}[!] Example: sudo bash $0 targets.txt${NC}"
    exit 1
fi

# Check if running as root
if [ "$EUID" -ne 0 ]; then
    echo -e "${RED}[!] Please run as root (sudo)${NC}"
    exit 1
fi

TARGET="$1"
RESULTS_DIR="results"
TIMESTAMP=$(date +"%Y%m%d_%H%M%S")

# Create results directory
mkdir -p "$RESULTS_DIR"

# Determine if input is a file or direct target
if [ -f "$TARGET" ]; then
    INPUT_FLAG="-iL $TARGET"
    echo -e "${GREEN}[*] Target file detected: $TARGET${NC}"
else
    INPUT_FLAG="$TARGET"
    echo -e "${GREEN}[*] Target: $TARGET${NC}"
fi

# ============================================
# PHASE 1: HOST DISCOVERY
# ============================================
echo -e "\n${YELLOW}[PHASE 1/4] Host Discovery - Finding live hosts...${NC}"
echo "================================================================"

# More robust grep using awk to avoid false positives
nmap -sn $INPUT_FLAG -oG - | awk '/Up$/{print $2}' > "$RESULTS_DIR/live_hosts.txt"



if [ "$LIVE_COUNT" -eq 0 ]; then
    echo -e "${RED}[!] No live hosts found. Exiting.${NC}"
    exit 1
fi

ATTACKER_IP=$(hostname -I | awk '{print $1}')

# Escape dots in attacker IP for regex
ATTACKER_REGEX=$(echo "$ATTACKER_IP" | sed 's/\./\\./g')

# Single regex — removes all invalid addresses
grep -Ev "^(${ATTACKER_REGEX}|0\.0\.0\.0|255\.255\.255\.255|127\.[0-9]+\.[0-9]+\.[0-9]+|169\.254\.[0-9]+\.[0-9]+|255\.[0-9]+\.[0-9]+\.[0-9]+|[0-9]+\.[0-9]+\.[0-9]+\.255|[0-9]+\.[0-9]+\.[0-9]+\.0|#.*|^$)" \
    "$RESULTS_DIR/live_hosts.txt" > "$RESULTS_DIR/final_live_hosts.txt"
rm "$RESULTS_DIR/live_hosts.txt"

LIVE_COUNT=$(wc -l < "$RESULTS_DIR/final_live_hosts.txt")
echo -e "${GREEN}[✓] Live hosts found: $LIVE_COUNT${NC}"
echo -e "${GREEN}[✓] Saved to: $RESULTS_DIR/final_live_hosts.txt${NC}"

cat "$RESULTS_DIR/final_live_hosts.txt"
echo ""


# ============================================
# PHASE 2: AGGRESSIVE SCAN
# ============================================
echo -e "\n${YELLOW}[PHASE 2/4] Aggressive Scan - Running comprehensive scan (-A)...${NC}"
echo "================================================================"

nmap -A -T3 \
    -iL "$RESULTS_DIR/final_live_hosts.txt" \
    -oN "$RESULTS_DIR/aggressive_scan.txt" \
    -oX "$RESULTS_DIR/aggressive_scan.xml" \
    > /dev/null 2>&1 \
    || true

echo -e "${GREEN}[✓] Aggressive scan complete${NC}"
echo -e "${GREEN}[✓] Results: $RESULTS_DIR/aggressive_scan.txt${NC}"

# ============================================
# PHASE 3: VULNERABILITY SCAN
# ============================================
echo -e "\n${YELLOW}[PHASE 3/4] Vulnerability Scan - Running vuln scripts...${NC}"
echo "================================================================"

nmap -sV --script vuln \
    -iL "$RESULTS_DIR/final_live_hosts.txt" \
    -oN "$RESULTS_DIR/vuln_scan.txt" \
    -oX "$RESULTS_DIR/vuln_scan.xml" \
    > /dev/null 2>&1 \
    || true

echo -e "${GREEN}[✓] Vulnerability scan complete${NC}"
echo -e "${GREEN}[✓] Results: $RESULTS_DIR/vuln_scan.txt${NC}"

# ============================================
# PHASE 4: GENERATE CSV REPORT
# ============================================
echo -e "\n${YELLOW}[REPORT] Generating consolidated CSV asset report...${NC}"
echo "================================================================"

if command -v python3 >/dev/null 2>&1; then
    python3 generate_csv.py
else
    echo -e "${RED}[!] python3 not found. Please install Python 3 to generate CSV.${NC}"
fi

echo -e "\n${CYAN}╔══════════════════════════════════════════════════════╗${NC}"
echo -e "${CYAN}║              RECONNAISSANCE COMPLETE!                 ║${NC}"
echo -e "${CYAN}╚══════════════════════════════════════════════════════╝${NC}"
echo ""
echo -e "${GREEN}Results saved in: $RESULTS_DIR/${NC}"
echo -e "${GREEN}  ├── live_hosts.txt${NC}"
echo -e "${GREEN}  ├── aggressive_scan.txt / aggressive_scan.xml${NC}"
echo -e "${GREEN}  ├── vuln_scan.txt / vuln_scan.xml${NC}"
echo -e "${GREEN}  └── final_asset_report.csv${NC}"
echo ""
echo -e "${YELLOW}[*] Total scan time: $SECONDS seconds${NC}"
