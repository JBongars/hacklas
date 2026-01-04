#!/bin/bash

set -euo pipefail

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

log() { echo -e "${GREEN}[+]${NC} $1"; }
warn() { echo -e "${YELLOW}[!]${NC} $1"; }
err() { echo -e "${RED}[-]${NC} $1"; }

IP_ADDRESS="${1:?Usage: $0 <IP_ADDRESS> [ATTACK_FOLDER]}"
ATTACK_FOLDER="${2:-$(pwd)/targets/${IP_ADDRESS}}"
SCAN_MODE="${3:-full}"

mkdir -p "$ATTACK_FOLDER/nmap"

# ============================================================================
# NMAP SCANNING
# ============================================================================
case "$SCAN_MODE" in {
    quick)
        log "Starting quick port scan (rustscan)"
        # Quick scan first for immediate results
        rustscan -a "$IP_ADDRESS" -ulimit 5000 -- -sC -sV -oA "$ATTACK_FOLDER/nmap/quick"
        ;;

    full)
        log "Starting full port scan (nmap)"
        nmap -sC -sV -p- -oA "$ATTACK_FOLDER/nmap/full" "$IP_ADDRESS" &
        FULL_NMAP_PID=$!
        ;;

    *)
        usage
        exit 1
}
