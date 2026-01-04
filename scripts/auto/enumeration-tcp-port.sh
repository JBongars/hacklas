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

usage(){
    cat <<EOF
Usage: $0 <IP_ADDRESS> <PORT> [ATTACK_FOLDER]

Automated web enumeration script for a specific IP and port.

Arguments:
    IP_ADDRESS      Target IP address
    PORT            Target HTTP/HTTPS port
    ATTACK_FOLDER   Output directory (default: ./targets/<IP_ADDRESS>)

Prerequisites:
    - Nmap scan results in ATTACK_FOLDER/nmap/ (quick.nmap or full.nmap)
    - Tools: httpx, katana, feroxbuster, ffuf, curl, openssl, jq

Features:
    - Auto-detects HTTP/HTTPS from nmap results
    - Discovers vhosts from redirects and SSL certificates
    - Performs vhost enumeration with ffuf
    - Runs httpx, katana, and feroxbuster for each discovered vhost
    - Saves SSL certificates and generates /etc/hosts entries

Examples:
    $0 10.10.10.10 80
    $0 10.10.10.10 443 /root/htb/box1
    
    # With ATTACK_FOLDER environment variable
    export ATTACK_FOLDER=/root/pentest/target1
    $0 192.168.1.100 8080

Output Structure:
    \$ATTACK_FOLDER/
    ├── web/
    │   └── <PORT>/
    │       ├── httpx.json
    │       ├── endpoints.txt
    │       ├── directories.txt
    │       ├── vhosts.txt
    │       ├── certificate.pem (if HTTPS)
    │       └── <vhost>/
    │           ├── httpx.json
    │           ├── endpoints.txt
    │           └── directories.txt
    └── hosts_entries.txt

EOF
    exit 1
}

# Check arguments
if [[ $# -lt 2 ]]; then
    usage
fi

IP_ADDRESS="${1}"
IP_PORT="${2}"
ATTACK_FOLDER="${ATTACK_FOLDER:-${3:-$(pwd)/targets/${IP_ADDRESS}}}"
NMAP_PATH=""

# Wordlists - adjust paths as needed
DIRLIST="/usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt"
FILELIST="/usr/share/seclists/Discovery/Web-Content/raft-medium-files.txt"
SUBDOMAIN_LIST="/usr/share/seclists/Discovery/DNS/subdomains-top1million-20000.txt"
VHOST_LIST="/usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt"

mkdir -p "$ATTACK_FOLDER/web"

# Automatically detect quick or full scan results
if [ -f "$ATTACK_FOLDER/nmap/full.nmap" ] ; then
    NMAP_PATH="$ATTACK_FOLDER/nmap/full"
elif [ -f "$ATTACK_FOLDER/nmap/quick.nmap" ] ; then
    NMAP_PATH="$ATTACK_FOLDER/nmap/quick"
else
    err "No nmap results found in $ATTACK_FOLDER/nmap/"
    err "Expected: quick.nmap or full.nmap (with .gnmap file)"
    usage
fi


# Parse nmap greppable output for open ports
get_open_ports() {
    local protocol="${1:-tcp}"
    local nmap_file="$NMAP_PATH.gnmap"
    
    if [[ -f "$nmap_file" ]]; then
        grep -oP '\d+/open/'"$protocol" "$nmap_file" | cut -d'/' -f1 | sort -u
    fi
}

# ============================================================================
# WEB ENUMERATION
# ============================================================================
web_enumeration() {
    local port="$1"
    local scheme="${2:-http}"
    local vhost="${3:-}"
    local target_url="${scheme}://${IP_ADDRESS}:${port}"
    local output_dir="$ATTACK_FOLDER/web/${port}"
    
    [[ -n "$vhost" ]] && {
        output_dir="$ATTACK_FOLDER/web/${port}/${vhost}"
        target_url="${scheme}://${vhost}:${port}"
    }
    
    mkdir -p "$output_dir"
    [[ -f "$output_dir/.complete" ]] && { 
        warn "Enumeration already complete for $target_url"
        return 0
    }
    
    log "Enumerating $target_url"
    
    # 1. Quick banner grab + tech detection (fast, always do this)
    echo "$target_url" | httpx \
        -silent \
        -tech-detect \
        -status-code \
        -title \
        -web-server \
        -json \
        ${vhost:+-H "Host: ${vhost}"} \
        -o "$output_dir/httpx.json"
    
    # 2. Light crawl (follows real links, JS analysis)
    echo "$target_url" | katana \
        -silent \
        -depth 2 \
        -js-crawl \
        -known-files all \
        ${vhost:+-H "Host: ${vhost}"} \
        -o "$output_dir/endpoints.txt"
    
    # 3. Targeted directory scan (only if you need bruteforce)
    if [[ -f "$DIRLIST" ]]; then
        feroxbuster \
            --url "$target_url" \
            ${vhost:+--add-header "Host: ${vhost}"} \
            --wordlist "$DIRLIST" \
            --extensions php,html,txt,js \
            --threads 10 \
            --depth 2 \
            --auto-tune \
            --quiet \
            --output "$output_dir/directories.txt"
    fi
    
    # Generate additional enumeration script
    cat > "$output_dir/additional_enumeration.sh" <<EOF
#!/bin/bash

whatweb -a 3 ${vhost:+-H "Host: ${vhost}"} "$target_url/"
nikto -h "$target_url" ${vhost:+-vhost "$vhost"} -o "$output_dir/nikto.txt"
echo "$target_url" | nuclei -silent -tags exposure,config,files -o "$output_dir/nuclei.txt"
EOF
    chmod +x "$output_dir/additional_enumeration.sh"
    
    touch "$output_dir/.complete"
}

# Extract vhost from redirect or certificate
detect_vhost() {
    local port="$1"
    local scheme="${2:-http}"
    
    # Check for redirect containing a hostname
    local redirect
    redirect=$(curl -sSik "${scheme}://${IP_ADDRESS}:${port}/" 2>/dev/null \
        | grep -i "^location:" \
        | grep -oP '(?<=://)[^:/]+' \
        | head -1)
    
    if [[ -n "$redirect" && "$redirect" != "$IP_ADDRESS" ]]; then
        echo "$redirect"
        return 0
    fi
    
    # For HTTPS, try extracting from certificate
    if [[ "$scheme" == "https" ]]; then
        local cert_cn
        cert_cn=$(echo | openssl s_client -connect "${IP_ADDRESS}:${port}" 2>/dev/null \
            | openssl x509 -noout -subject -nameopt multiline 2>/dev/null \
            | grep commonName \
            | sed 's/.*= //')
        
        if [[ -n "$cert_cn" && "$cert_cn" != "$IP_ADDRESS" ]]; then
            echo "$cert_cn"
            return 0
        fi
        
        # Check SAN entries too
        local san
        san=$(echo | openssl s_client -connect "${IP_ADDRESS}:${port}" 2>/dev/null \
            | openssl x509 -noout -ext subjectAltName 2>/dev/null \
            | grep -oP 'DNS:[^,]+' \
            | head -1 \
            | sed 's/DNS://')
        
        if [[ -n "$san" ]]; then
            echo "$san"
            return 0
        fi
    fi
    
    return 1
}

# Enumerate vhosts/subdomains
enumerate_vhosts() {
    local port="$1"
    local scheme="${2:-http}"
    local domain="$3"
    local output_file="$ATTACK_FOLDER/web/${port}/vhosts.txt"

    # Start with the base domain
    echo "$domain" > "$output_file"
    
    log "Enumerating vhosts for $domain on port $port"
    
    # Use auto-calibration instead of baseline size
    ffuf -w "$VHOST_LIST" \
        -u "${scheme}://${IP_ADDRESS}:${port}/" \
        -H "Host: FUZZ.${domain}" \
        -mc all \
        -ac \
        -t 40 \
        -rate 100 \
        -o "$ATTACK_FOLDER/web/${port}/vhost-scan.json" \
        -of json \
        -s 2>/dev/null || true
    
    # Extract found vhosts
    if [[ -f "$ATTACK_FOLDER/web/${port}/vhost-scan.json" ]]; then
        jq -r '.results[]?.input.FUZZ' "$ATTACK_FOLDER/web/${port}/vhost-scan.json" 2>/dev/null \
            | while read -r sub; do
                [[ -n "$sub" ]] && echo "${sub}.${domain}"
            done >> "$output_file"
    fi
    
    # Deduplicate
    sort -u "$output_file" -o "$output_file"
}

# Save certificate
save_certificate() {
    local port="$1"
    log "Saving SSL certificate from port $port"
    
    echo | openssl s_client -connect "${IP_ADDRESS}:${port}" 2>/dev/null \
        | openssl x509 -outform PEM > "$ATTACK_FOLDER/web/${port}/certificate.pem" 2>/dev/null || true
    
    # Also save human-readable version
    if [[ -f "$ATTACK_FOLDER/web/${port}/certificate.pem" ]]; then
        openssl x509 -in "$ATTACK_FOLDER/web/${port}/certificate.pem" -text -noout \
            > "$ATTACK_FOLDER/web/${port}/certificate.txt" 2>/dev/null || true
    fi
}

# ============================================================================
# MAIN
# ============================================================================
main(){
    local nmap_file="${NMAP_PATH}.gnmap"
    local scheme="http"
    local vhost

    # Verify nmap results contain the specified port
    if ! grep -q "$IP_PORT.*open" "$nmap_file" 2>/dev/null; then
        err "Port $IP_PORT not found as open in nmap results"
        usage
    fi

    # Check if it's HTTPS
    if grep -q "$IP_PORT.*ssl\|$IP_PORT.*https" "$nmap_file" 2>/dev/null || [[ "$IP_PORT" == "443" ]]; then
        scheme="https"
        save_certificate "$IP_PORT"
    fi

    # Detect vhost
    if vhost=$(detect_vhost "$IP_PORT" "$scheme"); then
        log "Detected vhost: $vhost"
        echo "$IP_ADDRESS    $vhost" >> "$ATTACK_FOLDER/hosts_entries.txt"
        warn "Add to /etc/hosts: $IP_ADDRESS    $vhost"

        enumerate_vhosts "$IP_PORT" "$scheme" "$vhost"

        # Enumerate each discovered vhost
        if [[ -f "$ATTACK_FOLDER/web/${IP_PORT}/vhosts.txt" ]]; then
            while IFS= read -r vh; do
                [[ -n "$vh" ]] && web_enumeration "$IP_PORT" "$scheme" "$vh"
            done < "$ATTACK_FOLDER/web/${IP_PORT}/vhosts.txt"
        fi

        exit 0
    fi

    # No vhost detected, enumerate IP directly
    web_enumeration "$IP_PORT" "$scheme"
}

main
