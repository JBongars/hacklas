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

# Wordlists - adjust paths as needed
DIRLIST="/usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt"
FILELIST="/usr/share/seclists/Discovery/Web-Content/raft-medium-files.txt"
SUBDOMAIN_LIST="/usr/share/seclists/Discovery/DNS/subdomains-top1million-20000.txt"
VHOST_LIST="/usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt"

mkdir -p "$ATTACK_FOLDER"/{nmap,web,ftp,smb,nfs}

# ============================================================================
# NMAP SCANNING
# ============================================================================
run_nmap() {
    log "Starting rustscan scan on $IP_ADDRESS"
    
    # Quick scan first for immediate results
    # nmap -sC -sV --top-ports 1000 -oA "$ATTACK_FOLDER/nmap/quick" "$IP_ADDRESS"
    
    if [ ! -f "$ATTACK_FOLDER/nmap/quick" ] ; then
        log "Starting quick port scan (backgrounded)"
        # Quick scan first for immediate results
        rustscan -a "$IP_ADDRESS" -ulimit 5000 -- -sC -sV -oA "$ATTACK_FOLDER/nmap/quick"
    fi

    # Full port scan in background
    log "Starting full port scan (backgrounded)"
    nmap -sC -sV -p- -oA "$ATTACK_FOLDER/nmap/full" "$IP_ADDRESS" &
    FULL_NMAP_PID=$!
}

# Parse nmap greppable output for open ports
get_open_ports() {
    local protocol="${1:-tcp}"
    local nmap_file="${2:-$ATTACK_FOLDER/nmap/quick.gnmap}"
    
    if [[ -f "$nmap_file" ]]; then
        grep -oP '\d+/open/'"$protocol" "$nmap_file" | cut -d'/' -f1 | sort -u
    fi
}

has_service() {
    local service="$1"
    local nmap_file="$ATTACK_FOLDER/nmap/quick.nmap"
    
    [[ -f "$nmap_file" ]] && grep -qi "$service" "$nmap_file"
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
    local header_args=()
    
    if [[ -n "$vhost" ]]; then
        output_dir="$ATTACK_FOLDER/web/${port}/${vhost}"
        header_args=(-H "Host: ${vhost}")
        target_url="${scheme}://${vhost}:${port}"
    fi
    
    mkdir -p "$output_dir"
    
    if [[ -f "$output_dir/.complete" ]]; then
        warn "Enumeration already complete for $target_url, skipping"
        return 0
    fi
    
    log "Enumerating $target_url"
    
    # Grab headers and homepage
    curl -sSikL "${header_args[@]}" "${scheme}://${IP_ADDRESS}:${port}/" \
        -o "$output_dir/index.html" \
        -D "$output_dir/headers.txt" 2>/dev/null || true
    
    # Tech detection with whatweb
    if command -v whatweb &>/dev/null; then
        log "Running whatweb on $target_url"
        whatweb -a 3 "${header_args[@]}" "${scheme}://${IP_ADDRESS}:${port}/" \
            > "$output_dir/whatweb.txt" 2>&1 || true
    fi
    
    # Directory bruteforce
    log "Directory bruteforce on $target_url"
    ffuf -w "$DIRLIST" \
        -u "${scheme}://${IP_ADDRESS}:${port}/FUZZ" \
        ${vhost:+-H "Host: ${vhost}"} \
        -mc all -fc 404 \
        -o "$output_dir/directories.json" \
        -of json \
        2>/dev/null || true
    
    # File bruteforce with extensions
    log "File bruteforce on $target_url"
    ffuf -w "$FILELIST" \
        -u "${scheme}://${IP_ADDRESS}:${port}/FUZZ" \
        ${vhost:+-H "Host: ${vhost}"} \
        -e .php,.html,.txt,.bak,.old,.zip,.config,.xml,.json,.asp,.aspx,.jsp \
        -mc all -fc 404 \
        -o "$output_dir/files.json" \
        -of json \
        2>/dev/null || true
    
    # Nikto scan (can be slow, backgrounded)
    if command -v nikto &>/dev/null; then
        log "Starting nikto (backgrounded)"
        nikto -h "${scheme}://${IP_ADDRESS}:${port}" ${vhost:+-vhost "$vhost"} \
            -o "$output_dir/nikto.txt" &>/dev/null &
    fi
    
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
    
    log "Enumerating vhosts for $domain on port $port"
    
    # Get baseline response size to filter
    local baseline_size
    baseline_size=$(curl -sSik "${scheme}://${IP_ADDRESS}:${port}/" 2>/dev/null | wc -c)
    
    ffuf -w "$VHOST_LIST" \
        -u "${scheme}://${IP_ADDRESS}:${port}/" \
        -H "Host: FUZZ.${domain}" \
        -mc all \
        -fs "$baseline_size" \
        -o "$ATTACK_FOLDER/web/${port}/vhost-scan.json" \
        -of json \
        2>/dev/null || true
    
    # Extract found vhosts
    if [[ -f "$ATTACK_FOLDER/web/${port}/vhost-scan.json" ]]; then
        jq -r '.results[].input.FUZZ' "$ATTACK_FOLDER/web/${port}/vhost-scan.json" 2>/dev/null \
            | while read -r sub; do
                echo "${sub}.${domain}"
            done > "$output_file"
    fi
    
    # Also add the base domain
    echo "$domain" >> "$output_file"
    sort -u "$output_file" -o "$output_file"
}

# Save certificate
save_certificate() {
    local port="$1"
    log "Saving SSL certificate from port $port"
    
    echo | openssl s_client -connect "${IP_ADDRESS}:${port}" 2>/dev/null \
        | openssl x509 -outform PEM > "$ATTACK_FOLDER/web/${port}/certificate.pem" 2>/dev/null || true
    
    # Also save human-readable version
    openssl x509 -in "$ATTACK_FOLDER/web/${port}/certificate.pem" -text -noout \
        > "$ATTACK_FOLDER/web/${port}/certificate.txt" 2>/dev/null || true
}

# ============================================================================
# FTP ENUMERATION
# ============================================================================
enumerate_ftp() {
    local port="${1:-21}"
    log "Checking FTP on port $port"
    
    # Test anonymous login
    if curl -sSf --connect-timeout 5 "ftp://${IP_ADDRESS}:${port}/" --user "anonymous:anonymous@" &>/dev/null; then
        log "Anonymous FTP access allowed!"
        echo "anonymous:anonymous@" > "$ATTACK_FOLDER/ftp/credentials.txt"
        
        # Download everything recursively
        log "Downloading FTP contents"
        wget -r -nH --no-passive-ftp -P "$ATTACK_FOLDER/ftp/anonymous" \
            "ftp://anonymous:anonymous@${IP_ADDRESS}:${port}/" 2>/dev/null || true
    else
        warn "Anonymous FTP not allowed"
    fi
}

# ============================================================================
# SMB ENUMERATION
# ============================================================================
enumerate_smb() {
    local port="${1:-445}"
    log "Enumerating SMB on port $port"
    
    # Null session enumeration
    if command -v smbclient &>/dev/null; then
        log "Listing shares (null session)"
        smbclient -L "//${IP_ADDRESS}" -N -p "$port" \
            > "$ATTACK_FOLDER/smb/shares.txt" 2>&1 || true
    fi
    
    if command -v enum4linux-ng &>/dev/null; then
        log "Running enum4linux-ng"
        enum4linux-ng -A "${IP_ADDRESS}" -oA "$ATTACK_FOLDER/smb/enum4linux" 2>/dev/null || true
    elif command -v enum4linux &>/dev/null; then
        log "Running enum4linux"
        enum4linux -a "${IP_ADDRESS}" > "$ATTACK_FOLDER/smb/enum4linux.txt" 2>&1 || true
    fi
    
    # crackmapexec for more info
    if command -v crackmapexec &>/dev/null; then
        crackmapexec smb "${IP_ADDRESS}" --shares -u '' -p '' \
            > "$ATTACK_FOLDER/smb/cme-shares.txt" 2>&1 || true
    fi
    
    # Try to download readable shares
    if command -v smbget &>/dev/null; then
        while IFS= read -r share; do
            share=$(echo "$share" | awk '{print $1}')
            [[ "$share" =~ ^(IPC\$|ADMIN\$|C\$)$ ]] && continue
            
            log "Attempting to download share: $share"
            mkdir -p "$ATTACK_FOLDER/smb/shares/$share"
            smbget -R "smb://${IP_ADDRESS}/${share}" -a \
                -O "$ATTACK_FOLDER/smb/shares/$share/" 2>/dev/null || true
        done < <(grep "Disk" "$ATTACK_FOLDER/smb/shares.txt" 2>/dev/null || true)
    fi
}

# ============================================================================
# NFS ENUMERATION
# ============================================================================
enumerate_nfs() {
    log "Enumerating NFS"
    
    # Show available mounts
    showmount -e "${IP_ADDRESS}" > "$ATTACK_FOLDER/nfs/exports.txt" 2>&1 || true
    
    if grep -q "/" "$ATTACK_FOLDER/nfs/exports.txt" 2>/dev/null; then
        log "NFS exports found!"
        
        while IFS= read -r export; do
            local mount_path
            mount_path=$(echo "$export" | awk '{print $1}')
            local safe_name
            safe_name=$(echo "$mount_path" | tr '/' '_')
            
            mkdir -p "$ATTACK_FOLDER/nfs/mounts/${safe_name}"
            log "Mounting $mount_path"
            
            # This requires root - will fail otherwise but that's ok
            sudo mount -t nfs "${IP_ADDRESS}:${mount_path}" "$ATTACK_FOLDER/nfs/mounts/${safe_name}" 2>/dev/null || \
                warn "Could not mount $mount_path (may need root)"
        done < <(grep "^/" "$ATTACK_FOLDER/nfs/exports.txt")
    fi
}

enumerate_tcp_port(){
    local port="${1}"
    local nmap_file="${2:-$ATTACK_FOLDER/nmap/quick.gnmap}"

    if grep -q "$port.*http" "$nmap_file" 2>/dev/null; then
        local scheme="http"

        # Check if it's HTTPS
        if grep -q "$port.*ssl\|$port.*https" "$nmap_file" 2>/dev/null || [[ "$port" == "443" ]]; then
            scheme="https"
            save_certificate "$port"
        fi

        # Detect vhost
        local vhost
        if vhost=$(detect_vhost "$port" "$scheme"); then
            log "Detected vhost: $vhost"
            echo "$IP_ADDRESS    $vhost" >> "$ATTACK_FOLDER/hosts_entries.txt"
            warn "Add to /etc/hosts: $IP_ADDRESS    $vhost"

            enumerate_vhosts "$port" "$scheme" "$vhost"

            # Enumerate each discovered vhost
            if [[ -f "$ATTACK_FOLDER/web/${port}/vhosts.txt" ]]; then
                while IFS= read -r vh; do
                    web_enumeration "$port" "$scheme" "$vh"
                done < "$ATTACK_FOLDER/web/${port}/vhosts.txt"
            fi
        else
            web_enumeration "$port" "$scheme"
        fi
    fi
}


# ============================================================================
# MAIN
# ============================================================================
main() {
    log "Starting enumeration of $IP_ADDRESS"
    log "Output directory: $ATTACK_FOLDER"
    
    run_nmap
    
    # Wait for quick scan to complete
    sleep 5
    while [[ ! -f "$ATTACK_FOLDER/nmap/quick.nmap" ]]; do
        sleep 2
    done
    
    log "Quick nmap complete, starting service enumeration"
    
    for port in $(get_open_ports "tcp" "$ATTACK_FOLDER/nmap/quick.gnmap"); do
        enumerate_tcp_port $port
    done
    
    # FTP
    if has_service "ftp"; then
        for port in $(get_open_ports | xargs -I{} grep -l "{}/open.*ftp" "$ATTACK_FOLDER/nmap/quick.gnmap" 2>/dev/null | head -1); do
            enumerate_ftp "$port"
        done
        # Fallback to default port check
        if grep -q "21/open" "$ATTACK_FOLDER/nmap/quick.gnmap" 2>/dev/null; then
            enumerate_ftp 21
        fi
    fi
    
    # SMB
    if has_service "smb\|microsoft-ds\|netbios"; then
        enumerate_smb
    fi
    
    # NFS
    if has_service "nfs\|rpcbind"; then
        enumerate_nfs
    fi
    
    # Wait for background full nmap scan
    if [[ -n "${FULL_NMAP_PID:-}" ]]; then
        log "Waiting for full port scan to complete..."
        wait "$FULL_NMAP_PID" 2>/dev/null || true
        log "Full port scan complete"
    fi
    
    log "Enumeration complete! Results in $ATTACK_FOLDER"
}

main "$@"
