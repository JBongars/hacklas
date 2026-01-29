#!/usr/bin/env bash
set -euo pipefail

VI=$(which nvim || which vim || which vi || which nano)

function usage() {
    echo "Usage: $0 [folder]"
    echo "Create/edit notes. If no folder provided, uses timestamp."
    echo "Opens editor to edit main.md inside the folder."
    exit 0
}

# Handle help flag
if [[ "${1:-}" == "-h" || "${1:-}" == "--help" ]]; then
    usage
fi

SCRIPT_DIR="$(dirname "$0")"
NOTE_FOLDER="${1:-$(date +'%Y%m%dT%H%M%S')-to-sort}"
FOLDER_PATH="$(cd "${SCRIPT_DIR}/.." && pwd)"
NOTE_LOCATION="$FOLDER_PATH/$NOTE_FOLDER"

echo $NOTE_LOCATION > .current-target

function init_note() {
    local file_path="$1"
    local dir_path="$(dirname "$file_path")"
    local title="$(basename "$dir_path")"
    
    # Create directory if it doesn't exist
    if [ ! -d "$dir_path" ]; then
        mkdir -p "$dir_path"
        mkdir -p "$dir_path/nmap"
    fi
    
    # Create file with template if it doesn't exist
    if [ ! -f "$file_path" ]; then
        cat <<EOF > "$file_path"
# ${title}
- **Author:** Julien Bongars
- **Date:** $(date +'%Y-%m-%d %H:%M:%S')
- **Path:** ${dir_path}
---

link = https://app.hackthebox.com/machines/${title}
ip = 

# Port scanning

**rustscan**
\`\`\`bash
rustscan -a "\$IP_ADDRESS" -ulimit 5000 -- -sC -sV -oA "${dir_path}/nmap/quick"
\`\`\`

**nmap**
\`\`\`bash
nmap -sC -sV -p- -oA "${dir_path}/nmap/full" "\$IP_ADDRESS"
\`\`\`

# Enumeration

# Creds
- 

# References
- 
EOF
    fi

    cp -r "$FOLDER_PATH/templates/checklists" "$dir_path"
}

function edit_note() {
    local folder_path="$1"
    init_note "$folder_path/main.md"
    $VI "$folder_path/main.md"
}

edit_note "$NOTE_LOCATION"
