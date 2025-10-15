#!/usr/bin/env bash
set -euo pipefail

VI=$(which nvim || which vim || which vi || which nano)

function usage() {
    echo "Usage: $0 [filename]"
    echo "Create/edit notes. If no directory provided, uses timestamp."
    echo "Accepts content via stdin or opens editor."
    exit 0
}

# Handle help flag
if [[ "${1:-}" == "-h" || "${1:-}" == "--help" ]]; then
    usage
fi

SCRIPT_DIR="$(dirname "$0")"
NOTE_FILENAME="${1:-$(date +'%Y%m%dT%H%M%S')-to-sort.md}"
FOLDER_PATH=$(cd "${SCRIPT_DIR}/.." && pwd)
NOTE_LOCATION="$FOLDER_PATH/$NOTE_FILENAME"

function init_note() {
    local file_path="$1"
    
    # Create directory if it doesn't exist
    local dir_path="$(dirname "$file_path")"
    if [ ! -d "$dir_path" ]; then
        mkdir -p "$dir_path"
    fi
    
    # Create file with template if it doesn't exist
    if [ ! -f "$file_path" ]; then
        cat <<'EOF' > "$file_path"
link = https://

# Port scanning

**rustscan**

```bash

```

**nmap**

```bash

```


# Enumeration


# Creds
- 

# References
- 
EOF
    fi
}

function edit_note() {
    local file_path="$1"
    init_note "$file_path/main.md"
    $VI "$file_path/main.md"
}

edit_note "$NOTE_LOCATION"
