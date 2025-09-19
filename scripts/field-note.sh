#!/usr/bin/env bash
set -euo pipefail

VI=$(which nvim || which vim || which vi || which nano)

function usage() {
    echo "Usage: $0 [filename]"
    echo "Create/edit notes. If no filename provided, uses timestamp."
    echo "Accepts content via stdin or opens editor."
    exit 0
}

# Handle help flag
if [[ "${1:-}" == "-h" || "${1:-}" == "--help" ]]; then
    usage
fi

SCRIPT_DIR="$(dirname "$0")"
NOTE_FILENAME="${1:-$(date +'%Y%m%dT%H%M%S')-to-sort.md}"
FOLDER_PATH=$(cd "${SCRIPT_DIR}/../notes" && pwd)
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
        cat > "$file_path" <<EOF
# $(basename "$NOTE_FILENAME" .md)

Author: Julien Bongars
Date: $(date +'%Y-%m-%d %H:%M:%S')

---

EOF
    fi
}

function add_to_note() {
    local file_path="$1"
    local content="$2"
    
    init_note "$file_path"
    echo "$content" >> "$file_path"
}

function edit_note() {
    local file_path="$1"
    init_note "$file_path"
    $VI "$file_path"
}

# Check if we have stdin input
if [ -t 0 ]; then
    # No stdin, open editor
    edit_note "$NOTE_LOCATION"
else
    # Have stdin, add content to note
    CONTENT="$(cat)"
    add_to_note "$NOTE_LOCATION" "$CONTENT"
fi
