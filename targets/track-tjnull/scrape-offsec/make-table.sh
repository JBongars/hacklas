#!/bin/bash

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
MACHINES_JSON="$SCRIPT_DIR/offsec-pg-machines.json"

while read name; do
  jq -r --arg n "$name" '.[] | select(.name == $n) | "| [ ] | \(.name) | \(.adjustedDifficulty) | [\(.name)](\(.link)) | | \(.os) | |"' "$MACHINES_JSON"
done
