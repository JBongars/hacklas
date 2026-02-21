#!/bin/bash

PROJECT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
CAPTAINS_LOG="$PROJECT_DIR/CAPTAINS_LOG.json"

DATE=$(date +"%Y%m%d%H%M%S")
TARGET=$(basename $(cat "$PROJECT_DIR/.current-target" 2>/dev/null || echo "unknown"))

if [ -t 0 ]; then
  LOG="$1"
else
  LOG=$(cat)
fi


jq -n -c --arg d "$DATE" --arg t "$TARGET" --arg l "$LOG" \
  '{date: $d, target: $t, log: $l}' >> "$CAPTAINS_LOG"

jq -r '"\(.date[0:4])-\(.date[4:6])-\(.date[6:8]) \(.target | split("/") | last): \(.log)"' "$CAPTAINS_LOG"
