#!/usr/bin/env bash

set -euo pipefail


VI=$(which nvim || which vim || which vi || which nano)
SCRIPT_DIR="$(dirname "$0")"
FOLDER_PATH="$(cd "${SCRIPT_DIR}/.." && pwd -P)"

echo "alias gtt='cd \"\$(cat \"$FOLDER_PATH/.current-target\")\"'"

