#!/bin/bash
PLATFORM=${1:-linux}

function usage(){
    echo "Usage: $0 [platform]"
    echo "Platforms: linux, powershell, dos"
    echo "Pipe content to this script to encode it"
    echo "Example: echo 'hello world' | $0 linux"
    exit 0
}

if [ -t 0 ]; then
    usage
else
    # Have stdin, add content to note
    CONTENT="$(cat)"
    CONTENT_B64="$(echo -n "$CONTENT" | base64 -w 0)"
    
    case $PLATFORM in
        "linux")
            echo "echo '$CONTENT_B64' | base64 -d > shell.php"
            ;;
        "powershell")
            echo "[System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String('$CONTENT_B64')) | Out-File -FilePath shell.php"
            ;;
        "dos")
            echo "echo $CONTENT_B64 > temp.b64 && certutil -decode temp.b64 shell.php && del temp.b64"
            ;;
        *)
            echo "Unknown platform: $PLATFORM"
            echo "Supported: linux, powershell, dos"
            exit 1
            ;;
    esac
fi
