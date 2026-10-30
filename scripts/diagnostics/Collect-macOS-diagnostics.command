#!/bin/sh
set -eu
cd "$(dirname "$0")/../.."
if [ "$(uname -s)" != Darwin ]; then
    echo 'Run this file in macOS Sequoia.'
    exit 1
fi
python3 scripts/diagnostics/collect-native-preflight.py
printf '\nPress Enter to close.\n'
read -r answer
