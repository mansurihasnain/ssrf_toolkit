#!/usr/bin/env bash
# SSRF Hunter Runner
# Uses recon endpoints.txt to discover and detect SSRF vulnerabilities.

set -euo pipefail

TOOL="/mnt/c/Users/mansu/bb/tools/ssrf_hunter.py"

echo "================================================"
echo " SSRF Hunter Runner"
echo " Tool: $TOOL"
echo "================================================"
echo

python3 "$TOOL" \
  -f endpoints.txt \
  --mode all \
  --oob-callback "https://webhook.site/YOUR_ID" \
  --confirm-authorized
