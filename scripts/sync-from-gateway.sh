#!/usr/bin/env bash
# Trigger the gateway's own client-export regeneration: pulling
# /sub/clash makes the gateway atomically rewrite mango-clash.yaml
# (fingerprint skip = instant when unchanged). mango-share's render
# fingerprint then picks the change up on the next request.
# Run as root (reads client-export.token). Cron: */10.
set -euo pipefail
STATE=${SHARE_STATE_DIR:-$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)}
CLASH_DIR=${SHARE_CLASH_DIR:-$(dirname "$STATE")/clash}
TOKEN_FILE=${SHARE_GATEWAY_EXPORT_TOKEN:-$CLASH_DIR/subscriptions/client-export.token}
GATEWAY=${SHARE_GATEWAY_BASE:-http://127.0.0.1:2053}
TOKEN=$(cat "$TOKEN_FILE")
curl -sf --max-time 20 "$GATEWAY/sub/clash?token=$TOKEN" -o /dev/null
