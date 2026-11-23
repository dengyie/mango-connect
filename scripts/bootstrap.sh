#!/usr/bin/env bash
# mango-share runtime bootstrap (container / ephemeral-/etc hosts).
#
# Rebuilds the RUNTIME layer (supervisor program + dirs + permissions) from
# the durable state dir (default: this repo checkout, i.e. <state>/scripts/..).
# State data (tokens/users/
# logs/backups/public render) lives on the NFS mount and survives container
# recycling; only /etc + the python environment are ephemeral.
#
# Run as root:  bash <state>/scripts/bootstrap.sh
#   env: SHARE_STATE_DIR (default: parent of scripts/), SHARE_SERVICE_USER
#                       bash ... --dry-run   (show actions only)
set -euo pipefail

STATE=${SHARE_STATE_DIR:-$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)}
SRC=$STATE/src
CONF_SRC=$STATE/supervisor-mango-share.conf
CONF_DST=/etc/supervisor/conf.d/mango-share.conf
SERVICE_USER=${SHARE_SERVICE_USER:-zdashboard}
DRY=0
[[ "${1:-}" == "--dry-run" ]] && DRY=1

step() { echo "==> $*"; }
run() { if [[ $DRY == 1 ]]; then echo "    [dry] $*"; else eval "$@"; fi; }

step "service user"
id "$SERVICE_USER" >/dev/null 2>&1 || {
  echo "  user $SERVICE_USER missing - create it (useradd -r -m $SERVICE_USER) and rerun"
  exit 1
}

step "python check"
command -v python3 >/dev/null || { echo "  python3 missing"; exit 1; }
python3 -m py_compile "$SRC"/server.py "$SRC"/users.py "$SRC"/pages.py \
  "$SRC"/tokens.py "$SRC"/state_backup.py "$SRC"/notify.py \
  "$SRC"/render_public.py "$SRC"/sync_exclude.py "$SRC"/share_constants.py \
  "$SRC"/clients.py "$SRC"/node_pool.py "$SRC"/format_converters.py

step "state dirs + permissions"
run mkdir -p "$STATE"/public "$STATE"/logs "$STATE"/backups
run chown root:"$SERVICE_USER" "$STATE"
run chmod 0770 "$STATE"
run chown -R "$SERVICE_USER":"$SERVICE_USER" "$STATE"/logs "$STATE"/backups "$STATE"/public/users 2>/dev/null || true
run chmod 0750 "$STATE"/logs
for f in tokens.json users.json usage.log audit.log traffic-ingest.log notify.log notify_state.json nodes.json secret.key; do
  [[ -f $STATE/$f ]] && run chown "$SERVICE_USER":"$SERVICE_USER" "$STATE/$f" && run chmod 0640 "$STATE/$f"
done
[[ -f $STATE/secret.key ]] && run chmod 0600 "$STATE/secret.key"
[[ -f $STATE/share-nodes.json ]] && run chown root:"$SERVICE_USER" "$STATE/share-nodes.json" && run chmod 0640 "$STATE/share-nodes.json"
[[ -f $STATE/exclude.json ]] && run chown root:"$SERVICE_USER" "$STATE/exclude.json" && run chmod 0640 "$STATE/exclude.json"

step "supervisor program"
[[ -f $CONF_SRC ]] || { echo "  missing $CONF_SRC"; exit 1; }
# Pin the sharing scope onto the EXISTING environment= line (single line,
# comma-merged). supervisor INI: a second environment= key silently
# overrides the first - the exact trap a container rebuild must not
# re-introduce (the state copy may already carry SHARE_PER_USER_YAML etc.).
if ! grep -q '^environment=' "$CONF_SRC"; then
  echo "  WARN: no environment= line in $CONF_SRC - SHARE_SCOPE not pinned"
elif ! grep -q 'SHARE_SCOPE' "$CONF_SRC"; then
  if [[ $DRY == 1 ]]; then
    echo "    [dry] merge SHARE_SCOPE=\"full\" into the existing environment= line"
  else
    python3 - "$CONF_SRC" <<'PYEOF'
import re, sys
p = sys.argv[1]
s = open(p, encoding='utf-8').read()
s2 = re.sub(r'^environment=(.*)$', lambda m: 'environment=' + m.group(1).rstrip() + ', SHARE_SCOPE="full"', s, count=1, flags=re.M)
open(p, 'w', encoding='utf-8').write(s2)
PYEOF
  fi
fi
run cp "$CONF_SRC" "$CONF_DST"
run supervisorctl reread
run supervisorctl update

step "start / verify"
run supervisorctl restart mango-share
sleep 2
run supervisorctl status mango-share
run curl -sf http://127.0.0.1:2054/health && echo

step "gateway alignment cron (10 min)"
CRON_LINE="*/10 * * * * root $STATE/scripts/sync-from-gateway.sh >/dev/null 2>&1"
if [[ $DRY == 1 ]]; then
  echo "    [dry] write /etc/cron.d/mango-share-sync: $CRON_LINE"
else
  printf '%s\n' "$CRON_LINE" > /etc/cron.d/mango-share-sync
  chmod 0644 /etc/cron.d/mango-share-sync
fi

step "CI deploy key (forced command; /root is ephemeral)"
CI_PUB=$STATE/ci/authorized_key.pub
if [[ -f $CI_PUB && -x $STATE/ci/ci-deploy.sh ]]; then
  CI_LINE="command=\"$STATE/ci/ci-deploy.sh\",restrict $(cat "$CI_PUB")"
  if grep -qF "$(awk '{print $2}' "$CI_PUB")" /root/.ssh/authorized_keys 2>/dev/null; then
    echo "  CI key present"
  elif [[ $DRY == 1 ]]; then
    echo "    [dry] append CI deploy key to /root/.ssh/authorized_keys"
  else
    install -d -m 0700 /root/.ssh
    printf '%s\n' "$CI_LINE" >> /root/.ssh/authorized_keys
    chmod 0600 /root/.ssh/authorized_keys
    echo "  CI key restored"
  fi
else
  echo "  no $CI_PUB - CI deploys disabled"
fi

step "cloudflared reminder"
if pgrep -f "cloudflared tunnel" >/dev/null 2>&1; then
  echo "  cloudflared tunnel running"
else
  echo "  NOTE: cloudflared tunnel not running - site unreachable until it starts"
fi

echo "bootstrap done"
