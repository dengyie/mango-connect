#!/usr/bin/env bash
# CI deploy receiver for mango-connect. Installed as the FORCED COMMAND of the
# CI deploy key in root's authorized_keys:
#
#   command="<state>/ci/ci-deploy.sh",restrict ssh-ed25519 AAAA... mango-connect-ci
#
# so the key published as a GitHub secret can do exactly two things, never a
# shell:
#   ssh host deploy <sha> < release.tar.gz   stage, verify, swap, restart, health-gate, auto-rollback
#   ssh host status                          print running state
#
# The receiver lives in <state>/ci/, OUTSIDE the deployable trees, on purpose:
# a release cannot rewrite the gatekeeper that validates it. It sits on the
# durable state volume so it survives container rebuilds. Update it by hand:
#   install -m 0755 -D scripts/ci-deploy.sh <state>/ci/ci-deploy.sh
#
# The tarball may only contain src/*.py, scripts/** and assets/brand/*; state
# (tokens/users/secret.key/logs) is never touched.
set -euo pipefail

# <state>/ci/ci-deploy.sh -> <state>
STATE=${SHARE_STATE_DIR:-$(cd "$(dirname "$(readlink -f "${BASH_SOURCE[0]}")")/.." && pwd)}
PROGRAM=${SHARE_SUPERVISOR_PROGRAM:-mango-share}
SERVICE_USER=${SHARE_SERVICE_USER:-zdashboard}
PYTHON=${SHARE_PYTHON:-/opt/mamba/bin/python3}
HEALTH_URL=${SHARE_HEALTH_URL:-http://127.0.0.1:2054/health}
KEEP_BACKUPS=${SHARE_KEEP_CI_BACKUPS:-5}
MAX_BYTES=$((20 * 1024 * 1024))
LOCK=/run/lock/mango-connect-ci-deploy.lock

log() { echo "[ci-deploy] $*"; }
die() { echo "[ci-deploy] ERROR: $*" >&2; exit 1; }

health() {
  # -q/--noproxy: root's curlrc on this host may point at a local proxy.
  curl -q --noproxy '*' -fsS -m 5 "$HEALTH_URL" 2>/dev/null | grep -q '"ok": true'
}

status() {
  supervisorctl status "$PROGRAM" || true
  echo "release: $(cat "$STATE/.release" 2>/dev/null || echo unknown)"
  if health; then echo "health: ok"; else echo "health: FAIL"; fi
  ls -1dt "$STATE"/rollback/ci-* 2>/dev/null | head -n "$KEEP_BACKUPS" | sed 's/^/backup: /'
}

deploy() {
  local sha=$1
  [[ $sha =~ ^[0-9a-f]{7,40}$ ]] || die "bad release id: $sha"

  # Global, not local: the EXIT trap fires after deploy() has returned.
  WORK=$(mktemp -d /tmp/mango-connect-release.XXXXXX)
  trap 'rm -rf "$WORK"' EXIT
  local work=$WORK

  head -c $((MAX_BYTES + 1)) > "$work/release.tar.gz"
  [[ $(stat -c %s "$work/release.tar.gz") -le $MAX_BYTES ]] || die "release larger than $MAX_BYTES bytes"

  # Whitelist every member BEFORE extracting: no absolute paths, no '..', no
  # links, nothing outside the three deployable trees.
  local bad
  bad=$(tar -tzvf "$work/release.tar.gz" | awk '
    { type = substr($1, 1, 1); name = $NF }
    type != "-" && type != "d" { print "non-regular: " name; next }
    name ~ /^\// || name ~ /(^|\/)\.\.(\/|$)/ { print "unsafe path: " name; next }
    name !~ /^(src|scripts|assets\/brand)(\/|$)/ { print "outside whitelist: " name }
  ')
  [[ -z $bad ]] || die "rejected release:"$'\n'"$bad"

  mkdir "$work/new"
  tar -xzf "$work/release.tar.gz" -C "$work/new" --no-same-owner --no-same-permissions
  [[ -f $work/new/src/server.py ]] || die "release has no src/server.py"

  log "compile check with $PYTHON"
  PYTHONDONTWRITEBYTECODE=1 "$PYTHON" -c '
import ast, pathlib, sys
for p in sorted(pathlib.Path(sys.argv[1]).glob("*.py")):
    ast.parse(p.read_text(encoding="utf-8"), str(p))
' "$work/new/src" || die "release does not parse"
  # Import the whole module graph from the STAGED tree with the production
  # env: a half-synced module set (missing symbol between files) fails here,
  # not after the restart.
  ( cd "$work/new/src" && SHARE_STATE_DIR="$STATE" PYTHONDONTWRITEBYTECODE=1 "$PYTHON" -c '
import sys; sys.path.insert(0, ".")
for m in ("share_constants", "state_backup", "users", "tokens", "notify",
          "format_converters", "render_public", "node_pool", "clients", "sync_exclude", "pages", "server"):
    __import__(m)
' ) || die "release does not import"

  local ts backup
  ts=$(date +%Y%m%d%H%M%S)
  backup="$STATE/rollback/ci-$ts-$(cat "$STATE/.release" 2>/dev/null || echo unknown)"
  mkdir -p "$backup"
  for d in src scripts assets; do
    [[ -d $STATE/$d ]] && cp -a "$STATE/$d" "$backup/"
  done
  # A rollback that restores nothing would turn a bad release into an
  # outage: refuse to deploy without a usable backup.
  [[ -f $backup/src/server.py ]] || die "backup $backup has no src/server.py; refusing to deploy"
  log "backup -> $backup"

  install_tree() {
    local from=$1
    for d in src scripts assets/brand; do
      [[ -d $from/$d ]] || continue
      mkdir -p "$STATE/$d"
      # Per-file rename into place: a running bash/python never reads a
      # half-written file, and files absent from the release are removed only
      # for src/*.py (stale modules shadow nothing else).
      (cd "$from/$d" && find . -type f) | while read -r f; do
        mkdir -p "$STATE/$d/$(dirname "$f")"
        cp "$from/$d/$f" "$STATE/$d/$f.ci-new"
        mv -f "$STATE/$d/$f.ci-new" "$STATE/$d/$f"
      done
    done
    if [[ -d $from/src ]]; then
      for f in "$STATE"/src/*.py; do
        [[ -f $from/src/$(basename "$f") ]] || rm -f "$f"
      done
    fi
    chown -R root:"$SERVICE_USER" "$STATE/src" "$STATE/assets"
    find "$STATE/src" "$STATE/assets" -type f -exec chmod 0644 {} +
    find "$STATE/scripts" -type f -name '*.sh' -exec chmod 0755 {} +
  }

  restart_and_wait() {
    supervisorctl restart "$PROGRAM" >/dev/null || true
    local i
    for i in $(seq 1 20); do
      sleep 1.5
      health && return 0
    done
    return 1
  }

  rollback() {
    log "$1 - rolling back to $backup"
    supervisorctl tail "$PROGRAM" stderr 2>/dev/null | tail -20 || tail -20 "$STATE/logs/mango-share.log" || true
    rm -f "$STATE"/src/*.py
    install_tree "$backup" || log "restoring backup files failed"
    if restart_and_wait; then
      log "rollback healthy"
    else
      log "rollback ALSO unhealthy - manual recovery required"
    fi
    exit 1
  }

  # A failure halfway through the copy (disk full, NFS hiccup) leaves a mixed
  # tree: roll back instead of letting `set -e` exit with it in place.
  ( set -e; install_tree "$work/new" ) || rollback "install failed"
  log "restarting $PROGRAM"
  if restart_and_wait; then
    echo "$sha" > "$STATE/.release.ci-new" && mv -f "$STATE/.release.ci-new" "$STATE/.release"
    log "release $sha healthy"
  else
    rollback "health gate FAILED"
  fi

  ls -1dt "$STATE"/rollback/ci-* 2>/dev/null | tail -n +$((KEEP_BACKUPS + 1)) | xargs -r rm -rf
  status
}

exec 9>"$LOCK"
flock -w 120 9 || die "another deploy holds $LOCK"

# Forced-command mode: the client's requested command arrives here. Split on
# whitespace only: no glob expansion of client-supplied words.
set -f
set -- ${SSH_ORIGINAL_COMMAND:-${*:-status}}
set +f
case "${1:-status}" in
  deploy) [[ $# -eq 2 ]] || die "usage: deploy <sha>"; deploy "$2" ;;
  status) status ;;
  *) die "unsupported command: $1 (allowed: deploy <sha>, status)" ;;
esac
