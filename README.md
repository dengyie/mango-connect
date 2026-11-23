# mango-connect

Self-hosted, multi-user **Clash / sing-box / Surge / Quantumult X subscription
share station**. It republishes a proxy gateway's node pool to a small group of
people. Each person gets their own revocable token, an account with a quota and
an expiry date, and a dashboard. Nothing in the gateway's own credentials or
topology is ever exposed.

Python 3.10+ with a single dependency (PyYAML, `pip install -r requirements.txt`),
no build step and no external assets. Pages are server-rendered and fully
self-contained: every CSS and JS asset is inline, under a strict CSP.

## Features

- **Subscriptions:** `GET /sub/<token>?fmt=clash|singbox|surge|qx|uri`.
  - ETag/304 caching, plus a last-good fallback when a render fails.
  - `subscription-userinfo` header for quota and expiry.
  - Signed, time-boxed `/sub/download` and `/sub/export` links.
- **Leak gate:** `render_public.py --check-leaks` fails if the public output
  contains any upstream secret, mesh-network server or private node name.
  - A loop guard stops the station from re-ingesting its own output.
  - A fake-node regex and a dead-node exclude list (`sync_exclude.py`) filter
    the pool.
- **Accounts:**
  - scrypt passwords, HMAC sessions, CSRF-protected forms.
  - Login rate limiting: 5 failures lock the account for 15 minutes, and
    scrypt work is capped in flight.
  - Monthly billing cycles, quota and expiry gates.
  - Admin console with an audit log.
- **Live node status:** `/nodes` reads the mihomo controller and never exposes
  servers or UUIDs.
- **Traffic metering:** `scripts/node-agent/` is a tiny agent for self-hosted
  sing-box nodes. It sends v2ray_api stats to `POST /ingest/traffic` with a
  Bearer node token.
  - Optional per-user rendered YAMLs (`SHARE_PER_USER_YAML=1`).
- **Reminders:** quota ≥85% and expiry ≤7 days, sent through an HTTP mail API.
  - Without a mail API configured, reminders go to a log transport.
- **Operations:** atomic state snapshots and restore (`state_backup.py`), and
  log rotation.

## Layout

```
src/
  server.py           HTTP server (ThreadingHTTPServer) – all routes
  pages.py            SSR templates (paper-ink UI, inline icon set, theme toggle)
  render_public.py    gateway pool -> public YAML (+ leak check CLI)
  format_converters.py clash -> sing-box / surge / qx / share-URI
  tokens.py           token store + CLI
  users.py            accounts / sessions / quotas + CLI
  notify.py           reminder engine + CLI
  state_backup.py     snapshots / restore / log rotation
  sync_exclude.py     dead-node exclude list sync
  share_constants.py  shared constants + path/env defaults
scripts/
  bootstrap.sh        rebuild supervisor runtime from the durable state dir
  sync-from-gateway.sh cron: ask the gateway to refresh its client export
  node-agent/         sing-box traffic agent + systemd unit + rollout SOP
assets/brand/         logo
tests/                unittest suite
```

## Quick start

```bash
git clone https://github.com/dengyie/mango-connect.git
cd mango-connect

export SHARE_STATE_DIR=$PWD            # tokens/users/logs live here
export SHARE_CLASH_DIR=/path/to/clash  # expects airports/mango-clash.yaml
export SHARE_PUBLIC_HOST=https://share.example.com

python3 src/users.py add-admin admin   # prompts for a password
python3 src/server.py --listen 127.0.0.1 --port 2054
# sign in at /login, then create users (and their tokens) from /admin;
# standalone tokens: python3 src/tokens.py add <name>  (shown once)
```

Put it behind a TLS reverse proxy or a tunnel. The server only binds to
loopback by default.

## Configuration

| Env | Default | Purpose |
|---|---|---|
| `SHARE_STATE_DIR` | parent of `src/` | tokens, users, logs, backups, rendered output |
| `SHARE_CLASH_DIR` | `<state>/../clash` | gateway artifacts (`airports/mango-clash.yaml`, controller secret) |
| `SHARE_PUBLIC_HOST` | `http://127.0.0.1:2054` | absolute base URL used in subscription links and emails |
| `SHARE_SCOPE` | `whitelist` | `full` mirrors the gateway export; `whitelist` filters `share-nodes.json` |
| `SHARE_PER_USER_YAML` | off | `1` serves per-user rendered YAMLs (needs node-agent rollout) |
| `SHARE_GATEWAY_API` | `http://127.0.0.1:9090` | mihomo controller for `/nodes` |
| `SHARE_GATEWAY_SECRET` | `<clash>/.controller-secret` | controller secret file |
| `ONE_MAIL_API_BASE` / `ONE_MAIL_SEND_TOKEN` | unset | reminder mail transport (log-only when unset) |
| `SHARE_CLIENTS_MANIFEST_URL` | unset | public `manifest.json` written by `scripts/client-mirror.py` (e.g. `https://dl.example.com/pub/clients/manifest.json`); unset = `/clients` links GitHub only |

## Client download mirror

`/clients` lists the recommended client per platform (Clash Verge Rev,
FlClash, CMFA, sing-box, v2rayN/v2rayNG, iOS App Store apps). Release assets
always link GitHub; when `SHARE_CLIENTS_MANIFEST_URL` is set, each file also
gets a mirror link served from your own download host.

Run the mirror on the host whose nginx serves the download directory:

```sh
python3 scripts/client-mirror.py --root /srv/pub/clients \
    --base-url https://dl.example.com/pub/clients --dry-run   # preview
python3 scripts/client-mirror.py --root /srv/pub/clients \
    --base-url https://dl.example.com/pub/clients --loop 21600 # daemon
```

Files land in versioned dirs (`<app>/<tag>/`, CDN-safe), are verified against
GitHub's sha256 digest, and the newest two versions are kept. The share site
re-reads the manifest every 10 minutes and caches the last good copy in the
state dir. Set `GITHUB_TOKEN` if the 60 req/h anonymous API limit is tight.

## Deploying with supervisor

```ini
[program:mango-connect]
command=/usr/bin/python3 /srv/mango-connect/src/server.py --listen 127.0.0.1 --port 2054
directory=/srv/mango-connect
user=mango
autorestart=true
environment=SHARE_STATE_DIR="/srv/mango-connect",SHARE_CLASH_DIR="/srv/clash",SHARE_PUBLIC_HOST="https://share.example.com",SHARE_SCOPE="full"
```

`scripts/bootstrap.sh` rebuilds this runtime layer, covering the supervisor
program, directories, permissions and the sync cron, on hosts where `/etc` is
ephemeral.

## Tests

```bash
python3 -m unittest discover -s tests
```

## License

MIT
