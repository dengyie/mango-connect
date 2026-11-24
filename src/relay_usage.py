"""tebi relay traffic meter: mihomo /connections -> mango-share /ingest/traffic.

All non-self-built (airport) nodes are chained through a single per-user
authenticated listener on the tebi gateway (dialer-proxy overlay). Every
client connection therefore enters mihomo with metadata.inboundUser = the
subscriber's username, which this worker aggregates into byte deltas and
reports to the site's existing /ingest/traffic endpoint.

Accounting semantics (IMPORTANT):
  mihomo's /connections reports only ACTIVE connections, with cumulative
  upload/download per connection id. We keep a per-id high-water mark and
  report the positive delta each tick. A connection that opens AND closes
  entirely between two ticks is invisible -> its bytes are not counted. With
  a 10s tick and proxy sessions that normally outlive seconds, the loss is
  small; this is a quota approximation, not a billing-grade counter. Never
  report a negative delta (counter reset / id reuse) and drop stale ids to
  bound state memory.

Security: controller secret and node token are read from files/env, never
logged. Only usernames and byte counts cross the wire to the site.
"""
from __future__ import annotations

import argparse
import json
import os
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path
from typing import Dict


def read_secret(path: Path) -> str:
    return path.read_text(encoding='utf-8').strip()


def controller_connections(api_base: str, secret: str, timeout: int = 20) -> list:
    req = urllib.request.Request(
        api_base.rstrip('/') + '/connections',
        headers={'Authorization': 'Bearer ' + secret},
        method='GET')
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        data = json.loads(resp.read().decode('utf-8'))
    conns = data.get('connections')
    return conns if isinstance(conns, list) else []


def apply_deltas(prev: Dict[str, int], conns: list, inbound_name: str,
                 stale_after: int) -> tuple:
    """Compute per-user byte deltas from the connection snapshot.

    Returns ({user: {'up','down'}}, new_state). `prev` maps connection id ->
    (upload, download, last_seen_ts). Only connections on `inbound_name` with
    a non-empty inboundUser are counted; everyone else is ignored.
    """
    now = int(time.time())
    out: Dict[str, dict] = {}
    state: Dict[str, tuple] = {}
    for c in conns:
        if not isinstance(c, dict):
            continue
        meta = c.get('metadata') or {}
        if str(meta.get('inboundName') or '') != inbound_name:
            continue
        user = str(meta.get('inboundUser') or '').strip().lower()
        if not user:
            continue
        try:
            cid = str(c['id'])
            up = max(0, int(c.get('upload') or 0))
            down = max(0, int(c.get('download') or 0))
        except (KeyError, TypeError, ValueError):
            continue
        old = prev.get(cid)
        du = dd = 0
        if old is not None:
            du = max(0, up - int(old[0]))
            dd = max(0, down - int(old[1]))
        state[cid] = (up, down, now)
        if du or dd:
            slot = out.setdefault(user, {'up': 0, 'down': 0})
            slot['up'] += du
            slot['down'] += dd
    # keep ids seen within the stale window so a brief API blip does not
    # re-count the whole connection as new on the next tick
    for cid, (u, d, seen) in prev.items():
        if cid not in state and now - int(seen) <= stale_after:
            state[cid] = (u, d, int(seen))
    return out, state


def post_ingest(url: str, node: str, token: str, updates: dict,
                timeout: int = 20) -> dict:
    if not updates:
        return {'ok': True, 'accepted': 0}
    body = json.dumps({
        'node': node,
        'updates': [{'user': u, 'up': v['up'], 'down': v['down']}
                    for u, v in sorted(updates.items())],
    }).encode('utf-8')
    req = urllib.request.Request(
        url, data=body, method='POST',
        headers={'Authorization': 'Bearer ' + token,
                 'Content-Type': 'application/json'})
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return json.loads(resp.read().decode('utf-8'))


def load_state(path: Path) -> Dict[str, tuple]:
    try:
        data = json.loads(path.read_text(encoding='utf-8'))
    except (OSError, ValueError):
        return {}
    if not isinstance(data, dict):
        return {}
    out: Dict[str, tuple] = {}
    for cid, v in data.items():
        if isinstance(v, list) and len(v) == 3:
            try:
                out[str(cid)] = (int(v[0]), int(v[1]), int(v[2]))
            except (TypeError, ValueError):
                pass
    return out


def save_state(path: Path, state: Dict[str, tuple]) -> None:
    tmp = path.with_suffix(path.suffix + '.tmp')
    tmp.write_text(json.dumps(state, ensure_ascii=False), encoding='utf-8')
    os.replace(tmp, path)


def run_once(cfg: dict) -> None:
    api = cfg['api']
    secret = read_secret(Path(cfg['secret_file']))
    token = read_secret(Path(cfg['token_file']))
    conns = controller_connections(api, secret, timeout=cfg['timeout'])
    path = Path(cfg['state_file'])
    prev = load_state(path)
    updates, state = apply_deltas(
        prev, conns, cfg['inbound_name'], stale_after=cfg['stale_after'])
    if updates:
        result = post_ingest(cfg['ingest_url'], cfg['node'], token,
                             updates, timeout=cfg['timeout'])
        sys.stderr.write('relay-meter %s report users=%d result=%s\n' % (
            time.strftime('%F %T'), len(updates), json.dumps(result)))
    save_state(path, state)


def config_from_env() -> dict:
    return {
        'api': os.environ.get('RELAY_API', 'http://127.0.0.1:9090'),
        'secret_file': os.environ['RELAY_CONTROLLER_SECRET'],
        'token_file': os.environ['RELAY_NODE_TOKEN_FILE'],
        'ingest_url': os.environ.get(
            'RELAY_INGEST_URL', 'http://127.0.0.1:2054/ingest/traffic'),
        'node': os.environ.get('RELAY_NODE_NAME', 'tebi-relay'),
        'inbound_name': os.environ.get('RELAY_INBOUND_NAME', 'MANGO-RELAY'),
        'state_file': os.environ.get(
            'RELAY_STATE_FILE', '/personal/sub-share/relay-meter-state.json'),
        'timeout': int(os.environ.get('RELAY_TIMEOUT', '20')),
        'stale_after': int(os.environ.get('RELAY_STALE_AFTER', '60')),
    }


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--once', action='store_true', help='one sampling tick')
    ap.add_argument('--interval', type=int, default=10, metavar='SEC',
                    help='polling interval (default 10s)')
    args = ap.parse_args()
    cfg = config_from_env()
    if args.once:
        run_once(cfg)
        return 0
    sys.stderr.write('relay-meter loop every %ss -> %s inbound=%s\n' % (
        args.interval, cfg['ingest_url'], cfg['inbound_name']))
    while True:
        started = time.time()
        try:
            run_once(cfg)
        except Exception as exc:  # noqa: BLE001 - never let a tick kill the loop
            sys.stderr.write('relay-meter tick error: %r\n' % (exc,))
        time.sleep(max(1, args.interval - (time.time() - started)))


if __name__ == '__main__':
    sys.exit(main())
