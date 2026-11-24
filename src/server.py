#!/usr/bin/env python3
"""Public subscription server for mango-share.

GET/HEAD /sub/<token>  -> sanitized Clash YAML (ETag/304, stale flag)
GET      /info/<token> -> JSON meta (node count, render rev, timestamps)

- Tokens: sha256-only store (tokens.py); wrong/missing token = 401 with
  constant-time compare and a small delay to blunt brute force.
- Never proxies to the gateway; only reads the public render output.
- Re-renders on demand when the source file changed (idempotent renderer).
"""

from __future__ import annotations

import hashlib
import hmac
import json
import math
import os
import re
import sys
import threading
import time
import traceback
from collections import OrderedDict
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any, Dict, Optional
from urllib.parse import parse_qs, quote, urlsplit

sys.path.insert(0, str(Path(__file__).resolve().parent))
import clients
import pages
import format_converters as fmtconv
import node_pool
import render_public
import share_constants as const
from share_constants import clash_dir
import tokens as token_store
import users


def _normalize_gateway_proxies(data: dict) -> list:
    """Clash /proxies payload -> node rows for the status page. Group/
    infrastructure types are filtered; addresses are never included (the
    API does not expose server/uuid)."""
    proxies = data.get('proxies') or {}
    nodes: list = []
    for name, info in proxies.items():
        ptype = str(info.get('type') or '')
        if ptype.lower() in _GATEWAY_GROUP_TYPES:
            continue
        hist = info.get('history') or []
        delay = None
        if hist and isinstance(hist[-1].get('delay'), int):
            delay = int(hist[-1]['delay'])
        nodes.append({
            'name': str(name),
            'type': ptype,
            'udp': bool(info.get('udp')),
            'alive': bool(info.get('alive', delay is not None)),
            'delay': delay,
            'checkedAt': (hist[-1] or {}).get('time') if hist else None,
        })
    nodes.sort(key=lambda n: (
        n['delay'] is None,
        n['delay'] if n['delay'] is not None else 1 << 30,
        n['name'].lower()))
    return nodes


class ShareState:
    def __init__(self) -> None:
        self.paths = render_public.default_paths()
        self.last_inputs_sha: str = ''
        self.last_meta: dict = {}
        self._render_lock = threading.Lock()
        # per-user render memo: uid -> (inputs sha, sha256 of output)
        self.user_renders: Dict[str, tuple] = {}
        self._user_render_lock = threading.Lock()
        self.pool = node_pool.NodePool(self.paths['pool'], self.paths['pool_dead'])

    def _hash_inputs(self, h) -> None:
        """Feed every render input into `h`. share-nodes.json, exclude.json
        and pool-dead.json are optional (render reads a missing one as empty), so a
        fresh install without them must still render; the source pool is
        mandatory and its absence raises."""
        for key in ('source', 'share_nodes', 'exclude', 'pool_dead'):
            try:
                data = self.paths[key].read_bytes()
            except FileNotFoundError:
                if key == 'source':
                    raise
                data = b'\0missing'
            h.update(hashlib.sha256(data).digest())

    def _inputs_sha(self) -> str:
        """Fingerprint every render input, not just the source pool, so
        share-nodes.json / exclude.json edits take effect without a restart."""
        h = hashlib.sha256()
        self._hash_inputs(h)
        return h.hexdigest()

    def _node_cred_map(self) -> list:
        """node-credentials.json: [{node: <pool node name>, key: <credential
        key>, type: vless|tuic|anytls}] mapping shared pool nodes to the
        per-user credential keys assigned during rollout. Empty/missing file
        = per-user rendering has nothing to substitute."""
        p = self.paths['state'] / 'node-credentials.json'
        try:
            data = json.loads(p.read_text(encoding='utf-8'))
            return data if isinstance(data, list) else []
        except (OSError, ValueError):
            return []

    def ensure_user_fresh(self, user: dict) -> tuple:
        """Render (or reuse) the per-user YAML; returns (path, sha256).
        Fingerprint covers every render input plus the user's own
        credentials, so a credential rotation re-renders immediately."""
        uid = str(user['id'])
        creds = user.get('credentials') or {}
        cred_map = self._node_cred_map()
        h = hashlib.sha256()
        self._hash_inputs(h)
        h.update(hashlib.sha256(
            json.dumps({'c': creds, 'm': cred_map}, sort_keys=True,
                       ensure_ascii=False).encode('utf-8')).digest())
        sha_in = h.hexdigest()
        memo = self.user_renders.get(uid)
        out_path = self.paths['out'].parent / f'users/{uid}.yaml'
        if memo and memo[0] == sha_in and out_path.exists():
            return out_path, memo[1]
        with self._user_render_lock:
            memo = self.user_renders.get(uid)
            if memo and memo[0] == sha_in and out_path.exists():
                return out_path, memo[1]
            other_secrets = []
            for r in users.load(users.users_file()):
                if str(r.get('id')) == uid:
                    continue
                for c in (r.get('credentials') or {}).values():
                    if isinstance(c, dict) and c.get('uuid'):
                        other_secrets.append(str(c['uuid']))
            meta = render_public.render_user(
                self.paths['source'], self.paths['share_nodes'],
                self.paths['exclude'], out_path, None,
                user=user, cred_map=cred_map, other_secrets=other_secrets,
                pool_dead_path=self.paths['pool_dead'])
            self.user_renders[uid] = (sha_in, meta['sha256'])
            return out_path, meta['sha256']

    def gateway_nodes(self) -> tuple:
        """Node rows for /nodes from the self-maintained pool (verdicts come
        from our own probes through the gateway, see node_pool):
        [{name,type,udp,status,alive,delay,checkedAt,fails,since}]. No
        server/uuid ever leaves. ([], error) while the pool has no verdicts."""
        snap = self.pool.snapshot()
        info = {n['name']: n for n in _export_nodes(self.paths['source'])}
        rows = []
        for name, rec in snap.items():
            status = rec['status']
            if status != node_pool.UNMANAGED and not rec.get('probed'):
                status = 'pending'
            meta = info.get(name, {})
            last = rec.get('last_probe')
            rows.append({
                'name': name,
                'type': meta.get('type', ''),
                'udp': bool(meta.get('udp')),
                'status': status,
                'alive': status == node_pool.ALIVE,
                'delay': (rec.get('delay') if status in (node_pool.ALIVE, node_pool.SUSPECT)
                          and not rec.get('fails') else None),
                'checkedAt': (time.strftime('%Y-%m-%dT%H:%M:%S%z', time.localtime(last))
                              if last else None),
                'fails': int(rec.get('fails') or 0),
                'since': int(rec.get('since') or 0),
            })
        order = {node_pool.ALIVE: 0, node_pool.SUSPECT: 1, 'pending': 2,
                 node_pool.UNMANAGED: 3, node_pool.DEAD: 4}
        rows.sort(key=lambda n: (order.get(n['status'], 5),
                                 n['delay'] if n['delay'] is not None else 1 << 30,
                                 n['name'].lower()))
        err = self.pool.last_error
        if not any(r['status'] != 'pending' for r in rows):
            return [], err or 'node pool warming up'
        return rows, err

    def ensure_fresh(self) -> dict:
        """Re-render when any input changed. Serialized by a lock: concurrent
        requests must not race two renders. Raises on failure (caller serves
        last-good)."""
        with self._render_lock:
            inputs_sha = self._inputs_sha()
            if inputs_sha != self.last_inputs_sha or not self.paths['out'].exists():
                meta = render_public.render(
                    self.paths['source'], self.paths['share_nodes'],
                    self.paths['exclude'], self.paths['out'], self.paths['meta'],
                    pool_dead_path=self.paths['pool_dead'],
                )
                self.last_inputs_sha = inputs_sha
                self.last_meta = meta
            if not self.last_meta:
                try:
                    self.last_meta = json.loads(self.paths['meta'].read_text(encoding='utf-8'))
                except Exception:
                    self.last_meta = {}
            return self.last_meta


STATE = ShareState()


def _csv_cell(value) -> str:
    """Neutralise spreadsheet formula injection: audit fields carry
    user-controlled text (usernames, login attempts), and a cell starting
    with = + - @ (or tab/CR) is executed by Excel/Sheets on open."""
    text = '' if value is None else str(value)
    if text and text[0] in '=+-@\t\r':
        return "'" + text
    return text

# fmt conversion memo: (sha256(body), fmt, managed_url) -> bytes, LRU-bounded
_CONVERT_CACHE: 'OrderedDict[tuple, bytes]' = OrderedDict()
_CONVERT_CACHE_MAX = 16
_CONVERT_LOCK = threading.Lock()

# Gateway controller (mihomo): probes for the node pool. Secret file is
# group-readable by the service user.
_GATEWAY_API = os.environ.get('SHARE_GATEWAY_API', 'http://127.0.0.1:9090')
_GATEWAY_SECRET_FILE = os.environ.get(
    'SHARE_GATEWAY_SECRET', str(clash_dir() / '.controller-secret'))
_GATEWAY_GROUP_TYPES = {'selector', 'urltest', 'fallback', 'loadbalance',
                        'relay', 'direct', 'reject', 'rejectdrop',
                        'compatible', 'pass', 'passrule', 'dns'}
# Node pool worker: every export node is probed through the controller's
# delay API (the gateway dials relay-chained nodes through their relay, so a
# verdict means "works through our clash"); node_pool keeps the state
# machine and writes pool-dead.json, which the renderer drops.
_GATEWAY_PROBE_URL = 'http://www.gstatic.com/generate_204'
_GATEWAY_PROBE_TIMEOUT_MS = 5000
_POOL_TICK = 30                 # seconds between worker passes
_POOL_BATCH = 40                # due nodes probed per pass (stalest first)
_POOL_WORKERS = 4               # low fan-out: a wide burst misfires
_POOL_MANAGED_TTL = 300         # gateway /proxies name list cache
_POOL_MANAGED: Dict[str, Any] = {'ts': 0.0, 'names': None}
_EXPORT_CACHE: Dict[str, Any] = {'key': None, 'nodes': []}
_EXPORT_LOCK = threading.Lock()


def _export_nodes(source: Path) -> list:
    """[{name,type,udp}] of the client export (what subscribers receive),
    minus loop-guard / fake rows; cached on (mtime, size)."""
    try:
        st = source.stat()
    except OSError:
        return []
    key = (st.st_mtime_ns, st.st_size)
    with _EXPORT_LOCK:
        if _EXPORT_CACHE['key'] == key:
            return list(_EXPORT_CACHE['nodes'])
    try:
        import yaml
        doc = yaml.safe_load(source.read_text(encoding='utf-8')) or {}
        picked = render_public.select_nodes_full(doc.get('proxies') or [], [])
    except Exception as e:
        sys.stderr.write(f'mango-share export parse failed: {e!r}\n')
        return []
    nodes = [{'name': str(p['name']), 'type': str(p.get('type') or ''),
              'udp': bool(p.get('udp'))} for p in picked]
    with _EXPORT_LOCK:
        _EXPORT_CACHE.update(key=key, nodes=nodes)
    return list(nodes)


def _gateway_secret() -> str:
    return Path(_GATEWAY_SECRET_FILE).read_text(encoding='utf-8').strip()


def _gateway_managed(now: Optional[float] = None) -> Optional[set]:
    """Proxy names the gateway has loaded (probe-able); None = unreachable."""
    import urllib.request
    now = time.time() if now is None else now
    if (_POOL_MANAGED['names'] is not None
            and now - float(_POOL_MANAGED['ts']) < _POOL_MANAGED_TTL):
        return _POOL_MANAGED['names']
    try:
        req = urllib.request.Request(
            _GATEWAY_API.rstrip('/') + '/proxies',
            headers={'Authorization': f'Bearer {_gateway_secret()}',
                     'User-Agent': 'mango-share/1'})
        with urllib.request.urlopen(req, timeout=5) as resp:
            data = json.loads(resp.read().decode('utf-8', 'replace'))
    except Exception as e:
        # detail to the log only: exception text can carry the controller URL
        sys.stderr.write(f'mango-share gateway fetch failed: {e!r}\n')
        return None
    names = {n['name'] for n in _normalize_gateway_proxies(data)}
    _POOL_MANAGED.update(ts=now, names=names)
    return names


def _probe_delay(name: str, secret: str) -> tuple:
    """One delay test via the controller -> (outcome, delay_ms).
    ok: 200 with a positive delay; fail: the controller says the node timed
    out / errored (504/503); error: anything that is OUR side (controller
    unreachable, auth, unknown name) - errors never count against a node."""
    import urllib.error
    import urllib.parse
    import urllib.request
    q = urllib.parse.quote(name, safe='')
    url = (_GATEWAY_API.rstrip('/') + '/proxies/' + q + '/delay'
           '?timeout=%d&url=%s'
           % (_GATEWAY_PROBE_TIMEOUT_MS,
              urllib.parse.quote(_GATEWAY_PROBE_URL, safe='')))
    req = urllib.request.Request(
        url, headers={'Authorization': 'Bearer ' + secret,
                      'User-Agent': 'mango-share/1'})
    try:
        with urllib.request.urlopen(
                req, timeout=_GATEWAY_PROBE_TIMEOUT_MS / 1000 + 3) as resp:
            data = json.loads(resp.read().decode('utf-8', 'replace'))
        delay = data.get('delay')
        if isinstance(delay, int) and delay > 0:
            return node_pool.OK, delay
        return node_pool.FAIL, None
    except urllib.error.HTTPError as e:
        e.close()
        return (node_pool.FAIL, None) if e.code in (503, 504) else (node_pool.ERROR, None)
    except Exception:
        return node_pool.ERROR, None


def _probe_node(name: str) -> tuple:
    """A failure must be confirmed by a second attempt (single timeouts are
    common under load); errors are returned as-is."""
    try:
        secret = _gateway_secret()
    except OSError:
        return node_pool.ERROR, None
    outcome, delay = _probe_delay(name, secret)
    if outcome == node_pool.FAIL:
        outcome, delay = _probe_delay(name, secret)
    return outcome, delay


def pool_tick(now: Optional[float] = None) -> list:
    """One worker pass: sync membership with the export, probe due nodes,
    re-render when the dead set moved. Returns the status changes."""
    pool = STATE.pool
    names = [n['name'] for n in _export_nodes(STATE.paths['source'])]
    if not names:
        return []
    managed = _gateway_managed(now)
    pool.sync(names, managed, now)
    if managed is None:
        pool.last_error = 'gateway unreachable'
        pool.save()
        return []
    changes = pool.run_round(_probe_node, now=now, limit=_POOL_BATCH,
                             workers=_POOL_WORKERS)
    for name, old, new in changes:
        print(f'mango-share pool: {name} {old} -> {new}', flush=True)
    if any(node_pool.DEAD in (old, new) for _, old, new in changes):
        try:
            STATE.ensure_fresh()
        except Exception as e:
            sys.stderr.write(f'mango-share re-render after pool change failed: {e!r}\n')
    return changes


def _pool_loop() -> None:
    while True:
        try:
            pool_tick()
        except Exception:
            traceback.print_exc()
        time.sleep(_POOL_TICK)


def start_pool_worker() -> None:
    threading.Thread(target=_pool_loop, name='node-pool', daemon=True).start()


# Client download mirror: manifest published by scripts/client-mirror.py on
# the download site. Unset URL = no mirror, /clients links GitHub only.
CLIENTS = clients.ManifestCache(os.environ.get('SHARE_CLIENTS_MANIFEST_URL', ''),
                                const.state_dir() / 'clients-manifest.json')


def _clients_loop() -> None:
    while True:
        try:
            CLIENTS.refresh()
        except Exception:
            traceback.print_exc()
        time.sleep(CLIENTS.ttl)


def start_clients_worker() -> None:
    if CLIENTS.enabled:
        threading.Thread(target=_clients_loop, name='clients-manifest', daemon=True).start()

# Landing-page region badges, keyed by the rendered output's sha256.
_REGIONS_CACHE: Dict[str, Any] = {'sha': '', 'regions': []}
_REGIONS_CACHE_LOCK = threading.Lock()

# Phase-2 switch: serve per-user rendered YAMLs (credential substitution).
# Off until the self-hosted nodes accept the per-user uuids (rollout SOP in
# scripts/node-agent/README.md); with the flag off, everyone gets the global
# render exactly as before.
PER_USER_YAML = os.environ.get('SHARE_PER_USER_YAML', '') == '1'

_STARTED_AT = time.time()

# Whole-site CSP: every asset is same-origin (brand PNG, inline style/script
# for the self-contained SSR pages), no third-party anything by design.
_CSP = ("default-src 'self'; script-src 'self' 'unsafe-inline'; "
        "style-src 'self' 'unsafe-inline'; img-src 'self' data:; "
        "connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; "
        "form-action 'self'")


def _html_security_headers() -> list:
    """Headers for HTML faces (defense-in-depth on top of the fully
    self-contained pages: no framing, no referrer leak, no sniffing)."""
    return [('Content-Security-Policy', _CSP),
            ('X-Frame-Options', 'DENY'),
            ('Referrer-Policy', 'no-referrer')]


def constant_delay() -> None:
    time.sleep(0.5)


class Handler(BaseHTTPRequestHandler):
    server_version = 'mango-share/1'
    protocol_version = 'HTTP/1.1'
    # Socket timeout: a client that stalls mid-request (or idles on a
    # keep-alive connection) must not pin a server thread forever.
    timeout = 30

    _TOKEN_IN_PATH = re.compile(r'(/(?:sub|info)/)[^?\s]+')

    def log_request(self, code: int | str = '-', size: int | str = '-') -> None:  # noqa: N802
        # Default log_request logs the request line, which carries the full
        # token. Redact it; keep only the first 4 chars for correlation.
        # parse_request can fail before self.path is set (non-HTTP probes);
        # fall back to '-' instead of raising and killing the handler thread.
        raw = getattr(self, 'path', '-') or '-'
        command = getattr(self, 'command', '-')
        path = urlsplit(raw).path
        redacted = self._TOKEN_IN_PATH.sub(
            lambda mm: mm.group(1) + (path[len(mm.group(1)):len(mm.group(1)) + 4] + '…' if len(path) > len(mm.group(1)) else ''),
            path,
        )
        sys.stderr.write('%s mango-share %s %s %s\n' % (
            time.strftime('%Y-%m-%dT%H:%M:%S'), command, redacted, code))

    def log_message(self, fmt: str, *args) -> None:  # noqa: N802
        # Fallback path: BaseHTTPRequestHandler sends arbitrary format strings
        # here (e.g. send_error). Nothing in them may contain a full token
        # because the token only ever appears in the URL path, which we never
        # pass through unredacted.
        msg = fmt % args
        if msg.startswith('Request timed out'):
            return  # idle keep-alive socket hitting `timeout`: not an error
        # send_error() may echo the request line: redact tokens here too.
        msg = self._TOKEN_IN_PATH.sub(lambda mm: mm.group(1) + '…', msg)
        sys.stderr.write('%s mango-share %s\n' % (time.strftime('%Y-%m-%dT%H:%M:%S'), msg))

    def _token(self) -> str:
        parts = urlsplit(self.path).path.split('/')
        return parts[-1] if len(parts) >= 3 else ''

    def _authorized(self) -> bool:
        token = self._token()
        rec = token_store.verify(token_store.token_file(), token)
        if rec is None:
            constant_delay()
            return False
        self._rec = rec
        return True

    def _send(self, code: int, body: bytes = b'', ctype: str = 'application/json',
              headers: dict | list | None = None) -> None:
        self.send_response(code)
        self.send_header('Content-Type', ctype)
        self.send_header('X-Content-Type-Options', 'nosniff')
        # Invite-only site: no page or subscription body belongs in a search
        # index (the edge-managed robots.txt allows search crawlers).
        self.send_header('X-Robots-Tag', 'noindex, nofollow, noarchive')
        items = (headers or {}).items() if isinstance(headers, dict) else (headers or [])
        for k, v in items:
            self.send_header(k, v)
        self.send_header('Content-Length', str(len(body)))
        self.end_headers()
        if body and self.command != 'HEAD':
            self.wfile.write(body)

    def do_GET(self) -> None:  # noqa: N802
        self.do_HEAD()

    def do_HEAD(self) -> None:  # noqa: N802
        path = urlsplit(self.path).path
        try:
            if path == '/sub/download':
                self._serve_sub_download()
            elif path == '/sub/export':
                self._serve_sub_export()
            elif path.startswith('/sub/'):
                self._serve_sub()
            elif path.startswith('/info/'):
                self._serve_info()
            elif path in ('/brand/mango-connect-mark.png', '/favicon.ico'):
                self._serve_brand_asset()
            elif path == '/health':
                self._serve_health()
            elif path == '/login':
                self._serve_login()
            elif path == '/dashboard':
                self._serve_dashboard()
            elif path == '/admin':
                self._serve_admin()
            elif path == '/nodes':
                self._serve_nodes()
            elif path == '/docs':
                self._serve_docs()
            elif path == '/clients':
                self._serve_clients()
            elif path == '/nodes/api':
                self._serve_nodes_api()
            elif path == '/admin/audit':
                self._serve_admin_audit()
            elif path == '/admin/audit/export':
                self._serve_admin_audit(export=True)
            elif path == '/' or path == '/index.html':
                self._serve_home()
            else:
                self._send(404, b'{"error":"not found"}')
        except Exception:  # noqa: BLE001 - last line of defense
            self._internal_error()

    def do_POST(self) -> None:  # noqa: N802
        path = urlsplit(self.path).path
        try:
            limit = 256 * 1024 if path == '/ingest/traffic' else 4096
            try:
                length = int(self.headers.get('Content-Length') or 0)
            except ValueError:
                self.close_connection = True
                self._send(400, b'{"error":"bad content-length"}')
                return
            if self.headers.get('Transfer-Encoding'):
                # Chunked bodies are never read here; leaving them on the
                # socket would desync the keep-alive stream.
                self.close_connection = True
                self._send(411, b'{"error":"length required"}')
                return
            if length < 0 or length > limit:
                err = b'{"error":"payload too large"}' if length > limit \
                    else b'{"error":"bad content-length"}'
                self.close_connection = True  # unread body stays on the socket
                self._send(413 if length > limit else 400, err)
                return
            raw = self.rfile.read(length) if length else b''
            if path == '/ingest/traffic':
                self._post_ingest(raw)
                return
            form = parse_qs(raw.decode('utf-8', 'replace'), keep_blank_values=True)
            if path == '/login':
                self._post_login(form)
            elif path == '/logout':
                self._post_logout(form)
            elif path == '/dashboard/password':
                self._post_dashboard_password(form)
            elif path == '/dashboard/regen-token':
                self._post_dashboard_regen(form)
            elif path == '/admin/users':
                self._post_admin_create(form)
            elif re.match(r'^/admin/users/[^/]+/action$', path):
                uid = path.rstrip('/').rsplit('/', 2)[1]
                self._post_admin_action(uid, form)
            else:
                self._send(404, b'{"error":"not found"}')
        except Exception:  # noqa: BLE001 - last line of defense
            self._internal_error()

    def _internal_error(self) -> None:
        """Unhandled failure: full traceback to the server log, a generic
        body to the (public) client - exception text carries internal paths
        and state that must not leave the box."""
        sys.stderr.write('mango-share ERROR %s %s\n%s' % (
            getattr(self, 'command', '-'),
            self._TOKEN_IN_PATH.sub(r'\1…', urlsplit(getattr(self, 'path', '') or '').path),
            traceback.format_exc()))
        try:
            self._send(500, b'{"error":"internal server error"}')
        except OSError:
            pass  # client already gone

    _BRAND_ASSET = Path(__file__).resolve().parent.parent / 'assets/brand/mango-connect-mark.png'

    def _serve_brand_asset(self) -> None:
        try:
            body = self._BRAND_ASSET.read_bytes()
        except OSError:
            self._send(404, b'{"error":"not found"}')
            return
        self._send(200, body, ctype='image/png',
                   headers={'Cache-Control': 'public, max-age=86400, immutable'})

    # ------------------------------------------------------------- sessions
    # Cookie-based accounts for the dashboard/admin faces. The subscription
    # endpoints stay token-in-URL (client apps cannot log in); sessions only
    # gate the human pages. Both cookies are HttpOnly: forms are server-
    # rendered with the CSRF value read from the request cookie.

    def _cookies(self) -> dict:
        out = {}
        for part in (self.headers.get('Cookie') or '').split(';'):
            if '=' in part:
                k, v = part.split('=', 1)
                out[k.strip()] = v.strip()
        return out

    def _secure_cookies(self) -> bool:
        # cloudflared sets X-Forwarded-Proto on the public ingress; local
        # previews (plain http) must not mark cookies Secure.
        return (self.headers.get('X-Forwarded-Proto') or '') == 'https'

    def _cookie_header(self, name: str, value: str, max_age: int) -> str:
        parts = [f'{name}={value}', 'Path=/', f'Max-Age={max_age}', 'SameSite=Lax', 'HttpOnly']
        if self._secure_cookies():
            parts.append('Secure')
        return '; '.join(parts)

    def _client_ip(self) -> str:
        # CF-Connecting-IP is set by the Cloudflare edge and arrives via the
        # local tunnel daemon, i.e. from a loopback peer. A direct (non-
        # loopback) peer could forge it to dodge rate limits, so only trust
        # it from loopback. X-Forwarded-For is never consulted.
        peer = self.client_address[0] if self.client_address else ''
        if peer in ('127.0.0.1', '::1') or peer.startswith('127.'):
            cip = (self.headers.get('CF-Connecting-IP') or '').strip()
            if cip:
                return cip[:64]
        return peer

    def _current_user(self) -> dict | None:
        self._session_payload = None
        tok = self._cookies().get(users.SESSION_COOKIE, '')
        if not tok:
            return None
        try:
            secret = users.load_secret()
            payload = users.read_session(secret, tok)
        except OSError:
            return None
        if not payload:
            return None
        records = users.load(users.users_file())
        rec = users.find_by_id(records, payload.get('uid'))
        if rec is None:
            return None
        # A password change bumps session_epoch; sessions issued before the
        # bump die here even though their HMAC is still valid.
        if int(payload.get('e', 0) or 0) != int(rec.get('session_epoch', 0) or 0):
            return None
        if rec.get('status') == 'disabled':
            return None  # disabled covers the web face, not just /sub
        self._session_payload = payload
        return rec

    def _slide_session_cookie(self, user: dict) -> tuple | None:
        """Sliding expiry: when less than half the session TTL remains,
        re-issue the cookie so an actively-used session is never logged out
        mid-usage. Returns a Set-Cookie header or None."""
        payload = getattr(self, '_session_payload', None)
        if not payload:
            return None
        if not users.session_needs_slide(payload):
            return None
        session = users.issue_session(
            users.load_secret(), user['id'],
            ttl=users.SESSION_TTL,
            epoch=int(user.get('session_epoch', 0) or 0))
        return self._cookie_header(users.SESSION_COOKIE, session,
                                   users.SESSION_TTL)

    def _csrf_pair(self) -> tuple:
        """(csrf_token, set_cookie_header_or_None). Reuse the browser's token
        so forms rendered earlier still validate on submit."""
        tok = self._cookies().get(users.CSRF_COOKIE, '')
        if tok:
            return tok, None
        tok = users.new_csrf_token()
        return tok, self._cookie_header(users.CSRF_COOKIE, tok, users.CSRF_TTL)

    def _csrf_ok(self, form: dict) -> bool:
        cookie = self._cookies().get(users.CSRF_COOKIE, '')
        field = (form.get('csrf') or [''])[0]
        return bool(cookie) and bool(field) and hmac.compare_digest(cookie, field)

    @staticmethod
    def _field(form: dict, name: str) -> str:
        return (form.get(name) or [''])[0]

    @staticmethod
    def _num(raw: str, default: float, hi: float) -> float:
        """Admin numeric field: blank -> default; non-finite ('inf', 'nan')
        or absurdly large values raise ValueError instead of overflowing in
        int() further down (that used to surface as a 500)."""
        raw = (raw or '').strip()
        if not raw:
            return default
        v = float(raw)
        if not math.isfinite(v) or abs(v) > hi:
            raise ValueError('数值超出范围')
        return v

    def _redirect(self, location: str, extra: list | None = None) -> None:
        headers = [('Location', location)] + (extra or [])
        self._send(303, b'', headers=headers)

    def _audit(self, actor: str, action: str, **detail) -> None:
        """Append the admin/account action to the append-only audit trail.
        Values logged here must never include passwords or tokens."""
        try:
            users.append_audit({'actor': actor, 'ip': self._client_ip(),
                                'action': action, **detail})
        except OSError:
            pass

    def _serve_admin_audit(self, export: bool = False) -> None:
        user = self._current_user()
        if user is None:
            self._redirect('/login')
            return
        if user.get('role') != 'admin':
            self._redirect('/dashboard?err=' + quote('仅管理员可访问审计页'))
            return
        tok, setc = self._csrf_pair()
        query = parse_qs(urlsplit(self.path).query)
        q = (query.get('q') or [''])[0].strip().lower()
        entries: list = []
        log_path = users.audit_file()
        if log_path.exists():
            for line in log_path.read_text(encoding='utf-8').splitlines():
                try:
                    e = json.loads(line)
                except ValueError:
                    continue
                if q and q not in json.dumps(e, ensure_ascii=False).lower():
                    continue
                entries.append(e)
        entries.reverse()  # newest first
        if export:
            import csv as _csv
            import io as _io
            buf = _io.StringIO()
            w = _csv.writer(buf)
            w.writerow(['time', 'actor', 'action', 'target', 'ip', 'detail'])
            for e in entries[:2000]:
                detail = {k: v for k, v in e.items()
                          if k not in ('at', 'actor', 'action', 'target', 'ip')}
                w.writerow([_csv_cell(c) for c in (
                    time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(e.get('at', 0))),
                    e.get('actor', ''), e.get('action', ''), e.get('target', ''),
                    e.get('ip', ''), json.dumps(detail, ensure_ascii=False))])
            self._send(200, buf.getvalue().encode('utf-8'),
                       ctype='text/csv; charset=utf-8',
                       headers=[('Content-Disposition', 'attachment; filename=audit.csv'),
                                ('Cache-Control', 'no-store')])
            return
        html_body = pages.audit_page(entries[:500], q, logout_csrf=tok)
        headers = self._page_headers(self._slide_session_cookie(user), setc)
        self._send(200, html_body.encode('utf-8'), ctype='text/html; charset=utf-8',
                   headers=headers)

    def _page_headers(self, *setcs: str | None) -> list:
        """Common response headers for the authed HTML faces. Every non-empty
        Set-Cookie is emitted: a sliding session re-issue must not swallow a
        freshly minted CSRF cookie (the next form post would then 403)."""
        headers = [('Cache-Control', 'no-store'), *_html_security_headers()]
        for c in setcs:
            if c:
                headers.append(('Set-Cookie', c))
        return headers

    def _export_url(self, user: dict, ttl: int = 30 * 86400) -> tuple:
        """Long-lived signed export URL (no long-term token inside). The
        signature binds the account's current token epoch, so rotating the
        subscription token instantly kills every link already copied into
        client apps - that revocability is what makes a 30-day window safe
        for one-click import (a 10-minute link silently stopped updating
        clients hours later, the exact failure mode this replaces)."""
        secret = users.load_secret()
        exp = int(time.time()) + ttl
        # token_id is the revocation generation: resetting the subscription
        # (which mints a new token_id) instantly kills every link already
        # copied into client apps. It is a non-secret record id, safe in a URL.
        generation = str(user.get('token_id') or '')
        sig = users.sign_export(secret, str(user['id']), exp, generation)
        return (f'/sub/export?u={quote(str(user["id"]))}&e={exp}'
                f'&k={quote(generation)}&s={sig}')

    def _user_yaml_bytes(self, user: dict) -> bytes:
        """The subscriber's rendered YAML (global mirror today; per-user
        file when SHARE_PER_USER_YAML is on)."""
        if PER_USER_YAML:
            try:
                cred_map = STATE._node_cred_map()
                provisioned = bool(cred_map) and any(
                    isinstance(m, dict)
                    and str(m.get('key')) in (user.get('credentials') or {})
                    for m in cred_map)
                if provisioned:
                    user_path, _ = STATE.ensure_user_fresh(user)
                    if user_path.exists():
                        return user_path.read_bytes()
            except Exception:
                pass
        try:
            STATE.ensure_fresh()
        except Exception:
            pass
        out = STATE.paths['out']
        return out.read_bytes() if out.exists() else b''

    def _serve_sub_download(self) -> None:
        user = self._current_user()
        if user is None:
            self._redirect('/login')
            return
        # Same service gate as /sub: 停发语义 covers config downloads too.
        _, ok, reason = users.refresh_and_check(users.users_file(), user)
        if not ok:
            self._redirect('/dashboard?err=' + quote(reason))
            return
        qs = parse_qs(urlsplit(self.path).query)
        fmt = (qs.get('fmt') or ['clash'])[0].lower()
        body = self._convert_body(fmt, self._user_yaml_bytes(user))
        ctype, title_suffix = self._FMT_META.get(fmt, self._FMT_META['clash'])
        safe = re.sub(r'[^A-Za-z0-9_-]', '', str(user.get('username') or 'user')) or 'user'
        self._send(200, body, ctype=ctype,
                   headers=[('Content-Disposition',
                             f'attachment; filename=mango-connect-{safe}{title_suffix}'),
                            ('Cache-Control', 'no-store')])

    def _serve_sub_export(self) -> None:
        """Signed export for client one-click import links: no session
        cookie needed (client apps cannot log in), no long-term token in
        the URL. The signature binds (uid, exp, token_id); resetting the
        subscription mints a new token_id and instantly invalidates every
        previously distributed import link."""
        qs = parse_qs(urlsplit(self.path).query)
        uid = (qs.get('u') or [''])[0]
        exp = (qs.get('e') or ['0'])[0]
        generation = (qs.get('k') or [''])[0]
        sig = (qs.get('s') or [''])[0]
        try:
            secret = users.load_secret()
        except OSError:
            self._send(500, json.dumps({'error': 'server error'}).encode())
            return
        try:
            exp_i = int(exp or 0)
        except ValueError:
            exp_i = -1
        records = users.load(users.users_file())
        user = users.find_by_id(records, uid)
        if user is not None:
            # The account's CURRENT token_id is the revocation gate: a link
            # minted before a subscription reset carries a stale k and dies
            # here even inside its 30-day window.
            if not users.export_link_ok(secret, uid, exp_i, sig,
                                        generation=generation,
                                        current_generation=str(user.get('token_id') or '')):
                user = None  # fall through to the generic 401
        if user is None:
            constant_delay()
            self._send(401, json.dumps({'error': 'expired or invalid export link; '
                                                're-open the dashboard to get a fresh one'}).encode())
            return
        # Full service gate (status/expire/quota) - same semantics as /sub.
        _, ok, reason = users.refresh_and_check(users.users_file(), user)
        if not ok:
            self._send(401, json.dumps({'error': reason}).encode())
            return
        qs = parse_qs(urlsplit(self.path).query)
        fmt = (qs.get('fmt') or ['clash'])[0].lower()
        managed = f'{pages.public_host()}{self.path}' if fmt == 'surge' else None
        body = self._convert_body(fmt, self._user_yaml_bytes(user), managed_url=managed)
        ctype, title_suffix = self._FMT_META.get(fmt, self._FMT_META['clash'])
        safe = re.sub(r'[^A-Za-z0-9_-]', '', str(user.get('username') or 'user')) or 'user'
        headers = [('Content-Disposition',
                    f'attachment; filename=mango-connect-{safe}{title_suffix}'),
                   ('Cache-Control', 'private, no-store'),
                   ('profile-title', f'mango-connect-{safe}{title_suffix}'),
                   ('profile-update-interval', '6')]
        # Import links are what client apps poll: they need the quota/expiry
        # header just like /sub/<token>.
        userinfo = self._userinfo_header(user)
        if userinfo:
            headers.append(('subscription-userinfo', userinfo))
        self._send(200, body, ctype=ctype, headers=headers)

    def _serve_docs(self) -> None:
        user = self._current_user()
        if user is None:
            self._redirect('/login')
            return
        tok, setc = self._csrf_pair()
        html_body = pages.docs_page(role=str(user.get('role') or 'user'),
                                    logout_csrf=tok)
        headers = self._page_headers(self._slide_session_cookie(user), setc)
        self._send(200, html_body.encode('utf-8'), ctype='text/html; charset=utf-8',
                   headers=headers)

    def _serve_clients(self) -> None:
        """Client download page - members only, like /docs: the mirror
        links are not advertised to anonymous visitors."""
        user = self._current_user()
        if user is None:
            self._redirect('/login')
            return
        tok, setc = self._csrf_pair()
        html_body = pages.clients_page(CLIENTS.get(), mirror_enabled=CLIENTS.enabled,
                                       role=str(user.get('role') or 'user'), logout_csrf=tok,
                                       device=clients.detect_platform(self.headers.get('User-Agent', '')))
        headers = self._page_headers(self._slide_session_cookie(user), setc)
        self._send(200, html_body.encode('utf-8'), ctype='text/html; charset=utf-8',
                   headers=headers)

    def _serve_nodes(self) -> None:
        user = self._current_user()
        if user is None:
            self._redirect('/login')
            return
        tok, setc = self._csrf_pair()
        nodes, err = STATE.gateway_nodes()
        meta = STATE.last_meta or {}
        html_body = pages.nodes_page(nodes, err,
                                     active='nodes',
                                     role=str(user.get('role') or 'user'),
                                     logout_csrf=tok,
                                     aligned=meta.get('aligned'),
                                     aligned_at=str(meta.get('generated_at') or ''))
        headers = self._page_headers(self._slide_session_cookie(user), setc)
        self._send(200, html_body.encode('utf-8'), ctype='text/html; charset=utf-8',
                   headers=headers)

    def _serve_nodes_api(self) -> None:
        user = self._current_user()
        if user is None:
            self._send(401, json.dumps({'error': 'login required'}).encode())
            return
        nodes, err = STATE.gateway_nodes()
        if not nodes and err:
            self._send(503, json.dumps({'error': err}).encode())
            return
        counts = STATE.pool.counts()
        payload = {'ok': True, 'nodes': nodes,
                   'fetchedAt': int(time.time()),
                   'alive': counts[node_pool.ALIVE],
                   'counts': counts,
                   'lastRound': STATE.pool.last_round,
                   'error': err or None}
        self._send(200, json.dumps(payload, ensure_ascii=False).encode(),
                   headers=[('Cache-Control', 'no-store')])

    def _serve_health(self) -> None:
        """Unauthenticated liveness probe for supervisor/CF checks: public
        metadata only (node count is already on the homepage), no state."""
        count = 0
        try:
            meta = STATE.last_meta or json.loads(
                STATE.paths['meta'].read_text(encoding='utf-8'))
            count = int(meta.get('node_count') or 0)
        except Exception:
            pass
        payload = {'ok': True, 'service': 'mango-share', 'node_count': count,
                   'uptime_s': int(time.time() - _STARTED_AT),
                   'render_rev': const.RENDER_REV,
                   'share_scope': render_public.share_scope(),
                   'aligned_with_gateway': STATE.last_meta.get('aligned'),
                   'node_pool': STATE.pool.counts(),
                   'clients_mirror': {
                       'enabled': CLIENTS.enabled,
                       'apps': len(CLIENTS.get()['apps']),
                       'generated': int(CLIENTS.get()['generated']),
                       'error': CLIENTS.last_error},
                   'per_user_yaml': bool(PER_USER_YAML)}
        self._send(200, json.dumps(payload).encode(),
                   headers={'Cache-Control': 'no-store'})

    def _serve_login(self) -> None:
        if self._current_user():
            self._redirect('/dashboard')
            return
        tok, setc = self._csrf_pair()
        headers = [('Cache-Control', 'no-store'), *_html_security_headers()]
        if setc:
            headers.append(('Set-Cookie', setc))
        body = pages.login_page(tok).encode('utf-8')
        self._send(200, body, ctype='text/html; charset=utf-8', headers=headers)

    def _serve_dashboard(self) -> None:
        user = self._current_user()
        if user is None:
            self._redirect('/login')
            return
        tok, setc = self._csrf_pair()
        fresh = users.refresh_cycle(users.users_file(), user)
        ok, reason = users.check_service(fresh)
        query = parse_qs(urlsplit(self.path).query)
        msg = (query.get('msg') or [''])[0]
        err = (query.get('err') or [''])[0]
        count = 0
        try:
            meta = STATE.last_meta or json.loads(
                STATE.paths['meta'].read_text(encoding='utf-8'))
            count = int(meta.get('node_count') or 0)
        except Exception:
            pass
        masked = f'{pages.public_host()}/sub/<你的专属令牌>'
        sub_url, sub_kind = '', 'token'
        if not fresh.get('token_id'):
            # Account never had a subscription token (e.g. CLI-created admin):
            # mint one now - nothing to break, and a logged-in user must
            # always see their own yml link.
            try:
                fresh = self._provision_user_token(fresh)
            except Exception as e:
                sys.stderr.write('mango-share ERROR token provisioning failed for %s: %r\n'
                                 % (fresh.get('username'), e))
        # after provisioning: the export signature binds the current token_id
        export_url = self._export_url(fresh)
        try:
            plain = token_store.recover_token(
                users.load_secret(),
                token_store.find_by_id(token_store.token_file(),
                                       str(fresh.get('token_id') or '')))
            if plain:
                sub_url = f'{pages.public_host()}/sub/{plain}'
        except Exception:
            pass
        if not sub_url:
            # Legacy random token: its plaintext was never stored. Show the
            # signed per-account yml link instead of forcing a reset that
            # would break clients already holding the old link.
            sub_url, sub_kind = f'{pages.public_host()}{export_url}', 'export'
        last_used = 0
        try:
            last_map = token_store.last_used_map(token_store.token_file())
            last_used = int(last_map.get(str(fresh.get('token_id') or '')) or 0)
        except Exception:
            pass
        html_body = pages.dashboard_page(
            fresh, tok, status_reason='' if ok else reason,
            masked_url=masked, sub_url=sub_url, sub_kind=sub_kind, node_count=count, last_used=last_used,
            export_url=f'{pages.public_host()}{export_url}', msg=msg, err=err)
        headers = self._page_headers(self._slide_session_cookie(fresh) or setc)
        self._send(200, html_body.encode('utf-8'), ctype='text/html; charset=utf-8', headers=headers)

    def _serve_admin(self) -> None:
        user = self._current_user()
        if user is None:
            self._redirect('/login')
            return
        if user.get('role') != 'admin':
            self._redirect('/dashboard?err=' + quote('仅管理员可访问管理页'))
            return
        tok, setc = self._csrf_pair()
        query = parse_qs(urlsplit(self.path).query)
        msg = (query.get('msg') or [''])[0]
        err = (query.get('err') or [''])[0]
        q = (query.get('q') or [''])[0].strip().lower()
        records = users.load(users.users_file())
        now = int(time.time())
        expiring = [u for u in records if u.get('status') == 'active'
                    and 0 < int(u.get('expire_ts') or 0) - now <= 7 * 86400]
        near_quota = [u for u in records if u.get('status') == 'active'
                      and int(u.get('quota_bytes') or 0) > 0
                      and int(u.get('used_bytes', 0) or 0) * 100
                      >= int(u['quota_bytes']) * 85]
        if q:
            records = [r for r in records
                       if q in str(r.get('username', '')).lower()
                       or q in str(r.get('notes', '')).lower()
                       or q in str(r.get('email', '')).lower()]
        tokens_by_id = {}
        try:
            for t in token_store.load(token_store.token_file()):
                tokens_by_id[str(t.get('id') or '')] = t
        except Exception:
            pass
        html_body = pages.admin_page(records, tokens_by_id, tok, msg=msg, err=err,
                                     q=q, expiring=expiring, near_quota=near_quota)
        headers = self._page_headers(self._slide_session_cookie(user), setc)
        self._send(200, html_body.encode('utf-8'), ctype='text/html; charset=utf-8', headers=headers)

    # ------------------------------------------------------------ POST: auth

    def _post_login(self, form: dict) -> None:
        if not self._csrf_ok(form):
            self._send(403, b'{"error":"csrf validation failed"}')
            return
        username = self._field(form, 'username').strip()
        password = self._field(form, 'password')
        ip = self._client_ip()
        remain = users.login_lockout_remaining(ip, username)
        if remain > 0:
            body = pages.login_page(self._field(form, 'csrf'),
                                    error=f'失败次数过多，已临时锁定，请约 {max(1, remain // 60)} 分钟后再试',
                                    username=username).encode('utf-8')
            self._send(429, body, ctype='text/html; charset=utf-8',
                       headers=[('Cache-Control', 'no-store'), *_html_security_headers()])
            return
        records = users.load(users.users_file())
        rec = users.find_by_username(records, username)
        if rec is None:
            users.record_login_fail(ip, username)
            constant_delay()  # same blunt-force delay as token auth
            body = pages.login_page(self._field(form, 'csrf'),
                                    error='用户名或密码错误', username=username).encode('utf-8')
            self._send(401, body, ctype='text/html; charset=utf-8',
                       headers=[('Cache-Control', 'no-store'), *_html_security_headers()])
            return
        try:
            password_ok = users.verify_password(rec, password)
        except users.ScryptBusy:
            # Derivation slots exhausted by other logins: shed load without
            # counting this attempt as a failure (the user did nothing wrong).
            body = pages.login_page(self._field(form, 'csrf'),
                                    error='系统繁忙，请稍后再试', username=username).encode('utf-8')
            self._send(429, body, ctype='text/html; charset=utf-8',
                       headers=[('Cache-Control', 'no-store'), *_html_security_headers()])
            return
        if not password_ok:
            users.record_login_fail(ip, username)
            constant_delay()
            body = pages.login_page(self._field(form, 'csrf'),
                                    error='用户名或密码错误', username=username).encode('utf-8')
            self._send(401, body, ctype='text/html; charset=utf-8',
                       headers=[('Cache-Control', 'no-store'), *_html_security_headers()])
            return
        if rec.get('status') == 'disabled':
            # Correct credentials, but the account is switched off: say so
            # (the caller just authenticated, so this reveals nothing new).
            body = pages.login_page(self._field(form, 'csrf'),
                                    error='账号已停用，订阅已停止服务。请联系分享者。',
                                    username=username).encode('utf-8')
            self._send(403, body, ctype='text/html; charset=utf-8',
                       headers=[('Cache-Control', 'no-store'), *_html_security_headers()])
            return
        users.clear_login_fails(ip, username)
        rec = users.refresh_cycle(users.users_file(), rec)
        secret = users.load_secret()
        session = users.issue_session(secret, rec['id'],
                                      epoch=int(rec.get('session_epoch', 0) or 0))
        csrf = users.new_csrf_token()
        self._redirect('/dashboard', extra=[
            ('Set-Cookie', self._cookie_header(users.SESSION_COOKIE, session, users.SESSION_TTL)),
            ('Set-Cookie', self._cookie_header(users.CSRF_COOKIE, csrf, users.CSRF_TTL)),
        ])

    def _post_logout(self, form: dict) -> None:
        if not self._csrf_ok(form):
            self._send(403, b'{"error":"csrf validation failed"}')
            return
        self._redirect('/login', extra=[
            ('Set-Cookie', self._cookie_header(users.SESSION_COOKIE, '', 0)),
            ('Set-Cookie', self._cookie_header(users.CSRF_COOKIE, '', 0)),
        ])

    # ------------------------------------------------------ POST: dashboard

    def _post_dashboard_password(self, form: dict) -> None:
        user = self._current_user()
        if user is None:
            self._redirect('/login')
            return
        if not self._csrf_ok(form):
            self._send(403, b'{"error":"csrf validation failed"}')
            return
        old = self._field(form, 'old_password')
        new = self._field(form, 'new_password')
        try:
            old_ok = users.verify_password(user, old)
        except users.ScryptBusy:
            self._redirect('/dashboard?err=' + quote('系统繁忙，请稍后再试'))
            return
        if not old_ok:
            self._redirect('/dashboard?err=' + quote('当前密码不正确'))
            return
        try:
            users.set_password(users.users_file(), user['id'], new)
        except ValueError as e:
            self._redirect('/dashboard?err=' + quote(str(e)))
            return
        # set_password bumped session_epoch: this browser's session died too.
        secret = users.load_secret()
        session = users.issue_session(secret, user['id'],
                                      epoch=int(user.get('session_epoch', 0) or 0) + 1)
        self._audit(user['username'], 'password.change', target=user['username'])
        self._redirect('/dashboard?msg=' + quote('密码已更新，其余登录已全部失效'), extra=[
            ('Set-Cookie', self._cookie_header(
                users.SESSION_COOKIE, session, users.SESSION_TTL)),
        ])

    def _post_dashboard_regen(self, form: dict) -> None:
        user = self._current_user()
        if user is None:
            self._redirect('/login')
            return
        if not self._csrf_ok(form):
            self._send(403, b'{"error":"csrf validation failed"}')
            return
        plaintext = self._rotate_user_token(user)  # audits token.regen itself
        url = f'{pages.public_host()}/sub/{plaintext}'
        body = pages.reveal_page(url, back='/dashboard',
                                 role=str(user.get('role') or 'user'),
                                 logout_csrf=self._field(form, 'csrf')).encode('utf-8')
        self._send(200, body, ctype='text/html; charset=utf-8',
                   headers=[('Cache-Control', 'no-store'), *_html_security_headers()])

    def _provision_user_token(self, user: dict) -> dict:
        """Give a token-less account its first (derived) subscription token.
        Re-checked inside the users-store lock so concurrent dashboard loads
        mint at most one. Returns the fresh user record."""
        minted = False
        with users.locked(users.users_file()):
            records = users.load(users.users_file())
            target = users.find_by_id(records, user['id'])
            if target is None:
                return user
            if not target.get('token_id'):
                rec, _ = token_store.create_token(
                    token_store.token_file(), target['username'],
                    owner=str(target['id']), secret=users.load_secret())
                target['token_id'] = rec['id']
                users.save(users.users_file(), records)
                minted = True
            fresh = dict(target)
        if minted:
            self._audit(user['username'], 'token.provision', target=user['username'])
        return fresh

    def _rotate_user_token(self, user: dict) -> str:
        """Revoke the user's old subscription token and mint a new one;
        returns the plaintext (shown exactly once on the response page).
        The whole sequence runs inside the users-store flock, and the token
        to revoke is re-read inside that critical section — revoking the
        caller's stale copy would let concurrent rotations strand active
        unbound tokens."""
        with users.locked(users.users_file()):
            records = users.load(users.users_file())
            target = users.find_by_id(records, user['id'])
            tokens_path = token_store.token_file()
            if target is not None:
                old_id = str(target.get('token_id') or '')
                if old_id:
                    token_store.revoke_by_id(tokens_path, old_id)
            rec, plaintext = token_store.create_token(
                tokens_path, user['username'], owner=str(user['id']),
                secret=users.load_secret())
            if target is not None:
                target['token_id'] = rec['id']
                users.save(users.users_file(), records)
        self._audit(user['username'], 'token.regen', target=user['username'])
        return plaintext

    # ---------------------------------------------------------- POST: admin

    def _require_admin(self) -> dict | None:
        user = self._current_user()
        if user is None:
            self._redirect('/login')
            return None
        if user.get('role') != 'admin':
            self._send(403, b'{"error":"admin only"}')
            return None
        return user

    def _post_admin_create(self, form: dict) -> None:
        admin = self._require_admin()
        if admin is None:
            return
        if not self._csrf_ok(form):
            self._send(403, b'{"error":"csrf validation failed"}')
            return
        username = self._field(form, 'username').strip().lower()
        password = self._field(form, 'password')
        email = self._field(form, 'email').strip().lower()
        email_err = users.validate_email(email)
        if email_err:
            self._redirect('/admin?err=' + quote(email_err))
            return
        try:
            quota_gb = self._num(self._field(form, 'quota_gb'), 0, 1 << 20)
            expire_days = int(self._num(self._field(form, 'expire_days'), 0, 36500))
            reset_day = int(self._num(self._field(form, 'reset_day'), 1, 31))
        except ValueError:
            self._redirect('/admin?err=' + quote('配额/有效期/重置日格式不正确'))
            return
        notes = self._field(form, 'notes').strip()
        if quota_gb < 0 or expire_days < 0:
            # 0 means "unlimited"; a negative value must not silently become
            # unlimited, which would disable the quota being set.
            self._redirect('/admin?err=' + quote('配额/有效期天数不能为负数'))
            return
        try:
            rec = users.create_user(
                users.users_file(), username, password,
                quota_bytes=int(quota_gb * (1 << 30)) if quota_gb > 0 else 0,
                reset_day=reset_day,
                expire_ts=int(time.time() + expire_days * 86400) if expire_days > 0 else 0,
                email=email, notes=notes)
        except ValueError as e:
            self._redirect('/admin?err=' + quote(str(e)))
            return
        except users.ScryptBusy:
            self._redirect('/admin?err=' + quote('系统繁忙，请稍后再试'))
            return
        user_id = rec['id']
        rec, plaintext = token_store.create_token(token_store.token_file(),
                                                  rec['username'], owner=rec['id'],
                                                  secret=users.load_secret())
        users.update_user(users.users_file(), user_id,
                          lambda r: r.update(token_id=rec['id']))
        self._audit(admin['username'], 'user.create', target=username,
                    quota_gb=quota_gb, expire_days=expire_days, reset_day=reset_day)
        url = f'{pages.public_host()}/sub/{plaintext}'
        body = pages.reveal_page(url, back='/admin',
                                 title_note=f'新用户 {username}',
                                 role='admin',
                                 logout_csrf=self._field(form, 'csrf')).encode('utf-8')
        self._send(200, body, ctype='text/html; charset=utf-8',
                   headers=[('Cache-Control', 'no-store'), *_html_security_headers()])

    def _post_admin_action(self, uid: str, form: dict) -> None:
        admin = self._require_admin()
        if admin is None:
            return
        if not self._csrf_ok(form):
            self._send(403, b'{"error":"csrf validation failed"}')
            return
        action = self._field(form, 'action')
        value = self._field(form, 'value').strip()
        try:
            records = users.load(users.users_file())
            target = users.find_by_id(records, uid)
            if target is None:
                self._redirect('/admin?err=' + quote('用户不存在'))
                return
            if action == 'set-quota':
                gb = self._num(value, 0, 1 << 20)
                if gb < 0:
                    self._redirect('/admin?err=' + quote('配额不能为负数（0 = 不限量）'))
                    return
                users.update_user(users.users_file(), uid,
                                  lambda r: r.update(quota_bytes=int(gb * (1 << 30)) if gb > 0 else 0))
                self._audit(admin['username'], 'user.set-quota',
                            target=target['username'], value=gb)
                self._redirect('/admin?msg=' + quote(f'[{target["username"]}] 配额已更新'))
            elif action == 'set-expire':
                days = int(self._num(value, 0, 36500))
                if days < 0:
                    self._redirect('/admin?err=' + quote('天数不能为负数（0 = 不限）'))
                    return
                expire = int(time.time() + days * 86400) if days > 0 else 0
                users.update_user(users.users_file(), uid,
                                  lambda r: r.update(expire_ts=expire))
                self._audit(admin['username'], 'user.set-expire',
                            target=target['username'], value=days)
                self._redirect('/admin?msg=' + quote(f'[{target["username"]}] 到期时间已更新'))
            elif action == 'reset-password':
                users.set_password(users.users_file(), uid, value)
                self._audit(admin['username'], 'user.reset-password',
                            target=target['username'])
                self._redirect('/admin?msg=' + quote(f'[{target["username"]}] 密码已重置，该用户登录已全部失效'))
            elif action == 'regen-token':
                plaintext = self._rotate_user_token(target)
                url = f'{pages.public_host()}/sub/{plaintext}'
                body = pages.reveal_page(url, back='/admin',
                                         title_note=f'用户 {target["username"]} 的新订阅',
                                         role='admin',
                                         logout_csrf=self._field(form, 'csrf')).encode('utf-8')
                self._send(200, body, ctype='text/html; charset=utf-8',
                           headers=[('Cache-Control', 'no-store'), *_html_security_headers()])
            elif action == 'set-email':
                email_err = users.validate_email(value.strip().lower())
                if email_err and value.strip():
                    self._redirect('/admin?err=' + quote(email_err))
                    return
                users.update_user(users.users_file(), uid,
                                  lambda r: r.update(email=value.strip().lower()))
                self._audit(admin['username'], 'user.set-email',
                            target=target['username'])
                self._redirect('/admin?msg=' + quote(f'[{target["username"]}] 邮箱已更新'))
            elif action in ('disable', 'enable'):
                status = 'disabled' if action == 'disable' else 'active'
                users.set_status(users.users_file(), uid, status)
                self._audit(admin['username'], f'user.{action}',
                            target=target['username'])
                self._redirect('/admin?msg=' + quote(f'[{target["username"]}] 已{ "停用" if action == "disable" else "启用" }'))
            else:
                self._redirect('/admin?err=' + quote('未知操作'))
        except (ValueError, KeyError) as e:
            self._redirect('/admin?err=' + quote(str(e)))
        except users.ScryptBusy:
            self._redirect('/admin?err=' + quote('系统繁忙，请稍后再试'))

    # ---------------------------------------------------------- POST: ingest

    def _post_ingest(self, raw: bytes) -> None:
        """Phase-2 hook for node agents (sing-box v2ray_api collectors).
        Auth: a node token (nodes.json, sha256 store) via the Authorization
        Bearer header — checked BEFORE any body parsing so unauthenticated
        traffic never spends cycles on payloads. Body: JSON
        {node?, updates:[{user,up,down}]}. Bytes are attributed to users by
        username; unknown names are skipped and audited, never rejected."""
        bearer = (self.headers.get('Authorization') or '').removeprefix('Bearer ').strip()
        rec = token_store.verify(token_store.nodes_file(), bearer) if bearer else None
        if rec is None:
            constant_delay()
            self._send(401, json.dumps({'error': 'invalid node token'}).encode())
            return
        ctype = (self.headers.get('Content-Type') or '').lower()
        try:
            if 'json' in ctype and raw:
                data = json.loads(raw.decode('utf-8', 'replace'))
                if not isinstance(data, dict):
                    raise ValueError('expected a JSON object')
                node = str(data.get('node') or 'unknown-node')[:64]
                updates = data.get('updates') or []
            else:
                form = parse_qs(raw.decode('utf-8', 'replace'), keep_blank_values=True)
                node = (self._field(form, 'node') or 'unknown-node')[:64]
                updates = json.loads(self._field(form, 'updates') or '[]')
        except ValueError as e:
            self._send(400, json.dumps({'error': f'bad payload: {e}'}).encode())
            return
        if not isinstance(updates, list):
            self._send(400, json.dumps({'error': 'updates must be a list'}).encode())
            return
        result = users.add_usage(users.users_file(), updates, node)
        token_store.touch(rec, token_store.nodes_file())
        self._send(200, json.dumps({'ok': True, **result}).encode())

    # Landing page follows MangoShare's paper-and-ink visual language rather
    # than a generic AI/glass landing page. It stays self-contained: no CDN,
    # analytics, remote fonts, or third-party assets on the credential host.
    def _serve_home(self) -> None:
        # Session-aware landing: same shell for everyone, sidebar and CTAs
        # adapt (进入用户中心 vs 登录). Node count is safe public metadata;
        # region badges are names+counts only, never addresses.
        user = self._current_user()
        role = str(user.get('role') or 'anon') if user else 'anon'
        count = 0
        regions: list = []
        try:
            meta = STATE.last_meta or json.loads(
                STATE.paths['meta'].read_text(encoding='utf-8'))
            count = int(meta.get('node_count') or 0)
        except Exception:
            pass
        # Region aggregation parses the whole YAML; cache it per output sha
        # (the homepage is unauthenticated and no-store, so crawler scans
        # would otherwise re-pay the parse on every request).
        try:
            out_sha = hashlib.sha256(
                STATE.paths['out'].read_bytes()).hexdigest()
            with _REGIONS_CACHE_LOCK:
                cached = _REGIONS_CACHE.get('sha')
            if cached == out_sha:
                with _REGIONS_CACHE_LOCK:
                    regions = list(_REGIONS_CACHE['regions'])
            else:
                import yaml as _yaml
                doc = _yaml.safe_load(
                    STATE.paths['out'].read_text(encoding='utf-8'))
                names = [str(p.get('name') or '')
                         for p in (doc.get('proxies') or [])]
                regions = render_public.node_regions(names)
                with _REGIONS_CACHE_LOCK:
                    _REGIONS_CACHE.update(sha=out_sha, regions=regions)
        except Exception:
            pass
        # Anonymous visitors get no csrf cookie; authed ones reuse the
        # browser's pair so the sidebar logout form validates on submit.
        tok, setc = self._csrf_pair() if user else ('', None)
        headers = [('Cache-Control', 'no-store'), *_html_security_headers()]
        if setc:
            headers.append(('Set-Cookie', setc))
        html_body = pages.landing_page(node_count=count, regions=regions,
                                       role=role, logout_csrf=tok)
        self._send(200, html_body.encode('utf-8'),
                   ctype='text/html; charset=utf-8',
                   headers=headers)

    def _sub_user_gate(self) -> tuple:
        """Token -> owning user -> service gate. Returns (user, ok, reason).
        Legacy tokens with no bound user pass through (user=None, ok=True)."""
        rec = getattr(self, '_rec', None)
        if not rec:
            return None, True, ''
        records = users.load(users.users_file())
        user = users.find_by_token_id(records, rec.get('id'))
        if user is None:
            return None, True, ''
        user, ok, reason = users.refresh_and_check(users.users_file(), user)
        return user, ok, reason

    @staticmethod
    def _userinfo_header(user: dict | None) -> str | None:
        """Mainstream subscription-userinfo header so clients render the
        traffic bar & expiry. Bytes come only from self-hosted node reports
        (phase-2 agents); before that, download stays an honest 0."""
        if not user:
            return None
        parts = ['upload=0', f"download={int(user.get('used_bytes', 0) or 0)}"]
        quota = int(user.get('quota_bytes') or 0)
        if quota > 0:
            parts.append(f'total={quota}')
        expire = int(user.get('expire_ts') or 0)
        if expire > 0:
            parts.append(f'expire={expire}')
        return '; '.join(parts)

    _FMT_META = {
        'clash': ('text/yaml; charset=utf-8', ''),
        'singbox': ('application/json; charset=utf-8', '-singbox'),
        'surge': ('text/plain; charset=utf-8', '-surge'),
        'qx': ('text/plain; charset=utf-8', '-qx'),
        'uri': ('text/plain; charset=utf-8', '-urilist'),
    }

    def _convert_body(self, fmt: str, body: bytes,
                      managed_url: str | None = None) -> bytes:
        """Convert the Clash mirror body to the requested client format.
        Unknown fmt falls back to clash. Results are memoised per (body,
        fmt, managed_url): every client polls the same mirror, so the YAML
        parse + conversion runs once per gateway refresh, not per request."""
        fmt = (fmt or 'clash').lower()
        if fmt == 'clash' or fmt not in self._FMT_META:
            return body
        key = (hashlib.sha256(body).digest(), fmt, managed_url)
        with _CONVERT_LOCK:
            hit = _CONVERT_CACHE.get(key)
            if hit is not None:
                _CONVERT_CACHE.move_to_end(key)
                return hit
        try:
            # the mirror body is always Clash YAML, whatever the target format
            clash = __import__('yaml').safe_load(body.decode('utf-8'))
            if not isinstance(clash, dict):
                raise ValueError('mirror is not a mapping')
            if fmt == 'singbox':
                text, skipped = fmtconv.to_singbox_json(clash)
            elif fmt == 'surge':
                text, skipped = fmtconv.to_surge(clash, managed_url=managed_url)
            elif fmt == 'qx':
                text, skipped = fmtconv.to_qx(clash)
            else:
                text, skipped = fmtconv.to_uri_list(clash)
        except Exception as e:
            sys.stderr.write(f'mango-share ERROR convert fmt={fmt}: {type(e).__name__}: {e}\n')
            return body  # unconvertible mirror: serve the Clash body as-is
        out = text.encode('utf-8')
        sys.stderr.write(f'mango-share convert fmt={fmt} skipped={len(skipped)}\n')
        with _CONVERT_LOCK:
            _CONVERT_CACHE[key] = out
            while len(_CONVERT_CACHE) > _CONVERT_CACHE_MAX:
                _CONVERT_CACHE.popitem(last=False)
        return out

    def _serve_sub(self) -> None:
        if not self._authorized():
            self._send(401, b'', headers={'WWW-Authenticate': 'Bearer'})
            return
        user, ok, reason = self._sub_user_gate()
        if not ok:
            # Authenticated but not entitled (disabled/expired/over quota).
            # No brute-force delay here: the token itself already verified.
            self._send(401, json.dumps({'error': reason}).encode(),
                       headers={'WWW-Authenticate': 'Bearer'})
            return
        stale = False
        try:
            STATE.ensure_fresh()
        except Exception as e:
            if not STATE.paths['out'].exists():
                sys.stderr.write(f'mango-share ERROR render failed: {e}\n')
                self._send(500, b'{"error":"render failed"}')
                return
            stale = True
        body_path = STATE.paths['out']
        # Phase-2: serve the user's own rendered YAML when the rollout flag is
        # on and they are provisioned on at least one mapped node. Any
        # per-user failure falls back to the global last-good render (shared
        # credentials stay valid), so connectivity never depends on it.
        if PER_USER_YAML and user is not None:
            try:
                cred_map = STATE._node_cred_map()
                provisioned = bool(cred_map) and any(
                    isinstance(m, dict)
                    and str(m.get('key')) in (user.get('credentials') or {})
                    for m in cred_map)
                if provisioned:
                    user_path, _ = STATE.ensure_user_fresh(user)
                    if user_path.exists():
                        body_path = user_path
                        stale = False  # per-user render is fresh by construction
            except Exception:
                pass  # keep the global render
        body = body_path.read_bytes()
        qs = parse_qs(urlsplit(self.path).query)
        fmt = (qs.get('fmt') or ['clash'])[0].lower()
        if fmt != 'clash':
            # Surge auto-updates from the #!MANAGED-CONFIG line: point it
            # back at the URL the client actually used.
            managed = f'{pages.public_host()}{self.path}' if fmt == 'surge' else None
            body = self._convert_body(fmt, body, managed_url=managed)
        ctype, title_suffix = self._FMT_META.get(fmt, self._FMT_META['clash'])
        userinfo = self._userinfo_header(user)
        # The validator covers the userinfo header too: a 304 replays the
        # client's cached headers, so a body-only ETag would freeze the
        # quota/expiry bar until the node list itself changed.
        digest = hashlib.sha256(body + b'\0' + (userinfo or '').encode()).hexdigest()
        etag = f'"{digest}"'
        # last-seen tracks polls, including the conditional ones
        token_store.touch(self._rec, token_store.token_file())
        inm = (self.headers.get('If-None-Match') or '').strip()
        if inm and hmac.compare_digest(inm.encode(), etag.encode()):
            self._send(304, b'', headers={'ETag': etag,
                                          'Cache-Control': 'private, no-cache',
                                          'profile-title': const.PROFILE_TITLE})
            return
        headers = {
            'ETag': etag,
            'Cache-Control': 'private, no-cache',
            'Content-Disposition': f'attachment; filename={const.PROFILE_TITLE}{title_suffix}',
            'profile-update-interval': '6',
            'profile-title': f'{const.PROFILE_TITLE}{title_suffix}',
        }
        if userinfo:
            headers['subscription-userinfo'] = userinfo
        headers['profile-web-page-url'] = f'{pages.public_host()}/dashboard'
        if body_path != STATE.paths['out'] and user is not None:
            # per-user render: let multi-account devices tell profiles apart
            safe = re.sub(r'[^A-Za-z0-9_-]', '', str(user.get('username') or ''))
            if safe:
                headers['profile-title'] = f'{const.PROFILE_TITLE}-{safe}'
                headers['Content-Disposition'] = (
                    f'attachment; filename={const.PROFILE_TITLE}-{safe}')
        if stale:
            headers['X-Mango-Share-Stale'] = '1'
        self._send(200, body, ctype=ctype, headers=headers)

    def _serve_info(self) -> None:
        if not self._authorized():
            self._send(401, b'', headers={'WWW-Authenticate': 'Bearer'})
            return
        try:
            meta = STATE.ensure_fresh()
        except Exception as e:
            # Same contract as /sub: a failed re-render serves last-good
            # metadata rather than an error.
            sys.stderr.write(f'mango-share ERROR render failed: {e}\n')
            meta = STATE.last_meta
            if not meta:
                try:
                    meta = json.loads(STATE.paths['meta'].read_text(encoding='utf-8'))
                except (OSError, ValueError):
                    self._send(500, b'{"error":"render failed"}')
                    return
        user, ok, reason = self._sub_user_gate()
        payload = {
            'profile': const.PROFILE_TITLE,
            'render_rev': meta.get('render_rev'),
            'node_count': meta.get('node_count'),
            'generated_at': meta.get('generated_at'),
            'recipient': self._rec.get('name'),
        }
        if user:
            payload['service'] = 'ok' if ok else reason
            payload['used_bytes'] = int(user.get('used_bytes', 0) or 0)
            payload['quota_bytes'] = int(user.get('quota_bytes') or 0)
            payload['expire_ts'] = int(user.get('expire_ts') or 0)
        self._send(200, json.dumps(payload, ensure_ascii=False).encode())


def main() -> int:
    import argparse

    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--listen', default=os.environ.get('SHARE_LISTEN', '127.0.0.1'))
    ap.add_argument('--port', type=int, default=int(os.environ.get('SHARE_PORT', '2054')))
    args = ap.parse_args()

    # Warm the first render so a broken config fails loudly at boot, not lazily.
    try:
        meta = STATE.ensure_fresh()
        print(f'mango-share ready: {meta.get("node_count")} nodes sha={meta.get("sha256", "")[:12]}', flush=True)
    except Exception as e:
        print(f'mango-share WARN initial render failed: {e}', flush=True)

    if os.environ.get('SHARE_NODE_POOL', '1') != '0':
        start_pool_worker()
    start_clients_worker()
    srv = ThreadingHTTPServer((args.listen, args.port), Handler)
    print(f'mango-share listening on {args.listen}:{args.port}', flush=True)
    srv.serve_forever()
    return 0


if __name__ == '__main__':
    sys.exit(main())
