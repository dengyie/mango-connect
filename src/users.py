#!/usr/bin/env python3
"""User accounts, sessions, quotas & traffic ingest for mango-share.

users.json: [{id, username, password:{scrypt,salt,n,r,p}, role, status,
              quota_bytes, reset_day, expire_ts, used_bytes, cycle_start,
              token_id, created, notes}]
- Passwords: scrypt with a per-user salt, never stored or logged in clear.
- Sessions: stateless HMAC-signed cookies signed with secret.key (0600 in
  the state dir); the store holds no session state, so restarts keep
  sessions valid and revocation = secret rotation.
- Quota: used_bytes accumulates from /ingest/traffic reports (phase-2
  sing-box agents); each user's billing period resets lazily on access at
  reset_day. Metering only ever covers self-hosted nodes; third-party
  (airport) nodes are access-controlled only and never counted.
- traffic-ingest.log: append-only audit of every ingest report.

CLI mirrors tokens.py: add-admin / set-quota / set-expire / reset-password
/ disable / enable / list. Passwords are prompted, never argv or logs.
"""

from __future__ import annotations

import argparse
import base64
import contextlib
import fcntl
import getpass
import hashlib
import hmac
import json
import os
import re
import secrets
import sys
import tempfile
import threading
import time
from pathlib import Path
from typing import Any, Dict, List, Optional

from state_backup import rotate_log_if_large, snapshot
from share_constants import state_dir

USER_MODE = 0o640
SECRET_MODE = 0o600
SESSION_TTL = 7 * 24 * 3600
SESSION_COOKIE = 'mango_session'
CSRF_COOKIE = 'mango_csrf'
CSRF_TTL = 7 * 24 * 3600
SCRYPT_N, SCRYPT_R, SCRYPT_P, SCRYPT_DK = 2**15, 8, 1, 32
# Each scrypt derivation allocates ~128*N*r (~33.5MB). The login endpoint is
# pre-auth, so concurrent floods must not multiply that: cap in-flight
# derivations and reject beyond the cap instead of queueing threads.
_SCRYPT_SLOTS = 4
_SCRYPT_GATE = threading.BoundedSemaphore(_SCRYPT_SLOTS)
MIN_PASSWORD_LEN = 8
USERNAME_RE = re.compile(r'^[a-z0-9][a-z0-9_-]{2,31}$')
SESSION_VERSION = 1

# Login brute-force guard: process-local counters (a restart clears them,
# which is acceptable because every failure also pays a constant delay).
LOCK_THRESHOLD = 5
LOCK_SECONDS = 900
# Bound on tracked keys: a flood of unique (ip|username) pairs must not grow
# the dict without limit. When full, stale entries (unlocked, last failure
# older than the lock window) are pruned first, then the oldest unlocked
# entry is evicted - so a username spray can never permanently switch the
# lockout off for a real target (it used to: entries never aged out).
_LOGIN_FAILS_MAX = 10_000
# key -> [lock_until, fail_count, last_fail_at]
_login_fails: Dict[str, List[int]] = {}
_login_lock = threading.Lock()


class ScryptBusy(Exception):
    """Too many password derivations are already in flight; the caller
    should shed load (429) instead of multiplying memory."""


def users_file(env: Optional[Dict[str, str]] = None) -> Path:
    env = env or os.environ
    base = state_dir(env)
    return base / 'users.json'


def ingest_file(env: Optional[Dict[str, str]] = None) -> Path:
    env = env or os.environ
    base = state_dir(env)
    return base / 'traffic-ingest.log'


def secret_file(env: Optional[Dict[str, str]] = None) -> Path:
    env = env or os.environ
    base = state_dir(env)
    return base / 'secret.key'


def cli_actor() -> str:
    """Audit actor for CLI mutations: the OS account running the command."""
    try:
        return f'cli:{getpass.getuser()}'
    except OSError:
        return 'cli:unknown'


def audit_cli(action: str, target: str = '', **detail) -> None:
    """Audit a CLI mutation (same trail as web actions; closes the gap where
    only web mutations were auditable)."""
    try:
        append_audit({'actor': cli_actor(), 'action': f'cli.{action}',
                      'target': target, **detail})
    except OSError:
        pass


def audit_file(env: Optional[Dict[str, str]] = None) -> Path:
    env = env or os.environ
    base = state_dir(env)
    return base / 'audit.log'


def append_audit(entry: Dict[str, Any], env: Optional[Dict[str, str]] = None) -> None:
    """Append one admin-action audit record (actor/ip/action/target). The
    trail is append-only and best-effort: a logging failure never rolls back
    the action it describes."""
    entry = {'at': int(time.time()), **entry}
    p = audit_file(env)
    if not p.parent.exists():
        return
    with locked(p):
        rotate_log_if_large(p)
        with open(p, 'a', encoding='utf-8') as f:
            f.write(json.dumps(entry, ensure_ascii=False) + '\n')


def locked(path: Path):
    """Exclusive flock on a sidecar lock file (same pattern as tokens.py);
    the store dir must already exist."""
    lock_path = path.with_suffix(path.suffix + '.lock')

    @contextlib.contextmanager
    def _ctx():
        f = open(lock_path, 'a')
        try:
            fcntl.flock(f, fcntl.LOCK_EX)
            yield
        finally:
            try:
                fcntl.flock(f, fcntl.LOCK_UN)
            finally:
                f.close()

    return _ctx()


def load(path: Path) -> List[Dict[str, Any]]:
    if not path.exists():
        return []
    data = json.loads(path.read_text(encoding='utf-8'))
    if not isinstance(data, list):
        raise ValueError(f'{path}: expected a JSON list')
    return data


def save(path: Path, records: List[Dict[str, Any]]) -> None:
    snapshot(path)  # rotate a backup of the current store before replacing it
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp_name = tempfile.mkstemp(prefix='users-', suffix='.tmp', dir=str(path.parent))
    tmp = Path(tmp_name)
    try:
        with os.fdopen(fd, 'w', encoding='utf-8') as f:
            f.write(json.dumps(records, ensure_ascii=False, indent=2) + '\n')
            f.flush()
            os.fsync(f.fileno())  # replace() must never expose an empty file after a crash
        os.chmod(tmp, USER_MODE)
        # Preserve ownership across the atomic replace (a root-run CLI must
        # not leave the store unreadable for the unprivileged service, the
        # same failure mode tokens.py guards against).
        try:
            st = path.stat()
            os.chown(tmp, st.st_uid, st.st_gid)
        except (PermissionError, OSError):
            pass
        os.replace(tmp, path)
    except BaseException:
        tmp.unlink(missing_ok=True)
        raise


# ---------------------------------------------------------------- passwords

def _derive(password: str, salt: bytes, n: int, r: int, p: int, blocking: bool) -> bytes:
    """scrypt under the concurrency gate. `blocking` (admin/CLI paths) waits
    for a slot; the pre-auth login path must pass False so floods shed load
    immediately instead of piling 33MB allocations onto the box."""
    if not _SCRYPT_GATE.acquire(blocking=blocking, timeout=10 if blocking else None):
        raise ScryptBusy()
    try:
        # maxmem must exceed 128*N*r (~32MiB) which is above OpenSSL's default.
        return hashlib.scrypt(password.encode('utf-8'), salt=salt,
                              n=n, r=r, p=p, dklen=SCRYPT_DK, maxmem=64 << 20)
    finally:
        _SCRYPT_GATE.release()


def hash_password(password: str) -> Dict[str, Any]:
    salt = secrets.token_bytes(16)
    h = _derive(password, salt, SCRYPT_N, SCRYPT_R, SCRYPT_P, blocking=True)
    return {'scrypt': h.hex(), 'salt': salt.hex(),
            'n': SCRYPT_N, 'r': SCRYPT_R, 'p': SCRYPT_P}


def verify_password(rec: Dict[str, Any], password: str) -> bool:
    p = rec.get('password') or {}
    try:
        h = _derive(password, bytes.fromhex(str(p.get('salt', ''))),
                    int(p.get('n', SCRYPT_N)), int(p.get('r', SCRYPT_R)),
                    int(p.get('p', SCRYPT_P)), blocking=False)
    except (KeyError, ValueError, TypeError):
        return False
    return secrets.compare_digest(h.hex(), str(p.get('scrypt', '')))


def validate_password(password: str) -> Optional[str]:
    if len(password) < MIN_PASSWORD_LEN:
        return f'密码至少 {MIN_PASSWORD_LEN} 位'
    return None


# One @, no whitespace, sane length caps for local part / domain.
EMAIL_RE = re.compile(r'^[^@\s]{1,64}@[^@\s]{1,251}$')


def validate_email(email: str) -> Optional[str]:
    """Return an error message for invalid reminder emails; '' / None are
    valid (means 'no email on file'). Shared by the web face and the CLI so
    the two entry points cannot drift."""
    email = (email or '').strip()
    if not email:
        return None
    if not EMAIL_RE.match(email):
        return '邮箱格式不正确'
    return None


# ---------------------------------------------------------------- accounts

def find_by_username(records: List[Dict[str, Any]], username: str) -> Optional[Dict[str, Any]]:
    want = (username or '').strip().lower()
    for r in records:
        if str(r.get('username', '')).lower() == want:
            return r
    return None


def find_by_id(records: List[Dict[str, Any]], uid: str) -> Optional[Dict[str, Any]]:
    for r in records:
        if str(r.get('id', '')) == str(uid or ''):
            return r
    return None


def find_by_token_id(records: List[Dict[str, Any]], token_id: str) -> Optional[Dict[str, Any]]:
    for r in records:
        if str(r.get('token_id') or '') == str(token_id or ''):
            return r
    return None


def create_user(path: Path, username: str, password: str, *, role: str = 'user',
                quota_bytes: int = 0, reset_day: int = 1, expire_ts: int = 0,
                notes: str = '', token_id: str = '', email: str = '',
                now: Optional[int] = None) -> Dict[str, Any]:
    """Create one account; raises ValueError on any invalid input."""
    username = (username or '').strip().lower()
    if not USERNAME_RE.match(username):
        raise ValueError('用户名需为 3-32 位小写字母/数字/_/-，且以字母或数字开头')
    err = validate_password(password)
    if err:
        raise ValueError(err)
    quota_bytes = max(0, int(quota_bytes or 0))
    reset_day = min(28, max(1, int(reset_day or 1)))
    expire_ts = max(0, int(expire_ts or 0))
    role = role if role in ('user', 'admin') else 'user'
    err = validate_email(email)
    if err:
        raise ValueError(err)
    now = int(now or time.time())
    with locked(path):
        records = load(path)
        if find_by_username(records, username):
            raise ValueError(f'用户名已存在: {username}')
        ids = {str(r.get('id') or '') for r in records}
        uid = 'u-' + secrets.token_hex(4)
        while uid in ids:  # same collision retry pattern as tokens.py
            uid = 'u-' + secrets.token_hex(4)
        rec = {
            'id': uid,
            'username': username,
            'password': hash_password(password),
            'role': role,
            'status': 'active',
            'quota_bytes': quota_bytes,
            'reset_day': reset_day,
            'expire_ts': expire_ts,
            'used_bytes': 0,
            'cycle_start': now,
            'session_epoch': 0,
            'token_id': str(token_id or ''),
            'email': (email or '').strip().lower(),
            'credentials': {},
            'created': now,
            'notes': notes or '',
        }
        records.append(rec)
        save(path, records)
    return rec


def update_user(path: Path, uid: str, mutate) -> Dict[str, Any]:
    """Apply mutate(rec) under the store lock; returns the updated record."""
    with locked(path):
        records = load(path)
        rec = find_by_id(records, uid)
        if rec is None:
            raise KeyError(f'user not found: {uid}')
        mutate(rec)
        save(path, records)
        return rec


def _update_by_name(path: Path, username: str, mutate) -> Dict[str, Any]:
    with locked(path):
        records = load(path)
        rec = find_by_username(records, username)
        if rec is None:
            raise SystemExit(f'user not found: {username}')
        mutate(rec)
        save(path, records)
        return rec


def _password_mutation(new_password: str):
    """Password updates also bump session_epoch so every previously issued
    session for this account dies immediately (stateless-cookie revocation)."""
    err = validate_password(new_password)
    if err:
        raise ValueError(err)
    h = hash_password(new_password)

    def _m(r: Dict[str, Any]) -> None:
        r['password'] = h
        r['session_epoch'] = int(r.get('session_epoch', 0) or 0) + 1

    return _m


def set_password(path: Path, uid: str, new_password: str) -> Dict[str, Any]:
    return update_user(path, uid, _password_mutation(new_password))


def set_password_by_name(path: Path, username: str, new_password: str) -> Dict[str, Any]:
    return _update_by_name(path, username, _password_mutation(new_password))


def _prompt_password(reason: str) -> str:
    for _ in range(3):
        p1 = getpass.getpass(f'{reason}: ')
        err = validate_password(p1)
        if err:
            print(err)
            continue
        p2 = getpass.getpass('再输入一次确认: ')
        if p1 == p2:
            return p1
        print('两次输入不一致')
    raise SystemExit('密码设置失败')


# ------------------------------------------------- per-node credentials

def _node_uuid(uid: str, node: str) -> str:
    """Deterministic per-(user,node) UUID so config snippets regenerate
    identically on any machine (no drift across re-provisioning)."""
    raw = hashlib.sha256(f'mango-connect:{uid}:{node}'.encode('utf-8')).digest()
    b = bytearray(raw[:16])
    b[6] = (b[6] & 0x0F) | 0x50  # version 5 shape (name-based, ours)
    b[8] = (b[8] & 0x3F) | 0x80  # RFC variant
    h = b.hex()
    return f'{h[0:8]}-{h[8:12]}-{h[12:16]}-{h[16:20]}-{h[20:32]}'


def ensure_node_credentials(path: Path, node: str) -> List[Dict[str, Any]]:
    """Assign a stable per-user UUID for `node` to every active account and
    return the sing-box `users` entries for the requested node. Additive
    only: the shared node credential is never touched, so existing
    subscriptions keep working until per-user YAMLs go live (phase 2)."""
    node = (node or '').strip()
    if not node or '/' in node or not re.match(r'^[A-Za-z0-9_-]{1,64}$', node):
        raise ValueError('node name must be 1-64 chars of A-Za-z0-9_-')
    out: List[Dict[str, Any]] = []
    with locked(path):
        records = load(path)
        changed = False
        for r in records:
            if r.get('status') != 'active':
                continue
            creds = r.setdefault('credentials', {})
            if not isinstance(creds, dict):
                creds = {}
                r['credentials'] = creds
            if node not in creds:
                creds[node] = {'uuid': _node_uuid(str(r['id']), node),
                               'created': int(time.time())}
                changed = True
            entry = {'name': str(r.get('username')),
                     'uuid': creds[node]['uuid'],
                     'password': creds[node]['uuid']}
            out.append(entry)
        if changed:
            save(path, records)
    return out


def rotate_node_credential(path: Path, username: str, node: str) -> Dict[str, Any]:
    """Replace a user's stored uuid for one node with a fresh random value
    (incident response). The deterministic derivation only seeds the FIRST
    assignment; rotations are random and stored, so gen-node-users output
    follows the stored value."""
    node = (node or '').strip()
    def _m(r: Dict[str, Any]) -> None:
        creds = r.setdefault('credentials', {})
        if node not in creds:
            raise KeyError(f'no credential for node [{node}] (run gen-node-users first)')
        h = secrets.token_hex(16)
        creds[node] = {'uuid': f'{h[0:8]}-{h[8:12]}-{h[12:16]}-{h[16:20]}-{h[20:32]}',
                       'rotated': int(time.time())}
    return _update_by_name(path, username, _m)


# ---------------------------------------------------------------- cycles & quota

def _period_start(ts: int, reset_day: int) -> int:
    """Start of the billing period containing ts (local time, day clamped to
    1-28 so every month has it)."""
    t = time.localtime(ts)
    y, m = t.tm_year, t.tm_mon
    if t.tm_mday < reset_day:
        m -= 1
        if m == 0:
            y, m = y - 1, 12
    return int(time.mktime((y, m, reset_day, 0, 0, 0, 0, 0, -1)))


def monthly_reset(rec: Dict[str, Any], now: Optional[int] = None) -> bool:
    """Lazy period rollover: zero used_bytes once the current period start
    moves past cycle_start. Mutates rec; returns True when it rolled."""
    now = int(now or time.time())
    start = _period_start(now, int(rec.get('reset_day', 1) or 1))
    if start > int(rec.get('cycle_start', 0) or 0):
        rec['cycle_start'] = start
        rec['used_bytes'] = 0
        return True
    return False


def refresh_cycle(path: Path, rec: Dict[str, Any], now: Optional[int] = None) -> Dict[str, Any]:
    """Persist a lazy monthly reset for rec (matched by id) if one is due."""
    probe = dict(rec)
    if not monthly_reset(probe, now):
        return rec
    now = int(now or time.time())
    return update_user(path, rec['id'], lambda r: monthly_reset(r, now))


def check_service(rec: Dict[str, Any], now: Optional[int] = None) -> tuple:
    """Distribution-layer service gate: disabled / expired / over quota.
    (Bytes only ever come from self-hosted node reports; third-party nodes
    are governed by this gate alone.)"""
    now = int(now or time.time())
    if rec.get('status') == 'disabled':
        return False, 'disabled'
    expire = int(rec.get('expire_ts') or 0)
    if expire and now >= expire:
        return False, 'expired'
    quota = int(rec.get('quota_bytes') or 0)
    if quota and int(rec.get('used_bytes', 0) or 0) >= quota:
        return False, 'quota_exceeded'
    return True, ''


def refresh_and_check(path: Path, rec: Dict[str, Any],
                      now: Optional[int] = None) -> tuple:
    """Hot-path convenience: roll the period if due (persisted), then run the
    service gate. Returns (fresh_rec, ok, reason)."""
    fresh = refresh_cycle(path, rec, now)
    ok, reason = check_service(fresh, now)
    return fresh, ok, reason


# ---------------------------------------------------------------- ingest

def add_usage(path: Path, updates: List[Any], node: str,
              now: Optional[int] = None, max_updates: int = 1000) -> Dict[str, Any]:
    """Accumulate per-user byte deltas reported by node agents. Every report
    line is appended to traffic-ingest.log for audit; the aggregate lives in
    users.json.used_bytes. Unknown users are skipped, not errors."""
    now = int(now or time.time())
    accepted, skipped = 0, []
    lines: List[str] = []
    with locked(path):
        records = load(path)
        by_name = {str(r.get('username', '')).lower(): r for r in records}
        changed = False
        for u in updates[:max_updates]:
            if not isinstance(u, dict):
                continue
            name = str(u.get('user', '')).strip().lower()
            try:
                up = max(0, int(u.get('up', 0) or 0))
                down = max(0, int(u.get('down', 0) or 0))
            except (TypeError, ValueError):
                continue
            lines.append(json.dumps({'user': name, 'node': node, 'up': up,
                                     'down': down, 'at': now}, ensure_ascii=False))
            rec = by_name.get(name)
            if rec is None:
                skipped.append({'user': name, 'reason': 'unknown'})
                continue
            monthly_reset(rec, now)
            rec['used_bytes'] = int(rec.get('used_bytes', 0) or 0) + up + down
            accepted += 1
            changed = True
        if changed:
            save(path, records)
    _append_ingest_log(ingest_file(), lines)
    return {'accepted': accepted, 'skipped': skipped}


def _append_ingest_log(log_path: Path, lines: List[str]) -> None:
    if not lines or not log_path.parent.exists():
        return
    with locked(log_path):
        rotate_log_if_large(log_path)
        with open(log_path, 'a', encoding='utf-8') as f:
            f.write('\n'.join(lines) + '\n')


# ---------------------------------------------------------------- sessions

_SECRET_CACHE: Dict[str, tuple] = {}


def load_secret(env: Optional[Dict[str, str]] = None) -> bytes:
    """Read secret.key, generating it (0600, ownership follows the state dir)
    on first use. Generation is serialized by the sidecar flock so two cold
    concurrent requests cannot mint different secrets. The file only ever
    holds random bytes.

    The secret signs every session, export link and derived token, so it is
    only ever minted when the file is ABSENT: a transient read error or a
    damaged file raises instead of silently rotating it (which would log
    everyone out and break every copied export link). Creation is atomic
    (tmp + fsync + rename). Reads are cached per (path, mtime, size): this
    runs on most requests and must not take a flock each time."""
    path = secret_file(env)
    key = str(path)
    try:
        st = path.stat()
        hit = _SECRET_CACHE.get(key)
        if hit and hit[0] == (st.st_mtime_ns, st.st_size):
            return hit[1]
    except FileNotFoundError:
        pass
    with locked(path):
        try:
            data = path.read_bytes().strip()
        except FileNotFoundError:
            data = None
        if data is not None:
            try:
                raw = bytes.fromhex(data.decode('ascii'))
            except ValueError:
                raw = b''
            if len(raw) < 32:
                raise RuntimeError(f'{path} is damaged; restore it from a state snapshot')
            st = path.stat()
            _SECRET_CACHE[key] = ((st.st_mtime_ns, st.st_size), raw)
            return raw
        raw = secrets.token_bytes(48)
        path.parent.mkdir(parents=True, exist_ok=True)
        tmp = path.with_name(path.name + '.new')
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, SECRET_MODE)
        try:
            os.write(fd, raw.hex().encode('ascii'))
            os.fsync(fd)
        finally:
            os.close(fd)
        try:
            st = path.parent.stat()
            os.chown(tmp, st.st_uid, st.st_gid)
        except (PermissionError, OSError):
            pass
        os.replace(tmp, path)
        return raw


def _b64e(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b'=').decode('ascii')


def _b64d(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + '=' * (-len(s) % 4))


def issue_session(secret: bytes, uid: str, ttl: int = SESSION_TTL,
                  now: Optional[int] = None, epoch: int = 0) -> str:
    now = int(now or time.time())
    payload = {'uid': uid, 'exp': now + int(ttl), 'v': SESSION_VERSION,
               'e': int(epoch)}
    body = _b64e(json.dumps(payload, separators=(',', ':')).encode('utf-8'))
    sig = hmac.new(secret, body.encode('ascii'), hashlib.sha256).hexdigest()
    return f'{body}.{sig}'


def read_session(secret: bytes, value: str, now: Optional[int] = None) -> Optional[Dict[str, Any]]:
    if not value or '.' not in value:
        return None
    body, sig = value.rsplit('.', 1)
    if not body.isascii() or not sig.isascii():
        return None  # forged/garbled cookie: anonymous, never a 500
    expect = hmac.new(secret, body.encode('ascii'), hashlib.sha256).hexdigest()
    if not hmac.compare_digest(sig, expect):
        return None
    try:
        payload = json.loads(_b64d(body))
    except (ValueError, TypeError):
        return None
    if not isinstance(payload, dict) or payload.get('v') != SESSION_VERSION:
        return None
    exp = payload.get('exp')
    uid = payload.get('uid')
    if not isinstance(exp, int) or not isinstance(uid, str):
        return None
    if int(now or time.time()) >= exp:
        return None
    return payload


def new_csrf_token() -> str:
    return secrets.token_hex(16)


def sign_export(secret: bytes, uid: str, exp: int, generation: str = '') -> str:
    """HMAC signature for a long-lived export deep link: binds the account
    id, expiry and the account's current token id. The link carries no
    long-term token - only the signed (uid, exp, token_id) triple. Rotating
    the subscription token changes token_id, which instantly invalidates
    every export link already copied into client apps."""
    msg = f'export:{uid}:{exp}:{generation}'.encode('utf-8')
    return hmac.new(secret, msg, hashlib.sha256).hexdigest()


def export_link_ok(secret: bytes, uid: str, exp: int, sig: str,
                   now: Optional[int] = None, generation: str = '',
                   current_generation: Optional[str] = None) -> bool:
    if int(exp or 0) < int(now or time.time()):
        return False
    if current_generation is not None and generation != str(current_generation):
        return False  # token was rotated: links minted before it are dead
    expect = sign_export(secret, uid, int(exp), str(generation))
    return secrets.compare_digest(expect, str(sig or ''))


# ---------------------------------------------------------------- login guard

def _fail_key(ip: str, username: str) -> str:
    return f'{ip}|{(username or "").strip().lower()}'


def login_lockout_remaining(ip: str, username: str, now: Optional[int] = None) -> int:
    """Seconds the (ip, username) pair is still locked out; 0 when free."""
    now = int(now or time.time())
    key = _fail_key(ip, username)
    with _login_lock:
        entry = _login_fails.get(key)
        if not entry:
            return 0
        lock_until = entry[0]
        if lock_until > now:
            return lock_until - now
        if lock_until:  # lock expired: forget past failures
            _login_fails.pop(key, None)
    return 0


def record_login_fail(ip: str, username: str, now: Optional[int] = None) -> None:
    now = int(now or time.time())
    key = _fail_key(ip, username)
    with _login_lock:
        if len(_login_fails) >= _LOGIN_FAILS_MAX and key not in _login_fails:
            if not _make_room_locked(now):
                return  # every slot is an active lock: stay bounded
        lock_until, count = _login_fails.get(key, (0, 0, 0))[:2]
        if lock_until and lock_until <= now:
            count = 0
        count += 1
        lock_until = now + LOCK_SECONDS if count >= LOCK_THRESHOLD else 0
        if lock_until:
            count = 0  # locked: restart the count after the window
        _login_fails[key] = [lock_until, count, now]


def _make_room_locked(now: int) -> bool:
    """Free one slot in the full guard table (caller holds _login_lock).
    Prune stale unlocked entries; otherwise evict the oldest unlocked one.
    Active locks are never evicted. Returns False when nothing can go."""
    stale = [k for k, v in _login_fails.items()
             if v[0] <= now and (v[2] if len(v) > 2 else 0) <= now - LOCK_SECONDS]
    for k in stale:
        del _login_fails[k]
    if len(_login_fails) < _LOGIN_FAILS_MAX:
        return True
    unlocked = [(v[2] if len(v) > 2 else 0, k)
                for k, v in _login_fails.items() if v[0] <= now]
    if not unlocked:
        return False
    del _login_fails[min(unlocked)[1]]
    return True


def clear_login_fails(ip: str, username: str) -> None:
    with _login_lock:
        _login_fails.pop(_fail_key(ip, username), None)


def reset_login_guard() -> None:
    """Forget all in-process lockout counters (ops/test hook; restarts do
    the same thing in production)."""
    with _login_lock:
        _login_fails.clear()


# ---------------------------------------------------------------- CLI

def fmt_bytes(n: int) -> str:
    n = float(n or 0)
    if n < 1024:
        return f'{int(n)} B'
    for unit in ('KB', 'MB', 'GB', 'TB'):
        n /= 1024
        if n < 1024:
            return f'{n:.1f} {unit}'
    return f'{n:.1f} TB'


def usage_view(rec: Dict[str, Any]) -> str:
    quota = int(rec.get('quota_bytes') or 0)
    used = int(rec.get('used_bytes') or 0)
    if quota <= 0:
        return f'{fmt_bytes(used)} / 不限量'
    pct = min(100.0, used / quota * 100)
    return f'{fmt_bytes(used)} / {fmt_bytes(quota)} ({pct:.0f}%)'


def cmd_add_admin(args: argparse.Namespace) -> int:
    if args.password_stdin:
        password = sys.stdin.readline().rstrip('\n')
        err = validate_password(password)
        if err:
            raise SystemExit(err)
    else:
        password = _prompt_password(f'为 [{args.username}] 设置密码')
    expire_ts = int(time.time()) + args.expire_days * 86400 if args.expire_days else 0
    quota_bytes = int(args.quota_gb * (1 << 30)) if args.quota_gb else 0
    rec = create_user(users_file(), args.username, password, role='admin',
                      quota_bytes=quota_bytes, reset_day=args.reset_day,
                      expire_ts=expire_ts, notes=args.notes or '')
    audit_cli('user.create', target=rec['username'],
              quota_gb=args.quota_gb, expire_days=args.expire_days, role='admin')
    print(f'admin [{rec["username"]}] created (id={rec["id"]})')
    return 0


def cmd_set_quota(args: argparse.Namespace) -> int:
    if args.gb < 0:
        raise SystemExit('配额不能为负数（0 = 不限量）')
    quota_bytes = int(args.gb * (1 << 30)) if args.gb else 0
    rec = _update_by_name(users_file(), args.username,
                          lambda r: r.update(quota_bytes=quota_bytes))
    audit_cli('user.set-quota', target=rec['username'], value=args.gb)
    print(f'[{rec["username"]}] quota -> {usage_view(rec)}')
    return 0


def cmd_set_expire(args: argparse.Namespace) -> int:
    if args.days < 0:
        raise SystemExit('天数不能为负数（--never = 永不过期）')
    expire_ts = 0 if args.never else int(time.time()) + args.days * 86400
    rec = _update_by_name(users_file(), args.username,
                          lambda r: r.update(expire_ts=expire_ts))
    audit_cli('user.set-expire', target=rec['username'], value=args.days)
    print(f'[{rec["username"]}] expire -> '
          f'{time.strftime("%Y-%m-%d", time.localtime(expire_ts)) if expire_ts else "never"}')
    return 0


def cmd_reset_password(args: argparse.Namespace) -> int:
    if args.password_stdin:
        password = sys.stdin.readline().rstrip('\n')
        err = validate_password(password)
        if err:
            raise SystemExit(err)
    else:
        password = _prompt_password(f'为 [{args.username}] 设置新密码')
    rec = set_password_by_name(users_file(), args.username, password)
    audit_cli('user.reset-password', target=rec['username'])
    print(f'[{rec["username"]}] password updated (existing sessions revoked)')
    return 0


def cmd_set_status(args: argparse.Namespace) -> int:
    status = 'disabled' if args.action == 'disable' else 'active'
    with locked(users_file()):
        records = load(users_file())
        rec = find_by_username(records, args.username)
        if rec is None:
            raise SystemExit(f'user not found: {args.username}')
    rec = set_status(users_file(), rec['id'], status)
    audit_cli(f'user.{args.action}', target=rec['username'])
    print(f'[{rec["username"]}] status -> {status} (sessions revoked)')
    return 0


def cmd_gen_node_users(args: argparse.Namespace) -> int:
    entries = ensure_node_credentials(users_file(), args.node)
    if args.type == 'vless':
        for e in entries:
            e.pop('password', None)
    audit_cli('node.users-assigned', target=args.node, count=len(entries),
              type=args.type)
    print(json.dumps(entries, ensure_ascii=False, indent=2))
    return 0


def cmd_set_email(args: argparse.Namespace) -> int:
    email = args.email.strip().lower()
    err = validate_email(email)
    if err:
        raise SystemExit(f'{err}（留空 = 清除）')
    rec = _update_by_name(users_file(), args.username,
                          lambda r: r.update(email=email))
    audit_cli('user.set-email', target=rec['username'])
    print(f'[{rec["username"]}] email -> {email or "(cleared)"}')
    return 0


def set_status(path: Path, uid: str, status: str) -> Dict[str, Any]:
    """Enable/disable an account. Bumping session_epoch here means a
    disabled user loses every live session immediately - 'disabled' covers
    the web face, not just the subscription gate."""
    if status not in ('active', 'disabled'):
        raise ValueError(f'invalid status: {status}')

    def _m(r: Dict[str, Any]) -> None:
        r['status'] = status
        r['session_epoch'] = int(r.get('session_epoch', 0) or 0) + 1

    return update_user(path, uid, _m)


def session_needs_slide(payload: Dict[str, Any], now: Optional[int] = None) -> bool:
    """Sliding-expiry predicate: re-issue when less than half the session
    TTL remains, so an actively used session never hits a hard logout.
    Expired payloads are already rejected by read_session."""
    remaining = int(payload.get('exp', 0) or 0) - int(now or time.time())
    return 0 < remaining <= SESSION_TTL // 2


def cmd_rotate_node_credential(args: argparse.Namespace) -> int:
    try:
        rec = rotate_node_credential(users_file(), args.username, args.node)
    except KeyError as e:
        raise SystemExit(str(e))
    audit_cli('user.rotate-node-credential', target=rec['username'], node=args.node)
    print(f'[{rec["username"]}] credential for [{args.node}] rotated '
          f'-> {rec["credentials"][args.node]["uuid"]}')
    print('NOTE: sync the node\'s sing-box config with the new uuid, or that '
          'user loses connectivity on this node.')
    return 0


def cmd_list(_args: argparse.Namespace) -> int:
    with locked(users_file()):
        records = load(users_file())
    for r in records:
        expire = (time.strftime('%Y-%m-%d', time.localtime(r['expire_ts']))
                  if r.get('expire_ts') else 'never')
        email = r.get('email') or '-'
        print(f'{r["id"]:14} {r["username"]:20} {r.get("role", "user"):6} '
              f'{r.get("status", "active"):9} {usage_view(r):34} expire={expire} '
              f'token={r.get("token_id") or "-"} {email}')
    return 0


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    sub = ap.add_subparsers(dest='cmd', required=True)

    p = sub.add_parser('add-admin', help='create an admin account')
    p.add_argument('username')
    p.add_argument('--password-stdin', action='store_true',
                   help='read the password from stdin (one line) instead of prompting')
    p.add_argument('--quota-gb', type=float, default=0, help='monthly quota GB (0 = unlimited)')
    p.add_argument('--expire-days', type=int, default=0, help='days from now (0 = never)')
    p.add_argument('--reset-day', type=int, default=1, help='monthly reset day 1-28')
    p.add_argument('--notes', default='')
    p.set_defaults(func=cmd_add_admin)

    p = sub.add_parser('set-quota', help='set monthly quota GB (0 = unlimited)')
    p.add_argument('username')
    p.add_argument('gb', nargs='?', type=float, default=0)
    p.set_defaults(func=cmd_set_quota)

    p = sub.add_parser('set-expire', help='set expiry')
    p.add_argument('username')
    p.add_argument('--days', type=int, default=0, help='days from now')
    p.add_argument('--never', action='store_true')
    p.set_defaults(func=cmd_set_expire)

    p = sub.add_parser('reset-password', help='reset a password (prompted)')
    p.add_argument('username')
    p.add_argument('--password-stdin', action='store_true',
                   help='read the new password from stdin (one line)')
    p.set_defaults(func=cmd_reset_password)

    p = sub.add_parser('disable', help='disable an account')
    p.add_argument('username')
    p.set_defaults(func=cmd_set_status, action='disable')

    p = sub.add_parser('enable', help='enable an account')
    p.add_argument('username')
    p.set_defaults(func=cmd_set_status, action='enable')

    p = sub.add_parser('gen-node-users', help='print sing-box users entries for a node (assigns per-user uuids)')
    p.add_argument('node')
    p.add_argument('--type', choices=('vless', 'tuic', 'anytls'), default='vless',
                   help='entry shape: vless{name,uuid} / tuic+anytls{name,uuid,password}')
    p.set_defaults(func=cmd_gen_node_users)

    p = sub.add_parser('set-email', help='set the reminder email for an account')
    p.add_argument('username')
    p.add_argument('email')
    p.set_defaults(func=cmd_set_email)

    p = sub.add_parser('rotate-node-credential', help='replace a user\'s uuid on one node (incident response)')
    p.add_argument('username')
    p.add_argument('node')
    p.set_defaults(func=cmd_rotate_node_credential)

    p = sub.add_parser('list', help='list accounts')
    p.set_defaults(func=cmd_list)

    args = ap.parse_args()
    return args.func(args)


if __name__ == '__main__':
    sys.exit(main())
