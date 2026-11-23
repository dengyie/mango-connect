#!/usr/bin/env python3
"""Token store & CLI for mango-share.

tokens.json: [{id, name, token_sha256, created, last_used, revoked}]
- Plaintext token is shown once at creation; only its SHA-256 is stored.
- No PANEL_PASSWORD fallback: a share token never grants panel access.
- Management is CLI-only; the public server has no admin API.

Concurrency: token.json reads/writes are serialized with an flock on a
sidecar .lock file (NFS-safe pattern from clash_lock). The server records
per-request usage to an append-only usage log, never rewriting tokens.json
from the hot path; CLI `list` merges it for display.
"""

from __future__ import annotations

import argparse
import contextlib
import fcntl
import base64
import hashlib
import hmac
import json
import os
import secrets
import sys
import tempfile
import time
from pathlib import Path
from typing import Any, Dict, List, Optional

from state_backup import rotate_log_if_large, snapshot
from share_constants import state_dir

TOKEN_MODE = 0o640


def token_file(env: Optional[Dict[str, str]] = None) -> Path:
    env = env or os.environ
    base = state_dir(env)
    return base / 'tokens.json'


def nodes_file(env: Optional[Dict[str, str]] = None) -> Path:
    """Separate store for node-agent tokens (phase-2 /ingest/traffic);
    same record shape, isolated from recipient tokens."""
    env = env or os.environ
    base = state_dir(env)
    return base / 'nodes.json'


def usage_file(env: Optional[Dict[str, str]] = None) -> Path:
    env = env or os.environ
    base = state_dir(env)
    return base / 'usage.log'


def _usage_for(token_path: Path) -> Path:
    """Usage log lives next to the token store it describes, so tests and
    alternate deployments never mix state dirs."""
    return token_path.parent / 'usage.log'


def _locked(path: Path):
    """Context manager factory: exclusive flock on a sidecar lock file.
    Never creates directories: the store dir must already exist (the deploy
    layout guarantees it); on a machine without the state dir, callers get
    empty/ENOENT semantics instead of silently mkdir-ing the state dir."""
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


def _hash(token: str) -> str:
    return hashlib.sha256(token.encode('utf-8')).hexdigest()


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
    fd, tmp_name = tempfile.mkstemp(prefix='tokens-', suffix='.tmp', dir=str(path.parent))
    tmp = Path(tmp_name)
    try:
        with os.fdopen(fd, 'w', encoding='utf-8') as f:
            f.write(json.dumps(records, ensure_ascii=False, indent=2) + '\n')
        os.chmod(tmp, TOKEN_MODE)
        # Preserve ownership across the atomic replace: the CLI may run as
        # root while the service runs as an unprivileged user; without this,
        # a root-run add/revoke leaves the store unreadable (401->500 outage).
        try:
            st = path.stat()
            os.chown(tmp, st.st_uid, st.st_gid)
        except (PermissionError, OSError):
            pass  # non-root caller: file already belongs to them
        os.replace(tmp, path)
    except BaseException:
        tmp.unlink(missing_ok=True)
        raise


def _save_locked(path: Path, records: List[Dict[str, Any]]) -> None:
    with _locked(path):
        save(path, records)


def verify(path: Path, token: str) -> Optional[Dict[str, Any]]:
    """Return the matching active record, or None. Empty tokens never match.
    Read-only under shared understanding: verification never rewrites the
    store, so a concurrent CLI add/revoke cannot be lost by a lookup."""
    if not token:
        return None
    digest = _hash(token)
    with _locked(path):
        for rec in load(path):
            if rec.get('revoked'):
                continue
            if secrets.compare_digest(str(rec.get('token_sha256') or ''), digest):
                return rec
    return None


def touch(rec: Dict[str, Any], path: Path) -> None:
    """Record a use. Appends to usage.log (cheap, no read-modify-write of
    tokens.json); CLI list merges it for the last_used column.
    No-op when the state dir doesn't exist (local dev / no deployment)."""
    if not path.parent.exists():
        return
    entry = {'id': rec.get('id'), 'name': rec.get('name'), 'at': int(time.time())}
    u = _usage_for(path)
    with _locked(u):
        rotate_log_if_large(u)
        with open(u, 'a', encoding='utf-8') as f:
            f.write(json.dumps(entry, ensure_ascii=False) + '\n')


def last_used_map(path: Path) -> Dict[str, int]:
    """Latest usage timestamp per token id, from the usage log next to the
    token store."""
    u = _usage_for(path)
    if not u.exists():
        return {}
    latest: Dict[str, int] = {}
    with _locked(u):
        for line in u.read_text(encoding='utf-8').splitlines():
            try:
                e = json.loads(line)
            except ValueError:
                continue
            if isinstance(e.get('at'), int):
                latest[str(e.get('id'))] = e['at']
    return latest


def derive_token(secret: bytes, nonce: str) -> str:
    """Account-bound subscription token: HMAC(secret.key, nonce). Only the
    SHA-256 and the (non-secret) nonce are stored, yet the server can show
    the owner their link again on the dashboard. Anyone holding secret.key
    can already forge sessions and export links, so this adds no new
    exposure; rotating secret.key invalidates the derivation (the hash check
    in recover_token then hides the link instead of showing a wrong one)."""
    mac = hmac.new(secret, b'mango-sub-token|v1|' + nonce.encode('ascii'),
                   hashlib.sha256).digest()
    return base64.urlsafe_b64encode(mac[:24]).decode('ascii')


def recover_token(secret: bytes, rec: Optional[Dict[str, Any]]) -> Optional[str]:
    """Plaintext of a derived, unrevoked token record; None for legacy random
    tokens (never persisted, cannot be shown again) or on any mismatch."""
    if not rec or rec.get('revoked'):
        return None
    nonce = str(rec.get('derive_nonce') or '')
    if not nonce:
        return None
    token = derive_token(secret, nonce)
    if not secrets.compare_digest(_hash(token), str(rec.get('token_sha256') or '')):
        return None
    return token


def find_by_id(path: Path, token_id: str) -> Optional[Dict[str, Any]]:
    for r in load(path):
        if str(r.get('id') or '') == str(token_id or ''):
            return r
    return None


def create_token(path: Path, name: str, owner: str = '',
                 now: Optional[int] = None,
                 secret: Optional[bytes] = None) -> tuple[Dict[str, Any], str]:
    """Create a token record and return (record, plaintext). The plaintext is
    never persisted; `owner` optionally links the token to a users.json
    account id (None/'' = legacy anonymous token). With `secret`, the token
    is derived from it (see derive_token) so its owner can view it again."""
    nonce = secrets.token_hex(16) if secret else ''
    token = derive_token(secret, nonce) if secret else secrets.token_urlsafe(24)
    with _locked(path):
        records = load(path)
        rec = {
            'id': name.lower().replace(' ', '-') or secrets.token_hex(4),
            'name': name,
            'token_sha256': _hash(token),
            'created': int(now or time.time()),
            'last_used': None,
            'revoked': False,
        }
        if nonce:
            rec['derive_nonce'] = nonce
        if owner:
            rec['owner'] = str(owner)
        ids = {r.get('id') for r in records}
        if rec['id'] in ids:
            rec['id'] = f"{rec['id']}-{secrets.token_hex(2)}"
        records.append(rec)
        save(path, records)
    return rec, token


def cmd_add(args: argparse.Namespace) -> int:
    path = nodes_file() if args.nodes else token_file()
    rec, token = create_token(path, args.name, owner=args.owner or '')
    try:
        from users import audit_cli
        audit_cli('token.add', target=rec['name'],
                  kind='node' if args.nodes else 'recipient', owner=rec.get('owner', ''))
    except OSError:
        pass
    print(f'token for [{rec["name"]}] (shown once, store it now):')
    print(token)
    return 0


def revoke_by_id(path: Path, token_id: str) -> int:
    """Revoke by exact record id; returns the number of records revoked."""
    hit = 0
    with _locked(path):
        records = load(path)
        for r in records:
            if str(r.get('id') or '') == str(token_id or '') and not r.get('revoked'):
                r['revoked'] = True
                hit += 1
        if hit:
            save(path, records)
    return hit


def cmd_revoke(args: argparse.Namespace) -> int:
    path = token_file()
    hit = 0
    with _locked(path):
        records = load(path)
        for r in records:
            if r.get('name') == args.name and not r.get('revoked'):
                r['revoked'] = True
                hit += 1
        if hit:
            save(path, records)
    try:
        from users import audit_cli
        audit_cli('token.revoke', target=args.name, count=hit)
    except OSError:
        pass
    print(f'revoked {hit} token(s) for [{args.name}]')
    return 0 if hit else 1


def cmd_list(_args: argparse.Namespace) -> int:
    path = token_file()
    with _locked(path):
        records = load(path)
    usage = last_used_map(path)
    for r in records:
        status = 'REVOKED' if r.get('revoked') else 'active'
        last = usage.get(str(r.get('id')))
        last_s = time.strftime('%Y-%m-%d %H:%M', time.gmtime(last)) if last else 'never'
        owner = r.get('owner') or '-'
        print(f'{r["id"]:24} {r["name"]:20} {status:8} last_used={last_s} owner={owner}')
    return 0


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    sub = ap.add_subparsers(dest='cmd', required=True)
    p_add = sub.add_parser('add', help='create a token for a recipient')
    p_add.add_argument('name')
    p_add.add_argument('--owner', default='', help='users.json account id to link')
    p_add.add_argument('--nodes', action='store_true',
                       help='create a node-agent token (nodes.json) instead')
    p_add.set_defaults(func=cmd_add)
    p_rev = sub.add_parser('revoke', help='revoke tokens by recipient name')
    p_rev.add_argument('name')
    p_rev.set_defaults(func=cmd_revoke)
    p_ls = sub.add_parser('list', help='list tokens')
    p_ls.set_defaults(func=cmd_list)
    args = ap.parse_args()
    return args.func(args)


if __name__ == '__main__':
    sys.exit(main())
