#!/usr/bin/env python3
"""Reminder emails for mango-share (quota / expiry), via one-mail.

Transport: one-mail external API (`POST {base}/external/api/send_mail`,
fields token/from_name/to_mail/to_name/subject/content/is_html) — the same
channel mangoshare-account uses. Config via env:
  ONE_MAIL_API_BASE   e.g. https://mail-api.example.com
  ONE_MAIL_SEND_TOKEN address JWT of this service's sending address
Unconfigured -> log transport (notify.log) so the reminder engine is
testable and the operator sees what WOULD be sent before wiring the token.

Reminders: active users whose account expires within REMIND_EXPIRY_DAYS or
whose period usage crossed REMIND_QUOTA_PCT get one mail per kind per
REMIND_COOLDOWN days (dedup state in notify_state.json).

CLI: python3 notify.py check-reminders [--dry-run]
"""

from __future__ import annotations

import argparse
import html
import json
import os
import tempfile
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import users as us
from state_backup import rotate_log_if_large, snapshot
from share_constants import public_host, state_dir

REMIND_EXPIRY_DAYS = 7
REMIND_QUOTA_PCT = 85
REMIND_COOLDOWN = 7 * 24 * 3600
STATE_FILE = 'notify_state.json'


def state_file(env: Optional[Dict[str, str]] = None) -> Path:
    env = env or os.environ
    base = state_dir(env)
    return base / STATE_FILE


def _log_path(env: Optional[Dict[str, str]] = None) -> Path:
    env = env or os.environ
    base = state_dir(env)
    return base / 'notify.log'


def one_mail_configured(env: Optional[Dict[str, str]] = None) -> bool:
    env = env or os.environ
    return bool(env.get('ONE_MAIL_API_BASE')) and bool(env.get('ONE_MAIL_SEND_TOKEN'))


def send_mail(to: str, subject: str, html: str,
              env: Optional[Dict[str, str]] = None) -> Tuple[bool, str]:
    """Send via one-mail; without a configured token, log the would-be mail
    instead and report False so callers keep the dedup state untouched."""
    env = env or os.environ
    if not to or '@' not in to:
        return False, 'no recipient address'
    base = env.get('ONE_MAIL_API_BASE', '')
    token = env.get('ONE_MAIL_SEND_TOKEN', '')
    entry = {'at': int(time.time()), 'to': to, 'subject': subject}
    if not base or not token:
        entry['transport'] = 'log(unconfigured)'
        _append_log(entry, env)
        return False, 'one-mail not configured'
    body = json.dumps({
        'token': token,
        'from_name': 'mango-connect',
        'to_mail': to,
        'to_name': to.split('@', 1)[0],
        'subject': subject,
        'content': html,
        'is_html': True,
    }).encode('utf-8')
    req = urllib.request.Request(
        base.rstrip('/') + '/external/api/send_mail', data=body,
        headers={'Content-Type': 'application/json',
                 'User-Agent': 'mango-share-notify/1'}, method='POST')
    try:
        with urllib.request.urlopen(req, timeout=15) as resp:
            entry['status'] = resp.status
            _append_log(entry, env)
            # one-mail may answer 200 or 202 (accepted): any 2xx means the
            # mail is on its way and must be recorded as sent, otherwise a
            # persistent condition would re-send every cooldown window.
            return 200 <= resp.status < 300, f'status {resp.status}'
    except urllib.error.HTTPError as e:
        entry.update(status=e.code, detail=e.read(256).decode('utf-8', 'replace'))
        _append_log(entry, env)
        return False, f'HTTP {e.code}'
    except OSError as e:
        entry['detail'] = str(e)[:256]
        _append_log(entry, env)
        return False, str(e)[:128]


def _append_log(entry: Dict[str, Any], env: Optional[Dict[str, str]] = None) -> None:
    p = _log_path(env)
    if not p.parent.exists():
        return
    with us.locked(p):
        rotate_log_if_large(p)
        with open(p, 'a', encoding='utf-8') as f:
            f.write(json.dumps(entry, ensure_ascii=False) + '\n')


def _load_state(path: Path) -> Dict[str, int]:
    try:
        data = json.loads(path.read_text(encoding='utf-8'))
        return data if isinstance(data, dict) else {}
    except (OSError, ValueError):
        return {}


def _save_state(path: Path, state: Dict[str, int]) -> None:
    snapshot(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp_name = tempfile.mkstemp(
        prefix='notify-state-', suffix='.tmp', dir=str(path.parent))
    tmp = Path(tmp_name)
    try:
        with os.fdopen(fd, 'w', encoding='utf-8') as f:
            f.write(json.dumps(state, ensure_ascii=False, indent=2) + '\n')
        os.chmod(tmp, 0o640)
        try:
            st = path.stat()
            os.chown(tmp, st.st_uid, st.st_gid)
        except OSError:
            pass
        os.replace(tmp, path)
    except BaseException:
        tmp.unlink(missing_ok=True)
        raise


def pending_reminders(records: List[Dict[str, Any]],
                      now: Optional[int] = None) -> List[Tuple[Dict[str, Any], str, str]]:
    """(user, kind, subject) pairs that currently deserve a reminder."""
    now = int(now or time.time())
    out: List[Tuple[Dict[str, Any], str, str]] = []
    for r in records:
        if r.get('status') != 'active':
            continue
        expire = int(r.get('expire_ts') or 0)
        if expire and 0 < expire - now <= REMIND_EXPIRY_DAYS * 86400:
            days = max(1, (expire - now) // 86400)
            out.append((r, 'expiry', f'【mango-connect】订阅将于 {days} 天后到期'))
        quota = int(r.get('quota_bytes') or 0)
        used = int(r.get('used_bytes') or 0)
        if quota and used >= quota * REMIND_QUOTA_PCT // 100:
            pct = min(100, used * 100 // quota)
            out.append((r, 'quota', f'【mango-connect】本期流量已用 {pct}%'))
    return out


def check_reminders(path: Path, dry_run: bool = False,
                    env: Optional[Dict[str, str]] = None,
                    now: Optional[int] = None) -> Dict[str, Any]:
    """Scan accounts, send due reminders, persist dedup state."""
    env = env or os.environ
    now = int(now or time.time())
    state_path = path.parent / STATE_FILE
    # Serialize overlapping runs (cron + manual) under the state sidecar flock:
    # the send-then-record sequence must be atomic or two runners double-send.
    with us.locked(state_path):
        state = _load_state(state_path)
        records = us.load(path)
        sent, skipped_cooldown, skipped_noemail = [], [], []
        for rec, kind, subject in pending_reminders(records, now):
            key = f"{rec['id']}:{kind}"
            last = state.get(key, 0)
            if now - last < REMIND_COOLDOWN:
                skipped_cooldown.append(key)
                continue
            email = str(rec.get('email') or '')
            if not email or '@' not in email:
                skipped_noemail.append(key)
                continue
            body = _mail_body(rec, kind, now)
            if dry_run:
                sent.append({'key': key, 'dry': True})
                continue
            ok, detail = send_mail(email, subject, body, env)
            if ok:
                state[key] = now
                sent.append({'key': key, 'to': email})
            else:
                skipped_noemail.append(f'{key} ({detail})')
        if not dry_run:
            _save_state(state_path, state)
    return {'sent': sent, 'cooldown': skipped_cooldown,
            'unsent': skipped_noemail, 'dry_run': dry_run}


def _mail_body(rec: Dict[str, Any], kind: str, now: int) -> str:
    expire = int(rec.get('expire_ts') or 0)
    quota = int(rec.get('quota_bytes') or 0)
    used = int(rec.get('used_bytes') or 0)
    rows = ''
    if kind == 'expiry':
        rows = (f'<p>你的订阅账号将于 <strong>{time.strftime("%Y-%m-%d", time.localtime(expire))}</strong> '
                f'到期。到期后订阅将停止服务，如需续期请联系分享者。</p>')
    else:
        rows = (f'<p>本期流量已使用 <strong>{us.fmt_bytes(used)} / {us.fmt_bytes(quota)}</strong>。'
                f'达到配额后订阅将暂停，下个周期自动恢复。</p>')
    return (f'<div style="font-family:sans-serif;max-width:560px">'
            f'<h2 style="color:#c2410c">mango-connect 订阅提醒</h2>{rows}'
            f'<p>登录管理：<a href="{html.escape(public_host())}/login">'
            f'{html.escape(public_host())}/login</a></p>'
            f'<p style="color:#888;font-size:12px">此为系统提醒，请勿回复。'
            f'账号：{html.escape(str(rec.get("username", "")))}</p></div>')


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    sub = ap.add_subparsers(dest='cmd', required=True)
    p = sub.add_parser('check-reminders', help='send due quota/expiry reminders')
    p.add_argument('--dry-run', action='store_true', help='list what would be sent')
    args = ap.parse_args()
    result = check_reminders(us.users_file(), dry_run=args.dry_run)
    print(json.dumps(result, ensure_ascii=False, indent=2))
    return 0


if __name__ == '__main__':
    sys.exit(main())
