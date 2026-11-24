"""Per-user traffic breakdown for the dashboard / usage API.

Source: traffic-ingest.log and its rotated siblings (append-only JSON lines
written by add_usage: {"user","node","up","down","at"}). The aggregate lives
in users.json; this module answers "when" and "through which node" questions.

Parsing cost is bounded: the log family is the live file plus the timestamped
rotations kept by rotate_log_if_large (8MB x 3), re-parsed at most once per
(mtime_ns, size) change of any member - the same cache pattern as the
token/user read caches. A fresh install without the log returns an empty
frame, never an error; a record with a damaged field is skipped, never fatal.
"""
from __future__ import annotations

import json
import re
import threading
import time
from collections import defaultdict
from pathlib import Path
from typing import Any, Dict, List

_CACHE_TTL = 2.0  # seconds; bounds re-parse frequency under stat races
_MAX_WINDOW_DAYS = 90  # hard cap for any ?days= (UI offers 7/14/30/90)
# add_usage stamps 'at' as int(time.time()); anything outside [0, 2100) is a
# damaged record, and bucketing it would crash strftime on some platforms.
_TS_MIN, _TS_MAX = 0, 4102444800

_CACHE: Dict[str, Any] = {'key': None, 'frames': {}, 'at': 0.0}
_CACHE_LOCK = threading.Lock()


def clamp_days(days: Any, default: int = 14) -> int:
    """Coerce any query-string value to a sane window: non-numeric falls
    back to the default instead of crashing; the window is bounded to
    [1, _MAX_WINDOW_DAYS]."""
    try:
        d = int(str(days).strip() or default)
    except (TypeError, ValueError):
        return default
    return max(1, min(d, _MAX_WINDOW_DAYS))


def _day(ts: int) -> str:
    return time.strftime('%Y-%m-%d', time.localtime(ts))


def _log_family(path: Path) -> List[Path]:
    """Live log + its rotated siblings, oldest first.

    rotate_log_if_large renames traffic-ingest.log ->
    traffic-ingest.log.<YYYYmmdd-HHMMSS> and keeps LOG_KEEP of those, so the
    history is every sibling matching that exact timestamp shape (not the
    .lock sidecar or .tmp scratch files). Sorting by name sorts by
    timestamp; the live file sorts last, keeping records in append order.
    """
    live = Path(path)
    fam = {live}
    try:
        pat = re.compile(re.escape(live.name) + r'\.\d{8}-\d{6}$')
        fam.update(p for p in live.parent.iterdir()
                   if p.is_file() and pat.match(p.name))
    except OSError:
        pass
    return sorted(fam, key=lambda p: p.name)


def _parse_log(path: Path) -> List[dict]:
    """All well-formed report lines; malformed lines are skipped (audit
    log must stay readable even if a writer crashed mid-line)."""
    try:
        raw = path.read_text(encoding='utf-8', errors='replace')
    except OSError:
        return []
    out = []
    for line in raw.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            rec = json.loads(line)
        except ValueError:
            continue
        if isinstance(rec, dict):
            out.append(rec)
    return out


def _load_frames(paths: List[Path]) -> Dict[str, dict]:
    """{username(lower): {daily: {day: [up, down]},
                          by_node: {'day|node': [up, down]}}}

    by_node is keyed "day|node" so per-node totals can be sliced to any
    date window later (an all-time number would overstate 7/14/30d views).
    Memoised on the family's ((path, mtime_ns, size)...) tuple: invalidated
    whenever any member is appended, rotated in/out or deleted. Rotation
    renames the live file aside and creates a fresh one, which changes both
    the family membership and the live file's stats in one step.
    """
    stat_key = []
    for p in paths:
        try:
            st = p.stat()
            stat_key.append((str(p), st.st_mtime_ns, st.st_size))
        except OSError:
            stat_key.append((str(p), -1, -1))
    key = tuple(stat_key)
    now = time.time()
    with _CACHE_LOCK:
        if (_CACHE.get('key') == key
                and now - _CACHE.get('at', 0.0) < _CACHE_TTL):
            return _CACHE['frames']
    frames: Dict[str, dict] = {}
    for p in paths:
        for rec in _parse_log(p):
            user = str(rec.get('user') or '').strip().lower()
            if not user:
                continue
            try:
                up = max(0, int(rec.get('up') or 0))
                down = max(0, int(rec.get('down') or 0))
                at = int(float(rec.get('at') or 0))
            except (TypeError, ValueError, OverflowError):
                continue
            if (up <= 0 and down <= 0) or not (_TS_MIN <= at <= _TS_MAX):
                continue
            node = str(rec.get('node') or 'unknown')
            day = _day(at)
            fr = frames.setdefault(user, {'daily': defaultdict(lambda: [0, 0]),
                                          'by_node': defaultdict(lambda: [0, 0])})
            if up:
                fr['daily'][day][0] += up
                fr['by_node'][f'{day}|{node}'][0] += up
            if down:
                fr['daily'][day][1] += down
                fr['by_node'][f'{day}|{node}'][1] += down
    with _CACHE_LOCK:
        _CACHE['key'] = key
        _CACHE['frames'] = frames
        _CACHE['at'] = now
    return frames


def usage_detail(path: Path, username: str, days: int = 14,
                 now: int | None = None) -> Dict[str, Any]:
    """Daily + per-node breakdown for one user over the last `days` days.

    Returns {'daily': [{'date','up','down'}...] (oldest first, zero-filled),
             'by_node': [{'node','up','down'}...] (busiest first, restricted
             to the same window), 'total': {'up','down'},
             'days': <clamped window>}. Bytes only; no credential material.
    """
    now = int(now or time.time())
    days = clamp_days(days)
    day_keys = [_day(now - 86400 * i) for i in range(days - 1, -1, -1)]
    window = set(day_keys)
    fr = _load_frames(_log_family(path)).get(username.strip().lower())
    daily_out = []
    total_up = total_down = 0
    if fr:
        for k in day_keys:
            up, down = fr['daily'].get(k, [0, 0])
            daily_out.append({'date': k, 'up': up, 'down': down})
            total_up += up
            total_down += down
        agg: Dict[str, List[int]] = defaultdict(lambda: [0, 0])
        for key, (up, down) in fr['by_node'].items():
            day, node = key.split('|', 1)
            if day not in window:
                continue
            agg[node][0] += up
            agg[node][1] += down
        by_node = sorted(
            ({'node': n, 'up': v[0], 'down': v[1]} for n, v in agg.items()),
            key=lambda r: -(r['up'] + r['down']))
    else:
        daily_out = [{'date': k, 'up': 0, 'down': 0} for k in day_keys]
        by_node = []
    return {'daily': daily_out,
            'by_node': by_node[:20],
            'total': {'up': total_up, 'down': total_down},
            'days': days}
