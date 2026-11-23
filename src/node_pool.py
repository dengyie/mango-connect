#!/usr/bin/env python3
"""Self-maintained node pool: available / suspect / dead.

Every node of the gateway's client export is tracked with a small state
machine, probed through the gateway controller (same relay chains the
gateway uses, so a verdict here == "works through our clash"):

    alive    probed every 10 min; 3 consecutive failures  -> suspect
    suspect  probed every 30 min; 2 consecutive successes -> alive
                                  10 consecutive failures -> dead
    dead     probed once a day;   1 success               -> suspect
    unmanaged  in the export but not loaded by the gateway (e.g. IPv6-only
               nodes the IPv4-only gateway host cannot dial): never probed,
               never dropped.

A node's very first probe decides its initial state (success -> alive,
failure -> suspect), so a fresh pool converges in one round instead of
starting everything in quarantine.

Only `dead` nodes leave the subscription (pool-dead.json, read by
render_public); suspect nodes keep being distributed - clients' url-test
groups route around a flaky node, while dropping it on a blip would cost
users a working server.

False-death guards:
- a failure is two failed attempts (the probe function retries once);
- controller/transport errors (gateway down, unknown name) never count;
- breaker: if a round has failures but no success, a few known-good
  "canary" nodes are probed; if they fail too the problem is our side
  (gateway host network), so the round's failures are discarded.
"""
from __future__ import annotations

import json
import os
import tempfile
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Callable, Dict, Iterable, List, Optional, Tuple

ALIVE, SUSPECT, DEAD, UNMANAGED = 'alive', 'suspect', 'dead', 'unmanaged'
STATUSES = (ALIVE, SUSPECT, DEAD, UNMANAGED)

OK, FAIL, ERROR = 'ok', 'fail', 'error'

INTERVAL = {ALIVE: 600, SUSPECT: 1800, DEAD: 86400}
ERROR_RETRY = 120              # transport error / breaker: retry soon, no count
ALIVE_FAILS_TO_SUSPECT = 3
SUSPECT_FAILS_TO_DEAD = 10
SUSPECT_OKS_TO_ALIVE = 2
CANARIES = 3
EVENTS_KEEP = 200

ProbeFn = Callable[[str], Tuple[str, Optional[int]]]


def new_record(now: float) -> dict:
    return {'status': SUSPECT, 'probed': False, 'fails': 0, 'oks': 0,
            'delay': None, 'last_ok': None, 'last_probe': None,
            'since': now, 'next_due': now}


def apply_outcome(rec: dict, outcome: str, delay: Optional[int],
                  now: float) -> Optional[Tuple[str, str]]:
    """Advance one record; returns (old, new) on a status change."""
    old = rec['status']
    if outcome == ERROR:
        rec['next_due'] = now + ERROR_RETRY
        return None
    first = not rec.get('probed')
    rec['probed'] = True
    rec['last_probe'] = now
    new = old
    if outcome == OK:
        rec['fails'] = 0
        rec['oks'] = int(rec.get('oks') or 0) + 1
        rec['delay'] = delay
        rec['last_ok'] = now
        if first:
            new = ALIVE
        elif old == DEAD:
            new = SUSPECT
        elif old == SUSPECT and rec['oks'] >= SUSPECT_OKS_TO_ALIVE:
            new = ALIVE
    else:
        rec['oks'] = 0
        rec['fails'] = int(rec.get('fails') or 0) + 1
        if first:
            new = SUSPECT
        elif old == ALIVE and rec['fails'] >= ALIVE_FAILS_TO_SUSPECT:
            new = SUSPECT
        elif old == SUSPECT and rec['fails'] >= SUSPECT_FAILS_TO_DEAD:
            new = DEAD
    if new != old:
        rec['status'] = new
        rec['since'] = now
        # each state counts its own streak from zero
        if not (first and new == SUSPECT):
            rec['fails'] = 0
        if new != ALIVE and outcome == OK:
            rec['oks'] = 1
    rec['next_due'] = now + INTERVAL[rec['status']]
    return (old, new) if new != old else None


def _atomic_write(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp_name = tempfile.mkstemp(prefix='.pool-', suffix='.tmp', dir=str(path.parent))
    tmp = Path(tmp_name)
    try:
        with os.fdopen(fd, 'w', encoding='utf-8') as f:
            f.write(text)
        os.chmod(tmp, 0o640)
        os.replace(tmp, path)
    except BaseException:
        tmp.unlink(missing_ok=True)
        raise


class NodePool:
    """Thread-safe pool persisted to `path`; the dead list is mirrored to
    `dead_path` ({"nodes": [...]}) only when it changes, so the renderer's
    input fingerprint moves only on real membership changes."""

    def __init__(self, path: Path, dead_path: Path) -> None:
        self.path = Path(path)
        self.dead_path = Path(dead_path)
        self.lock = threading.Lock()
        self.nodes: Dict[str, dict] = {}
        self.events: List[dict] = []
        self.last_round: Optional[float] = None
        self.last_error = ''
        self._load()

    # -- persistence -----------------------------------------------------
    def _load(self) -> None:
        try:
            data = json.loads(self.path.read_text(encoding='utf-8'))
        except (OSError, ValueError):
            return
        if not isinstance(data, dict):
            return
        nodes = data.get('nodes')
        if isinstance(nodes, dict):
            self.nodes = {str(k): v for k, v in nodes.items()
                          if isinstance(v, dict) and v.get('status') in STATUSES}
        ev = data.get('events')
        if isinstance(ev, list):
            self.events = ev[-EVENTS_KEEP:]
        if isinstance(data.get('last_round'), (int, float)):
            self.last_round = float(data['last_round'])

    def _save_locked(self) -> None:
        _atomic_write(self.path, json.dumps(
            {'version': 1, 'last_round': self.last_round,
             'nodes': self.nodes, 'events': self.events[-EVENTS_KEEP:]},
            ensure_ascii=False, indent=1) + '\n')
        dead = sorted(n for n, r in self.nodes.items() if r['status'] == DEAD)
        try:
            current = json.loads(self.dead_path.read_text(encoding='utf-8')).get('nodes')
        except (OSError, ValueError, AttributeError):
            current = None
        if current != dead:
            _atomic_write(self.dead_path,
                          json.dumps({'nodes': dead}, ensure_ascii=False, indent=1) + '\n')

    def save(self) -> None:
        with self.lock:
            self._save_locked()

    # -- membership ------------------------------------------------------
    def sync(self, names: Iterable[str], managed: Optional[set],
             now: Optional[float] = None) -> None:
        """Track exactly `names` (the export). `managed` = names the gateway
        can probe; None = unknown (gateway unreachable): leave states as-is."""
        now = time.time() if now is None else now
        names = list(dict.fromkeys(names))
        with self.lock:
            for gone in set(self.nodes) - set(names):
                del self.nodes[gone]
            for n in names:
                rec = self.nodes.get(n)
                if rec is None:
                    rec = self.nodes[n] = new_record(now)
                if managed is None:
                    continue
                if n not in managed:
                    if rec['status'] != UNMANAGED:
                        self.nodes[n] = dict(new_record(now), status=UNMANAGED)
                elif rec['status'] == UNMANAGED:
                    self.nodes[n] = new_record(now)

    # -- probing ---------------------------------------------------------
    def due(self, now: float, limit: int) -> List[str]:
        with self.lock:
            rows = [(r['next_due'], n) for n, r in self.nodes.items()
                    if r['status'] != UNMANAGED and r['next_due'] <= now]
        rows.sort()
        return [n for _, n in rows[:limit]]

    def _canaries(self, exclude: set) -> List[str]:
        with self.lock:
            rows = [(r.get('delay') or 1 << 30, n) for n, r in self.nodes.items()
                    if r['status'] == ALIVE and n not in exclude]
        rows.sort()
        return [n for _, n in rows[:CANARIES]]

    def run_round(self, probe: ProbeFn, *, now: Optional[float] = None,
                  limit: int = 40, workers: int = 4) -> List[Tuple[str, str, str]]:
        """Probe every due node (up to `limit`), apply the breaker, persist.
        Returns the status changes [(name, old, new)]."""
        now = time.time() if now is None else now
        names = self.due(now, limit)
        if not names:
            return []
        with ThreadPoolExecutor(max_workers=max(1, workers)) as pool:
            results = dict(zip(names, pool.map(probe, names)))
        outcomes = [o for o, _ in results.values()]
        if FAIL in outcomes and OK not in outcomes:
            canaries = self._canaries(set(names))
            if canaries:
                with ThreadPoolExecutor(max_workers=max(1, workers)) as pool:
                    checks = list(pool.map(probe, canaries))
                if not any(o == OK for o, _ in checks):
                    # our side is down, not the nodes: discard the failures
                    results = {n: ((ERROR, None) if o == FAIL else (o, d))
                               for n, (o, d) in results.items()}
                    self.last_error = 'probe breaker: canaries unreachable'
        changes: List[Tuple[str, str, str]] = []
        with self.lock:
            for n, (outcome, delay) in results.items():
                rec = self.nodes.get(n)
                if rec is None:
                    continue
                ch = apply_outcome(rec, outcome, delay, now)
                if ch:
                    changes.append((n, ch[0], ch[1]))
                    self.events.append({'ts': now, 'name': n,
                                        'from': ch[0], 'to': ch[1]})
            self.events = self.events[-EVENTS_KEEP:]
            if any(o != ERROR for o, _ in results.values()):
                self.last_round = now
                self.last_error = ''
            self._save_locked()
        return changes

    # -- views -----------------------------------------------------------
    def snapshot(self) -> Dict[str, dict]:
        with self.lock:
            return {n: dict(r) for n, r in self.nodes.items()}

    def dead_names(self) -> List[str]:
        with self.lock:
            return sorted(n for n, r in self.nodes.items() if r['status'] == DEAD)

    def counts(self) -> Dict[str, int]:
        out = {s: 0 for s in STATUSES}
        with self.lock:
            for r in self.nodes.values():
                out[r['status']] += 1
        return out
