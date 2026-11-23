#!/usr/bin/env python3
"""Timestamped state snapshots + log rotation + restore for mango-share.

- snapshot(): every tokens.json / users.json write snapshots the current
  file into <state>/backups/ first, keeping the newest BACKUP_KEEP
  rotations, so a bad CLI write or a corrupted store is always one
  file-copy away from recovery.
- rotate_log_if_large(): append-only logs (usage/audit/ingest/notify) are
  size-capped by rename-and-recreate; every call site holds its log's
  sidecar flock, so rotation and appends are mutually exclusive.
- restore(): copy a snapshot back onto its live store path atomically
  (ownership/permissions preserved). Best-effort by design: a snapshot or
  rotation failure never blocks the write it protects.
"""

from __future__ import annotations

import argparse
import os
import sys
import time
from pathlib import Path
from typing import Any, Dict, List, Optional

from share_constants import state_dir

BACKUP_KEEP = 20
DIR_MODE = 0o700
FILE_MODE = 0o640
LOG_MAX_BYTES = 8 * 1024 * 1024
LOG_KEEP = 3


def backup_dir(env: Optional[dict] = None) -> Path:
    env = env or os.environ
    base = state_dir(env)
    return base / 'backups'


def snapshot(path: Path, keep: int = BACKUP_KEEP,
             env: Optional[dict] = None) -> None:
    """Copy the current file to backups/<name>.<ts> and prune old rotations.
    Callers invoke this while already holding the store's flock."""
    try:
        if not path.exists():
            return
        bdir = backup_dir(env)
        bdir.mkdir(parents=True, exist_ok=True)
        try:
            os.chmod(bdir, DIR_MODE)
        except OSError:
            pass
        dest = bdir / f'{path.name}.{time.strftime("%Y%m%d-%H%M%S")}'
        tmp = bdir / (dest.name + '.tmp')
        tmp.write_bytes(path.read_bytes())
        os.chmod(tmp, FILE_MODE)
        try:
            st = path.stat()
            os.chown(tmp, st.st_uid, st.st_gid)
        except OSError:
            pass
        os.replace(tmp, dest)
        prefix = path.name + '.'
        snaps = sorted(p for p in bdir.iterdir() if p.name.startswith(prefix))
        for old in snaps[:-keep]:
            try:
                old.unlink()
            except OSError:
                pass
    except OSError:
        pass


def rotate_log_if_large(path: Path, max_bytes: int = LOG_MAX_BYTES,
                        keep: int = LOG_KEEP) -> None:
    """Rename a grown log aside and start a fresh one (size cap for the
    append-only trails). Best-effort."""
    try:
        if not path.exists() or path.stat().st_size < max_bytes:
            return
        rotated = path.with_suffix(path.suffix + f'.{time.strftime("%Y%m%d-%H%M%S")}')
        os.replace(path, rotated)
        path.parent.mkdir(parents=True, exist_ok=True)
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o640)
        os.close(fd)
        prefix = path.name + '.'
        olds = sorted(p for p in path.parent.iterdir()
                      if p.name.startswith(prefix) and p != path)
        for old in olds[:-keep]:
            try:
                old.unlink()
            except OSError:
                pass
    except OSError:
        pass


def restore(snapshot_path: Path, target: Optional[Path] = None,
            env: Optional[dict] = None) -> Path:
    """Copy a snapshot back onto its live store path (atomic replace,
    mode/ownership preserved). Returns the target path."""
    snap = Path(snapshot_path)
    if not snap.exists():
        raise FileNotFoundError(f'snapshot not found: {snap}')
    if target is None:
        env = env or os.environ
        base = state_dir(env)
        if snap.parent.resolve() != backup_dir(env).resolve():
            raise ValueError(
                'snapshot outside backups/: pass --target explicitly')
        # <store>.<ts> -> <store> under the state dir
        target = base / snap.name.rsplit('.', 1)[0]
    data = snap.read_bytes()
    tmp = Path(str(target) + '.restore.tmp')
    tmp.write_bytes(data)
    os.chmod(tmp, 0o640)
    try:
        st = target.stat() if target.exists() else snap.stat()
        os.chown(tmp, st.st_uid, st.st_gid)
    except OSError:
        pass
    os.replace(tmp, target)
    return target


def list_backups(env: Optional[dict] = None) -> List[Dict[str, Any]]:
    """Enumerate snapshots newest-first with timestamps and sizes."""
    bdir = backup_dir(env)
    out: List[Dict[str, Any]] = []
    if not bdir.exists():
        return out
    for p in sorted(bdir.iterdir(), reverse=True):
        if p.name.endswith('.tmp'):
            continue
        try:
            st = p.stat()
        except OSError:
            continue
        out.append({'file': p.name, 'bytes': st.st_size,
                    'mtime': int(st.st_mtime)})
    return out


def pack(env: Optional[dict] = None, out: Optional[Path] = None) -> Path:
    """Tar the live state (stores, logs, public render; excluding backups/
    logs rotations) into a single archive for off-site copy. Bohrium
    containers are recyclable - this is the grab-and-go artifact."""
    import tarfile
    env = env or os.environ
    base = state_dir(env)
    if out is None:
        out = bdir = backup_dir(env)
        out = bdir / f'state-pack-{time.strftime("%Y%m%d-%H%M%S")}.tar.gz'
    out = Path(out)
    out.parent.mkdir(parents=True, exist_ok=True)
    with tarfile.open(out, 'w:gz') as t:
        for p in sorted(base.rglob('*')):
            rel = p.relative_to(base)
            top = rel.parts[0] if rel.parts else ''
            if top in ('backups', 'logs') or p == out:
                continue
            try:
                # unreadable entries (root-owned __pycache__, broken links)
                # are skipped rather than aborting the whole archive
                if p.is_file() and os.access(p, os.R_OK):
                    t.add(p, arcname=str(rel))
            except OSError:
                continue
    # The archive carries secret.key/tokens/users: owner-only regardless of
    # umask or where --out points.
    os.chmod(out, 0o600)
    return out


def _cmd_pack(args: argparse.Namespace) -> int:
    env = dict(os.environ)
    if args.stdout:
        import io
        import tarfile
        base = state_dir(env)
        buf = io.BytesIO()
        with tarfile.open(fileobj=buf, mode='w:gz') as t:
            for f in sorted(base.rglob('*')):
                rel = f.relative_to(base)
                if rel.parts and rel.parts[0] in ('backups', 'logs'):
                    continue
                try:
                    if f.is_file() and os.access(f, os.R_OK):
                        t.add(f, arcname=str(rel))
                except OSError:
                    continue
        sys.stdout.buffer.write(buf.getvalue())
        return 0
    out = Path(args.out) if args.out else None
    made = pack(env, out)
    print(f'packed -> {made} ({made.stat().st_size} bytes)')
    return 0


def _cmd_restore(args: argparse.Namespace) -> int:
    target = Path(args.target) if args.target else None
    out = restore(Path(args.snapshot), target)
    print(f'restored {args.snapshot} -> {out}')
    return 0


def main() -> int:
    import argparse
    ap = argparse.ArgumentParser(description=__doc__)
    sub = ap.add_subparsers(dest='cmd', required=True)
    p = sub.add_parser('list', help='list available snapshots (newest first)')
    p.set_defaults(func=lambda a: _print_list())
    p = sub.add_parser('pack', help='tar the live state into backups/ for off-site copy')
    p.add_argument('--out', default='', help='override archive path')
    p.add_argument('--stdout', action='store_true', help='write the tarball to stdout')
    p.set_defaults(func=_cmd_pack)
    p = sub.add_parser('restore', help='copy a snapshot back onto its live path')
    p.add_argument('snapshot')
    p.add_argument('--target', default='', help='override live path (default: derived)')
    p.set_defaults(func=_cmd_restore)
    args = ap.parse_args()
    return args.func(args)


def _print_list() -> int:
    rows = list_backups()
    if not rows:
        print('no snapshots yet')
        return 0
    for r in rows:
        when = time.strftime('%Y-%m-%d %H:%M', time.localtime(r['mtime']))
        print(f'{when:>16} {r["bytes"]:>9} {r["file"]}')
    return 0


if __name__ == '__main__':
    sys.exit(main())
