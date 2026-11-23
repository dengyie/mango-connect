#!/usr/bin/env python3
"""Mirror client installers from GitHub releases to the download site.

Runs on the download-site host (local disk, nginx serves --root under
--base-url). For every app of src/clients.py CATALOG:

  1. read the project's latest GitHub release;
  2. download the catalog assets byte-for-byte into <root>/<app>/<tag>/,
     streaming into a .part file, verifying size and (when GitHub publishes
     one) the sha256 digest, then renaming into place - a public URL never
     serves a partial file;
  3. keep the newest --keep version dirs per app (versioned paths mean CDN
     caches never need purging);
  4. write <root>/manifest.json (atomic) which the share site reads.

An app whose release cannot be read keeps its previous manifest entry (its
files are still on disk), so a GitHub hiccup never blanks the page.

    client-mirror.py --root /srv/pub/clients --base-url https://dl.example.com/pub/clients
    client-mirror.py ... --loop 21600        # daemon mode (supervisor)
    client-mirror.py ... --dry-run           # show what would be mirrored
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import random
import shutil
import sys
import tempfile
import time
import traceback
import urllib.request
from pathlib import Path
from typing import Any, Dict, Optional

_HERE = Path(__file__).resolve().parent
for _p in (_HERE, _HERE.parent / 'src'):
    if (_p / 'clients.py').is_file():
        sys.path.insert(0, str(_p))
        break
import clients  # noqa: E402

UA = 'mango-share-client-mirror/1'
RESERVE_BYTES = 2 << 30      # never fill the disk past this headroom
CHUNK = 1 << 20


def log(msg: str) -> None:
    print(f'{time.strftime("%Y-%m-%d %H:%M:%S")} {msg}', flush=True)


def _request(url: str, accept: str = '') -> urllib.request.Request:
    headers = {'User-Agent': UA}
    if accept:
        headers['Accept'] = accept
    token = os.environ.get('GITHUB_TOKEN', '').strip()
    if token and url.startswith('https://api.github.com/'):
        headers['Authorization'] = f'Bearer {token}'
    return urllib.request.Request(url, headers=headers)


def latest_release(repo: str) -> Dict[str, Any]:
    url = f'https://api.github.com/repos/{repo}/releases/latest'
    with urllib.request.urlopen(_request(url, 'application/vnd.github+json'), timeout=30) as r:
        data = json.loads(r.read().decode('utf-8'))
    if not isinstance(data, dict) or not isinstance(data.get('assets'), list):
        raise ValueError(f'unexpected release payload for {repo}')
    return data


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open('rb') as f:
        for block in iter(lambda: f.read(CHUNK), b''):
            h.update(block)
    return h.hexdigest()


def download(url: str, dest: Path, size: int, digest: str, attempts: int = 3) -> str:
    """Stream `url` into dest atomically; returns the sha256 hex."""
    free = shutil.disk_usage(dest.parent).free
    if free - size < RESERVE_BYTES:
        raise OSError(f'disk headroom too small for {dest.name}: free={free} need={size}')
    want = digest.split(':', 1)[1].lower() if digest.startswith('sha256:') else ''
    last: Optional[BaseException] = None
    for attempt in range(1, attempts + 1):
        part = dest.parent / f'.{dest.name}.part'
        try:
            h = hashlib.sha256()
            got = 0
            with urllib.request.urlopen(_request(url), timeout=60) as r, part.open('wb') as f:
                while True:
                    block = r.read(CHUNK)
                    if not block:
                        break
                    f.write(block)
                    h.update(block)
                    got += len(block)
                f.flush()
                os.fsync(f.fileno())
            hexd = h.hexdigest()
            if got != size:
                raise ValueError(f'size mismatch {got} != {size}')
            if want and hexd != want:
                raise ValueError('sha256 mismatch against GitHub digest')
            os.chmod(part, 0o644)
            os.replace(part, dest)
            return hexd
        except Exception as e:  # noqa: BLE001 - retried, then re-raised
            last = e
            part.unlink(missing_ok=True)
            log(f'  retry {attempt}/{attempts} {dest.name}: {type(e).__name__}: {e}')
            time.sleep(5 * attempt)
    assert last is not None
    raise last


def _atomic_text(path: Path, text: str) -> None:
    fd, tmp = tempfile.mkstemp(prefix='.manifest-', suffix='.tmp', dir=str(path.parent))
    try:
        with os.fdopen(fd, 'w', encoding='utf-8') as f:
            f.write(text)
        os.chmod(tmp, 0o644)
        os.replace(tmp, path)
    except BaseException:
        Path(tmp).unlink(missing_ok=True)
        raise


def load_manifest(root: Path) -> Dict[str, Any]:
    try:
        data = json.loads((root / 'manifest.json').read_text(encoding='utf-8'))
        return data if isinstance(data, dict) else {}
    except (OSError, ValueError):
        return {}


def mirror_app(app: 'clients.App', root: Path, base_url: str,
               prev: Dict[str, Any], dry_run: bool) -> Dict[str, Any]:
    rel = latest_release(app.repo)
    tag = str(rel.get('tag_name') or '')
    if not clients.SAFE_TAG.match(tag):
        raise ValueError(f'unsafe tag {tag!r}')
    picked, problems = clients.pick_assets(app, rel['assets'])
    for p in problems:
        log(f'  WARN {p}')
    vdir = root / app.key / tag
    prev_assets = (prev.get('assets') or {}) if prev.get('tag') == tag else {}
    entry: Dict[str, Any] = {'tag': tag, 'published': str(rel.get('published_at') or ''),
                             'release_url': str(rel.get('html_url') or app.releases_url),
                             'assets': {}}
    if dry_run:
        for aid, a in picked.items():
            log(f'  would mirror {app.key}/{tag}/{a["name"]} ({clients.fmt_size(int(a["size"]))})')
        return entry
    vdir.mkdir(parents=True, exist_ok=True)
    os.chmod(vdir, 0o755)
    os.chmod(vdir.parent, 0o755)
    for aid, a in picked.items():
        name, size = str(a['name']), int(a.get('size') or 0)
        dest = vdir / name
        old = prev_assets.get(aid) or {}
        if dest.is_file() and dest.stat().st_size == size and old.get('name') == name \
                and clients._HEX64.match(str(old.get('sha256') or '')):
            sha = old['sha256']
        elif dest.is_file() and dest.stat().st_size == size:
            sha = sha256_file(dest)
            want = str(a.get('digest') or '')
            if want.startswith('sha256:') and want.split(':', 1)[1].lower() != sha:
                log(f'  {name}: on-disk copy fails GitHub digest, re-downloading')
                sha = download(str(a['browser_download_url']), dest, size, want)
        else:
            log(f'  fetch {app.key}/{tag}/{name} ({clients.fmt_size(size)})')
            sha = download(str(a['browser_download_url']), dest, size, str(a.get('digest') or ''))
        entry['assets'][aid] = {
            'name': name, 'size': size, 'sha256': sha,
            'url': f'{base_url}/{app.key}/{tag}/{name}',
            'github_url': str(a['browser_download_url']),
        }
    sums = ''.join(f'{v["sha256"]}  {v["name"]}\n'
                   for v in sorted(entry['assets'].values(), key=lambda v: v['name']))
    _atomic_text(vdir / 'SHA256SUMS', sums)
    return entry


def prune(app_dir: Path, keep_tags: set, keep: int) -> None:
    """Drop old version dirs beyond the newest `keep` (by mtime), never one
    the manifest references."""
    if not app_dir.is_dir():
        return
    dirs = sorted((d for d in app_dir.iterdir() if d.is_dir()),
                  key=lambda d: d.stat().st_mtime, reverse=True)
    for d in dirs[keep:]:
        if d.name in keep_tags:
            continue
        log(f'  prune {app_dir.name}/{d.name}')
        shutil.rmtree(d, ignore_errors=True)


def run_once(root: Path, base_url: str, keep: int, only: Optional[set], dry_run: bool) -> int:
    root.mkdir(parents=True, exist_ok=True)
    for stale in root.glob('*/*/.*.part'):
        stale.unlink(missing_ok=True)
    old = load_manifest(root)
    old_apps = old.get('apps') if isinstance(old.get('apps'), dict) else {}
    apps: Dict[str, Any] = {}
    failures = 0
    for app in clients.CATALOG:
        if only and app.key not in only:
            if app.key in old_apps:
                apps[app.key] = old_apps[app.key]
            continue
        prev = old_apps.get(app.key) or {}
        log(f'{app.key}: checking {app.repo}')
        try:
            entry = mirror_app(app, root, base_url, prev, dry_run)
            if not entry['assets'] and prev and not dry_run:
                raise ValueError('no catalog assets matched the latest release')
            apps[app.key] = entry
            log(f'{app.key}: {entry["tag"]} {len(entry["assets"])}/{len(app.assets)} assets')
        except Exception as e:  # noqa: BLE001 - one app never blocks the rest
            failures += 1
            log(f'{app.key}: FAILED {type(e).__name__}: {e} (keeping previous entry)')
            if prev:
                apps[app.key] = prev
    if dry_run:
        return failures
    manifest = {'version': 1, 'generated': time.time(), 'base_url': base_url, 'apps': apps}
    _atomic_text(root / 'manifest.json', json.dumps(manifest, ensure_ascii=False, indent=1) + '\n')
    for app in clients.CATALOG:
        cur = (apps.get(app.key) or {}).get('tag')
        before = (old_apps.get(app.key) or {}).get('tag')
        prune(root / app.key, {t for t in (cur, before) if t}, keep)
    log(f'manifest written: {len(apps)} apps, '
        f'{sum(len(a.get("assets") or {}) for a in apps.values())} files, {failures} failures')
    return failures


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument('--root', required=True, help='local dir served at --base-url')
    ap.add_argument('--base-url', required=True, help='public https URL of --root')
    ap.add_argument('--keep', type=int, default=2, help='version dirs kept per app (default 2)')
    ap.add_argument('--only', default='', help='comma-separated app keys')
    ap.add_argument('--loop', type=int, default=0, help='seconds between rounds; 0 = run once')
    ap.add_argument('--dry-run', action='store_true')
    args = ap.parse_args(argv)
    base_url = args.base_url.rstrip('/')
    if not base_url.startswith('https://'):
        ap.error('--base-url must be https')
    root = Path(args.root).resolve()
    only = {s.strip() for s in args.only.split(',') if s.strip()} or None
    if only and only - set(clients.APPS_BY_KEY):
        ap.error(f'unknown app keys: {sorted(only - set(clients.APPS_BY_KEY))}')
    keep = max(1, args.keep)
    if not args.loop:
        return 1 if run_once(root, base_url, keep, only, args.dry_run) else 0
    while True:
        try:
            run_once(root, base_url, keep, only, args.dry_run)
        except Exception:  # noqa: BLE001 - daemon keeps going
            traceback.print_exc()
        time.sleep(args.loop + random.randint(0, 300))


if __name__ == '__main__':
    sys.exit(main())
