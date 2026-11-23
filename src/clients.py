#!/usr/bin/env python3
"""Client software catalog + download-mirror manifest.

One catalog feeds both sides:
- scripts/client-mirror.py (runs next to the download site) picks the
  assets below out of each project's latest GitHub release, mirrors them
  byte-for-byte and publishes a manifest.json;
- the /clients page renders the catalog, preferring mirror links from the
  manifest and falling back to the GitHub release page per asset, so the
  page is complete even when the mirror is down or not configured.

Asset patterns are anchored regexes on the GitHub asset file name; each
must match exactly one asset of a release (see `pick_assets`).
"""
from __future__ import annotations

import json
import os
import re
import tempfile
import threading
import time
import urllib.request
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Mapping, Sequence, Tuple

PLATFORMS: Tuple[Tuple[str, str], ...] = (
    ('windows', 'Windows'),
    ('macos', 'macOS'),
    ('android', 'Android'),
    ('ios', 'iOS / iPadOS'),
    ('linux', 'Linux'),
)

# Subscription format each client consumes; drives the "导入方式" hint.
FORMAT_HINT = {
    'clash': 'Clash YAML · 用户中心「一键导入」或粘贴订阅链接',
    'singbox': 'Sing-Box JSON · 用户中心「一键导入 Sing-Box」或下载 JSON',
    'uri': 'URI 列表 · 订阅链接末尾加 ?fmt=uri（已含 ? 时用 &fmt=uri）后添加为订阅',
    'surge': 'Surge CONF · 用户中心「一键导入」',
    'qx': 'Quantumult X · 用户中心「一键导入」',
}

SAFE_NAME = re.compile(r'^[A-Za-z0-9][A-Za-z0-9._+-]{0,199}$')
SAFE_TAG = re.compile(r'^[A-Za-z0-9][A-Za-z0-9._+-]{0,63}$')


@dataclass(frozen=True)
class Asset:
    id: str          # stable key inside an app, e.g. "windows-x64"
    platform: str    # one of PLATFORMS
    label: str       # human label, e.g. "x64 安装包"
    pattern: str     # anchored regex on the release asset name


@dataclass(frozen=True)
class App:
    key: str
    name: str
    repo: str
    blurb: str
    fmt: str
    recommended: Tuple[str, ...] = ()   # platforms where this is the pick
    assets: Tuple[Asset, ...] = ()

    @property
    def releases_url(self) -> str:
        return f'https://github.com/{self.repo}/releases/latest'

    @property
    def repo_url(self) -> str:
        return f'https://github.com/{self.repo}'


@dataclass(frozen=True)
class StoreApp:
    key: str
    name: str
    url: str
    price: str
    blurb: str
    fmt: str
    recommended: bool = False


# Version fragment inside asset names: dotted numbers plus an optional
# numeric build suffix ("2.5.10-1"). Deliberately no letters, so variants
# like "SFA-1.14.4-legacy-android-5-..." never satisfy a plain pattern.
V = r'[0-9]+(?:\.[0-9]+)*(?:-[0-9]+)?'

CATALOG: Tuple[App, ...] = (
    App('clash-verge-rev', 'Clash Verge Rev', 'clash-verge-rev/clash-verge-rev',
        '桌面端首选：Mihomo 内核，图形界面完整，支持 clash:// 一键导入与自动更新订阅。',
        'clash', recommended=('windows', 'macos', 'linux'), assets=(
            Asset('windows-x64', 'windows', 'x64 安装包', rf'^Clash\.Verge_{V}_x64-setup\.exe$'),
            Asset('windows-arm64', 'windows', 'ARM64 安装包', rf'^Clash\.Verge_{V}_arm64-setup\.exe$'),
            Asset('macos-arm64', 'macos', 'Apple 芯片 (M 系列)', rf'^Clash\.Verge_{V}_aarch64\.dmg$'),
            Asset('macos-x64', 'macos', 'Intel 芯片', rf'^Clash\.Verge_{V}_x64\.dmg$'),
            Asset('linux-amd64-deb', 'linux', 'x64 · deb', rf'^Clash\.Verge_{V}_amd64\.deb$'),
            Asset('linux-arm64-deb', 'linux', 'ARM64 · deb', rf'^Clash\.Verge_{V}_arm64\.deb$'),
            Asset('linux-x86_64-rpm', 'linux', 'x64 · rpm', rf'^Clash\.Verge-{V}\.x86_64\.rpm$'),
        )),
    App('flclash', 'FlClash', 'chen08209/FlClash',
        '全平台 Mihomo 客户端，界面简洁；Android 上的推荐选择，支持 clash:// 一键导入。',
        'clash', recommended=('android',), assets=(
            Asset('android-arm64', 'android', 'arm64-v8a（绝大多数手机）', rf'^FlClash-{V}-android-arm64-v8a\.apk$'),
            Asset('android-armv7', 'android', 'armeabi-v7a（老旧 32 位机型）', rf'^FlClash-{V}-android-armeabi-v7a\.apk$'),
            Asset('windows-x64', 'windows', 'x64 安装包', rf'^FlClash-{V}-windows-amd64-setup\.exe$'),
            Asset('macos-arm64', 'macos', 'Apple 芯片 (M 系列)', rf'^FlClash-{V}-macos-arm64\.dmg$'),
            Asset('macos-x64', 'macos', 'Intel 芯片', rf'^FlClash-{V}-macos-amd64\.dmg$'),
            Asset('linux-amd64-deb', 'linux', 'x64 · deb', rf'^FlClash-{V}-linux-amd64\.deb$'),
        )),
    App('cmfa', 'Clash Meta for Android', 'MetaCubeX/ClashMetaForAndroid',
        'MetaCubeX 官方 Android 客户端，轻量稳定，支持 clash:// 一键导入。',
        'clash', assets=(
            Asset('android-arm64', 'android', 'arm64-v8a（绝大多数手机）', rf'^cmfa-{V}-meta-arm64-v8a-release\.apk$'),
            Asset('android-armv7', 'android', 'armeabi-v7a（老旧 32 位机型）', rf'^cmfa-{V}-meta-armeabi-v7a-release\.apk$'),
        )),
    App('sing-box', 'sing-box', 'SagerNet/sing-box',
        'sing-box 官方图形客户端（SFA / SFM / SFW / SFL），使用本站 Sing-Box JSON 订阅。',
        'singbox', assets=(
            Asset('android-arm64', 'android', 'SFA · arm64-v8a', rf'^SFA-{V}-arm64-v8a\.apk$'),
            Asset('windows-x64', 'windows', 'SFW · x64', rf'^SFW-{V}-x64\.exe$'),
            Asset('macos-arm64', 'macos', 'SFM · Apple 芯片', rf'^SFM-{V}-Apple\.pkg$'),
            Asset('macos-x64', 'macos', 'SFM · Intel 芯片', rf'^SFM-{V}-Intel\.pkg$'),
            Asset('linux-amd64-deb', 'linux', 'SFL · x64 · deb', rf'^SFL-{V}-amd64\.deb$'),
        )),
    App('v2rayn', 'v2rayN', '2dust/v2rayN',
        'Windows 老牌客户端，使用 URI 列表订阅（?fmt=uri）；中继链节点不支持。',
        'uri', assets=(
            Asset('windows-x64', 'windows', 'x64 · zip（解压即用）', r'^v2rayN-windows-64\.zip$'),
        )),
    App('v2rayng', 'v2rayNG', '2dust/v2rayNG',
        'Android 老牌客户端，使用 URI 列表订阅（?fmt=uri）；中继链节点不支持。',
        'uri', assets=(
            Asset('android-arm64', 'android', 'arm64-v8a', rf'^v2rayNG_{V}_arm64-v8a\.apk$'),
            Asset('android-armv7', 'android', 'armeabi-v7a', rf'^v2rayNG_{V}_armeabi-v7a\.apk$'),
        )),
)

STORE_APPS: Tuple[StoreApp, ...] = (
    StoreApp('shadowrocket', 'Shadowrocket', 'https://apps.apple.com/us/app/shadowrocket/id932747118',
             '付费', '小火箭：iOS 最常用，直接导入 Clash YAML。', 'clash', recommended=True),
    StoreApp('stash', 'Stash', 'https://apps.apple.com/us/app/stash-rule-based-proxy/id1596063349',
             '付费', 'Clash 规则体系原生客户端，策略组与规则完整生效。', 'clash'),
    StoreApp('surge', 'Surge', 'https://apps.apple.com/us/app/surge-6/id1442620678',
             '免费下载 · 功能订阅', '高级网络工具箱，使用本站 Surge CONF 托管配置。', 'surge'),
    StoreApp('quantumult-x', 'Quantumult X', 'https://apps.apple.com/us/app/quantumult-x/id1443988620',
             '付费', '使用本站 Quantumult X 格式（中继链与 reality 节点省略）。', 'qx'),
)

APPS_BY_KEY: Dict[str, App] = {a.key: a for a in CATALOG}


# ---------------------------------------------------------------------------
# Release asset selection (shared with the mirror script)
# ---------------------------------------------------------------------------
def pick_assets(app: App, release_assets: Sequence[Mapping[str, Any]]
                ) -> Tuple[Dict[str, Mapping[str, Any]], List[str]]:
    """Map catalog asset ids to GitHub release assets. Returns
    (picked, problems): an id is picked only when its pattern matches
    exactly one asset with a safe file name."""
    picked: Dict[str, Mapping[str, Any]] = {}
    problems: List[str] = []
    for spec in app.assets:
        rx = re.compile(spec.pattern)
        hits = [a for a in release_assets if rx.match(str(a.get('name') or ''))]
        if len(hits) != 1:
            problems.append(f'{app.key}/{spec.id}: {len(hits)} matches for {spec.pattern}')
            continue
        if not SAFE_NAME.match(str(hits[0].get('name'))):
            problems.append(f'{app.key}/{spec.id}: unsafe asset name')
            continue
        picked[spec.id] = hits[0]
    return picked, problems


# ---------------------------------------------------------------------------
# Manifest (written by the mirror, read by the page)
# ---------------------------------------------------------------------------
_HEX64 = re.compile(r'^[0-9a-f]{64}$')


def sanitize_manifest(data: Any, base_url: str) -> Dict[str, Any]:
    """Keep only well-formed entries of known apps/assets. Mirror URLs must
    live under `base_url` and GitHub URLs under the app's own repo, so a
    tampered manifest cannot inject links elsewhere (javascript:, phishing
    hosts). Returns {'generated': float, 'apps': {key: {...}}}."""
    out: Dict[str, Any] = {'generated': 0.0, 'apps': {}}
    if not isinstance(data, dict):
        return out
    base = base_url.rstrip('/') + '/'
    if not base.startswith('https://'):
        return out
    gen = data.get('generated')
    if isinstance(gen, (int, float)):
        out['generated'] = float(gen)
    apps = data.get('apps')
    if not isinstance(apps, dict):
        return out
    for key, entry in apps.items():
        app = APPS_BY_KEY.get(str(key))
        if app is None or not isinstance(entry, dict):
            continue
        tag = str(entry.get('tag') or '')
        if not SAFE_TAG.match(tag):
            continue
        known = {a.id for a in app.assets}
        gh_prefix = f'https://github.com/{app.repo}/releases/download/'
        assets: Dict[str, Dict[str, Any]] = {}
        for aid, a in (entry.get('assets') or {}).items():
            if aid not in known or not isinstance(a, dict):
                continue
            name, url, gh = str(a.get('name') or ''), str(a.get('url') or ''), str(a.get('github_url') or '')
            sha, size = str(a.get('sha256') or ''), a.get('size')
            if not (SAFE_NAME.match(name) and url.startswith(base) and gh.startswith(gh_prefix)
                    and _HEX64.match(sha) and isinstance(size, int) and size > 0):
                continue
            assets[aid] = {'name': name, 'url': url, 'github_url': gh,
                           'sha256': sha, 'size': size}
        published = str(entry.get('published') or '')[:10]
        out['apps'][app.key] = {'tag': tag, 'version': tag.lstrip('vV'),
                                'published': published if re.match(r'^\d{4}-\d{2}-\d{2}$', published) else '',
                                'assets': assets}
    return out


def _atomic_write(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(prefix='.clients-', suffix='.tmp', dir=str(path.parent))
    try:
        with os.fdopen(fd, 'w', encoding='utf-8') as f:
            f.write(text)
        os.chmod(tmp, 0o640)
        os.replace(tmp, path)
    except BaseException:
        Path(tmp).unlink(missing_ok=True)
        raise


class ManifestCache:
    """Last good mirror manifest. Refreshed off the request path (server
    worker thread); persisted so a restart serves mirror links before the
    first fetch. An empty URL disables the mirror (GitHub links only)."""

    MAX_BYTES = 512 * 1024

    def __init__(self, url: str, cache_path: Path, ttl: float = 600.0) -> None:
        self.url = (url or '').strip()
        self.base_url = self.url.rsplit('/', 1)[0] if self.url else ''
        self.cache_path = Path(cache_path)
        self.ttl = ttl
        self.lock = threading.Lock()
        self.data: Dict[str, Any] = {'generated': 0.0, 'apps': {}}
        self.fetched_at = 0.0
        self.last_error = ''
        if self.url:
            try:
                raw = json.loads(self.cache_path.read_text(encoding='utf-8'))
                self.data = sanitize_manifest(raw, self.base_url)
            except (OSError, ValueError):
                pass

    @property
    def enabled(self) -> bool:
        return bool(self.url)

    def get(self) -> Dict[str, Any]:
        with self.lock:
            return self.data

    def refresh(self, opener=urllib.request.urlopen) -> bool:
        if not self.url:
            return False
        try:
            req = urllib.request.Request(self.url, headers={'User-Agent': 'mango-share/1'})
            with opener(req, timeout=10) as resp:
                raw = resp.read(self.MAX_BYTES + 1)
            if len(raw) > self.MAX_BYTES:
                raise ValueError('manifest too large')
            parsed = json.loads(raw.decode('utf-8'))
            clean = sanitize_manifest(parsed, self.base_url)
            if not clean['apps']:
                raise ValueError('manifest has no usable apps')
        except Exception as e:  # noqa: BLE001 - keep serving the last good copy
            with self.lock:
                self.last_error = f'{type(e).__name__}: {e}'[:200]
            return False
        with self.lock:
            changed = clean != self.data
            self.data = clean
            self.fetched_at = time.time()
            self.last_error = ''
        if changed:
            try:
                _atomic_write(self.cache_path, json.dumps(parsed, ensure_ascii=False) + '\n')
            except OSError:
                pass
        return True


def fmt_size(n: int) -> str:
    if n >= 1 << 30:
        return f'{n / (1 << 30):.1f} GB'
    if n >= 1 << 20:
        return f'{n / (1 << 20):.0f} MB'
    return f'{max(1, n // 1024)} KB'


def platform_view(manifest: Mapping[str, Any]) -> List[Dict[str, Any]]:
    """Group the catalog by platform for rendering. Every catalog asset is
    present; `mirror` is set only when the manifest carries it."""
    apps = manifest.get('apps') or {}
    out: List[Dict[str, Any]] = []
    for pkey, plabel in PLATFORMS:
        rows: List[Dict[str, Any]] = []
        if pkey == 'ios':
            for s in STORE_APPS:
                rows.append({'store': True, 'key': s.key, 'name': s.name, 'url': s.url,
                             'price': s.price, 'blurb': s.blurb, 'fmt': s.fmt,
                             'recommended': s.recommended})
        for app in CATALOG:
            specs = [a for a in app.assets if a.platform == pkey]
            if not specs:
                continue
            entry = apps.get(app.key) or {}
            files = []
            for spec in specs:
                m = (entry.get('assets') or {}).get(spec.id)
                files.append({'id': spec.id, 'label': spec.label, 'mirror': m})
            rows.append({'store': False, 'key': app.key, 'name': app.name,
                         'repo_url': app.repo_url, 'releases_url': app.releases_url,
                         'blurb': app.blurb, 'fmt': app.fmt,
                         'recommended': pkey in app.recommended,
                         'version': entry.get('version') or '',
                         'published': entry.get('published') or '',
                         'files': files})
        rows.sort(key=lambda r: not r['recommended'])
        out.append({'key': pkey, 'label': plabel, 'apps': rows})
    return out
