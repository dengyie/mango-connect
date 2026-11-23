#!/usr/bin/env python3
"""Render a sanitized public Clash subscription from the private merged pool.

Pipeline: read NFS airports/mango-clash.yaml (read-only) -> filter nodes ->
rebuild minimal groups/rules -> atomic write public/mango-share.yaml.

Selection rules:
- whitelist: nodes listed in share-nodes.json (explicit consent, used for
  self-built nodes whose credentials would otherwise leak);
- blacklist: dead-node list exclude.json (shared with 3xui-health), fake/announcement
  node regex, loop-guard prefixes;
- everything else is dropped by default: the private pool is not public.

Idempotent: same input bytes + same config -> byte-identical output, so ETags
stay stable across renders.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import sys
import tempfile
from pathlib import Path
from typing import Any, Dict, List, Optional

sys.path.insert(0, str(Path(__file__).resolve().parent))
from importlib import import_module

_sh = import_module('share_constants')

RENDER_REV = _sh.RENDER_REV
PROFILE_TITLE = _sh.PROFILE_TITLE
NODE_PREFIX = _sh.NODE_PREFIX
LOOP_GUARD_PREFIXES = _sh.LOOP_GUARD_PREFIXES

DEFAULT_EXCLUDE_FILTER = r'(剩余流量|更新日期|官网|套餐|重置|到期|过期|公告|流量|时间|群|客服|traffic|expire|reset|website|notice)'

# Public groups; never carry internal business groups (Claude/OpenAI/home/CPA).
PUBLIC_GROUPS: List[Dict[str, Any]] = [
    {'name': 'PROXY', 'type': 'select', 'proxies': ['AUTO', 'DIRECT']},
    {'name': 'AUTO', 'type': 'url-test', 'proxies': [], 'url': 'https://www.gstatic.com/generate_204', 'interval': 300, 'tolerance': 50},
]
PUBLIC_RULES: List[str] = [
    'GEOIP,LAN,DIRECT,no-resolve',
    'GEOIP,CN,DIRECT',
    'MATCH,PROXY',
]

FAKE_NODE_RE = re.compile(DEFAULT_EXCLUDE_FILTER, re.IGNORECASE)


def share_scope(env: Optional[Dict[str, str]] = None) -> str:
    """Sharing scope: 'whitelist' (legacy: share-nodes.json only) or 'full'
    (everything in the pool incl. home/mesh nodes, per owner decision
    2026-11-22; token-gated). Default 'whitelist' in code; production sets
    SHARE_SCOPE=full via supervisor env."""
    env = env or os.environ
    return 'full' if str(env.get('SHARE_SCOPE', '')).lower() == 'full' else 'whitelist'


def select_nodes_full(
    proxies: List[Dict[str, Any]],
    exclude: List[str],
) -> List[Dict[str, Any]]:
    """Full-scope picking: everything passes except the hard filters
    (loop-guard prefixes, fake/announcement nodes, dead-node excludes).
    No whitelist, no renaming, dialer-proxy chains stay intact - the output
    mirrors the owner's own client config, gated by tokens."""
    exclude_set = set(exclude)
    picked: List[Dict[str, Any]] = []
    for p in proxies:
        if not isinstance(p, dict):
            continue
        name = str(p.get('name') or '')
        if not name:
            continue
        if any(name.startswith(pre) for pre in LOOP_GUARD_PREFIXES):
            continue
        if FAKE_NODE_RE.search(name):
            continue
        if name in exclude_set:
            continue
        picked.append(dict(p))
    return picked


# Public regions shown on the landing page (names + counts only; never
# node names, servers or credentials).
REGION_FLAGS = [
    ('US', '美国'), ('JP', '日本'), ('HK', '香港'), ('TW', '台湾'),
    ('SG', '新加坡'), ('GB', '英国'), ('UK', '英国'), ('KR', '韩国'),
    ('AU', '澳大利亚'), ('CA', '加拿大'), ('DE', '德国'), ('IN', '印度'),
    ('NL', '荷兰'), ('CN', '中国'),
]
_REGION_FLAG_RE = re.compile('[\U0001F1E6-\U0001F1FF]{2}')
_FLAG_NAMES = {''.join(chr(0x1F1E6 + ord(ch) - 65) for ch in code): name
               for code, name in REGION_FLAGS}


def node_regions(names: List[str]) -> List[Dict[str, Any]]:
    """Aggregate node names into public region badges (region, flag, count).
    Names without a flag emoji land in 专线/其他 by keyword or fallback."""
    counts: Dict[str, Dict[str, Any]] = {}
    order: List[str] = []
    for name in names:
        text = str(name or '')
        m = _REGION_FLAG_RE.search(text)
        region, flag = None, ''
        if m:
            pair = m.group(0)
            info = _FLAG_NAMES.get(pair)
            if info:
                flag, region = pair, info
        if region is None:
            for code, name in REGION_FLAGS:
                if name in text:
                    region, flag = name, ''
                    break
        if region is None:
            if any(k in text for k in ('家宽', 'EasyTier', 'Tebi', 'Pxed', '内网', '专线')):
                region, flag = '专用线路', ''
            else:
                region, flag = '其他', ''
        if region not in counts:
            counts[region] = {'region': region, 'flag': flag, 'count': 0}
            order.append(region)
        counts[region]['count'] += 1
    return [counts[r] for r in sorted(order, key=lambda x: -counts[x]['count'])]


def default_paths(env: Optional[Dict[str, str]] = None) -> Dict[str, Path]:
    env = env or os.environ
    clash_dir = _sh.clash_dir(env)
    share_dir = _sh.state_dir(env)
    return {
        'state': share_dir,
        'source': clash_dir / 'airports/mango-clash.yaml',
        'share_nodes': share_dir / 'share-nodes.json',
        'exclude': share_dir / 'exclude.json',
        'out': share_dir / 'public/mango-share.yaml',
        'meta': share_dir / 'public/mango-share.meta.json',
    }


def load_json_list(path: Path) -> List[str]:
    if not path.exists():
        return []
    data = json.loads(path.read_text(encoding='utf-8'))
    if isinstance(data, dict):
        data = data.get('nodes') or data.get('names') or []
    if not isinstance(data, list):
        raise ValueError(f'{path}: expected a JSON list of node names')
    return [str(x) for x in data]


def _is_whitelisted(name: str, whitelist: List[str]) -> bool:
    return name in whitelist


def sanitize_node(p: Dict[str, Any]) -> Dict[str, Any]:
    """Strip private-topology fields a public client cannot resolve.
    dialer-proxy points at internal mesh chains; direct dialing works for all
    whitelisted self-built nodes (public IPs)."""
    q = dict(p)
    q.pop('dialer-proxy', None)
    return q


def select_nodes(
    proxies: List[Dict[str, Any]],
    whitelist: List[str],
    exclude: List[str],
) -> List[Dict[str, Any]]:
    """Pick public nodes. Loop-guard + fake regex + exclude list are hard rules;
    anything not explicitly whitelisted is dropped."""
    exclude_set = set(exclude)
    picked: List[Dict[str, Any]] = []
    for p in proxies:
        if not isinstance(p, dict):
            continue
        name = str(p.get('name') or '')
        if not name:
            continue
        if any(name.startswith(pre) for pre in LOOP_GUARD_PREFIXES):
            continue
        if FAKE_NODE_RE.search(name):
            continue
        if name in exclude_set:
            continue
        if not _is_whitelisted(name, whitelist):
            continue
        q = sanitize_node(p)
        q['name'] = NODE_PREFIX + name
        picked.append(q)
    return picked


def render(source_path: Path, share_nodes_path: Path, exclude_path: Path,
           out_path: Path, meta_path: Path) -> Dict[str, Any]:
    return _render(source_path, share_nodes_path, exclude_path, out_path, meta_path,
                   scope=share_scope())


def render_user(source_path: Path, share_nodes_path: Path, exclude_path: Path,
                out_path: Path, meta_path: Optional[Path] = None, *,
                user: Dict[str, Any], cred_map: List[Dict[str, Any]],
                other_secrets: List[str]) -> Dict[str, Any]:
    """Phase-2 per-user render: same pipeline, but every mapped node gets the
    user's own credentials substituted in. `other_secrets` are credential
    values belonging to OTHER users — if any of them appears in the output
    the render raises instead of publishing (per-user leak gate). The caller
    reads the sha from the returned meta, so no meta file is written."""
    return _render(source_path, share_nodes_path, exclude_path, out_path,
                   meta_path,
                   user_credentials=user.get('credentials') or {},
                   cred_map=cred_map,
                   other_secrets=other_secrets,
                   scope=share_scope())


def _substitute_credentials(picked: List[Dict[str, Any]],
                            user_credentials: Dict[str, Any],
                            cred_map: List[Dict[str, Any]]) -> None:
    """Rewrite mapped nodes' credentials in place with the user's own values.
    Unmapped nodes keep the shared credential (additive rollout)."""
    by_orig = {m.get('node'): m for m in cred_map if isinstance(m, dict)}
    for p in picked:
        orig = str(p.get('name') or '')
        if orig.startswith(NODE_PREFIX):
            orig = orig[len(NODE_PREFIX):]
        m = by_orig.get(orig)
        if not m:
            continue
        cred = (user_credentials.get(str(m.get('key'))) or {})
        uuid = cred.get('uuid')
        if not uuid:
            continue  # user not provisioned on this node yet
        ctype = str(m.get('type') or 'vless')
        if ctype == 'vless':
            p['uuid'] = uuid
        elif ctype == 'tuic':
            p['uuid'] = uuid
            p['password'] = uuid
        elif ctype == 'anytls':
            p['password'] = uuid


def _render_full_mirror(source_path: Path, out_path: Path,
                        meta_path: Optional[Path]) -> Dict[str, Any]:
    """Full scope = byte-level mirror of the gateway's own client export:
    the output is the source file verbatim, so subscribers get byte-identical
    config to the owner's devices. The gateway already kernel-validates the
    candidate before writing it; alignment is computed against its meta."""
    source_bytes = source_path.read_bytes()
    sha = hashlib.sha256(source_bytes).hexdigest()
    out_path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp_name = tempfile.mkstemp(prefix='mango-share-', suffix='.tmp', dir=str(out_path.parent))
    tmp = Path(tmp_name)
    try:
        with os.fdopen(fd, 'wb') as f:
            f.write(source_bytes)
        os.chmod(tmp, 0o640)
        os.replace(tmp, out_path)
    except BaseException:
        tmp.unlink(missing_ok=True)
        raise
    node_count = 0
    try:
        import yaml as _yaml
        doc = _yaml.safe_load(source_bytes)
        node_count = len((doc or {}).get('proxies') or [])
    except Exception:
        pass
    aligned = None
    try:
        gm = json.loads((source_path.parent / 'mango-clash.meta.json').read_text(encoding='utf-8'))
        aligned = (gm.get('sha256') == sha)
    except Exception:
        pass
    meta = {
        'render_rev': RENDER_REV,
        'scope': 'full',
        'sha256': sha,
        'node_count': node_count,
        'aligned': aligned,
        'source_sha256': sha,
        'source_node_count': node_count,
        'whitelist_count': None,
        'generated_at': __json_ts__(),
    }
    if meta_path is not None:
        mfd, mtmp_name = tempfile.mkstemp(prefix='mango-share-meta-', suffix='.tmp', dir=str(meta_path.parent))
        mtmp = Path(mtmp_name)
        try:
            with os.fdopen(mfd, 'w', encoding='utf-8') as f:
                f.write(json.dumps(meta, ensure_ascii=False, indent=2) + '\n')
            os.chmod(mtmp, 0o640)
            os.replace(mtmp, meta_path)
        except BaseException:
            mtmp.unlink(missing_ok=True)
            raise
    return meta


def _render(source_path: Path, share_nodes_path: Path, exclude_path: Path,
            out_path: Path, meta_path: Path, *,
            user_credentials: Optional[Dict[str, Any]] = None,
            cred_map: Optional[List[Dict[str, Any]]] = None,
            other_secrets: Optional[List[str]] = None,
            scope: str = 'whitelist') -> Dict[str, Any]:
    if scope == 'full' and user_credentials is None:
        # byte-level mirror: no parse, no re-serialization, zero drift from
        # the gateway's own client export
        return _render_full_mirror(source_path, out_path, meta_path)
    import yaml

    doc = yaml.safe_load(source_path.read_text(encoding='utf-8'))
    if not isinstance(doc, dict):
        raise ValueError(f'{source_path}: not a mapping')
    proxies = doc.get('proxies') or []
    whitelist = load_json_list(share_nodes_path)
    exclude = load_json_list(exclude_path)

    if scope == 'full':
        # per-user path only (plain render took the mirror above): parse the
        # gateway client export and re-serialize with the user's credentials
        picked = select_nodes_full(proxies, exclude)
        public_groups = doc.get('proxy-groups') or []
        public_rules = list(doc.get('rules') or [])
    else:
        picked = select_nodes(proxies, whitelist, exclude)
        public_groups, public_rules = None, None
    names = [p['name'] for p in picked]
    if not names:
        raise ValueError('render produced zero nodes; refusing to publish an empty subscription')

    if user_credentials is not None:
        _substitute_credentials(picked, user_credentials, cred_map or [])

    if scope == 'full':
        final_groups, final_rules = public_groups, public_rules
    else:
        auto = dict(PUBLIC_GROUPS[1])
        auto['proxies'] = names
        proxy_grp = dict(PUBLIC_GROUPS[0])
        proxy_grp['proxies'] = ['AUTO', 'DIRECT']
        final_groups = [proxy_grp, auto]
        final_rules = list(PUBLIC_RULES)

    public = {
        'mixed-port': 7890,
        'allow-lan': False,
        'mode': 'rule',
        'log-level': 'info',
        'unified-delay': True,
        'ipv6': True,
        'dns': {
            'enable': True,
            'ipv6': True,
            'enhanced-mode': 'fake-ip',
            'fake-ip-range': '198.18.0.1/16',
            'default-nameserver': ['223.5.5.5', '119.29.29.29'],
            'nameserver': ['https://doh.pub/dns-query', 'https://dns.alidns.com/dns-query'],
        },
        'proxies': picked,
        'proxy-groups': final_groups,
        'rules': final_rules,
    }

    body = yaml.safe_dump(
        public, allow_unicode=True, sort_keys=False, default_flow_style=False
    )

    if other_secrets:
        leaked = [s for s in other_secrets if len(s) >= 8 and s in body]
        if leaked:
            raise ValueError(
                'per-user leak gate: output contains other users\' credentials')

    sha = hashlib.sha256(body.encode('utf-8')).hexdigest()

    out_path.parent.mkdir(parents=True, exist_ok=True)
    # Unique tmp per call: concurrent renders (ThreadingHTTPServer) must never
    # interleave into a shared fixed .tmp path.
    fd, tmp_name = tempfile.mkstemp(prefix='mango-share-', suffix='.tmp', dir=str(out_path.parent))
    tmp = Path(tmp_name)
    try:
        with os.fdopen(fd, 'w', encoding='utf-8') as f:
            f.write(body)
        os.chmod(tmp, 0o640)
        os.replace(tmp, out_path)
    except BaseException:
        tmp.unlink(missing_ok=True)
        raise

    meta = {
        'render_rev': RENDER_REV,
        'scope': scope,
        'sha256': sha,
        'node_count': len(picked),
        'source_sha256': hashlib.sha256(source_path.read_bytes()).hexdigest(),
        'source_node_count': len(proxies),
        'whitelist_count': len(whitelist),
        'generated_at': __json_ts__(),
    }
    if meta_path is not None:
        mfd, mtmp_name = tempfile.mkstemp(prefix='mango-share-meta-', suffix='.tmp', dir=str(meta_path.parent))
        mtmp = Path(mtmp_name)
        try:
            with os.fdopen(mfd, 'w', encoding='utf-8') as f:
                f.write(json.dumps(meta, ensure_ascii=False, indent=2) + '\n')
            os.chmod(mtmp, 0o640)
            os.replace(mtmp, meta_path)
        except BaseException:
            mtmp.unlink(missing_ok=True)
            raise
    return meta


def check_leaks(out_text: str, whitelist: List[str], proxies: List[Dict[str, Any]],
                scope: str = 'whitelist') -> List[str]:
    """Fail if non-shareable material appears in the public output.
    whitelist scope: non-whitelisted node names/credentials/mesh/home
    markers must be absent. full scope: the whole pool is shareable by
    owner decision; only loop-guard prefixes must stay absent."""
    bad: List[str] = []
    if scope == 'full':
        for name in (p.get('name') or '' for p in proxies):
            if any(name.startswith(pre) for pre in LOOP_GUARD_PREFIXES) and name in out_text:
                bad.append(f'loop-guard:{name}')
        return sorted(set(bad))
    wl = set(whitelist)
    secret_keys = ('uuid', 'password', 'public-key', 'private-key')
    for p in proxies:
        name = str(p.get('name') or '')
        if not name or name in wl:
            continue
        if name in out_text:
            bad.append(f'name:{name}')
        for k in secret_keys:
            v = p.get(k)
            if isinstance(v, str) and len(v) >= 8 and v in out_text:
                bad.append(f'secret:{k}:{name}')
        # mesh servers must never appear (EasyTier default subnet 10.144.144.0/24)
        srv = str(p.get('server') or '')
        if srv.startswith('10.144.144.') and srv in out_text:
            bad.append(f'mesh-server:{name}')
    for pat in ('🏠home-win', '🏠家宽'):
        if pat in out_text:
            bad.append(f'home-broadband:{pat}')
    return sorted(set(bad))


def __json_ts__() -> str:
    import datetime
    return datetime.datetime.now(datetime.timezone.utc).isoformat()


def main() -> int:
    import argparse

    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--check-leaks', action='store_true',
                    help='fail if the output contains self-built/home nodes or their secrets')
    args = ap.parse_args()

    paths = default_paths()
    meta = render(paths['source'], paths['share_nodes'], paths['exclude'], paths['out'], paths['meta'])
    print(json.dumps(meta, ensure_ascii=False))

    if args.check_leaks:
        import yaml as _yaml
        src_doc = _yaml.safe_load(paths['source'].read_text(encoding='utf-8'))
        wl = load_json_list(paths['share_nodes'])
        out_text = paths['out'].read_text(encoding='utf-8')
        bad = check_leaks(out_text, wl, src_doc.get('proxies') or [],
                          scope=share_scope())
        if bad:
            print('LEAK DETECTED:\n  ' + '\n  '.join(bad), file=sys.stderr)
            return 2
        print('leak check: clean')
    return 0


if __name__ == '__main__':
    sys.exit(main())
