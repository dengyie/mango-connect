#!/usr/bin/env python3
"""Subscription format converters for mango-share.

Convert a parsed Clash config (the station's full-scope mirror of the
gateway client export) into the per-client formats the station serves:

- sing-box JSON  (1.12+ schema: rule actions, new DNS servers, rule_set geoip)
- Surge CONF     (ss/vmess/trojan/http/socks5/tuic-v5/hysteria2 + groups)
- Quantumult X   (server_local + policy + filter_local)
- URI list       (v2rayN-style base64 of share URIs)

Pure functions over a parsed Clash dict; no I/O. A node that cannot be
represented faithfully in a target is skipped (never emitted half-broken,
never aborting the whole export); the returned (name, reason) pairs let
callers surface them. Proxy groups are resolved to a fixed point: a group
whose members all disappeared is dropped, and so are references to it.
Nodes chained through `dialer-proxy` keep the chain (sing-box `detour`,
Surge `underlying-proxy`) or are skipped where the target cannot chain —
emitting them unchained would dial a server that only answers the relay.
"""

from __future__ import annotations

import base64
import ipaddress
import json
import re
from typing import Any, Dict, List, Optional, Set, Tuple
from urllib.parse import quote, urlencode

Skipped = List[Tuple[str, str]]

DEFAULT_TEST_URL = 'https://www.gstatic.com/generate_204'
PRIVATE_CIDRS = ['10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16', '127.0.0.0/8']
GEOIP_RULESET_URL = 'https://raw.githubusercontent.com/SagerNet/sing-geoip/rule-set/geoip-{}.srs'
GEOSITE_RULESET_URL = 'https://raw.githubusercontent.com/SagerNet/sing-geosite/rule-set/geosite-{}.srs'

_GROUP_TYPES = {
    'select': 'select', 'selector': 'select',
    'url-test': 'url-test', 'urltest': 'url-test',
    'fallback': 'fallback',
    'load-balance': 'load-balance', 'loadbalance': 'load-balance',
}


class Unsupported(Exception):
    """A node feature the target format cannot express."""


# ----------------------------------------------------------------- helpers

def _s(v: Any) -> str:
    return '' if v is None else str(v)


def _port(p: Dict[str, Any]) -> int:
    try:
        port = int(p.get('port') or 0)
    except (TypeError, ValueError):
        return 0
    return port if 0 < port < 65536 else 0


def _sni(p: Dict[str, Any]) -> str:
    return _s(p.get('servername') or p.get('sni'))


def _alpn(p: Dict[str, Any]) -> List[str]:
    a = p.get('alpn')
    if not a:
        return []
    if isinstance(a, str):
        return [x.strip() for x in a.split(',') if x.strip()]
    return [str(x) for x in a]


def _is_ipv6(host: str) -> bool:
    try:
        return isinstance(ipaddress.ip_address(host), ipaddress.IPv6Address)
    except ValueError:
        return False


def _is_ip(host: str) -> bool:
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return False


def _hostport(server: str, port: int) -> str:
    return f'[{server}]:{port}' if _is_ipv6(server) else f'{server}:{port}'


def _mbps(v: Any) -> int:
    m = re.match(r'\s*(\d+)', _s(v))
    return int(m.group(1)) if m else 0


def _hop_ports(p: Dict[str, Any]) -> List[str]:
    """Clash `ports: 20000-30000,443` -> ['20000-30000', '443']."""
    raw = _s(p.get('ports') or p.get('mport'))
    return [x.strip() for x in raw.split(',') if x.strip()]


def _ws_opts(p: Dict[str, Any]) -> Tuple[str, Dict[str, str]]:
    ws = p.get('ws-opts') or {}
    headers = {str(k): str(v) for k, v in (ws.get('headers') or {}).items()}
    path = _s(ws.get('path') or p.get('ws-path')) or '/'
    return path, headers


def _ws_host(p: Dict[str, Any]) -> str:
    _path, headers = _ws_opts(p)
    for k, v in headers.items():
        if k.lower() == 'host':
            return v
    return ''


def _network(p: Dict[str, Any]) -> str:
    return _s(p.get('network') or 'tcp').lower()


def _tls_on(p: Dict[str, Any]) -> bool:
    return bool(p.get('tls') or p.get('reality-opts'))


def _relay(p: Dict[str, Any]) -> str:
    return _s(p.get('dialer-proxy'))


# Clash rules may carry trailing options (no-resolve / no-redirect) that are
# NOT the rule target; stripping them first prevents `GEOIP,LAN,DIRECT,
# no-resolve` from being misrouted.
_RULE_TAIL_OPTIONS = {'no-resolve', 'no-redirect', 'src'}


def _parse_rule(rule: str) -> Tuple[str, str, str, List[str]]:
    """Clash rule -> (rtype, target, value, options). Empty rtype =
    unparseable. Trailing option segments are peeled off before the target
    is read, so `GEOIP,LAN,DIRECT,no-resolve` yields target DIRECT."""
    parts = [x.strip() for x in str(rule).split(',')]
    if len(parts) < 2:
        return '', '', '', []
    rtype = parts[0].upper()
    options: List[str] = []
    while len(parts) >= 3 and parts[-1].lower() in _RULE_TAIL_OPTIONS:
        options.append(parts.pop())
    if 'src' in options:
        return '', '', '', []  # source-side match: no faithful target mapping
    target = parts[-1]
    value = parts[1] if len(parts) > 2 else ''
    return rtype, target, value, options


def _resolve_groups(clash: Dict[str, Any], leaves: Set[str],
                    builtins: Set[str]) -> List[Tuple[str, str, List[str], Dict[str, Any]]]:
    """Clash proxy-groups -> [(name, kind, members, raw)] resolved to a fixed
    point. Members may reference any group regardless of declaration order;
    members that do not exist in the target are dropped, a group left empty is
    dropped, and the references to it are dropped in the next round."""
    raw: List[Tuple[str, str, List[str], Dict[str, Any]]] = []
    for g in clash.get('proxy-groups') or []:
        if not isinstance(g, dict):
            continue
        name = _s(g.get('name'))
        kind = _GROUP_TYPES.get(_s(g.get('type')).lower())
        if not name or not kind or name in leaves or name in builtins:
            continue
        raw.append((name, kind, [str(m) for m in g.get('proxies') or []], g))
    alive = {r[0] for r in raw}
    while True:
        out = []
        for name, kind, members, g in raw:
            if name not in alive:
                continue
            ms = [m for m in dict.fromkeys(members)
                  if m != name and (m in leaves or m in alive or m in builtins)]
            out.append((name, kind, ms, g))
        dead = {r[0] for r in out if not r[2]}
        if not dead:
            return out
        alive -= dead


def _interval(g: Dict[str, Any]) -> int:
    try:
        return max(30, int(g.get('interval') or 300))
    except (TypeError, ValueError):
        return 300


# ----------------------------------------------------------------- sing-box

def _tls_from_proxy(p: Dict[str, Any], sni_fallback: str = '') -> Tuple[Dict[str, Any], Dict[str, Any]]:
    """Map clash tls/transport fields -> (sing-box tls object, transport).

    Transport (ws/grpc/h2/httpupgrade) is independent of TLS: a plaintext ws
    node keeps its ws transport and never gets tls.enabled. Raises
    Unsupported for a transport sing-box cannot dial."""
    tls: Dict[str, Any] = {}
    transport: Dict[str, Any] = {}
    sni = _sni(p) or sni_fallback
    if _tls_on(p):
        tls['enabled'] = True
        if sni:
            tls['server_name'] = sni
        if p.get('skip-cert-verify'):
            tls['insecure'] = True
        alpn = _alpn(p)
        if alpn:
            tls['alpn'] = alpn
        reality = p.get('reality-opts') or {}
        fp = _s(p.get('client-fingerprint'))
        if reality.get('public-key'):
            tls['reality'] = {'enabled': True, 'public_key': str(reality['public-key'])}
            if reality.get('short-id'):
                tls['reality']['short_id'] = str(reality['short-id'])
            fp = fp or 'chrome'  # sing-box refuses reality without uTLS
        if fp:
            tls['utls'] = {'enabled': True, 'fingerprint': fp}
    network = _network(p)
    if network == 'ws':
        path, headers = _ws_opts(p)
        transport = {'type': 'ws', 'path': path}
        if headers:
            transport['headers'] = headers
        ws = p.get('ws-opts') or {}
        if ws.get('max-early-data'):
            transport['max_early_data'] = int(ws['max-early-data'])
            transport['early_data_header_name'] = _s(
                ws.get('early-data-header-name') or 'Sec-WebSocket-Protocol')
    elif network == 'grpc':
        g = p.get('grpc-opts') or {}
        transport = {'type': 'grpc', 'service_name': _s(g.get('grpc-service-name'))}
    elif network == 'h2':
        h = p.get('h2-opts') or {}
        transport = {'type': 'http'}
        if h.get('host'):
            transport['host'] = [str(x) for x in h['host']]
        if h.get('path'):
            transport['path'] = _s(h['path'])
    elif network == 'httpupgrade':
        h = p.get('http-upgrade-opts') or p.get('ws-opts') or {}
        transport = {'type': 'httpupgrade', 'path': _s(h.get('path')) or '/'}
        host = _ws_host(p)
        if host:
            transport['host'] = host
    elif network != 'tcp':
        raise Unsupported(f'{network} transport')
    return tls, transport


def _forced_tls(p: Dict[str, Any], server: str, default_alpn: Optional[List[str]] = None) -> Dict[str, Any]:
    """TLS block for protocols that are always TLS (hy2/tuic/anytls/trojan)."""
    tls: Dict[str, Any] = {'enabled': True}
    sni = _sni(p) or ('' if _is_ip(server) else server)
    if sni:
        tls['server_name'] = sni
    if p.get('skip-cert-verify'):
        tls['insecure'] = True
    alpn = _alpn(p) or (default_alpn or [])
    if alpn:
        tls['alpn'] = alpn
    fp = _s(p.get('client-fingerprint'))
    if fp:
        tls['utls'] = {'enabled': True, 'fingerprint': fp}
    return tls


def _singbox_outbound(p: Dict[str, Any]) -> Dict[str, Any]:
    name = _s(p.get('name'))
    server = _s(p.get('server'))
    port = _port(p)
    ptype = _s(p.get('type')).lower()
    if not name or not server or not port:
        raise Unsupported('missing server/port')
    base: Dict[str, Any] = {'tag': name, 'server': server, 'server_port': port}

    if ptype in ('vless', 'vmess'):
        if ptype == 'vless':
            base.update(type='vless', uuid=_s(p.get('uuid')))
            if p.get('flow'):
                base['flow'] = _s(p['flow'])
        else:
            base.update(type='vmess', uuid=_s(p.get('uuid')),
                        security=_s(p.get('cipher') or 'auto'),
                        alter_id=int(p.get('alterId') or p.get('alter-id') or 0))
        tls, transport = _tls_from_proxy(p, sni_fallback='' if _is_ip(server) else server)
        if tls:
            base['tls'] = tls
        if transport:
            base['transport'] = transport
    elif ptype == 'trojan':
        base.update(type='trojan', password=_s(p.get('password')))
        _tls, transport = _tls_from_proxy(p)
        base['tls'] = _forced_tls(p, server)
        if transport:
            base['transport'] = transport
    elif ptype in ('ss', 'shadowsocks'):
        base.update(type='shadowsocks', method=_s(p.get('cipher')),
                    password=_s(p.get('password')))
        plugin = _s(p.get('plugin'))
        if plugin:
            opts = p.get('plugin-opts') or {}
            if plugin == 'obfs':
                base['plugin'] = 'obfs-local'
                base['plugin_opts'] = f'obfs={_s(opts.get("mode") or "http")}' + (
                    f';obfs-host={_s(opts["host"])}' if opts.get('host') else '')
            elif plugin == 'v2ray-plugin' and _s(opts.get('mode') or 'websocket') == 'websocket':
                parts = ['mode=websocket']
                if opts.get('tls'):
                    parts.append('tls')
                if opts.get('host'):
                    parts.append(f'host={_s(opts["host"])}')
                if opts.get('path'):
                    parts.append(f'path={_s(opts["path"])}')
                base['plugin'] = 'v2ray-plugin'
                base['plugin_opts'] = ';'.join(parts)
            else:
                raise Unsupported(f'ss plugin {plugin}')
    elif ptype in ('hysteria2', 'hy2'):
        base.update(type='hysteria2', password=_s(p.get('password') or p.get('auth')))
        hops = _hop_ports(p)
        if hops:
            base['server_ports'] = [h.replace('-', ':') if '-' in h else f'{h}:{h}' for h in hops]
            if p.get('hop-interval'):
                base['hop_interval'] = f'{_mbps(p["hop-interval"]) or 30}s'
        if p.get('obfs'):
            base['obfs'] = {'type': _s(p['obfs']), 'password': _s(p.get('obfs-password'))}
        if _mbps(p.get('up')):
            base['up_mbps'] = _mbps(p['up'])
        if _mbps(p.get('down')):
            base['down_mbps'] = _mbps(p['down'])
        base['tls'] = _forced_tls(p, server, ['h3'])
    elif ptype == 'tuic':
        if not p.get('uuid'):
            raise Unsupported('tuic v4 token auth')
        base.update(type='tuic', uuid=_s(p.get('uuid')), password=_s(p.get('password')))
        cc = p.get('congestion-controller') or p.get('congestion-control')
        if cc:
            base['congestion_control'] = _s(cc)
        if p.get('udp-relay-mode'):
            base['udp_relay_mode'] = _s(p['udp-relay-mode'])
        base['tls'] = _forced_tls(p, server, ['h3'])
    elif ptype == 'anytls':
        base.update(type='anytls', password=_s(p.get('password')))
        base['tls'] = _forced_tls(p, server)
    elif ptype in ('http', 'socks5'):
        base['type'] = 'http' if ptype == 'http' else 'socks'
        if p.get('username'):
            base['username'] = _s(p['username'])
        if p.get('password'):
            base['password'] = _s(p['password'])
        if p.get('tls'):
            base['tls'] = _forced_tls(p, server)
    else:
        raise Unsupported(f'{ptype} has no sing-box outbound')
    return base


def _singbox_rule(rtype: str, value: str) -> Optional[Dict[str, Any]]:
    """Clash matcher -> sing-box matcher fields (no action), or None."""
    if not value:
        return None
    if rtype == 'DOMAIN-SUFFIX':
        return {'domain_suffix': [value]}
    if rtype == 'DOMAIN':
        return {'domain': [value]}
    if rtype == 'DOMAIN-KEYWORD':
        return {'domain_keyword': [value]}
    if rtype == 'DOMAIN-REGEX':
        return {'domain_regex': [value]}
    if rtype in ('IP-CIDR', 'IP-CIDR6'):
        return {'ip_cidr': [value]}
    if rtype == 'SRC-IP-CIDR':
        return {'source_ip_cidr': [value]}
    if rtype == 'PROCESS-NAME':
        return {'process_name': [value]}
    if rtype in ('DST-PORT', 'SRC-PORT'):
        key = 'port' if rtype == 'DST-PORT' else 'source_port'
        if re.fullmatch(r'\d+', value):
            return {key: [int(value)]}
        if re.fullmatch(r'\d+-\d+', value):
            return {key + '_range': [value.replace('-', ':')]}
        return None
    if rtype == 'GEOIP':
        if value.lower() == 'lan':
            # no 'lan' geoip set in sing-box: RFC1918 + loopback instead
            return {'ip_cidr': list(PRIVATE_CIDRS)}
        return {'rule_set': [f'geoip-{value.lower()}']}
    if rtype == 'GEOSITE':
        return {'rule_set': [f'geosite-{value.lower()}']}
    return None


def to_singbox(clash: Dict[str, Any]) -> Tuple[Dict[str, Any], Skipped]:
    """Clash client config -> complete sing-box (1.12+) client config."""
    skipped: Skipped = []
    nodes: Dict[str, Dict[str, Any]] = {}
    relays: Dict[str, str] = {}
    for p in clash.get('proxies') or []:
        if not isinstance(p, dict):
            continue
        name = _s(p.get('name')) or '?'
        try:
            ob = _singbox_outbound(p)
        except (Unsupported, TypeError, ValueError) as e:
            skipped.append((name, str(e) or 'malformed'))
            continue
        nodes[ob['tag']] = ob
        if _relay(p):
            relays[ob['tag']] = _relay(p)

    builtins = {'DIRECT'}
    while True:
        groups = _resolve_groups(clash, set(nodes), builtins)
        known = set(nodes) | {g[0] for g in groups} | builtins
        broken = [n for n, r in relays.items() if n in nodes and r not in known]
        if not broken:
            break
        for n in broken:
            skipped.append((n, f'relay {relays[n]} unavailable'))
            del nodes[n]
    for n, r in relays.items():
        if n in nodes:
            nodes[n]['detour'] = r

    group_outbounds: List[Dict[str, Any]] = []
    for name, kind, members, g in groups:
        if kind == 'select':
            group_outbounds.append({'type': 'selector', 'tag': name,
                                    'outbounds': members, 'default': members[0]})
        else:
            ob = {'type': 'urltest', 'tag': name, 'outbounds': members,
                  'url': _s(g.get('url')) or DEFAULT_TEST_URL,
                  'interval': f'{_interval(g)}s'}
            if g.get('tolerance'):
                ob['tolerance'] = int(g['tolerance'])
            group_outbounds.append(ob)
    group_tags = {o['tag'] for o in group_outbounds}
    proxy = 'PROXY' if 'PROXY' in group_tags else (group_outbounds[0]['tag'] if group_outbounds else 'DIRECT')

    route_rules: List[Dict[str, Any]] = [
        {'action': 'sniff'},
        {'protocol': 'dns', 'action': 'hijack-dns'},
        {'ip_is_private': True, 'outbound': 'DIRECT'},
    ]
    rule_sets: Dict[str, Dict[str, Any]] = {}
    final = proxy
    for rule in clash.get('rules') or []:
        rtype, target, value, _opts = _parse_rule(rule)
        if not rtype:
            continue
        if target != 'REJECT' and target not in known:
            continue  # target group not representable -> falls to final
        if rtype == 'MATCH':
            if target != 'REJECT':
                final = target
            continue
        matcher = _singbox_rule(rtype, value)
        if matcher is None:
            continue
        for tag in matcher.get('rule_set', []):
            kind, code = tag.split('-', 1)
            url = (GEOIP_RULESET_URL if kind == 'geoip' else GEOSITE_RULESET_URL).format(code)
            rule_sets[tag] = {'tag': tag, 'type': 'remote', 'format': 'binary',
                              'url': url, 'download_detour': proxy}
        if target == 'REJECT':
            matcher['action'] = 'reject'
        else:
            matcher['outbound'] = target
        route_rules.append(matcher)

    remote_dns: Dict[str, Any] = {'type': 'https', 'tag': 'remote', 'server': '1.1.1.1'}
    if proxy != 'DIRECT':
        remote_dns['detour'] = proxy
    route: Dict[str, Any] = {'rules': route_rules, 'final': final,
                             'auto_detect_interface': True,
                             'default_domain_resolver': 'local'}
    if rule_sets:
        route['rule_set'] = list(rule_sets.values())
    return {
        'log': {'level': 'warn'},
        'dns': {'servers': [remote_dns, {'type': 'local', 'tag': 'local'}],
                'final': 'remote', 'strategy': 'prefer_ipv4'},
        'inbounds': [
            {'type': 'tun', 'tag': 'tun-in',
             'address': ['172.19.0.1/30', 'fdfe:dcba:9876::1/126'],
             'auto_route': True, 'strict_route': True},
            {'type': 'mixed', 'tag': 'mixed-in', 'listen': '127.0.0.1', 'listen_port': 7890},
        ],
        'outbounds': group_outbounds + [{'type': 'direct', 'tag': 'DIRECT'}] + list(nodes.values()),
        'route': route,
        'experimental': {'cache_file': {'enabled': True}},
    }, skipped


def to_singbox_json(clash: Dict[str, Any]) -> Tuple[str, Skipped]:
    cfg, skipped = to_singbox(clash)
    return json.dumps(cfg, ensure_ascii=False, indent=2), skipped


# ----------------------------------------------------------------- surge

_SURGE_RULE_TYPES = {'DOMAIN-SUFFIX': 'DOMAIN-SUFFIX', 'DOMAIN': 'DOMAIN',
                     'DOMAIN-KEYWORD': 'DOMAIN-KEYWORD', 'IP-CIDR': 'IP-CIDR',
                     'IP-CIDR6': 'IP-CIDR6', 'GEOIP': 'GEOIP', 'DST-PORT': 'DEST-PORT',
                     'SRC-IP-CIDR': 'SRC-IP', 'PROCESS-NAME': 'PROCESS-NAME'}
_BAD_SURGE_CHARS = (',', '=', '#', '"', '\n', '\r')


def _surge_safe(v: Any) -> str:
    v = _s(v)
    if any(ch in v for ch in (',', '"', '\n', '\r')):
        raise Unsupported('value contains a delimiter (unrepresentable in Surge)')
    return v


def _surge_tls_opts(p: Dict[str, Any], server: str) -> List[str]:
    out = []
    sni = _sni(p)
    if sni:
        out.append(f'sni={_surge_safe(sni)}')
    if p.get('skip-cert-verify'):
        out.append('skip-cert-verify=true')
    return out


def _surge_ws_opts(p: Dict[str, Any]) -> List[str]:
    network = _network(p)
    if network == 'tcp':
        return []
    if network != 'ws':
        raise Unsupported(f'{network} transport has no Surge equivalent')
    path, headers = _ws_opts(p)
    out = ['ws=true', f'ws-path={_surge_safe(path)}']
    if headers:
        out.append('ws-headers=' + '|'.join(
            f'{_surge_safe(k)}:{_surge_safe(v)}' for k, v in headers.items()))
    return out


def _surge_proxy(p: Dict[str, Any]) -> str:
    name = _s(p.get('name'))
    ptype = _s(p.get('type')).lower()
    server = _surge_safe(p.get('server'))
    port = _port(p)
    if not name or not server or not port:
        raise Unsupported('missing server/port')
    if any(ch in name for ch in _BAD_SURGE_CHARS):
        raise Unsupported('name contains ,/=/# (unrepresentable in Surge)')
    if p.get('reality-opts'):
        raise Unsupported('reality has no Surge equivalent')
    opts: List[str]
    if ptype in ('ss', 'shadowsocks'):
        stype = 'ss'
        opts = [f'encrypt-method={_surge_safe(p.get("cipher"))}',
                f'password={_surge_safe(p.get("password"))}']
        plugin = _s(p.get('plugin'))
        if plugin == 'obfs':
            po = p.get('plugin-opts') or {}
            opts.append(f'obfs={_surge_safe(po.get("mode") or "http")}')
            if po.get('host'):
                opts.append(f'obfs-host={_surge_safe(po["host"])}')
        elif plugin:
            raise Unsupported(f'ss plugin {plugin} has no Surge equivalent')
        if p.get('udp'):
            opts.append('udp-relay=true')
    elif ptype == 'vmess':
        stype = 'vmess'
        opts = [f'username={_surge_safe(p.get("uuid"))}'] + _surge_ws_opts(p)
        if p.get('tls'):
            opts += ['tls=true'] + _surge_tls_opts(p, server)
        if not int(p.get('alterId') or p.get('alter-id') or 0):
            opts.append('vmess-aead=true')
    elif ptype == 'trojan':
        stype = 'trojan'
        opts = [f'password={_surge_safe(p.get("password"))}'] + _surge_ws_opts(p) + _surge_tls_opts(p, server)
    elif ptype in ('http', 'socks5'):
        stype = ('https' if p.get('tls') else 'http') if ptype == 'http' else (
            'socks5-tls' if p.get('tls') else 'socks5')
        opts = []
        if p.get('username'):
            opts += [f'username={_surge_safe(p["username"])}',
                     f'password={_surge_safe(p.get("password"))}']
        if p.get('tls'):
            opts += _surge_tls_opts(p, server)
    elif ptype == 'tuic':
        if not p.get('uuid'):
            raise Unsupported('tuic v4 token auth')
        stype = 'tuic-v5'
        opts = [f'password={_surge_safe(p.get("password"))}',
                f'uuid={_surge_safe(p.get("uuid"))}',
                'alpn=' + _surge_safe((_alpn(p) or ['h3'])[0])] + _surge_tls_opts(p, server)
    elif ptype in ('hysteria2', 'hy2'):
        if p.get('obfs'):
            raise Unsupported('hysteria2 obfs has no Surge equivalent')
        stype = 'hysteria2'
        opts = [f'password={_surge_safe(p.get("password") or p.get("auth"))}'] + _surge_tls_opts(p, server)
        if _mbps(p.get('down')):
            opts.append(f'download-bandwidth={_mbps(p["down"])}')
    else:
        raise Unsupported(f'{ptype} has no Surge equivalent')
    relay = _relay(p)
    if relay:
        opts.append(f'underlying-proxy={relay}')
    return ', '.join([f'{name} = {stype}', server, str(port)] + opts)


def _private_lines(target: str, fmt: str) -> List[str]:
    """GEOIP,LAN has no Surge/QX equivalent: expand to the private ranges."""
    if fmt == 'qx':
        return [f'ip-cidr, {c}, {target}' for c in PRIVATE_CIDRS]
    return [f'IP-CIDR,{c},{target},no-resolve' for c in PRIVATE_CIDRS]


def to_surge(clash: Dict[str, Any], managed_url: Optional[str] = None) -> Tuple[str, Skipped]:
    """Surge CONF: every representable node, the proxy groups, the rules."""
    skipped: Skipped = []
    lines: Dict[str, str] = {}
    relays: Dict[str, str] = {}
    for p in clash.get('proxies') or []:
        if not isinstance(p, dict):
            continue
        name = _s(p.get('name')) or '?'
        try:
            lines[name] = _surge_proxy(p)
        except (Unsupported, TypeError, ValueError) as e:
            skipped.append((name, str(e) or 'malformed'))
            continue
        if _relay(p):
            relays[name] = _relay(p)
    # Surge's underlying-proxy must name a proxy line; drop chains to a
    # group or to a skipped node (repeat: a dropped relay can orphan another).
    while True:
        broken = [n for n, r in relays.items() if n in lines and r not in lines]
        if not broken:
            break
        for n in broken:
            skipped.append((n, f'relay {relays[n]} unavailable in Surge'))
            del lines[n]

    builtins = {'DIRECT', 'REJECT'}
    groups = [g for g in _resolve_groups(clash, set(lines), builtins)
              if not any(ch in g[0] for ch in _BAD_SURGE_CHARS)]
    group_lines: List[str] = []
    group_names = {g[0] for g in groups}
    for name, kind, members, g in groups:
        members = [m for m in members if m in lines or m in group_names or m in builtins]
        if kind == 'select':
            group_lines.append(f'{name} = select, ' + ', '.join(members))
        else:
            group_lines.append(f'{name} = {kind}, ' + ', '.join(members) +
                               f', url={_s(g.get("url")) or DEFAULT_TEST_URL}, interval={_interval(g)}')
    if 'PROXY' not in group_names:
        group_lines.insert(0, 'PROXY = select, ' + ', '.join(list(lines) + ['DIRECT']))
        group_names.add('PROXY')
    targets = set(lines) | group_names | builtins

    rule_lines: List[str] = []
    final = 'PROXY'
    for rule in clash.get('rules') or []:
        rtype, target, value, options = _parse_rule(rule)
        if not rtype:
            continue
        if rtype == 'MATCH':
            if target in targets:
                final = target
            continue
        if target not in targets:
            target = 'PROXY'  # group with no Surge equivalent
        if rtype == 'GEOIP' and value.lower() == 'lan':
            rule_lines += _private_lines(target, 'surge')
            continue
        stype = _SURGE_RULE_TYPES.get(rtype)
        if stype and value and ',' not in value:
            line = f'{stype},{value},{target}'
            if 'no-resolve' in options and stype in ('IP-CIDR', 'IP-CIDR6', 'GEOIP'):
                line += ',no-resolve'
            rule_lines.append(line)
    rule_lines.append(f'FINAL,{final},dns-failed')

    head = f'#!MANAGED-CONFIG {managed_url} interval=86400 strict=false\n' if managed_url else ''
    return (head +
            '# Surge export generated by mango-connect\n'
            '[General]\nloglevel = notify\n'
            'skip-proxy = 127.0.0.1, 192.168.0.0/16, 10.0.0.0/8, 172.16.0.0/12, 100.64.0.0/10, localhost, *.local\n'
            'dns-server = system\n'
            f'proxy-test-url = {DEFAULT_TEST_URL}\n\n'
            '[Proxy]\n' + '\n'.join(lines.values()) + '\n\n'
            '[Proxy Group]\n' + '\n'.join(group_lines) + '\n\n'
            '[Rule]\n' + '\n'.join(rule_lines) + '\n'), skipped


# ----------------------------------------------------------------- quantumult X

_QX_RULE_TYPES = {'DOMAIN-SUFFIX': 'host-suffix', 'DOMAIN': 'host',
                  'DOMAIN-KEYWORD': 'host-keyword', 'IP-CIDR': 'ip-cidr',
                  'IP-CIDR6': 'ip6-cidr', 'GEOIP': 'geoip'}
_QX_BUILTIN = {'PROXY': 'proxy', 'DIRECT': 'direct', 'REJECT': 'reject'}
_QX_VMESS_METHODS = {'auto': 'chacha20-ietf-poly1305', 'chacha20-poly1305': 'chacha20-ietf-poly1305',
                     'chacha20-ietf-poly1305': 'chacha20-ietf-poly1305',
                     'aes-128-gcm': 'aes-128-gcm', 'none': 'none', 'zero': 'none'}


def _qx_obfs(p: Dict[str, Any], tls: bool) -> List[str]:
    network = _network(p)
    sni = _sni(p)
    if network == 'ws':
        path, _h = _ws_opts(p)
        host = _ws_host(p) or sni
        out = [f'obfs={"wss" if tls else "ws"}', f'obfs-uri={_surge_safe(path)}']
        if host:
            out.append(f'obfs-host={_surge_safe(host)}')
        return out
    if network != 'tcp':
        raise Unsupported(f'{network} transport has no Quantumult X equivalent')
    if tls:
        return ['obfs=over-tls'] + ([f'obfs-host={_surge_safe(sni)}'] if sni else [])
    return []


def _qx_server(p: Dict[str, Any]) -> str:
    name = _s(p.get('name'))
    ptype = _s(p.get('type')).lower()
    server = _surge_safe(p.get('server'))
    port = _port(p)
    if not name or not server or not port:
        raise Unsupported('missing server/port')
    if ',' in name or '=' in name:
        raise Unsupported('name contains ,/= (unrepresentable in Quantumult X)')
    if _relay(p):
        raise Unsupported('relay chains have no Quantumult X equivalent')
    if _is_ipv6(server):
        raise Unsupported('IPv6 literal server')
    if p.get('reality-opts'):
        raise Unsupported('reality has no Quantumult X equivalent')
    verify = [] if not p.get('skip-cert-verify') else ['tls-verification=false']
    udp = 'udp-relay=true' if p.get('udp') else 'udp-relay=false'
    if ptype in ('ss', 'shadowsocks'):
        parts = [f'shadowsocks={server}:{port}', f'method={_surge_safe(p.get("cipher"))}',
                 f'password={_surge_safe(p.get("password"))}']
        plugin = _s(p.get('plugin'))
        if plugin == 'obfs':
            po = p.get('plugin-opts') or {}
            parts.append(f'obfs={_surge_safe(po.get("mode") or "http")}')
            if po.get('host'):
                parts.append(f'obfs-host={_surge_safe(po["host"])}')
        elif plugin:
            raise Unsupported(f'ss plugin {plugin} has no Quantumult X equivalent')
    elif ptype == 'vmess':
        method = _QX_VMESS_METHODS.get(_s(p.get('cipher') or 'auto').lower())
        if not method:
            raise Unsupported(f'vmess cipher {p.get("cipher")}')
        tls = bool(p.get('tls'))
        parts = [f'vmess={server}:{port}', f'method={method}',
                 f'password={_surge_safe(p.get("uuid"))}'] + _qx_obfs(p, tls)
        if tls:
            parts += verify
        aead = not int(p.get('alterId') or p.get('alter-id') or 0)
        parts.append(f'aead={"true" if aead else "false"}')
    elif ptype == 'trojan':
        parts = [f'trojan={server}:{port}', f'password={_surge_safe(p.get("password"))}']
        if _network(p) == 'ws':
            parts += _qx_obfs(p, True)
        elif _network(p) == 'tcp':
            parts.append('over-tls=true')
            if _sni(p):
                parts.append(f'tls-host={_surge_safe(_sni(p))}')
        else:
            raise Unsupported(f'{_network(p)} transport has no Quantumult X equivalent')
        parts += verify
    elif ptype in ('http', 'socks5'):
        parts = [f'{"http" if ptype == "http" else "socks5"}={server}:{port}']
        if p.get('username'):
            parts += [f'username={_surge_safe(p["username"])}',
                      f'password={_surge_safe(p.get("password"))}']
        if p.get('tls'):
            parts.append('over-tls=true')
            if _sni(p):
                parts.append(f'tls-host={_surge_safe(_sni(p))}')
            parts += verify
    else:
        raise Unsupported(f'{ptype} has no Quantumult X server_local line')
    return ', '.join(parts + ['fast-open=false', udp, f'tag={name}'])


def to_qx(clash: Dict[str, Any]) -> Tuple[str, Skipped]:
    """Quantumult X: [server_local] + [policy] + [filter_local]."""
    skipped: Skipped = []
    servers: Dict[str, str] = {}
    for p in clash.get('proxies') or []:
        if not isinstance(p, dict):
            continue
        name = _s(p.get('name')) or '?'
        try:
            servers[name] = _qx_server(p)
        except (Unsupported, TypeError, ValueError) as e:
            skipped.append((name, str(e) or 'malformed'))

    # PROXY maps onto QX's built-in `proxy` policy (all servers), so it is a
    # builtin here rather than an emitted static policy.
    groups = [g for g in _resolve_groups(clash, set(servers), set(_QX_BUILTIN))
              if ',' not in g[0] and '=' not in g[0]]
    names = {g[0] for g in groups}
    policy_lines: List[str] = []
    kinds = {'select': 'static', 'url-test': 'url-latency-benchmark',
             'fallback': 'available', 'load-balance': 'round-robin'}
    for name, kind, members, g in groups:
        ms = [_QX_BUILTIN.get(m, m) for m in members if m in servers or m in names or m in _QX_BUILTIN]
        line = f'{kinds[kind]}={name}, ' + ', '.join(ms)
        if kind == 'url-test':
            line += f', check-interval={_interval(g)}, tolerance={int(g.get("tolerance") or 0)}'
        elif kind in ('fallback', 'load-balance'):
            line += f', check-interval={_interval(g)}'
        policy_lines.append(line)

    def qx_target(t: str) -> Optional[str]:
        if t in _QX_BUILTIN:
            return _QX_BUILTIN[t]
        if t in names:
            return t
        return None

    rule_lines: List[str] = []
    final = 'proxy'
    for rule in clash.get('rules') or []:
        rtype, target, value, _opts = _parse_rule(rule)
        if not rtype:
            continue
        t = qx_target(target) or 'proxy'
        if rtype == 'MATCH':
            final = t
            continue
        if rtype == 'GEOIP' and value.lower() == 'lan':
            rule_lines += _private_lines(t, 'qx')
            continue
        qtype = _QX_RULE_TYPES.get(rtype)
        if qtype and value and ',' not in value:
            rule_lines.append(f'{qtype}, {value}, {t}')
    rule_lines.append(f'final, {final}')
    return ('# Quantumult X export generated by mango-connect\n'
            f'[general]\nserver_check_url={DEFAULT_TEST_URL}\n\n'
            '[server_local]\n' + '\n'.join(servers.values()) + '\n\n'
            '[policy]\n' + '\n'.join(policy_lines) + '\n\n'
            '[filter_local]\n' + '\n'.join(rule_lines) + '\n'), skipped


# ----------------------------------------------------------------- uri list

def _q(v: Any) -> str:
    return quote(_s(v), safe='')


def _qs(params: Dict[str, Any]) -> str:
    clean = {k: _s(v) for k, v in params.items() if v not in (None, '', False)}
    return urlencode(clean, quote_via=quote, safe='')


def _transport_params(p: Dict[str, Any]) -> Dict[str, Any]:
    network = _network(p)
    out: Dict[str, Any] = {'type': network}
    if network == 'ws' or network == 'httpupgrade':
        path, _h = _ws_opts(p)
        out.update(path=path, host=_ws_host(p))
    elif network == 'grpc':
        out['serviceName'] = _s((p.get('grpc-opts') or {}).get('grpc-service-name'))
    elif network == 'h2':
        h = p.get('h2-opts') or {}
        out.update(path=_s(h.get('path')), host=','.join(str(x) for x in h.get('host') or []))
    elif network != 'tcp':
        raise Unsupported(f'{network} transport')
    return out


def _uri_for(p: Dict[str, Any]) -> str:
    ptype = _s(p.get('type')).lower()
    server = _s(p.get('server'))
    port = _port(p)
    if not server or not port:
        raise Unsupported('missing server/port')
    if _relay(p):
        raise Unsupported('relay chains cannot be expressed as a share URI')
    hp = _hostport(server, port)
    frag = '#' + _q(p.get('name'))
    insecure = '1' if p.get('skip-cert-verify') else ''
    if ptype in ('vless', 'trojan'):
        reality = p.get('reality-opts') or {}
        if ptype == 'trojan':
            security = 'tls'
        else:
            security = 'reality' if reality.get('public-key') else ('tls' if p.get('tls') else 'none')
        params: Dict[str, Any] = {}
        if ptype == 'vless':
            params['encryption'] = 'none'
            params['flow'] = p.get('flow')
        params['security'] = security
        if security != 'none':
            params.update(sni=_sni(p), fp=p.get('client-fingerprint'),
                          alpn=','.join(_alpn(p)), allowInsecure=insecure)
        if security == 'reality':
            params.update(pbk=reality.get('public-key'), sid=reality.get('short-id'))
            params['fp'] = params.get('fp') or 'chrome'
        params.update(_transport_params(p))
        cred = _q(p.get('uuid') if ptype == 'vless' else p.get('password'))
        return f'{ptype}://{cred}@{hp}?{_qs(params)}{frag}'
    if ptype == 'vmess':
        tp = _transport_params(p)
        payload = {'v': '2', 'ps': _s(p.get('name')), 'add': server, 'port': str(port),
                   'id': _s(p.get('uuid')), 'aid': str(p.get('alterId') or p.get('alter-id') or 0),
                   'scy': _s(p.get('cipher') or 'auto'),
                   'net': tp['type'], 'type': 'none',
                   'host': tp.get('host', ''), 'path': tp.get('path') or tp.get('serviceName', ''),
                   'tls': 'tls' if p.get('tls') else '', 'sni': _sni(p),
                   'alpn': ','.join(_alpn(p)), 'fp': _s(p.get('client-fingerprint'))}
        return 'vmess://' + base64.b64encode(
            json.dumps(payload, ensure_ascii=False).encode()).decode()
    if ptype in ('ss', 'shadowsocks'):
        userinfo = base64.urlsafe_b64encode(
            f'{_s(p.get("cipher"))}:{_s(p.get("password"))}'.encode()).decode().rstrip('=')
        query = ''
        plugin = _s(p.get('plugin'))
        if plugin == 'obfs':
            po = p.get('plugin-opts') or {}
            spec = f'obfs-local;obfs={_s(po.get("mode") or "http")}'
            if po.get('host'):
                spec += f';obfs-host={_s(po["host"])}'
            query = '?' + _qs({'plugin': spec})
        elif plugin:
            raise Unsupported(f'ss plugin {plugin}')
        return f'ss://{userinfo}@{hp}{query}{frag}'
    if ptype in ('hysteria2', 'hy2'):
        params = {'sni': _sni(p), 'insecure': insecure,
                  'obfs': p.get('obfs'), 'obfs-password': p.get('obfs-password'),
                  'mport': ','.join(_hop_ports(p))}
        return f'hysteria2://{_q(p.get("password") or p.get("auth"))}@{hp}/?{_qs(params)}{frag}'
    if ptype == 'tuic':
        if not p.get('uuid'):
            raise Unsupported('tuic v4 token auth')
        params = {'sni': _sni(p), 'alpn': ','.join(_alpn(p) or ['h3']),
                  'congestion_control': p.get('congestion-controller') or p.get('congestion-control'),
                  'udp_relay_mode': p.get('udp-relay-mode'), 'allow_insecure': insecure}
        return f'tuic://{_q(p.get("uuid"))}:{_q(p.get("password"))}@{hp}?{_qs(params)}{frag}'
    if ptype == 'anytls':
        params = {'sni': _sni(p), 'insecure': insecure, 'fp': p.get('client-fingerprint')}
        return f'anytls://{_q(p.get("password"))}@{hp}/?{_qs(params)}{frag}'
    raise Unsupported(f'{ptype} has no share URI')


def to_uri_list(clash: Dict[str, Any]) -> Tuple[str, Skipped]:
    """v2rayN-style URI list (base64 of newline-joined share URIs)."""
    skipped: Skipped = []
    uris: List[str] = []
    for p in clash.get('proxies') or []:
        if not isinstance(p, dict):
            continue
        try:
            uris.append(_uri_for(p))
        except (Unsupported, TypeError, ValueError) as e:
            skipped.append((_s(p.get('name')) or '?', str(e) or 'malformed'))
    body = '\n'.join(uris) + ('\n' if uris else '')
    return base64.b64encode(body.encode()).decode(), skipped
