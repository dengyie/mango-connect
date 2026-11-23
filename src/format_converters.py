#!/usr/bin/env python3
"""Subscription format converters for mango-share.

Convert a parsed Clash config (the station's full-scope mirror of the
gateway client export) into the per-client formats the station serves:

- sing-box JSON  (complete: all protocols the pool carries)
- Surge CONF     (supported-protocol subset; vless/anytls/mieru/hysteria2
                  have no Surge equivalent and are skipped with a comment)
- Quantumult X   (server_local subset + rules)
- URI list       (v2rayN-style base64 vless/vmess/trojan/ss URIs)

Pure functions over a parsed Clash dict; no I/O. Unknown/unconvertible
nodes are skipped (never abort the whole export), and the returned
(skipped, reason) pairs let callers surface them in logs.
"""

from __future__ import annotations

import base64
import json
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import quote

SINGBOX_SUPPORTED = {
    'vless', 'vmess', 'trojan', 'ss', 'shadowsocks', 'hysteria2', 'hy2',
    'tuic', 'anytls', 'mieru', 'http', 'socks5',
}
SURGE_SUPPORTED = {'ss', 'shadowsocks', 'vmess', 'trojan', 'http', 'socks5', 'tuic'}


# ----------------------------------------------------------------- helpers

def _tls_from_proxy(p: Dict[str, Any], sni_fallback: str = '') -> Tuple[Dict[str, Any], Dict[str, Any]]:
    """Map clash tls fields -> (sing-box tls object, transport object).

    Transport (ws/grpc) is independent of TLS: a plaintext ws node must
    still carry its ws transport, and must NOT get tls.enabled=true (the
    previous `a or b or c and d` precedence silently turned plaintext-ws
    nodes with an sni field into broken TLS dials)."""
    tls: Dict[str, Any] = {}
    transport: Dict[str, Any] = {}
    sni = str(p.get('servername') or p.get('sni') or sni_fallback or '')
    if p.get('tls') or p.get('reality-opts'):
        tls['enabled'] = True
        if sni:
            tls['server_name'] = sni
        reality = p.get('reality-opts') or {}
        if reality.get('public-key'):
            tls['reality'] = {'enabled': True, 'public_key': str(reality['public-key'])}
            if reality.get('short-id'):
                tls['reality']['short_id'] = str(reality['short-id'])
        fp = p.get('client-fingerprint')
        if fp:
            tls['utls'] = {'enabled': True, 'fingerprint': str(fp)}
    network = str(p.get('network') or 'tcp')
    if network == 'ws':
        ws = p.get('ws-opts') or {}
        transport = {'type': 'ws', 'path': str(ws.get('path') or '/')}
        headers = ws.get('headers') or {}
        if headers:
            transport['headers'] = {str(k): str(v) for k, v in headers.items()}
    elif network == 'grpc':
        g = p.get('grpc-opts') or {}
        transport = {'type': 'grpc', 'service_name': str(g.get('grpc-service-name') or '')}
    return tls, transport


# Clash rules may carry trailing options (no-resolve / no-redirect) that are
# NOT the rule target; stripping them first prevents `GEOIP,LAN,DIRECT,
# no-resolve` from being misrouted (previously the last segment was taken as
# the target, sending LAN traffic to PROXY or dropping the rule entirely).
_RULE_TAIL_OPTIONS = {'no-resolve', 'no-redirect'}


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
    target = parts[-1]
    value = parts[1] if len(parts) > 1 else ''
    return rtype, target, value, options


def _skip(item: Any) -> Tuple[None, Tuple[str, str]]:
    return None, (str(item.get('name') or '?'), 'unsupported protocol')


# ----------------------------------------------------------------- sing-box

def _singbox_outbound(p: Dict[str, Any]) -> Tuple[Optional[Dict[str, Any]], Tuple[str, str]]:
    name = str(p.get('name') or '')
    server = str(p.get('server') or '')
    port = int(p.get('port') or 0)
    ptype = str(p.get('type') or '').lower()
    if not name or not server or not port:
        return None, (name, 'missing server/port')
    base: Dict[str, Any] = {'tag': name, 'server': server, 'server_port': port}

    if ptype == 'vless':
        base.update(type='vless', uuid=str(p.get('uuid') or ''))
        flow = p.get('flow')
        if flow:
            base['flow'] = str(flow)
        tls, transport = _tls_from_proxy(p, sni_fallback=server)
        if tls:
            base['tls'] = tls
        if transport:
            base['transport'] = transport
    elif ptype == 'vmess':
        base.update(type='vmess', uuid=str(p.get('uuid') or ''),
                    security=str(p.get('cipher') or 'auto'),
                    alter_id=int(p.get('alterId') or p.get('alter-id') or 0))
        tls, transport = _tls_from_proxy(p, sni_fallback=server)
        if tls:
            base['tls'] = tls
        if transport:
            base['transport'] = transport
    elif ptype == 'trojan':
        base.update(type='trojan', password=str(p.get('password') or ''))
        tls, transport = _tls_from_proxy(p, sni_fallback=server)
        if tls:
            base['tls'] = tls
        if transport:
            base['transport'] = transport
    elif ptype in ('ss', 'shadowsocks'):
        base.update(type='shadowsocks', method=str(p.get('cipher') or ''),
                    password=str(p.get('password') or ''))
    elif ptype in ('hysteria2', 'hy2'):
        base.update(type='hysteria2', password=str(p.get('password') or p.get('auth') or ''))
        obfs = p.get('obfs')
        if obfs:
            base['obfs'] = {'type': str(obfs),
                            'password': str(p.get('obfs-password') or '')}
    elif ptype == 'tuic':
        base.update(type='tuic', uuid=str(p.get('uuid') or ''),
                    password=str(p.get('password') or ''))
        cc = p.get('congestion-controller') or p.get('congestion-control')
        if cc:
            base['congestion_control'] = str(cc)
        alpn = p.get('alpn')
        if alpn:
            base['alpn'] = [str(a) for a in alpn]
    elif ptype == 'anytls':
        base.update(type='anytls', password=str(p.get('password') or ''))
    elif ptype == 'mieru':
        base.update(type='mieru', password=str(p.get('password') or ''))
    elif ptype == 'http':
        base.update(type='http')
        if p.get('username'):
            base['username'] = str(p['username'])
        if p.get('password'):
            base['password'] = str(p['password'])
        if p.get('tls'):
            base['tls'] = {'enabled': True}
    elif ptype == 'socks5':
        base.update(type='socks')
        if p.get('username'):
            base['username'] = str(p['username'])
        if p.get('password'):
            base['password'] = str(p['password'])
        if p.get('tls'):
            base['tls'] = {'enabled': True}
    else:
        return None, (name, f'unsupported protocol {ptype}')
    return base, (name, '')


def to_singbox(clash: Dict[str, Any]) -> Dict[str, Any]:
    """Clash client config -> complete sing-box client config (JSON-able)."""
    skipped: List[Tuple[str, str]] = []
    outbounds: List[Dict[str, Any]] = [{'type': 'direct', 'tag': 'DIRECT'}]
    node_tags: List[str] = []
    for p in clash.get('proxies') or []:
        ob, skipped_info = _singbox_outbound(p if isinstance(p, dict) else {})
        if ob:
            outbounds.append(ob)
            node_tags.append(ob['tag'])
        else:
            skipped.append(skipped_info)

    group_outbounds: List[Dict[str, Any]] = []
    for g in clash.get('proxy-groups') or []:
        gtype = str(g.get('type') or '').lower()
        if gtype not in ('select', 'selector', 'url-test', 'urltest',
                         'fallback', 'load-balance', 'loadbalance'):
            continue
        members = []
        for m in g.get('proxies') or []:
            m = str(m)
            if m in node_tags or m in ('DIRECT',) or any(o['tag'] == m for o in group_outbounds):
                members.append(m)
        if not members:
            continue
        if gtype in ('select', 'selector'):
            group_outbounds.append({'type': 'selector', 'tag': str(g.get('name')),
                                    'outbounds': members, 'default': members[0]})
        else:
            group_outbounds.append({'type': 'urltest', 'tag': str(g.get('name')),
                                    'outbounds': members,
                                    'url': str(g.get('url') or 'https://www.gstatic.com/generate_204'),
                                    'interval': f"{int(g.get('interval') or 300)}s"})

    # route rules (clash rule syntax -> sing-box legacy route rules)
    route_rules: List[Dict[str, Any]] = []
    final = 'PROXY' if any(o['tag'] == 'PROXY' for o in group_outbounds) else 'DIRECT'
    known = {o['tag'] for o in outbounds} | {o['tag'] for o in group_outbounds} | {'DIRECT'}
    for rule in clash.get('rules') or []:
        rtype, target, value, options = _parse_rule(rule)
        if not rtype:
            continue
        if target not in known:
            continue
        if rtype == 'MATCH':
            if target in known:
                final = target
            continue
        if rtype == 'DOMAIN-SUFFIX':
            route_rules.append({'domain_suffix': [value], 'outbound': target})
        elif rtype == 'DOMAIN':
            route_rules.append({'domain': [value], 'outbound': target})
        elif rtype == 'DOMAIN-KEYWORD':
            route_rules.append({'domain_keyword': [value], 'outbound': target})
        elif rtype == 'IP-CIDR' or rtype == 'IP-CIDR6':
            route_rules.append({'ip_cidr': [value], 'outbound': target})
        elif rtype == 'GEOIP':
            if value.lower() == 'lan':
                # sing-box has no 'lan' geoip set; use RFC1918 + loopback so
                # private traffic still goes DIRECT (never falls to PROXY).
                route_rules.append({'ip_cidr': ['10.0.0.0/8', '172.16.0.0/12',
                                                '192.168.0.0/16', '127.0.0.0/8'],
                                    'outbound': target})
            else:
                route_rules.append({'geoip': [value.lower()], 'outbound': target})

    return {
        'log': {'level': 'info'},
        'dns': {'servers': [
            {'tag': 'remote', 'address': 'https://doh.pub/dns-query', 'detour': 'PROXY'
             if any(o['tag'] == 'PROXY' for o in group_outbounds) else 'DIRECT'},
            {'tag': 'local', 'address': 'local'},
        ], 'final': 'remote', 'strategy': 'prefer_ipv4'},
        'inbounds': [{'type': 'mixed', 'tag': 'mixed-in',
                      'listen': '127.0.0.1', 'listen_port': 7890}],
        'outbounds': group_outbounds + outbounds,
        'route': {'rules': route_rules, 'final': final,
                  'auto_detect_interface': True},
    }, skipped


def to_singbox_json(clash: Dict[str, Any]) -> Tuple[str, List[Tuple[str, str]]]:
    cfg, skipped = to_singbox(clash)
    return json.dumps(cfg, ensure_ascii=False, indent=2), skipped


# ----------------------------------------------------------------- surge

def to_surge(clash: Dict[str, Any]) -> Tuple[str, List[Tuple[str, str]]]:
    """Surge CONF for the supported-protocol subset. vless/anytls/mieru/
    hysteria2 nodes are skipped (no Surge equivalent)."""
    skipped: List[Tuple[str, str]] = []
    proxy_lines: List[str] = []
    tags: List[str] = []
    for p in clash.get('proxies') or []:
        if not isinstance(p, dict):
            continue
        name = str(p.get('name') or '')
        ptype = str(p.get('type') or '').lower()
        server = str(p.get('server') or '')
        port = int(p.get('port') or 0)
        if ptype not in SURGE_SUPPORTED:
            skipped.append((name, f'{ptype} has no Surge equivalent'))
            continue
        if any(ch in name for ch in (',', '=', '#')):
            # A Surge proxy line is comma-delimited; names carrying the
            # delimiter would corrupt the CONF — skip rather than emit junk.
            skipped.append((name, 'name contains ,/= (unrepresentable in Surge)'))
            continue
        line = f'{name} = {ptype}, {server}, {port}'
        if ptype == 'vmess':
            line += f', username={p.get("uuid")}, tls={str(bool(p.get("tls"))).lower()}'
        elif ptype in ('ss', 'shadowsocks'):
            line += f', encrypt-method={p.get("cipher")}, password={p.get("password")}'
        elif ptype == 'trojan':
            line += f', password={p.get("password")}, tls=true'
        elif ptype == 'http':
            if p.get('username'):
                line += f', username={p["username"]}, password={p.get("password")}'
            if p.get('tls'):
                line += ', tls=true'
        elif ptype == 'socks5':
            if p.get('username'):
                line += f', username={p["username"]}, password={p.get("password")}'
        elif ptype == 'tuic':
            line += f', uuid={p.get("uuid")}, password={p.get("password")}, tls=true'
        proxy_lines.append(line)
        tags.append(name)

    rule_lines: List[str] = []
    final = 'PROXY'
    for rule in clash.get('rules') or []:
        rtype, target, value, options = _parse_rule(rule)
        if not rtype:
            continue
        if rtype == 'MATCH':
            final = target if target in ('PROXY', 'DIRECT') else 'PROXY'
            continue
        if target == '🏠家宽' or target not in ('PROXY', 'DIRECT'):
            # Surge policy must be a declared proxy/policy; internal groups
            # that have no Surge equivalent are demoted to PROXY.
            target = 'PROXY'
        surge_type = {'DOMAIN-SUFFIX': 'DOMAIN-SUFFIX', 'DOMAIN': 'DOMAIN',
                      'DOMAIN-KEYWORD': 'DOMAIN-KEYWORD', 'IP-CIDR': 'IP-CIDR',
                      'IP-CIDR6': 'IP-CIDR6', 'GEOIP': 'GEOIP'}.get(rtype)
        if surge_type and value:
            line = f'{surge_type},{value},{target}'
            if 'no-resolve' in options:
                line += ',no-resolve'
            rule_lines.append(line)
    rule_lines.append(f'FINAL,{final}')

    return ('# Surge export (supported-protocol subset) generated by mango-connect\n'
            '# vless/anytls/mieru/hysteria2 nodes are not representable in Surge and are omitted.\n'
            '[General]\nloglevel = notify\n\n'
            '[Proxy]\n' + '\n'.join(proxy_lines) + '\n\n'
            '[Proxy Group]\nPROXY = select, ' + ', '.join(['DIRECT'] + tags) + '\n\n'
            '[Rule]\n' + '\n'.join(rule_lines) + '\n'), skipped


# ----------------------------------------------------------------- quantumult X

def to_qx(clash: Dict[str, Any]) -> Tuple[str, List[Tuple[str, str]]]:
    """Quantumult X server_local subset + rules (supported protocols)."""
    skipped: List[Tuple[str, str]] = []
    server_lines: List[str] = []
    for p in clash.get('proxies') or []:
        if not isinstance(p, dict):
            continue
        name = str(p.get('name') or '')
        ptype = str(p.get('type') or '').lower()
        server = str(p.get('server') or '')
        port = int(p.get('port') or 0)
        if ptype == 'vmess':
            method = str(p.get('cipher') or 'auto')
            line = (f'vmess={server}:{port}, method={method}, password={p.get("uuid")}, '
                    f'fast-open=false, udp-relay=false, tag={name}')
            if p.get('tls'):
                line += ', tls=true'
            if p.get('servername'):
                line += f', tls-host={p["servername"]}'
            server_lines.append(line)
        elif ptype == 'http':
            auth = ''
            if p.get('username'):
                auth = f', username={p["username"]}, password={p.get("password")}'
            line = f'http={server}:{port}{auth}, fast-open=false, udp-relay=false, tag={name}'
            server_lines.append(line)
        elif ptype == 'socks5':
            auth = ''
            if p.get('username'):
                auth = f', username={p["username"]}, password={p.get("password")}'
            line = f'socks5={server}:{port}{auth}, fast-open=false, udp-relay=false, tag={name}'
            server_lines.append(line)
        else:
            skipped.append((name, f'{ptype} has no Quantumult X server_local line'))
    rule_lines: List[str] = []
    for rule in clash.get('rules') or []:
        rtype, target, value, options = _parse_rule(rule)
        if not rtype:
            continue
        qx_target = 'direct' if target == 'DIRECT' else 'proxy'
        qx_type = {'DOMAIN-SUFFIX': 'DOMAIN-SUFFIX', 'DOMAIN': 'DOMAIN',
                   'DOMAIN-KEYWORD': 'DOMAIN-KEYWORD', 'IP-CIDR': 'IP-CIDR',
                   'IP-CIDR6': 'IP-CIDR6', 'GEOIP': 'GEOIP'}.get(rtype)
        if qx_type and value:
            rule_lines.append(f'{qx_type},{value},{qx_target}')
    rule_lines.append('FINAL,proxy')
    return ('# Quantumult X export (supported-protocol subset) by mango-connect\n'
            '# vless/anytls/tuic/mieru/hysteria2 nodes are not representable here and are omitted.\n'
            '[server_local]\n' + '\n'.join(server_lines) + '\n\n'
            '[rule]\n' + '\n'.join(rule_lines) + '\n'), skipped


# ----------------------------------------------------------------- uri list

def _uri_for(p: Dict[str, Any]) -> Optional[str]:
    ptype = str(p.get('type') or '').lower()
    name = quote(str(p.get('name') or ''))
    server = str(p.get('server') or '')
    port = int(p.get('port') or 0)
    if ptype == 'vless':
        q = []
        if p.get('tls'):
            q.append('security=tls')
        r = p.get('reality-opts') or {}
        if r.get('public-key'):
            q.append(f'pbk={r["public-key"]}')
        if r.get('short-id'):
            q.append(f'sid={r["short-id"]}')
        fp = p.get('client-fingerprint')
        if fp:
            q.append(f'fp={fp}')
        sni = p.get('servername') or p.get('sni')
        if sni:
            q.append(f'sni={sni}')
        flow = p.get('flow')
        if flow:
            q.append(f'flow={flow}')
        return f'vless://{p.get("uuid")}@{server}:{port}?{"&".join(q)}#{name}'
    if ptype == 'vmess':
        payload = json.dumps({'v': '2', 'ps': name, 'add': server, 'port': str(port),
                              'id': str(p.get('uuid')), 'aid': str(p.get('alterId') or 0),
                              'scy': p.get('cipher') or 'auto', 'tls': 'tls' if p.get('tls') else '',
                              'sni': p.get('servername') or ''}, ensure_ascii=False)
        return 'vmess://' + base64.b64encode(payload.encode()).decode()
    if ptype == 'trojan':
        return f'trojan://{quote(str(p.get("password") or ""))}@{server}:{port}?#{name}'
    if ptype in ('ss', 'shadowsocks'):
        userinfo = base64.b64encode(
            f'{p.get("cipher")}:{p.get("password")}'.encode()).decode().rstrip('=')
        return f'ss://{userinfo}@{server}:{port}#{name}'
    if ptype in ('hysteria2', 'hy2'):
        return f'hysteria2://{quote(str(p.get("password") or ""))}@{server}:{port}?#{name}'
    if ptype == 'tuic':
        return f'tuic://{p.get("uuid")}:{quote(str(p.get("password") or ""))}@{server}:{port}?#{name}'
    if ptype == 'anytls':
        return f'anytls://{quote(str(p.get("password") or ""))}@{server}:{port}?#{name}'
    return None


def to_uri_list(clash: Dict[str, Any]) -> Tuple[str, List[Tuple[str, str]]]:
    """v2rayN-style URI list (base64 of CRLF-joined share URIs)."""
    skipped: List[Tuple[str, str]] = []
    uris: List[str] = []
    for p in clash.get('proxies') or []:
        if not isinstance(p, dict):
            continue
        uri = _uri_for(p)
        if uri:
            uris.append(uri)
        else:
            skipped.append((str(p.get('name') or '?'),
                            f'{p.get("type")} has no share URI'))
    body = '\n'.join(uris) + ('\n' if uris else '')
    return base64.b64encode(body.encode()).decode(), skipped
