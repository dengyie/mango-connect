#!/usr/bin/env python3
"""mango-connect node agent: sing-box v2ray_api -> mango-share ingest.

Runs on each self-hosted proxy node. Polls sing-box's V2Ray StatsService
(experimental.v2ray_api, gRPC) with reset=true, so every response IS the
delta since the last poll, and POSTs per-user byte totals to the station:

    POST <AGENT_API_BASE>/ingest/traffic
    Authorization: Bearer <node token>   (tokens.py add <name> --nodes)
    {"node": "<node-name>", "updates": [{"user": "<username>", "up": N, "down": N}]}

Counters look like `user>>>alice>>>traffic>>>uplink`. Only per-user counters
are reported; unknown users are skipped server-side (audited, not errors).

Dependencies on the node: `pip install grpcio` (no protobuf needed — the
QueryStats request/response wire format is hand-packed below; it is tiny and
stable: request = {pattern:string=1, reset:bool=2}, response =
repeated Stat {name:string=1, value:int64=2}).

Env:
  AGENT_NODE_NAME    identifier reported with each batch (required)
  AGENT_NODE_TOKEN   node token from the station (required)
  AGENT_API_BASE     station base URL, e.g. https://share.example.com (required)
  AGENT_SING_API     sing-box v2ray_api listen (default 127.0.0.1:10085)
  AGENT_INTERVAL     poll seconds (default 60)

Run: `AGENT_... python3 agent.py` under the provided systemd unit, or a
tmux/screen session for a quick pilot.
"""

from __future__ import annotations

import json
import os
import re
import sys
import time
from typing import Any, Dict, List, Optional, Tuple

# grpcio is only required for the live polling loop (main/query_stats); the
# wire-format helpers below are pure stdlib and unit-testable anywhere.

STATS_METHOD = '/v2ray.core.app.stats.command.StatsService/QueryStats'
_COUNTER_RE = re.compile(r'^user>>>(?P<user>.+)>>>traffic>>>(?P<dir>uplink|downlink)$')


# ---------------------------------------------------------- wire format

def pack_query_stats(pattern: str = '', reset: bool = True) -> bytes:
    """QueryStats{pattern:string=1, reset:bool=2} -> protobuf bytes."""
    out = bytearray()
    if pattern:
        raw = pattern.encode('utf-8')
        out += bytes([0x0A, len(raw)]) + raw
    if reset:
        out += bytes([0x10, 0x01])
    return bytes(out)


def _read_varint(buf: bytes, pos: int) -> Tuple[int, int]:
    result, shift = 0, 0
    while True:
        if pos >= len(buf):
            raise ValueError('truncated varint')
        b = buf[pos]
        pos += 1
        result |= (b & 0x7F) << shift
        if not b & 0x80:
            return result, pos
        shift += 7
        if shift > 70:
            raise ValueError('varint too long')


def _parse_stat(buf: bytes) -> Tuple[str, int]:
    name, value = '', 0
    pos = 0
    while pos < len(buf):
        tag, pos = _read_varint(buf, pos)
        field, wire = tag >> 3, tag & 0x07
        if wire == 2:
            ln, pos = _read_varint(buf, pos)
            chunk = buf[pos:pos + ln]
            pos += ln
            if field == 1:
                name = chunk.decode('utf-8', 'replace')
        elif wire == 0:
            value, pos = _read_varint(buf, pos)
            if field == 2:
                pass
        else:
            raise ValueError(f'unsupported wire type {wire}')
    return name, value


def parse_query_stats_response(body: bytes) -> Dict[str, Tuple[int, int]]:
    """QueryStatsResponse{repeated Stat stats=1} -> {user: (up, down)}."""
    stats: Dict[str, Tuple[int, int]] = {}
    pos = 0
    while pos < len(body):
        tag, pos = _read_varint(body, pos)
        field, wire = tag >> 3, tag & 0x07
        if wire != 2:
            raise ValueError(f'unsupported wire type {wire}')
        ln, pos = _read_varint(body, pos)
        chunk = body[pos:pos + ln]
        pos += ln
        if field == 1:
            name, value = _parse_stat(chunk)
            m = _COUNTER_RE.match(name)
            if not m:
                continue  # inbound/outbound counters are not per-user
            user, direction = m.group('user'), m.group('dir')
            prev = stats.get(user, (0, 0))
            up, down = prev[0], prev[1]
            if direction == 'uplink':
                up += value
            else:
                down += value
            stats[user] = (up, down)
    return stats


# ---------------------------------------------------------- agent loop

def query_stats(channel: Any) -> Dict[str, Tuple[int, int]]:
    import grpc  # noqa: deferred: only the live loop needs it
    stub = channel.unary_unary(
        STATS_METHOD,
        request_serializer=lambda b: b,
        response_deserializer=lambda b: b,
    )
    body = stub(pack_query_stats(reset=True), timeout=10)
    if not isinstance(body, (bytes, bytearray)):
        body = bytes(body)
    return parse_query_stats_response(bytes(body))


def post_ingest(base: str, token: str, node: str,
                updates: List[Dict[str, Any]]) -> Tuple[int, str]:
    import urllib.request
    body = json.dumps({'node': node, 'updates': updates}).encode('utf-8')
    req = urllib.request.Request(
        base.rstrip('/') + '/ingest/traffic', data=body,
        headers={'Authorization': f'Bearer {token}',
                 'Content-Type': 'application/json',
                 'User-Agent': 'mango-connect-node-agent/1'}, method='POST')
    try:
        with urllib.request.urlopen(req, timeout=15) as resp:
            return resp.status, resp.read(256).decode('utf-8', 'replace')
    except OSError as e:
        return 0, str(e)[:200]


def run_once(channel: Any, base: str, token: str, node: str) -> Dict[str, Any]:
    stats = query_stats(channel)
    updates = [{'user': u, 'up': up, 'down': down}
               for u, (up, down) in stats.items() if up or down]
    if not updates:
        return {'users': 0, 'status': None, 'detail': 'no traffic'}
    status, detail = post_ingest(base, token, node, updates)
    return {'users': len(updates), 'status': status, 'detail': detail}


def main() -> int:
    env = os.environ
    node = env.get('AGENT_NODE_NAME', '')
    token = env.get('AGENT_NODE_TOKEN', '')
    base = env.get('AGENT_API_BASE', '').rstrip('/')
    target = env.get('AGENT_SING_API', '127.0.0.1:10085')
    interval = int(env.get('AGENT_INTERVAL', '60'))
    if not node or not token or not base:
        print('AGENT_NODE_NAME, AGENT_NODE_TOKEN and AGENT_API_BASE are required', file=sys.stderr)
        return 2
    try:
        import grpc
    except ImportError:
        print('missing dependency: pip install grpcio', file=sys.stderr)
        return 2
    channel = grpc.insecure_channel(target)
    print(f'node-agent: node={node} sing-api={target} station={base} interval={interval}s',
          flush=True)
    while True:
        try:
            result = run_once(channel, base, token, node)
            print(f'poll: {result}', flush=True)
        except grpc.RpcError as e:
            print(f'poll: grpc error {e.code()}', flush=True)
        except Exception as e:  # keep the loop alive; station outages etc.
            print(f'poll: error {e}', flush=True)
        time.sleep(interval)


if __name__ == '__main__':
    sys.exit(main())
