#!/usr/bin/env python3
"""Sync dead-node names into mango-share's exclude.json.

Reads a 3xui-health results.json ({alive, slow, dead}) and merges the dead
list into SHARE_STATE_DIR/exclude.json, which render_public.py hard-filters.
Run after each confirm_dead.py pass; safe to re-run (idempotent union).

Usage:
    python3 sync_exclude.py [results.json]
"""
from __future__ import annotations

import json
import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import render_public  # for default_paths()


def main() -> int:
    results_path = Path(sys.argv[1]) if len(sys.argv) > 1 else Path('/tmp/scripts/results.json')
    try:
        results = json.loads(results_path.read_text(encoding='utf-8'))
    except OSError as e:
        raise SystemExit(f'cannot read {results_path}: {e}')
    except ValueError as e:
        raise SystemExit(f'{results_path}: invalid JSON: {e}')
    if not isinstance(results, dict):
        raise SystemExit(f'{results_path}: expected a JSON object with a "dead" list')
    dead = [str(n) for n in results.get('dead') or []]
    paths = render_public.default_paths()
    current = render_public.load_json_list(paths['exclude'])
    merged = sorted(set(current) | set(dead))
    added = len(merged) - len(current)
    paths['exclude'].parent.mkdir(parents=True, exist_ok=True)
    tmp = paths['exclude'].with_suffix('.tmp')
    tmp.write_text(json.dumps({'nodes': merged}, ensure_ascii=False, indent=1) + '\n', encoding='utf-8')
    os.chmod(tmp, 0o640)
    os.replace(tmp, paths['exclude'])
    print(f'exclude.json: {len(current)} -> {len(merged)} (+{added} dead from {results_path.name})')
    return 0


if __name__ == '__main__':
    sys.exit(main())
