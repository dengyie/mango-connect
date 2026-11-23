"""Shared constants for mango-share (kept import-light for tests/server)."""

import os
from pathlib import Path
from typing import Mapping, Optional

# Deployment layout: the code lives at <state>/src/*.py, so the state dir
# defaults to this file's grandparent and the gateway artifacts dir to a
# sibling `clash/` of the state dir. Both are overridable via env.
_DEFAULT_STATE_DIR = Path(__file__).resolve().parent.parent
DEFAULT_PUBLIC_HOST = 'http://127.0.0.1:2054'


def state_dir(env: Optional[Mapping[str, str]] = None) -> Path:
    env = env or os.environ
    return Path(env.get('SHARE_STATE_DIR') or _DEFAULT_STATE_DIR).resolve()


def clash_dir(env: Optional[Mapping[str, str]] = None) -> Path:
    env = env or os.environ
    raw = env.get('SHARE_CLASH_DIR')
    return Path(raw).resolve() if raw else state_dir(env).parent / 'clash'


def public_host(env: Optional[Mapping[str, str]] = None) -> str:
    """Public base URL used in subscription links and emails (no trailing /)."""
    env = env or os.environ
    return (env.get('SHARE_PUBLIC_HOST') or DEFAULT_PUBLIC_HOST).rstrip('/')

RENDER_REV = '2'
# The profile name clients display (profile-title header / config filename).
# This is a user-visible brand surface, NOT a technical identifier - the
# technical ids (server_version, log prefixes) are separate literals.
PROFILE_TITLE = 'mango-connect'
NODE_PREFIX = '[MS] '
# Loop guard: our own output, plus the name subscription-manager would inject
# when this public URL is pulled back as a `mango-share-public` source.
LOOP_GUARD_PREFIXES = ('[MS] ', '[mango-share-public] ')
