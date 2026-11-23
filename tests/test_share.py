#!/usr/bin/env python3
"""Tests for mango-share renderer, tokens, loop guard, leak gate, concurrency."""

from __future__ import annotations

import json
import os
import sys
import tempfile
import time
import unittest
import threading
import urllib.error
import urllib.request
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / 'src'))
import render_public as rp
import tokens as tk


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    """HTTPError on 3xx so tests can assert redirects explicitly."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None



def node(name, ntype='vless', **extra):
    p = {'name': name, 'type': ntype, 'server': '1.2.3.4', 'port': 443}
    p.update(extra)
    return p


SAMPLE_POOL = [
    node('[自建] 🇺🇸VLESS-AWS-Oregon-Reality', uuid='SECRET-UUID-1',
         **{'dialer-proxy': '[自建] EasyTier-mesh-socks'}),
    node('[自建] 🇨🇳VLESS-Tebi-HZ-Reality', uuid='SECRET-UUID-2',
         **{'reality-opts': {'public-key': 'PK-NOT-SHARED-0123456789abcdef', 'short-id': '9153'}}),
    node('[自建] 🏠home-win-mesh', ntype='http'),
    node('[自建] 🇺🇸PIGEONW-家宽-01', ntype='http'),
    node('[自建] EasyTier-mesh-socks', ntype='http', server='10.144.144.32'),
    node('[tomorin] [anytls]JP Osaka Oracle'),
    node('[share] 🇺🇸US-Vmess1(Bwh)'),
    node('新加坡_BGP_B'),
    node('套餐到期提醒，请联系客服'),  # fake announcement node
    node('[MS] already-public'),        # loop guard: own output
    node('[mango-share-public] [MS] echoed'),  # loop guard: re-imported source
]


class RenderTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.src = self.root / 'mango-clash.yaml'
        self.wl = self.root / 'share-nodes.json'
        self.ex = self.root / 'exclude.json'
        self.out = self.root / 'public/mango-share.yaml'
        self.meta = self.root / 'public/mango-share.meta.json'
        import yaml
        self.src.write_text(yaml.safe_dump({
            'proxies': SAMPLE_POOL,
            'proxy-groups': [{'name': 'PROXY', 'type': 'select',
                              'proxies': ['[自建] 🇺🇸VLESS-AWS-Oregon-Reality']},
                             {'name': '🏠家宽', 'type': 'select',
                              'proxies': ['[自建] 🏠home-win-mesh', 'DIRECT']}],
            'rules': ['DOMAIN-SUFFIX,example.com,PROXY', 'MATCH,PROXY'],
        }), encoding='utf-8')
        self.wl.write_text(json.dumps([
            '[自建] 🇺🇸VLESS-AWS-Oregon-Reality',
            '[tomorin] [anytls]JP Osaka Oracle',
            '[share] 🇺🇸US-Vmess1(Bwh)',
            '新加坡_BGP_B',
        ]), encoding='utf-8')
        self.ex.write_text(json.dumps(['[share] 🇺🇸US-Vmess1(Bwh)']), encoding='utf-8')  # dead per health tool

    def tearDown(self):
        self.tmp.cleanup()

    def _render(self):
        return rp.render(self.src, self.wl, self.ex, self.out, self.meta)

    def test_selection_rules(self):
        meta = self._render()
        import yaml
        doc = yaml.safe_load(self.out.read_text(encoding='utf-8'))
        names = [p['name'] for p in doc['proxies']]
        # whitelisted & alive only, renamed with prefix
        self.assertEqual(names, ['[MS] [自建] 🇺🇸VLESS-AWS-Oregon-Reality', '[MS] [tomorin] [anytls]JP Osaka Oracle', '[MS] 新加坡_BGP_B'])
        self.assertEqual(meta['node_count'], 3)

    def test_no_secret_leak(self):
        self._render()
        text = self.out.read_text(encoding='utf-8')
        # Whitelisted self-built node shares its credential BY DESIGN;
        # every non-whitelisted one must never leak.
        self.assertIn('SECRET-UUID-1', text)  # AWS Oregon: explicitly shared
        self.assertNotIn('SECRET-UUID-2', text)  # Tebi-HZ: not whitelisted
        self.assertNotIn('PK-NOT-SHARED', text)  # reality-opts of excluded node
        for pattern in ('[自建] 🇨🇳', 'home-win', 'PIGEONW', 'EasyTier-mesh'):
            self.assertNotIn(pattern, text)

    def test_dialer_proxy_stripped(self):
        # Regression: whitelisted AWS node carries dialer-proxy pointing at an
        # internal mesh chain; a public client cannot resolve it and the
        # reference itself leaks private topology.
        self._render()
        import yaml
        doc = yaml.safe_load(self.out.read_text(encoding='utf-8'))
        for p in doc['proxies']:
            self.assertNotIn('dialer-proxy', p, f'dialer-proxy leaked on {p["name"]}')

    def test_render_full_scope_byte_mirror(self):
        # SHARE_SCOPE=full: the output is a byte-level mirror of the gateway
        # client export (all nodes incl. home/mesh, verbatim groups+rules,
        # loop-guard prefixes included in the bytes; the leak check warns).
        import os
        os.environ['SHARE_SCOPE'] = 'full'
        try:
            self.ex.write_text(json.dumps([]), encoding='utf-8')
            meta = rp.render(self.src, self.wl, self.ex, self.out, self.meta)
            self.assertEqual(meta['scope'], 'full')
            self.assertEqual(meta['node_count'], 11)  # whole pool, verbatim
            self.assertIn(meta['aligned'], (True, False, None))
            # byte-identical to the source (gateway client export)
            self.assertEqual(self.out.read_bytes(), self.src.read_bytes())
            # whitelist-mode rendering still rebuilds minimal groups (rollback path)
            os.environ['SHARE_SCOPE'] = 'whitelist'
            rp.render(self.src, self.wl, self.ex, self.out, self.meta)
            import yaml
            doc = yaml.safe_load(self.out.read_text(encoding='utf-8'))
            self.assertEqual([g['name'] for g in doc['proxy-groups']], ['PROXY', 'AUTO'])
        finally:
            os.environ['SHARE_SCOPE'] = 'whitelist'
            self.wl.write_text(json.dumps([
                '[自建] 🇺🇸VLESS-AWS-Oregon-Reality',
                '[tomorin] [anytls]JP Osaka Oracle',
                '[share] 🇺🇸US-Vmess1(Bwh)',
                '新加坡_BGP_B',
            ]), encoding='utf-8')
            self.ex.write_text(json.dumps(['[share] 🇺🇸US-Vmess1(Bwh)']), encoding='utf-8')

    def test_check_leaks_full_scope_warns_loop_guard(self):
        # full scope: loop-guard prefixes in the bytes are flagged for the
        # operator (gateway skip_merge is the primary guard)
        body = '[MS] [自建] something\n[自建] 🏠home-win-mesh\n'
        bad = rp.check_leaks(body, [], [{'name': '[MS] [自建] something'}], scope='full')
        self.assertTrue(any(b.startswith('loop-guard:') for b in bad))

    def test_render_user_substitutes_and_gates(self):
        import copy
        src = copy.deepcopy(self.src)
        wl = json.loads(self.wl.read_text())
        # whitelist the two vless pool nodes with a mapped credential key
        self.wl.write_text(json.dumps([
            '[\u81ea\u5efa] \U0001f1fa\U0001f1f8VLESS-AWS-Oregon-Reality',
            '[\u81ea\u5efa] \U0001f1e8\U0001f1f3VLESS-Tebi-HZ-Reality',
        ]), encoding='utf-8')
        self.ex.write_text(json.dumps([]), encoding='utf-8')
        cred_map = [{'node': '[自建] 🇺🇸VLESS-AWS-Oregon-Reality', 'key': 'aws-1', 'type': 'vless'}]
        user = {'id': 'u-x', 'credentials': {'aws-1': {'uuid': 'USER-UUID-0001'}}}
        others = ['OTHER-USER-UUID-9999']
        out_u = self.out.parent / 'users/u-x.yaml'
        meta_u = self.out.parent / 'users/u-x.meta.json'
        rp.render_user(src, self.wl, self.ex, out_u, meta_u,
                       user=user, cred_map=cred_map, other_secrets=others)
        import yaml
        doc = yaml.safe_load(out_u.read_text(encoding='utf-8'))
        aws = [p for p in doc['proxies'] if 'AWS-Oregon' in p['name']][0]
        self.assertEqual(aws['uuid'], 'USER-UUID-0001')
        self.assertNotIn('SECRET-UUID-1', out_u.read_text(encoding='utf-8'))
        # another user's uuid must never appear (per-user leak gate)
        with self.assertRaises(ValueError):
            rp.render_user(src, self.wl, self.ex, out_u, meta_u,
                           user=user, cred_map=cred_map,
                           other_secrets=['USER-UUID-0001'])
        # unprovisioned user -> shared credential stays (additive rollout)
        user2 = {'id': 'u-y', 'credentials': {}}
        rp.render_user(src, self.wl, self.ex, out_u, meta_u,
                       user=user2, cred_map=cred_map, other_secrets=[])
        doc2 = yaml.safe_load(out_u.read_text(encoding='utf-8'))
        aws2 = [p for p in doc2['proxies'] if 'AWS-Oregon' in p['name']][0]
        self.assertEqual(aws2['uuid'], 'SECRET-UUID-1')

    def test_render_user_substitutes_and_gates(self):
        self.wl.write_text(json.dumps([
            '[\u81ea\u5efa] \U0001f1fa\U0001f1f8VLESS-AWS-Oregon-Reality',
            '[\u81ea\u5efa] \U0001f1e8\U0001f1f3VLESS-Tebi-HZ-Reality',
        ]), encoding='utf-8')
        self.ex.write_text(json.dumps([]), encoding='utf-8')
        cred_map = [{'node': '[自建] 🇺🇸VLESS-AWS-Oregon-Reality', 'key': 'aws-1', 'type': 'vless'}]
        user = {'id': 'u-x', 'credentials': {'aws-1': {'uuid': 'USER-UUID-0001'}}}
        out_u = self.out.parent / 'users/u-x.yaml'
        rp.render_user(self.src, self.wl, self.ex, out_u,
                       self.out.parent / 'users/u-x.meta.json',
                       user=user, cred_map=cred_map, other_secrets=['OTHER-USER-UUID-9999'])
        import yaml
        doc = yaml.safe_load(out_u.read_text(encoding='utf-8'))
        aws = [p for p in doc['proxies'] if 'AWS-Oregon' in p['name']][0]
        self.assertEqual(aws['uuid'], 'USER-UUID-0001')
        self.assertNotIn('SECRET-UUID-1', out_u.read_text(encoding='utf-8'))
        with self.assertRaises(ValueError):  # per-user leak gate
            rp.render_user(self.src, self.wl, self.ex, out_u,
                           self.out.parent / 'users/u-x.meta.json',
                           user=user, cred_map=cred_map,
                           other_secrets=['USER-UUID-0001'])
        user2 = {'id': 'u-y', 'credentials': {}}
        rp.render_user(self.src, self.wl, self.ex, out_u,
                       self.out.parent / 'users/u-x.meta.json',
                       user=user2, cred_map=cred_map, other_secrets=[])
        doc2 = yaml.safe_load(out_u.read_text(encoding='utf-8'))
        aws2 = [p for p in doc2['proxies'] if 'AWS-Oregon' in p['name']][0]
        self.assertEqual(aws2['uuid'], 'SECRET-UUID-1')  # additive: shared stays

    def test_render_user_tuic_anytls_shapes(self):
        self.wl.write_text(json.dumps(['[tomorin] [anytls]JP Osaka Oracle',
                                       '[share] 🇺🇸US-Vmess1(Bwh)']), encoding='utf-8')
        self.ex.write_text(json.dumps([]), encoding='utf-8')
        cred_map = [
            {'node': '[tomorin] [anytls]JP Osaka Oracle', 'key': 'anytls-node', 'type': 'anytls'},
            {'node': '[share] 🇺🇸US-Vmess1(Bwh)', 'key': 'tuic-node', 'type': 'tuic'},
        ]
        user = {'id': 'u-x', 'credentials': {
            'anytls-node': {'uuid': 'ANYTLS-PASS-0001'},
            'tuic-node': {'uuid': 'TUIC-UUID-0001'}}}
        out_u = self.out.parent / 'users/u-x.yaml'
        rp.render_user(self.src, self.wl, self.ex, out_u,
                       self.out.parent / 'users/u-x.meta.json',
                       user=user, cred_map=cred_map, other_secrets=[])
        import yaml
        doc = yaml.safe_load(out_u.read_text(encoding='utf-8'))
        anytls = [p for p in doc['proxies'] if 'anytls' in p['name']][0]
        tuic = [p for p in doc['proxies'] if 'Vmess1' in p['name']][0]
        self.assertEqual(anytls.get('password'), 'ANYTLS-PASS-0001')
        self.assertEqual(tuic.get('uuid'), 'TUIC-UUID-0001')
        self.assertEqual(tuic.get('password'), 'TUIC-UUID-0001')

    def test_check_leaks_detects_secrets_and_names(self):
        # Direct tests of the leak gate: it must flag non-whitelisted names,
        # credentials and mesh servers present in output text.
        wl = ['[自建] 🇺🇸VLESS-AWS-Oregon-Reality']
        pool = [dict(p) for p in SAMPLE_POOL]
        # Simulate a broken render: excluded node's secret + name + mesh server present
        bad_text = 'uuid: SECRET-UUID-2\n[自建] EasyTier-mesh-socks\nserver: 10.144.144.32\n🏠home-win'
        bad = rp.check_leaks(bad_text, wl, pool)
        self.assertTrue(any('SECRET-UUID-2' in b or 'secret:uuid' in b for b in bad))
        self.assertTrue(any('mesh-server' in b for b in bad))
        self.assertTrue(any('home-broadband' in b for b in bad))
        # Clean render output must pass (whitelist = the render's actual whitelist)
        self._render()
        import yaml
        wl_render = json.loads(self.wl.read_text(encoding='utf-8'))
        src = yaml.safe_load(self.src.read_text(encoding='utf-8'))
        clean = rp.check_leaks(self.out.read_text(encoding='utf-8'), wl_render, src['proxies'])
        self.assertEqual(clean, [])

    def test_loop_guard(self):
        self._render()
        text = self.out.read_text(encoding='utf-8')
        self.assertNotIn('[MS] already-public', text)
        self.assertNotIn('[mango-share-public]', text)

    def test_groups_and_rules(self):
        self._render()
        import yaml
        doc = yaml.safe_load(self.out.read_text(encoding='utf-8'))
        gnames = [g['name'] for g in doc['proxy-groups']]
        self.assertEqual(gnames, ['PROXY', 'AUTO'])
        text = self.out.read_text(encoding='utf-8')
        for banned in ('🎯Claude', '🎯OpenAI', '🏠家宽', 'cpa-clean-egress'):
            self.assertNotIn(banned, text)
            self.assertNotIn(banned, json.dumps(gnames))
        self.assertNotIn('meeting.tencent.com', text)
        rules = doc['rules']
        self.assertEqual(rules[-1], 'MATCH,PROXY')

    def test_no_empty_groups(self):
        self._render()
        import yaml
        doc = yaml.safe_load(self.out.read_text(encoding='utf-8'))
        for g in doc['proxy-groups']:
            self.assertTrue(g.get('proxies'), f'empty group {g["name"]}')

    def test_idempotent_bytes(self):
        m1 = self._render()
        b1 = self.out.read_bytes()
        m2 = self._render()
        self.assertEqual(b1, self.out.read_bytes())
        self.assertEqual(m1['sha256'], m2['sha256'])

    def test_concurrent_renders_consistent(self):
        # 8 threads rendering simultaneously (the server's ensure_fresh is
        # lock-serialized, but render() itself must also be safe standalone):
        # final output must parse and match meta sha.
        import hashlib
        errors = []
        def run():
            try:
                rp.render(self.src, self.wl, self.ex, self.out, self.meta)
            except Exception as e:  # pragma: no cover
                errors.append(e)
        threads = [threading.Thread(target=run) for _ in range(8)]
        [t.start() for t in threads]
        [t.join() for t in threads]
        self.assertEqual(errors, [])
        import yaml
        doc = yaml.safe_load(self.out.read_text(encoding='utf-8'))
        meta = json.loads(self.meta.read_text(encoding='utf-8'))
        self.assertEqual(len(doc['proxies']), meta['node_count'])
        body_sha = hashlib.sha256(self.out.read_bytes()).hexdigest()
        self.assertEqual(body_sha, meta['sha256'])

    def test_empty_result_refused(self):
        self.wl.write_text(json.dumps([]), encoding='utf-8')
        with self.assertRaises(ValueError):
            self._render()

    def test_no_tmp_files_left_behind(self):
        self._render()
        leftovers = [p.name for p in self.out.parent.iterdir() if p.suffix == '.tmp']
        self.assertEqual(leftovers, [])


class TokenTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.tf = Path(self.tmp.name) / 'tokens.json'

    def tearDown(self):
        self.tmp.cleanup()

    def test_add_verify_revoke(self):
        records = tk.load(self.tf)
        token = 'unittest-token-abc'
        records.append({'id': 'x', 'name': 'friend', 'token_sha256': tk._hash(token),
                        'created': 0, 'last_used': None, 'revoked': False})
        tk.save(self.tf, records)
        rec = tk.verify(self.tf, token)
        self.assertIsNotNone(rec)
        self.assertEqual(rec['name'], 'friend')
        # wrong token
        self.assertIsNone(tk.verify(self.tf, 'wrong'))
        # empty token never matches
        self.assertIsNone(tk.verify(self.tf, ''))
        # revoke: write revoked record via the locked save path (as CLI does)
        rec['revoked'] = True
        tk._save_locked(self.tf, [rec])
        self.assertTrue(tk.load(self.tf)[0]['revoked'])
        self.assertIsNone(tk.verify(self.tf, token))

    def test_file_permissions(self):
        import os
        tk.save(self.tf, [])
        mode = os.stat(self.tf).st_mode & 0o777
        self.assertEqual(mode, 0o640)

    def test_concurrent_touch_preserves_records(self):
        # Server touch (usage.log append) must never rewrite tokens.json;
        # concurrent add + verify + touch must not lose any record.
        tk._save_locked(self.tf, [{'id': 'a', 'name': 'friend', 'token_sha256': tk._hash('tok-a'),
                                   'created': 0, 'last_used': None, 'revoked': False}])
        rec = tk.verify(self.tf, 'tok-a')
        self.assertIsNotNone(rec)
        errors = []
        def churn():
            try:
                for _ in range(20):
                    tk.touch(rec, self.tf)  # server hot path
            except Exception as e:
                errors.append(e)
        def add_token():
            try:
                for i in range(10):
                    # emulate CLI add without printing
                    import contextlib, io
                    with contextlib.redirect_stdout(io.StringIO()):
                        pass
                    tk._save_locked(self.tf, tk.load(self.tf) + [{
                        'id': f'b{i}', 'name': f'x{i}', 'token_sha256': tk._hash(f't{i}'),
                        'created': 0, 'last_used': None, 'revoked': False}])
            except Exception as e:
                errors.append(e)
        threads = [threading.Thread(target=churn), threading.Thread(target=add_token)]
        [t.start() for t in threads]
        [t.join() for t in threads]
        self.assertEqual(errors, [])
        records = tk.load(self.tf)
        ids = {r['id'] for r in records}
        self.assertIn('a', ids)          # original record intact
        self.assertEqual(len([i for i in ids if i.startswith('b')]), 10)  # no lost adds
        usage = tk.last_used_map(self.tf)
        self.assertGreater(usage.get('a', 0), 0)

    def test_save_preserves_ownership(self):
        # Regression: root-run CLI (chown to uid 0) must not leave the store
        # unreadable for the unprivileged service user after atomic replace.
        import os
        if os.geteuid() != 0:  # chown to another uid requires root; emulate core logic
            tk.save(self.tf, [{'id': 'x', 'token_sha256': 'a'}])
            # simulate: file owned by someone else, save() again — no crash
            tk.save(self.tf, [])
            self.assertTrue(self.tf.exists())
        else:
            os.chown(self.tf, 65534, 65534)  # nobody
            tk.save(self.tf, [])
            st = os.stat(self.tf)
            self.assertEqual(st.st_uid, 65534)

    def test_revoke_via_touch_semantics(self):
        # revoke + concurrent verify: revoked token must never verify again
        tk._save_locked(self.tf, [{'id': 'a', 'name': 'friend', 'token_sha256': tk._hash('tok-a'),
                                   'created': 0, 'last_used': None, 'revoked': False}])
        rec = tk.verify(self.tf, 'tok-a')
        rec['revoked'] = True
        tk._save_locked(self.tf, [rec])
        self.assertIsNone(tk.verify(self.tf, 'tok-a'))


class HomePageTests(unittest.TestCase):
    """`/` must serve a human landing page (user-facing fix), leaking nothing."""

    HOME = 'http://127.0.0.1:0'  # placeholder; real test spins the server below

    def setUp(self):
        import threading
        from http.server import ThreadingHTTPServer
        sys.path.insert(0, str(Path(__file__).resolve().parent.parent / 'src'))
        import server as srv_mod
        # Point state at an empty temp dir: home page must not touch state.
        import os
        self._old_env = {k: os.environ.get(k) for k in ('SHARE_STATE_DIR', 'SHARE_CLASH_DIR')}
        self.tmp = tempfile.TemporaryDirectory()
        os.environ['SHARE_STATE_DIR'] = self.tmp.name
        os.environ['SHARE_CLASH_DIR'] = self.tmp.name
        import importlib
        importlib.reload(srv_mod)
        self.httpd = ThreadingHTTPServer(('127.0.0.1', 0), srv_mod.Handler)
        self.port = self.httpd.server_address[1]
        threading.Thread(target=self.httpd.serve_forever, daemon=True).start()

    def tearDown(self):
        self.httpd.shutdown()
        for k, v in self._old_env.items():
            if v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = v
        self.tmp.cleanup()

    def _get(self, path):
        import urllib.request
        r = urllib.request.urlopen(f'http://127.0.0.1:{self.port}{path}', timeout=5)
        return r.status, r.read().decode('utf-8', 'replace')

    def test_home_200_no_secrets(self):
        status, body = self._get('/')
        self.assertEqual(status, 200)
        self.assertIn('mango-connect', body)
        self.assertNotIn('mango-share', body)  # visible brand fully renamed
        # must not leak: token store, node names, mesh topology, internal paths
        for banned in ('token_sha256', '[自建]', 'EasyTier', '10.144.144.', '/personal',
                       'SECRET-', 'share-nodes'):
            self.assertNotIn(banned, body)

    def test_brand_asset_get_and_head(self):
        import urllib.request
        get = urllib.request.urlopen(f'http://127.0.0.1:{self.port}/brand/mango-connect-mark.png', timeout=5)
        self.assertEqual(get.status, 200)
        self.assertEqual(get.headers.get_content_type(), 'image/png')
        self.assertGreater(int(get.headers['Content-Length']), 100)
        self.assertEqual(get.read(8), b'\x89PNG\r\n\x1a\n')
        head = urllib.request.urlopen(urllib.request.Request(
            f'http://127.0.0.1:{self.port}/brand/mango-connect-mark.png', method='HEAD'), timeout=5)
        self.assertEqual(head.status, 200)
        self.assertEqual(head.headers.get_content_type(), 'image/png')
        self.assertEqual(int(head.headers['Content-Length']), int(get.headers['Content-Length']))

    def test_home_script_syntax_valid(self):
        # every inline <script> on the landing page must parse: one
        # SyntaxError inside an IIFE silently kills interactive features
        import re as _re
        import subprocess
        import server as _srv
        import users as _us
        body = _srv.pages.landing_page(
            3, [{'region': '美国', 'flag': '🇺🇸', 'count': 3}], role='anon')
        scripts = _re.findall(r'<script>(.*?)</script>', body, _re.S)
        self.assertTrue(scripts, 'landing page must carry its scripts')
        for i, sc in enumerate(scripts):
            with tempfile.NamedTemporaryFile('w', suffix='.js', delete=False) as f:
                f.write(sc)
                path = f.name
            try:
                r = subprocess.run(['node', '--check', path],
                                   capture_output=True, text=True)
                self.assertEqual(r.returncode, 0,
                                 f'script {i} syntax error:\n{r.stderr[:400]}')
            finally:
                import os
                os.unlink(path)

    def test_home_landing_contract(self):
        # landing joins the app shell: one-sentence hero, public region
        # badges, role-aware sidebar, old anchor/import flow gone
        import server as srv_mod
        self.assertFalse(hasattr(srv_mod.Handler, '_HOME_HTML'),
                         '_HOME_HTML must be gone (landing is SSR pages now)')
        status, body = self._get('/')
        self.assertEqual(status, 200)
        text = body  # HomePageTests._get already decodes
        self.assertIn('受邀制节点订阅', text)
        self.assertIn('region-badge', text)
        # anonymous: CTAs point to login, not the user center
        self.assertNotIn('进入用户中心', text)
        self.assertIn('href="/login"', text)
        self.assertIn('联系分享者', text)
        # old homepage sections/flow must be gone
        for gone in ('导入你的订阅', 'sub-url', 'copy-url', '仅本地处理',
                     'id="steps"', 'id="regions"', 'side-nav-group">{item('):
            self.assertNotIn(gone, text)
        # role-aware CTAs are server-side; anonymous sees 登录 CTA
        self.assertIn('href="/login">登录', text)

    def test_unknown_path_still_404_json(self):
        import urllib.error
        with self.assertRaises(urllib.error.HTTPError) as cm:
            self._get('/nope')
        self.assertEqual(cm.exception.code, 404)

    def test_home_links_to_login(self):
        # accounts feature: the landing page must expose the login face
        _, body = self._get('/')
        self.assertIn('href="/login"', body)


class ConverterRuleTests(unittest.TestCase):
    """Multi-format adapters: rule-option parsing, transport/TLS separation,
    group aliases, Surge line integrity (the 2026-11-23 review fixes)."""

    @classmethod
    def setUpClass(cls):
        import format_converters as fc
        cls.fc = fc

    def test_tail_options_never_become_the_target(self):
        fc = self.fc
        clash = {'proxies': [], 'proxy-groups': [], 'rules': [
            'GEOIP,LAN,DIRECT,no-resolve', 'IP-CIDR,10.0.0.0/8,DIRECT,no-resolve']}
        cfg, _ = fc.to_singbox(clash)
        # GEOIP,LAN -> private CIDRs DIRECT (sing-box has no 'lan' geoip set)
        self.assertIn({'ip_cidr': ['10.0.0.0/8', '172.16.0.0/12',
                                   '192.168.0.0/16', '127.0.0.0/8'],
                       'outbound': 'DIRECT'}, cfg['route']['rules'])
        self.assertIn({'ip_cidr': ['10.0.0.0/8'], 'outbound': 'DIRECT'},
                      cfg['route']['rules'])
        # Surge/QX have no LAN geoip set either: expanded to private ranges
        surge, _ = fc.to_surge(clash)
        self.assertIn('IP-CIDR,192.168.0.0/16,DIRECT,no-resolve', surge)
        self.assertNotIn('GEOIP,LAN', surge)
        qx, _ = fc.to_qx(clash)
        self.assertIn('ip-cidr, 192.168.0.0/16, direct', qx)
        self.assertNotIn('GEOIP,LAN', qx)

    def test_match_target_respected(self):
        fc = self.fc
        clash = {'proxies': [], 'proxy-groups': [
            {'name': 'PROXY', 'type': 'select', 'proxies': ['DIRECT']}],
            'rules': ['MATCH,PROXY']}
        cfg, _ = fc.to_singbox(clash)
        self.assertEqual(cfg['route']['final'], 'PROXY')

    def test_plaintext_ws_keeps_transport_without_tls(self):
        fc = self.fc
        p = {'name': 'x', 'type': 'vmess', 'server': 's', 'port': 80,
             'uuid': 'u', 'cipher': 'auto', 'network': 'ws',
             'ws-opts': {'path': '/w'}}
        tls, transport = fc._tls_from_proxy(p)
        self.assertEqual(tls, {})  # no fake TLS on a plaintext endpoint
        self.assertEqual(transport, {'type': 'ws', 'path': '/w'})

    def test_tls_ws_carries_both(self):
        fc = self.fc
        p = {'name': 'x', 'type': 'vless', 'server': 's', 'port': 443,
             'uuid': 'u', 'tls': True, 'network': 'ws',
             'ws-opts': {'path': '/w'}, 'servername': 's.example'}
        tls, transport = fc._tls_from_proxy(p)
        self.assertTrue(tls.get('enabled'))
        self.assertEqual(tls.get('server_name'), 's.example')
        self.assertEqual(transport, {'type': 'ws', 'path': '/w'})

    def test_reality_and_utls_preserved(self):
        fc = self.fc
        p = {'name': 'x', 'type': 'vless', 'server': 's', 'port': 443,
             'uuid': 'u', 'tls': True,
             'reality-opts': {'public-key': 'pk', 'short-id': 'ab'},
             'client-fingerprint': 'chrome'}
        tls, _tr = fc._tls_from_proxy(p)
        self.assertEqual(tls['reality'], {'enabled': True, 'public_key': 'pk',
                                          'short_id': 'ab'})
        self.assertEqual(tls['utls'], {'enabled': True, 'fingerprint': 'chrome'})

    def test_selector_alias_group_not_dropped(self):
        fc = self.fc
        clash = {'proxies': [{'name': 'n1', 'type': 'ss', 'server': 's',
                              'port': 1, 'cipher': 'c', 'password': 'p'}],
                 'proxy-groups': [{'name': 'P', 'type': 'selector',
                                   'proxies': ['n1']}],
                 'rules': ['MATCH,P']}
        cfg, _ = fc.to_singbox(clash)
        tags = {o['tag']: o.get('type') for o in cfg['outbounds']}
        self.assertEqual(tags.get('P'), 'selector')
        self.assertEqual(cfg['route']['final'], 'P')

    def test_surge_skips_delimiter_names(self):
        fc = self.fc
        clash = {'proxies': [{'name': 'a,b=c', 'type': 'ss', 'server': 's',
                              'port': 1, 'cipher': 'c', 'password': 'p'}],
                 'proxy-groups': [], 'rules': []}
        text, skipped = fc.to_surge(clash)
        self.assertNotIn('a,b=c', text)
        self.assertTrue(any('unrepresentable' in r for _n, r in skipped))


class ConverterFidelityTests(unittest.TestCase):
    """2026-11-23 deep review: group resolution, relay chains, always-TLS
    protocols, sing-box 1.12 schema, URI parameter fidelity."""

    @classmethod
    def setUpClass(cls):
        import format_converters as fc
        cls.fc = fc

    def _clash(self):
        return {'proxies': [
            {'name': 'relay', 'type': 'trojan', 'server': 'r.example', 'port': 443,
             'password': 'p,w', 'sni': 'r.example'},
            {'name': 'chained', 'type': 'ss', 'server': '9.9.9.9', 'port': 8388,
             'cipher': 'aes-128-gcm', 'password': 'x', 'dialer-proxy': 'relay'},
            {'name': 'orphan', 'type': 'ss', 'server': '8.8.8.8', 'port': 1,
             'cipher': 'aes-128-gcm', 'password': 'x', 'dialer-proxy': 'gone'},
            {'name': 'hy', 'type': 'hysteria2', 'server': 'h.example', 'port': 443,
             'password': 'pw', 'ports': '20000-30000', 'skip-cert-verify': True},
            {'name': 'tu', 'type': 'tuic', 'server': '3.3.3.3', 'port': 443,
             'uuid': 'U', 'password': 'P', 'sni': 't.example', 'alpn': ['h3']},
            {'name': 'mi', 'type': 'mieru', 'server': '4.4.4.4', 'port': 1, 'password': 'p'},
            {'name': 'bad', 'type': 'ss', 'server': '5.5.5.5', 'port': 'x'},
            {'name': 'vw', 'type': 'vmess', 'server': 'v.example', 'port': 443,
             'uuid': 'V', 'cipher': 'auto', 'tls': True, 'servername': 'v.example',
             'network': 'ws', 'ws-opts': {'path': '/ws', 'headers': {'Host': 'v.example'}}},
            {'name': 'rl', 'type': 'vless', 'server': '1.2.3.4', 'port': 443, 'uuid': 'U1',
             'tls': True, 'servername': 'apple.com', 'flow': 'xtls-rprx-vision',
             'reality-opts': {'public-key': 'PBK', 'short-id': '01'}},
        ], 'proxy-groups': [
            # PROXY references AUTO before AUTO is declared
            {'name': 'PROXY', 'type': 'select', 'proxies': ['AUTO', 'hy', 'DIRECT']},
            {'name': 'AUTO', 'type': 'url-test', 'proxies': ['hy', 'tu', 'mi']},
            {'name': 'EMPTY', 'type': 'select', 'proxies': ['mi', 'orphan']},
            {'name': 'USES-EMPTY', 'type': 'select', 'proxies': ['EMPTY']},
        ], 'rules': ['DOMAIN,ads.example,REJECT', 'DST-PORT,25,REJECT',
                     'GEOIP,CN,DIRECT', 'DOMAIN,x.example,EMPTY',
                     'IP-CIDR,1.0.0.0/8,DIRECT,src', 'MATCH,PROXY']}

    def test_singbox_groups_resolved_to_fixed_point(self):
        cfg, skipped = self.fc.to_singbox(self._clash())
        obs = {o['tag']: o for o in cfg['outbounds']}
        self.assertEqual(obs['PROXY']['outbounds'], ['AUTO', 'hy', 'DIRECT'])
        self.assertEqual(obs['AUTO']['outbounds'], ['hy', 'tu'])
        self.assertNotIn('EMPTY', obs)
        self.assertNotIn('USES-EMPTY', obs)
        self.assertNotIn('mi', obs)
        self.assertNotIn('bad', obs)
        names = dict(skipped)
        self.assertIn('mi', names)
        self.assertIn('bad', names)

    def test_singbox_relay_chain_becomes_detour(self):
        cfg, skipped = self.fc.to_singbox(self._clash())
        obs = {o['tag']: o for o in cfg['outbounds']}
        self.assertEqual(obs['chained']['detour'], 'relay')
        self.assertNotIn('orphan', obs)
        self.assertIn('relay gone unavailable', dict(skipped)['orphan'])

    def test_singbox_always_tls_protocols(self):
        cfg, _ = self.fc.to_singbox(self._clash())
        obs = {o['tag']: o for o in cfg['outbounds']}
        self.assertEqual(obs['hy']['tls'], {'enabled': True, 'server_name': 'h.example',
                                            'insecure': True, 'alpn': ['h3']})
        self.assertEqual(obs['hy']['server_ports'], ['20000:30000'])
        self.assertEqual(obs['tu']['tls']['server_name'], 't.example')
        self.assertNotIn('alpn', obs['tu'])  # alpn belongs to the tls block
        self.assertTrue(obs['relay']['tls']['enabled'])
        self.assertEqual(obs['rl']['tls']['utls']['fingerprint'], 'chrome')

    def test_singbox_112_schema(self):
        cfg, _ = self.fc.to_singbox(self._clash())
        rules = cfg['route']['rules']
        self.assertIn({'domain': ['ads.example'], 'action': 'reject'}, rules)
        self.assertIn({'port': [25], 'action': 'reject'}, rules)
        self.assertIn({'rule_set': ['geoip-cn'], 'outbound': 'DIRECT'}, rules)
        self.assertFalse(any('geoip' in r for r in rules))
        self.assertFalse(any(r.get('ip_cidr') == ['1.0.0.0/8'] for r in rules))
        self.assertFalse(any(r.get('domain') == ['x.example'] for r in rules))
        self.assertEqual(cfg['route']['rule_set'][0]['tag'], 'geoip-cn')
        self.assertEqual(cfg['route']['default_domain_resolver'], 'local')
        for srv in cfg['dns']['servers']:
            self.assertIn('type', srv)
            self.assertNotIn('address', srv)
        self.assertNotIn('block', {o['type'] for o in cfg['outbounds']})

    def test_surge_groups_and_protocols(self):
        text, skipped = self.fc.to_surge(self._clash(), managed_url='https://h/sub/T?fmt=surge')
        self.assertTrue(text.startswith('#!MANAGED-CONFIG https://h/sub/T?fmt=surge'))
        self.assertIn('PROXY = select, AUTO, hy, DIRECT', text)  # DIRECT not first
        self.assertIn('AUTO = url-test, hy, tu, url=', text)
        self.assertIn('hy = hysteria2, h.example, 443, password=pw, skip-cert-verify=true', text)
        self.assertIn('tu = tuic-v5, 3.3.3.3, 443, password=P, uuid=U, alpn=h3, sni=t.example', text)
        self.assertIn('vw = vmess, v.example, 443, username=V, ws=true, ws-path=/ws, '
                      'ws-headers=Host:v.example, tls=true, sni=v.example, vmess-aead=true', text)
        self.assertIn('DOMAIN,ads.example,REJECT', text)
        self.assertIn('DEST-PORT,25,REJECT', text)
        self.assertNotIn('= shadowsocks', text)
        # the relay's password carries the delimiter -> relay and its chain go
        self.assertIn('relay', dict(skipped))
        self.assertIn('chained', dict(skipped))

    def test_surge_underlying_proxy(self):
        clash = {'proxies': [
            {'name': 'r', 'type': 'ss', 'server': 's', 'port': 1, 'cipher': 'c', 'password': 'p'},
            {'name': 'c', 'type': 'ss', 'server': 't', 'port': 2, 'cipher': 'c', 'password': 'p',
             'dialer-proxy': 'r'}], 'proxy-groups': [], 'rules': []}
        text, _ = self.fc.to_surge(clash)
        self.assertIn('c = ss, t, 2, encrypt-method=c, password=p, underlying-proxy=r', text)
        self.assertIn('PROXY = select, r, c, DIRECT', text)

    def test_qx_policies_and_obfs(self):
        text, skipped = self.fc.to_qx(self._clash())
        self.assertNotIn('url-latency-benchmark=AUTO', text)  # hy/tu unsupported -> AUTO empty
        self.assertIn('vmess=v.example:443, method=chacha20-ietf-poly1305, password=V, '
                      'obfs=wss, obfs-uri=/ws, obfs-host=v.example, aead=true', text)
        self.assertIn('host, ads.example, reject', text)
        self.assertIn('final, proxy', text)
        self.assertNotIn('[rule]', text)
        self.assertIn('chained', dict(skipped))

    def test_uri_fidelity(self):
        import base64 as _b64
        from urllib.parse import parse_qs, unquote, urlsplit
        body, skipped = self.fc.to_uri_list(self._clash())
        uris = _b64.b64decode(body).decode().split()
        by = {unquote(urlsplit(u).fragment): u for u in uris if not u.startswith('vmess://')}
        q = parse_qs(urlsplit(by['rl']).query)
        self.assertEqual(q['security'], ['reality'])
        self.assertEqual(q['pbk'], ['PBK'])
        self.assertEqual(q['encryption'], ['none'])
        self.assertEqual(q['type'], ['tcp'])
        self.assertEqual(q['fp'], ['chrome'])
        self.assertTrue(by['relay'].startswith('trojan://p%2Cw@r.example:443?'))
        hq = parse_qs(urlsplit(by['hy']).query)
        self.assertEqual(hq['insecure'], ['1'])
        self.assertEqual(hq['mport'], ['20000-30000'])
        vm = [u for u in uris if u.startswith('vmess://')][0]
        payload = json.loads(_b64.b64decode(vm[8:]))
        self.assertEqual((payload['ps'], payload['net'], payload['path'], payload['host']),
                         ('vw', 'ws', '/ws', 'v.example'))
        self.assertIn('chained', dict(skipped))  # relay chains: no URI form
        ss = self.fc._uri_for({'name': 'a b', 'type': 'ss', 'server': '::1', 'port': 1,
                               'cipher': 'aes-128-gcm', 'password': '>>>?'})
        self.assertTrue(ss.startswith('ss://'))
        self.assertIn('@[::1]:1#a%20b', ss)
        self.assertNotIn('+', ss.split('@')[0])
        self.assertNotIn('/', ss.split('@')[0][5:])


class UserUnitTests(unittest.TestCase):
    """users.py core: scrypt, sessions, billing cycles, service gate, ingest."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.users_path = self.root / 'users.json'
        self._old_env = os.environ.get('SHARE_STATE_DIR')
        os.environ['SHARE_STATE_DIR'] = str(self.root)

    def tearDown(self):
        if self._old_env is None:
            os.environ.pop('SHARE_STATE_DIR', None)
        else:
            os.environ['SHARE_STATE_DIR'] = self._old_env
        self.tmp.cleanup()

    # -- accounts -----------------------------------------------------------

    def test_create_verify_password(self):
        import users as us
        rec = us.create_user(self.users_path, 'alice', 's3cretpass')
        self.assertTrue(us.verify_password(rec, 's3cretpass'))
        self.assertFalse(us.verify_password(rec, 'wrongpass'))
        self.assertEqual(rec['role'], 'user')

    def test_create_rejects_bad_input(self):
        import users as us
        with self.assertRaises(ValueError):
            us.create_user(self.users_path, 'Bad Name!', 's3cretpass')
        us.create_user(self.users_path, 'alice', 's3cretpass')
        with self.assertRaises(ValueError):  # duplicate
            us.create_user(self.users_path, 'alice', 'otherpass1')
        with self.assertRaises(ValueError):  # short password
            us.create_user(self.users_path, 'bob', 'short')

    def test_file_permissions_0640(self):
        import users as us
        us.create_user(self.users_path, 'alice', 's3cretpass')
        self.assertEqual(os.stat(self.users_path).st_mode & 0o777, 0o640)

    # -- sessions -----------------------------------------------------------

    def test_session_roundtrip_and_tamper(self):
        import users as us
        secret = us.load_secret()
        self.assertEqual(os.stat(us.secret_file()).st_mode & 0o777, 0o600)
        val = us.issue_session(secret, 'u-abc', ttl=3600, now=1000)
        payload = us.read_session(secret, val, now=2000)
        self.assertEqual(payload['uid'], 'u-abc')
        self.assertIsNone(us.read_session(secret, val, now=1000 + 3601))  # expired
        self.assertIsNone(us.read_session(secret, val[:-2] + 'zz'))  # bad sig
        self.assertIsNone(us.read_session(b'other-secret', val))  # wrong key

    def test_secret_reuse_and_regeneration(self):
        import users as us
        first = us.load_secret()
        self.assertEqual(us.load_secret(), first)  # stable across reads

    # -- billing cycle & gate ----------------------------------------------

    def test_period_start_and_monthly_reset(self):
        import users as us
        # Mar 15 with reset_day=1 -> period started Mar 1
        ts = int(time.mktime((2026, 3, 15, 12, 0, 0, 0, 0, -1)))
        self.assertEqual(us._period_start(ts, 1),
                         int(time.mktime((2026, 3, 1, 0, 0, 0, 0, 0, -1))))
        # Mar 1 before reset_day=15 -> period started Feb 15
        ts2 = int(time.mktime((2026, 3, 1, 8, 0, 0, 0, 0, -1)))
        self.assertEqual(us._period_start(ts2, 15),
                         int(time.mktime((2026, 2, 15, 0, 0, 0, 0, 0, -1))))
        rec = {'used_bytes': 500, 'cycle_start': ts, 'reset_day': 1}
        # 40 days later -> next period, lazy reset zeroes usage
        later = ts + 40 * 86400
        self.assertTrue(us.monthly_reset(rec, now=later))
        self.assertEqual(rec['used_bytes'], 0)
        self.assertEqual(rec['cycle_start'], us._period_start(later, 1))
        # same period -> no reset
        self.assertFalse(us.monthly_reset(rec, now=later + 86400))

    def test_check_service_disabled_expired_quota(self):
        import users as us
        now = 1_700_000_000
        self.assertEqual(us.check_service({'status': 'active'}, now=now), (True, ''))
        self.assertEqual(us.check_service({'status': 'disabled'}, now=now)[1], 'disabled')
        self.assertEqual(us.check_service({'expire_ts': now - 1}, now=now)[1], 'expired')
        self.assertEqual(us.check_service({'quota_bytes': 100, 'used_bytes': 100}, now=now)[1],
                         'quota_exceeded')
        self.assertEqual(us.check_service({'quota_bytes': 100, 'used_bytes': 99}, now=now),
                         (True, ''))

    def test_refresh_and_check_persists_rollover(self):
        import users as us
        old = int(time.time()) - 40 * 86400
        us.create_user(self.users_path, 'alice', 's3cretpass',
                       quota_bytes=1000, now=old)
        with us.locked(self.users_path):
            recs = us.load(self.users_path)
            recs[0]['cycle_start'] = old
            recs[0]['used_bytes'] = 999
            us.save(self.users_path, recs)
        fresh, ok, reason = us.refresh_and_check(self.users_path, us.load(self.users_path)[0])
        self.assertTrue(ok)  # new period: usage reset before the gate
        self.assertEqual(fresh['used_bytes'], 0)

    # -- ingest -------------------------------------------------------------

    def test_add_usage_accumulates_and_audits(self):
        import users as us
        us.create_user(self.users_path, 'alice', 's3cretpass')
        res = us.add_usage(self.users_path,
                           [{'user': 'alice', 'up': 100, 'down': 200},
                            {'user': 'ghost', 'up': 5, 'down': 5}],
                           node='aws-1')
        self.assertEqual(res['accepted'], 1)
        self.assertEqual(res['skipped'], [{'user': 'ghost', 'reason': 'unknown'}])
        rec = us.find_by_username(us.load(self.users_path), 'alice')
        self.assertEqual(rec['used_bytes'], 300)
        log = (self.root / 'traffic-ingest.log').read_text(encoding='utf-8')
        self.assertIn('aws-1', log)
        self.assertIn('ghost', log)  # unknown users audited too

    def test_add_usage_rolls_period_before_accumulating(self):
        import users as us
        old = int(time.time()) - 40 * 86400
        us.create_user(self.users_path, 'alice', 's3cretpass', now=old)
        with us.locked(self.users_path):
            recs = us.load(self.users_path)
            recs[0]['cycle_start'] = old
            recs[0]['used_bytes'] = 999
            us.save(self.users_path, recs)
        us.add_usage(self.users_path, [{'user': 'alice', 'up': 0, 'down': 50}], node='n')
        rec = us.find_by_username(us.load(self.users_path), 'alice')
        self.assertEqual(rec['used_bytes'], 50)  # reset wiped the old period

    def test_login_lockout(self):
        import users as us
        for _ in range(us.LOCK_THRESHOLD):
            us.record_login_fail('1.2.3.4', 'alice')
        self.assertGreater(us.login_lockout_remaining('1.2.3.4', 'alice'), 0)
        self.assertEqual(us.login_lockout_remaining('1.2.3.4', 'bob'), 0)
        us.reset_login_guard()

    def test_sync_exclude_friendly_errors(self):
        import subprocess
        src = str(Path(__file__).resolve().parent.parent / 'src' / 'sync_exclude.py')
        r = subprocess.run([sys.executable, src, str(self.root / 'missing.json')],
                           capture_output=True, text=True,
                           env={**os.environ, 'SHARE_STATE_DIR': str(self.root)})
        self.assertEqual(r.returncode, 1)
        self.assertIn('cannot read', r.stderr)
        self.assertNotIn('Traceback', r.stderr)
        bad = self.root / 'bad.json'
        bad.write_text('{oops', encoding='utf-8')
        r2 = subprocess.run([sys.executable, src, str(bad)],
                            capture_output=True, text=True,
                            env={**os.environ, 'SHARE_STATE_DIR': str(self.root)})
        self.assertEqual(r2.returncode, 1)
        self.assertIn('invalid JSON', r2.stderr)
        self.assertNotIn('Traceback', r2.stderr)

    def test_normalize_gateway_proxies(self):
        import server as srv
        raw = {'proxies': {
            'PROXY': {'type': 'Selector', 'history': []},
            'node-a': {'type': 'Vless', 'udp': True, 'alive': True,
                       'history': [{'time': '2026-11-22T10:00:00', 'delay': 234}]},
            'node-b': {'type': 'Http', 'udp': False, 'alive': False, 'history': []},
        }}
        nodes = srv._normalize_gateway_proxies(raw)
        names = [n['name'] for n in nodes]
        self.assertIn('node-a', names)
        self.assertIn('node-b', names)
        self.assertNotIn('PROXY', names)
        na = [n for n in nodes if n['name'] == 'node-a'][0]
        self.assertEqual(na['delay'], 234)
        self.assertTrue(na['alive'])
        self.assertEqual(na['checkedAt'], '2026-11-22T10:00:00')
        blob = json.dumps(nodes)
        self.assertNotIn('server', blob)
        self.assertNotIn('uuid', blob)

    def test_converters(self):
        import base64 as _b64
        import format_converters as fc
        clash = {'proxies': [
            {'name': 'aws-reality', 'type': 'vless', 'server': '1.2.3.4', 'port': 443,
             'uuid': 'U1', 'tls': True, 'servername': 'apple.com',
             'flow': 'xtls-rprx-vision',
             'reality-opts': {'public-key': 'PBK1', 'short-id': '01'},
             'client-fingerprint': 'chrome'},
            {'name': 'home-mesh', 'type': 'http', 'server': '10.144.144.10', 'port': 8082},
            {'name': 'anytls-jp', 'type': 'anytls', 'server': '2.2.2.2', 'port': 443,
             'password': 'PW'},
            {'name': 'vmess-node', 'type': 'vmess', 'server': '5.5.5.5', 'port': 80,
             'uuid': 'V1', 'cipher': 'auto'},
        ],
         'proxy-groups': [{'name': 'PROXY', 'type': 'select',
                           'proxies': ['AUTO', 'aws-reality', 'DIRECT']},
                          {'name': 'AUTO', 'type': 'url-test',
                           'proxies': ['aws-reality'], 'interval': 300}],
         'rules': ['DOMAIN-SUFFIX,claude.ai,PROXY', 'IP-CIDR,10.0.0.0/8,DIRECT',
                   'MATCH,PROXY'],
         'dns': {}}
        sb, skipped = fc.to_singbox_json(clash)
        cfg = json.loads(sb)
        tags = [o['tag'] for o in cfg['outbounds']]
        self.assertIn('PROXY', tags)
        self.assertIn('AUTO', tags)
        aws = [o for o in cfg['outbounds'] if o['tag'] == 'aws-reality'][0]
        self.assertEqual(aws['type'], 'vless')
        self.assertEqual(aws['tls']['reality']['public_key'], 'PBK1')
        self.assertEqual(aws['tls']['utls']['fingerprint'], 'chrome')
        self.assertEqual(aws['flow'], 'xtls-rprx-vision')
        self.assertTrue(any(r.get('domain_suffix') == ['claude.ai']
                            for r in cfg['route']['rules']))
        self.assertEqual(cfg['route']['final'], 'PROXY')
        surge, sk = fc.to_surge(clash)
        self.assertIn('home-mesh = http, 10.144.144.10, 8082', surge)
        self.assertIn('aws-reality', dict(sk))  # reality: no Surge equivalent
        self.assertIn('FINAL,PROXY', surge)
        qx, _ = fc.to_qx(clash)
        self.assertIn('vmess=5.5.5.5:80', qx)
        self.assertIn('[filter_local]', qx)
        self.assertIn('host-suffix, claude.ai, proxy', qx)
        uri, _ = fc.to_uri_list(clash)
        decoded = _b64.b64decode(uri).decode()
        self.assertIn('vless://U1@1.2.3.4:443', decoded)
        self.assertIn('anytls://PW@2.2.2.2:443', decoded)
        self.assertNotIn('10.144.144.', decoded)  # http node has no share URI

    def test_validate_email(self):
        import users as us
        self.assertIsNone(us.validate_email(''))
        self.assertIsNone(us.validate_email('a@b.co'))
        self.assertIsNotNone(us.validate_email('a@b@c'))
        self.assertIsNotNone(us.validate_email('a b@c.com'))
        self.assertIsNotNone(us.validate_email('no-at-sign'))

    def test_session_needs_slide(self):
        import users as us
        now = 1_000_000
        payload = {'exp': now + us.SESSION_TTL, 'uid': 'u-1'}
        self.assertFalse(us.session_needs_slide(payload, now=now))
        payload['exp'] = now + us.SESSION_TTL // 4  # 25% left -> slide
        self.assertTrue(us.session_needs_slide(payload, now=now))
        payload['exp'] = now  # expired
        self.assertFalse(us.session_needs_slide(payload, now=now))

    def test_rotate_node_credential(self):
        import users as us
        us.create_user(self.users_path, 'alice', 's3cretpass')
        us.ensure_node_credentials(self.users_path, 'aws-1')
        old_uuid = us.load(self.users_path)[0]['credentials']['aws-1']['uuid']
        us.rotate_node_credential(self.users_path, 'alice', 'aws-1')
        rec = us.load(self.users_path)[0]
        new_uuid = rec['credentials']['aws-1']['uuid']
        self.assertNotEqual(old_uuid, new_uuid)
        self.assertIn('rotated', rec['credentials']['aws-1'])
        us.ensure_node_credentials(self.users_path, 'aws-1')  # must not resurrect
        self.assertEqual(us.load(self.users_path)[0]['credentials']['aws-1']['uuid'],
                         new_uuid)
        with self.assertRaises(KeyError):  # domain API raises KeyError; CLI wraps SystemExit
            us.rotate_node_credential(self.users_path, 'alice', 'nope')

    def test_rotate_log_if_large(self):
        from state_backup import LOG_KEEP, rotate_log_if_large
        log = self.root / 'audit.log'
        log.write_text('x' * (10 * 1024 * 1024), encoding='utf-8')
        rotate_log_if_large(log)
        self.assertTrue(log.exists())
        self.assertEqual(log.stat().st_size, 0)
        rotated = list(self.root.glob('audit.log.*'))
        self.assertTrue(rotated)
        # small log untouched
        log.write_text('tiny', encoding='utf-8')
        rotate_log_if_large(log)
        self.assertEqual(log.read_text(encoding='utf-8'), 'tiny')

    def test_gen_node_users_cli_shape(self):
        import subprocess
        import users as us
        us.create_user(self.users_path, 'alice', 's3cretpass')
        src = str(Path(__file__).resolve().parent.parent / 'src' / 'users.py')
        r = subprocess.run(
            [sys.executable, src, 'gen-node-users', 'aws-1', '--type', 'vless'],
            capture_output=True, text=True,
            env={**os.environ, 'SHARE_STATE_DIR': str(self.root)})
        self.assertEqual(r.returncode, 0, r.stderr)
        entries = json.loads(r.stdout)
        self.assertEqual(len(entries), 1)
        self.assertEqual(set(entries[0]), {'name', 'uuid'})
        self.assertEqual(entries[0]['name'], 'alice')
        r2 = subprocess.run(
            [sys.executable, src, 'gen-node-users', 'aws-1', '--type', 'tuic'],
            capture_output=True, text=True,
            env={**os.environ, 'SHARE_STATE_DIR': str(self.root)})
        entries2 = json.loads(r2.stdout)
        self.assertEqual(set(entries2[0]), {'name', 'uuid', 'password'})
        self.assertEqual(entries2[0]['uuid'], entries[0]['uuid'])

    def test_restore_roundtrip(self):
        from state_backup import backup_dir, restore, snapshot
        import users as us
        us.create_user(self.users_path, 'alice', 's3cretpass')
        snapshot(self.users_path)  # snapshot BEFORE the change below
        snap = sorted(backup_dir().glob('users.json.*'))[-1]
        with us.locked(self.users_path):
            recs = us.load(self.users_path)
            recs[0]['username'] = 'renamed'
            us.save(self.users_path, recs)
        target = restore(snap)
        self.assertEqual(target, self.users_path.resolve())
        recs = us.load(self.users_path)
        self.assertEqual(recs[0]['username'], 'alice')

    def test_node_credentials_deterministic_and_additive(self):
        import users as us
        us.create_user(self.users_path, 'alice', 's3cretpass')
        uid = us.load(self.users_path)[0]['id']
        e1 = us.ensure_node_credentials(self.users_path, 'azure-hk-1')
        self.assertEqual([x['name'] for x in e1], ['alice'])
        uuid1 = e1[0]['uuid']
        # deterministic: same node regenerates the same uuid
        e2 = us.ensure_node_credentials(self.users_path, 'azure-hk-1')
        self.assertEqual(e2[0]['uuid'], uuid1)
        # a different node gets a different uuid
        e3 = us.ensure_node_credentials(self.users_path, 'aws-tokyo')
        self.assertNotEqual(e3[0]['uuid'], uuid1)
        rec = us.load(self.users_path)[0]
        self.assertEqual(set(rec['credentials']), {'azure-hk-1', 'aws-tokyo'})
        # invalid node names rejected
        with self.assertRaises(ValueError):
            us.ensure_node_credentials(self.users_path, '../evil')

    def test_set_email_cli_shape(self):
        import users as us
        us.create_user(self.users_path, 'alice', 's3cretpass')
        us.set_password_by_name  # exists for epoch semantics
        us._update_by_name(self.users_path, 'alice',
                           lambda r: r.update(email='alice@example.com'))
        rec = us.load(self.users_path)[0]
        self.assertEqual(rec['email'], 'alice@example.com')

    def test_state_backup_rotation(self):
        import users as us
        from state_backup import backup_dir, snapshot
        us.create_user(self.users_path, 'alice', 's3cretpass')
        uid = us.load(self.users_path)[0]['id']
        us.set_password(self.users_path, uid, 's3cretpass2')
        bdir = backup_dir()
        snaps = [p for p in bdir.glob('users.json.*') if not p.name.endswith('.tmp')]
        self.assertTrue(snaps, 'save must snapshot the prior store')
        json.loads(snaps[0].read_text(encoding='utf-8'))  # snapshot is valid JSON
        for i in range(6):  # rotation bound via explicit keep
            snapshot(self.users_path, keep=2)
        snaps = [p for p in bdir.glob('users.json.*') if not p.name.endswith('.tmp')]
        self.assertLessEqual(len(snaps), 2)


class AccountHarness(unittest.TestCase):
    """Shared server harness for the account HTTP faces (no test methods of
    its own; unittest only collects concrete test_* methods, so subclasses
    don't double-run the suite)."""

    def setUp(self):
        import threading
        from http.server import ThreadingHTTPServer
        sys.path.insert(0, str(Path(__file__).resolve().parent.parent / 'src'))
        import yaml
        import server as srv_mod
        self._old_env = {k: os.environ.get(k)
                         for k in ('SHARE_STATE_DIR', 'SHARE_CLASH_DIR', 'SHARE_PUBLIC_HOST')}
        self.tmp = tempfile.TemporaryDirectory()
        os.environ['SHARE_STATE_DIR'] = self.tmp.name
        clash = Path(self.tmp.name) / 'airports'
        clash.mkdir(parents=True)
        pool = {'proxies': [
            {'name': '[自建] demo-reality', 'type': 'vless', 'server': '1.2.3.4',
             'port': 443, 'uuid': 'DEMO-UUID-1234', 'tls': True,
             'flow': 'xtls-rprx-vision', 'servername': 'apple.com',
             'reality-opts': {'public-key': 'PKDEMO0123456789abcdef', 'short-id': '01'},
             'client-fingerprint': 'chrome'},
        ], 'proxy-groups': [], 'rules': []}
        (clash / 'mango-clash.yaml').write_text(yaml.safe_dump(pool), encoding='utf-8')
        (Path(self.tmp.name) / 'share-nodes.json').write_text(
            json.dumps(['[自建] demo-reality']), encoding='utf-8')
        (Path(self.tmp.name) / 'exclude.json').write_text('[]', encoding='utf-8')
        os.environ['SHARE_CLASH_DIR'] = self.tmp.name
        os.environ['SHARE_PUBLIC_HOST'] = 'http://127.0.0.1.local'
        import importlib
        importlib.reload(srv_mod)
        self.httpd = ThreadingHTTPServer(('127.0.0.1', 0), srv_mod.Handler)
        self.port = self.httpd.server_address[1]
        threading.Thread(target=self.httpd.serve_forever, daemon=True).start()
        import users as us
        self.us = us
        us.reset_login_guard()  # module-global guard: isolate tests
        us.create_user(us.users_file(), 'admin1', 'adminpass1', role='admin')

    def tearDown(self):
        import os
        self.httpd.shutdown()
        self.us.reset_login_guard()
        for k, v in self._old_env.items():
            if v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = v
        self.tmp.cleanup()

    # -- plumbing -----------------------------------------------------------

    def _req(self, path, data=None, headers=None, method=None):
        opener = urllib.request.build_opener(_NoRedirect)
        r = urllib.request.Request(f'http://127.0.0.1:{self.port}{path}',
                                   data=data, headers=headers or {}, method=method)
        try:
            resp = opener.open(r, timeout=10)
            return resp.status, resp.headers, resp.read()
        except urllib.error.HTTPError as e:
            return e.code, e.headers, e.read()

    @staticmethod
    def _cookies(headers):
        out = {}
        for v in (headers.get_all('Set-Cookie') or []):
            k, rest = v.split('=', 1)
            out[k] = rest.split(';')[0]
        return out

    def _auth(self, ck):
        """Both cookies must ride every request: double-submit CSRF pairs
        the mango_csrf cookie with the form field."""
        return {'Cookie': f"mango_session={ck['mango_session']}; mango_csrf={ck['mango_csrf']}"}

    def _export_url_for(self, user, ttl=600):
        import users as us
        from urllib.parse import quote
        secret = us.load_secret()
        exp = int(time.time()) + ttl
        generation = str(user.get('token_id') or '')
        sig = us.sign_export(secret, str(user['id']), exp, generation)
        return (f'/sub/export?u={quote(str(user["id"]))}&e={exp}'
                f'&k={quote(generation)}&s={sig}')


    def _login(self, username='admin1', password='adminpass1'):
        _, headers, _ = self._req('/login')
        csrf = self._cookies(headers)['mango_csrf']
        status, headers, _ = self._req(
            '/login',
            data=f'username={username}&password={password}&csrf={csrf}'.encode(),
            headers={'Cookie': f'mango_csrf={csrf}'})
        self.assertEqual(status, 303, 'login should redirect on success')
        ck = self._cookies(headers)
        self.assertIn('mango_session', ck)
        # login rotates the CSRF cookie; every later POST pairs the form
        # field with the CURRENT cookie value.
        return ck, ck['mango_csrf']

    def _create_demo_user(self, admin_ck, admin_csrf, quota_gb='10'):
        data = (f'csrf={admin_csrf}&username=demo1&password=demopass123'
                f'&quota_gb={quota_gb}&expire_days=0&reset_day=1&notes=')
        status, _, body = self._req('/admin/users', data=data.encode(),
                                    headers=self._auth(admin_ck))
        self.assertEqual(status, 200)
        self.assertIn('新订阅链接已生成', body.decode())
        import re
        m = re.search(rb'/sub/([A-Za-z0-9_-]+)', body)
        self.assertTrue(m, 'reveal page must show the full URL once')
        return m.group(1).decode()

    def _demo(self):
        return self.us.find_by_username(self.us.load(self.us.users_file()), 'demo1')

    def _update_demo(self, mutate):
        rec = self._demo()
        return self.us.update_user(self.us.users_file(), rec['id'], mutate)

class AccountHttpTests(AccountHarness):
    """HTTP face of the account system: login, dashboard, admin, gates."""

    # -- login flow ---------------------------------------------------------

    def test_login_page_sets_csrf(self):
        status, headers, body = self._req('/login')
        self.assertEqual(status, 200)
        self.assertIn('mango_csrf', self._cookies(headers))
        self.assertIn('<form method="post" action="/login">', body.decode())

    def test_login_requires_csrf_and_valid_password(self):
        _, headers, _ = self._req('/login')
        csrf = self._cookies(headers)['mango_csrf']
        status, _, _ = self._req('/login', data=b'username=admin1&password=adminpass1')
        self.assertEqual(status, 403, 'missing csrf cookie+field must fail')
        status, _, body = self._req(
            '/login', data=f'username=admin1&password=nope12345&csrf={csrf}'.encode(),
            headers={'Cookie': f'mango_csrf={csrf}'})
        self.assertEqual(status, 401)
        self.assertIn('用户名或密码错误', body.decode())

    def test_login_lockout_after_threshold(self):
        import users as us
        for _ in range(us.LOCK_THRESHOLD):
            us.record_login_fail('127.0.0.1', 'admin1')  # HTTP client ip
        _, headers, _ = self._req('/login')
        csrf = self._cookies(headers)['mango_csrf']
        status, _, body = self._req(
            '/login', data=f'username=admin1&password=adminpass1&csrf={csrf}'.encode(),
            headers={'Cookie': f'mango_csrf={csrf}'})
        self.assertEqual(status, 429)
        self.assertIn('临时锁定', body.decode())

    def test_dashboard_requires_session(self):
        status, headers, _ = self._req('/dashboard')
        self.assertEqual(status, 303)
        self.assertEqual(headers.get('Location'), '/login')

    def test_dashboard_shows_account(self):
        ck, _ = self._login()
        status, headers, body = self._req('/dashboard', headers=self._auth(ck))
        self.assertEqual(status, 200)
        self.assertEqual(headers.get('Cache-Control'), 'no-store')
        text = body.decode()
        self.assertIn('admin1', text)
        self.assertIn('订阅链接', text)
        self.assertIn('重置订阅链接', text)
        self.assertIn('/dashboard/password', text)

    def test_tampered_session_redirects(self):
        status, headers, _ = self._req(
            '/dashboard', headers={'Cookie': 'mango_session=forged.bad'})
        self.assertEqual(status, 303)

    def test_logout_from_home_landing_succeeds(self):
        # Regression: the authed landing page shares the app-shell sidebar
        # with the other pages; its logout form must embed the session CSRF
        # pair or POST /logout fails double-submit validation (403).
        ck, csrf = self._login()
        status, headers, body = self._req('/', headers=self._auth(ck))
        self.assertEqual(status, 200)
        text = body.decode()
        self.assertIn('<form method="post" action="/logout">', text)
        import re as _re
        m = _re.search(r'action="/logout">\s*<input type="hidden" name="csrf" value="([^"]*)"', text)
        self.assertTrue(m, 'logout form must carry a csrf field')
        self.assertEqual(m.group(1), csrf, 'landing logout csrf must match session pair')
        status, headers, _ = self._req(
            '/logout', data=f'csrf={csrf}'.encode(), headers=self._auth(ck))
        self.assertEqual(status, 303, 'logout from landing must redirect to /login')
        self.assertEqual(headers.get('Location'), '/login')

    # -- admin & subscription gate -----------------------------------------

    def test_admin_requires_admin_role(self):
        self.us.create_user(self.us.users_file(), 'plain', 'plainpass1')
        ck, csrf = self._login('plain', 'plainpass1')
        status, _, _ = self._req('/admin', headers=self._auth(ck))
        self.assertEqual(status, 303)  # bounced to /dashboard
        status, _, _ = self._req(
            '/admin/users',
            data=f'csrf={csrf}&username=x1&password=x1password'.encode(),
            headers=self._auth(ck))
        self.assertEqual(status, 403)

    def test_admin_create_user_and_pull_subscription(self):
        ck, csrf = self._login()
        demo_token = self._create_demo_user(ck, csrf)
        status, headers, body = self._req(f'/sub/{demo_token}')
        self.assertEqual(status, 200)
        self.assertIn(b'demo-reality', body)  # the rendered pool is served
        userinfo = headers.get('subscription-userinfo')
        self.assertIsNotNone(userinfo)
        self.assertIn('download=0', userinfo)   # honest zero before agents
        self.assertIn('total=', userinfo)
        status, _, body = self._req(f'/info/{demo_token}')
        payload = json.loads(body)
        self.assertEqual(payload['service'], 'ok')
        self.assertEqual(payload['quota_bytes'], 10 << 30)

    def test_over_quota_blocks_subscription(self):
        ck, csrf = self._login()
        demo_token = self._create_demo_user(ck, csrf, quota_gb='1')
        self._update_demo(lambda r: r.update(quota_bytes=1000, used_bytes=1000))
        status, _, body = self._req(f'/sub/{demo_token}')
        self.assertEqual(status, 401)
        self.assertEqual(json.loads(body)['error'], 'quota_exceeded')
        # /info also reflects the gate
        status, _, body = self._req(f'/info/{demo_token}')
        self.assertEqual(json.loads(body)['service'], 'quota_exceeded')

    def test_disabled_blocks_subscription(self):
        ck, csrf = self._login()
        demo_token = self._create_demo_user(ck, csrf)
        self._update_demo(lambda r: r.update(status='disabled'))
        status, _, body = self._req(f'/sub/{demo_token}')
        self.assertEqual(status, 401)
        self.assertEqual(json.loads(body)['error'], 'disabled')

    def test_expired_blocks_subscription(self):
        ck, csrf = self._login()
        demo_token = self._create_demo_user(ck, csrf)
        self._update_demo(lambda r: r.update(expire_ts=int(time.time()) - 10))
        status, _, body = self._req(f'/sub/{demo_token}')
        self.assertEqual(status, 401)
        self.assertEqual(json.loads(body)['error'], 'expired')

    def test_legacy_token_without_owner_still_works(self):
        _, token = tk.create_token(tk.token_file(), 'legacy')
        status, headers, _ = self._req(f'/sub/{token}')
        self.assertEqual(status, 200)
        self.assertIsNone(headers.get('subscription-userinfo'),
                          'anonymous tokens stay outside the quota system')

    def test_admin_set_quota_action(self):
        ck, csrf = self._login()
        self._create_demo_user(ck, csrf)
        rec = self._demo()
        status, headers, _ = self._req(
            f"/admin/users/{rec['id']}/action",
            data=f'csrf={csrf}&action=set-quota&value=5'.encode(),
            headers=self._auth(ck))
        self.assertEqual(status, 303)
        rec = self._demo()
        self.assertEqual(rec['quota_bytes'], 5 << 30)

    def test_admin_regen_token_invalidates_old(self):
        ck, csrf = self._login()
        old_token = self._create_demo_user(ck, csrf)
        rec = self._demo()
        status, _, body = self._req(
            f"/admin/users/{rec['id']}/action",
            data=f'csrf={csrf}&action=regen-token&value='.encode(),
            headers=self._auth(ck))
        self.assertEqual(status, 200)
        self.assertIn('新订阅链接已生成', body.decode())
        import re
        new_token = re.search(rb'/sub/([A-Za-z0-9_-]+)', body).group(1).decode()
        self.assertNotEqual(new_token, old_token)
        self.assertEqual(self._req(f'/sub/{old_token}')[0], 401)  # old revoked
        self.assertEqual(self._req(f'/sub/{new_token}')[0], 200)

    def test_dashboard_regen_token(self):
        ck, csrf = self._login()
        self.us.create_user(self.us.users_file(), 'demo1', 'demopass123')
        status, _, body = self._req(
            '/dashboard/regen-token', data=f'csrf={csrf}'.encode(),
            headers=self._auth(ck))
        self.assertEqual(status, 200)
        self.assertIn('/sub/', body.decode())
        admin = self.us.find_by_username(self.us.load(self.us.users_file()), 'admin1')
        self.assertTrue(admin['token_id'],
                        'dashboard regen binds a token to the logged-in user')

    def test_dashboard_shows_and_resets_sub_link(self):
        import re
        ck, csrf = self._login()
        # admin-created user: the derived link is visible on their dashboard
        token = self._create_demo_user(ck, csrf)
        uck, ucsrf = self._login('demo1', 'demopass123')
        status, _, body = self._req('/dashboard', headers=self._auth(uck))
        self.assertEqual(status, 200)
        self.assertIn(f'/sub/{token}', body.decode())
        # reset: old link dies, new link is shown on the dashboard
        status, _, body = self._req('/dashboard/regen-token',
                                    data=f'csrf={ucsrf}'.encode(),
                                    headers=self._auth(uck))
        self.assertEqual(status, 200)
        new = re.search(rb'/sub/([A-Za-z0-9_-]+)', body).group(1).decode()
        self.assertNotEqual(new, token)
        self.assertEqual(self._req(f'/sub/{token}')[0], 401)
        self.assertEqual(self._req(f'/sub/{new}')[0], 200)
        _, _, body = self._req('/dashboard', headers=self._auth(uck))
        self.assertIn(f'/sub/{new}', body.decode())
        self.assertNotIn(f'/sub/{token}', body.decode())

    def test_dashboard_legacy_token_not_shown(self):
        ck, csrf = self._login()
        self._create_demo_user(ck, csrf)
        # simulate a pre-derivation random token
        recs = tk.load(tk.token_file())
        for r in recs:
            r.pop('derive_nonce', None)
        tk.save(tk.token_file(), recs)
        uck, _ = self._login('demo1', 'demopass123')
        _, _, body = self._req('/dashboard', headers=self._auth(uck))
        html = body.decode()
        self.assertIn('id="sub-url"', html)   # still gets a yml link
        self.assertIn('旧版令牌', html)
        import re, html as _h
        url = _h.unescape(re.search(r'id="sub-url" readonly value="([^"]+)"', html).group(1))
        path = url.split('://', 1)[-1].split('/', 1)[1]
        self.assertTrue(path.startswith('sub/export?'))
        self.assertEqual(self._req('/' + path)[0], 200)

    def test_dashboard_provisions_token_for_tokenless_account(self):
        import re, html as _h
        ck, _ = self._login()   # admin1 has no token yet
        self.assertFalse(self.us.find_by_username(
            self.us.load(self.us.users_file()), 'admin1').get('token_id'))
        _, _, body = self._req('/dashboard', headers=self._auth(ck))
        html = body.decode()
        m = re.search(r'id="sub-url" readonly value="[^"]*/sub/([A-Za-z0-9_-]+)"', html)
        self.assertTrue(m, 'token-less account gets a derived link on first visit')
        self.assertEqual(self._req(f'/sub/{m.group(1)}')[0], 200)
        _, _, body2 = self._req('/dashboard', headers=self._auth(ck))
        self.assertIn(f'/sub/{m.group(1)}', body2.decode(), 'stable across visits')

    def test_ingest_endpoint(self):
        _, node_token = tk.create_token(tk.nodes_file(), 'node-a')
        ck, csrf = self._login()
        demo_token = self._create_demo_user(ck, csrf, quota_gb='1')
        status, _, body = self._req(
            '/ingest/traffic',
            data=json.dumps({'node': 'aws-1',
                             'updates': [{'user': 'demo1', 'up': 100, 'down': 900}]}).encode(),
            headers={'Authorization': f'Bearer {node_token}',
                     'Content-Type': 'application/json'})
        self.assertEqual(status, 200)
        self.assertEqual(json.loads(body)['accepted'], 1)
        status, headers, _ = self._req(f'/sub/{demo_token}')
        self.assertIn('download=1000', headers.get('subscription-userinfo'))
        # exceeding quota -> blocked (shrink the quota to 1000 bytes first)
        self._update_demo(lambda r: r.update(quota_bytes=1000))
        status, _, body = self._req(
            '/ingest/traffic',
            data=json.dumps({'updates': [{'user': 'demo1', 'up': 0, 'down': 500}]}).encode(),
            headers={'Authorization': f'Bearer {node_token}',
                     'Content-Type': 'application/json'})
        self.assertEqual(status, 200)
        status, _, body = self._req(f'/sub/{demo_token}')
        self.assertEqual(status, 401)
        self.assertEqual(json.loads(body)['error'], 'quota_exceeded')
        # bad node token
        status, _, _ = self._req(
            '/ingest/traffic', data=b'{}',
            headers={'Authorization': 'Bearer wrong', 'Content-Type': 'application/json'})
        self.assertEqual(status, 401)

    # -- review fixes -------------------------------------------------------

    def test_login_flood_sheds_load(self):
        """P1 regression: a parallel wrong-password flood must stay within the
        scrypt gate — every response is 401/429, never 5xx, and the server
        still serves afterwards."""
        _, headers, _ = self._req('/login')
        csrf = self._cookies(headers)['mango_csrf']
        results = []

        def attempt():
            try:
                status, _, _ = self._req(
                    '/login',
                    data=f'username=admin1&password=wrongpass1&csrf={csrf}'.encode(),
                    headers={'Cookie': f'mango_csrf={csrf}'})
                results.append(status)
            except Exception:
                results.append(500)

        threads = [threading.Thread(target=attempt) for _ in range(12)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        self.assertEqual(len(results), 12)
        for code in results:
            self.assertIn(code, (401, 429),
                          f'flood must shed load, got {code} (5xx = gate failed)')
        status, _, _ = self._req('/login')
        self.assertEqual(status, 200)

    def test_login_fails_capacity_bound(self):
        import users as us
        old_max = us._LOGIN_FAILS_MAX
        us._LOGIN_FAILS_MAX = 5
        try:
            for i in range(10):
                us.record_login_fail(f'10.0.0.{i}', 'alice')
            self.assertLessEqual(len(us._login_fails), 5)
        finally:
            us._LOGIN_FAILS_MAX = old_max
            us.reset_login_guard()

    def test_password_change_revokes_old_sessions(self):
        import users as us
        ck, csrf = self._login()
        status, _, _ = self._req('/dashboard', headers=self._auth(ck))
        self.assertEqual(status, 200)
        admin = us.find_by_username(us.load(us.users_file()), 'admin1')
        self.assertEqual(admin.get('session_epoch', 0), 0)
        status, headers, _ = self._req(
            '/dashboard/password',
            data=f'csrf={csrf}&old_password=adminpass1&new_password=newpass123'.encode(),
            headers=self._auth(ck))
        self.assertEqual(status, 303)
        admin = us.find_by_username(us.load(us.users_file()), 'admin1')
        self.assertEqual(admin.get('session_epoch'), 1)
        # old session cookie must now bounce even though its HMAC is valid
        status, headers, _ = self._req('/dashboard', headers=self._auth(ck))
        self.assertEqual(status, 303)
        self.assertEqual(headers.get('Location'), '/login')
        # new password logs in fine
        ck2, _ = self._login('admin1', 'newpass123')
        status, _, _ = self._req('/dashboard', headers=self._auth(ck2))
        self.assertEqual(status, 200)

    def test_disable_revokes_sessions_and_blocks_login(self):
        ck, csrf = self._login()
        self._create_demo_user(ck, csrf)
        self.us.create_user(self.us.users_file(), 'member', 'memberpass1')
        # disable the member, then log in as them: session must be refused
        mck, mcsrf = self._login('member', 'memberpass1')
        member = self.us.find_by_username(self.us.load(self.us.users_file()), 'member')
        self.us.set_status(self.us.users_file(), member['id'], 'disabled')
        status, _, _ = self._req('/dashboard', headers=self._auth(mck))
        self.assertEqual(status, 303, 'disabled user\'s live session must die')
        status, _, body = self._req(
            '/login',
            data=f'username=member&password=memberpass1&csrf={mcsrf}'.encode(),
            headers={'Cookie': f'mango_csrf={mcsrf}'})
        self.assertEqual(status, 403)
        self.assertIn('账号已停用', body.decode())
        # subscription gate already blocked them earlier (existing semantics)
        # re-enable -> login works again
        self.us.set_status(self.us.users_file(), member['id'], 'active')
        ck2, _ = self._login('member', 'memberpass1')
        status, _, _ = self._req('/dashboard', headers=self._auth(ck2))
        self.assertEqual(status, 200)

    def test_disable_admin_kills_admin_access(self):
        ck, csrf = self._login('admin1', 'adminpass1')
        admin = self.us.find_by_username(self.us.load(self.us.users_file()), 'admin1')
        self.us.set_status(self.us.users_file(), admin['id'], 'disabled')
        status, _, _ = self._req('/admin', headers=self._auth(ck))
        self.assertEqual(status, 303, 'disabled admin loses the admin face too')

    def test_negative_quota_and_expire_rejected(self):
        ck, csrf = self._login()
        data = (f'csrf={csrf}&username=demo1&password=demopass123'
                f'&quota_gb=-5&expire_days=-1&reset_day=1&notes=')
        status, _, _ = self._req('/admin/users', data=data.encode(),
                                 headers=self._auth(ck))
        self.assertEqual(status, 303)
        self.assertIsNone(self.us.find_by_username(
            self.us.load(self.us.users_file()), 'demo1'),
            'negative input must not create the account')
        self._create_demo_user(ck, csrf, quota_gb='10')
        rec = self._demo()
        status, _, _ = self._req(
            f"/admin/users/{rec['id']}/action",
            data=f'csrf={csrf}&action=set-quota&value=-1'.encode(),
            headers=self._auth(ck))
        self.assertEqual(status, 303)
        rec = self._demo()
        self.assertEqual(rec['quota_bytes'], 10 << 30, 'quota must be unchanged')

    def test_regen_token_leaves_no_orphans(self):
        """P3 regression: concurrent rotations must not strand active unbound
        tokens (rotation is serialized by the users-store flock)."""
        ck, csrf = self._login()
        self._create_demo_user(ck, csrf)
        rec = self._demo()
        errors = []

        def rotate():
            try:
                status, _, _ = self._req(
                    f"/admin/users/{rec['id']}/action",
                    data=f'csrf={csrf}&action=regen-token&value='.encode(),
                    headers=self._auth(ck))
                if status != 200:
                    errors.append(status)
            except Exception as e:
                errors.append(str(e))

        threads = [threading.Thread(target=rotate) for _ in range(4)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        self.assertEqual(errors, [])
        all_tokens = tk.load(tk.token_file())
        active = [t for t in all_tokens
                  if t.get('name') == 'demo1' and not t.get('revoked')]
        self.assertEqual(len(active), 1, 'exactly one active token must survive')
        rec = self._demo()
        self.assertEqual(rec['token_id'], active[0]['id'])

    def test_client_ip_ignores_spoofed_xff(self):
        import users as us
        _, headers, _ = self._req('/login')
        csrf = self._cookies(headers)['mango_csrf']
        # five failures claiming a fake XFF: with XFF ignored, the lock lands
        # on the real peer address (127.0.0.1), not on 9.9.9.9.
        for _ in range(us.LOCK_THRESHOLD):
            self._req('/login',
                      data=f'username=admin1&password=wrongpass1&csrf={csrf}'.encode(),
                      headers={'Cookie': f'mango_csrf={csrf}',
                               'X-Forwarded-For': '9.9.9.9'})
        # a request that legitimately arrives via CF from another client is
        # not locked by the earlier failures...
        status, _, _ = self._req(
            '/login',
            data=f'username=admin1&password=adminpass1&csrf={csrf}'.encode(),
            headers={'Cookie': f'mango_csrf={csrf}', 'CF-Connecting-IP': '8.8.8.8'})
        self.assertEqual(status, 303, 'CF-Connecting-IP keys its own lockout slot')
        # ...while the real peer address IS locked by those failures.
        status, _, body = self._req(
            '/login',
            data=f'username=admin1&password=adminpass1&csrf={csrf}'.encode(),
            headers={'Cookie': f'mango_csrf={csrf}'})
        self.assertEqual(status, 429)
        us.reset_login_guard()

    def test_ingest_rejects_before_parsing_body(self):
        """Auth-first: a bad node token gets 401 even with a malformed body."""
        status, _, body = self._req(
            '/ingest/traffic', data=b'not-json-at-all',
            headers={'Authorization': 'Bearer wrong', 'Content-Type': 'application/json'})
        self.assertEqual(status, 401)

    def test_notes_visible_in_admin_table(self):
        self.us.create_user(self.us.users_file(), 'demo1', 'demopass123',
                            notes='试用用户')
        ck, _ = self._login()
        status, _, body = self._req('/admin', headers=self._auth(ck))
        self.assertEqual(status, 200)
        self.assertIn('试用用户', body.decode())

    def test_cli_mutations_audited(self):
        import subprocess
        r = subprocess.run(
            [sys.executable, str(Path(__file__).resolve().parent.parent / 'src' / 'users.py'),
             'set-email', 'admin1', 'ops@example.com'],
            capture_output=True, text=True,
            env={**os.environ, 'SHARE_STATE_DIR': self.tmp.name})
        self.assertEqual(r.returncode, 0, r.stderr)
        log_path = self.us.audit_file()
        entries = [json.loads(x) for x
                   in log_path.read_text(encoding='utf-8').splitlines()]
        cli_entries = [e for e in entries if e['action'] == 'cli.user.set-email']
        self.assertTrue(cli_entries)
        self.assertTrue(cli_entries[0]['actor'].startswith('cli:'))
        self.assertEqual(cli_entries[0]['target'], 'admin1')

    def test_state_backup_cli(self):
        import subprocess
        src = str(Path(__file__).resolve().parent.parent / 'src' / 'state_backup.py')
        base = subprocess.run(
            [sys.executable, src, 'list'], capture_output=True, text=True,
            env={**os.environ, 'SHARE_STATE_DIR': self.tmp.name})
        self.assertEqual(base.returncode, 0)
        self.assertIn('no snapshots yet', base.stdout)  # empty at first
        from state_backup import backup_dir
        import users as us
        us.create_user(us.users_file(), 'alice', 's3cretpass')  # triggers snapshot
        r = subprocess.run(
            [sys.executable, src, 'list'], capture_output=True, text=True,
            env={**os.environ, 'SHARE_STATE_DIR': self.tmp.name})
        self.assertEqual(r.returncode, 0)
        self.assertIn('users.json.', r.stdout)
        # restore CLI roundtrip
        snap = str(sorted(backup_dir().glob('users.json.*'))[-1])
        r2 = subprocess.run(
            [sys.executable, src, 'restore', snap], capture_output=True, text=True,
            env={**os.environ, 'SHARE_STATE_DIR': self.tmp.name})
        self.assertEqual(r2.returncode, 0, r2.stderr)
        self.assertIn('restored', r2.stdout)

    def test_cli_missing_user_friendly_exit(self):
        import subprocess
        r = subprocess.run(
            [sys.executable, str(Path(__file__).resolve().parent.parent / 'src' / 'users.py'),
             'set-quota', 'nosuchuser', '5'],
            capture_output=True, text=True,
            env={**os.environ, 'SHARE_STATE_DIR': self.tmp.name})
        self.assertEqual(r.returncode, 1)
        self.assertIn('user not found', r.stderr)
        self.assertNotIn('Traceback', r.stderr)

    def test_health_endpoint(self):
        status, headers, body = self._req('/health')
        self.assertEqual(status, 200)
        payload = json.loads(body)
        self.assertTrue(payload['ok'])
        self.assertIsInstance(payload['node_count'], int)
        self.assertIn('uptime_s', payload)
        self.assertIn('render_rev', payload)
        self.assertIn('per_user_yaml', payload)
        for banned in ('token_sha256', 'SECRET-', '/personal', 'users.json'):
            self.assertNotIn(banned, body.decode())

    def test_security_headers(self):
        status, headers, _ = self._req('/login')
        self.assertIn("default-src 'self'", headers.get('Content-Security-Policy', ''))
        self.assertIn("frame-ancestors 'none'", headers.get('Content-Security-Policy', ''))
        self.assertEqual(headers.get('X-Frame-Options'), 'DENY')
        self.assertEqual(headers.get('X-Content-Type-Options'), 'nosniff')
        _, token = tk.create_token(tk.token_file(), 'hdr-check')
        status, headers, _ = self._req(f'/sub/{token}')
        self.assertEqual(headers.get('X-Content-Type-Options'), 'nosniff')
        self.assertIsNone(headers.get('Content-Security-Policy'),
                          'non-HTML faces carry nosniff only')

    def test_audit_trail_records_actions(self):
        import users as us
        ck, csrf = self._login()
        self._create_demo_user(ck, csrf)
        log_path = us.audit_file()
        lines = [json.loads(x) for x in log_path.read_text(encoding='utf-8').splitlines()]
        created = [e for e in lines if e['action'] == 'user.create']
        self.assertTrue(created, 'user creation must be audited')
        self.assertEqual(created[0]['actor'], 'admin1')
        self.assertEqual(created[0]['target'], 'demo1')
        status, _, _ = self._req(
            '/dashboard/password',
            data=f'csrf={csrf}&old_password=adminpass1&new_password=newpass999'.encode(),
            headers=self._auth(ck))
        self.assertEqual(status, 303)
        lines = [json.loads(x) for x in log_path.read_text(encoding='utf-8').splitlines()]
        changed = [e for e in lines if e['action'] == 'password.change']
        self.assertTrue(changed)
        self.assertNotIn('newpass999', json.dumps(lines),
                         'audit trail must never contain the password itself')

    def test_fresh_session_not_reslid(self):
        ck, _ = self._login()
        # brand-new session has >TTL/2 remaining -> no Set-Cookie on GET
        status, headers, _ = self._req('/dashboard', headers=self._auth(ck))
        self.assertEqual(status, 200)
        self.assertIsNone(headers.get('Set-Cookie'),
                          'active sessions must not be re-issued every request')

    def test_dashboard_shows_last_fetch(self):
        import re
        ck, csrf = self._login()
        # bind admin1's own token, then report a fetch for it
        status, _, _ = self._req('/dashboard/regen-token',
                                 data=f'csrf={csrf}'.encode(), headers=self._auth(ck))
        self.assertEqual(status, 200)
        admin = self.us.find_by_username(self.us.load(self.us.users_file()), 'admin1')
        rec = [t for t in tk.load(tk.token_file()) if t.get('id') == admin['token_id']][0]
        tk.touch(rec, tk.token_file())
        status, _, body = self._req('/dashboard', headers=self._auth(ck))
        self.assertEqual(status, 200)
        self.assertIn('最后拉取', body.decode())
        self.assertRegex(body.decode(), r'\d{4}-\d{2}-\d{2} \d{2}:\d{2}')

    def test_app_shell_menu_and_backdrop(self):
        ck, _ = self._login()
        status, _, d_bytes = self._req('/dashboard', headers=self._auth(ck))
        d = d_bytes.decode()
        text = d
        for part in ('app-layout', '<aside class="sidebar"', 'side-nav-button',
                     'fluid-contour-backdrop', 'status-indicator',
                     'mobile-menu-button', 'aria-current="page" href="/dashboard"',
                     '退出登录'):
            self.assertIn(part, text)
        # menu is role-aware: admin group only for admins
        status, _, a = self._req('/admin', headers=self._auth(ck))
        atext = a.decode()
        self.assertIn('aria-current="page" href="/admin"', atext)
        self.assertIn('审计流水', atext)
        # inline JS stays parseable with the new drawer script
        import re
        scripts = re.findall(r'<script>(.*?)</script>', d, re.S)
        import subprocess, tempfile
        for sc in scripts:
            f = tempfile.NamedTemporaryFile('w', suffix='.js', delete=False)
            f.write(sc)
            f.close()
            r = subprocess.run(['node', '--check', f.name], capture_output=True, text=True)
            self.assertEqual(r.returncode, 0, f'inline JS broken: {r.stderr[:200]}')

    def test_landing_role_aware(self):
        # anonymous: 登录 CTA, no user-center entry
        status, _, body = self._req('/')
        self.assertEqual(status, 200)
        self.assertNotIn('进入用户中心', body.decode())
        # authed: sidebar has site tabs, CTA enters the user center
        ck, _ = self._login()
        status, headers, body = self._req('/', headers=self._auth(ck))
        self.assertEqual(status, 200)
        self.assertEqual(headers.get('Cache-Control'), 'no-store')
        text = body.decode()
        self.assertIn('进入用户中心', text)
        self.assertIn('用户管理', text)  # admin tab visible for admin
        self.assertNotIn('href="/login">登录</a></li>', text)

    def test_export_link_dies_when_token_rotated(self):
        # 30-day link is safe only because resetting the subscription changes
        # token_id (the signature's generation) and kills it instantly.
        ck, csrf = self._login()
        self._create_demo_user(ck, csrf, quota_gb='10')
        rec = self._demo()
        sig_url = self._export_url_for(rec, ttl=30 * 86400)
        status, _, _ = self._req(sig_url)
        self.assertEqual(status, 200, 'fresh 30-day link must work')
        # admin resets demo1's subscription -> new token_id -> old link dead
        self._update_demo(lambda r: r.update(token_id='rotated-generation'))
        status, _, body = self._req(sig_url)
        self.assertEqual(status, 401)
        self.assertIn('invalid export link', json.loads(body)['error'])

    def test_export_link_wrong_generation_rejected(self):
        import users as us
        from urllib.parse import quote
        rec = self._demo() if self._demo() else None
        if rec is None:
            ck, csrf = self._login()
            self._create_demo_user(ck, csrf, quota_gb='10')
            rec = self._demo()
        secret = us.load_secret()
        exp = int(time.time()) + 3600
        sig = us.sign_export(secret, str(rec['id']), exp, 'some-other-token-id')
        url = (f'/sub/export?u={quote(str(rec["id"]))}&e={exp}'
               f'&k={quote("fresh-token-id")}&s={sig}')
        status, _, _ = self._req(url)
        self.assertEqual(status, 401)

    def test_download_and_export_respect_service_gate(self):
        # 停发语义 covers config downloads and signed export windows too
        ck, csrf = self._login()
        demo_token = self._create_demo_user(ck, csrf, quota_gb='1')
        rec = self._demo()
        # demo1 logs in as themselves: their session download must be gated
        dck, dcsrf = self._login('demo1', 'demopass123')
        dauth = self._auth(dck)
        # over quota: dashboard download redirects with reason, signed export 401
        self._update_demo(lambda r: r.update(quota_bytes=1000, used_bytes=1000))
        status, headers, _ = self._req('/sub/download', headers=dauth)
        self.assertEqual(status, 303)
        self.assertIn('quota_exceeded', headers.get('Location', ''))
        # valid signature minted BEFORE the quota breach still 401s in-window
        sig_url = self._export_url_for(rec)
        status, _, body = self._req(sig_url)
        self.assertEqual(status, 401)
        self.assertEqual(json.loads(body)['error'], 'quota_exceeded')
        # expired account: same gate
        self._update_demo(lambda r: r.update(
            status='active', quota_bytes=0, expire_ts=int(time.time()) - 10))
        status, headers, _ = self._req('/sub/download', headers=dauth)
        self.assertEqual(status, 303)
        self.assertIn('expired', headers.get('Location', ''))
        status, _, body = self._req(sig_url)
        self.assertEqual(status, 401)
        self.assertEqual(json.loads(body)['error'], 'expired')


    def test_export_bad_exp_and_fmt_fallback(self):
        import users as us
        us.create_user(self.us.users_file() if hasattr(self, 'us') else self.us.users_file(),
                       'plain2', 'plainpass2')
        ck, _ = self._login('plain2', 'plainpass2')
        # non-numeric e -> 401 (not 500)
        status, _, _ = self._req('/sub/export?u=x&e=abc&s=deadbeef')
        self.assertEqual(status, 401)
        # unknown fmt falls back to clash yaml
        _, token = tk.create_token(tk.token_file(), 'fmt-fallback')
        status, headers, body = self._req(f'/sub/{token}?fmt=bogus')
        self.assertEqual(status, 200)
        self.assertEqual(headers.get('Content-Type'), 'text/yaml; charset=utf-8')
        self.assertIn('proxies:', body.decode())
        # HEAD download: authed -> headers without body
        status, headers, _ = self._req('/sub/download', method='HEAD',
                                       headers=self._auth(ck) if hasattr(self, 'ck') else {})
        # (authed session from earlier login in this class is admin1)
        self.assertIn(status, (200, 303))

    def test_nodes_page_and_api_gates(self):
        # unauthenticated: page redirects, api 401
        status, headers, _ = self._req('/nodes')
        self.assertEqual(status, 303)
        status, _, body = self._req('/nodes/api')
        self.assertEqual(status, 401)
        ck, _ = self._login()
        status, headers, body = self._req('/nodes', headers=self._auth(ck))
        self.assertEqual(status, 200)
        text = body.decode()
        self.assertIn('节点现状', text)
        self.assertIn('nodes-grid', text)
        self.assertIn('aria-current="page" href="/nodes"', text)
        # no gateway running in the test env -> api 503 with error payload
        status, _, body = self._req('/nodes/api', headers=self._auth(ck))
        self.assertEqual(status, 503)
        self.assertIn('error', json.loads(body))

    def test_theme_toggle_on_authed_pages(self):
        ck, _ = self._login()
        status, _, d = self._req('/dashboard', headers=self._auth(ck))
        self.assertEqual(status, 200)
        self.assertIn('data-mode="dark"', d.decode())
        status, _, a = self._req('/admin', headers=self._auth(ck))
        self.assertIn('data-mode="dark"', a.decode())
        # login page: anti-flash resolver only, no toggle buttons
        status, _, l = self._req('/login')
        self.assertIn('localStorage', l.decode())
        self.assertNotIn('data-mode="dark"', l.decode())

    def test_admin_search_filters_table(self):
        ck, csrf = self._login()
        self._create_demo_user(ck, csrf)
        us_mod = self.us
        us_mod.create_user(us_mod.users_file(), 'other', 'otherpass1')
        status, _, body = self._req('/admin?q=demo', headers=self._auth(ck))
        self.assertEqual(status, 200)
        self.assertIn('demo1', body.decode())
        self.assertNotIn('other</strong>', body.decode())

    def test_audit_page_and_csv_export(self):
        ck, csrf = self._login()
        self._create_demo_user(ck, csrf)
        status, _, body = self._req('/admin/audit', headers=self._auth(ck))
        self.assertEqual(status, 200)
        text = body.decode()
        self.assertIn('审计流水', text)
        self.assertIn('user.create', text)
        status, headers, body = self._req('/admin/audit/export', headers=self._auth(ck))
        self.assertEqual(status, 200)
        self.assertIn('text/csv', headers.get('Content-Type'))
        self.assertIn('user.create', body.decode())
        # non-admin bounced
        self.us.create_user(self.us.users_file(), 'plain', 'plainpass1')
        ck2, _ = self._login('plain', 'plainpass1')
        status, _, _ = self._req('/admin/audit', headers=self._auth(ck2))
        self.assertEqual(status, 303)

    def test_admin_warning_cards(self):
        import time as _t
        ck, csrf = self._login()
        self._create_demo_user(ck, csrf)
        soon = int(_t.time()) + 3 * 86400
        self._update_demo(lambda r: r.update(expire_ts=soon))
        status, _, body = self._req('/admin', headers=self._auth(ck))
        self.assertIn('7 天内到期', body.decode())
        self._update_demo(lambda r: r.update(
            expire_ts=0, quota_bytes=1000, used_bytes=900))
        status, _, body = self._req('/admin', headers=self._auth(ck))
        self.assertIn('85%', body.decode())

    def test_create_user_with_email(self):
        ck, csrf = self._login()
        data = (f'csrf={csrf}&username=demo1&password=demopass123'
                f'&quota_gb=10&expire_days=0&reset_day=1&email=demo%40example.com&notes=')
        status, _, _ = self._req('/admin/users', data=data.encode(),
                                 headers=self._auth(ck))
        self.assertEqual(status, 200)
        rec = self._demo()
        self.assertEqual(rec['email'], 'demo@example.com')
        # invalid email -> err redirect, account untouched
        for bad in ('not-an-email', 'a@b@c', 'a b@c.com'):
            data = (f'csrf={csrf}&username=demo2&password=demopass123'
                    f'&quota_gb=1&expire_days=0&reset_day=1&email={bad}&notes=')
            status, _, _ = self._req('/admin/users', data=data.encode(),
                                     headers=self._auth(ck))
            self.assertEqual(status, 303, f'{bad!r} must be rejected')
            self.assertIsNone(self.us.find_by_username(
                self.us.load(self.us.users_file()), 'demo2'))


class NotifyUnitTests(unittest.TestCase):
    """Reminder engine: pending selection, dedup, log transport."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.users_path = self.root / 'users.json'
        self._old_env = os.environ.get('SHARE_STATE_DIR')
        os.environ['SHARE_STATE_DIR'] = str(self.root)

    def tearDown(self):
        if self._old_env is None:
            os.environ.pop('SHARE_STATE_DIR', None)
        else:
            os.environ['SHARE_STATE_DIR'] = self._old_env
        self.tmp.cleanup()

    def test_pending_reminders_selection(self):
        import notify as nt
        import users as us
        now = 1_700_000_000
        soon = now + 3 * 86400
        us.create_user(self.users_path, 'alice', 's3cretpass1',
                       quota_bytes=1000, expire_ts=soon, email='a@x.com')
        us.create_user(self.users_path, 'bob', 's3cretpass1',
                       quota_bytes=1000, email='b@x.com')
        us.create_user(self.users_path, 'carol', 's3cretpass1', email='c@x.com')
        with us.locked(self.users_path):
            recs = us.load(self.users_path)
            recs[1]['used_bytes'] = 900  # 90% of quota
            recs[2]['status'] = 'disabled'
            us.save(self.users_path, recs)
        pairs = nt.pending_reminders(us.load(self.users_path), now=now)
        kinds = {(r['username'], kind) for r, kind, _ in pairs}
        self.assertIn(('alice', 'expiry'), kinds)
        self.assertIn(('bob', 'quota'), kinds)
        self.assertNotIn(('carol', 'expiry'), kinds)  # disabled filtered
        # far-from-expiry & low usage -> nothing
        recs = us.load(self.users_path)
        recs[0]['expire_ts'] = now + 60 * 86400
        us.save(self.users_path, recs)
        pairs = nt.pending_reminders(us.load(self.users_path), now=now)
        kinds = {(r['username'], kind) for r, kind, _ in pairs}
        self.assertNotIn(('alice', 'expiry'), kinds)

    def test_check_reminders_dedup_and_log_transport(self):
        import notify as nt
        import users as us
        now = 1_700_000_000
        soon = now + 3 * 86400
        us.create_user(self.users_path, 'alice', 's3cretpass1',
                       quota_bytes=1000, expire_ts=soon, email='a@x.com')
        # one-mail NOT configured -> log transport, unsent (state untouched)
        r1 = nt.check_reminders(self.users_path, now=now)
        self.assertEqual(len(r1['unsent']), 1)
        log = (self.root / 'notify.log').read_text(encoding='utf-8')
        self.assertIn('a@x.com', log)
        self.assertIn('log(unconfigured)', log)
        # state file must not record a send that never happened
        self.assertEqual(nt._load_state(self.root / nt.STATE_FILE), {})
        # with a fake configured transport (local HTTP), mail sends + dedup
        self._fake_mail_server()

        class _Env(dict):
            pass

        env = _Env(os.environ)
        env['ONE_MAIL_API_BASE'] = self.mail_base
        env['ONE_MAIL_SEND_TOKEN'] = 'test-token'
        r2 = nt.check_reminders(self.users_path, now=now + 60, env=env)
        self.assertEqual(len(r2['sent']), 1)
        state = nt._load_state(self.root / nt.STATE_FILE)
        self.assertTrue(state)
        # second run within cooldown -> skipped
        r3 = nt.check_reminders(self.users_path, now=now + 120, env=env)
        self.assertEqual(len(r3['cooldown']), 1)
        self.assertEqual(len(r3['sent']), 0)
        # 202 Accepted counts as delivered (state recorded); drive the quota
        # reminder (alice is expired by now, which no longer reminds)
        with us.locked(self.users_path):
            recs = us.load(self.users_path)
            recs[0]['used_bytes'] = 900
            us.save(self.users_path, recs)
        self.mail_status = 202
        env2 = dict(os.environ)
        env2['ONE_MAIL_API_BASE'] = self.mail_base
        env2['ONE_MAIL_SEND_TOKEN'] = 't'
        r4 = nt.check_reminders(self.users_path, now=now + 8 * 86400, env=env2)
        self.assertEqual(len(r4['sent']), 1)
        # overlapping runners: exactly one mail leaves the building
        self.mail_status = 200
        state = nt._load_state(self.root / nt.STATE_FILE)
        for k in state:
            state[k] = 0  # re-arm the reminder
        nt._save_state(self.root / nt.STATE_FILE, state)
        counts = {'n': 0}
        clock = {'now': now + 9 * 86400}
        real_check = nt.check_reminders

        def run():
            res = nt.check_reminders(self.users_path, now=clock['now'], env=env2)
            counts['n'] += len(res['sent'])

        real_us_load = us.load

        def slow_load(path):
            time.sleep(0.05)  # widen the overlap window
            return real_us_load(path)

        us.load = slow_load
        try:
            ts = [threading.Thread(target=run) for _ in range(3)]
            for t in ts:
                t.start()
            for t in ts:
                t.join()
        finally:
            us.load = real_us_load
        self.assertEqual(counts['n'], 1, 'overlapping runs must send once')

    def _fake_mail_server(self):
        import threading
        from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
        import json as _json
        captured = self
        holder = {}

        status_code = getattr(self, 'mail_status', 200)

        class H(BaseHTTPRequestHandler):
            def do_POST(self):
                ln = int(self.headers.get('Content-Length') or 0)
                holder['path'] = self.path
                holder['body'] = _json.loads(self.rfile.read(ln))
                self.send_response(status_code)
                self.send_header('Content-Length', '2')
                self.end_headers()
                self.wfile.write(b'ok')

            def log_message(self, *a):
                pass

        srv = ThreadingHTTPServer(('127.0.0.1', 0), H)
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        self.mail_base = f'http://127.0.0.1:{srv.server_address[1]}'
        self.mail_holder = holder
        self.mail_status = getattr(self, 'mail_status', 200)
        self.addCleanup(srv.shutdown)


class PerUserYamlTests(AccountHarness):
    """Phase-2 serving: with SHARE_PER_USER_YAML=1 and a node-credentials
    map, provisioned users get their own rendered YAML (own uuid), everyone
    else keeps the global render."""

    def setUp(self):
        os.environ['SHARE_PER_USER_YAML'] = '1'
        super().setUp()

    def tearDown(self):
        super().tearDown()
        os.environ.pop('SHARE_PER_USER_YAML', None)

    def test_provisioned_user_gets_own_yaml(self):
        ck, csrf = self._login()
        demo_token = self._create_demo_user(ck, csrf)
        self.us.ensure_node_credentials(self.us.users_file(), 'demo-node')
        (Path(self.tmp.name) / 'node-credentials.json').write_text(
            json.dumps([{'node': '[自建] demo-reality', 'key': 'demo-node',
                         'type': 'vless'}]), encoding='utf-8')
        status, headers, body = self._req(f'/sub/{demo_token}')
        self.assertEqual(status, 200)
        text = body.decode()
        rec = self._demo()
        creds = rec['credentials']['demo-node']['uuid']
        self.assertIn(creds, text)                      # user's own uuid
        self.assertNotIn('DEMO-UUID-1234', text)        # shared uuid gone
        self.assertEqual(headers.get('profile-web-page-url'),
                         'http://127.0.0.1.local/dashboard')
        self.assertEqual(headers.get('profile-title'), 'mango-connect-demo1')
        self.assertIn('filename=mango-connect-demo1',
                      headers.get('Content-Disposition', ''))

    def test_unprovisioned_user_gets_global_yaml(self):
        _, token = tk.create_token(tk.token_file(), 'legacy')
        status, headers, body = self._req(f'/sub/{token}')
        self.assertEqual(status, 200)
        self.assertIn('DEMO-UUID-1234', body.decode())
        self.assertEqual(headers.get('profile-title'), 'mango-connect')


if __name__ == '__main__':
    unittest.main(verbosity=2)


class Review7Tests(AccountHarness):
    """Seventh review batch: guard capacity aging, fmt content-type,
    no exception text on 500s, non-ASCII cookies, pack archive perms."""

    def test_login_guard_full_table_still_locks_new_keys(self):
        # A flood of one-off failures must not permanently disable the
        # lockout: once the table is full and those entries are stale, a
        # new (ip, username) pair still gets tracked and locked.
        us = self.us
        old_max = us._LOGIN_FAILS_MAX
        us._LOGIN_FAILS_MAX = 5
        try:
            t0 = 1_000_000
            for i in range(5):
                us.record_login_fail(f'10.0.0.{i}', f'spray{i}', now=t0)
            later = t0 + us.LOCK_SECONDS + 1
            for _ in range(us.LOCK_THRESHOLD):
                us.record_login_fail('9.9.9.9', 'admin1', now=later)
            self.assertGreater(us.login_lockout_remaining('9.9.9.9', 'admin1', now=later), 0)
            self.assertLessEqual(len(us._login_fails), 5)
        finally:
            us._LOGIN_FAILS_MAX = old_max
            us.reset_login_guard()

    def test_login_guard_full_of_fresh_entries_evicts_oldest(self):
        # Even when every tracked entry is recent, the newest attacker key
        # must be tracked (oldest unlocked entry is evicted instead).
        us = self.us
        old_max = us._LOGIN_FAILS_MAX
        us._LOGIN_FAILS_MAX = 5
        try:
            t0 = 2_000_000
            for i in range(5):
                us.record_login_fail(f'10.0.1.{i}', f'spray{i}', now=t0 + i)
            for k in range(us.LOCK_THRESHOLD):
                us.record_login_fail('9.9.9.8', 'admin1', now=t0 + 10 + k)
            self.assertGreater(
                us.login_lockout_remaining('9.9.9.8', 'admin1', now=t0 + 20), 0)
            self.assertLessEqual(len(us._login_fails), 5)
        finally:
            us._LOGIN_FAILS_MAX = old_max
            us.reset_login_guard()

    def test_sub_singbox_content_type_is_json(self):
        ck, csrf = self._login()
        token = self._create_demo_user(ck, csrf)
        status, headers, body = self._req(f'/sub/{token}?fmt=singbox')
        self.assertEqual(status, 200)
        self.assertTrue(headers.get('Content-Type', '').startswith('application/json'),
                        headers.get('Content-Type'))
        json.loads(body)
        status, headers, _ = self._req(f'/sub/{token}')
        self.assertTrue(headers.get('Content-Type', '').startswith('text/yaml'))

    def test_unhandled_error_does_not_leak_exception_text(self):
        import server as srv_mod
        orig = srv_mod.Handler._serve_health

        def boom(self):
            raise RuntimeError('/secret/internal/path.yaml exploded')
        srv_mod.Handler._serve_health = boom
        try:
            status, _, body = self._req('/health')
        finally:
            srv_mod.Handler._serve_health = orig
        self.assertEqual(status, 500)
        self.assertNotIn(b'/secret/internal', body)
        self.assertNotIn(b'exploded', body)

    def test_non_ascii_session_cookie_is_anonymous_not_500(self):
        status, _, _ = self._req('/', headers={'Cookie': 'mango_session=été.abc'.encode('utf-8').decode('latin-1')})
        self.assertEqual(status, 200)
        status, _, _ = self._req('/dashboard', headers={'Cookie': 'mango_session=é.x'.encode('utf-8').decode('latin-1')})
        self.assertEqual(status, 303)

    def test_handler_has_socket_timeout(self):
        import server as srv_mod
        self.assertTrue(srv_mod.Handler.timeout and srv_mod.Handler.timeout <= 60)

    def test_state_pack_archive_is_owner_only(self):
        import state_backup as sb
        out = sb.pack(dict(os.environ), Path(self.tmp.name) / 'out/pack.tar.gz')
        self.assertEqual(out.stat().st_mode & 0o777, 0o600)


def quote_plain(u):
    from urllib.parse import quote
    return quote(u, safe='')


class Review8Tests(AccountHarness):
    """Eighth review batch: POST framing, numeric guards, CSV injection,
    cookie preservation on slide, proxy-header trust, /info fallback."""

    def _raw(self, payload: bytes) -> bytes:
        import socket
        with socket.create_connection(('127.0.0.1', self.port), timeout=5) as sk:
            sk.sendall(payload)
            chunks = []
            while True:
                try:
                    b = sk.recv(65536)
                except socket.timeout:
                    break
                if not b:
                    break
                chunks.append(b)
            return b''.join(chunks)

    def test_oversized_post_closes_connection(self):
        body = b'x' * 5000
        resp = self._raw(b'POST /login HTTP/1.1\r\nHost: x\r\nContent-Length: 5000\r\n\r\n' + body)
        self.assertTrue(resp.startswith(b'HTTP/1.1 413'), resp[:40])
        # exactly one response: the unread body was not parsed as a request
        self.assertEqual(resp.count(b'HTTP/1.1 '), 1)

    def test_chunked_post_is_refused(self):
        resp = self._raw(b'POST /login HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: chunked\r\n\r\n'
                         b'5\r\nhello\r\n0\r\n\r\n')
        self.assertTrue(resp.startswith(b'HTTP/1.1 411'), resp[:40])
        self.assertEqual(resp.count(b'HTTP/1.1 '), 1)

    def test_non_finite_numbers_are_rejected_not_500(self):
        ck, csrf = self._login()
        for q in ('inf', 'nan', '1e400'):
            data = (f'csrf={csrf}&username=n{q[:2]}x&password=demopass123'
                    f'&quota_gb={q}&expire_days=0&reset_day=1&notes=').encode()
            status, headers, _ = self._req('/admin/users', data=data, headers=self._auth(ck))
            self.assertEqual(status, 303, q)
            self.assertIn('/admin?err=', headers.get('Location', ''))
        self._create_demo_user(ck, csrf)
        uid = self._demo()['id']
        for action in ('set-quota', 'set-expire'):
            status, headers, _ = self._req(
                f'/admin/users/{uid}/action',
                data=f'csrf={csrf}&action={action}&value=inf'.encode(),
                headers=self._auth(ck))
            self.assertEqual(status, 303, action)
            self.assertIn('/admin?err=', headers.get('Location', ''))

    def test_reset_password_scrypt_busy_is_handled(self):
        ck, csrf = self._login()
        self._create_demo_user(ck, csrf)
        uid = self._demo()['id']
        orig = self.us.set_password

        def busy(*a, **k):
            raise self.us.ScryptBusy()
        self.us.set_password = busy
        try:
            status, headers, _ = self._req(
                f'/admin/users/{uid}/action',
                data=f'csrf={csrf}&action=reset-password&value=newpass1234'.encode(),
                headers=self._auth(ck))
        finally:
            self.us.set_password = orig
        self.assertEqual(status, 303)
        self.assertIn('/admin?err=', headers.get('Location', ''))

    def test_audit_csv_neutralises_formulas(self):
        import server as srv_mod
        self.assertEqual(srv_mod._csv_cell('=HYPERLINK("x")'), '\'=HYPERLINK("x")')
        self.assertEqual(srv_mod._csv_cell('@SUM(A1)'), "'@SUM(A1)")
        self.assertEqual(srv_mod._csv_cell('alice'), 'alice')
        self.us.append_audit({'actor': '=cmd|calc', 'action': 'login.fail', 'ip': '1.1.1.1'})
        ck, _ = self._login()
        status, _, body = self._req('/admin/audit/export', headers=self._auth(ck))
        self.assertEqual(status, 200)
        self.assertIn(b"'=cmd|calc", body)
        self.assertNotIn(b',=cmd', body)

    def test_slide_keeps_fresh_csrf_cookie(self):
        import server as srv_mod
        h = srv_mod.Handler.__new__(srv_mod.Handler)
        headers = h._page_headers('mango_session=a', 'mango_csrf=b')
        cookies = [v for k, v in headers if k == 'Set-Cookie']
        self.assertEqual(cookies, ['mango_session=a', 'mango_csrf=b'])
        headers = h._page_headers(None, None)
        self.assertFalse([v for k, v in headers if k == 'Set-Cookie'])

    def test_cf_connecting_ip_only_trusted_from_loopback(self):
        import server as srv_mod
        h = srv_mod.Handler.__new__(srv_mod.Handler)
        h.headers = {'CF-Connecting-IP': '8.8.8.8'}
        h.client_address = ('127.0.0.1', 1)
        self.assertEqual(h._client_ip(), '8.8.8.8')
        h.client_address = ('203.0.113.9', 1)
        self.assertEqual(h._client_ip(), '203.0.113.9')

    def test_client_deep_links_use_native_formats(self):
        import base64
        import pages
        from urllib.parse import unquote
        url = 'https://x.example/sub/export?u=1&e=2&k=3&s=4'
        links = dict(pages._client_links(url))
        self.assertIn(quote_plain(url + '&fmt=surge'), links['Surge'])
        self.assertIn('fmt=qx', unquote(links['Quantumult X']))
        rocket = links['Shadowrocket'].removeprefix('sub://')
        self.assertEqual(base64.urlsafe_b64decode(rocket + '=' * (-len(rocket) % 4)).decode(), url)
        self.assertNotIn('fmt=', unquote(links['Clash / Mihomo']))

    def test_export_link_carries_userinfo_and_surge_managed_header(self):
        ck, csrf = self._login()
        self._create_demo_user(ck, csrf, quota_gb='10')
        path = self._export_url_for(self._demo())
        status, headers, _ = self._req(path)
        self.assertEqual(status, 200)
        self.assertIn('total=', headers.get('subscription-userinfo', ''))
        status, _, body = self._req(path + '&fmt=surge')
        self.assertEqual(status, 200)
        self.assertTrue(body.startswith(b'#!MANAGED-CONFIG '), body[:60])

    def test_info_serves_last_good_meta_when_render_fails(self):
        import server as srv_mod
        ck, csrf = self._login()
        token = self._create_demo_user(ck, csrf)
        status, _, body = self._req(f'/info/{token}')
        self.assertEqual(status, 200)
        good = json.loads(body)
        orig = srv_mod.STATE.ensure_fresh

        def broken():
            raise RuntimeError('render exploded')
        srv_mod.STATE.ensure_fresh = broken
        try:
            status, _, body = self._req(f'/info/{token}')
        finally:
            srv_mod.STATE.ensure_fresh = orig
        self.assertEqual(status, 200)
        self.assertEqual(json.loads(body)['node_count'], good['node_count'])


class SecretKeyTests(unittest.TestCase):
    def setUp(self):
        sys.path.insert(0, str(Path(__file__).resolve().parent.parent / 'src'))
        import users as us
        self.us = us
        self.tmp = tempfile.TemporaryDirectory()
        self.env = {'SHARE_STATE_DIR': self.tmp.name}

    def tearDown(self):
        self.tmp.cleanup()

    def test_generated_once_and_stable(self):
        a = self.us.load_secret(self.env)
        b = self.us.load_secret(self.env)
        self.assertEqual(a, b)
        self.assertEqual(len(a), 48)
        p = self.us.secret_file(self.env)
        self.assertEqual(p.stat().st_mode & 0o777, 0o600)
        self.assertFalse(p.with_name(p.name + '.new').exists())

    def test_damaged_secret_raises_instead_of_rotating(self):
        p = self.us.secret_file(self.env)
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text('abc', encoding='ascii')
        with self.assertRaises(RuntimeError):
            self.us.load_secret(self.env)
        self.assertEqual(p.read_text(encoding='ascii'), 'abc')

    def test_token_ids_never_collide(self):
        import tokens as tk
        path = Path(self.tmp.name) / 'tokens.json'
        ids = {tk.create_token(path, 'same')[0]['id'] for _ in range(30)}
        self.assertEqual(len(ids), 30)


class _FakeGateway:
    """Minimal mihomo controller: /proxies mirrors a mutable alive table and
    /proxies/<name>/delay rewrites it exactly like mihomo's URLTest (a success
    sets alive + a positive history delay; a failure records delay 0)."""

    def __init__(self, dead_forever=()):
        from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
        self.state = {}                # name -> last delay (0 == dead)
        self.dead_forever = set(dead_forever)
        self.lock = threading.Lock()
        self.attempted = []            # names whose delay endpoint was hit
        self.done = threading.Event()
        outer = self

        class H(BaseHTTPRequestHandler):
            def log_message(self, *a):
                pass

            def _json(self, code, body):
                payload = body if isinstance(body, bytes) else json.dumps(body).encode()
                self.send_response(code)
                self.send_header('Content-Type', 'application/json')
                self.send_header('Content-Length', str(len(payload)))
                self.end_headers()
                self.wfile.write(payload)

            def do_GET(self):
                from urllib.parse import unquote, urlsplit
                parts = [unquote(p) for p in urlsplit(self.path).path.strip('/').split('/')]
                if parts == ['proxies']:
                    return self._json(200, {'proxies': outer._payload()})
                if len(parts) == 3 and parts[0] == 'proxies' and parts[2] == 'delay':
                    return outer._delay(self, parts[1])
                return self._json(404, {'message': 'not found'})

        self.httpd = ThreadingHTTPServer(('127.0.0.1', 0), H)
        self.port = self.httpd.server_address[1]
        threading.Thread(target=self.httpd.serve_forever, daemon=True).start()

    def _payload(self):
        with self.lock:
            items = {'PROXY': {'type': 'Selector', 'history': []}}
            for name, delay in self.state.items():
                items[name] = {'type': 'Vless', 'udp': True, 'alive': delay > 0,
                               'history': [{'time': '2026-11-23T00:00:00',
                                            'delay': delay}]}
            return items

    def _delay(self, handler, name):
        with self.lock:
            if name in self.state:
                self.attempted.append(name)
            if name in self.dead_forever or name not in self.state:
                failed = True
            else:
                self.state[name] = 120
                failed = False
            complete = set(self.attempted) >= set(self.state)
        if complete:
            self.done.set()
        if failed:
            return handler._json(504, {'message': 'Timeout'})
        return handler._json(200, {'delay': 120})

    def close(self):
        self.httpd.shutdown()
        self.httpd.server_close()


class GatewayReprobeTests(unittest.TestCase):
    """Regression for '/nodes shows many nodes offline': mihomo's url-test /
    fallback group probes run lazily (~5 min) and, at 100+ nodes, a bulk sweep
    times out under load while fallback groups stop probing after the first
    survivor - so reachable nodes can carry a stale 'dead' verdict. The status
    reader must re-test offline rows through the controller's own delay API
    (which rewrites mihomo's history) so the page recovers the real verdict."""

    def setUp(self):
        self._old_env = {k: os.environ.get(k) for k in (
            'SHARE_GATEWAY_API', 'SHARE_GATEWAY_SECRET',
            'SHARE_STATE_DIR', 'SHARE_CLASH_DIR')}
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        clash = self.root / 'clash'
        state = self.root / 'state'
        (clash / 'airports').mkdir(parents=True)
        (clash / 'airports' / 'mango-clash.yaml').write_text('proxies: []\n', encoding='utf-8')
        state.mkdir()
        (state / 'share-nodes.json').write_text('[]', encoding='utf-8')
        (state / 'exclude.json').write_text('[]', encoding='utf-8')
        secret = self.root / 'controller-secret'
        secret.write_text('test-secret\n', encoding='utf-8')
        self.gw = _FakeGateway(dead_forever=('node-dead',))
        with self.gw.lock:
            self.gw.state.update({'node-a': 0, 'node-b': 0, 'node-dead': 0})
        os.environ['SHARE_STATE_DIR'] = str(state)
        os.environ['SHARE_CLASH_DIR'] = str(clash)
        os.environ['SHARE_GATEWAY_API'] = f'http://127.0.0.1:{self.gw.port}'
        os.environ['SHARE_GATEWAY_SECRET'] = str(secret)
        import importlib
        import server as srv
        importlib.reload(srv)
        self.srv = srv

    def _wait_round_done(self, timeout=10):
        """A round sets running=False only after invalidating the cache, so
        waiting on it also guarantees the next read sees the new verdict."""
        deadline = time.time() + timeout
        while self.srv._GATEWAY_PROBE['running'] and time.time() < deadline:
            time.sleep(0.02)
        self.assertFalse(self.srv._GATEWAY_PROBE['running'], 'probe round never finished')

    def tearDown(self):
        deadline = time.time() + 5
        while self.srv._GATEWAY_PROBE['running'] and time.time() < deadline:
            time.sleep(0.02)
        self.gw.close()
        for k, v in self._old_env.items():
            if v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = v
        self.tmp.cleanup()

    def test_offline_rows_are_reprobed_and_reachable_ones_revive(self):
        nodes, err = self.srv.STATE.gateway_nodes()
        self.assertEqual(err, '')
        self.assertEqual({n['name'] for n in nodes}, {'node-a', 'node-b', 'node-dead'})
        self.assertFalse(any(n['alive'] for n in nodes), 'controller starts all-dead')
        self.assertTrue(self.gw.done.wait(10),
                        'background re-probe never hit the delay endpoint')
        self._wait_round_done()
        # The probe round invalidated the 15s cache; the next read must reflect
        # mihomo's corrected verdict - reachable rows online, truly-dead still dead.
        nodes2, err2 = self.srv.STATE.gateway_nodes()
        self.assertEqual(err2, '')
        by = {n['name']: n for n in nodes2}
        self.assertTrue(by['node-a']['alive'])
        self.assertTrue(by['node-b']['alive'])
        self.assertEqual(by['node-a']['delay'], 120)
        self.assertFalse(by['node-dead']['alive'])
        self.assertEqual(set(self.gw.attempted), {'node-a', 'node-b', 'node-dead'})

    def test_recheck_survives_a_later_bulk_sweep(self):
        # mihomo's next url-test sweep flips the same false negatives back to
        # delay=0; our recent direct success must keep them online.
        self.srv.STATE.gateway_nodes()
        self.assertTrue(self.gw.done.wait(10))
        self._wait_round_done()
        with self.gw.lock:
            self.gw.state.update({'node-a': 0, 'node-b': 0})
        with self.srv._GATEWAY_CACHE_LOCK:
            self.srv._GATEWAY_CACHE['ts'] = 0.0
        by = {n['name']: n for n in self.srv.STATE.gateway_nodes()[0]}
        self.assertTrue(by['node-a']['alive'])
        self.assertEqual(by['node-a']['delay'], 120)
        self.assertFalse(by['node-dead']['alive'])
        # and the verdict expires: after the TTL the sweep result shows again
        with self.srv._GATEWAY_VERDICT_LOCK:
            for k, (ts, d) in list(self.srv._GATEWAY_VERDICT.items()):
                self.srv._GATEWAY_VERDICT[k] = (ts - self.srv._GATEWAY_VERDICT_TTL - 1, d)
        with self.srv._GATEWAY_CACHE_LOCK:
            self.srv._GATEWAY_CACHE['ts'] = time.time()
        by = {n['name']: n for n in self.srv.STATE.gateway_nodes()[0]}
        self.assertFalse(by['node-a']['alive'])

    def test_sweep_flap_of_a_live_row_is_masked_until_reprobe_fails(self):
        with self.gw.lock:
            self.gw.state.update({'node-a': 90})
        self.srv.STATE.gateway_nodes()                    # observes node-a alive
        deadline = time.time() + 10
        while not self.srv._GATEWAY_PROBE['running'] and time.time() < deadline \
                and len(self.gw.attempted) < 2:
            time.sleep(0.02)
        self._wait_round_done()
        self.assertNotIn('node-a', self.gw.attempted)     # alive rows not probed
        with self.gw.lock:
            self.gw.state['node-a'] = 0                   # sweep flap
        with self.srv._GATEWAY_CACHE_LOCK:
            self.srv._GATEWAY_CACHE['ts'] = 0.0
        by = {n['name']: n for n in self.srv.STATE.gateway_nodes()[0]}
        self.assertTrue(by['node-a']['alive'], 'recent healthy observation masks the flap')
        self.assertFalse(by['node-dead']['alive'])

    def test_reprobe_is_throttled_within_the_gap(self):
        self.srv.STATE.gateway_nodes()
        self.assertTrue(self.gw.done.wait(10))
        self._wait_round_done()
        attempts = list(self.gw.attempted)
        # A second read must not kick another round inside the 120s gap.
        self.srv.STATE.gateway_nodes()
        time.sleep(0.3)
        self.assertEqual(self.gw.attempted, attempts)
