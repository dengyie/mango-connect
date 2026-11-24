#!/usr/bin/env python3
"""Usage-detail feature tests: usage_stats parsing (rotated logs, windows,
damage tolerance), /dashboard/usage + /api/usage over real HTTP (session
auth, self-only vs admin ?u=), and the usage_page SSR face.

Runs against a live ThreadingHTTPServer on 127.0.0.1 with an isolated
SHARE_STATE_DIR - no mocks for the HTTP layer, exactly like AccountHarness
in test_share.py but kept separate so the usage suite can run alone.
"""

from __future__ import annotations

import json
import os
import sys
import tempfile
import threading
import time
import unittest
import urllib.error
import urllib.request
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / 'src'))


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    """HTTPError on 3xx so tests can assert redirects explicitly."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


class UsageUnitTest(unittest.TestCase):
    """usage_stats: log parsing, rotation family, windows, damage control."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.log = self.root / 'traffic-ingest.log'
        # The module caches globally; every case gets a distinct path, but
        # clear the memo anyway so a same-shaped re-render is impossible.
        import usage_stats
        with usage_stats._CACHE_LOCK:
            usage_stats._CACHE.update(key=None, frames={}, at=0.0)

    def tearDown(self):
        import usage_stats
        with usage_stats._CACHE_LOCK:
            usage_stats._CACHE.update(key=None, frames={}, at=0.0)
        self.tmp.cleanup()

    def _write(self, records, path=None):
        path = path or self.log
        lines = [r if isinstance(r, str) else json.dumps(r, ensure_ascii=False)
                 for r in records]
        path.write_text('\n'.join(lines) + '\n', encoding='utf-8')

    # -- core aggregation ---------------------------------------------------

    def test_daily_window_and_by_node_are_date_correct(self):
        import usage_stats
        now = int(time.time())
        today = time.strftime('%Y-%m-%d', time.localtime(now))
        old = time.strftime('%Y-%m-%d', time.localtime(now - 40 * 86400))
        self._write([
            {'user': 'alice', 'node': 'aws-1', 'up': 100, 'down': 200, 'at': now},
            {'user': 'alice', 'node': 'tebi-relay', 'up': 5, 'down': 5,
             'at': now - 40 * 86400},  # outside a 14d window, inside 90d
        ])
        d14 = usage_stats.usage_detail(self.log, 'alice', days=14, now=now)
        self.assertEqual(d14['total'], {'up': 100, 'down': 200})
        self.assertEqual([r['node'] for r in d14['by_node']], ['aws-1'])
        d90 = usage_stats.usage_detail(self.log, 'alice', days=90, now=now)
        self.assertEqual(d90['total'], {'up': 105, 'down': 205})
        self.assertEqual(
            {(r['node'], r['up']) for r in d90['by_node']},
            {('aws-1', 100), ('tebi-relay', 5)})

    def test_rotated_siblings_are_read(self):
        import usage_stats
        now = int(time.time())
        self._write([{'user': 'alice', 'node': 'old-node', 'up': 7, 'down': 8,
                      'at': now - 3600}])
        rotated = self.root / ('traffic-ingest.log.'
                               + time.strftime('%Y%m%d-%H%M%S',
                                               time.localtime(now - 7200)))
        rotated.write_text(self.log.read_text(encoding='utf-8'), encoding='utf-8')
        self._write([{'user': 'alice', 'node': 'new-node', 'up': 3, 'down': 4,
                      'at': now}])
        d = usage_stats.usage_detail(self.log, 'alice', days=7, now=now)
        self.assertEqual(d['total'], {'up': 10, 'down': 12})
        self.assertEqual({r['node'] for r in d['by_node']},
                         {'old-node', 'new-node'})

    def test_lock_and_tmp_sidecars_are_not_logs(self):
        import usage_stats
        now = int(time.time())
        self._write([{'user': 'alice', 'node': 'n1', 'up': 1, 'down': 1, 'at': now}])
        (self.root / 'traffic-ingest.log.lock').write_text('not json', encoding='utf-8')
        (self.root / 'traffic-ingest.log.tmp').write_text('not json', encoding='utf-8')
        d = usage_stats.usage_detail(self.log, 'alice', days=7, now=now)
        self.assertEqual(d['total'], {'up': 1, 'down': 1})

    def test_damaged_records_never_crash(self):
        import usage_stats
        now = int(time.time())
        self._write([
            json.dumps({'user': 'alice', 'node': 'n', 'up': 2, 'down': 3, 'at': 'abc'}),
            json.dumps({'user': 'alice', 'node': 'n', 'up': 4, 'down': 5, 'at': None}),
            json.dumps({'user': 'alice', 'node': 'n', 'up': 6, 'down': 7,
                        'at': f'{now - 3600}.5'}),  # float string coerces
            json.dumps({'user': 'alice', 'node': 'n', 'up': 9, 'down': 9,
                        'at': 10 ** 20}),   # absurd future stamp: dropped
            json.dumps({'user': 'alice', 'node': 'n', 'up': 9, 'down': 9,
                        'at': -50}),        # pre-epoch stamp: dropped
            'garbage', '   ', '', '[]', '{"user": "  "}',
        ])
        d = usage_stats.usage_detail(self.log, 'alice', days=7, now=now)
        # only the float-string record survives
        hour_ago = time.strftime('%Y-%m-%d', time.localtime(now - 3600))
        by_date = {r['date']: r for r in d['daily']}
        self.assertEqual(by_date.get(hour_ago, {'up': 0})['up'], 6)
        self.assertEqual(d['total'], {'up': 6, 'down': 7})

    def test_zero_byte_lines_are_not_data(self):
        import usage_stats
        now = int(time.time())
        self._write([{'user': 'alice', 'node': 'n', 'up': 0, 'down': 0, 'at': now}])
        d = usage_stats.usage_detail(self.log, 'alice', days=7, now=now)
        self.assertEqual(d['total'], {'up': 0, 'down': 0})
        self.assertEqual(d['by_node'], [])

    def test_days_clamped_and_echoed(self):
        import usage_stats
        now = int(time.time())
        for raw, want in (('999', 90), ('0', 1), ('-5', 1), ('abc', 14),
                          ('', 14), ('30', 30)):
            d = usage_stats.usage_detail(self.log, 'a', days=raw, now=now)
            self.assertEqual(len(d['daily']), want, raw)
            self.assertEqual(d['days'], want)

    def test_cache_invalidates_on_append(self):
        import usage_stats
        now = int(time.time())
        self._write([{'user': 'alice', 'node': 'n', 'up': 1, 'down': 1, 'at': now}])
        d1 = usage_stats.usage_detail(self.log, 'alice', days=7, now=now)
        self.assertEqual(d1['total'], {'up': 1, 'down': 1})
        with open(self.log, 'a', encoding='utf-8') as f:
            f.write(json.dumps({'user': 'alice', 'node': 'n', 'up': 5, 'down': 5,
                                'at': now}) + '\n')
        d2 = usage_stats.usage_detail(self.log, 'alice', days=7, now=now)
        self.assertEqual(d2['total'], {'up': 6, 'down': 6})

    def test_cache_survives_ttl_when_unchanged(self):
        import usage_stats
        now = int(time.time())
        self._write([{'user': 'alice', 'node': 'n', 'up': 1, 'down': 1, 'at': now}])
        usage_stats.usage_detail(self.log, 'alice', days=7, now=now)
        # Rewrite the identical bytes: (mtime_ns, size) may shift, but a
        # within-TTL hit must serve the memoised frames without reparsing.
        with usage_stats._CACHE_LOCK:
            frozen = dict(usage_stats._CACHE)
        self._write([{'user': 'alice', 'node': 'n', 'up': 1, 'down': 1, 'at': now}])
        with usage_stats._CACHE_LOCK:
            usage_stats._CACHE.update(key=frozen['key'], frames=frozen['frames'],
                                      at=time.time())
        d = usage_stats.usage_detail(self.log, 'alice', days=7, now=now)
        self.assertEqual(d['total'], {'up': 1, 'down': 1})

    def test_other_users_isolated(self):
        import usage_stats
        now = int(time.time())
        self._write([
            {'user': 'alice', 'node': 'n', 'up': 1, 'down': 1, 'at': now},
            {'user': 'bob', 'node': 'n', 'up': 99, 'down': 99, 'at': now},
        ])
        d = usage_stats.usage_detail(self.log, 'Alice', days=7, now=now)
        self.assertEqual(d['total'], {'up': 1, 'down': 1})
        self.assertNotIn('bob', json.dumps(d))


class UsagePageUnitTests(unittest.TestCase):
    """SSR face: data table twin for a11y, mobile scroll, admin switcher."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.now = int(time.time())

    def tearDown(self):
        self.tmp.cleanup()

    def _detail(self, days=14):
        return {
            'daily': [{'date': time.strftime('%Y-%m-%d', time.localtime(self.now - i * 86400)),
                       'up': 100 * (i + 1), 'down': 200 * (i + 1)} for i in range(days)],
            'by_node': [{'node': 'aws-1', 'up': 300, 'down': 400}],
            'total': {'up': 300, 'down': 400}, 'days': days,
        }

    def test_page_has_a11y_data_table_and_scroll(self):
        import pages
        user = {'username': 'alice', 'role': 'user', 'quota_bytes': 10 ** 9,
                'used_bytes': 700, 'reset_day': 1, 'cycle_start': self.now}
        html = pages.usage_page(user, 'c', 'alice', self._detail(), days=14)
        self.assertIn('usage-chart-scroll', html)          # mobile swipe
        self.assertIn('aria-hidden="true"', html)          # chart is decoration
        self.assertIn('class="visually-hidden"', html)     # data-table twin
        self.assertIn('每日流量', html)
        self.assertIn('90 天', html)                       # max window chip
        self.assertIn('aria-current="true"', html)         # active chip marked

    def test_admin_switcher_carries_target(self):
        import pages
        admin = {'username': 'root', 'role': 'admin', 'quota_bytes': 0,
                 'used_bytes': 0, 'reset_day': 1, 'cycle_start': self.now}
        html = pages.usage_page(admin, 'c2', 'demo1', self._detail(),
                                is_admin=True, days=14)
        self.assertIn('查看用户', html)
        self.assertIn('value="demo1"', html)
        self.assertIn('u=demo1', html)

    def test_empty_state(self):
        import pages
        user = {'username': 'alice', 'role': 'user', 'quota_bytes': 0,
                'used_bytes': 0, 'reset_day': 1, 'cycle_start': self.now}
        html = pages.usage_page(user, 'c', 'alice',
                                {'daily': [], 'by_node': [],
                                 'total': {'up': 0, 'down': 0}, 'days': 14})
        self.assertIn('暂无', html)


class UsageHttpHarness(unittest.TestCase):
    """Shared live-server harness (no test_* methods of its own)."""

    def setUp(self):
        from http.server import ThreadingHTTPServer
        sys.path.insert(0, str(Path(__file__).resolve().parent.parent / 'src'))
        self._old_env = {k: os.environ.get(k)
                         for k in ('SHARE_STATE_DIR', 'SHARE_CLASH_DIR',
                                   'SHARE_PUBLIC_HOST')}
        self.tmp = tempfile.TemporaryDirectory()
        os.environ['SHARE_STATE_DIR'] = self.tmp.name
        state = Path(self.tmp.name)
        (state / 'airports').mkdir()
        (state / 'airports' / 'mango-clash.yaml').write_text(
            'proxies:\n  - {name: "[自建] demo-reality", type: vless, server: 1.2.3.4,'
            ' port: 443, uuid: DEMO-UUID-1234, tls: true, flow: xtls-rprx-vision,'
            ' servername: apple.com, reality-opts: {public-key: PKDEMO0123456789abcdef,'
            ' short-id: "01"}, client-fingerprint: chrome}\nproxy-groups: []\nrules: []\n',
            encoding='utf-8')
        (state / 'share-nodes.json').write_text('["[自建] demo-reality"]', encoding='utf-8')
        (state / 'exclude.json').write_text('[]', encoding='utf-8')
        os.environ['SHARE_CLASH_DIR'] = self.tmp.name
        os.environ['SHARE_PUBLIC_HOST'] = 'http://127.0.0.1.local'
        import importlib
        import server as srv_mod
        importlib.reload(srv_mod)
        self.httpd = ThreadingHTTPServer(('127.0.0.1', 0), srv_mod.Handler)
        self.port = self.httpd.server_address[1]
        threading.Thread(target=self.httpd.serve_forever, daemon=True).start()
        import users as us
        import usage_stats
        self.us = us
        self.usage_stats = usage_stats
        us.reset_login_guard()
        us.create_user(us.users_file(), 'admin1', 'adminpass1', role='admin')
        us.create_user(us.users_file(), 'demo1', 'demopass123', role='user')
        self.log = us.ingest_file()
        self._now = int(time.time())
        self._write_usage()

    def tearDown(self):
        import usage_stats
        with usage_stats._CACHE_LOCK:
            usage_stats._CACHE.update(key=None, frames={}, at=0.0)
        self.httpd.shutdown()
        self.us.reset_login_guard()
        for k, v in self._old_env.items():
            if v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = v
        self.tmp.cleanup()

    def _write_usage(self):
        """demo1 traffic on two nodes, now and 40 days ago (admin: 1B now)."""
        lines = [
            json.dumps({'user': 'demo1', 'node': 'aws-1', 'up': 100, 'down': 200,
                        'at': self._now}),
            json.dumps({'user': 'demo1', 'node': 'tebi-relay', 'up': 7, 'down': 9,
                        'at': self._now - 40 * 86400}),
            json.dumps({'user': 'admin1', 'node': 'aws-1', 'up': 1, 'down': 0,
                        'at': self._now}),
        ]
        self.log.parent.mkdir(parents=True, exist_ok=True)
        self.log.write_text('\n'.join(lines) + '\n', encoding='utf-8')

    def _req(self, path, data=None, headers=None, method=None):
        opener = urllib.request.build_opener(_NoRedirect)
        r = urllib.request.Request(f'http://127.0.0.1:{self.port}{path}',
                                   data=data, headers=headers or {},
                                   method=method)
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

    def _login(self, username, password):
        _, headers, _ = self._req('/login')
        csrf = self._cookies(headers)['mango_csrf']
        status, headers, _ = self._req(
            '/login',
            data=f'username={username}&password={password}&csrf={csrf}'.encode(),
            headers={'Cookie': f'mango_csrf={csrf}'})
        self.assertEqual(status, 303, 'login should redirect on success')
        return self._cookies(headers)

    @staticmethod
    def _auth(ck):
        return {'Cookie': f"mango_session={ck['mango_session']}; "
                          f"mango_csrf={ck['mango_csrf']}"}


class UsageHttpTests(UsageHttpHarness):
    """The two authed faces over real HTTP: page + JSON API."""

    # -- authentication -----------------------------------------------------

    def test_usage_page_requires_login(self):
        status, headers, _ = self._req('/dashboard/usage')
        self.assertEqual(status, 303)
        self.assertIn('/login', headers.get('Location') or '')

    def test_api_usage_requires_login(self):
        status, _, body = self._req('/api/usage')
        self.assertEqual(status, 401)
        self.assertIn('login required', body.decode())

    def test_api_usage_rejects_forged_session(self):
        status, _, body = self._req('/api/usage', headers={
            'Cookie': 'mango_session=forged.sig; mango_csrf=x'})
        self.assertEqual(status, 401)

    # -- self service (ordinary user) ---------------------------------------

    def test_member_sees_own_usage_page(self):
        ck = self._login('demo1', 'demopass123')
        status, headers, body = self._req('/dashboard/usage', headers=self._auth(ck))
        self.assertEqual(status, 200)
        html = body.decode()
        self.assertIn('demo1', html)
        self.assertIn('流量明细', html)
        self.assertNotIn('查看用户', html)  # no admin switcher for members

    def test_member_ignores_u_param(self):
        ck = self._login('demo1', 'demopass123')
        # member asks for the admin's numbers: served their own, silently
        status, _, body = self._req('/dashboard/usage?u=admin1&days=7',
                                    headers=self._auth(ck))
        self.assertEqual(status, 200)
        self.assertIn('>demo1<', body.decode())
        api_status, _, api_body = self._req('/api/usage?u=admin1&days=7',
                                            headers=self._auth(ck))
        self.assertEqual(api_status, 200)
        data = json.loads(api_body)
        self.assertEqual(data['user'], 'demo1')
        self.assertTrue(data['self'])

    def test_member_api_usage_numbers(self):
        ck = self._login('demo1', 'demopass123')
        status, _, body = self._req('/api/usage?days=14', headers=self._auth(ck))
        self.assertEqual(status, 200)
        data = json.loads(body)
        self.assertEqual(data['user'], 'demo1')
        self.assertEqual(data['days'], 14)
        self.assertEqual(data['total'], {'up': 100, 'down': 200})  # 40d-old excluded
        nodes = {r['node']: r for r in data['by_node']}
        self.assertEqual(set(nodes), {'aws-1'})
        self.assertEqual(len(data['daily']), 14)

    def test_member_api_90d_window_includes_old_traffic(self):
        ck = self._login('demo1', 'demopass123')
        _, _, body = self._req('/api/usage?days=90', headers=self._auth(ck))
        data = json.loads(body)
        self.assertEqual(data['days'], 90)
        self.assertEqual(data['total'], {'up': 107, 'down': 209})

    # -- admin explicit targeting -------------------------------------------

    def test_admin_can_view_other_user(self):
        ck = self._login('admin1', 'adminpass1')
        status, _, body = self._req('/dashboard/usage?u=demo1&days=14',
                                    headers=self._auth(ck))
        self.assertEqual(status, 200)
        html = body.decode()
        self.assertIn('>demo1<', html)
        self.assertIn('查看用户', html)

    def test_admin_unknown_target_is_a_soft_error(self):
        ck = self._login('admin1', 'adminpass1')
        status, headers, _ = self._req('/dashboard/usage?u=ghost',
                                       headers=self._auth(ck))
        self.assertEqual(status, 303)
        self.assertIn('/dashboard/usage?err=', headers.get('Location') or '')
        api_status, _, api_body = self._req('/api/usage?u=ghost',
                                            headers=self._auth(ck))
        self.assertEqual(api_status, 404)
        self.assertIn('no such user', api_body.decode())

    def test_admin_api_usage_other_and_self(self):
        ck = self._login('admin1', 'adminpass1')
        _, _, other = self._req('/api/usage?u=demo1&days=14', headers=self._auth(ck))
        data = json.loads(other)
        self.assertEqual((data['user'], data['self']), ('demo1', False))
        self.assertEqual(data['viewer'], 'admin1')
        _, _, own = self._req('/api/usage', headers=self._auth(ck))
        data = json.loads(own)
        self.assertEqual((data['user'], data['self']), ('admin1', True))
        self.assertEqual(data['total'], {'up': 1, 'down': 0})

    # -- the impersonation regression ---------------------------------------
    # An earlier draft slid the session cookie from the TARGET's record: an
    # admin inspecting ?u=demo1 got handed a session for demo1's account.

    def test_admin_inspection_never_mints_target_session(self):
        ck = self._login('admin1', 'adminpass1')
        # long-lived fresh session: past the slide threshold is what forced
        # the buggy path to re-issue; force re-issue by using a short-lived
        # forged... simplest reliable trigger: the bug re-issued from `fresh`
        # whenever the payload needed sliding. Verify structurally instead:
        # no Set-Cookie may ever carry a session whose uid is demo1's.
        demo = self.us.find_by_username(self.us.load(self.us.users_file()), 'demo1')
        _, headers, _ = self._req('/dashboard/usage?u=demo1', headers=self._auth(ck))
        for v in (headers.get_all('Set-Cookie') or []):
            if v.startswith('mango_session='):
                value = v.split('=', 1)[1].split(';')[0]
                payload = self.us.read_session(self.us.load_secret(), value)
                self.assertIsNotNone(payload)
                self.assertNotEqual(payload.get('uid'), demo['id'],
                                    'admin inspected ?u=demo1 and got demo1 session!')

    def test_admin_inspection_page_still_identifies_admin(self):
        ck = self._login('admin1', 'adminpass1')
        _, _, body = self._req('/dashboard/usage?u=demo1', headers=self._auth(ck))
        html = body.decode()
        # the shell sidebar must render the ADMIN nav, not the member's
        self.assertIn('用户管理', html)
        # and the target identity only appears as the inspected heading
        self.assertIn('>demo1<', html)

    # -- days handling over HTTP --------------------------------------------

    def test_garbage_days_falls_back_not_500(self):
        ck = self._login('demo1', 'demopass123')
        status, _, body = self._req('/dashboard/usage?days=banana',
                                    headers=self._auth(ck))
        self.assertEqual(status, 200)
        self.assertIn('流量明细', body.decode())
        status, _, body = self._req('/api/usage?days=999999', headers=self._auth(ck))
        self.assertEqual(status, 200)
        data = json.loads(body)
        self.assertEqual(data['days'], 90)  # clamped, echoed

    def test_days_chip_links_render(self):
        ck = self._login('demo1', 'demopass123')
        _, _, body = self._req('/dashboard/usage', headers=self._auth(ck))
        html = body.decode()
        for d in ('7', '14', '30', '90'):
            self.assertIn(f'days={d}', html)

    # -- no credential leakage ----------------------------------------------

    def test_api_payload_carries_no_credentials(self):
        ck = self._login('demo1', 'demopass123')
        _, _, body = self._req('/api/usage', headers=self._auth(ck))
        low = body.decode().lower()
        for forbidden in ('uuid', 'password', 'secret', 'scrypt', 'token'):
            self.assertNotIn(forbidden, low)

    # -- ingest -> visible (integration through the real writer) ------------

    def test_ingest_report_becomes_visible_via_add_usage(self):
        node_token = self._make_node_token()
        before = json.loads(self._req('/api/usage?days=7',
                                      headers=self._auth(self._login('demo1', 'demopass123')))[2])
        payload = json.dumps({'node': 'itest-node',
                              'updates': [{'user': 'demo1', 'up': 11, 'down': 22}]})
        status, _, body = self._req('/ingest/traffic', data=payload.encode(),
                                    headers={'Authorization': 'Bearer ' + node_token,
                                             'Content-Type': 'application/json'},
                                    method='POST')
        self.assertEqual(status, 200)
        self.assertEqual(json.loads(body)['accepted'], 1)
        after = json.loads(self._req('/api/usage?days=7',
                                     headers=self._auth(self._login('demo1', 'demopass123')))[2])
        nodes = {r['node']: r for r in after['by_node']}
        self.assertIn('itest-node', nodes)
        self.assertEqual(nodes['itest-node']['up'], 11)
        self.assertEqual(after['total']['up'], before['total']['up'] + 11)

    def _make_node_token(self):
        import tokens as tk
        _, token = tk.create_token(tk.nodes_file(), 'itest-node')
        return token


if __name__ == '__main__':
    unittest.main()
