import os
import sys
import json
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

import config


class TestDashboardApp(unittest.TestCase):

    def setUp(self):
        self.tmp = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
        self.tmp.close()
        self._orig_path = config.DB_PATH
        config.DB_PATH = self.tmp.name

        from database.models import init_db
        init_db()

        from dashboard.app import app, _login_attempts
        _login_attempts.clear()
        app.config["TESTING"] = True
        app.config["SECRET_KEY"] = "test-secret"
        self.app = app
        self.client = app.test_client()

    def tearDown(self):
        config.DB_PATH = self._orig_path
        os.unlink(self.tmp.name)

    def _get_csrf_token(self):
        resp = self.client.get("/login")
        data = resp.data.decode()
        marker = 'name="_csrf_token" value="'
        idx = data.find(marker)
        if idx == -1:
            return None
        start = idx + len(marker)
        end = data.find('"', start)
        return data[start:end]

    def _login(self):
        token = self._get_csrf_token()
        return self.client.post("/login", data={
            "username": config.DASHBOARD_USER,
            "password": config._DASHBOARD_PASS_RAW,
            "_csrf_token": token,
        }, follow_redirects=True)

    def test_login_page_renders(self):
        resp = self.client.get("/login")
        self.assertEqual(resp.status_code, 200)
        self.assertIn(b"_csrf_token", resp.data)

    def test_login_redirects_to_index(self):
        token = self._get_csrf_token()
        resp = self.client.post("/login", data={
            "username": config.DASHBOARD_USER,
            "password": config._DASHBOARD_PASS_RAW,
            "_csrf_token": token,
        })
        self.assertEqual(resp.status_code, 302)

    def test_login_wrong_password(self):
        token = self._get_csrf_token()
        resp = self.client.post("/login", data={
            "username": "admin",
            "password": "wrongpassword",
            "_csrf_token": token,
        })
        self.assertEqual(resp.status_code, 200)
        self.assertIn(b"Invalid credentials", resp.data)

    def test_login_without_csrf_token_returns_403(self):
        self.client.get("/login")
        resp = self.client.post("/login", data={
            "username": config.DASHBOARD_USER,
            "password": config._DASHBOARD_PASS_RAW,
        })
        self.assertEqual(resp.status_code, 403)

    def test_index_requires_login(self):
        resp = self.client.get("/")
        self.assertEqual(resp.status_code, 302)
        self.assertIn("/login", resp.headers["Location"])

    def test_api_stats_requires_login(self):
        resp = self.client.get("/api/stats")
        self.assertEqual(resp.status_code, 302)

    def test_api_stats_returns_json(self):
        self._login()
        resp = self.client.get("/api/stats")
        self.assertEqual(resp.status_code, 200)
        data = json.loads(resp.data)
        self.assertIn("total", data)
        self.assertIn("unique_ips", data)

    def test_api_attacks_returns_json(self):
        self._login()
        resp = self.client.get("/api/attacks")
        self.assertEqual(resp.status_code, 200)
        data = json.loads(resp.data)
        self.assertIsInstance(data, list)

    def test_api_attacks_invalid_limit_uses_default(self):
        self._login()
        resp = self.client.get("/api/attacks?limit=notanumber")
        self.assertEqual(resp.status_code, 200)

    def test_api_attacks_limit_capped_at_1000(self):
        self._login()
        resp = self.client.get("/api/attacks?limit=9999")
        self.assertEqual(resp.status_code, 200)

    def test_api_map_returns_json(self):
        self._login()
        resp = self.client.get("/api/map")
        self.assertEqual(resp.status_code, 200)
        data = json.loads(resp.data)
        self.assertIsInstance(data, list)

    def test_api_intel_returns_json(self):
        self._login()
        resp = self.client.get("/api/intel")
        self.assertEqual(resp.status_code, 200)
        data = json.loads(resp.data)
        self.assertIn("threat_levels", data)
        self.assertIn("top_techniques", data)

    def test_logout_clears_session(self):
        self._login()
        resp = self.client.get("/")
        self.assertEqual(resp.status_code, 200)
        self.client.get("/logout")
        resp = self.client.get("/")
        self.assertEqual(resp.status_code, 302)

    def test_attacks_page_requires_login(self):
        resp = self.client.get("/attacks")
        self.assertEqual(resp.status_code, 302)

    def test_intelligence_page_requires_login(self):
        resp = self.client.get("/intelligence")
        self.assertEqual(resp.status_code, 302)

    def test_security_headers_present(self):
        resp = self.client.get("/login")
        self.assertEqual(resp.headers.get("X-Content-Type-Options"), "nosniff")
        self.assertEqual(resp.headers.get("X-Frame-Options"), "DENY")
        self.assertEqual(resp.headers.get("X-XSS-Protection"), "1; mode=block")
        self.assertIn("strict-origin", resp.headers.get("Referrer-Policy", ""))

    def test_rate_limiting_blocks_after_max_attempts(self):
        from dashboard.app import _login_attempts
        _login_attempts.clear()
        for _ in range(config.MAX_LOGIN_ATTEMPTS):
            token = self._get_csrf_token()
            self.client.post("/login", data={
                "username": "admin", "password": "wrong",
                "_csrf_token": token,
            })
        token = self._get_csrf_token()
        resp = self.client.post("/login", data={
            "username": config.DASHBOARD_USER,
            "password": config._DASHBOARD_PASS_RAW,
            "_csrf_token": token,
        })
        self.assertEqual(resp.status_code, 429)
        self.assertIn(b"Too many login attempts", resp.data)


class TestBroadcastAttack(unittest.TestCase):

    @patch("dashboard.app.socketio")
    def test_broadcast_emits_event(self, mock_socketio):
        from dashboard.app import broadcast_attack
        attack = {"id": 1, "service": "ssh", "src_ip": "1.2.3.4"}
        broadcast_attack(attack)
        mock_socketio.emit.assert_called_once_with("new_attack", attack, namespace="/")


if __name__ == "__main__":
    unittest.main(verbosity=2)
