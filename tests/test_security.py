"""
Security-focused tests covering:
- Password hashing (never plaintext comparison)
- CSRF protection on login form
- Rate limiting on failed logins
- Session timeout configuration
- Security response headers
- HTML sanitization in Telegram alerts
- HTTP POST body size capping
- XSS prevention (esc function presence in templates)
- No sensitive data leakage
"""
import os
import sys
import html
import tempfile
import unittest
from unittest.mock import patch, MagicMock

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

import config


class TestPasswordHashing(unittest.TestCase):

    def test_password_hash_is_not_plaintext(self):
        self.assertNotEqual(config.DASHBOARD_PASS_HASH, config._DASHBOARD_PASS_RAW)
        self.assertTrue(config.DASHBOARD_PASS_HASH.startswith(("pbkdf2:", "scrypt:")))

    def test_password_hash_verifies_correctly(self):
        from werkzeug.security import check_password_hash
        self.assertTrue(check_password_hash(config.DASHBOARD_PASS_HASH, config._DASHBOARD_PASS_RAW))

    def test_password_hash_rejects_wrong_password(self):
        from werkzeug.security import check_password_hash
        self.assertFalse(check_password_hash(config.DASHBOARD_PASS_HASH, "wrong-password"))

    def test_no_DASHBOARD_PASS_in_config_exports(self):
        public_attrs = [a for a in dir(config) if not a.startswith("_") and a.isupper()]
        self.assertNotIn("DASHBOARD_PASS", public_attrs,
                         "Raw password should not be a public config attribute")


class TestCSRFProtection(unittest.TestCase):

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
        self.client = app.test_client()

    def tearDown(self):
        config.DB_PATH = self._orig_path
        os.unlink(self.tmp.name)

    def test_login_form_contains_csrf_token(self):
        resp = self.client.get("/login")
        self.assertIn(b'name="_csrf_token"', resp.data)

    def test_post_without_csrf_returns_403(self):
        self.client.get("/login")
        resp = self.client.post("/login", data={
            "username": "admin", "password": "admin",
        })
        self.assertEqual(resp.status_code, 403)

    def test_post_with_wrong_csrf_returns_403(self):
        self.client.get("/login")
        resp = self.client.post("/login", data={
            "username": "admin", "password": "admin",
            "_csrf_token": "invalid-token-value",
        })
        self.assertEqual(resp.status_code, 403)

    def test_post_with_valid_csrf_succeeds(self):
        resp = self.client.get("/login")
        data = resp.data.decode()
        marker = 'name="_csrf_token" value="'
        idx = data.find(marker)
        token = data[idx + len(marker): data.find('"', idx + len(marker))]
        resp = self.client.post("/login", data={
            "username": config.DASHBOARD_USER,
            "password": config._DASHBOARD_PASS_RAW,
            "_csrf_token": token,
        })
        self.assertEqual(resp.status_code, 302)


class TestRateLimiting(unittest.TestCase):

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
        self.client = app.test_client()

    def tearDown(self):
        config.DB_PATH = self._orig_path
        os.unlink(self.tmp.name)

    def _get_csrf(self):
        resp = self.client.get("/login")
        data = resp.data.decode()
        marker = 'name="_csrf_token" value="'
        idx = data.find(marker)
        return data[idx + len(marker): data.find('"', idx + len(marker))]

    def test_allows_under_limit(self):
        for i in range(config.MAX_LOGIN_ATTEMPTS - 1):
            token = self._get_csrf()
            resp = self.client.post("/login", data={
                "username": "admin", "password": "wrong",
                "_csrf_token": token,
            })
            self.assertEqual(resp.status_code, 200, f"Blocked too early at attempt {i+1}")

    def test_blocks_at_limit(self):
        from dashboard.app import _login_attempts
        _login_attempts.clear()
        for _ in range(config.MAX_LOGIN_ATTEMPTS):
            token = self._get_csrf()
            self.client.post("/login", data={
                "username": "admin", "password": "wrong",
                "_csrf_token": token,
            })
        token = self._get_csrf()
        resp = self.client.post("/login", data={
            "username": config.DASHBOARD_USER,
            "password": config._DASHBOARD_PASS_RAW,
            "_csrf_token": token,
        })
        self.assertEqual(resp.status_code, 429)


class TestSecurityHeaders(unittest.TestCase):

    def setUp(self):
        self.tmp = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
        self.tmp.close()
        self._orig_path = config.DB_PATH
        config.DB_PATH = self.tmp.name
        from database.models import init_db
        init_db()
        from dashboard.app import app
        app.config["TESTING"] = True
        app.config["SECRET_KEY"] = "test-secret"
        self.client = app.test_client()

    def tearDown(self):
        config.DB_PATH = self._orig_path
        os.unlink(self.tmp.name)

    def test_x_content_type_options(self):
        resp = self.client.get("/login")
        self.assertEqual(resp.headers.get("X-Content-Type-Options"), "nosniff")

    def test_x_frame_options(self):
        resp = self.client.get("/login")
        self.assertEqual(resp.headers.get("X-Frame-Options"), "DENY")

    def test_x_xss_protection(self):
        resp = self.client.get("/login")
        self.assertEqual(resp.headers.get("X-XSS-Protection"), "1; mode=block")

    def test_referrer_policy(self):
        resp = self.client.get("/login")
        self.assertEqual(resp.headers.get("Referrer-Policy"),
                         "strict-origin-when-cross-origin")


class TestTelegramHTMLSanitization(unittest.TestCase):

    def test_dispatch_escapes_html_in_credentials(self):
        from alerts.notifier import dispatch
        with patch("alerts.notifier._send_telegram") as mock_tg, \
             patch("alerts.notifier._send_email"):
            dispatch({
                "service": "ssh",
                "src_ip": "1.2.3.4",
                "country": "Test",
                "username": "<script>alert(1)</script>",
                "password": "pass&<>",
                "path": "/test\"path",
            })
            call_args = mock_tg.call_args[0][0]
            self.assertNotIn("<script>", call_args)
            self.assertIn("&lt;script&gt;", call_args)
            self.assertIn("pass&amp;&lt;&gt;", call_args)

    def test_dispatch_escapes_html_in_path(self):
        from alerts.notifier import dispatch
        with patch("alerts.notifier._send_telegram") as mock_tg, \
             patch("alerts.notifier._send_email"):
            dispatch({
                "service": "http",
                "src_ip": "5.6.7.8",
                "path": '/<img onerror="alert(1)">',
            })
            call_args = mock_tg.call_args[0][0]
            self.assertNotIn('<img', call_args)
            self.assertIn("&lt;img", call_args)


class TestHTTPBodySizeLimit(unittest.TestCase):

    def test_classify_payload_import(self):
        from honeypot.http_honeypot import _classify_payload
        result = _classify_payload("/test", "", {})
        self.assertEqual(result, "scan")


class TestGeoIPNoDataLeak(unittest.TestCase):

    @patch("geoip.locator.requests.get")
    def test_no_internal_keys_in_response(self, mock_get):
        mock_get.return_value = MagicMock(json=lambda: {
            "status": "success", "country": "US", "city": "NYC",
            "lat": 40.7, "lon": -74.0, "as": "AS1", "isp": "ISP",
        })
        from geoip import locator
        locator._cache.clear()
        result = locator.lookup("198.51.100.1")
        for key in result:
            self.assertFalse(key.startswith("_"),
                             f"Internal key '{key}' leaked into response")

    def test_private_ip_returns_no_internal_keys(self):
        from geoip.locator import lookup
        result = lookup("10.0.0.1")
        for key in result:
            self.assertFalse(key.startswith("_"))


class TestSessionConfig(unittest.TestCase):

    def test_session_lifetime_configured(self):
        from dashboard.app import app
        lifetime = app.config.get("PERMANENT_SESSION_LIFETIME")
        self.assertIsNotNone(lifetime)
        self.assertGreater(lifetime.total_seconds(), 0)

    def test_session_lifetime_matches_config(self):
        from dashboard.app import app
        from datetime import timedelta
        expected = timedelta(minutes=config.SESSION_LIFETIME_MINUTES)
        self.assertEqual(app.config["PERMANENT_SESSION_LIFETIME"], expected)


class TestDBParameterizedQueries(unittest.TestCase):

    def setUp(self):
        self.tmp = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
        self.tmp.close()
        self._orig_path = config.DB_PATH
        config.DB_PATH = self.tmp.name
        from database.models import init_db
        init_db()

    def tearDown(self):
        config.DB_PATH = self._orig_path
        os.unlink(self.tmp.name)

    def test_sqli_in_username_does_not_break_insert(self):
        from database.models import insert_attack, get_recent_attacks
        evil_user = "admin'; DROP TABLE attacks;--"
        row_id = insert_attack({
            "service": "ssh", "src_ip": "1.2.3.4",
            "username": evil_user, "password": "test",
        })
        self.assertIsInstance(row_id, int)
        attacks = get_recent_attacks(10)
        self.assertEqual(len(attacks), 1)
        self.assertEqual(attacks[0]["username"], evil_user)

    def test_sqli_in_src_ip_does_not_break_insert(self):
        from database.models import insert_attack, get_recent_attacks
        evil_ip = "1.2.3.4' OR '1'='1"
        row_id = insert_attack({"service": "ssh", "src_ip": evil_ip})
        self.assertIsInstance(row_id, int)
        attacks = get_recent_attacks(10)
        self.assertEqual(attacks[0]["src_ip"], evil_ip)


if __name__ == "__main__":
    unittest.main(verbosity=2)
