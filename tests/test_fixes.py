import os
import sys
import tempfile
import unittest
from unittest.mock import patch, MagicMock

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

import config


class TestGeoIPNoTsLeak(unittest.TestCase):

    @patch("geoip.locator.requests.get")
    def test_lookup_result_has_no_ts_key(self, mock_get):
        mock_get.return_value = MagicMock(json=lambda: {
            "status": "success",
            "country": "Germany",
            "city": "Berlin",
            "lat": 52.52,
            "lon": 13.40,
            "as": "AS1234",
            "isp": "Test ISP",
        })
        from geoip import locator
        locator._cache.clear()
        result = locator.lookup("203.0.113.1")
        self.assertNotIn("_ts", result)
        self.assertEqual(result["country"], "Germany")

    @patch("geoip.locator.requests.get", side_effect=Exception("timeout"))
    def test_lookup_failure_has_no_ts_key(self, _):
        from geoip import locator
        locator._cache.clear()
        result = locator.lookup("203.0.113.2")
        self.assertNotIn("_ts", result)
        self.assertIsNone(result["country"])

    @patch("geoip.locator.requests.get")
    def test_lookup_cache_hit_has_no_ts_key(self, mock_get):
        mock_get.return_value = MagicMock(json=lambda: {
            "status": "success",
            "country": "France",
            "city": "Paris",
            "lat": 48.85,
            "lon": 2.35,
            "as": "AS5678",
            "isp": "Test",
        })
        from geoip import locator
        locator._cache.clear()
        locator.lookup("203.0.113.3")
        result = locator.lookup("203.0.113.3")
        self.assertNotIn("_ts", result)
        self.assertEqual(result["country"], "France")


class TestDBConnectionSafety(unittest.TestCase):

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

    def test_insert_attack_returns_int(self):
        from database.models import insert_attack
        row_id = insert_attack({
            "service": "ssh", "src_ip": "1.2.3.4",
            "username": "root", "password": "123",
        })
        self.assertIsInstance(row_id, int)
        self.assertGreater(row_id, 0)

    def test_get_intel_summary_returns_all_keys(self):
        from database.models import insert_attack, get_intel_summary
        insert_attack({
            "service": "ssh", "src_ip": "1.2.3.4",
            "mitre_tags": '["T1110.001"]',
            "anomaly_score": -0.5,
            "threat_level": "high",
            "password": "pass123",
        })
        summary = get_intel_summary()
        self.assertIn("threat_levels", summary)
        self.assertIn("anomalies", summary)
        self.assertIn("top_techniques", summary)
        self.assertIn("campaigns", summary)

    def test_get_intel_summary_counts_techniques(self):
        from database.models import insert_attack, get_intel_summary
        for _ in range(3):
            insert_attack({
                "service": "ssh", "src_ip": "1.2.3.4",
                "mitre_tags": '["T1110.001", "T1046"]',
            })
        summary = get_intel_summary()
        tech_ids = {t["id"] for t in summary["top_techniques"]}
        self.assertIn("T1110.001", tech_ids)

    def test_migrate_db_is_idempotent(self):
        from database.models import migrate_db
        migrate_db()
        migrate_db()

    def test_get_stats_hourly_returns_list(self):
        from database.models import get_stats
        stats = get_stats()
        self.assertIsInstance(stats["hourly"], list)


class TestReputationScoringFix(unittest.TestCase):

    def _make_attacks(self, n, service="ssh", hour=14):
        from datetime import datetime, timedelta
        base = datetime(2024, 1, 15, hour, 0, 0)
        return [
            {
                "src_ip": "1.2.3.4",
                "service": service,
                "username": "root",
                "password": "123456",
                "payload": "",
                "timestamp": (base + timedelta(minutes=i)).isoformat(),
            }
            for i in range(n)
        ]

    def test_volume_scoring_monotonic(self):
        from intelligence.reputation import score_ip
        r10 = score_ip("1.2.3.4", self._make_attacks(10))
        r60 = score_ip("1.2.3.4", self._make_attacks(60))
        r250 = score_ip("1.2.3.4", self._make_attacks(250))
        self.assertGreater(r60["score"], r10["score"])
        self.assertGreater(r250["score"], r60["score"])

    def test_200_plus_scores_higher_than_50_plus(self):
        from intelligence.reputation import score_ip
        r50 = score_ip("1.2.3.4", self._make_attacks(55))
        r200 = score_ip("1.2.3.4", self._make_attacks(210))
        self.assertGreater(r200["score"], r50["score"])


class TestHTTPClassificationEdgeCases(unittest.TestCase):

    def _classify(self, path, body="", headers=None):
        from honeypot.http_honeypot import _classify_payload
        return _classify_payload(path, body, headers or {})

    def test_pma_case_insensitive(self):
        self.assertEqual(self._classify("/PMA/index.php"), "phpmyadmin_probe")

    def test_empty_path(self):
        result = self._classify("")
        self.assertEqual(result, "scan")

    def test_sqli_in_body(self):
        result = self._classify("/search", "id=1 UNION SELECT * FROM users", {})
        self.assertEqual(result, "sql_injection")

    def test_rce_in_header(self):
        result = self._classify("/", "", {"X-Forwarded-For": "${jndi:ldap://x}"})
        self.assertEqual(result, "rce_attempt")

    def test_xmlrpc_classified(self):
        self.assertEqual(self._classify("/xmlrpc.php"), "wordpress_brute")

    def test_git_probe(self):
        from intelligence.mitre import tag_attack
        attack = {"service": "http", "method": "GET", "path": "/.git/config", "payload": ""}
        tags = tag_attack(attack)
        ids = [t.id for t in tags]
        self.assertIn("T1083", ids)


class TestMitreEdgeCases(unittest.TestCase):

    def test_empty_attack(self):
        from intelligence.mitre import tag_attack
        tags = tag_attack({})
        self.assertTrue(len(tags) > 0)

    def test_long_user_agent_flagged(self):
        from intelligence.mitre import tag_attack
        attack = {
            "service": "http",
            "method": "GET",
            "path": "/",
            "user_agent": "A" * 250,
            "payload": "",
        }
        tags = tag_attack(attack)
        ids = [t.id for t in tags]
        self.assertIn("T1592", ids)

    def test_ssh_attack_always_tagged(self):
        from intelligence.mitre import tag_attack
        tags = tag_attack({"service": "ssh", "username": "x", "password": "y"})
        self.assertTrue(len(tags) >= 1)


class TestAnomalyDetectorEdgeCases(unittest.TestCase):

    def test_train_with_too_few_samples(self):
        from ml.detector import AnomalyDetector
        detector = AnomalyDetector()
        attacks = [{"service": "ssh", "timestamp": "2024-01-15T14:00:00"}] * 5
        detector.train(attacks)
        self.assertFalse(detector._trained)

    def test_predict_without_timestamp(self):
        from ml.detector import AnomalyDetector
        detector = AnomalyDetector()
        result = detector.predict({"service": "ssh"})
        self.assertIn("score", result)
        self.assertFalse(result["is_anomaly"])

    def test_feature_extraction_handles_none(self):
        from ml.detector import _extract_features
        features = _extract_features({})
        self.assertEqual(len(features), 7)
        self.assertIsInstance(features[0], float)


if __name__ == "__main__":
    unittest.main(verbosity=2)
