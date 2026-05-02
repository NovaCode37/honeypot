import os
import json
import pickle
import logging
import hashlib
from datetime import datetime
from typing import Optional

import numpy as np

logger = logging.getLogger(__name__)

_MODEL_PATH = os.path.join(os.path.dirname(__file__), "..", "data", "anomaly_model.pkl")

_DEFAULT_USERNAMES = {"root", "admin", "pi", "ubuntu", "test", "guest", "user", "oracle"}
_DEFAULT_PASSWORDS = {
    "123456", "password", "admin", "root", "raspberry", "1234",
    "12345678", "pass", "test", "guest", "letmein", "qwerty",
}
_EXPLOIT_CHARS = set("'\";<>(){}|&$`\\")


def _extract_features(attack: dict) -> list[float]:
    ts = attack.get("timestamp", "")
    try:
        hour = datetime.fromisoformat(ts).hour
    except Exception:
        hour = 12

    svc_map = {"ssh": 0, "http": 1, "ftp": 2}
    service_id = svc_map.get(attack.get("service", "ssh"), 0)

    username = (attack.get("username") or "").lower()
    password = (attack.get("password") or "").lower()
    payload  = (attack.get("payload") or "")
    path     = (attack.get("path") or "")

    is_default_cred = int(
        username in _DEFAULT_USERNAMES or password in _DEFAULT_PASSWORDS
    )

    payload_len = min(len(payload), 1000)

    path_depth = path.count("/") if path else 0

    has_special = int(bool(set(payload + path) & _EXPLOIT_CHARS))

    hour_sin = float(np.sin(2 * np.pi * hour / 24))
    hour_cos = float(np.cos(2 * np.pi * hour / 24))

    return [
        hour_sin,
        hour_cos,
        float(service_id),
        float(is_default_cred),
        float(payload_len) / 1000.0,
        float(path_depth) / 10.0,
        float(has_special),
    ]

class AnomalyDetector:

    CONTAMINATION = 0.05

    def __init__(self):
        self._model = None
        self._trained = False

    def train(self, attacks: list[dict]) -> None:
        try:
            from sklearn.ensemble import IsolationForest
        except ImportError:
            logger.warning("scikit-learn not installed — anomaly detection disabled")
            return

        if len(attacks) < 20:
            logger.info("Not enough data to train anomaly detector (%d records)", len(attacks))
            return

        X = np.array([_extract_features(a) for a in attacks], dtype=np.float32)
        self._model = IsolationForest(
            contamination=self.CONTAMINATION,
            n_estimators=100,
            random_state=42,
            n_jobs=-1,
        )
        self._model.fit(X)
        self._trained = True
        logger.info("Anomaly detector trained on %d samples", len(X))
        self._save()

    def predict(self, attack: dict) -> dict:
        if not self._trained or self._model is None:
            return {"score": 0.0, "is_anomaly": False, "explanation": "Model not trained"}

        x = np.array([_extract_features(attack)], dtype=np.float32)
        score = float(self._model.score_samples(x)[0])
        prediction = self._model.predict(x)[0]
        is_anomaly = bool(prediction == -1)

        explanation = self._explain(attack, score, is_anomaly)
        return {"score": round(score, 4), "is_anomaly": is_anomaly, "explanation": explanation}

    def _explain(self, attack: dict, score: float, is_anomaly: bool) -> str:
        if not is_anomaly:
            return "Normal pattern"

        reasons = []
        payload = (attack.get("payload") or "")
        path    = (attack.get("path") or "")

        if len(payload) > 200:
            reasons.append("unusually long payload")
        if set(payload + path) & _EXPLOIT_CHARS:
            reasons.append("exploit characters detected")
        ts = attack.get("timestamp", "")
        try:
            hour = datetime.fromisoformat(ts).hour
            if hour < 4 or hour > 22:
                reasons.append(f"off-hours attack ({hour}:00)")
        except Exception:
            pass
        if path.count("/") > 5:
            reasons.append("deep path traversal attempt")

        return "Anomaly: " + ("; ".join(reasons) if reasons else "unusual feature combination")

    def _save(self) -> None:
        os.makedirs(os.path.dirname(_MODEL_PATH), exist_ok=True)
        try:
            with open(_MODEL_PATH, "wb") as f:
                pickle.dump(self._model, f)
            logger.info("Anomaly model saved to %s", _MODEL_PATH)
        except Exception as exc:
            logger.warning("Could not save anomaly model: %s", exc)

    def load(self) -> bool:
        if not os.path.exists(_MODEL_PATH):
            return False
        try:
            with open(_MODEL_PATH, "rb") as f:
                self._model = pickle.load(f)
            self._trained = True
            logger.info("Anomaly model loaded from %s", _MODEL_PATH)
            return True
        except Exception as exc:
            logger.warning("Could not load anomaly model: %s", exc)
            return False


_detector = AnomalyDetector()

def get_detector() -> AnomalyDetector:
    return _detector
