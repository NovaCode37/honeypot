import os
import sys
import json
import logging
import threading
import re
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import urlparse, parse_qs

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from config import HTTP_PORT, BIND_HOST
from database.models import insert_attack
from geoip.locator import lookup
from alerts.notifier import dispatch
from intelligence.mitre import tag_attack, tags_to_dicts
from intelligence.reputation import score_ip, score_to_level
from ml.detector import get_detector
from dashboard.app import broadcast_attack

logger = logging.getLogger(__name__)

_SQLI_RE  = re.compile(r"(union\s+select|select\s+\*|drop\s+table|--|;--)", re.I)
_SHELL_RE = re.compile(r"(\$\{jndi:|;wget |;curl |/bin/sh|/bin/bash)", re.I)
_XSS_RE   = re.compile(r"(<script|onerror\s*=|onload\s*=|javascript:|alert\s*\()", re.I)
_FAKE_POWERED_BY = "PHP/7.4.33"


def _classify_payload(path: str, body: str, headers: dict) -> str:
    combined = path + body + " ".join(headers.values())
    if _SQLI_RE.search(combined):
        return "sql_injection"
    if _SHELL_RE.search(combined):
        return "rce_attempt"
    if _XSS_RE.search(combined):
        return "xss_attempt"
    if "/.env" in path or "/wp-config" in path:
        return "config_leak"
    if "/wp-login" in path or "/xmlrpc.php" in path:
        return "wordpress_brute"
    if "/phpmyadmin" in path.lower() or "/pma" in path.lower():
        return "phpmyadmin_probe"
    if "/cgi-bin" in path:
        return "cgi_exploit"
    return "scan"

class _HoneypotHTTPHandler(BaseHTTPRequestHandler):
    server_version  = "Apache/2.4.57"
    sys_version     = ""

    def log_message(self, fmt, *args):
        pass

    def _record(self, method: str, body: str = "") -> None:
        client_ip   = self.client_address[0]
        client_port = self.client_address[1]
        ua          = self.headers.get("User-Agent", "")
        path        = self.path

        payload_type = _classify_payload(
            path, body,
            {k: v for k, v in self.headers.items()},
        )

        geo = lookup(client_ip)
        attack = {
            "service":    "http",
            "src_ip":     client_ip,
            "src_port":   client_port,
            "user_agent": ua,
            "method":     method,
            "path":       path,
            "payload":    f"{payload_type}: {body[:500]}" if body else payload_type,
            **geo,
        }
        mitre_tags   = tags_to_dicts(tag_attack(attack))
        ml_result    = get_detector().predict(attack)
        attack["mitre_tags"]    = json.dumps([t["id"] for t in mitre_tags])
        attack["anomaly_score"] = ml_result["score"]
        attack["threat_level"]  = "critical" if ml_result["is_anomaly"] else "medium"
        logger.info("[HTTP] %s %s %s (%s)", client_ip, method, path, payload_type)
        attack_id = insert_attack(attack)
        attack["id"] = attack_id
        dispatch(attack)
        broadcast_attack(attack)

    def _fake_response(self, code: int, body: bytes, content_type: str = "text/html") -> None:
        self.send_response(code)
        self.send_header("Content-Type",   content_type)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("X-Powered-By",   _FAKE_POWERED_BY)
        self.send_header("Server",         "Apache/2.4.57 (Ubuntu)")
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        self._record("GET")
        path_lower = self.path.lower()
        if "/wp-login" in path_lower:
            self._fake_response(200, _WP_LOGIN_PAGE)
        elif "/.env" in path_lower:
            self._fake_response(200, _FAKE_ENV, "text/plain")
        elif "/phpmyadmin" in path_lower or "/pma" in path_lower:
            self._fake_response(200, _PMA_PAGE)
        else:
            self._fake_response(200, _INDEX_PAGE)

    def do_POST(self):
        _MAX_BODY = 1_048_576  # 1 MB
        length = min(int(self.headers.get("Content-Length", 0)), _MAX_BODY)
        body   = self.rfile.read(length).decode("utf-8", errors="replace")
        self._record("POST", body)
        path_lower = self.path.lower()
        if "/wp-login" in path_lower:
            self._fake_response(302, b"", "text/html")
        else:
            self._fake_response(200, _INDEX_PAGE)

    def do_HEAD(self):
        self._record("HEAD")
        self._fake_response(200, b"")


_INDEX_PAGE = b"""<!DOCTYPE html>
<html><head><title>Apache2 Ubuntu Default Page</title></head>
<body><h1>Apache2 Ubuntu Default Page</h1>
<p>It works!</p></body></html>"""

_WP_LOGIN_PAGE = b"""<!DOCTYPE html>
<html><head><title>Log In &lsaquo; WordPress</title></head>
<body id="login">
<form name="loginform" id="loginform" action="/wp-login.php" method="post">
<p><label>Username or Email Address<input type="text" name="log" /></label></p>
<p><label>Password<input type="password" name="pwd" /></label></p>
<input type="submit" name="wp-submit" value="Log In" />
</form></body></html>"""

_FAKE_ENV = b"""APP_ENV=production
DB_HOST=127.0.0.1
DB_DATABASE=wordpress
DB_USERNAME=wp_user
DB_PASSWORD=super_secret_db_pass_1337
SECRET_KEY=fake-secret-key-honeypot
AWS_ACCESS_KEY_ID=AKIAFAKEACCESSKEY000
AWS_SECRET_ACCESS_KEY=FakeSecretKey/HONEYPOT/DoNotUse+1234567890"""

_PMA_PAGE = b"""<!DOCTYPE html><html><head><title>phpMyAdmin</title></head>
<body><h1>phpMyAdmin</h1>
<form method="post">
<input name="pma_username" /><input name="pma_password" type="password" />
<input type="submit" value="Go" /></form></body></html>"""

def start(stop_event: threading.Event | None = None) -> None:
    httpd = HTTPServer((BIND_HOST, HTTP_PORT), _HoneypotHTTPHandler)
    httpd.timeout = 1.0
    logger.info("[HTTP] Honeypot listening on %s:%d", BIND_HOST, HTTP_PORT)
    while not (stop_event and stop_event.is_set()):
        httpd.handle_request()
    httpd.server_close()
    logger.info("[HTTP] Honeypot stopped.")
