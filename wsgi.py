import os
import sys
import logging
import threading

sys.path.insert(0, os.path.dirname(__file__))

from config import SECRET_KEY

if SECRET_KEY == "change-me-in-production-42xZ!":
    logging.warning(
        "SECRET_KEY is set to the default value. "
        "Generate a strong random key: python -c \"import secrets; print(secrets.token_hex(32))\""
    )

from database.models import init_db, migrate_db, get_recent_attacks

os.makedirs("data", exist_ok=True)
init_db()
migrate_db()

from ml.detector import get_detector

detector = get_detector()
if not detector.load():
    attacks = get_recent_attacks(5000)
    if attacks:
        detector.train(attacks)

from honeypot import ssh_honeypot, http_honeypot, ftp_honeypot

_stop_event = threading.Event()

for _target, _name in [
    (ssh_honeypot.start, "ssh-honeypot"),
    (http_honeypot.start, "http-honeypot"),
    (ftp_honeypot.start, "ftp-honeypot"),
]:
    t = threading.Thread(target=_target, args=(_stop_event,), name=_name, daemon=True)
    t.start()

from dashboard.app import app, socketio
