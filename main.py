import os
import sys
import logging
import threading
import signal

from config import (
    DASHBOARD_HOST, DASHBOARD_PORT,
    SSH_PORT, HTTP_PORT, FTP_PORT, LOG_LEVEL, LOG_FILE,
)
from database.models import init_db, migrate_db, get_recent_attacks
from ml.detector import get_detector

os.makedirs("data", exist_ok=True)

logging.basicConfig(
    level=getattr(logging, LOG_LEVEL.upper(), logging.INFO),
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    handlers=[
        logging.StreamHandler(sys.stdout),
        logging.FileHandler(LOG_FILE, encoding="utf-8"),
    ],
)
logger = logging.getLogger("honeypot.main")

stop_event = threading.Event()

def _handle_signal(signum, frame):
    logger.info("Shutdown signal received. Stopping…")
    stop_event.set()


signal.signal(signal.SIGINT,  _handle_signal)
signal.signal(signal.SIGTERM, _handle_signal)

from honeypot import ssh_honeypot, http_honeypot, ftp_honeypot
from dashboard.app import run as run_dashboard

def _bootstrap_ml() -> None:
    detector = get_detector()
    if detector.load():
        return
    attacks = get_recent_attacks(limit=5000)
    if attacks:
        detector.train(attacks)
    else:
        logger.info("No existing attacks — anomaly detector will train once data is collected.")

def main():
    logger.info("=" * 60)
    logger.info("  HoneyShield v2.0 starting up")
    logger.info(f"  SSH  honeypot  -> :{SSH_PORT}")
    logger.info(f"  HTTP honeypot  -> :{HTTP_PORT}")
    logger.info(f"  FTP  honeypot  -> :{FTP_PORT}")
    logger.info(f"  Dashboard      -> http://localhost:{DASHBOARD_PORT}")
    logger.info("=" * 60)

    init_db()
    migrate_db()
    logger.info("Database initialised and migrated.")

    _bootstrap_ml()
    logger.info("ML anomaly detector ready.")

    threads = [
        threading.Thread(
            target=ssh_honeypot.start,
            args=(stop_event,),
            name="ssh-honeypot",
            daemon=True,
        ),
        threading.Thread(
            target=http_honeypot.start,
            args=(stop_event,),
            name="http-honeypot",
            daemon=True,
        ),
        threading.Thread(
            target=ftp_honeypot.start,
            args=(stop_event,),
            name="ftp-honeypot",
            daemon=True,
        ),
    ]

    for t in threads:
        t.start()
        logger.info("Started thread: %s", t.name)

    try:
        run_dashboard(
            host=DASHBOARD_HOST,
            port=DASHBOARD_PORT,
            debug=False,
        )
    except KeyboardInterrupt:
        stop_event.set()

    for t in threads:
        t.join(timeout=5)
    logger.info("HoneyShield stopped.")

if __name__ == "__main__":
    main()
