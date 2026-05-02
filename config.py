import os
import logging
import warnings
from dotenv import load_dotenv
from werkzeug.security import generate_password_hash

load_dotenv()

_logger = logging.getLogger(__name__)

SSH_PORT      = int(os.getenv("SSH_PORT",  2222))
HTTP_PORT     = int(os.getenv("HTTP_PORT", 8080))
FTP_PORT      = int(os.getenv("FTP_PORT",  2121))
BIND_HOST     = os.getenv("BIND_HOST", "0.0.0.0")

DASHBOARD_HOST   = os.getenv("DASHBOARD_HOST", "0.0.0.0")
DASHBOARD_PORT   = int(os.getenv("DASHBOARD_PORT", 5000))
SECRET_KEY       = os.getenv("SECRET_KEY", "change-me-in-production-42xZ!")
DASHBOARD_USER   = os.getenv("DASHBOARD_USER", "admin")
_DASHBOARD_PASS_RAW = os.getenv("DASHBOARD_PASS", "admin")
DASHBOARD_PASS_HASH = generate_password_hash(_DASHBOARD_PASS_RAW)

SESSION_LIFETIME_MINUTES = int(os.getenv("SESSION_LIFETIME_MINUTES", 60))

MAX_LOGIN_ATTEMPTS = int(os.getenv("MAX_LOGIN_ATTEMPTS", 5))
LOGIN_BLOCK_SECONDS = int(os.getenv("LOGIN_BLOCK_SECONDS", 300))

DB_PATH = os.getenv("DB_PATH", os.path.join("data", "honeypot.db"))

GEOIP_API_KEY = os.getenv("GEOIP_API_KEY", "")

TELEGRAM_TOKEN   = os.getenv("TELEGRAM_TOKEN", "")
TELEGRAM_CHAT_ID = os.getenv("TELEGRAM_CHAT_ID", "")
ALERT_EMAIL_TO   = os.getenv("ALERT_EMAIL_TO", "")
SMTP_HOST        = os.getenv("SMTP_HOST", "smtp.gmail.com")
SMTP_PORT        = int(os.getenv("SMTP_PORT", 587))
SMTP_USER        = os.getenv("SMTP_USER", "")
SMTP_PASS        = os.getenv("SMTP_PASS", "")

SSH_KEY_PATH = os.getenv("SSH_KEY_PATH", "data/server.key")

LOG_LEVEL = os.getenv("LOG_LEVEL", "INFO")
LOG_FILE  = os.getenv("LOG_FILE",  "data/honeypot.log")
