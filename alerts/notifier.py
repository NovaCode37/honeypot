import html
import smtplib
import logging
import requests
from email.mime.text import MIMEText
from config import (
    TELEGRAM_TOKEN, TELEGRAM_CHAT_ID,
    ALERT_EMAIL_TO, SMTP_HOST, SMTP_PORT, SMTP_USER, SMTP_PASS,
)

logger = logging.getLogger(__name__)


def _send_telegram(message: str) -> None:
    if not TELEGRAM_TOKEN or not TELEGRAM_CHAT_ID:
        return
    try:
        requests.post(
            f"https://api.telegram.org/bot{TELEGRAM_TOKEN}/sendMessage",
            json={"chat_id": TELEGRAM_CHAT_ID, "text": message, "parse_mode": "HTML"},
            timeout=5,
        )
    except Exception as exc:
        logger.warning("Telegram alert failed: %s", exc)

def _send_email(subject: str, body: str) -> None:
    if not ALERT_EMAIL_TO or not SMTP_USER:
        return
    try:
        msg = MIMEText(body)
        msg["Subject"] = subject
        msg["From"]    = SMTP_USER
        msg["To"]      = ALERT_EMAIL_TO
        with smtplib.SMTP(SMTP_HOST, SMTP_PORT, timeout=10) as s:
            s.starttls()
            s.login(SMTP_USER, SMTP_PASS)
            s.send_message(msg)
    except Exception as exc:
        logger.warning("Email alert failed: %s", exc)

def dispatch(attack: dict) -> None:
    service  = html.escape(attack.get("service", "unknown").upper())
    src_ip   = html.escape(attack.get("src_ip", "?"))
    country  = html.escape(attack.get("country") or "Unknown")
    username = html.escape(attack.get("username") or "-")
    password = html.escape(attack.get("password") or "-")
    path     = html.escape(attack.get("path") or "-")

    msg = (
        f"🚨 <b>HoneyShield Alert</b>\n"
        f"Service : <code>{service}</code>\n"
        f"IP      : <code>{src_ip}</code> ({country})\n"
        f"User    : <code>{username}</code>\n"
        f"Pass    : <code>{password}</code>\n"
        f"Path    : <code>{path}</code>"
    )
    _send_telegram(msg)

    plain = (
        f"HoneyShield Alert\n"
        f"Service : {service}\n"
        f"IP      : {src_ip} ({country})\n"
        f"User    : {username}\n"
        f"Pass    : {password}\n"
        f"Path    : {path}\n"
    )
    _send_email(f"[HoneyShield] New {service} attack from {src_ip}", plain)
