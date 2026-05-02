import json
import os
import sys
import socket
import logging
import threading

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from config import BIND_HOST, FTP_PORT
from database.models import insert_attack
from geoip.locator import lookup
from alerts.notifier import dispatch
from intelligence.mitre import tag_attack, tags_to_dicts
from ml.detector import get_detector
from dashboard.app import broadcast_attack

logger = logging.getLogger(__name__)

_BANNER        = b"220 (vsFTPd 3.0.5)\r\n"
_READY         = b"331 Please specify the password.\r\n"
_LOGIN_FAILED  = b"530 Login incorrect.\r\n"
_GOODBYE       = b"221 Goodbye.\r\n"
_UNKNOWN_CMD   = b"500 Unknown command.\r\n"
_SYST_RESP     = b"215 UNIX Type: L8\r\n"
_FEAT_RESP     = b"211-Features:\r\n UTF8\r\n211 End\r\n"

def _handle_client(conn: socket.socket, addr: tuple) -> None:
    client_ip, client_port = addr
    username: str = ""

    try:
        conn.settimeout(30)
        conn.sendall(_BANNER)

        while True:
            try:
                raw = conn.recv(1024)
            except (socket.timeout, ConnectionResetError):
                break
            if not raw:
                break

            line = raw.decode("utf-8", errors="replace").strip()
            if not line:
                continue

            cmd = line[:4].upper().strip()
            arg = line[4:].strip() if len(line) > 4 else ""

            if cmd == "USER":
                username = arg
                conn.sendall(_READY)

            elif cmd == "PASS":
                password = arg
                logger.info("[FTP] %s → user=%s pass=%s", client_ip, username, password)

                geo    = lookup(client_ip)
                attack = {
                    "service":  "ftp",
                    "src_ip":   client_ip,
                    "src_port": client_port,
                    "username": username,
                    "password": password,
                    **geo,
                }
                mitre_tags   = tags_to_dicts(tag_attack(attack))
                ml_result    = get_detector().predict(attack)
                attack["mitre_tags"]    = json.dumps([t["id"] for t in mitre_tags])
                attack["anomaly_score"] = ml_result["score"]
                attack["threat_level"]  = "high" if ml_result["is_anomaly"] else "low"
                attack_id = insert_attack(attack)
                attack["id"] = attack_id
                dispatch(attack)
                broadcast_attack(attack)

                conn.sendall(_LOGIN_FAILED)
                username = ""

            elif cmd == "QUIT":
                conn.sendall(_GOODBYE)
                break

            elif cmd == "SYST":
                conn.sendall(_SYST_RESP)

            elif cmd == "FEAT":
                conn.sendall(_FEAT_RESP)

            elif cmd in ("NOOP", "TYPE"):
                conn.sendall(b"200 OK\r\n")

            else:
                conn.sendall(_UNKNOWN_CMD)

    except Exception as exc:
        logger.debug("[FTP] session error from %s: %s", client_ip, exc)
    finally:
        try:
            conn.close()
        except Exception:
            pass

def start(stop_event: threading.Event | None = None) -> None:
    server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server_sock.bind((BIND_HOST, FTP_PORT))
    server_sock.listen(128)
    server_sock.settimeout(1.0)
    logger.info("[FTP] Honeypot listening on %s:%d", BIND_HOST, FTP_PORT)

    while not (stop_event and stop_event.is_set()):
        try:
            conn, addr = server_sock.accept()
            t = threading.Thread(
                target=_handle_client,
                args=(conn, addr),
                daemon=True,
            )
            t.start()
        except socket.timeout:
            continue
        except Exception as exc:
            logger.error("[FTP] accept error: %s", exc)
            break

    server_sock.close()
    logger.info("[FTP] Honeypot stopped.")
