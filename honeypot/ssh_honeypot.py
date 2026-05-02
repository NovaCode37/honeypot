import os
import socket
import logging
import threading
import json
import time

import paramiko

import sys
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from config import SSH_PORT, BIND_HOST, SSH_KEY_PATH
from database.models import insert_attack
from geoip.locator import lookup
from alerts.notifier import dispatch
from intelligence.mitre import tag_attack, tags_to_dicts
from intelligence.reputation import score_ip, score_to_level
from ml.detector import get_detector
from dashboard.app import broadcast_attack

logger = logging.getLogger(__name__)

_FAKE_BANNER = "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.6"


class _HoneypotServerInterface(paramiko.ServerInterface):
    def __init__(self, client_ip: str, client_port: int, transport):
        self.client_ip   = client_ip
        self.client_port = client_port
        self.transport   = transport
        self._session_started = False

    def check_channel_request(self, kind, chanid):
        if kind == "session":
            return paramiko.OPEN_SUCCEEDED
        return paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED

    def check_auth_password(self, username: str, password: str):
        logger.info("[SSH] %s → user=%s pass=%s", self.client_ip, username, password)
        geo = lookup(self.client_ip)
        attack = {
            "service":   "ssh",
            "src_ip":    self.client_ip,
            "src_port":  self.client_port,
            "username":  username,
            "password":  password,
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
        return paramiko.AUTH_FAILED

    def check_auth_publickey(self, username, key):
        return paramiko.AUTH_FAILED

    def get_allowed_auths(self, username):
        return "password"

    def check_channel_shell_request(self, channel):
        return True

    def check_channel_pty_request(self, channel, term, width, height,
                                   pixelwidth, pixelheight, modes):
        return True

def _load_or_create_host_key() -> paramiko.RSAKey:
    os.makedirs(os.path.dirname(SSH_KEY_PATH), exist_ok=True)
    if os.path.exists(SSH_KEY_PATH):
        return paramiko.RSAKey(filename=SSH_KEY_PATH)
    logger.info("Generating new RSA host key -> %s", SSH_KEY_PATH)
    key = paramiko.RSAKey.generate(2048)
    key.write_private_key_file(SSH_KEY_PATH)
    return key

def _handle_client(client_sock: socket.socket, addr: tuple, host_key) -> None:
    client_ip, client_port = addr
    transport = None
    try:
        transport = paramiko.Transport(client_sock)
        transport.local_version = _FAKE_BANNER
        transport.add_server_key(host_key)
        server = _HoneypotServerInterface(client_ip, client_port, transport)
        transport.start_server(server=server)
        chan = transport.accept(20)
        if chan:
            time.sleep(2)
            chan.send("Welcome to Ubuntu 22.04.3 LTS (GNU/Linux 5.15.0-88-generic x86_64)\r\n\r\n")
            time.sleep(2)
            chan.close()
    except Exception as exc:
        logger.debug("[SSH] session error from %s: %s", client_ip, exc)
    finally:
        if transport:
            try:
                transport.close()
            except Exception:
                pass
        try:
            client_sock.close()
        except Exception:
            pass

def start(stop_event: threading.Event | None = None) -> None:
    host_key = _load_or_create_host_key()
    server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server_sock.bind((BIND_HOST, SSH_PORT))
    server_sock.listen(128)
    server_sock.settimeout(1.0)
    logger.info("[SSH] Honeypot listening on %s:%d", BIND_HOST, SSH_PORT)

    while not (stop_event and stop_event.is_set()):
        try:
            client_sock, addr = server_sock.accept()
            t = threading.Thread(
                target=_handle_client,
                args=(client_sock, addr, host_key),
                daemon=True,
            )
            t.start()
        except socket.timeout:
            continue
        except Exception as exc:
            logger.error("[SSH] accept error: %s", exc)
            break

    server_sock.close()
    logger.info("[SSH] Honeypot stopped.")
