import json
import random
import sqlite3
import os
import sys
from datetime import datetime, timedelta

from database.models import init_db, migrate_db, get_conn

ATTACKER_IPS = [
    ("185.220.101.45",  "Russia",       "Moscow",      55.7558,  37.6173,  "AS60068",  "Selectel"),
    ("45.33.32.156",    "United States","Fremont",      37.5485, -121.9886, "AS63949",  "Linode"),
    ("103.21.244.0",    "China",        "Hangzhou",     30.2936, 120.1614,  "AS13335",  "Alibaba Cloud"),
    ("195.54.160.149",  "Netherlands",  "Amsterdam",    52.3740,   4.8897,  "AS16276",  "OVH SAS"),
    ("185.107.80.202",  "Germany",      "Frankfurt",    50.1109,   8.6821,  "AS24940",  "Hetzner Online"),
    ("91.108.56.130",   "Ukraine",      "Kyiv",         50.4501,  30.5234,  "AS47694",  "Triolan"),
    ("118.25.6.39",     "China",        "Shenzhen",     22.5431, 114.0579,  "AS132203", "Tencent Cloud"),
    ("162.55.36.1",     "Germany",      "Nuremberg",    49.4521,  11.0767,  "AS24940",  "Hetzner Online"),
    ("134.209.24.3",    "United States","San Francisco", 37.7749,-122.4194, "AS14061",  "DigitalOcean"),
    ("178.62.194.226",  "United Kingdom","London",       51.5074,  -0.1278, "AS14061",  "DigitalOcean"),
    ("51.254.25.115",   "France",       "Paris",        48.8566,   2.3522,  "AS16276",  "OVH SAS"),
    ("159.89.49.202",   "Singapore",    "Singapore",     1.3521, 103.8198,  "AS14061",  "DigitalOcean"),
    ("46.4.68.84",      "Germany",      "Falkenstein",  50.4779,  12.3713,  "AS24940",  "Hetzner Online"),
    ("89.248.167.131",  "Netherlands",  "Amsterdam",    52.3740,   4.8897,  "AS49981",  "WorldStream"),
    ("222.186.42.137",  "China",        "Nanjing",      32.0603, 118.7969,  "AS4134",   "ChinaNet"),
]

SSH_USERNAMES = [
    "root", "admin", "ubuntu", "pi", "user", "test", "oracle",
    "postgres", "mysql", "ftp", "git", "deploy", "jenkins", "hadoop",
    "support", "guest", "www-data", "ec2-user", "centos", "vagrant",
]

SSH_PASSWORDS = [
    "123456", "password", "admin", "root", "12345", "test",
    "1234", "pass", "qwerty", "abc123", "letmein", "monkey",
    "master", "changeme", "dragon", "baseball", "football",
    "shadow", "sunshine", "welcome", "P@ssw0rd", "Admin123",
    "raspberry", "toor", "alpine", "ubnt", "vizxv",
]

HTTP_PATHS = [
    "/wp-login.php", "/wp-admin/", "/.env", "/.git/config",
    "/phpmyadmin/", "/pma/", "/admin/", "/login",
    "/xmlrpc.php", "/wp-content/plugins/contact-form-7/",
    "/.aws/credentials", "/config.php", "/server-status",
    "/cgi-bin/../../etc/passwd", "/api/v1/users",
    "/actuator/env", "/console", "/.htaccess",
    "/backup.zip", "/shell.php", "/cmd.php",
    "/?s=%3Cscript%3Ealert(1)%3C/script%3E",
    "/?id=1'%20OR%201=1--",
]

HTTP_USER_AGENTS = [
    "Mozilla/5.0 (compatible; Googlebot/2.1)",
    "masscan/1.3 (https://github.com/robertdavidgraham/masscan)",
    "zgrab/0.x",
    "Go-http-client/1.1",
    "python-requests/2.28.2",
    "curl/7.88.1",
    "Nikto/2.1.6",
    "sqlmap/1.7 (https://sqlmap.org)",
    "WPScan v3.8.22 (https://wpscan.com/wordpress-security-scanner)",
    "Nuclei - Open-source project (github.com/projectdiscovery/nuclei)",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36",
]

HTTP_PAYLOADS = [
    "config_leak", "wordpress_brute", "sql_injection", "rce_attempt",
    "phpmyadmin_probe", "cgi_exploit", "scan", "wordpress_brute",
    "config_leak", "scan",
]

def _random_timestamp(days_back: int = 7) -> str:
    delta = timedelta(
        seconds=random.randint(0, days_back * 86400)
    )
    t = datetime.utcnow() - delta
    return t.strftime("%Y-%m-%d %H:%M:%S")


_MITRE_SSH   = json.dumps(["T1110.001"])
_MITRE_SSH_S = json.dumps(["T1110.001", "T1110.003"])
_MITRE_HTTP_RCE  = json.dumps(["T1059.004", "T1190"])
_MITRE_HTTP_SQLI = json.dumps(["T1190", "T1212"])
_MITRE_HTTP_CFG  = json.dumps(["T1083"])
_MITRE_HTTP_WP   = json.dumps(["T1110.003", "T1078"])
_MITRE_HTTP_PMA  = json.dumps(["T1133"])
_MITRE_HTTP_CGI  = json.dumps(["T1505.003", "T1190"])
_MITRE_HTTP_SCAN = json.dumps(["T1046", "T1595.001"])
_MITRE_FTP   = json.dumps(["T1133", "T1110.001"])

_PAYLOAD_MITRE = {
    "rce_attempt":       _MITRE_HTTP_RCE,
    "sql_injection":     _MITRE_HTTP_SQLI,
    "config_leak":       _MITRE_HTTP_CFG,
    "wordpress_brute":   _MITRE_HTTP_WP,
    "phpmyadmin_probe":  _MITRE_HTTP_PMA,
    "cgi_exploit":       _MITRE_HTTP_CGI,
    "scan":              _MITRE_HTTP_SCAN,
}

_PAYLOAD_THREAT = {
    "rce_attempt":       "critical",
    "sql_injection":     "critical",
    "config_leak":       "high",
    "wordpress_brute":   "medium",
    "phpmyadmin_probe":  "medium",
    "cgi_exploit":       "high",
    "scan":              "low",
}

def seed(n_ssh: int = 800, n_http: int = 600, n_ftp: int = 200) -> None:
    init_db()
    migrate_db()
    conn = get_conn()
    try:
        _seed_data(conn, n_ssh, n_http, n_ftp)
    finally:
        conn.close()

def _seed_data(conn, n_ssh: int, n_http: int, n_ftp: int) -> None:
    cur  = conn.cursor()

    print(f"Seeding {n_ssh} SSH attacks...")
    for _ in range(n_ssh):
        ip_data  = random.choice(ATTACKER_IPS)
        ip, country, city, lat, lon, asn, isp = ip_data
        username = random.choice(SSH_USERNAMES)
        password = random.choice(SSH_PASSWORDS)
        is_pi    = username == "pi" and password == "raspberry"
        mitre    = _MITRE_SSH_S if is_pi else _MITRE_SSH
        score    = round(random.gauss(-0.05, 0.08), 4)
        threat   = "high" if score < -0.15 else "low"
        cur.execute("""
            INSERT INTO attacks
              (timestamp, service, src_ip, src_port, username, password,
               country, city, latitude, longitude, asn, isp,
               mitre_tags, anomaly_score, threat_level)
            VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
        """, (
            _random_timestamp(14),
            "ssh", ip, random.randint(40000, 65000),
            username, password,
            country, city, lat, lon, asn, isp,
            mitre, score, threat,
        ))

    print(f"Seeding {n_http} HTTP attacks...")
    for _ in range(n_http):
        ip_data  = random.choice(ATTACKER_IPS)
        ip, country, city, lat, lon, asn, isp = ip_data
        path    = random.choice(HTTP_PATHS)
        payload = random.choice(HTTP_PAYLOADS)
        ua      = random.choice(HTTP_USER_AGENTS)
        method  = random.choice(["GET", "GET", "GET", "POST"])
        mitre   = _PAYLOAD_MITRE.get(payload, _MITRE_HTTP_SCAN)
        threat  = _PAYLOAD_THREAT.get(payload, "info")
        score   = round(random.gauss(-0.05, 0.1) if threat in ("critical", "high") else random.gauss(0.02, 0.05), 4)
        cur.execute("""
            INSERT INTO attacks
              (timestamp, service, src_ip, src_port, method, path,
               payload, user_agent, country, city, latitude, longitude, asn, isp,
               mitre_tags, anomaly_score, threat_level)
            VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
        """, (
            _random_timestamp(14),
            "http", ip, random.randint(40000, 65000),
            method, path, payload, ua,
            country, city, lat, lon, asn, isp,
            mitre, score, threat,
        ))

    print(f"Seeding {n_ftp} FTP attacks...")
    for _ in range(n_ftp):
        ip_data  = random.choice(ATTACKER_IPS)
        ip, country, city, lat, lon, asn, isp = ip_data
        username = random.choice(["anonymous", "ftp", "admin", "user", "ftpuser", "backup"])
        password = random.choice(SSH_PASSWORDS + ["anonymous", "guest@", "ftp"])
        score    = round(random.gauss(-0.03, 0.06), 4)
        cur.execute("""
            INSERT INTO attacks
              (timestamp, service, src_ip, src_port, username, password,
               country, city, latitude, longitude, asn, isp,
               mitre_tags, anomaly_score, threat_level)
            VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
        """, (
            _random_timestamp(14),
            "ftp", ip, random.randint(40000, 65000),
            username, password,
            country, city, lat, lon, asn, isp,
            _MITRE_FTP, score, "low",
        ))

    print("Seeding coordinated campaign (Raspberry Pi scanner)...")
    campaign_ips = [
        ("45.142.212.100", "Netherlands", "Amsterdam",   52.37, 4.89,  "AS202425", "IP Volume"),
        ("45.142.212.101", "Netherlands", "Amsterdam",   52.37, 4.89,  "AS202425", "IP Volume"),
        ("45.142.212.102", "Netherlands", "Amsterdam",   52.37, 4.89,  "AS202425", "IP Volume"),
        ("23.129.64.10",   "United States","Herndon",    38.96,-77.38, "AS396507",  "Emerald Onion"),
        ("23.129.64.11",   "United States","Herndon",    38.96,-77.38, "AS396507",  "Emerald Onion"),
        ("23.129.64.12",   "United States","Herndon",    38.96,-77.38, "AS396507",  "Emerald Onion"),
        ("195.206.105.200","Germany",      "Frankfurt",  50.11, 8.68,  "AS60729",   "combahton"),
        ("195.206.105.201","Germany",      "Frankfurt",  50.11, 8.68,  "AS60729",   "combahton"),
    ]
    for ip, country, city, lat, lon, asn, isp in campaign_ips:
        for _ in range(random.randint(8, 20)):
            cur.execute("""
                INSERT INTO attacks
                  (timestamp, service, src_ip, src_port, username, password,
                   country, city, latitude, longitude, asn, isp,
                   mitre_tags, anomaly_score, threat_level)
                VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
            """, (
                _random_timestamp(3),
                "ssh", ip, random.randint(40000, 65000),
                "pi", "raspberry",
                country, city, lat, lon, asn, isp,
                _MITRE_SSH_S, round(random.gauss(-0.18, 0.05), 4), "high",
            ))

    conn.commit()
    total = n_ssh + n_http + n_ftp + len(campaign_ips) * 12
    print(f"\nDone. Demo data seeded: ~{total} attack events")
    print("   Run: python main.py  ->  open http://localhost:5000")
    print("   PDF: python docs/generate_pdf.py")


if __name__ == "__main__":
    large = "--large" in sys.argv
    if large:
        seed(n_ssh=2400, n_http=1800, n_ftp=600)
    else:
        seed()
