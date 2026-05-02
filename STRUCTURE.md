# Project Structure & Branching Strategy

## Directory Tree

```
honeyshield/
│
├── main.py                        Entry point — launches all services
├── config.py                      Central config, reads .env via os.getenv()
├── seed_demo_data.py              Generates 1400 realistic demo attacks for screenshots
├── requirements.txt               Python dependencies (pinned versions)
├── Dockerfile                     Container image definition
├── docker-compose.yml             One-command deploy (ports 22/80/5000)
├── .env.example                   Config template — copy to .env and fill in
├── .gitignore                     Excludes data/, .env, *.key, *.db
├── LICENSE                        MIT
│
├── honeypot/
│   ├── __init__.py
│   ├── ssh_honeypot.py               Fake OpenSSH 8.9p1 server (paramiko, port 2222)
│   │                                   └─ records every username + password attempt
│   ├── http_honeypot.py              Fake Apache + WordPress + phpMyAdmin (stdlib, port 8080)
│   │                                   └─ classifies 7 attack types (SQLi, RCE, …)
│   └── ftp_honeypot.py               Fake vsftpd 3.0.5 (raw sockets, port 2121)
│                                         └─ records USER/PASS attempts
│
├── ml/
│   ├── __init__.py
│   └── detector.py                   IsolationForest anomaly detector (scikit-learn)
│                                         └─ 7-feature extraction · auto-trains on history
│
├── intelligence/
│   ├── __init__.py
│   ├── mitre.py                      MITRE ATT&CK tagger — 12 techniques, 6 tactics
│   │                                   └─ tag_attack() → list[MitreTechnique]
│   └── reputation.py                 IP threat scoring (0–100) + campaign detection
│                                         └─ rank_threats() · detect_campaigns()
│
├── database/
│   ├── __init__.py
│   └── models.py                     SQLite WAL — schema + mitre_tags/anomaly_score cols
│                                         get_stats() · get_map_points() · get_intel_summary()
│
├── geoip/
│   ├── __init__.py
│   └── locator.py                    IP → country / city / lat-lon / ISP
│                                         ip-api.com · in-memory cache (1h TTL)
│
├── alerts/
│   ├── __init__.py
│   └── notifier.py                   Telegram bot + SMTP email dispatch
│
├── dashboard/
│   ├── __init__.py
│   ├── app.py                        Flask 3.0 + Flask-SocketIO
│   │                                   ├─ REST: /api/stats  /api/attacks  /api/map
│   │                                   ├─ REST: /api/intel  /api/threats  (NEW)
│   │                                   └─ WS:  broadcast_attack() → all browsers
│   └── templates/
│       ├── base.html                 Layout: Tailwind · Leaflet · Chart.js · socket.io
│       ├── login.html                Auth page
│       ├── index.html                Main dashboard (map + charts + live feed)
│       ├── attacks.html             Filterable attack log (search, service filter)
│       └── intelligence.html        Threat Intel: MITRE chart · ML anomalies
│                                         IP threat scores · campaign detection
│
├── tests/
│   ├── __init__.py
│   ├── test_honeypot.py              Unit tests: DB · GeoIP · HTTP classifier · Alerts
│   └── test_intelligence.py          Unit tests: MITRE · reputation · ML anomaly detector
│
└── docs/
    ├── architecture.md               Mermaid diagrams (components, ER, sequence, flow)
    ├── threat_model.md               STRIDE analysis · risk matrix · mitigations
    ├── report.md                     Academic research report (~2500 words)
    ├── generate_pdf.py               PDF report generator (fpdf2) with live DB stats
    └── assets/
        └── (screenshots go here)
```

---

## Git Branching Strategy

```
main ──────────────────────────────────────────────────────────► (stable, tagged releases)
  │                                                                v1.0   v1.1   v2.0
  │
  └─► develop ──────────────────────────────────────────────────► (integration branch)
          │
          ├─► feature/ftp-honeypot          SHIPPED v2.0 — FTP vsftpd decoy (port 2121)
          │       └── merged ──────────────────────────────────►
          │
          ├─► feature/ml-classifier         SHIPPED v2.0 — IsolationForest anomaly detection
          │       └── merged ──────────────────────────────────►
          │
          ├─► feature/mitre-tagging         SHIPPED v2.0 — 12 ATT&CK techniques auto-tagged
          │       └── merged ──────────────────────────────────►
          │
          ├─► feature/ip-reputation         SHIPPED v2.0 — 0–100 threat scoring + campaigns
          │       └── merged ──────────────────────────────────►
          │
          ├─► feature/intel-dashboard       SHIPPED v2.0 — /intelligence page
          │       └── merged ──────────────────────────────────►
          │
          ├─► feature/distributed-nodes     PLANNED — Multi-server aggregation (Kafka)
          │
          ├─► feature/pcap-capture          PLANNED — Scapy full packet recording
          │
          ├─► feature/cowrie-shell          PLANNED — Full SSH shell emulation
          │
          └─► hotfix/unicode-logging    ◄── branch from main (example)
                  └── merge → main + develop ──────────────────►
```

### Branch Rules

| Branch | Purpose | Merge into | Protected |
|---|---|---|---|
| `main` | Production-ready, tagged releases | — | yes |
| `develop` | Latest integrated work | `main` via PR | yes |
| `feature/*` | New functionality | `develop` | no |
| `hotfix/*` | Urgent production fixes | `main` + `develop` | no |
| `docs/*` | Documentation-only changes | `develop` | no |
| `experiment/*` | Exploratory / research branches | never merged | no |

### Commit Convention

```
type(scope): short description

feat(honeypot):   add FTP decoy service on port 2121
fix(dashboard):   prevent chart stretching to map height
docs(arch):       add STRIDE threat model diagrams
test(geoip):      add unit test for network failure fallback
chore(deps):      pin paramiko to 3.4.0
```

---

## Data Flow at a Glance

```
[Attacker]
    │  TCP connect
    ▼
[SSH / HTTP / FTP Honeypot]  ──extract──►  [GeoIP Resolver]
                                                  │
                                           country, city, lat/lon
                                                  │
                                                  ▼
                                         [MITRE ATT&CK Tagger]
                                                  │
                                           technique IDs
                                                  │
                                                  ▼
                                         [ML Anomaly Detector]
                                                  │
                                           anomaly_score, is_anomaly
                                                  │
                                                  ▼
                                          [SQLite Database]
                                           /             \
                               [Alert Dispatch]       [Flask API + WebSocket]
                              Telegram / Email               │
                                                             ▼
                                                  [Browser Dashboard]
                                          Map · Charts · Live Feed · Intelligence
```

---

## Runtime Threads

```
Process: python main.py
  │
  ├── Thread-1  ssh-honeypot    port 2222  (thread-per-connection, daemon)
  ├── Thread-2  http-honeypot   port 8080  (sequential, short-lived requests)
  ├── Thread-3  ftp-honeypot    port 2121  (thread-per-connection, daemon)
  └── Main      Flask+SocketIO  port 5000  (eventlet async mode)
```

---

## Environment Variables Quick Reference

```
SSH_PORT          2222      Honeypot SSH port
HTTP_PORT         8080      Honeypot HTTP port
FTP_PORT          2121      Honeypot FTP port
DASHBOARD_PORT    5000      Web UI port
DASHBOARD_USER    admin     Login username
DASHBOARD_PASS    admin     Login password  ← change in production!
SECRET_KEY        ...       Flask session key  ← use secrets.token_hex(32)
DB_PATH           data/honeypot.db
TELEGRAM_TOKEN    (opt)     Bot token from @BotFather
TELEGRAM_CHAT_ID  (opt)     From @userinfobot
ALERT_EMAIL_TO    (opt)     Recipient for SMTP alerts
```
