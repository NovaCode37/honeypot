# HoneyShield — System Architecture

## 1. Overview

HoneyShield is a **multi-service honeypot platform** designed to attract, record, and analyse cyber attacks in real-time. The system consists of three main layers:

1. **Honeypot Layer** — fake services that lure attackers
2. **Data Layer** — persistent storage and geo-enrichment
3. **Presentation Layer** — real-time dashboard for analysts

---

## 2. Component Diagram

```mermaid
graph TBl
    subgraph Internet["Internet"]
        ATK1[SSH Brute-force Tool]
        ATK2[Web Scanner / Bot]
        ATK3[CVE Exploit Tool]
    end

    subgraph Server["HoneyShield Server"]
        subgraph Layer1["Honeypot Layer (Deception)"]
            SSH["ssh_honeypot.py\nparamiko fake SSH\nport 2222"]
            HTTP["http_honeypot.py\nfake Apache + WordPress\nport 8080"]
        end

        subgraph Layer2["Intelligence Layer"]
            GEO["geoip/locator.py\nIP → lat/lon/country/ISP\nip-api.com (cached)"]
            DB["database/models.py\nSQLite WAL mode\n3 tables, 6 indexes"]
            ALERT["alerts/notifier.py\nTelegram + SMTP"]
        end

        subgraph Layer3["Presentation Layer"]
            FLASK["dashboard/app.py\nFlask 3.0 + REST API"]
            WS["Flask-SocketIO\nWebSocket server"]
            TPL["Jinja2 Templates\nTailwind + Chart.js + Leaflet"]
        end

        CONFIG["config.py\n.env → os.getenv()"]
    end

    subgraph Analyst["Security Analyst"]
        BROWSER["Web Browser\nport 5000"]
        TG["Telegram App"]
        MAIL["Email Client"]
    end

    ATK1 -- TCP SYN --> SSH
    ATK2 -- HTTP GET/POST --> HTTP
    ATK3 -- TCP --> SSH & HTTP

    SSH -- raw event --> GEO
    HTTP -- raw event --> GEO
    GEO -- enriched event --> DB
    DB -- event --> ALERT
    ALERT -- bot API --> TG
    ALERT -- SMTP --> MAIL

    DB -- queries --> FLASK
    FLASK -- JSON API --> TPL
    FLASK -- emit() --> WS
    WS -- socket.io --> BROWSER
    TPL -- served HTML/JS --> BROWSER
    CONFIG -.->|settings| SSH & HTTP & FLASK & GEO & ALERT & DB
```

---

## 3. Deployment Topology

```mermaid
graph LR
    subgraph Cloud["Cloud VPS / On-Prem Server"]
        subgraph Docker["Docker Container"]
            APP["Python 3.11\nmain.py"]
        end
        subgraph Volumes["Bind Mount"]
            DATA["/app/data\nhoneypot.db\nserver.key\nhoneypot.log"]
        end
    end

    subgraph Ports["Exposed Ports"]
        P22["22 → 2222\nSSH"]
        P80["80 → 8080\nHTTP"]
        P5000["5000 → 5000\nDashboard"]
    end

    Internet["Internet"] --> P22 & P80
    Analyst["Analyst"] --> P5000
    Docker --> Volumes
```

---

## 4. SSH Honeypot — Detailed Flow

```mermaid
sequenceDiagram
    participant A as Attacker
    participant T as TCP Socket
    participant P as paramiko.Transport
    participant SI as ServerInterface
    participant DB as Database
    participant GEO as GeoIP

    A->>T: TCP connect (port 2222)
    T->>P: wrap socket
    P-->>A: SSH banner "OpenSSH_8.9p1 Ubuntu"
    A->>P: SSH_MSG_KEXINIT (key exchange)
    P-->>A: server public key (RSA 2048)
    A->>P: SSH_MSG_USERAUTH_REQUEST (password)
    P->>SI: check_auth_password(user, pass)
    SI->>GEO: lookup(src_ip)
    GEO-->>SI: {country, lat, lon, isp}
    SI->>DB: INSERT INTO attacks
    SI-->>P: AUTH_FAILED
    P-->>A: SSH_MSG_USERAUTH_FAILURE
    Note over A,P: Attacker retries with next credential
```

---

## 5. HTTP Honeypot — Attack Classification

The HTTP honeypot classifies each request into one of these categories before storing:

```mermaid
flowchart TD
    REQ["Incoming HTTP Request"] --> E1{Headers contain\njndi://, wget, curl?}
    E1 -- Yes --> RCE["rce_attempt"]
    E1 -- No --> E2{Path contains\n/.env or /wp-config?}
    E2 -- Yes --> CFG["config_leak"]
    E2 -- No --> E3{Path contains\n/wp-login or /xmlrpc?}
    E3 -- Yes --> WP["wordpress_brute"]
    E3 -- No --> E4{Path contains\n/phpmyadmin or /pma?}
    E4 -- Yes --> PMA["phpmyadmin_probe"]
    E4 -- No --> E5{SQL keywords\nin URL/body?}
    E5 -- Yes --> SQLI["sql_injection"]
    E5 -- No --> E6{Path contains\n/cgi-bin?}
    E6 -- Yes --> CGI["cgi_exploit"]
    E6 -- No --> SCAN["scan"]

    style RCE  fill:#f85149,color:#fff
    style SQLI fill:#f85149,color:#fff
    style WP   fill:#d29922,color:#fff
    style CFG  fill:#d29922,color:#fff
    style PMA  fill:#58a6ff,color:#fff
    style CGI  fill:#58a6ff,color:#fff
    style SCAN fill:#3fb950,color:#fff
```

---

## 6. Data Model

```mermaid
erDiagram
    attacks {
        INTEGER id              PK
        TEXT    timestamp
        TEXT    service           "ssh | http | ftp"
        TEXT    src_ip
        INTEGER src_port
        TEXT    username
        TEXT    password
        TEXT    payload
        TEXT    user_agent
        TEXT    method
        TEXT    path
        TEXT    country
        TEXT    city
        REAL    latitude
        REAL    longitude
        TEXT    asn
        TEXT    isp
        INTEGER flagged           "analyst-marked"
        TEXT    mitre_tags        "JSON array of technique IDs"
        REAL    anomaly_score     "IsolationForest score"
        TEXT    threat_level      "info|low|medium|high|critical"
    }
    sessions {
        INTEGER id          PK
        INTEGER attack_id   FK
        TEXT    started_at
        TEXT    ended_at
        TEXT    commands     "JSON array"
    }
    stats_hourly {
        INTEGER id          PK
        TEXT    hour           "YYYY-MM-DD HH"
        INTEGER ssh_count
        INTEGER http_count
        INTEGER ftp_count
        INTEGER unique_ips
    }

    attacks ||--o{ sessions : "1 attack → N sessions"
```

---

## 7. ML Anomaly Detection Pipeline

```mermaid
flowchart LR
    A["Raw Attack Event"] --> B["_extract_features()"]
    B --> C["7-dim float32 vector\nhour_sin, hour_cos\nservice_id\nis_default_cred\npayload_len/1000\npath_depth/10\nhas_special_chars"]
    C --> D{{"IsolationForest\nn_estimators=100\ncontamination=0.05\nrandom_state=42"}}
    D --> E["score_samples() → float"]
    E --> F{"score < threshold?"}
    F -- No --> G["Normal\nanomaly_score stored"]
    F -- Yes --> H["Anomaly Detected\n_explain() → reason string"]
    H --> I["threat_level=high/critical"]
    G --> J["Persist to DB"]
    I --> J
    J --> K["Surface on\n/intelligence page"]
```

---

## 8. MITRE ATT&CK Tagging Engine

```mermaid
flowchart TD
    IN["Attack Dict\n{service, path, payload, ua}"] --> R1

    R1{service == ssh?} -- Yes --> T1["T1110.001\nPassword Guessing"]
    R1 -- No --> R2

    R2{service == ftp?} -- Yes --> T2["T1133 + T1110.001"]
    R2 -- No --> R3

    R3{HTTP: RCE\njndi / shell?} -- Yes --> T3["T1059.004\nT1190"]
    R3 -- No --> R4

    R4{HTTP: SQLi?} -- Yes --> T4["T1190 + T1212"]
    R4 -- No --> R5

    R5{HTTP: /.env\n/wp-config?} -- Yes --> T5["T1083"]
    R5 -- No --> R6

    R6{HTTP: /wp-login?} -- Yes --> T6["T1110.003 + T1078"]
    R6 -- No --> R7

    R7{HTTP: webshell\n/cgi-bin?} -- Yes --> T7["T1505.003 + T1190"]
    R7 -- No --> T8["T1046 / T1595.001\nNetwork Discovery"]
```

---

## 9. Intelligence Dashboard Architecture

```mermaid
graph LR
    subgraph Browser["Browser — /intelligence"]
        TL["Threat Level\nCards ×5"]
        MB["MITRE Bar Chart\n(Chart.js horizontal)"]
        AL["Anomaly List\n(font-mono table)"]
        TR["Threat Score\nBars (0–100)"]
        CA["Campaign Cards\n(auto-detected)"]
        CT["Technique Catalogue\n(click → attack.mitre.org)"]
    end

    subgraph Server["Server APIs"]
        AI["/api/intel\nget_intel_summary()\nget_all_techniques()"]
        AT["/api/threats\nrank_threats()\ndetect_campaigns()"]
    end

    Browser -->|"GET /api/intel"| AI
    Browser -->|"GET /api/threats"| AT
    AI --> TL & MB & AL & CT
    AT --> TR & CA
```

---

## 10. Dashboard Architecture

```mermaid
graph LR
    subgraph Browser
        MAP["Leaflet.js\nWorld Map"]
        CHART1["Chart.js\nHourly Bar"]
        CHART2["Chart.js\nService Pie"]
        TABLE["Attack Table\nwith filters"]
        TOAST["Toast Notifications\nreal-time"]
        WS_CLIENT["socket.io-client"]
    end

    subgraph Server
        FLASK_ROUTE["/api/stats\n/api/attacks\n/api/map\n/api/intel\n/api/threats"]
        SOCKETIO["Flask-SocketIO\nbroadcast_attack()"]
        DB_LAYER["database/models.py"]
    end

    Browser --> |"GET /api/*"| FLASK_ROUTE
    FLASK_ROUTE --> DB_LAYER
    DB_LAYER --> FLASK_ROUTE
    FLASK_ROUTE --> Browser
    SOCKETIO --> |"emit new_attack"| WS_CLIENT
    WS_CLIENT --> MAP & TOAST & TABLE
```

---

## 11. Technology Stack

| Layer | Technology | Reason |
|---|---|---|
| SSH emulation | `paramiko` 3.4 | Industry-standard Python SSH library, full server-mode API |
| HTTP server | `http.server` stdlib | Zero dependencies, full control over responses |
| FTP server | raw sockets (stdlib) | Custom protocol handler, zero external dependencies |
| ML anomaly detection | `scikit-learn` IsolationForest | Unsupervised, no labelled data needed, fast inference |
| MITRE ATT&CK | Custom rule engine | 13 techniques, 6 tactics, zero API calls |
| IP reputation | Custom scoring | Multi-factor 0–100 score, campaign detection |
| Database | SQLite + WAL | Zero-config, file-based, WAL for concurrent writes |
| GeoIP | ip-api.com | Free, no API key, 45 req/min, covers all public IPs |
| Web framework | Flask 3.0 | Lightweight, well-known, easy to extend |
| Real-time | Flask-SocketIO + eventlet | WebSocket support, room-based broadcasting |
| Frontend | Tailwind CSS + Chart.js + Leaflet | Modern, CDN-hosted, no build step |
| PDF reports | `fpdf2` | Pure-Python, dark-theme branded report generation |
| Containerisation | Docker + Compose | Reproducible deploys, port remapping |

---

## 12. Performance Characteristics

- **Concurrency model**: 3 honeypot threads + main thread for dashboard (4 total)
- **SSH**: handles ~100 simultaneous TCP connections (thread-per-connection, daemon threads)
- **FTP**: thread-per-connection, same model as SSH
- **HTTP**: sequential request handling (short-lived, sufficient for honeypot loads)
- **GeoIP**: results cached in-memory for 1 hour to avoid rate limiting
- **ML scoring**: IsolationForest inference is O(log n) per event — sub-millisecond
- **SQLite WAL**: allows concurrent readers + one writer without locking dashboard queries
- **WebSocket**: broadcast uses eventlet's green threads — no blocking

---

## 13. Limitations & Future Work

| Limitation | Status | Proposed Enhancement |
|---|---|---|
| Single server | Planned | Distributed honeypot network (Kafka + ClickHouse) |
| SQLite | Planned | Migrate to PostgreSQL for high-volume deployments |
| Static SSH (no shell) | Planned | Integrate Cowrie for full interactive shell emulation |
| No PCAP capture | Planned | Scapy / libpcap full packet recording |
| Manual GeoIP | Planned | MaxMind GeoIP2 for offline, GDPR-compliant lookups |
| ML trained offline | Planned | Periodic retraining pipeline as new attacks arrive |
| Only SSH+HTTP+FTP | Planned | Add Telnet, SMTP, RDP, Modbus/ICS honeypots |
| FTP honeypot | v2.0 | Implemented — fake vsftpd 3.0.5 |
| ML anomaly detection | v2.0 | Implemented — IsolationForest, 7 features |
| MITRE ATT&CK mapping | v2.0 | Implemented — 13 techniques, 6 tactics |
| XSS detection | v2.1 | Implemented — regex classifier + T1059.007 |
| IP threat scoring | v2.0 | Implemented — 0–100 composite score |
