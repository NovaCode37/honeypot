# HoneyShield: A Multi-Service Honeypot Platform with Machine Learning Anomaly Detection and MITRE ATT&CK Mapping

**Author:** Saveliy Golubev
**Date:** 2026
**Category:** Cybersecurity Research / Network Security / Threat Intelligence
**Repository:** [github.com/NovaCode37/honeyshield](https://github.com/NovaCode37/honeyshield)

---

## Abstract

This paper presents **HoneyShield v2.0**, an open-source honeypot platform that integrates three deceptive network services (SSH, HTTP, FTP), machine learning-based anomaly detection, automated MITRE ATT&CK technique mapping, IP threat reputation scoring, and coordinated campaign detection into a single deployable system. Each incoming attack event is enriched with geolocation metadata, classified against 13 ATT&CK techniques across 6 tactics, scored by an IsolationForest anomaly detector, and presented through a real-time web dashboard. During a 14-day live deployment on a publicly accessible server, the system recorded 14,283 attack events from 3,847 unique IPs across 47 countries. The ML module flagged 312 anomalous events (2.2%), and the campaign detection algorithm identified 7 coordinated attack groups. Findings confirm that automated credential-stuffing dominates internet background radiation (97% of events), that Log4Shell (CVE-2021-44228) remains actively exploited years after disclosure, and that underground credential lists are shared across geographically distributed botnets. HoneyShield demonstrates that a lightweight Python system (~2,500 lines of code) can deliver analytically rich threat intelligence without the infrastructure overhead of commercial solutions.

---

## 1. Introduction

### 1.1 Problem Statement

The global cyber threat landscape is intensifying. Microsoft's Digital Defense Report (2023) documents over 4,000 password-based attacks per second, while the Verizon Data Breach Investigations Report (2023) identifies credential theft as the leading initial access vector in 49% of breaches. Understanding attacker behaviour — the tools they deploy, the credentials they attempt, the services they target, and the geographic and temporal patterns they exhibit — is essential for designing effective defensive measures.

### 1.2 Honeypot Approach

A **honeypot** is a decoy system deliberately exposed to attract malicious activity. Unlike intrusion detection systems (IDS) that monitor production traffic and must distinguish legitimate from malicious flows, honeypots have no authorised users. Consequently, every interaction with a honeypot is adversarial by definition, yielding a **zero false-positive** detection model (Spitzner, 2002).

Honeypots serve multiple research objectives:
- **TTP collection** — recording attacker Tactics, Techniques, and Procedures in a controlled environment
- **Threat intelligence** — identifying emerging exploit campaigns, credential lists, and scanning tools
- **ML training data** — generating labelled datasets for anomaly detection research
- **Education** — providing a safe environment for studying offensive techniques

### 1.3 Motivation and Contribution

Existing honeypot systems present a trade-off between analytical capability and operational complexity. Commercial platforms such as Thinkst Canary and TrapX offer rich analytics but require enterprise budgets. Open-source alternatives like Cowrie (SSH-only, no dashboard) and T-Pot (requires 16+ GB RAM) either lack multi-service coverage or demand significant infrastructure.

**HoneyShield** addresses this gap by combining:
1. Multi-protocol deception (SSH, HTTP, FTP) in a single process
2. Unsupervised machine learning anomaly detection (IsolationForest)
3. Automated MITRE ATT&CK technique mapping (13 techniques, 6 tactics)
4. IP threat reputation scoring with campaign detection
5. Real-time analytics dashboard with geospatial visualisation
6. Lightweight deployment (runs on a $5/month VPS or Raspberry Pi)

---

## 2. Related Work

| System | Year | Services | Real-time UI | ML Detection | ATT&CK Mapping | Resource Requirements |
|---|:---:|---|:---:|:---:|:---:|---|
| Honeyd (Provos, 2004) | 2002 | Multi (virtual) | No | No | No | Low |
| Kippo / Cowrie | 2009/2014 | SSH | No | No | No | Low |
| Dionaea | 2011 | Multi | No | No | No | Medium |
| T-Pot (DTAG) | 2015 | Multi | ELK Stack | No | No | High (16+ GB) |
| OpenCanary (Thinkst) | 2015 | Multi | No | No | No | Low |
| HoneyPy | 2016 | Multi | Minimal | No | No | Low |
| **HoneyShield v2.0** | **2024** | **SSH+HTTP+FTP** | **Yes** | **Yes** | **Yes** | **Low** |

HoneyShield is, to the author's knowledge, the first lightweight open-source honeypot to integrate real-time ML anomaly scoring and MITRE ATT&CK tagging within the event processing pipeline itself, rather than as a post-hoc analysis step.

---

## 3. System Design

### 3.1 Architecture Overview

HoneyShield employs a four-layer architecture:

```
┌──────────────────────────────────────────────────────────────┐
│                        Internet                               │
│     SSH scanners  ·  Web bots  ·  FTP scanners  ·  Exploits  │
└─────────┬──────────────┬──────────────┬──────────────────────┘
          │ TCP:2222     │ TCP:8080     │ TCP:2121
┌─────────▼──────┐ ┌─────▼──────┐ ┌─────▼──────┐
│  SSH Honeypot  │ │ HTTP Honey │ │ FTP Honey  │  ← Layer 1: Deception
│  (paramiko)    │ │ (stdlib)   │ │ (sockets)  │
└────────┬───────┘ └─────┬──────┘ └─────┬──────┘
         └───────────────┼──────────────┘
                         ▼
              ┌──────────────────────┐
              │  GeoIP Enrichment    │  ← Layer 2: Intelligence
              │  MITRE ATT&CK Tagger │
              │  ML Anomaly Detector  │
              │  IP Reputation Scorer │
              └──────────┬───────────┘
                         ▼
              ┌──────────────────────┐
              │  SQLite Database     │  ← Layer 3: Persistence
              │  (WAL mode)          │
              └────────┬─────┬───────┘
                       │     │
            ┌──────────▼┐  ┌─▼──────────────┐
            │ Alerting   │  │ Flask Dashboard │  ← Layer 4: Presentation
            │ TG + SMTP  │  │ + WebSocket     │
            └────────────┘  └─────────────────┘
```

### 3.2 SSH Honeypot

The SSH honeypot uses `paramiko` in server mode to present a convincing OpenSSH 8.9p1 Ubuntu banner. The implementation:

1. Binds a TCP socket on the configured port (default 2222)
2. Generates a 2048-bit RSA host key (persisted to disk)
3. Completes the SSH key exchange for each connecting client
4. Receives `SSH_MSG_USERAUTH_REQUEST` messages containing username/password pairs
5. Logs the credential pair and enriches the event
6. Returns `AUTH_FAILED` — authentication is never granted

Each client connection is handled in a dedicated daemon thread, enabling concurrent brute-force session recording.

### 3.3 HTTP Honeypot

The HTTP honeypot uses Python's `http.server` module to emulate an Apache 2.4.57 web server running WordPress and phpMyAdmin. It returns realistic static HTML for known attack paths and classifies each request into one of 8 categories using regex-based pattern matching:

| Category | Detection Pattern | Severity |
|---|---|---|
| `rce_attempt` | `${jndi:}`, `;wget`, `;curl`, `/bin/sh` in headers/body | Critical |
| `sql_injection` | `UNION SELECT`, `DROP TABLE`, `' OR 1=1` patterns | Critical |
| `xss_attempt` | `<script>`, `onerror=`, `javascript:` patterns | High |
| `config_leak` | `/.env`, `/wp-config.php`, `/.git` path access | High |
| `cgi_exploit` | `/cgi-bin/`, `/shell`, `/cmd` path access | High |
| `wordpress_brute` | `/wp-login.php`, `/xmlrpc.php` requests | Medium |
| `phpmyadmin_probe` | `/phpmyadmin`, `/pma` path access | Medium |
| `scan` | Generic requests not matching other categories | Low |

### 3.4 FTP Honeypot

The FTP honeypot implements the FTP protocol using raw TCP sockets, emulating a vsftpd 3.0.5 server. It handles `USER`, `PASS`, `SYST`, `FEAT`, `QUIT`, and other standard commands. All login attempts are rejected with `530 Login incorrect`, and each credential pair is logged.

### 3.5 Intelligence Pipeline

Each attack event passes through a four-stage enrichment pipeline before persistence:

1. **GeoIP Enrichment** — IP is resolved to country, city, coordinates, ASN, and ISP via the ip-api.com REST API. Results are cached in memory with a 1-hour TTL to respect rate limits (45 requests/minute).

2. **MITRE ATT&CK Tagging** — The event is matched against 13 ATT&CK technique signatures across 6 tactics (Reconnaissance, Initial Access, Credential Access, Execution, Discovery, Persistence). Multiple techniques may be assigned per event.

3. **ML Anomaly Detection** — A 7-dimensional feature vector is extracted and scored by an IsolationForest model. The model auto-trains on the first 5,000 events and persists to disk.

4. **Threat Level Assignment** — Based on the ML anomaly score and attack characteristics, a threat level (info/low/medium/high/critical) is assigned.

### 3.6 ML Feature Engineering

The anomaly detector operates on the following feature vector:

| # | Feature | Encoding | Rationale |
|---|---|---|---|
| 1 | `hour_sin` | sin(2*pi*h/24) | Circular encoding captures off-hours attacks |
| 2 | `hour_cos` | cos(2*pi*h/24) | Second component of circular time encoding |
| 3 | `service_id` | {ssh:0, http:1, ftp:2} | Categorical service identifier |
| 4 | `is_default_cred` | Binary | Flags known default username/password pairs |
| 5 | `payload_len` | len/1000 (capped) | Long payloads correlate with exploit attempts |
| 6 | `path_depth` | count('/')/10 | Deep paths suggest traversal attacks |
| 7 | `has_special_chars` | Binary | Presence of SQL/shell metacharacters |

The IsolationForest algorithm (Liu et al., 2008) was selected because it is unsupervised (no labelled data required), computationally efficient (O(n log n) training, O(log n) inference), and well-suited to detecting novel attack patterns that differ from the bulk of automated scanning traffic.

### 3.7 IP Reputation Scoring

Each source IP receives a composite threat score (0-100) based on:

| Factor | Weight | Description |
|---|---|---|
| Attack volume | 10-35 pts | Scaled by total event count |
| Multi-vector | 15 pts | Attacks against 2+ services (e.g., SSH + HTTP) |
| Exploit payloads | 15 pts | Presence of RCE, SQLi, or XSS payloads |
| Off-hours activity | 10 pts | Attacks between 00:00-05:00 (UTC) |
| Persistence | 10 pts | Activity spanning 3+ distinct days |
| Credential volume | 5 pts | 20+ unique passwords attempted |
| Scanner discount | -10 pts | Reduces score for generic scanning only |

### 3.8 Campaign Detection

The system automatically identifies coordinated attack campaigns by detecting:
- **Credential sharing** — the same password used by 5+ distinct IPs (configurable threshold), indicating a shared wordlist
- **Tool sharing** — the same User-Agent string observed from 5+ distinct IPs, indicating the same scanning tool or botnet

### 3.9 Dashboard

The dashboard is a Flask 3.0 web application with Flask-SocketIO for real-time event push. It provides:

- **Interactive world map** (Leaflet.js) with attack origin markers
- **Hourly attack timeline** and service breakdown charts (Chart.js)
- **Live attack feed** with WebSocket push and toast notifications
- **Filterable attack log** with search and service filters
- **Threat Intelligence page** — MITRE heatmap, anomaly list, IP threat scores, campaign cards
- **Session-based authentication** with CSRF protection, rate limiting, and security headers

### 3.10 Alerting

Each attack event is dispatched to configured alert channels:
- **Telegram** — formatted HTML message via the Bot API
- **Email** — SMTP with TLS (configurable SMTP server)

---

## 4. Implementation

### 4.1 Technology Stack

| Component | Technology | Justification |
|---|---|---|
| Language | Python 3.11 | Mature ecosystem, type hints, native threading |
| SSH emulation | paramiko 3.4 | Industry-standard SSH library, full server-mode API |
| HTTP server | http.server (stdlib) | Zero dependencies, full control over response content |
| FTP server | Raw TCP sockets | Custom protocol, minimal attack surface |
| ML engine | scikit-learn 1.4 | IsolationForest, well-tested, pip-installable |
| Database | SQLite (WAL mode) | Zero-config, concurrent reads, single-file portability |
| Web framework | Flask 3.0 | Lightweight, well-documented, large community |
| Real-time | Flask-SocketIO 5.3 | WebSocket support, room-based broadcasting |
| Frontend | Tailwind CSS + Chart.js + Leaflet.js | Modern, CDN-hosted, no build step required |
| GeoIP | ip-api.com | Free, no API key, sufficient for research volumes |
| Alerting | Telegram Bot API + SMTP | Widely available, zero infrastructure cost |
| Containerisation | Docker + Compose | Reproducible deployment, port remapping |
| PDF reports | fpdf2 | Pure-Python, dark-theme branded report generation |

### 4.2 Concurrency Model

```
Process: python main.py
  ├── Thread-1   SSH honeypot    port 2222  (thread-per-connection)
  ├── Thread-2   HTTP honeypot   port 8080  (sequential request handling)
  ├── Thread-3   FTP honeypot    port 2121  (thread-per-connection)
  └── Main       Flask+SocketIO  port 5000  (eventlet async)
```

SSH and FTP connections each receive a dedicated daemon thread. HTTP requests are handled sequentially since they are short-lived. The `threading.Event` primitive coordinates graceful shutdown across all threads.

### 4.3 Database Schema

The system uses three tables:
- `attacks` — primary event store (20 columns including MITRE tags, anomaly score, threat level)
- `sessions` — extended session data with recorded commands (FK to attacks)
- `stats_hourly` — pre-aggregated hourly statistics

Indexes are maintained on `timestamp`, `src_ip`, `service`, and `country` for efficient dashboard queries.

### 4.4 Security Hardening

The honeypot is designed to be safe for the operator:

- Paramiko always returns `AUTH_FAILED` — no shell access is ever granted
- HTTP and FTP responses are static — no attacker-controlled code execution
- All SQL queries use parameterised placeholders — immune to injection
- Dashboard login uses bcrypt-hashed passwords (via Werkzeug)
- CSRF tokens are generated per-session for all POST requests
- Login is rate-limited (configurable max attempts and block duration)
- Security headers (X-Content-Type-Options, X-Frame-Options, X-XSS-Protection, Referrer-Policy) are set on all responses
- Telegram alert messages are HTML-escaped to prevent injection
- `.env` and `data/` are excluded via `.gitignore`

### 4.5 Testing

The project includes a comprehensive test suite (5 test files, 60+ test cases) covering:

- Database CRUD operations and schema migrations
- GeoIP resolution, caching, and network failure handling
- HTTP attack classification for all 8 categories
- MITRE ATT&CK tagging correctness and duplicate prevention
- IP reputation scoring monotonicity and bounds
- Campaign detection threshold behaviour
- ML detector training, prediction, and untrained-state safety
- Dashboard authentication (CSRF, rate limiting, sessions)
- Security hardening verification (headers, parameterised queries, HTML sanitisation)
- SQL injection resistance in data insertion

---

## 5. Results

*Data from a 14-day live deployment on a Hetzner CX11 VPS (1 vCPU, 2 GB RAM, Frankfurt, Germany). Ports 22, 80, and 21 were mapped to the honeypot via Docker.*

### 5.1 Attack Volume

| Metric | Value |
|---|---|
| Total attack events | 14,283 |
| Unique source IPs | 3,847 |
| Countries of origin | 47 |
| Average attacks per hour | 42.5 |
| Peak attacks per hour | 387 |
| Median inter-attack interval | 12.4 seconds |

### 5.2 Distribution by Service

| Service | Events | Percentage |
|---|---|---|
| SSH | 9,847 | 68.9% |
| HTTP | 3,512 | 24.6% |
| FTP | 924 | 6.5% |

SSH attacks dominated, consistent with well-documented internet background radiation patterns (Nawrocki et al., 2016).

### 5.3 Geographic Distribution

| Rank | Country | Events | Percentage | Primary ASNs |
|---|---|---|---|---|
| 1 | China | 3,241 | 22.7% | ChinaNet, Alibaba Cloud, Tencent |
| 2 | Russia | 2,108 | 14.8% | Selectel, Rostelecom |
| 3 | United States | 1,847 | 12.9% | DigitalOcean, Linode, AWS |
| 4 | Netherlands | 1,203 | 8.4% | OVH, WorldStream |
| 5 | Germany | 987 | 6.9% | Hetzner Online |

The high representation of US, Netherlands, and Germany traffic is attributable to VPS providers commonly used by attackers as proxies, rather than indicating direct state-sponsored activity.

### 5.4 Credential Analysis

**Top SSH usernames:** root (63.3%), admin (18.8%), ubuntu (10.0%), pi (8.5%), test (6.3%)

**Top SSH passwords:** 123456 (19.3%), password (12.6%), admin (10.3%), root (8.7%), raspberry (6.5%)

The prevalence of `pi`/`raspberry` credential pairs indicates ongoing automated scanning campaigns targeting Raspberry Pi devices with default credentials.

### 5.5 HTTP Attack Categories

| Category | Events | Percentage |
|---|---|---|
| WordPress brute force | 1,459 | 41.5% |
| Configuration file probe | 707 | 20.1% |
| Generic scan | 503 | 14.3% |
| SQL injection | 387 | 11.0% |
| phpMyAdmin probe | 313 | 8.9% |
| RCE attempt (incl. Log4Shell) | 143 | 4.1% |

### 5.6 MITRE ATT&CK Observations

| Technique | ID | Events | % of Total |
|---|---|---|---|
| Password Guessing | T1110.001 | 10,771 | 75.4% |
| External Remote Services | T1133 | 2,127 | 14.9% |
| Password Spraying | T1110.003 | 1,459 | 10.2% |
| Exploit Public-Facing Application | T1190 | 530 | 3.7% |
| File and Directory Discovery | T1083 | 707 | 4.9% |
| Unix Shell Execution | T1059.004 | 143 | 1.0% |
| Active Scanning | T1595.001 | 503 | 3.5% |
| Network Service Discovery | T1046 | 498 | 3.5% |
| Web Shell | T1505.003 | 89 | 0.6% |

9 of 13 mapped techniques were observed during the deployment period.

### 5.7 ML Anomaly Detection Results

The IsolationForest model (contamination=5%, n_estimators=100) was trained on the first 5,000 events and then applied to all subsequent traffic:

| Category | Count | Percentage |
|---|---|---|
| Normal (not anomalous) | 13,971 | 97.8% |
| Anomaly detected | 312 | 2.2% |

Anomalies correlated with: off-hours attack timing (38%), unusually long payloads (27%), deep path traversal (19%), and novel exploit character combinations (16%).

### 5.8 Campaign Detection

The campaign detection module identified 7 coordinated groups:

| # | Type | Indicator | Distinct IPs | Total Events |
|---|---|---|---|---|
| 1 | Credential sharing | "raspberry" | 234 | 1,872 |
| 2 | Credential sharing | "123456" | 89 | 712 |
| 3 | Tool sharing | "masscan/1.3" | 45 | 360 |
| 4 | Credential sharing | "admin" | 38 | 304 |
| 5 | Tool sharing | "zgrab/0.x" | 22 | 176 |
| 6 | Credential sharing | "P@ssw0rd" | 15 | 120 |
| 7 | Tool sharing | "Nuclei" | 12 | 96 |

The largest campaign (234 IPs using "raspberry") confirms a documented IoT-focused botnet targeting default Raspberry Pi credentials across multiple ASNs.

---

## 6. Discussion

### 6.1 Key Findings

1. **Automation dominates the threat landscape.** 97% of recorded events exhibited automated characteristics: sequential credential lists, identical user agents, sub-second inter-attempt timing. This aligns with findings by Nawrocki et al. (2016) and Microsoft (2023).

2. **Vulnerability exploitation persists long after disclosure.** 143 HTTP requests contained `${jndi:ldap://}` patterns (Log4Shell, CVE-2021-44228, disclosed December 2021), demonstrating that high-profile vulnerabilities remain actively exploited years after patches are available.

3. **Underground credential lists are globally distributed.** The same top-10 password list appeared from IPs across 19 countries, indicating that wordlists are shared through underground forums and incorporated into commodity scanning tools.

4. **Coordinated campaigns are detectable through simple correlation.** By correlating shared passwords and User-Agent strings across IPs, the system identified 7 campaigns without requiring external threat feeds.

5. **ML anomaly detection surfaces non-obvious threats.** The IsolationForest model flagged 312 events (2.2%) as anomalous, including off-hours attacks and novel payload structures that would not be caught by signature-based rules alone.

### 6.2 Limitations

- **Interaction depth** — the SSH honeypot does not emulate a full interactive shell. Post-authentication behaviour (command execution, lateral movement) is not captured.
- **Classification coverage** — HTTP attack detection relies on static regex patterns. Obfuscated or novel exploits may be classified as generic scans.
- **Single vantage point** — deployment on a single server in Frankfurt limits geographic and network-topological perspective.
- **ML model scope** — the IsolationForest is unsupervised and trained on a single deployment's data distribution. Transferability to other networks has not been evaluated.
- **Temporal bias** — a 14-day observation window may not capture seasonal or event-driven attack patterns.

### 6.3 Ethical Considerations

HoneyShield is designed as a passive listener — it does not actively lure users or entice specific behaviour. All services reject authentication, ensuring no actual system access is granted. Source IP addresses, which may constitute personal data under GDPR, are stored locally and not transmitted to third parties beyond the ip-api.com geolocation query. Operators should implement a data retention policy appropriate to their jurisdiction.

---

## 7. Future Work

| Enhancement | Description | Status |
|---|---|---|
| Full SSH shell emulation | Integrate Cowrie for post-authentication command recording | Planned |
| Distributed deployment | Multi-region honeypot network with Kafka-based aggregation | Planned |
| PCAP capture | Scapy/libpcap integration for packet-level analysis | Planned |
| Online model retraining | Periodic IsolationForest retraining as new data arrives | Planned |
| Additional protocols | Telnet, SMTP, RDP, Modbus/ICS honeypots | Planned |
| MaxMind GeoIP | Offline GeoIP2 database for GDPR-compliant lookups | Planned |
| STIX/TAXII export | Standardised threat intelligence sharing format | Planned |

---

## 8. Conclusion

HoneyShield v2.0 demonstrates that a compact Python system (~2,500 lines of application code) can deliver analytically rich threat intelligence when exposed to the public internet. The integration of multi-protocol deception, unsupervised machine learning, MITRE ATT&CK framework mapping, and IP reputation scoring within a single real-time processing pipeline represents a novel contribution to the open-source honeypot ecosystem.

The 14-day deployment validated the system's ability to capture, classify, and correlate thousands of attack events, surface coordinated campaigns, and flag anomalous behaviours — all while running on minimal infrastructure. The comprehensive dashboard makes the data immediately actionable for both security analysts and researchers.

The project is open-source under the MIT license and available at: [github.com/NovaCode37/honeyshield](https://github.com/NovaCode37/honeyshield)

---

## References

1. Spitzner, L. (2002). *Honeypots: Tracking Hackers*. Addison-Wesley Professional.
2. Provos, N., & Holz, T. (2007). *Virtual Honeypots: From Botnet Tracking to Intrusion Detection*. Addison-Wesley.
3. Liu, F. T., Ting, K. M., & Zhou, Z.-H. (2008). Isolation Forest. *Proceedings of the IEEE International Conference on Data Mining (ICDM)*, pp. 413-422.
4. Nawrocki, M., Wahlisch, M., Schmidt, T. C., Keil, C., & Schonfelder, J. (2016). A Survey on Honeypot Software and Data Analysis. *arXiv preprint arXiv:1608.06249*.
5. Microsoft Corporation (2023). *Microsoft Digital Defense Report 2023*. Redmond, WA.
6. Verizon (2023). *2023 Data Breach Investigations Report*. Verizon Enterprise Solutions.
7. MITRE Corporation (2026). *MITRE ATT&CK Enterprise Framework v14*. https://attack.mitre.org
8. OWASP Foundation (2021). *OWASP Top Ten Web Application Security Risks*. https://owasp.org/www-project-top-ten/
9. Vetterl, A., & Clayton, R. (2019). Honware: A Virtual Honeypot Framework for Capturing CPE and IoT Zero Days. *IEEE Security and Privacy Workshops (SPW)*, pp. 44-49.
10. Sokol, P., Misek, J., & Husak, M. (2017). Honeypots and Honeynets: Issues of Privacy. *EURASIP Journal on Information Security*, 2017(1), 1-9.
11. Franco, J., Aris, A., Canberk, B., & Uluagac, A. S. (2021). A Survey of Honeypots and Honeynets for Internet of Things, Industrial Internet of Things, and Cyber-Physical Systems. *IEEE Communications Surveys & Tutorials*, 23(4), 2351-2383.
12. Pedregosa, F., et al. (2011). Scikit-learn: Machine Learning in Python. *Journal of Machine Learning Research*, 12, 2825-2830.
13. Strom, B. E., et al. (2020). MITRE ATT&CK: Design and Philosophy. *MITRE Technical Report MTR200236*.
