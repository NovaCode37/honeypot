import argparse
import os
import sys
from datetime import datetime

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

try:
    from fpdf import FPDF, XPos, YPos
except ImportError:
    print("fpdf2 not installed. Run: pip install fpdf2")
    sys.exit(1)


C_BG       = (11,  17,  29)
C_SURFACE  = (20,  28,  46)
C_SURFACE2 = (28,  38,  62)
C_BORDER   = (44,  64,  94)
C_ACCENT   = (41,  128, 185)
C_WHITE    = (232, 240, 252)
C_MUTED    = (110, 140, 175)
C_RED      = (231, 76,  60)
C_ORANGE   = (211, 110, 40)
C_YELLOW   = (230, 180, 20)
C_GREEN    = (39,  174, 96)
C_PURPLE   = (142, 68,  173)
C_CYAN     = (22,  160, 133)
C_DARK     = (7,   11,  20)


class HoneyShieldReport(FPDF):

    _is_cover = False

    def header(self):
        self.set_fill_color(*C_BG)
        self.rect(0, 0, 210, 297, "F")
        if self._is_cover:
            return
        self.set_fill_color(*C_DARK)
        self.rect(0, 0, 210, 14, "F")
        self.set_fill_color(*C_ACCENT)
        self.rect(0, 14, 210, 0.7, "F")
        self.set_fill_color(*C_RED)
        self.rect(10, 4.5, 4.5, 4.5, "F")
        self.set_font("Helvetica", "B", 8)
        self.set_text_color(*C_WHITE)
        self.set_xy(17, 4)
        self.cell(60, 5, "HONEYSHIELD", align="L")
        self.set_font("Helvetica", "", 7)
        self.set_text_color(*C_MUTED)
        self.set_xy(17, 9.2)
        self.cell(60, 4, "Threat Intelligence Platform", align="L")
        self.set_font("Helvetica", "", 7)
        self.set_text_color(*C_MUTED)
        self.set_xy(0, 6)
        self.cell(200, 4, f"CONFIDENTIAL  |  {datetime.now().strftime('%d %B %Y')}", align="R")
        self.set_y(19)

    def footer(self):
        if self._is_cover:
            return
        self.set_fill_color(*C_DARK)
        self.rect(0, 285, 210, 12, "F")
        self.set_fill_color(*C_ACCENT)
        self.rect(0, 285, 210, 0.5, "F")
        self.set_font("Helvetica", "", 7)
        self.set_text_color(*C_MUTED)
        self.set_xy(12, 288.5)
        self.cell(90, 5, "HoneyShield v2.0  |  MIT License", align="L")
        self.set_xy(0, 288.5)
        self.cell(196, 5, f"Page {self.page_no()} / {{nb}}", align="R")

    def section_header(self, number: str, title: str, color=C_ACCENT):
        self.ln(5)
        y = self.get_y()
        self.set_fill_color(*C_SURFACE)
        self.rect(10, y, 190, 11, "F")
        self.set_fill_color(*color)
        self.rect(10, y, 4, 11, "F")
        self.set_font("Helvetica", "B", 8)
        self.set_text_color(*color)
        self.set_xy(17, y + 2)
        self.cell(14, 7, number, align="L")
        self.set_font("Helvetica", "B", 10)
        self.set_text_color(*C_WHITE)
        self.set_xy(30, y + 2)
        self.cell(165, 7, title.upper(), align="L")
        self.ln(15)

    def subsection(self, text: str, color=C_ACCENT):
        self.ln(2)
        y = self.get_y()
        self.set_fill_color(*color)
        self.rect(12, y, 2, 6, "F")
        self.set_font("Helvetica", "B", 9)
        self.set_text_color(*C_WHITE)
        self.set_xy(17, y)
        self.cell(0, 6, text, align="L")
        self.ln(8)

    def body_text(self, text: str):
        self.set_font("Helvetica", "", 8.5)
        self.set_text_color(*C_MUTED)
        self.set_x(12)
        self.multi_cell(186, 5, text)
        self.ln(2)

    def kv_table(self, rows: list, col_widths=(70, 118), header=None):
        self.set_line_width(0.15)
        x = 12
        w1, w2 = col_widths
        if header:
            self.set_fill_color(*C_SURFACE2)
            self.set_draw_color(*C_BORDER)
            self.set_font("Helvetica", "B", 8)
            self.set_text_color(*C_ACCENT)
            self.set_x(x)
            self.cell(w1, 7.5, f"  {header[0]}", border=1, fill=True)
            self.cell(w2, 7.5, f"  {header[1]}", border=1, fill=True,
                      new_x=XPos.LMARGIN, new_y=YPos.NEXT)
        for i, (k, v) in enumerate(rows):
            bg = C_SURFACE if i % 2 == 0 else C_SURFACE2
            self.set_fill_color(*bg)
            self.set_draw_color(*C_BORDER)
            self.set_x(x)
            self.set_font("Helvetica", "", 8)
            self.set_text_color(*C_MUTED)
            self.cell(w1, 6.5, f"  {k}", border=1, fill=True)
            self.set_font("Helvetica", "B", 8)
            self.set_text_color(*C_WHITE)
            self.cell(w2, 6.5, f"  {str(v)}", border=1, fill=True,
                      new_x=XPos.LMARGIN, new_y=YPos.NEXT)
        self.ln(3)

    def three_col_table(self, header_row: tuple, data_rows: list,
                        col_widths=(45, 52, 91)):
        self.set_line_width(0.15)
        x = 12
        w1, w2, w3 = col_widths
        self.set_fill_color(*C_SURFACE2)
        self.set_draw_color(*C_BORDER)
        self.set_font("Helvetica", "B", 8)
        self.set_text_color(*C_ACCENT)
        self.set_x(x)
        for cell_text, w in zip(header_row, [w1, w2, w3]):
            self.cell(w, 7.5, f"  {cell_text}", border=1, fill=True)
        self.ln(7.5)
        for i, row in enumerate(data_rows):
            bg = C_SURFACE if i % 2 == 0 else C_SURFACE2
            self.set_fill_color(*bg)
            self.set_draw_color(*C_BORDER)
            self.set_x(x)
            col_colors = [C_MUTED, C_GREEN, C_MUTED]
            col_styles = ["", "B", ""]
            for cell_text, w, col, style in zip(row, [w1, w2, w3],
                                                col_colors, col_styles):
                self.set_font("Helvetica", style, 8)
                self.set_text_color(*col)
                self.cell(w, 6.5, f"  {cell_text}", border=1, fill=True)
            self.ln(6.5)
        self.ln(3)

    def bar_row(self, label: str, value: int, max_val: int,
                color=C_ACCENT, suffix=""):
        bar_w = 95
        filled = int(bar_w * value / max_val) if max_val > 0 else 0
        y = self.get_y()
        x = 12
        self.set_font("Helvetica", "", 8)
        self.set_text_color(*C_MUTED)
        self.set_xy(x, y + 1)
        self.cell(52, 5, label, align="L")
        self.set_fill_color(*C_SURFACE2)
        self.rect(x + 54, y + 2, bar_w, 4, "F")
        if filled > 0:
            self.set_fill_color(*color)
            self.rect(x + 54, y + 2, filled, 4, "F")
        self.set_font("Helvetica", "B", 8)
        self.set_text_color(*C_WHITE)
        self.set_xy(x + 152, y + 1)
        self.cell(44, 5, f"{value:,}{suffix}", align="R")
        self.ln(7.5)

    def threat_row(self, ip: str, score: int, level: str, attacks: int):
        level_cols = {
            "critical": C_RED,    "high": C_ORANGE,
            "medium":   C_YELLOW, "low":  C_GREEN, "info": C_MUTED,
        }
        badge_txt_cols = {
            "critical": C_WHITE, "high": C_WHITE,
            "medium":   C_DARK,  "low":  C_WHITE, "info": C_WHITE,
        }
        col     = level_cols.get(level.lower(), C_MUTED)
        txt_col = badge_txt_cols.get(level.lower(), C_WHITE)
        y, x = self.get_y(), 12
        self.set_fill_color(*C_SURFACE)
        self.rect(x, y, 186, 8.5, "F")
        self.set_fill_color(*col)
        self.rect(x, y, 2.5, 8.5, "F")
        bar_fill = int(55 * score / 100)
        self.set_fill_color(*C_SURFACE2)
        self.rect(x + 65, y + 2.5, 55, 3, "F")
        if bar_fill > 0:
            self.set_fill_color(*col)
            self.rect(x + 65, y + 2.5, bar_fill, 3, "F")
        self.set_font("Helvetica", "B", 8)
        self.set_text_color(*C_WHITE)
        self.set_xy(x + 5, y + 2)
        self.cell(58, 5, ip)
        self.set_font("Helvetica", "B", 8)
        self.set_text_color(*col)
        self.set_xy(x + 122, y + 2)
        self.cell(24, 5, f"{score}/100", align="C")
        self.set_fill_color(*col)
        self.set_text_color(*txt_col)
        self.set_font("Helvetica", "B", 7)
        self.set_xy(x + 148, y + 2)
        self.cell(24, 4.5, level.upper(), fill=True, align="C")
        self.set_font("Helvetica", "", 7.5)
        self.set_text_color(*C_MUTED)
        self.set_xy(x + 175, y + 2)
        self.cell(20, 5, f"{attacks:,} atk", align="R")
        self.ln(10)

    def stat_blocks(self, items: list):
        n   = len(items)
        w   = 186 // n
        x   = 12
        y   = self.get_y()
        for label, value, color in items:
            self.set_fill_color(*C_SURFACE)
            self.rect(x, y, w - 3, 22, "F")
            self.set_fill_color(*color)
            self.rect(x, y, w - 3, 2, "F")
            self.set_font("Helvetica", "B", 16)
            self.set_text_color(*color)
            self.set_xy(x + 2, y + 4)
            self.cell(w - 7, 10, str(value), align="C")
            self.set_font("Helvetica", "", 6.5)
            self.set_text_color(*C_MUTED)
            self.set_xy(x + 2, y + 15)
            self.cell(w - 7, 5, label, align="C")
            x += w
        self.ln(26)


def _load_stats():
    try:
        sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
        from database.models import get_stats, get_intel_summary, get_recent_attacks
        from intelligence.reputation import rank_threats
        stats    = get_stats()
        intel    = get_intel_summary()
        attacks  = get_recent_attacks(5000)
        threats  = rank_threats(attacks, top_n=10)
        return stats, intel, threats
    except Exception as e:
        print(f"[warn] Could not load live DB data: {e}. Using demo data.")
        return _demo_stats()


def _demo_stats():
    stats = {
        "total": 14283, "unique_ips": 3847,
        "by_service": [
            {"service": "ssh",  "cnt": 9847},
            {"service": "http", "cnt": 4436},
        ],
        "top_countries": [
            {"country": "China",         "cnt": 3241},
            {"country": "Russia",        "cnt": 2108},
            {"country": "United States", "cnt": 1847},
            {"country": "Netherlands",   "cnt": 1203},
            {"country": "Germany",       "cnt": 987},
        ],
        "top_passwords": [
            {"password": "123456",   "cnt": 1847},
            {"password": "password", "cnt": 1203},
            {"password": "admin",    "cnt": 987},
            {"password": "root",     "cnt": 834},
            {"password": "raspberry","cnt": 623},
        ],
        "top_ips": [
            {"src_ip": "185.220.101.45", "cnt": 342},
            {"src_ip": "45.33.32.156",   "cnt": 287},
            {"src_ip": "198.199.100.23", "cnt": 201},
        ],
    }
    intel = {
        "threat_levels": [
            {"threat_level": "critical", "cnt": 182},
            {"threat_level": "high",     "cnt": 1847},
            {"threat_level": "medium",   "cnt": 4436},
            {"threat_level": "low",      "cnt": 7818},
        ],
        "top_techniques": [
            {"id": "T1110.001", "count": 9847},
            {"id": "T1190",     "count": 487},
            {"id": "T1083",     "count": 892},
            {"id": "T1595.001", "count": 634},
            {"id": "T1110.003", "count": 1847},
        ],
        "campaigns": [
            {"password": "raspberry", "ip_cnt": 234, "total": 623},
            {"password": "oracle",    "ip_cnt": 89,  "total": 312},
        ],
    }
    threats = [
        {"ip": "185.220.101.45", "score": 87, "level": "high",     "attack_count": 342},
        {"ip": "45.33.32.156",   "score": 74, "level": "medium",   "attack_count": 287},
        {"ip": "198.199.100.23", "score": 61, "level": "medium",   "attack_count": 201},
    ]
    return stats, intel, threats


def build_report(output_path: str = "docs/HoneyShield_Report.pdf") -> None:
    stats, intel, threats = _load_stats()

    pdf = HoneyShieldReport()
    pdf.alias_nb_pages()
    pdf.set_auto_page_break(auto=True, margin=22)
    pdf.set_margins(10, 22, 10)

    total    = stats.get("total", 0)
    uips     = stats.get("unique_ips", 0)
    by_svc   = {s["service"]: s["cnt"] for s in stats.get("by_service", [])}
    ssh_cnt  = by_svc.get("ssh",  0)
    http_cnt = by_svc.get("http", 0)
    ftp_cnt  = by_svc.get("ftp",  0)

    pdf._is_cover = True
    pdf.add_page()
    pdf._is_cover = False

    pdf.set_draw_color(*C_ACCENT)
    pdf.set_line_width(0.6)
    pdf.rect(12, 32, 186, 198, "D")
    pdf.set_fill_color(*C_ACCENT)
    pdf.rect(12, 32, 186, 2.5, "F")
    pdf.rect(12, 227.5, 186, 2.5, "F")

    pdf.set_font("Helvetica", "B", 48)
    pdf.set_text_color(*C_WHITE)
    pdf.set_xy(12, 56)
    pdf.cell(186, 24, "HONEYSHIELD", align="C", new_x=XPos.LMARGIN, new_y=YPos.NEXT)

    pdf.set_fill_color(*C_RED)
    pdf.rect(75, 82, 60, 1.5, "F")

    pdf.set_font("Helvetica", "", 12)
    pdf.set_text_color(*C_MUTED)
    pdf.set_xy(12, 87)
    pdf.cell(186, 8, "Real-Time Honeypot & Threat Intelligence Platform", align="C",
             new_x=XPos.LMARGIN, new_y=YPos.NEXT)

    features = [
        ("SSH + HTTP + FTP Honeypots",        C_ACCENT),
        ("MITRE ATT&CK Technique Mapping",    C_PURPLE),
        ("ML Anomaly Detection",              C_GREEN),
        ("Real-Time WebSocket Dashboard",     C_CYAN),
        ("IP Threat Reputation Scoring",      C_RED),
        ("Coordinated Campaign Detection",    C_ORANGE),
    ]
    col_x  = [28, 118]
    row_y  = 106
    for idx, (feat, col) in enumerate(features):
        cx = col_x[idx % 2]
        if idx > 0 and idx % 2 == 0:
            row_y += 12
        pdf.set_fill_color(*col)
        pdf.rect(cx, row_y + 2, 3, 3, "F")
        pdf.set_font("Helvetica", "", 9)
        pdf.set_text_color(*C_WHITE)
        pdf.set_xy(cx + 6, row_y)
        pdf.cell(84, 7, feat, align="L")

    pdf.set_font("Helvetica", "", 7.5)
    pdf.set_text_color(*C_MUTED)
    pdf.set_xy(12, 150)
    pdf.cell(186, 6,
             "Python 3.11  |  Flask 3.0  |  scikit-learn 1.4  |  SQLite  |  Docker",
             align="C")

    pdf.set_fill_color(*C_SURFACE2)
    pdf.rect(68, 163, 74, 14, "F")
    pdf.set_fill_color(*C_ACCENT)
    pdf.rect(68, 163, 74, 1.2, "F")
    pdf.set_font("Helvetica", "B", 9)
    pdf.set_text_color(*C_ACCENT)
    pdf.set_xy(68, 166)
    pdf.cell(74, 5, "v2.0  RELEASE", align="C", new_x=XPos.LMARGIN, new_y=YPos.NEXT)
    pdf.set_font("Helvetica", "", 7)
    pdf.set_text_color(*C_MUTED)
    pdf.set_xy(68, 172)
    pdf.cell(74, 4, "MIT License  |  Open Source", align="C")

    pdf.set_fill_color(*C_DARK)
    pdf.rect(0, 248, 210, 49, "F")
    pdf.set_fill_color(*C_ACCENT)
    pdf.rect(0, 248, 210, 0.8, "F")
    pdf.set_font("Helvetica", "B", 10)
    pdf.set_text_color(*C_WHITE)
    pdf.set_xy(12, 258)
    pdf.cell(186, 7, "Cybersecurity Research Portfolio", align="C")
    pdf.set_font("Helvetica", "", 8)
    pdf.set_text_color(*C_MUTED)
    pdf.set_xy(12, 267)
    pdf.cell(186, 6, f"Report generated {datetime.now().strftime('%B %d, %Y at %H:%M')}", align="C")
    pdf.set_font("Helvetica", "", 7)
    pdf.set_text_color(*C_BORDER)
    pdf.set_xy(12, 276)
    pdf.cell(186, 5, "CONFIDENTIAL - For Authorized Use Only", align="C")

    pdf.add_page()
    pdf.section_header("01", "Executive Summary", C_RED)
    pdf.body_text(
        "HoneyShield is an open-source honeypot and threat intelligence platform designed "
        "to attract, capture, and analyse real-world cyberattacks. The system emulates "
        "three network services - SSH, HTTP (Apache/WordPress), and FTP - on publicly "
        "accessible ports, recording every interaction by automated scanners and malicious "
        "actors.\n\n"
        "Unlike passive monitoring tools, a honeypot has no legitimate users, meaning "
        "every connection is inherently adversarial. This makes honeypots ideal for "
        "building ground-truth datasets, detecting emerging attack campaigns, and "
        "validating machine learning intrusion detection models."
    )
    pdf.stat_blocks([
        ("Total Attacks",     f"{total:,}",    C_RED),
        ("Unique IPs",        f"{uips:,}",     C_ACCENT),
        ("SSH Attempts",      f"{ssh_cnt:,}",  C_PURPLE),
        ("HTTP Probes",       f"{http_cnt:,}", C_GREEN),
        ("FTP Attempts",      f"{ftp_cnt:,}",  C_CYAN),
    ])

    pdf.section_header("02", "System Architecture", C_ACCENT)
    pdf.body_text(
        "HoneyShield follows a four-layer architecture designed for modularity, "
        "extensibility, and zero-dependency data persistence:"
    )
    pdf.kv_table([
        ("Honeypot Layer",     "ssh_honeypot.py (paramiko)  |  http_honeypot.py (stdlib)  |  ftp_honeypot.py"),
        ("Intelligence Layer", "geoip/locator.py  |  intelligence/mitre.py  |  intelligence/reputation.py"),
        ("ML Layer",           "ml/detector.py (scikit-learn IsolationForest + feature extraction)"),
        ("Presentation Layer", "Flask 3.0  |  Flask-SocketIO  |  Leaflet.js  |  Chart.js  |  Tailwind CSS"),
        ("Data Layer",         "SQLite WAL mode  |  3 tables  |  6 indexes  |  parameterised queries"),
        ("Alerting",           "Telegram Bot API  |  SMTP (Gmail / custom relay)"),
        ("Deployment",         "Docker + docker-compose  |  environment-variable configuration"),
    ], header=("Layer", "Components"))

    pdf.section_header("03", "Technology Stack", C_PURPLE)
    pdf.three_col_table(
        header_row=("Component", "Technology", "Justification"),
        data_rows=[
            ("SSH emulation",    "paramiko 3.4",              "Full server-mode API, RSA key exchange"),
            ("HTTP server",      "stdlib http.server",        "Zero dependencies, full response control"),
            ("FTP server",       "raw sockets",               "Custom protocol handler, zero dependencies"),
            ("Database",         "SQLite 3 + WAL",            "Zero-config, concurrent R/W, portable"),
            ("GeoIP",            "ip-api.com",                "Free, no key, 45 req/min, cached 1h"),
            ("Web framework",    "Flask 3.0",                 "Lightweight, well-known, extensible"),
            ("Real-time",        "Flask-SocketIO",            "WebSocket room broadcasting"),
            ("Frontend",         "Tailwind + Chart.js + Leaflet", "Modern, CDN, zero build step"),
            ("ML detection",     "scikit-learn IsolationForest", "Unsupervised, no labelled data needed"),
            ("MITRE mapping",    "Custom rule engine",        "12 techniques, 6 tactics covered"),
            ("Containerisation", "Docker + Compose",          "Reproducible, port remapping"),
        ],
        col_widths=(45, 52, 91),
    )

    pdf.add_page()
    pdf.section_header("04", "Attack Analysis & Results", C_GREEN)

    pdf.subsection("4.1   Attack Distribution by Service", C_GREEN)
    svc_data  = stats.get("by_service", [])
    total_svc = sum(s.get("cnt", 0) for s in svc_data)
    svc_cols  = {"ssh": C_PURPLE, "http": C_GREEN, "ftp": C_CYAN}
    for svc in svc_data:
        pct = (svc["cnt"] / total_svc * 100) if total_svc else 0
        pdf.bar_row(svc["service"].upper(), svc["cnt"], total_svc or 1,
                    svc_cols.get(svc["service"], C_ACCENT),
                    suffix=f"  ({pct:.1f}%)")
    pdf.ln(2)

    pdf.subsection("4.2   Top Attacker Countries", C_GREEN)
    top_countries = stats.get("top_countries", [])[:10]
    max_c = max((c["cnt"] for c in top_countries), default=1)
    for c in top_countries:
        pdf.bar_row(c["country"], c["cnt"], max_c, C_ACCENT)
    pdf.ln(2)

    pdf.subsection("4.3   Most-Tried SSH Credentials", C_GREEN)
    top_pass = stats.get("top_passwords", [])[:8]
    pdf.kv_table(
        [(p["password"], f"{p['cnt']:,} attempts") for p in top_pass],
        header=("Password", "Attempt Count"),
    )

    pdf.section_header("05", "MITRE ATT&CK Mapping", C_PURPLE)
    pdf.body_text(
        "Each attack event is automatically tagged with one or more MITRE ATT&CK "
        "Enterprise technique IDs using payload classification rules. This enables "
        "correlation with known adversary TTPs and compatibility with SIEM/SOAR platforms."
    )
    top_techniques = intel.get("top_techniques", [])[:10]
    mitre_names = {
        "T1110.001": "Brute Force: Password Guessing",
        "T1110.003": "Brute Force: Password Spraying",
        "T1190":     "Exploit Public-Facing Application",
        "T1059.004": "Command and Scripting Interpreter: Unix Shell",
        "T1083":     "File and Directory Discovery",
        "T1133":     "External Remote Services",
        "T1595.001": "Active Scanning: Scanning IP Blocks",
        "T1046":     "Network Service Discovery",
        "T1078":     "Valid Accounts",
        "T1505.003": "Server Software Component: Web Shell",
        "T1212":     "Exploitation for Credential Access",
        "T1592":     "Gather Victim Host Information",
    }
    max_t = max((t["count"] for t in top_techniques), default=1)
    for t in top_techniques:
        label = f"{t['id']}  {mitre_names.get(t['id'], t['id'])}"
        pdf.bar_row(label[:44], t["count"], max_t, C_PURPLE)
    pdf.ln(2)

    pdf.section_header("06", "ML Anomaly Detection", C_YELLOW)
    pdf.body_text(
        "HoneyShield uses scikit-learn's IsolationForest algorithm to detect "
        "statistically unusual attack patterns. The model trains on-demand on "
        "accumulated attack history - no labelled data required (unsupervised).\n\n"
        "Feature vector per attack:\n"
        "  - hour_of_day (sin/cos encoded)  - off-hours attacks score higher\n"
        "  - payload_length (normalised)    - unusually long = exploit attempt\n"
        "  - service_id (categorical)       - cross-service anomalies detected\n"
        "  - is_default_credential (binary) - root/admin/pi credential combos\n"
        "  - path_depth (normalised)        - deep URL paths = directory traversal\n"
        "  - has_special_chars (binary)     - SQLi/shell injection indicators"
    )
    tl_data   = intel.get("threat_levels", [])
    tl_map    = {r["threat_level"]: r["cnt"] for r in tl_data}
    tl_total  = sum(tl_map.values()) or 1
    tl_cols   = {
        "critical": C_RED, "high": C_ORANGE,
        "medium": C_YELLOW, "low": C_GREEN, "info": C_MUTED,
    }
    for level in ["critical", "high", "medium", "low", "info"]:
        pdf.bar_row(level.upper(), tl_map.get(level, 0), tl_total, tl_cols[level])

    pdf.add_page()
    pdf.section_header("07", "IP Threat Reputation Scoring", C_RED)
    pdf.body_text(
        "Each attacker IP receives a composite threat score (0-100) based on "
        "attack volume, multi-vector targeting, exploit indicators, off-hours "
        "activity, and persistence across days.\n"
        "  CRITICAL (>=90)  |  HIGH (>=75)  |  MEDIUM (>=50)  |  LOW (>=25)  |  INFO (<25)"
    )
    if threats:
        pdf.subsection("Top Threat Actors", C_RED)
        for t in threats[:10]:
            pdf.threat_row(t["ip"], t["score"], t["level"], t["attack_count"])
    pdf.ln(2)

    pdf.section_header("08", "Security Design & Ethics", C_MUTED)
    pdf.body_text(
        "The honeypot is engineered to be safe for the operator by design:\n\n"
        "  - Paramiko ALWAYS rejects authentication - no attacker gains shell access\n"
        "  - HTTP responses are static/hardcoded - no server-side code execution\n"
        "  - FTP always returns 530 Login incorrect - no filesystem access granted\n"
        "  - All DB inserts use parameterised queries - no SQL injection risk\n"
        "  - Dashboard protected by session-based authentication\n"
        "  - .env and data/ are in .gitignore - no credential leakage\n"
        "  - GeoIP queries use free-tier ip-api.com - minimal PII exposure\n\n"
        "Ethical note: Deploy only on infrastructure you own and control. "
        "This system is a research tool for understanding attacker behaviour. "
        "All fake credentials in honeypot responses are obviously synthetic."
    )

    pdf.section_header("09", "Future Work", C_ACCENT)
    pdf.kv_table([
        ("Distributed deployment",  "Multi-region network with Kafka + ClickHouse aggregation"),
        ("Full shell emulation",    "Integrate Cowrie for complete SSH session recording"),
        ("PCAP capture",            "Scapy/libpcap for packet-level recording and analysis"),
        ("CVE correlation",         "Automatic CVE database lookup for detected payloads"),
        ("Threat sharing",          "STIX/TAXII export for IOC sharing with threat intel communities"),
        ("Active ML retraining",    "Periodic model retraining as new attack patterns emerge"),
        ("PostgreSQL migration",    "Scalable DB backend for high-volume production deployments"),
    ], header=("Enhancement", "Description"))

    pdf.section_header("10", "References", C_MUTED)
    refs = [
        "1. Spitzner, L. (2002). Honeypots: Tracking Hackers. Addison-Wesley Professional.",
        "2. Provos, N. & Holz, T. (2007). Virtual Honeypots. Addison-Wesley.",
        "3. Microsoft (2023). Microsoft Digital Defense Report 2023.",
        "4. MITRE Corporation (2026). ATT&CK Framework v14. https://attack.mitre.org",
        "5. OWASP Foundation (2021). OWASP Top Ten. https://owasp.org",
        "6. Liu, F.T., Ting, K.M., & Zhou, Z.-H. (2008). Isolation Forest. IEEE ICDM.",
        "7. Nawrocki, M. et al. (2016). A Survey on Honeypot Software. arXiv:1608.06249.",
        "8. Vetterl, A. & Clayton, R. (2019). Honware: A Virtual Honeypot Framework. IEEE S&P.",
    ]
    for ref in refs:
        pdf.set_font("Helvetica", "", 8)
        pdf.set_text_color(*C_MUTED)
        pdf.set_x(12)
        pdf.multi_cell(186, 5, ref)
        pdf.ln(1)

    os.makedirs(os.path.dirname(os.path.abspath(output_path)), exist_ok=True)
    pdf.output(output_path)
    print(f"[OK] Report saved to: {output_path}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Generate HoneyShield PDF report")
    parser.add_argument("--output", default="docs/HoneyShield_Report.pdf",
                        help="Output PDF path")
    args = parser.parse_args()
    build_report(args.output)
