import logging
from typing import Optional
from datetime import datetime
from collections import defaultdict

logger = logging.getLogger(__name__)

_LEVEL_MAP = [
    (90, "critical"),
    (75, "high"),
    (50, "medium"),
    (25, "low"),
    (0,  "info"),
]


def score_to_level(score: int) -> str:
    for threshold, level in _LEVEL_MAP:
        if score >= threshold:
            return level
    return "info"

def _level_color(level: str) -> str:
    return {
        "critical": "#f85149",
        "high":     "#d29922",
        "medium":   "#58a6ff",
        "low":      "#3fb950",
        "info":     "#8b949e",
    }.get(level, "#8b949e")

def score_ip(ip: str, attacks: list[dict]) -> dict:
    score = 0
    reasons: list[str] = []

    count = len(attacks)
    if count == 0:
        return {
            "ip": ip, "score": 0, "level": "info",
            "color": _level_color("info"), "reasons": ["No attacks recorded"],
            "attack_count": 0,
        }

    if count >= 200:
        score += 35
        reasons.append(f"Very high volume: {count} attacks")
    elif count >= 50:
        score += 20
        reasons.append(f"High volume: {count} attacks")
    elif count >= 10:
        score += 10
        reasons.append(f"Moderate volume: {count} attacks")

    services = {a.get("service") for a in attacks if a.get("service")}
    if len(services) >= 2:
        score += 15
        reasons.append(f"Multi-vector attack ({', '.join(services).upper()})")

    exploit_keywords = ["rce_attempt", "sql_injection", "${jndi:", "/bin/sh", "union select"]
    payloads = " ".join((a.get("payload") or "") for a in attacks).lower()
    if any(kw in payloads for kw in exploit_keywords):
        score += 15
        reasons.append("Exploit payloads detected (RCE/SQLi)")

    off_hours_count = 0
    for a in attacks:
        ts = a.get("timestamp", "")
        try:
            hour = datetime.fromisoformat(ts).hour
            if hour < 5:
                off_hours_count += 1
        except Exception:
            pass
    if off_hours_count > 3:
        score += 10
        reasons.append(f"Off-hours activity ({off_hours_count} attacks between 00:00-05:00)")

    dates = set()
    for a in attacks:
        ts = a.get("timestamp", "")
        if ts:
            dates.add(ts[:10])
    if len(dates) >= 3:
        score += 10
        reasons.append(f"Persistent actor — active on {len(dates)} different days")

    passwords = [a.get("password") or "" for a in attacks if a.get("password")]
    if len(passwords) > 20:
        score += 5
        reasons.append(f"Large credential dictionary ({len(passwords)} unique passwords tried)")

    payloads_list = [(a.get("payload") or "").lower() for a in attacks]
    if all("scan" in p or p == "" for p in payloads_list):
        score = max(0, score - 10)
        reasons.append("Generic scanner (low threat)")

    score = max(0, min(100, score))
    level = score_to_level(score)

    return {
        "ip":           ip,
        "score":        score,
        "level":        level,
        "color":        _level_color(level),
        "reasons":      reasons,
        "attack_count": count,
        "services":     list(services),
        "days_active":  len(dates),
    }

def rank_threats(all_attacks: list[dict], top_n: int = 20) -> list[dict]:
    by_ip: dict[str, list[dict]] = {}
    for a in all_attacks:
        ip = a.get("src_ip") or "unknown"
        by_ip.setdefault(ip, []).append(a)

    scored = [score_ip(ip, attacks) for ip, attacks in by_ip.items()]
    scored.sort(key=lambda x: x["score"], reverse=True)
    return scored[:top_n]

def detect_campaigns(all_attacks: list[dict], threshold: int = 5) -> list[dict]:
    password_groups: dict[str, list[str]] = defaultdict(list)
    for a in all_attacks:
        pwd = a.get("password")
        ip  = a.get("src_ip")
        if pwd and ip:
            password_groups[pwd].append(ip)

    campaigns = []
    for credential, ips in password_groups.items():
        unique_ips = set(ips)
        if len(unique_ips) >= threshold:
            campaigns.append({
                "type":       "credential_sharing",
                "indicator":  credential,
                "ip_count":   len(unique_ips),
                "total_hits": len(ips),
                "description": (
                    f"Password '{credential}' used by {len(unique_ips)} "
                    f"distinct IPs — indicates shared credential list"
                ),
            })

    ua_groups: dict[str, list[str]] = defaultdict(list)
    for a in all_attacks:
        ua = a.get("user_agent")
        ip = a.get("src_ip")
        if ua and ip and len(ua) > 5:
            ua_groups[ua].append(ip)

    for ua, ips in ua_groups.items():
        unique_ips = set(ips)
        if len(unique_ips) >= threshold:
            campaigns.append({
                "type":       "tool_sharing",
                "indicator":  ua[:80],
                "ip_count":   len(unique_ips),
                "total_hits": len(ips),
                "description": (
                    f"User-Agent '{ua[:60]}' observed from {len(unique_ips)} "
                    f"IPs — indicates same scanning tool"
                ),
            })

    campaigns.sort(key=lambda x: x["ip_count"], reverse=True)
    return campaigns[:10]
