from dataclasses import dataclass
from typing import Optional


@dataclass
class MitreTechnique:
    id: str
    name: str
    tactic: str
    url: str
    severity: str


_TECHNIQUES: dict[str, MitreTechnique] = {
    "T1046": MitreTechnique(
        id="T1046",
        name="Network Service Discovery",
        tactic="Discovery",
        url="https://attack.mitre.org/techniques/T1046/",
        severity="low",
    ),
    "T1110.001": MitreTechnique(
        id="T1110.001",
        name="Brute Force: Password Guessing",
        tactic="Credential Access",
        url="https://attack.mitre.org/techniques/T1110/001/",
        severity="high",
    ),
    "T1110.003": MitreTechnique(
        id="T1110.003",
        name="Brute Force: Password Spraying",
        tactic="Credential Access",
        url="https://attack.mitre.org/techniques/T1110/003/",
        severity="high",
    ),
    "T1190": MitreTechnique(
        id="T1190",
        name="Exploit Public-Facing Application",
        tactic="Initial Access",
        url="https://attack.mitre.org/techniques/T1190/",
        severity="critical",
    ),
    "T1059.004": MitreTechnique(
        id="T1059.004",
        name="Command and Scripting Interpreter: Unix Shell",
        tactic="Execution",
        url="https://attack.mitre.org/techniques/T1059/004/",
        severity="critical",
    ),
    "T1083": MitreTechnique(
        id="T1083",
        name="File and Directory Discovery",
        tactic="Discovery",
        url="https://attack.mitre.org/techniques/T1083/",
        severity="medium",
    ),
    "T1133": MitreTechnique(
        id="T1133",
        name="External Remote Services",
        tactic="Persistence",
        url="https://attack.mitre.org/techniques/T1133/",
        severity="medium",
    ),
    "T1595.001": MitreTechnique(
        id="T1595.001",
        name="Active Scanning: Scanning IP Blocks",
        tactic="Reconnaissance",
        url="https://attack.mitre.org/techniques/T1595/001/",
        severity="low",
    ),
    "T1078": MitreTechnique(
        id="T1078",
        name="Valid Accounts",
        tactic="Defense Evasion",
        url="https://attack.mitre.org/techniques/T1078/",
        severity="high",
    ),
    "T1505.003": MitreTechnique(
        id="T1505.003",
        name="Server Software Component: Web Shell",
        tactic="Persistence",
        url="https://attack.mitre.org/techniques/T1505/003/",
        severity="critical",
    ),
    "T1592": MitreTechnique(
        id="T1592",
        name="Gather Victim Host Information",
        tactic="Reconnaissance",
        url="https://attack.mitre.org/techniques/T1592/",
        severity="low",
    ),
    "T1212": MitreTechnique(
        id="T1212",
        name="Exploitation for Credential Access",
        tactic="Credential Access",
        url="https://attack.mitre.org/techniques/T1212/",
        severity="critical",
    ),
    "T1059.007": MitreTechnique(
        id="T1059.007",
        name="Command and Scripting Interpreter: JavaScript",
        tactic="Execution",
        url="https://attack.mitre.org/techniques/T1059/007/",
        severity="high",
    ),
}

def tag_attack(attack: dict) -> list[MitreTechnique]:
    service = (attack.get("service") or "").lower()
    payload = (attack.get("payload") or "").lower()
    path    = (attack.get("path") or "").lower()
    ua      = (attack.get("user_agent") or "").lower()
    method  = (attack.get("method") or "").lower()

    tags: list[MitreTechnique] = []
    seen: set[str] = set()

    def _add(tid: str) -> None:
        if tid not in seen and tid in _TECHNIQUES:
            tags.append(_TECHNIQUES[tid])
            seen.add(tid)

    if service == "ssh":
        _add("T1110.001")
        if attack.get("username") and attack.get("password"):
            cred_combo = f"{attack['username']}:{attack['password']}"
            if "pi" in cred_combo or "raspberry" in cred_combo:
                _add("T1110.003")

    if service == "ftp":
        _add("T1133")
        _add("T1110.001")

    if service == "http":
        if not path or path == "/" or ua in ("", "-"):
            _add("T1595.001")

        if any(kw in payload + path for kw in ("union select", "select *", "drop table", "' or ", "1=1")):
            _add("T1190")
            _add("T1212")

        if any(kw in payload + path + ua for kw in ("${jndi:", ";wget ", ";curl ", "/bin/sh", "/bin/bash", "() {")):
            _add("T1059.004")
            _add("T1190")

        if any(kw in path for kw in ("/.env", "/wp-config", "/.git", "/.ssh")):
            _add("T1083")

        if any(kw in path for kw in ("/wp-login", "/xmlrpc.php")):
            _add("T1110.003")
            _add("T1078")

        if any(kw in path for kw in ("/phpmyadmin", "/pma", "/admin", "/manager")):
            _add("T1133")

        if any(kw in path for kw in ("/cgi-bin", "/shell", "/cmd", "/backdoor", "/webshell")):
            _add("T1505.003")
            _add("T1190")

        if any(kw in payload + path for kw in ("<script", "onerror=", "javascript:", "alert(")):
            _add("T1059.007")

        if ua and len(ua) > 200:
            _add("T1592")

    if not tags:
        _add("T1046")

    return tags

def tags_to_dicts(tags: list[MitreTechnique]) -> list[dict]:
    return [
        {
            "id":       t.id,
            "name":     t.name,
            "tactic":   t.tactic,
            "url":      t.url,
            "severity": t.severity,
        }
        for t in tags
    ]

def get_all_techniques() -> list[dict]:
    return [
        {
            "id":       t.id,
            "name":     t.name,
            "tactic":   t.tactic,
            "url":      t.url,
            "severity": t.severity,
        }
        for t in _TECHNIQUES.values()
    ]
