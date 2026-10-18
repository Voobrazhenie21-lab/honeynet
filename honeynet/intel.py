"""HoneyNet Threat Intelligence & Enrichment Engine.

Provides IP categorization (RFC1918, bogon, public), offline threat scoring,
MITRE ATT&CK mapping, Wazuh CDB rule generation, and optional AbuseIPDB/ThreatPulse enrichment.
Zero-dependency (stdlib only).
"""
from __future__ import annotations

import ipaddress
import json
import math
import os
import re
import shlex
import subprocess
import time
import urllib.request
import urllib.error
from typing import Any

_ABUSEIPDB_CACHE: dict[str, tuple[float, dict[str, Any] | None]] = {}

# MITRE ATT&CK Matrix Mapping
MITRE_MAPPING = {
    "http_probe": {"id": "T1190", "name": "Exploit Public-Facing Application", "tactic": "Initial Access"},
    "ssh_bruteforce": {"id": "T1110.001", "name": "Password Guessing", "tactic": "Credential Access"},
    "http_auth_brute": {"id": "T1110", "name": "Brute Force", "tactic": "Credential Access"},
    "sensitive_file_read": {"id": "T1005", "name": "Data from Local System", "tactic": "Collection"},
    "system_discovery": {"id": "T1082", "name": "System Information Discovery", "tactic": "Discovery"},
    "account_discovery": {"id": "T1087.001", "name": "Local Account Discovery", "tactic": "Discovery"},
    "malware_download": {"id": "T1105", "name": "Ingress Tool Transfer", "tactic": "Command and Control"},
    "reverse_shell": {"id": "T1059.004", "name": "Unix Shell", "tactic": "Execution"},
    "credential_access": {"id": "T1003.008", "name": "/etc/passwd and /etc/shadow", "tactic": "Credential Access"}
}

# High-risk path patterns for HTTP probes
HIGH_RISK_PATHS = [
    (re.compile(r"/\.env", re.I), "sensitive_file_read", 35, "Environment variable file probe"),
    (re.compile(r"/\.git", re.I), "sensitive_file_read", 30, "Git repository disclosure probe"),
    (re.compile(r"/wp-(login|admin|content)", re.I), "http_probe", 25, "WordPress CMS vulnerability probe"),
    (re.compile(r"/xmlrpc\.php", re.I), "http_auth_brute", 25, "WordPress XML-RPC brute-force probe"),
    (re.compile(r"/phpmyadmin|/pma", re.I), "http_probe", 30, "phpMyAdmin database portal probe"),
    (re.compile(r"/(shell|cmd|backdoor|wso|c99)\.php", re.I), "http_probe", 45, "Web shell backdoor probe"),
    (re.compile(r"/actuator(/env|/health)?", re.I), "http_probe", 35, "Spring Boot actuator probe"),
    (re.compile(r"/\.aws/(credentials|config)", re.I), "sensitive_file_read", 45, "Cloud credentials probe"),
    (re.compile(r"/(config|settings)\.(json|yml|yaml|ini)", re.I), "sensitive_file_read", 25, "Configuration file leak probe"),
]

# Command pattern heuristics for SSH honeypot
COMMAND_PATTERNS = [
    (re.compile(r"\b(cat|grep|head|tail)\s+/etc/shadow\b"), "credential_access", 45),
    (re.compile(r"\b(cat|grep|head|tail)\s+/etc/passwd\b"), "account_discovery", 25),
    (re.compile(r"\b(wget|curl)\s+https?://"), "malware_download", 40),
    (re.compile(r"\b(bash\s+-i|nc\s+-e|sh\s+-i|python\b.*pty\.spawn)\b"), "reverse_shell", 50),
    (re.compile(r"\b(chmod\s+(\+x|777|755))\b"), "malware_download", 25),
    (re.compile(r"\b(uname\s+-a|id|whoami|hostname|w|uptime)\b"), "system_discovery", 15),
]


def classify_ip(ip_str: str) -> dict[str, Any]:
    """Inspect IP address and return categorization metadata."""
    try:
        ip = ipaddress.ip_address(ip_str.strip())
    except ValueError:
        return {"ip": ip_str, "valid": False, "category": "invalid", "is_bogon": True}

    if ip.is_loopback:
        category = "loopback"
        is_bogon = True
    elif ip.is_private:
        category = "private_rfc1918"
        is_bogon = True
    elif ip.is_link_local:
        category = "link_local"
        is_bogon = True
    elif ip.is_multicast:
        category = "multicast"
        is_bogon = True
    elif ip.is_reserved:
        category = "reserved"
        is_bogon = True
    else:
        category = "public_routable"
        is_bogon = False

    return {
        "ip": str(ip),
        "valid": True,
        "version": ip.version,
        "category": category,
        "is_bogon": is_bogon,
    }


def shannon_entropy(data: str) -> float:
    """Calculate Shannon Entropy in bits per character."""
    if not data:
        return 0.0
    freq = {}
    for char in data:
        freq[char] = freq.get(char, 0) + 1
    length = len(data)
    return round(-sum((count / length) * math.log2(count / length) for count in freq.values()), 3)


def assess_event(
    proto: str,
    src_ip: str,
    kind: str,
    path: str = "",
    command: str = "",
    username: str = "",
    password: str = "",
    config: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Calculate threat score (0-100), risk category, and MITRE mapping."""
    ip_meta = classify_ip(src_ip)
    score = 0
    tags: list[str] = []
    mitre_techniques: list[dict[str, str]] = []

    # Protocol base scoring
    if proto == "ssh":
        score += 25
        tags.append("protocol:ssh")
    elif proto == "http":
        score += 15
        tags.append("protocol:http")

    # Event kind evaluation
    if kind == "auth_attempt":
        score += 25
        tags.append("action:auth_brute")
        technique = MITRE_MAPPING["ssh_bruteforce"] if proto == "ssh" else MITRE_MAPPING["http_auth_brute"]
        mitre_techniques.append(technique)

        # High entropy or common attacker default passwords
        if username.lower() in ("root", "admin", "administrator", "ubuntu", "guest", "oracle", "test"):
            score += 10
            tags.append("cred:privileged_target")

        if password:
            ent = shannon_entropy(password)
            if ent > 3.8:
                score += 5
                tags.append("cred:high_entropy_pwd")

    # Path heuristics for HTTP
    if path:
        for pattern, m_key, weight, label in HIGH_RISK_PATHS:
            if pattern.search(path):
                score += weight
                tags.append(f"probe:{label.lower().replace(' ', '_')}")
                if m_key in MITRE_MAPPING and MITRE_MAPPING[m_key] not in mitre_techniques:
                    mitre_techniques.append(MITRE_MAPPING[m_key])
                break

    # Command heuristics for SSH
    if command:
        tags.append("action:command_exec")
        for pattern, m_key, weight in COMMAND_PATTERNS:
            if pattern.search(command):
                score += weight
                if m_key in MITRE_MAPPING and MITRE_MAPPING[m_key] not in mitre_techniques:
                    mitre_techniques.append(MITRE_MAPPING[m_key])

    # Bogon / local traffic penalty (less critical than true external adversary)
    if ip_meta.get("is_bogon"):
        score = min(score, 45)
        tags.append("net:bogon_or_internal")
    else:
        tags.append("net:public_adversary")

    final_score = min(100, max(0, score))

    if final_score >= 75:
        severity = "CRITICAL"
    elif final_score >= 50:
        severity = "HIGH"
    elif final_score >= 25:
        severity = "MEDIUM"
    else:
        severity = "LOW"

    # Wazuh CDB record generation
    primary_mitre = mitre_techniques[0]["id"] if mitre_techniques else "T1190"
    wazuh_cdb = f"{src_ip}:{severity.lower()}:{primary_mitre}:block"

    intel_result: dict[str, Any] = {
        "score": final_score,
        "severity": severity,
        "ip_meta": ip_meta,
        "tags": tags,
        "mitre": mitre_techniques,
        "wazuh_cdb": wazuh_cdb,
    }

    # Optional AbuseIPDB API enrichment (cached)
    if config:
        abuse_key = config.get("intel", {}).get("abuseipdb_api_key", "").strip()
        if abuse_key and not ip_meta.get("is_bogon"):
            now_mono = time.monotonic()
            cached = _ABUSEIPDB_CACHE.get(src_ip)
            if cached and (now_mono - cached[0] < 3600):
                abuse_data = cached[1]
            else:
                abuse_data = query_abuseipdb(src_ip, abuse_key)
                _ABUSEIPDB_CACHE[src_ip] = (now_mono, abuse_data)

            if abuse_data:
                intel_result["abuseipdb"] = abuse_data
                conf_score = int(abuse_data.get("abuseConfidenceScore", 0))
                if conf_score > 0:
                    new_score = min(100, max(intel_result["score"], conf_score))
                    intel_result["score"] = new_score
                    tags.append(f"abuseipdb:score_{conf_score}")
                    if new_score >= 75:
                        severity = "CRITICAL"
                    elif new_score >= 50:
                        severity = "HIGH"
                    elif new_score >= 25:
                        severity = "MEDIUM"
                    else:
                        severity = "LOW"
                    intel_result["severity"] = severity
                    intel_result["wazuh_cdb"] = f"{src_ip}:{severity.lower()}:{primary_mitre}:block"

    # Optional ThreatPulse CLI enrichment
    if config:
        tp_cmd = config.get("intel", {}).get("threatpulse_cmd")
        if tp_cmd and not ip_meta.get("is_bogon"):
            tp_data = run_threatpulse_enrichment(src_ip, tp_cmd)
            if tp_data:
                intel_result["threatpulse"] = tp_data
                if "threat_score" in tp_data:
                    new_score = min(100, max(intel_result["score"], int(tp_data["threat_score"])))
                    intel_result["score"] = new_score
                    if new_score >= 75:
                        severity = "CRITICAL"
                    elif new_score >= 50:
                        severity = "HIGH"
                    elif new_score >= 25:
                        severity = "MEDIUM"
                    else:
                        severity = "LOW"
                    intel_result["severity"] = severity
                    intel_result["wazuh_cdb"] = f"{src_ip}:{severity.lower()}:{primary_mitre}:block"

    return intel_result


def run_threatpulse_enrichment(ip: str, cmd_template: str) -> dict[str, Any] | None:
    """Execute local ThreatPulse CLI for IOC enrichment."""
    try:
        cmd_str = cmd_template.replace("{ip}", ip)
        if "{ip}" not in cmd_template:
            cmd_str = f"{cmd_template} {ip}"
        cmd_args = shlex.split(cmd_str, posix=(os.name != "nt"))
        proc = subprocess.run(cmd_args, capture_output=True, text=True, timeout=3)
        if proc.returncode == 0 and proc.stdout:
            try:
                return json.loads(proc.stdout)
            except json.JSONDecodeError:
                return {"raw_output": proc.stdout.strip()}
    except (subprocess.SubprocessError, OSError):
        return None
    return None


def query_abuseipdb(ip: str, api_key: str, max_age_days: int = 90) -> dict[str, Any] | None:
    """Query AbuseIPDB API v2 with standard library urllib."""
    if not api_key or not ip:
        return None
    url = f"https://api.abuseipdb.com/api/v2/check?ipAddress={ip}&maxAgeInDays={max_age_days}"
    req = urllib.request.Request(
        url,
        headers={
            "Key": api_key,
            "Accept": "application/json",
            "User-Agent": "HoneyNet-SOC-Honeypot/1.0"
        }
    )
    try:
        with urllib.request.urlopen(req, timeout=3.5) as resp:
            if resp.status == 200:
                body = json.loads(resp.read().decode("utf-8"))
                return body.get("data")
    except (urllib.error.URLError, TimeoutError, OSError, json.JSONDecodeError):
        return None
    return None
