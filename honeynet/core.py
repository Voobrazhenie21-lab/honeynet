"""HoneyNet — low-interaction SSH/HTTP honeypot with dashboard and alerts.

Core primitives: event model, JSONL logging with rotation, configuration.
Zero-dependency (stdlib only); paramiko is required only for the SSH pot.
"""
from __future__ import annotations

import copy
import json
import os
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any

__version__ = "1.0.0"

# Event kinds
AUTH_ATTEMPT = "auth_attempt"
HTTP_REQUEST = "http_request"
COMMAND = "command"
PAYLOAD = "payload"
SESSION = "session"


def now_iso() -> str:
    """Local-time ISO-8601 timestamp with seconds precision."""
    return datetime.now(timezone.utc).astimezone().isoformat(timespec="seconds")


@dataclass
class Event:
    """A single observable honeypot event, serialized as one JSONL line."""

    ts: str
    proto: str                      # "ssh" | "http"
    src_ip: str
    kind: str                       # AUTH_ATTEMPT | HTTP_REQUEST | COMMAND | PAYLOAD | SESSION
    src_port: int = 0
    username: str = ""
    password: str = ""
    method: str = ""
    path: str = ""
    command: str = ""
    detail: str = ""
    tags: list[str] = field(default_factory=list)
    intel: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        """Drop empty fields to keep log lines compact."""
        return {
            k: v
            for k, v in asdict(self).items()
            if v not in ("", None) and v != [] and v != {}
        }


class EventLogger:
    """Append-only JSONL event log with size-based rotation (`.1` backup)."""

    def __init__(self, path: str, rotate_mb: int = 10, alerts: Any = None) -> None:
        self.path = path
        self.rotate_mb = max(1, rotate_mb)
        self.alerts = alerts
        directory = os.path.dirname(path)
        if directory:
            os.makedirs(directory, exist_ok=True)

    def _rotate_if_needed(self) -> None:
        try:
            size = os.path.getsize(self.path)
        except OSError:
            return
        if size >= self.rotate_mb * 1024 * 1024:
            try:
                os.replace(self.path, self.path + ".1")
            except OSError:
                pass

    def write(self, event: Event) -> dict[str, Any]:
        record = event.to_dict()
        self._rotate_if_needed()
        with open(self.path, "a", encoding="utf-8") as fh:
            fh.write(json.dumps(record, ensure_ascii=False) + "\n")
        if self.alerts is not None:
            self.alerts.consider(record)
        return record

    def read_all(self) -> list[dict[str, Any]]:
        try:
            with open(self.path, "r", encoding="utf-8") as fh:
                lines = fh.readlines()
        except OSError:
            return []
        events: list[dict[str, Any]] = []
        for line in lines:
            line = line.strip()
            if not line:
                continue
            try:
                events.append(json.loads(line))
            except json.JSONDecodeError:
                continue  # tolerate torn writes during rotation
        return events

    def read_recent(self, n: int = 200) -> list[dict[str, Any]]:
        if n <= 0:
            return []
        return self.read_all()[-n:]


DEFAULT_CONFIG: dict[str, Any] = {
    "http": {
        "enabled": True,
        "host": "0.0.0.0",
        "port": 8080,
        "server_header": "nginx",
        "site_title": "ACME Corp — Admin Panel",
    },
    "ssh": {
        "enabled": True,
        "host": "0.0.0.0",
        "port": 2222,
        "banner": "OpenSSH_8.9p1 Ubuntu-3ubuntu0.6",
        "hostname": "prod-acme-01",
        "host_key": "data/ssh_host_key.pem",
        "max_sessions": 64,
    },
    "log": {"path": "data/honeynet.jsonl", "rotate_mb": 10},
    "intel": {
        "abuseipdb_api_key": "",
        "threatpulse_cmd": "",
        "min_score_alert": 40,
    },
    "alerts": {
        "telegram": {"bot_token": "", "chat_id": ""},
        "webhook_url": "",
        "rate_limit_seconds": 30,
    },
    "dashboard": {"enabled": True, "host": "127.0.0.1", "port": 8888},
}


def _deep_merge(base: dict[str, Any], override: dict[str, Any]) -> dict[str, Any]:
    merged = copy.deepcopy(base)
    for key, value in override.items():
        if isinstance(value, dict) and isinstance(merged.get(key), dict):
            merged[key] = _deep_merge(merged[key], value)
        else:
            merged[key] = value
    return merged


def load_config(path: str | None = None) -> dict[str, Any]:
    """Load config with defaults; missing file is not an error."""
    if path:
        with open(path, "r", encoding="utf-8") as fh:
            user_cfg = json.load(fh)
        return _deep_merge(DEFAULT_CONFIG, user_cfg)
    return copy.deepcopy(DEFAULT_CONFIG)
