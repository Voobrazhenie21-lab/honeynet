"""HoneyNet Alert Dispatcher.

Handles multi-channel real-time notifications for high-risk honeypot activity:
- Telegram Bot API
- Generic SIEM / Chat Webhook (Slack, Discord, custom webhook)
- Rate limiting per IP to prevent notification storms.
Zero-dependency (stdlib only).
"""
from __future__ import annotations

import json
import time
import urllib.request
import urllib.error
from typing import Any


class AlertManager:
    """Evaluates events and dispatches rate-limited security alerts."""

    def __init__(self, config: dict[str, Any] | None = None) -> None:
        self.config = config or {}
        alert_cfg = self.config.get("alerts", {})
        self.tg_token = alert_cfg.get("telegram", {}).get("bot_token", "")
        self.tg_chat = alert_cfg.get("telegram", {}).get("chat_id", "")
        self.webhook_url = alert_cfg.get("webhook_url", "")
        self.rate_limit_sec = alert_cfg.get("rate_limit_seconds", 30)
        self.min_score = self.config.get("intel", {}).get("min_score_alert", 40)

        # In-memory tracking for throttling and dashboard display
        self._last_alert_time: dict[str, float] = {}
        self.dispatched_alerts: list[dict[str, Any]] = []

    def should_alert(self, record: dict[str, Any]) -> bool:
        """Determine if event exceeds threat threshold and passes rate limit."""
        intel = record.get("intel", {})
        score = intel.get("score", 0)
        if score < self.min_score:
            return False

        src_ip = record.get("src_ip", "unknown")
        now = time.time()
        last_time = self._last_alert_time.get(src_ip, 0.0)
        if now - last_time < self.rate_limit_sec:
            return False

        return True

    def consider(self, record: dict[str, Any]) -> bool:
        """Examine record and send alerts if eligible. Returns True if alert sent."""
        if not self.should_alert(record):
            return False

        src_ip = record.get("src_ip", "unknown")
        self._last_alert_time[src_ip] = time.time()

        message = self.format_telegram_message(record)
        dispatched = False

        if self.tg_token and self.tg_chat:
            if self.send_telegram(message):
                dispatched = True

        if self.webhook_url:
            if self.send_webhook(record):
                dispatched = True

        self.dispatched_alerts.append({
            "ts": record.get("ts"),
            "src_ip": src_ip,
            "score": record.get("intel", {}).get("score", 0),
            "severity": record.get("intel", {}).get("severity", "UNKNOWN"),
            "proto": record.get("proto"),
            "detail": record.get("detail", record.get("path") or record.get("command")),
        })
        if len(self.dispatched_alerts) > 100:
            self.dispatched_alerts.pop(0)

        return dispatched

    def format_telegram_message(self, record: dict[str, Any]) -> str:
        intel = record.get("intel", {})
        score = intel.get("score", 0)
        severity = intel.get("severity", "MEDIUM")
        proto = record.get("proto", "").upper()
        src_ip = record.get("src_ip", "")
        kind = record.get("kind", "")

        mitre_list = intel.get("mitre", [])
        mitre_str = ", ".join([f"{m['id']} ({m['name']})" for m in mitre_list]) if mitre_list else "T1190"
        cdb_rule = intel.get("wazuh_cdb", f"{src_ip}:high:block")

        detail = record.get("detail") or record.get("path") or record.get("command") or ""
        creds = ""
        if record.get("username") or record.get("password"):
            creds = f"\n🔑 Creds: `{record.get('username')}`:`{record.get('password')}`"

        return (
            f"🚨 *[HONEYNET SOC ALERT]*\n"
            f"━━━━━━━━━━━━━━━━━━\n"
            f"🎯 *Adversary IP:* `{src_ip}`\n"
            f"🛡️ *Protocol:* {proto} | *Event:* {kind}\n"
            f"📊 *Threat Score:* {score}/100 [{severity}]\n"
            f"⚔️ *MITRE ATT&CK:* {mitre_str}\n"
            f"📝 *Target:* `{detail}`{creds}\n"
            f"📋 *Wazuh CDB:* `{cdb_rule}`\n"
            f"⏰ *Timestamp:* {record.get('ts')}"
        )

    def send_telegram(self, text: str) -> bool:
        if not self.tg_token or not self.tg_chat:
            return False
        url = f"https://api.telegram.org/bot{self.tg_token}/sendMessage"
        payload = json.dumps({
            "chat_id": self.tg_chat,
            "text": text,
            "parse_mode": "Markdown",
            "disable_web_page_preview": True,
        }).encode("utf-8")
        req = urllib.request.Request(
            url,
            data=payload,
            headers={"Content-Type": "application/json"}
        )
        try:
            with urllib.request.urlopen(req, timeout=3.0) as resp:
                return resp.status == 200
        except (urllib.error.URLError, TimeoutError, OSError):
            return False

    def send_webhook(self, record: dict[str, Any]) -> bool:
        if not self.webhook_url:
            return False
        payload = json.dumps({
            "source": "honeynet",
            "event": record,
        }).encode("utf-8")
        req = urllib.request.Request(
            self.webhook_url,
            data=payload,
            headers={"Content-Type": "application/json"}
        )
        try:
            with urllib.request.urlopen(req, timeout=3.0) as resp:
                return resp.status in (200, 201, 204)
        except (urllib.error.URLError, TimeoutError, OSError):
            return False
