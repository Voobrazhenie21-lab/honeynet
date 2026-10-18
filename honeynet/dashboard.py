"""HoneyNet Real-Time Web Dashboard & REST Telemetry API.

Provides an embedded dark-themed SOC operations center for monitoring intercepted
adversaries, credentials, and auto-generated Wazuh CDB / Suricata rules.
Zero-dependency: built on stdlib asyncio.
"""
from __future__ import annotations

import asyncio
import json
import os
import urllib.parse
from typing import Any

from honeynet.core import EventLogger

HTTP_STATUS_PHRASES: dict[int, str] = {
    200: "OK",
    400: "Bad Request",
    401: "Unauthorized",
    403: "Forbidden",
    404: "Not Found",
    500: "Internal Server Error",
}

DASHBOARD_HTML = """<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>HoneyNet — SOC Telemetry Operations Center</title>
  <link rel="preconnect" href="https://fonts.googleapis.com">
  <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
  <link href="https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;600;800&display=swap" rel="stylesheet">
  <style>
    :root {
      --bg: #04070a; --card: #0a1210; --line: #1b2b26; --line2: #233930;
      --acc: #00ff9c; --acc2: #00d4ff; --red: #ff3b5c; --yel: #ffd166;
      --txt: #c7d8d0; --mut: #5f7a70; --mono: 'JetBrains Mono', monospace;
    }
    * { box-sizing: border-box; margin: 0; padding: 0; }
    body { background: var(--bg); color: var(--txt); font-family: var(--mono); font-size: 14px; padding: 24px; min-height: 100vh; }
    header { display: flex; justify-content: space-between; align-items: center; border-bottom: 1px solid var(--line); padding-bottom: 16px; margin-bottom: 24px; flex-wrap: wrap; gap: 12px; }
    .logo { font-size: 1.25rem; font-weight: 800; color: var(--acc); letter-spacing: 0.05em; display: flex; align-items: center; gap: 8px; }
    .status-badge { display: inline-flex; align-items: center; gap: 6px; font-size: 0.75rem; border: 1px solid var(--line2); padding: 4px 10px; border-radius: 999px; }
    .dot { width: 8px; height: 8px; border-radius: 50%; background: var(--acc); box-shadow: 0 0 8px var(--acc); }
    .btn-group { display: flex; gap: 8px; }
    .btn { background: rgba(0,255,156,0.08); border: 1px solid var(--line2); color: var(--acc); padding: 6px 14px; font-family: var(--mono); font-size: 0.78rem; font-weight: 700; cursor: pointer; text-decoration: none; border-radius: 4px; transition: all 0.2s; }
    .btn:hover { background: var(--acc); color: #02120b; box-shadow: 0 0 14px rgba(0,255,156,0.3); }
    
    .stats-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(210px, 1fr)); gap: 14px; margin-bottom: 24px; }
    .stat-card { background: var(--card); border: 1px solid var(--line); padding: 16px 20px; border-radius: 6px; }
    .stat-val { font-size: 1.8rem; font-weight: 800; color: var(--acc); }
    .stat-lbl { font-size: 0.72rem; color: var(--mut); text-transform: uppercase; letter-spacing: 0.06em; margin-top: 4px; }

    .main-grid { display: grid; grid-template-columns: 2fr 1.1fr; gap: 20px; }
    @media (max-width: 980px) { .main-grid { grid-template-columns: 1fr; } }

    .box { background: var(--card); border: 1px solid var(--line); border-radius: 6px; padding: 18px; }
    .box-title { font-size: 0.88rem; font-weight: 800; color: #fff; margin-bottom: 14px; display: flex; justify-content: space-between; align-items: center; border-bottom: 1px solid var(--line); padding-bottom: 8px; }
    
    table { width: 100%; border-collapse: collapse; font-size: 0.78rem; text-align: left; }
    th { color: var(--mut); padding: 8px 10px; border-bottom: 1px solid var(--line); font-weight: 600; }
    td { padding: 9px 10px; border-bottom: 1px solid rgba(27,43,38,0.5); word-break: break-all; }
    tr:hover td { background: rgba(0,255,156,0.03); }
    
    .badge { padding: 2px 7px; border-radius: 3px; font-size: 0.68rem; font-weight: 700; }
    .badge-crit { background: rgba(255,59,92,0.2); color: var(--red); border: 1px solid rgba(255,59,92,0.4); }
    .badge-high { background: rgba(255,209,102,0.2); color: var(--yel); border: 1px solid rgba(255,209,102,0.4); }
    .badge-med { background: rgba(0,212,255,0.2); color: var(--acc2); border: 1px solid rgba(0,212,255,0.4); }
    .badge-low { background: rgba(0,255,156,0.1); color: var(--acc); border: 1px solid rgba(0,255,156,0.3); }

    .cred-list { display: flex; flex-direction: column; gap: 8px; max-height: 240px; overflow-y: auto; }
    .cred-item { background: rgba(0,0,0,0.35); border: 1px solid var(--line); padding: 7px 10px; font-size: 0.75rem; display: flex; justify-content: space-between; }
    .cred-user { color: var(--acc2); font-weight: 700; }
    .cred-pass { color: var(--red); }
    
    .cdb-preview { background: #020508; border: 1px solid var(--line); padding: 12px; font-size: 0.72rem; color: var(--acc); border-radius: 4px; max-height: 180px; overflow-y: auto; white-space: pre-wrap; }
  </style>
</head>
<body>
  <header>
    <div class="logo">
      <span>⚡ HONEYNET</span>
      <span style="color:var(--mut); font-weight:400; font-size:0.9rem;">// SOC Threat Intelligence Decoy</span>
    </div>
    <div class="status-badge">
      <span class="dot"></span> ACTIVE DECOY DAEMON
    </div>
    <div class="btn-group">
      <a class="btn" href="/api/wazuh" target="_blank">Export Wazuh CDB</a>
      <a class="btn" href="/api/rules/snort" target="_blank">Export Snort Rules</a>
      <a class="btn" href="/api/events" target="_blank">Raw JSON Stream</a>
    </div>
  </header>

  <div class="stats-grid">
    <div class="stat-card">
      <div class="stat-val" id="cntEvents">0</div>
      <div class="stat-lbl">Intercepted Events</div>
    </div>
    <div class="stat-card">
      <div class="stat-val" id="cntIPs" style="color:var(--acc2);">0</div>
      <div class="stat-lbl">Unique Adversary IPs</div>
    </div>
    <div class="stat-card">
      <div class="stat-val" id="cntCritical" style="color:var(--red);">0</div>
      <div class="stat-lbl">Critical / High Threats</div>
    </div>
    <div class="stat-card">
      <div class="stat-val" id="cntCreds" style="color:var(--yel);">0</div>
      <div class="stat-lbl">Credentials Captured</div>
    </div>
  </div>

  <div class="main-grid">
    <div class="box">
      <div class="box-title">
        <span>LIVE ADVERSARY INTRUSION STREAM</span>
        <span style="font-size:0.72rem; color:var(--acc2);" id="streamStatus">Polling (3s)</span>
      </div>
      <table>
        <thead>
          <tr>
            <th>Time</th>
            <th>Protocol</th>
            <th>Adversary IP</th>
            <th>Score</th>
            <th>Activity / Target</th>
          </tr>
        </thead>
        <tbody id="eventsTbody">
          <tr><td colspan="5" style="text-align:center; color:var(--mut);">Awaiting incoming telemetry...</td></tr>
        </tbody>
      </table>
    </div>

    <div style="display:flex; flex-direction:column; gap:20px;">
      <div class="box">
        <div class="box-title">TOP CREDENTIAL HARVESTING ATTEMPTS</div>
        <div class="cred-list" id="credsList">
          <div style="color:var(--mut); font-size:0.75rem; text-align:center;">No credentials intercepted yet.</div>
        </div>
      </div>

      <div class="box">
        <div class="box-title">AUTO-GENERATED WAZUH CDB RULES</div>
        <div class="cdb-preview" id="cdbPreview"># /var/ossec/etc/lists/blacklist.cdb\n# Auto-synced from HoneyNet engine</div>
      </div>
    </div>
  </div>

  <script>
    function escapeHtml(str) {
      if (str === null || str === undefined) return '';
      return String(str)
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;')
        .replace(/'/g, '&#039;');
    }

    async function updateDashboard() {
      try {
        const [statsRes, eventsRes] = await Promise.all([
          fetch('/api/stats').then(r => r.json()),
          fetch('/api/events').then(r => r.json())
        ]);

        document.getElementById('cntEvents').textContent = statsRes.total_events || 0;
        document.getElementById('cntIPs').textContent = statsRes.unique_ips || 0;
        document.getElementById('cntCritical').textContent = statsRes.critical_threats || 0;
        document.getElementById('cntCreds').textContent = statsRes.creds_count || 0;

        // Events Table
        const tbody = document.getElementById('eventsTbody');
        if (eventsRes && eventsRes.length > 0) {
          tbody.innerHTML = eventsRes.slice(-15).reverse().map(ev => {
            const intel = ev.intel || {};
            const score = Number(intel.score) || 0;
            const sev = escapeHtml(intel.severity || 'LOW');
            let badgeClass = 'badge-low';
            if (score >= 75) badgeClass = 'badge-crit';
            else if (score >= 50) badgeClass = 'badge-high';
            else if (score >= 25) badgeClass = 'badge-med';

            const rawDetail = ev.detail || ev.path || ev.command || '';
            const safeDetail = escapeHtml(rawDetail);
            const safeIp = escapeHtml(ev.src_ip || 'unknown');
            const safeProto = escapeHtml((ev.proto || '').toUpperCase());
            const safeT = escapeHtml((ev.ts || '').split('T')[1]?.split('+')[0] || ev.ts || '');

            return `<tr>
              <td style="color:var(--mut);">${safeT}</td>
              <td><span style="color:var(--acc2); font-weight:700;">${safeProto}</span></td>
              <td><code>${safeIp}</code></td>
              <td><span class="badge ${badgeClass}">${score} [${sev}]</span></td>
              <td style="color:#fff;">${safeDetail}</td>
            </tr>`;
          }).join('');
        }

        // Creds List
        const credsBox = document.getElementById('credsList');
        if (statsRes.top_creds && statsRes.top_creds.length > 0) {
          credsBox.innerHTML = statsRes.top_creds.map(c => `
            <div class="cred-item">
              <span class="cred-user">${escapeHtml(c.user || '')}</span>
              <span class="cred-pass">${escapeHtml(c.pass || '')}</span>
            </div>
          `).join('');
        }

        // Wazuh Rules Preview
        if (statsRes.wazuh_rules && statsRes.wazuh_rules.length > 0) {
          document.getElementById('cdbPreview').textContent = statsRes.wazuh_rules.join('\\n');
        }

      } catch (err) {
        console.error('Telemetry refresh error:', err);
      }
    }

    updateDashboard();
    setInterval(updateDashboard, 3000);
  </script>
</body>
</html>
"""


class DashboardServer:
    """Async Dashboard & Telemetry API Server."""

    def __init__(self, config: dict[str, Any], logger: EventLogger) -> None:
        self.config = config
        self.logger = logger
        dash_cfg = config.get("dashboard", {})
        default_host = os.environ.get("HONEYNET_DASHBOARD_HOST") or dash_cfg.get("host", "127.0.0.1")
        self.host = default_host
        self.port = dash_cfg.get("port", 8888)
        self.server: asyncio.Server | None = None

    async def handle_request(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        try:
            line = await asyncio.wait_for(reader.readline(), timeout=3.0)
            if not line:
                writer.close()
                return

            req_line = line.decode("utf-8", errors="replace").strip()
            parts = req_line.split()
            if len(parts) < 2:
                writer.close()
                return

            method = parts[0].upper()
            raw_path = parts[1]
            path = urllib.parse.urlsplit(raw_path).path

            # Drain headers
            while True:
                h_line = await asyncio.wait_for(reader.readline(), timeout=2.0)
                if not h_line or h_line == b"\r\n" or h_line == b"\n":
                    break

            # Route API
            if path in ("/", "/index.html"):
                self.send_response(writer, 200, "text/html; charset=utf-8", DASHBOARD_HTML)
            elif path == "/api/events":
                events = self.logger.read_recent(100)
                self.send_response(writer, 200, "application/json", json.dumps(events, ensure_ascii=False))
            elif path == "/api/stats":
                stats = self.compute_stats()
                self.send_response(writer, 200, "application/json", json.dumps(stats, ensure_ascii=False))
            elif path == "/api/wazuh":
                rules = self.generate_wazuh_cdb()
                self.send_response(writer, 200, "text/plain; charset=utf-8", "\n".join(rules) + "\n")
            elif path == "/api/rules/snort":
                rules = self.generate_snort_rules()
                self.send_response(writer, 200, "text/plain; charset=utf-8", "\n".join(rules) + "\n")
            else:
                self.send_response(writer, 404, "text/plain", "Not Found")

        except (asyncio.TimeoutError, ConnectionResetError, BrokenPipeError, OSError):
            pass
        finally:
            try:
                writer.close()
                await writer.wait_closed()
            except OSError:
                pass

    def send_response(self, writer: asyncio.StreamWriter, status: int, ctype: str, body: str) -> None:
        b_bytes = body.encode("utf-8")
        phrase = HTTP_STATUS_PHRASES.get(status, "OK" if status < 400 else "Error")
        header = (
            f"HTTP/1.1 {status} {phrase}\r\n"
            f"Content-Type: {ctype}\r\n"
            f"Content-Length: {len(b_bytes)}\r\n"
            f"Access-Control-Allow-Origin: *\r\n"
            f"Connection: close\r\n\r\n"
        )
        writer.write(header.encode("utf-8") + b_bytes)

    def compute_stats(self) -> dict[str, Any]:
        events = self.logger.read_all()
        unique_ips = set()
        crit_count = 0
        creds: list[dict[str, str]] = []
        wazuh_rules: list[str] = []

        for ev in events:
            ip = ev.get("src_ip")
            if ip:
                unique_ips.add(ip)
            intel = ev.get("intel", {})
            if intel.get("score", 0) >= 50:
                crit_count += 1
            if ev.get("username") or ev.get("password"):
                creds.append({"user": ev.get("username", "<none>"), "pass": ev.get("password", "<none>")})
            cdb = intel.get("wazuh_cdb")
            if cdb and cdb not in wazuh_rules:
                wazuh_rules.append(cdb)

        return {
            "total_events": len(events),
            "unique_ips": len(unique_ips),
            "critical_threats": crit_count,
            "creds_count": len(creds),
            "top_creds": creds[-10:],
            "wazuh_rules": wazuh_rules[-20:],
        }

    def generate_wazuh_cdb(self) -> list[str]:
        events = self.logger.read_all()
        rules: list[str] = ["# HoneyNet Wazuh CDB Dynamic Threat Feed", "# Path: /var/ossec/etc/lists/honeynet_blacklist.cdb"]
        seen: set[str] = set()
        for ev in events:
            cdb = ev.get("intel", {}).get("wazuh_cdb")
            if cdb and cdb not in seen:
                seen.add(cdb)
                rules.append(cdb)
        return rules

    def generate_snort_rules(self) -> list[str]:
        events = self.logger.read_all()
        rules: list[str] = ["# HoneyNet Auto-Generated Suricata/Snort Drop Rules"]
        seen: set[str] = set()
        sid = 1000100
        for ev in events:
            ip = ev.get("src_ip")
            if ip and ip not in seen and not ev.get("intel", {}).get("ip_meta", {}).get("is_bogon"):
                seen.add(ip)
                rules.append(f'drop ip {ip} any -> any any (msg:"HoneyNet Intercepted Adversary {ip}"; reference:url,https://github.com/Voobrazhenie21-lab/threat-pulse; sid:{sid}; rev:1;)')
                sid += 1
        return rules

    async def start(self) -> None:
        self.server = await asyncio.start_server(self.handle_request, self.host, self.port)

    async def stop(self) -> None:
        if self.server:
            self.server.close()
            await self.server.wait_closed()
