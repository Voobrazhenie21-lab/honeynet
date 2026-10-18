"""HoneyNet Asynchronous HTTP Honeypot.

Emulates deceptive web services, sensitive endpoints, and login portals to
capture attacker reconnaissance, credential harvesting, and exploit attempts.
Zero-dependency: built on stdlib asyncio.
"""
from __future__ import annotations

import asyncio
import ipaddress
import urllib.parse
from typing import Any

from honeynet.core import Event, EventLogger, HTTP_REQUEST, AUTH_ATTEMPT, now_iso
from honeynet.intel import assess_event

HTTP_STATUS_PHRASES: dict[int, str] = {
    200: "OK",
    400: "Bad Request",
    401: "Unauthorized",
    403: "Forbidden",
    404: "Not Found",
    500: "Internal Server Error",
}

DECOY_LOGIN_HTML = """<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>ACME Corporation — Internal Portal</title>
  <style>
    body { background: #0f172a; color: #f8fafc; font-family: -apple-system, sans-serif; display: flex; align-items: center; justify-content: center; height: 100vh; margin: 0; }
    .box { background: #1e293b; padding: 2.2rem; border-radius: 8px; box-shadow: 0 10px 25px rgba(0,0,0,0.5); width: 340px; border: 1px solid #334155; }
    h2 { margin-top: 0; color: #38bdf8; font-size: 1.3rem; }
    p { font-size: 0.85rem; color: #94a3b8; margin-bottom: 1.5rem; }
    input { width: 100%; box-sizing: border-box; padding: 10px; margin-bottom: 12px; background: #0f172a; border: 1px solid #475569; color: #fff; border-radius: 4px; }
    button { width: 100%; padding: 10px; background: #0284c7; color: #fff; border: none; border-radius: 4px; font-weight: bold; cursor: pointer; }
    button:hover { background: #0369a1; }
    .footer { font-size: 0.72rem; color: #64748b; margin-top: 1rem; text-align: center; }
  </style>
</head>
<body>
  <div class="box">
    <h2>ACME Internal SSO</h2>
    <p>Authorized access only. All sessions are monitored.</p>
    <form method="POST" action="/api/v1/auth">
      <input type="text" name="username" placeholder="Corporate Username or Email" required autofocus>
      <input type="password" name="password" placeholder="Passcode / Token" required>
      <button type="submit">Sign In to Dashboard</button>
    </form>
    <div class="footer">ACME Security Gateway v4.8.1</div>
  </div>
</body>
</html>
"""

DECOY_ROBOTS_TXT = """User-agent: *
Disallow: /admin
Disallow: /api/v1/internal
Disallow: /.env
Disallow: /wp-admin
Disallow: /backup.tar.gz
"""

DECOY_ENV = """# ACME Production Environment
APP_ENV=production
APP_KEY=base64:7KqR9NfK...
DB_CONNECTION=pgsql
DB_HOST=10.244.0.18
DB_PORT=5432
DB_DATABASE=acme_core_prod
DB_USERNAME=acme_db_user
DB_PASSWORD=HoneyPass_Decoy_2026!
AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE
AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
"""


class HttpHoneypotServer:
    """Async HTTP honeypot server engine."""

    def __init__(self, config: dict[str, Any], logger: EventLogger) -> None:
        self.config = config
        self.logger = logger
        http_cfg = config.get("http", {})
        self.host = http_cfg.get("host", "0.0.0.0")
        self.port = http_cfg.get("port", 8080)
        self.server_header = http_cfg.get("server_header", "nginx/1.24.0 (Ubuntu)")
        self.server: asyncio.Server | None = None

    async def handle_client(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        client_addr = writer.get_extra_info("peername")
        src_ip = client_addr[0] if client_addr else "127.0.0.1"
        src_port = client_addr[1] if client_addr else 0

        try:
            line = await asyncio.wait_for(reader.readline(), timeout=5.0)
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

            # Read headers
            headers: dict[str, str] = {}
            content_length = 0
            while True:
                h_line = await asyncio.wait_for(reader.readline(), timeout=3.0)
                if not h_line or h_line == b"\r\n" or h_line == b"\n":
                    break
                decoded_h = h_line.decode("utf-8", errors="replace").strip()
                if ":" in decoded_h:
                    k, v = decoded_h.split(":", 1)
                    headers[k.strip().lower()] = v.strip()
                    if k.strip().lower() == "content-length":
                        try:
                            content_length = int(v.strip())
                        except ValueError:
                            content_length = 0

            # Inspect X-Forwarded-For if present (strictly validated)
            if "x-forwarded-for" in headers:
                raw_ip = headers["x-forwarded-for"].split(",")[0].strip()
                try:
                    ipaddress.ip_address(raw_ip)
                    src_ip = raw_ip
                except ValueError:
                    # Ignore malformed or exploit payload headers, retain real socket IP
                    pass

            # Read body for POST credential attempts
            body_data = ""
            username = ""
            password = ""
            if method == "POST" and content_length > 0:
                body_bytes = await asyncio.wait_for(reader.read(min(content_length, 8192)), timeout=3.0)
                body_data = body_bytes.decode("utf-8", errors="replace")
                parsed_body = urllib.parse.parse_qs(body_data)
                username = parsed_body.get("username", [""])[0] or parsed_body.get("user", [""])[0] or parsed_body.get("login", [""])[0]
                password = parsed_body.get("password", [""])[0] or parsed_body.get("pass", [""])[0]

            # Route response & classify event
            status_code, content_type, response_body = self.route_request(path, method, username, password)

            kind = AUTH_ATTEMPT if (username or password or "/login" in path) else HTTP_REQUEST
            detail = f"{method} {path}"
            if username:
                detail += f" (user: {username})"

            intel = assess_event(
                proto="http",
                src_ip=src_ip,
                kind=kind,
                path=path,
                username=username,
                password=password,
                config=self.config
            )

            event = Event(
                ts=now_iso(),
                proto="http",
                src_ip=src_ip,
                src_port=src_port,
                kind=kind,
                method=method,
                path=path,
                username=username,
                password=password,
                detail=detail,
                tags=intel.get("tags", []),
                intel=intel
            )
            self.logger.write(event)

            # Send HTTP response
            resp_bytes = response_body.encode("utf-8")
            phrase = HTTP_STATUS_PHRASES.get(status_code, "OK" if status_code < 400 else "Error")
            header_lines = [
                f"HTTP/1.1 {status_code} {phrase}",
                f"Server: {self.server_header}",
                f"Content-Type: {content_type}",
                f"Content-Length: {len(resp_bytes)}",
                "Connection: close",
                "\r\n"
            ]
            writer.write("\r\n".join(header_lines).encode("utf-8") + resp_bytes)
            await writer.drain()

        except (asyncio.TimeoutError, ConnectionResetError, BrokenPipeError, OSError):
            pass
        finally:
            try:
                writer.close()
                await writer.wait_closed()
            except OSError:
                pass

    def route_request(self, path: str, method: str, username: str, password: str) -> tuple[int, str, str]:
        """Generate deceptive decoy response based on requested URI."""
        norm_path = path.lower()

        if norm_path == "/robots.txt":
            return 200, "text/plain", DECOY_ROBOTS_TXT

        if norm_path in ("/", "/index.html", "/login", "/admin"):
            return 200, "text/html; charset=utf-8", DECOY_LOGIN_HTML

        if norm_path in ("/.env", "/.env.local", "/.env.production"):
            return 200, "text/plain", DECOY_ENV

        if norm_path in ("/.git/config", "/.git/head"):
            git_body = "[core]\n\trepositoryformatversion = 0\n\tfilemode = true\n\tbare = false\n[remote \"origin\"]\n\turl = git@github.com:acme-internal/backend.git\n"
            return 200, "text/plain", git_body

        if norm_path in ("/api/v1/auth", "/api/login"):
            return 401, "application/json", '{"status":"error","code":401,"message":"Invalid credentials or token expired."}'

        if norm_path in ("/wp-login.php", "/xmlrpc.php"):
            return 403, "text/html", "<html><head><title>403 Forbidden</title></head><body><h1>403 Forbidden</h1><p>WAF IP Blocklist Policy Enforced.</p></body></html>"

        if norm_path in ("/actuator", "/actuator/health", "/actuator/env"):
            return 200, "application/json", '{"status":"UP","components":{"db":{"status":"UP"},"diskSpace":{"status":"UP"}}}'

        # Default 404 response
        return 404, "text/html", "<html><head><title>404 Not Found</title></head><body><h1>404 Not Found</h1><p>nginx</p></body></html>"

    async def start(self) -> None:
        self.server = await asyncio.start_server(self.handle_client, self.host, self.port)

    async def stop(self) -> None:
        if self.server:
            self.server.close()
            await self.server.wait_closed()
