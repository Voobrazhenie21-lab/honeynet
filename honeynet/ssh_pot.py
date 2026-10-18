"""HoneyNet Paramiko-based SSH Honeypot Server.

Intercepts brute-force authentication attempts and hosts a simulated shell
session using honeynet.sshsim.VirtualShell.
Gracefully handles missing paramiko dependency for zero-dependency operation.
"""
from __future__ import annotations

import os
import socket
import threading
from typing import Any

from honeynet.core import Event, EventLogger, AUTH_ATTEMPT, COMMAND, PAYLOAD, SESSION, now_iso
from honeynet.intel import assess_event
from honeynet.sshsim import VirtualShell

try:
    import paramiko
    PARAMIKO_AVAILABLE = True
except ImportError:
    paramiko = None  # type: ignore
    PARAMIKO_AVAILABLE = False


class HoneyNetSSHInterface(paramiko.ServerInterface if PARAMIKO_AVAILABLE else object):  # type: ignore
    """Paramiko server callback interface for authentication and channel tracking."""

    def __init__(self, client_ip: str, client_port: int, logger: EventLogger, config: dict[str, Any]) -> None:
        self.client_ip = client_ip
        self.client_port = client_port
        self.logger = logger
        self.config = config
        self.username = "root"
        self.event_intel: dict[str, Any] = {}

    def check_auth_password(self, username: str, password: str) -> int:
        self.username = username
        self.event_intel = assess_event(
            proto="ssh",
            src_ip=self.client_ip,
            kind="auth_attempt",
            username=username,
            password=password,
            config=self.config,
        )
        event = Event(
            ts=now_iso(),
            proto="ssh",
            src_ip=self.client_ip,
            src_port=self.client_port,
            kind=AUTH_ATTEMPT,
            username=username,
            password=password,
            detail=f"SSH Password Login Attempt (user: {username})",
            tags=self.event_intel.get("tags", []),
            intel=self.event_intel,
        )
        self.logger.write(event)
        # Honeypot strategy: accept authentication to bait attacker into the fake shell
        return paramiko.AUTH_SUCCESSFUL

    def check_channel_request(self, kind: str, chanid: int) -> int:
        if kind == "session":
            return paramiko.OPEN_SUCCEEDED
        return paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED

    def check_channel_pty_request(self, channel: Any, term: str, width: int, height: int, pixelwidth: int, pixelheight: int, modes: str) -> bool:
        return True

    def check_channel_shell_request(self, channel: Any) -> bool:
        return True


class SshHoneypotServer:
    """Multi-threaded SSH Honeypot Server."""

    def __init__(self, config: dict[str, Any], logger: EventLogger) -> None:
        self.config = config
        self.logger = logger
        ssh_cfg = config.get("ssh", {})
        self.host = ssh_cfg.get("host", "0.0.0.0")
        self.port = ssh_cfg.get("port", 2222)
        self.hostname = ssh_cfg.get("hostname", "prod-acme-01")
        self.host_key_path = ssh_cfg.get("host_key", "data/ssh_host_key.pem")
        self.running = False
        self.sock: socket.socket | None = None
        self.host_key: Any = None

    def ensure_host_key(self) -> Any:
        if not PARAMIKO_AVAILABLE:
            return None
        dir_name = os.path.dirname(self.host_key_path)
        if dir_name:
            os.makedirs(dir_name, exist_ok=True)
        if not os.path.exists(self.host_key_path):
            key = paramiko.RSAKey.generate(2048)
            key.write_private_key_file(self.host_key_path)
            return key
        return paramiko.RSAKey(filename=self.host_key_path)

    def handle_client(self, client_sock: socket.socket, addr: tuple[str, int]) -> None:
        if not PARAMIKO_AVAILABLE:
            client_sock.close()
            return
        src_ip, src_port = addr
        transport = None
        try:
            transport = paramiko.Transport(client_sock)
            transport.local_version = self.config.get("ssh", {}).get("banner", "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.6")
            transport.add_server_key(self.host_key)

            interface = HoneyNetSSHInterface(src_ip, src_port, self.logger, self.config)
            transport.start_server(server=interface)

            chan = transport.accept(20)
            if chan is None:
                return

            vshell = VirtualShell(username=interface.username, hostname=self.hostname)

            # Interactive session banner
            welcome_msg = (
                f"Welcome to Ubuntu 22.04.4 LTS (GNU/Linux 5.15.0-105-generic x86_64)\r\n\r\n"
                f" * Documentation:  https://help.ubuntu.com\r\n"
                f" * Management:     https://landscape.canonical.com\r\n"
                f" * Support:        https://ubuntu.com/pro\r\n\r\n"
            )
            chan.send(welcome_msg.encode("utf-8"))
            chan.send(vshell.get_prompt().encode("utf-8"))

            buf = ""
            while not chan.exit_status_ready() and self.running:
                data = chan.recv(1024)
                if not data:
                    break
                text = data.decode("utf-8", errors="replace")
                for ch in text:
                    if ch in ("\r", "\n"):
                        chan.send(b"\r\n")
                        cmd_line = buf.strip()
                        buf = ""
                        if cmd_line:
                            output, should_exit, meta = vshell.execute(cmd_line)
                            
                            # Log command execution
                            kind = PAYLOAD if meta.get("is_payload") else COMMAND
                            intel = assess_event(
                                proto="ssh",
                                src_ip=src_ip,
                                kind=kind,
                                command=cmd_line,
                                username=interface.username,
                                config=self.config
                            )
                            event = Event(
                                ts=now_iso(),
                                proto="ssh",
                                src_ip=src_ip,
                                src_port=src_port,
                                kind=kind,
                                command=cmd_line,
                                username=interface.username,
                                detail=f"SSH Command: {cmd_line}",
                                tags=intel.get("tags", []),
                                intel=intel,
                            )
                            self.logger.write(event)

                            chan.send(output.replace("\n", "\r\n").encode("utf-8"))
                            if should_exit:
                                chan.close()
                                return
                        chan.send(vshell.get_prompt().encode("utf-8"))
                    elif ch == "\x7f" or ch == "\x08":  # Backspace
                        if len(buf) > 0:
                            buf = buf[:-1]
                            chan.send(b"\b \b")
                    elif ch == "\x03":  # Ctrl+C
                        buf = ""
                        chan.send(b"^C\r\n" + vshell.get_prompt().encode("utf-8"))
                    else:
                        buf += ch
                        chan.send(ch.encode("utf-8"))

        except Exception:
            pass
        finally:
            if transport:
                try:
                    transport.close()
                except Exception:
                    pass
            try:
                client_sock.close()
            except Exception:
                pass

    def is_available(self) -> bool:
        """Check whether paramiko is installed and SSH honeypot is usable."""
        return PARAMIKO_AVAILABLE

    def start(self) -> bool:
        """Start SSH server listening on host:port. Returns True if started, False otherwise."""
        if not PARAMIKO_AVAILABLE:
            return False
        try:
            self.host_key = self.ensure_host_key()
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.sock.bind((self.host, self.port))
            self.sock.listen(100)
            self.running = True

            def loop() -> None:
                while self.running:
                    try:
                        client_sock, addr = self.sock.accept()
                        t = threading.Thread(target=self.handle_client, args=(client_sock, addr), daemon=True)
                        t.start()
                    except OSError:
                        break

            thread = threading.Thread(target=loop, daemon=True)
            thread.start()
            return True
        except OSError:
            return False

    def stop(self) -> None:
        self.running = False
        if self.sock:
            try:
                self.sock.close()
            except OSError:
                pass
