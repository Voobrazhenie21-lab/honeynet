"""HoneyNet SSH Shell Simulator.

Provides an isolated, in-memory virtual Unix environment designed to record
attacker commands, payloads, and reconnaissance attempts without executing code.
Zero-dependency (stdlib only).
"""
from __future__ import annotations

import shlex
from typing import Any

FAKE_PASSWD = """root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
sync:x:4:65534:sync:/bin:/bin/sync
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
backup:x:34:34:backup:/var/backups:/usr/sbin/nologin
sshd:x:110:65534::/run/sshd:/usr/sbin/nologin
deploy:x:1000:1000:Deployer User,,,:/home/deploy:/bin/bash
soc-agent:x:1001:1001:Wazuh Agent Service:/var/ossec:/bin/false
"""

FAKE_SHADOW = """root:$6$vE3gJ...$H0/x...:19700:0:99999:7:::
daemon:*:19700:0:99999:7:::
www-data:*:19700:0:99999:7:::
deploy:$6$kL9xP...$M1/a...:19700:0:99999:7:::
soc-agent:!:19700:0:99999:7:::
"""

FAKE_OS_RELEASE = """NAME="Ubuntu"
VERSION="22.04.4 LTS (Jammy Jellyfish)"
ID=ubuntu
ID_LIKE=debian
PRETTY_NAME="Ubuntu 22.04.4 LTS"
VERSION_ID="22.04"
"""

FAKE_ENV = """# Production Database Credentials (HoneyToken)
DB_HOST=10.244.0.18
DB_PORT=5432
DB_USER=acme_prod_app
DB_PASS=P@ssw0rd_HoneyDecoy_2026!
AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE
AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
"""


class VirtualShell:
    """Simulates an interactive Bash shell session for SSH honeypot."""

    def __init__(self, username: str = "root", hostname: str = "prod-acme-01") -> None:
        self.username = username or "root"
        self.hostname = hostname
        self.cwd = f"/home/{self.username}" if self.username != "root" else "/root"
        self.history: list[str] = [
            "systemctl status nginx",
            "docker compose ps",
            "journalctl -u ssh -n 20",
        ]
        self.vfs: dict[str, str] = {
            "/etc/passwd": FAKE_PASSWD,
            "/etc/shadow": FAKE_SHADOW,
            "/etc/os-release": FAKE_OS_RELEASE,
            "/etc/issue": "Ubuntu 22.04.4 LTS \\n \\l\n",
            "/home/deploy/.env": FAKE_ENV,
            "/root/.bash_history": "\n".join(self.history) + "\n",
            "/root/notes.txt": "Internal maintenance scheduled for 03:00 UTC.\n",
        }

    def get_prompt(self) -> str:
        symbol = "#" if self.username == "root" else "$"
        display_cwd = "~" if self.cwd in ("/root", f"/home/{self.username}") else self.cwd
        return f"{self.username}@{self.hostname}:{display_cwd}{symbol} "

    def execute(self, line: str) -> tuple[str, bool, dict[str, Any]]:
        """
        Execute command line in virtual shell.
        Returns: (output_text, should_exit, telemetry_metadata)
        """
        cmd_clean = line.strip()
        if not cmd_clean:
            return "", False, {}

        self.history.append(cmd_clean)
        try:
            tokens = shlex.split(cmd_clean)
        except ValueError:
            tokens = cmd_clean.split()

        cmd = tokens[0].lower()
        args = tokens[1:]
        meta: dict[str, Any] = {"command": cmd_clean, "is_payload": False}

        if cmd in ("exit", "logout", "quit"):
            return "logout\n", True, meta

        if cmd == "clear":
            return "\033[H\033[2J", False, meta

        if cmd == "whoami":
            return f"{self.username}\n", False, meta

        if cmd == "id":
            if self.username == "root":
                return "uid=0(root) gid=0(root) groups=0(root)\n", False, meta
            return f"uid=1000({self.username}) gid=1000({self.username}) groups=1000({self.username}),27(sudo)\n", False, meta

        if cmd in ("hostname", "uname"):
            if cmd == "hostname":
                return f"{self.hostname}\n", False, meta
            if "-a" in args:
                return f"Linux {self.hostname} 5.15.0-105-generic #115-Ubuntu SMP Mon Mar 18 14:15:20 UTC 2024 x86_64 x86_64 x86_64 GNU/Linux\n", False, meta
            return "Linux\n", False, meta

        if cmd == "pwd":
            return f"{self.cwd}\n", False, meta

        if cmd == "cd":
            target = args[0] if args else "/root"
            if target == "~":
                target = "/root"
            elif target == "..":
                target = "/" if self.cwd.count("/") <= 1 else self.cwd.rsplit("/", 1)[0]
            self.cwd = target if target.startswith("/") else f"{self.cwd}/{target}".replace("//", "/")
            return "", False, meta

        if cmd == "ls":
            if self.cwd == "/root":
                return ".bashrc  .profile  .bash_history  notes.txt\n", False, meta
            if self.cwd == "/etc":
                return "passwd  shadow  os-release  issue  hosts  resolv.conf  network\n", False, meta
            return "bin  boot  dev  etc  home  lib  opt  proc  root  run  sbin  srv  sys  tmp  usr  var\n", False, meta

        if cmd == "cat":
            if not args:
                return "", False, meta
            target_path = args[0]
            if not target_path.startswith("/"):
                target_path = f"{self.cwd}/{target_path}".replace("//", "/")
            if target_path in self.vfs:
                return self.vfs[target_path], False, meta
            return f"cat: {args[0]}: No such file or directory\n", False, meta

        if cmd == "history":
            out_lines = [f"  {idx+1}  {entry}" for idx, entry in enumerate(self.history)]
            return "\n".join(out_lines) + "\n", False, meta

        if cmd in ("wget", "curl"):
            meta["is_payload"] = True
            url = args[0] if args else "unknown"
            return f"Connecting to {url}... connected.\nHTTP request sent, awaiting response... 200 OK\nSaved decoy artifact.\n", False, meta

        if cmd == "ps":
            return "  PID TTY          TIME CMD\n    1 ?        00:00:02 systemd\n  482 ?        00:00:00 sshd\n 1205 pts/0    00:00:00 bash\n 1250 pts/0    00:00:00 ps\n", False, meta

        if cmd in ("ifconfig", "ip"):
            return "eth0: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500\n        inet 10.244.0.12  netmask 255.255.255.0  broadcast 10.244.0.255\n        inet6 fe80::a00:27ff:fe4e:66a1  prefixlen 64  scopeid 0x20<link>\n        ether 08:00:27:4e:66:a1  txqueuelen 1000  (Ethernet)\n", False, meta

        # Generic default response
        return f"bash: {cmd}: command not found\n", False, meta
