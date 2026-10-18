"""HoneyNet Command-Line Interface.

Provides management commands for starting the honeypot daemon, viewing telemetry,
exporting Wazuh CDB / Suricata rules, and validating alerts.
"""
from __future__ import annotations

import argparse
import asyncio
import os
import signal
import sys
from typing import Any

from honeynet import __version__
from honeynet.alerts import AlertManager
from honeynet.core import Event, EventLogger, load_config, now_iso
from honeynet.dashboard import DashboardServer
from honeynet.http_pot import HttpHoneypotServer
from honeynet.intel import assess_event
from honeynet.ssh_pot import SshHoneypotServer

BANNER = rf"""
 ██░ ██  ▒█████   ███▄    █ ▓█████▓██   ██▓ ███▄    █ ▓█████▄▄▄█████▓
▓██░ ██▒▒██▒  ██▒ ██ ▀█   █ ▓█   ▀ ▒██  ██▒ ██ ▀█   █ ▓█   ▀▓  ██▒ ▓▒
▒██▀▀██░▒██░  ██▒▓██  ▀█ ██▒▒███    ▒██ ██░▓██  ▀█ ██▒▒███  ▒ ▓██░ ▒░
░▓█ ░██ ▒██   ██░▓██▒  ▐▌██▒▒▓█  ▄  ░ ▐██▓░▓██▒  ▐▌██▒▒▓█  ▄░ ▓██▓ ░ 
░▓█▒░██▓░ ████▓▒░▒██░   ▓██░░▒████▒ ░ ██▒▓░▒██░   ▓██░░▒████▒ ▒██▒ ░ 
 ▒ ░░▒░▒░ ▒░▒░▒░ ░ ▒░   ▒ ▒ ░░ ▒░ ░  ██▒▒▒ ░ ▒░   ▒ ▒ ░░ ▒░ ░ ▒ ░░   
 v{__version__} — Multi-Vector Low-Interaction SOC Decoy & Telemetry Daemon
"""


def cmd_run(args: argparse.Namespace) -> None:
    config = load_config(args.config)
    log_path = config.get("log", {}).get("path", "data/honeynet.jsonl")
    alert_mgr = AlertManager(config)
    logger = EventLogger(log_path, rotate_mb=config.get("log", {}).get("rotate_mb", 10), alerts=alert_mgr)

    print(BANNER)
    print(f"[*] Configuration loaded. Log path: {log_path}")

    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)

    http_server: HttpHoneypotServer | None = None
    dash_server: DashboardServer | None = None
    ssh_server: SshHoneypotServer | None = None

    # HTTP Honeypot
    if config.get("http", {}).get("enabled", True) and not args.no_http:
        http_server = HttpHoneypotServer(config, logger)
        loop.run_until_complete(http_server.start())
        print(f"[+] HTTP Decoy active on http://{http_server.host}:{http_server.port}")

    # Dashboard Server
    if config.get("dashboard", {}).get("enabled", True) and not args.no_dashboard:
        dash_server = DashboardServer(config, logger)
        loop.run_until_complete(dash_server.start())
        print(f"[+] Web Dashboard active at http://{dash_server.host}:{dash_server.port}")

    # SSH Honeypot
    if config.get("ssh", {}).get("enabled", True) and not args.no_ssh:
        ssh_server = SshHoneypotServer(config, logger)
        if ssh_server.start():
            print(f"[+] SSH Decoy active on {ssh_server.host}:{ssh_server.port}")
        else:
            print(f"[!] SSH Decoy disabled: paramiko is not installed. Run 'pip install \"honeynet-soc[ssh]\"' to enable SSH emulation.")

    print("\n[+] HoneyNet daemon running. Press Ctrl+C to terminate gracefully.\n")

    def shutdown(*_: Any) -> None:
        print("\n[*] Shutting down HoneyNet servers...")
        if http_server:
            loop.run_until_complete(http_server.stop())
        if dash_server:
            loop.run_until_complete(dash_server.stop())
        if ssh_server:
            ssh_server.stop()
        loop.stop()
        print("[+] HoneyNet stopped cleanly.")
        sys.exit(0)

    for sig in (signal.SIGINT, signal.SIGTERM):
        try:
            signal.signal(sig, shutdown)
        except (ValueError, AttributeError):
            pass

    try:
        loop.run_forever()
    except (KeyboardInterrupt, SystemExit):
        shutdown()


def cmd_status(args: argparse.Namespace) -> None:
    config = load_config(args.config)
    log_path = config.get("log", {}).get("path", "data/honeynet.jsonl")
    logger = EventLogger(log_path)
    events = logger.read_all()

    unique_ips = {ev.get("src_ip") for ev in events if ev.get("src_ip")}
    crit_count = sum(1 for ev in events if ev.get("intel", {}).get("score", 0) >= 50)
    creds_count = sum(1 for ev in events if ev.get("username") or ev.get("password"))

    print(BANNER)
    print(f"Log Path:             {log_path}")
    print(f"Total Events:         {len(events)}")
    print(f"Unique Adversaries:   {len(unique_ips)}")
    print(f"High/Crit Threats:    {crit_count}")
    print(f"Captured Creds:       {creds_count}")

    if events:
        print("\nRecent 5 Events:")
        for ev in events[-5:]:
            intel = ev.get("intel", {})
            print(f" - [{ev.get('ts')}] {ev.get('proto', '').upper()} from {ev.get('src_ip')}: score {intel.get('score')} [{intel.get('severity')}] - {ev.get('detail')}")


def cmd_export_wazuh(args: argparse.Namespace) -> None:
    config = load_config(args.config)
    log_path = config.get("log", {}).get("path", "data/honeynet.jsonl")
    logger = EventLogger(log_path)
    events = logger.read_all()

    rules: list[str] = ["# HoneyNet Wazuh CDB Dynamic Threat Feed", "# Path: /var/ossec/etc/lists/honeynet_blacklist.cdb"]
    seen: set[str] = set()
    for ev in events:
        cdb = ev.get("intel", {}).get("wazuh_cdb")
        if cdb and cdb not in seen:
            seen.add(cdb)
            rules.append(cdb)

    out_text = "\n".join(rules) + "\n"
    if args.out:
        with open(args.out, "w", encoding="utf-8") as fh:
            fh.write(out_text)
        print(f"[+] Exported {len(seen)} Wazuh CDB rules to {args.out}")
    else:
        sys.stdout.write(out_text)


def cmd_test_alert(args: argparse.Namespace) -> None:
    config = load_config(args.config)
    alert_mgr = AlertManager(config)
    print("[*] Dispatching test intrusion alert...")

    test_intel = assess_event(
        proto="http",
        src_ip="185.220.101.5",
        kind="auth_attempt",
        path="/.env",
        username="admin",
        password="P@ssw0rd_HoneyDecoy!",
        config=config,
    )
    test_event = {
        "ts": now_iso(),
        "proto": "http",
        "src_ip": "185.220.101.5",
        "kind": "auth_attempt",
        "path": "/.env",
        "username": "admin",
        "password": "P@ssw0rd_HoneyDecoy!",
        "detail": "Test Adversary Probe on /.env",
        "intel": test_intel,
    }

    msg = alert_mgr.format_telegram_message(test_event)
    print("\n--- Formatted Alert Message ---\n" + msg + "\n-------------------------------")

    if alert_mgr.tg_token and alert_mgr.tg_chat:
        success = alert_mgr.send_telegram(msg)
        print(f"[+] Telegram dispatch result: {'SUCCESS' if success else 'FAILED'}")
    else:
        print("[!] Telegram bot_token / chat_id not configured in config. Skipping API call.")


def main() -> None:
    if sys.platform == "win32":
        try:
            sys.stdout.reconfigure(encoding="utf-8")
            sys.stderr.reconfigure(encoding="utf-8")
        except AttributeError:
            pass

    parser = argparse.ArgumentParser(description="HoneyNet — Multi-Vector SOC Decoy & Telemetry Engine")
    parser.add_argument("--config", "-c", help="Path to custom JSON configuration file")
    subparsers = parser.add_subparsers(dest="command", required=True)

    # run command
    run_parser = subparsers.add_parser("run", help="Start HoneyNet daemon services")
    run_parser.add_argument("--no-ssh", action="store_true", help="Disable SSH honeypot")
    run_parser.add_argument("--no-http", action="store_true", help="Disable HTTP honeypot")
    run_parser.add_argument("--no-dashboard", action="store_true", help="Disable Web dashboard")

    # status command
    subparsers.add_parser("status", help="Display summary of recorded telemetry")

    # export-wazuh command
    wazuh_parser = subparsers.add_parser("export-wazuh", help="Export Wazuh CDB dynamic blacklist rules")
    wazuh_parser.add_argument("--out", "-o", help="Target output file path")

    # test-alert command
    subparsers.add_parser("test-alert", help="Verify Telegram / Webhook notification dispatching")

    args = parser.parse_args()

    if args.command == "run":
        cmd_run(args)
    elif args.command == "status":
        cmd_status(args)
    elif args.command == "export-wazuh":
        cmd_export_wazuh(args)
    elif args.command == "test-alert":
        cmd_test_alert(args)


if __name__ == "__main__":
    main()
