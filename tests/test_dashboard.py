"""Unit tests for honeynet.dashboard API and rule generators."""
import tempfile
import os
from honeynet.core import Event, EventLogger
from honeynet.dashboard import DashboardServer
from honeynet.intel import assess_event


def test_dashboard_compute_stats_and_rules():
    with tempfile.NamedTemporaryFile(suffix=".jsonl", delete=False) as tf:
        path = tf.name

    try:
        logger = EventLogger(path)
        intel1 = assess_event("http", "185.220.101.5", "http_request", path="/.env")
        ev1 = Event(
            ts="2026-10-17T18:00:00",
            proto="http",
            src_ip="185.220.101.5",
            kind="http_request",
            path="/.env",
            intel=intel1
        )
        intel2 = assess_event("ssh", "91.240.118.5", "auth_attempt", username="admin", password="password123")
        ev2 = Event(
            ts="2026-10-17T18:01:00",
            proto="ssh",
            src_ip="91.240.118.5",
            kind="auth_attempt",
            username="admin",
            password="password123",
            intel=intel2
        )
        logger.write(ev1)
        logger.write(ev2)

        server = DashboardServer({}, logger)
        stats = server.compute_stats()

        assert stats["total_events"] == 2
        assert stats["unique_ips"] == 2
        assert stats["creds_count"] == 1
        assert len(stats["wazuh_rules"]) >= 1

        wazuh_list = server.generate_wazuh_cdb()
        assert any("185.220.101.5" in r for r in wazuh_list)

        snort_list = server.generate_snort_rules()
        assert any("185.220.101.5" in r for r in snort_list)

    finally:
        if os.path.exists(path):
            os.remove(path)
