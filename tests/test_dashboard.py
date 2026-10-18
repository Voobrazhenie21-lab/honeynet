"""Unit tests for honeynet.dashboard API, rule generators, and XSS protection."""
import os
import tempfile
from honeynet.core import Event, EventLogger
from honeynet.dashboard import DashboardServer, DASHBOARD_HTML, HTTP_STATUS_PHRASES
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


def test_dashboard_xss_protection_in_template():
    """Verify that the dashboard template contains HTML sanitization logic for stored events."""
    assert "function escapeHtml" in DASHBOARD_HTML
    assert ".replace(/&/g, '&amp;')" in DASHBOARD_HTML
    assert ".replace(/</g, '&lt;')" in DASHBOARD_HTML
    assert ".replace(/>/g, '&gt;')" in DASHBOARD_HTML
    assert "escapeHtml(c.user" in DASHBOARD_HTML
    assert "escapeHtml(c.pass" in DASHBOARD_HTML
    assert "escapeHtml(rawDetail)" in DASHBOARD_HTML
    assert "escapeHtml(ev.src_ip" in DASHBOARD_HTML


def test_dashboard_host_override_via_env():
    """Verify that HONEYNET_DASHBOARD_HOST environment variable overrides dashboard host."""
    old_env = os.environ.get("HONEYNET_DASHBOARD_HOST")
    try:
        os.environ["HONEYNET_DASHBOARD_HOST"] = "0.0.0.0"
        server = DashboardServer({}, None)  # type: ignore
        assert server.host == "0.0.0.0"
    finally:
        if old_env is None:
            os.environ.pop("HONEYNET_DASHBOARD_HOST", None)
        else:
            os.environ["HONEYNET_DASHBOARD_HOST"] = old_env


def test_dashboard_http_status_phrases():
    """Verify that HTTP status codes are mapped to standard reason phrases."""
    assert HTTP_STATUS_PHRASES[200] == "OK"
    assert HTTP_STATUS_PHRASES[404] == "Not Found"
    assert HTTP_STATUS_PHRASES[401] == "Unauthorized"
    assert HTTP_STATUS_PHRASES[403] == "Forbidden"
