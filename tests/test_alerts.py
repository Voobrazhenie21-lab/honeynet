"""Unit tests for honeynet.alerts alert manager."""
from honeynet.alerts import AlertManager


def test_alert_manager_should_alert_threshold():
    mgr = AlertManager({"intel": {"min_score_alert": 50}, "alerts": {"rate_limit_seconds": 10}})
    
    low_event = {"src_ip": "1.1.1.1", "intel": {"score": 30}}
    assert mgr.should_alert(low_event) is False

    high_event = {"src_ip": "1.1.1.1", "intel": {"score": 85}}
    assert mgr.should_alert(high_event) is True


def test_alert_manager_rate_limiting():
    mgr = AlertManager({"intel": {"min_score_alert": 50}, "alerts": {"rate_limit_seconds": 60}})
    high_event = {"src_ip": "185.220.101.5", "intel": {"score": 90}}
    
    # First time -> allowed
    assert mgr.should_alert(high_event) is True
    mgr.consider(high_event)

    # Immediately subsequent event for same IP -> throttled
    assert mgr.should_alert(high_event) is False

    # Different IP -> allowed
    diff_ip_event = {"src_ip": "91.240.118.10", "intel": {"score": 90}}
    assert mgr.should_alert(diff_ip_event) is True


def test_format_telegram_message():
    mgr = AlertManager()
    event = {
        "ts": "2026-10-17T18:00:00",
        "proto": "http",
        "src_ip": "185.220.101.5",
        "kind": "http_request",
        "path": "/.env",
        "intel": {
            "score": 80,
            "severity": "HIGH",
            "mitre": [{"id": "T1190", "name": "Exploit Public-Facing Application"}],
            "wazuh_cdb": "185.220.101.5:high:T1190:block",
        }
    }
    msg = mgr.format_telegram_message(event)
    assert "HONEYNET SOC ALERT" in msg
    assert "185.220.101.5" in msg
    assert "T1190" in msg
    assert "185.220.101.5:high:T1190:block" in msg
