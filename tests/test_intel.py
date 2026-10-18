"""Unit tests for honeynet.intel threat intelligence engine."""
from unittest.mock import patch, MagicMock
from honeynet.intel import (
    classify_ip,
    shannon_entropy,
    assess_event,
    run_threatpulse_enrichment,
    query_abuseipdb,
    _ABUSEIPDB_CACHE,
)


def test_classify_ip():
    assert classify_ip("127.0.0.1")["category"] == "loopback"
    assert classify_ip("10.244.0.5")["category"] == "private_rfc1918"
    assert classify_ip("192.168.1.100")["is_bogon"] is True
    assert classify_ip("185.220.101.5")["category"] == "public_routable"
    assert classify_ip("185.220.101.5")["is_bogon"] is False
    assert classify_ip("invalid_ip")["valid"] is False


def test_shannon_entropy():
    assert shannon_entropy("") == 0.0
    assert shannon_entropy("aaaaaa") == 0.0
    assert shannon_entropy("abcdef123456") > 3.0


def test_assess_event_high_risk_http_env():
    intel = assess_event(
        proto="http",
        src_ip="185.220.101.5",
        kind="http_request",
        path="/.env"
    )
    assert intel["score"] >= 50
    assert intel["severity"] in ("HIGH", "CRITICAL")
    assert any(m["id"] == "T1005" for m in intel["mitre"])
    assert "185.220.101.5" in intel["wazuh_cdb"]


def test_assess_event_ssh_bruteforce_root():
    intel = assess_event(
        proto="ssh",
        src_ip="91.240.118.12",
        kind="auth_attempt",
        username="root",
        password="SuperSecretPassword123!"
    )
    assert intel["score"] >= 60
    assert any(m["id"] == "T1110.001" for m in intel["mitre"])
    assert "protocol:ssh" in intel["tags"]
    assert "cred:privileged_target" in intel["tags"]


def test_assess_event_bogon_score_damping():
    # Bogon / local traffic score is capped to prevent false positives on internal tests
    intel = assess_event(
        proto="http",
        src_ip="10.0.0.1",
        kind="http_request",
        path="/.env"
    )
    assert intel["score"] <= 45
    assert intel["ip_meta"]["is_bogon"] is True


def test_assess_event_abuseipdb_enrichment():
    _ABUSEIPDB_CACHE.clear()
    fake_abuse_data = {
        "ipAddress": "185.220.101.5",
        "abuseConfidenceScore": 95,
        "countryCode": "DE",
        "totalReports": 412,
    }

    config = {
        "intel": {
            "abuseipdb_api_key": "test_fake_api_key",
        }
    }

    with patch("honeynet.intel.query_abuseipdb", return_value=fake_abuse_data) as mock_query:
        intel = assess_event(
            proto="http",
            src_ip="185.220.101.5",
            kind="http_request",
            path="/robots.txt",
            config=config,
        )
        assert mock_query.called
        assert intel["score"] >= 95
        assert intel["severity"] == "CRITICAL"
        assert "abuseipdb:score_95" in intel["tags"]
        assert intel["abuseipdb"]["abuseConfidenceScore"] == 95

        # Verify caching: second call for same IP should not invoke query_abuseipdb again
        mock_query.reset_mock()
        intel2 = assess_event(
            proto="http",
            src_ip="185.220.101.5",
            kind="http_request",
            path="/robots.txt",
            config=config,
        )
        assert not mock_query.called
        assert intel2["score"] >= 95


def test_run_threatpulse_enrichment_uses_shlex():
    with patch("subprocess.run") as mock_run:
        mock_proc = MagicMock()
        mock_proc.returncode = 0
        mock_proc.stdout = '{"threat_score": 85, "verdict": "malicious"}'
        mock_run.return_value = mock_proc

        res = run_threatpulse_enrichment("185.220.101.5", "threatpulse check {ip}")
        assert res == {"threat_score": 85, "verdict": "malicious"}
        # Ensure subprocess.run was called with a list of args (shlex.split), NOT shell=True
        call_args, call_kwargs = mock_run.call_args
        assert isinstance(call_args[0], list)
        assert call_args[0] == ["threatpulse", "check", "185.220.101.5"]
        assert "shell" not in call_kwargs or call_kwargs["shell"] is False
