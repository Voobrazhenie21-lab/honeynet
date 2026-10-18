"""Unit tests for honeynet.http_pot server routing and headers."""
import pytest
from honeynet.core import EventLogger
from honeynet.http_pot import HttpHoneypotServer, HTTP_STATUS_PHRASES


def test_http_pot_route_request():
    server = HttpHoneypotServer({}, None)  # type: ignore

    # Decoy login portal
    code, ctype, body = server.route_request("/", "GET", "", "")
    assert code == 200
    assert "text/html" in ctype
    assert "ACME Internal SSO" in body

    # Decoy environment leakage
    code, ctype, body = server.route_request("/.env", "GET", "", "")
    assert code == 200
    assert "DB_PASSWORD" in body
    assert "AWS_ACCESS_KEY_ID" in body

    # Decoy git config
    code, ctype, body = server.route_request("/.git/config", "GET", "", "")
    assert code == 200
    assert "repositoryformatversion" in body

    # Decoy robots.txt
    code, ctype, body = server.route_request("/robots.txt", "GET", "", "")
    assert code == 200
    assert "Disallow: /.env" in body

    # WordPress decoy probe
    code, ctype, body = server.route_request("/wp-login.php", "GET", "", "")
    assert code == 403
    assert "WAF IP Blocklist" in body

    # Default 404
    code, ctype, body = server.route_request("/random_path", "GET", "", "")
    assert code == 404


def test_http_pot_status_phrases():
    """Verify HTTP reason phrases are properly declared."""
    assert HTTP_STATUS_PHRASES[200] == "OK"
    assert HTTP_STATUS_PHRASES[401] == "Unauthorized"
    assert HTTP_STATUS_PHRASES[403] == "Forbidden"
    assert HTTP_STATUS_PHRASES[404] == "Not Found"
