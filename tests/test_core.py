"""Unit tests for honeynet.core primitives."""
import json
import os
import tempfile
import pytest

from honeynet.core import Event, EventLogger, AUTH_ATTEMPT, load_config, DEFAULT_CONFIG


def test_event_to_dict_drops_empty_fields():
    ev = Event(ts="2026-10-17T18:00:00", proto="http", src_ip="1.2.3.4", kind=AUTH_ATTEMPT)
    d = ev.to_dict()
    assert d["proto"] == "http"
    assert d["src_ip"] == "1.2.3.4"
    assert "password" not in d
    assert "command" not in d


def test_event_logger_write_and_read():
    with tempfile.NamedTemporaryFile(suffix=".jsonl", delete=False) as tf:
        path = tf.name

    try:
        logger = EventLogger(path)
        ev1 = Event(ts="2026-10-17T18:01:00", proto="http", src_ip="10.0.0.1", kind="http_request", path="/.env")
        ev2 = Event(ts="2026-10-17T18:01:05", proto="ssh", src_ip="192.168.1.5", kind="auth_attempt", username="root")

        logger.write(ev1)
        logger.write(ev2)

        events = logger.read_all()
        assert len(events) == 2
        assert events[0]["path"] == "/.env"
        assert events[1]["username"] == "root"

        recent = logger.read_recent(1)
        assert len(recent) == 1
        assert recent[0]["proto"] == "ssh"
    finally:
        if os.path.exists(path):
            os.remove(path)


def test_event_logger_rotation():
    with tempfile.NamedTemporaryFile(suffix=".jsonl", delete=False) as tf:
        path = tf.name

    try:
        # Rotate after 1MB
        logger = EventLogger(path, rotate_mb=1)
        # Write large junk to trigger rotation
        with open(path, "w") as fh:
            fh.write("X" * (1024 * 1024 + 10))

        ev = Event(ts="2026-10-17T18:02:00", proto="http", src_ip="8.8.8.8", kind="http_request")
        logger.write(ev)

        assert os.path.exists(path + ".1")
        assert os.path.getsize(path) < 1000
    finally:
        if os.path.exists(path):
            os.remove(path)
        if os.path.exists(path + ".1"):
            os.remove(path + ".1")


def test_load_config_defaults():
    cfg = load_config()
    assert cfg["http"]["port"] == 8080
    assert cfg["ssh"]["port"] == 2222
    assert cfg["dashboard"]["port"] == 8888


def test_load_config_custom_merge():
    with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as tf:
        json.dump({"http": {"port": 9090}, "intel": {"min_score_alert": 60}}, tf)
        cfg_path = tf.name

    try:
        cfg = load_config(cfg_path)
        assert cfg["http"]["port"] == 9090
        assert cfg["http"]["enabled"] is True  # preserved default
        assert cfg["intel"]["min_score_alert"] == 60
    finally:
        if os.path.exists(cfg_path):
            os.remove(cfg_path)


def test_event_to_dict_deduplicates_tags():
    ev = Event(
        ts="2026-10-17T18:00:00",
        proto="http",
        src_ip="1.2.3.4",
        kind="http_request",
        tags=["protocol:http", "probe:env"],
        intel={"score": 80, "tags": ["protocol:http", "probe:env"]}
    )
    d = ev.to_dict()
    assert d["tags"] == ["protocol:http", "probe:env"]
    assert "tags" not in d["intel"]


def test_load_config_env_dashboard_host():
    old = os.environ.get("HONEYNET_DASHBOARD_HOST")
    try:
        os.environ["HONEYNET_DASHBOARD_HOST"] = "0.0.0.0"
        cfg = load_config()
        assert cfg["dashboard"]["host"] == "0.0.0.0"
    finally:
        if old is None:
            os.environ.pop("HONEYNET_DASHBOARD_HOST", None)
        else:
            os.environ["HONEYNET_DASHBOARD_HOST"] = old

