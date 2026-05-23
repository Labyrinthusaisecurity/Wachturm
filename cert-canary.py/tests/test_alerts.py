#!/usr/bin/env python3
"""
tests/test_alerts.py
━━━━━━━━━━━━━━━━━━━
Unit tests for cert_canary/alerts/*.

Tests cover:
  • alerts/base.py   — _should_alert(), _http_post(), _log_alert()
  • alerts/slack.py  — alert_slack() payload structure
  • alerts/discord.py — alert_discord() embed structure
  • alerts/pagerduty.py — alert_pagerduty() trigger + resolve
  • alerts/email.py  — alert_email() SMTP calls and message structure
  • alerts/webhook.py — alert_webhook() payload + HMAC signing
  • alerts/__init__.py — dispatch_alerts() calls all channels

All network I/O and SMTP connections are mocked.
No real HTTP requests or emails are sent.
"""

import hashlib
import hmac
import json
import smtplib
from dataclasses import asdict
from unittest.mock import MagicMock, call, patch

import pytest

from cert_canary.alerts       import dispatch_alerts
from cert_canary.alerts.base  import _should_alert, _http_post, _log_alert
from cert_canary.alerts.slack     import alert_slack
from cert_canary.alerts.discord   import alert_discord
from cert_canary.alerts.pagerduty import alert_pagerduty, resolve_pagerduty
from cert_canary.alerts.email     import alert_email
from cert_canary.alerts.webhook   import alert_webhook
from cert_canary.scanner      import CertInfo, _error, _grade


# ─────────────────────────────────────────────
# Fixtures
# ─────────────────────────────────────────────

@pytest.fixture
def thresholds():
    return {"critical": 7, "warning": 30, "info": 60}


@pytest.fixture
def base_config(thresholds):
    return {"thresholds": thresholds}


@pytest.fixture
def slack_config(base_config):
    return {**base_config, "slack_webhook": "https://hooks.slack.com/T/B/XXX"}


@pytest.fixture
def discord_config(base_config):
    return {**base_config, "discord_webhook": "https://discord.com/api/webhooks/1/XXX"}


@pytest.fixture
def pagerduty_config(base_config):
    return {**base_config, "pagerduty_key": "TESTKEY123"}


@pytest.fixture
def webhook_config(base_config):
    return {**base_config, "webhook_url": "https://example.com/hooks/certs"}


@pytest.fixture
def webhook_signed_config(webhook_config):
    return {**webhook_config, "webhook_secret": "super-secret-key"}


@pytest.fixture
def smtp_config(base_config):
    return {
        **base_config,
        "smtp": {
            "host":     "smtp.example.com",
            "port":     587,
            "starttls": True,
            "ssl":      False,
            "user":     "canary@example.com",
            "password": "app-password",
            "from":     "canary@example.com",
            "to":       ["ops@example.com", "sec@example.com"],
        },
    }


@pytest.fixture
def full_config(thresholds):
    return {
        "thresholds":      thresholds,
        "slack_webhook":   "https://hooks.slack.com/T/B/XXX",
        "discord_webhook": "https://discord.com/api/webhooks/1/XXX",
        "pagerduty_key":   "TESTKEY123",
        "webhook_url":     "https://example.com/hooks/certs",
        "smtp": {
            "host": "smtp.example.com", "port": 587, "starttls": True,
            "ssl": False, "user": "u", "password": "p",
            "from": "f@example.com", "to": ["t@example.com"],
        },
    }


def _make_cert(
    host:       str  = "example.com",
    port:       int  = 443,
    days_left:  int  = 90,
    grade:      str  = "OK",
    error:      str  = None,
    self_signed:bool = False,
    wildcard:   bool = False,
    expired:    bool = False,
) -> CertInfo:
    """Build a CertInfo for use in alert tests."""
    if expired:
        days_left = -5
        grade     = "CRITICAL"
    return CertInfo(
        host        = host,
        port        = port,
        common_name = f"*.{host}" if wildcard else host,
        sans        = [host],
        wildcard    = wildcard,
        serial      = "DEADBEEF",
        not_before  = "2026-01-01 00:00 UTC",
        not_after   = "2026-12-31 00:00 UTC",
        days_left   = days_left,
        issuer      = "R3",
        issuer_org  = "Let's Encrypt",
        self_signed = self_signed,
        tls_version = "TLSv1.3",
        cipher      = "TLS_AES_256_GCM_SHA384",
        cipher_bits = 256,
        fingerprint = "aabbccdd11223344",
        grade       = grade,
        error       = error,
    )


# ─────────────────────────────────────────────
# base.py tests
# ─────────────────────────────────────────────

class TestShouldAlert:

    def test_ok_cert_does_not_alert(self, thresholds):
        r = _make_cert(grade="OK", days_left=90)
        assert _should_alert(r, thresholds) is False

    def test_info_cert_alerts(self, thresholds):
        r = _make_cert(grade="INFO", days_left=45)
        assert _should_alert(r, thresholds) is True

    def test_warning_cert_alerts(self, thresholds):
        r = _make_cert(grade="WARNING", days_left=15)
        assert _should_alert(r, thresholds) is True

    def test_critical_cert_alerts(self, thresholds):
        r = _make_cert(grade="CRITICAL", days_left=3)
        assert _should_alert(r, thresholds) is True

    def test_expired_cert_alerts(self, thresholds):
        r = _make_cert(expired=True)
        assert _should_alert(r, thresholds) is True

    def test_error_cert_alerts(self, thresholds):
        r = _make_cert(error="Connection refused")
        assert _should_alert(r, thresholds) is True

    def test_ok_cert_with_error_alerts(self, thresholds):
        # error takes priority over grade
        r = _make_cert(grade="OK", error="DNS failed")
        assert _should_alert(r, thresholds) is True


class TestHttpPost:

    @patch("urllib.request.urlopen")
    def test_posts_json_content_type(self, mock_urlopen):
        mock_resp = MagicMock()
        mock_resp.status = 200
        mock_resp.read.return_value = b"ok"
        mock_resp.__enter__ = lambda s: s
        mock_resp.__exit__  = MagicMock(return_value=False)
        mock_urlopen.return_value = mock_resp

        _http_post("https://example.com", {"key": "value"})

        req = mock_urlopen.call_args[0][0]
        assert req.get_header("Content-type") == "application/json"

    @patch("urllib.request.urlopen")
    def test_returns_status_and_body(self, mock_urlopen):
        mock_resp = MagicMock()
        mock_resp.status = 200
        mock_resp.read.return_value = b"ok"
        mock_resp.__enter__ = lambda s: s
        mock_resp.__exit__  = MagicMock(return_value=False)
        mock_urlopen.return_value = mock_resp

        status, body = _http_post("https://example.com", {})
        assert status == 200
        assert body   == "ok"

    @patch("urllib.request.urlopen")
    def test_serialises_payload_as_json(self, mock_urlopen):
        mock_resp = MagicMock()
        mock_resp.status = 200
        mock_resp.read.return_value = b""
        mock_resp.__enter__ = lambda s: s
        mock_resp.__exit__  = MagicMock(return_value=False)
        mock_urlopen.return_value = mock_resp

        payload = {"host": "example.com", "days": 90}
        _http_post("https://example.com", payload)

        req  = mock_urlopen.call_args[0][0]
        data = json.loads(req.data.decode())
        assert data == payload

    @patch("urllib.request.urlopen")
    def test_custom_headers_merged(self, mock_urlopen):
        mock_resp = MagicMock()
        mock_resp.status = 200
        mock_resp.read.return_value = b""
        mock_resp.__enter__ = lambda s: s
        mock_resp.__exit__  = MagicMock(return_value=False)
        mock_urlopen.return_value = mock_resp

        _http_post("https://example.com", {}, headers={"X-Custom": "value"})
        req = mock_urlopen.call_args[0][0]
        assert req.get_header("X-custom") == "value"

    @patch("urllib.request.urlopen", side_effect=Exception("network down"))
    def test_returns_minus_one_on_exception(self, _):
        status, body = _http_post("https://example.com", {})
        assert status == -1
        assert "network down" in body


# ─────────────────────────────────────────────
# alerts/slack.py tests
# ─────────────────────────────────────────────

class TestAlertSlack:

    def _run(self, results, config):
        with patch("cert_canary.alerts.slack._http_post") as mock_post:
            mock_post.return_value = (200, "ok")
            alert_slack(results, config)
            return mock_post

    def test_no_call_when_no_webhook(self, base_config):
        mock = self._run([_make_cert(grade="CRITICAL", days_left=3)], base_config)
        mock.assert_not_called()

    def test_no_call_when_no_alertable_results(self, slack_config):
        mock = self._run([_make_cert(grade="OK", days_left=90)], slack_config)
        mock.assert_not_called()

    def test_posts_to_webhook_url(self, slack_config):
        mock = self._run([_make_cert(grade="CRITICAL", days_left=3)], slack_config)
        mock.assert_called_once()
        url = mock.call_args[0][0]
        assert url == slack_config["slack_webhook"]

    def test_payload_has_blocks(self, slack_config):
        mock = self._run([_make_cert(grade="CRITICAL", days_left=3)], slack_config)
        payload = mock.call_args[0][1]
        assert "blocks" in payload
        assert isinstance(payload["blocks"], list)

    def test_payload_has_header_block(self, slack_config):
        mock = self._run([_make_cert(grade="CRITICAL", days_left=3)], slack_config)
        payload = mock.call_args[0][1]
        block_types = [b["type"] for b in payload["blocks"]]
        assert "header" in block_types

    def test_payload_contains_host(self, slack_config):
        mock = self._run([_make_cert(host="api.example.com", grade="CRITICAL", days_left=3)], slack_config)
        payload_str = json.dumps(mock.call_args[0][1])
        assert "api.example.com" in payload_str

    def test_multiple_alertable_hosts(self, slack_config):
        results = [
            _make_cert(host="a.com", grade="CRITICAL", days_left=3),
            _make_cert(host="b.com", grade="WARNING",  days_left=20),
        ]
        mock = self._run(results, slack_config)
        payload_str = json.dumps(mock.call_args[0][1])
        assert "a.com" in payload_str
        assert "b.com" in payload_str

    def test_ok_certs_not_included(self, slack_config):
        results = [
            _make_cert(host="ok.com",   grade="OK",       days_left=90),
            _make_cert(host="crit.com", grade="CRITICAL", days_left=3),
        ]
        mock = self._run(results, slack_config)
        payload_str = json.dumps(mock.call_args[0][1])
        assert "ok.com"   not in payload_str
        assert "crit.com" in     payload_str

    def test_self_signed_warning_in_payload(self, slack_config):
        mock = self._run(
            [_make_cert(grade="WARNING", days_left=20, self_signed=True)],
            slack_config,
        )
        payload_str = json.dumps(mock.call_args[0][1])
        assert "self-signed" in payload_str.lower() or "Self-signed" in payload_str

    def test_expired_cert_in_payload(self, slack_config):
        mock = self._run([_make_cert(expired=True)], slack_config)
        payload_str = json.dumps(mock.call_args[0][1])
        assert "EXPIRED" in payload_str or "expired" in payload_str.lower()

    def test_error_cert_in_payload(self, slack_config):
        mock = self._run(
            [_make_cert(error="Connection refused", grade="CRITICAL", days_left=-9999)],
            slack_config,
        )
        payload_str = json.dumps(mock.call_args[0][1])
        assert "Connection refused" in payload_str


# ─────────────────────────────────────────────
# alerts/discord.py tests
# ─────────────────────────────────────────────

class TestAlertDiscord:

    def _run(self, results, config):
        with patch("cert_canary.alerts.discord._http_post") as mock_post:
            mock_post.return_value = (200, "")
            alert_discord(results, config)
            return mock_post

    def test_no_call_when_no_webhook(self, base_config):
        mock = self._run([_make_cert(grade="CRITICAL", days_left=3)], base_config)
        mock.assert_not_called()

    def test_no_call_when_no_alertable_results(self, discord_config):
        mock = self._run([_make_cert(grade="OK", days_left=90)], discord_config)
        mock.assert_not_called()

    def test_posts_to_webhook_url(self, discord_config):
        mock = self._run([_make_cert(grade="CRITICAL", days_left=3)], discord_config)
        mock.assert_called_once()
        assert mock.call_args[0][0] == discord_config["discord_webhook"]

    def test_payload_has_embeds(self, discord_config):
        mock = self._run([_make_cert(grade="CRITICAL", days_left=3)], discord_config)
        payload = mock.call_args[0][1]
        assert "embeds" in payload
        assert isinstance(payload["embeds"], list)
        assert len(payload["embeds"]) >= 1

    def test_embed_has_required_fields(self, discord_config):
        mock = self._run([_make_cert(grade="CRITICAL", days_left=3)], discord_config)
        embed = mock.call_args[0][1]["embeds"][0]
        assert "title"  in embed
        assert "color"  in embed
        assert "fields" in embed

    def test_embed_color_is_int(self, discord_config):
        mock = self._run([_make_cert(grade="CRITICAL", days_left=3)], discord_config)
        color = mock.call_args[0][1]["embeds"][0]["color"]
        assert isinstance(color, int)

    def test_critical_embed_color_is_red(self, discord_config):
        mock  = self._run([_make_cert(grade="CRITICAL", days_left=3)], discord_config)
        color = mock.call_args[0][1]["embeds"][0]["color"]
        assert color == 0xff4444

    def test_warning_embed_color_is_amber(self, discord_config):
        mock  = self._run([_make_cert(grade="WARNING", days_left=15)], discord_config)
        color = mock.call_args[0][1]["embeds"][0]["color"]
        assert color == 0xffb800

    def test_max_10_embeds_per_message(self, discord_config):
        """Discord rejects messages with more than 10 embeds."""
        results = [
            _make_cert(host=f"host{i}.com", grade="CRITICAL", days_left=3)
            for i in range(15)
        ]
        mock   = self._run(results, discord_config)
        embeds = mock.call_args[0][1]["embeds"]
        assert len(embeds) <= 10

    def test_username_in_payload(self, discord_config):
        mock    = self._run([_make_cert(grade="CRITICAL", days_left=3)], discord_config)
        payload = mock.call_args[0][1]
        assert "username" in payload
        assert payload["username"] == "cert-canary"

    def test_host_in_embed_title(self, discord_config):
        mock  = self._run([_make_cert(host="api.example.com", grade="CRITICAL", days_left=3)], discord_config)
        title = mock.call_args[0][1]["embeds"][0]["title"]
        assert "api.example.com" in title


# ─────────────────────────────────────────────
# alerts/pagerduty.py tests
# ─────────────────────────────────────────────

class TestAlertPagerduty:

    PAGERDUTY_URL = "https://events.pagerduty.com/v2/enqueue"

    def _run(self, results, config):
        with patch("cert_canary.alerts.pagerduty._http_post") as mock_post:
            mock_post.return_value = (202, '{"status":"success"}')
            alert_pagerduty(results, config)
            return mock_post

    def test_no_call_when_no_key(self, base_config):
        mock = self._run([_make_cert(grade="CRITICAL", days_left=3)], base_config)
        mock.assert_not_called()

    def test_no_call_when_no_alertable_results(self, pagerduty_config):
        mock = self._run([_make_cert(grade="OK", days_left=90)], pagerduty_config)
        mock.assert_not_called()

    def test_posts_to_pagerduty_url(self, pagerduty_config):
        mock = self._run([_make_cert(grade="CRITICAL", days_left=3)], pagerduty_config)
        mock.assert_called()
        url = mock.call_args[0][0]
        assert url == self.PAGERDUTY_URL

    def test_routing_key_in_payload(self, pagerduty_config):
        mock    = self._run([_make_cert(grade="CRITICAL", days_left=3)], pagerduty_config)
        payload = mock.call_args[0][1]
        assert payload["routing_key"] == "TESTKEY123"

    def test_event_action_is_trigger(self, pagerduty_config):
        mock    = self._run([_make_cert(grade="CRITICAL", days_left=3)], pagerduty_config)
        payload = mock.call_args[0][1]
        assert payload["event_action"] == "trigger"

    def test_dedup_key_contains_host(self, pagerduty_config):
        mock    = self._run([_make_cert(host="api.example.com", grade="CRITICAL", days_left=3)], pagerduty_config)
        payload = mock.call_args[0][1]
        assert "api.example.com" in payload["dedup_key"]

    def test_dedup_key_contains_port(self, pagerduty_config):
        mock    = self._run([_make_cert(host="api.example.com", port=8443, grade="CRITICAL", days_left=3)], pagerduty_config)
        payload = mock.call_args[0][1]
        assert "8443" in payload["dedup_key"]

    def test_severity_critical(self, pagerduty_config):
        mock    = self._run([_make_cert(grade="CRITICAL", days_left=3)], pagerduty_config)
        payload = mock.call_args[0][1]
        assert payload["payload"]["severity"] == "critical"

    def test_severity_warning(self, pagerduty_config):
        mock    = self._run([_make_cert(grade="WARNING", days_left=15)], pagerduty_config)
        payload = mock.call_args[0][1]
        assert payload["payload"]["severity"] == "warning"

    def test_severity_info(self, pagerduty_config):
        mock    = self._run([_make_cert(grade="INFO", days_left=45)], pagerduty_config)
        payload = mock.call_args[0][1]
        assert payload["payload"]["severity"] == "info"

    def test_custom_details_contains_days_left(self, pagerduty_config):
        mock    = self._run([_make_cert(grade="CRITICAL", days_left=3)], pagerduty_config)
        details = mock.call_args[0][1]["payload"]["custom_details"]
        assert details["days_left"] == 3

    def test_custom_details_contains_issuer(self, pagerduty_config):
        mock    = self._run([_make_cert(grade="CRITICAL", days_left=3)], pagerduty_config)
        details = mock.call_args[0][1]["payload"]["custom_details"]
        assert details["issuer"] == "Let's Encrypt"

    def test_one_event_per_alertable_host(self, pagerduty_config):
        results = [
            _make_cert(host="a.com", grade="CRITICAL", days_left=3),
            _make_cert(host="b.com", grade="WARNING",  days_left=15),
            _make_cert(host="c.com", grade="OK",       days_left=90),
        ]
        mock = self._run(results, pagerduty_config)
        # Only a.com and b.com should trigger — c.com is OK
        assert mock.call_count == 2

    def test_summary_contains_host(self, pagerduty_config):
        mock    = self._run([_make_cert(host="api.example.com", grade="CRITICAL", days_left=3)], pagerduty_config)
        summary = mock.call_args[0][1]["payload"]["summary"]
        assert "api.example.com" in summary


class TestResolvePagerduty:

    PAGERDUTY_URL = "https://events.pagerduty.com/v2/enqueue"

    def test_posts_resolve_action(self, pagerduty_config):
        with patch("cert_canary.alerts.pagerduty._http_post") as mock_post:
            mock_post.return_value = (202, '{"status":"success"}')
            resolve_pagerduty("example.com", 443, pagerduty_config)
            payload = mock_post.call_args[0][1]
            assert payload["event_action"] == "resolve"

    def test_dedup_key_matches_trigger_format(self, pagerduty_config):
        with patch("cert_canary.alerts.pagerduty._http_post") as mock_post:
            mock_post.return_value = (202, "{}")
            resolve_pagerduty("example.com", 443, pagerduty_config)
            payload = mock_post.call_args[0][1]
            assert "example.com" in payload["dedup_key"]
            assert "443"         in payload["dedup_key"]

    def test_no_call_when_no_key(self, base_config):
        with patch("cert_canary.alerts.pagerduty._http_post") as mock_post:
            resolve_pagerduty("example.com", 443, base_config)
            mock_post.assert_not_called()


# ─────────────────────────────────────────────
# alerts/email.py tests
# ─────────────────────────────────────────────

class TestAlertEmail:

    def _run(self, results, config, starttls=True):
        with patch("smtplib.SMTP") as mock_smtp_cls:
            mock_server = MagicMock()
            mock_smtp_cls.return_value = mock_server
            alert_email(results, config)
            return mock_smtp_cls, mock_server

    def test_no_call_when_no_smtp_config(self, base_config):
        cls, srv = self._run([_make_cert(grade="CRITICAL", days_left=3)], base_config)
        cls.assert_not_called()

    def test_no_call_when_no_alertable_results(self, smtp_config):
        cls, srv = self._run([_make_cert(grade="OK", days_left=90)], smtp_config)
        cls.assert_not_called()

    def test_connects_to_smtp_host(self, smtp_config):
        cls, srv = self._run([_make_cert(grade="CRITICAL", days_left=3)], smtp_config)
        cls.assert_called_once_with("smtp.example.com", 587, timeout=15)

    def test_calls_starttls(self, smtp_config):
        _, srv = self._run([_make_cert(grade="CRITICAL", days_left=3)], smtp_config)
        srv.starttls.assert_called_once()

    def test_calls_login(self, smtp_config):
        _, srv = self._run([_make_cert(grade="CRITICAL", days_left=3)], smtp_config)
        srv.login.assert_called_once_with("canary@example.com", "app-password")

    def test_calls_sendmail(self, smtp_config):
        _, srv = self._run([_make_cert(grade="CRITICAL", days_left=3)], smtp_config)
        srv.sendmail.assert_called_once()

    def test_sendmail_from_address(self, smtp_config):
        _, srv = self._run([_make_cert(grade="CRITICAL", days_left=3)], smtp_config)
        from_addr = srv.sendmail.call_args[0][0]
        assert from_addr == "canary@example.com"

    def test_sendmail_to_addresses(self, smtp_config):
        _, srv = self._run([_make_cert(grade="CRITICAL", days_left=3)], smtp_config)
        to_addrs = srv.sendmail.call_args[0][1]
        assert "ops@example.com" in to_addrs
        assert "sec@example.com" in to_addrs

    def test_email_body_contains_host(self, smtp_config):
        _, srv = self._run(
            [_make_cert(host="api.example.com", grade="CRITICAL", days_left=3)],
            smtp_config,
        )
        raw_msg = srv.sendmail.call_args[0][2]
        assert "api.example.com" in raw_msg

    def test_email_body_contains_grade(self, smtp_config):
        _, srv = self._run([_make_cert(grade="CRITICAL", days_left=3)], smtp_config)
        raw_msg = srv.sendmail.call_args[0][2]
        assert "CRITICAL" in raw_msg

    def test_subject_contains_critical_when_critical_certs(self, smtp_config):
        _, srv = self._run([_make_cert(grade="CRITICAL", days_left=3)], smtp_config)
        raw_msg = srv.sendmail.call_args[0][2]
        assert "CRITICAL" in raw_msg or "critical" in raw_msg.lower()

    def test_calls_quit(self, smtp_config):
        _, srv = self._run([_make_cert(grade="CRITICAL", days_left=3)], smtp_config)
        srv.quit.assert_called_once()

    def test_smtp_error_does_not_raise(self, smtp_config):
        """A broken SMTP server should not crash cert-canary."""
        with patch("smtplib.SMTP", side_effect=smtplib.SMTPException("auth failed")):
            # Should not raise
            alert_email([_make_cert(grade="CRITICAL", days_left=3)], smtp_config)

    def test_ssl_mode_uses_smtp_ssl(self, smtp_config):
        ssl_config = {
            **smtp_config,
            "smtp": {**smtp_config["smtp"], "ssl": True, "port": 465},
        }
        with patch("smtplib.SMTP_SSL") as mock_ssl_cls:
            mock_server = MagicMock()
            mock_ssl_cls.return_value = mock_server
            alert_email([_make_cert(grade="CRITICAL", days_left=3)], ssl_config)
            mock_ssl_cls.assert_called_once_with("smtp.example.com", 465, timeout=15)


# ─────────────────────────────────────────────
# alerts/webhook.py tests
# ─────────────────────────────────────────────

class TestAlertWebhook:

    def _run(self, results, config):
        with patch("cert_canary.alerts.webhook._http_post") as mock_post:
            mock_post.return_value = (200, "ok")
            alert_webhook(results, config)
            return mock_post

    def test_no_call_when_no_url(self, base_config):
        mock = self._run([_make_cert(grade="CRITICAL", days_left=3)], base_config)
        mock.assert_not_called()

    def test_no_call_when_no_alertable_results(self, webhook_config):
        mock = self._run([_make_cert(grade="OK", days_left=90)], webhook_config)
        mock.assert_not_called()

    def test_posts_to_webhook_url(self, webhook_config):
        mock = self._run([_make_cert(grade="CRITICAL", days_left=3)], webhook_config)
        mock.assert_called_once()
        assert mock.call_args[0][0] == webhook_config["webhook_url"]

    def test_payload_has_source_field(self, webhook_config):
        mock    = self._run([_make_cert(grade="CRITICAL", days_left=3)], webhook_config)
        payload = mock.call_args[0][1]
        assert payload["source"] == "cert-canary"

    def test_payload_has_timestamp(self, webhook_config):
        mock    = self._run([_make_cert(grade="CRITICAL", days_left=3)], webhook_config)
        payload = mock.call_args[0][1]
        assert "timestamp" in payload
        assert payload["timestamp"].endswith("Z")

    def test_payload_has_summary(self, webhook_config):
        mock    = self._run([_make_cert(grade="CRITICAL", days_left=3)], webhook_config)
        payload = mock.call_args[0][1]
        assert "summary" in payload
        for key in ("total", "ok", "warning", "critical", "errors"):
            assert key in payload["summary"]

    def test_payload_summary_counts_correct(self, webhook_config):
        results = [
            _make_cert(host="a.com", grade="OK",       days_left=90),
            _make_cert(host="b.com", grade="WARNING",  days_left=15),
            _make_cert(host="c.com", grade="CRITICAL", days_left=3),
        ]
        mock    = self._run(results, webhook_config)
        summary = mock.call_args[0][1]["summary"]
        assert summary["total"]    == 3
        assert summary["ok"]       == 1
        assert summary["warning"]  == 1
        assert summary["critical"] == 1

    def test_payload_alerts_only_contains_alertable(self, webhook_config):
        results = [
            _make_cert(host="ok.com",   grade="OK",       days_left=90),
            _make_cert(host="crit.com", grade="CRITICAL", days_left=3),
        ]
        mock   = self._run(results, webhook_config)
        alerts = mock.call_args[0][1]["alerts"]
        hosts  = [a["host"] for a in alerts]
        assert "ok.com"   not in hosts
        assert "crit.com" in     hosts

    def test_alert_entry_has_required_fields(self, webhook_config):
        mock  = self._run([_make_cert(grade="CRITICAL", days_left=3)], webhook_config)
        entry = mock.call_args[0][1]["alerts"][0]
        for field in ("host", "port", "grade", "days_left", "not_after",
                      "tls_version", "cipher", "self_signed", "error", "scan_time"):
            assert field in entry, f"Missing field: {field}"

    def test_hmac_signature_header_when_secret_set(self, webhook_signed_config):
        with patch("cert_canary.alerts.webhook._http_post") as mock_post:
            mock_post.return_value = (200, "ok")
            alert_webhook([_make_cert(grade="CRITICAL", days_left=3)], webhook_signed_config)
            headers = mock_post.call_args[0][2]
            assert "X-Canary-Signature" in headers

    def test_hmac_signature_is_valid_sha256(self, webhook_signed_config):
        with patch("cert_canary.alerts.webhook._http_post") as mock_post:
            mock_post.return_value = (200, "ok")
            alert_webhook([_make_cert(grade="CRITICAL", days_left=3)], webhook_signed_config)

            payload = mock_post.call_args[0][1]
            headers = mock_post.call_args[0][2]

            body      = json.dumps(payload).encode()
            secret    = webhook_signed_config["webhook_secret"].encode()
            expected  = "sha256=" + hmac.new(secret, body, hashlib.sha256).hexdigest()
            actual    = headers["X-Canary-Signature"]
            assert actual == expected

    def test_no_signature_header_without_secret(self, webhook_config):
        with patch("cert_canary.alerts.webhook._http_post") as mock_post:
            mock_post.return_value = (200, "ok")
            alert_webhook([_make_cert(grade="CRITICAL", days_left=3)], webhook_config)
            # headers arg may be None or empty dict
            headers = mock_post.call_args[0][2] if len(mock_post.call_args[0]) > 2 else {}
            assert "X-Canary-Signature" not in (headers or {})


# ─────────────────────────────────────────────
# alerts/__init__.py — dispatch_alerts() tests
# ─────────────────────────────────────────────

class TestDispatchAlerts:

    def test_calls_all_channels(self, full_config):
        """dispatch_alerts() should call every configured alert channel."""
        channels = [
            "cert_canary.alerts.alert_slack",
            "cert_canary.alerts.alert_discord",
            "cert_canary.alerts.alert_pagerduty",
            "cert_canary.alerts.alert_email",
            "cert_canary.alerts.alert_webhook",
        ]
        results = [_make_cert(grade="CRITICAL", days_left=3)]

        with patch("cert_canary.alerts.slack.alert_slack")         as ms, \
             patch("cert_canary.alerts.discord.alert_discord")     as md, \
             patch("cert_canary.alerts.pagerduty.alert_pagerduty") as mp, \
             patch("cert_canary.alerts.email.alert_email")         as me, \
             patch("cert_canary.alerts.webhook.alert_webhook")     as mw:

            dispatch_alerts(results, full_config)

            ms.assert_called_once_with(results, full_config)
            md.assert_called_once_with(results, full_config)
            mp.assert_called_once_with(results, full_config)
            me.assert_called_once_with(results, full_config)
            mw.assert_called_once_with(results, full_config)

    def test_channel_exception_does_not_stop_others(self, full_config):
        """
        If one alert channel crashes, the others should still fire.
        A broken Slack webhook must not prevent PagerDuty from alerting.
        """
        results = [_make_cert(grade="CRITICAL", days_left=3)]

        with patch("cert_canary.alerts.slack.alert_slack",
                   side_effect=Exception("Slack is down")), \
             patch("cert_canary.alerts.discord.alert_discord")     as md, \
             patch("cert_canary.alerts.pagerduty.alert_pagerduty") as mp, \
             patch("cert_canary.alerts.email.alert_email")         as me, \
             patch("cert_canary.alerts.webhook.alert_webhook")     as mw:

            # Should not raise even though Slack crashed
            dispatch_alerts(results, full_config)

            # Other channels still called
            md.assert_called_once()
            mp.assert_called_once()
            me.assert_called_once()
            mw.assert_called_once()

    def test_passes_results_unchanged(self, full_config):
        """dispatch_alerts must not mutate the results list."""
        results  = [_make_cert(grade="CRITICAL", days_left=3)]
        original = [asdict(r) for r in results]

        with patch("cert_canary.alerts.slack.alert_slack"), \
             patch("cert_canary.alerts.discord.alert_discord"), \
             patch("cert_canary.alerts.pagerduty.alert_pagerduty"), \
             patch("cert_canary.alerts.email.alert_email"), \
             patch("cert_canary.alerts.webhook.alert_webhook"):

            dispatch_alerts(results, full_config)

        assert [asdict(r) for r in results] == original

    def test_empty_results_does_not_raise(self, full_config):
        with patch("cert_canary.alerts.slack.alert_slack"), \
             patch("cert_canary.alerts.discord.alert_discord"), \
             patch("cert_canary.alerts.pagerduty.alert_pagerduty"), \
             patch("cert_canary.alerts.email.alert_email"), \
             patch("cert_canary.alerts.webhook.alert_webhook"):

            # Should not raise
            dispatch_alerts([], full_config)

    def test_all_ok_results_no_channels_post(self, full_config):
        """With all-OK results, no channel should make any network call."""
        results = [
            _make_cert(host="a.com", grade="OK", days_left=90),
            _make_cert(host="b.com", grade="OK", days_left=120),
        ]

        with patch("cert_canary.alerts.base._http_post") as mock_post, \
             patch("smtplib.SMTP") as mock_smtp:

            dispatch_alerts(results, full_config)

            mock_post.assert_not_called()
            mock_smtp.assert_not_called()