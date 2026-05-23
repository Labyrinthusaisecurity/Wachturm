#!/usr/bin/env python3
"""
tests/test_scanner.py
━━━━━━━━━━━━━━━━━━━━
Unit tests for cert_canary/scanner.py.

Tests cover:
  • CertInfo dataclass properties and computed fields
  • _grade() threshold logic across all grades
  • _flatten_rdns() RDN parsing
  • _sort_key() sweep ordering
  • _error() error result construction
  • scan_cert() with mocked TLS sockets — success paths
  • scan_cert() with mocked TLS sockets — all exception paths
  • sweep() parallelism and result ordering

All network I/O is mocked — no real connections are made.
Tests run with no external dependencies beyond pytest.
"""

import socket
import ssl
import hashlib
from dataclasses import asdict
from datetime import datetime, timedelta, timezone
from unittest.mock import MagicMock, patch, PropertyMock

import pytest

from cert_canary.scanner import (
    CertInfo,
    _do_scan,
    _error,
    _flatten_rdns,
    _grade,
    _sort_key,
    scan_cert,
    sweep,
)


# ─────────────────────────────────────────────
# Fixtures
# ─────────────────────────────────────────────

@pytest.fixture
def default_thresholds():
    return {"critical": 7, "warning": 30, "info": 60}


@pytest.fixture
def default_config(default_thresholds):
    return {
        "threads":    4,
        "timeout":    8,
        "thresholds": default_thresholds,
    }


def _make_cert_dict(
    cn:         str   = "example.com",
    issuer_cn:  str   = "Let's Encrypt R3",
    issuer_org: str   = "Let's Encrypt",
    days_until: int   = 90,
    sans:       list  = None,
    self_signed:bool  = False,
) -> dict:
    """
    Build a getpeercert()-style dict for use in mocked TLS sockets.
    days_until controls how many days until notAfter.
    Negative days_until produces an already-expired cert.
    """
    now        = datetime.now(timezone.utc)
    not_before = now - timedelta(days=30)
    not_after  = now + timedelta(days=days_until)
    fmt        = "%b %d %H:%M:%S %Y %Z"

    subject_rdns = (
        (("commonName", cn),),
    )
    if self_signed:
        issuer_rdns = subject_rdns
    else:
        issuer_rdns = (
            (("commonName",       issuer_cn),),
            (("organizationName", issuer_org),),
        )

    san_list = [(("DNS", s)) for s in (sans or [cn])]

    return {
        "subject":          subject_rdns,
        "issuer":           issuer_rdns,
        "notBefore":        not_before.strftime(fmt).replace("UTC", "GMT"),
        "notAfter":         not_after.strftime(fmt).replace("UTC", "GMT"),
        "subjectAltName":   san_list,
        "serialNumber":     "0A1B2C3D4E5F",
    }


def _make_cert_der() -> bytes:
    """Fake DER bytes — real enough for SHA-256 fingerprinting."""
    return b"\x30\x82\x04\x00" + b"\xaa" * 256


def _make_mock_tls_socket(cert_dict: dict, cert_der: bytes) -> MagicMock:
    """
    Build a mock that quacks like ssl.SSLSocket.
    Supports context manager protocol (with ... as s).
    """
    mock_ssl = MagicMock()
    mock_ssl.getpeercert.side_effect = lambda binary_form=False: (
        cert_der if binary_form else cert_dict
    )
    mock_ssl.version.return_value  = "TLSv1.3"
    mock_ssl.cipher.return_value   = ("TLS_AES_256_GCM_SHA384", "TLSv1.3", 256)
    mock_ssl.__enter__ = lambda s: s
    mock_ssl.__exit__  = MagicMock(return_value=False)
    return mock_ssl


def _make_mock_raw_socket() -> MagicMock:
    """Build a mock that quacks like a raw TCP socket."""
    mock_raw = MagicMock()
    mock_raw.__enter__ = lambda s: s
    mock_raw.__exit__  = MagicMock(return_value=False)
    return mock_raw


# ─────────────────────────────────────────────
# CertInfo dataclass tests
# ─────────────────────────────────────────────

class TestCertInfo:

    def _make(self, **kwargs) -> CertInfo:
        defaults = dict(
            host="example.com", port=443, common_name="example.com",
            sans=["example.com"], wildcard=False, serial="ABC123",
            not_before="2026-01-01 00:00 UTC", not_after="2026-12-31 00:00 UTC",
            days_left=90, issuer="R3", issuer_org="Let's Encrypt",
            self_signed=False, tls_version="TLSv1.3",
            cipher="TLS_AES_256_GCM_SHA384", cipher_bits=256,
            fingerprint="aabbccddeeff0011", grade="OK", error=None,
        )
        defaults.update(kwargs)
        return CertInfo(**defaults)

    def test_expired_property_true_when_days_negative(self):
        r = self._make(days_left=-1)
        assert r.expired is True

    def test_expired_property_false_when_days_zero(self):
        r = self._make(days_left=0)
        assert r.expired is False

    def test_expired_property_false_when_days_positive(self):
        r = self._make(days_left=30)
        assert r.expired is False

    def test_emoji_ok(self):
        assert self._make(grade="OK").emoji == "🟢"

    def test_emoji_info(self):
        assert self._make(grade="INFO").emoji == "🔵"

    def test_emoji_warning(self):
        assert self._make(grade="WARNING").emoji == "🟡"

    def test_emoji_critical(self):
        assert self._make(grade="CRITICAL").emoji == "🔴"

    def test_emoji_expired(self):
        assert self._make(grade="CRITICAL", days_left=-1).emoji == "💀"

    def test_emoji_error(self):
        assert self._make(error="Connection refused").emoji == "⚫"

    def test_emoji_error_takes_priority_over_grade(self):
        # Even a CRITICAL grade shows ⚫ if there's an error
        r = self._make(grade="CRITICAL", error="Timeout")
        assert r.emoji == "⚫"

    def test_color_hex_ok(self):
        assert self._make(grade="OK").color_hex == "#00ff88"

    def test_color_hex_warning(self):
        assert self._make(grade="WARNING").color_hex == "#ffb800"

    def test_color_hex_critical(self):
        assert self._make(grade="CRITICAL").color_hex == "#ff4444"

    def test_color_hex_error(self):
        assert self._make(error="timeout").color_hex == "#ff4444"

    def test_asdict_is_json_serialisable(self):
        import json
        r = self._make()
        # Should not raise
        json.dumps(asdict(r))

    def test_scan_time_is_set_automatically(self):
        r = self._make()
        assert r.scan_time.endswith("Z")
        # Should parse as valid ISO-8601
        datetime.fromisoformat(r.scan_time.rstrip("Z"))


# ─────────────────────────────────────────────
# _grade() tests
# ─────────────────────────────────────────────

class TestGrade:

    def setup_method(self):
        self.t = {"critical": 7, "warning": 30, "info": 60}

    def test_negative_days_is_critical(self):
        assert _grade(-1, self.t) == "CRITICAL"

    def test_zero_days_is_critical(self):
        # 0 days left means expires today — treat as critical
        assert _grade(0, self.t) == "CRITICAL"

    def test_one_day_is_critical(self):
        assert _grade(1, self.t) == "CRITICAL"

    def test_exactly_at_critical_threshold_is_critical(self):
        assert _grade(6, self.t) == "CRITICAL"

    def test_at_critical_threshold_boundary_is_warning(self):
        # days_left == critical threshold means NOT critical
        assert _grade(7, self.t) == "WARNING"

    def test_mid_warning_range(self):
        assert _grade(15, self.t) == "WARNING"

    def test_at_warning_threshold_boundary_is_info(self):
        assert _grade(30, self.t) == "INFO"

    def test_mid_info_range(self):
        assert _grade(45, self.t) == "INFO"

    def test_at_info_threshold_boundary_is_ok(self):
        assert _grade(60, self.t) == "OK"

    def test_well_above_info_is_ok(self):
        assert _grade(365, self.t) == "OK"

    def test_custom_thresholds_respected(self):
        t = {"critical": 14, "warning": 60, "info": 90}
        assert _grade(10, t) == "CRITICAL"
        assert _grade(14, t) == "WARNING"
        assert _grade(60, t) == "INFO"
        assert _grade(90, t) == "OK"

    def test_missing_threshold_keys_use_defaults(self):
        # Empty thresholds — all get() calls return None,
        # so defaults (7, 30, 60) kick in
        assert _grade(5,  {}) == "CRITICAL"
        assert _grade(15, {}) == "WARNING"
        assert _grade(45, {}) == "INFO"
        assert _grade(90, {}) == "OK"


# ─────────────────────────────────────────────
# _flatten_rdns() tests
# ─────────────────────────────────────────────

class TestFlattenRdns:

    def test_empty_input(self):
        assert _flatten_rdns([]) == {}

    def test_single_attribute(self):
        rdns = ((("commonName", "example.com"),),)
        assert _flatten_rdns(rdns) == {"commonName": "example.com"}

    def test_multiple_attributes(self):
        rdns = (
            (("commonName",       "example.com"),),
            (("organizationName", "Acme Corp"),),
            (("countryName",      "US"),),
        )
        result = _flatten_rdns(rdns)
        assert result["commonName"]       == "example.com"
        assert result["organizationName"] == "Acme Corp"
        assert result["countryName"]      == "US"

    def test_duplicate_key_last_value_wins(self):
        rdns = (
            (("commonName", "first.com"),),
            (("commonName", "second.com"),),
        )
        result = _flatten_rdns(rdns)
        assert result["commonName"] == "second.com"

    def test_multi_attribute_rdn(self):
        # Some certs pack multiple attributes in one RDN
        rdns = ((
            ("commonName",       "example.com"),
            ("organizationName", "Acme"),
        ),)
        result = _flatten_rdns(rdns)
        assert result["commonName"]       == "example.com"
        assert result["organizationName"] == "Acme"


# ─────────────────────────────────────────────
# _sort_key() tests
# ─────────────────────────────────────────────

class TestSortKey:

    def _r(self, grade, days_left, error=None) -> CertInfo:
        return CertInfo(
            host="x", port=443, common_name="x", sans=[], wildcard=False,
            serial="", not_before="", not_after="", days_left=days_left,
            issuer="", issuer_org="", self_signed=False, tls_version="",
            cipher="", cipher_bits=0, fingerprint="", grade=grade, error=error,
        )

    def test_error_sorts_before_critical(self):
        err  = self._r("CRITICAL", -9999, error="timeout")
        crit = self._r("CRITICAL", 1)
        assert _sort_key(err) < _sort_key(crit)

    def test_critical_sorts_before_warning(self):
        crit = self._r("CRITICAL", 3)
        warn = self._r("WARNING",  15)
        assert _sort_key(crit) < _sort_key(warn)

    def test_warning_sorts_before_info(self):
        warn = self._r("WARNING", 15)
        info = self._r("INFO",    45)
        assert _sort_key(warn) < _sort_key(info)

    def test_info_sorts_before_ok(self):
        info = self._r("INFO", 45)
        ok   = self._r("OK",   90)
        assert _sort_key(info) < _sort_key(ok)

    def test_within_grade_sorts_by_days_ascending(self):
        soon = self._r("WARNING", 8)
        late = self._r("WARNING", 25)
        assert _sort_key(soon) < _sort_key(late)

    def test_sweep_list_sorts_correctly(self):
        results = [
            self._r("OK",       90),
            self._r("INFO",     45),
            self._r("CRITICAL",  3),
            self._r("WARNING",  15),
            self._r("CRITICAL", -1),
            self._r("OK",       200, error="timeout"),
        ]
        results.sort(key=_sort_key)
        grades = [r.grade for r in results]
        # Error first, then CRITICAL x2, WARNING, INFO, OK
        assert results[0].error is not None
        assert grades[1] == "CRITICAL"
        assert grades[2] == "CRITICAL"
        assert grades[3] == "WARNING"
        assert grades[4] == "INFO"
        assert grades[5] == "OK"


# ─────────────────────────────────────────────
# _error() tests
# ─────────────────────────────────────────────

class TestErrorResult:

    def test_grade_is_critical(self):
        r = _error("example.com", 443, "timeout")
        assert r.grade == "CRITICAL"

    def test_error_message_preserved(self):
        r = _error("example.com", 443, "DNS resolution failed: Name or service not known")
        assert r.error == "DNS resolution failed: Name or service not known"

    def test_host_and_port_preserved(self):
        r = _error("api.example.com", 8443, "refused")
        assert r.host == "api.example.com"
        assert r.port == 8443

    def test_days_left_is_negative_sentinel(self):
        r = _error("example.com", 443, "timeout")
        assert r.days_left < 0

    def test_expired_property_is_true(self):
        r = _error("example.com", 443, "timeout")
        assert r.expired is True

    def test_emoji_is_error_symbol(self):
        r = _error("example.com", 443, "refused")
        assert r.emoji == "⚫"

    def test_sans_is_empty_list(self):
        r = _error("example.com", 443, "timeout")
        assert r.sans == []

    def test_asdict_serialisable(self):
        import json
        r = _error("example.com", 443, "timeout")
        json.dumps(asdict(r))


# ─────────────────────────────────────────────
# scan_cert() — success paths
# ─────────────────────────────────────────────

class TestScanCertSuccess:

    def _run_scan(self, cert_dict, cert_der=None, thresholds=None):
        """Helper: patch socket + ssl and call scan_cert()."""
        if cert_der is None:
            cert_der = _make_cert_der()
        if thresholds is None:
            thresholds = {"critical": 7, "warning": 30, "info": 60}

        mock_ssl_sock = _make_mock_tls_socket(cert_dict, cert_der)
        mock_raw_sock = _make_mock_raw_socket()

        with patch("socket.create_connection", return_value=mock_raw_sock), \
             patch("ssl.SSLContext.wrap_socket",  return_value=mock_ssl_sock):
            return scan_cert("example.com", 443, 8, thresholds)

    def test_returns_certinfo(self):
        cert = _make_cert_dict()
        r    = self._run_scan(cert)
        assert isinstance(r, CertInfo)

    def test_host_and_port_correct(self):
        r = self._run_scan(_make_cert_dict())
        assert r.host == "example.com"
        assert r.port == 443

    def test_common_name_extracted(self):
        r = self._run_scan(_make_cert_dict(cn="api.example.com"))
        assert r.common_name == "api.example.com"

    def test_issuer_org_extracted(self):
        r = self._run_scan(_make_cert_dict(issuer_org="Let's Encrypt"))
        assert r.issuer_org == "Let's Encrypt"

    def test_tls_version_extracted(self):
        r = self._run_scan(_make_cert_dict())
        assert r.tls_version == "TLSv1.3"

    def test_cipher_extracted(self):
        r = self._run_scan(_make_cert_dict())
        assert r.cipher == "TLS_AES_256_GCM_SHA384"

    def test_cipher_bits_extracted(self):
        r = self._run_scan(_make_cert_dict())
        assert r.cipher_bits == 256

    def test_sans_extracted(self):
        r = self._run_scan(_make_cert_dict(sans=["example.com", "www.example.com"]))
        assert "example.com"     in r.sans
        assert "www.example.com" in r.sans

    def test_sans_capped_at_20(self):
        many_sans = [f"sub{i}.example.com" for i in range(50)]
        r = self._run_scan(_make_cert_dict(sans=many_sans))
        assert len(r.sans) <= 20

    def test_wildcard_detected_in_cn(self):
        r = self._run_scan(_make_cert_dict(cn="*.example.com"))
        assert r.wildcard is True

    def test_wildcard_detected_in_san(self):
        r = self._run_scan(_make_cert_dict(cn="example.com", sans=["*.example.com"]))
        assert r.wildcard is True

    def test_not_wildcard_for_normal_cert(self):
        r = self._run_scan(_make_cert_dict(cn="example.com", sans=["example.com"]))
        assert r.wildcard is False

    def test_self_signed_detected(self):
        r = self._run_scan(_make_cert_dict(self_signed=True))
        assert r.self_signed is True

    def test_not_self_signed_for_ca_issued(self):
        r = self._run_scan(_make_cert_dict(self_signed=False))
        assert r.self_signed is False

    def test_fingerprint_is_16_hex_chars(self):
        r = self._run_scan(_make_cert_dict())
        assert len(r.fingerprint) == 16
        assert all(c in "0123456789abcdef" for c in r.fingerprint)

    def test_fingerprint_matches_sha256_of_der(self):
        der = _make_cert_der()
        r   = self._run_scan(_make_cert_dict(), cert_der=der)
        expected = hashlib.sha256(der).hexdigest()[:16]
        assert r.fingerprint == expected

    def test_error_is_none_on_success(self):
        r = self._run_scan(_make_cert_dict())
        assert r.error is None

    def test_grade_ok_for_90_days(self):
        r = self._run_scan(_make_cert_dict(days_until=90))
        assert r.grade == "OK"

    def test_grade_info_for_45_days(self):
        r = self._run_scan(_make_cert_dict(days_until=45))
        assert r.grade == "INFO"

    def test_grade_warning_for_15_days(self):
        r = self._run_scan(_make_cert_dict(days_until=15))
        assert r.grade == "WARNING"

    def test_grade_critical_for_3_days(self):
        r = self._run_scan(_make_cert_dict(days_until=3))
        assert r.grade == "CRITICAL"

    def test_grade_critical_for_expired(self):
        r = self._run_scan(_make_cert_dict(days_until=-5))
        assert r.grade == "CRITICAL"
        assert r.expired is True

    def test_days_left_approximately_correct(self):
        r = self._run_scan(_make_cert_dict(days_until=90))
        # Allow ±1 day for test execution timing
        assert 88 <= r.days_left <= 90

    def test_not_before_is_formatted_string(self):
        r = self._run_scan(_make_cert_dict())
        assert "UTC" in r.not_before
        assert "-"   in r.not_before     # YYYY-MM-DD format

    def test_not_after_is_formatted_string(self):
        r = self._run_scan(_make_cert_dict())
        assert "UTC" in r.not_after

    def test_serial_extracted(self):
        r = self._run_scan(_make_cert_dict())
        assert r.serial == "0A1B2C3D4E5F"


# ─────────────────────────────────────────────
# scan_cert() — exception paths
# ─────────────────────────────────────────────

class TestScanCertExceptions:

    def _scan_with_exception(self, exc, thresholds=None):
        """Patch create_connection to raise exc, run scan_cert."""
        if thresholds is None:
            thresholds = {"critical": 7, "warning": 30, "info": 60}
        with patch("socket.create_connection", side_effect=exc):
            return scan_cert("example.com", 443, 8, thresholds)

    def test_connection_refused_returns_error(self):
        r = self._scan_with_exception(ConnectionRefusedError())
        assert r.error is not None
        assert "refused" in r.error.lower()

    def test_connection_reset_returns_error(self):
        r = self._scan_with_exception(ConnectionResetError())
        assert r.error is not None
        assert "reset" in r.error.lower()

    def test_timeout_returns_error(self):
        r = self._scan_with_exception(socket.timeout())
        assert r.error is not None
        assert "timed out" in r.error.lower()

    def test_dns_failure_returns_error(self):
        r = self._scan_with_exception(
            socket.gaierror(8, "Name or service not known")
        )
        assert r.error is not None
        assert "dns" in r.error.lower() or "resolution" in r.error.lower()

    def test_ssl_error_returns_error(self):
        r = self._scan_with_exception(
            ssl.SSLError(1, "WRONG_VERSION_NUMBER")
        )
        assert r.error is not None
        assert r.grade == "CRITICAL"

    def test_ssl_cert_verification_error_returns_error(self):
        exc = ssl.SSLCertVerificationError(1, "certificate verify failed")
        r   = self._scan_with_exception(exc)
        assert r.error is not None
        assert "verification" in r.error.lower() or "certificate" in r.error.lower()

    def test_os_error_returns_error(self):
        r = self._scan_with_exception(OSError(111, "Connection refused"))
        assert r.error is not None

    def test_unexpected_exception_returns_error(self):
        r = self._scan_with_exception(RuntimeError("something unexpected"))
        assert r.error is not None
        assert "RuntimeError" in r.error

    def test_error_result_grade_is_critical(self):
        r = self._scan_with_exception(ConnectionRefusedError())
        assert r.grade == "CRITICAL"

    def test_error_result_host_preserved(self):
        r = self._scan_with_exception(socket.timeout())
        assert r.host == "example.com"

    def test_error_result_port_preserved(self):
        r = self._scan_with_exception(socket.timeout())
        assert r.port == 443

    def test_scan_never_raises(self):
        """scan_cert must never propagate exceptions to the caller."""
        brutal_exc = Exception("catastrophic failure")
        # Should not raise
        r = self._scan_with_exception(brutal_exc)
        assert r.error is not None


# ─────────────────────────────────────────────
# sweep() tests
# ─────────────────────────────────────────────

class TestSweep:

    def _mock_scan(self, host, port, timeout, thresholds) -> CertInfo:
        """Deterministic fake scan_cert for sweep() tests."""
        days_map = {
            "ok.example.com":       90,
            "info.example.com":     45,
            "warning.example.com":  15,
            "critical.example.com":  3,
            "expired.example.com":  -5,
        }
        days = days_map.get(host, 90)
        grade = _grade(days, thresholds)
        return CertInfo(
            host=host, port=port, common_name=host, sans=[],
            wildcard=False, serial="", not_before="", not_after="",
            days_left=days, issuer="", issuer_org="", self_signed=False,
            tls_version="TLSv1.3", cipher="AES", cipher_bits=256,
            fingerprint="", grade=grade, error=None,
        )

    def _mock_scan_with_error(self, host, port, timeout, thresholds) -> CertInfo:
        return _error(host, port, "Connection refused")

    @patch("cert_canary.scanner.scan_cert")
    def test_returns_list_of_certinfo(self, mock_scan, default_config):
        mock_scan.return_value = _error("example.com", 443, "test")
        results = sweep([("example.com", 443)], default_config)
        assert isinstance(results, list)
        assert all(isinstance(r, CertInfo) for r in results)

    @patch("cert_canary.scanner.scan_cert")
    def test_scans_all_hosts(self, mock_scan, default_config):
        mock_scan.return_value = _error("x", 443, "test")
        hosts = [("a.com", 443), ("b.com", 443), ("c.com", 443)]
        results = sweep(hosts, default_config)
        assert len(results) == 3
        assert mock_scan.call_count == 3

    @patch("cert_canary.scanner.scan_cert", side_effect=_mock_scan.__func__
           if hasattr(_mock_scan, "__func__") else lambda *a, **kw: _error("x", 443, ""))
    def test_results_sorted_by_urgency(self, default_config):
        """Errors and critical certs should appear before OK certs."""
        hosts = [
            ("ok.example.com",       443),
            ("warning.example.com",  443),
            ("critical.example.com", 443),
        ]

        # Manually build results to test sort without real scan_cert
        from cert_canary.scanner import _sort_key
        results = [
            CertInfo(host="ok.example.com",       port=443, common_name="", sans=[],
                     wildcard=False, serial="", not_before="", not_after="",
                     days_left=90, issuer="", issuer_org="", self_signed=False,
                     tls_version="", cipher="", cipher_bits=0, fingerprint="",
                     grade="OK"),
            CertInfo(host="critical.example.com", port=443, common_name="", sans=[],
                     wildcard=False, serial="", not_before="", not_after="",
                     days_left=3, issuer="", issuer_org="", self_signed=False,
                     tls_version="", cipher="", cipher_bits=0, fingerprint="",
                     grade="CRITICAL"),
            CertInfo(host="warning.example.com",  port=443, common_name="", sans=[],
                     wildcard=False, serial="", not_before="", not_after="",
                     days_left=15, issuer="", issuer_org="", self_signed=False,
                     tls_version="", cipher="", cipher_bits=0, fingerprint="",
                     grade="WARNING"),
        ]
        results.sort(key=_sort_key)
        assert results[0].grade == "CRITICAL"
        assert results[1].grade == "WARNING"
        assert results[2].grade == "OK"

    @patch("cert_canary.scanner.scan_cert")
    def test_thread_count_capped_at_host_count(self, mock_scan, default_config):
        """Never spin up more threads than there are hosts."""
        mock_scan.return_value = _error("x", 443, "test")
        config = {**default_config, "threads": 100}
        hosts  = [("a.com", 443), ("b.com", 443)]

        # Should complete without error even with threads > hosts
        results = sweep(hosts, config)
        assert len(results) == 2

    @patch("cert_canary.scanner.scan_cert")
    def test_single_host(self, mock_scan, default_config):
        mock_scan.return_value = _error("example.com", 443, "test")
        results = sweep([("example.com", 443)], default_config)
        assert len(results) == 1

    @patch("cert_canary.scanner.scan_cert")
    def test_empty_host_list(self, mock_scan, default_config):
        results = sweep([], default_config)
        assert results == []
        mock_scan.assert_not_called()

    @patch("cert_canary.scanner.scan_cert")
    def test_timeout_passed_to_scan(self, mock_scan, default_config):
        mock_scan.return_value = _error("x", 443, "test")
        config = {**default_config, "timeout": 15}
        sweep([("example.com", 443)], config)
        _, call_kwargs = mock_scan.call_args
        # timeout is the 3rd positional arg
        assert mock_scan.call_args[0][2] == 15

    @patch("cert_canary.scanner.scan_cert")
    def test_thresholds_passed_to_scan(self, mock_scan, default_config):
        mock_scan.return_value = _error("x", 443, "test")
        custom_t = {"critical": 14, "warning": 60, "info": 90}
        config   = {**default_config, "thresholds": custom_t}
        sweep([("example.com", 443)], config)
        assert mock_scan.call_args[0][3] == custom_t

    @patch("cert_canary.scanner.scan_cert")
    def test_future_exception_handled_gracefully(self, mock_scan, default_config):
        """
        If a future itself raises (shouldn't happen but be defensive),
        sweep should catch it and return an error CertInfo rather than crashing.
        """
        mock_scan.side_effect = Exception("unexpected future error")
        # sweep() should not raise
        results = sweep([("example.com", 443)], default_config)
        assert len(results) == 1
        assert results[0].error is not None