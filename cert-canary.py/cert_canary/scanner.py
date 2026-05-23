#!/usr/bin/env python3
"""
cert_canary/scanner.py
━━━━━━━━━━━━━━━━━━━━━
Core scanning logic. Connects to hosts via TLS, pulls certificate
details, grades them against configured thresholds, and returns
structured CertInfo dataclasses.

No alert logic, no output, no config parsing lives here.
This module is pure: given a host and config, return a CertInfo.
Every function is independently testable with mocked sockets.

Public API:
  scan_cert(host, port, timeout, thresholds) → CertInfo
  sweep(hosts, config)                       → list[CertInfo]
"""

import socket
import ssl
import hashlib
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Optional


# ─────────────────────────────────────────────
# CertInfo dataclass
# ─────────────────────────────────────────────

@dataclass
class CertInfo:
    """
    Everything cert-canary knows about one scanned host.
    Produced by scan_cert(), consumed by output.py and alerts/.

    Fields are intentionally flat — no nested objects —
    so asdict() produces clean JSON with no post-processing.
    """

    # Identity
    host:        str
    port:        int

    # Certificate subject
    common_name: str
    sans:        list[str]
    wildcard:    bool
    serial:      str

    # Validity window
    not_before:  str           # ISO-8601 string, UTC
    not_after:   str           # ISO-8601 string, UTC
    days_left:   int           # negative means expired

    # Issuer
    issuer:      str           # issuer CN
    issuer_org:  str           # issuer O
    self_signed: bool

    # Connection
    tls_version: str           # e.g. "TLSv1.3"
    cipher:      str           # e.g. "TLS_AES_256_GCM_SHA384"
    cipher_bits: int           # key size in bits

    # Fingerprint (SHA-256 of DER, first 16 hex chars)
    fingerprint: str

    # Grading
    grade:       str           # OK / INFO / WARNING / CRITICAL

    # Error — set if connection or parsing failed, None otherwise
    error:       Optional[str] = None

    # Scan metadata
    scan_time:   str = field(
        default_factory=lambda: datetime.utcnow().isoformat() + "Z"
    )

    # ── Computed properties ───────────────────────────────────

    @property
    def expired(self) -> bool:
        return self.days_left < 0

    @property
    def emoji(self) -> str:
        if self.error:               return "⚫"
        if self.expired:             return "💀"
        if self.grade == "CRITICAL": return "🔴"
        if self.grade == "WARNING":  return "🟡"
        if self.grade == "INFO":     return "🔵"
        return "🟢"

    @property
    def color_hex(self) -> str:
        """Hex colour for use in Slack/Discord embeds."""
        if self.error or self.expired: return "#ff4444"
        return {
            "CRITICAL": "#ff4444",
            "WARNING":  "#ffb800",
            "INFO":     "#00d4ff",
            "OK":       "#00ff88",
        }.get(self.grade, "#888888")


# ─────────────────────────────────────────────
# Single-host scanner
# ─────────────────────────────────────────────

def scan_cert(
    host:       str,
    port:       int,
    timeout:    int,
    thresholds: dict[str, int],
) -> CertInfo:
    """
    Open a TLS connection to host:port and return a CertInfo.

    Never raises — all exceptions are caught and returned as a
    CertInfo with error set and grade=CRITICAL so the caller
    can treat all results uniformly without try/except.

    Args:
        host:       Hostname or IP address to connect to.
        port:       TCP port (typically 443).
        timeout:    Socket connect/read timeout in seconds.
        thresholds: Dict with 'critical', 'warning', 'info' day counts.

    Returns:
        CertInfo — always, even on connection failure.
    """
    try:
        return _do_scan(host, port, timeout, thresholds)
    except ssl.SSLCertVerificationError as e:
        return _error(host, port, f"Certificate verification failed: {e.reason}")
    except ssl.SSLError as e:
        return _error(host, port, f"SSL error: {e.reason or str(e)}")
    except ConnectionRefusedError:
        return _error(host, port, "Connection refused")
    except ConnectionResetError:
        return _error(host, port, "Connection reset by peer")
    except socket.timeout:
        return _error(host, port, f"Timed out after {timeout}s")
    except socket.gaierror as e:
        return _error(host, port, f"DNS resolution failed: {e.args[1]}")
    except OSError as e:
        return _error(host, port, f"Network error: {e.strerror}")
    except Exception as e:
        return _error(host, port, f"Unexpected error: {type(e).__name__}: {e}")


def _do_scan(
    host:       str,
    port:       int,
    timeout:    int,
    thresholds: dict[str, int],
) -> CertInfo:
    """
    Inner scan — all the real work.
    Called by scan_cert() which wraps it in exception handling.
    """
    ctx = _build_ssl_context()

    with socket.create_connection((host, port), timeout=timeout) as raw_sock:
        with ctx.wrap_socket(raw_sock, server_hostname=host) as tls_sock:

            # Pull everything we need while the socket is open
            cert_dict = tls_sock.getpeercert()
            cert_der  = tls_sock.getpeercert(binary_form=True)
            tls_ver   = tls_sock.version() or "unknown"
            cipher    = tls_sock.cipher()  # (name, protocol, bits)

    # ── Parse subject ─────────────────────────────────────────
    subject_map = _flatten_rdns(cert_dict.get("subject", []))
    issuer_map  = _flatten_rdns(cert_dict.get("issuer",  []))

    common_name = subject_map.get("commonName", host)
    issuer_cn   = issuer_map.get("commonName",       "Unknown")
    issuer_org  = issuer_map.get("organizationName", "Unknown")
    serial      = str(cert_dict.get("serialNumber", ""))

    # ── Parse SANs ────────────────────────────────────────────
    sans = [
        value for rtype, value
        in cert_dict.get("subjectAltName", [])
        if rtype == "DNS"
    ]

    # ── Wildcard detection ────────────────────────────────────
    wildcard = (
        common_name.startswith("*.")
        or any(s.startswith("*.") for s in sans)
    )

    # ── Self-signed detection ─────────────────────────────────
    # A cert is self-signed when subject == issuer.
    # We compare the raw RDN tuples rather than the flattened
    # dicts to avoid false positives on certs with partial matches.
    self_signed = cert_dict.get("subject") == cert_dict.get("issuer")

    # ── Parse validity dates ──────────────────────────────────
    fmt = "%b %d %H:%M:%S %Y %Z"
    not_before_dt = datetime.strptime(
        cert_dict["notBefore"], fmt
    ).replace(tzinfo=timezone.utc)
    not_after_dt  = datetime.strptime(
        cert_dict["notAfter"], fmt
    ).replace(tzinfo=timezone.utc)

    now       = datetime.now(timezone.utc)
    days_left = (not_after_dt - now).days

    # ── Fingerprint ───────────────────────────────────────────
    fingerprint = hashlib.sha256(cert_der).hexdigest()[:16]

    # ── Cipher details ────────────────────────────────────────
    cipher_name = cipher[0] if cipher else "unknown"
    cipher_bits = cipher[2] if cipher and len(cipher) > 2 else 0

    # ── Grade ─────────────────────────────────────────────────
    grade = _grade(days_left, thresholds)

    return CertInfo(
        host        = host,
        port        = port,
        common_name = common_name,
        sans        = sans[:20],      # cap at 20 — certs with 100+ SANs exist
        wildcard    = wildcard,
        serial      = serial,
        not_before  = not_before_dt.strftime("%Y-%m-%d %H:%M UTC"),
        not_after   = not_after_dt.strftime( "%Y-%m-%d %H:%M UTC"),
        days_left   = days_left,
        issuer      = issuer_cn,
        issuer_org  = issuer_org,
        self_signed = self_signed,
        tls_version = tls_ver,
        cipher      = cipher_name,
        cipher_bits = cipher_bits,
        fingerprint = fingerprint,
        grade       = grade,
        error       = None,
    )


# ─────────────────────────────────────────────
# Multi-host parallel sweep
# ─────────────────────────────────────────────

def sweep(
    hosts:  list[tuple[str, int]],
    config: dict,
) -> list[CertInfo]:
    """
    Scan all hosts in parallel and return results sorted by severity.

    Uses ThreadPoolExecutor — appropriate here because scanning is
    I/O-bound (waiting on network). For CPU-bound work, use
    ProcessPoolExecutor instead.

    Sort order: errors first, then by days_left ascending so the
    most urgent certs appear at the top of the console output.

    Args:
        hosts:  List of (hostname, port) tuples.
        config: Full config dict from config.build_config().

    Returns:
        List of CertInfo, sorted by urgency.
    """
    timeout    = config.get("timeout",    8)
    thresholds = config.get("thresholds", {})
    n_threads  = min(
        config.get("threads", 10),
        len(hosts),          # no point spinning up more threads than hosts
    )

    results: list[CertInfo] = []

    with ThreadPoolExecutor(max_workers=n_threads) as executor:
        # Submit all scans
        future_to_host = {
            executor.submit(scan_cert, host, port, timeout, thresholds): (host, port)
            for host, port in hosts
        }

        # Collect results as they complete (not in submission order)
        for future in as_completed(future_to_host):
            try:
                result = future.result()
            except Exception as e:
                # Future itself raised — shouldn't happen since scan_cert
                # catches all exceptions, but be defensive
                host, port = future_to_host[future]
                result = _error(host, port, f"Future raised: {e}")
            results.append(result)

    # Sort: errors to top, then critical → warning → info → ok,
    # then by days_left ascending within each grade
    results.sort(key=_sort_key)
    return results


def _sort_key(r: CertInfo) -> tuple:
    """
    Sort key for sweep results.
    Returns a tuple that sorts most-urgent first:
      (has_no_error, grade_order, days_left)

    has_no_error=0 sorts errors to the top (False < True).
    grade_order maps grades to ints so CRITICAL < WARNING < INFO < OK.
    days_left ascending within each grade.
    """
    grade_order = {"CRITICAL": 0, "WARNING": 1, "INFO": 2, "OK": 3}
    return (
        0 if r.error else 1,                          # errors first
        grade_order.get(r.grade, 4),                  # then by grade
        r.days_left if not r.error else -99999,        # then soonest expiry
    )


# ─────────────────────────────────────────────
# Grading
# ─────────────────────────────────────────────

def _grade(days_left: int, thresholds: dict[str, int]) -> str:
    """
    Assign a grade based on days remaining and configured thresholds.

    Args:
        days_left:   Days until cert expiry. Negative = already expired.
        thresholds:  Dict with 'critical', 'warning', 'info' keys.

    Returns:
        One of: "CRITICAL", "WARNING", "INFO", "OK"
    """
    critical = thresholds.get("critical", 7)
    warning  = thresholds.get("warning",  30)
    info     = thresholds.get("info",     60)

    if days_left < 0:        return "CRITICAL"   # expired
    if days_left < critical: return "CRITICAL"
    if days_left < warning:  return "WARNING"
    if days_left < info:     return "INFO"
    return "OK"


# ─────────────────────────────────────────────
# SSL context
# ─────────────────────────────────────────────

def _build_ssl_context() -> ssl.SSLContext:
    """
    Build an SSL context for scanning.

    We use CERT_OPTIONAL rather than CERT_REQUIRED so we can
    connect to and report on hosts with expired or self-signed
    certs rather than raising before we get any data.

    check_hostname must be False when verify_mode is not CERT_REQUIRED.
    """
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode    = ssl.CERT_OPTIONAL
    return ctx


# ─────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────

def _flatten_rdns(rdns: list) -> dict[str, str]:
    """
    Flatten the nested RDN structure that getpeercert() returns
    into a simple {attributeType: value} dict.

    getpeercert() returns:
      ((('commonName', 'example.com'),), (('organizationName', 'Acme'),))

    We flatten to:
      {'commonName': 'example.com', 'organizationName': 'Acme'}

    If an attribute type appears more than once, last value wins.
    """
    result: dict[str, str] = {}
    for rdn in rdns:
        for attr_type, value in rdn:
            result[attr_type] = value
    return result


def _error(host: str, port: int, message: str) -> CertInfo:
    """
    Construct a CertInfo representing a failed scan.
    All fields are set to safe empty/zero values.
    grade is CRITICAL so failed hosts always surface in alerts.
    """
    return CertInfo(
        host        = host,
        port        = port,
        common_name = host,
        sans        = [],
        wildcard    = False,
        serial      = "",
        not_before  = "",
        not_after   = "",
        days_left   = -9999,
        issuer      = "",
        issuer_org  = "",
        self_signed = False,
        tls_version = "",
        cipher      = "",
        cipher_bits = 0,
        fingerprint = "",
        grade       = "CRITICAL",
        error       = message,
    )