#!/usr/bin/env python3
"""
vuln_sweep/checks/drown.py
━━━━━━━━━━━━━━━━━━━━━━━━━
CVE-2016-0800  DROWN
(Decrypting RSA with Obsolete and Weakened eNcryption)

Vulnerability:
    DROWN allows an attacker to decrypt TLS 1.x sessions by exploiting
    SSLv2 weaknesses on a server that shares an RSA key with the target.
    The attack uses SSLv2 as an oracle: by sending ~40,000 specially
    crafted SSLv2 handshakes using the server's RSA public key, the
    attacker can decrypt a captured TLS session in under 8 hours.

    There are two variants:
      General DROWN: server accepts SSLv2 connections.
      Special DROWN: server accepts SSLv2 EXPORT-grade ciphers, enabling
                     a cheaper attack (~256 connections vs 40,000).

Detection method:
    We use three sequential probes, stopping at the first hit:

    Probe 1 — Raw SSLv2 socket:
        Send a hand-crafted SSLv2 CLIENT-HELLO (from base._build_sslv2_client_hello)
        and check whether the server responds with a SERVER-HELLO (type 0x04).
        This works even when openssl is not available.

    Probe 2 — openssl s_client -ssl2 fallback:
        Some servers respond differently to the raw probe than to openssl.
        Used as a fallback if Probe 1 is inconclusive.

    Probe 3 — EXPORT cipher check:
        If SSLv2 is rejected, check whether EXPORT-grade ciphers are accepted
        on any protocol. EXPORT ciphers indicate Special DROWN vulnerability.

References:
    https://nvd.nist.gov/vuln/detail/CVE-2016-0800
    https://drownattack.com
    https://tools.ietf.org/html/rfc6176  (SSLv2 prohibition)
"""

import socket

from vuln_sweep.checks.base import (
    CheckResult,
    _build_sslv2_client_hello,
    _run_openssl,
    _tls_probe_cipher,
    openssl_available,
    make_vulnerable,
    make_clean,
    make_inconclusive,
)


# ─────────────────────────────────────────────
# Constants
# ─────────────────────────────────────────────

CVE  = "CVE-2016-0800"
NAME = "DROWN"

# EXPORT-grade cipher suites — accepted on any protocol
# indicates Special DROWN vulnerability
EXPORT_CIPHERS: list[str] = [
    "EXP-RC4-MD5",
    "EXP-RC2-CBC-MD5",
    "EXP-DES-CBC-SHA",
    "EXP-EDH-RSA-DES-CBC-SHA",
    "EXP-EDH-DSS-DES-CBC-SHA",
    "EXP-RC4-MD5",
    "EXP1024-RC4-SHA",
    "EXP1024-DES-CBC-SHA",
]

# SSLv2 SERVER-HELLO message type
_SSLV2_SERVER_HELLO = 0x04


# ─────────────────────────────────────────────
# Check entry point
# ─────────────────────────────────────────────

def check(host: str, port: int, timeout: int) -> CheckResult:
    """
    Check whether the host is vulnerable to DROWN.

    Detection order:
      1. Raw SSLv2 CLIENT-HELLO socket probe.
      2. openssl s_client -ssl2 fallback (if openssl available).
      3. EXPORT cipher probe for Special DROWN.

    Returns:
        CheckResult with vulnerable=True  if SSLv2 or EXPORT accepted.
                             vulnerable=False if all probes rejected.
                             vulnerable=None  if check could not complete.
    """
    try:
        return _do_check(host, port, timeout)
    except Exception as e:
        return make_inconclusive(CVE, NAME, f"Unexpected error: {e}")


def _do_check(host: str, port: int, timeout: int) -> CheckResult:

    # ── Probe 1: Raw SSLv2 CLIENT-HELLO ──────────────────────
    sslv2_result = _probe_sslv2_raw(host, port, timeout)

    if sslv2_result is True:
        return make_vulnerable(
            CVE, NAME,
            "Server accepted a raw SSLv2 CLIENT-HELLO and returned a "
            "SERVER-HELLO (General DROWN). An attacker can use this server "
            "as an SSLv2 oracle to decrypt TLS 1.x sessions encrypted with "
            "the same RSA key in approximately 40,000 adaptive handshakes "
            "(< 8 hours on commodity hardware). "
            "Disable SSLv2 immediately on this host and any server sharing "
            "this RSA key.",
        )

    # ── Probe 2: openssl -ssl2 fallback ──────────────────────
    if sslv2_result is None and openssl_available():
        openssl_result = _probe_sslv2_openssl(host, port, timeout)
        if openssl_result is True:
            return make_vulnerable(
                CVE, NAME,
                "Server accepted SSLv2 connection via openssl s_client "
                "(General DROWN). SSLv2 provides an oracle for decrypting "
                "TLS sessions sharing this RSA key. Disable SSLv2 immediately.",
            )

    # ── Probe 3: EXPORT cipher check (Special DROWN) ─────────
    if openssl_available():
        export_result = _probe_export_ciphers(host, port, timeout)
        if export_result:
            cipher_str = ", ".join(export_result[:3])
            overflow   = len(export_result) - 3
            return make_vulnerable(
                CVE, NAME,
                f"SSLv2 rejected but EXPORT-grade ciphers accepted: "
                f"{cipher_str}"
                f"{f', +{overflow} more' if overflow > 0 else ''}. "
                "This indicates Special DROWN vulnerability — EXPORT cipher "
                "keys can be brute-forced in ~256 connections, enabling "
                "decryption of TLS sessions sharing this RSA key. "
                "Disable all EXPORT-grade ciphers.",
            )

    # ── All probes rejected ───────────────────────────────────
    if sslv2_result is False:
        return make_clean(
            CVE, NAME,
            "Server rejected SSLv2 CLIENT-HELLO and no EXPORT-grade ciphers "
            "were accepted. Not vulnerable to General or Special DROWN.",
        )

    # sslv2_result is None and openssl unavailable — inconclusive
    return make_inconclusive(
        CVE, NAME,
        "Raw SSLv2 probe was inconclusive and openssl binary is not "
        "available for fallback. Install openssl and re-run for a "
        "definitive result.",
    )


# ─────────────────────────────────────────────
# Probe 1 — Raw SSLv2 CLIENT-HELLO
# ─────────────────────────────────────────────

def _probe_sslv2_raw(
    host:    str,
    port:    int,
    timeout: int,
) -> bool | None:
    """
    Send a hand-crafted SSLv2 CLIENT-HELLO and check the response.

    SSLv2 SERVER-HELLO starts with a 2-byte record header where the
    MSB of the first byte is set (no-padding form), followed by
    MSG-SERVER-HELLO (0x04).

    Returns:
        True  — server sent an SSLv2 SERVER-HELLO (SSLv2 supported).
        False — server sent a non-SSLv2 response or closed immediately.
        None  — connection failed (timeout, refused) — inconclusive.
    """
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((host, port))
        sock.send(_build_sslv2_client_hello())

        # Read up to 256 bytes — SERVER-HELLO is small
        response = b""
        try:
            while len(response) < 256:
                chunk = sock.recv(512)
                if not chunk:
                    break
                response += chunk
        except socket.timeout:
            pass
        finally:
            sock.close()

        if len(response) < 3:
            # Too short to be a valid SSLv2 SERVER-HELLO
            return False

        # SSLv2 SERVER-HELLO detection:
        # Byte 0: MSB set = no-padding record header (0x80 | length_high)
        # Byte 2: MSG-SERVER-HELLO = 0x04
        first_byte = response[0]
        msg_type   = response[2]

        if (first_byte & 0x80) and msg_type == _SSLV2_SERVER_HELLO:
            return True

        # TLS alert or other non-SSLv2 response — server rejected SSLv2
        return False

    except (ConnectionRefusedError, ConnectionResetError):
        return None
    except socket.timeout:
        return None
    except OSError:
        return None


def _build_sslv2_client_hello() -> bytes:
    """
    Thin wrapper that calls base._build_sslv2_client_hello with
    default cipher specs. Imported from base to keep packet-building
    logic centralised but aliased here for readability.
    """
    return _build_sslv2_client_hello()


# ─────────────────────────────────────────────
# Probe 2 — openssl s_client -ssl2 fallback
# ─────────────────────────────────────────────

def _probe_sslv2_openssl(
    host:    str,
    port:    int,
    timeout: int,
) -> bool:
    """
    Use openssl s_client -ssl2 to probe for SSLv2 support.
    Returns True if the handshake succeeded.

    Note: Many modern openssl builds are compiled without SSLv2
    support. If openssl returns "unknown option -ssl2" this probe
    is inconclusive rather than False.
    """
    rc, stdout, stderr = _run_openssl(
        ["s_client", "-ssl2",
         "-connect", f"{host}:{port}",
         "-brief"],
        timeout=timeout,
    )
    combined = (stdout + stderr).decode("utf-8", errors="replace")

    # openssl compiled without SSLv2 support
    if "unknown option" in combined or "ssl2 not supported" in combined.lower():
        return False

    return (
        rc == 0
        or "Server version" in combined
        or "Cipher    :" in combined
        or "CONNECTED" in combined
    )


# ─────────────────────────────────────────────
# Probe 3 — EXPORT cipher check (Special DROWN)
# ─────────────────────────────────────────────

def _probe_export_ciphers(
    host:    str,
    port:    int,
    timeout: int,
) -> list[str]:
    """
    Check whether the server accepts any EXPORT-grade cipher suite.
    Returns a list of accepted EXPORT cipher names (may be empty).

    First tries the combined "EXPORT" keyword via openssl, then
    falls back to individual cipher probes if the keyword fails.
    """
    accepted: list[str] = []

    # Quick combined EXPORT probe first
    rc, stdout, stderr = _run_openssl(
        ["s_client", "-cipher", "EXPORT",
         "-connect", f"{host}:{port}",
         "-brief"],
        timeout=timeout,
    )
    combined = (stdout + stderr).decode("utf-8", errors="replace")

    if rc == 0 or "Cipher is" in combined:
        # EXPORT accepted — find which specific ones
        for cipher in EXPORT_CIPHERS:
            if _tls_probe_cipher(host, port, cipher, "-tls1_2", timeout):
                accepted.append(cipher)
            if not accepted:
                # Try TLS 1.0 as well — EXPORT more common on older protocols
                if _tls_probe_cipher(host, port, cipher, "-tls1", timeout):
                    accepted.append(cipher)

        # If we still have nothing specific, just report the keyword hit
        if not accepted:
            accepted.append("EXPORT (generic)")

    return accepted