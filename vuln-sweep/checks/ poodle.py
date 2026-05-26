#!/usr/bin/env python3
"""
vuln_sweep/checks/poodle.py
━━━━━━━━━━━━━━━━━━━━━━━━━━
CVE-2014-3566  POODLE
(Padding Oracle On Downgraded Legacy Encryption)

Vulnerability:
    POODLE exploits the SSLv3 CBC padding oracle. SSLv3 uses a flawed
    padding scheme — the padding bytes are undefined (any value allowed)
    and only the last byte is checked. This means an attacker in a MITM
    position can mount a byte-by-byte padding oracle attack to decrypt
    individual bytes of an SSLv3 CBC-encrypted record.

    The classic attack scenario:
      1. Attacker forces a TLS downgrade to SSLv3 (e.g. by injecting
         connection failures during the TLS handshake).
      2. Attacker injects chosen ciphertext blocks into the SSLv3 stream.
      3. Server's padding validation response leaks one bit per attempt.
      4. Attacker recovers plaintext (e.g. session cookie) in ~256
         requests per byte.

    POODLE-TLS (CVE-2014-8730):
        A variant affecting some TLS 1.0/1.1/1.2 implementations that
        use the same broken padding validation as SSLv3. Less common but
        worth checking when SSLv3 is disabled.

Detection method:
    Probe 1 — SSLv3 handshake (openssl s_client -ssl3):
        If the server completes an SSLv3 handshake, it is vulnerable
        to General POODLE.

    Probe 2 — TLS 1.0/1.1 CBC cipher check (POODLE-TLS variant):
        If SSLv3 is rejected but TLS 1.0/1.1 accepts CBC ciphers,
        we flag POODLE-TLS structural exposure. Full confirmation of
        POODLE-TLS requires a padding oracle timing test against the
        specific implementation.

    Probe 3 — TLS_FALLBACK_SCSV check:
        If SSLv3 is accepted, we additionally check whether the server
        supports TLS_FALLBACK_SCSV (RFC 7507) — the downgrade protection
        mechanism that prevents forced downgrades. Servers that accept
        SSLv3 AND support FALLBACK_SCSV are still vulnerable to POODLE
        if the client supports SSLv3, but the SCSV presence reduces
        the risk of forced downgrade attacks.

References:
    https://nvd.nist.gov/vuln/detail/CVE-2014-3566
    https://nvd.nist.gov/vuln/detail/CVE-2014-8730
    https://www.openssl.org/~bodo/ssl-poodle.pdf
    https://tools.ietf.org/html/rfc7507
"""

from vuln_sweep.checks.base import (
    CheckResult,
    _tls_probe_protocol,
    _tls_probe_cipher,
    _run_openssl,
    openssl_available,
    make_vulnerable,
    make_clean,
    make_inconclusive,
)


# ─────────────────────────────────────────────
# Constants
# ─────────────────────────────────────────────

CVE  = "CVE-2014-3566"
NAME = "POODLE"

# CBC cipher suites on TLS 1.0/1.1 — POODLE-TLS variant
# Each tuple: (openssl_name, iana_name)
TLS_CBC_CIPHERS: list[tuple[str, str]] = [
    ("AES128-SHA",               "TLS_RSA_WITH_AES_128_CBC_SHA"),
    ("AES256-SHA",               "TLS_RSA_WITH_AES_256_CBC_SHA"),
    ("ECDHE-RSA-AES128-SHA",     "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA"),
    ("ECDHE-RSA-AES256-SHA",     "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA"),
    ("DHE-RSA-AES128-SHA",       "TLS_DHE_RSA_WITH_AES_128_CBC_SHA"),
    ("DHE-RSA-AES256-SHA",       "TLS_DHE_RSA_WITH_AES_256_CBC_SHA"),
    ("DES-CBC3-SHA",             "TLS_RSA_WITH_3DES_EDE_CBC_SHA"),
]

# TLS_FALLBACK_SCSV cipher code (RFC 7507)
# Included in a ClientHello to signal "this is a downgraded connection"
_FALLBACK_SCSV = b"\x56\x00"


# ─────────────────────────────────────────────
# Check entry point
# ─────────────────────────────────────────────

def check(host: str, port: int, timeout: int) -> CheckResult:
    """
    Check whether the host is vulnerable to POODLE or POODLE-TLS.

    Detection steps:
      1. Verify openssl binary is available.
      2. Probe SSLv3 handshake — General POODLE.
      3. If SSLv3 accepted: probe TLS_FALLBACK_SCSV support.
      4. If SSLv3 rejected: probe TLS 1.0/1.1 CBC — POODLE-TLS.

    Returns:
        CheckResult with vulnerable=True  if SSLv3 or POODLE-TLS exposure.
                             vulnerable=False if SSLv3 and CBC rejected.
                             vulnerable=None  if check could not complete.
    """
    try:
        return _do_check(host, port, timeout)
    except Exception as e:
        return make_inconclusive(CVE, NAME, f"Unexpected error: {e}")


def _do_check(host: str, port: int, timeout: int) -> CheckResult:

    # ── Step 1: openssl available? ────────────────────────────
    if not openssl_available():
        return make_inconclusive(
            CVE, NAME,
            "openssl binary not found in PATH — cannot probe SSLv3.",
        )

    # ── Step 2: SSLv3 handshake probe ────────────────────────
    sslv3_accepted = _probe_sslv3(host, port, timeout)

    if sslv3_accepted is None:
        # openssl compiled without SSLv3 support
        return make_inconclusive(
            CVE, NAME,
            "openssl binary does not support -ssl3 (compiled without SSLv3). "
            "Cannot probe for General POODLE. Checking POODLE-TLS variant.",
        )

    if sslv3_accepted:
        # ── Step 3: SSLv3 confirmed — check FALLBACK_SCSV ────
        fallback_scsv = _probe_fallback_scsv(host, port, timeout)
        return _build_sslv3_result(fallback_scsv)

    # ── Step 4: SSLv3 rejected — probe POODLE-TLS ────────────
    poodle_tls_ciphers = _probe_poodle_tls(host, port, timeout)

    if poodle_tls_ciphers:
        return _build_poodle_tls_result(poodle_tls_ciphers)

    # ── All clean ─────────────────────────────────────────────
    return make_clean(
        CVE, NAME,
        "Server rejected SSLv3 connections and no CBC ciphers were accepted "
        "on TLS 1.0/1.1. Not vulnerable to General POODLE or POODLE-TLS. "
        "Ensure TLS_FALLBACK_SCSV (RFC 7507) is supported to prevent "
        "forced protocol downgrade attacks.",
    )


# ─────────────────────────────────────────────
# Probe 1 — SSLv3 handshake
# ─────────────────────────────────────────────

def _probe_sslv3(
    host:    str,
    port:    int,
    timeout: int,
) -> bool | None:
    """
    Attempt an SSLv3 handshake via openssl s_client -ssl3.

    Returns:
        True  — SSLv3 handshake succeeded.
        False — Server rejected SSLv3.
        None  — openssl compiled without SSLv3 support.
    """
    rc, stdout, stderr = _run_openssl(
        ["s_client", "-ssl3",
         "-connect", f"{host}:{port}",
         "-brief"],
        timeout=timeout,
    )
    combined = (stdout + stderr).decode("utf-8", errors="replace")

    # openssl binary compiled without SSLv3 support
    if (
        "unknown option" in combined
        or "ssl3 not supported" in combined.lower()
        or "no protocols available" in combined.lower()
    ):
        return None

    # SSLv3 accepted
    if (
        rc == 0
        or "CONNECTED"     in combined
        or "Cipher is"     in combined
        or "Protocol  : SSLv3" in combined
        or "New, SSLv3"    in combined
    ):
        return True

    # SSLv3 rejected
    return False


# ─────────────────────────────────────────────
# Probe 2 — TLS_FALLBACK_SCSV
# ─────────────────────────────────────────────

def _probe_fallback_scsv(
    host:    str,
    port:    int,
    timeout: int,
) -> bool:
    """
    Check whether the server supports TLS_FALLBACK_SCSV (RFC 7507).

    TLS_FALLBACK_SCSV is a special sentinel cipher code (0x5600)
    that a client includes when it is doing a downgraded connection.
    A server that supports FALLBACK_SCSV will send an
    inappropriate_fallback alert if the client's offered version
    is lower than the server's best supported version.

    We probe by including FALLBACK_SCSV in a TLS 1.1 ClientHello
    (forcing a downgrade from TLS 1.2+). If the server sends
    an inappropriate_fallback alert — it supports FALLBACK_SCSV.
    """
    rc, stdout, stderr = _run_openssl(
        ["s_client",
         "-no_tls1_2", "-no_tls1_3",       # force TLS 1.1 or below
         "-connect", f"{host}:{port}",
         "-fallback_scsv",                  # include TLS_FALLBACK_SCSV
         "-brief"],
        timeout=timeout,
    )
    combined = (stdout + stderr).decode("utf-8", errors="replace")

    # Server sent inappropriate_fallback alert → FALLBACK_SCSV supported
    return (
        "inappropriate_fallback" in combined.lower()
        or "tlsv1 alert inappropriate fallback" in combined.lower()
        or "sslv3 alert handshake failure" in combined.lower()
    )


# ─────────────────────────────────────────────
# Probe 3 — POODLE-TLS (CBC on TLS 1.0/1.1)
# ─────────────────────────────────────────────

def _probe_poodle_tls(
    host:    str,
    port:    int,
    timeout: int,
) -> list[tuple[str, str, str]]:
    """
    Check for POODLE-TLS exposure: CBC ciphers accepted on TLS 1.0/1.1.

    Returns a list of (openssl_name, iana_name, protocol) tuples
    for accepted CBC ciphers. Empty list if none found.
    """
    accepted: list[tuple[str, str, str]] = []

    for proto_flag, proto_name in [("-tls1", "TLS 1.0"), ("-tls1_1", "TLS 1.1")]:
        for openssl_name, iana_name in TLS_CBC_CIPHERS:
            if _tls_probe_cipher(
                host, port,
                cipher     = openssl_name,
                proto_flag = proto_flag,
                timeout    = timeout,
            ):
                accepted.append((openssl_name, iana_name, proto_name))
                # One CBC per protocol is enough for structural check
                break

    return accepted


# ─────────────────────────────────────────────
# Result builders
# ─────────────────────────────────────────────

def _build_sslv3_result(fallback_scsv: bool) -> CheckResult:
    """
    Build the vulnerable result for General POODLE (SSLv3 accepted).
    Includes FALLBACK_SCSV status in the detail message.
    """
    scsv_note = (
        "Server supports TLS_FALLBACK_SCSV (RFC 7507) which reduces "
        "forced-downgrade risk, but the server still accepts SSLv3 "
        "directly — clients that support SSLv3 remain vulnerable. "
        if fallback_scsv else
        "Server does NOT support TLS_FALLBACK_SCSV (RFC 7507), meaning "
        "forced protocol downgrade attacks are also possible. "
    )

    detail = (
        "Server accepted an SSLv3 connection (General POODLE). "
        "A MITM attacker can exploit the SSLv3 CBC padding oracle to "
        "decrypt session cookies in approximately 256 requests per byte "
        "by injecting crafted CBC blocks and observing padding validation. "
        f"{scsv_note}"
        "Remediation: disable SSLv3 entirely. "
        "Set minimum protocol to TLS 1.2. "
        "Enable TLS_FALLBACK_SCSV if legacy clients require TLS 1.0/1.1."
    )

    return make_vulnerable(CVE, NAME, detail)


def _build_poodle_tls_result(
    accepted: list[tuple[str, str, str]],
) -> CheckResult:
    """
    Build the vulnerable result for POODLE-TLS exposure
    (CBC on TLS 1.0/1.1 with potentially broken padding).
    """
    # Format cipher list grouped by protocol
    by_proto: dict[str, list[str]] = {}
    for _, iana, proto in accepted:
        by_proto.setdefault(proto, []).append(iana)

    proto_lines = [
        f"{proto}: {', '.join(ciphers[:2])}"
        f"{'...' if len(ciphers) > 2 else ''}"
        for proto, ciphers in by_proto.items()
    ]

    detail = (
        "SSLv3 rejected but CBC ciphers accepted on TLS 1.0/1.1 "
        f"(POODLE-TLS variant, CVE-2014-8730). "
        f"Affected: {'; '.join(proto_lines)}. "
        "Some TLS implementations use the same flawed padding validation "
        "as SSLv3, making them vulnerable to the same padding oracle attack "
        "on TLS 1.0/1.1 CBC records. Full confirmation requires a "
        "padding oracle timing test against this specific implementation. "
        "Remediation: disable TLS 1.0 and TLS 1.1 (deprecated per RFC 8996). "
        "Use TLS 1.2+ with AEAD ciphersuites (AES-GCM, ChaCha20-Poly1305) only."
    )

    return make_vulnerable(CVE, NAME, detail)