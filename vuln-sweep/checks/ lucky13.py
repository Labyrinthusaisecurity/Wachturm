#!/usr/bin/env python3
"""
vuln_sweep/checks/lucky13.py
━━━━━━━━━━━━━━━━━━━━━━━━━━━
CVE-2013-0169  LUCKY13

Vulnerability:
    LUCKY13 is a timing side-channel attack against the MAC-then-encrypt
    construction used in TLS CBC ciphersuites. The attack exploits
    differences in the time taken to verify MAC padding depending on
    the position of the padding bytes within a decrypted CBC block.

    An attacker who can:
      1. Observe encrypted TLS traffic between client and server
      2. Inject modified ciphertext records (MITM position)
      3. Make timing measurements of the server's responses

    ...can distinguish between correctly and incorrectly padded records
    by measuring tiny differences (microseconds) in server response time.
    By sending many crafted records and statistically analysing response
    times, the attacker recovers plaintext one byte at a time.

    This is a structural vulnerability in the CBC MAC-then-encrypt design.
    It cannot be fully patched without switching to AEAD ciphers — it can
    only be mitigated by making the server's MAC verification constant-time.

Detection method:
    Full LUCKY13 confirmation requires thousands of adaptive timing
    measurements with sub-microsecond precision — impractical in a
    passive sweep tool. We perform a structural check instead:

    Condition 1: Server supports TLS 1.2 or below (TLS 1.3 uses only AEAD).
    Condition 2: Server accepts at least one CBC cipher suite.

    If both conditions are met, the host has the structural exposure.
    Whether the specific implementation has a constant-time MAC fix
    (OpenSSL's 2013 patch, NSS, GnuTLS) cannot be determined without
    timing measurements.

    We grade this as vulnerable=True when the structural exposure exists,
    with the detail message clearly noting that timing confirmation was
    not performed.

References:
    https://nvd.nist.gov/vuln/detail/CVE-2013-0169
    https://www.isg.rhul.ac.uk/tls/TLStiming.pdf
    https://www.openssl.org/news/secadv/20130205.txt
"""

from vuln_sweep.checks.base import (
    CheckResult,
    _tls_probe_protocol,
    _tls_probe_cipher,
    openssl_available,
    make_vulnerable,
    make_clean,
    make_inconclusive,
)


# ─────────────────────────────────────────────
# Constants
# ─────────────────────────────────────────────

CVE  = "CVE-2013-0169"
NAME = "LUCKY13"

# CBC cipher suites that create LUCKY13 exposure on TLS ≤ 1.2.
# Each tuple: (openssl_name, iana_name, key_exchange)
# Ordered from most-common to least-common in production deployments.
CBC_CIPHERS: list[tuple[str, str, str]] = [
    # RSA key exchange
    ("AES128-SHA",              "TLS_RSA_WITH_AES_128_CBC_SHA",         "RSA"),
    ("AES256-SHA",              "TLS_RSA_WITH_AES_256_CBC_SHA",         "RSA"),
    ("AES128-SHA256",           "TLS_RSA_WITH_AES_128_CBC_SHA256",      "RSA"),
    ("AES256-SHA256",           "TLS_RSA_WITH_AES_256_CBC_SHA256",      "RSA"),
    ("DES-CBC3-SHA",            "TLS_RSA_WITH_3DES_EDE_CBC_SHA",        "RSA"),
    # ECDHE — forward secret but still CBC
    ("ECDHE-RSA-AES128-SHA",    "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA",   "ECDHE"),
    ("ECDHE-RSA-AES256-SHA",    "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA",   "ECDHE"),
    ("ECDHE-RSA-AES128-SHA256", "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256","ECDHE"),
    ("ECDHE-RSA-AES256-SHA384", "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384","ECDHE"),
    # ECDSA
    ("ECDHE-ECDSA-AES128-SHA",  "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA","ECDSA"),
    ("ECDHE-ECDSA-AES256-SHA",  "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA","ECDSA"),
    # DHE
    ("DHE-RSA-AES128-SHA",      "TLS_DHE_RSA_WITH_AES_128_CBC_SHA",    "DHE"),
    ("DHE-RSA-AES256-SHA",      "TLS_DHE_RSA_WITH_AES_256_CBC_SHA",    "DHE"),
    ("DHE-RSA-AES128-SHA256",   "TLS_DHE_RSA_WITH_AES_128_CBC_SHA256", "DHE"),
]

# AEAD cipher suites — not vulnerable to LUCKY13
# Used to check whether a TLS ≤1.2 server is AEAD-only
AEAD_CIPHERS: list[str] = [
    "AES128-GCM-SHA256",
    "AES256-GCM-SHA384",
    "ECDHE-RSA-AES128-GCM-SHA256",
    "ECDHE-RSA-AES256-GCM-SHA384",
    "ECDHE-ECDSA-AES128-GCM-SHA256",
    "DHE-RSA-AES128-GCM-SHA256",
    "TLS_CHACHA20_POLY1305_SHA256",
]

# Protocol flags to probe (TLS 1.3 uses AEAD only — not vulnerable)
TLS_LEGACY_FLAGS: list[str] = ["-tls1_2", "-tls1_1", "-tls1"]


# ─────────────────────────────────────────────
# Check entry point
# ─────────────────────────────────────────────

def check(host: str, port: int, timeout: int) -> CheckResult:
    """
    Check whether the host has structural LUCKY13 exposure.

    Detection steps:
      1. Verify openssl binary is available.
      2. Check if server is TLS 1.3 only (not vulnerable).
      3. Probe CBC ciphers on TLS 1.2, 1.1, 1.0.
      4. Check for AEAD-only configuration (mitigated).
      5. Return result with appropriate detail.

    Returns:
        CheckResult with vulnerable=True  if TLS ≤1.2 + CBC accepted.
                             vulnerable=False if TLS 1.3 only or AEAD only.
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
            "openssl binary not found in PATH — cannot probe CBC ciphers.",
        )

    # ── Step 2: TLS 1.3 only check ───────────────────────────
    # TLS 1.3 mandates AEAD — if the server speaks only TLS 1.3
    # it cannot be vulnerable to LUCKY13 regardless of cipher config.
    if _is_tls13_only(host, port, timeout):
        return make_clean(
            CVE, NAME,
            "Server supports TLS 1.3 only. TLS 1.3 uses exclusively AEAD "
            "ciphersuites — CBC MAC-then-encrypt does not exist in TLS 1.3. "
            "LUCKY13 is not applicable.",
        )

    # ── Step 3: Probe CBC ciphers on TLS ≤ 1.2 ───────────────
    accepted_cbc = _probe_cbc_ciphers(host, port, timeout)

    if accepted_cbc:
        return _build_vulnerable_result(accepted_cbc)

    # ── Step 4: No CBC found — check for AEAD-only ───────────
    # Confirm the server genuinely negotiates AEAD on TLS ≤ 1.2
    # (rather than having refused all our connections).
    aead_accepted = _probe_aead_ciphers(host, port, timeout)

    if aead_accepted:
        return make_clean(
            CVE, NAME,
            "Server accepts TLS 1.2 or below but only AEAD ciphersuites "
            f"({', '.join(aead_accepted[:2])}"
            f"{'...' if len(aead_accepted) > 2 else ''}). "
            "LUCKY13 requires CBC MAC-then-encrypt — not applicable with AEAD. "
            "Configuration is correct.",
        )

    # ── Step 5: Could not confirm either way ─────────────────
    # Neither CBC nor AEAD probes succeeded — server may have
    # rejected all our connections or uses a non-standard config.
    return make_inconclusive(
        CVE, NAME,
        "Could not negotiate any cipher suite on TLS ≤ 1.2 — "
        "neither CBC nor AEAD ciphers were accepted. "
        "Server may require client certificates or use a non-standard "
        "cipher configuration. Result inconclusive.",
    )


# ─────────────────────────────────────────────
# TLS 1.3 only detection
# ─────────────────────────────────────────────

def _is_tls13_only(host: str, port: int, timeout: int) -> bool:
    """
    Return True if the server supports TLS 1.3 but rejects all
    TLS ≤ 1.2 connections.

    We probe TLS 1.2 explicitly — if rejected and TLS 1.3 is
    accepted, the server is TLS 1.3 only.
    """
    # Check if TLS 1.2 is accepted
    tls12_accepted = _tls_probe_protocol(
        host, port, "-tls1_2", timeout=timeout
    )
    if tls12_accepted:
        return False

    # TLS 1.2 rejected — check if TLS 1.3 works
    tls13_accepted = _tls_probe_protocol(
        host, port, "-tls1_3", timeout=timeout
    )
    return tls13_accepted


# ─────────────────────────────────────────────
# CBC cipher probing
# ─────────────────────────────────────────────

def _probe_cbc_ciphers(
    host:    str,
    port:    int,
    timeout: int,
) -> list[tuple[str, str, str]]:
    """
    Probe each CBC cipher in CBC_CIPHERS on TLS 1.2, 1.1, and 1.0.
    Returns a list of (openssl_name, iana_name, kex_type) tuples
    for accepted ciphers.

    Stops after finding the first accepted cipher per protocol —
    we only need to confirm structural exposure, not enumerate all.
    For a complete cipher audit use cipher-judge instead.
    """
    accepted: list[tuple[str, str, str]] = []

    for proto_flag in TLS_LEGACY_FLAGS:
        for openssl_name, iana_name, kex in CBC_CIPHERS:
            if _tls_probe_cipher(
                host, port,
                cipher     = openssl_name,
                proto_flag = proto_flag,
                timeout    = timeout,
            ):
                entry = (openssl_name, iana_name, kex)
                if entry not in accepted:
                    accepted.append(entry)

                # Found one per protocol — enough for structural check.
                # Break inner loop, continue to next protocol.
                break

    return accepted


def _probe_aead_ciphers(
    host:    str,
    port:    int,
    timeout: int,
) -> list[str]:
    """
    Check whether any AEAD cipher is accepted on TLS ≤ 1.2.
    Returns list of accepted AEAD openssl cipher names.
    """
    accepted: list[str] = []

    for cipher in AEAD_CIPHERS:
        for proto_flag in ("-tls1_2", "-tls1_1"):
            if _tls_probe_cipher(
                host, port,
                cipher     = cipher,
                proto_flag = proto_flag,
                timeout    = timeout,
            ):
                if cipher not in accepted:
                    accepted.append(cipher)
                break

    return accepted


# ─────────────────────────────────────────────
# Result builders
# ─────────────────────────────────────────────

def _build_vulnerable_result(
    accepted_cbc: list[tuple[str, str, str]],
) -> CheckResult:
    """
    Build the vulnerable CheckResult with a detailed message
    summarising which CBC ciphers were found and on which protocols.
    """
    # Group by key exchange type for a cleaner message
    rsa_ciphers   = [iana for _, iana, kex in accepted_cbc if kex == "RSA"]
    ecdhe_ciphers = [iana for _, iana, kex in accepted_cbc if kex == "ECDHE"]
    dhe_ciphers   = [iana for _, iana, kex in accepted_cbc if kex == "DHE"]
    ecdsa_ciphers = [iana for _, iana, kex in accepted_cbc if kex == "ECDSA"]

    cipher_lines = []
    if rsa_ciphers:
        cipher_lines.append(f"RSA: {', '.join(rsa_ciphers[:2])}"
                            f"{'...' if len(rsa_ciphers) > 2 else ''}")
    if ecdhe_ciphers:
        cipher_lines.append(f"ECDHE: {', '.join(ecdhe_ciphers[:2])}"
                            f"{'...' if len(ecdhe_ciphers) > 2 else ''}")
    if dhe_ciphers:
        cipher_lines.append(f"DHE: {', '.join(dhe_ciphers[:2])}"
                            f"{'...' if len(dhe_ciphers) > 2 else ''}")
    if ecdsa_ciphers:
        cipher_lines.append(f"ECDSA: {', '.join(ecdsa_ciphers[:2])}"
                            f"{'...' if len(ecdsa_ciphers) > 2 else ''}")

    total = len(accepted_cbc)

    detail = (
        f"Server accepted {total} CBC cipher suite"
        f"{'s' if total > 1 else ''} on TLS ≤ 1.2, "
        f"creating structural LUCKY13 exposure. "
        f"Accepted: {'; '.join(cipher_lines)}. "
        "LUCKY13 requires a MITM position and microsecond-precision "
        "timing measurements — timing confirmation was not performed "
        "in this sweep. Whether this specific implementation has a "
        "constant-time MAC fix cannot be determined without timing analysis. "
        "Recommended action: prefer AEAD ciphersuites "
        "(AES-GCM, ChaCha20-Poly1305) and disable CBC suites. "
        "Disable TLS 1.0 and TLS 1.1 regardless (deprecated per RFC 8996)."
    )

    return make_vulnerable(CVE, NAME, detail)