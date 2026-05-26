#!/usr/bin/env python3
"""
vuln_sweep/checks/beast.py
━━━━━━━━━━━━━━━━━━━━━━━━━
CVE-2011-3389  BEAST
(Browser Exploit Against SSL/TLS)

Vulnerability:
    TLS 1.0 uses CBC mode with a predictable IV — the last ciphertext
    block of the previous record becomes the IV for the next record.
    A MITM attacker who can inject chosen plaintext (e.g. via a script
    tag in a HTTP resource on the same connection) can mount a
    chosen-plaintext attack to recover individual bytes of a secret
    (typically a session cookie).

Detection method:
    BEAST requires two conditions both to be true:
      1. The server accepts TLS 1.0 connections.
      2. The server accepts at least one CBC cipher suite on TLS 1.0.

    We probe both conditions using openssl s_client with:
      - Protocol flag:   -tls1
      - Per-cipher flag: -cipher <name>

    If both conditions are met the host is flagged as structurally
    vulnerable to BEAST. Full exploitation also requires a MITM
    position and a chosen-plaintext injection vector — but the
    server configuration alone is the remediable surface.

Mitigations:
    • Disable TLS 1.0 (preferred — also fixes POODLE-TLS)
    • If TLS 1.0 must remain: prioritise RC4 ciphers server-side
      so clients negotiate RC4 over CBC on TLS 1.0 (note: RC4 has
      its own weaknesses so this is a last resort)
    • Prioritise TLS 1.2+ with AEAD ciphers (AES-GCM, ChaCha20)

References:
    https://nvd.nist.gov/vuln/detail/CVE-2011-3389
    https://www.openssl.org/~bodo/tls-cbc.txt
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

CVE  = "CVE-2011-3389"
NAME = "BEAST"

# CBC cipher suites accepted on TLS 1.0 constitute BEAST exposure.
# Ordered from most-common to least-common so we find a hit fast.
# Each tuple: (openssl_cipher_name, iana_name)
CBC_CIPHERS: list[tuple[str, str]] = [
    ("AES128-SHA",                   "TLS_RSA_WITH_AES_128_CBC_SHA"),
    ("AES256-SHA",                   "TLS_RSA_WITH_AES_256_CBC_SHA"),
    ("ECDHE-RSA-AES128-SHA",         "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA"),
    ("ECDHE-RSA-AES256-SHA",         "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA"),
    ("ECDHE-ECDSA-AES128-SHA",       "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA"),
    ("ECDHE-ECDSA-AES256-SHA",       "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA"),
    ("DHE-RSA-AES128-SHA",           "TLS_DHE_RSA_WITH_AES_128_CBC_SHA"),
    ("DHE-RSA-AES256-SHA",           "TLS_DHE_RSA_WITH_AES_256_CBC_SHA"),
    ("DES-CBC3-SHA",                 "TLS_RSA_WITH_3DES_EDE_CBC_SHA"),
    ("ECDHE-RSA-DES-CBC3-SHA",       "TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA"),
]

# RC4 ciphers on TLS 1.0 mitigate BEAST (no CBC used).
# We check for these to determine whether a BEAST-mitigated
# configuration exists even when TLS 1.0 is enabled.
RC4_CIPHERS: list[str] = [
    "RC4-SHA",
    "RC4-MD5",
    "ECDHE-RSA-RC4-SHA",
]


# ─────────────────────────────────────────────
# Check entry point
# ─────────────────────────────────────────────

def check(host: str, port: int, timeout: int) -> CheckResult:
    """
    Check whether the host is structurally vulnerable to BEAST.

    Detection steps:
      1. Verify openssl binary is available.
      2. Probe TLS 1.0 support.
      3. If TLS 1.0 accepted: probe each CBC cipher in CBC_CIPHERS.
      4. If TLS 1.0 accepted but only RC4: note partial mitigation.
      5. Return result.

    Returns:
        CheckResult with vulnerable=True  if TLS 1.0 + CBC accepted.
                             vulnerable=False if TLS 1.0 rejected.
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
            "openssl binary not found in PATH — cannot probe TLS 1.0 ciphers.",
        )

    # ── Step 2: Does server accept TLS 1.0? ──────────────────
    tls10_accepted = _tls_probe_protocol(
        host, port, "-tls1", timeout=timeout
    )

    if not tls10_accepted:
        return make_clean(
            CVE, NAME,
            "Server rejected TLS 1.0. BEAST requires TLS 1.0 — not vulnerable.",
        )

    # ── Step 3: TLS 1.0 accepted — probe CBC ciphers ─────────
    accepted_cbc: list[tuple[str, str]] = []

    for openssl_name, iana_name in CBC_CIPHERS:
        accepted = _tls_probe_cipher(
            host, port,
            cipher     = openssl_name,
            proto_flag = "-tls1",
            timeout    = timeout,
        )
        if accepted:
            accepted_cbc.append((openssl_name, iana_name))

    # ── Step 4: Vulnerable if any CBC cipher accepted ─────────
    if accepted_cbc:
        cbc_names = [iana for _, iana in accepted_cbc]
        first_3   = cbc_names[:3]
        overflow  = len(cbc_names) - 3

        detail = (
            f"TLS 1.0 is enabled and server accepted {len(accepted_cbc)} "
            f"CBC cipher suite{'s' if len(accepted_cbc) > 1 else ''}: "
            f"{', '.join(first_3)}"
            f"{f', +{overflow} more' if overflow > 0 else ''}. "
            "A MITM attacker with a chosen-plaintext injection vector "
            "can recover individual bytes of a TLS 1.0 CBC-encrypted "
            "secret (e.g. session cookie) via IV chaining. "
            "Disable TLS 1.0 or restrict to AEAD ciphers."
        )
        return make_vulnerable(CVE, NAME, detail)

    # ── Step 5: TLS 1.0 accepted but no CBC — check for RC4 ──
    # Server has TLS 1.0 but appears to have mitigated BEAST
    # by not accepting CBC ciphers. Check if RC4 is the reason.
    accepted_rc4: list[str] = []
    for rc4_cipher in RC4_CIPHERS:
        if _tls_probe_cipher(host, port, rc4_cipher, "-tls1", timeout):
            accepted_rc4.append(rc4_cipher)

    if accepted_rc4:
        detail = (
            "TLS 1.0 is enabled but no CBC ciphers accepted — "
            f"server appears to prefer RC4 ({', '.join(accepted_rc4)}) "
            "on TLS 1.0. BEAST is mitigated but RC4 has known statistical "
            "weaknesses (CVE-2013-2566, CVE-2015-2808). "
            "Disable TLS 1.0 entirely and use TLS 1.2+ with AEAD ciphers."
        )
        return make_clean(CVE, NAME, detail)

    # TLS 1.0 accepted but neither CBC nor RC4 negotiated.
    # Likely AEAD-only on TLS 1.0 (uncommon but possible).
    return make_clean(
        CVE, NAME,
        "TLS 1.0 is enabled but no CBC ciphers were accepted. "
        "BEAST requires both TLS 1.0 and CBC — structurally not vulnerable. "
        "Consider disabling TLS 1.0 regardless as it is deprecated (RFC 8996).",
    )