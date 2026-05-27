#!/usr/bin/env python3
"""
vuln_sweep/checks/robot.py
━━━━━━━━━━━━━━━━━━━━━━━━━━
CVE-2017-17382  ROBOT
(Return Of Bleichenbacher's Oracle Threat)

Vulnerability:
    ROBOT is the 2017 rediscovery of Daniel Bleichenbacher's 1998 attack
    against RSA PKCS#1 v1.5 encryption as used in TLS key exchange.

    When a TLS server uses RSA key exchange (as opposed to ephemeral
    ECDHE or DHE), the client encrypts the pre-master secret using the
    server's RSA public key. The server decrypts it and responds
    differently depending on whether the PKCS#1 v1.5 padding is valid.

    This response difference — even a timing difference of microseconds,
    or a different TLS error code — creates a padding oracle. An attacker
    who can send adaptive chosen-ciphertext queries can:
      • Decrypt any RSA-encrypted session without the private key
      • Forge RSA signatures
      • Break recorded TLS sessions retroactively

    The attack requires approximately 1 million adaptive queries in the
    worst case (~100 in the best case against some implementations).

    ROBOT affected a wide range of vendors in 2017: F5, Cisco, Citrix,
    Radware, Bouncy Castle, Erlang, WolfSSL, and others.

Detection method:
    Full ROBOT confirmation requires differential oracle measurements —
    sending crafted PKCS#1 v1.5 ciphertexts and measuring response
    differences. This is expensive and intrusive. We use a lightweight
    two-stage structural check:

    Stage 1 — Raw ServerHello cipher detection:
        Connect, send a ClientHello advertising only RSA key exchange
        cipher suites, and parse the ServerHello to extract the
        negotiated cipher code. If the server chose an RSA-kex cipher
        (codes 0x002f, 0x0035, 0x000a, 0x0005), the server uses RSA
        key exchange and is structurally exposed to ROBOT.

    Stage 2 — openssl s_client -cipher RSA fallback:
        If Stage 1 cannot parse a ServerHello (firewall, load balancer,
        or connection failure), fall back to openssl to confirm whether
        RSA key exchange ciphers are accepted.

    We flag vulnerable=True for RSA key exchange because:
      - All known ROBOT-vulnerable implementations use RSA kex
      - ECDHE/DHE key exchange is not vulnerable to ROBOT
      - RSA kex should be disabled regardless of ROBOT — it lacks
        forward secrecy, making it a security liability independently

    We flag vulnerable=False only when we can confirm the server
    rejected all RSA kex cipher suites.

References:
    https://nvd.nist.gov/vuln/detail/CVE-2017-17382
    https://robotattack.org
    https://www.bleichenbacher.org/
"""

import socket
import struct
import time

from vuln_sweep.checks.base import (
    CheckResult,
    _tcp_connect,
    _read_response,
    _parse_server_hello_cipher,
    _build_tls_client_hello,
    _run_openssl,
    openssl_available,
    make_vulnerable,
    make_clean,
    make_inconclusive,
)


# ─────────────────────────────────────────────
# Constants
# ─────────────────────────────────────────────

CVE  = "CVE-2017-17382"
NAME = "ROBOT"

# RSA key exchange cipher suite codes (2-byte big-endian)
# These are the cipher codes that indicate RSA key exchange in TLS.
# Sources: IANA TLS Cipher Suite Registry
RSA_KEX_CODES: set[int] = {
    0x0001,   # TLS_RSA_WITH_NULL_MD5
    0x0002,   # TLS_RSA_WITH_NULL_SHA
    0x0004,   # TLS_RSA_WITH_RC4_128_MD5
    0x0005,   # TLS_RSA_WITH_RC4_128_SHA
    0x000a,   # TLS_RSA_WITH_3DES_EDE_CBC_SHA
    0x002f,   # TLS_RSA_WITH_AES_128_CBC_SHA
    0x0035,   # TLS_RSA_WITH_AES_256_CBC_SHA
    0x003c,   # TLS_RSA_WITH_AES_128_CBC_SHA256
    0x003d,   # TLS_RSA_WITH_AES_256_CBC_SHA256
    0x009c,   # TLS_RSA_WITH_AES_128_GCM_SHA256
    0x009d,   # TLS_RSA_WITH_AES_256_GCM_SHA384
    0x00ba,   # TLS_RSA_WITH_CAMELLIA_128_CBC_SHA256
    0x00c0,   # TLS_RSA_WITH_CAMELLIA_256_CBC_SHA256
}

# RSA-preferring cipher suites to advertise in ClientHello
# Ordered so common ones appear first, maximising match probability
_RSA_PROBE_CIPHERS: bytes = bytes.fromhex(
    "002f"   # TLS_RSA_WITH_AES_128_CBC_SHA
    "0035"   # TLS_RSA_WITH_AES_256_CBC_SHA
    "009c"   # TLS_RSA_WITH_AES_128_GCM_SHA256
    "009d"   # TLS_RSA_WITH_AES_256_GCM_SHA384
    "003c"   # TLS_RSA_WITH_AES_128_CBC_SHA256
    "003d"   # TLS_RSA_WITH_AES_256_CBC_SHA256
    "000a"   # TLS_RSA_WITH_3DES_EDE_CBC_SHA
    "0005"   # TLS_RSA_WITH_RC4_128_SHA
)

# Non-RSA (ephemeral) cipher codes — confirm server prefers forward secrecy
ECDHE_DHE_CODES: set[int] = {
    0xc02b, 0xc02c, 0xc02f, 0xc030,   # ECDHE-ECDSA / ECDHE-RSA AES-GCM
    0xc013, 0xc014, 0xc009, 0xc00a,   # ECDHE-RSA / ECDHE-ECDSA AES-CBC
    0x009e, 0x009f,                    # DHE-RSA AES-GCM
    0x0033, 0x0039,                    # DHE-RSA AES-CBC
    0xcca8, 0xcca9, 0xccaa,           # ChaCha20-Poly1305
    0x1301, 0x1302, 0x1303,           # TLS 1.3 AEAD suites
}


# ─────────────────────────────────────────────
# Check entry point
# ─────────────────────────────────────────────

def check(host: str, port: int, timeout: int) -> CheckResult:
    """
    Check whether the host uses RSA key exchange (ROBOT exposure).

    Detection stages:
      1. Raw ServerHello cipher code parsing.
      2. openssl s_client -cipher RSA fallback.

    Returns:
        CheckResult with vulnerable=True  if RSA kex cipher negotiated.
                             vulnerable=False if only ECDHE/DHE negotiated.
                             vulnerable=None  if check could not complete.
    """
    try:
        return _do_check(host, port, timeout)
    except Exception as e:
        return make_inconclusive(CVE, NAME, f"Unexpected error: {e}")


def _do_check(host: str, port: int, timeout: int) -> CheckResult:

    # ── Stage 1: Raw ServerHello cipher detection ─────────────
    stage1_result = _probe_raw_server_hello(host, port, timeout)

    if stage1_result is not None:
        cipher_code, cipher_name = stage1_result
        return _build_result_from_code(cipher_code, cipher_name)

    # ── Stage 2: openssl fallback ─────────────────────────────
    if openssl_available():
        return _probe_openssl_rsa(host, port, timeout)

    # Neither stage produced a result
    return make_inconclusive(
        CVE, NAME,
        "Could not parse ServerHello and openssl binary is not available. "
        "Install openssl and re-run for a definitive result.",
    )


# ─────────────────────────────────────────────
# Stage 1 — Raw ServerHello cipher detection
# ─────────────────────────────────────────────

def _probe_raw_server_hello(
    host:    str,
    port:    int,
    timeout: int,
) -> tuple[int, str] | None:
    """
    Connect, send a ClientHello advertising RSA kex ciphers, and
    parse the ServerHello to get the negotiated cipher code.

    Returns:
        (cipher_code, cipher_name) if ServerHello was parsed.
        None if the connection failed or ServerHello was not seen.
    """
    try:
        sock = _tcp_connect(host, port, timeout)
    except Exception:
        return None

    try:
        # Send ClientHello preferring RSA key exchange ciphers
        hello = _build_tls_client_hello(
            version = b"\x03\x03",          # TLS 1.2
            ciphers = _RSA_PROBE_CIPHERS,
        )
        sock.send(hello)

        # Read server response — looking for ServerHello
        buf      = b""
        deadline = time.time() + timeout

        while time.time() < deadline:
            try:
                chunk = sock.recv(4096)
                if not chunk:
                    break
                buf += chunk

                # Try to parse ServerHello cipher code
                cipher_code = _parse_server_hello_cipher(buf)
                if cipher_code is not None:
                    sock.close()
                    cipher_name = _cipher_name(cipher_code)
                    return (cipher_code, cipher_name)

                # If we have a lot of data with no ServerHello,
                # server may have sent an alert — stop waiting
                if len(buf) > 16384:
                    break

            except socket.timeout:
                break
            except OSError:
                break

        sock.close()
        return None

    except Exception:
        try:
            sock.close()
        except Exception:
            pass
        return None


def _build_result_from_code(
    cipher_code: int,
    cipher_name: str,
) -> CheckResult:
    """
    Determine vulnerability from the negotiated cipher code and
    return the appropriate CheckResult.
    """
    if cipher_code in RSA_KEX_CODES:
        return make_vulnerable(
            CVE, NAME,
            f"Server negotiated RSA key exchange cipher "
            f"0x{cipher_code:04x} ({cipher_name}). "
            "RSA key exchange exposes the server to Bleichenbacher's "
            "padding oracle attack (ROBOT). An adaptive attacker can "
            "submit ~1M crafted RSA ciphertexts to decrypt any session "
            "or forge RSA signatures without the private key. "
            "Disable all RSA key exchange ciphersuites and use only "
            "ECDHE or DHE (forward-secret) ciphersuites.",
        )

    if cipher_code in ECDHE_DHE_CODES:
        return make_clean(
            CVE, NAME,
            f"Server negotiated ephemeral key exchange cipher "
            f"0x{cipher_code:04x} ({cipher_name}) — "
            "ECDHE/DHE ciphers are not vulnerable to ROBOT. "
            "Server correctly prefers forward-secret key exchange.",
        )

    # Unknown cipher code — inconclusive
    return make_inconclusive(
        CVE, NAME,
        f"Server negotiated unknown cipher code 0x{cipher_code:04x}. "
        "Cannot determine whether RSA key exchange is in use. "
        "Review cipher configuration manually.",
        detail=f"Negotiated cipher: 0x{cipher_code:04x}",
    )


# ─────────────────────────────────────────────
# Stage 2 — openssl s_client -cipher RSA
# ─────────────────────────────────────────────

def _probe_openssl_rsa(
    host:    str,
    port:    int,
    timeout: int,
) -> CheckResult:
    """
    Use openssl s_client to check whether RSA key exchange ciphers
    are accepted. Used as a fallback when Stage 1 cannot parse a
    ServerHello (e.g. connection reset by load balancer mid-read).
    """
    # Attempt connection with RSA-only cipher filter
    rc, stdout, stderr = _run_openssl(
        ["s_client",
         "-tls1_2",
         "-cipher", "RSA",
         "-connect", f"{host}:{port}",
         "-brief"],
        timeout=timeout,
    )
    combined = (stdout + stderr).decode("utf-8", errors="replace")

    # Explicitly rejected RSA ciphers
    if (
        "no cipher can be selected" in combined
        or "no ciphers available"   in combined
        or "sslv3 alert handshake"  in combined.lower()
        or "tlsv1 alert"            in combined.lower()
    ):
        # Confirm by trying ECDHE
        ecdhe_accepted = _confirm_ecdhe_accepted(host, port, timeout)
        if ecdhe_accepted:
            return make_clean(
                CVE, NAME,
                "Server rejected all RSA key exchange ciphers and accepted "
                "ECDHE key exchange. Not vulnerable to ROBOT. "
                "Server correctly enforces forward-secret key exchange.",
            )
        return make_inconclusive(
            CVE, NAME,
            "RSA ciphers rejected but ECDHE confirmation also failed. "
            "Server may have an unusual cipher configuration. "
            "Review manually.",
        )

    # RSA cipher was accepted
    if rc == 0 or "Cipher is" in combined or "CONNECTED" in combined:
        # Extract cipher name from output if possible
        cipher_name = _extract_cipher_from_openssl_output(combined)
        return make_vulnerable(
            CVE, NAME,
            f"Server accepted RSA key exchange cipher"
            f"{f' ({cipher_name})' if cipher_name else ''} "
            "via openssl s_client. RSA key exchange exposes the server "
            "to Bleichenbacher padding oracle attacks (ROBOT). "
            "An adaptive attacker can decrypt sessions or forge signatures "
            "without the private key in ~1M adaptive queries. "
            "Disable all RSA key exchange ciphersuites.",
        )

    # Could not determine — likely a connection failure
    return make_inconclusive(
        CVE, NAME,
        "openssl s_client RSA probe produced an indeterminate result. "
        "Connection may have been reset or the server requires SNI. "
        f"openssl exit code: {rc}.",
    )


def _confirm_ecdhe_accepted(
    host:    str,
    port:    int,
    timeout: int,
) -> bool:
    """
    Confirm the server accepts ECDHE ciphers.
    Used to validate a clean result when RSA was rejected.
    """
    rc, stdout, stderr = _run_openssl(
        ["s_client",
         "-tls1_2",
         "-cipher", "ECDHE",
         "-connect", f"{host}:{port}",
         "-brief"],
        timeout=timeout,
    )
    combined = (stdout + stderr).decode("utf-8", errors="replace")
    return rc == 0 or "Cipher is" in combined or "CONNECTED" in combined


# ─────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────

def _cipher_name(code: int) -> str:
    """
    Return the IANA cipher suite name for a given 2-byte code.
    Returns a hex string if the code is not in the lookup table.
    """
    _NAMES: dict[int, str] = {
        0x002f: "TLS_RSA_WITH_AES_128_CBC_SHA",
        0x0035: "TLS_RSA_WITH_AES_256_CBC_SHA",
        0x009c: "TLS_RSA_WITH_AES_128_GCM_SHA256",
        0x009d: "TLS_RSA_WITH_AES_256_GCM_SHA384",
        0x003c: "TLS_RSA_WITH_AES_128_CBC_SHA256",
        0x003d: "TLS_RSA_WITH_AES_256_CBC_SHA256",
        0x000a: "TLS_RSA_WITH_3DES_EDE_CBC_SHA",
        0x0005: "TLS_RSA_WITH_RC4_128_SHA",
        0x0004: "TLS_RSA_WITH_RC4_128_MD5",
        0xc02b: "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
        0xc02c: "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
        0xc02f: "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
        0xc030: "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
        0xc013: "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA",
        0xc014: "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA",
        0xcca8: "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256",
        0x1301: "TLS_AES_128_GCM_SHA256",
        0x1302: "TLS_AES_256_GCM_SHA384",
        0x1303: "TLS_CHACHA20_POLY1305_SHA256",
    }
    return _NAMES.get(code, f"0x{code:04x}")


def _extract_cipher_from_openssl_output(output: str) -> str:
    """
    Extract the negotiated cipher name from openssl s_client output.
    Returns empty string if not found.

    openssl s_client outputs lines like:
        Cipher    : AES256-SHA
    or
        New, TLSv1.2, Cipher is AES256-SHA
    """
    for line in output.splitlines():
        line = line.strip()
        if line.startswith("Cipher") and ":" in line:
            parts = line.split(":", 1)
            if len(parts) == 2:
                cipher = parts[1].strip()
                if cipher and cipher != "(NONE)":
                    return cipher
        if "Cipher is" in line:
            idx = line.index("Cipher is") + len("Cipher is")
            cipher = line[idx:].strip()
            if cipher and cipher != "(NONE)":
                return cipher
    return ""