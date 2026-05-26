#!/usr/bin/env python3
"""
vuln_sweep/checks/base.py
━━━━━━━━━━━━━━━━━━━━━━━━
Shared foundation for all CVE check modules.

Provides:
  CheckResult          — dataclass returned by every check function
  _tcp_connect()       — raw TCP socket with timeout
  _run_openssl()       — subprocess wrapper for openssl s_client
  _tls_probe_protocol()— handshake probe for a specific TLS/SSL version
  _tls_probe_cipher()  — handshake probe for a specific cipher suite
  _read_response()     — socket drain with timeout
  _drain_server_hello()— read until ServerHelloDone or timeout

Rules for check functions:
  • Signature:  check(host: str, port: int, timeout: int) → CheckResult
  • Never raise — catch all exceptions and set CheckResult.error
  • Set vulnerable=True  only when exploitation is confirmed
  • Set vulnerable=False only when server actively rejected the probe
  • Set vulnerable=None  when result is inconclusive (timeout, partial)
  • Always set cve and name fields matching the canonical values
    in checks/__init__.py CVE_MAP and NAME_MAP
"""

import os
import socket
import ssl
import struct
import subprocess
import sys
from dataclasses import dataclass, field
from typing import Optional


# ─────────────────────────────────────────────
# CheckResult dataclass
# ─────────────────────────────────────────────

@dataclass
class CheckResult:
    """
    The result of one CVE check against one host.

    Every check function returns exactly one CheckResult.
    Never raises — errors are captured in the error field.

    Fields:
        cve:          CVE ID string  e.g. "CVE-2014-0160"
        name:         Display name   e.g. "Heartbleed"
        vulnerable:   True  = confirmed vulnerable
                      False = confirmed not vulnerable
                      None  = inconclusive / error
        detail:       Human-readable explanation of the finding.
                      Always set when vulnerable is True or False.
        error:        Error message if check could not complete.
                      Set when vulnerable is None due to failure.
        duration_ms:  Wall-clock time for this check in milliseconds.
                      Set by scanner._run_check() after the check returns.
    """
    cve:         str
    name:        str
    vulnerable:  Optional[bool] = None
    detail:      str            = ""
    error:       str            = ""
    duration_ms: float          = 0.0

    # ── Computed properties ───────────────────────────────────

    @property
    def status(self) -> str:
        """Plain text status for JSON output and logging."""
        if self.error:              return "ERROR"
        if self.vulnerable is True: return "VULNERABLE"
        if self.vulnerable is False:return "NOT_VULNERABLE"
        return "INCONCLUSIVE"

    @property
    def emoji(self) -> str:
        if self.error:              return "⚫"
        if self.vulnerable is True: return "🔴"
        if self.vulnerable is False:return "🟢"
        return "🟡"

    @property
    def color_hex(self) -> str:
        """Hex colour for HTML report cells."""
        if self.error:              return "#888888"
        if self.vulnerable is True: return "#ff4444"
        if self.vulnerable is False:return "#00ff88"
        return "#ffb800"


# ─────────────────────────────────────────────
# TCP socket helper
# ─────────────────────────────────────────────

def _tcp_connect(host: str, port: int, timeout: int) -> socket.socket:
    """
    Open a raw TCP socket to host:port with timeout.
    Raises the underlying socket exception on failure —
    callers are responsible for catching it.

    Args:
        host:    Hostname or IP address.
        port:    TCP port number.
        timeout: Socket timeout in seconds.

    Returns:
        Connected socket.socket — caller must close it.

    Raises:
        socket.timeout, socket.gaierror, ConnectionRefusedError, OSError
    """
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    sock.connect((host, port))
    return sock


# ─────────────────────────────────────────────
# OpenSSL subprocess wrapper
# ─────────────────────────────────────────────

def _run_openssl(
    args:       list[str],
    input_data: bytes = b"Q\n",
    timeout:    int   = 10,
) -> tuple[int, bytes, bytes]:
    """
    Run openssl with the given arguments and return
    (returncode, stdout, stderr).

    Sends input_data to stdin — defaults to "Q\\n" which
    causes openssl s_client to close the connection cleanly.

    Never raises — returns (-1, b"", error_bytes) on failure.

    Args:
        args:       Arguments to pass after "openssl" binary.
        input_data: Data to write to stdin.
        timeout:    Subprocess timeout in seconds.

    Returns:
        (returncode, stdout, stderr) tuple.
    """
    try:
        result = subprocess.run(
            ["openssl"] + args,
            input          = input_data,
            capture_output = True,
            timeout        = timeout,
        )
        return result.returncode, result.stdout, result.stderr
    except subprocess.TimeoutExpired:
        return -1, b"", b"openssl subprocess timed out"
    except FileNotFoundError:
        return -1, b"", b"openssl binary not found in PATH"
    except Exception as e:
        return -1, b"", str(e).encode()


def openssl_available() -> bool:
    """
    Return True if the openssl binary is available in PATH.
    Cached after the first call via module-level variable.
    """
    global _OPENSSL_AVAILABLE
    if _OPENSSL_AVAILABLE is None:
        rc, _, _ = _run_openssl(["version"], timeout=3)
        _OPENSSL_AVAILABLE = (rc == 0)
    return _OPENSSL_AVAILABLE

_OPENSSL_AVAILABLE: Optional[bool] = None


# ─────────────────────────────────────────────
# TLS protocol handshake probes
# ─────────────────────────────────────────────

def _tls_probe_protocol(
    host:       str,
    port:       int,
    proto_flag: str,
    timeout:    int = 6,
) -> bool:
    """
    Attempt an openssl s_client handshake with a specific protocol flag.
    Returns True if the server accepted the protocol (handshake succeeded).

    Args:
        host:       Target hostname.
        port:       TCP port.
        proto_flag: openssl flag e.g. "-ssl3", "-tls1", "-tls1_2", "-tls1_3"
        timeout:    Subprocess timeout in seconds.

    Returns:
        True if handshake succeeded, False otherwise.
    """
    rc, stdout, stderr = _run_openssl(
        ["s_client", proto_flag,
         "-connect", f"{host}:{port}",
         "-brief"],
        timeout=timeout,
    )
    combined = (stdout + stderr).decode("utf-8", errors="replace")

    return (
        rc == 0
        or "CONNECTED"           in combined
        or "Cipher is"           in combined
        or "Protocol  :"         in combined
        or "New, TLS"            in combined
    )


def _tls_probe_cipher(
    host:        str,
    port:        int,
    cipher:      str,
    proto_flag:  str = "-tls1_2",
    timeout:     int = 6,
) -> bool:
    """
    Attempt an openssl s_client handshake requesting a specific cipher.
    Returns True if the server accepted the cipher.

    Args:
        host:       Target hostname.
        port:       TCP port.
        cipher:     OpenSSL cipher name e.g. "RC4-SHA", "AES128-SHA"
        proto_flag: Protocol version flag e.g. "-tls1", "-tls1_2"
        timeout:    Subprocess timeout in seconds.

    Returns:
        True if cipher was accepted, False otherwise.
    """
    rc, stdout, stderr = _run_openssl(
        ["s_client", proto_flag,
         "-cipher", cipher,
         "-connect", f"{host}:{port}",
         "-brief"],
        timeout=timeout,
    )
    combined = (stdout + stderr).decode("utf-8", errors="replace")

    return (
        rc == 0
        or cipher     in combined
        or "Cipher is" in combined
    )


# ─────────────────────────────────────────────
# Raw socket helpers
# ─────────────────────────────────────────────

def _read_response(
    sock:       socket.socket,
    timeout:    int   = 6,
    max_bytes:  int   = 16384,
) -> bytes:
    """
    Read from a socket until it closes, times out, or max_bytes reached.
    Returns whatever was received — may be empty if nothing arrived.

    Args:
        sock:      Connected socket to read from.
        timeout:   Read timeout in seconds.
        max_bytes: Maximum bytes to read before stopping.

    Returns:
        bytes received from the socket.
    """
    import time
    sock.settimeout(timeout)
    buf      = b""
    deadline = time.time() + timeout

    while time.time() < deadline and len(buf) < max_bytes:
        try:
            chunk = sock.recv(4096)
            if not chunk:
                break
            buf += chunk
        except socket.timeout:
            break
        except OSError:
            break

    return buf


def _drain_server_hello(
    sock:    socket.socket,
    timeout: int = 6,
) -> bool:
    """
    Read TLS records from sock until ServerHelloDone (handshake type 0x0e)
    is seen or timeout is reached.

    Used by Heartbleed probe to wait for the server to finish its
    handshake flight before sending the malformed HeartbeatRequest.

    Args:
        sock:    Socket mid-handshake (ClientHello already sent).
        timeout: Read timeout in seconds.

    Returns:
        True if ServerHelloDone was observed, False if timed out.
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

            # Scan for ServerHelloDone (handshake type 14 = 0x0e)
            # TLS record structure: type(1) version(2) length(2) body
            i = 0
            while i < len(buf) - 5:
                if buf[i] == 0x16:          # handshake record
                    rec_len = struct.unpack("!H", buf[i+3:i+5])[0]
                    rec_end = i + 5 + rec_len
                    if len(buf) >= rec_end:
                        body = buf[i+5:rec_end]
                        if body and body[0] == 0x0e:
                            return True
                        i = rec_end
                    else:
                        break               # need more data
                else:
                    i += 1
        except socket.timeout:
            break
        except OSError:
            break

    # ServerHelloDone not seen — may still be able to send heartbeat
    return False


def _parse_server_hello_cipher(buf: bytes) -> Optional[int]:
    """
    Scan a bytes buffer for a TLS ServerHello record and extract
    the negotiated cipher suite code (2-byte big-endian int).

    Returns the cipher code as an int, or None if not found.

    Used by ROBOT check to detect RSA key exchange without
    completing the full handshake.
    """
    i = 0
    while i < len(buf) - 5:
        if buf[i] == 0x16 and buf[i+1:i+3] in (b"\x03\x01",
                                                  b"\x03\x02",
                                                  b"\x03\x03"):
            rec_len = struct.unpack("!H", buf[i+3:i+5])[0]
            rec_end = i + 5 + rec_len
            if len(buf) >= rec_end:
                body = buf[i+5:rec_end]
                # HandshakeType 0x02 = ServerHello
                # ServerHello layout:
                #   type(1) len(3) version(2) random(32) sid_len(1)
                #   sid(sid_len) cipher(2) compression(1)
                if len(body) >= 40 and body[0] == 0x02:
                    sid_len   = body[38]
                    cipher_off = 39 + sid_len
                    if len(body) >= cipher_off + 2:
                        return struct.unpack(
                            "!H", body[cipher_off:cipher_off+2]
                        )[0]
                i = rec_end
            else:
                break
        else:
            i += 1
    return None


# ─────────────────────────────────────────────
# Packet builders
# ─────────────────────────────────────────────

def _build_tls_client_hello(
    version:  bytes = b"\x03\x01",
    ciphers:  bytes = None,
) -> bytes:
    """
    Build a minimal TLS ClientHello record.

    Args:
        version: TLS version bytes e.g. b"\\x03\\x01" (TLS 1.0)
                                        b"\\x03\\x03" (TLS 1.2)
        ciphers: Raw cipher suite bytes (2 bytes per suite).
                 Defaults to RSA + AES + RC4 suites.

    Returns:
        Raw bytes of a complete TLS record ready to send.
    """
    if ciphers is None:
        # TLS_RSA_WITH_AES_128_CBC_SHA + TLS_RSA_WITH_RC4_128_SHA
        # + TLS_RSA_WITH_AES_256_CBC_SHA + TLS_RSA_WITH_3DES_EDE_CBC_SHA
        ciphers = bytes.fromhex("002f" "0005" "0035" "000a")

    random_bytes = os.urandom(32)
    extensions   = b""

    hello_body = (
        version                                      # client version
        + random_bytes                               # random
        + b"\x00"                                    # session id length = 0
        + struct.pack("!H", len(ciphers)) + ciphers  # cipher suites
        + b"\x01\x00"                                # compression: null
        + struct.pack("!H", len(extensions))         # extensions length
        + extensions
    )

    # Handshake header: type=ClientHello(1) + 3-byte length
    hs_body = (
        b"\x01"
        + struct.pack("!I", len(hello_body))[1:]     # 3-byte length
        + hello_body
    )

    # TLS record: ContentType=Handshake(22) + version + length
    return b"\x16\x03\x01" + struct.pack("!H", len(hs_body)) + hs_body


def _build_sslv2_client_hello(
    cipher_specs: bytes = None,
) -> bytes:
    """
    Build an SSLv2 CLIENT-HELLO message.
    Used by DROWN check to probe for SSLv2 support.

    Args:
        cipher_specs: 3-byte cipher specs. Defaults to RC4 + EXPORT.

    Returns:
        Raw bytes of an SSLv2 CLIENT-HELLO ready to send.
    """
    if cipher_specs is None:
        # SSL_CK_RC4_128_WITH_MD5      = 0x010080
        # SSL_CK_RC2_128_CBC_WITH_MD5  = 0x030080
        # SSL_CK_RC4_128_EXPORT40      = 0x020080  ← export cipher
        cipher_specs = bytes.fromhex("010080" "030080" "020080")

    challenge = os.urandom(16)
    body = (
        b"\x01"                                       # MSG-CLIENT-HELLO
        + b"\x00\x02"                                 # version: SSLv2
        + struct.pack("!H", len(cipher_specs))        # cipher specs length
        + b"\x00\x00"                                 # session id length
        + struct.pack("!H", len(challenge))           # challenge length
        + cipher_specs
        + challenge
    )

    # SSLv2 2-byte record header: MSB set for no-padding, rest = length
    length = len(body)
    header = struct.pack("!H", 0x8000 | length)
    return header + body


# ─────────────────────────────────────────────
# Result constructors
# ─────────────────────────────────────────────

def make_vulnerable(
    cve:    str,
    name:   str,
    detail: str,
) -> CheckResult:
    """Construct a confirmed-vulnerable CheckResult."""
    return CheckResult(
        cve        = cve,
        name       = name,
        vulnerable = True,
        detail     = detail,
    )


def make_clean(
    cve:    str,
    name:   str,
    detail: str,
) -> CheckResult:
    """Construct a confirmed-clean CheckResult."""
    return CheckResult(
        cve        = cve,
        name       = name,
        vulnerable = False,
        detail     = detail,
    )


def make_inconclusive(
    cve:    str,
    name:   str,
    error:  str,
    detail: str = "",
) -> CheckResult:
    """Construct an inconclusive / errored CheckResult."""
    return CheckResult(
        cve        = cve,
        name       = name,
        vulnerable = None,
        detail     = detail,
        error      = error,
    )


__all__ = [
    # Dataclass
    "CheckResult",

    # Socket helpers
    "_tcp_connect",
    "_read_response",
    "_drain_server_hello",
    "_parse_server_hello_cipher",

    # OpenSSL helpers
    "_run_openssl",
    "_tls_probe_protocol",
    "_tls_probe_cipher",
    "openssl_available",

    # Packet builders
    "_build_tls_client_hello",
    "_build_sslv2_client_hello",

    # Result constructors
    "make_vulnerable",
    "make_clean",
    "make_inconclusive",
]