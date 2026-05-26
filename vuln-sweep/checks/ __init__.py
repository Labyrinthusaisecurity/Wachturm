#!/usr/bin/env python3
"""
vuln_sweep/checks/__init__.py
━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Check registry — the single place that knows about every CVE check.

Adding a new check requires exactly two changes:
  1. Create vuln_sweep/checks/newcheck.py with a check() function
  2. Add one entry to ALL_CHECKS and SUPPORTED_CVES below

Nothing else in the codebase needs to change.

Public API:
  ALL_CHECKS      — dict mapping check name → check function
  SUPPORTED_CVES  — list of CVE IDs the suite can detect
  CVE_MAP         — dict mapping check name → CVE ID
  NAME_MAP        — dict mapping check name → display name
  dispatch(name, host, port, timeout) → CheckResult
"""

from vuln_sweep.checks.heartbleed import check as _check_heartbleed
from vuln_sweep.checks.poodle     import check as _check_poodle
from vuln_sweep.checks.beast      import check as _check_beast
from vuln_sweep.checks.robot      import check as _check_robot
from vuln_sweep.checks.drown      import check as _check_drown
from vuln_sweep.checks.lucky13    import check as _check_lucky13
from vuln_sweep.checks.base       import CheckResult


# ─────────────────────────────────────────────
# Check registry
# ─────────────────────────────────────────────
# Maps canonical check name → check function.
# Order matters — this is the canonical display order.
# All functions have the signature:
#   check(host: str, port: int, timeout: int) → CheckResult

ALL_CHECKS: dict[str, callable] = {
    "heartbleed": _check_heartbleed,
    "poodle":     _check_poodle,
    "beast":      _check_beast,
    "robot":      _check_robot,
    "drown":      _check_drown,
    "lucky13":    _check_lucky13,
}


# ─────────────────────────────────────────────
# CVE metadata
# ─────────────────────────────────────────────

CVE_MAP: dict[str, str] = {
    "heartbleed": "CVE-2014-0160",
    "poodle":     "CVE-2014-3566",
    "beast":      "CVE-2011-3389",
    "robot":      "CVE-2017-17382",
    "drown":      "CVE-2016-0800",
    "lucky13":    "CVE-2013-0169",
}

NAME_MAP: dict[str, str] = {
    "heartbleed": "Heartbleed",
    "poodle":     "POODLE",
    "beast":      "BEAST",
    "robot":      "ROBOT",
    "drown":      "DROWN",
    "lucky13":    "LUCKY13",
}

DESCRIPTION_MAP: dict[str, str] = {
    "heartbleed": (
        "OpenSSL HeartbeatRequest memory disclosure. Sends a malformed "
        "HeartbeatRequest with inflated payload_length and checks whether "
        "the server echoes back memory beyond the actual payload."
    ),
    "poodle": (
        "SSLv3 CBC padding oracle. Checks whether the server accepts SSLv3 "
        "connections. A MITM attacker can decrypt session cookies in ~256 "
        "adaptive requests against CBC ciphers."
    ),
    "beast": (
        "TLS 1.0 CBC IV predictability. Checks whether the server supports "
        "TLS 1.0 and accepts CBC ciphers. A MITM attacker can recover "
        "plaintext via chosen-plaintext IV chaining."
    ),
    "robot": (
        "RSA PKCS#1 v1.5 padding oracle. Checks whether the server negotiates "
        "RSA key exchange, which exposes it to Bleichenbacher adaptive chosen "
        "ciphertext attacks. An attacker can decrypt RSA ciphertexts or forge "
        "signatures without the private key."
    ),
    "drown": (
        "SSLv2 cross-protocol attack. Checks whether the server accepts SSLv2 "
        "connections or EXPORT-grade ciphers. An attacker can use SSLv2 "
        "weaknesses to decrypt TLS sessions sharing the same RSA key."
    ),
    "lucky13": (
        "CBC MAC-then-encrypt timing side-channel. Checks whether the server "
        "accepts CBC ciphers on TLS 1.2 or below. Timing differences in MAC "
        "padding removal allow a MITM to recover plaintext over many requests."
    ),
}

CVSS_MAP: dict[str, str] = {
    "heartbleed": "7.5 HIGH",
    "poodle":     "3.4 LOW",
    "beast":      "3.4 LOW",
    "robot":      "7.5 HIGH",
    "drown":      "5.9 MEDIUM",
    "lucky13":    "5.9 MEDIUM",
}

REMEDIATION_MAP: dict[str, str] = {
    "heartbleed": (
        "Upgrade OpenSSL to 1.0.1g or later. Rotate any private keys and "
        "reissue certificates that may have been exposed. Revoke and replace "
        "all session tokens."
    ),
    "poodle": (
        "Disable SSLv3 entirely. Set SSLProtocol to TLSv1.2 or TLSv1.3 only. "
        "For POODLE-TLS variant: disable TLS 1.0 and 1.1 as well."
    ),
    "beast": (
        "Prefer TLS 1.2+ with AEAD ciphers (AES-GCM, ChaCha20-Poly1305). "
        "Disable TLS 1.0 or configure RC4 as the preferred cipher to mitigate "
        "the IV chaining issue (though RC4 has its own weaknesses)."
    ),
    "robot": (
        "Disable all RSA key exchange ciphersuites. Use only ECDHE or DHE "
        "ciphers which provide forward secrecy. This also mitigates future "
        "Bleichenbacher variants."
    ),
    "drown": (
        "Disable SSLv2 on all servers sharing the same RSA key. Disable "
        "EXPORT-grade ciphers. Consider using separate RSA keys per service "
        "to limit blast radius."
    ),
    "lucky13": (
        "Prefer AEAD ciphers (AES-GCM, ChaCha20-Poly1305) over CBC. "
        "If CBC is required, ensure the TLS implementation includes the "
        "Lucky Thirteen countermeasure (constant-time MAC verification)."
    ),
}

# Flat list of supported CVE IDs in canonical order
SUPPORTED_CVES: list[str] = [CVE_MAP[name] for name in ALL_CHECKS]


# ─────────────────────────────────────────────
# Dispatcher
# ─────────────────────────────────────────────

def dispatch(
    name:    str,
    host:    str,
    port:    int,
    timeout: int,
) -> CheckResult:
    """
    Run a single named check by its canonical name.

    Preferred over calling ALL_CHECKS[name](host, port, timeout)
    directly because it validates the name and returns a clean
    error CheckResult if the name is unknown rather than raising
    a KeyError that callers would have to handle.

    Args:
        name:    Check name (e.g. "heartbleed", "poodle").
        host:    Target hostname or IP.
        port:    TCP port.
        timeout: Socket timeout in seconds.

    Returns:
        CheckResult — always, even if the check name is unknown.
    """
    if name not in ALL_CHECKS:
        return CheckResult(
            cve        = CVE_MAP.get(name, "UNKNOWN"),
            name       = NAME_MAP.get(name, name),
            vulnerable = None,
            detail     = "",
            error      = f"Unknown check '{name}'. "
                         f"Valid checks: {', '.join(ALL_CHECKS)}",
        )
    return ALL_CHECKS[name](host, port, timeout)


# ─────────────────────────────────────────────
# Lookup helpers
# ─────────────────────────────────────────────

def get_cve(name: str) -> str:
    """Return the CVE ID for a check name. Empty string if unknown."""
    return CVE_MAP.get(name, "")


def get_description(name: str) -> str:
    """Return the human-readable description for a check name."""
    return DESCRIPTION_MAP.get(name, "")


def get_remediation(name: str) -> str:
    """Return the remediation guidance for a check name."""
    return REMEDIATION_MAP.get(name, "")


def get_cvss(name: str) -> str:
    """Return the CVSS score string for a check name."""
    return CVSS_MAP.get(name, "")


def check_info(name: str) -> dict:
    """
    Return a complete metadata dict for a check name.
    Useful for report generators that need all metadata at once.

    Returns:
        {
            "name":         "heartbleed",
            "display_name": "Heartbleed",
            "cve":          "CVE-2014-0160",
            "cvss":         "7.5 HIGH",
            "description":  "...",
            "remediation":  "...",
        }
    """
    return {
        "name":         name,
        "display_name": NAME_MAP.get(name, name),
        "cve":          CVE_MAP.get(name, ""),
        "cvss":         CVSS_MAP.get(name, ""),
        "description":  DESCRIPTION_MAP.get(name, ""),
        "remediation":  REMEDIATION_MAP.get(name, ""),
    }


__all__ = [
    "ALL_CHECKS",
    "SUPPORTED_CVES",
    "CVE_MAP",
    "NAME_MAP",
    "DESCRIPTION_MAP",
    "CVSS_MAP",
    "REMEDIATION_MAP",
    "dispatch",
    "get_cve",
    "get_description",
    "get_remediation",
    "get_cvss",
    "check_info",
]