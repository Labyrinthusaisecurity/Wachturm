#!/usr/bin/env python3
"""
vuln_sweep/report/console.py
━━━━━━━━━━━━━━━━━━━━━━━━━━━
Console output formatter for vuln-sweep.

Renders VulnResult objects as coloured terminal output.
Called by report/__init__.py dispatch_report() after every host sweep.

Public API:
  write(result, config) → None
"""

import os
import sys
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from vuln_sweep.scanner     import VulnResult
    from vuln_sweep.checks.base import CheckResult


# ─────────────────────────────────────────────
# ANSI colour helpers
# ─────────────────────────────────────────────

USE_COLOR: bool = sys.stdout.isatty() and os.name != "nt"


def _c(code: str, text: str) -> str:
    return f"\033[{code}m{text}\033[0m" if USE_COLOR else text


RED     = lambda t: _c("31;1", t)
GREEN   = lambda t: _c("32;1", t)
YELLOW  = lambda t: _c("33;1", t)
CYAN    = lambda t: _c("36;1", t)
MAGENTA = lambda t: _c("35;1", t)
BOLD    = lambda t: _c("1",    t)
DIM     = lambda t: _c("2",    t)


def _ansi_overhead(s: str) -> int:
    """Count invisible ANSI bytes for ljust() compensation."""
    if not USE_COLOR:
        return 0
    count, i = 0, 0
    while i < len(s):
        if s[i] == "\033" and i + 1 < len(s) and s[i + 1] == "[":
            j = i + 2
            while j < len(s) and not s[j].isalpha():
                j += 1
            count += (j - i + 1)
            i = j + 1
        else:
            i += 1
    return count


def _grade_color(grade: str) -> str:
    return {
        "A": GREEN(grade),
        "B": CYAN(grade),
        "C": YELLOW(grade),
        "F": RED(grade),
    }.get(grade, grade)


def _status_color(vulnerable) -> str:
    if vulnerable is True:  return RED("VULNERABLE")
    if vulnerable is False: return GREEN("NOT VULNERABLE")
    return YELLOW("INCONCLUSIVE")


# ─────────────────────────────────────────────
# Public write function
# ─────────────────────────────────────────────

def write(
    result: "VulnResult",
    config: dict,
) -> None:
    """
    Render a VulnResult to stdout.

    Normal mode:  one line per CVE check with status and duration.
    Verbose mode: adds detail text for VULNERABLE and ERROR results,
                  or all results when config["verbose"] is True.

    Args:
        result: VulnResult from scanner.run_sweep().
        config: Full config dict. Reads config["verbose"].
    """
    verbose = config.get("verbose", False)

    _print_host_header(result)
    _print_checks(result.checks, verbose)
    _print_host_footer(result)


# ─────────────────────────────────────────────
# Host header
# ─────────────────────────────────────────────

def _print_host_header(result: "VulnResult") -> None:
    """Print the per-host header line with grade and scan time."""
    host_str    = f"{result.host}:{result.port}"
    grade_str   = _grade_color(result.grade)
    duration    = DIM(f"{result.duration_ms:.0f}ms")
    scan_time   = DIM(
        result.scan_time[:19].replace("T", " ") + " UTC"
        if result.scan_time else ""
    )

    pad = 8 + _ansi_overhead(grade_str)

    print()
    print(f"  {'─' * 60}")
    print(
        f"  {BOLD(host_str.ljust(36))}"
        f"  Grade {grade_str.ljust(pad)}"
        f"  {duration}"
        f"  {scan_time}"
    )
    print(f"  {'─' * 60}")


# ─────────────────────────────────────────────
# Check rows
# ─────────────────────────────────────────────

def _print_checks(
    checks:  list["CheckResult"],
    verbose: bool,
) -> None:
    """Print one row per CVE check, with optional detail blocks."""
    for check in checks:
        _print_check_row(check, verbose)


def _print_check_row(
    check:   "CheckResult",
    verbose: bool,
) -> None:
    """
    Print a single check result row.

    Format:
      {emoji}  {CVE}              {NAME}      {STATUS}      {duration}

    Followed by an indented detail block when:
      - verbose=True (all checks)
      - check.vulnerable is True (always expand findings)
      - check.error is set (always expand errors)
    """
    # ── Summary line ─────────────────────────────────────────
    icon    = _icon(check)
    cve     = DIM(check.cve.ljust(17))
    name    = BOLD(check.name.ljust(10))
    status  = _error_status(check) if check.error else _status_color(check.vulnerable)
    dur     = DIM(f"{check.duration_ms:.0f}ms")

    pad = 22 + _ansi_overhead(status)
    print(f"  {icon}  {cve}  {name}  {status.ljust(pad)}  {dur}")

    # ── Detail block ─────────────────────────────────────────
    should_expand = (
        verbose
        or check.vulnerable is True
        or bool(check.error)
    )

    if not should_expand:
        return

    print()

    if check.error:
        _print_indented(RED("✗") + "  " + check.error)
    elif check.detail:
        _print_detail_block(check)

    print()


def _print_detail_block(check: "CheckResult") -> None:
    """
    Print the detail text for a check result, word-wrapped at 64 chars.
    Vulnerable findings get a remediation label prefix.
    """
    if check.vulnerable is True:
        print(f"       {RED('▶')}  {BOLD('Finding:')}")

    # Word-wrap detail at 64 chars
    words = check.detail.split()
    line  = ""

    for word in words:
        if len(line) + len(word) + 1 > 64:
            print(f"       {DIM(line)}")
            line = word
        else:
            line = (line + " " + word).strip()

    if line:
        print(f"       {DIM(line)}")

    # Remediation hint for vulnerable results
    if check.vulnerable is True:
        _print_remediation_hint(check.name)


def _print_remediation_hint(check_name: str) -> None:
    """
    Print a one-line remediation pointer below the finding detail.
    Avoids duplicating the full remediation text from checks/__init__.py
    — that lives in the HTML report. Console gets a concise pointer.
    """
    hints: dict[str, str] = {
        "Heartbleed": "→ Upgrade OpenSSL ≥ 1.0.1g. Rotate private keys. Reissue certs.",
        "POODLE":     "→ Disable SSLv3. Minimum protocol: TLS 1.2.",
        "BEAST":      "→ Disable TLS 1.0. Use TLS 1.2+ with AEAD ciphers.",
        "ROBOT":      "→ Disable RSA key exchange. Use ECDHE/DHE only.",
        "DROWN":      "→ Disable SSLv2 and EXPORT ciphers on all servers sharing this key.",
        "LUCKY13":    "→ Prefer AEAD (AES-GCM, ChaCha20-Poly1305). Disable CBC suites.",
    }
    hint = hints.get(check_name, "→ Review TLS configuration.")
    print(f"\n       {CYAN(hint)}")


# ─────────────────────────────────────────────
# Host footer
# ─────────────────────────────────────────────

def _print_host_footer(result: "VulnResult") -> None:
    """
    Print the per-host summary counts footer.
    Shows counts for each outcome category.
    """
    vuln   = result.vuln_count
    clean  = result.clean_count
    incon  = result.inconclusive_count
    errors = result.error_count

    parts = []
    if vuln:   parts.append(RED(f"{vuln} VULNERABLE"))
    if clean:  parts.append(GREEN(f"{clean} CLEAN"))
    if incon:  parts.append(YELLOW(f"{incon} INCONCLUSIVE"))
    if errors: parts.append(MAGENTA(f"{errors} ERROR"))

    print(f"  {'─' * 60}")
    print(f"  {' · '.join(parts)}")
    print()


# ─────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────

def _icon(check: "CheckResult") -> str:
    """Return the emoji icon for a check result."""
    if check.error:              return "⚫"
    if check.vulnerable is True: return "🔴"
    if check.vulnerable is False:return "🟢"
    return "🟡"


def _error_status(check: "CheckResult") -> str:
    """Return a coloured ERROR status string."""
    return MAGENTA("ERROR")


def _print_indented(text: str, indent: int = 7) -> None:
    """Print text with a fixed left indent."""
    prefix = " " * indent
    print(f"{prefix}{text}")