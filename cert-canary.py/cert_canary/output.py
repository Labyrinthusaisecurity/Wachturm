#!/usr/bin/env python3
"""
cert_canary/output.py
━━━━━━━━━━━━━━━━━━━━
All console output, ANSI colour helpers, and formatting.
Nothing in this module does network I/O or modifies config.
It only reads CertInfo objects and writes to stdout/stderr.

Public API:
  print_startup_banner(hosts, config)  — shown once at startup
  print_results(results, verbose)      — shown after every sweep
"""

import os
import sys
from datetime import datetime
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from cert_canary.scanner import CertInfo


# ─────────────────────────────────────────────
# ANSI colour helpers
# ─────────────────────────────────────────────
# Auto-disabled when stdout is not a TTY (cron, systemd, CI)
# or when running on Windows without ANSI support.

USE_COLOR: bool = sys.stdout.isatty() and os.name != "nt"


def _c(code: str, text: str) -> str:
    return f"\033[{code}m{text}\033[0m" if USE_COLOR else text


# Colour functions — each takes a string, returns coloured string
RED     = lambda t: _c("31;1", t)
GREEN   = lambda t: _c("32;1", t)
YELLOW  = lambda t: _c("33;1", t)
CYAN    = lambda t: _c("36;1", t)
BLUE    = lambda t: _c("34;1", t)
MAGENTA = lambda t: _c("35;1", t)
BOLD    = lambda t: _c("1",    t)
DIM     = lambda t: _c("2",    t)
ITALIC  = lambda t: _c("3",    t)


def _grade_color(grade: str, text: str) -> str:
    """Apply the standard colour for a given grade string."""
    return {
        "CRITICAL": RED(text),
        "WARNING":  YELLOW(text),
        "INFO":     CYAN(text),
        "OK":       GREEN(text),
    }.get(grade, text)


# ─────────────────────────────────────────────
# Startup banner
# ─────────────────────────────────────────────

def print_startup_banner(
    hosts:  list[tuple[str, int]],
    config: dict,
) -> None:
    """
    Print the startup banner once when cert-canary launches.
    Shows host count, thread count, configured alert channels,
    threshold settings, and run mode.
    """
    mode = (
        "single sweep" if config.get("once")
        else f"daemon  (every {_fmt_interval(config.get('interval', 3600))})"
    )

    alert_channels = [
        label for label, key in [
            ("Slack",      "slack_webhook"),
            ("Discord",    "discord_webhook"),
            ("PagerDuty",  "pagerduty_key"),
            ("Email",      "smtp"),
            ("Webhook",    "webhook_url"),
        ]
        if config.get(key)
    ]

    t = config.get("thresholds", {})

    print()
    print(f"  {BOLD('🔐 cert-canary')}  {DIM('v1.2.0')}")
    print(f"  {'─' * 50}")
    print(f"  {DIM('Hosts:'):<22} {len(hosts)}")
    print(f"  {DIM('Threads:'):<22} {config.get('threads', 10)}")
    print(f"  {DIM('Timeout:'):<22} {config.get('timeout', 8)}s per host")
    print(f"  {DIM('Mode:'):<22} {mode}")
    print(f"  {DIM('Thresholds:'):<22} "
          f"{RED('critical')} <{t.get('critical', 7)}d  "
          f"{YELLOW('warning')} <{t.get('warning', 30)}d  "
          f"{CYAN('info')} <{t.get('info', 60)}d")
    print(f"  {DIM('Alert channels:'):<22} "
          f"{', '.join(alert_channels) if alert_channels else DIM('console only')}")
    print(f"  {'─' * 50}")
    print()


# ─────────────────────────────────────────────
# Main results table
# ─────────────────────────────────────────────

def print_results(
    results: list["CertInfo"],
    verbose: bool = False,
) -> None:
    """
    Print the scan results table to stdout.

    In normal mode: one line per host with grade and days remaining.
    In verbose mode: expands WARNING/CRITICAL hosts (always) and
    all hosts (when --verbose) with CN, CA, cipher, SANs, and flags.

    Args:
        results: List of CertInfo objects from scanner.sweep()
        verbose: Show full details for every host, not just alerts.
    """
    now = datetime.utcnow().strftime("%Y-%m-%d %H:%M UTC")

    print(f"  {'─' * 62}")
    print(f"  {BOLD('cert-canary')}  {DIM(now)}")
    print(f"  {'─' * 62}")

    for r in results:
        _print_host_row(r, verbose)

    _print_summary_footer(results)


def _print_host_row(r: "CertInfo", verbose: bool) -> None:
    """Print one host — summary line plus optional detail block."""
    host_str = f"{r.host}:{r.port}"
    days_str = _fmt_days(r)

    # ── Summary line ─────────────────────────────────────────
    if r.error:
        status = MAGENTA("ERROR")
    else:
        status = _grade_color(r.grade, r.grade)

    # Pad status for alignment (colour codes add invisible chars)
    print(
        f"  {r.emoji}  {BOLD(host_str.ljust(34))}"
        f"{status.ljust(20 + _ansi_overhead(status))}"
        f"{DIM(days_str)}"
    )

    # ── Detail block ─────────────────────────────────────────
    # Always expanded for CRITICAL/WARNING/errors.
    # Expanded for all hosts in verbose mode.
    should_expand = (
        verbose
        or r.error
        or r.grade in ("CRITICAL", "WARNING")
    )

    if not should_expand:
        return

    print()

    if r.error:
        print(f"       {RED('✗')}  {r.error}")
    else:
        # Core cert fields
        _detail_row("CN",      r.common_name)
        _detail_row("Issuer",  f"{r.issuer_org}  {DIM(f'({r.issuer})')}")
        _detail_row("Valid",   f"{r.not_before}  →  {r.not_after}")
        _detail_row("TLS",     f"{r.tls_version}  {DIM('·')}  {r.cipher}")
        _detail_row("Serial",  DIM(r.serial[:32] + ("…" if len(r.serial) > 32 else "")))

        # SANs — show up to 6, collapse the rest
        if r.sans:
            san_display = r.sans[:6]
            overflow    = len(r.sans) - 6
            san_str     = "  ".join(san_display)
            if overflow > 0:
                san_str += f"  {DIM(f'+ {overflow} more')}"
            _detail_row("SANs", san_str)

        # Warning flags
        flags = []
        if r.self_signed: flags.append(YELLOW("⚠  Self-signed certificate"))
        if r.wildcard:    flags.append(DIM("★  Wildcard cert"))
        if r.expired:     flags.append(RED("💀 Certificate has expired"))
        for flag in flags:
            print(f"       {flag}")

    print()


def _detail_row(label: str, value: str) -> None:
    """Print one indented key-value detail line."""
    print(f"       {DIM((label + ':').ljust(10))} {value}")


# ─────────────────────────────────────────────
# Summary footer
# ─────────────────────────────────────────────

def _print_summary_footer(results: list["CertInfo"]) -> None:
    """Print the summary counts footer after the host list."""
    ok       = sum(1 for r in results if r.grade == "OK"       and not r.error and not r.expired)
    info     = sum(1 for r in results if r.grade == "INFO"     and not r.error)
    warning  = sum(1 for r in results if r.grade == "WARNING"  and not r.error)
    critical = sum(1 for r in results if r.grade == "CRITICAL" and not r.error and not r.expired)
    expired  = sum(1 for r in results if r.expired)
    errors   = sum(1 for r in results if r.error)

    print(f"  {'─' * 62}")

    parts = []
    if ok:       parts.append(GREEN(f"{ok} OK"))
    if info:     parts.append(CYAN(f"{info} INFO"))
    if warning:  parts.append(YELLOW(f"{warning} WARNING"))
    if critical: parts.append(RED(f"{critical} CRITICAL"))
    if expired:  parts.append(RED(f"{expired} EXPIRED"))
    if errors:   parts.append(MAGENTA(f"{errors} ERROR"))

    print(f"  {' · '.join(parts)}")
    print(f"  {'─' * 62}")
    print()


# ─────────────────────────────────────────────
# Formatting helpers
# ─────────────────────────────────────────────

def _fmt_days(r: "CertInfo") -> str:
    """Format the days-remaining string for a CertInfo."""
    if r.error:
        return "unreachable"
    if r.expired:
        return f"expired {abs(r.days_left)}d ago"
    if r.days_left == 0:
        return "expires today"
    if r.days_left == 1:
        return "1 day left"
    return f"{r.days_left}d left"


def _fmt_interval(seconds: int) -> str:
    """
    Format a seconds interval into a human-readable string.

      3600   → "1h"
      7200   → "2h"
      86400  → "24h"
      90     → "1m 30s"
      45     → "45s"
    """
    if seconds >= 3600 and seconds % 3600 == 0:
        return f"{seconds // 3600}h"
    if seconds >= 60 and seconds % 60 == 0:
        return f"{seconds // 60}m"
    if seconds >= 3600:
        h = seconds // 3600
        m = (seconds % 3600) // 60
        return f"{h}h {m}m" if m else f"{h}h"
    if seconds >= 60:
        m = seconds // 60
        s = seconds % 60
        return f"{m}m {s}s" if s else f"{m}m"
    return f"{seconds}s"


def _ansi_overhead(s: str) -> int:
    """
    Count the number of invisible ANSI escape characters in a string
    so callers can compensate when using ljust() for alignment.
    ANSI sequences are of the form: ESC [ ... m
    """
    if not USE_COLOR:
        return 0
    count = 0
    i     = 0
    while i < len(s):
        if s[i] == "\033" and i + 1 < len(s) and s[i + 1] == "[":
            # Scan to the end of the escape sequence (terminated by a letter)
            j = i + 2
            while j < len(s) and not s[j].isalpha():
                j += 1
            count += (j - i + 1)
            i = j + 1
        else:
            i += 1
    return count