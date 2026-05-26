#!/usr/bin/env python3
"""
vuln_sweep/output.py
━━━━━━━━━━━━━━━━━━━
All console output, ANSI colour helpers, and terminal formatting.
Nothing in this module does network I/O, subprocess calls,
or modifies config. It only reads VulnResult / CheckResult
objects and writes to stdout.

Public API:
  print_banner(targets, config)   — shown once at startup
  print_results(result, config)   — shown after every host sweep
  print_summary(results, config)  — shown at end of full run
"""

import os
import sys
from datetime import datetime
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from vuln_sweep.scanner     import VulnResult, SweepReport
    from vuln_sweep.checks.base import CheckResult


# ─────────────────────────────────────────────
# ANSI colour helpers
# ─────────────────────────────────────────────
# Auto-disabled when stdout is not a TTY
# (cron, systemd, CI pipelines, file redirection).

USE_COLOR: bool = sys.stdout.isatty() and os.name != "nt"


def _c(code: str, text: str) -> str:
    return f"\033[{code}m{text}\033[0m" if USE_COLOR else text


RED     = lambda t: _c("31;1", t)
GREEN   = lambda t: _c("32;1", t)
YELLOW  = lambda t: _c("33;1", t)
CYAN    = lambda t: _c("36;1", t)
BLUE    = lambda t: _c("34;1", t)
MAGENTA = lambda t: _c("35;1", t)
BOLD    = lambda t: _c("1",    t)
DIM     = lambda t: _c("2",    t)
ITALIC  = lambda t: _c("3",    t)


def _vuln_color(vulnerable, text: str) -> str:
    """Colour text based on vulnerability status."""
    if vulnerable is True:  return RED(text)
    if vulnerable is False: return GREEN(text)
    return YELLOW(text)                          # None = inconclusive


def _grade_color(grade: str, text: str) -> str:
    """Colour text based on sweep grade."""
    return {
        "A": GREEN(text),
        "B": CYAN(text),
        "C": YELLOW(text),
        "F": RED(text),
    }.get(grade, text)


def _ansi_overhead(s: str) -> int:
    """
    Count invisible ANSI escape bytes in a string so callers
    can compensate when using ljust() for column alignment.
    """
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


# ─────────────────────────────────────────────
# Startup banner
# ─────────────────────────────────────────────

def print_banner(
    targets: list[tuple[str, int]],
    config:  dict,
) -> None:
    """
    Print the startup banner once when vuln-sweep launches.
    Shows target count, selected checks, thread count,
    timeout, and output mode.
    """
    checks   = config.get("checks", list(config.get("all_checks", {}).keys()))
    n_checks = len(checks)
    timeout  = config.get("timeout", 6)
    threads  = config.get("threads", 4)
    outputs  = _active_outputs(config)

    print()
    print(f"  {BOLD('🔬 vuln-sweep')}  {DIM('v1.0.0')}")
    print(f"  {'─' * 56}")
    print(f"  {DIM('Targets:'):<24} {len(targets)}")
    print(f"  {DIM('Checks:'):<24} {n_checks} CVE{'s' if n_checks != 1 else ''}")
    print(f"  {DIM('Timeout:'):<24} {timeout}s per check")
    print(f"  {DIM('Threads:'):<24} {threads} (parallel checks per host)")
    print(f"  {DIM('Output:'):<24} "
          f"{', '.join(outputs) if outputs else 'console only'}")
    print(f"  {'─' * 56}")

    # List selected CVEs
    cve_map = {
        "heartbleed": ("CVE-2014-0160", "Heartbleed"),
        "poodle":     ("CVE-2014-3566", "POODLE"),
        "beast":      ("CVE-2011-3389", "BEAST"),
        "robot":      ("CVE-2017-17382","ROBOT"),
        "drown":      ("CVE-2016-0800", "DROWN"),
        "lucky13":    ("CVE-2013-0169", "LUCKY13"),
    }
    for name in checks:
        if name in cve_map:
            cve, label = cve_map[name]
            print(f"  {DIM('·')}  {DIM(cve)}  {label}")

    print()


# ─────────────────────────────────────────────
# Per-host results
# ─────────────────────────────────────────────

def print_results(
    result:  "VulnResult",
    config:  dict,
    verbose: bool = False,
) -> None:
    """
    Print the scan results for one host.

    Normal mode:  one line per CVE check.
    Verbose mode: adds detail text for every result,
                  not just vulnerable ones.

    Args:
        result:  VulnResult from run_sweep().
        config:  Full config dict.
        verbose: Show detail for all checks, not just findings.
    """
    host_str = f"{result.host}:{result.port}"
    grade    = _grade_color(result.grade, f"Grade {result.grade}")

    print(f"\n  {'─' * 56}")
    print(f"  {BOLD(host_str.ljust(36))} {grade}  "
          f"{DIM(result.scan_time[:19].replace('T',' ') + ' UTC')}")
    print(f"  {'─' * 56}")

    for check in result.checks:
        _print_check_row(check, verbose)

    # Footer counts
    vuln   = sum(1 for c in result.checks if c.vulnerable is True)
    clean  = sum(1 for c in result.checks if c.vulnerable is False)
    incon  = sum(1 for c in result.checks if c.vulnerable is None)
    errors = sum(1 for c in result.checks if c.error)

    print(f"  {'─' * 56}")

    parts = []
    if vuln:   parts.append(RED(f"{vuln} VULNERABLE"))
    if clean:  parts.append(GREEN(f"{clean} CLEAN"))
    if incon:  parts.append(YELLOW(f"{incon} INCONCLUSIVE"))
    if errors: parts.append(MAGENTA(f"{errors} ERROR"))
    print(f"  {' · '.join(parts)}")
    print()


def _print_check_row(check: "CheckResult", verbose: bool) -> None:
    """Print one CVE check row with optional detail block."""

    # Status label and icon
    if check.error:
        icon   = "⚫"
        status = MAGENTA("ERROR")
    elif check.vulnerable is True:
        icon   = "🔴"
        status = RED("VULNERABLE")
    elif check.vulnerable is False:
        icon   = "🟢"
        status = GREEN("NOT VULNERABLE")
    else:
        icon   = "🟡"
        status = YELLOW("INCONCLUSIVE")

    duration = DIM(f"{check.duration_ms:.0f}ms")
    cve_str  = DIM(check.cve.ljust(17))
    name_str = BOLD(check.name.ljust(10))

    pad = 22 + _ansi_overhead(status)
    print(f"  {icon}  {cve_str}  {name_str}  "
          f"{status.ljust(pad)}  {duration}")

    # Detail block — always shown for VULNERABLE, optionally for others
    should_expand = (
        verbose
        or check.vulnerable is True
        or check.error
    )

    if not should_expand:
        return

    print()
    if check.error:
        print(f"       {RED('✗')}  {check.error}")
    elif check.detail:
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
    print()


# ─────────────────────────────────────────────
# Multi-host summary
# ─────────────────────────────────────────────

def print_summary(
    report:  "SweepReport",
    config:  dict,
) -> None:
    """
    Print the final summary table after all hosts are scanned.
    One row per host with host, grade, vuln count, and status.
    """
    print(f"\n  {'═' * 56}")
    print(f"  {BOLD('SWEEP COMPLETE')}  "
          f"{DIM(datetime.utcnow().strftime('%Y-%m-%d %H:%M UTC'))}")
    print(f"  {'─' * 56}")
    print(f"  {'HOST'.ljust(32)}  {'GRADE':<8}  {'VULNS':<6}  STATUS")
    print(f"  {'─' * 56}")

    for result in report.results:
        host_str  = f"{result.host}:{result.port}"
        grade_str = _grade_color(result.grade, result.grade)
        vuln_n    = result.vuln_count

        if vuln_n > 0:
            status = RED(f"{vuln_n} finding{'s' if vuln_n > 1 else ''}")
        elif any(c.error for c in result.checks):
            status = MAGENTA("errors")
        elif any(c.vulnerable is None for c in result.checks):
            status = YELLOW("inconclusive")
        else:
            status = GREEN("clean")

        pad = 8 + _ansi_overhead(grade_str)
        print(f"  {host_str.ljust(32)}  "
              f"{grade_str.ljust(pad)}  "
              f"{str(vuln_n).ljust(6)}  "
              f"{status}")

    # Global totals
    total_hosts  = len(report.results)
    total_vulns  = sum(r.vuln_count for r in report.results)
    vuln_hosts   = sum(1 for r in report.results if r.vuln_count > 0)
    clean_hosts  = sum(1 for r in report.results if r.vuln_count == 0
                       and not any(c.error for c in r.checks))
    error_hosts  = sum(1 for r in report.results
                       if any(c.error for c in r.checks))

    print(f"  {'═' * 56}")
    print(f"  {BOLD('Hosts scanned:')}   {total_hosts}")
    print(f"  {RED('Vulnerable:') if vuln_hosts else DIM('Vulnerable:')}    "
          f"{RED(str(vuln_hosts)) if vuln_hosts else str(vuln_hosts)}")
    print(f"  {GREEN('Clean:')}           {clean_hosts}")
    if error_hosts:
        print(f"  {MAGENTA('Errors:')}          {error_hosts}")
    print(f"  {BOLD('Total findings:')} "
          f"{RED(str(total_vulns)) if total_vulns else GREEN('0')}")
    print(f"  {'═' * 56}\n")


# ─────────────────────────────────────────────
# Formatting helpers
# ─────────────────────────────────────────────

def _active_outputs(config: dict) -> list[str]:
    """Return list of active non-console output modes."""
    outputs = []
    if config.get("json_out"):  outputs.append(f"JSON → {config['json_out']}")
    if config.get("html_out"):  outputs.append(f"HTML → {config['html_out']}")
    if config.get("jsonl_out"): outputs.append(f"JSONL → {config['jsonl_out']}")
    return outputs


def _fmt_duration(ms: float) -> str:
    """Format a millisecond duration to a human-readable string."""
    if ms < 1000:
        return f"{ms:.0f}ms"
    return f"{ms/1000:.1f}s"