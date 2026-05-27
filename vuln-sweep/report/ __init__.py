#!/usr/bin/env python3
"""
vuln_sweep/report/__init__.py
━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Report dispatcher — the single place that routes scan results
to configured output formatters.

Adding a new output format requires exactly two changes:
  1. Create vuln_sweep/report/newformat.py with a write() function
  2. Add one entry to _FORMATTERS and one key to _active_formatters()

Public API:
  dispatch_report(result, config)   — write all configured outputs
                                      for a single VulnResult
  dispatch_summary(report, config)  — write all configured outputs
                                      for a complete SweepReport
"""

from vuln_sweep.report.console  import write as _write_console
from vuln_sweep.report.json_out import write as _write_json
from vuln_sweep.report.html_out import write as _write_html

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from vuln_sweep.scanner import VulnResult, SweepReport


# ─────────────────────────────────────────────
# Formatter registry
# ─────────────────────────────────────────────
# Maps config key → (formatter_fn, description)
# formatter_fn signature:
#   write(result_or_report, config) → None

_FORMATTERS: dict[str, tuple[callable, str]] = {
    "console":   (_write_console, "coloured terminal output"),
    "json_out":  (_write_json,    "JSON snapshot file"),
    "html_out":  (_write_html,    "self-contained HTML audit report"),
}

# JSONL is a special case of json_out — appends rather than overwrites.
# It shares the same write function but is triggered by a different key.
# The distinction is handled inside json_out.write() itself.
_JSONL_KEY = "jsonl_out"


# ─────────────────────────────────────────────
# Per-result dispatcher
# ─────────────────────────────────────────────

def dispatch_report(
    result: "VulnResult",
    config: dict,
) -> None:
    """
    Write all configured output formats for a single host result.

    Called once per host after run_sweep() returns. Console output
    always fires. JSON and HTML outputs fire only when their output
    path is configured.

    If a formatter raises, the exception is caught, logged to stderr,
    and the remaining formatters still run. A broken HTML renderer
    must never prevent the JSON log from being written.

    Args:
        result: VulnResult from scanner.run_sweep().
        config: Full config dict from config.build_config().
    """
    import sys

    for key, (fn, description) in _FORMATTERS.items():

        # Console always runs
        if key == "console":
            try:
                fn(result, config)
            except Exception as e:
                print(
                    f"vuln-sweep: report warning: console output failed: {e}",
                    file=sys.stderr,
                )
            continue

        # File formatters only run when path is configured
        if not config.get(key):
            continue

        try:
            fn(result, config)
        except Exception as e:
            print(
                f"vuln-sweep: report warning: {description} failed "
                f"({config[key]}): {e}",
                file=sys.stderr,
            )

    # JSONL is separate — append mode, different key
    if config.get(_JSONL_KEY):
        try:
            _write_json(result, config, jsonl_mode=True)
        except Exception as e:
            print(
                f"vuln-sweep: report warning: JSONL append failed "
                f"({config[_JSONL_KEY]}): {e}",
                file=sys.stderr,
            )


# ─────────────────────────────────────────────
# Full sweep report dispatcher
# ─────────────────────────────────────────────

def dispatch_summary(
    report: "SweepReport",
    config: dict,
) -> None:
    """
    Write all configured output formats for a complete SweepReport.

    Called once after run_multi() finishes all hosts.
    Produces the consolidated HTML report and final JSON snapshot
    that cover the entire sweep rather than individual hosts.

    Console summary is always printed.
    HTML and JSON outputs overwrite per-host outputs with the
    complete multi-host version.

    Args:
        report: SweepReport from scanner.run_multi().
        config: Full config dict from config.build_config().
    """
    import sys
    from vuln_sweep.output import print_summary

    # Always print console summary
    try:
        print_summary(report, config)
    except Exception as e:
        print(
            f"vuln-sweep: report warning: console summary failed: {e}",
            file=sys.stderr,
        )

    # Write consolidated JSON snapshot
    if config.get("json_out"):
        try:
            _write_json(report, config, summary_mode=True)
        except Exception as e:
            print(
                f"vuln-sweep: report warning: JSON summary failed: {e}",
                file=sys.stderr,
            )

    # Write consolidated HTML report
    if config.get("html_out"):
        try:
            _write_html(report, config, summary_mode=True)
        except Exception as e:
            print(
                f"vuln-sweep: report warning: HTML report failed: {e}",
                file=sys.stderr,
            )


# ─────────────────────────────────────────────
# Introspection helpers
# ─────────────────────────────────────────────

def active_formatters(config: dict) -> list[str]:
    """
    Return list of formatter names that will fire given the config.
    Used by output.print_banner() to show active output modes.

    Example:
        active_formatters({"json_out": "scan.json", "html_out": "report.html"})
        → ["console", "json_out", "html_out"]
    """
    active = ["console"]    # always active

    for key in ("json_out", "jsonl_out", "html_out"):
        if config.get(key):
            active.append(key)

    return active


def formatter_paths(config: dict) -> dict[str, str]:
    """
    Return a dict mapping active formatter names to their output paths.
    Console has no path so it is omitted.

    Example:
        formatter_paths({"json_out": "scan.json", "html_out": "report.html"})
        → {"json_out": "scan.json", "html_out": "report.html"}
    """
    paths = {}
    for key in ("json_out", "jsonl_out", "html_out"):
        val = config.get(key)
        if val:
            paths[key] = val
    return paths


__all__ = [
    "dispatch_report",
    "dispatch_summary",
    "active_formatters",
    "formatter_paths",
]