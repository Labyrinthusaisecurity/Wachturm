#!/usr/bin/env python3
"""
vuln_sweep/__init__.py
━━━━━━━━━━━━━━━━━━━━━
Package metadata and public API surface.

Anything imported here is available as:
  from vuln_sweep import VulnResult, run_sweep
  from vuln_sweep import CheckResult, ALL_CHECKS

Priority: keep this file short.
All logic lives in submodules — this file only
declares what is stable public API.
"""

__version__ = "1.0.0"
__author__  = "yourname"
__license__ = "MIT"
__email__   = "you@example.com"

# ── Core dataclasses ─────────────────────────
from vuln_sweep.checks.base import CheckResult
from vuln_sweep.scanner     import VulnResult, SweepReport, run_sweep

# ── Check registry ────────────────────────────
# ALL_CHECKS maps check name → check function.
# Import it here so callers never need to know
# which submodule each check lives in.
from vuln_sweep.checks import ALL_CHECKS, SUPPORTED_CVES

# ── Config helpers ────────────────────────────
from vuln_sweep.config import (
    build_config,
    parse_targets,
    DEFAULT_CONFIG,
    DEFAULT_CHECKS,
)

# ── Output helpers ────────────────────────────
from vuln_sweep.output import (
    print_banner,
    print_results,
)

# ── Report dispatcher ─────────────────────────
from vuln_sweep.report import dispatch_report

__all__ = [
    # Metadata
    "__version__",
    "__author__",
    "__license__",

    # Dataclasses
    "CheckResult",
    "VulnResult",
    "SweepReport",

    # Core functions
    "run_sweep",
    "dispatch_report",

    # Check registry
    "ALL_CHECKS",
    "SUPPORTED_CVES",

    # Config
    "build_config",
    "parse_targets",
    "DEFAULT_CONFIG",
    "DEFAULT_CHECKS",

    # Output
    "print_banner",
    "print_results",
]