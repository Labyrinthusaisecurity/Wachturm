#!/usr/bin/env python3
"""
vuln_sweep/scanner.py
━━━━━━━━━━━━━━━━━━━━
Core orchestration logic. Runs selected CVE checks against
a host in parallel and returns structured result dataclasses.

No alert logic, no output, no config parsing lives here.
This module is pure: given targets and config, return results.
Every function is independently testable with mocked checks.

Public API:
  run_sweep(host, port, checks, config)  → VulnResult
  run_multi(targets, config)             → SweepReport
"""

import time
from concurrent.futures import ThreadPoolExecutor, as_completed, Future
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Optional

from vuln_sweep.checks      import ALL_CHECKS
from vuln_sweep.checks.base import CheckResult


# ─────────────────────────────────────────────
# Dataclasses
# ─────────────────────────────────────────────

@dataclass
class VulnResult:
    """
    All CVE check results for a single host.
    Produced by run_sweep(), consumed by output.py and report/.

    Fields are flat and JSON-serialisable via dataclasses.asdict().
    """

    # Target identity
    host: str
    port: int

    # Individual CVE results — one CheckResult per check run
    checks: list[CheckResult] = field(default_factory=list)

    # Scan metadata
    scan_time:   str   = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )
    duration_ms: float = 0.0

    # ── Computed properties ───────────────────────────────────

    @property
    def vuln_count(self) -> int:
        """Number of confirmed vulnerabilities (vulnerable is True)."""
        return sum(1 for c in self.checks if c.vulnerable is True)

    @property
    def error_count(self) -> int:
        """Number of checks that returned an error."""
        return sum(1 for c in self.checks if c.error)

    @property
    def inconclusive_count(self) -> int:
        """Number of checks that could not confirm either way."""
        return sum(1 for c in self.checks if c.vulnerable is None and not c.error)

    @property
    def clean_count(self) -> int:
        """Number of checks that confirmed not vulnerable."""
        return sum(1 for c in self.checks if c.vulnerable is False)

    @property
    def grade(self) -> str:
        """
        Overall security grade for this host based on findings.

          A — no vulnerabilities confirmed
          B — inconclusive results but nothing confirmed vulnerable
          C — 1–2 confirmed vulnerabilities
          F — 3+ confirmed vulnerabilities

        Grade A is only possible if every check returned False
        (not vulnerable). Errors or inconclusives cap at B.
        """
        if self.vuln_count >= 3:
            return "F"
        if self.vuln_count == 2:
            return "C"
        if self.vuln_count == 1:
            return "C"
        if self.error_count > 0 or self.inconclusive_count > 0:
            return "B"
        return "A"

    @property
    def vulnerable_checks(self) -> list[CheckResult]:
        """Confirmed vulnerable checks only."""
        return [c for c in self.checks if c.vulnerable is True]

    @property
    def failed_checks(self) -> list[CheckResult]:
        """Checks that returned errors."""
        return [c for c in self.checks if c.error]

    @property
    def cves_found(self) -> list[str]:
        """List of CVE IDs confirmed as vulnerable."""
        return [c.cve for c in self.checks if c.vulnerable is True]

    @property
    def emoji(self) -> str:
        if self.vuln_count > 0:        return "🔴"
        if self.error_count > 0:       return "⚫"
        if self.inconclusive_count > 0:return "🟡"
        return "🟢"


@dataclass
class SweepReport:
    """
    Aggregated results for a full multi-host sweep.
    Produced by run_multi(), consumed by report/ and output.print_summary().
    """

    # All per-host results
    results: list[VulnResult] = field(default_factory=list)

    # Sweep metadata
    start_time:  str   = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )
    end_time:    str   = ""
    duration_ms: float = 0.0
    checks_run:  list[str] = field(default_factory=list)

    # ── Computed properties ───────────────────────────────────

    @property
    def total_hosts(self) -> int:
        return len(self.results)

    @property
    def vulnerable_hosts(self) -> int:
        return sum(1 for r in self.results if r.vuln_count > 0)

    @property
    def clean_hosts(self) -> int:
        return sum(1 for r in self.results
                   if r.vuln_count == 0 and r.error_count == 0)

    @property
    def error_hosts(self) -> int:
        return sum(1 for r in self.results if r.error_count > 0)

    @property
    def total_vulns(self) -> int:
        return sum(r.vuln_count for r in self.results)

    @property
    def all_cves_found(self) -> list[str]:
        """Deduplicated list of all CVEs confirmed across all hosts."""
        seen = set()
        cves = []
        for r in self.results:
            for cve in r.cves_found:
                if cve not in seen:
                    seen.add(cve)
                    cves.append(cve)
        return cves

    @property
    def grade(self) -> str:
        """
        Worst-case grade across all hosts.
        The sweep is only as clean as its dirtiest host.
        """
        grades = [r.grade for r in self.results]
        for g in ("F", "C", "B"):
            if g in grades:
                return g
        return "A"


# ─────────────────────────────────────────────
# Single-host sweep
# ─────────────────────────────────────────────

def run_sweep(
    host:    str,
    port:    int,
    checks:  list[str],
    config:  dict,
) -> VulnResult:
    """
    Run selected CVE checks against a single host in parallel.

    Each check is submitted to a ThreadPoolExecutor — checks are
    I/O-bound (socket + subprocess) so threading is appropriate.
    The number of workers is capped at len(checks) since there is
    no benefit spinning up more threads than checks.

    Never raises — all check exceptions are caught inside each
    check function (which returns CheckResult with error set).
    The outer try/except here catches Future-level failures that
    should not happen but are handled defensively.

    Args:
        host:    Hostname or IP to scan.
        port:    TCP port to connect to.
        checks:  List of check names to run (from ALL_CHECK_NAMES).
        config:  Full config dict from config.build_config().

    Returns:
        VulnResult — always, even if all checks errored.
    """
    timeout   = config.get("timeout",  6)
    n_workers = min(len(checks), config.get("threads", 4))

    if not checks:
        return VulnResult(host=host, port=port)

    t0       = time.perf_counter()
    results: list[CheckResult] = []

    with ThreadPoolExecutor(max_workers=n_workers) as executor:
        # Submit all checks concurrently
        future_to_name: dict[Future, str] = {
            executor.submit(
                _run_check, name, host, port, timeout
            ): name
            for name in checks
            if name in ALL_CHECKS
        }

        # Warn about unknown check names
        unknown = [n for n in checks if n not in ALL_CHECKS]
        for name in unknown:
            _warn(f"unknown check '{name}' — skipping")

        # Collect results as futures complete
        for future in as_completed(future_to_name):
            name = future_to_name[future]
            try:
                result = future.result()
            except Exception as e:
                # Future itself raised — shouldn't happen since
                # _run_check catches all exceptions, but be defensive
                result = _emergency_result(name, str(e))
            results.append(result)

    duration_ms = (time.perf_counter() - t0) * 1000

    # Sort results into canonical CVE order for consistent output
    results = _sort_results(results, checks)

    return VulnResult(
        host        = host,
        port        = port,
        checks      = results,
        scan_time   = datetime.now(timezone.utc).isoformat(),
        duration_ms = duration_ms,
    )


def _run_check(
    name:    str,
    host:    str,
    port:    int,
    timeout: int,
) -> CheckResult:
    """
    Run a single named check and return its CheckResult.
    Wraps the check function in timing logic.
    The check function itself catches all exceptions internally.
    """
    fn = ALL_CHECKS[name]
    t0 = time.perf_counter()
    result = fn(host, port, timeout)
    result.duration_ms = (time.perf_counter() - t0) * 1000
    return result


# ─────────────────────────────────────────────
# Multi-host sweep
# ─────────────────────────────────────────────

def run_multi(
    targets: list[tuple[str, int]],
    config:  dict,
) -> SweepReport:
    """
    Scan multiple hosts sequentially and return a SweepReport.

    Hosts are scanned one at a time (sequentially) while checks
    within each host run in parallel. This is intentional:
      - Parallel host scanning would multiply network load
      - Per-host parallel checks already max out the local
        network from the scanning machine's perspective
      - Sequential hosts makes progress reporting predictable

    For large target lists (50+ hosts), consider splitting into
    batches and running multiple vuln-sweep instances.

    Args:
        targets: List of (host, port) tuples from parse_targets().
        config:  Full config dict from build_config().

    Returns:
        SweepReport with one VulnResult per target.
    """
    checks     = config.get("checks", [])
    t0         = time.perf_counter()
    start_time = datetime.now(timezone.utc).isoformat()
    results: list[VulnResult] = []

    for host, port in targets:
        result = run_sweep(host, port, checks, config)
        results.append(result)

    duration_ms = (time.perf_counter() - t0) * 1000
    end_time    = datetime.now(timezone.utc).isoformat()

    return SweepReport(
        results     = results,
        start_time  = start_time,
        end_time    = end_time,
        duration_ms = duration_ms,
        checks_run  = checks,
    )


# ─────────────────────────────────────────────
# Sorting
# ─────────────────────────────────────────────

def _sort_results(
    results: list[CheckResult],
    check_order: list[str],
) -> list[CheckResult]:
    """
    Sort CheckResults into the canonical order defined by check_order
    (which mirrors ALL_CHECK_NAMES order).

    Results not found in check_order are appended at the end.
    This ensures output is always in the same order regardless of
    which futures completed first.
    """
    # Build a name→result map
    by_name = {r.name.lower(): r for r in results}

    # Re-order by check_order, then append any extras
    ordered = []
    name_map = {
        "heartbleed": "Heartbleed",
        "poodle":     "POODLE",
        "beast":      "BEAST",
        "robot":      "ROBOT",
        "drown":      "DROWN",
        "lucky13":    "LUCKY13",
    }
    for check_name in check_order:
        canonical = name_map.get(check_name, check_name).lower()
        result    = by_name.pop(canonical, None)
        if result:
            ordered.append(result)

    # Append any results not in check_order (shouldn't happen)
    ordered.extend(by_name.values())
    return ordered


# ─────────────────────────────────────────────
# Sort key for multi-result ordering
# ─────────────────────────────────────────────

def sort_key_vuln_result(r: VulnResult) -> tuple:
    """
    Sort key for a list of VulnResults.
    Most vulnerable first, then errors, then inconclusive, then clean.

      (vuln_count DESC, error_count DESC, host ASC)
    """
    return (
        -r.vuln_count,
        -r.error_count,
        -r.inconclusive_count,
        r.host,
    )


# ─────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────

def _emergency_result(check_name: str, error_msg: str) -> CheckResult:
    """
    Build a CheckResult for a check whose Future itself raised.
    This should never happen in normal operation since every check
    function catches its own exceptions — but be defensive.
    """
    cve_map = {
        "heartbleed": "CVE-2014-0160",
        "poodle":     "CVE-2014-3566",
        "beast":      "CVE-2011-3389",
        "robot":      "CVE-2017-17382",
        "drown":      "CVE-2016-0800",
        "lucky13":    "CVE-2013-0169",
    }
    name_map = {
        "heartbleed": "Heartbleed",
        "poodle":     "POODLE",
        "beast":      "BEAST",
        "robot":      "ROBOT",
        "drown":      "DROWN",
        "lucky13":    "LUCKY13",
    }
    return CheckResult(
        cve         = cve_map.get(check_name, "UNKNOWN"),
        name        = name_map.get(check_name, check_name),
        vulnerable  = None,
        detail      = "",
        error       = f"Future raised unexpectedly: {error_msg}",
        duration_ms = 0.0,
    )


def _warn(message: str) -> None:
    """Print a non-fatal warning to stderr."""
    import sys
    print(f"vuln-sweep: warning: {message}", file=sys.stderr)