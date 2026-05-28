#!/usr/bin/env python3
"""
tests/conftest.py
━━━━━━━━━━━━━━━━
Shared pytest fixtures for all top-level test files.

  tests/test_config.py
  tests/test_scanner.py
  tests/test_output.py
  tests/test_report.py

Fixtures defined here are available to every test file in
tests/ and tests/checks/ without any explicit import.
pytest discovers them automatically via conftest.py convention.

For CVE-check-specific fixtures (mock sockets, raw packet bytes,
openssl subprocess mocks), see tests/checks/conftest.py.
"""

import json
import os
import socket
import struct
from argparse import Namespace
from datetime import datetime, timezone
from unittest.mock import MagicMock, patch

import pytest

from vuln_sweep.checks      import ALL_CHECK_NAMES
from vuln_sweep.checks.base import CheckResult
from vuln_sweep.scanner     import VulnResult, SweepReport


# ─────────────────────────────────────────────
# Config fixtures
# ─────────────────────────────────────────────

@pytest.fixture
def default_config():
    """
    Minimal complete config dict used across scanner,
    output, and report tests.
    """
    return {
        "threads":   4,
        "timeout":   6,
        "checks":    ALL_CHECK_NAMES,
        "port":      443,
        "verbose":   False,
        "once":      True,
        "json_out":  None,
        "jsonl_out": None,
        "html_out":  None,
    }


@pytest.fixture
def verbose_config(default_config):
    """Config with verbose=True — expands detail blocks in output."""
    return {**default_config, "verbose": True}


@pytest.fixture
def minimal_config():
    """Bare-minimum config with one check only."""
    return {
        "threads": 1,
        "timeout": 6,
        "checks":  ["heartbleed"],
        "port":    443,
        "verbose": False,
    }


@pytest.fixture
def output_config(default_config, tmp_path):
    """
    Config with all output paths set to tmp_path files.
    Used by test_report.py to verify file creation.
    """
    return {
        **default_config,
        "json_out":  str(tmp_path / "scan.json"),
        "jsonl_out": str(tmp_path / "audit.jsonl"),
        "html_out":  str(tmp_path / "report.html"),
    }


# ─────────────────────────────────────────────
# CLI args fixture
# ─────────────────────────────────────────────

@pytest.fixture
def default_args():
    """
    Minimal argparse Namespace for build_config() tests.
    All flags at their defaults (None / False).
    """
    return Namespace(
        target    = None,
        file      = None,
        config    = None,
        port      = None,
        threads   = None,
        timeout   = None,
        once      = False,
        verbose   = False,
        all       = False,
        json_out  = None,
        jsonl_out = None,
        html_out  = None,
        heartbleed= False,
        poodle    = False,
        beast     = False,
        robot     = False,
        drown     = False,
        lucky13   = False,
    )


# ─────────────────────────────────────────────
# CheckResult fixtures
# ─────────────────────────────────────────────

@pytest.fixture
def make_check_result():
    """
    Factory fixture for building CheckResult objects in tests.

    Usage:
        def test_foo(make_check_result):
            r = make_check_result(vulnerable=True, name="Heartbleed")
    """
    def _factory(
        cve:        str   = "CVE-2014-0160",
        name:       str   = "Heartbleed",
        vulnerable        = False,
        detail:     str   = "Not vulnerable.",
        error:      str   = "",
        duration_ms:float = 45.0,
    ) -> CheckResult:
        return CheckResult(
            cve         = cve,
            name        = name,
            vulnerable  = vulnerable,
            detail      = detail,
            error       = error,
            duration_ms = duration_ms,
        )
    return _factory


@pytest.fixture
def clean_check(make_check_result):
    """A confirmed-clean CheckResult."""
    return make_check_result(vulnerable=False, detail="Server rejected probe.")


@pytest.fixture
def vuln_check(make_check_result):
    """A confirmed-vulnerable CheckResult."""
    return make_check_result(
        vulnerable = True,
        detail     = "Server returned HeartbeatResponse — memory leak confirmed.",
    )


@pytest.fixture
def error_check(make_check_result):
    """A CheckResult with an error (inconclusive)."""
    return make_check_result(
        vulnerable = None,
        error      = "Connection timed out after 6s.",
    )


@pytest.fixture
def inconclusive_check(make_check_result):
    """A CheckResult that is inconclusive but not an error."""
    return make_check_result(
        vulnerable = None,
        detail     = "Result inconclusive — openssl not available.",
        error      = "",
    )


@pytest.fixture
def all_clean_checks(make_check_result):
    """Six clean CheckResults — one per CVE."""
    return [
        make_check_result(
            cve  = cve,
            name = name,
            vulnerable = False,
        )
        for name, cve in [
            ("Heartbleed", "CVE-2014-0160"),
            ("POODLE",     "CVE-2014-3566"),
            ("BEAST",      "CVE-2011-3389"),
            ("ROBOT",      "CVE-2017-17382"),
            ("DROWN",      "CVE-2016-0800"),
            ("LUCKY13",    "CVE-2013-0169"),
        ]
    ]


@pytest.fixture
def all_vuln_checks(make_check_result):
    """Six vulnerable CheckResults — worst-case scenario."""
    return [
        make_check_result(
            cve        = cve,
            name       = name,
            vulnerable = True,
            detail     = f"{name} confirmed.",
        )
        for name, cve in [
            ("Heartbleed", "CVE-2014-0160"),
            ("POODLE",     "CVE-2014-3566"),
            ("BEAST",      "CVE-2011-3389"),
            ("ROBOT",      "CVE-2017-17382"),
            ("DROWN",      "CVE-2016-0800"),
            ("LUCKY13",    "CVE-2013-0169"),
        ]
    ]


# ─────────────────────────────────────────────
# VulnResult fixtures
# ─────────────────────────────────────────────

@pytest.fixture
def make_vuln_result():
    """
    Factory fixture for VulnResult objects.

    Usage:
        def test_foo(make_vuln_result):
            r = make_vuln_result(host="example.com", vuln_n=2)
    """
    def _factory(
        host:    str = "example.com",
        port:    int = 443,
        checks:  list = None,
        vuln_n:  int = 0,
        error_n: int = 0,
        incon_n: int = 0,
        clean_n: int = 6,
    ) -> VulnResult:
        if checks is not None:
            return VulnResult(host=host, port=port, checks=checks)

        pairs = [
            ("Heartbleed", "CVE-2014-0160"),
            ("POODLE",     "CVE-2014-3566"),
            ("BEAST",      "CVE-2011-3389"),
            ("ROBOT",      "CVE-2017-17382"),
            ("DROWN",      "CVE-2016-0800"),
            ("LUCKY13",    "CVE-2013-0169"),
        ]
        built = []
        idx   = 0

        for _ in range(vuln_n):
            n, c = pairs[idx % len(pairs)]; idx += 1
            built.append(CheckResult(cve=c, name=n, vulnerable=True,
                                     detail=f"{n} confirmed."))
        for _ in range(error_n):
            n, c = pairs[idx % len(pairs)]; idx += 1
            built.append(CheckResult(cve=c, name=n, vulnerable=None,
                                     error="timeout"))
        for _ in range(incon_n):
            n, c = pairs[idx % len(pairs)]; idx += 1
            built.append(CheckResult(cve=c, name=n, vulnerable=None))
        for _ in range(clean_n):
            n, c = pairs[idx % len(pairs)]; idx += 1
            built.append(CheckResult(cve=c, name=n, vulnerable=False,
                                     detail="Not vulnerable."))

        return VulnResult(host=host, port=port, checks=built,
                          duration_ms=150.0)
    return _factory


@pytest.fixture
def clean_vuln_result(make_vuln_result):
    """A VulnResult where all six checks are clean — grade A."""
    return make_vuln_result(vuln_n=0, error_n=0, incon_n=0, clean_n=6)


@pytest.fixture
def critical_vuln_result(make_vuln_result):
    """A VulnResult with three vulnerabilities — grade F."""
    return make_vuln_result(vuln_n=3, clean_n=3)


@pytest.fixture
def single_vuln_result(make_vuln_result):
    """A VulnResult with one vulnerability — grade C."""
    return make_vuln_result(vuln_n=1, clean_n=5)


@pytest.fixture
def error_vuln_result(make_vuln_result):
    """A VulnResult with connection errors — grade B."""
    return make_vuln_result(vuln_n=0, error_n=2, clean_n=4)


# ─────────────────────────────────────────────
# SweepReport fixtures
# ─────────────────────────────────────────────

@pytest.fixture
def make_sweep_report():
    """
    Factory fixture for SweepReport objects.

    Usage:
        def test_foo(make_sweep_report, make_vuln_result):
            r = make_vuln_result(vuln_n=1)
            report = make_sweep_report(results=[r])
    """
    def _factory(
        results:    list = None,
        checks_run: list = None,
    ) -> SweepReport:
        return SweepReport(
            results    = results    or [],
            checks_run = checks_run or ALL_CHECK_NAMES,
            start_time = datetime.now(timezone.utc).isoformat(),
            end_time   = datetime.now(timezone.utc).isoformat(),
            duration_ms= 500.0,
        )
    return _factory


@pytest.fixture
def clean_sweep_report(make_sweep_report, make_vuln_result):
    """A SweepReport where all hosts are clean — overall grade A."""
    results = [
        make_vuln_result(host="a.com", vuln_n=0, clean_n=6),
        make_vuln_result(host="b.com", vuln_n=0, clean_n=6),
        make_vuln_result(host="c.com", vuln_n=0, clean_n=6),
    ]
    return make_sweep_report(results=results)


@pytest.fixture
def mixed_sweep_report(make_sweep_report, make_vuln_result):
    """A SweepReport with a mix of clean, vulnerable, and error hosts."""
    results = [
        make_vuln_result(host="clean.com",    vuln_n=0, clean_n=6),
        make_vuln_result(host="vuln.com",     vuln_n=2, clean_n=4),
        make_vuln_result(host="critical.com", vuln_n=3, clean_n=3),
        make_vuln_result(host="error.com",    error_n=1, clean_n=5),
    ]
    return make_sweep_report(results=results)


# ─────────────────────────────────────────────
# File system fixtures
# ─────────────────────────────────────────────

@pytest.fixture
def json_config_file(tmp_path):
    """
    Write a valid vuln-sweep.json config file and return its path.
    """
    config = {
        "threads": 8,
        "timeout": 10,
        "checks":  ["heartbleed", "poodle", "beast"],
        "port":    443,
    }
    p = tmp_path / "vuln-sweep.json"
    p.write_text(json.dumps(config))
    return str(p)


@pytest.fixture
def targets_file(tmp_path):
    """
    Write a targets.txt file and return its path.
    """
    content = (
        "# Production\n"
        "example.com\n"
        "api.example.com:8443\n"
        "\n"
        "# Staging\n"
        "staging.example.com\n"
        "# internal.corp  (disabled)\n"
    )
    p = tmp_path / "targets.txt"
    p.write_text(content)
    return str(p)


# ─────────────────────────────────────────────
# Environment variable helpers
# ─────────────────────────────────────────────

@pytest.fixture
def clean_env():
    """
    Patch os.environ to remove all VULN_SWEEP_* variables.
    Useful for tests that verify default behaviour without env overrides.
    """
    clean = {k: v for k, v in os.environ.items()
             if not k.startswith("VULN_SWEEP_")}
    with patch.dict(os.environ, clean, clear=True):
        yield


@pytest.fixture
def env_with_timeout():
    """Patch VULN_SWEEP_TIMEOUT=15 into the environment."""
    with patch.dict(os.environ, {"VULN_SWEEP_TIMEOUT": "15"}):
        yield


@pytest.fixture
def env_with_all_vars():
    """Patch all VULN_SWEEP_* vars into the environment."""
    env = {
        "VULN_SWEEP_TIMEOUT": "10",
        "VULN_SWEEP_THREADS": "8",
        "VULN_SWEEP_PORT":    "8443",
    }
    with patch.dict(os.environ, env):
        yield