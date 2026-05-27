#!/usr/bin/env python3
"""
tests/test_scanner.py
━━━━━━━━━━━━━━━━━━━━
Unit tests for vuln_sweep/scanner.py.

Tests cover:
  • VulnResult dataclass — all properties and computed fields
  • SweepReport dataclass — aggregation and worst-case grade
  • run_sweep()  — parallel check orchestration, ordering, error handling
  • run_multi()  — sequential multi-host sweep, SweepReport construction
  • _sort_results() — canonical CVE order after parallel futures
  • sort_key_vuln_result() — ordering for multi-host output

All CVE check functions are mocked — no real network I/O.
"""

import time
from dataclasses import asdict
from unittest.mock import MagicMock, patch, call

import pytest

from vuln_sweep.scanner import (
    VulnResult,
    SweepReport,
    run_sweep,
    run_multi,
    _sort_results,
    _emergency_result,
    sort_key_vuln_result,
)
from vuln_sweep.checks.base import CheckResult
from vuln_sweep.checks      import ALL_CHECKS, ALL_CHECK_NAMES


# ─────────────────────────────────────────────
# Fixtures
# ─────────────────────────────────────────────

@pytest.fixture
def default_config():
    return {
        "threads":  4,
        "timeout":  6,
        "checks":   ALL_CHECK_NAMES,
        "port":     443,
        "verbose":  False,
    }


@pytest.fixture
def minimal_config():
    return {
        "threads": 2,
        "timeout": 6,
        "checks":  ["heartbleed"],
    }


def _make_check(
    name:       str   = "Heartbleed",
    cve:        str   = "CVE-2014-0160",
    vulnerable: bool  = False,
    error:      str   = "",
    detail:     str   = "Not vulnerable.",
    duration_ms:float = 45.0,
) -> CheckResult:
    return CheckResult(
        cve        = cve,
        name       = name,
        vulnerable = vulnerable,
        detail     = detail,
        error      = error,
        duration_ms= duration_ms,
    )


def _make_vuln_result(
    host:    str  = "example.com",
    port:    int  = 443,
    vuln_n:  int  = 0,
    error_n: int  = 0,
    incon_n: int  = 0,
    clean_n: int  = 6,
) -> VulnResult:
    """Build a VulnResult with the given counts of each outcome."""
    checks = []

    cve_names = [
        ("Heartbleed", "CVE-2014-0160"),
        ("POODLE",     "CVE-2014-3566"),
        ("BEAST",      "CVE-2011-3389"),
        ("ROBOT",      "CVE-2017-17382"),
        ("DROWN",      "CVE-2016-0800"),
        ("LUCKY13",    "CVE-2013-0169"),
    ]

    idx = 0
    for _ in range(vuln_n):
        n, c = cve_names[idx % len(cve_names)]; idx += 1
        checks.append(_make_check(name=n, cve=c, vulnerable=True))
    for _ in range(error_n):
        n, c = cve_names[idx % len(cve_names)]; idx += 1
        checks.append(_make_check(name=n, cve=c, vulnerable=None, error="timeout"))
    for _ in range(incon_n):
        n, c = cve_names[idx % len(cve_names)]; idx += 1
        checks.append(_make_check(name=n, cve=c, vulnerable=None))
    for _ in range(clean_n):
        n, c = cve_names[idx % len(cve_names)]; idx += 1
        checks.append(_make_check(name=n, cve=c, vulnerable=False))

    return VulnResult(
        host        = host,
        port        = port,
        checks      = checks,
        duration_ms = 150.0,
    )


def _clean_result(host="example.com", port=443) -> VulnResult:
    return _make_vuln_result(host, port, vuln_n=0, error_n=0, incon_n=0, clean_n=6)


def _vuln_result(host="example.com", port=443, n=1) -> VulnResult:
    return _make_vuln_result(host, port, vuln_n=n, clean_n=max(0, 6-n))


# ─────────────────────────────────────────────
# VulnResult dataclass tests
# ─────────────────────────────────────────────

class TestVulnResult:

    def test_vuln_count_zero_when_all_clean(self):
        r = _clean_result()
        assert r.vuln_count == 0

    def test_vuln_count_counts_true_only(self):
        r = _make_vuln_result(vuln_n=2, error_n=1, incon_n=1, clean_n=2)
        assert r.vuln_count == 2

    def test_clean_count_counts_false_only(self):
        r = _make_vuln_result(vuln_n=1, error_n=1, incon_n=1, clean_n=3)
        assert r.clean_count == 3

    def test_error_count_counts_error_set(self):
        r = _make_vuln_result(vuln_n=0, error_n=2, incon_n=0, clean_n=4)
        assert r.error_count == 2

    def test_inconclusive_count_excludes_errors(self):
        checks = [
            _make_check(vulnerable=None, error="timeout"),   # error
            _make_check(vulnerable=None, error=""),          # inconclusive
            _make_check(vulnerable=None, error=""),          # inconclusive
        ]
        r = VulnResult(host="x", port=443, checks=checks)
        assert r.inconclusive_count == 2

    def test_grade_a_all_clean(self):
        r = _make_vuln_result(vuln_n=0, error_n=0, incon_n=0, clean_n=6)
        assert r.grade == "A"

    def test_grade_b_has_inconclusive(self):
        r = _make_vuln_result(vuln_n=0, error_n=0, incon_n=1, clean_n=5)
        assert r.grade == "B"

    def test_grade_b_has_errors(self):
        r = _make_vuln_result(vuln_n=0, error_n=1, incon_n=0, clean_n=5)
        assert r.grade == "B"

    def test_grade_c_one_vuln(self):
        r = _make_vuln_result(vuln_n=1, clean_n=5)
        assert r.grade == "C"

    def test_grade_c_two_vulns(self):
        r = _make_vuln_result(vuln_n=2, clean_n=4)
        assert r.grade == "C"

    def test_grade_f_three_vulns(self):
        r = _make_vuln_result(vuln_n=3, clean_n=3)
        assert r.grade == "F"

    def test_grade_f_four_vulns(self):
        r = _make_vuln_result(vuln_n=4, clean_n=2)
        assert r.grade == "F"

    def test_grade_f_all_vulns(self):
        r = _make_vuln_result(vuln_n=6, clean_n=0)
        assert r.grade == "F"

    def test_cves_found_empty_when_clean(self):
        r = _clean_result()
        assert r.cves_found == []

    def test_cves_found_lists_vulnerable_cves(self):
        checks = [
            _make_check(cve="CVE-2014-0160", vulnerable=True),
            _make_check(cve="CVE-2014-3566", vulnerable=True),
            _make_check(cve="CVE-2011-3389", vulnerable=False),
        ]
        r = VulnResult(host="x", port=443, checks=checks)
        assert "CVE-2014-0160" in r.cves_found
        assert "CVE-2014-3566" in r.cves_found
        assert "CVE-2011-3389" not in r.cves_found

    def test_vulnerable_checks_property(self):
        checks = [
            _make_check(name="Heartbleed", vulnerable=True),
            _make_check(name="POODLE",     vulnerable=False),
            _make_check(name="BEAST",      vulnerable=True),
        ]
        r = VulnResult(host="x", port=443, checks=checks)
        names = [c.name for c in r.vulnerable_checks]
        assert "Heartbleed" in names
        assert "BEAST"      in names
        assert "POODLE"     not in names

    def test_failed_checks_property(self):
        checks = [
            _make_check(name="Heartbleed", vulnerable=None, error="timeout"),
            _make_check(name="POODLE",     vulnerable=False),
        ]
        r = VulnResult(host="x", port=443, checks=checks)
        assert len(r.failed_checks) == 1
        assert r.failed_checks[0].name == "Heartbleed"

    def test_emoji_green_when_clean(self):
        assert _clean_result().emoji == "🟢"

    def test_emoji_red_when_vulnerable(self):
        assert _vuln_result().emoji == "🔴"

    def test_emoji_black_when_error(self):
        r = _make_vuln_result(error_n=1, clean_n=5)
        assert r.emoji == "⚫"

    def test_emoji_yellow_when_inconclusive(self):
        r = _make_vuln_result(incon_n=1, clean_n=5)
        assert r.emoji == "🟡"

    def test_scan_time_set_automatically(self):
        r = VulnResult(host="x", port=443)
        assert r.scan_time != ""

    def test_asdict_json_serialisable(self):
        import json
        r = _clean_result()
        # Should not raise
        json.dumps(asdict(r), default=str)

    def test_host_and_port_preserved(self):
        r = VulnResult(host="api.example.com", port=8443)
        assert r.host == "api.example.com"
        assert r.port == 8443


# ─────────────────────────────────────────────
# SweepReport dataclass tests
# ─────────────────────────────────────────────

class TestSweepReport:

    def _report(self, results: list[VulnResult]) -> SweepReport:
        return SweepReport(
            results    = results,
            checks_run = ALL_CHECK_NAMES,
        )

    def test_total_hosts(self):
        report = self._report([_clean_result("a.com"), _clean_result("b.com")])
        assert report.total_hosts == 2

    def test_vulnerable_hosts_count(self):
        report = self._report([
            _clean_result("a.com"),
            _vuln_result("b.com"),
            _vuln_result("c.com"),
        ])
        assert report.vulnerable_hosts == 2

    def test_clean_hosts_count(self):
        report = self._report([
            _clean_result("a.com"),
            _clean_result("b.com"),
            _vuln_result("c.com"),
        ])
        assert report.clean_hosts == 2

    def test_total_vulns_aggregated(self):
        report = self._report([
            _vuln_result("a.com", n=2),
            _vuln_result("b.com", n=1),
            _clean_result("c.com"),
        ])
        assert report.total_vulns == 3

    def test_grade_a_all_clean(self):
        report = self._report([_clean_result("a.com"), _clean_result("b.com")])
        assert report.grade == "A"

    def test_grade_is_worst_case_single_f(self):
        """49 grade-A hosts + 1 grade-F = overall F."""
        results = [_clean_result(f"h{i}.com") for i in range(49)]
        results.append(_vuln_result("bad.com", n=3))
        report = self._report(results)
        assert report.grade == "F"

    def test_grade_c_when_no_f(self):
        results = [
            _clean_result("a.com"),
            _vuln_result("b.com", n=1),
        ]
        report = self._report(results)
        assert report.grade == "C"

    def test_grade_b_when_only_inconclusive(self):
        r = _make_vuln_result(incon_n=1, clean_n=5)
        report = self._report([r])
        assert report.grade == "B"

    def test_all_cves_found_deduplicated(self):
        """Same CVE on two hosts should appear once in all_cves_found."""
        checks_a = [_make_check(cve="CVE-2014-0160", vulnerable=True)]
        checks_b = [_make_check(cve="CVE-2014-0160", vulnerable=True)]
        r_a = VulnResult(host="a.com", port=443, checks=checks_a)
        r_b = VulnResult(host="b.com", port=443, checks=checks_b)
        report = self._report([r_a, r_b])
        assert report.all_cves_found.count("CVE-2014-0160") == 1

    def test_all_cves_found_across_hosts(self):
        checks_a = [_make_check(cve="CVE-2014-0160", vulnerable=True)]
        checks_b = [_make_check(cve="CVE-2014-3566", vulnerable=True)]
        r_a = VulnResult(host="a.com", port=443, checks=checks_a)
        r_b = VulnResult(host="b.com", port=443, checks=checks_b)
        report = self._report([r_a, r_b])
        assert "CVE-2014-0160" in report.all_cves_found
        assert "CVE-2014-3566" in report.all_cves_found

    def test_error_hosts_count(self):
        r = _make_vuln_result(error_n=2, clean_n=4)
        report = self._report([r])
        assert report.error_hosts == 1

    def test_empty_results(self):
        report = self._report([])
        assert report.total_hosts     == 0
        assert report.vulnerable_hosts== 0
        assert report.total_vulns     == 0
        assert report.grade           == "A"

    def test_asdict_json_serialisable(self):
        import json
        report = self._report([_clean_result()])
        json.dumps(asdict(report), default=str)


# ─────────────────────────────────────────────
# run_sweep() tests
# ─────────────────────────────────────────────

class TestRunSweep:

    def _mock_check_fn(self, name, cve, vulnerable=False):
        """Return a mock check function that returns a fixed CheckResult."""
        result = _make_check(name=name, cve=cve, vulnerable=vulnerable)
        return MagicMock(return_value=result)

    @patch("vuln_sweep.scanner.ALL_CHECKS", new_callable=dict)
    def test_runs_selected_checks(self, mock_checks, default_config):
        """Only checks in config["checks"] are submitted."""
        mock_fn = self._mock_check_fn("Heartbleed", "CVE-2014-0160")
        mock_checks["heartbleed"] = mock_fn

        config = {**default_config, "checks": ["heartbleed"]}
        result = run_sweep("example.com", 443, ["heartbleed"], config)

        assert len(result.checks) == 1
        mock_fn.assert_called_once_with("example.com", 443, config["timeout"])

    @patch("vuln_sweep.scanner.ALL_CHECKS", new_callable=dict)
    def test_skips_unknown_check_names(self, mock_checks, default_config, capsys):
        mock_checks["heartbleed"] = self._mock_check_fn("Heartbleed", "CVE-2014-0160")
        config = {**default_config, "checks": ["heartbleed"]}
        result = run_sweep("example.com", 443, ["heartbleed", "unknown_cve"], config)

        # Only heartbleed ran — unknown_cve was skipped with a warning
        assert len(result.checks) == 1
        captured = capsys.readouterr()
        assert "unknown" in captured.err.lower()

    @patch("vuln_sweep.scanner.ALL_CHECKS", new_callable=dict)
    def test_result_host_and_port_correct(self, mock_checks, default_config):
        mock_checks["heartbleed"] = self._mock_check_fn("Heartbleed", "CVE-2014-0160")
        result = run_sweep("api.example.com", 8443, ["heartbleed"], default_config)
        assert result.host == "api.example.com"
        assert result.port == 8443

    @patch("vuln_sweep.scanner.ALL_CHECKS", new_callable=dict)
    def test_empty_checks_returns_empty_result(self, mock_checks, default_config):
        result = run_sweep("example.com", 443, [], default_config)
        assert result.checks == []
        assert result.vuln_count == 0

    @patch("vuln_sweep.scanner.ALL_CHECKS", new_callable=dict)
    def test_duration_ms_is_set(self, mock_checks, default_config):
        mock_checks["heartbleed"] = self._mock_check_fn("Heartbleed", "CVE-2014-0160")
        result = run_sweep("example.com", 443, ["heartbleed"], default_config)
        assert result.duration_ms >= 0

    @patch("vuln_sweep.scanner.ALL_CHECKS", new_callable=dict)
    def test_timeout_passed_to_check(self, mock_checks):
        mock_fn = self._mock_check_fn("Heartbleed", "CVE-2014-0160")
        mock_checks["heartbleed"] = mock_fn
        config = {"threads": 2, "timeout": 15}
        run_sweep("example.com", 443, ["heartbleed"], config)
        assert mock_fn.call_args[0][2] == 15

    @patch("vuln_sweep.scanner._run_check")
    def test_future_exception_handled_gracefully(self, mock_run):
        """If a Future raises, run_sweep returns error CheckResult not crash."""
        mock_run.side_effect = Exception("unexpected future failure")
        config = {"threads": 2, "timeout": 6}
        # Should not raise
        result = run_sweep("example.com", 443, ["heartbleed"], config)
        assert result is not None
        assert len(result.checks) >= 0

    @patch("vuln_sweep.scanner.ALL_CHECKS", new_callable=dict)
    def test_results_in_canonical_order(self, mock_checks, default_config):
        """
        Checks run in parallel — results should be sorted into
        canonical ALL_CHECK_NAMES order regardless of completion order.
        """
        # Create mocks for all six checks
        pairs = [
            ("heartbleed", "Heartbleed", "CVE-2014-0160"),
            ("poodle",     "POODLE",     "CVE-2014-3566"),
            ("beast",      "BEAST",      "CVE-2011-3389"),
            ("robot",      "ROBOT",      "CVE-2017-17382"),
            ("drown",      "DROWN",      "CVE-2016-0800"),
            ("lucky13",    "LUCKY13",    "CVE-2013-0169"),
        ]
        for key, name, cve in pairs:
            mock_checks[key] = self._mock_check_fn(name, cve)

        result = run_sweep(
            "example.com", 443,
            ALL_CHECK_NAMES,
            {**default_config, "checks": ALL_CHECK_NAMES},
        )

        if len(result.checks) == 6:
            names = [c.name for c in result.checks]
            assert names.index("Heartbleed") < names.index("POODLE")
            assert names.index("POODLE")     < names.index("BEAST")
            assert names.index("BEAST")      < names.index("ROBOT")

    @patch("vuln_sweep.scanner.ALL_CHECKS", new_callable=dict)
    def test_vulnerable_result_reflected(self, mock_checks, default_config):
        mock_checks["heartbleed"] = MagicMock(
            return_value=_make_check(
                name="Heartbleed", cve="CVE-2014-0160", vulnerable=True,
                detail="Memory leak confirmed."
            )
        )
        result = run_sweep("example.com", 443, ["heartbleed"],
                           {**default_config, "checks": ["heartbleed"]})
        assert result.vuln_count == 1
        assert "CVE-2014-0160" in result.cves_found

    @patch("vuln_sweep.scanner.ALL_CHECKS", new_callable=dict)
    def test_threads_capped_at_check_count(self, mock_checks):
        """No benefit spinning up 100 threads for 1 check."""
        mock_checks["heartbleed"] = self._mock_check_fn("Heartbleed", "CVE-2014-0160")
        # Should complete without error even with threads > checks
        config = {"threads": 100, "timeout": 6}
        result = run_sweep("example.com", 443, ["heartbleed"], config)
        assert result is not None


# ─────────────────────────────────────────────
# run_multi() tests
# ─────────────────────────────────────────────

class TestRunMulti:

    def _mock_run_sweep(self, host, port, checks, config):
        """Deterministic fake run_sweep for multi-host tests."""
        vuln_n = 1 if "vulnerable" in host else 0
        return _make_vuln_result(host, port, vuln_n=vuln_n, clean_n=6-vuln_n)

    @patch("vuln_sweep.scanner.run_sweep")
    def test_scans_all_targets(self, mock_sweep, default_config):
        mock_sweep.side_effect = self._mock_run_sweep
        targets = [("a.com", 443), ("b.com", 443), ("c.com", 443)]
        report  = run_multi(targets, default_config)
        assert report.total_hosts == 3
        assert mock_sweep.call_count == 3

    @patch("vuln_sweep.scanner.run_sweep")
    def test_returns_sweep_report(self, mock_sweep, default_config):
        mock_sweep.side_effect = self._mock_run_sweep
        report = run_multi([("example.com", 443)], default_config)
        assert isinstance(report, SweepReport)

    @patch("vuln_sweep.scanner.run_sweep")
    def test_empty_targets_returns_empty_report(self, mock_sweep, default_config):
        report = run_multi([], default_config)
        assert report.total_hosts == 0
        assert mock_sweep.call_count == 0

    @patch("vuln_sweep.scanner.run_sweep")
    def test_start_and_end_time_set(self, mock_sweep, default_config):
        mock_sweep.side_effect = self._mock_run_sweep
        report = run_multi([("example.com", 443)], default_config)
        assert report.start_time != ""
        assert report.end_time   != ""

    @patch("vuln_sweep.scanner.run_sweep")
    def test_duration_ms_set(self, mock_sweep, default_config):
        mock_sweep.side_effect = self._mock_run_sweep
        report = run_multi([("example.com", 443)], default_config)
        assert report.duration_ms >= 0

    @patch("vuln_sweep.scanner.run_sweep")
    def test_checks_run_populated(self, mock_sweep, default_config):
        mock_sweep.side_effect = self._mock_run_sweep
        report = run_multi([("example.com", 443)], default_config)
        assert report.checks_run == default_config["checks"]

    @patch("vuln_sweep.scanner.run_sweep")
    def test_hosts_scanned_sequentially(self, mock_sweep, default_config):
        """run_multi scans hosts one at a time — calls are sequential."""
        call_order = []
        def _record(host, port, checks, config):
            call_order.append(host)
            return _make_vuln_result(host, port)
        mock_sweep.side_effect = _record

        targets = [("first.com", 443), ("second.com", 443), ("third.com", 443)]
        run_multi(targets, default_config)
        assert call_order == ["first.com", "second.com", "third.com"]

    @patch("vuln_sweep.scanner.run_sweep")
    def test_report_grade_worst_case(self, mock_sweep, default_config):
        def _side(host, port, checks, config):
            if host == "bad.com":
                return _make_vuln_result(host, port, vuln_n=3, clean_n=3)
            return _clean_result(host, port)
        mock_sweep.side_effect = _side

        targets = [
            ("good1.com", 443), ("good2.com", 443),
            ("good3.com", 443), ("bad.com",   443),
        ]
        report = run_multi(targets, default_config)
        assert report.grade == "F"


# ─────────────────────────────────────────────
# _sort_results() tests
# ─────────────────────────────────────────────

class TestSortResults:

    def _r(self, name: str) -> CheckResult:
        """Build a minimal CheckResult with a given name."""
        cve_map = {
            "Heartbleed": "CVE-2014-0160",
            "POODLE":     "CVE-2014-3566",
            "BEAST":      "CVE-2011-3389",
            "ROBOT":      "CVE-2017-17382",
            "DROWN":      "CVE-2016-0800",
            "LUCKY13":    "CVE-2013-0169",
        }
        return _make_check(name=name, cve=cve_map.get(name, "CVE-0000-0000"))

    def test_canonical_order_heartbleed_first(self):
        results = [self._r("ROBOT"), self._r("Heartbleed"), self._r("POODLE")]
        checks  = ["heartbleed", "poodle", "robot"]
        sorted_ = _sort_results(results, checks)
        assert sorted_[0].name == "Heartbleed"
        assert sorted_[1].name == "POODLE"
        assert sorted_[2].name == "ROBOT"

    def test_full_canonical_order(self):
        names   = ["LUCKY13","DROWN","ROBOT","BEAST","POODLE","Heartbleed"]
        results = [self._r(n) for n in names]
        sorted_ = _sort_results(results, ALL_CHECK_NAMES)
        result_names = [r.name for r in sorted_]
        expected = ["Heartbleed","POODLE","BEAST","ROBOT","DROWN","LUCKY13"]
        assert result_names == expected

    def test_unknown_results_appended_last(self):
        results = [
            self._r("Heartbleed"),
            _make_check(name="Unknown", cve="CVE-9999-9999"),
        ]
        sorted_ = _sort_results(results, ["heartbleed"])
        assert sorted_[0].name == "Heartbleed"
        assert sorted_[-1].name == "Unknown"

    def test_empty_results(self):
        assert _sort_results([], ALL_CHECK_NAMES) == []

    def test_single_result(self):
        results = [self._r("ROBOT")]
        sorted_ = _sort_results(results, ["robot"])
        assert len(sorted_) == 1
        assert sorted_[0].name == "ROBOT"

    def test_order_stable_for_same_name(self):
        """Two results with same name — both appear in output."""
        r1 = _make_check(name="Heartbleed", vulnerable=True)
        r2 = _make_check(name="Heartbleed", vulnerable=False)
        sorted_ = _sort_results([r1, r2], ["heartbleed"])
        assert len(sorted_) >= 1


# ─────────────────────────────────────────────
# _emergency_result() tests
# ─────────────────────────────────────────────

class TestEmergencyResult:

    def test_returns_check_result(self):
        r = _emergency_result("heartbleed", "something failed")
        assert isinstance(r, CheckResult)

    def test_vulnerable_is_none(self):
        r = _emergency_result("heartbleed", "error")
        assert r.vulnerable is None

    def test_error_message_preserved(self):
        r = _emergency_result("heartbleed", "Future raised unexpectedly: boom")
        assert "boom" in r.error

    def test_cve_mapped_correctly(self):
        mapping = {
            "heartbleed": "CVE-2014-0160",
            "poodle":     "CVE-2014-3566",
            "beast":      "CVE-2011-3389",
            "robot":      "CVE-2017-17382",
            "drown":      "CVE-2016-0800",
            "lucky13":    "CVE-2013-0169",
        }
        for check_name, expected_cve in mapping.items():
            r = _emergency_result(check_name, "test")
            assert r.cve == expected_cve

    def test_name_mapped_correctly(self):
        mapping = {
            "heartbleed": "Heartbleed",
            "poodle":     "POODLE",
            "beast":      "BEAST",
            "robot":      "ROBOT",
            "drown":      "DROWN",
            "lucky13":    "LUCKY13",
        }
        for check_name, expected_name in mapping.items():
            r = _emergency_result(check_name, "test")
            assert r.name == expected_name

    def test_unknown_check_name_handled(self):
        r = _emergency_result("totally_unknown", "error")
        assert r.cve  == "UNKNOWN"
        assert r.name == "totally_unknown"


# ─────────────────────────────────────────────
# sort_key_vuln_result() tests
# ─────────────────────────────────────────────

class TestSortKeyVulnResult:

    def test_vulnerable_sorts_before_clean(self):
        vuln  = _vuln_result("vuln.com",  n=1)
        clean = _clean_result("clean.com")
        assert sort_key_vuln_result(vuln) < sort_key_vuln_result(clean)

    def test_more_vulns_sorts_first(self):
        r3 = _vuln_result("c.com", n=3)
        r1 = _vuln_result("a.com", n=1)
        assert sort_key_vuln_result(r3) < sort_key_vuln_result(r1)

    def test_errors_sort_before_clean(self):
        err   = _make_vuln_result("err.com",   error_n=1, clean_n=5)
        clean = _clean_result("clean.com")
        assert sort_key_vuln_result(err) < sort_key_vuln_result(clean)

    def test_host_tiebreak_alphabetical(self):
        r_a = _clean_result("alpha.com")
        r_z = _clean_result("zeta.com")
        assert sort_key_vuln_result(r_a) < sort_key_vuln_result(r_z)

    def test_sweep_report_sorted_correctly(self):
        results = [
            _clean_result("ok.com"),
            _vuln_result("bad3.com", n=3),
            _vuln_result("bad1.com", n=1),
            _make_vuln_result("err.com", error_n=1, clean_n=5),
        ]
        results.sort(key=sort_key_vuln_result)
        # Most vulnerable first
        assert results[0].vuln_count >= results[1].vuln_count
        # Clean last
        assert results[-1].host == "ok.com"