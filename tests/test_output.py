#!/usr/bin/env python3
"""
tests/test_output.py
━━━━━━━━━━━━━━━━━━━
Unit tests for vuln_sweep/output.py.

Tests cover:
  • print_banner()   — startup banner content and format
  • print_results()  — per-host result table
  • print_summary()  — multi-host sweep summary table
  • ANSI helpers     — colour functions, _ansi_overhead(), grade/status colours
  • _fmt_duration()  — millisecond to human string
  • _fmt_interval()  — seconds to human string
  • _active_outputs()— active formatter list from config

All tests capture stdout via capsys.
USE_COLOR is forced False so assertions match plain text.
"""

import os
import sys
from io import StringIO
from unittest.mock import patch

import pytest

from vuln_sweep.output import (
    print_banner,
    print_results,
    print_summary,
    _fmt_duration,
    _fmt_interval,
    _active_outputs,
    _grade_color,
    _status_color,
    _ansi_overhead,
    USE_COLOR,
)
from vuln_sweep.checks import ALL_CHECK_NAMES


# ─────────────────────────────────────────────
# Force plain text output for all tests
# ─────────────────────────────────────────────
# USE_COLOR is True when running in a TTY.
# We patch it False so assertions work on plain strings.

@pytest.fixture(autouse=True)
def no_color(monkeypatch):
    monkeypatch.setattr("vuln_sweep.output.USE_COLOR", False)


# ─────────────────────────────────────────────
# print_banner() tests
# ─────────────────────────────────────────────

class TestPrintBanner:

    def test_prints_tool_name(self, default_config, capsys):
        targets = [("example.com", 443)]
        print_banner(targets, default_config)
        out = capsys.readouterr().out
        assert "vuln-sweep" in out

    def test_prints_host_count(self, default_config, capsys):
        targets = [("a.com", 443), ("b.com", 443), ("c.com", 443)]
        print_banner(targets, default_config)
        out = capsys.readouterr().out
        assert "3" in out

    def test_prints_check_count(self, default_config, capsys):
        print_banner([("example.com", 443)], default_config)
        out = capsys.readouterr().out
        assert "6" in out

    def test_prints_timeout(self, default_config, capsys):
        print_banner([("example.com", 443)], default_config)
        out = capsys.readouterr().out
        assert str(default_config["timeout"]) in out

    def test_prints_threads(self, default_config, capsys):
        print_banner([("example.com", 443)], default_config)
        out = capsys.readouterr().out
        assert str(default_config["threads"]) in out

    def test_lists_cve_names(self, default_config, capsys):
        print_banner([("example.com", 443)], default_config)
        out = capsys.readouterr().out
        for name in ["Heartbleed", "POODLE", "BEAST", "ROBOT", "DROWN", "LUCKY13"]:
            assert name in out

    def test_lists_cve_ids(self, default_config, capsys):
        print_banner([("example.com", 443)], default_config)
        out = capsys.readouterr().out
        assert "CVE-2014-0160" in out

    def test_console_only_when_no_outputs(self, default_config, capsys):
        print_banner([("example.com", 443)], default_config)
        out = capsys.readouterr().out
        assert "console only" in out.lower() or "console" in out.lower()

    def test_shows_output_path_when_configured(self, capsys, default_config):
        config = {**default_config, "json_out": "/tmp/scan.json"}
        print_banner([("example.com", 443)], config)
        out = capsys.readouterr().out
        assert "/tmp/scan.json" in out

    def test_single_check_shows_singular_label(self, capsys):
        config = {
            "threads": 4, "timeout": 6,
            "checks": ["heartbleed"],
            "port": 443, "verbose": False,
            "json_out": None, "jsonl_out": None, "html_out": None,
        }
        print_banner([("example.com", 443)], config)
        out = capsys.readouterr().out
        assert "1 CVE" in out

    def test_empty_targets_no_crash(self, default_config, capsys):
        print_banner([], default_config)
        out = capsys.readouterr().out
        assert "vuln-sweep" in out


# ─────────────────────────────────────────────
# print_results() tests
# ─────────────────────────────────────────────

class TestPrintResults:

    def test_prints_host_and_port(self, clean_vuln_result, default_config, capsys):
        print_results(clean_vuln_result, default_config)
        out = capsys.readouterr().out
        assert "example.com" in out
        assert "443"         in out

    def test_prints_grade(self, clean_vuln_result, default_config, capsys):
        print_results(clean_vuln_result, default_config)
        out = capsys.readouterr().out
        assert "Grade A" in out or "A" in out

    def test_prints_all_cve_names(self, all_clean_checks,
                                   default_config, make_vuln_result, capsys):
        result = make_vuln_result(checks=all_clean_checks)
        print_results(result, default_config)
        out = capsys.readouterr().out
        for name in ["Heartbleed", "POODLE", "BEAST", "ROBOT", "DROWN", "LUCKY13"]:
            assert name in out

    def test_prints_not_vulnerable_for_clean(self, all_clean_checks,
                                              make_vuln_result,
                                              default_config, capsys):
        result = make_vuln_result(checks=all_clean_checks)
        print_results(result, default_config)
        out = capsys.readouterr().out
        assert "NOT VULNERABLE" in out

    def test_prints_vulnerable_for_finding(self, all_vuln_checks,
                                            make_vuln_result,
                                            default_config, capsys):
        result = make_vuln_result(checks=all_vuln_checks)
        print_results(result, default_config)
        out = capsys.readouterr().out
        assert "VULNERABLE" in out

    def test_vulnerable_expands_detail_without_verbose(self,
                                                        vuln_check,
                                                        make_vuln_result,
                                                        default_config, capsys):
        """Vulnerable findings always expand, even without --verbose."""
        result = make_vuln_result(checks=[vuln_check])
        print_results(result, default_config)
        out = capsys.readouterr().out
        assert vuln_check.detail in out

    def test_clean_does_not_expand_without_verbose(self, clean_check,
                                                    make_vuln_result,
                                                    default_config, capsys):
        """Clean checks do not expand in default mode."""
        result = make_vuln_result(checks=[clean_check])
        print_results(result, default_config)
        out = capsys.readouterr().out
        assert clean_check.detail not in out

    def test_verbose_expands_all_checks(self, all_clean_checks,
                                         make_vuln_result,
                                         verbose_config, capsys):
        """In verbose mode, all check details are shown."""
        result = make_vuln_result(checks=all_clean_checks)
        print_results(result, verbose_config)
        out = capsys.readouterr().out
        for check in all_clean_checks:
            if check.detail:
                assert check.detail in out

    def test_error_expands_with_error_message(self, error_check,
                                               make_vuln_result,
                                               default_config, capsys):
        result = make_vuln_result(checks=[error_check])
        print_results(result, default_config)
        out = capsys.readouterr().out
        assert error_check.error in out

    def test_prints_duration_ms(self, clean_vuln_result, default_config, capsys):
        print_results(clean_vuln_result, default_config)
        out = capsys.readouterr().out
        assert "ms" in out

    def test_prints_footer_counts_clean(self, all_clean_checks,
                                         make_vuln_result,
                                         default_config, capsys):
        result = make_vuln_result(checks=all_clean_checks)
        print_results(result, default_config)
        out = capsys.readouterr().out
        assert "CLEAN" in out

    def test_prints_footer_counts_vulnerable(self, all_vuln_checks,
                                              make_vuln_result,
                                              default_config, capsys):
        result = make_vuln_result(checks=all_vuln_checks)
        print_results(result, default_config)
        out = capsys.readouterr().out
        assert "VULNERABLE" in out

    def test_prints_remediation_hint_for_vulnerable(self, vuln_check,
                                                     make_vuln_result,
                                                     default_config, capsys):
        """Vulnerable findings include a remediation pointer."""
        result = make_vuln_result(checks=[vuln_check])
        print_results(result, default_config)
        out = capsys.readouterr().out
        assert "→" in out or "Upgrade" in out or "Disable" in out

    def test_prints_error_status_for_errored_check(self, error_check,
                                                     make_vuln_result,
                                                     default_config, capsys):
        result = make_vuln_result(checks=[error_check])
        print_results(result, default_config)
        out = capsys.readouterr().out
        assert "ERROR" in out

    def test_prints_inconclusive_status(self, inconclusive_check,
                                         make_vuln_result,
                                         default_config, capsys):
        result = make_vuln_result(checks=[inconclusive_check])
        print_results(result, default_config)
        out = capsys.readouterr().out
        assert "INCONCLUSIVE" in out

    def test_scan_time_shown_in_header(self, clean_vuln_result,
                                        default_config, capsys):
        print_results(clean_vuln_result, default_config)
        out = capsys.readouterr().out
        assert "UTC" in out

    def test_separator_lines_present(self, clean_vuln_result,
                                      default_config, capsys):
        print_results(clean_vuln_result, default_config)
        out = capsys.readouterr().out
        assert "─" in out

    def test_does_not_raise_on_empty_checks(self, default_config,
                                             make_vuln_result, capsys):
        result = make_vuln_result(checks=[])
        # Should not raise
        print_results(result, default_config)


# ─────────────────────────────────────────────
# print_summary() tests
# ─────────────────────────────────────────────

class TestPrintSummary:

    def test_prints_sweep_complete(self, clean_sweep_report,
                                    default_config, capsys):
        print_summary(clean_sweep_report, default_config)
        out = capsys.readouterr().out
        assert "SWEEP COMPLETE" in out

    def test_prints_host_count(self, clean_sweep_report,
                                default_config, capsys):
        print_summary(clean_sweep_report, default_config)
        out = capsys.readouterr().out
        assert str(clean_sweep_report.total_hosts) in out

    def test_prints_each_host(self, clean_sweep_report,
                               default_config, capsys):
        print_summary(clean_sweep_report, default_config)
        out = capsys.readouterr().out
        for result in clean_sweep_report.results:
            assert result.host in out

    def test_prints_grades(self, mixed_sweep_report,
                            default_config, capsys):
        print_summary(mixed_sweep_report, default_config)
        out = capsys.readouterr().out
        assert "A" in out or "F" in out or "C" in out

    def test_prints_vuln_count_per_host(self, mixed_sweep_report,
                                         default_config, capsys):
        print_summary(mixed_sweep_report, default_config)
        out = capsys.readouterr().out
        # At least one host has findings
        assert "finding" in out.lower() or "vulnerable" in out.lower()

    def test_prints_total_findings(self, mixed_sweep_report,
                                    default_config, capsys):
        print_summary(mixed_sweep_report, default_config)
        out = capsys.readouterr().out
        assert "Total findings" in out or str(mixed_sweep_report.total_vulns) in out

    def test_clean_hosts_shown_as_clean(self, clean_sweep_report,
                                         default_config, capsys):
        print_summary(clean_sweep_report, default_config)
        out = capsys.readouterr().out
        assert "Clean" in out or "clean" in out

    def test_summary_separator_lines(self, clean_sweep_report,
                                      default_config, capsys):
        print_summary(clean_sweep_report, default_config)
        out = capsys.readouterr().out
        assert "═" in out

    def test_empty_report_no_crash(self, make_sweep_report,
                                    default_config, capsys):
        report = make_sweep_report(results=[])
        print_summary(report, default_config)


# ─────────────────────────────────────────────
# Formatting helpers
# ─────────────────────────────────────────────

class TestFmtDuration:

    def test_ms_below_one_second(self):
        assert "ms" in _fmt_duration(450.0)
        assert "450" in _fmt_duration(450.0)

    def test_exactly_one_second(self):
        result = _fmt_duration(1000.0)
        assert "1.0s" in result or "1s" in result

    def test_fractional_seconds(self):
        result = _fmt_duration(1500.0)
        assert "1.5s" in result

    def test_zero_ms(self):
        result = _fmt_duration(0.0)
        assert "0" in result

    def test_large_duration(self):
        result = _fmt_duration(5000.0)
        assert "5" in result
        assert "s" in result


class TestFmtInterval:

    def test_exact_hours(self):
        assert _fmt_interval(3600) == "1h"
        assert _fmt_interval(7200) == "2h"

    def test_exact_minutes(self):
        assert _fmt_interval(60)  == "1m"
        assert _fmt_interval(120) == "2m"

    def test_seconds_only(self):
        assert _fmt_interval(45)  == "45s"
        assert _fmt_interval(1)   == "1s"

    def test_hours_and_minutes(self):
        result = _fmt_interval(3660)
        assert "1h" in result
        assert "1m" in result

    def test_minutes_and_seconds(self):
        result = _fmt_interval(90)
        assert "1m" in result
        assert "30s" in result

    def test_zero_seconds(self):
        assert "0" in _fmt_interval(0)


class TestActiveOutputs:

    def test_no_outputs_configured(self, default_config):
        result = _active_outputs(default_config)
        assert result == []

    def test_json_out_active(self, default_config):
        config = {**default_config, "json_out": "/tmp/scan.json"}
        result = _active_outputs(config)
        assert any("json_out" in r or "scan.json" in r for r in result)

    def test_html_out_active(self, default_config):
        config = {**default_config, "html_out": "/tmp/report.html"}
        result = _active_outputs(config)
        assert any("html_out" in r or "report.html" in r for r in result)

    def test_jsonl_out_active(self, default_config):
        config = {**default_config, "jsonl_out": "/tmp/audit.jsonl"}
        result = _active_outputs(config)
        assert any("jsonl_out" in r or "audit.jsonl" in r for r in result)

    def test_multiple_outputs_all_listed(self, output_config):
        result = _active_outputs(output_config)
        assert len(result) == 3

    def test_none_paths_not_listed(self, default_config):
        result = _active_outputs(default_config)
        assert len(result) == 0


# ─────────────────────────────────────────────
# ANSI helpers
# ─────────────────────────────────────────────

class TestAnsiOverhead:

    def test_plain_string_zero_overhead(self):
        assert _ansi_overhead("hello world") == 0

    def test_overhead_zero_when_no_color(self):
        """USE_COLOR is patched False so all overhead is 0."""
        assert _ansi_overhead("\033[31;1mred\033[0m") == 0

    def test_overhead_counted_when_color_on(self, monkeypatch):
        monkeypatch.setattr("vuln_sweep.output.USE_COLOR", True)
        s = "\033[31;1mred\033[0m"
        overhead = _ansi_overhead(s)
        assert overhead > 0
        # Visible text is "red" (3 chars), total with escapes is len(s)
        assert overhead == len(s) - 3

    def test_empty_string(self):
        assert _ansi_overhead("") == 0


class TestGradeColor:

    def test_grade_a_returns_string(self):
        assert isinstance(_grade_color("A", "A"), str)

    def test_grade_f_returns_string(self):
        assert isinstance(_grade_color("F", "F"), str)

    def test_all_grades_produce_output(self):
        for grade in ("A", "B", "C", "F"):
            result = _grade_color(grade, grade)
            assert grade in result

    def test_unknown_grade_returns_text(self):
        result = _grade_color("Z", "Z")
        assert "Z" in result


class TestStatusColor:

    def test_vulnerable_true_returns_string_with_text(self):
        result = _status_color(True)
        assert "VULNERABLE" in result

    def test_vulnerable_false_returns_string_with_text(self):
        result = _status_color(False)
        assert "NOT VULNERABLE" in result

    def test_vulnerable_none_returns_string_with_text(self):
        result = _status_color(None)
        assert "INCONCLUSIVE" in result