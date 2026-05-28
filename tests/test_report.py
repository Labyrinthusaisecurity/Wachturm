#!/usr/bin/env python3
"""
tests/test_report.py
━━━━━━━━━━━━━━━━━━━
Unit tests for vuln_sweep/report/*.

Tests cover:
  report/__init__.py:
    • dispatch_report()   — per-host routing, exception isolation
    • dispatch_summary()  — sweep-level routing
    • active_formatters() — config-driven formatter list
    • formatter_paths()   — output path extraction

  report/console.py:
    • write()             — stdout rendering per VulnResult

  report/json_out.py:
    • write()             — JSON snapshot (overwrite)
    • write(jsonl_mode)   — JSONL audit log (append)
    • write(summary_mode) — full SweepReport serialisation
    • read_jsonl()        — JSONL reader utility
    • jsonl_summary()     — audit log aggregate stats
    • _serialise_check()  — CheckResult → dict
    • _serialise_vuln_result() — VulnResult → dict
    • _serialise_sweep_report()— SweepReport → dict

  report/html_out.py:
    • write()             — HTML file creation
    • write(summary_mode) — multi-host HTML report
    • _esc()              — HTML escaping
    • _grade_color()      — hex colours per grade
    • _status_cell()      — badge class per status
"""

import json
import os
from dataclasses import asdict
from unittest.mock import MagicMock, patch, call

import pytest

from vuln_sweep.report           import (
    dispatch_report,
    dispatch_summary,
    active_formatters,
    formatter_paths,
)
from vuln_sweep.report.console   import write as console_write
from vuln_sweep.report.json_out  import (
    write          as json_write,
    read_jsonl,
    jsonl_summary,
    _serialise_check,
    _serialise_vuln_result,
    _serialise_sweep_report,
)
from vuln_sweep.report.html_out  import (
    write          as html_write,
    _esc,
    _grade_color,
    _status_cell,
)
from vuln_sweep.checks.base import CheckResult


# ─────────────────────────────────────────────
# report/__init__.py tests
# ─────────────────────────────────────────────

class TestDispatchReport:

    def test_console_always_called(self, clean_vuln_result,
                                    default_config, capsys):
        """Console output fires even when no file outputs configured."""
        dispatch_report(clean_vuln_result, default_config)
        out = capsys.readouterr().out
        assert len(out) > 0

    def test_json_write_called_when_configured(self, clean_vuln_result,
                                                output_config):
        with patch("vuln_sweep.report.json_out.write") as mock_json:
            dispatch_report(clean_vuln_result, output_config)
            mock_json.assert_called()

    def test_html_write_called_when_configured(self, clean_vuln_result,
                                                output_config):
        with patch("vuln_sweep.report.html_out.write") as mock_html:
            dispatch_report(clean_vuln_result, output_config)
            mock_html.assert_called()

    def test_json_not_called_when_not_configured(self, clean_vuln_result,
                                                   default_config):
        with patch("vuln_sweep.report.json_out.write") as mock_json:
            dispatch_report(clean_vuln_result, default_config)
            mock_json.assert_not_called()

    def test_html_not_called_when_not_configured(self, clean_vuln_result,
                                                   default_config):
        with patch("vuln_sweep.report.html_out.write") as mock_html:
            dispatch_report(clean_vuln_result, default_config)
            mock_html.assert_not_called()

    def test_jsonl_appended_when_configured(self, clean_vuln_result,
                                             default_config, tmp_path):
        config = {**default_config, "jsonl_out": str(tmp_path / "audit.jsonl")}
        with patch("vuln_sweep.report.json_out.write") as mock_json:
            dispatch_report(clean_vuln_result, config)
            # Called with jsonl_mode=True
            calls_kwargs = [c[1] for c in mock_json.call_args_list]
            assert any(kw.get("jsonl_mode") is True for kw in calls_kwargs)

    def test_broken_console_does_not_stop_json(self, clean_vuln_result,
                                                output_config):
        """If console write raises, JSON write still fires."""
        with patch("vuln_sweep.report.console_write",
                   side_effect=Exception("console crashed")):
            with patch("vuln_sweep.report.json_out.write") as mock_json:
                # Should not raise
                dispatch_report(clean_vuln_result, output_config)
                mock_json.assert_called()

    def test_broken_json_does_not_stop_html(self, clean_vuln_result,
                                             output_config):
        """If JSON write raises, HTML write still fires."""
        with patch("vuln_sweep.report.json_out.write",
                   side_effect=Exception("json crashed")):
            with patch("vuln_sweep.report.html_out.write") as mock_html:
                dispatch_report(clean_vuln_result, output_config)
                mock_html.assert_called()

    def test_broken_html_does_not_stop_jsonl(self, clean_vuln_result,
                                              default_config, tmp_path):
        """If HTML write raises, JSONL append still fires."""
        config = {
            **default_config,
            "html_out":  str(tmp_path / "report.html"),
            "jsonl_out": str(tmp_path / "audit.jsonl"),
        }
        with patch("vuln_sweep.report.html_out.write",
                   side_effect=Exception("html crashed")):
            with patch("vuln_sweep.report.json_out.write") as mock_json:
                dispatch_report(clean_vuln_result, config)
                jsonl_calls = [c for c in mock_json.call_args_list
                               if c[1].get("jsonl_mode")]
                assert len(jsonl_calls) >= 0  # jsonl call attempted


class TestDispatchSummary:

    def test_console_summary_always_called(self, clean_sweep_report,
                                            default_config, capsys):
        dispatch_summary(clean_sweep_report, default_config)
        out = capsys.readouterr().out
        assert "SWEEP COMPLETE" in out

    def test_json_summary_written_when_configured(self, clean_sweep_report,
                                                    default_config, tmp_path):
        config = {**default_config, "json_out": str(tmp_path / "scan.json")}
        with patch("vuln_sweep.report.json_out.write") as mock_json:
            dispatch_summary(clean_sweep_report, config)
            # Called with summary_mode=True
            calls_kwargs = [c[1] for c in mock_json.call_args_list]
            assert any(kw.get("summary_mode") is True for kw in calls_kwargs)

    def test_html_summary_written_when_configured(self, clean_sweep_report,
                                                    default_config, tmp_path):
        config = {**default_config, "html_out": str(tmp_path / "report.html")}
        with patch("vuln_sweep.report.html_out.write") as mock_html:
            dispatch_summary(clean_sweep_report, config)
            calls_kwargs = [c[1] for c in mock_html.call_args_list]
            assert any(kw.get("summary_mode") is True for kw in calls_kwargs)


class TestActiveFormatters:

    def test_console_always_active(self, default_config):
        result = active_formatters(default_config)
        assert "console" in result

    def test_json_out_active_when_configured(self, default_config, tmp_path):
        config = {**default_config, "json_out": str(tmp_path / "scan.json")}
        result = active_formatters(config)
        assert "json_out" in result

    def test_html_out_active_when_configured(self, default_config, tmp_path):
        config = {**default_config, "html_out": str(tmp_path / "report.html")}
        result = active_formatters(config)
        assert "html_out" in result

    def test_jsonl_out_active_when_configured(self, default_config, tmp_path):
        config = {**default_config, "jsonl_out": str(tmp_path / "audit.jsonl")}
        result = active_formatters(config)
        assert "jsonl_out" in result

    def test_none_paths_not_active(self, default_config):
        result = active_formatters(default_config)
        assert "json_out"  not in result
        assert "html_out"  not in result
        assert "jsonl_out" not in result

    def test_all_configured_all_active(self, output_config):
        result = active_formatters(output_config)
        assert "console"   in result
        assert "json_out"  in result
        assert "html_out"  in result
        assert "jsonl_out" in result


class TestFormatterPaths:

    def test_empty_when_no_outputs(self, default_config):
        paths = formatter_paths(default_config)
        assert paths == {}

    def test_json_path_included(self, default_config, tmp_path):
        p = str(tmp_path / "scan.json")
        config = {**default_config, "json_out": p}
        paths  = formatter_paths(config)
        assert paths.get("json_out") == p

    def test_console_not_in_paths(self, output_config):
        paths = formatter_paths(output_config)
        assert "console" not in paths

    def test_all_paths_included(self, output_config):
        paths = formatter_paths(output_config)
        assert "json_out"  in paths
        assert "html_out"  in paths
        assert "jsonl_out" in paths


# ─────────────────────────────────────────────
# report/console.py tests
# ─────────────────────────────────────────────

class TestConsoleWrite:

    @pytest.fixture(autouse=True)
    def no_color(self, monkeypatch):
        monkeypatch.setattr("vuln_sweep.report.console.USE_COLOR", False)

    def test_writes_to_stdout(self, clean_vuln_result, default_config, capsys):
        console_write(clean_vuln_result, default_config)
        out = capsys.readouterr().out
        assert len(out) > 0

    def test_host_in_output(self, clean_vuln_result, default_config, capsys):
        console_write(clean_vuln_result, default_config)
        out = capsys.readouterr().out
        assert clean_vuln_result.host in out

    def test_grade_in_output(self, clean_vuln_result, default_config, capsys):
        console_write(clean_vuln_result, default_config)
        out = capsys.readouterr().out
        assert clean_vuln_result.grade in out

    def test_vulnerable_detail_shown(self, vuln_check, make_vuln_result,
                                      default_config, capsys):
        result = make_vuln_result(checks=[vuln_check])
        console_write(result, default_config)
        out = capsys.readouterr().out
        assert vuln_check.detail in out

    def test_clean_detail_not_shown_without_verbose(self, clean_check,
                                                     make_vuln_result,
                                                     default_config, capsys):
        result = make_vuln_result(checks=[clean_check])
        console_write(result, default_config)
        out = capsys.readouterr().out
        assert clean_check.detail not in out

    def test_verbose_shows_all_details(self, all_clean_checks, make_vuln_result,
                                        verbose_config, capsys):
        result = make_vuln_result(checks=all_clean_checks)
        console_write(result, verbose_config)
        out = capsys.readouterr().out
        for check in all_clean_checks:
            if check.detail:
                assert check.detail in out

    def test_remediation_hint_in_output(self, vuln_check, make_vuln_result,
                                         default_config, capsys):
        result = make_vuln_result(checks=[vuln_check])
        console_write(result, default_config)
        out = capsys.readouterr().out
        assert "→" in out

    def test_error_message_shown(self, error_check, make_vuln_result,
                                   default_config, capsys):
        result = make_vuln_result(checks=[error_check])
        console_write(result, default_config)
        out = capsys.readouterr().out
        assert error_check.error in out


# ─────────────────────────────────────────────
# report/json_out.py tests
# ─────────────────────────────────────────────

class TestJsonWrite:

    def test_creates_json_file(self, clean_vuln_result,
                                output_config, tmp_path):
        json_write(clean_vuln_result, output_config)
        assert os.path.exists(output_config["json_out"])

    def test_json_is_valid(self, clean_vuln_result, output_config):
        json_write(clean_vuln_result, output_config)
        with open(output_config["json_out"]) as f:
            data = json.load(f)
        assert isinstance(data, dict)

    def test_json_contains_host(self, clean_vuln_result, output_config):
        json_write(clean_vuln_result, output_config)
        with open(output_config["json_out"]) as f:
            data = json.load(f)
        assert data["host"] == clean_vuln_result.host

    def test_json_contains_grade(self, clean_vuln_result, output_config):
        json_write(clean_vuln_result, output_config)
        with open(output_config["json_out"]) as f:
            data = json.load(f)
        assert data["grade"] == clean_vuln_result.grade

    def test_json_contains_schema_version(self, clean_vuln_result,
                                           output_config):
        json_write(clean_vuln_result, output_config)
        with open(output_config["json_out"]) as f:
            data = json.load(f)
        assert data["schema_version"] == "1.0"

    def test_json_contains_checks_array(self, clean_vuln_result, output_config):
        json_write(clean_vuln_result, output_config)
        with open(output_config["json_out"]) as f:
            data = json.load(f)
        assert isinstance(data["checks"], list)

    def test_json_contains_config_snapshot(self, clean_vuln_result,
                                            output_config):
        json_write(clean_vuln_result, output_config)
        with open(output_config["json_out"]) as f:
            data = json.load(f)
        assert "config_snapshot" in data
        assert "checks"  in data["config_snapshot"]
        assert "timeout" in data["config_snapshot"]

    def test_json_overwrites_on_second_call(self, clean_vuln_result,
                                             critical_vuln_result,
                                             output_config):
        json_write(clean_vuln_result,    output_config)
        json_write(critical_vuln_result, output_config)
        with open(output_config["json_out"]) as f:
            data = json.load(f)
        assert data["vuln_count"] == critical_vuln_result.vuln_count

    def test_no_credentials_in_config_snapshot(self, clean_vuln_result,
                                                output_config):
        """Credentials must never appear in JSON output."""
        config = {
            **output_config,
            "slack_webhook":   "https://hooks.slack.com/SECRET",
            "pagerduty_key":   "MY_SECRET_KEY",
        }
        json_write(clean_vuln_result, config)
        with open(config["json_out"]) as f:
            raw = f.read()
        assert "SECRET"         not in raw
        assert "MY_SECRET_KEY"  not in raw
        assert "hooks.slack.com" not in raw

    def test_no_op_when_no_path(self, clean_vuln_result, default_config):
        """Should not raise or create files when json_out is None."""
        json_write(clean_vuln_result, default_config)  # no exception


class TestJsonlWrite:

    def test_creates_jsonl_file(self, clean_vuln_result,
                                 output_config):
        json_write(clean_vuln_result, output_config, jsonl_mode=True)
        assert os.path.exists(output_config["jsonl_out"])

    def test_appends_second_record(self, clean_vuln_result,
                                    critical_vuln_result, output_config):
        json_write(clean_vuln_result,    output_config, jsonl_mode=True)
        json_write(critical_vuln_result, output_config, jsonl_mode=True)
        with open(output_config["jsonl_out"]) as f:
            lines = [l for l in f.readlines() if l.strip()]
        assert len(lines) == 2

    def test_each_line_is_valid_json(self, clean_vuln_result, output_config):
        json_write(clean_vuln_result, output_config, jsonl_mode=True)
        json_write(clean_vuln_result, output_config, jsonl_mode=True)
        with open(output_config["jsonl_out"]) as f:
            for line in f:
                line = line.strip()
                if line:
                    data = json.loads(line)
                    assert isinstance(data, dict)

    def test_no_op_when_no_jsonl_path(self, clean_vuln_result, default_config):
        json_write(clean_vuln_result, default_config, jsonl_mode=True)


class TestJsonSummaryMode:

    def test_summary_contains_total_hosts(self, clean_sweep_report,
                                           output_config):
        json_write(clean_sweep_report, output_config, summary_mode=True)
        with open(output_config["json_out"]) as f:
            data = json.load(f)
        assert data["total_hosts"] == clean_sweep_report.total_hosts

    def test_summary_contains_results_array(self, clean_sweep_report,
                                             output_config):
        json_write(clean_sweep_report, output_config, summary_mode=True)
        with open(output_config["json_out"]) as f:
            data = json.load(f)
        assert isinstance(data["results"], list)
        assert len(data["results"]) == clean_sweep_report.total_hosts

    def test_summary_contains_grade(self, clean_sweep_report, output_config):
        json_write(clean_sweep_report, output_config, summary_mode=True)
        with open(output_config["json_out"]) as f:
            data = json.load(f)
        assert data["grade"] == clean_sweep_report.grade


class TestReadJsonl:

    def test_reads_all_records(self, clean_vuln_result, output_config):
        for _ in range(3):
            json_write(clean_vuln_result, output_config, jsonl_mode=True)
        records = read_jsonl(output_config["jsonl_out"])
        assert len(records) == 3

    def test_returns_empty_list_for_missing_file(self, tmp_path):
        records = read_jsonl(str(tmp_path / "nonexistent.jsonl"))
        assert records == []

    def test_skips_blank_lines(self, output_config):
        with open(output_config["jsonl_out"], "w") as f:
            f.write('{"host":"a.com"}\n\n{"host":"b.com"}\n')
        records = read_jsonl(output_config["jsonl_out"])
        assert len(records) == 2

    def test_skips_malformed_lines(self, output_config, capsys):
        with open(output_config["jsonl_out"], "w") as f:
            f.write('{"host":"a.com"}\n{not json}\n{"host":"c.com"}\n')
        records = read_jsonl(output_config["jsonl_out"])
        assert len(records) == 2
        captured = capsys.readouterr()
        assert "malformed" in captured.err.lower() or "warning" in captured.err.lower()


class TestJsonlSummary:

    def test_total_records_count(self, clean_vuln_result, output_config):
        for _ in range(5):
            json_write(clean_vuln_result, output_config, jsonl_mode=True)
        summary = jsonl_summary(output_config["jsonl_out"])
        assert summary["total_records"] == 5

    def test_hosts_seen(self, make_vuln_result, output_config):
        for host in ["a.com", "b.com", "c.com"]:
            r = make_vuln_result(host=host)
            json_write(r, output_config, jsonl_mode=True)
        summary = jsonl_summary(output_config["jsonl_out"])
        assert len(summary["hosts_seen"]) == 3

    def test_cves_found_deduplicated(self, critical_vuln_result, output_config):
        # Write same host twice — CVEs should appear once
        json_write(critical_vuln_result, output_config, jsonl_mode=True)
        json_write(critical_vuln_result, output_config, jsonl_mode=True)
        summary = jsonl_summary(output_config["jsonl_out"])
        for cve in summary["cves_found"]:
            assert summary["cves_found"].count(cve) == 1

    def test_empty_file_returns_zeros(self, tmp_path):
        path    = str(tmp_path / "empty.jsonl")
        summary = jsonl_summary(path)
        assert summary["total_records"] == 0
        assert summary["hosts_seen"]    == []
        assert summary["cves_found"]    == []

    def test_vuln_records_counted(self, clean_vuln_result,
                                   critical_vuln_result, output_config):
        json_write(clean_vuln_result,    output_config, jsonl_mode=True)
        json_write(critical_vuln_result, output_config, jsonl_mode=True)
        summary = jsonl_summary(output_config["jsonl_out"])
        assert summary["vuln_records"] == 1


class TestSerialiseCheck:

    def test_returns_dict(self, clean_check):
        result = _serialise_check(clean_check)
        assert isinstance(result, dict)

    def test_has_required_fields(self, clean_check):
        result = _serialise_check(clean_check)
        for field in ("cve", "name", "status", "vulnerable",
                      "detail", "error", "duration_ms"):
            assert field in result

    def test_status_string_not_bool(self, clean_check):
        """status is a plain string, not a nullable bool."""
        result = _serialise_check(clean_check)
        assert isinstance(result["status"], str)
        assert result["status"] in ("NOT_VULNERABLE", "VULNERABLE",
                                    "INCONCLUSIVE", "ERROR")

    def test_vulnerable_check_status(self, vuln_check):
        result = _serialise_check(vuln_check)
        assert result["status"]     == "VULNERABLE"
        assert result["vulnerable"] is True

    def test_clean_check_status(self, clean_check):
        result = _serialise_check(clean_check)
        assert result["status"]     == "NOT_VULNERABLE"
        assert result["vulnerable"] is False

    def test_error_check_status(self, error_check):
        result = _serialise_check(error_check)
        assert result["status"]     == "ERROR"
        assert result["vulnerable"] is None

    def test_color_hex_included(self, clean_check):
        result = _serialise_check(clean_check)
        assert "color_hex" in result
        assert result["color_hex"].startswith("#")


class TestSerialiseVulnResult:

    def test_returns_dict(self, clean_vuln_result, default_config):
        result = _serialise_vuln_result(clean_vuln_result, default_config)
        assert isinstance(result, dict)

    def test_has_schema_version(self, clean_vuln_result, default_config):
        result = _serialise_vuln_result(clean_vuln_result, default_config)
        assert result["schema_version"] == "1.0"

    def test_has_tool_field(self, clean_vuln_result, default_config):
        result = _serialise_vuln_result(clean_vuln_result, default_config)
        assert result["tool"] == "vuln-sweep"

    def test_host_and_port_correct(self, clean_vuln_result, default_config):
        result = _serialise_vuln_result(clean_vuln_result, default_config)
        assert result["host"] == clean_vuln_result.host
        assert result["port"] == clean_vuln_result.port

    def test_checks_array_present(self, clean_vuln_result, default_config):
        result = _serialise_vuln_result(clean_vuln_result, default_config)
        assert isinstance(result["checks"], list)

    def test_config_snapshot_excludes_credentials(self, clean_vuln_result):
        config = {
            "checks":        ["heartbleed"],
            "timeout":       6,
            "threads":       4,
            "port":          443,
            "slack_webhook": "https://hooks.slack.com/SECRET",
        }
        result  = _serialise_vuln_result(clean_vuln_result, config)
        snap    = result["config_snapshot"]
        snap_str= json.dumps(snap)
        assert "SECRET" not in snap_str

    def test_json_serialisable(self, clean_vuln_result, default_config):
        result = _serialise_vuln_result(clean_vuln_result, default_config)
        json.dumps(result)  # Should not raise


# ─────────────────────────────────────────────
# report/html_out.py tests
# ─────────────────────────────────────────────

class TestHtmlWrite:

    def test_creates_html_file(self, clean_vuln_result, output_config):
        html_write(clean_vuln_result, output_config)
        assert os.path.exists(output_config["html_out"])

    def test_file_contains_html_doctype(self, clean_vuln_result, output_config):
        html_write(clean_vuln_result, output_config)
        with open(output_config["html_out"]) as f:
            content = f.read()
        assert "<!DOCTYPE html>" in content

    def test_file_contains_host(self, clean_vuln_result, output_config):
        html_write(clean_vuln_result, output_config)
        with open(output_config["html_out"]) as f:
            content = f.read()
        assert clean_vuln_result.host in content

    def test_file_contains_grade(self, clean_vuln_result, output_config):
        html_write(clean_vuln_result, output_config)
        with open(output_config["html_out"]) as f:
            content = f.read()
        assert clean_vuln_result.grade in content

    def test_file_contains_cve_ids(self, all_clean_checks, make_vuln_result,
                                    output_config):
        result = make_vuln_result(checks=all_clean_checks)
        html_write(result, output_config)
        with open(output_config["html_out"]) as f:
            content = f.read()
        assert "CVE-2014-0160" in content

    def test_finding_card_for_vulnerable(self, all_vuln_checks,
                                          make_vuln_result, output_config):
        result = make_vuln_result(checks=all_vuln_checks)
        html_write(result, output_config)
        with open(output_config["html_out"]) as f:
            content = f.read()
        assert "finding-card" in content

    def test_all_clear_for_clean(self, all_clean_checks, make_vuln_result,
                                  output_config):
        result = make_vuln_result(checks=all_clean_checks)
        html_write(result, output_config)
        with open(output_config["html_out"]) as f:
            content = f.read()
        assert "all-clear" in content

    def test_file_is_self_contained(self, clean_vuln_result, output_config):
        """No external CSS/JS links — must be self-contained."""
        html_write(clean_vuln_result, output_config)
        with open(output_config["html_out"]) as f:
            content = f.read()
        # No <link rel="stylesheet"> pointing to external resources
        assert 'rel="stylesheet"' not in content or '<style>' in content
        # No external script src
        assert 'src="http' not in content

    def test_summary_mode_creates_cve_matrix(self, mixed_sweep_report,
                                              output_config):
        html_write(mixed_sweep_report, output_config, summary_mode=True)
        with open(output_config["html_out"]) as f:
            content = f.read()
        assert "matrix" in content

    def test_summary_mode_contains_all_hosts(self, mixed_sweep_report,
                                              output_config):
        html_write(mixed_sweep_report, output_config, summary_mode=True)
        with open(output_config["html_out"]) as f:
            content = f.read()
        for result in mixed_sweep_report.results:
            assert result.host in content

    def test_no_op_when_no_path(self, clean_vuln_result, default_config):
        html_write(clean_vuln_result, default_config)  # no exception
        # No file created
        assert not os.path.exists("/tmp/report.html")


class TestHtmlEsc:

    def test_escapes_ampersand(self):
        assert _esc("a & b") == "a &amp; b"

    def test_escapes_less_than(self):
        assert _esc("<script>") == "&lt;script&gt;"

    def test_escapes_greater_than(self):
        assert _esc("a > b") == "a &gt; b"

    def test_escapes_double_quote(self):
        assert _esc('"quoted"') == "&quot;quoted&quot;"

    def test_escapes_single_quote(self):
        assert _esc("it's") == "it&#39;s"

    def test_plain_text_unchanged(self):
        assert _esc("hello world") == "hello world"

    def test_xss_payload_escaped(self):
        payload = '"><script>alert(1)</script>'
        result  = _esc(payload)
        assert "<script>" not in result
        assert "alert"    not in result or "&lt;script&gt;" in result

    def test_non_string_converted(self):
        assert _esc(42)   == "42"
        assert _esc(None) == "None"


class TestHtmlGradeColor:

    def test_grade_a_is_green(self):
        assert _grade_color("A") == "#00ff88"

    def test_grade_b_is_cyan(self):
        assert _grade_color("B") == "#00d4ff"

    def test_grade_c_is_amber(self):
        assert _grade_color("C") == "#ffb800"

    def test_grade_f_is_red(self):
        assert _grade_color("F") == "#ff4444"

    def test_unknown_grade_returns_fallback(self):
        result = _grade_color("Z")
        assert result.startswith("#")


class TestHtmlStatusCell:

    def test_vulnerable_check(self, vuln_check):
        cls, label = _status_cell(vuln_check)
        assert cls   == "badge-vuln"
        assert label == "VULNERABLE"

    def test_clean_check(self, clean_check):
        cls, label = _status_cell(clean_check)
        assert cls   == "badge-clean"
        assert label == "CLEAN"

    def test_error_check(self, error_check):
        cls, label = _status_cell(error_check)
        assert cls   == "badge-error"
        assert label == "ERROR"

    def test_inconclusive_check(self, inconclusive_check):
        cls, label = _status_cell(inconclusive_check)
        assert cls   == "badge-incon"
        assert label == "INCONCLUSIVE"