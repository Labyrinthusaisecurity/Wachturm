#!/usr/bin/env python3
"""
tests/test_config.py
━━━━━━━━━━━━━━━━━━━
Unit tests for vuln_sweep/config.py.

Tests cover:
  • ALL_CHECK_NAMES and DEFAULT_CHECKS constants
  • DEFAULT_CONFIG values and mutation safety
  • load_config()     — JSON loading, validation, _comment stripping
  • _load_env()       — VULN_SWEEP_* environment variable resolution
  • build_config()    — priority merge (CLI > env > file > defaults)
  • _resolve_checks() — CVE check selection logic
  • parse_targets()   — target string parsing, deduplication, CIDR handling
  • _validate_config()— type checking and unknown key warnings
  • _merge()          — shallow merge behaviour

No real files are written — all file I/O uses pytest tmp_path.
No real environment variables are set — all patched via patch.dict.
"""

import json
import os
from argparse import Namespace
from unittest.mock import patch

import pytest

from vuln_sweep.config import (
    ALL_CHECK_NAMES,
    DEFAULT_CHECKS,
    DEFAULT_CONFIG,
    _load_env,
    _merge,
    _resolve_checks,
    _validate_config,
    build_config,
    load_config,
    parse_targets,
)


# ─────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────

def _args(**kwargs) -> Namespace:
    """
    Build a minimal argparse Namespace for build_config().
    Sets every expected attribute to a safe default (None/False)
    then applies kwargs overrides.
    """
    defaults = dict(
        target   = None,
        file     = None,
        config   = None,
        port     = None,
        threads  = None,
        timeout  = None,
        once     = False,
        verbose  = False,
        all      = False,
        json_out = None,
        jsonl_out= None,
        html_out = None,
        # Per-CVE flags
        heartbleed = False,
        poodle     = False,
        beast      = False,
        robot      = False,
        drown      = False,
        lucky13    = False,
    )
    defaults.update(kwargs)
    return Namespace(**defaults)


def _write_json(tmp_path, data: dict) -> str:
    """Write a JSON config file and return its path string."""
    p = tmp_path / "vuln-sweep.json"
    p.write_text(json.dumps(data))
    return str(p)


def _clean_env() -> dict:
    """Return os.environ without any VULN_SWEEP_* keys."""
    return {k: v for k, v in os.environ.items()
            if not k.startswith("VULN_SWEEP_")}


# ─────────────────────────────────────────────
# ALL_CHECK_NAMES and DEFAULT_CHECKS
# ─────────────────────────────────────────────

class TestCheckNameConstants:

    def test_all_check_names_has_six_entries(self):
        assert len(ALL_CHECK_NAMES) == 6

    def test_all_check_names_contains_expected(self):
        expected = {"heartbleed", "poodle", "beast", "robot", "drown", "lucky13"}
        assert set(ALL_CHECK_NAMES) == expected

    def test_all_check_names_is_list(self):
        assert isinstance(ALL_CHECK_NAMES, list)

    def test_default_checks_equals_all_check_names(self):
        assert DEFAULT_CHECKS == ALL_CHECK_NAMES

    def test_default_checks_is_independent_copy(self):
        """Mutating DEFAULT_CHECKS must not affect ALL_CHECK_NAMES."""
        original = ALL_CHECK_NAMES.copy()
        DEFAULT_CHECKS.append("injected")
        DEFAULT_CHECKS.remove("injected")
        assert ALL_CHECK_NAMES == original

    def test_canonical_order_heartbleed_first(self):
        assert ALL_CHECK_NAMES[0] == "heartbleed"

    def test_canonical_order_lucky13_last(self):
        assert ALL_CHECK_NAMES[-1] == "lucky13"


# ─────────────────────────────────────────────
# DEFAULT_CONFIG
# ─────────────────────────────────────────────

class TestDefaultConfig:

    def test_has_required_keys(self):
        required = (
            "targets", "checks", "threads", "timeout", "port",
            "json_out", "jsonl_out", "html_out", "verbose", "once",
        )
        for key in required:
            assert key in DEFAULT_CONFIG, f"Missing key: {key}"

    def test_targets_is_empty_list(self):
        assert DEFAULT_CONFIG["targets"] == []

    def test_checks_is_all_check_names(self):
        assert DEFAULT_CONFIG["checks"] == ALL_CHECK_NAMES

    def test_output_paths_are_none(self):
        for key in ("json_out", "jsonl_out", "html_out"):
            assert DEFAULT_CONFIG[key] is None

    def test_verbose_is_false(self):
        assert DEFAULT_CONFIG["verbose"] is False

    def test_once_is_true(self):
        # vuln-sweep is always one-shot
        assert DEFAULT_CONFIG["once"] is True

    def test_threads_is_positive_int(self):
        assert isinstance(DEFAULT_CONFIG["threads"], int)
        assert DEFAULT_CONFIG["threads"] >= 1

    def test_timeout_is_positive_int(self):
        assert isinstance(DEFAULT_CONFIG["timeout"], int)
        assert DEFAULT_CONFIG["timeout"] >= 1

    def test_not_mutated_between_calls(self):
        """build_config() must deep-copy DEFAULT_CONFIG."""
        args   = _args()
        config = build_config(args)
        config["targets"].append("injected.com")
        assert DEFAULT_CONFIG["targets"] == []

    def test_checks_not_mutated_between_calls(self):
        args   = _args()
        config = build_config(args)
        config["checks"].append("injected")
        assert DEFAULT_CONFIG["checks"] == ALL_CHECK_NAMES


# ─────────────────────────────────────────────
# load_config()
# ─────────────────────────────────────────────

class TestLoadConfig:

    def test_loads_valid_json(self, tmp_path):
        path = _write_json(tmp_path, {"threads": 8})
        cfg  = load_config(path)
        assert cfg["threads"] == 8

    def test_strips_comment_keys(self, tmp_path):
        path = _write_json(tmp_path, {
            "_comment":  "ignore me",
            "_comment2": "and me",
            "timeout":   10,
        })
        cfg = load_config(path)
        assert "_comment"  not in cfg
        assert "_comment2" not in cfg
        assert cfg["timeout"] == 10

    def test_file_not_found_raises_system_exit(self):
        with pytest.raises(SystemExit):
            load_config("/nonexistent/path/config.json")

    def test_invalid_json_raises_system_exit(self, tmp_path):
        p = tmp_path / "bad.json"
        p.write_text("{not valid json}")
        with pytest.raises(SystemExit):
            load_config(str(p))

    def test_non_object_json_raises_system_exit(self, tmp_path):
        p = tmp_path / "array.json"
        p.write_text('["heartbleed", "poodle"]')
        with pytest.raises(SystemExit):
            load_config(str(p))

    def test_unknown_key_prints_warning(self, tmp_path, capsys):
        path = _write_json(tmp_path, {"completely_unknown": "value"})
        load_config(path)
        captured = capsys.readouterr()
        assert "unknown" in captured.err.lower()

    def test_wrong_type_threads_raises_system_exit(self, tmp_path):
        path = _write_json(tmp_path, {"threads": "eight"})
        with pytest.raises(SystemExit):
            load_config(path)

    def test_wrong_type_verbose_raises_system_exit(self, tmp_path):
        path = _write_json(tmp_path, {"verbose": "yes"})
        with pytest.raises(SystemExit):
            load_config(path)

    def test_wrong_type_targets_raises_system_exit(self, tmp_path):
        path = _write_json(tmp_path, {"targets": "example.com"})
        with pytest.raises(SystemExit):
            load_config(path)

    def test_checks_list_loaded(self, tmp_path):
        path = _write_json(tmp_path, {"checks": ["heartbleed", "robot"]})
        cfg  = load_config(path)
        assert cfg["checks"] == ["heartbleed", "robot"]

    def test_targets_list_loaded(self, tmp_path):
        path = _write_json(tmp_path, {
            "targets": ["example.com", "api.example.com:8443"]
        })
        cfg = load_config(path)
        assert "example.com" in cfg["targets"]

    def test_output_paths_loaded(self, tmp_path):
        path = _write_json(tmp_path, {
            "json_out":  "/tmp/scan.json",
            "jsonl_out": "/tmp/audit.jsonl",
            "html_out":  "/tmp/report.html",
        })
        cfg = load_config(path)
        assert cfg["json_out"]  == "/tmp/scan.json"
        assert cfg["jsonl_out"] == "/tmp/audit.jsonl"
        assert cfg["html_out"]  == "/tmp/report.html"

    def test_unknown_check_name_warns(self, tmp_path, capsys):
        path = _write_json(tmp_path, {"checks": ["heartbleed", "unknown_cve"]})
        load_config(path)
        captured = capsys.readouterr()
        assert "unknown" in captured.err.lower()


# ─────────────────────────────────────────────
# _load_env()
# ─────────────────────────────────────────────

class TestLoadEnv:

    def test_timeout_from_env(self):
        with patch.dict(os.environ, {"VULN_SWEEP_TIMEOUT": "15"}):
            cfg = _load_env()
            assert cfg["timeout"] == 15

    def test_threads_from_env(self):
        with patch.dict(os.environ, {"VULN_SWEEP_THREADS": "8"}):
            cfg = _load_env()
            assert cfg["threads"] == 8

    def test_port_from_env(self):
        with patch.dict(os.environ, {"VULN_SWEEP_PORT": "8443"}):
            cfg = _load_env()
            assert cfg["port"] == 8443

    def test_unset_env_vars_not_in_result(self):
        with patch.dict(os.environ, _clean_env(), clear=True):
            cfg = _load_env()
            assert cfg == {}

    def test_empty_string_env_var_ignored(self):
        with patch.dict(os.environ, {"VULN_SWEEP_TIMEOUT": ""}):
            cfg = _load_env()
            assert "timeout" not in cfg

    def test_whitespace_only_env_var_ignored(self):
        with patch.dict(os.environ, {"VULN_SWEEP_TIMEOUT": "   "}):
            cfg = _load_env()
            assert "timeout" not in cfg

    def test_non_integer_env_var_prints_warning(self, capsys):
        with patch.dict(os.environ, {"VULN_SWEEP_TIMEOUT": "fast"}):
            cfg = _load_env()
            assert "timeout" not in cfg
            captured = capsys.readouterr()
            assert "warning" in captured.err.lower()

    def test_multiple_env_vars_together(self):
        env = {
            "VULN_SWEEP_TIMEOUT": "10",
            "VULN_SWEEP_THREADS": "6",
            "VULN_SWEEP_PORT":    "8443",
        }
        with patch.dict(os.environ, env):
            cfg = _load_env()
            assert cfg["timeout"] == 10
            assert cfg["threads"] == 6
            assert cfg["port"]    == 8443

    def test_env_int_conversion(self):
        with patch.dict(os.environ, {"VULN_SWEEP_TIMEOUT": "30"}):
            cfg = _load_env()
            assert isinstance(cfg["timeout"], int)


# ─────────────────────────────────────────────
# build_config() — priority merge
# ─────────────────────────────────────────────

class TestBuildConfig:

    def test_returns_dict(self):
        assert isinstance(build_config(_args()), dict)

    def test_defaults_present_with_no_overrides(self):
        cfg = build_config(_args())
        assert cfg["threads"]  == DEFAULT_CONFIG["threads"]
        assert cfg["timeout"]  == DEFAULT_CONFIG["timeout"]
        assert cfg["port"]     == DEFAULT_CONFIG["port"]

    def test_cli_threads_overrides_default(self):
        cfg = build_config(_args(threads=20))
        assert cfg["threads"] == 20

    def test_cli_timeout_overrides_default(self):
        cfg = build_config(_args(timeout=15))
        assert cfg["timeout"] == 15

    def test_cli_port_overrides_default(self):
        cfg = build_config(_args(port=8443))
        assert cfg["port"] == 8443

    def test_cli_verbose_flag(self):
        cfg = build_config(_args(verbose=True))
        assert cfg["verbose"] is True

    def test_cli_single_target(self):
        cfg = build_config(_args(target="example.com"))
        assert "example.com" in cfg["targets"]

    def test_cli_json_out(self):
        cfg = build_config(_args(json_out="/tmp/scan.json"))
        assert cfg["json_out"] == "/tmp/scan.json"

    def test_cli_jsonl_out(self):
        cfg = build_config(_args(jsonl_out="/tmp/audit.jsonl"))
        assert cfg["jsonl_out"] == "/tmp/audit.jsonl"

    def test_cli_html_out(self):
        cfg = build_config(_args(html_out="/tmp/report.html"))
        assert cfg["html_out"] == "/tmp/report.html"

    def test_json_file_overrides_defaults(self, tmp_path):
        path = _write_json(tmp_path, {"threads": 50, "timeout": 20})
        cfg  = build_config(_args(config=str(path)))
        assert cfg["threads"] == 50
        assert cfg["timeout"] == 20

    def test_cli_overrides_json_file(self, tmp_path):
        path = _write_json(tmp_path, {"threads": 50})
        cfg  = build_config(_args(config=str(path), threads=99))
        assert cfg["threads"] == 99

    def test_env_overrides_json_file(self, tmp_path):
        path = _write_json(tmp_path, {"timeout": 5})
        with patch.dict(os.environ, {"VULN_SWEEP_TIMEOUT": "20"}):
            cfg = build_config(_args(config=str(path)))
        assert cfg["timeout"] == 20

    def test_cli_overrides_env(self):
        with patch.dict(os.environ, {"VULN_SWEEP_TIMEOUT": "20"}):
            cfg = build_config(_args(timeout=30))
        assert cfg["timeout"] == 30

    def test_threads_minimum_is_one(self):
        cfg = build_config(_args(threads=0))
        assert cfg["threads"] >= 1

    def test_timeout_minimum_is_one(self):
        cfg = build_config(_args(timeout=0))
        assert cfg["timeout"] >= 1

    def test_port_minimum_is_one(self):
        cfg = build_config(_args(port=0))
        assert cfg["port"] >= 1

    def test_port_maximum_is_65535(self):
        cfg = build_config(_args(port=99999))
        assert cfg["port"] <= 65535

    def test_targets_from_file_arg(self, tmp_path):
        targets_file = tmp_path / "targets.txt"
        targets_file.write_text("a.com\nb.com\n# comment\n\nc.com\n")
        cfg = build_config(_args(file=str(targets_file)))
        assert "a.com" in cfg["targets"]
        assert "b.com" in cfg["targets"]
        assert "c.com" in cfg["targets"]

    def test_targets_file_not_found_raises_system_exit(self):
        with pytest.raises(SystemExit):
            build_config(_args(file="/nonexistent/targets.txt"))

    def test_checks_always_present(self):
        cfg = build_config(_args())
        assert "checks" in cfg
        assert len(cfg["checks"]) > 0


# ─────────────────────────────────────────────
# _resolve_checks()
# ─────────────────────────────────────────────

class TestResolveChecks:

    def _resolve(self, **kwargs) -> list[str]:
        args = _args(**kwargs)
        cfg  = {"checks": ALL_CHECK_NAMES}
        return _resolve_checks(args, cfg)

    def test_all_flag_returns_all_checks(self):
        result = self._resolve(**{"all": True})
        assert set(result) == set(ALL_CHECK_NAMES)

    def test_single_explicit_check(self):
        result = self._resolve(heartbleed=True)
        assert result == ["heartbleed"]

    def test_multiple_explicit_checks(self):
        result = self._resolve(heartbleed=True, robot=True)
        assert set(result) == {"heartbleed", "robot"}

    def test_explicit_checks_in_canonical_order(self):
        # robot comes before heartbleed in the flag order but
        # result should follow ALL_CHECK_NAMES canonical order
        result = self._resolve(robot=True, heartbleed=True, poodle=True)
        expected_order = [c for c in ALL_CHECK_NAMES
                          if c in {"heartbleed", "poodle", "robot"}]
        assert result == expected_order

    def test_no_flags_returns_config_checks(self):
        args = _args()
        cfg  = {"checks": ["heartbleed", "drown"]}
        result = _resolve_checks(args, cfg)
        assert result == ["heartbleed", "drown"]

    def test_no_flags_no_config_returns_all(self):
        args   = _args()
        cfg    = {}
        result = _resolve_checks(args, cfg)
        assert set(result) == set(ALL_CHECK_NAMES)

    def test_unknown_check_in_config_filtered_out(self, capsys):
        args   = _args()
        cfg    = {"checks": ["heartbleed", "totally_made_up"]}
        result = _resolve_checks(args, cfg)
        assert "totally_made_up" not in result
        assert "heartbleed" in result

    def test_unknown_check_prints_warning(self, capsys):
        args = _args()
        cfg  = {"checks": ["unknown_cve"]}
        _resolve_checks(args, cfg)
        captured = capsys.readouterr()
        assert "unknown" in captured.err.lower()

    def test_all_flag_beats_explicit_checks(self):
        # --all should return everything even if specific flags set
        result = self._resolve(**{"all": True, "heartbleed": True})
        assert set(result) == set(ALL_CHECK_NAMES)

    def test_explicit_cli_beats_config_file(self):
        args   = _args(heartbleed=True)
        cfg    = {"checks": ["poodle", "beast", "drown"]}
        result = _resolve_checks(args, cfg)
        assert result == ["heartbleed"]

    def test_empty_config_checks_falls_back_to_all(self):
        args   = _args()
        cfg    = {"checks": []}
        result = _resolve_checks(args, cfg)
        assert set(result) == set(ALL_CHECK_NAMES)

    def test_all_six_checks_individually(self):
        for check_name in ALL_CHECK_NAMES:
            result = self._resolve(**{check_name: True})
            assert result == [check_name]


# ─────────────────────────────────────────────
# parse_targets()
# ─────────────────────────────────────────────

class TestParseTargets:

    def _parse(self, targets: list[str], port: int = 443) -> list[tuple]:
        return parse_targets({"targets": targets, "port": port})

    def test_bare_hostname_uses_default_port(self):
        result = self._parse(["example.com"])
        assert result == [("example.com", 443)]

    def test_host_with_port(self):
        result = self._parse(["example.com:8443"])
        assert result == [("example.com", 8443)]

    def test_custom_default_port(self):
        result = self._parse(["example.com"], port=8443)
        assert result == [("example.com", 8443)]

    def test_comment_lines_skipped(self):
        result = self._parse(["# comment", "example.com"])
        assert len(result) == 1
        assert result[0][0] == "example.com"

    def test_blank_lines_skipped(self):
        result = self._parse(["", "   ", "example.com", ""])
        assert len(result) == 1

    def test_mixed_targets_and_comments(self):
        lines  = ["# production", "a.com", "", "# staging", "b.com:8443"]
        result = self._parse(lines)
        assert len(result) == 2
        assert ("a.com", 443)  in result
        assert ("b.com", 8443) in result

    def test_deduplication_same_host_port(self):
        result = self._parse(["example.com", "example.com"])
        assert len(result) == 1

    def test_deduplication_case_insensitive(self):
        result = self._parse(["Example.com", "example.com"])
        assert len(result) == 1

    def test_same_host_different_ports_not_deduplicated(self):
        result = self._parse(["example.com:443", "example.com:8443"])
        assert len(result) == 2

    def test_order_preserved(self):
        lines  = ["c.com", "a.com", "b.com"]
        result = self._parse(lines)
        hosts  = [h for h, _ in result]
        assert hosts == ["c.com", "a.com", "b.com"]

    def test_invalid_port_string_skipped(self, capsys):
        result = self._parse(["example.com:notaport"])
        assert result == []

    def test_port_zero_skipped(self, capsys):
        result = self._parse(["example.com:0"])
        assert result == []

    def test_port_above_65535_skipped(self, capsys):
        result = self._parse(["example.com:99999"])
        assert result == []

    def test_port_65535_accepted(self):
        result = self._parse(["example.com:65535"])
        assert result == [("example.com", 65535)]

    def test_port_1_accepted(self):
        result = self._parse(["example.com:1"])
        assert result == [("example.com", 1)]

    def test_cidr_notation_skipped_with_warning(self, capsys):
        result = self._parse(["192.168.1.0/24"])
        assert result == []
        captured = capsys.readouterr()
        assert "cidr" in captured.err.lower() or "not supported" in captured.err.lower()

    def test_hostname_with_spaces_skipped(self, capsys):
        result = self._parse(["exam ple.com"])
        assert result == []

    def test_empty_list(self):
        result = self._parse([])
        assert result == []

    def test_whitespace_stripped_from_lines(self):
        result = self._parse(["  example.com  "])
        assert result == [("example.com", 443)]

    def test_ipv4_address_accepted(self):
        result = self._parse(["192.168.1.1:443"])
        assert result == [("192.168.1.1", 443)]

    def test_ip_with_default_port(self):
        result = self._parse(["10.0.0.1"])
        assert result == [("10.0.0.1", 443)]

    def test_subdomain_accepted(self):
        result = self._parse(["deep.nested.sub.example.com"])
        assert result == [("deep.nested.sub.example.com", 443)]

    def test_multiple_invalid_lines_all_skipped(self, capsys):
        result = self._parse(["bad:port:here", "also:bad:here"])
        assert result == []

    def test_trailing_newlines_handled(self):
        result = self._parse(["example.com\n", "api.example.com\n"])
        assert len(result) == 2


# ─────────────────────────────────────────────
# _validate_config()
# ─────────────────────────────────────────────

class TestValidateConfig:

    def test_valid_config_does_not_raise(self):
        _validate_config({"threads": 10, "timeout": 8})

    def test_empty_config_does_not_raise(self):
        _validate_config({})

    def test_unknown_key_prints_warning(self, capsys):
        _validate_config({"totally_unknown": "value"})
        captured = capsys.readouterr()
        assert "unknown" in captured.err.lower()

    def test_wrong_type_threads_raises_system_exit(self):
        with pytest.raises(SystemExit):
            _validate_config({"threads": "ten"})

    def test_wrong_type_timeout_raises_system_exit(self):
        with pytest.raises(SystemExit):
            _validate_config({"timeout": "fast"})

    def test_wrong_type_targets_raises_system_exit(self):
        with pytest.raises(SystemExit):
            _validate_config({"targets": "example.com"})

    def test_wrong_type_verbose_raises_system_exit(self):
        with pytest.raises(SystemExit):
            _validate_config({"verbose": "yes"})

    def test_wrong_type_checks_raises_system_exit(self):
        with pytest.raises(SystemExit):
            _validate_config({"checks": "heartbleed"})

    def test_none_values_for_output_paths_accepted(self):
        _validate_config({
            "json_out":  None,
            "jsonl_out": None,
            "html_out":  None,
        })

    def test_string_output_paths_accepted(self):
        _validate_config({
            "json_out":  "/tmp/scan.json",
            "jsonl_out": "/tmp/audit.jsonl",
            "html_out":  "/tmp/report.html",
        })

    def test_valid_checks_list_accepted(self):
        _validate_config({"checks": ["heartbleed", "poodle"]})


# ─────────────────────────────────────────────
# _merge()
# ─────────────────────────────────────────────

class TestMerge:

    def test_override_wins_for_top_level_key(self):
        result = _merge({"threads": 10}, {"threads": 20})
        assert result["threads"] == 20

    def test_base_keys_preserved_when_not_overridden(self):
        result = _merge({"threads": 10, "timeout": 8}, {"threads": 20})
        assert result["timeout"] == 8

    def test_new_keys_in_override_added(self):
        result = _merge({"threads": 10}, {"json_out": "/tmp/scan.json"})
        assert result["json_out"] == "/tmp/scan.json"

    def test_lists_replaced_entirely(self):
        """Unlike cert-canary, vuln-sweep uses shallow list replace."""
        base     = {"checks": ["heartbleed", "poodle", "beast"]}
        override = {"checks": ["robot"]}
        result   = _merge(base, override)
        assert result["checks"] == ["robot"]

    def test_base_not_mutated(self):
        base     = {"threads": 10}
        _merge(base, {"threads": 20})
        assert base["threads"] == 10

    def test_override_not_mutated(self):
        override = {"threads": 20}
        _merge({"threads": 10}, override)
        assert override == {"threads": 20}

    def test_empty_override_returns_copy_of_base(self):
        base   = {"threads": 10, "timeout": 8}
        result = _merge(base, {})
        assert result == base
        assert result is not base

    def test_empty_base_returns_override(self):
        override = {"threads": 20}
        result   = _merge({}, override)
        assert result == override

    def test_none_value_in_override_overwrites(self):
        base     = {"json_out": "/tmp/scan.json"}
        override = {"json_out": None}
        result   = _merge(base, override)
        assert result["json_out"] is None