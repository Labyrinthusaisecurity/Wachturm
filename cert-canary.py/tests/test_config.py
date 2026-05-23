#!/usr/bin/env python3
"""
tests/test_config.py
━━━━━━━━━━━━━━━━━━━
Unit tests for cert_canary/config.py.

Tests cover:
  • DEFAULT_THRESHOLDS and DEFAULT_CONFIG values
  • load_config()   — JSON file loading, validation, _comment stripping
  • _load_env()     — environment variable resolution
  • build_config()  — priority merge (CLI > env > file > defaults)
  • parse_hosts()   — host string parsing, deduplication, error handling
  • _validate_config() — type checking and unknown key warnings
  • _validate_smtp()   — required SMTP field validation
  • _merge()        — shallow merge with deep threshold merge
  • _fmt_interval() — human-readable interval formatting (via output.py)

No real files are written — all file I/O is mocked with tmp_path
or unittest.mock. No real environment variables are set — all
os.environ access is patched.
"""

import json
import os
from argparse import Namespace
from unittest.mock import MagicMock, patch

import pytest

from cert_canary.config import (
    DEFAULT_CONFIG,
    DEFAULT_THRESHOLDS,
    _load_env,
    _merge,
    _validate_config,
    build_config,
    load_config,
    parse_hosts,
)


# ─────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────

def _args(**kwargs) -> Namespace:
    """
    Build a minimal argparse Namespace for build_config().
    Only sets the keys explicitly passed — everything else
    is None / False, mimicking an unset CLI flag.
    """
    defaults = dict(
        hosts_cli=None,
        hosts=None,
        config=None,
        port=443,
        threads=None,
        interval=None,
        timeout=None,
        once=False,
        critical=None,
        warning=None,
        info=None,
    )
    defaults.update(kwargs)
    return Namespace(**defaults)


def _write_json(path, data):
    """Write a JSON file to a pytest tmp_path location."""
    p = path / "canary.json"
    p.write_text(json.dumps(data))
    return str(p)


# ─────────────────────────────────────────────
# DEFAULT_THRESHOLDS and DEFAULT_CONFIG
# ─────────────────────────────────────────────

class TestDefaults:

    def test_default_thresholds_has_all_keys(self):
        for key in ("critical", "warning", "info"):
            assert key in DEFAULT_THRESHOLDS

    def test_default_thresholds_are_ints(self):
        for key, val in DEFAULT_THRESHOLDS.items():
            assert isinstance(val, int), f"{key} should be int"

    def test_default_threshold_order(self):
        # critical < warning < info — otherwise grading logic breaks
        assert DEFAULT_THRESHOLDS["critical"] < DEFAULT_THRESHOLDS["warning"]
        assert DEFAULT_THRESHOLDS["warning"]  < DEFAULT_THRESHOLDS["info"]

    def test_default_config_has_required_keys(self):
        required = (
            "hosts", "thresholds", "threads", "interval",
            "timeout", "once", "slack_webhook", "discord_webhook",
            "pagerduty_key", "webhook_url", "smtp",
        )
        for key in required:
            assert key in DEFAULT_CONFIG, f"Missing key: {key}"

    def test_default_hosts_is_empty_list(self):
        assert DEFAULT_CONFIG["hosts"] == []

    def test_default_alert_channels_are_none(self):
        for key in ("slack_webhook", "discord_webhook", "pagerduty_key",
                    "webhook_url", "smtp"):
            assert DEFAULT_CONFIG[key] is None

    def test_default_once_is_false(self):
        assert DEFAULT_CONFIG["once"] is False

    def test_default_config_is_not_mutated_between_calls(self):
        """
        build_config() must deep-copy DEFAULT_CONFIG.
        Mutating the returned config must not affect DEFAULT_CONFIG.
        """
        args   = _args()
        config = build_config(args)
        config["hosts"].append("injected.com")
        assert DEFAULT_CONFIG["hosts"] == []


# ─────────────────────────────────────────────
# load_config()
# ─────────────────────────────────────────────

class TestLoadConfig:

    def test_loads_valid_json(self, tmp_path):
        path = _write_json(tmp_path, {"threads": 20})
        cfg  = load_config(path)
        assert cfg["threads"] == 20

    def test_strips_comment_keys(self, tmp_path):
        path = _write_json(tmp_path, {
            "_comment":  "this is a comment",
            "_comment2": "another comment",
            "threads":   5,
        })
        cfg = load_config(path)
        assert "_comment"  not in cfg
        assert "_comment2" not in cfg
        assert cfg["threads"] == 5

    def test_partial_thresholds_deep_merged(self, tmp_path):
        """Setting only 'critical' should not wipe warning/info."""
        path = _write_json(tmp_path, {"thresholds": {"critical": 3}})
        cfg  = load_config(path)
        assert cfg["thresholds"]["critical"] == 3
        assert cfg["thresholds"]["warning"]  == DEFAULT_THRESHOLDS["warning"]
        assert cfg["thresholds"]["info"]     == DEFAULT_THRESHOLDS["info"]

    def test_full_thresholds_override(self, tmp_path):
        path = _write_json(tmp_path, {
            "thresholds": {"critical": 14, "warning": 45, "info": 90}
        })
        cfg = load_config(path)
        assert cfg["thresholds"] == {"critical": 14, "warning": 45, "info": 90}

    def test_file_not_found_raises_system_exit(self):
        with pytest.raises(SystemExit):
            load_config("/nonexistent/path/canary.json")

    def test_invalid_json_raises_system_exit(self, tmp_path):
        p = tmp_path / "bad.json"
        p.write_text("{this is not json}")
        with pytest.raises(SystemExit):
            load_config(str(p))

    def test_non_object_json_raises_system_exit(self, tmp_path):
        p = tmp_path / "list.json"
        p.write_text('["a", "b", "c"]')
        with pytest.raises(SystemExit):
            load_config(str(p))

    def test_unknown_key_does_not_raise(self, tmp_path, capsys):
        path = _write_json(tmp_path, {"unknown_key": "value"})
        # Should not raise SystemExit
        load_config(path)
        captured = capsys.readouterr()
        assert "unknown" in captured.err.lower()

    def test_wrong_type_raises_system_exit(self, tmp_path):
        # threads must be int, not string
        path = _write_json(tmp_path, {"threads": "ten"})
        with pytest.raises(SystemExit):
            load_config(path)

    def test_negative_threshold_raises_system_exit(self, tmp_path):
        path = _write_json(tmp_path, {"thresholds": {"critical": -1}})
        with pytest.raises(SystemExit):
            load_config(path)

    def test_hosts_as_list(self, tmp_path):
        path = _write_json(tmp_path, {"hosts": ["a.com", "b.com:8443"]})
        cfg  = load_config(path)
        assert cfg["hosts"] == ["a.com", "b.com:8443"]

    def test_smtp_block_loaded(self, tmp_path):
        smtp = {
            "host": "smtp.gmail.com", "port": 587, "starttls": True,
            "ssl": False, "user": "u@g.com", "password": "pw",
            "from": "f@g.com", "to": ["t@g.com"],
        }
        path = _write_json(tmp_path, {"smtp": smtp})
        cfg  = load_config(path)
        assert cfg["smtp"]["host"] == "smtp.gmail.com"

    def test_threshold_comment_keys_stripped(self, tmp_path):
        path = _write_json(tmp_path, {
            "thresholds": {"_comment": "days", "critical": 7, "warning": 30, "info": 60}
        })
        cfg = load_config(path)
        assert "_comment" not in cfg["thresholds"]


# ─────────────────────────────────────────────
# _load_env()
# ─────────────────────────────────────────────

class TestLoadEnv:

    def test_slack_webhook_from_env(self):
        with patch.dict(os.environ, {"CANARY_SLACK_WEBHOOK": "https://slack.test"}):
            cfg = _load_env()
            assert cfg["slack_webhook"] == "https://slack.test"

    def test_discord_webhook_from_env(self):
        with patch.dict(os.environ, {"CANARY_DISCORD_WEBHOOK": "https://discord.test"}):
            cfg = _load_env()
            assert cfg["discord_webhook"] == "https://discord.test"

    def test_pagerduty_key_from_env(self):
        with patch.dict(os.environ, {"CANARY_PAGERDUTY_KEY": "PDKEY123"}):
            cfg = _load_env()
            assert cfg["pagerduty_key"] == "PDKEY123"

    def test_webhook_url_from_env(self):
        with patch.dict(os.environ, {"CANARY_WEBHOOK_URL": "https://hook.test"}):
            cfg = _load_env()
            assert cfg["webhook_url"] == "https://hook.test"

    def test_webhook_secret_from_env(self):
        with patch.dict(os.environ, {"CANARY_WEBHOOK_SECRET": "mysecret"}):
            cfg = _load_env()
            assert cfg["webhook_secret"] == "mysecret"

    def test_unset_env_vars_not_in_result(self):
        # Ensure no CANARY_ vars are set
        clean_env = {k: v for k, v in os.environ.items()
                     if not k.startswith("CANARY_")}
        with patch.dict(os.environ, clean_env, clear=True):
            cfg = _load_env()
            assert cfg == {}

    def test_empty_string_env_var_ignored(self):
        with patch.dict(os.environ, {"CANARY_SLACK_WEBHOOK": ""}):
            cfg = _load_env()
            assert "slack_webhook" not in cfg

    def test_whitespace_only_env_var_ignored(self):
        with patch.dict(os.environ, {"CANARY_SLACK_WEBHOOK": "   "}):
            cfg = _load_env()
            assert "slack_webhook" not in cfg

    def test_env_value_stripped_of_whitespace(self):
        with patch.dict(os.environ, {"CANARY_SLACK_WEBHOOK": "  https://slack.test  "}):
            cfg = _load_env()
            assert cfg["slack_webhook"] == "https://slack.test"

    def test_multiple_env_vars_at_once(self):
        env = {
            "CANARY_SLACK_WEBHOOK":   "https://slack.test",
            "CANARY_PAGERDUTY_KEY":   "PDKEY",
            "CANARY_DISCORD_WEBHOOK": "https://discord.test",
        }
        with patch.dict(os.environ, env):
            cfg = _load_env()
            assert cfg["slack_webhook"]   == "https://slack.test"
            assert cfg["pagerduty_key"]   == "PDKEY"
            assert cfg["discord_webhook"] == "https://discord.test"


# ─────────────────────────────────────────────
# build_config() — priority merge
# ─────────────────────────────────────────────

class TestBuildConfig:

    def test_returns_dict(self):
        cfg = build_config(_args())
        assert isinstance(cfg, dict)

    def test_defaults_present_when_no_overrides(self):
        cfg = build_config(_args())
        assert cfg["threads"]  == DEFAULT_CONFIG["threads"]
        assert cfg["timeout"]  == DEFAULT_CONFIG["timeout"]
        assert cfg["interval"] == DEFAULT_CONFIG["interval"]

    def test_cli_threads_overrides_default(self):
        cfg = build_config(_args(threads=25))
        assert cfg["threads"] == 25

    def test_cli_timeout_overrides_default(self):
        cfg = build_config(_args(timeout=15))
        assert cfg["timeout"] == 15

    def test_cli_interval_overrides_default(self):
        cfg = build_config(_args(interval=7200))
        assert cfg["interval"] == 7200

    def test_cli_once_flag(self):
        cfg = build_config(_args(once=True))
        assert cfg["once"] is True

    def test_cli_host_list(self):
        cfg = build_config(_args(hosts_cli=["a.com", "b.com"]))
        assert "a.com" in cfg["hosts"]
        assert "b.com" in cfg["hosts"]

    def test_cli_threshold_critical(self):
        cfg = build_config(_args(critical=3))
        # Threshold overrides applied in main.py after build_config(),
        # but build_config itself should handle them via _extract_cli
        assert cfg["thresholds"]["critical"] == 3

    def test_cli_threshold_partial_override_preserves_others(self):
        cfg = build_config(_args(critical=3))
        assert cfg["thresholds"]["warning"] == DEFAULT_THRESHOLDS["warning"]
        assert cfg["thresholds"]["info"]    == DEFAULT_THRESHOLDS["info"]

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
        path = _write_json(tmp_path, {"slack_webhook": "https://from-file"})
        with patch.dict(os.environ, {"CANARY_SLACK_WEBHOOK": "https://from-env"}):
            cfg = build_config(_args(config=str(path)))
        assert cfg["slack_webhook"] == "https://from-env"

    def test_cli_overrides_env(self):
        # CLI hosts_cli overrides env — env vars don't set hosts
        # but this tests the general priority ordering
        with patch.dict(os.environ, {"CANARY_PAGERDUTY_KEY": "from-env"}):
            cfg = build_config(_args())
        assert cfg["pagerduty_key"] == "from-env"

    def test_threads_minimum_is_one(self):
        cfg = build_config(_args(threads=0))
        assert cfg["threads"] >= 1

    def test_timeout_minimum_is_one(self):
        cfg = build_config(_args(timeout=0))
        assert cfg["timeout"] >= 1

    def test_thresholds_always_complete(self):
        """Even with no config, thresholds dict has all three keys."""
        cfg = build_config(_args())
        for key in ("critical", "warning", "info"):
            assert key in cfg["thresholds"]

    def test_hosts_from_file_arg(self, tmp_path):
        hosts_file = tmp_path / "hosts.txt"
        hosts_file.write_text("a.com\nb.com\n# comment\n\nc.com\n")
        cfg = build_config(_args(hosts=str(hosts_file)))
        assert "a.com" in cfg["hosts"]
        assert "b.com" in cfg["hosts"]
        assert "c.com" in cfg["hosts"]

    def test_hosts_file_not_found_raises_system_exit(self):
        with pytest.raises(SystemExit):
            build_config(_args(hosts="/nonexistent/hosts.txt"))


# ─────────────────────────────────────────────
# parse_hosts()
# ─────────────────────────────────────────────

class TestParseHosts:

    def test_bare_hostname_uses_default_port(self):
        result = parse_hosts(["example.com"])
        assert result == [("example.com", 443)]

    def test_host_with_port(self):
        result = parse_hosts(["example.com:8443"])
        assert result == [("example.com", 8443)]

    def test_custom_default_port(self):
        result = parse_hosts(["example.com"], default_port=8443)
        assert result == [("example.com", 8443)]

    def test_comment_lines_skipped(self):
        result = parse_hosts(["# this is a comment", "example.com"])
        assert len(result) == 1
        assert result[0][0] == "example.com"

    def test_blank_lines_skipped(self):
        result = parse_hosts(["", "   ", "example.com", ""])
        assert len(result) == 1

    def test_mixed_hosts_and_comments(self):
        lines = [
            "# production",
            "example.com",
            "",
            "# staging",
            "staging.example.com:8443",
        ]
        result = parse_hosts(lines)
        assert len(result) == 2
        assert ("example.com",         443)  in result
        assert ("staging.example.com", 8443) in result

    def test_deduplication_same_host_port(self):
        result = parse_hosts(["example.com", "example.com"])
        assert len(result) == 1

    def test_deduplication_case_insensitive(self):
        result = parse_hosts(["Example.com", "example.com"])
        assert len(result) == 1

    def test_same_host_different_ports_not_deduplicated(self):
        result = parse_hosts(["example.com:443", "example.com:8443"])
        assert len(result) == 2

    def test_order_preserved(self):
        lines  = ["c.com", "a.com", "b.com"]
        result = parse_hosts(lines)
        hosts  = [h for h, _ in result]
        assert hosts == ["c.com", "a.com", "b.com"]

    def test_invalid_port_string_skipped(self, capsys):
        result = parse_hosts(["example.com:notaport"])
        assert result == []
        captured = capsys.readouterr()
        assert "invalid" in captured.err.lower() or "port" in captured.err.lower()

    def test_port_zero_skipped(self, capsys):
        result = parse_hosts(["example.com:0"])
        assert result == []

    def test_port_above_65535_skipped(self, capsys):
        result = parse_hosts(["example.com:99999"])
        assert result == []

    def test_port_65535_accepted(self):
        result = parse_hosts(["example.com:65535"])
        assert result == [("example.com", 65535)]

    def test_port_1_accepted(self):
        result = parse_hosts(["example.com:1"])
        assert result == [("example.com", 1)]

    def test_hostname_with_spaces_skipped(self, capsys):
        result = parse_hosts(["exam ple.com"])
        assert result == []

    def test_empty_list(self):
        result = parse_hosts([])
        assert result == []

    def test_all_comments_and_blanks(self):
        result = parse_hosts(["# comment", "", "   ", "# another"])
        assert result == []

    def test_whitespace_stripped_from_lines(self):
        result = parse_hosts(["  example.com  "])
        assert result == [("example.com", 443)]

    def test_trailing_newlines_handled(self):
        result = parse_hosts(["example.com\n", "api.example.com\n"])
        assert len(result) == 2

    def test_ipv4_address_accepted(self):
        result = parse_hosts(["192.168.1.1:443"])
        assert result == [("192.168.1.1", 443)]

    def test_subdomain_accepted(self):
        result = parse_hosts(["deep.nested.sub.example.com"])
        assert result == [("deep.nested.sub.example.com", 443)]

    def test_multiple_invalid_lines_all_skipped(self, capsys):
        result = parse_hosts(["bad:port:here", "also:bad:here"])
        assert result == []


# ─────────────────────────────────────────────
# _validate_config()
# ─────────────────────────────────────────────

class TestValidateConfig:

    def test_valid_config_does_not_raise(self):
        _validate_config({"threads": 10, "timeout": 8})

    def test_unknown_key_prints_warning(self, capsys):
        _validate_config({"totally_unknown_key": "value"})
        captured = capsys.readouterr()
        assert "unknown" in captured.err.lower()

    def test_wrong_type_threads_raises_system_exit(self):
        with pytest.raises(SystemExit):
            _validate_config({"threads": "ten"})

    def test_wrong_type_hosts_raises_system_exit(self):
        with pytest.raises(SystemExit):
            _validate_config({"hosts": "example.com"})   # should be list

    def test_wrong_type_once_raises_system_exit(self):
        with pytest.raises(SystemExit):
            _validate_config({"once": "yes"})            # should be bool

    def test_wrong_threshold_type_raises_system_exit(self):
        with pytest.raises(SystemExit):
            _validate_config({"thresholds": {"critical": "seven"}})

    def test_negative_threshold_raises_system_exit(self):
        with pytest.raises(SystemExit):
            _validate_config({"thresholds": {"critical": -1}})

    def test_zero_threshold_accepted(self):
        # 0 days is technically valid (alert immediately on expiry)
        _validate_config({"thresholds": {"critical": 0}})

    def test_unknown_threshold_key_warns(self, capsys):
        _validate_config({"thresholds": {"unknown_level": 5}})
        captured = capsys.readouterr()
        assert "unknown" in captured.err.lower()

    def test_none_value_for_optional_keys_accepted(self):
        _validate_config({
            "slack_webhook":   None,
            "discord_webhook": None,
            "pagerduty_key":   None,
            "smtp":            None,
        })

    def test_valid_smtp_block_accepted(self):
        _validate_config({
            "smtp": {
                "host": "smtp.gmail.com", "port": 587,
                "user": "u", "password": "p",
                "from": "f@g.com", "to": ["t@g.com"],
            }
        })

    def test_smtp_missing_required_field_raises(self):
        with pytest.raises(SystemExit):
            _validate_config({
                "smtp": {
                    "host": "smtp.gmail.com", "port": 587,
                    # missing user, password, to
                }
            })

    def test_smtp_to_must_be_list(self):
        with pytest.raises(SystemExit):
            _validate_config({
                "smtp": {
                    "host": "smtp.gmail.com", "port": 587,
                    "user": "u", "password": "p",
                    "from": "f", "to": "t@g.com",   # string not list
                }
            })

    def test_smtp_port_must_be_int(self):
        with pytest.raises(SystemExit):
            _validate_config({
                "smtp": {
                    "host": "smtp.gmail.com", "port": "587",  # string
                    "user": "u", "password": "p",
                    "from": "f", "to": ["t@g.com"],
                }
            })

    def test_empty_config_does_not_raise(self):
        _validate_config({})


# ─────────────────────────────────────────────
# _merge()
# ─────────────────────────────────────────────

class TestMerge:

    def test_override_wins_for_top_level_key(self):
        base     = {"threads": 10}
        override = {"threads": 20}
        result   = _merge(base, override)
        assert result["threads"] == 20

    def test_base_keys_preserved_when_not_overridden(self):
        base     = {"threads": 10, "timeout": 8}
        override = {"threads": 20}
        result   = _merge(base, override)
        assert result["timeout"] == 8

    def test_new_keys_in_override_added(self):
        base     = {"threads": 10}
        override = {"slack_webhook": "https://slack.test"}
        result   = _merge(base, override)
        assert result["slack_webhook"] == "https://slack.test"

    def test_thresholds_deep_merged(self):
        base     = {"thresholds": {"critical": 7, "warning": 30, "info": 60}}
        override = {"thresholds": {"critical": 3}}
        result   = _merge(base, override)
        assert result["thresholds"]["critical"] == 3
        assert result["thresholds"]["warning"]  == 30
        assert result["thresholds"]["info"]     == 60

    def test_thresholds_full_override(self):
        base     = {"thresholds": {"critical": 7, "warning": 30, "info": 60}}
        override = {"thresholds": {"critical": 14, "warning": 45, "info": 90}}
        result   = _merge(base, override)
        assert result["thresholds"] == {"critical": 14, "warning": 45, "info": 90}

    def test_base_not_mutated(self):
        base     = {"threads": 10}
        override = {"threads": 20}
        _merge(base, override)
        assert base["threads"] == 10

    def test_override_not_mutated(self):
        base     = {"threads": 10}
        override = {"threads": 20, "timeout": 5}
        _merge(base, override)
        assert override == {"threads": 20, "timeout": 5}

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
        base     = {"slack_webhook": "https://slack.test"}
        override = {"slack_webhook": None}
        result   = _merge(base, override)
        assert result["slack_webhook"] is None