#!/usr/bin/env python3
"""
cert_canary/config.py
━━━━━━━━━━━━━━━━━━━━
Single source of truth for all configuration.

Priority order (highest to lowest):
  1. CLI flags         (--critical, --threads, etc.)
  2. Environment vars  (CANARY_SLACK_WEBHOOK, etc.)
  3. JSON config file  (canary.json)
  4. Defaults          (DEFAULT_CONFIG, DEFAULT_THRESHOLDS)

Nothing in this module does I/O except load_config() (reads a file)
and _load_env() (reads os.environ). Everything else is pure functions.
"""

import json
import os
import sys
from typing import Any


# ─────────────────────────────────────────────
# Defaults
# ─────────────────────────────────────────────

DEFAULT_THRESHOLDS: dict[str, int] = {
    "critical": 7,     # days — alert immediately
    "warning":  30,    # days — schedule renewal
    "info":     60,    # days — heads-up
}

DEFAULT_CONFIG: dict[str, Any] = {
    # Host list — overridden by --host, --hosts, or canary.json
    "hosts": [],

    # Grading thresholds in days
    "thresholds": DEFAULT_THRESHOLDS,

    # Scan behaviour
    "threads":  10,    # parallel scan threads
    "interval": 3600,  # seconds between daemon sweeps
    "timeout":  8,     # per-host socket timeout in seconds
    "once":     False, # single sweep then exit

    # Alert channels — None means disabled
    "slack_webhook":   None,
    "discord_webhook": None,
    "pagerduty_key":   None,
    "webhook_url":     None,
    "webhook_secret":  None,
    "smtp":            None,
}

# Environment variable → config key mapping
_ENV_MAP: dict[str, str] = {
    "CANARY_SLACK_WEBHOOK":   "slack_webhook",
    "CANARY_DISCORD_WEBHOOK": "discord_webhook",
    "CANARY_PAGERDUTY_KEY":   "pagerduty_key",
    "CANARY_WEBHOOK_URL":     "webhook_url",
    "CANARY_WEBHOOK_SECRET":  "webhook_secret",
}


# ─────────────────────────────────────────────
# JSON config loader
# ─────────────────────────────────────────────

def load_config(path: str) -> dict[str, Any]:
    """
    Load and validate a canary.json config file.
    Unknown keys (including _comment keys) are silently ignored.
    Raises SystemExit with a helpful message on parse errors.
    """
    try:
        with open(path) as fh:
            raw = json.load(fh)
    except FileNotFoundError:
        _die(f"Config file not found: {path}")
    except json.JSONDecodeError as e:
        _die(f"Invalid JSON in {path}: {e}")

    if not isinstance(raw, dict):
        _die(f"Config file must be a JSON object, got: {type(raw).__name__}")

    # Strip _comment keys — they exist only for human readers
    cleaned = {k: v for k, v in raw.items() if not k.startswith("_")}

    # Validate known keys and their types
    _validate_config(cleaned, source=path)

    # Deep-merge thresholds so partial overrides work
    # e.g. {"thresholds": {"critical": 3}} still gets warning/info defaults
    if "thresholds" in cleaned and isinstance(cleaned["thresholds"], dict):
        thresholds_raw = {
            k: v for k, v in cleaned["thresholds"].items()
            if not k.startswith("_")
        }
        cleaned["thresholds"] = {**DEFAULT_THRESHOLDS, **thresholds_raw}

    return cleaned


# ─────────────────────────────────────────────
# Environment variable loader
# ─────────────────────────────────────────────

def _load_env() -> dict[str, Any]:
    """
    Read CANARY_* environment variables and return
    a partial config dict. Only set keys that are
    present in the environment — don't overwrite with None.
    """
    env_cfg: dict[str, Any] = {}
    for env_var, config_key in _ENV_MAP.items():
        val = os.environ.get(env_var)
        if val and val.strip():
            env_cfg[config_key] = val.strip()
    return env_cfg


# ─────────────────────────────────────────────
# Config builder — merges all sources
# ─────────────────────────────────────────────

def build_config(args) -> dict[str, Any]:
    """
    Merge config from all sources in priority order:
      CLI args > env vars > JSON file > defaults

    Args:
        args: argparse.Namespace from main.py parse_args()

    Returns:
        Complete config dict ready for use by scanner and alerts.
    """
    # Start with defaults
    cfg = _deep_copy(DEFAULT_CONFIG)

    # Layer 1: JSON config file
    if getattr(args, "config", None):
        file_cfg = load_config(args.config)
        cfg = _merge(cfg, file_cfg)

    # Layer 2: Environment variables
    env_cfg = _load_env()
    cfg = _merge(cfg, env_cfg)

    # Layer 3: CLI flags (explicit values only — skip None/unset)
    cli_cfg = _extract_cli(args)
    cfg = _merge(cfg, cli_cfg)

    # Ensure thresholds is always a complete dict
    if not isinstance(cfg.get("thresholds"), dict):
        cfg["thresholds"] = {**DEFAULT_THRESHOLDS}
    else:
        cfg["thresholds"] = {**DEFAULT_THRESHOLDS, **cfg["thresholds"]}

    # Ensure threads is at least 1
    cfg["threads"] = max(1, int(cfg.get("threads", 10)))

    # Ensure timeout is at least 1
    cfg["timeout"] = max(1, int(cfg.get("timeout", 8)))

    return cfg


def _extract_cli(args) -> dict[str, Any]:
    """
    Pull CLI-provided values out of the argparse Namespace.
    Only includes keys that were explicitly set — skips None
    so they don't overwrite file/env config with empty values.
    """
    cli: dict[str, Any] = {}

    # Host sources
    if getattr(args, "hosts_cli", None):
        cli["hosts"] = list(args.hosts_cli)
    elif getattr(args, "hosts", None):
        # --hosts FILE: read file and expand into list
        cli["hosts"] = _read_hosts_file(args.hosts)

    # Scan behaviour
    for attr, key in [
        ("threads",  "threads"),
        ("interval", "interval"),
        ("timeout",  "timeout"),
    ]:
        val = getattr(args, attr, None)
        if val is not None:
            cli[key] = val

    # Flags
    if getattr(args, "once", False):
        cli["once"] = True

    # Threshold overrides
    thresholds: dict[str, int] = {}
    for key in ("critical", "warning", "info"):
        val = getattr(args, key, None)
        if val is not None:
            thresholds[key] = val
    if thresholds:
        cli["thresholds"] = thresholds

    return cli


# ─────────────────────────────────────────────
# Host list parser
# ─────────────────────────────────────────────

def parse_hosts(
    raw: list[str],
    default_port: int = 443,
) -> list[tuple[str, int]]:
    """
    Parse a list of raw host strings into (hostname, port) tuples.

    Accepts:
      "example.com"           → ("example.com", 443)
      "example.com:8443"      → ("example.com", 8443)
      "# comment"             → skipped
      ""                      → skipped

    Args:
        raw:          List of raw host strings (from config, file, or CLI).
        default_port: Port to use when not specified. Default 443.

    Returns:
        Deduplicated list of (hostname, port) tuples, order preserved.
    """
    seen:   set[tuple[str, int]]      = set()
    hosts:  list[tuple[str, int]]     = []
    errors: list[str]                 = []

    for line in raw:
        line = line.strip()

        # Skip blank lines and comments
        if not line or line.startswith("#"):
            continue

        # Parse host:port or bare host
        if ":" in line:
            parts = line.rsplit(":", 1)
            hostname = parts[0].strip()
            try:
                port = int(parts[1].strip())
            except ValueError:
                errors.append(f"  invalid port in '{line}' — skipping")
                continue
        else:
            hostname = line
            port     = default_port

        # Basic hostname sanity check
        if not hostname or " " in hostname:
            errors.append(f"  malformed hostname '{hostname}' — skipping")
            continue

        if port < 1 or port > 65535:
            errors.append(f"  port {port} out of range in '{line}' — skipping")
            continue

        # Deduplicate while preserving order
        key = (hostname.lower(), port)
        if key not in seen:
            seen.add(key)
            hosts.append((hostname, port))

    if errors:
        print("cert-canary: host parse warnings:", file=sys.stderr)
        for e in errors:
            print(e, file=sys.stderr)

    return hosts


def _read_hosts_file(path: str) -> list[str]:
    """Read a hosts file and return raw lines. Raises SystemExit on error."""
    try:
        with open(path) as fh:
            return fh.readlines()
    except FileNotFoundError:
        _die(f"Hosts file not found: {path}")
    except PermissionError:
        _die(f"Permission denied reading hosts file: {path}")


# ─────────────────────────────────────────────
# Validation
# ─────────────────────────────────────────────

# Expected types for each top-level config key
_KEY_TYPES: dict[str, type | tuple] = {
    "hosts":           list,
    "thresholds":      dict,
    "threads":         int,
    "interval":        int,
    "timeout":         int,
    "once":            bool,
    "slack_webhook":   str,
    "discord_webhook": str,
    "pagerduty_key":   str,
    "webhook_url":     str,
    "webhook_secret":  str,
    "smtp":            dict,
}

_THRESHOLD_KEYS = ("critical", "warning", "info")


def _validate_config(cfg: dict, source: str = "config") -> None:
    """
    Validate config keys and types. Prints warnings for unknown keys
    and raises SystemExit for type mismatches on known keys.
    Does not validate values (e.g. whether a URL is reachable).
    """
    known = set(_KEY_TYPES.keys())

    for key, val in cfg.items():
        if key not in known:
            print(
                f"cert-canary: warning: unknown config key '{key}' in {source}",
                file=sys.stderr,
            )
            continue

        expected = _KEY_TYPES[key]
        if val is not None and not isinstance(val, expected):
            _die(
                f"Config key '{key}' in {source} must be "
                f"{expected.__name__ if isinstance(expected, type) else expected}, "
                f"got {type(val).__name__}"
            )

    # Validate thresholds sub-keys
    thresholds = cfg.get("thresholds")
    if isinstance(thresholds, dict):
        for k, v in thresholds.items():
            if k.startswith("_"):
                continue
            if k not in _THRESHOLD_KEYS:
                print(
                    f"cert-canary: warning: unknown threshold key '{k}' in {source}",
                    file=sys.stderr,
                )
            elif not isinstance(v, int):
                _die(
                    f"Threshold '{k}' in {source} must be an integer (days), "
                    f"got {type(v).__name__}"
                )
            elif v < 0:
                _die(f"Threshold '{k}' in {source} must be >= 0, got {v}")

    # Validate smtp sub-keys if present
    smtp = cfg.get("smtp")
    if isinstance(smtp, dict):
        _validate_smtp(smtp, source)


def _validate_smtp(smtp: dict, source: str) -> None:
    """Validate required SMTP fields."""
    required = ("host", "port", "user", "password", "to")
    missing  = [k for k in required if k not in smtp or not smtp[k]]

    if missing:
        _die(
            f"SMTP config in {source} is missing required fields: "
            f"{', '.join(missing)}"
        )

    if not isinstance(smtp.get("port"), int):
        _die(f"SMTP 'port' in {source} must be an integer")

    if not isinstance(smtp.get("to"), list) or not smtp["to"]:
        _die(f"SMTP 'to' in {source} must be a non-empty list of email addresses")


# ─────────────────────────────────────────────
# Internal helpers
# ─────────────────────────────────────────────

def _merge(base: dict, override: dict) -> dict:
    """
    Shallow merge: override wins for all top-level keys.
    Thresholds are deep-merged so partial overrides work.
    """
    result = {**base}
    for key, val in override.items():
        if key == "thresholds" and isinstance(val, dict):
            existing = result.get("thresholds", {})
            result["thresholds"] = {**existing, **val}
        else:
            result[key] = val
    return result


def _deep_copy(d: dict) -> dict:
    """
    Shallow-copy the top level and any dict values one level deep.
    Avoids mutating DEFAULT_CONFIG when callers modify the result.
    json.loads(json.dumps()) would work too but this is faster.
    """
    result = {}
    for k, v in d.items():
        result[k] = dict(v) if isinstance(v, dict) else v
    return result


def _die(message: str) -> None:
    """Print an error and exit with code 1."""
    print(f"cert-canary: error: {message}", file=sys.stderr)
    sys.exit(1)