#!/usr/bin/env python3
"""
vuln_sweep/config.py
━━━━━━━━━━━━━━━━━━━
Single source of truth for all configuration.

Priority order (highest to lowest):
  1. CLI flags         (--timeout, --threads, --all, etc.)
  2. Environment vars  (VULN_SWEEP_TIMEOUT, etc.)
  3. JSON config file  (vuln-sweep.json)
  4. Defaults          (DEFAULT_CONFIG, DEFAULT_CHECKS)

Nothing in this module does network I/O.
The only I/O is load_config() (reads a file)
and _load_env() (reads os.environ).
"""

import json
import os
import sys
from typing import Any


# ─────────────────────────────────────────────
# Check names — canonical identifiers
# ─────────────────────────────────────────────

ALL_CHECK_NAMES: list[str] = [
    "heartbleed",   # CVE-2014-0160
    "poodle",       # CVE-2014-3566
    "beast",        # CVE-2011-3389
    "robot",        # CVE-2017-17382
    "drown",        # CVE-2016-0800
    "lucky13",      # CVE-2013-0169
]

# Default checks run when --all is passed or no specific check is named
DEFAULT_CHECKS: list[str] = ALL_CHECK_NAMES.copy()


# ─────────────────────────────────────────────
# Defaults
# ─────────────────────────────────────────────

DEFAULT_CONFIG: dict[str, Any] = {
    # Target list — overridden by --target, --file, or config file
    "targets":  [],

    # Which CVE checks to run
    "checks":   DEFAULT_CHECKS,

    # Scan behaviour
    "threads":  4,      # parallel checks per host (not parallel hosts)
    "timeout":  6,      # per-check socket timeout in seconds
    "port":     443,    # default port when not specified in target

    # Output modes
    "json_out":  None,  # path to write JSON snapshot
    "jsonl_out": None,  # path to append JSONL audit log
    "html_out":  None,  # path to write HTML report
    "verbose":   False, # show detail for all checks, not just findings

    # One-shot vs daemon
    "once":     True,   # vuln-sweep is always one-shot (no daemon mode)
}

# Environment variable → config key mapping
_ENV_MAP: dict[str, str] = {
    "VULN_SWEEP_TIMEOUT": "timeout",
    "VULN_SWEEP_THREADS": "threads",
    "VULN_SWEEP_PORT":    "port",
}

# Expected types for validation
_KEY_TYPES: dict[str, type | tuple] = {
    "targets":   list,
    "checks":    list,
    "threads":   int,
    "timeout":   int,
    "port":      int,
    "json_out":  str,
    "jsonl_out": str,
    "html_out":  str,
    "verbose":   bool,
    "once":      bool,
}


# ─────────────────────────────────────────────
# JSON config loader
# ─────────────────────────────────────────────

def load_config(path: str) -> dict[str, Any]:
    """
    Load and validate a vuln-sweep.json config file.
    _comment keys are silently stripped.
    Raises SystemExit with a helpful message on error.
    """
    try:
        with open(path) as fh:
            raw = json.load(fh)
    except FileNotFoundError:
        _die(f"Config file not found: {path}")
    except json.JSONDecodeError as e:
        _die(f"Invalid JSON in {path}: {e}")

    if not isinstance(raw, dict):
        _die(f"Config must be a JSON object, got {type(raw).__name__}")

    # Strip _comment keys
    cleaned = {k: v for k, v in raw.items() if not k.startswith("_")}

    # Validate
    _validate_config(cleaned, source=path)

    # Validate check names
    if "checks" in cleaned:
        _validate_check_names(cleaned["checks"], source=path)

    return cleaned


# ─────────────────────────────────────────────
# Environment variable loader
# ─────────────────────────────────────────────

def _load_env() -> dict[str, Any]:
    """
    Read VULN_SWEEP_* environment variables.
    Only returns keys that are actually set in the environment.
    Converts int-typed env vars from strings automatically.
    """
    env_cfg: dict[str, Any] = {}

    for env_var, config_key in _ENV_MAP.items():
        val = os.environ.get(env_var, "").strip()
        if not val:
            continue

        # Convert to correct type
        expected = _KEY_TYPES.get(config_key)
        if expected is int:
            try:
                env_cfg[config_key] = int(val)
            except ValueError:
                print(
                    f"vuln-sweep: warning: {env_var}={val!r} "
                    f"is not an integer — ignoring",
                    file=sys.stderr,
                )
        else:
            env_cfg[config_key] = val

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
        Complete config dict ready for scanner and report modules.
    """
    # Start from defaults
    cfg = _deep_copy(DEFAULT_CONFIG)

    # Layer 1: JSON config file
    if getattr(args, "config", None):
        file_cfg = load_config(args.config)
        cfg = _merge(cfg, file_cfg)

    # Layer 2: Environment variables
    cfg = _merge(cfg, _load_env())

    # Layer 3: CLI flags
    cfg = _merge(cfg, _extract_cli(args))

    # Resolve which checks to run
    cfg["checks"] = _resolve_checks(args, cfg)

    # Clamp numerics
    cfg["threads"] = max(1, int(cfg.get("threads", 4)))
    cfg["timeout"] = max(1, int(cfg.get("timeout", 6)))
    cfg["port"]    = max(1, min(65535, int(cfg.get("port", 443))))

    return cfg


def _extract_cli(args) -> dict[str, Any]:
    """
    Pull explicitly set CLI values from the argparse Namespace.
    Skips None/False/unset values so they don't overwrite
    file or env config.
    """
    cli: dict[str, Any] = {}

    # Target sources
    if getattr(args, "target", None):
        cli["targets"] = [args.target]
    elif getattr(args, "file", None):
        cli["targets"] = _read_targets_file(args.file)

    # Numerics — only if explicitly set
    for attr, key in [
        ("threads", "threads"),
        ("timeout", "timeout"),
        ("port",    "port"),
    ]:
        val = getattr(args, attr, None)
        if val is not None:
            cli[key] = val

    # Output paths
    for attr, key in [
        ("json_out",  "json_out"),
        ("jsonl_out", "jsonl_out"),
        ("html_out",  "html_out"),
    ]:
        val = getattr(args, attr, None)
        if val:
            cli[key] = val

    # Flags
    if getattr(args, "verbose", False):
        cli["verbose"] = True

    return cli


def _resolve_checks(args, cfg: dict) -> list[str]:
    """
    Determine which CVE checks to run.

    Priority:
      1. Explicit check flags on CLI (--heartbleed, --robot, etc.)
      2. checks list from config file
      3. DEFAULT_CHECKS (all of them) if --all or nothing specified

    Always returns a deduplicated list in canonical order
    (same order as ALL_CHECK_NAMES).
    """
    # Collect explicitly named CLI checks
    explicit = [
        name for name in ALL_CHECK_NAMES
        if getattr(args, name, False)
    ]

    if explicit:
        # CLI flags win — run only what was named
        return explicit

    if getattr(args, "all", False):
        # --all flag — run everything
        return ALL_CHECK_NAMES.copy()

    # Fall back to config file value or default
    checks = cfg.get("checks", DEFAULT_CHECKS)

    # Validate and filter to known names
    valid = [c for c in checks if c in ALL_CHECK_NAMES]
    unknown = [c for c in checks if c not in ALL_CHECK_NAMES]
    if unknown:
        print(
            f"vuln-sweep: warning: unknown check name(s) in config: "
            f"{', '.join(unknown)} — ignoring",
            file=sys.stderr,
        )

    return valid if valid else ALL_CHECK_NAMES.copy()


# ─────────────────────────────────────────────
# Target parser
# ─────────────────────────────────────────────

def parse_targets(
    config:       dict[str, Any],
    default_port: int = 443,
) -> list[tuple[str, int]]:
    """
    Parse raw target strings into (host, port) tuples.

    Accepts:
      "example.com"            → ("example.com", 443)
      "example.com:8443"       → ("example.com", 8443)
      "192.168.1.1"            → ("192.168.1.1", 443)
      "192.168.1.1:8443"       → ("192.168.1.1", 8443)
      "# comment"              → skipped
      ""                       → skipped

    Note: CIDR ranges (192.168.1.0/24) are intentionally
    not expanded here — use a dedicated network scanner
    to generate the host list and pass via --file.

    Args:
        config:       Full config dict from build_config().
        default_port: Port to use when not in target string.

    Returns:
        Deduplicated list of (host, port) tuples, order preserved.
    """
    raw          = config.get("targets", [])
    default_port = config.get("port", default_port)

    seen:    set[tuple[str, int]]  = set()
    targets: list[tuple[str, int]] = []
    errors:  list[str]             = []

    for line in raw:
        line = line.strip()

        # Skip blanks and comments
        if not line or line.startswith("#"):
            continue

        # CIDR notation — warn and skip
        if "/" in line:
            errors.append(
                f"  CIDR '{line}' not supported — "
                "expand to host list with nmap -sL first"
            )
            continue

        # Parse host:port or bare host
        if ":" in line:
            parts = line.rsplit(":", 1)
            host  = parts[0].strip()
            try:
                port = int(parts[1].strip())
            except ValueError:
                errors.append(f"  invalid port in '{line}' — skipping")
                continue
        else:
            host = line
            port = default_port

        # Sanity checks
        if not host or " " in host:
            errors.append(f"  malformed host '{host}' — skipping")
            continue

        if not (1 <= port <= 65535):
            errors.append(f"  port {port} out of range in '{line}' — skipping")
            continue

        # Deduplicate, preserve order
        key = (host.lower(), port)
        if key not in seen:
            seen.add(key)
            targets.append((host, port))

    if errors:
        print("vuln-sweep: target parse warnings:", file=sys.stderr)
        for e in errors:
            print(e, file=sys.stderr)

    return targets


def _read_targets_file(path: str) -> list[str]:
    """Read a targets file and return raw lines."""
    try:
        with open(path) as fh:
            return [line.strip() for line in fh.readlines()]
    except FileNotFoundError:
        _die(f"Targets file not found: {path}")
    except PermissionError:
        _die(f"Permission denied reading targets file: {path}")


# ─────────────────────────────────────────────
# Validation
# ─────────────────────────────────────────────

def _validate_config(cfg: dict, source: str = "config") -> None:
    """
    Validate config key types.
    Warns on unknown keys, raises SystemExit on type mismatches.
    """
    known = set(_KEY_TYPES.keys())

    for key, val in cfg.items():
        if key not in known:
            print(
                f"vuln-sweep: warning: unknown config key '{key}' in {source}",
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


def _validate_check_names(names: list, source: str = "config") -> None:
    """Warn about unknown check names in the checks list."""
    if not isinstance(names, list):
        _die(f"'checks' in {source} must be a list of check names")

    unknown = [n for n in names if n not in ALL_CHECK_NAMES]
    if unknown:
        print(
            f"vuln-sweep: warning: unknown check(s) in {source}: "
            f"{', '.join(unknown)}\n"
            f"  Valid checks: {', '.join(ALL_CHECK_NAMES)}",
            file=sys.stderr,
        )


# ─────────────────────────────────────────────
# Internal helpers
# ─────────────────────────────────────────────

def _merge(base: dict, override: dict) -> dict:
    """
    Shallow merge — override wins for every top-level key.
    Lists (targets, checks) are replaced entirely, not appended.
    """
    return {**base, **override}


def _deep_copy(d: dict) -> dict:
    """
    Copy top-level dict and any list/dict values one level deep.
    Prevents mutations of DEFAULT_CONFIG across build_config() calls.
    """
    result = {}
    for k, v in d.items():
        if isinstance(v, dict):
            result[k] = dict(v)
        elif isinstance(v, list):
            result[k] = list(v)
        else:
            result[k] = v
    return result


def _die(message: str) -> None:
    """Print a fatal error and exit with code 1."""
    print(f"vuln-sweep: error: {message}", file=sys.stderr)
    sys.exit(1)