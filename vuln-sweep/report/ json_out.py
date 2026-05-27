#!/usr/bin/env python3
"""
vuln_sweep/report/json_out.py
━━━━━━━━━━━━━━━━━━━━━━━━━━━━
JSON and JSONL output formatter for vuln-sweep.

Produces two output modes:

  JSON snapshot  (config["json_out"]):
    Writes a single JSON object to a file.
    Overwrites on every call.
    In per-host mode: one VulnResult object.
    In summary mode: a full SweepReport object.
    Use for: single-target scans, CI/CD pipeline integration,
             machine-readable output for downstream tooling.

  JSONL audit log (config["jsonl_out"]):
    Appends one JSON object per line to a file.
    Never overwrites — always appends.
    One record per host per sweep.
    Use for: long-running audit trails, multi-sweep history,
             feeding into SIEM/log aggregation systems.

Schema:
    Both modes produce flat, JSON-serialisable dicts via
    dataclasses.asdict(). All fields are present in every record
    so consumers never need to handle missing keys.

Public API:
  write(result_or_report, config,
        jsonl_mode=False, summary_mode=False) → None
"""

import json
import os
from dataclasses import asdict
from datetime import datetime, timezone
from typing import TYPE_CHECKING, Any, Union

if TYPE_CHECKING:
    from vuln_sweep.scanner     import VulnResult, SweepReport
    from vuln_sweep.checks.base import CheckResult


# ─────────────────────────────────────────────
# Public write function
# ─────────────────────────────────────────────

def write(
    result,
    config:       dict,
    jsonl_mode:   bool = False,
    summary_mode: bool = False,
) -> None:
    """
    Write JSON or JSONL output to the configured path.

    Mode matrix:
      jsonl_mode=False, summary_mode=False → JSON per-host snapshot
      jsonl_mode=False, summary_mode=True  → JSON full sweep snapshot
      jsonl_mode=True,  summary_mode=False → JSONL append per-host record
      jsonl_mode=True,  summary_mode=True  → JSONL append sweep summary

    Args:
        result:       VulnResult (per-host) or SweepReport (summary).
        config:       Full config dict.
        jsonl_mode:   If True, append to jsonl_out path instead of
                      overwriting json_out path.
        summary_mode: If True, serialise as SweepReport rather than
                      VulnResult.
    """
    if jsonl_mode:
        path = config.get("jsonl_out")
    else:
        path = config.get("json_out")

    if not path:
        return

    if summary_mode:
        payload = _serialise_sweep_report(result, config)
    else:
        payload = _serialise_vuln_result(result, config)

    if jsonl_mode:
        _append_jsonl(path, payload)
    else:
        _write_json(path, payload)


# ─────────────────────────────────────────────
# Serialisers
# ─────────────────────────────────────────────

def _serialise_vuln_result(
    result: "VulnResult",
    config: dict,
) -> dict[str, Any]:
    """
    Serialise a single VulnResult to a JSON-ready dict.

    Schema:
    {
      "schema_version": "1.0",
      "tool":           "vuln-sweep",
      "generated_at":   "2026-05-21T14:00:00Z",
      "host":           "example.com",
      "port":           443,
      "grade":          "A",
      "vuln_count":     0,
      "duration_ms":    1234.5,
      "scan_time":      "2026-05-21T14:00:00Z",
      "checks": [
        {
          "cve":         "CVE-2014-0160",
          "name":        "Heartbleed",
          "status":      "NOT_VULNERABLE",
          "vulnerable":  false,
          "detail":      "...",
          "error":       "",
          "duration_ms": 450.2
        },
        ...
      ],
      "cves_found":     [],
      "config_snapshot": {
        "checks":  ["heartbleed", "poodle", ...],
        "timeout": 6,
        "threads": 4
      }
    }
    """
    return {
        "schema_version":  "1.0",
        "tool":            "vuln-sweep",
        "generated_at":    _now_iso(),
        "host":            result.host,
        "port":            result.port,
        "grade":           result.grade,
        "vuln_count":      result.vuln_count,
        "clean_count":     result.clean_count,
        "inconclusive_count": result.inconclusive_count,
        "error_count":     result.error_count,
        "duration_ms":     round(result.duration_ms, 2),
        "scan_time":       result.scan_time,
        "checks":          [_serialise_check(c) for c in result.checks],
        "cves_found":      result.cves_found,
        "config_snapshot": _config_snapshot(config),
    }


def _serialise_sweep_report(
    report: "SweepReport",
    config: dict,
) -> dict[str, Any]:
    """
    Serialise a full SweepReport to a JSON-ready dict.

    Schema:
    {
      "schema_version":   "1.0",
      "tool":             "vuln-sweep",
      "generated_at":     "2026-05-21T14:00:00Z",
      "grade":            "A",
      "total_hosts":      5,
      "vulnerable_hosts": 0,
      "clean_hosts":      5,
      "error_hosts":      0,
      "total_vulns":      0,
      "all_cves_found":   [],
      "start_time":       "2026-05-21T14:00:00Z",
      "end_time":         "2026-05-21T14:01:30Z",
      "duration_ms":      90123.4,
      "checks_run":       ["heartbleed", "poodle", ...],
      "results": [ ...per-host VulnResult dicts... ],
      "config_snapshot": { ... }
    }
    """
    return {
        "schema_version":   "1.0",
        "tool":             "vuln-sweep",
        "generated_at":     _now_iso(),
        "grade":            report.grade,
        "total_hosts":      report.total_hosts,
        "vulnerable_hosts": report.vulnerable_hosts,
        "clean_hosts":      report.clean_hosts,
        "error_hosts":      report.error_hosts,
        "total_vulns":      report.total_vulns,
        "all_cves_found":   report.all_cves_found,
        "start_time":       report.start_time,
        "end_time":         report.end_time,
        "duration_ms":      round(report.duration_ms, 2),
        "checks_run":       report.checks_run,
        "results": [
            _serialise_vuln_result(r, config)
            for r in report.results
        ],
        "config_snapshot":  _config_snapshot(config),
    }


def _serialise_check(check: "CheckResult") -> dict[str, Any]:
    """
    Serialise a single CheckResult to a JSON-ready dict.

    Uses check.status (NOT_VULNERABLE / VULNERABLE / INCONCLUSIVE / ERROR)
    rather than raw vulnerable bool so consumers don't have to handle
    nullable booleans.
    """
    return {
        "cve":         check.cve,
        "name":        check.name,
        "status":      check.status,
        "vulnerable":  check.vulnerable,
        "detail":      check.detail,
        "error":       check.error,
        "duration_ms": round(check.duration_ms, 2),
        "color_hex":   check.color_hex,
    }


def _config_snapshot(config: dict) -> dict[str, Any]:
    """
    Extract the scan configuration into a JSON-ready dict.
    Included in every output record so the file is self-documenting —
    a consumer can always see exactly how the scan was configured.
    Credentials are never included.
    """
    return {
        "checks":  config.get("checks",  []),
        "timeout": config.get("timeout", 6),
        "threads": config.get("threads", 4),
        "port":    config.get("port",    443),
    }


# ─────────────────────────────────────────────
# File writers
# ─────────────────────────────────────────────

def _write_json(path: str, payload: dict) -> None:
    """
    Write a JSON object to path, overwriting any existing file.
    Uses 2-space indentation for human readability.
    """
    _ensure_dir(path)
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(payload, fh, indent=2, default=_json_default)
        fh.write("\n")      # trailing newline for POSIX compatibility


def _append_jsonl(path: str, payload: dict) -> None:
    """
    Append a JSON object as a single line to path.
    Creates the file if it does not exist.
    Uses compact encoding (no indentation) for log efficiency.
    No trailing newline on the last line — the newline is written
    before the payload so every line including the first is
    terminated by a newline at the end of the previous line.

    JSONL format: one complete JSON object per line, newline-delimited.
    Compatible with: jq, Splunk, Elasticsearch, Datadog, BigQuery.
    """
    _ensure_dir(path)
    with open(path, "a", encoding="utf-8") as fh:
        fh.write(json.dumps(payload, default=_json_default) + "\n")


# ─────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────

def _now_iso() -> str:
    """Return current UTC time as ISO-8601 string with Z suffix."""
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _ensure_dir(path: str) -> None:
    """Create parent directories for path if they don't exist."""
    parent = os.path.dirname(os.path.abspath(path))
    os.makedirs(parent, exist_ok=True)


def _json_default(obj: Any) -> Any:
    """
    JSON serialisation fallback for non-standard types.
    Called by json.dump() when it encounters an unknown type.

    Handles:
      - dataclasses → dict via asdict()
      - datetime    → ISO-8601 string
      - set         → sorted list (for deterministic output)
      - bytes       → hex string
      - anything else → str()
    """
    import dataclasses
    if dataclasses.is_dataclass(obj) and not isinstance(obj, type):
        return asdict(obj)
    if isinstance(obj, datetime):
        return obj.isoformat().replace("+00:00", "Z")
    if isinstance(obj, set):
        return sorted(obj)
    if isinstance(obj, bytes):
        return obj.hex()
    return str(obj)


# ─────────────────────────────────────────────
# JSONL reader (for audit log introspection)
# ─────────────────────────────────────────────

def read_jsonl(path: str) -> list[dict]:
    """
    Read a JSONL audit log and return a list of records.
    Skips blank lines and malformed JSON lines with a warning.

    Not used by the write path — provided as a utility for
    scripts that consume the audit log (e.g. trend analysis,
    reporting pipelines, test fixtures).

    Args:
        path: Path to a JSONL audit log file.

    Returns:
        List of dicts, one per valid line.
    """
    import sys

    records = []
    try:
        with open(path, encoding="utf-8") as fh:
            for lineno, line in enumerate(fh, 1):
                line = line.strip()
                if not line:
                    continue
                try:
                    records.append(json.loads(line))
                except json.JSONDecodeError as e:
                    print(
                        f"vuln-sweep: jsonl warning: "
                        f"skipping malformed line {lineno} in {path}: {e}",
                        file=sys.stderr,
                    )
    except FileNotFoundError:
        pass    # Caller treats missing file as empty log

    return records


def jsonl_summary(path: str) -> dict[str, Any]:
    """
    Return a summary dict for a JSONL audit log.
    Useful for trend reporting and dashboard integration.

    Returns:
    {
      "total_records":   int,
      "hosts_seen":      list[str],
      "cves_found":      list[str],    # deduplicated across all records
      "first_scan":      str,          # ISO-8601
      "last_scan":       str,          # ISO-8601
      "vuln_records":    int,          # records with vuln_count > 0
    }
    """
    records = read_jsonl(path)
    if not records:
        return {
            "total_records": 0,
            "hosts_seen":    [],
            "cves_found":    [],
            "first_scan":    "",
            "last_scan":     "",
            "vuln_records":  0,
        }

    hosts_seen: set[str] = set()
    cves_found: set[str] = set()
    timestamps: list[str] = []
    vuln_records = 0

    for rec in records:
        host = rec.get("host", "")
        port = rec.get("port", 443)
        if host:
            hosts_seen.add(f"{host}:{port}")

        for cve in rec.get("cves_found", []):
            cves_found.add(cve)

        if rec.get("scan_time"):
            timestamps.append(rec["scan_time"])

        if rec.get("vuln_count", 0) > 0:
            vuln_records += 1

    timestamps.sort()

    return {
        "total_records": len(records),
        "hosts_seen":    sorted(hosts_seen),
        "cves_found":    sorted(cves_found),
        "first_scan":    timestamps[0]  if timestamps else "",
        "last_scan":     timestamps[-1] if timestamps else "",
        "vuln_records":  vuln_records,
    }