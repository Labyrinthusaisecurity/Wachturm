#!/usr/bin/env python3
"""
main.py — cert-canary CLI entry point
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Thin shell that wires together the cert_canary package modules.
All business logic lives in the package — this file only:
  1. Parses CLI arguments
  2. Builds config
  3. Runs the sweep loop
  4. Dispatches alerts
  5. Handles exit codes

Usage:
  python3 main.py --host example.com --once
  python3 main.py --hosts hosts.txt --threads 20 --verbose
  python3 main.py --config canary.json
  python3 main.py --hosts hosts.txt --interval 3600 --json-out audit.jsonl
"""

import argparse
import json
import sys
import time
from dataclasses import asdict
from datetime import datetime

from cert_canary.config  import build_config, parse_hosts, DEFAULT_THRESHOLDS
from cert_canary.scanner import sweep
from cert_canary.output  import print_results, print_startup_banner
from cert_canary.alerts  import dispatch_alerts


# ─────────────────────────────────────────────
# CLI argument parser
# ─────────────────────────────────────────────
def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="cert-canary",
        description="SSL/TLS certificate expiry monitor with multi-channel alerting.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
environment variables:
  CANARY_SLACK_WEBHOOK     Slack incoming webhook URL
  CANARY_DISCORD_WEBHOOK   Discord webhook URL
  CANARY_PAGERDUTY_KEY     PagerDuty Events API v2 routing key
  CANARY_WEBHOOK_URL       Generic webhook endpoint

examples:
  python3 main.py --host example.com --once
  python3 main.py --host example.com --host api.example.com --verbose
  python3 main.py --hosts hosts.txt --threads 20 --interval 3600
  python3 main.py --config canary.json --json-out audit.jsonl
  python3 main.py --hosts hosts.txt --once --json-out results.jsonl
        """,
    )

    # ── Target selection (mutually exclusive) ────────────────
    target_group = parser.add_mutually_exclusive_group()
    target_group.add_argument(
        "--host",
        action="append",
        metavar="HOST",
        dest="hosts_cli",
        help="Host to monitor. Repeatable: --host a.com --host b.com:8443",
    )
    target_group.add_argument(
        "--hosts",
        metavar="FILE",
        help="Path to file with one host[:port] per line. Lines starting with # are ignored.",
    )

    # ── Config file ───────────────────────────────────────────
    parser.add_argument(
        "--config",
        metavar="FILE",
        help="Path to JSON config file. CLI flags override config values.",
    )

    # ── Connection settings ───────────────────────────────────
    parser.add_argument(
        "--port",
        type=int,
        default=443,
        metavar="PORT",
        help="Default port when not specified in host string. (default: 443)",
    )
    parser.add_argument(
        "--timeout",
        type=int,
        default=8,
        metavar="SECS",
        help="Per-host socket timeout in seconds. (default: 8)",
    )

    # ── Scan behaviour ────────────────────────────────────────
    parser.add_argument(
        "--threads",
        type=int,
        default=10,
        metavar="N",
        help="Number of parallel scan threads. (default: 10)",
    )
    parser.add_argument(
        "--once",
        action="store_true",
        help="Run a single sweep then exit. Default is daemon mode (loop forever).",
    )
    parser.add_argument(
        "--interval",
        type=int,
        default=3600,
        metavar="SECS",
        help="Seconds between sweeps in daemon mode. (default: 3600)",
    )

    # ── Threshold overrides ───────────────────────────────────
    parser.add_argument(
        "--critical",
        type=int,
        default=None,
        metavar="DAYS",
        help=f"Days-left threshold for CRITICAL grade. (default: {DEFAULT_THRESHOLDS['critical']})",
    )
    parser.add_argument(
        "--warning",
        type=int,
        default=None,
        metavar="DAYS",
        help=f"Days-left threshold for WARNING grade. (default: {DEFAULT_THRESHOLDS['warning']})",
    )
    parser.add_argument(
        "--info",
        type=int,
        default=None,
        metavar="DAYS",
        help=f"Days-left threshold for INFO grade. (default: {DEFAULT_THRESHOLDS['info']})",
    )

    # ── Output ────────────────────────────────────────────────
    parser.add_argument(
        "--verbose",
        action="store_true",
        help="Show full cert details (CN, CA, cipher, SANs) for every host.",
    )
    parser.add_argument(
        "--json-out",
        metavar="FILE",
        help="Append JSON scan records to file (one JSON object per line, JSONL format).",
    )
    parser.add_argument(
        "--quiet",
        action="store_true",
        help="Suppress console output. Alerts still fire. Useful for cron.",
    )

    # ── Version ───────────────────────────────────────────────
    parser.add_argument(
        "--version",
        action="version",
        version="cert-canary 1.2.0",
    )

    return parser.parse_args()


# ─────────────────────────────────────────────
# JSON log writer
# ─────────────────────────────────────────────
def append_json_log(path: str, sweep_n: int, results: list) -> None:
    """Append a single sweep record to a JSONL audit log file."""
    record = {
        "sweep":     sweep_n,
        "timestamp": datetime.utcnow().isoformat() + "Z",
        "total":     len(results),
        "summary": {
            "ok":       sum(1 for r in results if r.grade == "OK"       and not r.error),
            "info":     sum(1 for r in results if r.grade == "INFO"     and not r.error),
            "warning":  sum(1 for r in results if r.grade == "WARNING"  and not r.error),
            "critical": sum(1 for r in results if r.grade == "CRITICAL" and not r.error),
            "errors":   sum(1 for r in results if r.error),
        },
        "results": [asdict(r) for r in results],
    }
    with open(path, "a") as fh:
        fh.write(json.dumps(record) + "\n")


# ─────────────────────────────────────────────
# Exit code logic
# ─────────────────────────────────────────────
def exit_code(results: list) -> int:
    """
    0 — all certs healthy
    1 — one or more in INFO / WARNING / CRITICAL
    2 — one or more hosts returned connection/SSL errors
    """
    if any(r.error for r in results):
        return 2
    if any(r.grade in ("INFO", "WARNING", "CRITICAL") for r in results):
        return 1
    return 0


# ─────────────────────────────────────────────
# Main loop
# ─────────────────────────────────────────────
def main() -> None:
    args = parse_args()

    # ── Build config (merges file + CLI flags + env vars) ────
    config = build_config(args)

    # ── Apply any threshold CLI overrides ────────────────────
    for key in ("critical", "warning", "info"):
        val = getattr(args, key, None)
        if val is not None:
            config["thresholds"][key] = val

    # ── Resolve host list ─────────────────────────────────────
    raw_hosts = config.get("hosts", [])
    if not raw_hosts:
        print("cert-canary: error: no hosts specified.", file=sys.stderr)
        print("  Use --host, --hosts FILE, or --config FILE.", file=sys.stderr)
        sys.exit(1)

    hosts = parse_hosts(raw_hosts, default_port=args.port)
    if not hosts:
        print("cert-canary: error: host list is empty after parsing.", file=sys.stderr)
        sys.exit(1)

    # ── Startup banner ────────────────────────────────────────
    if not args.quiet:
        print_startup_banner(hosts, config)

    # ── Sweep loop ────────────────────────────────────────────
    sweep_count = 0

    while True:
        sweep_count += 1

        # Run parallel scan
        results = sweep(hosts, config)

        # Console output
        if not args.quiet:
            print_results(results, verbose=args.verbose)

        # Fire all configured alert channels
        dispatch_alerts(results, config)

        # Write JSON audit log
        if args.json_out:
            append_json_log(args.json_out, sweep_count, results)
            if not args.quiet:
                print(f"  ↳ sweep #{sweep_count} appended to {args.json_out}\n")

        # One-shot mode: exit with meaningful code
        if args.once or config.get("once"):
            sys.exit(exit_code(results))

        # Daemon mode: sleep until next sweep
        if not args.quiet:
            print(f"  Next sweep in {config['interval']}s  (Ctrl-C to stop)\n")

        try:
            time.sleep(config["interval"])
        except KeyboardInterrupt:
            if not args.quiet:
                print("\ncert-canary stopped.")
            sys.exit(0)


# ─────────────────────────────────────────────
# Entry point
# ─────────────────────────────────────────────
if __name__ == "__main__":
    main()