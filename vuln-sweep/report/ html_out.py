#!/usr/bin/env python3
"""
vuln_sweep/report/html_out.py
━━━━━━━━━━━━━━━━━━━━━━━━━━━━
HTML audit report formatter for vuln-sweep.

Generates a self-contained single-file HTML report with:
  • Executive summary with overall grade and finding counts
  • Per-host results table with CVE exposure matrix
  • Per-finding detail cards with remediation guidance
  • CVSS scores and CVE metadata
  • Timestamp, scan duration, and tool metadata footer

Zero external dependencies — pure Python stdlib.
All CSS and JS is inlined. The output file opens in any browser
with no internet connection required.

Public API:
  write(result_or_report, config, summary_mode=False) → None
"""

import json
import os
from dataclasses import asdict
from datetime import datetime, timezone
from typing import TYPE_CHECKING, Union

if TYPE_CHECKING:
    from vuln_sweep.scanner     import VulnResult, SweepReport
    from vuln_sweep.checks.base import CheckResult


# ─────────────────────────────────────────────
# Public write function
# ─────────────────────────────────────────────

def write(
    result,
    config:       dict,
    summary_mode: bool = False,
) -> None:
    """
    Write an HTML audit report to config["html_out"].

    In per-host mode (summary_mode=False):
        Called after each host sweep. Overwrites the file with a
        single-host report. Useful for quick single-target scans.

    In summary mode (summary_mode=True):
        Called after all hosts are scanned. Overwrites the file with
        the full multi-host consolidated report.

    Args:
        result:       VulnResult (per-host) or SweepReport (summary).
        config:       Full config dict. Reads config["html_out"].
        summary_mode: True for SweepReport, False for VulnResult.
    """
    path = config.get("html_out")
    if not path:
        return

    if summary_mode:
        html = _render_sweep_report(result, config)
    else:
        html = _render_vuln_result(result, config)

    with open(path, "w", encoding="utf-8") as fh:
        fh.write(html)


# ─────────────────────────────────────────────
# Single-host report renderer
# ─────────────────────────────────────────────

def _render_vuln_result(result: "VulnResult", config: dict) -> str:
    """Render a self-contained HTML report for one host."""
    host_str  = f"{result.host}:{result.port}"
    grade     = result.grade
    scan_time = _fmt_time(result.scan_time)
    duration  = f"{result.duration_ms / 1000:.1f}s"

    check_rows = "\n".join(
        _render_check_row(c) for c in result.checks
    )
    finding_cards = "\n".join(
        _render_finding_card(c) for c in result.checks
        if c.vulnerable is True
    )

    vuln_count  = result.vuln_count
    clean_count = result.clean_count
    incon_count = result.inconclusive_count
    error_count = result.error_count

    return _wrap_html(
        title      = f"vuln-sweep — {host_str}",
        body       = f"""
        {_render_header_single(host_str, grade, scan_time, duration)}
        {_render_stats_bar(vuln_count, clean_count, incon_count, error_count)}
        {_render_check_table(check_rows)}
        {finding_cards if finding_cards else _render_all_clear()}
        {_render_footer(config)}
        """,
    )


# ─────────────────────────────────────────────
# Multi-host report renderer
# ─────────────────────────────────────────────

def _render_sweep_report(report: "SweepReport", config: dict) -> str:
    """Render a self-contained HTML report for all hosts."""
    scan_time = _fmt_time(report.start_time)
    duration  = f"{report.duration_ms / 1000:.1f}s"

    host_rows = "\n".join(
        _render_host_summary_row(r) for r in report.results
    )
    finding_cards = "\n".join(
        _render_finding_card(c)
        for r in report.results
        for c in r.checks
        if c.vulnerable is True
    )
    cve_matrix = _render_cve_matrix(report)

    return _wrap_html(
        title = "vuln-sweep — Audit Report",
        body  = f"""
        {_render_header_multi(report, scan_time, duration)}
        {_render_sweep_stats(report)}
        {_render_host_table(host_rows)}
        {cve_matrix}
        {finding_cards if finding_cards else _render_all_clear()}
        {_render_footer(config)}
        """,
    )


# ─────────────────────────────────────────────
# Section renderers
# ─────────────────────────────────────────────

def _render_header_single(
    host_str:  str,
    grade:     str,
    scan_time: str,
    duration:  str,
) -> str:
    grade_color = _grade_color(grade)
    return f"""
    <div class="report-header">
      <div class="header-left">
        <div class="tool-name">🔬 vuln-sweep</div>
        <div class="target-name">{_esc(host_str)}</div>
        <div class="meta">
          Scanned {_esc(scan_time)} · {_esc(duration)}
        </div>
      </div>
      <div class="header-right">
        <div class="grade-circle" style="background:{grade_color}">
          {_esc(grade)}
        </div>
        <div class="grade-label">Security Grade</div>
      </div>
    </div>"""


def _render_header_multi(
    report:    "SweepReport",
    scan_time: str,
    duration:  str,
) -> str:
    grade       = report.grade
    grade_color = _grade_color(grade)
    return f"""
    <div class="report-header">
      <div class="header-left">
        <div class="tool-name">🔬 vuln-sweep</div>
        <div class="target-name">Audit Report</div>
        <div class="meta">
          {report.total_hosts} hosts · {len(report.checks_run)} CVE checks ·
          Scanned {_esc(scan_time)} · {_esc(duration)}
        </div>
      </div>
      <div class="header-right">
        <div class="grade-circle" style="background:{grade_color}">
          {_esc(grade)}
        </div>
        <div class="grade-label">Overall Grade</div>
      </div>
    </div>"""


def _render_stats_bar(
    vuln:  int,
    clean: int,
    incon: int,
    error: int,
) -> str:
    total = vuln + clean + incon + error
    return f"""
    <div class="stats-bar">
      <div class="stat {('stat-critical' if vuln > 0 else '')}">
        <span class="stat-n">{vuln}</span>
        <span class="stat-l">VULNERABLE</span>
      </div>
      <div class="stat">
        <span class="stat-n" style="color:var(--green)">{clean}</span>
        <span class="stat-l">CLEAN</span>
      </div>
      <div class="stat">
        <span class="stat-n" style="color:var(--amber)">{incon}</span>
        <span class="stat-l">INCONCLUSIVE</span>
      </div>
      <div class="stat">
        <span class="stat-n" style="color:var(--muted)">{error}</span>
        <span class="stat-l">ERRORS</span>
      </div>
      <div class="stat">
        <span class="stat-n">{total}</span>
        <span class="stat-l">TOTAL CHECKS</span>
      </div>
    </div>"""


def _render_sweep_stats(report: "SweepReport") -> str:
    return f"""
    <div class="stats-bar">
      <div class="stat {('stat-critical' if report.vulnerable_hosts > 0 else '')}">
        <span class="stat-n">{report.vulnerable_hosts}</span>
        <span class="stat-l">VULNERABLE HOSTS</span>
      </div>
      <div class="stat">
        <span class="stat-n" style="color:var(--green)">{report.clean_hosts}</span>
        <span class="stat-l">CLEAN HOSTS</span>
      </div>
      <div class="stat">
        <span class="stat-n" style="color:var(--red)">{report.total_vulns}</span>
        <span class="stat-l">TOTAL FINDINGS</span>
      </div>
      <div class="stat">
        <span class="stat-n">{report.total_hosts}</span>
        <span class="stat-l">HOSTS SCANNED</span>
      </div>
    </div>"""


def _render_check_table(rows: str) -> str:
    return f"""
    <section>
      <h2>CVE Check Results</h2>
      <table class="results-table">
        <thead>
          <tr>
            <th>CVE</th>
            <th>Name</th>
            <th>Status</th>
            <th>CVSS</th>
            <th>Duration</th>
          </tr>
        </thead>
        <tbody>{rows}</tbody>
      </table>
    </section>"""


def _render_check_row(check: "CheckResult") -> str:
    status_cls, status_label = _status_cell(check)
    cvss = _cvss_for_check(check.name)

    return f"""
        <tr>
          <td><code>{_esc(check.cve)}</code></td>
          <td><strong>{_esc(check.name)}</strong></td>
          <td><span class="badge {status_cls}">{status_label}</span></td>
          <td>{_esc(cvss)}</td>
          <td class="muted">{check.duration_ms:.0f}ms</td>
        </tr>"""


def _render_host_table(rows: str) -> str:
    return f"""
    <section>
      <h2>Host Summary</h2>
      <table class="results-table">
        <thead>
          <tr>
            <th>Host</th>
            <th>Grade</th>
            <th>Findings</th>
            <th>Duration</th>
          </tr>
        </thead>
        <tbody>{rows}</tbody>
      </table>
    </section>"""


def _render_host_summary_row(result: "VulnResult") -> str:
    host_str    = f"{result.host}:{result.port}"
    grade_color = _grade_color(result.grade)
    vuln_n      = result.vuln_count

    vuln_cell = (
        f'<span class="badge badge-vuln">{vuln_n} finding{"s" if vuln_n != 1 else ""}</span>'
        if vuln_n > 0
        else '<span class="badge badge-clean">Clean</span>'
    )

    return f"""
        <tr>
          <td><strong>{_esc(host_str)}</strong></td>
          <td>
            <span class="grade-badge" style="background:{grade_color}">
              {_esc(result.grade)}
            </span>
          </td>
          <td>{vuln_cell}</td>
          <td class="muted">{result.duration_ms:.0f}ms</td>
        </tr>"""


def _render_cve_matrix(report: "SweepReport") -> str:
    """
    Render a host × CVE matrix showing vulnerability status
    for every combination. Each cell is colour-coded.
    """
    from vuln_sweep.checks import CVE_MAP

    checks = report.checks_run
    hosts  = [f"{r.host}:{r.port}" for r in report.results]

    # Header row
    header_cells = "".join(
        f'<th title="{_esc(CVE_MAP.get(c, c))}">{_esc(c.upper())}</th>'
        for c in checks
    )

    # Data rows
    data_rows = ""
    for result in report.results:
        host_str = f"{result.host}:{result.port}"

        # Build a lookup by check name
        by_name = {
            c.name.lower(): c for c in result.checks
        }

        cells = ""
        for check_name in checks:
            check = by_name.get(check_name.lower())
            if check is None:
                cells += '<td class="matrix-na">—</td>'
            elif check.error:
                cells += '<td class="matrix-error" title="Error">⚫</td>'
            elif check.vulnerable is True:
                cells += f'<td class="matrix-vuln" title="{_esc(check.cve)}">🔴</td>'
            elif check.vulnerable is False:
                cells += '<td class="matrix-clean">🟢</td>'
            else:
                cells += '<td class="matrix-incon">🟡</td>'

        data_rows += f"""
        <tr>
          <td class="matrix-host"><strong>{_esc(host_str)}</strong></td>
          {cells}
        </tr>"""

    return f"""
    <section>
      <h2>CVE Exposure Matrix</h2>
      <div class="matrix-wrap">
        <table class="matrix-table">
          <thead>
            <tr>
              <th>Host</th>
              {header_cells}
            </tr>
          </thead>
          <tbody>{data_rows}</tbody>
        </table>
      </div>
      <div class="matrix-legend">
        <span>🔴 Vulnerable</span>
        <span>🟢 Clean</span>
        <span>🟡 Inconclusive</span>
        <span>⚫ Error</span>
        <span>— Not checked</span>
      </div>
    </section>"""


def _render_finding_card(check: "CheckResult") -> str:
    """Render a detailed finding card for a vulnerable check."""
    from vuln_sweep.checks import get_description, get_remediation, get_cvss

    check_key    = check.name.lower()
    description  = get_description(check_key)
    remediation  = get_remediation(check_key)
    cvss         = get_cvss(check_key)

    return f"""
    <div class="finding-card">
      <div class="finding-header">
        <div class="finding-title">
          🔴 <strong>{_esc(check.name)}</strong>
          <code class="cve-tag">{_esc(check.cve)}</code>
          <span class="cvss-tag">{_esc(cvss)}</span>
        </div>
      </div>
      <div class="finding-body">
        <div class="finding-section">
          <div class="section-label">Finding</div>
          <p>{_esc(check.detail)}</p>
        </div>
        {f'''
        <div class="finding-section">
          <div class="section-label">Vulnerability</div>
          <p>{_esc(description)}</p>
        </div>''' if description else ''}
        {f'''
        <div class="finding-section remediation">
          <div class="section-label">Remediation</div>
          <p>{_esc(remediation)}</p>
        </div>''' if remediation else ''}
      </div>
    </div>"""


def _render_all_clear() -> str:
    return """
    <div class="all-clear">
      <div class="all-clear-icon">🟢</div>
      <div class="all-clear-text">
        <strong>No vulnerabilities confirmed</strong><br>
        All CVE checks returned clean or inconclusive results.
      </div>
    </div>"""


def _render_footer(config: dict) -> str:
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    return f"""
    <footer>
      <div>Generated by <strong>vuln-sweep</strong> v1.0.0
        · Part of the <strong>Wachturm</strong> security suite</div>
      <div class="muted">{_esc(now)}</div>
    </footer>"""


# ─────────────────────────────────────────────
# HTML wrapper
# ─────────────────────────────────────────────

def _wrap_html(title: str, body: str) -> str:
    """Wrap rendered sections in the full HTML document with inline CSS."""
    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{_esc(title)}</title>
<style>
{_CSS}
</style>
</head>
<body>
<div class="container">
{body}
</div>
</body>
</html>"""


# ─────────────────────────────────────────────
# Inline CSS
# ─────────────────────────────────────────────

_CSS = """
:root {
  --bg:       #0a0c0f;
  --surface:  #111318;
  --card:     #161a21;
  --border:   #1e2430;
  --text:     #e2e8f0;
  --muted:    #64748b;
  --green:    #00ff88;
  --cyan:     #00d4ff;
  --amber:    #ffb800;
  --red:      #ff4444;
  --purple:   #a855f7;
  --mono:     'Courier New', monospace;
}

* { box-sizing: border-box; margin: 0; padding: 0; }

body {
  font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
  font-size: 14px;
  background: var(--bg);
  color: var(--text);
  line-height: 1.6;
}

.container { max-width: 960px; margin: 0 auto; padding: 2rem 1.5rem; }

/* ── Header ── */
.report-header {
  display: flex;
  justify-content: space-between;
  align-items: center;
  padding: 2rem;
  background: var(--card);
  border: 1px solid var(--border);
  border-radius: 12px;
  margin-bottom: 1.5rem;
}
.tool-name {
  font-size: 12px;
  letter-spacing: 2px;
  text-transform: uppercase;
  color: var(--muted);
  margin-bottom: 6px;
}
.target-name {
  font-size: 1.6rem;
  font-weight: 700;
  color: var(--text);
  margin-bottom: 6px;
  font-family: var(--mono);
}
.meta { font-size: 12px; color: var(--muted); }
.grade-circle {
  width: 72px;
  height: 72px;
  border-radius: 50%;
  display: flex;
  align-items: center;
  justify-content: center;
  font-size: 2rem;
  font-weight: 800;
  color: #0a0c0f;
  margin-bottom: 6px;
}
.grade-label {
  font-size: 11px;
  text-align: center;
  color: var(--muted);
  letter-spacing: 1px;
  text-transform: uppercase;
}
.header-right { text-align: center; }

/* ── Stats bar ── */
.stats-bar {
  display: flex;
  gap: 1px;
  background: var(--border);
  border: 1px solid var(--border);
  border-radius: 10px;
  overflow: hidden;
  margin-bottom: 1.5rem;
}
.stat {
  flex: 1;
  display: flex;
  flex-direction: column;
  align-items: center;
  padding: 1rem;
  background: var(--card);
  gap: 4px;
}
.stat-critical { background: rgba(255,68,68,0.08); }
.stat-n {
  font-size: 1.6rem;
  font-weight: 700;
  color: var(--red);
}
.stat-l {
  font-size: 10px;
  color: var(--muted);
  letter-spacing: 1px;
  text-transform: uppercase;
}

/* ── Sections ── */
section {
  background: var(--card);
  border: 1px solid var(--border);
  border-radius: 10px;
  padding: 1.5rem;
  margin-bottom: 1.5rem;
  overflow: hidden;
}
section h2 {
  font-size: 13px;
  font-weight: 600;
  letter-spacing: 2px;
  text-transform: uppercase;
  color: var(--muted);
  margin-bottom: 1rem;
  padding-bottom: 8px;
  border-bottom: 1px solid var(--border);
}

/* ── Tables ── */
.results-table {
  width: 100%;
  border-collapse: collapse;
  font-size: 13px;
}
.results-table th {
  text-align: left;
  font-size: 11px;
  color: var(--muted);
  text-transform: uppercase;
  letter-spacing: 1px;
  padding: 8px 12px;
  border-bottom: 1px solid var(--border);
  font-weight: 400;
}
.results-table td {
  padding: 10px 12px;
  border-bottom: 1px solid #0d1017;
  vertical-align: middle;
}
.results-table tr:last-child td { border-bottom: none; }
.results-table tr:hover td { background: rgba(255,255,255,0.02); }
code {
  font-family: var(--mono);
  font-size: 12px;
  color: var(--cyan);
}
.muted { color: var(--muted); }

/* ── Badges ── */
.badge {
  display: inline-block;
  font-size: 11px;
  padding: 3px 10px;
  border-radius: 999px;
  font-weight: 600;
  letter-spacing: 0.5px;
}
.badge-vuln  { background: rgba(255,68,68,0.15);  color: var(--red);   border: 1px solid rgba(255,68,68,0.3); }
.badge-clean { background: rgba(0,255,136,0.1);   color: var(--green); border: 1px solid rgba(0,255,136,0.2); }
.badge-incon { background: rgba(255,184,0,0.1);   color: var(--amber); border: 1px solid rgba(255,184,0,0.2); }
.badge-error { background: rgba(100,116,139,0.1); color: var(--muted); border: 1px solid var(--border); }
.grade-badge {
  display: inline-block;
  width: 28px;
  height: 28px;
  border-radius: 50%;
  text-align: center;
  line-height: 28px;
  font-weight: 800;
  font-size: 13px;
  color: #0a0c0f;
}
.cve-tag {
  font-size: 11px;
  background: var(--surface);
  border: 1px solid var(--border);
  padding: 2px 8px;
  border-radius: 4px;
  margin-left: 8px;
}
.cvss-tag {
  font-size: 11px;
  color: var(--amber);
  margin-left: 6px;
}

/* ── CVE Matrix ── */
.matrix-wrap { overflow-x: auto; }
.matrix-table {
  width: 100%;
  border-collapse: collapse;
  font-size: 12px;
}
.matrix-table th {
  padding: 8px 12px;
  text-align: center;
  font-size: 10px;
  color: var(--muted);
  border-bottom: 1px solid var(--border);
  font-weight: 600;
  letter-spacing: 1px;
  text-transform: uppercase;
}
.matrix-table th:first-child { text-align: left; }
.matrix-table td {
  padding: 8px 12px;
  text-align: center;
  border-bottom: 1px solid #0d1017;
  font-size: 14px;
}
.matrix-host { text-align: left !important; font-size: 13px; }
.matrix-vuln  { background: rgba(255,68,68,0.08); }
.matrix-clean { background: rgba(0,255,136,0.04); }
.matrix-incon { background: rgba(255,184,0,0.05); }
.matrix-error { background: rgba(100,116,139,0.06); }
.matrix-na    { color: var(--muted); }
.matrix-legend {
  display: flex;
  gap: 1.5rem;
  margin-top: 1rem;
  font-size: 12px;
  color: var(--muted);
}

/* ── Finding cards ── */
.finding-card {
  background: rgba(255,68,68,0.04);
  border: 1px solid rgba(255,68,68,0.2);
  border-radius: 10px;
  margin-bottom: 1rem;
  overflow: hidden;
}
.finding-header {
  padding: 1rem 1.25rem;
  border-bottom: 1px solid rgba(255,68,68,0.15);
  background: rgba(255,68,68,0.06);
}
.finding-title {
  display: flex;
  align-items: center;
  gap: 6px;
  font-size: 15px;
}
.finding-body { padding: 1.25rem; }
.finding-section { margin-bottom: 1rem; }
.finding-section:last-child { margin-bottom: 0; }
.section-label {
  font-size: 10px;
  font-weight: 600;
  letter-spacing: 1.5px;
  text-transform: uppercase;
  color: var(--muted);
  margin-bottom: 6px;
}
.finding-section p {
  font-size: 13px;
  color: var(--text);
  line-height: 1.7;
}
.remediation {
  background: rgba(0,255,136,0.03);
  border: 1px solid rgba(0,255,136,0.1);
  border-radius: 8px;
  padding: 1rem;
}
.remediation .section-label { color: var(--green); }

/* ── All clear ── */
.all-clear {
  display: flex;
  align-items: center;
  gap: 1rem;
  background: rgba(0,255,136,0.05);
  border: 1px solid rgba(0,255,136,0.2);
  border-radius: 10px;
  padding: 1.5rem;
  margin-bottom: 1.5rem;
}
.all-clear-icon { font-size: 2rem; }
.all-clear-text { font-size: 14px; color: var(--text); line-height: 1.6; }

/* ── Footer ── */
footer {
  display: flex;
  justify-content: space-between;
  align-items: center;
  padding: 1rem 0;
  font-size: 12px;
  color: var(--muted);
  border-top: 1px solid var(--border);
  margin-top: 1rem;
}
"""


# ─────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────

def _esc(text: str) -> str:
    """Escape text for safe HTML insertion."""
    return (
        str(text)
        .replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace('"', "&quot;")
        .replace("'", "&#39;")
    )


def _grade_color(grade: str) -> str:
    """Return a hex colour for a grade letter."""
    return {
        "A": "#00ff88",
        "B": "#00d4ff",
        "C": "#ffb800",
        "F": "#ff4444",
    }.get(grade, "#888888")


def _status_cell(check: "CheckResult") -> tuple[str, str]:
    """Return (css_class, label) for a check status badge."""
    if check.error:              return ("badge-error", "ERROR")
    if check.vulnerable is True: return ("badge-vuln",  "VULNERABLE")
    if check.vulnerable is False:return ("badge-clean", "CLEAN")
    return ("badge-incon", "INCONCLUSIVE")


def _cvss_for_check(name: str) -> str:
    """Return CVSS score string for a check name."""
    from vuln_sweep.checks import get_cvss
    return get_cvss(name.lower()) or "—"


def _fmt_time(iso: str) -> str:
    """Format an ISO-8601 timestamp to a human-readable string."""
    try:
        dt = datetime.fromisoformat(iso.rstrip("Z")).replace(tzinfo=timezone.utc)
        return dt.strftime("%Y-%m-%d %H:%M UTC")
    except Exception:
        return iso