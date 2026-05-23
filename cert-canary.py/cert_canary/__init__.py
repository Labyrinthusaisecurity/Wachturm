# cert_canary/__init__.py
# ─────────────────────────────────────────────
# Package metadata and public API surface.
# Anything imported here is available as:
#   from cert_canary import CertInfo, sweep
# ─────────────────────────────────────────────

__version__ = "1.2.0"
__author__  = "yourname"
__license__ = "MIT"
__email__   = "you@example.com"

from cert_canary.scanner import CertInfo, sweep
from cert_canary.config  import build_config, parse_hosts, DEFAULT_THRESHOLDS
from cert_canary.output  import print_results, print_startup_banner
from cert_canary.alerts  import dispatch_alerts

__all__ = [
    "CertInfo",
    "sweep",
    "build_config",
    "parse_hosts",
    "DEFAULT_THRESHOLDS",
    "print_results",
    "print_startup_banner",
    "dispatch_alerts",
]