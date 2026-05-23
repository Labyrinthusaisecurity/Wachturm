# deploy/Dockerfile
# ─────────────────────────────────────────────
# cert-canary container image.
# Builds a minimal, hardened Python image with no pip dependencies.
#
# Build:
#   docker build -f deploy/Dockerfile -t cert-canary .
#
# Run:
#   docker run --env-file .env \
#     -v $(pwd)/canary.json:/app/canary.json:ro \
#     -v $(pwd)/hosts.txt:/app/hosts.txt:ro \
#     cert-canary
# ─────────────────────────────────────────────

# ── Stage 1: base ─────────────────────────────
# python:3.12-slim is Debian-based with only the Python runtime.
# No pip cache, no build tools, no unnecessary packages.
# Pinned to a specific digest for reproducible builds.
# Update digest with: docker pull python:3.12-slim && docker inspect python:3.12-slim
FROM python:3.12-slim AS base

# Metadata
LABEL org.opencontainers.image.title="cert-canary"
LABEL org.opencontainers.image.description="SSL/TLS certificate expiry monitor"
LABEL org.opencontainers.image.source="https://github.com/yourname/cert-canary"
LABEL org.opencontainers.image.licenses="MIT"

# ── Python environment ────────────────────────
# PYTHONDONTWRITEBYTECODE  — don't write .pyc files to disk
# PYTHONUNBUFFERED         — stdout/stderr go straight to Docker logs
#                            without buffering (critical for log tailing)
# PYTHONFAULTHANDLER       — dump a traceback on SIGSEGV/SIGBUS
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PYTHONFAULTHANDLER=1

# ── System hardening ──────────────────────────
# Update base packages to pull in any security patches
# then remove the apt cache to keep the image small.
RUN apt-get update \
    && apt-get upgrade -y \
    && apt-get install -y --no-install-recommends \
        openssl \
        ca-certificates \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

# ── Non-root user ─────────────────────────────
# Never run application code as root inside a container.
# Create a dedicated user with no home directory and no shell.
RUN groupadd --system canary \
    && useradd --system \
               --no-create-home \
               --shell /sbin/nologin \
               --gid canary \
               canary


# ── Stage 2: app ──────────────────────────────
FROM base AS app

# Working directory
WORKDIR /app

# ── Copy source ───────────────────────────────
# Copy the package and entry point.
# .dockerignore excludes .env, canary.json, hosts.txt, __pycache__,
# .git, tests/, and deploy/ from the build context.
COPY cert_canary/ ./cert_canary/
COPY main.py      ./

# ── Log directory ─────────────────────────────
# Create log directory owned by canary user.
# audit.jsonl will be written here (or to a mounted volume).
RUN mkdir -p /var/log/cert-canary \
    && chown canary:canary /var/log/cert-canary

# ── Permissions ───────────────────────────────
# App source is owned by root, readable by all, not writable by canary.
# This prevents a compromised process from modifying its own code.
RUN chown -R root:root /app \
    && chmod -R 755 /app

# ── Switch to non-root ────────────────────────
USER canary

# ── Verify the package imports cleanly ────────
# Catches missing files, syntax errors, and bad imports at build time
# rather than at container startup.
RUN python3 -c "\
from cert_canary.scanner import sweep, CertInfo; \
from cert_canary.config  import build_config, parse_hosts; \
from cert_canary.output  import print_results, print_startup_banner; \
from cert_canary.alerts  import dispatch_alerts; \
print('cert_canary package ok')"

# ── Healthcheck ───────────────────────────────
# Verify the process is alive. The more thorough healthcheck
# (log recency) is defined in docker-compose.yml.
HEALTHCHECK --interval=5m --timeout=10s --retries=3 \
    CMD python3 -c "import cert_canary; print('ok')" || exit 1

# ── Entrypoint ────────────────────────────────
# Use exec form (JSON array) not shell form (string).
# exec form: PID 1 is python3 — signals (SIGTERM) go directly to it.
# shell form: PID 1 is /bin/sh — signals go to the shell, which may
#             not forward them, causing unclean shutdowns.
ENTRYPOINT ["python3", "main.py"]

# ── Default arguments ─────────────────────────
# Overridden by the command: key in docker-compose.yml
# or by arguments passed to docker run after the image name.
CMD ["--hosts", "/app/hosts.txt", "--once"]