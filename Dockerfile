# packages/guardian/Dockerfile
# Standalone Guardian sidecar — no LegionForge source required.
#
# Build context is this directory (packages/guardian/ in the monorepo,
# or the repo root in the standalone legionforge-guardian repo).
#
# Build:  docker build -t legionforge-guardian .
# Run:    docker compose up

FROM python:3.14-slim

# Security: non-root user
RUN addgroup --system guardian && adduser --system --ingroup guardian guardian

WORKDIR /app

# Copy the package from the build context (this directory) and install it.
# Works whether built from the standalone repo root or from packages/guardian/.
COPY . /app/guardian_pkg/
RUN pip install --no-cache-dir /app/guardian_pkg/

# Runtime directories
RUN mkdir -p /app/logs && chown -R guardian:guardian /app

USER guardian

EXPOSE ${GUARDIAN_PORT:-9766}

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD python -c "import os, urllib.request; urllib.request.urlopen('http://localhost:' + os.environ.get('GUARDIAN_PORT', '9766') + '/health')"

CMD ["python", "-m", "legionforge_guardian"]
