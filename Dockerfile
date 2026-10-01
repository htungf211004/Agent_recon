# ---- Stage 1: Build ----
ARG RECON_RUNTIME_BASE=python:3.11-slim-bookworm
FROM python:3.11-slim-bookworm AS builder

WORKDIR /app

COPY requirements.txt .
RUN --mount=type=secret,id=build_ca \
    if [ -f /run/secrets/build_ca ]; then export PIP_CERT=/run/secrets/build_ca; fi; \
    python -m venv /opt/venv && /opt/venv/bin/pip install --no-cache-dir -r requirements.txt

COPY scripts/install_recon_tools.py scripts/recon-tools.lock.json ./scripts/
RUN --mount=type=secret,id=build_ca \
    if [ -f /run/secrets/build_ca ]; then export SSL_CERT_FILE=/run/secrets/build_ca; fi; \
    /opt/venv/bin/python scripts/install_recon_tools.py --prefix /opt/recon

# ---- Stage 2: Production ----
FROM ${RECON_RUNTIME_BASE}

USER root

WORKDIR /app

# Copy installed packages from builder
COPY --from=builder /opt/venv /opt/venv
COPY --from=builder /opt/recon /opt/recon
ENV PATH=/opt/recon/bin:/opt/venv/bin:$PATH \
    PLAYWRIGHT_BROWSERS_PATH=/ms-playwright

# The pinned Python package selects its matching Chromium revision.
RUN --mount=type=secret,id=build_ca \
    if [ -f /run/secrets/build_ca ]; then export NODE_EXTRA_CA_CERTS=/run/secrets/build_ca; fi; \
    python -m playwright install --with-deps chromium \
    && chmod -R a+rX /ms-playwright \
    && rm -rf /var/lib/apt/lists/*

# Security: run as non-root user
RUN apt-get update \
    && apt-get install -y --no-install-recommends nmap whatweb ffuf=1.1.0-1+b8 \
    && rm -rf /var/lib/apt/lists/*

RUN id -u appuser >/dev/null 2>&1 || useradd -m appuser

# Copy application code
COPY src ./src
COPY scripts/check_recon_runtime.py ./scripts/check_recon_runtime.py
COPY scripts/check_recon_v3_runtime.py ./scripts/check_recon_v3_runtime.py
COPY scripts/run_recon_live.py ./scripts/run_recon_live.py
COPY scripts/recon_ui.py ./scripts/recon_ui.py

# Create data directory with correct ownership
RUN mkdir -p /app/data && chown -R appuser:appuser /app

USER appuser

EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=10s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:8000/health')" || exit 1

CMD ["uvicorn", "src.main:app", "--host", "0.0.0.0", "--port", "8000"]
