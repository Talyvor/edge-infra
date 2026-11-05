# Multi-stage build for the self-service broker (FastAPI API + NATS worker).
# Build from the repo root so the osb/ directory is in context.

FROM python:3.12.15-slim-trixie@sha256:02108f5d322dd89f1c9e552442c25acb0543dfdbc455693a5599624f20d9155d AS deps
WORKDIR /app
# Exactly the packages, versions and hashes in requirements.lock (make -f
# osb/Makefile lock): pip refuses anything the lock does not name, and any
# download whose hash differs from the one locked.
COPY osb/requirements.lock ./
RUN pip install --no-cache-dir --require-hashes -r requirements.lock


FROM python:3.12.15-slim-trixie@sha256:02108f5d322dd89f1c9e552442c25acb0543dfdbc455693a5599624f20d9155d
WORKDIR /app
COPY --from=deps /usr/local/lib/python3.12 /usr/local/lib/python3.12
COPY --from=deps /usr/local/bin/uvicorn   /usr/local/bin/uvicorn
# CVE-2026-103111 (pcre2, HIGH) is fixed in Debian's libpcre2-8-0
# 10.46-1~deb13u3, and CVE-2026-109518 (apt, HIGH) in apt/libapt-pkg7.0
# 3.0.4, both newer than the pinned base carries. Drop each once a base
# digest bump brings it.
RUN apt-get update \
 && apt-get install -y --no-install-recommends --only-upgrade libpcre2-8-0 apt libapt-pkg7.0 \
 && rm -rf /var/lib/apt/lists/*
COPY osb/ .
# The broker's modules are plain files in /app, importable from any directory.
ENV PYTHONPATH=/app
RUN useradd -r -u 1001 appuser
USER appuser
EXPOSE 8080
# Default CMD runs the API server. Override to ["python", "-m", "worker"]
# for the worker Deployment.
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8080", "--workers", "2"]
