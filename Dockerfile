# Ataram Email Analyzer - Backend Dockerfile
#
# Two stages so the compiler toolchain needed to build wheels never reaches the
# runtime image: gcc/g++ in a published container is a ready-made tool for
# anyone who gets code execution inside it.

# ---------------------------------------------------------------- build stage
FROM python:3.11-slim-bookworm AS builder

ENV PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    g++ \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /build
COPY requirements.txt .

# Install into a self-contained prefix that the runtime stage copies wholesale.
RUN pip install --no-cache-dir --prefix=/install -r requirements.txt

# -------------------------------------------------------------- runtime stage
FROM python:3.11-slim-bookworm

# Run as an unprivileged account. Without this the process is root inside the
# container, so any parser bug in an untrusted .eml starts from uid 0 and has a
# much shorter path to the host.
RUN groupadd --system --gid 10001 analyzer \
    && useradd --system --uid 10001 --gid analyzer --no-create-home --shell /usr/sbin/nologin analyzer

# Apply outstanding security updates from the base image, then drop the package
# lists again.
RUN apt-get update \
    && apt-get upgrade -y --no-install-recommends \
    && rm -rf /var/lib/apt/lists/*

COPY --from=builder /install /usr/local

WORKDIR /app
COPY --chown=root:root . .

# Application code is owned by root and readable — but not writable — by the
# account that runs it, so the process cannot rewrite its own source.
RUN chmod -R a-w /app \
    && rm -rf /app/tests /app/.pytest_cache /app/logs \
    && find /app -name '__pycache__' -type d -prune -exec rm -rf {} + 2>/dev/null || true

ENV FLASK_APP=run.py \
    FLASK_ENV=production \
    PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    LOG_TO_STDOUT=true

EXPOSE 5000

USER analyzer

# Uses urllib from the standard library rather than `requests` so the check does
# not depend on an application dependency staying installed.
HEALTHCHECK --interval=30s --timeout=10s --start-period=20s --retries=3 \
    CMD ["python", "-c", "import urllib.request,sys; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:5000/health', timeout=5).status == 200 else 1)"]

# Request-size limits are set explicitly rather than left to defaults: they are
# the first line against header-based resource exhaustion, and --max-requests
# recycles workers so a slow leak in the in-process cache cannot accumulate
# indefinitely. --worker-tmp-dir points at a tmpfs so the root filesystem can be
# mounted read-only.
CMD ["gunicorn", \
     "--bind", "0.0.0.0:5000", \
     "--workers", "4", \
     "--worker-tmp-dir", "/dev/shm", \
     "--timeout", "120", \
     "--graceful-timeout", "30", \
     "--keep-alive", "5", \
     "--max-requests", "1000", \
     "--max-requests-jitter", "100", \
     "--limit-request-line", "4094", \
     "--limit-request-fields", "100", \
     "--limit-request-field_size", "8190", \
     "--access-logfile", "-", \
     "--error-logfile", "-", \
     "run:app"]
