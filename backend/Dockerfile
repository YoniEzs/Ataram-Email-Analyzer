# syntax=docker/dockerfile:1

# Pinned by digest; Dependabot keeps the digest current.
FROM python:3.11-slim@sha256:e031123e3d85762b141ad1cbc56452ba69c6e722ebf2f042cc0dc86c47c0d8b3 AS builder

ENV PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /build

RUN apt-get update && apt-get install -y --no-install-recommends \
        build-essential \
    && rm -rf /var/lib/apt/lists/*

COPY requirements-prod.txt .
RUN python -m pip wheel --wheel-dir /wheels \
        setuptools==83.0.0 wheel==0.47.0 \
    && python -m pip wheel --wheel-dir /wheels -r requirements-prod.txt


FROM python:3.11-slim@sha256:e031123e3d85762b141ad1cbc56452ba69c6e722ebf2f042cc0dc86c47c0d8b3 AS runtime

ENV FLASK_APP=run.py \
    FLASK_ENV=production \
    PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /app

# Patch fixable OS CVEs that the pinned base digest predates. The Trivy gate
# (severity HIGH/CRITICAL, ignore-unfixed) fails the build on any fixable
# base-image vulnerability, and a security tool should ship the patched
# packages. Dependabot advances the digest; this keeps the interim image clean.
RUN apt-get update && apt-get upgrade -y \
    && rm -rf /var/lib/apt/lists/*

COPY --from=builder /wheels /wheels
COPY requirements-prod.txt .
RUN python -m pip install --no-index --find-links=/wheels --upgrade \
        setuptools==83.0.0 wheel==0.47.0 \
    && python -m pip install --no-index --find-links=/wheels -r requirements-prod.txt \
    && rm -rf /wheels \
    && groupadd --system ataram \
    && useradd --system --gid ataram --home-dir /nonexistent ataram

COPY --chown=ataram:ataram . .

USER ataram
EXPOSE 5000

HEALTHCHECK --interval=30s --timeout=10s --start-period=10s --retries=3 \
    CMD python -c "import requests; requests.get('http://localhost:5000/health', timeout=5).raise_for_status()"

CMD ["gunicorn", "--bind", "0.0.0.0:5000", "--workers", "2", "--threads", "2", \
     "--timeout", "120", "--access-logfile", "-", "--error-logfile", "-", "run:app"]
