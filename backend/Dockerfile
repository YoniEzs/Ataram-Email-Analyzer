# Ataram Email Analyzer - Backend Dockerfile

FROM python:3.11-slim

WORKDIR /app

# Install system dependencies (minimal set)
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    g++ \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements first for layer-cache efficiency
COPY requirements.txt .

RUN pip install --no-cache-dir -r requirements.txt

COPY . .

# Non-root user — never run as root in production
RUN groupadd -r ataram && useradd -r -g ataram ataram \
    && mkdir -p logs \
    && chown -R ataram:ataram /app

USER ataram

ENV FLASK_APP=run.py
ENV FLASK_ENV=production
ENV PYTHONUNBUFFERED=1
ENV PYTHONDONTWRITEBYTECODE=1

EXPOSE 5000

HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD python -c "import requests; requests.get('http://localhost:5000/health', timeout=5).raise_for_status()"

# sync workers (no gevent — not in deps and not needed for I/O-bound analysis tasks at this scale)
CMD ["gunicorn", "--bind", "0.0.0.0:5000", "--workers", "4", "--timeout", "120", \
     "--access-logfile", "-", "--error-logfile", "-", "run:app"]
