# ================================================================
# Dockerfile — API Segura (bd_contatus)
#
# Build a partir da raiz do projeto:
#   docker build -f api/Dockerfile -t api-contatus .
#
# Run:
#   docker run -p 5001:5001 --env-file api/.env api-contatus
# ================================================================

FROM python:3.12-slim

# ── Dependências de sistema ────────────────────────────────────
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    default-libmysqlclient-dev \
    pkg-config \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# ── Dependências Python (layer de cache separado) ─────────────
COPY api/requirements.txt ./api/requirements.txt
RUN pip install --no-cache-dir -r api/requirements.txt

# ── Código da aplicação ───────────────────────────────────────
COPY api/ ./api/

# ── Usuário sem privilégios (nunca root em produção) ──────────
RUN useradd -m -u 1000 apiuser \
    && mkdir -p api/logs api/output/temp \
    && chown -R apiuser:apiuser /app

USER apiuser

# ── Porta exposta ──────────────────────────────────────────────
EXPOSE 5001

# ── Health check ──────────────────────────────────────────────
HEALTHCHECK --interval=30s --timeout=10s --start-period=10s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:5001/api/v1/health')" || exit 1

# ── Entrypoint ────────────────────────────────────────────────
# Gunicorn com config em api/gunicorn.conf.py
CMD ["gunicorn", "--config", "api/gunicorn.conf.py", "api.app:create_app()"]
