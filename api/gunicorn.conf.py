"""
api/gunicorn.conf.py
--------------------
Configuração do servidor Gunicorn para produção.

Uso (a partir da raiz do projeto):
  gunicorn --config api/gunicorn.conf.py "api.app:create_app()"

Ou via Docker:
  docker run --env-file api/.env api-contatus
"""

import multiprocessing
import os

# ── Bind ────────────────────────────────────────────────────────
bind = f"0.0.0.0:{os.environ.get('API_PORT', '5001')}"

# ── Workers ─────────────────────────────────────────────────────
# Fórmula recomendada pela Gunicorn: (2 × CPU) + 1
# Para big data com queries longas, não exceder (CPU × 2) para evitar
# contenção no pool de conexões MySQL.
_cpu = multiprocessing.cpu_count()
workers = int(os.environ.get("GUNICORN_WORKERS", min(_cpu * 2 + 1, 8)))
worker_class = "sync"       # sync é mais estável para I/O bloqueante (MySQL)
worker_connections = 1000
threads = 1                 # 1 thread por worker (sync mode)

# ── Timeouts ────────────────────────────────────────────────────
# Deve ser maior que REQUEST_TIMEOUT_ADMIN (180s) para não matar queries longas
_admin_timeout = int(os.environ.get("API_REQUEST_TIMEOUT_ADMIN", "180"))
timeout = _admin_timeout + 30   # margem de 30s além do timeout do admin
graceful_timeout = 30           # espera antes de forçar shutdown de worker
keepalive = 5                   # segundos para manter conexão HTTP viva

# ── Reciclagem de workers (evita memory leaks em longo prazo) ──
max_requests = 500
max_requests_jitter = 50        # aleatoriza para evitar restart simultâneo

# ── Logging ─────────────────────────────────────────────────────
accesslog = "-"    # stdout (coletado pelo Docker/systemd)
errorlog  = "-"    # stderr
loglevel  = os.environ.get("GUNICORN_LOG_LEVEL", "info")
access_log_format = (
    '%(h)s %(l)s %(u)s %(t)s "%(r)s" %(s)s %(b)s '
    '"%(f)s" "%(a)s" %(D)sµs'
)

# ── Processo ────────────────────────────────────────────────────
proc_name = "api_contatus"

# ── Limites de requisição (segurança) ───────────────────────────
limit_request_line        = 4094   # tamanho máximo da linha de request
limit_request_fields      = 100    # número máximo de headers
limit_request_field_size  = 8190   # tamanho máximo por header

# ── Preload (carrega app antes de forkar workers) ───────────────
# ATENÇÃO: APScheduler conflita com preload (scheduler duplicado por fork).
# Mantenha preload_app=False para esta aplicação.
preload_app = False
