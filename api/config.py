"""
api/config.py
-------------
Configurações centralizadas da API segura.

TODAS as credenciais sensíveis devem vir de variáveis de ambiente.
Nunca commitar valores reais em código-fonte.
"""

import os
import secrets
from pathlib import Path

# ── Diretórios ─────────────────────────────────────────────────
BASE_DIR = Path(__file__).parent
PROJECT_DIR = BASE_DIR.parent
LOGS_DIR = BASE_DIR / "logs"
LOGS_DIR.mkdir(parents=True, exist_ok=True)

# ── JWT ────────────────────────────────────────────────────────
# OBRIGATÓRIO: defina API_JWT_SECRET como variável de ambiente em produção
JWT_SECRET_KEY = os.environ.get("API_JWT_SECRET", secrets.token_hex(64))
JWT_ALGORITHM = "HS256"
JWT_ACCESS_TOKEN_EXPIRE_MINUTES = 30          # token de acesso: 30 min
JWT_REFRESH_TOKEN_EXPIRE_MINUTES = 60 * 24    # refresh: 24 horas

# ── API Keys ───────────────────────────────────────────────────
# Chaves pré-autorizadas (em produção: manter em banco ou vault)
# Formato: { "api_key": {"nome": "...", "role": "admin"|"user", "ativo": True} }
API_KEYS_FILE = BASE_DIR / "api_keys.json"

# ── Rate Limiting ──────────────────────────────────────────────
# Janela deslizante (sliding window) por IP e/ou API key
RATE_LIMIT_ENABLED = True
RATE_LIMIT_DEFAULT = {
    "requests_per_minute": 30,
    "requests_per_hour": 500,
    "requests_per_day": 5000,
}
RATE_LIMIT_BY_ROLE = {
    "admin": {
        "requests_per_minute": 120,
        "requests_per_hour": 3000,
        "requests_per_day": 50000,
    },
    "user": {
        "requests_per_minute": 30,
        "requests_per_hour": 500,
        "requests_per_day": 5000,
    },
    "readonly": {
        "requests_per_minute": 10,
        "requests_per_hour": 100,
        "requests_per_day": 1000,
    },
}

# ── Brute Force Protection ────────────────────────────────────
MAX_LOGIN_ATTEMPTS = 5               # tentativas antes de bloquear
LOGIN_LOCKOUT_MINUTES = 15           # tempo de bloqueio
FAILED_ATTEMPTS_WINDOW_MINUTES = 30  # janela para contar tentativas

# ── IP Filtering ───────────────────────────────────────────────
IP_WHITELIST_ENABLED = False  # True para ativar whitelist (modo restritivo)
IP_WHITELIST = [
    # "192.168.1.0/24",
    # "10.0.0.0/8",
    "127.0.0.1",
    "::1",
]
IP_BLACKLIST = [
    # IPs bloqueados manualmente
]

# ── CORS ───────────────────────────────────────────────────────
CORS_ORIGINS = os.environ.get("API_CORS_ORIGINS", "http://localhost:5000").split(",")
CORS_METHODS = ["GET", "POST"]
CORS_HEADERS = ["Content-Type", "Authorization", "X-API-Key", "X-Request-ID"]
CORS_MAX_AGE = 3600

# ── Segurança Geral ───────────────────────────────────────────
ENFORCE_HTTPS = os.environ.get("API_ENFORCE_HTTPS", "false").lower() == "true"
MAX_CONTENT_LENGTH = 1 * 1024 * 1024   # 1 MB máximo por request
REQUEST_TIMEOUT = 30                    # segundos

# Quantidade máxima de registros retornados por consulta
MAX_REGISTROS_POR_CONSULTA = 10000
MAX_REGISTROS_PADRAO = 1000

# ── Auditoria ─────────────────────────────────────────────────
AUDIT_LOG_FILE = LOGS_DIR / "audit.log"
SECURITY_LOG_FILE = LOGS_DIR / "security.log"

# ── Banco de Dados ────────────────────────────────────────────
# Importa as configs do projeto pai
import sys
sys.path.insert(0, str(PROJECT_DIR))
from config_db import DB_CONFIG as _DB_CONFIG
DB_CONFIG = _DB_CONFIG.copy()

# Pool de conexões (evita excesso de conexões abertas)
DB_POOL_SIZE = 5
DB_POOL_NAME = "api_pool"

# Timeout de query na API (segundos) — segurança extra contra full scans
API_QUERY_TIMEOUT = int(os.environ.get("API_QUERY_TIMEOUT", "120"))

# ── Criptografia de dados sensíveis nos logs ──────────────────
MASK_CPF = True           # mascara CPF nos logs (***.***.***-XX)
MASK_EMAIL = True         # mascara email nos logs (a***@dom***)
MASK_TELEFONE = True      # mascara telefone nos logs ((**) *****-XXXX)

# ── Modo de execução ──────────────────────────────────────────
DEBUG = os.environ.get("API_DEBUG", "false").lower() == "true"
HOST = os.environ.get("API_HOST", "0.0.0.0")
PORT = int(os.environ.get("API_PORT", "5001"))
