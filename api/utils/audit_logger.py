"""
api/utils/audit_logger.py
-------------------------
Sistema de auditoria e logging de segurança.

Dois tipos de log:
  1. Audit Log  — todas as requisições (quem, quando, o quê)
  2. Security Log — eventos de segurança (falhas, bloqueios, ataques)

Formato: JSON estruturado para fácil integração com SIEM
(Splunk, ELK, Datadog, etc.)
"""

import json
import logging
import os
import time
from datetime import datetime, timezone
from logging.handlers import RotatingFileHandler
from typing import Any, Optional

from api.config import AUDIT_LOG_FILE, LOGS_DIR, SECURITY_LOG_FILE


# ── Configurar loggers ────────────────────────────────────────

def _setup_logger(
    name: str,
    log_file: str,
    max_bytes: int = 10 * 1024 * 1024,   # 10 MB
    backup_count: int = 10,
) -> logging.Logger:
    """Configura logger com rotação por tamanho."""
    logger = logging.getLogger(name)
    if logger.handlers:
        return logger

    logger.setLevel(logging.INFO)

    handler = RotatingFileHandler(
        str(log_file),
        maxBytes=max_bytes,
        backupCount=backup_count,
        encoding="utf-8",
    )

    # Formato JSON para cada linha
    formatter = logging.Formatter("%(message)s")
    handler.setFormatter(formatter)
    logger.addHandler(handler)

    # Console handler para eventos críticos
    console = logging.StreamHandler()
    console.setLevel(logging.WARNING)
    console.setFormatter(logging.Formatter(
        "%(asctime)s | SECURITY | %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    ))
    logger.addHandler(console)

    return logger


_audit_logger = _setup_logger("api.audit", AUDIT_LOG_FILE)
_security_logger = _setup_logger("api.security", SECURITY_LOG_FILE)


def _json_entry(**kwargs) -> str:
    """Cria uma entrada JSON estruturada para log."""
    entry = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "epoch": time.time(),
    }
    entry.update(kwargs)
    return json.dumps(entry, ensure_ascii=False, default=str)


# ── API Pública ───────────────────────────────────────────────

def log_request(
    method: str,
    path: str,
    status_code: int,
    ip: str,
    user: Optional[str] = None,
    role: Optional[str] = None,
    auth_method: Optional[str] = None,
    response_time_ms: Optional[float] = None,
    request_id: Optional[str] = None,
    extra: Optional[dict] = None,
) -> None:
    """
    Registra uma requisição no audit log.
    Chamado automaticamente pelo middleware ou manualmente pela rota.
    """
    entry = _json_entry(
        event="REQUEST",
        method=method,
        path=path,
        status_code=status_code,
        ip=ip,
        user=user,
        role=role,
        auth_method=auth_method,
        response_time_ms=response_time_ms,
        request_id=request_id,
        **(extra or {}),
    )
    _audit_logger.info(entry)


def log_security_event(
    event_type: str,
    severity: str = "WARNING",
    **details: Any,
) -> None:
    """
    Registra um evento de segurança.

    Tipos comuns:
      - JWT_AUTH_FAILED
      - API_KEY_AUTH_FAILED
      - BRUTE_FORCE_BLOCKED
      - RATE_LIMIT_EXCEEDED
      - MALICIOUS_PAYLOAD_DETECTED
      - SUSPICIOUS_QUERY_PARAM
      - IP_BLACKLISTED
      - IP_NOT_WHITELISTED
      - UNAUTHORIZED_ACCESS
      - DATA_EXPORT (exportação de dados sensíveis)
    """
    entry = _json_entry(
        event="SECURITY",
        event_type=event_type,
        severity=severity,
        **details,
    )

    if severity == "CRITICAL":
        _security_logger.critical(entry)
    elif severity == "ERROR":
        _security_logger.error(entry)
    elif severity == "WARNING":
        _security_logger.warning(entry)
    else:
        _security_logger.info(entry)


def log_data_access(
    user: str,
    role: str,
    action: str,
    filtros: dict,
    registros_retornados: int,
    ip: str,
    request_id: Optional[str] = None,
) -> None:
    """
    Registra acesso a dados sensíveis (compliance LGPD).
    Deve ser chamado sempre que dados pessoais são retornados.
    """
    entry = _json_entry(
        event="DATA_ACCESS",
        user=user,
        role=role,
        action=action,
        filtros=filtros,
        registros_retornados=registros_retornados,
        ip=ip,
        request_id=request_id,
    )
    _audit_logger.info(entry)
    _security_logger.info(entry)
