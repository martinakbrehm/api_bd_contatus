"""
api/utils/json_logger.py
------------------------
Formatter de log estruturado em JSON.

Cada linha de log vira um objeto JSON com campos padronizados,
compatível com CloudWatch, Datadog, Loki, etc.

Uso em app.py:
    from api.utils.json_logger import configurar_logging
    configurar_logging()
"""

import json
import logging
import os
import time


class JsonFormatter(logging.Formatter):
    """Formata cada registro de log como uma linha JSON."""

    CAMPOS_EXTRAS = (
        "request_id", "user", "role", "endpoint", "method",
        "ip", "filtros", "registros", "latencia_ms", "cache_hit",
        "action", "severity",
    )

    def format(self, record: logging.LogRecord) -> str:
        entry: dict = {
            "timestamp": self.formatTime(record, "%Y-%m-%dT%H:%M:%S"),
            "level":     record.levelname,
            "logger":    record.name,
            "message":   record.getMessage(),
        }

        # Campos extras definidos por quem chama logger.info(..., extra={...})
        for campo in self.CAMPOS_EXTRAS:
            val = getattr(record, campo, None)
            if val is not None:
                entry[campo] = val

        # Exceção, se houver
        if record.exc_info:
            entry["exception"] = self.formatException(record.exc_info)

        return json.dumps(entry, ensure_ascii=False, default=str)


def configurar_logging(level: str | None = None) -> None:
    """
    Substitui o handler raiz pelo JsonFormatter.
    Deve ser chamado uma única vez em app.py antes de criar a app Flask.
    """
    nivel = getattr(logging, (level or os.environ.get("LOG_LEVEL", "INFO")).upper(), logging.INFO)

    handler = logging.StreamHandler()
    handler.setFormatter(JsonFormatter())

    root = logging.getLogger()
    root.handlers.clear()
    root.addHandler(handler)
    root.setLevel(nivel)

    # Reduz verbosidade de libs externas
    for lib in ("werkzeug", "urllib3", "mysql.connector", "APScheduler"):
        logging.getLogger(lib).setLevel(logging.WARNING)
