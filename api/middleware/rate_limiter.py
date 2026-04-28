"""
api/middleware/rate_limiter.py
-----------------------------
Rate limiting com janela deslizante (sliding window).

Estratégias implementadas:
  - Por IP: limita requisições por endereço IP
  - Por API Key: limita por chave de autenticação
  - Por Role: limites diferenciados por nível de acesso
  - Global: limite absoluto para proteção do servidor

Armazenamento em memória (em produção: usar Redis com MULTI/EXEC).

Headers retornados:
  X-RateLimit-Limit      : limite total da janela
  X-RateLimit-Remaining  : requisições restantes
  X-RateLimit-Reset      : timestamp Unix de reset da janela
  Retry-After            : segundos até poder tentar novamente (quando bloqueado)
"""

import time
import threading
from collections import defaultdict
from typing import Optional

from flask import Flask, g, jsonify, request

from api.config import (
    RATE_LIMIT_BY_ROLE,
    RATE_LIMIT_DEFAULT,
    RATE_LIMIT_ENABLED,
)


class SlidingWindowCounter:
    """
    Contador de janela deslizante thread-safe.
    Divide a janela em sub-buckets para precisão.
    """

    def __init__(self, window_seconds: int, max_requests: int, buckets: int = 10):
        self.window = window_seconds
        self.max_requests = max_requests
        self.bucket_size = window_seconds / buckets
        self.buckets_count = buckets
        self._lock = threading.Lock()
        # {identifier: {bucket_key: count}}
        self._counters: dict[str, dict[int, int]] = defaultdict(lambda: defaultdict(int))

    def _current_bucket(self) -> int:
        return int(time.time() / self.bucket_size)

    def _prune(self, identifier: str) -> None:
        """Remove buckets expirados."""
        current = self._current_bucket()
        cutoff = current - self.buckets_count
        buckets = self._counters[identifier]
        expired = [k for k in buckets if k <= cutoff]
        for k in expired:
            del buckets[k]

    def hit(self, identifier: str) -> tuple[bool, int, int, float]:
        """
        Registra uma requisição.

        Retorna: (permitido, total_atual, limite, segundos_para_reset)
        """
        with self._lock:
            self._prune(identifier)
            current = self._current_bucket()

            # Contar total na janela
            total = sum(self._counters[identifier].values())

            if total >= self.max_requests:
                # Bloqueado — calcular tempo para reset
                oldest = min(self._counters[identifier].keys()) if self._counters[identifier] else current
                reset_at = (oldest + self.buckets_count + 1) * self.bucket_size
                retry_after = max(0, reset_at - time.time())
                return False, total, self.max_requests, retry_after

            # Permitido — registrar
            self._counters[identifier][current] += 1
            total += 1
            reset_at = (current + self.buckets_count + 1) * self.bucket_size
            remaining_time = max(0, reset_at - time.time())
            return True, total, self.max_requests, remaining_time

    def get_remaining(self, identifier: str) -> int:
        """Retorna quantas requisições restam na janela atual."""
        with self._lock:
            self._prune(identifier)
            total = sum(self._counters[identifier].values())
            return max(0, self.max_requests - total)

    def cleanup_all(self) -> int:
        """Remove todos os contadores expirados. Retorna quantidade removida."""
        with self._lock:
            cleaned = 0
            empty_ids = []
            for identifier in list(self._counters.keys()):
                self._prune(identifier)
                if not self._counters[identifier]:
                    empty_ids.append(identifier)
            for identifier in empty_ids:
                del self._counters[identifier]
                cleaned += 1
            return cleaned


class RateLimiter:
    """
    Rate Limiter principal com múltiplas janelas (minuto, hora, dia).
    """

    def __init__(self):
        self._limiters: dict[str, dict[str, SlidingWindowCounter]] = {}
        self._cleanup_interval = 300  # limpar a cada 5 min
        self._last_cleanup = time.time()

    def _get_or_create_limiter(
        self, role: str
    ) -> dict[str, SlidingWindowCounter]:
        """Obtém ou cria limiters para um role específico."""
        if role not in self._limiters:
            limits = RATE_LIMIT_BY_ROLE.get(role, RATE_LIMIT_DEFAULT)
            self._limiters[role] = {
                "minute": SlidingWindowCounter(60, limits["requests_per_minute"]),
                "hour": SlidingWindowCounter(3600, limits["requests_per_hour"]),
                "day": SlidingWindowCounter(86400, limits["requests_per_day"]),
            }
        return self._limiters[role]

    def _maybe_cleanup(self) -> None:
        now = time.time()
        if now - self._last_cleanup > self._cleanup_interval:
            for role_limiters in self._limiters.values():
                for limiter in role_limiters.values():
                    limiter.cleanup_all()
            self._last_cleanup = now

    def check(self, identifier: str, role: str = "user") -> dict:
        """
        Verifica rate limit para o identificador com o role dado.

        Retorna dict com:
          - allowed: bool
          - limit: int (mais restritivo)
          - remaining: int
          - retry_after: float (segundos, 0 se permitido)
          - window: str (qual janela bloqueou)
        """
        self._maybe_cleanup()
        limiters = self._get_or_create_limiter(role)

        # Verificar cada janela (da mais restritiva para a menos)
        for window_name in ("minute", "hour", "day"):
            limiter = limiters[window_name]
            allowed, total, limit, retry_after = limiter.hit(identifier)

            if not allowed:
                return {
                    "allowed": False,
                    "limit": limit,
                    "remaining": 0,
                    "retry_after": retry_after,
                    "window": window_name,
                    "total": total,
                }

        # Todas as janelas OK — retornar info da janela por minuto
        minute_remaining = limiters["minute"].get_remaining(identifier)
        limits = RATE_LIMIT_BY_ROLE.get(role, RATE_LIMIT_DEFAULT)

        return {
            "allowed": True,
            "limit": limits["requests_per_minute"],
            "remaining": minute_remaining,
            "retry_after": 0,
            "window": "minute",
        }


# ── Instância global ──────────────────────────────────────────
_rate_limiter = RateLimiter()


def rate_limit_middleware(app: Flask) -> None:
    """
    Registra o middleware de rate limiting no Flask app.
    Executa antes de cada request.
    """

    @app.before_request
    def _check_rate_limit():
        if not RATE_LIMIT_ENABLED:
            return None

        # Identificador: API Key > IP
        auth = getattr(g, "auth_user", None)
        if auth:
            identifier = auth.get("subject", request.remote_addr)
            role = auth.get("role", "user")
        else:
            identifier = request.remote_addr or "unknown"
            role = "user"

        result = _rate_limiter.check(identifier, role)

        # Sempre adicionar headers de rate limit
        g.rate_limit_info = result

        if not result["allowed"]:
            from api.utils.audit_logger import log_security_event
            log_security_event(
                "RATE_LIMIT_EXCEEDED",
                identifier=identifier,
                role=role,
                window=result["window"],
                limit=result["limit"],
            )

            response = jsonify({
                "erro": "Limite de requisições excedido.",
                "limite": result["limit"],
                "janela": result["window"],
                "tente_apos_segundos": int(result["retry_after"]) + 1,
            })
            response.status_code = 429
            response.headers["Retry-After"] = str(int(result["retry_after"]) + 1)
            response.headers["X-RateLimit-Limit"] = str(result["limit"])
            response.headers["X-RateLimit-Remaining"] = "0"
            return response

    @app.after_request
    def _add_rate_limit_headers(response):
        info = getattr(g, "rate_limit_info", None)
        if info:
            response.headers["X-RateLimit-Limit"] = str(info.get("limit", ""))
            response.headers["X-RateLimit-Remaining"] = str(info.get("remaining", ""))
        return response
