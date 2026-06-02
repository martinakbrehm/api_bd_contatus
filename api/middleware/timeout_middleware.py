"""
api/middleware/timeout_middleware.py
-------------------------------------
Decorador de timeout para rotas de consulta.

Limita o tempo total de processamento de uma requisição Flask.
Se o handler não concluir no prazo, retorna HTTP 408 (Request Timeout)
ao cliente enquanto a thread de background encerra naturalmente via
DB_READ_TIMEOUT e MAX_EXECUTION_TIME configurados no banco.

Uso
---
    # Timeout automático por role (configurado em config.py):
    @with_timeout
    def minha_rota():
        ...

    # Timeout explícito em segundos:
    @with_timeout(timeout=60)
    def minha_rota():
        ...

Hierarquia de timeouts
----------------------
  1. Timeout explícito no decorador           (se fornecido)
  2. REQUEST_TIMEOUT_BY_ROLE[role]            (se role conhecido)
  3. REQUEST_TIMEOUT                          (fallback)
  4. DB_READ_TIMEOUT / MAX_EXECUTION_TIME     (camada de banco — último recurso)

Notas
-----
  - Compatível com Windows (não usa signal.alarm).
  - Usa copy_current_request_context para preservar contexto Flask
    (g, request, session) na thread de execução.
"""

import concurrent.futures
import functools
import logging

from flask import copy_current_request_context, g, jsonify

from api.config import REQUEST_TIMEOUT, REQUEST_TIMEOUT_BY_ROLE

logger = logging.getLogger(__name__)


def with_timeout(f=None, *, timeout: int | None = None):
    """
    Decorador que aplica timeout ao handler de rota Flask.

    Pode ser usado sem parênteses (@with_timeout) ou com timeout
    explícito (@with_timeout(timeout=60)).

    Quando o tempo é excedido, retorna JSON:
      {"ok": false, "erro": "...", "codigo": "REQUEST_TIMEOUT"}
    com status HTTP 408.
    """
    def decorator(func):
        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            # Determinar timeout: explícito > por role > padrão
            if timeout is not None:
                _timeout = timeout
            else:
                role = getattr(g, "auth_user", {}).get("role", "")
                _timeout = REQUEST_TIMEOUT_BY_ROLE.get(role, REQUEST_TIMEOUT)

            ctx_func = copy_current_request_context(func)

            with concurrent.futures.ThreadPoolExecutor(max_workers=1) as executor:
                future = executor.submit(ctx_func, *args, **kwargs)
                try:
                    return future.result(timeout=_timeout)
                except concurrent.futures.TimeoutError:
                    logger.warning(
                        "Request timeout (%ds) excedido em '%s'",
                        _timeout,
                        func.__name__,
                    )
                    return jsonify({
                        "ok": False,
                        "erro": (
                            f"A requisição excedeu o tempo limite de {_timeout}s. "
                            "Tente filtros mais restritivos ou uma quantidade menor de registros."
                        ),
                        "codigo": "REQUEST_TIMEOUT",
                    }), 408

        return wrapper

    # Suporte a @with_timeout sem parênteses
    if f is not None:
        return decorator(f)
    return decorator
