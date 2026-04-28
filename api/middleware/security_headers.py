"""
api/middleware/security_headers.py
----------------------------------
Adiciona headers de segurança HTTP em todas as respostas.

Equivalente ao helmet.js do Node — protege contra:
  - XSS (Cross-Site Scripting)
  - Clickjacking
  - MIME sniffing
  - Referrer leakage
  - Insecure connections
"""

from flask import Flask, request

from api.config import CORS_HEADERS, CORS_MAX_AGE, CORS_METHODS, CORS_ORIGINS, ENFORCE_HTTPS


def security_headers_middleware(app: Flask) -> None:
    """Registra middleware que adiciona headers de segurança em toda resposta."""

    @app.after_request
    def _add_security_headers(response):
        # ── Anti-XSS ─────────────────────────────────────────
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-XSS-Protection"] = "1; mode=block"

        # ── Anti-Clickjacking ────────────────────────────────
        response.headers["X-Frame-Options"] = "DENY"

        # ── Referrer Policy ──────────────────────────────────
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"

        # ── Content Security Policy ──────────────────────────
        response.headers["Content-Security-Policy"] = (
            "default-src 'none'; "
            "frame-ancestors 'none'; "
            "base-uri 'none'; "
            "form-action 'none'"
        )

        # ── Permissions Policy ───────────────────────────────
        response.headers["Permissions-Policy"] = (
            "camera=(), microphone=(), geolocation=(), "
            "interest-cohort=()"
        )

        # ── Cache Control (API não deve ser cacheada) ────────
        response.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, max-age=0"
        response.headers["Pragma"] = "no-cache"
        response.headers["Expires"] = "0"

        # ── HSTS (apenas se HTTPS enforçado) ─────────────────
        if ENFORCE_HTTPS:
            response.headers["Strict-Transport-Security"] = (
                "max-age=31536000; includeSubDomains; preload"
            )

        # ── Remover headers que revelam tecnologia ───────────
        response.headers.pop("Server", None)
        response.headers.pop("X-Powered-By", None)

        return response


def cors_middleware(app: Flask) -> None:
    """
    Implementação manual de CORS (sem dependência externa).
    Mais segura que flask-cors pois permite controle granular.
    """

    @app.before_request
    def _handle_preflight():
        """Responde a preflight OPTIONS requests."""
        if request.method == "OPTIONS":
            from flask import make_response
            resp = make_response()
            origin = request.headers.get("Origin", "")

            if _origin_allowed(origin):
                resp.headers["Access-Control-Allow-Origin"] = origin
                resp.headers["Access-Control-Allow-Methods"] = ", ".join(CORS_METHODS)
                resp.headers["Access-Control-Allow-Headers"] = ", ".join(CORS_HEADERS)
                resp.headers["Access-Control-Max-Age"] = str(CORS_MAX_AGE)
                resp.headers["Access-Control-Allow-Credentials"] = "true"

            resp.status_code = 204
            return resp

    @app.after_request
    def _add_cors_headers(response):
        origin = request.headers.get("Origin", "")
        if _origin_allowed(origin):
            response.headers["Access-Control-Allow-Origin"] = origin
            response.headers["Access-Control-Allow-Credentials"] = "true"
            response.headers["Vary"] = "Origin"
        return response


def _origin_allowed(origin: str) -> bool:
    """Verifica se a origin está na lista de permitidos."""
    if not origin:
        return False
    if "*" in CORS_ORIGINS:
        return True
    return origin in CORS_ORIGINS
