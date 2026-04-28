"""
api/app.py
----------
Flask Application Factory — cria e configura a aplicação da API segura.

Registra todos os blueprints, middlewares e configurações de segurança.
"""

import logging
import os
import time

from flask import Flask, g, jsonify, request

from api.config import DEBUG, MAX_CONTENT_LENGTH


def create_app() -> Flask:
    """
    Cria e configura a aplicação Flask da API.
    
    Ordem de inicialização (importante para segurança):
      1. Configurações base do Flask
      2. Middleware de IP filter (bloqueia IPs antes de qualquer processamento)
      3. Middleware de request validator (valida payload, detecta ataques)
      4. Middleware de rate limiting (protege contra DoS)
      5. Middleware de security headers (headers em toda resposta)
      6. Middleware de CORS (Cross-Origin)
      7. Blueprints de rotas
      8. Error handlers globais
      9. Request/Response logging
    """
    app = Flask(__name__)

    # ── Configurações Flask ──────────────────────────────────
    app.config["MAX_CONTENT_LENGTH"] = MAX_CONTENT_LENGTH
    app.config["JSON_SORT_KEYS"] = False
    app.config["JSONIFY_PRETTYPRINT_REGULAR"] = DEBUG

    # Secret key para sessions (não usamos session na API, mas é boa prática)
    app.secret_key = os.environ.get("API_FLASK_SECRET", os.urandom(32))

    # ── Logger ───────────────────────────────────────────────
    if not app.debug:
        app.logger.setLevel(logging.INFO)

    # ── 1. IP Filter ─────────────────────────────────────────
    from api.middleware.ip_filter import ip_filter_middleware
    ip_filter_middleware(app)

    # ── 2. Request Validator ─────────────────────────────────
    from api.middleware.request_validator import request_validator_middleware
    request_validator_middleware(app)

    # ── 3. Rate Limiting ─────────────────────────────────────
    from api.middleware.rate_limiter import rate_limit_middleware
    rate_limit_middleware(app)

    # ── 4. Security Headers ──────────────────────────────────
    from api.middleware.security_headers import cors_middleware, security_headers_middleware
    security_headers_middleware(app)
    cors_middleware(app)

    # ── 5. Blueprints ────────────────────────────────────────
    from api.routes.auth_routes import auth_bp
    from api.routes.consulta import consulta_bp
    from api.routes.health import health_bp
    from api.routes.admin import admin_bp

    app.register_blueprint(auth_bp)
    app.register_blueprint(consulta_bp)
    app.register_blueprint(health_bp)
    app.register_blueprint(admin_bp)

    # ── 6. Request/Response Audit Logging ────────────────────
    @app.after_request
    def _audit_log(response):
        """Loga toda requisição para auditoria."""
        from api.utils.audit_logger import log_request

        auth = getattr(g, "auth_user", None)
        request_id = getattr(g, "request_id", "")
        start = getattr(g, "request_start_time", None)
        elapsed_ms = round((time.time() - start) * 1000, 1) if start else None

        log_request(
            method=request.method,
            path=request.path,
            status_code=response.status_code,
            ip=request.remote_addr or "unknown",
            user=auth.get("subject") if auth else None,
            role=auth.get("role") if auth else None,
            auth_method=auth.get("auth_method") if auth else None,
            response_time_ms=elapsed_ms,
            request_id=request_id,
        )

        return response

    # ── 7. Error Handlers ────────────────────────────────────
    @app.errorhandler(400)
    def bad_request(e):
        return jsonify({"erro": "Requisição inválida.", "codigo": 400}), 400

    @app.errorhandler(404)
    def not_found(e):
        return jsonify({"erro": "Endpoint não encontrado.", "codigo": 404}), 404

    @app.errorhandler(405)
    def method_not_allowed(e):
        return jsonify({"erro": "Método HTTP não permitido.", "codigo": 405}), 405

    @app.errorhandler(413)
    def payload_too_large(e):
        return jsonify({"erro": "Payload excede o tamanho máximo.", "codigo": 413}), 413

    @app.errorhandler(415)
    def unsupported_media(e):
        return jsonify({"erro": "Content-Type não suportado.", "codigo": 415}), 415

    @app.errorhandler(429)
    def too_many_requests(e):
        return jsonify({"erro": "Limite de requisições excedido.", "codigo": 429}), 429

    @app.errorhandler(500)
    def internal_error(e):
        from api.utils.audit_logger import log_security_event
        log_security_event(
            "INTERNAL_ERROR",
            severity="ERROR",
            error=str(e),
            path=request.path,
        )
        return jsonify({"erro": "Erro interno do servidor.", "codigo": 500}), 500

    # ── 8. Rota raiz ─────────────────────────────────────────
    @app.route("/")
    def index():
        return jsonify({
            "api": "Lista PF - API Segura",
            "versao": "1.0.0",
            "documentacao": "/api/v1/health",
            "endpoints": {
                "auth": "/api/v1/auth/login",
                "consulta": "/api/v1/consulta",
                "contagem": "/api/v1/consulta/contagem",
                "preview": "/api/v1/consulta/preview",
                "health": "/api/v1/health",
            },
        }), 200

    app.logger.info("API Segura inicializada com sucesso.")
    return app
