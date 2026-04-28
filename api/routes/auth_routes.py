"""
api/routes/auth_routes.py
-------------------------
Rotas de autenticação:
  POST /api/v1/auth/login     → obter tokens via API Key
  POST /api/v1/auth/refresh   → renovar access token
  POST /api/v1/auth/logout    → revogar token
  GET  /api/v1/auth/me        → informações do usuário autenticado
"""

import time

from flask import Blueprint, g, jsonify, request

from api.auth.api_keys import validar_api_key
from api.auth.decorators import _get_client_ip, require_auth
from api.auth.jwt_handler import criar_access_token, criar_refresh_token, revogar_token, validar_token
from api.models.schemas import ValidationError, validar_login
from api.utils.audit_logger import log_request, log_security_event

auth_bp = Blueprint("auth", __name__, url_prefix="/api/v1/auth")


@auth_bp.route("/login", methods=["POST"])
def login():
    """
    Autenticação via API Key → retorna access + refresh tokens.

    Body (JSON):
      { "api_key": "lspf_..." }

    Resposta (200):
      {
        "access_token": "eyJ...",
        "refresh_token": "eyJ...",
        "token_type": "Bearer",
        "expires_in": 1800,
        "role": "user"
      }
    """
    client_ip = _get_client_ip()

    try:
        data = request.get_json(silent=True) or {}
        dados_validados = validar_login(data)
    except ValidationError as e:
        return jsonify({"erro": "Dados inválidos.", "detalhes": e.erros}), 400

    api_key = dados_validados["api_key"]
    key_data = validar_api_key(api_key, ip_origem=client_ip)

    if not key_data:
        log_security_event(
            "LOGIN_FAILED",
            ip=client_ip,
            reason="API Key inválida",
        )
        # Resposta genérica (não revelar se a key existe ou não)
        return jsonify({"erro": "Credenciais inválidas."}), 401

    # Gerar tokens
    subject = key_data["key_id"]
    role = key_data["role"]

    access_token = criar_access_token(
        subject=subject,
        role=role,
        ip_address=client_ip,
        extra_claims={"nome": key_data.get("nome", "")},
    )
    refresh_token = criar_refresh_token(subject=subject, role=role)

    log_security_event(
        "LOGIN_SUCCESS",
        severity="INFO",
        ip=client_ip,
        subject=subject,
        role=role,
    )

    from api.config import JWT_ACCESS_TOKEN_EXPIRE_MINUTES
    return jsonify({
        "access_token": access_token,
        "refresh_token": refresh_token,
        "token_type": "Bearer",
        "expires_in": JWT_ACCESS_TOKEN_EXPIRE_MINUTES * 60,
        "role": role,
    }), 200


@auth_bp.route("/refresh", methods=["POST"])
def refresh():
    """
    Renova o access token usando o refresh token.

    Body (JSON):
      { "refresh_token": "eyJ..." }

    Resposta (200):
      { "access_token": "eyJ...", "token_type": "Bearer", "expires_in": 1800 }
    """
    client_ip = _get_client_ip()
    data = request.get_json(silent=True) or {}
    refresh_token = data.get("refresh_token", "")

    if not refresh_token:
        return jsonify({"erro": "'refresh_token' é obrigatório."}), 400

    try:
        payload = validar_token(refresh_token, expected_type="refresh")
    except ValueError as e:
        log_security_event(
            "REFRESH_FAILED",
            ip=client_ip,
            reason=str(e),
        )
        return jsonify({"erro": str(e)}), 401

    # Revogar o refresh token antigo (single use)
    revogar_token(refresh_token)

    # Emitir novos tokens
    access_token = criar_access_token(
        subject=payload["sub"],
        role=payload["role"],
        ip_address=client_ip,
    )
    new_refresh = criar_refresh_token(
        subject=payload["sub"],
        role=payload["role"],
    )

    from api.config import JWT_ACCESS_TOKEN_EXPIRE_MINUTES
    return jsonify({
        "access_token": access_token,
        "refresh_token": new_refresh,
        "token_type": "Bearer",
        "expires_in": JWT_ACCESS_TOKEN_EXPIRE_MINUTES * 60,
    }), 200


@auth_bp.route("/logout", methods=["POST"])
@require_auth
def logout():
    """
    Revoga o token atual (logout).
    Requer header Authorization: Bearer <token>.
    """
    auth_header = request.headers.get("Authorization", "")
    if auth_header.startswith("Bearer "):
        token = auth_header[7:].strip()
        revogar_token(token)

    log_security_event(
        "LOGOUT",
        severity="INFO",
        subject=g.auth_user.get("subject"),
        ip=_get_client_ip(),
    )

    return jsonify({"mensagem": "Logout realizado com sucesso."}), 200


@auth_bp.route("/me", methods=["GET"])
@require_auth
def me():
    """Retorna informações do usuário autenticado."""
    auth = g.auth_user
    return jsonify({
        "subject": auth.get("subject"),
        "role": auth.get("role"),
        "auth_method": auth.get("auth_method"),
    }), 200
