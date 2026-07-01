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
from api.models.schemas import ValidationError, validar_login, validar_login_usuario
from api.utils.audit_logger import log_request, log_security_event
from api.utils.crypto import (
    hash_senha,
    is_hash_argon2,
    precisa_rehash,
    verificar_senha,
    verificar_senha_legado,
)

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


@auth_bp.route("/login_usuario", methods=["POST"])
def login_usuario():
    """
    Autenticação via email + senha (tabela usuarios_app) → retorna access + refresh tokens.

    Body (JSON):
      { "email": "teste@contatus.com", "senha": "teste" }

    Resposta (200):
      {
        "access_token": "eyJ...",
        "refresh_token": "eyJ...",
        "token_type": "Bearer",
        "expires_in": 1800,
        "role": "admin"
      }
    """
    client_ip = _get_client_ip()

    try:
        data = request.get_json(silent=True) or {}
        dados = validar_login_usuario(data)
    except ValidationError as e:
        return jsonify({"erro": "Dados inválidos.", "detalhes": e.erros}), 400

    usuario = _buscar_usuario_por_email(dados["email"])

    # Resposta genérica para não revelar se o email existe
    _MSG_CREDENCIAIS = "Credenciais inválidas."

    if usuario is None:
        log_security_event("LOGIN_USUARIO_FAILED", ip=client_ip, reason="email não encontrado")
        return jsonify({"erro": _MSG_CREDENCIAIS}), 401

    if not usuario.get("ativo"):
        log_security_event("LOGIN_USUARIO_FAILED", ip=client_ip, reason="usuário inativo")
        return jsonify({"erro": _MSG_CREDENCIAIS}), 401

    expira_em = usuario.get("expira_em")
    if expira_em:
        from datetime import datetime, timezone
        try:
            if isinstance(expira_em, str):
                from datetime import datetime as _dt
                exp = _dt.fromisoformat(expira_em)
            else:
                exp = expira_em  # já é datetime (vindo do mysql-connector)
            if exp.tzinfo is None:
                exp = exp.replace(tzinfo=timezone.utc)
            if datetime.now(timezone.utc) > exp:
                log_security_event("LOGIN_USUARIO_FAILED", ip=client_ip, reason="conta expirada")
                return jsonify({"erro": _MSG_CREDENCIAIS}), 401
        except (ValueError, TypeError):
            pass

    senha_armazenada = usuario.get("senha_hash", "")
    senha_ok = False
    rehash_necessario = False

    if is_hash_argon2(senha_armazenada):
        senha_ok = verificar_senha(dados["senha"], senha_armazenada)
        if senha_ok and precisa_rehash(senha_armazenada):
            rehash_necessario = True
    else:
        # Hash legado PBKDF2 (hash_hex$salt_hex) — migração transparente
        senha_ok = verificar_senha_legado(dados["senha"], senha_armazenada)
        if senha_ok:
            rehash_necessario = True

    if not senha_ok:
        log_security_event("LOGIN_USUARIO_FAILED", ip=client_ip, reason="senha incorreta")
        return jsonify({"erro": _MSG_CREDENCIAIS}), 401

    if rehash_necessario:
        _atualizar_senha_hash(usuario["id"], hash_senha(dados["senha"]))

    subject = usuario["email"]
    role = usuario.get("role", "user")

    access_token = criar_access_token(
        subject=subject,
        role=role,
        ip_address=client_ip,
        extra_claims={"nome": usuario.get("nome", "")},
    )
    refresh_token = criar_refresh_token(subject=subject, role=role)

    _atualizar_ultimo_acesso(usuario["id"])

    log_security_event(
        "LOGIN_USUARIO_SUCCESS",
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
        "nome": usuario.get("nome", ""),
    }), 200


def _buscar_usuario_por_email(email: str):
    """Busca um usuário ativo na tabela usuarios_app pelo email."""
    try:
        import mysql.connector
        from api.config_db import DB_CONFIG
        conn = mysql.connector.connect(**DB_CONFIG)
        try:
            cur = conn.cursor(dictionary=True)
            cur.execute(
                "SELECT id, nome, email, senha_hash, role, ativo, expira_em "
                "FROM usuarios_app WHERE email = %s LIMIT 1",
                (email,),
            )
            return cur.fetchone()
        finally:
            conn.close()
    except Exception:
        return None


def _atualizar_senha_hash(usuario_id: int, novo_hash: str) -> None:
    """Substitui o hash da senha por um novo (migração ou rehash por parâmetros desatualizados)."""
    try:
        import mysql.connector
        from api.config_db import DB_CONFIG_ADMIN
        conn = mysql.connector.connect(**DB_CONFIG_ADMIN)
        try:
            cur = conn.cursor()
            cur.execute(
                "UPDATE usuarios_app SET senha_hash = %s WHERE id = %s",
                (novo_hash, usuario_id),
            )
            conn.commit()
        finally:
            conn.close()
    except Exception:
        pass


def _atualizar_ultimo_acesso(usuario_id: int) -> None:
    """Atualiza o campo ultimo_acesso na tabela usuarios_app."""
    try:
        import mysql.connector
        from api.config_db import DB_CONFIG
        conn = mysql.connector.connect(**DB_CONFIG)
        try:
            cur = conn.cursor()
            cur.execute(
                "UPDATE usuarios_app SET ultimo_acesso = NOW() WHERE id = %s",
                (usuario_id,),
            )
            conn.commit()
        finally:
            conn.close()
    except Exception:
        pass


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
