"""
api/auth/decorators.py
----------------------
Decoradores de autenticação e autorização para as rotas da API.

Camadas de segurança:
  1. require_auth       — exige token JWT válido OU API Key válida
  2. require_role       — exige role específico (admin, user, readonly)
  3. require_api_key    — exige apenas API Key (sem JWT)
  4. require_jwt        — exige apenas JWT (sem API Key)
"""

import functools
import time
from typing import Optional

from flask import g, jsonify, request

from api.auth.api_keys import validar_api_key
from api.auth.jwt_handler import validar_token
from api.config import MAX_LOGIN_ATTEMPTS, LOGIN_LOCKOUT_MINUTES, FAILED_ATTEMPTS_WINDOW_MINUTES
from api.utils.audit_logger import log_security_event


# ── Tracking de tentativas falhas (brute force protection) ────
_failed_attempts: dict[str, list[float]] = {}


def _get_client_ip() -> str:
    """Obtém IP real do cliente (suporte a proxies)."""
    # X-Forwarded-For pode ser spoofado — em produção, confiar apenas
    # se estiver atrás de um proxy reverso configurado (nginx, ALB, etc.)
    forwarded = request.headers.get("X-Forwarded-For", "")
    if forwarded:
        # Pegar o primeiro IP (cliente original)
        return forwarded.split(",")[0].strip()
    return request.remote_addr or "unknown"


def _check_brute_force(identifier: str) -> Optional[dict]:
    """
    Verifica se o identificador está bloqueado por excesso de tentativas.
    Retorna dict com erro se bloqueado, None se OK.
    """
    now = time.time()
    window = FAILED_ATTEMPTS_WINDOW_MINUTES * 60

    if identifier in _failed_attempts:
        # Limpar tentativas fora da janela
        _failed_attempts[identifier] = [
            t for t in _failed_attempts[identifier]
            if now - t < window
        ]

        if len(_failed_attempts[identifier]) >= MAX_LOGIN_ATTEMPTS:
            # Verificar se o lockout já passou
            ultima = max(_failed_attempts[identifier])
            lockout_restante = LOGIN_LOCKOUT_MINUTES * 60 - (now - ultima)

            if lockout_restante > 0:
                log_security_event(
                    "BRUTE_FORCE_BLOCKED",
                    identifier=identifier,
                    attempts=len(_failed_attempts[identifier]),
                )
                return {
                    "erro": "Muitas tentativas falhas. Tente novamente mais tarde.",
                    "bloqueado_por_segundos": int(lockout_restante),
                }
            else:
                # Lockout expirou — limpar
                _failed_attempts[identifier] = []

    return None


def _register_failed_attempt(identifier: str) -> None:
    """Registra uma tentativa falha de autenticação."""
    if identifier not in _failed_attempts:
        _failed_attempts[identifier] = []
    _failed_attempts[identifier].append(time.time())


def _clear_failed_attempts(identifier: str) -> None:
    """Limpa tentativas falhas após autenticação bem-sucedida."""
    _failed_attempts.pop(identifier, None)


def _extract_bearer_token() -> Optional[str]:
    """Extrai o token Bearer do header Authorization."""
    auth_header = request.headers.get("Authorization", "")
    if auth_header.startswith("Bearer "):
        return auth_header[7:].strip()
    return None


def _extract_api_key() -> Optional[str]:
    """Extrai a API Key do header X-API-Key ou query param."""
    # Prioridade: header > query param
    key = request.headers.get("X-API-Key", "")
    if not key:
        key = request.args.get("api_key", "")
    return key.strip() if key else None


def require_auth(f):
    """
    Decorador: exige autenticação via JWT Bearer token OU API Key.
    
    Popula `g.auth_user` com:
      - subject: identificador do usuário
      - role: papel (admin, user, readonly)
      - auth_method: "jwt" ou "api_key"
    """
    @functools.wraps(f)
    def decorated(*args, **kwargs):
        client_ip = _get_client_ip()

        # Verificar brute force
        brute_check = _check_brute_force(client_ip)
        if brute_check:
            return jsonify(brute_check), 429

        # Tentar JWT primeiro
        token = _extract_bearer_token()
        if token:
            try:
                payload = validar_token(token, expected_type="access")
                g.auth_user = {
                    "subject": payload["sub"],
                    "role": payload["role"],
                    "auth_method": "jwt",
                    "token_jti": payload.get("jti"),
                }
                _clear_failed_attempts(client_ip)
                return f(*args, **kwargs)
            except ValueError as e:
                _register_failed_attempt(client_ip)
                log_security_event(
                    "JWT_AUTH_FAILED",
                    ip=client_ip,
                    reason=str(e),
                )
                return jsonify({"erro": str(e)}), 401

        # Tentar API Key
        api_key = _extract_api_key()
        if api_key:
            dados = validar_api_key(api_key, ip_origem=client_ip)
            if dados:
                g.auth_user = {
                    "subject": dados["key_id"],
                    "role": dados["role"],
                    "auth_method": "api_key",
                    "key_nome": dados.get("nome"),
                }
                _clear_failed_attempts(client_ip)
                return f(*args, **kwargs)
            else:
                _register_failed_attempt(client_ip)
                log_security_event(
                    "API_KEY_AUTH_FAILED",
                    ip=client_ip,
                    key_preview=api_key[:12] + "..." if len(api_key) > 12 else "***",
                )
                return jsonify({"erro": "API Key inválida ou expirada."}), 401

        # Nenhuma credencial fornecida
        return jsonify({
            "erro": "Autenticação necessária.",
            "metodos_aceitos": [
                "Header 'Authorization: Bearer <token>'",
                "Header 'X-API-Key: <chave>'",
            ],
        }), 401

    return decorated


def require_role(*roles):
    """
    Decorador: exige que o usuário autenticado tenha um dos roles especificados.
    Deve ser usado APÓS require_auth.

    Exemplo:
        @require_auth
        @require_role("admin", "user")
        def minha_rota():
            ...
    """
    def decorator(f):
        @functools.wraps(f)
        def decorated(*args, **kwargs):
            auth = getattr(g, "auth_user", None)
            if not auth:
                return jsonify({"erro": "Autenticação necessária."}), 401

            user_role = auth.get("role", "")
            if user_role not in roles:
                log_security_event(
                    "UNAUTHORIZED_ACCESS",
                    subject=auth.get("subject"),
                    role=user_role,
                    required_roles=list(roles),
                    endpoint=request.endpoint,
                )
                return jsonify({
                    "erro": "Permissão insuficiente.",
                    "seu_role": user_role,
                    "roles_necessarios": list(roles),
                }), 403

            return f(*args, **kwargs)
        return decorated
    return decorator


def require_api_key(f):
    """Decorador: exige exclusivamente API Key (sem fallback JWT)."""
    @functools.wraps(f)
    def decorated(*args, **kwargs):
        client_ip = _get_client_ip()

        brute_check = _check_brute_force(client_ip)
        if brute_check:
            return jsonify(brute_check), 429

        api_key = _extract_api_key()
        if not api_key:
            return jsonify({"erro": "Header 'X-API-Key' é obrigatório."}), 401

        dados = validar_api_key(api_key, ip_origem=client_ip)
        if not dados:
            _register_failed_attempt(client_ip)
            log_security_event("API_KEY_REJECTED", ip=client_ip)
            return jsonify({"erro": "API Key inválida ou expirada."}), 401

        g.auth_user = {
            "subject": dados["key_id"],
            "role": dados["role"],
            "auth_method": "api_key",
            "key_nome": dados.get("nome"),
        }
        _clear_failed_attempts(client_ip)
        return f(*args, **kwargs)
    return decorated
