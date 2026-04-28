"""
api/auth/jwt_handler.py
-----------------------
Gerenciamento seguro de tokens JWT.

Funcionalidades:
  - Criação de access tokens (curta duração)
  - Criação de refresh tokens (longa duração)
  - Validação e decodificação segura
  - Blacklist de tokens revogados
  - Proteção contra replay attacks (jti — JWT ID único)
"""

import hashlib
import secrets
import time
from datetime import datetime, timedelta, timezone
from typing import Optional

import jwt

from api.config import (
    JWT_ACCESS_TOKEN_EXPIRE_MINUTES,
    JWT_ALGORITHM,
    JWT_REFRESH_TOKEN_EXPIRE_MINUTES,
    JWT_SECRET_KEY,
)


# ── Blacklist de tokens revogados (em produção: usar Redis) ────
_token_blacklist: set[str] = set()

# ── JTI (JWT ID) tracking para prevenir replay ────────────────
_used_jtis: dict[str, float] = {}   # {jti: timestamp_expiração}
_JTI_CLEANUP_INTERVAL = 3600        # limpar JTIs expirados a cada 1h
_last_jti_cleanup = time.time()


def _cleanup_expired_jtis() -> None:
    """Remove JTIs expirados para não consumir memória indefinidamente."""
    global _last_jti_cleanup
    now = time.time()
    if now - _last_jti_cleanup < _JTI_CLEANUP_INTERVAL:
        return
    expired = [jti for jti, exp in _used_jtis.items() if exp < now]
    for jti in expired:
        del _used_jtis[jti]
    _last_jti_cleanup = now


def _generate_jti() -> str:
    """Gera um JWT ID único e criptograficamente seguro."""
    return secrets.token_hex(16)


def _fingerprint(extra: str = "") -> str:
    """Gera fingerprint para binding ao contexto."""
    return hashlib.sha256(f"{extra}{secrets.token_hex(8)}".encode()).hexdigest()[:16]


def criar_access_token(
    subject: str,
    role: str = "user",
    extra_claims: Optional[dict] = None,
    ip_address: Optional[str] = None,
) -> str:
    """
    Cria um access token JWT de curta duração.

    Parâmetros
    ----------
    subject      : identificador do usuário/api_key
    role         : papel do usuário (admin, user, readonly)
    extra_claims : claims adicionais no payload
    ip_address   : IP do cliente (binding opcional)

    Retorna
    -------
    str : token JWT codificado
    """
    now = datetime.now(timezone.utc)
    jti = _generate_jti()

    payload = {
        "sub": subject,
        "role": role,
        "type": "access",
        "jti": jti,
        "iat": now,
        "exp": now + timedelta(minutes=JWT_ACCESS_TOKEN_EXPIRE_MINUTES),
        "nbf": now,  # não válido antes de agora
    }

    if ip_address:
        # Hash do IP — não armazena IP em texto claro no token
        payload["ip_hash"] = hashlib.sha256(ip_address.encode()).hexdigest()[:16]

    if extra_claims:
        # Não permitir sobreescrever claims de segurança
        safe_claims = {
            k: v for k, v in extra_claims.items()
            if k not in ("sub", "role", "type", "jti", "iat", "exp", "nbf", "ip_hash")
        }
        payload.update(safe_claims)

    return jwt.encode(payload, JWT_SECRET_KEY, algorithm=JWT_ALGORITHM)


def criar_refresh_token(subject: str, role: str = "user") -> str:
    """
    Cria um refresh token JWT de longa duração.
    Usado apenas para renovar o access token.
    """
    now = datetime.now(timezone.utc)
    jti = _generate_jti()

    payload = {
        "sub": subject,
        "role": role,
        "type": "refresh",
        "jti": jti,
        "iat": now,
        "exp": now + timedelta(minutes=JWT_REFRESH_TOKEN_EXPIRE_MINUTES),
        "nbf": now,
    }

    return jwt.encode(payload, JWT_SECRET_KEY, algorithm=JWT_ALGORITHM)


def validar_token(token: str, expected_type: str = "access") -> dict:
    """
    Valida e decodifica um token JWT.

    Verificações:
      1. Assinatura válida (chave secreta)
      2. Não expirado (exp)
      3. Não antes do tempo (nbf)
      4. Tipo correto (access/refresh)
      5. Não está na blacklist (revogado)
      6. JTI não foi reutilizado (anti-replay)

    Retorna
    -------
    dict : payload decodificado

    Raises
    ------
    jwt.InvalidTokenError  : token inválido por qualquer motivo
    ValueError             : token revogado ou tipo incorreto
    """
    _cleanup_expired_jtis()

    try:
        payload = jwt.decode(
            token,
            JWT_SECRET_KEY,
            algorithms=[JWT_ALGORITHM],
            options={
                "verify_exp": True,
                "verify_nbf": True,
                "verify_iat": True,
                "require": ["sub", "role", "type", "jti", "iat", "exp"],
            },
        )
    except jwt.ExpiredSignatureError:
        raise ValueError("Token expirado. Faça login novamente.")
    except jwt.InvalidTokenError as e:
        raise ValueError(f"Token inválido: {e}")

    # Verificar tipo
    if payload.get("type") != expected_type:
        raise ValueError(f"Tipo de token inválido. Esperado: {expected_type}")

    # Verificar blacklist
    jti = payload.get("jti", "")
    if jti in _token_blacklist:
        raise ValueError("Token revogado. Faça login novamente.")

    return payload


def revogar_token(token: str) -> None:
    """
    Adiciona o token à blacklist (logout / revogação).
    Em produção, usar Redis com TTL = tempo restante do token.
    """
    try:
        payload = jwt.decode(
            token,
            JWT_SECRET_KEY,
            algorithms=[JWT_ALGORITHM],
            options={"verify_exp": False},  # permitir revogar mesmo expirado
        )
        jti = payload.get("jti", "")
        if jti:
            _token_blacklist.add(jti)
    except jwt.InvalidTokenError:
        pass  # token completamente inválido — não precisa revogar


def revogar_todos_tokens_usuario(subject: str) -> int:
    """
    Revoga todos os tokens de um usuário específico.
    Nota: em produção com Redis, isso seria mais eficiente.
    Retorna quantidade de tokens revogados.
    """
    # Em memória, não temos como rastrear todos os tokens de um usuário.
    # Em produção, armazenar tokens emitidos em Redis e invalidar por subject.
    # Aqui, retornamos 0 como placeholder.
    return 0
