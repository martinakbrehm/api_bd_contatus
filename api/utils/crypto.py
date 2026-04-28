"""
api/utils/crypto.py
-------------------
Utilitários criptográficos para a API.

Funcionalidades:
  - HMAC para assinatura de requests
  - Hash seguro de senhas (bcrypt-like com hashlib)
  - Geração de tokens seguros
  - Criptografia simétrica simplificada para dados em trânsito
"""

import hashlib
import hmac
import secrets
import time
from typing import Optional


def gerar_token_seguro(nbytes: int = 32) -> str:
    """Gera um token criptograficamente seguro (hex)."""
    return secrets.token_hex(nbytes)


def gerar_token_url_safe(nbytes: int = 32) -> str:
    """Gera um token URL-safe (base64)."""
    return secrets.token_urlsafe(nbytes)


def hash_senha(senha: str, salt: Optional[str] = None) -> tuple[str, str]:
    """
    Gera hash seguro de senha usando PBKDF2-HMAC-SHA256.
    
    Retorna (hash_hex, salt_hex).
    Em produção, use bcrypt ou argon2 (mais resistentes a GPU).
    """
    if salt is None:
        salt = secrets.token_hex(16)

    dk = hashlib.pbkdf2_hmac(
        "sha256",
        senha.encode("utf-8"),
        salt.encode("utf-8"),
        iterations=100_000,
        dklen=32,
    )
    return dk.hex(), salt


def verificar_senha(senha: str, hash_esperado: str, salt: str) -> bool:
    """Verifica uma senha contra seu hash."""
    hash_calculado, _ = hash_senha(senha, salt)
    # Comparação em tempo constante (anti-timing attack)
    return hmac.compare_digest(hash_calculado, hash_esperado)


def hmac_sign(payload: str, secret: str) -> str:
    """
    Gera assinatura HMAC-SHA256 de um payload.
    Usado para assinatura de requests (webhook-style).
    """
    return hmac.new(
        secret.encode("utf-8"),
        payload.encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()


def hmac_verify(payload: str, signature: str, secret: str) -> bool:
    """
    Verifica assinatura HMAC-SHA256.
    Usa comparação em tempo constante.
    """
    expected = hmac_sign(payload, secret)
    return hmac.compare_digest(expected, signature)


def gerar_nonce() -> str:
    """Gera um nonce único para prevenir replay attacks."""
    return f"{int(time.time() * 1000)}_{secrets.token_hex(8)}"


def hash_ip(ip: str) -> str:
    """Hash de IP para armazenamento anonimizado."""
    return hashlib.sha256(ip.encode("utf-8")).hexdigest()[:16]
