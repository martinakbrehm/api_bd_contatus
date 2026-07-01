"""
api/utils/crypto.py
-------------------
Utilitários criptográficos para a API.

Padrão de hash de senhas: argon2id (OWASP recomendação #1).
  - Memory-hard: resistente a ataques por GPU/ASIC
  - Hash auto-descritivo: inclui algoritmo, parâmetros e salt na string
  - Formato: $argon2id$v=19$m=65536,t=3,p=2$<salt_b64>$<hash_b64>

Migração transparente: hashes legados (PBKDF2 formato hash$salt)
são aceitos no login e re-hasheados automaticamente para argon2id.
"""

import hashlib
import hmac
import secrets
import time
from typing import Optional

from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerificationError, VerifyMismatchError

# Parâmetros argon2id (OWASP Interactive login profile)
# m=65536 (64 MB), t=3 iterações, p=2 threads
_ph = PasswordHasher(
    time_cost=3,
    memory_cost=65536,
    parallelism=2,
    hash_len=32,
    salt_len=16,
)


def hash_senha(senha: str) -> str:
    """
    Gera hash argon2id da senha.
    Retorna string auto-descritiva: $argon2id$v=19$m=65536,t=3,p=2$...
    """
    return _ph.hash(senha)


def verificar_senha(senha: str, hash_armazenado: str) -> bool:
    """
    Verifica senha contra hash argon2id.
    Retorna True se correta, False caso contrário.
    """
    try:
        return _ph.verify(hash_armazenado, senha)
    except (VerifyMismatchError, VerificationError, InvalidHashError):
        return False


def precisa_rehash(hash_armazenado: str) -> bool:
    """True se o hash foi gerado com parâmetros desatualizados."""
    return _ph.check_needs_rehash(hash_armazenado)


# ── Legado: PBKDF2 (mantido apenas para migração transparente) ───────────────

def _hash_senha_pbkdf2(senha: str, salt: str) -> str:
    """Recalcula hash PBKDF2 legado. Usado só na verificação de migração."""
    dk = hashlib.pbkdf2_hmac(
        "sha256",
        senha.encode("utf-8"),
        salt.encode("utf-8"),
        iterations=100_000,
        dklen=32,
    )
    return dk.hex()


def verificar_senha_legado(senha: str, hash_armazenado: str) -> bool:
    """
    Verifica senhas no formato legado PBKDF2 (hash_hex$salt_hex).
    Retorna True se a senha bate com o hash legacy.
    """
    try:
        hash_hex, salt_hex = hash_armazenado.split("$", 1)
    except ValueError:
        return False
    calculado = _hash_senha_pbkdf2(senha, salt_hex)
    return hmac.compare_digest(calculado, hash_hex)


def is_hash_argon2(hash_armazenado: str) -> bool:
    """Detecta se o hash está no formato argon2 (novo padrão)."""
    return hash_armazenado.startswith("$argon2")


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
