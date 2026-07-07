"""
test_crypto.py
--------------
Testes dos utilitários criptográficos.

Padrão atual de senha: argon2id (auto-descritivo — não usa salt externo).
"""

import pytest

from api.utils.crypto import (
    gerar_nonce,
    gerar_token_seguro,
    gerar_token_url_safe,
    hash_ip,
    hash_senha,
    hmac_sign,
    hmac_verify,
    verificar_senha,
)


class TestTokens:
    """Testes de geração de tokens."""

    def test_token_seguro_tamanho(self):
        token = gerar_token_seguro(32)
        assert len(token) == 64  # 32 bytes = 64 hex chars

    def test_token_seguro_unico(self):
        tokens = {gerar_token_seguro() for _ in range(100)}
        assert len(tokens) == 100, "Tokens devem ser únicos"

    def test_token_url_safe_e_string(self):
        token = gerar_token_url_safe(32)
        assert isinstance(token, str)
        assert len(token) > 0

    def test_nonce_unico(self):
        nonces = {gerar_nonce() for _ in range(100)}
        assert len(nonces) == 100


class TestHashSenha:
    """
    Testes de hash de senhas com argon2id.

    A API atual retorna uma string auto-descritiva (sem salt separado):
      hash_senha(pwd)  → str no formato $argon2id$...
      verificar_senha(pwd, hash) → bool
    """

    def test_hash_retorna_string_argon2id(self):
        h = hash_senha("minha_senha_secreta")
        assert isinstance(h, str)
        assert h.startswith("$argon2id$")

    def test_verificar_senha_correta(self):
        h = hash_senha("minha_senha_secreta")
        assert verificar_senha("minha_senha_secreta", h)

    def test_senha_errada_rejeitada(self):
        h = hash_senha("senha_correta")
        assert not verificar_senha("senha_errada", h)

    def test_mesmo_pwd_gera_hashes_diferentes(self):
        """argon2id usa salt aleatório embutido — mesmo pwd gera hashes distintos."""
        h1 = hash_senha("test")
        h2 = hash_senha("test")
        assert h1 != h2

    def test_hash_nao_contem_senha_original(self):
        h = hash_senha("minha_senha")
        assert "minha_senha" not in h


class TestHMAC:
    """Testes de HMAC para assinatura de requests."""

    def test_sign_e_verify(self):
        payload = '{"campo": "valor"}'
        secret = "chave_secreta_123"
        signature = hmac_sign(payload, secret)
        assert hmac_verify(payload, signature, secret)

    def test_payload_alterado_falha(self):
        secret = "chave_secreta_123"
        signature = hmac_sign("payload_original", secret)
        assert not hmac_verify("payload_alterado", signature, secret)

    def test_chave_errada_falha(self):
        payload = "dados"
        sig = hmac_sign(payload, "chave_1")
        assert not hmac_verify(payload, sig, "chave_2")

    def test_signature_deterministica(self):
        sig1 = hmac_sign("data", "key")
        sig2 = hmac_sign("data", "key")
        assert sig1 == sig2


class TestHashIP:
    """Testes de hash de IP."""

    def test_hash_ip_retorna_string(self):
        result = hash_ip("192.168.1.1")
        assert isinstance(result, str)
        assert len(result) == 16

    def test_hash_ip_mesmo_input_mesmo_output(self):
        h1 = hash_ip("10.0.0.1")
        h2 = hash_ip("10.0.0.1")
        assert h1 == h2

    def test_hash_ip_diferente_input_diferente_output(self):
        h1 = hash_ip("10.0.0.1")
        h2 = hash_ip("10.0.0.2")
        assert h1 != h2
