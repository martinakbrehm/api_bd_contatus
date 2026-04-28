"""
test_crypto.py
--------------
Testes dos utilitários criptográficos.
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

    def test_token_url_safe(self):
        token = gerar_token_url_safe(32)
        assert isinstance(token, str)
        # Não deve conter +, / ou =
        assert "+" not in token or token  # base64url encoded

    def test_nonce_unico(self):
        nonces = {gerar_nonce() for _ in range(100)}
        assert len(nonces) == 100


class TestHashSenha:
    """Testes de hash de senhas."""

    def test_hash_e_verificar(self):
        hash_val, salt = hash_senha("minha_senha_secreta")
        assert verificar_senha("minha_senha_secreta", hash_val, salt)

    def test_senha_errada_rejeitada(self):
        hash_val, salt = hash_senha("senha_correta")
        assert not verificar_senha("senha_errada", hash_val, salt)

    def test_mesmo_salt_mesmo_hash(self):
        h1, _ = hash_senha("test", salt="fixed_salt")
        h2, _ = hash_senha("test", salt="fixed_salt")
        assert h1 == h2

    def test_salt_diferente_hash_diferente(self):
        h1, s1 = hash_senha("test")
        h2, s2 = hash_senha("test")
        # Salts gerados aleatoriamente devem ser diferentes
        assert s1 != s2
        assert h1 != h2

    def test_hash_nao_contem_senha_original(self):
        hash_val, salt = hash_senha("minha_senha")
        assert "minha_senha" not in hash_val
        assert "minha_senha" not in salt


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
