"""
test_jwt_handler.py
-------------------
Testes do sistema JWT: criação, validação, expiração, revogação, replay.
"""

import time
from datetime import datetime, timedelta, timezone
from unittest.mock import patch

import jwt as pyjwt
import pytest


class TestCriarAccessToken:
    """Testes para criação de access tokens."""

    def test_cria_token_valido(self):
        from api.auth.jwt_handler import criar_access_token, validar_token

        token = criar_access_token(subject="test_user", role="user")
        assert token
        assert isinstance(token, str)

        payload = validar_token(token, expected_type="access")
        assert payload["sub"] == "test_user"
        assert payload["role"] == "user"
        assert payload["type"] == "access"

    def test_token_contem_jti_unico(self):
        from api.auth.jwt_handler import criar_access_token, validar_token

        t1 = criar_access_token(subject="u1", role="user")
        t2 = criar_access_token(subject="u1", role="user")

        p1 = validar_token(t1)
        p2 = validar_token(t2)

        assert p1["jti"] != p2["jti"], "JTIs devem ser únicos"

    def test_token_com_ip_binding(self):
        from api.auth.jwt_handler import criar_access_token, validar_token

        token = criar_access_token(subject="u1", role="admin", ip_address="192.168.1.1")
        payload = validar_token(token)
        assert "ip_hash" in payload
        assert isinstance(payload["ip_hash"], str)
        assert len(payload["ip_hash"]) == 16

    def test_extra_claims_incluidos(self):
        from api.auth.jwt_handler import criar_access_token, validar_token

        token = criar_access_token(
            subject="u1", role="user",
            extra_claims={"nome": "João", "custom_field": "valor"},
        )
        payload = validar_token(token)
        assert payload["nome"] == "João"
        assert payload["custom_field"] == "valor"

    def test_extra_claims_nao_sobreescrevem_seguranca(self):
        from api.auth.jwt_handler import criar_access_token, validar_token

        token = criar_access_token(
            subject="u1", role="user",
            extra_claims={"sub": "hacker", "role": "admin", "type": "refresh"},
        )
        payload = validar_token(token)
        # Claims de segurança NÃO devem ser sobrescritos
        assert payload["sub"] == "u1"
        assert payload["role"] == "user"
        assert payload["type"] == "access"

    def test_roles_validos(self):
        from api.auth.jwt_handler import criar_access_token, validar_token

        for role in ("admin", "user", "readonly"):
            token = criar_access_token(subject="u1", role=role)
            payload = validar_token(token)
            assert payload["role"] == role


class TestCriarRefreshToken:
    """Testes para criação de refresh tokens."""

    def test_cria_refresh_valido(self):
        from api.auth.jwt_handler import criar_refresh_token, validar_token

        token = criar_refresh_token(subject="u1", role="user")
        payload = validar_token(token, expected_type="refresh")
        assert payload["sub"] == "u1"
        assert payload["type"] == "refresh"

    def test_refresh_nao_valida_como_access(self):
        from api.auth.jwt_handler import criar_refresh_token, validar_token

        token = criar_refresh_token(subject="u1", role="user")
        with pytest.raises(ValueError, match="Tipo de token inválido"):
            validar_token(token, expected_type="access")


class TestValidarToken:
    """Testes de validação de tokens."""

    def test_token_expirado_rejeitado(self):
        from api.auth.jwt_handler import validar_token
        from api.config import JWT_ALGORITHM, JWT_SECRET_KEY

        payload = {
            "sub": "u1", "role": "user", "type": "access",
            "jti": "test123", "iat": datetime.now(timezone.utc),
            "exp": datetime.now(timezone.utc) - timedelta(hours=1),  # expirado
            "nbf": datetime.now(timezone.utc) - timedelta(hours=2),
        }
        token = pyjwt.encode(payload, JWT_SECRET_KEY, algorithm=JWT_ALGORITHM)

        with pytest.raises(ValueError, match="[Ee]xpirado"):
            validar_token(token)

    def test_token_com_assinatura_invalida(self):
        from api.auth.jwt_handler import validar_token

        payload = {
            "sub": "u1", "role": "user", "type": "access",
            "jti": "test123", "iat": datetime.now(timezone.utc),
            "exp": datetime.now(timezone.utc) + timedelta(hours=1),
            "nbf": datetime.now(timezone.utc),
        }
        token = pyjwt.encode(payload, "chave_errada_123", algorithm="HS256")

        with pytest.raises(ValueError, match="[Ii]nválido"):
            validar_token(token)

    def test_token_sem_campos_obrigatorios(self):
        from api.auth.jwt_handler import validar_token
        from api.config import JWT_ALGORITHM, JWT_SECRET_KEY

        payload = {
            "sub": "u1",
            # Faltando: role, type, jti
            "iat": datetime.now(timezone.utc),
            "exp": datetime.now(timezone.utc) + timedelta(hours=1),
        }
        token = pyjwt.encode(payload, JWT_SECRET_KEY, algorithm=JWT_ALGORITHM)

        with pytest.raises(ValueError):
            validar_token(token)

    def test_token_string_aleatoria_rejeitada(self):
        from api.auth.jwt_handler import validar_token

        with pytest.raises(ValueError):
            validar_token("nao.um.token.valido")

    def test_token_vazio_rejeitado(self):
        from api.auth.jwt_handler import validar_token

        with pytest.raises(ValueError):
            validar_token("")

    def test_tipo_errado_rejeitado(self):
        from api.auth.jwt_handler import criar_access_token, validar_token

        token = criar_access_token(subject="u1", role="user")
        with pytest.raises(ValueError, match="Tipo de token inválido"):
            validar_token(token, expected_type="refresh")


class TestRevogacao:
    """Testes de revogação (blacklist) de tokens."""

    def test_revogar_token_impede_uso(self):
        from api.auth.jwt_handler import criar_access_token, revogar_token, validar_token

        token = criar_access_token(subject="u1", role="user")
        # Antes de revogar funciona
        validar_token(token)

        revogar_token(token)

        with pytest.raises(ValueError, match="[Rr]evogado"):
            validar_token(token)

    def test_revogar_token_invalido_nao_quebra(self):
        from api.auth.jwt_handler import revogar_token

        # Não deve lançar exceção
        revogar_token("token.invalido.completamente")
        revogar_token("")

    def test_refresh_revogado_nao_funciona(self):
        from api.auth.jwt_handler import criar_refresh_token, revogar_token, validar_token

        token = criar_refresh_token(subject="u1", role="user")
        revogar_token(token)

        with pytest.raises(ValueError, match="[Rr]evogado"):
            validar_token(token, expected_type="refresh")
