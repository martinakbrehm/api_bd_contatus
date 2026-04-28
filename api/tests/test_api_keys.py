"""
test_api_keys.py
----------------
Testes do sistema de API Keys: geração, validação, expiração, desativação, IP.
"""

import json
import time
from datetime import datetime, timedelta, timezone
from unittest.mock import patch

import pytest


class TestGerarApiKey:
    """Testes de geração de API Keys."""

    def test_gera_key_com_prefixo_correto(self):
        from api.auth.api_keys import gerar_api_key

        api_key, key_id = gerar_api_key(nome="Teste", role="user")
        assert api_key.startswith("lspf_")
        assert key_id.startswith("lspf_")

    def test_gera_key_com_comprimento_adequado(self):
        from api.auth.api_keys import gerar_api_key

        api_key, key_id = gerar_api_key(nome="Teste", role="user")
        # lspf_ (5) + 64 hex chars = 69 chars
        assert len(api_key) == 69
        assert len(key_id) == 12

    def test_keys_sao_unicas(self):
        from api.auth.api_keys import gerar_api_key

        keys = set()
        for i in range(10):
            api_key, _ = gerar_api_key(nome=f"Key {i}", role="user")
            keys.add(api_key)
        assert len(keys) == 10, "Todas as keys devem ser únicas"

    def test_role_admin(self):
        from api.auth.api_keys import gerar_api_key, validar_api_key

        api_key, _ = gerar_api_key(nome="Admin", role="admin")
        dados = validar_api_key(api_key)
        assert dados["role"] == "admin"

    def test_role_readonly(self):
        from api.auth.api_keys import gerar_api_key, validar_api_key

        api_key, _ = gerar_api_key(nome="RO", role="readonly")
        dados = validar_api_key(api_key)
        assert dados["role"] == "readonly"

    def test_role_invalido_rejeitado(self):
        from api.auth.api_keys import gerar_api_key

        with pytest.raises(ValueError, match="Role inválido"):
            gerar_api_key(nome="Bad", role="superadmin")

    def test_key_com_expiracao(self):
        from api.auth.api_keys import gerar_api_key, validar_api_key

        api_key, _ = gerar_api_key(nome="Exp", role="user", expira_em_dias=30)
        dados = validar_api_key(api_key)
        assert dados is not None
        assert dados["expira_em"] is not None

    def test_key_com_ip_restrito(self):
        from api.auth.api_keys import gerar_api_key, validar_api_key

        api_key, _ = gerar_api_key(
            nome="IP", role="user",
            ip_restrito=["192.168.1.0/24"],
        )
        # IP dentro do range: OK
        dados = validar_api_key(api_key, ip_origem="192.168.1.50")
        assert dados is not None

        # IP fora do range: rejeitado
        dados2 = validar_api_key(api_key, ip_origem="10.0.0.1")
        assert dados2 is None


class TestValidarApiKey:
    """Testes de validação de API Keys."""

    def test_key_valida_retorna_dados(self):
        from api.auth.api_keys import gerar_api_key, validar_api_key

        api_key, key_id = gerar_api_key(nome="Valid", role="user")
        dados = validar_api_key(api_key)
        assert dados is not None
        assert dados["key_id"] == key_id
        assert dados["nome"] == "Valid"
        assert dados["ativo"] is True

    def test_key_inexistente_retorna_none(self):
        from api.auth.api_keys import validar_api_key

        assert validar_api_key("lspf_chave_que_nao_existe_12345678901234567890abcdef12345678") is None

    def test_key_sem_prefixo_retorna_none(self):
        from api.auth.api_keys import validar_api_key

        assert validar_api_key("sem_prefixo_correto") is None

    def test_key_vazia_retorna_none(self):
        from api.auth.api_keys import validar_api_key

        assert validar_api_key("") is None
        assert validar_api_key(None) is None

    def test_tracking_de_uso(self):
        from api.auth.api_keys import gerar_api_key, validar_api_key

        api_key, _ = gerar_api_key(nome="Track", role="user")

        for i in range(3):
            validar_api_key(api_key)

        dados = validar_api_key(api_key)
        assert dados["total_requests"] >= 3
        assert dados["ultimo_uso"] is not None


class TestDesativarApiKey:
    """Testes de desativação de API Keys."""

    def test_desativar_impede_uso(self):
        from api.auth.api_keys import desativar_api_key, gerar_api_key, validar_api_key

        api_key, key_id = gerar_api_key(nome="Deactivate", role="user")
        assert validar_api_key(api_key) is not None

        resultado = desativar_api_key(key_id)
        assert resultado is True

        assert validar_api_key(api_key) is None

    def test_desativar_key_inexistente(self):
        from api.auth.api_keys import desativar_api_key

        assert desativar_api_key("lspf_naoexis") is False


class TestListarKeys:
    """Testes da listagem de API Keys."""

    def test_listar_sem_keys(self):
        from api.auth.api_keys import listar_keys

        keys = listar_keys()
        assert isinstance(keys, list)

    def test_listar_nao_expoe_hash(self):
        from api.auth.api_keys import gerar_api_key, listar_keys

        gerar_api_key(nome="NoHash", role="user")
        keys = listar_keys()
        for k in keys:
            assert "key_hash" not in k, "Hash não deve aparecer na listagem"

    def test_listar_mostra_dados_basicos(self):
        from api.auth.api_keys import gerar_api_key, listar_keys

        gerar_api_key(nome="List Test", role="admin")
        keys = listar_keys()
        assert len(keys) >= 1
        k = keys[-1]
        assert "nome" in k
        assert "role" in k
        assert "ativo" in k


class TestExpiracaoApiKey:
    """Testes de expiração de API Keys."""

    def test_key_expirada_retorna_none(self):
        from api.auth.api_keys import gerar_api_key, validar_api_key, _carregar_keys, _salvar_keys

        api_key, key_id = gerar_api_key(nome="Expired", role="user", expira_em_dias=1)

        # Forçar expiração no passado
        keys = _carregar_keys()
        past = (datetime.now(timezone.utc) - timedelta(days=2)).isoformat()
        keys[key_id]["expira_em"] = past
        _salvar_keys(keys)

        assert validar_api_key(api_key) is None

    def test_key_sem_expiracao_sempre_valida(self):
        from api.auth.api_keys import gerar_api_key, validar_api_key

        api_key, _ = gerar_api_key(nome="NoExpiry", role="user", expira_em_dias=None)
        assert validar_api_key(api_key) is not None


class TestIpRestriction:
    """Testes de restrição por IP."""

    def test_ip_exato_permitido(self):
        from api.auth.api_keys import gerar_api_key, validar_api_key

        api_key, _ = gerar_api_key(
            nome="IPExact", role="user",
            ip_restrito=["10.0.0.5"],
        )
        assert validar_api_key(api_key, ip_origem="10.0.0.5") is not None
        assert validar_api_key(api_key, ip_origem="10.0.0.6") is None

    def test_cidr_permitido(self):
        from api.auth.api_keys import gerar_api_key, validar_api_key

        api_key, _ = gerar_api_key(
            nome="CIDR", role="user",
            ip_restrito=["10.0.0.0/8"],
        )
        assert validar_api_key(api_key, ip_origem="10.255.255.255") is not None
        assert validar_api_key(api_key, ip_origem="192.168.1.1") is None

    def test_sem_restricao_aceita_qualquer_ip(self):
        from api.auth.api_keys import gerar_api_key, validar_api_key

        api_key, _ = gerar_api_key(nome="NoIP", role="user", ip_restrito=[])
        assert validar_api_key(api_key, ip_origem="1.2.3.4") is not None
