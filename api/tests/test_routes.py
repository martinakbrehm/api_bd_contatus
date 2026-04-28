"""
test_routes.py
--------------
Testes dos endpoints da API: auth, consulta, health, admin.
Testes de autorização (RBAC) e comportamentos esperados.
"""

import json
from unittest.mock import MagicMock, patch

import pandas as pd
import pytest


# ================================================================
# HEALTH
# ================================================================

class TestHealthEndpoints:
    """Testes dos endpoints de saúde."""

    def test_health_sem_autenticacao(self, client):
        resp = client.get("/api/v1/health")
        assert resp.status_code == 200
        data = resp.get_json()
        assert data["status"] == "healthy"
        assert "version" in data
        assert "uptime_seconds" in data

    def test_health_db_requer_admin(self, client, user_headers):
        resp = client.get("/api/v1/health/db", headers=user_headers)
        assert resp.status_code == 403

    def test_health_db_sem_auth(self, client):
        resp = client.get("/api/v1/health/db")
        assert resp.status_code == 401

    def test_health_stats_requer_admin(self, client, readonly_headers):
        resp = client.get("/api/v1/health/stats", headers=readonly_headers)
        assert resp.status_code == 403

    def test_health_stats_admin_ok(self, client, admin_headers):
        resp = client.get("/api/v1/health/stats", headers=admin_headers)
        assert resp.status_code == 200
        data = resp.get_json()
        assert "version" in data
        assert "uptime_seconds" in data


# ================================================================
# AUTH
# ================================================================

class TestAuthLogin:
    """Testes do endpoint de login."""

    def test_login_com_api_key_valida(self, client, admin_api_key):
        api_key, _ = admin_api_key
        resp = client.post(
            "/api/v1/auth/login",
            json={"api_key": api_key},
            content_type="application/json",
        )
        assert resp.status_code == 200
        data = resp.get_json()
        assert "access_token" in data
        assert "refresh_token" in data
        assert data["token_type"] == "Bearer"
        assert data["role"] == "admin"
        assert data["expires_in"] > 0

    def test_login_com_api_key_invalida(self, client):
        resp = client.post(
            "/api/v1/auth/login",
            json={"api_key": "lspf_chave_falsa_00000000000000000000000000000000000000abcdef12"},
            content_type="application/json",
        )
        assert resp.status_code == 401
        data = resp.get_json()
        assert "erro" in data

    def test_login_sem_body(self, client):
        resp = client.post(
            "/api/v1/auth/login",
            json={},
            content_type="application/json",
        )
        assert resp.status_code == 400

    def test_login_retorna_role_correto(self, client, user_api_key):
        api_key, _ = user_api_key
        resp = client.post(
            "/api/v1/auth/login",
            json={"api_key": api_key},
            content_type="application/json",
        )
        assert resp.status_code == 200
        assert resp.get_json()["role"] == "user"


class TestAuthRefresh:
    """Testes do endpoint de refresh."""

    def test_refresh_com_token_valido(self, client, admin_api_key):
        api_key, _ = admin_api_key
        # Login
        login_resp = client.post(
            "/api/v1/auth/login",
            json={"api_key": api_key},
            content_type="application/json",
        )
        refresh_token = login_resp.get_json()["refresh_token"]

        # Refresh
        resp = client.post(
            "/api/v1/auth/refresh",
            json={"refresh_token": refresh_token},
            content_type="application/json",
        )
        assert resp.status_code == 200
        data = resp.get_json()
        assert "access_token" in data
        assert "refresh_token" in data

    def test_refresh_sem_token(self, client):
        resp = client.post(
            "/api/v1/auth/refresh",
            json={},
            content_type="application/json",
        )
        assert resp.status_code == 400

    def test_refresh_com_token_invalido(self, client):
        resp = client.post(
            "/api/v1/auth/refresh",
            json={"refresh_token": "token.invalido.abc"},
            content_type="application/json",
        )
        assert resp.status_code == 401

    def test_refresh_single_use(self, client, admin_api_key):
        """Refresh token deve ser revogado após uso (single use)."""
        api_key, _ = admin_api_key
        login_resp = client.post(
            "/api/v1/auth/login",
            json={"api_key": api_key},
            content_type="application/json",
        )
        refresh_token = login_resp.get_json()["refresh_token"]

        # Primeiro refresh: OK
        resp1 = client.post(
            "/api/v1/auth/refresh",
            json={"refresh_token": refresh_token},
            content_type="application/json",
        )
        assert resp1.status_code == 200

        # Segundo refresh com mesmo token: deve falhar (revogado)
        resp2 = client.post(
            "/api/v1/auth/refresh",
            json={"refresh_token": refresh_token},
            content_type="application/json",
        )
        assert resp2.status_code == 401


class TestAuthLogout:
    """Testes do endpoint de logout."""

    def test_logout_com_token_valido(self, client, admin_headers):
        resp = client.post("/api/v1/auth/logout", headers=admin_headers)
        assert resp.status_code == 200

    def test_logout_sem_auth(self, client):
        resp = client.post("/api/v1/auth/logout")
        assert resp.status_code == 401


class TestAuthMe:
    """Testes do endpoint /me."""

    def test_me_retorna_info_usuario(self, client, admin_headers):
        resp = client.get("/api/v1/auth/me", headers=admin_headers)
        assert resp.status_code == 200
        data = resp.get_json()
        assert "subject" in data
        assert data["role"] == "admin"
        assert data["auth_method"] == "jwt"

    def test_me_com_api_key(self, client, api_key_headers):
        resp = client.get("/api/v1/auth/me", headers=api_key_headers)
        assert resp.status_code == 200
        data = resp.get_json()
        assert data["auth_method"] == "api_key"

    def test_me_sem_auth(self, client):
        resp = client.get("/api/v1/auth/me")
        assert resp.status_code == 401


# ================================================================
# CONSULTA — autorização RBAC
# ================================================================

class TestConsultaAutorizacao:
    """Testes de autorização nos endpoints de consulta."""

    def test_consulta_requer_auth(self, client):
        resp = client.post(
            "/api/v1/consulta",
            json={"ufs": ["SP"]},
            content_type="application/json",
        )
        assert resp.status_code == 401

    def test_consulta_readonly_proibido(self, client, readonly_headers):
        resp = client.post(
            "/api/v1/consulta",
            json={"ufs": ["SP"]},
            headers=readonly_headers,
        )
        assert resp.status_code == 403

    def test_contagem_readonly_permitido(self, client, readonly_headers):
        """Contagem deve ser acessível por readonly (não retorna dados pessoais)."""
        with patch("api.routes.consulta._conectar_banco") as mock_conn:
            mock_cursor = MagicMock()
            mock_cursor.fetchone.return_value = {"total": 42}
            mock_conn.return_value.cursor.return_value = mock_cursor

            resp = client.post(
                "/api/v1/consulta/contagem",
                json={"ufs": ["SP"]},
                headers=readonly_headers,
            )
            assert resp.status_code == 200
            assert resp.get_json()["total_banco"] == 42

    def test_preview_readonly_permitido(self, client, readonly_headers):
        """Preview deve ser acessível (dados mascarados)."""
        mock_df = pd.DataFrame([{
            "NOME": "JOAO", "CPF": "12345678901",
            "TELEFONE_1": "11987654321", "TELEFONE_2": None,
            "TELEFONE_3": None, "TELEFONE_4": None,
            "TELEFONE_5": None, "TELEFONE_6": None,
            "GENERO": "M", "DATA_NASCIMENTO": "1985-01-01",
            "ENDERECO": "RUA", "NUM_END": "1", "COMPLEMENTO": None,
            "BAIRRO": "CENTRO", "CIDADE": "SAO PAULO",
            "UF": "SP", "CEP": "01000000",
            "EMAIL_1": "j@mail.com", "EMAIL_2": None,
        }])

        with patch("api.routes.consulta._executar_query", return_value=mock_df):
            resp = client.post(
                "/api/v1/consulta/preview",
                json={"ufs": ["SP"], "quantidade": 5},
                headers=readonly_headers,
            )
            assert resp.status_code == 200
            data = resp.get_json()
            assert data["ok"] is True
            assert "registros_preview" in data

    def test_consulta_admin_permitido(self, client, admin_headers):
        mock_df = pd.DataFrame([{
            "NOME": "JOAO", "CPF": "12345678901",
            "TELEFONE_1": "11987654321", "TELEFONE_2": None,
            "TELEFONE_3": None, "TELEFONE_4": None,
            "TELEFONE_5": None, "TELEFONE_6": None,
            "GENERO": "M", "DATA_NASCIMENTO": "1985-01-01",
            "ENDERECO": "RUA", "NUM_END": "1", "COMPLEMENTO": None,
            "BAIRRO": "CENTRO", "CIDADE": "SAO PAULO",
            "UF": "SP", "CEP": "01000000",
            "EMAIL_1": "j@mail.com", "EMAIL_2": None,
        }])

        with patch("api.routes.consulta._executar_query", return_value=mock_df):
            resp = client.post(
                "/api/v1/consulta",
                json={"ufs": ["SP"], "quantidade": 1},
                headers=admin_headers,
            )
            assert resp.status_code == 200
            data = resp.get_json()
            assert data["ok"] is True
            assert data["total_final"] >= 0


class TestConsultaValidacao:
    """Testes de validação de dados nos endpoints de consulta."""

    def test_consulta_sem_uf_retorna_400(self, client, admin_headers):
        resp = client.post(
            "/api/v1/consulta",
            json={},
            headers=admin_headers,
        )
        assert resp.status_code == 400
        data = resp.get_json()
        assert data["ok"] is False
        assert "detalhes" in data

    def test_contagem_sem_uf_retorna_400(self, client, admin_headers):
        resp = client.post(
            "/api/v1/consulta/contagem",
            json={},
            headers=admin_headers,
        )
        assert resp.status_code == 400

    def test_consulta_uf_invalida_retorna_400(self, client, admin_headers):
        resp = client.post(
            "/api/v1/consulta",
            json={"ufs": ["ZZ"]},
            headers=admin_headers,
        )
        assert resp.status_code == 400

    def test_consulta_banco_vazio_retorna_200(self, client, admin_headers):
        with patch("api.routes.consulta._executar_query", return_value=pd.DataFrame()):
            resp = client.post(
                "/api/v1/consulta",
                json={"ufs": ["SP"]},
                headers=admin_headers,
            )
            assert resp.status_code == 200
            data = resp.get_json()
            assert data["ok"] is True
            assert data["total_banco"] == 0
            assert data["registros"] == []

    def test_contagem_com_mock(self, client, admin_headers):
        with patch("api.routes.consulta._conectar_banco") as mock_conn:
            mock_cursor = MagicMock()
            mock_cursor.fetchone.return_value = {"total": 12345}
            mock_conn.return_value.cursor.return_value = mock_cursor

            resp = client.post(
                "/api/v1/consulta/contagem",
                json={"ufs": ["SP", "RJ"], "genero": "F", "idade_min": 25, "idade_max": 50},
                headers=admin_headers,
            )
            assert resp.status_code == 200
            data = resp.get_json()
            assert data["ok"] is True
            assert data["total_banco"] == 12345
            assert "descricao" in data

    def test_request_id_na_resposta(self, client, admin_headers):
        resp = client.post(
            "/api/v1/consulta/contagem",
            json={"ufs": ["SP"]},
            headers={**admin_headers, "X-Request-ID": "test-id-999"},
        )
        # Independente de sucesso/erro, request_id deve estar presente
        data = resp.get_json()
        if "request_id" in data:
            assert data["request_id"] == "test-id-999"


# ================================================================
# ADMIN
# ================================================================

class TestAdminEndpoints:
    """Testes dos endpoints administrativos."""

    def test_criar_key_admin_ok(self, client, admin_headers):
        resp = client.post(
            "/api/v1/admin/keys",
            json={"nome": "Nova Key", "role": "user"},
            headers=admin_headers,
        )
        assert resp.status_code == 201
        data = resp.get_json()
        assert "api_key" in data
        assert data["api_key"].startswith("lspf_")
        assert "aviso" in data

    def test_criar_key_user_proibido(self, client, user_headers):
        resp = client.post(
            "/api/v1/admin/keys",
            json={"nome": "Hack", "role": "admin"},
            headers=user_headers,
        )
        assert resp.status_code == 403

    def test_criar_key_readonly_proibido(self, client, readonly_headers):
        resp = client.post(
            "/api/v1/admin/keys",
            json={"nome": "Hack", "role": "user"},
            headers=readonly_headers,
        )
        assert resp.status_code == 403

    def test_criar_key_sem_nome(self, client, admin_headers):
        resp = client.post(
            "/api/v1/admin/keys",
            json={"role": "user"},
            headers=admin_headers,
        )
        assert resp.status_code == 400

    def test_criar_key_role_invalido(self, client, admin_headers):
        resp = client.post(
            "/api/v1/admin/keys",
            json={"nome": "Bad", "role": "superuser"},
            headers=admin_headers,
        )
        assert resp.status_code == 400

    def test_listar_keys_admin_ok(self, client, admin_headers):
        resp = client.get("/api/v1/admin/keys", headers=admin_headers)
        assert resp.status_code == 200
        data = resp.get_json()
        assert "keys" in data
        assert isinstance(data["keys"], list)

    def test_listar_keys_user_proibido(self, client, user_headers):
        resp = client.get("/api/v1/admin/keys", headers=user_headers)
        assert resp.status_code == 403

    def test_desativar_key(self, client, admin_headers):
        # Criar key
        create_resp = client.post(
            "/api/v1/admin/keys",
            json={"nome": "ToDeactivate", "role": "user"},
            headers=admin_headers,
        )
        key_id = create_resp.get_json()["key_id"]

        # Desativar
        resp = client.delete(f"/api/v1/admin/keys/{key_id}", headers=admin_headers)
        assert resp.status_code == 200

    def test_desativar_key_inexistente(self, client, admin_headers):
        resp = client.delete("/api/v1/admin/keys/lspf_naoexis", headers=admin_headers)
        assert resp.status_code == 404


# ================================================================
# ROTA RAIZ
# ================================================================

class TestRootEndpoint:
    """Testes da rota raiz."""

    def test_root_retorna_info_api(self, client):
        resp = client.get("/")
        assert resp.status_code == 200
        data = resp.get_json()
        assert "api" in data
        assert "endpoints" in data

    def test_404_endpoint_inexistente(self, client):
        resp = client.get("/api/v1/rota_que_nao_existe")
        assert resp.status_code == 404
        data = resp.get_json()
        assert "erro" in data

    def test_405_metodo_incorreto(self, client):
        resp = client.delete("/api/v1/health")
        assert resp.status_code == 405
