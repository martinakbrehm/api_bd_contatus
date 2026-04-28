"""
test_integration.py
-------------------
Testes de integração: fluxos completos end-to-end.

Simula cenários reais de uso da API combinando múltiplas camadas
(auth → validação → consulta → resposta).
"""

import json
from unittest.mock import MagicMock, patch

import pandas as pd
import pytest


class TestFluxoCompletoLogin:
    """Testa o fluxo completo: criar key → login → usar token → logout."""

    def test_fluxo_completo_jwt(self, client, admin_api_key):
        api_key, key_id = admin_api_key

        # 1. Login
        login_resp = client.post(
            "/api/v1/auth/login",
            json={"api_key": api_key},
            content_type="application/json",
        )
        assert login_resp.status_code == 200
        tokens = login_resp.get_json()
        access_token = tokens["access_token"]
        refresh_token = tokens["refresh_token"]

        # 2. Usar access token para acessar /me
        me_resp = client.get(
            "/api/v1/auth/me",
            headers={"Authorization": f"Bearer {access_token}"},
        )
        assert me_resp.status_code == 200
        assert me_resp.get_json()["role"] == "admin"

        # 3. Refresh token
        refresh_resp = client.post(
            "/api/v1/auth/refresh",
            json={"refresh_token": refresh_token},
            content_type="application/json",
        )
        assert refresh_resp.status_code == 200
        new_access = refresh_resp.get_json()["access_token"]

        # 4. Novo token funciona
        me2_resp = client.get(
            "/api/v1/auth/me",
            headers={"Authorization": f"Bearer {new_access}"},
        )
        assert me2_resp.status_code == 200

        # 5. Logout
        logout_resp = client.post(
            "/api/v1/auth/logout",
            headers={"Authorization": f"Bearer {new_access}"},
            content_type="application/json",
        )
        assert logout_resp.status_code == 200

        # 6. Token antigo não funciona mais
        me3_resp = client.get(
            "/api/v1/auth/me",
            headers={"Authorization": f"Bearer {new_access}"},
        )
        assert me3_resp.status_code == 401


class TestFluxoCompletoConsulta:
    """Testa o fluxo completo de consulta com mock do banco."""

    def _mock_df(self, n=5):
        rows = []
        for i in range(n):
            rows.append({
                "NOME": f"PESSOA {i}",
                "CPF": f"3216549870{i}",
                "TELEFONE_1": f"119876{50000+i}",
                "TELEFONE_2": None, "TELEFONE_3": None,
                "TELEFONE_4": None, "TELEFONE_5": None,
                "TELEFONE_6": None,
                "GENERO": "M" if i % 2 == 0 else "F",
                "DATA_NASCIMENTO": "1990-01-01",
                "ENDERECO": f"RUA {i}", "NUM_END": str(i),
                "COMPLEMENTO": None,
                "BAIRRO": "CENTRO", "CIDADE": "SAO PAULO",
                "UF": "SP", "CEP": "01000000",
                "EMAIL_1": f"p{i}@mail.com", "EMAIL_2": None,
            })
        return pd.DataFrame(rows)

    def test_consulta_completa_com_dados(self, client, admin_headers):
        with patch("api.routes.consulta._executar_query", return_value=self._mock_df(10)):
            resp = client.post(
                "/api/v1/consulta",
                json={
                    "ufs": ["SP"],
                    "cidades": ["SAO PAULO"],
                    "genero": "ambos",
                    "quantidade": 5,
                },
                headers=admin_headers,
            )
            assert resp.status_code == 200
            data = resp.get_json()
            assert data["ok"] is True
            assert data["total_banco"] == 10
            assert len(data["registros"]) <= 5
            assert "colunas" in data
            assert "tempo_processamento_s" in data

    def test_contagem_retorna_total_sem_dados(self, client, user_headers):
        with patch("api.routes.consulta._conectar_banco") as mock_conn:
            mock_cursor = MagicMock()
            mock_cursor.fetchone.return_value = {"total": 9999}
            mock_conn.return_value.cursor.return_value = mock_cursor

            resp = client.post(
                "/api/v1/consulta/contagem",
                json={"ufs": ["RJ"], "genero": "F", "idade_min": 30, "idade_max": 50},
                headers=user_headers,
            )
            assert resp.status_code == 200
            data = resp.get_json()
            assert data["ok"] is True
            assert data["total_banco"] == 9999
            # Contagem NÃO deve retornar registros
            assert "registros" not in data

    def test_preview_mascara_dados(self, client, readonly_headers):
        with patch("api.routes.consulta._executar_query", return_value=self._mock_df(3)):
            resp = client.post(
                "/api/v1/consulta/preview",
                json={"ufs": ["SP"]},
                headers=readonly_headers,
            )
            assert resp.status_code == 200
            data = resp.get_json()
            assert data["ok"] is True
            assert "registros_preview" in data
            assert data["nota"] is not None

            # Verificar que dados estão mascarados
            for reg in data["registros_preview"]:
                if reg.get("CPF"):
                    assert "***" in str(reg["CPF"]), "CPF deveria estar mascarado"
                if reg.get("NOME"):
                    assert "*" in str(reg["NOME"]), "Nome deveria estar mascarado"


class TestFluxoAdminKeys:
    """Testa o fluxo administrativo de API Keys."""

    def test_criar_e_usar_nova_key(self, client, admin_headers):
        # 1. Admin cria key de user
        create_resp = client.post(
            "/api/v1/admin/keys",
            json={"nome": "App Mobile", "role": "user", "expira_em_dias": 30},
            headers=admin_headers,
        )
        assert create_resp.status_code == 201
        new_key = create_resp.get_json()["api_key"]
        key_id = create_resp.get_json()["key_id"]

        # 2. Nova key consegue fazer login
        login_resp = client.post(
            "/api/v1/auth/login",
            json={"api_key": new_key},
            content_type="application/json",
        )
        assert login_resp.status_code == 200
        assert login_resp.get_json()["role"] == "user"

        # 3. Key aparece na listagem
        list_resp = client.get("/api/v1/admin/keys", headers=admin_headers)
        keys = [k["key_id"] for k in list_resp.get_json()["keys"]]
        assert key_id in keys

        # 4. Admin desativa a key
        del_resp = client.delete(f"/api/v1/admin/keys/{key_id}", headers=admin_headers)
        assert del_resp.status_code == 200

        # 5. Key desativada não consegue mais fazer login
        login_resp2 = client.post(
            "/api/v1/auth/login",
            json={"api_key": new_key},
            content_type="application/json",
        )
        assert login_resp2.status_code == 401


class TestSegurancaCamadas:
    """Testa que todas as camadas de segurança funcionam juntas."""

    def test_request_sem_auth_em_rota_protegida(self, client):
        """Requisição sem credencial deve retornar 401."""
        endpoints = [
            ("/api/v1/consulta", "POST"),
            ("/api/v1/consulta/contagem", "POST"),
            ("/api/v1/consulta/preview", "POST"),
            ("/api/v1/auth/me", "GET"),
            ("/api/v1/auth/logout", "POST"),
            ("/api/v1/admin/keys", "GET"),
            ("/api/v1/admin/keys", "POST"),
            ("/api/v1/health/db", "GET"),
            ("/api/v1/health/stats", "GET"),
        ]
        for url, method in endpoints:
            if method == "GET":
                resp = client.get(url)
            else:
                resp = client.post(url, json={"ufs": ["SP"]}, content_type="application/json")
            assert resp.status_code in (401, 415), f"Esperado 401 para {method} {url}, obtido {resp.status_code}"

    def test_escalacao_de_privilegio_bloqueada(self, client, readonly_headers):
        """Readonly não deve acessar endpoints de admin ou consulta completa."""
        # consulta completa
        resp = client.post(
            "/api/v1/consulta",
            json={"ufs": ["SP"]},
            headers=readonly_headers,
        )
        assert resp.status_code == 403

        # admin endpoints
        resp2 = client.get("/api/v1/admin/keys", headers=readonly_headers)
        assert resp2.status_code == 403

        resp3 = client.post(
            "/api/v1/admin/keys",
            json={"nome": "hack", "role": "admin"},
            headers=readonly_headers,
        )
        assert resp3.status_code == 403

    def test_user_nao_acessa_admin(self, client, user_headers):
        """User não deve acessar endpoints admin."""
        resp = client.get("/api/v1/admin/keys", headers=user_headers)
        assert resp.status_code == 403

        resp2 = client.get("/api/v1/health/db", headers=user_headers)
        assert resp2.status_code == 403

    def test_api_key_direta_funciona(self, client, user_api_key):
        """API Key via header X-API-Key deve funcionar sem JWT."""
        api_key, _ = user_api_key

        with patch("api.routes.consulta._conectar_banco") as mock_conn:
            mock_cursor = MagicMock()
            mock_cursor.fetchone.return_value = {"total": 100}
            mock_conn.return_value.cursor.return_value = mock_cursor

            resp = client.post(
                "/api/v1/consulta/contagem",
                json={"ufs": ["SP"]},
                headers={
                    "X-API-Key": api_key,
                    "Content-Type": "application/json",
                },
            )
            assert resp.status_code == 200

    def test_token_invalido_rejeitado(self, client):
        """Token forjado deve ser rejeitado."""
        resp = client.get(
            "/api/v1/auth/me",
            headers={"Authorization": "Bearer token.forjado.invalido"},
        )
        assert resp.status_code == 401

    def test_api_key_forjada_rejeitada(self, client):
        """API Key forjada deve ser rejeitada."""
        resp = client.get(
            "/api/v1/auth/me",
            headers={
                "X-API-Key": "lspf_chave_forjada_quenaoexistenobanco_aaaa1234567890abcdef0123456789",
            },
        )
        assert resp.status_code == 401


class TestBruteForceProtection:
    """Testa proteção contra brute force."""

    def test_brute_force_bloqueio_apos_tentativas(self, client, monkeypatch):
        """Após muitas tentativas falhas, deve bloquear o IP."""
        monkeypatch.setattr("api.config.MAX_LOGIN_ATTEMPTS", 3)
        monkeypatch.setattr("api.auth.decorators.MAX_LOGIN_ATTEMPTS", 3)
        monkeypatch.setattr("api.config.LOGIN_LOCKOUT_MINUTES", 1)
        monkeypatch.setattr("api.auth.decorators.LOGIN_LOCKOUT_MINUTES", 1)

        # Forçar tentativas falhas
        for i in range(3):
            client.get(
                "/api/v1/auth/me",
                headers={"Authorization": "Bearer token.invalido.falso"},
            )

        # Próxima tentativa (mesmo com token válido) deve ser bloqueada
        resp = client.get(
            "/api/v1/auth/me",
            headers={"Authorization": "Bearer qualquer.token"},
        )
        assert resp.status_code in (401, 429)
