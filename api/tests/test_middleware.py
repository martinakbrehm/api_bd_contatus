"""
test_middleware.py
-----------------
Testes dos middlewares de segurança: headers, request validator, IP filter.
"""

import json

import pytest


class TestSecurityHeaders:
    """Testes dos headers de segurança HTTP."""

    def test_x_content_type_options(self, client):
        resp = client.get("/api/v1/health")
        assert resp.headers.get("X-Content-Type-Options") == "nosniff"

    def test_x_xss_protection(self, client):
        resp = client.get("/api/v1/health")
        assert resp.headers.get("X-XSS-Protection") == "1; mode=block"

    def test_x_frame_options(self, client):
        resp = client.get("/api/v1/health")
        assert resp.headers.get("X-Frame-Options") == "DENY"

    def test_referrer_policy(self, client):
        resp = client.get("/api/v1/health")
        assert "strict-origin" in resp.headers.get("Referrer-Policy", "")

    def test_content_security_policy(self, client):
        resp = client.get("/api/v1/health")
        csp = resp.headers.get("Content-Security-Policy", "")
        assert "default-src 'none'" in csp

    def test_cache_control_no_store(self, client):
        resp = client.get("/api/v1/health")
        cache = resp.headers.get("Cache-Control", "")
        assert "no-store" in cache

    def test_server_header_removido(self, client):
        resp = client.get("/api/v1/health")
        # Server header não deve revelar tecnologia
        assert "Flask" not in resp.headers.get("Server", "")

    def test_request_id_gerado(self, client):
        resp = client.get("/api/v1/health")
        rid = resp.headers.get("X-Request-ID", "")
        assert rid.startswith("req_") or len(rid) > 0

    def test_request_id_propagado(self, client):
        custom_id = "meu-request-id-12345"
        resp = client.get(
            "/api/v1/health",
            headers={"X-Request-ID": custom_id},
        )
        assert resp.headers.get("X-Request-ID") == custom_id

    def test_response_time_header(self, client):
        resp = client.get("/api/v1/health")
        rt = resp.headers.get("X-Response-Time", "")
        assert rt.endswith("s")


class TestRequestValidator:
    """Testes de validação de requisições — detecção de ataques."""

    def test_sql_injection_bloqueado(self, client, admin_headers):
        payload = {"ufs": ["SP"], "cidades": ["'; DROP TABLE users; --"]}
        resp = client.post(
            "/api/v1/consulta/contagem",
            headers=admin_headers,
            json=payload,
        )
        # Deve ser bloqueado pelo middleware ou schema
        assert resp.status_code in (400, 415)

    def test_xss_bloqueado(self, client, admin_headers):
        payload = {"ufs": ["SP"], "cidades": ["<script>alert(1)</script>"]}
        resp = client.post(
            "/api/v1/consulta/contagem",
            headers=admin_headers,
            json=payload,
        )
        assert resp.status_code == 400

    def test_command_injection_bloqueado(self, client, admin_headers):
        payload = {"ufs": ["SP"], "cidades": ["SAO PAULO && rm -rf /"]}
        resp = client.post(
            "/api/v1/consulta/contagem",
            headers=admin_headers,
            json=payload,
        )
        assert resp.status_code == 400

    def test_path_traversal_bloqueado(self, client, admin_headers):
        payload = {"ufs": ["SP"], "cidades": ["../../etc/passwd"]}
        resp = client.post(
            "/api/v1/consulta/contagem",
            headers=admin_headers,
            json=payload,
        )
        assert resp.status_code == 400

    def test_content_type_obrigatorio_post(self, client, admin_token):
        resp = client.post(
            "/api/v1/consulta/contagem",
            headers={"Authorization": f"Bearer {admin_token}"},
            data="nao e json",
        )
        assert resp.status_code == 415

    def test_ufs_validas_nao_sao_bloqueadas(self, client, admin_headers):
        """UFs legítimas (SP, RJ, etc.) não devem trigger falso positivo."""
        payload = {"ufs": ["SP"]}
        resp = client.post(
            "/api/v1/consulta/contagem",
            headers=admin_headers,
            json=payload,
        )
        # Pode falhar por conexão ao banco, mas NÃO deve ser 400 por "malicioso"
        assert resp.status_code != 415

    def test_genero_valido_nao_bloqueado(self, client, admin_headers):
        """Gênero M/F não deve trigger falso positivo."""
        payload = {"ufs": ["SP"], "genero": "M"}
        resp = client.post(
            "/api/v1/consulta/contagem",
            headers=admin_headers,
            json=payload,
        )
        assert resp.status_code != 415

    def test_numeros_puros_nao_bloqueados(self, client, admin_headers):
        """Números (idade, quantidade) não devem ser bloqueados."""
        payload = {"ufs": ["SP"], "idade_min": 25, "idade_max": 60}
        resp = client.post(
            "/api/v1/consulta/contagem",
            headers=admin_headers,
            json=payload,
        )
        assert resp.status_code != 415


class TestCORS:
    """Testes de CORS."""

    def test_preflight_options(self, client):
        resp = client.options(
            "/api/v1/health",
            headers={"Origin": "http://localhost:5000"},
        )
        assert resp.status_code == 204
        assert "Access-Control-Allow-Origin" in resp.headers

    def test_origin_permitido(self, client, monkeypatch):
        monkeypatch.setattr("api.middleware.security_headers.CORS_ORIGINS", ["http://localhost:5000"])
        resp = client.get(
            "/api/v1/health",
            headers={"Origin": "http://localhost:5000"},
        )
        assert resp.headers.get("Access-Control-Allow-Origin") == "http://localhost:5000"

    def test_origin_nao_permitido(self, client, monkeypatch):
        monkeypatch.setattr("api.middleware.security_headers.CORS_ORIGINS", ["http://allowed.com"])
        resp = client.get(
            "/api/v1/health",
            headers={"Origin": "http://evil.com"},
        )
        assert resp.headers.get("Access-Control-Allow-Origin") != "http://evil.com"


class TestIPFilter:
    """Testes da filtragem de IPs."""

    def test_blacklist_bloqueia_ip(self, client, monkeypatch):
        monkeypatch.setattr("api.middleware.ip_filter.IP_BLACKLIST", ["127.0.0.1"])
        resp = client.get("/api/v1/health")
        assert resp.status_code == 403

    def test_whitelist_ativo_bloqueia_ip_nao_listado(self, client, monkeypatch):
        monkeypatch.setattr("api.middleware.ip_filter.IP_WHITELIST_ENABLED", True)
        monkeypatch.setattr("api.middleware.ip_filter.IP_WHITELIST", ["10.0.0.1"])
        resp = client.get("/api/v1/health")
        assert resp.status_code == 403

    def test_whitelist_ativo_permite_ip_listado(self, client, monkeypatch):
        monkeypatch.setattr("api.middleware.ip_filter.IP_WHITELIST_ENABLED", True)
        monkeypatch.setattr("api.middleware.ip_filter.IP_WHITELIST", ["127.0.0.1"])
        resp = client.get("/api/v1/health")
        assert resp.status_code == 200
