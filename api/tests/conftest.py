"""
api/tests/conftest.py
---------------------
Fixtures compartilhadas para todos os testes da API segura.

Fornece:
  - Flask test client configurado
  - API Keys de teste (admin, user, readonly)
  - Tokens JWT de teste
  - Helpers para autenticação nos requests
  - Cleanup automático entre testes
"""

import json
import os
import sys
import tempfile
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

# Garantir imports do projeto
_ROOT = Path(__file__).parent.parent.parent
sys.path.insert(0, str(_ROOT))


# ── Fixtures de configuração ─────────────────────────────────

@pytest.fixture(autouse=True)
def _isolate_api_keys(tmp_path, monkeypatch):
    """
    Isola o arquivo de API keys em diretório temporário
    para que os testes não afetem keys reais.
    """
    fake_keys_file = tmp_path / "api_keys.json"
    monkeypatch.setattr("api.config.API_KEYS_FILE", fake_keys_file)
    monkeypatch.setattr("api.auth.api_keys.API_KEYS_FILE", fake_keys_file)
    yield fake_keys_file


@pytest.fixture(autouse=True)
def _isolate_logs(tmp_path, monkeypatch):
    """Isola logs em diretório temporário."""
    logs_dir = tmp_path / "logs"
    logs_dir.mkdir()
    monkeypatch.setattr("api.config.LOGS_DIR", logs_dir)
    monkeypatch.setattr("api.config.AUDIT_LOG_FILE", logs_dir / "audit.log")
    monkeypatch.setattr("api.config.SECURITY_LOG_FILE", logs_dir / "security.log")


@pytest.fixture(autouse=True)
def _disable_rate_limit(monkeypatch):
    """Desabilita rate limiting por padrão nos testes."""
    monkeypatch.setattr("api.config.RATE_LIMIT_ENABLED", False)


@pytest.fixture(autouse=True)
def _clear_brute_force():
    """Limpa tracking de brute force entre testes."""
    from api.auth import decorators
    decorators._failed_attempts.clear()
    yield
    decorators._failed_attempts.clear()


@pytest.fixture(autouse=True)
def _clear_jwt_blacklist():
    """Limpa blacklist de JWT entre testes."""
    from api.auth import jwt_handler
    jwt_handler._token_blacklist.clear()
    jwt_handler._used_jtis.clear()
    yield
    jwt_handler._token_blacklist.clear()
    jwt_handler._used_jtis.clear()


@pytest.fixture
def app():
    """Cria a Flask app de teste."""
    from api.app import create_app
    app = create_app()
    app.config["TESTING"] = True
    return app


@pytest.fixture
def client(app):
    """Flask test client."""
    return app.test_client()


@pytest.fixture
def admin_api_key():
    """Cria e retorna uma API Key de admin para testes."""
    from api.auth.api_keys import gerar_api_key
    api_key, key_id = gerar_api_key(
        nome="Test Admin",
        role="admin",
        expira_em_dias=1,
    )
    return api_key, key_id


@pytest.fixture
def user_api_key():
    """Cria e retorna uma API Key de user para testes."""
    from api.auth.api_keys import gerar_api_key
    api_key, key_id = gerar_api_key(
        nome="Test User",
        role="user",
        expira_em_dias=1,
    )
    return api_key, key_id


@pytest.fixture
def readonly_api_key():
    """Cria e retorna uma API Key readonly para testes."""
    from api.auth.api_keys import gerar_api_key
    api_key, key_id = gerar_api_key(
        nome="Test Readonly",
        role="readonly",
        expira_em_dias=1,
    )
    return api_key, key_id


@pytest.fixture
def admin_token(admin_api_key):
    """Cria um access token JWT de admin."""
    from api.auth.jwt_handler import criar_access_token
    api_key, key_id = admin_api_key
    return criar_access_token(subject=key_id, role="admin")


@pytest.fixture
def user_token(user_api_key):
    """Cria um access token JWT de user."""
    from api.auth.jwt_handler import criar_access_token
    api_key, key_id = user_api_key
    return criar_access_token(subject=key_id, role="user")


@pytest.fixture
def readonly_token(readonly_api_key):
    """Cria um access token JWT de readonly."""
    from api.auth.jwt_handler import criar_access_token
    api_key, key_id = readonly_api_key
    return criar_access_token(subject=key_id, role="readonly")


@pytest.fixture
def admin_headers(admin_token):
    """Headers com autenticação JWT admin."""
    return {
        "Authorization": f"Bearer {admin_token}",
        "Content-Type": "application/json",
    }


@pytest.fixture
def user_headers(user_token):
    """Headers com autenticação JWT user."""
    return {
        "Authorization": f"Bearer {user_token}",
        "Content-Type": "application/json",
    }


@pytest.fixture
def readonly_headers(readonly_token):
    """Headers com autenticação JWT readonly."""
    return {
        "Authorization": f"Bearer {readonly_token}",
        "Content-Type": "application/json",
    }


@pytest.fixture
def api_key_headers(user_api_key):
    """Headers com autenticação via API Key."""
    api_key, _ = user_api_key
    return {
        "X-API-Key": api_key,
        "Content-Type": "application/json",
    }


# ── Filtros de exemplo ───────────────────────────────────────

@pytest.fixture
def filtro_basico():
    """Filtro mínimo válido para consultas."""
    return {"ufs": ["SP"]}


@pytest.fixture
def filtro_completo():
    """Filtro completo com todos os campos."""
    return {
        "ufs": ["SP", "RJ"],
        "cidades": ["SAO PAULO"],
        "bairros": ["JARDIM BOTANICO"],
        "genero": "ambos",
        "idade_min": 25,
        "idade_max": 60,
        "email": "nao_filtrar",
        "tipo_telefone": "movel",
        "cbos": [],
        "quantidade": 100,
    }
