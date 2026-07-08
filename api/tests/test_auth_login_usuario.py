"""
test_auth_login_usuario.py
--------------------------
Testes da rota POST /api/v1/auth/login_usuario (autenticação por email + senha).

Cobre:
- Login com argon2id correto → 200 + tokens
- Senha errada → 401 com mensagem genérica
- Email não encontrado → 401 com MESMA mensagem (não revelar se email existe)
- Usuário inativo → 401
- Conta expirada → 401
- Migração transparente: hash PBKDF2 legado aceito e rehashado
- Rehash automático quando precisa_rehash() == True
- Validação de schema: campos ausentes ou inválidos → 400
"""

import datetime
from unittest.mock import MagicMock, patch

import pytest

from api.utils.crypto import _hash_senha_pbkdf2, hash_senha


# ── Fixtures ──────────────────────────────────────────────────────────────────

def _usuario(
    senha="senha_correta",
    role="user",
    ativo=1,
    expira_em=None,
    legacy=False,
):
    """Monta um dict de usuario_app com hash gerado dinamicamente."""
    if legacy:
        salt = "testsalt"
        h = _hash_senha_pbkdf2(senha, salt)
        senha_hash = f"{h}${salt}"
    else:
        senha_hash = hash_senha(senha)

    return {
        "id": 1,
        "nome": "Usuário Teste",
        "email": "teste@contatus.com",
        "senha_hash": senha_hash,
        "role": role,
        "ativo": ativo,
        "expira_em": expira_em,
    }


def _post(client, body: dict):
    return client.post("/api/v1/auth/login_usuario", json=body)


# ── Caminho feliz ─────────────────────────────────────────────────────────────

class TestLoginSucesso:

    def test_retorna_200_e_tokens(self, client):
        usuario = _usuario(senha="senha_ok")
        with patch("api.routes.auth_routes._buscar_usuario_por_email", return_value=usuario), \
             patch("api.routes.auth_routes._atualizar_ultimo_acesso"), \
             patch("api.routes.auth_routes._atualizar_senha_hash"):
            resp = _post(client, {"email": "teste@contatus.com", "senha": "senha_ok"})
        assert resp.status_code == 200
        data = resp.get_json()
        assert "access_token" in data
        assert "refresh_token" in data
        assert data["token_type"] == "Bearer"
        assert data["role"] == "user"

    def test_nome_incluso_na_resposta(self, client):
        usuario = _usuario(senha="abc")
        with patch("api.routes.auth_routes._buscar_usuario_por_email", return_value=usuario), \
             patch("api.routes.auth_routes._atualizar_ultimo_acesso"), \
             patch("api.routes.auth_routes._atualizar_senha_hash"):
            resp = _post(client, {"email": "teste@contatus.com", "senha": "abc"})
        assert resp.get_json()["nome"] == "Usuário Teste"

    def test_role_admin_retornado(self, client):
        usuario = _usuario(senha="abc", role="admin")
        with patch("api.routes.auth_routes._buscar_usuario_por_email", return_value=usuario), \
             patch("api.routes.auth_routes._atualizar_ultimo_acesso"), \
             patch("api.routes.auth_routes._atualizar_senha_hash"):
            resp = _post(client, {"email": "teste@contatus.com", "senha": "abc"})
        assert resp.get_json()["role"] == "admin"

    def test_ultimo_acesso_atualizado(self, client):
        usuario = _usuario(senha="abc")
        with patch("api.routes.auth_routes._buscar_usuario_por_email", return_value=usuario), \
             patch("api.routes.auth_routes._atualizar_ultimo_acesso") as mock_acesso, \
             patch("api.routes.auth_routes._atualizar_senha_hash"):
            _post(client, {"email": "teste@contatus.com", "senha": "abc"})
        mock_acesso.assert_called_once_with(1)


# ── Senha incorreta ───────────────────────────────────────────────────────────

class TestSenhaIncorreta:

    def test_senha_errada_retorna_401(self, client):
        usuario = _usuario(senha="senha_correta")
        with patch("api.routes.auth_routes._buscar_usuario_por_email", return_value=usuario), \
             patch("api.routes.auth_routes._atualizar_ultimo_acesso"), \
             patch("api.routes.auth_routes._atualizar_senha_hash"):
            resp = _post(client, {"email": "teste@contatus.com", "senha": "senha_errada"})
        assert resp.status_code == 401

    def test_mensagem_generica_nao_revela_motivo(self, client):
        """Não revelar se o problema é email ou senha."""
        usuario = _usuario(senha="senha_correta")
        with patch("api.routes.auth_routes._buscar_usuario_por_email", return_value=usuario), \
             patch("api.routes.auth_routes._atualizar_ultimo_acesso"), \
             patch("api.routes.auth_routes._atualizar_senha_hash"):
            resp = _post(client, {"email": "teste@contatus.com", "senha": "errada"})
        msg = resp.get_json()["erro"]
        assert "Credenciais inválidas" in msg
        assert "senha" not in msg.lower()


# ── Email não encontrado ───────────────────────────────────────────────────────

class TestEmailNaoEncontrado:

    def test_email_inexistente_retorna_401(self, client):
        with patch("api.routes.auth_routes._buscar_usuario_por_email", return_value=None):
            resp = _post(client, {"email": "naoexiste@contatus.com", "senha": "abc"})
        assert resp.status_code == 401

    def test_mensagem_identica_a_senha_errada(self, client):
        """Timing/mensagem idêntica independente de ser email ou senha errada."""
        usuario = _usuario(senha="correta")
        # Senha errada
        with patch("api.routes.auth_routes._buscar_usuario_por_email", return_value=usuario), \
             patch("api.routes.auth_routes._atualizar_ultimo_acesso"), \
             patch("api.routes.auth_routes._atualizar_senha_hash"):
            resp_senha = _post(client, {"email": "teste@contatus.com", "senha": "errada"})

        # Email não encontrado
        with patch("api.routes.auth_routes._buscar_usuario_por_email", return_value=None):
            resp_email = _post(client, {"email": "naoexiste@x.com", "senha": "abc"})

        assert resp_senha.get_json()["erro"] == resp_email.get_json()["erro"]


# ── Restrições de conta ───────────────────────────────────────────────────────

class TestRestricoesConta:

    def test_usuario_inativo_retorna_401(self, client):
        usuario = _usuario(senha="abc", ativo=0)
        with patch("api.routes.auth_routes._buscar_usuario_por_email", return_value=usuario):
            resp = _post(client, {"email": "teste@contatus.com", "senha": "abc"})
        assert resp.status_code == 401

    def test_conta_expirada_retorna_401(self, client):
        expirada = datetime.datetime(2000, 1, 1, tzinfo=datetime.timezone.utc)
        usuario = _usuario(senha="abc", expira_em=expirada)
        with patch("api.routes.auth_routes._buscar_usuario_por_email", return_value=usuario):
            resp = _post(client, {"email": "teste@contatus.com", "senha": "abc"})
        assert resp.status_code == 401

    def test_conta_nao_expirada_aceita(self, client):
        futura = datetime.datetime(2099, 1, 1, tzinfo=datetime.timezone.utc)
        usuario = _usuario(senha="abc", expira_em=futura)
        with patch("api.routes.auth_routes._buscar_usuario_por_email", return_value=usuario), \
             patch("api.routes.auth_routes._atualizar_ultimo_acesso"), \
             patch("api.routes.auth_routes._atualizar_senha_hash"):
            resp = _post(client, {"email": "teste@contatus.com", "senha": "abc"})
        assert resp.status_code == 200


# ── Migração PBKDF2 → argon2id ────────────────────────────────────────────────

class TestMigracaoLegado:

    def test_hash_pbkdf2_aceito_no_login(self, client):
        """Hash legado PBKDF2 deve autenticar com sucesso."""
        usuario = _usuario(senha="senha_legado", legacy=True)
        with patch("api.routes.auth_routes._buscar_usuario_por_email", return_value=usuario), \
             patch("api.routes.auth_routes._atualizar_ultimo_acesso"), \
             patch("api.routes.auth_routes._atualizar_senha_hash"):
            resp = _post(client, {"email": "teste@contatus.com", "senha": "senha_legado"})
        assert resp.status_code == 200

    def test_hash_pbkdf2_dispara_rehash(self, client):
        """Após autenticar com PBKDF2, deve chamar _atualizar_senha_hash."""
        usuario = _usuario(senha="senha_legado", legacy=True)
        with patch("api.routes.auth_routes._buscar_usuario_por_email", return_value=usuario), \
             patch("api.routes.auth_routes._atualizar_ultimo_acesso"), \
             patch("api.routes.auth_routes._atualizar_senha_hash") as mock_rehash:
            _post(client, {"email": "teste@contatus.com", "senha": "senha_legado"})
        mock_rehash.assert_called_once()
        # Novo hash deve ser argon2id
        novo_hash = mock_rehash.call_args[0][1]
        assert novo_hash.startswith("$argon2id$")

    def test_hash_pbkdf2_senha_errada_rejeitada(self, client):
        usuario = _usuario(senha="senha_legado", legacy=True)
        with patch("api.routes.auth_routes._buscar_usuario_por_email", return_value=usuario), \
             patch("api.routes.auth_routes._atualizar_ultimo_acesso"), \
             patch("api.routes.auth_routes._atualizar_senha_hash"):
            resp = _post(client, {"email": "teste@contatus.com", "senha": "errada"})
        assert resp.status_code == 401

    def test_hash_argon2id_nao_dispara_rehash_desnecessario(self, client):
        """Hash argon2id atual não deve disparar rehash."""
        usuario = _usuario(senha="senha_ok")
        with patch("api.routes.auth_routes._buscar_usuario_por_email", return_value=usuario), \
             patch("api.routes.auth_routes._atualizar_ultimo_acesso"), \
             patch("api.routes.auth_routes._atualizar_senha_hash") as mock_rehash:
            _post(client, {"email": "teste@contatus.com", "senha": "senha_ok"})
        mock_rehash.assert_not_called()


# ── Validação de schema ───────────────────────────────────────────────────────

class TestValidacaoSchema:

    def test_sem_email_retorna_400(self, client):
        resp = _post(client, {"senha": "abc123"})
        assert resp.status_code == 400

    def test_sem_senha_retorna_400(self, client):
        resp = _post(client, {"email": "user@contatus.com"})
        assert resp.status_code == 400

    def test_body_vazio_retorna_400(self, client):
        resp = _post(client, {})
        assert resp.status_code == 400

    def test_email_invalido_retorna_400(self, client):
        resp = _post(client, {"email": "nao_e_email", "senha": "abc"})
        assert resp.status_code == 400

    def test_senha_muito_longa_retorna_400(self, client):
        resp = _post(client, {"email": "u@x.com", "senha": "x" * 201})
        assert resp.status_code == 400
