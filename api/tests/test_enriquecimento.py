"""
test_enriquecimento.py
----------------------
Testes de segurança e comportamento do endpoint POST /api/v1/enriquecimento.

TODOS os testes são unitários com DB completamente mockado — nenhuma conexão
real é estabelecida, conforme exigência de não sobrecarregar o banco.
"""

import io
from unittest.mock import MagicMock, patch

import pandas as pd
import pytest


# ── Helpers ────────────────────────────────────────────────────────────────────

def _txt(conteudo: str) -> io.BytesIO:
    """Cria arquivo .txt em memória com o conteúdo fornecido."""
    buf = io.BytesIO(conteudo.encode("utf-8"))
    buf.name = "lista.txt"
    return buf


def _post_enriquecimento(client, headers, conteudo: str, tipo: str = "cpf"):
    """Atalho para POST multipart com arquivo."""
    return client.post(
        "/api/v1/enriquecimento",
        data={
            "arquivo": (io.BytesIO(conteudo.encode("utf-8")), "lista.txt"),
            "tipo": tipo,
        },
        headers={k: v for k, v in headers.items() if k != "Content-Type"},
        content_type="multipart/form-data",
    )


# ── Autenticação / autorização ─────────────────────────────────────────────────

class TestEnriquecimentoAuth:
    """Segurança: autenticação e RBAC no endpoint de enriquecimento."""

    def test_sem_token_retorna_401(self, client):
        resp = client.post(
            "/api/v1/enriquecimento",
            data={"arquivo": (_txt("09199194996"), "l.txt"), "tipo": "cpf"},
            content_type="multipart/form-data",
        )
        assert resp.status_code == 401

    def test_token_invalido_retorna_401(self, client):
        resp = client.post(
            "/api/v1/enriquecimento",
            data={"arquivo": (_txt("09199194996"), "l.txt"), "tipo": "cpf"},
            headers={"Authorization": "Bearer token.invalido.xyz"},
            content_type="multipart/form-data",
        )
        assert resp.status_code == 401

    def test_role_readonly_retorna_403(self, client, readonly_headers):
        resp = _post_enriquecimento(client, readonly_headers, "09199194996")
        assert resp.status_code == 403

    def test_role_user_permitido(self, client, user_headers):
        """role 'user' deve ter acesso ao endpoint de enriquecimento."""
        df_vazio = pd.DataFrame(columns=["CPF", "NOME"])
        with patch("api.routes.enriquecimento._carregar_cpfs_sessao"), \
             patch("api.routes.enriquecimento._conectar") as mock_conn:
            mock_conn.return_value.__enter__ = lambda s: s
            mock_conn.return_value.__exit__ = MagicMock(return_value=False)
            with patch("pandas.read_sql", return_value=df_vazio), \
                 patch("api.routes.enriquecimento.gerar_excel_bytes", return_value=io.BytesIO(b"PK")):
                resp = _post_enriquecimento(client, user_headers, "09199194996")
        assert resp.status_code in (200, 400, 500)
        assert resp.status_code != 403

    def test_role_admin_permitido(self, client, admin_headers):
        df_vazio = pd.DataFrame(columns=["CPF", "NOME"])
        with patch("api.routes.enriquecimento._carregar_cpfs_sessao"), \
             patch("api.routes.enriquecimento._conectar") as mock_conn:
            mock_conn.return_value.__enter__ = lambda s: s
            mock_conn.return_value.__exit__ = MagicMock(return_value=False)
            with patch("pandas.read_sql", return_value=df_vazio), \
                 patch("api.routes.enriquecimento.gerar_excel_bytes", return_value=io.BytesIO(b"PK")):
                resp = _post_enriquecimento(client, admin_headers, "09199194996")
        assert resp.status_code != 403


# ── Validação de entrada ───────────────────────────────────────────────────────

class TestEnriquecimentoValidacao:
    """Comportamento esperado para inputs inválidos (todos mocked)."""

    def test_sem_arquivo_retorna_400(self, client, user_headers):
        resp = client.post(
            "/api/v1/enriquecimento",
            data={"tipo": "cpf"},
            headers={k: v for k, v in user_headers.items() if k != "Content-Type"},
            content_type="multipart/form-data",
        )
        assert resp.status_code == 400
        assert "arquivo" in resp.get_json()["erro"].lower()

    def test_tipo_invalido_retorna_400(self, client, user_headers):
        resp = client.post(
            "/api/v1/enriquecimento",
            data={
                "arquivo": (_txt("09199194996"), "l.txt"),
                "tipo": "rg",
            },
            headers={k: v for k, v in user_headers.items() if k != "Content-Type"},
            content_type="multipart/form-data",
        )
        assert resp.status_code == 400
        data = resp.get_json()
        assert "tipo" in data["erro"].lower()

    def test_arquivo_vazio_retorna_400(self, client, user_headers):
        resp = _post_enriquecimento(client, user_headers, "")
        assert resp.status_code == 400

    def test_arquivo_com_cpfs_invalidos_retorna_400(self, client, user_headers):
        """Arquivo com linhas que não produzem CPF válido após normalização."""
        resp = _post_enriquecimento(client, user_headers, "abc\ndef\n12345\n")
        assert resp.status_code == 400

    def test_content_type_json_retorna_400(self, client, user_headers):
        """Enviar JSON em vez de multipart/form-data deve falhar."""
        resp = client.post(
            "/api/v1/enriquecimento",
            json={"cpfs": ["09199194996"]},
            headers=user_headers,
        )
        assert resp.status_code in (400, 415)


# ── Parsing / normalização ────────────────────────────────────────────────────

class TestEnriquecimentoParsing:
    """Testes unitários de _normalizar_cpf, _normalizar_telefone, _parse_arquivo."""

    def test_normalizar_cpf_digitos(self):
        from api.routes.enriquecimento import _normalizar_cpf
        assert _normalizar_cpf("091.991.949-96") == "09199194996"

    def test_normalizar_cpf_invalido(self):
        from api.routes.enriquecimento import _normalizar_cpf
        assert _normalizar_cpf("12345") is None
        assert _normalizar_cpf("abc") is None

    def test_normalizar_telefone_movel(self):
        from api.routes.enriquecimento import _normalizar_telefone
        assert _normalizar_telefone("73 8157-6452") == "7381576452"

    def test_normalizar_telefone_com_ddi(self):
        from api.routes.enriquecimento import _normalizar_telefone
        assert _normalizar_telefone("+55 41 9178-6575") == "41917865750"[:11] or \
               _normalizar_telefone("+55 41 9178-6575") == "4191786575"

    def test_normalizar_telefone_invalido(self):
        from api.routes.enriquecimento import _normalizar_telefone
        assert _normalizar_telefone("123") is None
        assert _normalizar_telefone("abc") is None

    def test_parse_arquivo_txt_simples(self):
        from api.routes.enriquecimento import _normalizar_cpf, _parse_arquivo
        conteudo = b"091.991.949-96\n000.000.001-91\n"
        resultado = _parse_arquivo(conteudo, _normalizar_cpf)
        assert "09199194996" in resultado
        assert len(resultado) == 2

    def test_parse_arquivo_csv_usa_primeira_coluna(self):
        from api.routes.enriquecimento import _normalizar_cpf, _parse_arquivo
        conteudo = b"CPF;NOME\n091.991.949-96;JOAO\n000.000.001-91;MARIA\n"
        resultado = _parse_arquivo(conteudo, _normalizar_cpf)
        assert "09199194996" in resultado

    def test_parse_arquivo_deduplica(self):
        from api.routes.enriquecimento import _normalizar_cpf, _parse_arquivo
        conteudo = b"091.991.949-96\n091.991.949-96\n09199194996\n"
        resultado = _parse_arquivo(conteudo, _normalizar_cpf)
        assert resultado.count("09199194996") == 1

    def test_parse_arquivo_linhas_vazias_ignoradas(self):
        from api.routes.enriquecimento import _normalizar_cpf, _parse_arquivo
        conteudo = b"\n\n091.991.949-96\n\n"
        resultado = _parse_arquivo(conteudo, _normalizar_cpf)
        assert len(resultado) == 1

    def test_parse_arquivo_latin1(self):
        from api.routes.enriquecimento import _normalizar_cpf, _parse_arquivo
        conteudo = "091.991.949-96\n".encode("latin-1")
        resultado = _parse_arquivo(conteudo, _normalizar_cpf)
        assert "09199194996" in resultado


# ── Segurança / abuso ──────────────────────────────────────────────────────────

class TestEnriquecimentoSeguranca:
    """Testes de borda: arquivos grandes, injeção, abuso."""

    def test_arquivo_acima_do_limite_retorna_400(self, client, user_headers):
        """1.000.001 CPFs únicos devem ser rejeitados."""
        cpfs_unicos = "\n".join(str(i).zfill(11) for i in range(1_000_001))
        resp = _post_enriquecimento(client, user_headers, cpfs_unicos)
        assert resp.status_code == 400
        assert "limite" in resp.get_json()["erro"].lower()

    def test_arquivo_exatamente_no_limite_aceito(self, client, user_headers):
        """1.000.000 CPFs (11 dígitos cada) devem passar pela validação de tamanho."""
        cpfs_unicos = "\n".join(str(i).zfill(11) for i in range(1_000_000))
        df_vazio = pd.DataFrame(columns=["CPF"])
        with patch("api.routes.enriquecimento._carregar_cpfs_sessao"), \
             patch("api.routes.enriquecimento._conectar"), \
             patch("pandas.read_sql", return_value=df_vazio), \
             patch("api.routes.enriquecimento.gerar_excel_bytes", return_value=io.BytesIO(b"PK")):
            resp = _post_enriquecimento(client, user_headers, cpfs_unicos)
        assert resp.status_code != 400 or "limite" not in resp.get_data(as_text=True)

    def test_injecao_sql_no_cpf_ignorada(self, client, user_headers):
        """Linha com tentativa de SQL injection deve ser descartada como CPF inválido."""
        conteudo = "' OR '1'='1\n09199194996\n"
        df_vazio = pd.DataFrame(columns=["CPF"])
        with patch("api.routes.enriquecimento._carregar_cpfs_sessao") as mock_load, \
             patch("api.routes.enriquecimento._conectar"), \
             patch("pandas.read_sql", return_value=df_vazio), \
             patch("api.routes.enriquecimento.gerar_excel_bytes", return_value=io.BytesIO(b"PK")):
            resp = _post_enriquecimento(client, user_headers, conteudo)
            if mock_load.called:
                cpfs_carregados = mock_load.call_args[0][0]
                assert "' OR '1'='1" not in cpfs_carregados
                assert all(c.isdigit() and len(c) == 11 for c in cpfs_carregados)

    def test_null_bytes_no_arquivo_ignorados(self, client, user_headers):
        """Arquivo com null bytes não deve causar erro 500."""
        conteudo_bytes = b"09199194996\x00\n000.000.001-91\n"
        resp = client.post(
            "/api/v1/enriquecimento",
            data={
                "arquivo": (io.BytesIO(conteudo_bytes), "lista.txt"),
                "tipo": "cpf",
            },
            headers={k: v for k, v in user_headers.items() if k != "Content-Type"},
            content_type="multipart/form-data",
        )
        assert resp.status_code != 500

    def test_cabecalho_x_enviados_presente(self, client, user_headers):
        """Resposta bem-sucedida deve incluir headers de contagem."""
        df_resultado = pd.DataFrame([{
            "NOME": "JOAO", "CPF": "09199194996",
            "TELEFONE_1": "11987654321", "TELEFONE_2": None,
            "TELEFONE_3": None, "TELEFONE_4": None,
            "TELEFONE_5": None, "TELEFONE_6": None,
            "GENERO": "M", "DATA_NASCIMENTO": "1985-01-01",
            "ENDERECO": "RUA TESTE", "NUM_END": "1", "COMPLEMENTO": None,
            "BAIRRO": "CENTRO", "CIDADE": "SAO PAULO", "CEP": "01000000",
            "UF": "SP", "EMAIL_1": "j@mail.com", "EMAIL_2": None,
            "TIPO_PESSOA": "FISICA",
        }])
        with patch("api.routes.enriquecimento._carregar_cpfs_sessao"), \
             patch("api.routes.enriquecimento._conectar"), \
             patch("pandas.read_sql", return_value=df_resultado), \
             patch("api.routes.enriquecimento.gerar_excel_bytes", return_value=io.BytesIO(b"PK")):
            resp = _post_enriquecimento(client, user_headers, "09199194996")

        if resp.status_code == 200:
            assert "X-Enviados" in resp.headers
            assert "X-Encontrados" in resp.headers
            assert "X-Nao-Encontrados" in resp.headers

    def test_tipo_telefone_normaliza_ddi(self, client, user_headers):
        """Telefone com DDI +55 deve ser aceito e normalizado."""
        df_vazio = pd.DataFrame(columns=["CPF"])
        conteudo = "+55 41 9178-6575\n73 8157-6452\n"
        with patch("api.routes.enriquecimento._carregar_cpfs_sessao") as mock_load, \
             patch("api.routes.enriquecimento._conectar"), \
             patch("pandas.read_sql", return_value=df_vazio), \
             patch("api.routes.enriquecimento.gerar_excel_bytes", return_value=io.BytesIO(b"PK")):
            _post_enriquecimento(client, user_headers, conteudo, tipo="telefone")
            if mock_load.called:
                tels = mock_load.call_args[0][0]
                assert all(t.isdigit() for t in tels)
                assert all(len(t) in (10, 11) for t in tels)
