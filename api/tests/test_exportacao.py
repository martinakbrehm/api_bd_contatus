"""
api/tests/test_exportacao.py
----------------------------
Testes dos metadados de exportação obrigatórios introduzidos nas rotas de download.

Cobre:
  - Validação do schema (validar_exportacao)            — testes unitários puros
  - POST /api/v1/consulta/gerar                         — token + tipo_lista
  - POST /api/v1/consulta/download                      — filtro + tipo_lista
  - POST /api/v1/consulta/job/<id>/xlsx                 — job assíncrono (mudou de GET → POST)
  - POST /api/v1/enriquecimento                         — form-data + tipo_lista

Estratégia de mock
  - Banco de dados   : nunca acessado (todas as funções de DB são mockadas)
  - registrar_log_consulta / registrar_venda : mockadas (operações fire-and-forget)
  - _pipeline_consulta / pd.read_sql : mockadas com DataFrames mínimos
  - gerar_xlsx / gerar_excel_bytes   : retornam BytesIO fake
  - _DIR_TEMP   : redirecionado para tmp_path nos testes que necessitam de parquet real
"""

import io
import uuid
from unittest.mock import MagicMock, patch

import pandas as pd
import pytest


# ================================================================
# Helpers
# ================================================================

def _df_fake() -> pd.DataFrame:
    """DataFrame mínimo válido para simular resultado de consulta."""
    return pd.DataFrame([{"CPF": "12345678901", "NOME": "Teste"}])


def _xlsx_fake() -> io.BytesIO:
    return io.BytesIO(b"PK\x03\x04fake_xlsx_content")


# ================================================================
# SCHEMA — validar_exportacao
# ================================================================

class TestValidarExportacao:
    """
    Testes unitários da função de validação de metadados de exportação.
    Não dependem de Flask nem de banco de dados.
    """

    def setup_method(self):
        from api.routes.consulta.schema import ValidationError, validar_exportacao
        self.validar = validar_exportacao
        self.ValidationError = ValidationError

    # ── tipo_lista obrigatório ───────────────────────────────────────────────

    def test_sem_tipo_lista_levanta_erro(self):
        """Corpo vazio deve falhar com menção a tipo_lista."""
        with pytest.raises(self.ValidationError) as exc:
            self.validar({})
        assert any("tipo_lista" in e for e in exc.value.erros)

    def test_tipo_lista_invalido_levanta_erro(self):
        """Valores fora do conjunto permitido devem ser rejeitados."""
        with pytest.raises(self.ValidationError) as exc:
            self.validar({"tipo_lista": "cobranca"})
        assert any("tipo_lista" in e for e in exc.value.erros)

    # ── tipos sem campos financeiros ─────────────────────────────────────────

    def test_consulta_disponibilidade_valido(self):
        """Tipo consulta_disponibilidade não exige campos financeiros."""
        r = self.validar({"tipo_lista": "consulta_disponibilidade"})
        assert r["tipo_lista"] == "consulta_disponibilidade"
        assert r["valor_lista"] is None
        assert r["nome_cliente"] is None

    def test_teste_valido(self):
        """Tipo teste não exige campos financeiros."""
        r = self.validar({"tipo_lista": "teste"})
        assert r["tipo_lista"] == "teste"
        assert r["valor_lista"] is None

    # ── venda — campos obrigatórios ──────────────────────────────────────────

    def test_venda_sem_nome_cliente_levanta_erro(self):
        with pytest.raises(self.ValidationError) as exc:
            self.validar({"tipo_lista": "venda", "valor_lista": 500})
        assert any("nome_cliente" in e for e in exc.value.erros)

    def test_venda_sem_valor_lista_levanta_erro(self):
        with pytest.raises(self.ValidationError) as exc:
            self.validar({"tipo_lista": "venda", "nome_cliente": "Empresa X"})
        assert any("valor_lista" in e for e in exc.value.erros)

    def test_venda_valor_lista_negativo_levanta_erro(self):
        with pytest.raises(self.ValidationError) as exc:
            self.validar({
                "tipo_lista": "venda",
                "nome_cliente": "Empresa X",
                "valor_lista": -100,
                "parcelado": False,
            })
        assert any("valor_lista" in e for e in exc.value.erros)

    def test_venda_nome_cliente_muito_longo_levanta_erro(self):
        with pytest.raises(self.ValidationError) as exc:
            self.validar({
                "tipo_lista": "venda",
                "nome_cliente": "A" * 151,
                "valor_lista": 500,
                "parcelado": False,
            })
        assert any("nome_cliente" in e for e in exc.value.erros)

    def test_venda_parcelado_sem_num_parcelas_levanta_erro(self):
        with pytest.raises(self.ValidationError) as exc:
            self.validar({
                "tipo_lista": "venda",
                "nome_cliente": "Empresa X",
                "valor_lista": 500,
                "parcelado": True,
            })
        assert any("num_parcelas" in e for e in exc.value.erros)

    def test_venda_parcelado_num_parcelas_menor_que_2_levanta_erro(self):
        with pytest.raises(self.ValidationError) as exc:
            self.validar({
                "tipo_lista": "venda",
                "nome_cliente": "Empresa X",
                "valor_lista": 500,
                "parcelado": True,
                "num_parcelas": 1,
            })
        assert any("num_parcelas" in e for e in exc.value.erros)

    def test_venda_a_vista_retorna_campos_corretos(self):
        r = self.validar({
            "tipo_lista": "venda",
            "nome_cliente": "Empresa X",
            "valor_lista": 800.00,
            "parcelado": False,
        })
        assert r["tipo_lista"] == "venda"
        assert r["nome_cliente"] == "Empresa X"
        assert r["valor_lista"] == 800.00
        assert r["parcelado"] is False
        assert r["num_parcelas"] is None

    def test_venda_parcelada_retorna_campos_corretos(self):
        r = self.validar({
            "tipo_lista": "venda",
            "nome_cliente": "Empresa Y",
            "valor_lista": 900.00,
            "parcelado": True,
            "num_parcelas": 3,
            "valor_parcela": 300.00,
        })
        assert r["num_parcelas"] == 3
        assert r["valor_parcela"] == 300.00

    def test_parcelado_como_string_true(self):
        """
        Aceita 'true' como string — necessário para campos de formulário
        multipart onde todos os valores chegam como texto.
        """
        r = self.validar({
            "tipo_lista": "venda",
            "nome_cliente": "Empresa X",
            "valor_lista": "500.00",
            "parcelado": "true",
            "num_parcelas": "3",
        })
        assert r["parcelado"] is True
        assert r["num_parcelas"] == 3
        assert r["valor_lista"] == 500.00


# ================================================================
# POST /consulta/gerar
# ================================================================

# UUID4 válido fixo para toda a classe (gerado uma vez ao importar o módulo)
_GERAR_TOKEN = str(uuid.uuid4())


class TestGerarExportacao:
    """
    Testes do endpoint POST /api/v1/consulta/gerar.

    O endpoint:
      1. Valida o UUID do token
      2. Valida metadados de exportação (tipo_lista etc.)
      3. Lê o parquet gerado em /consulta e serve como XLSX
    """

    # ── rejeições por validação ──────────────────────────────────────────────

    def test_sem_tipo_lista_retorna_400(self, client, user_headers):
        """token válido mas sem tipo_lista deve ser rejeitado."""
        resp = client.post(
            "/api/v1/consulta/gerar",
            json={"resultado_token": _GERAR_TOKEN},
            headers=user_headers,
        )
        assert resp.status_code == 400
        body = resp.get_json()
        assert "exportação" in body["erro"].lower()

    def test_tipo_lista_invalido_retorna_400(self, client, user_headers):
        resp = client.post(
            "/api/v1/consulta/gerar",
            json={"resultado_token": _GERAR_TOKEN, "tipo_lista": "invalido"},
            headers=user_headers,
        )
        assert resp.status_code == 400

    def test_venda_sem_nome_cliente_retorna_400(self, client, user_headers):
        resp = client.post(
            "/api/v1/consulta/gerar",
            json={
                "resultado_token": _GERAR_TOKEN,
                "tipo_lista": "venda",
                "valor_lista": 500,
            },
            headers=user_headers,
        )
        assert resp.status_code == 400

    def test_token_uuid_invalido_retorna_400(self, client, user_headers):
        """UUID malformado é rejeitado antes mesmo de checar tipo_lista."""
        resp = client.post(
            "/api/v1/consulta/gerar",
            json={"resultado_token": "nao-e-uuid", "tipo_lista": "teste"},
            headers=user_headers,
        )
        assert resp.status_code == 400

    def test_sem_autenticacao_retorna_401(self, client):
        resp = client.post(
            "/api/v1/consulta/gerar",
            json={"resultado_token": _GERAR_TOKEN, "tipo_lista": "teste"},
        )
        assert resp.status_code == 401

    # ── fluxo feliz: tipo=teste ──────────────────────────────────────────────

    @patch("api.routes.consulta.registrar_log_consulta")
    @patch("api.routes.consulta.log_data_access")
    @patch("api.routes.consulta.gerar_xlsx")
    def test_tipo_teste_baixa_xlsx(
        self, mock_xlsx, mock_log_access, mock_log_db,
        client, user_headers, tmp_path
    ):
        """
        tipo_lista=teste sem dados financeiros deve retornar XLSX com sucesso.
        Escreve o parquet em tmp_path e redireciona _DIR_TEMP.
        """
        mock_xlsx.return_value = _xlsx_fake()
        _df_fake().to_parquet(tmp_path / f"{_GERAR_TOKEN}.parquet", index=False)

        with patch("api.routes.consulta._DIR_TEMP", tmp_path):
            resp = client.post(
                "/api/v1/consulta/gerar",
                json={"resultado_token": _GERAR_TOKEN, "tipo_lista": "teste"},
                headers=user_headers,
            )
        assert resp.status_code == 200
        assert "spreadsheetml" in resp.content_type

    # ── fluxo feliz: tipo=venda chama registrar_venda ────────────────────────

    @patch("api.routes.consulta.registrar_venda")
    @patch("api.routes.consulta.registrar_log_consulta")
    @patch("api.routes.consulta.log_data_access")
    @patch("api.routes.consulta.gerar_xlsx")
    def test_venda_chama_registrar_venda(
        self, mock_xlsx, mock_log_access, mock_log_db, mock_venda,
        client, user_headers, tmp_path
    ):
        """
        tipo_lista=venda com campos financeiros completos deve:
          - Retornar XLSX
          - Chamar registrar_venda com os dados corretos
        """
        mock_xlsx.return_value = _xlsx_fake()
        _df_fake().to_parquet(tmp_path / f"{_GERAR_TOKEN}.parquet", index=False)

        with patch("api.routes.consulta._DIR_TEMP", tmp_path):
            resp = client.post(
                "/api/v1/consulta/gerar",
                json={
                    "resultado_token": _GERAR_TOKEN,
                    "tipo_lista": "venda",
                    "nome_cliente": "Empresa X",
                    "valor_lista": 800.00,
                    "parcelado": False,
                },
                headers=user_headers,
            )
        assert resp.status_code == 200
        mock_venda.assert_called_once()
        kwargs = mock_venda.call_args.kwargs
        assert kwargs["nome_cliente"] == "Empresa X"
        assert kwargs["valor_lista"] == 800.00

    # ── tipo=teste NÃO chama registrar_venda ────────────────────────────────

    @patch("api.routes.consulta.registrar_venda")
    @patch("api.routes.consulta.registrar_log_consulta")
    @patch("api.routes.consulta.log_data_access")
    @patch("api.routes.consulta.gerar_xlsx")
    def test_teste_nao_chama_registrar_venda(
        self, mock_xlsx, mock_log_access, mock_log_db, mock_venda,
        client, user_headers, tmp_path
    ):
        mock_xlsx.return_value = _xlsx_fake()
        _df_fake().to_parquet(tmp_path / f"{_GERAR_TOKEN}.parquet", index=False)

        with patch("api.routes.consulta._DIR_TEMP", tmp_path):
            resp = client.post(
                "/api/v1/consulta/gerar",
                json={"resultado_token": _GERAR_TOKEN, "tipo_lista": "teste"},
                headers=user_headers,
            )
        assert resp.status_code == 200
        mock_venda.assert_not_called()


# ================================================================
# POST /consulta/download
# ================================================================

_FILTRO_BASE = {"ufs": ["SP"], "cidades": ["SAO PAULO"], "quantidade": 10}

_PIPELINE_RESULTADO = {
    "df_saida": _df_fake(),
    "cols_existentes": ["CPF", "NOME"],
    "total_bruto_buscado": 1,
    "total_final": 1,
    "alguma_esgotou": False,
    "duracao_s": 0.05,
    "cache_hit": False,
}


class TestDownloadExportacao:
    """
    Testes do endpoint POST /api/v1/consulta/download.

    O endpoint combina filtros de consulta + metadados de exportação
    num único request.
    """

    # ── rejeições por validação de exportação ────────────────────────────────

    def test_sem_tipo_lista_retorna_400(self, client, user_headers):
        """Filtro válido mas sem tipo_lista deve ser rejeitado."""
        resp = client.post(
            "/api/v1/consulta/download",
            json=_FILTRO_BASE,
            headers=user_headers,
        )
        assert resp.status_code == 400
        body = resp.get_json()
        assert "exportação" in body["erro"].lower()

    def test_venda_sem_nome_cliente_retorna_400(self, client, user_headers):
        resp = client.post(
            "/api/v1/consulta/download",
            json={**_FILTRO_BASE, "tipo_lista": "venda", "valor_lista": 500},
            headers=user_headers,
        )
        assert resp.status_code == 400

    def test_filtro_invalido_retorna_400(self, client, user_headers):
        """Sem UF/cidades mas com tipo_lista — falha na validação de filtros."""
        resp = client.post(
            "/api/v1/consulta/download",
            json={"tipo_lista": "teste"},
            headers=user_headers,
        )
        assert resp.status_code == 400

    # ── fluxo feliz: tipo=venda ──────────────────────────────────────────────

    @patch("api.routes.consulta.registrar_venda")
    @patch("api.routes.consulta.registrar_log_consulta")
    @patch("api.routes.consulta.log_data_access")
    @patch("api.routes.consulta._pipeline_consulta")
    @patch("api.routes.consulta.gerar_xlsx")
    def test_venda_completa_retorna_xlsx_e_registra_venda(
        self, mock_xlsx, mock_pipeline, mock_log_access, mock_log_db, mock_venda,
        client, user_headers
    ):
        """
        Venda completa deve retornar XLSX e registrar a venda no banco.
        """
        mock_xlsx.return_value = _xlsx_fake()
        mock_pipeline.return_value = _PIPELINE_RESULTADO

        resp = client.post(
            "/api/v1/consulta/download",
            json={
                **_FILTRO_BASE,
                "tipo_lista": "venda",
                "nome_cliente": "Empresa Z",
                "valor_lista": 600.00,
                "parcelado": False,
            },
            headers=user_headers,
        )
        assert resp.status_code == 200
        assert "spreadsheetml" in resp.content_type
        mock_venda.assert_called_once()

    # ── tipo=consulta_disponibilidade não chama registrar_venda ─────────────

    @patch("api.routes.consulta.registrar_venda")
    @patch("api.routes.consulta.registrar_log_consulta")
    @patch("api.routes.consulta.log_data_access")
    @patch("api.routes.consulta._pipeline_consulta")
    @patch("api.routes.consulta.gerar_xlsx")
    def test_consulta_disponibilidade_nao_registra_venda(
        self, mock_xlsx, mock_pipeline, mock_log_access, mock_log_db, mock_venda,
        client, user_headers
    ):
        mock_xlsx.return_value = _xlsx_fake()
        mock_pipeline.return_value = _PIPELINE_RESULTADO

        resp = client.post(
            "/api/v1/consulta/download",
            json={**_FILTRO_BASE, "tipo_lista": "consulta_disponibilidade"},
            headers=user_headers,
        )
        assert resp.status_code == 200
        mock_venda.assert_not_called()


# ================================================================
# POST /consulta/job/<id>/xlsx  (era GET — agora POST)
# ================================================================

# job_id: 32 dígitos hex (uuid4().hex)
_JOB_ID = uuid.uuid4().hex


class TestJobXlsxExportacao:
    """
    Testes do endpoint POST /api/v1/consulta/job/<id>/xlsx.

    Mudança importante: o método HTTP mudou de GET para POST para
    suportar o body com tipo_lista.
    """

    # ── GET deve retornar 405 (método não permitido) ─────────────────────────

    def test_get_retorna_405(self, client, user_headers):
        """Confirma que o endpoint não aceita mais GET."""
        resp = client.get(
            f"/api/v1/consulta/job/{_JOB_ID}/xlsx",
            headers=user_headers,
        )
        assert resp.status_code == 405

    # ── rejeições por validação ──────────────────────────────────────────────

    def test_sem_tipo_lista_retorna_400(self, client, user_headers):
        resp = client.post(
            f"/api/v1/consulta/job/{_JOB_ID}/xlsx",
            json={},
            headers=user_headers,
        )
        assert resp.status_code == 400

    def test_job_id_invalido_retorna_400(self, client, user_headers):
        """job_id que não seja 32 hex chars deve ser rejeitado."""
        resp = client.post(
            "/api/v1/consulta/job/id-invalido/xlsx",
            json={"tipo_lista": "teste"},
            headers=user_headers,
        )
        assert resp.status_code == 400

    def test_job_nao_concluido_retorna_409(self, client, user_headers):
        """Job ainda em processamento deve retornar 409."""
        with patch("api.routes.consulta.obter_job") as mock_job:
            mock_job.return_value = {"status": "processando"}
            resp = client.post(
                f"/api/v1/consulta/job/{_JOB_ID}/xlsx",
                json={"tipo_lista": "teste"},
                headers=user_headers,
            )
        assert resp.status_code == 409

    def test_job_inexistente_retorna_404(self, client, user_headers):
        with patch("api.routes.consulta.obter_job") as mock_job:
            mock_job.return_value = None
            resp = client.post(
                f"/api/v1/consulta/job/{_JOB_ID}/xlsx",
                json={"tipo_lista": "teste"},
                headers=user_headers,
            )
        assert resp.status_code == 404

    # ── fluxo feliz: venda chama registrar_venda ─────────────────────────────

    @patch("api.routes.consulta.registrar_venda")
    @patch("api.routes.consulta.registrar_log_consulta")
    @patch("api.routes.consulta.log_data_access")
    @patch("api.routes.consulta.obter_job")
    @patch("api.routes.consulta.gerar_xlsx")
    def test_venda_chama_registrar_venda(
        self, mock_xlsx, mock_job, mock_log_access, mock_log_db, mock_venda,
        client, user_headers, tmp_path
    ):
        mock_xlsx.return_value = _xlsx_fake()
        mock_job.return_value = {"status": "concluido", "resultado": {}}
        _df_fake().to_parquet(tmp_path / f"{_JOB_ID}.parquet", index=False)

        with patch("api.routes.consulta._DIR_TEMP", tmp_path):
            resp = client.post(
                f"/api/v1/consulta/job/{_JOB_ID}/xlsx",
                json={
                    "tipo_lista": "venda",
                    "nome_cliente": "Empresa W",
                    "valor_lista": 400.00,
                    "parcelado": False,
                },
                headers=user_headers,
            )
        assert resp.status_code == 200
        mock_venda.assert_called_once()
        assert mock_venda.call_args.kwargs["nome_cliente"] == "Empresa W"

    @patch("api.routes.consulta.registrar_venda")
    @patch("api.routes.consulta.registrar_log_consulta")
    @patch("api.routes.consulta.log_data_access")
    @patch("api.routes.consulta.obter_job")
    @patch("api.routes.consulta.gerar_xlsx")
    def test_teste_nao_chama_registrar_venda(
        self, mock_xlsx, mock_job, mock_log_access, mock_log_db, mock_venda,
        client, user_headers, tmp_path
    ):
        mock_xlsx.return_value = _xlsx_fake()
        mock_job.return_value = {"status": "concluido", "resultado": {}}
        _df_fake().to_parquet(tmp_path / f"{_JOB_ID}.parquet", index=False)

        with patch("api.routes.consulta._DIR_TEMP", tmp_path):
            resp = client.post(
                f"/api/v1/consulta/job/{_JOB_ID}/xlsx",
                json={"tipo_lista": "teste"},
                headers=user_headers,
            )
        assert resp.status_code == 200
        mock_venda.assert_not_called()


# ================================================================
# POST /enriquecimento  (multipart/form-data)
# ================================================================

def _arquivo_fake(conteudo: str = "12345678901\n") -> tuple:
    """Tupla (stream, filename) para upload em multipart/form-data."""
    return (io.BytesIO(conteudo.encode()), "lista.txt")


class TestEnriquecimentoExportacao:
    """
    Testes do endpoint POST /api/v1/enriquecimento com validação de exportação.

    Difere das rotas de consulta por usar multipart/form-data em vez de JSON.
    O tipo_lista é um campo de formulário.
    """

    def _headers_sem_content_type(self, user_headers: dict) -> dict:
        """Remove Content-Type para deixar o Flask definir boundary do multipart."""
        return {k: v for k, v in user_headers.items() if k != "Content-Type"}

    # ── rejeições por validação de exportação ────────────────────────────────

    def test_sem_tipo_lista_retorna_400(self, client, user_headers):
        """Formulário sem tipo_lista deve ser rejeitado antes de checar arquivo."""
        headers = self._headers_sem_content_type(user_headers)
        resp = client.post(
            "/api/v1/enriquecimento",
            data={"tipo": "cpf"},
            content_type="multipart/form-data",
            headers=headers,
        )
        assert resp.status_code == 400
        assert "exportação" in resp.get_json()["erro"].lower()

    def test_venda_sem_nome_cliente_retorna_400(self, client, user_headers):
        headers = self._headers_sem_content_type(user_headers)
        resp = client.post(
            "/api/v1/enriquecimento",
            data={"tipo": "cpf", "tipo_lista": "venda", "valor_lista": "500"},
            content_type="multipart/form-data",
            headers=headers,
        )
        assert resp.status_code == 400

    def test_tipo_lista_valido_mas_sem_arquivo_retorna_400(self, client, user_headers):
        """
        tipo_lista=teste é válido, mas arquivo ausente causa erro de negócio
        (não de exportação). Verifica que a mensagem de erro menciona 'arquivo'.
        """
        headers = self._headers_sem_content_type(user_headers)
        resp = client.post(
            "/api/v1/enriquecimento",
            data={"tipo": "cpf", "tipo_lista": "teste"},
            content_type="multipart/form-data",
            headers=headers,
        )
        assert resp.status_code == 400
        assert "arquivo" in resp.get_json()["erro"].lower()

    # ── fluxo feliz: tipo=venda chama registrar_venda ────────────────────────

    @patch("api.routes.enriquecimento.registrar_venda")
    @patch("api.routes.enriquecimento.registrar_log_consulta")
    @patch("api.routes.enriquecimento.log_data_access")
    @patch("api.routes.enriquecimento._carregar_cpfs_sessao")
    @patch("api.routes.enriquecimento._conectar")
    @patch("pandas.read_sql")
    @patch("api.routes.enriquecimento.gerar_excel_bytes")
    def test_venda_chama_registrar_venda(
        self, mock_excel, mock_read_sql, mock_conectar,
        mock_carregar, mock_log_access, mock_log_db, mock_venda,
        client, user_headers
    ):
        """
        Enriquecimento com tipo_lista=venda e campos financeiros completos deve:
          - Retornar XLSX
          - Chamar registrar_venda com nome_cliente correto
        """
        mock_excel.return_value = _xlsx_fake()
        mock_read_sql.return_value = _df_fake()
        mock_conectar.return_value = MagicMock()

        headers = self._headers_sem_content_type(user_headers)
        resp = client.post(
            "/api/v1/enriquecimento",
            data={
                "tipo": "cpf",
                "tipo_lista": "venda",
                "nome_cliente": "Empresa Q",
                "valor_lista": "300.00",
                "parcelado": "false",
                "arquivo": _arquivo_fake(),
            },
            content_type="multipart/form-data",
            headers=headers,
        )
        assert resp.status_code == 200
        mock_venda.assert_called_once()
        assert mock_venda.call_args.kwargs["nome_cliente"] == "Empresa Q"

    # ── fluxo feliz: tipo=teste NÃO chama registrar_venda ───────────────────

    @patch("api.routes.enriquecimento.registrar_venda")
    @patch("api.routes.enriquecimento.registrar_log_consulta")
    @patch("api.routes.enriquecimento.log_data_access")
    @patch("api.routes.enriquecimento._carregar_cpfs_sessao")
    @patch("api.routes.enriquecimento._conectar")
    @patch("pandas.read_sql")
    @patch("api.routes.enriquecimento.gerar_excel_bytes")
    def test_teste_nao_chama_registrar_venda(
        self, mock_excel, mock_read_sql, mock_conectar,
        mock_carregar, mock_log_access, mock_log_db, mock_venda,
        client, user_headers
    ):
        mock_excel.return_value = _xlsx_fake()
        mock_read_sql.return_value = _df_fake()
        mock_conectar.return_value = MagicMock()

        headers = self._headers_sem_content_type(user_headers)
        resp = client.post(
            "/api/v1/enriquecimento",
            data={
                "tipo": "cpf",
                "tipo_lista": "teste",
                "arquivo": _arquivo_fake(),
            },
            content_type="multipart/form-data",
            headers=headers,
        )
        assert resp.status_code == 200
        mock_venda.assert_not_called()
