"""
api/tests/test_db_logger.py
---------------------------
Testes unitários das funções de persistência de log e financeiro.

Cobre:
  - registrar_venda        → INSERT em acompanhamento_financeiro
  - registrar_log_consulta → INSERT em api_log_consultas (com tipo_lista e baixado)
  - extrair_campos_auth    → extração de identidade de API Key vs JWT

Estratégia de execução das threads
  As funções são fire-and-forget: disparam uma daemon thread e retornam.
  Para tornar os testes determinísticos, substituímos threading.Thread por
  uma versão que chama .join() antes de retornar — o target roda em thread
  real mas o teste espera ela terminar (timeout=5s máx).
"""

import threading
from unittest.mock import MagicMock, call, patch

import pytest


# ── Helper: torna threads síncronas nos testes ───────────────────────────────

_real_thread = threading.Thread


def _sync_thread(*args, **kwargs):
    """
    Substituto síncrono de threading.Thread.
    Executa o target imediatamente e retorna um objeto cujo .start() é no-op
    (o target já rodou).
    """
    t = _real_thread(*args, **kwargs)
    t.start()
    t.join(timeout=5)
    done = MagicMock()
    done.start = lambda: None   # db_logger chama .start() no objeto retornado
    return done


# ── Fixtures de conexão mockada ───────────────────────────────────────────────

@pytest.fixture
def mock_db():
    """
    Retorna (mock_connect, mock_conn, mock_cur) com a cadeia completa mockada:
      connect() → conn → cursor() → cur → execute() / commit() / close()
    """
    mock_cur = MagicMock()
    mock_conn = MagicMock()
    mock_conn.cursor.return_value = mock_cur
    mock_connect = MagicMock(return_value=mock_conn)
    return mock_connect, mock_conn, mock_cur


# ================================================================
# registrar_venda
# ================================================================

class TestRegistrarVenda:
    """
    Testa que registrar_venda monta o INSERT correto em
    acompanhamento_financeiro e o envia ao banco.
    """

    def test_venda_a_vista_insere_colunas_corretas(self, mock_db):
        """Venda à vista: parcelado=0, num_parcelas/valor_parcela devem ser NULL."""
        from api.utils.db_logger import registrar_venda

        mock_connect, mock_conn, mock_cur = mock_db

        with patch("mysql.connector.connect", mock_connect), \
             patch("threading.Thread", _sync_thread):
            registrar_venda(
                request_id="req-001",
                usuario_id=42,
                nome_cliente="Empresa Alpha",
                valor_lista=800.00,
                parcelado=False,
                num_parcelas=None,
                valor_parcela=None,
                registros_exportados=500,
            )

        mock_connect.assert_called_once()
        mock_cur.execute.assert_called_once()
        sql, params = mock_cur.execute.call_args[0]

        assert "acompanhamento_financeiro" in sql
        assert "INSERT INTO" in sql.upper()
        # posições dos parâmetros (ver db_logger.py: request_id, usuario_id,
        # nome_cliente, valor_lista, parcelado, num_parcelas, valor_parcela,
        # registros_exportados)
        assert params[0] == "req-001"
        assert params[1] == 42
        assert params[2] == "Empresa Alpha"
        assert params[3] == 800.00
        assert params[4] == 0       # parcelado=False → int(False) = 0
        assert params[5] is None    # num_parcelas
        assert params[6] is None    # valor_parcela
        assert params[7] == 500
        mock_conn.commit.assert_called_once()

    def test_venda_parcelada_insere_parcelas(self, mock_db):
        """Venda parcelada: num_parcelas e valor_parcela preenchidos."""
        from api.utils.db_logger import registrar_venda

        mock_connect, mock_conn, mock_cur = mock_db

        with patch("mysql.connector.connect", mock_connect), \
             patch("threading.Thread", _sync_thread):
            registrar_venda(
                request_id="req-002",
                usuario_id=None,
                nome_cliente="Empresa Beta",
                valor_lista=900.00,
                parcelado=True,
                num_parcelas=3,
                valor_parcela=300.00,
                registros_exportados=200,
            )

        sql, params = mock_cur.execute.call_args[0]
        assert params[4] == 1       # parcelado=True → 1
        assert params[5] == 3       # num_parcelas
        assert params[6] == 300.00  # valor_parcela

    def test_usuario_id_none_quando_api_key(self, mock_db):
        """Autenticação via API Key não tem usuario_id — deve gravar NULL."""
        from api.utils.db_logger import registrar_venda

        mock_connect, mock_conn, mock_cur = mock_db

        with patch("mysql.connector.connect", mock_connect), \
             patch("threading.Thread", _sync_thread):
            registrar_venda(
                request_id="req-003",
                usuario_id=None,     # API Key não tem FK de usuário
                nome_cliente="Empresa Gamma",
                valor_lista=400.00,
                parcelado=False,
                registros_exportados=100,
            )

        _, params = mock_cur.execute.call_args[0]
        assert params[1] is None

    def test_falha_no_banco_nao_propaga_excecao(self):
        """
        Fire-and-forget: erro de conexão deve ser silenciado (log warning),
        nunca lançado para o chamador.
        """
        from api.utils.db_logger import registrar_venda

        with patch("mysql.connector.connect", side_effect=Exception("DB offline")), \
             patch("threading.Thread", _sync_thread):
            # Não deve levantar exceção
            registrar_venda(
                request_id="req-fail",
                nome_cliente="Empresa X",
                valor_lista=100.00,
                parcelado=False,
            )


# ================================================================
# registrar_log_consulta  (foco: campos tipo_lista e baixado)
# ================================================================

class TestRegistrarLogConsulta:
    """
    Testa que registrar_log_consulta persiste tipo_lista e baixado corretamente.
    Esses campos foram adicionados na feature de metadados de exportação.
    """

    def test_log_venda_baixada_insere_tipo_lista_e_baixado(self, mock_db):
        """Exportação de venda bem-sucedida: tipo_lista='venda', baixado=1."""
        from api.utils.db_logger import registrar_log_consulta

        mock_connect, mock_conn, mock_cur = mock_db

        with patch("mysql.connector.connect", mock_connect), \
             patch("threading.Thread", _sync_thread):
            registrar_log_consulta(
                request_id="req-log-001",
                endpoint="gerar",
                usuario_id=7,
                key_id=None,
                nome_usuario="martina",
                role="user",
                ip="127.0.0.1",
                quantidade_retornada=300,
                tipo_lista="venda",
                baixado=True,
                status_http=200,
            )

        sql, params = mock_cur.execute.call_args[0]
        assert "api_log_consultas" in sql
        assert "tipo_lista" in sql
        assert "baixado" in sql
        # tipo_lista está na posição -2 (penúltima), baixado na última
        assert params[-2] == "venda"
        assert params[-1] == 1          # baixado=True → int(True) = 1
        mock_conn.commit.assert_called_once()

    def test_log_consulta_nao_baixada_insere_baixado_zero(self, mock_db):
        """Consulta de disponibilidade sem download: baixado=0."""
        from api.utils.db_logger import registrar_log_consulta

        mock_connect, mock_conn, mock_cur = mock_db

        with patch("mysql.connector.connect", mock_connect), \
             patch("threading.Thread", _sync_thread):
            registrar_log_consulta(
                request_id="req-log-002",
                endpoint="contagem",
                tipo_lista="consulta_disponibilidade",
                baixado=False,
                status_http=200,
            )

        _, params = mock_cur.execute.call_args[0]
        assert params[-2] == "consulta_disponibilidade"
        assert params[-1] == 0          # baixado=False → 0

    def test_log_sem_tipo_lista_insere_none(self, mock_db):
        """Endpoints que não têm tipo_lista (ex: /preview) devem gravar NULL."""
        from api.utils.db_logger import registrar_log_consulta

        mock_connect, mock_conn, mock_cur = mock_db

        with patch("mysql.connector.connect", mock_connect), \
             patch("threading.Thread", _sync_thread):
            registrar_log_consulta(
                request_id="req-log-003",
                endpoint="preview",
                status_http=200,
            )

        _, params = mock_cur.execute.call_args[0]
        assert params[-2] is None   # tipo_lista
        assert params[-1] is None   # baixado

    def test_falha_no_banco_nao_propaga_excecao(self):
        """Erro de DB no log nunca bloqueia a resposta da API."""
        from api.utils.db_logger import registrar_log_consulta

        with patch("mysql.connector.connect", side_effect=Exception("timeout")), \
             patch("threading.Thread", _sync_thread):
            registrar_log_consulta(
                request_id="req-log-fail",
                endpoint="gerar",
                tipo_lista="venda",
                baixado=True,
                status_http=200,
            )


# ================================================================
# extrair_campos_auth
# ================================================================

class TestExtrairCamposAuth:
    """
    Testa a extração de identidade do contexto de autenticação.
    Garante que API Key e JWT produzem tuplas distintas.
    """

    def setup_method(self):
        from api.utils.db_logger import extrair_campos_auth
        self.extrair = extrair_campos_auth

    def test_api_key_retorna_key_id_e_usuario_id_none(self):
        """API Key não tem FK de usuário — usuario_id deve ser None."""
        auth = {
            "auth_method": "api_key",
            "subject": "lspf_abc123",
            "key_nome": "Chave Teste",
            "user_id": None,
        }
        key_id, nome_usuario, usuario_id = self.extrair(auth)
        assert key_id == "lspf_abc123"
        assert nome_usuario == "Chave Teste"
        assert usuario_id is None

    def test_jwt_retorna_none_key_id_e_usuario_id(self):
        """JWT tem user_id do DB — key_id deve ser None."""
        auth = {
            "auth_method": "jwt",
            "subject": "martina",
            "user_id": 5,
        }
        key_id, nome_usuario, usuario_id = self.extrair(auth)
        assert key_id is None
        assert nome_usuario == "martina"
        assert usuario_id == 5

    def test_jwt_sem_user_id_retorna_none(self):
        """JWT criado sem extra_claims (ex: token de teste antigo) → usuario_id None."""
        auth = {
            "auth_method": "jwt",
            "subject": "usuario_legado",
        }
        _, _, usuario_id = self.extrair(auth)
        assert usuario_id is None
