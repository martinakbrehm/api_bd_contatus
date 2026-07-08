"""
test_alta_renda.py
------------------
Testes unitários de alta_renda.buscar_bairros().

DB é sempre mockado — sem conexão real.
"""

import time
from unittest.mock import MagicMock, patch

import pytest


@pytest.fixture(autouse=True)
def _limpar_cache():
    from api.utils.alta_renda import limpar_cache
    limpar_cache()
    yield
    limpar_cache()


def _mock_conn(bairros: list[str]):
    """Cria mock de conexão MySQL que retorna bairros."""
    conn = MagicMock()
    cur = MagicMock()
    cur.fetchall.return_value = [(b,) for b in bairros]
    conn.cursor.return_value = cur
    return conn


# ── Retorno correto ───────────────────────────────────────────────────────────

class TestRetorno:

    def test_retorna_lista_de_strings(self):
        from api.utils.alta_renda import buscar_bairros
        with patch("api.utils.alta_renda.mysql.connector.connect", return_value=_mock_conn(["JARDIM EUROPA", "ITAIM BIBI"])):
            result = buscar_bairros("SP", "SAO PAULO")
        assert result == ["JARDIM EUROPA", "ITAIM BIBI"]

    def test_retorna_vazio_sem_bairros_mapeados(self):
        from api.utils.alta_renda import buscar_bairros
        with patch("api.utils.alta_renda.mysql.connector.connect", return_value=_mock_conn([])):
            result = buscar_bairros("AM", "MANAUS")
        assert result == []

    def test_uf_e_cidade_em_maiusculo_na_query(self):
        from api.utils.alta_renda import buscar_bairros
        conn = _mock_conn([])
        with patch("api.utils.alta_renda.mysql.connector.connect", return_value=conn):
            buscar_bairros("sp", "sao paulo")
        # Verifica que a query usou ("SP", "SAO PAULO")
        call_args = conn.cursor.return_value.execute.call_args[0]
        params = call_args[1]
        assert params == ("SP", "SAO PAULO")


# ── Falha de conexão ──────────────────────────────────────────────────────────

class TestFalhaConexao:

    def test_excecao_na_conexao_retorna_vazio(self):
        from api.utils.alta_renda import buscar_bairros
        with patch("api.utils.alta_renda.mysql.connector.connect", side_effect=Exception("Connection refused")):
            result = buscar_bairros("SP", "SAO PAULO")
        assert result == []

    def test_excecao_no_cursor_retorna_vazio(self):
        from api.utils.alta_renda import buscar_bairros
        conn = MagicMock()
        conn.cursor.return_value.execute.side_effect = Exception("Table not found")
        with patch("api.utils.alta_renda.mysql.connector.connect", return_value=conn):
            result = buscar_bairros("SP", "SAO PAULO")
        assert result == []


# ── Cache ─────────────────────────────────────────────────────────────────────

class TestCache:

    def test_segunda_chamada_usa_cache(self):
        from api.utils.alta_renda import buscar_bairros
        with patch("api.utils.alta_renda.mysql.connector.connect", return_value=_mock_conn(["JARDIM EUROPA"])) as mock_connect:
            buscar_bairros("SP", "SAO PAULO")
            buscar_bairros("SP", "SAO PAULO")
        assert mock_connect.call_count == 1

    def test_cache_e_por_chave_uf_cidade(self):
        """Cache distingue (SP, SAO PAULO) de (RJ, RIO DE JANEIRO)."""
        from api.utils.alta_renda import buscar_bairros
        with patch("api.utils.alta_renda.mysql.connector.connect", return_value=_mock_conn(["B1"])) as mock_connect:
            buscar_bairros("SP", "SAO PAULO")
            buscar_bairros("RJ", "RIO DE JANEIRO")
        assert mock_connect.call_count == 2

    def test_cache_expirado_busca_novamente(self):
        from api.utils.alta_renda import buscar_bairros
        import api.utils.alta_renda as _ar
        with patch("api.utils.alta_renda.mysql.connector.connect", return_value=_mock_conn(["JARDIM EUROPA"])) as mock_connect:
            buscar_bairros("SP", "SAO PAULO")
            # Força expiração do cache
            _ar._CACHE_TS[("SP", "SAO PAULO")] = time.monotonic() - _ar._TTL - 1
            buscar_bairros("SP", "SAO PAULO")
        assert mock_connect.call_count == 2

    def test_limpar_cache_forca_reconsulta(self):
        from api.utils.alta_renda import buscar_bairros, limpar_cache
        with patch("api.utils.alta_renda.mysql.connector.connect", return_value=_mock_conn(["B1"])) as mock_connect:
            buscar_bairros("SP", "SAO PAULO")
            limpar_cache()
            buscar_bairros("SP", "SAO PAULO")
        assert mock_connect.call_count == 2
