"""
test_cache.py
-------------
Testes unitários de api/utils/cache.py.

Redis é sempre mockado — nenhuma conexão real.
"""

import io
import json
from unittest.mock import MagicMock, patch

import pandas as pd
import pytest


# ── Fixtures ──────────────────────────────────────────────────────────────────

@pytest.fixture(autouse=True)
def _reset_cache_client():
    """Reseta o singleton _client entre testes."""
    import api.utils.cache as _c
    original = _c._client
    _c._client = None
    yield
    _c._client = None


def _mock_redis(data: dict | None = None):
    """Cria cliente Redis falso cujo get() devolve data serializado."""
    client = MagicMock()
    client.ping.return_value = True
    if data is None:
        client.get.return_value = None
    else:
        client.get.return_value = json.dumps(data).encode()
    return client


def _df_para_hex(df: pd.DataFrame) -> str:
    buf = io.BytesIO()
    df.to_parquet(buf, index=False)
    return buf.getvalue().hex()


# ── cache_key ─────────────────────────────────────────────────────────────────

class TestCacheKey:

    def test_retorna_string_com_prefixo(self):
        from api.utils.cache import cache_key
        k = cache_key({"ufs": ["SP"], "cidades": ["SAO PAULO"]})
        assert k.startswith("consulta:")

    def test_mesmos_filtros_mesma_chave(self):
        from api.utils.cache import cache_key
        f = {"ufs": ["SP"], "cidades": ["SAO PAULO"], "genero": "F"}
        assert cache_key(f) == cache_key(f)

    def test_ordem_de_chaves_nao_altera_resultado(self):
        from api.utils.cache import cache_key
        k1 = cache_key({"ufs": ["SP"], "cidades": ["SAO PAULO"]})
        k2 = cache_key({"cidades": ["SAO PAULO"], "ufs": ["SP"]})
        assert k1 == k2

    def test_filtros_diferentes_chaves_diferentes(self):
        from api.utils.cache import cache_key
        k1 = cache_key({"ufs": ["SP"]})
        k2 = cache_key({"ufs": ["RJ"]})
        assert k1 != k2

    def test_chave_tem_64_chars_hex(self):
        from api.utils.cache import cache_key
        k = cache_key({"ufs": ["SP"]})
        digest = k.replace("consulta:", "")
        assert len(digest) == 64
        assert all(c in "0123456789abcdef" for c in digest)


# ── Redis indisponível ────────────────────────────────────────────────────────

class TestSemRedis:

    def test_cache_get_sem_redis_retorna_none(self):
        from api.utils.cache import cache_get
        with patch("api.utils.cache._get_client", return_value=None):
            result = cache_get("consulta:abc")
        assert result is None

    def test_cache_set_sem_redis_nao_levanta(self):
        from api.utils.cache import cache_set
        df = pd.DataFrame([{"A": 1}])
        with patch("api.utils.cache._get_client", return_value=None):
            cache_set("consulta:abc", df, {"meta": "ok"}, ttl=300)

    def test_sem_redis_url_client_e_none(self):
        from api.utils.cache import _get_client
        with patch.dict("os.environ", {"REDIS_URL": ""}):
            c = _get_client()
        assert c is None


# ── cache_get ─────────────────────────────────────────────────────────────────

class TestCacheGet:

    def test_get_miss_retorna_none(self):
        from api.utils.cache import cache_get
        client = _mock_redis(None)
        with patch("api.utils.cache._get_client", return_value=client):
            result = cache_get("consulta:naoexiste")
        assert result is None

    def test_get_hit_retorna_dataframe(self):
        from api.utils.cache import cache_get
        df_orig = pd.DataFrame([{"CPF": "12345678901", "NOME": "JOAO"}])
        payload = {"df_hex": _df_para_hex(df_orig), "meta": {"total": 1}}
        client = _mock_redis(payload)
        with patch("api.utils.cache._get_client", return_value=client):
            result = cache_get("consulta:qualquer")
        assert result is not None
        assert result["cache_hit"] is True
        assert "df" in result
        assert list(result["df"]["CPF"]) == ["12345678901"]

    def test_get_hit_retorna_meta(self):
        from api.utils.cache import cache_get
        df_orig = pd.DataFrame([{"A": 1}])
        payload = {"df_hex": _df_para_hex(df_orig), "meta": {"total_final": 42}}
        client = _mock_redis(payload)
        with patch("api.utils.cache._get_client", return_value=client):
            result = cache_get("consulta:x")
        assert result["meta"]["total_final"] == 42

    def test_get_payload_corrompido_retorna_none(self):
        from api.utils.cache import cache_get
        client = MagicMock()
        client.get.return_value = b"not valid json"
        with patch("api.utils.cache._get_client", return_value=client):
            result = cache_get("consulta:corrompido")
        assert result is None

    def test_get_hex_invalido_retorna_none(self):
        from api.utils.cache import cache_get
        client = MagicMock()
        client.get.return_value = json.dumps({"df_hex": "ZZZZ", "meta": {}}).encode()
        with patch("api.utils.cache._get_client", return_value=client):
            result = cache_get("consulta:hexinvalido")
        assert result is None


# ── cache_set ─────────────────────────────────────────────────────────────────

class TestCacheSet:

    def test_set_chama_setex_com_ttl(self):
        from api.utils.cache import cache_set
        client = MagicMock()
        df = pd.DataFrame([{"A": 1}])
        with patch("api.utils.cache._get_client", return_value=client):
            cache_set("consulta:k", df, {"total": 1}, ttl=1800)
        client.setex.assert_called_once()
        args = client.setex.call_args[0]
        assert args[0] == "consulta:k"
        assert args[1] == 1800

    def test_set_payload_contem_df_hex_e_meta(self):
        from api.utils.cache import cache_set
        client = MagicMock()
        df = pd.DataFrame([{"CPF": "12345678901"}])
        meta = {"total_final": 1}
        with patch("api.utils.cache._get_client", return_value=client):
            cache_set("consulta:k", df, meta, ttl=300)
        raw = client.setex.call_args[0][2]
        payload = json.loads(raw)
        assert "df_hex" in payload
        assert payload["meta"] == meta

    def test_set_df_hex_roundtrip(self):
        """DataFrame salvo e relido via hex deve ser idêntico."""
        from api.utils.cache import cache_set
        client = MagicMock()
        df = pd.DataFrame([{"CPF": "12345678901", "NOME": "JOAO"}])
        with patch("api.utils.cache._get_client", return_value=client):
            cache_set("consulta:k", df, {}, ttl=300)
        raw = client.setex.call_args[0][2]
        payload = json.loads(raw)
        df_back = pd.read_parquet(io.BytesIO(bytes.fromhex(payload["df_hex"])))
        assert list(df_back["CPF"]) == ["12345678901"]

    def test_set_erro_redis_nao_levanta(self):
        from api.utils.cache import cache_set
        client = MagicMock()
        client.setex.side_effect = Exception("Redis down")
        df = pd.DataFrame([{"A": 1}])
        with patch("api.utils.cache._get_client", return_value=client):
            cache_set("consulta:k", df, {}, ttl=300)  # não deve levantar
