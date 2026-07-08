"""
test_bairros_api.py
-------------------
Testes unitários de bairros_api.obter_bairros() e helpers.

APIs externas (IBGE e Overpass) são sempre mockadas — sem chamadas HTTP reais.
"""

import time
from unittest.mock import patch

import pytest


@pytest.fixture(autouse=True)
def _limpar_cache():
    """Garante cache limpo antes e depois de cada teste."""
    from api.utils.bairros_api import limpar_cache
    limpar_cache()
    yield
    limpar_cache()


def _ibge_municipio(id_=3550308, nome="São Paulo"):
    return [{"id": id_, "nome": nome, "microrregiao": {}}]


def _overpass_bairros(*nomes):
    return {
        "elements": [
            {"type": "node", "tags": {"name": n}}
            for n in nomes
        ]
    }


# ── obter_bairros — cache ──────────────────────────────────────────────────────

class TestCache:

    def test_cache_hit_nao_faz_chamada_http(self):
        from api.utils.bairros_api import obter_bairros, _cache, CACHE_TTL_HORAS
        _cache["SAO PAULO"] = (time.time(), ["CENTRO", "PINHEIROS"])
        with patch("api.utils.bairros_api._get_json") as mock_get, \
             patch("api.utils.bairros_api._post_json") as mock_post:
            result = obter_bairros("SAO PAULO")
        mock_get.assert_not_called()
        mock_post.assert_not_called()
        assert result == ["CENTRO", "PINHEIROS"]

    def test_resultado_salvo_no_cache(self):
        from api.utils.bairros_api import obter_bairros, _cache
        with patch("api.utils.bairros_api._get_json", return_value=_ibge_municipio()), \
             patch("api.utils.bairros_api._post_json", return_value=_overpass_bairros("Pinheiros", "Centro")):
            obter_bairros("SAO PAULO")
        assert "SAO PAULO" in _cache

    def test_segunda_chamada_usa_cache(self):
        from api.utils.bairros_api import obter_bairros
        with patch("api.utils.bairros_api._get_json", return_value=_ibge_municipio()) as mock_get, \
             patch("api.utils.bairros_api._post_json", return_value=_overpass_bairros("Pinheiros")):
            obter_bairros("SAO PAULO")
            obter_bairros("SAO PAULO")
        assert mock_get.call_count == 1  # só chamado uma vez


# ── obter_bairros — IBGE ──────────────────────────────────────────────────────

class TestIBGE:

    def test_municipio_nao_encontrado_retorna_vazio(self):
        from api.utils.bairros_api import obter_bairros
        with patch("api.utils.bairros_api._get_json", return_value=None):
            result = obter_bairros("CIDADE INEXISTENTE")
        assert result == []

    def test_ibge_retorna_lista_vazia_retorna_vazio(self):
        from api.utils.bairros_api import obter_bairros
        with patch("api.utils.bairros_api._get_json", return_value=[]):
            result = obter_bairros("CIDADE X")
        assert result == []

    def test_alias_bh_resolve_para_belo_horizonte(self):
        """BH deve ser resolvido para 'Belo Horizonte' ao chamar IBGE."""
        from api.utils.bairros_api import obter_bairros
        captured = {}
        def fake_get(url, timeout=10):
            captured["url"] = url
            return [{"id": 3106200, "nome": "Belo Horizonte"}]
        with patch("api.utils.bairros_api._get_json", side_effect=fake_get), \
             patch("api.utils.bairros_api._post_json", return_value=_overpass_bairros("Savassi")):
            obter_bairros("BH")
        assert "Belo Horizonte" in captured["url"] or "belo" in captured["url"].lower()

    def test_alias_rio_resolve_para_rio_de_janeiro(self):
        from api.utils.bairros_api import obter_bairros
        captured = {}
        def fake_get(url, timeout=10):
            captured["url"] = url
            return [{"id": 3304557, "nome": "Rio de Janeiro"}]
        with patch("api.utils.bairros_api._get_json", side_effect=fake_get), \
             patch("api.utils.bairros_api._post_json", return_value=_overpass_bairros("Copacabana")):
            obter_bairros("RIO")
        assert "Rio" in captured["url"] or "rio" in captured["url"].lower()


# ── obter_bairros — Overpass ──────────────────────────────────────────────────

class TestOverpass:

    def test_overpass_sem_elements_retorna_vazio(self):
        from api.utils.bairros_api import obter_bairros
        with patch("api.utils.bairros_api._get_json", return_value=_ibge_municipio()), \
             patch("api.utils.bairros_api._post_json", return_value={"elements": []}):
            result = obter_bairros("SAO PAULO")
        assert result == []

    def test_overpass_none_retorna_vazio(self):
        from api.utils.bairros_api import obter_bairros
        with patch("api.utils.bairros_api._get_json", return_value=_ibge_municipio()), \
             patch("api.utils.bairros_api._post_json", return_value=None):
            result = obter_bairros("SAO PAULO")
        assert result == []

    def test_bairros_em_maiusculo_e_ordenados(self):
        from api.utils.bairros_api import obter_bairros
        with patch("api.utils.bairros_api._get_json", return_value=_ibge_municipio()), \
             patch("api.utils.bairros_api._post_json",
                   return_value=_overpass_bairros("Pinheiros", "Centro", "Bela Vista")):
            result = obter_bairros("SAO PAULO")
        assert result == sorted(r.upper() for r in result)
        for b in result:
            assert b == b.upper()

    def test_nomes_curtos_ignorados(self):
        """Nomes com 2 chars ou menos são descartados."""
        from api.utils.bairros_api import obter_bairros
        overpass = {"elements": [
            {"type": "node", "tags": {"name": "AB"}},   # ignorar (<=2)
            {"type": "node", "tags": {"name": "Pinheiros"}},
        ]}
        with patch("api.utils.bairros_api._get_json", return_value=_ibge_municipio()), \
             patch("api.utils.bairros_api._post_json", return_value=overpass):
            result = obter_bairros("SAO PAULO")
        assert "AB" not in result
        assert "PINHEIROS" in result

    def test_prefere_name_pt_sobre_name(self):
        """Tag name:pt tem prioridade sobre name."""
        from api.utils.bairros_api import obter_bairros
        overpass = {"elements": [
            {"type": "node", "tags": {"name": "Copacabana", "name:pt": "Copacabana PT"}}
        ]}
        with patch("api.utils.bairros_api._get_json", return_value=_ibge_municipio()), \
             patch("api.utils.bairros_api._post_json", return_value=overpass):
            result = obter_bairros("SAO PAULO")
        assert "COPACABANA PT" in result


# ── _normalizar ───────────────────────────────────────────────────────────────

class TestNormalizar:

    def test_remove_acentos(self):
        from api.utils.bairros_api import _normalizar
        assert _normalizar("São Paulo") == "SAO PAULO"
        assert _normalizar("Goiânia") == "GOIANIA"

    def test_converte_maiusculo(self):
        from api.utils.bairros_api import _normalizar
        assert _normalizar("belo horizonte") == "BELO HORIZONTE"

    def test_trim(self):
        from api.utils.bairros_api import _normalizar
        assert _normalizar("  CENTRO  ") == "CENTRO"
