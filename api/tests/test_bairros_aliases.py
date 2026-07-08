"""
test_bairros_aliases.py
-----------------------
Testes unitários de bairros_aliases.variantes() e expandir_bairros().

Sem mocks — lógica pura de expansão de prefixos.
"""

import pytest


class TestVariantes:

    def _fn(self):
        from api.utils.bairros_aliases import variantes
        return variantes

    def test_jardim_expande_para_jd(self):
        result = self._fn()("JARDIM BOTANICO")
        assert "JARDIM BOTANICO" in result
        assert "JD BOTANICO" in result

    def test_jd_expande_para_jardim(self):
        result = self._fn()("JD BOTANICO")
        assert "JD BOTANICO" in result
        assert "JARDIM BOTANICO" in result

    def test_parque_expande_para_prq_e_pq(self):
        result = self._fn()("PARQUE CAMPOLIM")
        assert "PARQUE CAMPOLIM" in result
        assert "PRQ CAMPOLIM" in result
        assert "PQ CAMPOLIM" in result

    def test_prq_expande_para_parque_e_pq(self):
        result = self._fn()("PRQ CAMPOLIM")
        assert "PRQ CAMPOLIM" in result
        assert "PARQUE CAMPOLIM" in result
        assert "PQ CAMPOLIM" in result

    def test_vila_expande_para_vl(self):
        result = self._fn()("VILA MADALENA")
        assert "VILA MADALENA" in result
        assert "VL MADALENA" in result

    def test_vl_expande_para_vila(self):
        result = self._fn()("VL MADALENA")
        assert "VL MADALENA" in result
        assert "VILA MADALENA" in result

    def test_centro_sem_variantes(self):
        """Nome sem prefixo reconhecível retorna só o original."""
        result = self._fn()("CENTRO")
        assert result == ["CENTRO"]

    def test_nome_uma_palavra_sem_variantes(self):
        result = self._fn()("HIGIENOPOLIS")
        assert result == ["HIGIENOPOLIS"]

    def test_santa_expande_para_sta(self):
        result = self._fn()("SANTA CECILIA")
        assert "STA CECILIA" in result

    def test_sta_expande_para_santa(self):
        result = self._fn()("STA CECILIA")
        assert "SANTA CECILIA" in result

    def test_sem_duplicatas_no_resultado(self):
        result = self._fn()("JARDIM DAS FLORES")
        assert len(result) == len(set(result))

    def test_preserva_original_sempre_primeiro(self):
        for bairro in ("JARDIM BOTANICO", "JD BOTANICO", "PARQUE X", "CENTRO"):
            result = self._fn()(bairro)
            assert result[0] == bairro


class TestExpandirBairros:

    def _fn(self):
        from api.utils.bairros_aliases import expandir_bairros
        return expandir_bairros

    def test_lista_vazia_retorna_vazia(self):
        assert self._fn()([]) == []

    def test_expande_jardim(self):
        result = self._fn()(["JARDIM BOTANICO"])
        assert "JARDIM BOTANICO" in result
        assert "JD BOTANICO" in result

    def test_deduplica_variantes_sobrepostas(self):
        """Se o usuário passar JD e JARDIM do mesmo bairro, não duplica."""
        result = self._fn()(["JD BOTANICO", "JARDIM BOTANICO"])
        # Cada variante deve aparecer apenas uma vez
        assert result.count("JD BOTANICO") == 1
        assert result.count("JARDIM BOTANICO") == 1

    def test_multiplos_bairros(self):
        result = self._fn()(["CENTRO", "JARDIM PAULISTA"])
        assert "CENTRO" in result
        assert "JARDIM PAULISTA" in result
        assert "JD PAULISTA" in result

    def test_preserva_ordem_de_insercao(self):
        result = self._fn()(["CENTRO", "VILA MADALENA"])
        assert result.index("CENTRO") < result.index("VILA MADALENA")

    def test_resultado_sem_duplicatas(self):
        result = self._fn()(["PARQUE DAS FLORES", "PRQ DAS FLORES"])
        assert len(result) == len(set(result))
