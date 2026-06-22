"""
test_data_processor.py
----------------------
Testes unitários de data_processor.py e helpers de telefone.

Sem acesso ao banco — testa diretamente as funções Python com DataFrames
construídos localmente. Garante:
  - Filtro tipo_telefone "ambos" remove registros sem nenhum telefone
  - Celular e fixo identificados corretamente
  - Compactação de telefones move válidos para colunas iniciais
  - Deduplicação por CPF mantém apenas primeira ocorrência
"""

import pandas as pd
import pytest


# ── Helpers de telefone ────────────────────────────────────────────────────────

class TestEhCelular:
    def _fn(self):
        from api.utils.data_processor import _eh_celular
        return _eh_celular

    def test_celular_11_digitos_terceiro_9(self):
        assert self._fn()("11987654321") is True

    def test_celular_ddd_diferente(self):
        assert self._fn()("73987654321") is True

    def test_fixo_10_digitos_nao_e_celular(self):
        assert self._fn()("1131234567") is False

    def test_numero_curto_nao_e_celular(self):
        assert self._fn()("98765432") is False

    def test_11_digitos_sem_9_na_posicao_3(self):
        assert self._fn()("11187654321") is False

    def test_vazio_nao_e_celular(self):
        assert self._fn()("") is False


class TestEhFixo:
    def _fn(self):
        from api.utils.data_processor import _eh_fixo
        return _eh_fixo

    def test_fixo_10_digitos(self):
        assert self._fn()("1131234567") is True

    def test_celular_11_digitos_nao_e_fixo(self):
        assert self._fn()("11987654321") is False

    def test_numero_curto_nao_e_fixo(self):
        assert self._fn()("31234567") is False

    def test_vazio_nao_e_fixo(self):
        assert self._fn()("") is False


class TestTemTelefonDoTipo:
    def _fn(self):
        from api.utils.data_processor import _tem_telefone_do_tipo
        return _tem_telefone_do_tipo

    def _row(self, **kwargs) -> pd.Series:
        base = {f"DDD_{i}": "" for i in range(1, 7)}
        base.update({f"TELEFONE_{i}": "" for i in range(1, 7)})
        base.update(kwargs)
        return pd.Series(base)

    def test_movel_encontrado(self):
        row = self._row(DDD_1="11", TELEFONE_1="987654321")
        assert self._fn()(row, "movel") is True

    def test_movel_nao_encontrado_com_fixo(self):
        row = self._row(DDD_1="11", TELEFONE_1="31234567")
        assert self._fn()(row, "movel") is False

    def test_fixo_encontrado(self):
        row = self._row(DDD_1="11", TELEFONE_1="31234567")
        assert self._fn()(row, "fixo") is True

    def test_fixo_nao_encontrado_com_celular(self):
        row = self._row(DDD_1="11", TELEFONE_1="987654321")
        assert self._fn()(row, "fixo") is False

    def test_ambos_aceita_celular(self):
        row = self._row(DDD_1="11", TELEFONE_1="987654321")
        assert self._fn()(row, "ambos") is True

    def test_ambos_aceita_fixo(self):
        row = self._row(DDD_1="11", TELEFONE_1="31234567")
        assert self._fn()(row, "ambos") is True

    def test_ambos_sem_telefone_retorna_false(self):
        row = self._row()
        assert self._fn()(row, "ambos") is False

    def test_movel_na_segunda_coluna_encontrado(self):
        row = self._row(DDD_2="41", TELEFONE_2="917865750")
        assert self._fn()(row, "movel") is True

    def test_sem_telefone_nao_passa_filtro_movel(self):
        row = self._row()
        assert self._fn()(row, "movel") is False

    def test_none_nos_campos_nao_quebra(self):
        row = pd.Series({
            "DDD_1": None, "TELEFONE_1": None,
            "DDD_2": None, "TELEFONE_2": None,
            "DDD_3": None, "TELEFONE_3": None,
            "DDD_4": None, "TELEFONE_4": None,
            "DDD_5": None, "TELEFONE_5": None,
            "DDD_6": None, "TELEFONE_6": None,
        })
        assert self._fn()(row, "ambos") is False


# ── processar() — filtro tipo_telefone ────────────────────────────────────────

def _df_base(rows: list[dict]) -> pd.DataFrame:
    """DataFrame mínimo compatível com processar()."""
    template = {
        "CPF": None, "NOME": "TESTE", "GENERO": "M",
        "DATA_NASCIMENTO": "1985-01-01", "ENDERECO": "RUA X",
        "NUM_END": "1", "COMPLEMENTO": None, "BAIRRO": "CENTRO",
        "CIDADE": "SAO PAULO", "UF": "SP", "CEP": "01000000",
        "EMAIL_1": None, "EMAIL_2": None,
        "TELEFONE_1": None, "TELEFONE_2": None, "TELEFONE_3": None,
        "TELEFONE_4": None, "TELEFONE_5": None, "TELEFONE_6": None,
    }
    return pd.DataFrame([{**template, **r} for r in rows])


class TestProcessarTipoTelefone:
    """Garante que processar() filtra registros por tipo_telefone corretamente."""

    def test_ambos_remove_registros_sem_telefone(self):
        from api.utils.data_processor import processar
        df = _df_base([
            {"CPF": "11111111111", "TELEFONE_1": "11987654321"},
            {"CPF": "22222222222", "TELEFONE_1": None},
            {"CPF": "33333333333", "TELEFONE_1": "1131234567"},
        ])
        resultado, _ = processar(df, {"tipo_telefone": "ambos"})
        cpfs = set(resultado["CPF"].tolist())
        assert "22222222222" not in cpfs
        assert "11111111111" in cpfs or "33333333333" in cpfs

    def test_movel_retorna_so_celulares(self):
        from api.utils.data_processor import processar
        df = _df_base([
            {"CPF": "11111111111", "TELEFONE_1": "11987654321"},
            {"CPF": "22222222222", "TELEFONE_1": "1131234567"},
        ])
        resultado, _ = processar(df, {"tipo_telefone": "movel"})
        assert len(resultado) == 1
        assert resultado.iloc[0]["CPF"] == "11111111111"

    def test_fixo_retorna_so_fixos(self):
        from api.utils.data_processor import processar
        df = _df_base([
            {"CPF": "11111111111", "TELEFONE_1": "11987654321"},
            {"CPF": "22222222222", "TELEFONE_1": "1131234567"},
        ])
        resultado, _ = processar(df, {"tipo_telefone": "fixo"})
        assert len(resultado) == 1
        assert resultado.iloc[0]["CPF"] == "22222222222"

    def test_ambos_aceita_mix_celular_e_fixo(self):
        from api.utils.data_processor import processar
        df = _df_base([
            {"CPF": "11111111111", "TELEFONE_1": "11987654321"},
            {"CPF": "22222222222", "TELEFONE_1": "1131234567"},
        ])
        resultado, _ = processar(df, {"tipo_telefone": "ambos"})
        assert len(resultado) == 2

    def test_df_vazio_retorna_vazio(self):
        from api.utils.data_processor import processar
        resultado, _ = processar(pd.DataFrame(), {"tipo_telefone": "ambos"})
        assert resultado.empty

    def test_quantidade_limita_resultado(self):
        from api.utils.data_processor import processar
        rows = [{"CPF": str(i).zfill(11), "TELEFONE_1": "11987654321"} for i in range(10)]
        df = _df_base(rows)
        resultado, _ = processar(df, {"tipo_telefone": "movel", "quantidade": 3})
        assert len(resultado) <= 3


# ── Deduplicação por CPF ───────────────────────────────────────────────────────

class TestProcessarDeduplicacao:
    def test_cpf_duplicado_mantém_primeiro(self):
        from api.utils.data_processor import processar
        df = _df_base([
            {"CPF": "11111111111", "TELEFONE_1": "11987654321", "NOME": "PRIMEIRO"},
            {"CPF": "11111111111", "TELEFONE_1": "11987654322", "NOME": "SEGUNDO"},
        ])
        resultado, _ = processar(df, {"tipo_telefone": "movel"})
        assert len(resultado) == 1
        assert resultado.iloc[0]["NOME"] == "PRIMEIRO"

    def test_sem_cpf_nao_é_deduplicado(self):
        from api.utils.data_processor import processar
        df = _df_base([
            {"CPF": None, "TELEFONE_1": "11987654321"},
            {"CPF": None, "TELEFONE_1": "11987654322"},
        ])
        resultado, _ = processar(df, {"tipo_telefone": "movel"})
        assert len(resultado) == 2


# ── Compactação de telefones ──────────────────────────────────────────────────

class TestCompactarTelefones:
    def test_telefone_na_posicao_3_vai_para_posicao_1(self):
        from api.utils.data_processor import _compactar_telefones
        df = pd.DataFrame([{
            "DDD_1": "", "TELEFONE_1": "",
            "DDD_2": "", "TELEFONE_2": "",
            "DDD_3": "11", "TELEFONE_3": "987654321",
            "DDD_4": "", "TELEFONE_4": "",
            "DDD_5": "", "TELEFONE_5": "",
            "DDD_6": "", "TELEFONE_6": "",
        }])
        resultado = _compactar_telefones(df, "movel")
        assert resultado.iloc[0]["TELEFONE_1"] == "987654321"
        assert resultado.iloc[0]["DDD_1"] == "11"
        assert resultado.iloc[0]["TELEFONE_3"] == ""
