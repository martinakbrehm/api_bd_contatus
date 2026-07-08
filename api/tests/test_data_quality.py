"""
test_data_quality.py
--------------------
Testes unitários de data_quality.metricas_qualidade().

Sem mocks — testa a função com DataFrames construídos localmente.
"""

import pandas as pd
import pytest


def _metricas(df):
    from api.utils.data_quality import metricas_qualidade
    return metricas_qualidade(df)


def _row(**kwargs):
    base = {
        "NOME": "JOAO", "CPF": "12345678901",
        "TELEFONE_1": None, "TELEFONE_2": None, "TELEFONE_3": None,
        "TELEFONE_4": None, "TELEFONE_5": None, "TELEFONE_6": None,
        "EMAIL_1": None, "EMAIL_2": None,
        "GENERO": None, "DATA_NASCIMENTO": None, "ENDERECO": None,
    }
    base.update(kwargs)
    return base


# ── DataFrame vazio ───────────────────────────────────────────────────────────

class TestVazio:

    def test_df_vazio_retorna_total_zero(self):
        result = _metricas(pd.DataFrame())
        assert result == {"total": 0}

    def test_df_sem_linhas_retorna_total_zero(self):
        result = _metricas(pd.DataFrame(columns=["NOME", "CPF"]))
        assert result == {"total": 0}


# ── Total ─────────────────────────────────────────────────────────────────────

class TestTotal:

    def test_total_correto(self):
        df = pd.DataFrame([_row() for _ in range(5)])
        assert _metricas(df)["total"] == 5

    def test_total_um_registro(self):
        df = pd.DataFrame([_row()])
        assert _metricas(df)["total"] == 1


# ── Email ─────────────────────────────────────────────────────────────────────

class TestEmail:

    def test_com_email_1_conta(self):
        df = pd.DataFrame([_row(EMAIL_1="a@b.com")])
        m = _metricas(df)
        assert m["com_email"] == 1
        assert m["pct_email"] == 100.0

    def test_com_email_2_conta(self):
        df = pd.DataFrame([_row(EMAIL_2="x@y.com")])
        m = _metricas(df)
        assert m["com_email"] == 1

    def test_sem_email_zero(self):
        df = pd.DataFrame([_row()])
        m = _metricas(df)
        assert m["com_email"] == 0
        assert m["pct_email"] == 0.0

    def test_string_vazia_nao_conta(self):
        df = pd.DataFrame([_row(EMAIL_1="")])
        assert _metricas(df)["com_email"] == 0

    def test_parcialmente_com_email(self):
        df = pd.DataFrame([
            _row(EMAIL_1="a@b.com"),
            _row(),
            _row(EMAIL_1="c@d.com"),
            _row(),
        ])
        m = _metricas(df)
        assert m["com_email"] == 2
        assert m["pct_email"] == 50.0


# ── Telefones ─────────────────────────────────────────────────────────────────

class TestTelefones:

    def test_celular_9_digitos(self):
        """Celular BR: 9 dígitos (sem DDD, que fica em DDD_i)."""
        df = pd.DataFrame([_row(TELEFONE_1="987654321")])  # 9 chars
        m = _metricas(df)
        assert m["com_movel"] == 1
        assert m["pct_movel"] == 100.0

    def test_fixo_8_digitos(self):
        """Fixo BR: 8 dígitos."""
        df = pd.DataFrame([_row(TELEFONE_1="31234567")])  # 8 chars
        m = _metricas(df)
        assert m["com_fixo"] == 1
        assert m["pct_fixo"] == 100.0

    def test_sem_telefone_zero(self):
        df = pd.DataFrame([_row()])
        m = _metricas(df)
        assert m["com_movel"] == 0
        assert m["com_fixo"] == 0
        assert m["com_algum_tel"] == 0

    def test_com_algum_tel_e_or_movel_fixo(self):
        """com_algum_tel = quem tem movel OU fixo."""
        df = pd.DataFrame([
            _row(TELEFONE_1="987654321"),   # movel
            _row(TELEFONE_1="31234567"),    # fixo
            _row(),                          # nenhum
        ])
        m = _metricas(df)
        assert m["com_algum_tel"] == 2

    def test_mesmo_registro_movel_e_fixo_conta_uma_vez(self):
        """Um registro com movel E fixo conta como 1 em com_algum_tel."""
        df = pd.DataFrame([_row(TELEFONE_1="987654321", TELEFONE_2="31234567")])
        m = _metricas(df)
        assert m["com_algum_tel"] == 1
        assert m["com_movel"] == 1
        assert m["com_fixo"] == 1

    def test_telefone_em_qualquer_coluna_conta(self):
        """TELEFONE_6 também é verificado."""
        df = pd.DataFrame([_row(TELEFONE_6="987654321")])
        assert _metricas(df)["com_movel"] == 1


# ── Outros campos ─────────────────────────────────────────────────────────────

class TestOutrosCampos:

    def test_com_genero(self):
        df = pd.DataFrame([_row(GENERO="M"), _row()])
        m = _metricas(df)
        assert m["com_genero"] == 1
        assert m["pct_genero"] == 50.0

    def test_com_data_nascimento(self):
        df = pd.DataFrame([_row(DATA_NASCIMENTO="1985-01-01"), _row()])
        assert _metricas(df)["com_data_nascimento"] == 1

    def test_com_endereco(self):
        df = pd.DataFrame([_row(ENDERECO="RUA DAS FLORES"), _row()])
        assert _metricas(df)["com_endereco"] == 1


# ── Percentuais ───────────────────────────────────────────────────────────────

class TestPercentuais:

    def test_pct_arredondado_para_1_decimal(self):
        df = pd.DataFrame([_row(EMAIL_1="a@b.com")] + [_row() for _ in range(2)])
        m = _metricas(df)
        # 1/3 = 33.3%
        assert m["pct_email"] == round(100 / 3, 1)

    def test_colunas_ausentes_nao_levantam_excecao(self):
        """DataFrame sem colunas de telefone deve funcionar com 0."""
        df = pd.DataFrame([{"NOME": "JOAO"}])
        m = _metricas(df)
        assert m["total"] == 1
        assert m["com_movel"] == 0
        assert m["com_email"] == 0
