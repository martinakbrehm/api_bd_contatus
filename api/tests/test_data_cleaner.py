"""
test_data_cleaner.py
--------------------
Testes unitários de data_cleaner.

Módulo puramente pandas — sem mocks, sem banco.
Cobre as funções de validação individuais e o pipeline limpar_dataframe().
"""

import pandas as pd
import pytest

from api.utils.data_cleaner import (
    _eh_string_invalida,
    _validar_cpf,
    _validar_email,
    _validar_localidade,
    _validar_nome,
    _validar_telefone,
    limpar_dataframe,
    relatorio_html,
)


# ── _eh_string_invalida ───────────────────────────────────────────────────────

class TestEhStringInvalida:

    def test_string_vazia_invalida(self):
        assert _eh_string_invalida("") is True

    def test_string_espacos_invalida(self):
        assert _eh_string_invalida("   ") is True

    def test_none_nao_invalida(self):
        # None/NaN são tratados separadamente — não conta como string inválida
        assert _eh_string_invalida(None) is False

    def test_nan_nao_invalido(self):
        assert _eh_string_invalida(float("nan")) is False

    def test_em_validacao(self):
        assert _eh_string_invalida("EM VALIDACAO") is True

    def test_nao_informado(self):
        assert _eh_string_invalida("NAO INFORMADO") is True

    def test_n_a(self):
        assert _eh_string_invalida("N/A") is True

    def test_fulano(self):
        assert _eh_string_invalida("FULANO") is True

    def test_todos_iguais_mais_de_2(self):
        assert _eh_string_invalida("aaaaaa") is True

    def test_todos_iguais_2_ou_menos_nao_invalido(self):
        # "aa" tem 2 chars — a regra exige len > 2
        assert _eh_string_invalida("aa") is False

    def test_nome_normal_valido(self):
        assert _eh_string_invalida("MARIA SILVA") is False

    def test_cidade_real_valida(self):
        assert _eh_string_invalida("SAO PAULO") is False


# ── _validar_cpf ──────────────────────────────────────────────────────────────

class TestValidarCpf:

    def test_none_aceito(self):
        assert _validar_cpf(None) is True

    def test_nan_aceito(self):
        assert _validar_cpf(float("nan")) is True

    def test_cpf_valido_11_digitos(self):
        assert _validar_cpf("91234567890") is True

    def test_cpf_com_pontos_e_tracos(self):
        assert _validar_cpf("912.345.678-90") is True

    def test_cpf_com_letras_invalido(self):
        assert _validar_cpf("9123456789A") is False

    def test_cpf_menos_11_digitos_invalido(self):
        assert _validar_cpf("1234567890") is False

    def test_cpf_mais_11_digitos_invalido(self):
        assert _validar_cpf("123456789012") is False

    def test_cpf_sequencia_repetida_invalido(self):
        for d in "0123456789":
            assert _validar_cpf(d * 11) is False

    def test_cpf_teste_classico_invalido(self):
        assert _validar_cpf("12345678901") is False

    def test_cpf_zeros_invalido(self):
        assert _validar_cpf("00000000000") is False


# ── _validar_email ────────────────────────────────────────────────────────────

class TestValidarEmail:

    def test_none_aceito(self):
        assert _validar_email(None) is True

    def test_nan_aceito(self):
        assert _validar_email(float("nan")) is True

    def test_email_valido(self):
        assert _validar_email("joao@contatus.com.br") is True

    def test_sem_arroba_invalido(self):
        assert _validar_email("joaocontatus.com") is False

    def test_sem_ponto_no_dominio_invalido(self):
        assert _validar_email("joao@contatuscom") is False

    def test_espaco_invalido(self):
        assert _validar_email("jo ao@email.com") is False

    def test_multiplos_arrobas_invalido(self):
        assert _validar_email("a@b@c.com") is False

    def test_string_invalida_conhecida(self):
        assert _validar_email("N/A") is False

    def test_usuario_vazio_invalido(self):
        assert _validar_email("@dominio.com") is False

    def test_dominio_vazio_invalido(self):
        assert _validar_email("usuario@") is False

    def test_usuario_comeca_com_ponto_invalido(self):
        assert _validar_email(".user@email.com") is False

    def test_usuario_termina_com_ponto_invalido(self):
        assert _validar_email("user.@email.com") is False

    def test_dominio_comeca_com_hifen_invalido(self):
        assert _validar_email("user@-email.com") is False

    def test_email_muito_longo_invalido(self):
        longo = "a" * 250 + "@email.com"
        assert _validar_email(longo) is False

    def test_usuario_so_numeros_curto_valido(self):
        # até 3 dígitos no usuário é aceito
        assert _validar_email("123@email.com") is True

    def test_usuario_so_numeros_longo_invalido(self):
        assert _validar_email("12345@email.com") is False


# ── _validar_telefone ─────────────────────────────────────────────────────────

class TestValidarTelefone:

    def test_none_aceito(self):
        assert _validar_telefone(None) is True

    def test_nan_aceito(self):
        assert _validar_telefone(float("nan")) is True

    def test_vazio_aceito(self):
        assert _validar_telefone("") is True

    def test_celular_11_digitos_valido(self):
        assert _validar_telefone("11987654321") is True

    def test_fixo_10_digitos_valido(self):
        assert _validar_telefone("1133334444") is True

    def test_com_formatacao_valido(self):
        assert _validar_telefone("(11) 98765-4321") is True

    def test_menos_10_digitos_invalido(self):
        assert _validar_telefone("119876543") is False

    def test_mais_11_digitos_invalido(self):
        assert _validar_telefone("119876543210") is False

    def test_sequencia_repetida_invalido(self):
        assert _validar_telefone("11111111111") is False

    def test_letras_invalido(self):
        assert _validar_telefone("1198765432A") is False

    def test_ddd_00_invalido(self):
        assert _validar_telefone("00987654321") is False

    def test_celular_nono_digito_invalido(self):
        # celular com nono dígito 5 (não é 6-9) → inválido
        assert _validar_telefone("11587654321") is False

    def test_celular_nono_digito_6_valido(self):
        assert _validar_telefone("11687654321") is True


# ── _validar_nome ─────────────────────────────────────────────────────────────

class TestValidarNome:

    def test_none_invalido(self):
        assert _validar_nome(None) is False

    def test_nome_curto_invalido(self):
        assert _validar_nome("AB") is False

    def test_nome_normal_valido(self):
        assert _validar_nome("MARIA SILVA") is True

    def test_so_numeros_invalido(self):
        assert _validar_nome("12345") is False

    def test_so_simbolos_invalido(self):
        assert _validar_nome("---") is False

    def test_string_invalida_conhecida(self):
        assert _validar_nome("TESTE") is False

    def test_todos_iguais_invalido(self):
        assert _validar_nome("AAAA") is False

    def test_nome_com_acento_valido(self):
        assert _validar_nome("JOÃO") is True

    def test_nome_começa_com_simbolo_invalido(self):
        assert _validar_nome("!Maria") is False


# ── _validar_localidade ───────────────────────────────────────────────────────

class TestValidarLocalidade:

    def test_none_aceito(self):
        assert _validar_localidade(None) is True

    def test_nan_aceito(self):
        assert _validar_localidade(float("nan")) is True

    def test_vazio_aceito(self):
        assert _validar_localidade("") is True

    def test_bairro_real_valido(self):
        assert _validar_localidade("JARDIM PAULISTA") is True

    def test_so_numeros_invalido(self):
        assert _validar_localidade("12345") is False

    def test_string_invalida_conhecida(self):
        assert _validar_localidade("SEM BAIRRO") is False

    def test_comprimento_1_invalido(self):
        assert _validar_localidade("A") is False

    def test_so_simbolos_invalido(self):
        assert _validar_localidade("---") is False

    def test_cidade_com_acento_valido(self):
        assert _validar_localidade("SÃO PAULO") is True


# ── limpar_dataframe ──────────────────────────────────────────────────────────

def _df(**kwargs):
    """Constrói DataFrame com uma linha a partir de campos nomeados."""
    return pd.DataFrame([kwargs])


class TestLimparDataframe:

    def test_df_vazio_retorna_vazio(self):
        df = pd.DataFrame(columns=["CPF", "NOME"])
        resultado, rel = limpar_dataframe(df)
        assert len(resultado) == 0
        assert rel["total_final"] == 0

    def test_registro_limpo_preservado(self):
        df = _df(CPF="91234567890", NOME="JOAO SILVA", CIDADE="SAO PAULO")
        resultado, rel = limpar_dataframe(df)
        assert len(resultado) == 1
        assert rel["total_final"] == 1

    def test_cpf_invalido_removido(self):
        df = _df(CPF="00000000000", NOME="JOAO SILVA")
        resultado, rel = limpar_dataframe(df)
        assert len(resultado) == 0
        assert rel["removidos_cpf"] == 1

    def test_nome_invalido_removido(self):
        # "AB" passa _eh_string_invalida (não está na lista) mas falha _validar_nome (len<3)
        df = _df(NOME="AB")
        resultado, rel = limpar_dataframe(df)
        assert len(resultado) == 0
        assert rel["removidos_nome"] == 1

    def test_cidade_em_validacao_removida(self):
        df = _df(NOME="MARIA SILVA", CIDADE="EM VALIDACAO")
        resultado, rel = limpar_dataframe(df)
        assert len(resultado) == 0
        assert rel["removidos_validacao"] == 1

    def test_email_invalido_substituido_por_none_registro_mantido(self):
        df = _df(NOME="JOAO SILVA", EMAIL_1="naotememail")
        resultado, rel = limpar_dataframe(df)
        assert len(resultado) == 1
        assert pd.isna(resultado.iloc[0]["EMAIL_1"])
        assert rel["removidos_email"] == 1

    def test_telefone_invalido_substituido_por_none_registro_mantido(self):
        df = _df(NOME="JOAO SILVA", TELEFONE_1="11111111111")
        resultado, rel = limpar_dataframe(df)
        assert len(resultado) == 1
        assert pd.isna(resultado.iloc[0]["TELEFONE_1"])
        assert rel["removidos_telefone"] == 1

    def test_multiplos_registros_contagem_correta(self):
        # "AB" passes _eh_string_invalida (not in list, not all-same) but fails _validar_nome (len<3)
        df = pd.DataFrame([
            {"NOME": "JOAO SILVA",  "CPF": "91234567890"},
            {"NOME": "AB",          "CPF": "91234567891"},  # nome muito curto → removidos_nome
            {"NOME": "MARIA COSTA", "CPF": "00000000000"},  # CPF inválido → removidos_cpf
        ])
        resultado, rel = limpar_dataframe(df)
        assert rel["total_inicial"] == 3
        assert rel["total_final"] == 1
        assert rel["removidos_nome"] == 1
        assert rel["removidos_cpf"] == 1

    def test_relatorio_tem_todos_campos(self):
        df = _df(NOME="JOAO SILVA")
        _, rel = limpar_dataframe(df)
        for campo in ("total_inicial", "removidos_cpf", "removidos_nome",
                      "removidos_validacao", "removidos_email", "removidos_telefone", "total_final"):
            assert campo in rel

    def test_indice_resetado_apos_limpeza(self):
        df = pd.DataFrame([
            {"NOME": "TESTE"},
            {"NOME": "MARIA SILVA"},
        ])
        resultado, _ = limpar_dataframe(df)
        assert list(resultado.index) == list(range(len(resultado)))


# ── relatorio_html ────────────────────────────────────────────────────────────

class TestRelatorioHtml:

    def _relatorio(self):
        return {
            "total_inicial": 1000,
            "removidos_cpf": 10,
            "removidos_nome": 5,
            "removidos_validacao": 3,
            "removidos_email": 7,
            "removidos_telefone": 2,
            "total_final": 980,
        }

    def test_retorna_string(self):
        assert isinstance(relatorio_html(self._relatorio()), str)

    def test_contem_total_inicial(self):
        html = relatorio_html(self._relatorio())
        assert "1,000" in html or "1000" in html

    def test_contem_total_final(self):
        html = relatorio_html(self._relatorio())
        assert "980" in html

    def test_contem_tag_ul(self):
        html = relatorio_html(self._relatorio())
        assert "<ul" in html and "</ul>" in html
