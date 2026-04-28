"""
test_sanitizer.py
-----------------
Testes de mascaramento e sanitização de dados sensíveis.
"""

import pytest

from api.utils.sanitizer import (
    mascarar_cpf,
    mascarar_email,
    mascarar_nome,
    mascarar_registro,
    mascarar_telefone,
    normalizar_texto,
    normalizar_uf,
    sanitizar_string,
)


class TestMascaraCpf:
    """Testes de mascaramento de CPF."""

    def test_cpf_11_digitos(self):
        result = mascarar_cpf("12345678901")
        assert result == "***.456.***-01"

    def test_cpf_com_pontos(self):
        result = mascarar_cpf("123.456.789-01")
        assert "***.456.***-01" == result

    def test_cpf_vazio(self):
        assert mascarar_cpf("") == ""
        assert mascarar_cpf(None) == ""

    def test_cpf_tamanho_errado(self):
        result = mascarar_cpf("12345")
        assert result == "***.***.***-**"

    def test_cpf_mascara_esconde_dados_sensiveis(self):
        result = mascarar_cpf("98765432100")
        # Primeiros e terceiros blocos mascarados
        assert result.startswith("***.")
        assert "***-" in result


class TestMascaraEmail:
    """Testes de mascaramento de email."""

    def test_email_normal(self):
        result = mascarar_email("joao.silva@gmail.com")
        assert result == "j***@gm***.com"

    def test_email_sem_arroba(self):
        result = mascarar_email("semdominio")
        assert "***" in result

    def test_email_vazio(self):
        assert "***" in mascarar_email("")
        assert "***" in mascarar_email(None)

    def test_email_usuario_curto(self):
        result = mascarar_email("a@b.com")
        assert "@" in result

    def test_email_mascara_esconde_dados(self):
        result = mascarar_email("maria.santos@empresa.com.br")
        # Não deve conter email original
        assert "maria" not in result
        assert "santos" not in result


class TestMascaraTelefone:
    """Testes de mascaramento de telefone."""

    def test_celular_11_digitos(self):
        result = mascarar_telefone("11987654321")
        assert result == "(11) *****-4321"

    def test_fixo_10_digitos(self):
        result = mascarar_telefone("1132165498")
        assert result == "(11) *****-5498"

    def test_telefone_curto(self):
        result = mascarar_telefone("123")
        assert "****" in result

    def test_telefone_vazio(self):
        result = mascarar_telefone("")
        assert "****" in result
        result = mascarar_telefone(None)
        assert "****" in result

    def test_mascara_mostra_apenas_ddd_e_ultimos4(self):
        result = mascarar_telefone("21999887766")
        assert "(21)" in result
        assert "7766" in result
        assert "9998" not in result


class TestMascaraNome:
    """Testes de mascaramento de nome."""

    def test_nome_completo(self):
        result = mascarar_nome("JOAO DA SILVA")
        assert result.startswith("J")
        assert "JOAO" not in result
        assert "SILVA" not in result

    def test_nome_vazio(self):
        assert mascarar_nome("") == "***"
        assert mascarar_nome(None) == "***"

    def test_nome_curto(self):
        result = mascarar_nome("AB")
        assert "A" in result


class TestMascaraRegistro:
    """Testes de mascaramento de registro completo."""

    def test_mascara_campos_padrao(self):
        reg = {
            "CPF": "12345678901",
            "NOME": "JOAO SILVA",
            "EMAIL_1": "joao@mail.com",
            "EMAIL_2": None,
            "CIDADE": "SAO PAULO",
        }
        result = mascarar_registro(reg)
        assert "12345678901" not in str(result["CPF"])
        assert "JOAO" not in result["NOME"]
        assert result["CIDADE"] == "SAO PAULO"  # não mascarado

    def test_mascara_campos_personalizados(self):
        reg = {"TELEFONE_1": "11987654321", "NOME": "MARIA"}
        result = mascarar_registro(reg, campos_sensiveis=["TELEFONE_1", "NOME"])
        assert "98765" not in str(result["TELEFONE_1"])
        assert "MARIA" not in result["NOME"]


class TestSanitizarString:
    """Testes de sanitização de inputs."""

    def test_remove_null_bytes(self):
        result = sanitizar_string("hello\x00world")
        assert "\x00" not in result

    def test_remove_caracteres_controle(self):
        result = sanitizar_string("abc\x01\x02\x03def")
        assert result == "abc def" or result == "abcdef"

    def test_limita_comprimento(self):
        result = sanitizar_string("a" * 1000, max_length=10)
        assert len(result) == 10

    def test_strip_espacos(self):
        result = sanitizar_string("  hello  world  ")
        assert result == "hello world"

    def test_string_vazia(self):
        assert sanitizar_string("") == ""

    def test_nao_string_retorna_vazio(self):
        assert sanitizar_string(123) == ""
        assert sanitizar_string(None) == ""


class TestNormalizarUf:
    """Testes de normalização de UF."""

    def test_uf_valida(self):
        assert normalizar_uf("sp") == "SP"

    def test_uf_invalida(self):
        assert normalizar_uf("XX") == ""
        assert normalizar_uf("") == ""

    def test_uf_com_espacos(self):
        assert normalizar_uf("  SP  ") == "SP"


class TestNormalizarTexto:
    """Testes de normalização de texto."""

    def test_remove_acentos(self):
        result = normalizar_texto("São Paulo")
        assert result == "SAO PAULO"

    def test_uppercase(self):
        result = normalizar_texto("campinas")
        assert result == "CAMPINAS"

    def test_vazio(self):
        assert normalizar_texto("") == ""
        assert normalizar_texto(None) == ""
