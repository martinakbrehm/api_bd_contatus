"""
test_schemas.py
---------------
Testes de validação de schemas — inputs, limites, injeções.
"""

import pytest

from api.models.schemas import ValidationError, validar_consulta, validar_contagem, validar_login


class TestValidarConsulta:
    """Testes do schema de consulta."""

    # ── UFs ──────────────────────────────────────────────────

    def test_ufs_obrigatorias(self):
        with pytest.raises(ValidationError) as exc:
            validar_consulta({})
        assert any("UF" in e for e in exc.value.erros)

    def test_ufs_lista_vazia_rejeitada(self):
        with pytest.raises(ValidationError):
            validar_consulta({"ufs": []})

    def test_uf_valida_aceita(self):
        result = validar_consulta({"ufs": ["SP"]})
        assert result["ufs"] == ["SP"]

    def test_todas_ufs_validas(self):
        ufs = ["AC", "AL", "AM", "AP", "BA", "CE", "DF", "ES", "GO", "MA",
               "MG", "MS", "MT", "PA", "PB", "PE", "PI", "PR", "RJ", "RN",
               "RO", "RR", "RS", "SC", "SE", "SP", "TO"]
        result = validar_consulta({"ufs": ufs})
        assert len(result["ufs"]) == 27

    def test_uf_invalida_rejeitada(self):
        with pytest.raises(ValidationError) as exc:
            validar_consulta({"ufs": ["XX"]})
        assert any("inválida" in e.lower() or "XX" in e for e in exc.value.erros)

    def test_uf_como_string_parseada(self):
        result = validar_consulta({"ufs": "SP, RJ"})
        assert "SP" in result["ufs"]
        assert "RJ" in result["ufs"]

    def test_uf_lowercase_convertida(self):
        result = validar_consulta({"ufs": ["sp", "rj"]})
        assert result["ufs"] == ["SP", "RJ"]

    # ── Cidades ──────────────────────────────────────────────

    def test_cidades_opcional(self):
        result = validar_consulta({"ufs": ["SP"]})
        assert result["cidades"] == []

    def test_cidades_lista_valida(self):
        result = validar_consulta({"ufs": ["SP"], "cidades": ["SAO PAULO", "CAMPINAS"]})
        assert len(result["cidades"]) == 2

    def test_cidade_muito_longa_rejeitada(self):
        with pytest.raises(ValidationError):
            validar_consulta({"ufs": ["SP"], "cidades": ["X" * 150]})

    def test_cidade_curta_demais_rejeitada(self):
        with pytest.raises(ValidationError):
            validar_consulta({"ufs": ["SP"], "cidades": ["A"]})

    def test_cidade_com_caracteres_perigosos(self):
        with pytest.raises(ValidationError):
            validar_consulta({"ufs": ["SP"], "cidades": ["SAO PAULO<script>"]})

    def test_max_50_cidades(self):
        with pytest.raises(ValidationError):
            validar_consulta({"ufs": ["SP"], "cidades": [f"CIDADE{i}" for i in range(51)]})

    # ── Bairros ──────────────────────────────────────────────

    def test_bairros_opcional(self):
        result = validar_consulta({"ufs": ["SP"]})
        assert result["bairros"] == []

    def test_bairros_como_string_parseada(self):
        result = validar_consulta({"ufs": ["SP"], "bairros": "CENTRO;LIBERDADE"})
        assert "CENTRO" in result["bairros"]
        assert "LIBERDADE" in result["bairros"]

    def test_max_100_bairros(self):
        with pytest.raises(ValidationError):
            validar_consulta({"ufs": ["SP"], "bairros": [f"BAIRRO{i}" for i in range(101)]})

    # ── Gênero ───────────────────────────────────────────────

    def test_genero_ambos_padrao(self):
        result = validar_consulta({"ufs": ["SP"]})
        assert result["genero"] == "AMBOS"

    def test_generos_validos(self):
        for g in ("M", "F", "MASCULINO", "FEMININO", "AMBOS"):
            result = validar_consulta({"ufs": ["SP"], "genero": g})
            assert result["genero"] == g.upper()

    def test_genero_invalido_rejeitado(self):
        with pytest.raises(ValidationError):
            validar_consulta({"ufs": ["SP"], "genero": "OUTRO"})

    # ── Idade ────────────────────────────────────────────────

    def test_idade_padrao_nulo(self):
        result = validar_consulta({"ufs": ["SP"]})
        assert result["idade_min"] is None
        assert result["idade_max"] is None

    def test_idade_valida(self):
        result = validar_consulta({"ufs": ["SP"], "idade_min": 25, "idade_max": 60})
        assert result["idade_min"] == 25
        assert result["idade_max"] == 60

    def test_idade_min_abaixo_18_rejeitada(self):
        with pytest.raises(ValidationError):
            validar_consulta({"ufs": ["SP"], "idade_min": 10})

    def test_idade_max_acima_120_rejeitada(self):
        with pytest.raises(ValidationError):
            validar_consulta({"ufs": ["SP"], "idade_max": 200})

    def test_idade_min_maior_que_max_rejeitada(self):
        with pytest.raises(ValidationError):
            validar_consulta({"ufs": ["SP"], "idade_min": 50, "idade_max": 25})

    def test_idade_nao_numerica_rejeitada(self):
        with pytest.raises(ValidationError):
            validar_consulta({"ufs": ["SP"], "idade_min": "vinte"})

    # ── Email ────────────────────────────────────────────────

    def test_email_opcoes_validas(self):
        for opt in ("obrigatorio", "nao_filtrar", "nao", "preferencial"):
            result = validar_consulta({"ufs": ["SP"], "email": opt})
            assert result["email"] == opt

    def test_email_invalido_rejeitado(self):
        with pytest.raises(ValidationError):
            validar_consulta({"ufs": ["SP"], "email": "invalido"})

    # ── Tipo telefone ────────────────────────────────────────

    def test_telefone_opcoes_validas(self):
        for opt in ("movel", "fixo", "ambos"):
            result = validar_consulta({"ufs": ["SP"], "tipo_telefone": opt})
            assert result["tipo_telefone"] == opt

    def test_telefone_invalido_rejeitado(self):
        with pytest.raises(ValidationError):
            validar_consulta({"ufs": ["SP"], "tipo_telefone": "satelite"})

    # ── Quantidade ───────────────────────────────────────────

    def test_quantidade_valida(self):
        result = validar_consulta({"ufs": ["SP"], "quantidade": 500})
        assert result["quantidade"] == 500

    def test_quantidade_zero_rejeitada(self):
        with pytest.raises(ValidationError):
            validar_consulta({"ufs": ["SP"], "quantidade": 0})

    def test_quantidade_negativa_rejeitada(self):
        with pytest.raises(ValidationError):
            validar_consulta({"ufs": ["SP"], "quantidade": -10})

    def test_quantidade_acima_10000_truncada(self):
        with pytest.raises(ValidationError):
            validar_consulta({"ufs": ["SP"], "quantidade": 99999})

    def test_quantidade_nao_numerica(self):
        with pytest.raises(ValidationError):
            validar_consulta({"ufs": ["SP"], "quantidade": "muitos"})

    # ── CBOs ─────────────────────────────────────────────────

    def test_cbos_opcional(self):
        result = validar_consulta({"ufs": ["SP"]})
        assert result["cbos"] == []

    def test_cbos_validos(self):
        result = validar_consulta({"ufs": ["SP"], "cbos": ["252515", "123456"]})
        assert len(result["cbos"]) == 2

    # ── Consulta completa ────────────────────────────────────

    def test_consulta_completa_valida(self):
        result = validar_consulta({
            "ufs": ["SP", "RJ"],
            "cidades": ["SAO PAULO", "RIO DE JANEIRO"],
            "bairros": ["CENTRO"],
            "genero": "F",
            "idade_min": 25,
            "idade_max": 55,
            "email": "obrigatorio",
            "tipo_telefone": "movel",
            "cbos": ["252515"],
            "quantidade": 5000,
        })
        assert result["ufs"] == ["SP", "RJ"]
        assert result["genero"] == "F"
        assert result["quantidade"] == 5000


class TestValidarLogin:
    """Testes do schema de login."""

    def test_login_api_key_valida(self):
        result = validar_login({"api_key": "lspf_uma_chave_muito_longa_e_segura_1234"})
        assert result["api_key"] == "lspf_uma_chave_muito_longa_e_segura_1234"

    def test_login_sem_api_key(self):
        with pytest.raises(ValidationError):
            validar_login({})

    def test_login_api_key_vazia(self):
        with pytest.raises(ValidationError):
            validar_login({"api_key": ""})

    def test_login_api_key_muito_curta(self):
        with pytest.raises(ValidationError):
            validar_login({"api_key": "abc"})

    def test_login_api_key_muito_longa(self):
        with pytest.raises(ValidationError):
            validar_login({"api_key": "x" * 300})


class TestValidarContagem:
    """Testes do schema de contagem (reutiliza validação de consulta)."""

    def test_contagem_valida(self):
        result = validar_contagem({"ufs": ["MG"]})
        assert result["ufs"] == ["MG"]

    def test_contagem_sem_uf_rejeitada(self):
        with pytest.raises(ValidationError):
            validar_contagem({})
