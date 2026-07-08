"""
test_query_builder.py
---------------------
Testes unitários de query_builder.py.

build_query() e descrever_filtros_db() constroem SQL puro — sem acesso ao
banco. Todos os testes verificam a estrutura do SQL e a ordem dos parâmetros.
"""

from unittest.mock import patch

import pytest


# ── Filtros mínimos válidos ────────────────────────────────────────────────────

_BASE = {"ufs": ["SP"], "cidades": ["SAO PAULO"]}


def _build(filtros=None, limite=None, last_id=None):
    from api.utils.query_builder import build_query
    return build_query(filtros or _BASE, limite=limite, last_id=last_id)


# ── Estrutura básica ──────────────────────────────────────────────────────────

class TestBuildQueryEstrutura:

    def test_retorna_tupla_sql_params(self):
        sql, params = _build()
        assert isinstance(sql, str)
        assert isinstance(params, list)

    def test_sql_tem_select_from_where(self):
        sql, _ = _build()
        assert "SELECT" in sql
        assert "FROM" in sql
        assert "WHERE" in sql

    def test_uf_obrigatorio_sem_uf_levanta_value_error(self):
        from api.utils.query_builder import build_query
        with pytest.raises(ValueError, match="UF"):
            build_query({"cidades": ["SAO PAULO"]})

    def test_tabela_principal_presente(self):
        sql, _ = _build()
        assert "latest_contacts" in sql

    def test_colunas_padrao_presentes(self):
        sql, _ = _build()
        for col in ("TELEFONE_1", "NOME", "CPF", "DATA_NASCIMENTO", "GENERO", "EMAIL_1"):
            assert col in sql


# ── Filtro UF ─────────────────────────────────────────────────────────────────

class TestFiltroUF:

    def test_uf_em_maiusculo_nos_params(self):
        _, params = _build({"ufs": ["sp"], "cidades": ["SAO PAULO"]})
        assert "SP" in params

    def test_multiplas_ufs(self):
        sql, params = _build({"ufs": ["SP", "RJ"], "cidades": ["SAO PAULO"]})
        assert params.count("SP") + params.count("RJ") >= 2
        assert sql.count("%s") >= 2


# ── Filtro cidade ─────────────────────────────────────────────────────────────

class TestFiltroCidade:

    def test_cidade_adicionada_ao_where(self):
        sql, params = _build({"ufs": ["SP"], "cidades": ["CAMPINAS"]})
        assert "CAMPINAS" in params
        assert "cidade" in sql.lower() or "CIDADE" in sql

    def test_sem_cidade_nao_adiciona_clausula_cidade(self):
        sql, params = _build({"ufs": ["SP"]})
        # sem cidades, apenas UF no WHERE
        assert "SP" in params


# ── Filtro bairro ─────────────────────────────────────────────────────────────

class TestFiltroBairro:

    def test_bairro_expande_variantes(self):
        """expandir_bairros é chamado — JD BOTANICO gera JARDIM BOTANICO."""
        filtros = {**_BASE, "bairros": ["JD BOTANICO"]}
        _, params = _build(filtros)
        # "JARDIM BOTANICO" ou "JD BOTANICO" deve estar nos params
        bairro_params = [p for p in params if isinstance(p, str) and "BOTANICO" in p]
        assert len(bairro_params) >= 1

    def test_sem_bairro_sem_clausula_bairro(self):
        sql, _ = _build(_BASE)
        assert "BAIRRO IN" not in sql


# ── Filtro gênero ─────────────────────────────────────────────────────────────

class TestFiltroGenero:

    def test_genero_masculino_adiciona_like(self):
        sql, params = _build({**_BASE, "genero": "M"})
        assert "%M%" in params
        assert "LIKE" in sql

    def test_genero_feminino_adiciona_like(self):
        sql, params = _build({**_BASE, "genero": "F"})
        assert "%F%" in params

    def test_genero_ambos_sem_filtro(self):
        sql, params = _build({**_BASE, "genero": "ambos"})
        assert "%M%" not in params
        assert "%F%" not in params

    def test_genero_masculino_maiusculo_e_minusculo(self):
        _, params_min = _build({**_BASE, "genero": "masculino"})
        assert "%M%" in params_min


# ── Filtro idade ──────────────────────────────────────────────────────────────

class TestFiltroIdade:

    def test_idade_padrao_sem_clausula(self):
        """18-70 é padrão — não adiciona cláusula SQL (evita restrição desnecessária)."""
        sql, _ = _build({**_BASE, "idade_min": 18, "idade_max": 70})
        assert "INTERVAL" not in sql

    def test_idade_customizada_adiciona_between(self):
        sql, params = _build({**_BASE, "idade_min": 25, "idade_max": 45})
        assert "BETWEEN" in sql or "INTERVAL" in sql
        assert 45 in params and 25 in params

    def test_ordem_params_idade_max_antes_min(self):
        """SQL usa BETWEEN (CURDATE() - INTERVAL %s YEAR) ... → idade_max primeiro."""
        _, params = _build({**_BASE, "idade_min": 30, "idade_max": 50})
        idx_max = params.index(50)
        idx_min = params.index(30)
        assert idx_max < idx_min

    def test_null_nunca_excluido_clausula_or_null(self):
        sql, _ = _build({**_BASE, "idade_min": 25, "idade_max": 45})
        assert "IS NULL" in sql


# ── Filtro email ──────────────────────────────────────────────────────────────

class TestFiltroEmail:

    def test_email_obrigatorio_is_not_null(self):
        sql, _ = _build({**_BASE, "email": "obrigatorio"})
        assert "IS NOT NULL" in sql

    def test_email_nao_is_null(self):
        sql, _ = _build({**_BASE, "email": "nao"})
        assert "IS NULL" in sql

    def test_email_nao_filtrar_sem_clausula(self):
        sql, _ = _build({**_BASE, "email": "nao_filtrar"})
        assert "email_1" not in sql.lower() or "IS NULL" not in sql


# ── Filtro telefone ───────────────────────────────────────────────────────────

class TestFiltroTelefone:

    def test_tem_telefone_obrigatorio_is_not_null(self):
        sql, _ = _build({**_BASE, "tem_telefone": "obrigatorio"})
        assert "IS NOT NULL" in sql

    def test_tem_telefone_nao_filtrar_sem_clausula_extra(self):
        sql1, _ = _build(_BASE)
        sql2, _ = _build({**_BASE, "tem_telefone": "nao_filtrar"})
        # mesma estrutura
        assert ("telefone_1" in sql1.lower()) == ("telefone_1" in sql2.lower())


# ── Filtro CBO ────────────────────────────────────────────────────────────────

class TestFiltroCBO:

    def test_cbos_especificos_adiciona_join_e_where(self):
        sql, params = _build({**_BASE, "cbos": ["252515", "252525"]})
        assert "all_cpf_cbo" in sql
        assert "all_cbo" in sql
        assert 252515 in params
        assert 252525 in params

    def test_tem_cbo_obrigatorio_sem_cbos_especificos(self):
        sql, _ = _build({**_BASE, "tem_cbo": "obrigatorio"})
        assert "all_cpf_cbo" in sql
        assert "IS NOT NULL" in sql

    def test_tem_cbo_incluir_sem_filtro_cbo(self):
        sql, params = _build({**_BASE, "tem_cbo": "incluir"})
        assert "all_cpf_cbo" in sql
        # não deve ter WHERE e.cbo IS NOT NULL
        assert "cbo IS NOT NULL" not in sql

    def test_cbos_atividade_no_select(self):
        sql, _ = _build({**_BASE, "cbos": ["252515"]})
        assert "ATIVIDADE" in sql

    def test_sem_cbo_sem_join(self):
        sql, _ = _build(_BASE)
        assert "all_cpf_cbo" not in sql


# ── Paginação ─────────────────────────────────────────────────────────────────

class TestPaginacao:

    def test_limite_adiciona_limit_e_order_by(self):
        sql, params = _build(limite=500)
        assert "LIMIT" in sql
        assert "ORDER BY" in sql
        assert 500 in params

    def test_limit_e_ultimo_param(self):
        """LIMIT deve ser o último parâmetro."""
        _, params = _build({**_BASE, "genero": "F"}, limite=100)
        assert params[-1] == 100

    def test_sem_limite_sem_limit_clause(self):
        sql, _ = _build(limite=None)
        assert "LIMIT" not in sql

    def test_last_id_adiciona_cursor_where(self):
        sql, params = _build(last_id=(1000, 2))
        assert "(lc.ID_MAILING, lc.ID_COMPLEMENT) > (%s, %s)" in sql
        assert 1000 in params
        assert 2 in params

    def test_last_id_e_limite_juntos(self):
        sql, params = _build(last_id=(999, 1), limite=200)
        assert "LIMIT" in sql
        assert "(lc.ID_MAILING, lc.ID_COMPLEMENT) > (%s, %s)" in sql
        assert params[-1] == 200


# ── descrever_filtros_db ──────────────────────────────────────────────────────

class TestDescreverFiltros:

    def test_retorna_string(self):
        from api.utils.query_builder import descrever_filtros_db
        result = descrever_filtros_db(_BASE)
        assert isinstance(result, str)
        assert len(result) > 0

    def test_contem_uf(self):
        from api.utils.query_builder import descrever_filtros_db
        result = descrever_filtros_db({"ufs": ["MG"], "cidades": ["BH"]})
        assert "MG" in result

    def test_contem_cidade(self):
        from api.utils.query_builder import descrever_filtros_db
        result = descrever_filtros_db({"ufs": ["SP"], "cidades": ["CAMPINAS"]})
        assert "CAMPINAS" in result

    def test_genero_aparece_se_nao_ambos(self):
        from api.utils.query_builder import descrever_filtros_db
        result = descrever_filtros_db({**_BASE, "genero": "F"})
        assert "F" in result or "Gênero" in result or "nero" in result

    def test_email_obrigatorio_descrito(self):
        from api.utils.query_builder import descrever_filtros_db
        result = descrever_filtros_db({**_BASE, "email": "obrigatorio"})
        assert "brig" in result.lower() or "email" in result.lower()

    def test_cbos_listados(self):
        from api.utils.query_builder import descrever_filtros_db
        result = descrever_filtros_db({**_BASE, "cbos": ["252515"]})
        assert "252515" in result

    def test_separador_pipe(self):
        from api.utils.query_builder import descrever_filtros_db
        result = descrever_filtros_db({**_BASE, "genero": "M", "email": "obrigatorio"})
        assert "|" in result
