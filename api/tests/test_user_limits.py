"""
test_user_limits.py
--------------------
Testes unitários de user_limits.verificar_e_ajustar_quantidade().

Todos os acessos ao banco são mockados — nenhuma conexão real.
"""

from unittest.mock import patch

import pytest


def _verificar(nome, role, qtd, limites_db=None, consumo=None):
    """Atalho que mocka DB e chama verificar_e_ajustar_quantidade."""
    consumo = consumo or {"consumido_hoje": 0, "consumido_mes": 0}
    with patch("api.utils.user_limits._obter_limites_usuario", return_value=limites_db), \
         patch("api.utils.user_limits._consumo_atual", return_value=consumo):
        from api.utils.user_limits import verificar_e_ajustar_quantidade
        return verificar_e_ajustar_quantidade(nome, role, qtd)


# ── Usuários sem conta (API Keys) ─────────────────────────────────────────────

class TestApiKeys:

    def test_api_key_sem_email_nao_busca_banco(self):
        """Subject sem '@' é API Key — limites de role aplicados, sem acesso DB."""
        qtd, erro = _verificar("lspf_abc123", "user", 100_000)
        assert erro is None
        assert qtd == 100_000

    def test_api_key_admin_sem_limite_por_lista(self):
        qtd, erro = _verificar("lspf_xyz", "admin", 1_000_000)
        assert erro is None
        assert qtd == 1_000_000

    def test_api_key_capped_pelo_role_user(self):
        """Role 'user' tem MAX_REGISTROS_POR_ROLE = 250_000."""
        qtd, erro = _verificar("lspf_xyz", "user", 999_999)
        assert erro is None
        assert qtd <= 250_000

    def test_role_desconhecido_sem_limite(self):
        """Role desconhecido → MAX_REGISTROS_POR_ROLE retorna 0 → tratado como None (sem restrição).
        O bloqueio de readonly ocorre no RBAC da rota, antes dessa função."""
        qtd, erro = _verificar("lspf_xyz", "role_inexistente", 1000)
        assert erro is None  # sem erro, RBAC cuida do bloqueio


# ── Usuários_app sem limites no DB ────────────────────────────────────────────

class TestUsuarioSemLimites:

    def test_sem_linha_no_banco_passa_direto(self):
        """Se _obter_limites_usuario retorna None, não aplica limites diário/mensal."""
        qtd, erro = _verificar("user@email.com", "user", 50_000, limites_db=None)
        assert erro is None
        # quantidade ajustada apenas pelo role (250_000) mas não pelo banco
        assert qtd <= 250_000

    def test_sem_limites_diario_e_mensal(self):
        """Todos os limites None → passa direto."""
        qtd, erro = _verificar(
            "user@email.com", "user", 5_000,
            limites_db={"limite_por_lista": None, "limite_diario": None, "limite_mensal": None},
        )
        assert erro is None
        assert qtd == 5_000


# ── Limite por lista ──────────────────────────────────────────────────────────

class TestLimitePorLista:

    def test_limite_por_lista_db_sobrescreve_role(self):
        """limite_por_lista de 10.000 restringe abaixo do padrão de role."""
        qtd, erro = _verificar(
            "user@email.com", "user", 100_000,
            limites_db={"limite_por_lista": 10_000, "limite_diario": None, "limite_mensal": None},
        )
        assert erro is None
        assert qtd == 10_000

    def test_limite_por_lista_maior_que_solicitado_nao_aumenta(self):
        """Limite maior que o solicitado não aumenta a quantidade."""
        qtd, erro = _verificar(
            "user@email.com", "user", 500,
            limites_db={"limite_por_lista": 50_000, "limite_diario": None, "limite_mensal": None},
        )
        assert erro is None
        assert qtd == 500


# ── Limite diário ─────────────────────────────────────────────────────────────

class TestLimiteDiario:

    def test_limite_diario_atingido_retorna_erro(self):
        """Sem saldo diário → erro 429."""
        _, erro = _verificar(
            "user@email.com", "user", 1_000,
            limites_db={"limite_por_lista": None, "limite_diario": 5_000, "limite_mensal": None},
            consumo={"consumido_hoje": 5_000, "consumido_mes": 5_000},
        )
        assert erro is not None
        assert "diário" in erro or "diario" in erro.lower()

    def test_limite_diario_parcialmente_consumido_ajusta_quantidade(self):
        """Saldo de 2.000 ajusta uma requisição de 5.000."""
        qtd, erro = _verificar(
            "user@email.com", "user", 5_000,
            limites_db={"limite_por_lista": None, "limite_diario": 7_000, "limite_mensal": None},
            consumo={"consumido_hoje": 5_000, "consumido_mes": 5_000},
        )
        assert erro is None
        assert qtd == 2_000

    def test_limite_diario_com_saldo_suficiente_nao_altera(self):
        qtd, erro = _verificar(
            "user@email.com", "user", 1_000,
            limites_db={"limite_por_lista": None, "limite_diario": 10_000, "limite_mensal": None},
            consumo={"consumido_hoje": 0, "consumido_mes": 0},
        )
        assert erro is None
        assert qtd == 1_000


# ── Limite mensal ─────────────────────────────────────────────────────────────

class TestLimiteMensal:

    def test_limite_mensal_atingido_retorna_erro(self):
        _, erro = _verificar(
            "user@email.com", "user", 1_000,
            limites_db={"limite_por_lista": None, "limite_diario": None, "limite_mensal": 50_000},
            consumo={"consumido_hoje": 0, "consumido_mes": 50_000},
        )
        assert erro is not None
        assert "mensal" in erro.lower()

    def test_limite_mensal_parcialmente_consumido_ajusta(self):
        qtd, erro = _verificar(
            "user@email.com", "user", 10_000,
            limites_db={"limite_por_lista": None, "limite_diario": None, "limite_mensal": 50_000},
            consumo={"consumido_hoje": 0, "consumido_mes": 48_000},
        )
        assert erro is None
        assert qtd == 2_000


# ── Combinação de limites ─────────────────────────────────────────────────────

class TestCombinacaoLimites:

    def test_mais_restritivo_prevalece(self):
        """Saldo diário 3.000, saldo mensal 1.000 → resultado = 1.000."""
        qtd, erro = _verificar(
            "user@email.com", "user", 10_000,
            limites_db={"limite_por_lista": None, "limite_diario": 10_000, "limite_mensal": 15_000},
            consumo={"consumido_hoje": 7_000, "consumido_mes": 14_000},
        )
        assert erro is None
        assert qtd == 1_000

    def test_diario_esgotado_antes_de_checar_mensal(self):
        """Diário esgotado → retorna erro sem verificar mensal."""
        _, erro = _verificar(
            "user@email.com", "user", 1_000,
            limites_db={"limite_por_lista": None, "limite_diario": 100, "limite_mensal": 10_000},
            consumo={"consumido_hoje": 100, "consumido_mes": 0},
        )
        assert erro is not None
        assert "diário" in erro or "diario" in erro.lower()

    def test_quantidade_zero_sem_erro_quando_nenhum_limite(self):
        qtd, erro = _verificar("lspf_xyz", "admin", 0)
        assert erro is None
        assert qtd == 0
