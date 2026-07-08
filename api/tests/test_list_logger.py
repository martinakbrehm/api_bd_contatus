"""
test_list_logger.py
-------------------
Testes unitários de list_logger.registrar_geracao() e registrar_erro().

Usa tmp_path para isolar arquivos CSV dos logs reais.
"""

import csv
from pathlib import Path
from unittest.mock import patch

import pytest


def _ler_csv(path: Path) -> list[dict]:
    with open(path, encoding="utf-8-sig") as f:
        return list(csv.DictReader(f, delimiter=";"))


def _filtros_base():
    return {
        "ufs": ["SP"],
        "cidades": ["SAO PAULO"],
        "bairros": ["CENTRO"],
        "genero": "F",
        "idade_min": 25,
        "idade_max": 50,
        "email": "nao_filtrar",
        "tipo_telefone": "movel",
        "cbos": ["252515"],
        "quantidade": 1000,
    }


# ── registrar_geracao ─────────────────────────────────────────────────────────

class TestRegistrarGeracao:

    def test_cria_arquivo_csv(self, tmp_path):
        arquivo = tmp_path / "geracoes.csv"
        from api.utils import list_logger as ll
        with patch.object(ll, "ARQUIVO_GERACOES", arquivo):
            ll.registrar_geracao(
                filtros=_filtros_base(),
                total_banco=1000,
                total_apos_limpeza=950,
                total_final=900,
                nome_arquivo="lista_2026.xlsx",
                duracao_s=1.23,
            )
        assert arquivo.exists()

    def test_cabecalho_correto(self, tmp_path):
        arquivo = tmp_path / "geracoes.csv"
        from api.utils import list_logger as ll
        with patch.object(ll, "ARQUIVO_GERACOES", arquivo):
            ll.registrar_geracao(
                filtros=_filtros_base(), total_banco=100,
                total_apos_limpeza=90, total_final=80,
                nome_arquivo="f.xlsx", duracao_s=0.5,
            )
        rows = _ler_csv(arquivo)
        assert len(rows) == 1
        for col in ("data_hora", "ufs", "cidades", "total_banco", "status"):
            assert col in rows[0]

    def test_valores_da_linha(self, tmp_path):
        arquivo = tmp_path / "geracoes.csv"
        from api.utils import list_logger as ll
        with patch.object(ll, "ARQUIVO_GERACOES", arquivo):
            ll.registrar_geracao(
                filtros=_filtros_base(),
                total_banco=500,
                total_apos_limpeza=480,
                total_final=400,
                nome_arquivo="lista.xlsx",
                duracao_s=2.5,
                status="OK",
            )
        row = _ler_csv(arquivo)[0]
        assert row["ufs"] == "SP"
        assert row["cidades"] == "SAO PAULO"
        assert row["total_banco"] == "500"
        assert row["total_final"] == "400"
        assert row["nome_arquivo"] == "lista.xlsx"
        assert row["status"] == "OK"
        assert row["duracao_s"] == "2.50"

    def test_cabecalho_escrito_so_uma_vez(self, tmp_path):
        arquivo = tmp_path / "geracoes.csv"
        from api.utils import list_logger as ll
        with patch.object(ll, "ARQUIVO_GERACOES", arquivo):
            for _ in range(3):
                ll.registrar_geracao(
                    filtros=_filtros_base(), total_banco=10,
                    total_apos_limpeza=9, total_final=8,
                    nome_arquivo="f.xlsx", duracao_s=0.1,
                )
        rows = _ler_csv(arquivo)
        assert len(rows) == 3

    def test_cbos_separados_por_pipe(self, tmp_path):
        arquivo = tmp_path / "geracoes.csv"
        filtros = {**_filtros_base(), "cbos": ["252515", "252525"]}
        from api.utils import list_logger as ll
        with patch.object(ll, "ARQUIVO_GERACOES", arquivo):
            ll.registrar_geracao(
                filtros=filtros, total_banco=0, total_apos_limpeza=0,
                total_final=0, nome_arquivo="f.xlsx", duracao_s=0.0,
            )
        row = _ler_csv(arquivo)[0]
        assert "|" in row["cbos"]
        assert "252515" in row["cbos"]

    def test_filtros_vazios_nao_levantam(self, tmp_path):
        arquivo = tmp_path / "geracoes.csv"
        from api.utils import list_logger as ll
        with patch.object(ll, "ARQUIVO_GERACOES", arquivo):
            ll.registrar_geracao(
                filtros={}, total_banco=0, total_apos_limpeza=0,
                total_final=0, nome_arquivo="", duracao_s=0.0,
            )
        assert arquivo.exists()


# ── registrar_erro ────────────────────────────────────────────────────────────

class TestRegistrarErro:

    def test_status_erro(self, tmp_path):
        arquivo = tmp_path / "geracoes.csv"
        from api.utils import list_logger as ll
        with patch.object(ll, "ARQUIVO_GERACOES", arquivo):
            ll.registrar_erro(filtros=_filtros_base(), erro="Traceback: ...")
        row = _ler_csv(arquivo)[0]
        assert row["status"] == "ERRO"

    def test_totais_zerados(self, tmp_path):
        arquivo = tmp_path / "geracoes.csv"
        from api.utils import list_logger as ll
        with patch.object(ll, "ARQUIVO_GERACOES", arquivo):
            ll.registrar_erro(filtros=_filtros_base(), erro="Erro")
        row = _ler_csv(arquivo)[0]
        assert row["total_banco"] == "0"
        assert row["total_final"] == "0"

    def test_observacao_limitada_a_500_chars(self, tmp_path):
        arquivo = tmp_path / "geracoes.csv"
        from api.utils import list_logger as ll
        erro_longo = "X" * 1000
        with patch.object(ll, "ARQUIVO_GERACOES", arquivo):
            ll.registrar_erro(filtros=_filtros_base(), erro=erro_longo)
        row = _ler_csv(arquivo)[0]
        assert len(row["observacao"]) <= 500
