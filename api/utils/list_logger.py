"""
list_logger.py
--------------
Controle interno de listas geradas.

Responsabilidades:
  1. Logging estruturado da aplicação Flask (arquivo rotativo em logs/app/)
  2. Registro de auditoria de cada geração em CSV (logs/geracoes/)
     — permite rastrear quem pediu o quê, quando e quantos registros saíram

Arquivos gerados:
  logs/app/flask_YYYY-MM-DD.log      — log da aplicação (rotativo por dia)
  logs/geracoes/geracoes.csv         — histórico acumulado de gerações
"""

import csv
import logging
import os
from datetime import datetime
from logging.handlers import TimedRotatingFileHandler
from pathlib import Path


# ============================================================
# CAMINHOS BASE
# ============================================================

_BASE = Path(__file__).parent
DIR_LOGS_APP     = _BASE / "logs" / "app"
DIR_LOGS_GERACOES = _BASE / "logs" / "geracoes"
DIR_OUTPUT       = _BASE / "output"

# Garante que as pastas existem em runtime
for _d in (DIR_LOGS_APP, DIR_LOGS_GERACOES, DIR_OUTPUT):
    _d.mkdir(parents=True, exist_ok=True)

ARQUIVO_GERACOES = DIR_LOGS_GERACOES / "geracoes.csv"


# ============================================================
# COLUNAS DO CSV DE AUDITORIA
# ============================================================

_COLUNAS_AUDITORIA = [
    "data_hora",
    "ufs",
    "cidades",
    "bairros",
    "genero",
    "idade_min",
    "idade_max",
    "email",
    "tipo_telefone",
    "cbos",
    "quantidade_solicitada",
    "total_banco",
    "total_apos_limpeza",
    "total_final",
    "nome_arquivo",
    "duracao_s",
    "status",          # OK | ERRO | VAZIO
    "observacao",
]


# ============================================================
# CONFIGURAÇÃO DO LOGGER DA APLICAÇÃO
# ============================================================

def configurar_logging(nivel: str = "INFO") -> logging.Logger:
    """
    Configura e retorna o logger principal da aplicação.

    O log vai para:
      - Console (stdout) — útil em desenvolvimento e Docker
      - Arquivo rotativo diário em logs/app/flask_YYYY-MM-DD.log
        (mantém os últimos 30 dias)

    Uso típico em app.py:
        from api.utils.list_logger import configurar_logging
        logger = configurar_logging()
    """
    nivel_int = getattr(logging, nivel.upper(), logging.INFO)

    logger = logging.getLogger("lista_pf")
    if logger.handlers:
        return logger   # já configurado (evita duplicar handlers)

    logger.setLevel(nivel_int)

    fmt = logging.Formatter(
        "%(asctime)s | %(levelname)-8s | %(name)s | %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )

    # Handler de console
    ch = logging.StreamHandler()
    ch.setFormatter(fmt)
    logger.addHandler(ch)

    # Handler de arquivo rotativo por dia (30 dias de retenção)
    log_arquivo = DIR_LOGS_APP / "flask.log"
    fh = TimedRotatingFileHandler(
        filename=str(log_arquivo),
        when="midnight",
        interval=1,
        backupCount=30,
        encoding="utf-8",
    )
    fh.suffix = "%Y-%m-%d"
    fh.setFormatter(fmt)
    logger.addHandler(fh)

    logger.info("Logger iniciado. Logs em: %s", DIR_LOGS_APP)
    return logger


# ============================================================
# REGISTRO DE CADA GERAÇÃO (AUDITORIA CSV)
# ============================================================

def registrar_geracao(
    filtros:             dict,
    total_banco:         int,
    total_apos_limpeza:  int,
    total_final:         int,
    nome_arquivo:        str,
    duracao_s:           float,
    status:              str = "OK",
    observacao:          str = "",
) -> None:
    """
    Registra uma linha de auditoria no CSV de gerações.

    Parâmetros
    ----------
    filtros             : dict retornado por extrair_filtros()
    total_banco         : registros brutos retornados do banco
    total_apos_limpeza  : após data_cleaner.limpar_dataframe()
    total_final         : após todos os filtros Python + quantidade
    nome_arquivo        : nome do CSV gerado (sem o caminho)
    duracao_s           : tempo total de processamento em segundos
    status              : "OK" | "VAZIO" | "ERRO"
    observacao          : mensagem livre (ex: traceback resumido)
    """
    criar_cabecalho = not ARQUIVO_GERACOES.exists()

    linha = {
        "data_hora":           datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "ufs":                 "|".join(filtros.get("ufs", [])),
        "cidades":             "|".join(filtros.get("cidades", [])),
        "bairros":             "|".join(filtros.get("bairros", [])),
        "genero":              filtros.get("genero", "ambos"),
        "idade_min":           filtros.get("idade_min", ""),
        "idade_max":           filtros.get("idade_max", ""),
        "email":               filtros.get("email", "nao_filtrar"),
        "tipo_telefone":       filtros.get("tipo_telefone", ""),
        "cbos":                "|".join(str(c) for c in filtros.get("cbos", [])),
        "quantidade_solicitada": filtros.get("quantidade", ""),
        "total_banco":         total_banco,
        "total_apos_limpeza":  total_apos_limpeza,
        "total_final":         total_final,
        "nome_arquivo":        nome_arquivo,
        "duracao_s":           f"{duracao_s:.2f}",
        "status":              status,
        "observacao":          observacao,
    }

    with open(ARQUIVO_GERACOES, "a", newline="", encoding="utf-8-sig") as f:
        writer = csv.DictWriter(f, fieldnames=_COLUNAS_AUDITORIA, delimiter=";")
        if criar_cabecalho:
            writer.writeheader()
        writer.writerow(linha)


def registrar_erro(
    filtros:    dict,
    erro:       str,
    duracao_s:  float = 0.0,
) -> None:
    """
    Atalho para registrar uma geração que terminou em erro.
    """
    registrar_geracao(
        filtros=filtros,
        total_banco=0,
        total_apos_limpeza=0,
        total_final=0,
        nome_arquivo="",
        duracao_s=duracao_s,
        status="ERRO",
        observacao=erro[:500],   # limita para não explodir o CSV
    )
