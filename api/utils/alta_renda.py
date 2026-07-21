"""
Lookup de bairros de alta renda por (UF, cidade).
Cache em memória com TTL de 30 minutos para evitar queries repetidas.
"""
from __future__ import annotations

import time
import unicodedata

import mysql.connector

from api.config_db import DB_CONFIG

_CACHE: dict[tuple[str, str], list[str]] = {}
_CACHE_TS: dict[tuple[str, str], float] = {}
_TTL = 1800  # 30 minutos


def _sem_acento(s: str) -> str:
    return "".join(
        c for c in unicodedata.normalize("NFD", s)
        if unicodedata.category(c) != "Mn"
    )


def buscar_bairros(uf: str, cidade: str) -> tuple[list[str], str | None]:
    """
    Retorna (bairros, erro_debug) para (uf, cidade).
    Normaliza acentos antes da query — a tabela bairros_alta_renda não tem acentos.
    """
    uf_norm     = _sem_acento(uf.strip().upper())
    cidade_norm = _sem_acento(cidade.strip().upper())
    chave = (uf_norm, cidade_norm)

    agora = time.monotonic()
    if chave in _CACHE and agora - _CACHE_TS.get(chave, 0) < _TTL:
        return _CACHE[chave], None

    conn = None
    erro_debug = None
    try:
        conn = mysql.connector.connect(**DB_CONFIG)
        cur = conn.cursor()
        cur.execute(
            "SELECT b.bairro "
            "FROM bairros_alta_renda b "
            "JOIN uf u ON u.ID = b.uf_id "
            "WHERE u.UF = %s AND b.cidade = %s "
            "ORDER BY b.ranking, b.bairro",
            (uf_norm, cidade_norm),
        )
        bairros = [row[0] for row in cur.fetchall()]
        cur.close()
    except Exception as exc:
        bairros = []
        erro_debug = str(exc)
    finally:
        if conn:
            try:
                conn.close()
            except Exception:
                pass

    _CACHE[chave] = bairros
    _CACHE_TS[chave] = agora
    return bairros, erro_debug


def limpar_cache() -> None:
    """Força reload do cache na próxima requisição."""
    _CACHE.clear()
    _CACHE_TS.clear()
