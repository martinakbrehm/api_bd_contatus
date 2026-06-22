"""
Lookup de bairros de alta renda por (UF, cidade).
Cache em memória com TTL de 30 minutos para evitar queries repetidas.
"""
from __future__ import annotations

import time

import mysql.connector

from api.config_db import DB_CONFIG

_CACHE: dict[tuple[str, str], list[str]] = {}
_CACHE_TS: dict[tuple[str, str], float] = {}
_TTL = 1800  # 30 minutos


def buscar_bairros(uf: str, cidade: str) -> list[str]:
    """
    Retorna lista de bairros de alta renda para (uf, cidade).
    Lista vazia se a cidade não está mapeada ou a tabela ainda não existe.
    """
    chave = (uf.upper(), cidade.upper())
    agora = time.monotonic()
    if chave in _CACHE and agora - _CACHE_TS.get(chave, 0) < _TTL:
        return _CACHE[chave]

    conn = None
    try:
        conn = mysql.connector.connect(**DB_CONFIG)
        cur = conn.cursor()
        cur.execute(
            "SELECT b.bairro "
            "FROM bairros_alta_renda b "
            "JOIN uf u ON u.ID = b.uf_id "
            "WHERE u.UF = %s AND b.cidade = %s "
            "ORDER BY b.ranking, b.bairro",
            chave,
        )
        bairros = [row[0] for row in cur.fetchall()]
        cur.close()
    except Exception:
        bairros = []
    finally:
        if conn:
            try:
                conn.close()
            except Exception:
                pass

    _CACHE[chave] = bairros
    _CACHE_TS[chave] = agora
    return bairros


def limpar_cache() -> None:
    """Força reload do cache na próxima requisição."""
    _CACHE.clear()
    _CACHE_TS.clear()
