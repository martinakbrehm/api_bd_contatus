"""
api/utils/cache.py
------------------
Cache Redis para resultados de consulta.

- Chave: SHA256 dos filtros normalizados (sort_keys=True)
- Valor: DataFrame serializado como parquet (hex) + metadados JSON
- TTL: configurável via CACHE_TTL_SECONDS (padrão 30 min)
- Graceful degradation: se Redis indisponível, opera sem cache silenciosamente
"""

import hashlib
import io
import json
import logging
import os

import pandas as pd

log = logging.getLogger(__name__)

_client = None   # singleton lazy-initialized


def _get_client():
    global _client
    if _client is not None:
        return _client

    url = os.environ.get("REDIS_URL", "")
    if not url:
        return None

    try:
        import redis
        c = redis.from_url(url, socket_connect_timeout=2, socket_timeout=2, decode_responses=False)
        c.ping()
        _client = c
        log.info("Cache Redis conectado: %s", url.split("@")[-1])
    except Exception as exc:
        log.warning("Redis indisponível — cache desabilitado: %s", exc)
        _client = None

    return _client


# ── Chave de cache ───────────────────────────────────────────────────────────

def cache_key(filtros: dict) -> str:
    """SHA256 dos filtros normalizados — garante mesma chave para mesma consulta."""
    payload = json.dumps(filtros, sort_keys=True, ensure_ascii=False, default=str)
    digest = hashlib.sha256(payload.encode()).hexdigest()
    return f"consulta:{digest}"


# ── Leitura ──────────────────────────────────────────────────────────────────

def cache_get(key: str) -> dict | None:
    """
    Retorna resultado cacheado ou None.

    Retorno quando encontrado:
      {"df": DataFrame, "meta": dict, "cache_hit": True}
    """
    client = _get_client()
    if client is None:
        return None

    try:
        raw = client.get(key)
        if raw is None:
            return None

        payload = json.loads(raw)
        df = pd.read_parquet(io.BytesIO(bytes.fromhex(payload["df_hex"])))
        return {"df": df, "meta": payload["meta"], "cache_hit": True}

    except Exception as exc:
        log.warning("Erro ao ler cache [%s]: %s", key[:20], exc)
        return None


# ── Escrita ──────────────────────────────────────────────────────────────────

def cache_set(key: str, df: pd.DataFrame, meta: dict, ttl: int) -> None:
    """Persiste DataFrame + metadados no Redis com TTL em segundos."""
    client = _get_client()
    if client is None:
        return

    try:
        buf = io.BytesIO()
        df.to_parquet(buf, index=False)
        payload = json.dumps(
            {"df_hex": buf.getvalue().hex(), "meta": meta},
            ensure_ascii=False,
        )
        client.setex(key, ttl, payload)
    except Exception as exc:
        log.warning("Erro ao gravar cache [%s]: %s", key[:20], exc)


# ── Invalidação manual ───────────────────────────────────────────────────────

def cache_delete(key: str) -> None:
    client = _get_client()
    if client is None:
        return
    try:
        client.delete(key)
    except Exception:
        pass


def cache_flush_consultas() -> int:
    """Remove todas as chaves do padrão 'consulta:*'. Retorna quantidade deletada."""
    client = _get_client()
    if client is None:
        return 0
    try:
        keys = client.keys("consulta:*")
        if keys:
            client.delete(*keys)
        return len(keys)
    except Exception as exc:
        log.warning("Erro ao limpar cache: %s", exc)
        return 0
