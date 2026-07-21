"""
api/routes/localidades.py
--------------------------
Rotas de apoio para o frontend: lista cidades e bairros disponíveis no banco.

Cidades: servidas do dicionário estático do IBGE (municipios_ibge.json).
         Zero queries no banco — atualizar o JSON quando necessário.

Bairros: query indexada por (UF, cidade) — só toca registros daquela cidade.
         Cache em memória com TTL de 6h para evitar queries repetidas.
"""

import json
import time
from pathlib import Path

import mysql.connector
from flask import Blueprint, g, jsonify, request

from api.auth.decorators import require_auth
from api.db_settings import COLUNAS
from api.utils.data_cleaner import _validar_localidade

# ── Dicionário estático de municípios (IBGE) ──────────────────────────────────
_MUNICIPIOS: dict[str, list[str]] = json.loads(
    (Path(__file__).parent.parent / "utils" / "municipios_ibge.json").read_text(encoding="utf-8")
)

localidades_bp = Blueprint("localidades", __name__, url_prefix="/api/v1/localidades")

_COL_UF     = COLUNAS["uf"]
_COL_CIDADE = COLUNAS["cidade"]
_COL_BAIRRO = COLUNAS["bairro"]

# ── Cache em memória (bairros apenas) ────────────────────────────────────────
_TTL_BAIRROS =  6 * 3600   #  6 horas

# { chave: (timestamp_expira, dados) }
_cache: dict[str, tuple[float, list]] = {}


def _cache_get(chave: str) -> list | None:
    entrada = _cache.get(chave)
    if entrada and time.time() < entrada[0]:
        return entrada[1]
    if chave in _cache:
        del _cache[chave]
    return None


def _cache_set(chave: str, dados: list, ttl: int) -> None:
    _cache[chave] = (time.time() + ttl, dados)


# ── Helpers ───────────────────────────────────────────────────────────────────

def _get_conn():
    from api.config_db import DB_CONFIG
    return mysql.connector.connect(**DB_CONFIG)


# ── Rotas ─────────────────────────────────────────────────────────────────────

@localidades_bp.route("/cidades", methods=["GET"])
@require_auth
def cidades():
    """
    Retorna municípios oficiais (IBGE) para um estado. Zero queries no banco.

    Query params:
      uf  — sigla do estado (obrigatório)

    Resposta:
      { "cidades": [...], "total": N }
    """
    uf = (request.args.get("uf") or "").strip().upper()
    if not uf or len(uf) != 2:
        return jsonify({"erro": "Parâmetro 'uf' obrigatório (2 letras)."}), 400

    lista = _MUNICIPIOS.get(uf, [])
    return jsonify({"uf": uf, "cidades": lista, "total": len(lista)}), 200


@localidades_bp.route("/bairros", methods=["GET"])
@require_auth
def bairros():
    """
    Retorna bairros disponíveis para uma cidade.

    Query params:
      uf     — sigla do estado (obrigatório)
      cidade — nome da cidade  (obrigatório)

    Resposta:
      { "bairros": [...], "total": N, "cache": true|false }
    """
    uf     = (request.args.get("uf")     or "").strip().upper()
    cidade = (request.args.get("cidade") or "").strip().upper()

    if not uf or len(uf) != 2:
        return jsonify({"erro": "Parâmetro 'uf' obrigatório (2 letras)."}), 400
    if not cidade:
        return jsonify({"erro": "Parâmetro 'cidade' obrigatório."}), 400

    chave = f"bairros:{uf}:{cidade}"
    cached = _cache_get(chave)
    if cached is not None:
        return jsonify({"uf": uf, "cidade": cidade, "bairros": cached, "total": len(cached), "cache": True}), 200

    try:
        conn = _get_conn()
        try:
            cur = conn.cursor()
            # Usa o nome canônico diretamente — utf8mb4_unicode_ci já iguala
            # variantes de acento na comparação. Expandir causaria timeout.
            cur.execute(
                f"SELECT {_COL_BAIRRO}, COUNT(*) AS qtd "
                f"FROM {TABELA_PRINCIPAL} "
                f"WHERE {_COL_UF} = %s AND {_COL_CIDADE} = %s "
                f"  AND {_COL_BAIRRO} IS NOT NULL AND {_COL_BAIRRO} != '' "
                f"GROUP BY {_COL_BAIRRO} "
                f"HAVING qtd >= 5 "
                f"ORDER BY {_COL_BAIRRO} "
                f"LIMIT 1000",
                (uf, cidade),
            )
            rows = sorted({
                r[0] for r in cur.fetchall()
                if r[0] and _validar_localidade(r[0])
            })
        finally:
            conn.close()
    except Exception as e:
        return jsonify({"erro": "Erro ao consultar banco.", "detalhe": str(e)}), 500

    _cache_set(chave, rows, _TTL_BAIRROS)
    return jsonify({"uf": uf, "cidade": cidade, "bairros": rows, "total": len(rows), "cache": False}), 200


@localidades_bp.route("/alta-renda", methods=["GET"])
@require_auth
def alta_renda():
    """
    Retorna os bairros de alta renda mapeados para uma cidade.

    Query params:
      uf     — sigla do estado (obrigatório)
      cidade — nome da cidade  (obrigatório)

    Resposta:
      { "bairros": ["JARDIM EUROPA", ...], "mapeada": true|false }
    """
    uf     = (request.args.get("uf")     or "").strip().upper()
    cidade = (request.args.get("cidade") or "").strip().upper()

    if not uf or len(uf) != 2:
        return jsonify({"erro": "Parâmetro 'uf' obrigatório (2 letras)."}), 400
    if not cidade:
        return jsonify({"erro": "Parâmetro 'cidade' obrigatório."}), 400

    from api.utils.alta_renda import buscar_bairros
    bairros_ar, erro_debug = buscar_bairros(uf, cidade)
    return jsonify({
        "uf": uf,
        "cidade": cidade,
        "bairros": bairros_ar,
        "mapeada": len(bairros_ar) > 0,
        "_debug_erro": erro_debug,
    }), 200


@localidades_bp.route("/cache/limpar", methods=["POST"])
@require_auth
def limpar_cache():
    """
    Invalida o cache de localidades (cidades e bairros).
    Requer role admin. Útil após atualização da base.

    Query param opcional:
      uf — limpa só o cache desse estado
    """
    auth = g.auth_user
    if auth.get("role") != "admin":
        return jsonify({"erro": "Apenas administradores podem limpar o cache."}), 403

    uf = (request.args.get("uf") or "").strip().upper()
    removidas = 0

    if uf:
        chaves = [k for k in list(_cache) if k.endswith(f":{uf}") or f":{uf}:" in k]
    else:
        chaves = list(_cache)

    for k in chaves:
        del _cache[k]
        removidas += 1

    return jsonify({
        "mensagem": f"{removidas} entrada(s) removida(s) do cache.",
        "uf": uf or "todas",
    }), 200
