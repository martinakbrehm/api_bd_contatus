"""
api/routes/consulta.py
----------------------
Endpoints de consulta ao banco de dados.

Rotas:
  POST /api/v1/consulta          → consulta com filtros, retorna dados
  POST /api/v1/consulta/contagem → apenas contagem (sem dados pessoais)
  POST /api/v1/consulta/preview  → retorna amostra limitada (max 50)

Todas as rotas requerem autenticação e são auditadas.
"""

import time

from flask import Blueprint, g, jsonify, request

from api.auth.decorators import _get_client_ip, require_auth, require_role
from api.config import (
    BATCH_MAX_ITERACOES,
    MAX_REGISTROS_PADRAO,
    MAX_REGISTROS_POR_CONSULTA,
)
from api.config_db import DB_CONFIG
from api.middleware.timeout_middleware import with_timeout
from api.models.schemas import ValidationError, validar_consulta, validar_contagem
from api.utils.audit_logger import log_data_access, log_security_event
from api.utils.data_cleaner import limpar_dataframe, relatorio_html
from api.utils.data_processor import colunas_saida, processar
from api.utils.query_builder import build_query, descrever_filtros_db
from api.utils.sanitizer import mascarar_registro

import mysql.connector
import pandas as pd

consulta_bp = Blueprint("consulta", __name__, url_prefix="/api/v1/consulta")


def _conectar_banco():
    """Cria conexão com o banco de dados com timeout de sessão."""
    conn = mysql.connector.connect(**DB_CONFIG)
    try:
        from api.config import API_QUERY_TIMEOUT
        cursor = conn.cursor()
        # Timeout de query no MySQL — cancela queries que excedam o limite
        cursor.execute(f"SET SESSION MAX_EXECUTION_TIME = {API_QUERY_TIMEOUT * 1000}")
        cursor.close()
    except Exception:
        pass  # connection_timeout e read_timeout já protegem no DB_CONFIG
    return conn


def _executar_query(sql: str, params: list) -> pd.DataFrame:
    """Executa query e retorna DataFrame. Garante fechamento da conexão."""
    conn = None
    try:
        conn = _conectar_banco()
        df = pd.read_sql(sql, conn, params=params)
        return df
    except Exception:
        raise
    finally:
        if conn is not None:
            try:
                conn.close()
            except Exception:
                pass  # Conexão pode já ter sido encerrada por timeout


def _executar_count(sql_count: str, params: list) -> int:
    """Executa query de contagem e retorna o total de registros no banco."""
    conn = None
    try:
        conn = _conectar_banco()
        cursor = conn.cursor(dictionary=True)
        cursor.execute(sql_count, params)
        resultado = cursor.fetchone()
        cursor.close()
        return int(resultado.get("total", 0)) if resultado else 0
    except Exception:
        raise
    finally:
        if conn is not None:
            try:
                conn.close()
            except Exception:
                pass


def _buscar_ate_quantidade(filtros_particao: dict, quantidade: int) -> tuple[pd.DataFrame, bool, int]:
    """
    Executa o loop de lotes para uma única partição de filtros
    (ex: uma cidade ou um bairro específico).

    Busca `quantidade` registros brutos por lote, aplica limpeza e
    acumula os válidos. Repete com OFFSET até ter `quantidade` registros
    limpos ou esgotar os registros disponíveis na partição.

    Retorna
    -------
    df          : DataFrame com até `quantidade` registros limpos.
    esgotou     : True se a base foi esgotada antes de atingir `quantidade`.
    total_bruto : Total de registros brutos buscados no banco nesta partição.
    """
    filtros_sem_qtd = {**filtros_particao, "quantidade": None}
    df_acumulado = pd.DataFrame()
    offset = 0
    esgotou = False
    total_bruto = 0

    for _ in range(BATCH_MAX_ITERACOES):
        sql_lote, params_lote = build_query(filtros_particao, limite=quantidade, offset=offset)
        df_lote = _executar_query(sql_lote, params_lote)
        total_bruto += len(df_lote)

        if df_lote.empty:
            esgotou = True
            break

        df_limpo, _ = processar(df_lote, filtros_sem_qtd)

        if not df_limpo.empty:
            df_acumulado = (
                pd.concat([df_acumulado, df_limpo], ignore_index=True)
                if not df_acumulado.empty
                else df_limpo.reset_index(drop=True)
            )

        if len(df_acumulado) >= quantidade:
            break

        # Lote retornou menos registros do que o pedido → base esgotada
        if len(df_lote) < quantidade:
            esgotou = True
            break

        offset += quantidade

    df_final = df_acumulado.head(quantidade) if not df_acumulado.empty else pd.DataFrame()
    return df_final, esgotou, total_bruto


@consulta_bp.route("", methods=["POST"])
@require_auth
@require_role("admin", "user")
@with_timeout
def consultar():
    """
    Consulta completa com filtros e busca particionada em lotes.

    A consulta é particionada por dimensões indexadas no banco, garantindo
    `quantidade` registros limpos por partição. Dimensões de particionamento
    (produto cartesiano, em ordem de prioridade de localização):

      Localização : bairros (se informados) > cidades (se múltiplas)
      Gênero      : M e F separados quando genero="ambos"

    A limpeza pesada (CPF/telefone inválido, dados sujos, etc.) ocorre em
    Python após cada lote do banco — não vai para o banco.

    Body (JSON):
    {
      "ufs": ["SP"],
      "cidades": ["SAO PAULO", "CAMPINAS"],
      "bairros": [],
      "genero": "ambos",
      "idade_min": 25,
      "idade_max": 60,
      "email": "nao_filtrar",
      "tem_telefone": "obrigatorio",
      "tipo_telefone": "movel",
      "cbos": [],
      "quantidade": 1000
    }

    → 4 partições: SP×M, SP×F, CAMPINAS×M, CAMPINAS×F
    → até 1000 registros limpos por partição = 4000 total

    Resposta (200):
    {
      "ok": true,
      "total_banco": 120000,
      "total_final": 4000,
      "particoes_consultadas": 4,
      "registros": [...],
      "colunas": [...],
      "filtros_aplicados": "...",
      "esgotou_base": false,
      "tempo_processamento_s": 4.1
    }
    """
    t0 = time.perf_counter()
    client_ip = _get_client_ip()
    auth = g.auth_user
    request_id = getattr(g, "request_id", "")

    # ── Validar input ────────────────────────────────────────
    try:
        data = request.get_json(silent=True) or {}
        filtros = validar_consulta(data)
    except ValidationError as e:
        return jsonify({
            "ok": False,
            "erro": "Dados inválidos.",
            "detalhes": e.erros,
            "request_id": request_id,
        }), 400

    # ── Limitar quantidade (por partição) ────────────────────
    if not filtros.get("quantidade"):
        filtros["quantidade"] = MAX_REGISTROS_PADRAO

    max_allowed = MAX_REGISTROS_POR_CONSULTA
    if auth.get("role") == "admin":
        max_allowed = MAX_REGISTROS_POR_CONSULTA * 2

    if filtros["quantidade"] > max_allowed:
        filtros["quantidade"] = max_allowed

    quantidade_por_particao = filtros["quantidade"]

    try:
        # ── 1. Definir partições ─────────────────────────────
        # Bairros têm prioridade: cada bairro vira uma partição independente.
        # Se não há bairros mas há múltiplas cidades, cada cidade é uma partição.
        # Caso contrário, consulta única sem particionamento.
        bairros = filtros.get("bairros") or []
        cidades = filtros.get("cidades") or []
        genero = (filtros.get("genero") or "AMBOS").upper()

        # ── Dimensão de localização ──────────────────────────
        if bairros:
            loc_particoes = [
                {**filtros, "bairros": [bairro]}
                for bairro in bairros
            ]
        elif len(cidades) > 1:
            loc_particoes = [
                {**filtros, "cidades": [cidade]}
                for cidade in cidades
            ]
        else:
            loc_particoes = [filtros]

        # ── Dimensão de gênero (produto cartesiano) ──────────
        # genero="ambos" → M e F viram partições separadas no banco,
        # garantindo `quantidade` de cada sexo por localização.
        if genero in ("AMBOS",):
            particoes = []
            for p in loc_particoes:
                particoes.append({**p, "genero": "M"})
                particoes.append({**p, "genero": "F"})
        else:
            particoes = loc_particoes

        # ── 2. Contagem total no banco (soma das partições) ──
        total_banco = 0
        for particao in particoes:
            sql_base, params_base = build_query(particao)
            sql_count = "SELECT COUNT(*) AS total\n" + sql_base[sql_base.index("FROM"):]
            total_banco += _executar_count(sql_count, params_base)

        if total_banco == 0:
            duracao = time.perf_counter() - t0
            return jsonify({
                "ok": True,
                "total_banco": 0,
                "total_final": 0,
                "particoes_consultadas": len(particoes),
                "registros": [],
                "colunas": [],
                "filtros_aplicados": descrever_filtros_db(filtros),
                "esgotou_base": True,
                "tempo_processamento_s": round(duracao, 2),
                "request_id": request_id,
            }), 200

        # ── 3. Consulta em lotes por partição ────────────────
        # Para cada partição: busca lotes de `quantidade_por_particao`
        # registros brutos → limpa → acumula até ter o suficiente.
        frames = []
        alguma_esgotou = False

        for particao in particoes:
            df_particao, esgotou = _buscar_ate_quantidade(particao, quantidade_por_particao)
            if esgotou:
                alguma_esgotou = True
            if not df_particao.empty:
                frames.append(df_particao)

        df_final = (
            pd.concat(frames, ignore_index=True)
            if frames
            else pd.DataFrame()
        )
        total_final = len(df_final)

        # ── 3. Selecionar colunas de saída ─────────────────────────────
        incluir_email = filtros.get("email") != "nao_filtrar"
        cols_desejadas = colunas_saida(com_email=incluir_email)
        cols_existentes = [c for c in cols_desejadas if c in df_final.columns]
        df_saida = df_final[cols_existentes].copy() if cols_existentes else df_final

        registros = df_saida.to_dict(orient="records")
        duracao = time.perf_counter() - t0

        # ── Auditoria LGPD ───────────────────────────────────
        log_data_access(
            user=auth.get("subject", "unknown"),
            role=auth.get("role", "unknown"),
            action="CONSULTA",
            filtros=filtros,
            registros_retornados=total_final,
            ip=client_ip,
            request_id=request_id,
        )

        return jsonify({
            "ok": True,
            "total_bruto_buscado": total_bruto_buscado,
            "total_final": total_final,
            "particoes_consultadas": len(particoes),
            "registros": registros,
            "colunas": cols_existentes,
            "filtros_aplicados": descrever_filtros_db(filtros),
            "esgotou_base": alguma_esgotou,
            "tempo_processamento_s": round(duracao, 2),
            "request_id": request_id,
        }), 200

    except ValueError as ve:
        return jsonify({
            "ok": False,
            "erro": str(ve),
            "request_id": request_id,
        }), 400
    except Exception as e:
        log_security_event(
            "QUERY_ERROR",
            severity="ERROR",
            subject=auth.get("subject"),
            error=str(e),
            ip=client_ip,
        )
        return jsonify({
            "ok": False,
            "erro": "Erro interno ao processar a consulta.",
            "request_id": request_id,
        }), 500


@consulta_bp.route("/contagem", methods=["POST"])
@require_auth
@require_role("admin", "user", "readonly")
@with_timeout
def contagem():
    """
    Contagem rápida de registros (sem retornar dados pessoais).
    Acessível por todos os roles, incluindo readonly.

    Body (JSON):
      { "ufs": ["SP"], "cidades": ["SAO PAULO"], ... }

    Resposta (200):
      {
        "ok": true,
        "total_banco": 50000,
        "descricao": "UF: SP | Cidade(s): SAO PAULO | Idade: 18–70"
      }
    """
    t0 = time.perf_counter()
    client_ip = _get_client_ip()
    auth = g.auth_user
    request_id = getattr(g, "request_id", "")

    try:
        data = request.get_json(silent=True) or {}
        filtros = validar_contagem(data)
    except ValidationError as e:
        return jsonify({
            "ok": False,
            "erro": "Dados inválidos.",
            "detalhes": e.erros,
            "request_id": request_id,
        }), 400

    try:
        sql, params = build_query(filtros)
        sql_count = "SELECT COUNT(*) AS total\n" + sql[sql.index("FROM"):]

        conn = None
        try:
            conn = _conectar_banco()
            cursor = conn.cursor(dictionary=True)
            cursor.execute(sql_count, params)
            resultado = cursor.fetchone()
            cursor.close()
        finally:
            if conn is not None:
                try:
                    conn.close()
                except Exception:
                    pass

        total = resultado.get("total", 0) if resultado else 0
        duracao = time.perf_counter() - t0

        log_data_access(
            user=auth.get("subject", "unknown"),
            role=auth.get("role", "unknown"),
            action="CONTAGEM",
            filtros=filtros,
            registros_retornados=0,
            ip=client_ip,
            request_id=request_id,
        )

        return jsonify({
            "ok": True,
            "total_banco": total,
            "descricao": descrever_filtros_db(filtros),
            "tempo_processamento_s": round(duracao, 2),
            "request_id": request_id,
        }), 200

    except ValueError as ve:
        return jsonify({"ok": False, "erro": str(ve)}), 400
    except Exception as e:
        log_security_event(
            "COUNT_QUERY_ERROR",
            severity="ERROR",
            error=str(e),
            ip=client_ip,
        )
        return jsonify({
            "ok": False,
            "erro": "Erro interno ao processar a contagem.",
            "request_id": request_id,
        }), 500


@consulta_bp.route("/preview", methods=["POST"])
@require_auth
@require_role("admin", "user", "readonly")
@with_timeout
def preview():
    """
    Retorna amostra com dados parcialmente mascarados.
    Útil para validar filtros antes de uma consulta completa.
    Máximo 50 registros, CPFs e dados sensíveis mascarados.

    Body (JSON): mesmos campos de /consulta.

    Resposta: registros com CPF, email e telefones mascarados.
    """
    t0 = time.perf_counter()
    client_ip = _get_client_ip()
    auth = g.auth_user
    request_id = getattr(g, "request_id", "")

    try:
        data = request.get_json(silent=True) or {}
        filtros = validar_consulta(data)
    except ValidationError as e:
        return jsonify({
            "ok": False,
            "erro": "Dados inválidos.",
            "detalhes": e.erros,
        }), 400

    # Forçar limite de 50 para preview
    filtros["quantidade"] = min(filtros.get("quantidade") or 50, 50)

    try:
        sql, params = build_query(filtros)
        df_bruto = _executar_query(sql, params)
        total_banco = len(df_bruto)

        if total_banco == 0:
            return jsonify({
                "ok": True,
                "total_banco": 0,
                "registros": [],
                "request_id": request_id,
            }), 200

        df_filtrado, _ = processar(df_bruto, filtros)
        total_final = len(df_filtrado)

        incluir_email = filtros.get("email") != "nao_filtrar"
        cols_desejadas = colunas_saida(com_email=incluir_email)
        cols_existentes = [c for c in cols_desejadas if c in df_filtrado.columns]
        df_saida = df_filtrado[cols_existentes].head(50)

        # Mascarar dados sensíveis no preview
        registros = df_saida.to_dict(orient="records")
        campos_mascarar = ["CPF", "NOME", "EMAIL_1", "EMAIL_2",
                           "TELEFONE_1", "TELEFONE_2", "TELEFONE_3",
                           "TELEFONE_4", "TELEFONE_5", "TELEFONE_6"]
        registros_mascarados = [
            mascarar_registro(r, campos_mascarar) for r in registros
        ]

        duracao = time.perf_counter() - t0

        log_data_access(
            user=auth.get("subject", "unknown"),
            role=auth.get("role", "unknown"),
            action="PREVIEW",
            filtros=filtros,
            registros_retornados=len(registros_mascarados),
            ip=client_ip,
            request_id=request_id,
        )

        return jsonify({
            "ok": True,
            "total_banco": total_banco,
            "total_final": total_final,
            "registros_preview": registros_mascarados,
            "colunas": cols_existentes,
            "nota": "Dados sensíveis mascarados neste preview.",
            "tempo_processamento_s": round(duracao, 2),
            "request_id": request_id,
        }), 200

    except ValueError as ve:
        return jsonify({"ok": False, "erro": str(ve)}), 400
    except Exception as e:
        log_security_event(
            "PREVIEW_ERROR",
            severity="ERROR",
            error=str(e),
            ip=client_ip,
        )
        return jsonify({
            "ok": False,
            "erro": "Erro interno ao gerar preview.",
            "request_id": request_id,
        }), 500
