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

import sys
import time
from pathlib import Path

from flask import Blueprint, g, jsonify, request

from api.auth.decorators import _get_client_ip, require_auth, require_role
from api.config import MAX_REGISTROS_PADRAO, MAX_REGISTROS_POR_CONSULTA
from api.models.schemas import ValidationError, validar_consulta, validar_contagem
from api.utils.audit_logger import log_data_access, log_security_event
from api.utils.sanitizer import mascarar_registro

# Importar módulos do projeto pai
_PROJECT_DIR = Path(__file__).parent.parent.parent
sys.path.insert(0, str(_PROJECT_DIR))

from config import DB_CONFIG
from data_cleaner import limpar_dataframe, relatorio_html
from data_processor import colunas_saida, processar
from query_builder import build_query, descrever_filtros_db

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


@consulta_bp.route("", methods=["POST"])
@require_auth
@require_role("admin", "user")
def consultar():
    """
    Consulta completa com filtros.
    Retorna dados processados e limpos.

    Body (JSON):
    {
      "ufs": ["SP", "RJ"],
      "cidades": ["SAO PAULO"],
      "bairros": [],
      "genero": "ambos",
      "idade_min": 25,
      "idade_max": 60,
      "email": "nao_filtrar",
      "tipo_telefone": "movel",
      "cbos": [],
      "quantidade": 1000
    }

    Resposta (200):
    {
      "ok": true,
      "total_banco": 50000,
      "total_final": 1000,
      "registros": [...],
      "colunas": [...],
      "filtros_aplicados": "...",
      "tempo_processamento_s": 2.3
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

    # ── Limitar quantidade ───────────────────────────────────
    if not filtros.get("quantidade"):
        filtros["quantidade"] = MAX_REGISTROS_PADRAO

    max_allowed = MAX_REGISTROS_POR_CONSULTA
    if auth.get("role") == "admin":
        max_allowed = MAX_REGISTROS_POR_CONSULTA * 2

    if filtros["quantidade"] > max_allowed:
        filtros["quantidade"] = max_allowed

    # ── Construir e executar query ───────────────────────────
    try:
        sql, params = build_query(filtros)
        df_bruto = _executar_query(sql, params)
        total_banco = len(df_bruto)

        if total_banco == 0:
            duracao = time.perf_counter() - t0
            return jsonify({
                "ok": True,
                "total_banco": 0,
                "total_final": 0,
                "registros": [],
                "colunas": [],
                "filtros_aplicados": descrever_filtros_db(filtros),
                "tempo_processamento_s": round(duracao, 2),
                "request_id": request_id,
            }), 200

        # ── Pipeline de processamento ────────────────────────
        df_filtrado, rel_limpeza = processar(df_bruto, filtros)
        total_final = len(df_filtrado)

        # Selecionar colunas de saída
        incluir_email = filtros.get("email") != "nao_filtrar"
        cols_desejadas = colunas_saida(com_email=incluir_email)
        cols_existentes = [c for c in cols_desejadas if c in df_filtrado.columns]
        df_saida = df_filtrado[cols_existentes].copy()

        # Converter para lista de dicts
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
            "total_banco": total_banco,
            "total_final": total_final,
            "registros": registros,
            "colunas": cols_existentes,
            "filtros_aplicados": descrever_filtros_db(filtros),
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
