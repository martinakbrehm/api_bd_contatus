"""
api/routes/consulta/__init__.py
--------------------------------
Endpoints de consulta ao banco de dados.

Rotas:
  POST /api/v1/consulta              → consulta com filtros, retorna dados
  POST /api/v1/consulta/contagem     → apenas contagem (sem dados pessoais)
  POST /api/v1/consulta/preview      → retorna amostra limitada (max 50)
  POST /api/v1/consulta/gerar        → gera XLSX a partir de token de levantamento
  POST /api/v1/consulta/download     → consulta + download XLSX direto
  POST /api/v1/consulta/iniciar      → inicia job assíncrono, retorna job_id
  GET  /api/v1/consulta/job/<job_id> → status/resultado do job assíncrono

Todas as rotas requerem autenticação e são auditadas.
"""

import datetime
import io
import json
import logging
import os
import re
import threading
import time
import uuid
from pathlib import Path

from flask import Blueprint, g, jsonify, request, send_file

from api.auth.decorators import _get_client_ip, require_auth, require_role
from api.config import (
    BATCH_MAX_ITERACOES,
    BATCH_SIZE_DB,
    CACHE_TTL_SECONDS,
    MAX_REGISTROS_PADRAO,
    MAX_REGISTROS_POR_CONSULTA,
)
from api.utils.cache import cache_get, cache_key, cache_set
from api.config_db import DB_CONFIG
from api.middleware.timeout_middleware import with_timeout
from api.utils.alta_renda import buscar_bairros as _buscar_bairros_ar
from api.utils.audit_logger import log_data_access, log_security_event
from api.utils.db_logger import extrair_campos_auth, registrar_log_consulta, registrar_venda
from api.utils.user_limits import verificar_e_ajustar_quantidade
from api.utils.data_cleaner import limpar_dataframe, relatorio_html
from api.utils.data_processor import colunas_saida, processar
from api.utils.data_quality import metricas_qualidade
from api.utils.job_store import atualizar_job, criar_job, obter_job
from api.utils.query_builder import build_query, descrever_filtros_db
from api.utils.sanitizer import mascarar_registro
from api.utils.xlsx_exporter import gerar_xlsx

log = logging.getLogger(__name__)

from .schema import (
    FILTROS_ETAPA_BANCO,
    FILTROS_ETAPA_PYTHON,
    ValidationError,
    validar_consulta,
    validar_contagem,
    validar_exportacao,
)

import mysql.connector
import pandas as pd

consulta_bp = Blueprint("consulta", __name__, url_prefix="/api/v1/consulta")

# ── Armazenamento temporário de levantamentos ───────────────────────────
_DIR_TEMP = Path(__file__).parent.parent.parent / "output" / "temp"
_UUID4_RE = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$"
)
_TOKEN_MAX_AGE = 1800  # segundos (30 minutos)


def _conectar_banco():
    """Cria conexão com o banco de dados com timeout de sessão."""
    conn = mysql.connector.connect(**DB_CONFIG)
    try:
        from api.config import API_QUERY_TIMEOUT
        cursor = conn.cursor()
        cursor.execute(f"SET SESSION MAX_EXECUTION_TIME = {API_QUERY_TIMEOUT * 1000}")
        cursor.close()
    except Exception:
        pass
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
                pass


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


def _enriquecer_alta_renda(filtros: dict) -> dict:
    """
    Se alta_renda=True e nenhum bairro foi especificado na requisição,
    injeta os bairros de alta renda para cada (uf, cidade) informados.
    Levanta ValueError se alguma cidade não tiver bairros cadastrados.
    """
    if not filtros.get("alta_renda") or filtros.get("bairros"):
        return filtros
    bairros: list[str] = []
    visto: set[str] = set()
    sem_mapeamento: list[str] = []
    for uf in filtros.get("ufs", []):
        for cidade in filtros.get("cidades", []):
            bairros_cidade = _buscar_bairros_ar(uf, cidade)
            if not bairros_cidade:
                sem_mapeamento.append(cidade)
            else:
                for b in bairros_cidade:
                    if b not in visto:
                        bairros.append(b)
                        visto.add(b)
    if sem_mapeamento:
        lista = ", ".join(sem_mapeamento)
        raise ValueError(
            f"A(s) cidade(s) {lista} não possuem bairros de alta renda cadastrados. "
            f"Remova 'alta_renda' para consultar sem esse filtro."
        )
    return {**filtros, "bairros": bairros}


def _buscar_ate_quantidade(
    filtros_particao: dict,
    quantidade: int,
    exclude_cpfs: set[str] | None = None,
    batch_size: int | None = None,
) -> tuple[pd.DataFrame, bool, int]:
    """
    Executa o loop de lotes para uma única partição de filtros.

    ┌─ Etapa 1 — Banco (SQL) ─────────────────────────────────────────────┐
    │  build_query recebe filtros_banco (UF, cidade, bairro, gênero,      │
    │  idade, email, telefone, tem_cbo, cbos) e monta a query indexada.   │
    └─────────────────────────────────────────────────────────────────────┘
    ┌─ Etapa 2 — Python ──────────────────────────────────────────────────┐
    │  processar() aplica limpeza de sujeiras (CPF/email/tel inválidos)   │
    │  e filtra tipo_telefone (móvel/fixo) + email preferencial.          │
    └─────────────────────────────────────────────────────────────────────┘

    Retorna
    -------
    df          : DataFrame com até `quantidade` registros limpos.
    esgotou     : True se a base foi esgotada antes de atingir `quantidade`.
    total_bruto : Total de registros brutos buscados no banco nesta partição.
    """
    # ── Etapa 1: parâmetros SQL (enviados ao banco) ───────────────────────
    filtros_banco = {k: v for k, v in filtros_particao.items() if k in FILTROS_ETAPA_BANCO}

    # ── Etapa 2: parâmetros Python (aplicados pós-query) ─────────────────
    filtros_python = {k: v for k, v in filtros_particao.items() if k in FILTROS_ETAPA_PYTHON}
    filtros_python["quantidade"] = None

    _batch = batch_size if batch_size is not None else BATCH_SIZE_DB

    df_acumulado = pd.DataFrame()
    last_id: tuple[int, int] | None = None
    esgotou = False
    total_bruto = 0

    for _ in range(BATCH_MAX_ITERACOES):
        sql_lote, params_lote = build_query(filtros_banco, limite=_batch, last_id=last_id)
        df_lote = _executar_query(sql_lote, params_lote)
        total_bruto += len(df_lote)

        if df_lote.empty:
            esgotou = True
            break

        # Avança o cursor antes da limpeza Python (usa linhas brutas do banco)
        if "_ID_MAILING" in df_lote.columns and "_ID_COMPLEMENT" in df_lote.columns:
            ultimo = df_lote.sort_values(["_ID_MAILING", "_ID_COMPLEMENT"]).iloc[-1]
            last_id = (int(ultimo["_ID_MAILING"]), int(ultimo["_ID_COMPLEMENT"]))

        # ── Etapa 2: limpeza e filtros Python ────────────────────────────
        df_limpo, _ = processar(df_lote, filtros_python)
        if exclude_cpfs and "CPF" in df_limpo.columns:
            df_limpo = df_limpo[~df_limpo["CPF"].astype(str).isin(exclude_cpfs)]
        if not df_limpo.empty:
            df_acumulado = (
                pd.concat([df_acumulado, df_limpo], ignore_index=True)
                if not df_acumulado.empty
                else df_limpo.reset_index(drop=True)
            )

        if len(df_acumulado) >= quantidade:
            break

        if len(df_lote) < _batch:
            esgotou = True
            break

    df_final = df_acumulado.head(quantidade) if not df_acumulado.empty else pd.DataFrame()
    return df_final, esgotou, total_bruto


def _pipeline_consulta(filtros: dict) -> dict:
    """
    Executa a consulta com os filtros recebidos e retorna os dados.

    Se 'distribuicao' for fornecido: processa cada fatia independentemente
    (cidade, bairro, gênero, quantidade absoluta por fatia) e devolve todos
    os registros merged em uma única lista.
    Caso contrário: executa uma única consulta com os filtros globais.

    Retorna dict com:
      df_saida, cols_existentes, total_bruto_buscado, total_final,
      alguma_esgotou, duracao_s, cache_hit
    """
    t0 = time.perf_counter()

    # ── Cache hit ─────────────────────────────────────────────────────────────
    ck = cache_key(filtros)
    cached = cache_get(ck)
    if cached:
        df = cached["df"]
        meta = cached["meta"]
        usar_cbo = bool(filtros.get("cbos")) or filtros.get("tem_cbo") == "obrigatorio"
        cols_desejadas = colunas_saida(com_atividade=usar_cbo)
        cols_existentes = [c for c in cols_desejadas if c in df.columns]
        return {
            "df_saida":            df[cols_existentes].copy() if cols_existentes else df,
            "cols_existentes":     cols_existentes,
            "total_bruto_buscado": meta.get("total_bruto_buscado", 0),
            "total_final":         len(df),
            "alguma_esgotou":      meta.get("alguma_esgotou", False),
            "duracao_s":           time.perf_counter() - t0,
            "cache_hit":           True,
        }

    dist_items = filtros.get("distribuicao") or []

    # Alta renda no caminho simples (sem distribuicao): injeta bairros antes do loop
    if not dist_items:
        filtros = _enriquecer_alta_renda(filtros)

    cbos_lista = filtros.get("cbos", [])

    if dist_items:
        frames: list[pd.DataFrame] = []
        alguma_esgotou = False
        total_bruto_buscado = 0
        seen_cpfs: set[str] = set()

        for item in dist_items:
            cidade_i = str(item.get("cidade", "")).strip().upper()
            bairro_i = str(item.get("bairro",  "")).strip().upper()
            genero_i = str(item.get("genero",  "AMBOS")).strip().upper()
            qtd_i    = int(item["quantidade"])

            particao = {**filtros}
            particao["cidades"] = [cidade_i] if cidade_i else (filtros.get("cidades") or [])

            # Alta renda por cidade na distribuicao: lookup por cidade específica
            if filtros.get("alta_renda") and not bairro_i:
                bairros_ar: list[str] = []
                visto_ar: set[str] = set()
                for uf in filtros.get("ufs", []):
                    for b in _buscar_bairros_ar(uf, cidade_i):
                        if b not in visto_ar:
                            bairros_ar.append(b)
                            visto_ar.add(b)
                if not bairros_ar:
                    raise ValueError(
                        f"A cidade {cidade_i} não possui bairros de alta renda cadastrados. "
                        f"Remova 'alta_renda' para consultar sem esse filtro."
                    )
                particao["bairros"] = bairros_ar
            else:
                particao["bairros"] = [bairro_i] if bairro_i else (filtros.get("bairros") or [])
            particao["genero"]  = genero_i

            df_p, esgotou, bruto = _buscar_ate_quantidade(particao, qtd_i, exclude_cpfs=seen_cpfs)
            total_bruto_buscado += bruto
            if esgotou:
                alguma_esgotou = True
            if not df_p.empty:
                frames.append(df_p)
                if "CPF" in df_p.columns:
                    seen_cpfs.update(df_p["CPF"].dropna().astype(str).tolist())

        df = pd.concat(frames, ignore_index=True) if frames else pd.DataFrame()
        total_final = len(df)

    elif cbos_lista:
        # Um CBO por vez: batch menor evita timeout sem alterar a query indexada.
        # sem_cidade → batch 200 (scan estadual mais pesado)
        # com_cidade  → batch 500 (índice uf+cidade já filtra bem)
        _batch_cbo = 200 if filtros.get("sem_cidade") else 500
        frames_cbo: list[pd.DataFrame] = []
        alguma_esgotou = False
        total_bruto_buscado = 0
        seen_cpfs_cbo: set[str] = set()
        meta_cap = filtros["quantidade"]

        for cbo in cbos_lista:
            ja_coletados = sum(len(f) for f in frames_cbo)
            if ja_coletados >= meta_cap:
                break
            restante = meta_cap - ja_coletados
            filtros_cbo = {**filtros, "cbos": [cbo], "quantidade": restante}
            df_p, esgotou_p, bruto_p = _buscar_ate_quantidade(
                filtros_cbo, restante,
                exclude_cpfs=seen_cpfs_cbo,
                batch_size=_batch_cbo,
            )
            total_bruto_buscado += bruto_p
            if esgotou_p:
                alguma_esgotou = True
            if not df_p.empty:
                frames_cbo.append(df_p)
                if "CPF" in df_p.columns:
                    seen_cpfs_cbo.update(df_p["CPF"].dropna().astype(str).tolist())

        df = pd.concat(frames_cbo, ignore_index=True) if frames_cbo else pd.DataFrame()
        total_final = len(df)

    else:
        df, alguma_esgotou, total_bruto_buscado = _buscar_ate_quantidade(
            filtros, filtros["quantidade"]
        )
        total_final = len(df)

    usar_cbo = bool(filtros.get("cbos")) or filtros.get("tem_cbo") == "obrigatorio"
    cols_desejadas = colunas_saida(com_atividade=usar_cbo)
    cols_existentes = [c for c in cols_desejadas if c in df.columns]
    df_saida = df[cols_existentes].copy() if cols_existentes else df

    meta_cache = {"total_bruto_buscado": total_bruto_buscado, "alguma_esgotou": alguma_esgotou}
    cache_set(ck, df_saida, meta_cache, ttl=CACHE_TTL_SECONDS)

    return {
        "df_saida":            df_saida,
        "cols_existentes":     cols_existentes,
        "total_bruto_buscado": total_bruto_buscado,
        "total_final":         total_final,
        "alguma_esgotou":      alguma_esgotou,
        "duracao_s":           time.perf_counter() - t0,
        "cache_hit":           False,
    }


@consulta_bp.route("", methods=["POST"])
@require_auth
@require_role("admin", "user")
@with_timeout
def consultar():
    client_ip = _get_client_ip()
    auth = g.auth_user
    request_id = getattr(g, "request_id", "")
    key_id, nome_usuario, usuario_id = extrair_campos_auth(auth)

    try:
        data = request.get_json(silent=True) or {}
        filtros = validar_consulta(data)
    except ValidationError as e:
        registrar_log_consulta(
            request_id=request_id, endpoint="consulta",
            usuario_id=usuario_id, key_id=key_id, nome_usuario=nome_usuario, role=auth.get("role"), ip=client_ip,
            status_http=400, erro="Dados inválidos.",
        )
        return jsonify({"ok": False, "erro": "Dados inválidos.", "detalhes": e.erros, "request_id": request_id}), 400

    if not filtros.get("quantidade"):
        filtros["quantidade"] = MAX_REGISTROS_PADRAO
    max_allowed = MAX_REGISTROS_POR_CONSULTA
    filtros["quantidade"] = min(filtros["quantidade"], max_allowed)

    filtros["quantidade"], limite_erro = verificar_e_ajustar_quantidade(nome_usuario, auth.get("role"), filtros["quantidade"])
    if limite_erro:
        registrar_log_consulta(
            request_id=request_id, endpoint="consulta",
            usuario_id=usuario_id, key_id=key_id, nome_usuario=nome_usuario, role=auth.get("role"), ip=client_ip,
            filtros_json=filtros, quantidade_solicitada=filtros.get("quantidade"),
            status_http=429, erro=limite_erro,
        )
        return jsonify({"ok": False, "erro": limite_erro, "request_id": request_id}), 429

    try:
        resultado = _pipeline_consulta(filtros)
    except ValueError as ve:
        registrar_log_consulta(
            request_id=request_id, endpoint="consulta",
            usuario_id=usuario_id, key_id=key_id, nome_usuario=nome_usuario, role=auth.get("role"), ip=client_ip,
            filtros_json=filtros, quantidade_solicitada=filtros.get("quantidade"),
            status_http=400, erro=str(ve),
        )
        return jsonify({"ok": False, "erro": str(ve), "request_id": request_id}), 400
    except Exception as e:
        log_security_event("QUERY_ERROR", severity="ERROR", subject=auth.get("subject"), error=str(e), ip=client_ip)
        registrar_log_consulta(
            request_id=request_id, endpoint="consulta",
            usuario_id=usuario_id, key_id=key_id, nome_usuario=nome_usuario, role=auth.get("role"), ip=client_ip,
            filtros_json=filtros, quantidade_solicitada=filtros.get("quantidade"),
            status_http=500, erro=str(e),
        )
        return jsonify({"ok": False, "erro": "Erro interno ao processar a consulta.", "request_id": request_id}), 500

    qualidade = metricas_qualidade(resultado["df_saida"])
    log.info(
        "consulta concluída",
        extra={
            "request_id": request_id,
            "user":       auth.get("subject"),
            "action":     "CONSULTA",
            "registros":  resultado["total_final"],
            "latencia_ms": round(resultado["duracao_s"] * 1000),
            "cache_hit":  resultado.get("cache_hit", False),
        },
    )
    log_data_access(user=auth.get("subject", "unknown"), role=auth.get("role", "unknown"),
                    action="CONSULTA", filtros=filtros, registros_retornados=resultado["total_final"],
                    ip=client_ip, request_id=request_id)
    registrar_log_consulta(
        request_id=request_id, endpoint="consulta",
        usuario_id=usuario_id, key_id=key_id, nome_usuario=nome_usuario, role=auth.get("role"), ip=client_ip,
        filtros_json=filtros, quantidade_solicitada=filtros.get("quantidade"),
        quantidade_retornada=resultado["total_final"],
        esgotou_base=resultado["alguma_esgotou"],
        cache_hit=resultado.get("cache_hit", False),
        tempo_ms=round(resultado["duracao_s"] * 1000),
        status_http=200,
    )

    return jsonify({
        "ok":                    True,
        "total_bruto_buscado":   resultado["total_bruto_buscado"],
        "total_final":           resultado["total_final"],
        "registros":             resultado["df_saida"].to_dict(orient="records"),
        "colunas":               resultado["cols_existentes"],
        "qualidade":             qualidade,
        "filtros_aplicados":     descrever_filtros_db(filtros),
        "esgotou_base":          resultado["alguma_esgotou"],
        "cache_hit":             resultado.get("cache_hit", False),
        "tempo_processamento_s": round(resultado["duracao_s"], 2),
        "request_id":            request_id,
    }), 200


@consulta_bp.route("/contagem", methods=["POST"])
@require_auth
@require_role("admin", "user")
@with_timeout
def contagem():
    client_ip = _get_client_ip()
    auth = g.auth_user
    request_id = getattr(g, "request_id", "")
    key_id, nome_usuario, usuario_id = extrair_campos_auth(auth)

    try:
        data = request.get_json(silent=True) or {}
        filtros = validar_consulta(data)
    except ValidationError as e:
        registrar_log_consulta(
            request_id=request_id, endpoint="contagem",
            usuario_id=usuario_id, key_id=key_id, nome_usuario=nome_usuario, role=auth.get("role"), ip=client_ip,
            status_http=400, erro="Dados inválidos.",
        )
        return jsonify({"ok": False, "erro": "Dados inválidos.", "detalhes": e.erros, "request_id": request_id}), 400

    if not filtros.get("quantidade"):
        filtros["quantidade"] = MAX_REGISTROS_PADRAO
    max_allowed = MAX_REGISTROS_POR_CONSULTA
    filtros["quantidade"] = min(filtros["quantidade"], max_allowed)

    filtros["quantidade"], limite_erro = verificar_e_ajustar_quantidade(nome_usuario, auth.get("role"), filtros["quantidade"])
    if limite_erro:
        registrar_log_consulta(
            request_id=request_id, endpoint="contagem",
            usuario_id=usuario_id, key_id=key_id, nome_usuario=nome_usuario, role=auth.get("role"), ip=client_ip,
            filtros_json=filtros, quantidade_solicitada=filtros.get("quantidade"),
            status_http=429, erro=limite_erro,
        )
        return jsonify({"ok": False, "erro": limite_erro, "request_id": request_id}), 429

    try:
        resultado = _pipeline_consulta(filtros)
    except ValueError as ve:
        registrar_log_consulta(
            request_id=request_id, endpoint="contagem",
            usuario_id=usuario_id, key_id=key_id, nome_usuario=nome_usuario, role=auth.get("role"), ip=client_ip,
            filtros_json=filtros, quantidade_solicitada=filtros.get("quantidade"),
            status_http=400, erro=str(ve),
        )
        return jsonify({"ok": False, "erro": str(ve), "request_id": request_id}), 400
    except Exception as e:
        log_security_event("LEVANTAMENTO_ERROR", severity="ERROR", subject=auth.get("subject"), error=str(e), ip=client_ip)
        registrar_log_consulta(
            request_id=request_id, endpoint="contagem",
            usuario_id=usuario_id, key_id=key_id, nome_usuario=nome_usuario, role=auth.get("role"), ip=client_ip,
            filtros_json=filtros, quantidade_solicitada=filtros.get("quantidade"),
            status_http=500, erro=str(e),
        )
        return jsonify({"ok": False, "erro": "Erro interno ao processar o levantamento.", "request_id": request_id}), 500

    df_saida = resultado["df_saida"]
    total_disponivel = len(df_saida)
    quantidade_pedida = filtros["quantidade"]

    token = str(uuid.uuid4())
    _DIR_TEMP.mkdir(parents=True, exist_ok=True)
    try:
        df_saida.to_parquet(_DIR_TEMP / f"{token}.parquet", index=False)
        meta = {
            "filtros_aplicados":     descrever_filtros_db(filtros),
            "total_bruto_buscado":   resultado["total_bruto_buscado"],
            "total_final":           total_disponivel,
            "esgotou_base":          resultado["alguma_esgotou"],
            "tempo_processamento_s": round(resultado["duracao_s"], 2),
        }
        (_DIR_TEMP / f"{token}.json").write_text(json.dumps(meta, ensure_ascii=False), encoding="utf-8")
    except Exception:
        return jsonify({"ok": False, "erro": "Erro ao salvar resultado do levantamento.", "request_id": request_id}), 500

    log_data_access(user=auth.get("subject", "unknown"), role=auth.get("role", "unknown"),
                    action="LEVANTAMENTO", filtros=filtros, registros_retornados=total_disponivel,
                    ip=client_ip, request_id=request_id)
    registrar_log_consulta(
        request_id=request_id, endpoint="contagem",
        usuario_id=usuario_id, key_id=key_id, nome_usuario=nome_usuario, role=auth.get("role"), ip=client_ip,
        filtros_json=filtros, quantidade_solicitada=quantidade_pedida,
        quantidade_retornada=total_disponivel,
        esgotou_base=resultado["alguma_esgotou"],
        cache_hit=resultado.get("cache_hit", False),
        tempo_ms=round(resultado["duracao_s"] * 1000),
        status_http=200,
    )

    return jsonify({
        "ok":                    True,
        "total_disponivel":      total_disponivel,
        "suficiente":            total_disponivel >= quantidade_pedida,
        "quantidade_pedida":     quantidade_pedida,
        "resultado_token":       token,
        "descricao":             descrever_filtros_db(filtros),
        "tempo_processamento_s": round(resultado["duracao_s"], 2),
        "request_id":            request_id,
    }), 200


@consulta_bp.route("/gerar", methods=["POST"])
@require_auth
@require_role("admin", "user")
@with_timeout
def gerar():
    client_ip = _get_client_ip()
    auth = g.auth_user
    request_id = getattr(g, "request_id", "")
    key_id, nome_usuario, usuario_id = extrair_campos_auth(auth)

    data = request.get_json(silent=True) or {}
    token = str(data.get("resultado_token", "")).strip().lower()

    if not _UUID4_RE.match(token):
        return jsonify({"ok": False, "erro": "Token inválido.", "request_id": request_id}), 400

    try:
        exportacao = validar_exportacao(data)
    except ValidationError as e:
        return jsonify({"ok": False, "erro": "Dados de exportação inválidos.", "detalhes": e.erros, "request_id": request_id}), 400

    caminho_parquet = _DIR_TEMP / f"{token}.parquet"
    if not caminho_parquet.exists():
        registrar_log_consulta(
            request_id=request_id, endpoint="gerar",
            usuario_id=usuario_id, key_id=key_id, nome_usuario=nome_usuario, role=auth.get("role"), ip=client_ip,
            tipo_lista=exportacao["tipo_lista"], baixado=False,
            status_http=410, erro="Token não encontrado.",
        )
        return jsonify({"ok": False, "erro": "Token não encontrado. Refaça o levantamento.", "request_id": request_id}), 410

    if time.time() - caminho_parquet.stat().st_mtime > _TOKEN_MAX_AGE:
        try:
            caminho_parquet.unlink(missing_ok=True)
            (_DIR_TEMP / f"{token}.json").unlink(missing_ok=True)
        except Exception:
            pass
        registrar_log_consulta(
            request_id=request_id, endpoint="gerar",
            usuario_id=usuario_id, key_id=key_id, nome_usuario=nome_usuario, role=auth.get("role"), ip=client_ip,
            tipo_lista=exportacao["tipo_lista"], baixado=False,
            status_http=410, erro="Token expirado.",
        )
        return jsonify({"ok": False, "erro": "Token expirado. Refaça o levantamento.", "request_id": request_id}), 410

    try:
        df = pd.read_parquet(caminho_parquet)
    except Exception:
        registrar_log_consulta(
            request_id=request_id, endpoint="gerar",
            usuario_id=usuario_id, key_id=key_id, nome_usuario=nome_usuario, role=auth.get("role"), ip=client_ip,
            tipo_lista=exportacao["tipo_lista"], baixado=False,
            status_http=500, erro="Erro ao ler parquet.",
        )
        return jsonify({"ok": False, "erro": "Erro ao ler resultado do levantamento.", "request_id": request_id}), 500

    if df.empty:
        registrar_log_consulta(
            request_id=request_id, endpoint="gerar",
            usuario_id=usuario_id, key_id=key_id, nome_usuario=nome_usuario, role=auth.get("role"), ip=client_ip,
            tipo_lista=exportacao["tipo_lista"], baixado=False,
            status_http=404, erro="Levantamento sem registros.",
        )
        return jsonify({"ok": False, "erro": "O levantamento não encontrou registros.", "request_id": request_id}), 404

    meta: dict = {}
    caminho_meta = _DIR_TEMP / f"{token}.json"
    if caminho_meta.exists():
        try:
            meta = json.loads(caminho_meta.read_text(encoding="utf-8"))
        except Exception:
            pass

    log_data_access(user=auth.get("subject", "unknown"), role=auth.get("role", "unknown"),
                    action="GERAR_XLSX", filtros={"resultado_token": token},
                    registros_retornados=len(df), ip=client_ip, request_id=request_id)
    registrar_log_consulta(
        request_id=request_id, endpoint="gerar",
        usuario_id=usuario_id, key_id=key_id, nome_usuario=nome_usuario, role=auth.get("role"), ip=client_ip,
        quantidade_retornada=len(df),
        tipo_lista=exportacao["tipo_lista"],
        baixado=True,
        status_http=200,
    )
    if exportacao["tipo_lista"] == "venda":
        registrar_venda(
            request_id=request_id,
            usuario_id=auth.get("user_id"),
            nome_cliente=exportacao["nome_cliente"],
            valor_lista=exportacao["valor_lista"],
            parcelado=exportacao["parcelado"],
            num_parcelas=exportacao["num_parcelas"],
            valor_parcela=exportacao["valor_parcela"],
            registros_exportados=len(df),
        )

    buf = gerar_xlsx(df, meta)
    nome = f"lista_{datetime.datetime.now():%Y%m%d_%H%M%S}.xlsx"
    return send_file(buf, as_attachment=True, download_name=nome,
                     mimetype="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet")


@consulta_bp.route("/preview", methods=["POST"])
@require_auth
@require_role("admin", "user", "readonly")
@with_timeout
def preview():
    t0 = time.perf_counter()
    client_ip = _get_client_ip()
    auth = g.auth_user
    request_id = getattr(g, "request_id", "")
    key_id, nome_usuario, usuario_id = extrair_campos_auth(auth)

    try:
        data = request.get_json(silent=True) or {}
        filtros = validar_consulta(data)
    except ValidationError as e:
        registrar_log_consulta(
            request_id=request_id, endpoint="preview",
            usuario_id=usuario_id, key_id=key_id, nome_usuario=nome_usuario, role=auth.get("role"), ip=client_ip,
            status_http=400, erro="Dados inválidos.",
        )
        return jsonify({"ok": False, "erro": "Dados inválidos.", "detalhes": e.erros}), 400

    filtros["quantidade"] = min(filtros.get("quantidade") or 50, 50)
    filtros = _enriquecer_alta_renda(filtros)

    try:
        sql, params = build_query(filtros)
        df_bruto = _executar_query(sql, params)
        total_banco = len(df_bruto)

        if total_banco == 0:
            registrar_log_consulta(
                request_id=request_id, endpoint="preview",
                usuario_id=usuario_id, key_id=key_id, nome_usuario=nome_usuario, role=auth.get("role"), ip=client_ip,
                filtros_json=filtros, quantidade_solicitada=filtros.get("quantidade"),
                quantidade_retornada=0, esgotou_base=True,
                tempo_ms=round((time.perf_counter() - t0) * 1000),
                status_http=200,
            )
            return jsonify({"ok": True, "total_banco": 0, "registros": [], "request_id": request_id}), 200

        df_filtrado, _ = processar(df_bruto, filtros)
        cols_desejadas = colunas_saida()
        cols_existentes = [c for c in cols_desejadas if c in df_filtrado.columns]
        df_saida = df_filtrado[cols_existentes].head(50)

        campos_mascarar = ["CPF", "NOME", "EMAIL_1", "EMAIL_2",
                           "TELEFONE_1", "TELEFONE_2", "TELEFONE_3",
                           "TELEFONE_4", "TELEFONE_5", "TELEFONE_6"]
        registros_mascarados = [mascarar_registro(r, campos_mascarar)
                                for r in df_saida.to_dict(orient="records")]

        log_data_access(user=auth.get("subject", "unknown"), role=auth.get("role", "unknown"),
                        action="PREVIEW", filtros=filtros, registros_retornados=len(registros_mascarados),
                        ip=client_ip, request_id=request_id)
        registrar_log_consulta(
            request_id=request_id, endpoint="preview",
            usuario_id=usuario_id, key_id=key_id, nome_usuario=nome_usuario, role=auth.get("role"), ip=client_ip,
            filtros_json=filtros, quantidade_solicitada=filtros.get("quantidade"),
            quantidade_retornada=len(registros_mascarados),
            tempo_ms=round((time.perf_counter() - t0) * 1000),
            status_http=200,
        )

        return jsonify({
            "ok": True,
            "total_banco": total_banco,
            "total_final": len(df_filtrado),
            "registros_preview": registros_mascarados,
            "colunas": cols_existentes,
            "nota": "Dados sensíveis mascarados neste preview.",
            "tempo_processamento_s": round(time.perf_counter() - t0, 2),
            "request_id": request_id,
        }), 200

    except ValueError as ve:
        registrar_log_consulta(
            request_id=request_id, endpoint="preview",
            usuario_id=usuario_id, key_id=key_id, nome_usuario=nome_usuario, role=auth.get("role"), ip=client_ip,
            filtros_json=filtros, status_http=400, erro=str(ve),
        )
        return jsonify({"ok": False, "erro": str(ve)}), 400
    except Exception as e:
        log_security_event("PREVIEW_ERROR", severity="ERROR", error=str(e), ip=client_ip)
        registrar_log_consulta(
            request_id=request_id, endpoint="preview",
            usuario_id=usuario_id, key_id=key_id, nome_usuario=nome_usuario, role=auth.get("role"), ip=client_ip,
            filtros_json=filtros, status_http=500, erro=str(e),
        )
        return jsonify({"ok": False, "erro": "Erro interno ao gerar preview.", "request_id": request_id}), 500


@consulta_bp.route("/download", methods=["POST"])
@require_auth
@require_role("admin", "user")
@with_timeout
def download():
    client_ip = _get_client_ip()
    auth = g.auth_user
    request_id = getattr(g, "request_id", "")
    key_id, nome_usuario, usuario_id = extrair_campos_auth(auth)

    data = request.get_json(silent=True) or {}

    try:
        filtros = validar_consulta(data)
    except ValidationError as e:
        registrar_log_consulta(
            request_id=request_id, endpoint="download",
            usuario_id=usuario_id, key_id=key_id, nome_usuario=nome_usuario, role=auth.get("role"), ip=client_ip,
            status_http=400, erro="Dados inválidos.",
        )
        return jsonify({"ok": False, "erro": "Dados inválidos.", "detalhes": e.erros, "request_id": request_id}), 400

    try:
        exportacao = validar_exportacao(data)
    except ValidationError as e:
        registrar_log_consulta(
            request_id=request_id, endpoint="download",
            usuario_id=usuario_id, key_id=key_id, nome_usuario=nome_usuario, role=auth.get("role"), ip=client_ip,
            status_http=400, erro="Dados de exportação inválidos.",
        )
        return jsonify({"ok": False, "erro": "Dados de exportação inválidos.", "detalhes": e.erros, "request_id": request_id}), 400

    if not filtros.get("quantidade"):
        filtros["quantidade"] = MAX_REGISTROS_PADRAO
    max_allowed = MAX_REGISTROS_POR_CONSULTA
    filtros["quantidade"] = min(filtros["quantidade"], max_allowed)

    filtros["quantidade"], limite_erro = verificar_e_ajustar_quantidade(nome_usuario, auth.get("role"), filtros["quantidade"])
    if limite_erro:
        registrar_log_consulta(
            request_id=request_id, endpoint="download",
            usuario_id=usuario_id, key_id=key_id, nome_usuario=nome_usuario, role=auth.get("role"), ip=client_ip,
            filtros_json=filtros, quantidade_solicitada=filtros.get("quantidade"),
            tipo_lista=exportacao["tipo_lista"], baixado=False,
            status_http=429, erro=limite_erro,
        )
        return jsonify({"ok": False, "erro": limite_erro, "request_id": request_id}), 429

    try:
        resultado = _pipeline_consulta(filtros)
    except ValueError as ve:
        registrar_log_consulta(
            request_id=request_id, endpoint="download",
            usuario_id=usuario_id, key_id=key_id, nome_usuario=nome_usuario, role=auth.get("role"), ip=client_ip,
            filtros_json=filtros, quantidade_solicitada=filtros.get("quantidade"),
            tipo_lista=exportacao["tipo_lista"], baixado=False,
            status_http=400, erro=str(ve),
        )
        return jsonify({"ok": False, "erro": str(ve), "request_id": request_id}), 400
    except Exception as e:
        log_security_event("DOWNLOAD_ERROR", severity="ERROR", subject=auth.get("subject"), error=str(e), ip=client_ip)
        registrar_log_consulta(
            request_id=request_id, endpoint="download",
            usuario_id=usuario_id, key_id=key_id, nome_usuario=nome_usuario, role=auth.get("role"), ip=client_ip,
            filtros_json=filtros, quantidade_solicitada=filtros.get("quantidade"),
            tipo_lista=exportacao["tipo_lista"], baixado=False,
            status_http=500, erro=str(e),
        )
        return jsonify({"ok": False, "erro": "Erro interno ao gerar o arquivo.", "request_id": request_id}), 500

    if resultado["df_saida"].empty:
        registrar_log_consulta(
            request_id=request_id, endpoint="download",
            usuario_id=usuario_id, key_id=key_id, nome_usuario=nome_usuario, role=auth.get("role"), ip=client_ip,
            filtros_json=filtros, quantidade_solicitada=filtros.get("quantidade"),
            quantidade_retornada=0,
            tipo_lista=exportacao["tipo_lista"], baixado=False,
            status_http=404, erro="Nenhum registro encontrado.",
        )
        return jsonify({"ok": False, "erro": "Nenhum registro encontrado.", "request_id": request_id}), 404

    log_data_access(user=auth.get("subject", "unknown"), role=auth.get("role", "unknown"),
                    action="DOWNLOAD_XLSX", filtros=filtros, registros_retornados=resultado["total_final"],
                    ip=client_ip, request_id=request_id)
    registrar_log_consulta(
        request_id=request_id, endpoint="download",
        usuario_id=usuario_id, key_id=key_id, nome_usuario=nome_usuario, role=auth.get("role"), ip=client_ip,
        filtros_json=filtros, quantidade_solicitada=filtros.get("quantidade"),
        quantidade_retornada=resultado["total_final"],
        esgotou_base=resultado["alguma_esgotou"],
        cache_hit=resultado.get("cache_hit", False),
        tempo_ms=round(resultado["duracao_s"] * 1000),
        tipo_lista=exportacao["tipo_lista"],
        baixado=True,
        status_http=200,
    )
    if exportacao["tipo_lista"] == "venda":
        registrar_venda(
            request_id=request_id,
            usuario_id=auth.get("user_id"),
            nome_cliente=exportacao["nome_cliente"],
            valor_lista=exportacao["valor_lista"],
            parcelado=exportacao["parcelado"],
            num_parcelas=exportacao["num_parcelas"],
            valor_parcela=exportacao["valor_parcela"],
            registros_exportados=resultado["total_final"],
        )

    resumo_xlsx = {
        "filtros_aplicados":     descrever_filtros_db(filtros),
        "total_bruto_buscado":   resultado["total_bruto_buscado"],
        "total_final":           resultado["total_final"],
        "esgotou_base":          resultado["alguma_esgotou"],
        "tempo_processamento_s": round(resultado["duracao_s"], 2),
    }

    buf = gerar_xlsx(resultado["df_saida"], resumo_xlsx)
    nome = f"lista_{datetime.datetime.now():%Y%m%d_%H%M%S}.xlsx"
    return send_file(buf, as_attachment=True, download_name=nome,
                     mimetype="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet")


# ── Job assíncrono ────────────────────────────────────────────────────────────

def _executar_job(job_id: str, filtros: dict, user: str, ip: str, key_id: str | None = None, usuario_id: int | None = None) -> None:
    """Worker rodando em thread separada. Atualiza job_store ao concluir."""
    atualizar_job(job_id, status="processando")
    try:
        resultado = _pipeline_consulta(filtros)
        df = resultado["df_saida"]

        # Salva parquet para download posterior
        _DIR_TEMP.mkdir(parents=True, exist_ok=True)
        parquet_path = _DIR_TEMP / f"{job_id}.parquet"
        df.to_parquet(parquet_path, index=False)

        meta = {
            "filtros_aplicados":     descrever_filtros_db(filtros),
            "total_bruto_buscado":   resultado["total_bruto_buscado"],
            "total_final":           resultado["total_final"],
            "esgotou_base":          resultado["alguma_esgotou"],
            "qualidade":             metricas_qualidade(df),
            "tempo_processamento_s": round(resultado["duracao_s"], 2),
            "cache_hit":             resultado.get("cache_hit", False),
        }
        (_DIR_TEMP / f"{job_id}.json").write_text(
            json.dumps(meta, ensure_ascii=False), encoding="utf-8"
        )

        log_data_access(user=user, role="async_job", action="JOB_CONCLUIDO",
                        filtros=filtros, registros_retornados=resultado["total_final"],
                        ip=ip, request_id=job_id)
        registrar_log_consulta(
            request_id=job_id, endpoint="consulta_async",
            usuario_id=usuario_id, key_id=key_id, nome_usuario=user, ip=ip,
            filtros_json=filtros, quantidade_solicitada=filtros.get("quantidade"),
            quantidade_retornada=resultado["total_final"],
            esgotou_base=resultado["alguma_esgotou"],
            cache_hit=resultado.get("cache_hit", False),
            tempo_ms=round(resultado["duracao_s"] * 1000),
            status_http=200,
        )

        atualizar_job(job_id, status="concluido", resultado=meta)

    except Exception as exc:
        log.error("Job %s falhou: %s", job_id, exc)
        registrar_log_consulta(
            request_id=job_id, endpoint="consulta_async",
            usuario_id=usuario_id, key_id=key_id, nome_usuario=user, ip=ip,
            filtros_json=filtros, quantidade_solicitada=filtros.get("quantidade"),
            status_http=500, erro=str(exc),
        )
        atualizar_job(job_id, status="erro", erro=str(exc))


@consulta_bp.route("/iniciar", methods=["POST"])
@require_auth
@require_role("admin", "user")
def iniciar():
    """
    Inicia uma extração assíncrona em background.

    Body: mesmos filtros do POST /consulta.
    Resposta imediata (202):
      { "job_id": "...", "status": "processando" }

    Após concluir, acessar GET /consulta/job/<job_id> para resultado
    e GET /consulta/job/<job_id>/xlsx para download.
    """
    client_ip = _get_client_ip()
    auth = g.auth_user
    request_id = getattr(g, "request_id", "")

    try:
        data = request.get_json(silent=True) or {}
        filtros = validar_consulta(data)
    except ValidationError as e:
        return jsonify({"ok": False, "erro": "Dados inválidos.", "detalhes": e.erros, "request_id": request_id}), 400

    if not filtros.get("quantidade"):
        filtros["quantidade"] = MAX_REGISTROS_PADRAO
    max_allowed = MAX_REGISTROS_POR_CONSULTA
    filtros["quantidade"] = min(filtros["quantidade"], max_allowed)

    key_id, nome_usuario, usuario_id = extrair_campos_auth(auth)

    filtros["quantidade"], limite_erro = verificar_e_ajustar_quantidade(nome_usuario, auth.get("role"), filtros["quantidade"])
    if limite_erro:
        return jsonify({"ok": False, "erro": limite_erro, "request_id": request_id}), 429

    job_id = criar_job(filtros)
    t = threading.Thread(
        target=_executar_job,
        args=(job_id, filtros, nome_usuario or auth.get("subject", "unknown"), client_ip, key_id, usuario_id),
        daemon=True,
    )
    t.start()

    log.info("job iniciado", extra={"request_id": request_id, "user": auth.get("subject"), "action": "JOB_INICIADO", "job_id": job_id})

    return jsonify({
        "ok":         True,
        "job_id":     job_id,
        "status":     "processando",
        "request_id": request_id,
    }), 202


@consulta_bp.route("/job/<job_id>", methods=["GET"])
@require_auth
@require_role("admin", "user")
def status_job(job_id: str):
    """
    Retorna status e resultado de um job assíncrono.

    Quando status == 'concluido':
      resultado contém total_final, qualidade, filtros_aplicados, etc.
      Use GET /consulta/job/<job_id>/xlsx para baixar o arquivo.
    """
    request_id = getattr(g, "request_id", "")

    if not re.match(r"^[0-9a-f]{32}$", job_id):
        return jsonify({"ok": False, "erro": "job_id inválido.", "request_id": request_id}), 400

    job = obter_job(job_id)
    if job is None:
        return jsonify({"ok": False, "erro": "Job não encontrado ou expirado.", "request_id": request_id}), 404

    resposta = {
        "ok":         True,
        "job_id":     job_id,
        "status":     job["status"],
        "request_id": request_id,
    }
    if job["status"] == "concluido":
        resposta["resultado"]      = job["resultado"]
        resposta["xlsx_url"]       = f"/api/v1/consulta/job/{job_id}/xlsx"
        resposta["xlsx_metodo"]    = "POST"
        resposta["xlsx_nota"]      = "Enviar tipo_lista (e dados financeiros se venda) no body."
    elif job["status"] == "erro":
        resposta["erro"] = job["erro"]

    return jsonify(resposta), 200


@consulta_bp.route("/job/<job_id>/xlsx", methods=["POST"])
@require_auth
@require_role("admin", "user")
def download_job(job_id: str):
    """
    Download do XLSX de um job assíncrono concluído.

    Body obrigatório (mesmo da rota /gerar):
      tipo_lista   "venda" | "consulta_geral" | "teste"
      + campos financeiros quando tipo_lista == "venda"
    """
    client_ip = _get_client_ip()
    request_id = getattr(g, "request_id", "")
    auth = g.auth_user
    key_id, nome_usuario, usuario_id = extrair_campos_auth(auth)

    if not re.match(r"^[0-9a-f]{32}$", job_id):
        return jsonify({"ok": False, "erro": "job_id inválido.", "request_id": request_id}), 400

    data = request.get_json(silent=True) or {}
    try:
        exportacao = validar_exportacao(data)
    except ValidationError as e:
        return jsonify({"ok": False, "erro": "Dados de exportação inválidos.", "detalhes": e.erros, "request_id": request_id}), 400

    job = obter_job(job_id)
    if job is None:
        return jsonify({"ok": False, "erro": "Job não encontrado ou expirado.", "request_id": request_id}), 404
    if job["status"] != "concluido":
        return jsonify({"ok": False, "erro": f"Job ainda não concluído (status: {job['status']}).", "request_id": request_id}), 409

    parquet_path = _DIR_TEMP / f"{job_id}.parquet"
    if not parquet_path.exists():
        registrar_log_consulta(
            request_id=request_id, endpoint="download_job",
            usuario_id=usuario_id, key_id=key_id, nome_usuario=nome_usuario, role=auth.get("role"), ip=client_ip,
            tipo_lista=exportacao["tipo_lista"], baixado=False,
            status_http=410, erro="Parquet do job não encontrado.",
        )
        return jsonify({"ok": False, "erro": "Arquivo de resultado não encontrado.", "request_id": request_id}), 410

    try:
        df = pd.read_parquet(parquet_path)
    except Exception:
        registrar_log_consulta(
            request_id=request_id, endpoint="download_job",
            usuario_id=usuario_id, key_id=key_id, nome_usuario=nome_usuario, role=auth.get("role"), ip=client_ip,
            tipo_lista=exportacao["tipo_lista"], baixado=False,
            status_http=500, erro="Erro ao ler parquet do job.",
        )
        return jsonify({"ok": False, "erro": "Erro ao ler resultado do job.", "request_id": request_id}), 500

    meta = job.get("resultado", {})
    log_data_access(user=auth.get("subject", "unknown"), role=auth.get("role", "unknown"),
                    action="DOWNLOAD_JOB_XLSX", filtros={"job_id": job_id},
                    registros_retornados=len(df), ip=client_ip, request_id=request_id)
    registrar_log_consulta(
        request_id=request_id, endpoint="download_job",
        usuario_id=usuario_id, key_id=key_id, nome_usuario=nome_usuario, role=auth.get("role"), ip=client_ip,
        quantidade_retornada=len(df),
        tipo_lista=exportacao["tipo_lista"],
        baixado=True,
        status_http=200,
    )
    if exportacao["tipo_lista"] == "venda":
        registrar_venda(
            request_id=request_id,
            usuario_id=auth.get("user_id"),
            nome_cliente=exportacao["nome_cliente"],
            valor_lista=exportacao["valor_lista"],
            parcelado=exportacao["parcelado"],
            num_parcelas=exportacao["num_parcelas"],
            valor_parcela=exportacao["valor_parcela"],
            registros_exportados=len(df),
        )

    buf = gerar_xlsx(df, meta)
    nome = f"lista_{datetime.datetime.now():%Y%m%d_%H%M%S}.xlsx"
    return send_file(buf, as_attachment=True, download_name=nome,
                     mimetype="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet")
