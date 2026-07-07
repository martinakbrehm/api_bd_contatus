"""
api/utils/db_logger.py
----------------------
Persiste entradas de log de consulta na tabela api_log_consultas.
Falhas de banco não propagam — o log nunca bloqueia a resposta da API.
"""

import json
import logging
import threading
from typing import Optional

log = logging.getLogger(__name__)


def registrar_log_consulta(
    *,
    request_id: str,
    endpoint: str,
    usuario_id: Optional[int] = None,
    key_id: Optional[str] = None,
    nome_usuario: Optional[str] = None,
    role: Optional[str] = None,
    ip: Optional[str] = None,
    filtros_json: Optional[dict] = None,
    quantidade_solicitada: Optional[int] = None,
    quantidade_retornada: Optional[int] = None,
    esgotou_base: Optional[bool] = None,
    cache_hit: Optional[bool] = None,
    tempo_ms: Optional[int] = None,
    enriq_tipo: Optional[str] = None,
    enriq_enviados: Optional[int] = None,
    enriq_encontrados: Optional[int] = None,
    status_http: Optional[int] = None,
    erro: Optional[str] = None,
    tipo_lista: Optional[str] = None,
    baixado: Optional[bool] = None,
) -> None:
    """Insere uma linha em api_log_consultas em thread separada (fire-and-forget)."""

    filtros_str = (
        json.dumps(filtros_json, ensure_ascii=False, default=str)
        if filtros_json is not None
        else None
    )

    params = (
        request_id,
        usuario_id,
        key_id,
        nome_usuario,
        role,
        ip,
        endpoint,
        filtros_str,
        quantidade_solicitada,
        quantidade_retornada,
        int(esgotou_base) if esgotou_base is not None else None,
        int(cache_hit) if cache_hit is not None else None,
        tempo_ms,
        enriq_tipo,
        enriq_enviados,
        enriq_encontrados,
        status_http,
        erro,
        tipo_lista,
        int(baixado) if baixado is not None else None,
    )

    def _insert():
        import mysql.connector
        from api.config_db import DB_CONFIG
        try:
            conn = mysql.connector.connect(**DB_CONFIG)
            try:
                cur = conn.cursor()
                cur.execute(
                    """
                    INSERT INTO api_log_consultas (
                        request_id, usuario_id, key_id, nome_usuario, role, ip,
                        endpoint, filtros_json, quantidade_solicitada,
                        quantidade_retornada, esgotou_base, cache_hit, tempo_ms,
                        enriq_tipo, enriq_enviados, enriq_encontrados,
                        status_http, erro,
                        tipo_lista, baixado
                    ) VALUES (
                        %s, %s, %s, %s, %s, %s,
                        %s, %s, %s,
                        %s, %s, %s, %s,
                        %s, %s, %s,
                        %s, %s,
                        %s, %s
                    )
                    """,
                    params,
                )
                conn.commit()
                cur.close()
            finally:
                conn.close()
        except Exception as exc:
            log.warning("db_logger: falha ao inserir log de consulta: %s", exc)

    threading.Thread(target=_insert, daemon=True).start()


def registrar_venda(
    *,
    request_id: str,
    usuario_id: Optional[int] = None,
    nome_cliente: str,
    valor_lista: float,
    parcelado: bool,
    num_parcelas: Optional[int] = None,
    valor_parcela: Optional[float] = None,
    registros_exportados: Optional[int] = None,
) -> None:
    """Insere uma linha em acompanhamento_financeiro para listas de venda."""

    params = (
        request_id,
        usuario_id,
        nome_cliente,
        valor_lista,
        int(parcelado),
        num_parcelas,
        valor_parcela,
        registros_exportados,
    )

    def _insert():
        import mysql.connector
        from api.config_db import DB_CONFIG
        try:
            conn = mysql.connector.connect(**DB_CONFIG)
            try:
                cur = conn.cursor()
                cur.execute(
                    """
                    INSERT INTO acompanhamento_financeiro (
                        request_id, usuario_id, nome_cliente,
                        valor_lista, parcelado, num_parcelas, valor_parcela,
                        registros_exportados
                    ) VALUES (
                        %s, %s, %s,
                        %s, %s, %s, %s,
                        %s
                    )
                    """,
                    params,
                )
                conn.commit()
                cur.close()
            finally:
                conn.close()
        except Exception as exc:
            log.warning("db_logger: falha ao inserir acompanhamento financeiro: %s", exc)

    threading.Thread(target=_insert, daemon=True).start()


def extrair_campos_auth(auth: dict) -> tuple[Optional[str], Optional[str], Optional[int]]:
    """
    Extrai (key_id, nome_usuario, usuario_id) do contexto g.auth_user.

    - API Key: key_id = subject (prefixo lspf_...), nome_usuario = key_nome, usuario_id = None
    - JWT:     key_id = None,                       nome_usuario = subject,   usuario_id = id do DB
    """
    if auth.get("auth_method") == "api_key":
        return auth.get("subject"), auth.get("key_nome"), None
    return None, auth.get("subject"), auth.get("user_id")
