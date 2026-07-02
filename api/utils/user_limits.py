"""
api/utils/user_limits.py
------------------------
Verificação dos três limites de uso por usuário (tabla usuarios_app).

Limites aplicados em sequência:

  1. limite_por_lista  — cap por requisição individual
                         padrão: admin=1.000.000 / user=250.000
                         override: usuarios_app.limite_por_lista

  2. limite_diario     — teto acumulado no dia corrente
                         NULL = sem limite diário

  3. limite_mensal     — teto acumulado no mês corrente
                         NULL = sem limite mensal

Todos os limites são opcionais (NULL = sem restrição).
Só se aplicam a usuários autenticados via login_usuario (subject = email).
API Keys não têm linha em usuarios_app e não são afetadas.
"""

import logging
from typing import Optional

log = logging.getLogger(__name__)

_ENDPOINTS_CONTABILIZADOS = ("consulta", "contagem", "consulta_async")


def _conectar():
    import mysql.connector
    from api.config_db import DB_CONFIG
    return mysql.connector.connect(**DB_CONFIG)


def _obter_limites_usuario(email: str) -> Optional[dict]:
    """
    Retorna {'limite_por_lista', 'limite_diario', 'limite_mensal'} ou None.
    """
    try:
        conn = _conectar()
        try:
            cur = conn.cursor(dictionary=True)
            cur.execute(
                "SELECT limite_por_lista, limite_diario, limite_mensal "
                "FROM usuarios_app WHERE email = %s AND ativo = 1 LIMIT 1",
                (email,),
            )
            return cur.fetchone()
        finally:
            conn.close()
    except Exception as exc:
        log.warning("user_limits: erro ao buscar limites de %s: %s", email, exc)
        return None


def _consumo_atual(email: str) -> dict:
    """
    Retorna {'consumido_hoje': int, 'consumido_mes': int}
    somando quantidade_retornada de consultas bem-sucedidas do usuário.
    """
    try:
        conn = _conectar()
        try:
            cur = conn.cursor(dictionary=True)
            ph = ", ".join(["%s"] * len(_ENDPOINTS_CONTABILIZADOS))
            cur.execute(
                f"""
                SELECT
                    COALESCE(SUM(CASE WHEN DATE(created_at) = CURDATE()
                                     THEN quantidade_retornada ELSE 0 END), 0) AS consumido_hoje,
                    COALESCE(SUM(CASE WHEN YEAR(created_at)  = YEAR(NOW())
                                      AND MONTH(created_at) = MONTH(NOW())
                                     THEN quantidade_retornada ELSE 0 END), 0) AS consumido_mes
                FROM api_log_consultas
                WHERE nome_usuario = %s
                  AND status_http  = 200
                  AND endpoint     IN ({ph})
                """,
                (email, *_ENDPOINTS_CONTABILIZADOS),
            )
            row = cur.fetchone()
            return {
                "consumido_hoje": int(row["consumido_hoje"]),
                "consumido_mes":  int(row["consumido_mes"]),
            }
        finally:
            conn.close()
    except Exception as exc:
        log.warning("user_limits: erro ao calcular consumo de %s: %s", email, exc)
        return {"consumido_hoje": 0, "consumido_mes": 0}


def verificar_e_ajustar_quantidade(
    nome_usuario: Optional[str],
    role: Optional[str],
    quantidade_solicitada: int,
) -> tuple[int, Optional[str]]:
    """
    Aplica os três limites em sequência e devolve a quantidade permitida.

    Retorna
    -------
    (quantidade_ajustada, erro)
      - erro não None  → requisição deve ser rejeitada com HTTP 429
      - erro None      → quantidade_ajustada já está dentro dos limites
    """
    from api.config import MAX_REGISTROS_POR_ROLE

    # ── 1. Limite por lista ───────────────────────────────────────────────────
    # Padrão do role, override possível por usuario
    limite_por_lista = MAX_REGISTROS_POR_ROLE.get(role or "", 0) or None

    # Apenas usuarios_app têm override individual (subject = email)
    eh_usuario_app = bool(nome_usuario and "@" in nome_usuario)

    limites_db = None
    if eh_usuario_app:
        limites_db = _obter_limites_usuario(nome_usuario)
        if limites_db and limites_db.get("limite_por_lista") is not None:
            limite_por_lista = int(limites_db["limite_por_lista"])

    quantidade = quantidade_solicitada
    if limite_por_lista is not None:
        quantidade = min(quantidade, limite_por_lista)

    # ── 2 & 3. Limites diário e mensal (acumulados) ──────────────────────────
    if not eh_usuario_app or limites_db is None:
        return quantidade, None

    limite_diario = limites_db.get("limite_diario")
    limite_mensal = limites_db.get("limite_mensal")

    if limite_diario is None and limite_mensal is None:
        return quantidade, None

    consumo = _consumo_atual(nome_usuario)
    consumido_hoje = consumo["consumido_hoje"]
    consumido_mes  = consumo["consumido_mes"]

    if limite_diario is not None:
        saldo_diario = limite_diario - consumido_hoje
        if saldo_diario <= 0:
            return 0, (
                f"Limite diário atingido. "
                f"Você já consultou {consumido_hoje:,} registro(s) hoje "
                f"(limite: {limite_diario:,})."
            )
        quantidade = min(quantidade, saldo_diario)

    if limite_mensal is not None:
        saldo_mensal = limite_mensal - consumido_mes
        if saldo_mensal <= 0:
            return 0, (
                f"Limite mensal atingido. "
                f"Você já consultou {consumido_mes:,} registro(s) neste mês "
                f"(limite: {limite_mensal:,})."
            )
        quantidade = min(quantidade, saldo_mensal)

    return quantidade, None
