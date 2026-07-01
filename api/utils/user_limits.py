"""
api/utils/user_limits.py
------------------------
Verificação de limites de uso por usuário (tabla usuarios_app).

Fluxo:
  1. Busca limite_diario e limite_mensal em usuarios_app pelo email.
  2. Soma quantidade_retornada em api_log_consultas (hoje / mês corrente).
  3. Ajusta a quantidade solicitada ao saldo restante, ou rejeita se zerado.

Só se aplica a usuários autenticados via login_usuario (subject = email).
API Keys não têm linha em usuarios_app e não são afetadas.
"""

import logging
from typing import Optional

log = logging.getLogger(__name__)

# Endpoints que contam contra o limite de registros do usuário
_ENDPOINTS_CONTABILIZADOS = ("consulta", "contagem", "consulta_async")


def _conectar():
    import mysql.connector
    from api.config_db import DB_CONFIG
    return mysql.connector.connect(**DB_CONFIG)


def _obter_limites(email: str) -> Optional[dict]:
    """
    Retorna {'limite_diario': int|None, 'limite_mensal': int|None}
    se o email existir em usuarios_app, ou None se não encontrado.
    """
    try:
        conn = _conectar()
        try:
            cur = conn.cursor(dictionary=True)
            cur.execute(
                "SELECT limite_diario, limite_mensal "
                "FROM usuarios_app WHERE email = %s AND ativo = 1 LIMIT 1",
                (email,),
            )
            row = cur.fetchone()
            return row  # pode ser None se não encontrado
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
    quantidade_solicitada: int,
) -> tuple[int, Optional[str]]:
    """
    Verifica limites do usuário e devolve a quantidade permitida.

    Parâmetros
    ----------
    nome_usuario        : email do usuário (None = API Key, sem limites por usuário)
    quantidade_solicitada : quantidade após o clamp de MAX_REGISTROS_POR_CONSULTA

    Retorna
    -------
    (quantidade_ajustada, erro)
      - Se erro não for None, a requisição deve ser rejeitada com HTTP 429.
      - Se quantidade_ajustada < quantidade_solicitada, foi cortada pelo saldo.
    """
    if not nome_usuario or "@" not in nome_usuario:
        # Não é um usuário de usuarios_app — sem limites individuais
        return quantidade_solicitada, None

    limites = _obter_limites(nome_usuario)
    if limites is None:
        # Email não encontrado em usuarios_app → sem limites
        return quantidade_solicitada, None

    limite_diario  = limites.get("limite_diario")
    limite_mensal  = limites.get("limite_mensal")

    if limite_diario is None and limite_mensal is None:
        # Usuário sem limites configurados
        return quantidade_solicitada, None

    consumo = _consumo_atual(nome_usuario)
    consumido_hoje = consumo["consumido_hoje"]
    consumido_mes  = consumo["consumido_mes"]

    saldo_diario  = (limite_diario  - consumido_hoje) if limite_diario  is not None else None
    saldo_mensal  = (limite_mensal  - consumido_mes)  if limite_mensal  is not None else None

    # Verificar limites esgotados
    if saldo_diario is not None and saldo_diario <= 0:
        return 0, (
            f"Limite diário atingido. "
            f"Você já consultou {consumido_hoje:,} registro(s) hoje "
            f"(limite: {limite_diario:,})."
        )

    if saldo_mensal is not None and saldo_mensal <= 0:
        return 0, (
            f"Limite mensal atingido. "
            f"Você já consultou {consumido_mes:,} registro(s) neste mês "
            f"(limite: {limite_mensal:,})."
        )

    # Calcular a menor permissão entre os saldos disponíveis
    saldos_ativos = [s for s in (saldo_diario, saldo_mensal) if s is not None]
    quantidade_permitida = min(quantidade_solicitada, *saldos_ativos)

    return quantidade_permitida, None
