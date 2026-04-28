"""
api/middleware/ip_filter.py
---------------------------
Filtragem de IPs: whitelist e blacklist.

Funciona em duas modalidades:
  - Whitelist (IP_WHITELIST_ENABLED=True): APENAS IPs listados podem acessar
  - Blacklist (sempre ativo): IPs na lista negra são bloqueados

Suporte a CIDR (ex: 192.168.1.0/24).
"""

import ipaddress
import logging
from typing import Optional

from flask import Flask, jsonify, request

from api.config import IP_BLACKLIST, IP_WHITELIST, IP_WHITELIST_ENABLED

logger = logging.getLogger("api.ip_filter")


def _get_real_ip() -> str:
    """Obtém o IP real do cliente."""
    forwarded = request.headers.get("X-Forwarded-For", "")
    if forwarded:
        return forwarded.split(",")[0].strip()
    return request.remote_addr or "0.0.0.0"


def _ip_in_list(ip_str: str, ip_list: list[str]) -> bool:
    """Verifica se um IP está numa lista (suporte a CIDR)."""
    try:
        ip = ipaddress.ip_address(ip_str)
    except ValueError:
        return False

    for entry in ip_list:
        try:
            if "/" in entry:
                network = ipaddress.ip_network(entry, strict=False)
                if ip in network:
                    return True
            else:
                if ip == ipaddress.ip_address(entry):
                    return True
        except ValueError:
            continue

    return False


def ip_filter_middleware(app: Flask) -> None:
    """Registra middleware de filtragem de IP."""

    @app.before_request
    def _check_ip():
        client_ip = _get_real_ip()

        # ── Blacklist (sempre ativo) ─────────────────────────
        if IP_BLACKLIST and _ip_in_list(client_ip, IP_BLACKLIST):
            logger.warning("IP bloqueado (blacklist): %s", client_ip)
            from api.utils.audit_logger import log_security_event
            log_security_event(
                "IP_BLACKLISTED",
                ip=client_ip,
                endpoint=request.endpoint,
            )
            return jsonify({"erro": "Acesso negado."}), 403

        # ── Whitelist (se habilitado) ────────────────────────
        if IP_WHITELIST_ENABLED:
            if not _ip_in_list(client_ip, IP_WHITELIST):
                logger.warning("IP não autorizado (whitelist): %s", client_ip)
                from api.utils.audit_logger import log_security_event
                log_security_event(
                    "IP_NOT_WHITELISTED",
                    ip=client_ip,
                    endpoint=request.endpoint,
                )
                return jsonify({"erro": "Acesso negado."}), 403
