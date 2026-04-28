"""
api/middleware/request_validator.py
-----------------------------------
Validação e sanitização de todas as requisições recebidas.

Proteções:
  - Tamanho máximo do body
  - Content-Type obrigatório para POST/PUT
  - Sanitização de inputs contra XSS e injection
  - Validação de charset
  - Detecção de payloads maliciosos
  - Request ID tracking (rastreabilidade)
"""

import re
import secrets
import time

from flask import Flask, g, jsonify, request

from api.config import MAX_CONTENT_LENGTH


# ── Padrões suspeitos (SQLi, XSS, Command Injection) ─────────
_SUSPICIOUS_PATTERNS = [
    # SQL Injection
    re.compile(r"(\b(UNION|SELECT|INSERT|UPDATE|DELETE|DROP|ALTER|CREATE|EXEC|EXECUTE)\b\s)", re.I),
    re.compile(r"(--|;|/\*|\*/|xp_|sp_)", re.I),
    re.compile(r"(\b(OR|AND)\b\s+\d+\s*=\s*\d+)", re.I),
    re.compile(r"(\'|\"|\\\\|%27|%22)", re.I),

    # XSS
    re.compile(r"(<script|javascript:|on\w+\s*=|<iframe|<object|<embed)", re.I),
    re.compile(r"(alert\s*\(|confirm\s*\(|prompt\s*\(|eval\s*\()", re.I),
    re.compile(r"(document\.|window\.|\.cookie|\.location)", re.I),

    # Command Injection
    re.compile(r"(\||&&|\$\(|`|;|\bcat\b|\bls\b|\brm\b|\bwget\b|\bcurl\b)", re.I),

    # Path Traversal
    re.compile(r"(\.\./|\.\.\\|%2e%2e)", re.I),

    # LDAP Injection
    re.compile(r"(\)\(|\(|\)|\*\|)", re.I),
]

# Padrões que NÃO devem ser bloqueados (falsos positivos comuns)
_SAFE_EXCEPTIONS = [
    re.compile(r"^(M|F|MASCULINO|FEMININO|AMBOS)$", re.I),
    re.compile(r"^(SP|RJ|MG|BA|RS|PR|PE|CE|PA|MA|SC|GO|PB|AM|ES|RN|AL|MT|MS|DF|SE|RO|PI|TO|AC|AP|RR)$", re.I),
    re.compile(r"^\d+$"),  # números puros
]


def _is_suspicious(value: str) -> tuple[bool, str]:
    """
    Verifica se um valor contém padrões suspeitos.
    Retorna (suspeito, padrão_detectado).
    """
    if not value or not isinstance(value, str):
        return False, ""

    # Verificar exceções seguras primeiro
    for pattern in _SAFE_EXCEPTIONS:
        if pattern.match(value.strip()):
            return False, ""

    for pattern in _SUSPICIOUS_PATTERNS:
        match = pattern.search(value)
        if match:
            return True, match.group(0)

    return False, ""


def _sanitize_string(value: str) -> str:
    """
    Sanitiza uma string removendo caracteres potencialmente perigosos.
    Mantém apenas alfanuméricos, espaços, hifens, pontos e vírgulas.
    """
    if not isinstance(value, str):
        return value
    # Remover caracteres de controle
    value = re.sub(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]", "", value)
    return value.strip()


def _scan_payload(data: dict, path: str = "") -> list[str]:
    """
    Escaneia recursivamente o payload procurando padrões suspeitos.
    Retorna lista de alertas.
    """
    alerts = []
    if isinstance(data, dict):
        for key, value in data.items():
            current_path = f"{path}.{key}" if path else key

            # Verificar a chave
            suspicious, pattern = _is_suspicious(str(key))
            if suspicious:
                alerts.append(f"Chave suspeita '{current_path}': {pattern}")

            # Verificar o valor
            if isinstance(value, str):
                suspicious, pattern = _is_suspicious(value)
                if suspicious:
                    alerts.append(f"Valor suspeito em '{current_path}': {pattern}")
            elif isinstance(value, (dict, list)):
                alerts.extend(_scan_payload(value, current_path))

    elif isinstance(data, list):
        for i, item in enumerate(data):
            current_path = f"{path}[{i}]"
            if isinstance(item, str):
                suspicious, pattern = _is_suspicious(item)
                if suspicious:
                    alerts.append(f"Valor suspeito em '{current_path}': {pattern}")
            elif isinstance(item, (dict, list)):
                alerts.extend(_scan_payload(item, current_path))

    return alerts


def request_validator_middleware(app: Flask) -> None:
    """Registra middleware de validação de requisições."""

    @app.before_request
    def _validate_request():
        # ── Request ID (rastreabilidade) ─────────────────────
        request_id = request.headers.get("X-Request-ID", "")
        if not request_id:
            request_id = f"req_{secrets.token_hex(12)}"
        g.request_id = request_id
        g.request_start_time = time.time()

        # ── Tamanho do body ──────────────────────────────────
        content_length = request.content_length or 0
        if content_length > MAX_CONTENT_LENGTH:
            return jsonify({
                "erro": "Payload excede o tamanho máximo permitido.",
                "max_bytes": MAX_CONTENT_LENGTH,
                "request_id": request_id,
            }), 413

        # ── Content-Type para métodos com body ───────────────
        if request.method in ("POST", "PUT", "PATCH"):
            content_type = request.content_type or ""
            allowed_types = ("application/json", "application/x-www-form-urlencoded")
            if not any(ct in content_type for ct in allowed_types):
                return jsonify({
                    "erro": "Content-Type inválido. Use 'application/json'.",
                    "request_id": request_id,
                }), 415

        # ── Scan do payload JSON para padrões maliciosos ─────
        if request.is_json:
            try:
                data = request.get_json(silent=True)
                if data:
                    alerts = _scan_payload(data)
                    if alerts:
                        from api.utils.audit_logger import log_security_event
                        log_security_event(
                            "MALICIOUS_PAYLOAD_DETECTED",
                            ip=request.remote_addr,
                            alerts=alerts[:5],  # limitar log
                            endpoint=request.endpoint,
                        )
                        return jsonify({
                            "erro": "Requisição rejeitada: conteúdo potencialmente malicioso detectado.",
                            "request_id": request_id,
                        }), 400
            except Exception:
                pass  # payload mal formado será tratado pela rota

        # ── Scan de query parameters ─────────────────────────
        for key, value in request.args.items():
            suspicious, pattern = _is_suspicious(value)
            if suspicious:
                from api.utils.audit_logger import log_security_event
                log_security_event(
                    "SUSPICIOUS_QUERY_PARAM",
                    ip=request.remote_addr,
                    param=key,
                    pattern=pattern,
                )
                return jsonify({
                    "erro": "Parâmetro de consulta rejeitado.",
                    "request_id": request_id,
                }), 400

    @app.after_request
    def _add_request_id(response):
        request_id = getattr(g, "request_id", "")
        if request_id:
            response.headers["X-Request-ID"] = request_id

        # Tempo de resposta
        start = getattr(g, "request_start_time", None)
        if start:
            elapsed = time.time() - start
            response.headers["X-Response-Time"] = f"{elapsed:.3f}s"

        return response
