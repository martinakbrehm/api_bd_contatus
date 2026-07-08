"""
test_audit_logger.py
--------------------
Testes unitários de audit_logger.

Verifica estrutura JSON dos eventos sem escrever em arquivo real
(loggers são mockados).
"""

import json
from unittest.mock import MagicMock, patch

import pytest


def _capturar_log(fn, *args, **kwargs):
    """Executa fn e captura a string JSON passada para o logger."""
    captured = {}
    mock_logger = MagicMock()
    def _store(msg):
        captured["entry"] = json.loads(msg)
    mock_logger.info.side_effect = _store
    mock_logger.warning.side_effect = _store
    mock_logger.error.side_effect = _store
    mock_logger.critical.side_effect = _store
    return mock_logger, captured


# ── _json_entry ───────────────────────────────────────────────────────────────

class TestJsonEntry:

    def test_sempre_tem_timestamp(self):
        from api.utils.audit_logger import _json_entry
        entry = json.loads(_json_entry(event="TEST"))
        assert "timestamp" in entry

    def test_sempre_tem_epoch(self):
        from api.utils.audit_logger import _json_entry
        entry = json.loads(_json_entry(event="TEST"))
        assert "epoch" in entry
        assert isinstance(entry["epoch"], float)

    def test_campos_extras_incluidos(self):
        from api.utils.audit_logger import _json_entry
        entry = json.loads(_json_entry(event="TEST", campo="valor", numero=42))
        assert entry["campo"] == "valor"
        assert entry["numero"] == 42

    def test_campo_nao_serializavel_usa_str(self):
        """Objetos não-JSON usam default=str."""
        from api.utils.audit_logger import _json_entry
        import datetime
        entry = json.loads(_json_entry(event="TEST", ts=datetime.datetime(2026, 1, 1)))
        assert "ts" in entry


# ── log_request ───────────────────────────────────────────────────────────────

class TestLogRequest:

    def test_campos_obrigatorios(self):
        from api.utils.audit_logger import log_request
        captured = []
        with patch("api.utils.audit_logger._audit_logger") as mock:
            mock.info.side_effect = lambda m: captured.append(json.loads(m))
            log_request("POST", "/api/v1/consulta", 200, "127.0.0.1")
        assert len(captured) == 1
        e = captured[0]
        assert e["event"] == "REQUEST"
        assert e["method"] == "POST"
        assert e["path"] == "/api/v1/consulta"
        assert e["status_code"] == 200
        assert e["ip"] == "127.0.0.1"

    def test_campos_opcionais_incluidos(self):
        from api.utils.audit_logger import log_request
        captured = []
        with patch("api.utils.audit_logger._audit_logger") as mock:
            mock.info.side_effect = lambda m: captured.append(json.loads(m))
            log_request(
                "GET", "/api/v1/health", 200, "10.0.0.1",
                user="joao@email.com", role="user",
                auth_method="jwt", response_time_ms=12.5,
                request_id="req_abc123",
            )
        e = captured[0]
        assert e["user"] == "joao@email.com"
        assert e["role"] == "user"
        assert e["auth_method"] == "jwt"
        assert e["response_time_ms"] == 12.5
        assert e["request_id"] == "req_abc123"

    def test_campos_opcionais_none_aceitos(self):
        from api.utils.audit_logger import log_request
        with patch("api.utils.audit_logger._audit_logger"):
            log_request("GET", "/health", 200, "127.0.0.1")


# ── log_security_event ────────────────────────────────────────────────────────

class TestLogSecurityEvent:

    def test_campos_obrigatorios(self):
        from api.utils.audit_logger import log_security_event
        captured = []
        with patch("api.utils.audit_logger._security_logger") as mock:
            mock.warning.side_effect = lambda m: captured.append(json.loads(m))
            log_security_event("JWT_AUTH_FAILED", severity="WARNING", ip="1.2.3.4")
        e = captured[0]
        assert e["event"] == "SECURITY"
        assert e["event_type"] == "JWT_AUTH_FAILED"
        assert e["severity"] == "WARNING"
        assert e["ip"] == "1.2.3.4"

    def test_severity_warning_chama_warning(self):
        from api.utils.audit_logger import log_security_event
        with patch("api.utils.audit_logger._security_logger") as mock:
            log_security_event("RATE_LIMIT_EXCEEDED", severity="WARNING")
        mock.warning.assert_called_once()
        mock.error.assert_not_called()

    def test_severity_error_chama_error(self):
        from api.utils.audit_logger import log_security_event
        with patch("api.utils.audit_logger._security_logger") as mock:
            log_security_event("QUERY_ERROR", severity="ERROR")
        mock.error.assert_called_once()

    def test_severity_critical_chama_critical(self):
        from api.utils.audit_logger import log_security_event
        with patch("api.utils.audit_logger._security_logger") as mock:
            log_security_event("DATA_BREACH", severity="CRITICAL")
        mock.critical.assert_called_once()

    def test_kwargs_extras_incluidos(self):
        from api.utils.audit_logger import log_security_event
        captured = []
        with patch("api.utils.audit_logger._security_logger") as mock:
            mock.warning.side_effect = lambda m: captured.append(json.loads(m))
            log_security_event("BRUTE_FORCE_BLOCKED", ip="1.2.3.4", subject="user@x.com")
        e = captured[0]
        assert e["ip"] == "1.2.3.4"
        assert e["subject"] == "user@x.com"


# ── log_data_access ───────────────────────────────────────────────────────────

class TestLogDataAccess:

    def test_campos_obrigatorios(self):
        from api.utils.audit_logger import log_data_access
        captured = []
        with patch("api.utils.audit_logger._audit_logger") as mock_audit, \
             patch("api.utils.audit_logger._security_logger"):
            mock_audit.info.side_effect = lambda m: captured.append(json.loads(m))
            log_data_access(
                user="joao@email.com",
                role="user",
                action="CONSULTA",
                filtros={"ufs": ["SP"]},
                registros_retornados=500,
                ip="127.0.0.1",
            )
        e = captured[0]
        assert e["event"] == "DATA_ACCESS"
        assert e["user"] == "joao@email.com"
        assert e["role"] == "user"
        assert e["action"] == "CONSULTA"
        assert e["registros_retornados"] == 500

    def test_registrado_em_audit_e_security(self):
        """DATA_ACCESS deve ir para AMBOS os loggers (compliance LGPD)."""
        from api.utils.audit_logger import log_data_access
        with patch("api.utils.audit_logger._audit_logger") as mock_audit, \
             patch("api.utils.audit_logger._security_logger") as mock_sec:
            log_data_access(
                user="u", role="user", action="ENRIQUECIMENTO",
                filtros={}, registros_retornados=0, ip="127.0.0.1",
            )
        mock_audit.info.assert_called_once()
        mock_sec.info.assert_called_once()

    def test_filtros_incluidos_no_log(self):
        from api.utils.audit_logger import log_data_access
        captured = []
        with patch("api.utils.audit_logger._audit_logger") as mock, \
             patch("api.utils.audit_logger._security_logger"):
            mock.info.side_effect = lambda m: captured.append(json.loads(m))
            log_data_access(
                user="u", role="user", action="CONSULTA",
                filtros={"ufs": ["RJ"], "genero": "F"},
                registros_retornados=100, ip="1.1.1.1",
            )
        e = captured[0]
        assert "filtros" in e
        assert e["filtros"]["ufs"] == ["RJ"]
