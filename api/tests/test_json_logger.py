"""
test_json_logger.py
-------------------
Testes unitários de json_logger.JsonFormatter e configurar_logging.
"""

import json
import logging

import pytest


def _formatar(msg: str, level: int = logging.INFO, **extra) -> dict:
    """Cria um LogRecord e formata com JsonFormatter, retorna dict."""
    from api.utils.json_logger import JsonFormatter
    formatter = JsonFormatter()
    record = logging.LogRecord(
        name="api.test",
        level=level,
        pathname="",
        lineno=0,
        msg=msg,
        args=(),
        exc_info=None,
    )
    for k, v in extra.items():
        setattr(record, k, v)
    return json.loads(formatter.format(record))


# ── Campos obrigatórios ───────────────────────────────────────────────────────

class TestCamposObrigatorios:

    def test_tem_timestamp(self):
        entry = _formatar("teste")
        assert "timestamp" in entry

    def test_tem_level(self):
        entry = _formatar("teste", level=logging.WARNING)
        assert entry["level"] == "WARNING"

    def test_tem_logger(self):
        entry = _formatar("teste")
        assert entry["logger"] == "api.test"

    def test_tem_message(self):
        entry = _formatar("minha mensagem")
        assert entry["message"] == "minha mensagem"

    def test_saida_e_json_valido(self):
        from api.utils.json_logger import JsonFormatter
        formatter = JsonFormatter()
        record = logging.LogRecord("x", logging.INFO, "", 0, "msg", (), None)
        saida = formatter.format(record)
        json.loads(saida)  # não deve lançar


# ── Campos extras ─────────────────────────────────────────────────────────────

class TestCamposExtras:

    def test_request_id_incluido(self):
        entry = _formatar("req", request_id="abc-123")
        assert entry["request_id"] == "abc-123"

    def test_user_incluido(self):
        entry = _formatar("req", user="joao@x.com")
        assert entry["user"] == "joao@x.com"

    def test_role_incluido(self):
        entry = _formatar("req", role="admin")
        assert entry["role"] == "admin"

    def test_campo_nao_definido_nao_aparece(self):
        entry = _formatar("sem extras")
        assert "request_id" not in entry
        assert "user" not in entry

    def test_multiplos_campos_extras(self):
        entry = _formatar("req", request_id="r1", user="u@x.com", role="user",
                          ip="1.2.3.4", latencia_ms=15.3)
        assert entry["request_id"] == "r1"
        assert entry["latencia_ms"] == 15.3
        assert entry["ip"] == "1.2.3.4"


# ── Exceção ───────────────────────────────────────────────────────────────────

class TestExcecao:

    def test_exc_info_incluido(self):
        from api.utils.json_logger import JsonFormatter
        formatter = JsonFormatter()
        try:
            raise ValueError("erro de teste")
        except ValueError:
            import sys
            record = logging.LogRecord("x", logging.ERROR, "", 0, "falhou", (), sys.exc_info())
        entry = json.loads(formatter.format(record))
        assert "exception" in entry
        assert "ValueError" in entry["exception"]

    def test_sem_excecao_nao_tem_campo(self):
        entry = _formatar("ok")
        assert "exception" not in entry


# ── configurar_logging ────────────────────────────────────────────────────────

class TestConfigurarLogging:

    def test_root_logger_tem_handler(self):
        from api.utils.json_logger import configurar_logging, JsonFormatter
        configurar_logging()
        root = logging.getLogger()
        assert len(root.handlers) >= 1
        assert any(isinstance(h.formatter, JsonFormatter) for h in root.handlers)

    def test_nivel_info_por_padrao(self):
        from api.utils.json_logger import configurar_logging
        configurar_logging()
        assert logging.getLogger().level == logging.INFO

    def test_nivel_debug_via_parametro(self):
        from api.utils.json_logger import configurar_logging
        configurar_logging(level="DEBUG")
        assert logging.getLogger().level == logging.DEBUG

    def test_werkzeug_reduzido(self):
        from api.utils.json_logger import configurar_logging
        configurar_logging()
        assert logging.getLogger("werkzeug").level == logging.WARNING
