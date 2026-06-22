"""
api/utils/job_store.py
-----------------------
Store de jobs assíncronos em memória (thread-safe).

Usado pelo endpoint POST /api/v1/consulta/iniciar para processar
extrações grandes em background sem bloquear o request HTTP.

Estrutura de um job:
  {
    "job_id":     str (UUID4 hex),
    "status":     "pendente" | "processando" | "concluido" | "erro",
    "criado_em":  float (timestamp),
    "filtros":    dict,
    "resultado":  dict | None,   ← preenchido quando concluido
    "erro":       str | None,    ← preenchido quando erro
  }

Jobs expiram e são limpos automaticamente após JOB_TTL_SECONDS.
"""

import threading
import time
import uuid

JOB_TTL_SECONDS = 7200  # 2 horas

_jobs: dict[str, dict] = {}
_lock = threading.Lock()


def _novo_id() -> str:
    return uuid.uuid4().hex


def criar_job(filtros: dict) -> str:
    """Registra um novo job e retorna seu job_id."""
    job_id = _novo_id()
    with _lock:
        _jobs[job_id] = {
            "job_id":    job_id,
            "status":    "pendente",
            "criado_em": time.time(),
            "filtros":   filtros,
            "resultado": None,
            "erro":      None,
        }
    return job_id


def atualizar_job(job_id: str, **kwargs) -> None:
    """Atualiza campos do job (status, resultado, erro)."""
    with _lock:
        if job_id in _jobs:
            _jobs[job_id].update(kwargs)


def obter_job(job_id: str) -> dict | None:
    """Retorna cópia do job ou None se não existir/expirado."""
    with _lock:
        job = _jobs.get(job_id)
        if job is None:
            return None
        if time.time() - job["criado_em"] > JOB_TTL_SECONDS:
            del _jobs[job_id]
            return None
        return dict(job)


def limpar_expirados() -> int:
    """Remove jobs expirados. Chamado pelo scheduler periódico."""
    agora = time.time()
    with _lock:
        expirados = [jid for jid, j in _jobs.items()
                     if agora - j["criado_em"] > JOB_TTL_SECONDS]
        for jid in expirados:
            del _jobs[jid]
    return len(expirados)
