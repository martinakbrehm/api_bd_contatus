"""
test_job_store.py
-----------------
Testes unitários de api/utils/job_store.py.

Store em memória — sem mocks. Isolamento garantido limpando _jobs
antes de cada teste.
"""

import time
import threading

import pytest


@pytest.fixture(autouse=True)
def _limpar_jobs():
    """Garante que _jobs está vazio antes e depois de cada teste."""
    import api.utils.job_store as _js
    _js._jobs.clear()
    yield
    _js._jobs.clear()


# ── criar_job ─────────────────────────────────────────────────────────────────

class TestCriarJob:

    def test_retorna_string_hex(self):
        from api.utils.job_store import criar_job
        job_id = criar_job({"ufs": ["SP"]})
        assert isinstance(job_id, str)
        assert len(job_id) == 32
        assert all(c in "0123456789abcdef" for c in job_id)

    def test_job_criado_com_status_pendente(self):
        from api.utils.job_store import criar_job, obter_job
        jid = criar_job({"ufs": ["SP"]})
        job = obter_job(jid)
        assert job["status"] == "pendente"

    def test_job_criado_com_filtros(self):
        from api.utils.job_store import criar_job, obter_job
        filtros = {"ufs": ["RJ"], "cidades": ["RIO DE JANEIRO"]}
        jid = criar_job(filtros)
        job = obter_job(jid)
        assert job["filtros"] == filtros

    def test_job_resultado_e_erro_inicialmente_none(self):
        from api.utils.job_store import criar_job, obter_job
        jid = criar_job({})
        job = obter_job(jid)
        assert job["resultado"] is None
        assert job["erro"] is None

    def test_ids_sao_unicos(self):
        from api.utils.job_store import criar_job
        ids = {criar_job({}) for _ in range(100)}
        assert len(ids) == 100


# ── obter_job ─────────────────────────────────────────────────────────────────

class TestObterJob:

    def test_job_inexistente_retorna_none(self):
        from api.utils.job_store import obter_job
        assert obter_job("naoexiste") is None

    def test_retorna_copia_nao_referencia(self):
        """Modificar o retorno não deve alterar o store."""
        from api.utils.job_store import criar_job, obter_job
        jid = criar_job({})
        job = obter_job(jid)
        job["status"] = "modificado"
        job2 = obter_job(jid)
        assert job2["status"] == "pendente"

    def test_job_expirado_retorna_none(self):
        from api.utils.job_store import criar_job, obter_job, JOB_TTL_SECONDS
        import api.utils.job_store as _js
        jid = criar_job({})
        # Manipula criado_em para simular expiração
        with _js._lock:
            _js._jobs[jid]["criado_em"] -= JOB_TTL_SECONDS + 1
        assert obter_job(jid) is None

    def test_job_expirado_removido_do_store(self):
        from api.utils.job_store import criar_job, obter_job, JOB_TTL_SECONDS
        import api.utils.job_store as _js
        jid = criar_job({})
        with _js._lock:
            _js._jobs[jid]["criado_em"] -= JOB_TTL_SECONDS + 1
        obter_job(jid)
        assert jid not in _js._jobs

    def test_job_recente_nao_expira(self):
        from api.utils.job_store import criar_job, obter_job
        jid = criar_job({})
        assert obter_job(jid) is not None


# ── atualizar_job ─────────────────────────────────────────────────────────────

class TestAtualizarJob:

    def test_atualiza_status(self):
        from api.utils.job_store import criar_job, atualizar_job, obter_job
        jid = criar_job({})
        atualizar_job(jid, status="processando")
        assert obter_job(jid)["status"] == "processando"

    def test_atualiza_resultado(self):
        from api.utils.job_store import criar_job, atualizar_job, obter_job
        jid = criar_job({})
        resultado = {"df": "bytes", "total": 42}
        atualizar_job(jid, status="concluido", resultado=resultado)
        job = obter_job(jid)
        assert job["status"] == "concluido"
        assert job["resultado"] == resultado

    def test_atualiza_erro(self):
        from api.utils.job_store import criar_job, atualizar_job, obter_job
        jid = criar_job({})
        atualizar_job(jid, status="erro", erro="Conexão recusada")
        job = obter_job(jid)
        assert job["status"] == "erro"
        assert job["erro"] == "Conexão recusada"

    def test_atualizar_job_inexistente_nao_levanta(self):
        from api.utils.job_store import atualizar_job
        atualizar_job("naoexiste", status="concluido")  # não deve levantar

    def test_atualiza_campo_extra(self):
        from api.utils.job_store import criar_job, atualizar_job, obter_job
        jid = criar_job({})
        atualizar_job(jid, campo_customizado="valor")
        assert obter_job(jid)["campo_customizado"] == "valor"


# ── limpar_expirados ──────────────────────────────────────────────────────────

class TestLimparExpirados:

    def test_sem_jobs_retorna_zero(self):
        from api.utils.job_store import limpar_expirados
        assert limpar_expirados() == 0

    def test_remove_apenas_expirados(self):
        from api.utils.job_store import criar_job, limpar_expirados, JOB_TTL_SECONDS
        import api.utils.job_store as _js
        jid_valido = criar_job({"ufs": ["SP"]})
        jid_exp = criar_job({"ufs": ["RJ"]})
        with _js._lock:
            _js._jobs[jid_exp]["criado_em"] -= JOB_TTL_SECONDS + 1
        removidos = limpar_expirados()
        assert removidos == 1
        assert jid_valido in _js._jobs
        assert jid_exp not in _js._jobs

    def test_todos_expirados_limpa_tudo(self):
        from api.utils.job_store import criar_job, limpar_expirados, JOB_TTL_SECONDS
        import api.utils.job_store as _js
        for _ in range(3):
            jid = criar_job({})
            with _js._lock:
                _js._jobs[jid]["criado_em"] -= JOB_TTL_SECONDS + 1
        removidos = limpar_expirados()
        assert removidos == 3
        assert len(_js._jobs) == 0


# ── Thread-safety ─────────────────────────────────────────────────────────────

class TestThreadSafety:

    def test_criacao_concorrente_sem_colisao(self):
        from api.utils.job_store import criar_job
        ids = []
        erros = []

        def _criar():
            try:
                ids.append(criar_job({"ufs": ["SP"]}))
            except Exception as e:
                erros.append(e)

        threads = [threading.Thread(target=_criar) for _ in range(50)]
        for t in threads:
            t.start()
        for t in threads:
            t.join(timeout=5)

        assert not erros
        assert len(set(ids)) == 50

    def test_atualizacao_concorrente_sem_exception(self):
        from api.utils.job_store import criar_job, atualizar_job
        jid = criar_job({})
        erros = []

        def _atualizar(i):
            try:
                atualizar_job(jid, status="processando", tick=i)
            except Exception as e:
                erros.append(e)

        threads = [threading.Thread(target=_atualizar, args=(i,)) for i in range(30)]
        for t in threads:
            t.start()
        for t in threads:
            t.join(timeout=5)

        assert not erros
