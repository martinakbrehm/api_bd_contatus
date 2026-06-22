"""
api/routes/enriquecimento/__init__.py
--------------------------------------
Endpoint de enriquecimento de lista por CPF ou telefone.

Fluxo:
  1. Recebe arquivo .txt ou .csv (multipart/form-data) com CPFs ou telefones.
  2. Para CPF   : trunca cpf_consultas → carrega via LOAD DATA LOCAL INFILE
                  (fallback: INSERT batched) → executa JOIN query.
  3. Para telefone: localiza CPFs pelos campos de telefone →
                    carrega CPFs na staging → executa mesma JOIN query.
  4. Retorna XLSX com todos os campos de contato.

Rota:
  POST /api/v1/enriquecimento
  Content-Type: multipart/form-data
    arquivo : arquivo .txt ou .csv (um valor por linha; CSV usa 1ª coluna)
    tipo    : "cpf" ou "telefone"
"""

import datetime
import re
import tempfile
import uuid
from pathlib import Path

import mysql.connector
import pandas as pd
from flask import Blueprint, g, jsonify, request, send_file

from api.auth.decorators import _get_client_ip, require_auth, require_role
from api.config_db import DB_CONFIG, DB_CONFIG_ADMIN
from api.middleware.timeout_middleware import with_timeout
from api.utils.audit_logger import log_data_access, log_security_event
from api.utils.xlsx_exporter import gerar_excel_bytes

enriquecimento_bp = Blueprint("enriquecimento", __name__, url_prefix="/api/v1")

_BATCH_SIZE = 50_000  # registros por lote no fallback INSERT

# Colunas esperadas no XLSX de saída — mesma ordem de colunas_saida()
_COLUNAS_SAIDA = [
    "DDD_1", "TELEFONE_1", "DDD_2", "TELEFONE_2", "DDD_3", "TELEFONE_3",
    "DDD_4", "TELEFONE_4", "DDD_5", "TELEFONE_5", "DDD_6", "TELEFONE_6",
    "NOME", "CPF", "TIPO_PESSOA", "DATA_NASCIMENTO", "GENERO",
    "ENDERECO", "NUM_END", "COMPLEMENTO",
    "BAIRRO", "CIDADE", "CEP", "UF",
    "EMAIL_1", "EMAIL_2",
]

# Campos de saída comuns às duas queries
_SELECT_CAMPOS = """
    a.telefone_1      AS TELEFONE_1,
    a.telefone_2      AS TELEFONE_2,
    a.telefone_3      AS TELEFONE_3,
    a.telefone_4      AS TELEFONE_4,
    a.telefone_5      AS TELEFONE_5,
    a.telefone_6      AS TELEFONE_6,
    a.nome            AS NOME,
    a.cpf             AS CPF,
    'FISICA'          AS TIPO_PESSOA,
    a.data_nascimento AS DATA_NASCIMENTO,
    a.genero          AS GENERO,
    a.ENDERECO        AS ENDERECO,
    a.NUM_END         AS NUM_END,
    a.COMPLEMENTO     AS COMPLEMENTO,
    a.BAIRRO          AS BAIRRO,
    a.cidade          AS CIDADE,
    a.CEP             AS CEP,
    a.UF              AS UF,
    a.email_1         AS EMAIL_1,
    a.email_2         AS EMAIL_2
"""

# Subquery derivada para filtrar apenas o snapshot mais recente por CPF.
# Usa derived table (não correlacionada) — muito mais eficiente para grandes volumes.
def _sql_por_cpf(sid: str) -> str:
    """Monta query de enriquecimento por CPF filtrando pela sessão (ID_IMPORT)."""
    return f"""
SELECT {_SELECT_CAMPOS}
FROM latest_contacts a
JOIN cpf_consultas b ON a.cpf = b.cpf AND b.ID_IMPORT = '{sid}'
JOIN (
    SELECT lc.cpf, MAX(lc.snapshot_updated_at) AS max_ts
    FROM latest_contacts lc
    JOIN cpf_consultas c ON lc.cpf = c.cpf AND c.ID_IMPORT = '{sid}'
    GROUP BY lc.cpf
) mx ON a.cpf = mx.cpf AND a.snapshot_updated_at = mx.max_ts
"""


def _sql_por_telefone(sid: str) -> str:
    """Monta query de enriquecimento por telefone filtrando pela sessão (ID_IMPORT)."""
    return f"""
SELECT {_SELECT_CAMPOS}
FROM latest_contacts a
LEFT JOIN telephone d ON a.ID_MAILING = d.ID_MAILING
JOIN cpf_consultas f ON d.telefone_completo = f.cpf AND f.ID_IMPORT = '{sid}'
JOIN (
    SELECT lc.cpf, MAX(lc.snapshot_updated_at) AS max_ts
    FROM latest_contacts lc
    JOIN telephone t2 ON lc.ID_MAILING = t2.ID_MAILING
    JOIN cpf_consultas c ON t2.telefone_completo = c.cpf AND c.ID_IMPORT = '{sid}'
    GROUP BY lc.cpf
) mx ON a.cpf = mx.cpf AND a.snapshot_updated_at = mx.max_ts
"""


# ── Normalizadores ───────────────────────────────────────────────────────────

def _normalizar_cpf(valor: str) -> str | None:
    """Retorna CPF apenas com dígitos (11), ou None se inválido."""
    cpf = re.sub(r"\D", "", str(valor))
    return cpf if len(cpf) == 11 else None


def _normalizar_telefone(valor: str) -> str | None:
    """
    Retorna telefone apenas com dígitos (10 ou 11), ou None se inválido.
    Remove DDI 55 quando o número chega com 12–13 dígitos.
    """
    tel = re.sub(r"\D", "", str(valor))
    if len(tel) in (12, 13) and tel.startswith("55"):
        tel = tel[2:]
    return tel if len(tel) in (10, 11) else None


# ── Helpers de arquivo e banco ───────────────────────────────────────────────

def _parse_arquivo(raw_bytes: bytes, normalizador) -> list[str]:
    """
    Lê bytes de arquivo (TXT ou CSV) linha a linha (streaming) e retorna
    lista de valores normalizados e deduplicados, preservando ordem de aparição.
    """
    import io as _io
    try:
        stream = _io.StringIO(raw_bytes.decode("utf-8"))
    except UnicodeDecodeError:
        stream = _io.StringIO(raw_bytes.decode("latin-1", errors="replace"))

    seen: dict[str, None] = {}
    for line in stream:
        raw = re.split(r"[;,\t]", line)[0].strip().strip('"').strip("'")
        if not raw:
            continue
        normalized = normalizador(raw)
        if normalized and normalized not in seen:
            seen[normalized] = None
    return list(seen.keys())


def _conectar(local_infile: bool = False, admin: bool = False):
    cfg = {**(DB_CONFIG_ADMIN if admin else DB_CONFIG)}
    if local_infile:
        cfg["allow_local_infile"] = True
    return mysql.connector.connect(**cfg)


def _carregar_cpfs_sessao(cpfs: list[str], session_id: str) -> None:
    """
    Carrega CPFs na staging com ID_IMPORT = session_id.
    Não apaga linhas de outras sessões — isolamento por session_id.
    Tenta LOAD DATA LOCAL INFILE (rápido); fallback para INSERT batched.
    """
    tmp_path = Path(tempfile.gettempdir()) / f"cpf_{uuid.uuid4().hex}.csv"
    try:
        with tmp_path.open("w", encoding="utf-8", newline="") as f:
            f.write("CPF;ID_IMPORT\n")
            for cpf in cpfs:
                f.write(f"{cpf};{session_id}\n")

        conn = _conectar(local_infile=True, admin=True)
        cur = conn.cursor()
        try:
            file_literal = str(tmp_path).replace("\\", "\\\\")
            cur.execute(
                f"LOAD DATA LOCAL INFILE '{file_literal}' "
                "INTO TABLE cpf_consultas "
                "CHARACTER SET utf8 "
                "FIELDS TERMINATED BY ';' "
                "IGNORE 1 LINES "
                "(@CPF, @ID_IMPORT) "
                "SET CPF = NULLIF(@CPF, ''), ID_IMPORT = NULLIF(@ID_IMPORT, '')"
            )
            conn.commit()
        except Exception:
            # Fallback: INSERT batched
            for i in range(0, len(cpfs), _BATCH_SIZE):
                lote = [(c, session_id) for c in cpfs[i: i + _BATCH_SIZE]]
                cur.executemany(
                    "INSERT INTO cpf_consultas (CPF, ID_IMPORT) VALUES (%s, %s)", lote
                )
            conn.commit()
        finally:
            cur.close()
            conn.close()
    finally:
        tmp_path.unlink(missing_ok=True)


def _cpfs_por_telefone(telefones: list[str]) -> list[str]:
    """
    Retorna lista de CPFs distintos encontrados em qualquer campo de telefone
    de latest_contacts para os telefones fornecidos.
    """
    cpfs: dict[str, None] = {}
    conn = _conectar()
    try:
        for i in range(0, len(telefones), _BATCH_SIZE):
            lote = telefones[i: i + _BATCH_SIZE]
            ph = ", ".join(["%s"] * len(lote))
            sql = (
                "SELECT DISTINCT cpf FROM latest_contacts "
                "WHERE cpf IS NOT NULL AND ("
                f"  telefone_1 IN ({ph}) OR telefone_2 IN ({ph}) OR "
                f"  telefone_3 IN ({ph}) OR telefone_4 IN ({ph}) OR "
                f"  telefone_5 IN ({ph}) OR telefone_6 IN ({ph})"
                ")"
            )
            cur = conn.cursor()
            cur.execute(sql, lote * 6)
            for (cpf,) in cur.fetchall():
                if cpf and cpf not in cpfs:
                    cpfs[cpf] = None
            cur.close()
    finally:
        conn.close()
    return list(cpfs.keys())


# ── Rota ─────────────────────────────────────────────────────────────────────

@enriquecimento_bp.route("/enriquecimento", methods=["POST"])
@require_auth
@require_role("admin", "user")
@with_timeout
def enriquecimento():
    """
    Enriquece lista de CPFs ou telefones com dados completos do banco.

    Content-Type: multipart/form-data
      arquivo : .txt ou .csv com CPFs ou telefones (um por linha)
      tipo    : "cpf" ou "telefone"

    Para CPF    : trunca cpf_consultas → LOAD DATA (ou INSERT batched) → JOIN query.
    Para telefone: localiza CPFs pelos campos de telefone → carrega staging → JOIN query.

    Resposta: XLSX com TELEFONE_1–6, NOME, CPF, TIPO_PESSOA, DATA_NASCIMENTO,
              GENERO, ENDERECO, NUM_END, COMPLEMENTO, BAIRRO, CIDADE, CEP, UF,
              EMAIL_1, EMAIL_2.
    Headers: X-Enviados, X-Encontrados, X-Nao-Encontrados.
    """
    client_ip = _get_client_ip()
    auth = g.auth_user
    request_id = getattr(g, "request_id", "")

    arquivo = request.files.get("arquivo")
    tipo = request.form.get("tipo", "cpf").strip().lower()

    if arquivo is None:
        return jsonify({
            "ok": False,
            "erro": "Campo 'arquivo' é obrigatório (multipart/form-data).",
            "request_id": request_id,
        }), 400

    if tipo not in ("cpf", "telefone"):
        return jsonify({
            "ok": False,
            "erro": "Campo 'tipo' deve ser 'cpf' ou 'telefone'.",
            "request_id": request_id,
        }), 400

    # ── Limite de tamanho do arquivo (10 MB) ─────────────────────────────────
    _MAX_BYTES = 10 * 1024 * 1024  # 10 MB
    raw_bytes = arquivo.read(_MAX_BYTES + 1)
    if len(raw_bytes) > _MAX_BYTES:
        return jsonify({
            "ok": False,
            "erro": "Arquivo muito grande. O limite é 10 MB.",
            "request_id": request_id,
        }), 413

    # ── Parsear arquivo ──────────────────────────────────────────────────────
    normalizador = _normalizar_cpf if tipo == "cpf" else _normalizar_telefone
    itens = _parse_arquivo(raw_bytes, normalizador)

    if not itens:
        return jsonify({
            "ok": False,
            "erro": "Nenhum valor válido encontrado no arquivo após normalização.",
            "request_id": request_id,
        }), 400

    if len(itens) > 1_000_000:
        return jsonify({
            "ok": False,
            "erro": f"Limite excedido: o arquivo contém {len(itens):,} registros únicos. O máximo permitido é 1.000.000.",
            "request_id": request_id,
        }), 400

    enviados = len(itens)

    # UUID por request — isola linhas desta sessão na staging table
    session_id = uuid.uuid4().hex

    try:
        if not itens:
            df_resultado = pd.DataFrame(columns=_COLUNAS_SAIDA)
        else:
            # ── Carregar staging table (apenas linhas desta sessão) ──────────
            _carregar_cpfs_sessao(itens, session_id)

            sql = _sql_por_cpf(session_id) if tipo == "cpf" else _sql_por_telefone(session_id)

            # ── Executar query de enriquecimento ─────────────────────────────
            conn = _conectar()
            try:
                df_resultado = pd.read_sql(sql, conn)
                # Separar DDD dos telefones (banco armazena DDD+número concatenados)
                for _i in range(1, 7):
                    _col = f"TELEFONE_{_i}"
                    if _col in df_resultado.columns:
                        _s = df_resultado[_col].fillna("").astype(str).str.strip()
                        df_resultado[f"DDD_{_i}"] = _s.apply(
                            lambda x: x[:2] if len(x) >= 10 else ""
                        )
                        df_resultado[_col] = _s.apply(
                            lambda x: x[2:] if len(x) >= 10 else x
                        )
            finally:
                # Limpa apenas as linhas desta sessão
                try:
                    _adm = _conectar(admin=True)
                    _cur = _adm.cursor()
                    _cur.execute("DELETE FROM cpf_consultas WHERE ID_IMPORT = %s", (session_id,))
                    _adm.commit()
                    _cur.close()
                    _adm.close()
                except Exception:
                    pass
                conn.close()

    except Exception as e:
        log_security_event(
            "ENRIQUECIMENTO_ERROR",
            severity="ERROR",
            subject=auth.get("subject"),
            error=str(e),
            ip=client_ip,
        )
        return jsonify({
            "ok": False,
            "erro": "Erro ao processar o enriquecimento.",
            "request_id": request_id,
        }), 500

    encontrados = len(df_resultado)
    nao_encontrados = max(0, enviados - encontrados)

    log_data_access(
        user=auth.get("subject", "unknown"),
        role=auth.get("role", "unknown"),
        action="ENRIQUECIMENTO",
        filtros={"tipo": tipo, "enviados": enviados},
        registros_retornados=encontrados,
        ip=client_ip,
        request_id=request_id,
    )

    if encontrados == 0:
        return jsonify({
            "ok": False,
            "erro": f"Nenhum registro encontrado para os {enviados} {tipo}(s) enviados.",
            "enviados": enviados,
            "encontrados": 0,
            "request_id": request_id,
        }), 404

    buf = gerar_excel_bytes(df_resultado)
    nome = f"enriquecimento_{datetime.datetime.now():%Y%m%d_%H%M%S}.xlsx"
    response = send_file(
        buf,
        as_attachment=True,
        download_name=nome,
        mimetype="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
    )
    response.headers["X-Enviados"] = str(enviados)
    response.headers["X-Encontrados"] = str(encontrados)
    response.headers["X-Nao-Encontrados"] = str(nao_encontrados)
    return response
