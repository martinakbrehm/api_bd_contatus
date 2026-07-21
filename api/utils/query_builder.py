"""
query_builder.py
----------------
Etapa 1 do pipeline: monta a query SQL enviada ao banco.

ETAPA 1 — BANCO (SQL, indexed):
  UF       → WHERE lc.UF IN (...)                        — obrigatório
  CIDADE   → WHERE lc.cidade IN (...)                    — obrigatório
  BAIRRO   → WHERE lc.BAIRRO IN (...)
  GENERO   → WHERE lc.GENERO LIKE "%M%" / "%F%"
  IDADE    → WHERE lc.DATA_NASCIMENTO BETWEEN ... OR IS NULL
             (skip quando padrão 18–70; NULL nunca excluído)
  EMAIL    → obrigatorio → WHERE lc.email_1 IS NOT NULL
             nao         → WHERE lc.email_1 IS NULL
             preferencial/nao_filtrar → sem cláusula SQL
  CBO      → cbos especificados   → LEFT JOIN all_cpf_cbo + all_cbo
                                     WHERE e.cbo IN (...)
             tem_cbo=obrigatorio  → JOIN + WHERE e.cbo IS NOT NULL
             (JOIN só adicionado quando necessário)

ETAPA 2 — PYTHON (data_processor.py, pós-query):
  tipo_telefone → identifica celular/fixo pelo nº de dígitos
  limpezas      → CPF inválido, email sem @, tel com dígitos iguais,
                  nomes de teste, strings nulas disfarçadas, etc.
  email=preferencial → reordena priorizando registros com email

PAGINAÇÃO:
  limite → LIMIT N  |  offset → OFFSET N
"""

from api.db_settings import (
    COLUNAS,
    TABELA_PRINCIPAL,
    TABELA_CBO_CPF,
    TABELA_CBO,
)
from api.utils.bairros_aliases import expandir_bairros
from api.utils.cidades_aliases import expandir_cidades


# Idades padrão quando o cliente não especifica
IDADE_MIN_PADRAO = 18
IDADE_MAX_PADRAO = 70


def build_query(
    filtros: dict,
    limite: int | None = None,
    last_id: tuple[int, int] | None = None,
) -> tuple[str, list]:
    """
    Constrói a query SQL parametrizada seguindo o padrão de consulta indexada.

    Quando 'cbos' é informado nos filtros, adiciona LEFT JOIN com as tabelas
    all_cpf_cbo e all_cbo e inclui a coluna ATIVIDADE (descrição da profissão)
    no resultado.

    Parâmetros
    ----------
    filtros : dict          — filtros validados pelo schema.
    limite  : int | None    — LIMIT N (tamanho do lote); None = sem limite.
    last_id : tuple[int, int] | None  — cursor (ID_MAILING, ID_COMPLEMENT) do
                                          último registro do lote anterior.
                                          None = primeiro lote (sem restrição).

    Retorna
    -------
    (sql, params) : SQL parametrizado com placeholders %s + lista de valores.
    """
    c = COLUNAS
    t = TABELA_PRINCIPAL

    # ── CBO: JOIN ativo quando profissão é solicitada OU existência exigida ────
    cbos_solicitados = [
        str(cbo).strip() for cbo in filtros.get("cbos", []) if str(cbo).strip()
    ]
    tem_cbo = filtros.get("tem_cbo", "nao_filtrar")
    # "incluir" → LEFT JOIN sem WHERE no CBO (mostra profissão quando disponível)
    # "obrigatorio" → LEFT JOIN + WHERE e.cbo IS NOT NULL
    usar_cbo = bool(cbos_solicitados) or tem_cbo in ("obrigatorio", "incluir")

    # ── SELECT ────────────────────────────────────────────────────────────
    select_campos = [
        f"lc.{c['telefone_1']}      AS TELEFONE_1",
        f"lc.{c['telefone_2']}      AS TELEFONE_2",
        f"lc.{c['telefone_3']}      AS TELEFONE_3",
        f"lc.{c['telefone_4']}      AS TELEFONE_4",
        f"lc.{c['telefone_5']}      AS TELEFONE_5",
        f"lc.{c['telefone_6']}      AS TELEFONE_6",
        f"lc.{c['nome']}            AS NOME",
        f"lc.{c['cpf']}             AS CPF",
        f"'FISICA'                  AS TIPO_PESSOA",
        f"lc.{c['data_nascimento']} AS DATA_NASCIMENTO",
        f"lc.{c['genero']}          AS GENERO",
        f"lc.{c['endereco']}        AS ENDERECO",
        f"lc.{c['num_end']}         AS NUM_END",
        f"lc.{c['complemento']}     AS COMPLEMENTO",
        f"lc.{c['bairro']}          AS BAIRRO",
        f"lc.{c['cidade']}          AS CIDADE",
        f"lc.{c['cep']}             AS CEP",
        f"lc.{c['uf']}              AS UF",
        f"lc.{c['email_1']}         AS EMAIL_1",
        f"lc.{c['email_2']}         AS EMAIL_2",
        "lc.ID_MAILING               AS _ID_MAILING",    # cursor interno
        "lc.ID_COMPLEMENT            AS _ID_COMPLEMENT",  # cursor interno
    ]
    if usar_cbo:
        # Inclui descrição da profissão quando CBO foi solicitado
        select_campos.append(f"d.{c['atividade']}          AS ATIVIDADE")

    select_str = ",\n    ".join(select_campos)

    # ── FROM + JOINs ──────────────────────────────────────────────────────
    # JOIN de CBO via CPF — só adicionado quando filtro de profissão é ativo.
    # Segue o mesmo padrão da consulta base do sistema.
    from_str = f"{t} lc"
    if usar_cbo:
        # INNER JOIN quando CBOs específicos são solicitados — descarta linhas sem CBO
        # na junção, reduzindo o volume processado antes do WHERE.
        # LEFT JOIN mantido apenas quando o CBO é opcional (tem_cbo="incluir").
        join_tipo = "LEFT JOIN" if (tem_cbo == "incluir" and not cbos_solicitados) else "JOIN"
        from_str += (
            f"\n{join_tipo} {TABELA_CBO_CPF} e"
            f"  ON lc.{c['cpf']} = e.cpf"
            f"\nLEFT JOIN {TABELA_CBO} d ON e.cbo = d.cbo"
        )

    # ── WHERE — filtros indexados ─────────────────────────────────────────
    where_clauses = []
    params = []

    # 1. UF — obrigatório; usa idx_latest_contacts_uf_cidade
    ufs = filtros.get("ufs", [])
    if not ufs:
        raise ValueError("Ao menos um estado (UF) deve ser informado.")
    ph_uf = ", ".join(["%s"] * len(ufs))
    where_clauses.append(f"lc.{c['uf']} IN ({ph_uf})")
    params.extend([uf.strip().upper() for uf in ufs])

    # 2. CIDADE — usa idx_latest_contacts_uf_cidade (composto com UF)
    #    expandir_cidades() inclui variantes com typos conhecidos no banco
    cidades = filtros.get("cidades", [])
    if cidades:
        cidades_expandidas = expandir_cidades(
            [cidade.strip().upper() for cidade in cidades],
            ufs=ufs,
        )
        ph_cid = ", ".join(["%s"] * len(cidades_expandidas))
        where_clauses.append(f"lc.{c['cidade']} IN ({ph_cid})")
        params.extend(cidades_expandidas)

    # 3. BAIRRO — usa idx_latest_contacts_bairro
    #    expandir_bairros() inclui variantes abreviadas do banco (JD=JARDIM, VL=VILA, etc.)
    bairros = filtros.get("bairros", [])
    if bairros:
        bairros_expandidos = expandir_bairros([b.strip().upper() for b in bairros])
        ph_bai = ", ".join(["%s"] * len(bairros_expandidos))
        where_clauses.append(f"lc.{c['bairro']} IN ({ph_bai})")
        params.extend(bairros_expandidos)

    # 4. GÊNERO — LIKE para compatibilidade com valores compostos no banco
    genero = filtros.get("genero", "ambos").strip().upper()
    if genero in ("M", "MASCULINO"):
        where_clauses.append(f"lc.{c['genero']} LIKE %s")
        params.append("%M%")
    elif genero in ("F", "FEMININO"):
        where_clauses.append(f"lc.{c['genero']} LIKE %s")
        params.append("%F%")
    # "ambos" → sem filtro de gênero

    # 5. IDADE — usa idx_lc_uf_nascimento (composto com UF) ou idx_lc_nascimento.
    #    Só aplica quando diferente dos padrões (18, 70).
    #    Registros sem data_nascimento (NULL) nunca são excluídos.
    idade_min = filtros.get("idade_min") or IDADE_MIN_PADRAO
    idade_max = filtros.get("idade_max") or IDADE_MAX_PADRAO
    idade_min = max(int(idade_min), IDADE_MIN_PADRAO)
    idade_max = int(idade_max)
    if idade_min != IDADE_MIN_PADRAO or idade_max != IDADE_MAX_PADRAO:
        where_clauses.append(
            f"(lc.{c['data_nascimento']} BETWEEN "
            f"(CURDATE() - INTERVAL %s YEAR) AND (CURDATE() - INTERVAL %s YEAR) "
            f"OR lc.{c['data_nascimento']} IS NULL)"
        )
        params.extend([idade_max, idade_min])

    # 6. EMAIL — sem índice; filtro leve aplicado após os filtros indexados
    email_filtro = filtros.get("email", "nao_filtrar")
    if email_filtro == "obrigatorio":
        where_clauses.append(f"lc.{c['email_1']} IS NOT NULL")
    elif email_filtro == "nao":
        where_clauses.append(f"lc.{c['email_1']} IS NULL")

    # 7. TELEFONE — existência; sem índice dedicado
    tem_telefone = filtros.get("tem_telefone", "nao_filtrar")
    if tem_telefone == "obrigatorio":
        where_clauses.append(f"lc.{c['telefone_1']} IS NOT NULL")

    # 8. CBO — via LEFT JOIN com all_cpf_cbo + all_cbo.
    #    cbos específicos  → WHERE e.cbo IN (...)
    #    tem_cbo=obrigatorio sem cbos específicos → WHERE e.cbo IS NOT NULL
    if usar_cbo:
        if cbos_solicitados:
            ph_cbo = ", ".join(["%s"] * len(cbos_solicitados))
            where_clauses.append(f"e.cbo IN ({ph_cbo})")
            params.extend([int(cbo) for cbo in cbos_solicitados])
        elif tem_cbo == "obrigatorio":
            where_clauses.append("e.cbo IS NOT NULL")
        # tem_cbo == "incluir" → LEFT JOIN sem filtro, ATIVIDADE NULL quando sem CBO

    where_str = "\n    AND ".join(where_clauses)
    # 9. Cursor de paginação — usa chave composta (ID_MAILING, ID_COMPLEMENT)
    #    para garantir que nenhuma linha seja pulada entre lotes consecutivos.
    #    MySQL usa o índice da PK para essa comparação de tupla.
    if last_id is not None:
        where_str += "\n    AND (lc.ID_MAILING, lc.ID_COMPLEMENT) > (%s, %s)"
        params.extend([int(last_id[0]), int(last_id[1])])
    # ── QUERY FINAL ───────────────────────────────────────────────────────
    sql = f"""SELECT
    {select_str}
FROM
    {from_str}
WHERE
    {where_str}"""

    # Paginação cursor-based: ORDER BY chave composta + LIMIT, sem OFFSET.
    # (ID_MAILING, ID_COMPLEMENT) é a PK da tabela — garante ordem única.
    if limite is not None:
        sql += "\nORDER BY lc.ID_MAILING, lc.ID_COMPLEMENT"
        sql += "\nLIMIT %s"
        params.append(int(limite))

    return sql, params


def descrever_filtros_db(filtros: dict) -> str:
    """Retorna descrição legível dos filtros aplicados na consulta."""
    partes = []
    partes.append(f"UF: {', '.join(filtros.get('ufs', []))}")
    if filtros.get("cidades"):
        partes.append(f"Cidade(s): {', '.join(filtros['cidades'])}")
    if filtros.get("bairros"):
        partes.append(f"Bairro(s): {', '.join(filtros['bairros'])}")
    genero = filtros.get("genero", "ambos")
    if genero.upper() not in ("AMBOS", ""):
        partes.append(f"Gênero: {genero}")
    idade_min = filtros.get("idade_min") or IDADE_MIN_PADRAO
    idade_max = filtros.get("idade_max") or IDADE_MAX_PADRAO
    partes.append(f"Idade: {idade_min}–{idade_max} anos")
    if filtros.get("email") == "obrigatorio":
        partes.append("Email: obrigatório")
    elif filtros.get("email") == "nao":
        partes.append("Email: excluir com email")
    if filtros.get("tem_telefone") == "obrigatorio":
        partes.append("Telefone: obrigatório")
    if filtros.get("tem_cbo") == "obrigatorio" and not filtros.get("cbos"):
        partes.append("CBO: obrigatório (qualquer profissão)")
    elif filtros.get("cbos"):
        partes.append(f"Profissão (CBO): {', '.join(str(c) for c in filtros['cbos'])}")
    if filtros.get("ddds"):
        partes.append(f"DDD(s): {', '.join(str(d) for d in filtros['ddds'])}")
    if filtros.get("alta_renda"):
        partes.append("Alta renda: sim")
    return " | ".join(partes)
