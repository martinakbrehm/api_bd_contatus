"""
query_builder.py
----------------
Monta a query SQL que será enviada ao banco de dados big data.

FILTROS NO BANCO (campos indexados — respeitam a indexação):
  1. UF            → filtro primário, sempre obrigatório
  2. CIDADE        → filtro secundário
  3. BAIRRO        → filtro terciário (opcional)
  4. GÊNERO        → LIKE "%M%" / "%F%" (igual à query base)
  5. IDADE         → data_nascimento BETWEEN (CURDATE - max_anos) AND (CURDATE - min_anos)
                     Padrão quando não informado: 18 a 70 anos
  6. EMAIL         → email_1 IS NOT NULL / IS NULL

FILTROS EM PYTHON (data_processor.py — não vão ao banco):
  - Tipo de telefone (móvel/fixo)
  - CBO / profissão
  - Quantidade (limite de registros)

PAGINAÇÃO (consulta em lotes):
  - limite  → LIMIT N   (tamanho do lote)
  - offset  → OFFSET N  (posição de início do lote)
"""

from api.db_settings import TABELA_PRINCIPAL, COLUNAS, COLUNAS_OPCIONAIS


# Idades padrão quando o cliente não especifica
IDADE_MIN_PADRAO = 18
IDADE_MAX_PADRAO = 70


def build_query(
    filtros: dict,
    limite: int | None = None,
    offset: int = 0,
) -> tuple[str, list]:
    """
    Constrói a query SQL com todos os filtros que vão ao banco.

    Parâmetros
    ----------
    filtros : dict          — filtros selecionados pelo cliente.
    limite  : int | None    — LIMIT N (tamanho do lote); None = sem limite.
    offset  : int           — OFFSET N (posição de início do lote).

    Retorna
    -------
    sql    : str  — SQL parametrizado com placeholders %s
    params : list — valores correspondentes
    """
    c = COLUNAS
    t = TABELA_PRINCIPAL

    # ----------------------------------------------------------
    # SELECT — todos os campos disponíveis
    # ----------------------------------------------------------
    select_campos = [
        f"{c['telefone_1']}      AS TELEFONE_1",
        f"{c['telefone_2']}      AS TELEFONE_2",
        f"{c['telefone_3']}      AS TELEFONE_3",
        f"{c['telefone_4']}      AS TELEFONE_4",
        f"{c['telefone_5']}      AS TELEFONE_5",
        f"{c['telefone_6']}      AS TELEFONE_6",
        f"{c['nome']}            AS NOME",
        f"lc.{c['cpf']}          AS CPF",
        f"'FISICA'               AS TIPO_PESSOA",
        f"{c['data_nascimento']} AS DATA_NASCIMENTO",
        f"{c['genero']}          AS GENERO",
        f"{c['endereco']}        AS ENDERECO",
        f"{c['num_end']}         AS NUM_END",
        f"{c['complemento']}     AS COMPLEMENTO",
        f"{c['bairro']}          AS BAIRRO",
        f"{c['cidade']}          AS CIDADE",
        f"{c['cep']}             AS CEP",
        f"{c['uf']}              AS UF",
        f"{c['email_1']}         AS EMAIL_1",
        f"{c['email_2']}         AS EMAIL_2",
    ]
    if COLUNAS_OPCIONAIS.get("cbo"):
        select_campos.append(f"{c['cbo']} AS CBO")

    select_str = ",\n    ".join(select_campos)

    # ----------------------------------------------------------
    # WHERE — filtros indexados
    # ----------------------------------------------------------
    where_clauses = []
    params = []

    # 1. UF — obrigatório, primário de índice
    ufs = filtros.get("ufs", [])
    if not ufs:
        raise ValueError("Ao menos um estado (UF) deve ser informado.")
    ph_uf = ", ".join(["%s"] * len(ufs))
    where_clauses.append(f"lc.{c['uf']} IN ({ph_uf})")
    params.extend([uf.strip().upper() for uf in ufs])

    # 2. CIDADE — secundário
    cidades = filtros.get("cidades", [])
    if cidades:
        ph_cid = ", ".join(["%s"] * len(cidades))
        where_clauses.append(f"{c['cidade']} IN ({ph_cid})")
        params.extend([cidade.strip().upper() for cidade in cidades])

    # 3. BAIRRO — terciário
    bairros = filtros.get("bairros", [])
    if bairros:
        ph_bai = ", ".join(["%s"] * len(bairros))
        where_clauses.append(f"{c['bairro']} IN ({ph_bai})")
        params.extend([b.strip().upper() for b in bairros])

    # 4. GÊNERO — LIKE igual à query base
    genero = filtros.get("genero", "ambos").strip().upper()
    if genero in ("M", "MASCULINO"):
        where_clauses.append(f"lc.{c['genero']} LIKE %s")
        params.append("%M%")
    elif genero in ("F", "FEMININO"):
        where_clauses.append(f"lc.{c['genero']} LIKE %s")
        params.append("%F%")
    # "ambos" → sem filtro de gênero

    # 5. IDADE — data_nascimento BETWEEN
    #    Padrão: 18 a 70 anos (evita menores e registros de falecidos)
    idade_min = filtros.get("idade_min") or IDADE_MIN_PADRAO
    idade_max = filtros.get("idade_max") or IDADE_MAX_PADRAO
    idade_min = max(int(idade_min), IDADE_MIN_PADRAO)   # nunca abaixo de 18
    idade_max = int(idade_max)
    # data_nascimento BETWEEN (hoje - idade_max anos) AND (hoje - idade_min anos)
    where_clauses.append(
        f"{c['data_nascimento']} BETWEEN "
        f"(CURDATE() - INTERVAL %s YEAR) AND (CURDATE() - INTERVAL %s YEAR)"
    )
    params.extend([idade_max, idade_min])

    # 6. EMAIL — null/not null
    email_filtro = filtros.get("email", "nao_filtrar")
    if email_filtro == "obrigatorio":
        where_clauses.append(f"{c['email_1']} IS NOT NULL")

    # 7. TELEFONE — existência (indexed; tipo movel/fixo é filtro Python)
    tem_telefone = filtros.get("tem_telefone", "nao_filtrar")
    if tem_telefone == "obrigatorio":
        where_clauses.append(f"{c['telefone_1']} IS NOT NULL")

    # 8. CBO — profissão (filtro no banco quando a coluna existe)
    # Quando COLUNAS_OPCIONAIS["cbo"] = True e cbos foram informados,
    # o filtro vai ao banco evitando trazer registros irrelevantes.
    # Quando False, o filtro é aplicado em Python pelo data_processor.
    cbos_solicitados = [str(cbo).strip().upper() for cbo in filtros.get("cbos", []) if str(cbo).strip()]
    if cbos_solicitados and COLUNAS_OPCIONAIS.get("cbo") and c.get("cbo"):
        ph_cbo = ", ".join(["%s"] * len(cbos_solicitados))
        where_clauses.append(f"{c['cbo']} IN ({ph_cbo})")
        params.extend(cbos_solicitados)

    where_str = "\n    AND ".join(where_clauses)

    # ----------------------------------------------------------
    # QUERY FINAL
    # ----------------------------------------------------------
    sql = f"""SELECT
    {select_str}
FROM
    {t} lc
WHERE
    {where_str}"""

    # Paginação — usada pela consulta em lotes
    if limite is not None:
        sql += "\nLIMIT %s OFFSET %s"
        params.extend([int(limite), int(offset)])

    return sql, params


def descrever_filtros_db(filtros: dict) -> str:
    """Retorna descrição legível dos filtros enviados ao banco."""
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
    if filtros.get("tem_telefone") == "obrigatorio":
        partes.append("Telefone: obrigatório")
    if filtros.get("cbos") and COLUNAS_OPCIONAIS.get("cbo"):
        partes.append(f"CBO(s): {', '.join(str(c) for c in filtros['cbos'])}")
    return " | ".join(partes)
