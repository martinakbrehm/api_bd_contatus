"""
api/models/schemas.py
---------------------
Schemas de validação para requisições e respostas da API.

Usa classes simples com validação manual (sem dependência de Pydantic).
Em produção com mais endpoints, migrar para Pydantic v2 ou marshmallow.

Cada schema valida:
  - Tipos corretos
  - Valores dentro dos ranges permitidos
  - Campos obrigatórios
  - Tamanhos máximos
  - Valores de enums
"""

import re
from typing import Any, Optional


# ── UFs válidas ───────────────────────────────────────────────
UFS_VALIDAS = {
    "AC", "AL", "AM", "AP", "BA", "CE", "DF", "ES", "GO", "MA",
    "MG", "MS", "MT", "PA", "PB", "PE", "PI", "PR", "RJ", "RN",
    "RO", "RR", "RS", "SC", "SE", "SP", "TO",
}

GENEROS_VALIDOS = {"M", "F", "MASCULINO", "FEMININO", "AMBOS"}
EMAIL_OPCOES = {"obrigatorio", "nao_filtrar", "nao", "preferencial"}
TELEFONE_OPCOES = {"movel", "fixo", "ambos"}


class ValidationError(Exception):
    """Erro de validação de schema."""

    def __init__(self, erros: list[str]):
        self.erros = erros
        super().__init__(f"Erros de validação: {'; '.join(erros)}")


def validar_consulta(data: dict) -> dict:
    """
    Valida e sanitiza os dados de uma requisição de consulta.

    Campos aceitos:
      - ufs (obrigatório): lista de UFs
      - cidades: lista de nomes de cidades
      - bairros: lista de bairros
      - genero: M, F, MASCULINO, FEMININO, AMBOS
      - idade_min: inteiro 18-120
      - idade_max: inteiro 18-120
      - email: obrigatorio, nao_filtrar, nao, preferencial
      - tipo_telefone: movel, fixo, ambos
      - cbos: lista de códigos CBO
      - quantidade: inteiro 1-10000

    Retorna dict sanitizado e validado.
    Raises ValidationError se dados inválidos.
    """
    erros = []
    resultado = {}

    # ── UFs (obrigatório) ────────────────────────────────────
    ufs = data.get("ufs", [])
    if isinstance(ufs, str):
        ufs = [u.strip() for u in re.split(r"[,;\s]+", ufs) if u.strip()]
    if not isinstance(ufs, list):
        erros.append("'ufs' deve ser uma lista.")
    elif not ufs:
        erros.append("Ao menos um estado (UF) deve ser informado.")
    else:
        ufs_limpas = []
        for uf in ufs[:27]:  # máximo 27 UFs
            uf_upper = str(uf).strip().upper()
            if uf_upper in UFS_VALIDAS:
                ufs_limpas.append(uf_upper)
            else:
                erros.append(f"UF inválida: '{uf}'")
        resultado["ufs"] = ufs_limpas

    # ── Cidades (opcional) ───────────────────────────────────
    cidades = data.get("cidades", [])
    if isinstance(cidades, str):
        cidades = [c.strip() for c in re.split(r"[,;\n]+", cidades) if c.strip()]
    if cidades:
        if len(cidades) > 50:
            erros.append("Máximo de 50 cidades por consulta.")
        cidades_limpas = []
        for cidade in cidades[:50]:
            c = str(cidade).strip().upper()
            if len(c) > 100:
                erros.append(f"Nome de cidade muito longo: '{c[:20]}...'")
            elif len(c) < 2:
                erros.append(f"Nome de cidade muito curto: '{c}'")
            elif re.search(r"[<>{}()\[\]@#$%^&*]", c):
                erros.append(f"Caracteres inválidos no nome da cidade: '{c[:20]}'")
            else:
                cidades_limpas.append(c)
        resultado["cidades"] = cidades_limpas
    else:
        resultado["cidades"] = []

    # ── Bairros (opcional) ───────────────────────────────────
    bairros = data.get("bairros", [])
    if isinstance(bairros, str):
        bairros = [b.strip() for b in re.split(r"[,;\n]+", bairros) if b.strip()]
    if bairros:
        if len(bairros) > 100:
            erros.append("Máximo de 100 bairros por consulta.")
        bairros_limpos = []
        for bairro in bairros[:100]:
            b = str(bairro).strip().upper()
            if len(b) > 100:
                erros.append(f"Nome de bairro muito longo: '{b[:20]}...'")
            elif re.search(r"[<>{}()\[\]@#$%^&*]", b):
                erros.append(f"Caracteres inválidos no nome do bairro: '{b[:20]}'")
            else:
                bairros_limpos.append(b)
        resultado["bairros"] = bairros_limpos
    else:
        resultado["bairros"] = []

    # ── Gênero ───────────────────────────────────────────────
    genero = str(data.get("genero", "ambos")).strip().upper()
    if genero not in GENEROS_VALIDOS:
        erros.append(f"Gênero inválido: '{genero}'. Use: {', '.join(sorted(GENEROS_VALIDOS))}")
    resultado["genero"] = genero if genero in GENEROS_VALIDOS else "AMBOS"

    # ── Idade ────────────────────────────────────────────────
    idade_min = data.get("idade_min")
    idade_max = data.get("idade_max")

    if idade_min is not None:
        try:
            idade_min = int(idade_min)
            if idade_min < 18:
                erros.append("Idade mínima não pode ser menor que 18.")
                idade_min = 18
            if idade_min > 120:
                erros.append("Idade mínima não pode ser maior que 120.")
        except (ValueError, TypeError):
            erros.append("'idade_min' deve ser um número inteiro.")
            idade_min = None

    if idade_max is not None:
        try:
            idade_max = int(idade_max)
            if idade_max > 120:
                erros.append("Idade máxima não pode ser maior que 120.")
                idade_max = 120
            if idade_max < 18:
                erros.append("Idade máxima não pode ser menor que 18.")
        except (ValueError, TypeError):
            erros.append("'idade_max' deve ser um número inteiro.")
            idade_max = None

    if idade_min and idade_max and idade_min > idade_max:
        erros.append("'idade_min' não pode ser maior que 'idade_max'.")

    resultado["idade_min"] = idade_min
    resultado["idade_max"] = idade_max

    # ── Email ────────────────────────────────────────────────
    email = str(data.get("email", "nao_filtrar")).strip().lower()
    if email not in EMAIL_OPCOES:
        erros.append(f"Opção de email inválida: '{email}'. Use: {', '.join(sorted(EMAIL_OPCOES))}")
        email = "nao_filtrar"
    resultado["email"] = email

    # ── Tipo de telefone ─────────────────────────────────────
    tipo_tel = str(data.get("tipo_telefone", "movel")).strip().lower()
    if tipo_tel not in TELEFONE_OPCOES:
        erros.append(f"Tipo de telefone inválido: '{tipo_tel}'. Use: {', '.join(sorted(TELEFONE_OPCOES))}")
        tipo_tel = "movel"
    resultado["tipo_telefone"] = tipo_tel

    # ── CBOs (opcional) ──────────────────────────────────────
    cbos = data.get("cbos", [])
    if isinstance(cbos, str):
        cbos = [c.strip() for c in re.split(r"[,;\n]+", cbos) if c.strip()]
    if cbos:
        cbos_limpos = []
        for cbo in cbos[:50]:
            c = str(cbo).strip()
            if re.match(r"^[\w\-\s]{1,20}$", c):
                cbos_limpos.append(c.upper())
            else:
                erros.append(f"CBO inválido: '{c[:20]}'")
        resultado["cbos"] = cbos_limpos
    else:
        resultado["cbos"] = []

    # ── Quantidade ───────────────────────────────────────────
    quantidade = data.get("quantidade")
    if quantidade is not None:
        try:
            quantidade = int(quantidade)
            if quantidade < 1:
                erros.append("'quantidade' deve ser pelo menos 1.")
                quantidade = None
            elif quantidade > 10000:
                erros.append("'quantidade' máxima é 10.000 por consulta.")
                quantidade = 10000
        except (ValueError, TypeError):
            erros.append("'quantidade' deve ser um número inteiro.")
            quantidade = None
    resultado["quantidade"] = quantidade

    # ── Validação final ──────────────────────────────────────
    if erros:
        raise ValidationError(erros)

    return resultado


def validar_contagem(data: dict) -> dict:
    """
    Valida dados para endpoint de contagem (mais permissivo).
    A contagem não retorna dados pessoais.
    """
    # Reutiliza validação de consulta
    return validar_consulta(data)


def validar_login(data: dict) -> dict:
    """Valida dados de login (API Key ou credenciais)."""
    erros = []

    api_key = data.get("api_key", "")
    if not api_key:
        erros.append("'api_key' é obrigatório.")
    elif len(str(api_key)) < 10:
        erros.append("'api_key' parece inválida (muito curta).")
    elif len(str(api_key)) > 200:
        erros.append("'api_key' excede tamanho máximo.")

    if erros:
        raise ValidationError(erros)

    return {"api_key": str(api_key).strip()}
