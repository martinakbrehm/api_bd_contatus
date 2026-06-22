"""
data_cleaner.py
---------------
Identifica e trata "sujeiras" comuns nos dados retornados do banco big data.

Sujeiras mapeadas:
  - Valores de validação pendente: "EM VALIDACAO", "A VALIDAR", "AGUARDANDO VALIDACAO", etc.
  - Valores nulos disfarçados: "N/A", "NULL", "NULO", "0", "00...", "-", "NSA", "NI", "S/D", etc.
  - Desconhecidos/indefinidos: "DESCONHECIDO", "INDEFINIDO", "IGNORADO", "NAO IDENTIFICADO", etc.
  - Sujeiras de endereço: "SEM BAIRRO", "RUA NAO INFORMADA", "BAIRRO NAO INFORMADO", etc.
  - Inválidos explícitos: "INVALIDO", "NAO INFORMADO", "SEM INFORMACAO"
  - Placeholders de teste: "FULANO", "BELTRANO", "CICRANO", "ASDF", "QWERTY", etc.
  - CPFs inválidos: todos zeros, repetições, comprimento incorreto, CPFs de teste conhecidos
  - Emails inválidos: sem "@", sem ".", com padrões de validação
  - Telefones inválidos: todos dígitos iguais, menos de 10 ou mais de 11 dígitos,
                         começando com padrões impossíveis (ex: DDD 00)
  - Nomes inválidos: numéricos, muito curtos, padrões de teste
  - Bairros/cidades inválidos: vazio, numérico, padrões de validação

Uso:
    from api.utils.data_cleaner import limpar_dataframe, relatorio_sujeira

    df_limpo, relatorio = limpar_dataframe(df)
"""

import re
import unicodedata

import pandas as pd


# ============================================================
# STRINGS INVÁLIDAS (em qualquer campo de texto)
# ============================================================

_STRINGS_INVALIDAS = {
    # Valores de validação / pendentes
    "EM VALIDACAO", "EM VALIDAÇÃO", "EM VALIDAÇÃO.", "EM VALIDACAO.",
    "VALIDACAO", "VALIDANDO", "PENDENTE", "PENDENTE VALIDACAO",
    "EM ANÁLISE", "EM ANALISE",
    "A VALIDAR", "AGUARDANDO VALIDACAO", "AGUARDANDO VALIDAÇÃO",
    "EM ATUALIZACAO", "EM ATUALIZAÇÃO",
    "EM PROCESSAMENTO", "EM VERIFICACAO", "EM VERIFICAÇÃO",
    "AGUARDANDO RETORNO", "AGUARDANDO CONFIRMACAO", "AGUARDANDO CONFIRMAÇÃO",

    # Nulos disfarçados
    "N/A", "NA", "N.A", "N.A.", "NULL", "NULO", "NULA", "NULOS",
    "NONE", "NIL", "NÃO INFORMADO", "NAO INFORMADO",
    "NÃO CONSTA", "NAO CONSTA", "NÃO DISPONÍVEL", "NAO DISPONIVEL",
    "SEM INFORMACAO", "SEM INFORMAÇÃO", "SEM DADOS", "SEM REGISTRO",
    "SEM CADASTRO", "NAO CADASTRADO", "NÃO CADASTRADO",
    "NÃO PREENCHIDO", "NAO PREENCHIDO",
    "NAO SE APLICA", "NÃO SE APLICA",
    "NSA", "NI", "ND", "S/I", "S/D", "S/N", "S.N.", "SN", "SC", "SR", "SD",
    "N.I.", "N.D.", "N.C.", "N.R.",

    # Inválidos explícitos
    "INVALIDO", "INVÁLIDO", "INVALIDA", "INVÁLIDA",
    "ERRO", "ERROR", "FAIL", "FAILED",
    "INCORRETO", "INCOMPLETO",
    "DESCONHECIDO", "INDEFINIDO", "IGNORADO",
    "NAO IDENTIFICADO", "NÃO IDENTIFICADO",
    "NAO DEFINIDO", "NÃO DEFINIDO",
    "NAO APLICAVEL", "NÃO APLICÁVEL",
    "NAO POSSUI", "NÃO POSSUI",
    "NAO TEM", "NÃO TEM",

    # Sujeiras de endereço
    "SEM BAIRRO", "SEM ENDERECO", "SEM ENDEREÇO", "SEM CIDADE",
    "ENDERECO NAO INFORMADO", "ENDEREÇO NÃO INFORMADO",
    "RUA NAO INFORMADA", "RUA NÃO INFORMADA",
    "BAIRRO NAO INFORMADO", "BAIRRO NÃO INFORMADO",
    "LOGRADOURO NAO INFORMADO", "LOGRADOURO NÃO INFORMADO",

    # Testes / placeholders
    "TESTE", "TEST", "TESTING", "TEMP",
    "XXXXXXXXXX", "XXXXXXXXXXXXXXXXXX",
    "AAAAAAAAA", "AAAA", "ASDF", "QWERTY", "ABCDE", "ABCD",
    "FULANO", "BELTRANO", "CICRANO", "FULANO DE TAL",
    "NOME TESTE", "NOME INVALIDO", "NOME INVÁLIDO",

    # Caracteres isolados / pontuação
    "-", "_", ".", "/", "\\", "?", "???", "...",
    "#", "##", "###", "*", "**", "***",
    "N", "S",  # single chars — nunca nome válido

    # Números de preenchimento / teste
    "9999", "99999", "999999", "9999999", "99999999",
    "999999999", "9999999999", "99999999999",
    "12345678", "123456789", "12345678901",  # CPF teste clássico
    "11111111111", "22222222222", "33333333333",
    "44444444444", "55555555555", "66666666666",
    "77777777777", "88888888888", "99999999999",

    # Zeros e sequências
    "0", "00", "000", "0000", "00000", "000000",
    "0000000", "00000000", "000000000", "0000000000", "00000000000",
}

# Padrão regex extra: apenas espaços, apenas símbolos, apenas números em campos de texto
_RE_APENAS_NUMEROS  = re.compile(r"^\d+$")
_RE_APENAS_SIMBOLOS = re.compile(r"^[\W_]+$")
_RE_TODOS_IGUAIS    = re.compile(r"^(.)\1+$")   # ex: aaaaaaa, 11111111


# ============================================================
# VALIDAÇÕES ESPECÍFICAS
# ============================================================

def _normalizar(valor) -> str:
    """Remove acento e converte para maiúsculo para comparação."""
    if not valor or pd.isna(valor):
        return ""
    s = str(valor).strip().upper()
    s = unicodedata.normalize("NFKD", s)
    return "".join(c for c in s if not unicodedata.combining(c))


def _eh_string_invalida(valor) -> bool:
    """Verifica se o valor é uma string inválida conhecida."""
    if pd.isna(valor) or valor is None:
        return False  # None/NaN são tratados separadamente
    s = _normalizar(valor)
    if not s:
        return True   # string vazia após strip
    if s in _STRINGS_INVALIDAS:
        return True
    if _RE_TODOS_IGUAIS.match(s) and len(s) > 2:
        return True   # aaaaaaa, 11111111
    return False


_CPF_INVALIDOS_CONHECIDOS = {
    # Sequências óbvias de teste
    "12345678901", "11122233344", "00011122233",
    "01234567890", "98765432100",
    # Sequências numéricas de 11 dígitos
    "01234567890", "12345678900",
}

def _validar_cpf(cpf) -> bool:
    """
    Retorna True se o CPF parece válido estruturalmente.
    - 11 dígitos
    - Não é sequência repetida (00000000000, 11111111111, ...)
    - Não é CPF de teste conhecido (12345678901, etc.)
    - Não contém letras ou caracteres inválidos
    """
    if pd.isna(cpf) or cpf is None:
        return False
    s = str(cpf).strip()

    # CPF não pode conter letras
    if any(c.isalpha() for c in s):
        return False

    # Extrair apenas dígitos
    digits = re.sub(r"\D", "", s)
    if len(digits) != 11:
        return False

    # Não pode ser sequência repetida
    if _RE_TODOS_IGUAIS.match(digits):
        return False

    # Não pode ser CPF de teste conhecido
    if digits in _CPF_INVALIDOS_CONHECIDOS:
        return False

    # Verificar se não é uma sequência numérica óbvia
    # (além das já verificadas acima)
    if digits in ["01234567890", "09876543210", "12345678900"]:
        return False

    return True


def _validar_email(email) -> bool:
    """Retorna True se o email parece válido minimamente."""
    if pd.isna(email) or email is None:
        return True   # email vazio é OK — filtro de email é separado
    s = str(email).strip()
    if not s or s.upper() in _STRINGS_INVALIDAS:
        return False

    # Verificações básicas de estrutura
    if "@" not in s:
        return False
    partes = s.split("@")
    if len(partes) != 2:
        return False  # múltiplos @

    usuario, dominio = partes
    if not usuario or not dominio:
        return False  # @dominio ou usuario@

    # Domínio deve ter pelo menos um ponto
    if "." not in dominio:
        return False

    # Verificações de caracteres inválidos
    # Email não pode conter espaços
    if " " in s:
        return False

    # Email não pode conter caracteres de controle ou inválidos
    if any(ord(c) < 32 or ord(c) > 126 for c in s):
        return False

    # Usuário não pode começar ou terminar com ponto
    if usuario.startswith(".") or usuario.endswith("."):
        return False

    # Domínio não pode começar ou terminar com ponto ou hífen
    # Também não pode ter sequências inválidas como "-." ou ".-"
    if (dominio.startswith(".") or dominio.endswith(".") or
        dominio.startswith("-") or dominio.endswith("-") or
        "-." in dominio or ".-" in dominio):
        return False

    # Verificações de comprimento
    if len(s) > 254:  # RFC 5321
        return False
    if len(usuario) > 64:  # RFC 5321
        return False

    # Padrões comuns de email inválido
    # Apenas números no usuário (muito suspeito)
    if usuario.isdigit() and len(usuario) > 3:
        return False

    # Sequências suspeitas
    if _RE_TODOS_IGUAIS.match(usuario) and len(usuario) > 2:
        return False

    return True


def _validar_telefone(tel) -> bool:
    """
    Retorna True se o telefone parece válido.
    - 10 ou 11 dígitos
    - Não é sequência repetida
    - DDD entre 11 e 99 (não começa com 0)
    - Não contém letras ou caracteres inválidos
    """
    if pd.isna(tel) or tel is None:
        return True   # campo vazio é OK
    s = str(tel).strip()
    if not s:
        return True   # vazio = OK

    # Extrair apenas dígitos
    digits = re.sub(r"\D", "", s)

    # Se não há dígitos, é inválido
    if not digits:
        return False

    # Verificar se o original contém letras (telefone não pode ter letras)
    if any(c.isalpha() for c in s):
        return False

    # Verificar comprimento
    if len(digits) not in (10, 11):
        return False

    # Não pode ser sequência repetida
    if _RE_TODOS_IGUAIS.match(digits):
        return False

    # DDD deve ser válido (11-99)
    ddd = int(digits[:2])
    if ddd < 11 or ddd > 99:
        return False

    # Verificar padrões suspeitos
    # Telefone não pode começar com 0 após DDD
    if len(digits) == 11 and digits[2] == '0':
        return False

    # Nono dígito deve ser 6-9 para celular
    if len(digits) == 11 and digits[2] not in '6789':
        return False

    return True


def _validar_nome(nome) -> bool:
    """Retorna True se o nome parece válido."""
    if pd.isna(nome) or nome is None:
        return False
    s = str(nome).strip()
    if len(s) < 3:
        return False
    if _eh_string_invalida(s):
        return False

    # Nome não pode ser só números
    if _RE_APENAS_NUMEROS.match(s):
        return False

    # Nome não pode ser só símbolos/pontuação
    if _RE_APENAS_SIMBOLOS.match(s):
        return False

    # Nome não pode conter apenas caracteres repetidos
    if _RE_TODOS_IGUAIS.match(s) and len(s) > 2:
        return False

    # Nome deve conter pelo menos uma letra
    if not any(c.isalpha() for c in s):
        return False

    # Nome não pode ter caracteres de controle ou inválidos
    if any(ord(char) < 32 or ord(char) in (127, 129, 141, 143, 144, 157, 160) for char in s):
        return False

    # Nome não pode começar ou terminar com símbolos (exceto alguns aceitáveis)
    simbolos_invalidos_inicio_fim = "!@#$%^&*()_+-=[]{}|;:,.<>?/~`"
    if s[0] in simbolos_invalidos_inicio_fim or s[-1] in simbolos_invalidos_inicio_fim:
        return False

    # Verificar se não é apenas números com símbolos (ex: "123-456")
    s_sem_simbolos = re.sub(r"[^\w\s]", "", s)
    if s_sem_simbolos.isdigit():
        return False

    return True


def _validar_localidade(local) -> bool:
    """Retorna True se bairro/cidade/UF parecem válidos."""
    if pd.isna(local) or local is None:
        return True   # campo vazio é OK
    s = str(local).strip()
    if not s:
        return True   # vazio = OK
    if _eh_string_invalida(s):
        return False

    # Localidade não pode ser só números
    if _RE_APENAS_NUMEROS.match(s):
        return False

    # Localidade não pode ser só símbolos
    if _RE_APENAS_SIMBOLOS.match(s):
        return False

    # Deve conter pelo menos uma letra
    if not any(c.isalpha() for c in s):
        return False

    # Não pode ter caracteres de controle (mas permite acentos latinos)
    if any(ord(char) < 32 or ord(char) in (127, 129, 141, 143, 144, 157, 160) for char in s):
        return False

    # Comprimento mínimo para ser significativo
    if len(s) < 2:
        return False

    return True


# ============================================================
# PIPELINE DE LIMPEZA
# ============================================================

def limpar_dataframe(df: pd.DataFrame) -> tuple[pd.DataFrame, dict]:
    """
    Aplica todos os filtros de sujeira ao DataFrame.

    Retorna
    -------
    df_limpo  : DataFrame sem registros claramente inválidos
    relatorio : dict com contagens de registros removidos por motivo
    """
    total_inicial = len(df)
    relatorio = {
        "total_inicial":       total_inicial,
        "removidos_cpf":       0,
        "removidos_nome":      0,
        "removidos_validacao": 0,
        "removidos_email":     0,
        "removidos_telefone":  0,
        "total_final":         0,
    }

    # ── 1. Campos com "EM VALIDACAO" e strings inválidas ─────────────
    # Verificamos os campos de texto mais críticos
    # UF é excluído: é enum controlado (2 letras) e códigos como "SC" estão
    # na lista de strings inválidas como placeholder, mas são UFs válidas.
    campos_texto = ["NOME", "BAIRRO", "CIDADE", "ENDERECO"]
    campos_texto_existentes = [c for c in campos_texto if c in df.columns]

    mask_validacao = pd.Series(False, index=df.index)
    for col in campos_texto_existentes:
        if col in ["BAIRRO", "CIDADE"]:
            # Para bairros e cidades, usar validação específica
            mask_validacao |= ~df[col].apply(_validar_localidade)
        else:
            # Para outros campos, usar validação geral de string
            mask_validacao |= df[col].apply(_eh_string_invalida)

    removidos_val = mask_validacao.sum()
    if pd.isna(removidos_val) or removidos_val == "":
        removidos_val = 0
    df = df[~mask_validacao]
    relatorio["removidos_validacao"] = int(removidos_val)

    # ── 2. CPF inválido ───────────────────────────────────────────────
    if "CPF" in df.columns:
        mask_cpf = ~df["CPF"].apply(_validar_cpf)
        removidos_cpf = mask_cpf.sum()
        if pd.isna(removidos_cpf) or removidos_cpf == "":
            removidos_cpf = 0
        df = df[~mask_cpf]
        relatorio["removidos_cpf"] = int(removidos_cpf)

    # ── 3. Nome inválido ──────────────────────────────────────────────
    if "NOME" in df.columns:
        mask_nome = ~df["NOME"].apply(_validar_nome)
        removidos_nome = mask_nome.sum()
        if pd.isna(removidos_nome) or removidos_nome == "":
            removidos_nome = 0
        df = df[~mask_nome]
        relatorio["removidos_nome"] = int(removidos_nome)

    # ── 4. Emails inválidos — substituir por None (não remove registro) ─
    for col in ["EMAIL_1", "EMAIL_2"]:
        if col in df.columns:
            invalidos = ~df[col].apply(_validar_email)
            n = invalidos.sum()
            relatorio["removidos_email"] = relatorio.get("removidos_email", 0) + int(n)
            df.loc[invalidos, col] = None   # invalida mas mantém o registro

    # ── 5. Telefones inválidos — substituir por None ──────────────────
    tel_cols = [f"TELEFONE_{i}" for i in range(1, 7) if f"TELEFONE_{i}" in df.columns]
    for col in tel_cols:
        invalidos = ~df[col].apply(_validar_telefone)
        n = invalidos.sum()
        relatorio["removidos_telefone"] = relatorio.get("removidos_telefone", 0) + int(n)
        df.loc[invalidos, col] = None

    relatorio["total_final"] = len(df)

    _imprimir_relatorio(relatorio)
    return df.reset_index(drop=True), relatorio


def _imprimir_relatorio(r: dict):
    total_removido = r["total_inicial"] - r["total_final"]
    msg = (
        f"[LIMPEZA] {r['total_inicial']} -> {r['total_final']} "
        f"({total_removido} removidos) | "
        f"EM_VALIDACAO: {r['removidos_validacao']} | "
        f"CPF: {r['removidos_cpf']} | "
        f"NOME: {r['removidos_nome']} | "
        f"Emails invalidos: {r['removidos_email']} | "
        f"Tels invalidos: {r['removidos_telefone']}"
    )
    print(msg.encode("ascii", errors="replace").decode("ascii"))


def relatorio_html(r: dict) -> str:
    """Gera bloco HTML com o resumo de limpeza para exibir na interface."""
    total_removido = r["total_inicial"] - r["total_final"]
    linhas = [
        f"<strong>Limpeza de dados:</strong> {r['total_inicial']:,} recebidos → "
        f"<strong>{r['total_final']:,}</strong> válidos "
        f"({total_removido:,} removidos)",
        f"<ul class='mb-0 small'>",
        f"<li>Registros com 'EM VALIDACAO' ou dados inválidos: <strong>{r['removidos_validacao']:,}</strong></li>",
        f"<li>CPF inválido ou zerado: <strong>{r['removidos_cpf']:,}</strong></li>",
        f"<li>Nome inválido: <strong>{r['removidos_nome']:,}</strong></li>",
        f"<li>Emails sobrescritos (inválidos): <strong>{r['removidos_email']:,}</strong></li>",
        f"<li>Telefones sobrescritos (inválidos): <strong>{r['removidos_telefone']:,}</strong></li>",
        f"</ul>",
    ]
    return "\n".join(linhas)
