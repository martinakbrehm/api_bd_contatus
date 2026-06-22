"""
data_processor.py
-----------------
ETAPA 2 do pipeline: filtros e limpeza aplicados em Python, após a query SQL.

O banco (Etapa 1) já entrega filtrado por:
  UF, Cidade, Bairro, Gênero, Idade, Email (IS NOT NULL / IS NULL), CBO.

O que este módulo faz:
  1. Limpeza de sujeiras  — CPF/email/telefone inválidos, nomes de teste,
                             strings nulas dis farçadas, placeholders, etc.
  2. Tipo de telefone     — identifica celular (11 dígitos) vs fixo (10);
                             filtra por movel | fixo | ambos.
  3. Email preferencial   — quando "preferencial": reordena priorizando
                             registros que têm email.
  4. Quantidade           — limita o total de registros (aplicado por último).

Retorno de processar():
  tuple[pd.DataFrame, str]  →  (df_filtrado, html_relatorio_limpeza)
"""

import re

import pandas as pd

from api.db_settings import COLUNAS_OPCIONAIS, COMPRIMENTO_CELULAR, COMPRIMENTO_FIXO
from api.utils.data_cleaner import limpar_dataframe, relatorio_html


# ============================================================
# HELPERS INTERNOS
# ============================================================

def _apenas_digitos(valor) -> str:
    """Remove tudo que nao for digito."""
    if pd.isna(valor) or valor is None:
        return ""
    return re.sub(r"\D", "", str(valor))


def _normalizar_str(valor) -> str:
    """Remove espacos extras e converte para maiusculo."""
    if pd.isna(valor) or valor is None:
        return ""
    return str(valor).strip().upper()


def _eh_celular(numero: str) -> bool:
    """
    Celular BR: 11 digitos e 3 digito (apos DDD de 2 digitos) == '9'.
    Ex: 11987654321  ->  DDD=11, 9=celular, restante=87654321
    """
    digits = _apenas_digitos(numero)
    return len(digits) == COMPRIMENTO_CELULAR and len(digits) > 2 and digits[2] == "9"


def _eh_fixo(numero: str) -> bool:
    """Fixo BR: exatamente 10 digitos (DDD + 8 digitos)."""
    return len(_apenas_digitos(numero)) == COMPRIMENTO_FIXO


def _tem_telefone_do_tipo(row: pd.Series, tipo: str) -> bool:
    """
    Retorna True se ao menos um dos 6 campos de telefone do registro
    corresponde ao tipo: 'movel', 'fixo' ou 'ambos'.
    Considera DDD + número concatenados.
    """
    for i in range(1, 7):
        ddd = str(row.get(f"DDD_{i}", "") or "").strip()
        tel = str(row.get(f"TELEFONE_{i}", "") or "").strip()
        numero_completo = ddd + tel
        
        if not numero_completo or numero_completo in ("None", "nan", ""):
            continue
        
        if tipo == "movel" and _eh_celular(numero_completo):
            return True
        if tipo == "fixo" and _eh_fixo(numero_completo):
            return True
        if tipo == "ambos" and (_eh_celular(numero_completo) or _eh_fixo(numero_completo)):
            return True
    return False


def _tem_email_valido(row: pd.Series) -> bool:
    """Retorna True se o registro possui ao menos um e-mail com '@'."""
    for col in ("EMAIL_1", "EMAIL_2"):
        val = str(row.get(col, "") or "")
        if val and val not in ("None", "nan") and "@" in val:
            return True
    return False


def _compactar_telefones(df: pd.DataFrame, tipo: str) -> pd.DataFrame:
    """
    Move os telefones válidos para as primeiras colunas (esquerda).

    Para cada linha, coleta os pares (DDD_i, TELEFONE_i) cujo número
    corresponde ao tipo solicitado e os redistribui nas posições 1, 2, 3...
    As posições restantes ficam vazias.

    Isso garante que TELEFONE_1 sempre contenha o primeiro número válido,
    independentemente de em qual posição original ele estava.
    """
    if df.empty:
        return df

    def _compactar_row(row: pd.Series) -> pd.Series:
        pares: list[tuple[str, str]] = []
        for i in range(1, 7):
            ddd = str(row.get(f"DDD_{i}", "") or "").strip()
            tel = str(row.get(f"TELEFONE_{i}", "") or "").strip()
            if not tel or tel in ("None", "nan"):
                continue
            numero = ddd + tel
            if tipo == "movel" and not _eh_celular(numero):
                continue
            if tipo == "fixo" and not _eh_fixo(numero):
                continue
            if tipo == "ambos" and not (_eh_celular(numero) or _eh_fixo(numero)):
                continue
            pares.append((ddd, tel))

        row = row.copy()
        for i in range(1, 7):
            if pares:
                ddd, tel = pares.pop(0)
                row[f"DDD_{i}"] = ddd
                row[f"TELEFONE_{i}"] = tel
            else:
                row[f"DDD_{i}"] = ""
                row[f"TELEFONE_{i}"] = ""
        return row

    return df.apply(_compactar_row, axis=1)


def _separar_ddd_telefones(df: pd.DataFrame) -> pd.DataFrame:
    """
    Separa DDD dos telefones válidos.
    Cria colunas DDD_1, DDD_2, ..., DDD_6 e atualiza TELEFONE_1, etc.
    para conter apenas o número sem DDD.
    """
    tel_cols = [f"TELEFONE_{i}" for i in range(1, 7)]
    
    for i in range(1, 7):
        tel_col = f"TELEFONE_{i}"
        ddd_col = f"DDD_{i}"
        
        if tel_col in df.columns:
            df[ddd_col] = df[tel_col].apply(
                lambda x: str(x)[:2] if pd.notna(x) and str(x).strip() and len(str(x)) >= 10 else ""
            )
            df[tel_col] = df[tel_col].apply(
                lambda x: str(x)[2:] if pd.notna(x) and str(x).strip() and len(str(x)) >= 10 else str(x) if pd.notna(x) else ""
            )
    
    return df


# ============================================================
# PIPELINE PRINCIPAL
# ============================================================

def processar(df: pd.DataFrame, filtros: dict) -> tuple[pd.DataFrame, str]:
    """
    Aplica limpeza de dados e filtros Python sobre o DataFrame do banco.

    Parametros
    ----------
    df      : DataFrame bruto retornado pelo banco.
    filtros : dict com parametros selecionados pelo cliente.

    Retorna
    -------
    (df_final, rel_html) : DataFrame limpo/filtrado + HTML do relatorio
                           de limpeza para exibicao na interface.
    """
    if df.empty:
        return df, ""

    # -- LIMPEZA DE SUJEIRAS -------------------------------------------------
    df, relatorio = limpar_dataframe(df)
    rel_html = relatorio_html(relatorio)

    if df.empty:
        return df, rel_html

    # -- DEDUPLICACAO POR CPF ------------------------------------------------
    # Remove registros com o mesmo CPF dentro do lote, mantendo a primeira
    # ocorrência. Registros sem CPF válido não são afetados.
    if "CPF" in df.columns:
        mask_cpf = df["CPF"].notna() & (df["CPF"].astype(str).str.strip() != "")
        df_com_cpf = df[mask_cpf].drop_duplicates(subset=["CPF"], keep="first")
        df_sem_cpf = df[~mask_cpf]
        df = pd.concat([df_com_cpf, df_sem_cpf], ignore_index=True)

    # -- SEPARAR DDD DOS TELEFONES -------------------------------------------
    df = _separar_ddd_telefones(df)

    # -- FORMATAR CEP --------------------------------------------------------
    # 8 dígitos: usa direto.
    # 7 dígitos começando com '0': falta zero à esquerda (ex: SP 01310100 → 1310100).
    # 7 dígitos começando com outro dígito: falta zero à direita (ex: SC 88385000 → 8838500).
    # Demais tamanhos: descarta.
    def _fix_cep(val) -> str:
        d = re.sub(r"\D", "", str(val).strip())
        if len(d) == 8:
            return d
        if len(d) == 7:
            return ("0" + d) if d[0] == "0" else (d + "0")
        return ""

    if "CEP" in df.columns:
        df["CEP"] = df["CEP"].apply(_fix_cep)

    log = [f"[INICIO apos limpeza] {len(df)} registros validos."]

    # -- TIPO DE TELEFONE -----------------------------------------------------
    tipo_tel = filtros.get("tipo_telefone", "movel").lower()
    if tipo_tel in ("movel", "fixo", "ambos"):
        df = df[df.apply(lambda r: _tem_telefone_do_tipo(r, tipo_tel), axis=1)]
        log.append(f"[TELEFONE: {tipo_tel}] -> {len(df)} registros")

    # -- COMPACTAR TELEFONES À ESQUERDA --------------------------------------
    # Move telefones válidos para TELEFONE_1, TELEFONE_2, ... em sequência.
    if not df.empty:
        df = _compactar_telefones(df, tipo_tel if tipo_tel in ("movel", "fixo") else "ambos")

    # -- DDD ------------------------------------------------------------------
    ddds = filtros.get("ddds")
    if ddds:
        ddds_set = {str(d).zfill(2) for d in ddds}
        df = df[df.apply(
            lambda r: any(
                str(r.get(f"DDD_{i}", "") or "").strip() in ddds_set
                for i in range(1, 7)
            ), axis=1
        )]
        log.append(f"[DDD: {', '.join(sorted(ddds_set))}] -> {len(df)} registros")

    # -- PRIORIZACAO DE EMAIL -------------------------------------------------
    if filtros.get("email") == "preferencial":
        df = df.copy()
        df["_tem_email"] = df.apply(_tem_email_valido, axis=1)
        df = df.sort_values("_tem_email", ascending=False).drop(columns=["_tem_email"])
        log.append(f"[EMAIL: priorizados com email] -> {len(df)} registros")

    # -- QUANTIDADE -----------------------------------------------------------
    quantidade = filtros.get("quantidade")
    if quantidade and int(quantidade) > 0:
        df = df.head(int(quantidade))
        log.append(f"[QUANTIDADE] -> limitado a {len(df)} registros")

    log.append(f"[FINAL] {len(df)} registros apos filtros Python.")
    print("\n".join(log))

    return df.reset_index(drop=True), rel_html


# ============================================================
# COLUNAS DE SAIDA (CSV)
# ============================================================

def colunas_saida(com_email: bool = True, com_atividade: bool = False) -> list[str]:
    """
    Retorna lista ordenada das colunas do output gerado para o cliente.

    Ordem fixa:
      DDD/TEL × 6 | NOME CPF TIPO_PESSOA DATA_NASCIMENTO GENERO |
      ENDERECO NUM_END COMPLEMENTO BAIRRO CIDADE CEP UF |
      EMAIL_1 EMAIL_2 | [ATIVIDADE]

    com_email e com_atividade mantidos por compatibilidade;
    EMAIL é sempre incluído independentemente de com_email.
    """
    cols = [
        "DDD_1", "TELEFONE_1", "DDD_2", "TELEFONE_2", "DDD_3", "TELEFONE_3",
        "DDD_4", "TELEFONE_4", "DDD_5", "TELEFONE_5", "DDD_6", "TELEFONE_6",
        "NOME", "CPF", "TIPO_PESSOA", "DATA_NASCIMENTO", "GENERO",
        "ENDERECO", "NUM_END", "COMPLEMENTO",
        "BAIRRO", "CIDADE", "CEP", "UF",
        "EMAIL_1", "EMAIL_2",
    ]
    if com_atividade:
        cols.append("ATIVIDADE")
    return cols
