"""
data_processor.py
-----------------
Aplica em Python os filtros que NAO vao ao banco de dados.

O banco ja entrega os dados filtrados por:
  UF, Cidade, Bairro, Genero, Idade (data_nascimento), Email null/not null.

O que este modulo trata:
  1. Limpeza de sujeiras nos dados (EM VALIDACAO, CPF/email/telefone invalidos)
  2. Tipo de telefone (movel / fixo / ambos) -- identifica pelo comprimento
  3. CBO / Profissao                         -- se a coluna existir
  4. Priorizacao de email                   -- quando "preferencial"
  5. Quantidade                              -- limita o total de registros

Retorno de processar():
  tuple[pd.DataFrame, str]  ->  (df_filtrado, html_relatorio_limpeza)
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
            # Extrair DDD (2 primeiros dígitos) e número restante
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

    # -- SEPARAR DDD DOS TELEFONES -------------------------------------------
    df = _separar_ddd_telefones(df)

    log = [f"[INICIO apos limpeza] {len(df)} registros validos."]

    # -- TIPO DE TELEFONE -----------------------------------------------------
    tipo_tel = filtros.get("tipo_telefone", "movel").lower()
    if tipo_tel in ("movel", "fixo"):
        df = df[df.apply(lambda r: _tem_telefone_do_tipo(r, tipo_tel), axis=1)]
        log.append(f"[TELEFONE: {tipo_tel}] -> {len(df)} registros")

    # -- CBO / PROFISSAO ------------------------------------------------------
    if COLUNAS_OPCIONAIS.get("cbo") and "CBO" in df.columns:
        cbos = [str(c).strip().upper() for c in filtros.get("cbos", []) if str(c).strip()]
        if cbos:
            df["CBO"] = df["CBO"].astype(str).str.strip().str.upper()
            df = df[df["CBO"].isin(cbos)]
            log.append(f"[CBO] -> {len(df)} registros")

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

def colunas_saida(com_email: bool = True) -> list[str]:
    """
    Retorna lista ordenada das colunas presentes no CSV gerado para o cliente.
    """
    cols = [
        "NOME", "CPF",
        "DDD_1", "TELEFONE_1", "DDD_2", "TELEFONE_2", "DDD_3", "TELEFONE_3",
        "DDD_4", "TELEFONE_4", "DDD_5", "TELEFONE_5", "DDD_6", "TELEFONE_6",
        "GENERO", "DATA_NASCIMENTO",
        "ENDERECO", "NUM_END", "COMPLEMENTO",
        "BAIRRO", "CIDADE", "UF", "CEP",
    ]
    if com_email:
        cols += ["EMAIL_1", "EMAIL_2"]
    # CBO sempre por último, se habilitado
    if COLUNAS_OPCIONAIS.get("cbo"):
        cols.append("CBO")
    return cols
