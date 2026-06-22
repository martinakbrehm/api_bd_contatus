"""
api/utils/data_quality.py
--------------------------
Métricas de qualidade dos dados retornados numa consulta.

Retorna um dict com contagens e percentuais de completude para os
campos mais relevantes: email, telefone móvel, telefone fixo, gênero,
data de nascimento e endereço.
"""

import pandas as pd


def metricas_qualidade(df: pd.DataFrame) -> dict:
    """
    Calcula métricas de completude do DataFrame de resultado.

    Retorno:
    {
      "total": 1000,
      "com_email": 650,           pct_email: 65.0
      "com_movel": 920,           pct_movel: 92.0
      "com_fixo": 210,            pct_fixo: 21.0
      "com_algum_tel": 980,       pct_algum_tel: 98.0
      "com_genero": 1000,
      "com_data_nascimento": 950,
      "com_endereco": 870,
    }
    """
    n = len(df)
    if n == 0:
        return {"total": 0}

    def _pct(count: int) -> float:
        return round(count / n * 100, 1)

    def _tem_col(col: str) -> pd.Series:
        if col not in df.columns:
            return pd.Series(False, index=df.index)
        return df[col].notna() & (df[col].astype(str).str.strip() != "")

    # ── Email ─────────────────────────────────────────────────────────────────
    tem_email = _tem_col("EMAIL_1") | _tem_col("EMAIL_2")
    com_email = int(tem_email.sum())

    # ── Telefones (DDD_i/TELEFONE_i já separados pelo endpoint) ──────────────
    movel_cols  = [f"TELEFONE_{i}" for i in range(1, 7)]
    fixo_cols   = [f"TELEFONE_{i}" for i in range(1, 7)]

    def _e_movel(s: pd.Series) -> pd.Series:
        """Celular BR: 9 dígitos após DDD."""
        return s.notna() & (s.astype(str).str.strip().str.len() == 9)

    def _e_fixo(s: pd.Series) -> pd.Series:
        """Fixo BR: 8 dígitos após DDD."""
        return s.notna() & (s.astype(str).str.strip().str.len() == 8)

    tem_movel = pd.Series(False, index=df.index)
    tem_fixo  = pd.Series(False, index=df.index)
    for col in movel_cols:
        if col in df.columns:
            tem_movel |= _e_movel(df[col])
            tem_fixo  |= _e_fixo(df[col])

    com_movel    = int(tem_movel.sum())
    com_fixo     = int(tem_fixo.sum())
    com_algum_tel = int((tem_movel | tem_fixo).sum())

    # ── Outros campos ─────────────────────────────────────────────────────────
    com_genero   = int(_tem_col("GENERO").sum())
    com_nasc     = int(_tem_col("DATA_NASCIMENTO").sum())
    com_endereco = int(_tem_col("ENDERECO").sum())

    return {
        "total":               n,
        "com_email":           com_email,
        "pct_email":           _pct(com_email),
        "com_movel":           com_movel,
        "pct_movel":           _pct(com_movel),
        "com_fixo":            com_fixo,
        "pct_fixo":            _pct(com_fixo),
        "com_algum_tel":       com_algum_tel,
        "pct_algum_tel":       _pct(com_algum_tel),
        "com_genero":          com_genero,
        "pct_genero":          _pct(com_genero),
        "com_data_nascimento": com_nasc,
        "pct_data_nascimento": _pct(com_nasc),
        "com_endereco":        com_endereco,
        "pct_endereco":        _pct(com_endereco),
    }
