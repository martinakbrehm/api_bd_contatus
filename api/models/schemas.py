"""
api/models/schemas.py
---------------------
Re-exporta os schemas de validação da API para compatibilidade de imports.

Os schemas de consulta foram movidos para api/routes/consulta/schema.py.
Este módulo re-exporta tudo para que imports antigos continuem funcionando.
"""

# ── Re-exportações ───────────────────────────────────────────────────────────
# Toda a lógica de validação de consulta vive em api/routes/consulta/schema.py
# Este módulo re-exporta tudo para que imports existentes continuem funcionando.

from api.routes.consulta.schema import (  # noqa: F401
    UFS_VALIDAS,
    GENEROS_VALIDOS,
    EMAIL_OPCOES,
    TELEFONE_OPCOES,
    TEM_TELEFONE_OPCOES,
    TEM_CBO_OPCOES,
    FILTROS_ETAPA_BANCO,
    FILTROS_ETAPA_PYTHON,
    ValidationError,
    validar_consulta,
    validar_contagem,
)

import re


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