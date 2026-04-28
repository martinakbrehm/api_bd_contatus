"""
api/utils/sanitizer.py
----------------------
Funções de sanitização e mascaramento de dados sensíveis.

Usado para:
  - Mascarar CPFs, emails e telefones nos logs e respostas parciais
  - Sanitizar inputs do usuário
  - Normalizar strings para comparação segura
"""

import re
import unicodedata
from typing import Any, Optional


# ── Mascaramento de dados sensíveis ───────────────────────────

def mascarar_cpf(cpf: str) -> str:
    """
    Mascara CPF: 123.456.789-01 → ***.456.***-01
    Mostra apenas dígitos centrais e últimos 2.
    """
    if not cpf:
        return ""
    digits = re.sub(r"\D", "", str(cpf))
    if len(digits) != 11:
        return "***.***.***-**"
    return f"***.{digits[3:6]}.***-{digits[9:]}"


def mascarar_email(email: str) -> str:
    """
    Mascara email: joao.silva@gmail.com → j***@gm***.com
    """
    if not email or "@" not in str(email):
        return "***@***.***"
    partes = str(email).split("@")
    usuario = partes[0]
    dominio = partes[1]

    # Mascarar usuário
    if len(usuario) <= 1:
        usuario_mask = "*"
    else:
        usuario_mask = usuario[0] + "***"

    # Mascarar domínio
    dom_parts = dominio.split(".")
    if len(dom_parts) >= 2:
        dom_mask = dom_parts[0][:2] + "***." + dom_parts[-1]
    else:
        dom_mask = dominio[:2] + "***"

    return f"{usuario_mask}@{dom_mask}"


def mascarar_telefone(telefone: str) -> str:
    """
    Mascara telefone: 11987654321 → (11) *****-4321
    Mostra DDD e últimos 4 dígitos.
    """
    if not telefone:
        return "(**) *****-****"
    digits = re.sub(r"\D", "", str(telefone))
    if len(digits) < 10:
        return "(**) *****-****"
    ddd = digits[:2]
    ultimos4 = digits[-4:]
    return f"({ddd}) *****-{ultimos4}"


def mascarar_nome(nome: str) -> str:
    """
    Mascara nome: JOAO DA SILVA → J*** D* S****
    """
    if not nome:
        return "***"
    partes = str(nome).strip().split()
    masked = []
    for parte in partes:
        if len(parte) <= 2:
            masked.append(parte[0] + "*" if parte else "*")
        else:
            masked.append(parte[0] + "*" * (len(parte) - 1))
    return " ".join(masked)


def mascarar_registro(registro: dict, campos_sensiveis: Optional[list] = None) -> dict:
    """
    Mascara campos sensíveis em um registro (dict).
    Útil para logs e previews.
    """
    if campos_sensiveis is None:
        campos_sensiveis = ["CPF", "NOME", "EMAIL_1", "EMAIL_2"]

    resultado = registro.copy()

    for campo in campos_sensiveis:
        if campo not in resultado or not resultado[campo]:
            continue
        valor = str(resultado[campo])

        if "CPF" in campo.upper():
            resultado[campo] = mascarar_cpf(valor)
        elif "EMAIL" in campo.upper():
            resultado[campo] = mascarar_email(valor)
        elif "TELEFONE" in campo.upper():
            resultado[campo] = mascarar_telefone(valor)
        elif "NOME" in campo.upper():
            resultado[campo] = mascarar_nome(valor)

    return resultado


# ── Sanitização de inputs ─────────────────────────────────────

def sanitizar_string(valor: str, max_length: int = 500) -> str:
    """
    Sanitiza uma string de entrada:
      - Remove caracteres de controle
      - Limita comprimento
      - Remove espaços extras
      - Strip de null bytes
    """
    if not isinstance(valor, str):
        return ""

    # Remover null bytes
    valor = valor.replace("\x00", "")

    # Remover caracteres de controle (exceto newline e tab)
    valor = re.sub(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]", "", valor)

    # Limitar comprimento
    valor = valor[:max_length]

    # Strip e normalizar espaços
    valor = " ".join(valor.split())

    return valor.strip()


def normalizar_uf(uf: str) -> str:
    """Normaliza UF: remove acentos, upper, valida 2 chars."""
    s = sanitizar_string(uf, max_length=2)
    s = s.upper().strip()
    ufs_validas = {
        "AC", "AL", "AM", "AP", "BA", "CE", "DF", "ES", "GO", "MA",
        "MG", "MS", "MT", "PA", "PB", "PE", "PI", "PR", "RJ", "RN",
        "RO", "RR", "RS", "SC", "SE", "SP", "TO",
    }
    if s not in ufs_validas:
        return ""
    return s


def normalizar_texto(texto: str) -> str:
    """Remove acentos e converte para uppercase para comparação."""
    if not texto:
        return ""
    s = str(texto).strip().upper()
    s = unicodedata.normalize("NFKD", s)
    return "".join(c for c in s if not unicodedata.combining(c))
