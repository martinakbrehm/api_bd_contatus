"""
bairros_aliases.py
------------------
Normalização bidirecional de nomes de bairros para o banco bd_contatus.

O banco armazena o mesmo bairro em formas abreviadas e completas de forma
inconsistente. Análise de +6.000 bairros encontrou 1.312 pares de variantes.

Padrões confirmados no banco:
  JD  = JARDIM    VL  = VILA     PRQ / PQ = PARQUE
  COND = CONDOMINIO  CJ / CJTO = CONJUNTO
  BSQ = BOSQUE    CPO = CAMPOS   AT  = ALTO
  FAZ = FAZENDA   LOT = LOTEAMENTO  RES = RESIDENCIAL
  STA = SANTA     STO = SANTO    NUC = NUCLEO
  N   = NOVA      S   = SAO      PTE = PONTE

Uso:
  A função expandir_bairros() é chamada em query_builder.py antes de montar
  o BAIRRO IN (...) para incluir automaticamente todas as variantes do banco.
  Não requer manutenção — funciona para qualquer bairro, conhecido ou não.

Cidades:
  O banco usa COLLATE utf8mb4_unicode_ci, que trata acentos como equivalentes
  em comparações SQL (SÃO PAULO = SAO PAULO). Nenhuma normalização necessária.
"""

from __future__ import annotations

# Mapeamento: prefixo abreviado → palavra completa
# Cada entrada é  ABREV: COMPLETO (sem espaço, sem ponto)
_ABREV_PARA_COMPLETO: dict[str, str] = {
    "JD":    "JARDIM",
    "VL":    "VILA",
    "PRQ":   "PARQUE",
    "PQ":    "PARQUE",
    "COND":  "CONDOMINIO",
    "CJ":    "CONJUNTO",
    "CJTO":  "CONJUNTO",
    "BSQ":   "BOSQUE",
    "CPO":   "CAMPOS",
    "AT":    "ALTO",
    "FAZ":   "FAZENDA",
    "LOT":   "LOTEAMENTO",
    "STA":   "SANTA",
    "STO":   "SANTO",
    "N":     "NOVA",
    "S":     "SAO",
    "NUC":   "NUCLEO",
    "PTE":   "PONTE",
    "RES":   "RESIDENCIAL",
    "HAB":   "HABITACIONAL",
    "DIST":  "DISTRITO",
}

# Inverso: palavra completa → lista de todas as abreviações conhecidas
_COMPLETO_PARA_ABREV: dict[str, list[str]] = {}
for _abrev, _completo in _ABREV_PARA_COMPLETO.items():
    _COMPLETO_PARA_ABREV.setdefault(_completo, []).append(_abrev)


def variantes(bairro: str) -> list[str]:
    """
    Retorna todas as variantes de escrita conhecidas para um bairro.

    Exemplos:
      variantes("JARDIM BOTANICO")
        → ["JARDIM BOTANICO", "JD BOTANICO"]

      variantes("JD BOTANICO")
        → ["JD BOTANICO", "JARDIM BOTANICO"]

      variantes("PARQUE CAMPOLIM")
        → ["PARQUE CAMPOLIM", "PRQ CAMPOLIM", "PQ CAMPOLIM"]

      variantes("CENTRO")
        → ["CENTRO"]   (sem prefixo reconhecível, retorna só o original)
    """
    b = bairro.strip().upper()
    resultado: list[str] = [b]
    visto: set[str] = {b}

    partes = b.split(" ", 1)
    if len(partes) < 2:
        return resultado  # nome de uma palavra só, sem variantes

    prefixo, resto = partes

    # Caso 1: prefixo é uma abreviação → gera a forma completa
    #         e outras abreviações para a mesma palavra completa
    if prefixo in _ABREV_PARA_COMPLETO:
        completo = _ABREV_PARA_COMPLETO[prefixo]
        candidatos = [f"{completo} {resto}"]
        for outra_abrev in _COMPLETO_PARA_ABREV.get(completo, []):
            if outra_abrev != prefixo:
                candidatos.append(f"{outra_abrev} {resto}")
        for c in candidatos:
            if c not in visto:
                resultado.append(c)
                visto.add(c)

    # Caso 2: prefixo é uma palavra completa → gera todas as abreviações
    if prefixo in _COMPLETO_PARA_ABREV:
        for abrev in _COMPLETO_PARA_ABREV[prefixo]:
            c = f"{abrev} {resto}"
            if c not in visto:
                resultado.append(c)
                visto.add(c)

    return resultado


def expandir_bairros(bairros: list[str]) -> list[str]:
    """
    Recebe lista de bairros e retorna lista expandida com todas as variantes.
    Duplicatas são eliminadas preservando ordem de inserção.

    Exemplo:
      expandir_bairros(["JARDIM BOTANICO", "CENTRO"])
      → ["JARDIM BOTANICO", "JD BOTANICO", "CENTRO"]
    """
    resultado: list[str] = []
    visto: set[str] = set()
    for bairro in bairros:
        for v in variantes(bairro):
            if v not in visto:
                resultado.append(v)
                visto.add(v)
    return resultado
