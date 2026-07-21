"""
Gera lista de correções de bairros de ALTA CONFIANÇA:
apenas casos onde bairro_errado é claramente uma abreviação da forma correta,
usando expansão determinística (STA->SANTA, VL->VILA, JD->JARDIM etc.)
Não usa fuzzy — zero falso positivo de "nomes diferentes".
"""
import csv, re, sys, unicodedata
from pathlib import Path

csv.field_size_limit(10_000_000)

ENTRADA = Path("C:/Users/marti/Desktop/erros_bairros.csv")
SAIDA   = Path("C:/Users/marti/Desktop/correcoes_confiaveis.csv")

# Mapa de abreviações conhecidas → forma completa
EXPANSOES = {
    "STA":   "SANTA",
    "STO":   "SANTO",
    "S":     "SAO",       # S PAULO → SAO PAULO
    "VL":    "VILA",
    "VLE":   "VALE",
    "JD":    "JARDIM",
    "PRQ":   "PARQUE",
    "CPO":   "CAMPO",
    "AT":    "ALTO",
    "BX":    "BAIXA",
    "MTE":   "MONTE",
    "LGA":   "LAGOA",
    "PNT":   "PONTA",
    "PR":    "PRAIA",
    "FNT":   "FONTE",
    "REC":   "RECANTO",
    "ST":    "SETOR",
    "PL":    "PLANO",
    "CEL":   "CORONEL",
    "D":     "DOM",
    "FR":    "FREI",
    "PE":    "PADRE",
    "SEN":   "SENADOR",
    "DQ":    "DUQUE",
    "CJ":    "CONJUNTO",
    "GJA":   "GRANJA",
    "IA":    "ILHA",
    "POR":   "PORTO",
    "MAJ":   "MAJOR",
    "RCHO":  "RIACHO",
    "N":     "NOVA",
    "B":     "BOA",
}


def sem_acento(s):
    s = unicodedata.normalize("NFD", s.upper().strip())
    return " ".join("".join(c for c in s if unicodedata.category(c) != "Mn").split())


def expandir(s):
    """Expande primeira(s) palavra(s) abreviadas."""
    palavras = s.split()
    if not palavras:
        return s
    resultado = []
    i = 0
    while i < len(palavras):
        p = palavras[i]
        if p in EXPANSOES:
            resultado.append(EXPANSOES[p])
        else:
            resultado.append(p)
        i += 1
    return " ".join(resultado)


def e_expansao(errado, certo):
    """Retorna True se certo == expandir(errado) e eles diferem."""
    expandido = sem_acento(expandir(sem_acento(errado)))
    certo_n = sem_acento(certo)
    return expandido == certo_n and sem_acento(errado) != certo_n


# Deduplica por (uf, cidade, bairro_errado)
mapa = {}
with open(ENTRADA, encoding="utf-8-sig", errors="replace") as f:
    for row in csv.DictReader(f, delimiter=";"):
        if any("\x00" in v for v in row.values()):
            continue
        errado = sem_acento(row["bairro_errado"])
        certo  = sem_acento(row["sugestao_correta"])
        uf     = row["uf"].strip()
        cidade = row["cidade"].strip()
        if len(uf) != 2:
            continue
        try:
            qtd = int(row["ocorrencias"])
        except ValueError:
            continue

        if not e_expansao(errado, certo):
            continue

        chave = (uf, cidade, errado)
        if chave not in mapa or qtd > mapa[chave]["ocorrencias"]:
            mapa[chave] = {
                "uf": uf, "cidade": cidade,
                "bairro_errado": errado,
                "sugestao_correta": certo,
                "ocorrencias": qtd,
            }

# Ordena por uf, cidade, -ocorrencias
saida = sorted(mapa.values(), key=lambda r: (r["uf"], r["cidade"], -r["ocorrencias"]))

with open(SAIDA, "w", newline="", encoding="utf-8-sig") as f:
    w = csv.DictWriter(f, delimiter=";",
                       fieldnames=["uf", "cidade", "bairro_errado", "sugestao_correta", "ocorrencias"])
    w.writeheader()
    w.writerows(saida)

print(f"Correções confiáveis: {len(saida)}")
print(f"Salvo em: {SAIDA}")

# Amostra das top 30
print("\n--- Top 30 por ocorrências ---")
top = sorted(saida, key=lambda r: -r["ocorrencias"])[:30]
for r in top:
    print(f"  {r['ocorrencias']:6} | {r['uf']} {r['cidade'][:20]:20} | {r['bairro_errado'][:28]:28} -> {r['sugestao_correta']}")
