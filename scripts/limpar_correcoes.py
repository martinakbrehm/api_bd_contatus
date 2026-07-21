"""
Gera correcoes_bairros_limpo.csv a partir de correcoes_bairros.csv com:
  1. sugestao_correta normalizada para UPPERCASE
  2. Direção invertida quando sugestao_correta é abreviação do bairro_errado
  3. Linhas com diferença só de numeral marcadas como tipo=numeral_incerto
"""
import csv, re, sys, unicodedata
from collections import Counter
from pathlib import Path

csv.field_size_limit(10_000_000)

ENTRADA = Path("C:/Users/marti/Desktop/correcoes_bairros.csv")
SAIDA   = Path("C:/Users/marti/Desktop/correcoes_bairros_limpo.csv")
NUMERAIS = Path("C:/Users/marti/Desktop/bairros_numeral_incerto.csv")

ABREVIACOES = {
    "STA", "VL", "JD", "PRQ", "AT", "FNT", "REC", "MTE", "CPO",
    "CJ", "CEL", "FR", "PE", "PNT", "BX", "LGA", "VLE", "POR",
    "PR", "GJA", "HAB", "LTM", "LOT", "MAJ", "SEN", "DQ", "GNL",
    "HAB", "REC", "PRF", "D", "N", "S",
}

RE_NUMERAL = re.compile(r'[\s\-_]*(I{1,3}|IV|VI{0,3}|IX|[0-9]+)\s*$')


def sem_acento(s):
    s = unicodedata.normalize("NFD", s.upper().strip())
    return " ".join("".join(c for c in s if unicodedata.category(c) != "Mn").split())


def primeira_palavra(s):
    return s.strip().split()[0] if s.strip() else ""


def e_abreviacao(s):
    return primeira_palavra(s) in ABREVIACOES


def base_sem_numeral(s):
    return RE_NUMERAL.sub("", s.upper().strip()).strip()


stats = Counter()
numerais = []
saida_rows = []

with open(ENTRADA, encoding="utf-8-sig") as f:
    for row in csv.DictReader(f, delimiter=";"):
        errado = row["bairro_errado"].strip()
        certo  = row["sugestao_correta"].strip()
        uf     = row["uf"].strip()
        cidade = row["cidade"].strip()
        tipo   = row["tipo"].strip()
        try:
            qtd = int(row["ocorrencias"])
        except ValueError:
            continue

        # 1. Normalizar certo para uppercase
        certo_up = sem_acento(certo)

        # 2. Verificar se difere só no numeral
        base_e = base_sem_numeral(errado)
        base_c = base_sem_numeral(certo_up)
        if base_e == base_c and errado.upper() != certo_up:
            stats["numeral_incerto"] += 1
            numerais.append({
                "uf": uf, "cidade": cidade,
                "bairro_errado": errado, "sugestao_correta": certo_up,
                "ocorrencias": qtd
            })
                # Não incluir na lista de correções — são bairros distintos reais
            continue

        # 3. Verificar direção invertida (certo é abreviação de errado)
        if e_abreviacao(certo_up) and len(errado) > len(certo_up):
            # Inverter: o "errado" era na verdade a forma correta
            errado, certo_up = certo_up, errado
            tipo = "direcao_corrigida"
            stats["invertido"] += 1
        else:
            stats["ok"] += 1

        saida_rows.append({
            "uf": uf, "cidade": cidade,
            "bairro_errado": errado, "sugestao_correta": certo_up,
            "tipo": tipo, "ocorrencias": qtd
        })

# Salvar CSV limpo
with open(SAIDA, "w", newline="", encoding="utf-8-sig") as f:
    w = csv.DictWriter(f, delimiter=";",
                       fieldnames=["uf", "cidade", "bairro_errado", "sugestao_correta", "tipo", "ocorrencias"])
    w.writeheader()
    w.writerows(saida_rows)

# Salvar numerais incertos (top por frequência)
numerais_sorted = sorted(numerais, key=lambda r: -r["ocorrencias"])
with open(NUMERAIS, "w", newline="", encoding="utf-8-sig") as f:
    w = csv.DictWriter(f, delimiter=";",
                       fieldnames=["uf", "cidade", "bairro_errado", "sugestao_correta", "ocorrencias"])
    w.writeheader()
    w.writerows(numerais_sorted)

print(f"Total linhas: {len(saida_rows)}")
print(f"  OK (sem mudança):       {stats['ok']}")
print(f"  Direção invertida:      {stats['invertido']}")
print(f"  Numeral incerto:        {stats['numeral_incerto']}")
print(f"Salvo em: {SAIDA}")
print(f"Numerais incertos: {NUMERAIS}")
