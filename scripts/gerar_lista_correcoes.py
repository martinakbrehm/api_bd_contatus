"""
Lê erros_bairros.csv (resultado do mapear_bairros.py) e gera:
  - correcoes_bairros.csv: lista limpa e deduplicada de bairro_errado → sugestao_correta
    ordenada por uf, cidade, ocorrencias (desc)
"""
import csv
import sys
from pathlib import Path

csv.field_size_limit(10_000_000)

ENTRADA = Path("C:/Users/marti/Desktop/erros_bairros.csv")
SAIDA   = Path("C:/Users/marti/Desktop/correcoes_bairros.csv")

# Deduplica por (uf, cidade, bairro_errado) — mantém a sugestão com mais ocorrências
mapa = {}  # (uf, cidade, bairro_errado) → {sugestao, tipo, ocorrencias}

with open(ENTRADA, encoding="utf-8-sig") as f:
    reader = csv.DictReader(f, delimiter=";")
    for row in reader:
        chave = (row["uf"], row["cidade"], row["bairro_errado"])
        qtd = int(row["ocorrencias"]) if row["ocorrencias"].isdigit() else 0
        if chave not in mapa or qtd > mapa[chave]["ocorrencias"]:
            mapa[chave] = {
                "sugestao_correta": row["sugestao_correta"],
                "tipo": row["tipo"],
                "ocorrencias": qtd,
            }

print(f"Entradas únicas: {len(mapa)}")

# Ordena por uf, cidade, ocorrencias desc
entradas = sorted(
    [(uf, cidade, errado, v["sugestao_correta"], v["tipo"], v["ocorrencias"])
     for (uf, cidade, errado), v in mapa.items()],
    key=lambda r: (r[0], r[1], -r[5]),
)

with open(SAIDA, "w", newline="", encoding="utf-8-sig") as f:
    w = csv.writer(f, delimiter=";")
    w.writerow(["uf", "cidade", "bairro_errado", "sugestao_correta", "tipo", "ocorrencias"])
    for row in entradas:
        w.writerow(row)

print(f"Salvo em: {SAIDA}")
print(f"Total de correções: {len(entradas)}")

# Estatísticas por UF
from collections import Counter
por_uf = Counter(r[0] for r in entradas)
print("\nCorreções por UF:")
for uf, cnt in sorted(por_uf.items()):
    print(f"  {uf}: {cnt}")
