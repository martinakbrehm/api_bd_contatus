"""
Combina correções de cidades e bairros em um único CSV.

Colunas: tipo;uf;cidade_banco;bairro_banco;valor_correto;ocorrencias

- tipo=cidade: corrige o campo `cidade` no banco
  WHERE UF=uf AND cidade=cidade_banco  →  SET cidade=valor_correto
- tipo=bairro: corrige o campo `BAIRRO` no banco
  WHERE UF=uf AND cidade=cidade_banco AND BAIRRO=bairro_banco  →  SET BAIRRO=valor_correto

Fontes:
  cidades: erros_cidades_ibge.csv  (filtrada por confiança)
  bairros: correcoes_confiaveis.csv
"""
import csv, re, unicodedata
from difflib import SequenceMatcher
from pathlib import Path

csv.field_size_limit(10_000_000)

CIDADES_SRC = Path("C:/Users/marti/Desktop/erros_cidades_ibge.csv")
BAIRROS_SRC = Path("C:/Users/marti/Desktop/correcoes_confiaveis.csv")
SAIDA       = Path("C:/Users/marti/Desktop/correcoes_banco.csv")


def sem_acento(s):
    s = unicodedata.normalize("NFD", s.upper().strip())
    return " ".join("".join(c for c in s if unicodedata.category(c) != "Mn").split())


def sim(a, b):
    return SequenceMatcher(None, a, b).ratio()


# Sufixos de UF que aparecem colados ao nome da cidade
RE_SUFIXO_UF = re.compile(
    r'\s+(AC|AL|AM|AP|BA|CE|DF|ES|GO|MA|MG|MS|MT|PA|PB|PE|PI|PR|RJ|RN|RO|RR|RS|SC|SE|SP|TO)\s*$'
)

# Palavras que indicam dado inválido
INVALIDOS = {"NAO INFORMADO", "N INF", "NAO INFORMAD", "SEM BAIRRO", "SEM CIDADE",
             "INTERIOR", "ZONA RURAL", "RURAL", "NAO IDENTIFICADO", "OUTROS"}


def cidade_confiavel(errado, certo, uf):
    """Retorna True se a correção de cidade é de alta confiança."""
    if not certo:
        return False
    e = sem_acento(errado)
    c = sem_acento(certo)
    if e in INVALIDOS or not e:
        return False
    if e == c:
        return False

    # Caso 1: errado tem sufixo de UF (ex: "CRUZEIRO DO SUL AC" → "CRUZEIRO DO SUL")
    e_sem_sufixo = RE_SUFIXO_UF.sub("", e).strip()
    if e_sem_sufixo == c:
        return True

    # Caso 2: errado tem parêntese com sub-localidade (ex: "RIO BRANCO (NOVA PRATA)" → "RIO BRANCO")
    e_sem_par = re.sub(r'\s*\(.*?\)', '', e).strip()
    if e_sem_par == c:
        return True

    # Caso 3: alta similaridade E mesma primeira palavra
    if sim(e, c) >= 0.88:
        e_palavras = e.split()
        c_palavras = c.split()
        if e_palavras[0] == c_palavras[0]:
            return True

    # Caso 4: errado é claramente truncamento do certo (errado ⊂ início do certo)
    if len(e) < len(c) and c.startswith(e[:max(4, len(e)-2)]):
        return True

    return False


rows = []

# ── Cidades ────────────────────────────────────────────────────────────────
print("Processando cidades...")
cidades_ok = 0
with open(CIDADES_SRC, encoding="utf-8-sig", errors="replace") as f:
    for r in csv.DictReader(f, delimiter=";"):
        uf     = r["uf"].strip()
        errado = r["errado_no_banco"].strip()
        certo  = r.get("certo_ibge", "").strip()
        try:
            qtd = int(r["ocorrencias"])
        except ValueError:
            continue

        if not cidade_confiavel(errado, certo, uf):
            continue

        rows.append({
            "tipo": "cidade",
            "uf": uf,
            "cidade_banco": errado,
            "bairro_banco": "",
            "valor_correto": sem_acento(certo),
            "ocorrencias": qtd,
        })
        cidades_ok += 1

print(f"  Cidades aceitas: {cidades_ok}")

# ── Bairros ─────────────────────────────────────────────────────────────────
print("Processando bairros...")
bairros_ok = 0
with open(BAIRROS_SRC, encoding="utf-8-sig", errors="replace") as f:
    for r in csv.DictReader(f, delimiter=";"):
        uf     = r["uf"].strip()
        cidade = r["cidade"].strip()
        errado = r["bairro_errado"].strip()
        certo  = r["sugestao_correta"].strip()
        try:
            qtd = int(r["ocorrencias"])
        except ValueError:
            continue

        rows.append({
            "tipo": "bairro",
            "uf": uf,
            "cidade_banco": cidade,
            "bairro_banco": errado,
            "valor_correto": certo,
            "ocorrencias": qtd,
        })
        bairros_ok += 1

print(f"  Bairros aceitos: {bairros_ok}")

# Ordena: primeiro cidades, depois bairros; dentro de cada, por uf + cidade + -ocorrencias
rows.sort(key=lambda r: (r["tipo"], r["uf"], r["cidade_banco"], -r["ocorrencias"]))

with open(SAIDA, "w", newline="", encoding="utf-8-sig") as f:
    w = csv.DictWriter(f, delimiter=";",
                       fieldnames=["tipo", "uf", "cidade_banco", "bairro_banco", "valor_correto", "ocorrencias"])
    w.writeheader()
    w.writerows(rows)

print(f"\nTotal combinado: {len(rows)} correções")
print(f"  Cidades: {cidades_ok}")
print(f"  Bairros: {bairros_ok}")
print(f"Salvo em: {SAIDA}")
