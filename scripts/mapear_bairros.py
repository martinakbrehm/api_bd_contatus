"""
Mapeia erros em nomes de bairros consultando cidade por cidade.
Usa o índice (UF, cidade, BAIRRO) — sem full scan.
Pausa a cada 100 cidades para não sobrecarregar o banco.

Detecta:
  1. Abreviações  — JD EUROPA → JARDIM EUROPA  (via bairros_aliases)
  2. Duplicatas   — VL OLIMPIA ≈ VILA OLIMPIA   (fuzzy match dentro da cidade)

Saída: Desktop/erros_bairros.csv
"""

import csv, json, sys, time, unicodedata
from difflib import SequenceMatcher
from pathlib import Path

import mysql.connector

sys.path.insert(0, str(Path(__file__).parent.parent))
from api.utils.bairros_aliases import expandir_bairros

DB = dict(
    host="integracoes-assisty.ccr0wsmgsayo.us-east-1.rds.amazonaws.com",
    port=3306, user="time_dados", password="Assisty@2025!",
    database="bd_contatus", connection_timeout=10, read_timeout=180,
)

IBGE  = json.loads((Path(__file__).parent.parent / "api" / "utils" / "municipios_ibge.json").read_text(encoding="utf-8"))
SAIDA      = Path("C:/Users/marti/Desktop/erros_bairros.csv")
PROGRESSO  = Path("C:/Users/marti/Desktop/bairros_progresso.json")
PAUSA_A_CADA = 1     # pausa após CADA cidade
PAUSA_SEG    = 1     # 1 segundo entre cada cidade
QTD_MIN      = 30    # threshold alto — só bairros frequentes, query leve

# Arquivo de progresso separado — rastreia TODAS as cidades consultadas,
# não só as que tiveram erro (que é o que o CSV registra).
def _carregar_prontas() -> set:
    if PROGRESSO.exists():
        data = json.loads(PROGRESSO.read_text(encoding="utf-8"))
        return {tuple(p) for p in data}
    return set()

def _salvar_prontas(prontas: set) -> None:
    PROGRESSO.write_text(json.dumps(list(prontas)), encoding="utf-8")


def norm(s):
    s = unicodedata.normalize("NFD", str(s).upper().strip())
    return " ".join("".join(c for c in s if unicodedata.category(c) != "Mn").split())


def sim(a, b):
    return SequenceMatcher(None, a, b).ratio()


def buscar_bairros(uf, cidade):
    conn = mysql.connector.connect(**DB)
    try:
        cur = conn.cursor()
        cur.execute(
            "SELECT BAIRRO, COUNT(*) AS qtd FROM latest_contacts "
            "WHERE UF=%s AND cidade=%s AND BAIRRO IS NOT NULL AND BAIRRO!='' "
            "GROUP BY BAIRRO HAVING qtd>=%s ORDER BY qtd DESC LIMIT 100",
            (uf, cidade, QTD_MIN),
        )
        return [(r[0].strip(), int(r[1])) for r in cur.fetchall() if r[0]]
    finally:
        conn.close()


def detectar_erros(uf, cidade, bairros_raw):
    """Retorna lista de (bairro_errado, sugestao, tipo, qtd)."""
    erros = []
    vistos = {}  # norm → (bairro_original, qtd)

    for bairro, qtd in bairros_raw:
        n = norm(bairro)

        # 1. Abreviação — expandir_bairros retorna forma expandida
        expandido = expandir_bairros([bairro])
        if expandido and norm(expandido[0]) != n:
            erros.append((bairro, expandido[0], "abreviacao", qtd))
            continue

        # 2. Fuzzy duplicata contra bairros já vistos na mesma cidade
        matched = None
        for vn, (vo, vq) in vistos.items():
            s = sim(n, vn)
            if s >= 0.85 and n != vn:
                # o mais frequente é o "certo"
                if qtd > vq:
                    erros.append((vo, bairro, "duplicata_fuzzy", vq))
                    vistos[n] = (bairro, qtd)
                else:
                    erros.append((bairro, vo, "duplicata_fuzzy", qtd))
                matched = True
                break

        if not matched:
            vistos[n] = (bairro, qtd)

    return erros


# ── Main ──────────────────────────────────────────────────────────────────────

total_cidades = sum(len(v) for v in IBGE.values())
prontas = _carregar_prontas()
modo = "a" if SAIDA.exists() else "w"
print(f"Total cidades IBGE: {total_cidades}")
print(f"Já processadas: {len(prontas)} — retomando...", flush=True)

consultadas = 0
erros_total = 0

with open(SAIDA, modo, newline="", encoding="utf-8-sig") as f:
    w = csv.writer(f, delimiter=";")
    if modo == "w":
        w.writerow(["uf", "cidade", "bairro_errado", "sugestao_correta", "tipo", "ocorrencias"])

    for uf in sorted(IBGE.keys()):
        cidades = IBGE[uf]
        erros_uf = 0
        puladas = 0

        for cidade in cidades:
            if (uf, cidade) in prontas:
                puladas += 1
                consultadas += 1
                continue

            try:
                bairros = buscar_bairros(uf, cidade)
                erros = detectar_erros(uf, cidade, bairros) if bairros else []
                for erro in erros:
                    w.writerow([uf, cidade, erro[0], erro[1], erro[2], erro[3]])
                    erros_total += 1
                erros_uf += len(erros)
            except Exception as e:
                print(f"  ERRO {uf}/{cidade}: {e}", flush=True)

            # Marca como processada independente de ter erro ou não
            prontas.add((uf, cidade))
            consultadas += 1

            if consultadas % PAUSA_A_CADA == 0:
                _salvar_prontas(prontas)
                pct = consultadas / total_cidades * 100
                print(f"  {consultadas}/{total_cidades} ({pct:.0f}%) — {erros_total} erros acumulados", flush=True)
                time.sleep(PAUSA_SEG)

        print(f"[{uf}] {len(cidades)} cidades ({puladas} puladas), {erros_uf} novos erros", flush=True)

    _salvar_prontas(prontas)

print(f"\nConcluído. {erros_total} erros encontrados.")
print(f"Salvo em: {SAIDA}")
