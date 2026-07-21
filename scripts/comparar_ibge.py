import mysql.connector, json, csv, unicodedata, time
from pathlib import Path
from difflib import get_close_matches

DB = dict(
    host="integracoes-assisty.ccr0wsmgsayo.us-east-1.rds.amazonaws.com",
    port=3306, user="time_dados", password="Assisty@2025!",
    database="bd_contatus", connection_timeout=10, read_timeout=120,
)

IBGE = json.loads(
    Path(__file__).parent.parent / "api" / "utils" / "municipios_ibge.json"
    and (Path(__file__).parent.parent / "api" / "utils" / "municipios_ibge.json").read_text(encoding="utf-8")
)

def norm(s):
    s = unicodedata.normalize("NFD", str(s).upper().strip())
    return " ".join("".join(c for c in s if unicodedata.category(c) != "Mn").split())

UFS    = sorted(IBGE.keys())
PAUSA  = 5
saida  = Path("C:/Users/marti/Desktop/erros_cidades_ibge.csv")

resultados = []

for i, uf in enumerate(UFS):
    ibge_norm = {norm(c): c for c in IBGE[uf]}
    ibge_set  = set(ibge_norm.keys())

    try:
        conn = mysql.connector.connect(**DB)
        cur  = conn.cursor()
        cur.execute(
            "SELECT cidade, COUNT(*) AS qtd FROM latest_contacts "
            "WHERE UF=%s AND cidade IS NOT NULL AND cidade!='' "
            "GROUP BY cidade HAVING qtd>=5",
            (uf,),
        )
        rows = [(r[0].strip(), int(r[1])) for r in cur.fetchall() if r[0]]
        conn.close()
    except Exception as e:
        print(f"  ERRO {uf}: {e}", flush=True)
        continue

    erros_uf = 0
    for cidade_raw, qtd in rows:
        n = norm(cidade_raw)
        if n in ibge_set:
            continue
        matches   = get_close_matches(n, ibge_set, n=1, cutoff=0.6)
        sugestao  = ibge_norm[matches[0]] if matches else ""
        resultados.append((uf, cidade_raw, qtd, sugestao))
        erros_uf += 1

    print(f"[{i+1:02d}/27] {uf}: {len(rows)} cidades, {erros_uf} com erro", flush=True)

    if i < len(UFS) - 1:
        time.sleep(PAUSA)

resultados.sort(key=lambda x: (x[0], -x[2]))
with open(saida, "w", newline="", encoding="utf-8-sig") as f:
    w = csv.writer(f, delimiter=";")
    w.writerow(["uf", "errado_no_banco", "ocorrencias", "certo_ibge"])
    w.writerows(resultados)

print(f"\nTotal erros: {len(resultados)}")
print(f"Salvo em: {saida}")
