"""
scripts/exportar_cidades_aliases.py
------------------------------------
Exporta todas as cidades do banco (uma UF por vez, com pausa entre cada)
e detecta variantes/erros usando agrupar_cidades().

Usa apenas o índice (UF, cidade) — sem full scan na tabela principal.
Salva progresso em JSON para poder retomar se interrompido.

Saída:
  Desktop/cidades_aliases_completo.csv  — canonical, variante, UF

Uso:
  python scripts/exportar_cidades_aliases.py
"""

import csv
import json
import sys
import time
from pathlib import Path

import mysql.connector

# ── Config ───────────────────────────────────────────────────────────────────
DB_HOST     = "integracoes-assisty.ccr0wsmgsayo.us-east-1.rds.amazonaws.com"
DB_NAME     = "bd_contatus"
DB_PORT     = 3306
DB_USER     = "time_dados"
DB_PASSWORD = "Assisty@2025!"

TABELA   = "latest_contacts"
COL_UF   = "UF"
COL_CIDADE = "cidade"

PAUSA_SEGUNDOS = 6      # pausa entre cada UF para não sobrecarregar
QTD_MINIMA     = 10     # mesma regra do endpoint /cidades

UFS = [
    "AC","AL","AP","AM","BA","CE","DF","ES","GO","MA",
    "MT","MS","MG","PA","PB","PR","PE","PI","RJ","RN",
    "RS","RO","RR","SC","SP","SE","TO",
]

ARQUIVO_PROGRESSO = Path(__file__).parent / "_progresso_cidades.json"
ARQUIVO_SAIDA     = Path.home() / "Desktop" / "cidades_aliases_completo.csv"

# ── Importa agrupar_cidades do projeto ───────────────────────────────────────
sys.path.insert(0, str(Path(__file__).parent.parent))
from api.utils.cidades_aliases import agrupar_cidades, _base_cidade


def conectar():
    return mysql.connector.connect(
        host=DB_HOST, port=DB_PORT,
        user=DB_USER, password=DB_PASSWORD,
        database=DB_NAME,
        connection_timeout=10,
        read_timeout=120,
    )


def buscar_cidades_uf(uf: str) -> list[tuple[str, int]]:
    """Retorna [(cidade, qtd)] para a UF — usa índice, sem full scan."""
    conn = conectar()
    try:
        cur = conn.cursor()
        cur.execute(
            f"SELECT {COL_CIDADE}, COUNT(*) AS qtd "
            f"FROM {TABELA} "
            f"WHERE {COL_UF} = %s "
            f"  AND {COL_CIDADE} IS NOT NULL AND {COL_CIDADE} != '' "
            f"GROUP BY {COL_CIDADE} "
            f"HAVING qtd >= %s "
            f"LIMIT 3000",
            (uf, QTD_MINIMA),
        )
        return [(r[0].strip().upper(), int(r[1])) for r in cur.fetchall() if r[0]]
    finally:
        conn.close()


def detectar_aliases(cidades_raw: list[tuple[str, int]]) -> list[tuple[str, str]]:
    """
    Retorna pares (variante_no_banco, canonical) onde variante != canonical.
    Usa a mesma lógica do agrupar_cidades() — dict estático + fuzzy.
    """
    # Ordena por frequência desc (mais frequente = canonical)
    ordenado = sorted(cidades_raw, key=lambda x: x[1], reverse=True)

    # Rebuilda mapeamento interno manualmente para capturar o que foi agrupado
    from api.utils.cidades_aliases import (
        _NORM_PARA_CANONICAL, _base_cidade, _sim, _sufixo_cidade_conhecida,
        _VARIANTES,
    )
    _canonicos_dict = frozenset(_VARIANTES.keys())

    canonicos: list[str] = []
    mapa: dict[str, str] = {}  # base → canonical

    for cidade_raw, _ in ordenado:
        base = _base_cidade(cidade_raw)

        # 1. Dict estático
        canonical_static = _NORM_PARA_CANONICAL.get(base)
        if canonical_static:
            if canonical_static not in canonicos:
                canonicos.append(canonical_static)
            mapa[base] = canonical_static
            continue

        # 2. Sufixo de cidade conhecida
        sufixo = _sufixo_cidade_conhecida(base, _canonicos_dict)
        if sufixo:
            if sufixo not in canonicos:
                canonicos.append(sufixo)
            mapa[base] = sufixo
            continue

        # 3. Fuzzy match contra canônicos já estabelecidos
        matched = None
        for c in canonicos:
            sim = _sim(base, c)
            if len(base) >= 6 and c.startswith(base):
                sim = max(sim, 0.88)
            if sim >= 0.82:
                matched = c
                break
        if matched:
            mapa[base] = matched
            continue

        canonicos.append(base)
        mapa[base] = base

    # Retorna apenas os que são variantes (base != canonical)
    aliases = []
    for cidade_raw, _ in ordenado:
        base    = _base_cidade(cidade_raw)
        canonical = mapa.get(base, base)
        if base != canonical or cidade_raw.upper() != base:
            aliases.append((cidade_raw, canonical))

    return aliases


def main():
    # Carrega progresso anterior se existir
    progresso: dict[str, list] = {}
    if ARQUIVO_PROGRESSO.exists():
        with open(ARQUIVO_PROGRESSO, encoding="utf-8") as f:
            progresso = json.load(f)
        print(f"Retomando — {len(progresso)} UFs já processadas: {list(progresso.keys())}")

    ufs_pendentes = [uf for uf in UFS if uf not in progresso]
    print(f"UFs pendentes: {ufs_pendentes}\n")

    for i, uf in enumerate(ufs_pendentes):
        print(f"[{i+1}/{len(ufs_pendentes)}] {uf} ...", end=" ", flush=True)
        try:
            cidades_raw = buscar_cidades_uf(uf)
            aliases = detectar_aliases(cidades_raw)
            progresso[uf] = aliases
            print(f"{len(cidades_raw)} cidades brutas, {len(aliases)} com variante")

            # Salva progresso a cada UF
            with open(ARQUIVO_PROGRESSO, "w", encoding="utf-8") as f:
                json.dump(progresso, f, ensure_ascii=False, indent=2)

        except Exception as e:
            print(f"ERRO: {e}")

        if i < len(ufs_pendentes) - 1:
            print(f"    aguardando {PAUSA_SEGUNDOS}s...", flush=True)
            time.sleep(PAUSA_SEGUNDOS)

    # Gera CSV final
    print(f"\nGerando {ARQUIVO_SAIDA} ...")
    with open(ARQUIVO_SAIDA, "w", newline="", encoding="utf-8-sig") as f:
        w = csv.writer(f)
        w.writerow(["uf", "variante_no_banco", "canonical", "tipo"])
        for uf in UFS:
            for variante, canonical in progresso.get(uf, []):
                if variante.upper() == canonical:
                    tipo = "acento/caixa"
                elif _base_cidade(variante) != variante.upper():
                    tipo = "ruido (UF sufixo / parenteses)"
                else:
                    tipo = "typo/abreviacao"
                w.writerow([uf, variante, canonical, tipo])

    total = sum(len(v) for v in progresso.values())
    print(f"Concluído. {total} variantes exportadas.")

    # Remove arquivo de progresso
    if ARQUIVO_PROGRESSO.exists():
        ARQUIVO_PROGRESSO.unlink()


if __name__ == "__main__":
    main()
