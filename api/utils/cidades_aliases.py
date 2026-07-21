"""
cidades_aliases.py
------------------
Correspondência de variantes de escrita para cidades no banco bd_contatus.

O banco usa COLLATE utf8mb4_unicode_ci — variantes de acento (SÃO PAULO =
SAO PAULO) já são tratadas automaticamente pelo MySQL nas comparações SQL.
Este módulo cuida de variantes com LETRAS diferentes (typos de digitação)
nas cidades mais frequentes do banco.

Uso:
  expandir_cidades() → chamada em query_builder.py antes do WHERE cidade IN
  agrupar_cidades()  → chamada em localidades.py para deduplicar dropdown
"""

from __future__ import annotations
import re
import unicodedata
from difflib import SequenceMatcher

# Todas as siglas de UF do Brasil
_UFS: frozenset[str] = frozenset([
    "AC", "AL", "AP", "AM", "BA", "CE", "DF", "ES", "GO", "MA",
    "MT", "MS", "MG", "PA", "PB", "PR", "PE", "PI", "RJ", "RN",
    "RS", "RO", "RR", "SC", "SP", "SE", "TO",
])

_RE_PARENS_FULL   = re.compile(r'^\((.+)\)$')   # string inteira entre parênteses
_RE_PARENS_SUFFIX = re.compile(r'\s*\(.*?\)')   # parênteses no sufixo


def normalizar(cidade: str) -> str:
    """Remove acentos, espaços extras e converte para maiúsculo."""
    s = str(cidade).strip().upper()
    s = unicodedata.normalize("NFKD", s)
    s = "".join(c for c in s if not unicodedata.combining(c))
    return " ".join(s.split())


def _base_cidade(cidade: str) -> str:
    """
    Limpa o nome de cidade removendo ruídos comuns do banco:

      1. Parênteses e seu conteúdo
           "(MACAPA)"        → "MACAPA"
           "MACAPA (AP)"     → "MACAPA"
           "MACAPA (AMAPA)"  → "MACAPA"

      2. Sigla de UF no final
           "AGUA BRANCA AL"  → "AGUA BRANCA"
           "FLORIANOPOLIS SC"→ "FLORIANOPOLIS"

    Retorna a string original normalizada se nenhum padrão for detectado.
    """
    norm = normalizar(cidade)

    # 1. Remove parênteses
    #    Caso inteiro: "(MACAPA)"       → "MACAPA"
    #    Caso sufixo:  "MACAPA (AP)"   → "MACAPA"
    m = _RE_PARENS_FULL.match(norm)
    if m:
        norm = m.group(1).strip()
    else:
        norm = _RE_PARENS_SUFFIX.sub("", norm).strip()
    if not norm:
        norm = normalizar(cidade)

    # 2. Remove sigla de UF no final (ex: "AGUA BRANCA AL")
    partes = norm.rsplit(" ", 1)
    if len(partes) == 2 and partes[1] in _UFS and len(partes[0]) >= 3:
        norm = partes[0]

    return norm


def _sufixo_cidade_conhecida(nome: str, canonicos: frozenset[str]) -> str | None:
    """
    Verifica se 'nome' termina com um nome de cidade canônica.
    Usado para detectar "ABACATE DA PEDREIRA MACAPA" → "MACAPA".

    Testa de 1 até 4 palavras finais. Retorna o canônico se encontrado.
    """
    partes = nome.split()
    for n in range(1, min(5, len(partes))):
        sufixo = " ".join(partes[-n:])
        if sufixo in canonicos and sufixo != nome:
            return sufixo
    return None


# Mapeamento: nome_canônico → [todas as variantes conhecidas no banco]
# Inclui o próprio canonical na lista para que expandir_cidades() sempre
# o retorne. Não inclui variantes de acento (ex: Ó/O) — o MySQL já trata.
_VARIANTES: dict[str, list[str]] = {
    # ── Santa Catarina ────────────────────────────────────────────────────
    "FLORIANOPOLIS": [
        "FLORIANOPOLIS", "FLORIANOPLIS", "FLORIANOPOLES",
        "FLORIANOPOLISS", "FLORANOPOLIS", "FLORIONOPOLIS",
    ],
    "JOINVILLE": [
        "JOINVILLE", "JOINVILE", "JOINVILLES", "JONVILLE", "JONIVILLE",
    ],
    "BLUMENAU": [
        "BLUMENAU", "BLUMENA", "BLUMENAUS", "BLUMENAUX",
    ],
    "SAO JOSE": [
        "SAO JOSE", "SAOJOSE", "S JOSE", "STO JOSE", "SAO JOZE",
    ],
    "CHAPECO": [
        "CHAPECO", "CHAPECÓ", "XAPECO", "CHAPEÇO",
    ],
    "CRICIUMA": [
        "CRICIUMA", "CRIÇIUMA", "CRICIMA", "CRICUMA", "CRISSIUMA",
    ],
    "ITAJAI": [
        "ITAJAI", "ITAJAÍ", "ITAJHAI",
    ],
    "LAGES": [
        "LAGES", "LAGEST", "LAGEZ",
    ],
    "JARAGUA DO SUL": [
        "JARAGUA DO SUL", "JARAGUÁ DO SUL", "JARAGUA SUL", "JARAGUA D SUL",
    ],
    "CAMBORIU": [
        "CAMBORIU", "CAMBORIÚ", "CAMBORUI",
    ],
    "BALNEARIO CAMBORIU": [
        "BALNEARIO CAMBORIU", "BALNEÁRIO CAMBORIÚ", "BAL CAMBORIU",
        "BALNEAREO CAMBORIU", "BALNEARIO CAMBORUI", "BALNEARIO CAMBORIÚ",
    ],
    "PALHOCA": [
        "PALHOCA", "PALHOÇA", "PALHORAS",
    ],
    "BRUSQUE": [
        "BRUSQUE", "BRUSKE", "BRUSQUES",
    ],
    "TUBARAO": [
        "TUBARAO", "TUBARÃO", "TUBARAÃO",
    ],
    "SAO BENTO DO SUL": [
        "SAO BENTO DO SUL", "STO BENTO DO SUL", "SAO BENTO SUL", "S BENTO DO SUL",
    ],
    "RIO DO SUL": [
        "RIO DO SUL", "RIO SUL",
    ],
    "CONCORDIA": [
        "CONCORDIA", "CONCÓRDIA", "CONCORDÍA",
    ],
    "CANOINHAS": [
        "CANOINHAS", "CANONHAS", "CANOINHA",
    ],
    "ARARANGUA": [
        "ARARANGUA", "ARARANGUÁ", "ARARANGUÃ", "ARARA NGUA",
    ],
    "NAVEGANTES": [
        "NAVEGANTES", "NAVEGANTE",
    ],
    "SAO FRANCISCO DO SUL": [
        "SAO FRANCISCO DO SUL", "S FRANCISCO DO SUL", "SAO FRANCISCO SUL",
    ],
    "GASPAR": [
        "GASPAR", "GASPÁR",
    ],
    "INDAIAL": [
        "INDAIAL", "INDAÍAL", "INDAYAL",
    ],
    "BIGUACU": [
        "BIGUACU", "BIGUAÇU", "BIGUASSU",
    ],
    "POMERODE": [
        "POMERODE", "POMEROD",
    ],
    "TIMBO": [
        "TIMBO", "TIMBÓ",
    ],
    "XANXERE": [
        "XANXERE", "XANXERÊ", "XANXERÊ",
    ],
    "LAGUNA": [
        "LAGUNA", "LAGUNAH",
    ],
    "IMBITUBA": [
        "IMBITUBA", "IMBITUBAL",
    ],
    "JOACABA": [
        "JOACABA", "JOAÇABA", "JOACABÁ",
    ],

    # ── Paraná ────────────────────────────────────────────────────────────
    "CURITIBA": [
        "CURITIBA", "CURTIBA", "CURITIBAS", "CURITÍBA",
    ],
    "LONDRINA": [
        "LONDRINA", "LONDRINAS", "LOND RINA",
    ],
    "MARINGA": [
        "MARINGA", "MARINGÁ", "MARINGA",
    ],
    "PONTA GROSSA": [
        "PONTA GROSSA", "PTA GROSSA", "PTA GOSSA",
    ],
    "CASCAVEL": [
        "CASCAVEL", "CASCAVELZ",
    ],
    "SAO JOSE DOS PINHAIS": [
        "SAO JOSE DOS PINHAIS", "STO JOSE DOS PINHAIS", "SAO JOSE PINHAIS",
    ],
    "FOZ DO IGUACU": [
        "FOZ DO IGUACU", "FOZ DO IGUAÇU", "FOZ IGUACU", "FOZ D IGUACU",
    ],
    "COLOMBO": [
        "COLOMBO",
    ],
    "GUARAPUAVA": [
        "GUARAPUAVA", "GUARAPUAV",
    ],
    "ARAUCARIA": [
        "ARAUCARIA", "ARAUCÁRIA", "ARAUCARÍA",
    ],
    "TOLEDO": [
        "TOLEDO", "TOLÊDO",
    ],
    "APUCARANA": [
        "APUCARANA", "APUCARANAS",
    ],

    # ── Rio Grande do Sul ─────────────────────────────────────────────────
    "PORTO ALEGRE": [
        "PORTO ALEGRE", "POA", "P ALEGRE", "PORT ALEGRE",
    ],
    "CAXIAS DO SUL": [
        "CAXIAS DO SUL", "CAXIAS SUL", "CAXIAS D SUL",
    ],
    "PELOTAS": [
        "PELOTAS", "PELOTASM",
    ],
    "CANOAS": [
        "CANOAS", "CANOS",
    ],
    "NOVO HAMBURGO": [
        "NOVO HAMBURGO", "N HAMBURGO", "NVO HAMBURGO", "NOVO HAMB",
    ],
    "SAO LEOPOLDO": [
        "SAO LEOPOLDO", "S LEOPOLDO", "STO LEOPOLDO",
    ],
    "GRAVATAI": [
        "GRAVATAI", "GRAVATAÍ", "GRAVATAY",
    ],
    "VIAMAO": [
        "VIAMAO", "VIAMÃO",
    ],
    "SANTA MARIA": [
        "SANTA MARIA", "STA MARIA", "STA. MARIA",
    ],
    "PASSO FUNDO": [
        "PASSO FUNDO", "PASSO FUND",
    ],
    "SAPUCAIA DO SUL": [
        "SAPUCAIA DO SUL", "SAPUCAIA SUL",
    ],
    "CACHOEIRINHA": [
        "CACHOEIRINHA", "CACHOEIRNHA",
    ],

    # ── São Paulo ─────────────────────────────────────────────────────────
    "SAO PAULO": [
        "SAO PAULO", "S PAULO", "SÃO PAULO", "SAOPAULO",
    ],
    "CAMPINAS": [
        "CAMPINAS", "CAMPINA",
    ],
    "GUARULHOS": [
        "GUARULHOS", "GUARULOS", "GUARULHOSS",
    ],
    "RIBEIRAO PRETO": [
        "RIBEIRAO PRETO", "RIBEIRÃO PRETO", "RIB PRETO", "RIBERAO PRETO",
        "RIBEIRÃO PRETO", "RIBEIRAO PRÊTO",
    ],
    "SOROCABA": [
        "SOROCABA", "SOROCAB",
    ],
    "SAO BERNARDO DO CAMPO": [
        "SAO BERNARDO DO CAMPO", "SAO BERNARDO", "S BERNARDO DO CAMPO",
        "STO BERNARDO DO CAMPO",
    ],
    "SAO JOSE DOS CAMPOS": [
        "SAO JOSE DOS CAMPOS", "SAOJOSE DOS CAMPOS", "SJC",
        "SAO JOSE D CAMPOS", "S JOSE DOS CAMPOS",
    ],
    "OSASCO": [
        "OSASCO", "OSASCOS",
    ],
    "SANTO ANDRE": [
        "SANTO ANDRE", "STO ANDRE", "STO ANDRÉ",
    ],
    "MOGI DAS CRUZES": [
        "MOGI DAS CRUZES", "MOGY DAS CRUZES", "MOGI D CRUZES",
    ],
    "DIADEMA": [
        "DIADEMA", "DIADÊMA",
    ],
    "JUNDIAI": [
        "JUNDIAI", "JUNDIAÍ",
    ],
    "PIRACICABA": [
        "PIRACICABA", "PIRASICABA",
    ],
    "BAURU": [
        "BAURU", "BAUR",
    ],
    "SAO JOSE DO RIO PRETO": [
        "SAO JOSE DO RIO PRETO", "S JOSE DO RIO PRETO", "SJR PRETO",
        "SJRP", "RIO PRETO",
    ],

    # ── Rio de Janeiro ────────────────────────────────────────────────────
    "RIO DE JANEIRO": [
        "RIO DE JANEIRO", "RIO", "RJ", "R DE JANEIRO",
    ],
    "NITEROI": [
        "NITEROI", "NITERÓI",
    ],
    "DUQUE DE CAXIAS": [
        "DUQUE DE CAXIAS", "DUQUE CAXIAS", "DQUE DE CAXIAS",
    ],
    "NOVA IGUACU": [
        "NOVA IGUACU", "NOVA IGUAÇU", "N IGUACU",
    ],
    "SAO GONCALO": [
        "SAO GONCALO", "SÃO GONÇALO", "S GONCALO",
    ],
    "BELFORD ROXO": [
        "BELFORD ROXO", "BELFORT ROXO",
    ],

    # ── Minas Gerais ──────────────────────────────────────────────────────
    "BELO HORIZONTE": [
        "BELO HORIZONTE", "BH", "B HORIZONTE", "BELO HORIZONTE",
    ],
    "UBERLANDIA": [
        "UBERLANDIA", "UBERLÂNDIA", "UBERLAND",
    ],
    "CONTAGEM": [
        "CONTAGEM", "CONTAGM",
    ],
    "JUIZ DE FORA": [
        "JUIZ DE FORA", "JUIZ FORA",
    ],
    "BETIM": [
        "BETIM", "BETINS",
    ],
    "MONTES CLAROS": [
        "MONTES CLAROS", "MONTES CLAR",
    ],

    # ── Capitais e outras cidades relevantes ──────────────────────────────
    "SALVADOR": [
        "SALVADOR", "SALVADORE",
    ],
    "FORTALEZA": [
        "FORTALEZA", "FORTALEZAS",
    ],
    "MANAUS": [
        "MANAUS", "MANUS", "MANÁUS",
    ],
    "RECIFE": [
        "RECIFE", "RECIFES",
    ],
    "BELEM": [
        "BELEM", "BELÉM", "BELEN",
    ],
    "GOIANIA": [
        "GOIANIA", "GOIÂNIA", "GOYANIA",
    ],
    "BRASILIA": [
        "BRASILIA", "BRASÍLIA", "BRAZILIA", "BRASÍLA",
    ],
    "MACEIO": [
        "MACEIO", "MACEIÓ",
    ],
    "NATAL": [
        "NATAL",
    ],
    "TERESINA": [
        "TERESINA",
    ],
    "CAMPO GRANDE": [
        "CAMPO GRANDE", "CAMPO GRANDEM",
    ],
    "JOAO PESSOA": [
        "JOAO PESSOA", "JOÃO PESSOA", "JP", "J PESSOA",
    ],
    "ARACAJU": [
        "ARACAJU", "ARACAJÚ",
    ],
    "CUIABA": [
        "CUIABA", "CUIABÁ",
    ],
    "PORTO VELHO": [
        "PORTO VELHO", "P VELHO",
    ],
    "RIO BRANCO": [
        "RIO BRANCO", "R BRANCO",
    ],
    "MACAPA": [
        "MACAPA", "MACAPÁ",
    ],
    "BOA VISTA": [
        "BOA VISTA", "BOA VISTAS",
    ],
    "PALMAS": [
        "PALMAS",
    ],
    "SAO LUIS": [
        "SAO LUIS", "SÃO LUÍS", "SAO LUÍS", "S LUIS",
    ],
}

# ── Índices derivados ─────────────────────────────────────────────────────
# _base(variante) → nome_canônico
_NORM_PARA_CANONICAL: dict[str, str] = {}
# _base(variante) → lista_completa_de_variantes do dict estático
_NORM_PARA_VARIANTES: dict[str, list[str]] = {}

for _canonical, _variantes in _VARIANTES.items():
    _norm_c = _base_cidade(_canonical)
    for _v in _variantes:
        _norm_v = _base_cidade(_v)
        _NORM_PARA_CANONICAL[_norm_v] = _canonical
        _NORM_PARA_VARIANTES[_norm_v] = _variantes
    _NORM_PARA_CANONICAL.setdefault(_norm_c, _canonical)
    _NORM_PARA_VARIANTES.setdefault(_norm_c, _variantes)


# ── API pública ───────────────────────────────────────────────────────────

def expandir_cidades(cidades: list[str], ufs: list[str] | None = None) -> list[str]:
    """
    Recebe lista de cidades selecionadas e retorna lista expandida com
    todas as variantes conhecidas no banco.

    Parâmetros
    ----------
    cidades : nomes canônicos selecionados pelo usuário
    ufs     : siglas dos estados filtrados (opcional). Quando informado,
              inclui também a forma "CIDADE UF" para capturar registros
              onde alguém digitou a sigla junto ao nome da cidade.

    Exemplos:
      expandir_cidades(["FLORIANOPOLIS"], ufs=["SC"])
      → ["FLORIANOPOLIS", "FLORIANOPLIS", ..., "FLORIANOPOLIS SC"]

      expandir_cidades(["AGUA BRANCA"], ufs=["AL"])
      → ["AGUA BRANCA", "AGUA BRANCA AL"]
    """
    resultado: list[str] = []
    visto: set[str] = set()
    ufs_norm = [u.strip().upper() for u in (ufs or [])]

    for cidade in cidades:
        # Resolve forma base: remove parênteses e sufixo UF
        base = _base_cidade(cidade)

        variantes_estaticas = _NORM_PARA_VARIANTES.get(base)
        if variantes_estaticas:
            for v in variantes_estaticas:
                if v not in visto:
                    resultado.append(v)
                    visto.add(v)
        else:
            # Não mapeado: inclui só a forma base limpa
            if base not in visto:
                resultado.append(base)
                visto.add(base)

        # Inclui "CIDADE UF" para capturar registros onde alguém digitou
        # a sigla do estado junto ao nome da cidade no banco
        for uf in ufs_norm:
            com_uf = f"{base} {uf}"
            if com_uf not in visto:
                resultado.append(com_uf)
                visto.add(com_uf)

    return resultado


def _sim(a: str, b: str) -> float:
    return SequenceMatcher(None, a, b).ratio()


def agrupar_cidades(cidades_db: list) -> list[str]:
    """
    Recebe lista bruta de cidades do banco e retorna lista deduplicada.

    Aceita:
      - list[str]              — cidades sem contagem
      - list[tuple[str, int]]  — (cidade, qtd) vindas do GROUP BY

    Quando as contagens são fornecidas, ordena por frequência descendente:
    a forma mais frequente no banco se torna o nome canônico, e variantes
    menos frequentes colapsam nela por:
      1. Dict estático (typos mapeados)
      2. Padrão "BAIRRO CIDADE" (sufixo é uma cidade conhecida)
      3. Fuzzy match: similaridade ≥ 0.82 OU prefixo significativo (≥ 6 chars)
         — captura FLORIANAPOLIS, FLORIANPOLIS, FLORIANO → FLORIANOPOLIS

    Também limpa automaticamente:
      - Parênteses: "(MACAPA)", "MACAPA (AP)" → "MACAPA"
      - Sufixo UF:  "AGUA BRANCA AL"          → "AGUA BRANCA"
    """
    # Normaliza input: garante lista de (str, int)
    if cidades_db and isinstance(cidades_db[0], (tuple, list)):
        pares: list[tuple[str, int]] = [(str(c), int(n)) for c, n in cidades_db]
    else:
        pares = [(str(c), 1) for c in cidades_db]

    # Ordena por frequência desc — mais frequente vira canônico
    pares.sort(key=lambda x: x[1], reverse=True)

    _canonicos_dict = frozenset(_VARIANTES.keys())

    # Conjunto de bases presentes no banco para este estado.
    # Usado para evitar que um canonical de outro estado "invada" a lista:
    # ex: SP tem "PORT ALEGRE" (typo) → canonical "PORTO ALEGRE" (RS) →
    # só aceita se "PORTO ALEGRE" também existe nos dados brutos de SP.
    bases_no_banco: set[str] = {_base_cidade(c) for c, _ in pares}

    # canonicos: lista ordenada de inserção (= ordem de frequência)
    canonicos: list[str] = []

    for cidade_raw, _ in pares:
        base = _base_cidade(cidade_raw)

        # 1. Dict estático — só aplica se o canonical pertence a este estado
        #    (i.e., o próprio canonical ou sua base aparece no banco daqui)
        canonical_static = _NORM_PARA_CANONICAL.get(base)
        if canonical_static:
            canonical_base = _base_cidade(canonical_static)
            if canonical_base in bases_no_banco:
                if canonical_static not in canonicos:
                    canonicos.append(canonical_static)
            else:
                # Canonical é de outro estado — mantém a base limpa local
                if base not in canonicos:
                    canonicos.append(base)
            continue

        # 2. Sufixo de cidade conhecida ("ABACATE DA PEDREIRA MACAPA" → "MACAPA")
        #    Mesma proteção: só aplica se o sufixo existe neste estado
        sufixo = _sufixo_cidade_conhecida(base, _canonicos_dict)
        if sufixo and sufixo in bases_no_banco:
            if sufixo not in canonicos:
                canonicos.append(sufixo)
            continue

        # 3. Fuzzy match contra canônicos já estabelecidos
        matched = False
        for c in canonicos:
            sim = _sim(base, c)
            # Prefixo significativo: "FLORIANO" é prefixo de "FLORIANOPOLIS"
            if len(base) >= 6 and c.startswith(base):
                sim = max(sim, 0.88)
            if sim >= 0.82:
                matched = True
                break
        if matched:
            continue

        canonicos.append(base)

    return sorted(canonicos)
