"""
bairros_api.py
--------------
Consulta bairros de forma dinâmica usando fontes públicas oficiais / abertas:

  1. IBGE Localidades API — resolve o nome oficial do município e obtém o
     código IBGE (necessário para a query do Overpass).
  2. Overpass API (OpenStreetMap) — retorna os bairros cadastrados no OSM
     para o município, usando as tags place=neighbourhood e place=suburb.

Por que não só o IBGE?
  O IBGE não possui uma API pública para bairros. A endpoint
  /localidades/municipios/{id}/subdistritos retorna lista vazia para a
  maioria dos municípios brasileiros. Bairros são entidades municipais,
  não federais — cada prefeitura os define de forma diferente.

Por que OSM/Overpass?
  - Gratuito, sem chave de API
  - Atualizado continuamente por colaboradores e prefeituras
  - Cobre todos os municípios brasileiros
  - Respeita User-Agent correto (obrigatório pela política do OSM)

Cache em memória:
  Resultados ficam em cache por CACHE_TTL_HORAS horas para evitar
  excesso de requisições às APIs externas.
"""

import gzip
import io
import time
import unicodedata
import urllib.parse
import urllib.request
import json
import logging

logger = logging.getLogger(__name__)

# ============================================================
# CONFIGURAÇÕES
# ============================================================

CACHE_TTL_HORAS   = 24          # horas que o resultado fica em cache
TIMEOUT_IBGE      = 8           # segundos de timeout para IBGE
TIMEOUT_OVERPASS  = 30          # segundos de timeout para Overpass

USER_AGENT = "ProjetoListasPF/1.0 (lista-pf@contatus.com.br)"

IBGE_MUNICIPIOS_URL = (
    "https://servicodados.ibge.gov.br/api/v1/localidades/municipios"
    "?nome={nome}"
)

# Query Overpass: busca bairros dentro do município pelo nome oficial.
# admin_level=8 corresponde a município no Brasil.
# Inclui place=neighbourhood e place=suburb.
OVERPASS_URL = "https://overpass-api.de/api/interpreter"
OVERPASS_QUERY = """
[out:json][timeout:30];
area["name"="{nome_cidade}"]["admin_level"="8"]->.a;
(
  node["place"="neighbourhood"](area.a);
  node["place"="suburb"](area.a);
  way["place"="neighbourhood"](area.a);
  way["place"="suburb"](area.a);
);
out tags;
"""


# ============================================================
# CACHE SIMPLES
# ============================================================

_cache: dict[str, tuple[float, list[str]]] = {}
# { chave: (timestamp, [bairros]) }


def _chave_cache(cidade: str) -> str:
    return _normalizar(cidade)


def _cache_valido(chave: str) -> bool:
    if chave not in _cache:
        return False
    ts, _ = _cache[chave]
    return (time.time() - ts) < CACHE_TTL_HORAS * 3600


def _salvar_cache(chave: str, bairros: list[str]) -> None:
    _cache[chave] = (time.time(), bairros)


# ============================================================
# UTILITÁRIOS
# ============================================================

def _normalizar(texto: str) -> str:
    """Remove acentos e converte para maiúsculo (comparações)."""
    s = str(texto).strip().upper()
    s = unicodedata.normalize("NFKD", s)
    return "".join(c for c in s if not unicodedata.combining(c))


def _get_json(url: str, timeout: int = 10) -> dict | list | None:
    """Faz GET e retorna JSON. Suporta resposta gzip. Retorna None se falhar."""
    req = urllib.request.Request(
        url,
        headers={
            "User-Agent":      USER_AGENT,
            "Accept-Encoding": "gzip, deflate",
            "Accept":          "application/json",
        },
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            raw = resp.read()
            encoding = resp.headers.get("Content-Encoding", "")
            if encoding == "gzip":
                raw = gzip.decompress(raw)
            elif encoding == "deflate":
                import zlib
                raw = zlib.decompress(raw)
            return json.loads(raw.decode("utf-8"))
    except Exception as exc:
        logger.warning("GET falhou (%s): %s", url[:80], exc)
        return None


def _post_json(url: str, data: str, timeout: int = 30) -> dict | list | None:
    """Faz POST e retorna JSON. Suporta resposta gzip. Retorna None se falhar."""
    payload = data.encode("utf-8")
    req = urllib.request.Request(
        url,
        data=payload,
        headers={
            "User-Agent":      USER_AGENT,
            "Content-Type":    "application/x-www-form-urlencoded",
            "Accept-Encoding": "gzip, deflate",
        },
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            raw = resp.read()
            encoding = resp.headers.get("Content-Encoding", "")
            if encoding == "gzip":
                raw = gzip.decompress(raw)
            elif encoding == "deflate":
                import zlib
                raw = zlib.decompress(raw)
            return json.loads(raw.decode("utf-8"))
    except Exception as exc:
        logger.warning("POST falhou (%s): %s", url, exc)
        return None


# ============================================================
# STEP 1 — IBGE: obter código do município
# ============================================================

# Aliases comuns → nome oficial IBGE
_ALIASES: dict[str, str] = {
    "BH":          "Belo Horizonte",
    "DF":          "Brasília",
    "BRASILIA":    "Brasília",
    "RIO":         "Rio de Janeiro",
    "SP":          "São Paulo",
    "SAMPA":       "São Paulo",
    "FORTALEZA":   "Fortaleza",
    "FLORIPA":     "Florianópolis",
    "GOIANIA":     "Goiânia",
    "MACEIO":      "Maceió",
    "JOAO PESSOA": "João Pessoa",
    "NATAL":       "Natal",
    "TERESINA":    "Teresina",
    "BELEM":       "Belém",
    "MANAUS":      "Manaus",
}


def _resolver_nome_ibge(cidade: str) -> str:
    """Devolve o nome oficial para usar na API caso o alias exista."""
    chave = _normalizar(cidade)
    for alias, oficial in _ALIASES.items():
        if _normalizar(alias) == chave:
            return oficial
    return cidade.strip()


def _buscar_municipio_ibge(cidade: str) -> dict | None:
    """
    Consulta a API IBGE Localidades e devolve o objeto do primeiro
    município cujo nome normalizado coincide com a cidade buscada.
    Retorna None se não encontrar.
    """
    nome_oficial = _resolver_nome_ibge(cidade)
    nome_enc = urllib.parse.quote(nome_oficial)
    url = IBGE_MUNICIPIOS_URL.format(nome=nome_enc)
    dados = _get_json(url, timeout=TIMEOUT_IBGE)
    if not dados:
        return None

    # Compara com o nome oficial resolvido (não o alias original)
    chave_busca = _normalizar(nome_oficial)
    for mun in dados:
        if _normalizar(mun.get("nome", "")) == chave_busca:
            return mun

    # Fallback: primeiro resultado se só houver um
    if len(dados) == 1:
        return dados[0]

    return None


# ============================================================
# STEP 2 — Overpass/OSM: obter bairros
# ============================================================

def _buscar_bairros_overpass(nome_cidade: str) -> list[str]:
    """
    Consulta o Overpass API usando o nome oficial do município (IBGE).
    Devolve lista de bairros em ordem alfabética.
    """
    query = OVERPASS_QUERY.format(nome_cidade=nome_cidade)
    payload = "data=" + urllib.parse.quote(query)
    resultado = _post_json(OVERPASS_URL, payload, timeout=TIMEOUT_OVERPASS)

    if not resultado or "elements" not in resultado:
        return []

    bairros: set[str] = set()
    for elem in resultado["elements"]:
        tags = elem.get("tags", {})
        # Prioriza nome em português (name:pt), senão name
        nome = tags.get("name:pt") or tags.get("name") or ""
        nome = nome.strip()
        if nome and len(nome) > 2:
            bairros.add(nome.upper())

    return sorted(bairros)


# ============================================================
# API PÚBLICA
# ============================================================

def obter_bairros(cidade: str) -> list[str]:
    """
    Retorna a lista de bairros de uma cidade, consultando OSM via
    Overpass API. Resultados são cacheados por CACHE_TTL_HORAS horas.

    Parâmetros
    ----------
    cidade : str — nome da cidade (aceita aliases como "BH", "RIO")

    Retorna
    -------
    list[str] — bairros em ordem alfabética, todos em maiúsculas.
                Lista vazia se a cidade não for encontrada.
    """
    chave = _chave_cache(cidade)

    if _cache_valido(chave):
        logger.debug("Cache hit para '%s'", cidade)
        return _cache[chave][1]

    logger.info("Consultando IBGE para '%s'...", cidade)
    municipio = _buscar_municipio_ibge(cidade)

    if not municipio:
        logger.warning("Município '%s' não encontrado no IBGE.", cidade)
        _salvar_cache(chave, [])
        return []

    ibge_id   = municipio["id"]
    nome_real = municipio["nome"]
    logger.info("Município encontrado: %s (IBGE: %s). Consultando Overpass...",
                nome_real, ibge_id)

    bairros = _buscar_bairros_overpass(nome_real)
    logger.info("%d bairros encontrados para %s.", len(bairros), nome_real)

    _salvar_cache(chave, bairros)
    return bairros


def listar_cidades() -> list[str]:
    """
    Retorna lista de cidades que já estão no cache.
    Útil para pré-aquecer o cache ou para listar cidades disponíveis.
    """
    return [chave.title() for chave in _cache if _cache_valido(chave)]


def cidades_para_select() -> list[str]:
    """
    Retorna lista de cidades em cache (pode ser vazia na inicialização).
    """
    return listar_cidades()


def limpar_cache() -> None:
    """Limpa o cache manualmente (útil para testes)."""
    _cache.clear()
