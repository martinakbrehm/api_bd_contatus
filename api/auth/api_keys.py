"""
api/auth/api_keys.py
--------------------
Gerenciamento de API Keys para autenticação de serviços.

Funcionalidades:
  - CRUD de API Keys
  - Validação com hash seguro (bcrypt)
  - Persistência em arquivo JSON (em produção: banco/vault)
  - Tracking de uso por key
  - Expiração de keys
"""

import hashlib
import json
import secrets
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from api.config import API_KEYS_FILE


# ── Estrutura de uma API Key ──────────────────────────────────
# {
#   "key_id": "prefixo público (primeiros 8 chars)",
#   "key_hash": "SHA-256 da chave completa",
#   "nome": "Nome descritivo",
#   "role": "admin|user|readonly",
#   "ativo": true/false,
#   "criado_em": "ISO 8601",
#   "expira_em": "ISO 8601" ou null,
#   "ultimo_uso": "ISO 8601" ou null,
#   "total_requests": 0,
#   "ip_restrito": ["192.168.1.0/24"] ou [],
# }

_KEY_PREFIX = "lspf_"  # prefixo identificador: Lista Segura PF


def _hash_key(api_key: str) -> str:
    """Hash SHA-256 da API key para armazenamento seguro."""
    return hashlib.sha256(api_key.encode("utf-8")).hexdigest()


def _carregar_keys() -> dict:
    """Carrega as API keys do arquivo JSON."""
    if not API_KEYS_FILE.exists():
        return {}
    try:
        with open(API_KEYS_FILE, "r", encoding="utf-8") as f:
            return json.load(f)
    except (json.JSONDecodeError, IOError):
        return {}


def _salvar_keys(keys: dict) -> None:
    """Salva as API keys no arquivo JSON com permissões restritas."""
    with open(API_KEYS_FILE, "w", encoding="utf-8") as f:
        json.dump(keys, f, indent=2, ensure_ascii=False, default=str)


def gerar_api_key(
    nome: str,
    role: str = "user",
    ip_restrito: Optional[list[str]] = None,
    expira_em_dias: Optional[int] = None,
) -> tuple[str, str]:
    """
    Gera uma nova API Key.

    Parâmetros
    ----------
    nome            : Nome descritivo (ex: "App Frontend")
    role            : Papel: "admin", "user", "readonly"
    ip_restrito     : Lista de IPs/CIDRs autorizados (vazio = todos)
    expira_em_dias  : Dias até expiração (None = sem expiração)

    Retorna
    -------
    (api_key, key_id) : A chave completa (mostrar apenas uma vez!) e o ID público
    """
    if role not in ("admin", "user", "readonly"):
        raise ValueError(f"Role inválido: {role}. Use: admin, user, readonly")

    # Gerar chave criptograficamente segura
    raw_key = secrets.token_hex(32)  # 64 caracteres hex = 256 bits
    api_key = f"{_KEY_PREFIX}{raw_key}"
    key_id = api_key[:12]  # prefixo público para identificação

    now = datetime.now(timezone.utc)
    expira = None
    if expira_em_dias:
        from datetime import timedelta
        expira = (now + timedelta(days=expira_em_dias)).isoformat()

    keys = _carregar_keys()
    keys[key_id] = {
        "key_id": key_id,
        "key_hash": _hash_key(api_key),
        "nome": nome,
        "role": role,
        "ativo": True,
        "criado_em": now.isoformat(),
        "expira_em": expira,
        "ultimo_uso": None,
        "total_requests": 0,
        "ip_restrito": ip_restrito or [],
    }
    _salvar_keys(keys)

    return api_key, key_id


def validar_api_key(api_key: str, ip_origem: Optional[str] = None) -> Optional[dict]:
    """
    Valida uma API key e retorna os dados associados.

    Verificações:
      1. Formato correto (prefixo)
      2. Hash corresponde a uma key registrada
      3. Key está ativa
      4. Key não expirou
      5. IP de origem permitido (se restrição configurada)

    Retorna
    -------
    dict com dados da key, ou None se inválida
    """
    if not api_key or not api_key.startswith(_KEY_PREFIX):
        return None

    key_hash = _hash_key(api_key)
    keys = _carregar_keys()

    # Buscar por hash (não por key_id — segurança por comparação de hash)
    for kid, dados in keys.items():
        if dados.get("key_hash") != key_hash:
            continue

        # Encontrou — verificar estado
        if not dados.get("ativo", False):
            return None

        # Verificar expiração
        expira_em = dados.get("expira_em")
        if expira_em:
            try:
                exp_dt = datetime.fromisoformat(expira_em)
                if datetime.now(timezone.utc) > exp_dt:
                    return None  # expirada
            except (ValueError, TypeError):
                pass

        # Verificar restrição de IP
        ips_restritos = dados.get("ip_restrito", [])
        if ips_restritos and ip_origem:
            if not _ip_permitido(ip_origem, ips_restritos):
                return None

        # Atualizar tracking de uso
        dados["ultimo_uso"] = datetime.now(timezone.utc).isoformat()
        dados["total_requests"] = dados.get("total_requests", 0) + 1
        _salvar_keys(keys)

        return dados

    return None


def desativar_api_key(key_id: str) -> bool:
    """Desativa uma API key pelo seu ID público."""
    keys = _carregar_keys()
    if key_id in keys:
        keys[key_id]["ativo"] = False
        _salvar_keys(keys)
        return True
    return False


def listar_keys() -> list[dict]:
    """Lista todas as API keys (sem os hashes)."""
    keys = _carregar_keys()
    resultado = []
    for kid, dados in keys.items():
        info = {k: v for k, v in dados.items() if k != "key_hash"}
        resultado.append(info)
    return resultado


def _ip_permitido(ip: str, lista_permitidos: list[str]) -> bool:
    """Verifica se o IP está na lista de permitidos (suporte CIDR básico)."""
    import ipaddress
    try:
        ip_addr = ipaddress.ip_address(ip)
        for permitido in lista_permitidos:
            try:
                if "/" in permitido:
                    rede = ipaddress.ip_network(permitido, strict=False)
                    if ip_addr in rede:
                        return True
                else:
                    if ip_addr == ipaddress.ip_address(permitido):
                        return True
            except ValueError:
                continue
        return False
    except ValueError:
        return False
