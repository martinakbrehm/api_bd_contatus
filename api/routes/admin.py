"""
api/routes/admin.py
-------------------
Endpoints administrativos (apenas role=admin).

Rotas:
  POST   /api/v1/admin/keys          → criar nova API Key
  GET    /api/v1/admin/keys          → listar API Keys
  DELETE /api/v1/admin/keys/<key_id> → desativar API Key
"""

from flask import Blueprint, g, jsonify, request

from api.auth.api_keys import desativar_api_key, gerar_api_key, listar_keys
from api.auth.decorators import _get_client_ip, require_auth, require_role
from api.utils.audit_logger import log_security_event

admin_bp = Blueprint("admin", __name__, url_prefix="/api/v1/admin")


@admin_bp.route("/keys", methods=["POST"])
@require_auth
@require_role("admin")
def criar_key():
    """
    Cria uma nova API Key.

    Body (JSON):
    {
      "nome": "App Frontend",
      "role": "user",
      "ip_restrito": ["192.168.1.0/24"],
      "expira_em_dias": 90
    }

    Resposta (201):
    {
      "api_key": "lspf_...",        ← MOSTRADA APENAS UMA VEZ!
      "key_id": "lspf_abc123...",
      "aviso": "Guarde esta chave..."
    }
    """
    data = request.get_json(silent=True) or {}

    nome = data.get("nome", "").strip()
    if not nome or len(nome) > 100:
        return jsonify({"erro": "Campo 'nome' é obrigatório (1-100 chars)."}), 400

    role = data.get("role", "user")
    if role not in ("admin", "user", "readonly"):
        return jsonify({"erro": "Role inválido. Use: admin, user, readonly."}), 400

    ip_restrito = data.get("ip_restrito", [])
    if not isinstance(ip_restrito, list):
        return jsonify({"erro": "'ip_restrito' deve ser uma lista."}), 400

    expira_em_dias = data.get("expira_em_dias")
    if expira_em_dias is not None:
        try:
            expira_em_dias = int(expira_em_dias)
            if expira_em_dias < 1 or expira_em_dias > 365:
                return jsonify({"erro": "'expira_em_dias': 1-365."}), 400
        except (ValueError, TypeError):
            return jsonify({"erro": "'expira_em_dias' deve ser inteiro."}), 400

    try:
        api_key, key_id = gerar_api_key(
            nome=nome,
            role=role,
            ip_restrito=ip_restrito,
            expira_em_dias=expira_em_dias,
        )
    except Exception as e:
        return jsonify({"erro": f"Falha ao gerar key: {e}"}), 500

    log_security_event(
        "API_KEY_CREATED",
        severity="INFO",
        created_by=g.auth_user.get("subject"),
        key_id=key_id,
        nome=nome,
        role=role,
        ip=_get_client_ip(),
    )

    return jsonify({
        "api_key": api_key,
        "key_id": key_id,
        "aviso": "GUARDE ESTA CHAVE! Ela não será exibida novamente.",
    }), 201


@admin_bp.route("/keys", methods=["GET"])
@require_auth
@require_role("admin")
def listar():
    """Lista todas as API Keys (sem os hashes)."""
    keys = listar_keys()
    return jsonify({
        "total": len(keys),
        "keys": keys,
    }), 200


@admin_bp.route("/keys/<key_id>", methods=["DELETE"])
@require_auth
@require_role("admin")
def desativar(key_id: str):
    """Desativa uma API Key."""
    if not key_id or len(key_id) > 50:
        return jsonify({"erro": "key_id inválido."}), 400

    sucesso = desativar_api_key(key_id)
    if sucesso:
        log_security_event(
            "API_KEY_DEACTIVATED",
            severity="INFO",
            deactivated_by=g.auth_user.get("subject"),
            key_id=key_id,
            ip=_get_client_ip(),
        )
        return jsonify({"mensagem": f"Key '{key_id}' desativada."}), 200
    else:
        return jsonify({"erro": f"Key '{key_id}' não encontrada."}), 404
