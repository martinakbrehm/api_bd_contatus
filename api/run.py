"""
api/run.py
----------
Entry point para a API Segura.

Uso:
  python -m api.run                    # Inicia a API (desenvolvimento)
  python -m api.run --create-key       # Cria a primeira API Key de admin
  python -m api.run --create-user-key  # Cria uma API Key de usuário

Em produção, use Gunicorn ou Waitress:
  gunicorn "api.app:create_app()" -b 0.0.0.0:5001 -w 4
  waitress-serve --port=5001 --call api.app:create_app
"""

import argparse
import sys
from pathlib import Path

# Garantir que o diretório do projeto está no path
_ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(_ROOT))


def main():
    parser = argparse.ArgumentParser(description="API Segura - Projeto Listas PF")
    parser.add_argument(
        "--create-key", action="store_true",
        help="Cria uma API Key de administrador (primeira key do sistema)"
    )
    parser.add_argument(
        "--create-user-key", action="store_true",
        help="Cria uma API Key de usuário"
    )
    parser.add_argument(
        "--list-keys", action="store_true",
        help="Lista todas as API Keys registradas"
    )
    parser.add_argument(
        "--host", default=None,
        help="Host para bind (padrão: config)"
    )
    parser.add_argument(
        "--port", type=int, default=None,
        help="Porta para bind (padrão: config)"
    )
    args = parser.parse_args()

    # ── Gerenciamento de API Keys via CLI ────────────────────
    if args.create_key:
        from api.auth.api_keys import gerar_api_key
        api_key, key_id = gerar_api_key(
            nome="Admin Principal",
            role="admin",
            expira_em_dias=365,
        )
        print("\n" + "=" * 60)
        print("  API KEY DE ADMINISTRADOR CRIADA")
        print("=" * 60)
        print(f"\n  Key ID:   {key_id}")
        print(f"  API Key:  {api_key}")
        print(f"  Role:     admin")
        print(f"  Expira:   365 dias")
        print("\n  ⚠️  GUARDE ESTA CHAVE! Ela NÃO será exibida novamente.")
        print("=" * 60 + "\n")
        return

    if args.create_user_key:
        from api.auth.api_keys import gerar_api_key
        api_key, key_id = gerar_api_key(
            nome="Usuário API",
            role="user",
            expira_em_dias=90,
        )
        print("\n" + "=" * 60)
        print("  API KEY DE USUÁRIO CRIADA")
        print("=" * 60)
        print(f"\n  Key ID:   {key_id}")
        print(f"  API Key:  {api_key}")
        print(f"  Role:     user")
        print(f"  Expira:   90 dias")
        print("\n  ⚠️  GUARDE ESTA CHAVE! Ela NÃO será exibida novamente.")
        print("=" * 60 + "\n")
        return

    if args.list_keys:
        from api.auth.api_keys import listar_keys
        keys = listar_keys()
        if not keys:
            print("\nNenhuma API Key encontrada.")
            print("Use: python -m api.run --create-key\n")
            return
        print(f"\n{'='*60}")
        print(f"  API Keys registradas: {len(keys)}")
        print(f"{'='*60}")
        for k in keys:
            status = "✅ Ativo" if k.get("ativo") else "❌ Inativo"
            print(f"\n  [{k.get('key_id', '?')}]")
            print(f"    Nome:    {k.get('nome', '?')}")
            print(f"    Role:    {k.get('role', '?')}")
            print(f"    Status:  {status}")
            print(f"    Criada:  {k.get('criado_em', '?')}")
            print(f"    Expira:  {k.get('expira_em', 'nunca')}")
            print(f"    Uso:     {k.get('total_requests', 0)} requests")
        print(f"\n{'='*60}\n")
        return

    # ── Iniciar a API ────────────────────────────────────────
    from api.app import create_app
    from api.config import DEBUG, HOST, PORT

    app = create_app()

    host = args.host or HOST
    port = args.port or PORT

    print("\n" + "=" * 60)
    print("  🔒 API SEGURA - Projeto Listas PF")
    print("=" * 60)
    print(f"  Host:    {host}")
    print(f"  Porta:   {port}")
    print(f"  Debug:   {DEBUG}")
    print(f"  URL:     http://{host}:{port}")
    print(f"\n  Endpoints:")
    print(f"    POST  /api/v1/auth/login")
    print(f"    POST  /api/v1/consulta")
    print(f"    POST  /api/v1/consulta/contagem")
    print(f"    POST  /api/v1/consulta/preview")
    print(f"    GET   /api/v1/health")
    print("=" * 60 + "\n")

    app.run(
        host=host,
        port=port,
        debug=DEBUG,
        threaded=True,
    )


if __name__ == "__main__":
    main()
