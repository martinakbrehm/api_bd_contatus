"""
Cria ou lista usuários na tabela usuarios_app.
Uso: python criar_usuario.py
"""

import os
import sys

# Carrega variáveis do .env antes de importar config_db
from pathlib import Path
env_path = Path(__file__).parent / "api" / ".env"
if env_path.exists():
    for line in env_path.read_text().splitlines():
        line = line.strip()
        if line and not line.startswith("#") and "=" in line:
            k, v = line.split("=", 1)
            os.environ.setdefault(k.strip(), v.strip())

import mysql.connector
from api.utils.crypto import hash_senha

DB = {
    "host":     os.environ["DB_HOST"],
    "port":     int(os.environ.get("DB_PORT", "3306")),
    "user":     os.environ["DB_USER"],
    "password": os.environ["DB_PASSWORD"],
    "database": os.environ.get("DB_NAME", "bd_contatus"),
    "charset":  "utf8mb4",
}

def listar_usuarios(cur):
    cur.execute("SELECT id, nome, email, role, ativo, ultimo_acesso FROM usuarios_app ORDER BY id")
    rows = cur.fetchall()
    if not rows:
        print("  Nenhum usuário cadastrado.")
    for r in rows:
        status = "ativo" if r["ativo"] else "INATIVO"
        print(f"  [{r['id']}] {r['nome']} <{r['email']}> | role={r['role']} | {status} | último acesso: {r['ultimo_acesso']}")

def criar(cur, nome, email, senha, role="admin"):
    cur.execute("SELECT id FROM usuarios_app WHERE email = %s", (email,))
    if cur.fetchone():
        print(f"  Usuário {email} já existe.")
        return
    h = hash_senha(senha)
    cur.execute(
        "INSERT INTO usuarios_app (nome, email, senha_hash, role) VALUES (%s, %s, %s, %s)",
        (nome, email, h, role)
    )
    print(f"  Usuário criado: {email} | role={role}")

conn = mysql.connector.connect(**DB)
cur = conn.cursor(dictionary=True)

print("\n=== Usuários existentes ===")
listar_usuarios(cur)

print("\n=== Criando usuário admin ===")
criar(cur, "Martina", "martina@contatus.com", "Contatus@2025", role="admin")
conn.commit()

print("\n=== Lista atualizada ===")
listar_usuarios(cur)

cur.close()
conn.close()
print()
