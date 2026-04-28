"""
config_db.example.py
--------------------
Arquivo de exemplo para configuração das credenciais do banco de dados MySQL.

INSTRUÇÕES:
1. Copie este arquivo para config_db.py
2. Substitua as credenciais abaixo pelas reais
3. Mantenha config_db.py fora do versionamento Git (.gitignore já o exclui)

IMPORTANTE:
- Este arquivo é seguro versionar (contém apenas dados fictícios)
- O config_db.py real contém dados sensíveis e NÃO deve ser versionado
"""

# ── Configurações de conexão MySQL ─────────────────────────────

DB_HOST = "seu-host-mysql.rds.amazonaws.com"  # Host AWS RDS ou servidor MySQL
DB_USER = "seu_usuario"                       # Usuário do banco
DB_PASSWORD = "sua_senha_segura_aqui"         # Senha do usuário (ALTERE!)
DB_NAME = "nome_do_banco"                     # Nome do banco de dados
DB_PORT = 3306                                # Porta MySQL (padrão: 3306)

# ── Configurações opcionais ────────────────────────────────────

DB_CHARSET = "utf8mb4"         # Charset para suporte a emojis e caracteres especiais
DB_AUTOCOMMIT = True           # Auto-commit para transações

# ── Validação básica (não substitui segurança real) ────────────

# Desabilitar validação durante testes ou desenvolvimento
import sys
is_test = any("pytest" in arg or "test" in arg for arg in sys.argv)
if DB_PASSWORD == "sua_senha_segura_aqui" and not is_test:
    raise ValueError("ERRO: Altere a senha padrão em config_db.py antes de executar a aplicação!")

# ── DB_CONFIG para compatibilidade com app.py ──────────────────

DB_CONFIG = {
    "host": DB_HOST,
    "port": DB_PORT,
    "user": DB_USER,
    "password": DB_PASSWORD,
    "database": DB_NAME,
    "charset": DB_CHARSET,
    "autocommit": DB_AUTOCOMMIT,
}

# ── Exemplo de uso em app.py ────────────────────────────────────
#
# import mysql.connector
# from config_db import DB_CONFIG
#
# conn = mysql.connector.connect(**DB_CONFIG)
# # ... usar conexão ...</content>
<parameter name="filePath">c:\Users\marti\Desktop\Projeto Listas\config_db.example.py