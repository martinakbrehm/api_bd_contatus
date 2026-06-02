# ============================================================
# CONFIGURAÇÃO DE CONEXÃO COM O BANCO DE DADOS
# ============================================================
# Credenciais movidas para config_db.py (arquivo seguro, não versionado)

from api.config_db import DB_CONFIG

# Nome da tabela principal (conforme a query base)
TABELA_PRINCIPAL = "latest_contacts"

# ----------------------------------------------------------------
# MAPEAMENTO DE COLUNAS NA TABELA
# Ajuste os nomes se seu banco tiver colunas com grafias diferentes
# ----------------------------------------------------------------
COLUNAS = {
    "cpf":              "CPF",
    "nome":             "NOME",
    "data_nascimento":  "DATA_NASCIMENTO",
    "genero":           "GENERO",
    "uf":               "UF",
    "cidade":           "cidade",  # está em minúsculo no banco
    "bairro":           "BAIRRO",
    "cep":              "CEP",
    "endereco":         "ENDERECO",
    "num_end":          "NUM_END",
    "complemento":      "COMPLEMENTO",
    "email_1":          "email_1",
    "email_2":          "email_2",
    "telefone_1":       "telefone_1",
    "telefone_2":       "telefone_2",
    "telefone_3":       "telefone_3",
    "telefone_4":       "telefone_4",
    "telefone_5":       "telefone_5",
    "telefone_6":       "telefone_6",
    # Campos opcionais — verificar existência no banco:
    "cbo":              "cbo",     # código CBO (profissão)
    # RENDA: não disponível no banco — campo removido
    # SCORE: não disponível no banco — campo removido
}

# ----------------------------------------------------------------
# Colunas opcionais — defina False se a coluna não existir no banco
# ----------------------------------------------------------------
COLUNAS_OPCIONAIS = {
    "cbo":    False,   # CBO não existe no banco atual
}

# ----------------------------------------------------------------
# Identificação de tipo de telefone pelo número de dígitos
# Celular BR: DDD (2) + 9 + número (8) = 11 dígitos
# Fixo BR:    DDD (2) + número (8)     = 10 dígitos
# ----------------------------------------------------------------
COMPRIMENTO_CELULAR = 11
COMPRIMENTO_FIXO    = 10

# ----------------------------------------------------------------
# ESTRUTURA DE PASTAS DO PROJETO
#
#   Projeto Listas/
#   ├── app.py
#   ├── config.py
#   ├── list_logger.py      ← logging + auditoria
#   ├── query_builder.py
#   ├── data_processor.py
#   ├── data_cleaner.py
#   ├── bairros_api.py
#   ├── requirements.txt
#   ├── output/             ← Excels gerados para download (limpo periodicamente)
#   ├── logs/
#   │   ├── app/            ← flask.log (rotativo por dia, 30 dias)
#   │   └── geracoes/       ← geracoes.csv (auditoria acumulada)
#   ├── pedidos/            ← PDFs dos pedidos dos clientes
#   └── templates/
#       └── index.html
# ----------------------------------------------------------------

from pathlib import Path

_BASE_DIR   = Path(__file__).parent
DIR_OUTPUT  = _BASE_DIR / "output"
DIR_LOGS    = _BASE_DIR / "logs"

# Garante que existem (idempotente)
DIR_OUTPUT.mkdir(exist_ok=True)
(DIR_LOGS / "app").mkdir(parents=True, exist_ok=True)
(DIR_LOGS / "geracoes").mkdir(parents=True, exist_ok=True)

# Nível de log: "DEBUG" em desenvolvimento, "INFO" em produção
LOG_LEVEL = "INFO"

# Dias que os CSVs de output ficam armazenados (limpeza manual via script)
OUTPUT_RETENCAO_DIAS = 7
