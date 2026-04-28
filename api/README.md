# 🔒 API Segura — Projeto Listas PF

API REST extremamente segura para consultas ao banco de dados de listas PF.

---

## 📁 Estrutura

```
api/
├── app.py                      # Flask App Factory
├── config.py                   # Configurações centralizadas
├── run.py                      # Entry point (CLI + servidor)
├── requirements.txt            # Dependências Python
├── api_keys.json               # API Keys (⚠️ NÃO versionado)
│
├── auth/                       # Autenticação & Autorização
│   ├── jwt_handler.py          # Criação/validação de tokens JWT
│   ├── api_keys.py             # Gerenciamento de API Keys
│   └── decorators.py           # Decoradores @require_auth, @require_role
│
├── middleware/                  # Camadas de segurança
│   ├── rate_limiter.py         # Rate limiting (janela deslizante)
│   ├── security_headers.py     # Headers HTTP de segurança + CORS
│   ├── request_validator.py    # Validação de payload + anti-injection
│   └── ip_filter.py            # Whitelist / blacklist de IPs
│
├── routes/                     # Endpoints da API
│   ├── auth_routes.py          # Login, refresh, logout
│   ├── consulta.py             # Consulta, contagem, preview
│   ├── health.py               # Health check, status do banco
│   └── admin.py                # Gestão de API Keys
│
├── models/                     # Validação de dados
│   └── schemas.py              # Validação de inputs (UFs, cidades, etc.)
│
├── utils/                      # Utilitários
│   ├── audit_logger.py         # Logging de auditoria (JSON)
│   ├── sanitizer.py            # Mascaramento de dados (CPF, email)
│   └── crypto.py               # HMAC, hash, tokens seguros
│
└── logs/                       # Logs (gerados automaticamente)
    ├── audit.log               # Todas as requisições
    └── security.log            # Eventos de segurança
```

---

## 🚀 Início Rápido

### 1. Instalar dependências

```bash
pip install -r api/requirements.txt
```

### 2. Criar primeira API Key (admin)

```bash
python -m api.run --create-key
```

> ⚠️ **Copie e guarde a chave exibida!** Ela não será mostrada novamente.

### 3. Iniciar a API

```bash
python -m api.run
```

A API inicia em `http://localhost:5001`.

### Ou no Windows, execute:

```
run_api.bat
```

---

## 🔑 Autenticação

A API suporta dois métodos de autenticação:

### Método 1: API Key direta (header)

```bash
curl -H "X-API-Key: lspf_sua_chave_aqui" \
     http://localhost:5001/api/v1/consulta/contagem \
     -X POST -H "Content-Type: application/json" \
     -d '{"ufs": ["SP"]}'
```

### Método 2: JWT Bearer Token

**Passo 1 — Login (obter token):**

```bash
curl -X POST http://localhost:5001/api/v1/auth/login \
     -H "Content-Type: application/json" \
     -d '{"api_key": "lspf_sua_chave_aqui"}'
```

Resposta:
```json
{
  "access_token": "eyJ...",
  "refresh_token": "eyJ...",
  "token_type": "Bearer",
  "expires_in": 1800,
  "role": "user"
}
```

**Passo 2 — Usar o token:**

```bash
curl -H "Authorization: Bearer eyJ..." \
     http://localhost:5001/api/v1/consulta \
     -X POST -H "Content-Type: application/json" \
     -d '{"ufs": ["SP"], "cidades": ["SAO PAULO"], "quantidade": 100}'
```

**Passo 3 — Renovar token (quando expirar):**

```bash
curl -X POST http://localhost:5001/api/v1/auth/refresh \
     -H "Content-Type: application/json" \
     -d '{"refresh_token": "eyJ..."}'
```

---

## 📡 Endpoints

| Método | Endpoint                       | Auth | Role                 | Descrição                          |
|--------|--------------------------------|------|----------------------|------------------------------------|
| GET    | `/api/v1/health`               | ❌   | —                    | Health check                       |
| POST   | `/api/v1/auth/login`           | ❌   | —                    | Login com API Key → tokens JWT     |
| POST   | `/api/v1/auth/refresh`         | ❌   | —                    | Renovar access token               |
| POST   | `/api/v1/auth/logout`          | ✅   | qualquer             | Revogar token (logout)             |
| GET    | `/api/v1/auth/me`              | ✅   | qualquer             | Info do usuário autenticado        |
| POST   | `/api/v1/consulta`             | ✅   | admin, user          | Consulta completa com dados        |
| POST   | `/api/v1/consulta/contagem`    | ✅   | admin, user, readonly| Contagem (sem dados pessoais)      |
| POST   | `/api/v1/consulta/preview`     | ✅   | admin, user, readonly| Preview com dados mascarados       |
| GET    | `/api/v1/health/db`            | ✅   | admin                | Teste de conexão com banco         |
| GET    | `/api/v1/health/stats`         | ✅   | admin                | Estatísticas da API                |
| POST   | `/api/v1/admin/keys`           | ✅   | admin                | Criar nova API Key                 |
| GET    | `/api/v1/admin/keys`           | ✅   | admin                | Listar API Keys                    |
| DELETE | `/api/v1/admin/keys/<key_id>`  | ✅   | admin                | Desativar API Key                  |

---

## 📋 Exemplo de Consulta

```json
POST /api/v1/consulta
Content-Type: application/json
Authorization: Bearer eyJ...

{
  "ufs": ["SP", "RJ"],
  "cidades": ["SAO PAULO", "RIO DE JANEIRO"],
  "bairros": [],
  "genero": "ambos",
  "idade_min": 25,
  "idade_max": 60,
  "email": "nao_filtrar",
  "tipo_telefone": "movel",
  "cbos": [],
  "quantidade": 1000
}
```

**Resposta:**
```json
{
  "ok": true,
  "total_banco": 150000,
  "total_final": 1000,
  "registros": [
    {
      "NOME": "JOAO DA SILVA",
      "CPF": "12345678901",
      "DDD_1": "11",
      "TELEFONE_1": "987654321",
      ...
    }
  ],
  "colunas": ["NOME", "CPF", "DDD_1", "TELEFONE_1", ...],
  "filtros_aplicados": "UF: SP, RJ | Cidade(s): SAO PAULO, RIO DE JANEIRO | Idade: 25–60",
  "tempo_processamento_s": 2.3,
  "request_id": "req_abc123..."
}
```

---

## 🛡️ Camadas de Segurança

### 1. Autenticação
- **JWT com expiração curta** (30 min access, 24h refresh)
- **API Keys** com hash SHA-256 (chave original nunca armazenada)
- **Refresh token rotation** (single-use)
- **Token blacklist** (revogação imediata)
- **JTI tracking** (previne replay attacks)

### 2. Autorização (RBAC)
- **admin**: acesso total + gestão de keys
- **user**: consultas completas
- **readonly**: apenas contagem e preview (dados mascarados)

### 3. Rate Limiting
- **Janela deslizante** (sliding window) por minuto/hora/dia
- **Limites por role**:
  - admin: 120/min, 3000/hora, 50000/dia
  - user: 30/min, 500/hora, 5000/dia
  - readonly: 10/min, 100/hora, 1000/dia
- **Headers HTTP**: `X-RateLimit-Limit`, `X-RateLimit-Remaining`, `Retry-After`

### 4. Proteção contra Brute Force
- **5 tentativas falhas** → bloqueio de 15 minutos
- Tracking por IP

### 5. Validação de Input
- Schemas rigorosos (UFs válidas, ranges de idade, etc.)
- Detecção de **SQL Injection**, **XSS**, **Command Injection**
- **Path Traversal** detection
- Sanitização de todos os inputs
- `MAX_CONTENT_LENGTH` = 1 MB

### 6. Headers de Segurança HTTP
- `X-Content-Type-Options: nosniff`
- `X-XSS-Protection: 1; mode=block`
- `X-Frame-Options: DENY`
- `Content-Security-Policy` restritivo
- `Referrer-Policy: strict-origin-when-cross-origin`
- `Strict-Transport-Security` (HSTS, quando HTTPS)
- Cache desabilitado (`no-store`)

### 7. Filtragem de IPs
- **Blacklist** sempre ativa
- **Whitelist** opcional (modo restritivo)
- Suporte a CIDR (`192.168.1.0/24`)

### 8. CORS
- Origins explicitamente permitidas
- Preflight (OPTIONS) handling
- `Access-Control-Allow-Credentials`

### 9. Auditoria Completa
- **Audit log**: toda requisição (JSON estruturado)
- **Security log**: eventos de segurança
- **Data Access log**: compliance LGPD
- Logs rotativos (10 MB, 10 backups)

### 10. Mascaramento de Dados
- CPF: `***.456.***-01`
- Email: `j***@gm***.com`
- Telefone: `(11) *****-4321`
- Nos previews e logs

---

## ⚙️ Variáveis de Ambiente

| Variável              | Padrão               | Descrição                          |
|-----------------------|----------------------|------------------------------------|
| `API_JWT_SECRET`      | aleatório (dev only) | Chave secreta JWT (OBRIGATÓRIO em prod) |
| `API_CORS_ORIGINS`    | `http://localhost:5000` | Origins CORS permitidas (vírgula) |
| `API_ENFORCE_HTTPS`   | `false`              | Forçar HSTS                        |
| `API_DEBUG`           | `false`              | Modo debug                         |
| `API_HOST`            | `0.0.0.0`            | Host de bind                       |
| `API_PORT`            | `5001`               | Porta de bind                      |

---

## 🔧 CLI

```bash
# Criar key de admin
python -m api.run --create-key

# Criar key de usuário
python -m api.run --create-user-key

# Listar keys
python -m api.run --list-keys

# Iniciar API
python -m api.run

# Iniciar em porta customizada
python -m api.run --port 8080

# Produção (Linux)
gunicorn "api.app:create_app()" -b 0.0.0.0:5001 -w 4

# Produção (Windows)
waitress-serve --port=5001 --call api.app:create_app
```

---

## 🚨 Segurança em Produção

1. **SEMPRE** defina `API_JWT_SECRET` como variável de ambiente
2. **NUNCA** commite `api_keys.json` no Git (adicione ao `.gitignore`)
3. Use **HTTPS** em produção (`API_ENFORCE_HTTPS=true`)
4. Ative **IP whitelist** se possível
5. Use **Gunicorn/Waitress** (nunca `app.run()` em produção)
6. Configure **firewall** na porta da API
7. Monitore os **security logs** regularmente
8. Rotacione **API Keys** periodicamente (expira_em_dias)
