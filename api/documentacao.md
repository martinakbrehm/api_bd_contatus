# Documentação — API Segura Lista PF

**Versão:** 1.0.0  
**Base URL:** `http://localhost:5001`  
**Content-Type:** `application/json`

---

## Índice

1. [Visão Geral](#1-visão-geral)
2. [Arquitetura de Segurança](#2-arquitetura-de-segurança)
3. [Autenticação](#3-autenticação)
   - 3.1 [API Keys](#31-api-keys)
   - 3.2 [JWT (JSON Web Tokens)](#32-jwt-json-web-tokens)
   - 3.3 [Fluxo de Autenticação](#33-fluxo-de-autenticação)
4. [Controle de Acesso (RBAC)](#4-controle-de-acesso-rbac)
5. [Rate Limiting](#5-rate-limiting)
6. [Endpoints](#6-endpoints)
   - 6.1 [Autenticação](#61-autenticação)
   - 6.2 [Consulta](#62-consulta)
   - 6.3 [Administração](#63-administração)
   - 6.4 [Health Check](#64-health-check)
7. [Schemas de Validação](#7-schemas-de-validação)
8. [Filtros de Consulta](#8-filtros-de-consulta)
9. [Códigos de Erro](#9-códigos-de-erro)
10. [Middlewares de Segurança](#10-middlewares-de-segurança)
11. [Auditoria e Logs](#11-auditoria-e-logs)
12. [Mascaramento de Dados (LGPD)](#12-mascaramento-de-dados-lgpd)
13. [Configuração](#13-configuração)
14. [Execução](#14-execução)
15. [Testes](#15-testes)
16. [Exemplos de Uso](#16-exemplos-de-uso)

---

## 1. Visão Geral

A **API Segura Lista PF** é uma interface REST para consulta segura ao banco de dados de contatos do projeto Listas PF. Ela foi desenvolvida com múltiplas camadas de segurança para proteger dados pessoais sensíveis em conformidade com a LGPD.

### Características Principais

| Recurso | Descrição |
|---------|-----------|
| Autenticação dupla | API Keys + JWT (Bearer Tokens) |
| RBAC | 3 roles: `admin`, `user`, `readonly` |
| Rate Limiting | Janela deslizante por IP/role (minuto/hora/dia) |
| Proteção contra ataques | SQL Injection, XSS, Command Injection, Path Traversal |
| Proteção brute force | Bloqueio após 5 tentativas falhas (15 min) |
| Auditoria completa | Todos os requests e acessos a dados são logados |
| Mascaramento LGPD | CPF, email, nome e telefone mascarados em previews |
| Security Headers | X-XSS-Protection, CSP, HSTS, anti-clickjacking |
| Filtragem de IP | Whitelist/blacklist com suporte a CIDR |
| CORS configurável | Origins, métodos e headers controlados |

---

## 2. Arquitetura de Segurança

Cada requisição passa por múltiplas camadas de segurança na seguinte ordem:

```
Request → IP Filter → Request Validator → Rate Limiter → Security Headers → CORS → Auth Decorator → Route Handler
```

### Camadas detalhadas:

1. **IP Filter** — Bloqueia IPs na blacklist; se whitelist ativada, só permite IPs autorizados (suporte CIDR)
2. **Request Validator** — Analisa headers, query strings e body JSON para detectar:
   - SQL Injection (`UNION SELECT`, `DROP TABLE`, `OR 1=1`, etc.)
   - XSS (`<script>`, `onerror=`, `javascript:`, etc.)
   - Command Injection (`; rm -rf`, `| cat /etc/passwd`, etc.)
   - Path Traversal (`../`, `..\\`, `etc/passwd`, etc.)
   - Valida `Content-Type: application/json` em requisições POST
   - Gera `X-Request-ID` único para rastreabilidade
3. **Rate Limiter** — Sliding window counter thread-safe, limites por role
4. **Security Headers** — Adiciona headers de segurança a toda resposta
5. **CORS** — Controle de origens permitidas para requests cross-origin
6. **Auth Decorators** — Validam JWT ou API Key; verificam role do usuário
7. **Route Handler** — Lógica de negócio com validação de schema

---

## 3. Autenticação

A API suporta dois métodos de autenticação, que podem ser usados de forma independente ou combinada.

### 3.1 API Keys

Chaves de API com prefixo `lspf_`, armazenadas com hash SHA-256.

**Características:**
- Prefixo identificador: `lspf_`
- Hash SHA-256 (chave original nunca é armazenada)
- Suporte a expiração (1-365 dias)
- Restrição por IP/CIDR
- Tracking de uso (último uso, total de usos)

**Uso direto via header:**
```
X-API-Key: lspf_abc123...
```

### 3.2 JWT (JSON Web Tokens)

Tokens de curta duração emitidos após login com API Key.

| Tipo | Duração | Uso |
|------|---------|-----|
| Access Token | 30 minutos | Autenticação em endpoints protegidos |
| Refresh Token | 24 horas | Renovação do access token (uso único) |

**Características:**
- Algoritmo: HS256
- JTI (JWT ID) único para anti-replay
- Binding por IP (opcional)
- Blacklist em memória para tokens revogados
- Refresh tokens são single-use (revogados após uso)

**Uso via header:**
```
Authorization: Bearer eyJhbGciOiJIUzI1NiIs...
```

### 3.3 Fluxo de Autenticação

```
┌──────────────┐     POST /auth/login        ┌───────────┐
│   Cliente     │ ──────────────────────────→  │    API    │
│               │     { "api_key": "lspf_" }  │           │
│               │ ←──────────────────────────  │           │
│               │   { access_token, refresh }  │           │
│               │                              │           │
│               │     GET /api/v1/auth/me      │           │
│               │ ──────────────────────────→  │           │
│               │   Authorization: Bearer ...  │           │
│               │ ←──────────────────────────  │           │
│               │   { subject, role }          │           │
│               │                              │           │
│  (30 min)     │     POST /auth/refresh       │           │
│               │ ──────────────────────────→  │           │
│               │   { refresh_token }          │           │
│               │ ←──────────────────────────  │           │
│               │   { new_access, new_refresh }│           │
│               │                              │           │
│               │     POST /auth/logout        │           │
│               │ ──────────────────────────→  │           │
│               │   Authorization: Bearer ...  │           │
│               │ ←──────────────────────────  │           │
│               │   { "mensagem": "Logout..." }│           │
└──────────────┘                              └───────────┘
```

---

## 4. Controle de Acesso (RBAC)

### Permissões por Role

| Endpoint | `admin` | `user` | `readonly` |
|----------|:-------:|:------:|:----------:|
| `POST /api/v1/consulta` | ✅ | ✅ | ❌ |
| `POST /api/v1/consulta/contagem` | ✅ | ✅ | ✅ |
| `POST /api/v1/consulta/preview` | ✅ | ✅ | ✅ |
| `POST /api/v1/auth/login` | ✅ | ✅ | ✅ |
| `POST /api/v1/auth/refresh` | ✅ | ✅ | ✅ |
| `POST /api/v1/auth/logout` | ✅ | ✅ | ✅ |
| `GET /api/v1/auth/me` | ✅ | ✅ | ✅ |
| `POST /api/v1/admin/keys` | ✅ | ❌ | ❌ |
| `GET /api/v1/admin/keys` | ✅ | ❌ | ❌ |
| `DELETE /api/v1/admin/keys/<id>` | ✅ | ❌ | ❌ |
| `GET /api/v1/health` | 🔓 Público | 🔓 Público | 🔓 Público |
| `GET /api/v1/health/db` | ✅ | ❌ | ❌ |
| `GET /api/v1/health/stats` | ✅ | ❌ | ❌ |

### Limites por Role

| Role | Registros/consulta | Admins podem criar keys? |
|------|-------------------|--------------------------|
| `admin` | Até 20.000 | Sim |
| `user` | Até 10.000 | Não |
| `readonly` | Apenas contagem/preview | Não |

---

## 5. Rate Limiting

Sistema de janela deslizante (sliding window) thread-safe por IP e/ou API Key.

### Limites por Role

| Role | Por Minuto | Por Hora | Por Dia |
|------|-----------|----------|---------|
| `admin` | 120 | 3.000 | 50.000 |
| `user` | 30 | 500 | 5.000 |
| `readonly` | 10 | 100 | 1.000 |
| Sem auth | 30 | 500 | 5.000 |

### Headers de Resposta

Toda resposta inclui headers informativos sobre o rate limit:

```
X-RateLimit-Limit: 30
X-RateLimit-Remaining: 27
X-RateLimit-Reset: 1700000060
```

Quando o limite é excedido:
- Status: `429 Too Many Requests`
- Header: `Retry-After: <segundos>` 

---

## 6. Endpoints

### 6.1 Autenticação

#### `POST /api/v1/auth/login`

Autentica via API Key e retorna tokens JWT.

**Request:**
```json
{
  "api_key": "lspf_abc123..."
}
```

**Response (200):**
```json
{
  "access_token": "eyJhbGciOiJIUzI1NiIs...",
  "refresh_token": "eyJhbGciOiJIUzI1NiIs...",
  "token_type": "Bearer",
  "expires_in": 1800,
  "role": "user"
}
```

**Erros:**
| Status | Descrição |
|--------|-----------|
| 400 | Body inválido (api_key ausente, curta ou longa) |
| 401 | API Key inválida ou desativada |
| 429 | Rate limit excedido |

---

#### `POST /api/v1/auth/refresh`

Renova o access token usando um refresh token (uso único).

**Request:**
```json
{
  "refresh_token": "eyJhbGciOiJIUzI1NiIs..."
}
```

**Response (200):**
```json
{
  "access_token": "eyJhbGciOiJIUzI1NiIs...",
  "refresh_token": "eyJhbGciOiJIUzI1NiIs...",
  "token_type": "Bearer",
  "expires_in": 1800
}
```

> ⚠️ O refresh token é de uso único. Após o uso, um novo refresh token é emitido e o antigo é revogado.

---

#### `POST /api/v1/auth/logout`

Revoga o token atual. Requer `Authorization: Bearer <token>`.

**Response (200):**
```json
{
  "mensagem": "Logout realizado com sucesso."
}
```

---

#### `GET /api/v1/auth/me`

Retorna informações do usuário autenticado.

**Headers:** `Authorization: Bearer <token>` ou `X-API-Key: lspf_...`

**Response (200):**
```json
{
  "subject": "lspf_abc123",
  "role": "admin",
  "auth_method": "jwt"
}
```

---

### 6.2 Consulta

#### `POST /api/v1/consulta`

Consulta completa com filtros. Retorna dados processados e limpos.

**Roles:** `admin`, `user`

**Headers:** `Authorization: Bearer <token>` ou `X-API-Key: lspf_...`

**Request:**
```json
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

**Response (200):**
```json
{
  "ok": true,
  "total_banco": 50000,
  "total_final": 1000,
  "registros": [
    {
      "NOME": "JOAO DA SILVA",
      "CPF": "12345678901",
      "TELEFONE_1": "11999998888",
      "..."
    }
  ],
  "colunas": ["NOME", "CPF", "TELEFONE_1", "..."],
  "filtros_aplicados": "UF: SP, RJ | Cidade(s): SAO PAULO, RIO DE JANEIRO | Idade: 25–60",
  "tempo_processamento_s": 2.3,
  "request_id": "req_abc123..."
}
```

---

#### `POST /api/v1/consulta/contagem`

Apenas contagem de registros (sem dados pessoais). Acessível por todos os roles.

**Roles:** `admin`, `user`, `readonly`

**Request:** Mesmo schema de `/consulta`.

**Response (200):**
```json
{
  "ok": true,
  "total_banco": 50000,
  "descricao": "UF: SP | Cidade(s): SAO PAULO | Idade: 25–60",
  "tempo_processamento_s": 0.5,
  "request_id": "req_abc123..."
}
```

---

#### `POST /api/v1/consulta/preview`

Amostra de até 50 registros com dados sensíveis mascarados. Útil para validar filtros antes de uma consulta completa.

**Roles:** `admin`, `user`, `readonly`

**Request:** Mesmo schema de `/consulta`.

**Response (200):**
```json
{
  "ok": true,
  "total_banco": 50000,
  "total_final": 3200,
  "registros_preview": [
    {
      "NOME": "J*** D* S***",
      "CPF": "***.***.***-01",
      "EMAIL_1": "j***@gm***",
      "TELEFONE_1": "(11) *****-8888"
    }
  ],
  "colunas": ["NOME", "CPF", "EMAIL_1", "TELEFONE_1"],
  "nota": "Dados sensíveis mascarados neste preview.",
  "tempo_processamento_s": 1.1,
  "request_id": "req_abc123..."
}
```

---

### 6.3 Administração

Endpoints exclusivos para o role `admin`.

#### `POST /api/v1/admin/keys`

Cria uma nova API Key.

**Request:**
```json
{
  "nome": "App Frontend",
  "role": "user",
  "ip_restrito": ["192.168.1.0/24"],
  "expira_em_dias": 90
}
```

| Campo | Tipo | Obrigatório | Descrição |
|-------|------|-------------|-----------|
| `nome` | string | ✅ | Nome/descrição da key (1-100 chars) |
| `role` | string | Não (padrão: `user`) | `admin`, `user` ou `readonly` |
| `ip_restrito` | string[] | Não | Lista de IPs ou CIDRs permitidos |
| `expira_em_dias` | int | Não | Dias até expiração (1-365) |

**Response (201):**
```json
{
  "api_key": "lspf_abc123def456...",
  "key_id": "lspf_abc123d",
  "aviso": "GUARDE ESTA CHAVE! Ela não será exibida novamente."
}
```

> ⚠️ A chave completa é exibida **apenas uma vez** na criação. Guarde-a em local seguro.

---

#### `GET /api/v1/admin/keys`

Lista todas as API Keys cadastradas (sem exibir hashes).

**Response (200):**
```json
{
  "total": 3,
  "keys": [
    {
      "key_id": "lspf_abc123d",
      "nome": "App Frontend",
      "role": "user",
      "ativo": true,
      "criado_em": "2025-01-01T12:00:00",
      "ultimo_uso": "2025-01-15T10:30:00",
      "total_usos": 42
    }
  ]
}
```

---

#### `DELETE /api/v1/admin/keys/<key_id>`

Desativa uma API Key (soft delete).

**Response (200):**
```json
{
  "mensagem": "Key 'lspf_abc123d' desativada."
}
```

**Response (404):**
```json
{
  "erro": "Key 'lspf_xyz' não encontrada."
}
```

---

### 6.4 Health Check

#### `GET /api/v1/health`

Health check básico — **sem autenticação**. Usado por load balancers e monitoramento.

**Response (200):**
```json
{
  "status": "healthy",
  "version": "1.0.0",
  "timestamp": "2025-01-01T12:00:00+00:00",
  "uptime_seconds": 3600
}
```

---

#### `GET /api/v1/health/db`

Teste de conexão com o banco de dados. **Somente admin.**

**Response (200):**
```json
{
  "status": "connected",
  "latency_ms": 45.2,
  "host": "integracoes-assisty.ccr0ws...",
  "database": "bd_contatus"
}
```

---

#### `GET /api/v1/health/stats`

Estatísticas gerais da API. **Somente admin.**

**Response (200):**
```json
{
  "version": "1.0.0",
  "uptime_seconds": 7200,
  "logs_size_mb": 1.35,
  "pid": 12345,
  "timestamp": "2025-01-01T12:00:00+00:00"
}
```

---

#### `GET /`

Rota raiz — lista de endpoints disponíveis.

**Response (200):**
```json
{
  "api": "Lista PF - API Segura",
  "versao": "1.0.0",
  "documentacao": "/api/v1/health",
  "endpoints": {
    "auth": "/api/v1/auth/login",
    "consulta": "/api/v1/consulta",
    "contagem": "/api/v1/consulta/contagem",
    "preview": "/api/v1/consulta/preview",
    "health": "/api/v1/health"
  }
}
```

---

## 7. Schemas de Validação

### Schema de Consulta

Usado nos endpoints `/consulta`, `/contagem` e `/preview`.

| Campo | Tipo | Obrigatório | Padrão | Descrição |
|-------|------|:-----------:|--------|-----------|
| `ufs` | string[] | ✅ | — | Lista de UFs (siglas de 2 letras) |
| `cidades` | string[] | Não | `[]` | Nomes de cidades (máx. 50, 2-100 chars) |
| `bairros` | string[] | Não | `[]` | Nomes de bairros (máx. 100) |
| `genero` | string | Não | `"ambos"` | `M`, `F`, `MASCULINO`, `FEMININO`, `AMBOS` |
| `idade_min` | int | Não | `null` | Idade mínima (18-120) |
| `idade_max` | int | Não | `null` | Idade máxima (18-120) |
| `email` | string | Não | `"nao_filtrar"` | `obrigatorio`, `nao_filtrar`, `nao`, `preferencial` |
| `tipo_telefone` | string | Não | `"movel"` | `movel`, `fixo`, `ambos` |
| `cbos` | string[] | Não | `[]` | Códigos CBO (máx. 50) |
| `quantidade` | int | Não | `1000` | Quantidade de registros (1-10.000) |

### UFs Válidas

```
AC, AL, AM, AP, BA, CE, DF, ES, GO, MA, MG, MS, MT, PA, PB, PE,
PI, PR, RJ, RN, RO, RR, RS, SC, SE, SP, TO
```

### Aceite de strings como listas

Os campos `ufs`, `cidades`, `bairros` e `cbos` aceitam tanto array quanto string separada por `,`, `;` ou espaços:

```json
{ "ufs": "SP, RJ, MG" }
```
é equivalente a:
```json
{ "ufs": ["SP", "RJ", "MG"] }
```

### Schema de Login

| Campo | Tipo | Obrigatório | Descrição |
|-------|------|:-----------:|-----------|
| `api_key` | string | ✅ | API Key com prefixo `lspf_` (10-200 chars) |

---

## 8. Filtros de Consulta

### Opções de Email

| Valor | Descrição |
|-------|-----------|
| `nao_filtrar` | Retorna registros com ou sem email |
| `obrigatorio` | Apenas registros que possuem email |
| `nao` | Apenas registros sem email |
| `preferencial` | Prioriza registros com email, mas inclui sem |

### Tipos de Telefone

| Valor | Descrição |
|-------|-----------|
| `movel` | Apenas telefones celulares |
| `fixo` | Apenas telefones fixos |
| `ambos` | Celulares e fixos |

### Limites de Registros

| Role | Máximo por consulta |
|------|-------|
| `admin` | 20.000 |
| `user` | 10.000 |
| `readonly` | Preview: 50 (mascarados) |

Se `quantidade` não for informada, o padrão é 1.000 registros.

---

## 9. Códigos de Erro

### Códigos HTTP

| Código | Significado | Quando |
|--------|------------|--------|
| 200 | Sucesso | Requisição processada com sucesso |
| 201 | Criado | API Key criada com sucesso |
| 400 | Bad Request | Body inválido, filtros incorretos |
| 401 | Unauthorized | Token expirado, API Key inválida, sem credenciais |
| 403 | Forbidden | Role insuficiente para o endpoint |
| 404 | Not Found | Endpoint ou recurso não encontrado |
| 405 | Method Not Allowed | Método HTTP não suportado no endpoint |
| 413 | Payload Too Large | Body excede 1 MB |
| 415 | Unsupported Media Type | POST sem `Content-Type: application/json` |
| 429 | Too Many Requests | Rate limit excedido |
| 500 | Internal Error | Erro interno do servidor |
| 503 | Service Unavailable | Banco de dados indisponível |

### Formato de Erro Padrão

```json
{
  "erro": "Mensagem descritiva do erro.",
  "codigo": 400,
  "request_id": "req_abc123..."
}
```

### Erros de Validação

```json
{
  "ok": false,
  "erro": "Dados inválidos.",
  "detalhes": [
    "UF inválida: 'XX'",
    "'idade_min' não pode ser menor que 18.",
    "Máximo de 50 cidades por consulta."
  ],
  "request_id": "req_abc123..."
}
```

---

## 10. Middlewares de Segurança

### Security Headers

Todas as respostas incluem os seguintes headers de segurança:

| Header | Valor | Proteção |
|--------|-------|----------|
| `X-Content-Type-Options` | `nosniff` | MIME sniffing |
| `X-XSS-Protection` | `1; mode=block` | XSS refletido |
| `X-Frame-Options` | `DENY` | Clickjacking |
| `Referrer-Policy` | `strict-origin-when-cross-origin` | Vazamento de referrer |
| `Content-Security-Policy` | `default-src 'self'` | Injeção de conteúdo |
| `Cache-Control` | `no-store, no-cache, must-revalidate` | Cache de dados sensíveis |
| `Pragma` | `no-cache` | Cache (HTTP/1.0) |
| `X-Request-ID` | `req_abc123...` | Rastreabilidade |
| `X-Response-Time` | `45 ms` | Performance |

O header `Server` é removido para não expor informações do servidor.

### Detecção de Ataques

O middleware de validação detecta e bloqueia automaticamente:

**SQL Injection:**
- `UNION SELECT`, `DROP TABLE`, `INSERT INTO`
- `OR 1=1`, `AND 1=1`, `' OR '`
- `EXEC(`, `EXECUTE(`, `xp_cmdshell`
- `LOAD_FILE`, `INTO OUTFILE`

**XSS (Cross-Site Scripting):**
- Tags `<script>`, `<iframe>`, `<object>`, `<embed>`
- Atributos `onclick=`, `onerror=`, `onload=`
- Protocolos `javascript:`, `vbscript:`, `data:`

**Command Injection:**
- Operadores `; rm`, `| cat`, `&& wget`
- Referências a `/etc/passwd`, `/etc/shadow`
- Backticks e `$()` para execução de comandos

**Path Traversal:**
- Sequências `../`, `..\\`
- Referências absolutas a `/etc/`, `/proc/`

### Proteção contra Brute Force

| Parâmetro | Valor |
|-----------|-------|
| Tentativas máximas | 5 |
| Tempo de bloqueio | 15 minutos |
| Janela de contagem | 30 minutos |

Após 5 tentativas de login falhas no mesmo IP, o IP é temporariamente bloqueado por 15 minutos.

---

## 11. Auditoria e Logs

### Logs Gerados

A API gera dois tipos de log em formato JSON estruturado:

#### Log de Requisições (`logs/audit.log`)

Cada requisição gera uma entrada com:
```json
{
  "timestamp": "2025-01-01T12:00:00.000000+00:00",
  "epoch": 1704110400.0,
  "event": "REQUEST",
  "method": "POST",
  "path": "/api/v1/consulta",
  "status_code": 200,
  "ip": "192.168.1.100",
  "user": "lspf_abc123",
  "role": "admin",
  "auth_method": "jwt",
  "response_time_ms": 2345.6,
  "request_id": "req_abc123..."
}
```

#### Log de Segurança (`logs/security.log`)

Eventos de segurança (login, logout, falhas, criação de keys):
```json
{
  "timestamp": "2025-01-01T12:00:00.000000+00:00",
  "event": "SECURITY",
  "event_type": "LOGIN_SUCCESS",
  "severity": "INFO",
  "ip": "192.168.1.100",
  "subject": "lspf_abc123",
  "role": "admin"
}
```

#### Log de Acesso a Dados (LGPD)

Consultas, contagens e previews são logados com detalhes dos filtros:
```json
{
  "timestamp": "2025-01-01T12:00:00.000000+00:00",
  "event": "DATA_ACCESS",
  "event_type": "CONSULTA",
  "user": "lspf_abc123",
  "role": "admin",
  "filtros": {"ufs": ["SP"]},
  "registros_retornados": 1000,
  "ip": "192.168.1.100"
}
```

### Eventos Registrados

| Evento | Quando |
|--------|--------|
| `LOGIN_SUCCESS` | Login com API Key bem-sucedido |
| `LOGIN_FAILED` | Tentativa de login com credenciais inválidas |
| `LOGOUT` | Logout e revogação de token |
| `REFRESH_FAILED` | Tentativa de refresh com token inválido |
| `API_KEY_CREATED` | Nova API Key criada por admin |
| `API_KEY_DEACTIVATED` | API Key desativada por admin |
| `BRUTE_FORCE_BLOCKED` | IP bloqueado por excesso de tentativas |
| `RATE_LIMIT_EXCEEDED` | Limite de requisições excedido |
| `ATTACK_DETECTED` | SQLi, XSS ou outro ataque detectado |
| `IP_BLOCKED` | IP na blacklist tentou acessar |
| `QUERY_ERROR` | Erro ao executar consulta no banco |
| `INTERNAL_ERROR` | Erro interno do servidor |

---

## 12. Mascaramento de Dados (LGPD)

### Dados mascarados no Preview

O endpoint `/preview` retorna dados com mascaramento automático para proteção de dados pessoais:

| Campo | Original | Mascarado |
|-------|----------|-----------|
| CPF | `12345678901` | `***.***.***-01` |
| Nome | `JOAO DA SILVA` | `J*** D* S***` |
| Email | `joao@gmail.com` | `j***@gm***` |
| Telefone | `11999998888` | `(11) *****-8888` |

### Regras de Mascaramento

- **CPF**: Mantém últimos 2 dígitos, mascara o restante
- **Nome**: Mantém a primeira letra de cada palavra, mascara o restante
- **Email**: Mantém a primeira letra do usuário e as duas primeiras do domínio
- **Telefone**: Mantém DDD e últimos 4 dígitos, mascara o miolo
- Campos de chave identificados automaticamente: `CPF`, `NOME`, `EMAIL_*`, `TELEFONE_*`

---

## 13. Configuração

### Variáveis de Ambiente

| Variável | Descrição | Padrão |
|----------|-----------|--------|
| `API_JWT_SECRET` | Chave secreta para assinar JWTs | Auto-gerada (dev) |
| `API_CORS_ORIGINS` | Origins permitidas (separadas por vírgula) | `http://localhost:5000` |
| `API_ENFORCE_HTTPS` | Forçar HTTPS | `false` |
| `API_DEBUG` | Modo debug | `false` |
| `API_HOST` | Host de bind | `0.0.0.0` |
| `API_PORT` | Porta | `5001` |
| `API_FLASK_SECRET` | Secret key do Flask | Auto-gerada |

### Configurações em `api/config.py`

| Parâmetro | Valor | Descrição |
|-----------|-------|-----------|
| `MAX_CONTENT_LENGTH` | 1 MB | Tamanho máximo do body |
| `MAX_REGISTROS_POR_CONSULTA` | 10.000 | Limite padrão por role |
| `MAX_REGISTROS_PADRAO` | 1.000 | Quantidade padrão se não informada |
| `RATE_LIMIT_ENABLED` | `True` | Ativar/desativar rate limiting |
| `IP_WHITELIST_ENABLED` | `False` | Ativar whitelist restritiva |
| `MASK_CPF` | `True` | Mascarar CPFs nos logs |
| `MASK_EMAIL` | `True` | Mascarar emails nos logs |
| `MASK_TELEFONE` | `True` | Mascarar telefones nos logs |

### Banco de Dados

A API reutiliza as configurações de banco do projeto pai (`config_db.py`):
- **Host**: AWS RDS
- **Database**: `bd_contatus`
- **Pool**: 5 conexões

---

## 14. Execução

### Pré-requisitos

```bash
pip install -r api/requirements.txt
```

Dependências principais:
- `Flask >= 3.0`
- `PyJWT >= 2.8`
- `mysql-connector-python >= 9.0`
- `pandas >= 2.0`

### Primeira Execução

1. **Criar a primeira API Key (admin):**
```bash
cd api
python run.py --create-key
```

2. **Iniciar o servidor:**
```bash
python run.py
```
ou no Windows:
```bash
run_api.bat
```

### Comandos CLI

| Comando | Descrição |
|---------|-----------|
| `python run.py` | Iniciar servidor na porta 5001 |
| `python run.py --create-key` | Criar API Key de admin |
| `python run.py --create-user-key` | Criar API Key de user |
| `python run.py --list-keys` | Listar API Keys cadastradas |

### Verificação

```bash
# Health check (sem autenticação)
curl http://localhost:5001/api/v1/health

# Login
curl -X POST http://localhost:5001/api/v1/auth/login \
  -H "Content-Type: application/json" \
  -d '{"api_key": "lspf_sua_chave_aqui"}'
```

---

## 15. Testes

### Suíte de Testes

A API possui uma suíte abrangente de **220 testes automatizados** cobrindo:

| Arquivo | Testes | Cobertura |
|---------|--------|-----------|
| `test_jwt_handler.py` | 17 | Criação, validação, expiração e revogação de tokens JWT |
| `test_api_keys.py` | 23 | Geração, validação, desativação, expiração e restrição IP |
| `test_rate_limiter.py` | 10 | Sliding window, limites por role, independência por usuário |
| `test_middleware.py` | 17 | Security headers, detecção de ataques, CORS, IP filter |
| `test_schemas.py` | 35 | Validação de UFs, cidades, bairros, gênero, idade, email, etc. |
| `test_routes.py` | 27 | Health, auth, consulta, admin, RBAC, error handlers |
| `test_sanitizer.py` | 27 | Mascaramento de CPF, email, telefone, nome, sanitização |
| `test_crypto.py` | 14 | Tokens, hash de senha, HMAC, hash de IP |
| `test_integration.py` | 12 | Fluxo completo JWT, consulta com mocks, segurança multicamada |

### Executar Testes

```bash
# Todos os testes
python -m pytest api/tests/ -v

# Testes específicos
python -m pytest api/tests/test_routes.py -v

# Com cobertura
python -m pytest api/tests/ --cov=api --cov-report=html

# Apenas testes de segurança
python -m pytest api/tests/test_middleware.py api/tests/test_integration.py -v
```

### Fixtures Disponíveis

| Fixture | Escopo | Descrição |
|---------|--------|-----------|
| `app` | function | App Flask configurada para testes |
| `client` | function | Flask test client |
| `admin_api_key` | function | API Key com role `admin` (tuple: key, key_id) |
| `user_api_key` | function | API Key com role `user` |
| `readonly_api_key` | function | API Key com role `readonly` |
| `admin_token` | function | JWT access token de admin |
| `admin_headers` | function | Headers prontos com Bearer token admin |
| `user_headers` | function | Headers prontos com Bearer token user |
| `readonly_headers` | function | Headers prontos com Bearer token readonly |
| `filtro_basico` | function | Filtro mínimo válido (`ufs: ["SP"]`) |
| `filtro_completo` | function | Filtro com todos os campos preenchidos |

### Isolamento em Testes

Os testes usam fixtures autouse para garantir isolamento:
- API Keys em diretório temporário (`tmp_path`)
- Logs direcionados para diretório temporário  
- Rate limiter desabilitado
- Blacklist JWT limpa entre testes
- Contadores de brute force zerados

---

## 16. Exemplos de Uso

### Python (requests)

```python
import requests

BASE = "http://localhost:5001/api/v1"
API_KEY = "lspf_sua_chave_aqui"

# 1. Login
resp = requests.post(f"{BASE}/auth/login", json={"api_key": API_KEY})
tokens = resp.json()
headers = {"Authorization": f"Bearer {tokens['access_token']}"}

# 2. Contagem rápida
contagem = requests.post(
    f"{BASE}/consulta/contagem",
    json={"ufs": ["SP"], "cidades": ["SAO PAULO"], "idade_min": 25, "idade_max": 50},
    headers=headers,
)
print(f"Total encontrado: {contagem.json()['total_banco']}")

# 3. Preview (dados mascarados)
preview = requests.post(
    f"{BASE}/consulta/preview",
    json={"ufs": ["SP"], "cidades": ["SAO PAULO"]},
    headers=headers,
)
for reg in preview.json().get("registros_preview", []):
    print(reg)

# 4. Consulta completa
dados = requests.post(
    f"{BASE}/consulta",
    json={
        "ufs": ["SP"],
        "cidades": ["SAO PAULO"],
        "genero": "F",
        "idade_min": 30,
        "idade_max": 45,
        "email": "obrigatorio",
        "tipo_telefone": "movel",
        "quantidade": 500,
    },
    headers=headers,
)
resultado = dados.json()
print(f"Registros: {resultado['total_final']}")

# 5. Logout
requests.post(
    f"{BASE}/auth/logout",
    headers={**headers, "Content-Type": "application/json"},
)
```

### cURL

```bash
# Health check
curl http://localhost:5001/api/v1/health

# Login
curl -X POST http://localhost:5001/api/v1/auth/login \
  -H "Content-Type: application/json" \
  -d '{"api_key": "lspf_sua_chave"}'

# Consulta com token
curl -X POST http://localhost:5001/api/v1/consulta \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer eyJ..." \
  -d '{"ufs": ["SP"], "quantidade": 100}'

# Uso direto com API Key (sem login)
curl -X POST http://localhost:5001/api/v1/consulta/contagem \
  -H "Content-Type: application/json" \
  -H "X-API-Key: lspf_sua_chave" \
  -d '{"ufs": ["RJ"]}'

# Criar API Key (admin)
curl -X POST http://localhost:5001/api/v1/admin/keys \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer eyJ..." \
  -d '{"nome": "App Mobile", "role": "user", "expira_em_dias": 90}'

# Listar API Keys
curl http://localhost:5001/api/v1/admin/keys \
  -H "Authorization: Bearer eyJ..."
```

### Uso direto com API Key (sem JWT)

Todos os endpoints autenticados também aceitam autenticação direta via API Key no header `X-API-Key`:

```bash
curl -X POST http://localhost:5001/api/v1/consulta \
  -H "Content-Type: application/json" \
  -H "X-API-Key: lspf_sua_chave_aqui" \
  -d '{"ufs": ["MG"], "cidades": ["BELO HORIZONTE"], "quantidade": 200}'
```

---

## Estrutura de Arquivos

```
api/
├── __init__.py              # Versão da API
├── app.py                   # App factory Flask
├── config.py                # Configurações centralizadas
├── run.py                   # Entry point CLI
├── requirements.txt         # Dependências Python
├── run_api.bat              # Script Windows para iniciar
├── README.md                # README resumido
├── documentacao.md           # Esta documentação
├── api_keys.json            # API Keys (auto-gerado, .gitignore)
│
├── auth/
│   ├── __init__.py
│   ├── jwt_handler.py       # Criação/validação/revogação JWT
│   ├── api_keys.py          # CRUD e validação de API Keys
│   └── decorators.py        # @require_auth, @require_role
│
├── middleware/
│   ├── __init__.py
│   ├── ip_filter.py         # Whitelist/blacklist IP
│   ├── rate_limiter.py      # Sliding window rate limiter
│   ├── request_validator.py # Detecção de ataques (SQLi, XSS...)
│   └── security_headers.py  # Headers de segurança + CORS
│
├── models/
│   ├── __init__.py
│   └── schemas.py           # Validação de schemas de entrada
│
├── routes/
│   ├── __init__.py
│   ├── auth_routes.py       # Login, refresh, logout, /me
│   ├── consulta.py          # Consulta, contagem, preview
│   ├── admin.py             # Gerenciamento de API Keys
│   └── health.py            # Health check, DB check, stats
│
├── utils/
│   ├── __init__.py
│   ├── audit_logger.py      # Log estruturado JSON
│   ├── sanitizer.py         # Mascaramento LGPD
│   └── crypto.py            # Hash, HMAC, tokens seguros
│
├── tests/
│   ├── conftest.py          # Fixtures compartilhadas
│   ├── test_jwt_handler.py  # Testes JWT
│   ├── test_api_keys.py     # Testes API Keys
│   ├── test_rate_limiter.py # Testes Rate Limiting
│   ├── test_middleware.py   # Testes Middlewares
│   ├── test_schemas.py      # Testes Validação
│   ├── test_routes.py       # Testes Rotas/Endpoints
│   ├── test_sanitizer.py    # Testes Mascaramento
│   ├── test_crypto.py       # Testes Criptografia
│   └── test_integration.py  # Testes de Integração
│
└── logs/                     # Logs gerados (auto-criado, .gitignore)
    ├── audit.log
    └── security.log
```

---

*Documentação gerada para o projeto Lista PF — API Segura v1.0.0*
