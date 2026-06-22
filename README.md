# API de consulta de contatos

API REST para consulta, filtragem e extração de dados de contatos pessoa física, com pipeline de limpeza integrado e exportação XLSX. Construída com Flask sobre um banco MySQL (AWS RDS).

---

## Visão Geral

O sistema permite que o frontend envie filtros (UF, cidade, bairro, faixa etária, gênero, CBO, etc.) e receba de volta uma lista limpa e formatada — em JSON ou XLSX — com até 50.000 registros por extração, ou enriqueça uma lista existente de CPFs/telefones com dados completos de contato.

---

## Arquitetura

```
                        ┌─────────────────────┐
                        │      Frontend        │
                        │  (filtros → XLSX)    │
                        └──────────┬──────────┘
                                   │ HTTPS
                                   ▼
              ┌────────────────────────────────────────────┐
              │                 Flask API                   │
              │                                            │
              │  1. Auth (API Key / JWT Bearer)            │
              │  2. Rate Limiter (sliding window)          │
              │  3. Request Validator (anti-injection)     │
              │  4. Timeout Middleware                     │
              │                 │                          │
              │     ┌───────────▼──────────┐              │
              │     │    Cache Redis        │              │
              │     │  (SHA256 dos filtros) │              │
              │     │  TTL configurável     │              │
              │     └───────────┬──────────┘              │
              │            miss │ hit                      │
              │                 ▼                          │
              │     ┌───────────────────────┐             │
              │     │    Query Builder       │             │
              │     │  SQL dinâmico com      │             │
              │     │  cursor paginado       │             │
              │     └───────────┬───────────┘             │
              │                 │ lotes de 5k              │
              │                 ▼                          │
              │     ┌───────────────────────┐             │
              │     │    MySQL RDS           │             │
              │     │  (latest_contacts)     │             │
              │     └───────────┬───────────┘             │
              │                 │                          │
              │                 ▼                          │
              │     ┌───────────────────────┐             │
              │     │   Data Processor       │             │
              │     │  Limpeza + validação   │             │
              │     │  Separação DDD         │             │
              │     │  Métricas de qualidade │             │
              │     └───────────┬───────────┘             │
              │                 │ acumula até 50k          │
              │                 ▼                          │
              │     ┌───────────────────────┐             │
              │     │   XLSX Exporter        │             │
              │     │  CPF com zeros (int)   │             │
              │     │  DDD_1/TEL_1 separados │             │
              │     └───────────┬───────────┘             │
              └─────────────────┼──────────────────────────┘
                                │ XLSX / JSON
                                ▼
                        ┌─────────────────┐
                        │    Frontend      │
                        └─────────────────┘
```

### Estrutura de arquivos

```
api/
├── app.py                    # Flask App Factory
├── config.py                 # Configurações centralizadas (limites, TTLs, etc.)
├── config_db.py              # Credenciais do banco (lê variáveis de ambiente)
├── run.py                    # Entry point (CLI: criar keys, iniciar servidor)
├── requirements.txt
├── Dockerfile
├── gunicorn.conf.py
│
├── auth/
│   ├── api_keys.py           # Hash SHA-256, criação e validação de API Keys
│   ├── jwt_handler.py        # JWT com blacklist, refresh rotation, JTI
│   └── decorators.py         # @require_auth, @require_role
│
├── middleware/
│   ├── ip_filter.py          # Whitelist/blacklist de IPs (suporte CIDR)
│   ├── rate_limiter.py       # Sliding window por minuto/hora/dia por role
│   ├── request_validator.py  # Detecção de SQLi, XSS, path traversal
│   ├── security_headers.py   # HSTS, CSP, X-Frame-Options, CORS
│   └── timeout_middleware.py # Timeout por role (admin 180s, user 90s)
│
├── routes/
│   ├── auth_routes.py        # Login, refresh, logout, /me
│   ├── admin.py              # CRUD de API Keys
│   ├── health.py             # /health, /health/db, /health/stats
│   ├── consulta/
│   │   ├── __init__.py       # Pipeline principal + jobs assíncronos
│   │   └── schema.py         # Validação e normalização dos filtros
│   └── enriquecimento/
│       └── __init__.py       # Enriquecimento por CPF ou telefone
│
└── utils/
    ├── query_builder.py      # Monta SQL dinâmico com cursor paginado
    ├── data_processor.py     # Limpeza, separação DDD, filtros Python
    ├── data_quality.py       # Métricas de completude (% email, móvel, etc.)
    ├── data_cleaner.py       # Remoção de registros inválidos
    ├── xlsx_exporter.py      # Formatação XLSX (CPF numérico, colunas ordenadas)
    ├── alta_renda.py         # Cache de bairros nobres por cidade (30 min TTL)
    ├── bairros_aliases.py    # Expansão de abreviações de bairros (JD→JARDIM etc.)
    ├── cache.py              # Cache Redis (graceful degradation se offline)
    ├── job_store.py          # Store de jobs assíncronos (thread-safe, em memória)
    ├── json_logger.py        # Formatter de logs em JSON estruturado
    ├── sanitizer.py          # Mascaramento de CPF, email e telefone em logs
    └── audit_logger.py       # Logs de acesso a dados (compliance LGPD)
```

---

## Pipeline de dados

### Consulta (extração de lista)

```
Filtros do frontend
       │
       ▼
1. Validação de schema (schema.py)
   - UFs válidas, ranges de idade, listas de cidades/bairros
   - Normaliza gênero, email, tipo_telefone
       │
       ▼
2. Enriquecimento de filtros (se alta_renda=true)
   - Injeta bairros nobres da cidade via tabela bairros_alta_renda
   - Expande abreviações: "JD BOTANICO" → ["JD BOTANICO", "JARDIM BOTANICO", ...]
       │
       ▼
3. Cache Redis
   - Chave: SHA256(sort(filtros))
   - Hit → retorna DataFrame do parquet cacheado
   - Miss → executa pipeline abaixo
       │
       ▼
4. Loop de lotes (BATCH_SIZE_DB=5k, máx BATCH_MAX_ITER=20)
   ┌─────────────────────────────────────────────┐
   │  build_query() → SQL com cursor paginado    │
   │  (WHERE ID_MAILING > last_id ORDER BY ID)   │
   │              ↓                              │
   │  MySQL RDS → lote bruto de até 5.000 linhas │
   │              ↓                              │
   │  data_processor.processar()                 │
   │  - Remove CPF inválido (dígito verificador) │
   │  - Remove telefone inválido (qtd dígitos)   │
   │  - Valida email (regex)                     │
   │  - Separa DDD dos telefones                 │
   │  - Filtra tipo (móvel/fixo) pós-query       │
   │  - Filtra por DDD se ddds= fornecido        │
   │              ↓                              │
   │  Acumula no DataFrame resultado             │
   │  Para quando: atingiu quantidade OU esgotou │
   └─────────────────────────────────────────────┘
       │
       ▼
5. Salva no cache (Redis) com TTL
       │
       ▼
6. Métricas de qualidade
   - com_email, com_movel, com_fixo, pct_* calculados sobre o resultado
       │
       ▼
7. XLSX Exporter
   - CPF armazenado como inteiro com format="00000000000" (zeros à esquerda sem flag verde)
   - Colunas na ordem: DDD_1, TEL_1, DDD_2, TEL_2, ..., NOME, CPF, ...
   - Aba de metadados: filtros aplicados, total, tempo de processamento
```

### Enriquecimento

```
Arquivo .txt/.csv (CPFs ou telefones)
       │
       ▼
1. Leitura com limite de 10 MB
   - Normaliza CPF (11 dígitos) ou telefone (10-11 dígitos, remove DDI +55)
   - Deduplica preservando ordem
   - Suporte a TXT (um por linha), CSV (usa 1ª coluna), separadores , ; \t
       │
       ▼
2. Gera session_id (UUID hex)
   - Isolamento por request: cada sessão usa seu próprio ID_IMPORT
   - Permite múltiplas extrações simultâneas sem race condition
       │
       ▼
3. LOAD DATA LOCAL INFILE → cpf_consultas (com ID_IMPORT = session_id)
   Fallback: INSERT batched de 50k
       │
       ▼
4. JOIN query filtrando por ID_IMPORT
   - Por CPF: JOIN latest_contacts ON cpf = cpf_consultas.cpf AND ID_IMPORT = session_id
   - Por telefone: JOIN via tabela telephone (telefone_completo = DDD+número)
       │
       ▼
5. Separação DDD (banco armazena DDD+número concatenados)
   - "41991234567" → DDD_1=41, TELEFONE_1=991234567
       │
       ▼
6. DELETE FROM cpf_consultas WHERE ID_IMPORT = session_id (cleanup)
       │
       ▼
7. XLSX com CPF numérico (format="00000000000")
   Headers: X-Enviados, X-Encontrados, X-Nao-Encontrados
```

---

## Modelo de dados

### Tabela principal: `latest_contacts`

A tabela segue um padrão de **snapshot versionado**: cada CPF pode ter múltiplas linhas correspondendo a diferentes momentos de captura (`snapshot_updated_at`). Isso preserva o histórico sem sobrescrever dados.

Para qualquer consulta, interessa apenas o snapshot mais recente por CPF. A query usa uma **derived table não-correlacionada** para calcular o `MAX(snapshot_updated_at)` por CPF e então faz JOIN de volta:

```sql
-- Padrão adotado (derived table — executa uma vez)
JOIN (
  SELECT cpf, MAX(snapshot_updated_at) AS max_ts
  FROM latest_contacts lc
  JOIN cpf_consultas c ON lc.cpf = c.cpf AND c.ID_IMPORT = 'session_id'
  GROUP BY cpf
) mx ON a.cpf = mx.cpf AND a.snapshot_updated_at = mx.max_ts

-- Alternativa rejeitada (subquery correlacionada — executa N vezes)
WHERE a.snapshot_updated_at = (
  SELECT MAX(snapshot_updated_at) FROM latest_contacts
  WHERE cpf = a.cpf   -- ← re-executa para cada linha do resultado externo
)
```

A derived table materializa o agrupamento uma única vez. Em tabelas com milhões de snapshots, a diferença de performance é de ordens de grandeza.

### Cursor composto `(ID_MAILING, ID_COMPLEMENT)`

A paginação por cursor usa dois campos porque a chave primária é composta. Avançar pelo cursor garante cobertura total da tabela sem duplicatas entre lotes:

```sql
WHERE (ID_MAILING > :last_mailing)
   OR (ID_MAILING = :last_mailing AND ID_COMPLEMENT > :last_complement)
ORDER BY ID_MAILING, ID_COMPLEMENT
LIMIT 5000
```

Isso preserva a ordem física dos dados no índice primário, tornando cada lote uma leitura sequencial — o padrão mais eficiente para MySQL InnoDB.

### Staging table `cpf_consultas` e o padrão ELT

O enriquecimento usa um padrão clássico de engenharia de dados: **staging table**. Em vez de passar uma lista de CPFs como parâmetro (o MySQL tem limite de ~65k elementos em `IN`), a API faz:

1. **Extract** — lê e normaliza o arquivo enviado
2. **Load** — carrega na staging via `LOAD DATA LOCAL INFILE` (bulk insert — ordens de grandeza mais rápido que `INSERT` linha a linha)
3. **Transform** — executa o JOIN diretamente no banco, que usa seus índices para cruzar as tabelas

`LOAD DATA LOCAL INFILE` lida com arquivos de milhões de linhas em segundos porque escreve diretamente nos data files do MySQL, sem overhead de protocolo por linha. O fallback para `INSERT` em batches de 50k existe para ambientes onde `LOCAL INFILE` está desabilitado.

---

## Decisões de projeto

### Por que cursor paginado e não OFFSET?

`OFFSET N` em MySQL faz full scan até a posição N — para a página 100 com 5k registros, ele lê 500k linhas e descarta. Com cursor paginado (`WHERE ID_MAILING > last_id`), cada query lê exatamente os próximos 5k, independente da posição. Em tabelas com milhões de registros, a diferença é de segundos vs minutos.

### Por que lotes de 5k e não 50k de uma vez?

O banco tem um teto operacional de 5k por query. Além disso, lotes menores permitem:
- Acumular apenas registros válidos (a limpeza descarta ~10-30% em média)
- Liberar memória entre lotes
- Detectar esgotamento da base mais cedo

### Por que a consulta ao banco é indexada e parte da limpeza fica na API?

A decisão central do sistema é dividir o trabalho em dois estágios com responsabilidades distintas.

**O que o banco faz (Etapa 1 — SQL indexado):**

Os filtros que chegam ao SQL são aqueles para os quais existem índices na tabela: UF, cidade, bairro, gênero, faixa etária (data de nascimento), existência de email, existência de CBO. Esses filtros eliminam 95–99% dos registros antes de qualquer dado sair do banco. Uma query bem indexada nessa tabela retorna 5.000 registros em ~200ms mesmo contra dezenas de milhões de linhas.

**O que a API faz (Etapa 2 — Python):**

Algumas validações não podem ser feitas por índice e seriam caras ou impossíveis em SQL puro:

- **CPF com dígito verificador**: requer aritmética módulo 11 sobre os dígitos. O banco armazena o CPF como string — um `WHERE cpf REGEXP ...` não valida o dígito verificador, apenas o formato. Em Python, a validação é uma função de 10 linhas.
- **Classificação de telefone (móvel vs fixo)**: o banco armazena DDD + número concatenados (`41991234567`). Separar o DDD e verificar se o 3º dígito é 9 (celular BR) requer manipulação de string que o SQL faria de forma verbosa e sem índice.
- **Email por regex**: o banco pode verificar se o campo não é nulo, mas não valida o formato com precisão (domínio existente, estrutura válida). Isso é feito em Python com um regex calibrado para o perfil dos dados.
- **Filtro por DDD**: depois de separar o DDD do número, a API filtra os registros cujo DDD está na lista fornecida — novamente uma operação sobre dado derivado, não armazenado diretamente com índice.

**Por que não fazer tudo no banco?**

Além da complexidade (stored procedures ou funções UDF), misturar lógica de negócio no banco cria acoplamento difícil de versionar e testar. Uma mudança na regra de validação de CPF exigiria alterar a stored function em produção. Na API, é um arquivo Python com testes unitários.

**Por que não fazer tudo em Python?**

Buscar 50.000 registros válidos de uma tabela com 20 milhões de linhas sem filtrar no banco significa trazer potencialmente milhões de registros para memória. Com os filtros indexados no SQL, o banco entrega lotes de 5.000 já pré-filtrados — a API só precisa fazer a validação fina em um volume pequeno.

**O trade-off aceito:**

Alguns registros passam pelo SQL mas são descartados pela limpeza Python (CPF inválido, telefone com dígitos errados). A taxa de descarte típica é 10–30% dependendo da região. Por isso o loop busca lotes até acumular a quantidade de registros *limpos* pedida — o banco faz o trabalho pesado de seleção, Python faz o trabalho fino de validação.

### Por que usar ID_IMPORT para isolamento no enriquecimento?

A tabela `cpf_consultas` é compartilhada. A alternativa seria um lock por request (bloquearia requisições simultâneas) ou uma tabela por sessão (requereria permissões DDL). O `ID_IMPORT` já existia na tabela — cada request grava com seu próprio UUID e filtra/limpa apenas suas linhas. Zero contention, zero schema change.

### Por que DELETE e não TRUNCATE?

`TRUNCATE` requer privilégio DROP, que não é concedido ao usuário de leitura. `DELETE WHERE ID_IMPORT = session_id` requer apenas DELETE — e tem a vantagem de ser cirúrgico, removendo só as linhas da sessão atual.

### Por que Redis com graceful degradation?

Cache Redis é opcional. Se `REDIS_URL` estiver vazio ou o Redis cair, a API continua funcionando normalmente sem cache — o pipeline vai ao banco. Isso evita que uma dependência de infraestrutura derrube a API. Quando disponível, consultas com os mesmos filtros não rebatem no banco por 30 minutos.

### Por que jobs assíncronos?

Extrações de 50k registros podem levar 30-90 segundos dependendo dos filtros e da carga do banco. Bloquear um request HTTP por esse tempo é ruim para proxies, load balancers e experiência do usuário. O fluxo `/iniciar` → polling `/job/{id}` → `/job/{id}/xlsx` permite que o frontend mostre um progresso e não fique aguardando timeout.

### Por que logs em JSON?

Logs em texto plano não são parseáveis por ferramentas de observabilidade (CloudWatch, Datadog, Loki). Cada linha JSON tem `request_id`, `user`, `latencia_ms`, `cache_hit`, etc. como campos indexáveis — permite criar dashboards, alertas e queries sem regex.

---

## Garantias do pipeline

### Isolamento de sessão no enriquecimento

Cada request de enriquecimento gera um `session_id = uuid4().hex` que é gravado na coluna `ID_IMPORT` da staging table. Isso garante que:

- Dois requests simultâneos **nunca leem os dados um do outro** — cada JOIN filtra por seu `ID_IMPORT`
- O cleanup é **cirúrgico**: `DELETE WHERE ID_IMPORT = session_id` remove apenas as linhas da sessão encerrada
- Não há lock de tabela — múltiplas sessões escrevem e leem em paralelo sem bloqueio

Isso é equivalente ao padrão de **partition-by-session** usado em pipelines de ingestão distribuída, implementado sem nenhuma mudança estrutural no banco.

### Idempotência da limpeza

A etapa de limpeza Python é **pura e determinística**: dado o mesmo lote bruto do banco, produz sempre o mesmo resultado limpo. Não há estado externo, escrita paralela ou side effects. Isso permite:

- Reprocessar qualquer lote sem risco de duplicatas
- Testar a lógica de limpeza isoladamente com dados sintéticos
- Alterar as regras de validação sem tocar no banco

### Deduplicação por CPF entre fatias

Quando a consulta usa `distribuicao` (múltiplas fatias cidade/gênero), o pipeline mantém um `set` de CPFs já coletados e exclui duplicatas entre fatias:

```python
exclude_cpfs: set[str] = set()
for fatia in distribuicao:
    df_p, _, _ = _buscar_ate_quantidade(fatia, qtd, exclude_cpfs=exclude_cpfs)
    exclude_cpfs.update(df_p["CPF"].dropna())
```

Isso garante que um mesmo CPF nunca apareça em duas fatias diferentes da mesma extração — propriedade crítica para listas de marketing onde o mesmo contato não pode receber comunicações duplicadas.

### Detecção de esgotamento de base

O loop de lotes distingue dois casos de parada:

- **Quantidade atingida**: acumulou registros limpos suficientes — `esgotou_base: false`
- **Base esgotada**: o banco retornou menos linhas que o lote (`< BATCH_SIZE_DB`), indicando que não há mais dados com aqueles filtros — `esgotou_base: true`

O campo `esgotou_base` é retornado na resposta e no metadado do XLSX, permitindo que o frontend informe ao usuário quando a base não tem volume suficiente para a segmentação pedida.

---

## Qualidade de dados

Qualidade não é checada apenas no output — é parte do pipeline.

### O que é validado antes de sair

| Campo | Regra aplicada |
|-------|---------------|
| CPF | Algoritmo de dígito verificador (módulo 11) |
| Telefone | 10 dígitos (fixo) ou 11 dígitos com 3° dígito = 9 (móvel BR) |
| Email | Regex calibrado para o perfil dos dados (domínio + estrutura) |
| DDD | Separado do número após validação do comprimento total |

### Métricas retornadas em toda extração

```json
"qualidade": {
  "total": 50000,
  "com_email": 38500,      "pct_email": 77.0,
  "com_movel": 49200,      "pct_movel": 98.4,
  "com_fixo": 8100,        "pct_fixo": 16.2,
  "com_algum_tel": 49800,  "pct_algum_tel": 99.6,
  "com_genero": 48000,     "pct_genero": 96.0,
  "com_data_nascimento": 47500, "pct_data_nascimento": 95.0,
  "com_endereco": 45000,   "pct_endereco": 90.0
}
```

Essas métricas permitem ao usuário avaliar a completude da lista antes de usar — um padrão de **data profiling** embutido no próprio pipeline de extração.

---

## Observabilidade

Todo request produz uma linha de log JSON com campos indexáveis:

```json
{
  "timestamp": "2026-06-22T15:30:00",
  "level": "INFO",
  "logger": "api.routes.consulta",
  "message": "consulta concluída",
  "request_id": "req_abc123",
  "user": "usuario@empresa.com",
  "action": "CONSULTA",
  "registros": 50000,
  "latencia_ms": 42300,
  "cache_hit": false
}
```

Campos disponíveis para monitoramento: `latencia_ms` (SLA), `cache_hit` (taxa de aproveitamento do cache), `registros` (volume extraído por usuário), `action` (tipo de operação).

Compatível com qualquer stack de observabilidade que consuma JSON (CloudWatch Logs Insights, Datadog Log Management, Grafana Loki).

---

## Endpoints

| Método | Endpoint | Role | Descrição |
|--------|----------|------|-----------|
| GET | `/api/v1/health` | — | Health check público |
| GET | `/api/v1/health/db` | admin | Testa conexão com banco |
| GET | `/api/v1/health/stats` | admin | Métricas da API |
| POST | `/api/v1/auth/login` | — | API Key → JWT tokens |
| POST | `/api/v1/auth/refresh` | — | Renova access token |
| POST | `/api/v1/auth/logout` | qualquer | Revoga token |
| GET | `/api/v1/auth/me` | qualquer | Info do usuário autenticado |
| POST | `/api/v1/consulta` | admin, user | Consulta síncrona → JSON |
| POST | `/api/v1/consulta/preview` | todos | Amostra de 50 registros mascarados |
| POST | `/api/v1/consulta/contagem` | admin, user | Executa query → salva parquet → retorna token |
| POST | `/api/v1/consulta/gerar` | admin, user | Token → XLSX |
| POST | `/api/v1/consulta/download` | admin, user | Query + XLSX em um request |
| POST | `/api/v1/consulta/iniciar` | admin, user | Inicia job assíncrono → job_id (202) |
| GET | `/api/v1/consulta/job/<id>` | admin, user | Status e resultado do job |
| GET | `/api/v1/consulta/job/<id>/xlsx` | admin, user | Download XLSX do job concluído |
| POST | `/api/v1/enriquecimento` | admin, user | Enriquece lista por CPF ou telefone → XLSX |
| POST | `/api/v1/admin/keys` | admin | Cria nova API Key |
| GET | `/api/v1/admin/keys` | admin | Lista API Keys |
| DELETE | `/api/v1/admin/keys/<key_id>` | admin | Desativa API Key |

---

## Exemplos

### Extração de lista síncrona

```bash
curl -X POST http://localhost:5001/api/v1/consulta \
  -H "X-API-Key: lspf_sua_chave" \
  -H "Content-Type: application/json" \
  -d '{
    "ufs": ["PR"],
    "cidades": ["CURITIBA"],
    "bairros": ["BATEL", "BIGORRILHO"],
    "genero": "F",
    "idade_min": 25,
    "idade_max": 45,
    "tipo_telefone": "movel",
    "email": "obrigatorio",
    "quantidade": 1000
  }'
```

Resposta:
```json
{
  "ok": true,
  "total_final": 1000,
  "registros": [{ "DDD_1": "41", "TELEFONE_1": "991234567", "NOME": "...", "CPF": "...", ... }],
  "qualidade": {
    "total": 1000,
    "com_email": 1000, "pct_email": 100.0,
    "com_movel": 1000, "pct_movel": 100.0,
    "com_fixo": 0,     "pct_fixo": 0.0
  },
  "cache_hit": false,
  "tempo_processamento_s": 4.2
}
```

### Alta renda

```bash
curl -X POST http://localhost:5001/api/v1/consulta \
  -H "X-API-Key: lspf_sua_chave" \
  -H "Content-Type: application/json" \
  -d '{
    "ufs": ["PR"],
    "cidades": ["CURITIBA"],
    "alta_renda": true,
    "quantidade": 5000
  }'
```

Os bairros nobres (BATEL, CHAMPAGNAT, BIGORRILHO, etc.) são injetados automaticamente pela API via tabela `bairros_alta_renda`, com expansão de abreviações.

### Extração assíncrona (50k registros)

```bash
# 1. Iniciar job
curl -X POST http://localhost:5001/api/v1/consulta/iniciar \
  -H "X-API-Key: lspf_sua_chave" \
  -H "Content-Type: application/json" \
  -d '{"ufs": ["SP"], "cidades": ["SAO PAULO"], "quantidade": 50000}'
# → { "job_id": "abc123...", "status": "processando" }

# 2. Polling
curl http://localhost:5001/api/v1/consulta/job/abc123 \
  -H "X-API-Key: lspf_sua_chave"
# → { "status": "concluido", "resultado": { "total_final": 50000, "qualidade": {...} } }

# 3. Download
curl http://localhost:5001/api/v1/consulta/job/abc123/xlsx \
  -H "X-API-Key: lspf_sua_chave" \
  -o lista.xlsx
```

### Enriquecimento por CPF

```bash
# arquivo cpfs.txt: um CPF por linha (com ou sem pontuação)
curl -X POST http://localhost:5001/api/v1/enriquecimento \
  -H "X-API-Key: lspf_sua_chave" \
  -F "arquivo=@cpfs.txt" \
  -F "tipo=cpf" \
  -o resultado.xlsx
# Headers de resposta: X-Enviados, X-Encontrados, X-Nao-Encontrados
```

### Distribuição por fatias

```bash
curl -X POST http://localhost:5001/api/v1/consulta \
  -H "X-API-Key: lspf_sua_chave" \
  -H "Content-Type: application/json" \
  -d '{
    "ufs": ["SC"],
    "distribuicao": [
      { "cidade": "FLORIANOPOLIS", "genero": "M", "quantidade": 500 },
      { "cidade": "JOINVILLE",     "genero": "F", "quantidade": 300 },
      { "cidade": "BLUMENAU",      "genero": "ambos", "quantidade": 200 }
    ]
  }'
```

---

## Filtros disponíveis

| Filtro | Tipo | Descrição |
|--------|------|-----------|
| `ufs` | `string[]` | UFs brasileiras (ex: `["SP", "RJ"]`) |
| `cidades` | `string[]` | Nomes de cidades (até 50) |
| `bairros` | `string[]` | Nomes de bairros (até 100) |
| `alta_renda` | `boolean` | Injeta bairros nobres automaticamente |
| `genero` | `string` | `M`, `F` ou `ambos` |
| `idade_min` / `idade_max` | `integer` | Faixa etária (18–120) |
| `tipo_telefone` | `string` | `movel`, `fixo` ou `ambos` |
| `ddds` | `integer[]` | Filtra por DDD (ex: `[41, 42]`) |
| `email` | `string` | `obrigatorio`, `nao`, `preferencial`, `nao_filtrar` |
| `tem_cbo` | `string` | `obrigatorio` ou `nao_filtrar` |
| `cbos` | `string[]` | Filtra por código CBO (até 50) |
| `quantidade` | `integer` | Até 50.000 por request |
| `distribuicao` | `object[]` | Fatias independentes com quantidade por segmento |

---

## Configuração

Copie `api/.env.example` para `api/.env` e preencha:

```bash
# Banco (obrigatório)
DB_HOST=seu-host.rds.amazonaws.com
DB_NAME=bd_contatus
DB_USER=usuario_leitura
DB_PASSWORD=senha
DB_USER_ADMIN=usuario_admin      # precisa de DELETE na tabela cpf_consultas
DB_PASSWORD_ADMIN=senha_admin

# API
API_JWT_SECRET=hex_64_chars      # obrigatório em produção
API_PORT=5001
API_CORS_ORIGINS=https://seu-dominio.com

# Lotes
API_BATCH_SIZE_DB=5000           # linhas por query ao banco
API_BATCH_MAX_ITER=20            # máx iterações por extração

# Cache Redis (opcional — deixe vazio para desabilitar)
REDIS_URL=redis://localhost:6379/0
CACHE_TTL_SECONDS=1800

# Log
LOG_LEVEL=info
```

---

## Como rodar

### Desenvolvimento

```bash
pip install -r api/requirements.txt
cp api/.env.example api/.env   # preencher credenciais

python -m api.run --create-key  # cria primeira API Key (admin)
python -m api.run               # inicia em localhost:5001
```

### Produção (Docker)

```bash
docker build -f api/Dockerfile -t api-contatus .
docker run -p 5001:5001 --env-file api/.env api-contatus
```

### Produção (Gunicorn direto)

```bash
gunicorn --config api/gunicorn.conf.py "api.app:create_app()"
```

Gunicorn usa `(2 × CPU) + 1` workers com `preload_app=False` (necessário para evitar duplicar o APScheduler nos forks).

---

## Segurança

### Autenticação
- API Keys armazenadas como SHA-256 — a chave original nunca é guardada
- JWT com access token de 30 min e refresh de 24h
- Refresh token rotation (single-use) + blacklist de JTIs revogados

### Autorização (RBAC)
| Role | Acesso |
|------|--------|
| `admin` | Tudo + gestão de keys |
| `user` | Consultas e enriquecimento |
| `readonly` | Apenas preview (dados mascarados) |

### Rate Limiting (sliding window)
| Role | /min | /hora | /dia |
|------|------|-------|------|
| admin | 120 | 3.000 | 50.000 |
| user | 30 | 500 | 5.000 |
| readonly | 10 | 100 | 1.000 |

### Outras camadas
- Detecção de SQL Injection, XSS e path traversal em todos os inputs
- Headers HTTP: HSTS, CSP, X-Frame-Options: DENY, X-Content-Type-Options: nosniff
- IP blacklist (e whitelist opcional com suporte a CIDR)
- Timeout por role: admin 180s, user 90s, readonly 30s
- Mascaramento de CPF, email e telefone em todos os logs
- Audit log de todos os acessos a dados (compliance LGPD)

---

## Stack

| Componente | Tecnologia |
|------------|-----------|
| Framework | Flask 3 |
| Banco | MySQL 8 (AWS RDS) |
| Processamento | pandas 2, pyarrow |
| Cache | Redis 7 (opcional) |
| Exportação | openpyxl |
| Auth | PyJWT |
| Servidor (prod) | Gunicorn (Linux) / Waitress (Windows) |
| Container | Docker |
