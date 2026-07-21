# Mapeamento de Qualidade de Dados — Cidades e Bairros

## Contexto

O banco `bd_contatus` (`latest_contacts`, ~100M linhas) armazena dados de contato com campos `UF`, `cidade` e `BAIRRO` preenchidos manualmente/por importação. Esses campos acumularam variações, abreviações e erros ao longo do tempo.

Este documento registra o processo de mapeamento de erros e os resultados.

---

## Arquivos Gerados

Todos os arquivos estão em `output/correcoes/`:

| Arquivo | Conteúdo | Tamanho |
|---|---|---|
| `correcoes_banco.csv` | **Correções prontas para aplicar no banco** (24.655 entradas) | 1,2 MB |
| `erros_bairros.csv` | Mapeamento completo de todos os bairros do banco com possíveis variações | 10,4 MB |
| `bairros_numeral_incerto.csv` | 10.816 bairros com diferença só no número (I/II/III) — NÃO corrigir | 0,5 MB |
| `erros_cidades_ibge.csv` | Comparação completa de cidades do banco vs. IBGE (31.707 divergências) | 1 MB |

---

## Arquivo Principal: `correcoes_banco.csv`

### Formato

```
tipo;uf;cidade_banco;bairro_banco;valor_correto;ocorrencias
```

### Como aplicar

```sql
-- Corrigir cidade:
UPDATE latest_contacts
SET cidade = valor_correto
WHERE UF = uf AND cidade = cidade_banco;

-- Corrigir bairro:
UPDATE latest_contacts
SET BAIRRO = valor_correto
WHERE UF = uf AND cidade = cidade_banco AND BAIRRO = bairro_banco;
```

> O collation `utf8mb4_unicode_ci` garante que diferenças de acento (ex: `SAO PAULO` vs `SÃO PAULO`) fazem match automaticamente.

### Conteúdo

- **6.535 correções de cidade** — variantes claras: sufixo de UF (`CRUZEIRO DO SUL AC → CRUZEIRO DO SUL`), parênteses (`RIO BRANCO (NOVA PRATA) → RIO BRANCO`), variantes com similaridade ≥ 0.88 e mesma raiz
- **18.120 correções de bairro** — expansão determinística de abreviações conhecidas (sem fuzzy matching)

---

## Etapa 1 — Mapeamento de Cidades

### Script: `scripts/comparar_ibge.py`

1. Baixa a lista oficial de 5.571 municípios do IBGE via API pública
2. Salva em `api/utils/municipios_ibge.json` (uppercase, sem acentos) — **usado em produção** pelo endpoint `/cidades`
3. Consulta o banco agrupando cidades por UF
4. Compara com a lista IBGE usando `difflib.get_close_matches`

**Resultado bruto:** `erros_cidades_ibge.csv` — 31.707 divergências (qualidade mista, inclui falsos positivos).

**Resultado filtrado:** incluído em `correcoes_banco.csv` (6.535 entradas de alta confiança).

### Mudança em produção

O endpoint `/cidades` foi migrado para retornar a lista IBGE estática — zero queries no banco. Ver `api/routes/localidades.py`.

---

## Etapa 2 — Mapeamento de Bairros

### Script: `scripts/mapear_bairros.py`

Para cada um dos 5.571 municípios IBGE:
1. Consulta: `SELECT BAIRRO, COUNT(*) FROM latest_contacts WHERE UF=%s AND cidade=%s GROUP BY BAIRRO HAVING COUNT(*) >= 30 ORDER BY COUNT(*) DESC LIMIT 100`
2. Detecta variações fuzzy (threshold 0.85) dentro da mesma cidade
3. Resume via `bairros_progresso.json` (rastreia todos os pares processados)
4. Pausa de 1s entre cidades para não sobrecarregar o banco

**Resultado:** `erros_bairros.csv` — mapeamento completo de 142.851 variações encontradas.

---

## Etapa 3 — Filtragem e Geração das Correções Confiáveis

### Por que o fuzzy sozinho não é suficiente

O fuzzy por frequência assume que o nome mais frequente é o correto. Isso gera dois problemas:

1. **Direção invertida**: abreviações (`STA RITA`) são mais frequentes que o nome completo (`SANTA RITA`), então o fuzzy marca o nome completo como "errado"
2. **Falsos positivos**: bairros com nomes similares mas distintos (`NOVA ESPERANÇA` ≠ `BOA ESPERANÇA`, `SETOR SUDOESTE` ≠ `SETOR OESTE`)
3. **Bairros numerados**: `BELO JARDIM I` e `BELO JARDIM II` são bairros reais e distintos — verificado via web para os casos mais frequentes (Cuiabá CPA I/II/III/IV, São Luís COHAB ANIL I/II/III/IV, Maracanaú Jereissati I/II/III, etc.)

### Script: `scripts/correcoes_confiaveis.py`

Aceita apenas correções onde `bairro_errado` é **exatamente** uma abreviação conhecida de `sugestao_correta`. Abreviações mapeadas:

| Abrev. | Expandido | Abrev. | Expandido |
|---|---|---|---|
| STA / STO | SANTA / SANTO | VL | VILA |
| S | SAO | JD | JARDIM |
| ST | SETOR | PRQ | PARQUE |
| CPO | CAMPO | LGA | LAGOA |
| PNT | PONTA | PR | PRAIA |
| AT | ALTO | BX | BAIXA |
| MTE | MONTE | FNT | FONTE |
| REC | RECANTO | CEL | CORONEL |
| D | DOM | FR | FREI |
| PE | PADRE | SEN | SENADOR |
| CJ | CONJUNTO | IA | ILHA |
| POR | PORTO | RCHO | RIACHO |
| PL | PLANO | MAJ | MAJOR |
| DQ | DUQUE | | |

**Resultado:** 18.120 correções — zero falso positivo.

### Script: `scripts/combinar_correcoes.py`

Junta correções de cidade e bairro em um único arquivo (`correcoes_banco.csv`) com coluna `tipo` para distinguir o campo a corrigir.

---

## Scripts

| Script | Função |
|---|---|
| `scripts/comparar_ibge.py` | Compara cidades do banco vs. IBGE |
| `scripts/mapear_bairros.py` | Mapeia variações de bairros cidade por cidade |
| `scripts/gerar_lista_correcoes.py` | Deduplica `erros_bairros.csv` |
| `scripts/correcoes_confiaveis.py` | Filtra para correções de alta confiança (abreviações) |
| `scripts/combinar_correcoes.py` | Combina correções de cidade + bairro |

---

## Arquivos em Produção

| Arquivo | Uso |
|---|---|
| `api/utils/municipios_ibge.json` | Lista oficial IBGE — endpoint `/cidades` |
| `api/utils/bairros_aliases.py` | Expansão de abreviações de bairros |
| `api/utils/cidades_aliases.py` | Deduplicação e normalização de cidades |
| `api/utils/alta_renda.py` | Busca bairros de alta renda por cidade |
