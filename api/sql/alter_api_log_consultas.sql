-- Migração: adiciona campos de controle de exportação em api_log_consultas.
-- Dados financeiros ficam em acompanhamento_financeiro (tabela separada).
--
-- Aplicar ANTES de fazer deploy do código correspondente.
--
-- Estado atual confirmado em 2026-07-07:
--   - usuario_id INT UNSIGNED NULL  → já existe (não adicionar)
--   - endpoint ENUM                 → expandir com gerar / download / download_job
--   - tipo_lista                    → não existe (adicionar)
--   - baixado                       → não existe (adicionar)

-- Passo 1 — expande o ENUM de endpoint para incluir os novos tipos de download
ALTER TABLE api_log_consultas
    MODIFY COLUMN endpoint ENUM(
        'consulta',
        'consulta_async',
        'enriquecimento',
        'preview',
        'contagem',
        'gerar',
        'download',
        'download_job'
    ) NOT NULL;

-- Passo 2 — adiciona tipo_lista e baixado
--   (usuario_id já existe — não incluir aqui)
ALTER TABLE api_log_consultas
    ADD COLUMN tipo_lista ENUM('venda','teste','consulta_disponibilidade') NULL AFTER erro,
    ADD COLUMN baixado    TINYINT(1)                                        NULL AFTER tipo_lista;

