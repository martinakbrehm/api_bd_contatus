-- Tabela de acompanhamento financeiro das listas vendidas.
-- Só recebe registros quando tipo_lista = 'venda' e o download foi efetivado.
-- Vinculada a api_log_consultas pelo request_id.

CREATE TABLE acompanhamento_financeiro (

    id                   BIGINT UNSIGNED   AUTO_INCREMENT PRIMARY KEY,
    request_id           VARCHAR(64)       NOT NULL,
    created_at           DATETIME(3)       NOT NULL DEFAULT CURRENT_TIMESTAMP(3),

    usuario_id           INT UNSIGNED      NULL,
    nome_cliente         VARCHAR(150)      NOT NULL,

    valor_lista          DECIMAL(10,2)     NOT NULL,
    parcelado            TINYINT(1)        NOT NULL DEFAULT 0,
    num_parcelas         SMALLINT UNSIGNED NULL,
    valor_parcela        DECIMAL(10,2)     NULL,

    registros_exportados INT UNSIGNED      NULL,

    INDEX idx_created_at (created_at),
    CONSTRAINT fk_af_usuario FOREIGN KEY (usuario_id) REFERENCES usuarios_app (id)
        ON DELETE SET NULL ON UPDATE CASCADE

) ENGINE = InnoDB
  DEFAULT CHARSET = utf8mb4
  COLLATE = utf8mb4_unicode_ci;
