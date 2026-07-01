CREATE TABLE api_log_consultas (

    id                    BIGINT UNSIGNED        AUTO_INCREMENT PRIMARY KEY,
    request_id            VARCHAR(64)            NOT NULL,
    created_at            DATETIME(3)            NOT NULL DEFAULT CURRENT_TIMESTAMP(3),

    key_id                VARCHAR(50)            NULL,
    nome_usuario          VARCHAR(100)           NULL,
    role                  ENUM('admin','user','readonly') NULL,
    ip                    VARCHAR(45)            NULL,

    endpoint              ENUM('consulta','consulta_async','enriquecimento','preview','contagem') NOT NULL,
    filtros_json          JSON                   NULL,
    quantidade_solicitada INT UNSIGNED           NULL,

    quantidade_retornada  INT UNSIGNED           NULL,
    esgotou_base          TINYINT(1)             NULL,
    cache_hit             TINYINT(1)             NULL,
    tempo_ms              INT UNSIGNED           NULL,

    enriq_tipo            ENUM('cpf','telefone') NULL,
    enriq_enviados        INT UNSIGNED           NULL,
    enriq_encontrados     INT UNSIGNED           NULL,

    status_http           SMALLINT UNSIGNED      NULL,
    erro                  TEXT                   NULL

) ENGINE = InnoDB
  DEFAULT CHARSET = utf8mb4
  COLLATE = utf8mb4_unicode_ci;
