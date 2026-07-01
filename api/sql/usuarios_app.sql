CREATE TABLE usuarios_app (

    id                INT UNSIGNED       AUTO_INCREMENT PRIMARY KEY,
    nome              VARCHAR(100)       NOT NULL,
    email             VARCHAR(150)       NOT NULL,
    senha_hash        VARCHAR(255)       NOT NULL,

    role              ENUM('admin','user','readonly') NOT NULL DEFAULT 'user',
    ativo             TINYINT(1)         NOT NULL DEFAULT 1,

    limite_diario     INT UNSIGNED       NULL,
    limite_mensal     INT UNSIGNED       NULL,

    ip_restrito       VARCHAR(500)       NULL,
    expira_em         DATETIME           NULL,

    criado_em         DATETIME           NOT NULL DEFAULT CURRENT_TIMESTAMP,
    atualizado_em     DATETIME           NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    ultimo_acesso     DATETIME           NULL,

    UNIQUE KEY uk_email (email)

) ENGINE = InnoDB
  DEFAULT CHARSET = utf8mb4
  COLLATE = utf8mb4_unicode_ci;
