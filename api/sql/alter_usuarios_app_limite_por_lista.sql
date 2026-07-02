ALTER TABLE usuarios_app
    ADD COLUMN limite_por_lista INT UNSIGNED NULL
    AFTER limite_mensal;
