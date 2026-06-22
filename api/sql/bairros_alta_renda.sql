CREATE TABLE IF NOT EXISTS bairros_alta_renda (
    id              INT UNSIGNED     AUTO_INCREMENT PRIMARY KEY,
    uf_id           INT              NOT NULL
                    COMMENT 'FK para uf.ID — normalizado, evita varchar livre',
    cidade          VARCHAR(100)     NOT NULL
                    COMMENT 'Nome da cidade em UPPERCASE com acentos (igual ao banco)',
    bairro          VARCHAR(100)     NOT NULL
                    COMMENT 'Nome do bairro em UPPERCASE sem acentos (igual ao banco)',
    ranking         TINYINT UNSIGNED NOT NULL DEFAULT 2
                    COMMENT '1=Premium, 2=Classe A, 3=Classe B+',

    UNIQUE KEY uk_uf_id_cidade_bairro       (uf_id, cidade, bairro),
    INDEX      idx_uf_id_cidade_rank_bairro (uf_id, cidade, ranking, bairro),

    CONSTRAINT fk_bar_uf FOREIGN KEY (uf_id) REFERENCES uf (ID)

) ENGINE = InnoDB
  DEFAULT CHARSET = utf8mb4
  COLLATE = utf8mb4_unicode_ci
  COMMENT = 'Bairros de alta renda por cidade — prioridade para alta_renda=true';

SET @AC = (SELECT ID FROM uf WHERE UF = 'AC');
SET @AL = (SELECT ID FROM uf WHERE UF = 'AL');
SET @AM = (SELECT ID FROM uf WHERE UF = 'AM');
SET @AP = (SELECT ID FROM uf WHERE UF = 'AP');
SET @BA = (SELECT ID FROM uf WHERE UF = 'BA');
SET @CE = (SELECT ID FROM uf WHERE UF = 'CE');
SET @DF = (SELECT ID FROM uf WHERE UF = 'DF');
SET @ES = (SELECT ID FROM uf WHERE UF = 'ES');
SET @GO = (SELECT ID FROM uf WHERE UF = 'GO');
SET @MA = (SELECT ID FROM uf WHERE UF = 'MA');
SET @MG = (SELECT ID FROM uf WHERE UF = 'MG');
SET @MS = (SELECT ID FROM uf WHERE UF = 'MS');
SET @MT = (SELECT ID FROM uf WHERE UF = 'MT');
SET @PA = (SELECT ID FROM uf WHERE UF = 'PA');
SET @PB = (SELECT ID FROM uf WHERE UF = 'PB');
SET @PE = (SELECT ID FROM uf WHERE UF = 'PE');
SET @PI = (SELECT ID FROM uf WHERE UF = 'PI');
SET @PR = (SELECT ID FROM uf WHERE UF = 'PR');
SET @RJ = (SELECT ID FROM uf WHERE UF = 'RJ');
SET @RN = (SELECT ID FROM uf WHERE UF = 'RN');
SET @RO = (SELECT ID FROM uf WHERE UF = 'RO');
SET @RR = (SELECT ID FROM uf WHERE UF = 'RR');
SET @RS = (SELECT ID FROM uf WHERE UF = 'RS');
SET @SC = (SELECT ID FROM uf WHERE UF = 'SC');
SET @SE = (SELECT ID FROM uf WHERE UF = 'SE');
SET @SP = (SELECT ID FROM uf WHERE UF = 'SP');
SET @TO = (SELECT ID FROM uf WHERE UF = 'TO');

INSERT INTO bairros_alta_renda (uf_id, cidade, bairro, ranking) VALUES

(@SP, 'SÃO PAULO', 'JARDIM PAULISTANO',       1),
(@SP, 'SÃO PAULO', 'JARDIM AMERICA',           1),
(@SP, 'SÃO PAULO', 'JARDIM EUROPA',            1),
(@SP, 'SÃO PAULO', 'ALTO DA BOA VISTA',        1),
(@SP, 'SÃO PAULO', 'ITAIM BIBI',               1),
(@SP, 'SÃO PAULO', 'VILA NOVA CONCEICAO',      1),
(@SP, 'SÃO PAULO', 'MOEMA',                    1),
(@SP, 'SÃO PAULO', 'VILA MADALENA',            2),
(@SP, 'SÃO PAULO', 'PINHEIROS',                2),
(@SP, 'SÃO PAULO', 'PERDIZES',                 2),
(@SP, 'SÃO PAULO', 'HIGIENOPOLIS',             2),
(@SP, 'SÃO PAULO', 'CONSOLACAO',               2),
(@SP, 'SÃO PAULO', 'BELA VISTA',               2),
(@SP, 'SÃO PAULO', 'CAMPO BELO',               2),
(@SP, 'SÃO PAULO', 'BROOKLIN',                 2),
(@SP, 'SÃO PAULO', 'VILA OLIMPIA',             2),
(@SP, 'SÃO PAULO', 'CENTRO',                   3),
(@SP, 'SÃO PAULO', 'SANTANA',                  3),
(@SP, 'SÃO PAULO', 'TATUAPE',                  3),
(@SP, 'SÃO PAULO', 'IPIRANGA',                 3),
(@SP, 'SÃO PAULO', 'SAUDE',                    3),
(@SP, 'SÃO PAULO', 'SANTO ANDRE',              3),
(@SP, 'SÃO PAULO', 'LAPA',                     3),

(@SP, 'CAMPINAS', 'CAMBUÍ',                    1),
(@SP, 'CAMPINAS', 'JARDIM GUANABARA',          1),
(@SP, 'CAMPINAS', 'JARDIM ITALIA',             1),
(@SP, 'CAMPINAS', 'NOVA CAMPINAS',             1),
(@SP, 'CAMPINAS', 'CENTRO',                    2),
(@SP, 'CAMPINAS', 'BOSQUE',                    2),
(@SP, 'CAMPINAS', 'JARDIM CHAPADAO',           2),
(@SP, 'CAMPINAS', 'SWISS PARK',                2),
(@SP, 'CAMPINAS', 'PARQUE PRADO',              3),
(@SP, 'CAMPINAS', 'VILA ITAPURA',              3),
(@SP, 'CAMPINAS', 'TAQUARAL',                  3),

(@SP, 'PIRACICABA', 'ALTO',                    1),
(@SP, 'PIRACICABA', 'SAO DIMAS',               1),
(@SP, 'PIRACICABA', 'ALEMAES',                 1),
(@SP, 'PIRACICABA', 'CENTRO',                  2),
(@SP, 'PIRACICABA', 'HIGIENOPOLIS',            2),
(@SP, 'PIRACICABA', 'NOVA AMERICA',            2),
(@SP, 'PIRACICABA', 'JARDIM ELITE',            2),
(@SP, 'PIRACICABA', 'PAULISTA',                2),
(@SP, 'PIRACICABA', 'MORUMBI',                 3),
(@SP, 'PIRACICABA', 'CIDADE ALTA',             3),
(@SP, 'PIRACICABA', 'VILA REZENDE',            3),

(@SP, 'RIBEIRÃO PRETO', 'JARDIM BOTANICO',     1),
(@SP, 'RIBEIRÃO PRETO', 'CAMPOS ELISEOS',      1),
(@SP, 'RIBEIRÃO PRETO', 'SUMAREZINHO',         1),
(@SP, 'RIBEIRÃO PRETO', 'ALTO DA BOA VISTA',   1),
(@SP, 'RIBEIRÃO PRETO', 'HIGIENOPOLIS',        2),
(@SP, 'RIBEIRÃO PRETO', 'CENTRO',              2),
(@SP, 'RIBEIRÃO PRETO', 'NOVA ALIANCA',        2),
(@SP, 'RIBEIRÃO PRETO', 'JARDIM PAULISTA',     2),
(@SP, 'RIBEIRÃO PRETO', 'IPIRANGA',            3),
(@SP, 'RIBEIRÃO PRETO', 'PLANALTO VERDE',      3),

(@SP, 'SAO JOSE DO RIO PRETO', 'BOA VISTA',        1),
(@SP, 'SAO JOSE DO RIO PRETO', 'HIGIENOPOLIS',     1),
(@SP, 'SAO JOSE DO RIO PRETO', 'CENTRO',           2),
(@SP, 'SAO JOSE DO RIO PRETO', 'ELDORADO',         2),

(@SP, 'SOROCABA', 'PARQUE CAMPOLIM',           1),
(@SP, 'SOROCABA', 'CENTRO',                    2),
(@SP, 'SOROCABA', 'JARDIM EUROPA',             2),
(@SP, 'SOROCABA', 'BOA VISTA',                 3),

(@SP, 'SAO JOSE DOS CAMPOS', 'PARQUE RESIDENCIAL AQUARIUS',   1),
(@SP, 'SAO JOSE DOS CAMPOS', 'URBANOVA',                      1),
(@SP, 'SAO JOSE DOS CAMPOS', 'CIDADE VISTA VERDE',            2),
(@SP, 'SAO JOSE DOS CAMPOS', 'JARDIM SATELITE',               2),
(@SP, 'SAO JOSE DOS CAMPOS', 'CENTRO',                        2),
(@SP, 'SAO JOSE DOS CAMPOS', 'FLORADAS DE SAO JOSE',          3),

(@SP, 'JUNDIAÍ', 'MEDEIROS',                   1),
(@SP, 'JUNDIAÍ', 'VILA DAS HORTENCIAS',        1),
(@SP, 'JUNDIAÍ', 'MORADA DAS VINHAS',          1),
(@SP, 'JUNDIAÍ', 'CENTRO',                     2),
(@SP, 'JUNDIAÍ', 'ENGORDADOURO',               2),
(@SP, 'JUNDIAÍ', 'ANHANGABAU',                 2),

(@SC, 'FLORIANÓPOLIS', 'JURERE INTERNACIONAL',          1),
(@SC, 'FLORIANÓPOLIS', 'JURERE',                        1),
(@SC, 'FLORIANÓPOLIS', 'LAGOA DA CONCEICAO',            1),
(@SC, 'FLORIANÓPOLIS', 'DANIELA',                       2),
(@SC, 'FLORIANÓPOLIS', 'CAMPECHE',                      2),
(@SC, 'FLORIANÓPOLIS', 'JOAO PAULO',                    2),
(@SC, 'FLORIANÓPOLIS', 'ITACORUBI',                     2),
(@SC, 'FLORIANÓPOLIS', 'TRINDADE',                      2),
(@SC, 'FLORIANÓPOLIS', 'AGRONOMICA',                    2),
(@SC, 'FLORIANÓPOLIS', 'COQUEIROS',                     2),
(@SC, 'FLORIANÓPOLIS', 'CENTRO',                        3),
(@SC, 'FLORIANÓPOLIS', 'INGLESES DO RIO VERMELHO',      3),
(@SC, 'FLORIANÓPOLIS', 'CANASVIEIRAS',                  3),

(@SC, 'JOINVILLE', 'AMERICA',                  1),
(@SC, 'JOINVILLE', 'COSTA E SILVA',            1),
(@SC, 'JOINVILLE', 'BOA VISTA',                2),
(@SC, 'JOINVILLE', 'FLORESTA',                 2),
(@SC, 'JOINVILLE', 'CENTRO',                   2),
(@SC, 'JOINVILLE', 'ATIRADORES',               2),
(@SC, 'JOINVILLE', 'SAGUACU',                  3),
(@SC, 'JOINVILLE', 'VILA NOVA',                3),

(@SC, 'BLUMENAU', 'VICTOR KONDER',             1),
(@SC, 'BLUMENAU', 'PONTA AGUDA',               1),
(@SC, 'BLUMENAU', 'VORSTADT',                  1),
(@SC, 'BLUMENAU', 'CENTRO',                    2),
(@SC, 'BLUMENAU', 'AGUA VERDE',                2),
(@SC, 'BLUMENAU', 'GARCIA',                    2),
(@SC, 'BLUMENAU', 'VELHA',                     3),
(@SC, 'BLUMENAU', 'BOA VISTA',                 3),

(@SC, 'BALNEÁRIO CAMBORIÚ', 'CENTRO',          1),
(@SC, 'BALNEÁRIO CAMBORIÚ', 'BARRA SUL',       1),
(@SC, 'BALNEÁRIO CAMBORIÚ', 'PIONEIROS',       2),
(@SC, 'BALNEÁRIO CAMBORIÚ', 'DAS NACOES',      2),

(@SC, 'SÃO JOSÉ', 'KOBRASOL',                  1),
(@SC, 'SÃO JOSÉ', 'REAL PARQUE',               2),
(@SC, 'SÃO JOSÉ', 'CAMPINAS',                  2),
(@SC, 'SÃO JOSÉ', 'CENTRO',                    2),
(@SC, 'SÃO JOSÉ', 'BARREIROS',                 3),

(@RS, 'PORTO ALEGRE', 'MOINHOS DE VENTO',      1),
(@RS, 'PORTO ALEGRE', 'TRES FIGUEIRAS',        1),
(@RS, 'PORTO ALEGRE', 'MONT SERRAT',           1),
(@RS, 'PORTO ALEGRE', 'AUXILIADORA',           2),
(@RS, 'PORTO ALEGRE', 'PETROPOLIS',            2),
(@RS, 'PORTO ALEGRE', 'VILA ASSUNCAO',         2),
(@RS, 'PORTO ALEGRE', 'BELA VISTA',            2),
(@RS, 'PORTO ALEGRE', 'RIO BRANCO',            2),
(@RS, 'PORTO ALEGRE', 'HIGIENOPOLIS',          2),
(@RS, 'PORTO ALEGRE', 'JARDIM BOTANICO',       2),
(@RS, 'PORTO ALEGRE', 'MENINO DEUS',           2),
(@RS, 'PORTO ALEGRE', 'CENTRO HISTORICO',      3),
(@RS, 'PORTO ALEGRE', 'TRISTEZA',              3),
(@RS, 'PORTO ALEGRE', 'IPANEMA',               3),
(@RS, 'PORTO ALEGRE', 'BOM FIM',               3),

(@RS, 'CAXIAS DO SUL', 'SAO PELEGRINO',        1),
(@RS, 'CAXIAS DO SUL', 'CENTRO HISTORICO',     1),
(@RS, 'CAXIAS DO SUL', 'NOSSA SENHORA DE LOURDES', 2),
(@RS, 'CAXIAS DO SUL', 'CENTRO',               2),
(@RS, 'CAXIAS DO SUL', 'JARDIM AMERICA',       2),
(@RS, 'CAXIAS DO SUL', 'EXPOSICAO',            2),
(@RS, 'CAXIAS DO SUL', 'BOA VISTA',            3),

(@RS, 'NOVO HAMBURGO', 'HAMBURGO VELHO',       1),
(@RS, 'NOVO HAMBURGO', 'CENTRO',               2),
(@RS, 'NOVO HAMBURGO', 'SAO JOAO',             2),
(@RS, 'NOVO HAMBURGO', 'RONDONIA',             2),
(@RS, 'NOVO HAMBURGO', 'OURO BRANCO',          3),
(@RS, 'NOVO HAMBURGO', 'IDEAL',                3),

(@RS, 'CANOAS', 'IGARA',                       1),
(@RS, 'CANOAS', 'HARMONIA',                    1),
(@RS, 'CANOAS', 'NOSSA SENHORA DAS GRACAS',    2),
(@RS, 'CANOAS', 'MARECHAL RONDON',             2),
(@RS, 'CANOAS', 'CENTRO',                      3),

(@RS, 'GRAMADO', 'CENTRO',                     1),
(@RS, 'GRAMADO', 'BAVARIA',                    1),
(@RS, 'GRAMADO', 'LOGEMANN',                   2),
(@RS, 'GRAMADO', 'CARNIEL',                    2),

(@RS, 'PELOTAS', 'CENTRO',                     2),
(@RS, 'PELOTAS', 'AREAL',                      2),
(@RS, 'PELOTAS', 'TRES VENDAS',                3),
(@RS, 'PELOTAS', 'FRAGATA',                    3),

(@RJ, 'RIO DE JANEIRO', 'LEBLON',              1),
(@RJ, 'RIO DE JANEIRO', 'IPANEMA',             1),
(@RJ, 'RIO DE JANEIRO', 'LAGOA',               1),
(@RJ, 'RIO DE JANEIRO', 'SAO CONRADO',         1),
(@RJ, 'RIO DE JANEIRO', 'GAVEA',               1),
(@RJ, 'RIO DE JANEIRO', 'JARDIM BOTANICO',     2),
(@RJ, 'RIO DE JANEIRO', 'FLAMENGO',            2),
(@RJ, 'RIO DE JANEIRO', 'BOTAFOGO',            2),
(@RJ, 'RIO DE JANEIRO', 'TIJUCA',              3),
(@RJ, 'RIO DE JANEIRO', 'CENTRO',              3),
(@RJ, 'RIO DE JANEIRO', 'BARRA DA TIJUCA',     2),

(@RJ, 'NITERÓI', 'ICARAI',                     1),
(@RJ, 'NITERÓI', 'SANTA ROSA',                 2),
(@RJ, 'NITERÓI', 'INGÁ',                       2),
(@RJ, 'NITERÓI', 'CENTRO',                     3),

(@MG, 'BELO HORIZONTE', 'SAVASSI',             1),
(@MG, 'BELO HORIZONTE', 'LOURDES',             1),
(@MG, 'BELO HORIZONTE', 'FUNCIONARIOS',        1),
(@MG, 'BELO HORIZONTE', 'ANCHIETA',            1),
(@MG, 'BELO HORIZONTE', 'BELVEDERE',           1),
(@MG, 'BELO HORIZONTE', 'MANGABEIRAS',         1),
(@MG, 'BELO HORIZONTE', 'SANTO AGOSTINHO',     2),
(@MG, 'BELO HORIZONTE', 'SERRA',               2),
(@MG, 'BELO HORIZONTE', 'BURITIS',             2),
(@MG, 'BELO HORIZONTE', 'CIDADE JARDIM',       2),
(@MG, 'BELO HORIZONTE', 'CENTRO',              3),
(@MG, 'BELO HORIZONTE', 'PAMPULHA',            3),

(@PR, 'CURITIBA', 'BATEL',                     1),
(@PR, 'CURITIBA', 'BIGORRILHO',                1),
(@PR, 'CURITIBA', 'ALTO DA GLORIA',            1),
(@PR, 'CURITIBA', 'AGUA VERDE',                2),
(@PR, 'CURITIBA', 'CENTRO CIVICO',             2),
(@PR, 'CURITIBA', 'CENTRO',                    2),
(@PR, 'CURITIBA', 'CHAMPAGNAT',                1),
(@PR, 'CURITIBA', 'JARDIM BOTANICO',           2),
(@PR, 'CURITIBA', 'MERCÊS',                    2),
(@PR, 'CURITIBA', 'SANTA FELICIDADE',          3),
(@PR, 'CURITIBA', 'BOA VISTA',                 3),

(@PR, 'LONDRINA', 'CENTRO',                    2),
(@PR, 'LONDRINA', 'JARDIM TORONTO',            1),
(@PR, 'LONDRINA', 'JARDIM SHANGRI-LA',         1),
(@PR, 'LONDRINA', 'GLEBA PALHANO',             2),
(@PR, 'LONDRINA', 'CENTRO CIVICO',             3),

(@PR, 'MARINGÁ', 'ZONA 1',                     1),
(@PR, 'MARINGÁ', 'ZONA 2',                     1),
(@PR, 'MARINGÁ', 'ZONA 3',                     2),
(@PR, 'MARINGÁ', 'ZONA 7',                     2),
(@PR, 'MARINGÁ', 'ZONA 5',                     3),

(@PR, 'FOZ DO IGUACU', 'CENTRO',               2),
(@PR, 'FOZ DO IGUACU', 'JARDIM CENTRAL',       2),
(@PR, 'FOZ DO IGUACU', 'MORUMBI',              2),
(@PR, 'FOZ DO IGUACU', 'NOBRE',                1),
(@PR, 'FOZ DO IGUACU', 'CARIMÃ',               1),

(@PR, 'CASCAVEL', 'CENTRO',                    2),
(@PR, 'CASCAVEL', 'NEVA',                      1),
(@PR, 'CASCAVEL', 'INTERLAGOS',                2),
(@PR, 'CASCAVEL', 'UNIVERSITARIO',             2),
(@PR, 'CASCAVEL', 'PERIOLO',                   2),

(@DF, 'BRASILIA', 'LAGO SUL',              1),
(@DF, 'BRASILIA', 'LAGO NORTE',            1),
(@DF, 'BRASILIA', 'PARK WAY',              1),
(@DF, 'BRASILIA', 'JARDIM BOTANICO',       1),
(@DF, 'BRASILIA', 'ASA SUL',               2),
(@DF, 'BRASILIA', 'ASA NORTE',             2),
(@DF, 'BRASILIA', 'SUDOESTE',              2),
(@DF, 'BRASILIA', 'NOROESTE',              2),
(@DF, 'BRASILIA', 'OCTOGONAL',             2),
(@DF, 'BRASILIA', 'CRUZEIRO',              3),
(@DF, 'BRASILIA', 'AGUAS CLARAS',          3),
(@DF, 'BRASILIA', 'TAGUATINGA',            3),

(@GO, 'GOIANIA', 'SETOR BUENO',            1),
(@GO, 'GOIANIA', 'SETOR OESTE',            1),
(@GO, 'GOIANIA', 'SETOR MARISTA',          1),
(@GO, 'GOIANIA', 'SETOR SUL',              2),
(@GO, 'GOIANIA', 'JARDIM AMERICA',         2),
(@GO, 'GOIANIA', 'SETOR NOVA SUICA',       2),
(@GO, 'GOIANIA', 'JARDIM GOIAS',           2),
(@GO, 'GOIANIA', 'SETOR AEROPORTO',        3),
(@GO, 'GOIANIA', 'SETOR CENTRAL',          3),
(@GO, 'GOIANIA', 'CENTRO',                 3),

(@GO, 'APARECIDA DE GOIANIA', 'JARDIM BELA VISTA',     2),
(@GO, 'APARECIDA DE GOIANIA', 'RESIDENCIAL VILLAGE',   2),
(@GO, 'APARECIDA DE GOIANIA', 'CENTRO',                3),

(@GO, 'ANAPOLIS', 'CENTRO',                2),
(@GO, 'ANAPOLIS', 'JUNDIAI',               2),
(@GO, 'ANAPOLIS', 'VILA JAIARA',           2),
(@GO, 'ANAPOLIS', 'SETOR NORTE',           3),

(@MT, 'CUIABA', 'JARDIM ACLIMACAO',        1),
(@MT, 'CUIABA', 'BOA ESPERANCA',           2),
(@MT, 'CUIABA', 'GOIABEIRAS',              2),
(@MT, 'CUIABA', 'CENTRO POLITICO ADMINISTRATIVO', 2),
(@MT, 'CUIABA', 'DUQUE DE CAXIAS',         2),
(@MT, 'CUIABA', 'CENTRO',                  3),

(@MT, 'VARZEA GRANDE', 'CENTRO',           2),
(@MT, 'VARZEA GRANDE', 'JARDIM IMPERIAL',  2),
(@MT, 'VARZEA GRANDE', 'VILA AURORA',      2),

(@MT, 'RONDONOPOLIS', 'CENTRO',            2),
(@MT, 'RONDONOPOLIS', 'JARDIM TROPICAL',   2),
(@MT, 'RONDONOPOLIS', 'RESIDENCIAL MONTE LIBANO', 2),

(@MS, 'CAMPO GRANDE', 'JARDIM DOS ESTADOS', 1),
(@MS, 'CAMPO GRANDE', 'MONTE CASTELO',      1),
(@MS, 'CAMPO GRANDE', 'CHACARA CACHOEIRA',  1),
(@MS, 'CAMPO GRANDE', 'BELA VISTA',         2),
(@MS, 'CAMPO GRANDE', 'JARDIM PAULISTA',    2),
(@MS, 'CAMPO GRANDE', 'NOVA LIMA',          2),
(@MS, 'CAMPO GRANDE', 'CENTRO',             2),

(@MS, 'DOURADOS', 'JARDIM AMERICA',         2),
(@MS, 'DOURADOS', 'CENTRO',                 2),
(@MS, 'DOURADOS', 'JARDIM UNIVERSITARIO',   2),

(@BA, 'SALVADOR', 'BARRA',                 1),
(@BA, 'SALVADOR', 'VITORIA',               1),
(@BA, 'SALVADOR', 'GRACA',                 1),
(@BA, 'SALVADOR', 'CAMPO GRANDE',          2),
(@BA, 'SALVADOR', 'ONDINA',                2),
(@BA, 'SALVADOR', 'RIO VERMELHO',          2),
(@BA, 'SALVADOR', 'PITUBA',                2),
(@BA, 'SALVADOR', 'CAMINHO DAS ARVORES',   2),
(@BA, 'SALVADOR', 'COSTA AZUL',            2),
(@BA, 'SALVADOR', 'ITAIGARA',              2),
(@BA, 'SALVADOR', 'ALPHAVILLE PARALELA',   1),
(@BA, 'SALVADOR', 'CENTRO',                3),

(@BA, 'FEIRA DE SANTANA', 'SIM',           2),
(@BA, 'FEIRA DE SANTANA', 'KALILÂNDIA',    2),
(@BA, 'FEIRA DE SANTANA', 'CENTRO',        2),
(@BA, 'FEIRA DE SANTANA', 'BRASILIA',      2),

(@BA, 'VITORIA DA CONQUISTA', 'CENTRO',          2),
(@BA, 'VITORIA DA CONQUISTA', 'JUREMA',           2),
(@BA, 'VITORIA DA CONQUISTA', 'CANDEIAS',         2),

(@CE, 'FORTALEZA', 'MEIRELES',             1),
(@CE, 'FORTALEZA', 'ALDEOTA',              1),
(@CE, 'FORTALEZA', 'COCO',                 1),
(@CE, 'FORTALEZA', 'GUARARAPES',           2),
(@CE, 'FORTALEZA', 'DIONISIO TORRES',      2),
(@CE, 'FORTALEZA', 'VARJOTA',              2),
(@CE, 'FORTALEZA', 'FATIMA',               2),
(@CE, 'FORTALEZA', 'MUCURIPE',             2),
(@CE, 'FORTALEZA', 'PRAIA DE IRACEMA',     3),
(@CE, 'FORTALEZA', 'CENTRO',               3),

(@CE, 'JUAZEIRO DO NORTE', 'CENTRO',       2),
(@CE, 'JUAZEIRO DO NORTE', 'LIMOEIRO',     2),
(@CE, 'JUAZEIRO DO NORTE', 'SALESIANOS',   2),

(@PE, 'RECIFE', 'BOA VIAGEM',              1),
(@PE, 'RECIFE', 'CASA FORTE',              1),
(@PE, 'RECIFE', 'ESPINHEIRO',              1),
(@PE, 'RECIFE', 'GRACAS',                  1),
(@PE, 'RECIFE', 'PINA',                    2),
(@PE, 'RECIFE', 'TORRE',                   2),
(@PE, 'RECIFE', 'MADALENA',                2),
(@PE, 'RECIFE', 'AFLITOS',                 2),
(@PE, 'RECIFE', 'PARNAMIRIM',              2),
(@PE, 'RECIFE', 'CENTRO',                  3),
(@PE, 'RECIFE', 'BOA VISTA',               3),

(@PE, 'CARUARU', 'CENTRO',                 2),
(@PE, 'CARUARU', 'MAURICIO DE NASSAU',     2),
(@PE, 'CARUARU', 'UNIVERSITARIO',          2),

(@PE, 'OLINDA', 'CARMO',                   2),
(@PE, 'OLINDA', 'CENTRO',                  2),
(@PE, 'OLINDA', 'CASA CAIADA',             2),

(@AL, 'MACEIO', 'PONTA VERDE',             1),
(@AL, 'MACEIO', 'JATIUCA',                 1),
(@AL, 'MACEIO', 'PAJUCARA',                2),
(@AL, 'MACEIO', 'PINHEIRO',                2),
(@AL, 'MACEIO', 'FAROL',                   2),
(@AL, 'MACEIO', 'MANGABEIRAS',             2),
(@AL, 'MACEIO', 'CENTRO',                  3),

(@SE, 'ARACAJU', 'JARDINS',                1),
(@SE, 'ARACAJU', '13 DE JULHO',            1),
(@SE, 'ARACAJU', 'GRAGERU',                2),
(@SE, 'ARACAJU', 'LUZIA',                  2),
(@SE, 'ARACAJU', 'ATALAIA',                2),
(@SE, 'ARACAJU', 'COROA DO MEIO',          2),
(@SE, 'ARACAJU', 'CENTRO',                 3),

(@PB, 'JOAO PESSOA', 'MANAIRA',            1),
(@PB, 'JOAO PESSOA', 'TAMBAU',             1),
(@PB, 'JOAO PESSOA', 'ALTIPLANO',          1),
(@PB, 'JOAO PESSOA', 'CABO BRANCO',        2),
(@PB, 'JOAO PESSOA', 'BESSA',              2),
(@PB, 'JOAO PESSOA', 'JARDIM OCEANIA',     2),
(@PB, 'JOAO PESSOA', 'CENTRO',             3),

(@PB, 'CAMPINA GRANDE', 'CENTRO',          2),
(@PB, 'CAMPINA GRANDE', 'CATOLÉ',          2),
(@PB, 'CAMPINA GRANDE', 'MIRAMAR',         2),
(@PB, 'CAMPINA GRANDE', 'MIRANTE',         2),

(@RN, 'NATAL', 'PETROPOLIS',               1),
(@RN, 'NATAL', 'TIROL',                    1),
(@RN, 'NATAL', 'CAPIM MACIO',              1),
(@RN, 'NATAL', 'LAGOA NOVA',               2),
(@RN, 'NATAL', 'PONTA NEGRA',              2),
(@RN, 'NATAL', 'CANDELARIA',               2),
(@RN, 'NATAL', 'CENTRO',                   3),

(@RN, 'MOSSORO', 'CENTRO',                 2),
(@RN, 'MOSSORO', 'ALTO DE SAO MANOEL',     2),
(@RN, 'MOSSORO', 'NOVA BETANIA',           2),

(@PI, 'TERESINA', 'FATIMA',                1),
(@PI, 'TERESINA', 'JOQUEI',                1),
(@PI, 'TERESINA', 'NOIVOS',                2),
(@PI, 'TERESINA', 'HORTO FLORESTAL',       2),
(@PI, 'TERESINA', 'ININGA',                2),
(@PI, 'TERESINA', 'ILHOTAS',               2),
(@PI, 'TERESINA', 'CENTRO',                3),

(@MA, 'SAO LUIS', 'RENASCENCA',            1),
(@MA, 'SAO LUIS', 'JARDIM RENASCENCA',     1),
(@MA, 'SAO LUIS', 'CALHAU',                1),
(@MA, 'SAO LUIS', 'PONTA D AREIA',         2),
(@MA, 'SAO LUIS', 'OLHO D AGUA',           2),
(@MA, 'SAO LUIS', 'SAO FRANCISCO',         2),
(@MA, 'SAO LUIS', 'CENTRO',                3),

(@MA, 'IMPERATRIZ', 'CENTRO',              2),
(@MA, 'IMPERATRIZ', 'JARDIM TROPICAL',     2),
(@MA, 'IMPERATRIZ', 'SAO FRANCISCO',       2),

(@AM, 'MANAUS', 'ADRIANOPOLIS',            1),
(@AM, 'MANAUS', 'PONTA NEGRA',             1),
(@AM, 'MANAUS', 'VIEIRALVES',              1),
(@AM, 'MANAUS', 'NOSSA SENHORA DAS GRACAS',2),
(@AM, 'MANAUS', 'CHAPADA',                 2),
(@AM, 'MANAUS', 'SAO GERALDO',             2),
(@AM, 'MANAUS', 'ALEIXO',                  2),
(@AM, 'MANAUS', 'CENTRO',                  3),

(@PA, 'BELEM', 'UMARIZAL',                 1),
(@PA, 'BELEM', 'NAZARE',                   1),
(@PA, 'BELEM', 'BATISTA CAMPOS',           2),
(@PA, 'BELEM', 'SAO BRAS',                 2),
(@PA, 'BELEM', 'MARCO',                    2),
(@PA, 'BELEM', 'CENTRO',                   3),
(@PA, 'BELEM', 'CAMPINA',                  3),

(@PA, 'ANANINDEUA', 'CENTRO',              2),
(@PA, 'ANANINDEUA', 'CIDADES NOVAS',       2),
(@PA, 'ANANINDEUA', 'ICUI-GUAJARA',        2),

(@AP, 'MACAPA', 'CENTRO',                  2),
(@AP, 'MACAPA', 'SANTA RITA',              2),
(@AP, 'MACAPA', 'BURITIZAL',               2),
(@AP, 'MACAPA', 'PACOVAL',                 3),

(@RR, 'BOA VISTA', 'CENTRO',               2),
(@RR, 'BOA VISTA', 'SAO FRANCISCO',        2),
(@RR, 'BOA VISTA', 'CAETE',                2),
(@RR, 'BOA VISTA', 'CARANA',               2),

(@RO, 'PORTO VELHO', 'OLARIA',             2),
(@RO, 'PORTO VELHO', 'CENTRO',             2),
(@RO, 'PORTO VELHO', 'AREAL',              2),
(@RO, 'PORTO VELHO', 'EMBRATEL',           2),

(@RO, 'JI-PARANA', 'CENTRO',               2),
(@RO, 'JI-PARANA', 'JARDIM AUREA',         2),

(@AC, 'RIO BRANCO', 'BOSQUE',              1),
(@AC, 'RIO BRANCO', 'CENTRO',              2),
(@AC, 'RIO BRANCO', 'ELDORADO',            2),
(@AC, 'RIO BRANCO', 'CALADINHO',           3),

(@TO, 'PALMAS', 'PLANO DIRETOR SUL',       2),
(@TO, 'PALMAS', 'PLANO DIRETOR NORTE',     2),
(@TO, 'PALMAS', 'JARDIM AURENY I',         3),
(@TO, 'PALMAS', 'CENTRO',                  2),

(@ES, 'VITORIA', 'PRAIA DO CANTO',         1),
(@ES, 'VITORIA', 'ENSEADA DO SUA',         1),
(@ES, 'VITORIA', 'SANTA LUCIA',            2),
(@ES, 'VITORIA', 'JARDIM CAMBURI',         2),
(@ES, 'VITORIA', 'BENTO FERREIRA',         2),
(@ES, 'VITORIA', 'JARDIM DA PENHA',        2),
(@ES, 'VITORIA', 'CENTRO',                 3),

(@ES, 'VILA VELHA', 'PRAIA DA COSTA',      1),
(@ES, 'VILA VELHA', 'ITAPOA',              2),
(@ES, 'VILA VELHA', 'COQUEIRAL DE ITAPARICA', 2),
(@ES, 'VILA VELHA', 'CENTRO',              3),

(@ES, 'SERRA', 'LARANJEIRAS',              2),
(@ES, 'SERRA', 'JARDIM LIMOEIRO',          2),
(@ES, 'SERRA', 'CENTRO',                   3),

(@ES, 'CARIACICA', 'CENTRO',               2),
(@ES, 'CARIACICA', 'CAMPO GRANDE',         2),
(@ES, 'CARIACICA', 'ITACIBA',              2),

(@MG, 'UBERLANDIA', 'SARAIVA',             1),
(@MG, 'UBERLANDIA', 'SANTA MONICA',        1),
(@MG, 'UBERLANDIA', 'LIDICE',              2),
(@MG, 'UBERLANDIA', 'TUBALINA',            2),
(@MG, 'UBERLANDIA', 'JARDIM BRASILIA',     2),
(@MG, 'UBERLANDIA', 'MARTINS',             2),
(@MG, 'UBERLANDIA', 'CENTRO',              2),

(@MG, 'JUIZ DE FORA', 'SAO MATEUS',        1),
(@MG, 'JUIZ DE FORA', 'CASCATINHA',        1),
(@MG, 'JUIZ DE FORA', 'ALTO DOS PASSOS',   2),
(@MG, 'JUIZ DE FORA', 'BENFICA',           2),
(@MG, 'JUIZ DE FORA', 'CENTRO',            2),

(@MG, 'CONTAGEM', 'ELDORADO',              2),
(@MG, 'CONTAGEM', 'SEDE',                  2),
(@MG, 'CONTAGEM', 'NOVO PROGRESSO',        2),
(@MG, 'CONTAGEM', 'CENTRO',                2),

(@MG, 'MONTES CLAROS', 'CENTRO',           2),
(@MG, 'MONTES CLAROS', 'TODOS OS SANTOS',  2),
(@MG, 'MONTES CLAROS', 'IBITURUNA',        1),
(@MG, 'MONTES CLAROS', 'MORADA DO PARQUE', 2),

(@MG, 'BETIM', 'CENTRO',                   2),
(@MG, 'BETIM', 'JARDIM TERESOPOLIS',       2),
(@MG, 'BETIM', 'NACIONAL',                 2),

(@SP, 'SANTOS', 'GONZAGA',                 1),
(@SP, 'SANTOS', 'BOQUEIRAO',               2),
(@SP, 'SANTOS', 'POMPEIA',                 2),
(@SP, 'SANTOS', 'EMBARÉ',                  2),
(@SP, 'SANTOS', 'CENTRO',                  3),

(@SP, 'GUARULHOS', 'CENTRO',               2),
(@SP, 'GUARULHOS', 'VILA GALVAO',          2),
(@SP, 'GUARULHOS', 'JARDIM SAO JOAO',      2),
(@SP, 'GUARULHOS', 'GOPOUVINHA',           2),

(@SP, 'SAO BERNARDO DO CAMPO', 'CENTRO',              2),
(@SP, 'SAO BERNARDO DO CAMPO', 'JARDIM DO MAR',       1),
(@SP, 'SAO BERNARDO DO CAMPO', 'NOVA PETROPOLIS',     2),
(@SP, 'SAO BERNARDO DO CAMPO', 'VILA EUCLIDES',       2),

(@SP, 'SANTO ANDRE', 'CENTRO',             2),
(@SP, 'SANTO ANDRE', 'JARDIM',             2),
(@SP, 'SANTO ANDRE', 'VILA BASTOS',        2),
(@SP, 'SANTO ANDRE', 'CAMPESTRE',          1),

(@SP, 'OSASCO', 'CENTRO',                  2),
(@SP, 'OSASCO', 'JARDIM D ABRIL',          2),
(@SP, 'OSASCO', 'VILA YARA',               2),

(@SP, 'MOGI DAS CRUZES', 'CENTRO',         2),
(@SP, 'MOGI DAS CRUZES', 'VILA OLIVEIRA',  2),
(@SP, 'MOGI DAS CRUZES', 'JARDIM ARMANDO', 2),

(@SP, 'BAURU', 'CENTRO',                   2),
(@SP, 'BAURU', 'JARDIM AMERICA',           2),
(@SP, 'BAURU', 'JARDIM BELA VISTA',        2),
(@SP, 'BAURU', 'NOVO JARDIM',              1),
(@SP, 'BAURU', 'ALTO PARAISO',             2),

(@SP, 'FRANCA', 'CENTRO',                  2),
(@SP, 'FRANCA', 'JARDIM AMERICA',          2),
(@SP, 'FRANCA', 'VILA NORTE',              2),
(@SP, 'FRANCA', 'JARDIM CONSOLACAO',       2),

(@SP, 'PRESIDENTE PRUDENTE', 'CENTRO',            2),
(@SP, 'PRESIDENTE PRUDENTE', 'JARDIM PAULISTANO', 2),
(@SP, 'PRESIDENTE PRUDENTE', 'VILA LIBERDADE',    2),

(@SP, 'SAO CARLOS', 'CENTRO',              2),
(@SP, 'SAO CARLOS', 'JARDIM CANADA',       2),
(@SP, 'SAO CARLOS', 'JARDIM LUTFALLA',     2),
(@SP, 'SAO CARLOS', 'RESIDENCIAL FIGUEIRA', 2),

(@SP, 'LIMEIRA', 'CENTRO',                 2),
(@SP, 'LIMEIRA', 'JARDIM AMERICA',         2),
(@SP, 'LIMEIRA', 'JARDIM TAQUARAL',        2),

(@SP, 'TAUBATE', 'CENTRO',                 2),
(@SP, 'TAUBATE', 'JARDIM PAULISTA',        2),
(@SP, 'TAUBATE', 'ESPLANADA',              2),

(@SP, 'AMERICANA', 'CENTRO',               2),
(@SP, 'AMERICANA', 'JARDIM BOER I',        2),
(@SP, 'AMERICANA', 'VILA MEDON',           2),

(@SP, 'ARACATUBA', 'CENTRO',               2),
(@SP, 'ARACATUBA', 'JARDIM DAS OLIVEIRAS', 2),
(@SP, 'ARACATUBA', 'JARDIM IMPERIAL',      2),

(@SP, 'MARILIA', 'CENTRO',                 2),
(@SP, 'MARILIA', 'JARDIM CALIFÓRNIA',      2),
(@SP, 'MARILIA', 'JARDIM PAULISTA',        2),

(@RJ, 'DUQUE DE CAXIAS', 'CENTRO',         2),
(@RJ, 'DUQUE DE CAXIAS', 'CENTRO HISTORICO', 2),
(@RJ, 'DUQUE DE CAXIAS', 'JARDIM PRIMAVERA', 2),

(@RJ, 'NOVA IGUACU', 'CENTRO',             2),
(@RJ, 'NOVA IGUACU', 'JARDIM ATLANTICO',   2),
(@RJ, 'NOVA IGUACU', 'VILA DE CAVA',       2),

(@RJ, 'CAMPOS DOS GOYTACAZES', 'CENTRO',        2),
(@RJ, 'CAMPOS DOS GOYTACAZES', 'PARQUE LEBLON', 1),
(@RJ, 'CAMPOS DOS GOYTACAZES', 'PELINCA',       2),

(@RJ, 'PETROPOLIS', 'CENTRO',              2),
(@RJ, 'PETROPOLIS', 'RETIRO',              2),
(@RJ, 'PETROPOLIS', 'QUITANDINHA',         1),
(@RJ, 'PETROPOLIS', 'ITAIPAVA',            1),

(@RJ, 'VOLTA REDONDA', 'ATERRADO',         2),
(@RJ, 'VOLTA REDONDA', 'CENTRO',           2),
(@RJ, 'VOLTA REDONDA', 'JARDIM NORMANDIA', 2),

(@RJ, 'MACAE', 'CENTRO',                   2),
(@RJ, 'MACAE', 'CAVALEIROS',               2),
(@RJ, 'MACAE', 'IMBETIBA',                 2),

(@RJ, 'SAO GONCALO', 'CENTRO',             2),
(@RJ, 'SAO GONCALO', 'COLUBANDE',          2),
(@RJ, 'SAO GONCALO', 'MUTONDO',            2),
(@RJ, 'SAO GONCALO', 'JARDIM CATARINA',    2),

(@RJ, 'CABO FRIO', 'CENTRO',               2),
(@RJ, 'CABO FRIO', 'BRAGA',                2),
(@RJ, 'CABO FRIO', 'PORTINHO',             1),
(@RJ, 'CABO FRIO', 'JARDIM EXCELSIOR',     2),

(@RJ, 'NOVA FRIBURGO', 'CENTRO',           2),
(@RJ, 'NOVA FRIBURGO', 'CONSELHEIRO PAULINO', 2),
(@RJ, 'NOVA FRIBURGO', 'TIJUCA',           2),
(@RJ, 'NOVA FRIBURGO', 'CORREIAS',         1),

(@RJ, 'ANGRA DOS REIS', 'CENTRO',          2),
(@RJ, 'ANGRA DOS REIS', 'FRADE',           1),
(@RJ, 'ANGRA DOS REIS', 'PRAIA GRANDE',    2),
(@RJ, 'ANGRA DOS REIS', 'BRACUHY',         1),

(@RJ, 'TERESOPOLIS', 'CENTRO',             2),
(@RJ, 'TERESOPOLIS', 'VARZEA',             2),
(@RJ, 'TERESOPOLIS', 'JARDIM CASCATA',     1),
(@RJ, 'TERESOPOLIS', 'BOM RETIRO',         2),

(@RJ, 'BARRA MANSA', 'CENTRO',             2),
(@RJ, 'BARRA MANSA', 'SANTA CLARA',        2),
(@RJ, 'BARRA MANSA', 'ANO BOM',            2),

(@RJ, 'RESENDE', 'CENTRO',                 2),
(@RJ, 'RESENDE', 'JARDIM TROPICAL',        2),
(@RJ, 'RESENDE', 'MORADA DA COLINA',       1),

(@PR, 'PONTA GROSSA', 'CENTRO',            2),
(@PR, 'PONTA GROSSA', 'JARDIM CARVALHO',   2),
(@PR, 'PONTA GROSSA', 'ESTRELA',           2),
(@PR, 'PONTA GROSSA', 'UVARANAS',          2),
(@PR, 'PONTA GROSSA', 'OFICINAS',          3),

(@PR, 'SAO JOSE DOS PINHAIS', 'CENTRO',           2),
(@PR, 'SAO JOSE DOS PINHAIS', 'JARDIM PARANAENSE',2),
(@PR, 'SAO JOSE DOS PINHAIS', 'COSTEIRA',         2),
(@PR, 'SAO JOSE DOS PINHAIS', 'AFONSO PENA',      1),

(@PR, 'GUARAPUAVA', 'CENTRO',              2),
(@PR, 'GUARAPUAVA', 'PRIMAVERA',           2),
(@PR, 'GUARAPUAVA', 'BATEL',               2),
(@PR, 'GUARAPUAVA', 'TRIANON',             2),

(@PR, 'PARANAGUA', 'CENTRO',               2),
(@PR, 'PARANAGUA', 'JARDIM SAMAMBAIA',     2),
(@PR, 'PARANAGUA', 'ROCIO',                2),

(@PR, 'TOLEDO', 'CENTRO',                  2),
(@PR, 'TOLEDO', 'JARDIM PORTO ALEGRE',     2),
(@PR, 'TOLEDO', 'JARDIM LA SALLE',         2),

(@PR, 'PATO BRANCO', 'CENTRO',             2),
(@PR, 'PATO BRANCO', 'LA SALLE',           2),
(@PR, 'PATO BRANCO', 'FRARON',             2),

(@PR, 'UMUARAMA', 'CENTRO',                2),
(@PR, 'UMUARAMA', 'JARDIM AMERICA',        2),
(@PR, 'UMUARAMA', 'ZONA I',                2),

(@PR, 'CAMPO MOURAO', 'CENTRO',            2),
(@PR, 'CAMPO MOURAO', 'JARDIM OLIMPICO',   2),
(@PR, 'CAMPO MOURAO', 'JARDIM ALPES',      2),

(@PR, 'FRANCISCO BELTRAO', 'CENTRO',       2),
(@PR, 'FRANCISCO BELTRAO', 'PRESIDENTE',   2),
(@PR, 'FRANCISCO BELTRAO', 'ALVORADA',     2),

(@RS, 'SANTA MARIA', 'CENTRO',             2),
(@RS, 'SANTA MARIA', 'NOSSA SENHORA DO ROSARIO', 2),
(@RS, 'SANTA MARIA', 'PATRONATO',          2),
(@RS, 'SANTA MARIA', 'CAMOBI',             2),
(@RS, 'SANTA MARIA', 'URLÂNDIA',           2),

(@RS, 'PASSO FUNDO', 'CENTRO',             2),
(@RS, 'PASSO FUNDO', 'LUCAS ARAUJO',       1),
(@RS, 'PASSO FUNDO', 'BOQUEIRAO',          2),
(@RS, 'PASSO FUNDO', 'JARDIM AMERICA',     2),
(@RS, 'PASSO FUNDO', 'VERA CRUZ',          2),

(@RS, 'SAO LEOPOLDO', 'CENTRO',            2),
(@RS, 'SAO LEOPOLDO', 'JARDIM AMERICA',    2),
(@RS, 'SAO LEOPOLDO', 'VICENTINA',         2),
(@RS, 'SAO LEOPOLDO', 'FIAO',              2),

(@RS, 'GRAVATAI', 'CENTRO',                2),
(@RS, 'GRAVATAI', 'MORADA DO VALE',        2),
(@RS, 'GRAVATAI', 'SANTA FE',              2),

(@RS, 'RIO GRANDE', 'CENTRO',              2),
(@RS, 'RIO GRANDE', 'CASSINO',             2),
(@RS, 'RIO GRANDE', 'GETÚLIO VARGAS',      2),

(@RS, 'BENTO GONCALVES', 'CENTRO',         2),
(@RS, 'BENTO GONCALVES', 'SAO ROQUE',      1),
(@RS, 'BENTO GONCALVES', 'CIDADE ALTA',    2),
(@RS, 'BENTO GONCALVES', 'MEDIANEIRA',     2),

(@RS, 'URUGUAIANA', 'CENTRO',              2),
(@RS, 'URUGUAIANA', 'JARDIM MEDIANEIRA',   2),
(@RS, 'URUGUAIANA', 'COPAS VERDES',        2),

(@MG, 'UBERABA', 'CENTRO',                 2),
(@MG, 'UBERABA', 'NOVA UBERABA',           1),
(@MG, 'UBERABA', 'ABADIA',                 2),
(@MG, 'UBERABA', 'SAO BENEDITO',           2),
(@MG, 'UBERABA', 'MERCÊS',                 2),

(@MG, 'GOVERNADOR VALADARES', 'CENTRO',             2),
(@MG, 'GOVERNADOR VALADARES', 'SANTA HELENA',       2),
(@MG, 'GOVERNADOR VALADARES', 'JARDIM AMERICA',     2),
(@MG, 'GOVERNADOR VALADARES', 'ESPLANADINHA',       2),

(@MG, 'DIVINOPOLIS', 'CENTRO',             2),
(@MG, 'DIVINOPOLIS', 'ESPLANADA',          2),
(@MG, 'DIVINOPOLIS', 'BOM PASTOR',         2),
(@MG, 'DIVINOPOLIS', 'JARDINOPOLIS',       2),

(@MG, 'IPATINGA', 'HORTO',                 1),
(@MG, 'IPATINGA', 'CARIRU',                2),
(@MG, 'IPATINGA', 'CENTRO',                2),
(@MG, 'IPATINGA', 'BELA VISTA',            2),

(@MG, 'SETE LAGOAS', 'CENTRO',             2),
(@MG, 'SETE LAGOAS', 'ELDORADO',           2),
(@MG, 'SETE LAGOAS', 'SANTOS DUMONT',      2),
(@MG, 'SETE LAGOAS', 'VILA ROMANA',        2),

(@MG, 'POCOS DE CALDAS', 'CENTRO',         2),
(@MG, 'POCOS DE CALDAS', 'MORRO DO ENGENHO', 1),
(@MG, 'POCOS DE CALDAS', 'JARDIM QUISISANA', 2),
(@MG, 'POCOS DE CALDAS', 'JARDIM NOVA CALDAS', 2),

(@MG, 'VARGINHA', 'CENTRO',                2),
(@MG, 'VARGINHA', 'JARDIM ANDERE',         1),
(@MG, 'VARGINHA', 'PRAINHA',               2),
(@MG, 'VARGINHA', 'JARDIM MONTE OLIMPO',   2),

(@MG, 'POUSO ALEGRE', 'CENTRO',            2),
(@MG, 'POUSO ALEGRE', 'JARDIM VIRGINIA',   2),
(@MG, 'POUSO ALEGRE', 'BELA VISTA',        2),

(@MG, 'BARBACENA', 'CENTRO',               2),
(@MG, 'BARBACENA', 'JARDIM ALVORADA',      2),
(@MG, 'BARBACENA', 'LINS DE VASCONCELOS',  2),

(@MG, 'PATOS DE MINAS', 'CENTRO',          2),
(@MG, 'PATOS DE MINAS', 'JARDIM ELDORADO', 2),
(@MG, 'PATOS DE MINAS', 'BONITO',          2),

(@SC, 'ITAJAI', 'CENTRO',                  2),
(@SC, 'ITAJAI', 'FAZENDA',                 2),
(@SC, 'ITAJAI', 'CORDEIROS',               2),
(@SC, 'ITAJAI', 'SAO JOAO',                2),
(@SC, 'ITAJAI', 'JARDIM ESPERANCA',        2),

(@SC, 'CHAPECO', 'CENTRO',                 2),
(@SC, 'CHAPECO', 'JARDIM AMERICA',         2),
(@SC, 'CHAPECO', 'SAO CRISTOVAO',          2),
(@SC, 'CHAPECO', 'JARDIM ITALIA',          2),

(@SC, 'CRICIUMA', 'CENTRO',                2),
(@SC, 'CRICIUMA', 'SANTA AUGUSTA',         2),
(@SC, 'CRICIUMA', 'UNIVERSITARIO',         2),
(@SC, 'CRICIUMA', 'COMERCIARIO',           2),

(@SC, 'LAGES', 'CENTRO',                   2),
(@SC, 'LAGES', 'CORAL',                    2),
(@SC, 'LAGES', 'COPACABANA',               2),
(@SC, 'LAGES', 'SAO LUIZ',                 2),

(@SC, 'JARAGUA DO SUL', 'CENTRO',          2),
(@SC, 'JARAGUA DO SUL', 'AMIZADE',         2),
(@SC, 'JARAGUA DO SUL', 'NEREU RAMOS',     2),

(@SC, 'PALHOCA', 'CENTRO',                 2),
(@SC, 'PALHOCA', 'CAMINHO NOVO',           2),
(@SC, 'PALHOCA', 'SANTA CATARINA',         2),

(@SC, 'BRUSQUE', 'CENTRO',                 2),
(@SC, 'BRUSQUE', 'AZAMBUJA',               2),
(@SC, 'BRUSQUE', 'LIMEIRA',                2),

(@SC, 'TUBARAO', 'CENTRO',                 2),
(@SC, 'TUBARAO', 'HUMAITÁ',               2),
(@SC, 'TUBARAO', 'DEHON',                  2),

(@CE, 'CAUCAIA', 'CENTRO',                 2),
(@CE, 'CAUCAIA', 'JUREMA',                 2),
(@CE, 'CAUCAIA', 'PARQUE SOLON DE LUCENA', 2),

(@CE, 'SOBRAL', 'CENTRO',                  2),
(@CE, 'SOBRAL', 'SUMARÉ',                  2),
(@CE, 'SOBRAL', 'TERRENOS NOVOS',          2),
(@CE, 'SOBRAL', 'DOM EXPEDITO',            2),

(@CE, 'MARACANAU', 'CENTRO',               2),
(@CE, 'MARACANAU', 'MONDUBIM',             2),
(@CE, 'MARACANAU', 'ACARAPE',              2),

(@CE, 'CRATO', 'CENTRO',                   2),
(@CE, 'CRATO', 'MONTE CASTELO',            2),
(@CE, 'CRATO', 'SAO MIGUEL',               2),

(@BA, 'LAURO DE FREITAS', 'BURAQUINHO',           1),
(@BA, 'LAURO DE FREITAS', 'VILLAS DO ATLANTICO',  1),
(@BA, 'LAURO DE FREITAS', 'ARPOADOR',             2),
(@BA, 'LAURO DE FREITAS', 'CENTRO',               2),

(@BA, 'CAMACARI', 'CENTRO',                2),
(@BA, 'CAMACARI', 'JARDIM LIMOEIRO',       2),
(@BA, 'CAMACARI', 'ABRANTES',              2),

(@BA, 'ILHEUS', 'CENTRO',                  2),
(@BA, 'ILHEUS', 'MALHADO',                 2),
(@BA, 'ILHEUS', 'JOSE MENINO',             2),
(@BA, 'ILHEUS', 'JARDIM SAVOIA',           1),

(@BA, 'BARREIRAS', 'CENTRO',               2),
(@BA, 'BARREIRAS', 'MORADA NOBRE',         1),
(@BA, 'BARREIRAS', 'SIM',                  2),

(@BA, 'ITABUNA', 'CENTRO',                 2),
(@BA, 'ITABUNA', 'JESSICA',                2),
(@BA, 'ITABUNA', 'BANCO DA VITORIA',       2),

(@PE, 'JABOATAO DOS GUARARAPES', 'CANDEIAS',         1),
(@PE, 'JABOATAO DOS GUARARAPES', 'PIEDADE',          2),
(@PE, 'JABOATAO DOS GUARARAPES', 'CAVALEIRO',        2),
(@PE, 'JABOATAO DOS GUARARAPES', 'PRAZERES',         2),
(@PE, 'JABOATAO DOS GUARARAPES', 'MURIBECA',         2),

(@PE, 'PAULISTA', 'CENTRO',                2),
(@PE, 'PAULISTA', 'PARATIBE',              2),
(@PE, 'PAULISTA', 'JANGA',                 2),

(@PE, 'PETROLINA', 'CENTRO',               2),
(@PE, 'PETROLINA', 'JARDIM PRIMAVERA',     2),
(@PE, 'PETROLINA', 'BAIRRO UNIVERSITARIO', 2),
(@PE, 'PETROLINA', 'COND. GREENVILLE',     1),

(@PE, 'GARANHUNS', 'CENTRO',               2),
(@PE, 'GARANHUNS', 'HELIODORO BALTAR',     2),
(@PE, 'GARANHUNS', 'MAGALHAES',            2),

(@RN, 'PARNAMIRIM', 'CENTRO',              2),
(@RN, 'PARNAMIRIM', 'NOVA PARNAMIRIM',     1),
(@RN, 'PARNAMIRIM', 'EMAUS',               2),
(@RN, 'PARNAMIRIM', 'PARQUE DAS DUNAS',    2),

(@SE, 'NOSSA SENHORA DO SOCORRO', 'CENTRO',              2),
(@SE, 'NOSSA SENHORA DO SOCORRO', 'CONJUNTO AUGUSTO FRANCO', 2),
(@SE, 'NOSSA SENHORA DO SOCORRO', 'RESIDENCIAL MANAIRA',  2),

(@PI, 'PARNAIBA', 'CENTRO',                2),
(@PI, 'PARNAIBA', 'SAO JOSE',              2),
(@PI, 'PARNAIBA', 'SANTA HELENA',          2),
(@PI, 'PARNAIBA', 'BEIRA RIO',             2),

(@MT, 'SINOP', 'CENTRO',                   2),
(@MT, 'SINOP', 'JARDIM DOS IPES',          1),
(@MT, 'SINOP', 'JARDIM BOTÂNICO',          2),
(@MT, 'SINOP', 'JARDIM UBIRAJARA',         2),

(@MT, 'TANGARA DA SERRA', 'CENTRO',        2),
(@MT, 'TANGARA DA SERRA', 'JARDIM ELDORADO', 2),
(@MT, 'TANGARA DA SERRA', 'JARDIM AMERICA', 2),

(@MT, 'SORRISO', 'CENTRO',                 2),
(@MT, 'SORRISO', 'JARDIM SAO LUCAS',       2),
(@MT, 'SORRISO', 'JARDIM PANORAMA',        2),

(@GO, 'RIO VERDE', 'CENTRO',               2),
(@GO, 'RIO VERDE', 'JARDIM GOIAS',         1),
(@GO, 'RIO VERDE', 'VILA LEMES',           2),
(@GO, 'RIO VERDE', 'BELA VISTA',           2),

(@GO, 'JATAI', 'CENTRO',                   2),
(@GO, 'JATAI', 'JARDIM AMERICA',           2),
(@GO, 'JATAI', 'SETOR AEROPORTO',          2),

(@MS, 'TRES LAGOAS', 'CENTRO',             2),
(@MS, 'TRES LAGOAS', 'JARDIM ALVORADA',    2),
(@MS, 'TRES LAGOAS', 'SAO BENTO',          2),

(@MS, 'CORUMBA', 'CENTRO',                 2),
(@MS, 'CORUMBA', 'GUATÔ',                  2),
(@MS, 'CORUMBA', 'POPULAR',                2),

(@MS, 'PONTA PORA', 'CENTRO',              2),
(@MS, 'PONTA PORA', 'AERO RANCHO',         2),
(@MS, 'PONTA PORA', 'JARDIM OASIS',        2),

(@RO, 'ARIQUEMES', 'CENTRO',               2),
(@RO, 'ARIQUEMES', 'SETOR INSTITUCIONAL',  2),
(@RO, 'ARIQUEMES', 'LAGOA AZUL',           2),

(@RO, 'CACOAL', 'CENTRO',                  2),
(@RO, 'CACOAL', 'JARDIM CLODOALDO',        2),
(@RO, 'CACOAL', 'JARDIM AUREA',            2),

(@RO, 'VILHENA', 'CENTRO',                 2),
(@RO, 'VILHENA', 'JARDIM ELDORADO',        2),
(@RO, 'VILHENA', 'JARDIM AMERICA',         2),

(@PA, 'SANTAREM', 'CENTRO',                2),
(@PA, 'SANTAREM', 'ALDEIA',                2),
(@PA, 'SANTAREM', 'CARANAZAL',             2),
(@PA, 'SANTAREM', 'LIBERDADE',             2),

(@PA, 'MARABA', 'CENTRO',                  2),
(@PA, 'MARABA', 'NOVA MARABÁ',             2),
(@PA, 'MARABA', 'CIDADE NOVA',             2),

(@PA, 'CASTANHAL', 'CENTRO',               2),
(@PA, 'CASTANHAL', 'JARDIM PROGRESSO',     2),
(@PA, 'CASTANHAL', 'SAO JOSE',             2),

(@AM, 'PARINTINS', 'CENTRO',               2),
(@AM, 'PARINTINS', 'PALMARES',             2),

(@SP, 'INDAIATUBA', 'CENTRO',              2),
(@SP, 'INDAIATUBA', 'PARQUE RESIDENCIAL ESPLANADA', 2),
(@SP, 'INDAIATUBA', 'JARDIM MORADA DO SOL',         2),
(@SP, 'INDAIATUBA', 'CIDADE NOVA',         2),

(@SP, 'BOTUCATU', 'CENTRO',                2),
(@SP, 'BOTUCATU', 'RUBIAO JUNIOR',         2),
(@SP, 'BOTUCATU', 'JARDIM PEREIRA DO CAMPO', 2),

(@SP, 'ARARAQUARA', 'CENTRO',              2),
(@SP, 'ARARAQUARA', 'JARDIM SUMARE',       2),
(@SP, 'ARARAQUARA', 'JARDIM NOVA ARARAQUARA', 2),

(@SP, 'CATANDUVA', 'CENTRO',               2),
(@SP, 'CATANDUVA', 'JARDIM AMERICA',       2),
(@SP, 'CATANDUVA', 'VILA SANTA THEREZINHA', 2),

(@PR, 'CURITIBA', 'BATEL',                 1),
(@PR, 'CURITIBA', 'BIGORRILHO',            1),
(@PR, 'CURITIBA', 'JUVEVE',                1),
(@PR, 'CURITIBA', 'HUGO LANGE',            2),
(@PR, 'CURITIBA', 'AHU',                   2),
(@PR, 'CURITIBA', 'ECOVILLE',              2),
(@PR, 'CURITIBA', 'MOSSUNGUE',             2),
(@PR, 'CURITIBA', 'CAMPINA DO SIQUEIRA',   3),
(@PR, 'CURITIBA', 'SEMINARIO',             3),

(@PR, 'LONDRINA', 'GLEBA PALHANO',         1),
(@PR, 'LONDRINA', 'BELA SUICA',            1),
(@PR, 'LONDRINA', 'CAMBRIDGE',             3),

(@PR, 'MARINGÁ', 'JARDIM ALVORADA',        2),
(@PR, 'MARINGÁ', 'JARDIM PARIS',           2),

(@RS, 'PORTO ALEGRE', 'TRES FIGUEIRAS',    1),
(@RS, 'PORTO ALEGRE', 'BELA VISTA',        1),
(@RS, 'PORTO ALEGRE', 'MOINHOS DE VENTO',  1),
(@RS, 'PORTO ALEGRE', 'MONTSERRAT',        2),
(@RS, 'PORTO ALEGRE', 'JARDIM EUROPA',     2),
(@RS, 'PORTO ALEGRE', 'RIO BRANCO',        2),
(@RS, 'PORTO ALEGRE', 'PETROPOLIS',        2),
(@RS, 'PORTO ALEGRE', 'INDEPENDENCIA',     3),
(@RS, 'PORTO ALEGRE', 'BOA VISTA',         3),

(@RS, 'CAXIAS DO SUL', 'EXPOSICAO',        1),
(@RS, 'CAXIAS DO SUL', 'CENTRO',           1),
(@RS, 'CAXIAS DO SUL', 'SAO PELEGRINO',    2),
(@RS, 'CAXIAS DO SUL', 'NOSSA SENHORA DE FATIMA', 2),
(@RS, 'CAXIAS DO SUL', 'MARECHAL FLORIANO', 3),

(@SC, 'FLORIANÓPOLIS', 'JURERE INTERNACIONAL', 1),
(@SC, 'FLORIANÓPOLIS', 'AGRONOMICA',       1),
(@SC, 'FLORIANÓPOLIS', 'JOAO PAULO',       2),
(@SC, 'FLORIANÓPOLIS', 'CORREGO GRANDE',   2),
(@SC, 'FLORIANÓPOLIS', 'CENTRO',           2),

(@SC, 'JOINVILLE', 'ATIRADORES',           1),
(@SC, 'JOINVILLE', 'AMERICA',              1),
(@SC, 'JOINVILLE', 'COSTA E SILVA',        2),
(@SC, 'JOINVILLE', 'GLORIA',               2),
(@SC, 'JOINVILLE', 'BUCAREIN',             3),

(@SC, 'BLUMENAU', 'VELHA',                 1),
(@SC, 'BLUMENAU', 'PONTA AGUDA',           1),
(@SC, 'BLUMENAU', 'VICTOR KONDER',         2),
(@SC, 'BLUMENAU', 'AGUA VERDE',            2),
(@SC, 'BLUMENAU', 'ITOUPAVA SECA',         3),

(@MG, 'BELO HORIZONTE', 'LOURDES',         1),
(@MG, 'BELO HORIZONTE', 'SAVASSI',         1),
(@MG, 'BELO HORIZONTE', 'BELVEDERE',       1),
(@MG, 'BELO HORIZONTE', 'CIDADE JARDIM',   2),
(@MG, 'BELO HORIZONTE', 'SAO PEDRO',       2),
(@MG, 'BELO HORIZONTE', 'SION',            2),
(@MG, 'BELO HORIZONTE', 'CRUZEIRO',        3),
(@MG, 'BELO HORIZONTE', 'MANGABEIRAS',     3),

(@ES, 'VITORIA', 'ILHA DO BOI',            1),

(@ES, 'VILA VELHA', 'ITAPOA',              1),
(@ES, 'VILA VELHA', 'INTERLAGOS',          2),
(@ES, 'VILA VELHA', 'PRAIA DAS GAIVOTAS',  3),

(@GO, 'GOIANIA', 'JARDIM GOIAS',           1),
(@GO, 'GOIANIA', 'SETOR MARISTA',          1),
(@GO, 'GOIANIA', 'SETOR JAO',              3),

(@MT, 'CUIABA', 'TERRA NOVA',              2),
(@MT, 'CUIABA', 'ARAES',                   3),

(@MS, 'CAMPO GRANDE', 'CARANDA BOSQUE',    3),

(@AM, 'MANAUS', 'DOM PEDRO I',             2),
(@AM, 'MANAUS', 'PARQUE 10 DE NOVEMBRO',   3),

(@PA, 'BELEM', 'BATISTA CAMPOS',           1),
(@PA, 'BELEM', 'REDUTO',                   3),

(@CE, 'FORTALEZA', 'ENGENHEIRO LUCIANO CAVALCANTE', 2),

(@PE, 'RECIFE', 'ROSARINHO',               3),

(@BA, 'SALVADOR', 'CORREDOR DA VITORIA',   1),
(@BA, 'SALVADOR', 'HORTO FLORESTAL',       2),
(@BA, 'SALVADOR', 'ALPHAVILLE SALVADOR',   1),

(@AL, 'MACEIO', 'JACARECICA',              1),
(@AL, 'MACEIO', 'PAJUCARA',                1),
(@AL, 'MACEIO', 'CRUZ DAS ALMAS',          2),

(@RN, 'NATAL', 'NEOPOLIS',                 3),

(@RN, 'PARNAMIRIM', 'NOVA PARNAMIRIM',     1),

(@PB, 'JOAO PESSOA', 'ALTIPLANO',          1),
(@PB, 'JOAO PESSOA', 'JARDIM OCEANIA',     1),
(@PB, 'JOAO PESSOA', 'MANAIRA',            2),
(@PB, 'JOAO PESSOA', 'BESSA',              3),

(@PI, 'TERESINA', 'SAO CRISTOVAO',         2),
(@PI, 'TERESINA', 'MORADA DO SOL',         3),

(@MA, 'SAO LUIS', 'PONTA D AREIA',         1),
(@MA, 'SAO LUIS', 'COHAMA',                3)

ON DUPLICATE KEY UPDATE ranking = VALUES(ranking);

INSERT INTO bairros_alta_renda (uf_id, cidade, bairro, ranking) VALUES

(@SP, 'BARUERI', 'ALPHAVILLE',                        1),
(@SP, 'BARUERI', 'TAMBORE',                           1),
(@SP, 'BARUERI', 'JARDIM CALIFORNIA',                 2),
(@SP, 'BARUERI', 'PORTO SEGURO',                      2),

(@SP, 'SANTANA DE PARNAÍBA', 'ALPHAVILLE',            1),
(@SP, 'SANTANA DE PARNAÍBA', 'TAMBORE',               1),
(@SP, 'SANTANA DE PARNAÍBA', 'CAXAMBU',               2),
(@SP, 'SANTANA DE PARNAÍBA', 'CHACARA SANTA LETICIA', 2),

(@SP, 'COTIA', 'GRANJA VIANA',                        1),
(@SP, 'COTIA', 'JARDIM SAO JOAQUIM',                  2),
(@SP, 'COTIA', 'CHACARA ONDAS VERDES',                2),

(@SP, 'JACAREÍ', 'JARDIM SANTA ROSA',                 2),
(@SP, 'JACAREÍ', 'JARDIM CALIFORNIA',                 2),
(@SP, 'JACAREÍ', 'RESIDENCIAL FLAMBOYANT',            2),
(@SP, 'JACAREÍ', 'JARDIM DAS INDUSTRIAS',             3),

(@AL, 'ARAPIRACA', 'CENTRO',                          3),
(@AL, 'ARAPIRACA', 'JARDIM ESPERANCA',                2),
(@AL, 'ARAPIRACA', 'BRASILIA',                        2),
(@AL, 'ARAPIRACA', 'SANTA ANGELA',                    2),
(@AL, 'ARAPIRACA', 'XINGU',                           3),

(@ES, 'CACHOEIRO DE ITAPEMIRIM', 'AEROPORTO',         2),
(@ES, 'CACHOEIRO DE ITAPEMIRIM', 'PARAISO',           2),
(@ES, 'CACHOEIRO DE ITAPEMIRIM', 'MONTE BELO',        2),
(@ES, 'CACHOEIRO DE ITAPEMIRIM', 'CENTRO',            3),
(@ES, 'CACHOEIRO DE ITAPEMIRIM', 'JARDIM ITAPOAMA',   3),

(@ES, 'LINHARES', 'NOVA LINHARES',                    2),
(@ES, 'LINHARES', 'JARDIM LAGOA NOVA',                2),
(@ES, 'LINHARES', 'AVISO',                            2),
(@ES, 'LINHARES', 'CENTRO',                           3),

(@BA, 'PORTO SEGURO', 'ARRAIAL D AJUDA',              1),
(@BA, 'PORTO SEGURO', 'TAPERAPUAN',                   2),
(@BA, 'PORTO SEGURO', 'VALE DOS PASSAROS',            2),
(@BA, 'PORTO SEGURO', 'CENTRO',                       3),

(@BA, 'TEIXEIRA DE FREITAS', 'MARCO ZERO',            2),
(@BA, 'TEIXEIRA DE FREITAS', 'JARDIM ATLANTICO',      2),
(@BA, 'TEIXEIRA DE FREITAS', 'CENTRO',                3),
(@BA, 'TEIXEIRA DE FREITAS', 'NOVO HORIZONTE',        3),

(@RS, 'BAGÉ', 'MALAFAIA',                             2),
(@RS, 'BAGÉ', 'JARDIM',                               2),
(@RS, 'BAGÉ', 'TUPI',                                 2),
(@RS, 'BAGÉ', 'CENTRO',                               3),

(@RS, 'SANTA CRUZ DO SUL', 'BELA VISTA',              2),
(@RS, 'SANTA CRUZ DO SUL', 'HIGIENOPOLIS',            2),
(@RS, 'SANTA CRUZ DO SUL', 'KROEFF',                  2),
(@RS, 'SANTA CRUZ DO SUL', 'CENTRO',                  3),

(@GO, 'CATALÃO', 'JARDIM GRECIA',                     2),
(@GO, 'CATALÃO', 'MONTE CASTELO',                     2),
(@GO, 'CATALÃO', 'JARDIM PRESIDENTE',                 2),
(@GO, 'CATALÃO', 'CENTRO',                            3)

ON DUPLICATE KEY UPDATE ranking = VALUES(ranking);

INSERT INTO bairros_alta_renda (uf_id, cidade, bairro, ranking) VALUES

(@ES, 'COLATINA', 'ESPLANADA',                        2),
(@ES, 'COLATINA', 'CENTRO NOVO',                      2),
(@ES, 'COLATINA', 'CENTRO',                           3),

(@ES, 'SÃO MATEUS', 'SERNAMBY',                       2),
(@ES, 'SÃO MATEUS', 'ITAUANA',                        2),
(@ES, 'SÃO MATEUS', 'CENTRO',                         3),

(@GO, 'LUZIÂNIA', 'JARDIM INGA',                      2),
(@GO, 'LUZIÂNIA', 'SETOR AEROPORTO',                  2),
(@GO, 'LUZIÂNIA', 'CENTRO',                           3),

(@GO, 'FORMOSA', 'JARDIM FORMOSA',                    2),
(@GO, 'FORMOSA', 'SETOR LESTE',                       2),
(@GO, 'FORMOSA', 'CENTRO',                            3),

(@GO, 'ITUMBIARA', 'COIMBRA',                         2),
(@GO, 'ITUMBIARA', 'JARDIM PRESIDENTE',               2),
(@GO, 'ITUMBIARA', 'CENTRO',                          3),

(@BA, 'ALAGOINHAS', 'CAPUCHINHOS',                    2),
(@BA, 'ALAGOINHAS', 'ADALGISA',                       2),
(@BA, 'ALAGOINHAS', 'CENTRO',                         3),

(@BA, 'JEQUIÉ', 'CALHAU',                             2),
(@BA, 'JEQUIÉ', 'JEQUIEZINHO',                        2),
(@BA, 'JEQUIÉ', 'CENTRO',                             3),

(@PE, 'CABO DE SANTO AGOSTINHO', 'PONTE DOS CARVALHOS', 3),
(@PE, 'CABO DE SANTO AGOSTINHO', 'CENTRO',            3),

(@PE, 'CAMARAGIBE', 'JARDIM PRIMAVERA',               2),
(@PE, 'CAMARAGIBE', 'CENTRO',                         3),

(@PR, 'COLOMBO', 'MARACANÃ',                          2),
(@PR, 'COLOMBO', 'JARDIM DAS GRACAS',                 2),
(@PR, 'COLOMBO', 'CENTRO',                            3),

(@PR, 'APUCARANA', 'JARDIM MAUA',                     2),
(@PR, 'APUCARANA', 'JARDIM FLAMINGOS',                2),
(@PR, 'APUCARANA', 'NOVO JARDIM',                     2),
(@PR, 'APUCARANA', 'CENTRO',                          3),

(@RS, 'CACHOEIRINHA', 'MORADA DO VALE',               2),
(@RS, 'CACHOEIRINHA', 'PARQUE ELDORADO',              2),
(@RS, 'CACHOEIRINHA', 'CENTRO',                       3),

(@RS, 'ERECHIM', 'BELA VISTA',                        2),
(@RS, 'ERECHIM', 'PRESIDENTE VARGAS',                 2),
(@RS, 'ERECHIM', 'CENTRO',                            3),

(@RS, 'LAJEADO', 'MOINHOS',                           2),
(@RS, 'LAJEADO', 'CONVENTOS',                         2),
(@RS, 'LAJEADO', 'CENTRO',                            3),

(@MG, 'ARAGUARI', 'JARDIM EUROPA',                    2),
(@MG, 'ARAGUARI', 'SAO JOSE',                         2),
(@MG, 'ARAGUARI', 'CENTRO',                           3),

(@MT, 'CÁCERES', 'JARDIM VITORIA',                    2),
(@MT, 'CÁCERES', 'CENTRO',                            3)

ON DUPLICATE KEY UPDATE ranking = VALUES(ranking);

INSERT INTO bairros_alta_renda (uf_id, cidade, bairro, ranking) VALUES

(@SP, 'SANTOS', 'PONTA DA PRAIA',             1),
(@SP, 'SANTOS', 'JOSE MENINO',                2),
(@SP, 'SANTOS', 'APARECIDA',                  2),
(@SP, 'SANTOS', 'MACUCO',                     3),

(@SP, 'SANTO ANDRE', 'VILA ASSUNCAO',         1),
(@SP, 'SANTO ANDRE', 'BARCELONA',             2),

(@SP, 'SAO BERNARDO DO CAMPO', 'CERAMICA',        2),
(@SP, 'SAO BERNARDO DO CAMPO', 'BARCELONA',       2),
(@SP, 'SAO BERNARDO DO CAMPO', 'JARDIM BOTANICO', 2),

(@SP, 'TAUBATE', 'JARDIM DAS NACOES',         1),
(@SP, 'TAUBATE', 'INDEPENDENCIA',             2),

(@SP, 'MARILIA', 'JARDIM ESTORIL',            1),
(@SP, 'MARILIA', 'FRAGATA',                   2),

(@SP, 'ARACATUBA', 'JARDIM NOVA YORK',        1),
(@SP, 'ARACATUBA', 'IPANEMA',                 2),
(@SP, 'ARACATUBA', 'CONCORDIA',               3),

(@SP, 'SAO CARLOS', 'CIDADE JARDIM',          1),
(@SP, 'SAO CARLOS', 'PARQUE FABER',           1),
(@SP, 'SAO CARLOS', 'SANTA FELICIA',          2),

(@SP, 'BAURU', 'JARDIM ESTORIL',              1),
(@SP, 'BAURU', 'ALTOS DA CIDADE',             2),
(@SP, 'BAURU', 'JARDIM PANORAMA',             2),

(@SP, 'AMERICANA', 'JARDIM SAO PAULO',        1),
(@SP, 'AMERICANA', 'JARDIM IPIRANGA',         2),

(@SP, 'LIMEIRA', 'VILA CLAUDIA',              2),
(@SP, 'LIMEIRA', 'JARDIM NOVO MUNDO',         3),

(@SP, 'FRANCA', 'JARDIM FRANCA',              1),
(@SP, 'FRANCA', 'JARDIM AEROPORTO',           2),

(@SP, 'PRESIDENTE PRUDENTE', 'JARDIM BONGIOVANI', 1),
(@SP, 'PRESIDENTE PRUDENTE', 'JARDIM PAULISTA',   2),

(@RJ, 'PETROPOLIS', 'MOSELA',                 2),
(@RJ, 'PETROPOLIS', 'CENTRO HISTORICO',       2),

(@RJ, 'VOLTA REDONDA', 'JARDIM AMALIA',       1),
(@RJ, 'VOLTA REDONDA', 'JARDIM BELVEDERE',    1),
(@RJ, 'VOLTA REDONDA', 'JARDIM PROVENCE',     2),
(@RJ, 'VOLTA REDONDA', 'SAO LUCAS',           2),

(@RJ, 'MACAE', 'GRANJA DOS CAVALEIROS',       1),
(@RJ, 'MACAE', 'NOVO CAVALEIROS',             2),
(@RJ, 'MACAE', 'GLORIA',                      2),

(@RJ, 'CAMPOS DOS GOYTACAZES', 'FLAMBOYANT',       2),
(@RJ, 'CAMPOS DOS GOYTACAZES', 'PARQUE PECUARIA',  2),
(@RJ, 'CAMPOS DOS GOYTACAZES', 'PARQUE FUNDAO',    3),

(@RJ, 'NITERÓI', 'CHARITAS',                  1),
(@RJ, 'NITERÓI', 'BOA VIAGEM',                1),
(@RJ, 'NITERÓI', 'SAO FRANCISCO',             2),

(@MG, 'JUIZ DE FORA', 'GRANBERY',             2),
(@MG, 'JUIZ DE FORA', 'SAO PEDRO',            2),
(@MG, 'JUIZ DE FORA', 'JARDIM LARANJEIRAS',   3),

(@MG, 'MONTES CLAROS', 'MORADA DO SOL',       2),
(@MG, 'MONTES CLAROS', 'JARDIM PRIMAVERA',    2),
(@MG, 'MONTES CLAROS', 'VILA MAURICEIA',      2),

(@MG, 'GOVERNADOR VALADARES', 'ILHA DOS ARAUJOS', 1),
(@MG, 'GOVERNADOR VALADARES', 'VILA BRETAS',      2),

(@MG, 'UBERLANDIA', 'GRANJA MARILEUSA',       1),
(@MG, 'UBERLANDIA', 'MORADA DA COLINA',       2),
(@MG, 'UBERLANDIA', 'JARDIM KARAIBA',         2),

(@PR, 'LONDRINA', 'HIPICA',                   2),
(@PR, 'LONDRINA', 'VIRGINIA',                 2),

(@PR, 'MARINGÁ', 'ZONA 8',                    2),
(@PR, 'MARINGÁ', 'ZONA 4',                    2),

(@PR, 'CASCAVEL', 'COUNTRY',                  1),
(@PR, 'CASCAVEL', 'TROPICAL',                 2),
(@PR, 'CASCAVEL', 'CANCELLI',                 2),

(@PR, 'PONTA GROSSA', 'VILA ESTRELA',         1),
(@PR, 'PONTA GROSSA', 'CONTORNO',             2),

(@RS, 'PELOTAS', 'DOM JOAQUIM',               2),
(@RS, 'PELOTAS', 'LAS ACACIAS',               2),
(@RS, 'PELOTAS', 'CHARQUEADAS',               3),

(@RS, 'CANOAS', 'NITEROI',                    1),
(@RS, 'CANOAS', 'FATIMA',                     2),

(@RS, 'NOVO HAMBURGO', 'BOA VISTA',           2),
(@RS, 'NOVO HAMBURGO', 'VILA NOVA',           2),

(@RS, 'CAXIAS DO SUL', 'CAMELIAS',            1),
(@RS, 'CAXIAS DO SUL', 'BELA VISTA',          2),
(@RS, 'CAXIAS DO SUL', 'VINHEDOS',            2),

(@RS, 'PASSO FUNDO', 'PETROPOLIS',            1),
(@RS, 'PASSO FUNDO', 'VILA RODRIGUES',        1),
(@RS, 'PASSO FUNDO', 'SAO CRISTOVAO',         2),

(@RS, 'SANTA MARIA', 'NOSSA SENHORA DE LOURDES', 1),
(@RS, 'SANTA MARIA', 'SAO JOSE',              2),
(@RS, 'SANTA MARIA', 'TOMAZETTI',             2),

(@SC, 'BLUMENAU', 'JARDIM BLUMENAU',          1),
(@SC, 'BLUMENAU', 'ALAMEDA',                  2),

(@SC, 'JOINVILLE', 'SANTO ANTONIO',           2),
(@SC, 'JOINVILLE', 'ANITA GARIBALDI',         2),
(@SC, 'JOINVILLE', 'BOM RETIRO',              3),

(@SC, 'CHAPECO', 'MARIA GORETE',              1),
(@SC, 'CHAPECO', 'DESBRAVADOR',               2),
(@SC, 'CHAPECO', 'PASSO DOS FORTES',          2),

(@SC, 'LAGES', 'SAGRADO CORACAO DE JESUS',    1),
(@SC, 'LAGES', 'BELA VISTA',                  2),

(@BA, 'FEIRA DE SANTANA', 'CAPUCHINHOS',      1),
(@BA, 'FEIRA DE SANTANA', 'MANGABEIRA',       2),
(@BA, 'FEIRA DE SANTANA', 'CASEB',            2),
(@BA, 'FEIRA DE SANTANA', 'PONTO CENTRAL',    2),
(@BA, 'FEIRA DE SANTANA', 'TOMBA',            3),

(@BA, 'VITORIA DA CONQUISTA', 'PRIMAVERA',    1),
(@BA, 'VITORIA DA CONQUISTA', 'BOA VISTA',    2),
(@BA, 'VITORIA DA CONQUISTA', 'RECREIO',      2),
(@BA, 'VITORIA DA CONQUISTA', 'FELICIA',      3),

(@PE, 'CARUARU', 'LUIZ GONZAGA',              1),
(@PE, 'CARUARU', 'INDIANOPOLIS',              2),

(@PE, 'PETROLINA', 'ORLA',                    1),
(@PE, 'PETROLINA', 'VALE DOURADO',            2),

(@PB, 'CAMPINA GRANDE', 'JARDIM TAVARES',     1),
(@PB, 'CAMPINA GRANDE', 'ALTO BRANCO',        2),
(@PB, 'CAMPINA GRANDE', 'BAIRRO DAS NACOES',  2),

(@RN, 'MOSSORO', 'BELO HORIZONTE',            2),
(@RN, 'MOSSORO', 'ABOLIÇÃO',                  3),

(@MA, 'IMPERATRIZ', 'NOVA IMPERATRIZ',        2),
(@MA, 'IMPERATRIZ', 'BACURI',                 2)

ON DUPLICATE KEY UPDATE ranking = VALUES(ranking);

INSERT INTO bairros_alta_renda (uf_id, cidade, bairro, ranking) VALUES

(@PA, 'BELEM', 'MARCO',                       2),
(@PA, 'BELEM', 'SAO BRAS',                    2),
(@PA, 'BELEM', 'FATIMA',                      2),
(@PA, 'BELEM', 'CAMPINA',                     3),

(@AM, 'MANAUS', 'CHAPADA',                    2),
(@AM, 'MANAUS', 'PARQUE DEZ DE NOVEMBRO',     2),
(@AM, 'MANAUS', 'ALEIXO',                     2),
(@AM, 'MANAUS', 'FLORES',                     3),

(@RO, 'PORTO VELHO', 'BAIRRO NOVO',           2),
(@RO, 'PORTO VELHO', 'NACIONAL',              2),
(@RO, 'PORTO VELHO', 'JARDIM ELDORADO',       3),

(@RR, 'BOA VISTA', 'SAO PEDRO',               2),
(@RR, 'BOA VISTA', 'CARANA',                  2),
(@RR, 'BOA VISTA', 'ASA BRANCA',              3),

(@TO, 'PALMAS', 'PLANO DIRETOR SUL',          2),
(@TO, 'PALMAS', 'PLANO DIRETOR NORTE',        2),
(@TO, 'PALMAS', 'JARDIM AURENY III',          3),

(@AP, 'MACAPA', 'CENTRAL',                    2),
(@AP, 'MACAPA', 'JESUS DE NAZARE',            2),
(@AP, 'MACAPA', 'CONGOS',                     3),

(@CE, 'FORTALEZA', 'VARJOTA',                 2),
(@CE, 'FORTALEZA', 'GUARARAPES',              2),
(@CE, 'FORTALEZA', 'DIONISIO TORRES',         2),
(@CE, 'FORTALEZA', 'CIDADE DOS FUNCIONARIOS', 3),
(@CE, 'FORTALEZA', 'AGUA FRIA',               3),

(@PE, 'RECIFE', 'DERBY',                      1),
(@PE, 'RECIFE', 'GRACAS',                     1),
(@PE, 'RECIFE', 'ESPINHEIRO',                 2),
(@PE, 'RECIFE', 'AFLITOS',                    2),
(@PE, 'RECIFE', 'JAQUEIRA',                   2),
(@PE, 'RECIFE', 'SANTANA',                    2),
(@PE, 'RECIFE', 'ILHA DO LEITE',              2),
(@PE, 'RECIFE', 'MONTEIRO',                   3),

(@BA, 'SALVADOR', 'GRACA',                    1),
(@BA, 'SALVADOR', 'PITUBA',                   2),
(@BA, 'SALVADOR', 'RIO VERMELHO',             2),
(@BA, 'SALVADOR', 'COSTA AZUL',               2),
(@BA, 'SALVADOR', 'PATAMARES',                3),
(@BA, 'SALVADOR', 'PARALELA',                 3),

(@MA, 'SAO LUIS', 'CALHAU',                   1),
(@MA, 'SAO LUIS', 'SAO FRANCISCO',            2),
(@MA, 'SAO LUIS', 'JARDIM RENASCENCA',        2),
(@MA, 'SAO LUIS', 'OLHO D AGUA',              3),

(@RN, 'NATAL', 'PETROPOLIS',                  1),
(@RN, 'NATAL', 'TIROL',                       1),
(@RN, 'NATAL', 'CANDELARIA',                  2),
(@RN, 'NATAL', 'CAPIM MACIO',                 2),

(@PB, 'JOAO PESSOA', 'TAMBAU',                1),
(@PB, 'JOAO PESSOA', 'EXPEDICIONARIOS',       3),

(@PI, 'TERESINA', 'ILHOTAS',                  2),
(@PI, 'TERESINA', 'FREI SERAFIM',             2),

(@SE, 'ARACAJU', 'LUZIA',                     2),
(@SE, 'ARACAJU', 'SAO JOSE',                  2),
(@SE, 'ARACAJU', 'TREZE DE JULHO',            2),
(@SE, 'ARACAJU', 'FAROLANDIA',                3),

(@AL, 'MACEIO', 'JATIUCA',                    1),
(@AL, 'MACEIO', 'MANGABEIRAS',                2),
(@AL, 'MACEIO', 'GUAXUMA',                    3),

(@RJ, 'RIO DE JANEIRO', 'JOA',                1),
(@RJ, 'RIO DE JANEIRO', 'HUMAITA',            2),
(@RJ, 'RIO DE JANEIRO', 'COSME VELHO',        2),
(@RJ, 'RIO DE JANEIRO', 'SAO CONRADO',        2),
(@RJ, 'RIO DE JANEIRO', 'ITANHANGA',          2),
(@RJ, 'RIO DE JANEIRO', 'URCA',               2),
(@RJ, 'RIO DE JANEIRO', 'LARANJEIRAS',        2),
(@RJ, 'RIO DE JANEIRO', 'BOTAFOGO',           2),
(@RJ, 'RIO DE JANEIRO', 'ALTO DA BOA VISTA',  3),
(@RJ, 'RIO DE JANEIRO', 'GLORIA',             3),

(@MG, 'BELO HORIZONTE', 'ANCHIETA',           1),
(@MG, 'BELO HORIZONTE', 'MANGABEIRAS',        1),
(@MG, 'BELO HORIZONTE', 'SANTO AGOSTINHO',    2),
(@MG, 'BELO HORIZONTE', 'SERRA',              2),
(@MG, 'BELO HORIZONTE', 'CARMO',              2),
(@MG, 'BELO HORIZONTE', 'CRUZEIRO',           2),
(@MG, 'BELO HORIZONTE', 'LUXEMBURGO',         3),
(@MG, 'BELO HORIZONTE', 'BURITIS',            3),

(@SP, 'SÃO PAULO', 'ALTO DE PINHEIROS',       1),
(@SP, 'SÃO PAULO', 'JARDIM PAULISTA',         1),
(@SP, 'SÃO PAULO', 'MORUMBI',                 2),
(@SP, 'SÃO PAULO', 'PACAEMBU',                2),
(@SP, 'SÃO PAULO', 'ALTO DA LAPA',            2)

ON DUPLICATE KEY UPDATE ranking = VALUES(ranking);

INSERT INTO bairros_alta_renda (uf_id, cidade, bairro, ranking) VALUES

(@SP, 'VALINHOS', 'NOVA GARDENIA',                2),
(@SP, 'VALINHOS', 'PARQUE VILLA FLORES',          2),
(@SP, 'VALINHOS', 'RESERVA DA SERRA',             2),
(@SP, 'VALINHOS', 'CITY VALINHOS',                3),

(@SP, 'VINHEDO', 'PARQUE DAS GARCAS',             1),
(@SP, 'VINHEDO', 'TERRAS DE VINHEDO',             1),
(@SP, 'VINHEDO', 'VISTA ALEGRE',                  2),
(@SP, 'VINHEDO', 'JARDIM VIRGINIA',               2),
(@SP, 'VINHEDO', 'VILLA D ESTE',                  2),

(@SP, 'ITATIBA', 'VILLA RICA',                    2),
(@SP, 'ITATIBA', 'JARDIM ITALIA',                 3),

(@SP, 'LOUVEIRA', 'JARDIM AMERICA',               2),
(@SP, 'LOUVEIRA', 'RESIDENCIAL BELA VISTA',       2),

(@SP, 'SUMARE', 'SWISS PARK',                     2),
(@SP, 'SUMARE', 'NOVA VENEZA',                    3),

(@SP, 'HORTOLANDIA', 'PARQUE DOS POMARES',        3),

(@SP, 'SAO SEBASTIAO', 'MARESIAS',                1),
(@SP, 'SAO SEBASTIAO', 'JUQUEHY',                 1),
(@SP, 'SAO SEBASTIAO', 'CAMBURY',                 1),
(@SP, 'SAO SEBASTIAO', 'BOICUCANGA',              2),
(@SP, 'SAO SEBASTIAO', 'BARRA DO UNA',            2),
(@SP, 'SAO SEBASTIAO', 'PAUBA',                   2),
(@SP, 'SAO SEBASTIAO', 'CENTRO',                  3),

(@SP, 'UBATUBA', 'ITAMAMBUCA',                    1),
(@SP, 'UBATUBA', 'PRAIA DO LAZARO',               1),
(@SP, 'UBATUBA', 'MARANDUBA',                     2),
(@SP, 'UBATUBA', 'SAPE',                          2),
(@SP, 'UBATUBA', 'PRAIA DO FELIX',                2),
(@SP, 'UBATUBA', 'PEREQUÊ ACU',                   3),

(@SP, 'CARAGUATATUBA', 'TABATINGA',               2),
(@SP, 'CARAGUATATUBA', 'MASSAGUACU',              2),
(@SP, 'CARAGUATATUBA', 'INDAIA',                  2),
(@SP, 'CARAGUATATUBA', 'PEGORELLI',               3),

(@SP, 'GUARUJA', 'ENSEADA',                       1),
(@SP, 'GUARUJA', 'PITANGUEIRAS',                  1),
(@SP, 'GUARUJA', 'ASTURIAS',                      1),
(@SP, 'GUARUJA', 'IPORANGA',                      1),
(@SP, 'GUARUJA', 'JARDIM LAS PALMAS',             1),
(@SP, 'GUARUJA', 'JARDIM VIRGINIA',               2),
(@SP, 'GUARUJA', 'ACARAU',                        2),

(@SP, 'PRAIA GRANDE', 'CANTO DO FORTE',           1),
(@SP, 'PRAIA GRANDE', 'AVIACAO',                  2),
(@SP, 'PRAIA GRANDE', 'GUILHERMINA',              2),
(@SP, 'PRAIA GRANDE', 'TUPI',                     2),

(@SP, 'ITAPECERICA DA SERRA', 'CHACARA NAZARETH', 2),
(@SP, 'ITAPECERICA DA SERRA', 'JARDIM DAS FLORES', 3),

(@SP, 'EMBU DAS ARTES', 'JARDIM SAN FERNANDO',   2),
(@SP, 'EMBU DAS ARTES', 'MORRO GRANDE',          3),

(@SP, 'TABOAO DA SERRA', 'JARDIM MONTE ALEGRE',   3),

(@SP, 'MAUA', 'JARDIM ZAIRA',                     3),

(@SP, 'SUZANO', 'JARDIM IMPERADOR',               3),
(@SP, 'SUZANO', 'CITY SUZANO',                    3),

(@SP, 'ARARAQUARA', 'JARDIM RESIDENCIAL ELDORADO', 2),
(@SP, 'ARARAQUARA', 'NOVA ARARAQUARA',            2),

(@SP, 'BOTUCATU', 'RUBIAO JUNIOR',                2),
(@SP, 'BOTUCATU', 'VITORIANA',                    3)

ON DUPLICATE KEY UPDATE ranking = VALUES(ranking);

INSERT INTO bairros_alta_renda (uf_id, cidade, bairro, ranking) VALUES

(@MG, 'ITUIUTABA', 'RESIDENCIAL VILA RICA',    1),
(@MG, 'ITUIUTABA', 'JARDIM EUROPA',            2),
(@MG, 'ITUIUTABA', 'BELA VISTA',               2),
(@MG, 'ITUIUTABA', 'CENTRO',                   2),
(@MG, 'ITUIUTABA', 'JARDIM PANORAMA',          3),

(@MG, 'ITAJUBA', 'RESIDENCIAL MONTECHIARO',    1),
(@MG, 'ITAJUBA', 'VARGINHA',                   2),
(@MG, 'ITAJUBA', 'SANTA TEREZA',               2),
(@MG, 'ITAJUBA', 'JARDIM DAS NACOES',          2),
(@MG, 'ITAJUBA', 'CENTRO',                     2),

(@MG, 'PARA DE MINAS', 'TODOS OS SANTOS',      2),
(@MG, 'PARA DE MINAS', 'JARDIM EUROPA',        2),
(@MG, 'PARA DE MINAS', 'CENTRO',               2),
(@MG, 'PARA DE MINAS', 'SAO JOSE',             3),

(@MG, 'CORONEL FABRICIANO', 'CALADAO',                 1),
(@MG, 'CORONEL FABRICIANO', 'AMIZADE',                 2),
(@MG, 'CORONEL FABRICIANO', 'NOSSA SENHORA DE FATIMA', 2),
(@MG, 'CORONEL FABRICIANO', 'CENTRO',                  2),

(@MG, 'TIMOTEO', 'HORTO',                      1),
(@MG, 'TIMOTEO', 'VILA ISABEL',                2),
(@MG, 'TIMOTEO', 'CENTRO',                     2),
(@MG, 'TIMOTEO', 'LIMOEIRO',                   3),

(@PR, 'PINHAIS', 'EMILIANO PERNETA',           1),
(@PR, 'PINHAIS', 'CENTRO',                     2),
(@PR, 'PINHAIS', 'JARDIM CARAGUA',             2),
(@PR, 'PINHAIS', 'VARGEM GRANDE',              2),
(@PR, 'PINHAIS', 'JARDIM PARANA',              3),

(@PR, 'ARAUCARIA', 'CENTRO',                   2),
(@PR, 'ARAUCARIA', 'JARDIM IGUACU',            2),
(@PR, 'ARAUCARIA', 'TINDIQUERA',               2),
(@PR, 'ARAUCARIA', 'COSTEIRA',                 2),
(@PR, 'ARAUCARIA', 'THOMAZ COELHO',            3),

(@PR, 'CAMPO LARGO', 'CENTRO',                 2),
(@PR, 'CAMPO LARGO', 'JARDIM ALVORADA',        2),
(@PR, 'CAMPO LARGO', 'VILA CRISTINA',          2),
(@PR, 'CAMPO LARGO', 'JARDIM SAO PAULO',       3),

(@PR, 'ARAPONGAS', 'JARDIM IMPERIAL',          1),
(@PR, 'ARAPONGAS', 'JARDIM AMERICA',           2),
(@PR, 'ARAPONGAS', 'CATUAI',                   2),
(@PR, 'ARAPONGAS', 'CENTRO',                   2),
(@PR, 'ARAPONGAS', 'JARDIM ARAPONGAS',         3),

(@PR, 'CAMBE', 'RESIDENCIAL SOLAR',            1),
(@PR, 'CAMBE', 'JARDIM UNIVERSITARIO',         2),
(@PR, 'CAMBE', 'JARDIM GUANABARA',             2),
(@PR, 'CAMBE', 'CENTRO',                       2),
(@PR, 'CAMBE', 'JARDIM PARAISO',               3),

(@RS, 'SANTO ANGELO', 'CENTRO',                2),
(@RS, 'SANTO ANGELO', 'SAO MIGUEL',            2),
(@RS, 'SANTO ANGELO', 'JARDIM DAS AMERICAS',   2),
(@RS, 'SANTO ANGELO', 'PINHEIRINHO',           2),
(@RS, 'SANTO ANGELO', 'COPAS VERDES',          3),

(@RS, 'SANTANA DO LIVRAMENTO', 'VILLA OASIS',              1),
(@RS, 'SANTANA DO LIVRAMENTO', 'CENTRO',                   2),
(@RS, 'SANTANA DO LIVRAMENTO', 'JARDIM DR SEZEFREDO',      2),
(@RS, 'SANTANA DO LIVRAMENTO', 'BAIRRO DO CHALE',          2),
(@RS, 'SANTANA DO LIVRAMENTO', 'SAO JOSE',                 3),

(@RS, 'ALEGRETE', 'CENTRO',                    2),
(@RS, 'ALEGRETE', 'PROMORAR',                  2),
(@RS, 'ALEGRETE', 'JARDIM DO PRADO',           2),
(@RS, 'ALEGRETE', 'VERA CRUZ',                 3),

(@RS, 'IJUI', 'CENTRO',                        2),
(@RS, 'IJUI', 'IGUACU',                        2),
(@RS, 'IJUI', 'JARDIM DAS AMERICAS',           2),
(@RS, 'IJUI', 'SAO JOSE',                      3),

(@RS, 'SANTA ROSA', 'CENTRO',                  2),
(@RS, 'SANTA ROSA', 'JARDIM DAS AMERICAS',     2),
(@RS, 'SANTA ROSA', 'SAO CRISTOVAO',           2),
(@RS, 'SANTA ROSA', 'VILA SCHERER',            3),

(@RS, 'CACHOEIRA DO SUL', 'CENTRO',            2),
(@RS, 'CACHOEIRA DO SUL', 'JARDIM AMERICA',    2),
(@RS, 'CACHOEIRA DO SUL', 'SAO JOSE',          3),

(@SC, 'ITAPEMA', 'MEIA PRAIA',                 1),
(@SC, 'ITAPEMA', 'CENTRO',                     1),
(@SC, 'ITAPEMA', 'ILHOTA',                     2),
(@SC, 'ITAPEMA', 'CANTO DA PRAIA',             2),
(@SC, 'ITAPEMA', 'FAZENDA',                    3),

(@SC, 'CAMBORIU', 'JARDIM IATE CLUBE',         1),
(@SC, 'CAMBORIU', 'CENTRO',                    2),
(@SC, 'CAMBORIU', 'BAIRRO DAS NACOES',         2),
(@SC, 'CAMBORIU', 'VILA REAL',                 3),

(@SC, 'NAVEGANTES', 'MEIA PRAIA',              1),
(@SC, 'NAVEGANTES', 'CENTRO',                  2),
(@SC, 'NAVEGANTES', 'MACHADOS',                2),
(@SC, 'NAVEGANTES', 'SAO MARCOS',              3),

(@GO, 'TRINDADE', 'RESIDENCIAL DAS AMERICAS',  1),
(@GO, 'TRINDADE', 'CENTRO',                    2),
(@GO, 'TRINDADE', 'JARDIM PLANALTO',           2),
(@GO, 'TRINDADE', 'SETOR MARISTA',             2),
(@GO, 'TRINDADE', 'JARDIM BELA VISTA',         3),

(@GO, 'SENADOR CANEDO', 'RESIDENCIAL VALE DO SOL', 1),
(@GO, 'SENADOR CANEDO', 'CENTRO',              2),
(@GO, 'SENADOR CANEDO', 'JARDIM PLANALTO',     2),
(@GO, 'SENADOR CANEDO', 'JARDIM NOVA ERA',     3),

(@GO, 'AGUAS LINDAS DE GOIAS', 'PARQUE ESTRELA DALVA', 2),
(@GO, 'AGUAS LINDAS DE GOIAS', 'JARDIM IMPERIAL',      2),
(@GO, 'AGUAS LINDAS DE GOIAS', 'CENTRO',               3),

(@ES, 'GUARAPARI', 'PRAIA DO MORRO',           1),
(@ES, 'GUARAPARI', 'ENSEADA AZUL',             1),
(@ES, 'GUARAPARI', 'CENTRO',                   2),
(@ES, 'GUARAPARI', 'MUQUICABA',                2),
(@ES, 'GUARAPARI', 'MEAIPE',                   2),
(@ES, 'GUARAPARI', 'BARRA DO SAHY',            3),

(@ES, 'ARACRUZ', 'COQUEIRAL DE ARACRUZ',       1),
(@ES, 'ARACRUZ', 'CENTRO',                     2),
(@ES, 'ARACRUZ', 'BARRA DO RIACHO',            2),
(@ES, 'ARACRUZ', 'JARDIM BAVARIA',             2),
(@ES, 'ARACRUZ', 'SANTA RITA',                 3),

(@ES, 'CACHOEIRO DE ITAPEMIRIM', 'GILBERLANDIA',   1),
(@ES, 'CACHOEIRO DE ITAPEMIRIM', 'AQUIDABAN',       2),
(@ES, 'CACHOEIRO DE ITAPEMIRIM', 'INDEPENDENCIA',   2),

(@PA, 'PARAUAPEBAS', 'JARDIM CARAJAS',         1),
(@PA, 'PARAUAPEBAS', 'PALMEIRAS',              1),
(@PA, 'PARAUAPEBAS', 'CIDADE NOVA',            2),
(@PA, 'PARAUAPEBAS', 'BEIRA RIO',              2),
(@PA, 'PARAUAPEBAS', 'NOVA CARAJAS',           2),
(@PA, 'PARAUAPEBAS', 'CENTRO',                 3),

(@PA, 'ALTAMIRA', 'BOA ESPERANCA',             2),
(@PA, 'ALTAMIRA', 'JARDIM INDEPENDENCIA',      2),
(@PA, 'ALTAMIRA', 'CENTRO',                    2),

(@AM, 'MANACAPURU', 'CENTRO',                  2),
(@AM, 'MANACAPURU', 'FLORES',                  2),
(@AM, 'MANACAPURU', 'SAO JOSE',                3),

(@AC, 'CRUZEIRO DO SUL', 'CENTRO',             2),
(@AC, 'CRUZEIRO DO SUL', 'MIRITIZAL',          2),
(@AC, 'CRUZEIRO DO SUL', 'AEROPORTO',          2),

(@RO, 'JI-PARANA', 'MILANI',                   1),
(@RO, 'JI-PARANA', 'URUPA',                    2),
(@RO, 'JI-PARANA', 'JARDIM ELDORADO',          2),
(@RO, 'JI-PARANA', 'BOM JARDIM',               2),

(@TO, 'ARAGUAINA', 'CIMBA',                    1),
(@TO, 'ARAGUAINA', 'SETOR ARAGUAIA',           2),
(@TO, 'ARAGUAINA', 'SETOR ANHANGUERA',         2),
(@TO, 'ARAGUAINA', 'JARDIM PAULISTA',          2),
(@TO, 'ARAGUAINA', 'CENTRO',                   2),
(@TO, 'ARAGUAINA', 'SETOR OESTE',              3),

(@TO, 'GURUPI', 'SETOR DOS FUNCIONARIOS',      1),
(@TO, 'GURUPI', 'RESIDENCIAL MORADA DO SOL',   1),
(@TO, 'GURUPI', 'CENTRO',                      2),
(@TO, 'GURUPI', 'SETOR CENTRAL',               2),
(@TO, 'GURUPI', 'JARDIM PAULISTA',             3),

(@MA, 'SAO JOSE DE RIBAMAR', 'RESIDENCIAL PRAIA MAR', 1),
(@MA, 'SAO JOSE DE RIBAMAR', 'ARACAGI',               2),
(@MA, 'SAO JOSE DE RIBAMAR', 'PACIENCIA',             2),
(@MA, 'SAO JOSE DE RIBAMAR', 'CENTRO',                2),
(@MA, 'SAO JOSE DE RIBAMAR', 'BAIRRO DE FATIMA',      3),

(@MA, 'CAXIAS', 'CENTRO',                      2),
(@MA, 'CAXIAS', 'JARDIM SAO CRISTOVAO',        2),
(@MA, 'CAXIAS', 'SAO LUIZ',                    2),

(@MA, 'TIMON', 'PARQUE PIAUI',                 2),
(@MA, 'TIMON', 'JARDIM TROPICAL',              2),
(@MA, 'TIMON', 'CENTRO',                       2),
(@MA, 'TIMON', 'NOVO TIMON',                   3),

(@BA, 'JUAZEIRO', 'RECANTO DAS ACAIAS',        1),
(@BA, 'JUAZEIRO', 'JARDIM AMERICA',            2),
(@BA, 'JUAZEIRO', 'JOSE WALTER',               2),
(@BA, 'JUAZEIRO', 'NOVO HORIZONTE',            2),
(@BA, 'JUAZEIRO', 'CENTRO',                    3),

(@CE, 'JUAZEIRO DO NORTE', 'LAGOA SECA',           1),
(@CE, 'JUAZEIRO DO NORTE', 'FRANCISCO CAVALCANTE', 2),
(@CE, 'JUAZEIRO DO NORTE', 'NOVO JUAZEIRO',        2),
(@CE, 'JUAZEIRO DO NORTE', 'JARDIM GONZAGA',       3),

(@CE, 'IGUATU', 'JARDIM DAS OLIVEIRAS',        1),
(@CE, 'IGUATU', 'DOM QUINTINO',                2),
(@CE, 'IGUATU', 'CENTRO',                      2),
(@CE, 'IGUATU', 'NOVO IGUATU',                 3),

(@SE, 'LAGARTO', 'CENTRO',                     2),
(@SE, 'LAGARTO', 'SAO JOSE',                   2),
(@SE, 'LAGARTO', 'JARDIM PRIMAVERA',           2),

(@PI, 'PICOS', 'MONTE CASTELO',                1),
(@PI, 'PICOS', 'JUNCO',                        2),
(@PI, 'PICOS', 'CENTRO',                       2),
(@PI, 'PICOS', 'SAO JOSE',                     3)

ON DUPLICATE KEY UPDATE ranking = VALUES(ranking);
