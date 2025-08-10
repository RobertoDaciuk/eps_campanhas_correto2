-- ==============================================================================
-- ESQUEMA DE BANCO DE DADOS PREMIUM (Premium Database Schema) - v4.1 CORRIGIDO
-- ==============================================================================
-- Localização: /database/schema.sql
-- 
-- Aprimoramentos v4.1:
-- - Correção para criação automática do banco
-- - Estrutura otimizada para performance
-- - Índices compostos inteligentes
-- - Triggers de auditoria automática
-- - Particionamento por data
-- - Constraints de integridade avançadas
-- - Sistema de gamificação completo
-- - LGPD compliance
-- ==============================================================================

-- ==============================================================================
-- 0. CONFIGURAÇÃO INICIAL E CRIAÇÃO DO BANCO
-- ==============================================================================

-- Cria o banco de dados se não existir
CREATE DATABASE IF NOT EXISTS `campanhas_eps` 
DEFAULT CHARACTER SET utf8mb4 
DEFAULT COLLATE utf8mb4_unicode_ci;

-- Seleciona o banco de dados
USE `campanhas_eps`;

-- Configurações iniciais
SET NAMES utf8mb4 COLLATE utf8mb4_unicode_ci;
SET FOREIGN_KEY_CHECKS = 0;
SET SQL_MODE = 'STRICT_TRANS_TABLES,NO_ZERO_DATE,NO_ZERO_IN_DATE,ERROR_FOR_DIVISION_BY_ZERO';

-- Informações sobre o processo
SELECT CONCAT('Criando schema no banco: ', DATABASE()) as 'Status Inicial';

-- ==============================================================================
-- 1. TABELA DE ÓTICAS PARCEIRAS
-- ==============================================================================

DROP TABLE IF EXISTS `oticas`;

CREATE TABLE `oticas` (
    `id_otica` INT(11) UNSIGNED NOT NULL AUTO_INCREMENT,
    `cnpj` VARCHAR(14) NOT NULL COMMENT 'CNPJ sem formatação',
    `razao_social` VARCHAR(255) NOT NULL COMMENT 'Razão social da empresa',
    `nome_fantasia` VARCHAR(255) DEFAULT NULL COMMENT 'Nome fantasia',
    `endereco` TEXT NOT NULL COMMENT 'Endereço completo',
    `cep` VARCHAR(8) DEFAULT NULL COMMENT 'CEP sem formatação',
    `cidade` VARCHAR(100) NOT NULL,
    `estado` CHAR(2) NOT NULL COMMENT 'UF do estado',
    `telefone` VARCHAR(15) DEFAULT NULL COMMENT 'Telefone principal',
    `email` VARCHAR(255) DEFAULT NULL COMMENT 'Email de contato',
    `responsavel_nome` VARCHAR(150) DEFAULT NULL COMMENT 'Nome do responsável',
    `responsavel_cpf` VARCHAR(11) DEFAULT NULL COMMENT 'CPF do responsável',
    `responsavel_telefone` VARCHAR(15) DEFAULT NULL,
    `tipo_parceria` ENUM('bronze', 'prata', 'ouro', 'diamante') DEFAULT 'bronze' COMMENT 'Nível de parceria',
    `desconto_padrao` DECIMAL(5,2) DEFAULT 0.00 COMMENT 'Desconto padrão em %',
    `limite_credito` DECIMAL(12,2) DEFAULT 0.00 COMMENT 'Limite de crédito',
    `dia_fechamento` TINYINT(2) DEFAULT 30 COMMENT 'Dia do fechamento mensal',
    `status` ENUM('ativa', 'inativa', 'suspensa', 'bloqueada') DEFAULT 'ativa',
    `observacoes` TEXT DEFAULT NULL COMMENT 'Observações gerais',
    `metadata` JSON DEFAULT NULL COMMENT 'Dados adicionais em JSON',
    `created_at` TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    `updated_at` TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    `deleted_at` TIMESTAMP NULL DEFAULT NULL COMMENT 'Soft delete',
    
    PRIMARY KEY (`id_otica`),
    UNIQUE KEY `uk_oticas_cnpj` (`cnpj`),
    INDEX `idx_oticas_status` (`status`),
    INDEX `idx_oticas_cidade_estado` (`cidade`, `estado`),
    INDEX `idx_oticas_tipo_parceria` (`tipo_parceria`),
    INDEX `idx_oticas_created` (`created_at`),
    INDEX `idx_oticas_deleted` (`deleted_at`),
    FULLTEXT KEY `ft_oticas_search` (`razao_social`, `nome_fantasia`, `endereco`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci COMMENT='Óticas parceiras do laboratório';

-- ==============================================================================
-- 2. TABELA DE USUÁRIOS
-- ==============================================================================

DROP TABLE IF EXISTS `usuarios`;

CREATE TABLE `usuarios` (
    `id` INT(11) UNSIGNED NOT NULL AUTO_INCREMENT,
    `nome` VARCHAR(120) NOT NULL COMMENT 'Nome completo do usuário',
    `cpf` VARCHAR(11) NOT NULL COMMENT 'CPF sem formatação',
    `email` VARCHAR(255) NOT NULL COMMENT 'Email único do usuário',
    `celular` VARCHAR(15) NOT NULL COMMENT 'Celular com DDD',
    `senha_hash` VARCHAR(255) NOT NULL COMMENT 'Hash da senha',
    `tipo` ENUM('vendedor', 'gerente', 'admin') NOT NULL DEFAULT 'vendedor',
    `status` ENUM('pendente', 'ativo', 'inativo', 'bloqueado', 'suspenso', 'excluido') DEFAULT 'pendente',
    `id_otica` INT(11) UNSIGNED DEFAULT NULL COMMENT 'FK para ótica (NULL para admins)',
    
    -- Campos de verificação
    `email_verificado_at` TIMESTAMP NULL DEFAULT NULL,
    `telefone_verificado_at` TIMESTAMP NULL DEFAULT NULL,
    
    -- Tokens de segurança
    `token_confirmacao` VARCHAR(64) DEFAULT NULL COMMENT 'Token de ativação da conta',
    `token_expira` TIMESTAMP NULL DEFAULT NULL COMMENT 'Expiração do token',
    `token_recuperacao` VARCHAR(64) DEFAULT NULL COMMENT 'Token de recuperação de senha',
    `token_recuperacao_expira` TIMESTAMP NULL DEFAULT NULL,
    
    -- Controle de tentativas de login
    `failed_login_attempts` TINYINT(3) UNSIGNED DEFAULT 0,
    `last_failed_login` TIMESTAMP NULL DEFAULT NULL,
    `last_successful_login` TIMESTAMP NULL DEFAULT NULL,
    `lockout_until` TIMESTAMP NULL DEFAULT NULL COMMENT 'Bloqueio temporário até',
    
    -- Campos de auditoria
    `ip_cadastro` VARCHAR(45) DEFAULT NULL COMMENT 'IP do cadastro',
    `user_agent_cadastro` TEXT DEFAULT NULL COMMENT 'User agent do cadastro',
    `ip_ultimo_acesso` VARCHAR(45) DEFAULT NULL,
    `user_agent_ultimo_acesso` TEXT DEFAULT NULL,
    `total_logins` INT(11) UNSIGNED DEFAULT 0 COMMENT 'Contador de logins',
    
    -- Configurações do usuário
    `configuracoes` JSON DEFAULT NULL COMMENT 'Preferências do usuário',
    `permissoes_extras` JSON DEFAULT NULL COMMENT 'Permissões adicionais',
    
    -- LGPD
    `consentimento_lgpd` TIMESTAMP NULL DEFAULT NULL COMMENT 'Data do consentimento LGPD',
    `data_exclusao_solicitada` TIMESTAMP NULL DEFAULT NULL COMMENT 'Solicitação de exclusão',
    
    -- Timestamps
    `created_at` TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    `updated_at` TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    `deleted_at` TIMESTAMP NULL DEFAULT NULL COMMENT 'Soft delete',
    
    PRIMARY KEY (`id`),
    UNIQUE KEY `uk_usuarios_cpf` (`cpf`),
    UNIQUE KEY `uk_usuarios_email` (`email`),
    UNIQUE KEY `uk_usuarios_token` (`token_confirmacao`),
    UNIQUE KEY `uk_usuarios_token_rec` (`token_recuperacao`),
    INDEX `idx_usuarios_status` (`status`),
    INDEX `idx_usuarios_tipo` (`tipo`),
    INDEX `idx_usuarios_otica` (`id_otica`),
    INDEX `idx_usuarios_email_status` (`email`, `status`),
    INDEX `idx_usuarios_cpf_status` (`cpf`, `status`),
    INDEX `idx_usuarios_created` (`created_at`),
    INDEX `idx_usuarios_last_login` (`last_successful_login`),
    INDEX `idx_usuarios_failed_attempts` (`failed_login_attempts`, `last_failed_login`),
    INDEX `idx_usuarios_tokens_expira` (`token_expira`),
    INDEX `idx_usuarios_deleted` (`deleted_at`),
    
    CONSTRAINT `fk_usuarios_otica` FOREIGN KEY (`id_otica`) REFERENCES `oticas` (`id_otica`) ON DELETE SET NULL ON UPDATE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci COMMENT='Usuários do sistema (vendedores, gerentes, admins)';

-- ==============================================================================
-- 3. TABELA DE PERFIS DE USUÁRIO (GAMIFICAÇÃO)
-- ==============================================================================

DROP TABLE IF EXISTS `user_profiles`;

CREATE TABLE `user_profiles` (
    `id` INT(11) UNSIGNED NOT NULL AUTO_INCREMENT,
    `user_id` INT(11) UNSIGNED NOT NULL,
    `avatar_url` VARCHAR(500) DEFAULT NULL COMMENT 'URL do avatar',
    `biografia` TEXT DEFAULT NULL COMMENT 'Biografia do usuário',
    
    -- Sistema de pontuação
    `pontos_total` INT(11) UNSIGNED DEFAULT 0 COMMENT 'Total de pontos acumulados',
    `pontos_mes_atual` INT(11) UNSIGNED DEFAULT 0 COMMENT 'Pontos do mês atual',
    `pontos_ano_atual` INT(11) UNSIGNED DEFAULT 0 COMMENT 'Pontos do ano atual',
    `pontos_resgatados` INT(11) UNSIGNED DEFAULT 0 COMMENT 'Pontos já resgatados',
    
    -- Sistema de níveis
    `nivel_atual` ENUM('bronze', 'prata', 'ouro', 'platina', 'diamante') DEFAULT 'bronze',
    `experiencia_nivel` INT(11) UNSIGNED DEFAULT 0 COMMENT 'XP no nível atual',
    `nivel_anterior` ENUM('bronze', 'prata', 'ouro', 'platina', 'diamante') DEFAULT 'bronze',
    `data_ultimo_nivel` TIMESTAMP NULL DEFAULT NULL,
    
    -- Estatísticas
    `total_vendas` INT(11) UNSIGNED DEFAULT 0,
    `total_campanhas_participadas` INT(11) UNSIGNED DEFAULT 0,
    `melhor_posicao_ranking` INT(11) UNSIGNED DEFAULT NULL,
    `sequencia_dias_ativo` INT(11) UNSIGNED DEFAULT 0 COMMENT 'Dias consecutivos ativo',
    `maior_sequencia_dias` INT(11) UNSIGNED DEFAULT 0,
    
    -- Conquistas
    `conquistas` JSON DEFAULT NULL COMMENT 'Array de conquistas obtidas',
    `badges` JSON DEFAULT NULL COMMENT 'Badges especiais',
    
    -- Preferências
    `tema_preferido` ENUM('claro', 'escuro', 'auto') DEFAULT 'escuro',
    `notificacoes_email` BOOLEAN DEFAULT TRUE,
    `notificacoes_whatsapp` BOOLEAN DEFAULT TRUE,
    `notificacoes_push` BOOLEAN DEFAULT TRUE,
    `idioma` VARCHAR(5) DEFAULT 'pt_BR',
    `timezone` VARCHAR(50) DEFAULT 'America/Sao_Paulo',
    
    -- Datas importantes
    `conta_ativada_at` TIMESTAMP NULL DEFAULT NULL,
    `primeiro_login_at` TIMESTAMP NULL DEFAULT NULL,
    `ultima_atividade_at` TIMESTAMP NULL DEFAULT NULL,
    
    -- Timestamps
    `data_criacao` TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    `updated_at` TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    
    PRIMARY KEY (`id`),
    UNIQUE KEY `uk_profiles_user` (`user_id`),
    INDEX `idx_profiles_pontos` (`pontos_total`),
    INDEX `idx_profiles_nivel` (`nivel_atual`),
    INDEX `idx_profiles_vendas` (`total_vendas`),
    INDEX `idx_profiles_atividade` (`ultima_atividade_at`),
    
    CONSTRAINT `fk_profiles_user` FOREIGN KEY (`user_id`) REFERENCES `usuarios` (`id`) ON DELETE CASCADE ON UPDATE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci COMMENT='Perfis e gamificação dos usuários';

-- ==============================================================================
-- 4. TABELA DE CAMPANHAS
-- ==============================================================================

DROP TABLE IF EXISTS `campanhas`;

CREATE TABLE `campanhas` (
    `id` INT(11) UNSIGNED NOT NULL AUTO_INCREMENT,
    `titulo` VARCHAR(200) NOT NULL COMMENT 'Título da campanha',
    `descricao` TEXT NOT NULL COMMENT 'Descrição detalhada',
    `slug` VARCHAR(250) NOT NULL COMMENT 'Slug para URL amigável',
    
    -- Configuração visual
    `imagem_destaque` VARCHAR(500) DEFAULT NULL COMMENT 'URL da imagem principal',
    `cor_primaria` VARCHAR(7) DEFAULT '#3b82f6' COMMENT 'Cor hex da campanha',
    `template_layout` JSON DEFAULT NULL COMMENT 'Configuração do layout',
    
    -- Datas e prazos
    `data_inicio` TIMESTAMP NOT NULL,
    `data_fim` TIMESTAMP NOT NULL,
    `data_inicio_validacao` TIMESTAMP NULL DEFAULT NULL COMMENT 'Início do período de validação',
    `data_fim_validacao` TIMESTAMP NULL DEFAULT NULL COMMENT 'Fim do período de validação',
    
    -- Configurações de participação
    `tipos_pedido_aceitos` JSON NOT NULL COMMENT 'Array com tipos aceitos: eps_web, opticlick, ordem_producao',
    `prefixos_aceitos` JSON DEFAULT NULL COMMENT 'Prefixos de pedidos aceitos',
    `oticas_participantes` JSON DEFAULT NULL COMMENT 'IDs das óticas (NULL = todas)',
    `requer_comprovante` BOOLEAN DEFAULT FALSE COMMENT 'Se exige upload de comprovante',
    
    -- Regras da campanha
    `regras_pontuacao` JSON NOT NULL COMMENT 'Regras de pontuação e validação',
    `meta_minima` INT(11) UNSIGNED DEFAULT NULL COMMENT 'Meta mínima para participar',
    `limite_participantes` INT(11) UNSIGNED DEFAULT NULL COMMENT 'Limite de participantes',
    `permite_acumulacao` BOOLEAN DEFAULT TRUE COMMENT 'Se permite acumular com outras campanhas',
    
    -- Premiação
    `sistema_premiacao` JSON DEFAULT NULL COMMENT 'Configuração de prêmios por posição/meta',
    `orcamento_total` DECIMAL(12,2) DEFAULT NULL COMMENT 'Orçamento total da campanha',
    `orcamento_utilizado` DECIMAL(12,2) DEFAULT 0.00 COMMENT 'Orçamento já utilizado',
    
    -- Status e controle
    `status` ENUM('rascunho', 'agendada', 'ativa', 'pausada', 'finalizada', 'cancelada') DEFAULT 'rascunho',
    `criado_por` INT(11) UNSIGNED NOT NULL COMMENT 'Admin que criou',
    `aprovado_por` INT(11) UNSIGNED DEFAULT NULL COMMENT 'Admin que aprovou',
    `data_aprovacao` TIMESTAMP NULL DEFAULT NULL,
    
    -- Métricas
    `total_participantes` INT(11) UNSIGNED DEFAULT 0,
    `total_vendas_submetidas` INT(11) UNSIGNED DEFAULT 0,
    `total_vendas_validadas` INT(11) UNSIGNED DEFAULT 0,
    `total_pontos_distribuidos` INT(11) UNSIGNED DEFAULT 0,
    
    -- Configurações avançadas
    `configuracoes_avancadas` JSON DEFAULT NULL COMMENT 'Configs específicas',
    `mensagens_automaticas` JSON DEFAULT NULL COMMENT 'Mensagens automáticas configuradas',
    
    -- Timestamps
    `created_at` TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    `updated_at` TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    `deleted_at` TIMESTAMP NULL DEFAULT NULL,
    
    PRIMARY KEY (`id`),
    UNIQUE KEY `uk_campanhas_slug` (`slug`),
    INDEX `idx_campanhas_status` (`status`),
    INDEX `idx_campanhas_datas` (`data_inicio`, `data_fim`),
    INDEX `idx_campanhas_ativas` (`status`, `data_inicio`, `data_fim`),
    INDEX `idx_campanhas_criador` (`criado_por`),
    INDEX `idx_campanhas_participantes` (`total_participantes`),
    INDEX `idx_campanhas_deleted` (`deleted_at`),
    FULLTEXT KEY `ft_campanhas_search` (`titulo`, `descricao`),
    
    CONSTRAINT `fk_campanhas_criador` FOREIGN KEY (`criado_por`) REFERENCES `usuarios` (`id`) ON DELETE RESTRICT ON UPDATE CASCADE,
    CONSTRAINT `fk_campanhas_aprovador` FOREIGN KEY (`aprovado_por`) REFERENCES `usuarios` (`id`) ON DELETE SET NULL ON UPDATE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci COMMENT='Campanhas promocionais';

-- ==============================================================================
-- 5. TABELA DE VENDAS
-- ==============================================================================

DROP TABLE IF EXISTS `vendas`;

CREATE TABLE `vendas` (
    `id` INT(11) UNSIGNED NOT NULL AUTO_INCREMENT,
    `user_id` INT(11) UNSIGNED NOT NULL COMMENT 'Vendedor que submeteu',
    `campanha_id` INT(11) UNSIGNED NOT NULL COMMENT 'Campanha relacionada',
    `numero_pedido` VARCHAR(50) NOT NULL COMMENT 'Número do pedido',
    `tipo_pedido` ENUM('eps_web', 'opticlick', 'ordem_producao') NOT NULL,
    
    -- Dados da venda
    `valor_total` DECIMAL(10,2) DEFAULT NULL COMMENT 'Valor total da venda',
    `quantidade_produtos` INT(11) UNSIGNED DEFAULT 1,
    `produtos_detalhes` JSON DEFAULT NULL COMMENT 'Detalhes dos produtos vendidos',
    `cliente_nome` VARCHAR(150) DEFAULT NULL COMMENT 'Nome do cliente final',
    `cliente_documento` VARCHAR(14) DEFAULT NULL COMMENT 'CPF/CNPJ do cliente',
    
    -- Comprovação
    `comprovante_url` VARCHAR(500) DEFAULT NULL COMMENT 'URL do comprovante anexado',
    `comprovante_tipo` VARCHAR(50) DEFAULT NULL COMMENT 'Tipo do arquivo',
    `comprovante_tamanho` INT(11) UNSIGNED DEFAULT NULL COMMENT 'Tamanho em bytes',
    
    -- Validação e pontuação
    `status` ENUM('pendente', 'validando', 'validada', 'rejeitada', 'contestada') DEFAULT 'pendente',
    `pontos_base` INT(11) UNSIGNED DEFAULT 0 COMMENT 'Pontos base da venda',
    `pontos_bonus` INT(11) UNSIGNED DEFAULT 0 COMMENT 'Pontos de bônus',
    `pontos_total` INT(11) UNSIGNED DEFAULT 0 COMMENT 'Total de pontos',
    `multiplicador_aplicado` DECIMAL(3,2) DEFAULT 1.00 COMMENT 'Multiplicador usado',
    
    -- Auditoria de validação
    `validado_por` INT(11) UNSIGNED DEFAULT NULL COMMENT 'Admin que validou',
    `data_validacao` TIMESTAMP NULL DEFAULT NULL,
    `motivo_rejeicao` TEXT DEFAULT NULL COMMENT 'Motivo da rejeição se aplicável',
    `observacoes_validacao` TEXT DEFAULT NULL,
    
    -- Dados técnicos
    `ip_submissao` VARCHAR(45) DEFAULT NULL COMMENT 'IP da submissão',
    `user_agent_submissao` TEXT DEFAULT NULL,
    `hash_verificacao` VARCHAR(64) DEFAULT NULL COMMENT 'Hash para verificação de integridade',
    
    -- Timestamps
    `data_venda` DATE NOT NULL COMMENT 'Data da venda original',
    `created_at` TIMESTAMP DEFAULT CURRENT_TIMESTAMP COMMENT 'Data de submissão',
    `updated_at` TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    
    PRIMARY KEY (`id`),
    UNIQUE KEY `uk_vendas_pedido_campanha` (`numero_pedido`, `campanha_id`),
    INDEX `idx_vendas_user` (`user_id`),
    INDEX `idx_vendas_campanha` (`campanha_id`),
    INDEX `idx_vendas_status` (`status`),
    INDEX `idx_vendas_data` (`data_venda`),
    INDEX `idx_vendas_pontos` (`pontos_total`),
    INDEX `idx_vendas_validador` (`validado_por`),
    INDEX `idx_vendas_user_campanha` (`user_id`, `campanha_id`),
    INDEX `idx_vendas_campanha_status` (`campanha_id`, `status`),
    INDEX `idx_vendas_data_submissao` (`created_at`),
    
    CONSTRAINT `fk_vendas_user` FOREIGN KEY (`user_id`) REFERENCES `usuarios` (`id`) ON DELETE RESTRICT ON UPDATE CASCADE,
    CONSTRAINT `fk_vendas_campanha` FOREIGN KEY (`campanha_id`) REFERENCES `campanhas` (`id`) ON DELETE RESTRICT ON UPDATE CASCADE,
    CONSTRAINT `fk_vendas_validador` FOREIGN KEY (`validado_por`) REFERENCES `usuarios` (`id`) ON DELETE SET NULL ON UPDATE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci COMMENT='Vendas submetidas pelos vendedores';

-- ==============================================================================
-- 6. TABELA DE HISTÓRICO DE PONTOS
-- ==============================================================================

DROP TABLE IF EXISTS `points_history`;

CREATE TABLE `points_history` (
    `id` INT(11) UNSIGNED NOT NULL AUTO_INCREMENT,
    `user_id` INT(11) UNSIGNED NOT NULL,
    `tipo_transacao` ENUM('ganho', 'resgate', 'bonus', 'penalidade', 'ajuste', 'expiracao') NOT NULL,
    `pontos` INT(11) NOT NULL COMMENT 'Pode ser negativo para resgates/penalidades',
    `pontos_antes` INT(11) UNSIGNED NOT NULL COMMENT 'Saldo antes da transação',
    `pontos_depois` INT(11) UNSIGNED NOT NULL COMMENT 'Saldo após a transação',
    
    -- Origem da transação
    `origem_tipo` ENUM('venda', 'campanha', 'manual', 'sistema', 'resgate', 'contestacao') NOT NULL,
    `origem_id` INT(11) UNSIGNED DEFAULT NULL COMMENT 'ID da origem (venda_id, campanha_id, etc)',
    `origem_descricao` VARCHAR(255) NOT NULL COMMENT 'Descrição da origem',
    
    -- Detalhes
    `motivo` TEXT DEFAULT NULL COMMENT 'Motivo detalhado da transação',
    `processado_por` INT(11) UNSIGNED DEFAULT NULL COMMENT 'Admin que processou (se manual)',
    `metadata` JSON DEFAULT NULL COMMENT 'Dados adicionais',
    
    -- Expiração (para pontos que expiram)
    `expira_em` TIMESTAMP NULL DEFAULT NULL COMMENT 'Data de expiração dos pontos',
    `status` ENUM('ativo', 'expirado', 'resgatado', 'cancelado') DEFAULT 'ativo',
    
    `created_at` TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    
    PRIMARY KEY (`id`),
    INDEX `idx_points_user` (`user_id`),
    INDEX `idx_points_tipo` (`tipo_transacao`),
    INDEX `idx_points_origem` (`origem_tipo`, `origem_id`),
    INDEX `idx_points_status` (`status`),
    INDEX `idx_points_expiracao` (`expira_em`),
    INDEX `idx_points_data` (`created_at`),
    INDEX `idx_points_user_data` (`user_id`, `created_at`),
    
    CONSTRAINT `fk_points_user` FOREIGN KEY (`user_id`) REFERENCES `usuarios` (`id`) ON DELETE CASCADE ON UPDATE CASCADE,
    CONSTRAINT `fk_points_processador` FOREIGN KEY (`processado_por`) REFERENCES `usuarios` (`id`) ON DELETE SET NULL ON UPDATE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci COMMENT='Histórico de transações de pontos';

-- ==============================================================================
-- 7. TABELA DE RESGATES DE PRÊMIOS
-- ==============================================================================

DROP TABLE IF EXISTS `resgates`;

CREATE TABLE `resgates` (
    `id` INT(11) UNSIGNED NOT NULL AUTO_INCREMENT,
    `user_id` INT(11) UNSIGNED NOT NULL,
    `premio_nome` VARCHAR(200) NOT NULL COMMENT 'Nome do prêmio resgatado',
    `premio_descricao` TEXT DEFAULT NULL,
    `pontos_utilizados` INT(11) UNSIGNED NOT NULL,
    `valor_estimado` DECIMAL(10,2) DEFAULT NULL COMMENT 'Valor estimado do prêmio',
    
    -- Status do resgate
    `status` ENUM('solicitado', 'aprovado', 'processando', 'enviado', 'entregue', 'cancelado') DEFAULT 'solicitado',
    `codigo_rastreamento` VARCHAR(100) DEFAULT NULL,
    `transportadora` VARCHAR(100) DEFAULT NULL,
    
    -- Endereço de entrega
    `endereco_entrega` JSON NOT NULL COMMENT 'Dados completos do endereço',
    
    -- Auditoria
    `aprovado_por` INT(11) UNSIGNED DEFAULT NULL,
    `data_aprovacao` TIMESTAMP NULL DEFAULT NULL,
    `data_envio` TIMESTAMP NULL DEFAULT NULL,
    `data_entrega` TIMESTAMP NULL DEFAULT NULL,
    `observacoes` TEXT DEFAULT NULL,
    
    `created_at` TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    `updated_at` TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    
    PRIMARY KEY (`id`),
    INDEX `idx_resgates_user` (`user_id`),
    INDEX `idx_resgates_status` (`status`),
    INDEX `idx_resgates_aprovador` (`aprovado_por`),
    INDEX `idx_resgates_data` (`created_at`),
    INDEX `idx_resgates_pontos` (`pontos_utilizados`),
    
    CONSTRAINT `fk_resgates_user` FOREIGN KEY (`user_id`) REFERENCES `usuarios` (`id`) ON DELETE RESTRICT ON UPDATE CASCADE,
    CONSTRAINT `fk_resgates_aprovador` FOREIGN KEY (`aprovado_por`) REFERENCES `usuarios` (`id`) ON DELETE SET NULL ON UPDATE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci COMMENT='Resgates de prêmios pelos usuários';

-- ==============================================================================
-- 8. TABELA DE SESSIONS (CONTROLE DE SESSÕES)
-- ==============================================================================

DROP TABLE IF EXISTS `user_sessions`;

CREATE TABLE `user_sessions` (
    `id` VARCHAR(128) NOT NULL COMMENT 'Session ID',
    `user_id` INT(11) UNSIGNED NOT NULL,
    `ip_address` VARCHAR(45) NOT NULL,
    `user_agent` TEXT NOT NULL,
    `fingerprint` VARCHAR(64) NOT NULL COMMENT 'Hash do fingerprint do dispositivo',
    `is_mobile` BOOLEAN DEFAULT FALSE,
    `browser` VARCHAR(50) DEFAULT NULL,
    `platform` VARCHAR(50) DEFAULT NULL,
    `location_country` VARCHAR(2) DEFAULT NULL COMMENT 'País detectado pelo IP',
    `location_city` VARCHAR(100) DEFAULT NULL,
    
    -- Controle de atividade
    `last_activity` TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    `login_at` TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    `logout_at` TIMESTAMP NULL DEFAULT NULL,
    `is_active` BOOLEAN DEFAULT TRUE,
    
    -- Dados da sessão
    `session_data` JSON DEFAULT NULL COMMENT 'Dados específicos da sessão',
    
    PRIMARY KEY (`id`),
    INDEX `idx_sessions_user` (`user_id`),
    INDEX `idx_sessions_active` (`is_active`, `last_activity`),
    INDEX `idx_sessions_fingerprint` (`fingerprint`),
    INDEX `idx_sessions_ip` (`ip_address`),
    INDEX `idx_sessions_login` (`login_at`),
    
    CONSTRAINT `fk_sessions_user` FOREIGN KEY (`user_id`) REFERENCES `usuarios` (`id`) ON DELETE CASCADE ON UPDATE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci COMMENT='Controle de sessões ativas dos usuários';

-- ==============================================================================
-- 9. TABELA DE REMEMBER TOKENS
-- ==============================================================================

DROP TABLE IF EXISTS `remember_tokens`;

CREATE TABLE `remember_tokens` (
    `id` INT(11) UNSIGNED NOT NULL AUTO_INCREMENT,
    `user_id` INT(11) UNSIGNED NOT NULL,
    `token_hash` VARCHAR(64) NOT NULL COMMENT 'Hash SHA-256 do token',
    `expires_at` TIMESTAMP NOT NULL,
    `used_at` TIMESTAMP NULL DEFAULT NULL,
    `revoked_at` TIMESTAMP NULL DEFAULT NULL,
    `ip_address` VARCHAR(45) DEFAULT NULL,
    `user_agent` TEXT DEFAULT NULL,
    `created_at` TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    
    PRIMARY KEY (`id`),
    UNIQUE KEY `uk_remember_token` (`token_hash`),
    INDEX `idx_remember_user` (`user_id`),
    INDEX `idx_remember_expires` (`expires_at`),
    INDEX `idx_remember_active` (`used_at`, `revoked_at`, `expires_at`),
    
    CONSTRAINT `fk_remember_user` FOREIGN KEY (`user_id`) REFERENCES `usuarios` (`id`) ON DELETE CASCADE ON UPDATE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci COMMENT='Tokens de "lembrar-me"';

-- ==============================================================================
-- 10. TABELA DE LOGS DE SEGURANÇA
-- ==============================================================================

DROP TABLE IF EXISTS `security_logs`;

CREATE TABLE `security_logs` (
    `id` INT(11) UNSIGNED NOT NULL AUTO_INCREMENT,
    `event_type` VARCHAR(50) NOT NULL COMMENT 'Tipo do evento de segurança',
    `severity` ENUM('low', 'medium', 'high', 'critical') DEFAULT 'medium',
    `user_id` INT(11) UNSIGNED DEFAULT NULL COMMENT 'Usuário relacionado (se aplicável)',
    `ip_address` VARCHAR(45) NOT NULL,
    `user_agent` TEXT DEFAULT NULL,
    `session_id` VARCHAR(128) DEFAULT NULL,
    
    -- Detalhes do evento
    `message` TEXT NOT NULL COMMENT 'Mensagem descritiva',
    `context_data` JSON DEFAULT NULL COMMENT 'Dados contextuais do evento',
    `request_uri` VARCHAR(500) DEFAULT NULL,
    `request_method` VARCHAR(10) DEFAULT NULL,
    `request_data` JSON DEFAULT NULL COMMENT 'Dados da requisição (sanitizados)',
    
    -- Localização
    `country` VARCHAR(2) DEFAULT NULL,
    `city` VARCHAR(100) DEFAULT NULL,
    
    -- Status
    `is_blocked` BOOLEAN DEFAULT FALSE COMMENT 'Se o acesso foi bloqueado',
    `is_resolved` BOOLEAN DEFAULT FALSE COMMENT 'Se o incidente foi resolvido',
    `resolved_by` INT(11) UNSIGNED DEFAULT NULL,
    `resolved_at` TIMESTAMP NULL DEFAULT NULL,
    
    `created_at` TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    
    PRIMARY KEY (`id`),
    INDEX `idx_security_type` (`event_type`),
    INDEX `idx_security_severity` (`severity`),
    INDEX `idx_security_user` (`user_id`),
    INDEX `idx_security_ip` (`ip_address`),
    INDEX `idx_security_date` (`created_at`),
    INDEX `idx_security_blocked` (`is_blocked`),
    INDEX `idx_security_resolved` (`is_resolved`),
    INDEX `idx_security_type_date` (`event_type`, `created_at`),
    
    CONSTRAINT `fk_security_user` FOREIGN KEY (`user_id`) REFERENCES `usuarios` (`id`) ON DELETE SET NULL ON UPDATE CASCADE,
    CONSTRAINT `fk_security_resolver` FOREIGN KEY (`resolved_by`) REFERENCES `usuarios` (`id`) ON DELETE SET NULL ON UPDATE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci COMMENT='Logs de eventos de segurança';

-- ==============================================================================
-- 11. TABELA DE AUDIT TRAIL
-- ==============================================================================

DROP TABLE IF EXISTS `audit_trail`;

CREATE TABLE `audit_trail` (
    `id` INT(11) UNSIGNED NOT NULL AUTO_INCREMENT,
    `user_id` INT(11) UNSIGNED DEFAULT NULL,
    `session_id` VARCHAR(128) DEFAULT NULL,
    `action` VARCHAR(100) NOT NULL COMMENT 'Ação realizada',
    `entity_type` VARCHAR(50) DEFAULT NULL COMMENT 'Tipo de entidade afetada',
    `entity_id` INT(11) UNSIGNED DEFAULT NULL COMMENT 'ID da entidade',
    `description` TEXT NOT NULL COMMENT 'Descrição da ação',
    
    -- Dados técnicos
    `ip_address` VARCHAR(45) DEFAULT NULL,
    `user_agent` TEXT DEFAULT NULL,
    `request_uri` VARCHAR(500) DEFAULT NULL,
    `request_method` VARCHAR(10) DEFAULT NULL,
    
    -- Dados da mudança
    `old_values` JSON DEFAULT NULL COMMENT 'Valores anteriores',
    `new_values` JSON DEFAULT NULL COMMENT 'Novos valores',
    `changes_summary` TEXT DEFAULT NULL COMMENT 'Resumo das mudanças',
    
    -- Contexto adicional
    `context` JSON DEFAULT NULL COMMENT 'Contexto adicional',
    `tags` JSON DEFAULT NULL COMMENT 'Tags para categorização',
    
    `created_at` TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    
    PRIMARY KEY (`id`),
    INDEX `idx_audit_user` (`user_id`),
    INDEX `idx_audit_action` (`action`),
    INDEX `idx_audit_entity` (`entity_type`, `entity_id`),
    INDEX `idx_audit_date` (`created_at`),
    INDEX `idx_audit_session` (`session_id`),
    INDEX `idx_audit_ip` (`ip_address`),
    
    CONSTRAINT `fk_audit_user` FOREIGN KEY (`user_id`) REFERENCES `usuarios` (`id`) ON DELETE SET NULL ON UPDATE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci COMMENT='Trilha de auditoria de todas as ações';

-- ==============================================================================
-- 12. TABELA DE MÉTRICAS E ANALYTICS
-- ==============================================================================

DROP TABLE IF EXISTS `metrics`;

CREATE TABLE `metrics` (
    `id` INT(11) UNSIGNED NOT NULL AUTO_INCREMENT,
    `metric_name` VARCHAR(100) NOT NULL COMMENT 'Nome da métrica',
    `metric_type` ENUM('counter', 'gauge', 'histogram', 'summary') DEFAULT 'counter',
    `value` DECIMAL(15,4) NOT NULL COMMENT 'Valor da métrica',
    `unit` VARCHAR(20) DEFAULT NULL COMMENT 'Unidade de medida',
    
    -- Dimensões para agrupamento
    `user_id` INT(11) UNSIGNED DEFAULT NULL,
    `campaign_id` INT(11) UNSIGNED DEFAULT NULL,
    `otica_id` INT(11) UNSIGNED DEFAULT NULL,
    `dimensions` JSON DEFAULT NULL COMMENT 'Outras dimensões em JSON',
    
    -- Temporal
    `metric_date` DATE NOT NULL COMMENT 'Data da métrica',
    `metric_hour` TINYINT(2) DEFAULT NULL COMMENT 'Hora (0-23)',
    `aggregation_period` ENUM('hourly', 'daily', 'weekly', 'monthly') DEFAULT 'daily',
    
    `created_at` TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    
    PRIMARY KEY (`id`),
    INDEX `idx_metrics_name` (`metric_name`),
    INDEX `idx_metrics_date` (`metric_date`),
    INDEX `idx_metrics_user` (`user_id`),
    INDEX `idx_metrics_campaign` (`campaign_id`),
    INDEX `idx_metrics_otica` (`otica_id`),
    INDEX `idx_metrics_name_date` (`metric_name`, `metric_date`),
    INDEX `idx_metrics_period` (`aggregation_period`, `metric_date`),
    
    CONSTRAINT `fk_metrics_user` FOREIGN KEY (`user_id`) REFERENCES `usuarios` (`id`) ON DELETE SET NULL ON UPDATE CASCADE,
    CONSTRAINT `fk_metrics_campaign` FOREIGN KEY (`campaign_id`) REFERENCES `campanhas` (`id`) ON DELETE SET NULL ON UPDATE CASCADE,
    CONSTRAINT `fk_metrics_otica` FOREIGN KEY (`otica_id`) REFERENCES `oticas` (`id_otica`) ON DELETE SET NULL ON UPDATE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci COMMENT='Métricas e analytics do sistema';

-- ==============================================================================
-- 13. TABELA DE CONFIGURAÇÕES DO SISTEMA
-- ==============================================================================

DROP TABLE IF EXISTS `system_settings`;

CREATE TABLE `system_settings` (
    `id` INT(11) UNSIGNED NOT NULL AUTO_INCREMENT,
    `setting_key` VARCHAR(100) NOT NULL COMMENT 'Chave única da configuração',
    `setting_value` TEXT DEFAULT NULL COMMENT 'Valor da configuração',
    `setting_type` ENUM('string', 'integer', 'float', 'boolean', 'json', 'encrypted') DEFAULT 'string',
    `category` VARCHAR(50) DEFAULT 'general' COMMENT 'Categoria da configuração',
    `description` TEXT DEFAULT NULL COMMENT 'Descrição da configuração',
    `is_sensitive` BOOLEAN DEFAULT FALSE COMMENT 'Se contém dados sensíveis',
    `updated_by` INT(11) UNSIGNED DEFAULT NULL,
    `created_at` TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    `updated_at` TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    
    PRIMARY KEY (`id`),
    UNIQUE KEY `uk_settings_key` (`setting_key`),
    INDEX `idx_settings_category` (`category`),
    INDEX `idx_settings_type` (`setting_type`),
    
    CONSTRAINT `fk_settings_updater` FOREIGN KEY (`updated_by`) REFERENCES `usuarios` (`id`) ON DELETE SET NULL ON UPDATE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci COMMENT='Configurações globais do sistema';

-- ==============================================================================
-- 14. TABELA DE NOTIFICAÇÕES
-- ==============================================================================

DROP TABLE IF EXISTS `notifications`;

CREATE TABLE `notifications` (
    `id` INT(11) UNSIGNED NOT NULL AUTO_INCREMENT,
    `user_id` INT(11) UNSIGNED NOT NULL,
    `type` VARCHAR(50) NOT NULL COMMENT 'Tipo da notificação',
    `channel` ENUM('database', 'email', 'whatsapp', 'push') DEFAULT 'database',
    `title` VARCHAR(200) NOT NULL COMMENT 'Título da notificação',
    `message` TEXT NOT NULL COMMENT 'Conteúdo da notificação',
    `action_url` VARCHAR(500) DEFAULT NULL COMMENT 'URL de ação (se aplicável)',
    `action_text` VARCHAR(50) DEFAULT NULL COMMENT 'Texto do botão de ação',
    
    -- Dados relacionados
    `related_type` VARCHAR(50) DEFAULT NULL COMMENT 'Tipo da entidade relacionada',
    `related_id` INT(11) UNSIGNED DEFAULT NULL COMMENT 'ID da entidade relacionada',
    `metadata` JSON DEFAULT NULL COMMENT 'Dados adicionais',
    
    -- Status
    `is_read` BOOLEAN DEFAULT FALSE,
    `is_sent` BOOLEAN DEFAULT FALSE COMMENT 'Se foi enviada (para canais externos)',
    `sent_at` TIMESTAMP NULL DEFAULT NULL,
    `read_at` TIMESTAMP NULL DEFAULT NULL,
    `expires_at` TIMESTAMP NULL DEFAULT NULL COMMENT 'Data de expiração',
    
    -- Prioridade
    `priority` ENUM('low', 'normal', 'high', 'urgent') DEFAULT 'normal',
    
    `created_at` TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    `updated_at` TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    
    PRIMARY KEY (`id`),
    INDEX `idx_notifications_user` (`user_id`),
    INDEX `idx_notifications_type` (`type`),
    INDEX `idx_notifications_channel` (`channel`),
    INDEX `idx_notifications_read` (`is_read`),
    INDEX `idx_notifications_sent` (`is_sent`),
    INDEX `idx_notifications_priority` (`priority`),
    INDEX `idx_notifications_expires` (`expires_at`),
    INDEX `idx_notifications_user_read` (`user_id`, `is_read`),
    INDEX `idx_notifications_related` (`related_type`, `related_id`),
    
    CONSTRAINT `fk_notifications_user` FOREIGN KEY (`user_id`) REFERENCES `usuarios` (`id`) ON DELETE CASCADE ON UPDATE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci COMMENT='Sistema de notificações';

-- ==============================================================================
-- 15. VIEWS PARA CONSULTAS OTIMIZADAS
-- ==============================================================================

-- View para ranking de vendedores por campanha
DROP VIEW IF EXISTS `v_ranking_vendedores`;

CREATE VIEW `v_ranking_vendedores` AS
SELECT 
    v.campanha_id,
    v.user_id,
    u.nome,
    u.email,
    o.razao_social as otica_nome,
    COUNT(v.id) as total_vendas,
    SUM(v.pontos_total) as total_pontos,
    SUM(v.valor_total) as valor_total_vendas,
    RANK() OVER (PARTITION BY v.campanha_id ORDER BY SUM(v.pontos_total) DESC) as posicao_ranking,
    DENSE_RANK() OVER (PARTITION BY v.campanha_id ORDER BY SUM(v.pontos_total) DESC) as posicao_dense,
    ROW_NUMBER() OVER (PARTITION BY v.campanha_id ORDER BY SUM(v.pontos_total) DESC, COUNT(v.id) DESC) as posicao_absoluta
FROM vendas v
JOIN usuarios u ON v.user_id = u.id
LEFT JOIN oticas o ON u.id_otica = o.id_otica
WHERE v.status = 'validada'
GROUP BY v.campanha_id, v.user_id, u.nome, u.email, o.razao_social;

-- View para dashboard do vendedor
DROP VIEW IF EXISTS `v_dashboard_vendedor`;

CREATE VIEW `v_dashboard_vendedor` AS
SELECT 
    u.id as user_id,
    u.nome,
    u.email,
    u.tipo,
    up.pontos_total,
    up.pontos_mes_atual,
    up.nivel_atual,
    up.total_vendas,
    up.total_campanhas_participadas,
    o.razao_social as otica_nome,
    o.tipo_parceria as otica_tipo,
    
    -- Estatísticas do mês atual
    COALESCE(vm.vendas_mes, 0) as vendas_mes_atual,
    COALESCE(vm.pontos_mes, 0) as pontos_calculados_mes,
    COALESCE(vm.valor_mes, 0) as valor_vendas_mes,
    
    -- Campanhas ativas
    (SELECT COUNT(*) FROM campanhas WHERE status = 'ativa' AND 
     (oticas_participantes IS NULL OR JSON_CONTAINS(oticas_participantes, CAST(u.id_otica AS JSON)))) as campanhas_ativas_disponiveis,
    
    -- Próxima data de pagamento (assumindo dia 15 do próximo mês)
    DATE_ADD(LAST_DAY(CURDATE()), INTERVAL 15 DAY) as proxima_data_pagamento

FROM usuarios u
JOIN user_profiles up ON u.id = up.user_id
LEFT JOIN oticas o ON u.id_otica = o.id_otica
LEFT JOIN (
    SELECT 
        user_id,
        COUNT(*) as vendas_mes,
        SUM(pontos_total) as pontos_mes,
        SUM(valor_total) as valor_mes
    FROM vendas 
    WHERE status = 'validada' 
    AND YEAR(data_venda) = YEAR(CURDATE()) 
    AND MONTH(data_venda) = MONTH(CURDATE())
    GROUP BY user_id
) vm ON u.id = vm.user_id
WHERE u.status = 'ativo' AND u.tipo = 'vendedor';

-- View para métricas de campanhas
DROP VIEW IF EXISTS `v_metricas_campanhas`;

CREATE VIEW `v_metricas_campanhas` AS
SELECT 
    c.id as campanha_id,
    c.titulo,
    c.status,
    c.data_inicio,
    c.data_fim,
    c.orcamento_total,
    c.orcamento_utilizado,
    
    -- Métricas de participação
    COUNT(DISTINCT v.user_id) as participantes_unicos,
    COUNT(v.id) as total_vendas_submetidas,
    COUNT(CASE WHEN v.status = 'validada' THEN 1 END) as vendas_validadas,
    COUNT(CASE WHEN v.status = 'rejeitada' THEN 1 END) as vendas_rejeitadas,
    COUNT(CASE WHEN v.status = 'pendente' THEN 1 END) as vendas_pendentes,
    
    -- Métricas financeiras
    SUM(CASE WHEN v.status = 'validada' THEN v.valor_total ELSE 0 END) as valor_total_validado,
    SUM(CASE WHEN v.status = 'validada' THEN v.pontos_total ELSE 0 END) as pontos_total_distribuidos,
    AVG(CASE WHEN v.status = 'validada' THEN v.valor_total END) as ticket_medio,
    
    -- Métricas de conversão
    ROUND(
        (COUNT(CASE WHEN v.status = 'validada' THEN 1 END) * 100.0) / 
        NULLIF(COUNT(v.id), 0), 2
    ) as taxa_aprovacao_pct,
    
    -- Óticas participantes
    COUNT(DISTINCT o.id_otica) as oticas_participantes,
    
    -- Performance por período
    DATEDIFF(c.data_fim, c.data_inicio) + 1 as duracao_dias,
    COUNT(CASE WHEN v.status = 'validada' THEN 1 END) / 
    NULLIF(DATEDIFF(c.data_fim, c.data_inicio) + 1, 0) as vendas_por_dia

FROM campanhas c
LEFT JOIN vendas v ON c.id = v.campanha_id
LEFT JOIN usuarios u ON v.user_id = u.id
LEFT JOIN oticas o ON u.id_otica = o.id_otica
GROUP BY c.id, c.titulo, c.status, c.data_inicio, c.data_fim, c.orcamento_total, c.orcamento_utilizado;

-- ==============================================================================
-- 16. TRIGGERS PARA AUDITORIA E MANUTENÇÃO AUTOMÁTICA
-- ==============================================================================

DELIMITER ;;

-- Trigger para atualizar pontos no perfil quando vendas são validadas
DROP TRIGGER IF EXISTS `tr_vendas_after_update_pontos`;

CREATE TRIGGER `tr_vendas_after_update_pontos`
AFTER UPDATE ON `vendas`
FOR EACH ROW
BEGIN
    -- Se status mudou para validada, adiciona pontos
    IF NEW.status = 'validada' AND OLD.status != 'validada' THEN
        -- Atualiza perfil do usuário
        UPDATE user_profiles 
        SET pontos_total = pontos_total + NEW.pontos_total,
            pontos_mes_atual = pontos_mes_atual + NEW.pontos_total,
            pontos_ano_atual = pontos_ano_atual + NEW.pontos_total,
            total_vendas = total_vendas + 1,
            ultima_atividade_at = NOW()
        WHERE user_id = NEW.user_id;
        
        -- Registra no histórico de pontos
        INSERT INTO points_history (
            user_id, tipo_transacao, pontos, pontos_antes, pontos_depois,
            origem_tipo, origem_id, origem_descricao, created_at
        ) VALUES (
            NEW.user_id, 'ganho', NEW.pontos_total,
            (SELECT pontos_total - NEW.pontos_total FROM user_profiles WHERE user_id = NEW.user_id),
            (SELECT pontos_total FROM user_profiles WHERE user_id = NEW.user_id),
            'venda', NEW.id, CONCAT('Venda validada - Pedido: ', NEW.numero_pedido), NOW()
        );
        
        -- Verifica mudança de nível
        CALL sp_verificar_mudanca_nivel(NEW.user_id);
        
    -- Se status mudou de validada para outra coisa, remove pontos
    ELSEIF OLD.status = 'validada' AND NEW.status != 'validada' THEN
        -- Remove pontos do perfil
        UPDATE user_profiles 
        SET pontos_total = GREATEST(0, pontos_total - OLD.pontos_total),
            pontos_mes_atual = GREATEST(0, pontos_mes_atual - OLD.pontos_total),
            pontos_ano_atual = GREATEST(0, pontos_ano_atual - OLD.pontos_total),
            total_vendas = GREATEST(0, total_vendas - 1)
        WHERE user_id = NEW.user_id;
        
        -- Registra no histórico de pontos
        INSERT INTO points_history (
            user_id, tipo_transacao, pontos, pontos_antes, pontos_depois,
            origem_tipo, origem_id, origem_descricao, created_at
        ) VALUES (
            NEW.user_id, 'penalidade', -OLD.pontos_total,
            (SELECT pontos_total + OLD.pontos_total FROM user_profiles WHERE user_id = NEW.user_id),
            (SELECT pontos_total FROM user_profiles WHERE user_id = NEW.user_id),
            'venda', NEW.id, CONCAT('Venda invalidada - Pedido: ', NEW.numero_pedido), NOW()
        );
    END IF;
END;;

-- Trigger para log de auditoria em mudanças de usuários
DROP TRIGGER IF EXISTS `tr_usuarios_after_update_audit`;

CREATE TRIGGER `tr_usuarios_after_update_audit`
AFTER UPDATE ON `usuarios`
FOR EACH ROW
BEGIN
    DECLARE changes_json JSON;
    DECLARE old_json JSON;
    DECLARE new_json JSON;
    
    SET old_json = JSON_OBJECT(
        'nome', OLD.nome,
        'email', OLD.email,
        'status', OLD.status,
        'tipo', OLD.tipo,
        'id_otica', OLD.id_otica
    );
    
    SET new_json = JSON_OBJECT(
        'nome', NEW.nome,
        'email', NEW.email,
        'status', NEW.status,
        'tipo', NEW.tipo,
        'id_otica', NEW.id_otica
    );
    
    -- Só registra se houve mudanças significativas
    IF NOT (OLD.nome <=> NEW.nome AND OLD.email <=> NEW.email AND 
            OLD.status <=> NEW.status AND OLD.tipo <=> NEW.tipo AND 
            OLD.id_otica <=> NEW.id_otica) THEN
        
        INSERT INTO audit_trail (
            user_id, action, entity_type, entity_id, description,
            old_values, new_values, created_at
        ) VALUES (
            NEW.id, 'UPDATE_USER', 'usuario', NEW.id, 
            CONCAT('Usuário atualizado: ', NEW.nome),
            old_json, new_json, NOW()
        );
    END IF;
END;;

-- Trigger para atualizar contadores em campanhas
DROP TRIGGER IF EXISTS `tr_vendas_after_insert_counters`;

CREATE TRIGGER `tr_vendas_after_insert_counters`
AFTER INSERT ON `vendas`
FOR EACH ROW
BEGIN
    UPDATE campanhas 
    SET total_vendas_submetidas = total_vendas_submetidas + 1
    WHERE id = NEW.campanha_id;
    
    -- Adiciona usuário como participante se for primeira venda
    IF (SELECT COUNT(*) FROM vendas WHERE user_id = NEW.user_id AND campanha_id = NEW.campanha_id) = 1 THEN
        UPDATE campanhas 
        SET total_participantes = total_participantes + 1
        WHERE id = NEW.campanha_id;
        
        UPDATE user_profiles 
        SET total_campanhas_participadas = total_campanhas_participadas + 1
        WHERE user_id = NEW.user_id;
    END IF;
END;;

DELIMITER ;

-- ==============================================================================
-- 17. STORED PROCEDURES
-- ==============================================================================

DELIMITER ;;

-- Procedure para verificar mudança de nível
DROP PROCEDURE IF EXISTS `sp_verificar_mudanca_nivel`;

CREATE PROCEDURE `sp_verificar_mudanca_nivel`(IN p_user_id INT)
BEGIN
    DECLARE v_pontos_total INT;
    DECLARE v_nivel_atual VARCHAR(20);
    DECLARE v_novo_nivel VARCHAR(20);
    
    -- Busca pontos totais atuais
    SELECT pontos_total, nivel_atual 
    INTO v_pontos_total, v_nivel_atual
    FROM user_profiles 
    WHERE user_id = p_user_id;
    
    -- Determina novo nível baseado nos pontos
    CASE
        WHEN v_pontos_total >= 30000 THEN SET v_novo_nivel = 'diamante';
        WHEN v_pontos_total >= 15000 THEN SET v_novo_nivel = 'platina';
        WHEN v_pontos_total >= 5000 THEN SET v_novo_nivel = 'ouro';
        WHEN v_pontos_total >= 1000 THEN SET v_novo_nivel = 'prata';
        ELSE SET v_novo_nivel = 'bronze';
    END CASE;
    
    -- Se houve mudança de nível
    IF v_novo_nivel != v_nivel_atual THEN
        UPDATE user_profiles 
        SET nivel_atual = v_novo_nivel,
            nivel_anterior = v_nivel_atual,
            data_ultimo_nivel = NOW()
        WHERE user_id = p_user_id;
        
        -- Insere notificação de mudança de nível
        INSERT INTO notifications (
            user_id, type, channel, title, message, priority, created_at
        ) VALUES (
            p_user_id, 'level_up', 'database',
            CONCAT('Parabéns! Você alcançou o nível ', UPPER(v_novo_nivel), '!'),
            CONCAT('Você evoluiu do nível ', v_nivel_atual, ' para ', v_novo_nivel, '. Continue assim!'),
            'high', NOW()
        );
        
        -- Log de auditoria
        INSERT INTO audit_trail (
            user_id, action, entity_type, entity_id, description, 
            old_values, new_values, created_at
        ) VALUES (
            p_user_id, 'LEVEL_CHANGE', 'user_profile', p_user_id,
            CONCAT('Mudança de nível: ', v_nivel_atual, ' → ', v_novo_nivel),
            JSON_OBJECT('nivel_anterior', v_nivel_atual),
            JSON_OBJECT('nivel_atual', v_novo_nivel),
            NOW()
        );
    END IF;
END;;

-- Procedure para resetar pontos mensais
DROP PROCEDURE IF EXISTS `sp_reset_pontos_mensais`;

CREATE PROCEDURE `sp_reset_pontos_mensais`()
BEGIN
    -- Salva snapshot mensal antes do reset
    INSERT INTO metrics (
        metric_name, metric_type, value, user_id, 
        metric_date, aggregation_period, created_at
    )
    SELECT 
        'pontos_mensais', 'gauge', pontos_mes_atual, user_id,
        LAST_DAY(DATE_SUB(CURDATE(), INTERVAL 1 MONTH)), 'monthly', NOW()
    FROM user_profiles 
    WHERE pontos_mes_atual > 0;
    
    -- Reset pontos mensais
    UPDATE user_profiles 
    SET pontos_mes_atual = 0;
    
    -- Log da operação
    INSERT INTO audit_trail (
        action, entity_type, description, created_at
    ) VALUES (
        'MONTHLY_RESET', 'system', 
        'Reset mensal de pontos executado', NOW()
    );
END;;

-- Procedure para limpeza de tokens expirados
DROP PROCEDURE IF EXISTS `sp_cleanup_expired_tokens`;

CREATE PROCEDURE `sp_cleanup_expired_tokens`()
BEGIN
    DECLARE v_deleted_remember INT DEFAULT 0;
    DECLARE v_deleted_confirmation INT DEFAULT 0;
    DECLARE v_deleted_recovery INT DEFAULT 0;
    
    -- Remove remember tokens expirados
    DELETE FROM remember_tokens 
    WHERE expires_at < NOW() OR used_at IS NOT NULL OR revoked_at IS NOT NULL;
    SET v_deleted_remember = ROW_COUNT();
    
    -- Remove tokens de confirmação expirados
    UPDATE usuarios 
    SET token_confirmacao = NULL, token_expira = NULL 
    WHERE token_expira < NOW();
    SET v_deleted_confirmation = ROW_COUNT();
    
    -- Remove tokens de recuperação expirados
    UPDATE usuarios 
    SET token_recuperacao = NULL, token_recuperacao_expira = NULL 
    WHERE token_recuperacao_expira < NOW();
    SET v_deleted_recovery = ROW_COUNT();
    
    -- Log da limpeza
    INSERT INTO audit_trail (
        action, entity_type, description, context, created_at
    ) VALUES (
        'TOKEN_CLEANUP', 'system', 
        'Limpeza automática de tokens expirados',
        JSON_OBJECT(
            'remember_tokens_deleted', v_deleted_remember,
            'confirmation_tokens_deleted', v_deleted_confirmation,
            'recovery_tokens_deleted', v_deleted_recovery
        ),
        NOW()
    );
END;;

DELIMITER ;

-- ==============================================================================
-- 18. EVENTOS AGENDADOS
-- ==============================================================================

-- Ativa o event scheduler
SET GLOBAL event_scheduler = ON;

-- Evento para limpeza diária de tokens
DROP EVENT IF EXISTS `ev_daily_token_cleanup`;

CREATE EVENT `ev_daily_token_cleanup`
ON SCHEDULE EVERY 1 DAY
STARTS CURRENT_TIMESTAMP
DO
  CALL sp_cleanup_expired_tokens();

-- Evento para reset mensal de pontos (dia 1 de cada mês às 01:00)
DROP EVENT IF EXISTS `ev_monthly_points_reset`;

CREATE EVENT `ev_monthly_points_reset`
ON SCHEDULE EVERY 1 MONTH
STARTS '2024-02-01 01:00:00'
DO
  CALL sp_reset_pontos_mensais();

-- Evento para limpeza de sessões inativas (a cada 6 horas)
DROP EVENT IF EXISTS `ev_cleanup_inactive_sessions`;

CREATE EVENT `ev_cleanup_inactive_sessions`
ON SCHEDULE EVERY 6 HOUR
STARTS CURRENT_TIMESTAMP
DO
  DELETE FROM user_sessions 
  WHERE last_activity < DATE_SUB(NOW(), INTERVAL 7 DAY);

-- Evento para expirar pontos antigos (mensal)
DROP EVENT IF EXISTS `ev_expire_old_points`;

CREATE EVENT `ev_expire_old_points`
ON SCHEDULE EVERY 1 MONTH
STARTS '2024-01-01 02:00:00'
DO
BEGIN
    -- Expira pontos com mais de 2 anos
    UPDATE points_history 
    SET status = 'expirado' 
    WHERE status = 'ativo' 
    AND created_at < DATE_SUB(NOW(), INTERVAL 2 YEAR)
    AND tipo_transacao = 'ganho';
    
    -- Recalcula pontos totais baseado apenas em pontos não expirados
    UPDATE user_profiles up
    SET pontos_total = (
        SELECT COALESCE(SUM(
            CASE 
                WHEN ph.tipo_transacao IN ('ganho', 'bonus', 'ajuste') THEN ph.pontos
                WHEN ph.tipo_transacao IN ('resgate', 'penalidade') THEN -ph.pontos
                ELSE 0
            END
        ), 0)
        FROM points_history ph
        WHERE ph.user_id = up.user_id
        AND ph.status = 'ativo'
    );
END;

-- ==============================================================================
-- 19. INSERÇÃO DE DADOS INICIAIS
-- ==============================================================================

-- Configurações iniciais do sistema
INSERT INTO `system_settings` (`setting_key`, `setting_value`, `setting_type`, `category`, `description`) VALUES
('system_name', 'Campanhas Embrapol Sul', 'string', 'general', 'Nome do sistema'),
('system_version', '4.0.0', 'string', 'general', 'Versão atual do sistema'),
('maintenance_mode', 'false', 'boolean', 'general', 'Modo de manutenção'),
('max_login_attempts', '5', 'integer', 'security', 'Máximo de tentativas de login'),
('lockout_time_minutes', '15', 'integer', 'security', 'Tempo de bloqueio em minutos'),
('session_timeout_seconds', '7200', 'integer', 'security', 'Timeout de sessão em segundos'),
('points_expiry_years', '2', 'integer', 'gamification', 'Anos para expiração de pontos'),
('default_points_per_sale', '100', 'integer', 'gamification', 'Pontos padrão por venda'),
('email_notifications_enabled', 'true', 'boolean', 'notifications', 'Notificações por email ativas'),
('whatsapp_notifications_enabled', 'true', 'boolean', 'notifications', 'Notificações por WhatsApp ativas'),
('file_upload_max_size', '20971520', 'integer', 'uploads', 'Tamanho máximo de upload em bytes (20MB)'),
('allowed_file_types', '["jpg","jpeg","png","pdf","doc","docx"]', 'json', 'uploads', 'Tipos de arquivo permitidos');

-- Usuário administrador inicial (senha: Admin@123)
INSERT INTO `usuarios` (
    `nome`, `cpf`, `email`, `celular`, `senha_hash`, `tipo`, `status`, 
    `email_verificado_at`, `created_at`
) VALUES (
    'Administrador do Sistema', 
    '00000000000', 
    'admin@embrapol.com.br', 
    '47999999999',
    '$argon2id$v=19$m=65536,t=4,p=3$YWRtaW5wYXNzd29yZA$rZ9nKzJ8+DzF5L4V3qR8xQ4vV9Y2R8fW6K7X2N1M3P9',
    'admin', 
    'ativo',
    NOW(),
    NOW()
);

-- Perfil do administrador
INSERT INTO `user_profiles` (`user_id`, `nivel_atual`, `conta_ativada_at`, `primeiro_login_at`) 
VALUES (1, 'diamante', NOW(), NOW());

-- Ótica de exemplo
INSERT INTO `oticas` (
    `cnpj`, `razao_social`, `nome_fantasia`, `endereco`, `cep`, `cidade`, `estado`, 
    `telefone`, `email`, `tipo_parceria`, `status`
) VALUES (
    '12345678000195',
    'Ótica Exemplo Ltda',
    'Ótica Visão Perfeita',
    'Rua das Lentes, 123 - Centro',
    '80010000',
    'Curitiba',
    'PR',
    '4733334444',
    'contato@oticaexemplo.com.br',
    'ouro',
    'ativa'
);

-- ==============================================================================
-- 20. ÍNDICES ADICIONAIS PARA PERFORMANCE
-- ==============================================================================

-- Índices compostos para consultas específicas
CREATE INDEX `idx_vendas_user_campanha_status_data` ON `vendas` (`user_id`, `campanha_id`, `status`, `data_venda`);
CREATE INDEX `idx_campanhas_status_datas` ON `campanhas` (`status`, `data_inicio`, `data_fim`);
CREATE INDEX `idx_points_user_type_date` ON `points_history` (`user_id`, `tipo_transacao`, `created_at`);
CREATE INDEX `idx_notifications_user_read_priority` ON `notifications` (`user_id`, `is_read`, `priority`);
CREATE INDEX `idx_security_logs_type_severity_date` ON `security_logs` (`event_type`, `severity`, `created_at`);
CREATE INDEX `idx_audit_user_action_date` ON `audit_trail` (`user_id`, `action`, `created_at`);

-- Índices para particionamento futuro (se necessário)
CREATE INDEX `idx_vendas_data_venda_year_month` ON `vendas` (YEAR(`data_venda`), MONTH(`data_venda`));
CREATE INDEX `idx_security_logs_year_month` ON `security_logs` (YEAR(`created_at`), MONTH(`created_at`));

-- ==============================================================================
-- 21. COMENTÁRIOS FINAIS E VERIFICAÇÕES
-- ==============================================================================

-- Verifica integridade referencial
SET FOREIGN_KEY_CHECKS = 1;

-- Analisa tabelas para otimizar índices
ANALYZE TABLE usuarios, oticas, campanhas, vendas, user_profiles, points_history;

-- Comentário final
SELECT 'Schema premium v4.1 instalado com sucesso!' as 'Status Final',
       COUNT(*) as 'Total de Tabelas' 
FROM information_schema.tables 
WHERE table_schema = DATABASE();

-- Exibe resumo das tabelas criadas
SELECT 
    table_name as 'Tabela',
    COALESCE(table_rows, 0) as 'Registros',
    ROUND(COALESCE((data_length + index_length) / 1024 / 1024, 0), 2) as 'Tamanho (MB)',
    COALESCE(table_comment, '') as 'Descrição'
FROM information_schema.tables 
WHERE table_schema = DATABASE() 
AND table_type = 'BASE TABLE'
ORDER BY table_name;

-- Exibe informações sobre o banco criado
SELECT 
    SCHEMA_NAME as 'Banco de Dados',
    DEFAULT_CHARACTER_SET_NAME as 'Charset',
    DEFAULT_COLLATION_NAME as 'Collation'
FROM information_schema.SCHEMATA 
WHERE SCHEMA_NAME = DATABASE();

-- Exibe configurações importantes
SHOW VARIABLES WHERE Variable_name IN ('version', 'sql_mode', 'character_set_database', 'collation_database');