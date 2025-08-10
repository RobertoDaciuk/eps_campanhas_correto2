<?php
declare(strict_types=1);

/**
 * ==============================================================================
 * SISTEMA DE USUÁRIOS PREMIUM (Premium User System) - v4.0
 * ==============================================================================
 * Localização: /app/core/users.php
 * 
 * Aprimoramentos v4.0:
 * - Validação avançada de dados
 * - Sistema de avatar e perfil
 * - Histórico de alterações
 * - Compliance com LGPD
 * - Integração com sistema óptico
 * - Gamificação e pontuação
 */

// --- PREVENÇÃO DE ACESSO DIRETO ---
if (!defined('APP_INITIATED')) {
    http_response_code(403);
    exit('Forbidden');
}

// ==============================================================================
// 1. CLASSE PRINCIPAL DE USUÁRIO
// ==============================================================================

if (!class_exists('UserManager')) {
    class UserManager
    {
        private array $validationRules = [];
        private array $auditTrail = [];
        
        public function __construct()
        {
            $this->setupValidationRules();
        }
        
        /**
         * Define regras de validação por tipo de usuário
         */
        private function setupValidationRules(): void
        {
            $this->validationRules = [
                'nome' => [
                    'required' => true,
                    'min_length' => 2,
                    'max_length' => 120,
                    'pattern' => '/^[\p{L}\s\'\-\.]+$/u',
                    'message' => 'Nome deve conter apenas letras, espaços e acentos'
                ],
                'cpf' => [
                    'required' => true,
                    'length' => 11,
                    'numeric' => true,
                    'unique' => true,
                    'validation_function' => 'validateCpf'
                ],
                'email' => [
                    'required' => true,
                    'max_length' => 255,
                    'format' => 'email',
                    'unique' => true,
                    'domain_check' => true
                ],
                'celular' => [
                    'required' => true,
                    'validation_function' => 'validatePhone',
                    'format_function' => 'formatPhone'
                ],
                'senha' => [
                    'required' => true,
                    'min_length' => 8,
                    'strength_check' => true
                ]
            ];
        }
        
        /**
         * Valida dados do usuário
         */
        public function validateUserData(array $data, array $skipFields = []): array
        {
            $errors = [];
            $warnings = [];
            
            foreach ($this->validationRules as $field => $rules) {
                if (in_array($field, $skipFields)) {
                    continue;
                }
                
                $value = $data[$field] ?? null;
                $fieldErrors = $this->validateField($field, $value, $rules, $data);
                
                if (!empty($fieldErrors)) {
                    $errors[$field] = $fieldErrors;
                }
                
                // Validações específicas do ramo óptico
                if ($field === 'email') {
                    $domainWarning = $this->checkEmailDomainReputation($value);
                    if ($domainWarning) {
                        $warnings[$field] = $domainWarning;
                    }
                }
            }
            
            return [
                'errors' => $errors,
                'warnings' => $warnings,
                'is_valid' => empty($errors)
            ];
        }
        
        /**
         * Valida campo individual
         */
        private function validateField(string $field, mixed $value, array $rules, array $allData): array
        {
            $errors = [];
            
            // Campo obrigatório
            if ($rules['required'] && (empty($value) || $value === '')) {
                $errors[] = "Campo {$field} é obrigatório";
                return $errors; // Para se obrigatório e vazio
            }
            
            if (empty($value)) {
                return $errors; // Se não obrigatório e vazio, não valida mais
            }
            
            // Comprimento mínimo
            if (isset($rules['min_length']) && strlen($value) < $rules['min_length']) {
                $errors[] = "Campo {$field} deve ter pelo menos {$rules['min_length']} caracteres";
            }
            
            // Comprimento máximo
            if (isset($rules['max_length']) && strlen($value) > $rules['max_length']) {
                $errors[] = "Campo {$field} deve ter no máximo {$rules['max_length']} caracteres";
            }
            
            // Comprimento exato
            if (isset($rules['length']) && strlen($value) !== $rules['length']) {
                $errors[] = "Campo {$field} deve ter exatamente {$rules['length']} caracteres";
            }
            
            // Apenas números
            if (isset($rules['numeric']) && !ctype_digit($value)) {
                $errors[] = "Campo {$field} deve conter apenas números";
            }
            
            // Padrão regex
            if (isset($rules['pattern']) && !preg_match($rules['pattern'], $value)) {
                $message = $rules['message'] ?? "Formato inválido para {$field}";
                $errors[] = $message;
            }
            
            // Formato de email
            if (isset($rules['format']) && $rules['format'] === 'email') {
                if (!filter_var($value, FILTER_VALIDATE_EMAIL)) {
                    $errors[] = "E-mail em formato inválido";
                }
            }
            
            // Função de validação customizada
            if (isset($rules['validation_function']) && function_exists($rules['validation_function'])) {
                $validationFunction = $rules['validation_function'];
                if (!$validationFunction($value)) {
                    $errors[] = "Valor inválido para {$field}";
                }
            }
            
            // Verificação de unicidade
            if (isset($rules['unique']) && $rules['unique']) {
                if ($this->checkFieldUniqueness($field, $value, $allData['user_id'] ?? null)) {
                    $errors[] = "Este {$field} já está sendo usado por outro usuário";
                }
            }
            
            // Verificação de força da senha
            if (isset($rules['strength_check']) && $rules['strength_check']) {
                $strengthResult = isStrongPassword($value);
                if (!$strengthResult['valid']) {
                    $errors[] = "Senha não atende aos requisitos de segurança";
                }
            }
            
            // Verificação de domínio de email
            if (isset($rules['domain_check']) && $rules['domain_check']) {
                if (!isValidEmailDomain($value)) {
                    $errors[] = "Domínio de e-mail não é permitido";
                }
            }
            
            return $errors;
        }
        
        /**
         * Verifica unicidade de campo
         */
        private function checkFieldUniqueness(string $field, string $value, ?int $excludeUserId = null): bool
        {
            try {
                $sql = "SELECT COUNT(*) FROM usuarios WHERE {$field} = :value";
                $params = [':value' => $field === 'email' ? strtolower($value) : $value];
                
                if ($excludeUserId) {
                    $sql .= " AND id != :user_id";
                    $params[':user_id'] = $excludeUserId;
                }
                
                $stmt = dbQuery($sql, $params, 'read');
                return $stmt->fetchColumn() > 0;
                
            } catch (Exception $e) {
                logSecurityEvent('USER_VALIDATION_ERROR', 'Erro na verificação de unicidade', [
                    'field' => $field,
                    'error' => $e->getMessage()
                ]);
                return false; // Em caso de erro, assume que não é único
            }
        }
        
        /**
         * Verifica reputação do domínio de email
         */
        private function checkEmailDomainReputation(string $email): ?string
        {
            $domain = strtolower(substr(strrchr($email, '@'), 1));
            
            // Domínios com possíveis problemas no ramo óptico
            $suspiciousDomains = [
                'tempmail.org', 'guerrillamail.com', 'mailinator.com',
                '10minutemail.com', 'throwaway.email'
            ];
            
            if (in_array($domain, $suspiciousDomains)) {
                return 'Domínio de e-mail temporário detectado';
            }
            
            // Verifica se é domínio empresarial comum
            $businessDomains = ['gmail.com', 'hotmail.com', 'yahoo.com', 'outlook.com'];
            if (!in_array($domain, $businessDomains)) {
                // Pode ser domínio empresarial - sem warning
            }
            
            return null;
        }
    }
}

// ==============================================================================
// 2. FUNÇÕES DE CRIAÇÃO DE USUÁRIO
// ==============================================================================

if (!function_exists('criarNovoUsuario')) {
    /**
     * Cria novo usuário com validação completa
     */
    function criarNovoUsuario(array $dadosUsuario): ?string
    {
        $userManager = new UserManager();
        
        // 1. Validação completa dos dados
        $validation = $userManager->validateUserData($dadosUsuario);
        
        if (!$validation['is_valid']) {
            logSecurityEvent('USER_CREATE_VALIDATION_FAILED', 'Falha na validação de dados', [
                'errors' => $validation['errors'],
                'warnings' => $validation['warnings']
            ]);
            return null;
        }
        
        // 2. Log de warnings se existirem
        if (!empty($validation['warnings'])) {
            logSecurityEvent('USER_CREATE_WARNINGS', 'Avisos na criação de usuário', [
                'warnings' => $validation['warnings']
            ]);
        }
        
        // 3. Normalização e sanitização
        $userData = normalizeUserData($dadosUsuario);
        
        // 4. Validação da ótica
        $oticaValidation = validateOpticalShop($userData['cnpj']);
        if (!$oticaValidation['valid']) {
            logSecurityEvent('USER_CREATE_OPTICAL_INVALID', 'Ótica inválida', [
                'cnpj' => $userData['cnpj'],
                'reason' => $oticaValidation['reason']
            ]);
            return null;
        }
        
        $userData['id_otica'] = $oticaValidation['id_otica'];
        
        // 5. Geração de hash da senha
        $userData['senha_hash'] = hashPassword($userData['senha']);
        unset($userData['senha'], $userData['confirmar_senha']);
        
        // 6. Geração de token de confirmação
        $token = generateSecureToken(32, 'hex');
        $tokenExpiry = (new DateTimeImmutable('now'))
            ->add(new DateInterval('PT2H'))
            ->format('Y-m-d H:i:s');
        
        $userData['token_confirmacao'] = $token;
        $userData['token_expira'] = $tokenExpiry;
        $userData['status'] = 'pendente';
        $userData['tipo'] = 'vendedor';
        $userData['created_at'] = date('Y-m-d H:i:s');
        
        // 7. Persistência com transação
        try {
            return dbTransaction(function($pdo) use ($userData, $token) {
                // Inserção do usuário
                $userId = insertUser($userData);
                
                // Criação do perfil inicial
                createUserProfile($userId, $userData);
                
                // Log de auditoria
                auditUserAction('USER_CREATED', 'Novo usuário criado', [
                    'user_id' => $userId,
                    'email' => $userData['email'],
                    'cpf' => $userData['cpf'],
                    'id_otica' => $userData['id_otica']
                ]);
                
                logSecurityEvent('USER_CREATE_SUCCESS', 'Usuário criado com sucesso', [
                    'user_id' => $userId,
                    'email_hash' => hash('sha256', $userData['email']),
                    'cpf_hash' => hash('sha256', $userData['cpf']),
                    'id_otica' => $userData['id_otica']
                ]);
                
                return $token;
            });
            
        } catch (Exception $e) {
            logSecurityEvent('USER_CREATE_FAILURE', 'Falha na criação de usuário', [
                'error' => $e->getMessage(),
                'email_hash' => hash('sha256', $userData['email']),
                'cpf_hash' => hash('sha256', $userData['cpf'])
            ]);
            
            throw $e;
        }
    }
}

if (!function_exists('normalizeUserData')) {
    /**
     * Normaliza e sanitiza dados do usuário
     */
    function normalizeUserData(array $data): array
    {
        return [
            'nome' => sanitizeString(ucwords(strtolower(trim($data['nome']))), 120),
            'cpf' => preg_replace('/\D/', '', $data['cpf']),
            'email' => strtolower(trim($data['email'])),
            'celular' => preg_replace('/\D/', '', $data['celular']),
            'cnpj' => preg_replace('/\D/', '', $data['cnpj']),
            'senha' => $data['senha'],
            'confirmar_senha' => $data['confirmar_senha'] ?? ''
        ];
    }
}

if (!function_exists('validateOpticalShop')) {
    /**
     * Valida ótica no sistema
     */
    function validateOpticalShop(string $cnpj): array
    {
        try {
            if (!validateCnpj($cnpj)) {
                return ['valid' => false, 'reason' => 'CNPJ inválido'];
            }
            
            $stmt = dbQuery(
                "SELECT id_otica, razao_social, status, endereco FROM oticas WHERE cnpj = ? LIMIT 1",
                [$cnpj],
                'read'
            );
            
            $otica = $stmt->fetch();
            
            if (!$otica) {
                return ['valid' => false, 'reason' => 'Ótica não encontrada'];
            }
            
            if ($otica['status'] !== 'ativa') {
                return ['valid' => false, 'reason' => 'Ótica não está ativa'];
            }
            
            return [
                'valid' => true,
                'id_otica' => (int)$otica['id_otica'],
                'razao_social' => $otica['razao_social'],
                'endereco' => $otica['endereco']
            ];
            
        } catch (Exception $e) {
            logSecurityEvent('OPTICAL_VALIDATION_ERROR', 'Erro na validação da ótica', [
                'cnpj' => $cnpj,
                'error' => $e->getMessage()
            ]);
            
            return ['valid' => false, 'reason' => 'Erro interno na validação'];
        }
    }
}

if (!function_exists('insertUser')) {
    /**
     * Insere usuário na base de dados
     */
    function insertUser(array $userData): int
    {
        $fields = [
            'nome', 'cpf', 'email', 'celular', 'senha_hash', 'tipo', 'status',
            'id_otica', 'token_confirmacao', 'token_expira', 'created_at'
        ];
        
        $placeholders = str_repeat('?,', count($fields) - 1) . '?';
        $values = [];
        
        foreach ($fields as $field) {
            $values[] = $userData[$field] ?? null;
        }
        
        $sql = "INSERT INTO usuarios (" . implode(',', $fields) . ") VALUES ({$placeholders})";
        
        $pdo = getDbConnection();
        $stmt = $pdo->prepare($sql);
        $stmt->execute($values);
        
        return (int)$pdo->lastInsertId();
    }
}

if (!function_exists('createUserProfile')) {
    /**
     * Cria perfil inicial do usuário
     */
    function createUserProfile(int $userId, array $userData): void
    {
        $profileData = [
            'user_id' => $userId,
            'avatar_url' => null,
            'biografia' => null,
            'pontos_total' => 0,
            'nivel_atual' => 'bronze',
            'data_criacao' => date('Y-m-d H:i:s'),
            'preferencias' => json_encode([
                'notificacoes_email' => true,
                'notificacoes_whatsapp' => true,
                'tema' => 'escuro',
                'idioma' => 'pt_BR'
            ])
        ];
        
        try {
            $stmt = dbQuery(
                "INSERT INTO user_profiles (user_id, pontos_total, nivel_atual, data_criacao, preferencias) 
                 VALUES (?, ?, ?, ?, ?)",
                [
                    $profileData['user_id'],
                    $profileData['pontos_total'],
                    $profileData['nivel_atual'],
                    $profileData['data_criacao'],
                    $profileData['preferencias']
                ]
            );
            
            logSecurityEvent('USER_PROFILE_CREATED', 'Perfil de usuário criado', [
                'user_id' => $userId
            ]);
            
        } catch (Exception $e) {
            logSecurityEvent('USER_PROFILE_CREATE_ERROR', 'Erro ao criar perfil', [
                'user_id' => $userId,
                'error' => $e->getMessage()
            ]);
        }
    }
}

// ==============================================================================
// 3. SISTEMA DE ATIVAÇÃO DE CONTA
// ==============================================================================

if (!function_exists('ativarContaUsuario')) {
    /**
     * Ativa conta do usuário via token
     */
    function ativarContaUsuario(string $token): array
    {
        if (empty($token)) {
            return ['success' => false, 'message' => 'Token inválido'];
        }
        
        try {
            return dbTransaction(function($pdo) use ($token) {
                // Busca usuário pelo token
                $stmt = $pdo->prepare(
                    "SELECT id, nome, email, status, token_expira 
                     FROM usuarios 
                     WHERE token_confirmacao = ? AND status = 'pendente' 
                     LIMIT 1"
                );
                $stmt->execute([$token]);
                $user = $stmt->fetch();
                
                if (!$user) {
                    logSecurityEvent('ACTIVATION_TOKEN_INVALID', 'Token de ativação inválido', [
                        'token_hash' => hash('sha256', $token)
                    ]);
                    return ['success' => false, 'message' => 'Token inválido ou já utilizado'];
                }
                
                // Verifica expiração
                $now = new DateTimeImmutable();
                $expiry = new DateTimeImmutable($user['token_expira']);
                
                if ($now > $expiry) {
                    logSecurityEvent('ACTIVATION_TOKEN_EXPIRED', 'Token de ativação expirado', [
                        'user_id' => $user['id'],
                        'expired_at' => $user['token_expira']
                    ]);
                    return ['success' => false, 'message' => 'Token expirado. Solicite um novo link de ativação'];
                }
                
                // Ativa a conta
                $updateStmt = $pdo->prepare(
                    "UPDATE usuarios 
                     SET status = 'ativo', 
                         token_confirmacao = NULL, 
                         token_expira = NULL,
                         email_verificado_at = NOW(),
                         updated_at = NOW()
                     WHERE id = ?"
                );
                $updateStmt->execute([$user['id']]);
                
                // Atualiza perfil
                $profileStmt = $pdo->prepare(
                    "UPDATE user_profiles 
                     SET conta_ativada_at = NOW() 
                     WHERE user_id = ?"
                );
                $profileStmt->execute([$user['id']]);
                
                // Log de sucesso
                logSecurityEvent('ACCOUNT_ACTIVATED', 'Conta ativada com sucesso', [
                    'user_id' => $user['id'],
                    'email_hash' => hash('sha256', $user['email'])
                ]);
                
                auditUserAction('ACCOUNT_ACTIVATED', 'Conta ativada via email', [
                    'user_id' => $user['id']
                ]);
                
                return [
                    'success' => true,
                    'message' => 'Conta ativada com sucesso! Você já pode fazer login.',
                    'user' => [
                        'id' => $user['id'],
                        'nome' => $user['nome'],
                        'email' => $user['email']
                    ]
                ];
            });
            
        } catch (Exception $e) {
            logSecurityEvent('ACTIVATION_ERROR', 'Erro na ativação de conta', [
                'token_hash' => hash('sha256', $token),
                'error' => $e->getMessage()
            ]);
            
            return ['success' => false, 'message' => 'Erro interno. Tente novamente mais tarde.'];
        }
    }
}

if (!function_exists('reenviarTokenAtivacao')) {
    /**
     * Reenvia token de ativação
     */
    function reenviarTokenAtivacao(string $email): array
    {
        try {
            $email = strtolower(trim($email));
            
            if (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
                return ['success' => false, 'message' => 'E-mail inválido'];
            }
            
            return dbTransaction(function($pdo) use ($email) {
                // Busca usuário pendente
                $stmt = $pdo->prepare(
                    "SELECT id, nome, email, status 
                     FROM usuarios 
                     WHERE email = ? AND status = 'pendente' 
                     LIMIT 1"
                );
                $stmt->execute([$email]);
                $user = $stmt->fetch();
                
                if (!$user) {
                    // Não revela se email existe ou não por segurança
                    return ['success' => true, 'message' => 'Se o e-mail estiver registrado, você receberá um novo link de ativação.'];
                }
                
                // Gera novo token
                $newToken = generateSecureToken(32, 'hex');
                $newExpiry = (new DateTimeImmutable('now'))
                    ->add(new DateInterval('PT2H'))
                    ->format('Y-m-d H:i:s');
                
                // Atualiza token
                $updateStmt = $pdo->prepare(
                    "UPDATE usuarios 
                     SET token_confirmacao = ?, token_expira = ?, updated_at = NOW() 
                     WHERE id = ?"
                );
                $updateStmt->execute([$newToken, $newExpiry, $user['id']]);
                
                // Envia novo email
                $emailSent = enviarEmailAtivacao($user['email'], $user['nome'], $newToken);
                
                logSecurityEvent('ACTIVATION_TOKEN_RESENT', 'Token de ativação reenviado', [
                    'user_id' => $user['id'],
                    'email_sent' => $emailSent
                ]);
                
                return ['success' => true, 'message' => 'Novo link de ativação enviado para seu e-mail.'];
            });
            
        } catch (Exception $e) {
            logSecurityEvent('ACTIVATION_RESEND_ERROR', 'Erro no reenvio de ativação', [
                'email_hash' => hash('sha256', $email),
                'error' => $e->getMessage()
            ]);
            
            return ['success' => false, 'message' => 'Erro interno. Tente novamente mais tarde.'];
        }
    }
}

// ==============================================================================
// 4. SISTEMA DE PERFIL DO USUÁRIO
// ==============================================================================

if (!function_exists('getUserProfile')) {
    /**
     * Retorna perfil completo do usuário
     */
    function getUserProfile(int $userId): ?array
    {
        try {
            $stmt = dbQuery(
                "SELECT u.*, up.*, o.razao_social as otica_nome, o.endereco as otica_endereco
                 FROM usuarios u
                 LEFT JOIN user_profiles up ON u.id = up.user_id
                 LEFT JOIN oticas o ON u.id_otica = o.id_otica
                 WHERE u.id = ? AND u.status != 'excluido'
                 LIMIT 1",
                [$userId],
                'read'
            );
            
            $profile = $stmt->fetch();
            
            if (!$profile) {
                return null;
            }
            
            // Processa preferências JSON
            if ($profile['preferencias']) {
                $profile['preferencias'] = json_decode($profile['preferencias'], true);
            }
            
            // Remove dados sensíveis
            unset($profile['senha_hash'], $profile['token_confirmacao']);
            
            // Adiciona estatísticas de vendas
            $profile['estatisticas'] = getUserStatistics($userId);
            
            // Adiciona progresso de gamificação
            $profile['gamificacao'] = getUserGamificationData($userId);
            
            return $profile;
            
        } catch (Exception $e) {
            logSecurityEvent('USER_PROFILE_ERROR', 'Erro ao buscar perfil', [
                'user_id' => $userId,
                'error' => $e->getMessage()
            ]);
            
            return null;
        }
    }
}

if (!function_exists('updateUserProfile')) {
    /**
     * Atualiza perfil do usuário
     */
    function updateUserProfile(int $userId, array $data): array
    {
        try {
            $allowedFields = ['nome', 'celular', 'avatar_url', 'biografia'];
            $updates = [];
            $params = [];
            
            foreach ($allowedFields as $field) {
                if (isset($data[$field])) {
                    $updates[] = "{$field} = ?";
                    $params[] = $field === 'nome' ? sanitizeString($data[$field], 120) : $data[$field];
                }
            }
            
            if (empty($updates)) {
                return ['success' => false, 'message' => 'Nenhum campo válido para atualizar'];
            }
            
            $params[] = $userId;
            
            return dbTransaction(function($pdo) use ($updates, $params, $userId, $data) {
                // Atualiza tabela usuarios
                $sql = "UPDATE usuarios SET " . implode(', ', $updates) . ", updated_at = NOW() WHERE id = ?";
                $stmt = $pdo->prepare($sql);
                $stmt->execute($params);
                
                // Atualiza preferências se fornecidas
                if (isset($data['preferencias'])) {
                    $prefStmt = $pdo->prepare(
                        "UPDATE user_profiles SET preferencias = ? WHERE user_id = ?"
                    );
                    $prefStmt->execute([json_encode($data['preferencias']), $userId]);
                }
                
                auditUserAction('PROFILE_UPDATED', 'Perfil atualizado', [
                    'user_id' => $userId,
                    'updated_fields' => array_keys($data)
                ]);
                
                return ['success' => true, 'message' => 'Perfil atualizado com sucesso'];
            });
            
        } catch (Exception $e) {
            logSecurityEvent('PROFILE_UPDATE_ERROR', 'Erro na atualização de perfil', [
                'user_id' => $userId,
                'error' => $e->getMessage()
            ]);
            
            return ['success' => false, 'message' => 'Erro interno. Tente novamente.'];
        }
    }
}

// ==============================================================================
// 5. SISTEMA DE GAMIFICAÇÃO
// ==============================================================================

if (!function_exists('getUserStatistics')) {
    /**
     * Retorna estatísticas do usuário
     */
    function getUserStatistics(int $userId): array
    {
        try {
            // Estatísticas básicas
            $stats = [
                'total_vendas' => 0,
                'pontos_mes_atual' => 0,
                'pontos_total' => 0,
                'campanhas_participadas' => 0,
                'meta_mensal' => 0,
                'progresso_meta' => 0,
                'ranking_otica' => 0,
                'nivel_atual' => 'bronze'
            ];
            
            // Total de vendas validadas
            $stmt = dbQuery(
                "SELECT COUNT(*) as total FROM vendas WHERE user_id = ? AND status = 'validada'",
                [$userId],
                'read'
            );
            $stats['total_vendas'] = (int)$stmt->fetchColumn();
            
            // Pontos do mês atual
            $stmt = dbQuery(
                "SELECT SUM(pontos) as pontos FROM vendas 
                 WHERE user_id = ? AND status = 'validada' 
                 AND DATE_FORMAT(created_at, '%Y-%m') = DATE_FORMAT(NOW(), '%Y-%m')",
                [$userId],
                'read'
            );
            $stats['pontos_mes_atual'] = (int)($stmt->fetchColumn() ?: 0);
            
            // Pontos total
            $stmt = dbQuery(
                "SELECT pontos_total FROM user_profiles WHERE user_id = ?",
                [$userId],
                'read'
            );
            $stats['pontos_total'] = (int)($stmt->fetchColumn() ?: 0);
            
            return $stats;
            
        } catch (Exception $e) {
            logSecurityEvent('USER_STATS_ERROR', 'Erro ao buscar estatísticas', [
                'user_id' => $userId,
                'error' => $e->getMessage()
            ]);
            
            return [];
        }
    }
}

if (!function_exists('getUserGamificationData')) {
    /**
     * Retorna dados de gamificação
     */
    function getUserGamificationData(int $userId): array
    {
        $levels = [
            'bronze' => ['min_points' => 0, 'max_points' => 999, 'benefits' => ['Acesso básico']],
            'prata' => ['min_points' => 1000, 'max_points' => 4999, 'benefits' => ['Bônus de 5%', 'Relatórios avançados']],
            'ouro' => ['min_points' => 5000, 'max_points' => 14999, 'benefits' => ['Bônus de 10%', 'Suporte prioritário']],
            'platina' => ['min_points' => 15000, 'max_points' => 29999, 'benefits' => ['Bônus de 15%', 'Eventos exclusivos']],
            'diamante' => ['min_points' => 30000, 'max_points' => PHP_INT_MAX, 'benefits' => ['Bônus de 20%', 'Clube VIP']]
        ];
        
        try {
            $stmt = dbQuery(
                "SELECT pontos_total, nivel_atual FROM user_profiles WHERE user_id = ?",
                [$userId],
                'read'
            );
            $profile = $stmt->fetch();
            
            if (!$profile) {
                return [];
            }
            
            $totalPoints = (int)$profile['pontos_total'];
            $currentLevel = $profile['nivel_atual'] ?: 'bronze';
            
            // Calcula próximo nível
            $nextLevel = null;
            $progressToNext = 0;
            
            foreach ($levels as $level => $data) {
                if ($totalPoints >= $data['min_points'] && $totalPoints <= $data['max_points']) {
                    $currentLevel = $level;
                }
                
                if ($totalPoints < $data['min_points'] && !$nextLevel) {
                    $nextLevel = $level;
                    $pointsNeeded = $data['min_points'] - $totalPoints;
                    $progressToNext = max(0, 100 - (($pointsNeeded / $data['min_points']) * 100));
                    break;
                }
            }
            
            return [
                'nivel_atual' => $currentLevel,
                'pontos_total' => $totalPoints,
                'proximo_nivel' => $nextLevel,
                'progresso_proximo_nivel' => round($progressToNext, 1),
                'beneficios_atual' => $levels[$currentLevel]['benefits'] ?? [],
                'beneficios_proximo' => $nextLevel ? $levels[$nextLevel]['benefits'] : [],
                'levels_info' => $levels
            ];
            
        } catch (Exception $e) {
            logSecurityEvent('GAMIFICATION_ERROR', 'Erro nos dados de gamificação', [
                'user_id' => $userId,
                'error' => $e->getMessage()
            ]);
            
            return [];
        }
    }
}

if (!function_exists('updateUserPoints')) {
    /**
     * Atualiza pontuação do usuário
     */
    function updateUserPoints(int $userId, int $points, string $reason = 'Venda validada'): bool
    {
        try {
            return dbTransaction(function($pdo) use ($userId, $points, $reason) {
                // Atualiza pontos totais
                $stmt = $pdo->prepare(
                    "UPDATE user_profiles 
                     SET pontos_total = pontos_total + ?, updated_at = NOW() 
                     WHERE user_id = ?"
                );
                $stmt->execute([$points, $userId]);
                
                // Verifica se houve mudança de nível
                $newGamificationData = getUserGamificationData($userId);
                
                // Atualiza nível se necessário
                if (isset($newGamificationData['nivel_atual'])) {
                    $levelStmt = $pdo->prepare(
                        "UPDATE user_profiles SET nivel_atual = ? WHERE user_id = ?"
                    );
                    $levelStmt->execute([$newGamificationData['nivel_atual'], $userId]);
                }
                
                // Registra histórico de pontos
                $historyStmt = $pdo->prepare(
                    "INSERT INTO points_history (user_id, points, reason, created_at) VALUES (?, ?, ?, NOW())"
                );
                $historyStmt->execute([$userId, $points, $reason]);
                
                auditUserAction('POINTS_UPDATED', 'Pontuação atualizada', [
                    'user_id' => $userId,
                    'points_added' => $points,
                    'reason' => $reason
                ]);
                
                return true;
            });
            
        } catch (Exception $e) {
            logSecurityEvent('POINTS_UPDATE_ERROR', 'Erro na atualização de pontos', [
                'user_id' => $userId,
                'points' => $points,
                'error' => $e->getMessage()
            ]);
            
            return false;
        }
    }
}

// ==============================================================================
// 6. SISTEMA DE BUSCA E LISTAGEM
// ==============================================================================

if (!function_exists('searchUsers')) {
    /**
     * Busca usuários com filtros avançados
     */
    function searchUsers(array $filters = [], int $page = 1, int $limit = 20): array
    {
        try {
            $where = ['u.status != ?'];
            $params = ['excluido'];
            
            // Filtros disponíveis
            if (!empty($filters['nome'])) {
                $where[] = 'u.nome LIKE ?';
                $params[] = '%' . $filters['nome'] . '%';
            }
            
            if (!empty($filters['email'])) {
                $where[] = 'u.email LIKE ?';
                $params[] = '%' . $filters['email'] . '%';
            }
            
            if (!empty($filters['tipo'])) {
                $where[] = 'u.tipo = ?';
                $params[] = $filters['tipo'];
            }
            
            if (!empty($filters['status'])) {
                $where[] = 'u.status = ?';
                $params[] = $filters['status'];
            }
            
            if (!empty($filters['id_otica'])) {
                $where[] = 'u.id_otica = ?';
                $params[] = (int)$filters['id_otica'];
            }
            
            $whereClause = implode(' AND ', $where);
            $offset = ($page - 1) * $limit;
            
            // Busca usuários
            $sql = "SELECT u.id, u.nome, u.email, u.cpf, u.celular, u.tipo, u.status, 
                           u.created_at, u.last_successful_login, o.razao_social as otica_nome,
                           up.pontos_total, up.nivel_atual
                    FROM usuarios u
                    LEFT JOIN oticas o ON u.id_otica = o.id_otica
                    LEFT JOIN user_profiles up ON u.id = up.user_id
                    WHERE {$whereClause}
                    ORDER BY u.created_at DESC
                    LIMIT ? OFFSET ?";
            
            $params[] = $limit;
            $params[] = $offset;
            
            $stmt = dbQuery($sql, $params, 'read');
            $users = $stmt->fetchAll();
            
            // Conta total
            $countSql = "SELECT COUNT(*) FROM usuarios u WHERE {$whereClause}";
            $countParams = array_slice($params, 0, -2); // Remove limit e offset
            $countStmt = dbQuery($countSql, $countParams, 'read');
            $total = (int)$countStmt->fetchColumn();
            
            return [
                'users' => $users,
                'pagination' => [
                    'current_page' => $page,
                    'per_page' => $limit,
                    'total' => $total,
                    'total_pages' => ceil($total / $limit)
                ]
            ];
            
        } catch (Exception $e) {
            logSecurityEvent('USER_SEARCH_ERROR', 'Erro na busca de usuários', [
                'filters' => $filters,
                'error' => $e->getMessage()
            ]);
            
            return ['users' => [], 'pagination' => ['total' => 0]];
        }
    }
}