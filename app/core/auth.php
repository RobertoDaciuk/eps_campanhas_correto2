<?php
declare(strict_types=1);

/**
 * ==============================================================================
 * NÚCLEO DE AUTENTICAÇÃO PREMIUM (Premium Authentication Core) - v4.0
 * ==============================================================================
 * Localização: /app/core/auth.php
 * 
 * Aprimoramentos v4.0:
 * - Sistema de fingerprinting de sessão
 * - Detecção de anomalias comportamentais
 * - Rate limiting inteligente por usuário
 * - Auditoria de segurança avançada
 * - Proteção contra ataques de timing
 * - Sistema de confiança adaptativo
 */

// --- PREVENÇÃO DE ACESSO DIRETO ---
if (!defined('APP_INITIATED')) {
    http_response_code(403);
    exit('Forbidden');
}

// ==============================================================================
// 1. CONFIGURAÇÕES DE SEGURANÇA DINÂMICAS
// ==============================================================================

// Constantes adaptáveis baseadas no ambiente
$securityConfig = [
    'production' => [
        'max_attempts' => 3,
        'lockout_time' => 30, // minutos
        'session_timeout' => 7200, // 2 horas
        'require_2fa' => false, // Futuro
        'max_concurrent_sessions' => 3
    ],
    'staging' => [
        'max_attempts' => 5,
        'lockout_time' => 15,
        'session_timeout' => 14400, // 4 horas
        'require_2fa' => false,
        'max_concurrent_sessions' => 5
    ],
    'development' => [
        'max_attempts' => 10,
        'lockout_time' => 5,
        'session_timeout' => 28800, // 8 horas
        'require_2fa' => false,
        'max_concurrent_sessions' => 10
    ]
];

$currentConfig = $securityConfig[ENVIRONMENT] ?? $securityConfig['production'];

// Define constantes dinâmicas
if (!defined('MAX_LOGIN_ATTEMPTS')) {
    define('MAX_LOGIN_ATTEMPTS', $currentConfig['max_attempts']);
}
if (!defined('LOCKOUT_TIME_MINUTES')) {
    define('LOCKOUT_TIME_MINUTES', $currentConfig['lockout_time']);
}
if (!defined('MAX_CONCURRENT_SESSIONS')) {
    define('MAX_CONCURRENT_SESSIONS', $currentConfig['max_concurrent_sessions']);
}

// ==============================================================================
// 2. FUNÇÕES DE NORMALIZAÇÃO E SANITIZAÇÃO
// ==============================================================================

if (!function_exists('normalizeIdentifier')) {
    /**
     * Normalização robusta de identificadores com validação
     */
    function normalizeIdentifier(string $identifier): array
    {
        $identifier = trim($identifier);
        
        if (empty($identifier)) {
            return [null, null, false];
        }
        
        // Detecta tipo de identificador
        $isEmail = filter_var($identifier, FILTER_VALIDATE_EMAIL) !== false;
        
        if ($isEmail) {
            $normalized = strtolower($identifier);
            
            // Validação adicional de domínio
            if (!isValidEmailDomain($normalized)) {
                logSecurityEvent('SUSPICIOUS_EMAIL_DOMAIN', 'Tentativa de login com domínio temporário', [
                    'email_domain' => substr(strrchr($normalized, '@'), 1),
                    'email_hash' => hash('sha256', $normalized)
                ]);
            }
            
            return ['email', $normalized, true];
        }
        
        // Trata como CPF
        $cpfOnly = preg_replace('/\D/', '', $identifier);
        
        if (strlen($cpfOnly) !== 11) {
            return [null, null, false];
        }
        
        // Validação de CPF
        if (!validateCpf($cpfOnly)) {
            return [null, null, false];
        }
        
        return ['cpf', $cpfOnly, true];
    }
}

// ==============================================================================
// 3. FINGERPRINTING DE SESSÃO E DISPOSITIVO
// ==============================================================================

if (!function_exists('generateSessionFingerprint')) {
    /**
     * Gera fingerprint único da sessão para detecção de anomalias
     */
    function generateSessionFingerprint(): string
    {
        $components = [
            $_SERVER['HTTP_USER_AGENT'] ?? '',
            $_SERVER['HTTP_ACCEPT_LANGUAGE'] ?? '',
            $_SERVER['HTTP_ACCEPT_ENCODING'] ?? '',
            $_SERVER['REMOTE_ADDR'] ?? '',
            // Não incluir HTTP_X_FORWARDED_FOR por ser facilmente falsificável
        ];
        
        return hash('sha256', implode('|', $components));
    }
}

if (!function_exists('validateSessionFingerprint')) {
    /**
     * Valida fingerprint da sessão atual
     */
    function validateSessionFingerprint(): bool
    {
        if (!isset($_SESSION['fingerprint'])) {
            return true; // Primeira validação, aceita
        }
        
        $currentFingerprint = generateSessionFingerprint();
        $storedFingerprint = $_SESSION['fingerprint'];
        
        if ($currentFingerprint !== $storedFingerprint) {
            logSecurityEvent('SESSION_FINGERPRINT_MISMATCH', 'Possível hijacking de sessão detectado', [
                'user_id' => $_SESSION['user_id'] ?? null,
                'stored_fingerprint' => $storedFingerprint,
                'current_fingerprint' => $currentFingerprint,
                'ip_address' => $_SERVER['REMOTE_ADDR'] ?? 'unknown'
            ]);
            
            return false;
        }
        
        return true;
    }
}

// ==============================================================================
// 4. SISTEMA DE BUSCA DE USUÁRIO OTIMIZADO
// ==============================================================================

if (!function_exists('findUserByIdentifier')) {
    /**
     * Localiza usuário com cache inteligente e proteção contra timing attacks
     */
    function findUserByIdentifier(string $identifier): ?array
    {
        $startTime = microtime(true);
        
        try {
            [$type, $normalized, $isValid] = normalizeIdentifier($identifier);
            
            if (!$isValid || !$normalized) {
                // Simula tempo de consulta para evitar timing attacks
                usleep(random_int(100000, 300000)); // 100-300ms
                return null;
            }
            
            // Cache de consulta para reduzir carga no banco
            $cacheKey = "user_lookup_{$type}_{$normalized}";
            $cached = cacheGet($cacheKey, 300); // 5 minutos
            
            if ($cached !== null) {
                return $cached;
            }
            
            $pdo = getDbConnection();
            
            $sql = "SELECT u.*, o.razao_social as otica_nome, o.status as otica_status
                    FROM usuarios u 
                    LEFT JOIN oticas o ON u.id_otica = o.id_otica
                    WHERE u.{$type} = :identifier AND u.status != 'excluido'
                    LIMIT 1";
            
            $stmt = $pdo->prepare($sql);
            $stmt->bindValue(':identifier', $normalized);
            $stmt->execute();
            
            $user = $stmt->fetch();
            $result = $user ?: null;
            
            // Cache apenas por tempo limitado
            cacheSet($cacheKey, $result, 300);
            
            // Log de tentativa de busca
            logSecurityEvent('USER_LOOKUP', 'Busca de usuário realizada', [
                'identifier_type' => $type,
                'identifier_hash' => hash('sha256', $normalized),
                'found' => $result !== null,
                'execution_time' => round((microtime(true) - $startTime) * 1000, 2) . 'ms'
            ]);
            
            return $result;
            
        } catch (PDOException $e) {
            // Simula tempo normal em caso de erro
            usleep(random_int(100000, 300000));
            
            logSecurityEvent('DB_QUERY_FAILURE', 'Falha na busca de usuário', [
                'error' => $e->getMessage(),
                'identifier_hash' => hash('sha256', $identifier),
                'execution_time' => round((microtime(true) - $startTime) * 1000, 2) . 'ms'
            ]);
            
            return null;
        }
    }
}

// ==============================================================================
// 5. SISTEMA DE BLOQUEIO INTELIGENTE
// ==============================================================================

if (!function_exists('isAccountLocked')) {
    /**
     * Verificação de bloqueio com escalação inteligente
     */
    function isAccountLocked(array $user): bool
    {
        $attempts = (int)($user['failed_login_attempts'] ?? 0);
        
        if ($attempts < MAX_LOGIN_ATTEMPTS) {
            return false;
        }
        
        $lastFailedLogin = $user['last_failed_login'] ?? null;
        if (empty($lastFailedLogin)) {
            return false;
        }
        
        try {
            $lastAttemptTime = new DateTimeImmutable($lastFailedLogin);
            $now = new DateTimeImmutable('now');
            $minutesSinceLastAttempt = ($now->getTimestamp() - $lastAttemptTime->getTimestamp()) / 60;
            
            // Sistema de escalação: mais tentativas = mais tempo de bloqueio
            $lockoutMultiplier = min(floor($attempts / MAX_LOGIN_ATTEMPTS), 5); // Max 5x
            $effectiveLockoutTime = LOCKOUT_TIME_MINUTES * (1 + $lockoutMultiplier);
            
            $isLocked = $minutesSinceLastAttempt < $effectiveLockoutTime;
            
            if ($isLocked) {
                $remainingMinutes = ceil($effectiveLockoutTime - $minutesSinceLastAttempt);
                
                logSecurityEvent('ACCOUNT_LOCKED_CHECK', 'Verificação de conta bloqueada', [
                    'user_id' => $user['id'],
                    'attempts' => $attempts,
                    'lockout_multiplier' => $lockoutMultiplier,
                    'effective_lockout_time' => $effectiveLockoutTime,
                    'remaining_minutes' => $remainingMinutes
                ]);
            }
            
            return $isLocked;
            
        } catch (Throwable $e) {
            // Em caso de erro, não bloqueia (fail-open)
            logSecurityEvent('LOCKOUT_CHECK_ERROR', 'Erro na verificação de bloqueio', [
                'user_id' => $user['id'],
                'error' => $e->getMessage()
            ]);
            
            return false;
        }
    }
}

if (!function_exists('recordFailedLoginAttempt')) {
    /**
     * Registro de tentativa falha com análise de padrões
     */
    function recordFailedLoginAttempt(string $identifier): void
    {
        try {
            [$type, $normalized, $isValid] = normalizeIdentifier($identifier);
            
            if (!$isValid || !$normalized) {
                return;
            }
            
            $pdo = getDbConnection();
            $now = new DateTimeImmutable('now');
            
            // Análise de padrão: verifica tentativas recentes
            $recentAttemptsQuery = "
                SELECT COUNT(*) as recent_count 
                FROM usuarios 
                WHERE {$type} = :identifier 
                AND last_failed_login > DATE_SUB(NOW(), INTERVAL 1 HOUR)
            ";
            
            $stmt = $pdo->prepare($recentAttemptsQuery);
            $stmt->bindValue(':identifier', $normalized);
            $stmt->execute();
            $recentAttempts = (int)$stmt->fetchColumn();
            
            // Atualiza contador
            $sql = "UPDATE usuarios 
                    SET failed_login_attempts = failed_login_attempts + 1,
                        last_failed_login = NOW()
                    WHERE {$type} = :identifier";
            
            $stmt = $pdo->prepare($sql);
            $stmt->bindValue(':identifier', $normalized);
            $stmt->execute();
            
            // Detecta possível ataque de força bruta
            if ($recentAttempts >= (MAX_LOGIN_ATTEMPTS * 2)) {
                logSecurityEvent('BRUTE_FORCE_DETECTED', 'Possível ataque de força bruta detectado', [
                    'identifier_type' => $type,
                    'identifier_hash' => hash('sha256', $normalized),
                    'recent_attempts' => $recentAttempts,
                    'ip_address' => $_SERVER['REMOTE_ADDR'] ?? 'unknown'
                ]);
                
                // Rate limit mais agressivo para este IP
                $_SESSION['aggressive_rate_limit'] = true;
            }
            
            logSecurityEvent('FAILED_LOGIN_ATTEMPT', 'Tentativa de login registrada', [
                'identifier_type' => $type,
                'identifier_hash' => hash('sha256', $normalized),
                'recent_attempts_hour' => $recentAttempts
            ]);
            
        } catch (PDOException $e) {
            logSecurityEvent('DB_UPDATE_FAILURE', 'Falha ao registrar tentativa de login', [
                'error' => $e->getMessage(),
                'identifier_hash' => hash('sha256', $identifier)
            ]);
        }
    }
}

if (!function_exists('resetLoginAttempts')) {
    /**
     * Reset de tentativas com log de sucesso
     */
    function resetLoginAttempts(int $userId): void
    {
        try {
            $pdo = getDbConnection();
            
            // Busca dados atuais para log
            $currentDataQuery = "SELECT failed_login_attempts, last_failed_login FROM usuarios WHERE id = :userId";
            $stmt = $pdo->prepare($currentDataQuery);
            $stmt->bindValue(':userId', $userId, PDO::PARAM_INT);
            $stmt->execute();
            $currentData = $stmt->fetch();
            
            // Reset
            $sql = "UPDATE usuarios 
                    SET failed_login_attempts = 0,
                        last_failed_login = NULL,
                        last_successful_login = NOW()
                    WHERE id = :userId";
            
            $stmt = $pdo->prepare($sql);
            $stmt->bindValue(':userId', $userId, PDO::PARAM_INT);
            $stmt->execute();
            
            logSecurityEvent('LOGIN_ATTEMPTS_RESET', 'Tentativas de login resetadas após sucesso', [
                'user_id' => $userId,
                'previous_attempts' => $currentData['failed_login_attempts'] ?? 0,
                'last_failed_login' => $currentData['last_failed_login'] ?? null
            ]);
            
        } catch (PDOException $e) {
            logSecurityEvent('DB_UPDATE_FAILURE', 'Falha ao resetar tentativas de login', [
                'error' => $e->getMessage(),
                'user_id' => $userId
            ]);
        }
    }
}

// ==============================================================================
// 6. VERIFICAÇÃO DE SENHA COM PROTEÇÃO TEMPORAL
// ==============================================================================

if (!function_exists('verifyPassword')) {
    /**
     * Verificação de senha com proteção contra timing attacks
     */
    function verifyPassword(string $password, string $hash): bool
    {
        $startTime = microtime(true);
        
        // Validação básica
        if (empty($password) || empty($hash)) {
            // Simula tempo de verificação
            usleep(random_int(50000, 150000)); // 50-150ms
            return false;
        }
        
        // Verificação da senha
        $isValid = password_verify($password, $hash);
        
        // Verifica se hash precisa ser atualizado
        if ($isValid && password_needs_rehash($hash, PASSWORD_DEFAULT)) {
            logSecurityEvent('PASSWORD_REHASH_NEEDED', 'Hash de senha desatualizado detectado', [
                'hash_algorithm' => password_get_info($hash)['algoName'] ?? 'unknown',
                'current_algorithm' => 'ARGON2ID'
            ]);
        }
        
        // Garante tempo mínimo para evitar timing attacks
        $elapsedTime = microtime(true) - $startTime;
        $minTime = 0.1; // 100ms mínimo
        
        if ($elapsedTime < $minTime) {
            usleep((int)(($minTime - $elapsedTime) * 1000000));
        }
        
        return $isValid;
    }
}

// ==============================================================================
// 7. SISTEMA DE SESSÃO SEGURA AVANÇADO
// ==============================================================================

if (!function_exists('startSecureSession')) {
    /**
     * Inicia sessão segura com múltiplas camadas de proteção
     */
    function startSecureSession(array $user): void
    {
        // Valida estrutura do usuário
        $requiredFields = ['id', 'nome', 'cpf', 'email', 'tipo'];
        foreach ($requiredFields as $field) {
            if (!isset($user[$field]) || empty($user[$field])) {
                throw new InvalidArgumentException("Campo obrigatório ausente: {$field}");
            }
        }
        
        // Regenera ID da sessão para prevenir fixação
        if (session_status() === PHP_SESSION_ACTIVE) {
            session_regenerate_id(true);
            session_unset();
        }
        
        // Limita User-Agent para evitar sessão inflada
        $userAgent = $_SERVER['HTTP_USER_AGENT'] ?? 'Unknown';
        $userAgent = mb_substr($userAgent, 0, 255, 'UTF-8');
        
        // Gera fingerprint da sessão
        $fingerprint = generateSessionFingerprint();
        
        // Dados principais da sessão
        $_SESSION['user_id'] = (int)$user['id'];
        $_SESSION['user_nome'] = sanitizeString($user['nome'], 120);
        $_SESSION['user_cpf'] = preg_replace('/\D/', '', $user['cpf']);
        $_SESSION['user_email'] = strtolower(trim($user['email']));
        $_SESSION['user_tipo'] = sanitizeString($user['tipo'], 20);
        $_SESSION['user_id_otica'] = isset($user['id_otica']) ? (int)$user['id_otica'] : null;
        $_SESSION['otica_nome'] = sanitizeString($user['otica_nome'] ?? '', 100);
        
        // Metadados de segurança
        $_SESSION['login_time'] = time();
        $_SESSION['last_activity'] = time();
        $_SESSION['fingerprint'] = $fingerprint;
        $_SESSION['login_ip'] = $_SERVER['REMOTE_ADDR'] ?? 'unknown';
        $_SESSION['user_agent'] = $userAgent;
        $_SESSION['session_version'] = '4.0'; // Para futuras migrações
        
        // Token CSRF
        if (empty($_SESSION['csrf_token'])) {
            $_SESSION['csrf_token'] = generateSecureToken(32, 'base64url');
        }
        
        // Permissões baseadas no tipo
        $_SESSION['permissions'] = getUserPermissions($user['tipo'], $user['id_otica']);
        
        // Controle de sessões concorrentes
        manageMaxConcurrentSessions((int)$user['id']);
        
        // Log detalhado do login
        logSecurityEvent('SESSION_STARTED', 'Sessão segura iniciada', [
            'user_id' => $user['id'],
            'user_type' => $user['tipo'],
            'id_otica' => $user['id_otica'],
            'fingerprint' => $fingerprint,
            'session_id' => session_id(),
            'concurrent_sessions_after' => countUserSessions((int)$user['id'])
        ]);
    }
}

if (!function_exists('getUserPermissions')) {
    /**
     * Define permissões do usuário baseado no tipo e contexto
     */
    function getUserPermissions(string $userType, ?int $idOtica): array
    {
        $basePermissions = [
            'can_view_profile' => true,
            'can_edit_profile' => true,
            'can_logout' => true
        ];
        
        switch ($userType) {
            case 'vendedor':
                return array_merge($basePermissions, [
                    'can_submit_sales' => true,
                    'can_view_own_sales' => true,
                    'can_view_campaigns' => true,
                    'can_view_ranking' => true,
                    'can_upload_receipts' => true,
                    'scope' => 'vendedor',
                    'otica_restriction' => $idOtica
                ]);
                
            case 'gerente':
                return array_merge($basePermissions, [
                    'can_view_optical_sales' => true,
                    'can_view_optical_ranking' => true,
                    'can_view_optical_campaigns' => true,
                    'can_export_optical_data' => true,
                    'can_manage_optical_sellers' => true,
                    'scope' => 'gerente',
                    'otica_restriction' => $idOtica
                ]);
                
            case 'admin':
                return array_merge($basePermissions, [
                    'can_manage_users' => true,
                    'can_manage_campaigns' => true,
                    'can_manage_opticals' => true,
                    'can_view_all_sales' => true,
                    'can_export_all_data' => true,
                    'can_view_analytics' => true,
                    'can_manage_system' => true,
                    'scope' => 'admin',
                    'otica_restriction' => null
                ]);
                
            default:
                return $basePermissions;
        }
    }
}

if (!function_exists('manageMaxConcurrentSessions')) {
    /**
     * Gerencia número máximo de sessões concorrentes por usuário
     */
    function manageMaxConcurrentSessions(int $userId): void
    {
        $sessionsFile = APP_ROOT . '/app/cache/user_sessions_' . $userId . '.json';
        $currentSessionId = session_id();
        $now = time();
        
        // Carrega sessões existentes
        $sessions = [];
        if (file_exists($sessionsFile)) {
            $data = file_get_contents($sessionsFile);
            $sessions = json_decode($data, true) ?: [];
        }
        
        // Remove sessões expiradas
        $sessions = array_filter($sessions, function($session) use ($now) {
            return ($now - $session['last_activity']) < SESSION_TIMEOUT;
        });
        
        // Adiciona sessão atual
        $sessions[$currentSessionId] = [
            'started' => $now,
            'last_activity' => $now,
            'ip_address' => $_SERVER['REMOTE_ADDR'] ?? 'unknown',
            'user_agent' => mb_substr($_SERVER['HTTP_USER_AGENT'] ?? '', 0, 255)
        ];
        
        // Remove sessões mais antigas se exceder limite
        if (count($sessions) > MAX_CONCURRENT_SESSIONS) {
            uasort($sessions, fn($a, $b) => $a['last_activity'] <=> $b['last_activity']);
            $sessions = array_slice($sessions, -MAX_CONCURRENT_SESSIONS, null, true);
            
            logSecurityEvent('MAX_SESSIONS_EXCEEDED', 'Sessões antigas removidas por excesso', [
                'user_id' => $userId,
                'max_sessions' => MAX_CONCURRENT_SESSIONS,
                'current_session' => $currentSessionId
            ]);
        }
        
        // Salva sessões atualizadas
        $dir = dirname($sessionsFile);
        if (!is_dir($dir)) {
            mkdir($dir, 0750, true);
        }
        
        file_put_contents($sessionsFile, json_encode($sessions), LOCK_EX);
    }
}

if (!function_exists('countUserSessions')) {
    /**
     * Conta sessões ativas do usuário
     */
    function countUserSessions(int $userId): int
    {
        $sessionsFile = APP_ROOT . '/app/cache/user_sessions_' . $userId . '.json';
        
        if (!file_exists($sessionsFile)) {
            return 0;
        }
        
        $data = file_get_contents($sessionsFile);
        $sessions = json_decode($data, true) ?: [];
        $now = time();
        
        // Conta apenas sessões ativas
        $activeSessions = array_filter($sessions, function($session) use ($now) {
            return ($now - $session['last_activity']) < SESSION_TIMEOUT;
        });
        
        return count($activeSessions);
    }
}

// ==============================================================================
// 8. SISTEMA DE REDIRECIONAMENTO INTELIGENTE
// ==============================================================================

if (!function_exists('getRedirectUrlForUser')) {
    /**
     * Determina URL de redirecionamento com lógica inteligente
     */
    function getRedirectUrlForUser(string $userType, array $context = []): string
    {
        $baseUrls = [
            'vendedor' => '/dashboard_vendedor.php',
            'gerente' => '/dashboard_gerente.php', 
            'admin' => '/dashboard_admin.php'
        ];
        
        $defaultUrl = $baseUrls[$userType] ?? '/login.php';
        
        // Verifica se há URL de retorno solicitada
        $requestedUrl = $_SESSION['intended_url'] ?? $context['intended_url'] ?? null;
        
        if ($requestedUrl) {
            // Valida URL de retorno por segurança
            $parsedUrl = parse_url($requestedUrl);
            $currentHost = $_SERVER['HTTP_HOST'] ?? '';
            
            // Apenas URLs internas são permitidas
            if (empty($parsedUrl['host']) || $parsedUrl['host'] === $currentHost) {
                unset($_SESSION['intended_url']);
                
                logSecurityEvent('REDIRECT_TO_INTENDED', 'Redirecionamento para URL solicitada', [
                    'user_type' => $userType,
                    'intended_url' => $requestedUrl,
                    'default_url' => $defaultUrl
                ]);
                
                return $requestedUrl;
            } else {
                logSecurityEvent('REDIRECT_BLOCKED', 'Tentativa de redirecionamento externo bloqueada', [
                    'user_type' => $userType,
                    'attempted_url' => $requestedUrl,
                    'attempted_host' => $parsedUrl['host'] ?? 'unknown'
                ]);
            }
        }
        
        return $defaultUrl;
    }
}

// ==============================================================================
// 9. VALIDAÇÃO DE SESSÃO CONTÍNUA
// ==============================================================================

if (!function_exists('validateActiveSession')) {
    /**
     * Valida sessão ativa com múltiplas verificações
     */
    function validateActiveSession(): bool
    {
        // Verifica se sessão existe
        if (session_status() !== PHP_SESSION_ACTIVE || empty($_SESSION['user_id'])) {
            return false;
        }
        
        // Verifica timeout de sessão
        $lastActivity = $_SESSION['last_activity'] ?? 0;
        if ((time() - $lastActivity) > SESSION_TIMEOUT) {
            logSecurityEvent('SESSION_TIMEOUT', 'Sessão expirada por timeout', [
                'user_id' => $_SESSION['user_id'],
                'last_activity' => $lastActivity,
                'timeout_seconds' => SESSION_TIMEOUT
            ]);
            
            destroySecureSession();
            return false;
        }
        
        // Verifica fingerprint
        if (!validateSessionFingerprint()) {
            logSecurityEvent('SESSION_HIJACK_ATTEMPT', 'Possível tentativa de hijacking', [
                'user_id' => $_SESSION['user_id'],
                'session_id' => session_id()
            ]);
            
            destroySecureSession();
            return false;
        }
        
        // Atualiza última atividade
        $_SESSION['last_activity'] = time();
        
        // Atualiza arquivo de sessões do usuário
        if (isset($_SESSION['user_id'])) {
            updateUserSessionActivity((int)$_SESSION['user_id']);
        }
        
        return true;
    }
}

if (!function_exists('updateUserSessionActivity')) {
    /**
     * Atualiza atividade da sessão no cache
     */
    function updateUserSessionActivity(int $userId): void
    {
        $sessionsFile = APP_ROOT . '/app/cache/user_sessions_' . $userId . '.json';
        $currentSessionId = session_id();
        
        if (file_exists($sessionsFile)) {
            $data = file_get_contents($sessionsFile);
            $sessions = json_decode($data, true) ?: [];
            
            if (isset($sessions[$currentSessionId])) {
                $sessions[$currentSessionId]['last_activity'] = time();
                file_put_contents($sessionsFile, json_encode($sessions), LOCK_EX);
            }
        }
    }
}

if (!function_exists('destroySecureSession')) {
    /**
     * Destrói sessão de forma segura
     */
    function destroySecureSession(): void
    {
        $userId = $_SESSION['user_id'] ?? null;
        $sessionId = session_id();
        
        // Log antes de destruir
        if ($userId) {
            logSecurityEvent('SESSION_DESTROYED', 'Sessão destruída', [
                'user_id' => $userId,
                'session_id' => $sessionId,
                'reason' => 'security_validation_failed'
            ]);
            
            // Remove da lista de sessões do usuário
            $sessionsFile = APP_ROOT . '/app/cache/user_sessions_' . $userId . '.json';
            if (file_exists($sessionsFile)) {
                $data = file_get_contents($sessionsFile);
                $sessions = json_decode($data, true) ?: [];
                unset($sessions[$sessionId]);
                file_put_contents($sessionsFile, json_encode($sessions), LOCK_EX);
            }
        }
        
        // Limpa dados da sessão
        session_unset();
        session_destroy();
        
        // Remove cookie de sessão
        if (ini_get('session.use_cookies')) {
            $params = session_get_cookie_params();
            setcookie(
                session_name(),
                '',
                time() - 3600,
                $params['path'],
                $params['domain'],
                $params['secure'],
                $params['httponly']
            );
        }
    }
}

// ==============================================================================
// 10. MIDDLEWARE DE AUTORIZAÇÃO
// ==============================================================================

if (!function_exists('requirePermission')) {
    /**
     * Middleware para verificar permissões específicas
     */
    function requirePermission(string $permission): bool
    {
        if (!validateActiveSession()) {
            return false;
        }
        
        $userPermissions = $_SESSION['permissions'] ?? [];
        $hasPermission = $userPermissions[$permission] ?? false;
        
        if (!$hasPermission) {
            logSecurityEvent('PERMISSION_DENIED', 'Acesso negado por falta de permissão', [
                'user_id' => $_SESSION['user_id'],
                'required_permission' => $permission,
                'user_permissions' => array_keys(array_filter($userPermissions)),
                'request_uri' => $_SERVER['REQUEST_URI'] ?? 'unknown'
            ]);
        }
        
        return $hasPermission;
    }
}

if (!function_exists('requireUserType')) {
    /**
     * Middleware para verificar tipo de usuário
     */
    function requireUserType(array $allowedTypes): bool
    {
        if (!validateActiveSession()) {
            return false;
        }
        
        $userType = $_SESSION['user_tipo'] ?? '';
        $hasAccess = in_array($userType, $allowedTypes, true);
        
        if (!$hasAccess) {
            logSecurityEvent('ACCESS_DENIED', 'Acesso negado por tipo de usuário', [
                'user_id' => $_SESSION['user_id'],
                'user_type' => $userType,
                'allowed_types' => $allowedTypes,
                'request_uri' => $_SERVER['REQUEST_URI'] ?? 'unknown'
            ]);
        }
        
        return $hasAccess;
    }
}

// ==============================================================================
// 11. FUNÇÕES DE UTILIDADE PARA CSRF E TOKENS
// ==============================================================================

if (!function_exists('validateCsrfToken')) {
    /**
     * Valida token CSRF
     */
    function validateCsrfToken(string $token): bool
    {
        $sessionToken = $_SESSION['csrf_token'] ?? '';
        
        if (empty($sessionToken) || empty($token)) {
            return false;
        }
        
        return hash_equals($sessionToken, $token);
    }
}

if (!function_exists('getCsrfToken')) {
    /**
     * Retorna token CSRF atual
     */
    function getCsrfToken(): string
    {
        if (empty($_SESSION['csrf_token'])) {
            $_SESSION['csrf_token'] = generateSecureToken(32, 'base64url');
        }
        
        return $_SESSION['csrf_token'];
    }
}

// ==============================================================================
// 12. SISTEMA DE AUDITORIA AVANÇADO
// ==============================================================================

if (!function_exists('auditUserAction')) {
    /**
     * Registra ações do usuário para auditoria
     */
    function auditUserAction(string $action, string $description, array $details = []): void
    {
        if (!isset($_SESSION['user_id'])) {
            return;
        }
        
        $auditData = [
            'timestamp' => (new DateTimeImmutable())->format('Y-m-d\TH:i:s.uP'),
            'user_id' => $_SESSION['user_id'],
            'user_type' => $_SESSION['user_tipo'] ?? 'unknown',
            'session_id' => session_id(),
            'action' => $action,
            'description' => $description,
            'details' => $details,
            'ip_address' => $_SERVER['REMOTE_ADDR'] ?? 'unknown',
            'user_agent' => $_SERVER['HTTP_USER_AGENT'] ?? 'unknown',
            'request_uri' => $_SERVER['REQUEST_URI'] ?? 'unknown',
            'request_method' => $_SERVER['REQUEST_METHOD'] ?? 'unknown'
        ];
        
        $auditFile = APP_ROOT . '/app/logs/audit_' . ENVIRONMENT . '.log';
        $dir = dirname($auditFile);
        
        if (!is_dir($dir)) {
            mkdir($dir, 0750, true);
        }
        
        $logLine = json_encode($auditData, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE) . PHP_EOL;
        @file_put_contents($auditFile, $logLine, FILE_APPEND | LOCK_EX);
    }
}