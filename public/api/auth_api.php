<?php
declare(strict_types=1);

/**
 * ==============================================================================
 * API DE AUTENTICAÇÃO PREMIUM (Premium Authentication API) - v4.1 CORRIGIDA
 * ==============================================================================
 * Localização: /public/api/auth_api.php
 * 
 * Correções v4.1:
 * - Funções ausentes implementadas
 * - Estrutura de resposta consistente
 * - Headers otimizados
 * - Validação CSRF melhorada
 * - Tratamento de erros robusto
 */

// Define a constante de inicialização
define('APP_INITIATED', true);
define('APP_ROOT', dirname(__DIR__, 2));

// Carrega o sistema
require_once APP_ROOT . '/app/config/config.php';

// ==============================================================================
// 1. FUNÇÕES AUXILIARES NECESSÁRIAS
// ==============================================================================

if (!function_exists('detectHttps')) {
    /**
     * Detecção robusta de HTTPS
     */
    function detectHttps(): bool
    {
        return !empty($_SERVER['HTTPS']) && strtolower((string)$_SERVER['HTTPS']) !== 'off'
            || !empty($_SERVER['SERVER_PORT']) && (int)$_SERVER['SERVER_PORT'] === 443
            || !empty($_SERVER['HTTP_X_FORWARDED_PROTO']) && strtolower((string)$_SERVER['HTTP_X_FORWARDED_PROTO']) === 'https'
            || !empty($_SERVER['HTTP_X_ARR_SSL'])
            || !empty($_SERVER['HTTP_CF_VISITOR']) && str_contains((string)$_SERVER['HTTP_CF_VISITOR'], 'https');
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
        
        $defaultUrl = $baseUrls[$userType] ?? '/dashboard.php';
        
        // Verifica se há URL de retorno solicitada
        $requestedUrl = $_SESSION['intended_url'] ?? $context['intended_url'] ?? null;
        
        if ($requestedUrl) {
            // Valida URL de retorno por segurança
            $parsedUrl = parse_url($requestedUrl);
            $currentHost = $_SERVER['HTTP_HOST'] ?? '';
            
            // Apenas URLs internas são permitidas
            if (empty($parsedUrl['host']) || $parsedUrl['host'] === $currentHost) {
                unset($_SESSION['intended_url']);
                
                if (function_exists('logSecurityEvent')) {
                    logSecurityEvent('REDIRECT_TO_INTENDED', 'Redirecionamento para URL solicitada', [
                        'user_type' => $userType,
                        'intended_url' => $requestedUrl,
                        'default_url' => $defaultUrl
                    ]);
                }
                
                return $requestedUrl;
            } else {
                if (function_exists('logSecurityEvent')) {
                    logSecurityEvent('REDIRECT_BLOCKED', 'Tentativa de redirecionamento externo bloqueada', [
                        'user_type' => $userType,
                        'attempted_url' => $requestedUrl,
                        'attempted_host' => $parsedUrl['host'] ?? 'unknown'
                    ]);
                }
            }
        }
        
        return $defaultUrl;
    }
}

// ==============================================================================
// 2. CONFIGURAÇÃO DE HEADERS E SEGURANÇA
// ==============================================================================

// Evita headers duplicados
if (!headers_sent()) {
    // Headers de API seguros
    header('Content-Type: application/json; charset=utf-8');
    header('X-Content-Type-Options: nosniff');
    header('X-Frame-Options: DENY');
    header('X-XSS-Protection: 1; mode=block');
    header('Referrer-Policy: strict-origin-when-cross-origin');
    
    // Cache control para API
    header('Cache-Control: no-store, no-cache, must-revalidate, max-age=0');
    header('Pragma: no-cache');
    
    // CORS se necessário (ajustar conforme ambiente)
    if (ENVIRONMENT === 'development') {
        header('Access-Control-Allow-Origin: *');
        header('Access-Control-Allow-Methods: POST, OPTIONS');
        header('Access-Control-Allow-Headers: Content-Type, X-Requested-With');
    }
}

// Rate limiting específico para login
$rateLimitKey = 'auth_' . ($_SERVER['REMOTE_ADDR'] ?? 'unknown');
$maxAttempts = ENVIRONMENT === 'production' ? 10 : 50;
$windowTime = 900; // 15 minutos

if (!checkRateLimit($rateLimitKey, $maxAttempts, $windowTime)) {
    http_response_code(429);
    echo json_encode([
        'success' => false,
        'error' => 'RATE_LIMIT_EXCEEDED',
        'message' => 'Muitas tentativas de login. Tente novamente em 15 minutos.',
        'retry_after' => 900,
        'timestamp' => date('c')
    ]);
    exit;
}

// ==============================================================================
// 3. CLASSE PRINCIPAL DA API - CORRIGIDA
// ==============================================================================

class AuthAPI
{
    private float $startTime;
    private array $securityMetrics = [];
    
    public function __construct()
    {
        $this->startTime = microtime(true);
        $this->securityMetrics = [
            'ip_address' => $_SERVER['REMOTE_ADDR'] ?? 'unknown',
            'user_agent' => $_SERVER['HTTP_USER_AGENT'] ?? 'unknown',
            'request_time' => date('Y-m-d H:i:s'),
            'fingerprint' => $this->generateRequestFingerprint()
        ];
    }
    
    /**
     * Gera fingerprint da requisição para análise de segurança
     */
    private function generateRequestFingerprint(): string
    {
        $components = [
            $_SERVER['HTTP_USER_AGENT'] ?? '',
            $_SERVER['HTTP_ACCEPT_LANGUAGE'] ?? '',
            $_SERVER['HTTP_ACCEPT_ENCODING'] ?? '',
            $_SERVER['REMOTE_ADDR'] ?? ''
        ];
        
        return hash('sha256', implode('|', $components));
    }
    
    /**
     * Processa requisição de login
     */
    public function processLogin(): void
    {
        try {
            // 1. Validação do método
            if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
                $this->logSecurityEvent('INVALID_METHOD', 'Método inválido para login', [
                    'method' => $_SERVER['REQUEST_METHOD']
                ]);
                
                $this->sendErrorResponse('METHOD_NOT_ALLOWED', 'Método não permitido', 405);
                return;
            }
            
            // 2. Validação do payload
            $input = $this->validateAndParseInput();
            if ($input === null) {
                return; // Erro já enviado
            }
            
            // 3. Validação CSRF opcional (apenas se enviado)
            if (isset($input['csrf_token']) && !empty($_SESSION['csrf_token'])) {
                if (!validateCsrfToken($input['csrf_token'])) {
                    $this->logSecurityEvent('CSRF_VIOLATION', 'Token CSRF inválido');
                    $this->sendErrorResponse('CSRF_ERROR', 'Token de segurança inválido', 403);
                    return;
                }
            }
            
            // 4. Sanitização dos dados
            $identifier = $this->sanitizeIdentifier($input['identifier']);
            $password = $input['password'];
            $rememberMe = $input['remember'] ?? false;
            
            if (!$identifier) {
                $this->sendErrorResponse('INVALID_IDENTIFIER', 'Usuário inválido', 400);
                return;
            }
            
            // 5. Busca do usuário
            $user = $this->findUserSecurely($identifier);
            
            if (!$user) {
                $this->simulateProcessingTime();
                $this->recordFailedAttempt($identifier);
                $this->sendErrorResponse('INVALID_CREDENTIALS', 'Usuário ou senha inválidos', 401);
                return;
            }
            
            // 6. Verificação de bloqueio
            if ($this->isUserBlocked($user)) {
                $lockoutTime = $this->calculateLockoutTime($user);
                $this->sendErrorResponse('ACCOUNT_LOCKED', 
                    "Conta bloqueada temporariamente. Tente novamente em {$lockoutTime} minutos.", 
                    423
                );
                return;
            }
            
            // 7. Verificação da senha
            if (!$this->verifyPasswordSecurely($password, $user['senha_hash'])) {
                $this->recordFailedAttempt($identifier);
                $this->simulateProcessingTime();
                $this->sendErrorResponse('INVALID_CREDENTIALS', 'Usuário ou senha inválidos', 401);
                return;
            }
            
            // 8. Verificação do status da conta
            $statusCheck = $this->checkAccountStatus($user);
            if (!$statusCheck['valid']) {
                $this->sendErrorResponse('ACCOUNT_STATUS', $statusCheck['message'], 403);
                return;
            }
            
            // 9. Login bem-sucedido
            $this->processSuccessfulLogin($user, $rememberMe);
            
        } catch (Exception $e) {
            $this->logSecurityEvent('LOGIN_EXCEPTION', 'Exceção durante login', [
                'error' => $e->getMessage(),
                'trace' => ENVIRONMENT === 'development' ? $e->getTraceAsString() : 'hidden'
            ]);
            
            $this->sendErrorResponse('INTERNAL_ERROR', 'Erro interno do servidor', 500);
        }
    }
    
    /**
     * Valida e parse o input JSON
     */
    private function validateAndParseInput(): ?array
    {
        $rawInput = file_get_contents('php://input');
        
        if (empty($rawInput)) {
            $this->sendErrorResponse('EMPTY_PAYLOAD', 'Dados de entrada ausentes', 400);
            return null;
        }
        
        $input = json_decode($rawInput, true);
        
        if (json_last_error() !== JSON_ERROR_NONE) {
            $this->logSecurityEvent('MALFORMED_JSON', 'JSON malformado', [
                'json_error' => json_last_error_msg(),
                'payload_length' => strlen($rawInput)
            ]);
            
            $this->sendErrorResponse('INVALID_JSON', 'Formato de dados inválido', 400);
            return null;
        }
        
        // Validação de campos obrigatórios
        if (empty($input['identifier']) || empty($input['password'])) {
            $this->sendErrorResponse('MISSING_FIELDS', 'Usuário e senha são obrigatórios', 400);
            return null;
        }
        
        // Validação de tamanhos
        if (strlen($input['identifier']) > 255 || strlen($input['password']) > 255) {
            $this->logSecurityEvent('OVERSIZED_INPUT', 'Input com tamanho suspeito');
            $this->sendErrorResponse('INVALID_INPUT', 'Dados de entrada inválidos', 400);
            return null;
        }
        
        return $input;
    }
    
    /**
     * Sanitiza identificador do usuário
     */
    private function sanitizeIdentifier(string $identifier): ?string
    {
        $identifier = trim($identifier);
        
        // Detecta se é email ou CPF
        if (filter_var($identifier, FILTER_VALIDATE_EMAIL)) {
            $sanitized = strtolower($identifier);
            return filter_var($sanitized, FILTER_VALIDATE_EMAIL) ? $sanitized : null;
        }
        
        // Trata como CPF
        $cpf = preg_replace('/\D/', '', $identifier);
        return strlen($cpf) === 11 ? $cpf : null;
    }
    
    /**
     * Busca usuário de forma segura
     */
    private function findUserSecurely(string $identifier): ?array
    {
        $startTime = microtime(true);
        
        try {
            $user = findUserByIdentifier($identifier);
            
            $queryTime = microtime(true) - $startTime;
            
            $this->logSecurityEvent('USER_LOOKUP', 'Consulta de usuário realizada', [
                'identifier_hash' => hash('sha256', $identifier),
                'found' => $user !== null,
                'query_time_ms' => round($queryTime * 1000, 2)
            ]);
            
            return $user;
            
        } catch (Exception $e) {
            $this->logSecurityEvent('USER_LOOKUP_ERROR', 'Erro na consulta de usuário', [
                'error' => $e->getMessage()
            ]);
            
            return null;
        }
    }
    
    /**
     * Verifica se usuário está bloqueado
     */
    private function isUserBlocked(array $user): bool
    {
        return isAccountLocked($user);
    }
    
    /**
     * Calcula tempo de bloqueio restante
     */
    private function calculateLockoutTime(array $user): int
    {
        $attempts = (int)($user['failed_login_attempts'] ?? 0);
        $lastFailed = $user['last_failed_login'] ?? null;
        
        if (!$lastFailed) {
            return LOCKOUT_TIME_MINUTES;
        }
        
        try {
            $lastAttemptTime = new DateTimeImmutable($lastFailed);
            $now = new DateTimeImmutable();
            $minutesPassed = ($now->getTimestamp() - $lastAttemptTime->getTimestamp()) / 60;
            
            // Sistema de escalação
            $lockoutMultiplier = min(floor($attempts / MAX_LOGIN_ATTEMPTS), 5);
            $totalLockoutTime = LOCKOUT_TIME_MINUTES * (1 + $lockoutMultiplier);
            
            return max(1, ceil($totalLockoutTime - $minutesPassed));
            
        } catch (Exception $e) {
            return LOCKOUT_TIME_MINUTES;
        }
    }
    
    /**
     * Verifica senha de forma segura
     */
    private function verifyPasswordSecurely(string $password, string $hash): bool
    {
        return verifyPassword($password, $hash);
    }
    
    /**
     * Verifica status da conta
     */
    private function checkAccountStatus(array $user): array
    {
        switch ($user['status']) {
            case 'ativo':
                return ['valid' => true];
                
            case 'pendente':
                return [
                    'valid' => false,
                    'message' => 'Conta pendente de ativação. Verifique seu e-mail.'
                ];
                
            case 'bloqueado':
                return [
                    'valid' => false,
                    'message' => 'Conta bloqueada. Entre em contato com o suporte.'
                ];
                
            case 'suspenso':
                return [
                    'valid' => false,
                    'message' => 'Conta temporariamente suspensa.'
                ];
                
            default:
                return [
                    'valid' => false,
                    'message' => 'Status de conta inválido.'
                ];
        }
    }
    
    /**
     * Processa login bem-sucedido
     */
    private function processSuccessfulLogin(array $user, bool $rememberMe): void
    {
        try {
            // Reset de tentativas falhadas
            resetLoginAttempts((int)$user['id']);
            
            // Inicia sessão segura
            startSecureSession($user);
            
            // Configura cookie de "lembrar-me" se solicitado
            if ($rememberMe) {
                $this->setRememberMeCookie($user);
            }
            
            // URL de redirecionamento
            $redirectUrl = getRedirectUrlForUser($user['tipo']);
            
            // Log de sucesso
            $this->logSecurityEvent('LOGIN_SUCCESS', 'Login realizado com sucesso', [
                'user_id' => $user['id'],
                'user_type' => $user['tipo'],
                'remember_me' => $rememberMe,
                'session_id' => session_id()
            ]);
            
            // Audit trail
            if (function_exists('auditUserAction')) {
                auditUserAction('LOGIN', 'Usuário fez login no sistema', [
                    'user_id' => $user['id'],
                    'remember_me' => $rememberMe
                ]);
            }
            
            $this->sendSuccessResponse([
                'user' => [
                    'id' => $user['id'],
                    'nome' => $user['nome'],
                    'email' => $user['email'],
                    'tipo' => $user['tipo'],
                    'otica_nome' => $user['otica_nome'] ?? null
                ],
                'redirect_url' => $redirectUrl,
                'session_info' => [
                    'expires_in' => SESSION_TIMEOUT,
                    'csrf_token' => getCsrfToken()
                ]
            ], 'Login realizado com sucesso');
            
        } catch (Exception $e) {
            $this->logSecurityEvent('LOGIN_SUCCESS_ERROR', 'Erro pós-login', [
                'user_id' => $user['id'],
                'error' => $e->getMessage()
            ]);
            
            $this->sendErrorResponse('POST_LOGIN_ERROR', 'Erro na finalização do login', 500);
        }
    }
    
    /**
     * Configura cookie de "lembrar-me"
     */
    private function setRememberMeCookie(array $user): void
    {
        try {
            $token = generateSecureToken(32, 'base64url');
            $expires = time() + (30 * 24 * 60 * 60); // 30 dias
            
            // Salva token no banco se a tabela existir
            try {
                $stmt = dbQuery(
                    "INSERT INTO remember_tokens (user_id, token_hash, expires_at, created_at) VALUES (?, ?, FROM_UNIXTIME(?), NOW())",
                    [$user['id'], hash('sha256', $token), $expires]
                );
            } catch (Exception $e) {
                // Tabela pode não existir ainda - log mas não falha
                $this->logSecurityEvent('REMEMBER_TOKEN_TABLE_ERROR', 'Tabela remember_tokens não existe', [
                    'error' => $e->getMessage()
                ]);
            }
            
            // Define cookie seguro
            $cookieOptions = [
                'expires' => $expires,
                'path' => '/',
                'domain' => '',
                'secure' => detectHttps(),
                'httponly' => true,
                'samesite' => 'Lax'
            ];
            
            setcookie('remember_token', $token, $cookieOptions);
            
            $this->logSecurityEvent('REMEMBER_TOKEN_SET', 'Token de lembrança configurado', [
                'user_id' => $user['id'],
                'expires_at' => date('Y-m-d H:i:s', $expires)
            ]);
            
        } catch (Exception $e) {
            $this->logSecurityEvent('REMEMBER_TOKEN_ERROR', 'Erro ao configurar token de lembrança', [
                'user_id' => $user['id'],
                'error' => $e->getMessage()
            ]);
        }
    }
    
    /**
     * Registra tentativa de login falhada
     */
    private function recordFailedAttempt(string $identifier): void
    {
        recordFailedLoginAttempt($identifier);
        
        $this->logSecurityEvent('LOGIN_FAILURE', 'Tentativa de login falhada', [
            'identifier_hash' => hash('sha256', $identifier)
        ]);
    }
    
    /**
     * Simula tempo de processamento
     */
    private function simulateProcessingTime(): void
    {
        $elapsed = microtime(true) - $this->startTime;
        $minTime = 0.2; // 200ms mínimo
        
        if ($elapsed < $minTime) {
            usleep((int)(($minTime - $elapsed) * 1000000));
        }
    }
    
    /**
     * Log de eventos de segurança
     */
    private function logSecurityEvent(string $event, string $message, array $context = []): void
    {
        $enrichedContext = array_merge($this->securityMetrics, $context);
        
        if (function_exists('logSecurityEvent')) {
            logSecurityEvent($event, $message, $enrichedContext);
        } else {
            error_log("SECURITY EVENT [{$event}]: {$message} " . json_encode($enrichedContext));
        }
    }
    
    /**
     * Envia resposta de sucesso
     */
    private function sendSuccessResponse(array $data, string $message = 'Operação realizada com sucesso'): void
    {
        $response = [
            'success' => true,
            'message' => $message,
            'data' => $data,
            'timestamp' => date('c'),
            'request_id' => uniqid('req_', true)
        ];
        
        http_response_code(200);
        echo json_encode($response, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
    }
    
    /**
     * Envia resposta de erro
     */
    private function sendErrorResponse(string $errorCode, string $message, int $httpCode = 400): void
    {
        $response = [
            'success' => false,
            'error' => $errorCode,
            'message' => $message,
            'timestamp' => date('c'),
            'request_id' => uniqid('req_', true)
        ];
        
        // Adiciona informações extras em desenvolvimento
        if (ENVIRONMENT === 'development') {
            $response['debug'] = [
                'execution_time_ms' => round((microtime(true) - $this->startTime) * 1000, 2),
                'memory_usage' => round(memory_get_peak_usage(true) / 1024 / 1024, 2) . 'MB',
                'environment' => ENVIRONMENT
            ];
        }
        
        http_response_code($httpCode);
        echo json_encode($response, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
    }
}

// ==============================================================================
// 4. EXECUÇÃO DA API
// ==============================================================================

try {
    // Responde OPTIONS para CORS preflight
    if ($_SERVER['REQUEST_METHOD'] === 'OPTIONS') {
        http_response_code(200);
        echo json_encode(['success' => true, 'message' => 'CORS preflight OK']);
        exit;
    }
    
    $api = new AuthAPI();
    $api->processLogin();
    
} catch (Throwable $e) {
    // Fallback para erros críticos
    if (!headers_sent()) {
        http_response_code(500);
    }
    
    $response = [
        'success' => false,
        'error' => 'CRITICAL_ERROR',
        'message' => 'Erro crítico no servidor',
        'timestamp' => date('c')
    ];
    
    if (ENVIRONMENT === 'development') {
        $response['debug'] = [
            'error' => $e->getMessage(),
            'file' => $e->getFile(),
            'line' => $e->getLine()
        ];
    }
    
    error_log('CRITICAL AUTH API ERROR: ' . $e->getMessage());
    echo json_encode($response);
}

exit;