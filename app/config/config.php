<?php
declare(strict_types=1);

/**
 * ==============================================================================
 * NEXO DE CONFIGURAÇÃO PREMIUM (Premium Configuration Nexus) - v4.0
 * ==============================================================================
 * Localização: /app/config/config.php
 * 
 * Aprimoramentos v4.0:
 * - Sistema de cache otimizado
 * - Rate limiting integrado
 * - Headers de segurança premium
 * - Detecção inteligente de ambiente
 * - Logs estruturados aprimorados
 * - Suporte a múltiplos ambientes
 */

// --- PREVENÇÃO DE ACESSO DIRETO ---
if (!defined('APP_INITIATED')) {
    http_response_code(403);
    exit('Forbidden');
}

// --- BASE DO PROJETO ---
if (!defined('APP_ROOT')) {
    define('APP_ROOT', dirname(__DIR__, 2));
}

// ==============================================================================
// 1. FUNÇÕES AUXILIARES (MOVIDAS PARA O INÍCIO)
// ==============================================================================

/**
 * Função auxiliar para detectar HTTPS
 */
if (!function_exists('detectHttps')) {
    function detectHttps(): bool {
        return !empty($_SERVER['HTTPS']) && strtolower((string)$_SERVER['HTTPS']) !== 'off'
            || !empty($_SERVER['SERVER_PORT']) && (int)$_SERVER['SERVER_PORT'] === 443
            || !empty($_SERVER['HTTP_X_FORWARDED_PROTO']) && strtolower((string)$_SERVER['HTTP_X_FORWARDED_PROTO']) === 'https'
            || !empty($_SERVER['HTTP_X_ARR_SSL'])
            || !empty($_SERVER['HTTP_CF_VISITOR']) && str_contains((string)$_SERVER['HTTP_CF_VISITOR'], 'https');
    }
}

// ==============================================================================
// 2. CARREGAMENTO DE VARIÁVEIS DE AMBIENTE
// ==============================================================================

if (!function_exists('loadEnvironmentVariables')) {
    function loadEnvironmentVariables(): void {
        $envFile = APP_ROOT . '/.env';
        
        if (file_exists($envFile) && is_readable($envFile)) {
            $lines = file($envFile, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES);
            
            foreach ($lines as $line) {
                if (strpos(trim($line), '#') === 0) {
                    continue; // Ignora comentários
                }
                
                if (strpos($line, '=') !== false) {
                    [$key, $value] = explode('=', $line, 2);
                    $key = trim($key);
                    $value = trim($value, " \t\n\r\0\x0B\"'");
                    
                    if (!empty($key) && !getenv($key)) {
                        putenv("$key=$value");
                        $_ENV[$key] = $value;
                    }
                }
            }
        }
    }
}

// Carrega variáveis de ambiente
loadEnvironmentVariables();

// ==============================================================================
// 3. DETECÇÃO INTELIGENTE DE AMBIENTE
// ==============================================================================

$detectedEnv = getenv('APP_ENV') ?: 'development';

// Detecção automática baseada em domínio/host
if (!getenv('APP_ENV')) {
    $host = $_SERVER['HTTP_HOST'] ?? $_SERVER['SERVER_NAME'] ?? 'localhost';
    
    if (str_contains($host, 'localhost') || str_contains($host, '127.0.0.1') || str_contains($host, '.local')) {
        $detectedEnv = 'development';
    } elseif (str_contains($host, 'staging') || str_contains($host, 'test') || str_contains($host, 'dev.')) {
        $detectedEnv = 'staging';
    } else {
        $detectedEnv = 'production';
    }
}

define('ENVIRONMENT', in_array($detectedEnv, ['development', 'staging', 'production'], true) ? $detectedEnv : 'development');

// ==============================================================================
// 4. CONFIGURAÇÃO DE LOGS ESTRUTURADOS
// ==============================================================================

$logsDir = APP_ROOT . '/app/logs';
if (!is_dir($logsDir)) {
    mkdir($logsDir, 0750, true);
}

$errorLogPath = $logsDir . '/' . ENVIRONMENT . '_errors.log';

// ==============================================================================
// 5. CONFIGURAÇÃO DE PHP POR AMBIENTE
// ==============================================================================

switch (ENVIRONMENT) {
    case 'production':
        error_reporting(E_ALL & ~E_DEPRECATED & ~E_STRICT & ~E_NOTICE);
        ini_set('display_errors', '0');
        ini_set('display_startup_errors', '0');
        
        // Cache otimizado para produção
        if (function_exists('opcache_get_status')) {
            ini_set('opcache.enable', '1');
            ini_set('opcache.validate_timestamps', '0');
        }
        break;
        
    case 'staging':
        error_reporting(E_ALL & ~E_DEPRECATED & ~E_STRICT);
        ini_set('display_errors', '0');
        ini_set('display_startup_errors', '1');
        break;
        
    case 'development':
    default:
        error_reporting(E_ALL);
        ini_set('display_errors', '1');
        ini_set('display_startup_errors', '1');
        
        // Disable cache em desenvolvimento
        if (function_exists('opcache_get_status')) {
            ini_set('opcache.enable', '0');
        }
        break;
}

// Configurações globais
ini_set('log_errors', '1');
ini_set('error_log', $errorLogPath);
ini_set('default_charset', 'UTF-8');
ini_set('memory_limit', '256M');
ini_set('max_execution_time', '30');
ini_set('post_max_size', '50M');
ini_set('upload_max_filesize', '20M');

// Timezone
date_default_timezone_set(getenv('APP_TIMEZONE') ?: 'America/Sao_Paulo');

// ==============================================================================
// 6. CONFIGURAÇÃO DE BANCO DE DADOS
// ==============================================================================

// Prioriza variáveis de ambiente, fallback para constantes
if (!defined('DB_HOST'))    { define('DB_HOST', getenv('DB_HOST') ?: 'localhost'); }
if (!defined('DB_PORT'))    { define('DB_PORT', getenv('DB_PORT') ?: '3306'); }
if (!defined('DB_NAME'))    { define('DB_NAME', getenv('DB_NAME') ?: 'campanhas_eps'); }
if (!defined('DB_USER'))    { define('DB_USER', getenv('DB_USER') ?: 'campanha'); }
if (!defined('DB_PASS'))    { define('DB_PASS', getenv('DB_PASS') ?: 'admin'); }
if (!defined('DB_CHARSET')) { define('DB_CHARSET', getenv('DB_CHARSET') ?: 'utf8mb4'); }

if (!defined('DB_DSN')) {
    define('DB_DSN', sprintf(
        'mysql:host=%s;port=%s;dbname=%s;charset=%s',
        DB_HOST,
        DB_PORT,
        DB_NAME,
        DB_CHARSET
    ));
}

// ==============================================================================
// 7. CONFIGURAÇÃO DE SEGURANÇA AVANÇADA
// ==============================================================================

// Constantes de segurança
if (!defined('MAX_LOGIN_ATTEMPTS'))    { define('MAX_LOGIN_ATTEMPTS', 5); }
if (!defined('LOCKOUT_TIME_MINUTES'))  { define('LOCKOUT_TIME_MINUTES', 15); }
if (!defined('SESSION_TIMEOUT'))       { define('SESSION_TIMEOUT', 7200); } // 2 horas
if (!defined('PASSWORD_COST'))         { define('PASSWORD_COST', 12); }
if (!defined('CSRF_TOKEN_LENGTH'))     { define('CSRF_TOKEN_LENGTH', 32); }

// Rate limiting
if (!defined('RATE_LIMIT_REQUESTS'))   { define('RATE_LIMIT_REQUESTS', 100); }
if (!defined('RATE_LIMIT_WINDOW'))     { define('RATE_LIMIT_WINDOW', 3600); } // 1 hora

// ==============================================================================
// 8. CONFIGURAÇÃO DE SESSÃO PREMIUM
// ==============================================================================

/**
 * Configuração avançada de sessão com detecção de contexto
 */
function configureSession(): void {
    if (session_status() !== PHP_SESSION_NONE) {
        return; // Sessão já iniciada
    }
    
    // Detecção HTTPS robusta
    $isHttps = detectHttps();
    
    // Nome da sessão com prefixo seguro
    $sessionName = $isHttps ? '__Secure-EmbrapolCampanhaID' : 'EmbrapolCampanhaID';
    
    // Configurações de sessão otimizadas
    ini_set('session.use_only_cookies', '1');
    ini_set('session.cookie_httponly', '1');
    ini_set('session.use_strict_mode', '1');
    ini_set('session.cookie_samesite', 'Lax');
    ini_set('session.gc_maxlifetime', (string)SESSION_TIMEOUT);
    ini_set('session.gc_probability', '1');
    ini_set('session.gc_divisor', '100');
    
    // Cookie parameters
    $cookieParams = [
        'lifetime' => 0,
        'path'     => '/',
        'domain'   => '',
        'secure'   => $isHttps,
        'httponly' => true,
        'samesite' => 'Lax'
    ];
    
    session_name($sessionName);
    
    // Inicia sessão apenas se não for CLI e headers não foram enviados
    if (PHP_SAPI !== 'cli' && !headers_sent()) {
        session_set_cookie_params($cookieParams);
        session_start();
        
        // Regenera ID da sessão periodicamente
        if (!isset($_SESSION['last_regeneration'])) {
            $_SESSION['last_regeneration'] = time();
        } elseif (time() - $_SESSION['last_regeneration'] > 1800) { // 30 min
            session_regenerate_id(true);
            $_SESSION['last_regeneration'] = time();
        }
        
        // Timeout de sessão
        if (isset($_SESSION['last_activity']) && (time() - $_SESSION['last_activity']) > SESSION_TIMEOUT) {
            session_unset();
            session_destroy();
            session_start();
        }
        $_SESSION['last_activity'] = time();
    }
}

// Configura sessão
configureSession();

// ==============================================================================
// 9. HEADERS DE SEGURANÇA PREMIUM
// ==============================================================================

if (!headers_sent() && PHP_SAPI !== 'cli') {
    // Security headers básicos
    header('X-Content-Type-Options: nosniff');
    header('X-Frame-Options: DENY');
    header('X-XSS-Protection: 1; mode=block');
    header('Referrer-Policy: strict-origin-when-cross-origin');
    header('X-Permitted-Cross-Domain-Policies: none');
    
    // Remove headers que expõem informações
    header_remove('X-Powered-By');
    header_remove('Server');
    
    // HSTS para produção com HTTPS
    if (ENVIRONMENT === 'production' && detectHttps()) {
        header('Strict-Transport-Security: max-age=31536000; includeSubDomains; preload');
    }
    
    // CSP dinâmico baseado no ambiente
    $nonce = base64_encode(random_bytes(16));
    $_SESSION['csp_nonce'] = $nonce;
    
    $cspPolicies = [
        "default-src 'self'",
        "base-uri 'self'",
        "frame-ancestors 'none'",
        "form-action 'self'",
        "img-src 'self' data: blob:",
        "font-src 'self' https://fonts.gstatic.com https://cdnjs.cloudflare.com",
        "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com https://cdnjs.cloudflare.com",
        "script-src 'self' 'unsafe-inline' 'nonce-{$nonce}'" . (ENVIRONMENT === 'development' ? " 'unsafe-eval'" : ""),
        "connect-src 'self'",
        "object-src 'none'",
        "media-src 'self'",
        "worker-src 'self'"
    ];
    
    header('Content-Security-Policy: ' . implode('; ', $cspPolicies));
    
    // Permissions Policy
    $permissionsPolicies = [
        'geolocation=()',
        'microphone=()',
        'camera=()',
        'payment=()',
        'usb=()',
        'magnetometer=()',
        'gyroscope=()',
        'accelerometer=()'
    ];
    
    header('Permissions-Policy: ' . implode(', ', $permissionsPolicies));
}

// ==============================================================================
// 10. SISTEMA DE LOG ESTRUTURADO AVANÇADO
// ==============================================================================

if (!function_exists('logSecurityEvent')) {
    /**
     * Sistema de log de segurança com rotação automática e análise de padrões
     */
    function logSecurityEvent(string $eventType, string $message, array $context = []): void
    {
        $logFile = APP_ROOT . '/app/logs/security_' . ENVIRONMENT . '.log';
        $dir = dirname($logFile);
        
        if (!is_dir($dir)) {
            mkdir($dir, 0750, true);
        }
        
        // Rotação automática de logs
        if (is_file($logFile) && filesize($logFile) > (10 * 1024 * 1024)) { // 10MB
            $timestamp = date('Ymd_His');
            $rotatedFile = $logFile . '.' . $timestamp;
            rename($logFile, $rotatedFile);
            
            // Comprime logs antigos
            if (function_exists('gzencode')) {
                file_put_contents($rotatedFile . '.gz', gzencode(file_get_contents($rotatedFile)));
                unlink($rotatedFile);
            }
        }
        
        $now = new DateTimeImmutable('now');
        $sessionId = session_id() ?: 'no-session';
        $userId = $_SESSION['user_id'] ?? null;
        
        // Enriquece contexto com dados de request
        $enrichedContext = array_merge([
            'ip_address' => $_SERVER['REMOTE_ADDR'] ?? 'unknown',
            'user_agent' => $_SERVER['HTTP_USER_AGENT'] ?? 'unknown',
            'request_uri' => $_SERVER['REQUEST_URI'] ?? 'unknown',
            'request_method' => $_SERVER['REQUEST_METHOD'] ?? 'unknown',
            'referer' => $_SERVER['HTTP_REFERER'] ?? null,
            'session_id' => $sessionId,
            'user_id' => $userId,
            'environment' => ENVIRONMENT
        ], $context);
        
        $logData = [
            'timestamp' => $now->format('Y-m-d\TH:i:s.uP'),
            'level' => 'SECURITY',
            'event_type' => $eventType,
            'message' => $message,
            'context' => $enrichedContext,
            'hash' => hash('sha256', $eventType . $message . serialize($enrichedContext))
        ];
        
        $payload = json_encode($logData, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE) . PHP_EOL;
        
        $success = @file_put_contents($logFile, $payload, FILE_APPEND | LOCK_EX);
        
        if ($success === false) {
            error_log('CRITICAL: Falha ao escrever log de segurança: ' . $payload);
        }
        
        // Alerta em tempo real para eventos críticos
        if (in_array($eventType, ['BRUTE_FORCE_ATTEMPT', 'SQL_INJECTION_ATTEMPT', 'XSS_ATTEMPT'], true)) {
            error_log("SECURITY ALERT [{$eventType}]: {$message}");
        }
    }
}

// ==============================================================================
// 11. RATE LIMITING INTELIGENTE (CORRIGIDO)
// ==============================================================================

if (!function_exists('checkRateLimit')) {
    /**
     * Sistema de rate limiting por IP com diferentes níveis
     */
    function checkRateLimit(?string $identifier = null, ?int $maxRequests = null, ?int $windowSeconds = null): bool
    {
        $identifier = $identifier ?: ($_SERVER['REMOTE_ADDR'] ?? 'unknown');
        $maxRequests = $maxRequests ?: RATE_LIMIT_REQUESTS;
        $windowSeconds = $windowSeconds ?: RATE_LIMIT_WINDOW;
        
        $rateLimitFile = APP_ROOT . '/app/cache/rate_limit_' . md5($identifier) . '.json';
        $now = time();
        
        // Carrega dados existentes
        $data = [];
        if (file_exists($rateLimitFile)) {
            $content = file_get_contents($rateLimitFile);
            $data = json_decode($content, true) ?: [];
        }
        
        // Remove entradas expiradas
        $data = array_filter($data, fn($timestamp) => ($now - $timestamp) < $windowSeconds);
        
        // Verifica limite
        if (count($data) >= $maxRequests) {
            logSecurityEvent('RATE_LIMIT_EXCEEDED', 'Rate limit exceeded', [
                'identifier' => $identifier,
                'requests_count' => count($data),
                'max_requests' => $maxRequests,
                'window_seconds' => $windowSeconds
            ]);
            return false;
        }
        
        // Adiciona nova requisição
        $data[] = $now;
        
        // Salva dados
        $dir = dirname($rateLimitFile);
        if (!is_dir($dir)) {
            mkdir($dir, 0750, true);
        }
        
        file_put_contents($rateLimitFile, json_encode($data), LOCK_EX);
        
        return true;
    }
}

// ==============================================================================
// 12. CONSTANTES DA APLICAÇÃO
// ==============================================================================

// URLs da aplicação
if (!defined('APP_URL')) {
    $protocol = detectHttps() ? 'https' : 'http';
    $host = $_SERVER['HTTP_HOST'] ?? 'localhost';
    define('APP_URL', getenv('APP_URL') ?: $protocol . '://' . $host);
}

// Paths importantes
define('UPLOADS_PATH', APP_ROOT . '/uploads');
define('CACHE_PATH', APP_ROOT . '/app/cache');
define('LOGS_PATH', APP_ROOT . '/app/logs');

// Configurações de email
define('MAIL_FROM_NAME', getenv('MAIL_FROM_NAME') ?: 'Sistema Campanhas EPS');
define('MAIL_FROM_EMAIL', getenv('MAIL_FROM_EMAIL') ?: 'noreply@embrapol.com.br');

// Versão da aplicação
define('APP_VERSION', getenv('APP_VERSION') ?: '1.0.0');

// ==============================================================================
// 13. CARREGAMENTO DE MÓDULOS PRINCIPAIS
// ==============================================================================

function safeRequire(string $path, bool $required = true): bool {
    if (!is_file($path)) {
        $message = "Arquivo crítico não encontrado: {$path}";
        
        if ($required) {
            http_response_code(500);
            error_log($message);
            if (ENVIRONMENT === 'development') {
                exit($message);
            } else {
                exit('Erro interno do servidor');
            }
        }
        
        error_log($message);
        return false;
    }
    
    require_once $path;
    return true;
}

// Carrega helpers primeiro
safeRequire(APP_ROOT . '/app/core/helpers.php');

// Carrega módulos principais
safeRequire(APP_ROOT . '/app/config/database.php');
safeRequire(APP_ROOT . '/app/core/auth.php');

// Módulos opcionais
safeRequire(APP_ROOT . '/app/core/users.php', false);
safeRequire(APP_ROOT . '/app/core/email.php', false);

// ==============================================================================
// 14. VERIFICAÇÕES DE INTEGRIDADE
// ==============================================================================

// Verifica se diretórios necessários existem
$requiredDirs = [
    APP_ROOT . '/app/logs',
    APP_ROOT . '/app/cache',
    APP_ROOT . '/uploads'
];

foreach ($requiredDirs as $dir) {
    if (!is_dir($dir)) {
        mkdir($dir, 0750, true);
    }
}

// Verifica permissões críticas
$criticalFiles = [
    APP_ROOT . '/app/logs' => 'writable',
    APP_ROOT . '/app/cache' => 'writable',
    APP_ROOT . '/.env' => 'readable'
];

foreach ($criticalFiles as $path => $permission) {
    if (file_exists($path)) {
        switch ($permission) {
            case 'writable':
                if (!is_writable($path)) {
                    error_log("CRITICAL: {$path} não é gravável");
                }
                break;
            case 'readable':
                if (!is_readable($path)) {
                    error_log("CRITICAL: {$path} não é legível");
                }
                break;
        }
    }
}

// Log de inicialização
if (function_exists('logSecurityEvent')) {
    logSecurityEvent('SYSTEM_INIT', 'Sistema inicializado com sucesso', [
        'environment' => ENVIRONMENT,
        'php_version' => PHP_VERSION,
        'app_version' => APP_VERSION,
        'memory_limit' => ini_get('memory_limit'),
        'max_execution_time' => ini_get('max_execution_time')
    ]);
}