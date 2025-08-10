<?php
declare(strict_types=1);

/**
 * ==============================================================================
 * SISTEMA DE FUNÇÕES UTILITÁRIAS PREMIUM (Premium Helpers System) - v3.0
 * ==============================================================================
 * Localização: /app/core/helpers.php
 * Responsabilidade: Funções auxiliares reutilizáveis em todo o sistema
 * Focado em: Performance, Segurança, Validação e UX para o ramo óptico
 */

// --- PREVENÇÃO DE ACESSO DIRETO ---
if (!defined('APP_INITIATED')) {
    http_response_code(403);
    exit('Forbidden');
}

// ==============================================================================
// 1. DETECÇÃO DE PROTOCOLO E AMBIENTE
// ==============================================================================

if (!function_exists('detectHttps')) {
    /**
     * Detecção robusta de HTTPS (considera proxies/CDNs/load balancers)
     */
    function detectHttps(): bool
    {
        // Verifica HTTPS direto
        if (!empty($_SERVER['HTTPS']) && strtolower((string)$_SERVER['HTTPS']) !== 'off') {
            return true;
        }
        
        // Verifica porta 443
        if (!empty($_SERVER['SERVER_PORT']) && (int)$_SERVER['SERVER_PORT'] === 443) {
            return true;
        }
        
        // Headers de proxy/CDN
        $headers = [
            'HTTP_X_FORWARDED_PROTO' => 'https',
            'HTTP_X_ARR_SSL' => true, // Azure
            'HTTP_CF_VISITOR' => '"scheme":"https"', // Cloudflare
            'HTTP_X_FORWARDED_SSL' => 'on',
            'HTTP_X_HTTPS' => '1'
        ];
        
        foreach ($headers as $header => $value) {
            if (isset($_SERVER[$header])) {
                if (is_bool($value)) {
                    return !empty($_SERVER[$header]);
                }
                return strpos(strtolower((string)$_SERVER[$header]), (string)$value) !== false;
            }
        }
        
        return false;
    }
}

if (!function_exists('getBaseUrl')) {
    /**
     * Retorna a URL base da aplicação de forma inteligente
     */
    function getBaseUrl(): string
    {
        // Prioriza APP_URL se definida
        if (defined('APP_URL') && APP_URL) {
            return rtrim((string)APP_URL, '/');
        }
        
        // CLI ou sem servidor
        if (PHP_SAPI === 'cli' || empty($_SERVER['HTTP_HOST'])) {
            return 'http://localhost';
        }
        
        $scheme = detectHttps() ? 'https' : 'http';
        $host = $_SERVER['HTTP_HOST'] ?? $_SERVER['SERVER_NAME'] ?? 'localhost';
        $port = $_SERVER['SERVER_PORT'] ?? ($scheme === 'https' ? '443' : '80');
        
        // Remove porta padrão da URL
        if (($scheme === 'https' && $port === '443') || ($scheme === 'http' && $port === '80')) {
            return $scheme . '://' . $host;
        }
        
        return $scheme . '://' . $host . ':' . $port;
    }
}

// ==============================================================================
// 2. SANITIZAÇÃO E VALIDAÇÃO AVANÇADA
// ==============================================================================

if (!function_exists('sanitizeString')) {
    /**
     * Sanitização robusta de strings com múltiplas camadas
     */
    function sanitizeString(string $input, int $maxLength = 255, bool $allowHtml = false): string
    {
        // Remove null bytes
        $clean = str_replace("\0", '', $input);
        
        // Trim
        $clean = trim($clean);
        
        // Remove ou escapa HTML
        if (!$allowHtml) {
            $clean = strip_tags($clean);
            $clean = htmlspecialchars($clean, ENT_QUOTES | ENT_HTML5, 'UTF-8');
        }
        
        // Normaliza espaços
        $clean = preg_replace('/\s+/', ' ', $clean);
        
        // Limita comprimento
        return mb_substr($clean, 0, $maxLength, 'UTF-8');
    }
}

if (!function_exists('validateCpf')) {
    /**
     * Validação completa de CPF com algoritmo de dígito verificador
     */
    function validateCpf(string $cpf): bool
    {
        // Remove caracteres não numéricos
        $cpf = preg_replace('/\D/', '', $cpf);
        
        // Verifica se tem 11 dígitos
        if (strlen($cpf) !== 11) {
            return false;
        }
        
        // Verifica se todos os dígitos são iguais
        if (preg_match('/^(\d)\1{10}$/', $cpf)) {
            return false;
        }
        
        // Validação do primeiro dígito verificador
        $sum = 0;
        for ($i = 0; $i < 9; $i++) {
            $sum += (int)$cpf[$i] * (10 - $i);
        }
        $remainder = $sum % 11;
        $digit1 = $remainder < 2 ? 0 : 11 - $remainder;
        
        if ((int)$cpf[9] !== $digit1) {
            return false;
        }
        
        // Validação do segundo dígito verificador
        $sum = 0;
        for ($i = 0; $i < 10; $i++) {
            $sum += (int)$cpf[$i] * (11 - $i);
        }
        $remainder = $sum % 11;
        $digit2 = $remainder < 2 ? 0 : 11 - $remainder;
        
        return (int)$cpf[10] === $digit2;
    }
}

if (!function_exists('validateCnpj')) {
    /**
     * Validação completa de CNPJ com algoritmo de dígito verificador
     */
    function validateCnpj(string $cnpj): bool
    {
        // Remove caracteres não numéricos
        $cnpj = preg_replace('/\D/', '', $cnpj);
        
        // Verifica se tem 14 dígitos
        if (strlen($cnpj) !== 14) {
            return false;
        }
        
        // Verifica se todos os dígitos são iguais
        if (preg_match('/^(\d)\1{13}$/', $cnpj)) {
            return false;
        }
        
        // Validação do primeiro dígito verificador
        $weights = [5, 4, 3, 2, 9, 8, 7, 6, 5, 4, 3, 2];
        $sum = 0;
        
        for ($i = 0; $i < 12; $i++) {
            $sum += (int)$cnpj[$i] * $weights[$i];
        }
        
        $remainder = $sum % 11;
        $digit1 = $remainder < 2 ? 0 : 11 - $remainder;
        
        if ((int)$cnpj[12] !== $digit1) {
            return false;
        }
        
        // Validação do segundo dígito verificador
        $weights = [6, 5, 4, 3, 2, 9, 8, 7, 6, 5, 4, 3, 2];
        $sum = 0;
        
        for ($i = 0; $i < 13; $i++) {
            $sum += (int)$cnpj[$i] * $weights[$i];
        }
        
        $remainder = $sum % 11;
        $digit2 = $remainder < 2 ? 0 : 11 - $remainder;
        
        return (int)$cnpj[13] === $digit2;
    }
}

if (!function_exists('isValidEmailDomain')) {
    /**
     * Valida se o domínio do e-mail não é temporário/descartável
     */
    function isValidEmailDomain(string $email): bool
    {
        $domain = strtolower(substr(strrchr($email, '@'), 1));
        
        // Lista expandida de domínios temporários conhecidos
        $tempDomains = [
            '10minutemail.com', 'guerrillamail.com', 'mailinator.com',
            'tempmail.org', 'throwaway.email', 'temp-mail.org',
            'maildrop.cc', 'mailnesia.com', 'yopmail.com',
            'fake-mail.ml', 'mohmal.com', 'dispostable.com',
            'getairmail.com', 'mailcatch.com', 'sharklasers.com'
        ];
        
        return !in_array($domain, $tempDomains, true);
    }
}

if (!function_exists('validatePhone')) {
    /**
     * Validação robusta de telefone brasileiro
     */
    function validatePhone(string $phone): bool
    {
        // Remove caracteres não numéricos
        $phone = preg_replace('/\D/', '', $phone);
        
        // Celular brasileiro: 11 dígitos (DDD + 9 + 8 dígitos)
        // Fixo brasileiro: 10 dígitos (DDD + 7/8 dígitos)
        if (strlen($phone) < 10 || strlen($phone) > 11) {
            return false;
        }
        
        // Valida DDD (11 a 99)
        $ddd = (int)substr($phone, 0, 2);
        $validDdds = [
            11, 12, 13, 14, 15, 16, 17, 18, 19, // SP
            21, 22, 24, // RJ/ES
            27, 28, // ES
            31, 32, 33, 34, 35, 37, 38, // MG
            41, 42, 43, 44, 45, 46, // PR
            47, 48, 49, // SC
            51, 53, 54, 55, // RS
            61, // DF
            62, 64, // GO
            63, // TO
            65, 66, // MT
            67, // MS
            68, // AC
            69, // RO
            71, 73, 74, 75, 77, // BA
            79, // SE
            81, 87, // PE
            82, // AL
            83, // PB
            84, // RN
            85, 88, // CE
            86, 89, // PI
            91, 93, 94, // PA
            92, 97, // AM
            95, // RR
            96, // AP
            98, 99 // MA
        ];
        
        if (!in_array($ddd, $validDdds, true)) {
            return false;
        }
        
        // Se for celular (11 dígitos), verifica se começa com 9
        if (strlen($phone) === 11) {
            return $phone[2] === '9';
        }
        
        return true;
    }
}

// ==============================================================================
// 3. FORMATAÇÃO E MÁSCARAS
// ==============================================================================

if (!function_exists('formatCpf')) {
    /**
     * Formata CPF com máscara
     */
    function formatCpf(string $cpf): string
    {
        $cpf = preg_replace('/\D/', '', $cpf);
        return preg_replace('/(\d{3})(\d{3})(\d{3})(\d{2})/', '$1.$2.$3-$4', $cpf);
    }
}

if (!function_exists('formatCnpj')) {
    /**
     * Formata CNPJ com máscara
     */
    function formatCnpj(string $cnpj): string
    {
        $cnpj = preg_replace('/\D/', '', $cnpj);
        return preg_replace('/(\d{2})(\d{3})(\d{3})(\d{4})(\d{2})/', '$1.$2.$3/$4-$5', $cnpj);
    }
}

if (!function_exists('formatPhone')) {
    /**
     * Formata telefone brasileiro
     */
    function formatPhone(string $phone): string
    {
        $phone = preg_replace('/\D/', '', $phone);
        
        if (strlen($phone) === 11) {
            // Celular: (XX) 9XXXX-XXXX
            return preg_replace('/(\d{2})(\d{5})(\d{4})/', '($1) $2-$3', $phone);
        } elseif (strlen($phone) === 10) {
            // Fixo: (XX) XXXX-XXXX
            return preg_replace('/(\d{2})(\d{4})(\d{4})/', '($1) $2-$3', $phone);
        }
        
        return $phone;
    }
}

// ==============================================================================
// 4. SISTEMA DE LOGS AVANÇADO
// ==============================================================================

if (!function_exists('rotateLogFile')) {
    /**
     * Rotaciona arquivo de log quando atinge tamanho máximo
     */
    function rotateLogFile(string $logFile, int $maxSizeMB = 5): void
    {
        if (!is_file($logFile)) {
            return;
        }
        
        $fileSize = filesize($logFile);
        $maxSize = $maxSizeMB * 1024 * 1024;
        
        if ($fileSize > $maxSize) {
            $timestamp = date('Ymd_His');
            $rotatedFile = $logFile . '.' . $timestamp . '.gz';
            
            // Comprime o log antigo
            $content = file_get_contents($logFile);
            if ($content !== false) {
                file_put_contents($rotatedFile, gzencode($content));
                file_put_contents($logFile, ''); // Limpa o arquivo atual
            }
        }
    }
}

if (!function_exists('logWithContext')) {
    /**
     * Sistema de log avançado com contexto e níveis
     */
    function logWithContext(string $level, string $message, array $context = []): void
    {
        $logFile = APP_ROOT . '/app/logs/app.log';
        $dir = dirname($logFile);
        
        if (!is_dir($dir)) {
            mkdir($dir, 0750, true);
        }
        
        // Rotaciona se necessário
        rotateLogFile($logFile);
        
        $timestamp = (new DateTimeImmutable('now'))->format('Y-m-d H:i:s.u P');
        $sessionId = session_id() ?: 'no-session';
        $userId = $_SESSION['user_id'] ?? 'anonymous';
        $ip = $_SERVER['REMOTE_ADDR'] ?? 'unknown';
        
        $logData = [
            'timestamp' => $timestamp,
            'level' => strtoupper($level),
            'message' => $message,
            'context' => $context,
            'meta' => [
                'session_id' => $sessionId,
                'user_id' => $userId,
                'ip_address' => $ip,
                'user_agent' => $_SERVER['HTTP_USER_AGENT'] ?? 'unknown',
                'request_uri' => $_SERVER['REQUEST_URI'] ?? 'unknown',
                'request_method' => $_SERVER['REQUEST_METHOD'] ?? 'unknown'
            ]
        ];
        
        $logLine = json_encode($logData, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE) . PHP_EOL;
        
        @file_put_contents($logFile, $logLine, FILE_APPEND | LOCK_EX);
    }
}

// ==============================================================================
// 5. SEGURANÇA E TOKENS
// ==============================================================================

if (!function_exists('generateSecureToken')) {
    /**
     * Gera token seguro com diferentes formatos
     */
    function generateSecureToken(int $bytes = 32, string $format = 'hex'): string
    {
        $randomBytes = random_bytes($bytes);
        
        switch ($format) {
            case 'base64':
                return rtrim(strtr(base64_encode($randomBytes), '+/', '-_'), '=');
            case 'base64url':
                return strtr(rtrim(base64_encode($randomBytes), '='), '+/', '-_');
            case 'hex':
            default:
                return bin2hex($randomBytes);
        }
    }
}

if (!function_exists('hashPassword')) {
    /**
     * Hash de senha com configurações otimizadas
     */
    function hashPassword(string $password): string
    {
        $options = [
            'cost' => defined('PASSWORD_COST') ? PASSWORD_COST : 12,
        ];
        
        return password_hash($password, PASSWORD_ARGON2ID, $options);
    }
}

if (!function_exists('isStrongPassword')) {
    /**
     * Validação robusta de força de senha
     */
    function isStrongPassword(string $password): array
    {
        $result = [
            'valid' => false,
            'score' => 0,
            'requirements' => []
        ];
        
        $requirements = [
            'length' => strlen($password) >= 8,
            'uppercase' => preg_match('/[A-Z]/', $password),
            'lowercase' => preg_match('/[a-z]/', $password),
            'number' => preg_match('/[0-9]/', $password),
            'special' => preg_match('/[^A-Za-z0-9]/', $password),
            'no_common' => !in_array(strtolower($password), [
                'password', '12345678', 'qwerty', 'abc123', 'password123'
            ], true)
        ];
        
        $result['requirements'] = $requirements;
        $result['score'] = array_sum($requirements);
        $result['valid'] = $result['score'] >= 5; // Todas exceto uma
        
        return $result;
    }
}

// ==============================================================================
// 6. UTILITÁRIOS ESPECÍFICOS PARA SISTEMA ÓPTICO
// ==============================================================================

if (!function_exists('validatePrescriptionData')) {
    /**
     * Valida dados de prescrição óptica
     */
    function validatePrescriptionData(array $prescription): array
    {
        $errors = [];
        
        // Validações específicas para grau, cilindro, eixo, etc.
        $fields = ['od_esferico', 'oe_esferico', 'od_cilindrico', 'oe_cilindrico'];
        
        foreach ($fields as $field) {
            if (isset($prescription[$field])) {
                $value = (float)$prescription[$field];
                if ($value < -30.00 || $value > 30.00) {
                    $errors[] = "Valor de {$field} fora do range válido (-30.00 a +30.00)";
                }
            }
        }
        
        return $errors;
    }
}

if (!function_exists('formatCurrency')) {
    /**
     * Formata valor monetário brasileiro
     */
    function formatCurrency(float $value): string
    {
        return 'R$ ' . number_format($value, 2, ',', '.');
    }
}

if (!function_exists('generateOpticalReceipt')) {
    /**
     * Gera número de recibo óptico único
     */
    function generateOpticalReceipt(): string
    {
        $timestamp = date('YmdHis');
        $random = str_pad((string)mt_rand(0, 9999), 4, '0', STR_PAD_LEFT);
        return 'OPT' . $timestamp . $random;
    }
}

// ==============================================================================
// 7. PERFORMANCE E CACHE
// ==============================================================================

if (!function_exists('cacheGet')) {
    /**
     * Sistema simples de cache em arquivo
     */
    function cacheGet(string $key, int $ttl = 3600): mixed
    {
        $cacheDir = APP_ROOT . '/app/cache';
        if (!is_dir($cacheDir)) {
            mkdir($cacheDir, 0750, true);
        }
        
        $cacheFile = $cacheDir . '/' . md5($key) . '.cache';
        
        if (!file_exists($cacheFile)) {
            return null;
        }
        
        $data = @unserialize(file_get_contents($cacheFile));
        if ($data === false || $data['expires'] < time()) {
            @unlink($cacheFile);
            return null;
        }
        
        return $data['value'];
    }
}

if (!function_exists('cacheSet')) {
    /**
     * Armazena valor no cache
     */
    function cacheSet(string $key, mixed $value, int $ttl = 3600): bool
    {
        $cacheDir = APP_ROOT . '/app/cache';
        if (!is_dir($cacheDir)) {
            mkdir($cacheDir, 0750, true);
        }
        
        $cacheFile = $cacheDir . '/' . md5($key) . '.cache';
        $data = [
            'value' => $value,
            'expires' => time() + $ttl
        ];
        
        return @file_put_contents($cacheFile, serialize($data), LOCK_EX) !== false;
    }
}