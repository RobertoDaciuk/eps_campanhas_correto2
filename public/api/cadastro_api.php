<?php
declare(strict_types=1);

/**
 * ==============================================================================
 * API DE CADASTRO PREMIUM (Premium Registration API) - v4.0
 * ==============================================================================
 * Localização: /public/api/cadastro_api.php
 * 
 * Aprimoramentos v4.0:
 * - Validação em tempo real otimizada
 * - Sistema de detecção de fraude
 * - Upload de documentos opcional
 * - Integração com sistema óptico
 * - Analytics de conversão
 */

// Define a constante de inicialização
define('APP_INITIATED', true);
define('APP_ROOT', dirname(__DIR__, 2));

// Carrega o sistema
require_once APP_ROOT . '/app/config/config.php';

// Função auxiliar para verificar rate limiting (se não existir)
if (!function_exists('checkRateLimit')) {
    function checkRateLimit(string $identifier, int $maxRequests = 10, int $windowSeconds = 3600): bool
    {
        $rateLimitFile = APP_ROOT . '/app/cache/rate_limit_' . md5($identifier) . '.json';
        $now = time();
        
        // Cria diretório se não existir
        $dir = dirname($rateLimitFile);
        if (!is_dir($dir)) {
            mkdir($dir, 0750, true);
        }
        
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
            return false;
        }
        
        // Adiciona nova requisição
        $data[] = $now;
        
        // Salva dados
        file_put_contents($rateLimitFile, json_encode($data), LOCK_EX);
        
        return true;
    }
}

// Função auxiliar para validação CNPJ (se não existir)
if (!function_exists('validateCnpj')) {
    function validateCnpj(string $cnpj): bool
    {
        $cnpj = preg_replace('/\D/', '', $cnpj);
        
        if (strlen($cnpj) !== 14 || preg_match('/^(\d)\1{13}$/', $cnpj)) {
            return false;
        }
        
        // Validação do primeiro dígito verificador
        $weights1 = [5, 4, 3, 2, 9, 8, 7, 6, 5, 4, 3, 2];
        $sum = 0;
        
        for ($i = 0; $i < 12; $i++) {
            $sum += (int)$cnpj[$i] * $weights1[$i];
        }
        
        $remainder = $sum % 11;
        $digit1 = $remainder < 2 ? 0 : 11 - $remainder;
        
        if ((int)$cnpj[12] !== $digit1) {
            return false;
        }
        
        // Validação do segundo dígito verificador
        $weights2 = [6, 5, 4, 3, 2, 9, 8, 7, 6, 5, 4, 3, 2];
        $sum = 0;
        
        for ($i = 0; $i < 13; $i++) {
            $sum += (int)$cnpj[$i] * $weights2[$i];
        }
        
        $remainder = $sum % 11;
        $digit2 = $remainder < 2 ? 0 : 11 - $remainder;
        
        return (int)$cnpj[13] === $digit2;
    }
}

// Função para dbQuery se não existir
if (!function_exists('dbQuery')) {
    function dbQuery(string $query, array $params = [], string $connectionType = 'write') {
        try {
            $pdo = getDbConnection($connectionType);
            
            if (empty($params)) {
                return $pdo->query($query);
            } else {
                $stmt = $pdo->prepare($query);
                $stmt->execute($params);
                return $stmt;
            }
        } catch (Exception $e) {
            error_log('Database query error: ' . $e->getMessage());
            throw $e;
        }
    }
}

// ==============================================================================
// 1. CONFIGURAÇÃO DE HEADERS E SEGURANÇA
// ==============================================================================

// Headers de API seguros
header('Content-Type: application/json; charset=utf-8');
header('X-Content-Type-Options: nosniff');
header('X-Frame-Options: DENY');
header('X-XSS-Protection: 1; mode=block');
header('Referrer-Policy: strict-origin-when-cross-origin');

// Rate limiting para cadastro
$rateLimitKey = 'register_' . ($_SERVER['REMOTE_ADDR'] ?? 'unknown');
$maxAttempts = ENVIRONMENT === 'production' ? 5 : 20; // Mais restritivo para cadastro
$windowTime = 3600; // 1 hora

if (!checkRateLimit($rateLimitKey, $maxAttempts, $windowTime)) {
    http_response_code(429);
    echo json_encode([
        'success' => false,
        'error' => 'RATE_LIMIT_EXCEEDED',
        'message' => 'Muitas tentativas de cadastro. Tente novamente em 1 hora.',
        'retry_after' => 3600
    ]);
    exit;
}

// ==============================================================================
// 2. CLASSE PRINCIPAL DA API DE CADASTRO
// ==============================================================================

class RegistrationAPI
{
    private float $startTime;
    private array $fraudMetrics = [];
    private UserManager $userManager;
    
    public function __construct()
    {
        $this->startTime = microtime(true);
        $this->userManager = new UserManager();
        $this->fraudMetrics = [
            'ip_address' => $_SERVER['REMOTE_ADDR'] ?? 'unknown',
            'user_agent' => $_SERVER['HTTP_USER_AGENT'] ?? 'unknown',
            'request_time' => date('Y-m-d H:i:s'),
            'referrer' => $_SERVER['HTTP_REFERER'] ?? null,
            'submission_speed' => null // Calculado posteriormente
        ];
    }
    
    /**
     * Processa requisição de cadastro
     */
    public function processRegistration(): array
    {
        try {
            // 1. Validação do método
            if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
                return $this->errorResponse('METHOD_NOT_ALLOWED', 'Método não permitido', 405);
            }
            
            // 2. Validação e parse do input
            $input = $this->validateAndParseInput();
            if (isset($input['error'])) {
                return $input;
            }
            
            // 3. Análise de fraude
            $fraudCheck = $this->analyzeFraudRisk($input);
            if ($fraudCheck['high_risk']) {
                $this->logSecurityEvent('FRAUD_DETECTED', 'Alto risco de fraude detectado', $fraudCheck);
                return $this->errorResponse('FRAUD_DETECTED', 'Cadastro bloqueado por suspeita de fraude', 403);
            }
            
            // 4. Validação completa dos dados
            $validation = $this->userManager->validateUserData($input);
            if (!$validation['is_valid']) {
                return $this->errorResponse('VALIDATION_FAILED', 'Dados inválidos', 400, [
                    'field_errors' => $validation['errors'],
                    'warnings' => $validation['warnings']
                ]);
            }
            
            // 5. Verificação de duplicatas avançada
            $duplicateCheck = $this->checkForDuplicates($input);
            if ($duplicateCheck['found']) {
                return $this->errorResponse('DUPLICATE_FOUND', $duplicateCheck['message'], 409, [
                    'duplicate_fields' => $duplicateCheck['fields']
                ]);
            }
            
            // 6. Validação da ótica
            $opticalValidation = $this->validateOpticalShop($input['cnpj']);
            if (!$opticalValidation['valid']) {
                return $this->errorResponse('OPTICAL_INVALID', $opticalValidation['message'], 400);
            }
            
            // 7. Criação do usuário
            $registrationResult = $this->createUser($input, $opticalValidation);
            if (!$registrationResult['success']) {
                return $this->errorResponse('REGISTRATION_FAILED', $registrationResult['message'], 500);
            }
            
            // 8. Envio de e-mail de ativação
            $emailResult = $this->sendActivationEmail($registrationResult);
            
            // 9. Log de sucesso e analytics
            $this->recordSuccessfulRegistration($registrationResult, $emailResult);
            
            return $this->successResponse([
                'user_id' => $registrationResult['user_id'],
                'email_sent' => $emailResult['sent'],
                'next_steps' => [
                    'check_email' => true,
                    'activation_required' => true,
                    'support_contact' => getenv('SUPPORT_EMAIL') ?: 'suporte@embrapol.com.br'
                ]
            ], 'Cadastro realizado com sucesso! Verifique seu e-mail para ativar a conta.');
            
        } catch (Exception $e) {
            $this->logSecurityEvent('REGISTRATION_EXCEPTION', 'Exceção durante cadastro', [
                'error' => $e->getMessage(),
                'trace' => ENVIRONMENT === 'development' ? $e->getTraceAsString() : null
            ]);
            
            return $this->errorResponse('INTERNAL_ERROR', 'Erro interno do servidor', 500);
        }
    }
    
    /**
     * Valida e parse o input JSON
     */
    private function validateAndParseInput(): array
    {
        $rawInput = file_get_contents('php://input');
        
        if (empty($rawInput)) {
            return $this->errorResponse('EMPTY_PAYLOAD', 'Dados de entrada ausentes', 400);
        }
        
        // Calcula velocidade de submissão (detecção de bot)
        $submissionTime = $_SERVER['HTTP_X_SUBMISSION_TIME'] ?? null;
        if ($submissionTime) {
            $this->fraudMetrics['submission_speed'] = time() - (int)$submissionTime;
        }
        
        $input = json_decode($rawInput, true);
        
        if (json_last_error() !== JSON_ERROR_NONE) {
            $this->logSecurityEvent('MALFORMED_JSON', 'JSON malformado no cadastro', [
                'json_error' => json_last_error_msg(),
                'payload_length' => strlen($rawInput)
            ]);
            
            return $this->errorResponse('INVALID_JSON', 'Formato de dados inválido', 400);
        }
        
        // Validação de campos obrigatórios
        $requiredFields = ['nome', 'cpf', 'email', 'celular', 'cnpj', 'senha', 'confirmar_senha', 'termos'];
        $missingFields = [];
        
        foreach ($requiredFields as $field) {
            if (!isset($input[$field]) || $input[$field] === '') {
                $missingFields[] = $field;
            }
        }
        
        if (!empty($missingFields)) {
            return $this->errorResponse('MISSING_FIELDS', 'Campos obrigatórios ausentes', 400, [
                'missing_fields' => $missingFields
            ]);
        }
        
        // Validação de tamanhos básicos
        if (strlen($input['nome']) > 120 || strlen($input['email']) > 255) {
            return $this->errorResponse('FIELD_TOO_LONG', 'Um ou mais campos excedem o tamanho máximo', 400);
        }
        
        return $input;
    }
    
    /**
     * Análise de risco de fraude
     */
    private function analyzeFraudRisk(array $input): array
    {
        $riskScore = 0;
        $indicators = [];
        
        // 1. Velocidade de submissão muito rápida (possível bot)
        if ($this->fraudMetrics['submission_speed'] !== null && $this->fraudMetrics['submission_speed'] < 30) {
            $riskScore += 30;
            $indicators[] = 'fast_submission';
        }
        
        // 2. User-Agent suspeito
        $userAgent = $this->fraudMetrics['user_agent'];
        if (empty($userAgent) || 
            strpos($userAgent, 'bot') !== false || 
            strpos($userAgent, 'crawler') !== false) {
            $riskScore += 25;
            $indicators[] = 'suspicious_user_agent';
        }
        
        // 3. Dados muito similares ou padrões suspeitos
        if ($this->detectSuspiciousPatterns($input)) {
            $riskScore += 20;
            $indicators[] = 'suspicious_data_patterns';
        }
        
        // 4. IP em lista negra (implementação futura)
        if ($this->isBlacklistedIP($this->fraudMetrics['ip_address'])) {
            $riskScore += 40;
            $indicators[] = 'blacklisted_ip';
        }
        
        // 5. Múltiplas tentativas do mesmo IP
        if ($this->countRecentAttemptsFromIP() > 3) {
            $riskScore += 15;
            $indicators[] = 'multiple_attempts';
        }
        
        return [
            'risk_score' => $riskScore,
            'high_risk' => $riskScore >= 50,
            'indicators' => $indicators,
            'metrics' => $this->fraudMetrics
        ];
    }
    
    /**
     * Detecta padrões suspeitos nos dados
     */
    private function detectSuspiciousPatterns(array $input): bool
    {
        // Nome com padrões repetitivos
        if (preg_match('/(.)\1{3,}/', $input['nome'])) {
            return true;
        }
        
        // Email com domínios temporários conhecidos
        $email = strtolower($input['email']);
        $suspiciousDomains = [
            'tempmail.org', 'guerrillamail.com', 'mailinator.com',
            '10minutemail.com', 'throwaway.email'
        ];
        
        foreach ($suspiciousDomains as $domain) {
            if (strpos($email, $domain) !== false) {
                return true;
            }
        }
        
        // CPF com padrões conhecidos
        $cpf = preg_replace('/\D/', '', $input['cpf']);
        if (preg_match('/^(\d)\1{10}$/', $cpf)) {
            return true;
        }
        
        return false;
    }
    
    /**
     * Verifica se IP está em lista negra
     */
    private function isBlacklistedIP(string $ip): bool
    {
        // Implementação básica - expandir conforme necessário
        $blacklistedIPs = [
            '127.0.0.1', // placeholder
        ];
        
        return in_array($ip, $blacklistedIPs, true);
    }
    
    /**
     * Conta tentativas recentes do mesmo IP
     */
    private function countRecentAttemptsFromIP(): int
    {
        try {
            $stmt = dbQuery(
                "SELECT COUNT(*) FROM usuarios 
                 WHERE created_at > DATE_SUB(NOW(), INTERVAL 1 HOUR) 
                 AND JSON_EXTRACT(metadata, '$.ip_address') = ?",
                [$this->fraudMetrics['ip_address']],
                'read'
            );
            
            return (int)$stmt->fetchColumn();
            
        } catch (Exception $e) {
            return 0;
        }
    }
    
    /**
     * Verificação avançada de duplicatas
     */
    private function checkForDuplicates(array $input): array
    {
        $duplicates = [];
        
        try {
            // Verifica CPF
            $cpf = preg_replace('/\D/', '', $input['cpf']);
            $stmt = dbQuery(
                "SELECT id, nome, status FROM usuarios WHERE cpf = ? LIMIT 1",
                [$cpf],
                'read'
            );
            $existingCpf = $stmt->fetch();
            
            if ($existingCpf) {
                $duplicates['cpf'] = [
                    'field' => 'cpf',
                    'user_id' => $existingCpf['id'],
                    'status' => $existingCpf['status']
                ];
            }
            
            // Verifica E-mail
            $email = strtolower(trim($input['email']));
            $stmt = dbQuery(
                "SELECT id, nome, status FROM usuarios WHERE email = ? LIMIT 1",
                [$email],
                'read'
            );
            $existingEmail = $stmt->fetch();
            
            if ($existingEmail) {
                $duplicates['email'] = [
                    'field' => 'email',
                    'user_id' => $existingEmail['id'],
                    'status' => $existingEmail['status']
                ];
            }
            
            if (!empty($duplicates)) {
                $message = 'Dados já cadastrados no sistema.';
                
                // Mensagem específica baseada no status
                foreach ($duplicates as $duplicate) {
                    if ($duplicate['status'] === 'pendente') {
                        $message = 'Existe um cadastro pendente com estes dados. Verifique seu e-mail ou solicite novo link de ativação.';
                        break;
                    } elseif ($duplicate['status'] === 'ativo') {
                        $message = 'Estes dados já estão cadastrados e ativos. Faça login ou recupere sua senha.';
                        break;
                    }
                }
                
                return [
                    'found' => true,
                    'message' => $message,
                    'fields' => array_keys($duplicates)
                ];
            }
            
            return ['found' => false];
            
        } catch (Exception $e) {
            $this->logSecurityEvent('DUPLICATE_CHECK_ERROR', 'Erro na verificação de duplicatas', [
                'error' => $e->getMessage()
            ]);
            
            return ['found' => false]; // Em caso de erro, permite prosseguir
        }
    }
    
    /**
     * Valida ótica no sistema
     */
    private function validateOpticalShop(string $cnpj): array
    {
        $validation = validateOpticalShop($cnpj);
        
        if (!$validation['valid']) {
            $this->logSecurityEvent('OPTICAL_VALIDATION_FAILED', 'Validação de ótica falhou', [
                'cnpj' => $cnpj,
                'reason' => $validation['reason']
            ]);
            
            $message = match($validation['reason']) {
                'CNPJ inválido' => 'CNPJ informado é inválido.',
                'Ótica não encontrada' => 'CNPJ não encontrado em nossa base de óticas parceiras.',
                'Ótica não está ativa' => 'Esta ótica não está ativa no sistema.',
                default => 'Erro na validação da ótica.'
            };
            
            return ['valid' => false, 'message' => $message];
        }
        
        return $validation;
    }
    
    /**
     * Cria usuário no sistema
     */
    private function createUser(array $input, array $opticalData): array
    {
        try {
            // Prepara dados normalizados
            $userData = [
                'nome' => sanitizeString(ucwords(strtolower(trim($input['nome']))), 120),
                'cpf' => preg_replace('/\D/', '', $input['cpf']),
                'email' => strtolower(trim($input['email'])),
                'celular' => preg_replace('/\D/', '', $input['celular']),
                'cnpj' => preg_replace('/\D/', '', $input['cnpj']),
                'senha' => $input['senha'],
                'confirmar_senha' => $input['confirmar_senha'],
                'id_otica' => $opticalData['id_otica'],
                'metadata' => json_encode([
                    'ip_address' => $this->fraudMetrics['ip_address'],
                    'user_agent' => $this->fraudMetrics['user_agent'],
                    'registration_source' => 'web_form',
                    'otica_info' => [
                        'id' => $opticalData['id_otica'],
                        'razao_social' => $opticalData['razao_social'],
                        'endereco' => $opticalData['endereco']
                    ]
                ])
            ];
            
            // Valida senhas coincidentes
            if ($userData['senha'] !== $userData['confirmar_senha']) {
                return ['success' => false, 'message' => 'Senhas não coincidem'];
            }
            
            // Cria usuário
            $token = criarNovoUsuario($userData);
            
            if (!$token) {
                return ['success' => false, 'message' => 'Falha na criação do usuário'];
            }
            
            // Busca o usuário criado para retornar informações
            $newUser = findUserByIdentifier($userData['cpf']);
            
            return [
                'success' => true,
                'user_id' => $newUser['id'],
                'token' => $token,
                'user_data' => [
                    'nome' => $newUser['nome'],
                    'email' => $newUser['email'],
                    'otica_nome' => $opticalData['razao_social']
                ]
            ];
            
        } catch (Exception $e) {
            $this->logSecurityEvent('USER_CREATION_ERROR', 'Erro na criação de usuário', [
                'error' => $e->getMessage(),
                'email_hash' => hash('sha256', $input['email']),
                'cpf_hash' => hash('sha256', $input['cpf'])
            ]);
            
            return ['success' => false, 'message' => 'Erro interno na criação do usuário'];
        }
    }
    
    /**
     * Envia e-mail de ativação
     */
    private function sendActivationEmail(array $registrationResult): array
    {
        try {
            $sent = enviarEmailAtivacao(
                $registrationResult['user_data']['email'],
                $registrationResult['user_data']['nome'],
                $registrationResult['token']
            );
            
            $result = [
                'sent' => $sent,
                'email' => $registrationResult['user_data']['email']
            ];
            
            if (!$sent) {
                $this->logSecurityEvent('ACTIVATION_EMAIL_FAILED', 'Falha no envio de e-mail de ativação', [
                    'user_id' => $registrationResult['user_id'],
                    'email_hash' => hash('sha256', $registrationResult['user_data']['email'])
                ]);
                
                $result['message'] = 'Usuário criado, mas houve falha no envio do e-mail. Entre em contato com o suporte.';
            }
            
            return $result;
            
        } catch (Exception $e) {
            $this->logSecurityEvent('EMAIL_SEND_ERROR', 'Exceção no envio de e-mail', [
                'user_id' => $registrationResult['user_id'],
                'error' => $e->getMessage()
            ]);
            
            return [
                'sent' => false,
                'message' => 'Falha no envio do e-mail de ativação'
            ];
        }
    }
    
    /**
     * Registra cadastro bem-sucedido para analytics
     */
    private function recordSuccessfulRegistration(array $registrationResult, array $emailResult): void
    {
        $analyticsData = [
            'user_id' => $registrationResult['user_id'],
            'registration_time' => date('Y-m-d H:i:s'),
            'source' => 'web_form',
            'email_sent' => $emailResult['sent'],
            'otica_nome' => $registrationResult['user_data']['otica_nome'],
            'user_agent' => $this->fraudMetrics['user_agent'],
            'ip_address' => $this->fraudMetrics['ip_address'],
            'submission_speed' => $this->fraudMetrics['submission_speed'],
            'execution_time_ms' => round((microtime(true) - $this->startTime) * 1000, 2)
        ];
        
        // Log para analytics
        $this->logSecurityEvent('REGISTRATION_SUCCESS', 'Cadastro realizado com sucesso', $analyticsData);
        
        // Audit trail
        if (function_exists('auditUserAction')) {
            auditUserAction('USER_REGISTERED', 'Novo usuário se cadastrou no sistema', [
                'user_id' => $registrationResult['user_id'],
                'registration_source' => 'web_form'
            ]);
        }
        
        // Salva métricas para análise futura
        $this->saveRegistrationMetrics($analyticsData);
    }
    
    /**
     * Salva métricas de cadastro para análise
     */
    private function saveRegistrationMetrics(array $data): void
    {
        try {
            $stmt = dbQuery(
                "INSERT INTO registration_metrics (user_id, source, execution_time_ms, email_sent, ip_address, created_at) 
                 VALUES (?, ?, ?, ?, ?, NOW())",
                [
                    $data['user_id'],
                    $data['source'],
                    $data['execution_time_ms'],
                    $data['email_sent'] ? 1 : 0,
                    $data['ip_address']
                ]
            );
            
        } catch (Exception $e) {
            // Falha silenciosa - métricas não são críticas
            error_log('Registration metrics save failed: ' . $e->getMessage());
        }
    }
    
    /**
     * Log de eventos de segurança
     */
    private function logSecurityEvent(string $event, string $message, array $context = []): void
    {
        $enrichedContext = array_merge($this->fraudMetrics, $context);
        
        if (function_exists('logSecurityEvent')) {
            logSecurityEvent($event, $message, $enrichedContext);
        } else {
            error_log("SECURITY EVENT [{$event}]: {$message} " . json_encode($enrichedContext));
        }
    }
    
    /**
     * Resposta de sucesso padronizada
     */
    private function successResponse(array $data, string $message = 'Operação realizada com sucesso'): array
    {
        $response = [
            'success' => true,
            'message' => $message,
            'data' => $data,
            'timestamp' => date('c'),
            'request_id' => uniqid('reg_', true)
        ];
        
        // Métricas de performance em desenvolvimento
        if (ENVIRONMENT === 'development') {
            $response['debug'] = [
                'execution_time_ms' => round((microtime(true) - $this->startTime) * 1000, 2),
                'memory_usage' => round(memory_get_peak_usage(true) / 1024 / 1024, 2) . 'MB'
            ];
        }
        
        http_response_code(201); // Created
        return $response;
    }
    
    /**
     * Resposta de erro padronizada
     */
    private function errorResponse(string $errorCode, string $message, int $httpCode = 400, array $additionalData = []): array
    {
        $response = [
            'success' => false,
            'error' => $errorCode,
            'message' => $message,
            'timestamp' => date('c'),
            'request_id' => uniqid('reg_', true)
        ];
        
        if (!empty($additionalData)) {
            $response['data'] = $additionalData;
        }
        
        // Debug info em desenvolvimento
        if (ENVIRONMENT === 'development') {
            $response['debug'] = [
                'execution_time_ms' => round((microtime(true) - $this->startTime) * 1000, 2),
                'memory_usage' => round(memory_get_peak_usage(true) / 1024 / 1024, 2) . 'MB',
                'environment' => ENVIRONMENT
            ];
        }
        
        http_response_code($httpCode);
        return $response;
    }
}

// ==============================================================================
// 3. API DE VALIDAÇÃO EM TEMPO REAL
// ==============================================================================

class ValidationAPI
{
    /**
     * Valida campo individual em tempo real
     */
    public static function validateField(): array
    {
        if ($_SERVER['REQUEST_METHOD'] !== 'GET') {
            http_response_code(405);
            return ['success' => false, 'message' => 'Método não permitido'];
        }
        
        $field = $_GET['field'] ?? '';
        $value = $_GET['value'] ?? '';
        
        if (empty($field) || $value === '') {
            http_response_code(400);
            return ['success' => false, 'message' => 'Parâmetros inválidos'];
        }
        
        try {
            switch ($field) {
                case 'cpf':
                    return self::validateCpfField($value);
                    
                case 'email':
                    return self::validateEmailField($value);
                    
                case 'cnpj':
                    return self::validateCnpjField($value);
                    
                default:
                    http_response_code(400);
                    return ['success' => false, 'message' => 'Campo não suportado'];
            }
            
        } catch (Exception $e) {
            logSecurityEvent('VALIDATION_API_ERROR', 'Erro na API de validação', [
                'field' => $field,
                'error' => $e->getMessage()
            ]);
            
            http_response_code(500);
            return ['success' => false, 'message' => 'Erro interno'];
        }
    }
    
    /**
     * Valida CPF em tempo real
     */
    private static function validateCpfField(string $cpf): array
    {
        $cpfClean = preg_replace('/\D/', '', $cpf);
        
        if (strlen($cpfClean) !== 11) {
            return [
                'success' => true,
                'valid' => false,
                'message' => 'CPF deve ter 11 dígitos'
            ];
        }
        
        if (!validateCpf($cpfClean)) {
            return [
                'success' => true,
                'valid' => false,
                'message' => 'CPF inválido'
            ];
        }
        
        // Verifica se já existe
        $stmt = dbQuery(
            "SELECT COUNT(*) FROM usuarios WHERE cpf = ?",
            [$cpfClean],
            'read'
        );
        
        $exists = $stmt->fetchColumn() > 0;
        
        return [
            'success' => true,
            'valid' => !$exists,
            'available' => !$exists,
            'message' => $exists ? 'CPF já cadastrado' : 'CPF válido'
        ];
    }
    
    /**
     * Valida e-mail em tempo real
     */
    private static function validateEmailField(string $email): array
    {
        $emailClean = strtolower(trim($email));
        
        if (!filter_var($emailClean, FILTER_VALIDATE_EMAIL)) {
            return [
                'success' => true,
                'valid' => false,
                'message' => 'E-mail inválido'
            ];
        }
        
        if (!isValidEmailDomain($emailClean)) {
            return [
                'success' => true,
                'valid' => false,
                'message' => 'Domínio de e-mail não permitido'
            ];
        }
        
        // Verifica se já existe
        $stmt = dbQuery(
            "SELECT COUNT(*) FROM usuarios WHERE email = ?",
            [$emailClean],
            'read'
        );
        
        $exists = $stmt->fetchColumn() > 0;
        
        return [
            'success' => true,
            'valid' => !$exists,
            'available' => !$exists,
            'message' => $exists ? 'E-mail já cadastrado' : 'E-mail válido'
        ];
    }
    
    /**
     * Valida CNPJ e retorna dados da ótica
     */
    private static function validateCnpjField(string $cnpj): array
    {
        $cnpjClean = preg_replace('/\D/', '', $cnpj);
        
        if (strlen($cnpjClean) !== 14) {
            return [
                'success' => true,
                'valid' => false,
                'message' => 'CNPJ deve ter 14 dígitos'
            ];
        }
        
        if (!validateCnpj($cnpjClean)) {
            return [
                'success' => true,
                'valid' => false,
                'message' => 'CNPJ inválido'
            ];
        }
        
        // Busca ótica
        $stmt = dbQuery(
            "SELECT id_otica, razao_social, endereco, status FROM oticas WHERE cnpj = ? LIMIT 1",
            [$cnpjClean],
            'read'
        );
        
        $otica = $stmt->fetch();
        
        if (!$otica) {
            return [
                'success' => true,
                'valid' => false,
                'found' => false,
                'message' => 'CNPJ não encontrado em nossa base de óticas parceiras'
            ];
        }
        
        if ($otica['status'] !== 'ativa') {
            return [
                'success' => true,
                'valid' => false,
                'found' => true,
                'message' => 'Esta ótica não está ativa no sistema'
            ];
        }
        
        return [
            'success' => true,
            'valid' => true,
            'found' => true,
            'otica' => [
                'id_otica' => $otica['id_otica'],
                'razao_social' => $otica['razao_social'],
                'endereco' => $otica['endereco']
            ],
            'message' => 'CNPJ válido'
        ];
    }
}

// ==============================================================================
// 4. EXECUÇÃO DA API
// ==============================================================================

try {
    // Determina qual API executar baseado na URL
    $requestUri = $_SERVER['REQUEST_URI'] ?? '';
    
    if (strpos($requestUri, '/validate') !== false) {
        // API de validação em tempo real
        $result = ValidationAPI::validateField();
    } else {
        // API de cadastro completo
        $api = new RegistrationAPI();
        $result = $api->processRegistration();
    }
    
    echo json_encode($result, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
    
} catch (Throwable $e) {
    // Fallback para erros críticos
    http_response_code(500);
    
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
    
    error_log('CRITICAL REGISTRATION API ERROR: ' . $e->getMessage());
    echo json_encode($response);
}

exit;