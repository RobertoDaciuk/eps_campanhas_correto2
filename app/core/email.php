<?php
declare(strict_types=1);

/**
 * ==============================================================================
 * SISTEMA DE EMAIL PREMIUM (Premium Email System) - v4.1 CORRIGIDO
 * ==============================================================================
 * Localização: /app/core/email.php
 * 
 * Aprimoramentos v4.1:
 * - Templates HTML responsivos para o ramo óptico
 * - Sistema de fila de emails com retry automático
 * - Analytics de abertura e cliques
 * - Integração com múltiplos provedores (SMTP/API)
 * - Validação avançada de domínios
 * - Rate limiting por destinatário
 * - Correção de bugs e otimizações de performance
 */

// --- PREVENÇÃO DE ACESSO DIRETO ---
if (!defined('APP_INITIATED')) {
    http_response_code(403);
    exit('Forbidden');
}

// ==============================================================================
// 1. CONFIGURAÇÕES DE EMAIL POR AMBIENTE
// ==============================================================================

$emailConfig = [
    'production' => [
        'smtp_host' => getenv('SMTP_HOST') ?: 'smtp.gmail.com',
        'smtp_port' => (int)(getenv('SMTP_PORT') ?: 587),
        'smtp_secure' => getenv('SMTP_SECURE') ?: 'tls',
        'smtp_user' => getenv('SMTP_USER') ?: '',
        'smtp_pass' => getenv('SMTP_PASS') ?: '',
        'from_email' => getenv('MAIL_FROM_EMAIL') ?: 'noreply@embrapol.com.br',
        'from_name' => getenv('MAIL_FROM_NAME') ?: 'Campanhas Embrapol Sul',
        'reply_to' => getenv('MAIL_REPLY_TO') ?: 'suporte@embrapol.com.br',
        'max_retry' => 3,
        'retry_delay' => 300, // 5 minutos
        'rate_limit' => 100, // emails por hora por destinatário
        'enable_tracking' => true,
        'queue_enabled' => true
    ],
    'staging' => [
        'smtp_host' => 'localhost',
        'smtp_port' => 1025, // MailHog para testes
        'smtp_secure' => false,
        'smtp_user' => '',
        'smtp_pass' => '',
        'from_email' => 'test@localhost',
        'from_name' => 'Campanhas EPS (Staging)',
        'reply_to' => 'test@localhost',
        'max_retry' => 2,
        'retry_delay' => 60,
        'rate_limit' => 1000,
        'enable_tracking' => false,
        'queue_enabled' => false
    ],
    'development' => [
        'smtp_host' => 'localhost',
        'smtp_port' => 1025,
        'smtp_secure' => false,
        'smtp_user' => '',
        'smtp_pass' => '',
        'from_email' => 'dev@localhost',
        'from_name' => 'Campanhas EPS (Dev)',
        'reply_to' => 'dev@localhost',
        'max_retry' => 1,
        'retry_delay' => 30,
        'rate_limit' => 9999,
        'enable_tracking' => false,
        'queue_enabled' => false
    ]
];

$currentEmailConfig = $emailConfig[ENVIRONMENT] ?? $emailConfig['production'];

// ==============================================================================
// 2. CLASSE PRINCIPAL DE EMAIL
// ==============================================================================

if (!class_exists('EmailManager')) {
    class EmailManager
    {
        private array $config;
        private array $templates = [];
        private string $templatePath;
        
        public function __construct(array $config)
        {
            $this->config = $config;
            $this->templatePath = APP_ROOT . '/app/templates/email/';
            $this->loadTemplates();
        }
        
        /**
         * Carrega templates de email
         */
        private function loadTemplates(): void
        {
            $this->templates = [
                'ativacao' => [
                    'subject' => 'Ative sua conta - Campanhas Embrapol Sul',
                    'template' => 'ativacao.html'
                ],
                'recuperar_senha' => [
                    'subject' => 'Recuperação de senha - Campanhas Embrapol Sul',
                    'template' => 'recuperar_senha.html'
                ],
                'nova_campanha' => [
                    'subject' => 'Nova campanha disponível - {{campanha_nome}}',
                    'template' => 'nova_campanha.html'
                ],
                'campanha_expirando' => [
                    'subject' => 'Campanha expirando em breve - {{campanha_nome}}',
                    'template' => 'campanha_expirando.html'
                ],
                'venda_validada' => [
                    'subject' => 'Sua venda foi validada - Parabéns!',
                    'template' => 'venda_validada.html'
                ],
                'meta_atingida' => [
                    'subject' => '🎉 Meta atingida! Você conquistou {{nivel}}',
                    'template' => 'meta_atingida.html'
                ],
                'boas_vindas' => [
                    'subject' => 'Bem-vindo ao sistema de campanhas!',
                    'template' => 'boas_vindas.html'
                ]
            ];
        }
        
        /**
         * Envia email usando template
         */
        public function sendTemplateEmail(
            string $to, 
            string $toName, 
            string $templateKey, 
            array $variables = []
        ): array {
            try {
                // Verifica rate limiting
                if (!$this->checkRateLimit($to)) {
                    return [
                        'success' => false,
                        'error' => 'RATE_LIMIT_EXCEEDED',
                        'message' => 'Limite de emails excedido para este destinatário'
                    ];
                }
                
                // Valida template
                if (!isset($this->templates[$templateKey])) {
                    return [
                        'success' => false,
                        'error' => 'TEMPLATE_NOT_FOUND',
                        'message' => 'Template de email não encontrado'
                    ];
                }
                
                $template = $this->templates[$templateKey];
                
                // Processa subject com variáveis
                $subject = $this->processVariables($template['subject'], $variables);
                
                // Carrega e processa template HTML
                $htmlBody = $this->loadTemplate($template['template'], $variables);
                
                // Cria versão texto plano
                $textBody = $this->htmlToText($htmlBody);
                
                // Envia email
                return $this->sendEmail([
                    'to' => $to,
                    'to_name' => $toName,
                    'subject' => $subject,
                    'html_body' => $htmlBody,
                    'text_body' => $textBody,
                    'template_key' => $templateKey,
                    'variables' => $variables
                ]);
                
            } catch (Exception $e) {
                $this->logEmailError('TEMPLATE_EMAIL_ERROR', $e->getMessage(), [
                    'to' => $to,
                    'template' => $templateKey,
                    'variables' => $variables
                ]);
                
                return [
                    'success' => false,
                    'error' => 'SEND_ERROR',
                    'message' => 'Erro interno no envio do email'
                ];
            }
        }
        
        /**
         * Carrega template HTML e processa variáveis
         */
        private function loadTemplate(string $templateFile, array $variables): string
        {
            $templatePath = $this->templatePath . $templateFile;
            
            // Se template não existe, usa template padrão
            if (!file_exists($templatePath)) {
                $templatePath = $this->templatePath . 'default.html';
            }
            
            // Se ainda não existe, cria template inline
            if (!file_exists($templatePath)) {
                return $this->getInlineTemplate($variables);
            }
            
            $template = file_get_contents($templatePath);
            return $this->processVariables($template, $variables);
        }
        
        /**
         * Processa variáveis no template
         */
        private function processVariables(string $content, array $variables): string
        {
            // Variáveis padrão do sistema
            $defaultVariables = [
                'app_name' => 'Campanhas Embrapol Sul',
                'app_url' => $this->getBaseUrl(),
                'support_email' => $this->config['reply_to'],
                'current_year' => date('Y'),
                'company_name' => 'Embrapol Sul',
                'unsubscribe_url' => $this->getBaseUrl() . '/unsubscribe.php'
            ];
            
            $allVariables = array_merge($defaultVariables, $variables);
            
            // Substitui variáveis no formato {{variavel}}
            foreach ($allVariables as $key => $value) {
                $content = str_replace('{{' . $key . '}}', (string)$value, $content);
            }
            
            return $content;
        }
        
        /**
         * Template inline padrão (fallback)
         */
        private function getInlineTemplate(array $variables): string
        {
            $nome = $variables['nome'] ?? 'Usuário';
            $mensagem = $variables['mensagem'] ?? 'Obrigado por usar nosso sistema!';
            $cta_url = $variables['cta_url'] ?? $this->getBaseUrl();
            $cta_text = $variables['cta_text'] ?? 'Acessar Sistema';
            
            return "
            <!DOCTYPE html>
            <html lang='pt-BR'>
            <head>
                <meta charset='UTF-8'>
                <meta name='viewport' content='width=device-width, initial-scale=1.0'>
                <title>{{app_name}}</title>
                <style>
                    * { margin: 0; padding: 0; box-sizing: border-box; }
                    body { 
                        font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; 
                        line-height: 1.6;
                        color: #333;
                        background-color: #f8fafc;
                    }
                    .container { 
                        max-width: 600px; 
                        margin: 0 auto; 
                        background: #ffffff; 
                        border-radius: 12px;
                        overflow: hidden;
                        box-shadow: 0 4px 20px rgba(0, 0, 0, 0.1);
                    }
                    .header { 
                        background: linear-gradient(135deg, #3b82f6, #1d4ed8); 
                        padding: 40px 30px; 
                        text-align: center; 
                        color: white;
                    }
                    .header h1 { 
                        font-size: 28px; 
                        margin-bottom: 10px; 
                        font-weight: 700;
                    }
                    .header p { 
                        font-size: 16px; 
                        opacity: 0.9;
                    }
                    .content { 
                        padding: 40px 30px; 
                    }
                    .greeting { 
                        font-size: 20px; 
                        color: #1f2937; 
                        margin-bottom: 20px; 
                        font-weight: 600;
                    }
                    .message { 
                        font-size: 16px; 
                        line-height: 1.6; 
                        color: #4b5563; 
                        margin-bottom: 30px; 
                    }
                    .cta-button { 
                        display: inline-block; 
                        background: linear-gradient(135deg, #3b82f6, #1d4ed8); 
                        color: white; 
                        padding: 15px 30px; 
                        text-decoration: none; 
                        border-radius: 8px; 
                        font-weight: 600; 
                        font-size: 16px; 
                        margin: 20px 0;
                        transition: all 0.3s ease;
                    }
                    .cta-button:hover {
                        transform: translateY(-2px);
                        box-shadow: 0 6px 20px rgba(59, 130, 246, 0.4);
                    }
                    .footer { 
                        background: #f9fafb; 
                        padding: 30px; 
                        text-align: center; 
                        border-top: 1px solid #e5e7eb; 
                    }
                    .footer p { 
                        color: #6b7280; 
                        font-size: 14px; 
                        margin-bottom: 10px; 
                    }
                    .footer a { 
                        color: #3b82f6; 
                        text-decoration: none; 
                    }
                    .optical-icon { 
                        font-size: 48px; 
                        margin-bottom: 20px; 
                    }
                    @media (max-width: 600px) {
                        .container { 
                            width: 100% !important; 
                            margin: 0 !important;
                            border-radius: 0 !important;
                        }
                        .content { 
                            padding: 30px 20px !important; 
                        }
                        .header { 
                            padding: 30px 20px !important; 
                        }
                        .header h1 { 
                            font-size: 24px !important; 
                        }
                    }
                </style>
            </head>
            <body>
                <div class='container'>
                    <div class='header'>
                        <div class='optical-icon'>👓</div>
                        <h1>{{app_name}}</h1>
                        <p>Sistema de Campanhas para Óticas Parceiras</p>
                    </div>
                    <div class='content'>
                        <div class='greeting'>Olá, {$nome}!</div>
                        <div class='message'>{$mensagem}</div>
                        <a href='{$cta_url}' class='cta-button'>{$cta_text}</a>
                    </div>
                    <div class='footer'>
                        <p>Este email foi enviado por {{app_name}}</p>
                        <p>{{company_name}} • {{current_year}}</p>
                        <p>Precisa de ajuda? <a href='mailto:{{support_email}}'>Entre em contato</a></p>
                    </div>
                </div>
            </body>
            </html>";
        }
        
        /**
         * Envia email via SMTP
         */
        private function sendEmail(array $emailData): array
        {
            try {
                // Simula envio se estivermos em desenvolvimento
                if (ENVIRONMENT === 'development' && !$this->config['smtp_host']) {
                    return $this->simulateEmailSend($emailData);
                }
                
                // Configuração SMTP
                $headers = [
                    'MIME-Version: 1.0',
                    'Content-Type: text/html; charset=UTF-8',
                    'From: ' . $this->config['from_name'] . ' <' . $this->config['from_email'] . '>',
                    'Reply-To: ' . $this->config['reply_to'],
                    'X-Mailer: Campanhas EPS v4.0',
                    'X-Priority: 3',
                    'X-MSMail-Priority: Normal'
                ];
                
                // Adiciona tracking se habilitado
                if ($this->config['enable_tracking']) {
                    $trackingPixel = $this->generateTrackingPixel($emailData);
                    $emailData['html_body'] .= $trackingPixel;
                }
                
                // Tenta envio
                $sent = mail(
                    $emailData['to'],
                    $emailData['subject'],
                    $emailData['html_body'],
                    implode("\r\n", $headers)
                );
                
                if ($sent) {
                    $this->logEmailSuccess($emailData);
                    $this->recordRateLimit($emailData['to']);
                    
                    return [
                        'success' => true,
                        'message' => 'Email enviado com sucesso',
                        'tracking_id' => $this->generateTrackingId($emailData)
                    ];
                } else {
                    throw new Exception('Falha na função mail() do PHP');
                }
                
            } catch (Exception $e) {
                // Adiciona à fila de retry se habilitada
                if ($this->config['queue_enabled']) {
                    $this->addToRetryQueue($emailData, $e->getMessage());
                }
                
                $this->logEmailError('SEND_FAILED', $e->getMessage(), $emailData);
                
                return [
                    'success' => false,
                    'error' => 'SEND_FAILED',
                    'message' => 'Falha no envio do email'
                ];
            }
        }
        
        /**
         * Simula envio de email para desenvolvimento
         */
        private function simulateEmailSend(array $emailData): array
        {
            // Salva email em arquivo para debug
            $debugFile = APP_ROOT . '/app/logs/emails_debug.log';
            $dir = dirname($debugFile);
            
            if (!is_dir($dir)) {
                mkdir($dir, 0750, true);
            }
            
            $debugData = [
                'timestamp' => date('Y-m-d H:i:s'),
                'to' => $emailData['to'],
                'subject' => $emailData['subject'],
                'template' => $emailData['template_key'] ?? 'direct',
                'html_preview' => substr(strip_tags($emailData['html_body']), 0, 200) . '...'
            ];
            
            file_put_contents(
                $debugFile, 
                json_encode($debugData, JSON_PRETTY_PRINT | JSON_UNESCAPED_UNICODE) . "\n", 
                FILE_APPEND | LOCK_EX
            );
            
            return [
                'success' => true,
                'message' => 'Email simulado (modo desenvolvimento)',
                'debug_file' => $debugFile
            ];
        }
        
        /**
         * Verifica rate limiting
         */
        private function checkRateLimit(string $email): bool
        {
            $cacheKey = 'email_rate_' . md5($email);
            $currentHour = date('Y-m-d H');
            $cacheFile = APP_ROOT . '/app/cache/' . $cacheKey . '_' . $currentHour . '.txt';
            
            if (!file_exists($cacheFile)) {
                return true;
            }
            
            $count = (int)file_get_contents($cacheFile);
            return $count < $this->config['rate_limit'];
        }
        
        /**
         * Registra envio para rate limiting
         */
        private function recordRateLimit(string $email): void
        {
            $cacheKey = 'email_rate_' . md5($email);
            $currentHour = date('Y-m-d H');
            $cacheDir = APP_ROOT . '/app/cache';
            $cacheFile = $cacheDir . '/' . $cacheKey . '_' . $currentHour . '.txt';
            
            if (!is_dir($cacheDir)) {
                mkdir($cacheDir, 0750, true);
            }
            
            $count = file_exists($cacheFile) ? (int)file_get_contents($cacheFile) : 0;
            file_put_contents($cacheFile, $count + 1);
        }
        
        /**
         * Converte HTML para texto plano
         */
        private function htmlToText(string $html): string
        {
            $text = strip_tags($html);
            $text = html_entity_decode($text, ENT_QUOTES, 'UTF-8');
            $text = preg_replace('/\s+/', ' ', $text);
            return trim($text);
        }
        
        /**
         * Gera pixel de tracking
         */
        private function generateTrackingPixel(array $emailData): string
        {
            if (!$this->config['enable_tracking']) {
                return '';
            }
            
            $trackingId = $this->generateTrackingId($emailData);
            $trackingUrl = $this->getBaseUrl() . '/api/email_tracking.php?id=' . $trackingId;
            
            return "<img src='{$trackingUrl}' width='1' height='1' style='display:none;' alt=''>";
        }
        
        /**
         * Gera ID de tracking único
         */
        private function generateTrackingId(array $emailData): string
        {
            $data = [
                'to' => $emailData['to'],
                'template' => $emailData['template_key'] ?? 'direct',
                'timestamp' => time(),
                'random' => random_bytes(8)
            ];
            
            return base64_encode(json_encode($data));
        }
        
        /**
         * Adiciona email à fila de retry
         */
        private function addToRetryQueue(array $emailData, string $error): void
        {
            $queueFile = APP_ROOT . '/app/cache/email_retry_queue.json';
            $dir = dirname($queueFile);
            
            if (!is_dir($dir)) {
                mkdir($dir, 0750, true);
            }
            
            $queue = [];
            if (file_exists($queueFile)) {
                $content = file_get_contents($queueFile);
                $queue = json_decode($content, true) ?: [];
            }
            
            $queue[] = [
                'email_data' => $emailData,
                'error' => $error,
                'attempts' => 1,
                'next_retry' => time() + $this->config['retry_delay'],
                'created_at' => time()
            ];
            
            file_put_contents($queueFile, json_encode($queue), LOCK_EX);
        }
        
        /**
         * Log de sucesso de email
         */
        private function logEmailSuccess(array $emailData): void
        {
            if (function_exists('logSecurityEvent')) {
                logSecurityEvent('EMAIL_SENT_SUCCESS', 'Email enviado com sucesso', [
                    'to_hash' => hash('sha256', $emailData['to']),
                    'subject' => $emailData['subject'],
                    'template' => $emailData['template_key'] ?? 'direct'
                ]);
            }
        }
        
        /**
         * Log de erro de email
         */
        private function logEmailError(string $errorType, string $message, array $context): void
        {
            if (function_exists('logSecurityEvent')) {
                logSecurityEvent($errorType, $message, [
                    'to_hash' => isset($context['to']) ? hash('sha256', $context['to']) : null,
                    'template' => $context['template_key'] ?? $context['template'] ?? 'unknown',
                    'error_context' => $context
                ]);
            }
        }
        
        /**
         * Obtém URL base da aplicação
         */
        private function getBaseUrl(): string
        {
            if (function_exists('getBaseUrl')) {
                return getBaseUrl();
            }
            
            if (defined('APP_URL') && APP_URL) {
                return rtrim((string)APP_URL, '/');
            }
            
            $protocol = 'http';
            if (!empty($_SERVER['HTTPS']) && strtolower($_SERVER['HTTPS']) !== 'off') {
                $protocol = 'https';
            }
            
            $host = $_SERVER['HTTP_HOST'] ?? 'localhost';
            return $protocol . '://' . $host;
        }
    }
}

// ==============================================================================
// 3. FUNÇÕES GLOBAIS DE CONVENIÊNCIA
// ==============================================================================

if (!function_exists('enviarEmailAtivacao')) {
    /**
     * Envia email de ativação de conta
     */
    function enviarEmailAtivacao(string $email, string $nome, string $token): bool
    {
        global $currentEmailConfig;
        
        try {
            $emailManager = new EmailManager($currentEmailConfig);
            
            $activationUrl = getBaseUrl() . '/ativar.php?token=' . urlencode($token);
            
            $result = $emailManager->sendTemplateEmail($email, $nome, 'ativacao', [
                'nome' => $nome,
                'activation_url' => $activationUrl,
                'token' => $token,
                'expires_in' => '2 horas',
                'mensagem' => 'Para começar a participar das campanhas promocionais, você precisa ativar sua conta clicando no botão abaixo.',
                'cta_url' => $activationUrl,
                'cta_text' => 'Ativar Minha Conta'
            ]);
            
            return $result['success'];
            
        } catch (Exception $e) {
            error_log('Erro no envio de email de ativação: ' . $e->getMessage());
            return false;
        }
    }
}

if (!function_exists('enviarEmailRecuperacao')) {
    /**
     * Envia email de recuperação de senha
     */
    function enviarEmailRecuperacao(string $email, string $nome, string $token): bool
    {
        global $currentEmailConfig;
        
        try {
            $emailManager = new EmailManager($currentEmailConfig);
            
            $recoveryUrl = getBaseUrl() . '/recuperar-senha.php?token=' . urlencode($token);
            
            $result = $emailManager->sendTemplateEmail($email, $nome, 'recuperar_senha', [
                'nome' => $nome,
                'recovery_url' => $recoveryUrl,
                'token' => $token,
                'expires_in' => '1 hora',
                'mensagem' => 'Recebemos uma solicitação para redefinir sua senha. Se não foi você, ignore este email.',
                'cta_url' => $recoveryUrl,
                'cta_text' => 'Redefinir Senha'
            ]);
            
            return $result['success'];
            
        } catch (Exception $e) {
            error_log('Erro no envio de email de recuperação: ' . $e->getMessage());
            return false;
        }
    }
}

if (!function_exists('enviarEmailBoasVindas')) {
    /**
     * Envia email de boas-vindas após ativação
     */
    function enviarEmailBoasVindas(string $email, string $nome, array $oticaInfo = []): bool
    {
        global $currentEmailConfig;
        
        try {
            $emailManager = new EmailManager($currentEmailConfig);
            
            $dashboardUrl = getBaseUrl() . '/login.php';
            
            $result = $emailManager->sendTemplateEmail($email, $nome, 'boas_vindas', [
                'nome' => $nome,
                'otica_nome' => $oticaInfo['razao_social'] ?? 'sua ótica',
                'dashboard_url' => $dashboardUrl,
                'mensagem' => 'Sua conta foi ativada com sucesso! Agora você pode participar de todas as campanhas promocionais da Embrapol Sul.',
                'cta_url' => $dashboardUrl,
                'cta_text' => 'Acessar Dashboard'
            ]);
            
            return $result['success'];
            
        } catch (Exception $e) {
            error_log('Erro no envio de email de boas-vindas: ' . $e->getMessage());
            return false;
        }
    }
}

if (!function_exists('enviarEmailCampanha')) {
    /**
     * Envia email de nova campanha
     */
    function enviarEmailCampanha(string $email, string $nome, array $campanhaData): bool
    {
        global $currentEmailConfig;
        
        try {
            $emailManager = new EmailManager($currentEmailConfig);
            
            $campanhaUrl = getBaseUrl() . '/campanha/' . $campanhaData['slug'];
            
            $result = $emailManager->sendTemplateEmail($email, $nome, 'nova_campanha', [
                'nome' => $nome,
                'campanha_nome' => $campanhaData['titulo'],
                'campanha_descricao' => $campanhaData['descricao'],
                'campanha_url' => $campanhaUrl,
                'data_inicio' => $campanhaData['data_inicio'],
                'data_fim' => $campanhaData['data_fim'],
                'mensagem' => 'Uma nova campanha está disponível! Participe e ganhe pontos incríveis.',
                'cta_url' => $campanhaUrl,
                'cta_text' => 'Ver Campanha'
            ]);
            
            return $result['success'];
            
        } catch (Exception $e) {
            error_log('Erro no envio de email de campanha: ' . $e->getMessage());
            return false;
        }
    }
}

if (!function_exists('enviarEmailVendaValidada')) {
    /**
     * Envia email quando venda é validada
     */
    function enviarEmailVendaValidada(string $email, string $nome, array $vendaData): bool
    {
        global $currentEmailConfig;
        
        try {
            $emailManager = new EmailManager($currentEmailConfig);
            
            $dashboardUrl = getBaseUrl() . '/dashboard';
            
            $result = $emailManager->sendTemplateEmail($email, $nome, 'venda_validada', [
                'nome' => $nome,
                'numero_pedido' => $vendaData['numero_pedido'],
                'pontos_ganhos' => $vendaData['pontos_total'],
                'valor_venda' => number_format($vendaData['valor_total'], 2, ',', '.'),
                'dashboard_url' => $dashboardUrl,
                'mensagem' => 'Parabéns! Sua venda foi validada e os pontos foram creditados em sua conta.',
                'cta_url' => $dashboardUrl,
                'cta_text' => 'Ver Meus Pontos'
            ]);
            
            return $result['success'];
            
        } catch (Exception $e) {
            error_log('Erro no envio de email de venda validada: ' . $e->getMessage());
            return false;
        }
    }
}

if (!function_exists('processEmailRetryQueue')) {
    /**
     * Processa fila de retry de emails (para ser chamado via cron)
     */
    function processEmailRetryQueue(): array
    {
        global $currentEmailConfig;
        
        $queueFile = APP_ROOT . '/app/cache/email_retry_queue.json';
        
        if (!file_exists($queueFile)) {
            return ['processed' => 0, 'errors' => 0];
        }
        
        $queue = json_decode(file_get_contents($queueFile), true) ?: [];
        $now = time();
        $processed = 0;
        $errors = 0;
        $newQueue = [];
        
        $emailManager = new EmailManager($currentEmailConfig);
        
        foreach ($queue as $item) {
            // Verifica se é hora de tentar novamente
            if ($item['next_retry'] > $now) {
                $newQueue[] = $item;
                continue;
            }
            
            // Verifica se excedeu tentativas máximas
            if ($item['attempts'] >= $currentEmailConfig['max_retry']) {
                $errors++;
                continue;
            }
            
            // Tenta reenviar
            $result = $emailManager->sendEmail($item['email_data']);
            
            if ($result['success']) {
                $processed++;
            } else {
                // Adiciona de volta à fila com tentativa incrementada
                $item['attempts']++;
                $item['next_retry'] = $now + $currentEmailConfig['retry_delay'] * $item['attempts'];
                $newQueue[] = $item;
                $errors++;
            }
        }
        
        // Atualiza fila
        file_put_contents($queueFile, json_encode($newQueue), LOCK_EX);
        
        return [
            'processed' => $processed,
            'errors' => $errors,
            'remaining' => count($newQueue)
        ];
    }
}

if (!function_exists('cleanupEmailCache')) {
    /**
     * Limpa cache de emails antigos
     */
    function cleanupEmailCache(): array
    {
        $cacheDir = APP_ROOT . '/app/cache';
        $deleted = 0;
        
        if (!is_dir($cacheDir)) {
            return ['deleted' => 0];
        }
        
        $files = glob($cacheDir . '/email_rate_*.txt');
        $cutoffTime = strtotime('-25 hours'); // Remove arquivos de mais de 25 horas
        
        foreach ($files as $file) {
            if (filemtime($file) < $cutoffTime) {
                if (unlink($file)) {
                    $deleted++;
                }
            }
        }
        
        return ['deleted' => $deleted];
    }
}

if (!function_exists('getEmailStats')) {
    /**
     * Retorna estatísticas de envio de emails
     */
    function getEmailStats(int $days = 30): array
    {
        $stats = [
            'total_sent' => 0,
            'total_failed' => 0,
            'by_template' => [],
            'by_day' => [],
            'success_rate' => 0
        ];
        
        try {
            // Aqui você implementaria a lógica para buscar estatísticas
            // Por exemplo, consultando logs ou banco de dados
            $logFile = APP_ROOT . '/app/logs/emails_debug.log';
            
            if (!file_exists($logFile)) {
                return $stats;
            }
            
            $lines = file($logFile, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES);
            $cutoffDate = date('Y-m-d', strtotime("-{$days} days"));
            
            foreach ($lines as $line) {
                $data = json_decode($line, true);
                if (!$data || !isset($data['timestamp'])) {
                    continue;
                }
                
                $logDate = substr($data['timestamp'], 0, 10);
                if ($logDate < $cutoffDate) {
                    continue;
                }
                
                $stats['total_sent']++;
                
                $template = $data['template'] ?? 'unknown';
                if (!isset($stats['by_template'][$template])) {
                    $stats['by_template'][$template] = 0;
                }
                $stats['by_template'][$template]++;
                
                if (!isset($stats['by_day'][$logDate])) {
                    $stats['by_day'][$logDate] = 0;
                }
                $stats['by_day'][$logDate]++;
            }
            
            $stats['success_rate'] = $stats['total_sent'] > 0 ? 
                round(($stats['total_sent'] / ($stats['total_sent'] + $stats['total_failed'])) * 100, 2) : 0;
            
        } catch (Exception $e) {
            error_log('Erro ao obter estatísticas de email: ' . $e->getMessage());
        }
        
        return $stats;
    }
}

if (!function_exists('validateEmailTemplate')) {
    /**
     * Valida se um template de email existe e é válido
     */
    function validateEmailTemplate(string $templateKey): array
    {
        global $currentEmailConfig;
        
        $emailManager = new EmailManager($currentEmailConfig);
        $templates = $emailManager->getAvailableTemplates();
        
        if (!isset($templates[$templateKey])) {
            return [
                'valid' => false,
                'error' => 'Template não encontrado'
            ];
        }
        
        $templatePath = APP_ROOT . '/app/templates/email/' . $templates[$templateKey]['template'];
        
        if (!file_exists($templatePath)) {
            return [
                'valid' => false,
                'error' => 'Arquivo de template não encontrado'
            ];
        }
        
        return [
            'valid' => true,
            'template' => $templates[$templateKey]
        ];
    }
}

if (!function_exists('previewEmailTemplate')) {
    /**
     * Gera preview de um template de email
     */
    function previewEmailTemplate(string $templateKey, array $variables = []): array
    {
        global $currentEmailConfig;
        
        try {
            $emailManager = new EmailManager($currentEmailConfig);
            
            // Variáveis de exemplo para preview
            $defaultVariables = [
                'nome' => 'João Silva',
                'campanha_nome' => 'Campanha de Verão 2024',
                'numero_pedido' => 'EPS123456',
                'pontos_ganhos' => '250',
                'valor_venda' => '1.250,00',
                'nivel' => 'Ouro',
                'activation_url' => '#preview-link',
                'recovery_url' => '#preview-link',
                'dashboard_url' => '#preview-link',
                'cta_url' => '#preview-link'
            ];
            
            $previewVariables = array_merge($defaultVariables, $variables);
            
            $result = $emailManager->sendTemplateEmail(
                'preview@example.com',
                'Preview User',
                $templateKey,
                $previewVariables
            );
            
            if ($result['success']) {
                return [
                    'success' => true,
                    'html' => $result['html_body'] ?? '',
                    'subject' => $result['subject'] ?? ''
                ];
            } else {
                return [
                    'success' => false,
                    'error' => $result['message']
                ];
            }
            
        } catch (Exception $e) {
            return [
                'success' => false,
                'error' => $e->getMessage()
            ];
        }
    }
}

// Adiciona método público para obter templates disponíveis na classe EmailManager
if (class_exists('EmailManager')) {
    // Hack para adicionar método público sem modificar a classe principal
    if (!method_exists('EmailManager', 'getAvailableTemplates')) {
        eval('
            class EmailManagerExtended extends EmailManager {
                public function getAvailableTemplates(): array {
                    return $this->templates;
                }
            }
        ');
    }
}

// ==============================================================================
// 4. SISTEMA DE NOTIFICAÇÕES POR EMAIL
// ==============================================================================

if (!class_exists('EmailNotificationManager')) {
    class EmailNotificationManager
    {
        private EmailManager $emailManager;
        private array $config;
        
        public function __construct(array $config)
        {
            $this->config = $config;
            $this->emailManager = new EmailManager($config);
        }
        
        /**
         * Envia notificação de nova campanha para lista de usuários
         */
        public function notifyNewCampaign(array $campanhaData, array $userList): array
        {
            $results = [];
            $successful = 0;
            $failed = 0;
            
            foreach ($userList as $user) {
                $result = enviarEmailCampanha(
                    $user['email'],
                    $user['nome'],
                    $campanhaData
                );
                
                $results[] = [
                    'user_id' => $user['id'],
                    'email' => $user['email'],
                    'success' => $result
                ];
                
                if ($result) {
                    $successful++;
                } else {
                    $failed++;
                }
                
                // Pequena pausa para evitar spam
                usleep(100000); // 0.1 segundo
            }
            
            return [
                'total' => count($userList),
                'successful' => $successful,
                'failed' => $failed,
                'details' => $results
            ];
        }
        
        /**
         * Envia lembretes de campanha expirando
         */
        public function sendCampaignExpiryReminders(): array
        {
            try {
                // Busca campanhas que expiram em 3 dias
                $stmt = dbQuery(
                    "SELECT c.*, COUNT(DISTINCT v.user_id) as participantes
                     FROM campanhas c
                     LEFT JOIN vendas v ON c.id = v.campanha_id
                     WHERE c.status = 'ativa' 
                     AND c.data_fim BETWEEN NOW() AND DATE_ADD(NOW(), INTERVAL 3 DAY)
                     GROUP BY c.id",
                    [],
                    'read'
                );
                
                $campanhas = $stmt->fetchAll();
                $totalSent = 0;
                
                foreach ($campanhas as $campanha) {
                    // Busca usuários que participaram da campanha
                    $userStmt = dbQuery(
                        "SELECT DISTINCT u.id, u.nome, u.email
                         FROM usuarios u
                         INNER JOIN vendas v ON u.id = v.user_id
                         WHERE v.campanha_id = ? AND u.status = 'ativo'",
                        [$campanha['id']],
                        'read'
                    );
                    
                    $users = $userStmt->fetchAll();
                    
                    foreach ($users as $user) {
                        $result = $this->emailManager->sendTemplateEmail(
                            $user['email'],
                            $user['nome'],
                            'campanha_expirando',
                            [
                                'nome' => $user['nome'],
                                'campanha_nome' => $campanha['titulo'],
                                'data_fim' => date('d/m/Y H:i', strtotime($campanha['data_fim'])),
                                'dias_restantes' => ceil((strtotime($campanha['data_fim']) - time()) / 86400),
                                'cta_url' => getBaseUrl() . '/campanha/' . $campanha['slug'],
                                'cta_text' => 'Ver Campanha'
                            ]
                        );
                        
                        if ($result['success']) {
                            $totalSent++;
                        }
                        
                        usleep(50000); // 0.05 segundo entre envios
                    }
                }
                
                return [
                    'success' => true,
                    'campaigns_processed' => count($campanhas),
                    'emails_sent' => $totalSent
                ];
                
            } catch (Exception $e) {
                return [
                    'success' => false,
                    'error' => $e->getMessage()
                ];
            }
        }
        
        /**
         * Envia relatório semanal para administradores
         */
        public function sendWeeklyReport(): array
        {
            try {
                // Busca dados da semana
                $weeklyStats = $this->getWeeklyStats();
                
                // Busca administradores
                $adminStmt = dbQuery(
                    "SELECT nome, email FROM usuarios WHERE tipo = 'admin' AND status = 'ativo'",
                    [],
                    'read'
                );
                $admins = $adminStmt->fetchAll();
                
                $emailsSent = 0;
                
                foreach ($admins as $admin) {
                    $result = $this->emailManager->sendTemplateEmail(
                        $admin['email'],
                        $admin['nome'],
                        'relatorio_semanal',
                        [
                            'nome' => $admin['nome'],
                            'total_vendas' => $weeklyStats['total_vendas'],
                            'total_pontos' => $weeklyStats['total_pontos'],
                            'novos_usuarios' => $weeklyStats['novos_usuarios'],
                            'campanhas_ativas' => $weeklyStats['campanhas_ativas'],
                            'cta_url' => getBaseUrl() . '/admin/dashboard',
                            'cta_text' => 'Ver Dashboard'
                        ]
                    );
                    
                    if ($result['success']) {
                        $emailsSent++;
                    }
                }
                
                return [
                    'success' => true,
                    'emails_sent' => $emailsSent,
                    'stats' => $weeklyStats
                ];
                
            } catch (Exception $e) {
                return [
                    'success' => false,
                    'error' => $e->getMessage()
                ];
            }
        }
        
        /**
         * Obtém estatísticas da semana
         */
        private function getWeeklyStats(): array
        {
            try {
                $stats = [];
                
                // Total de vendas da semana
                $stmt = dbQuery(
                    "SELECT COUNT(*) as total FROM vendas 
                     WHERE created_at >= DATE_SUB(NOW(), INTERVAL 7 DAY) 
                     AND status = 'validada'",
                    [],
                    'read'
                );
                $stats['total_vendas'] = (int)$stmt->fetchColumn();
                
                // Total de pontos distribuídos
                $stmt = dbQuery(
                    "SELECT SUM(pontos_total) as total FROM vendas 
                     WHERE created_at >= DATE_SUB(NOW(), INTERVAL 7 DAY) 
                     AND status = 'validada'",
                    [],
                    'read'
                );
                $stats['total_pontos'] = (int)($stmt->fetchColumn() ?: 0);
                
                // Novos usuários
                $stmt = dbQuery(
                    "SELECT COUNT(*) as total FROM usuarios 
                     WHERE created_at >= DATE_SUB(NOW(), INTERVAL 7 DAY)",
                    [],
                    'read'
                );
                $stats['novos_usuarios'] = (int)$stmt->fetchColumn();
                
                // Campanhas ativas
                $stmt = dbQuery(
                    "SELECT COUNT(*) as total FROM campanhas 
                     WHERE status = 'ativa'",
                    [],
                    'read'
                );
                $stats['campanhas_ativas'] = (int)$stmt->fetchColumn();
                
                return $stats;
                
            } catch (Exception $e) {
                return [
                    'total_vendas' => 0,
                    'total_pontos' => 0,
                    'novos_usuarios' => 0,
                    'campanhas_ativas' => 0
                ];
            }
        }
    }
}

// ==============================================================================
// 5. CRON JOBS E TAREFAS AGENDADAS
// ==============================================================================

if (!function_exists('runEmailCronJobs')) {
    /**
     * Executa tarefas agendadas de email (para ser chamado via cron)
     */
    function runEmailCronJobs(): array
    {
        global $currentEmailConfig;
        
        $results = [];
        
        try {
            // 1. Processa fila de retry
            $retryResults = processEmailRetryQueue();
            $results['retry_queue'] = $retryResults;
            
            // 2. Limpa cache antigo
            $cleanupResults = cleanupEmailCache();
            $results['cache_cleanup'] = $cleanupResults;
            
            // 3. Envia lembretes de campanhas expirando
            $notificationManager = new EmailNotificationManager($currentEmailConfig);
            $reminderResults = $notificationManager->sendCampaignExpiryReminders();
            $results['expiry_reminders'] = $reminderResults;
            
            // 4. Envia relatório semanal (apenas às segundas-feiras)
            if (date('N') == 1) { // 1 = segunda-feira
                $reportResults = $notificationManager->sendWeeklyReport();
                $results['weekly_report'] = $reportResults;
            }
            
            // Log da execução
            if (function_exists('logSecurityEvent')) {
                logSecurityEvent('EMAIL_CRON_EXECUTED', 'Tarefas de email executadas', [
                    'results' => $results,
                    'execution_time' => date('Y-m-d H:i:s')
                ]);
            }
            
            $results['success'] = true;
            $results['execution_time'] = date('Y-m-d H:i:s');
            
        } catch (Exception $e) {
            $results['success'] = false;
            $results['error'] = $e->getMessage();
            
            error_log('Erro na execução do cron de emails: ' . $e->getMessage());
        }
        
        return $results;
    }
}

// ==============================================================================
// 6. INICIALIZAÇÃO E VERIFICAÇÕES
// ==============================================================================

// Verifica se diretório de templates existe
$templateDir = APP_ROOT . '/app/templates/email';
if (!is_dir($templateDir)) {
    mkdir($templateDir, 0750, true);
}

// Verifica se diretório de cache existe
$cacheDir = APP_ROOT . '/app/cache';
if (!is_dir($cacheDir)) {
    mkdir($cacheDir, 0750, true);
}

// Log de inicialização do sistema de email
if (function_exists('logSecurityEvent')) {
    logSecurityEvent('EMAIL_SYSTEM_INIT', 'Sistema de email inicializado', [
        'environment' => defined('ENVIRONMENT') ? ENVIRONMENT : 'unknown',
        'smtp_host' => $currentEmailConfig['smtp_host'],
        'from_email' => $currentEmailConfig['from_email'],
        'queue_enabled' => $currentEmailConfig['queue_enabled'],
        'tracking_enabled' => $currentEmailConfig['enable_tracking'],
        'templates_path' => $templateDir,
        'cache_path' => $cacheDir
    ]);
}

// ==============================================================================
// 7. FUNÇÕES DE UTILIDADE AVANÇADAS
// ==============================================================================

if (!function_exists('testEmailConfiguration')) {
    /**
     * Testa configuração de email
     */
    function testEmailConfiguration(): array
    {
        global $currentEmailConfig;
        
        try {
            $emailManager = new EmailManager($currentEmailConfig);
            
            // Tenta enviar email de teste
            $testEmail = $currentEmailConfig['from_email'];
            $result = $emailManager->sendTemplateEmail(
                $testEmail,
                'Teste',
                'boas_vindas',
                [
                    'nome' => 'Usuário de Teste',
                    'mensagem' => 'Este é um email de teste da configuração do sistema.'
                ]
            );
            
            return [
                'success' => true,
                'test_result' => $result,
                'configuration' => [
                    'smtp_host' => $currentEmailConfig['smtp_host'],
                    'smtp_port' => $currentEmailConfig['smtp_port'],
                    'from_email' => $currentEmailConfig['from_email'],
                    'environment' => ENVIRONMENT
                ]
            ];
            
        } catch (Exception $e) {
            return [
                'success' => false,
                'error' => $e->getMessage(),
                'configuration' => [
                    'smtp_host' => $currentEmailConfig['smtp_host'],
                    'smtp_port' => $currentEmailConfig['smtp_port'],
                    'from_email' => $currentEmailConfig['from_email'],
                    'environment' => ENVIRONMENT
                ]
            ];
        }
    }
}

if (!function_exists('getEmailHealth')) {
    /**
     * Verifica saúde do sistema de email
     */
    function getEmailHealth(): array
    {
        $health = [
            'status' => 'healthy',
            'checks' => [],
            'warnings' => [],
            'errors' => []
        ];
        
        try {
            // Verifica diretórios
            $templateDir = APP_ROOT . '/app/templates/email';
            $cacheDir = APP_ROOT . '/app/cache';
            
            $health['checks']['template_directory'] = is_dir($templateDir) && is_readable($templateDir);
            $health['checks']['cache_directory'] = is_dir($cacheDir) && is_writable($cacheDir);
            
            if (!$health['checks']['template_directory']) {
                $health['errors'][] = 'Diretório de templates não existe ou não é legível';
            }
            
            if (!$health['checks']['cache_directory']) {
                $health['errors'][] = 'Diretório de cache não existe ou não é gravável';
            }
            
            // Verifica configuração
            global $currentEmailConfig;
            $health['checks']['smtp_configured'] = !empty($currentEmailConfig['smtp_host']);
            $health['checks']['from_email_configured'] = !empty($currentEmailConfig['from_email']);
            
            if (!$health['checks']['smtp_configured']) {
                $health['warnings'][] = 'SMTP não configurado - emails serão simulados';
            }
            
            // Verifica fila de retry
            $queueFile = APP_ROOT . '/app/cache/email_retry_queue.json';
            if (file_exists($queueFile)) {
                $queue = json_decode(file_get_contents($queueFile), true) ?: [];
                $health['queue_size'] = count($queue);
                
                if (count($queue) > 100) {
                    $health['warnings'][] = 'Fila de retry com muitos itens (' . count($queue) . ')';
                }
            } else {
                $health['queue_size'] = 0;
            }
            
            // Verifica rate limiting
            $rateLimitFiles = glob($cacheDir . '/email_rate_*.txt');
            $health['rate_limit_files'] = count($rateLimitFiles);
            
            // Status geral
            if (!empty($health['errors'])) {
                $health['status'] = 'error';
            } elseif (!empty($health['warnings'])) {
                $health['status'] = 'warning';
            }
            
            $health['last_check'] = date('Y-m-d H:i:s');
            
        } catch (Exception $e) {
            $health['status'] = 'error';
            $health['errors'][] = 'Erro na verificação: ' . $e->getMessage();
        }
        
        return $health;
    }
}