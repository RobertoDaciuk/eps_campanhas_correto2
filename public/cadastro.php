<?php
declare(strict_types=1);
/**
 * ==============================================================================
 * INTERFACE DE CADASTRO DE VENDEDOR - v3.0 COMPLETA
 * ==============================================================================
 *
 * Localização: /public/cadastro.php
 *
 * Propósito:
 * Renderiza a interface para que novos vendedores possam se cadastrar no sistema.
 * Esta versão inclui a estrutura HTML necessária para o feedback visual
 * interativo de força da senha e os botões de login/esqueci senha.
 */

// Define a constante de inicialização para segurança.
define('APP_INITIATED', true);
// Define o caminho raiz absoluto da aplicação.
define('APP_ROOT', dirname(__DIR__));

// Cabeçalhos de segurança
header('X-Content-Type-Options: nosniff');
header('X-Frame-Options: DENY');
header('Referrer-Policy: strict-origin-when-cross-origin');
header('X-XSS-Protection: 1; mode=block');

// Cache: não armazenar página de cadastro
header('Cache-Control: no-store, no-cache, must-revalidate, max-age=0');
header('Pragma: no-cache');
header('Expires: 0');

// CSP otimizada para cadastro
$csp = implode('; ', [
    "default-src 'self'",
    "base-uri 'self'",
    "frame-ancestors 'none'",
    "form-action 'self'",
    "img-src 'self' data:",
    "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com https://cdnjs.cloudflare.com",
    "font-src 'self' https://fonts.gstatic.com https://cdnjs.cloudflare.com",
    "script-src 'self' 'unsafe-inline'",
    "connect-src 'self'",
]);
header('Content-Security-Policy: ' . $csp);

// Permissions-Policy
header('Permissions-Policy: geolocation=(), microphone=(), camera=()');

// Carrega o nexo de configuração.
require_once APP_ROOT . '/app/config/config.php';

// --- LÓGICA DE REDIRECIONAMENTO ---
if (isset($_SESSION['user_id'])) {
    $redirectUrl = getRedirectUrlForUser($_SESSION['user_tipo']);
    header("Location: " . $redirectUrl);
    exit;
}

// Gera CSRF token se não existir
if (empty($_SESSION['csrf_token'])) {
    $_SESSION['csrf_token'] = rtrim(strtr(base64_encode(random_bytes(32)), '+/', '-_'), '=');
}

$csrf = htmlspecialchars((string)$_SESSION['csrf_token'], ENT_QUOTES, 'UTF-8');

?>
<!DOCTYPE html>
<html lang="pt-BR">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Cadastro de Vendedor - Campanhas Embrapol Sul</title>
    <meta name="description" content="Cadastre-se como vendedor para participar das campanhas promocionais da Embrapol Sul.">
    <meta name="robots" content="noindex, nofollow">

    <!-- Preconnect/Preload -->
    <link rel="preconnect" href="https://fonts.googleapis.com" crossorigin>
    <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
    <link rel="preload" href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&display=swap" as="style">

    <!-- Fonts & Icons -->
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&display=swap" rel="stylesheet">
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.5.1/css/all.min.css" crossorigin="anonymous" referrerpolicy="no-referrer">

    <!-- App CSS -->
    <link rel="stylesheet" href="/css/theme.css">
    <link rel="stylesheet" href="/css/components.css">
    <link rel="stylesheet" href="/css/animations.css">
    <link rel="stylesheet" href="/css/login.css">
    <link rel="stylesheet" href="/css/cadastro.css">

    <!-- Favicon -->
    <link rel="icon" type="image/x-icon" href="/favicon.ico">
</head>
<body>

    <div class="login-page-container">
        <div class="register-card glass-effect">

            <div class="login-logo">
                <i class="fas fa-user-plus logo-icon glow"></i>
                <h2>Cadastro de Vendedor</h2>
                <p class="subtitle">Preencha os dados para iniciar sua participação.</p>
            </div>

            <!-- Message Container -->
            <div id="message-container" class="message-container" role="alert" aria-live="polite"></div>

            <form id="register-form" method="POST" action="/api/cadastro_api.php" novalidate>
                <!-- CSRF Token -->
                <input type="hidden" name="csrf_token" value="<?php echo $csrf; ?>">

                <fieldset>
                    <legend>Dados Pessoais</legend>
                    <div class="input-group">
                        <label for="nome">Nome Completo</label>
                        <div class="input-wrapper">
                            <input 
                                type="text" 
                                id="nome" 
                                name="nome" 
                                placeholder="Ex: João da Silva" 
                                required
                                autocomplete="name"
                                class="input"
                                aria-describedby="nome-error"
                            >
                            <i class="validation-icon"></i>
                        </div>
                        <div class="error-message-inline" id="nome-error"></div>
                    </div>
                    
                    <div class="input-group">
                        <label for="cpf">CPF</label>
                        <div class="input-wrapper">
                            <input 
                                type="text" 
                                id="cpf" 
                                name="cpf" 
                                placeholder="000.000.000-00" 
                                required 
                                inputmode="numeric"
                                autocomplete="off"
                                class="input"
                                aria-describedby="cpf-error"
                                maxlength="14"
                            >
                            <i class="validation-icon"></i>
                        </div>
                        <div class="error-message-inline" id="cpf-error"></div>
                        <div id="cpf-exists-options" class="already-exists-options" style="display: none;">
                            <button type="button" class="mini-button login-button">Fazer login</button>
                            <button type="button" class="mini-button forgot-password-button">Esqueci a senha</button>
                        </div>
                    </div>
                    
                    <div class="input-group">
                        <label for="email">E-mail</label>
                        <div class="input-wrapper">
                            <input 
                                type="email" 
                                id="email" 
                                name="email" 
                                placeholder="seu.email@exemplo.com" 
                                required
                                autocomplete="email"
                                class="input"
                                aria-describedby="email-error"
                            >
                            <i class="validation-icon"></i>
                        </div>
                        <div class="error-message-inline" id="email-error"></div>
                        <div id="email-exists-options" class="already-exists-options" style="display: none;">
                            <button type="button" class="mini-button login-button">Fazer login</button>
                            <button type="button" class="mini-button forgot-password-button">Esqueci a senha</button>
                        </div>
                    </div>
                    
                    <div class="input-group">
                        <label for="celular">Celular (WhatsApp)</label>
                        <div class="input-wrapper">
                            <input 
                                type="tel" 
                                id="celular" 
                                name="celular" 
                                placeholder="(47) 99999-9999" 
                                required 
                                inputmode="tel"
                                autocomplete="tel"
                                class="input"
                                aria-describedby="celular-error"
                                maxlength="15"
                            >
                            <i class="validation-icon"></i>
                        </div>
                        <div class="error-message-inline" id="celular-error"></div>
                    </div>
                </fieldset>

                <fieldset>
                    <legend>Dados da sua Ótica</legend>
                    <div class="input-group">
                        <label for="cnpj">CNPJ da Ótica</label>
                        <div class="input-wrapper">
                            <input 
                                type="text" 
                                id="cnpj" 
                                name="cnpj" 
                                placeholder="00.000.000/0000-00" 
                                required 
                                inputmode="numeric"
                                autocomplete="off"
                                class="input"
                                aria-describedby="cnpj-error"
                                maxlength="18"
                            >
                            <i class="validation-icon"></i>
                        </div>
                        <div class="error-message-inline" id="cnpj-error"></div>
                    </div>
                    
                    <div id="otica-dados-wrapper" class="hidden">
                        <div class="input-group">
                            <label for="razao_social">Razão Social</label>
                            <input 
                                type="text" 
                                id="razao_social" 
                                name="razao_social" 
                                readonly 
                                disabled
                                class="input"
                            >
                        </div>
                        <div class="input-group">
                            <label for="endereco_otica">Endereço</label>
                            <input 
                                type="text" 
                                id="endereco_otica" 
                                name="endereco_otica" 
                                readonly 
                                disabled
                                class="input"
                            >
                        </div>
                    </div>
                </fieldset>

                <fieldset>
                    <legend>Segurança</legend>
                    <div class="input-group">
                        <label for="senha">Crie sua Senha</label>
                        <div class="input-wrapper password-input-wrapper">
                            <input 
                                type="password" 
                                id="senha" 
                                name="senha" 
                                placeholder="Crie uma senha forte" 
                                required
                                autocomplete="new-password"
                                class="input"
                                aria-describedby="senha-error password-strength-feedback"
                                minlength="8"
                            >
                            <i class="validation-icon"></i>
                            <button type="button" id="toggle-password" class="toggle-password" aria-label="Mostrar/Ocultar senha">
                                <i class="fas fa-eye"></i>
                            </button>
                        </div>
                        <div class="error-message-inline" id="senha-error"></div>
                        <div id="password-strength-feedback" class="password-rules">
                            <span id="length"><i class="fa-solid fa-xmark"></i> 8+ caracteres</span>
                            <span id="uppercase"><i class="fa-solid fa-xmark"></i> 1 Letra Maiúscula</span>
                            <span id="lowercase"><i class="fa-solid fa-xmark"></i> 1 Letra Minúscula</span>
                            <span id="number"><i class="fa-solid fa-xmark"></i> 1 Número</span>
                            <span id="special"><i class="fa-solid fa-xmark"></i> 1 Símbolo</span>
                        </div>
                    </div>
                    
                    <div class="input-group">
                        <label for="confirmar_senha">Confirme sua Senha</label>
                        <div class="input-wrapper">
                            <input 
                                type="password" 
                                id="confirmar_senha" 
                                name="confirmar_senha" 
                                placeholder="Repita a senha" 
                                required 
                                disabled
                                autocomplete="new-password"
                                class="input"
                                aria-describedby="confirmar-senha-error"
                                minlength="8"
                            >
                            <i class="validation-icon"></i>
                        </div>
                        <div class="error-message-inline" id="confirmar-senha-error"></div>
                    </div>
                </fieldset>

                <div class="checkbox-group">
                    <input type="checkbox" id="termos" name="termos" required>
                    <label for="termos">
                        Li e aceito os <a href="/termos.php" target="_blank" rel="noopener">Termos de Uso</a> 
                        e a <a href="/privacidade.php" target="_blank" rel="noopener">Política de Privacidade</a>.
                    </label>
                </div>
                <div class="error-message-inline" id="termos-error"></div>

                <button type="submit" id="register-button" class="login-btn primary-gradient-btn" disabled>
                    <span class="btn-text">Criar Cadastro</span>
                    <span class="btn-loading" style="display: none;" aria-hidden="true">
                        <i class="fas fa-spinner fa-spin"></i>
                        Processando...
                    </span>
                </button>
            </form>

            <div class="login-links">
                <p>Já tem uma conta? <a href="/login.php">Acesse aqui</a></p>
            </div>
        </div>

        <!-- Loading Overlay -->
        <div id="loading-overlay" class="loading-overlay" aria-hidden="true">
            <div class="loading-spinner">
                <div class="spinner-ring"></div>
                <p>Processando cadastro...</p>
            </div>
        </div>
    </div>

    <!-- App JS -->
    <script src="/js/cadastro.js" defer></script>

    <!-- Service Worker registration -->
    <script nonce="<?php echo $_SESSION['csp_nonce'] ?? ''; ?>">
        // Service Worker removido temporariamente
        console.log('📱 Script inline carregado com nonce');
    </script>
</body>
</html>