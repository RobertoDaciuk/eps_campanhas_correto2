<?php
declare(strict_types=1);
/**
 * ==============================================================================
 * INTERFACE DE ACESSO (Login View) - v3.1 COMPLETA
 * ==============================================================================
 * Localização: /public/login.php
 * Função: exibir o formulário de login com validações e headers de segurança.
 */

// -----------------------------------------------------------------------------
// Segurança e bootstrap
// -----------------------------------------------------------------------------
if (!defined('APP_INITIATED')) {
    define('APP_INITIATED', true);
}
if (!defined('APP_ROOT')) {
    define('APP_ROOT', dirname(__DIR__));
}

// Cabeçalhos de segurança básicos
header('X-Content-Type-Options: nosniff');
header('X-Frame-Options: DENY');
header('Referrer-Policy: strict-origin-when-cross-origin');
header('X-XSS-Protection: 1; mode=block');

// Cache: não armazenar página de login
header('Cache-Control: no-store, no-cache, must-revalidate, max-age=0');
header('Pragma: no-cache');
header('Expires: 0');

// CSP (ajustada aos recursos usados nesta página)
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

// Permissions-Policy mínima
header('Permissions-Policy: geolocation=(), microphone=(), camera=()');

// HSTS (somente produção e HTTPS)
$__isHttps = (!empty($_SERVER['HTTPS']) && strtolower((string)$_SERVER['HTTPS']) !== 'off')
    || (!empty($_SERVER['SERVER_PORT']) && (int)$_SERVER['SERVER_PORT'] === 443)
    || (isset($_SERVER['HTTP_X_FORWARDED_PROTO']) && strtolower((string)$_SERVER['HTTP_X_FORWARDED_PROTO']) === 'https');

if (defined('ENVIRONMENT') ? ENVIRONMENT === 'production' : false) {
    if ($__isHttps) {
        header('Strict-Transport-Security: max-age=15552000; includeSubDomains; preload');
    }
}

// Carrega config
$configPath = APP_ROOT . '/app/config/config.php';
if (!is_file($configPath)) {
    http_response_code(500);
    exit('Erro: Arquivo de configuração não encontrado.');
}
require_once $configPath;

// -----------------------------------------------------------------------------
// Redirecionamento se já autenticado
// -----------------------------------------------------------------------------
if (!headers_sent() && !empty($_SESSION['user_id']) && !empty($_SESSION['user_tipo'])) {
    $redirectUrl = function_exists('getRedirectUrlForUser')
        ? getRedirectUrlForUser((string)$_SESSION['user_tipo'])
        : '/dashboard.php';

    if ($redirectUrl && $redirectUrl !== '/login.php') {
        header('Location: ' . $redirectUrl, true, 302);
        exit;
    }
}

// -----------------------------------------------------------------------------
// Garante CSRF token para o formulário
// -----------------------------------------------------------------------------
if (empty($_SESSION['csrf_token'])) {
    $_SESSION['csrf_token'] = rtrim(strtr(base64_encode(random_bytes(32)), '+/', '-_'), '=');
}

$csrf = htmlspecialchars((string)$_SESSION['csrf_token'], ENT_QUOTES, 'UTF-8');

// Detecta se há mensagens de status
$message = '';
$messageType = '';

if (isset($_GET['registered']) && $_GET['registered'] === '1') {
    $message = 'Cadastro realizado com sucesso! Verifique seu e-mail para ativar a conta.';
    $messageType = 'success';
} elseif (isset($_GET['activated']) && $_GET['activated'] === '1') {
    $message = 'Conta ativada com sucesso! Você já pode fazer login.';
    $messageType = 'success';
} elseif (isset($_GET['error']) && $_GET['error'] === 'session_expired') {
    $message = 'Sua sessão expirou. Faça login novamente.';
    $messageType = 'warning';
}
?>
<!DOCTYPE html>
<html lang="pt-BR">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Acesso ao Sistema de Campanhas - Embrapol Sul</title>
    <meta name="description" content="Aceda ao portal de campanhas promocionais para vendedores e óticas parceiras da Embrapol Sul.">
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

    <!-- Favicon -->
    <link rel="icon" type="image/x-icon" href="/favicon.ico">
</head>
<body>
    <div class="login-page-container">
        <div class="login-card glass-effect">
            <div class="login-header">
                <div class="login-logo">
                    <i class="fas fa-chart-line logo-icon glow" aria-hidden="true"></i>
                    <h1>Campanhas <span class="logo-span">EPS</span></h1>
                </div>
                <h2>Aceder ao Sistema</h2>
            </div>

            <!-- Error/Success Messages -->
            <div id="message-container" class="message-container" role="alert" aria-live="polite">
                <?php if ($message): ?>
                    <div class="message <?php echo $messageType; ?>">
                        <i class="fas fa-<?php echo $messageType === 'success' ? 'check-circle' : ($messageType === 'warning' ? 'exclamation-triangle' : 'info-circle'); ?>" aria-hidden="true"></i>
                        <span><?php echo htmlspecialchars($message, ENT_QUOTES, 'UTF-8'); ?></span>
                    </div>
                <?php endif; ?>
            </div>

            <form id="login-form" method="POST" action="/api/auth_api.php" novalidate autocomplete="on">
                <!-- CSRF Token -->
                <input type="hidden" name="csrf_token" value="<?php echo $csrf; ?>">

                <div class="input-group">
                    <label for="identifier" class="input-label">
                        <i class="fas fa-user-circle" aria-hidden="true"></i>
                        <span>Utilizador</span>
                        <small>(CPF ou E-mail)</small>
                    </label>
                    <div class="input-wrapper">
                        <input
                            type="text"
                            id="identifier"
                            name="identifier"
                            placeholder="Digite o seu CPF ou e-mail"
                            required
                            autocomplete="username"
                            autocapitalize="none"
                            spellcheck="false"
                            aria-describedby="identifier-error"
                            autofocus
                            class="input"
                        >
                        <span class="input-focus-border"></span>
                    </div>
                    <div id="identifier-error" class="field-error" role="alert"></div>
                </div>

                <div class="input-group">
                    <label for="password" class="input-label">
                        <i class="fas fa-lock" aria-hidden="true"></i>
                        <span>Senha</span>
                    </label>
                    <div class="input-wrapper">
                        <input
                            type="password"
                            id="password"
                            name="password"
                            placeholder="Digite a sua senha"
                            required
                            autocomplete="current-password"
                            aria-describedby="password-error"
                            minlength="6"
                            class="input"
                        >
                        <button type="button" class="password-toggle" aria-label="Mostrar/Ocultar senha">
                            <i class="fas fa-eye" aria-hidden="true"></i>
                        </button>
                        <span class="input-focus-border"></span>
                    </div>
                    <div id="password-error" class="field-error" role="alert"></div>
                </div>

                <div class="form-options">
                    <label class="checkbox-container">
                        <input type="checkbox" name="remember" id="remember" value="1">
                        <span class="checkmark"></span>
                        <span class="checkbox-text">Lembrar-me por 30 dias</span>
                    </label>
                    <a href="/recuperar-senha.php" class="forgot-password-link">
                        <i class="fas fa-key" aria-hidden="true"></i>
                        Esqueceu a senha?
                    </a>
                </div>

                <button type="submit" id="login-button" class="login-btn primary-gradient-btn">
                    <span class="btn-text">Entrar no Sistema</span>
                    <span class="btn-loading" aria-hidden="true">
                        <i class="fas fa-spinner fa-spin"></i>
                        Autenticando...
                    </span>
                </button>
            </form>

            <div class="login-footer">
                <div class="divider">
                    <span>ou</span>
                </div>

                <div class="login-links">
                    <p>
                        <i class="fas fa-user-plus" aria-hidden="true"></i>
                        Não tem uma conta?
                        <a href="/cadastro.php" class="register-link">Registe-se aqui</a>
                    </p>
                </div>

                <div class="login-help">
                    <p>
                        <i class="fas fa-question-circle" aria-hidden="true"></i>
                        Precisa de ajuda?
                        <a href="/ajuda.php">Centro de Ajuda</a>
                    </p>
                </div>
            </div>
        </div>

        <!-- Loading Overlay -->
        <div id="loading-overlay" class="loading-overlay" aria-hidden="true">
            <div class="loading-spinner">
                <div class="spinner-ring"></div>
                <p>Verificando credenciais...</p>
            </div>
        </div>
    </div>

    <!-- App JS -->
    <script src="/js/auth.js" defer></script>

    <!-- Service Worker registration -->
    <script nonce="<?php echo $_SESSION['csp_nonce'] ?? ''; ?>">
    // Service Worker removido temporariamente
    // if ('serviceWorker' in navigator) {
    //     navigator.serviceWorker.register('/sw.js').catch(() => { /* silent fail */ });
    // }
    </script>
</body>
</html>