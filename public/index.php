<?php
declare(strict_types=1);

/**
 * ==============================================================================
 * PONTO DE ENTRADA PRINCIPAL - Sistema de Campanhas EPS v4.0
 * ==============================================================================
 * Localização: /public/index.php
 * 
 * Este arquivo serve como ponto de entrada principal do sistema.
 * Redireciona usuários autenticados para seus dashboards específicos
 * e usuários não autenticados para a página de login.
 */

// Define constantes de inicialização
define('APP_INITIATED', true);
define('APP_ROOT', dirname(__DIR__));

// Configuração de erro para desenvolvimento
if (!file_exists(APP_ROOT . '/.env')) {
    // Se não existir .env, mostra página de instalação
    http_response_code(503);
    ?>
    <!DOCTYPE html>
    <html lang="pt-BR">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Configuração Necessária - Campanhas EPS</title>
        <style>
            * { margin: 0; padding: 0; box-sizing: border-box; }
            body {
                font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
                background: linear-gradient(135deg, #020617 0%, #0f172a 100%);
                color: #f8fafc;
                height: 100vh;
                display: flex;
                align-items: center;
                justify-content: center;
                padding: 2rem;
            }
            .setup-container {
                text-align: center;
                max-width: 600px;
                background: rgba(15, 23, 42, 0.4);
                backdrop-filter: blur(20px);
                border: 1px solid rgba(148, 163, 184, 0.2);
                border-radius: 24px;
                padding: 4rem 3rem;
                box-shadow: 0 25px 50px -12px rgba(0, 0, 0, 0.25);
            }
            .setup-icon {
                font-size: 4rem;
                color: #3b82f6;
                margin-bottom: 2rem;
            }
            h1 {
                font-size: 2.5rem;
                font-weight: 600;
                margin-bottom: 1rem;
                color: #f8fafc;
            }
            p {
                font-size: 1.4rem;
                color: #cbd5e1;
                margin-bottom: 2rem;
                line-height: 1.6;
            }
            .steps {
                text-align: left;
                background: rgba(30, 41, 59, 0.3);
                border-radius: 12px;
                padding: 2rem;
                margin: 2rem 0;
            }
            .step {
                margin-bottom: 1rem;
                padding: 1rem;
                background: rgba(51, 65, 85, 0.3);
                border-radius: 8px;
                border-left: 4px solid #3b82f6;
            }
            .step h3 {
                color: #3b82f6;
                margin-bottom: 0.5rem;
            }
            .code {
                background: #0f172a;
                color: #10b981;
                padding: 0.5rem 1rem;
                border-radius: 6px;
                font-family: 'Courier New', monospace;
                font-size: 1.2rem;
                margin: 0.5rem 0;
                display: inline-block;
            }
        </style>
    </head>
    <body>
        <div class="setup-container">
            <div class="setup-icon">⚙️</div>
            <h1>Configuração Inicial Necessária</h1>
            <p>O sistema precisa ser configurado antes do primeiro uso.</p>
            
            <div class="steps">
                <div class="step">
                    <h3>1. Criar arquivo de configuração</h3>
                    <p>Crie o arquivo <span class="code">.env</span> na raiz do projeto com as configurações de banco.</p>
                </div>
                
                <div class="step">
                    <h3>2. Configurar banco de dados</h3>
                    <p>Crie o banco <span class="code">campanhas_eps</span> no MySQL e execute o arquivo <span class="code">schema.sql</span>.</p>
                </div>
                
                <div class="step">
                    <h3>3. Verificar permissões</h3>
                    <p>Certifique-se que as pastas <span class="code">app/logs</span> e <span class="code">app/cache</span> têm permissão de escrita.</p>
                </div>
            </div>
            
            <p><strong>Após a configuração, recarregue esta página.</strong></p>
        </div>
    </body>
    </html>
    <?php
    exit;
}

// Headers de segurança básicos
if (!headers_sent()) {
    header('X-Content-Type-Options: nosniff');
    header('X-Frame-Options: DENY');
    header('X-XSS-Protection: 1; mode=block');
    header('Referrer-Policy: strict-origin-when-cross-origin');
}

try {
    // Carrega o sistema
    require_once APP_ROOT . '/app/config/config.php';
    
    // Verifica se as tabelas existem
    $healthCheck = checkDatabaseHealth();
    
    if ($healthCheck['status'] === 'error' || !$healthCheck['tables_exist']) {
        // Mostra página de setup do banco
        ?>
        <!DOCTYPE html>
        <html lang="pt-BR">
        <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <title>Setup do Banco - Campanhas EPS</title>
            <style>
                * { margin: 0; padding: 0; box-sizing: border-box; }
                body {
                    font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
                    background: linear-gradient(135deg, #020617 0%, #0f172a 100%);
                    color: #f8fafc;
                    min-height: 100vh;
                    padding: 2rem;
                }
                .setup-container {
                    max-width: 800px;
                    margin: 0 auto;
                    background: rgba(15, 23, 42, 0.4);
                    backdrop-filter: blur(20px);
                    border: 1px solid rgba(148, 163, 184, 0.2);
                    border-radius: 24px;
                    padding: 4rem 3rem;
                }
                .database-icon {
                    font-size: 4rem;
                    color: #ef4444;
                    text-align: center;
                    margin-bottom: 2rem;
                }
                h1 {
                    font-size: 2.5rem;
                    text-align: center;
                    margin-bottom: 2rem;
                    color: #f8fafc;
                }
                .error-details {
                    background: rgba(239, 68, 68, 0.1);
                    border: 1px solid rgba(239, 68, 68, 0.3);
                    border-radius: 12px;
                    padding: 2rem;
                    margin: 2rem 0;
                }
                .solution {
                    background: rgba(59, 130, 246, 0.1);
                    border: 1px solid rgba(59, 130, 246, 0.3);
                    border-radius: 12px;
                    padding: 2rem;
                    margin: 2rem 0;
                }
                .code-block {
                    background: #0f172a;
                    color: #10b981;
                    padding: 1rem;
                    border-radius: 8px;
                    font-family: 'Courier New', monospace;
                    font-size: 1.2rem;
                    margin: 1rem 0;
                    overflow-x: auto;
                    white-space: pre;
                }
                p {
                    font-size: 1.4rem;
                    line-height: 1.6;
                    margin-bottom: 1rem;
                }
                .btn {
                    display: inline-block;
                    background: linear-gradient(135deg, #3b82f6, #1d4ed8);
                    color: white;
                    padding: 1rem 2rem;
                    border: none;
                    border-radius: 8px;
                    font-size: 1.4rem;
                    font-weight: 600;
                    text-decoration: none;
                    cursor: pointer;
                    margin: 1rem 0;
                    transition: transform 0.2s;
                }
                .btn:hover {
                    transform: translateY(-2px);
                }
            </style>
        </head>
        <body>
            <div class="setup-container">
                <div class="database-icon">🗄️</div>
                <h1>Setup do Banco de Dados</h1>
                
                <div class="error-details">
                    <h3>❌ Problema Detectado:</h3>
                    <p><?php echo htmlspecialchars($healthCheck['error'] ?? 'Banco de dados não configurado'); ?></p>
                    <?php if (!empty($healthCheck['missing_tables'])): ?>
                    <p><strong>Tabelas faltando:</strong> <?php echo implode(', ', $healthCheck['missing_tables']); ?></p>
                    <?php endif; ?>
                </div>
                
                <div class="solution">
                    <h3>💡 Solução:</h3>
                    <p>Execute os seguintes comandos no MySQL:</p>
                    
                    <div class="code-block">mysql -u root -p
CREATE DATABASE campanhas_eps CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
USE campanhas_eps;
SOURCE caminho/para/schema.sql;</div>
                    
                    <p>Ou importe o arquivo <strong>schema.sql</strong> através do phpMyAdmin.</p>
                </div>
                
                <button class="btn" onclick="window.location.reload()">
                    🔄 Verificar Novamente
                </button>
            </div>
        </body>
        </html>
        <?php
        exit;
    }
    
    // Sistema funcionando - redireciona conforme autenticação
    
    // Verifica se o usuário já está logado
    if (!empty($_SESSION['user_id']) && !empty($_SESSION['user_tipo'])) {
        // Usuário autenticado - redireciona para dashboard apropriado
        $redirectUrl = getRedirectUrlForUser($_SESSION['user_tipo']);
        
        if (function_exists('logSecurityEvent')) {
            logSecurityEvent('INDEX_REDIRECT_AUTHENTICATED', 'Usuário autenticado redirecionado', [
                'user_id' => $_SESSION['user_id'],
                'user_type' => $_SESSION['user_tipo'],
                'redirect_url' => $redirectUrl
            ]);
        }
        
        header("Location: $redirectUrl", true, 302);
        exit;
    }
    
    // Usuário não autenticado - redireciona para login
    if (function_exists('logSecurityEvent')) {
        logSecurityEvent('INDEX_REDIRECT_GUEST', 'Usuário não autenticado redirecionado para login', [
            'ip_address' => $_SERVER['REMOTE_ADDR'] ?? 'unknown',
            'user_agent' => $_SERVER['HTTP_USER_AGENT'] ?? 'unknown'
        ]);
    }
    
    header('Location: /login.php', true, 302);
    exit;
    
} catch (Exception $e) {
    // Em caso de erro crítico, mostra página de erro amigável
    
    // Log do erro se possível
    error_log('CRITICAL INDEX ERROR: ' . $e->getMessage());
    
    http_response_code(500);
    ?>
    <!DOCTYPE html>
    <html lang="pt-BR">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Erro Interno - Campanhas EPS</title>
        <style>
            * { margin: 0; padding: 0; box-sizing: border-box; }
            body {
                font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
                background: linear-gradient(135deg, #020617 0%, #0f172a 100%);
                color: #f8fafc;
                height: 100vh;
                display: flex;
                align-items: center;
                justify-content: center;
                padding: 2rem;
            }
            .error-container {
                text-align: center;
                max-width: 600px;
                background: rgba(15, 23, 42, 0.4);
                backdrop-filter: blur(20px);
                border: 1px solid rgba(148, 163, 184, 0.2);
                border-radius: 24px;
                padding: 4rem 3rem;
                box-shadow: 0 25px 50px -12px rgba(0, 0, 0, 0.25);
            }
            .error-icon {
                font-size: 6rem;
                color: #ef4444;
                margin-bottom: 2rem;
            }
            h1 {
                font-size: 2.5rem;
                font-weight: 600;
                margin-bottom: 1rem;
                color: #f8fafc;
            }
            p {
                font-size: 1.6rem;
                color: #cbd5e1;
                margin-bottom: 2rem;
                line-height: 1.6;
            }
            .error-details {
                background: rgba(239, 68, 68, 0.1);
                border: 1px solid rgba(239, 68, 68, 0.3);
                border-radius: 12px;
                padding: 2rem;
                margin: 2rem 0;
                text-align: left;
            }
            .error-code {
                font-family: 'Courier New', monospace;
                font-size: 1.2rem;
                color: #fbbf24;
                word-break: break-all;
            }
            .btn {
                display: inline-block;
                background: linear-gradient(135deg, #3b82f6, #1d4ed8);
                color: white;
                padding: 1.2rem 2.4rem;
                border: none;
                border-radius: 8px;
                font-size: 1.6rem;
                font-weight: 600;
                text-decoration: none;
                cursor: pointer;
                margin: 1rem;
                transition: transform 0.2s;
            }
            .btn:hover {
                transform: translateY(-2px);
            }
        </style>
    </head>
    <body>
        <div class="error-container">
            <div class="error-icon">⚠️</div>
            <h1>Erro Interno do Sistema</h1>
            <p>Ocorreu um erro inesperado. Nossa equipe foi notificada automaticamente.</p>
            
            <?php if (defined('ENVIRONMENT') && ENVIRONMENT === 'development'): ?>
            <div class="error-details">
                <h3>Detalhes do Erro (Modo Desenvolvimento):</h3>
                <p class="error-code"><?php echo htmlspecialchars($e->getMessage()); ?></p>
                <p><strong>Arquivo:</strong> <?php echo htmlspecialchars($e->getFile()); ?></p>
                <p><strong>Linha:</strong> <?php echo $e->getLine(); ?></p>
            </div>
            <?php endif; ?>
            
            <button class="btn" onclick="window.location.reload()">
                🔄 Tentar Novamente
            </button>
            
            <a href="mailto:suporte@embrapol.com.br" class="btn">
                📧 Reportar Problema
            </a>
        </div>
    </body>
    </html>
    <?php
    exit;
}
?>