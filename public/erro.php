<?php
declare(strict_types=1);
/**
 * ==============================================================================
 * PÁGINA DE ERRO PREMIUM
 * ==============================================================================
 * Localização: /public/erro.php
 */

$errorCode = $_GET['code'] ?? '404';
$errorMessages = [
    '400' => ['Requisição Inválida', 'A requisição não pôde ser processada devido a um erro do cliente.'],
    '401' => ['Não Autorizado', 'Você precisa fazer login para acessar esta página.'],
    '403' => ['Acesso Proibido', 'Você não tem permissão para acessar este recurso.'],
    '404' => ['Página Não Encontrada', 'A página que você está procurando não existe.'],
    '500' => ['Erro Interno', 'Ocorreu um erro interno no servidor. Tente novamente mais tarde.'],
];

$error = $errorMessages[$errorCode] ?? $errorMessages['404'];
http_response_code((int)$errorCode);
?>
<!DOCTYPE html>
<html lang="pt-BR">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Erro <?php echo $errorCode; ?> - Campanhas EPS</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body {
            font-family: 'Inter', sans-serif;
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
            max-width: 500px;
            background: rgba(15, 23, 42, 0.4);
            backdrop-filter: blur(20px);
            border: 1px solid rgba(148, 163, 184, 0.2);
            border-radius: 24px;
            padding: 4rem 3rem;
            box-shadow: 0 25px 50px -12px rgba(0, 0, 0, 0.25);
        }
        .error-code {
            font-size: 6rem;
            font-weight: 700;
            color: #3b82f6;
            margin-bottom: 1rem;
        }
        .error-title {
            font-size: 2.5rem;
            font-weight: 600;
            margin-bottom: 1rem;
            color: #f8fafc;
        }
        .error-description {
            font-size: 1.6rem;
            color: #cbd5e1;
            margin-bottom: 3rem;
            line-height: 1.6;
        }
        .error-actions {
            display: flex;
            gap: 1.5rem;
            justify-content: center;
            flex-wrap: wrap;
        }
        .btn {
            padding: 1.2rem 2.4rem;
            border: none;
            border-radius: 12px;
            font-size: 1.6rem;
            font-weight: 600;
            text-decoration: none;
            cursor: pointer;
            transition: all 0.3s ease;
            display: inline-flex;
            align-items: center;
            gap: 0.8rem;
        }
        .btn-primary {
            background: linear-gradient(135deg, #3b82f6, #1d4ed8);
            color: white;
            box-shadow: 0 4px 15px rgba(59, 130, 246, 0.4);
        }
        .btn-primary:hover {
            transform: translateY(-2px);
            box-shadow: 0 6px 25px rgba(59, 130, 246, 0.5);
        }
        .btn-secondary {
            background: rgba(15, 23, 42, 0.3);
            border: 1px solid rgba(148, 163, 184, 0.2);
            color: #cbd5e1;
        }
        .btn-secondary:hover {
            background: rgba(30, 41, 59, 0.5);
            color: #f8fafc;
        }
        @media (max-width: 480px) {
            .error-container { padding: 3rem 2rem; }
            .error-code { font-size: 4rem; }
            .error-title { font-size: 2rem; }
            .error-description { font-size: 1.4rem; }
            .error-actions { flex-direction: column; }
        }
    </style>
</head>
<body>
    <div class="error-container">
        <div class="error-code"><?php echo $errorCode; ?></div>
        <h1 class="error-title"><?php echo $error[0]; ?></h1>
        <p class="error-description"><?php echo $error[1]; ?></p>
        
        <div class="error-actions">
            <a href="/login.php" class="btn btn-primary">
                <i class="fas fa-home"></i>
                Voltar ao Início
            </a>
            <button onclick="history.back()" class="btn btn-secondary">
                <i class="fas fa-arrow-left"></i>
                Página Anterior
            </button>
        </div>
    </div>
    
    <script src="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.5.1/js/all.min.js"></script>
</body>
</html>