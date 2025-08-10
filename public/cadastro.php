.register-card {
            background: var(--bg-glass);
            backdrop-filter: blur(25px);
            -webkit-backdrop-filter: blur(25px);
            border: 1px solid var(--border-glass);
            border-radius: 24px;
            padding: 2rem;
            width: 100%;
            max-width: 580px;
            box-shadow: var(--shadow-card);
            opacity: 0;
            transform: translateY(30px);
            animation: fadeInUp 0.8s cubic-bezier(0.4, 0, 0.2, 1) 0.2s forwards;
        }
        
        @keyframes fadeInUp {
            to {
                opacity: 1;
                transform: translateY(0);
            }
        }
        
        .login-logo h2 {
            font-size: 2.5rem;
            font-weight: 700;
            margin-bottom: 0.5rem;
            background: linear-gradient(135deg, var(--primary-light) 0%, var(--primary) 100%);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
            background-clip: text;
        }
        
        .logo-icon {
            font-size: 3rem;
            color: var(--primary-light);
            margin-bottom: 1rem;
            display: block;
        }
        
        /* Loading states */
        .loading {
            opacity: 0.6;
            pointer-events: none;
        }
        
        .sr-only {
            position: absolute !important;
            width: 1px !important;
            height: 1px !important;
            padding: 0 !important;
            margin: -1px !important;
            overflow: hidden !important;
            clip: rect(0, 0, 0, 0) !important;
            white-space: nowrap !important;
            border: 0 !important;
        }
        
        /* High contrast support */
        @media (prefers-contrast: high) {
            :root {
                --bg-primary: #000000;
                --bg-secondary: #1a1a1a;
                --text-primary: #ffffff;
                --border-glass: rgba(255, 255, 255, 0.3);
            }
        }
        
        /* Reduced motion support */
        @media (prefers-reduced-motion: reduce) {
            *, *::before, *::after {
                animation-duration: 0.01ms !important;
                animation-iteration-count: 1 !important;
                transition-duration: 0.01ms !important;
            }
        }
    </style>
    
    <!-- === FAVICONS & ICONS === -->
    <link rel="icon" type="image/svg+xml" href="/favicon.svg">
    <link rel="icon" type="image/png" sizes="32x32" href="/favicon-32x32.png">
    <link rel="icon" type="image/png" sizes="16x16" href="/favicon-16x16.png">
    <link rel="apple-touch-icon" sizes="180x180" href="/apple-touch-icon.png">
    <link rel="manifest" href="/manifest.json">
    
    <!-- === WEB APP MANIFEST === -->
    <script nonce="<?php echo $nonce; ?>">
        // Remove no-js class immediately
        document.documentElement.classList.remove('no-js');
        document.documentElement.classList.add('js');
        
        // Early performance mark
        if ('performance' in window && 'mark' in performance) {
            performance.mark('registration-page-start');
        }
        
        // Critical JavaScript for immediate functionality
        window.REGISTRATION_CONFIG = {
            environment: '<?php echo ENVIRONMENT; ?>',
            version: '<?php echo $appVersion; ?>',
            csrf_token: '<?php echo $csrf; ?>',
            app_url: '<?php echo APP_URL; ?>',
            debug: <?php echo $isDevelopment ? 'true' : 'false'; ?>
        };
    </script>
</head>
<body>
    <!-- === SCHEMA.ORG STRUCTURED DATA === -->
    <script type="application/ld+json" nonce="<?php echo $nonce; ?>">
    {
        "@context": "https://schema.org",
        "@type": "WebPage",
        "name": "Cadastro de Vendedor",
        "description": "Sistema de cadastro para vendedores das campanhas promocionais Embrapol Sul",
        "url": "<?php echo APP_URL; ?>/cadastro.php",
        "isPartOf": {
            "@type": "WebSite",
            "name": "Sistema Campanhas Embrapol Sul",
            "url": "<?php echo APP_URL; ?>"
        },
        "mainEntity": {
            "@type": "WebApplication",
            "name": "Sistema de Cadastro de Vendedores",
            "applicationCategory": "BusinessApplication",
            "operatingSystem": "Web Browser",
            "offers": {
                "@type": "Offer",
                "price": "0",
                "priceCurrency": "BRL"
            }
        }
    }
    </script>

    <!-- === SKIP LINKS PARA ACESSIBILIDADE === -->
    <nav class="skip-links sr-only" aria-label="Links de navegação rápida">
        <a href="#main-content" class="skip-link">Pular para o conteúdo principal</a>
        <a href="#register-form" class="skip-link">Pular para o formulário</a>
    </nav>

    <!-- === CONTAINER PRINCIPAL === -->
    <div class="login-page-container" role="main">
        <!-- === BACKGROUND PARTICLES (OPCIONAL) === -->
        <canvas id="bg-particles" class="background-particles js-only" aria-hidden="true"></canvas>
        
        <main class="register-card glass-effect" id="main-content">
            <!-- === CABEÇALHO === -->
            <header class="login-logo" role="banner">
                <i class="fas fa-user-plus logo-icon glow" aria-hidden="true"></i>
                <h1>Cadastro de Vendedor</h1>
                <p class="subtitle">Preencha os dados para iniciar sua participação nas campanhas.</p>
            </header>

            <!-- === CONTAINER DE MENSAGENS === -->
            <div id="message-container" 
                 class="message-container" 
                 role="alert" 
                 aria-live="polite" 
                 aria-atomic="true"
                 style="min-height: 1px;">
            </div>

            <!-- === FALLBACK PARA JAVASCRIPT DESABILITADO === -->
            <noscript class="no-js-only">
                <div class="alert alert-warning" role="alert">
                    <h3>JavaScript Requerido</h3>
                    <p>Este formulário requer JavaScript para funcionar corretamente. Por favor, habilite JavaScript em seu navegador e recarregue a página.</p>
                    <details>
                        <summary>Por que JavaScript é necessário?</summary>
                        <ul>
                            <li>Validação em tempo real dos dados</li>
                            <li>Formatação automática de CPF, CNPJ e telefone</li>
                            <li>Verificação de força da senha</li>
                            <li>Interface acessível e responsiva</li>
                        </ul>
                    </details>
                </div>
            </noscript>

            <!-- === FORMULÁRIO PRINCIPAL === -->
            <form id="register-form" 
                  method="POST" 
                  action="/api/cadastro_api.php" 
                  novalidate 
                  autocomplete="on"
                  class="js-only">
                
                <!-- === TOKEN CSRF === -->
                <input type="hidden" 
                       name="csrf_token" 
                       value="<?php echo $csrf; ?>"
                       id="csrf-token">

                <!-- === DADOS PESSOAIS === -->
                <fieldset class="form-section">
                    <legend class="section-title">
                        <i class="fas fa-user" aria-hidden="true"></i>
                        Dados Pessoais
                    </legend>
                    
                    <div class="input-group">
                        <label for="nome" class="required-field">
                            Nome Completo
                            <span class="required-indicator" aria-label="Campo obrigatório">*</span>
                        </label>
                        <div class="input-wrapper">
                            <input type="text" 
                                   id="nome" 
                                   name="nome" 
                                   placeholder="Digite seu nome completo" 
                                   required
                                   autocomplete="name"
                                   class="input"
                                   aria-describedby="nome-error nome-hint"
                                   minlength="2"
                                   maxlength="120">
                            <i class="validation-icon" aria-hidden="true"></i>
                        </div>
                        <div class="input-hint" id="nome-hint">
                            Digite seu nome completo como aparece no documento
                        </div>
                        <div class="error-message-inline" 
                             id="nome-error" 
                             role="alert" 
                             aria-live="polite"></div>
                    </div>
                    
                    <div class="input-group">
                        <label for="cpf" class="required-field">
                            CPF
                            <span class="required-indicator" aria-label="Campo obrigatório">*</span>
                        </label>
                        <div class="input-wrapper">
                            <input type="text" 
                                   id="cpf" 
                                   name="cpf" 
                                   placeholder="000.000.000-00" 
                                   required 
                                   inputmode="numeric"
                                   autocomplete="off"
                                   class="input"
                                   aria-describedby="cpf-error cpf-hint"
                                   maxlength="14"
                                   pattern="\d{3}\.\d{3}\.\d{3}-\d{2}">
                            <i class="validation-icon" aria-hidden="true"></i>
                        </div>
                        <div class="input-hint" id="cpf-hint">
                            Apenas números - a formatação é automática
                        </div>
                        <div class="error-message-inline" 
                             id="cpf-error" 
                             role="alert" 
                             aria-live="polite"></div>
                        <div id="cpf-exists-options" 
                             class="already-exists-options" 
                             style="display: none;">
                            <p class="info-text">CPF já cadastrado no sistema.</p>
                            <div class="action-buttons">
                                <button type="button" 
                                        class="mini-button login-button"
                                        aria-label="Ir para página de login">
                                    <i class="fas fa-sign-in-alt" aria-hidden="true"></i>
                                    Fazer Login
                                </button>
                                <button type="button" 
                                        class="mini-button forgot-password-button"
                                        aria-label="Ir para recuperação de senha">
                                    <i class="fas fa-key" aria-hidden="true"></i>
                                    Esqueci a Senha
                                </button>
                            </div>
                        </div>
                    </div>
                    
                    <div class="input-group">
                        <label for="email" class="required-field">
                            E-mail
                            <span class="required-indicator" aria-label="Campo obrigatório">*</span>
                        </label>
                        <div class="input-wrapper">
                            <input type="email" 
                                   id="email" 
                                   name="email" 
                                   placeholder="seu.email@exemplo.com" 
                                   required
                                   autocomplete="email"
                                   class="input"
                                   aria-describedby="email-error email-hint"
                                   maxlength="255">
                            <i class="validation-icon" aria-hidden="true"></i>
                        </div>
                        <div class="input-hint" id="email-hint">
                            Use um e-mail válido e ativo para receber confirmações
                        </div>
                        <div class="error-message-inline" 
                             id="email-error" 
                             role="alert" 
                             aria-live="polite"></div>
                        <div id="email-exists-options" 
                             class="already-exists-options" 
                             style="display: none;">
                            <p class="info-text">E-mail já cadastrado no sistema.</p>
                            <div class="action-buttons">
                                <button type="button" 
                                        class="mini-button login-button"
                                        aria-label="Ir para página de login">
                                    <i class="fas fa-sign-in-alt" aria-hidden="true"></i>
                                    Fazer Login
                                </button>
                                <button type="button" 
                                        class="mini-button forgot-password-button"
                                        aria-label="Ir para recuperação de senha">
                                    <i class="fas fa-key" aria-hidden="true"></i>
                                    Esqueci a Senha
                                </button>
                            </div>
                        </div>
                    </div>
                    
                    <div class="input-group">
                        <label for="celular" class="required-field">
                            Celular (WhatsApp)
                            <span class="required-indicator" aria-label="Campo obrigatório">*</span>
                        </label>
                        <div class="input-wrapper">
                            <input type="tel" 
                                   id="celular" 
                                   name="celular" 
                                   placeholder="(47) 99999-9999" 
                                   required 
                                   inputmode="tel"
                                   autocomplete="tel"
                                   class="input"
                                   aria-describedby="celular-error celular-hint"
                                   maxlength="18">
                            <i class="validation-icon" aria-hidden="true"></i>
                        </div>
                        <div class="input-hint" id="celular-hint">
                            Número do WhatsApp para contato sobre campanhas
                        </div>
                        <div class="error-message-inline" 
                             id="celular-error" 
                             role="alert" 
                             aria-live="polite"></div>
                    </div>
                </fieldset>

                <!-- === DADOS DA ÓTICA === -->
                <fieldset class="form-section">
                    <legend class="section-title">
                        <i class="fas fa-store" aria-hidden="true"></i>
                        Dados da sua Ótica
                    </legend>
                    
                    <div class="input-group">
                        <label for="cnpj" class="required-field">
                            CNPJ da Ótica
                            <span class="required-indicator" aria-label="Campo obrigatório">*</span>
                        </label>
                        <div class="input-wrapper">
                            <input type="text" 
                                   id="cnpj" 
                                   name="cnpj" 
                                   placeholder="00.000.000/0000-00" 
                                   required 
                                   inputmode="numeric"
                                   autocomplete="off"
                                   class="input"
                                   aria-describedby="cnpj-error cnpj-hint"
                                   maxlength="18"
                                   pattern="\d{2}\.\d{3}\.\d{3}/\d{4}-\d{2}">
                            <i class="validation-icon" aria-hidden="true"></i>
                        </div>
                        <div class="input-hint" id="cnpj-hint">
                            CNPJ da ótica onde você trabalha
                        </div>
                        <div class="error-message-inline" 
                             id="cnpj-error" 
                             role="alert" 
                             aria-live="polite"></div>
                    </div>
                    
                    <!-- === DADOS AUTOMÁTICOS DA ÓTICA === -->
                    <div id="otica-dados-wrapper" 
                         class="optical-data-section hidden"
                         aria-live="polite"
                         role="group"
                         aria-labelledby="optical-data-title">
                        
                        <h3 id="optical-data-title" class="optical-data-title">
                            <i class="fas fa-check-circle" aria-hidden="true"></i>
                            Dados da Ótica Encontrados
                        </h3>
                        
                        <div class="input-group">
                            <label for="razao_social">Razão Social</label>
                            <input type="text" 
                                   id="razao_social" 
                                   name="razao_social" 
                                   readonly 
                                   tabindex="-1"
                                   class="input readonly-input"
                                   aria-describedby="razao-social-hint">
                            <div class="input-hint" id="razao-social-hint">
                                Preenchido automaticamente
                            </div>
                        </div>
                        
                        <div class="input-group">
                            <label for="endereco_otica">Endereço</label>
                            <input type="text" 
                                   id="endereco_otica" 
                                   name="endereco_otica" 
                                   readonly 
                                   tabindex="-1"
                                   class="input readonly-input"
                                   aria-describedby="endereco-hint">
                            <div class="input-hint" id="endereco-hint">
                                Endereço cadastrado da ótica
                            </div>
                        </div>
                    </div>
                </fieldset>

                <!-- === SEGURANÇA === -->
                <fieldset class="form-section">
                    <legend class="section-title">
                        <i class="fas fa-shield-alt" aria-hidden="true"></i>
                        Segurança da Conta
                    </legend>
                    
                    <div class="input-group">
                        <label for="senha" class="required-field">
                            Crie sua Senha
                            <span class="required-indicator" aria-label="Campo obrigatório">*</span>
                        </label>
                        <div class="input-wrapper password-input-wrapper">
                            <input type="password" 
                                   id="senha" 
                                   name="senha" 
                                   placeholder="Crie uma senha forte" 
                                   required
                                   autocomplete="new-password"
                                   class="input"
                                   aria-describedby="senha-error password-strength-feedback senha-hint"
                                   minlength="8"
                                   maxlength="128">
                            <i class="validation-icon" aria-hidden="true"></i>
                            <button type="button" 
                                    id="toggle-password" 
                                    class="toggle-password" 
                                    aria-label="Mostrar/Ocultar senha"
                                    tabindex="0">
                                <i class="fas fa-eye" aria-hidden="true"></i>
                            </button>
                        </div>
                        <div class="input-hint" id="senha-hint">
                            A senha deve atender aos critérios de segurança abaixo
                        </div>
                        <div class="error-message-inline" 
                             id="senha-error" 
                             role="alert" 
                             aria-live="polite"></div>
                        
                        <!-- === INDICADOR DE FORÇA DA SENHA === -->
                        <div id="password-strength-feedback" 
                             class="password-rules"
                             role="group"
                             aria-labelledby="password-requirements-title">
                            <h4 id="password-requirements-title" class="sr-only">
                                Requisitos da senha
                            </h4>
                            <div class="password-strength-indicator" aria-hidden="true">
                                <div class="strength-bar"></div>
                                <span class="strength-text"></span>
                            </div>
                            <div class="requirements-list">
                                <span id="length" class="requirement" aria-live="polite">
                                    <i class="fas fa-times" aria-hidden="true"></i>
                                    <span class="requirement-text">8+ caracteres</span>
                                </span>
                                <span id="uppercase" class="requirement" aria-live="polite">
                                    <i class="fas fa-times" aria-hidden="true"></i>
                                    <span class="requirement-text">1 Letra Maiúscula</span>
                                </span>
                                <span id="lowercase" class="requirement" aria-live="polite">
                                    <i class="fas fa-times" aria-hidden="true"></i>
                                    <span class="requirement-text">1 Letra Minúscula</span>
                                </span>
                                <span id="number" class="requirement" aria-live="polite">
                                    <i class="fas fa-times" aria-hidden="true"></i>
                                    <span class="requirement-text">1 Número</span>
                                </span>
                                <span id="special" class="requirement" aria-live="polite">
                                    <i class="fas fa-times" aria-hidden="true"></i>
                                    <span class="requirement-text">1 Símbolo</span>
                                </span>
                            </div>
                        </div>
                    </div>
                    
                    <div class="input-group">
                        <label for="confirmar_senha" class="required-field">
                            Confirme sua Senha
                            <span class="required-indicator" aria-label="Campo obrigatório">*</span>
                        </label>
                        <div class="input-wrapper">
                            <input type="password" 
                                   id="confirmar_senha" 
                                   name="confirmar_senha" 
                                   placeholder="Digite a senha novamente" 
                                   required 
                                   disabled
                                   autocomplete="new-password"
                                   class="input"
                                   aria-describedby="confirmar-senha-error confirmar-senha-hint"
                                   minlength="8"
                                   maxlength="128">
                            <i class="validation-icon" aria-hidden="true"></i>
                        </div>
                        <div class="input-hint" id="confirmar-senha-hint">
                            Será habilitado após a senha atender todos os requisitos
                        </div>
                        <div class="error-message-inline" 
                             id="confirmar-senha-error" 
                             role="alert" 
                             aria-live="polite"></div>
                    </div>
                </fieldset>

                <!-- === TERMOS DE USO === -->
                <div class="checkbox-group" role="group" aria-labelledby="terms-title">
                    <input type="checkbox" 
                           id="termos" 
                           name="termos" 
                           required
                           class="checkbox-input"
                           aria-describedby="termos-error">
                    <label for="termos" class="checkbox-label">
                        <span class="checkbox-custom" aria-hidden="true"></span>
                        <span class="checkbox-text">
                            Li e aceito os 
                            <a href="/termos.php" 
                               target="_blank" 
                               rel="noopener noreferrer"
                               aria-label="Termos de Uso (abre em nova aba)">
                                Termos de Uso
                            </a> 
                            e a 
                            <a href="/privacidade.php" 
                               target="_blank" 
                               rel="noopener noreferrer"
                               aria-label="Política de Privacidade (abre em nova aba)">
                                Política de Privacidade
                            </a>.
                        </span>
                    </label>
                </div>
                <div class="error-message-inline" 
                     id="termos-error" 
                     role="alert" 
                     aria-live="polite"></div>

                <!-- === BOTÃO DE CADASTRO === -->
                <button type="submit" 
                        id="register-button" 
                        class="login-btn primary-gradient-btn" 
                        disabled
                        aria-describedby="button-hint">
                    <span class="btn-content">
                        <span class="btn-text">
                            <i class="fas fa-user-plus" aria-hidden="true"></i>
                            Criar Cadastro
                        </span>
                        <span class="btn-loading" style="display: none;" aria-hidden="true">
                            <i class="fas fa-spinner fa-spin" aria-hidden="true"></i>
                            Processando...
                        </span>
                    </span>
                </button>
                <div class="input-hint" id="button-hint">
                    Botão será habilitado quando todos os campos estiverem válidos
                </div>
            </form>

            <!-- === LINKS DE NAVEGAÇÃO === -->
            <nav class="login-links" aria-label="Links relacionados">
                <p>Já tem uma conta? 
                    <a href="/login.php" 
                       class="link-primary"
                       aria-label="Ir para página de login">
                        Acesse aqui
                    </a>
                </p>
                <div class="additional-links">
                    <a href="/suporte.php" 
                       class="link-secondary">
                        <i class="fas fa-question-circle" aria-hidden="true"></i>
                        Precisa de ajuda?
                    </a>
                    <a href="/sobre.php" 
                       class="link-secondary">
                        <i class="fas fa-info-circle" aria-hidden="true"></i>
                        Sobre o sistema
                    </a>
                </div>
            </nav>
        </main>

        <!-- === LOADING OVERLAY === -->
        <div id="loading-overlay" 
             class="loading-overlay" 
             aria-hidden="true"
             role="dialog"
             aria-modal="true"
             aria-labelledby="loading-title">
            <div class="loading-spinner">
                <div class="spinner-ring"></div>
                <h2 id="loading-title">Processando cadastro...</h2>
                <p>Aguarde enquanto validamos seus dados</p>
            </div>
        </div>
    </div>

    <!-- === CSS NÃO-CRÍTICO === -->
    <link rel="preload" href="/css/theme.css" as="style" onload="this.onload=null;this.rel='stylesheet'">
    <link rel="preload" href="/css/components.css" as="style" onload="this.onload=null;this.rel='stylesheet'">
    <link rel="preload" href="/css/animations.css" as="style" onload="this.onload=null;this.rel='stylesheet'">
    <link rel="preload" href="/css/login.css" as="style" onload="this.onload=null;this.rel='stylesheet'">
    <link rel="preload" href="/css/cadastro.css" as="style" onload="this.onload=null;this.rel='stylesheet'">
    
    <!-- === FALLBACK PARA CSS === -->
    <noscript>
        <link rel="stylesheet" href="/css/theme.css">
        <link rel="stylesheet" href="/css/components.css">
        <link rel="stylesheet" href="/css/animations.css">
        <link rel="stylesheet" href="/css/login.css">
        <link rel="stylesheet" href="/css/cadastro.css">
    </noscript>

    <!-- === FONT AWESOME === -->
    <link rel="preload" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.5.1/css/all.min.css" 
          as="style" 
          onload="this.onload=null;this.rel='stylesheet'" 
          crossorigin="anonymous" 
          referrerpolicy="no-referrer">

    <!-- === JAVASCRIPT PRINCIPAL === -->
    <script src="/js/cadastro.js" defer nonce="<?php echo $nonce; ?>"></script>

    <!-- === ANALYTICS E MONITORAMENTO === -->
    <?php if ($isProduction): ?>
    <script nonce="<?php echo $nonce; ?>">
        // Google Analytics ou outro sistema de analytics
        window.dataLayer = window.dataLayer || [];
        function gtag(){dataLayer.push(arguments);}
        gtag('js', new Date());
        gtag('config', 'GA_MEASUREMENT_ID', {
            page_title: 'Cadastro de Vendedor',
            page_location: window.location.href,
            content_group1: 'Registration'
        });
    </script>
    <?php endif; ?>

    <!-- === DESENVOLVIMENTO === -->
    <?php if ($isDevelopment): ?>
    <script nonce="<?php echo $nonce; ?>">
        console.log('🔧 Modo de desenvolvimento ativo');
        console.log('📊 Configurações:', window.REGISTRATION_CONFIG);
        
        // Hot reload para desenvolvimento (se disponível)
        if (typeof EventSource !== 'undefined') {
            const eventSource = new EventSource('/dev/hot-reload');
            eventSource.onmessage = function(event) {
                if (event.data === 'reload') {
                    console.log('🔄 Recarregando página...');
                    window.location.reload();
                }
            };
        }
    </script>
    <?php endif; ?>

    <!-- === PERFORMANCE MONITORING === -->
    <script nonce="<?php echo $nonce; ?>">
        // Web Vitals monitoring
        if ('performance' in window) {
            window.addEventListener('load', () => {
                // Marca fim do carregamento
                performance.mark('registration-page-loaded');
                
                // Medida do tempo total de carregamento
                performance.measure(
                    'registration-page-load-time',
                    'registration-page-start',
                    'registration-page-loaded'
                );
                
                // Log em desenvolvimento
                <?php if ($isDevelopment): ?>
                const loadMeasure = performance.getEntriesByName('registration-page-load-time')[0];
                if (loadMeasure) {
                    console.log(`⏱️ Tempo de carregamento: ${Math.round(loadMeasure.duration)}ms`);
                }
                <?php endif; ?>
            });
        }
        
        // Service Worker registration (apenas em produção com HTTPS)
        if ('serviceWorker' in navigator && 
            window.location.protocol === 'https:' && 
            '<?php echo ENVIRONMENT; ?>' === 'production') {
            
            window.addEventListener('load', async () => {
                try {
                    const registration = await navigator.serviceWorker.register('/sw.js', {
                        scope: '/'
                    });
                    console.log('📱 Service Worker registrado:', registration.scope);
                } catch (error) {
                    console.warn('Service Worker registration failed:', error);
                }
            });
        }
    </script>
</body>
</html>
                <?php
declare(strict_types=1);
/**
 * ==============================================================================
 * INTERFACE DE CADASTRO PREMIUM (Premium Registration Interface) - v3.1
 * ==============================================================================
 *
 * Localização: /public/cadastro.php
 *
 * Aprimoramentos v3.1:
 * - Meta tags otimizadas para SEO e performance
 * - Progressive Web App (PWA) ready
 * - Acessibilidade WCAG 2.1 AAA
 * - Schema.org structured data
 * - Critical CSS inline
 * - Resource hints otimizados
 * - Security headers avançados
 * - Performance budgets
 */

// === INICIALIZAÇÃO SEGURA ===
define('APP_INITIATED', true);
define('APP_ROOT', dirname(__DIR__));

// === HEADERS DE SEGURANÇA PREMIUM ===
$securityHeaders = [
    'X-Content-Type-Options' => 'nosniff',
    'X-Frame-Options' => 'DENY',
    'Referrer-Policy' => 'strict-origin-when-cross-origin',
    'X-XSS-Protection' => '1; mode=block',
    'X-Permitted-Cross-Domain-Policies' => 'none',
    'Cache-Control' => 'no-store, no-cache, must-revalidate, max-age=0',
    'Pragma' => 'no-cache',
    'Expires' => '0',
    'Permissions-Policy' => 'geolocation=(), microphone=(), camera=(), payment=(), usb=()',
];

foreach ($securityHeaders as $header => $value) {
    header("{$header}: {$value}");
}

// === CARREGAMENTO DO SISTEMA ===
require_once APP_ROOT . '/app/config/config.php';

// === LÓGICA DE REDIRECIONAMENTO ===
if (isset($_SESSION['user_id'])) {
    $redirectUrl = getRedirectUrlForUser($_SESSION['user_tipo'] ?? 'vendedor');
    header("Location: " . $redirectUrl);
    exit;
}

// === GERAÇÃO DE TOKENS DE SEGURANÇA ===
if (empty($_SESSION['csrf_token'])) {
    $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
}

if (empty($_SESSION['csp_nonce'])) {
    $_SESSION['csp_nonce'] = base64_encode(random_bytes(16));
}

$csrf = htmlspecialchars($_SESSION['csrf_token'], ENT_QUOTES, 'UTF-8');
$nonce = htmlspecialchars($_SESSION['csp_nonce'], ENT_QUOTES, 'UTF-8');

// === CSP OTIMIZADA ===
$cspPolicies = [
    "default-src 'self'",
    "base-uri 'self'",
    "frame-ancestors 'none'",
    "form-action 'self'",
    "img-src 'self' data: blob:",
    "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com https://cdnjs.cloudflare.com",
    "font-src 'self' https://fonts.gstatic.com https://cdnjs.cloudflare.com",
    "script-src 'self' 'nonce-{$nonce}'" . (ENVIRONMENT === 'development' ? " 'unsafe-eval' 'unsafe-inline'" : ""),
    "connect-src 'self'",
    "object-src 'none'",
    "media-src 'self'",
    "worker-src 'self'"
];

header('Content-Security-Policy: ' . implode('; ', $cspPolicies));

// === CONFIGURAÇÕES DINÂMICAS ===
$isProduction = ENVIRONMENT === 'production';
$isDevelopment = ENVIRONMENT === 'development';
$appVersion = APP_VERSION ?? '3.1.0';
$currentYear = date('Y');

// === RESOURCE HINTS ===
$resourceHints = [
    'preconnect' => [
        'https://fonts.googleapis.com',
        'https://fonts.gstatic.com',
        'https://cdnjs.cloudflare.com'
    ],
    'dns-prefetch' => [
        '//fonts.googleapis.com',
        '//fonts.gstatic.com',
        '//cdnjs.cloudflare.com'
    ],
    'preload' => [
        [
            'href' => 'https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&display=swap',
            'as' => 'style',
            'onload' => "this.onload=null;this.rel='stylesheet'"
        ],
        [
            'href' => '/css/critical.css',
            'as' => 'style'
        ]
    ]
];

?>
<!DOCTYPE html>
<html lang="pt-BR" class="no-js">
<head>
    <!-- === META ESSENCIAIS === -->
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0, viewport-fit=cover">
    <meta http-equiv="X-UA-Compatible" content="IE=edge">
    
    <!-- === SEO & METADATA === -->
    <title>Cadastro de Vendedor - Sistema Campanhas Embrapol Sul</title>
    <meta name="description" content="Cadastre-se gratuitamente como vendedor no sistema de campanhas promocionais da Embrapol Sul. Processo rápido, seguro e 100% online.">
    <meta name="keywords" content="cadastro vendedor, embrapol sul, campanhas promocionais, registro vendas">
    <meta name="author" content="Embrapol Sul">
    <meta name="robots" content="noindex, nofollow">
    <meta name="format-detection" content="telephone=no">
    
    <!-- === OPEN GRAPH === -->
    <meta property="og:title" content="Cadastro de Vendedor - Embrapol Sul">
    <meta property="og:description" content="Sistema de cadastro para vendedores das campanhas promocionais Embrapol Sul">
    <meta property="og:type" content="website">
    <meta property="og:url" content="<?php echo APP_URL; ?>/cadastro.php">
    <meta property="og:site_name" content="Sistema Campanhas Embrapol Sul">
    <meta property="og:locale" content="pt_BR">
    
    <!-- === TWITTER CARD === -->
    <meta name="twitter:card" content="summary">
    <meta name="twitter:title" content="Cadastro de Vendedor - Embrapol Sul">
    <meta name="twitter:description" content="Sistema de cadastro seguro para vendedores">
    
    <!-- === THEME & APPEARANCE === -->
    <meta name="theme-color" content="#667eea">
    <meta name="color-scheme" content="light dark">
    <meta name="msapplication-navbutton-color" content="#667eea">
    <meta name="apple-mobile-web-app-status-bar-style" content="default">
    <meta name="apple-mobile-web-app-capable" content="yes">
    <meta name="apple-mobile-web-app-title" content="Cadastro EPS">
    
    <!-- === RESOURCE HINTS === -->
    <?php foreach ($resourceHints['preconnect'] as $url): ?>
    <link rel="preconnect" href="<?php echo $url; ?>" crossorigin>
    <?php endforeach; ?>
    
    <?php foreach ($resourceHints['dns-prefetch'] as $url): ?>
    <link rel="dns-prefetch" href="<?php echo $url; ?>">
    <?php endforeach; ?>
    
    <?php foreach ($resourceHints['preload'] as $resource): ?>
    <link rel="preload" href="<?php echo $resource['href']; ?>" as="<?php echo $resource['as']; ?>"<?php 
        if (isset($resource['onload'])): ?> onload="<?php echo $resource['onload']; ?>"<?php endif; ?>>
    <?php endforeach; ?>
    
    <!-- === CRITICAL CSS INLINE === -->
    <style nonce="<?php echo $nonce; ?>">
        /* Critical CSS para First Paint otimizado */
        :root {
            --primary: #667eea;
            --primary-dark: #5a6fd8;
            --primary-light: #7c8df0;
            --bg-primary: #0f0f23;
            --bg-secondary: #1a1a2e;
            --bg-glass: rgba(255, 255, 255, 0.08);
            --text-primary: #f5f5f7;
            --text-secondary: rgba(245, 245, 247, 0.8);
            --border-glass: rgba(255, 255, 255, 0.12);
            --shadow-card: 0 8px 32px rgba(0, 0, 0, 0.3);
            --transition: all 0.3s cubic-bezier(0.4, 0, 0.2, 1);
        }
        
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }
        
        html.no-js .js-only { display: none !important; }
        html.js .no-js-only { display: none !important; }
        
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif;
            background: linear-gradient(135deg, var(--bg-primary) 0%, var(--bg-secondary) 100%);
            color: var(--text-primary);
            min-height: 100vh;
            overflow-x: hidden;
            line-height: 1.5;
            -webkit-font-smoothing: antialiased;
            -moz-osx-font-smoothing: grayscale;
        }
        
        .login-page-container {
            min-height: 100vh;
            display: flex;
            align-items: center;
            justify-content: center;
            padding: 20px;
            position: relative;
        }
        
        .register-card {
            background: var(--bg-glass);
            backdrop-filter: blur