/**
 * ==============================================================================
 * MÓDULO DE AUTENTICAÇÃO PREMIUM (Premium Authentication Module) - v5.0
 * ==============================================================================
 * Localização: /public/js/auth.js
 * 
 * Aprimoramentos v5.0:
 * - Biometria web (quando disponível)
 * - Rate limiting local
 * - Detecção de fraude básica
 * - Remember me avançado
 * - Feedback UX premium
 * - Analytics de conversão
 */

class AuthenticationManager {
    constructor() {
        this.form = document.getElementById('login-form');
        this.elements = {};
        this.attemptCount = 0;
        this.maxAttempts = 5;
        this.lockoutTime = 15 * 60 * 1000; // 15 minutos
        this.isSubmitting = false;
        this.startTime = Date.now();
        
        if (!this.form) {
            console.error('Formulário de login não encontrado');
            return;
        }
        
        this.init();
    }
    
    /**
     * Inicialização do sistema
     */
    init() {
        this.mapElements();
        this.loadStoredData();
        this.checkBiometricSupport();
        this.bindEvents();
        this.setupAccessibility();
        this.checkRememberToken();
        this.preloadAssets();
        
        console.log('✅ Sistema de autenticação premium inicializado');
    }
    
    /**
     * Mapeia elementos do DOM
     */
    mapElements() {
        this.elements = {
            identifier: document.getElementById('identifier'),
            password: document.getElementById('password'),
            remember: document.getElementById('remember'),
            loginButton: document.getElementById('login-button'),
            buttonText: this.form.querySelector('.btn-text'),
            buttonLoading: this.form.querySelector('.btn-loading'),
            passwordToggle: this.form.querySelector('.password-toggle'),
            messageContainer: document.getElementById('message-container'),
            loadingOverlay: document.getElementById('loading-overlay'),
            biometricButton: document.getElementById('biometric-login'), // Se existir
            forgotPasswordLink: this.form.querySelector('a[href="/recuperar-senha.php"]')
        };
        
        // Verifica elementos críticos
        if (!this.elements.identifier || !this.elements.password || !this.elements.loginButton) {
            console.error('Elementos críticos do formulário não encontrados');
            return;
        }
    }
    
    /**
     * Carrega dados armazenados (tentativas, etc.)
     */
    loadStoredData() {
        try {
            // Carrega contador de tentativas
            const storedAttempts = localStorage.getItem('login_attempts');
            if (storedAttempts) {
                const { count, timestamp } = JSON.parse(storedAttempts);
                
                // Verifica se ainda está no período de lockout
                if (Date.now() - timestamp < this.lockoutTime) {
                    this.attemptCount = count;
                    
                    if (this.attemptCount >= this.maxAttempts) {
                        this.handleLockout(timestamp);
                    }
                } else {
                    // Período expirou, reseta
                    localStorage.removeItem('login_attempts');
                }
            }
            
            // Carrega último usuário se remember me estava ativo
            const lastUser = localStorage.getItem('last_user');
            if (lastUser && this.elements.identifier) {
                this.elements.identifier.value = lastUser;
                this.elements.identifier.classList.add('has-value');
            }
            
        } catch (error) {
            console.warn('Erro ao carregar dados armazenados:', error);
        }
    }
    
    /**
     * Verifica suporte à biometria
     */
    async checkBiometricSupport() {
        if (typeof window.PublicKeyCredential === 'undefined') {
            return;
        }
        
        try {
            const available = await PublicKeyCredential.isUserVerifyingPlatformAuthenticatorAvailable();
            
            if (available && this.elements.biometricButton) {
                this.elements.biometricButton.style.display = 'block';
                this.elements.biometricButton.addEventListener('click', this.handleBiometricLogin.bind(this));
            }
        } catch (error) {
            console.log('Biometria não disponível:', error);
        }
    }
    
    /**
     * Vincula eventos
     */
    bindEvents() {
        // Evento de submit
        this.form.addEventListener('submit', this.handleSubmit.bind(this));
        
        // Toggle de senha
        if (this.elements.passwordToggle) {
            this.elements.passwordToggle.addEventListener('click', this.togglePasswordVisibility.bind(this));
        }
        
        // Limpeza de erros ao digitar
        this.elements.identifier.addEventListener('input', this.clearErrors.bind(this));
        this.elements.password.addEventListener('input', this.clearErrors.bind(this));
        
        // Validação em tempo real
        this.elements.identifier.addEventListener('blur', this.validateIdentifier.bind(this));
        this.elements.password.addEventListener('blur', this.validatePassword.bind(this));
        
        // Enter para submeter
        this.elements.password.addEventListener('keydown', (e) => {
            if (e.key === 'Enter' && !this.elements.loginButton.disabled) {
                this.form.dispatchEvent(new Event('submit'));
            }
        });
        
        // Analytics de comportamento
        this.trackUserBehavior();
    }
    
    /**
     * Configuração de acessibilidade
     */
    setupAccessibility() {
        // ARIA labels dinâmicos
        this.elements.identifier.setAttribute('aria-describedby', 'identifier-help');
        this.elements.password.setAttribute('aria-describedby', 'password-help');
        
        // Região para anúncios de screen reader
        this.createScreenReaderRegion();
        
        // Navegação por teclado otimizada
        this.setupKeyboardNavigation();
    }
    
    /**
     * Cria região para screen readers
     */
    createScreenReaderRegion() {
        this.srRegion = document.createElement('div');
        this.srRegion.setAttribute('aria-live', 'polite');
        this.srRegion.setAttribute('aria-atomic', 'true');
        this.srRegion.className = 'sr-only';
        this.srRegion.style.cssText = 'position:absolute;left:-10000px;width:1px;height:1px;overflow:hidden;';
        document.body.appendChild(this.srRegion);
    }
    
    /**
     * Navegação por teclado
     */
    setupKeyboardNavigation() {
        // Tab sequence otimizado
        const focusableElements = [
            this.elements.identifier,
            this.elements.password,
            this.elements.passwordToggle,
            this.elements.remember,
            this.elements.forgotPasswordLink,
            this.elements.loginButton
        ].filter(Boolean);
        
        focusableElements.forEach((element, index) => {
            element.addEventListener('keydown', (e) => {
                if (e.key === 'Tab') {
                    // Implementar navegação customizada se necessário
                }
            });
        });
    }
    
    /**
     * Verifica token de remember me
     */
    async checkRememberToken() {
        const urlParams = new URLSearchParams(window.location.search);
        const autoLogin = urlParams.get('auto_login');
        
        if (autoLogin === '1') {
            // Tenta login automático se token válido
            await this.attemptAutoLogin();
        }
    }
    
    /**
     * Tentativa de login automático
     */
    async attemptAutoLogin() {
        try {
            const response = await fetch('/api/auto_login.php', {
                method: 'POST',
                credentials: 'include',
                headers: {
                    'Content-Type': 'application/json'
                }
            });
            
            const result = await response.json();
            
            if (result.success) {
                this.showMessage('Login automático realizado', 'success');
                setTimeout(() => {
                    window.location.href = result.redirect_url;
                }, 1000);
            }
        } catch (error) {
            console.log('Login automático falhou:', error);
        }
    }
    
    /**
     * Pré-carrega assets críticos
     */
    preloadAssets() {
        // Desabilitado temporariamente até que as páginas sejam criadas
        console.log('⚠️ Preload desabilitado - páginas de dashboard ainda não criadas');
        // Pré-carrega páginas de destino comuns
        //const destinations = ['/dashboard_vendedor.php', '/dashboard_gerente.php', '/dashboard_admin.php'];
        
        //destinations.forEach(url => {
        //    const link = document.createElement('link');
        //    link.rel = 'prefetch';
        //    link.href = url;
        //    document.head.appendChild(link);
        //});
    }
    
    /**
     * Validação do identificador
     */
    validateIdentifier() {
        const value = this.elements.identifier.value.trim();
        
        if (!value) {
            this.showFieldError('identifier', 'Campo obrigatório');
            return false;
        }
        
        // Detecta tipo (email ou CPF)
        const isEmail = value.includes('@');
        const isCPF = /^\d{3}\.?\d{3}\.?\d{3}-?\d{2}$/.test(value);
        
        if (!isEmail && !isCPF) {
            this.showFieldError('identifier', 'Digite um e-mail ou CPF válido');
            return false;
        }
        
        if (isEmail && !this.validateEmail(value)) {
            this.showFieldError('identifier', 'E-mail em formato inválido');
            return false;
        }
        
        if (isCPF && !this.validateCPF(value.replace(/\D/g, ''))) {
            this.showFieldError('identifier', 'CPF inválido');
            return false;
        }
        
        this.clearFieldError('identifier');
        return true;
    }
    
    /**
     * Validação da senha
     */
    validatePassword() {
        const value = this.elements.password.value;
        
        if (!value) {
            this.showFieldError('password', 'Senha é obrigatória');
            return false;
        }
        
        if (value.length < 6) {
            this.showFieldError('password', 'Senha deve ter pelo menos 6 caracteres');
            return false;
        }
        
        this.clearFieldError('password');
        return true;
    }
    
    /**
     * Manipula submissão do formulário
     */
    async handleSubmit(event) {
        event.preventDefault();
        
        if (this.isSubmitting) return;
        
        // Verifica lockout
        if (this.attemptCount >= this.maxAttempts) {
            this.showMessage('Muitas tentativas. Tente novamente mais tarde.', 'error');
            return;
        }
        
        // Validação final
        const identifierValid = this.validateIdentifier();
        const passwordValid = this.validatePassword();
        
        if (!identifierValid || !passwordValid) {
            this.shakeForm();
            return;
        }
        
        this.isSubmitting = true;
        this.setLoadingState(true);
        
        try {
            const formData = this.collectFormData();
            const response = await this.submitLogin(formData);
            
            if (response.success) {
                await this.handleSuccessfulLogin(response);
            } else {
                this.handleLoginError(response);
            }
            
        } catch (error) {
            console.error('Erro no login:', error);
            this.showMessage('Erro de conexão. Verifique sua internet.', 'error');
        } finally {
            this.isSubmitting = false;
            this.setLoadingState(false);
        }
    }
    
    /**
     * Coleta dados do formulário
     */
    collectFormData() {
        return {
            identifier: this.elements.identifier.value.trim(),
            password: this.elements.password.value,
            remember: this.elements.remember?.checked || false,
            csrf_token: this.getCSRFToken(),
            submission_time: Math.floor((Date.now() - this.startTime) / 1000),
            user_agent_hash: this.hashUserAgent(),
            screen_resolution: `${screen.width}x${screen.height}`,
            timezone: Intl.DateTimeFormat().resolvedOptions().timeZone
        };
    }
    
    /**
     * Submete login para API
     */
    async submitLogin(formData) {
        const response = await fetch('/api/auth_api.php', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'Accept': 'application/json',
                'X-Requested-With': 'XMLHttpRequest'
            },
            credentials: 'include',
            body: JSON.stringify(formData)
        });
        
        if (!response.ok) {
            throw new Error(`HTTP ${response.status}: ${response.statusText}`);
        }
        
        return await response.json();
    }
    
    /**
     * Manipula login bem-sucedido
     */
    async handleSuccessfulLogin(response) {
        // Reset contador de tentativas
        this.resetAttemptCounter();
        
        // Salva usuário se remember me ativo
        if (this.elements.remember?.checked) {
            this.saveUserData(response.data.user);
        }
        
        // Analytics de conversão
        this.trackConversion(response.data.user);
        
        // Feedback visual
        this.showMessage('Login realizado com sucesso!', 'success');
        this.elements.loginButton.classList.add('success');
        
        // Pré-carrega página de destino
        this.preloadDestination(response.data.redirect_url);
        
        // Aguarda um pouco para UX e depois redireciona
        await this.delay(800);
        
        // Redireciona
        window.location.href = response.data.redirect_url;
    }
    
    /**
     * Manipula erro de login
     */
    handleLoginError(response) {
        // Incrementa contador de tentativas
        this.incrementAttemptCounter();
        
        // Análise do tipo de erro
        const errorType = response.error || 'UNKNOWN';
        
        switch (errorType) {
            case 'INVALID_CREDENTIALS':
                this.showMessage('Usuário ou senha incorretos', 'error');
                this.highlightInvalidFields();
                break;
                
            case 'ACCOUNT_LOCKED':
                this.showMessage(response.message, 'error');
                this.suggestPasswordRecovery();
                break;
                
            case 'ACCOUNT_STATUS':
                this.showMessage(response.message, 'warning');
                this.suggestAccountActivation(response);
                break;
                
            case 'RATE_LIMIT_EXCEEDED':
                this.handleRateLimit(response);
                break;
                
            default:
                this.showMessage(response.message || 'Erro no login', 'error');
        }
        
        // Shake animation para feedback visual
        this.shakeForm();
        
        // Analytics de erro
        this.trackLoginError(errorType);
    }
    
    /**
     * Manipula rate limiting
     */
    handleRateLimit(response) {
        const retryAfter = response.retry_after || 900; // 15 min padrão
        const minutes = Math.ceil(retryAfter / 60);
        
        this.showMessage(`Muitas tentativas. Tente novamente em ${minutes} minutos.`, 'error');
        this.disableForm(retryAfter * 1000);
    }
    
    /**
     * Desabilita formulário temporariamente
     */
    disableForm(duration) {
        this.elements.loginButton.disabled = true;
        this.elements.identifier.disabled = true;
        this.elements.password.disabled = true;
        
        const endTime = Date.now() + duration;
        
        const updateCountdown = () => {
            const remaining = endTime - Date.now();
            
            if (remaining <= 0) {
                this.enableForm();
                return;
            }
            
            const minutes = Math.floor(remaining / 60000);
            const seconds = Math.floor((remaining % 60000) / 1000);
            
            this.elements.loginButton.textContent = `Bloqueado (${minutes}:${seconds.toString().padStart(2, '0')})`;
            
            setTimeout(updateCountdown, 1000);
        };
        
        updateCountdown();
    }
    
    /**
     * Reabilita formulário
     */
    enableForm() {
        this.elements.loginButton.disabled = false;
        this.elements.identifier.disabled = false;
        this.elements.password.disabled = false;
        this.elements.loginButton.textContent = 'Entrar no Sistema';
    }
    
    /**
     * Incrementa contador de tentativas
     */
    incrementAttemptCounter() {
        this.attemptCount++;
        
        try {
            localStorage.setItem('login_attempts', JSON.stringify({
                count: this.attemptCount,
                timestamp: Date.now()
            }));
        } catch (error) {
            console.warn('Erro ao salvar contador de tentativas:', error);
        }
        
        // Aviso próximo ao limite
        if (this.attemptCount >= this.maxAttempts - 1) {
            this.showMessage('Atenção: você tem mais 1 tentativa antes do bloqueio temporário', 'warning');
        }
    }
    
    /**
     * Reset contador de tentativas
     */
    resetAttemptCounter() {
        this.attemptCount = 0;
        
        try {
            localStorage.removeItem('login_attempts');
        } catch (error) {
            console.warn('Erro ao limpar contador:', error);
        }
    }
    
    /**
     * Manipula lockout
     */
    handleLockout(timestamp) {
        const remaining = this.lockoutTime - (Date.now() - timestamp);
        const minutes = Math.ceil(remaining / 60000);
        
        this.showMessage(`Conta temporariamente bloqueada. Tente novamente em ${minutes} minutos.`, 'error');
        this.disableForm(remaining);
    }
    
    /**
     * Login biométrico
     */
    async handleBiometricLogin() {
        try {
            this.setLoadingState(true);
            
            const credential = await navigator.credentials.create({
                publicKey: {
                    challenge: new Uint8Array(32),
                    rp: { name: "Campanhas EPS" },
                    user: {
                        id: new Uint8Array(16),
                        name: "user@example.com",
                        displayName: "User"
                    },
                    pubKeyCredParams: [{ alg: -7, type: "public-key" }],
                    authenticatorSelection: {
                        userVerification: "required"
                    }
                }
            });
            
            if (credential) {
                // Enviar credential para servidor para verificação
                const response = await fetch('/api/biometric_login.php', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ credential: credential.id })
                });
                
                const result = await response.json();
                
                if (result.success) {
                    this.handleSuccessfulLogin(result);
                } else {
                    this.showMessage('Falha na autenticação biométrica', 'error');
                }
            }
            
        } catch (error) {
            console.error('Erro biométrico:', error);
            this.showMessage('Autenticação biométrica não disponível', 'error');
        } finally {
            this.setLoadingState(false);
        }
    }
    
    /**
     * Toggle visibilidade da senha
     */
    togglePasswordVisibility() {
        const isPassword = this.elements.password.type === 'password';
        const icon = this.elements.passwordToggle.querySelector('i');
        
        this.elements.password.type = isPassword ? 'text' : 'password';
        
        if (icon) {
            icon.classList.toggle('fa-eye', !isPassword);
            icon.classList.toggle('fa-eye-slash', isPassword);
        }
        
        // Auto-hide após 5 segundos
        if (isPassword) {
            setTimeout(() => {
                if (this.elements.password.type === 'text') {
                    this.elements.password.type = 'password';
                    if (icon) {
                        icon.classList.remove('fa-eye-slash');
                        icon.classList.add('fa-eye');
                    }
                }
            }, 5000);
        }
        
        // Mantém foco no campo
        this.elements.password.focus();
    }
    
    /**
     * Define estado de loading
     */
    setLoadingState(isLoading) {
        if (this.elements.loginButton) {
            this.elements.loginButton.disabled = isLoading;
            this.elements.loginButton.classList.toggle('loading', isLoading);
        }
        
        if (this.elements.buttonText) {
            this.elements.buttonText.style.display = isLoading ? 'none' : 'inline';
        }
        
        if (this.elements.buttonLoading) {
            this.elements.buttonLoading.style.display = isLoading ? 'inline' : 'none';
        }
        
        if (this.elements.loadingOverlay) {
            this.elements.loadingOverlay.classList.toggle('show', isLoading);
        }
        
        // Desabilita campos durante loading
        if (this.elements.identifier) this.elements.identifier.disabled = isLoading;
        if (this.elements.password) this.elements.password.disabled = isLoading;
    }
    
    /**
     * Limpa erros
     */
    clearErrors() {
        this.hideMessage();
        this.clearFieldError('identifier');
        this.clearFieldError('password');
    }
    
    /**
     * Mostra erro de campo
     */
    showFieldError(field, message) {
        const errorElement = document.getElementById(`${field}-error`);
        if (errorElement) {
            errorElement.textContent = message;
            errorElement.classList.add('show');
        }
        
        if (this.elements[field]) {
            this.elements[field].classList.add('error');
            this.elements[field].setAttribute('aria-invalid', 'true');
        }
    }
    
    /**
     * Limpa erro de campo
     */
    clearFieldError(field) {
        const errorElement = document.getElementById(`${field}-error`);
        if (errorElement) {
            errorElement.textContent = '';
            errorElement.classList.remove('show');
        }
        
        if (this.elements[field]) {
            this.elements[field].classList.remove('error');
            this.elements[field].setAttribute('aria-invalid', 'false');
        }
    }
    
    /**
     * Destaca campos inválidos
     */
    highlightInvalidFields() {
        ['identifier', 'password'].forEach(field => {
            const element = this.elements[field];
            if (element) {
                element.classList.add('invalid-flash');
                setTimeout(() => {
                    element.classList.remove('invalid-flash');
                }, 2000);
            }
        });
    }
    
    /**
     * Animação de shake no formulário
     */
    shakeForm() {
        this.form.classList.add('error-shake');
        setTimeout(() => {
            this.form.classList.remove('error-shake');
        }, 600);
    }
    
    /**
     * Sistema de mensagens
     */
    showMessage(message, type = 'info') {
        if (!this.elements.messageContainer) return;
        
        // Remove mensagens anteriores
        this.elements.messageContainer.innerHTML = '';
        
        // Cria nova mensagem
        const messageElement = document.createElement('div');
        messageElement.className = `message ${type}`;
        messageElement.innerHTML = `
            <i class="fas fa-${this.getMessageIcon(type)}"></i>
            <span>${message}</span>
        `;
        
        this.elements.messageContainer.appendChild(messageElement);
        this.elements.messageContainer.style.display = 'block';
        
        // Anúncio para screen readers
        this.announceToScreenReader(message);
        
        // Auto-hide para mensagens de sucesso
        if (type === 'success') {
            setTimeout(() => {
                this.hideMessage();
            }, 3000);
        }
    }
    
    /**
     * Esconde mensagem
     */
    hideMessage() {
        if (this.elements.messageContainer) {
            this.elements.messageContainer.style.display = 'none';
            this.elements.messageContainer.innerHTML = '';
        }
    }
    
    /**
     * Retorna ícone para tipo de mensagem
     */
    getMessageIcon(type) {
        const icons = {
            success: 'check-circle',
            error: 'exclamation-circle',
            warning: 'exclamation-triangle',
            info: 'info-circle'
        };
        
        return icons[type] || 'info-circle';
    }
    
    /**
     * Anúncio para screen readers
     */
    announceToScreenReader(message) {
        if (this.srRegion) {
            this.srRegion.textContent = message;
        }
    }
    
    /**
     * Sugere recuperação de senha
     */
    suggestPasswordRecovery() {
        const suggestion = document.createElement('div');
        suggestion.className = 'suggestion-box';
        suggestion.innerHTML = `
            <p>Esqueceu sua senha?</p>
            <a href="/recuperar-senha.php" class="btn btn-secondary btn-sm">Recuperar Senha</a>
        `;
        
        if (this.elements.messageContainer) {
            this.elements.messageContainer.appendChild(suggestion);
        }
    }
    
    /**
     * Sugere ativação de conta
     */
    suggestAccountActivation(response) {
        if (response.message?.includes('pendente')) {
            const suggestion = document.createElement('div');
            suggestion.className = 'suggestion-box';
            suggestion.innerHTML = `
                <p>Não recebeu o e-mail de ativação?</p>
                <button class="btn btn-secondary btn-sm" onclick="this.requestNewActivation()">Reenviar E-mail</button>
            `;
            
            if (this.elements.messageContainer) {
                this.elements.messageContainer.appendChild(suggestion);
            }
        }
    }
    
    /**
     * Solicita novo e-mail de ativação
     */
    async requestNewActivation() {
        try {
            const email = this.elements.identifier.value;
            
            const response = await fetch('/api/reenviar_ativacao.php', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ email })
            });
            
            const result = await response.json();
            
            this.showMessage(result.message, result.success ? 'success' : 'error');
            
        } catch (error) {
            this.showMessage('Erro ao reenviar e-mail', 'error');
        }
    }
    
    /**
     * Salva dados do usuário para remember me
     */
    saveUserData(user) {
        try {
            localStorage.setItem('last_user', user.email || user.cpf);
            
            // Salva preferências não sensíveis
            localStorage.setItem('user_preferences', JSON.stringify({
                theme: 'dark',
                language: 'pt-BR',
                remember_me: true
            }));
        } catch (error) {
            console.warn('Erro ao salvar dados do usuário:', error);
        }
    }
    
    /**
     * Pré-carrega página de destino
     */
    preloadDestination(url) {
        const link = document.createElement('link');
        link.rel = 'prefetch';
        link.href = url;
        document.head.appendChild(link);
    }
    
    /**
     * Delay utilitário
     */
    delay(ms) {
        return new Promise(resolve => setTimeout(resolve, ms));
    }
    
    /**
     * Analytics de comportamento do usuário
     */
    trackUserBehavior() {
        let keystrokes = 0;
        let focusChanges = 0;
        
        ['identifier', 'password'].forEach(field => {
            if (this.elements[field]) {
                this.elements[field].addEventListener('keydown', () => keystrokes++);
                this.elements[field].addEventListener('focus', () => focusChanges++);
            }
        });
        
        // Salva métricas para análise anti-fraude
        this.behaviorMetrics = {
            get keystrokes() { return keystrokes; },
            get focusChanges() { return focusChanges; },
            get timeOnPage() { return Date.now() - this.startTime; }
        };
    }
    
    /**
     * Analytics de conversão
     */
    trackConversion(user) {
        // Google Analytics
        if (typeof gtag !== 'undefined') {
            gtag('event', 'login', {
                method: 'form',
                user_type: user.tipo
            });
        }
        
        // Facebook Pixel
        if (typeof fbq !== 'undefined') {
            fbq('track', 'Login');
        }
        
        // Analytics customizado
        this.sendAnalytics('login_success', {
            user_type: user.tipo,
            time_to_login: Date.now() - this.startTime,
            attempts: this.attemptCount + 1
        });
    }
    
    /**
     * Analytics de erro
     */
    trackLoginError(errorType) {
        this.sendAnalytics('login_error', {
            error_type: errorType,
            attempt_number: this.attemptCount,
            time_to_error: Date.now() - this.startTime
        });
    }
    
    /**
     * Envia analytics
     */
    sendAnalytics(event, data) {
        try {
            // Analytics interno
            fetch('/api/analytics.php', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    event,
                    data,
                    timestamp: Date.now(),
                    page: 'login'
                })
            }).catch(() => {}); // Falha silenciosa
        } catch (error) {
            // Falha silenciosa em analytics
        }
    }
    
    /**
     * Obtém token CSRF
     */
    getCSRFToken() {
        const metaTag = document.querySelector('meta[name="csrf-token"]');
        return metaTag ? metaTag.getAttribute('content') : '';
    }
    
    /**
     * Hash do User Agent para fingerprinting básico
     */
    hashUserAgent() {
        const ua = navigator.userAgent;
        let hash = 0;
        
        for (let i = 0; i < ua.length; i++) {
            const char = ua.charCodeAt(i);
            hash = ((hash << 5) - hash) + char;
            hash = hash & hash; // Converte para 32-bit
        }
        
        return hash.toString(36);
    }
    
    // ========================================================================
    // VALIDADORES
    // ========================================================================
    
    /**
     * Valida e-mail
     */
    validateEmail(email) {
        return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email);
    }
    
    /**
     * Valida CPF
     */
    validateCPF(cpf) {
        if (cpf.length !== 11 || /^(\d)\1{10}$/.test(cpf)) {
            return false;
        }
        
        let sum = 0;
        for (let i = 0; i < 9; i++) {
            sum += parseInt(cpf.charAt(i)) * (10 - i);
        }
        
        let remainder = (sum * 10) % 11;
        if (remainder === 10 || remainder === 11) remainder = 0;
        if (remainder !== parseInt(cpf.charAt(9))) return false;
        
        sum = 0;
        for (let i = 0; i < 10; i++) {
            sum += parseInt(cpf.charAt(i)) * (11 - i);
        }
        
        remainder = (sum * 10) % 11;
        if (remainder === 10 || remainder === 11) remainder = 0;
        
        return remainder === parseInt(cpf.charAt(10));
    }
}

// ============================================================================
// INICIALIZAÇÃO
// ============================================================================

// Inicializa quando DOM estiver pronto
if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', () => {
        new AuthenticationManager();
    });
} else {
    new AuthenticationManager();
}

// Service Worker para cache offline
// Service Worker desabilitado temporariamente
//if ('serviceWorker' in navigator) {
//    navigator.serviceWorker.register('/sw.js').catch(() => {
//        console.log('Service Worker não disponível');
//    });
//}

// Export para testes
if (typeof module !== 'undefined' && module.exports) {
    module.exports = AuthenticationManager;
}