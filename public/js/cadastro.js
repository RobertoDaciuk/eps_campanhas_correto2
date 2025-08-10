/**
 * ==============================================================================
 * SISTEMA DE CADASTRO PREMIUM (Premium Registration System) - v6.0
 * ==============================================================================
 * Localização: /public/js/cadastro.js
 * 
 * Aprimoramentos v6.0:
 * - Arquitetura modular com Observer Pattern
 * - Performance otimizada com Web Workers
 * - Sistema de cache inteligente com IndexedDB
 * - Validação em tempo real com debouncing adaptativo
 * - Sistema de telemetria e analytics avançado
 * - Detecção de fraude client-side
 * - Acessibilidade WCAG 2.1 AAA
 * - Progressive Web App features
 * - Micro-animações fluidas com CSS-in-JS
 * - Sistema de notificações push
 */

// ==============================================================================
// 1. CONFIGURAÇÃO GLOBAL E CONSTANTES
// ==============================================================================

const REGISTRATION_CONFIG = {
    API_ENDPOINTS: {
        VALIDATE: '/api/cadastro_api.php/validate',
        REGISTER: '/api/cadastro_api.php',
        CHECK_OPTICAL: '/api/oticas_api.php/check'
    },
    
    VALIDATION_TIMEOUTS: {
        nome: 300,
        cpf: 500,
        email: 400,
        celular: 300,
        cnpj: 700,
        senha: 200,
        confirmarSenha: 150
    },
    
    SECURITY: {
        MIN_FORM_TIME: 30000, // 30 segundos mínimos
        MAX_TYPING_SPEED: 50, // chars por segundo
        SUSPICIOUS_PATTERNS: [
            /(.)\1{5,}/, // caracteres repetitivos
            /^(test|admin|user)\d*$/i, // nomes suspeitos
            /^\d+$/, // apenas números em nome
        ]
    },
    
    ANIMATIONS: {
        DURATION_FAST: 150,
        DURATION_NORMAL: 300,
        DURATION_SLOW: 500,
        EASING: 'cubic-bezier(0.4, 0.0, 0.2, 1)'
    }
};

// ==============================================================================
// 2. CLASSE PRINCIPAL DO SISTEMA DE CADASTRO
// ==============================================================================

class AdvancedRegistrationSystem {
    constructor() {
        this.state = new Proxy({
            formStartTime: Date.now(),
            isSubmitting: false,
            validationState: {},
            fraudScore: 0,
            telemetryData: {},
            networkStatus: 'online'
        }, {
            set: (target, property, value) => {
                const oldValue = target[property];
                target[property] = value;
                this.emit('stateChange', { property, value, oldValue });
                return true;
            }
        });
        
        this.elements = new Map();
        this.validators = new Map();
        this.cache = new AdvancedCache();
        this.eventEmitter = new EventEmitter();
        this.fraudDetector = new FraudDetector();
        this.telemetry = new TelemetrySystem();
        this.accessibility = new AccessibilityManager();
        this.animator = new MicroAnimator();
        
        this.init();
    }
    
    async init() {
        try {
            await this.setupEnvironment();
            await this.mapElements();
            this.setupValidators();
            this.bindEvents();
            this.setupServiceWorker();
            this.startTelemetry();
            
            console.log('🚀 Sistema de Cadastro Premium v6.0 inicializado');
            this.telemetry.track('system_initialized', {
                timestamp: Date.now(),
                version: '6.0'
            });
            
        } catch (error) {
            console.error('❌ Erro na inicialização:', error);
            this.handleCriticalError(error);
        }
    }
    
    // ==============================================================================
    // 3. CONFIGURAÇÃO E INICIALIZAÇÃO
    // ==============================================================================
    
    async setupEnvironment() {
        // Detecção de recursos do navegador
        this.capabilities = {
            webWorkers: typeof Worker !== 'undefined',
            indexedDB: typeof indexedDB !== 'undefined',
            serviceWorker: 'serviceWorker' in navigator,
            intersectionObserver: typeof IntersectionObserver !== 'undefined',
            webAnimations: typeof Element.prototype.animate === 'function',
            clipboard: navigator.clipboard !== undefined
        };
        
        // Configuração de cache
        if (this.capabilities.indexedDB) {
            await this.cache.init();
        }
        
        // Monitor de conectividade
        this.setupNetworkMonitoring();
        
        // Configuração de acessibilidade
        await this.accessibility.init();
    }
    
    mapElements() {
        const selectors = {
            // Formulário principal
            form: '#register-form',
            
            // Campos de input
            nome: '#nome',
            cpf: '#cpf',
            email: '#email',
            celular: '#celular',
            cnpj: '#cnpj',
            senha: '#senha',
            confirmarSenha: '#confirmar_senha',
            termos: '#termos',
            
            // Campos de ótica
            razaoSocial: '#razao_social',
            enderecoOtica: '#endereco_otica',
            oticaDadosWrapper: '#otica-dados-wrapper',
            
            // Controles
            togglePassword: '#toggle-password',
            registerButton: '#register-button',
            buttonText: '.btn-text',
            buttonSpinner: '.btn-loading',
            
            // Indicadores de senha
            passwordRules: {
                container: '#password-strength-feedback',
                length: '#length',
                uppercase: '#uppercase', 
                lowercase: '#lowercase',
                number: '#number',
                special: '#special'
            },
            
            // Containers de erro e opções
            messageContainer: '#message-container',
            cpfExistsOptions: '#cpf-exists-options',
            emailExistsOptions: '#email-exists-options',
            termosError: '#termos-error'
        };
        
        // Mapeia elementos com verificação robusta
        for (const [key, selector] of Object.entries(selectors)) {
            if (typeof selector === 'string') {
                const element = document.querySelector(selector);
                if (element) {
                    this.elements.set(key, element);
                } else if (key === 'form') {
                    throw new Error(`Elemento crítico não encontrado: ${selector}`);
                }
            } else if (typeof selector === 'object') {
                const group = new Map();
                for (const [subKey, subSelector] of Object.entries(selector)) {
                    const element = document.querySelector(subSelector);
                    if (element) {
                        group.set(subKey, element);
                    }
                }
                this.elements.set(key, group);
            }
        }
        
        // Inicializa estado de validação para campos obrigatórios
        const requiredFields = ['nome', 'cpf', 'email', 'celular', 'cnpj', 'senha', 'confirmarSenha', 'termos'];
        requiredFields.forEach(field => {
            this.state.validationState[field] = false;
        });
    }
    
    setupValidators() {
        // Configuração de validadores por campo
        this.validators.set('nome', new NameValidator());
        this.validators.set('cpf', new CPFValidator());
        this.validators.set('email', new EmailValidator());
        this.validators.set('celular', new PhoneValidator());
        this.validators.set('cnpj', new CNPJValidator());
        this.validators.set('senha', new PasswordValidator());
        this.validators.set('confirmarSenha', new PasswordConfirmValidator());
    }
    
    // ==============================================================================
    // 4. SISTEMA DE EVENTOS
    // ==============================================================================
    
    bindEvents() {
        const form = this.elements.get('form');
        if (!form) return;
        
        // Eventos de formulário
        form.addEventListener('submit', this.handleSubmit.bind(this));
        
        // Eventos de campos com debouncing inteligente
        this.setupFieldEvents();
        
        // Eventos de controle
        this.setupControlEvents();
        
        // Eventos de acessibilidade
        this.setupAccessibilityEvents();
        
        // Eventos do sistema
        this.setupSystemEvents();
    }
    
    setupFieldEvents() {
        const inputFields = ['nome', 'cpf', 'email', 'celular', 'cnpj', 'senha', 'confirmarSenha'];
        
        inputFields.forEach(fieldName => {
            const element = this.elements.get(fieldName);
            if (!element) return;
            
            const validator = this.validators.get(fieldName);
            const debounceTime = REGISTRATION_CONFIG.VALIDATION_TIMEOUTS[fieldName];
            
            // Input event com formatação instantânea
            element.addEventListener('input', (e) => {
                this.handleFieldInput(fieldName, e);
            });
            
            // Validação com debounce
            const debouncedValidation = this.debounce(
                (e) => this.validateField(fieldName, e.target.value),
                debounceTime
            );
            
            element.addEventListener('input', debouncedValidation);
            
            // Blur para validação final
            element.addEventListener('blur', (e) => {
                this.validateField(fieldName, e.target.value, true);
            });
            
            // Focus para limpar erros
            element.addEventListener('focus', () => {
                this.clearFieldError(fieldName);
            });
            
            // Eventos especiais para senha
            if (fieldName === 'senha') {
                element.addEventListener('input', (e) => {
                    this.updatePasswordStrength(e.target.value);
                });
            }
            
            // Eventos para confirmação de senha
            if (fieldName === 'confirmarSenha') {
                element.addEventListener('input', () => {
                    if (element.value) {
                        this.validatePasswordMatch();
                    }
                });
            }
        });
    }
    
    setupControlEvents() {
        // Toggle de senha
        const togglePassword = this.elements.get('togglePassword');
        if (togglePassword) {
            togglePassword.addEventListener('click', this.togglePasswordVisibility.bind(this));
        }
        
        // Checkbox de termos
        const termos = this.elements.get('termos');
        if (termos) {
            termos.addEventListener('change', this.validateTerms.bind(this));
        }
        
        // Botões de ação rápida
        document.querySelectorAll('.login-button').forEach(btn => {
            btn.addEventListener('click', () => {
                this.telemetry.track('quick_action_login');
                window.location.href = '/login.php';
            });
        });
        
        document.querySelectorAll('.forgot-password-button').forEach(btn => {
            btn.addEventListener('click', () => {
                this.telemetry.track('quick_action_forgot_password');
                window.location.href = '/recuperar-senha.php';
            });
        });
    }
    
    setupAccessibilityEvents() {
        // Navegação por teclado
        document.addEventListener('keydown', (e) => {
            if (e.key === 'Escape') {
                this.clearAllErrors();
                this.accessibility.announce('Erros limpos');
            }
            
            if (e.key === 'F1') {
                e.preventDefault();
                this.showKeyboardShortcuts();
            }
        });
        
        // Atalhos de teclado
        document.addEventListener('keydown', (e) => {
            if (e.ctrlKey || e.metaKey) {
                switch (e.key) {
                    case 'Enter':
                        e.preventDefault();
                        if (this.isFormValid()) {
                            this.handleSubmit(e);
                        }
                        break;
                }
            }
        });
    }
    
    setupSystemEvents() {
        // Monitor de performance
        if ('PerformanceObserver' in window) {
            const observer = new PerformanceObserver((list) => {
                for (const entry of list.getEntries()) {
                    if (entry.entryType === 'navigation') {
                        this.telemetry.track('page_load_time', {
                            loadTime: entry.loadEventEnd - entry.loadEventStart
                        });
                    }
                }
            });
            observer.observe({ entryTypes: ['navigation'] });
        }
        
        // Monitor de visibilidade da página
        document.addEventListener('visibilitychange', () => {
            if (document.hidden) {
                this.telemetry.track('page_hidden');
            } else {
                this.telemetry.track('page_visible');
            }
        });
        
        // Monitor de erros globais
        window.addEventListener('error', (e) => {
            this.telemetry.trackError('javascript_error', {
                message: e.message,
                filename: e.filename,
                lineno: e.lineno,
                colno: e.colno
            });
        });
        
        // Monitor de promessas rejeitadas
        window.addEventListener('unhandledrejection', (e) => {
            this.telemetry.trackError('unhandled_promise_rejection', {
                reason: e.reason
            });
        });
    }
    
    setupNetworkMonitoring() {
        if ('connection' in navigator) {
            const updateNetworkStatus = () => {
                this.state.networkStatus = navigator.onLine ? 'online' : 'offline';
                this.telemetry.track('network_status_change', {
                    status: this.state.networkStatus,
                    connection: navigator.connection
                });
            };
            
            window.addEventListener('online', updateNetworkStatus);
            window.addEventListener('offline', updateNetworkStatus);
            updateNetworkStatus();
        }
    }
    
    // ==============================================================================
    // 5. SISTEMA DE VALIDAÇÃO AVANÇADO
    // ==============================================================================
    
    handleFieldInput(fieldName, event) {
        const value = event.target.value;
        const element = event.target;
        
        // Análise de detecção de fraude
        this.fraudDetector.analyzeInput(fieldName, value, event.timeStamp);
        
        // Aplicar formatadores em tempo real
        const formatter = this.getFormatter(fieldName);
        if (formatter) {
            const cursorPos = element.selectionStart;
            const formattedValue = formatter.format(value);
            
            if (formattedValue !== value) {
                element.value = formattedValue;
                
                // Restaurar posição do cursor
                const newCursorPos = this.calculateNewCursorPosition(value, formattedValue, cursorPos);
                element.setSelectionRange(newCursorPos, newCursorPos);
            }
        }
        
        // Limpar erro visual
        this.clearFieldError(fieldName);
        
        // Telemetria de interação
        this.telemetry.track('field_interaction', {
            field: fieldName,
            length: value.length,
            timestamp: Date.now()
        });
    }
    
    async validateField(fieldName, value, isFinal = false) {
        const validator = this.validators.get(fieldName);
        if (!validator) return;
        
        const element = this.elements.get(fieldName);
        if (!element) return;
        
        // Show loading
        this.updateFieldFeedback(fieldName, 'loading');
        
        try {
            // Validação local
            const localResult = await validator.validateLocal(value);
            
            if (!localResult.valid) {
                this.updateFieldFeedback(fieldName, 'invalid', localResult.message);
                this.state.validationState[fieldName] = false;
                this.checkFormValidity();
                return;
            }
            
            // Validação remota se necessário
            if (validator.hasRemoteValidation && value.trim()) {
                const cacheKey = `${fieldName}:${value}`;
                let remoteResult = await this.cache.get(cacheKey);
                
                if (!remoteResult) {
                    remoteResult = await this.performRemoteValidation(fieldName, value);
                    if (remoteResult) {
                        await this.cache.set(cacheKey, remoteResult, 300000); // 5 min cache
                    }
                }
                
                if (remoteResult && !remoteResult.valid) {
                    this.updateFieldFeedback(fieldName, 'invalid', remoteResult.message);
                    this.state.validationState[fieldName] = false;
                    
                    if (remoteResult.showOptions) {
                        this.showActionOptions(fieldName, remoteResult);
                    }
                } else if (remoteResult) {
                    this.updateFieldFeedback(fieldName, 'valid');
                    this.state.validationState[fieldName] = true;
                    
                    if (remoteResult.data) {
                        this.processRemoteData(fieldName, remoteResult.data);
                    }
                } else {
                    // Falha na validação remota - permite continuar
                    this.updateFieldFeedback(fieldName, 'valid');
                    this.state.validationState[fieldName] = true;
                }
            } else {
                this.updateFieldFeedback(fieldName, 'valid');
                this.state.validationState[fieldName] = true;
            }
            
        } catch (error) {
            console.error(`Erro na validação do campo ${fieldName}:`, error);
            this.updateFieldFeedback(fieldName, 'error', 'Erro na validação. Tente novamente.');
            this.state.validationState[fieldName] = false;
            
            this.telemetry.trackError('field_validation_error', {
                field: fieldName,
                error: error.message
            });
        } finally {
            this.checkFormValidity();
        }
    }
    
    async performRemoteValidation(fieldName, value) {
        try {
            const response = await fetch(
                `${REGISTRATION_CONFIG.API_ENDPOINTS.VALIDATE}?field=${fieldName}&value=${encodeURIComponent(value)}`,
                {
                    method: 'GET',
                    headers: {
                        'Content-Type': 'application/json',
                        'X-Requested-With': 'XMLHttpRequest'
                    }
                }
            );
            
            if (!response.ok) {
                throw new Error(`HTTP ${response.status}`);
            }
            
            return await response.json();
            
        } catch (error) {
            console.warn('Erro na validação remota:', error);
            this.telemetry.trackError('remote_validation_error', {
                field: fieldName,
                error: error.message
            });
            return null;
        }
    }
    
    // ==============================================================================
    // 6. SISTEMA DE FEEDBACK VISUAL
    // ==============================================================================
    
    updateFieldFeedback(fieldName, state, message = '') {
        const element = this.elements.get(fieldName);
        if (!element) return;
        
        const wrapper = element.closest('.input-wrapper') || element.closest('.input-group');
        if (!wrapper) return;
        
        const icon = wrapper.querySelector('.validation-icon');
        const errorContainer = wrapper.querySelector('.error-message-inline');
        
        if (!icon || !errorContainer) return;
        
        // Animação de saída do estado anterior
        this.animator.fadeOut(icon, 100).then(() => {
            // Limpa classes anteriores
            icon.className = 'validation-icon';
            errorContainer.textContent = message;
            
            // Esconde opções de ação
            this.hideActionOptions(fieldName);
            
            // Aplica novo estado
            switch (state) {
                case 'valid':
                    icon.classList.add('valid');
                    element.setAttribute('aria-invalid', 'false');
                    this.accessibility.announce(`${this.getFieldLabel(fieldName)} válido`);
                    break;
                    
                case 'invalid':
                    icon.classList.add('invalid');
                    element.setAttribute('aria-invalid', 'true');
                    element.setAttribute('aria-describedby', `${fieldName}-error`);
                    break;
                    
                case 'loading':
                    icon.classList.add('fa-spinner', 'fa-spin');
                    icon.style.color = 'var(--primary-color-light)';
                    break;
                    
                case 'error':
                    icon.classList.add('invalid');
                    element.setAttribute('aria-invalid', 'true');
                    break;
            }
            
            // Animação de entrada do novo estado
            this.animator.fadeIn(icon, 150);
        });
        
        // Atualização da acessibilidade
        if (message) {
            errorContainer.setAttribute('role', 'alert');
            errorContainer.setAttribute('aria-live', 'assertive');
        }
    }
    
    updatePasswordStrength(password) {
        const rules = {
            length: password.length >= 8,
            uppercase: /[A-Z]/.test(password),
            lowercase: /[a-z]/.test(password),
            number: /[0-9]/.test(password),
            special: /[^A-Za-z0-9]/.test(password)
        };
        
        const passwordRules = this.elements.get('passwordRules');
        if (!passwordRules) return;
        
        // Atualiza cada regra com animação
        for (const [rule, passed] of Object.entries(rules)) {
            const element = passwordRules.get(rule);
            if (!element) continue;
            
            const icon = element.querySelector('i');
            
            this.animator.slideOut(element, 'left', 150).then(() => {
                element.classList.remove('valid', 'invalid');
                
                if (passed) {
                    element.classList.add('valid');
                    if (icon) {
                        icon.className = 'fas fa-check';
                        icon.style.color = '#28a745';
                    }
                } else {
                    element.classList.add('invalid');
                    if (icon) {
                        icon.className = 'fas fa-times';
                        icon.style.color = '#dc3545';
                    }
                }
                
                this.animator.slideIn(element, 'left', 200);
            });
        }
        
        const allValid = Object.values(rules).every(Boolean);
        
        // Habilita campo de confirmação
        const confirmarSenha = this.elements.get('confirmarSenha');
        if (confirmarSenha) {
            confirmarSenha.disabled = !allValid;
            
            if (!allValid && confirmarSenha.value) {
                confirmarSenha.value = '';
                this.state.validationState.confirmarSenha = false;
                this.clearFieldError('confirmarSenha');
            }
        }
        
        // Calcular força da senha
        const strength = this.calculatePasswordStrength(password, rules);
        this.updatePasswordStrengthIndicator(strength);
    }
    
    calculatePasswordStrength(password, rules) {
        let score = 0;
        let feedback = [];
        
        // Pontuação básica por regras
        Object.entries(rules).forEach(([rule, passed]) => {
            if (passed) {
                score += 20;
            } else {
                switch (rule) {
                    case 'length':
                        feedback.push('Use pelo menos 8 caracteres');
                        break;
                    case 'uppercase':
                        feedback.push('Adicione uma letra maiúscula');
                        break;
                    case 'lowercase':
                        feedback.push('Adicione uma letra minúscula');
                        break;
                    case 'number':
                        feedback.push('Adicione um número');
                        break;
                    case 'special':
                        feedback.push('Adicione um símbolo especial');
                        break;
                }
            }
        });
        
        // Bonificações adicionais
        if (password.length >= 12) score += 10;
        if (password.length >= 16) score += 10;
        if (/[àáâãäåæçèéêëìíîïñòóôõöøùúûüý]/gi.test(password)) score += 5; // acentos
        if (!/(.)\1{2,}/.test(password)) score += 5; // sem repetições
        
        // Penalidades
        if (/^[a-zA-Z]+$/.test(password)) score -= 10; // apenas letras
        if (/^\d+$/.test(password)) score -= 20; // apenas números
        if (/password|123456|qwerty/gi.test(password)) score -= 25; // senhas comuns
        
        const level = score >= 90 ? 'very-strong' : 
                     score >= 70 ? 'strong' : 
                     score >= 50 ? 'medium' : 
                     score >= 30 ? 'weak' : 'very-weak';
        
        return { score: Math.max(0, Math.min(100, score)), level, feedback };
    }
    
    updatePasswordStrengthIndicator(strength) {
        // Implementar indicador visual de força da senha
        const indicator = document.querySelector('.password-strength-indicator');
        if (!indicator) return;
        
        const colors = {
            'very-weak': '#dc3545',
            'weak': '#fd7e14',
            'medium': '#ffc107',
            'strong': '#28a745',
            'very-strong': '#20c997'
        };
        
        const labels = {
            'very-weak': 'Muito fraca',
            'weak': 'Fraca',
            'medium': 'Média',
            'strong': 'Forte',
            'very-strong': 'Muito forte'
        };
        
        this.animator.morphWidth(indicator, `${strength.score}%`, 300).then(() => {
            indicator.style.backgroundColor = colors[strength.level];
            indicator.setAttribute('data-strength', labels[strength.level]);
        });
    }
    
    // ==============================================================================
    // 7. SISTEMA DE SUBMISSÃO
    // ==============================================================================
    
    async handleSubmit(event) {
        event.preventDefault();
        
        if (this.state.isSubmitting) return;
        
        // Validação final completa
        const finalValidation = await this.performFinalValidation();
        if (!finalValidation.valid) {
            this.showError(finalValidation.message);
            this.focusFirstErrorField();
            return;
        }
        
        // Verificação de fraude
        const fraudCheck = this.fraudDetector.getFinalScore();
        if (fraudCheck.riskLevel === 'high') {
            this.telemetry.track('fraud_detected', fraudCheck);
            this.showError('Atividade suspeita detectada. Entre em contato com o suporte.');
            return;
        }
        
        this.state.isSubmitting = true;
        this.setSubmitState(true);
        
        try {
            const formData = this.collectFormData();
            const response = await this.submitRegistration(formData);
            
            if (response.success) {
                await this.handleSuccessfulRegistration(response);
            } else {
                this.handleRegistrationError(response);
            }
            
        } catch (error) {
            console.error('Erro na submissão:', error);
            this.showError('Erro de conexão. Verifique sua internet e tente novamente.');
            
            this.telemetry.trackError('submission_error', {
                error: error.message,
                stack: error.stack
            });
            
        } finally {
            this.state.isSubmitting = false;
            this.setSubmitState(false);
        }
    }
    
    async performFinalValidation() {
        const errors = [];
        
        // Valida todos os campos obrigatórios
        for (const fieldName of Object.keys(this.state.validationState)) {
            if (!this.state.validationState[fieldName]) {
                const element = this.elements.get(fieldName);
                if (element && element.value.trim()) {
                    // Re-valida campo
                    await this.validateField(fieldName, element.value, true);
                    
                    if (!this.state.validationState[fieldName]) {
                        errors.push(this.getFieldLabel(fieldName));
                    }
                } else {
                    errors.push(this.getFieldLabel(fieldName));
                }
            }
        }
        
        // Verifica tempo mínimo no formulário
        const formTime = Date.now() - this.state.formStartTime;
        if (formTime < REGISTRATION_CONFIG.SECURITY.MIN_FORM_TIME) {
            this.fraudDetector.addFlag('form_too_fast', { formTime });
            errors.push('Formulário preenchido muito rapidamente');
        }
        
        return {
            valid: errors.length === 0,
            message: errors.length > 0 ? `Corrija os seguintes campos: ${errors.join(', ')}` : ''
        };
    }
    
    collectFormData() {
        const data = {
            nome: this.sanitizeInput(this.elements.get('nome').value.trim()),
            cpf: this.elements.get('cpf').value.replace(/\D/g, ''),
            email: this.elements.get('email').value.trim().toLowerCase(),
            celular: this.elements.get('celular').value.replace(/\D/g, ''),
            cnpj: this.elements.get('cnpj').value.replace(/\D/g, ''),
            senha: this.elements.get('senha').value,
            confirmar_senha: this.elements.get('confirmarSenha').value,
            termos: this.elements.get('termos').checked
        };
        
        // Adiciona metadados de segurança
        data.metadata = {
            form_time_seconds: Math.floor((Date.now() - this.state.formStartTime) / 1000),
            fraud_score: this.fraudDetector.getFinalScore(),
            telemetry: this.telemetry.getSummary(),
            capabilities: this.capabilities,
            timezone: Intl.DateTimeFormat().resolvedOptions().timeZone,
            language: navigator.language,
            screen_resolution: `${screen.width}x${screen.height}`,
            user_agent: navigator.userAgent
        };
        
        return data;
    }
    
    async submitRegistration(formData) {
        const controller = new AbortController();
        const timeoutId = setTimeout(() => controller.abort(), 30000); // 30s timeout
        
        try {
            const response = await fetch(REGISTRATION_CONFIG.API_ENDPOINTS.REGISTER, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'Accept': 'application/json',
                    'X-Requested-With': 'XMLHttpRequest',
                    'X-Client-Version': '6.0'
                },
                body: JSON.stringify(formData),
                signal: controller.signal
            });
            
            clearTimeout(timeoutId);
            
            if (!response.ok) {
                throw new Error(`HTTP ${response.status}: ${response.statusText}`);
            }
            
            return await response.json();
            
        } catch (error) {
            clearTimeout(timeoutId);
            
            if (error.name === 'AbortError') {
                throw new Error('Timeout: O servidor demorou muito para responder');
            }
            
            throw error;
        }
    }
    
    async handleSuccessfulRegistration(response) {
        // Analytics de conversão
        this.telemetry.trackConversion(response);
        
        // Limpa dados sensíveis do cache
        await this.cache.clear();
        
        // Mostra modal de sucesso com animação
        await this.showSuccessModal(
            response.message || 'Cadastro realizado com sucesso!',
            () => {
                window.location.href = '/login.php?registered=1';
            }
        );
    }
    
    handleRegistrationError(response) {
        console.error('Erro no registro:', response);
        
        this.telemetry.trackError('registration_error', {
            error: response.error,
            message: response.message
        });
        
        // Mostra erros específicos de campo se disponíveis
        if (response.data?.field_errors) {
            this.showFieldErrors(response.data.field_errors);
        } else {
            this.showError(response.message || 'Erro no cadastro. Tente novamente.');
        }
    }
    
    // ==============================================================================
    // 8. FORMATADORES AVANÇADOS
    // ==============================================================================
    
    getFormatter(fieldName) {
        const formatters = {
            cpf: new CPFFormatter(),
            cnpj: new CNPJFormatter(),
            celular: new PhoneFormatter(),
            nome: new NameFormatter()
        };
        
        return formatters[fieldName] || null;
    }
    
    calculateNewCursorPosition(oldValue, newValue, oldCursor) {
        // Algoritmo inteligente para manter cursor na posição correta após formatação
        const beforeCursor = oldValue.slice(0, oldCursor);
        const afterFormatting = newValue.slice(0, newValue.length);
        
        let newCursor = oldCursor;
        let drift = 0;
        
        // Conta quantos caracteres de formatação foram adicionados/removidos
        for (let i = 0; i < Math.min(beforeCursor.length, afterFormatting.length); i++) {
            if (beforeCursor[i] !== afterFormatting[i]) {
                if (/\d/.test(beforeCursor[i]) && !/\d/.test(afterFormatting[i])) {
                    drift++; // Caractere de formatação adicionado
                } else if (!/\d/.test(beforeCursor[i]) && /\d/.test(afterFormatting[i])) {
                    drift--; // Caractere de formatação removido
                }
            }
        }
        
        return Math.max(0, Math.min(newValue.length, oldCursor + drift));
    }
    
    // ==============================================================================
    // 9. SISTEMA DE NOTIFICAÇÕES E UI
    // ==============================================================================
    
    showError(message) {
        this.showNotification(message, 'error', 5000);
    }
    
    showSuccess(message) {
        this.showNotification(message, 'success', 3000);
    }
    
    showNotification(message, type = 'info', duration = 4000) {
        // Remove notificações anteriores
        const existing = document.querySelector('.notification-toast');
        if (existing) {
            this.animator.slideOut(existing, 'right', 200).then(() => {
                existing.remove();
            });
        }
        
        // Cria nova notificação
        const notification = this.createNotificationElement(message, type);
        document.body.appendChild(notification);
        
        // Animação de entrada
        this.animator.slideIn(notification, 'right', 300);
        
        // Auto-remove
        if (duration > 0) {
            setTimeout(() => {
                if (document.contains(notification)) {
                    this.removeNotification(notification);
                }
            }, duration);
        }
        
        return notification;
    }
    
    createNotificationElement(message, type) {
        const notification = document.createElement('div');
        notification.className = `notification-toast notification-${type}`;
        notification.setAttribute('role', 'alert');
        notification.setAttribute('aria-live', 'assertive');
        
        const icons = {
            error: 'fa-exclamation-circle',
            success: 'fa-check-circle',
            warning: 'fa-exclamation-triangle',
            info: 'fa-info-circle'
        };
        
        notification.innerHTML = `
            <div class="notification-content">
                <i class="fas ${icons[type] || icons.info}"></i>
                <span class="notification-message">${message}</span>
            </div>
            <button class="notification-close" aria-label="Fechar notificação" tabindex="0">
                <i class="fas fa-times"></i>
            </button>
        `;
        
        // Estilos dinâmicos
        const styles = {
            error: { bg: '#fee2e2', border: '#dc2626', text: '#991b1b' },
            success: { bg: '#dcfce7', border: '#16a34a', text: '#166534' },
            warning: { bg: '#fef3c7', border: '#d97706', text: '#92400e' },
            info: { bg: '#dbeafe', border: '#2563eb', text: '#1e40af' }
        };
        
        const style = styles[type] || styles.info;
        Object.assign(notification.style, {
            position: 'fixed',
            top: '20px',
            right: '20px',
            zIndex: '10000',
            maxWidth: '400px',
            padding: '16px',
            borderRadius: '12px',
            border: `2px solid ${style.border}`,
            backgroundColor: style.bg,
            color: style.text,
            boxShadow: '0 10px 25px rgba(0,0,0,0.15)',
            transform: 'translateX(100%)',
            transition: 'all 0.3s cubic-bezier(0.4, 0, 0.2, 1)',
            fontFamily: 'Inter, sans-serif',
            fontSize: '14px',
            fontWeight: '500'
        });
        
        // Event listener para fechar
        const closeBtn = notification.querySelector('.notification-close');
        closeBtn.addEventListener('click', () => {
            this.removeNotification(notification);
        });
        
        return notification;
    }
    
    removeNotification(notification) {
        this.animator.slideOut(notification, 'right', 200).then(() => {
            if (document.contains(notification)) {
                notification.remove();
            }
        });
    }
    
    async showSuccessModal(message, callback) {
        const modal = document.createElement('div');
        modal.className = 'success-modal-overlay';
        modal.setAttribute('role', 'dialog');
        modal.setAttribute('aria-modal', 'true');
        modal.setAttribute('aria-labelledby', 'success-title');
        modal.setAttribute('aria-describedby', 'success-description');
        
        modal.innerHTML = `
            <div class="success-modal">
                <div class="success-icon-wrapper">
                    <div class="success-icon">
                        <i class="fas fa-check-circle"></i>
                    </div>
                </div>
                <h3 id="success-title">Cadastro Realizado!</h3>
                <p id="success-description">${message}</p>
                <div class="success-actions">
                    <button class="btn btn-primary" id="continue-btn">
                        <span>Continuar</span>
                        <i class="fas fa-arrow-right"></i>
                    </button>
                </div>
            </div>
        `;
        
        // Estilos do modal
        Object.assign(modal.style, {
            position: 'fixed',
            top: '0',
            left: '0',
            right: '0',
            bottom: '0',
            background: 'rgba(0,0,0,0.8)',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'center',
            zIndex: '10001',
            opacity: '0',
            backdropFilter: 'blur(8px)'
        });
        
        const modalContent = modal.querySelector('.success-modal');
        Object.assign(modalContent.style, {
            background: 'linear-gradient(135deg, #667eea 0%, #764ba2 100%)',
            padding: '40px',
            borderRadius: '20px',
            textAlign: 'center',
            maxWidth: '450px',
            width: '90%',
            color: 'white',
            transform: 'scale(0.7) translateY(50px)',
            boxShadow: '0 25px 50px rgba(0,0,0,0.3)'
        });
        
        document.body.appendChild(modal);
        
        // Animação de entrada
        await this.animator.parallel([
            this.animator.fadeIn(modal, 300),
            this.animator.scale(modalContent, { from: 0.7, to: 1.0 }, 400),
            this.animator.slideUp(modalContent, 400)
        ]);
        
        // Foca no botão para acessibilidade
        const continueBtn = modal.querySelector('#continue-btn');
        continueBtn.focus();
        
        // Event listeners
        const handleContinue = async () => {
            await this.animator.parallel([
                this.animator.fadeOut(modal, 200),
                this.animator.scale(modalContent, { from: 1.0, to: 0.8 }, 200)
            ]);
            
            modal.remove();
            if (callback) callback();
        };
        
        continueBtn.addEventListener('click', handleContinue);
        
        // ESC para fechar
        const handleKeydown = (e) => {
            if (e.key === 'Escape') {
                handleContinue();
                document.removeEventListener('keydown', handleKeydown);
            }
        };
        document.addEventListener('keydown', handleKeydown);
    }
    
    // ==============================================================================
    // 10. UTILITÁRIOS E HELPERS
    // ==============================================================================
    
    togglePasswordVisibility() {
        const senha = this.elements.get('senha');
        const icon = this.elements.get('togglePassword')?.querySelector('i');
        
        if (!senha || !icon) return;
        
        const isVisible = senha.type === 'text';
        
        senha.type = isVisible ? 'password' : 'text';
        icon.className = isVisible ? 'fas fa-eye' : 'fas fa-eye-slash';
        
        // Atualiza acessibilidade
        const toggleBtn = this.elements.get('togglePassword');
        if (toggleBtn) {
            toggleBtn.setAttribute('aria-label', 
                isVisible ? 'Mostrar senha' : 'Ocultar senha'
            );
        }
        
        // Auto-hide após 10 segundos
        if (!isVisible) {
            setTimeout(() => {
                if (senha.type === 'text') {
                    senha.type = 'password';
                    icon.className = 'fas fa-eye';
                }
            }, 10000);
        }
        
        this.telemetry.track('password_visibility_toggle', { visible: !isVisible });
    }
    
    validatePasswordMatch() {
        const senha = this.elements.get('senha')?.value || '';
        const confirmacao = this.elements.get('confirmarSenha')?.value || '';
        
        const match = senha === confirmacao && confirmacao !== '';
        
        this.state.validationState.confirmarSenha = match;
        this.updateFieldFeedback(
            'confirmarSenha',
            match ? 'valid' : 'invalid',
            match ? '' : 'As senhas não coincidem'
        );
    }
    
    validateTerms() {
        const checked = this.elements.get('termos')?.checked || false;
        this.state.validationState.termos = checked;
        
        const termosError = this.elements.get('termosError');
        if (termosError) {
            termosError.textContent = checked ? '' : 'Você deve aceitar os termos para continuar';
        }
        
        this.checkFormValidity();
    }
    
    checkFormValidity() {
        const allValid = Object.values(this.state.validationState).every(Boolean);
        
        const registerButton = this.elements.get('registerButton');
        if (registerButton) {
            registerButton.disabled = !allValid;
            
            if (allValid) {
                registerButton.classList.add('ready');
                this.animator.pulse(registerButton, 1);
            } else {
                registerButton.classList.remove('ready');
            }
        }
    }
    
    setSubmitState(isSubmitting) {
        const registerButton = this.elements.get('registerButton');
        const buttonText = this.elements.get('buttonText');
        const buttonSpinner = this.elements.get('buttonSpinner');
        
        if (registerButton) registerButton.disabled = isSubmitting;
        if (buttonText) buttonText.style.display = isSubmitting ? 'none' : 'inline-block';
        if (buttonSpinner) buttonSpinner.style.display = isSubmitting ? 'inline-block' : 'none';
        
        // Desabilita campos durante submissão
        const form = this.elements.get('form');
        if (form) {
            const inputs = form.querySelectorAll('input, select, textarea, button');
            inputs.forEach(input => {
                if (input !== registerButton) {
                    input.disabled = isSubmitting;
                }
            });
        }
    }
    
    clearFieldError(fieldName) {
        const element = this.elements.get(fieldName);
        if (!element) return;
        
        const errorContainer = element.closest('.input-group')?.querySelector('.error-message-inline');
        if (errorContainer) {
            errorContainer.textContent = '';
        }
        
        this.hideActionOptions(fieldName);
    }
    
    clearAllErrors() {
        const form = this.elements.get('form');
        if (!form) return;
        
        const errorContainers = form.querySelectorAll('.error-message-inline');
        errorContainers.forEach(container => {
            container.textContent = '';
        });
        
        const validationIcons = form.querySelectorAll('.validation-icon');
        validationIcons.forEach(icon => {
            icon.className = 'validation-icon';
        });
        
        // Esconde todas as opções de ação
        ['cpf', 'email'].forEach(field => {
            this.hideActionOptions(field);
        });
    }
    
    showActionOptions(fieldName, validation) {
        if (validation.message?.includes('já está registado') || 
            validation.message?.includes('já cadastrado')) {
            
            const optionsElement = this.elements.get(`${fieldName}ExistsOptions`);
            if (optionsElement) {
                this.animator.slideDown(optionsElement, 200);
            }
        }
    }
    
    hideActionOptions(fieldName) {
        const optionsElement = this.elements.get(`${fieldName}ExistsOptions`);
        if (optionsElement && optionsElement.style.display !== 'none') {
            this.animator.slideUp(optionsElement, 200);
        }
    }
    
    processRemoteData(fieldName, data) {
        if (fieldName === 'cnpj' && data.otica) {
            this.populateOpticalData(data.otica);
        }
    }
    
    populateOpticalData(oticaData) {
        const razaoSocial = this.elements.get('razaoSocial');
        const enderecoOtica = this.elements.get('enderecoOtica');
        const wrapper = this.elements.get('oticaDadosWrapper');
        
        if (razaoSocial) razaoSocial.value = oticaData.razao_social || '';
        if (enderecoOtica) enderecoOtica.value = oticaData.endereco || '';
        
        if (wrapper && wrapper.classList.contains('hidden')) {
            wrapper.classList.remove('hidden');
            this.animator.slideDown(wrapper, 300);
        }
    }
    
    getFieldLabel(field) {
        const labels = {
            nome: 'Nome',
            cpf: 'CPF',
            email: 'E-mail',
            celular: 'Celular',
            cnpj: 'CNPJ',
            senha: 'Senha',
            confirmarSenha: 'Confirmação de senha',
            termos: 'Termos de uso'
        };
        
        return labels[field] || field;
    }
    
    sanitizeInput(value) {
        return value
            .replace(/[<>\"'&]/g, '')
            .trim()
            .substring(0, 255);
    }
    
    isFormValid() {
        return Object.values(this.state.validationState).every(Boolean);
    }
    
    focusFirstErrorField() {
        for (const [fieldName, isValid] of Object.entries(this.state.validationState)) {
            if (!isValid) {
                const element = this.elements.get(fieldName);
                if (element) {
                    element.focus();
                    break;
                }
            }
        }
    }
    
    showFieldErrors(fieldErrors) {
        for (const [field, errors] of Object.entries(fieldErrors)) {
            const element = this.elements.get(field);
            if (element) {
                const message = Array.isArray(errors) ? errors[0] : errors;
                this.updateFieldFeedback(field, 'invalid', message);
                this.state.validationState[field] = false;
            }
        }
        
        this.checkFormValidity();
        this.focusFirstErrorField();
    }
    
    showKeyboardShortcuts() {
        const shortcuts = [
            'F1 - Mostrar atalhos de teclado',
            'Esc - Limpar erros',
            'Ctrl+Enter - Enviar formulário (se válido)',
            'Tab - Navegar entre campos'
        ];
        
        this.showNotification(
            shortcuts.join('\n'),
            'info',
            0 // Não remove automaticamente
        );
    }
    
    handleCriticalError(error) {
        console.error('❌ Erro crítico:', error);
        
        const fallbackHTML = `
            <div style="text-align: center; padding: 40px; color: #dc3545;">
                <h3>⚠️ Erro no Sistema</h3>
                <p>Ocorreu um erro crítico. Recarregue a página para tentar novamente.</p>
                <button onclick="window.location.reload()" 
                        style="padding: 10px 20px; background: #dc3545; color: white; border: none; border-radius: 5px; cursor: pointer;">
                    Recarregar Página
                </button>
            </div>
        `;
        
        const messageContainer = document.getElementById('message-container');
        if (messageContainer) {
            messageContainer.innerHTML = fallbackHTML;
        }
    }
    
    async setupServiceWorker() {
        if (!this.capabilities.serviceWorker || !navigator.serviceWorker) return;
        
        try {
            const registration = await navigator.serviceWorker.register('/sw-cadastro.js');
            console.log('🔧 Service Worker registrado:', registration.scope);
            
            this.telemetry.track('service_worker_registered');
        } catch (error) {
            console.warn('Service Worker registration failed:', error);
        }
    }
    
    startTelemetry() {
        this.telemetry.start();
        
        // Track de início de sessão
        this.telemetry.track('session_start', {
            timestamp: Date.now(),
            referrer: document.referrer,
            user_agent: navigator.userAgent,
            viewport: `${window.innerWidth}x${window.innerHeight}`,
            color_scheme: window.matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'light',
            reduced_motion: window.matchMedia('(prefers-reduced-motion: reduce)').matches
        });
    }
    
    // Event Emitter methods
    on(event, callback) {
        return this.eventEmitter.on(event, callback);
    }
    
    emit(event, data) {
        return this.eventEmitter.emit(event, data);
    }
    
    off(event, callback) {
        return this.eventEmitter.off(event, callback);
    }
    
    // Debounce utility
    debounce(func, wait, immediate = false) {
        let timeout;
        return function executedFunction(...args) {
            const later = () => {
                timeout = null;
                if (!immediate) func.apply(this, args);
            };
            const callNow = immediate && !timeout;
            clearTimeout(timeout);
            timeout = setTimeout(later, wait);
            if (callNow) func.apply(this, args);
        };
    }
}

// ==============================================================================
// 11. CLASSES AUXILIARES
// ==============================================================================

class EventEmitter {
    constructor() {
        this.events = new Map();
    }
    
    on(event, callback) {
        if (!this.events.has(event)) {
            this.events.set(event, []);
        }
        this.events.get(event).push(callback);
        return () => this.off(event, callback);
    }
    
    emit(event, data) {
        const callbacks = this.events.get(event);
        if (callbacks) {
            callbacks.forEach(callback => {
                try {
                    callback(data);
                } catch (error) {
                    console.error('Error in event callback:', error);
                }
            });
        }
    }
    
    off(event, callback) {
        const callbacks = this.events.get(event);
        if (callbacks) {
            const index = callbacks.indexOf(callback);
            if (index > -1) {
                callbacks.splice(index, 1);
            }
        }
    }
}

class AdvancedCache {
    constructor() {
        this.memoryCache = new Map();
        this.dbName = 'RegistrationCache';
        this.version = 1;
        this.db = null;
    }
    
    async init() {
        if (!('indexedDB' in window)) return;
        
        return new Promise((resolve, reject) => {
            const request = indexedDB.open(this.dbName, this.version);
            
            request.onerror = () => reject(request.error);
            request.onsuccess = () => {
                this.db = request.result;
                resolve();
            };
            
            request.onupgradeneeded = (event) => {
                const db = event.target.result;
                if (!db.objectStoreNames.contains('validation')) {
                    const store = db.createObjectStore('validation', { keyPath: 'key' });
                    store.createIndex('timestamp', 'timestamp');
                }
            };
        });
    }
    
    async get(key) {
        // Tenta memory cache primeiro
        if (this.memoryCache.has(key)) {
            const item = this.memoryCache.get(key);
            if (item.expires > Date.now()) {
                return item.data;
            } else {
                this.memoryCache.delete(key);
            }
        }
        
        // Tenta IndexedDB
        if (!this.db) return null;
        
        return new Promise((resolve) => {
            const transaction = this.db.transaction(['validation'], 'readonly');
            const store = transaction.objectStore('validation');
            const request = store.get(key);
            
            request.onsuccess = () => {
                const result = request.result;
                if (result && result.expires > Date.now()) {
                    // Adiciona ao memory cache
                    this.memoryCache.set(key, result);
                    resolve(result.data);
                } else {
                    resolve(null);
                }
            };
            
            request.onerror = () => resolve(null);
        });
    }
    
    async set(key, data, ttl = 300000) { // 5 minutos padrão
        const expires = Date.now() + ttl;
        const item = { key, data, expires, timestamp: Date.now() };
        
        // Memory cache
        this.memoryCache.set(key, item);
        
        // IndexedDB
        if (!this.db) return;
        
        const transaction = this.db.transaction(['validation'], 'readwrite');
        const store = transaction.objectStore('validation');
        store.put(item);
    }
    
    async clear() {
        this.memoryCache.clear();
        
        if (!this.db) return;
        
        const transaction = this.db.transaction(['validation'], 'readwrite');
        const store = transaction.objectStore('validation');
        store.clear();
    }
}

class FraudDetector {
    constructor() {
        this.inputTimes = new Map();
        this.flags = [];
        this.startTime = Date.now();
    }
    
    analyzeInput(fieldName, value, timestamp) {
        const now = Date.now();
        
        // Análise de velocidade de digitação
        if (this.inputTimes.has(fieldName)) {
            const lastTime = this.inputTimes.get(fieldName);
            const timeDiff = now - lastTime;
            const charDiff = Math.abs(value.length - (this.lastValues?.get(fieldName)?.length || 0));
            
            if (timeDiff > 0 && charDiff > 0) {
                const charsPerSecond = (charDiff / timeDiff) * 1000;
                
                if (charsPerSecond > REGISTRATION_CONFIG.SECURITY.MAX_TYPING_SPEED) {
                    this.addFlag('typing_too_fast', {
                        field: fieldName,
                        charsPerSecond,
                        timestamp: now
                    });
                }
            }
        }
        
        // Análise de padrões suspeitos
        REGISTRATION_CONFIG.SECURITY.SUSPICIOUS_PATTERNS.forEach((pattern, index) => {
            if (pattern.test(value)) {
                this.addFlag('suspicious_pattern', {
                    field: fieldName,
                    patternIndex: index,
                    value: value.substring(0, 20) // Apenas início para privacidade
                });
            }
        });
        
        this.inputTimes.set(fieldName, now);
        
        if (!this.lastValues) this.lastValues = new Map();
        this.lastValues.set(fieldName, value);
    }
    
    addFlag(type, data) {
        this.flags.push({
            type,
            data,
            timestamp: Date.now()
        });
        
        console.warn(`🚨 Flag de fraude: ${type}`, data);
    }
    
    getFinalScore() {
        const weights = {
            typing_too_fast: 20,
            suspicious_pattern: 15,
            form_too_fast: 25,
            multiple_tabs: 10,
            automation_detected: 30
        };
        
        let score = 0;
        const flagCounts = {};
        
        this.flags.forEach(flag => {
            flagCounts[flag.type] = (flagCounts[flag.type] || 0) + 1;
            score += weights[flag.type] || 5;
        });
        
        // Penalidade adicional por múltiplas ocorrências
        Object.entries(flagCounts).forEach(([type, count]) => {
            if (count > 3) {
                score += (count - 3) * 10;
            }
        });
        
        const riskLevel = score >= 50 ? 'high' : score >= 25 ? 'medium' : 'low';
        
        return {
            score,
            riskLevel,
            flags: this.flags,
            flagCounts,
            sessionDuration: Date.now() - this.startTime
        };
    }
}

class TelemetrySystem {
    constructor() {
        this.events = [];
        this.startTime = Date.now();
        this.sessionId = this.generateSessionId();
    }
    
    generateSessionId() {
        return Date.now().toString(36) + Math.random().toString(36).substr(2);
    }
    
    start() {
        this.isRunning = true;
        
        // Coleta métricas de performance periodicamente
        if ('PerformanceObserver' in window) {
            try {
                const observer = new PerformanceObserver((list) => {
                    for (const entry of list.getEntries()) {
                        this.track('performance_entry', {
                            name: entry.name,
                            entryType: entry.entryType,
                            duration: entry.duration,
                            startTime: entry.startTime
                        });
                    }
                });
                
                observer.observe({ entryTypes: ['navigation', 'resource', 'measure'] });
            } catch (error) {
                console.warn('PerformanceObserver não suportado:', error);
            }
        }
    }
    
    track(eventType, data = {}) {
        if (!this.isRunning) return;
        
        const event = {
            type: eventType,
            data,
            timestamp: Date.now(),
            sessionId: this.sessionId,
            url: window.location.href,
            userAgent: navigator.userAgent
        };
        
        this.events.push(event);
        
        // Limita o número de eventos para evitar vazamento de memória
        if (this.events.length > 1000) {
            this.events = this.events.slice(-500); // Mantém os 500 mais recentes
        }
        
        // Debug em desenvolvimento
        if (window.location.hostname === 'localhost') {
            console.log(`📊 Telemetry [${eventType}]:`, data);
        }
    }
    
    trackError(errorType, errorData) {
        this.track('error', {
            errorType,
            ...errorData,
            stack: errorData.stack?.substring(0, 500) // Limita stack trace
        });
    }
    
    trackConversion(response) {
        this.track('conversion', {
            success: true,
            userId: response.data?.user_id,
            sessionDuration: Date.now() - this.startTime,
            totalEvents: this.events.length
        });
        
        // Envia dados críticos para analytics
        if (typeof gtag !== 'undefined') {
            gtag('event', 'sign_up', {
                method: 'form',
                value: 1,
                custom_parameter_session_duration: Math.floor((Date.now() - this.startTime) / 1000)
            });
        }
    }
    
    getSummary() {
        const eventTypes = {};
        let totalInteractions = 0;
        
        this.events.forEach(event => {
            eventTypes[event.type] = (eventTypes[event.type] || 0) + 1;
            if (event.type === 'field_interaction') {
                totalInteractions++;
            }
        });
        
        return {
            sessionId: this.sessionId,
            sessionDuration: Date.now() - this.startTime,
            totalEvents: this.events.length,
            totalInteractions,
            eventTypes,
            timestamp: Date.now()
        };
    }
    
    async sendBatch() {
        if (this.events.length === 0) return;
        
        try {
            const payload = {
                sessionId: this.sessionId,
                events: this.events.slice(), // Copia dos eventos
                metadata: {
                    userAgent: navigator.userAgent,
                    url: window.location.href,
                    timestamp: Date.now(),
                    timezone: Intl.DateTimeFormat().resolvedOptions().timeZone
                }
            };
            
            // Envia para endpoint de telemetria (se existir)
            await fetch('/api/telemetry.php', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'X-Requested-With': 'XMLHttpRequest'
                },
                body: JSON.stringify(payload)
            });
            
            // Limpa eventos enviados
            this.events = [];
            
        } catch (error) {
            console.warn('Falha ao enviar telemetria:', error);
        }
    }
}

class AccessibilityManager {
    constructor() {
        this.announcements = [];
        this.focusHistory = [];
        this.setupAnnouncer();
    }
    
    async init() {
        this.detectReducedMotion();
        this.detectHighContrast();
        this.setupKeyboardTraps();
        this.enhanceFormLabels();
    }
    
    setupAnnouncer() {
        // Cria região ARIA live para anúncios
        this.announcer = document.createElement('div');
        this.announcer.setAttribute('aria-live', 'polite');
        this.announcer.setAttribute('aria-atomic', 'true');
        this.announcer.className = 'sr-only';
        this.announcer.style.cssText = `
            position: absolute !important;
            left: -10000px !important;
            width: 1px !important;
            height: 1px !important;
            overflow: hidden !important;
            clip: rect(1px, 1px, 1px, 1px) !important;
            white-space: nowrap !important;
        `;
        
        document.body.appendChild(this.announcer);
        
        // Announcer para alertas urgentes
        this.alertAnnouncer = this.announcer.cloneNode(true);
        this.alertAnnouncer.setAttribute('aria-live', 'assertive');
        document.body.appendChild(this.alertAnnouncer);
    }
    
    announce(message, priority = 'polite') {
        const announcer = priority === 'assertive' ? this.alertAnnouncer : this.announcer;
        
        // Limpa mensagem anterior
        announcer.textContent = '';
        
        // Adiciona nova mensagem após pequeno delay para garantir que seja lida
        setTimeout(() => {
            announcer.textContent = message;
        }, 100);
        
        this.announcements.push({
            message,
            priority,
            timestamp: Date.now()
        });
        
        // Limita histórico de anúncios
        if (this.announcements.length > 10) {
            this.announcements = this.announcements.slice(-5);
        }
    }
    
    detectReducedMotion() {
        const mediaQuery = window.matchMedia('(prefers-reduced-motion: reduce)');
        this.reducedMotion = mediaQuery.matches;
        
        mediaQuery.addEventListener('change', (e) => {
            this.reducedMotion = e.matches;
            document.documentElement.classList.toggle('reduced-motion', this.reducedMotion);
        });
        
        if (this.reducedMotion) {
            document.documentElement.classList.add('reduced-motion');
        }
    }
    
    detectHighContrast() {
        const mediaQuery = window.matchMedia('(prefers-contrast: high)');
        this.highContrast = mediaQuery.matches;
        
        mediaQuery.addEventListener('change', (e) => {
            this.highContrast = e.matches;
            document.documentElement.classList.toggle('high-contrast', this.highContrast);
        });
        
        if (this.highContrast) {
            document.documentElement.classList.add('high-contrast');
        }
    }
    
    setupKeyboardTraps() {
        // Monitora navegação por teclado
        let isTabbing = false;
        
        document.addEventListener('keydown', (e) => {
            if (e.key === 'Tab') {
                isTabbing = true;
                document.body.classList.add('keyboard-navigation');
            } else if (e.key === 'Escape') {
                // Remove foco de elemento ativo se necessário
                if (document.activeElement && document.activeElement.blur) {
                    document.activeElement.blur();
                }
            }
        });
        
        document.addEventListener('mousedown', () => {
            if (isTabbing) {
                isTabbing = false;
                document.body.classList.remove('keyboard-navigation');
            }
        });
        
        // Melhora foco visível
        document.addEventListener('focusin', (e) => {
            this.focusHistory.push({
                element: e.target,
                timestamp: Date.now()
            });
            
            // Limita histórico
            if (this.focusHistory.length > 20) {
                this.focusHistory = this.focusHistory.slice(-10);
            }
        });
    }
    
    enhanceFormLabels() {
        // Melhora labels de formulário
        const inputs = document.querySelectorAll('input, select, textarea');
        
        inputs.forEach(input => {
            if (!input.getAttribute('aria-label') && !input.getAttribute('aria-labelledby')) {
                const label = document.querySelector(`label[for="${input.id}"]`);
                if (label) {
                    input.setAttribute('aria-labelledby', input.id + '-label');
                    label.id = input.id + '-label';
                }
            }
            
            // Adiciona descrições para campos obrigatórios
            if (input.hasAttribute('required') && !input.getAttribute('aria-describedby')) {
                const description = document.createElement('span');
                description.id = input.id + '-required';
                description.className = 'sr-only';
                description.textContent = 'campo obrigatório';
                
                input.parentNode.appendChild(description);
                
                const describedBy = input.getAttribute('aria-describedby');
                input.setAttribute('aria-describedby', 
                    describedBy ? `${describedBy} ${description.id}` : description.id
                );
            }
        });
    }
    
    getLastFocusedElement() {
        return this.focusHistory[this.focusHistory.length - 1]?.element || null;
    }
    
    restoreFocus() {
        const lastFocused = this.getLastFocusedElement();
        if (lastFocused && document.contains(lastFocused)) {
            lastFocused.focus();
        }
    }
}

class MicroAnimator {
    constructor() {
        this.running = new Set();
        this.reducedMotion = window.matchMedia('(prefers-reduced-motion: reduce)').matches;
    }
    
    async fadeIn(element, duration = 300) {
        if (this.reducedMotion) {
            element.style.opacity = '1';
            return Promise.resolve();
        }
        
        return new Promise(resolve => {
            element.style.opacity = '0';
            element.style.transition = `opacity ${duration}ms cubic-bezier(0.4, 0, 0.2, 1)`;
            
            requestAnimationFrame(() => {
                element.style.opacity = '1';
                
                setTimeout(() => {
                    element.style.transition = '';
                    resolve();
                }, duration);
            });
        });
    }
    
    async fadeOut(element, duration = 300) {
        if (this.reducedMotion) {
            element.style.opacity = '0';
            return Promise.resolve();
        }
        
        return new Promise(resolve => {
            element.style.transition = `opacity ${duration}ms cubic-bezier(0.4, 0, 0.2, 1)`;
            element.style.opacity = '0';
            
            setTimeout(() => {
                element.style.transition = '';
                resolve();
            }, duration);
        });
    }
    
    async slideIn(element, direction = 'right', duration = 300) {
        if (this.reducedMotion) {
            element.style.transform = 'translateX(0)';
            return Promise.resolve();
        }
        
        const transforms = {
            right: 'translateX(100%)',
            left: 'translateX(-100%)',
            up: 'translateY(-100%)',
            down: 'translateY(100%)'
        };
        
        return new Promise(resolve => {
            element.style.transform = transforms[direction] || transforms.right;
            element.style.transition = `transform ${duration}ms cubic-bezier(0.4, 0, 0.2, 1)`;
            
            requestAnimationFrame(() => {
                element.style.transform = 'translate(0)';
                
                setTimeout(() => {
                    element.style.transition = '';
                    resolve();
                }, duration);
            });
        });
    }
    
    async slideOut(element, direction = 'right', duration = 300) {
        if (this.reducedMotion) {
            return Promise.resolve();
        }
        
        const transforms = {
            right: 'translateX(100%)',
            left: 'translateX(-100%)',
            up: 'translateY(-100%)',
            down: 'translateY(100%)'
        };
        
        return new Promise(resolve => {
            element.style.transition = `transform ${duration}ms cubic-bezier(0.4, 0, 0.2, 1)`;
            element.style.transform = transforms[direction] || transforms.right;
            
            setTimeout(() => {
                element.style.transition = '';
                resolve();
            }, duration);
        });
    }
    
    async slideDown(element, duration = 300) {
        if (this.reducedMotion) {
            element.style.display = 'block';
            return Promise.resolve();
        }
        
        return new Promise(resolve => {
            element.style.display = 'block';
            element.style.height = '0';
            element.style.overflow = 'hidden';
            element.style.transition = `height ${duration}ms cubic-bezier(0.4, 0, 0.2, 1)`;
            
            const targetHeight = element.scrollHeight + 'px';
            
            requestAnimationFrame(() => {
                element.style.height = targetHeight;
                
                setTimeout(() => {
                    element.style.height = '';
                    element.style.overflow = '';
                    element.style.transition = '';
                    resolve();
                }, duration);
            });
        });
    }
    
    async slideUp(element, duration = 300) {
        if (this.reducedMotion) {
            element.style.display = 'none';
            return Promise.resolve();
        }
        
        return new Promise(resolve => {
            element.style.height = element.scrollHeight + 'px';
            element.style.overflow = 'hidden';
            element.style.transition = `height ${duration}ms cubic-bezier(0.4, 0, 0.2, 1)`;
            
            requestAnimationFrame(() => {
                element.style.height = '0';
                
                setTimeout(() => {
                    element.style.display = 'none';
                    element.style.height = '';
                    element.style.overflow = '';
                    element.style.transition = '';
                    resolve();
                }, duration);
            });
        });
    }
    
    async scale(element, options = {}, duration = 300) {
        if (this.reducedMotion) {
            element.style.transform = `scale(${options.to || 1})`;
            return Promise.resolve();
        }
        
        const from = options.from || 0.8;
        const to = options.to || 1;
        
        return new Promise(resolve => {
            element.style.transform = `scale(${from})`;
            element.style.transition = `transform ${duration}ms cubic-bezier(0.4, 0, 0.2, 1)`;
            
            requestAnimationFrame(() => {
                element.style.transform = `scale(${to})`;
                
                setTimeout(() => {
                    element.style.transition = '';
                    resolve();
                }, duration);
            });
        });
    }
    
    async pulse(element, intensity = 1) {
        if (this.reducedMotion) return Promise.resolve();
        
        const keyframes = [
            { transform: 'scale(1)', opacity: '1' },
            { transform: `scale(${1 + (intensity * 0.05)})`, opacity: '0.9' },
            { transform: 'scale(1)', opacity: '1' }
        ];
        
        const animation = element.animate(keyframes, {
            duration: 200,
            easing: 'ease-in-out'
        });
        
        return animation.finished;
    }
    
    async morphWidth(element, targetWidth, duration = 300) {
        if (this.reducedMotion) {
            element.style.width = targetWidth;
            return Promise.resolve();
        }
        
        return new Promise(resolve => {
            element.style.transition = `width ${duration}ms cubic-bezier(0.4, 0, 0.2, 1)`;
            element.style.width = targetWidth;
            
            setTimeout(() => {
                element.style.transition = '';
                resolve();
            }, duration);
        });
    }
    
    async parallel(animations) {
        return Promise.all(animations);
    }
}

// ==============================================================================
// 12. VALIDADORES ESPECIALIZADOS
// ==============================================================================

class BaseValidator {
    constructor() {
        this.hasRemoteValidation = false;
    }
    
    async validateLocal(value) {
        return { valid: true };
    }
    
    async validateRemote(value) {
        return { valid: true };
    }
}

class NameValidator extends BaseValidator {
    async validateLocal(value) {
        if (!value || value.trim().length < 2) {
            return { valid: false, message: 'Nome deve ter pelo menos 2 caracteres' };
        }
        
        if (value.trim().length > 120) {
            return { valid: false, message: 'Nome muito longo (máximo 120 caracteres)' };
        }
        
        if (!/^[\p{L}\s'-.]+$/u.test(value)) {
            return { valid: false, message: 'Nome contém caracteres inválidos' };
        }
        
        const words = value.trim().split(/\s+/);
        if (words.length < 2) {
            return { valid: false, message: 'Digite seu nome completo' };
        }
        
        // Verifica se não é apenas números
        if (/^\d+$/.test(value.replace(/\s/g, ''))) {
            return { valid: false, message: 'Nome não pode conter apenas números' };
        }
        
        return { valid: true };
    }
}

class CPFValidator extends BaseValidator {
    constructor() {
        super();
        this.hasRemoteValidation = true;
    }
    
    async validateLocal(value) {
        const numbers = value.replace(/\D/g, '');
        
        if (numbers.length !== 11) {
            return { valid: false, message: 'CPF deve ter 11 dígitos' };
        }
        
        // Verifica sequências repetidas
        if (/^(\d)\1{10}$/.test(numbers)) {
            return { valid: false, message: 'CPF inválido' };
        }
        
        // Algoritmo de validação do CPF
        if (!this.validateCPFAlgorithm(numbers)) {
            return { valid: false, message: 'CPF inválido' };
        }
        
        return { valid: true };
    }
    
    validateCPFAlgorithm(cpf) {
        let sum = 0;
        let remainder;
        
        // Primeiro dígito verificador
        for (let i = 1; i <= 9; i++) {
            sum += parseInt(cpf.substring(i - 1, i)) * (11 - i);
        }
        
        remainder = (sum * 10) % 11;
        if (remainder === 10 || remainder === 11) remainder = 0;
        if (remainder !== parseInt(cpf.substring(9, 10))) return false;
        
        sum = 0;
        
        // Segundo dígito verificador
        for (let i = 1; i <= 10; i++) {
            sum += parseInt(cpf.substring(i - 1, i)) * (12 - i);
        }
        
        remainder = (sum * 10) % 11;
        if (remainder === 10 || remainder === 11) remainder = 0;
        if (remainder !== parseInt(cpf.substring(10, 11))) return false;
        
        return true;
    }
}

class EmailValidator extends BaseValidator {
    constructor() {
        super();
        this.hasRemoteValidation = true;
    }
    
    async validateLocal(value) {
        if (!value || value.trim().length === 0) {
            return { valid: false, message: 'E-mail é obrigatório' };
        }
        
        const email = value.trim().toLowerCase();
        
        // RFC 5322 compliant regex (simplificado)
        const emailRegex = /^[a-zA-Z0-9.!#$%&'*+/=?^_`{|}~-]+@[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$/;
        
        if (!emailRegex.test(email)) {
            return { valid: false, message: 'E-mail inválido' };
        }
        
        if (email.length > 255) {
            return { valid: false, message: 'E-mail muito longo' };
        }
        
        // Verifica domínios suspeitos
        const suspiciousDomains = [
            'tempmail.org', 'guerrillamail.com', 'mailinator.com',
            '10minutemail.com', 'throwaway.email', 'temp-mail.org'
        ];
        
        const domain = email.split('@')[1];
        if (suspiciousDomains.includes(domain)) {
            return { valid: false, message: 'E-mail temporário não é permitido' };
        }
        
        return { valid: true };
    }
}

class PhoneValidator extends BaseValidator {
    async validateLocal(value) {
        const numbers = value.replace(/\D/g, '');
        
        if (numbers.length < 10 || numbers.length > 11) {
            return { valid: false, message: 'Número de celular inválido' };
        }
        
        // Verifica DDD válido
        const ddd = parseInt(numbers.substring(0, 2));
        const validDDDs = [
            11, 12, 13, 14, 15, 16, 17, 18, 19, // SP
            21, 22, 24, 27, 28, // RJ/ES
            31, 32, 33, 34, 35, 37, 38, // MG
            41, 42, 43, 44, 45, 46, // PR
            47, 48, 49, // SC
            51, 53, 54, 55, // RS
            61, 62, 63, 64, 65, 66, 67, 68, 69, // Centro-Oeste
            71, 73, 74, 75, 77, 79, // Nordeste
            81, 82, 83, 84, 85, 86, 87, 88, 89, // Nordeste
            91, 92, 93, 94, 95, 96, 97, 98, 99  // Norte
        ];
        
        if (!validDDDs.includes(ddd)) {
            return { valid: false, message: 'DDD inválido' };
        }
        
        // Para celular (11 dígitos), deve começar com 9
        if (numbers.length === 11 && numbers.charAt(2) !== '9') {
            return { valid: false, message: 'Celular deve começar com 9' };
        }
        
        return { valid: true };
    }
}

class CNPJValidator extends BaseValidator {
    constructor() {
        super();
        this.hasRemoteValidation = true;
    }
    
    async validateLocal(value) {
        const numbers = value.replace(/\D/g, '');
        
        if (numbers.length !== 14) {
            return { valid: false, message: 'CNPJ deve ter 14 dígitos' };
        }
        
        // Verifica sequências repetidas
        if (/^(\d)\1{13}$/.test(numbers)) {
            return { valid: false, message: 'CNPJ inválido' };
        }
        
        // Algoritmo de validação do CNPJ
        if (!this.validateCNPJAlgorithm(numbers)) {
            return { valid: false, message: 'CNPJ inválido' };
        }
        
        return { valid: true };
    }
    
    validateCNPJAlgorithm(cnpj) {
        const weights1 = [5, 4, 3, 2, 9, 8, 7, 6, 5, 4, 3, 2];
        const weights2 = [6, 5, 4, 3, 2, 9, 8, 7, 6, 5, 4, 3, 2];
        
        let sum = 0;
        
        // Primeiro dígito verificador
        for (let i = 0; i < 12; i++) {
            sum += parseInt(cnpj.charAt(i)) * weights1[i];
        }
        
        let remainder = sum % 11;
        const digit1 = remainder < 2 ? 0 : 11 - remainder;
        
        if (digit1 !== parseInt(cnpj.charAt(12))) {
            return false;
        }
        
        sum = 0;
        
        // Segundo dígito verificador
        for (let i = 0; i < 13; i++) {
            sum += parseInt(cnpj.charAt(i)) * weights2[i];
        }
        
        remainder = sum % 11;
        const digit2 = remainder < 2 ? 0 : 11 - remainder;
        
        return digit2 === parseInt(cnpj.charAt(13));
    }
}

class PasswordValidator extends BaseValidator {
    async validateLocal(value) {
        if (!value || value.length === 0) {
            return { valid: false, message: 'Senha é obrigatória' };
        }
        
        const errors = [];
        
        if (value.length < 8) {
            errors.push('mínimo 8 caracteres');
        }
        
        if (!/[A-Z]/.test(value)) {
            errors.push('1 letra maiúscula');
        }
        
        if (!/[a-z]/.test(value)) {
            errors.push('1 letra minúscula');
        }
        
        if (!/[0-9]/.test(value)) {
            errors.push('1 número');
        }
        
        if (!/[^A-Za-z0-9]/.test(value)) {
            errors.push('1 símbolo especial');
        }
        
        // Senhas comuns
        const commonPasswords = ['password', '123456789', '12345678', 'qwerty', 'abc123'];
        if (commonPasswords.some(common => value.toLowerCase().includes(common))) {
            errors.push('evite senhas comuns');
        }
        
        if (errors.length > 0) {
            return { valid: false, message: `Senha deve ter: ${errors.join(', ')}` };
        }
        
        return { valid: true };
    }
}

class PasswordConfirmValidator extends BaseValidator {
    async validateLocal(value, originalPassword) {
        if (!value) {
            return { valid: false, message: 'Confirmação de senha é obrigatória' };
        }
        
        const senhaOriginal = document.getElementById('senha')?.value || '';
        
        if (value !== senhaOriginal) {
            return { valid: false, message: 'As senhas não coincidem' };
        }
        
        return { valid: true };
    }
}

// ==============================================================================
// 13. FORMATADORES
// ==============================================================================

class BaseFormatter {
    format(value) {
        return value;
    }
}

class CPFFormatter extends BaseFormatter {
    format(value) {
        const numbers = value.replace(/\D/g, '').substring(0, 11);
        
        if (numbers.length <= 3) {
            return numbers;
        } else if (numbers.length <= 6) {
            return numbers.replace(/(\d{3})(\d+)/, '$1.$2');
        } else if (numbers.length <= 9) {
            return numbers.replace(/(\d{3})(\d{3})(\d+)/, '$1.$2.$3');
        } else {
            return numbers.replace(/(\d{3})(\d{3})(\d{3})(\d+)/, '$1.$2.$3-$4');
        }
    }
}

class CNPJFormatter extends BaseFormatter {
    format(value) {
        const numbers = value.replace(/\D/g, '').substring(0, 14);
        
        if (numbers.length <= 2) {
            return numbers;
        } else if (numbers.length <= 5) {
            return numbers.replace(/(\d{2})(\d+)/, '$1.$2');
        } else if (numbers.length <= 8) {
            return numbers.replace(/(\d{2})(\d{3})(\d+)/, '$1.$2.$3');
        } else if (numbers.length <= 12) {
            return numbers.replace(/(\d{2})(\d{3})(\d{3})(\d+)/, '$1.$2.$3/$4');
        } else {
            return numbers.replace(/(\d{2})(\d{3})(\d{3})(\d{4})(\d+)/, '$1.$2.$3/$4-$5');
        }
    }
}

class PhoneFormatter extends BaseFormatter {
    format(value) {
        let numbers = value.replace(/\D/g, '');
        
        // Remove 55 se digitado (evita duplicação)
        if (numbers.startsWith('55') && numbers.length > 11) {
            numbers = numbers.substring(2);
        }
        
        numbers = numbers.substring(0, 11);
        
        if (numbers.length === 0) {
            return '';
        } else if (numbers.length <= 2) {
            return `+55 (${numbers}`;
        } else if (numbers.length <= 7) {
            return `+55 (${numbers.substring(0, 2)}) ${numbers.substring(2)}`;
        } else {
            const ddd = numbers.substring(0, 2);
            const first = numbers.substring(2, 7);
            const second = numbers.substring(7);
            return `+55 (${ddd}) ${first}${second ? '-' + second : ''}`;
        }
    }
}

class NameFormatter extends BaseFormatter {
    format(value) {
        return value
            .toLowerCase()
            .split(' ')
            .map(word => {
                if (word.length === 0) return word;
                
                // Preposições ficam em minúscula
                const lowercase = ['de', 'da', 'do', 'das', 'dos', 'e', 'em', 'na', 'no'];
                if (lowercase.includes(word)) {
                    return word;
                }
                
                // Primeira letra maiúscula
                return word.charAt(0).toUpperCase() + word.slice(1);
            })
            .join(' ');
    }
}

// ==============================================================================
// 14. INICIALIZAÇÃO GLOBAL
// ==============================================================================

// Aguarda DOM estar pronto
function initializeRegistrationSystem() {
    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', () => {
            window.registrationSystem = new AdvancedRegistrationSystem();
        });
    } else {
        window.registrationSystem = new AdvancedRegistrationSystem();
    }
}

// Inicialização
initializeRegistrationSystem();

// Exporta para testes (se em ambiente de desenvolvimento)
if (typeof module !== 'undefined' && module.exports) {
    module.exports = {
        AdvancedRegistrationSystem,
        FraudDetector,
        TelemetrySystem,
        AccessibilityManager,
        MicroAnimator,
        AdvancedCache,
        // Validadores
        NameValidator,
        CPFValidator,
        EmailValidator,
        PhoneValidator,
        CNPJValidator,
        PasswordValidator,
        PasswordConfirmValidator,
        // Formatadores
        CPFFormatter,
        CNPJFormatter,
        PhoneFormatter,
        NameFormatter
    };
}

// ==============================================================================
// 15. POLYFILLS E COMPATIBILIDADE
// ==============================================================================

// Polyfill para Element.closest (IE/Edge antigo)
if (!Element.prototype.closest) {
    Element.prototype.closest = function(s) {
        var el = this;
        do {
            if (el.matches(s)) return el;
            el = el.parentElement || el.parentNode;
        } while (el !== null && el.nodeType === 1);
        return null;
    };
}

// Polyfill para Element.matches
if (!Element.prototype.matches) {
    Element.prototype.matches = Element.prototype.matchesSelector ||
        Element.prototype.mozMatchesSelector ||
        Element.prototype.msMatchesSelector ||
        Element.prototype.oMatchesSelector ||
        Element.prototype.webkitMatchesSelector ||
        function(s) {
            var matches = (this.document || this.ownerDocument).querySelectorAll(s),
                i = matches.length;
            while (--i >= 0 && matches.item(i) !== this) {}
            return i > -1;
        };
}

// Polyfill para Promise.allSettled
if (!Promise.allSettled) {
    Promise.allSettled = function(promises) {
        return Promise.all(promises.map(promise =>
            Promise.resolve(promise)
                .then(value => ({ status: 'fulfilled', value }))
                .catch(reason => ({ status: 'rejected', reason }))
        ));
    };
}

// Polyfill para Array.prototype.includes
if (!Array.prototype.includes) {
    Array.prototype.includes = function(searchElement, fromIndex) {
        if (this == null) {
            throw new TypeError('"this" is null or not defined');
        }
        
        var o = Object(this);
        var len = parseInt(o.length) || 0;
        
        if (len === 0) {
            return false;
        }
        
        var n = parseInt(fromIndex) || 0;
        var k;
        
        if (n >= 0) {
            k = n;
        } else {
            k = len + n;
            if (k < 0) {
                k = 0;
            }
        }
        
        function sameValueZero(x, y) {
            return x === y || (typeof x === 'number' && typeof y === 'number' && isNaN(x) && isNaN(y));
        }
        
        while (k < len) {
            if (sameValueZero(o[k], searchElement)) {
                return true;
            }
            k++;
        }
        
        return false;
    };
}

// ==============================================================================
// 16. SERVICE WORKER HELPER
// ==============================================================================

// Registra service worker específico para cadastro (cache de validações)
if ('serviceWorker' in navigator && window.location.protocol === 'https:') {
    window.addEventListener('load', async () => {
        try {
            const registration = await navigator.serviceWorker.register('/sw-cadastro.js', {
                scope: '/cadastro'
            });
            
            console.log('📱 Service Worker registrado:', registration.scope);
            
            // Escuta atualizações
            registration.addEventListener('updatefound', () => {
                const newWorker = registration.installing;
                newWorker.addEventListener('statechange', () => {
                    if (newWorker.state === 'installed' && navigator.serviceWorker.controller) {
                        // Nova versão disponível
                        if (window.registrationSystem) {
                            window.registrationSystem.showNotification(
                                'Nova versão disponível. Recarregue a página.',
                                'info',
                                0
                            );
                        }
                    }
                });
            });
            
        } catch (error) {
            console.warn('Service Worker registration failed:', error);
        }
    });
}

// ==============================================================================
// 17. UTILITÁRIOS GLOBAIS
// ==============================================================================

/**
 * Utilitários globais para debug e desenvolvimento
 */
window.RegistrationUtils = {
    // Debug helpers
    debug: {
        getState() {
            return window.registrationSystem?.state || null;
        },
        
        getValidationState() {
            return window.registrationSystem?.state.validationState || null;
        },
        
        getTelemetryEvents() {
            return window.registrationSystem?.telemetry.events || [];
        },
        
        getFraudScore() {
            return window.registrationSystem?.fraudDetector.getFinalScore() || null;
        },
        
        clearCache() {
            return window.registrationSystem?.cache.clear();
        },
        
        forceValidateAll() {
            const system = window.registrationSystem;
            if (!system) return;
            
            const fields = ['nome', 'cpf', 'email', 'celular', 'cnpj', 'senha', 'confirmarSenha'];
            fields.forEach(field => {
                const element = system.elements.get(field);
                if (element && element.value) {
                    system.validateField(field, element.value, true);
                }
            });
        }
    },
    
    // Test helpers
    test: {
        fillForm(testData = {}) {
            const system = window.registrationSystem;
            if (!system) return;
            
            const defaultData = {
                nome: 'João Silva Santos',
                cpf: '12345678901',
                email: 'joao.test@exemplo.com',
                celular: '47999887766',
                cnpj: '12345678901234',
                senha: 'MinhaSenh@123',
                confirmarSenha: 'MinhaSenh@123'
            };
            
            const data = { ...defaultData, ...testData };
            
            Object.entries(data).forEach(([field, value]) => {
                const element = system.elements.get(field);
                if (element) {
                    element.value = value;
                    element.dispatchEvent(new Event('input', { bubbles: true }));
                    element.dispatchEvent(new Event('blur', { bubbles: true }));
                }
            });
            
            // Aceita termos
            const termos = system.elements.get('termos');
            if (termos) {
                termos.checked = true;
                termos.dispatchEvent(new Event('change', { bubbles: true }));
            }
        },
        
        simulateSlowTyping(text, fieldName, delay = 100) {
            const system = window.registrationSystem;
            const element = system?.elements.get(fieldName);
            
            if (!element) return;
            
            let i = 0;
            const typeChar = () => {
                if (i < text.length) {
                    element.value = text.substring(0, i + 1);
                    element.dispatchEvent(new Event('input', { bubbles: true }));
                    i++;
                    setTimeout(typeChar, delay);
                } else {
                    element.dispatchEvent(new Event('blur', { bubbles: true }));
                }
            };
            
            element.value = '';
            element.focus();
            typeChar();
        },
        
        simulateFastTyping(text, fieldName) {
            this.simulateSlowTyping(text, fieldName, 10); // 10ms entre caracteres
        }
    }
};

// ==============================================================================
// 18. ERROR BOUNDARY E RECOVERY
// ==============================================================================

/**
 * Sistema de recuperação de erros
 */
class ErrorBoundary {
    constructor() {
        this.errors = [];
        this.maxErrors = 10;
        this.setupGlobalHandlers();
    }
    
    setupGlobalHandlers() {
        // Captura erros JavaScript
        window.addEventListener('error', (event) => {
            this.handleError({
                type: 'javascript',
                message: event.message,
                filename: event.filename,
                lineno: event.lineno,
                colno: event.colno,
                stack: event.error?.stack,
                timestamp: Date.now()
            });
        });
        
        // Captura promessas rejeitadas
        window.addEventListener('unhandledrejection', (event) => {
            this.handleError({
                type: 'promise_rejection',
                reason: event.reason,
                timestamp: Date.now()
            });
        });
    }
    
    handleError(error) {
        this.errors.push(error);
        
        // Limita número de erros armazenados
        if (this.errors.length > this.maxErrors) {
            this.errors = this.errors.slice(-this.maxErrors / 2);
        }
        
        console.error('🚨 Error captured by ErrorBoundary:', error);
        
        // Envia erro para telemetria
        if (window.registrationSystem?.telemetry) {
            window.registrationSystem.telemetry.trackError('error_boundary', error);
        }
        
        // Tenta recuperação automática para erros conhecidos
        this.attemptRecovery(error);
    }
    
    attemptRecovery(error) {
        // Recuperação para erros de rede
        if (error.message?.includes('fetch') || error.message?.includes('network')) {
            this.showRecoveryOptions('network');
        }
        
        // Recuperação para erros de validação
        if (error.message?.includes('validation') || error.filename?.includes('cadastro')) {
            this.showRecoveryOptions('validation');
        }
    }
    
    showRecoveryOptions(type) {
        const system = window.registrationSystem;
        if (!system) return;
        
        const messages = {
            network: 'Erro de conexão detectado. Verifique sua internet e tente novamente.',
            validation: 'Erro na validação. Os dados serão revalidados automaticamente.',
            general: 'Erro detectado. O sistema tentará se recuperar automaticamente.'
        };
        
        system.showNotification(
            messages[type] || messages.general,
            'warning',
            5000
        );
        
        // Ações específicas de recuperação
        switch (type) {
            case 'network':
                // Retry automático após delay
                setTimeout(() => {
                    if (navigator.onLine) {
                        system.showNotification('Conexão restaurada.', 'success', 2000);
                    }
                }, 3000);
                break;
                
            case 'validation':
                // Revalida campos automaticamente
                setTimeout(() => {
                    if (system.debug) {
                        system.debug.forceValidateAll();
                    }
                }, 1000);
                break;
        }
    }
    
    getErrorSummary() {
        const errorTypes = {};
        this.errors.forEach(error => {
            errorTypes[error.type] = (errorTypes[error.type] || 0) + 1;
        });
        
        return {
            totalErrors: this.errors.length,
            errorTypes,
            lastError: this.errors[this.errors.length - 1] || null,
            timestamp: Date.now()
        };
    }
}

// Inicializa Error Boundary
const errorBoundary = new ErrorBoundary();

// ==============================================================================
// 19. PERFORMANCE MONITOR
// ==============================================================================

/**
 * Monitor de performance em tempo real
 */
class PerformanceMonitor {
    constructor() {
        this.metrics = {
            loadTime: 0,
            firstInput: 0,
            memoryUsage: 0,
            networkSpeed: 0,
            renderTime: 0
        };
        
        this.observers = [];
        this.startMonitoring();
    }
    
    startMonitoring() {
        // Performance Observer para métricas essenciais
        if ('PerformanceObserver' in window) {
            this.setupPerformanceObserver();
        }
        
        // Memory monitoring (se disponível)
        if ('memory' in performance) {
            this.monitorMemoryUsage();
        }
        
        // Network monitoring
        this.monitorNetworkSpeed();
        
        // First Input Delay
        this.monitorFirstInputDelay();
    }
    
    setupPerformanceObserver() {
        try {
            // Largest Contentful Paint
            const lcpObserver = new PerformanceObserver((entryList) => {
                const entries = entryList.getEntries();
                const lastEntry = entries[entries.length - 1];
                this.metrics.renderTime = lastEntry.renderTime || lastEntry.loadTime;
            });
            lcpObserver.observe({ entryTypes: ['largest-contentful-paint'] });
            this.observers.push(lcpObserver);
            
            // First Input Delay
            const fidObserver = new PerformanceObserver((entryList) => {
                const entries = entryList.getEntries();
                entries.forEach((entry) => {
                    this.metrics.firstInput = entry.processingStart - entry.startTime;
                });
            });
            fidObserver.observe({ entryTypes: ['first-input'] });
            this.observers.push(fidObserver);
            
            // Navigation timing
            const navObserver = new PerformanceObserver((entryList) => {
                const entries = entryList.getEntries();
                entries.forEach((entry) => {
                    this.metrics.loadTime = entry.loadEventEnd - entry.loadEventStart;
                });
            });
            navObserver.observe({ entryTypes: ['navigation'] });
            this.observers.push(navObserver);
            
        } catch (error) {
            console.warn('PerformanceObserver setup failed:', error);
        }
    }
    
    monitorMemoryUsage() {
        setInterval(() => {
            if (performance.memory) {
                this.metrics.memoryUsage = {
                    used: performance.memory.usedJSHeapSize,
                    total: performance.memory.totalJSHeapSize,
                    limit: performance.memory.jsHeapSizeLimit
                };
            }
        }, 10000); // A cada 10 segundos
    }
    
    monitorNetworkSpeed() {
        if ('connection' in navigator) {
            this.metrics.networkSpeed = {
                effectiveType: navigator.connection.effectiveType,
                downlink: navigator.connection.downlink,
                rtt: navigator.connection.rtt
            };
            
            navigator.connection.addEventListener('change', () => {
                this.metrics.networkSpeed = {
                    effectiveType: navigator.connection.effectiveType,
                    downlink: navigator.connection.downlink,
                    rtt: navigator.connection.rtt
                };
            });
        }
    }
    
    monitorFirstInputDelay() {
        let firstInputProcessed = false;
        
        ['click', 'keydown', 'touchstart'].forEach(eventType => {
            document.addEventListener(eventType, (event) => {
                if (!firstInputProcessed) {
                    firstInputProcessed = true;
                    
                    // Simula medição de FID
                    const startTime = performance.now();
                    
                    requestIdleCallback(() => {
                        this.metrics.firstInput = performance.now() - startTime;
                    });
                }
            }, { once: true, passive: true });
        });
    }
    
    getMetrics() {
        return {
            ...this.metrics,
            timestamp: Date.now(),
            url: window.location.href,
            userAgent: navigator.userAgent
        };
    }
    
    assessPerformance() {
        const assessment = {
            score: 100,
            issues: [],
            recommendations: []
        };
        
        // Avalia tempo de carregamento
        if (this.metrics.loadTime > 3000) {
            assessment.score -= 20;
            assessment.issues.push('Tempo de carregamento lento');
            assessment.recommendations.push('Otimizar recursos estáticos');
        }
        
        // Avalia First Input Delay
        if (this.metrics.firstInput > 100) {
            assessment.score -= 15;
            assessment.issues.push('Demora na primeira interação');
            assessment.recommendations.push('Reduzir JavaScript no thread principal');
        }
        
        // Avalia uso de memória
        if (this.metrics.memoryUsage && this.metrics.memoryUsage.used > 50000000) { // 50MB
            assessment.score -= 10;
            assessment.issues.push('Alto uso de memória');
            assessment.recommendations.push('Otimizar cache e limpeza de objetos');
        }
        
        // Avalia conexão de rede
        if (this.metrics.networkSpeed?.effectiveType === 'slow-2g' || 
            this.metrics.networkSpeed?.effectiveType === '2g') {
            assessment.score -= 25;
            assessment.issues.push('Conexão lenta detectada');
            assessment.recommendations.push('Implementar modo offline/light');
        }
        
        return {
            ...assessment,
            grade: assessment.score >= 80 ? 'A' : 
                   assessment.score >= 60 ? 'B' : 
                   assessment.score >= 40 ? 'C' : 'D'
        };
    }
    
    cleanup() {
        this.observers.forEach(observer => observer.disconnect());
        this.observers = [];
    }
}

// Inicializa monitor de performance
const performanceMonitor = new PerformanceMonitor();

// Disponibiliza globalmente para debug
window.RegistrationPerformance = {
    getMetrics: () => performanceMonitor.getMetrics(),
    assess: () => performanceMonitor.assessPerformance(),
    monitor: performanceMonitor
};

// ==============================================================================
// 20. CLEANUP E FINALIZAÇÃO
// ==============================================================================

// Cleanup quando página é descarregada
window.addEventListener('beforeunload', () => {
    // Cleanup de observers
    if (window.RegistrationPerformance?.monitor) {
        window.RegistrationPerformance.monitor.cleanup();
    }
    
    // Envia telemetria final
    if (window.registrationSystem?.telemetry) {
        window.registrationSystem.telemetry.sendBatch();
    }
    
    // Limpa cache sensível
    if (window.registrationSystem?.cache) {
        // Mantém apenas validações não-sensíveis
        const sensitiveKeys = ['senha', 'confirmar_senha'];
        sensitiveKeys.forEach(key => {
            window.registrationSystem.cache.memoryCache.delete(key);
        });
    }
});

// Freeze object para prevenir modificações acidentais
Object.freeze(REGISTRATION_CONFIG);

console.log('✅ Sistema de Cadastro Premium v6.0 carregado com sucesso');
console.log('🔧 Recursos:', {
    'Validação em tempo real': '✅',
    'Detecção de fraude': '✅', 
    'Acessibilidade avançada': '✅',
    'Telemetria': '✅',
    'Cache inteligente': '✅',
    'Animações fluidas': '✅',
    'Monitor de performance': '✅',
    'Error boundary': '✅'
});

// Disponibiliza utilitários de debug em desenvolvimento
if (window.location.hostname === 'localhost' || window.location.hostname.includes('dev')) {
    window.DEBUG_REGISTRATION = {
        system: () => window.registrationSystem,
        utils: window.RegistrationUtils,
        performance: window.RegistrationPerformance,
        errorBoundary: errorBoundary,
        config: REGISTRATION_CONFIG
    };
    
    console.log('🐛 Debug utilities disponíveis em window.DEBUG_REGISTRATION');
}