/**
 * ==============================================================================
 * MÓDULO DE CADASTRO PREMIUM (Premium Registration Module) - v5.0
 * ==============================================================================
 * Localização: /public/js/cadastro.js
 * 
 * Aprimoramentos v5.0:
 * - Performance otimizada com debouncing inteligente
 * - Validação em tempo real com cache
 * - Análise de força de senha avançada
 * - Detecção de padrões de fraude
 * - UX premium com micro-animações
 * - Acessibilidade WCAG 2.1 AA
 */

class RegistrationManager {
    constructor() {
        this.form = document.getElementById('register-form');
        this.elements = {};
        this.validationState = {};
        this.validationCache = new Map();
        this.submitTime = Date.now();
        this.isSubmitting = false;
        
        if (!this.form) {
            console.error('Formulário de cadastro não encontrado');
            return;
        }
        
        this.init();
    }
    
    /**
     * Inicialização do sistema
     */
    init() {
        this.mapElements();
        this.setupValidationRules();
        this.bindEvents();
        this.setupAccessibility();
        this.preloadOpticalData();
        
        // Analytics de tempo de permanência
        this.submitTime = Date.now();
        
        console.log('✅ Sistema de cadastro premium inicializado');
    }
    
    /**
     * Mapeia elementos do DOM
     */
    mapElements() {
        const selectors = {
            nome: '#nome',
            cpf: '#cpf',
            email: '#email',
            celular: '#celular',
            cnpj: '#cnpj',
            oticaDadosWrapper: '#otica-dados-wrapper',
            razaoSocial: '#razao_social',
            enderecoOtica: '#endereco_otica',
            senha: '#senha',
            confirmarSenha: '#confirmar_senha',
            togglePassword: '#toggle-password',
            termos: '#termos',
            termosError: '#termos-error',
            registerButton: '#register-button',
            buttonText: '.btn-text',
            buttonSpinner: '#register-spinner',
            cpfExistsOptions: '#cpf-exists-options',
            emailExistsOptions: '#email-exists-options'
        };
        
        // Mapeia elementos e inicializa estado de validação
        for (const [key, selector] of Object.entries(selectors)) {
            this.elements[key] = document.querySelector(selector);
            
            if (key !== 'oticaDadosWrapper' && key !== 'razaoSocial' && 
                key !== 'enderecoOtica' && key !== 'togglePassword' && 
                key !== 'termosError' && key !== 'registerButton' && 
                key !== 'buttonText' && key !== 'buttonSpinner' &&
                key !== 'cpfExistsOptions' && key !== 'emailExistsOptions') {
                this.validationState[key] = false;
            }
        }
        
        // Mapeia regras de senha
        this.elements.passwordRules = {
            length: document.getElementById('length'),
            uppercase: document.getElementById('uppercase'),
            lowercase: document.getElementById('lowercase'),
            number: document.getElementById('number'),
            special: document.getElementById('special')
        };
    }
    
    /**
     * Configuração de regras de validação
     */
    setupValidationRules() {
        this.validationRules = {
            nome: {
                pattern: /^[\p{L}\s'-.]+$/u,
                minLength: 5,
                transform: this.capitalizeName
            },
            cpf: {
                length: 11,
                validator: this.validateCPF,
                formatter: this.formatCPF,
                remote: true
            },
            email: {
                pattern: /^[^\s@]+@[^\s@]+\.[^\s@]+$/,
                remote: true
            },
            celular: {
                minLength: 10,
                maxLength: 11,
                formatter: this.formatPhone,
                validator: this.validatePhone
            },
            cnpj: {
                length: 14,
                validator: this.validateCNPJ,
                formatter: this.formatCNPJ,
                remote: true
            },
            senha: {
                minLength: 8,
                strengthChecker: true,
                validator: this.validatePasswordStrength
            }
        };
    }
    
    /**
     * Vincula eventos
     */
    bindEvents() {
        // Eventos de input com debouncing otimizado
        this.bindInputEvents();
        
        // Evento de submit
        this.form.addEventListener('submit', this.handleSubmit.bind(this));
        
        // Toggle de senha
        this.elements.togglePassword?.addEventListener('click', this.togglePasswordVisibility.bind(this));
        
        // Termos de uso
        this.elements.termos?.addEventListener('change', this.validateTerms.bind(this));
        
        // Botões de ação rápida
        this.bindQuickActionButtons();
        
        // Eventos de acessibilidade
        this.bindA11yEvents();
    }
    
    /**
     * Vincula eventos de input com debouncing inteligente
     */
    bindInputEvents() {
        const inputFields = ['nome', 'cpf', 'email', 'celular', 'cnpj', 'senha', 'confirmarSenha'];
        
        inputFields.forEach(field => {
            const element = this.elements[field];
            if (!element) return;
            
            // Debouncing diferenciado por tipo de campo
            const debounceTime = this.getDebounceTime(field);
            const debouncedValidation = this.debounce(
                this.validateField.bind(this, field), 
                debounceTime
            );
            
            // Eventos otimizados COM FORMATAÇÃO EM TEMPO REAL
            element.addEventListener('input', (e) => {
                // Salva posição do cursor
                const cursorPos = e.target.selectionStart;
                const oldValue = e.target.value;
                
                // Aplica formatação e validação
                this.handleInput(field, e);
                
                // Restaura cursor se necessário (para formatadores)
                const newValue = e.target.value;
                if (oldValue !== newValue && field !== 'nome') {
                    // Ajusta posição do cursor após formatação
                    const diff = newValue.length - oldValue.length;
                    const newCursorPos = Math.max(0, cursorPos + diff);
                    e.target.setSelectionRange(newCursorPos, newCursorPos);
                }
                
                // Validação com debounce
                debouncedValidation(e);
            });

            element.addEventListener('blur', () => {
                this.validateField(field, this.elements[field]);
            });

            // Validação especial para senha em tempo real (sem debounce)
            if (field === 'senha') {
                element.addEventListener('input', (e) => {
                    this.validatePasswordStrength(e.target.value);
                });
            }

            // Validação de confirmação de senha em tempo real
            if (field === 'confirmarSenha') {
                element.addEventListener('input', () => {
                    if (this.elements.confirmarSenha.value) {
                        this.validatePasswordMatch();
                    }
                });
            }
        });
    }     
    
    /**
     * Retorna tempo de debounce otimizado por campo
     */
    getDebounceTime(field) {
        const times = {
            nome: 300,      // Mais rápido para nome
            cpf: 500,       // Médio para documentos
            email: 400,     // Rápido para email
            celular: 300,   // Rápido para telefone
            cnpj: 700,      // Mais lento para CNPJ (consulta externa)
            senha: 200,     // Muito rápido para senha
            confirmarSenha: 200
        };
        
        return times[field] || 500;
    }
    
    /**
     * Manipula input com pré-processamento
     */
    handleInput(field, event) {
        const value = event.target.value;
        
        // Análise de padrões suspeitos
        if (this.detectSuspiciousInput(field, value)) {
            this.flagSuspiciousActivity(field, value);
        }
        
        // Limpa estado de erro ao começar a digitar
        this.clearFieldError(field);
        
        // Análise específica por campo
        this.analyzeFieldInput(field, value);
    }

    /**
     * Análise específica por campo
     */
    analyzeFieldInput(field, value) {
        switch (field) {
            case 'nome':
                // Capitaliza automaticamente
                if (value !== this.capitalizeName(value)) {
                    this.elements[field].value = this.capitalizeName(value);
                }
                break;
                
            case 'cpf':
                // Permite apenas números e aplica máscara
                const cpfNumbers = value.replace(/\D/g, '');
                if (cpfNumbers !== value.replace(/[^\d.-]/g, '')) {
                    this.elements[field].value = this.formatCPF(cpfNumbers);
                }
                break;
                
            case 'cnpj':
                // Permite apenas números e aplica máscara
                const cnpjNumbers = value.replace(/\D/g, '');
                if (cnpjNumbers !== value.replace(/[^\d./-]/g, '')) {
                    this.elements[field].value = this.formatCNPJ(cnpjNumbers);
                }
                break;
                
            case 'celular':
                // Aplica máscara de celular brasileiro
                const phoneNumbers = value.replace(/\D/g, '');
                this.elements[field].value = this.formatPhone(phoneNumbers);
                break;
                
            case 'senha':
                // Validação em tempo real da senha
                this.validatePasswordStrength(value);
                break;
        }
    }    
    
    /**
     * Detecta inputs suspeitos (possível bot/fraude)
     */
    detectSuspiciousInput(field, value) {
        // Velocidade de digitação muito alta
        const now = Date.now();
        const lastInputTime = this.lastInputTimes?.[field] || now;
        const timeDiff = now - lastInputTime;
        
        if (!this.lastInputTimes) this.lastInputTimes = {};
        this.lastInputTimes[field] = now;
        
        // Mais de 10 caracteres em menos de 100ms = suspeito
        if (value.length > 10 && timeDiff < 100) {
            return true;
        }
        
        // Padrões repetitivos
        if (/(.)\1{5,}/.test(value)) {
            return true;
        }
        
        return false;
    }
    
    /**
     * Marca atividade suspeita
     */
    flagSuspiciousActivity(field, value) {
        console.warn(`⚠️ Atividade suspeita detectada no campo ${field}`);
        
        // Adiciona à submissão para análise no servidor
        if (!this.suspiciousFlags) this.suspiciousFlags = [];
        this.suspiciousFlags.push({
            field,
            timestamp: Date.now(),
            pattern: 'fast_input'
        });
    }
    
    /**
     * Aplica formatação em tempo real
     */
    applyFormatter(field, event) {
        const formatter = this.validationRules[field]?.formatter;
        if (!formatter) return;
        
        const oldValue = event.target.value;
        const formattedValue = formatter.call(this, oldValue);
        
        if (formattedValue !== oldValue) {
            event.target.value = formattedValue;
        }
    }
    
    /**
     * Valida campo individual
     */
    async validateField(field, element) {
        if (!element || !this.validationRules[field]) return;
        
        const value = element.value.trim();
        const rule = this.validationRules[field];
        
        // Mostra loading
        this.showFieldLoading(field);
        
        try {
            // Validação local primeiro
            const localValidation = this.validateLocally(field, value, rule);
            
            if (!localValidation.valid) {
                this.updateFieldFeedback(field, 'invalid', localValidation.message);
                this.validationState[field] = false;
                this.checkFormValidity();
                return;
            }
            
            // Validação remota se necessária
            if (rule.remote && value) {
                const remoteValidation = await this.validateRemotely(field, value);
                
                if (!remoteValidation.valid) {
                    this.updateFieldFeedback(field, 'invalid', remoteValidation.message);
                    this.validationState[field] = false;
                    
                    // Mostra opções de ação se aplicável
                    this.showActionOptions(field, remoteValidation);
                } else {
                    this.updateFieldFeedback(field, 'valid');
                    this.validationState[field] = true;
                    
                    // Processa dados adicionais (ex: dados da ótica)
                    this.processRemoteData(field, remoteValidation);
                }
            } else {
                this.updateFieldFeedback(field, 'valid');
                this.validationState[field] = true;
            }
            
        } catch (error) {
            console.error(`Erro na validação do campo ${field}:`, error);
            this.updateFieldFeedback(field, 'error', 'Erro na validação. Tente novamente.');
            this.validationState[field] = false;
        }
        
        this.checkFormValidity();
    }
    
    /**
     * Validação local
     */
    validateLocally(field, value, rule) {
        // Campo vazio
        if (!value) {
            return { valid: false, message: `${this.getFieldLabel(field)} é obrigatório` };
        }
        
        // Comprimento
        if (rule.minLength && value.length < rule.minLength) {
            return { valid: false, message: `Mínimo ${rule.minLength} caracteres` };
        }
        
        if (rule.length && value.replace(/\D/g, '').length !== rule.length) {
            return { valid: false, message: `Deve ter ${rule.length} dígitos` };
        }
        
        // Padrão
        if (rule.pattern && !rule.pattern.test(value)) {
            return { valid: false, message: `Formato inválido` };
        }
        
        // Validador customizado
        if (rule.validator) {
            const result = rule.validator.call(this, value);
            if (!result.valid) {
                return result;
            }
        }
        
        return { valid: true };
    }
    
    /**
     * Validação remota com cache
     */
    async validateRemotely(field, value) {
        const cacheKey = `${field}:${value}`;
        
        // Verifica cache
        if (this.validationCache.has(cacheKey)) {
            const cached = this.validationCache.get(cacheKey);
            // Cache válido por 5 minutos
            if (Date.now() - cached.timestamp < 300000) {
                return cached.result;
            }
        }
        
        try {
            const response = await fetch(`/api/cadastro_api.php/validate?field=${field}&value=${encodeURIComponent(value)}`, {
                method: 'GET',
                headers: {
                    'Content-Type': 'application/json',
                    'X-Requested-With': 'XMLHttpRequest'
                }
            });
            
            const result = await response.json();
            
            // Armazena no cache
            this.validationCache.set(cacheKey, {
                result: result,
                timestamp: Date.now()
            });
            
            return result;
            
        } catch (error) {
            console.error('Erro na validação remota:', error);
            return { valid: true }; // Falha silenciosa - não bloqueia o usuário
        }
    }
    
    /**
     * Atualiza feedback visual do campo
     */
    updateFieldFeedback(field, state, message = '') {
        const element = this.elements[field];
        const wrapper = element?.closest('.input-wrapper');
        const icon = wrapper?.querySelector('.validation-icon');
        const errorContainer = element?.closest('.input-group')?.querySelector('.error-message-inline');
        
        if (!icon || !errorContainer) return;
        
        // Limpa classes anteriores
        icon.className = 'validation-icon';
        errorContainer.textContent = message;
        
        // Esconde opções de ação
        this.hideActionOptions(field);
        
        switch (state) {
            case 'valid':
                icon.classList.add('valid');
                element.setAttribute('aria-invalid', 'false');
                this.announceToScreenReader(`${this.getFieldLabel(field)} válido`);
                break;
                
            case 'invalid':
                icon.classList.add('invalid');
                element.setAttribute('aria-invalid', 'true');
                element.setAttribute('aria-describedby', `${field}-error`);
                break;
                
            case 'loading':
                icon.classList.add('fas', 'fa-spinner', 'fa-pulse');
                break;
                
            case 'error':
                icon.classList.add('invalid');
                element.setAttribute('aria-invalid', 'true');
                break;
        }
    }
    
    /**
     * Mostra loading no campo
     */
    showFieldLoading(field) {
        this.updateFieldFeedback(field, 'loading');
    }
    
    /**
     * Limpa erro do campo
     */
    clearFieldError(field) {
        const errorContainer = this.elements[field]?.closest('.input-group')?.querySelector('.error-message-inline');
        if (errorContainer) {
            errorContainer.textContent = '';
        }
        
        this.hideActionOptions(field);
    }
    
    /**
     * Mostra opções de ação (login/recuperar senha)
     */
    showActionOptions(field, validation) {
        if (validation.message?.includes('já está registado') || validation.message?.includes('já cadastrado')) {
            const optionsElement = this.elements[`${field}ExistsOptions`];
            if (optionsElement) {
                optionsElement.style.display = 'flex';
            }
        }
    }
    
    /**
     * Esconde opções de ação
     */
    hideActionOptions(field) {
        const optionsElement = this.elements[`${field}ExistsOptions`];
        if (optionsElement) {
            optionsElement.style.display = 'none';
        }
    }
    
    /**
     * Processa dados remotos adicionais
     */
    processRemoteData(field, validation) {
        if (field === 'cnpj' && validation.otica) {
            this.populateOpticalData(validation.otica);
        }
    }
    
    /**
     * Popula dados da ótica
     */
    populateOpticalData(oticaData) {
        if (this.elements.razaoSocial) {
            this.elements.razaoSocial.value = oticaData.razao_social || '';
        }
        
        if (this.elements.enderecoOtica) {
            this.elements.enderecoOtica.value = oticaData.endereco || '';
        }
        
        if (this.elements.oticaDadosWrapper) {
            this.elements.oticaDadosWrapper.classList.remove('hidden');
            
            // Animação suave
            this.elements.oticaDadosWrapper.style.opacity = '0';
            this.elements.oticaDadosWrapper.style.transform = 'translateY(-10px)';
            
            setTimeout(() => {
                this.elements.oticaDadosWrapper.style.transition = 'all 0.3s ease';
                this.elements.oticaDadosWrapper.style.opacity = '1';
                this.elements.oticaDadosWrapper.style.transform = 'translateY(0)';
            }, 50);
        }
    }
    
    /**
     * Validação de força da senha
     */
    validatePasswordStrength(password) {
        const rules = {
            length: password.length >= 8,
            uppercase: /[A-Z]/.test(password),
            lowercase: /[a-z]/.test(password),
            number: /[0-9]/.test(password),
            special: /[^A-Za-z0-9]/.test(password)
        };
        
        // Atualiza indicadores visuais EM TEMPO REAL
        for (const [rule, passed] of Object.entries(rules)) {
            const element = this.elements.passwordRules?.[rule];
            if (element) {
                const icon = element.querySelector('i');
                
                // Remove classes anteriores
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
            }
        }
        
        const allValid = Object.values(rules).every(Boolean);
        
        // Habilita confirmação de senha
        if (this.elements.confirmarSenha) {
            this.elements.confirmarSenha.disabled = !allValid;
            
            if (!allValid) {
                this.elements.confirmarSenha.value = '';
                this.validationState.confirmarSenha = false;
                this.clearFieldError('confirmarSenha');
            } else if (this.elements.confirmarSenha.value) {
                this.validatePasswordMatch();
            }
        }
        
        return { valid: allValid };
    }
    
    /**
     * Valida confirmação de senha
     */
    validatePasswordMatch() {
        const senha = this.elements.senha.value;
        const confirmacao = this.elements.confirmarSenha.value;
        
        const match = senha === confirmacao && confirmacao !== '';
        
        this.validationState.confirmarSenha = match;
        this.updateFieldFeedback(
            'confirmarSenha',
            match ? 'valid' : 'invalid',
            match ? '' : 'As senhas não coincidem'
        );
    }
    
    /**
     * Valida termos de uso
     */
    validateTerms() {
        const checked = this.elements.termos?.checked || false;
        this.validationState.termos = checked;
        
        if (this.elements.termosError) {
            this.elements.termosError.textContent = checked ? '' : 'Você deve aceitar os termos para continuar';
        }
        
        this.checkFormValidity();
    }
    
    /**
     * Verifica validade geral do formulário
     */
    checkFormValidity() {
        const allValid = Object.values(this.validationState).every(Boolean);
        
        if (this.elements.registerButton) {
            this.elements.registerButton.disabled = !allValid;
            
            // Feedback visual
            if (allValid) {
                this.elements.registerButton.classList.add('ready');
            } else {
                this.elements.registerButton.classList.remove('ready');
            }
        }
    }
    
    /**
     * Manipula submissão do formulário
     */
    async handleSubmit(event) {
        event.preventDefault();
        
        if (this.isSubmitting) return;
        
        // Validação final
        if (!Object.values(this.validationState).every(Boolean)) {
            this.showError('Por favor, corrija os erros antes de continuar');
            return;
        }
        
        this.isSubmitting = true;
        this.setSubmitState(true);
        
        try {
            const formData = this.collectFormData();
            const response = await this.submitRegistration(formData);
            
            if (response.success) {
                this.handleSuccessfulRegistration(response);
            } else {
                this.handleRegistrationError(response);
            }
            
        } catch (error) {
            console.error('Erro na submissão:', error);
            this.showError('Erro de conexão. Verifique sua internet e tente novamente.');
        } finally {
            this.isSubmitting = false;
            this.setSubmitState(false);
        }
    }
    
    /**
     * Coleta dados do formulário
     */
    collectFormData() {
        const data = {
            nome: this.elements.nome.value.trim(),
            cpf: this.elements.cpf.value.replace(/\D/g, ''),
            email: this.elements.email.value.trim().toLowerCase(),
            celular: this.elements.celular.value.replace(/\D/g, '').substring(2), // Remove +55
            cnpj: this.elements.cnpj.value.replace(/\D/g, ''),
            senha: this.elements.senha.value,
            confirmar_senha: this.elements.confirmarSenha.value,
            termos: this.elements.termos.checked
        };
        
        // Adiciona métricas de submissão
        data.submission_time = Math.floor((Date.now() - this.submitTime) / 1000);
        
        // Adiciona flags de suspeita se existirem
        if (this.suspiciousFlags?.length) {
            data.suspicious_flags = this.suspiciousFlags;
        }
        
        return data;
    }
    
    /**
     * Submete registro para API
     */
    async submitRegistration(formData) {
        const response = await fetch('/api/cadastro_api.php', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'Accept': 'application/json',
                'X-Requested-With': 'XMLHttpRequest'
            },
            body: JSON.stringify(formData)
        });
        
        if (!response.ok) {
            throw new Error(`HTTP ${response.status}: ${response.statusText}`);
        }
        
        return await response.json();
    }
    
    /**
     * Manipula registro bem-sucedido
     */
    handleSuccessfulRegistration(response) {
        // Analytics de conversão
        this.trackConversion(response);
        
        // Mostra modal de sucesso
        this.showSuccessModal(response.message, () => {
            window.location.href = '/login.php?registered=1';
        });
    }
    
    /**
     * Manipula erro de registro
     */
    handleRegistrationError(response) {
        console.error('Erro no registro:', response);
        
        // Mostra erros específicos de campo se disponíveis
        if (response.data?.field_errors) {
            this.showFieldErrors(response.data.field_errors);
        } else {
            this.showError(response.message || 'Erro no cadastro. Tente novamente.');
        }
    }
    
    /**
     * Define estado de submissão
     */
    setSubmitState(isSubmitting) {
        if (this.elements.registerButton) {
            this.elements.registerButton.disabled = isSubmitting;
        }
        
        if (this.elements.buttonText) {
            this.elements.buttonText.style.display = isSubmitting ? 'none' : 'inline-block';
        }
        
        if (this.elements.buttonSpinner) {
            this.elements.buttonSpinner.style.display = isSubmitting ? 'inline-block' : 'none';
        }
        
        // Desabilita campos durante submissão
        const inputs = this.form.querySelectorAll('input, select, textarea');
        inputs.forEach(input => {
            input.disabled = isSubmitting;
        });
    }
    
    // ========================================================================
    // FORMATADORES
    // ========================================================================
    
    formatCPF(value) {
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
    
    formatCNPJ(value) {
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
    
    formatPhone(value) {
        let numbers = value.replace(/\D/g, '');
        
        // Remove o 55 se o usuário digitou (evita duplicação)
        if (numbers.startsWith('55') && numbers.length > 11) {
            numbers = numbers.substring(2);
        }
        
        // Limita a 11 dígitos (DDD + 9 dígitos)
        numbers = numbers.substring(0, 11);
        
        if (numbers.length === 0) {
            return '';
        } else if (numbers.length <= 2) {
            return `+55 (${numbers}`;
        } else if (numbers.length <= 7) {
            return `+55 (${numbers.substring(0, 2)}) ${numbers.substring(2)}`;
        } else if (numbers.length <= 11) {
            // Formato: +55 (11) 99999-9999
            const ddd = numbers.substring(0, 2);
            const first = numbers.substring(2, 7);
            const second = numbers.substring(7);
            return `+55 (${ddd}) ${first}${second ? '-' + second : ''}`;
        }
        
        return `+55 (${numbers.substring(0, 2)}) ${numbers.substring(2, 7)}-${numbers.substring(7, 11)}`;
    }
    
    capitalizeName(name) {
        return name
            .toLowerCase()
            .split(' ')
            .map(word => {
                if (word.length === 0) return word;
                // Palavras que ficam em minúsculas (preposições)
                const lowercase = ['de', 'da', 'do', 'das', 'dos', 'e'];
                if (lowercase.includes(word)) {
                    return word;
                }
                return word.charAt(0).toUpperCase() + word.slice(1);
            })
            .join(' ');
    }
    
    // ========================================================================
    // VALIDADORES
    // ========================================================================
    
    validateCPF(cpf) {
        const numbers = cpf.replace(/\D/g, '');
        
        if (numbers.length !== 11 || /^(\d)\1{10}$/.test(numbers)) {
            return { valid: false, message: 'CPF inválido' };
        }
        
        // Validação do algoritmo do CPF
        let sum = 0;
        for (let i = 0; i < 9; i++) {
            sum += parseInt(numbers.charAt(i)) * (10 - i);
        }
        
        let remainder = (sum * 10) % 11;
        if (remainder === 10 || remainder === 11) remainder = 0;
        if (remainder !== parseInt(numbers.charAt(9))) {
            return { valid: false, message: 'CPF inválido' };
        }
        
        sum = 0;
        for (let i = 0; i < 10; i++) {
            sum += parseInt(numbers.charAt(i)) * (11 - i);
        }
        
        remainder = (sum * 10) % 11;
        if (remainder === 10 || remainder === 11) remainder = 0;
        if (remainder !== parseInt(numbers.charAt(10))) {
            return { valid: false, message: 'CPF inválido' };
        }
        
        return { valid: true };
    }
    
    validateCNPJ(cnpj) {
        const numbers = cnpj.replace(/\D/g, '');
        
        if (numbers.length !== 14 || /^(\d)\1{13}$/.test(numbers)) {
            return { valid: false, message: 'CNPJ inválido' };
        }
        
        // Validação do algoritmo do CNPJ
        const weights1 = [5, 4, 3, 2, 9, 8, 7, 6, 5, 4, 3, 2];
        const weights2 = [6, 5, 4, 3, 2, 9, 8, 7, 6, 5, 4, 3, 2];
        
        let sum = 0;
        for (let i = 0; i < 12; i++) {
            sum += parseInt(numbers.charAt(i)) * weights1[i];
        }
        
        let remainder = sum % 11;
        const digit1 = remainder < 2 ? 0 : 11 - remainder;
        
        if (digit1 !== parseInt(numbers.charAt(12))) {
            return { valid: false, message: 'CNPJ inválido' };
        }
        
        sum = 0;
        for (let i = 0; i < 13; i++) {
            sum += parseInt(numbers.charAt(i)) * weights2[i];
        }
        
        remainder = sum % 11;
        const digit2 = remainder < 2 ? 0 : 11 - remainder;
        
        if (digit2 !== parseInt(numbers.charAt(13))) {
            return { valid: false, message: 'CNPJ inválido' };
        }
        
        return { valid: true };
    }
    
    validatePhone(phone) {
        const numbers = phone.replace(/\D/g, '');
        
        if (numbers.length < 10 || numbers.length > 11) {
            return { valid: false, message: 'Número de telefone inválido' };
        }
        
        // Validação de DDD (códigos válidos do Brasil)
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
        
        // Se for celular (11 dígitos), deve começar com 9
        if (numbers.length === 11 && numbers.charAt(2) !== '9') {
            return { valid: false, message: 'Celular deve começar com 9' };
        }
        
        return { valid: true };
    }
    
    // ========================================================================
    // UTILITÁRIOS E ACESSIBILIDADE
    // ========================================================================
    
    /**
     * Configuração de acessibilidade
     */
    setupAccessibility() {
        // ARIA labels dinâmicos
        this.updateAriaLabels();
        
        // Navegação por teclado
        this.setupKeyboardNavigation();
        
        // Anúncios para screen readers
        this.createScreenReaderRegion();
    }
    
    updateAriaLabels() {
        const labels = {
            nome: 'Nome completo',
            cpf: 'CPF',
            email: 'E-mail',
            celular: 'Número de celular',
            cnpj: 'CNPJ da ótica',
            senha: 'Senha',
            confirmarSenha: 'Confirmação de senha'
        };
        
        for (const [field, label] of Object.entries(labels)) {
            const element = this.elements[field];
            if (element) {
                element.setAttribute('aria-label', label);
                element.setAttribute('aria-required', 'true');
            }
        }
    }
    
    setupKeyboardNavigation() {
        // Enter nos campos de texto pula para o próximo
        const inputs = this.form.querySelectorAll('input[type="text"], input[type="email"], input[type="password"], input[type="tel"]');
        
        inputs.forEach((input, index) => {
            input.addEventListener('keydown', (e) => {
                if (e.key === 'Enter' && !e.shiftKey) {
                    e.preventDefault();
                    
                    const nextInput = inputs[index + 1];
                    if (nextInput) {
                        nextInput.focus();
                    } else if (this.elements.registerButton && !this.elements.registerButton.disabled) {
                        this.elements.registerButton.focus();
                    }
                }
            });
        });
    }
    
    createScreenReaderRegion() {
        // Região para anúncios dinâmicos
        this.srRegion = document.createElement('div');
        this.srRegion.setAttribute('aria-live', 'polite');
        this.srRegion.setAttribute('aria-atomic', 'true');
        this.srRegion.className = 'sr-only';
        this.srRegion.style.cssText = 'position:absolute;left:-10000px;width:1px;height:1px;overflow:hidden;';
        document.body.appendChild(this.srRegion);
    }
    
    announceToScreenReader(message) {
        if (this.srRegion) {
            this.srRegion.textContent = message;
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
            confirmarSenha: 'Confirmação de senha'
        };
        
        return labels[field] || field;
    }
    
    /**
     * Vincula botões de ação rápida
     */
    bindQuickActionButtons() {
        // Botões de login
        document.querySelectorAll('.login-button').forEach(btn => {
            btn.addEventListener('click', () => {
                window.location.href = '/login.php';
            });
        });
        
        // Botões de recuperar senha
        document.querySelectorAll('.forgot-password-button').forEach(btn => {
            btn.addEventListener('click', () => {
                window.location.href = '/recuperar-senha.php';
            });
        });
    }
    
    /**
     * Vincula eventos de acessibilidade
     */
    bindA11yEvents() {
        // Esc para limpar erros
        document.addEventListener('keydown', (e) => {
            if (e.key === 'Escape') {
                this.clearAllErrors();
            }
        });
    }
    
    /**
     * Toggle de visibilidade da senha
     */
    togglePasswordVisibility() {
        const senha = this.elements.senha;
        const icon = this.elements.togglePassword?.querySelector('i');
        
        if (!senha || !icon) return;
        
        if (senha.type === 'password') {
            senha.type = 'text';
            icon.classList.remove('fa-eye');
            icon.classList.add('fa-eye-slash');
            
            // Auto-hide após 10 segundos
            setTimeout(() => {
                if (senha.type === 'text') {
                    senha.type = 'password';
                    icon.classList.remove('fa-eye-slash');
                    icon.classList.add('fa-eye');
                }
            }, 10000);
        } else {
            senha.type = 'password';
            icon.classList.remove('fa-eye-slash');
            icon.classList.add('fa-eye');
        }
    }
    
    /**
     * Pré-carrega dados de óticas para melhor UX
     */
    async preloadOpticalData() {
        console.log('⚠️ preloadOpticalData desabilitado - API oticas_ativas.php não existe ainda');
        
        // TODO: Implementar quando a API estiver pronta
        // try {
        //     const response = await fetch('/api/oticas_ativas.php');
        //     if (response.ok) {
        //         this.opticalShops = await response.json();
        //     }
        // } catch (error) {
        //     console.log('Pré-carregamento de óticas falhou:', error);
        // }
    }
    
    /**
     * Analytics e métricas
     */
    trackConversion(response) {
        // Google Analytics / Facebook Pixel / etc.
        if (typeof gtag !== 'undefined') {
            gtag('event', 'sign_up', {
                method: 'form',
                value: 1
            });
        }
        
        // Analytics customizado
        if (typeof analytics !== 'undefined') {
            analytics.track('Registration Completed', {
                userId: response.data?.user_id,
                source: 'web_form',
                submissionTime: Date.now() - this.submitTime
            });
        }
    }
    
    /**
     * Sistema de notificações
     */
    showError(message) {
        this.showNotification(message, 'error');
    }
    
    showSuccess(message) {
        this.showNotification(message, 'success');
    }
    
    showNotification(message, type = 'info') {
        // Remove notificações anteriores
        const existing = document.querySelector('.notification-toast');
        if (existing) {
            existing.remove();
        }
        
        // Cria nova notificação
        const notification = document.createElement('div');
        notification.className = `notification-toast notification-${type}`;
        notification.innerHTML = `
            <div class="notification-content">
                <i class="fas fa-${type === 'error' ? 'exclamation-circle' : type === 'success' ? 'check-circle' : 'info-circle'}"></i>
                <span>${message}</span>
            </div>
            <button class="notification-close" aria-label="Fechar notificação">
                <i class="fas fa-times"></i>
            </button>
        `;
        
        // Estilos inline para garantir funcionamento
        notification.style.cssText = `
            position: fixed;
            top: 20px;
            right: 20px;
            z-index: 10000;
            max-width: 400px;
            padding: 15px;
            border-radius: 8px;
            box-shadow: 0 4px 12px rgba(0,0,0,0.15);
            font-family: inherit;
            font-size: 14px;
            transform: translateX(100%);
            transition: transform 0.3s ease;
            ${type === 'error' ? 'background: #fee; border-left: 4px solid #dc3545; color: #721c24;' : ''}
            ${type === 'success' ? 'background: #d4edda; border-left: 4px solid #28a745; color: #155724;' : ''}
            ${type === 'info' ? 'background: #d1ecf1; border-left: 4px solid #17a2b8; color: #0c5460;' : ''}
        `;
        
        document.body.appendChild(notification);
        
        // Animação de entrada
        setTimeout(() => {
            notification.style.transform = 'translateX(0)';
        }, 100);
        
        // Botão de fechar
        const closeBtn = notification.querySelector('.notification-close');
        closeBtn.addEventListener('click', () => {
            this.removeNotification(notification);
        });
        
        // Auto-remove após 5 segundos
        setTimeout(() => {
            if (document.contains(notification)) {
                this.removeNotification(notification);
            }
        }, 5000);
    }
    
    removeNotification(notification) {
        notification.style.transform = 'translateX(100%)';
        setTimeout(() => {
            if (document.contains(notification)) {
                notification.remove();
            }
        }, 300);
    }
    
    showSuccessModal(message, callback) {
        const modal = document.createElement('div');
        modal.className = 'success-modal-overlay';
        modal.innerHTML = `
            <div class="success-modal">
                <div class="success-icon">
                    <i class="fas fa-check-circle"></i>
                </div>
                <h3>Cadastro Realizado!</h3>
                <p>${message}</p>
                <button class="btn btn-primary" id="continue-btn">Continuar</button>
            </div>
        `;
        
        // Estilos inline
        modal.style.cssText = `
            position: fixed;
            top: 0;
            left: 0;
            right: 0;
            bottom: 0;
            background: rgba(0,0,0,0.8);
            display: flex;
            align-items: center;
            justify-content: center;
            z-index: 10001;
            opacity: 0;
            transition: opacity 0.3s ease;
        `;
        
        const modalContent = modal.querySelector('.success-modal');
        modalContent.style.cssText = `
            background: white;
            padding: 40px;
            border-radius: 12px;
            text-align: center;
            max-width: 400px;
            transform: scale(0.8);
            transition: transform 0.3s ease;
        `;
        
        document.body.appendChild(modal);
        
        setTimeout(() => {
            modal.style.opacity = '1';
            modalContent.style.transform = 'scale(1)';
        }, 100);
        
        // Botão continuar
        document.getElementById('continue-btn').addEventListener('click', () => {
            modal.style.opacity = '0';
            modalContent.style.transform = 'scale(0.8)';
            setTimeout(() => {
                modal.remove();
                if (callback) callback();
            }, 300);
        });
    }
    
    showFieldErrors(fieldErrors) {
        for (const [field, errors] of Object.entries(fieldErrors)) {
            if (this.elements[field]) {
                const message = Array.isArray(errors) ? errors[0] : errors;
                this.updateFieldFeedback(field, 'invalid', message);
                this.validationState[field] = false;
            }
        }
        
        this.checkFormValidity();
    }
    
    clearAllErrors() {
        const errorContainers = this.form.querySelectorAll('.error-message-inline');
        errorContainers.forEach(container => {
            container.textContent = '';
        });
        
        const validationIcons = this.form.querySelectorAll('.validation-icon');
        validationIcons.forEach(icon => {
            icon.className = 'validation-icon';
        });
    }
    
    /**
     * Função de debounce otimizada
     */
    debounce(func, wait, immediate = false) {
        let timeout;
        return function executedFunction(...args) {
            const later = () => {
                timeout = null;
                if (!immediate) func(...args);
            };
            const callNow = immediate && !timeout;
            clearTimeout(timeout);
            timeout = setTimeout(later, wait);
            if (callNow) func(...args);
        };
    }
}

// ============================================================================
// INICIALIZAÇÃO
// ============================================================================

// Inicializa quando DOM estiver pronto
if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', () => {
        new RegistrationManager();
    });
} else {
    new RegistrationManager();
}

// Export para uso em testes
if (typeof module !== 'undefined' && module.exports) {
    module.exports = RegistrationManager;
}