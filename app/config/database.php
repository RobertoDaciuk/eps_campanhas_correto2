<?php
declare(strict_types=1);

/**
 * ==============================================================================
 * SISTEMA DE BANCO DE DADOS PREMIUM (Premium Database System) - v4.0
 * ==============================================================================
 * Localização: /app/config/database.php
 * 
 * Aprimoramentos v4.0:
 * - Pool de conexões inteligente
 * - Health check automático
 * - Retry logic com backoff exponencial
 * - Monitoramento de performance
 * - Read/Write splitting preparado
 * - Cache de prepared statements
 */

// --- PREVENÇÃO DE ACESSO DIRETO ---
if (!defined('APP_INITIATED')) {
    http_response_code(403);
    exit('Forbidden');
}

// ==============================================================================
// 1. CONFIGURAÇÕES AVANÇADAS DE CONEXÃO
// ==============================================================================

// Pool de conexões por ambiente
$connectionConfig = [
    'production' => [
        'max_connections' => 10,
        'connection_timeout' => 5,
        'read_timeout' => 30,
        'retry_attempts' => 3,
        'retry_delay' => 1000, // microseconds
        'health_check_interval' => 300, // seconds
        'statement_cache_size' => 100
    ],
    'staging' => [
        'max_connections' => 5,
        'connection_timeout' => 5,
        'read_timeout' => 15,
        'retry_attempts' => 2,
        'retry_delay' => 500,
        'health_check_interval' => 600,
        'statement_cache_size' => 50
    ],
    'development' => [
        'max_connections' => 3,
        'connection_timeout' => 10,
        'read_timeout' => 30,
        'retry_attempts' => 1,
        'retry_delay' => 100,
        'health_check_interval' => 3600,
        'statement_cache_size' => 25
    ]
];

$dbConfig = $connectionConfig[ENVIRONMENT] ?? $connectionConfig['production'];

// ==============================================================================
// 2. CLASSE DE GERENCIAMENTO DE CONEXÕES
// ==============================================================================

if (!class_exists('DatabaseManager')) {
    class DatabaseManager
    {
        private static ?self $instance = null;
        private array $connections = [];
        private array $config = [];
        private array $healthChecks = [];
        private array $statementCache = [];
        
        private function __construct(array $config)
        {
            $this->config = $config;
        }
        
        public static function getInstance(array $config = []): self
        {
            if (self::$instance === null) {
                global $dbConfig;
                self::$instance = new self($config ?: $dbConfig);
            }
            return self::$instance;
        }
        
        /**
         * Retorna conexão otimizada com health check
         */
        public function getConnection(string $type = 'write'): PDO
        {
            $connectionKey = $type . '_' . md5(DB_DSN . DB_USER);
            
            // Verifica se conexão existe e está saudável
            if (isset($this->connections[$connectionKey])) {
                if ($this->isConnectionHealthy($connectionKey)) {
                    return $this->connections[$connectionKey];
                } else {
                    unset($this->connections[$connectionKey]);
                }
            }
            
            // Cria nova conexão com retry logic
            $connection = $this->createConnectionWithRetry();
            $this->connections[$connectionKey] = $connection;
            $this->healthChecks[$connectionKey] = time();
            
            return $connection;
        }
        
        /**
         * Cria conexão com retry e backoff exponencial
         */
        private function createConnectionWithRetry(): PDO
        {
            $attempts = 0;
            $maxAttempts = $this->config['retry_attempts'];
            $delay = $this->config['retry_delay'];
            
            while ($attempts < $maxAttempts) {
                try {
                    return $this->createConnection();
                } catch (PDOException $e) {
                    $attempts++;
                    
                    if ($attempts >= $maxAttempts) {
                        $this->logConnectionFailure($e, $attempts);
                        throw $e;
                    }
                    
                    // Backoff exponencial
                    $currentDelay = $delay * pow(2, $attempts - 1);
                    usleep($currentDelay);
                    
                    logSecurityEvent('DB_CONNECTION_RETRY', 'Tentativa de reconexão', [
                        'attempt' => $attempts,
                        'max_attempts' => $maxAttempts,
                        'delay_microseconds' => $currentDelay,
                        'error' => $e->getMessage()
                    ]);
                }
            }
            
            throw new PDOException('Falha ao conectar após todas as tentativas');
        }
        
        /**
         * Cria conexão PDO otimizada
         */
        private function createConnection(): PDO
        {
            // Validação prévia
            if (!extension_loaded('pdo_mysql')) {
                throw new PDOException('Extensão pdo_mysql não está disponível');
            }
            
            // Constrói DSN com opções otimizadas
            $dsn = $this->buildOptimizedDsn();
            
            // Opções de conexão premium
            $options = [
                PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
                PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
                PDO::ATTR_EMULATE_PREPARES => false,
                PDO::ATTR_PERSISTENT => false,
                PDO::ATTR_STRINGIFY_FETCHES => false,
                PDO::ATTR_TIMEOUT => $this->config['connection_timeout'],
                
                // Configurações MySQL específicas
                PDO::MYSQL_ATTR_INIT_COMMAND => "SET NAMES utf8mb4 COLLATE utf8mb4_unicode_ci, sql_mode='STRICT_TRANS_TABLES,NO_ZERO_DATE,NO_ZERO_IN_DATE,ERROR_FOR_DIVISION_BY_ZERO'",
                PDO::MYSQL_ATTR_USE_BUFFERED_QUERY => true,
                PDO::MYSQL_ATTR_MULTI_STATEMENTS => false, // Segurança
            ];
            
            // Configurações específicas do ambiente
            if (ENVIRONMENT === 'production') {
                $options[PDO::MYSQL_ATTR_COMPRESS] = true;
                $options[PDO::MYSQL_ATTR_LOCAL_INFILE] = false; // Segurança
            }
            
            $startTime = microtime(true);
            $pdo = new PDO($dsn, DB_USER, DB_PASS, $options);
            $connectionTime = (microtime(true) - $startTime) * 1000;
            
            // Configurações adicionais pós-conexão
            $this->configureConnection($pdo);
            
            logSecurityEvent('DB_CONNECTION_SUCCESS', 'Conexão estabelecida com sucesso', [
                'connection_time_ms' => round($connectionTime, 2),
                'server_version' => $pdo->getAttribute(PDO::ATTR_SERVER_VERSION),
                'connection_status' => $pdo->getAttribute(PDO::ATTR_CONNECTION_STATUS)
            ]);
            
            return $pdo;
        }
        
        /**
         * Constrói DSN otimizado
         */
        private function buildOptimizedDsn(): string
        {
            if (defined('DB_DSN') && DB_DSN) {
                return DB_DSN;
            }
            
            $dsnParts = [
                'mysql:host=' . (DB_HOST ?: 'localhost'),
                'port=' . (DB_PORT ?: '3306'),
                'dbname=' . (DB_NAME ?: ''),
                'charset=' . (DB_CHARSET ?: 'utf8mb4')
            ];
            
            // Configurações adicionais de performance
            if (ENVIRONMENT === 'production') {
                $dsnParts[] = 'compress=true';
            }
            
            return implode(';', $dsnParts);
        }
        
        /**
         * Configura conexão pós-estabelecimento
         */
        private function configureConnection(PDO $pdo): void
        {
            $statements = [
                "SET SESSION sql_mode = 'STRICT_TRANS_TABLES,NO_ZERO_DATE,NO_ZERO_IN_DATE,ERROR_FOR_DIVISION_BY_ZERO'",
                "SET SESSION time_zone = '+00:00'", // UTC
                "SET SESSION autocommit = 1",
                "SET SESSION transaction_isolation = 'READ-COMMITTED'",
            ];
            
            // Configurações específicas de ambiente
            if (ENVIRONMENT === 'production') {
                $statements[] = "SET SESSION query_cache_type = ON";
                $statements[] = "SET SESSION max_execution_time = 30000"; // 30s
            }
            
            foreach ($statements as $sql) {
                try {
                    $pdo->exec($sql);
                } catch (PDOException $e) {
                    logSecurityEvent('DB_CONFIG_WARNING', 'Falha na configuração pós-conexão', [
                        'statement' => $sql,
                        'error' => $e->getMessage()
                    ]);
                }
            }
        }
        
        /**
         * Verifica saúde da conexão
         */
        private function isConnectionHealthy(string $connectionKey): bool
        {
            if (!isset($this->connections[$connectionKey])) {
                return false;
            }
            
            $lastCheck = $this->healthChecks[$connectionKey] ?? 0;
            if ((time() - $lastCheck) < $this->config['health_check_interval']) {
                return true; // Assume saudável se verificado recentemente
            }
            
            try {
                $pdo = $this->connections[$connectionKey];
                $stmt = $pdo->query('SELECT 1');
                $result = $stmt->fetchColumn();
                
                $this->healthChecks[$connectionKey] = time();
                return $result === 1;
                
            } catch (PDOException $e) {
                logSecurityEvent('DB_HEALTH_CHECK_FAILED', 'Health check falhou', [
                    'connection_key' => $connectionKey,
                    'error' => $e->getMessage()
                ]);
                
                return false;
            }
        }
        
        /**
         * Log detalhado de falhas de conexão
         */
        private function logConnectionFailure(PDOException $e, int $attempts): void
        {
            $context = [
                'attempts' => $attempts,
                'error_code' => $e->getCode(),
                'error_message' => $e->getMessage(),
                'host' => DB_HOST,
                'database' => DB_NAME,
                'charset' => DB_CHARSET,
                'environment' => ENVIRONMENT
            ];
            
            logSecurityEvent('DB_CONNECTION_FAILURE', 'Falha crítica na conexão com banco', $context);
            
            // Alerta crítico para produção
            if (ENVIRONMENT === 'production') {
                error_log('CRITICAL DATABASE CONNECTION FAILURE: ' . json_encode($context));
            }
        }
        
        /**
         * Prepared statement com cache
         */
        public function prepare(string $query, string $connectionType = 'write'): PDO
        {
            $queryHash = md5($query);
            
            if (isset($this->statementCache[$queryHash])) {
                return $this->statementCache[$queryHash];
            }
            
            $pdo = $this->getConnection($connectionType);
            $stmt = $pdo->prepare($query);
            
            // Cache se não estiver cheio
            if (count($this->statementCache) < $this->config['statement_cache_size']) {
                $this->statementCache[$queryHash] = $stmt;
            }
            
            return $stmt;
        }
        
        /**
         * Executa query com monitoramento de performance
         */
        public function executeQuery(string $query, array $params = [], string $connectionType = 'write'): PDO
        {
            $startTime = microtime(true);
            $pdo = $this->getConnection($connectionType);
            
            try {
                if (empty($params)) {
                    $result = $pdo->query($query);
                } else {
                    $stmt = $pdo->prepare($query);
                    $stmt->execute($params);
                    $result = $stmt;
                }
                
                $executionTime = (microtime(true) - $startTime) * 1000;
                
                // Log queries lentas
                if ($executionTime > 1000) { // > 1 segundo
                    logSecurityEvent('SLOW_QUERY', 'Query lenta detectada', [
                        'execution_time_ms' => round($executionTime, 2),
                        'query_hash' => md5($query),
                        'query_length' => strlen($query),
                        'param_count' => count($params)
                    ]);
                }
                
                return $result;
                
            } catch (PDOException $e) {
                $executionTime = (microtime(true) - $startTime) * 1000;
                
                logSecurityEvent('DB_QUERY_ERROR', 'Erro na execução de query', [
                    'execution_time_ms' => round($executionTime, 2),
                    'error_code' => $e->getCode(),
                    'error_message' => $e->getMessage(),
                    'query_hash' => md5($query)
                ]);
                
                throw $e;
            }
        }
        
        /**
         * Transação segura com rollback automático
         */
        public function transaction(callable $callback, string $connectionType = 'write'): mixed
        {
            $pdo = $this->getConnection($connectionType);
            $startTime = microtime(true);
            
            try {
                $pdo->beginTransaction();
                
                $result = $callback($pdo);
                
                $pdo->commit();
                
                $executionTime = (microtime(true) - $startTime) * 1000;
                
                logSecurityEvent('DB_TRANSACTION_SUCCESS', 'Transação executada com sucesso', [
                    'execution_time_ms' => round($executionTime, 2)
                ]);
                
                return $result;
                
            } catch (Throwable $e) {
                if ($pdo->inTransaction()) {
                    $pdo->rollBack();
                }
                
                $executionTime = (microtime(true) - $startTime) * 1000;
                
                logSecurityEvent('DB_TRANSACTION_FAILURE', 'Falha na transação - rollback executado', [
                    'execution_time_ms' => round($executionTime, 2),
                    'error' => $e->getMessage()
                ]);
                
                throw $e;
            }
        }
        
        /**
         * Fecha todas as conexões
         */
        public function closeAll(): void
        {
            foreach ($this->connections as $key => $connection) {
                $this->connections[$key] = null;
            }
            
            $this->connections = [];
            $this->healthChecks = [];
            $this->statementCache = [];
            
            logSecurityEvent('DB_CONNECTIONS_CLOSED', 'Todas as conexões foram fechadas');
        }
        
        /**
         * Estatísticas das conexões
         */
        public function getStats(): array
        {
            return [
                'active_connections' => count($this->connections),
                'cached_statements' => count($this->statementCache),
                'max_connections' => $this->config['max_connections'],
                'statement_cache_size' => $this->config['statement_cache_size'],
                'environment' => ENVIRONMENT
            ];
        }
    }
}

// ==============================================================================
// 3. FUNÇÕES DE CONVENIÊNCIA GLOBAL
// ==============================================================================

if (!function_exists('getDbConnection')) {
    /**
     * Função global para obter conexão (backward compatibility)
     */
    function getDbConnection(string $type = 'write'): PDO
    {
        global $dbConfig;
        $manager = DatabaseManager::getInstance($dbConfig);
        return $manager->getConnection($type);
    }
}

if (!function_exists('dbQuery')) {
    /**
     * Executa query com parâmetros de forma segura
     */
    function dbQuery(string $query, array $params = [], string $connectionType = 'write'): PDO
    {
        global $dbConfig;
        $manager = DatabaseManager::getInstance($dbConfig);
        return $manager->executeQuery($query, $params, $connectionType);
    }
}

if (!function_exists('dbTransaction')) {
    /**
     * Executa transação de forma segura
     */
    function dbTransaction(callable $callback): mixed
    {
        global $dbConfig;
        $manager = DatabaseManager::getInstance($dbConfig);
        return $manager->transaction($callback);
    }
}

if (!function_exists('dbSelect')) {
    /**
     * Query SELECT otimizada
     */
    function dbSelect(string $table, array $conditions = [], array $options = []): array
    {
        $where = '';
        $params = [];
        
        if (!empty($conditions)) {
            $whereParts = [];
            foreach ($conditions as $field => $value) {
                if (is_array($value)) {
                    $placeholders = str_repeat('?,', count($value) - 1) . '?';
                    $whereParts[] = "{$field} IN ({$placeholders})";
                    $params = array_merge($params, $value);
                } else {
                    $whereParts[] = "{$field} = ?";
                    $params[] = $value;
                }
            }
            $where = 'WHERE ' . implode(' AND ', $whereParts);
        }
        
        $orderBy = isset($options['order']) ? "ORDER BY {$options['order']}" : '';
        $limit = isset($options['limit']) ? "LIMIT {$options['limit']}" : '';
        $offset = isset($options['offset']) ? "OFFSET {$options['offset']}" : '';
        
        $query = "SELECT * FROM {$table} {$where} {$orderBy} {$limit} {$offset}";
        
        $stmt = dbQuery(trim($query), $params, 'read');
        return $stmt->fetchAll();
    }
}

if (!function_exists('dbInsert')) {
    /**
     * INSERT otimizado com retorno do ID
     */
    function dbInsert(string $table, array $data): int
    {
        $fields = array_keys($data);
        $values = array_values($data);
        $placeholders = str_repeat('?,', count($fields) - 1) . '?';
        
        $query = "INSERT INTO {$table} (" . implode(',', $fields) . ") VALUES ({$placeholders})";
        
        return dbTransaction(function($pdo) use ($query, $values) {
            $stmt = $pdo->prepare($query);
            $stmt->execute($values);
            return (int)$pdo->lastInsertId();
        });
    }
}

if (!function_exists('dbUpdate')) {
    /**
     * UPDATE otimizado
     */
    function dbUpdate(string $table, array $data, array $conditions): int
    {
        $setParts = [];
        $params = [];
        
        foreach ($data as $field => $value) {
            $setParts[] = "{$field} = ?";
            $params[] = $value;
        }
        
        $whereParts = [];
        foreach ($conditions as $field => $value) {
            $whereParts[] = "{$field} = ?";
            $params[] = $value;
        }
        
        $query = "UPDATE {$table} SET " . implode(', ', $setParts) . 
                 " WHERE " . implode(' AND ', $whereParts);
        
        $stmt = dbQuery($query, $params);
        return $stmt->rowCount();
    }
}

if (!function_exists('dbDelete')) {
    /**
     * DELETE seguro
     */
    function dbDelete(string $table, array $conditions): int
    {
        if (empty($conditions)) {
            throw new InvalidArgumentException('DELETE sem condições não é permitido');
        }
        
        $whereParts = [];
        $params = [];
        
        foreach ($conditions as $field => $value) {
            $whereParts[] = "{$field} = ?";
            $params[] = $value;
        }
        
        $query = "DELETE FROM {$table} WHERE " . implode(' AND ', $whereParts);
        
        $stmt = dbQuery($query, $params);
        return $stmt->rowCount();
    }
}

// ==============================================================================
// 4. SISTEMA DE MIGRAÇÃO E MANUTENÇÃO
// ==============================================================================

if (!function_exists('checkDatabaseHealth')) {
    /**
     * Verifica saúde geral do banco de dados
     */
    function checkDatabaseHealth(): array
    {
        $health = [
            'status' => 'unknown',
            'connection' => false,
            'version' => null,
            'charset' => null,
            'timezone' => null,
            'tables_exist' => false,
            'performance' => []
        ];
        
        try {
            $startTime = microtime(true);
            $pdo = getDbConnection();
            $connectionTime = (microtime(true) - $startTime) * 1000;
            
            $health['connection'] = true;
            $health['performance']['connection_time_ms'] = round($connectionTime, 2);
            
            // Informações do servidor
            $health['version'] = $pdo->getAttribute(PDO::ATTR_SERVER_VERSION);
            
            // Verifica charset
            $stmt = $pdo->query("SELECT @@character_set_database as charset");
            $health['charset'] = $stmt->fetchColumn();
            
            // Verifica timezone
            $stmt = $pdo->query("SELECT @@session.time_zone as timezone");
            $health['timezone'] = $stmt->fetchColumn();
            
            // Verifica tabelas principais
            $requiredTables = ['usuarios', 'oticas', 'campanhas'];
            $stmt = $pdo->query("SHOW TABLES");
            $existingTables = $stmt->fetchAll(PDO::FETCH_COLUMN);
            
            $missingTables = array_diff($requiredTables, $existingTables);
            $health['tables_exist'] = empty($missingTables);
            $health['missing_tables'] = $missingTables;
            
            // Performance check simples
            $startTime = microtime(true);
            $pdo->query("SELECT COUNT(*) FROM usuarios");
            $health['performance']['simple_query_ms'] = round((microtime(true) - $startTime) * 1000, 2);
            
            $health['status'] = $health['tables_exist'] ? 'healthy' : 'warning';
            
        } catch (Exception $e) {
            $health['status'] = 'error';
            $health['error'] = $e->getMessage();
            
            logSecurityEvent('DB_HEALTH_CHECK_FAILED', 'Health check do banco falhou', [
                'error' => $e->getMessage()
            ]);
        }
        
        return $health;
    }
}

if (!function_exists('optimizeDatabase')) {
    /**
     * Otimização básica do banco de dados
     */
    function optimizeDatabase(): array
    {
        $results = [];
        
        try {
            $pdo = getDbConnection();
            
            // Lista tabelas
            $stmt = $pdo->query("SHOW TABLES");
            $tables = $stmt->fetchAll(PDO::FETCH_COLUMN);
            
            foreach ($tables as $table) {
                try {
                    $pdo->exec("OPTIMIZE TABLE {$table}");
                    $results[$table] = 'optimized';
                } catch (PDOException $e) {
                    $results[$table] = 'error: ' . $e->getMessage();
                }
            }
            
            logSecurityEvent('DB_OPTIMIZATION', 'Otimização de banco executada', [
                'tables_processed' => count($tables),
                'results' => $results
            ]);
            
        } catch (Exception $e) {
            $results['error'] = $e->getMessage();
            
            logSecurityEvent('DB_OPTIMIZATION_FAILED', 'Falha na otimização do banco', [
                'error' => $e->getMessage()
            ]);
        }
        
        return $results;
    }
}

// ==============================================================================
// 5. INICIALIZAÇÃO E VERIFICAÇÕES
// ==============================================================================

// Verifica se extensão MySQL está disponível
if (!extension_loaded('pdo_mysql')) {
    $error = 'Extensão PDO MySQL não está carregada';
    error_log('CRITICAL: ' . $error);
    
    if (ENVIRONMENT === 'development') {
        throw new RuntimeException($error);
    }
}

// Inicializa manager global (lazy loading)
$dbManager = null;

register_shutdown_function(function() {
    global $dbManager;
    if ($dbManager instanceof DatabaseManager) {
        $dbManager->closeAll();
    }
});

// Log de inicialização do sistema de banco
if (function_exists('logSecurityEvent')) {
    logSecurityEvent('DB_SYSTEM_INIT', 'Sistema de banco inicializado', [
        'environment' => defined('ENVIRONMENT') ? ENVIRONMENT : 'unknown',
        'host' => defined('DB_HOST') ? DB_HOST : 'localhost',
        'database' => defined('DB_NAME') ? DB_NAME : 'unknown',
        'charset' => defined('DB_CHARSET') ? DB_CHARSET : 'utf8mb4',
        'mysql_version' => extension_loaded('pdo_mysql') ? phpversion('pdo_mysql') : 'not_loaded'
    ]);
}