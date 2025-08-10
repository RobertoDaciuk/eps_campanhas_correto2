<?php
echo "PHP: ✅ Funcionando<br>";
echo "Versão PHP: " . PHP_VERSION . "<br><br>";

try {
    $pdo = new PDO('mysql:host=127.0.0.1;dbname=campanhas_eps;charset=utf8mb4', 'root', 'root');
    echo "MySQL: ✅ Conectado<br>";
    echo "Versão MySQL: " . $pdo->getAttribute(PDO::ATTR_SERVER_VERSION) . "<br>";
} catch(PDOException $e) {
    echo "MySQL: ❌ Erro: " . $e->getMessage() . "<br>";
}
?>