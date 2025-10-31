<?php
// Use forward slashes for Windows paths
$rootPath = 'C:/Users/LENOVO/Desktop/acss-1';

require $rootPath . '/vendor/autoload.php';

// Debug output
echo "Root path: $rootPath\n";
echo ".env exists: " . (file_exists($rootPath . '/.env') ? 'YES' : 'NO') . "\n";

// Load environment variables
try {
    $dotenv = Dotenv\Dotenv::createImmutable($rootPath);
    $dotenv->load();
    echo "Environment loaded successfully!\n";
} catch (Exception $e) {
    die("Failed to load .env: " . $e->getMessage());
}

// Verify loaded variables
echo "\nLoaded Environment Variables:\n";
print_r($_ENV);

// Test database connection
try {
    $db = new PDO(
        "mysql:host=" . $_ENV['DB_HOST'] . ";dbname=" . $_ENV['DB_NAME'],
        $_ENV['DB_USER'],
        $_ENV['DB_PASS'] ?? '' // Handle empty password
    );
    echo "\nDatabase connection SUCCESS!\n";
} catch (PDOException $e) {
    echo "\nDatabase connection FAILED: " . $e->getMessage() . "\n";
}
