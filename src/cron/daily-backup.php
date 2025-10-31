<?php
// Load Composer autoloader and environment variables
require_once __DIR__ . '/../../vendor/autoload.php';

// Load environment using Dotenv
$dotenv = Dotenv\Dotenv::createImmutable(__DIR__ . '/../../');
$dotenv->load();

// Now load the AutoBackup class
require_once __DIR__ . '/../script/auto_backup.php';

echo "Testing automatic backup...\n\n";

// Check if .env is loaded
echo "Environment check:\n";
echo "- DB_HOST: " . ($_ENV['DB_HOST'] ?? 'NOT SET') . "\n";
echo "- DB_NAME: " . ($_ENV['DB_NAME'] ?? 'NOT SET') . "\n";
echo "- DB_USER: " . ($_ENV['DB_USER'] ?? 'NOT SET') . "\n\n";

try {
    $backupDir = __DIR__ . '/../../backups';
    $autoBackup = new AutoBackup($backupDir);

    echo "Starting backup...\n";
    $result = $autoBackup->createBackup();

    if ($result['success']) {
        echo "\n✓ Backup created successfully!\n";
        echo "Filename: {$result['filename']}\n\n";

        $lastBackup = $autoBackup->getLastBackupInfo();
        if ($lastBackup) {
            echo "Last backup details:\n";
            echo "- File: {$lastBackup['filename']}\n";
            echo "- Date: " . date('Y-m-d H:i:s', $lastBackup['modified']) . "\n";
            echo "- Size: " . round($lastBackup['size'] / 1024 / 1024, 2) . " MB\n";
        }
    } else {
        echo "\n✗ Backup failed!\n";
        echo "Error: {$result['error']}\n";
    }
} catch (Exception $e) {
    echo "\n✗ Error occurred!\n";
    echo "Error: " . $e->getMessage() . "\n";
    echo "Trace: " . $e->getTraceAsString() . "\n";
}
