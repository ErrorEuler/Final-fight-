<?php
require_once __DIR__ . '/../script/auto_backup.php';

echo "Testing automatic backup...\n\n";

$backupDir = __DIR__ . '/../backups';
$autoBackup = new AutoBackup($backupDir);

$result = $autoBackup->createBackup();

if ($result['success']) {
    echo "✓ Backup created successfully!\n";
    echo "Filename: {$result['filename']}\n\n";

    $lastBackup = $autoBackup->getLastBackupInfo();
    if ($lastBackup) {
        echo "Last backup details:\n";
        echo "- File: {$lastBackup['filename']}\n";
        echo "- Date: " . date('Y-m-d H:i:s', $lastBackup['modified']) . "\n";
        echo "- Size: " . round($lastBackup['size'] / 1024 / 1024, 2) . " MB\n";
    }
} else {
    echo "✗ Backup failed!\n";
    echo "Error: {$result['error']}\n";
}
