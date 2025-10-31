<?php
// Load Composer autoloader and environment variables FIRST
require_once __DIR__ . '/../../vendor/autoload.php';

// Load environment variables using Dotenv
$dotenv = Dotenv\Dotenv::createImmutable(__DIR__ . '/../../');
$dotenv->load();

// Now load the Database class
require_once __DIR__ . '/../config/Database.php';

class AutoBackup
{
    private $db;
    private $backupDir;
    private $keepDays;

    public function __construct($backupDir = null, $keepDays = 30)
    {
        $this->db = (new Database())->connect();
        $this->backupDir = $backupDir ?? __DIR__ . '/../../backups';
        $this->keepDays = $keepDays;

        // Create backup directory if it doesn't exist
        if (!is_dir($this->backupDir)) {
            mkdir($this->backupDir, 0755, true);
        }
    }

    public function createBackup()
    {
        try {
            $timestamp = date('Y-m-d_H-i-s');
            $dbName = $this->getDatabaseName();
            $backupFilename = "auto_backup_{$dbName}_{$timestamp}.sql";
            $backupPath = $this->backupDir . '/' . $backupFilename;

            $backupContent = $this->generateBackupContent($dbName);

            // Write backup file
            if (file_put_contents($backupPath, $backupContent) !== false) {
                chmod($backupPath, 0644);

                // Compress the backup
                $this->compressBackup($backupPath);

                // Clean up old backups
                $this->cleanupOldBackups();

                error_log("Automatic backup created successfully: " . $backupFilename);
                return ['success' => true, 'filename' => $backupFilename];
            } else {
                throw new Exception('Failed to write backup file');
            }
        } catch (Exception $e) {
            error_log("Automatic backup failed: " . $e->getMessage());
            return ['success' => false, 'error' => $e->getMessage()];
        }
    }

    private function generateBackupContent($dbName)
    {
        $content = "";

        // Set SQL headers
        $content .= "-- Automatic Database Backup\n";
        $content .= "-- Generated: " . date('Y-m-d H:i:s') . "\n";
        $content .= "-- Database: {$dbName}\n";
        $content .= "-- PHP Version: " . PHP_VERSION . "\n";
        $content .= "\nSET FOREIGN_KEY_CHECKS=0;\n";
        $content .= "SET SQL_MODE = \"NO_AUTO_VALUE_ON_ZERO\";\n";
        $content .= "SET time_zone = \"+00:00\";\n\n";

        // Get all tables
        $tables = $this->getAllTables();

        // Backup each table
        foreach ($tables as $table) {
            $content .= $this->backupTable($table);
        }

        $content .= "SET FOREIGN_KEY_CHECKS=1;\n";

        return $content;
    }

    private function getAllTables()
    {
        $stmt = $this->db->query("SHOW TABLES");
        return $stmt->fetchAll(PDO::FETCH_COLUMN);
    }

    private function getDatabaseName()
    {
        $stmt = $this->db->query("SELECT DATABASE()");
        return $stmt->fetchColumn();
    }

    private function backupTable($tableName)
    {
        $output = "--\n";
        $output .= "-- Table structure for table `{$tableName}`\n";
        $output .= "--\n\n";

        // Drop table if exists
        $output .= "DROP TABLE IF EXISTS `{$tableName}`;\n";

        // Get table creation script
        $stmt = $this->db->query("SHOW CREATE TABLE `{$tableName}`");
        $createTable = $stmt->fetch(PDO::FETCH_ASSOC);
        $output .= $createTable['Create Table'] . ";\n\n";

        // Get table data
        $output .= "--\n";
        $output .= "-- Dumping data for table `{$tableName}`\n";
        $output .= "--\n\n";

        $stmt = $this->db->query("SELECT * FROM `{$tableName}`");
        $rows = $stmt->fetchAll(PDO::FETCH_ASSOC);

        if (count($rows) > 0) {
            $output .= "INSERT INTO `{$tableName}` VALUES \n";

            $insertValues = [];
            foreach ($rows as $row) {
                $values = array_map(function ($value) {
                    if ($value === null) return 'NULL';
                    // Escape special characters properly
                    $value = addslashes($value);
                    return "'" . $value . "'";
                }, $row);

                $insertValues[] = "(" . implode(", ", $values) . ")";
            }

            $output .= implode(",\n", $insertValues) . ";\n\n";
        }

        return $output;
    }

    private function compressBackup($backupPath)
    {
        if (extension_loaded('zip')) {
            $zip = new ZipArchive();
            $zipPath = $backupPath . '.zip';

            if ($zip->open($zipPath, ZipArchive::CREATE) === TRUE) {
                $zip->addFile($backupPath, basename($backupPath));
                $zip->close();

                // Remove the original SQL file if zip was created successfully
                if (file_exists($zipPath)) {
                    unlink($backupPath);
                    error_log("Backup compressed: " . basename($zipPath));
                    return true;
                }
            }
        }
        return false;
    }

    private function cleanupOldBackups()
    {
        try {
            $files = scandir($this->backupDir);
            $cutoffTime = time() - ($this->keepDays * 24 * 60 * 60);

            foreach ($files as $file) {
                if ($file === '.' || $file === '..') continue;

                $filePath = $this->backupDir . '/' . $file;
                $fileExtension = pathinfo($file, PATHINFO_EXTENSION);

                if (($fileExtension === 'sql' || $fileExtension === 'zip') &&
                    strpos($file, 'auto_backup_') === 0
                ) {

                    if (filemtime($filePath) < $cutoffTime) {
                        unlink($filePath);
                        error_log("Deleted old automatic backup: " . $file);
                    }
                }
            }
        } catch (Exception $e) {
            error_log("Cleanup old backups error: " . $e->getMessage());
        }
    }

    public function getLastBackupInfo()
    {
        try {
            $files = scandir($this->backupDir);
            $backups = [];

            foreach ($files as $file) {
                if ($file === '.' || $file === '..') continue;

                $fileExtension = pathinfo($file, PATHINFO_EXTENSION);
                if (($fileExtension === 'sql' || $fileExtension === 'zip') &&
                    strpos($file, 'auto_backup_') === 0
                ) {

                    $filePath = $this->backupDir . '/' . $file;
                    $backups[] = [
                        'filename' => $file,
                        'modified' => filemtime($filePath),
                        'size' => filesize($filePath)
                    ];
                }
            }

            if (empty($backups)) {
                return null;
            }

            // Sort by modification time (newest first)
            usort($backups, function ($a, $b) {
                return $b['modified'] - $a['modified'];
            });

            return $backups[0];
        } catch (Exception $e) {
            error_log("Get last backup info error: " . $e->getMessage());
            return null;
        }
    }
}
