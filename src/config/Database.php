<?php

class Database
{
    private $host;
    private $db_name;
    private $username;
    private $password;
    private $conn;

    public function __construct()
    {
        // Verify environment variables are loaded
        if (
            !isset($_ENV['DB_HOST']) || !isset($_ENV['DB_NAME']) ||
            !isset($_ENV['DB_USER']) || !isset($_ENV['DB_PASS'])
        ) {
            throw new RuntimeException(
                'Database configuration missing. ' .
                    'Verify your .env file exists and environment is loaded before creating Database instance.'
            );
        }

        $this->host = $_ENV['DB_HOST'];
        $this->db_name = $_ENV['DB_NAME'];
        $this->username = $_ENV['DB_USER'];
        $this->password = $_ENV['DB_PASS'];
    }

    public function connect()
    {
        $this->conn = null;

        try {
            $this->conn = new PDO(
                "mysql:host={$this->host};dbname={$this->db_name};charset=utf8mb4",
                $this->username,
                $this->password,
                [
                    PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
                    PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
                    PDO::ATTR_EMULATE_PREPARES => false,
                ]
            );
        } catch (PDOException $e) {
            error_log("Database connection failed: " . $e->getMessage());
            throw new RuntimeException("Database connection error. Please check your configuration.");
        }

        return $this->conn;
    }
}
