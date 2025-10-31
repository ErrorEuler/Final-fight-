<?php
// src/services/SecurityService.php

class SecurityService
{
    private $db;

    public function __construct($db)
    {
        $this->db = $db;
    }

    /**
     * Check rate limits and prevent brute force attacks
     */
    public function checkRateLimit($ipAddress, $actionType, $maxAttempts = 5, $timeWindow = 900)
    {
        try {
            // Clean up old records
            $this->cleanupRateLimits();

            $query = "SELECT attempt_count, first_attempt, is_blocked, block_until 
                      FROM rate_limits 
                      WHERE ip_address = :ip_address AND action_type = :action_type";
            $stmt = $this->db->prepare($query);
            $stmt->execute([
                ':ip_address' => $ipAddress,
                ':action_type' => $actionType
            ]);
            $record = $stmt->fetch(PDO::FETCH_ASSOC);

            $now = time();

            if ($record) {
                if ($record['is_blocked'] && strtotime($record['block_until']) > $now) {
                    $this->logSecurityAction($ipAddress, 'rate_limit_blocked', $actionType);
                    return ['allowed' => false, 'remaining' => 0, 'reset_time' => strtotime($record['block_until'])];
                }

                // Reset if time window has passed
                if (strtotime($record['first_attempt']) < ($now - $timeWindow)) {
                    $this->resetRateLimit($ipAddress, $actionType);
                    $record = null;
                }
            }

            if (!$record) {
                // Create new record
                $query = "INSERT INTO rate_limits (ip_address, action_type, attempt_count) 
                          VALUES (:ip_address, :action_type, 1)";
                $stmt = $this->db->prepare($query);
                $stmt->execute([
                    ':ip_address' => $ipAddress,
                    ':action_type' => $actionType
                ]);
                return ['allowed' => true, 'remaining' => $maxAttempts - 1, 'reset_time' => $now + $timeWindow];
            }

            $attemptCount = $record['attempt_count'] + 1;
            $remaining = max(0, $maxAttempts - $attemptCount);

            if ($attemptCount >= $maxAttempts) {
                // Block for 1 hour
                $blockUntil = date('Y-m-d H:i:s', $now + 3600);
                $query = "UPDATE rate_limits 
                          SET attempt_count = :attempt_count, is_blocked = 1, block_until = :block_until 
                          WHERE ip_address = :ip_address AND action_type = :action_type";
                $stmt = $this->db->prepare($query);
                $stmt->execute([
                    ':attempt_count' => $attemptCount,
                    ':block_until' => $blockUntil,
                    ':ip_address' => $ipAddress,
                    ':action_type' => $actionType
                ]);

                $this->logSecurityAction($ipAddress, 'rate_limit_exceeded', $actionType);
                return ['allowed' => false, 'remaining' => 0, 'reset_time' => strtotime($blockUntil)];
            }

            // Update attempt count
            $query = "UPDATE rate_limits 
                      SET attempt_count = :attempt_count, last_attempt = NOW() 
                      WHERE ip_address = :ip_address AND action_type = :action_type";
            $stmt = $this->db->prepare($query);
            $stmt->execute([
                ':attempt_count' => $attemptCount,
                ':ip_address' => $ipAddress,
                ':action_type' => $actionType
            ]);

            return ['allowed' => true, 'remaining' => $remaining, 'reset_time' => strtotime($record['first_attempt']) + $timeWindow];
        } catch (PDOException $e) {
            error_log("Rate limit check error: " . $e->getMessage());
            return ['allowed' => true, 'remaining' => $maxAttempts, 'reset_time' => time() + $timeWindow];
        }
    }

    /**
     * Reset rate limit for an IP and action
     */
    private function resetRateLimit($ipAddress, $actionType)
    {
        try {
            $query = "DELETE FROM rate_limits 
                      WHERE ip_address = :ip_address AND action_type = :action_type";
            $stmt = $this->db->prepare($query);
            $stmt->execute([
                ':ip_address' => $ipAddress,
                ':action_type' => $actionType
            ]);
        } catch (PDOException $e) {
            error_log("Reset rate limit error: " . $e->getMessage());
        }
    }

    /**
     * Clean up old rate limit records
     */
    private function cleanupRateLimits()
    {
        try {
            $query = "DELETE FROM rate_limits 
                      WHERE last_attempt < DATE_SUB(NOW(), INTERVAL 24 HOUR) 
                      AND is_blocked = 0";
            $stmt = $this->db->prepare($query);
            $stmt->execute();
        } catch (PDOException $e) {
            error_log("Cleanup rate limits error: " . $e->getMessage());
        }
    }

    /**
     * Log security actions
     */
    public function logSecurityAction($ipAddress, $actionType, $identifier = null, $details = null)
    {
        try {
            $query = "INSERT INTO security_logs (ip_address, user_agent, action_type, identifier, details) 
                      VALUES (:ip_address, :user_agent, :action_type, :identifier, :details)";
            $stmt = $this->db->prepare($query);
            $stmt->execute([
                ':ip_address' => $ipAddress,
                ':user_agent' => $_SERVER['HTTP_USER_AGENT'] ?? 'Unknown',
                ':action_type' => $actionType,
                ':identifier' => $identifier,
                ':details' => $details
            ]);
        } catch (PDOException $e) {
            error_log("Security log error: " . $e->getMessage());
        }
    }

    /**
     * Validate and sanitize input
     */
    public function sanitizeInput($input)
    {
        if (is_array($input)) {
            return array_map([$this, 'sanitizeInput'], $input);
        }

        // Remove whitespace
        $input = trim($input);
        // Convert special characters to HTML entities
        $input = htmlspecialchars($input, ENT_QUOTES | ENT_HTML5, 'UTF-8');
        // Remove null bytes
        $input = str_replace(chr(0), '', $input);

        return $input;
    }

    /**
     * Validate email format
     */
    public function isValidEmail($email)
    {
        return filter_var($email, FILTER_VALIDATE_EMAIL) !== false;
    }

    /**
     * Check for SQL injection patterns
     */
    public function detectSqlInjection($input)
    {
        $patterns = [
            '/\b(UNION|SELECT|INSERT|UPDATE|DELETE|DROP|CREATE|ALTER)\b/i',
            '/\b(OR|AND)\s+[\'"]?[\d\w]+[\'"]?\s*=\s*[\'"]?[\d\w]+[\'"]?/i',
            '/--|\/\*|\*\//',
            '/;\s*(DROP|DELETE|UPDATE|INSERT)/i'
        ];

        foreach ($patterns as $pattern) {
            if (preg_match($pattern, $input)) {
                return true;
            }
        }

        return false;
    }

    /**
     * Generate and verify CAPTCHA
     */
    public function generateCaptcha()
    {
        $captchaCode = substr(str_shuffle('0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ'), 0, 6);
        $_SESSION['captcha_code'] = $captchaCode;
        $_SESSION['captcha_generated'] = time();
        return $captchaCode;
    }

    public function verifyCaptcha($userInput)
    {
        if (!isset($_SESSION['captcha_code']) || !isset($_SESSION['captcha_generated'])) {
            return false;
        }

        // CAPTCHA expires after 10 minutes
        if (time() - $_SESSION['captcha_generated'] > 600) {
            unset($_SESSION['captcha_code'], $_SESSION['captcha_generated']);
            return false;
        }

        $isValid = strtoupper($userInput) === $_SESSION['captcha_code'];
        unset($_SESSION['captcha_code'], $_SESSION['captcha_generated']);

        return $isValid;
    }
}
