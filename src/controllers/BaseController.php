<?php
require_once __DIR__ . '/../config/Database.php';

class BaseController
{
    protected $db;
    protected $userRoles;

    public function __construct()
    {
        if (session_status() === PHP_SESSION_NONE) {
            session_start();
        }

        $this->db = (new Database())->connect();
        $this->db->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);

        $this->userRoles = $_SESSION['roles'] ?? [];
        error_log("BaseController: userRoles set to: " . json_encode($this->userRoles));
    }

    protected function hasRole($role)
    {
        if (!isset($this->userRoles)) {
            error_log("BaseController: userRoles is not set");
            return false;
        }
        return in_array(strtolower($role), array_map('strtolower', $this->userRoles));
    }

    protected function requireRole($role)
    {
        if (!$this->hasRole($role)) {
            error_log("BaseController: Access denied for role $role, user roles: " . json_encode($this->userRoles));
            http_response_code(403);
            include __DIR__ . '/../views/errors/403.php';
            exit;
        }
    }

    protected function requireAnyRole(...$roles)
    {

        if (!isset($this->userRoles) || empty($this->userRoles)) {
            http_response_code(403);
            include __DIR__ . '/../views/errors/403.php';
            exit;
        }

        $hasRole = array_intersect(
            array_map('strtolower', $roles),
            array_map('strtolower', $this->userRoles)
        );

        error_log("requireAnyRole: Result - hasRole: " . json_encode($hasRole) . ", empty: " . (empty($hasRole) ? 'yes' : 'no'));

        if (empty($hasRole)) {
            http_response_code(403);
            include __DIR__ . '/../views/errors/403.php';
            exit;
        }
    }

    protected function getCurrentUserId()
    {
        return $_SESSION['user_id'] ?? null;
    }
}
