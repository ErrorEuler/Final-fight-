<?php

class AuthMiddleware
{
    private static $roleMap = [
        'admin' => 1,
        'vpaa' => 2,
        'd.i' => 3,
        'dean' => 4,
        'chair' => 5,
        'faculty' => 6
    ];

    public static function handle($requiredRoles = null)
    {
        if (session_status() === PHP_SESSION_NONE) {
            session_start();
        }

        if (!isset($_SESSION['user_id'])) {
            error_log("AuthMiddleware: No user session, redirecting to /login");
            header('Location: /login');
            exit;
        }

        if ($requiredRoles) {
            $requiredRoles = is_array($requiredRoles) ? $requiredRoles : [$requiredRoles];
            $requiredRoleIds = [];
            foreach ($requiredRoles as $role) {
                $roleId = self::$roleMap[strtolower($role)] ?? null;
                if ($roleId) {
                    $requiredRoleIds[] = $roleId;
                }
            }

            $userRoles = $_SESSION['roles'] ?? [];
            $userRoleIds = array_map(function ($role) {
                return self::$roleMap[strtolower($role)] ?? null;
            }, $userRoles);

            error_log("AuthMiddleware: Required role IDs: " . json_encode($requiredRoleIds) . ", User role IDs: " . json_encode($userRoleIds));

            if (empty(array_intersect($userRoleIds, $requiredRoleIds))) {
                error_log("AuthMiddleware: Role mismatch, denying access");
                http_response_code(403);
                include __DIR__ . '/../views/errors/403.php';
                exit;
            }
        }

        error_log("AuthMiddleware: Access granted for user_id: " . $_SESSION['user_id']);
    }
}
