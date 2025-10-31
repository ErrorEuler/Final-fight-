<?php
require_once __DIR__ . '/../services/AuthService.php';
require_once __DIR__ . '/../services/EmailService.php';
require_once __DIR__ . '/../config/Database.php';
require_once __DIR__ . '/../models/UserModel.php';

class AuthController
{
    private $authService;
    private $db;
    private $userModel;

    public function __construct()
    {
        if (session_status() === PHP_SESSION_NONE) {
            session_start();
        }

        $this->db = (new Database())->connect();
        $this->authService = new AuthService($this->db);
        $this->userModel = new UserModel($this->db);
    }

    /**
     * Handle login request
     */
    public function login()
    {
        if ($this->authService->isLoggedIn()) {
            $this->redirectBasedOnRole();
        }

        $rememberMe = isset($_POST['remember-me']) && $_POST['remember-me'] === '1';
        $error = $_GET['error'] ?? '';

        if ($_SERVER['REQUEST_METHOD'] === 'POST') {
            $employeeId = trim($_POST['employee_id'] ?? '');
            $password = $_POST['password'] ?? '';

            if (empty($employeeId) || empty($password)) {
                error_log("Login failed: Missing employee_id or password");
                $error = "Employee ID and password are required.";
                require_once __DIR__ . '/../views/auth/login.php';
                return;
            }

            $userData = $this->authService->login($employeeId, $password);

            if ($userData) {
                // Let AuthService handle all session setup
                $this->authService->startSession($userData);

                error_log("Login successful for employee_id: $employeeId with roles: " . json_encode($_SESSION['roles']));

                if ($rememberMe) {
                    $token = bin2hex(random_bytes(32));
                    $expiry = time() + (30 * 24 * 60 * 60);
                    setcookie('remember_me', $token, $expiry, '/', '', true, true);

                    $updateQuery = "UPDATE users SET remember_token = :token, remember_token_expiry = :expiry WHERE user_id = :user_id";
                    $stmt = $this->db->prepare($updateQuery);
                    $stmt->execute([
                        ':token' => $token,
                        ':expiry' => date('Y-m-d H:i:s', $expiry),
                        ':user_id' => $userData['user_id']
                    ]);
                    error_log("Remember token saved for user_id: " . $userData['user_id']);
                } else {
                    if (isset($_COOKIE['remember_me'])) {
                        $updateQuery = "UPDATE users SET remember_token = NULL, remember_token_expiry = NULL WHERE user_id = :user_id";
                        $stmt = $this->db->prepare($updateQuery);
                        $stmt->execute([':user_id' => $userData['user_id']]);
                        setcookie('remember_me', '', time() - 3600, '/', '', true, true);
                    }
                }

                $this->redirectBasedOnRole();
            } else {
                error_log("Login failed for employee_id: $employeeId - Invalid credentials");
                $error = "Invalid Employee ID or password.";
                require_once __DIR__ . '/../views/auth/login.php';
            }
        } else {
            if (isset($_COOKIE['remember_me'])) {
                $token = $_COOKIE['remember_me'];
                $userData = $this->authService->loginWithToken($token);

                if ($userData) {
                    $this->authService->startSession($userData);
                    error_log("Auto-login successful for user_id: " . $userData['user_id']);
                    $this->redirectBasedOnRole();
                } else {
                    error_log("Auto-login failed for token: $token");
                    setcookie('remember_me', '', time() - 3600, '/', '', true, true);
                }
            }
            require_once __DIR__ . '/../views/auth/login.php';
        }
    }
    
    /**
     * Handle registration request
     */
    public function register()
    {
        if ($this->authService->isLoggedIn()) {
            $this->redirectBasedOnRole();
        }

        if ($_SERVER['REQUEST_METHOD'] === 'POST') {
            error_log("Received roles: " . print_r($_POST['roles'] ?? 'empty', true));
            error_log("Received department_ids: " . print_r($_POST['department_ids'] ?? 'empty', true));

            // Handle department IDs - can be multiple for Program Chair
            $departmentIds = [];
            $primaryDepartmentId = 0;

            if (isset($_POST['department_ids']) && is_array($_POST['department_ids'])) {
                // Multiple departments selected (Program Chair)
                $departmentIds = array_map('intval', $_POST['department_ids']);
                $primaryDepartmentId = intval($_POST['primary_department_id'] ?? 0);

                // If no primary set, use first one
                if ($primaryDepartmentId === 0 && !empty($departmentIds)) {
                    $primaryDepartmentId = $departmentIds[0];
                }
            } else {
                // Single department
                $primaryDepartmentId = intval($_POST['department_id'] ?? 0);
                $departmentIds = [$primaryDepartmentId];
            }

            $data = [
                'employee_id' => trim($_POST['employee_id'] ?? ''),
                'username' => trim($_POST['username'] ?? ''),
                'password' => $_POST['password'] ?? '',
                'email' => trim($_POST['email'] ?? ''),
                'first_name' => trim($_POST['first_name'] ?? ''),
                'middle_name' => trim($_POST['middle_name'] ?? ''),
                'last_name' => trim($_POST['last_name'] ?? ''),
                'suffix' => trim($_POST['suffix'] ?? ''),
                'phone' => trim($_POST['phone'] ?? ''),
                'roles' => isset($_POST['roles']) ? array_map('intval', (array)$_POST['roles']) : [],
                'college_id' => intval($_POST['college_id'] ?? 0),
                'department_id' => $primaryDepartmentId, // Primary department
                'department_ids' => $departmentIds, // All selected departments
                'academic_rank' => trim($_POST['academic_rank'] ?? ''),
                'employment_type' => trim($_POST['employment_type'] ?? ''),
                'classification' => trim($_POST['classification'] ?? ''),
                'program_id' => !empty($_POST['program_id']) ? intval($_POST['program_id']) : null,
                'role_id' => !empty($_POST['roles']) ? (int)reset($_POST['roles']) : null
            ];

            error_log("Data to be registered: " . json_encode($data));

            $errors = [];

            // Basic validation
            if (empty($data['employee_id'])) $errors[] = "Employee ID is required.";
            if (empty($data['username'])) $errors[] = "Username is required.";
            if (empty($data['password']) || strlen($data['password']) < 6) {
                $errors[] = "Password must be at least 6 characters.";
            }
            if (empty($data['email']) || !filter_var($data['email'], FILTER_VALIDATE_EMAIL)) {
                $errors[] = "Valid email is required.";
            }
            if (empty($data['first_name'])) $errors[] = "First name is required.";
            if (empty($data['last_name'])) $errors[] = "Last name is required.";
            if (empty($data['roles'])) $errors[] = "At least one role must be selected.";
            if (empty($data['college_id'])) $errors[] = "College is required.";
            if (empty($data['department_ids'])) $errors[] = "At least one department is required.";
            if (empty($data['role_id'])) $errors[] = "A valid role is required.";

            // Check if Program Chair is selected
            $isProgramChair = in_array(5, $data['roles']);

            if ($isProgramChair) {
                if (count($data['department_ids']) === 0) {
                    $errors[] = "Program Chair must be assigned to at least one department.";
                }

                if (count($data['department_ids']) > 1 && empty($data['department_id'])) {
                    $errors[] = "Please select a primary department.";
                }

                // Get program_id from first department (you may need to adjust this logic)
                if (empty($data['program_id'])) {
                    try {
                        $programs = $this->userModel->getProgramsByDepartment($data['department_id']);
                        if (!empty($programs)) {
                            $data['program_id'] = $programs[0]['program_id'];
                        } else {
                            $errors[] = "No program found for the selected department.";
                        }
                    } catch (Exception $e) {
                        $errors[] = "Error loading program information.";
                    }
                }
            }

            if (empty($errors)) {
                try {
                    if ($this->authService->register($data)) {
                        $deptCount = count($data['department_ids']);
                        $deptText = $deptCount > 1 ? "$deptCount departments" : "1 department";

                        $success = $isProgramChair || in_array(6, $data['roles'])
                            ? "Registration submitted successfully for $deptText. Awaiting Dean approval."
                            : "Registration successful. You can now log in.";

                        header('Location: /login?success=' . urlencode($success));
                        exit;
                    } else {
                        $error = "Registration failed. Employee ID or email may already be in use.";
                        require_once __DIR__ . '/../views/auth/register.php';
                    }
                } catch (Exception $e) {
                    $error = $e->getMessage();
                    error_log("Registration exception: " . $error);
                    require_once __DIR__ . '/../views/auth/register.php';
                }
            } else {
                $error = implode("<br>", $errors);
                require_once __DIR__ . '/../views/auth/register.php';
            }
        } else {
            require_once __DIR__ . '/../views/auth/register.php';
        }
    }

    /**
     * Handle forgot password request
     */
    public function forgotPassword()
    {
        header('Content-Type: application/json');
        error_log("Forgot password request received for employee_id: " . ($_POST['employee_id'] ?? 'N/A'));

        if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
            echo json_encode(['success' => false, 'message' => 'Invalid request method.']);
            exit;
        }

        $employeeId = trim($_POST['employee_id'] ?? '');

        if (empty($employeeId)) {
            echo json_encode(['success' => false, 'message' => 'Employee ID is required.']);
            exit;
        }

        $query = "SELECT user_id, email, first_name FROM users WHERE employee_id = :employee_id AND is_active = 1";
        $stmt = $this->db->prepare($query);
        $stmt->execute([':employee_id' => $employeeId]);
        $user = $stmt->fetch(PDO::FETCH_ASSOC);

        if ($user) {
            $token = bin2hex(random_bytes(32));
            $expiry = time() + (24 * 60 * 60);
            $updateQuery = "UPDATE users SET reset_token = :token, reset_token_expiry = :expiry WHERE user_id = :user_id";
            $stmt = $this->db->prepare($updateQuery);
            $stmt->execute([
                ':token' => $token,
                ':expiry' => date('Y-m-d H:i:s', $expiry),
                ':user_id' => $user['user_id']
            ]);

            $emailService = new EmailService();
            $resetLink = "http://localhost:8000/reset-password?token=" . $token;
            try {
                if ($emailService->sendForgotPasswordEmail($user['email'], $user['first_name'], $resetLink)) {
                    echo json_encode(['success' => true, 'message' => 'A password reset link has been sent to your email.']);
                } else {
                    echo json_encode(['success' => false, 'message' => 'Failed to send reset email. Please try again or contact support.']);
                    error_log("Failed to send forgot password email to " . $user['email'] . " - Email service error");
                }
            } catch (Exception $e) {
                echo json_encode(['success' => false, 'message' => 'Failed to send reset email. Please try again or contact support.']);
                error_log("Exception in sending forgot password email to " . $user['email'] . ": " . $e->getMessage());
            }
        } else {
            echo json_encode(['success' => false, 'message' => 'No active account found with that Employee ID.']);
        }
        exit;
    }
    /**
     * Handle password reset request
     */
    public function resetPassword()
    {
        if ($_SERVER['REQUEST_METHOD'] === 'POST') {
            $token = $_POST['token'] ?? '';
            $newPassword = $_POST['password'] ?? '';

            if (empty($token) || empty($newPassword)) {
                $error = "Token and new password are required.";
                require_once __DIR__ . '/../views/auth/reset_password.php';
                return;
            }

            $query = "SELECT user_id FROM users WHERE reset_token = :token AND reset_token_expiry > NOW()";
            $stmt = $this->db->prepare($query);
            $stmt->execute([':token' => $token]);
            $user = $stmt->fetch(PDO::FETCH_ASSOC);

            if ($user) {
                $passwordHash = password_hash($newPassword, PASSWORD_DEFAULT);
                $updateQuery = "UPDATE users SET password_hash = :password_hash, reset_token = NULL, reset_token_expiry = NULL WHERE user_id = :user_id";
                $stmt = $this->db->prepare($updateQuery);
                $stmt->execute([
                    ':password_hash' => $passwordHash,
                    ':user_id' => $user['user_id']
                ]);
                $success = "Password reset successfully. You can now <a href='/login'>login</a>.";
            } else {
                $error = "Invalid or expired reset token.";
            }
            require_once __DIR__ . '/../views/auth/reset_password.php';
        } else {
            $token = $_GET['token'] ?? '';
            if (empty($token)) {
                $error = "Invalid reset token.";
                require_once __DIR__ . '/../views/auth/reset_password.php';
                return;
            }
            require_once __DIR__ . '/../views/auth/reset_password.php';
        }
    }

    /**
     * Get departments API endpoint
     */
    public function getDepartments()
    {
        header('Content-Type: application/json');

        try {
            $collegeId = intval($_GET['college_id'] ?? 0);
            if ($collegeId < 1) {
                echo json_encode([
                    'success' => false,
                    'message' => 'Invalid college ID'
                ]);
                exit;
            }

            $userModel = new UserModel();
            $departments = $userModel->getDepartmentsByCollege($collegeId);

            echo json_encode([
                'success' => true,
                'departments' => $departments
            ]);
        } catch (Exception $e) {
            error_log("Error in getDepartments: " . $e->getMessage());
            echo json_encode([
                'success' => false,
                'message' => 'Error loading departments: ' . $e->getMessage()
            ]);
        }
        exit;
    }

    public function switchRole()
    {
        try {
            // Check if user is logged in
            if (!isset($_SESSION['user_id'])) {
                http_response_code(401);
                echo json_encode(['success' => false, 'error' => 'Unauthorized']);
                return;
            }

            // Get the requested role from POST data
            $role = $_POST['role'] ?? '';
            if (empty($role)) {
                http_response_code(400);
                echo json_encode(['success' => false, 'error' => 'Role is required']);
                return;
            }

            // Fetch user's available roles
            $userId = $_SESSION['user_id'];
            $roles = $this->userModel->getUserRoles($userId);
            $availableRoles = array_column($roles, 'role_name');

            // Validate the requested role
            $roleLower = strtolower($role);
            if (!in_array(ucfirst($role), $availableRoles)) {
                http_response_code(403);
                echo json_encode(['success' => false, 'error' => 'Invalid role']);
                return;
            }

            // Update session with the new current role
            $_SESSION['current_role'] = ucfirst($role);
            error_log("Switched role to: " . $_SESSION['current_role'] . " for user_id: $userId");

            // Determine redirect URL based on role
            $redirectUrl = '/';
            switch ($roleLower) {
                case 'program_chair':
                    $redirectUrl = '/chair/dashboard';
                    break;
                case 'faculty':
                    $redirectUrl = '/faculty/dashboard';
                    break;
                case 'dean':
                    $redirectUrl = '/dean/dashboard'; // Add dean route if not already defined
                    break;
                    // Add other roles as needed
            }

            // Return success response
            echo json_encode([
                'success' => true,
                'message' => 'Role switched successfully',
                'redirect' => $redirectUrl
            ]);
        } catch (Exception $e) {
            error_log("Error switching role: " . $e->getMessage());
            http_response_code(500);
            echo json_encode(['success' => false, 'error' => 'Internal server error']);
        }
    }

    /**
     * Handle logout request
     */
    public function logout()
    {
        $this->authService->logout();
        header('Location: /home');
        exit;
    }

    /**
     * Redirect based on user role
     */
    private function redirectBasedOnRole()
    {
        $roles = $_SESSION['roles'] ?? [];
        error_log("redirectBasedOnRole: User roles: " . json_encode($roles));

        if (empty($roles)) {
            error_log("redirectBasedOnRole: No roles found, logging out");
            $this->logout();
            exit;
        }

        $roleMappings = [
            'admin' => '/admin/dashboard',
            'vpaa' => '/admin/dashboard',
            'd.i' => '/director/dashboard',  // Add this to handle "D.I" from database
            'dean' => '/dean/dashboard',
            'chair' => '/chair/dashboard',
            'faculty' => '/faculty/dashboard'
        ];

        foreach ($roles as $role) {
            $role = strtolower(trim($role));
            if (isset($roleMappings[$role])) {
                error_log("redirectBasedOnRole: Redirecting to " . $roleMappings[$role] . " for role $role");

                // CRITICAL: Ensure session cookie is sent
                session_regenerate_id(false); // Regenerate but keep data

                // Force immediate redirect with session cookie
                $url = $roleMappings[$role];
                header("Location: $url", true, 303); // 303 See Other (POST to GET)
                exit;
            }
        }

        error_log("redirectBasedOnRole: No valid role found, logging out");
        $this->logout();
        exit;
    }
}
