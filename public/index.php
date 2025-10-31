<?php
require __DIR__ . '/../vendor/autoload.php';

// Load environment
Dotenv\Dotenv::createImmutable(__DIR__ . '/../')->load();

// Initialize secure session
session_start([
    'cookie_lifetime' => 86400,
    'cookie_secure' => isset($_SERVER['HTTPS']),
    'cookie_httponly' => true,
    'use_strict_mode' => true
]);

// Include middleware
require_once __DIR__ . '/../src/middleware/AuthMiddleware.php';

// Define route handler functions
function handleAdminRoutes($path)
{
    error_log("Entering handleAdminRoutes with path: $path");
    require_once __DIR__ . '/../src/controllers/AdminController.php';
    $controller = new AdminController();

    $normalizedPath = '/' . trim($path, '/');
    error_log("Normalized path: $normalizedPath");

    switch ($normalizedPath) {
        case '/admin/dashboard':
            error_log("Routing to AdminController::dashboard");
            $controller->dashboard();
            break;
        case '/admin/act_logs':
            error_log("Routing to AdminController::activityLogs");
            $controller->activityLogs();
            break;
        case '/admin/act_logs/load-more':
            error_log("Routing to loadMore");
            $controller->loadMore();
            break;
        case '/admin/act_logs/generate-pdf':
            error_log("Routing to AdminController::generateActivityPDF");
            $controller->generateActivityPDF();
            break;
        case '/admin/act_logs/view-pdf':
            error_log("Routing to AdminController::viewActivityPDF");
            $controller->viewActivityPDF();
            break;
        case '/admin/act_logs/download-pdf':
            error_log("Routing to AdminController::downloadActivityPDF");
            $controller->downloadActivityPDF();
            break;
        case '/admin/schedule':
            error_log("Routing to AdminController::schedule");
            $controller->mySchedule();
            break;
        case '/admin/users':
        case '/admin/edit_user':
            error_log("Routing to AdminController::users");
            $controller->manageUsers();
            break;
        case '/admin/colleges':
        case '/admin/departments':
        case '/admin/colleges_departments':
            error_log("Routing to AdminController::collegesDepartments");
            $controller->collegesDepartments();
            break;
        case '/admin/colleges_departments/create':
            error_log("Routing to AdminController::createCollegeDepartment");
            $controller->createCollegeDepartment();
            break;
        case '/admin/colleges_departments/update':
            error_log("Routing to AdminController::update college/departments");
            $controller->updateCollegeDepartment();
            break;
        case '/admin/classroom':
            error_log("Routing to AdminController::classroom");
            $controller->classroom();
            break;
        case '/admin/faculty':
            error_log("Routing to AdminController::faculty");
            $controller->faculty();
            break;
        case '/admin/faculty/create':
            error_log("Routing to AdminController::createFaculty");
            $controller->createFaculty();
            break;
        case '/admin/schedules':
            error_log("Routing to AdminController::schedules");
            $controller->schedules();
            break;
        case '/admin/profile':
            error_log("Routing to AdminController::profile");
            $controller->profile();
            break;
        case '/admin/settings':
            error_log("Routing to AdminController::settings");
            $controller->settings();
            break;
        case '/admin/database-backup':
            error_log("Routing to AdminController::backupDatabase");
            $controller->databaseBackup();
            break;
        case '/admin/logout':
            error_log("Routing to AuthController::logout");
            require_once __DIR__ . '/../src/controllers/AuthController.php';
            (new AuthController())->logout();
            exit;
        default:
            error_log("No matching admin route for: $normalizedPath");
            http_response_code(404);
            echo "404 Not Found: $normalizedPath";
            exit;
    }
}

function handleVpaaRoutes($path)
{
    AuthMiddleware::handle('vpaa'); // Require vpaa role
    http_response_code(404);
    echo "VPAA routes not implemented";
    exit;
}

function handleDirectorRoutes($path)
{
    error_log("Entering handleDirectorRoutes with path: $path");
    require_once __DIR__ . '/../src/controllers/DirectorController.php';
    $controller = new DirectorController();

    $normalizedPath = '/' . trim($path, '/');
    error_log("Normalized path: $normalizedPath");

    switch ($normalizedPath) {
        case '/director/dashboard':
            error_log("Routing to DirectorController::dashboard");
            $controller->dashboard();
            break;
        case '/director/schedule':
            error_log("Routing to DirectorController::mySchedule");
            $controller->mySchedule();
            break;
        case '/director/approve-teaching-load':
            $controller->approveTeachingLoadDirector();
            break;
        case '/director/reject-teaching-load':
            $controller->rejectTeachingLoadDirector();
            break;
        case '/director/api/all-approval-status':
            $controller->getFacultyApprovalStatusDirector($_GET['facultyId'] ?? null);
            exit; // Add exit here to prevent further execution
            break;
        case '/director/api/all-schedule':  // ADD THIS ROUTE
            $controller->getFacultySchedule($_GET['facultyId'] ?? null);
            exit;
            break;
        case '/director/api/all-schedule':
            $controller->collegeTeachingLoad($_GET['facultyId'] ?? null);
            exit; // Add exit here to prevent further execution
            break;
        case '/director/all-teaching-load':
            $controller->collegeTeachingLoad();
            break;
        case '/director/monitor':
            error_log("Routing to DirectorController::monitoring");
            $controller->monitor();
            break;
        case '/director/monitor/load-more':
            error_log("Routing to loadMore");
            $controller->loadMore();
            break;
        case '/director/profile':
            error_log("Routing to DirectorController::profile");
            $controller->profile();
            break;
        case '/director/schedule_deadline':
            error_log("Routing to DirectorController::setSchedule");
            $controller->setScheduleDeadline();
            break;
        case '/director/pending-approvals':
            error_log("Routing to DirectorController::pendingApprovalsView");
            $controller->manageSchedule();
            break;
        case '/director/settings':
            error_log("Routing to DirectorController::settings");
            $controller->settings();
            break;
        case '/director/logout':
            error_log("Routing to AuthController::logout");
            require_once __DIR__ . '/../src/controllers/AuthController.php';
            (new AuthController())->logout();
            exit;
        default:
            http_response_code(404);
            echo "Page not found";
            exit;
    }
}

function handleDeanRoutes($path)
{
    error_log("Entering handleDeanRoutes with path: $path");

    require_once __DIR__ . '/../src/controllers/DeanController.php';
    $controller = new DeanController();

    $normalizedPath = '/' . trim($path, '/');
    error_log("Normalized path: $normalizedPath");

    switch ($normalizedPath) {
        case '/dean/dashboard':
            $controller->dashboard();
            break;
        case '/dean/schedule':
            $controller->mySchedule();
            break;
        case '/dean/manage_schedules':
            $controller->manageSchedule();
            break;
        case '/dean/approve-teaching-load':
            $controller->approveTeachingLoad();
            break;
        case '/dean/reject-teaching-load':
            $controller->rejectTeachingLoad();
            break;
        case '/dean/api/faculty-approval-status':
            $controller->getFacultyApprovalStatus($_GET['facultyId'] ?? null);
            exit; // Add exit here to prevent further execution
            break;
        case '/dean/api/faculty-schedule':
            $controller->getFacultySchedule($_GET['facultyId'] ?? null);
            exit; // Add exit here to prevent further execution
            break;
        case '/dean/faculty-teaching-load':
            $controller->facultyTeachingLoad();
            break;
        case '/dean/manage_department':
            $controller->manageDepartments();
            break;
        case '/dean/activities':
            $controller->activities();
            break;
        case '/dean/activities/load-more':
            error_log("Routing to loadMoreActivities");
            $controller->loadMoreActivities();
            break;
        case '/dean/classroom':
            $controller->classroom();
            break;
        case '/dean/faculty':
            $controller->faculty();
            break;
        case '/dean/search':
            $controller->search();
            break;
        case '/dean/courses':
            $controller->courses();
            break;
        case '/dean/curriculum':
            $controller->curriculum();
            break;
        case '/dean/profile':
            $controller->profile();
            break;
        case '/dean/profile/search_courses':
            $controller->searchCourses();
            exit;
        case '/dean/settings':
            $controller->settings();
            break;
        case '/dean/logout':
            error_log("Routing to AuthController::logout");
            require_once __DIR__ . '/../src/controllers/AuthController.php';
            (new AuthController())->logout();
            exit;
        default:
            http_response_code(404);
            echo "Page not found";
            exit;
    }
}

function handleChairRoutes($path)
{
    error_log("Entering handleChairRoutes with path: $path");

    require_once __DIR__ . '/../src/controllers/ChairController.php';
    $controller = new ChairController();

    $normalizedPath = '/' . trim($path, '/');
    error_log("Normalized path: $normalizedPath");

    switch ($normalizedPath) {
        case '/chair/dashboard':
            error_log("Routing to ChairController::dashboard");
            $controller->dashboard();
            exit;
        case '/chair/switch-department':
            error_log("Routing to ChairController::switchDepartment");
            $controller->switchDepartment();
            exit;
        case '/chair/my_schedule':
            error_log("Routing to ChairController::my_schedule");
            $controller->mySchedule();
            exit;
        case '/chair/api/faculty-schedule':
            $controller->getFacultyScheduleForChair($_GET['facultyId'] ?? null);
            exit; // Add exit here to prevent further execution
            break;
        case '/chair/faculty-teaching-load':
            $controller->departmentTeachingLoad();
            break;
        case '/chair/schedule_management':
            error_log("Routing to ChairController::createSchedule");
            $controller->manageSchedule();
            exit;
        case '/chair/generate-schedules':
            error_log("Routing to ChairController::generateSchedule");
            $controller->generateSchedulesAjax();
            exit;
        case '/chair/delete-all-schedules':
            error_log("Routing to ChairController::delete all schedules");
            $controller->deleteAllSchedules();
            break;
        case '/chair/schedule_history':
            error_log("Routing to ChairController::scheduleHistory");
            $controller->viewScheduleHistory();
            exit;
        case '/chair/classroom':
            error_log("Routing to ChairController::classroom");
            $controller->classroom();
            exit;
        case '/chair/sections':
            error_log("Routing to ChairController::sections");
            $controller->sections();
            exit;
        case '/chair/faculty':
            error_log("Routing to ChairController::faculty");
            $controller->faculty();
            exit;
        case '/chair/faculty/search':
            error_log("Routing to ChairController::search");
            $controller->search();
            exit;
        case '/chair/courses':
            error_log("Routing to ChairController::courses");
            $controller->courses();
            exit;
        case '/chair/checkCourseCode':
            error_log("Routing to ChairController::checkCourseCode");
            $controller->checkCourseCode();
            break;
        case '/chair/curriculum':
            error_log("Routing to ChairController::curriculum");
            $controller->curriculum();
            exit;
        case '/chair/profile':
            error_log("Routing to ChairController::profile");
            $controller->profile();
            exit;
        case '/chair/profile/search_courses':
            error_log("Routing to ChairController::profile");
            $controller->searchCourses();
            exit;
        case '/chair/settings':
            error_log("Routing to ChairController::settings");
            $controller->settings();
            exit;
        case '/chair/logout':
            error_log("Routing to AuthController::logout");
            require_once __DIR__ . '/../src/controllers/AuthController.php';
            (new AuthController())->logout();
            exit;
        default:
            error_log("No matching chair route for: $normalizedPath");
            http_response_code(404);
            echo "404 Not Found: $normalizedPath";
            exit;
    }
}

function handleFacultyRoutes($path)
{
    error_log("Entering handleFacultyRoutes with path: $path");

    require_once __DIR__ . '/../src/controllers/FacultyController.php';
    $controller = new FacultyController();

    $normalizedPath = '/' . trim($path, '/');
    error_log("Normalized path: $normalizedPath");

    switch ($normalizedPath) {
        case '/faculty/dashboard':
            error_log("Routing to FacultyController::dashboard");
            $controller->dashboard();
            exit;
        case '/faculty/schedule':
            error_log("Routing to FacultyController::mySchedule");
            $controller->mySchedule();
            exit;
        case '/faculty/schedule/request':
            if ($_SERVER['REQUEST_METHOD'] === 'GET') {
                error_log("Routing to FacultyController::submitScheduleRequest (GET)");
                $controller->submitScheduleRequest();
            } elseif ($_SERVER['REQUEST_METHOD'] === 'POST') {
                error_log("Routing to FacultyController::submitScheduleRequest (POST)");
                $controller->submitScheduleRequest();
            }
            exit;
        case '/faculty/schedule/requests':
            error_log("Routing to FacultyController::getScheduleRequests");
            $controller->getScheduleRequests();
            exit;
        case '/faculty/profile':
            if ($_SERVER['REQUEST_METHOD'] === 'GET') {
                error_log("Routing to FacultyController::profile (GET)");
                $controller->profile();
            } elseif ($_SERVER['REQUEST_METHOD'] === 'POST') {
                error_log("Routing to FacultyController::profile (POST)");
                $controller->profile();
            }
            exit;
        case '/faculty/profile/search_courses':
            error_log("Routing to FacultyController::profile");
            $controller->searchCourses();
            exit;
        case '/faculty/logout':
            error_log("Routing to AuthController::logout");
            require_once __DIR__ . '/../src/controllers/AuthController.php';
            (new AuthController())->logout();
            exit;
        case '/faculty/settings':
            $controller->settings();
            exit;
        default:
            error_log("No matching faculty route for: $normalizedPath");
            http_response_code(404);
            echo "404 Not Found: $normalizedPath";
            exit;
    }
}

// Simple router
$path = trim(parse_url($_SERVER['REQUEST_URI'], PHP_URL_PATH), '/');

// Public routes that don't require authentication
$publicRoutes = ['login', 'register', '', 'home', 'public/search', 'public/departments', 'public/sections', 'forgot-password', 'api/departments'];

if (in_array($path, $publicRoutes)) {
    require_once __DIR__ . '/../src/controllers/AuthController.php';
    $controller = new AuthController();

    switch ($path) {
        case 'login':
            $controller->login();
            break;
        case 'register':
            $controller->register();
            break;
        case 'forgot-password':
            $controller->forgotPassword();
            break;
        case 'api/departments':
            if ($_SERVER['REQUEST_METHOD'] === 'GET') {
                $controller->getDepartments();
            } else {
                http_response_code(405);
                echo "Method Not Allowed";
            }
            break;
        case '':
        case 'home':
            require_once __DIR__ . '/../src/controllers/PublicController.php';
            (new PublicController())->showHomepage();
            break;
        case 'public/search':
            if ($_SERVER['REQUEST_METHOD'] === 'POST') {
                require_once __DIR__ . '/../src/controllers/PublicController.php';
                (new PublicController())->searchSchedules();
            } else {
                http_response_code(405);
                echo "Method Not Allowed";
            }
            break;
        case 'public/departments':
            if ($_SERVER['REQUEST_METHOD'] === 'POST') {
                require_once __DIR__ . '/../src/controllers/PublicController.php';
                (new PublicController())->getDepartmentsByCollege();
            } else {
                http_response_code(405);
                echo "Method Not Allowed";
            }
            break;
        case 'public/sections':
            if ($_SERVER['REQUEST_METHOD'] === 'POST') {
                require_once __DIR__ . '/../src/controllers/PublicController.php';
                (new PublicController())->getSectionsByDepartment();
            } else {
                http_response_code(405);
                echo "Method Not Allowed";
            }
            break;
        default:
            http_response_code(404);
            echo "Page not found";
            break;
    }
    exit;
}

// Protected routes - require authentication
if (!isset($_SESSION['user_id'])) {
    error_log("User not authenticated, redirecting to /login");
    header('Location: /login');
    exit;
}

// Handle API routes before role-specific routes
if ($path === 'api/load_data') {
    error_log("Routing to ApiController::loadData for path: $path");
    require_once __DIR__ . '/../src/controllers/ApiController.php';
    $controller = new ApiController();
    $controller->loadData();
    exit;
}

if (preg_match('#^api/departments/(\d+)/programs$#', $path, $matches)) {
    error_log("Routing to ApiController::getPrograms for department_id: " . $matches[1]);
    require_once __DIR__ . '/../src/controllers/ApiController.php';
    $controller = new ApiController();
    $controller->getPrograms($matches[1]);
    exit;
}

// Add this BEFORE the role switch handler for debugging
if ($path === 'switch-role' && $_SERVER['REQUEST_METHOD'] === 'GET') {
    header('Content-Type: application/json');
    echo json_encode([
        'session_id' => session_id(),
        'user_id' => $_SESSION['user_id'] ?? null,
        'roles' => $_SESSION['roles'] ?? [],
        'current_role' => $_SESSION['current_role'] ?? null,
        'post_data' => $_POST
    ]);
    exit;
}

// Handle role switching for multi-role users
if ($path === 'switch-role' && $_SERVER['REQUEST_METHOD'] === 'POST') {
    header('Content-Type: application/json');

    // Security checks
    if (!isset($_SESSION['user_id'])) {
        http_response_code(401);
        echo json_encode(['error' => 'Unauthorized']);
        exit;
    }

    $requestedRole = $_POST['role'] ?? null;
    $userRoles = $_SESSION['roles'] ?? [];

    // Log for debugging
    error_log("Role switch attempt - Requested: " . $requestedRole);
    error_log("User roles: " . json_encode($userRoles));

    if (!$requestedRole) {
        http_response_code(400);
        echo json_encode(['error' => 'Role not specified']);
        exit;
    }

    // Normalize roles for comparison (case-insensitive)
    $normalizedUserRoles = array_map('strtolower', $userRoles);
    $normalizedRequestedRole = strtolower($requestedRole);

    error_log("Normalized requested role: " . $normalizedRequestedRole);
    error_log("Normalized user roles: " . json_encode($normalizedUserRoles));

    // Check if requested role exists in user's roles
    if (!in_array($normalizedRequestedRole, $normalizedUserRoles)) {
        error_log("Role not found in user roles!");
        http_response_code(400);
        echo json_encode([
            'error' => 'Invalid role',
            'requested' => $requestedRole,
            'available' => $userRoles
        ]);
        exit;
    }

    // Find the actual role from the session (preserve original case)
    $actualRole = null;
    foreach ($userRoles as $role) {
        if (strtolower($role) === $normalizedRequestedRole) {
            $actualRole = $role;
            break;
        }
    }

    // Update current_role with the actual role from session
    $_SESSION['current_role'] = $actualRole;
    error_log("Role switched successfully for user_id: {$_SESSION['user_id']}, new role: $actualRole");

    // Determine redirect URL based on role
    $redirectUrl = '/';
    switch ($normalizedRequestedRole) {
        case 'admin':
            $redirectUrl = '/admin/dashboard';
            break;
        case 'vpaa':
            $redirectUrl = '/admin/dashboard';
            break;
        case 'd.i':
            $redirectUrl = '/director/dashboard';
            break;
        case 'dean':
            $redirectUrl = '/dean/dashboard';
            break;
        case 'chair':
            $redirectUrl = '/chair/dashboard';
            break;
        case 'faculty':
            $redirectUrl = '/faculty/dashboard';
            break;
        default:
            error_log("Unknown role for redirect: $normalizedRequestedRole");
            $redirectUrl = '/';
    }

    echo json_encode([
        'success' => true,
        'message' => "Switched to $actualRole role",
        'redirect' => $redirectUrl,
        'redirect' => $redirectUrl,
        'pdf_access' => true // Indicate PDF functionality is available
    ]);
    exit;
}

// Get user roles from session
$roles = $_SESSION['roles'] ?? [];
$currentRole = $_SESSION['current_role'] ?? (empty($roles) ? null : $roles[0]);

// If no roles or current_role, redirect to login
if (empty($roles) || !$currentRole) {
    error_log("No roles or current_role in session, redirecting to login");
    header('Location: /login');
    exit;
}

error_log("Routing for current_role: $currentRole");

// Handle role-specific routes
switch (strtolower($currentRole)) {
    case 'admin':
        handleAdminRoutes($path);
        break;
    case 'vpaa':
        handleAdminRoutes($path); // VPAA uses admin routes
        break;
    case 'd.i':
        handleDirectorRoutes($path);
        break;
    case 'dean':
        handleDeanRoutes($path);
        break;
    case 'chair':
        handleChairRoutes($path);
        break;
    case 'faculty':
        handleFacultyRoutes($path);
        break;
    default:
        error_log("Unknown current_role: $currentRole");
        http_response_code(403);
        echo "Unauthorized role";
        exit;
}

// If no route matched, show 404
http_response_code(404);
echo "Page not found";
exit;
