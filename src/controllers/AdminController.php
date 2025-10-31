<?php
require_once __DIR__ . '/../config/Database.php';
require_once __DIR__ . '/../services/AuthService.php';
require_once __DIR__ . '/../services/EmailService.php';
require_once __DIR__ . '/../services/PdfService.php';
require_once __DIR__ . '/../models/UserModel.php';
class AdminController
{
    public $db;
    private $authService;
    private $emailService;
    private $pdfService;
    private $UserModel;

    public function __construct()  // Remove the $db parameter since we're not using it
    {
        error_log("AdminController instantiated");
        $this->db = (new Database())->connect();
        if ($this->db === null) {
            error_log("Failed to connect to the database in AdminController");
            die("Database connection failed. Please try again later.");
        }

        $this->emailService = new EmailService();
        $this->authService = new AuthService($this->db);
        $this->UserModel = new UserModel($this->db);
        $this->pdfService = new PdfService();
        $this->db->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
    }

    private function getUserData()
    {
        try {
            $stmt = $this->db->prepare("SELECT * FROM users WHERE user_id = :user_id");
            $stmt->execute([':user_id' => $_SESSION['user_id']]);
            return $stmt->fetch(PDO::FETCH_ASSOC);
        } catch (PDOException $e) {
            error_log("getUserData error: " . $e->getMessage());
            return null;
        }
    }

    public function dashboard()
    {
        try {
            // Fetch stats (your existing code)
            $userCount = $this->db->query("SELECT COUNT(*) FROM users")->fetchColumn();
            $collegeCount = $this->db->query("SELECT COUNT(*) FROM colleges")->fetchColumn();
            $departmentCount = $this->db->query("SELECT COUNT(*) FROM departments")->fetchColumn();
            $scheduleCount = $this->db->query("SELECT COUNT(*) FROM schedules")->fetchColumn();

            // Get user role distribution
            $roleStmt = $this->db->query("
        SELECT r.role_name, COUNT(u.user_id) as count 
        FROM users u 
        JOIN roles r ON u.role_id = r.role_id 
        GROUP BY r.role_name
        ");
            $roleDistribution = $roleStmt->fetchAll(PDO::FETCH_ASSOC);

            // Get schedule status distribution
            $scheduleStmt = $this->db->query("
        SELECT status, COUNT(*) as count 
        FROM schedules 
        GROUP BY status
        ");
            $scheduleDistribution = $scheduleStmt->fetchAll(PDO::FETCH_ASSOC);

            // Fetch current semester (your existing code)
            $currentSemesterStmt = $this->db->query("SELECT semester_name, academic_year FROM semesters WHERE is_current = 1 LIMIT 1");
            $currentSemester = $currentSemesterStmt->fetch(PDO::FETCH_ASSOC);
            $semesterInfo = $currentSemester ? "{$currentSemester['semester_name']} Semester A.Y {$currentSemester['academic_year']}" : '2nd Semester 2024-2025';

            // Fetch all available semesters (your existing code)
            $semestersStmt = $this->db->query("SELECT semester_id, semester_name, academic_year FROM semesters ORDER BY start_date DESC");
            $semesters = $semestersStmt->fetchAll(PDO::FETCH_ASSOC);

            // Handle semester set form submission (your existing code)
            if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['set_semester'])) {
                // ... your existing semester handling code
            }

            $controller = $this;
            require_once __DIR__ . '/../views/admin/dashboard.php';
        } catch (PDOException $e) {
            error_log("Dashboard error: " . $e->getMessage());
            http_response_code(500);
            echo "Server error";
        }
    }

    public function activityLogs()
    {
        try {
            // Get current semester information
            $currentSemester = $this->UserModel->getCurrentSemester();
            $currentSemesterDisplay = $currentSemester ?
                $currentSemester['semester_name'] . ' Semester, A.Y ' . $currentSemester['academic_year'] : 'Not Set';

            // Get filters from request for the HTML view
            $filters = $this->getFiltersFromRequest();

            // Use the same data fetching method for consistency
            $activities = $this->getActivitiesData(['limit' => 50] + $filters); // Limit for web view

            $data = [
                'activities' => $activities,
                'title' => 'Activity Monitor - All Departments',
                'current_semester_display' => $currentSemesterDisplay,
                'current_semester' => $currentSemester,
                'filters' => $filters // Pass filters to view if needed
            ];

            $controller = $this;
            require_once __DIR__ . '/../views/admin/act_logs.php';
        } catch (PDOException $e) {
            error_log("Activity logs error: " . $e->getMessage());
            $_SESSION['error'] = "Server error";
            header('Location: /admin/dashboard');
            exit;
        }
    }

    public function loadMore()
    {
        ob_clean(); // Clear any existing output buffer
        ob_start(); // Start a new buffer for this response

        error_log("loadMore called with offset: " . ($_POST['offset'] ?? 'null'));

        if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
            error_log("Method not allowed, returning 405");
            http_response_code(405);
            echo json_encode(['error' => 'Method not allowed. Use POST.']);
            ob_end_flush();
            exit;
        }

        try {
            $userData = $this->getUserData();
            if (!$userData) {
                error_log("loadMore: Failed to load user data for user_id: " . ($_SESSION['user_id'] ?? 'null'));
                http_response_code(401);
                echo json_encode(['error' => 'Unauthorized']);
                ob_end_flush();
                exit;
            }

            $offset = (int)($_POST['offset'] ?? 0);

            $activityStmt = $this->db->prepare("
            SELECT al.log_id, al.action_type, al.action_description, al.created_at, u.first_name, u.last_name,
                   d.department_name, col.college_name
            FROM activity_logs al
            JOIN users u ON al.user_id = u.user_id
            JOIN departments d ON al.department_id = d.department_id
            JOIN colleges col ON d.college_id = col.college_id
            ORDER BY al.created_at DESC
            LIMIT 10 OFFSET :offset
        ");
            $activityStmt->bindValue(':offset', $offset, PDO::PARAM_INT);
            $activityStmt->execute();
            $activities = $activityStmt->fetchAll(PDO::FETCH_ASSOC);

            header('Content-Type: application/json');
            error_log("Sending JSON response with " . count($activities) . " activities");
            echo json_encode([
                'success' => true,
                'activities' => $activities,
                'hasMore' => count($activities) === 10
            ]);
            ob_end_flush();
        } catch (PDOException $e) {
            error_log("loadMore: Database error - " . $e->getMessage());
            http_response_code(500);
            echo json_encode(['error' => 'Failed to load more activities']);
            ob_end_flush();
        }
        exit; // Ensure script stops after response
    }

    /**
     * Get activities data with optional filtering
     */
    private function getActivitiesData($filters = [])
    {
        try {
            // Build the base query (same as your activityLogs method)
            $sql = "
            SELECT al.log_id, al.action_type, al.action_description, al.created_at, 
                   u.first_name, u.last_name, d.department_name, col.college_name
            FROM activity_logs al
            JOIN users u ON al.user_id = u.user_id
            JOIN departments d ON al.department_id = d.department_id
            JOIN colleges col ON d.college_id = col.college_id
        ";

            $params = [];
            $whereConditions = [];

            // Apply filters if provided
            if (!empty($filters)) {
                // Date range filter
                if (isset($filters['dateRange']) && $filters['dateRange'] !== 'all') {
                    $dateCondition = $this->buildDateCondition($filters['dateRange'], $filters['startDate'] ?? null, $filters['endDate'] ?? null);
                    if ($dateCondition) {
                        $whereConditions[] = $dateCondition['condition'];
                        $params = array_merge($params, $dateCondition['params']);
                    }
                }

                // College filter
                if (isset($filters['college']) && $filters['college'] !== 'all') {
                    $whereConditions[] = "col.college_name = :college";
                    $params[':college'] = $filters['college'];
                }

                // Department filter
                if (isset($filters['department']) && $filters['department'] !== 'all') {
                    $whereConditions[] = "d.department_name = :department";
                    $params[':department'] = $filters['department'];
                }

                // Action type filter
                if (isset($filters['actionType']) && $filters['actionType'] !== 'all') {
                    $whereConditions[] = "al.action_type = :actionType";
                    $params[':actionType'] = $filters['actionType'];
                }

                // Time filter
                if (isset($filters['timeFilter']) && $filters['timeFilter'] !== 'all') {
                    $timeCondition = $this->buildTimeCondition($filters['timeFilter']);
                    if ($timeCondition) {
                        $whereConditions[] = $timeCondition;
                    }
                }
            }

            // Add WHERE clause if we have conditions
            if (!empty($whereConditions)) {
                $sql .= " WHERE " . implode(" AND ", $whereConditions);
            }

            // Add ordering
            $sql .= " ORDER BY al.created_at DESC";

            // For PDF, we might want all records or a larger limit
            $limit = isset($filters['limit']) ? (int)$filters['limit'] : 1000; // Larger limit for PDF
            $sql .= " LIMIT :limit";
            $params[':limit'] = $limit;

            $stmt = $this->db->prepare($sql);

            // Bind parameters
            foreach ($params as $key => $value) {
                $paramType = is_int($value) ? PDO::PARAM_INT : PDO::PARAM_STR;
                $stmt->bindValue($key, $value, $paramType);
            }

            $stmt->execute();
            return $stmt->fetchAll(PDO::FETCH_ASSOC);
        } catch (PDOException $e) {
            error_log("getActivitiesData error: " . $e->getMessage());
            throw new Exception("Failed to fetch activities data");
        }
    }

    /**
     * Get filters from request (POST or GET)
     */
    private function getFiltersFromRequest()
    {
        $filters = [
            'dateRange' => $_POST['dateRange'] ?? $_GET['dateRange'] ?? 'all',
            'startDate' => $_POST['startDate'] ?? $_GET['startDate'] ?? null,
            'endDate' => $_POST['endDate'] ?? $_GET['endDate'] ?? null,
            'timeFilter' => $_POST['timeFilter'] ?? $_GET['timeFilter'] ?? 'all',
            'college' => $_POST['college'] ?? $_GET['college'] ?? 'all',
            'department' => $_POST['department'] ?? $_GET['department'] ?? 'all',
            'actionType' => $_POST['actionType'] ?? $_GET['actionType'] ?? 'all',
            'limit' => $_POST['limit'] ?? $_GET['limit'] ?? 1000
        ];

        return $filters;
    }

    /**
     * Build date condition for SQL query
     */
    private function buildDateCondition($dateRange, $startDate = null, $endDate = null)
    {
        $conditions = [];
        $params = [];

        switch ($dateRange) {
            case 'today':
                $conditions[] = "DATE(al.created_at) = CURDATE()";
                break;

            case 'yesterday':
                $conditions[] = "DATE(al.created_at) = DATE_SUB(CURDATE(), INTERVAL 1 DAY)";
                break;

            case 'week':
                $conditions[] = "al.created_at >= DATE_SUB(CURDATE(), INTERVAL 7 DAY)";
                break;

            case 'month':
                $conditions[] = "al.created_at >= DATE_SUB(CURDATE(), INTERVAL 30 DAY)";
                break;

            case 'custom':
                if ($startDate && $endDate) {
                    $conditions[] = "DATE(al.created_at) BETWEEN :startDate AND :endDate";
                    $params[':startDate'] = $startDate;
                    $params[':endDate'] = $endDate;
                }
                break;

            default:
                // 'all' or unknown - no date filter
                return null;
        }

        if (empty($conditions)) {
            return null;
        }

        return [
            'condition' => implode(" AND ", $conditions),
            'params' => $params
        ];
    }

    /**
     * Build time condition for SQL query
     */
    private function buildTimeCondition($timeFilter)
    {
        switch ($timeFilter) {
            case 'morning':
                return "HOUR(al.created_at) BETWEEN 6 AND 11";
            case 'afternoon':
                return "HOUR(al.created_at) BETWEEN 12 AND 17";
            case 'evening':
                return "HOUR(al.created_at) BETWEEN 18 AND 23";
            case 'night':
                return "HOUR(al.created_at) BETWEEN 0 AND 5";
            default:
                return null; // 'all' - no time filter
        }
    }

    // In AdminController.php
    public function generateActivityPDF()
    {
        // Get activities data (use your existing method)
        $activities = $this->getActivitiesData();
        $filters = $this->getFiltersFromRequest();

        // Generate PDF
        $pdfData = $this->pdfService->generateActivityReport($activities, $filters, "Your University");

        // Send as download
        $filename = "activity_report_" . date('Y-m-d') . ".pdf";
        $this->pdfService->sendAsDownload($pdfData, $filename);
    }

    public function viewActivityPDF()
    {
        $activities = $this->getActivitiesData();
        $filters = $this->getFiltersFromRequest();

        $pdfData = $this->pdfService->generateActivityReport($activities, $filters, "Your University");
        $this->pdfService->outputToBrowser($pdfData);
    }

    public function downloadActivityPDF()
    {
        $activities = $this->getActivitiesData();
        $filters = $this->getFiltersFromRequest();

        $pdfData = $this->pdfService->generateActivityReport($activities, $filters, "Your University");

        $filename = "activity_report_" . date('Y-m-d_H-i') . ".pdf";
        $this->pdfService->sendAsDownload($pdfData, $filename);
    }

    public function mySchedule()
    {
        try {
            $adminId = $_SESSION['user_id'];
            error_log("mySchedule: Starting mySchedule method for user_id: $adminId");

            // Fetch faculty ID and name with join to users table
            $facultyStmt = $this->db->prepare("
            SELECT f.faculty_id, CONCAT(u.title, ' ', u.first_name, ' ', u.middle_name, ' ', u.last_name, ' ', u.suffix) AS faculty_name 
            FROM faculty f 
            JOIN users u ON f.user_id = u.user_id 
            WHERE u.user_id = :user_id
        ");
            $facultyStmt->execute([':user_id' => $adminId]);
            $faculty = $facultyStmt->fetch(PDO::FETCH_ASSOC);

            if (!$faculty) {
                $error = "No faculty profile found for this user.";
                require_once __DIR__ . '/../views/admin/schedule.php';
                return;
            }
            $facultyId = $faculty['faculty_id'];
            $facultyName = $faculty['faculty_name'];

            // Fetch faculty position and employment status
            $positionStmt = $this->db->prepare("SELECT academic_rank FROM faculty WHERE faculty_id = :faculty_id");
            $positionStmt->execute([':faculty_id' => $facultyId]);
            $facultyPosition = $positionStmt->fetchColumn() ?: 'Not Specified';

            // Get department and college details (corrected join)
            $deptStmt = $this->db->prepare("
            SELECT d.department_name, c.college_name 
            FROM users u 
            JOIN faculty f ON f.user_id = u.user_id
             
            JOIN departments d ON u.department_id = d.department_id 
            JOIN colleges c ON d.college_id = c.college_id 
            WHERE u.user_id = :user_id 
        ");
            $deptStmt->execute([':user_id' => $adminId]);
            $department = $deptStmt->fetch(PDO::FETCH_ASSOC);
            $departmentName = $department['department_name'] ?? 'Not Assigned';
            $collegeName = $department['college_name'] ?? 'Not Assigned';

            $semesterStmt = $this->db->query("SELECT semester_id, semester_name, academic_year FROM semesters WHERE is_current = 1");
            $semester = $semesterStmt->fetch(PDO::FETCH_ASSOC);

            if (!$semester) {
                error_log("mySchedule: No current semester found");
                $error = "No current semester defined. Please contact the administrator to set the current semester.";
                require_once __DIR__ . '/../views/admin/schedule.php';
                return;
            }
            $semesterId = $semester['semester_id'];
            $semesterName = $semester['semester_name'] . ' Semester, AY ' . $semester['academic_year'];
            error_log("mySchedule: Current semester ID: $semesterId, Name: $semesterName");

            $schedulesStmt = $this->db->prepare("
            SELECT s.schedule_id, c.course_code, c.course_name, r.room_name, s.day_of_week, 
                   s.start_time, s.end_time, s.schedule_type, COALESCE(sec.section_name, 'N/A') AS section_name,
                   TIMESTAMPDIFF(MINUTE, s.start_time, s.end_time) / 60 AS duration_hours
            FROM schedules s
            LEFT JOIN courses c ON s.course_id = c.course_id
            LEFT JOIN sections sec ON s.section_id = sec.section_id
            LEFT JOIN classrooms r ON s.room_id = r.room_id
            WHERE s.faculty_id = :faculty_id AND s.semester_id = :semester_id
            ORDER BY FIELD(s.day_of_week, 'Monday', 'Tuesday', 'Wednesday', 'Thursday', 'Friday', 'Saturday'), s.start_time
        ");
            $schedulesStmt->execute([':faculty_id' => $facultyId, ':semester_id' => $semesterId]);
            $schedules = $schedulesStmt->fetchAll(PDO::FETCH_ASSOC);
            error_log("mySchedule: Fetched " . count($schedules) . " schedules for faculty_id $facultyId in semester $semesterId");

            $showAllSchedules = false;
            if (empty($schedules)) {
                error_log("mySchedule: No schedules found for current semester, trying to fetch all schedules");
                $schedulesStmt = $this->db->prepare("
                SELECT s.schedule_id, c.course_code, c.course_name, r.room_name, s.day_of_week, 
                       s.start_time, s.end_time, s.schedule_type, COALESCE(sec.section_name, 'N/A') AS section_name,
                       TIMESTAMPDIFF(MINUTE, s.start_time, s.end_time) / 60 AS duration_hours
                FROM schedules s
                LEFT JOIN courses c ON s.course_id = c.course_id
                LEFT JOIN sections sec ON s.section_id = sec.section_id
                LEFT JOIN classrooms r ON s.room_id = r.room_id
                WHERE s.faculty_id = :faculty_id
                ORDER BY FIELD(s.day_of_week, 'Monday', 'Tuesday', 'Wednesday', 'Thursday', 'Friday', 'Saturday'), s.start_time
            ");
                $schedulesStmt->execute([':faculty_id' => $facultyId]);
                $schedules = $schedulesStmt->fetchAll(PDO::FETCH_ASSOC);
                $showAllSchedules = true;
                error_log("mySchedule: Fetched " . count($schedules) . " total schedules for faculty_id $facultyId");
            }

            if (empty($schedules)) {
                error_log("mySchedule: No schedules found after fallback. Checking raw data...");
                $debugStmt = $this->db->prepare("SELECT * FROM schedules WHERE faculty_id = :faculty_id");
                $debugStmt->execute([':faculty_id' => $facultyId]);
                $debugSchedules = $debugStmt->fetchAll(PDO::FETCH_ASSOC);
                error_log("mySchedule: Debug - Found " . count($debugSchedules) . " raw schedules for faculty_id $facultyId");
            }

            $totalHours = 0;
            foreach ($schedules as $schedule) {
                $totalHours += $schedule['duration_hours'];
            }
            error_log("mySchedule: Total hours calculated: $totalHours");

            require_once __DIR__ . '/../views/admin/schedule.php';
        } catch (Exception $e) {
            error_log("mySchedule: Full error: " . $e->getMessage());
            http_response_code(500);
            echo "Error loading schedule: " . htmlspecialchars($e->getMessage());
            exit;
        }
    }

    public function manageUsers()
    {
        try {
            $action = $_GET['action'] ?? 'list';
            $userId = $_GET['user_id'] ?? null;
            $csrfToken = $this->authService->generateCsrfToken();

            // Fetch common data
            $usersStmt = $this->db->query("
            SELECT u.user_id, u.employee_id, u.title, u.username, u.first_name, u.middle_name, u.last_name, u.suffix, u.is_active, u.email, u.profile_picture, u.phone,                    -- ADD THIS
                u.created_at, r.role_name, c.college_id, c.college_name, d.department_id, d.department_name, f.academic_rank, f.employment_type, f.classification, bachelor_degree,
                f.master_degree, f.doctorate_degree, f.post_doctorate_degree, f.designation, 
                cd.department_id as chair_department_id,
                deans.college_id as dean_college_id,
                di.department_id as instructor_department_id
            FROM users u
            JOIN roles r ON u.role_id = r.role_id
            LEFT JOIN faculty f ON u.user_id = f.user_id
            LEFT JOIN colleges c ON u.college_id = c.college_id
            LEFT JOIN departments d ON u.department_id = d.department_id
            LEFT JOIN chair_departments cd ON u.user_id = cd.user_id AND cd.is_primary = 1
            LEFT JOIN deans ON u.user_id = deans.user_id AND deans.is_current = 1
            LEFT JOIN department_instructors di ON u.user_id = di.user_id AND di.is_current = 1
            ORDER BY u.first_name, u.last_name
            ");
            $users = $usersStmt->fetchAll(PDO::FETCH_ASSOC);

            $roles = $this->db->query("SELECT role_id, role_name FROM roles ORDER BY role_name")->fetchAll(PDO::FETCH_ASSOC);
            $colleges = $this->db->query("SELECT college_id, college_name FROM colleges ORDER BY college_name")->fetchAll(PDO::FETCH_ASSOC);
            $departments = $this->db->query("SELECT department_id, department_name, college_id FROM departments ORDER BY department_name")->fetchAll(PDO::FETCH_ASSOC);
            $programs = $this->db->query("SELECT program_id, program_name, department_id FROM programs ORDER BY program_name")->fetchAll(PDO::FETCH_ASSOC);
            // FIX: Populate the enum data properly
            $titles = ['Mr.', 'Ms.', 'Mrs.', 'Dr.', 'Prof.', 'Engr.', 'Atty.'];
            $academicRanks = [
                'Instructor I',
                'Instructor II',
                'Instructor III',
                'Assistant Professor I',
                'Assistant Professor II',
                'Assistant Professor III',
                'Assistant Professor IV',
                'Associate Professor I',
                'Associate Professor II',
                'Associate Professor III',
                'Associate Professor IV',
                'Associate Professor V',
                'Professor I',
                'Professor II',
                'Professor III',
                'Professor IV',
                'Professor V',
                'Professor VI'
            ];
            $employmentTypes = ['Regular', 'Contractual', 'Part-time', 'Full-time'];
            $classifications = ['TL', 'VSL'];

            if ($_SERVER['REQUEST_METHOD'] === 'POST') {
                if (!$this->authService->verifyCsrfToken($_POST['csrf_token'] ?? '')) {
                    $_SESSION['flash'] = ['type' => 'error', 'message' => 'Invalid CSRF token'];
                    header('Location: /admin/users');
                    exit;
                }

                $this->db->beginTransaction();

                try {
                    $data = $_POST;
                    $data['user_id'] = $userId;

                    if ($action === 'add') {
                        $result = $this->addNewUser($data);
                    } else {
                        $result = $this->handleUserAction($data);
                    }

                    $this->db->commit();
                    $_SESSION['flash'] = ['type' => $result['success'] ? 'success' : 'error', 'message' => $result['message'] ?? $result['error']];

                    header('Content-Type: application/json');
                    echo json_encode($result);
                    exit;
                } catch (PDOException $e) {
                    $this->db->rollBack();
                    error_log("User action error ($action): " . $e->getMessage());
                    $_SESSION['flash'] = ['type' => 'error', 'message' => 'Failed to process user action'];
                    header('Content-Type: application/json');
                    echo json_encode(['success' => false, 'message' => 'Database error occurred']);
                    exit;
                }
            }

            // Group departments by college for the form
            $departmentsByCollege = [];
            foreach ($departments as $dept) {
                $departmentsByCollege[$dept['college_id']][] = $dept;
            }

            // In your manageUsers() function, before requiring the view:
            $controller = $this;

            // Pass all data to the view
            $viewData = [
                'users' => $users,
                'roles' => $roles,
                'colleges' => $colleges,
                'departments' => $departments,
                'programs' => $programs,
                'titles' => $titles,
                'academicRanks' => $academicRanks,
                'employmentTypes' => $employmentTypes,
                'classifications' => $classifications,
                'departmentsByCollege' => $departmentsByCollege,
                'csrfToken' => $csrfToken
            ];

            extract($viewData);

            require_once __DIR__ . '/../views/admin/users.php';
        } catch (PDOException $e) {
            error_log("Manage users error: " . $e->getMessage());
            http_response_code(500);
            echo "Server error";
        }
    }

    private function addNewUser($data)
    {
        try {
            // Validate required fields
            $required = ['employee_id', 'username', 'email', 'first_name', 'last_name', 'role_id'];
            foreach ($required as $field) {
                if (empty($data[$field])) {
                    return ['success' => false, 'error' => "Field '$field' is required"];
                }
            }

            // Check for existing user
            $checkStmt = $this->db->prepare("
            SELECT user_id FROM users WHERE username = :username OR email = :email OR employee_id = :employee_id
        ");
            $checkStmt->execute([
                ':username' => $data['username'],
                ':email' => $data['email'],
                ':employee_id' => $data['employee_id']
            ]);

            if ($checkStmt->fetch()) {
                return ['success' => false, 'error' => 'Username, email, or employee ID already exists'];
            }

            // Generate temporary password
            // Hash the generated password
            $passwordHash = password_hash($data['temporary_password'], PASSWORD_DEFAULT);

            // Start transaction
            $this->db->beginTransaction();

            // Insert user
            $stmt = $this->db->prepare("
            INSERT INTO users (
                employee_id, username, password_hash, email, phone, title, first_name, middle_name, 
                last_name, suffix, role_id, college_id, department_id, is_active, created_at, updated_at
            ) VALUES (
                :employee_id, :username, :password_hash, :email, :phone, :title, :first_name, :middle_name,
                :last_name, :suffix, :role_id, :college_id, :department_id, 1, NOW(), NOW()
            )
        ");

            $userData = [
                ':employee_id' => $data['employee_id'],
                ':username' => $data['username'],
                ':password_hash' => $passwordHash,
                ':email' => $data['email'],
                ':phone' => $data['phone'] ?? null,
                ':title' => $data['title'] ?? null,
                ':first_name' => $data['first_name'],
                ':middle_name' => $data['middle_name'] ?? null,
                ':last_name' => $data['last_name'],
                ':suffix' => $data['suffix'] ?? null,
                ':role_id' => $data['role_id'],
                ':college_id' => !empty($data['college_id']) ? $data['college_id'] : null,
                ':department_id' => !empty($data['department_id']) ? $data['department_id'] : null
            ];

            $stmt->execute($userData);
            $newUserId = $this->db->lastInsertId();

            // Insert into faculty table for ALL user roles
            $facultyStmt = $this->db->prepare("
            INSERT INTO faculty (
                user_id, employee_id, academic_rank, employment_type, classification, max_hours,
                bachelor_degree, master_degree, doctorate_degree, post_doctorate_degree,
                designation, equiv_teaching_load, total_lecture_hours, total_laboratory_hours,
                total_laboratory_hours_x075, no_of_preparation, advisory_class,
                equiv_units_no_of_prep, actual_teaching_loads, total_working_load, excess_hours,
                primary_program_id, secondary_program_id, created_at, updated_at
            ) VALUES (
                :user_id, :employee_id, :academic_rank, :employment_type, :classification, :max_hours,
                :bachelor_degree, :master_degree, :doctorate_degree, :post_doctorate_degree,
                :designation, :equiv_teaching_load, :total_lecture_hours, :total_laboratory_hours,
                :total_laboratory_hours_x075, :no_of_preparation, :advisory_class,
                :equiv_units_no_of_prep, :actual_teaching_loads, :total_working_load, :excess_hours,
                :primary_program_id, :secondary_program_id, NOW(), NOW()
            )
        ");

            $facultyData = [
                ':user_id' => $newUserId,
                ':employee_id' => $data['employee_id'],
                ':academic_rank' => $data['academic_rank'] ?? null,
                ':employment_type' => $data['employment_type'] ?? null,
                ':classification' => $data['classification'] ?? null,
                ':max_hours' => $data['max_hours'] ?? 18.00,
                ':bachelor_degree' => $data['bachelor_degree'] ?? null,
                ':master_degree' => $data['master_degree'] ?? null,
                ':doctorate_degree' => $data['doctorate_degree'] ?? null,
                ':post_doctorate_degree' => $data['post_doctorate_degree'] ?? null,
                ':designation' => $data['designation'] ?? null,
                ':equiv_teaching_load' => $data['equiv_teaching_load'] ?? null,
                ':total_lecture_hours' => $data['total_lecture_hours'] ?? null,
                ':total_laboratory_hours' => $data['total_laboratory_hours'] ?? null,
                ':total_laboratory_hours_x075' => $data['total_laboratory_hours_x075'] ?? null,
                ':no_of_preparation' => $data['no_of_preparation'] ?? null,
                ':advisory_class' => $data['advisory_class'] ?? null,
                ':equiv_units_no_of_prep' => $data['equiv_units_no_of_prep'] ?? null,
                ':actual_teaching_loads' => $data['actual_teaching_loads'] ?? null,
                ':total_working_load' => $data['total_working_load'] ?? null,
                ':excess_hours' => $data['excess_hours'] ?? null,
                ':primary_program_id' => $data['primary_program_id'] ?? null,
                ':secondary_program_id' => $data['secondary_program_id'] ?? null
            ];

            $facultyStmt->execute($facultyData);

            // Handle role-specific assignments
            $this->handleRoleSpecificAssignments($newUserId, $data);

            // Commit transaction
            $this->db->commit();

            // Send welcome email (optional)
            if (isset($data['send_welcome_email']) && $data['send_welcome_email']) {
                $this->emailService->getWelcomeEmailTemplate(
                    $data['email'],
                    $data['first_name'],
                    $data['employee_id'],
                    $data['temporary_password']
                );
            }

            return [
                'success' => true,
                'message' => 'User added successfully',
                'user_id' => $newUserId,
            ];
        } catch (Exception $e) {
            // Rollback transaction on error
            $this->db->rollBack();
            error_log("addNewUser error: " . $e->getMessage());
            return ['success' => false, 'error' => 'Failed to add user: ' . $e->getMessage()];
        }
    }

    private function handleRoleSpecificAssignments($userId, $data)
    {
        $roleId = $data['role_id'];

        switch ($roleId) {
            case 3: //d.1
                $this->UserModel->addDepartmentInstructor($data);
                break;
            case 4: //dean
                $this->UserModel->addDean($data);
                break;
            case 5: //program chair
                $this->UserModel->addProgramChair($data);
                break;
            case 6: //faculty
                $this->UserModel->addFaculty($data);
                break;
        }
    }

    private function generateTemporaryPassword($length = 12)
    {
        $chars = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*';
        $password = '';
        for ($i = 0; $i < $length; $i++) {
            $password .= $chars[random_int(0, strlen($chars) - 1)];
        }
        return $password;
    }

    public function showTemporaryPassword($userId)
    {
        if (isset($_SESSION['temp_passwords'][$userId])) {
            $tempData = $_SESSION['temp_passwords'][$userId];

            // Remove from session after displaying (one-time view)
            unset($_SESSION['temp_passwords'][$userId]);

            return [
                'success' => true,
                'password' => $tempData['password'],
                'username' => $tempData['username'],
                'timestamp' => $tempData['timestamp']
            ];
        }

        return ['success' => false, 'error' => 'Temporary password not found or already viewed'];
    }

    public function resetUserPassword($userId)
    {
        try {
            $stmt = $this->db->prepare("SELECT username, email FROM users WHERE user_id = :user_id");
            $stmt->execute([':user_id' => $userId]);
            $user = $stmt->fetch(PDO::FETCH_ASSOC);

            if (!$user) {
                return ['success' => false, 'error' => 'User not found'];
            }

            $temporaryPassword = $this->generateTemporaryPassword();
            $passwordHash = password_hash($temporaryPassword, PASSWORD_DEFAULT);

            $updateStmt = $this->db->prepare("UPDATE users SET password_hash = :password_hash WHERE user_id = :user_id");
            $updateStmt->execute([
                ':password_hash' => $passwordHash,
                ':user_id' => $userId
            ]);

            // Store for one-time display
            $_SESSION['temp_passwords'][$userId] = [
                'password' => $temporaryPassword,
                'username' => $user['username'],
                'timestamp' => time()
            ];

            return [
                'success' => true,
                'message' => 'Password reset successfully',
                'user_id' => $userId,
                'temporary_password' => $temporaryPassword
            ];
        } catch (Exception $e) {
            error_log("resetUserPassword error: " . $e->getMessage());
            return ['success' => false, 'error' => 'Failed to reset password'];
        }
    }

    private function handleUserAction($data)
    {
        $userId = filter_var($data['user_id'], FILTER_VALIDATE_INT);
        $action = $data['action'];

        if (!$userId) {
            error_log("handleUserAction: Invalid user_id=$userId");
            return ['success' => false, 'error' => 'Invalid user ID'];
        }

        // Handle password reset action
        if ($action === 'reset_password') {
            return $this->resetUserPassword($userId);
        }

        // Fetch user details including college_id and department_id
        $stmt = $this->db->prepare("
        SELECT college_id, department_id, email, first_name, last_name, role_id
        FROM users
        WHERE user_id = :user_id
        ");
        $stmt->execute([':user_id' => $userId]);
        $user = $stmt->fetch(PDO::FETCH_ASSOC);

        if (!$user) {
            error_log("handleUserAction: No user found for user_id=$userId");
            return ['success' => false, 'error' => 'User not found'];
        }

        $collegeId = $user['college_id'] ?: null;
        $departmentId = $user['department_id'] ?: null;

        try {
            $this->db->beginTransaction();

            if ($action === 'deactivate') {
                $query = "UPDATE users SET is_active = 0 WHERE user_id = :user_id";
                $stmt = $this->db->prepare($query);
                $stmt->execute([':user_id' => $userId]);
                error_log("handleUserAction: Deactivated user_id=$userId");
                $message = 'User account deactivated successfully';
            } elseif ($action === 'activate') {
                $query = "UPDATE users SET is_active = 1 WHERE user_id = :user_id";
                $stmt = $this->db->prepare($query);
                $stmt->execute([':user_id' => $userId]);
                error_log("handleUserAction: Activated user_id=$userId");

                // Fetch role name for email
                $roleStmt = $this->db->prepare("SELECT role_name FROM roles WHERE role_id = :role_id");
                $roleStmt->execute([':role_id' => $user['role_id']]);
                $role = $roleStmt->fetchColumn();

                if ($user['email'] && $role) {
                    $this->emailService->sendApprovalEmail(
                        $user['email'],
                        $user['first_name'] . ' ' . $user['last_name'],
                        $role
                    );
                    error_log("handleUserAction: Approval email sent to {$user['email']}");
                } else {
                    error_log("handleUserAction: Failed to send email for user_id=$userId");
                }
                $message = 'User account activated successfully';
            } else {
                throw new Exception("Invalid action: $action");
            }

            $this->db->commit();
            return ['success' => true, 'message' => $message];
        } catch (Exception $e) {
            $this->db->rollBack();
            error_log("handleUserAction: Error - " . $e->getMessage());
            return ['success' => false, 'error' => 'An error occurred while processing the action: ' . $e->getMessage()];
        }
    }

    public function classroom()
    {
        try {
            $query = "
        SELECT 
            c.room_id, c.room_name, c.building, c.capacity, c.room_type, c.shared, c.availability,
            c.created_at, c.updated_at, c.department_id,
            d.department_name
        FROM classrooms c
        LEFT JOIN departments d ON c.department_id = d.department_id
        ";

            $query .= " ORDER BY c.department_id, c.room_name";

            // Prepare and execute the query
            $stmt = $this->db->prepare($query);
            $stmt->execute();

            // Fetch all results and store them in a variable
            $classrooms = $stmt->fetchAll(PDO::FETCH_ASSOC);

            $controller = $this;

            // Include the view file and pass the data to it
            require_once __DIR__ . '/../views/admin/classroom.php';
        } catch (PDOException $e) {
            error_log("Classroom error: " . $e->getMessage());
            http_response_code(500);
            echo "Server error";
        }
    }

    public function collegesDepartments()
    {
        try {
            $collegesStmt = $this->db->query("SELECT college_id, college_name, college_code FROM colleges");
            $colleges = $collegesStmt->fetchAll(PDO::FETCH_ASSOC);

            $departmentsStmt = $this->db->query("
            SELECT d.department_id, d.department_name, d.college_id, c.college_name, 
                   p.program_id, p.program_name, p.program_code
            FROM departments d
            JOIN colleges c ON d.college_id = c.college_id
            LEFT JOIN programs p ON d.department_id = p.department_id
            ");
            $departments = $departmentsStmt->fetchAll(PDO::FETCH_ASSOC);

            $controller = $this;
            require_once __DIR__ . '/../views/admin/colleges_departments.php';
        } catch (PDOException $e) {
            error_log("Colleges/Departments error: " . $e->getMessage());
            $_SESSION['error'] = "Server error";
            header('Location: /admin/dashboard');
            exit;
        }
    }

    public function createCollegeDepartment()
    {
        if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
            http_response_code(405);
            echo "Method Not Allowed";
            exit;
        }

        try {
            $type = $_POST['type'] ?? '';
            if ($type === 'college') {
                $college_name = trim($_POST['college_name'] ?? '');
                $college_code = trim($_POST['college_code'] ?? '');

                if (empty($college_name) || empty($college_code)) {
                    $_SESSION['error'] = "College name and code are required";
                    header('Location: /admin/colleges_departments'); // CHANGED
                    exit;
                }

                $stmt = $this->db->prepare("SELECT COUNT(*) FROM colleges WHERE college_code = :college_code");
                $stmt->execute([':college_code' => $college_code]);
                if ($stmt->fetchColumn() > 0) {
                    $_SESSION['error'] = "College code already exists";
                    header('Location: /admin/colleges_departments'); // CHANGED
                    exit;
                }

                $stmt = $this->db->prepare("
            INSERT INTO colleges (college_name, college_code)
            VALUES (:college_name, :college_code)
        ");
                $stmt->execute([
                    ':college_name' => $college_name,
                    ':college_code' => $college_code
                ]);

                $_SESSION['success'] = "College created successfully";
            } elseif ($type === 'department') {
                $department_name = trim($_POST['department_name'] ?? '');
                $college_id = $_POST['college_id'] ?? null;
                $program_name = trim($_POST['program_name'] ?? '');
                $program_code = trim($_POST['program_code'] ?? '');
                $program_type = $_POST['program_type'] ?? 'Major';

                if (empty($department_name) || empty($college_id) || empty($program_name) || empty($program_code)) {
                    $_SESSION['error'] = "Department name, college, program name, and program code are required";
                    header('Location: /admin/colleges_departments'); // CHANGED
                    exit;
                }

                // Check for duplicate department
                $stmt = $this->db->prepare("SELECT COUNT(*) FROM departments WHERE department_name = :department_name AND college_id = :college_id");
                $stmt->execute([':department_name' => $department_name, ':college_id' => $college_id]);
                if ($stmt->fetchColumn() > 0) {
                    $_SESSION['error'] = "Department already exists in this college";
                    header('Location: /admin/colleges_departments'); // CHANGED
                    exit;
                }

                // Check for duplicate program code
                $stmt = $this->db->prepare("SELECT COUNT(*) FROM programs WHERE program_code = :program_code");
                $stmt->execute([':program_code' => $program_code]);
                if ($stmt->fetchColumn() > 0) {
                    $_SESSION['error'] = "Program code already exists";
                    header('Location: /admin/colleges_departments'); // CHANGED
                    exit;
                }

                // Start transaction to ensure both department and program are created
                $this->db->beginTransaction();

                // Insert department
                $stmt = $this->db->prepare("
            INSERT INTO departments (department_name, college_id)
            VALUES (:department_name, :college_id)
        ");
                $stmt->execute([
                    ':department_name' => $department_name,
                    ':college_id' => $college_id
                ]);
                $departmentId = $this->db->lastInsertId();

                // Insert program
                $stmt = $this->db->prepare("
            INSERT INTO programs (program_name, program_code, program_type, department_id, is_active)
            VALUES (:program_name, :program_code, :program_type, :department_id, 1)
        ");
                $stmt->execute([
                    ':program_name' => $program_name,
                    ':program_code' => $program_code,
                    ':program_type' => $program_type,
                    ':department_id' => $departmentId
                ]);

                $this->db->commit();

                $_SESSION['success'] = "Department and associated program created successfully";
            } else {
                $_SESSION['error'] = "Invalid request type";
                header('Location: /admin/colleges_departments'); // CHANGED
                exit;
            }

            header('Location: /admin/colleges_departments'); // CHANGED
            exit;
        } catch (PDOException $e) {
            $this->db->rollBack();
            error_log("Create college/department error: " . $e->getMessage());
            $_SESSION['error'] = "Failed to create $type";
            header('Location: /admin/colleges_departments'); // CHANGED
            exit;
        }
    }

    public function updateCollegeDepartment()
    {
        if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
            http_response_code(405);
            echo "Method Not Allowed";
            exit;
        }

        try {
            $type = $_POST['type'] ?? '';
            $id = $_POST['id'] ?? '';

            if (empty($type) || empty($id)) {
                $_SESSION['error'] = "Invalid request";
                header('Location: /admin/colleges_departments'); // CHANGED
                exit;
            }

            if ($type === 'college') {
                $college_name = trim($_POST['college_name'] ?? '');
                $college_code = trim($_POST['college_code'] ?? '');

                if (empty($college_name) || empty($college_code)) {
                    $_SESSION['error'] = "College name and code are required";
                    header('Location: /admin/colleges_departments'); // CHANGED
                    exit;
                }

                $stmt = $this->db->prepare("UPDATE colleges SET college_name = :college_name, college_code = :college_code WHERE college_id = :id");
                $stmt->execute([':college_name' => $college_name, ':college_code' => $college_code, ':id' => $id]);
                $_SESSION['success'] = "College updated successfully";
            } elseif ($type === 'department') {
                $department_name = trim($_POST['department_name'] ?? '');
                $college_id = $_POST['college_id'] ?? null;
                $program_name = trim($_POST['program_name'] ?? '');
                $program_code = trim($_POST['program_code'] ?? '');
                $program_type = $_POST['program_type'] ?? 'Major';

                if (empty($department_name) || empty($college_id) || empty($program_name) || empty($program_code)) {
                    $_SESSION['error'] = "All fields are required";
                    header('Location: /admin/colleges_departments'); // CHANGED
                    exit;
                }

                $this->db->beginTransaction();
                $stmt = $this->db->prepare("UPDATE departments SET department_name = :department_name, college_id = :college_id WHERE department_id = :id");
                $stmt->execute([':department_name' => $department_name, ':college_id' => $college_id, ':id' => $id]);

                // Update or insert program (assuming one program per department for simplicity)
                $programStmt = $this->db->prepare("SELECT program_id FROM programs WHERE department_id = :id");
                $programStmt->execute([':id' => $id]);
                $program = $programStmt->fetch(PDO::FETCH_ASSOC);

                if ($program) {
                    $stmt = $this->db->prepare("UPDATE programs SET program_name = :program_name, program_code = :program_code, program_type = :program_type WHERE program_id = :program_id");
                    $stmt->execute([':program_name' => $program_name, ':program_code' => $program_code, ':program_type' => $program_type, ':program_id' => $program['program_id']]);
                } else {
                    $stmt = $this->db->prepare("INSERT INTO programs (program_name, program_code, program_type, department_id, is_active) VALUES (:program_name, :program_code, :program_type, :department_id, 1)");
                    $stmt->execute([':program_name' => $program_name, ':program_code' => $program_code, ':program_type' => $program_type, ':department_id' => $id]);
                }

                $this->db->commit();
                $_SESSION['success'] = "Department and program updated successfully";
            }

            header('Location: /admin/colleges_departments'); // CHANGED
            exit;
        } catch (PDOException $e) {
            $this->db->rollBack();
            error_log("Update college/department error: " . $e->getMessage());
            $_SESSION['error'] = "Failed to update $type";
            header('Location: /admin/colleges_departments'); // CHANGED
            exit;
        }
    }

    public function schedules()
    {
        try {
            $stmt = $this->db->query("
                SELECT s.schedule_id, c.course_name, u.first_name, u.last_name, cl.room_number, cl.building_name, s.day_of_week, s.start_time, s.end_time
                FROM schedules s
                JOIN courses c ON s.course_id = c.course_id
                JOIN faculty f ON s.faculty_id = f.faculty_id
                JOIN users u ON f.user_id = u.user_id
                JOIN classrooms cl ON s.classroom_id = cl.classroom_id
            ");
            $schedules = $stmt->fetchAll(PDO::FETCH_ASSOC);

            $controller = $this;
            require_once __DIR__ . '/../views/admin/schedules.php';
        } catch (PDOException $e) {
            error_log("Schedules error: " . $e->getMessage());
            http_response_code(500);
            echo "Server error";
        }
    }

    /**
     * View/edit profile
     */
    public function profile()
    {
        try {
            if (!$this->authService->isLoggedIn()) {
                $_SESSION['flash'] = ['type' => 'error', 'message' => 'Please log in to view your profile'];
                header('Location: /login');
                exit;
            }

            $userId = $_SESSION['user_id'];
            $csrfToken = $this->authService->generateCsrfToken();

            if ($_SERVER['REQUEST_METHOD'] === 'POST') {

                if (!$this->authService->verifyCsrfToken($_POST['csrf_token'] ?? '')) {
                    $_SESSION['flash'] = ['type' => 'error', 'message' => 'Invalid CSRF token'];
                    header('Location: /admin/profile');
                    exit;
                }

                $data = [
                    'email' => trim($_POST['email'] ?? ''),
                    'phone' => trim($_POST['phone'] ?? ''),
                    'username' => trim($_POST['username'] ?? ''),
                    'first_name' => trim($_POST['first_name'] ?? ''),
                    'middle_name' => trim($_POST['middle_name'] ?? ''),
                    'last_name' => trim($_POST['last_name'] ?? ''),
                    'suffix' => trim($_POST['suffix'] ?? ''),
                    'title' => trim($_POST['title'] ?? ''),
                    'classification' => trim($_POST['classification'] ?? ''),
                    'academic_rank' => trim($_POST['academic_rank'] ?? ''),
                    'employment_type' => trim($_POST['employment_type'] ?? ''),
                    'bachelor_degree' => trim($_POST['bachelor_degree'] ?? ''),
                    'master_degree' => trim($_POST['master_degree'] ?? ''),
                    'doctorate_degree' => trim($_POST['dpost_doctorate_degree'] ?? ''),
                    'post_doctorate_degree' => trim($_POST['bachelor_degree'] ?? ''),
                    'advisory_class' => trim($_POST['advisory_class'] ?? ''),
                    'designation' => trim($_POST['designation'] ?? ''),
                    'expertise_level' => trim($_POST['expertise_level'] ?? ''),
                    'course_id' => trim($_POST['course_id'] ?? ''),
                    'specialization_index' => trim($_POST['specialization_index'] ?? ''),
                    'action' => trim($_POST['action'] ?? ''),
                ];

                $errors = [];

                try {
                    $this->db->beginTransaction();

                    $profilePictureResult = $this->handleProfilePictureUpload($userId);
                    $profilePicturePath = null;

                    if ($profilePictureResult !== null) {
                        if (strpos($profilePictureResult, 'Error:') === 0) {
                            // It's an error message
                            $errors[] = $profilePictureResult;
                        } else {
                            // It's a successful upload path
                            $profilePicturePath = $profilePictureResult;
                        }
                    }

                    // Handle user profile updates only if fields are provided or profile picture uploaded
                    if (
                        !empty($data['email']) || !empty($data['first_name']) || !empty($data['last_name']) ||
                        !empty($data['phone']) || !empty($data['username']) || !empty($data['suffix']) ||
                        !empty($data['title']) || $profilePicturePath
                    ) {
                        // Validate required fields only if they are being updated
                        if (!empty($data['email']) && !filter_var($data['email'], FILTER_VALIDATE_EMAIL)) {
                            $errors[] = 'Valid email is required.';
                        }
                        if (!empty($data['phone']) && !preg_match('/^\d{10,12}$/', $data['phone'])) {
                            $errors[] = 'Phone number must be 10-12 digits.';
                        }
                        // And add this after your existing foreach loop for validFields:
                        if ($profilePicturePath) {
                            $setClause[] = "`profile_picture` = :profile_picture";
                            $params[":profile_picture"] = $profilePicturePath;
                        }

                        if (empty($errors)) {
                            $setClause = [];
                            $params = [':user_id' => $userId];
                            $validFields = ['email', 'phone', 'username', 'first_name', 'middle_name', 'last_name', 'suffix', 'title'];

                            foreach ($validFields as $field) {
                                if (isset($data[$field]) && $data[$field] !== '') {
                                    $setClause[] = "`$field` = :$field";
                                    $params[":$field"] = $data[$field];
                                }
                            }

                            // Add profile picture to update if uploaded
                            if ($profilePicturePath) {
                                $setClause[] = "`profile_picture` = :profile_picture";
                                $params[":profile_picture"] = $profilePicturePath;
                            }

                            if (!empty($setClause)) {
                                $userStmt = $this->db->prepare("UPDATE users SET " . implode(', ', $setClause) . ", updated_at = NOW() WHERE user_id = :user_id");

                                if (!$userStmt->execute($params)) {
                                    $errorInfo = $userStmt->errorInfo();
                                    error_log("profile: User update failed - " . print_r($errorInfo, true));
                                    throw new Exception("Failed to update user profile");
                                }
                                error_log("profile: User profile updated successfully");
                            }
                        }
                    }

                    // Get faculty ID
                    $facultyStmt = $this->db->prepare("SELECT faculty_id FROM faculty WHERE user_id = :user_id");
                    $facultyStmt->execute([':user_id' => $userId]);
                    $facultyId = $facultyStmt->fetchColumn();
                    error_log("profile: Retrieved faculty_id for user_id $userId: $facultyId");

                    if (!$facultyId) {
                        error_log("profile: No faculty record found for user_id $userId");
                        throw new Exception("Faculty record not found for this user");
                    }

                    // Handle faculty updates
                    if ($facultyId && empty($errors)) {
                        $facultyParams = [':faculty_id' => $facultyId];
                        $facultySetClause = [];
                        $facultyFields = [
                            'academic_rank',
                            'employment_type',
                            'classification',
                            'designation',
                            'advisory_class',
                            'bachelor_degree',
                            'master_degree',
                            'doctorate_degree',
                            'post_doctorate_degree'
                        ];
                        foreach ($facultyFields as $field) {
                            if (isset($data[$field]) && $data[$field] !== '') {
                                $facultySetClause[] = "$field = :$field";
                                $facultyParams[":$field"] = $data[$field];
                            }
                        }

                        if (!empty($facultySetClause)) {
                            $updateFacultyStmt = $this->db->prepare("UPDATE faculty SET " . implode(', ', $facultySetClause) . ", updated_at = NOW() WHERE faculty_id = :faculty_id");
                            error_log("profile: Faculty query - " . $updateFacultyStmt->queryString . ", Params: " . print_r($facultyParams, true));
                            if (!$updateFacultyStmt->execute($facultyParams)) {
                                $errorInfo = $updateFacultyStmt->errorInfo();
                                error_log("profile: Faculty update failed - " . print_r($errorInfo, true));
                                throw new Exception("Failed to update faculty information");
                            }
                        }

                        // Handle specialization actions
                        if (!empty($data['action'])) {
                            switch ($data['action']) {
                                case 'add_specialization':
                                    if (!empty($data['expertise_level']) && !empty($data['course_id'])) {
                                        // Check if specialization already exists
                                        $checkStmt = $this->db->prepare("SELECT COUNT(*) FROM specializations WHERE faculty_id = :faculty_id AND course_id = :course_id");
                                        $checkStmt->execute([':faculty_id' => $facultyId, ':course_id' => $data['course_id']]);
                                        $exists = $checkStmt->fetchColumn();

                                        if ($exists > 0) {
                                            $errors[] = 'You already have this specialization. Use edit to modify it.';
                                            break;
                                        }

                                        $insertSpecializationStmt = $this->db->prepare("
                                        INSERT INTO specializations (faculty_id, course_id, expertise_level, created_at)
                                        VALUES (:faculty_id, :course_id, :expertise_level, NOW())
                                    ");
                                        $specializationParams = [
                                            ':faculty_id' => $facultyId,
                                            ':course_id' => $data['course_id'],
                                            ':expertise_level' => $data['expertise_level'],
                                        ];
                                        error_log("profile: Add specialization query - " . $insertSpecializationStmt->queryString . ", Params: " . print_r($specializationParams, true));

                                        if (!$insertSpecializationStmt->execute($specializationParams)) {
                                            $errorInfo = $insertSpecializationStmt->errorInfo();
                                            error_log("profile: Add specialization failed - " . print_r($errorInfo, true));
                                            throw new Exception("Failed to add specialization");
                                        }
                                        error_log("profile: Successfully added specialization");
                                    } else {
                                        $errors[] = 'Course and expertise level are required to add specialization.';
                                    }
                                    break;

                                case 'remove_specialization':
                                    if (!empty($data['course_id'])) {
                                        error_log("profile: Attempting to remove specialization with course_id: " . $data['course_id'] . ", faculty_id: $facultyId");

                                        // First, check if the record exists
                                        $checkStmt = $this->db->prepare("SELECT COUNT(*) FROM specializations WHERE faculty_id = :faculty_id AND course_id = :course_id");
                                        $checkStmt->execute([':faculty_id' => $facultyId, ':course_id' => $data['course_id']]);
                                        $recordExists = $checkStmt->fetchColumn();
                                        error_log("profile: Records found for deletion: $recordExists");

                                        if ($recordExists > 0) {
                                            $deleteStmt = $this->db->prepare("DELETE FROM specializations WHERE faculty_id = :faculty_id AND course_id = :course_id");
                                            $deleteParams = [
                                                ':faculty_id' => $facultyId,
                                                ':course_id' => $data['course_id'],
                                            ];
                                            error_log("profile: Remove specialization query - " . $deleteStmt->queryString . ", Params: " . print_r($deleteParams, true));

                                            if ($deleteStmt->execute($deleteParams)) {
                                                $affectedRows = $deleteStmt->rowCount();
                                                error_log("profile: Successfully deleted $affectedRows rows");
                                                if ($affectedRows === 0) {
                                                    error_log("profile: Warning - No rows were affected by delete operation");
                                                    $errors[] = 'No specialization was removed. It may have already been deleted.';
                                                }
                                            } else {
                                                $errorInfo = $deleteStmt->errorInfo();
                                                error_log("profile: Delete failed - " . print_r($errorInfo, true));
                                                throw new Exception("Failed to execute delete query: " . $errorInfo[2]);
                                            }
                                        } else {
                                            error_log("profile: No record found for deletion");
                                            $errors[] = 'Specialization not found for removal.';
                                        }
                                    } else {
                                        $errors[] = 'Course ID is required to remove specialization.';
                                    }
                                    break;

                                case 'update_specialization':
                                    if (!empty($data['course_id']) && !empty($data['expertise_level'])) {
                                        error_log("profile: Attempting to update specialization with course_id: " . $data['course_id'] . ", faculty_id: $facultyId");

                                        // Check if the record exists first
                                        $checkStmt = $this->db->prepare("SELECT COUNT(*) FROM specializations WHERE faculty_id = :faculty_id AND course_id = :course_id");
                                        $checkStmt->execute([':faculty_id' => $facultyId, ':course_id' => $data['course_id']]);
                                        $recordExists = $checkStmt->fetchColumn();

                                        if ($recordExists > 0) {
                                            $updateStmt = $this->db->prepare("UPDATE specializations SET expertise_level = :expertise_level, updated_at = NOW() WHERE faculty_id = :faculty_id AND course_id = :course_id");
                                            $updateParams = [
                                                ':faculty_id' => $facultyId,
                                                ':course_id' => $data['course_id'],
                                                ':expertise_level' => $data['expertise_level'],
                                            ];
                                            error_log("profile: Update specialization query - " . $updateStmt->queryString . ", Params: " . print_r($updateParams, true));

                                            if ($updateStmt->execute($updateParams)) {
                                                $affectedRows = $updateStmt->rowCount();
                                                error_log("profile: Successfully updated $affectedRows rows");
                                                if ($affectedRows === 0) {
                                                    error_log("profile: Warning - No rows were affected by update operation");
                                                    $errors[] = 'No changes were made to the specialization.';
                                                }
                                            } else {
                                                $errorInfo = $updateStmt->errorInfo();
                                                error_log("profile: Update failed - " . print_r($errorInfo, true));
                                                throw new Exception("Failed to update specialization: " . $errorInfo[2]);
                                            }
                                        } else {
                                            error_log("profile: No record found for update");
                                            $errors[] = 'Specialization not found for update.';
                                        }
                                    } else {
                                        $errors[] = 'Course ID and expertise level are required to update specialization.';
                                    }
                                    break;

                                case 'edit_specialization':
                                    if (!empty($data['specialization_index'])) {
                                        error_log("profile: Edit specialization triggered for index: " . $data['specialization_index']);
                                        // No database update needed here, just trigger the modal
                                    }
                                    break;

                                default:
                                    error_log("profile: Unknown action: " . $data['action']);
                                    break;
                            }
                        }
                    }

                    // If there are validation errors, rollback and don't commit
                    if (!empty($errors)) {
                        $this->db->rollBack();
                        error_log("profile: Validation errors found, rolling back transaction: " . implode(', ', $errors));
                    } else {
                        $this->db->commit();
                        error_log("profile: Transaction committed successfully");

                        $_SESSION['username'] = $data['username'] ?: $_SESSION['username'];
                        $_SESSION['last_name'] = $data['last_name'] ?: $_SESSION['last_name'];
                        $_SESSION['middle_name'] = $data['middle_name'] ?: $_SESSION['middle_name'];
                        $_SESSION['suffix'] = $data['suffix'] ?: $_SESSION['suffix'];
                        $_SESSION['title'] = $data['title'] ?: $_SESSION['title'];
                        $_SESSION['first_name'] = $data['first_name'] ?: $_SESSION['first_name'];
                        $_SESSION['email'] = $data['email'] ?: $_SESSION['email'];

                        // Update profile picture in session if it was uploaded
                        if ($profilePicturePath) {
                            $_SESSION['profile_picture'] = $profilePicturePath;
                            error_log("profile: Updated session profile_picture to: " . $profilePicturePath);
                        }

                        $_SESSION['flash'] = ['type' => 'success', 'message' => 'Profile updated successfully'];
                    }
                } catch (PDOException $e) {
                    if ($this->db->inTransaction()) {
                        $this->db->rollBack();
                    }
                    error_log("profile: PDO Database error - " . $e->getMessage());
                    $errors[] = 'Database error occurred: ' . $e->getMessage();
                } catch (Exception $e) {
                    if ($this->db->inTransaction()) {
                        $this->db->rollBack();
                    }
                    error_log("profile: General error - " . $e->getMessage());
                    $errors[] = $e->getMessage();
                }

                if (!empty($errors)) {
                    $_SESSION['flash'] = ['type' => 'error', 'message' => implode('<br>', $errors)];
                }

                header('Location: /admin/profile');
                exit;
            }

            // GET request - Display profile
            $stmt = $this->db->prepare("
            SELECT u.*, d.department_name, c.college_name, r.role_name,
                   f.academic_rank, f.employment_type, f.classification, f.bachelor_degree, f.master_degree,
                   f.doctorate_degree, f.post_doctorate_degree, f.advisory_class, f.designation
            FROM users u
            LEFT JOIN departments d ON u.department_id = d.department_id
            LEFT JOIN colleges c ON u.college_id = c.college_id
            LEFT JOIN roles r ON u.role_id = r.role_id
            LEFT JOIN faculty f ON u.user_id = f.user_id
            WHERE u.user_id = :user_id
        ");
            $stmt->execute([':user_id' => $userId]);
            $user = $stmt->fetch(PDO::FETCH_ASSOC);

            if (!$user) {
                throw new Exception('User not found.');
            }

            $specializationStmt = $this->db->prepare("
            SELECT s.expertise_level AS level, c.course_code, c.course_name, s.course_id
            FROM specializations s
            JOIN courses c ON s.course_id = c.course_id
            WHERE s.faculty_id = (SELECT faculty_id FROM faculty WHERE user_id = :user_id)
            ORDER BY c.course_code
        ");
            $specializationStmt->execute([':user_id' => $userId]);
            $specializations = $specializationStmt->fetchAll(PDO::FETCH_ASSOC);

            // Fetch user data and stats...
            $stmt = $this->db->prepare("
                SELECT u.*, d.department_name, c.college_name, r.role_name,
                       f.academic_rank, f.employment_type, f.classification, f.bachelor_degree, f.master_degree,
                       f.doctorate_degree, f.post_doctorate_degree, f.advisory_class, f.designation,
                       s.expertise_level, 
                       (SELECT COUNT(*) FROM faculty f2 JOIN users fu ON f2.user_id = fu.user_id WHERE fu.department_id = u.department_id) as facultyCount,
                       (SELECT COUNT(DISTINCT sch.course_id) FROM schedules sch WHERE sch.faculty_id = f.faculty_id) as coursesCount,
                       (SELECT COUNT(*) FROM specializations s2 WHERE s2.course_id = c2.course_id) as specializationsCount,
                       (SELECT COUNT(*) FROM faculty_requests fr WHERE fr.department_id = u.department_id AND fr.status = 'pending') as pendingApplicantsCount,
                       (SELECT semester_name FROM semesters WHERE is_current = 1) as currentSemester,
                       (SELECT created_at FROM auth_logs WHERE user_id = u.user_id AND action = 'login_success' ORDER BY created_at DESC LIMIT 1) as lastLogin
                FROM users u
                LEFT JOIN departments d ON u.department_id = d.department_id
                LEFT JOIN colleges c ON u.college_id = c.college_id
                LEFT JOIN courses c2 ON d.department_id = c2.department_id
                LEFT JOIN schedules sch ON c2.course_id = sch.course_id
                LEFT JOIN roles r ON u.role_id = r.role_id
                LEFT JOIN faculty f ON u.user_id = f.user_id
                LEFT JOIN specializations s ON f.faculty_id = s.faculty_id
                WHERE u.user_id = :user_id
            ");
            $stmt->execute([':user_id' => $userId]);
            $user = $stmt->fetch(PDO::FETCH_ASSOC);

            if (!$user) {
                throw new Exception('User not found.');
            }

            // Extract stats
            $facultyCount = $user['facultyCount'] ?? 0;
            $coursesCount = $user['coursesCount'] ?? 0;
            $specializationsCount = $user['specializationsCount'] ?? 0;
            $pendingApplicantsCount = $user['pendingApplicantsCount'] ?? 0;
            $currentSemester = $user['currentSemester'] ?? '2nd';
            $lastLogin = $user['lastLogin'] ?? 'N/A';

            require_once __DIR__ . '/../views/admin/profile.php';
        } catch (Exception $e) {
            if (isset($this->db) && $this->db->inTransaction()) {
                $this->db->rollBack();
            }

            error_log("profile: Error - " . $e->getMessage());
            $_SESSION['flash'] = ['type' => 'error', 'message' => 'Failed to load or update profile. Please try again.'];

            $user = [
                'user_id' => $userId ?? 0,
                'username' => '',
                'first_name' => '',
                'last_name' => '',
                'middle_name' => '',
                'suffix' => '',
                'email' => '',
                'phone' => '',
                'title' => '',
                'profile_picture' => '',
                'employee_id' => '',
                'department_name' => '',
                'college_name' => '',
                'role_name' => 'Program admin',
                'academic_rank' => '',
                'employment_type' => '',
                'classification' => '',
                'bachelor_degree' => '',
                'master_degree' => '',
                'doctorate_degree' => '',
                'post_doctorate_degree' => '',
                'advisory_class' => '',
                'designation' => '',
                'updated_at' => date('Y-m-d H:i:s')
            ];
            $specializations = [];
            require_once __DIR__ . '/../views/admin/profile.php';
        }
    }

    private function handleProfilePictureUpload($userId)
    {
        if (!isset($_FILES['profile_picture']) || $_FILES['profile_picture']['error'] == UPLOAD_ERR_NO_FILE) {
            error_log("profile: No file uploaded for user_id: $userId");
            return null;
        }

        $file = $_FILES['profile_picture'];
        $allowedTypes = ['image/jpeg', 'image/png', 'image/gif'];
        $maxSize = 2 * 1024 * 1024; // 2MB

        if (!in_array($file['type'], $allowedTypes)) {
            error_log("profile: Invalid file type for user_id: $userId - " . $file['type']);
            return "Error: Only JPEG, PNG, and GIF files are allowed.";
        }

        if ($file['size'] > $maxSize) {
            error_log("profile: File size exceeds limit for user_id: $userId - " . $file['size']);
            return "Error: File size exceeds 2MB limit.";
        }

        $ext = pathinfo($file['name'], PATHINFO_EXTENSION);
        $filename = "profile_{$userId}_" . time() . ".{$ext}";
        $uploadDir = $_SERVER['DOCUMENT_ROOT'] . '/uploads/profile_pictures/'; // Public-accessible path
        $uploadPath = $uploadDir . $filename;

        if (!is_dir($uploadDir)) {
            if (!mkdir($uploadDir, 0755, true)) {
                error_log("profile: Failed to create upload adminy: $uploadDir");
                return "Error: Failed to create upload adminy.";
            }
        }

        // Remove existing profile picture
        $stmt = $this->db->prepare("SELECT profile_picture FROM users WHERE user_id = :user_id");
        $stmt->execute([':user_id' => $userId]);
        $currentPicture = $stmt->fetchColumn();
        if ($currentPicture && file_exists($_SERVER['DOCUMENT_ROOT'] . $currentPicture)) {
            if (!unlink($_SERVER['DOCUMENT_ROOT'] . $currentPicture)) {
                error_log("profile: Failed to delete existing profile picture: $currentPicture");
            }
        }

        if (move_uploaded_file($file['tmp_name'], $uploadPath)) {
            error_log("profile: Successfully uploaded file to $uploadPath for user_id: $userId");
            return "/uploads/profile_pictures/{$filename}";
        } else {
            error_log("profile: Failed to move uploaded file for user_id: $userId to $uploadPath - Check permissions or disk space");
            return "Error: Failed to upload file.";
        }
    }

    public function settings()
    {
        try {
            $stmt = $this->db->prepare("
                SELECT u.user_id, u.username, u.email, u.phone, u.first_name, u.middle_name, u.last_name, u.suffix, 
                       u.profile_picture
                FROM users u
                WHERE u.user_id = :user_id
            ");
            $stmt->execute([':user_id' => $_SESSION['user_id']]);
            $user = $stmt->fetch(PDO::FETCH_ASSOC);

            if (!$user) {
                $_SESSION['error'] = "User not found";
                header('Location: /admin/dashboard');
                exit;
            }

            $colleges = $this->db->query("SELECT college_id, college_name FROM colleges")->fetchAll(PDO::FETCH_ASSOC);
            $departments = $this->db->query("SELECT department_id, department_name FROM departments")->fetchAll(PDO::FETCH_ASSOC);

            $controller = $this;
            require_once __DIR__ . '/../views/admin/settings.php';
        } catch (PDOException $e) {
            error_log("Settings error: " . $e->getMessage());
            $_SESSION['error'] = "Server error";
            header('Location: /admin/dashboard');
            exit;
        }
    }


    public function updatePassword()
    {
        if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
            http_response_code(405);
            echo "Method Not Allowed";
            exit;
        }

        try {
            $user_id = $_SESSION['user_id'];
            $current_password = $_POST['current_password'] ?? '';
            $new_password = $_POST['new_password'] ?? '';
            $confirm_password = $_POST['confirm_password'] ?? '';

            // Validate inputs
            if (empty($current_password) || empty($new_password) || empty($confirm_password)) {
                $_SESSION['error'] = "All password fields are required";
                header('Location: /admin/settings');
                exit;
            }
            if ($new_password !== $confirm_password) {
                $_SESSION['error'] = "New passwords do not match";
                header('Location: /admin/settings');
                exit;
            }
            if (strlen($new_password) < 8) {
                $_SESSION['error'] = "New password must be at least 8 characters long";
                header('Location: /admin/settings');
                exit;
            }

            // Verify current password
            $stmt = $this->db->prepare("SELECT password_hash FROM users WHERE user_id = :user_id");
            $stmt->execute([':user_id' => $user_id]);
            $user = $stmt->fetch(PDO::FETCH_ASSOC);

            if (!$user || !password_verify($current_password, $user['password_hash'])) {
                $_SESSION['error'] = "Current password is incorrect";
                header('Location: /admin/settings');
                exit;
            }

            // Update password
            $new_password_hash = password_hash($new_password, PASSWORD_BCRYPT);
            $stmt = $this->db->prepare("UPDATE users SET password_hash = :password_hash WHERE user_id = :user_id");
            $stmt->execute([
                ':password_hash' => $new_password_hash,
                ':user_id' => $user_id
            ]);

            $_SESSION['success'] = "Password updated successfully";
            header('Location: /admin/settings');
            exit;
        } catch (PDOException $e) {
            error_log("Update password error: " . $e->getMessage());
            $_SESSION['error'] = "Failed to update password";
            header('Location: /admin/settings');
            exit;
        }
    }

    public function databaseBackup()
    {
        try {
            $action = $_GET['action'] ?? 'view';
            $csrfToken = $this->authService->generateCsrfToken();

            if ($_SERVER['REQUEST_METHOD'] === 'POST') {
                if (!$this->authService->verifyCsrfToken($_POST['csrf_token'] ?? '')) {
                    $_SESSION['flash'] = ['type' => 'error', 'message' => 'Invalid CSRF token'];
                    header('Location: /admin/database-backup');
                    exit;
                }

                if ($action === 'create_backup') {
                    $result = $this->createDatabaseBackup();
                    $_SESSION['flash'] = ['type' => $result['success'] ? 'success' : 'error', 'message' => $result['message']];
                    header('Location: /admin/database-backup');
                    exit;
                } elseif ($action === 'download_backup' && isset($_POST['backup_file'])) {
                    $this->downloadBackupFile($_POST['backup_file']);
                    exit;
                } elseif ($action === 'delete_backup' && isset($_POST['backup_file'])) {
                    $result = $this->deleteBackupFile($_POST['backup_file']);
                    $_SESSION['flash'] = ['type' => $result['success'] ? 'success' : 'error', 'message' => $result['message']];
                    header('Location: /admin/database-backup');
                    exit;
                }
            }

            // Get existing backups
            $backup_files = $this->getBackupFiles();

            // Get database info
            $database_info = $this->getDatabaseInfo();

            // Extract variables for the view
            $csrf_token = $csrfToken;
            $controller = $this;

            // Debug: Check if data is being passed correctly
            error_log("Backup files count: " . count($backup_files));
            error_log("Database info: " . print_r($database_info, true));

            require_once __DIR__ . '/../views/admin/database-backup.php';
        } catch (Exception $e) {
            error_log("Database backup error: " . $e->getMessage());
            error_log("Stack trace: " . $e->getTraceAsString());
            $_SESSION['flash'] = ['type' => 'error', 'message' => 'An error occurred: ' . $e->getMessage()];
            header('Location: /admin/dashboard');
            exit;
        }
    }

    private function createDatabaseBackup()
    {
        try {
            // Create backup directory if it doesn't exist
            $backupDir = __DIR__ . '/../../backups';
            if (!is_dir($backupDir)) {
                mkdir($backupDir, 0755, true);
            }

            // Get database configuration
            $dbHost = $this->db->getAttribute(PDO::ATTR_CONNECTION_STATUS); // This might not give host, so you may need to store it in config
            $dbName = $this->getDatabaseName();

            // Generate backup filename with timestamp
            $timestamp = date('Y-m-d_H-i-s');
            $backupFilename = "backup_{$dbName}_{$timestamp}.sql";
            $backupPath = $backupDir . '/' . $backupFilename;

            // Get all tables
            $tables = $this->getAllTables();

            $backupContent = "";

            // Set SQL headers
            $backupContent .= "-- Database Backup\n";
            $backupContent .= "-- Generated: " . date('Y-m-d H:i:s') . "\n";
            $backupContent .= "-- Database: {$dbName}\n";
            $backupContent .= "-- PHP Version: " . PHP_VERSION . "\n";
            $backupContent .= "\nSET FOREIGN_KEY_CHECKS=0;\n\n";

            // Backup each table
            foreach ($tables as $table) {
                $backupContent .= $this->backupTable($table);
            }

            $backupContent .= "SET FOREIGN_KEY_CHECKS=1;\n";

            // Write backup file
            if (file_put_contents($backupPath, $backupContent) !== false) {
                // Compress the backup (optional)
                $this->compressBackup($backupPath);

                // Set file permissions
                chmod($backupPath, 0644);

                // Clean up old backups (keep last 30 days)
                $this->cleanupOldBackups();

                return [
                    'success' => true,
                    'message' => 'Database backup created successfully: ' . $backupFilename,
                    'filename' => $backupFilename
                ];
            } else {
                throw new Exception('Failed to write backup file');
            }
        } catch (Exception $e) {
            error_log("Create backup error: " . $e->getMessage());
            return ['success' => false, 'message' => 'Failed to create backup: ' . $e->getMessage()];
        }
    }

    private function getAllTables()
    {
        $stmt = $this->db->query("SHOW TABLES");
        $tables = $stmt->fetchAll(PDO::FETCH_COLUMN);
        return $tables;
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
                    // Escape special characters
                    $value = str_replace("'", "''", $value);
                    $value = str_replace("\\", "\\\\", $value);
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
                    return true;
                }
            }
        }
        return false;
    }

    private function getBackupFiles()
    {
        $backupDir = __DIR__ . '/../../backups';
        if (!is_dir($backupDir)) {
            return [];
        }

        $files = scandir($backupDir);
        $backupFiles = [];

        foreach ($files as $file) {
            if ($file !== '.' && $file !== '..' && (pathinfo($file, PATHINFO_EXTENSION) === 'sql' || pathinfo($file, PATHINFO_EXTENSION) === 'zip')) {
                $filePath = $backupDir . '/' . $file;
                $backupFiles[] = [
                    'filename' => $file,
                    'path' => $filePath,
                    'size' => filesize($filePath),
                    'modified' => filemtime($filePath),
                    'download_url' => '/admin/database-backup?action=download&file=' . urlencode($file)
                ];
            }
        }

        // Sort by modification time (newest first)
        usort($backupFiles, function ($a, $b) {
            return $b['modified'] - $a['modified'];
        });

        return $backupFiles;
    }

    private function downloadBackupFile($filename)
    {
        $backupDir = __DIR__ . '/../../backups';
        $filePath = $backupDir . '/' . basename($filename);

        if (!file_exists($filePath)) {
            $_SESSION['flash'] = ['type' => 'error', 'message' => 'Backup file not found'];
            header('Location: /admin/database-backup');
            exit;
        }

        header('Content-Description: File Transfer');
        header('Content-Type: application/octet-stream');
        header('Content-Disposition: attachment; filename="' . basename($filePath) . '"');
        header('Expires: 0');
        header('Cache-Control: must-revalidate');
        header('Pragma: public');
        header('Content-Length: ' . filesize($filePath));
        readfile($filePath);
        exit;
    }

    private function deleteBackupFile($filename)
    {
        try {
            $backupDir = __DIR__ . '/../../backups';
            $filePath = $backupDir . '/' . basename($filename);

            if (!file_exists($filePath)) {
                return ['success' => false, 'message' => 'Backup file not found'];
            }

            if (unlink($filePath)) {
                return ['success' => true, 'message' => 'Backup file deleted successfully'];
            } else {
                throw new Exception('Failed to delete file');
            }
        } catch (Exception $e) {
            error_log("Delete backup error: " . $e->getMessage());
            return ['success' => false, 'message' => 'Failed to delete backup: ' . $e->getMessage()];
        }
    }

    private function getDatabaseInfo()
    {
        try {
            // Get database size
            $dbName = $this->getDatabaseName();
            $stmt = $this->db->query("
            SELECT 
                table_schema as 'Database',
                ROUND(SUM(data_length + index_length) / 1024 / 1024, 2) as 'Size_MB',
                COUNT(*) as 'Table_Count'
            FROM information_schema.tables 
            WHERE table_schema = '{$dbName}'
            GROUP BY table_schema
        ");
            $dbSize = $stmt->fetch(PDO::FETCH_ASSOC);

            // Get table counts
            $stmt = $this->db->query("SELECT COUNT(*) as total_tables FROM information_schema.tables WHERE table_schema = '{$dbName}'");
            $tableCount = $stmt->fetchColumn();

            // Get last backup info
            $backupFiles = $this->getBackupFiles();
            $lastBackup = !empty($backupFiles) ? $backupFiles[0] : null;

            return [
                'name' => $dbName,
                'size_mb' => $dbSize['Size_MB'] ?? 0,
                'table_count' => $tableCount,
                'last_backup' => $lastBackup ? [
                    'filename' => $lastBackup['filename'],
                    'date' => date('Y-m-d H:i:s', $lastBackup['modified']),
                    'size' => $this->formatBytes($lastBackup['size'])
                ] : null
            ];
        } catch (Exception $e) {
            error_log("Get database info error: " . $e->getMessage());
            return [
                'name' => 'Unknown',
                'size_mb' => 0,
                'table_count' => 0,
                'last_backup' => null
            ];
        }
    }

    private function cleanupOldBackups($keepDays = 30)
    {
        try {
            $backupDir = __DIR__ . '/../../backups';
            $files = $this->getBackupFiles();
            $cutoffTime = time() - ($keepDays * 24 * 60 * 60);

            foreach ($files as $file) {
                if ($file['modified'] < $cutoffTime) {
                    unlink($file['path']);
                    error_log("Deleted old backup: " . $file['filename']);
                }
            }
        } catch (Exception $e) {
            error_log("Cleanup old backups error: " . $e->getMessage());
        }
    }

    private function formatBytes($bytes, $precision = 2)
    {
        $units = ['B', 'KB', 'MB', 'GB', 'TB'];
        $bytes = max($bytes, 0);
        $pow = floor(($bytes ? log($bytes) : 0) / log(1024));
        $pow = min($pow, count($units) - 1);
        $bytes /= pow(1024, $pow);
        return round($bytes, $precision) . ' ' . $units[$pow];
    }

    /**
     * Manage admission applications
     */
    public function manageApplications()
    {
        AuthMiddleware::handle('admin');

        $admissionService = new AdmissionService($this->db);

        // Handle application actions
        if ($_SERVER['REQUEST_METHOD'] === 'POST') {
            if (isset($_POST['approve_application'])) {
                $applicationId = intval($_POST['application_id']);
                $reviewedBy = $_SESSION['user_id'];

                try {
                    $userId = $admissionService->approveApplication($applicationId, $reviewedBy);
                    $_SESSION['success'] = "Application approved successfully. User account created.";
                } catch (Exception $e) {
                    $_SESSION['error'] = "Failed to approve application: " . $e->getMessage();
                }
            } elseif (isset($_POST['reject_application'])) {
                $applicationId = intval($_POST['application_id']);
                $reviewedBy = $_SESSION['user_id'];
                $reason = trim($_POST['rejection_reason'] ?? '');

                if (empty($reason)) {
                    $_SESSION['error'] = "Rejection reason is required.";
                } else {
                    $success = $admissionService->rejectApplication($applicationId, $reviewedBy, $reason);
                    if ($success) {
                        $_SESSION['success'] = "Application rejected successfully.";
                    } else {
                        $_SESSION['error'] = "Failed to reject application.";
                    }
                }
            }

            header('Location: /admin/applications');
            exit;
        }

        // Get pending applications
        $page = intval($_GET['page'] ?? 1);
        $limit = 20;
        $offset = ($page - 1) * $limit;

        $applications = $admissionService->getPendingApplications($limit, $offset);
        $totalApplications = $this->getTotalPendingApplications();
        $totalPages = ceil($totalApplications / $limit);

        require_once __DIR__ . '/../views/admin/applications.php';
    }

    private function getTotalPendingApplications()
    {
        try {
            $query = "SELECT COUNT(*) FROM admission_applications WHERE status = 'pending'";
            $stmt = $this->db->prepare($query);
            $stmt->execute();
            return $stmt->fetchColumn();
        } catch (PDOException $e) {
            error_log("Error counting pending applications: " . $e->getMessage());
            return 0;
        }
    }
}
