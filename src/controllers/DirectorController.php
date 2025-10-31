<?php
require_once __DIR__ . '/../config/Database.php';
require_once __DIR__ . '/../models/UserModel.php';
require_once __DIR__ . '/../services/AuthService.php';
require_once __DIR__ . '/../controllers/ApiController.php';
require_once __DIR__ . '/../services/SchedulingService.php';

class DirectorController
{
    public $db;
    private $userModel;
    public $api;
    public $authService;
    private $schedulingService;

    public function __construct()
    {
        error_log("DirectorController instantiated");
        $this->db = (new Database())->connect();
        if ($this->db === null) {
            error_log("Failed to connect to the database in DirectorController");
            die("Database connection failed. Please try again later.");
        }
        $this->userModel = new UserModel();
        $this->api = new ApiController();
        $this->authService = new AuthService($this->db);
        $this->schedulingService = new SchedulingService($this->db);
        $this->db->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
    }

    private function getUserData()
    {
        try {
            $stmt = $this->db->prepare("
                SELECT u.*, f.employment_type, f.academic_rank
                FROM users u
                LEFT JOIN faculty f ON u.user_id = f.user_id
                WHERE u.user_id = :user_id
            ");
            $stmt->execute([':user_id' => $_SESSION['user_id']]);
            $user = $stmt->fetch(PDO::FETCH_ASSOC);
            if ($user) {
                $specStmt = $this->db->prepare("
                    SELECT s.specialization_id, c.course_name
                    FROM specializations s
                    JOIN courses c ON s.course_id = c.course_id
                    WHERE s.faculty_id = :faculty_id AND s.is_primary_specialization = 1
                    LIMIT 1
                ");
                $specStmt->execute([':faculty_id' => $_SESSION['user_id']]);
                $specialization = $specStmt->fetch(PDO::FETCH_ASSOC);
                $user['course_specialization'] = $specialization ? $specialization['course_name'] : null;
                $user['specialization_id'] = $specialization ? $specialization['specialization_id'] : null;
                error_log("getUserData: Successfully fetched user data for user_id: " . $_SESSION['user_id']);
                return $user;
            } else {
                error_log("getUserData: No user found for user_id: " . $_SESSION['user_id']);
                return null;
            }
        } catch (PDOException $e) {
            error_log("getUserData: Database error - " . $e->getMessage());
            return null;
        }
    }

    public function dashboard()
    {
        try {
            // Fetch user data
            $userData = $this->getUserData();
            if (!$userData) {
                error_log("dashboard: Failed to load user data for user_id: " . ($_SESSION['user_id'] ?? 'unknown'));
                header('Location: /login?error=User data not found');
                exit;
            }

            // Fetch department and curriculum data
            $departmentId = $this->getDepartmentId($userData['user_id']);
            if ($departmentId === null) {
                error_log("dashboard: No department found for user_id: " . $userData['user_id']);
                header('Location: /login?error=Department not assigned');
                exit;
            }

            // Fetch department name
            $deptStmt = $this->db->prepare("SELECT department_name FROM departments WHERE department_id = :department_id");
            $deptStmt->execute([':department_id' => $departmentId]);
            $departmentName = $deptStmt->fetchColumn();

            // Fetch current semester
            $semester = $this->userModel->getCurrentSemester();

            // Fetch pending schedule approvals
            $scheduleStmt = $this->db->prepare(
                "
            SELECT COUNT(*) as pending_count
            FROM schedules s
            WHERE s.department_id = :department_id 
            AND s.status = 'Dean_Approved'
            AND s.semester_id = :semester_id"
            );
            $scheduleStmt->execute([
                ':department_id' => $departmentId,
                ':semester_id' => $semester['semester_id']
            ]);
            $pendingCount = $scheduleStmt->fetchColumn() ?: 0;

            // Fetch schedule deadline
            $deadline = $this->getScheduleDeadline($departmentId);

            // Fetch class schedules for charts
            $facultyId = $this->getFacultyId($userData['user_id']);
            $schedules = $facultyId ? $this->getSchedules($facultyId) : [];

            // Fetch schedule statistics for charts - FIXED QUERY
            $scheduleStatsStmt = $this->db->prepare("
            SELECT 
                COUNT(*) as total_schedules,
                SUM(CASE WHEN status = 'approved' OR status = 'Dean_Approved' THEN 1 ELSE 0 END) as approved_schedules,
                SUM(CASE WHEN status = 'pending' OR status = 'Dean_Approved' THEN 1 ELSE 0 END) as pending_schedules,
                SUM(CASE WHEN status = 'rejected' THEN 1 ELSE 0 END) as rejected_schedules
            FROM schedules 
            WHERE department_id = :department_id 
            AND semester_id = :semester_id
        ");
            $scheduleStatsStmt->execute([
                ':department_id' => $departmentId,
                ':semester_id' => $semester['semester_id']
            ]);
            $scheduleStats = $scheduleStatsStmt->fetch(PDO::FETCH_ASSOC);

            // Fetch schedule distribution by day
            $dayDistributionStmt = $this->db->prepare("
            SELECT day_of_week, COUNT(*) as count
            FROM schedules 
            WHERE department_id = :department_id 
            AND semester_id = :semester_id
            GROUP BY day_of_week
            ORDER BY 
                CASE day_of_week
                    WHEN 'Monday' THEN 1
                    WHEN 'Tuesday' THEN 2
                    WHEN 'Wednesday' THEN 3
                    WHEN 'Thursday' THEN 4
                    WHEN 'Friday' THEN 5
                    WHEN 'Saturday' THEN 6
                    WHEN 'Sunday' THEN 7
                END
        ");
            $dayDistributionStmt->execute([
                ':department_id' => $departmentId,
                ':semester_id' => $semester['semester_id']
            ]);
            $dayDistribution = $dayDistributionStmt->fetchAll(PDO::FETCH_ASSOC);

            // Fetch time distribution (hours per day) - FIXED QUERY using start_time and end_time
            $timeDistributionStmt = $this->db->prepare("
            SELECT 
                day_of_week,
                COUNT(*) as schedule_count,
                AVG(TIMESTAMPDIFF(HOUR, start_time, end_time)) as avg_hours_per_schedule
            FROM schedules 
            WHERE department_id = :department_id 
            AND semester_id = :semester_id
            AND start_time IS NOT NULL 
            AND end_time IS NOT NULL
            GROUP BY day_of_week
            ORDER BY 
                CASE day_of_week
                    WHEN 'Monday' THEN 1
                    WHEN 'Tuesday' THEN 2
                    WHEN 'Wednesday' THEN 3
                    WHEN 'Thursday' THEN 4
                    WHEN 'Friday' THEN 5
                    WHEN 'Saturday' THEN 6
                    WHEN 'Sunday' THEN 7
                END
        ");
            $timeDistributionStmt->execute([
                ':department_id' => $departmentId,
                ':semester_id' => $semester['semester_id']
            ]);
            $timeDistribution = $timeDistributionStmt->fetchAll(PDO::FETCH_ASSOC);

            // Alternative: If TIMESTAMPDIFF doesn't work, use this simpler version
            if (empty($timeDistribution)) {
                $timeDistributionStmt = $this->db->prepare("
                SELECT 
                    day_of_week,
                    COUNT(*) as schedule_count
                FROM schedules 
                WHERE department_id = :department_id 
                AND semester_id = :semester_id
                GROUP BY day_of_week
                ORDER BY 
                    CASE day_of_week
                        WHEN 'Monday' THEN 1
                        WHEN 'Tuesday' THEN 2
                        WHEN 'Wednesday' THEN 3
                        WHEN 'Thursday' THEN 4
                        WHEN 'Friday' THEN 5
                        WHEN 'Saturday' THEN 6
                        WHEN 'Sunday' THEN 7
                    END
            ");
                $timeDistributionStmt->execute([
                    ':department_id' => $departmentId,
                    ':semester_id' => $semester['semester_id']
                ]);
                $timeDistribution = $timeDistributionStmt->fetchAll(PDO::FETCH_ASSOC);
            }

            // Fetch recent activity
            $activityStmt = $this->db->prepare("
            SELECT al.action_type, al.action_description, al.created_at, 
                   u.first_name, u.last_name, u.role_id
            FROM activity_logs al
            JOIN users u ON al.user_id = u.user_id
            WHERE al.department_id = :department_id
            ORDER BY al.created_at DESC
            LIMIT 6
        ");
            $activityStmt->execute([':department_id' => $departmentId]);
            $recentActivity = $activityStmt->fetchAll(PDO::FETCH_ASSOC);

            // Prepare data for view
            $data = [
                'user' => $userData,
                'department_name' => $departmentName,
                'pending_approvals' => $pendingCount,
                'deadline' => $deadline ? date('Y-m-d H:i:s', strtotime($deadline)) : null,
                'semester' => $semester,
                'schedules' => $schedules,
                'schedule_stats' => $scheduleStats,
                'day_distribution' => $dayDistribution,
                'time_distribution' => $timeDistribution,
                'recent_activity' => $recentActivity,
                'title' => 'Director Dashboard',
                'current_time' => date('h:i A T', time()),
                'has_db_error' => $departmentId === null || $pendingCount === null || $deadline === null
            ];

            require_once __DIR__ . '/../views/director/dashboard.php';
        } catch (PDOException $e) {
            error_log("dashboard: Database error - " . $e->getMessage());
            http_response_code(500);
            echo "Server error";
        } catch (Exception $e) {
            error_log("dashboard: General error - " . $e->getMessage());
            http_response_code(500);
            echo "Server error";
        }
    }

    // Helper methods to encapsulate database queries
    private function getDepartmentId($userId)
    {
        try {
            $stmt = $this->db->prepare("
            SELECT department_id 
            FROM department_instructors 
            WHERE user_id = :user_id AND is_current = 1
        ");
            $stmt->execute([':user_id' => $userId]);
            $department = $stmt->fetch(PDO::FETCH_ASSOC);
            return $department ? $department['department_id'] : null;
        } catch (PDOException $e) {
            error_log("getDepartmentId: " . $e->getMessage());
            return null;
        }
    }

    public function mySchedule()
    {
        try {
            $userId = $_SESSION['user_id'];
            error_log("mySchedule: Starting mySchedule method for user_id: $userId");

            // Fetch faculty ID and complete faculty info with join to users table
            $facultyStmt = $this->db->prepare("
            SELECT f.*, 
                   CONCAT(COALESCE(u.title, ''), ' ', u.first_name, ' ', 
                          COALESCE(u.middle_name, ''), ' ', u.last_name, ' ', 
                          COALESCE(u.suffix, '')) AS faculty_name,
                   u.first_name, u.middle_name, u.last_name, u.title, u.suffix
            FROM faculty f 
            JOIN users u ON f.user_id = u.user_id 
            WHERE u.user_id = ?
        ");
            $facultyStmt->execute([$userId]);
            $faculty = $facultyStmt->fetch(PDO::FETCH_ASSOC);

            if (!$faculty) {
                $error = "No faculty profile found for this user.";
                require_once __DIR__ . '/../views/director/schedule.php';
                return;
            }

            $facultyId = $faculty['faculty_id'];
            $facultyName = trim($faculty['faculty_name']);
            $facultyPosition = $faculty['academic_rank'] ?? 'Not Specified';
            $employmentType = $faculty['employment_type'] ?? 'Regular';

            // Get department and college details from directors table
            $deptStmt = $this->db->prepare("
            SELECT d.department_name, c.college_name 
            FROM department_instructors dn 
            JOIN departments d ON dn.department_id = d.college_id 
            JOIN colleges c ON d.college_id = c.college_id 
            WHERE dn.user_id = ? AND dn.is_current = 1
        ");
            $deptStmt->execute([$userId]);
            $department = $deptStmt->fetch(PDO::FETCH_ASSOC);
            $departmentName = $department['department_name'] ?? 'Not Assigned';
            $collegeName = $department['college_name'] ?? 'Not Assigned';

            $semesterStmt = $this->db->query("SELECT semester_id, semester_name, academic_year FROM semesters WHERE is_current = 1");
            $semester = $semesterStmt->fetch(PDO::FETCH_ASSOC);

            if (!$semester) {
                error_log("mySchedule: No current semester found");
                $error = "No current semester defined. Please contact the administrator to set the current semester.";
                require_once __DIR__ . '/../views/director/schedule.php';
                return;
            }

            $semesterId = $semester['semester_id'];
            $semesterName = $semester['semester_name'] . ' Semester, A.Y ' . $semester['academic_year'];
            error_log("mySchedule: Current semester ID: $semesterId, Name: $semesterName");

            // Get schedules with grouped days and better data structure
            $schedulesStmt = $this->db->prepare("
            SELECT s.schedule_id, c.course_code, c.course_name, c.units,
                   r.room_name, s.day_of_week, s.start_time, s.end_time, s.schedule_type, 
                   COALESCE(sec.section_name, 'N/A') AS section_name, sec.current_students,
                   TIMESTAMPDIFF(MINUTE, s.start_time, s.end_time) / 60 AS duration_hours,
                   sec.year_level,
                   CASE 
                       WHEN s.schedule_type = 'Laboratory' THEN TIMESTAMPDIFF(MINUTE, s.start_time, s.end_time) / 60
                       ELSE 0 
                   END AS lab_hours,
                   CASE 
                       WHEN s.schedule_type = 'Lecture' THEN TIMESTAMPDIFF(MINUTE, s.start_time, s.end_time) / 60
                       ELSE 0 
                   END AS lecture_hours,
                   COUNT(sec.current_students) as student_count
            FROM schedules s
            LEFT JOIN courses c ON s.course_id = c.course_id
            LEFT JOIN sections sec ON s.section_id = sec.section_id
            LEFT JOIN classrooms r ON s.room_id = r.room_id
            WHERE s.faculty_id = ? AND s.semester_id = ?
            GROUP BY s.schedule_id, c.course_code, c.course_name, r.room_name, 
                     s.start_time, s.end_time, s.schedule_type, sec.section_name
            ORDER BY c.course_code, s.start_time
        ");
            $schedulesStmt->execute([$facultyId, $semesterId]);
            $rawSchedules = $schedulesStmt->fetchAll(PDO::FETCH_ASSOC);

            // Group schedules by course, time, and room to combine days
            $groupedSchedules = [];
            $scheduleKey = [];

            foreach ($rawSchedules as $schedule) {
                $key = $schedule['course_code'] . '|' . $schedule['start_time'] . '|' . $schedule['end_time'] . '|' . $schedule['schedule_type'] . '|' . $schedule['section_name'];

                if (!isset($groupedSchedules[$key])) {
                    $groupedSchedules[$key] = $schedule;
                    $groupedSchedules[$key]['days'] = [];
                }

                $groupedSchedules[$key]['days'][] = $schedule['day_of_week'];
            }

            // Format days and create final schedule array
            $schedules = [];
            foreach ($groupedSchedules as $schedule) {
                $schedule['day_of_week'] = $this->schedulingService->formatScheduleDays(implode(', ', $schedule['days']));
                unset($schedule['days']);
                $schedules[] = $schedule;
            }

            error_log("mySchedule: Fetched " . count($schedules) . " grouped schedules for faculty_id $facultyId in semester $semesterId");

            $showAllSchedules = false;
            if (empty($schedules)) {
                error_log("mySchedule: No schedules found for current semester, trying to fetch all schedules");
                // Repeat the same process for all semesters
                $schedulesStmt = $this->db->prepare("
                SELECT s.schedule_id, c.course_code, c.course_name, c.units,
                       r.room_name, s.day_of_week, s.start_time, s.end_time, s.schedule_type, 
                       COALESCE(sec.section_name, 'N/A') AS section_name, sec.current_students,
                       TIMESTAMPDIFF(MINUTE, s.start_time, s.end_time) / 60 AS duration_hours,
                       sec.year_level,
                       CASE 
                           WHEN s.schedule_type = 'Laboratory' THEN TIMESTAMPDIFF(MINUTE, s.start_time, s.end_time) / 60
                           ELSE 0 
                       END AS lab_hours,
                       CASE 
                           WHEN s.schedule_type = 'Lecture' THEN TIMESTAMPDIFF(MINUTE, s.start_time, s.end_time) / 60
                           ELSE 0 
                       END AS lecture_hours,
                       COUNT(sec.current_students) as student_count
                FROM schedules s
                LEFT JOIN courses c ON s.course_id = c.course_id
                LEFT JOIN sections sec ON s.section_id = sec.section_id
                LEFT JOIN classrooms r ON s.room_id = r.room_id
                WHERE s.faculty_id = ?
                GROUP BY s.schedule_id, c.course_code, c.course_name, r.room_name, 
                         s.start_time, s.end_time, s.schedule_type, sec.section_name
                ORDER BY c.course_code, s.start_time
            ");
                $schedulesStmt->execute([$facultyId]);
                $rawSchedules = $schedulesStmt->fetchAll(PDO::FETCH_ASSOC);

                // Same grouping logic
                $groupedSchedules = [];
                foreach ($rawSchedules as $schedule) {
                    $key = $schedule['course_code'] . '|' . $schedule['start_time'] . '|' . $schedule['end_time'] . '|' . $schedule['schedule_type'] . '|' . $schedule['section_name'];

                    if (!isset($groupedSchedules[$key])) {
                        $groupedSchedules[$key] = $schedule;
                        $groupedSchedules[$key]['days'] = [];
                    }

                    $groupedSchedules[$key]['days'][] = $schedule['day_of_week'];
                }

                $schedules = [];
                foreach ($groupedSchedules as $schedule) {
                    $schedule['day_of_week'] = $this->schedulingService->formatScheduleDays(implode(', ', $schedule['days']));
                    unset($schedule['days']);
                    $schedules[] = $schedule;
                }

                $showAllSchedules = true;
                error_log("mySchedule: Fetched " . count($schedules) . " total grouped schedules for faculty_id $facultyId");
            }

            // Calculate totals
            $totalHours = 0;
            $totalLectureHours = 0;
            $totalLabHours = 0;
            $preparations = [];

            foreach ($schedules as $schedule) {
                $totalHours += $schedule['duration_hours'];
                $totalLectureHours += $schedule['lecture_hours'];
                $totalLabHours += $schedule['lab_hours'];
                $preparations[$schedule['course_code']] = true;
            }

            $totalLabHoursX075 = $totalLabHours * 0.75;
            $noOfPreparations = count($preparations);
            $actualTeachingLoad = $totalLectureHours + $totalLabHoursX075;
            $equivalTeachingLoad = $faculty['equiv_teaching_load'] ?? 0;
            $totalWorkingLoad = $actualTeachingLoad + $equivalTeachingLoad;
            $excessHours = max(0, $totalWorkingLoad - 24);

            error_log("mySchedule: Calculations - Total hours: $totalHours, Lecture: $totalLectureHours, Lab: $totalLabHours, Preparations: $noOfPreparations");

            // Pass all data to view
            $facultyData = [
                'faculty_id' => $facultyId,
                'faculty_name' => $facultyName,
                'academic_rank' => $facultyPosition,
                'employment_type' => $employmentType,
                'bachelor_degree' => $faculty['bachelor_degree'] ?? 'Not specified',
                'master_degree' => $faculty['master_degree'] ?? 'Not specified',
                'doctorate_degree' => $faculty['doctorate_degree'] ?? 'Not specified',
                'post_doctorate_degree' => $faculty['post_doctorate_degree'] ?? 'Not applicable',
                'designation' => $faculty['designation'] ?? 'Not specified',
                'classification' => $faculty['classification'] ?? 'Not specified',
                'advisory_class' => $faculty['advisory_class'] ?? 'Not assigned',
                'total_lecture_hours' => $totalLectureHours,
                'total_laboratory_hours' => $totalLabHours,
                'total_laboratory_hours_x075' => $totalLabHoursX075,
                'no_of_preparation' => $noOfPreparations,
                'actual_teaching_load' => $actualTeachingLoad,
                'equiv_teaching_load' => $equivalTeachingLoad,
                'total_working_load' => $totalWorkingLoad,
                'excess_hours' => $excessHours
            ];

            require_once __DIR__ . '/../views/director/schedule.php';
        } catch (Exception $e) {
            error_log("mySchedule: Full error: " . $e->getMessage());
            http_response_code(500);
            echo "Error loading schedule: " . htmlspecialchars($e->getMessage());
            exit;
        }
    }

    public function manageSchedule()
    {
        $userId = $_SESSION['user_id'];

        // Handle approval/rejection actions
        if (isset($_POST['action']) && in_array($_POST['action'], ['approve', 'reject'])) {
            $scheduleIdsStr = $_POST['schedule_ids'] ?? $_POST['schedule_id'] ?? '';
            $status = $_POST['action'] === 'approve' ? 'Approved' : 'Rejected';
            $isPublic = $_POST['action'] === 'approve' ? 1 : 0;

            // Get current semester details
            $currentSemester = $this->userModel->getCurrentSemester();
            $currentSemesterId = $currentSemester ? $currentSemester['semester_id'] : null;

            if ($currentSemesterId && !empty($scheduleIdsStr)) {
                try {
                    $scheduleIds = array_map('intval', explode(',', $scheduleIdsStr));
                    $placeholders = implode(',', array_fill(0, count($scheduleIds), '?'));

                    $stmt = $this->db->prepare("
                        UPDATE schedules 
                        SET status = ?, approved_by_di = ?, approval_date_di = NOW(), is_public = ?, updated_at = NOW()
                        WHERE schedule_id IN ($placeholders) AND semester_id = ? AND status = 'Dean_Approved'
                    ");
                    $params = array_merge([$status, $userId, $isPublic], $scheduleIds, [$currentSemesterId]);
                    $result = $stmt->execute($params);

                    if ($result && $stmt->rowCount() > 0) {
                        $_SESSION['success'] = "Schedule(s) {$status} successfully.";
                    } else {
                        error_log("Director manageSchedule: No schedules updated for IDs $scheduleIdsStr in semester $currentSemesterId");
                        $_SESSION['error'] = "No schedules pending Director approval or failed to update.";
                    }
                } catch (PDOException $e) {
                    error_log("Director manageSchedule: PDO Error - " . $e->getMessage());
                    $_SESSION['error'] = "Database error occurred.";
                }
            } else {
                error_log("Director manageSchedule: No current semester found or invalid schedule IDs");
                $_SESSION['error'] = "No current semester found or invalid schedule IDs.";
            }

            // Redirect to prevent form resubmission
            header('Location: ' . $_SERVER['REQUEST_URI']);
            exit;
        }

        // Get current semester details
        $currentSemester = $this->userModel->getCurrentSemester();
        $currentSemesterId = $currentSemester ? $currentSemester['semester_id'] : null;

        if (!$currentSemesterId) {
            error_log("Director manageSchedule: No current semester found");
            $departments = [];
            $schedules = [];
            require_once __DIR__ . '/../views/director/pending-approvals.php';
            return;
        }

        try {
            // Count pending schedules for the current semester
            $stmt = $this->db->prepare("
                SELECT COUNT(DISTINCT s.schedule_id) as total_pending
                FROM schedules s
                WHERE s.semester_id = :semester_id AND s.status = 'Dean_Approved'
            ");
            $stmt->execute([':semester_id' => $currentSemesterId]);
            $stats['total_pending'] = (int) $stmt->fetchColumn();
            error_log("Director manageSchedule: Found {$stats['total_pending']} pending schedules for semester $currentSemesterId");

            // Fetch all departments with college name
            $stmt = $this->db->prepare("
                SELECT d.department_id, d.department_name, c.college_id, c.college_name
                FROM departments d
                JOIN colleges c ON d.college_id = c.college_id
                ORDER BY c.college_name, d.department_name
            ");
            $stmt->execute();
            $departments = $stmt->fetchAll(PDO::FETCH_ASSOC);

            // Fetch schedules pending Director approval
            $stmt = $this->db->prepare("
                SELECT 
                    GROUP_CONCAT(DISTINCT s.schedule_id) as schedule_ids,
                    s.department_id, d.department_name, c.college_name,
                    s.start_time, s.end_time, co.course_code, cl.room_name,
                    sec.section_name, s.schedule_type, s.status,
                    CONCAT(COALESCE(u.title, ''), ' ', u.first_name, ' ', u.middle_name, ' ', u.last_name) AS faculty_name, 
                    GROUP_CONCAT(DISTINCT s.day_of_week ORDER BY 
                        CASE s.day_of_week 
                            WHEN 'Monday' THEN 1
                            WHEN 'Tuesday' THEN 2
                            WHEN 'Wednesday' THEN 3
                            WHEN 'Thursday' THEN 4
                            WHEN 'Friday' THEN 5
                            WHEN 'Saturday' THEN 6
                            WHEN 'Sunday' THEN 7
                        END
                        SEPARATOR ', '
                    ) as day_of_week
                FROM schedules s
                JOIN faculty f ON s.faculty_id = f.faculty_id
                JOIN users u ON f.user_id = u.user_id
                JOIN courses co ON s.course_id = co.course_id
                LEFT JOIN classrooms cl ON s.room_id = cl.room_id
                JOIN sections sec ON s.section_id = sec.section_id
                JOIN departments d ON s.department_id = d.department_id
                JOIN colleges c ON d.college_id = c.college_id
                WHERE s.semester_id = :semester_id AND s.status = 'Dean_Approved'
                GROUP BY s.department_id, d.department_name, c.college_name, co.course_code, 
                         sec.section_name, s.schedule_type, u.title, u.first_name, 
                         u.middle_name, u.last_name, cl.room_name, s.start_time, s.end_time
                ORDER BY c.college_name, d.department_name, co.course_code, s.start_time
            ");
            $stmt->execute([':semester_id' => $currentSemesterId]);
            $allSchedules = $stmt->fetchAll(PDO::FETCH_ASSOC);

            // Group schedules by department_id
            $schedules = [];
            foreach ($allSchedules as $schedule) {
                $deptId = $schedule['department_id'];
                if (!isset($schedules[$deptId])) {
                    $schedules[$deptId] = [];
                }
                $schedule['formatted_days'] = $this->schedulingService->formatScheduleDays($schedule['day_of_week']);
                $schedules[$deptId][] = $schedule;
            }

            error_log("Director manageSchedule: Fetched " . count($allSchedules) . " grouped schedules for semester $currentSemesterId, grouped into " . count($schedules) . " departments");
        } catch (PDOException $e) {
            error_log("Director manageSchedule: PDO Error - " . $e->getMessage());
            $departments = [];
            $schedules = [];
            $stats['total_pending'] = 0;
        }

        require_once __DIR__ . '/../views/director/pending-approvals.php';
    }

    /**
     * Director's view of ALL faculty teaching loads across ALL colleges and departments
     */
    public function collegeTeachingLoad()
    {
        try {
            $userId = $_SESSION['user_id'];
            error_log("collegeTeachingLoad: Starting method for director user_id: $userId");

            // Get current semester
            $semesterStmt = $this->db->query("SELECT semester_id, semester_name, academic_year FROM semesters WHERE is_current = 1");
            $semester = $semesterStmt->fetch(PDO::FETCH_ASSOC);

            if (!$semester) {
                error_log("collegeTeachingLoad: No current semester found");
                $error = "No current semester defined. Please contact the administrator to set the current semester.";
                require_once __DIR__ . '/../views/director/all-teaching-load.php';
                return;
            }

            $semesterId = $semester['semester_id'];
            $semesterName = $semester['semester_name'] . ' Semester, A.Y ' . $semester['academic_year'];
            error_log("collegeTeachingLoad: Current semester ID: $semesterId, Name: $semesterName");

            // Get selected department and college from filter
            $selectedDepartment = $_GET['department'] ?? 'all';
            $selectedCollege = $_GET['college'] ?? 'all';

            $departmentFilter = '';
            $collegeFilter = '';
            $filterParams = [];

            if ($selectedDepartment !== 'all') {
                $departmentFilter = "AND d.department_id = ?";
                $filterParams[] = $selectedDepartment;
            }

            if ($selectedCollege !== 'all') {
                $collegeFilter = "AND c.college_id = ?";
                $filterParams[] = $selectedCollege;
            }

            // Get all colleges for the filter dropdown
            $collegesStmt = $this->db->query("SELECT college_id, college_name FROM colleges ORDER BY college_name");
            $colleges = $collegesStmt->fetchAll(PDO::FETCH_ASSOC);

            // Get all departments for the filter dropdown
            $departmentsStmt = $this->db->query("SELECT department_id, department_name, college_id FROM departments ORDER BY department_name");
            $departments = $departmentsStmt->fetchAll(PDO::FETCH_ASSOC);

            // Get ALL faculty across ALL colleges with their schedules
            $facultyStmt = $this->db->prepare("
            SELECT 
                f.faculty_id,
                f.academic_rank,
                f.employment_type,
                f.equiv_teaching_load,
                f.bachelor_degree,
                f.master_degree,
                f.doctorate_degree,
                f.post_doctorate_degree,
                f.designation,
                f.classification,
                f.advisory_class,
                CONCAT(COALESCE(u.title, ''), ' ', u.first_name, ' ', 
                    COALESCE(u.middle_name, ''), ' ', u.last_name, ' ', 
                    COALESCE(u.suffix, '')) AS faculty_name,
                d.department_name,
                d.department_id,
                c.college_name,
                c.college_id,
                COUNT(DISTINCT s.schedule_id) as total_schedules,
                COUNT(DISTINCT s.course_id) as total_courses,
                SUM(TIMESTAMPDIFF(MINUTE, s.start_time, s.end_time) / 60) as total_hours,
                SUM(CASE WHEN s.component_type = 'lecture' THEN TIMESTAMPDIFF(MINUTE, s.start_time, s.end_time) / 60 ELSE 0 END) as lecture_hours,
                SUM(CASE WHEN s.component_type = 'laboratory' THEN TIMESTAMPDIFF(MINUTE, s.start_time, s.end_time) / 60 ELSE 0 END) as lab_hours,
                COUNT(DISTINCT CASE WHEN s.component_type = 'lecture' THEN s.course_id END) as lecture_preparations,
                COUNT(DISTINCT CASE WHEN s.component_type = 'laboratory' THEN s.course_id END) as lab_preparations
            FROM faculty f
            JOIN users u ON f.user_id = u.user_id
            JOIN faculty_departments fd ON f.faculty_id = fd.faculty_id
            JOIN departments d ON fd.department_id = d.department_id
            JOIN colleges c ON d.college_id = c.college_id
            LEFT JOIN schedules s ON f.faculty_id = s.faculty_id 
                AND s.semester_id = ?
                AND s.status != 'Rejected'
            WHERE 1=1
            $departmentFilter
            $collegeFilter
            GROUP BY f.faculty_id, u.first_name, u.middle_name, u.last_name, u.title, u.suffix,
                    f.academic_rank, f.employment_type, f.equiv_teaching_load, d.department_name,
                    f.bachelor_degree, f.master_degree, f.doctorate_degree, f.post_doctorate_degree,
                    f.designation, f.classification, f.advisory_class, d.department_id, c.college_name, c.college_id
            ORDER BY c.college_name, d.department_name, faculty_name
        ");

            $params = array_merge([$semesterId], $filterParams);
            $facultyStmt->execute($params);
            $facultyData = $facultyStmt->fetchAll(PDO::FETCH_ASSOC);

            error_log("collegeTeachingLoad: Found " . count($facultyData) . " faculty members across all colleges");

            // Calculate teaching loads for each faculty
            $facultyTeachingLoads = [];
            $systemTotals = [
                'total_faculty' => 0,
                'total_lecture_hours' => 0,
                'total_lab_hours' => 0,
                'total_teaching_load' => 0,
                'total_working_load' => 0,
                'total_excess_hours' => 0
            ];

            foreach ($facultyData as $faculty) {
                $lectureHours = (float)$faculty['lecture_hours'];
                $labHours = (float)$faculty['lab_hours'];
                $labHoursX075 = $labHours * 0.75;
                $actualTeachingLoad = $lectureHours + $labHoursX075;
                $equivTeachingLoad = (float)$faculty['equiv_teaching_load'] ?? 0;
                $totalWorkingLoad = $actualTeachingLoad + $equivTeachingLoad;
                $excessHours = max(0, $totalWorkingLoad - 24);
                $totalPreparations = (int)$faculty['lecture_preparations'] + (int)$faculty['lab_preparations'];

                $facultyTeachingLoads[] = [
                    'faculty_id' => $faculty['faculty_id'],
                    'faculty_name' => trim($faculty['faculty_name']),
                    'department_name' => $faculty['department_name'],
                    'department_id' => $faculty['department_id'],
                    'college_name' => $faculty['college_name'],
                    'college_id' => $faculty['college_id'],
                    'academic_rank' => $faculty['academic_rank'] ?? 'Not Specified',
                    'employment_type' => $faculty['employment_type'] ?? 'Regular',
                    'bachelor_degree' => $faculty['bachelor_degree'] ?? 'Not specified',
                    'master_degree' => $faculty['master_degree'] ?? 'Not specified',
                    'doctorate_degree' => $faculty['doctorate_degree'] ?? 'Not specified',
                    'post_doctorate_degree' => $faculty['post_doctorate_degree'] ?? 'Not applicable',
                    'designation' => $faculty['designation'] ?? 'Not specified',
                    'classification' => $faculty['classification'] ?? 'Not specified',
                    'advisory_class' => $faculty['advisory_class'] ?? 'Not assigned',
                    'total_schedules' => (int)$faculty['total_schedules'],
                    'total_courses' => (int)$faculty['total_courses'],
                    'total_hours' => (float)$faculty['total_hours'],
                    'lecture_hours' => $lectureHours,
                    'lab_hours' => $labHours,
                    'lab_hours_x075' => $labHoursX075,
                    'total_preparations' => $totalPreparations,
                    'lecture_preparations' => (int)$faculty['lecture_preparations'],
                    'lab_preparations' => (int)$faculty['lab_preparations'],
                    'actual_teaching_load' => $actualTeachingLoad,
                    'equiv_teaching_load' => $equivTeachingLoad,
                    'total_working_load' => $totalWorkingLoad,
                    'excess_hours' => $excessHours,
                    'load_status' => $this->schedulingService->getLoadStatus($totalWorkingLoad, $excessHours)
                ];

                // Update system totals
                $systemTotals['total_faculty']++;
                $systemTotals['total_lecture_hours'] += $lectureHours;
                $systemTotals['total_lab_hours'] += $labHours;
                $systemTotals['total_teaching_load'] += $actualTeachingLoad;
                $systemTotals['total_working_load'] += $totalWorkingLoad;
                $systemTotals['total_excess_hours'] += $excessHours;
            }

            error_log("collegeTeachingLoad: Processed teaching loads for " . count($facultyTeachingLoads) . " faculty members");

            // Pass all data to view
            require_once __DIR__ . '/../views/director/all-teaching-load.php';
        } catch (Exception $e) {
            error_log("collegeTeachingLoad: Full error: " . $e->getMessage());
            http_response_code(500);
            echo "Error loading college teaching loads: " . htmlspecialchars($e->getMessage());
            exit;
        }
    }

    /**
     * Approve faculty teaching load (Director level - NO RESTRICTIONS)
     */
    public function approveTeachingLoadDirector()
    {
        header('Content-Type: application/json');

        try {
            $userId = $_SESSION['user_id'];
            $facultyId = $_POST['faculty_id'] ?? null;
            $semesterId = $_POST['semester_id'] ?? null;
            $notes = $_POST['notes'] ?? '';

            if (!$facultyId || !$semesterId) {
                echo json_encode(['success' => false, 'message' => 'Missing required parameters']);
                exit;
            }

            // NO COLLEGE VERIFICATION - Director can approve ANY faculty

            // Update all schedules for this faculty in the current semester to Di_Approved
            $updateStmt = $this->db->prepare("
            UPDATE schedules 
            SET status = 'Di_Approved', 
                approved_by_di = ?,
                approval_date_di = NOW(),
                updated_at = NOW()
            WHERE faculty_id = ? 
            AND semester_id = ?
            AND status IN ('Pending', 'Dean_Approved') -- Only update pending or dean approved schedules
        ");

            $updateStmt->execute([$userId, $facultyId, $semesterId]);
            $affectedRows = $updateStmt->rowCount();

            echo json_encode([
                'success' => true,
                'message' => "Teaching load approved successfully. {$affectedRows} schedules updated.",
                'affected_rows' => $affectedRows
            ]);
        } catch (Exception $e) {
            error_log("approveTeachingLoadDirector error: " . $e->getMessage());
            echo json_encode(['success' => false, 'message' => 'Error approving teaching load']);
        }
        exit;
    }

    /**
     * Reject faculty teaching load (Director level - NO RESTRICTIONS)
     */
    public function rejectTeachingLoadDirector()
    {
        header('Content-Type: application/json');

        try {
            $userId = $_SESSION['user_id'];
            $facultyId = $_POST['faculty_id'] ?? null;
            $semesterId = $_POST['semester_id'] ?? null;
            $rejectionReason = $_POST['rejection_reason'] ?? '';

            if (!$facultyId || !$semesterId) {
                echo json_encode(['success' => false, 'message' => 'Missing required parameters']);
                exit;
            }

            if (empty($rejectionReason)) {
                echo json_encode(['success' => false, 'message' => 'Rejection reason is required']);
                exit;
            }

            // NO COLLEGE VERIFICATION - Director can reject ANY faculty

            // Update all schedules for this faculty in the current semester to Rejected
            $updateStmt = $this->db->prepare("
            UPDATE schedules 
            SET status = 'Rejected', 
                updated_at = NOW()
            WHERE faculty_id = ? 
            AND semester_id = ?
            AND status != 'Rejected' -- Don't update already rejected schedules
        ");

            $updateStmt->execute([$facultyId, $semesterId]);
            $affectedRows = $updateStmt->rowCount();

            echo json_encode([
                'success' => true,
                'message' => "Teaching load rejected successfully. {$affectedRows} schedules updated.",
                'affected_rows' => $affectedRows
            ]);
        } catch (Exception $e) {
            error_log("rejectTeachingLoadDirector error: " . $e->getMessage());
            echo json_encode(['success' => false, 'message' => 'Error rejecting teaching load']);
        }
        exit;
    }

    /**
     * Get faculty approval status for director (NO RESTRICTIONS)
     */
    public function getFacultyApprovalStatusDirector($facultyId)
    {
        header('Content-Type: application/json');

        try {
            // Get current semester
            $semesterStmt = $this->db->query("SELECT semester_id FROM semesters WHERE is_current = 1");
            $semester = $semesterStmt->fetch(PDO::FETCH_ASSOC);

            if (!$semester) {
                echo json_encode(['success' => false, 'message' => 'No current semester']);
                exit;
            }

            // Get approval status breakdown for faculty schedules
            $statusStmt = $this->db->prepare("
            SELECT 
                status,
                COUNT(*) as schedule_count
            FROM schedules 
            WHERE faculty_id = ? AND semester_id = ?
            GROUP BY status
            ORDER BY 
                CASE status
                    WHEN 'Rejected' THEN 1
                    WHEN 'Pending' THEN 2
                    WHEN 'Dean_Approved' THEN 3
                    WHEN 'Di_Approved' THEN 4
                    WHEN 'Approved' THEN 5
                    ELSE 6
                END
        ");
            $statusStmt->execute([$facultyId, $semester['semester_id']]);
            $statusData = $statusStmt->fetchAll(PDO::FETCH_ASSOC);

            // Get total schedule count
            $totalStmt = $this->db->prepare("
            SELECT COUNT(*) as total_schedules 
            FROM schedules 
            WHERE faculty_id = ? AND semester_id = ?
        ");
            $totalStmt->execute([$facultyId, $semester['semester_id']]);
            $total = $totalStmt->fetch(PDO::FETCH_ASSOC);

            // Determine overall status
            $overallStatus = 'Pending';
            $hasRejected = false;
            $hasPending = false;
            $hasApproved = false;
            $hasDeanApproved = false;
            $hasDiApproved = false;

            foreach ($statusData as $status) {
                switch ($status['status']) {
                    case 'Rejected':
                        $hasRejected = true;
                        break;
                    case 'Pending':
                        $hasPending = true;
                        break;
                    case 'Dean_Approved':
                        $hasDeanApproved = true;
                        break;
                    case 'Di_Approved':
                        $hasDiApproved = true;
                        break;
                    case 'Approved':
                        $hasApproved = true;
                        break;
                }
            }

            // Determine overall status
            if ($hasRejected) {
                $overallStatus = 'Rejected';
            } elseif ($hasApproved) {
                $overallStatus = 'Approved';
            } elseif ($hasDiApproved && !$hasPending) {
                $overallStatus = 'Di_Approved';
            } elseif ($hasDeanApproved && !$hasPending) {
                $overallStatus = 'Dean_Approved';
            } elseif (($hasDeanApproved || $hasDiApproved) && $hasPending) {
                $overallStatus = 'Partially_Approved';
            } else {
                $overallStatus = 'Pending';
            }

            echo json_encode([
                'success' => true,
                'overall_status' => $overallStatus,
                'status_details' => $statusData,
                'total_schedules' => $total['total_schedules'],
                'semester_id' => $semester['semester_id']
            ]);
        } catch (Exception $e) {
            error_log("getFacultyApprovalStatusDirector error: " . $e->getMessage());
            echo json_encode(['success' => false, 'message' => 'Error fetching approval status']);
        }
        exit;
    }

    /**
     * API endpoint to get faculty schedule details for directors (NO RESTRICTIONS)
     */
    public function getFacultySchedule($facultyId)
    {
        header('Content-Type: application/json');

        try {
            // Validate faculty ID
            if (!is_numeric($facultyId) || $facultyId <= 0) {
                throw new Exception('Invalid faculty ID');
            }

            // Get faculty info - NO COLLEGE VERIFICATION
            $facultyStmt = $this->db->prepare("
            SELECT f.faculty_id, 
                   CONCAT(COALESCE(u.title, ''), ' ', u.first_name, ' ', COALESCE(u.middle_name, ''), ' ', u.last_name, ' ', COALESCE(u.suffix, '')) AS faculty_name,
                   d.department_name,
                   c.college_name,
                   f.employment_type,
                   f.academic_rank
            FROM faculty f
            JOIN users u ON f.user_id = u.user_id
            JOIN faculty_departments fd ON f.faculty_id = fd.faculty_id
            JOIN departments d ON fd.department_id = d.department_id
            JOIN colleges c ON d.college_id = c.college_id
            WHERE f.faculty_id = ?
        ");
            $facultyStmt->execute([$facultyId]);
            $faculty = $facultyStmt->fetch(PDO::FETCH_ASSOC);

            if (!$faculty) {
                throw new Exception('Faculty not found');
            }

            // Get current semester
            $semesterStmt = $this->db->query("SELECT semester_id FROM semesters WHERE is_current = 1");
            $semester = $semesterStmt->fetch(PDO::FETCH_ASSOC);

            if (!$semester) {
                throw new Exception('No current semester defined');
            }

            // Get faculty schedules
            $schedulesStmt = $this->db->prepare("
            SELECT 
                c.course_code,
                c.course_name,
                COALESCE(sec.section_name, 'N/A') AS section_name,
                r.room_name,
                s.day_of_week,
                s.start_time,
                s.end_time,
                s.component_type,
                s.status,
                TIMESTAMPDIFF(MINUTE, s.start_time, s.end_time) / 60 AS duration_hours
            FROM schedules s
            LEFT JOIN courses c ON s.course_id = c.course_id
            LEFT JOIN sections sec ON s.section_id = sec.section_id
            LEFT JOIN classrooms r ON s.room_id = r.room_id
            WHERE s.faculty_id = ? 
                AND s.semester_id = ?
                AND s.status != 'Rejected'
            ORDER BY 
                CASE s.day_of_week 
                    WHEN 'Monday' THEN 1
                    WHEN 'Tuesday' THEN 2
                    WHEN 'Wednesday' THEN 3
                    WHEN 'Thursday' THEN 4
                    WHEN 'Friday' THEN 5
                    WHEN 'Saturday' THEN 6
                    WHEN 'Sunday' THEN 7
                END,
                s.start_time
        ");
            $schedulesStmt->execute([$facultyId, $semester['semester_id']]);
            $schedules = $schedulesStmt->fetchAll(PDO::FETCH_ASSOC);

            // Always return valid JSON
            echo json_encode([
                'success' => true,
                'faculty' => $faculty,
                'schedules' => $schedules
            ]);
        } catch (Exception $e) {
            error_log("getFacultySchedule error: " . $e->getMessage());
            // Always return valid JSON even for errors
            echo json_encode([
                'success' => false,
                'message' => 'Error loading schedule: ' . $e->getMessage()
            ]);
        }
        exit;
    }

    public function getStats()
    {
        $stats = ['total_pending' => 0];
        $currentSemester = $this->userModel->getCurrentSemester();
        if ($currentSemester) {
            try {
                $stmt = $this->db->prepare("
                    SELECT COUNT(DISTINCT s.schedule_id) as total_pending
                    FROM schedules s
                    WHERE s.semester_id = :semester_id AND s.status = 'Dean_Approved'
                ");
                $stmt->execute([':semester_id' => $currentSemester['semester_id']]);
                $stats['total_pending'] = (int) $stmt->fetchColumn();
                error_log("getStats: Found {$stats['total_pending']} pending schedules for semester {$currentSemester['semester_id']}");
            } catch (PDOException $e) {
                error_log("getStats: PDO Error - " . $e->getMessage());
                $stats['total_pending'] = 0;
            }
        } else {
            error_log("getStats: No current semester found");
        }
        return $stats;
    }

    private function getScheduleDeadline($departmentId)
    {
        try {
            $stmt = $this->db->prepare("
            SELECT deadline 
            FROM schedule_deadlines 
            WHERE department_id = :department_id 
            ORDER BY deadline DESC LIMIT 1
        ");
            $stmt->execute([':department_id' => $departmentId]);
            return $stmt->fetchColumn();
        } catch (PDOException $e) {
            error_log("getScheduleDeadline: " . $e->getMessage());
            return null;
        }
    }

    private function getFacultyId($userId)
    {
        try {
            $stmt = $this->db->prepare("SELECT faculty_id FROM faculty WHERE user_id = :user_id");
            $stmt->execute([':user_id' => $userId]);
            $faculty = $stmt->fetch(PDO::FETCH_ASSOC);
            return $faculty ? $faculty['faculty_id'] : null;
        } catch (PDOException $e) {
            error_log("getFacultyId: " . $e->getMessage());
            return null;
        }
    }

    private function getSchedules($facultyId)
    {
        try {
            $stmt = $this->db->prepare("
            SELECT s.*, c.course_code, c.course_name, r.room_name, se.semester_name, se.academic_year
            FROM schedules s
            JOIN courses c ON s.course_id = c.course_id
            LEFT JOIN classrooms r ON s.room_id = r.room_id
            JOIN semesters se ON s.semester_id = se.semester_id
            WHERE s.faculty_id = :faculty_id AND se.is_current = 1
            ORDER BY s.day_of_week, s.start_time
        ");
            $stmt->execute([':faculty_id' => $facultyId]);
            return $stmt->fetchAll(PDO::FETCH_ASSOC);
        } catch (PDOException $e) {
            error_log("getSchedules: " . $e->getMessage());
            return [];
        }
    }

    public function setScheduleDeadline()
    {
        try {
            $userData = $this->getUserData();

            // Check if user is system admin (can set deadlines for all colleges)
            $isSystemAdmin = $this->checkSystemAdminRole($_SESSION['user_id']);

            // fetch the current semester
            $currentSemester = $this->api->getCurrentSemester();

            // Fetch department_id and college_id from department_instructors with department join
            $stmt = $this->db->prepare("
            SELECT di.department_id, d.college_id 
            FROM department_instructors di
            INNER JOIN departments d ON di.department_id = d.department_id
            WHERE di.user_id = :user_id AND di.is_current = 1
            ");
            $stmt->execute([':user_id' => $_SESSION['user_id']]);
            $userDepartment = $stmt->fetch(PDO::FETCH_ASSOC);

            if (!$userDepartment) {
                error_log("setScheduleDeadline: No department found for user_id: " . $_SESSION['user_id']);
                header('Location: /login?error=Department not assigned');
                exit;
            }

            $collegeId = $userDepartment['college_id'];
            $userDepartmentId = $userDepartment['department_id'];

            if ($_SERVER['REQUEST_METHOD'] === 'POST') {
                $deadline = filter_input(INPUT_POST, 'deadline', FILTER_SANITIZE_STRING);
                $applyScope = filter_input(INPUT_POST, 'apply_scope', FILTER_SANITIZE_STRING);
                $selectedColleges = filter_input(INPUT_POST, 'selected_colleges', FILTER_DEFAULT, FILTER_REQUIRE_ARRAY) ?: [];
                $selectedDepartments = filter_input(INPUT_POST, 'selected_departments', FILTER_DEFAULT, FILTER_REQUIRE_ARRAY) ?: [];

                // Check if it's an AJAX request
                $isAjax = isset($_SERVER['HTTP_X_REQUESTED_WITH']) && $_SERVER['HTTP_X_REQUESTED_WITH'] === 'XMLHttpRequest';

                if (!$deadline) {
                    $errorMsg = 'Please provide a valid deadline date and time.';
                    error_log("setScheduleDeadline: Invalid deadline format");

                    if ($isAjax) {
                        header('Content-Type: application/json');
                        echo json_encode(['success' => false, 'error' => $errorMsg]);
                        exit;
                    } else {
                        $_SESSION['error'] = $errorMsg;
                        header('Location: /director/schedule_deadline');
                        exit;
                    }
                }

                // Parse deadline with the correct format from datetime-local input
                $deadlineDate = DateTime::createFromFormat('Y-m-d\TH:i', $deadline, new DateTimeZone('America/Los_Angeles'));
                if ($deadlineDate === false) {
                    $errorMsg = 'Please provide a valid deadline date and time.';
                    error_log("setScheduleDeadline: Failed to parse deadline: $deadline");

                    if ($isAjax) {
                        header('Content-Type: application/json');
                        echo json_encode(['success' => false, 'error' => $errorMsg]);
                        exit;
                    } else {
                        $_SESSION['error'] = $errorMsg;
                        header('Location: /director/schedule_deadline');
                        exit;
                    }
                }

                // Compare with current time in the same timezone
                $currentTime = new DateTime('now', new DateTimeZone('America/Los_Angeles'));
                if ($deadlineDate < $currentTime) {
                    $errorMsg = 'Deadline must be a future date and time.';
                    error_log("setScheduleDeadline: Deadline is in the past: " . $deadlineDate->format('Y-m-d H:i:s'));

                    if ($isAjax) {
                        header('Content-Type: application/json');
                        echo json_encode(['success' => false, 'error' => $errorMsg]);
                        exit;
                    } else {
                        $_SESSION['error'] = $errorMsg;
                        header('Location: /director/schedule_deadline');
                        exit;
                    }
                }

                // Determine scope and get target departments
                $targetDepartments = [];
                $successMessage = '';
                $affectedColleges = [];

                try {
                    switch ($applyScope) {
                        case 'all_colleges':
                            if (!$isSystemAdmin) {
                                $errorMsg = 'You do not have permission to set system-wide deadlines.';
                                if ($isAjax) {
                                    header('Content-Type: application/json');
                                    echo json_encode(['success' => false, 'error' => $errorMsg]);
                                    exit;
                                } else {
                                    $_SESSION['error'] = $errorMsg;
                                    header('Location: /director/schedule_deadline');
                                    exit;
                                }
                            }

                            $deptStmt = $this->db->prepare("
                SELECT d.department_id, c.college_name
                FROM departments d
                INNER JOIN colleges c ON d.college_id = c.college_id
                ORDER BY c.college_name ASC
                ");
                            $deptStmt->execute();
                            $deptResults = $deptStmt->fetchAll(PDO::FETCH_ASSOC);
                            $targetDepartments = array_column($deptResults, 'department_id');
                            $affectedColleges = array_unique(array_column($deptResults, 'college_name'));

                            $successMessage = "Schedule deadline set successfully for all departments across all colleges.";
                            break;

                        case 'college_wide':
                            $deptStmt = $this->db->prepare("
                SELECT d.department_id, c.college_name
                FROM departments d 
                INNER JOIN colleges c ON d.college_id = c.college_id
                WHERE d.college_id = :college_id
                ");
                            $deptStmt->execute([':college_id' => $collegeId]);
                            $deptResults = $deptStmt->fetchAll(PDO::FETCH_ASSOC);
                            $targetDepartments = array_column($deptResults, 'department_id');
                            $affectedColleges = array_unique(array_column($deptResults, 'college_name'));

                            $successMessage = "Schedule deadline set successfully for all departments in your college.";
                            break;

                        case 'specific_colleges':
                            if (!$isSystemAdmin) {
                                $errorMsg = 'You do not have permission to set deadlines for other colleges.';
                                if ($isAjax) {
                                    header('Content-Type: application/json');
                                    echo json_encode(['success' => false, 'error' => $errorMsg]);
                                    exit;
                                } else {
                                    $_SESSION['error'] = $errorMsg;
                                    header('Location: /director/schedule_deadline');
                                    exit;
                                }
                            }

                            if (empty($selectedColleges)) {
                                $errorMsg = 'Please select at least one college.';
                                if ($isAjax) {
                                    header('Content-Type: application/json');
                                    echo json_encode(['success' => false, 'error' => $errorMsg]);
                                    exit;
                                } else {
                                    $_SESSION['error'] = $errorMsg;
                                    header('Location: /director/schedule_deadline');
                                    exit;
                                }
                            }

                            $placeholders = str_repeat('?,', count($selectedColleges) - 1) . '?';
                            $validateStmt = $this->db->prepare("
                SELECT college_id FROM colleges WHERE college_id IN ($placeholders)
                ");
                            $validateStmt->execute($selectedColleges);
                            $validColleges = $validateStmt->fetchAll(PDO::FETCH_COLUMN);

                            if (count($validColleges) !== count($selectedColleges)) {
                                $errorMsg = 'One or more selected colleges are invalid.';
                                if ($isAjax) {
                                    header('Content-Type: application/json');
                                    echo json_encode(['success' => false, 'error' => $errorMsg]);
                                    exit;
                                } else {
                                    $_SESSION['error'] = $errorMsg;
                                    header('Location: /director/schedule_deadline');
                                    exit;
                                }
                            }

                            $deptStmt = $this->db->prepare("
                SELECT d.department_id, c.college_name
                FROM departments d
                INNER JOIN colleges c ON d.college_id = c.college_id
                WHERE d.college_id IN ($placeholders)
                ORDER BY c.college_name ASC
                ");
                            $deptStmt->execute($selectedColleges);
                            $deptResults = $deptStmt->fetchAll(PDO::FETCH_ASSOC);
                            $targetDepartments = array_column($deptResults, 'department_id');
                            $affectedColleges = array_unique(array_column($deptResults, 'college_name'));

                            $collegeCount = count($affectedColleges);
                            $collegeNames = implode(', ', $affectedColleges);
                            $successMessage = "Schedule deadline set successfully for all departments in {$collegeCount} college(s): {$collegeNames}.";
                            break;

                        case 'specific_departments':
                            if (empty($selectedDepartments)) {
                                $errorMsg = 'Please select at least one department.';
                                if ($isAjax) {
                                    header('Content-Type: application/json');
                                    echo json_encode(['success' => false, 'error' => $errorMsg]);
                                    exit;
                                } else {
                                    $_SESSION['error'] = $errorMsg;
                                    header('Location: /director/schedule_deadline');
                                    exit;
                                }
                            }

                            if (!$isSystemAdmin) {
                                $placeholders = str_repeat('?,', count($selectedDepartments) - 1) . '?';
                                $validateStmt = $this->db->prepare("
                    SELECT department_id FROM departments 
                    WHERE department_id IN ($placeholders) AND college_id = ?
                    ");
                                $validateParams = array_merge($selectedDepartments, [$collegeId]);
                                $validateStmt->execute($validateParams);
                                $validDepartments = $validateStmt->fetchAll(PDO::FETCH_COLUMN);

                                if (count($validDepartments) !== count($selectedDepartments)) {
                                    $errorMsg = 'You can only select departments from your college.';
                                    if ($isAjax) {
                                        header('Content-Type: application/json');
                                        echo json_encode(['success' => false, 'error' => $errorMsg]);
                                        exit;
                                    } else {
                                        $_SESSION['error'] = $errorMsg;
                                        header('Location: /director/schedule_deadline');
                                        exit;
                                    }
                                }
                                $targetDepartments = $validDepartments;
                            } else {
                                $placeholders = str_repeat('?,', count($selectedDepartments) - 1) . '?';
                                $validateStmt = $this->db->prepare("
                    SELECT d.department_id, c.college_name 
                    FROM departments d
                    INNER JOIN colleges c ON d.college_id = c.college_id
                    WHERE d.department_id IN ($placeholders)
                    ");
                                $validateStmt->execute($selectedDepartments);
                                $deptResults = $validateStmt->fetchAll(PDO::FETCH_ASSOC);

                                if (count($deptResults) !== count($selectedDepartments)) {
                                    $errorMsg = 'One or more selected departments are invalid.';
                                    if ($isAjax) {
                                        header('Content-Type: application/json');
                                        echo json_encode(['success' => false, 'error' => $errorMsg]);
                                        exit;
                                    } else {
                                        $_SESSION['error'] = $errorMsg;
                                        header('Location: /director/schedule_deadline');
                                        exit;
                                    }
                                }

                                $targetDepartments = array_column($deptResults, 'department_id');
                                $affectedColleges = array_unique(array_column($deptResults, 'college_name'));
                            }

                            $deptCount = count($targetDepartments);
                            $successMessage = "Schedule deadline set successfully for {$deptCount} selected department(s).";
                            break;

                        case 'department_only':
                        default:
                            $targetDepartments = [$userDepartmentId];
                            $successMessage = 'Schedule deadline set successfully for your department.';
                            break;
                    }

                    if (empty($targetDepartments)) {
                        $errorMsg = 'No departments found for the selected scope.';
                        if ($isAjax) {
                            header('Content-Type: application/json');
                            echo json_encode(['success' => false, 'error' => $errorMsg]);
                            exit;
                        } else {
                            $_SESSION['error'] = $errorMsg;
                            header('Location: /director/schedule_deadline');
                            exit;
                        }
                    }

                    // Begin transaction for batch operations
                    $this->db->beginTransaction();

                    try {
                        // Deactivate existing active deadlines for target departments
                        $deactivateStmt = $this->db->prepare("
            UPDATE schedule_deadlines 
            SET is_active = 0 
            WHERE department_id IN (" . str_repeat('?,', count($targetDepartments) - 1) . "?) 
            AND is_active = 1
            ");
                        $deactivateStmt->execute($targetDepartments);

                        // Insert or update deadline for target departments with is_active = 1
                        $stmt = $this->db->prepare("
            INSERT INTO schedule_deadlines (user_id, department_id, deadline, created_at, is_active)
            VALUES (:user_id, :department_id, :deadline, NOW(), 1)
            ON DUPLICATE KEY UPDATE 
                deadline = VALUES(deadline), 
                created_at = NOW(),
                user_id = VALUES(user_id),
                is_active = VALUES(is_active)
            ");

                        $affectedDepartments = 0;
                        foreach ($targetDepartments as $deptId) {
                            $stmt->execute([
                                ':user_id' => $_SESSION['user_id'],
                                ':department_id' => $deptId,
                                ':deadline' => $deadlineDate->format('Y-m-d H:i:s')
                            ]);
                            $affectedDepartments++;
                        }

                        $this->db->commit();

                        error_log("setScheduleDeadline: Set deadline for $affectedDepartments departments (scope: $applyScope) to " . $deadlineDate->format('Y-m-d H:i:s'));

                        $finalMessage = $successMessage . " ({$affectedDepartments} departments affected)";

                        if ($isAjax) {
                            header('Content-Type: application/json');
                            echo json_encode([
                                'success' => true,
                                'message' => $finalMessage,
                                'affected_departments' => $affectedDepartments
                            ]);
                            exit;
                        } else {
                            $_SESSION['success'] = $finalMessage;
                            header('Location: /director/dashboard');
                            exit;
                        }
                    } catch (Exception $e) {
                        $this->db->rollback();
                        throw $e;
                    }
                } catch (Exception $e) {
                    $errorMsg = 'An error occurred while setting the deadline. Please try again.';
                    error_log("setScheduleDeadline: Error - " . $e->getMessage());

                    if ($isAjax) {
                        header('Content-Type: application/json');
                        echo json_encode(['success' => false, 'error' => $errorMsg]);
                        exit;
                    } else {
                        $_SESSION['error'] = $errorMsg;
                        header('Location: /director/schedule_deadline');
                        exit;
                    }
                }
            }

            // Fetch data for display
            if ($isSystemAdmin) {
                $deadlineStmt = $this->db->prepare("
                SELECT 
                    sd.department_id,
                    d.department_name,
                    c.college_name,
                    sd.deadline,
                    sd.user_id,
                    sd.created_at,
                    sd.is_active,
                    CONCAT(u.first_name, ' ', u.last_name) as set_by_name
                FROM schedule_deadlines sd
                INNER JOIN departments d ON sd.department_id = d.department_id
                INNER JOIN colleges c ON d.college_id = c.college_id
                LEFT JOIN users u ON sd.user_id = u.user_id
                ORDER BY c.college_name ASC, d.department_name ASC, sd.deadline DESC
            ");
                $deadlineStmt->execute();

                $allCollegesStmt = $this->db->prepare("
                SELECT college_id, college_name, 
                       (SELECT COUNT(*) FROM departments WHERE college_id = colleges.college_id) as department_count
                FROM colleges 
                ORDER BY college_name ASC
            ");
                $allCollegesStmt->execute();
                $allColleges = $allCollegesStmt->fetchAll(PDO::FETCH_ASSOC);

                $allDeptStmt = $this->db->prepare("
                SELECT d.department_id, d.department_name, c.college_id, c.college_name
                FROM departments d
                INNER JOIN colleges c ON d.college_id = c.college_id
                ORDER BY c.college_name ASC, d.department_name ASC
            ");
                $allDeptStmt->execute();
                $allDepartments = $allDeptStmt->fetchAll(PDO::FETCH_ASSOC);
            } else {
                $deadlineStmt = $this->db->prepare("
                SELECT 
                    sd.department_id,
                    d.department_name,
                    sd.deadline,
                    sd.user_id,
                    sd.created_at,
                    sd.is_active,
                    CONCAT(u.first_name, ' ', u.last_name) as set_by_name
                FROM schedule_deadlines sd
                INNER JOIN departments d ON sd.department_id = d.department_id
                LEFT JOIN users u ON sd.user_id = u.user_id
                WHERE d.college_id = :college_id 
                ORDER BY d.department_name ASC, sd.deadline DESC
            ");
                $deadlineStmt->execute([':college_id' => $collegeId]);

                $allDeptStmt = $this->db->prepare("
                SELECT department_id, department_name, college_id
                FROM departments 
                WHERE college_id = :college_id 
                ORDER BY department_name ASC
            ");
                $allDeptStmt->execute([':college_id' => $collegeId]);
                $allDepartments = $allDeptStmt->fetchAll(PDO::FETCH_ASSOC);

                $allColleges = null;
            }

            $deadlines = $deadlineStmt->fetchAll(PDO::FETCH_ASSOC);

            $collegeStmt = $this->db->prepare("
            SELECT college_name FROM colleges WHERE college_id = :college_id
        ");
            $collegeStmt->execute([':college_id' => $collegeId]);
            $collegeName = $collegeStmt->fetchColumn();

            $departmentsByCollege = [];
            foreach ($allDepartments as $dept) {
                $collegeKey = $dept['college_id'] ?? $collegeId;
                $departmentsByCollege[$collegeKey][] = $dept;
            }

            $data = [
                'user' => $userData,
                'current_semester' => $currentSemester,
                'title' => 'Set Schedule Deadline',
                'deadlines' => $deadlines,
                'all_departments' => $allDepartments,
                'departments_by_college' => $departmentsByCollege,
                'all_colleges' => $allColleges,
                'college_name' => $collegeName,
                'college_id' => $collegeId,
                'user_department_id' => $userDepartmentId,
                'is_system_admin' => $isSystemAdmin
            ];

            require_once __DIR__ . '/../views/director/schedule_deadline.php';
        } catch (PDOException $e) {
            if ($this->db->inTransaction()) {
                $this->db->rollback();
            }
            error_log("setScheduleDeadline: Database error - " . $e->getMessage());
            $_SESSION['error'] = 'A database error occurred. Please try again.';
            header('Location: /director/schedule_deadline');
            exit;
        } catch (Exception $e) {
            if ($this->db->inTransaction()) {
                $this->db->rollback();
            }
            error_log("setScheduleDeadline: General error - " . $e->getMessage());
            $_SESSION['error'] = 'An unexpected error occurred. Please try again.';
            header('Location: /director/schedule_deadline');
            exit;
        }
    }

    /**
     * Check if user has system admin role
     */
    private function checkSystemAdminRole($userId)
    {
        try {
            $stmt = $this->db->prepare("
            SELECT COUNT(*) 
            FROM users u
            INNER JOIN roles r ON u.role_id = r.role_id
            WHERE u.user_id = :user_id AND r.role_name = 'D.I'
        ");
            $stmt->execute([':user_id' => $userId]);
            return $stmt->fetchColumn() > 0;
        } catch (PDOException $e) {
            error_log("checkSystemAdminRole: Database error - " . $e->getMessage());
            return false;
        }
    }

    public function monitor()
    {
        try {
            $userData = $this->getUserData();
            if (!$userData) {
                error_log("monitor: Failed to load user data for user_id: " . $_SESSION['user_id']);
                header('Location: /login?error=User data not found');
                exit;
            }

            // Get current semester information
            $currentSemester = $this->userModel->getCurrentSemester();
            $currentSemesterDisplay = $currentSemester ?
                $currentSemester['semester_name'] . ' Semester, A.Y ' . $currentSemester['academic_year'] : 'Not Set';

            // Fetch activity log for all departments
            $activityStmt = $this->db->prepare("
            SELECT al.log_id, al.action_type, al.action_description, al.created_at, u.first_name, u.last_name,
                   d.department_name, col.college_name
            FROM activity_logs al
            JOIN users u ON al.user_id = u.user_id
            JOIN departments d ON al.department_id = d.department_id
            JOIN colleges col ON d.college_id = col.college_id
            ORDER BY al.created_at DESC
        ");
            $activityStmt->execute();
            $activities = $activityStmt->fetchAll(PDO::FETCH_ASSOC);

            $data = [
                'user' => $userData,
                'activities' => $activities,
                'title' => 'Activity Monitor - All Departments',
                'current_semester_display' => $currentSemesterDisplay,
                'current_semester' => $currentSemester
            ];

            require_once __DIR__ . '/../views/director/monitor.php';
        } catch (PDOException $e) {
            error_log("monitor: Database error - " . $e->getMessage());
            header('Location: /error?message=Database error');
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
                    header('Location: /director/profile');
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

                header('Location: /director/profile');
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

            require_once __DIR__ . '/../views/director/profile.php';
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
                'role_name' => 'Program director',
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
            require_once __DIR__ . '/../views/director/profile.php';
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
                error_log("profile: Failed to create upload directory: $uploadDir");
                return "Error: Failed to create upload directory.";
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
        if (!$this->authService->isLoggedIn()) {
            $_SESSION['flash'] = ['type' => 'error', 'message' => 'Please log in to view settings'];
            header('Location: /login');
            exit;
        }

        $userId = $_SESSION['user_id'];
        $csrfToken = $this->authService->generateCsrfToken();
        $errors = [];

        if ($_SERVER['REQUEST_METHOD'] === 'POST') {
            if (!$this->authService->verifyCsrfToken($_POST['csrf_token'] ?? '')) {
                $_SESSION['flash'] = ['type' => 'error', 'message' => 'Invalid CSRF token'];
                header('Location: /director/settings');
                exit;
            }

            $currentPassword = $_POST['current_password'] ?? '';
            $newPassword = $_POST['new_password'] ?? '';
            $confirmPassword = $_POST['confirm_password'] ?? '';

            if (empty($currentPassword) || empty($newPassword) || empty($confirmPassword)) {
                $errors[] = 'All password fields are required.';
            } else {
                if ($newPassword !== $confirmPassword) {
                    $errors[] = 'New password and confirmation do not match.';
                }

                if (strlen($newPassword) < 8) {
                    $errors[] = 'New password must be at least 8 characters long.';
                }

                // Fetch current password hash
                $stmt = $this->db->prepare("SELECT password_hash FROM users WHERE user_id = :user_id");
                $stmt->execute([':user_id' => $userId]);
                $currentHash = $stmt->fetchColumn();

                if (!password_verify($currentPassword, $currentHash)) {
                    $errors[] = 'Current password is incorrect.';
                }
            }

            if (empty($errors)) {
                $newHash = password_hash($newPassword, PASSWORD_BCRYPT);
                $updateStmt = $this->db->prepare("UPDATE users SET password_hash = :password_hash, updated_at = NOW() WHERE user_id = :user_id");
                if ($updateStmt->execute([':password_hash' => $newHash, ':user_id' => $userId])) {
                    $_SESSION['flash'] = ['type' => 'success', 'message' => 'Password updated successfully'];
                    header('Location: /director/settings');
                    exit;
                } else {
                    error_log("settings: Failed to update password for user_id: $userId");
                    $errors[] = 'Failed to update password. Please try again.';
                }
            }
        }

        // Render the settings view
        require_once __DIR__ . '/../views/director/settings.php';
    }
}
