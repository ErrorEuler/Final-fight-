<?php
// File: controllers/FacultyController.php
require_once __DIR__ . '/../config/Database.php';
require_once __DIR__ . '/../services/AuthService.php';
require_once __DIR__ . '/../services/SchedulingService.php';

class FacultyController
{
    private $db;
    private $authService;
    private $schedulingService;

    public function __construct()
    {
        error_log("FacultyController instantiated");
        $this->db = (new Database())->connect();
        if ($this->db === null) {
            error_log("Failed to connect to the database in FacultyController");
            die("Database connection failed. Please try again later.");
        }
        $this->db->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
        $this->authService = new AuthService($this->db);
        $this->schedulingService = new SchedulingService($this->db);
    }

    private function restrictToFaculty()
    {
        error_log("restrictToFaculty: Checking session - user_id: " . ($_SESSION['user_id'] ?? 'none') . ", role_id: " . ($_SESSION['role_id'] ?? 'none'));
        if (!isset($_SESSION['user_id']) || !isset($_SESSION['role_id']) || $_SESSION['role_id'] != 6) {
            error_log("restrictToFaculty: Redirecting to login due to unauthorized access");
            header('Location: /login?error=Unauthorized access');
            exit;
        }
    }

    private function getFacultyId($userId)
    {
        $stmt = $this->db->prepare("SELECT faculty_id FROM faculty WHERE user_id = :user_id");
        $stmt->execute([':user_id' => $userId]);
        return $stmt->fetchColumn();
    }

    public function dashboard()
    {
        try {
            $userId = $_SESSION['user_id'];
            error_log("dashboard: Starting dashboard method for user_id: $userId");

            $facultyId = $this->getFacultyId($userId);
            if (!$facultyId) {
                error_log("dashboard: No faculty profile found for user_id: $userId");
                $error = "No faculty profile found for this user.";
                require_once __DIR__ . '/../views/faculty/dashboard.php';
                return;
            }

            // Get current semester
            $currentSemesterStmt = $this->db->query("SELECT semester_name, academic_year FROM semesters WHERE is_current = 1 LIMIT 1");
            $currentSemester = $currentSemesterStmt->fetch(PDO::FETCH_ASSOC);
            $semesterInfo = $currentSemester ? "{$currentSemester['semester_name']} Semester A.Y {$currentSemester['academic_year']}" : '2nd Semester 2024-2025';

            $deptStmt = $this->db->prepare("SELECT d.department_name FROM departments d JOIN users u ON d.department_id = u.department_id WHERE u.user_id = :user_id");
            $deptStmt->execute([':user_id' => $userId]);
            $departmentName = $deptStmt->fetchColumn();

            $teachingLoadStmt = $this->db->prepare("SELECT COUNT(*) FROM schedules s WHERE s.faculty_id = :faculty_id");
            $teachingLoadStmt->execute([':faculty_id' => $facultyId]);
            $teachingLoad = $teachingLoadStmt->fetchColumn();

            $pendingRequestsStmt = $this->db->prepare("SELECT COUNT(*) FROM schedule_requests sr WHERE sr.faculty_id = :faculty_id AND sr.status = 'pending'");
            $pendingRequestsStmt->execute([':faculty_id' => $facultyId]);
            $pendingRequests = $pendingRequestsStmt->fetchColumn();

            $recentSchedulesStmt = $this->db->prepare("
                  SELECT s.schedule_id, c.course_code, c.course_name, r.room_name, s.day_of_week, s.start_time, s.end_time, s.schedule_type
                  FROM schedules s
                  JOIN courses c ON s.course_id = c.course_id
                  LEFT JOIN classrooms r ON s.room_id = r.room_id
                  WHERE s.faculty_id = :faculty_id
                  ORDER BY s.created_at DESC
                  LIMIT 5
              ");
            $recentSchedulesStmt->execute([':faculty_id' => $facultyId]);
            $recentSchedules = $recentSchedulesStmt->fetchAll(PDO::FETCH_ASSOC);
            error_log("dashboard: Fetched " . count($recentSchedules) . " recent schedules for faculty_id $facultyId");

            $scheduleDistStmt = $this->db->prepare("
                  SELECT s.day_of_week, COUNT(*) as count 
                  FROM schedules s 
                  WHERE s.faculty_id = :faculty_id 
                  GROUP BY s.day_of_week
              ");
            $scheduleDistStmt->execute([':faculty_id' => $facultyId]);
            $scheduleDistData = $scheduleDistStmt->fetchAll(PDO::FETCH_ASSOC);

            $days = ['Monday', 'Tuesday', 'Wednesday', 'Thursday', 'Friday', 'Saturday'];
            $scheduleDist = array_fill_keys($days, 0);
            foreach ($scheduleDistData as $row) {
                $scheduleDist[$row['day_of_week']] = (int)$row['count'];
            }
            $scheduleDistJson = json_encode(array_values($scheduleDist));

            // Pass variables to the view instead of a single $content string
            require_once __DIR__ . '/../views/faculty/dashboard.php';
        } catch (Exception $e) {
            error_log("dashboard: Full error: " . $e->getMessage());
            http_response_code(500);
            echo "Error loading dashboard: " . htmlspecialchars($e->getMessage());
            exit;
        }
    }

    /**
     * Display Faculty's teaching schedule
     */
    public function mySchedule()
    {
        try {
            $userId = $_SESSION['user_id'];
            error_log("mySchedule: Starting mySchedule method for user_id: $userId");

            // Handle download requests
            if (isset($_GET['action']) && $_GET['action'] === 'download') {
                $this->handleDownload($userId);
                return;
            }

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
                require_once __DIR__ . '/../views/faculty/my_schedule.php';
                return;
            }

            $facultyId = $faculty['faculty_id'];
            $facultyName = trim($faculty['faculty_name']);
            $facultyPosition = $faculty['academic_rank'] ?? 'Not Specified';
            $employmentType = $faculty['employment_type'] ?? 'Regular';

            // Get department and college details from department_instructors table
            $deptStmt = $this->db->prepare("
                SELECT d.department_name, c.college_name 
                FROM department_instructors dn 
                JOIN departments d ON dn.department_id = d.department_id 
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
                require_once __DIR__ . '/../views/faculty/my_schedule.php';
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

            require_once __DIR__ . '/../views/faculty/my_schedule.php';
        } catch (Exception $e) {
            error_log("mySchedule: Full error: " . $e->getMessage());
            http_response_code(500);
            echo "Error loading schedule: " . htmlspecialchars($e->getMessage());
            exit;
        }
    }

    private function handleDownload($chairId)
    {
        $format = $_GET['format'] ?? 'pdf';

        // Fetch all necessary data for download
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
        $facultyStmt->execute([$chairId]);
        $faculty = $facultyStmt->fetch(PDO::FETCH_ASSOC);

        if (!$faculty) {
            http_response_code(404);
            echo "No faculty profile found.";
            exit;
        }

        $facultyId = $faculty['faculty_id'];
        $facultyName = trim($faculty['faculty_name']);

        // Get department and college details
        $deptStmt = $this->db->prepare("
        SELECT d.department_name, c.college_name 
        FROM faculty f
        JOIN users u ON f.user_id = u.user_id 
        JOIN departments d ON u.department_id = d.department_id 
        JOIN colleges c ON d.college_id = c.college_id 
        WHERE f.user_id = ? 
        ");
        $deptStmt->execute([$chairId]);
        $department = $deptStmt->fetch(PDO::FETCH_ASSOC);
        $departmentName = $department['department_name'] ?? 'Not Assigned';
        $collegeName = $department['college_name'] ?? 'Not Assigned';

        // Get current semester
        $semesterStmt = $this->db->query("SELECT semester_id, semester_name, academic_year FROM semesters WHERE is_current = 1");
        $semester = $semesterStmt->fetch(PDO::FETCH_ASSOC);

        if (!$semester) {
            http_response_code(404);
            echo "No current semester defined.";
            exit;
        }

        $semesterId = $semester['semester_id'];
        $semesterName = $semester['semester_name'] . ' Semester, A.Y ' . $semester['academic_year'];

        // Fetch schedules (same logic as your existing method)
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

        // Group schedules (same logic as your existing method)
        $groupedSchedules = [];
        foreach ($rawSchedules as $schedule) {
            $key = $schedule['course_code'] . '|' . $schedule['start_time'] . '|' . $schedule['end_time'] . '|' . $schedule['schedule_type'] . '|' . $schedule['section_name'] . '|' . $schedule['student_count'];

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

        // Faculty data
        $facultyData = [
            'faculty_id' => $facultyId,
            'faculty_name' => $facultyName,
            'academic_rank' => $faculty['academic_rank'] ?? 'Not specified',
            'employment_type' => $faculty['employment_type'] ?? 'Regular',
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

        // Generate download based on format
        if ($format === 'pdf') {
            $this->schedulingService->generateOfficialPDFFaculty($schedules, $semesterName, $collegeName, $facultyData, $facultyName);
        } elseif ($format === 'excel') {
            $this->schedulingService->generateOfficialExcelFaculty($schedules, $semesterName, $collegeName, $facultyData, $facultyName);
        }
    }
    /**
     * Submit a schedule request
     */
    public function submitScheduleRequest()
    {
        error_log("submitScheduleRequest: Starting submitScheduleRequest method");
        $userId = $_SESSION['user_id'];
        $facultyId = $this->getFacultyId($userId);

        if (!$facultyId) {
            error_log("submitScheduleRequest: No faculty profile found for user_id: $userId");
            $error = "No faculty profile found for this user.";
            require_once __DIR__ . '/../views/faculty/schedule_request.php';
            return;
        }

        if ($_SERVER['REQUEST_METHOD'] === 'POST') {
            try {
                $data = [
                    'faculty_id' => $facultyId,
                    'course_id' => intval($_POST['course_id'] ?? 0),
                    'preferred_day' => $_POST['preferred_day'] ?? '',
                    'preferred_start_time' => $_POST['preferred_start_time'] ?? '',
                    'preferred_end_time' => $_POST['preferred_end_time'] ?? '',
                    'room_preference' => $_POST['room_preference'] ?? '',
                    'schedule_type' => $_POST['schedule_type'] ?? 'F2F',
                    'semester_id' => intval($_POST['semester_id'] ?? 0),
                    'reason' => trim($_POST['reason'] ?? '')
                ];

                error_log("submitScheduleRequest: POST data - " . json_encode($data));

                $errors = [];
                if ($data['course_id'] < 1) {
                    $errors[] = "Course is required.";
                }
                if (!in_array($data['preferred_day'], ['Monday', 'Tuesday', 'Wednesday', 'Thursday', 'Friday', 'Saturday'])) {
                    $errors[] = "Invalid preferred day.";
                }
                if (!preg_match('/^\d{2}:\d{2}$/', $data['preferred_start_time']) || !preg_match('/^\d{2}:\d{2}$/', $data['preferred_end_time'])) {
                    $errors[] = "Invalid time format.";
                }
                if ($data['semester_id'] < 1) {
                    $errors[] = "Semester is required.";
                }
                if (empty($data['reason'])) {
                    $errors[] = "Reason for request is required.";
                }
                if (!in_array($data['schedule_type'], ['F2F', 'Online', 'Hybrid', 'Asynchronous'])) {
                    $errors[] = "Invalid schedule type.";
                }

                if (empty($errors)) {
                    $stmt = $this->db->prepare("
                          INSERT INTO schedule_requests (faculty_id, course_id, preferred_day, preferred_start_time, preferred_end_time, room_preference, schedule_type, semester_id, reason, status, created_at)
                          VALUES (:faculty_id, :course_id, :preferred_day, :preferred_start_time, :preferred_end_time, :room_preference, :schedule_type, :semester_id, :reason, 'pending', NOW())
                      ");
                    $stmt->execute($data);

                    error_log("submitScheduleRequest: Schedule request submitted successfully");
                    header('Location: /faculty/schedule/requests?success=Schedule request submitted successfully');
                    exit;
                } else {
                    error_log("submitScheduleRequest: Validation errors - " . implode(", ", $errors));
                    $error = implode("<br>", $errors);
                }
            } catch (Exception $e) {
                error_log("submitScheduleRequest: Error - " . $e->getMessage());
                $error = $e->getMessage();
            }
        }

        try {
            $coursesStmt = $this->db->prepare("SELECT c.course_id, c.course_code, c.course_name 
                                                 FROM courses c 
                                                 JOIN users u ON c.department_id = u.department_id 
                                                 WHERE u.user_id = :user_id");
            $coursesStmt->execute([':user_id' => $userId]);
            $courses = $coursesStmt->fetchAll(PDO::FETCH_ASSOC);

            $semesters = $this->db->query("SELECT semester_id, CONCAT(semester_name, ' ', academic_year) AS semester_name FROM semesters")->fetchAll(PDO::FETCH_ASSOC);

            require_once __DIR__ . '/../views/faculty/schedule_request.php';
        } catch (PDOException $e) {
            error_log("submitScheduleRequest: Error loading form data - " . $e->getMessage());
            $error = "Failed to load form data.";
            require_once __DIR__ . '/../views/faculty/schedule_request.php';
        }
    }

    /**
     * View schedule requests
     */
    public function getScheduleRequests()
    {
        error_log("getScheduleRequests: Starting getScheduleRequests method");
        try {
            $userId = $_SESSION['user_id'];
            $facultyId = $this->getFacultyId($userId);
            if (!$facultyId) {
                error_log("getScheduleRequests: No faculty profile found for user_id: $userId");
                $error = "No faculty profile found for this user.";
                require_once __DIR__ . '/../views/faculty/schedule_requests.php';
                return;
            }

            $requestsStmt = $this->db->prepare("
                  SELECT sr.request_id, c.course_code, sr.preferred_day, sr.preferred_start_time, sr.preferred_end_time, 
                         sr.room_preference, sr.schedule_type, sr.status, sr.reason, s.semester_name
                  FROM schedule_requests sr
                  JOIN courses c ON sr.course_id = c.course_id
                  JOIN semesters s ON sr.semester_id = s.semester_id
                  WHERE sr.faculty_id = :faculty_id
                  ORDER BY sr.created_at DESC
              ");
            $requestsStmt->execute([':faculty_id' => $facultyId]);
            $requests = $requestsStmt->fetchAll(PDO::FETCH_ASSOC);

            require_once __DIR__ . '/../views/faculty/schedule_requests.php';
        } catch (Exception $e) {
            error_log("getScheduleRequests: Error - " . $e->getMessage());
            $error = "Failed to load schedule requests.";
            require_once __DIR__ . '/../views/faculty/schedule_requests.php';
        }
    }

    /**
     * View/edit profile
     */
    public function searchCourses()
    {
        try {
            if (!$this->authService->isLoggedIn()) {
                http_response_code(401);
                echo json_encode(['error' => 'Unauthorized']);
                exit;
            }

            $query = trim($_GET['query'] ?? '');
            if (strlen($query) < 2) {
                http_response_code(400);
                echo json_encode(['error' => 'Query must be at least 2 characters']);
                exit;
            }

            // Use positional parameters (?) instead
            $stmt = $this->db->prepare("
            SELECT c.course_id, c.course_code, c.course_name, d.department_name, co.college_name
            FROM courses c
            JOIN departments d ON c.department_id = d.department_id
            JOIN colleges co ON d.college_id = co.college_id
            WHERE UPPER(c.course_code) LIKE UPPER(?) OR UPPER(c.course_name) LIKE UPPER(?)
            LIMIT 10
        ");

            $searchTerm = "%" . strtoupper($query) . "%";
            error_log("searchCourses: Preparing query with positional parameters");
            error_log("searchCourses: Search term = $searchTerm");

            // Execute with array of parameters
            $stmt->execute([$searchTerm, $searchTerm]);
            $courses = $stmt->fetchAll(PDO::FETCH_ASSOC);

            error_log("searchCourses: Query executed successfully, found " . count($courses) . " results");
            header('Content-Type: application/json');
            echo json_encode($courses);
        } catch (PDOException $e) {
            http_response_code(500);
            error_log("searchCourses: PDO Error - SQLSTATE[" . $e->getCode() . "]: " . $e->getMessage());
            error_log("searchCourses: Query: " . (isset($stmt) ? $stmt->queryString : 'Query not prepared'));
            error_log("searchCourses: Search term: " . (isset($searchTerm) ? $searchTerm : 'Not set'));
            echo json_encode(['error' => 'An error occurred while fetching courses: ' . $e->getMessage()]);
        } catch (Exception $e) {
            http_response_code(500);
            error_log("searchCourses: General Error - " . $e->getMessage());
            echo json_encode(['error' => 'An error occurred while fetching courses']);
        }
        exit;
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
                    header('Location: /faculty/profile');
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
                    'doctorate_degree' => trim($_POST['doctorate_degree'] ?? ''),
                    'post_doctorate_degree' => trim($_POST['post_doctorate_degree'] ?? ''),
                    'advisory_class' => trim($_POST['advisory_class'] ?? ''),
                    'designation' => trim($_POST['designation'] ?? ''),
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
                            $errors[] = $profilePictureResult;
                        } else {
                            $profilePicturePath = $profilePictureResult;
                        }
                    }

                    // Handle user profile updates only if fields are provided or profile picture uploaded
                    if (
                        !empty($data['email']) || !empty($data['first_name']) || !empty($data['last_name']) ||
                        !empty($data['phone']) || !empty($data['username']) || !empty($data['suffix']) ||
                        !empty($data['title']) || $profilePicturePath
                    ) {
                        if (!empty($data['email']) && !filter_var($data['email'], FILTER_VALIDATE_EMAIL)) {
                            $errors[] = 'Valid email is required.';
                        }
                        if (!empty($data['phone']) && !preg_match('/^\d{10,12}$/', $data['phone'])) {
                            $errors[] = 'Phone number must be 10-12 digits.';
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
                                    if (!empty($data['course_id'])) {
                                        // Check if specialization already exists
                                        $checkStmt = $this->db->prepare("SELECT COUNT(*) FROM specializations WHERE faculty_id = :faculty_id AND course_id = :course_id");
                                        $checkStmt->execute([':faculty_id' => $facultyId, ':course_id' => $data['course_id']]);
                                        $exists = $checkStmt->fetchColumn();

                                        if ($exists > 0) {
                                            $errors[] = 'You already have this specialization.';
                                            break;
                                        }

                                        $insertSpecializationStmt = $this->db->prepare("
                                        INSERT INTO specializations (faculty_id, course_id, created_at)
                                        VALUES (:faculty_id, :course_id, NOW())
                                    ");
                                        $specializationParams = [
                                            ':faculty_id' => $facultyId,
                                            ':course_id' => $data['course_id'],
                                        ];
                                        error_log("profile: Add specialization query - " . $insertSpecializationStmt->queryString . ", Params: " . print_r($specializationParams, true));

                                        if (!$insertSpecializationStmt->execute($specializationParams)) {
                                            $errorInfo = $insertSpecializationStmt->errorInfo();
                                            error_log("profile: Add specialization failed - " . print_r($errorInfo, true));
                                            throw new Exception("Failed to add specialization");
                                        }
                                        error_log("profile: Successfully added specialization");
                                    } else {
                                        $errors[] = 'Course is required to add specialization.';
                                    }
                                    break;

                                case 'remove_specialization':
                                    if (!empty($data['course_id'])) {
                                        error_log("profile: Attempting to remove specialization with course_id: " . $data['course_id'] . ", faculty_id: $facultyId");

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

                header('Location: /faculty/profile');
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
                   (SELECT COUNT(*) FROM faculty f2 JOIN users fu ON f2.user_id = fu.user_id WHERE fu.department_id = u.department_id) as facultyCount,
                   (SELECT COUNT(DISTINCT sch.course_id) FROM schedules sch WHERE sch.faculty_id = f.faculty_id) as coursesCount,
                   (SELECT COUNT(*) FROM specializations s2 WHERE s2.faculty_id = f.faculty_id) as specializationsCount,
                   (SELECT COUNT(*) FROM faculty_requests fr WHERE fr.department_id = u.department_id AND fr.status = 'pending') as pendingApplicantsCount,
                   (SELECT semester_name FROM semesters WHERE is_current = 1) as currentSemester,
                   (SELECT created_at FROM auth_logs WHERE user_id = u.user_id AND action = 'login_success' ORDER BY created_at DESC LIMIT 1) as lastLogin
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

            // Extract stats
            $facultyCount = $user['facultyCount'] ?? 0;
            $coursesCount = $user['coursesCount'] ?? 0;
            $specializationsCount = $user['specializationsCount'] ?? 0;
            $pendingApplicantsCount = $user['pendingApplicantsCount'] ?? 0;
            $currentSemester = $user['currentSemester'] ?? '2nd';
            $lastLogin = $user['lastLogin'] ?? 'N/A';

            require_once __DIR__ . '/../views/faculty/profile.php';
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
                'role_name' => 'Faculty',
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
            require_once __DIR__ . '/../views/faculty/profile.php';
        }
    }

    private function handleProfilePictureUpload($userId)
    {
        if (!isset($_FILES['profile_picture']) || $_FILES['profile_picture']['error'] == UPLOAD_ERR_NO_FILE) {
            return null;
        }

        $file = $_FILES['profile_picture'];
        $allowedTypes = ['image/jpeg', 'image/png'];
        $maxSize = 2 * 1024 * 1024; // 2MB

        if (!in_array($file['type'], $allowedTypes)) {
            error_log("profile: Invalid file type for user_id: $userId - " . $file['type']);
            return "Error: Only JPEG and PNG files are allowed.";
        }

        if ($file['size'] > $maxSize) {
            error_log("profile: File size exceeds limit for user_id: $userId - " . $file['size']);
            return "Error: File size exceeds 2MB limit.";
        }

        $ext = pathinfo($file['name'], PATHINFO_EXTENSION);
        $filename = "user_{$userId}_" . time() . ".{$ext}";
        $uploadDir = $_SERVER['DOCUMENT_ROOT'] . '/uploads/profile_pictures/';
        $uploadPath = $uploadDir . $filename;

        if (!is_dir($uploadDir)) {
            if (!mkdir($uploadDir, 0755, true)) {
                error_log("profile: Failed to create upload facultyy: $uploadDir");
                return "Error: Failed to create upload facultyy.";
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
            return "/uploads/profile_pictures/{$filename}";
        } else {
            error_log("profile: Failed to move uploaded file for user_id: $userId to $uploadPath");
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
                header('Location: /faculty/settings');
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
                    header('Location: /faculty/settings');
                    exit;
                } else {
                    error_log("settings: Failed to update password for user_id: $userId");
                    $errors[] = 'Failed to update password. Please try again.';
                }
            }
        }

        // Render the settings view
        require_once __DIR__ . '/../views/faculty/settings.php';
    }

}