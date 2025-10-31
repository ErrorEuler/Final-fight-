<?php
require_once __DIR__ . '/../config/Database.php';
require_once __DIR__ . '/../../vendor/autoload.php'; // For TCPDF or LaTeX rendering

use setasign\Fpdi\Tcpdf\Fpdi;

class PublicController
{
    private $db;

    public function __construct()
    {
        error_log("Public Controller instantiated");
        $this->db = (new Database())->connect();
        if ($this->db === null) {
            error_log("Failed to connect to the database in Public Controller");
            die("Database connection failed. Please try again later.");
        }
        $this->db->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
    }

    public function showHomepage()
    {
        $colleges = $this->fetchColleges();
        $departments = $this->fetchDepartments();
        $programs = $this->fetchPrograms();
        $currentSemester = $this->getCurrentSemester();

        require_once __DIR__ . '/../views/public/home.php';
    }

    private function fetchColleges()
    {
        $query = "SELECT college_id, college_name FROM colleges ORDER BY college_name";
        $stmt = $this->db->prepare($query);
        $stmt->execute();
        return $stmt->fetchAll(PDO::FETCH_ASSOC);
    }

    private function fetchDepartments()
    {
        $query = "SELECT department_id, department_name, college_id FROM departments WHERE college_id IS NOT NULL ORDER BY department_name";
        $stmt = $this->db->prepare($query);
        $stmt->execute();
        return $stmt->fetchAll(PDO::FETCH_ASSOC);
    }

    private function fetchPrograms()
    {
        $query = "SELECT program_id, program_name, department_id FROM programs ORDER BY program_name";
        $stmt = $this->db->prepare($query);
        $stmt->execute();
        return $stmt->fetchAll(PDO::FETCH_ASSOC);
    }

    private function fetchSemesters()
    {
        $query = "SELECT semester_id, semester_name, academic_year FROM semesters ORDER BY year_start DESC, semester_name";
        $stmt = $this->db->prepare($query);
        $stmt->execute();
        return $stmt->fetchAll(PDO::FETCH_ASSOC);
    }

    public function getDepartmentsByCollege()
    {
        try {
            $college_id = isset($_POST['college_id']) ? (int)$_POST['college_id'] : 0;

            if ($college_id === 0) {
                header('Content-Type: application/json');
                echo json_encode([]);
                exit;
            }

            $stmt = $this->db->prepare("
                SELECT department_id, department_name 
                FROM departments 
                WHERE college_id = :college_id 
                ORDER BY department_name
            ");

            $stmt->execute([':college_id' => $college_id]);
            $departments = $stmt->fetchAll(PDO::FETCH_ASSOC);

            header('Content-Type: application/json');
            echo json_encode($departments);
        } catch (PDOException $e) {
            error_log("Get Departments Error: " . $e->getMessage());
            header('Content-Type: application/json');
            echo json_encode(['error' => 'Failed to fetch departments']);
        }
        exit;
    }

    public function getSectionsByDepartment()
    {
        try {
            $department_id = isset($_POST['department_id']) ? (int)$_POST['department_id'] : 0;

            if ($department_id === 0) {
                header('Content-Type: application/json');
                echo json_encode([]);
                exit;
            }

            $currentSemester = $this->getCurrentSemester();
            $semester_id = $currentSemester['semester_id'];

            $stmt = $this->db->prepare("
                SELECT DISTINCT s.section_id, s.section_name, s.year_level 
                FROM sections s
                JOIN schedules sch ON s.section_id = sch.section_id
                WHERE s.department_id = :department_id 
                AND sch.semester_id = :semester_id
                ORDER BY s.year_level, s.section_name
            ");

            $stmt->execute([
                ':department_id' => $department_id,
                ':semester_id' => $semester_id
            ]);
            $sections = $stmt->fetchAll(PDO::FETCH_ASSOC);

            header('Content-Type: application/json');
            echo json_encode($sections);
        } catch (PDOException $e) {
            error_log("Get Sections Error: " . $e->getMessage());
            header('Content-Type: application/json');
            echo json_encode(['error' => 'Failed to fetch sections']);
        }
        exit;
    }

    public function searchSchedules()
    {
        $currentSemester = $this->getCurrentSemester();

        $college_id = isset($_POST['college_id']) ? (int)$_POST['college_id'] : 0;
        $semester_id = isset($_POST['semester_id']) ? (int)$_POST['semester_id'] : $currentSemester['semester_id'];
        $department_id = isset($_POST['department_id']) ? (int)$_POST['department_id'] : 0;
        $year_level = isset($_POST['year_level']) ? trim($_POST['year_level']) : '';
        $section_id = isset($_POST['section_id']) ? (int)$_POST['section_id'] : 0;
        $search = isset($_POST['search']) ? trim($_POST['search']) : '';

        $query = "
        SELECT 
            s.schedule_id, 
            c.course_code, 
            c.course_name, 
            sec.section_name,
            sec.year_level,
            r.room_name, 
            r.building, 
            s.day_of_week, 
            s.start_time, 
            s.end_time, 
            s.schedule_type, 
            TRIM(CONCAT(COALESCE(u.title, ''), ' ', u.first_name, ' ', u.last_name)) AS instructor_name,  -- FIXED: COALESCE + TRIM for null titles
            d.department_name,
            col.college_name
        FROM schedules s
        JOIN courses c ON s.course_id = c.course_id
        JOIN sections sec ON s.section_id = sec.section_id
        JOIN semesters sem ON s.semester_id = sem.semester_id
        LEFT JOIN classrooms r ON s.room_id = r.room_id
        JOIN faculty f ON s.faculty_id = f.faculty_id
        JOIN users u ON f.user_id = u.user_id
        JOIN departments d ON sec.department_id = d.department_id
        JOIN colleges col ON d.college_id = col.college_id
        WHERE s.is_public = 1
        AND sem.semester_id = ?
        AND (? = 0 OR col.college_id = ?)
        AND (? = 0 OR d.department_id = ?)
        AND (? = '' OR sec.year_level = ?)
        AND (? = 0 OR sec.section_id = ?)
        AND (c.course_code LIKE ? OR c.course_name LIKE ? OR CONCAT(u.first_name, ' ', u.last_name) LIKE ?)
        ORDER BY s.day_of_week, s.start_time
    ";

        try {
            $stmt = $this->db->prepare($query);
            $searchPattern = '%' . $search . '%';

            $stmt->execute([
                $semester_id,
                $college_id,
                $college_id,
                $department_id,
                $department_id,
                $year_level,
                $year_level,
                $section_id,
                $section_id,
                $searchPattern,
                $searchPattern,
                $searchPattern
            ]);

            $schedules = $stmt->fetchAll(PDO::FETCH_ASSOC);

            // UPDATED: Log with filters (helps debug why only Monday)
            $dayCounts = [];
            foreach ($schedules as $sch) {
                $day = $sch['day_of_week'];
                $dayCounts[$day] = ($dayCounts[$day] ?? 0) + 1;
            }
            error_log("SearchSchedules DEBUG: Total: " . count($schedules) . ", Filters: college=$college_id, dept=$department_id, year='$year_level', section=$section_id, search='$search' | By Day: " . json_encode($dayCounts));

            $total = count($schedules);
            $perPage = 10;
            $page = isset($_POST['page']) ? (int)$_POST['page'] : 1;
            $offset = ($page - 1) * $perPage;
            $pagedSchedules = array_slice($schedules, $offset, $perPage);

            header('Content-Type: application/json');
            echo json_encode([
                'schedules' => $pagedSchedules,
                'total' => $total,
                'page' => $page,
                'per_page' => $perPage,
                'debug_days' => $dayCounts  // For JS console
            ]);
        } catch (PDOException $e) {
            error_log("Search Schedules Error: " . $e->getMessage());
            header('Content-Type: application/json');
            echo json_encode(['error' => 'An error occurred while fetching schedules.']);
        }
        exit;
    }

    private function getCurrentSemester()
    {
        $query = "SELECT semester_id, semester_name, academic_year
            FROM semesters
            WHERE is_current = 1
            LIMIT 1";
        $stmt = $this->db->prepare($query);
        $stmt->execute();
        return $stmt->fetch(PDO::FETCH_ASSOC) ?: [];
    }

    public function downloadSchedulePDF()
    {
        $college_id = isset($_POST['college_id']) ? (int)$_POST['college_id'] : 0;
        $department_id = isset($_POST['department_id']) ? (int)$_POST['department_id'] : 0;
        $program_id = isset($_POST['program_id']) ? (int)$_POST['program_id'] : 0;
        $year_level = isset($_POST['year_level']) ? $_POST['year_level'] : '';
        $semester_id = isset($_POST['semester_id']) ? (int)$_POST['semester_id'] : 0;

        $query = "
            SELECT 
                s.schedule_id, 
                c.course_code, 
                c.course_name, 
                sec.section_name, 
                r.room_name, 
                r.building, 
                s.day_of_week, 
                s.start_time, 
                s.end_time, 
                s.schedule_type, 
                CONCAT(u.first_name, ' ', u.last_name) AS instructor_name,
                sem.semester_name, 
                sem.academic_year,
                col.college_name,
                d.department_name,
                p.program_name
            FROM schedules s
            JOIN courses c ON s.course_id = c.course_id
            JOIN sections sec ON s.section_id = sec.section_id
            JOIN semesters sem ON s.semester_id = sem.semester_id
            LEFT JOIN classrooms r ON s.room_id = r.room_id
            JOIN faculty f ON s.faculty_id = f.faculty_id
            JOIN users u ON f.user_id = u.user_id
            JOIN departments d ON sec.department_id = d.department_id
            JOIN colleges col ON d.college_id = col.college_id
            JOIN curriculum_courses cc ON c.course_id = cc.course_id
            JOIN curriculum_programs cp ON cc.curriculum_id = cp.curriculum_id
            JOIN programs p ON cp.program_id = p.program_id
            WHERE s.is_public = 1
            AND (col.college_id = :college_id OR :college_id = 0)
            AND (d.department_id = :department_id OR :department_id = 0)
            AND (cp.program_id = :program_id OR :program_id = 0)
            AND (sec.year_level = :year_level OR :year_level = '')
            AND (s.semester_id = :semester_id OR :semester_id = 0)
            ORDER BY s.day_of_week, s.start_time
        ";

        try {
            $stmt = $this->db->prepare($query);
            $stmt->execute([
                ':college_id' => $college_id,
                ':department_id' => $department_id,
                ':program_id' => $program_id,
                ':year_level' => $year_level,
                ':semester_id' => $semester_id
            ]);
            $schedules = $stmt->fetchAll(PDO::FETCH_ASSOC);

            if (empty($schedules)) {
                header('Content-Type: application/json');
                echo json_encode(['error' => 'No schedules found to generate PDF.']);
                exit;
            }

            // Create new PDF document
            $pdf = new \TCPDF('L', 'mm', 'A4', true, 'UTF-8', false);

            $pdf->SetCreator('PRMSU University');
            $pdf->SetAuthor('PRMSU University');
            $pdf->SetTitle('Class Schedule');
            $pdf->SetSubject('Class Schedule');

            $pdf->AddPage();

            $pdf->setHeaderFont(array('helvetica', '', 10));
            $pdf->setFooterFont(array('helvetica', '', 8));

            $pdf->SetMargins(15, 25, 15);
            $pdf->SetHeaderMargin(10);
            $pdf->SetFooterMargin(10);

            $pdf->SetAutoPageBreak(true, 25);

            $pdf->setHeaderData('', 0, 'PRMSU University', 'Class Schedule');

            $pdf->SetFont('helvetica', 'B', 12);
            $pdf->Cell(0, 10, 'Class Schedule', 0, 1, 'C');
            $pdf->SetFont('helvetica', '', 10);
            $pdf->Cell(0, 6, ($semester_id ? $schedules[0]['semester_name'] : 'All Semesters') . ' ' . ($semester_id ? $schedules[0]['academic_year'] : ''), 0, 1, 'C');
            $pdf->Cell(0, 6, 'College: ' . ($college_id ? $schedules[0]['college_name'] : 'All') . ' | Department: ' . ($department_id ? $schedules[0]['department_name'] : 'All') . ' | Program: ' . ($program_id ? $schedules[0]['program_name'] : 'All') . ' | Year Level: ' . ($year_level ?: 'All'), 0, 1, 'C');
            $pdf->Ln(5);

            $headers = ['Course Code', 'Course Name', 'Section', 'Instructor', 'Room', 'Day', 'Time', 'Type'];
            $columnWidths = [25, 40, 20, 35, 30, 20, 25, 20];

            $pdf->SetFont('helvetica', 'B', 8);
            foreach ($headers as $key => $header) {
                $pdf->Cell($columnWidths[$key], 7, $header, 1, 0, 'C');
            }
            $pdf->Ln();

            $pdf->SetFont('helvetica', '', 8);
            foreach ($schedules as $schedule) {
                $room = $schedule['room_name'] ? htmlspecialchars($schedule['room_name'] . ', ' . htmlspecialchars($schedule['building'])) : 'TBD';
                $time = date('h:i A', strtotime($schedule['start_time'])) . ' - ' . date('h:i A', strtotime($schedule['end_time']));

                $pdf->Cell($columnWidths[0], 6, htmlspecialchars($schedule['course_code']), 1);
                $pdf->Cell($columnWidths[1], 6, htmlspecialchars($schedule['course_name']), 1);
                $pdf->Cell($columnWidths[2], 6, htmlspecialchars($schedule['section_name']), 1);
                $pdf->Cell($columnWidths[3], 6, htmlspecialchars($schedule['instructor_name']), 1);
                $pdf->Cell($columnWidths[4], 6, $room, 1);
                $pdf->Cell($columnWidths[5], 6, htmlspecialchars($schedule['day_of_week']), 1);
                $pdf->Cell($columnWidths[6], 6, $time, 1);
                $pdf->Cell($columnWidths[7], 6, htmlspecialchars($schedule['schedule_type']), 1);
                $pdf->Ln();
            }

            $pdf->Output('PRMSU_Schedule_' . date('Ymd_His') . '.pdf', 'D');
        } catch (PDOException $e) {
            error_log("Download Schedule PDF Error: " . $e->getMessage());
            header('Content-Type: application/json');
            echo json_encode(['error' => 'An error occurred while generating the PDF.']);
        } catch (Exception $e) {
            error_log("TCPDF Error: " . $e->getMessage());
            header('Content-Type: application/json');
            echo json_encode(['error' => 'Failed to generate PDF.']);
        }
        exit;
    }
}
