<?php
require_once __DIR__ . '/../config/database.php';

class ApiController
{
    protected $db;

    public function __construct()
    {
        try {
            $this->db = (new Database())->connect();
            if ($this->db === null) {
                error_log("Failed to connect to the database in ApiController");
                die("Database connection failed. Please try again later.");
            }
            $this->db->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
        } catch (PDOException $e) {
            error_log("ApiController::construct: Database connection failed - " . $e->getMessage());
            throw new Exception("Database connection failed");
        }
    }

    protected function getDepartmentId($userId)
    {
        $stmt = $this->db->prepare("SELECT department_id FROM users WHERE user_id = :user_id");
        $stmt->execute([':user_id' => $userId]);
        $result = $stmt->fetch(PDO::FETCH_ASSOC);
        return $result['department_id'] ?? null;
    }

    private function getChairDepartment($userId)
    {
        $stmt = $this->db->prepare("
            SELECT d.department_id
            FROM departments d
            JOIN users u ON u.department_id = d.department_id
            JOIN program_chairs pc ON pc.chair_id = u.user_id
            WHERE u.user_id = :user_id
            LIMIT 1
        ");
        $stmt->execute([':user_id' => $userId]);
        return $stmt->fetchColumn() ?: 0;
    }

    public function getCurrentSemester()
    {
        $stmt = $this->db->prepare("
            SELECT semester_id, semester_name, academic_year
            FROM semesters
            WHERE is_current = 1
            LIMIT 1
        ");
        $stmt->execute();
        return $stmt->fetch(PDO::FETCH_ASSOC) ?: null;
    }

    public function getCurricula($departmentId)
    {
        $stmt = $this->db->prepare("SELECT curriculum_id, curriculum_name FROM curricula WHERE department_id = :dept_id AND status = 'Active'");
        $stmt->execute([':dept_id' => $departmentId]);
        return $stmt->fetchAll();
    }

    public function loadData()
    {
        header('Content-Type: application/json');

        try {
            $type = $_GET['type'] ?? null;
            $curriculumId = (int)($_GET['curriculum_id'] ?? 0);
            $departmentId = $this->getChairDepartment($_SESSION['user_id'] ?? 0);
            $currentSemester = $this->getCurrentSemester();

            if (!$departmentId || !$currentSemester) {
                throw new Exception('Invalid department or semester');
            }

            // Debugging logs
            error_log("API loadData: type=$type, curriculum_id=$curriculumId, department_id=$departmentId, semester={$currentSemester['semester_name']}");

            $response = ['success' => false, 'data' => [], 'message' => ''];

            switch ($type) {
                case 'sections':
                    $query = "
                        SELECT 
                            s.section_id,
                            s.section_name,
                            s.year_level,
                            s.semester,
                            s.curriculum_id,
                            c.curriculum_name
                        FROM sections s
                        LEFT JOIN curricula c ON s.curriculum_id = c.curriculum_id
                        WHERE s.department_id = :department_id
                        AND s.semester = :semester
                        AND s.is_active = 1
                    ";
                    $params = [
                        ':department_id' => $departmentId,
                        ':semester' => $currentSemester['semester_name']
                    ];                 

                    $query .= " ORDER BY FIELD(s.year_level, '1st Year', '2nd Year', '3rd Year', '4th Year'), s.section_name";

                    $stmt = $this->db->prepare($query);
                    $stmt->execute($params);
                    $sections = $stmt->fetchAll(PDO::FETCH_ASSOC);

                    $response['success'] = true;
                    $response['data'] = $sections;
                    break;

                case 'courses':
                    if (!$curriculumId) {
                        throw new Exception('Curriculum ID is required');
                    }
                    $query = "
                        SELECT 
                            c.course_id,
                            c.course_code,
                            c.course_name,
                            cc.year_level,
                            cc.semester
                        FROM curriculum_courses cc
                        JOIN courses c ON cc.course_id = c.course_id
                        WHERE cc.curriculum_id = :curriculum_id
                        ORDER BY 
                            FIELD(cc.year_level, '1st Year', '2nd Year', '3rd Year', '4th Year'),
                            FIELD(cc.semester, '1st', '2nd', 'Summer'),
                            c.course_code
                    ";
                    $params = [':curriculum_id' => $curriculumId];

                    $stmt = $this->db->prepare($query);
                    $stmt->execute($params);
                    $courses = $stmt->fetchAll(PDO::FETCH_ASSOC);

                    $response['success'] = true;
                    $response['data'] = $courses;
                    break;

                case 'faculty':
                    $stmt = $this->db->prepare("
                        SELECT 
                            f.faculty_id,
                            CONCAT(u.first_name, ' ', u.last_name) AS name
                        FROM faculty f
                        JOIN users u ON f.user_id = u.user_id
                        WHERE u.department_id = :department_id
                        ORDER BY u.last_name, u.first_name
                    ");
                    $stmt->execute([':department_id' => $departmentId]);
                    $faculty = $stmt->fetchAll(PDO::FETCH_ASSOC);

                    $response['success'] = true;
                    $response['data'] = $faculty;
                    break;

                case 'classrooms':
                    $stmt = $this->db->prepare("
                        SELECT 
                            room_id,
                            room_name
                        FROM classrooms
                        WHERE (department_id = :department_id OR shared = 1)
                        AND availability = 'available'
                        ORDER BY room_name
                    ");
                    $stmt->execute([':department_id' => $departmentId]);
                    $classrooms = $stmt->fetchAll(PDO::FETCH_ASSOC);

                    $response['success'] = true;
                    $response['data'] = $classrooms;
                    break;

                default:
                    throw new Exception('Invalid data type requested');
            }

            echo json_encode($response);
        } catch (Exception $e) {
            error_log("API loadData error: " . $e->getMessage());
            echo json_encode([
                'success' => false,
                'data' => [],
                'message' => 'Error: ' . $e->getMessage()
            ]);
        }
    }

    public function searchCoursesAPI()
    {
        header('Content-Type: application/json');

        $searchTerm = isset($_GET['term']) ? trim($_GET['term']) : '';

        if (empty($searchTerm)) {
            echo json_encode([]);
            return;
        }

        try {
            $chairId = $_SESSION['user_id'] ?? 0;
            $departmentId = $this->getChairDepartment($chairId);

            if (!$departmentId) {
                echo json_encode([]);
                return;
            }

            $searchTerm = '%' . $searchTerm . '%';
            $query = "SELECT course_code, course_name FROM courses WHERE department_id = :department_id AND (course_code LIKE :search OR course_name LIKE :search) LIMIT 10";
            $stmt = $this->db->prepare($query);
            $stmt->bindValue(':department_id', $departmentId, PDO::PARAM_INT);
            $stmt->bindValue(':search', $searchTerm, PDO::PARAM_STR);

            if ($stmt->execute()) {
                $results = $stmt->fetchAll(PDO::FETCH_ASSOC);
                echo json_encode($results);
            } else {
                error_log("searchCoursesAPI: Query failed - " . implode(', ', $stmt->errorInfo()));
                echo json_encode([]);
            }
        } catch (PDOException $e) {
            error_log("searchCoursesAPI: Error - " . $e->getMessage());
            echo json_encode([]);
        }
    }

    public function getPrograms($departmentId)
    {
        header('Content-Type: application/json');
        try {
            $departmentId = filter_var($departmentId, FILTER_VALIDATE_INT);
            if (!$departmentId) {
                throw new Exception('Invalid department ID');
            }
            require_once __DIR__ . '/../models/UserModel.php';
            $userModel = new UserModel($this->db);
            $programs = $userModel->getProgramsByDepartment($departmentId);
            echo json_encode($programs);
        } catch (Exception $e) {
            error_log("getPrograms: Error - " . $e->getMessage());
            http_response_code(500);
            echo json_encode(['error' => 'Failed to fetch programs: ' . $e->getMessage()]);
        }
    }

}

