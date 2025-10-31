<?php
require_once __DIR__ . '/../config/Database.php';

class ContentModel
{
    private $db;

    public function __construct()
    {
        $this->db = (new Database())->connect();
        $this->db->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
    }

    /**
     * Fetch all active courses by program ID
     * @param int $programId
     * @return array
     */
    public function getCoursesByProgram($programId)
    {
        try {
            $query = "
                SELECT c.course_id, c.course_code, c.course_name, c.units, c.semester, c.year_level,
                       d.department_name, p.program_name
                FROM courses c
                JOIN departments d ON c.department_id = d.department_id
                LEFT JOIN programs p ON c.program_id = p.program_id
                WHERE c.program_id = :programId AND c.is_active = 1
                ORDER BY c.year_level, c.semester, c.course_code
            ";
            $stmt = $this->db->prepare($query);
            $stmt->bindParam(':programId', $programId, PDO::PARAM_INT);
            $stmt->execute();
            return $stmt->fetchAll(PDO::FETCH_ASSOC);
        } catch (PDOException $e) {
            error_log("Error fetching courses by program: " . $e->getMessage());
            return [];
        }
    }

    /**
     * Fetch all active courses by department ID
     * @param int $departmentId
     * @return array
     */
    public function getCoursesByDepartment($departmentId)
    {
        try {
            $query = "
                SELECT c.course_id, c.course_code, c.course_name, c.units, c.semester, c.year_level,
                       d.department_name
                FROM courses c
                JOIN departments d ON c.department_id = d.department_id
                WHERE c.department_id = :departmentId AND c.is_active = 1
                ORDER BY c.year_level, c.semester,independent
            ";
            $stmt = $this->db->prepare($query);
            $stmt->bindParam(':departmentId', $departmentId, PDO::PARAM_INT);
            $stmt->execute();
            return $stmt->fetchAll(PDO::FETCH_ASSOC);
        } catch (PDOException $e) {
            error_log("Error fetching courses by department: " . $e->getMessage());
            return [];
        }
    }

    /**
     * Fetch curriculum details by curriculum ID
     * @param int $curriculumId
     * @return array
     */
    public function getCurriculumDetails($curriculumId)
    {
        try {
            $query = "
                SELECT c.curriculum_id, c.curriculum_name, c.curriculum_code, c.total_units,
                       c.effective_year, c.status, d.department_name, d.department_id,
                       cl.college_name, cl.college_id
                FROM curricula c
                JOIN departments d ON c.department_id = d.department_id
                JOIN colleges cl ON d.college_id = cl.college_id
                WHERE c.curriculum_id = :curriculumId
            ";
            $stmt = $this->db->prepare($query);
            $stmt->bindParam(':curriculumId', $curriculumId, PDO::PARAM_INT);
            $stmt->execute();
            $curriculum = $stmt->fetch(PDO::FETCH_ASSOC);

            if ($curriculum) {
                // Fetch associated programs
                $curriculum['programs'] = $this->getCurriculumPrograms($curriculumId);
                // Fetch associated courses
                $curriculum['courses'] = $this->getCurriculumCourses($curriculumId);
            }

            return $curriculum ?: [];
        } catch (PDOException $e) {
            error_log("Error fetching curriculum details: " . $e->getMessage());
            return [];
        }
    }

    /**
     * Fetch programs associated with a curriculum
     * @param int $curriculumId
     * @return array
     */
    private function getCurriculumPrograms($curriculumId)
    {
        try {
            $query = "
                SELECT p.program_id, p.program_name, p.program_code, p.program_type,
                       cp.is_primary, cp.required
                FROM curriculum_programs cp
                JOIN programs p ON cp.program_id = p.program_id
                WHERE cp.curriculum_id = :curriculumId
            ";
            $stmt = $this->db->prepare($query);
            $stmt->bindParam(':curriculumId', $curriculumId, PDO::PARAM_INT);
            $stmt->execute();
            return $stmt->fetchAll(PDO::FETCH_ASSOC);
        } catch (PDOException $e) {
            error_log("Error fetching curriculum programs: " . $e->getMessage());
            return [];
        }
    }

    /**
     * Fetch courses associated with a curriculum
     * @param int $curriculumId
     * @return array
     */
    private function getCurriculumCourses($curriculumId)
    {
        try {
            $query = "
                SELECT cc.curriculum_course_id, c.course_id, c.course_code, c.course_name,
                       cc.year_level, cc.semester, cc.subject_type, cc.is_core,
                       cc.prerequisites, cc.co_requisites
                FROM curriculum_courses cc
                JOIN courses c ON cc.course_id = c.course_id
                WHERE cc.curriculum_id = :curriculumId
                ORDER BY cc.year_level, cc.semester, c.course_code
            ";
            $stmt = $this->db->prepare($query);
            $stmt->bindParam(':curriculumId', $curriculumId, PDO::PARAM_INT);
            $stmt->execute();
            return $stmt->fetchAll(PDO::FETCH_ASSOC);
        } catch (PDOException $e) {
            error_log("Error fetching curriculum courses: " . $e->getMessage());
            return [];
        }
    }

    /**
     * Fetch program details by program ID
     * @param int $programId
     * @return array
     */
    public function getProgramDetails($programId)
    {
        try {
            $query = "
                SELECT p.program_id, p.program_name, p.program_code, p.program_type,
                       p.total_units, p.description, p.is_active,
                       d.department_name, d.department_id,
                       c.college_name, c.college_id
                FROM programs p
                JOIN departments d ON p.department_id = d.department_id
                JOIN colleges c ON d.college_id = c.college_id
                WHERE p.program_id = :programId AND p.is_active = 1
            ";
            $stmt = $this->db->prepare($query);
            $stmt->bindParam(':programId', $programId, PDO::PARAM_INT);
            $stmt->execute();
            return $stmt->fetch(PDO::FETCH_ASSOC) ?: [];
        } catch (PDOException $e) {
            error_log("Error fetching program details: " . $e->getMessage());
            return [];
        }
    }

    /**
     * Create a new course
     * @param array $data
     * @return bool
     */
    public function createCourse($data)
    {
        try {
            $query = "
                INSERT INTO courses (
                    course_code, course_name, year_level, department_id, program_id,
                    units, lecture_hours, lab_hours, semester, is_active
                ) VALUES (
                    :course_code, :course_name, :year_level, :department_id, :program_id,
                    :units, :lecture_hours, :lab_hours, :semester, :is_active
                )
            ";
            $stmt = $this->db->prepare($query);
            $stmt->bindParam(':course_code', $data['course_code'], PDO::PARAM_STR);
            $stmt->bindParam(':course_name', $data['course_name'], PDO::PARAM_STR);
            $stmt->bindParam(':year_level', $data['year_level'], PDO::PARAM_STR);
            $stmt->bindParam(':department_id', $data['department_id'], PDO::PARAM_INT);
            $stmt->bindParam(':program_id', $data['program_id'], PDO::PARAM_INT);
            $stmt->bindParam(':units', $data['units'], PDO::PARAM_INT);
            $stmt->bindParam(':lecture_hours', $data['lecture_hours'], PDO::PARAM_INT);
            $stmt->bindParam(':lab_hours', $data['lab_hours'], PDO::PARAM_INT);
            $stmt->bindParam(':semester', $data['semester'], PDO::PARAM_STR);
            $stmt->bindParam(':is_active', $data['is_active'], PDO::PARAM_INT);
            return $stmt->execute();
        } catch (PDOException $e) {
            error_log("Error creating course: " . $e->getMessage());
            return false;
        }
    }

    /**
     * Update an existing course
     * @param int $courseId
     * @param array $data
     * @return bool
     */
    public function updateCourse($courseId, $data)
    {
        try {
            $query = "
                UPDATE courses
                SET course_code = :course_code,
                    course_name = :course_name,
                    year_level = :year_level,
                    department_id = :department_id,
                    program_id = :program_id,
                    units = :units,
                    lecture_hours = :lecture_hours,
                    lab_hours = :lab_hours,
                    semester = :semester,
                    is_active = :is_active
                WHERE course_id = :course_id
            ";
            $stmt = $this->db->prepare($query);
            $stmt->bindParam(':course_code', $data['course_code'], PDO::PARAM_STR);
            $stmt->bindParam(':course_name', $data['course_name'], PDO::PARAM_STR);
            $stmt->bindParam(':year_level', $data['year_level'], PDO::PARAM_STR);
            $stmt->bindParam(':department_id', $data['department_id'], PDO::PARAM_INT);
            $stmt->bindParam(':program_id', $data['program_id'], PDO::PARAM_INT);
            $stmt->bindParam(':units', $data['units'], PDO::PARAM_INT);
            $stmt->bindParam(':lecture_hours', $data['lecture_hours'], PDO::PARAM_INT);
            $stmt->bindParam(':lab_hours', $data['lab_hours'], PDO::PARAM_INT);
            $stmt->bindParam(':semester', $data['semester'], PDO::PARAM_STR);
            $stmt->bindParam(':is_active', $data['is_active'], PDO::PARAM_INT);
            $stmt->bindParam(':course_id', $courseId, PDO::PARAM_INT);
            return $stmt->execute();
        } catch (PDOException $e) {
            error_log("Error updating course: " . $e->getMessage());
            return false;
        }
    }

    /**
     * Delete a course (soft delete by setting is_active to 0)
     * @param int $courseId
     * @return bool
     */
    public function deleteCourse($courseId)
    {
        try {
            $query = "UPDATE courses SET is_active = 0 WHERE course_id = :course_id";
            $stmt = $this->db->prepare($query);
            $stmt->bindParam(':course_id', $courseId, PDO::PARAM_INT);
            return $stmt->execute();
        } catch (PDOException $e) {
            error_log("Error deleting course: " . $e->getMessage());
            return false;
        }
    }
}
