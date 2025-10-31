<?php
require_once __DIR__ . '/../config/Database.php';

class UserModel
{
    private $db;

    public function __construct()
    {
        $this->db = (new Database())->connect();
        $this->db->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
    }

    /**
     * Check if an email already exists
     * @param string $email
     * @return bool
     */
    public function emailExists($email)
    {
        try {
            $query = "SELECT COUNT(*) FROM users WHERE email = :email";
            $stmt = $this->db->prepare($query);
            $stmt->bindParam(':email', $email, PDO::PARAM_STR);
            $stmt->execute();
            return $stmt->fetchColumn() > 0;
        } catch (PDOException $e) {
            error_log("Error checking email existence: " . $e->getMessage());
            return false;
        }
    }

    /**
     * Check if an employee ID exists
     * @param string $employee_id
     * @return bool
     */
    public function employeeIdExists($employee_id)
    {
        try {
            $stmt = $this->db->prepare("SELECT COUNT(*) FROM users WHERE employee_id = :employee_id");
            $stmt->execute([':employee_id' => $employee_id]);
            return $stmt->fetchColumn() > 0;
        } catch (PDOException $e) {
            error_log("Error checking employee ID existence: " . $e->getMessage());
            return false;
        }
    }

    /**
     * Fetch user details by user ID
     * @param int $userId
     * @return array
     */
    public function getUserById($userId)
    {
        try {
            $query = "
                SELECT u.user_id, u.employee_id, u.username, u.email, u.first_name, u.middle_name, 
                       u.last_name, u.suffix, u.profile_picture, u.is_active,
                       r.role_name, d.department_name, c.college_name
                FROM users u
                JOIN roles r ON u.role_id = r.role_id
                LEFT JOIN departments d ON u.department_id = d.department_id
                JOIN colleges c ON u.college_id = c.college_id
                WHERE u.user_id = :userId AND u.is_active = 1
            ";
            $stmt = $this->db->prepare($query);
            $stmt->bindParam(':userId', $userId, PDO::PARAM_INT);
            $stmt->execute();
            return $stmt->fetch(PDO::FETCH_ASSOC) ?: [];
        } catch (PDOException $e) {
            error_log("Error fetching user by ID: " . $e->getMessage());
            return [];
        }
    }

    /**
     * Fetch users by role name
     * @param string $roleName
     * @return array
     */
    public function getUsersByRole($roleName)
    {
        try {
            $query = "
                SELECT u.user_id, u.employee_id, u.username, u.email, u.first_name, u.middle_name, 
                       u.last_name, u.suffix, u.profile_picture, u.is_active,
                       r.role_name, d.department_name, c.college_name
                FROM users u
                JOIN roles r ON u.role_id = r.role_id
                LEFT JOIN departments d ON u.department_id = d.department_id
                JOIN colleges c ON u.college_id = c.college_id
                WHERE r.role_name = :roleName AND u.is_active = 1
                ORDER BY u.last_name, u.first_name
            ";
            $stmt = $this->db->prepare($query);
            $stmt->bindParam(':roleName', $roleName, PDO::PARAM_STR);
            $stmt->execute();
            return $stmt->fetchAll(PDO::FETCH_ASSOC);
        } catch (PDOException $e) {
            error_log("Error fetching users by role: " . $e->getMessage());
            return [];
        }
    }

    /**
     * Fetch faculty details by user ID
     * @param int $userId
     * @return array
     */
    public function getFacultyDetails($userId)
    {
        try {
            $query = "
                SELECT f.faculty_id, f.user_id, f.employee_id, f.academic_rank, f.employment_type, 
                       f.classification, f.max_hours, 
                       GROUP_CONCAT(d.department_name SEPARATOR ', ') AS department_names,
                       p.program_name AS primary_program
                FROM faculty f
                LEFT JOIN faculty_departments fd ON f.faculty_id = fd.faculty_id
                LEFT JOIN departments d ON fd.department_id = d.department_id
                LEFT JOIN programs p ON f.primary_program_id = p.program_id
                WHERE f.user_id = :userId
                GROUP BY f.faculty_id
            ";
            $stmt = $this->db->prepare($query);
            $stmt->bindParam(':userId', $userId, PDO::PARAM_INT);
            $stmt->execute();
            $faculty = $stmt->fetch(PDO::FETCH_ASSOC);

            if ($faculty) {
                $faculty['specializations'] = $this->getFacultySpecializations($faculty['faculty_id']);
            }

            return $faculty ?: [];
        } catch (PDOException $e) {
            error_log("Error fetching faculty details: " . $e->getMessage());
            return [];
        }
    }

    /**
     * Fetch specializations for a faculty member
     * @param int $facultyId
     * @return array
     */
    private function getFacultySpecializations($facultyId)
    {
        try {
            $query = "
                SELECT s.specialization_id, c.course_name, s.expertise_level, 
                       p.program_name, s.is_primary_specialization
                FROM specializations s
                LEFT JOIN courses c ON s.course_id = c.course_id
                LEFT JOIN programs p ON s.program_id = p.program_id
                WHERE s.faculty_id = :facultyId
                ORDER BY s.is_primary_specialization DESC, c.course_name
            ";
            $stmt = $this->db->prepare($query);
            $stmt->bindParam(':facultyId', $facultyId, PDO::PARAM_INT);
            $stmt->execute();
            return $stmt->fetchAll(PDO::FETCH_ASSOC);
        } catch (PDOException $e) {
            error_log("Error fetching faculty specializations: " . $e->getMessage());
            return [];
        }
    }

    /**
     * Register a user with faculty and role-specific record
     * @param array $data
     * @return int|bool User ID on success, false on failure
     */
    public function registerUser($data)
    {
        try {
            $this->db->beginTransaction();

            // Validate required fields
            $required_fields = ['employee_id', 'username', 'password', 'email', 'first_name', 'last_name', 'department_id', 'college_id', 'role_id'];
            foreach ($required_fields as $field) {
                if (empty($data[$field])) {
                    error_log("Error registering user: Missing required field $field");
                    throw new Exception("Missing required field: $field");
                }
            }

            // Check for duplicates
            if ($this->employeeIdExists($data['employee_id'])) {
                error_log("Error registering user: Employee ID {$data['employee_id']} already exists");
                throw new Exception("Employee ID already exists");
            }
            if ($this->emailExists($data['email'])) {
                error_log("Error registering user: Email {$data['email']} already exists");
                throw new Exception("Email already exists");
            }
            $stmt = $this->db->prepare("SELECT COUNT(*) FROM users WHERE username = :username");
            $stmt->execute([':username' => $data['username']]);
            if ($stmt->fetchColumn() > 0) {
                error_log("Error registering user: Username {$data['username']} already exists");
                throw new Exception("Username already exists");
            }

            // Create user
            $user_id = $this->createUser([
                'employee_id' => $data['employee_id'],
                'title' => $data['title'] ?? null,
                'username' => $data['username'],
                'password_hash' => password_hash($data['password'], PASSWORD_DEFAULT),
                'email' => $data['email'],
                'phone' => $data['phone'] ?? null,
                'first_name' => $data['first_name'],
                'middle_name' => $data['middle_name'] ?? null,
                'last_name' => $data['last_name'],
                'suffix' => $data['suffix'] ?? null,
                'profile_picture' => $data['profile_picture'] ?? null,
                'role_id' => $data['role_id'],
                'department_id' => $data['department_id'],
                'college_id' => $data['college_id'],
                'is_active' => 0
            ]);

            if (!$user_id) {
                throw new Exception("Failed to create user");
            }

            // Create faculty record for all users
            $faculty_success = $this->createFaculty([
                'user_id' => $user_id,
                'employee_id' => $data['employee_id'],
                'academic_rank' => $data['academic_rank'] ?? 'Instructor',
                'employment_type' => $data['employment_type'] ?? 'Part-time',
                'classification' => $data['classification'] ?? null,
                'primary_program_id' => $data['program_id'] ?? null
            ]);

            if (!$faculty_success) {
                throw new Exception("Failed to create faculty record");
            }

            // Insert into faculty_departments
            $dept_stmt = $this->db->prepare("
                INSERT INTO faculty_departments (faculty_id, department_id, is_primary)
                VALUES ((SELECT faculty_id FROM faculty WHERE user_id = :user_id), :department_id, 1)
            ");
            $dept_stmt->execute([
                ':user_id' => $user_id,
                ':department_id' => $data['department_id']
            ]);

            // Handle role-specific tables
            switch ($data['role_id']) {
                case 3: // Department Instructor
                    if (empty($data['department_id'])) {
                        throw new Exception("Department ID required for Department Instructor");
                    }
                    $instructor_success = $this->createDepartmentInstructor([
                        'user_id' => $user_id,
                        'department_id' => $data['department_id'],
                        'start_date' => $data['start_date'] ?? date('Y-m-d')
                    ]);
                    if (!$instructor_success) {
                        throw new Exception("Failed to create department instructor record");
                    }
                    break;
                case 4: // Dean
                    if (empty($data['college_id'])) {
                        throw new Exception("College ID required for Dean");
                    }
                    $dean_success = $this->createDean([
                        'user_id' => $user_id,
                        'college_id' => $data['college_id'],
                        'start_date' => $data['start_date'] ?? date('Y-m-d')
                    ]);
                    if (!$dean_success) {
                        throw new Exception("Failed to create dean record");
                    }
                    break;
                case 5: // Program Chair
                    if (empty($data['program_id'])) {
                        throw new Exception("Program ID required for Program Chair");
                    }
                    $chair_success = $this->createProgramChair([
                        'user_id' => $user_id,
                        'program_id' => $data['program_id'],
                        'start_date' => $data['start_date'] ?? date('Y-m-d')
                    ]);
                    if (!$chair_success) {
                        throw new Exception("Failed to create program chair record");
                    }
                    break;
                case 6: // Faculty
                    // Faculty record already created above
                    break;

                default:
                    // No role-specific table for other roles
                    break;
            }

            $this->db->commit();
            error_log("Successfully registered user: user_id $user_id, role_id {$data['role_id']}");
            return $user_id;
        } catch (Exception $e) {
            $this->db->rollBack();
            error_log("Error registering user: " . $e->getMessage());
            return false;
        }
    }

    /**
     * Create a new user
     * @param array $data
     * @return int|bool
     */
    private function createUser($data)
    {
        try {
            $query = "
                INSERT INTO users (
                    employee_id, username, password_hash, email, phone, title, first_name, middle_name,
                    last_name, suffix, profile_picture, role_id, department_id, college_id, is_active
                ) VALUES (
                    :employee_id, :username, :password_hash, :email, :title, :phone, :first_name, :middle_name,
                    :last_name, :suffix, :profile_picture, :role_id, :department_id, :college_id, :is_active
                )
            ";
            $stmt = $this->db->prepare($query);
            $stmt->execute([
                ':employee_id' => $data['employee_id'],
                ':username' => $data['username'],
                ':password_hash' => $data['password_hash'],
                ':email' => $data['email'],
                ':phone' => $data['phone'] ?? null,
                ':title' => $data['title'] ?? null,
                ':first_name' => $data['first_name'],
                ':middle_name' => $data['middle_name'] ?? null,
                ':last_name' => $data['last_name'],
                ':suffix' => $data['suffix'] ?? null,
                ':profile_picture' => $data['profile_picture'] ?? null,
                ':role_id' => $data['role_id'],
                ':department_id' => $data['department_id'],
                ':college_id' => $data['college_id'],
                ':is_active' => $data['is_active']
            ]);
            return $this->db->lastInsertId();
        } catch (PDOException $e) {
            error_log("Error creating user: " . $e->getMessage());
            return false;
        }
    }

    /**
     * Create a faculty record
     * @param array $data
     * @return bool
     */
    private function createFaculty($data)
    {
        try {
            $query = "
                INSERT INTO faculty (
                    user_id, employee_id, academic_rank, employment_type, classification, primary_program_id
                ) VALUES (
                    :user_id, :employee_id, :academic_rank, :employment_type, :classification, :primary_program_id
                )
            ";
            $stmt = $this->db->prepare($query);
            $stmt->execute([
                ':user_id' => $data['user_id'],
                ':employee_id' => $data['employee_id'],
                ':academic_rank' => $data['academic_rank'] ?? 'Instructor',
                ':employment_type' => $data['employment_type'] ?? 'Regular',
                ':classification' => $data['classification'] ?? null,
                ':primary_program_id' => $data['primary_program_id'] ?? null
            ]);
            error_log("Faculty record created for user_id {$data['user_id']}");
            return true;
        } catch (PDOException $e) {
            error_log("Error creating faculty: " . $e->getMessage());
            return false;
        }
    }

    public function addFaculty($data)
    {
        return $this->createFaculty($data);
    }

    /**
     * Create a program chair record
     * @param array $data
     * @return bool
     */
    private function createProgramChair($data)
    {
        try {
            // Check if program_id exists
            $stmt = $this->db->prepare("SELECT program_id FROM programs WHERE program_id = :program_id");
            $stmt->execute([':program_id' => $data['program_id']]);
            if (!$stmt->fetchColumn()) {
                error_log("Error creating program chair: Invalid program_id {$data['program_id']}");
                return false;
            }

            // Check if faculty_id is required
            $columns = $this->db->query("SHOW COLUMNS FROM program_chairs LIKE 'faculty_id'")->fetch();
            $query = "
                INSERT INTO program_chairs (user_id" . ($columns ? ", faculty_id" : "") . ", program_id, start_date, is_current)
                VALUES (:user_id" . ($columns ? ", :faculty_id" : "") . ", :program_id, :start_date, 1)
            ";
            $params = [
                ':user_id' => $data['user_id'],
                ':program_id' => $data['program_id'],
                ':start_date' => $data['start_date'] ?? date('Y-m-d')
            ];

            if ($columns) {
                $stmt = $this->db->prepare("SELECT faculty_id FROM faculty WHERE user_id = :user_id");
                $stmt->execute([':user_id' => $data['user_id']]);
                $faculty_id = $stmt->fetchColumn();
                if (!$faculty_id) {
                    error_log("Error creating program chair: No faculty record for user_id {$data['user_id']}");
                    return false;
                }
                $params[':faculty_id'] = $faculty_id;
            }

            $stmt = $this->db->prepare($query);
            $stmt->execute($params);
            error_log("Program chair created for user_id {$data['user_id']}, program_id {$data['program_id']}");
            return true;
        } catch (PDOException $e) {
            error_log("Error creating program chair: " . $e->getMessage());
            return false;
        }
    }

    public function addProgramChair($data)
    {
        return $this->createProgramChair($data);
    }

    /**
     * Create a dean record
     * @param array $data
     * @return bool
     */
    private function createDean($data)
    {
        try {
            $query = "
                INSERT INTO deans (user_id, college_id, start_date, is_current)
                VALUES (:user_id, :college_id, :start_date, 1)
            ";
            $stmt = $this->db->prepare($query);
            $stmt->execute([
                ':user_id' => $data['user_id'],
                ':college_id' => $data['college_id'],
                ':start_date' => $data['start_date']
            ]);
            error_log("Dean created for user_id {$data['user_id']}, college_id {$data['college_id']}");
            return true;
        } catch (PDOException $e) {
            error_log("Error creating dean: " . $e->getMessage());
            return false;
        }
    }

    public function addDean($data)
    {
        return $this->createDean($data);
    }

    /**
     * Create a department instructor record
     * @param array $data
     * @return bool
     */
    private function createDepartmentInstructor($data)
    {
        try {
            $query = "
                INSERT INTO department_instructors (user_id, department_id, start_date, is_current)
                VALUES (:user_id, :department_id, :start_date, 1)
            ";
            $stmt = $this->db->prepare($query);
            $stmt->execute([
                ':user_id' => $data['user_id'],
                ':department_id' => $data['department_id'],
                ':start_date' => $data['start_date']
            ]);
            error_log("Department instructor created for user_id {$data['user_id']}, department_id {$data['department_id']}");
            return true;
        } catch (PDOException $e) {
            error_log("Error creating department instructor: " . $e->getMessage());
            return false;
        }
    }

    public function addDepartmentInstructor($data)
    {
        return $this->createDepartmentInstructor($data);
    }

    /**
     * Update an existing user
     * @param int $userId
     * @param array $data
     * @return bool
     */
    public function updateUser($userId, $data)
    {
        try {
            $query = "
                UPDATE users
                SET employee_id = :employee_id,
                    username = :username,
                    email = :email,
                    phone = :phone,
                    first_name = :first_name,
                    middle_name = :middle_name,
                    last_name = :last_name,
                    suffix = :suffix,
                    profile_picture = :profile_picture,
                    role_id = :role_id,
                    department_id = :department_id,
                    college_id = :college_id,
                    is_active = :is_active
                WHERE user_id = :user_id
            ";
            $stmt = $this->db->prepare($query);
            $stmt->bindParam(':employee_id', $data['employee_id'], PDO::PARAM_STR);
            $stmt->bindParam(':username', $data['username'], PDO::PARAM_STR);
            $stmt->bindParam(':email', $data['email'], PDO::PARAM_STR);
            $stmt->bindParam(':phone', $data['phone'], PDO::PARAM_STR);
            $stmt->bindParam(':first_name', $data['first_name'], PDO::PARAM_STR);
            $stmt->bindParam(':middle_name', $data['middle_name'], PDO::PARAM_STR);
            $stmt->bindParam(':last_name', $data['last_name'], PDO::PARAM_STR);
            $stmt->bindParam(':suffix', $data['suffix'], PDO::PARAM_STR);
            $stmt->bindParam(':profile_picture', $data['profile_picture'], PDO::PARAM_STR);
            $stmt->bindParam(':role_id', $data['role_id'], PDO::PARAM_INT);
            $stmt->bindParam(':department_id', $data['department_id'], PDO::PARAM_INT);
            $stmt->bindParam(':college_id', $data['college_id'], PDO::PARAM_INT);
            $stmt->bindParam(':is_active', $data['is_active'], PDO::PARAM_INT);
            $stmt->bindParam(':user_id', $userId, PDO::PARAM_INT);
            return $stmt->execute();
        } catch (PDOException $e) {
            error_log("Error updating user: " . $e->getMessage());
            return false;
        }
    }

    /**
     * Delete a user (soft delete by setting is_active to 0)
     * @param int $userId
     * @return bool
     */
    public function deleteUser($userId)
    {
        try {
            $query = "UPDATE users SET is_active = 0 WHERE user_id = :user_id";
            $stmt = $this->db->prepare($query);
            $stmt->bindParam(':user_id', $userId, PDO::PARAM_INT);
            return $stmt->execute();
        } catch (PDOException $e) {
            error_log("Error deleting user: " . $e->getMessage());
            return false;
        }
    }

    /**
     * Add faculty specialization
     * @param array $data
     * @return bool
     */
    public function addFacultySpecialization($data)
    {
        try {
            $query = "
                INSERT INTO specializations (
                    faculty_id, course_id, expertise_level, program_id, is_primary_specialization
                ) VALUES (
                    :faculty_id, :course_id, :expertise_level, :program_id, :is_primary_specialization
                )
            ";
            $stmt = $this->db->prepare($query);
            $stmt->bindParam(':faculty_id', $data['faculty_id'], PDO::PARAM_INT);
            $stmt->bindParam(':course_id', $data['course_id'], PDO::PARAM_INT);
            $stmt->bindParam(':expertise_level', $data['expertise_level'], PDO::PARAM_STR);
            $stmt->bindParam(':program_id', $data['program_id'], PDO::PARAM_INT);
            $stmt->bindParam(':is_primary_specialization', $data['is_primary_specialization'], PDO::PARAM_INT);
            return $stmt->execute();
        } catch (PDOException $e) {
            error_log("Error adding faculty specialization: " . $e->getMessage());
            return false;
        }
    }

    /**
     * Get all roles
     * @return array
     */
    public function getRoles()
    {
        try {
            $query = "SELECT role_id, role_name FROM roles ORDER BY role_name";
            $stmt = $this->db->prepare($query);
            $stmt->execute();
            return $stmt->fetchAll(PDO::FETCH_ASSOC);
        } catch (PDOException $e) {
            error_log("Error fetching roles: " . $e->getMessage());
            return [];
        }
    }

    public function getUserRoles($userId)
    {
        try {
            $query = "
            SELECT r.role_name
            FROM user_roles ur
            JOIN roles r ON ur.role_id = r.role_id
            WHERE ur.user_id = :user_id
            ";
            $stmt = $this->db->prepare($query);
            $stmt->bindParam(':user_id', $userId, PDO::PARAM_INT);
            $stmt->execute();
            return $stmt->fetchAll(PDO::FETCH_ASSOC);
        } catch (PDOException $e) {
            error_log("Error fetching user roles: " . $e->getMessage());
            return [];
        }
    }

    /**
     * Get all colleges
     * @return array
     */
    public function getColleges()
    {
        try {
            $query = "SELECT college_id, college_name FROM colleges ORDER BY college_name";
            $stmt = $this->db->prepare($query);
            $stmt->execute();
            return $stmt->fetchAll(PDO::FETCH_ASSOC);
        } catch (PDOException $e) {
            error_log("Error fetching colleges: " . $e->getMessage());
            return [];
        }
    }

    /**
     * Get departments by college
     * @param int $collegeId
     * @return array
     */
    public function getDepartmentsByCollege($collegeId)
    {
        try {
            $query = "SELECT department_id, department_name 
                      FROM departments 
                      WHERE college_id = :college_id 
                      ORDER BY department_name";
            $stmt = $this->db->prepare($query);
            $stmt->bindParam(':college_id', $collegeId, PDO::PARAM_INT);
            $stmt->execute();
            return $stmt->fetchAll(PDO::FETCH_ASSOC);
        } catch (PDOException $e) {
            error_log("Error fetching departments: " . $e->getMessage());
            return [];
        }
    }

    public function getCurrentSemester()
    {
        try {
            error_log("getCurrentSemester: Querying for current semester");
            // First, try to find the semester marked as current
            $stmt = $this->db->prepare("
                SELECT semester_id, semester_name, academic_year 
                FROM semesters 
                WHERE is_current = 1
            ");
            $stmt->execute();
            $semester = $stmt->fetch(PDO::FETCH_ASSOC);

            if ($semester) {
                error_log("getCurrentSemester: Found current semester - semester_id: {$semester['semester_id']}, semester_name: {$semester['semester_name']}, academic_year: {$semester['academic_year']}");
                return $semester;
            }

            error_log("getCurrentSemester: No semester with is_current = 1, checking date range");
            // Fall back to date range
            $stmt = $this->db->prepare("
                SELECT semester_id, semester_name, academic_year 
                FROM semesters 
                WHERE CURRENT_DATE BETWEEN start_date AND end_date
            ");
            $stmt->execute();
            $semester = $stmt->fetch(PDO::FETCH_ASSOC);

            if ($semester) {
                error_log("getCurrentSemester: Found semester by date range - semester_id: {$semester['semester_id']}, semester_name: {$semester['semester_name']}, academic_year: {$semester['academic_year']}");
            } else {
                error_log("getCurrentSemester: No semester found for current date");
            }

            return $semester ?: null;
        } catch (PDOException $e) {
            error_log("getCurrentSemester: Error - " . $e->getMessage());
            return null;
        }
    }

    /**
     * Get programs by department
     * @param int $departmentId
     * @return array
     */
    public function getProgramsByDepartment($departmentId)
    {
        try {
            $query = "SELECT program_id, program_name 
                      FROM programs 
                      WHERE department_id = :department_id 
                      ORDER BY program_name";
            $stmt = $this->db->prepare($query);
            $stmt->bindParam(':department_id', $departmentId, PDO::PARAM_INT);
            $stmt->execute();
            return $stmt->fetchAll(PDO::FETCH_ASSOC);
        } catch (PDOException $e) {
            error_log("Error fetching programs by department: " . $e->getMessage());
            return [];
        }
    }

    public function promoteToProgramChair($userId, $departmentId)
    {
        try {
            // Verify user is a faculty member and active
            $query = "SELECT u.role_id, u.college_id, u.is_active FROM users u WHERE u.user_id = :user_id";
            $stmt = $this->db->prepare($query);
            $stmt->execute([':user_id' => $userId]);
            $user = $stmt->fetch(PDO::FETCH_ASSOC);
            if (!$user || $user['role_id'] != 6 || !$user['is_active']) {
                error_log("promoteToProgramChair: Invalid user or not faculty, user_id=$userId");
                return ['success' => false, 'error' => 'User is not a valid or active faculty member'];
            }

            // Verify department exists and belongs to the same college
            $query = "SELECT d.department_id FROM departments d WHERE d.department_id = :department_id AND d.college_id = :college_id";
            $stmt = $this->db->prepare($query);
            $stmt->execute([':department_id' => $departmentId, ':college_id' => $user['college_id']]);
            if (!$stmt->fetch()) {
                error_log("promoteToProgramChair: Invalid department_id=$departmentId for college_id={$user['college_id']}");
                return ['success' => false, 'error' => 'Invalid department selected'];
            }

            // Check for existing current program chair in the department
            $query = "
            SELECT CONCAT(u.first_name, ' ', u.last_name) AS chair_name
            FROM program_chairs pc
            JOIN users u ON pc.user_id = u.user_id
            JOIN programs p ON pc.program_id = p.program_id
            WHERE p.department_id = :department_id AND pc.is_current = 1
            LIMIT 1
        ";
            $stmt = $this->db->prepare($query);
            $stmt->execute([':department_id' => $departmentId]);
            $existingChair = $stmt->fetch(PDO::FETCH_ASSOC);

            if ($existingChair) {
                error_log("promoteToProgramChair: Department $departmentId already has a program chair: {$existingChair['chair_name']}");
                return [
                    'success' => false,
                    'error' => "Department already has a Program Chair: {$existingChair['chair_name']}. Please demote the current chair before promoting a new one."
                ];
            }

            // Fetch faculty_id for the user
            $query = "SELECT faculty_id FROM faculty WHERE user_id = :user_id";
            $stmt = $this->db->prepare($query);
            $stmt->execute([':user_id' => $userId]);
            $facultyId = $stmt->fetchColumn();
            if (!$facultyId) {
                return ['success' => false, 'error' => 'Faculty record not found for the user'];
            }

            // Fetch all programs in the department
            $query = "SELECT program_id FROM programs WHERE department_id = :department_id";
            $stmt = $this->db->prepare($query);
            $stmt->execute([':department_id' => $departmentId]);
            $allPrograms = $stmt->fetchAll(PDO::FETCH_COLUMN);

            if (empty($allPrograms)) {
                return ['success' => false, 'error' => 'No programs found in the department'];
            }

            // Update user role to Program Chair (role_id = 5)
            $query = "UPDATE users SET role_id = 5 WHERE user_id = :user_id";
            $stmt = $this->db->prepare($query);
            $stmt->execute([':user_id' => $userId]);

            // Deactivate any previous program chair assignments for this user
            $query = "UPDATE program_chairs SET is_current = 0 WHERE user_id = :user_id";
            $stmt = $this->db->prepare($query);
            $stmt->execute([':user_id' => $userId]);

            // Add to program_chairs table for all programs in the department, including faculty_id
            $query = "INSERT INTO program_chairs (user_id, faculty_id, program_id, is_current, created_at) 
                      VALUES (:user_id, :faculty_id, :program_id, 1, NOW())";
            $stmt = $this->db->prepare($query);
            $insertedCount = 0;
            foreach ($allPrograms as $progId) {
                $result = $stmt->execute([
                    ':user_id' => $userId,
                    ':faculty_id' => $facultyId,
                    ':program_id' => $progId
                ]);
                if ($result) {
                    $insertedCount++;
                }
            }

            error_log("promoteToProgramChair: Promoted user_id=$userId (faculty_id=$facultyId) to chair for $insertedCount programs in department $departmentId");

            return ['success' => true, 'message' => "Promoted to Program Chair for $insertedCount programs in the department."];
        } catch (PDOException $e) {
            error_log("promoteToProgramChair: PDO Error - " . $e->getMessage());
            return ['success' => false, 'error' => 'Database error: ' . $e->getMessage()];
        }
    }

    public function demoteProgramChair($userId)
    {
        try {
            // Verify user is a program chair and get department_id for faculty_departments
            $query = "SELECT u.role_id, p.department_id, pc.program_id 
                      FROM users u 
                      JOIN program_chairs pc ON u.user_id = pc.user_id 
                      JOIN programs p ON pc.program_id = p.program_id 
                      WHERE u.user_id = :user_id AND pc.is_current = 1";
            $stmt = $this->db->prepare($query);
            $stmt->execute([':user_id' => $userId]);
            $user = $stmt->fetch(PDO::FETCH_ASSOC);
            if (!$user || $user['role_id'] != 5) {
                error_log("demoteProgramChair: User is not a program chair, user_id=$userId");
                return ['success' => false, 'error' => 'User is not a program chair'];
            }

            $deptId = $user['department_id'];

            $this->db->beginTransaction();

            // Update user role to Faculty (role_id = 6)
            $query = "UPDATE users SET role_id = 6 WHERE user_id = :user_id";
            $stmt = $this->db->prepare($query);
            $stmt->execute([':user_id' => $userId]);
            error_log("demoteProgramChair: Updated role to Faculty for user_id=$userId");

            // Fetch all program_chairs entries for this user
            $query = "SELECT program_id FROM program_chairs WHERE user_id = :user_id AND is_current = 1";
            $stmt = $this->db->prepare($query);
            $stmt->execute([':user_id' => $userId]);
            $programIds = $stmt->fetchAll(PDO::FETCH_COLUMN);

            if (empty($programIds)) {
                error_log("demoteProgramChair: No active program chair entries found for user_id=$userId");
            } else {
                // For each program_id, check for existing is_current = 0 entries
                foreach ($programIds as $programId) {
                    $checkQuery = "SELECT COUNT(*) FROM program_chairs 
                                   WHERE program_id = :program_id AND is_current = 0";
                    $stmt = $this->db->prepare($checkQuery);
                    $stmt->execute([':program_id' => $programId]);
                    $existingCount = $stmt->fetchColumn();

                    if ($existingCount > 0) {
                        // Delete existing is_current = 0 entries for this program_id
                        $deleteQuery = "DELETE FROM program_chairs 
                                        WHERE program_id = :program_id AND is_current = 0";
                        $stmt = $this->db->prepare($deleteQuery);
                        $stmt->execute([':program_id' => $programId]);
                        error_log("demoteProgramChair: Deleted $existingCount is_current=0 entries for program_id=$programId");
                    }
                }

                // Mark all program chair records for this user as not current
                $query = "UPDATE program_chairs SET is_current = 0 WHERE user_id = :user_id";
                $stmt = $this->db->prepare($query);
                $stmt->execute([':user_id' => $userId]);
                $affectedRows = $stmt->rowCount();
                error_log("demoteProgramChair: Updated $affectedRows program_chairs entries for user_id=$userId");
            }

            // Ensure faculty_departments entry exists or update it
            $facultyQuery = "SELECT f.faculty_id FROM faculty f WHERE f.user_id = :user_id";
            $stmt = $this->db->prepare($facultyQuery);
            $stmt->execute([':user_id' => $userId]);
            $facultyId = $stmt->fetchColumn();
            if ($facultyId) {
                $checkQuery = "SELECT COUNT(*) FROM faculty_departments 
                               WHERE faculty_id = :faculty_id AND department_id = :dept_id";
                $stmt = $this->db->prepare($checkQuery);
                $stmt->execute([':faculty_id' => $facultyId, ':dept_id' => $deptId]);
                $exists = $stmt->fetchColumn();

                if ($exists) {
                    error_log("demoteProgramChair: faculty_departments entry already exists for faculty_id=$facultyId, dept_id=$deptId; no changes made");
                } else {
                    $insertQuery = "INSERT INTO faculty_departments (faculty_id, department_id, is_primary, created_at) 
                                    VALUES (:faculty_id, :dept_id, 1, NOW())";
                    $stmt = $this->db->prepare($insertQuery);
                    $stmt->execute([':faculty_id' => $facultyId, ':dept_id' => $deptId]);
                    error_log("demoteProgramChair: Added faculty_departments entry for faculty_id=$facultyId, dept_id=$deptId");
                }
            } else {
                error_log("demoteProgramChair: No faculty record found for user_id=$userId");
            }

            $this->db->commit();
            return ['success' => true, 'message' => 'User demoted to Faculty successfully'];
        } catch (PDOException $e) {
            $this->db->rollBack();
            error_log("demoteProgramChair: PDO Error - " . $e->getMessage());
            return ['success' => false, 'error' => 'Database error: ' . $e->getMessage()];
        }
    }
}
