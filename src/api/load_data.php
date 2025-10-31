<?php
header('Content-Type: application/json');
header('Access-Control-Allow-Origin: *'); // Allow CORS if needed (adjust for security)

require_once __DIR__ . '/../config/Database.php'; // Adjust path based on your project structure


// Enable error logging for debugging
ini_set('display_errors', 0);
error_log("load_data.php: Starting request");

// Validate input
$type = isset($_GET['type']) ? trim($_GET['type']) : '';
if (empty($type) || !in_array($type, ['faculty', 'course'])) {
    error_log("load_data.php: Invalid or missing type parameter: $type");
    echo json_encode(['error' => 'Invalid request type']);
    exit;
}

try {
    $this->db = (new Database())->connect();
    if ($this->db === null) {
        error_log("Failed to connect to the database in FacultyController");
        die("Database connection failed. Please try again later.");
    }
    $db->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
    $data = [];

    if ($type === 'faculty') {
        // Fetch faculty data with names from users table
        $stmt = $db->prepare("SELECT f.faculty_id AS id, CONCAT(u.first_name, ' ', u.last_name) AS name 
                              FROM faculty f 
                              JOIN users u ON f.user_id = u.user_id 
                              WHERE u.department_id = :department_id");
        $stmt->execute([':department_id' => $_SESSION['department_id'] ?? 0]); // Restrict to current user's department
        $data = $stmt->fetchAll(PDO::FETCH_ASSOC);
    } elseif ($type === 'course') {
        // Fetch course data, restricted to the current department
        $stmt = $db->prepare("SELECT course_id AS id, course_code AS code, course_name AS name 
                              FROM courses 
                              WHERE department_id = :department_id");
        $stmt->execute([':department_id' => $_SESSION['department_id'] ?? 0]);
        $data = $stmt->fetchAll(PDO::FETCH_ASSOC);
    }

    if (empty($data)) {
        error_log("load_data.php: No data found for type: $type");
        echo json_encode([]);
    } else {
        echo json_encode($data);
    }
} catch (PDOException $e) {
    error_log("load_data.php: Database error - " . $e->getMessage());
    echo json_encode(['error' => 'Failed to load data']);
} catch (Exception $e) {
    error_log("load_data.php: General error - " . $e->getMessage());
    echo json_encode(['error' => 'An unexpected error occurred']);
}
