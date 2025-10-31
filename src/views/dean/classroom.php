<?php
ob_start();

// Fetch departments for the modal and filter
$collegeId = $controller->getDeanCollegeId($_SESSION['user_id']);
$query = "SELECT department_id, department_name FROM departments WHERE college_id = :college_id ORDER BY department_name";
$stmt = $controller->db->prepare($query);
$stmt->execute([':college_id' => $collegeId]);
$departments = $stmt->fetchAll(PDO::FETCH_ASSOC);

// Check for success/error messages from DeanController
$success = isset($_GET['success']) ? htmlspecialchars($_GET['success']) : null;
$error = isset($_GET['error']) ? htmlspecialchars($_GET['error']) : null;

// Fetch classrooms for the Dean's college only
$query = "
    SELECT c.*, d.department_name, col.college_name
    FROM classrooms c
    JOIN departments d ON c.department_id = d.department_id
    JOIN colleges col ON d.college_id = col.college_id
    WHERE d.college_id = :college_id
    ORDER BY d.department_name, c.building, c.room_name";
$stmt = $controller->db->prepare($query);
$stmt->execute([':college_id' => $collegeId]);
$classrooms = $stmt->fetchAll(PDO::FETCH_ASSOC) ?: [];
if (!is_array($classrooms)) {
    error_log("classroom.php: \$classrooms is not an array. College ID: $collegeId");
    $classrooms = [];
}

// Fetch reservations and ensure $reservations is an array
$query = "
    SELECT rr.reservation_id, rr.room_id, c.room_name, rr.start_time, rr.end_time, rr.description, u.first_name, u.last_name
    FROM room_reservations rr
    JOIN classrooms c ON rr.room_id = c.room_id
    JOIN departments d ON c.department_id = d.department_id
    JOIN users u ON rr.reserved_by = u.user_id
    WHERE d.college_id = :college_id AND rr.approval_status = 'Pending'
    ORDER BY rr.start_time";
$stmt = $controller->db->prepare($query);
$stmt->execute([':college_id' => $collegeId]);
$reservations = $stmt->fetchAll(PDO::FETCH_ASSOC) ?: [];
if (!is_array($reservations)) {
    error_log("classroom.php: \$reservations is not an array. College ID: $collegeId");
    $reservations = [];
}
?>

<!DOCTYPE html>
<html lang="en">

<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Classroom Management | ACSS</title>
    <style>
        :root {
            --gold: #D4AF37;
            --white: #FFFFFF;
            --gray-dark: #4B5563;
            --gray-light: #E5E7EB;
        }

        .fade-in {
            animation: fadeIn 0.5s ease-in;
        }

        @keyframes fadeIn {
            from {
                opacity: 0;
            }

            to {
                opacity: 1;
            }
        }

        .slide-in-left {
            animation: slideInLeft 0.5s ease-in;
        }

        @keyframes slideInLeft {
            from {
                transform: translateX(-20px);
                opacity: 0;
            }

            to {
                transform: translateX(0);
                opacity: 1;
            }
        }

        .toast {
            position: fixed;
            top: 20px;
            right: 20px;
            z-index: 1000;
            transition: all 0.3s ease;
        }

        .modal {
            transition: opacity 0.3s ease;
        }

        .modal.hidden {
            opacity: 0;
            pointer-events: none;
        }

        .modal-content {
            transition: transform 0.3s ease;
        }

        .input-focus {
            transition: all 0.2s ease;
        }

        .input-focus:focus {
            border-color: var(--gold);
            ring-color: var(--gold);
        }

        .btn-gold {
            background-color: var(--gold);
            color: var(--white);
        }

        .btn-gold:hover {
            background-color: #b8972e;
        }

        .tooltip {
            display: none;
        }

        .group:hover .tooltip {
            display: block;
        }
    </style>
</head>

<body class="bg-gray-light font-sans antialiased">
    <div id="toast-container" class="fixed top-5 right-5 z-50"></div>

    <!-- Main Content -->
    <div class="container mx-auto px-4 py-8 max-w-7xl">
        <!-- Add Classroom Button -->
        <div class="mb-6 flex justify-end fade-in">
            <button id="openModalBtn" class="btn-gold px-6 py-3 rounded-lg shadow-md hover:shadow-lg flex items-center transition-all duration-300 focus:outline-none focus:ring-2 focus:ring-gold focus:ring-opacity-50">
                <i class="fas fa-plus mr-2"></i> Add Classroom
            </button>
        </div>

        <!-- Add Classroom Modal -->
        <div id="addClassroomModal" class="modal fixed inset-0 bg-black bg-opacity-60 flex items-center justify-center z-50 hidden">
            <div class="bg-white rounded-xl shadow-2xl w-full max-w-3xl mx-4 transform modal-content scale-95">
                <!-- Modal Header -->
                <div class="flex justify-between items-center p-6 border-b border-gray-light bg-gradient-to-r from-white to-gray-50 rounded-t-xl">
                    <h3 class="text-xl font-bold text-gray-dark">Add New Classroom</h3>
                    <button id="closeModalBtn" class="text-gray-dark hover:text-gray-700 focus:outline-none bg-gray-light hover:bg-gray-200 rounded-full h-8 w-8 flex items-center justify-center transition-all duration-200" aria-label="Close modal">
                        <i class="fas fa-times"></i>
                    </button>
                </div>

                <!-- Form Content -->
                <form action="/dean/classroom" method="POST" class="p-6 grid grid-cols-1 md:grid-cols-2 gap-6" id="addClassroomForm">
                    <!-- Room Name -->
                    <div>
                        <label for="room_name" class="block text-sm font-medium text-gray-dark mb-1">Room Name <span class="text-red-500">*</span></label>
                        <div class="relative">
                            <div class="absolute inset-y-0 left-0 pl-3 flex items-center pointer-events-none">
                                <i class="fas fa-door-open text-gray-dark"></i>
                            </div>
                            <input type="text" id="room_name" name="room_name" required
                                class="pl-10 pr-4 py-3 w-full rounded-lg border-gray-light bg-white shadow-sm input-focus focus:ring focus:ring-gold focus:ring-opacity-50"
                                placeholder="e.g., Lecture Room 101" aria-required="true">
                        </div>
                        <p class="text-red-500 text-xs mt-1 hidden error-message">Room name is required.</p>
                    </div>

                    <!-- Building -->
                    <div>
                        <label for="building" class="block text-sm font-medium text-gray-dark mb-1">Building <span class="text-red-500">*</span></label>
                        <div class="relative">
                            <div class="absolute inset-y-0 left-0 pl-3 flex items-center pointer-events-none">
                                <i class="fas fa-building text-gray-dark"></i>
                            </div>
                            <input type="text" id="building" name="building" required
                                class="pl-10 pr-4 py-3 w-full rounded-lg border-gray-light bg-white shadow-sm input-focus focus:ring focus:ring-gold focus:ring-opacity-50"
                                placeholder="e.g., Science Building" aria-required="true">
                        </div>
                        <p class="text-red-500 text-xs mt-1 hidden error-message">Building is required.</p>
                    </div>

                    <!-- Department -->
                    <div>
                        <label for="department_id" class="block text-sm font-medium text-gray-dark mb-1">Department <span class="text-red-500">*</span></label>
                        <div class="relative">
                            <div class="absolute inset-y-0 left-0 pl-3 flex items-center pointer-events-none">
                                <i class="fas fa-university text-gray-dark"></i>
                            </div>
                            <select id="department_id" name="department_id" required
                                class="pl-10 pr-10 py-3 w-full rounded-lg border-gray-light bg-white shadow-sm input-focus focus:ring focus:ring-gold focus:ring-opacity-50 appearance-none"
                                aria-required="true">
                                <option value="">Select Department</option>
                                <?php foreach ($departments as $dept): ?>
                                    <option value="<?php echo $dept['department_id']; ?>"><?php echo htmlspecialchars($dept['department_name']); ?></option>
                                <?php endforeach; ?>
                            </select>
                            <div class="absolute inset-y-0 right-0 pr-3 flex items-center pointer-events-none">
                                <i class="fas fa-chevron-down text-gray-dark"></i>
                            </div>
                        </div>
                        <p class="text-red-500 text-xs mt-1 hidden error-message">Department is required.</p>
                    </div>

                    <!-- Capacity -->
                    <div>
                        <label for="capacity" class="block text-sm font-medium text-gray-dark mb-1">Capacity <span class="text-red-500">*</span></label>
                        <div class="relative">
                            <div class="absolute inset-y-0 left-0 pl-3 flex items-center pointer-events-none">
                                <i class="fas fa-users text-gray-dark"></i>
                            </div>
                            <input type="number" id="capacity" name="capacity" required min="1"
                                class="pl-10 pr-4 py-3 w-full rounded-lg border-gray-light bg-white shadow-sm input-focus focus:ring focus:ring-gold focus:ring-opacity-50"
                                placeholder="e.g., 50" aria-required="true">
                        </div>
                        <p class="text-red-500 text-xs mt-1 hidden error-message">Capacity must be at least 1.</p>
                    </div>

                    <!-- Room Type -->
                    <div>
                        <label for="room_type" class="block text-sm font-medium text-gray-dark mb-1">Room Type <span class="text-red-500">*</span></label>
                        <div class="relative">
                            <div class="absolute inset-y-0 left-0 pl-3 flex items-center pointer-events-none">
                                <i class="fas fa-chalkboard text-gray-dark"></i>
                            </div>
                            <select id="room_type" name="room_type" required
                                class="pl-10 pr-10 py-3 w-full rounded-lg border-gray-light bg-white shadow-sm input-focus focus:ring focus:ring-gold focus:ring-opacity-50 appearance-none"
                                aria-required="true">
                                <option value="classroom">Classroom</option>
                                <option value="laboratory">Laboratory</option>
                                <option value="auditorium">Auditorium</option>
                                <option value="seminar">Seminar</option>
                            </select>
                            <div class="absolute inset-y-0 right-0 pr-3 flex items-center pointer-events-none">
                                <i class="fas fa-chevron-down text-gray-dark"></i>
                            </div>
                        </div>
                        <p class="text-red-500 text-xs mt-1 hidden error-message">Room type is required.</p>
                    </div>

                    <!-- Availability -->
                    <div>
                        <label for="availability" class="block text-sm font-medium text-gray-dark mb-1">Availability <span class="text-red-500">*</span></label>
                        <div class="relative">
                            <div class="absolute inset-y-0 left-0 pl-3 flex items-center pointer-events-none">
                                <i class="fas fa-traffic-light text-gray-dark"></i>
                            </div>
                            <select id="availability" name="availability" required
                                class="pl-10 pr-10 py-3 w-full rounded-lg border-gray-light bg-white shadow-sm input-focus focus:ring focus:ring-gold focus:ring-opacity-50 appearance-none"
                                aria-required="true">
                                <option value="available">Available</option>
                                <option value="unavailable">Unavailable</option>
                                <option value="under_maintenance">Under Maintenance</option>
                            </select>
                            <div class="absolute inset-y-0 right-0 pr-3 flex items-center pointer-events-none">
                                <i class="fas fa-chevron-down text-gray-dark"></i>
                            </div>
                        </div>
                        <p class="text-red-500 text-xs mt-1 hidden error-message">Availability is required.</p>
                    </div>

                    <!-- Shared -->
                    <div class="md:col-span-2">
                        <div class="flex items-center bg-gray-50 p-4 rounded-lg border border-gray-light">
                            <input type="checkbox" id="shared" name="shared" class="h-5 w-5 text-gold focus:ring-gold border-gray-light rounded">
                            <label for="shared" class="ml-2 text-sm text-gray-dark">Allow sharing with other departments</label>
                        </div>
                    </div>

                    <!-- Form Actions -->
                    <div class="md:col-span-2 flex justify-end space-x-3 pt-4 border-t border-gray-light">
                        <button type="button" id="cancelModalBtn" class="bg-gray-light text-gray-dark px-5 py-3 rounded-lg hover:bg-gray-200 transition-all duration-200 font-medium">Cancel</button>
                        <button type="submit" name="add_classroom" class="btn-gold px-5 py-3 rounded-lg shadow-md hover:shadow-lg transition-all duration-200 font-medium">Add Classroom</button>
                    </div>
                </form>
            </div>
        </div>

        <!-- Edit Classroom Modal -->
        <div id="editClassroomModal" class="modal fixed inset-0 bg-black bg-opacity-60 flex items-center justify-center z-50 hidden">
            <div class="bg-white rounded-xl shadow-2xl w-full max-w-3xl mx-4 transform modal-content scale-95">
                <!-- Modal Header -->
                <div class="flex justify-between items-center p-6 border-b border-gray-light bg-gradient-to-r from-white to-gray-50 rounded-t-xl">
                    <h3 class="text-xl font-bold text-gray-dark">Edit Classroom</h3>
                    <button id="closeEditModalBtn" class="text-gray-dark hover:text-gray-700 focus:outline-none bg-gray-light hover:bg-gray-200 rounded-full h-8 w-8 flex items-center justify-center transition-all duration-200" aria-label="Close modal">
                        <i class="fas fa-times"></i>
                    </button>
                </div>

                <!-- Form Content -->
                <form action="/dean/classroom" method="POST" class="p-6 grid grid-cols-1 md:grid-cols-2 gap-6" id="editClassroomForm">
                    <input type="hidden" id="edit_room_id" name="room_id">
                    <!-- Room Name -->
                    <div>
                        <label for="edit_room_name" class="block text-sm font-medium text-gray-dark mb-1">Room Name <span class="text-red-500">*</span></label>
                        <div class="relative">
                            <div class="absolute inset-y-0 left-0 pl-3 flex items-center pointer-events-none">
                                <i class="fas fa-door-open text-gray-dark"></i>
                            </div>
                            <input type="text" id="edit_room_name" name="room_name" required
                                class="pl-10 pr-4 py-3 w-full rounded-lg border-gray-light bg-white shadow-sm input-focus focus:ring focus:ring-gold focus:ring-opacity-50"
                                placeholder="e.g., Lecture Room 101" aria-required="true">
                        </div>
                        <p class="text-red-500 text-xs mt-1 hidden error-message">Room name is required.</p>
                    </div>

                    <!-- Building -->
                    <div>
                        <label for="edit_building" class="block text-sm font-medium text-gray-dark mb-1">Building <span class="text-red-500">*</span></label>
                        <div class="relative">
                            <div class="absolute inset-y-0 left-0 pl-3 flex items-center pointer-events-none">
                                <i class="fas fa-building text-gray-dark"></i>
                            </div>
                            <input type="text" id="edit_building" name="building" required
                                class="pl-10 pr-4 py-3 w-full rounded-lg border-gray-light bg-white shadow-sm input-focus focus:ring focus:ring-gold focus:ring-opacity-50"
                                placeholder="e.g., Science Building" aria-required="true">
                        </div>
                        <p class="text-red-500 text-xs mt-1 hidden error-message">Building is required.</p>
                    </div>

                    <!-- Department -->
                    <div>
                        <label for="edit_department_id" class="block text-sm font-medium text-gray-dark mb-1">Department <span class="text-red-500">*</span></label>
                        <div class="relative">
                            <div class="absolute inset-y-0 left-0 pl-3 flex items-center pointer-events-none">
                                <i class="fas fa-university text-gray-dark"></i>
                            </div>
                            <select id="edit_department_id" name="department_id" required
                                class="pl-10 pr-10 py-3 w-full rounded-lg border-gray-light bg-white shadow-sm input-focus focus:ring focus:ring-gold focus:ring-opacity-50 appearance-none"
                                aria-required="true">
                                <option value="">Select Department</option>
                                <?php foreach ($departments as $dept): ?>
                                    <option value="<?php echo $dept['department_id']; ?>"><?php echo htmlspecialchars($dept['department_name']); ?></option>
                                <?php endforeach; ?>
                            </select>
                            <div class="absolute inset-y-0 right-0 pr-3 flex items-center pointer-events-none">
                                <i class="fas fa-chevron-down text-gray-dark"></i>
                            </div>
                        </div>
                        <p class="text-red-500 text-xs mt-1 hidden error-message">Department is required.</p>
                    </div>

                    <!-- Capacity -->
                    <div>
                        <label for="edit_capacity" class="block text-sm font-medium text-gray-dark mb-1">Capacity <span class="text-red-500">*</span></label>
                        <div class="relative">
                            <div class="absolute inset-y-0 left-0 pl-3 flex items-center pointer-events-none">
                                <i class="fas fa-users text-gray-dark"></i>
                            </div>
                            <input type="number" id="edit_capacity" name="capacity" required min="1"
                                class="pl-10 pr-4 py-3 w-full rounded-lg border-gray-light bg-white shadow-sm input-focus focus:ring focus:ring-gold focus:ring-opacity-50"
                                placeholder="e.g., 50" aria-required="true">
                        </div>
                        <p class="text-red-500 text-xs mt-1 hidden error-message">Capacity must be at least 1.</p>
                    </div>

                    <!-- Room Type -->
                    <div>
                        <label for="edit_room_type" class="block text-sm font-medium text-gray-dark mb-1">Room Type <span class="text-red-500">*</span></label>
                        <div class="relative">
                            <div class="absolute inset-y-0 left-0 pl-3 flex items-center pointer-events-none">
                                <i class="fas fa-chalkboard text-gray-dark"></i>
                            </div>
                            <select id="edit_room_type" name="room_type" required
                                class="pl-10 pr-10 py-3 w-full rounded-lg border-gray-light bg-white shadow-sm input-focus focus:ring focus:ring-gold focus:ring-opacity-50 appearance-none"
                                aria-required="true">
                                <option value="classroom">Classroom</option>
                                <option value="laboratory">Laboratory</option>
                                <option value="auditorium">Auditorium</option>
                                <option value="seminar">Seminar</option>
                            </select>
                            <div class="absolute inset-y-0 right-0 pr-3 flex items-center pointer-events-none">
                                <i class="fas fa-chevron-down text-gray-dark"></i>
                            </div>
                        </div>
                        <p class="text-red-500 text-xs mt-1 hidden error-message">Room type is required.</p>
                    </div>

                    <!-- Availability -->
                    <div>
                        <label for="edit_availability" class="block text-sm font-medium text-gray-dark mb-1">Availability <span class="text-red-500">*</span></label>
                        <div class="relative">
                            <div class="absolute inset-y-0 left-0 pl-3 flex items-center pointer-events-none">
                                <i class="fas fa-traffic-light text-gray-dark"></i>
                            </div>
                            <select id="edit_availability" name="availability" required
                                class="pl-10 pr-10 py-3 w-full rounded-lg border-gray-light bg-white shadow-sm input-focus focus:ring focus:ring-gold focus:ring-opacity-50 appearance-none"
                                aria-required="true">
                                <option value="available">Available</option>
                                <option value="unavailable">Unavailable</option>
                                <option value="under_maintenance">Under Maintenance</option>
                            </select>
                            <div class="absolute inset-y-0 right-0 pr-3 flex items-center pointer-events-none">
                                <i class="fas fa-chevron-down text-gray-dark"></i>
                            </div>
                        </div>
                        <p class="text-red-500 text-xs mt-1 hidden error-message">Availability is required.</p>
                    </div>

                    <!-- Shared -->
                    <div class="md:col-span-2">
                        <div class="flex items-center bg-gray-50 p-4 rounded-lg border border-gray-light">
                            <input type="checkbox" id="edit_shared" name="shared" class="h-5 w-5 text-gold focus:ring-gold border-gray-light rounded">
                            <label for="edit_shared" class="ml-2 text-sm text-gray-dark">Allow sharing with other departments</label>
                        </div>
                    </div>

                    <!-- Form Actions -->
                    <div class="md:col-span-2 flex justify-end space-x-3 pt-4 border-t border-gray-light">
                        <button type="button" id="cancelEditModalBtn" class="bg-gray-light text-gray-dark px-5 py-3 rounded-lg hover:bg-gray-200 transition-all duration-200 font-medium">Cancel</button>
                        <button type="submit" name="update_classroom" class="btn-gold px-5 py-3 rounded-lg shadow-md hover:shadow-lg transition-all duration-200 font-medium">Update Classroom</button>
                    </div>
                </form>
            </div>
        </div>

        <!-- Search and Filter Section -->
        <div class="bg-white rounded-xl shadow-lg p-6 mb-8 fade-in">
            <div class="grid grid-cols-1 md:grid-cols-2 gap-6">
                <!-- Search Input -->
                <div>
                    <label for="searchClassrooms" class="block text-sm font-medium text-gray-dark mb-1">Search Classrooms</label>
                    <div class="relative">
                        <div class="absolute inset-y-0 left-0 pl-3 flex items-center pointer-events-none">
                            <i class="fas fa-search text-gray-dark"></i>
                        </div>
                        <input type="text" id="searchClassrooms"
                            class="pl-10 pr-10 py-3 w-full rounded-lg border-gray-light bg-white shadow-sm input-focus focus:ring focus:ring-gold focus:ring-opacity-50"
                            placeholder="Search by room name, building, department, or capacity">
                        <button id="clearSearch" class="absolute inset-y-0 right-0 pr-3 flex items-center text-gray-dark hover:text-gray-700 hidden">
                            <i class="fas fa-times-circle"></i>
                        </button>
                    </div>
                </div>

                <!-- Department Filter -->
                <div>
                    <label for="departmentFilter" class="block text-sm font-medium text-gray-dark mb-1">Filter by Department</label>
                    <div class="relative">
                        <div class="absolute inset-y-0 left-0 pl-3 flex items-center pointer-events-none">
                            <i class="fas fa-sitemap text-gray-dark"></i>
                        </div>
                        <select id="departmentFilter"
                            class="pl-10 pr-10 py-3 w-full rounded-lg border-gray-light bg-white shadow-sm input-focus focus:ring focus:ring-gold focus:ring-opacity-50 appearance-none">
                            <option value="">All Departments</option>
                            <?php foreach ($departments as $dept): ?>
                                <option value="<?php echo $dept['department_id']; ?>"><?php echo htmlspecialchars($dept['department_name']); ?></option>
                            <?php endforeach; ?>
                        </select>
                        <div class="absolute inset-y-0 right-0 pr-3 flex items-center pointer-events-none">
                            <i class="fas fa-chevron-down text-gray-dark"></i>
                        </div>
                    </div>
                </div>
            </div>
        </div>

        <!-- Classrooms List -->
        <div class="bg-white rounded-xl shadow-lg p-6 fade-in">
            <div class="flex justify-between items-center mb-6">
                <h3 class="text-xl font-bold text-gray-dark">Classrooms</h3>
                <span class="text-sm font-medium text-gray-dark bg-gray-light px-3 py-1 rounded-full" id="classroomCount"><?php echo count($classrooms); ?> Classrooms</span>
            </div>

            <div id="noResults" class="text-gray-dark text-lg hidden py-8 text-center">
                <i class="fas fa-search text-gray-dark text-2xl mb-2"></i>
                <p>No classrooms found.</p>
            </div>

            <?php if (empty($classrooms)): ?>
                <div class="text-gray-dark text-lg py-10 text-center">
                    <i class="fas fa-school text-gray-dark text-3xl mb-3"></i>
                    <p>No classrooms found in your college.</p>
                </div>
            <?php else: ?>
                <div class="overflow-x-auto">
                    <table class="min-w-full divide-y divide-gray-light" id="classroomsTable">
                        <thead class="bg-gray-50">
                            <tr>
                                <th class="px-6 py-3 text-left text-xs font-semibold text-gray-dark uppercase tracking-wider">Room Name</th>
                                <th class="px-6 py-3 text-left text-xs font-semibold text-gray-dark uppercase tracking-wider">Building</th>
                                <th class="px-6 py-3 text-left text-xs font-semibold text-gray-dark uppercase tracking-wider">Department</th>
                                <th class="px-6 py-3 text-left text-xs font-semibold text-gray-dark uppercase tracking-wider">Capacity</th>
                                <th class="px-6 py-3 text-left text-xs font-semibold text-gray-dark uppercase tracking-wider">Room Type</th>
                                <th class="px-6 py-3 text-left text-xs font-semibold text-gray-dark uppercase tracking-wider">Shared</th>
                                <th class="px-6 py-3 text-left text-xs font-semibold text-gray-dark uppercase tracking-wider">Availability</th>
                                <th class="px-6 py-3 text-left text-xs font-semibold text-gray-dark uppercase tracking-wider">Actions</th>
                            </tr>
                        </thead>
                        <tbody class="bg-white divide-y divide-gray-light">
                            <?php foreach ($classrooms as $index => $classroom): ?>
                                <tr class="hover:bg-gray-50 transition-all duration-200"
                                    data-room-name="<?php echo htmlspecialchars(strtolower($classroom['room_name'])); ?>"
                                    data-building="<?php echo htmlspecialchars(strtolower($classroom['building'])); ?>"
                                    data-department="<?php echo htmlspecialchars(strtolower($classroom['department_name'])); ?>"
                                    data-capacity="<?php echo htmlspecialchars($classroom['capacity']); ?>"
                                    data-department-id="<?php echo htmlspecialchars($classroom['department_id']); ?>">
                                    <td class="px-6 py-4 whitespace-nowrap text-sm font-medium text-gray-dark"><?php echo htmlspecialchars($classroom['room_name']); ?></td>
                                    <td class="px-6 py-4 whitespace-nowrap text-sm text-gray-dark"><?php echo htmlspecialchars($classroom['building']); ?></td>
                                    <td class="px-6 py-4 whitespace-nowrap text-sm text-gray-dark">
                                        <?php echo htmlspecialchars($classroom['department_name']); ?>
                                        <span class="ml-2 inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium bg-gold text-white">
                                            <i class="fas fa-graduation-cap mr-1"></i>Your College
                                        </span>
                                    </td>
                                    <td class="px-6 py-4 whitespace-nowrap text-sm text-gray-dark">
                                        <span class="inline-flex items-center">
                                            <i class="fas fa-users text-gray-dark mr-1.5"></i>
                                            <?php echo htmlspecialchars($classroom['capacity']); ?>
                                        </span>
                                    </td>
                                    <td class="px-6 py-4 whitespace-nowrap text-sm text-gray-dark"><?php echo htmlspecialchars(ucfirst($classroom['room_type'])); ?></td>
                                    <td class="px-6 py-4 whitespace-nowrap text-sm text-gray-dark">
                                        <?php echo $classroom['shared'] ? '<i class="fas fa-check text-green-500"></i> Yes' : '<i class="fas fa-times text-red-500"></i> No'; ?>
                                    </td>
                                    <td class="px-6 py-4 whitespace-nowrap text-sm text-gray-dark">
                                        <form action="/dean/classroom" method="POST" class="inline">
                                            <input type="hidden" name="room_id" value="<?php echo $classroom['room_id']; ?>">
                                            <input type="hidden" name="current_availability" value="<?php echo $classroom['availability']; ?>">
                                            <button type="submit" name="toggle_availability"
                                                class="px-3 py-1 rounded text-white text-xs font-medium <?php echo $classroom['availability'] === 'available' ? 'bg-green-500 hover:bg-green-600' : ($classroom['availability'] === 'unavailable' ? 'bg-red-500 hover:bg-red-600' : 'bg-orange-500 hover:bg-orange-600'); ?> transition-all duration-200 group relative"
                                                title="Change to <?php echo $classroom['availability'] === 'available' ? 'Unavailable' : ($classroom['availability'] === 'unavailable' ? 'Under Maintenance' : 'Available'); ?>">
                                                <?php echo htmlspecialchars(ucfirst($classroom['availability'])); ?>
                                                <span class="tooltip absolute bg-gray-dark text-white text-xs rounded py-1 px-2 -top-8 left-1/2 transform -translate-x-1/2">
                                                    Change to <?php echo $classroom['availability'] === 'available' ? 'Unavailable' : ($classroom['availability'] === 'unavailable' ? 'Under Maintenance' : 'Available'); ?>
                                                </span>
                                            </button>
                                        </form>
                                    </td>
                                    <td class="px-6 py-4 whitespace-nowrap text-sm">
                                        <button class="editClassroomBtn btn-gold px-3 py-1 rounded shadow-md hover:shadow-lg transition-all duration-200 group relative"
                                            data-room-id="<?php echo $classroom['room_id']; ?>"
                                            data-room-name="<?php echo htmlspecialchars($classroom['room_name']); ?>"
                                            data-building="<?php echo htmlspecialchars($classroom['building']); ?>"
                                            data-department-id="<?php echo $classroom['department_id']; ?>"
                                            data-capacity="<?php echo htmlspecialchars($classroom['capacity']); ?>"
                                            data-room-type="<?php echo htmlspecialchars($classroom['room_type']); ?>"
                                            data-shared="<?php echo $classroom['shared']; ?>"
                                            data-availability="<?php echo htmlspecialchars($classroom['availability']); ?>"
                                            title="Edit Classroom">
                                            Edit
                                            <span class="tooltip absolute bg-gray-dark text-white text-xs rounded py-1 px-2 -top-8 left-1/2 transform -translate-x-1/2">Edit Classroom</span>
                                        </button>
                                    </td>
                                </tr>
                            <?php endforeach; ?>
                        </tbody>
                    </table>
                </div>
            <?php endif; ?>
        </div>

        <!-- Room Reservations -->
        <div class="bg-white rounded-xl shadow-lg p-6 mt-8 fade-in">
            <div class="flex justify-between items-center mb-6">
                <h3 class="text-xl font-bold text-gray-dark">Pending Room Reservations</h3>
                <span class="text-sm font-medium text-gray-dark bg-gray-light px-3 py-1 rounded-full"><?php echo count($reservations); ?> Pending</span>
            </div>

            <?php if (empty($reservations)): ?>
                <div class="text-gray-dark text-lg py-10 text-center">
                    <i class="fas fa-calendar-times text-gray-dark text-3xl mb-3"></i>
                    <p>No pending room reservations.</p>
                </div>
            <?php else: ?>
                <div class="overflow-x-auto">
                    <table class="min-w-full divide-y divide-gray-light">
                        <thead class="bg-gray-50">
                            <tr>
                                <th class="px-6 py-3 text-left text-xs font-semibold text-gray-dark uppercase tracking-wider">Room</th>
                                <th class="px-6 py-3 text-left text-xs font-semibold text-gray-dark uppercase tracking-wider">Requested By</th>
                                <th class="px-6 py-3 text-left text-xs font-semibold text-gray-dark uppercase tracking-wider">Purpose</th>
                                <th class="px-6 py-3 text-left text-xs font-semibold text-gray-dark uppercase tracking-wider">Date & Time</th>
                                <th class="px-6 py-3 text-left text-xs font-semibold text-gray-dark uppercase tracking-wider">Actions</th>
                            </tr>
                        </thead>
                        <tbody class="bg-white divide-y divide-gray-light">
                            <?php foreach ($reservations as $index => $reservation): ?>
                                <tr class="hover:bg-gray-50 transition-all duration-200">
                                    <td class="px-6 py-4 whitespace-nowrap text-sm text-gray-dark"><?php echo htmlspecialchars($reservation['room_name']); ?></td>
                                    <td class="px-6 py-4 whitespace-nowrap text-sm text-gray-dark"><?php echo htmlspecialchars($reservation['first_name'] . ' ' . $reservation['last_name']); ?></td>
                                    <td class="px-6 py-4 whitespace-nowrap text-sm text-gray-dark"><?php echo htmlspecialchars($reservation['description']); ?></td>
                                    <td class="px-6 py-4 whitespace-nowrap text-sm text-gray-dark">
                                        <?php echo htmlspecialchars(date('M d, Y', strtotime($reservation['start_time'])) . ' ' . date('h:i A', strtotime($reservation['start_time'])) . ' - ' . date('h:i A', strtotime($reservation['end_time']))); ?>
                                    </td>
                                    <td class="px-6 py-4 whitespace-nowrap text-sm">
                                        <form action="/dean/classroom" method="POST" class="inline">
                                            <input type="hidden" name="reservation_id" value="<?php echo $reservation['reservation_id']; ?>">
                                            <input type="hidden" name="status" value="Approved">
                                            <button type="submit" class="bg-green-500 text-white px-3 py-1 rounded hover:bg-green-600 group relative" title="Approve Reservation">
                                                Approve
                                                <span class="tooltip absolute bg-gray-dark text-white text-xs rounded py-1 px-2 -top-8 left-1/2 transform -translate-x-1/2">Approve Reservation</span>
                                            </button>
                                        </form>
                                        <form action="/dean/classroom" method="POST" class="inline ml-2">
                                            <input type="hidden" name="reservation_id" value="<?php echo $reservation['reservation_id']; ?>">
                                            <input type="hidden" name="status" value="Rejected">
                                            <button type="submit" class="bg-red-500 text-white px-3 py-1 rounded hover:bg-red-600 group relative" title="Reject Reservation">
                                                Reject
                                                <span class="tooltip absolute bg-gray-dark text-white text-xs rounded py-1 px-2 -top-8 left-1/2 transform -translate-x-1/2">Reject Reservation</span>
                                            </button>
                                        </form>
                                    </td>
                                </tr>
                            <?php endforeach; ?>
                        </tbody>
                    </table>
                </div>
            <?php endif; ?>
        </div>
    </div>

    <!-- JavaScript for Toast Notifications and Functionality -->
    <script>
        document.addEventListener('DOMContentLoaded', () => {
            // Toast Notifications
            <?php if ($success): ?>
                showToast('<?php echo $success; ?>', 'bg-green-500');
            <?php endif; ?>
            <?php if ($error): ?>
                showToast('<?php echo $error; ?>', 'bg-red-500');
            <?php endif; ?>

            function showToast(message, bgColor) {
                const toast = document.createElement('div');
                toast.className = `toast ${bgColor} text-white px-4 py-2 rounded-lg shadow-lg`;
                toast.textContent = message;
                toast.setAttribute('role', 'alert');
                document.getElementById('toast-container').appendChild(toast);
                setTimeout(() => {
                    toast.style.opacity = '0';
                    setTimeout(() => toast.remove(), 300);
                }, 5000);
            }

            // Add Classroom Modal
            const addModal = document.getElementById('addClassroomModal');
            const openModalBtn = document.getElementById('openModalBtn');
            const closeModalBtn = document.getElementById('closeModalBtn');
            const cancelModalBtn = document.getElementById('cancelModalBtn');
            const addModalContent = addModal.querySelector('.modal-content');

            // Edit Classroom Modal
            const editModal = document.getElementById('editClassroomModal');
            const closeEditModalBtn = document.getElementById('closeEditModalBtn');
            const cancelEditModalBtn = document.getElementById('cancelEditModalBtn');
            const editModalContent = editModal.querySelector('.modal-content');
            const editClassroomButtons = document.querySelectorAll('.editClassroomBtn');

            // Open Add Modal
            openModalBtn.addEventListener('click', () => {
                addModal.classList.remove('hidden');
                addModalContent.classList.remove('scale-95');
                addModalContent.classList.add('scale-100');
                document.body.style.overflow = 'hidden';
            });

            // Close Add Modal
            const closeAddModal = () => {
                addModalContent.classList.remove('scale-100');
                addModalContent.classList.add('scale-95');
                setTimeout(() => {
                    addModal.classList.add('hidden');
                    document.body.style.overflow = 'auto';
                    document.getElementById('addClassroomForm').reset();
                    document.querySelectorAll('#addClassroomForm .error-message').forEach(msg => msg.classList.add('hidden'));
                    document.querySelectorAll('#addClassroomForm input, #addClassroomForm select').forEach(input => input.classList.remove('border-red-500'));
                }, 200);
            };

            closeModalBtn.addEventListener('click', closeAddModal);
            cancelModalBtn.addEventListener('click', closeAddModal);

            // Open Edit Modal
            editClassroomButtons.forEach(button => {
                button.addEventListener('click', () => {
                    const roomId = button.dataset.roomId;
                    const roomName = button.dataset.roomName;
                    const building = button.dataset.building;
                    const departmentId = button.dataset.departmentId;
                    const capacity = button.dataset.capacity;
                    const roomType = button.dataset.roomType;
                    const shared = button.dataset.shared === '1';
                    const availability = button.dataset.availability;

                    document.getElementById('edit_room_id').value = roomId;
                    document.getElementById('edit_room_name').value = roomName;
                    document.getElementById('edit_building').value = building;
                    document.getElementById('edit_department_id').value = departmentId;
                    document.getElementById('edit_capacity').value = capacity;
                    document.getElementById('edit_room_type').value = roomType;
                    document.getElementById('edit_shared').checked = shared;
                    document.getElementById('edit_availability').value = availability;

                    editModal.classList.remove('hidden');
                    editModalContent.classList.remove('scale-95');
                    editModalContent.classList.add('scale-100');
                    document.body.style.overflow = 'hidden';
                });
            });

            // Close Edit Modal
            const closeEditModal = () => {
                editModalContent.classList.remove('scale-100');
                editModalContent.classList.add('scale-95');
                setTimeout(() => {
                    editModal.classList.add('hidden');
                    document.body.style.overflow = 'auto';
                    document.getElementById('editClassroomForm').reset();
                    document.querySelectorAll('#editClassroomForm .error-message').forEach(msg => msg.classList.add('hidden'));
                    document.querySelectorAll('#editClassroomForm input, #editClassroomForm select').forEach(input => input.classList.remove('border-red-500'));
                }, 200);
            };

            closeEditModalBtn.addEventListener('click', closeEditModal);
            cancelEditModalBtn.addEventListener('click', closeEditModal);

            // Close modals on backdrop click
            addModal.addEventListener('click', (e) => {
                if (e.target === addModal) closeAddModal();
            });
            editModal.addEventListener('click', (e) => {
                if (e.target === editModal) closeEditModal();
            });

            // Close modals on ESC key
            document.addEventListener('keydown', (e) => {
                if (e.key === 'Escape') {
                    if (!addModal.classList.contains('hidden')) closeAddModal();
                    if (!editModal.classList.contains('hidden')) closeEditModal();
                }
            });

            // Form validation for both modals
            ['addClassroomForm', 'editClassroomForm'].forEach(formId => {
                const form = document.getElementById(formId);
                form.addEventListener('submit', (e) => {
                    let isValid = true;
                    form.querySelectorAll('input[required], select[required]').forEach(input => {
                        const errorMessage = input.nextElementSibling;
                        if (!input.value.trim()) {
                            input.classList.add('border-red-500');
                            errorMessage.classList.remove('hidden');
                            isValid = false;
                        } else {
                            input.classList.remove('border-red-500');
                            errorMessage.classList.add('hidden');
                        }
                    });

                    const capacityInput = form.querySelector('[name="capacity"]');
                    const capacityError = capacityInput.nextElementSibling;
                    if (capacityInput.value < 1) {
                        capacityInput.classList.add('border-red-500');
                        capacityError.classList.remove('hidden');
                        isValid = false;
                    } else {
                        capacityInput.classList.remove('border-red-500');
                        capacityError.classList.add('hidden');
                    }

                    if (!isValid) e.preventDefault();
                });

                form.querySelectorAll('input[required], select[required]').forEach(input => {
                    input.addEventListener('input', () => {
                        const errorMessage = input.nextElementSibling;
                        if (input.value.trim()) {
                            input.classList.remove('border-red-500');
                            errorMessage.classList.add('hidden');
                        }
                    });
                });

                form.querySelector('[name="capacity"]').addEventListener('input', function() {
                    const errorMessage = this.nextElementSibling;
                    if (this.value >= 1) {
                        this.classList.remove('border-red-500');
                        errorMessage.classList.add('hidden');
                    }
                });
            });

            // Search and filter functionality
            const searchInput = document.getElementById('searchClassrooms');
            const clearSearchBtn = document.getElementById('clearSearch');
            const departmentFilter = document.getElementById('departmentFilter');
            const classroomsTable = document.getElementById('classroomsTable');
            const noResults = document.getElementById('noResults');
            const classroomCount = document.getElementById('classroomCount');
            const rows = classroomsTable ? classroomsTable.querySelectorAll('tbody tr') : [];

            const updateTable = () => {
                const query = searchInput.value.trim().toLowerCase();
                const selectedDepartment = departmentFilter.value;
                let visibleRows = 0;

                rows.forEach(row => {
                    const roomName = row.dataset.roomName;
                    const building = row.dataset.building;
                    const department = row.dataset.department;
                    const capacity = row.dataset.capacity;
                    const departmentId = row.dataset.departmentId;

                    const matchesSearch = query === '' ||
                        roomName.includes(query) ||
                        building.includes(query) ||
                        department.includes(query) ||
                        capacity.includes(query);

                    const matchesDepartment = selectedDepartment === '' || departmentId === selectedDepartment;

                    const matches = matchesSearch && matchesDepartment;

                    row.style.display = matches ? '' : 'none';
                    if (matches) visibleRows++;
                });

                clearSearchBtn.classList.toggle('hidden', query === '');
                noResults.classList.toggle('hidden', visibleRows > 0);
                classroomCount.textContent = `${visibleRows} Classrooms`;
            };

            searchInput.addEventListener('input', updateTable);
            departmentFilter.addEventListener('change', updateTable);

            clearSearchBtn.addEventListener('click', () => {
                searchInput.value = '';
                departmentFilter.value = '';
                rows.forEach(row => row.style.display = '');
                clearSearchBtn.classList.add('hidden');
                noResults.classList.add('hidden');
                classroomCount.textContent = `${rows.length} Classrooms`;
            });

            // Trigger initial table update
            updateTable();
        });
    </script>
</body>

</html>

<?php
$content = ob_get_clean();
require_once __DIR__ . '/layout.php';
?>