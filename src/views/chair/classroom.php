<?php
require_once __DIR__ . '/../../controllers/ChairController.php';

// Define BASE_URL for your environment (e.g., '/myapp' for subdirectories, '' for root)
define('BASE_URL', ''); // Adjust this based on your server setup

ini_set('display_errors', 0); // Disable display_errors in production
ini_set('display_startup_errors', 0);
error_reporting(E_ALL);
ob_start();

// Initialize variables with defaults
$searchTerm = $_GET['search'] ?? '';
$error = $error ?? null;
$success = $success ?? null;
$classrooms = $classrooms ?? [];
$departmentInfo = $departmentInfo ?? null;
$departments = $departments ?? [];

$controller = new ChairController();
$db = $controller->db;

ob_start();
?>

<!DOCTYPE html>
<html lang="en">

<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Manage Classrooms</title>
    <style>
        :root {
            --white: #FFFFFF;
            --yellow: #FFC107;
            --dark-gray: #333333;
            --gray-light: #E5E7EB;
        }

        .bg-white {
            background-color: var(--white) !important;
        }

        .bg-yellow {
            background-color: var(--yellow) !important;
        }

        .bg-dark-gray {
            background-color: var(--dark-gray) !important;
        }

        .text-dark-gray {
            color: var(--dark-gray) !important;
        }

        .text-yellow {
            color: var(--yellow) !important;
        }

        .border-dark-gray {
            border-color: var(--dark-gray) !important;
        }

        .focus:ring-yellow {
            --tw-ring-color: var(--yellow) !important;
        }

        .hover:bg-yellow {
            background-color: var(--yellow) !important;
        }

        .hover:text-white {
            color: var(--white) !important;
        }

        .input-group input,
        .input-group select {
            padding-left: 3rem !important;
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
            background-color: rgba(0, 0, 0, 0.5);
            transition: opacity 0.3s ease;
        }

        .modal.hidden {
            opacity: 0;
            pointer-events: none;
        }

        .modal-content {
            transition: transform 0.3s ease;
        }

        .suggestions {
            position: absolute;
            top: 100%;
            left: 0;
            right: 0;
            background: var(--white);
            border: 1px solid var(--gray-light);
            border-radius: 0.5rem;
            box-shadow: 0 4px 6px rgba(0, 0, 0, 0.1);
            max-height: 200px;
            overflow-y: auto;
            z-index: 10;
        }

        .suggestion-item {
            padding: 0.75rem 1rem;
            cursor: pointer;
            transition: background-color 0.2s ease;
        }

        .suggestion-item:hover {
            background-color: rgba(255, 193, 7, 0.1);
        }

        .loading::after {
            content: '';
            display: inline-block;
            width: 16px;
            height: 16px;
            border: 2px solid var(--yellow);
            border-top-color: transparent;
            border-radius: 50%;
            animation: spin 0.8s linear infinite;
            margin-left: 8px;
        }

        @keyframes spin {
            to {
                transform: rotate(360deg);
            }
        }

        .tooltip {
            display: none;
        }

        .group:hover .tooltip {
            display: block;
        }
    </style>
</head>

<body class="bg-white font-sans antialiased">
    <div id="toast-container" class="fixed top-5 right-5 z-50"></div>

    <div class="container mx-auto px-4 py-8">
        <h1 class="text-3xl font-bold text-dark-gray mb-8 fade-in">Classrooms Management</h1>

        <?php if ($error): ?>
            <div class="bg-red-100 border border-red-400 text-red-700 px-4 py-3 rounded-lg mb-6 animate-fade-in">
                <?= htmlspecialchars($error) ?>
            </div>
        <?php endif; ?>
        <?php if ($success): ?>
            <div class="bg-green-100 border border-green-400 text-green-700 px-4 py-3 rounded-lg mb-6 animate-fade-in">
                <?= htmlspecialchars($success) ?>
            </div>
        <?php endif; ?>

        <!-- Search and Add Classroom Buttons -->
        <div class="flex flex-col sm:flex-row justify-between items-center gap-4 mb-6 fade-in">
            <div class="w-full sm:w-1/2">
                <div class="relative">
                    <i class="fas fa-search absolute left-3 top-1/2 transform -translate-y-1/2 text-dark-gray"></i>
                    <input type="text" id="searchInput" name="search" value="<?= htmlspecialchars($searchTerm) ?>"
                        placeholder="Search shared rooms..."
                        class="pl-10 w-full px-4 py-2.5 border border-dark-gray rounded-lg focus:ring-2 focus:ring-yellow focus:border-yellow transition-all"
                        autocomplete="off">
                    <span id="search-feedback" class="ml-3 text-sm font-medium"></span>
                </div>
                <div id="suggestions" class="suggestions hidden"></div>
            </div>
            <div class="flex gap-4">
                <button onclick="openModal('addClassroomModal')"
                    class="px-6 py-3 bg-dark-gray text-white rounded-lg font-medium shadow-lg hover:bg-yellow hover:text-dark-gray transition-colors duration-300 flex items-center gap-2">
                    <i class="fas fa-plus"></i>
                    Add Classroom
                </button>
            </div>
        </div>

        <!-- Search Results -->
        <div id="search-results" class="mb-6"></div>

        <!-- Classrooms Table -->
        <div class="bg-white rounded-lg shadow-md overflow-hidden fade-in">
            <div class="bg-dark-gray text-white px-6 py-4">
                <h5 class="text-xl font-semibold">Your Department's Classrooms</h5>
            </div>
            <div class="p-6">
                <?php if (empty($classrooms)): ?>
                    <div class="text-center py-12 text-dark-gray">
                        <i class="fas fa-door-open text-4xl mb-4"></i>
                        <p class="text-lg font-medium">No classrooms found.</p>
                        <p class="text-sm mt-1">Add a classroom or search for shared rooms to include.</p>
                    </div>
                <?php else: ?>
                    <div class="overflow-x-auto">
                        <table id="classroomsTable" class="w-full table-auto">
                            <thead class="bg-yellow bg-opacity-10">
                                <tr>
                                    <th class="px-4 py-3 text-left text-sm font-medium text-dark-gray">Room Name</th>
                                    <th class="px-4 py-3 text-left text-sm font-medium text-dark-gray">Building</th>
                                    <th class="px-4 py-3 text-left text-sm font-medium text-dark-gray">Capacity</th>
                                    <th class="px-4 py-3 text-left text-sm font-medium text-dark-gray">Room Type</th>
                                    <th class="px-4 py-3 text-left text-sm font-medium text-dark-gray">Department</th>
                                    <th class="px-4 py-3 text-left text-sm font-medium text-dark-gray">College</th>
                                    <th class="px-4 py-3 text-left text-sm font-medium text-dark-gray">Status</th>
                                    <th class="px-4 py-3 text-left text-sm font-medium text-dark-gray">Shared</th>
                                    <th class="px-4 py-3 text-left text-sm font-medium text-dark-gray">Access</th>
                                    <th class="px-4 py-3 text-left text-sm font-medium text-dark-gray">Usage</th>
                                    <th class="px-4 py-3 text-left text-sm font-medium text-dark-gray">Actions</th>
                                </tr>
                            </thead>
                            <tbody class="divide-y divide-dark-gray divide-opacity-20">
                                <?php foreach ($classrooms as $classroom): ?>
                                    <tr class="hover:bg-yellow hover:bg-opacity-10 transition-colors"
                                        data-search="<?= htmlspecialchars(strtolower($classroom['room_name'] . ' ' . $classroom['building'] . ' ' . ($classroom['department_name'] ?? ''))) ?>">
                                        <td class="px-4 py-3 text-sm text-dark-gray font-medium">
                                            <?= htmlspecialchars($classroom['room_name']) ?>
                                        </td>
                                        <td class="px-4 py-3 text-sm text-dark-gray">
                                            <?= htmlspecialchars($classroom['building']) ?>
                                        </td>
                                        <td class="px-4 py-3 text-sm text-dark-gray">
                                            <?= htmlspecialchars($classroom['capacity']) ?>
                                        </td>
                                        <td class="px-4 py-3 text-sm text-dark-gray">
                                            <?= htmlspecialchars(ucfirst($classroom['room_type'])) ?>
                                        </td>
                                        <td class="px-4 py-3 text-sm text-dark-gray">
                                            <?= htmlspecialchars($classroom['department_name'] ?? 'N/A') ?>
                                        </td>
                                        <td class="px-4 py-3 text-sm text-dark-gray">
                                            <?= htmlspecialchars($classroom['college_name'] ?? 'N/A') ?>
                                        </td>
                                        <td class="px-4 py-3">
                                            <span class="inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium <?= $classroom['availability'] === 'available' ? 'bg-green-100 text-green-800' : ($classroom['availability'] === 'unavailable' ? 'bg-red-100 text-red-800' : 'bg-yellow text-dark-gray') ?>">
                                                <?= htmlspecialchars(ucfirst($classroom['availability'])) ?>
                                            </span>
                                        </td>
                                        <td class="px-4 py-3 text-sm text-dark-gray">
                                            <?= $classroom['shared'] ? 'Yes' : 'No' ?>
                                        </td>
                                        <td class="px-4 py-3 text-sm text-dark-gray">
                                            <?= htmlspecialchars($classroom['room_status']) ?>
                                        </td>
                                        <td class="px-4 py-3 text-sm text-dark-gray">
                                            <?= htmlspecialchars($classroom['current_semester_usage']) ?> schedules
                                        </td>
                                        <td class="px-4 py-3 space-x-2">
                                            <?php if ($classroom['room_status'] === 'Owned'): ?>
                                                <button class="edit-classroom-btn text-yellow hover:text-dark-gray focus:outline-none"
                                                    data-classroom='<?= json_encode($classroom) ?>'>
                                                    <i class="fas fa-edit"></i>
                                                </button>
                                            <?php elseif ($classroom['room_status'] === 'Included'): ?>
                                                <button class="remove-btn text-red-600 group relative hover:text-red-700 transition-all duration-200"
                                                    data-id="<?= htmlspecialchars($classroom['room_id']) ?>"
                                                    data-name="<?= htmlspecialchars($classroom['room_name']) ?>">
                                                    <i class="fa-solid fa-xmark"></i>
                                                    <span class="tooltip absolute bg-dark-gray text-white text-xs rounded py-1 px-2 -top-8 left-1/2 transform -translate-x-1/2">Remove Room</span>
                                                </button>
                                            <?php endif; ?>
                                        </td>
                                    </tr>
                                <?php endforeach; ?>
                            </tbody>
                        </table>
                    </div>
                <?php endif; ?>
            </div>
        </div>

        <!-- Add Classroom Modal -->
        <div id="addClassroomModal" class="modal hidden fixed inset-0 z-50 bg-black bg-opacity-50 flex items-center justify-center p-4">
            <div class="modal-content bg-white rounded-lg shadow-xl w-full max-w-2xl max-h-[90vh] overflow-y-auto">
                <div class="bg-dark-gray text-white px-6 py-4 rounded-t-lg flex justify-between items-center sticky top-0 z-10">
                    <h5 class="text-xl font-semibold">Add New Classroom</h5>
                    <button onclick="closeModal('addClassroomModal')" class="text-white hover:text-yellow transition-colors focus:outline-none text-2xl" aria-label="Close modal">
                        &times;
                    </button>
                </div>
                <div class="p-6">
                    <form id="addClassroomForm" method="POST" class="space-y-6">
                        <input type="hidden" name="action" value="add">
                        <?php if ($departmentInfo): ?>
                            <div class="bg-yellow bg-opacity-10 p-4 rounded-lg border border-yellow">
                                <p class="text-sm text-dark-gray">
                                    <span class="font-medium">Department Assignment:</span><br>
                                    <?= htmlspecialchars($departmentInfo['department_name']) ?>
                                    (<?= htmlspecialchars($departmentInfo['college_name']) ?>)
                                </p>
                            </div>
                        <?php endif; ?>
                        <div class="grid grid-cols-1 md:grid-cols-2 gap-6">
                            <div class="input-group">
                                <label for="room_name" class="block text-dark-gray font-medium mb-2">Room Name <span class="text-yellow">*</span></label>
                                <div class="relative">
                                    <div class="absolute inset-y-0 left-0 pl-3 flex items-center pointer-events-none text-dark-gray">
                                        <i class="fas fa-door-open"></i>
                                    </div>
                                    <input type="text" id="room_name" name="room_name" required
                                        class="pl-12 w-full px-4 py-2.5 border border-dark-gray rounded-lg focus:ring-2 focus:ring-yellow focus:border-yellow transition-all">
                                </div>
                            </div>
                            <div class="input-group">
                                <label for="building" class="block text-dark-gray font-medium mb-2">Building <span class="text-yellow">*</span></label>
                                <div class="relative">
                                    <div class="absolute inset-y-0 left-0 pl-3 flex items-center pointer-events-none text-dark-gray">
                                        <i class="fas fa-building"></i>
                                    </div>
                                    <input type="text" id="building" name="building" required
                                        class="pl-12 w-full px-4 py-2.5 border border-dark-gray rounded-lg focus:ring-2 focus:ring-yellow focus:border-yellow transition-all">
                                </div>
                            </div>
                            <div class="input-group">
                                <label for="capacity" class="block text-dark-gray font-medium mb-2">Capacity <span class="text-yellow">*</span></label>
                                <div class="relative">
                                    <div class="absolute inset-y-0 left-0 pl-3 flex items-center pointer-events-none text-dark-gray">
                                        <i class="fas fa-users"></i>
                                    </div>
                                    <input type="number" id="capacity" name="capacity" min="1" required
                                        class="pl-12 w-full px-4 py-2.5 border border-dark-gray rounded-lg focus:ring-2 focus:ring-yellow focus:border-yellow transition-all">
                                </div>
                            </div>
                            <div class="input-group">
                                <label for="room_type" class="block text-dark-gray font-medium mb-2">Room Type <span class="text-yellow">*</span></label>
                                <div class="relative">
                                    <div class="absolute inset-y-0 left-0 pl-3 flex items-center pointer-events-none text-dark-gray">
                                        <i class="fas fa-chalkboard"></i>
                                    </div>
                                    <select id="room_type" name="room_type" required
                                        class="pl-12 w-full px-4 py-2.5 border border-dark-gray rounded-lg focus:ring-2 focus:ring-yellow focus:border-yellow appearance-none bg-white">
                                        <option value="">Select Room Type</option>
                                        <option value="lecture">Lecture Room</option>
                                        <option value="laboratory">Laboratory</option>
                                        <option value="avr">AVR/Multimedia Room</option>
                                        <option value="seminar_room">Seminar Room</option>
                                    </select>
                                </div>
                            </div>
                            <div class="input-group">
                                <label class="block text-dark-gray font-medium mb-2">Sharing Options</label>
                                <label class="inline-flex items-center space-x-3 cursor-pointer">
                                    <div class="relative">
                                        <input type="checkbox" name="shared" value="1" class="sr-only peer">
                                        <div class="w-11 h-6 bg-gray-200 rounded-full peer peer-checked:after:translate-x-full peer-checked:after:border-white after:content-[''] after:absolute after:top-0.5 after:left-[2px] after:bg-white after:border-dark-gray after:border after:rounded-full after:h-5 after:w-5 after:transition-all peer-checked:bg-dark-gray"></div>
                                    </div>
                                    <span class="text-dark-gray">Share with all colleges</span>
                                </label>
                            </div>
                            <div class="input-group">
                                <label for="availability" class="block text-dark-gray font-medium mb-2">Status <span class="text-yellow">*</span></label>
                                <div class="relative">
                                    <div class="absolute inset-y-0 left-0 pl-3 flex items-center pointer-events-none text-dark-gray">
                                        <i class="fas fa-calendar-check"></i>
                                    </div>
                                    <select id="availability" name="availability" required
                                        class="pl-12 w-full px-4 py-2.5 border border-dark-gray rounded-lg focus:ring-2 focus:ring-yellow focus:border-yellow appearance-none bg-white">
                                        <option value="available">Available</option>
                                        <option value="unavailable">Unavailable</option>
                                        <option value="under_maintenance">Under Maintenance</option>
                                    </select>
                                </div>
                            </div>
                        </div>
                        <div class="mt-8 flex justify-end space-x-3">
                            <button type="button" onclick="closeModal('addClassroomModal')"
                                class="px-6 py-2.5 bg-white border border-dark-gray text-dark-gray rounded-lg font-medium hover:bg-yellow hover:text-white focus:outline-none focus:ring-2 focus:ring-yellow focus:ring-offset-2 transition-colors">
                                Cancel
                            </button>
                            <button type="submit"
                                class="px-6 py-2.5 bg-dark-gray text-white rounded-lg font-medium shadow-sm hover:bg-yellow focus:outline-none focus:ring-2 focus:ring-yellow focus:ring-offset-2 transition-colors flex items-center space-x-2">
                                <i class="fas fa-plus"></i>
                                <span>Add Classroom</span>
                            </button>
                        </div>
                    </form>
                </div>
            </div>
        </div>

        <!-- Edit Classroom Modal -->
        <div id="editClassroomModal" class="modal hidden fixed inset-0 z-50 bg-black bg-opacity-50 flex items-center justify-center p-4">
            <div class="modal-content bg-white rounded-lg shadow-xl w-full max-w-2xl max-h-[90vh] overflow-y-auto">
                <div class="bg-dark-gray text-white px-6 py-4 rounded-t-lg flex justify-between items-center sticky top-0 z-10">
                    <h5 class="text-xl font-semibold">Edit Classroom</h5>
                    <button onclick="closeModal('editClassroomModal')" class="text-white hover:text-yellow transition-colors focus:outline-none text-2xl" aria-label="Close modal">
                        &times;
                    </button>
                </div>
                <div class="p-6">
                    <form id="editClassroomForm" method="POST" class="space-y-6">
                        <input type="hidden" name="action" value="edit">
                        <input type="hidden" id="edit_room_id" name="room_id">
                        <div class="grid grid-cols-1 md:grid-cols-2 gap-6">
                            <div class="input-group">
                                <label for="edit_room_name" class="block text-dark-gray font-medium mb-2">Room Name <span class="text-yellow">*</span></label>
                                <div class="relative">
                                    <div class="absolute inset-y-0 left-0 pl-3 flex items-center pointer-events-none text-dark-gray">
                                        <i class="fas fa-door-open"></i>
                                    </div>
                                    <input type="text" id="edit_room_name" name="room_name" required
                                        class="pl-12 w-full px-4 py-2.5 border border-dark-gray rounded-lg focus:ring-2 focus:ring-yellow focus:border-yellow transition-all">
                                </div>
                            </div>
                            <div class="input-group">
                                <label for="edit_building" class="block text-dark-gray font-medium mb-2">Building <span class="text-yellow">*</span></label>
                                <div class="relative">
                                    <div class="absolute inset-y-0 left-0 pl-3 flex items-center pointer-events-none text-dark-gray">
                                        <i class="fas fa-building"></i>
                                    </div>
                                    <input type="text" id="edit_building" name="building" required
                                        class="pl-12 w-full px-4 py-2.5 border border-dark-gray rounded-lg focus:ring-2 focus:ring-yellow focus:border-yellow transition-all">
                                </div>
                            </div>
                            <div class="input-group">
                                <label for="edit_capacity" class="block text-dark-gray font-medium mb-2">Capacity <span class="text-yellow">*</span></label>
                                <div class="relative">
                                    <div class="absolute inset-y-0 left-0 pl-3 flex items-center pointer-events-none text-dark-gray">
                                        <i class="fas fa-users"></i>
                                    </div>
                                    <input type="number" id="edit_capacity" name="capacity" min="1" required
                                        class="pl-12 w-full px-4 py-2.5 border border-dark-gray rounded-lg focus:ring-2 focus:ring-yellow focus:border-yellow transition-all">
                                </div>
                            </div>
                            <div class="input-group">
                                <label for="edit_room_type" class="block text-dark-gray font-medium mb-2">Room Type <span class="text-yellow">*</span></label>
                                <div class="relative">
                                    <div class="absolute inset-y-0 left-0 pl-3 flex items-center pointer-events-none text-dark-gray">
                                        <i class="fas fa-chalkboard"></i>
                                    </div>
                                    <select id="edit_room_type" name="room_type" required
                                        class="pl-12 w-full px-4 py-2.5 border border-dark-gray rounded-lg focus:ring-2 focus:ring-yellow focus:border-yellow appearance-none bg-white">
                                        <option value="lecture">Lecture Room</option>
                                        <option value="laboratory">Laboratory</option>
                                        <option value="avr">AVR/Multimedia Room</option>
                                        <option value="seminar_room">Seminar Room</option>
                                    </select>
                                </div>
                            </div>
                            <div class="input-group">
                                <label class="block text-dark-gray font-medium mb-2">Sharing Options</label>
                                <label class="inline-flex items-center space-x-3 cursor-pointer">
                                    <div class="relative">
                                        <input type="checkbox" id="edit_shared" name="shared" value="1" class="sr-only peer">
                                        <div class="w-11 h-6 bg-gray-200 rounded-full peer peer-checked:after:translate-x-full peer-checked:after:border-white after:content-[''] after:absolute after:top-0.5 after:left-[2px] after:bg-white after:border-dark-gray after:border after:rounded-full after:h-5 after:w-5 after:transition-all peer-checked:bg-dark-gray"></div>
                                    </div>
                                    <span class="text-dark-gray">Share with all colleges</span>
                                </label>
                            </div>
                            <div class="input-group">
                                <label for="edit_availability" class="block text-dark-gray font-medium mb-2">Status <span class="text-yellow">*</span></label>
                                <div class="relative">
                                    <div class="absolute inset-y-0 left-0 pl-3 flex items-center pointer-events-none text-dark-gray">
                                        <i class="fas fa-calendar-check"></i>
                                    </div>
                                    <select id="edit_availability" name="availability" required
                                        class="pl-12 w-full px-4 py-2.5 border border-dark-gray rounded-lg focus:ring-2 focus:ring-yellow focus:border-yellow appearance-none bg-white">
                                        <option value="available">Available</option>
                                        <option value="unavailable">Unavailable</option>
                                        <option value="under_maintenance">Under Maintenance</option>
                                    </select>
                                </div>
                            </div>
                        </div>
                        <div class="mt-8 flex justify-end space-x-3">
                            <button type="button" onclick="closeModal('editClassroomModal')"
                                class="px-6 py-2.5 bg-white border border-dark-gray text-dark-gray rounded-lg font-medium hover:bg-yellow hover:text-white focus:outline-none focus:ring-2 focus:ring-yellow focus:ring-offset-2 transition-colors">
                                Cancel
                            </button>
                            <button type="submit"
                                class="px-6 py-2.5 bg-dark-gray text-white rounded-lg font-medium shadow-sm hover:bg-yellow focus:outline-none focus:ring-2 focus:ring-yellow focus:ring-offset-2 transition-colors flex items-center space-x-2">
                                <i class="fas fa-save"></i>
                                <span>Save Changes</span>
                            </button>
                        </div>
                    </form>
                </div>
            </div>
        </div>

        <!-- Include Room Modal -->
        <div id="includeRoomModal" class="modal hidden fixed inset-0 z-50 bg-black bg-opacity-50 flex items-center justify-center p-4">
            <div class="modal-content bg-white rounded-lg shadow-xl w-full max-w-md">
                <div class="bg-dark-gray text-white px-6 py-4 rounded-t-lg flex justify-between items-center">
                    <h5 class="text-xl font-semibold">Include Shared Room</h5>
                    <button onclick="closeModal('includeRoomModal')" class="text-white hover:text-yellow transition-colors focus:outline-none text-2xl" aria-label="Close modal">
                        &times;
                    </button>
                </div>
                <div class="p-6">
                    <p class="text-dark-gray mb-6">Are you sure you want to include <strong id="modal-room-name"></strong> in your department?</p>
                    <input type="hidden" id="modal-room-id" name="room_id">
                    <div class="flex justify-end space-x-3">
                        <button onclick="closeModal('includeRoomModal')"
                            class="px-6 py-2.5 bg-white border border-dark-gray text-dark-gray rounded-lg font-medium hover:bg-yellow hover:text-white focus:outline-none focus:ring-2 focus:ring-yellow focus:ring-offset-2 transition-colors">
                            Cancel
                        </button>
                        <button id="confirmIncludeBtn"
                            class="px-6 py-2.5 bg-dark-gray text-white rounded-lg font-medium shadow-sm hover:bg-yellow focus:outline-none focus:ring-2 focus:ring-yellow focus:ring-offset-2 transition-colors flex items-center space-x-2">
                            <i class="fas fa-plus"></i>
                            <span>Confirm</span>
                        </button>
                    </div>
                </div>
            </div>
        </div>

        <!-- Remove Room Modal -->
        <div id="removeRoomModal" class="modal hidden fixed inset-0 z-50 bg-black bg-opacity-50 flex items-center justify-center p-4">
            <div class="modal-content bg-white rounded-lg shadow-xl w-full max-w-md">
                <div class="bg-dark-gray text-white px-6 py-4 rounded-t-lg flex justify-between items-center">
                    <h5 class="text-xl font-semibold">Remove Shared Room</h5>
                    <button onclick="closeModal('removeRoomModal')" class="text-white hover:text-yellow transition-colors focus:outline-none text-2xl" aria-label="Close modal">
                        &times;
                    </button>
                </div>
                <div class="p-6">
                    <p class="text-dark-gray mb-6">Are you sure you want to remove <strong id="remove-modal-room-name"></strong> from your department?</p>
                    <input type="hidden" id="remove-modal-room-id" name="room_id">
                    <div class="flex justify-end space-x-3">
                        <button onclick="closeModal('removeRoomModal')"
                            class="px-6 py-2.5 bg-white border border-dark-gray text-dark-gray rounded-lg font-medium hover:bg-yellow hover:text-white focus:outline-none focus:ring-2 focus:ring-yellow focus:ring-offset-2 transition-colors">
                            Cancel
                        </button>
                        <button id="confirmRemoveBtn"
                            class="px-6 py-2.5 bg-red-600 text-white rounded-lg font-medium shadow-sm hover:bg-red-700 focus:outline-none focus:ring-2 focus:ring-red-500 focus:ring-offset-2 transition-colors flex items-center space-x-2">
                            <i class="fas fa-trash"></i>
                            <span>Confirm</span>
                        </button>
                    </div>
                </div>
            </div>
        </div>
    </div>

    <script>
        function openModal(modalId) {
            const modal = document.getElementById(modalId);
            if (!modal) {
                console.error(`Modal with ID ${modalId} not found`);
                return;
            }
            modal.classList.remove('hidden');
            modal.querySelector('.modal-content').classList.add('scale-100');
            document.body.style.overflow = 'hidden';
        }

        function closeModal(modalId) {
            const modal = document.getElementById(modalId);
            if (!modal) {
                console.error(`Modal with ID ${modalId} not found`);
                return;
            }
            modal.querySelector('.modal-content').classList.remove('scale-100');
            modal.querySelector('.modal-content').classList.add('scale-95');
            setTimeout(() => {
                modal.classList.add('hidden');
                document.body.style.overflow = 'auto';
            }, 200);
        }

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

        function editClassroom(classroom) {
            document.getElementById('edit_room_id').value = classroom.room_id;
            document.getElementById('edit_room_name').value = classroom.room_name;
            document.getElementById('edit_building').value = classroom.building;
            document.getElementById('edit_capacity').value = classroom.capacity;
            document.getElementById('edit_room_type').value = classroom.room_type;
            document.getElementById('edit_availability').value = classroom.availability;
            document.getElementById('edit_shared').checked = classroom.shared == 1;
            openModal('editClassroomModal');
        }

        document.addEventListener('DOMContentLoaded', () => {
            const searchInput = document.getElementById('searchInput');
            const searchFeedback = document.getElementById('search-feedback');
            const suggestions = document.getElementById('suggestions');
            const searchResults = document.getElementById('search-results');

            let searchTimeout;
            searchInput.addEventListener('input', () => {
                const query = searchInput.value.trim();
                clearTimeout(searchTimeout);

                if (query.length < 2) {
                    searchFeedback.textContent = '';
                    suggestions.classList.add('hidden');
                    suggestions.innerHTML = '';
                    searchResults.innerHTML = '';
                    return;
                }

                searchFeedback.textContent = 'Searching...';
                searchFeedback.classList.add('loading', 'text-dark-gray');
                searchFeedback.classList.remove('text-green-500', 'text-red-500');

                searchTimeout = setTimeout(async () => {
                    try {
                        const response = await fetch(window.location.href, {
                            method: 'POST',
                            headers: {
                                'Content-Type': 'application/x-www-form-urlencoded',
                                'X-Requested-With': 'XMLHttpRequest'
                            },
                            body: `action=search_shared_rooms&search=${encodeURIComponent(query)}`
                        });
                        if (!response.ok) {
                            const errorData = await response.json().catch(() => ({}));
                            throw new Error(errorData.message || `HTTP error! Status: ${response.status}`);
                        }
                        const data = await response.json();
                        console.log('Search response:', data);

                        if (data.success && data.searchResults.length > 0) {
                            searchFeedback.textContent = 'Rooms found';
                            searchFeedback.classList.remove('loading', 'text-dark-gray', 'text-red-500');
                            searchFeedback.classList.add('text-green-500');
                            renderSuggestions(data.searchResults);
                            renderSearchResults(data.searchResults);
                        } else {
                            searchFeedback.textContent = 'No shared rooms found';
                            searchFeedback.classList.remove('loading', 'text-dark-gray', 'text-green-500');
                            searchFeedback.classList.add('text-red-500');
                            suggestions.classList.add('hidden');
                            suggestions.innerHTML = '';
                            searchResults.innerHTML = '<p class="text-dark-gray text-center py-4">No shared rooms found matching your criteria.</p>';
                        }
                    } catch (error) {
                        console.error('Search error:', error);
                        searchFeedback.textContent = 'Error searching rooms';
                        searchFeedback.classList.remove('loading', 'text-dark-gray', 'text-green-500');
                        searchFeedback.classList.add('text-red-500');
                        suggestions.classList.add('hidden');
                        suggestions.innerHTML = '';
                        searchResults.innerHTML = '<p class="text-dark-gray text-center py-4">Error searching shared rooms.</p>';
                        showToast(`Failed to search rooms: ${error.message}`, 'bg-red-500');
                    }
                }, 300);
            });

            function renderSuggestions(results) {
                suggestions.innerHTML = '';
                if (results.length === 0) {
                    suggestions.classList.add('hidden');
                    return;
                }

                results.forEach(result => {
                    const div = document.createElement('div');
                    div.className = 'suggestion-item';
                    div.textContent = `${result.room_name} (${result.building}, ${result.department_name})`;
                    div.dataset.roomId = result.room_id;
                    div.dataset.roomName = result.room_name;
                    div.addEventListener('click', () => {
                        document.getElementById('modal-room-id').value = result.room_id;
                        document.getElementById('modal-room-name').textContent = result.room_name;
                        openModal('includeRoomModal');
                        suggestions.classList.add('hidden');
                    });
                    suggestions.appendChild(div);
                });

                suggestions.classList.remove('hidden');
            }

            function renderSearchResults(results) {
                searchResults.innerHTML = '';
                if (results.length === 0) {
                    searchResults.innerHTML = '<p class="text-dark-gray text-center py-4">No shared rooms found matching your criteria.</p>';
                    return;
                }

                const container = document.createElement('div');
                container.className = 'bg-white rounded-lg shadow-md p-6';
                container.innerHTML = `
                    <div class="flex justify-between items-center border-b border-gray-light pb-2 mb-6">
                        <h3 class="text-xl font-bold text-dark-gray">Available Shared Rooms</h3>
                        <span class="text-sm font-medium text-dark-gray bg-gray-light px-3 py-1 rounded-full">${results.length} Found</span>
                    </div>
                    <div class="overflow-x-auto">
                        <table class="w-full table-auto">
                            <thead class="bg-yellow bg-opacity-10">
                                <tr>
                                    <th class="px-4 py-3 text-left text-sm font-medium text-dark-gray">Room Name</th>
                                    <th class="px-4 py-3 text-left text-sm font-medium text-dark-gray">Building</th>
                                    <th class="px-4 py-3 text-left text-sm font-medium text-dark-gray">Capacity</th>
                                    <th class="px-4 py-3 text-left text-sm font-medium text-dark-gray">Room Type</th>
                                    <th class="px-4 py-3 text-left text-sm font-medium text-dark-gray">Department</th>
                                    <th class="px-4 py-3 text-left text-sm font-medium text-dark-gray">College</th>
                                    <th class="px-4 py-3 text-left text-sm font-medium text-dark-gray">Status</th>
                                    <th class="px-4 py-3 text-left text-sm font-medium text-dark-gray">Action</th>
                                </tr>
                            </thead>
                            <tbody class="divide-y divide-dark-gray divide-opacity-20">
                                ${results.map(result => `
                                    <tr class="hover:bg-yellow hover:bg-opacity-10 transition-colors">
                                        <td class="px-4 py-3 text-sm text-dark-gray font-medium">${result.room_name}</td>
                                        <td class="px-4 py-3 text-sm text-dark-gray">${result.building}</td>
                                        <td class="px-4 py-3 text-sm text-dark-gray">${result.capacity}</td>
                                        <td class="px-4 py-3 text-sm text-dark-gray">${result.room_type.charAt(0).toUpperCase() + result.room_type.slice(1)}</td>
                                        <td class="px-4 py-3 text-sm text-dark-gray">${result.department_name}</td>
                                        <td class="px-4 py-3 text-sm text-dark-gray">${result.college_name}</td>
                                        <td class="px-4 py-3">
                                            <span class="inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium ${result.availability === 'available' ? 'bg-green-100 text-green-800' : (result.availability === 'unavailable' ? 'bg-red-100 text-red-800' : 'bg-yellow text-dark-gray')}">
                                                ${result.availability.charAt(0).toUpperCase() + result.availability.slice(1)}
                                            </span>
                                        </td>
                                        <td class="px-4 py-3">
                                            <button class="include-btn text-dark-gray group relative hover:text-yellow transition-all duration-200"
                                                data-id="${result.room_id}"
                                                data-name="${result.room_name}">
                                                <i class="fas fa-plus"></i>
                                                <span class="tooltip absolute bg-dark-gray text-white text-xs rounded py-1 px-2 -top-8 left-1/2 transform -translate-x-1/2">Include Room</span>
                                            </button>
                                        </td>
                                    </tr>
                                `).join('')}
                            </tbody>
                        </table>
                    </div>
                `;
                searchResults.appendChild(container);

                // Add event listeners for include buttons
                document.querySelectorAll('.include-btn').forEach(button => {
                    button.addEventListener('click', () => {
                        const roomId = button.dataset.id;
                        const roomName = button.dataset.name;
                        document.getElementById('modal-room-id').value = roomId;
                        document.getElementById('modal-room-name').textContent = roomName;
                        openModal('includeRoomModal');
                    });
                });
            }

            // Handle include room confirmation
            document.getElementById('confirmIncludeBtn').addEventListener('click', async () => {
                const roomId = document.getElementById('modal-room-id').value;
                try {
                    const response = await fetch(window.location.href, {
                        method: 'POST',
                        headers: {
                            'Content-Type': 'application/x-www-form-urlencoded',
                            'X-Requested-With': 'XMLHttpRequest'
                        },
                        body: `action=include_room&room_id=${encodeURIComponent(roomId)}`
                    });
                    const data = await response.json();
                    if (data.success) {
                        showToast(data.message, 'bg-green-500');
                        closeModal('includeRoomModal');
                        updateClassroomsTable(data.classrooms);
                    } else {
                        showToast(data.message, 'bg-red-500');
                    }
                } catch (error) {
                    console.error('Include room error:', error);
                    showToast(`Failed to include room: ${error.message}`, 'bg-red-500');
                }
            });

            // Handle remove room confirmation
            document.querySelectorAll('.remove-btn').forEach(button => {
                button.addEventListener('click', () => {
                    const roomId = button.dataset.id;
                    const roomName = button.dataset.name;
                    document.getElementById('remove-modal-room-id').value = roomId;
                    document.getElementById('remove-modal-room-name').textContent = roomName;
                    openModal('removeRoomModal');
                });
            });

            document.getElementById('confirmRemoveBtn').addEventListener('click', async () => {
                const roomId = document.getElementById('remove-modal-room-id').value;
                try {
                    const response = await fetch(window.location.href, {
                        method: 'POST',
                        headers: {
                            'Content-Type': 'application/x-www-form-urlencoded',
                            'X-Requested-With': 'XMLHttpRequest'
                        },
                        body: `action=remove_room&room_id=${encodeURIComponent(roomId)}`
                    });
                    const data = await response.json();
                    if (data.success) {
                        showToast(data.message, 'bg-green-500');
                        closeModal('removeRoomModal');
                        updateClassroomsTable(data.classrooms);
                    } else {
                        showToast(data.message, 'bg-red-500');
                    }
                } catch (error) {
                    console.error('Remove room error:', error);
                    showToast(`Failed to remove room: ${error.message}`, 'bg-red-500');
                }
            });

            function updateClassroomsTable(classrooms) {
                const tableContainer = document.querySelector('#classroomsTable').parentElement.parentElement;
                if (!classrooms || classrooms.length === 0) {
                    tableContainer.innerHTML = `
                        <div class="text-center py-12 text-dark-gray">
                            <i class="fas fa-door-open text-4xl mb-4"></i>
                            <p class="text-lg font-medium">No classrooms found.</p>
                            <p class="text-sm mt-1">Add a classroom or search for shared rooms to include.</p>
                        </div>
                    `;
                    return;
                }

                const tableBody = document.querySelector('#classroomsTable tbody');
                tableBody.innerHTML = classrooms.map(classroom => `
                    <tr class="hover:bg-yellow hover:bg-opacity-10 transition-colors"
                        data-search="${(classroom.room_name + ' ' + classroom.building + ' ' + (classroom.department_name || '')).toLowerCase()}">
                        <td class="px-4 py-3 text-sm text-dark-gray font-medium">${classroom.room_name}</td>
                        <td class="px-4 py-3 text-sm text-dark-gray">${classroom.building}</td>
                        <td class="px-4 py-3 text-sm text-dark-gray">${classroom.capacity}</td>
                        <td class="px-4 py-3 text-sm text-dark-gray">${classroom.room_type.charAt(0).toUpperCase() + classroom.room_type.slice(1)}</td>
                        <td class="px-4 py-3 text-sm text-dark-gray">${classroom.department_name || 'N/A'}</td>
                        <td class="px-4 py-3 text-sm text-dark-gray">${classroom.college_name || 'N/A'}</td>
                        <td class="px-4 py-3">
                            <span class="inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium ${classroom.availability === 'available' ? 'bg-green-100 text-green-800' : (classroom.availability === 'unavailable' ? 'bg-red-100 text-red-800' : 'bg-yellow text-dark-gray')}">
                                ${classroom.availability.charAt(0).toUpperCase() + classroom.availability.slice(1)}
                            </span>
                        </td>
                        <td class="px-4 py-3 text-sm text-dark-gray">${classroom.shared ? 'Yes' : 'No'}</td>
                        <td class="px-4 py-3 text-sm text-dark-gray">${classroom.room_status}</td>
                        <td class="px-4 py-3 text-sm text-dark-gray">${classroom.current_semester_usage} schedules</td>
                        <td class="px-4 py-3 space-x-2">
                            ${classroom.room_status === 'Owned' ? `
                                <button class="edit-classroom-btn text-yellow hover:text-dark-gray focus:outline-none"
                                    data-classroom='${JSON.stringify(classroom).replace(/'/g, "&#39;")}'>
                                    <i class="fas fa-edit"></i>
                                </button>
                            ` : (classroom.room_status === 'Included' ? `
                                <button class="remove-btn text-red-600 group relative hover:text-red-700 transition-all duration-200"
                                    data-id="${classroom.room_id}"
                                    data-name="${classroom.room_name}">
                                    <i class="fa-solid fa-xmark"></i>
                                    <span class="tooltip absolute bg-dark-gray text-white text-xs rounded py-1 px-2 -top-8 left-1/2 transform -translate-x-1/2">Remove Room</span>
                                </button>
                            ` : '')}
                        </td>
                    </tr>
                `).join('');

                // Reattach remove button event listeners
                document.querySelectorAll('.remove-btn').forEach(button => {
                    button.addEventListener('click', () => {
                        const roomId = button.dataset.id;
                        const roomName = button.dataset.name;
                        document.getElementById('remove-modal-room-id').value = roomId;
                        document.getElementById('remove-modal-room-name').textContent = roomName;
                        openModal('removeRoomModal');
                    });
                });
            }

            // Handle form submissions via AJAX
            document.getElementById('addClassroomForm').addEventListener('submit', async (e) => {
                e.preventDefault();
                const formData = new FormData(e.target);
                const submitButton = e.target.querySelector('button[type="submit"]');
                submitButton.disabled = true;
                submitButton.classList.add('loading');

                try {
                    const response = await fetch(window.location.href, {
                        method: 'POST',
                        headers: {
                            'X-Requested-With': 'XMLHttpRequest'
                        },
                        body: formData
                    });
                    const data = await response.json();
                    if (data.success) {
                        showToast(data.message, 'bg-green-500');
                        closeModal('addClassroomModal');
                        updateClassroomsTable(data.classrooms);
                        e.target.reset();
                    } else {
                        showToast(data.message, 'bg-red-500');
                    }
                } catch (error) {
                    console.error('Add classroom error:', error);
                    showToast(`Failed to add classroom: ${error.message}`, 'bg-red-500');
                } finally {
                    submitButton.disabled = false;
                    submitButton.classList.remove('loading');
                }
            });

            document.querySelectorAll('.edit-classroom-btn').forEach(button => {
                button.addEventListener('click', function() {
                    const classroom = JSON.parse(this.dataset.classroom);
                    editClassroom(classroom);
                });
            });

            document.getElementById('editClassroomForm').addEventListener('submit', async (e) => {
                e.preventDefault();
                const formData = new FormData(e.target);
                const submitButton = e.target.querySelector('button[type="submit"]');
                submitButton.disabled = true;
                submitButton.classList.add('loading');

                try {
                    const response = await fetch(window.location.href, {
                        method: 'POST',
                        headers: {
                            'X-Requested-With': 'XMLHttpRequest'
                        },
                        body: formData
                    });
                    const data = await response.json();
                    if (data.success) {
                        showToast(data.message, 'bg-green-500');
                        closeModal('editClassroomModal');
                        updateClassroomsTable(data.classrooms);
                    } else {
                        showToast(data.message, 'bg-red-500');
                    }
                } catch (error) {
                    console.error('Edit classroom error:', error);
                    showToast(`Failed to edit classroom: ${error.message}`, 'bg-red-500');
                } finally {
                    submitButton.disabled = false;
                    submitButton.classList.remove('loading');
                }
            });

            // Close suggestions when clicking outside
            document.addEventListener('click', (e) => {
                if (!suggestions.contains(e.target) && e.target !== searchInput) {
                    suggestions.classList.add('hidden');
                }
                const editBtn = e.target.closest('.edit-classroom-btn');
                if (editBtn) {
                    const classroom = JSON.parse(editBtn.dataset.classroom);
                    editClassroom(classroom);
                }
            });
        });
    </script>
</body>

<?php
$content = ob_get_clean();
require_once __DIR__ . '/layout.php';
?>