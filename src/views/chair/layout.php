<?php
require_once __DIR__ . '/../../controllers/ChairController.php';
require_once __DIR__ . '/../../config/Database.php';

// Fetch profile picture
$profilePicture = $_SESSION['profile_picture'] ?? null;
if (!$profilePicture) {
    try {
        $db = (new Database())->connect();
        $stmt = $db->prepare("SELECT title, first_name, middle_name, last_name, suffix, profile_picture FROM users WHERE user_id = :user_id");
        $stmt->execute([':user_id' => $_SESSION['user_id']]);
        $profilePicture = $stmt->fetchColumn() ?: '';
        $_SESSION['profile_picture'] = $profilePicture;
    } catch (PDOException $e) {
        error_log("layout: Error fetching profile picture - " . $e->getMessage());
        $profilePicture = '';
    }
}

$isScheduleActive = strpos($_SERVER['REQUEST_URI'], '/chair/schedule') !== false;

// Get department ID
$userDepartmentId = $_SESSION['department_id'] ?? null;
if (!$userDepartmentId) {
    $chairController = new ChairController();
    $userDepartmentId = $chairController->getChairDepartment($_SESSION['user_id']);
    $_SESSION['department_id'] = $userDepartmentId;
}

// Fetch college logo based on department ID
$collegeLogoPath = '/assets/logo/main_logo/PRMSUlogo.png';
if ($userDepartmentId) {
    try {
        $db = (new Database())->connect();
        $stmt = $db->prepare("SELECT c.logo_path FROM colleges c JOIN departments d ON c.college_id = d.college_id WHERE d.department_id = :department_id");
        $stmt->execute([':department_id' => $userDepartmentId]);
        $logoPath = $stmt->fetchColumn();
        if ($logoPath) {
            $collegeLogoPath = $logoPath;
        }
    } catch (PDOException $e) {
        error_log("layout: Error fetching college logo - " . $e->getMessage());
    }
}

// MOVED: Get departments for switcher
$userDepartments = [];
$currentDepartmentId = $_SESSION['current_department_id'] ?? $userDepartmentId;

try {
    $db = (new Database())->connect();
    $stmt = $db->prepare("
        SELECT 
            cd.department_id, 
            d.department_name, 
            cd.is_primary,
            c.college_name
        FROM chair_departments cd
        JOIN departments d ON cd.department_id = d.department_id
        JOIN colleges c ON d.college_id = c.college_id
        WHERE cd.user_id = :user_id
        ORDER BY cd.is_primary DESC, d.department_name ASC
    ");
    $stmt->execute([':user_id' => $_SESSION['user_id']]);
    $userDepartments = $stmt->fetchAll(PDO::FETCH_ASSOC);

    // Fallback if no departments found
    if (empty($userDepartments) && $userDepartmentId) {
        $stmt = $db->prepare("
            SELECT 
                d.department_id, 
                d.department_name, 
                1 as is_primary,
                c.college_name
            FROM departments d
            JOIN colleges c ON d.college_id = c.college_id
            WHERE d.department_id = :department_id
        ");
        $stmt->execute([':department_id' => $userDepartmentId]);
        $userDepartments = [$stmt->fetch(PDO::FETCH_ASSOC)];
    }
} catch (PDOException $e) {
    error_log("layout: Error loading departments - " . $e->getMessage());
}

$chairController = new ChairController();
$deadlineStatus = $chairController->checkScheduleDeadlineStatus($userDepartmentId);
$isScheduleLocked = $deadlineStatus['locked'] ?? false;

$currentUri = $_SERVER['REQUEST_URI'];
$modal_content = $modal_content ?? '';

// Get available roles
$availableRoles = $_SESSION['roles'] ?? [];
$currentRole = $_SESSION['current_role'] ?? ($_SESSION['roles'][0] ?? null);
?>

<!DOCTYPE html>
<html lang="en">

<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Program Chair Dashboard</title>
    <link rel="stylesheet" href="/css/output.css">
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.1.1/css/all.min.css">
    <style>
        @import url('https://fonts.googleapis.com/css2?family=Roboto:wght@300;400;500;700&display=swap');
        @import url('https://fonts.googleapis.com/css2?family=Poppins:wght@400;500;600;700&display=swap');

        body {
            font-family: 'Roboto', sans-serif;
            scroll-behavior: smooth;
        }

        h1,
        h2,
        h3,
        h4,
        h5,
        h6 {
            font-family: 'Poppins', sans-serif;
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

        @keyframes slideInRight {
            from {
                transform: translateX(20px);
                opacity: 0;
            }

            to {
                transform: translateX(0);
                opacity: 1;
            }
        }

        .fade-in {
            animation: fadeIn 0.5s ease forwards;
        }

        .slide-in-left {
            animation: slideInLeft 0.4s ease forwards;
        }

        .slide-in-right {
            animation: slideInRight 0.4s ease forwards;
        }

        /* Sidebar */
        .sidebar {
            background: linear-gradient(to bottom, #1F2937, #111827);
            box-shadow: 2px 0 10px rgba(0, 0, 0, 0.1);
            transition: all 0.3s ease;
            z-index: 40;
        }

        /* Mobile Sidebar States */
        @media (max-width: 767px) {
            .sidebar {
                transform: translateX(-100%);
            }

            .sidebar.show {
                transform: translateX(0);
            }
        }

        /* Desktop Sidebar */
        @media (min-width: 768px) {
            .sidebar {
                transform: translateX(0) !important;
            }
        }

        /* Mobile Overlay */
        .sidebar-overlay {
            display: none;
            position: fixed;
            top: 0;
            left: 0;
            right: 0;
            bottom: 0;
            background-color: rgba(0, 0, 0, 0.5);
            z-index: 35;
            transition: opacity 0.3s ease;
        }

        .sidebar-overlay.show {
            display: block;
            opacity: 1;
        }

        /* Responsive Header */
        .header-desktop {
            left: 16rem;
            /* 256px - sidebar width */
        }

        .header-mobile {
            left: 0;
        }

        @media (max-width: 767px) {
            .header-desktop {
                left: 0;
            }
        }

        /* Mobile Hamburger Menu */
        .hamburger {
            display: flex;
            flex-direction: column;
            cursor: pointer;
            padding: 8px;
            border-radius: 4px;
            transition: all 0.3s ease;
        }

        .hamburger:hover {
            background-color: rgba(0, 0, 0, 0.1);
        }

        .hamburger-line {
            width: 24px;
            height: 2px;
            background-color: #374151;
            margin: 2px 0;
            transition: 0.3s;
            border-radius: 1px;
        }

        /* Hamburger Animation */
        .hamburger.active .hamburger-line:nth-child(1) {
            transform: rotate(-45deg) translate(-5px, 6px);
        }

        .hamburger.active .hamburger-line:nth-child(2) {
            opacity: 0;
        }

        .hamburger.active .hamburger-line:nth-child(3) {
            transform: rotate(45deg) translate(-5px, -6px);
        }

        /* Dropdown */
        .dropdown {
            position: relative;
        }

        .dropdown-menu {
            display: none;
            position: absolute;
            top: 100%;
            left: 0;
            min-width: 200px;
            z-index: 20;
            box-shadow: 0 8px 16px rgba(0, 0, 0, 0.15);
            border-radius: 0.375rem;
            background: #1F2937;
            transform: translateY(-10px);
        }

        .dropdown-menu.show {
            display: flex;
            flex-direction: column;
            transform: translateY(0);
        }

        /* Header Profile Dropdown - Mobile Responsive */
        @media (max-width: 640px) {
            .dropdown-menu {
                right: 0;
                left: auto;
                min-width: 180px;
            }
        }

        /* Navigation items */
        .nav-item {
            transition: all 0.3s ease;
            border-radius: 0.375rem;
            position: relative;
            overflow: hidden;
        }

        .nav-item::before {
            content: '';
            position: absolute;
            left: 0;
            top: 0;
            height: 100%;
            width: 0;
            background-color: rgba(212, 175, 55, 0.15);
            z-index: -1;
            transition: width 0.3s ease;
        }

        .nav-item:hover::before {
            width: 100%;
        }

        .nav-item:hover {
            color: #D4AF37;
        }

        .active-nav {
            border-left: 4px solid #D4AF37;
            background-color: rgba(212, 175, 55, 0.1);
            font-weight: 500;
        }

        /* Header */
        .header-shadow {
            box-shadow: 0 2px 10px rgba(0, 0, 0, 0.08);
        }

        /* Responsive Main Content */
        .main-content {
            transition: margin-left 0.3s ease;
        }

        @media (min-width: 768px) {
            .main-content {
                margin-left: 16rem;
                /* 256px - sidebar width */
            }
        }

        @media (max-width: 767px) {
            .main-content {
                margin-left: 0;
            }
        }

        /* Responsive Padding */
        @media (max-width: 640px) {
            .main-content {
                padding: 1rem;
            }
        }

        /* Gradient and card effects */
        .yellow-gradient {
            background: linear-gradient(135deg, #D4AF37 0%, #F2D675 100%);
        }

        .card {
            transition: transform 0.3s ease, box-shadow 0.3s ease;
            overflow: hidden;
        }

        .card:hover {
            transform: translateY(-5px);
            box-shadow: 0 12px 20px rgba(0, 0, 0, 0.15);
        }

        /* Logo styles */
        .university-logo {
            height: 40px;
            transition: transform 0.3s ease;
        }

        .university-logo:hover {
            transform: scale(1.05);
        }

        /* Mobile Logo Size */
        @media (max-width: 640px) {
            .university-logo {
                height: 32px;
            }
        }

        /* Buttons */
        .btn {
            transition: all 0.3s ease;
            position: relative;
            overflow: hidden;
        }

        .btn::after {
            content: '';
            position: absolute;
            top: 50%;
            left: 50%;
            width: 5px;
            height: 5px;
            background: rgba(255, 255, 255, 0.5);
            opacity: 0;
            border-radius: 100%;
            transform: scale(1, 1) translate(-50%, -50%);
            transform-origin: 50% 50%;
        }

        .btn:hover::after {
            animation: ripple 1s ease-out;
        }

        @keyframes ripple {
            0% {
                transform: scale(0, 0);
                opacity: 0.5;
            }

            100% {
                transform: scale(20, 20);
                opacity: 0;
            }
        }

        /* Scrollbar */
        ::-webkit-scrollbar {
            width: 8px;
            height: 8px;
        }

        ::-webkit-scrollbar-track {
            background: #f1f1f1;
            border-radius: 10px;
        }

        ::-webkit-scrollbar-thumb {
            background: #D4AF37;
            border-radius: 10px;
        }

        ::-webkit-scrollbar-thumb:hover {
            background: #B8860B;
        }

        #role-switcher-menu {
            animation: slideInRight 0.2s ease forwards;
        }

        .role-switch-item:hover {
            background-color: #fef3c7 !important;
        }

        /* Notifications */
        .notification-badge {
            position: absolute;
            top: -5px;
            right: -5px;
            background-color: #EF4444;
            color: white;
            border-radius: 50%;
            padding: 0.1rem 0.4rem;
            font-size: 0.65rem;
            font-weight: bold;
        }

        /* Toggle animations */
        .toggle-icon {
            transition: transform 0.3s ease;
        }

        .rotate-icon {
            transform: rotate(180deg);
        }

        /* Toast notifications */
        .toast {
            animation: slideInRight 0.5s ease forwards, fadeOut 0.5s ease 5s forwards;
            box-shadow: 0 10px 15px -3px rgba(0, 0, 0, 0.1), 0 4px 6px -2px rgba(0, 0, 0, 0.05);
        }

        @keyframes fadeOut {
            from {
                opacity: 1;
            }

            to {
                opacity: 0;
            }
        }

        /* Ensure modals are above all elements */
        .modal-overlay {
            z-index: 60 !important;
        }

        /* Additional CSS for hover effects and tooltips */
        .group:hover .group-hover\:opacity-100 {
            opacity: 1;
        }

        .locked-item {
            position: relative;
            cursor: not-allowed;
        }

        .locked-item::after {
            content: '';
            position: absolute;
            top: 0;
            left: 0;
            right: 0;
            bottom: 0;
            background: repeating-linear-gradient(45deg,
                    transparent,
                    transparent 2px,
                    rgba(255, 255, 255, 0.1) 2px,
                    rgba(255, 255, 255, 0.1) 4px);
            pointer-events: none;
        }

        /* Mobile Text Size Adjustments */
        @media (max-width: 640px) {
            .breadcrumb-text {
                font-size: 0.75rem;
            }

            .mobile-text-sm {
                font-size: 0.875rem;
            }
        }

        /* Hide elements on mobile */
        @media (max-width: 640px) {
            .hidden-mobile {
                display: none !important;
            }
        }
    </style>
</head>

<body class="bg-gray-50 font-sans">
    <!-- Toast notifications container -->
    <div id="toast-container" class="fixed top-5 right-5 z-50 space-y-4"></div>

    <!-- Mobile Sidebar Overlay -->
    <div id="sidebar-overlay" class="sidebar-overlay md:hidden"></div>

    <!-- Header -->
    <header class="fixed top-0 header-desktop right-0 bg-white header-shadow z-30">
        <div class="max-w-full mx-auto px-4 sm:px-6 lg:px-8 py-4 flex items-center justify-between">
            <!-- Left: Mobile Hamburger and Desktop Logo -->
            <div class="flex items-center">
                <!-- Mobile Hamburger Menu -->
                <button id="hamburger-menu" class="hamburger md:hidden mr-4" aria-label="Toggle menu">
                    <div class="hamburger-line"></div>
                    <div class="hamburger-line"></div>
                    <div class="hamburger-line"></div>
                </button>

                <!-- Logo - Always visible -->
                <a href="/chair/dashboard" class="flex items-center">
                    <img src="<?php echo htmlspecialchars($collegeLogoPath); ?>" alt="College Logo" class="university-logo" onerror="this.src='/assets/logo/main_logo/PRMSUlogo.png'; console.log('Fallback to university logo due to error')">
                    <span class="text-lg font-heading text-gray-800 ml-2 hidden-mobile sm:inline">Automated Classroom Scheduling System</span>
                </a>
            </div>

            <!-- Right: User Profile and Notifications -->
            <div class="flex items-center space-x-2 sm:space-x-4">
                <!-- User Profile Dropdown -->
                <div class="dropdown relative">
                    <button class="flex items-center text-gray-600 hover:text-yellow-400 focus:outline-none">
                        <?php if (!empty($profilePicture)): ?>
                            <img class="h-8 w-8 rounded-full border-2 border-yellow-400 object-cover"
                                src="<?php echo htmlspecialchars($profilePicture); ?>" alt="Profile">
                        <?php else: ?>
                            <div class="h-8 w-8 rounded-full border-2 border-yellow-400 bg-yellow-400 flex items-center justify-center text-white text-sm font-bold">
                                <?php echo strtoupper(substr($_SESSION['first_name'], 0, 1) . substr($_SESSION['last_name'], 0, 1)); ?>
                            </div>
                        <?php endif; ?>
                        <span class="ml-2 hidden sm:inline text-sm font-medium"><?php echo htmlspecialchars($_SESSION['first_name']); ?></span>
                        <i class="fas fa-chevron-down ml-2 text-xs"></i>
                    </button>
                    <div class="dropdown-menu mt-2">
                        <a href="/chair/profile" class="flex items-center px-4 py-2 text-gray-300 hover:bg-gray-600 hover:text-yellow-300">
                            <i class="fas fa-user w-5 mr-2"></i> Profile
                        </a>
                        <a href="/chair/settings" class="flex items-center px-4 py-2 text-gray-300 hover:bg-gray-600 hover:text-yellow-300">
                            <i class="fas fa-cog w-5 mr-2"></i> Settings
                        </a>
                        <a href="/chair/logout" class="flex items-center px-4 py-2 text-gray-300 hover:bg-gray-600 hover:text-yellow-300">
                            <i class="fas fa-sign-out-alt w-5 mr-2"></i> Logout
                        </a>
                    </div>
                </div>

                <!-- Department Switcher - Only show if user has MULTIPLE departments -->
                <?php if (!empty($userDepartments) && count($userDepartments) > 1): ?>
                    <div class="relative pl-4 border-l border-gray-300 group">
                        <button class="flex items-center gap-2 px-3 py-2 text-sm font-medium text-gray-600 hover:text-yellow-500 hover:bg-gray-100 rounded-lg transition-colors">
                            <i class="fas fa-building"></i>
                            <span class="hidden sm:inline text-xs">
                                <?php
                                $currentDeptName = '';
                                foreach ($userDepartments as $dept) {
                                    if ($dept['department_id'] == $currentDepartmentId) {
                                        $currentDeptName = htmlspecialchars($dept['department_name']);
                                        break;
                                    }
                                }
                                echo $currentDeptName ?: 'Department';
                                ?>
                            </span>
                            <i class="fas fa-chevron-down text-xs transition-transform group-hover:rotate-180"></i>
                        </button>

                        <!-- Department Dropdown Menu -->
                        <div class="absolute top-full right-0 mt-2 bg-white border border-gray-300 rounded-lg shadow-lg z-50 min-w-64 max-w-xs opacity-0 invisible group-hover:opacity-100 group-hover:visible transition-all duration-200 slide-in-right">
                            <form method="POST" action="/chair/switch-department" id="department-switch-form">
                                <?php foreach ($userDepartments as $dept): ?>
                                    <button type="button" class="department-switch-item w-full text-left px-4 py-2 hover:bg-yellow-50 transition-colors flex items-center gap-2 first:rounded-t-lg last:rounded-b-lg <?php echo $dept['department_id'] == $currentDepartmentId ? 'bg-yellow-100 text-yellow-700 font-semibold' : 'text-gray-700'; ?>" data-dept-id="<?php echo $dept['department_id']; ?>">
                                        <i class="fas fa-<?php echo $dept['is_primary'] ? 'star text-yellow-500' : 'building text-gray-400'; ?> text-sm"></i>
                                        <span class="flex-1 truncate text-sm"><?php echo htmlspecialchars($dept['department_name']); ?></span>
                                        <?php if ($dept['is_primary']): ?>
                                            <span class="text-xs text-yellow-600 font-medium ml-2">Primary</span>
                                        <?php endif; ?>
                                        <?php if ($dept['department_id'] == $currentDepartmentId): ?>
                                            <i class="fas fa-check ml-2 text-yellow-500 text-sm"></i>
                                        <?php endif; ?>
                                    </button>
                                <?php endforeach; ?>
                                <input type="hidden" name="department_id" id="selected-department-id">
                            </form>
                        </div>
                    </div>
                <?php endif; ?>

                <!-- Role Switcher -->
                <?php if (count($availableRoles) > 1): ?>
                    <div class="relative pl-4 border-l border-gray-300">
                        <button id="role-switcher-btn" class="flex items-center gap-2 px-3 py-2 text-sm font-medium text-gray-600 hover:text-yellow-500 transition-colors rounded-lg hover:bg-gray-100" aria-label="Switch role">
                            <i class="fas fa-exchange-alt"></i>
                            <span class="hidden sm:inline text-xs">
                                <?php echo ucfirst($currentRole); ?>
                            </span>
                            <i class="fas fa-chevron-down text-xs"></i>
                        </button>

                        <!-- Role Dropdown Menu -->
                        <div id="role-switcher-menu" class="hidden absolute top-full right-0 mt-2 bg-white border border-gray-300 rounded-lg shadow-lg z-50 min-w-max">
                            <?php foreach ($availableRoles as $role): ?>
                                <?php $roleLower = strtolower($role); ?>
                                <button type="button" class="role-switch-item w-full text-left px-4 py-2 hover:bg-yellow-50 transition-colors flex items-center gap-2 first:rounded-t-lg last:rounded-b-lg <?php echo $roleLower === strtolower($currentRole) ? 'bg-yellow-100 text-yellow-700 font-semibold' : 'text-gray-700'; ?>" data-role="<?php echo $roleLower; ?>">
                                    <i class="fas fa-<?php echo $roleLower === 'dean' ? 'user-tie' : 'chalkboard-teacher'; ?>"></i>
                                    <span><?php echo ucfirst(str_replace('_', ' ', $roleLower)); ?></span>
                                    <?php if ($roleLower === strtolower($currentRole)): ?>
                                        <i class="fas fa-check ml-auto text-yellow-500"></i>
                                    <?php endif; ?>
                                </button>
                            <?php endforeach; ?>
                        </div>
                    </div>
                <?php endif; ?>
            </div>
        </div>
    </header>

    <!-- Sidebar -->
    <aside id="sidebar" class="sidebar w-64 text-white fixed h-full overflow-y-auto top-0">
        <!-- Sidebar Header -->
        <div class="py-6 px-6 flex flex-col items-center justify-center border-b border-gray-700 bg-gray-900">
            <div class="flex items-center justify-center mb-3">
                <img src="/assets/logo/main_logo/PRMSUlogo.png" alt="PRMSU Logo" class="h-12">
            </div>
            <h2 class="text-xl text-yellow-600 font-bold text-center">PRMSU Scheduling System - ACSS</h2>
            <p class="text-xs text-gray-400 mt-1 text-center">Management System</p>
        </div>

        <!-- User Profile Section -->
        <div class="p-4 border-b border-gray-700 bg-gray-800/70">
            <div class="flex items-center space-x-3">
                <?php if (!empty($profilePicture)): ?>
                    <img class="h-12 w-12 rounded-full border-2 border-yellow-400 object-cover shadow-md flex-shrink-0"
                        src="<?php echo htmlspecialchars($profilePicture); ?>" alt="Profile">
                <?php else: ?>
                    <div class="h-12 w-12 rounded-full border-2 border-yellow-400 bg-yellow-400 flex items-center justify-center text-white text-lg font-bold shadow-md flex-shrink-0">
                        <?php echo strtoupper(substr($_SESSION['first_name'], 0, 1) . substr($_SESSION['last_name'], 0, 1)); ?>
                    </div>
                <?php endif; ?>
                <div class="min-w-0 flex-1">
                    <p class="font-medium text-white truncate">
                        <?php
                        // Display title if it exists
                        if (!empty($_SESSION['title'])) {
                            echo htmlspecialchars($_SESSION['title'] . ' ');
                        }
                        echo htmlspecialchars($_SESSION['first_name'] . ' ' . $_SESSION['last_name']);
                        ?>
                    </p>
                    <div class="flex items-center text-xs text-yellow-400">
                        <i class="fas fa-circle text-green-500 mr-1 text-xs"></i>
                        <span>Program Chair</span>
                    </div>
                </div>
            </div>
        </div>

        <!-- Navigation -->
        <nav class="mt-4 px-2 pb-20">
            <!-- Dashboard Link -->
            <a href="/chair/dashboard" class="nav-item flex items-center px-4 py-3 text-gray-200 rounded-lg mb-1 hover:text-white transition-all duration-300 <?= strpos($currentUri, '/chair/dashboard') !== false ? 'active-nav bg-gray-800 text-yellow-300' : '' ?>">
                <i class="fas fa-tachometer-alt w-5 mr-3 <?= strpos($currentUri, '/chair/dashboard') !== false ? 'text-yellow-400' : 'text-gray-400' ?>"></i>
                <span>Dashboard</span>
            </a>

            <!-- Schedule Dropdown -->
            <div class="dropdown relative my-1">
                <button class="nav-item w-full flex px-4 py-3 text-gray-200 hover:text-white items-center justify-between cursor-pointer rounded-lg transition-all duration-300 <?= strpos($currentUri, '/chair/schedule') !== false || strpos($currentUri, '/chair/my_schedule') !== false ? 'active-nav bg-gray-800 text-yellow-300' : '' ?>">
                    <div class="flex items-center">
                        <i class="fas fa-calendar-alt w-5 mr-3 <?= strpos($currentUri, '/chair/schedule') !== false || strpos($currentUri, '/chair/my_schedule') !== false ? 'text-yellow-400' : 'text-gray-400' ?>"></i>
                        <span>Schedule</span>
                    </div>
                    <i class="fas fa-chevron-down text-xs transition-transform duration-300 toggle-icon"></i>
                </button>

                <div class="dropdown-menu ml-5 mt-1 rounded-md flex-col bg-gray-800/80 overflow-hidden">
                    <!-- Deadline Status Indicator -->
                    <?php if ($isScheduleLocked): ?>
                        <div class="ml-5 mb-2 px-3 py-2 bg-red-900/50 rounded-md text-xs">
                            <div class="flex items-center text-red-300">
                                <i class="fas fa-lock mr-2"></i>
                                <span>Schedule Creation Locked</span>
                            </div>
                            <div class="text-red-400 mt-1">
                                <?= htmlspecialchars($deadlineStatus['message'] ?? 'Unknown deadline') ?>
                            </div>
                        </div>
                    <?php elseif (isset($deadlineStatus['deadline'])): ?>
                        <?php
                        $timeRemaining = $deadlineStatus['time_remaining'] ?? null;
                        $totalHours = $deadlineStatus['total_hours'] ?? 0;
                        $warningClass = ($totalHours <= 24) ? 'deadline-warning text-yellow-400' : (($totalHours <= 48) ? 'text-orange-400' : 'text-blue-400');
                        ?>
                        <div class="ml-5 mb-2 px-3 py-2 bg-blue-900/50 rounded-md text-xs">
                            <div class="flex items-center text-blue-300">
                                <i class="fas fa-clock mr-2"></i>
                                <span>Deadline: <?= ($deadlineStatus['deadline'] ?? new DateTime())->format('M j, g:i A') ?></span>
                            </div>
                            <div class="text-<?= $warningClass ?> mt-1">
                                <?php if ($totalHours <= 24): ?>
                                    <span>⚠️ <?= $totalHours ?> hours remaining</span>
                                <?php elseif ($totalHours <= 48): ?>
                                    <span>⏳ <?= $timeRemaining->days ?? 0 ?>d <?= $timeRemaining->h ?? 0 ?>h left</span>
                                <?php else: ?>
                                    <span><?= $timeRemaining->days ?? 0 ?>d <?= $timeRemaining->h ?? 0 ?>h remaining</span>
                                <?php endif; ?>
                            </div>
                        </div>
                    <?php endif; ?>

                    <!-- Create Schedule - Conditional Locking -->
                    <?php if ($isScheduleLocked): ?>
                        <div class="locked-item">
                            <div class="flex items-center px-4 py-3 text-gray-500 bg-gray-900/50 cursor-not-allowed rounded-md opacity-75">
                                <i class="fas fa-lock w-5 mr-2 text-red-400"></i> Create Schedule
                                <span class="ml-auto text-xs bg-red-100 text-red-800 px-2 py-1 rounded-full">Locked</span>
                            </div>
                            <div class="absolute left-full top-0 ml-2 px-3 py-2 bg-gray-900 text-white text-sm rounded-lg shadow-lg opacity-0 pointer-events-none group-hover:opacity-100 transition-opacity duration-200 whitespace-nowrap z-50">
                                <?= htmlspecialchars($deadlineStatus['message'] ?? 'Deadline passed') ?>
                                <div class="absolute top-1/2 left-0 transform -translate-x-1 -translate-y-1/2 w-2 h-2 bg-gray-900 rotate-45"></div>
                            </div>
                        </div>
                    <?php else: ?>
                        <a href="/chair/schedule_management" class="group relative flex items-center px-4 py-3 text-gray-300 hover:bg-gray-700 hover:text-yellow-300 transition duration-300 rounded-md <?= strpos($currentUri, '/chair/schedule_management') !== false ? 'bg-gray-700 text-yellow-300' : '' ?>">
                            <i class="fas fa-plus-circle w-5 mr-2"></i> Create Schedule
                            <?php if (isset($deadlineStatus['deadline']) && $totalHours <= 48): ?>
                                <span class="ml-auto text-xs bg-yellow-100 text-yellow-800 px-2 py-1 rounded-full <?= ($totalHours <= 24) ? 'deadline-warning' : '' ?>">
                                    <?= $totalHours ?>h left
                                </span>
                                <div class="absolute left-full top-0 ml-2 px-3 py-2 bg-gray-900 text-white text-sm rounded-lg shadow-lg opacity-0 pointer-events-none group-hover:opacity-100 transition-opacity duration-200 whitespace-nowrap z-50">
                                    Deadline: <?= ($deadlineStatus['deadline'] ?? new DateTime())->format('M j, Y g:i A') ?>
                                    <div class="absolute top-1/2 left-0 transform -translate-x-1 -translate-y-1/2 w-2 h-2 bg-gray-900 rotate-45"></div>
                                </div>
                            <?php endif; ?>
                        </a>
                    <?php endif; ?>

                    <a href="/chair/my_schedule" class="flex items-center px-4 py-3 text-gray-300 hover:bg-gray-700 hover:text-yellow-300 transition duration-300 rounded-md <?= strpos($currentUri, '/chair/my_schedule') !== false ? 'bg-gray-700 text-yellow-300' : '' ?>">
                        <i class="fas fa-list w-5 mr-2"></i> My Schedule
                    </a>

                    <a href="/chair/faculty-teaching-load" class="flex items-center px-4 py-3 text-gray-300 hover:bg-gray-700 hover:text-yellow-300 transition duration-300 rounded-md <?= strpos($currentUri, '/chair/faculty-teaching-load') !== false ? 'bg-gray-700 text-yellow-300' : '' ?>">
                        <i class="fas fa-user-clock w-5 mr-2"></i> Faculty Teaching Load
                    </a>

                    <a href="/chair/schedule_history" class="flex items-center px-4 py-3 text-gray-300 hover:bg-gray-700 hover:text-yellow-300 transition duration-300 rounded-md <?= strpos($currentUri, '/chair/schedule_history') !== false ? 'bg-gray-700 text-yellow-300' : '' ?>">
                        <i class="fas fa-history w-5 mr-2"></i>View All Created Schedule
                    </a>
                </div>
            </div>

            <!-- Curriculum -->
            <a href="/chair/curriculum" class="nav-item flex items-center px-4 py-3 text-gray-200 rounded-lg mb-1 hover:text-white transition-all duration-300 <?= strpos($currentUri, '/chair/curriculum') !== false ? 'active-nav bg-gray-800 text-yellow-300' : '' ?>">
                <i class="fas fa-graduation-cap w-5 mr-3 <?= strpos($currentUri, '/chair/curriculum') !== false ? 'text-yellow-400' : 'text-gray-400' ?>"></i>
                <span>Curriculum</span>
            </a>

            <!-- Faculty -->
            <a href="/chair/faculty" class="nav-item flex items-center px-4 py-3 text-gray-200 rounded-lg mb-1 hover:text-white transition-all duration-300 <?= ($currentUri === '/chair/faculty' || strpos($currentUri, '/chair/faculty?') === 0 || (strpos($currentUri, '/chair/faculty/') !== false && strpos($currentUri, '/chair/faculty-') === false)) ? 'active-nav bg-gray-800 text-yellow-300' : '' ?>">
                <i class="fas fa-chalkboard-teacher w-5 mr-3 <?= ($currentUri === '/chair/faculty' || strpos($currentUri, '/chair/faculty?') === 0 || (strpos($currentUri, '/chair/faculty/') !== false && strpos($currentUri, '/chair/faculty-') === false)) ? 'text-yellow-400' : 'text-gray-400' ?>"></i>
                <span>Faculty</span>
            </a>

            <!-- Courses -->
            <a href="/chair/courses" class="nav-item flex items-center px-4 py-3 text-gray-200 rounded-lg mb-1 hover:text-white transition-all duration-300 <?= strpos($currentUri, '/chair/courses') !== false ? 'active-nav bg-gray-800 text-yellow-300' : '' ?>">
                <i class="fas fa-book w-5 mr-3 <?= strpos($currentUri, '/chair/courses') !== false ? 'text-yellow-400' : 'text-gray-400' ?>"></i>
                <span>Courses</span>
            </a>

            <!-- Sections -->
            <a href="/chair/sections" class="nav-item flex items-center px-4 py-3 text-gray-200 rounded-lg mb-1 hover:text-white transition-all duration-300 <?= strpos($currentUri, '/chair/sections') !== false ? 'active-nav bg-gray-800 text-yellow-300' : '' ?>">
                <i class="fas fa-layer-group w-5 mr-3 <?= strpos($currentUri, '/chair/sections') !== false ? 'text-yellow-400' : 'text-gray-400' ?>"></i>
                <span>Sections</span>
            </a>

            <!-- Classrooms -->
            <a href="/chair/classroom" class="nav-item flex items-center px-4 py-3 text-gray-200 rounded-lg mb-1 hover:text-white transition-all duration-300 <?= strpos($currentUri, '/chair/classroom') !== false ? 'active-nav bg-gray-800 text-yellow-300' : '' ?>">
                <i class="fas fa-door-open w-5 mr-3 <?= strpos($currentUri, '/chair/classroom') !== false ? 'text-yellow-400' : 'text-gray-400' ?>"></i>
                <span>Classrooms</span>
            </a>

            <!-- Profile -->
            <a href="/chair/profile" class="nav-item flex items-center px-4 py-3 text-gray-200 rounded-lg mb-1 hover:text-white transition-all duration-300 <?= strpos($currentUri, '/chair/profile') !== false ? 'active-nav bg-gray-800 text-yellow-300' : '' ?>">
                <i class="fas fa-user-circle w-5 mr-3 <?= strpos($currentUri, '/chair/profile') !== false ? 'text-yellow-400' : 'text-gray-400' ?>"></i>
                <span>Profile</span>
            </a>

            <!-- Settings -->
            <a href="/chair/settings" class="nav-item flex items-center px-4 py-3 text-gray-200 rounded-lg mb-1 hover:text-white transition-all duration-300 <?= strpos($currentUri, '/chair/settings') !== false ? 'active-nav bg-gray-800 text-yellow-300' : '' ?>">
                <i class="fas fa-cog w-5 mr-3 <?= strpos($currentUri, '/chair/settings') !== false ? 'text-yellow-400' : 'text-gray-400' ?>"></i>
                <span>Settings</span>
            </a>

            <!-- Reports
            <a href="/chair/reports" class="nav-item flex items-center px-4 py-3 text-gray-200 rounded-lg mb-1 hover:text-white transition-all duration-300 <?= strpos($currentUri, '/chair/reports') !== false ? 'active-nav bg-gray-800 text-yellow-300' : '' ?>">
                <i class="fas fa-chart-bar w-5 mr-3 <?= strpos($currentUri, '/chair/reports') !== false ? 'text-yellow-400' : 'text-gray-400' ?>"></i>
                <span>Reports</span>
            </a>
             -->
        </nav>

        <!-- Sidebar Footer -->
        <div class="absolute bottom-0 left-0 right-0 p-4 bg-gray-900 border-t border-gray-700">
            <div class="flex items-center justify-between text-xs text-gray-400">
                <div>
                    <p>Program Chair System</p>
                    <p>Version 2.1.0</p>
                </div>
                <a href="/chair/system/status" class="text-yellow-400 hover:text-yellow-300 transition-all duration-300">
                    <i class="fas fa-circle text-green-500 mr-1"></i> Online
                </a>
            </div>
        </div>
    </aside>

    <main class="main-content pt-20 p-4 md:pt-16 md:p-6 lg:p-8 min-h-screen transition-all duration-300 bg-gray-50 relative">
        <div class="max-w-7xl mx-auto">
            <!-- Breadcrumb -->
            <?php
            $segments = explode('/', trim($currentUri, '/'));
            if (count($segments) > 1):
            ?>
                <nav class="flex mb-5 text-sm breadcrumb-text" aria-label="Breadcrumb">
                    <ol class="inline-flex items-center space-x-1 md:space-x-3">
                        <li class="inline-flex items-center">
                            <a href="/chair/dashboard" class="inline-flex items-center text-gray-500 hover:text-yellow-500">
                                <i class="fas fa-home mr-2"></i>
                                <span class="hidden sm:inline">Home</span>
                            </a>
                        </li>
                        <?php
                        $path = '/chair';
                        foreach ($segments as $index => $segment):
                            if ($index == 0) continue;
                            $path .= '/' . $segment;
                            $isLast = ($index === count($segments) - 1);
                        ?>
                            <li>
                                <div class="flex items-center">
                                    <i class="fas fa-chevron-right text-gray-400 mx-2"></i>
                                    <?php if ($isLast): ?>
                                        <span class="text-yellow-600 font-medium mobile-text-sm"><?= ucfirst(str_replace('-', ' ', $segment)) ?></span>
                                    <?php else: ?>
                                        <a href="<?= $path ?>" class="text-gray-500 hover:text-yellow-500 mobile-text-sm"><?= ucfirst(str_replace('-', ' ', $segment)) ?></a>
                                    <?php endif; ?>
                                </div>
                            </li>
                        <?php endforeach; ?>
                    </ol>
                </nav>
            <?php endif; ?>

            <!-- Page Content -->
            <div class="slide-in-left">
                <?php echo $content; ?>
            </div>
        </div>
    </main>

    <!-- Modal Container -->
    <div id="modal-container">
        <?php echo $modal_content; ?>
    </div>

    <script>
        // Mobile Hamburger Menu and Sidebar Control
        const hamburgerMenu = document.getElementById('hamburger-menu');
        const sidebar = document.getElementById('sidebar');
        const sidebarOverlay = document.getElementById('sidebar-overlay');

        // Toggle sidebar for mobile
        function toggleSidebar() {
            const isSmallScreen = window.innerWidth < 768;

            if (isSmallScreen) {
                sidebar.classList.toggle('show');
                sidebarOverlay.classList.toggle('show');
                hamburgerMenu.classList.toggle('active');

                // Prevent body scroll when sidebar is open on mobile
                if (sidebar.classList.contains('show')) {
                    document.body.style.overflow = 'hidden';
                } else {
                    document.body.style.overflow = '';
                }
            }
        }

        // Hide hamburger menu on desktop
        function updateHamburgerVisibility() {
            if (window.innerWidth >= 768) {
                hamburgerMenu.style.display = 'none';
            } else {
                hamburgerMenu.style.display = 'flex';
            }
        }

        // Initial check
        updateHamburgerVisibility();

        // Update on window resize
        window.addEventListener('resize', updateHamburgerVisibility);

        // Close sidebar when clicking overlay
        function closeSidebar() {
            sidebar.classList.remove('show');
            sidebarOverlay.classList.remove('show');
            hamburgerMenu.classList.remove('active');
            document.body.style.overflow = '';
        }

        // Event listeners
        hamburgerMenu.addEventListener('click', toggleSidebar);
        sidebarOverlay.addEventListener('click', closeSidebar);

        // Handle window resize
        window.addEventListener('resize', () => {
            if (window.innerWidth >= 768) {
                // Desktop view - ensure sidebar is visible and overlay is hidden
                sidebar.classList.remove('show');
                sidebarOverlay.classList.remove('show');
                hamburgerMenu.classList.remove('active');
                document.body.style.overflow = '';
            }
        });

        // Close sidebar when clicking on a link (mobile only)
        const sidebarLinks = sidebar.querySelectorAll('a');
        sidebarLinks.forEach(link => {
            link.addEventListener('click', () => {
                if (window.innerWidth < 768) {
                    closeSidebar();
                }
            });
        });

        // Dropdown functionality
        document.addEventListener('DOMContentLoaded', () => {
            const dropdowns = document.querySelectorAll('.dropdown');

            dropdowns.forEach(dropdown => {
                const trigger = dropdown.querySelector('button');
                const menu = dropdown.querySelector('.dropdown-menu');
                const toggleIcon = trigger.querySelector('.toggle-icon');

                trigger.addEventListener('click', (e) => {
                    e.stopPropagation();
                    const isOpen = menu.classList.contains('show');

                    // Close all dropdowns
                    dropdowns.forEach(d => {
                        d.querySelector('.dropdown-menu').classList.remove('show');
                        const icon = d.querySelector('.toggle-icon');
                        if (icon) icon.classList.remove('rotate-icon');
                    });

                    // Toggle current dropdown
                    if (!isOpen) {
                        menu.classList.add('show');
                        if (toggleIcon) toggleIcon.classList.add('rotate-icon');
                    }
                });

                // Close dropdown on outside click
                document.addEventListener('click', (event) => {
                    if (!dropdown.contains(event.target)) {
                        menu.classList.remove('show');
                        if (toggleIcon) toggleIcon.classList.remove('rotate-icon');
                    }
                });
            });
        });

        // Department Switcher functionality
        document.addEventListener('DOMContentLoaded', function() {
            const departmentSwitchItems = document.querySelectorAll('.department-switch-item');
            const departmentSwitchForm = document.getElementById('department-switch-form');
            const selectedDepartmentInput = document.getElementById('selected-department-id');

            departmentSwitchItems.forEach(item => {
                item.addEventListener('click', async function(e) {
                    e.preventDefault();
                    const departmentId = this.dataset.deptId;

                    if (this.classList.contains('bg-yellow-100')) {
                        return;
                    }

                    selectedDepartmentInput.value = departmentId;

                    // Show loading state
                    const currentButton = this;
                    const originalContent = currentButton.innerHTML;
                    currentButton.innerHTML = '<i class="fas fa-spinner fa-spin"></i> Switching...';
                    currentButton.disabled = true;

                    try {
                        const response = await fetch('/chair/switch-department', {
                            method: 'POST',
                            headers: {
                                'Content-Type': 'application/x-www-form-urlencoded',
                            },
                            body: `department_id=${departmentId}`
                        });

                        // Debug: Check what's actually being returned
                        const responseText = await response.text();
                        console.log('Raw response:', responseText);

                        // Try to parse as JSON, but handle the case where it's HTML
                        let data;
                        try {
                            data = JSON.parse(responseText);
                        } catch (parseError) {
                            console.error('Failed to parse JSON. Response is:', responseText.substring(0, 200));
                            throw new Error('Server returned HTML instead of JSON. Check if endpoint exists.');
                        }

                        if (data.success) {
                            showToast('Department switched successfully!', 'success');
                            setTimeout(() => {
                                window.location.reload();
                            }, 1000);
                        } else {
                            showToast(data.error || 'Failed to switch department', 'error');
                            currentButton.innerHTML = originalContent;
                            currentButton.disabled = false;
                        }
                    } catch (error) {
                        console.error('Department switch error:', error);
                        showToast('Endpoint not found or server error. Check console.', 'error');
                        currentButton.innerHTML = originalContent;
                        currentButton.disabled = false;
                    }
                });
            });

            function showToast(message, type = 'info') {
                const toastContainer = document.getElementById('toast-container');
                if (!toastContainer) return;

                const toast = document.createElement('div');
                toast.className = `p-4 rounded-lg shadow-lg text-white ${
            type === 'success' ? 'bg-green-500' : 
            type === 'error' ? 'bg-red-500' : 'bg-blue-500'
        }`;
                toast.textContent = message;
                toastContainer.appendChild(toast);

                setTimeout(() => toast.remove(), 3000);
            }
        });

        // Prevent sidebar from interfering with modals
        const modalContainer = document.getElementById('modal-container');
        const observer = new MutationObserver((mutations) => {
            mutations.forEach((mutation) => {
                if (mutation.type === 'childList') {
                    const hasModal = modalContainer.querySelector('.modal-overlay');
                    if (hasModal && window.innerWidth < 768) {
                        closeSidebar();
                    }
                }
            });
        });

        observer.observe(modalContainer, {
            childList: true,
            subtree: true
        });

        document.addEventListener('DOMContentLoaded', function() {
            const roleSwitcherBtn = document.getElementById('role-switcher-btn');
            const roleSwitcherMenu = document.getElementById('role-switcher-menu');
            const roleSwitchItems = document.querySelectorAll('.role-switch-item');

            if (!roleSwitcherBtn) return;

            // Toggle menu
            roleSwitcherBtn.addEventListener('click', (e) => {
                e.stopPropagation();
                roleSwitcherMenu.classList.toggle('hidden');
            });

            // Handle role switching
            roleSwitchItems.forEach(item => {
                item.addEventListener('click', async (e) => {
                    e.preventDefault();
                    const role = item.dataset.role;
                    const currentRole = '<?php echo strtolower($currentRole); ?>';

                    console.log('Switching to role:', role);
                    console.log('Current role:', currentRole);

                    if (role === currentRole) {
                        roleSwitcherMenu.classList.add('hidden');
                        return;
                    }

                    // Disable button to prevent double-clicks
                    item.disabled = true;
                    item.style.opacity = '0.5';

                    try {
                        const formData = new FormData();
                        formData.append('role', role);

                        const response = await fetch('/switch-role', {
                            method: 'POST',
                            body: formData
                        });

                        console.log('Response status:', response.status);
                        const data = await response.json();
                        console.log('Response data:', data);

                        if (data.success) {
                            // Show toast notification
                            const toastContainer = document.getElementById('toast-container');
                            if (toastContainer) {
                                const toast = document.createElement('div');
                                toast.className = 'p-4 rounded-lg shadow-lg text-white bg-green-500';
                                toast.textContent = data.message;
                                toastContainer.appendChild(toast);

                                setTimeout(() => toast.remove(), 3000);
                            }

                            // Redirect after brief delay
                            setTimeout(() => {
                                window.location.href = data.redirect;
                            }, 500);
                        } else {
                            console.error('Switch failed:', data);
                            alert(data.error || 'Failed to switch role');
                            item.disabled = false;
                            item.style.opacity = '1';
                        }
                    } catch (error) {
                        console.error('Role switch error:', error);
                        alert('An error occurred while switching roles');
                        item.disabled = false;
                        item.style.opacity = '1';
                    }
                });
            });

            // Close menu on outside click
            document.addEventListener('click', (e) => {
                if (!e.target.closest('[id^="role-switcher"]') && roleSwitcherBtn) {
                    roleSwitcherMenu.classList.add('hidden');
                }
            });

            // Close on Escape key
            document.addEventListener('keydown', (e) => {
                if (e.key === 'Escape' && roleSwitcherMenu) {
                    roleSwitcherMenu.classList.add('hidden');
                }
            });
        });
    </script>
</body>

</html>