<?php
require_once __DIR__ . '/../../controllers/DeanController.php';

// Fetch profile picture from session or database
$profilePicture = $_SESSION['profile_picture'] ?? null;
if (!$profilePicture) {
    try {
        $db = (new Database())->connect();
        $stmt = $db->prepare("SELECT profile_picture FROM users WHERE user_id = :user_id");
        $stmt->execute([':user_id' => $_SESSION['user_id']]);
        $profilePicture = $stmt->fetchColumn() ?: '';
        $_SESSION['profile_picture'] = $profilePicture; // Cache in session
    } catch (PDOException $e) {
        error_log("layout: Error fetching profile picture - " . $e->getMessage());
        $profilePicture = '';
    }
}

// Fetch college logo based on dean's college ID
$collegeLogoPath = '/assets/logo/main_logo/PRMSUlogo.png'; // Fallback to university logo
try {
    $db = (new Database())->connect();
    $stmt = $db->prepare("SELECT logo_path FROM colleges WHERE college_id = (SELECT college_id FROM users WHERE user_id = :user_id)");
    $stmt->execute([':user_id' => $_SESSION['user_id']]);
    $logoPath = $stmt->fetchColumn();
    if ($logoPath) {
        $collegeLogoPath = $logoPath;
    }
} catch (PDOException $e) {
    error_log("layout: Error fetching college logo - " . $e->getMessage());
}

// Determine current page for active navigation highlighting
$currentUri = $_SERVER['REQUEST_URI'];

$deanController = new DeanController();
$stats = $deanController->getStats();
$stats = $stats ?? ['total_pending' => 0];

$pendingFacultyCount = $deanController->getPendingFacultyCount();
?>

<!DOCTYPE html>
<html lang="en">

<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Dean Dashboard</title>
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

        @keyframes fadeIn {
            from {
                opacity: 0;
            }

            to {
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

        /* Responsive Header */
        .header {
            background: white;
            box-shadow: 0 2px 10px rgba(0, 0, 0, 0.08);
            transition: all 0.3s ease;
        }

        .header-content {
            display: flex;
            align-items: center;
            justify-content: space-between;
            padding: 0.75rem 1rem;
            max-width: 100%;
        }

        /* Logo section - responsive */
        .logo-section {
            display: flex;
            align-items: center;
            gap: 0.5rem;
            min-width: 0;
            flex-shrink: 0;
        }

        .university-logo {
            height: 32px;
            width: auto;
            transition: transform 0.3s ease;
            flex-shrink: 0;
        }

        .university-logo:hover {
            transform: scale(1.05);
        }

        .logo-text {
            font-size: 1rem;
            font-weight: 600;
            color: #1f2937;
            white-space: nowrap;
        }

        /* Mobile hamburger */
        .mobile-toggle {
            display: flex;
            align-items: center;
            justify-content: center;
            width: 40px;
            height: 40px;
            border-radius: 0.375rem;
            background: transparent;
            border: none;
            color: #6b7280;
            cursor: pointer;
            transition: all 0.3s ease;
            margin-right: 0.75rem;
        }

        .mobile-toggle:hover {
            background-color: #f3f4f6;
            color: #e5ad0f;
        }

        /* User profile section - responsive */
        .user-section {
            display: flex;
            align-items: center;
            gap: 0.75rem;
            min-width: 0;
        }

        .profile-dropdown {
            position: relative;
        }

        .profile-button {
            display: flex;
            align-items: center;
            gap: 0.5rem;
            padding: 0.5rem;
            border-radius: 0.375rem;
            background: transparent;
            border: none;
            color: #6b7280;
            cursor: pointer;
            transition: all 0.3s ease;
            min-width: 0;
        }

        .profile-button:hover {
            color: #e5ad0f;
            background-color: #fef3c7;
        }

        .profile-avatar {
            height: 32px;
            width: 32px;
            border-radius: 50%;
            border: 2px solid #e5ad0f;
            object-fit: cover;
            flex-shrink: 0;
        }

        .profile-initials {
            height: 32px;
            width: 32px;
            border-radius: 50%;
            border: 2px solid #e5ad0f;
            background-color: #e5ad0f;
            display: flex;
            align-items: center;
            justify-content: center;
            color: white;
            font-size: 0.75rem;
            font-weight: bold;
            flex-shrink: 0;
        }

        .profile-name {
            font-size: 0.875rem;
            font-weight: 500;
            white-space: nowrap;
            overflow: hidden;
            text-overflow: ellipsis;
            max-width: 120px;
        }

        .profile-chevron {
            font-size: 0.75rem;
            transition: transform 0.3s ease;
            flex-shrink: 0;
        }

        /* Dropdown menu - responsive */
        .dropdown-menu {
            display: none;
            position: absolute;
            top: 100%;
            right: 0;
            min-width: 200px;
            z-index: 50;
            box-shadow: 0 10px 25px rgba(0, 0, 0, 0.15);
            border-radius: 0.5rem;
            background: #1f2937;
            border: 1px solid #374151;
            margin-top: 0.5rem;
            overflow: hidden;
        }

        .dropdown-menu.show {
            display: block;
            animation: slideInRight 0.2s ease forwards;
        }

        .dropdown-item {
            display: flex;
            align-items: center;
            padding: 0.75rem 1rem;
            color: #d1d5db;
            text-decoration: none;
            font-size: 0.875rem;
            transition: all 0.3s ease;
        }

        .dropdown-item:hover {
            background-color: #374151;
            color: #fbbf24;
        }

        .dropdown-item i {
            margin-right: 0.75rem;
            width: 16px;
            flex-shrink: 0;
        }

        /* Sidebar - responsive */
        .sidebar {
            background: linear-gradient(to bottom, #1f2937, #111827);
            box-shadow: 2px 0 10px rgba(0, 0, 0, 0.1);
            transition: all 0.3s ease;
            z-index: 40;
            width: 256px;
            position: fixed;
            top: 0;
            left: 0;
            height: 100vh;
            overflow-y: auto;
            transform: translateX(-100%);
        }

        .sidebar.show {
            transform: translateX(0);
        }

        /* Sidebar overlay for mobile */
        .sidebar-overlay {
            display: none;
            position: fixed;
            top: 0;
            left: 0;
            right: 0;
            bottom: 0;
            background-color: rgba(0, 0, 0, 0.5);
            z-index: 30;
        }

        #role-switcher-menu {
            animation: slideInRight 0.2s ease forwards;
        }

        .role-switch-item:hover {
            background-color: #fef3c7 !important;
        }

        .sidebar-overlay.show {
            display: block;
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
            background-color: rgba(229, 173, 15, 0.15);
            z-index: -1;
            transition: width 0.3s ease;
        }

        .nav-item:hover::before {
            width: 100%;
        }

        .nav-item:hover {
            color: #e5ad0f;
        }

        .active-nav {
            border-left: 4px solid #e5ad0f;
            background-color: rgba(229, 173, 15, 0.1);
            font-weight: 500;
        }

        /* Dropdown for Manage pages */
        .nav-dropdown {
            position: relative;
        }

        .nav-dropdown-toggle {
            display: flex;
            align-items: center;
            padding: 0.75rem 1rem;
            color: #d1d5db;
            text-decoration: none;
            font-size: 0.875rem;
            width: 100%;
            border-radius: 0.375rem;
            transition: all 0.3s ease;
            cursor: pointer;
        }

        .nav-dropdown-toggle:hover {
            color: #e5ad0f;
        }

        .nav-dropdown-toggle i {
            margin-right: 0.75rem;
            width: 16px;
            flex-shrink: 0;
        }

        .nav-dropdown-toggle .chevron {
            margin-left: auto;
            transition: transform 0.3s ease;
        }

        .nav-dropdown-menu {
            display: none;
            padding-left: 1rem;
            background: #1f2937;
        }

        .nav-dropdown-menu.show {
            display: block;
            animation: slideInRight 0.2s ease forwards;
        }

        .nav-dropdown-item {
            display: flex;
            align-items: center;
            padding: 0.5rem 1rem;
            color: #d1d5db;
            text-decoration: none;
            font-size: 0.875rem;
            border-radius: 0.375rem;
            transition: all 0.3s ease;
        }

        .nav-dropdown-item:hover {
            background-color: #374151;
            color: #e5ad0f;
        }

        .nav-dropdown-item i {
            margin-right: 0.75rem;
            width: 16px;
            flex-shrink: 0;
        }

        .nav-dropdown-item.active-nav {
            border-left: 4px solid #e5ad0f;
            background-color: rgba(229, 173, 15, 0.1);
            font-weight: 500;
            color: #e5ad0f;
        }

        /* Main content - responsive */
        .main-content {
            transition: all 0.3s ease;
            padding-top: 60px;
            padding-left: 1rem;
            padding-right: 1rem;
            padding-bottom: 2rem;
            min-height: 100vh;
            background-color: #f3f4f6;
        }

        .content-container {
            max-width: 1280px;
            margin: 0 auto;
        }

        /* Breadcrumb - responsive */
        .breadcrumb {
            display: flex;
            flex-wrap: wrap;
            align-items: center;
            gap: 0.5rem;
            margin-bottom: 1.5rem;
            font-size: 0.875rem;
        }

        .breadcrumb-item {
            display: flex;
            align-items: center;
            gap: 0.5rem;
        }

        .breadcrumb-separator {
            color: #9ca3af;
            font-size: 0.75rem;
        }

        /* Responsive breakpoints */
        @media (min-width: 768px) {
            .mobile-toggle {
                display: none;
            }

            .sidebar {
                transform: translateX(0);
                position: fixed;
            }

            .main-content {
                margin-left: 256px;
                padding-left: 2rem;
                padding-right: 2rem;
            }

            .header-content {
                padding: 1rem 1.5rem;
            }

            .university-logo {
                height: 40px;
            }

            .logo-text {
                font-size: 1.125rem;
            }

            .profile-name {
                max-width: 150px;
            }
        }

        @media (min-width: 1024px) {
            .main-content {
                padding-left: 2.5rem;
                padding-right: 2.5rem;
            }

            .header {
                position: fixed;
                top: 0;
                left: 256px;
                /* Sidebar width */
                right: 0;
                z-index: 20;
            }

            .header-content {
                padding: 1rem 1.5rem;
            }
        }

        /* Mobile optimizations */
        @media (max-width: 767px) {
            .logo-text {
                display: none;
            }

            .profile-name {
                display: none;
            }

            .sidebar {
                z-index: 50;
            }

            .main-content {
                margin-left: 0;
            }

            .breadcrumb {
                font-size: 0.75rem;
            }

            .nav-dropdown-menu {
                padding-left: 0.5rem;
            }
        }

        /* Small mobile screens */
        @media (max-width: 480px) {
            .header-content {
                padding: 0.75rem;
            }

            .profile-avatar,
            .profile-initials {
                height: 28px;
                width: 28px;
            }

            .university-logo {
                height: 28px;
            }

            .main-content {
                padding-top: 65px;
                padding-left: 0.75rem;
                padding-right: 0.75rem;
            }
        }

        /* Additional responsive utilities */
        .sr-only {
            position: absolute;
            width: 1px;
            height: 1px;
            padding: 0;
            margin: -1px;
            overflow: hidden;
            clip: rect(0, 0, 0, 0);
            white-space: nowrap;
            border: 0;
        }

        /* Scrollbar styling */
        ::-webkit-scrollbar {
            width: 8px;
            height: 8px;
        }

        ::-webkit-scrollbar-track {
            background: #f1f1f1;
            border-radius: 10px;
        }

        ::-webkit-scrollbar-thumb {
            background: #e5ad0f;
            border-radius: 10px;
        }

        ::-webkit-scrollbar-thumb:hover {
            background: #b98a0c;
        }
    </style>
</head>

<body class="bg-gray-100">
    <!-- Toast notifications container -->
    <div id="toast-container" class="fixed top-5 right-5 z-50 space-y-4"></div>

    <!-- Sidebar Overlay (Mobile) -->
    <div id="sidebar-overlay" class="sidebar-overlay"></div>

    <!-- Header -->
    <header class="header">
        <div class="header-content max-w-full mx-auto flex items-center justify-between">
            <!-- Left section: Mobile toggle + Logo -->
            <div class="logo-section">
                <button id="mobile-toggle" class="mobile-toggle" aria-label="Toggle sidebar">
                    <i class="fas fa-bars text-xl"></i>
                </button>
                <a href="/dean/dashboard" class="flex items-center gap-3">
                    <img src="<?php echo htmlspecialchars($collegeLogoPath); ?>" alt="College Logo" class="university-logo" onerror="this.src='/assets/logo/main_logo/PRMSUlogo.png'; console.log('Fallback to university logo due to error')">
                    <span class="logo-text">Automated Classroom Scheduling System</span>
                </a>
            </div>

            <!-- Right section: User profile -->
            <div class="user-section">
                <div class="profile-dropdown">
                    <button class="profile-button" aria-expanded="false" aria-haspopup="true">
                        <?php if (!empty($profilePicture)): ?>
                            <img class="profile-avatar" src="<?php echo htmlspecialchars($profilePicture); ?>" alt="Profile picture">
                        <?php else: ?>
                            <div class="profile-initials">
                                <?php echo strtoupper(substr($_SESSION['first_name'], 0, 1) . substr($_SESSION['last_name'], 0, 1)); ?>
                            </div>
                        <?php endif; ?>
                        <span class="profile-name"><?php echo htmlspecialchars($_SESSION['first_name']); ?></span>
                        <i class="fas fa-chevron-down profile-chevron"></i>
                    </button>
                    <div class="dropdown-menu" role="menu">
                        <a href="/dean/profile" class="dropdown-item" role="menuitem">
                            <i class="fas fa-user"></i>
                            Profile
                        </a>
                        <a href="/dean/settings" class="dropdown-item" role="menuitem">
                            <i class="fas fa-cog"></i>
                            Settings
                        </a>
                        <a href="/dean/logout" class="dropdown-item" role="menuitem">
                            <i class="fas fa-sign-out-alt"></i>
                            Logout
                        </a>
                    </div>
                </div>

                <?php
                $availableRoles = $_SESSION['roles'] ?? [];
                $currentRole = $_SESSION['current_role'] ?? ($_SESSION['roles'][0] ?? null);
                ?>

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
    <aside id="sidebar" class="sidebar" role="navigation" aria-label="Main navigation">
        <!-- Sidebar Header -->
        <div class="py-6 px-6 flex flex-col items-center justify-center border-b border-gray-700 bg-gray-900">
            <div class="flex items-center justify-center mb-3">
                <img src="/assets/logo/main_logo/PRMSUlogo.png" alt="PRMSU Logo" class="h-12">
            </div>
            <h2 class="text-xl font-bold text-yellow-400 text-center">PRMSU Scheduling System - ACSS</h2>
            <p class="text-xs text-gray-400 mt-1 text-center">Dean Management System</p>
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
                        <span>College Dean</span>
                    </div>
                </div>
            </div>
        </div>

        <!-- Navigation -->
        <nav class="mt-4 px-2" role="navigation">
            <!-- Dashboard Link -->
            <a href="/dean/dashboard" class="nav-item flex items-center px-4 py-3 text-gray-200 rounded-lg mb-1 hover:text-white transition-all duration-300 <?= strpos($currentUri, '/dean/dashboard') !== false ? 'active-nav bg-gray-800 text-yellow-400' : '' ?>">
                <i class="fas fa-tachometer-alt w-5 mr-3 <?= strpos($currentUri, '/dean/dashboard') !== false ? 'text-yellow-400' : 'text-gray-400' ?>"></i>
                <span>Dashboard</span>
            </a>

            <!-- Schedule Link -->
            <a href="/dean/schedule" class="nav-item flex items-center px-4 py-3 text-gray-200 rounded-lg mb-1 hover:text-white transition-all duration-300 <?= strpos($currentUri, '/dean/schedule') !== false ? 'active-nav bg-gray-800 text-yellow-400' : '' ?>">
                <i class="fas fa-calendar-alt w-5 mr-3 <?= strpos($currentUri, '/dean/schedule') !== false ? 'text-yellow-400' : 'text-gray-400' ?>"></i>
                <span>My Schedule</span>
            </a>

            <!--Faculty Teaching Load Schedule Link -->
            <a href="/dean/faculty-teaching-load" class="nav-item flex items-center px-4 py-3 text-gray-200 rounded-lg mb-1 hover:text-white transition-all duration-300 <?= strpos($currentUri, '/dean/faculty-teaching-load') !== false ? 'active-nav bg-gray-800 text-yellow-400' : '' ?>">
                <i class="fas fa-chalkboard-teacher w-5 mr-3 <?= strpos($currentUri, '/dean/faculty-teaching-load') !== false ? 'text-yellow-400' : 'text-gray-400' ?>"></i>
                <span>Faculty Teaching Load</span>
            </a>

            <!-- Manage Dropdown -->
            <div class="nav-dropdown">
                <button class="nav-dropdown-toggle flex items-center px-4 py-3 text-gray-200 rounded-lg mb-1 hover:text-white transition-all duration-300 <?= (strpos($currentUri, '/dean/manage_department') !== false || strpos($currentUri, '/dean/manage_schedules') !== false || strpos($currentUri, '/dean/classroom') !== false || (strpos($currentUri, '/dean/faculty') !== false && strpos($currentUri, '/dean/faculty-teaching-load') === false)) ? 'active-nav bg-gray-800 text-yellow-400' : '' ?>">
                    <i class="fas fa-cogs w-5 mr-3 <?= (strpos($currentUri, '/dean/manage_department') !== false || strpos($currentUri, '/dean/manage_schedules') !== false || strpos($currentUri, '/dean/classroom') !== false || (strpos($currentUri, '/dean/faculty') !== false && strpos($currentUri, '/dean/faculty-teaching-load') === false)) ? 'text-yellow-400' : 'text-gray-400' ?>"></i>
                    <span>Manage</span>
                    <i class="fas fa-chevron-down chevron ml-auto text-xs transition-transform <?= (strpos($currentUri, '/dean/manage_department') !== false || strpos($currentUri, '/dean/manage_schedules') !== false || strpos($currentUri, '/dean/classroom') !== false || (strpos($currentUri, '/dean/faculty') !== false && strpos($currentUri, '/dean/faculty-teaching-load') === false)) ? 'rotate-180' : '' ?>"></i>
                </button>
                <div class="nav-dropdown-menu <?= (strpos($currentUri, '/dean/manage_department') !== false || strpos($currentUri, '/dean/manage_schedules') !== false || strpos($currentUri, '/dean/classroom') !== false || (strpos($currentUri, '/dean/faculty') !== false && strpos($currentUri, '/dean/faculty-teaching-load') === false)) ? 'show' : '' ?>">
                    <a href="/dean/manage_department" class="nav-dropdown-item <?= strpos($currentUri, '/dean/manage_department') !== false ? 'active-nav' : '' ?>">
                        <i class="fas fa-university w-5 mr-3 <?= strpos($currentUri, '/dean/manage_department') !== false ? 'text-yellow-400' : 'text-gray-400' ?>"></i>
                        <span>Manage College Departments</span>
                    </a>
                    <a href="/dean/manage_schedules" class="nav-dropdown-item <?= strpos($currentUri, '/dean/manage_schedules') !== false ? 'active-nav' : '' ?>">
                        <i class="fas fa-plus-circle w-5 mr-3 <?= strpos($currentUri, '/dean/manage_schedules') !== false ? 'text-yellow-400' : 'text-gray-400' ?>"></i>
                        <span>Manage College Departments Schedule</span>
                        <?php if (isset($stats) && $stats['total_pending'] > 0): ?>
                            <span class="ml-auto bg-red-500 text-white text-xs font-bold px-2 py-1 rounded-full">
                                <?php echo $stats['total_pending']; ?>
                            </span>
                        <?php endif; ?>
                    </a>
                    <a href="/dean/classroom" class="nav-dropdown-item <?= strpos($currentUri, '/dean/classroom') !== false ? 'active-nav' : '' ?>">
                        <i class="fas fa-door-open w-5 mr-3 <?= strpos($currentUri, '/dean/classroom') !== false ? 'text-yellow-400' : 'text-gray-400' ?>"></i>
                        <span>Manage Classrooms</span>
                    </a>
                    <a href="/dean/faculty" class="nav-dropdown-item <?= strpos($currentUri, '/dean/faculty') !== false ? 'active-nav' : '' ?>">
                        <i class="fas fa-chalkboard-teacher w-5 mr-3 <?= strpos($currentUri, '/dean/faculty') !== false ? 'text-yellow-400' : 'text-gray-400' ?>"></i>
                        <span>Manage Faculty</span>
                        <?php if (isset($pendingFacultyCount) && $pendingFacultyCount > 0): ?>
                            <span class="ml-auto bg-red-500 text-white text-xs font-bold px-2 py-1 rounded-full">
                                <?php echo $pendingFacultyCount; ?>
                            </span>
                        <?php endif; ?>
                    </a>
                </div>
            </div>

            <!-- My Activity Logs Link -->
            <a href="/dean/activities" class="nav-item flex items-center px-4 py-3 text-gray-200 rounded-lg mb-1 hover:text-white transition-all duration-300 <?php echo strpos($currentUri, '/dean/activities') !== false ? 'active-nav bg-gray-800 text-yellow-400' : ''; ?>">
                <i class="fa-solid fa-desktop w-5 mr-3 <?php echo strpos($currentUri, '/dean/activities') !== false ? 'text-yellow-400' : 'text-gray-400'; ?>"></i>
                <span>College Activity Logs</span>
            </a>

            <!-- Profile Link -->
            <a href="/dean/profile" class="nav-item flex items-center px-4 py-3 text-gray-200 rounded-lg mb-1 hover:text-white transition-all duration-300 <?= strpos($currentUri, '/dean/profile') !== false ? 'active-nav bg-gray-800 text-yellow-400' : '' ?>">
                <i class="fas fa-user-circle w-5 mr-3 <?= strpos($currentUri, '/dean/profile') !== false ? 'text-yellow-400' : 'text-gray-400' ?>"></i>
                <span>Profile</span>
            </a>

            <!-- Settings Link -->
            <a href="/dean/settings" class="nav-item flex items-center px-4 py-3 text-gray-200 rounded-lg mb-1 hover:text-white transition-all duration-300 <?= strpos($currentUri, '/dean/settings') !== false ? 'active-nav bg-gray-800 text-yellow-400' : '' ?>">
                <i class="fas fa-cog w-5 mr-3 <?= strpos($currentUri, '/dean/settings') !== false ? 'text-yellow-400' : 'text-gray-400' ?>"></i>
                <span>Settings</span>
            </a>
        </nav>

        <!-- Sidebar Footer -->
        <div class="absolute bottom-0 left-0 right-0 p-4 bg-gray-900 border-t border-gray-700">
            <div class="flex items-center justify-between text-xs text-gray-400">
                <div>
                    <p>Dean System</p>
                    <p>Version 2.1.0</p>
                </div>
                <a href="/dean/system/status" class="text-yellow-400 hover:text-yellow-300 transition-all duration-300">
                    <i class="fas fa-circle text-green-500 mr-1"></i> Online
                </a>
            </div>
        </div>
    </aside>

    <!-- Main Content -->
    <main class="main-content">
        <div class="content-container">
            <!-- Breadcrumb -->
            <?php
            $segments = explode('/', trim($currentUri, '/'));
            if (count($segments) > 1):
            ?>
                <nav class="breadcrumb" aria-label="Breadcrumb">
                    <div class="breadcrumb-item">
                        <a href="/dean/dashboard" class="inline-flex items-center text-gray-500 hover:text-yellow-500 transition-colors">
                            <i class="fas fa-home mr-2"></i>
                            Home
                        </a>
                    </div>
                    <?php
                    $path = '/dean';
                    foreach ($segments as $index => $segment):
                        if ($index == 0) continue;
                        $path .= '/' . $segment;
                        $isLast = ($index === count($segments) - 1);
                    ?>
                        <i class="fas fa-chevron-right breadcrumb-separator"></i>
                        <div class="breadcrumb-item">
                            <?php if ($isLast): ?>
                                <span class="text-yellow-500 font-medium"><?= ucfirst(str_replace('-', ' ', $segment)) ?></span>
                            <?php else: ?>
                                <a href="<?= $path ?>" class="text-gray-500 hover:text-yellow-500 transition-colors"><?= ucfirst(str_replace('-', ' ', $segment)) ?></a>
                            <?php endif; ?>
                        </div>
                    <?php endforeach; ?>
                </nav>
            <?php endif; ?>

            <!-- Page Content -->
            <div class="slide-in-left">
                <?php echo $content; ?>
            </div>
        </div>
    </main>

    <script>
        // DOM elements
        const mobileToggle = document.getElementById('mobile-toggle');
        const sidebar = document.getElementById('sidebar');
        const sidebarOverlay = document.getElementById('sidebar-overlay');
        const profileButton = document.querySelector('.profile-button');
        const dropdownMenu = document.querySelector('.dropdown-menu');
        const profileChevron = document.querySelector('.profile-chevron');
        const manageDropdownToggle = document.querySelector('.nav-dropdown-toggle');
        const manageDropdownMenu = document.querySelector('.nav-dropdown-menu');

        // Mobile sidebar toggle
        function toggleSidebar() {
            sidebar.classList.toggle('show');
            sidebarOverlay.classList.toggle('show');
            document.body.style.overflow = sidebar.classList.contains('show') ? 'hidden' : '';
        }

        function closeSidebar() {
            sidebar.classList.remove('show');
            sidebarOverlay.classList.remove('show');
            document.body.style.overflow = '';
        }

        // Event listeners
        mobileToggle.addEventListener('click', toggleSidebar);
        sidebarOverlay.addEventListener('click', closeSidebar);

        // Close sidebar on window resize (if desktop)
        window.addEventListener('resize', () => {
            if (window.innerWidth >= 768) {
                closeSidebar();
            }
        });

        // Profile dropdown functionality
        profileButton.addEventListener('click', (e) => {
            e.stopPropagation();
            const isOpen = dropdownMenu.classList.contains('show');

            if (isOpen) {
                dropdownMenu.classList.remove('show');
                profileChevron.style.transform = 'rotate(0deg)';
                profileButton.setAttribute('aria-expanded', 'false');
            } else {
                dropdownMenu.classList.add('show');
                profileChevron.style.transform = 'rotate(180deg)';
                profileButton.setAttribute('aria-expanded', 'true');
            }
        });

        // Close dropdown on outside click
        document.addEventListener('click', (e) => {
            if (!profileButton.contains(e.target) && !dropdownMenu.contains(e.target)) {
                dropdownMenu.classList.remove('show');
                profileChevron.style.transform = 'rotate(0deg)';
                profileButton.setAttribute('aria-expanded', 'false');
            }
        });

        // Close dropdown on escape key
        document.addEventListener('keydown', (e) => {
            if (e.key === 'Escape') {
                dropdownMenu.classList.remove('show');
                profileChevron.style.transform = ('rotate(0deg)');
                profileButton.setAttribute('aria-expanded', 'false');
                closeSidebar();
            }
        });

        // Touch support for mobile devices
        let touchStartX = 0;
        let touchEndX = 0;

        document.addEventListener('touchstart', (e) => {
            touchStartX = e.changedTouches[0].screenX;
        });

        document.addEventListener('touchend', (e) => {
            touchEndX = e.changedTouches[0].screenX;
            handleSwipe();
        });

        function handleSwipe() {
            const swipeThreshold = 50;
            const swipeDistance = touchEndX - touchStartX;

            // Swipe right to open sidebar (from left edge)
            if (swipeDistance > swipeThreshold && touchStartX < 50 && window.innerWidth < 768) {
                if (!sidebar.classList.contains('show')) {
                    toggleSidebar();
                }
            }

            // Swipe left to close sidebar
            if (swipeDistance < -swipeThreshold && sidebar.classList.contains('show')) {
                closeSidebar();
            }
        }

        // Prevent scroll when sidebar is open on mobile
        sidebar.addEventListener('scroll', (e) => {
            e.stopPropagation();
        });

        // Initialize
        document.addEventListener('DOMContentLoaded', () => {
            // Set initial ARIA states
            profileButton.setAttribute('aria-expanded', 'false');

            // Add focus management for accessibility
            const navLinks = sidebar.querySelectorAll('.nav-item, .nav-dropdown-item');
            navLinks.forEach(link => {
                link.addEventListener('focus', () => {
                    link.scrollIntoView({
                        behavior: 'smooth',
                        block: 'nearest'
                    });
                });
            });

            // Manage dropdown toggle
            if (manageDropdownToggle && manageDropdownMenu) {
                manageDropdownToggle.addEventListener('click', (e) => {
                    e.preventDefault();
                    e.stopPropagation();
                    const isOpen = manageDropdownMenu.classList.contains('show');
                    manageDropdownMenu.classList.toggle('show');
                    manageDropdownToggle.querySelector('.chevron').style.transform = isOpen ? 'rotate(0deg)' : 'rotate(180deg)';
                });

                // Close manage dropdown on outside click
                document.addEventListener('click', (e) => {
                    if (!manageDropdownToggle.contains(e.target) && !manageDropdownMenu.contains(e.target)) {
                        manageDropdownMenu.classList.remove('show');
                        manageDropdownToggle.querySelector('.chevron').style.transform = 'rotate(0deg)';
                    }
                });

                // Close manage dropdown on escape key
                document.addEventListener('keydown', (e) => {
                    if (e.key === 'Escape' && manageDropdownMenu.classList.contains('show')) {
                        manageDropdownMenu.classList.remove('show');
                        manageDropdownToggle.querySelector('.chevron').style.transform = 'rotate(0deg)';
                    }
                });
            }
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