<?php
ob_start();
?>

<!-- Add this in the head section of your layout.php -->
<script src="https://cdn.jsdelivr.net/npm/chart.js"></script>

<style>
    .chart-container {
        background: white;
        border-radius: 0.75rem;
        border: 1px solid #e5e7eb;
        padding: 1.5rem;
        height: 100%;
    }

    .stats-card {
        background: white;
        border-radius: 0.75rem;
        border: 1px solid #e5e7eb;
        padding: 1.5rem;
        transition: all 0.3s ease;
        position: relative;
        overflow: hidden;
    }

    .stats-card:hover {
        transform: translateY(-2px);
        box-shadow: 0 10px 25px -5px rgba(0, 0, 0, 0.1), 0 4px 6px -2px rgba(0, 0, 0, 0.05);
    }

    .stats-card::before {
        content: '';
        position: absolute;
        top: 0;
        left: 0;
        width: 4px;
        height: 100%;
        background: linear-gradient(to bottom, #d97706, #f59e0b);
    }

    .user-role-badge {
        font-size: 0.7rem;
        padding: 0.25rem 0.5rem;
        border-radius: 0.375rem;
        font-weight: 500;
    }

    .activity-item {
        border-left: 3px solid #f59e0b;
        padding-left: 1rem;
        margin-bottom: 1rem;
    }

    .progress-bar {
        height: 6px;
        background: #f3f4f6;
        border-radius: 3px;
        overflow: hidden;
    }

    .progress-fill {
        height: 100%;
        background: linear-gradient(90deg, #d97706, #f59e0b);
        border-radius: 3px;
        transition: width 0.3s ease;
    }
</style>

<div class="p-4 sm:p-6 bg-gray-50 min-h-screen font-sans">
    <!-- Success/Error Messages -->
    <?php if (isset($_SESSION['success'])): ?>
        <div class="bg-amber-50 border-l-4 border-amber-500 p-4 mb-8 rounded-xl" role="alert">
            <div class="flex items-center">
                <div class="flex-shrink-0">
                    <div class="w-6 h-6 bg-amber-500 rounded-xl flex items-center justify-center">
                        <svg class="h-3 w-3 text-white" fill="currentColor" viewBox="0 0 20 20">
                            <path fill-rule="evenodd" d="M10 18a8 8 0 100-16 8 8 0 000 16zm3.707-9.293a1 1 0 00-1.414-1.414L9 10.586 7.707 9.293a1 1 0 00-1.414 1.414l2 2a1 1 0 001.414 0l4-4z" clip-rule="evenodd"></path>
                        </svg>
                    </div>
                </div>
                <div class="ml-3">
                    <p class="text-amber-800 font-medium"><?php echo htmlspecialchars($_SESSION['success']);
                                                            unset($_SESSION['success']); ?></p>
                </div>
            </div>
        </div>
    <?php endif; ?>

    <?php if (isset($_SESSION['error'])): ?>
        <div class="bg-red-50 border-l-4 border-red-500 p-4 mb-8 rounded-xl" role="alert">
            <div class="flex items-center">
                <div class="flex-shrink-0">
                    <div class="w-6 h-6 bg-red-500 rounded-xl flex items-center justify-center">
                        <svg class="h-3 w-3 text-white" fill="currentColor" viewBox="0 0 20 20">
                            <path fill-rule="evenodd" d="M10 18a8 8 0 100-16 8 8 0 000 16zM8.707 7.293a1 1 0 00-1.414 1.414L8.586 10l-1.293 1.293a1 1 0 101.414 1.414L10 11.414l1.293 1.293a1 1 0 001.414-1.414L11.414 10l1.293-1.293a1 1 0 00-1.414-1.414L10 8.586 8.707 7.293z" clip-rule="evenodd"></path>
                        </svg>
                    </div>
                </div>
                <div class="ml-3">
                    <p class="text-red-800 font-medium"><?php echo htmlspecialchars($_SESSION['error']);
                                                        unset($_SESSION['error']); ?></p>
                </div>
            </div>
        </div>
    <?php endif; ?>

    <!-- Main Header Section -->
    <div class="bg-gradient-to-r from-gray-800 to-gray-900 text-white rounded-xl p-6 sm:p-8 mb-8 shadow-lg relative overflow-hidden">
        <div class="absolute top-0 right-0 w-64 h-64 bg-yellow-500 opacity-10 rounded-full -translate-y-32 translate-x-32"></div>
        <div class="absolute bottom-0 left-0 w-32 h-32 bg-amber-500 opacity-10 rounded-full translate-y-16 -translate-x-16"></div>

        <div class="relative">
            <div class="flex flex-col md:flex-row items-start md:items-center justify-between">
                <div class="mb-4 md:mb-0">
                    <h1 class="text-2xl sm:text-3xl font-bold mb-2">Admin Dashboard</h1>
                    <p class="text-gray-300 text-sm sm:text-base">Welcome back, <?php echo htmlspecialchars($_SESSION['first_name'] . ' ' . $_SESSION['last_name']); ?></p>
                </div>
                <div class="flex items-center space-x-2 sm:space-x-4 text-xs sm:text-sm">
                    <span class="bg-gray-700 px-3 py-1 rounded-full flex items-center backdrop-blur-sm">
                        <svg class="w-4 h-4 mr-1 text-yellow-500" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M8 7V3m8 4V3m-9 8h10M5 21h14a2 2 0 002-2V7a2 2 0 00-2-2H5a2 2 0 00-2 2v12a2 2 0 002 2z" />
                        </svg>
                        <?php echo htmlspecialchars($semesterInfo ?? '2nd Semester 2024-2025'); ?>
                    </span>
                    <span class="bg-yellow-600 px-3 py-1 rounded-full flex items-center backdrop-blur-sm">
                        <svg class="w-4 h-4 mr-1 text-white" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 8v4l3 3m6-3a9 9 0 11-18 0 9 9 0 0118 0z" />
                        </svg>
                        Active Term
                    </span>
                </div>
            </div>
        </div>
    </div>

    <!-- Stats Cards Grid -->
    <div class="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6 mb-8">
        <!-- Total Users Card -->
        <div class="stats-card">
            <div class="flex items-center justify-between mb-4">
                <div class="flex items-center">
                    <div class="w-12 h-12 bg-gradient-to-br from-amber-500 to-yellow-600 rounded-xl flex items-center justify-center shadow-lg">
                        <svg class="w-6 h-6 text-white" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 4.354a4 4 0 110 5.292M15 21H3v-1a6 6 0 0112 0v1zm0 0h6v-1a6 6 0 00-9-5.197m13.5-9a2.5 2.5 0 11-5 0 2.5 2.5 0 015 0z"></path>
                        </svg>
                    </div>
                    <div class="ml-4">
                        <p class="text-2xl font-bold text-gray-900"><?php echo htmlspecialchars($userCount ?? '0'); ?></p>
                        <p class="text-sm font-medium text-gray-500">Total Users</p>
                    </div>
                </div>
            </div>
            <div class="flex items-center justify-between">
                <div class="progress-bar flex-1 mr-3">
                    <div class="progress-fill" style="width: 85%"></div>
                </div>
                <a href="/admin/users" class="text-sm font-medium text-amber-600 hover:text-amber-800 transition-colors">
                    View All →
                </a>
            </div>
        </div>

        <!-- Total Colleges Card -->
        <div class="stats-card">
            <div class="flex items-center justify-between mb-4">
                <div class="flex items-center">
                    <div class="w-12 h-12 bg-gradient-to-br from-amber-500 to-yellow-600 rounded-xl flex items-center justify-center shadow-lg">
                        <svg class="w-6 h-6 text-white" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M19 21V5a2 2 0 00-2-2H7a2 2 0 00-2 2v16m14 0h2m-2 0h-5m-9 0H3m2 0h5M9 7h1m-1 4h1m4-4h1m-1 4h1m-5 10v-5a1 1 0 011-1h2a1 1 0 011 1v5m-4 0h4"></path>
                        </svg>
                    </div>
                    <div class="ml-4">
                        <p class="text-2xl font-bold text-gray-900"><?php echo htmlspecialchars($collegeCount ?? '0'); ?></p>
                        <p class="text-sm font-medium text-gray-500">Colleges</p>
                    </div>
                </div>
            </div>
            <div class="flex items-center justify-between">
                <div class="progress-bar flex-1 mr-3">
                    <div class="progress-fill" style="width: 70%"></div>
                </div>
                <a href="/admin/colleges" class="text-sm font-medium text-amber-600 hover:text-amber-800 transition-colors">
                    Manage →
                </a>
            </div>
        </div>

        <!-- Total Departments Card -->
        <div class="stats-card">
            <div class="flex items-center justify-between mb-4">
                <div class="flex items-center">
                    <div class="w-12 h-12 bg-gradient-to-br from-amber-500 to-yellow-600 rounded-xl flex items-center justify-center shadow-lg">
                        <svg class="w-6 h-6 text-white" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M19 11H5m14 0a2 2 0 012 2v6a2 2 0 01-2 2H5a2 2 0 01-2-2v-6a2 2 0 012-2m14 0V9a2 2 0 00-2-2M5 11V9a2 2 0 012-2m0 0V5a2 2 0 012-2h6a2 2 0 012 2v2M7 7h10"></path>
                        </svg>
                    </div>
                    <div class="ml-4">
                        <p class="text-2xl font-bold text-gray-900"><?php echo htmlspecialchars($departmentCount ?? '0'); ?></p>
                        <p class="text-sm font-medium text-gray-500">Departments</p>
                    </div>
                </div>
            </div>
            <div class="flex items-center justify-between">
                <div class="progress-bar flex-1 mr-3">
                    <div class="progress-fill" style="width: 60%"></div>
                </div>
                <a href="/admin/colleges" class="text-sm font-medium text-amber-600 hover:text-amber-800 transition-colors">
                    Manage →
                </a>
            </div>
        </div>

        <!-- Total Schedules Card -->
        <div class="stats-card">
            <div class="flex items-center justify-between mb-4">
                <div class="flex items-center">
                    <div class="w-12 h-12 bg-gradient-to-br from-amber-500 to-yellow-600 rounded-xl flex items-center justify-center shadow-lg">
                        <svg class="w-6 h-6 text-white" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M8 7V3m8 4V3m-9 8h10M5 21h14a2 2 0 002-2V7a2 2 0 00-2-2H5a2 2 0 00-2 2v12a2 2 0 002 2z"></path>
                        </svg>
                    </div>
                    <div class="ml-4">
                        <p class="text-2xl font-bold text-gray-900"><?php echo htmlspecialchars($scheduleCount ?? '0'); ?></p>
                        <p class="text-sm font-medium text-gray-500">Schedules</p>
                    </div>
                </div>
            </div>
            <div class="flex items-center justify-between">
                <div class="progress-bar flex-1 mr-3">
                    <div class="progress-fill" style="width: 90%"></div>
                </div>
                <a href="/admin/schedules" class="text-sm font-medium text-amber-600 hover:text-amber-800 transition-colors">
                    View All →
                </a>
            </div>
        </div>
    </div>

    <!-- Charts and Analytics Section -->
    <div class="grid grid-cols-1 lg:grid-cols-2 gap-6 mb-8">
        <!-- User Distribution Chart -->
        <div class="chart-container">
            <div class="flex items-center justify-between mb-6">
                <h3 class="text-lg font-semibold text-gray-900">User Distribution</h3>
                <span class="text-sm text-gray-500">By Role</span>
            </div>
            <div class="h-64">
                <canvas id="userDistributionChart"></canvas>
            </div>
        </div>

        <!-- Schedule Status Chart -->
        <div class="chart-container">
            <div class="flex items-center justify-between mb-6">
                <h3 class="text-lg font-semibold text-gray-900">Schedule Status</h3>
                <span class="text-sm text-gray-500">Current Semester</span>
            </div>
            <div class="h-64">
                <canvas id="scheduleStatusChart"></canvas>
            </div>
        </div>
    </div>

    <!-- Semester Configuration and Quick Stats -->
    <div class="grid grid-cols-1 lg:grid-cols-3 gap-6 mb-8">
        <!-- Semester Configuration -->
        <div class="lg:col-span-2 bg-white rounded-xl border border-gray-200 p-6">
            <div class="flex items-center mb-6">
                <div class="w-10 h-10 bg-gradient-to-br from-amber-500 to-yellow-600 rounded-xl flex items-center justify-center mr-4 shadow-lg">
                    <svg class="w-5 h-5 text-white" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                        <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M10.325 4.317c.426-1.756 2.924-1.756 3.35 0a1.724 1.724 0 002.573 1.066c1.543-.94 3.31.826 2.37 2.37a1.724 1.724 0 001.065 2.572c1.756.426 1.756 2.924 0 3.35a1.724 1.724 0 00-1.066 2.573c.94 1.543-.826 3.31-2.37 2.37a1.724 1.724 0 00-2.572 1.065c-.426 1.756-2.924 1.756-3.35 0a1.724 1.724 0 00-2.573-1.066c-1.543.94-3.31-.826-2.37-2.37a1.724 1.724 0 00-1.065-2.572c-1.756-.426-1.756-2.924 0-3.35a1.724 1.724 0 001.066-2.573c-.94-1.543.826-3.31 2.37-2.37.996.608 2.296.07 2.572-1.065z" />
                    </svg>
                </div>
                <div>
                    <h2 class="text-xl font-bold text-gray-900">Semester Configuration</h2>
                    <p class="text-gray-600 text-sm mt-1">Set the current active academic semester</p>
                </div>
            </div>

            <form method="POST" class="grid grid-cols-1 md:grid-cols-3 gap-4">
                <div>
                    <label for="semester_name" class="block text-sm font-medium text-gray-700 mb-2">Semester</label>
                    <select id="semester_name" name="semester_name" class="w-full px-3 py-2 border border-gray-300 rounded-xl focus:outline-none focus:ring-2 focus:ring-amber-500 focus:border-amber-500 transition-colors">
                        <option value="1st" <?php echo $currentSemester && $currentSemester['semester_name'] === '1st' ? 'selected' : ''; ?>>1st Semester</option>
                        <option value="2nd" <?php echo $currentSemester && $currentSemester['semester_name'] === '2nd' ? 'selected' : ''; ?>>2nd Semester</option>
                        <option value="Summer" <?php echo $currentSemester && $currentSemester['semester_name'] === 'Summer' ? 'selected' : ''; ?>>Mid Year</option>
                    </select>
                </div>

                <div>
                    <label for="academic_year" class="block text-sm font-medium text-gray-700 mb-2">Academic Year</label>
                    <input type="text" id="academic_year" name="academic_year"
                        value="<?php echo htmlspecialchars($currentSemester['academic_year'] ?? '', ENT_QUOTES, 'UTF-8'); ?>"
                        class="w-full px-3 py-2 border border-gray-300 rounded-xl focus:outline-none focus:ring-2 focus:ring-amber-500 focus:border-amber-500 transition-colors"
                        placeholder="e.g., 2024-2025">
                </div>

                <div class="flex items-end">
                    <button type="submit" name="set_semester"
                        class="w-full bg-gradient-to-r from-amber-500 to-yellow-600 text-white px-4 py-2 rounded-xl hover:from-amber-600 hover:to-yellow-700 font-medium transition-all duration-200 shadow-lg hover:shadow-xl">
                        Update Semester
                    </button>
                </div>
            </form>
        </div>

        <!-- Quick Stats -->
        <div class="bg-white rounded-xl border border-gray-200 p-6">
            <div class="flex items-center mb-6">
                <div class="w-10 h-10 bg-gradient-to-br from-amber-500 to-yellow-600 rounded-xl flex items-center justify-center mr-4 shadow-lg">
                    <svg class="w-5 h-5 text-white" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                        <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 19v-6a2 2 0 00-2-2H5a2 2 0 00-2 2v6a2 2 0 002 2h2a2 2 0 002-2zm0 0V9a2 2 0 012-2h2a2 2 0 012 2v10m-6 0a2 2 0 002 2h2a2 2 0 002-2m0 0V5a2 2 0 012-2h2a2 2 0 012 2v14a2 2 0 01-2 2h-2a2 2 0 01-2-2z" />
                    </svg>
                </div>
                <div>
                    <h2 class="text-xl font-bold text-gray-900">Quick Stats</h2>
                    <p class="text-gray-600 text-sm mt-1">System Overview</p>
                </div>
            </div>

            <div class="space-y-4">
                <div class="flex justify-between items-center">
                    <span class="text-sm text-gray-600">Active Users</span>
                    <span class="text-sm font-semibold text-gray-900"><?php echo htmlspecialchars($userCount ?? '0'); ?></span>
                </div>
                <div class="flex justify-between items-center">
                    <span class="text-sm text-gray-600">Colleges</span>
                    <span class="text-sm font-semibold text-gray-900"><?php echo htmlspecialchars($collegeCount ?? '0'); ?></span>
                </div>
                <div class="flex justify-between items-center">
                    <span class="text-sm text-gray-600">Departments</span>
                    <span class="text-sm font-semibold text-gray-900"><?php echo htmlspecialchars($departmentCount ?? '0'); ?></span>
                </div>
                <div class="flex justify-between items-center">
                    <span class="text-sm text-gray-600">Active Schedules</span>
                    <span class="text-sm font-semibold text-gray-900"><?php echo htmlspecialchars($scheduleCount ?? '0'); ?></span>
                </div>
            </div>
        </div>
    </div>

    <!-- Recent Activity and System Status -->
    <div class="grid grid-cols-1 lg:grid-cols-2 gap-6">
        <!-- Recent Activity -->
        <div class="bg-white rounded-xl border border-gray-200">
            <div class="px-6 py-4 border-b border-gray-200">
                <div class="flex items-center justify-between">
                    <div class="flex items-center">
                        <div class="w-8 h-8 bg-gradient-to-br from-amber-500 to-yellow-600 rounded-lg flex items-center justify-center mr-3 shadow-lg">
                            <svg class="w-4 h-4 text-white" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 5H7a2 2 0 00-2 2v10a2 2 0 002 2h8a2 2 0 002-2V7a2 2 0 00-2-2h-2M9 5a2 2 0 002 2h2a2 2 0 002-2M9 5a2 2 0 012-2h2a2 2 0 012 2"></path>
                            </svg>
                        </div>
                        <h2 class="text-lg font-semibold text-gray-900">Recent Activity</h2>
                    </div>
                    <span class="text-sm text-gray-500">Last 24 hours</span>
                </div>
            </div>

            <div class="p-6 max-h-96 overflow-y-auto">
                <?php
                try {
                    $stmt = $controller->db->prepare("
                        SELECT al.log_id, al.action_type, al.action_description, al.entity_type, al.entity_id, 
                               al.created_at, u.first_name, u.last_name, u.role_id
                        FROM activity_logs al
                        JOIN users u ON al.user_id = u.user_id
                        ORDER BY al.created_at DESC
                        LIMIT 6
                    ");
                    $stmt->execute();
                    $logs = $stmt->fetchAll(PDO::FETCH_ASSOC);

                    if (empty($logs)) {
                        echo '<div class="text-center py-8">
                            <svg class="w-12 h-12 text-gray-300 mx-auto mb-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 5H7a2 2 0 00-2 2v10a2 2 0 002 2h8a2 2 0 002-2V7a2 2 0 00-2-2h-2M9 5a2 2 0 002 2h2a2 2 0 002-2M9 5a2 2 0 012-2h2a2 2 0 012 2"></path>
                            </svg>
                            <p class="text-gray-500 font-medium">No recent activity</p>
                            <p class="text-gray-400 text-sm mt-1">Activity will appear here as users interact with the system</p>
                        </div>';
                    } else {
                        foreach ($logs as $log) {
                            echo '<div class="activity-item">
                                <div class="flex justify-between items-start mb-1">
                                    <div class="flex items-center">
                                        <div class="user-avatar mr-3">
                                            ' . strtoupper(substr($log['first_name'], 0, 1)) . strtoupper(substr($log['last_name'], 0, 1)) . '
                                        </div>
                                        <div>
                                            <p class="text-sm font-medium text-gray-900">' . htmlspecialchars($log['first_name'] . ' ' . $log['last_name']) . '</p>
                                            <p class="text-xs text-gray-500">' . htmlspecialchars($log['action_type']) . '</p>
                                        </div>
                                    </div>
                                    <span class="text-xs text-gray-400">' . date('H:i', strtotime($log['created_at'])) . '</span>
                                </div>
                                <p class="text-sm text-gray-600 truncate">' . htmlspecialchars($log['action_description']) . '</p>
                            </div>';
                        }
                    }
                } catch (PDOException $e) {
                    error_log("Activity logs error: " . $e->getMessage());
                    echo '<div class="text-center py-8">
                        <svg class="w-12 h-12 text-red-300 mx-auto mb-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-2.5L13.732 4c-.77-.833-1.964-.833-2.732 0L3.732 16.5c-.77.833.192 2.5 1.732 2.5z"></path>
                        </svg>
                        <p class="text-red-600 font-medium">Error loading activity</p>
                    </div>';
                }
                ?>
            </div>

            <div class="px-6 py-4 border-t border-gray-200 bg-gray-50">
                <a href="/admin/act_logs" class="inline-flex items-center justify-center w-full px-4 py-2 bg-gradient-to-r from-amber-500 to-yellow-600 hover:from-amber-600 hover:to-yellow-700 text-white text-sm font-medium rounded-lg transition-all duration-200 shadow-lg hover:shadow-xl">
                    View All Activity
                    <svg class="ml-2 w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                        <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M13 7l5 5m0 0l-5 5m5-5H6"></path>
                    </svg>
                </a>
            </div>
        </div>

        <!-- System Status -->
        <div class="bg-white rounded-xl border border-gray-200">
            <div class="px-6 py-4 border-b border-gray-200">
                <div class="flex items-center">
                    <div class="w-8 h-8 bg-gradient-to-br from-amber-500 to-yellow-600 rounded-lg flex items-center justify-center mr-3 shadow-lg">
                        <svg class="w-4 h-4 text-white" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M13 10V3L4 14h7v7l9-11h-7z" />
                        </svg>
                    </div>
                    <h2 class="text-lg font-semibold text-gray-900">System Status</h2>
                </div>
            </div>

            <div class="p-6">
                <div class="space-y-4">
                    <div class="flex items-center justify-between">
                        <span class="text-sm text-gray-600">Database</span>
                        <span class="inline-flex items-center px-2 py-1 rounded-full text-xs font-medium bg-green-100 text-green-800">
                            <svg class="w-3 h-3 mr-1" fill="currentColor" viewBox="0 0 20 20">
                                <path fill-rule="evenodd" d="M10 18a8 8 0 100-16 8 8 0 000 16zm3.707-9.293a1 1 0 00-1.414-1.414L9 10.586 7.707 9.293a1 1 0 00-1.414 1.414l2 2a1 1 0 001.414 0l4-4z" clip-rule="evenodd" />
                            </svg>
                            Online
                        </span>
                    </div>
                    <div class="flex items-center justify-between">
                        <span class="text-sm text-gray-600">API Services</span>
                        <span class="inline-flex items-center px-2 py-1 rounded-full text-xs font-medium bg-green-100 text-green-800">
                            <svg class="w-3 h-3 mr-1" fill="currentColor" viewBox="0 0 20 20">
                                <path fill-rule="evenodd" d="M10 18a8 8 0 100-16 8 8 0 000 16zm3.707-9.293a1 1 0 00-1.414-1.414L9 10.586 7.707 9.293a1 1 0 00-1.414 1.414l2 2a1 1 0 001.414 0l4-4z" clip-rule="evenodd" />
                            </svg>
                            Operational
                        </span>
                    </div>
                    <div class="flex items-center justify-between">
                        <span class="text-sm text-gray-600">Scheduling Engine</span>
                        <span class="inline-flex items-center px-2 py-1 rounded-full text-xs font-medium bg-green-100 text-green-800">
                            <svg class="w-3 h-3 mr-1" fill="currentColor" viewBox="0 0 20 20">
                                <path fill-rule="evenodd" d="M10 18a8 8 0 100-16 8 8 0 000 16zm3.707-9.293a1 1 0 00-1.414-1.414L9 10.586 7.707 9.293a1 1 0 00-1.414 1.414l2 2a1 1 0 001.414 0l4-4z" clip-rule="evenodd" />
                            </svg>
                            Running
                        </span>
                    </div>
                    <div class="flex items-center justify-between">
                        <span class="text-sm text-gray-600">User Authentication</span>
                        <span class="inline-flex items-center px-2 py-1 rounded-full text-xs font-medium bg-green-100 text-green-800">
                            <svg class="w-3 h-3 mr-1" fill="currentColor" viewBox="0 0 20 20">
                                <path fill-rule="evenodd" d="M10 18a8 8 0 100-16 8 8 0 000 16zm3.707-9.293a1 1 0 00-1.414-1.414L9 10.586 7.707 9.293a1 1 0 00-1.414 1.414l2 2a1 1 0 001.414 0l4-4z" clip-rule="evenodd" />
                            </svg>
                            Secure
                        </span>
                    </div>
                </div>

                <div class="mt-6 p-4 bg-amber-50 rounded-lg border border-amber-200">
                    <div class="flex items-center">
                        <svg class="w-5 h-5 text-amber-600 mr-2" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M13 16h-1v-4h-1m1-4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z" />
                        </svg>
                        <p class="text-sm text-amber-800">
                            All systems are running smoothly. Last updated: <?php echo date('M j, Y g:i A'); ?>
                        </p>
                    </div>
                </div>
            </div>
        </div>
    </div>
</div>

<script>
    document.addEventListener('DOMContentLoaded', function() {
        // User Distribution Chart (Doughnut)
        const userDistributionCtx = document.getElementById('userDistributionChart').getContext('2d');

        // Prepare user distribution data from PHP
        const roleData = <?php echo json_encode($roleDistribution); ?>;
        const roleLabels = roleData.map(item => item.role_name);
        const roleCounts = roleData.map(item => parseInt(item.count));

        const userDistributionChart = new Chart(userDistributionCtx, {
            type: 'doughnut',
            data: {
                labels: roleLabels,
                datasets: [{
                    data: roleCounts,
                    backgroundColor: [
                        '#f59e0b', '#d97706', '#fbbf24', '#f97316',
                        '#ea580c', '#dc2626', '#b91c1c'
                    ],
                    borderWidth: 2,
                    borderColor: '#ffffff'
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                plugins: {
                    legend: {
                        position: 'right',
                        labels: {
                            boxWidth: 12,
                            padding: 15,
                            font: {
                                size: 11
                            }
                        }
                    },
                    tooltip: {
                        callbacks: {
                            label: function(context) {
                                const label = context.label || '';
                                const value = context.raw || 0;
                                const total = context.dataset.data.reduce((a, b) => a + b, 0);
                                const percentage = Math.round((value / total) * 100);
                                return `${label}: ${value} (${percentage}%)`;
                            }
                        }
                    }
                },
                cutout: '65%'
            }
        });

        // Schedule Status Chart (Bar)
        const scheduleStatusCtx = document.getElementById('scheduleStatusChart').getContext('2d');

        // Prepare schedule status data (you'll need to modify this based on your actual data structure)
        const scheduleData = <?php echo json_encode($scheduleDistribution ?? []); ?>;

        // Default data if no schedule distribution is available
        const scheduleLabels = scheduleData.length > 0 ?
            scheduleData.map(item => item.status) : ['Pending', 'Approved', 'Completed', 'Cancelled'];

        const scheduleCounts = scheduleData.length > 0 ?
            scheduleData.map(item => parseInt(item.count)) : [5, 12, 8, 2];

        const scheduleStatusChart = new Chart(scheduleStatusCtx, {
            type: 'bar',
            data: {
                labels: scheduleLabels,
                datasets: [{
                    label: 'Schedules',
                    data: scheduleCounts,
                    backgroundColor: [
                        'rgba(245, 158, 11, 0.8)',
                        'rgba(34, 197, 94, 0.8)',
                        'rgba(59, 130, 246, 0.8)',
                        'rgba(239, 68, 68, 0.8)'
                    ],
                    borderColor: [
                        'rgb(245, 158, 11)',
                        'rgb(34, 197, 94)',
                        'rgb(59, 130, 246)',
                        'rgb(239, 68, 68)'
                    ],
                    borderWidth: 1,
                    borderRadius: 6,
                    borderSkipped: false,
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                plugins: {
                    legend: {
                        display: false
                    }
                },
                scales: {
                    y: {
                        beginAtZero: true,
                        grid: {
                            color: 'rgba(0, 0, 0, 0.1)'
                        },
                        ticks: {
                            stepSize: 1
                        }
                    },
                    x: {
                        grid: {
                            display: false
                        }
                    }
                }
            }
        });

        // College Department Distribution (Optional - if you want more charts)
        const collegeDeptData = <?php echo json_encode($departmentsByCollege ?? []); ?>;
        if (collegeDeptData && Object.keys(collegeDeptData).length > 0) {
            // You can add more charts here if needed
        }

        // Handle window resize for charts
        window.addEventListener('resize', function() {
            userDistributionChart.resize();
            scheduleStatusChart.resize();
        });
    });
</script>

<?php
$content = ob_get_clean();
require_once __DIR__ . '/layout.php';
?>