<?php
ob_start();
?>

<!DOCTYPE html>
<html lang="en">

<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title><?php echo htmlspecialchars($data['title']); ?></title>
    <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
    <style>
        @keyframes fadeIn {
            from {
                opacity: 0;
                transform: translateY(10px);
            }

            to {
                opacity: 1;
                transform: translateY(0);
            }
        }

        @keyframes slideUp {
            from {
                opacity: 0;
                transform: translateY(20px);
            }

            to {
                opacity: 1;
                transform: translateY(0);
            }
        }

        .activity-item {
            transition: all 0.2s ease;
        }

        .activity-item:hover {
            transform: translateX(4px);
        }

        .glass-effect {
            backdrop-filter: blur(10px);
            background: rgba(255, 255, 255, 0.9);
        }

        /* Print Styles */
        @media print {
            .no-print {
                display: none !important;
            }

            .print-full-width {
                width: 100% !important;
            }

            body {
                background: white !important;
            }

            .bg-white {
                background: white !important;
            }

            .shadow-sm,
            .shadow-lg {
                box-shadow: none !important;
            }

            .border {
                border: 1px solid #ddd !important;
            }
        }

        @media print {
            .no-print {
                display: none !important;
            }

            body {
                background: white !important;
                font-size: 12pt;
                line-height: 1.4;
            }

            .print-container {
                width: 100% !important;
                margin: 0 !important;
                padding: 0 !important;
            }

            .letter-header {
                text-align: center;
                border-bottom: 2px solid #000;
                padding-bottom: 20px;
                margin-bottom: 20px;
            }

            .university-logo {
                max-width: 150px;
                height: auto;
                margin-bottom: 10px;
            }

            .report-title {
                font-size: 18pt;
                font-weight: bold;
                margin: 10px 0;
            }

            .report-subtitle {
                font-size: 14pt;
                margin-bottom: 15px;
            }

            .activity-table {
                width: 100%;
                border-collapse: collapse;
                margin: 20px 0;
            }

            .activity-table th,
            .activity-table td {
                border: 1px solid #ddd;
                padding: 8px;
                text-align: left;
                font-size: 10pt;
            }

            .activity-table th {
                background-color: #f5f5f5;
                font-weight: bold;
            }

            .report-footer {
                margin-top: 30px;
                padding-top: 20px;
                border-top: 1px solid #ddd;
                text-align: center;
                font-size: 10pt;
            }

            /* Hide unnecessary elements */
            .bg-gradient-to-br,
            .shadow-sm,
            .shadow-lg,
            .rounded-xl,
            .hover\\:bg-gray-50,
            .focus\\:ring-2,
            .grid,
            .gap-8 {
                all: unset !important;
            }
        }
    </style>
</head>

<body class="bg-gradient-to-br from-gray-50 to-gray-100 min-h-screen">
    <div class="max-w-7xl mx-auto px-4 sm:p-6 lg:p-8 py-8">
        <!-- Report Header and Controls -->
        <div class="mb-8 bg-white rounded-xl shadow-sm border border-gray-200 p-6">
            <div class="flex flex-col lg:flex-row lg:items-center lg:justify-between gap-4">
                <div>
                    <h1 class="text-2xl font-bold text-gray-900"><?php echo htmlspecialchars($data['title']); ?></h1>
                    <p class="text-gray-600 mt-1">Activity monitoring and reporting system</p>
                </div>

                <div class="flex flex-wrap gap-3 no-print">
                    <!-- Print Button -->
                    <button onclick="printReport()" class="inline-flex items-center px-4 py-2 border border-gray-300 rounded-lg text-sm font-medium text-gray-700 bg-white hover:bg-gray-50 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-gold-primary">
                        <i class="fas fa-print mr-2"></i>
                        Print Report
                    </button>

                    <!-- Export Button -->
                    <button onclick="generatePDF()" class="inline-flex items-center px-4 py-2 border border-gray-300 rounded-lg text-sm font-medium text-gray-700 bg-white hover:bg-gray-50 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-gold-primary">
                        <i class="fas fa-file-pdf mr-2"></i>
                        Export PDF
                    </button>


                    <!-- Filter Toggle -->
                    <button onclick="toggleFilters()" class="inline-flex items-center px-4 py-2 border border-gray-300 rounded-lg text-sm font-medium text-gray-700 bg-white hover:bg-gray-50 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-gold-primary">
                        <i class="fas fa-filter mr-2"></i>
                        Filters
                    </button>
                </div>
            </div>
        </div>

        <!-- Filters Section -->
        <div id="filtersSection" class="mb-8 bg-white rounded-xl shadow-sm border border-gray-200 p-6 no-print" style="display: none;">
            <div class="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
                <!-- Date Range -->
                <div>
                    <label class="block text-sm font-medium text-gray-700 mb-2">Date Range</label>
                    <select id="dateFilter" class="w-full px-3 py-2 border border-gray-300 rounded-lg focus:outline-none focus:ring-2 focus:ring-gold-primary">
                        <option value="today">Today</option>
                        <option value="yesterday">Yesterday</option>
                        <option value="week">This Week</option>
                        <option value="month">This Month</option>
                        <option value="custom">Custom Range</option>
                    </select>
                </div>

                <!-- Custom Date Range (shown when custom is selected) -->
                <div id="customDateRange" style="display: none;">
                    <label class="block text-sm font-medium text-gray-700 mb-2">Custom Range</label>
                    <div class="flex gap-2">
                        <input type="date" id="startDate" class="flex-1 px-3 py-2 border border-gray-300 rounded-lg focus:outline-none focus:ring-2 focus:ring-gold-primary">
                        <input type="date" id="endDate" class="flex-1 px-3 py-2 border border-gray-300 rounded-lg focus:outline-none focus:ring-2 focus:ring-gold-primary">
                    </div>
                </div>

                <!-- Time Filter -->
                <div>
                    <label class="block text-sm font-medium text-gray-700 mb-2">Time of Day</label>
                    <select id="timeFilter" class="w-full px-3 py-2 border border-gray-300 rounded-lg focus:outline-none focus:ring-2 focus:ring-gold-primary">
                        <option value="all">All Hours</option>
                        <option value="morning">Morning (6AM-12PM)</option>
                        <option value="afternoon">Afternoon (12PM-6PM)</option>
                        <option value="evening">Evening (6PM-12AM)</option>
                        <option value="night">Night (12AM-6AM)</option>
                    </select>
                </div>

                <!-- College Filter -->
                <div>
                    <label class="block text-sm font-medium text-gray-700 mb-2">College</label>
                    <select id="collegeFilter" class="w-full px-3 py-2 border border-gray-300 rounded-lg focus:outline-none focus:ring-2 focus:ring-gold-primary">
                        <option value="all">All Colleges</option>
                        <?php
                        $colleges = array_unique(array_column($data['activities'], 'college_name'));
                        foreach ($colleges as $college):
                            if (!empty($college)):
                        ?>
                                <option value="<?php echo htmlspecialchars($college); ?>"><?php echo htmlspecialchars($college); ?></option>
                        <?php
                            endif;
                        endforeach;
                        ?>
                    </select>
                </div>

                <!-- Department Filter -->
                <div>
                    <label class="block text-sm font-medium text-gray-700 mb-2">Department</label>
                    <select id="departmentFilter" class="w-full px-3 py-2 border border-gray-300 rounded-lg focus:outline-none focus:ring-2 focus:ring-gold-primary">
                        <option value="all">All Departments</option>
                        <?php
                        $departments = array_unique(array_column($data['activities'], 'department_name'));
                        foreach ($departments as $department):
                            if (!empty($department)):
                        ?>
                                <option value="<?php echo htmlspecialchars($department); ?>"><?php echo htmlspecialchars($department); ?></option>
                        <?php
                            endif;
                        endforeach;
                        ?>
                    </select>
                </div>

                <!-- Action Type Filter -->
                <div>
                    <label class="block text-sm font-medium text-gray-700 mb-2">Action Type</label>
                    <select id="actionTypeFilter" class="w-full px-3 py-2 border border-gray-300 rounded-lg focus:outline-none focus:ring-2 focus:ring-gold-primary">
                        <option value="all">All Types</option>
                        <option value="login">Login</option>
                        <option value="logout">Logout</option>
                        <option value="schedule">Schedule</option>
                        <option value="update">Update</option>
                        <option value="create">Create</option>
                        <option value="delete">Delete</option>
                        <option value="system">System</option>
                    </select>
                </div>
            </div>

            <!-- Filter Actions -->
            <div class="flex justify-end gap-3 mt-6 pt-6 border-t border-gray-200">
                <button onclick="resetFilters()" class="px-4 py-2 border border-gray-300 rounded-lg text-sm font-medium text-gray-700 bg-white hover:bg-gray-50 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-gray-500">
                    Reset Filters
                </button>
                <button onclick="applyFilters()" class="px-4 py-2 border border-transparent rounded-lg text-sm font-medium text-white bg-yellow-600 hover:bg-yellow-700 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-yellow-600">
                    Apply Filters
                </button>
            </div>
        </div>

        <!-- Report Summary -->
        <div class="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6 mb-8">
            <!-- Current Semester -->
            <div class="bg-white rounded-xl shadow-sm border border-gray-200 p-6">
                <div class="flex items-center justify-between">
                    <div>
                        <p class="text-sm font-medium text-gray-500 mb-1">Current Semester</p>
                        <p class="text-xl font-bold text-gray-900"><?php echo htmlspecialchars($data['current_semester_display']); ?></p>
                    </div>
                    <div class="w-12 h-12 bg-gradient-to-r from-yellow-500 to-yellow-600 rounded-lg flex items-center justify-center">
                        <i class="fas fa-calendar-alt text-white"></i>
                    </div>
                </div>
            </div>

            <!-- Total Activities -->
            <div class="bg-white rounded-xl shadow-sm border border-gray-200 p-6">
                <div class="flex items-center justify-between">
                    <div>
                        <p class="text-sm font-medium text-gray-500 mb-1">Total Activities</p>
                        <p class="text-2xl font-bold text-gray-900" id="totalActivities">
                            <?php echo count($data['activities']); ?>
                        </p>
                    </div>
                    <div class="w-12 h-12 bg-gradient-to-r from-blue-500 to-blue-600 rounded-lg flex items-center justify-center">
                        <i class="fas fa-chart-bar text-white"></i>
                    </div>
                </div>
            </div>

            <!-- Filtered Count -->
            <div class="bg-white rounded-xl shadow-sm border border-gray-200 p-6">
                <div class="flex items-center justify-between">
                    <div>
                        <p class="text-sm font-medium text-gray-500 mb-1">Filtered Results</p>
                        <p class="text-2xl font-bold text-gray-900" id="filteredCount">
                            <?php echo count($data['activities']); ?>
                        </p>
                    </div>
                    <div class="w-12 h-12 bg-gradient-to-r from-green-500 to-green-600 rounded-lg flex items-center justify-center">
                        <i class="fas fa-filter text-white"></i>
                    </div>
                </div>
            </div>

            <!-- Active Users -->
            <div class="bg-white rounded-xl shadow-sm border border-gray-200 p-6">
                <div class="flex items-center justify-between">
                    <div>
                        <p class="text-sm font-medium text-gray-500 mb-1">Active Users</p>
                        <p class="text-2xl font-bold text-gray-900" id="activeUsers">
                            <?php
                            $uniqueUsers = array_unique(array_map(function ($activity) {
                                return $activity['first_name'] . ' ' . $activity['last_name'];
                            }, $data['activities']));
                            echo count($uniqueUsers);
                            ?>
                        </p>
                    </div>
                    <div class="w-12 h-12 bg-gradient-to-r from-purple-500 to-purple-600 rounded-lg flex items-center justify-center">
                        <i class="fas fa-users text-white"></i>
                    </div>
                </div>
            </div>
        </div>

        <!-- Print Template (Hidden by default) -->
        <div id="printTemplate" class="hidden">
            <div class="print-container">
                <!-- University Header -->
                <div class="letter-header">
                    <img src="/assets/logo/main_logo/PRMSUlogo.png" alt="University Logo" class="university-logo">
                    <h1 class="report-title">UNIVERSITY ACTIVITY REPORT</h1>
                    <div class="report-subtitle">
                        Activity Logs - <?php echo date('F j, Y'); ?>
                    </div>
                    <div class="report-meta">
                        Generated on: <?php echo date('F j, Y g:i A'); ?><br>
                        Semester: <?php echo htmlspecialchars($data['current_semester_display']); ?>
                    </div>
                </div>

                <!-- Summary Statistics -->
                <div class="summary-stats">
                    <table style="width: 100%; margin-bottom: 20px;">
                        <tr>
                            <td style="width: 25%; text-align: center; border: 1px solid #ddd; padding: 10px;">
                                <strong>Total Activities</strong><br>
                                <span id="printTotalActivities"><?php echo count($data['activities']); ?></span>
                            </td>
                            <td style="width: 25%; text-align: center; border: 1px solid #ddd; padding: 10px;">
                                <strong>Active Users</strong><br>
                                <span id="printActiveUsers">
                                    <?php
                                    $uniqueUsers = array_unique(array_map(function ($activity) {
                                        return $activity['first_name'] . ' ' . $activity['last_name'];
                                    }, $data['activities']));
                                    echo count($uniqueUsers);
                                    ?>
                                </span>
                            </td>
                            <td style="width: 25%; text-align: center; border: 1px solid #ddd; padding: 10px;">
                                <strong>Date Range</strong><br>
                                <span id="printDateRange">All Time</span>
                            </td>
                            <td style="width: 25%; text-align: center; border: 1px solid #ddd; padding: 10px;">
                                <strong>Generated By</strong><br>
                                System Administrator
                            </td>
                        </tr>
                    </table>
                </div>

                <!-- Activities Table -->
                <table class="activity-table">
                    <thead>
                        <tr>
                            <th>Date & Time</th>
                            <th>User</th>
                            <th>Department</th>
                            <th>College</th>
                            <th>Action Type</th>
                            <th>Description</th>
                        </tr>
                    </thead>
                    <tbody id="printActivityBody">
                        <?php foreach ($data['activities'] as $activity): ?>
                            <tr>
                                <td><?php echo date('M j, Y g:i A', strtotime($activity['created_at'])); ?></td>
                                <td><?php echo htmlspecialchars($activity['first_name'] . ' ' . $activity['last_name']); ?></td>
                                <td><?php echo htmlspecialchars($activity['department_name']); ?></td>
                                <td><?php echo htmlspecialchars($activity['college_name']); ?></td>
                                <td><?php echo htmlspecialchars(ucfirst($activity['action_type'])); ?></td>
                                <td><?php echo htmlspecialchars($activity['action_description']); ?></td>
                            </tr>
                        <?php endforeach; ?>
                    </tbody>
                </table>

                <!-- Footer -->
                <div class="report-footer">
                    <p>Confidential Activity Report - <?php echo htmlspecialchars($data['current_semester_display']); ?></p>
                    <p>Page 1 of 1 | Generated by University Activity Monitoring System</p>
                </div>
            </div>
        </div>

        <!-- Main Content -->
        <div class="grid grid-cols-1 lg:grid-cols-3 gap-8">
            <!-- Activity Feed -->
            <div class="lg:col-span-2">
                <div class="bg-white rounded-xl shadow-sm border border-gray-200 print-full-width">
                    <div class="p-6 border-b border-gray-200">
                        <div class="flex items-center justify-between">
                            <div class="flex items-center space-x-3">
                                <div class="w-8 h-8 bg-gradient-to-r from-gold-primary to-gold-dark rounded-lg flex items-center justify-center">
                                    <i class="fas fa-stream text-white text-sm"></i>
                                </div>
                                <h3 class="text-lg font-semibold text-gray-900">Activity Log</h3>
                                <span id="resultsCount" class="text-sm text-gray-500">
                                    (Showing <?php echo count($data['activities']); ?> activities)
                                </span>
                            </div>
                            <div class="flex items-center space-x-2 no-print">
                                <button id="refreshBtn" class="inline-flex items-center px-3 py-1.5 border border-gray-300 rounded-lg text-xs font-medium text-gray-700 bg-white hover:bg-gray-50 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-gold-primary">
                                    <i class="fas fa-sync-alt mr-1.5"></i>
                                    Refresh
                                </button>
                            </div>
                        </div>
                    </div>

                    <div class="p-6">
                        <div class="space-y-4" id="activityFeed">
                            <?php if (empty($data['activities'])): ?>
                                <div class="text-center py-12">
                                    <div class="w-16 h-16 bg-gray-100 rounded-full flex items-center justify-center mx-auto mb-4">
                                        <i class="fas fa-chart-line text-2xl text-gray-400"></i>
                                    </div>
                                    <h3 class="text-lg font-medium text-gray-900 mb-2">No Activities Found</h3>
                                    <p class="text-gray-500">No activity data matches your current filters</p>
                                </div>
                            <?php else: ?>
                                <?php foreach (array_slice($data['activities'], 0, 10) as $activity): ?>
                                    <div class="activity-item flex items-start space-x-3 p-4 rounded-lg border border-gray-100 hover:border-gold-primary hover:bg-gold-primary hover:bg-opacity-5">
                                        <div class="flex-shrink-0">
                                            <div class="w-8 h-8 rounded-full flex items-center justify-center <?php echo getActivityIcon($activity['action_type'])['bg']; ?>">
                                                <i class="<?php echo getActivityIcon($activity['action_type'])['icon']; ?> text-white text-sm"></i>
                                            </div>
                                        </div>
                                        <div class="flex-1 min-w-0">
                                            <div class="flex items-center justify-between">
                                                <p class="text-sm font-medium text-gray-900">
                                                    <?php echo htmlspecialchars($activity['first_name'] . ' ' . $activity['last_name']); ?>
                                                </p>
                                                <p class="text-xs text-gray-500">
                                                    <?php echo date('M j, Y g:i A', strtotime($activity['created_at'])); ?>
                                                </p>
                                            </div>
                                            <p class="text-sm text-gray-600 mt-1">
                                                <?php echo htmlspecialchars($activity['action_description']); ?>
                                                <span class="text-gray-400">(<?php echo htmlspecialchars($activity['department_name']); ?>, <?php echo htmlspecialchars($activity['college_name']); ?>)</span>
                                            </p>
                                            <div class="mt-2 flex items-center gap-2">
                                                <span class="inline-flex items-center px-2 py-1 rounded-full text-xs font-medium <?php echo getActivityType($activity['action_type'])['class']; ?>">
                                                    <?php echo getActivityType($activity['action_type'])['label']; ?>
                                                </span>
                                                <span class="text-xs text-gray-500">
                                                    <?php echo timeAgo($activity['created_at']); ?>
                                                </span>
                                            </div>
                                        </div>
                                    </div>
                                <?php endforeach; ?>
                            <?php endif; ?>
                        </div>

                        <?php if (count($data['activities']) > 10): ?>
                            <div class="mt-6 text-center no-print">
                                <button id="loadMoreBtn" class="inline-flex items-center px-4 py-2 border border-gray-300 rounded-lg text-sm font-medium text-gray-700 bg-white hover:bg-gray-50 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-gold-primary">
                                    <i class="fas fa-chevron-down mr-2"></i>
                                    Load More Activities
                                </button>
                            </div>
                        <?php endif; ?>
                    </div>
                </div>
            </div>

            <!-- Sidebar -->
            <div class="lg:col-span-1 space-y-6 no-print">
                <!-- Activity Chart -->
                <div class="bg-white rounded-xl shadow-sm border border-gray-200 p-6">
                    <div class="flex items-center justify-between mb-4">
                        <h3 class="text-lg font-semibold text-gray-900">Activity Trends</h3>
                    </div>
                    <div class="relative h-48">
                        <canvas id="activityChart"></canvas>
                    </div>
                </div>

                <!-- Quick Stats -->
                <div class="bg-white rounded-xl shadow-sm border border-gray-200 p-6">
                    <h3 class="text-lg font-semibold text-gray-900 mb-4">Activity Summary</h3>
                    <div class="space-y-4" id="quickStats">
                        <!-- Stats will be populated by JavaScript -->
                    </div>
                </div>
            </div>
        </div>
    </div>

    <script>
        // Filter state
        let currentFilters = {
            dateRange: 'today',
            timeFilter: 'all',
            college: 'all',
            department: 'all',
            actionType: 'all'
        };

        document.addEventListener('DOMContentLoaded', function() {
            initializeFilters();
            initActivityChart();
            updateQuickStats();

            // Event listeners
            document.getElementById('dateFilter').addEventListener('change', function() {
                const customRange = document.getElementById('customDateRange');
                customRange.style.display = this.value === 'custom' ? 'block' : 'none';
            });

            document.getElementById('refreshBtn').addEventListener('click', refreshActivities);
        });

        function initializeFilters() {
            // Set today's date as default for custom range
            const today = new Date().toISOString().split('T')[0];
            document.getElementById('startDate').value = today;
            document.getElementById('endDate').value = today;
        }

        function toggleFilters() {
            const filtersSection = document.getElementById('filtersSection');
            filtersSection.style.display = filtersSection.style.display === 'none' ? 'block' : 'none';
        }

        function applyFilters() {
            // Get filter values
            currentFilters = {
                dateRange: document.getElementById('dateFilter').value,
                startDate: document.getElementById('startDate').value,
                endDate: document.getElementById('endDate').value,
                timeFilter: document.getElementById('timeFilter').value,
                college: document.getElementById('collegeFilter').value,
                department: document.getElementById('departmentFilter').value,
                actionType: document.getElementById('actionTypeFilter').value
            };

            // Simulate filtering (replace with actual AJAX call)
            filterActivities(currentFilters);

            // Close filters
            document.getElementById('filtersSection').style.display = 'none';

            showNotification('Filters applied successfully', 'success');
        }

        function resetFilters() {
            document.getElementById('dateFilter').value = 'today';
            document.getElementById('timeFilter').value = 'all';
            document.getElementById('collegeFilter').value = 'all';
            document.getElementById('departmentFilter').value = 'all';
            document.getElementById('actionTypeFilter').value = 'all';
            document.getElementById('customDateRange').style.display = 'none';

            currentFilters = {
                dateRange: 'today',
                timeFilter: 'all',
                college: 'all',
                department: 'all',
                actionType: 'all'
            };

            filterActivities(currentFilters);
            showNotification('Filters reset', 'info');
        }

        function filterActivities(filters) {
            // This would typically be an AJAX call to your backend
            // For now, we'll simulate filtering with the existing data

            const activities = <?php echo json_encode($data['activities']); ?>;
            let filteredActivities = activities.filter(activity => {
                let match = true;

                // Date range filtering
                if (filters.dateRange !== 'all') {
                    const activityDate = new Date(activity.created_at);
                    const today = new Date();

                    switch (filters.dateRange) {
                        case 'today':
                            match = match && activityDate.toDateString() === today.toDateString();
                            break;
                        case 'yesterday':
                            const yesterday = new Date(today);
                            yesterday.setDate(yesterday.getDate() - 1);
                            match = match && activityDate.toDateString() === yesterday.toDateString();
                            break;
                        case 'week':
                            const weekAgo = new Date(today);
                            weekAgo.setDate(weekAgo.getDate() - 7);
                            match = match && activityDate >= weekAgo;
                            break;
                        case 'month':
                            const monthAgo = new Date(today);
                            monthAgo.setMonth(monthAgo.getMonth() - 1);
                            match = match && activityDate >= monthAgo;
                            break;
                        case 'custom':
                            if (filters.startDate && filters.endDate) {
                                const start = new Date(filters.startDate);
                                const end = new Date(filters.endDate);
                                end.setHours(23, 59, 59);
                                match = match && activityDate >= start && activityDate <= end;
                            }
                            break;
                    }
                }

                // Time filtering
                if (filters.timeFilter !== 'all') {
                    const activityHour = new Date(activity.created_at).getHours();
                    switch (filters.timeFilter) {
                        case 'morning':
                            match = match && activityHour >= 6 && activityHour < 12;
                            break;
                        case 'afternoon':
                            match = match && activityHour >= 12 && activityHour < 18;
                            break;
                        case 'evening':
                            match = match && activityHour >= 18 && activityHour < 24;
                            break;
                        case 'night':
                            match = match && (activityHour >= 0 && activityHour < 6);
                            break;
                    }
                }

                // College filtering
                if (filters.college !== 'all') {
                    match = match && activity.college_name === filters.college;
                }

                // Department filtering
                if (filters.department !== 'all') {
                    match = match && activity.department_name === filters.department;
                }

                // Action type filtering
                if (filters.actionType !== 'all') {
                    match = match && activity.action_type === filters.actionType;
                }

                return match;
            });

            updateActivityDisplay(filteredActivities);
            updateQuickStats(filteredActivities);
        }

        function updateActivityDisplay(activities) {
            const activityFeed = document.getElementById('activityFeed');
            const resultsCount = document.getElementById('resultsCount');
            const filteredCount = document.getElementById('filteredCount');
            const totalActivities = document.getElementById('totalActivities');

            filteredCount.textContent = activities.length;
            resultsCount.textContent = `(Showing ${activities.length} activities)`;

            if (activities.length === 0) {
                activityFeed.innerHTML = `
                    <div class="text-center py-12">
                        <div class="w-16 h-16 bg-gray-100 rounded-full flex items-center justify-center mx-auto mb-4">
                            <i class="fas fa-search text-2xl text-gray-400"></i>
                        </div>
                        <h3 class="text-lg font-medium text-gray-900 mb-2">No Activities Found</h3>
                        <p class="text-gray-500">No activity data matches your current filters</p>
                    </div>
                `;
            } else {
                activityFeed.innerHTML = activities.slice(0, 10).map(activity => `
                    <div class="activity-item flex items-start space-x-3 p-4 rounded-lg border border-gray-100 hover:border-gold-primary hover:bg-gold-primary hover:bg-opacity-5">
                        <div class="flex-shrink-0">
                            <div class="w-8 h-8 rounded-full flex items-center justify-center ${getActivityIcon(activity.action_type).bg}">
                                <i class="${getActivityIcon(activity.action_type).icon} text-white text-sm"></i>
                            </div>
                        </div>
                        <div class="flex-1 min-w-0">
                            <div class="flex items-center justify-between">
                                <p class="text-sm font-medium text-gray-900">${activity.first_name} ${activity.last_name}</p>
                                <p class="text-xs text-gray-500">${new Date(activity.created_at).toLocaleDateString('en-US', { month: 'short', day: 'numeric', year: 'numeric', hour: 'numeric', minute: '2-digit' })}</p>
                            </div>
                            <p class="text-sm text-gray-600 mt-1">${activity.action_description} <span class="text-gray-400">(${activity.department_name}, ${activity.college_name})</span></p>
                            <div class="mt-2 flex items-center gap-2">
                                <span class="inline-flex items-center px-2 py-1 rounded-full text-xs font-medium ${getActivityType(activity.action_type).class}">
                                    ${getActivityType(activity.action_type).label}
                                </span>
                                <span class="text-xs text-gray-500">${timeAgo(activity.created_at)}</span>
                            </div>
                        </div>
                    </div>
                `).join('');
            }
        }

        function updateQuickStats(activities = null) {
            const stats = activities || <?php echo json_encode($data['activities']); ?>;
            const quickStats = document.getElementById('quickStats');

            const typeCounts = {};
            const collegeCounts = {};
            const deptCounts = {};

            stats.forEach(activity => {
                typeCounts[activity.action_type] = (typeCounts[activity.action_type] || 0) + 1;
                collegeCounts[activity.college_name] = (collegeCounts[activity.college_name] || 0) + 1;
                deptCounts[activity.department_name] = (deptCounts[activity.department_name] || 0) + 1;
            });

            quickStats.innerHTML = `
                <div class="flex items-center justify-between">
                    <span class="text-sm text-gray-600">Login Activities</span>
                    <span class="text-sm font-semibold text-gray-900">${typeCounts.login || 0}</span>
                </div>
                <div class="flex items-center justify-between">
                    <span class="text-sm text-gray-600">Schedule Updates</span>
                    <span class="text-sm font-semibold text-gray-900">${typeCounts.schedule || 0}</span>
                </div>
                <div class="flex items-center justify-between">
                    <span class="text-sm text-gray-600">System Actions</span>
                    <span class="text-sm font-semibold text-gray-900">${typeCounts.system || 0}</span>
                </div>
                <div class="pt-4 border-t border-gray-200">
                    <p class="text-sm font-medium text-gray-700 mb-2">Top Colleges</p>
                    ${Object.entries(collegeCounts).sort((a,b) => b[1]-a[1]).slice(0,3).map(([college, count]) => `
                        <div class="flex items-center justify-between text-sm">
                            <span class="text-gray-600 truncate">${college}</span>
                            <span class="font-semibold">${count}</span>
                        </div>
                    `).join('')}
                </div>
            `;
        }

        function printReport() {
            // Create a new window for printing
            const printWindow = window.open('', '_blank');

            // Get the current filter values for the report header
            const dateFilter = document.getElementById('dateFilter').value;
            const collegeFilter = document.getElementById('collegeFilter').value;
            const departmentFilter = document.getElementById('departmentFilter').value;
            const actionTypeFilter = document.getElementById('actionTypeFilter').value;

            // Build filter description
            let filterDescription = 'All Activities';
            if (dateFilter !== 'today' || collegeFilter !== 'all' || departmentFilter !== 'all' || actionTypeFilter !== 'all') {
                filterDescription = 'Filtered: ';
                const filters = [];
                if (dateFilter !== 'today') filters.push(`Date: ${dateFilter}`);
                if (collegeFilter !== 'all') filters.push(`College: ${collegeFilter}`);
                if (departmentFilter !== 'all') filters.push(`Department: ${departmentFilter}`);
                if (actionTypeFilter !== 'all') filters.push(`Type: ${actionTypeFilter}`);
                filterDescription += filters.join(', ');
            }

            // Write the print content
            printWindow.document.write(`
                <!DOCTYPE html>
                <html>
                <head>
                    <title>University Activity Report</title>
                    <style>
                        body { 
                            font-family: Arial, sans-serif; 
                            margin: 0.5in;
                            font-size: 12pt;
                            line-height: 1.4;
                            color: #000;
                        }
                        .letter-header {
                            text-align: center;
                            border-bottom: 2px solid #000;
                            padding-bottom: 20px;
                            margin-bottom: 20px;
                        }
                        .university-logo {
                            max-width: 1.5in;
                            height: auto;
                            margin-bottom: 10px;
                        }
                        .report-title {
                            font-size: 18pt;
                            font-weight: bold;
                            margin: 10px 0;
                            color: #000;
                        }
                        .report-subtitle {
                            font-size: 14pt;
                            margin-bottom: 15px;
                            color: #333;
                        }
                        .report-meta {
                            font-size: 10pt;
                            color: #666;
                            margin-bottom: 10px;
                        }
                        .summary-stats {
                            margin-bottom: 20px;
                        }
                        .stats-table {
                            width: 100%;
                            border-collapse: collapse;
                            margin-bottom: 15px;
                        }
                        .stats-table td {
                            border: 1px solid #ddd;
                            padding: 10px;
                            text-align: center;
                            vertical-align: top;
                        }
                        .stats-table strong {
                            display: block;
                            margin-bottom: 5px;
                        }
                        .activity-table {
                            width: 100%;
                            border-collapse: collapse;
                            margin: 20px 0;
                            font-size: 10pt;
                        }
                        .activity-table th,
                        .activity-table td {
                            border: 1px solid #ddd;
                            padding: 8px;
                            text-align: left;
                        }
                        .activity-table th {
                            background-color: #f5f5f5;
                            font-weight: bold;
                        }
                        .report-footer {
                            margin-top: 30px;
                            padding-top: 20px;
                            border-top: 1px solid #ddd;
                            text-align: center;
                            font-size: 9pt;
                            color: #666;
                        }
                        @page {
                            margin: 0.5in;
                            size: letter;
                        }
                    </style>
                </head>
                <body>
                    <div class="letter-header">
                        <!-- Replace with your actual university logo path -->
                        <img src="/assets/logo/main_logo/PRMSUlogo.png" alt="University Logo" class="university-logo" onerror="this.style.display='none'">
                        <div class="report-title">UNIVERSITY ACTIVITY REPORT</div>
                        <div class="report-subtitle">Activity Monitoring System</div>
                        <div class="report-meta">
                            Generated on: ${new Date().toLocaleDateString('en-US', { 
                                year: 'numeric', 
                                month: 'long', 
                                day: 'numeric',
                                hour: '2-digit',
                                minute: '2-digit'
                            })}<br>
                            Semester: <?php echo htmlspecialchars($data['current_semester_display']); ?><br>
                            ${filterDescription}
                        </div>
                    </div>

                    <div class="summary-stats">
                        <table class="stats-table">
                            <tr>
                                <td style="width: 25%">
                                    <strong>Total Activities</strong>
                                    ${document.getElementById('filteredCount').textContent}
                                </td>
                                <td style="width: 25%">
                                    <strong>Active Users</strong>
                                    ${document.getElementById('activeUsers').textContent}
                                </td>
                                <td style="width: 25%">
                                    <strong>Date Range</strong>
                                    ${document.getElementById('dateFilter').options[document.getElementById('dateFilter').selectedIndex].text}
                                </td>
                                <td style="width: 25%">
                                    <strong>Report Period</strong>
                                    ${new Date().toLocaleDateString()}
                                </td>
                            </tr>
                        </table>
                    </div>

                    <table class="activity-table">
                        <thead>
                            <tr>
                                <th>Date & Time</th>
                                <th>User</th>
                                <th>Department</th>
                                <th>College</th>
                                <th>Action Type</th>
                                <th>Description</th>
                            </tr>
                        </thead>
                        <tbody>
                            ${getPrintableActivities()}
                        </tbody>
                    </table>

                    <div class="report-footer">
                        <p>Confidential Activity Report - <?php echo htmlspecialchars($data['current_semester_display']); ?></p>
                        <p>Page 1 of 1 | Generated by University Activity Monitoring System</p>
                    </div>
                </body>
                </html>
            `);

            printWindow.document.close();
            printWindow.focus();

            // Wait for content to load then print
            setTimeout(() => {
                printWindow.print();
                printWindow.close();
            }, 500);
        }

        function getPrintableActivities() {
            const activities = <?php echo json_encode($data['activities']); ?>;
            let tableRows = '';

            activities.forEach(activity => {
                tableRows += `
            <tr>
                <td>${new Date(activity.created_at).toLocaleDateString('en-US', { 
                    year: 'numeric', 
                    month: 'short', 
                    day: 'numeric',
                    hour: '2-digit',
                    minute: '2-digit'
                })}</td>
                <td>${activity.first_name} ${activity.last_name}</td>
                <td>${activity.department_name}</td>
                <td>${activity.college_name}</td>
                <td>${activity.action_type.charAt(0).toUpperCase() + activity.action_type.slice(1)}</td>
                <td>${activity.action_description}</td>
            </tr>
            `;
            });

            return tableRows;
        }

        function generatePDF(action = 'download') {
            // Get current filter values
            const filters = {
                dateRange: document.getElementById('dateFilter')?.value || 'all',
                startDate: document.getElementById('startDate')?.value || '',
                endDate: document.getElementById('endDate')?.value || '',
                timeFilter: document.getElementById('timeFilter')?.value || 'all',
                college: document.getElementById('collegeFilter')?.value || 'all',
                department: document.getElementById('departmentFilter')?.value || 'all',
                actionType: document.getElementById('actionTypeFilter')?.value || 'all'
            };

            // Show loading
            showLoading('Generating PDF report...');

            // Determine the endpoint based on action
            let endpoint = '';
            switch (action) {
                case 'view':
                    endpoint = '/admin/act_logs/view-pdf';
                    break;
                case 'download':
                default:
                    endpoint = '/admin/act_logs/download-pdf';
                    break;
            }

            // Create and submit form
            const form = document.createElement('form');
            form.method = 'POST';
            form.action = endpoint;
            form.style.display = 'none';

            // Add filter values as hidden inputs
            Object.keys(filters).forEach(key => {
                if (filters[key]) { // Only add if value exists
                    const input = document.createElement('input');
                    input.type = 'hidden';
                    input.name = key;
                    input.value = filters[key];
                    form.appendChild(input);
                }
            });

            document.body.appendChild(form);
            form.submit();

            // Hide loading after a short delay (since we're navigating away)
            setTimeout(() => {
                hideLoading();
            }, 3000); // Longer timeout for PDF generation
        }

        function showLoading(message = 'Loading...') {
            // Remove existing loading if any
            hideLoading();

            // Create loading overlay
            const loadingOverlay = document.createElement('div');
            loadingOverlay.id = 'loadingOverlay';
            loadingOverlay.style.cssText = `
                position: fixed;
                top: 0;
                left: 0;
                width: 100%;
                height: 100%;
                background: rgba(0, 0, 0, 0.7);
                display: flex;
                flex-direction: column;
                justify-content: center;
                align-items: center;
                z-index: 9999;
                color: white;
                font-family: Arial, sans-serif;
            `;

            loadingOverlay.innerHTML = `
                <div style="text-align: center;">
                    <div class="fas fa-spinner fa-spin" style="font-size: 40px; margin-bottom: 10px;"></div>
                    <div style="font-size: 16px;">${message}</div>
                </div>
            `;

            document.body.appendChild(loadingOverlay);
            document.body.style.overflow = 'hidden';
        }

        function hideLoading() {
            const loadingOverlay = document.getElementById('loadingOverlay');
            if (loadingOverlay) {
                document.body.removeChild(loadingOverlay);
            }
            document.body.style.overflow = '';
        }

        function refreshActivities() {
            const refreshBtn = document.getElementById('refreshBtn');
            const icon = refreshBtn.querySelector('i');

            icon.classList.add('fa-spin');
            refreshBtn.disabled = true;

            // Simulate refresh
            setTimeout(() => {
                icon.classList.remove('fa-spin');
                refreshBtn.disabled = false;
                showNotification('Activities refreshed successfully', 'success');
            }, 1000);
        }

        function showNotification(message, type = 'info') {
            const notification = document.createElement('div');
            const bgColor = type === 'success' ? 'bg-green-100 border-green-500 text-green-700' :
                type === 'error' ? 'bg-red-100 border-red-500 text-red-700' :
                'bg-blue-100 border-blue-500 text-blue-700';

            notification.className = `fixed top-4 right-4 z-50 p-4 border-l-4 ${bgColor} rounded shadow-lg`;
            notification.innerHTML = `
                <div class="flex items-center">
                    <i class="fas ${type === 'success' ? 'fa-check-circle' : type === 'error' ? 'fa-exclamation-circle' : 'fa-info-circle'} mr-2"></i>
                    <span>${message}</span>
                </div>
            `;

            document.body.appendChild(notification);
            setTimeout(() => notification.remove(), 3000);
        }

        // Existing helper functions
        function getActivityIcon(type) {
            const icons = {
                'login': {
                    icon: 'fas fa-sign-in-alt',
                    bg: 'bg-green-500'
                },
                'logout': {
                    icon: 'fas fa-sign-out-alt',
                    bg: 'bg-red-500'
                },
                'schedule': {
                    icon: 'fas fa-calendar-alt',
                    bg: 'bg-blue-500'
                },
                'update': {
                    icon: 'fas fa-edit',
                    bg: 'bg-yellow-500'
                },
                'delete': {
                    icon: 'fas fa-trash',
                    bg: 'bg-red-500'
                },
                'create': {
                    icon: 'fas fa-plus',
                    bg: 'bg-green-500'
                },
                'system': {
                    icon: 'fas fa-cog',
                    bg: 'bg-gray-500'
                },
                'default': {
                    icon: 'fas fa-info-circle',
                    bg: 'bg-blue-500'
                }
            };
            return icons[type] || icons['default'];
        }

        function getActivityType(type) {
            const types = {
                'login': {
                    label: 'Login',
                    class: 'bg-green-100 text-green-800'
                },
                'logout': {
                    label: 'Logout',
                    class: 'bg-red-100 text-red-800'
                },
                'schedule': {
                    label: 'Schedule',
                    class: 'bg-blue-100 text-blue-800'
                },
                'update': {
                    label: 'Update',
                    class: 'bg-yellow-100 text-yellow-800'
                },
                'delete': {
                    label: 'Delete',
                    class: 'bg-red-100 text-red-800'
                },
                'create': {
                    label: 'Create',
                    class: 'bg-green-100 text-green-800'
                },
                'system': {
                    label: 'System',
                    class: 'bg-gray-100 text-gray-800'
                },
                'default': {
                    label: 'Activity',
                    class: 'bg-blue-100 text-blue-800'
                }
            };
            return types[type] || types['default'];
        }

        function timeAgo(datetime) {
            const time = new Date() - new Date(datetime);
            if (time < 60000) return 'just now';
            if (time < 3600000) return Math.floor(time / 60000) + ' min ago';
            if (time < 86400000) return Math.floor(time / 3600000) + ' hr ago';
            if (time < 2592000000) return Math.floor(time / 86400000) + ' days ago';
            return new Date(datetime).toLocaleDateString('en-US', {
                month: 'short',
                day: 'numeric',
                year: 'numeric'
            });
        }

        function initActivityChart() {
            const ctx = document.getElementById('activityChart');
            if (!ctx) return;

            const activities = <?php echo json_encode($data['activities']); ?>;
            const last7Days = [];
            const activityData = [];

            for (let i = 6; i >= 0; i--) {
                const date = new Date();
                date.setDate(date.getDate() - i);
                last7Days.push(date.toLocaleDateString('en', {
                    weekday: 'short'
                }));

                const dayActivities = activities.filter(activity => {
                    const activityDate = new Date(activity.created_at);
                    return activityDate.toDateString() === date.toDateString();
                }).length;

                activityData.push(dayActivities);
            }

            new Chart(ctx, {
                type: 'line',
                data: {
                    labels: last7Days,
                    datasets: [{
                        label: 'Activities',
                        data: activityData,
                        borderColor: '#D4AF37',
                        backgroundColor: 'rgba(212, 175, 55, 0.1)',
                        borderWidth: 2,
                        fill: true,
                        tension: 0.4
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
                                color: '#f3f4f6'
                            },
                            ticks: {
                                color: '#6b7280'
                            }
                        },
                        x: {
                            grid: {
                                display: false
                            },
                            ticks: {
                                color: '#6b7280'
                            }
                        }
                    }
                }
            });
        }
    </script>
</body>

</html>

<?php
// Helper functions (keep your existing PHP helper functions)
function getActivityIcon($type)
{
    $icons = [
        'login' => ['icon' => 'fas fa-sign-in-alt', 'bg' => 'bg-green-500'],
        'logout' => ['icon' => 'fas fa-sign-out-alt', 'bg' => 'bg-red-500'],
        'schedule' => ['icon' => 'fas fa-calendar-alt', 'bg' => 'bg-blue-500'],
        'update' => ['icon' => 'fas fa-edit', 'bg' => 'bg-yellow-500'],
        'delete' => ['icon' => 'fas fa-trash', 'bg' => 'bg-red-500'],
        'create' => ['icon' => 'fas fa-plus', 'bg' => 'bg-green-500'],
        'system' => ['icon' => 'fas fa-cog', 'bg' => 'bg-gray-500'],
        'default' => ['icon' => 'fas fa-info-circle', 'bg' => 'bg-blue-500']
    ];
    return $icons[$type] ?? $icons['default'];
}

function getActivityType($type)
{
    $types = [
        'login' => ['label' => 'Login', 'class' => 'bg-green-100 text-green-800'],
        'logout' => ['label' => 'Logout', 'class' => 'bg-red-100 text-red-800'],
        'schedule' => ['label' => 'Schedule', 'class' => 'bg-blue-100 text-blue-800'],
        'update' => ['label' => 'Update', 'class' => 'bg-yellow-100 text-yellow-800'],
        'delete' => ['label' => 'Delete', 'class' => 'bg-red-100 text-red-800'],
        'create' => ['label' => 'Create', 'class' => 'bg-green-100 text-green-800'],
        'system' => ['label' => 'System', 'class' => 'bg-gray-100 text-gray-800'],
        'default' => ['label' => 'Activity', 'class' => 'bg-blue-100 text-blue-800']
    ];
    return $types[$type] ?? $types['default'];
}

function timeAgo($datetime)
{
    $time = time() - strtotime($datetime);
    if ($time < 60) return 'just now';
    if ($time < 3600) return floor($time / 60) . ' min ago';
    if ($time < 86400) return floor($time / 3600) . ' hr ago';
    if ($time < 2592000) return floor($time / 86400) . ' days ago';
    return date('M j, Y', strtotime($datetime));
}

$content = ob_get_clean();
require_once __DIR__ . '/layout.php';
?>