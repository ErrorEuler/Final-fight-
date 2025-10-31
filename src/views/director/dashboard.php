<?php
ob_start();
?>

<!DOCTYPE html>
<html lang="en">

<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title><?php echo htmlspecialchars($data['title']); ?></title>
    <script src="https://cdn.jsdelivr.net/npm/chart.js@4.4.0/dist/chart.umd.min.js"></script>
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css">
    <style>
        :root {
            --primary-yellow: #F4C029;
            --primary-dark: #1e40af;
            --secondary-yellow: #B98A0C;
            --accent-orange: #f59e0b;
            --card-bg: #ffffff;
            --text-primary: #1f2937;
            --text-secondary: #6b7280;
            --border-color: #e5e7eb;
        }

        body {
            font-family: 'Inter', -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            background: linear-gradient(135deg, #f8fafc 0%, #e2e8f0 100%);
            min-height: 100vh;
        }

        .stats-card {
            background: var(--card-bg);
            border-radius: 16px;
            box-shadow: 0 4px 6px -1px rgba(0, 0, 0, 0.1), 0 2px 4px -1px rgba(0, 0, 0, 0.06);
            border: 1px solid var(--border-color);
            transition: all 0.3s ease;
            position: relative;
            overflow: hidden;
        }

        .stats-card::before {
            content: '';
            position: absolute;
            top: 0;
            left: 0;
            right: 0;
            height: 4px;
            background: linear-gradient(90deg, var(--primary-yellow), var(--secondary-yellow));
        }

        .stats-card:hover {
            transform: translateY(-2px);
            box-shadow: 0 10px 15px -3px rgba(0, 0, 0, 0.1);
        }

        .chart-card {
            background: var(--card-bg);
            border-radius: 16px;
            box-shadow: 0 4px 6px -1px rgba(0, 0, 0, 0.1);
            border: 1px solid var(--border-color);
            padding: 1.5rem;
        }

        .chart-header {
            display: flex;
            align-items: center;
            justify-content: space-between;
            margin-bottom: 1.5rem;
            padding-bottom: 1rem;
            border-bottom: 2px solid var(--primary-yellow);
        }

        .chart-title {
            font-size: 1.125rem;
            font-weight: 700;
            color: var(--text-primary);
            display: flex;
            align-items: center;
            gap: 0.5rem;
        }

        .stats-icon {
            width: 56px;
            height: 56px;
            border-radius: 16px;
            display: flex;
            align-items: center;
            justify-content: center;
            font-size: 1.5rem;
        }

        .icon-pending {
            background: linear-gradient(135deg, #f59e0b, #d97706);
            color: white;
        }

        .icon-deadline {
            background: linear-gradient(135deg, #ef4444, #dc2626);
            color: white;
        }

        .icon-schedule {
            background: linear-gradient(135deg, #10b981, #059669);
            color: white;
        }

        .deadline-card {
            background: linear-gradient(135deg, #fef3c7 0%, #fed7aa 100%);
            border: 2px solid #f59e0b;
            border-radius: 12px;
            padding: 1.5rem;
            margin-bottom: 1.5rem;
        }

        .activity-item {
            display: flex;
            align-items: start;
            padding: 1rem;
            border-radius: 8px;
            transition: all 0.2s ease;
            border-left: 3px solid transparent;
        }

        .activity-item:hover {
            background: #f9fafb;
            border-left-color: var(--primary-yellow);
        }

        .activity-icon {
            width: 40px;
            height: 40px;
            border-radius: 10px;
            display: flex;
            align-items: center;
            justify-content: center;
            flex-shrink: 0;
            margin-right: 1rem;
            background: var(--primary-yellow);
            color: white;
        }

        .quick-action-card {
            background: linear-gradient(135deg, var(--primary-dark) 0%, #1e3a8a 100%);
            border-radius: 12px;
            padding: 1.5rem;
            color: white;
            transition: all 0.3s ease;
        }

        .quick-action-card:hover {
            transform: translateY(-2px);
            box-shadow: 0 8px 20px rgba(30, 64, 175, 0.3);
        }

        .progress-bar {
            height: 6px;
            background: #e5e7eb;
            border-radius: 3px;
            overflow: hidden;
            margin-top: 0.5rem;
        }

        .progress-fill {
            height: 100%;
            background: linear-gradient(90deg, var(--primary-yellow), var(--secondary-yellow));
            border-radius: 3px;
            transition: width 1s ease;
        }

        .metric-badge {
            display: inline-flex;
            align-items: center;
            gap: 0.25rem;
            padding: 0.25rem 0.75rem;
            border-radius: 9999px;
            font-size: 0.75rem;
            font-weight: 600;
        }

        .trend-up {
            color: #059669;
            background: #d1fae5;
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

        .animate-slide-up {
            animation: slideUp 0.5s ease-out forwards;
        }

        .summary-card {
            background: linear-gradient(135deg, #f0f9ff 0%, #e0f2fe 100%);
            border: 2px solid #0284c7;
            border-radius: 12px;
            padding: 1.5rem;
        }
    </style>
</head>

<body>
    <div class="min-h-screen px-4 sm:px-6 lg:px-8 py-6">
        <!-- Main Header -->
        <div class="bg-gray-800 text-white rounded-xl p-6 mb-8 shadow-lg">
            <div class="flex flex-col lg:flex-row items-start lg:items-center justify-between">
                <div>
                    <h1 class="text-3xl font-bold mb-2">PRMSU Scheduling System</h1>
                    <p class="font-bold text-yellow-400 mb-1">Director Dashboard</p>
                </div>
                <div class="flex flex-col sm:flex-row items-start sm:items-center gap-3 mt-4 lg:mt-0">
                    <span class="text-sm bg-gray-700 px-4 py-2 rounded-full flex items-center">
                        <i class="fas fa-calendar mr-2 text-yellow-500"></i>
                        <?php
                        if (!empty($data['semester'])) {
                            $sem = htmlspecialchars($data['semester']['semester_name'] ?? 'Unknown');
                            $ay  = htmlspecialchars($data['semester']['academic_year'] ?? 'Unknown');
                            echo "{$sem} Semester | A.Y: {$ay}";
                        } else {
                            echo 'Semester: Not Set';
                        }
                        ?>
                    </span>
                    <span class="text-sm bg-yellow-600 px-4 py-2 rounded-full flex items-center">
                        <i class="fas fa-clock mr-2"></i>
                        Active Term
                    </span>
                </div>
            </div>
        </div>

        <!-- Stats Cards -->
        <div class="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-6 mb-8">
            <!-- Pending Approvals -->
            <div class="stats-card p-6 animate-slide-up">
                <div class="flex items-center justify-between mb-4">
                    <div class="stats-icon icon-pending">
                        <i class="fas fa-clock"></i>
                    </div>
                    <div class="text-xs font-semibold <?php echo ($data['pending_approvals'] > 0) ? 'text-orange-600 bg-orange-100' : 'text-green-600 bg-green-100'; ?> px-3 py-1 rounded-full">
                        <?php echo ($data['pending_approvals'] > 0) ? 'ACTION NEEDED' : 'UP TO DATE'; ?>
                    </div>
                </div>
                <div>
                    <p class="text-sm font-semibold text-gray-600 mb-2">Pending Approvals</p>
                    <p class="text-3xl font-bold text-gray-900 mb-2"><?php echo htmlspecialchars($data['pending_approvals'] ?? '0'); ?></p>
                    <p class="text-xs text-gray-500">Schedule reviews awaiting approval</p>
                </div>
            </div>

            <!-- Schedule Deadline -->
            <div class="stats-card p-6 animate-slide-up">
                <a href="/director/schedule_deadline" class="block">
                    <div class="flex items-center justify-between mb-4">
                        <div class="stats-icon icon-deadline">
                            <i class="fas fa-calendar-times"></i>
                        </div>
                        <div class="text-xs font-semibold <?php echo ($data['deadline']) ? 'text-green-600 bg-green-100' : 'text-red-600 bg-red-100'; ?> px-3 py-1 rounded-full">
                            <?php echo ($data['deadline']) ? 'SET' : 'NOT SET'; ?>
                        </div>
                    </div>
                    <div>
                        <p class="text-sm font-semibold text-gray-600 mb-2">Schedule Deadline</p>
                        <p class="text-xl font-bold text-gray-900 mb-2">
                            <?php echo $data['deadline'] ? htmlspecialchars(date('M d, Y', strtotime($data['deadline']))) : 'Not Set'; ?>
                        </p>
                        <p class="text-xs text-gray-500">Submission deadline for schedules</p>
                    </div>
                </a>
            </div>

            <!-- Department Overview -->
            <div class="stats-card p-6 animate-slide-up">
                <div class="flex items-center justify-between mb-4">
                    <div class="stats-icon icon-schedule">
                        <i class="fas fa-users"></i>
                    </div>
                    <div class="text-xs font-semibold text-blue-600 bg-blue-100 px-3 py-1 rounded-full">
                        OVERVIEW
                    </div>
                </div>
                <div>
                    <p class="text-sm font-semibold text-gray-600 mb-2">Department Stats</p>
                    <p class="text-xl font-bold text-gray-900 mb-2">Active</p>
                    <p class="text-xs text-gray-500">View department analytics</p>
                </div>
            </div>
        </div>

        <!-- Deadline Alert -->
        <?php if ($data['deadline']): ?>
            <div class="deadline-card animate-slide-up">
                <div class="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-4">
                    <div class="flex items-start">
                        <i class="fas fa-exclamation-triangle text-orange-600 text-xl mr-3 mt-1"></i>
                        <div>
                            <h3 class="font-semibold text-orange-900 mb-1">Schedule Deadline Set</h3>
                            <p class="text-orange-700 text-sm">Deadline: <?php echo htmlspecialchars(date('F j, Y \a\t g:i A', strtotime($data['deadline']))); ?></p>
                        </div>
                    </div>
                    <a href="/director/schedule_deadline" class="bg-orange-600 hover:bg-orange-700 text-white px-4 py-2 rounded-lg font-medium transition-colors">
                        Update Deadline
                    </a>
                </div>
            </div>
        <?php endif; ?>

        <!-- Charts Section -->
        <div class="grid grid-cols-1 lg:grid-cols-3 gap-6 mb-8">
            <!-- Schedule Distribution -->
            <div class="lg:col-span-2 chart-card animate-slide-up">
                <div class="chart-header">
                    <h3 class="chart-title">
                        <i class="fas fa-chart-pie text-yellow-600"></i>
                        Schedule Distribution
                    </h3>
                    <span class="metric-badge trend-up">
                        <i class="fas fa-arrow-up text-xs"></i>
                        Active
                    </span>
                </div>
                <div style="height: 300px;">
                    <canvas id="scheduleDistributionChart"></canvas>
                </div>
            </div>

            <!-- Quick Actions Section - Updated with CSS classes -->
            <div class="space-y-4 animate-slide-up">
                <a href="/director/pending-approvals" class="block quick-action-card">
                    <div class="flex items-center justify-between mb-2">
                        <div class="w-10 h-10 bg-white bg-opacity-20 rounded-lg flex items-center justify-center">
                            <span class="fas fa-check-circle text-xl"></span>
                        </div>
                        <span class="fas fa-arrow-right"></span>
                    </div>
                    <h4 class="font-bold mb-1">Review Schedules</h4>
                    <p class="text-sm text-gray-200 opacity-90">Approve pending submissions</p>
                </a>

                <a href="/director/schedule_deadline" class="block quick-action-card" style="background: linear-gradient(135deg, #f59e0b 0%, #d97706 100%);">
                    <div class="flex items-center justify-between mb-2">
                        <div class="w-10 h-10 bg-white bg-opacity-20 rounded-lg flex items-center justify-center">
                            <span class="fas fa-clock text-xl"></span>
                        </div>
                        <span class="fas fa-arrow-right"></span>
                    </div>
                    <h4 class="font-bold mb-1">Set Deadline</h4>
                    <p class="text-sm text-gray-200 opacity-90">Manage submission dates</p>
                </a>

                <a href="/director/schedule" class="block quick-action-card" style="background: linear-gradient(135deg, #10b981 0%, #059669 100%);">
                    <div class="flex items-center justify-between mb-2">
                        <div class="w-10 h-10 bg-white bg-opacity-20 rounded-lg flex items-center justify-center">
                            <span class="fas fa-calendar-alt text-xl"></span>
                        </div>
                        <span class="fas fa-arrow-right"></span>
                    </div>
                    <h4 class="font-bold mb-1">View Schedule</h4>
                    <p class="text-sm text-gray-200 opacity-90">See full calendar</p>
                </a>
            </div>
        </div>

        <!-- Analytics Section -->
        <div class="grid grid-cols-1 lg:grid-cols-3 gap-6">
            <!-- Time Distribution -->
            <div class="lg:col-span-2 chart-card animate-slide-up">
                <div class="chart-header">
                    <h3 class="chart-title">
                        <i class="fas fa-chart-bar text-yellow-600"></i>
                        Weekly Distribution
                    </h3>
                    <span class="text-xs text-gray-500">Schedules per day</span>
                </div>
                <div style="height: 300px;">
                    <canvas id="timeDistributionChart"></canvas>
                </div>
            </div>

            <!-- Recent Activity -->
            <div class="chart-card animate-slide-up">
                <div class="chart-header">
                    <h3 class="chart-title">
                        <i class="fas fa-bell text-yellow-600"></i>
                        Recent Activity
                    </h3>
                    <span class="text-xs text-gray-500">Last 24 hours</span>
                </div>
                <div class="space-y-3 max-h-80 overflow-y-auto">
                    <?php if (!empty($data['recent_activity'])): ?>
                        <?php foreach ($data['recent_activity'] as $activity): ?>
                            <div class="activity-item">
                                <div class="activity-icon">
                                    <i class="fas fa-user"></i>
                                </div>
                                <div class="flex-1">
                                    <p class="text-sm font-medium text-gray-900">
                                        <?php echo htmlspecialchars($activity['first_name'] . ' ' . $activity['last_name']); ?>
                                    </p>
                                    <p class="text-xs text-gray-600">
                                        <?php echo htmlspecialchars($activity['action_description']); ?>
                                    </p>
                                    <p class="text-xs text-gray-400 mt-1">
                                        <?php echo date('h:i A', strtotime($activity['created_at'])); ?>
                                    </p>
                                </div>
                            </div>
                        <?php endforeach; ?>
                    <?php else: ?>
                        <div class="text-center py-8 text-gray-500">
                            <i class="fas fa-inbox text-2xl mb-2"></i>
                            <p class="text-sm">No recent activity</p>
                        </div>
                    <?php endif; ?>
                </div>
            </div>
        </div>
    </div>

    <script>
        document.addEventListener('DOMContentLoaded', function() {
            // Schedule Distribution Chart
            const dayDistribution = <?php echo json_encode($data['day_distribution']); ?>;

            if (dayDistribution && dayDistribution.length > 0) {
                const scheduleCtx = document.getElementById('scheduleDistributionChart').getContext('2d');
                new Chart(scheduleCtx, {
                    type: 'doughnut',
                    data: {
                        labels: dayDistribution.map(item => item.day_of_week),
                        datasets: [{
                            data: dayDistribution.map(item => parseInt(item.count)),
                            backgroundColor: ['#F4C029', '#1e40af', '#10b981', '#f59e0b', '#ef4444', '#8b5cf6', '#06b6d4'],
                            borderWidth: 2,
                            borderColor: '#ffffff'
                        }]
                    },
                    options: {
                        responsive: true,
                        maintainAspectRatio: false,
                        plugins: {
                            legend: {
                                position: 'bottom'
                            }
                        }
                    }
                });
            }

            // Time Distribution Chart
            const timeDistribution = <?php echo json_encode($data['time_distribution']); ?>;
            const daysOfWeek = ['Monday', 'Tuesday', 'Wednesday', 'Thursday', 'Friday', 'Saturday', 'Sunday'];

            const timeCtx = document.getElementById('timeDistributionChart').getContext('2d');
            new Chart(timeCtx, {
                type: 'bar',
                data: {
                    labels: daysOfWeek,
                    datasets: [{
                        label: 'Schedules',
                        data: daysOfWeek.map(day => {
                            const dayData = timeDistribution?.find(item => item.day_of_week === day);
                            return dayData ? parseInt(dayData.schedule_count || dayData.count || 0) : 0;
                        }),
                        backgroundColor: 'rgba(244, 192, 41, 0.8)',
                        borderColor: '#F4C029',
                        borderWidth: 1,
                        borderRadius: 4
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
                            beginAtZero: true
                        }
                    }
                }
            });
        });
    </script>
</body>

</html>

<?php
$content = ob_get_clean();
require_once __DIR__ . '/layout.php';
?>