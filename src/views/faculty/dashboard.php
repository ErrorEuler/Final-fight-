<?php
// Default values for safety
$teachingLoad = isset($teachingLoad) ? $teachingLoad : 0;
$pendingRequests = isset($pendingRequests) ? $pendingRequests : 0;
$recentSchedules = isset($recentSchedules) ? $recentSchedules : [];
$scheduleDistJson = isset($scheduleDistJson) ? $scheduleDistJson : json_encode([0, 0, 0, 0, 0, 0]);
$departmentName = isset($departmentName) ? $departmentName : 'Department';
$error = isset($error) ? $error : '';
$success = isset($success) ? $success : '';
// Keep original semester info formatting
$semesterInfo = isset($semesterInfo) ? $semesterInfo : '2nd Semester A.Y. 2024-2025';

ob_start();
?>

<!DOCTYPE html>
<html lang="en">

<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>PRMSU Scheduling System - Faculty Dashboard</title>
    <link rel="stylesheet" href="/css/output.css">
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css">
    <script src="https://cdnjs.cloudflare.com/ajax/libs/Chart.js/3.9.1/chart.min.js"></script>
    <style>
        @import url('https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700&display=swap');

        * {
            font-family: 'Inter', sans-serif;
        }

        .custom-shadow {
            box-shadow: 0 4px 6px -1px rgba(0, 0, 0, 0.1), 0 2px 4px -1px rgba(0, 0, 0, 0.06);
        }

        .hover-lift {
            transition: transform 0.2s ease-in-out, box-shadow 0.2s ease-in-out;
        }

        .hover-lift:hover {
            transform: translateY(-2px);
            box-shadow: 0 8px 25px -5px rgba(0, 0, 0, 0.1), 0 4px 10px -3px rgba(0, 0, 0, 0.05);
        }

        .gradient-bg {
            background: linear-gradient(135deg, #1f2937 0%, #374151 100%);
        }

        @keyframes slideIn {
            from {
                opacity: 0;
                transform: translateY(20px);
            }

            to {
                opacity: 1;
                transform: translateY(0);
            }
        }

        .slide-in {
            animation: slideIn 0.6s ease-out forwards;
        }

        .metric-card {
            position: relative;
            overflow: hidden;
        }

        .metric-card::before {
            content: '';
            position: absolute;
            top: 0;
            left: 0;
            right: 0;
            height: 4px;
            background: linear-gradient(90deg, #fbbf24, #f59e0b);
        }
    </style>
</head>

<body class="bg-gray-50 min-h-screen">
    <!-- Header Section -->
    <div class="bg-gray-800 text-white rounded-xl mx-4 sm:mx-6 lg:mx-8 mt-4 mb-4 p-6 shadow-lg relative overflow-hidden">
        <div class="absolute top-0 left-0 w-2 h-full bg-yellow-600"></div>
        <div class="flex items-center justify-between">
            <div>
                <h1 class="text-3xl font-bold">PRMSU Scheduling System</h1>
                <h3 class="font-bold text-white">Welcome, <?php echo htmlspecialchars($_SESSION['first_name']); ?>!</h3>
                <?php if (isset($departmentName) && !empty($departmentName)): ?>
                    <p class="text-gray-300 mt-2"><?php echo htmlspecialchars($departmentName); ?></p>
                <?php endif; ?>
            </div>
            <div class="hidden md:flex items-center space-x-4">
                <span class="text-sm bg-gray-700 px-3 py-1 rounded-full flex items-center">
                    <svg class="w-4 h-4 mr-1 text-yellow-500" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                        <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M8 7V3m8 4V3m-9 8h10M5 21h14a2 2 0 002-2V7a2 2 0 00-2-2H5a2 2 0 00-2 2v12a2 2 0 002 2z" />
                    </svg>
                    <?php echo htmlspecialchars($semesterInfo, ENT_QUOTES, 'UTF-8'); ?>
                </span>
                <span class="text-sm bg-yellow-600 px-3 py-1 rounded-full flex items-center">
                    <svg class="w-4 h-4 mr-1" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                        <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 8v4l3 3m6-3a9 9 0 11-18 0 9 9 0 0118 0z" />
                    </svg>
                    Active Term
                </span>
            </div>
        </div>
    </div>

    <!-- Main Content -->
    <div class="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8">

        <!-- Metrics Cards -->
        <div class="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-6 mb-8">
            <!-- Teaching Load Card -->
            <div class="metric-card bg-white rounded-xl custom-shadow hover-lift cursor-pointer slide-in"
                onclick="window.location.href='/faculty/schedule'"
                style="animation-delay: 0.1s">
                <div class="p-6">
                    <div class="flex items-center justify-between">
                        <div>
                            <p class="text-sm font-medium text-gray-600 mb-1">Teaching Load</p>
                            <p class="text-3xl font-bold text-gray-900"><?php echo htmlspecialchars($teachingLoad); ?></p>
                            <p class="text-xs text-gray-500 mt-1">
                                <i class="fas fa-book mr-1"></i>
                                Assigned schedules
                            </p>
                        </div>
                        <div class="w-12 h-12 bg-yellow-100 rounded-full flex items-center justify-center">
                            <i class="fas fa-calendar-check text-yellow-600 text-lg"></i>
                        </div>
                    </div>
                </div>
            </div>

            <!-- Total Courses Card -->
            <div class="metric-card bg-white rounded-xl custom-shadow hover-lift slide-in"
                style="animation-delay: 0.3s">
                <div class="p-6">
                    <div class="flex items-center justify-between">
                        <div>
                            <p class="text-sm font-medium text-gray-600 mb-1">Total Courses</p>
                            <p class="text-3xl font-bold text-gray-900"><?php echo count($recentSchedules); ?></p>
                            <p class="text-xs text-gray-500 mt-1">
                                <i class="fas fa-graduation-cap mr-1"></i>
                                This semester
                            </p>
                        </div>
                        <div class="w-12 h-12 bg-yellow-100 rounded-full flex items-center justify-center">
                            <i class="fas fa-chalkboard-teacher text-yellow-600 text-lg"></i>
                        </div>
                    </div>
                </div>
            </div>

            <!-- Status Card -->
            <div class="metric-card bg-white rounded-xl custom-shadow hover-lift slide-in"
                style="animation-delay: 0.4s">
                <div class="p-6">
                    <div class="flex items-center justify-between">
                        <div>
                            <p class="text-sm font-medium text-gray-600 mb-1">Status</p>
                            <p class="text-xl font-bold text-green-600">Active</p>
                            <p class="text-xs text-gray-500 mt-1">
                                <i class="fas fa-user-check mr-1"></i>
                                All systems ready
                            </p>
                        </div>
                        <div class="w-12 h-12 bg-green-100 rounded-full flex items-center justify-center">
                            <i class="fas fa-check-circle text-green-600 text-lg"></i>
                        </div>
                    </div>
                </div>
            </div>
        </div>

        <!-- Charts and Actions Section -->
        <div class="grid grid-cols-1 lg:grid-cols-3 gap-8 mb-8">
            <!-- Schedule Distribution Chart -->
            <div class="lg:col-span-2 bg-white rounded-xl custom-shadow slide-in" style="animation-delay: 0.5s">
                <div class="p-6">
                    <div class="flex items-center justify-between mb-6">
                        <h3 class="text-lg font-semibold text-gray-900">Weekly Schedule Distribution</h3>
                        <div class="text-sm text-gray-500">
                            <i class="fas fa-chart-bar mr-1"></i>
                            Current semester
                        </div>
                    </div>
                    <div class="h-64 flex items-center justify-center">
                        <canvas id="scheduleChart" class="max-w-full max-h-full"></canvas>
                    </div>
                </div>
            </div>

            <!-- Quick Actions -->
            <div class="bg-white rounded-xl custom-shadow slide-in" style="animation-delay: 0.6s">
                <div class="p-6">
                    <h3 class="text-lg font-semibold text-gray-900 mb-6">Quick Actions</h3>
                    <div class="space-y-4">
                       

                        <a href="/faculty/schedule"
                            class="w-full bg-yellow-500 hover:bg-yellow-200 text-yellow-700 px-4 py-3 rounded-lg transition duration-200 flex items-center justify-center font-medium hover-lift">
                            <i class="fas fa-calendar-alt mr-2"></i>
                            View My Schedule
                        </a>

                        <a href="/faculty/profile"
                            class="w-full bg-gray-100 hover:bg-gray-200 text-gray-700 px-4 py-3 rounded-lg transition duration-200 flex items-center justify-center font-medium hover-lift">
                            <i class="fas fa-user-cog mr-2"></i>
                            Update Profile
                        </a>

                        <a href="/faculty/reports"
                            class="w-full bg-gray-100 hover:bg-gray-200 text-gray-700 px-4 py-3 rounded-lg transition duration-200 flex items-center justify-center font-medium hover-lift">
                            <i class="fas fa-file-alt mr-2"></i>
                            Generate Reports
                        </a>
                    </div>
                </div>
            </div>
        </div>

        <!-- Recent Schedules Table -->
        <div class="bg-white rounded-xl custom-shadow slide-in" style="animation-delay: 0.7s">
            <div class="p-6 border-b border-gray-200">
                <div class="flex flex-col sm:flex-row sm:items-center sm:justify-between">
                    <div>
                        <h3 class="text-lg font-semibold text-gray-900">Recent Schedules</h3>
                        <p class="text-sm text-gray-500 mt-1">Your recently assigned teaching schedules</p>
                    </div>
                    <a href="/faculty/schedule"
                        class="mt-3 sm:mt-0 text-yellow-600 hover:text-yellow-700 text-sm font-medium flex items-center">
                        View All
                        <i class="fas fa-arrow-right ml-1"></i>
                    </a>
                </div>
            </div>

            <div class="overflow-x-auto">
                <?php if (empty($recentSchedules)): ?>
                    <div class="px-6 py-12 text-center">
                        <div class="w-16 h-16 bg-gray-100 rounded-full flex items-center justify-center mx-auto mb-4">
                            <i class="fas fa-calendar-times text-gray-400 text-2xl"></i>
                        </div>
                        <h3 class="text-lg font-medium text-gray-900 mb-2">No schedules assigned</h3>
                        <p class="text-gray-500 mb-6">You don't have any teaching schedules assigned yet.</p>
                        
                    </div>
                <?php else: ?>
                    <table class="min-w-full divide-y divide-gray-200">
                        <thead class="bg-gray-50">
                            <tr>
                                <th scope="col" class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Course Code</th>
                                <th scope="col" class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Course Name</th>
                                <th scope="col" class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Room</th>
                                <th scope="col" class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Schedule</th>
                                <th scope="col" class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Type</th>
                            </tr>
                        </thead>
                        <tbody class="bg-white divide-y divide-gray-200">
                            <?php foreach ($recentSchedules as $schedule): ?>
                                <tr class="hover:bg-gray-50 transition duration-150">
                                    <td class="px-6 py-4 whitespace-nowrap">
                                        <div class="flex items-center">
                                            <div class="w-8 h-8 bg-yellow-100 rounded-full flex items-center justify-center mr-3">
                                                <i class="fas fa-book text-yellow-600 text-sm"></i>
                                            </div>
                                            <div class="text-sm font-medium text-gray-900">
                                                <?php echo htmlspecialchars($schedule['course_code']); ?>
                                            </div>
                                        </div>
                                    </td>
                                    <td class="px-6 py-4 whitespace-nowrap">
                                        <div class="flex items-center">
                                            <div class="w-8 h-8 bg-yellow-100 rounded-full flex items-center justify-center mr-3">
                                                <i class="fas fa-book text-yellow-600 text-sm"></i>
                                            </div>
                                            <div class="text-sm font-medium text-gray-900">
                                                <?php echo htmlspecialchars($schedule['course_name']); ?>
                                            </div>
                                        </div>
                                    </td>
                                    <td class="px-6 py-4 whitespace-nowrap">
                                        <div class="flex items-center text-sm text-gray-900">
                                            <i class="fas fa-map-marker-alt text-gray-400 mr-2"></i>
                                            <?php echo htmlspecialchars($schedule['room_name'] ?? 'Online'); ?>
                                        </div>
                                    </td>
                                    <td class="px-6 py-4 whitespace-nowrap">
                                        <div class="text-sm text-gray-900 font-medium">
                                            <?php echo htmlspecialchars($schedule['day_of_week']); ?>
                                        </div>
                                        <div class="text-sm text-gray-500">
                                            <i class="fas fa-clock mr-1"></i>
                                            <?php echo htmlspecialchars(date('g:i A', strtotime($schedule['start_time'])) . ' - ' . date('g:i A', strtotime($schedule['end_time']))); ?>
                                        </div>
                                    </td>
                                    <td class="px-6 py-4 whitespace-nowrap">
                                        <?php
                                        $typeConfig = [
                                            'F2F' => ['bg-green-100 text-green-800', 'fas fa-users'],
                                            'Online' => ['bg-blue-100 text-blue-800', 'fas fa-laptop'],
                                            'Hybrid' => ['bg-purple-100 text-purple-800', 'fas fa-route'],
                                            'Asynchronous' => ['bg-yellow-100 text-yellow-800', 'fas fa-clock']
                                        ];
                                        $config = $typeConfig[$schedule['schedule_type']] ?? ['bg-gray-100 text-gray-800', 'fas fa-question'];
                                        ?>
                                        <span class="inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium <?php echo $config[0]; ?>">
                                            <i class="<?php echo $config[1]; ?> mr-1"></i>
                                            <?php echo htmlspecialchars($schedule['schedule_type']); ?>
                                        </span>
                                    </td>
                                </tr>
                            <?php endforeach; ?>
                        </tbody>
                    </table>
                <?php endif; ?>
            </div>
        </div>
    </div>

    <script>
        // Initialize Chart.js
        document.addEventListener('DOMContentLoaded', function() {
            const ctx = document.getElementById('scheduleChart').getContext('2d');
            const scheduleData = <?php echo $scheduleDistJson; ?>;
            const days = ['Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat'];

            new Chart(ctx, {
                type: 'bar',
                data: {
                    labels: days,
                    datasets: [{
                        label: 'Classes',
                        data: scheduleData,
                        backgroundColor: 'rgba(251, 191, 36, 0.8)',
                        borderColor: 'rgba(245, 158, 11, 1)',
                        borderWidth: 2,
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
                            ticks: {
                                stepSize: 1,
                                color: '#6B7280'
                            },
                            grid: {
                                color: 'rgba(107, 114, 128, 0.1)'
                            }
                        },
                        x: {
                            ticks: {
                                color: '#6B7280'
                            },
                            grid: {
                                display: false
                            }
                        }
                    }
                }
            });
        });
    </script>
</body>

</html>

<?php
// Capture the content and pass it to layout
$content = ob_get_clean();
require_once __DIR__ . '/layout.php';
?>