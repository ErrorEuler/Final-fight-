<?php
ob_start();
?>

<div>
    <!-- Dashboard Header -->
    <div class="bg-gradient-to-r from-gray-800 to-gray-900 text-white rounded-xl p-6 sm:p-8 mb-8 shadow-lg relative overflow-hidden">
        <div class="absolute top-0 left-0 w-2 h-full bg-yellow-500"></div>
        <div class="flex flex-col sm:flex-row items-start sm:items-center justify-between">
            <div>
                <h1 class="text-2xl sm:text-3xl font-bold">PRMSU Scheduling System</h1>
                <p class="text-gray-300 mt-2"><?php echo htmlspecialchars($college['college_name'] ?? 'College'); ?></p>
            </div>
            <div class="flex flex-col sm:flex-row items-start sm:items-center space-y-2 sm:space-y-0 sm:space-x-4 mt-4 sm:mt-0">
                <span class="text-sm bg-gray-700 px-3 py-1 rounded-full flex items-center">
                    <svg class="w-4 h-4 mr-1 text-yellow-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                        <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M8 7V3m8 4V3m-9 8h10M5 21h14a2 2 0 002-2V7a2 2 0 00-2-2H5a2 2 0 00-2 2v12a2 2 0 002 2z" />
                    </svg>
                    <?php echo htmlspecialchars($currentSemester); ?>
                </span>
                <span class="bg-yellow-500 px-3 py-1 rounded-full flex items-center text-gray-900 font-semibold">
                    <svg class="w-4 h-4 mr-1" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                        <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 8v4l3 3m6-3a9 9 0 11-18 0 9 9 0 0118 0z" />
                    </svg>
                    Active Term
                </span>
            </div>
        </div>
    </div>

    <!-- Stats Grid -->
    <div class="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6 mb-8">
        <!-- Total Faculty Card -->
        <div class="bg-white rounded-lg shadow-md p-6 border-l-4 border-yellow-500 hover:shadow-lg transition-shadow">
            <div class="flex items-center justify-between">
                <div>
                    <p class="text-gray-500 text-sm font-medium">Total Faculty</p>
                    <h3 class="text-3xl font-bold text-gray-800 mt-2"><?php echo $stats['total_faculty']; ?></h3>
                </div>
                <div class="bg-yellow-100 rounded-full p-3">
                    <i class="fas fa-users text-yellow-500 text-2xl"></i>
                </div>
            </div>
        </div>

        <!-- Total Classrooms Card -->
        <div class="bg-white rounded-lg shadow-md p-6 border-l-4 border-yellow-500 hover:shadow-lg transition-shadow">
            <div class="flex items-center justify-between">
                <div>
                    <p class="text-gray-500 text-sm font-medium">Total Classrooms</p>
                    <h3 class="text-3xl font-bold text-gray-800 mt-2"><?php echo $stats['total_classrooms']; ?></h3>
                </div>
                <div class="bg-yellow-100 rounded-full p-3">
                    <i class="fas fa-door-open text-yellow-500 text-2xl"></i>
                </div>
            </div>
        </div>

        <!-- Total Departments Card -->
        <div class="bg-white rounded-lg shadow-md p-6 border-l-4 border-yellow-500 hover:shadow-lg transition-shadow">
            <div class="flex items-center justify-between">
                <div>
                    <p class="text-gray-500 text-sm font-medium">Total Departments</p>
                    <h3 class="text-3xl font-bold text-gray-800 mt-2"><?php echo $stats['total_departments']; ?></h3>
                </div>
                <div class="bg-yellow-100 rounded-full p-3">
                    <i class="fas fa-building text-yellow-600 text-2xl"></i>
                </div>
            </div>
        </div>

        <!-- Pending Approvals Card -->
        <div class="bg-white rounded-lg shadow-md p-6 border-l-4 border-yellow-500 hover:shadow-lg transition-shadow">
            <div class="flex items-center justify-between">
                <div>
                    <p class="text-gray-500 text-sm font-medium">Pending Approvals</p>
                    <h3 class="text-3xl font-bold text-gray-800 mt-2"><?php echo $stats['pending_approvals']; ?></h3>
                </div>
                <div class="bg-yellow-100 rounded-full p-3">
                    <i class="fas fa-clock text-yellow-500 text-2xl"></i>
                </div>
            </div>
        </div>
    </div>

    <!-- Main Content Grid - REARRANGED LAYOUT -->
    <div class="grid grid-cols-1 lg:grid-cols-3 gap-6">
        <!-- Middle Column - Charts -->
        <div class="lg:col-span-2 space-y-6">
            <!-- Schedule Distribution Chart -->
            <div class="bg-white p-6 rounded-xl border border-yellow-200 shadow-sm">
                <div class="flex items-center justify-between mb-6">
                    <h3 class="text-lg font-semibold text-gray-900">Schedule Distribution by Day</h3>
                    <span class="fas fa-chart-bar text-yellow-500"></span>
                </div>
                <div class="h-64">
                    <?php if (!empty($scheduleDistribution)): ?>
                        <canvas id="scheduleDistributionChart"></canvas>
                    <?php else: ?>
                        <div class="h-full flex items-center justify-center text-gray-400">
                            <div class="text-center">
                                <span class="fas fa-chart-bar text-4xl mb-2"></span>
                                <p>No schedule data available</p>
                            </div>
                        </div>
                    <?php endif; ?>
                </div>
            </div>

            <!-- Classroom Availability -->
            <div class="bg-white p-6 rounded-xl border border-yellow-200 shadow-sm">
                <div class="flex items-center justify-between mb-6">
                    <h3 class="text-lg font-semibold text-gray-900">Classroom Availability</h3>
                    <span class="fas fa-door-open text-yellow-500"></span>
                </div>
                <div class="h-64">
                    <?php if (!empty($classroomAvailability)): ?>
                        <canvas id="classroomAvailabilityChart"></canvas>
                    <?php else: ?>
                        <div class="h-full flex items-center justify-center text-gray-400">
                            <div class="text-center">
                                <span class="fas fa-door-open text-4xl mb-2"></span>
                                <p>No classroom data available</p>
                            </div>
                        </div>
                    <?php endif; ?>
                </div>
            </div>

            <!-- Department Overview -->
            <div class="bg-white p-6 rounded-xl border border-yellow-200 shadow-sm">
                <div class="flex items-center justify-between mb-6">
                    <h3 class="text-lg font-semibold text-gray-900">Department Overview</h3>
                    <span class="fas fa-building text-yellow-500"></span>
                </div>
                <div class="space-y-4">
                    <?php if (!empty($departmentOverview)): ?>
                        <?php foreach ($departmentOverview as $dept): ?>
                            <div class="flex items-center justify-between p-4 bg-yellow-50 rounded-lg border border-yellow-100">
                                <div>
                                    <p class="font-medium text-gray-900"><?php echo htmlspecialchars($dept['department_name']); ?></p>
                                    <p class="text-sm text-gray-600"><?php echo $dept['faculty_count']; ?> faculty • <?php echo $dept['active_schedules']; ?> schedules</p>
                                </div>
                                <div class="text-right">
                                    <span class="text-sm font-medium text-gray-900"><?php echo $dept['course_count']; ?> courses</span>
                                    <div class="text-xs text-gray-500 mt-1">
                                        <?php if ($dept['faculty_count'] > 0): ?>
                                            <span class="text-yellow-600 font-medium">Active</span>
                                        <?php else: ?>
                                            <span class="text-gray-400">No faculty</span>
                                        <?php endif; ?>
                                    </div>
                                </div>
                            </div>
                        <?php endforeach; ?>
                    <?php else: ?>
                        <div class="text-center py-8 text-gray-400">
                            <span class="fas fa-inbox text-2xl mb-2"></span>
                            <p>No departments</p>
                        </div>
                    <?php endif; ?>
                </div>
            </div>
        </div>

        <!-- Left Column - My Schedule & Quick Actions -->
        <div class="space-y-6">
            <!-- My Schedule - MOVED TO LEFT COLUMN -->
            <div class="bg-white p-6 rounded-xl border border-yellow-200 shadow-sm">
                <div class="flex items-center justify-between mb-4">
                    <h3 class="text-lg font-semibold text-gray-900">My Schedule</h3>
                    <span class="fas fa-calendar text-yellow-500"></span>
                </div>
                <div class="space-y-3">
                    <?php if (!empty($schedules)): ?>
                        <?php foreach (array_slice($schedules, 0, 5) as $schedule): ?>
                            <div class="p-3 bg-yellow-50 rounded-lg border border-yellow-100">
                                <div class="flex justify-between items-start">
                                    <div>
                                        <p class="font-medium text-gray-900 text-sm"><?php echo htmlspecialchars($schedule['course_code']); ?></p>
                                        <p class="text-xs text-gray-600"><?php echo htmlspecialchars($schedule['course_name']); ?></p>
                                    </div>
                                    <span class="text-xs font-medium text-yellow-700 bg-yellow-100 px-2 py-1 rounded">
                                        <?php echo htmlspecialchars($schedule['day_of_week'] ?? 'TBD'); ?>
                                    </span>
                                </div>
                                <div class="flex justify-between items-center mt-2 text-xs text-gray-500">
                                    <span><?php echo htmlspecialchars($schedule['room_name'] ?? 'TBA'); ?></span>
                                    <span><?php echo htmlspecialchars($schedule['start_time'] . ' - ' . $schedule['end_time']); ?></span>
                                </div>
                            </div>
                        <?php endforeach; ?>
                        <?php if (count($schedules) > 5): ?>
                            <a href="/dean/schedule" class="block text-center text-sm text-yellow-600 hover:text-yellow-700 font-medium mt-2">
                                View all <?php echo count($schedules); ?> schedules
                            </a>
                        <?php endif; ?>
                    <?php else: ?>
                        <div class="text-center py-6 text-gray-400">
                            <span class="fas fa-calendar-times text-2xl mb-2"></span>
                            <p class="text-sm">No schedules</p>
                        </div>
                    <?php endif; ?>
                </div>
            </div>

            <!-- Quick Actions -->
            <div class="bg-white p-6 rounded-xl border border-yellow-200 shadow-sm">
                <h3 class="text-lg font-semibold text-gray-900 mb-4">Quick Actions</h3>
                <div class="space-y-3">
                    <a href="/dean/pending-approvals" class="flex items-center justify-between p-4 bg-yellow-50 rounded-lg hover:bg-yellow-100 transition-colors border border-yellow-200">
                        <div class="flex items-center">
                            <span class="fas fa-check-circle text-yellow-600 text-lg mr-3"></span>
                            <span class="font-medium text-gray-900">Review Approvals</span>
                        </div>
                        <span class="fas fa-arrow-right text-yellow-500"></span>
                    </a>

                    <a href="/dean/schedule" class="flex items-center justify-between p-4 bg-yellow-50 rounded-lg hover:bg-yellow-100 transition-colors border border-yellow-200">
                        <div class="flex items-center">
                            <span class="fas fa-calendar-alt text-yellow-600 text-lg mr-3"></span>
                            <span class="font-medium text-gray-900">View Schedule</span>
                        </div>
                        <span class="fas fa-arrow-right text-yellow-500"></span>
                    </a>

                    <a href="/dean/faculty" class="flex items-center justify-between p-4 bg-yellow-50 rounded-lg hover:bg-yellow-100 transition-colors border border-yellow-200">
                        <div class="flex items-center">
                            <span class="fas fa-users text-yellow-600 text-lg mr-3"></span>
                            <span class="font-medium text-gray-900">Manage Faculty</span>
                        </div>
                        <span class="fas fa-arrow-right text-yellow-500"></span>
                    </a>
                </div>
            </div>

            <!-- Recent Activity -->
            <div class="bg-white p-6 rounded-xl border border-yellow-200 shadow-sm">
                <div class="flex items-center justify-between mb-4">
                    <h3 class="text-lg font-semibold text-gray-900">Recent Activity</h3>
                    <span class="fas fa-bell text-yellow-500"></span>
                </div>
                <div class="space-y-3">
                    <?php if (!empty($activities)): ?>
                        <?php foreach (array_slice($activities, 0, 4) as $activity): ?>
                            <div class="flex items-start space-x-3">
                                <div class="w-8 h-8 bg-yellow-100 rounded-full flex items-center justify-center flex-shrink-0">
                                    <span class="fas fa-user text-yellow-600 text-sm"></span>
                                </div>
                                <div class="flex-1 min-w-0">
                                    <p class="text-sm text-gray-900 truncate"><?php echo htmlspecialchars($activity['description'] ?? 'Activity'); ?></p>
                                    <p class="text-xs text-gray-500 mt-1"><?php echo date('h:i A', strtotime($activity['created_at'] ?? 'now')); ?></p>
                                </div>
                            </div>
                        <?php endforeach; ?>
                    <?php else: ?>
                        <div class="text-center py-4 text-gray-400">
                            <span class="fas fa-inbox text-lg mb-1"></span>
                            <p class="text-sm">No recent activity</p>
                        </div>
                    <?php endif; ?>
                </div>
            </div>
        </div>
    </div>
</div>

<script src="https://cdnjs.cloudflare.com/ajax/libs/Chart.js/3.9.1/chart.min.js"></script>
<script>
    document.addEventListener('DOMContentLoaded', function() {
        // Schedule Distribution Chart - Bar Chart
        const scheduleCtx = document.getElementById('scheduleDistributionChart');
        if (scheduleCtx) {
            <?php if (!empty($scheduleDistribution)): ?>
                new Chart(scheduleCtx, {
                    type: 'bar',
                    data: {
                        labels: <?php echo json_encode(array_column($scheduleDistribution, 'day_of_week')); ?>,
                        datasets: [{
                            label: 'Number of Schedules',
                            data: <?php echo json_encode(array_column($scheduleDistribution, 'schedule_count')); ?>,
                            backgroundColor: [
                                '#F59E0B', '#FBBF24', '#FCD34D', '#FDE68A', '#FEF3C7', '#FEF7CD', '#FFFBEB'
                            ],
                            borderColor: '#D97706',
                            borderWidth: 1
                        }]
                    },
                    options: {
                        responsive: true,
                        maintainAspectRatio: false,
                        plugins: {
                            legend: {
                                display: false
                            },
                            tooltip: {
                                callbacks: {
                                    label: function(context) {
                                        return `Schedules: ${context.parsed.y}`;
                                    }
                                }
                            }
                        },
                        scales: {
                            y: {
                                beginAtZero: true,
                                title: {
                                    display: true,
                                    text: 'Number of Schedules'
                                },
                                ticks: {
                                    stepSize: 1
                                }
                            },
                            x: {
                                title: {
                                    display: true,
                                    text: 'Day of Week'
                                }
                            }
                        }
                    }
                });
            <?php endif; ?>
        }

        // Classroom Availability Chart - Horizontal Bar Chart
        const classroomCtx = document.getElementById('classroomAvailabilityChart');
        if (classroomCtx) {
            <?php if (!empty($classroomAvailability)): ?>
                // Group classrooms by usage level
                const usageLevels = {
                    'Available': 0,
                    'Moderate': 0,
                    'Heavy': 0
                };

                <?php foreach ($classroomAvailability as $classroom): ?>
                    usageLevels['<?php echo $classroom['usage_level']; ?>']++;
                <?php endforeach; ?>

                new Chart(classroomCtx, {
                    type: 'bar',
                    data: {
                        labels: ['Available', 'Moderate', 'Heavy'],
                        datasets: [{
                            label: 'Classrooms',
                            data: [usageLevels['Available'], usageLevels['Moderate'], usageLevels['Heavy']],
                            backgroundColor: [
                                '#10B981', // Green for available
                                '#F59E0B', // Yellow for moderate
                                '#EF4444' // Red for heavy
                            ],
                            borderColor: [
                                '#047857',
                                '#D97706',
                                '#DC2626'
                            ],
                            borderWidth: 1
                        }]
                    },
                    options: {
                        indexAxis: 'y',
                        responsive: true,
                        maintainAspectRatio: false,
                        plugins: {
                            legend: {
                                display: false
                            },
                            tooltip: {
                                callbacks: {
                                    label: function(context) {
                                        return `${context.parsed.x} classrooms`;
                                    }
                                }
                            }
                        },
                        scales: {
                            x: {
                                beginAtZero: true,
                                title: {
                                    display: true,
                                    text: 'Number of Classrooms'
                                },
                                ticks: {
                                    stepSize: 1
                                }
                            },
                            y: {
                                title: {
                                    display: true,
                                    text: 'Usage Level'
                                }
                            }
                        }
                    }
                });
            <?php endif; ?>
        }
    });
</script>

<?php
$content = ob_get_clean();
require_once __DIR__ . '/layout.php';
?>