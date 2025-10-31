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
    </style>
</head>

<body class="bg-gradient-to-br from-gray-50 to-gray-100 min-h-screen">
    <div class="max-w-7xl mx-auto px-4 sm:p-6 lg:p-8 py-8">
        <!-- Stats Cards -->
        <div class="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-6 mb-8">
            <!-- Header -->
            <div class="mb-6 bg-white rounded-xl shadow-sm border border-gray-200 p-6 animate-fade-in" style="animation-delay: 0.1s">
                <div class="flex items-center justify-between">
                    <div>
                        <h1 class="text-2xl font-bold text-gray-900"><?php echo htmlspecialchars($data['title']); ?></h1>
                        <div class="mt-2 flex items-center space-x-4">
                            <div class="text-sm text-gray-600">
                                <span class="inline-flex items-center bg-yellow-100 text-yellow-800 px-3 py-1 rounded-full">
                                    <i class="fas fa-calendar-alt mr-2"></i>
                                    Current Semester: <?php echo htmlspecialchars($data['current_semester_display']); ?>
                                </span>
                            </div>
                        </div>
                    </div>
                </div>
            </div>

            <!-- Total Activities -->
            <div class="mb-6 bg-white rounded-xl shadow-sm border border-gray-200 p-6 animate-fade-in">
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
                <div class="mt-4">
                    <div class="flex items-center text-sm">
                        <i class="fas fa-arrow-up text-green-500 mr-1"></i>
                        <span class="text-green-600 font-medium">12%</span>
                        <span class="text-gray-500 ml-1">from last week</span>
                    </div>
                </div>
            </div>

            <!-- Today's Activities -->
            <div class="mb-6 bg-white rounded-xl shadow-sm border border-gray-200 p-6 animate-fade-in" style="animation-delay: 0.1s">
                <div class="flex items-center justify-between">
                    <div>
                        <p class="text-sm font-medium text-gray-500 mb-1">Today's Activities</p>
                        <p class="text-2xl font-bold text-gray-900" id="todayActivities">
                            <?php
                            $todayCount = 0;
                            foreach ($data['activities'] as $activity) {
                                if (date('Y-m-d', strtotime($activity['created_at'])) === date('Y-m-d')) {
                                    $todayCount++;
                                }
                            }
                            echo $todayCount;
                            ?>
                        </p>
                    </div>
                    <div class="w-12 h-12 bg-gradient-to-r from-green-500 to-green-600 rounded-lg flex items-center justify-center">
                        <i class="fas fa-calendar-day text-white"></i>
                    </div>
                </div>
                <div class="mt-4">
                    <div class="flex items-center text-sm">
                        <i class="fas fa-clock text-blue-500 mr-1"></i>
                        <span class="text-blue-600 font-medium">Live</span>
                        <span class="text-gray-500 ml-1">updating</span>
                    </div>
                </div>
            </div>

            <!-- Active Users -->
            <div class="mb-6 bg-white rounded-xl shadow-sm border border-gray-200 p-6 animate-fade-in" style="animation-delay: 0.2s">
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
                <div class="mt-4">
                    <div class="flex items-center text-sm">
                        <i class="fas fa-pulse text-purple-500 mr-1"></i>
                        <span class="text-purple-600 font-medium">Online</span>
                        <span class="text-gray-500 ml-1">now</span>
                    </div>
                </div>
            </div>
        </div>

        <div class="grid grid-cols-1 lg:grid-cols-3 gap-8">
            <!-- Activity Feed -->
            <div class="lg:col-span-2">
                <div class="bg-white rounded-xl shadow-sm border border-gray-200">
                    <div class="p-6 border-b border-gray-200">
                        <div class="flex items-center justify-between">
                            <div class="flex items-center space-x-3">
                                <div class="w-8 h-8 bg-gradient-to-r from-gold-primary to-gold-dark rounded-lg flex items-center justify-center">
                                    <i class="fas fa-stream text-white text-sm"></i>
                                </div>
                                <h3 class="text-lg font-semibold text-gray-900">Recent Activities</h3>
                            </div>
                            <div class="flex items-center space-x-2">
                                <button id="refreshBtn" class="inline-flex items-center px-3 py-1.5 border border-gray-300 rounded-lg text-xs font-medium text-gray-700 bg-white hover:bg-gray-50 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-gold-primary transition-all duration-200">
                                    <i class="fas fa-sync-alt mr-1.5"></i>
                                    Refresh
                                </button>
                                <div class="flex items-center space-x-1">
                                    <div class="w-2 h-2 bg-green-500 rounded-full animate-pulse"></div>
                                    <span class="text-xs text-green-600 font-medium">Live</span>
                                </div>
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
                                    <h3 class="text-lg font-medium text-gray-900 mb-2">No Activities Yet</h3>
                                    <p class="text-gray-500">Activity data will appear here when available</p>
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
                                                    <?php echo timeAgo($activity['created_at']); ?>
                                                </p>
                                            </div>
                                            <p class="text-sm text-gray-600 mt-1">
                                                <?php echo htmlspecialchars($activity['action_description']); ?>
                                                <span class="text-gray-400">(<?php echo htmlspecialchars($activity['department_name']); ?>, <?php echo htmlspecialchars($activity['college_name']); ?>)</span>
                                            </p>
                                            <div class="mt-2">
                                                <span class="inline-flex items-center px-2 py-1 rounded-full text-xs font-medium <?php echo getActivityType($activity['action_type'])['class']; ?>">
                                                    <?php echo getActivityType($activity['action_type'])['label']; ?>
                                                </span>
                                            </div>
                                        </div>
                                    </div>
                                <?php endforeach; ?>
                            <?php endif; ?>
                        </div>

                        <?php if (count($data['activities']) > 10): ?>
                            <div class="mt-6 text-center">
                                <button id="loadMoreBtn" class="inline-flex items-center px-4 py-2 border border-gray-300 rounded-lg text-sm font-medium text-gray-700 bg-white hover:bg-gray-50 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-gold-primary transition-all duration-200">
                                    <i class="fas fa-chevron-down mr-2"></i>
                                    Load More Activities
                                </button>
                            </div>
                        <?php endif; ?>
                    </div>
                </div>
            </div>

            <!-- Sidebar -->
            <div class="lg:col-span-1 space-y-6">
                <!-- Activity Chart -->
                <div class="bg-white rounded-xl shadow-sm border border-gray-200 p-6">
                    <div class="flex items-center justify-between mb-4">
                        <h3 class="text-lg font-semibold text-gray-900">Activity Trends</h3>
                        <div class="flex items-center space-x-2">
                            <div class="w-2 h-2 bg-gold-primary rounded-full"></div>
                            <span class="text-xs text-gray-500">Last 7 days</span>
                        </div>
                    </div>
                    <div class="relative h-48">
                        <canvas id="activityChart"></canvas>
                    </div>
                </div>

                <!-- Quick Stats -->
                <div class="bg-white rounded-xl shadow-sm border border-gray-200 p-6">
                    <h3 class="text-lg font-semibold text-gray-900 mb-4">Quick Stats</h3>
                    <div class="space-y-4">
                        <div class="flex items-center justify-between">
                            <span class="text-sm text-gray-600">Schedule Updates</span>
                            <span class="text-sm font-semibold text-gray-900">
                                <?php
                                $scheduleCount = 0;
                                foreach ($data['activities'] as $activity) {
                                    if (strpos(strtolower($activity['action_description']), 'schedule') !== false) {
                                        $scheduleCount++;
                                    }
                                }
                                echo $scheduleCount;
                                ?>
                            </span>
                        </div>
                        <div class="flex items-center justify-between">
                            <span class="text-sm text-gray-600">Login Activities</span>
                            <span class="text-sm font-semibold text-gray-900">
                                <?php
                                $loginCount = 0;
                                foreach ($data['activities'] as $activity) {
                                    if ($activity['action_type'] === 'login' || strpos(strtolower($activity['action_description']), 'login') !== false) {
                                        $loginCount++;
                                    }
                                }
                                echo $loginCount;
                                ?>
                            </span>
                        </div>
                        <div class="flex items-center justify-between">
                            <span class="text-sm text-gray-600">System Updates</span>
                            <span class="text-sm font-semibold text-gray-900">
                                <?php
                                $systemCount = 0;
                                foreach ($data['activities'] as $activity) {
                                    if ($activity['action_type'] === 'system' || strpos(strtolower($activity['action_description']), 'system') !== false) {
                                        $systemCount++;
                                    }
                                }
                                echo $systemCount;
                                ?>
                            </span>
                        </div>
                    </div>
                </div>

                <!-- Activity Types -->
                <div class="bg-white rounded-xl shadow-sm border border-gray-200 p-6">
                    <h3 class="text-lg font-semibold text-gray-900 mb-4">Activity Types</h3>
                    <div class="space-y-3">
                        <?php
                        $activityTypes = [];
                        foreach ($data['activities'] as $activity) {
                            $type = $activity['action_type'] ?? 'other';
                            $activityTypes[$type] = ($activityTypes[$type] ?? 0) + 1;
                        }
                        arsort($activityTypes);
                        ?>
                        <?php foreach (array_slice($activityTypes, 0, 5, true) as $type => $count): ?>
                            <div class="flex items-center justify-between">
                                <div class="flex items-center space-x-2">
                                    <div class="w-4 h-4 rounded-full <?php echo getActivityIcon($type)['bg']; ?>"></div>
                                    <span class="text-sm text-gray-600 capitalize"><?php echo htmlspecialchars($type); ?></span>
                                </div>
                                <span class="text-sm font-semibold text-gray-900"><?php echo $count; ?></span>
                            </div>
                        <?php endforeach; ?>
                    </div>
                </div>
            </div>
        </div>
    </div>

    <script>
        // JavaScript helper functions
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
                    'bg': 'bg-green-500'
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

        document.addEventListener('DOMContentLoaded', function() {
            // Initialize activity chart
            initActivityChart();

            // Auto-refresh functionality
            let refreshInterval;
            startAutoRefresh();

            // Refresh button
            document.getElementById('refreshBtn').addEventListener('click', function() {
                refreshActivities();
            });

            // Load more functionality
            const loadMoreBtn = document.getElementById('loadMoreBtn');
            if (loadMoreBtn) {
                loadMoreBtn.addEventListener('click', function() {
                    const offset = document.querySelectorAll('#activityFeed .activity-item').length;
                    fetch('/director/monitor/load-more', {
                            method: 'POST',
                            headers: {
                                'Content-Type': 'application/x-www-form-urlencoded'
                            },
                            body: `offset=${offset}`
                        })
                        .then(response => {
                            if (!response.ok) {
                                throw new Error(`HTTP error! Status: ${response.status}`);
                            }
                            return response.json();
                        })
                        .then(data => {
                            if (data.success) {
                                data.activities.forEach(activity => {
                                    const item = createActivityItem(activity);
                                    document.getElementById('activityFeed').appendChild(item);
                                });
                                if (!data.hasMore) loadMoreBtn.style.display = 'none';
                            } else {
                                showNotification(data.error || 'Failed to load more activities', 'error');
                            }
                        })
                        .catch(error => {
                            console.error('Load more error:', error);
                            showNotification('An error occurred while loading more activities.', 'error');
                        });
                });

                function createActivityItem(activity) {
                    const div = document.createElement('div');
                    div.className = 'activity-item flex items-start space-x-3 p-4 rounded-lg border border-gray-100 hover:border-gold-primary hover:bg-gold-primary hover:bg-opacity-5';
                    div.innerHTML = `
                    <div class="flex-shrink-0">
                        <div class="w-8 h-8 rounded-full flex items-center justify-center ${getActivityIcon(activity.action_type).bg}">
                            <i class="${getActivityIcon(activity.action_type).icon}" text-white text-sm"></i>
                        </div>
                    </div>
                    <div class="flex-1 min-w-0">
                        <div class="flex items-center justify-between">
                            <p class="text-sm font-medium text-gray-900">${activity.first_name} ${activity.last_name}</p>
                            <p class="text-xs text-gray-500">${timeAgo(activity.created_at)}</p>
                        </div>
                        <p class="text-sm text-gray-600 mt-1">${activity.action_description} ( ${activity.department_name}, ${activity.college_name} )</p>
                        <div class="mt-2">
                            <span class="inline-flex items-center px-2 py-1 rounded-full text-xs font-medium ${getActivityType(activity.action_type).class}">
                                ${getActivityType(activity.action_type).label}
                            </span>
                        </div>
                    </div>
                `;
                    return div;
                }
            }

            function initActivityChart() {
                const ctx = document.getElementById('activityChart');
                if (!ctx) return;

                // Generate sample data for the last 7 days
                const last7Days = [];
                const activityData = [];

                for (let i = 6; i >= 0; i--) {
                    const date = new Date();
                    date.setDate(date.getDate() - i);
                    last7Days.push(date.toLocaleDateString('en', {
                        weekday: 'short'
                    }));

                    // Count activities for this day
                    const dayActivities = <?php echo json_encode($data['activities']); ?>.filter(activity => {
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

            function refreshActivities() {
                const refreshBtn = document.getElementById('refreshBtn');
                const icon = refreshBtn.querySelector('i');

                // Add loading state
                icon.classList.add('fa-spin');
                refreshBtn.disabled = true;

                // Simulate refresh (replace with actual AJAX call)
                setTimeout(() => {
                    icon.classList.remove('fa-spin');
                    refreshBtn.disabled = false;

                    // Show success notification
                    showNotification('Activities refreshed successfully', 'success');
                }, 1000);
            }

            function startAutoRefresh() {
                refreshInterval = setInterval(() => {
                    // Silently refresh data every 30 seconds
                    // Replace with actual AJAX call
                    console.log('Auto-refreshing activities...');
                }, 30000);
            }

            function showNotification(message, type = 'info') {
                const notification = document.createElement('div');
                const bgColor = type === 'success' ? 'bg-green-100 border-green-500 text-green-700' : 'bg-blue-100 border-blue-500 text-blue-700';

                notification.className = `fixed top-4 right-4 z-50 p-4 border-l-4 ${bgColor} rounded shadow-lg animate-slide-up`;
                notification.innerHTML = `
                <div class="flex items-center">
                    <i class="fas ${type === 'success' ? 'fa-check-circle' : 'fa-info-circle'} mr-2"></i>
                    <span>${message}</span>
                </div>
            `;

                document.body.appendChild(notification);

                setTimeout(() => {
                    notification.remove();
                }, 3000);
            }

            // Add smooth scrolling to activity items
            const activityItems = document.querySelectorAll('.activity-item');
            activityItems.forEach((item, index) => {
                item.style.animationDelay = `${index * 0.05}s`;
                item.classList.add('animate-fade-in');
            });
        });
    </script>
</body>

</html>

<?php
// Helper functions
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