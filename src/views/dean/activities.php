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
    </style>
</head>

<body class="bg-white text-gray-800 font-sans min-h-screen">
    <div class="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8">
        <!-- Header Section with Semester Info -->
        <div class="mb-8">
            <div class="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-4">
                <div>
                    <h1 class="text-3xl font-bold text-gray-900">College Activities Dashboard</h1>
                    <div class="flex items-center gap-4 mt-2">
                        <!-- Current Semester Badge -->
                        <span class="inline-flex items-center px-3 py-1 rounded-full bg-yellow-100 border border-yellow-300">
                            <i class="fas fa-calendar-alt text-yellow-600 mr-2"></i>
                            <span class="text-sm font-medium text-yellow-800"><?php echo htmlspecialchars($data['current_semester_display']); ?></span>
                        </span>
                        <!-- College Info -->
                        <span class="inline-flex items-center px-3 py-1 rounded-lg bg-gray-100 border border-gray-300">
                            <i class="fas fa-university text-gray-600 mr-2"></i>
                            <span class="text-sm text-gray-700">Viewing All Departments</span>
                        </span>
                    </div>
                </div>

                <!-- Filters -->
                <div class="flex flex-col sm:flex-row gap-2">
                    <form method="GET" class="flex gap-2">
                        <select name="department_id" onchange="this.form.submit()" class="border border-gray-300 rounded-lg px-3 py-2 text-sm text-gray-700 focus:outline-none focus:ring-2 focus:ring-yellow-400">
                            <option value="">All Departments</option>
                            <?php foreach ($data['departments'] as $dept): ?>
                                <option value="<?php echo $dept['department_id']; ?>" <?php echo ($data['department_id'] == $dept['department_id']) ? 'selected' : ''; ?>>
                                    <?php echo htmlspecialchars($dept['department_name']); ?>
                                </option>
                            <?php endforeach; ?>
                        </select>
                        <input type="date" name="date" value="<?php echo htmlspecialchars($data['date'] ?? ''); ?>" onchange="this.form.submit()"
                            class="border border-gray-300 rounded-lg px-3 py-2 text-sm text-gray-700 focus:outline-none focus:ring-2 focus:ring-yellow-400">
                        <?php if ($data['department_id'] || $data['date']): ?>
                            <a href="?" class="inline-flex items-center px-3 py-2 bg-white border border-gray-300 rounded-lg text-sm text-gray-700 hover:bg-gray-50 focus:outline-none focus:ring-2 focus:ring-yellow-400">
                                <i class="fas fa-times mr-1"></i> Clear
                            </a>
                        <?php endif; ?>
                    </form>
                </div>
            </div>
        </div>

        <!-- Stats Cards -->
        <div class="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-6 mb-8">
            <!-- Current Semester Card -->
            <div class="bg-yellow-100 rounded-xl shadow-md p-6 text-gray-900 animate-fade-in">
                <div class="flex items-center justify-between">
                    <div>
                        <p class="text-sm font-medium text-yellow-800">Current Semester</p>
                        <p class="text-xl font-bold"><?php echo htmlspecialchars($data['current_semester']['semester_name'] ?? 'Not Set'); ?></p>
                        <p class="text-sm text-yellow-700 mt-1"><?php echo htmlspecialchars($data['current_semester']['academic_year'] ?? ''); ?></p>
                    </div>
                    <div class="w-12 h-12 bg-yellow-200 rounded-lg flex items-center justify-center">
                        <i class="fas fa-calendar-alt text-yellow-600"></i>
                    </div>
                </div>
            </div>

            <!-- Total Activities -->
            <div class="bg-white rounded-xl shadow-md border border-gray-200 p-6 animate-fade-in" style="animation-delay: 0.1s">
                <div class="flex items-center justify-between">
                    <div>
                        <p class="text-sm font-medium text-gray-600">Total Activities</p>
                        <p class="text-2xl font-bold text-gray-900" id="totalActivities"><?php echo count($data['activities']); ?></p>
                        <p class="text-xs text-gray-500 mt-1">This semester</p>
                    </div>
                    <div class="w-12 h-12 bg-gray-100 rounded-lg flex items-center justify-center">
                        <i class="fas fa-chart-bar text-gray-600"></i>
                    </div>
                </div>
            </div>

            <!-- Today's Activities -->
            <div class="bg-white rounded-xl shadow-md border border-gray-200 p-6 animate-fade-in" style="animation-delay: 0.2s">
                <div class="flex items-center justify-between">
                    <div>
                        <p class="text-sm font-medium text-gray-600">Today's Activities</p>
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
                    <div class="w-12 h-12 bg-gray-100 rounded-lg flex items-center justify-center">
                        <i class="fas fa-calendar-day text-gray-600"></i>
                    </div>
                </div>
            </div>

            <!-- Active Departments -->
            <div class="bg-white rounded-xl shadow-md border border-gray-200 p-6 animate-fade-in" style="animation-delay: 0.3s">
                <div class="flex items-center justify-between">
                    <div>
                        <p class="text-sm font-medium text-gray-600">Active Departments</p>
                        <p class="text-2xl font-bold text-gray-900" id="activeDepartments">
                            <?php
                            $activeDepts = array_unique(array_column($data['activities'], 'department_name'));
                            echo count($activeDepts);
                            ?>
                        </p>
                        <p class="text-xs text-gray-500 mt-1">With activities</p>
                    </div>
                    <div class="w-12 h-12 bg-gray-100 rounded-lg flex items-center justify-center">
                        <i class="fas fa-building text-gray-600"></i>
                    </div>
                </div>
            </div>
        </div>

        <div class="grid grid-cols-1 lg:grid-cols-3 gap-8">
            <!-- Activity Feed -->
            <div class="lg:col-span-2">
                <div class="bg-white rounded-xl shadow-md border border-gray-200">
                    <div class="p-6 border-b border-gray-200">
                        <div class="flex items-center justify-between">
                            <div class="flex items-center gap-3">
                                <div class="w-8 h-8 bg-yellow-100 rounded-lg flex items-center justify-center">
                                    <i class="fas fa-stream text-yellow-600"></i>
                                </div>
                                <h3 class="text-lg font-semibold text-gray-900">Recent Activities</h3>
                            </div>
                            <div class="flex items-center gap-2">
                                <button id="refreshBtn" class="inline-flex items-center px-3 py-1.5 bg-white border border-gray-300 rounded-lg text-sm font-medium text-gray-700 hover:bg-gray-50 focus:outline-none focus:ring-2 focus:ring-yellow-400 transition-all duration-200">
                                    <i class="fas fa-sync-alt mr-1.5"></i> Refresh
                                </button>
                                <div class="flex items-center gap-1">
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
                                    <h3 class="text-lg font-medium text-gray-900">No Activities Yet</h3>
                                    <p class="text-gray-500">Activity data will appear here when available</p>
                                </div>
                            <?php else: ?>
                                <?php foreach (array_slice($data['activities'], 0, 10) as $activity): ?>
                                    <div class="activity-item flex items-start gap-3 p-4 rounded-lg border border-gray-200 hover:border-yellow-300 hover:bg-yellow-50 animate-fade-in">
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
                                                <span class="text-gray-400"> (<?php echo htmlspecialchars($activity['department_name']); ?>, <?php echo htmlspecialchars($activity['college_name']); ?>)</span>
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
                                <button id="loadMoreBtn" class="inline-flex items-center px-4 py-2 bg-white border border-gray-300 rounded-lg text-sm font-medium text-gray-700 hover:bg-gray-50 focus:outline-none focus:ring-2 focus:ring-yellow-400 transition-all duration-200">
                                    <i class="fas fa-chevron-down mr-2"></i> Load More Activities
                                </button>
                            </div>
                        <?php endif; ?>
                    </div>
                </div>
            </div>

            <!-- Sidebar -->
            <div class="lg:col-span-1 space-y-6">
                <!-- Activity Chart -->
                <div class="bg-white rounded-xl shadow-md border border-gray-200 p-6">
                    <div class="flex items-center justify-between mb-4">
                        <h3 class="text-lg font-semibold text-gray-900">Activity Trends</h3>
                        <div class="flex items-center gap-2">
                            <div class="w-2 h-2 bg-yellow-400 rounded-full"></div>
                            <span class="text-xs text-gray-600">Last 7 days</span>
                        </div>
                    </div>
                    <div class="relative h-48">
                        <canvas id="activityChart"></canvas>
                    </div>
                </div>

                <!-- Quick Stats -->
                <div class="bg-white rounded-xl shadow-md border border-gray-200 p-6">
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
                <div class="bg-white rounded-xl shadow-md border border-gray-200 p-6">
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
                                <div class="flex items-center gap-2">
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
        document.addEventListener('DOMContentLoaded', function() {
            initActivityChart();

            let refreshInterval;
            startAutoRefresh();

            document.getElementById('refreshBtn').addEventListener('click', refreshActivities);

            const loadMoreBtn = document.getElementById('loadMoreBtn');
            if (loadMoreBtn) {
                loadMoreBtn.addEventListener('click', function() {
                    const currentDepartmentId = '<?php echo $data['department_id'] ?? ""; ?>';
                    const currentDate = '<?php echo $data['date'] ?? ""; ?>';
                    const currentOffset = document.querySelectorAll('#activityFeed .activity-item').length;

                    loadMoreBtn.innerHTML = '<i class="fas fa-spinner fa-spin mr-2"></i>Loading...';
                    loadMoreBtn.disabled = true;

                    fetch('/dean/activities/load-more', {
                            method: 'POST',
                            headers: {
                                'Content-Type': 'application/x-www-form-urlencoded'
                            },
                            body: new URLSearchParams({
                                offset: currentOffset,
                                department_id: currentDepartmentId,
                                date: currentDate
                            })
                        })
                        .then(response => response.ok ? response.json() : Promise.reject(new Error('Network response was not ok')))
                        .then(data => {
                            if (data.success && data.activities.length > 0) {
                                data.activities.forEach(activity => {
                                    const item = createActivityItem(activity);
                                    document.getElementById('activityFeed').appendChild(item);
                                });
                                if (!data.hasMore) loadMoreBtn.style.display = 'none';
                            } else {
                                loadMoreBtn.style.display = 'none';
                                showNotification('No more activities to load', 'info');
                            }
                        })
                        .catch(error => {
                            console.error('Load more error:', error);
                            showNotification('Failed to load more activities', 'error');
                        })
                        .finally(() => {
                            loadMoreBtn.innerHTML = '<i class="fas fa-chevron-down mr-2"></i>Load More Activities';
                            loadMoreBtn.disabled = false;
                        });
                });

                function createActivityItem(activity) {
                    const div = document.createElement('div');
                    div.className = 'activity-item flex items-start gap-3 p-4 rounded-lg border border-gray-200 hover:border-yellow-300 hover:bg-yellow-50 animate-fade-in';
                    div.innerHTML = `
                        <div class="flex-shrink-0">
                            <div class="w-8 h-8 rounded-full flex items-center justify-center ${getActivityIcon(activity.action_type).bg}">
                                <i class="${getActivityIcon(activity.action_type).icon} text-white text-sm"></i>
                            </div>
                        </div>
                        <div class="flex-1 min-w-0">
                            <div class="flex items-center justify-between">
                                <p class="text-sm font-medium text-gray-900">${activity.first_name} ${activity.last_name}</p>
                                <p class="text-xs text-gray-500">${timeAgo(activity.created_at)}</p>
                            </div>
                            <p class="text-sm text-gray-600 mt-1">${activity.action_description} 
                                <span class="text-gray-400">(${activity.department_name}, ${activity.college_name})</span>
                            </p>
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
                        bg: 'bg-gray-600'
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
                const time = new Date().getTime() - new Date(datetime).getTime();
                const seconds = Math.floor(time / 1000);
                const minutes = Math.floor(seconds / 60);
                const hours = Math.floor(minutes / 60);
                const days = Math.floor(hours / 24);

                if (seconds < 60) return 'just now';
                if (minutes < 60) return minutes + ' min ago';
                if (hours < 24) return hours + ' hr ago';
                if (days < 30) return days + ' days ago';

                return new Date(datetime).toLocaleDateString();
            }

            function initActivityChart() {
                const ctx = document.getElementById('activityChart');
                if (!ctx) return;

                const last30Days = [];
                const activityData = [];

                for (let i = 29; i >= 0; i--) {
                    const date = new Date();
                    date.setDate(date.getDate() - i);
                    last30Days.push(date.getDate() + '/' + (date.getMonth() + 1));
                    const dayActivities = <?php echo json_encode($data['activities']); ?>.filter(activity =>
                        new Date(activity.created_at).toDateString() === date.toDateString()
                    ).length;
                    activityData.push(dayActivities);
                }

                new Chart(ctx, {
                    type: 'line',
                    data: {
                        labels: last30Days,
                        datasets: [{
                            label: 'Activities - <?php echo $data['current_semester_display']; ?>',
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
                            },
                            tooltip: {
                                callbacks: {
                                    title: context => new Date().setDate(new Date().getDate() - (29 - context[0].dataIndex)).toLocaleDateString('en-US', {
                                        weekday: 'long',
                                        year: 'numeric',
                                        month: 'long',
                                        day: 'numeric'
                                    })
                                }
                            }
                        },
                        scales: {
                            y: {
                                beginAtZero: true,
                                grid: {
                                    color: '#e5e7eb'
                                },
                                ticks: {
                                    color: '#4B4B4B'
                                }
                            },
                            x: {
                                grid: {
                                    display: false
                                },
                                ticks: {
                                    color: '#4B4B4B'
                                }
                            }
                        }
                    }
                });
            }

            function refreshActivities() {
                const refreshBtn = document.getElementById('refreshBtn');
                const icon = refreshBtn.querySelector('i');
                icon.classList.add('fa-spin');
                refreshBtn.disabled = true;

                setTimeout(() => {
                    icon.classList.remove('fa-spin');
                    refreshBtn.disabled = false;
                    showNotification('Activities refreshed successfully', 'success');
                }, 1000);
            }

            function startAutoRefresh() {
                refreshInterval = setInterval(() => console.log('Auto-refreshing activities...'), 30000);
            }

            function showNotification(message, type = 'info') {
                const notification = document.createElement('div');
                let bgColor, icon;
                switch (type) {
                    case 'success':
                        bgColor = 'bg-green-100 border-green-500 text-green-700';
                        icon = 'fa-check-circle';
                        break;
                    case 'error':
                        bgColor = 'bg-red-100 border-red-500 text-red-700';
                        icon = 'fa-exclamation-circle';
                        break;
                    case 'warning':
                        bgColor = 'bg-yellow-100 border-yellow-500 text-yellow-700';
                        icon = 'fa-exclamation-triangle';
                        break;
                    default:
                        bgColor = 'bg-blue-100 border-blue-500 text-blue-700';
                        icon = 'fa-info-circle';
                }
                notification.className = `fixed top-4 right-4 z-50 p-4 border-l-4 ${bgColor} rounded shadow-lg animate-slide-up`;
                notification.innerHTML = `<div class="flex items-center"><i class="fas ${icon} mr-2"></i><span>${message}</span></div>`;
                document.body.appendChild(notification);
                setTimeout(() => notification.remove(), 3000);
            }

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
function getActivityIcon($type)
{
    $icons = [
        'login' => ['icon' => 'fas fa-sign-in-alt', 'bg' => 'bg-green-500'],
        'logout' => ['icon' => 'fas fa-sign-out-alt', 'bg' => 'bg-red-500'],
        'schedule' => ['icon' => 'fas fa-calendar-alt', 'bg' => 'bg-blue-500'],
        'update' => ['icon' => 'fas fa-edit', 'bg' => 'bg-yellow-500'],
        'delete' => ['icon' => 'fas fa-trash', 'bg' => 'bg-red-500'],
        'create' => ['icon' => 'fas fa-plus', 'bg' => 'bg-green-500'],
        'system' => ['icon' => 'fas fa-cog', 'bg' => 'bg-gray-600'],
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