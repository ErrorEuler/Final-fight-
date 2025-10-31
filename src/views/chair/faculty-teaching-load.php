<?php
ob_start();
?>

<style>
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
</style>

<div class="min-h-screen bg-gray-50">
    <!-- Header -->
    <div class="bg-gradient-to-r from-yellow-500 to-yellow-600 text-white shadow-lg">
        <div class="container mx-auto px-4 py-6">
            <div class="flex flex-col md:flex-row justify-between items-start md:items-center">
                <div>
                    <h1 class="text-2xl md:text-3xl font-bold">Department Teaching Load</h1>
                    <p class="text-blue-100 mt-2"><?php echo htmlspecialchars($departmentName ?? 'Department'); ?></p>
                    <p class="text-blue-100 text-sm"><?php echo htmlspecialchars($collegeName ?? 'College'); ?></p>
                    <p class="text-blue-100 text-sm"><?php echo htmlspecialchars($semesterName ?? 'Current Semester'); ?></p>
                </div>
                <div class="mt-4 md:mt-0 flex flex-wrap gap-2">
                    <span class="bg-yellow-400 text-yellow-900 px-3 py-1 rounded-full text-sm font-medium">
                        <i class="fas fa-users mr-1"></i>
                        <?php echo $departmentTotals['total_faculty'] ?? 0; ?> Faculty
                    </span>
                    <span class="bg-yellow-700 text-blue-100 px-3 py-1 rounded-full text-sm font-medium">
                        <i class="fas fa-chalkboard-teacher mr-1"></i>
                        Department Overview
                    </span>
                </div>
            </div>
        </div>
    </div>

    <!-- Department Summary Cards -->
    <div class="container mx-auto px-4 py-6">
        <div class="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6 mb-8">
            <!-- Total Faculty -->
            <div class="bg-white rounded-lg shadow-md p-6 border-l-4 border-blue-500">
                <div class="flex items-center justify-between">
                    <div>
                        <p class="text-gray-500 text-sm font-medium">Total Faculty</p>
                        <h3 class="text-3xl font-bold text-gray-800 mt-2"><?php echo $departmentTotals['total_faculty'] ?? 0; ?></h3>
                    </div>
                    <div class="bg-blue-100 rounded-full p-3">
                        <i class="fas fa-users text-blue-500 text-2xl"></i>
                    </div>
                </div>
            </div>

            <!-- Total Teaching Load -->
            <div class="bg-white rounded-lg shadow-md p-6 border-l-4 border-green-500">
                <div class="flex items-center justify-between">
                    <div>
                        <p class="text-gray-500 text-sm font-medium">Total Teaching Load</p>
                        <h3 class="text-3xl font-bold text-gray-800 mt-2"><?php echo number_format($departmentTotals['total_teaching_load'] ?? 0, 1); ?> hrs</h3>
                    </div>
                    <div class="bg-green-100 rounded-full p-3">
                        <i class="fas fa-book-open text-green-500 text-2xl"></i>
                    </div>
                </div>
            </div>

            <!-- Total Working Load -->
            <div class="bg-white rounded-lg shadow-md p-6 border-l-4 border-purple-500">
                <div class="flex items-center justify-between">
                    <div>
                        <p class="text-gray-500 text-sm font-medium">Total Working Load</p>
                        <h3 class="text-3xl font-bold text-gray-800 mt-2"><?php echo number_format($departmentTotals['total_working_load'] ?? 0, 1); ?> hrs</h3>
                    </div>
                    <div class="bg-purple-100 rounded-full p-3">
                        <i class="fas fa-briefcase text-purple-500 text-2xl"></i>
                    </div>
                </div>
            </div>

            <!-- Excess Hours -->
            <div class="bg-white rounded-lg shadow-md p-6 border-l-4 border-orange-500">
                <div class="flex items-center justify-between">
                    <div>
                        <p class="text-gray-500 text-sm font-medium">Total Excess Hours</p>
                        <h3 class="text-3xl font-bold text-gray-800 mt-2"><?php echo number_format($departmentTotals['total_excess_hours'] ?? 0, 1); ?> hrs</h3>
                    </div>
                    <div class="bg-orange-100 rounded-full p-3">
                        <i class="fas fa-exclamation-triangle text-orange-500 text-2xl"></i>
                    </div>
                </div>
            </div>
        </div>

        <!-- Load Distribution Summary -->
        <div class="bg-white rounded-lg shadow-md p-6 mb-8">
            <h3 class="text-lg font-semibold text-gray-900 mb-4">Load Distribution</h3>
            <div class="grid grid-cols-2 md:grid-cols-4 gap-4">
                <?php
                $loadStats = [
                    'Normal Load' => 0,
                    'Underload' => 0,
                    'Overload' => 0,
                    'No Load' => 0
                ];

                foreach ($facultyTeachingLoads ?? [] as $faculty) {
                    $loadStats[$faculty['load_status']]++;
                }

                $loadColors = [
                    'Normal Load' => 'bg-green-500',
                    'Underload' => 'bg-yellow-500',
                    'Overload' => 'bg-red-500',
                    'No Load' => 'bg-gray-500'
                ];

                foreach ($loadStats as $status => $count):
                ?>
                    <div class="text-center p-4 bg-gray-50 rounded-lg">
                        <div class="text-2xl font-bold text-gray-900"><?php echo $count; ?></div>
                        <div class="text-sm text-gray-600 mt-1"><?php echo $status; ?></div>
                        <div class="w-8 h-1 mx-auto mt-2 rounded-full <?php echo $loadColors[$status]; ?>"></div>
                    </div>
                <?php endforeach; ?>
            </div>
        </div>

        <!-- Faculty Teaching Load Table -->
        <div class="bg-white rounded-lg shadow-md overflow-hidden">
            <div class="px-6 py-4 border-b border-gray-200">
                <div class="flex flex-col md:flex-row justify-between items-start md:items-center">
                    <h2 class="text-xl font-semibold text-gray-900">Faculty Teaching Load Details</h2>
                    <div class="mt-2 md:mt-0 flex space-x-2">
                        <button onclick="exportToExcel()" class="bg-green-500 hover:bg-green-600 text-white px-4 py-2 rounded-lg text-sm font-medium transition-colors">
                            <i class="fas fa-file-excel mr-2"></i>Export Excel
                        </button>
                        <button onclick="window.print()" class="bg-blue-500 hover:bg-blue-600 text-white px-4 py-2 rounded-lg text-sm font-medium transition-colors">
                            <i class="fas fa-print mr-2"></i>Print
                        </button>
                    </div>
                </div>
            </div>

            <div class="overflow-x-auto">
                <table class="min-w-full divide-y divide-gray-200" id="teachingLoadTable">
                    <thead class="bg-gray-50">
                        <tr>
                            <th class="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Faculty Member</th>
                            <th class="px-4 py-3 text-center text-xs font-medium text-gray-500 uppercase tracking-wider">Rank/Type</th>
                            <th class="px-4 py-3 text-center text-xs font-medium text-gray-500 uppercase tracking-wider">Courses</th>
                            <th class="px-4 py-3 text-center text-xs font-medium text-gray-500 uppercase tracking-wider">Lecture Hrs</th>
                            <th class="px-4 py-3 text-center text-xs font-medium text-gray-500 uppercase tracking-wider">Lab Hrs</th>
                            <th class="px-4 py-3 text-center text-xs font-medium text-gray-500 uppercase tracking-wider">Teaching Load</th>
                            <th class="px-4 py-3 text-center text-xs font-medium text-gray-500 uppercase tracking-wider">Total Load</th>
                            <th class="px-4 py-3 text-center text-xs font-medium text-gray-500 uppercase tracking-wider">Status</th>
                            <th class="px-4 py-3 text-center text-xs font-medium text-gray-500 uppercase tracking-wider">Actions</th>
                        </tr>
                    </thead>
                    <tbody class="bg-white divide-y divide-gray-200">
                        <?php if (!empty($facultyTeachingLoads)): ?>
                            <?php foreach ($facultyTeachingLoads as $faculty): ?>
                                <tr class="hover:bg-gray-50 transition-colors">
                                    <td class="px-4 py-3 whitespace-nowrap">
                                        <div class="flex items-center">
                                            <div class="flex-shrink-0 h-10 w-10 bg-blue-100 rounded-full flex items-center justify-center">
                                                <i class="fas fa-user text-blue-600"></i>
                                            </div>
                                            <div class="ml-4">
                                                <div class="text-sm font-medium text-gray-900">
                                                    <?php echo htmlspecialchars($faculty['faculty_name']); ?>
                                                </div>
                                                <div class="text-sm text-gray-500">
                                                    <?php echo htmlspecialchars($faculty['designation']); ?>
                                                </div>
                                            </div>
                                        </div>
                                    </td>
                                    <td class="px-4 py-3 whitespace-nowrap text-center">
                                        <div class="text-sm text-gray-900"><?php echo htmlspecialchars($faculty['academic_rank']); ?></div>
                                        <div class="text-xs text-gray-500"><?php echo htmlspecialchars($faculty['employment_type']); ?></div>
                                    </td>
                                    <td class="px-4 py-3 whitespace-nowrap text-center">
                                        <span class="inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium bg-blue-100 text-blue-800">
                                            <?php echo $faculty['total_preparations']; ?> courses
                                        </span>
                                    </td>
                                    <td class="px-4 py-3 whitespace-nowrap text-center text-sm text-gray-900">
                                        <?php echo number_format($faculty['lecture_hours'], 1); ?>
                                    </td>
                                    <td class="px-4 py-3 whitespace-nowrap text-center text-sm text-gray-900">
                                        <?php echo number_format($faculty['lab_hours'], 1); ?>
                                    </td>
                                    <td class="px-4 py-3 whitespace-nowrap text-center text-sm font-medium text-gray-900">
                                        <?php echo number_format($faculty['actual_teaching_load'], 1); ?>
                                    </td>
                                    <td class="px-4 py-3 whitespace-nowrap text-center">
                                        <span class="text-sm font-semibold <?php echo $faculty['total_working_load'] > 24 ? 'text-red-600' : 'text-green-600'; ?>">
                                            <?php echo number_format($faculty['total_working_load'], 1); ?>
                                        </span>
                                    </td>
                                    <td class="px-4 py-3 whitespace-nowrap text-center">
                                        <?php
                                        $statusConfig = [
                                            'Normal Load' => ['color' => 'green', 'icon' => 'check-circle'],
                                            'Underload' => ['color' => 'yellow', 'icon' => 'exclamation-circle'],
                                            'Overload' => ['color' => 'red', 'icon' => 'exclamation-triangle'],
                                            'No Load' => ['color' => 'gray', 'icon' => 'minus-circle']
                                        ];
                                        $status = $faculty['load_status'];
                                        $config = $statusConfig[$status] ?? $statusConfig['Normal Load'];
                                        ?>
                                        <span class="inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium bg-<?php echo $config['color']; ?>-100 text-<?php echo $config['color']; ?>-800">
                                            <i class="fas fa-<?php echo $config['icon']; ?> mr-1"></i>
                                            <?php echo $status; ?>
                                        </span>
                                    </td>
                                    <td class="px-4 py-3 whitespace-nowrap text-center text-sm font-medium">
                                        <button onclick="viewFacultySchedule(<?php echo $faculty['faculty_id']; ?>)"
                                            class="text-blue-600 hover:text-blue-900" title="View Schedule">
                                            <i class="fas fa-calendar-alt"></i>
                                        </button>
                                    </td>
                                </tr>
                            <?php endforeach; ?>
                        <?php else: ?>
                            <tr>
                                <td colspan="9" class="px-6 py-8 text-center text-gray-500">
                                    <i class="fas fa-users text-4xl mb-3 text-gray-300"></i>
                                    <p class="text-lg">No faculty teaching load data available</p>
                                    <p class="text-sm mt-1">No schedules found for the current semester.</p>
                                </td>
                            </tr>
                        <?php endif; ?>
                    </tbody>
                </table>
            </div>
        </div>

        <!-- Faculty Schedule Details Modal -->
        <div id="scheduleModal" class="fixed inset-0 bg-black/70 backdrop-blur-sm bg-opacity-50 overflow-y-auto h-full w-full hidden z-50">
            <div class="relative top-20 mx-auto p-5 border w-11/12 md:w-3/4 lg:w-2/3 shadow-lg rounded-md bg-white max-h-[80vh] overflow-y-auto">
                <div class="mt-3">
                    <div class="flex justify-between items-center pb-3 border-b">
                        <h3 class="text-xl font-semibold text-gray-900" id="modalTitle">Faculty Schedule</h3>
                        <button onclick="closeModal()" class="text-gray-400 hover:text-gray-600">
                            <i class="fas fa-times text-2xl"></i>
                        </button>
                    </div>

                    <div class="mt-4" id="modalContent">
                        <!-- Schedule content will be loaded here -->
                    </div>

                    <div class="flex justify-end mt-6 pt-4 border-t">
                        <button onclick="closeModal()" class="bg-gray-500 hover:bg-gray-600 text-white px-4 py-2 rounded-lg text-sm font-medium transition-colors">
                            Close
                        </button>
                    </div>
                </div>
            </div>
        </div>
    </div>
</div>

<!-- JavaScript -->
<script>
    function viewFacultySchedule(facultyId) {
        // Show loading in modal
        document.getElementById('modalTitle').textContent = 'Loading Schedule...';
        document.getElementById('modalContent').innerHTML = `
            <div class="flex justify-center items-center py-8">
                <div class="animate-spin rounded-full h-12 w-12 border-b-2 border-blue-500"></div>
            </div>
        `;
        document.getElementById('scheduleModal').classList.remove('hidden');

        // Fetch faculty schedule data
        fetch(`/chair/api/faculty-schedule?facultyId=${facultyId}`)
            .then(response => response.json())
            .then(data => {
                if (data.success) {
                    displayFacultySchedule(data.faculty, data.schedules);
                } else {
                    document.getElementById('modalContent').innerHTML = `
                        <div class="text-center py-8 text-gray-500">
                            <i class="fas fa-exclamation-triangle text-4xl mb-3 text-gray-300"></i>
                            <p class="text-lg">Error loading schedule</p>
                            <p class="text-sm mt-1">${data.message || 'Unable to load faculty schedule'}</p>
                        </div>
                    `;
                }
            })
            .catch(error => {
                console.error('Error:', error);
                document.getElementById('modalContent').innerHTML = `
                    <div class="text-center py-8 text-gray-500">
                        <i class="fas fa-exclamation-triangle text-4xl mb-3 text-gray-300"></i>
                        <p class="text-lg">Error loading schedule</p>
                        <p class="text-sm mt-1">Please try again later</p>
                    </div>
                `;
            });
    }

    function displayFacultySchedule(faculty, schedules) {
        document.getElementById('modalTitle').textContent = `Schedule - ${faculty.faculty_name}`;

        if (schedules.length === 0) {
            document.getElementById('modalContent').innerHTML = `
            <div class="text-center py-8 text-gray-500">
                <i class="fas fa-calendar-times text-4xl mb-3 text-gray-300"></i>
                <p class="text-lg">No schedules found</p>
                <p class="text-sm mt-1">This faculty member has no assigned schedules for the current semester.</p>
            </div>
        `;
            return;
        }

        let scheduleHTML = `
        <div class="mb-4 p-4 bg-gray-50 rounded-lg">
            <div class="grid grid-cols-2 md:grid-cols-4 gap-4 text-sm">
                <div>
                    <span class="font-semibold">Department:</span>
                    <p>${faculty.department_name}</p>
                </div>
                <div>
                    <span class="font-semibold">Employment Type:</span>
                    <p>${faculty.employment_type}</p>
                </div>
                <div>
                    <span class="font-semibold">Academic Rank:</span>
                    <p>${faculty.academic_rank}</p>
                </div>
                <div>
                    <span class="font-semibold">Total Courses:</span>
                    <p>${faculty.total_preparations}</p>
                </div>
            </div>
        </div>
        
        <div class="overflow-x-auto">
            <table class="min-w-full divide-y divide-gray-200">
                <thead class="bg-gray-50">
                    <tr>
                        <th class="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase">Course</th>
                        <th class="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase">Section</th>
                        <th class="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase">Days</th>
                        <th class="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase">Time</th>
                        <th class="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase">Room</th>
                        <th class="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase">Type</th>
                        <th class="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase">Hours</th>
                        <th class="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase">Status</th>
                    </tr>
                </thead>
                <tbody class="bg-white divide-y divide-gray-200">
        `;

        schedules.forEach(schedule => {
            const formattedDays = formatScheduleDays(schedule.day_of_week);

            // Status badge with different colors
            let statusBadge = '';
            let statusClass = '';

            switch (schedule.status) {
                case 'Approved':
                    statusClass = 'bg-green-100 text-green-800';
                    statusBadge = '<i class="fas fa-check-circle mr-1"></i>Approved';
                    break;
                case 'Di_Approved':
                    statusClass = 'bg-blue-100 text-blue-800';
                    statusBadge = '<i class="fas fa-check mr-1"></i>DI Approved';
                    break;
                case 'Dean_Approved':
                    statusClass = 'bg-indigo-100 text-indigo-800';
                    statusBadge = '<i class="fas fa-check mr-1"></i>Dean Approved';
                    break;
                case 'Pending':
                    statusClass = 'bg-yellow-100 text-yellow-800';
                    statusBadge = '<i class="fas fa-clock mr-1"></i>Pending';
                    break;
                case 'Rejected':
                    statusClass = 'bg-red-100 text-red-800';
                    statusBadge = '<i class="fas fa-times-circle mr-1"></i>Rejected';
                    break;
                default:
                    statusClass = 'bg-gray-100 text-gray-800';
                    statusBadge = schedule.status;
            }

            scheduleHTML += `
        <tr class="hover:bg-gray-50">
            <td class="px-4 py-3 whitespace-nowrap">
                <div class="text-sm font-medium text-gray-900">${schedule.course_code}</div>
                <div class="text-xs text-gray-500">${schedule.course_name}</div>
            </td>
            <td class="px-4 py-3 whitespace-nowrap text-sm text-gray-900">
                ${schedule.section_name}
            </td>
            <td class="px-4 py-3 whitespace-nowrap text-sm text-gray-900">
                ${formattedDays}
            </td>
            <td class="px-4 py-3 whitespace-nowrap text-sm text-gray-900">
                ${schedule.start_time} - ${schedule.end_time}
            </td>
            <td class="px-4 py-3 whitespace-nowrap text-sm text-gray-900">
                ${schedule.room_name || 'TBA'}
            </td>
            <td class="px-4 py-3 whitespace-nowrap">
                <span class="inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium ${
                    schedule.component_type === 'lecture' ? 'bg-blue-100 text-blue-800' : 'bg-green-100 text-green-800'
                }">
                    ${schedule.component_type}
                </span>
            </td>
            <td class="px-4 py-3 whitespace-nowrap text-sm text-gray-900">
                ${schedule.duration_hours}
            </td>
            <td class="px-4 py-3 whitespace-nowrap">
                <span class="inline-flex items-center px-2 py-0.5 rounded-full text-xs font-medium ${statusClass}">
                    ${statusBadge}
                </span>
            </td>
        </tr>
        `;
        });

        scheduleHTML += `
                </tbody>
            </table>
        </div>
    `;

        document.getElementById('modalContent').innerHTML = scheduleHTML;
    }

    function closeModal() {
        document.getElementById('scheduleModal').classList.add('hidden');
    }

    function formatScheduleDays(daysString) {
        if (!daysString) return 'TBD';

        const days = daysString.split(', ');

        // Day abbreviation map
        const dayMap = {
            'Monday': 'M',
            'Tuesday': 'T',
            'Wednesday': 'W',
            'Thursday': 'Th',
            'Friday': 'F',
            'Saturday': 'Sat',
            'Sunday': 'Sun'
        };

        // Day order for sorting
        const dayOrder = {
            'Monday': 1,
            'Tuesday': 2,
            'Wednesday': 3,
            'Thursday': 4,
            'Friday': 5,
            'Saturday': 6,
            'Sunday': 7
        };

        // Sort days by weekday order
        const sortedDays = days.sort((a, b) => dayOrder[a] - dayOrder[b]);

        // Special handling for common patterns
        const dayString = sortedDays.join(',');

        // Check for common patterns first
        const commonPatterns = {
            'Monday,Wednesday,Friday': 'MWF',
            'Tuesday,Thursday': 'TTh',
            'Monday,Wednesday': 'MW',
            'Monday,Tuesday,Wednesday,Thursday,Friday': 'MTWThF',
            'Saturday': 'Sat',
            'Sunday': 'Sun'
        };

        if (commonPatterns[dayString]) {
            return commonPatterns[dayString];
        }

        // For other combinations, just concatenate abbreviations
        return sortedDays.map(day => dayMap[day] || day).join('');
    }

    function exportToExcel() {
        const table = document.getElementById('teachingLoadTable');
        const html = table.outerHTML;
        const url = 'data:application/vnd.ms-excel;charset=utf-8,' + encodeURIComponent(html);
        const link = document.createElement('a');
        link.download = 'department_teaching_load_' + new Date().toISOString().split('T')[0] + '.xls';
        link.href = url;
        link.click();
    }

    // Close modal when clicking outside
    document.getElementById('scheduleModal').addEventListener('click', function(e) {
        if (e.target.id === 'scheduleModal') {
            closeModal();
        }
    });

    document.addEventListener('DOMContentLoaded', function() {
        console.log('Department Teaching Load page loaded');
    });
</script>

<?php
$content = ob_get_clean();
require_once __DIR__ . '/layout.php';
?>