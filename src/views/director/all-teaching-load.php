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

    /* Filter animations */
    .filter-transition {
        transition: all 0.3s ease-in-out;
    }

    .filter-highlight {
        animation: highlight 2s ease-in-out;
    }

    @keyframes highlight {
        0% {
            background-color: transparent;
        }

        50% {
            background-color: #fef3c7;
        }

        100% {
            background-color: transparent;
        }
    }

    @media print {
        .bg-gradient-to-r {
            background: #f59e0b !important;
        }

        .shadow-md {
            box-shadow: none !important;
        }

        button {
            display: none !important;
        }

        #scheduleModal {
            display: none !important;
        }

        /* Hide filters in print */
        .flex.flex-col.sm\\:flex-row.gap-4 {
            display: none !important;
        }
    }
</style>

<div class="min-h-screen bg-gray-50">
    <!-- Header -->
    <div class="bg-gradient-to-r from-yellow-500 to-yellow-600 text-white shadow-lg">
        <div class="container mx-auto px-4 py-6">
            <div class="flex flex-col md:flex-row justify-between items-start md:items-center">
                <div>
                    <h1 class="text-2xl md:text-3xl font-bold">College Teaching Load</h1>
                    <p class="text-yellow-100 mt-2"><?php echo htmlspecialchars($collegeName ?? 'College'); ?></p>
                    <p class="text-yellow-100 text-sm"><?php echo htmlspecialchars($semesterName ?? 'Current Semester'); ?></p>
                </div>
                <div class="mt-4 md:mt-0 flex flex-wrap gap-2">
                    <span class="bg-yellow-400 text-yellow-900 px-3 py-1 rounded-full text-sm font-medium">
                        <i class="fas fa-users mr-1"></i>
                        <?php echo $collegeTotals['total_faculty'] ?? 0; ?> Faculty
                    </span>
                    <span class="bg-yellow-700 text-yellow-100 px-3 py-1 rounded-full text-sm font-medium">
                        <i class="fas fa-chalkboard-teacher mr-1"></i>
                        College Overview
                    </span>
                </div>
            </div>
        </div>
    </div>

    <!-- College Summary Cards -->
    <div class="container mx-auto px-4 py-6">
        <div class="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6 mb-8">
            <!-- Total Faculty -->
            <div class="bg-white rounded-lg shadow-md p-6 border-l-4 border-yellow-500">
                <div class="flex items-center justify-between">
                    <div>
                        <p class="text-gray-500 text-sm font-medium">Total Faculty</p>
                        <h3 class="text-3xl font-bold text-gray-800 mt-2"><?php echo $collegeTotals['total_faculty'] ?? 0; ?></h3>
                    </div>
                    <div class="bg-yellow-100 rounded-full p-3">
                        <i class="fas fa-users text-yellow-500 text-2xl"></i>
                    </div>
                </div>
            </div>

            <!-- Total Teaching Load -->
            <div class="bg-white rounded-lg shadow-md p-6 border-l-4 border-green-500">
                <div class="flex items-center justify-between">
                    <div>
                        <p class="text-gray-500 text-sm font-medium">Total Teaching Load</p>
                        <h3 class="text-3xl font-bold text-gray-800 mt-2"><?php echo number_format($collegeTotals['total_teaching_load'] ?? 0, 1); ?> hrs</h3>
                    </div>
                    <div class="bg-green-100 rounded-full p-3">
                        <i class="fas fa-book-open text-green-500 text-2xl"></i>
                    </div>
                </div>
            </div>

            <!-- Total Working Load -->
            <div class="bg-white rounded-lg shadow-md p-6 border-l-4 border-blue-500">
                <div class="flex items-center justify-between">
                    <div>
                        <p class="text-gray-500 text-sm font-medium">Total Working Load</p>
                        <h3 class="text-3xl font-bold text-gray-800 mt-2"><?php echo number_format($collegeTotals['total_working_load'] ?? 0, 1); ?> hrs</h3>
                    </div>
                    <div class="bg-blue-100 rounded-full p-3">
                        <i class="fas fa-briefcase text-blue-500 text-2xl"></i>
                    </div>
                </div>
            </div>

            <!-- Excess Hours -->
            <div class="bg-white rounded-lg shadow-md p-6 border-l-4 border-orange-500">
                <div class="flex items-center justify-between">
                    <div>
                        <p class="text-gray-500 text-sm font-medium">Total Excess Hours</p>
                        <h3 class="text-3xl font-bold text-gray-800 mt-2"><?php echo number_format($collegeTotals['total_excess_hours'] ?? 0, 1); ?> hrs</h3>
                    </div>
                    <div class="bg-orange-100 rounded-full p-3">
                        <i class="fas fa-exclamation-triangle text-orange-500 text-2xl"></i>
                    </div>
                </div>
            </div>
        </div>

        <!-- Department Summary -->
        <div class="bg-white rounded-lg shadow-md p-6 mb-8">
            <h3 class="text-lg font-semibold text-gray-900 mb-4">Department Summary</h3>
            <div class="overflow-x-auto">
                <table class="min-w-full">
                    <thead>
                        <tr class="bg-gray-50">
                            <th class="px-4 py-2 text-left text-xs font-medium text-gray-500 uppercase">Department</th>
                            <th class="px-4 py-2 text-center text-xs font-medium text-gray-500 uppercase">Faculty</th>
                            <th class="px-4 py-2 text-center text-xs font-medium text-gray-500 uppercase">Avg Load</th>
                            <th class="px-4 py-2 text-center text-xs font-medium text-gray-500 uppercase">Overload</th>
                            <th class="px-4 py-2 text-center text-xs font-medium text-gray-500 uppercase">Underload</th>
                        </tr>
                    </thead>
                    <tbody class="divide-y divide-gray-200">
                        <?php
                        $deptStats = [];
                        foreach ($facultyTeachingLoads ?? [] as $faculty) {
                            $dept = $faculty['department_name'];
                            if (!isset($deptStats[$dept])) {
                                $deptStats[$dept] = [
                                    'faculty_count' => 0,
                                    'total_load' => 0,
                                    'overload_count' => 0,
                                    'underload_count' => 0
                                ];
                            }
                            $deptStats[$dept]['faculty_count']++;
                            $deptStats[$dept]['total_load'] += $faculty['total_working_load'];
                            if ($faculty['load_status'] === 'Overload') {
                                $deptStats[$dept]['overload_count']++;
                            }
                            if ($faculty['load_status'] === 'Underload') {
                                $deptStats[$dept]['underload_count']++;
                            }
                        }

                        foreach ($deptStats as $deptName => $stats):
                            $avgLoad = $stats['faculty_count'] > 0 ? $stats['total_load'] / $stats['faculty_count'] : 0;
                        ?>
                            <tr>
                                <td class="px-4 py-3 text-sm font-medium text-gray-900"><?php echo htmlspecialchars($deptName); ?></td>
                                <td class="px-4 py-3 text-sm text-gray-500 text-center"><?php echo $stats['faculty_count']; ?></td>
                                <td class="px-4 py-3 text-sm text-gray-500 text-center"><?php echo number_format($avgLoad, 1); ?> hrs</td>
                                <td class="px-4 py-3 text-sm text-center">
                                    <span class="inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium <?php echo $stats['overload_count'] > 0 ? 'bg-red-100 text-red-800' : 'bg-green-100 text-green-800'; ?>">
                                        <?php echo $stats['overload_count']; ?>
                                    </span>
                                </td>
                                <td class="px-4 py-3 text-sm text-center">
                                    <span class="inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium <?php echo $stats['underload_count'] > 0 ? 'bg-yellow-100 text-yellow-800' : 'bg-green-100 text-green-800'; ?>">
                                        <?php echo $stats['underload_count']; ?>
                                    </span>
                                </td>
                            </tr>
                        <?php endforeach; ?>
                    </tbody>
                </table>
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

                <!-- Filters Section -->
                <div class="mt-4 flex flex-col sm:flex-row gap-4 items-start sm:items-center">
                    <!-- College Filter -->
                    <div class="flex items-center space-x-2">
                        <label for="collegeFilter" class="text-sm font-medium text-gray-700 whitespace-nowrap">
                            <i class="fas fa-university mr-1"></i>College:
                        </label>
                        <select id="collegeFilter" onchange="filterByCollege()"
                            class="block w-full sm:w-48 px-3 py-2 border border-gray-300 rounded-md shadow-sm focus:outline-none focus:ring-2 focus:ring-purple-500 focus:border-purple-500 text-sm">
                            <option value="all" <?php echo ($selectedCollege ?? 'all') === 'all' ? 'selected' : ''; ?>>All Colleges</option>
                            <?php foreach ($colleges ?? [] as $col): ?>
                                <option value="<?php echo $col['college_id']; ?>"
                                    <?php echo ($selectedCollege ?? 'all') == $col['college_id'] ? 'selected' : ''; ?>>
                                    <?php echo htmlspecialchars($col['college_name']); ?>
                                </option>
                            <?php endforeach; ?>
                        </select>
                    </div>

                    <!-- Department Filter -->
                    <div class="flex items-center space-x-2">
                        <label for="departmentFilter" class="text-sm font-medium text-gray-700 whitespace-nowrap">
                            <i class="fas fa-filter mr-1"></i>Department:
                        </label>
                        <select id="departmentFilter" onchange="filterByDepartment()"
                            class="block w-full sm:w-64 px-3 py-2 border border-gray-300 rounded-md shadow-sm focus:outline-none focus:ring-2 focus:ring-purple-500 focus:border-purple-500 text-sm">
                            <option value="all" <?php echo ($selectedDepartment ?? 'all') === 'all' ? 'selected' : ''; ?>>All Departments</option>
                            <?php foreach ($departments ?? [] as $dept): ?>
                                <option value="<?php echo $dept['department_id']; ?>"
                                    <?php echo ($selectedDepartment ?? 'all') == $dept['department_id'] ? 'selected' : ''; ?>>
                                    <?php echo htmlspecialchars($dept['department_name']); ?>
                                </option>
                            <?php endforeach; ?>
                        </select>
                    </div>

                    <!-- Active Filters Display -->
                    <div id="activeFilters" class="flex flex-wrap gap-2">
                        <?php if (($selectedCollege ?? 'all') !== 'all'): ?>
                            <?php
                            $selectedCollegeName = 'All Colleges';
                            foreach ($colleges ?? [] as $col) {
                                if ($col['college_id'] == $selectedCollege) {
                                    $selectedCollegeName = $col['college_name'];
                                    break;
                                }
                            }
                            ?>
                            <span class="inline-flex items-center px-3 py-1 rounded-full text-xs font-medium bg-purple-100 text-purple-800">
                                College: <?php echo htmlspecialchars($selectedCollegeName); ?>
                                <button onclick="clearCollegeFilter()" class="ml-1 text-purple-600 hover:text-purple-800">
                                    <i class="fas fa-times"></i>
                                </button>
                            </span>
                        <?php endif; ?>

                        <?php if (($selectedDepartment ?? 'all') !== 'all'): ?>
                            <?php
                            $selectedDeptName = 'All Departments';
                            foreach ($departments ?? [] as $dept) {
                                if ($dept['department_id'] == $selectedDepartment) {
                                    $selectedDeptName = $dept['department_name'];
                                    break;
                                }
                            }
                            ?>
                            <span class="inline-flex items-center px-3 py-1 rounded-full text-xs font-medium bg-purple-100 text-purple-800">
                                Department: <?php echo htmlspecialchars($selectedDeptName); ?>
                                <button onclick="clearDepartmentFilter()" class="ml-1 text-purple-600 hover:text-purple-800">
                                    <i class="fas fa-times"></i>
                                </button>
                            </span>
                        <?php endif; ?>
                    </div>

                    <!-- Results Count -->
                    <div class="text-sm text-gray-600 ml-auto">
                        Showing <?php echo count($facultyTeachingLoads); ?> faculty members
                    </div>
                </div>
            </div>

            <div class="overflow-x-auto">
                <table class="min-w-full divide-y divide-gray-200" id="teachingLoadTable">
                    <thead class="bg-gray-50">
                        <tr>
                            <th class="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Faculty Member</th>
                            <th class="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">College/Department</th>
                            <th class="px-4 py-3 text-center text-xs font-medium text-gray-500 uppercase tracking-wider">Rank/Type</th>
                            <th class="px-4 py-3 text-center text-xs font-medium text-gray-500 uppercase tracking-wider">Courses</th>
                            <th class="px-4 py-3 text-center text-xs font-medium text-gray-500 uppercase tracking-wider">Teaching Load</th>
                            <th class="px-4 py-3 text-center text-xs font-medium text-gray-500 uppercase tracking-wider">Total Load</th>
                            <th class="px-4 py-3 text-center text-xs font-medium text-gray-500 uppercase tracking-wider">Load Status</th>
                            <th class="px-4 py-3 text-center text-xs font-medium text-gray-500 uppercase tracking-wider">Approval Status</th>
                            <th class="px-4 py-3 text-center text-xs font-medium text-gray-500 uppercase tracking-wider" style="position:sticky; right:0; background:#fff; z-index:30;">Actions</th>
                        </tr>
                    </thead>
                    <tbody class="bg-white divide-y divide-gray-200">
                        <?php if (!empty($facultyTeachingLoads)): ?>
                            <?php foreach ($facultyTeachingLoads as $faculty): ?>
                                <tr class="hover:bg-gray-50 transition-colors">
                                    <td class="px-4 py-3 whitespace-nowrap">
                                        <div class="flex items-center">
                                            <div class="flex-shrink-0 h-10 w-10 bg-purple-100 rounded-full flex items-center justify-center">
                                                <i class="fas fa-user text-purple-600"></i>
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
                                    <td class="px-4 py-3 whitespace-nowrap">
                                        <div class="text-sm font-medium text-gray-900"><?php echo htmlspecialchars($faculty['college_name']); ?></div>
                                        <div class="text-sm text-gray-500"><?php echo htmlspecialchars($faculty['department_name']); ?></div>
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
                                    <td class="px-4 py-3 whitespace-nowrap text-center">
                                        <div class="text-xs mt-1 px-1" id="approval-status-<?php echo $faculty['faculty_id']; ?>">
                                            <span class="text-gray-500 animate-pulse">Loading...</span>
                                        </div>
                                    </td>
                                    <td class="px-4 py-3 whitespace-nowrap text-center text-sm font-medium">
                                        <div class="flex flex-col space-y-1">
                                            <div class="flex justify-center space-x-1">
                                                <button onclick="viewFacultySchedule(<?php echo $faculty['faculty_id']; ?>)"
                                                    class="text-purple-600 hover:text-purple-900" title="View Schedule">
                                                    <i class="fas fa-calendar-alt"></i>
                                                </button>
                                            </div>
                                            <div class="flex justify-center space-x-1 mt-1" id="approval-buttons-<?php echo $faculty['faculty_id']; ?>">
                                                <button onclick="approveTeachingLoad(<?php echo $faculty['faculty_id']; ?>)"
                                                    class="text-green-600 hover:text-green-900 text-xs p-1 rounded hover:bg-green-50 transition-colors"
                                                    title="Approve Teaching Load">
                                                    <i class="fas fa-check"></i>
                                                </button>
                                                <button onclick="showRejectModal(<?php echo $faculty['faculty_id']; ?>)"
                                                    class="text-red-600 hover:text-red-900 text-xs p-1 rounded hover:bg-red-50 transition-colors"
                                                    title="Reject Teaching Load">
                                                    <i class="fas fa-times"></i>
                                                </button>
                                            </div>
                                        </div>
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

        <!-- Legend -->
        <div class="mt-6 bg-white rounded-lg shadow-md p-4">
            <h3 class="text-sm font-semibold text-gray-900 mb-2">Legend:</h3>
            <div class="flex flex-wrap gap-4 text-xs">
                <div class="flex items-center">
                    <div class="w-3 h-3 bg-green-500 rounded-full mr-2"></div>
                    <span>Normal Load (18-24 hours)</span>
                </div>
                <div class="flex items-center">
                    <div class="w-3 h-3 bg-yellow-500 rounded-full mr-2"></div>
                    <span>Underload (&lt;18 hours)</span>
                </div>
                <div class="flex items-center">
                    <div class="w-3 h-3 bg-red-500 rounded-full mr-2"></div>
                    <span>Overload (&gt;24 hours)</span>
                </div>
                <div class="flex items-center">
                    <div class="w-3 h-3 bg-gray-500 rounded-full mr-2"></div>
                    <span>No Load (0 hours)</span>
                </div>
            </div>
        </div>
    </div>
</div>

<!-- Rejection Reason Modal -->
<div id="rejectModal" class="fixed inset-0 bg-gray-600 bg-opacity-50 overflow-y-auto h-full w-full hidden z-50">
    <div class="relative top-20 mx-auto p-5 border w-11/12 md:w-1/2 lg:w-1/3 shadow-lg rounded-md bg-white">
        <div class="mt-3">
            <div class="flex justify-between items-center pb-3 border-b">
                <h3 class="text-xl font-semibold text-gray-900">Reject Teaching Load</h3>
                <button onclick="closeRejectModal()" class="text-gray-400 hover:text-gray-600">
                    <i class="fas fa-times text-2xl"></i>
                </button>
            </div>

            <div class="mt-4">
                <input type="hidden" id="rejectFacultyId">
                <div class="mb-4">
                    <label for="rejectionReason" class="block text-sm font-medium text-gray-700 mb-2">
                        Reason for Rejection *
                    </label>
                    <textarea
                        id="rejectionReason"
                        rows="4"
                        class="w-full px-3 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-yellow-500 focus:border-yellow-500"
                        placeholder="Please provide a reason for rejecting this teaching load..."
                        required></textarea>
                </div>
            </div>

            <div class="flex justify-end space-x-3 mt-6 pt-4 border-t">
                <button onclick="closeRejectModal()" class="bg-gray-500 hover:bg-gray-600 text-white px-4 py-2 rounded-lg text-sm font-medium transition-colors">
                    Cancel
                </button>
                <button onclick="rejectTeachingLoad()" class="bg-red-500 hover:bg-red-600 text-white px-4 py-2 rounded-lg text-sm font-medium transition-colors">
                    <i class="fas fa-times mr-1"></i>Reject Teaching Load
                </button>
            </div>
        </div>
    </div>
</div>

<!-- Approval Success Modal -->
<div id="successModal" class="fixed inset-0 bg-gray-600 bg-opacity-50 overflow-y-auto h-full w-full hidden z-50">
    <div class="relative top-20 mx-auto p-5 border w-11/12 md:w-1/3 shadow-lg rounded-md bg-white">
        <div class="mt-3 text-center">
            <div class="mx-auto flex items-center justify-center h-12 w-12 rounded-full bg-green-100">
                <i class="fas fa-check text-green-600 text-xl"></i>
            </div>
            <h3 class="text-lg font-medium text-gray-900 mt-3" id="successTitle">Success</h3>
            <div class="mt-2 px-4">
                <p class="text-sm text-gray-500" id="successMessage"></p>
            </div>
            <div class="flex justify-center mt-6">
                <button onclick="closeSuccessModal()" class="bg-green-500 hover:bg-green-600 text-white px-6 py-2 rounded-lg text-sm font-medium transition-colors">
                    OK
                </button>
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
            <div class="animate-spin rounded-full h-12 w-12 border-b-2 border-yellow-500"></div>
            <span class="ml-3 text-gray-600">Loading schedule...</span>
        </div>
    `;
        document.getElementById('scheduleModal').classList.remove('hidden');

        // Fetch faculty schedule data
        fetch(`/director/api/all-schedule?facultyId=${facultyId}`)
            .then(response => {
                // First check if response is OK
                if (!response.ok) {
                    throw new Error(`HTTP error! status: ${response.status}`);
                }

                // Get the response as text first
                return response.text();
            })
            .then(text => {
                console.log('Raw response:', text);

                // Check if response is empty
                if (!text.trim()) {
                    throw new Error('Empty response from server');
                }

                try {
                    const data = JSON.parse(text);

                    if (data.success) {
                        displayFacultySchedule(data.faculty, data.schedules);
                    } else {
                        document.getElementById('modalContent').innerHTML = `
                        <div class="text-center py-8 text-gray-500">
                            <i class="fas fa-exclamation-triangle text-4xl mb-3 text-gray-300"></i>
                            <p class="text-lg">Error loading schedule</p>
                            <p class="text-sm mt-1">${data.message || 'Unable to load faculty schedule'}</p>
                            <button onclick="closeModal()" class="mt-4 bg-gray-500 hover:bg-gray-600 text-white px-4 py-2 rounded text-sm">
                                Close
                            </button>
                        </div>
                    `;
                    }
                } catch (error) {
                    console.error('JSON Parse Error:', error);
                    console.error('Response text:', text);

                    // Check if it's HTML instead of JSON
                    if (text.includes('<!DOCTYPE') || text.includes('<html')) {
                        document.getElementById('modalContent').innerHTML = `
                        <div class="text-center py-8 text-gray-500">
                            <i class="fas fa-exclamation-triangle text-4xl mb-3 text-gray-300"></i>
                            <p class="text-lg">Server Error</p>
                            <p class="text-sm mt-1">The server returned an HTML page instead of data. Please check the API endpoint.</p>
                            <button onclick="closeModal()" class="mt-4 bg-gray-500 hover:bg-gray-600 text-white px-4 py-2 rounded text-sm">
                                Close
                            </button>
                        </div>
                    `;
                    } else {
                        document.getElementById('modalContent').innerHTML = `
                        <div class="text-center py-8 text-gray-500">
                            <i class="fas fa-exclamation-triangle text-4xl mb-3 text-gray-300"></i>
                            <p class="text-lg">Invalid Response Format</p>
                            <p class="text-sm mt-1">The server returned data in an unexpected format.</p>
                            <button onclick="closeModal()" class="mt-4 bg-gray-500 hover:bg-gray-600 text-white px-4 py-2 rounded text-sm">
                                Close
                            </button>
                        </div>
                    `;
                    }
                }
            })
            .catch(error => {
                console.error('Fetch Error:', error);
                document.getElementById('modalContent').innerHTML = `
                <div class="text-center py-8 text-gray-500">
                    <i class="fas fa-exclamation-triangle text-4xl mb-3 text-gray-300"></i>
                    <p class="text-lg">Network Error</p>
                    <p class="text-sm mt-1">Unable to connect to the server. Please try again later.</p>
                    <p class="text-xs mt-2 text-gray-400">Error: ${error.message}</p>
                    <button onclick="closeModal()" class="mt-4 bg-gray-500 hover:bg-gray-600 text-white px-4 py-2 rounded text-sm">
                        Close
                    </button>
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
                case 'director_Approved':
                    statusClass = 'bg-indigo-100 text-indigo-800';
                    statusBadge = '<i class="fas fa-check mr-1"></i>director Approved';
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

    function viewFacultyDetails(facultyId) {
        // Implement view faculty details functionality
        window.open(`/director/faculty/${facultyId}`, '_blank');
    }

    function closeModal() {
        document.getElementById('scheduleModal').classList.add('hidden');
    }

    // Approval functions
    function approveTeachingLoad(facultyId) {
        if (!confirm('Are you sure you want to approve this teaching load? This will mark all schedules as director Approved.')) {
            return;
        }

        const button = document.querySelector(`#approval-buttons-${facultyId} button[onclick="approveTeachingLoad(${facultyId})"]`);
        const originalHTML = button.innerHTML;
        button.innerHTML = '<i class="fas fa-spinner fa-spin"></i>';
        button.disabled = true;

        fetch('/director/approve-teaching-load', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/x-www-form-urlencoded',
                },
                body: `faculty_id=${facultyId}&semester_id=${getCurrentSemesterId()}&notes=Teaching load approved by director`
            })
            .then(response => response.json())
            .then(data => {
                if (data.success) {
                    showSuccessModal('Teaching Load Approved', data.message);
                    loadApprovalStatus(facultyId);
                } else {
                    alert('Error: ' + data.message);
                    button.innerHTML = originalHTML;
                    button.disabled = false;
                }
            })
            .catch(error => {
                console.error('Error:', error);
                alert('Error approving teaching load');
                button.innerHTML = originalHTML;
                button.disabled = false;
            });
    }

    function showRejectModal(facultyId) {
        document.getElementById('rejectFacultyId').value = facultyId;
        document.getElementById('rejectionReason').value = '';
        document.getElementById('rejectModal').classList.remove('hidden');
    }

    function closeRejectModal() {
        document.getElementById('rejectModal').classList.add('hidden');
    }

    function rejectTeachingLoad() {
        const facultyId = document.getElementById('rejectFacultyId').value;
        const rejectionReason = document.getElementById('rejectionReason').value.trim();

        if (!rejectionReason) {
            alert('Please provide a reason for rejection.');
            return;
        }

        if (!confirm('Are you sure you want to reject this teaching load? This will mark all schedules as Rejected.')) {
            return;
        }

        const button = document.querySelector(`#approval-buttons-${facultyId} button[onclick="showRejectModal(${facultyId})"]`);
        const originalHTML = button.innerHTML;
        button.innerHTML = '<i class="fas fa-spinner fa-spin"></i>';
        button.disabled = true;

        fetch('/director/reject-teaching-load', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/x-www-form-urlencoded',
                },
                body: `faculty_id=${facultyId}&semester_id=${getCurrentSemesterId()}&rejection_reason=${encodeURIComponent(rejectionReason)}`
            })
            .then(response => response.json())
            .then(data => {
                if (data.success) {
                    closeRejectModal();
                    showSuccessModal('Teaching Load Rejected', data.message);
                    loadApprovalStatus(facultyId);
                } else {
                    alert('Error: ' + data.message);
                    button.innerHTML = originalHTML;
                    button.disabled = false;
                }
            })
            .catch(error => {
                console.error('Error:', error);
                alert('Error rejecting teaching load');
                button.innerHTML = originalHTML;
                button.disabled = false;
            });
    }

    function loadApprovalStatus(facultyId) {
        fetch(`/director/api/all-approval-status?facultyId=${facultyId}`)
            .then(response => response.json())
            .then(data => {
                if (data.success) {
                    updateApprovalStatusUI(facultyId, data.overall_status, data.status_details);
                } else {
                    document.getElementById(`approval-status-${facultyId}`).innerHTML =
                        '<span class="text-gray-500">Error loading status</span>';
                }
            })
            .catch(error => {
                console.error('Error loading approval status:', error);
                document.getElementById(`approval-status-${facultyId}`).innerHTML =
                    '<span class="text-gray-500">Status unavailable</span>';
            });
    }

    function updateApprovalStatusUI(facultyId, overallStatus, statusDetails) {
        const statusElement = document.getElementById(`approval-status-${facultyId}`);
        const buttonsElement = document.getElementById(`approval-buttons-${facultyId}`);

        let statusHTML = '';
        let buttonState = 'enabled';
        let statusColor = 'gray';

        switch (overallStatus) {
            case 'Approved':
                statusHTML = '<span class="text-green-600 font-medium"><i class="fas fa-check-circle mr-1"></i>Approved</span>';
                statusColor = 'green';
                buttonState = 'disabled';
                break;
            case 'director_Approved':
                statusHTML = '<span class="text-indigo-600 font-medium"><i class="fas fa-check mr-1"></i>director Approved</span>';
                statusColor = 'indigo';
                buttonState = 'disabled';
                break;
            case 'Di_Approved':
                statusHTML = '<span class="text-blue-600 font-medium"><i class="fas fa-check mr-1"></i>DI Approved</span>';
                statusColor = 'blue';
                buttonState = 'disabled';
                break;
            case 'Rejected':
                statusHTML = '<span class="text-red-600 font-medium"><i class="fas fa-times-circle mr-1"></i>Rejected</span>';
                statusColor = 'red';
                buttonState = 'disabled';
                break;
            case 'Partially_Approved':
                statusHTML = '<span class="text-yellow-600 font-medium"><i class="fas fa-exclamation-circle mr-1"></i>Partially Approved</span>';
                statusColor = 'yellow';
                buttonState = 'enabled';
                break;
            default: // Pending
                statusHTML = '<span class="text-gray-600 font-medium"><i class="fas fa-clock mr-1"></i>Pending</span>';
                statusColor = 'gray';
                buttonState = 'enabled';
        }

        // Add status breakdown tooltip if available
        if (statusDetails && statusDetails.length > 0) {
            let tooltipContent = 'Status Breakdown:<br>';
            statusDetails.forEach(detail => {
                tooltipContent += `${detail.status}: ${detail.schedule_count}<br>`;
            });

            statusHTML = `
            <div class="relative group">
                ${statusHTML}
                <div class="absolute bottom-full left-1/2 transform -translate-x-1/2 mb-2 px-2 py-1 text-xs text-white bg-gray-900 rounded opacity-0 group-hover:opacity-100 transition-opacity duration-200 whitespace-nowrap z-50">
                    ${tooltipContent}
                    <div class="absolute top-full left-1/2 transform -translate-x-1/2 border-4 border-transparent border-t-gray-900"></div>
                </div>
            </div>
        `;
        }

        statusElement.innerHTML = statusHTML;

        // Update button states
        if (buttonState === 'disabled') {
            buttonsElement.querySelectorAll('button').forEach(button => {
                button.disabled = true;
                button.classList.add('opacity-50', 'cursor-not-allowed');
                button.classList.remove('hover:bg-green-50', 'hover:bg-red-50');
            });
        } else {
            buttonsElement.querySelectorAll('button').forEach(button => {
                button.disabled = false;
                button.classList.remove('opacity-50', 'cursor-not-allowed');
                if (button.innerHTML.includes('fa-check')) {
                    button.classList.add('hover:bg-green-50');
                } else {
                    button.classList.add('hover:bg-red-50');
                }
            });
        }
    }

    function showSuccessModal(title, message) {
        document.getElementById('successTitle').textContent = title;
        document.getElementById('successMessage').textContent = message;
        document.getElementById('successModal').classList.remove('hidden');
    }

    function closeSuccessModal() {
        document.getElementById('successModal').classList.add('hidden');
        // Reload the page to reflect changes
        setTimeout(() => {
            window.location.reload();
        }, 1000);
    }

    function updateApprovalStatusUI(facultyId, overallStatus, statusDetails) {
        const statusElement = document.getElementById(`approval-status-${facultyId}`);
        const buttonsElement = document.getElementById(`approval-buttons-${facultyId}`);

        let statusHTML = '';
        let buttonState = 'enabled';
        let statusColor = 'gray';
        let statusIcon = 'clock';

        switch (overallStatus) {
            case 'Approved':
                statusHTML = '<span class="text-green-600 font-medium"><i class="fas fa-check-circle mr-1"></i>Fully Approved</span>';
                statusColor = 'green';
                statusIcon = 'check-circle';
                buttonState = 'disabled';
                break;
            case 'Di_Approved':
                statusHTML = '<span class="text-blue-600 font-medium"><i class="fas fa-check-double mr-1"></i>DI Approved</span>';
                statusColor = 'blue';
                statusIcon = 'check-double';
                buttonState = 'disabled';
                break;
            case 'Dean_Approved':
                statusHTML = '<span class="text-indigo-600 font-medium"><i class="fas fa-check mr-1"></i>Dean Approved</span>';
                statusColor = 'indigo';
                statusIcon = 'check';
                buttonState = 'enabled'; // Director can still approve after dean
                break;
            case 'Rejected':
                statusHTML = '<span class="text-red-600 font-medium"><i class="fas fa-times-circle mr-1"></i>Rejected</span>';
                statusColor = 'red';
                statusIcon = 'times-circle';
                buttonState = 'disabled';
                break;
            case 'Partially_Approved':
                statusHTML = '<span class="text-yellow-600 font-medium"><i class="fas fa-exclamation-circle mr-1"></i>Partially Approved</span>';
                statusColor = 'yellow';
                statusIcon = 'exclamation-circle';
                buttonState = 'enabled';
                break;
            default: // Pending
                statusHTML = '<span class="text-gray-600 font-medium"><i class="fas fa-clock mr-1"></i>Pending</span>';
                statusColor = 'gray';
                statusIcon = 'clock';
                buttonState = 'enabled';
        }

        // Add status breakdown tooltip with dean approval info
        if (statusDetails && statusDetails.length > 0) {
            let tooltipContent = 'Approval Breakdown:<br>';
            let hasDeanApproved = false;
            let deanApprovedCount = 0;

            statusDetails.forEach(detail => {
                tooltipContent += `${detail.status}: ${detail.schedule_count}<br>`;
                if (detail.status === 'Dean_Approved') {
                    hasDeanApproved = true;
                    deanApprovedCount = detail.schedule_count;
                }
            });

            // Add dean approval info to the main status
            if (hasDeanApproved) {
                statusHTML = `
                <div class="relative group">
                    <div class="flex items-center">
                        ${statusHTML}
                        <span class="ml-1 text-xs text-indigo-500" title="Dean Approved Schedules">
                            <i class="fas fa-user-tie"></i> ${deanApprovedCount}
                        </span>
                    </div>
                    <div class="absolute bottom-full left-1/2 transform -translate-x-1/2 mb-2 px-2 py-1 text-xs text-white bg-gray-900 rounded opacity-0 group-hover:opacity-100 transition-opacity duration-200 whitespace-nowrap z-50">
                        ${tooltipContent}
                        <div class="absolute top-full left-1/2 transform -translate-x-1/2 border-4 border-transparent border-t-gray-900"></div>
                    </div>
                </div>
            `;
            } else {
                statusHTML = `
                <div class="relative group">
                    ${statusHTML}
                    <div class="absolute bottom-full left-1/2 transform -translate-x-1/2 mb-2 px-2 py-1 text-xs text-white bg-gray-900 rounded opacity-0 group-hover:opacity-100 transition-opacity duration-200 whitespace-nowrap z-50">
                        ${tooltipContent}
                        <div class="absolute top-full left-1/2 transform -translate-x-1/2 border-4 border-transparent border-t-gray-900"></div>
                    </div>
                </div>
            `;
            }
        }

        statusElement.innerHTML = statusHTML;

        // Update button states
        if (buttonState === 'disabled') {
            buttonsElement.querySelectorAll('button').forEach(button => {
                button.disabled = true;
                button.classList.add('opacity-50', 'cursor-not-allowed');
                button.classList.remove('hover:bg-green-50', 'hover:bg-red-50');
            });
        } else {
            buttonsElement.querySelectorAll('button').forEach(button => {
                button.disabled = false;
                button.classList.remove('opacity-50', 'cursor-not-allowed');
                if (button.innerHTML.includes('fa-check')) {
                    button.classList.add('hover:bg-green-50');
                } else {
                    button.classList.add('hover:bg-red-50');
                }
            });
        }
    }

    function getCurrentSemesterId() {
        // This should be set from PHP, you might need to pass it as a data attribute
        return <?php echo $semesterId ?? 'null'; ?>;
    }

    // Filter functions
    function filterByCollege() {
        const collegeFilter = document.getElementById('collegeFilter');
        const selectedCollege = collegeFilter.value;

        const url = new URL(window.location.href);

        if (selectedCollege === 'all') {
            url.searchParams.delete('college');
        } else {
            url.searchParams.set('college', selectedCollege);
        }

        // Reset department filter when college changes
        url.searchParams.delete('department');

        window.location.href = url.toString();
    }

    function filterByDepartment() {
        const departmentFilter = document.getElementById('departmentFilter');
        const selectedDepartment = departmentFilter.value;

        const url = new URL(window.location.href);

        if (selectedDepartment === 'all') {
            url.searchParams.delete('department');
        } else {
            url.searchParams.set('department', selectedDepartment);
        }

        window.location.href = url.toString();
    }

    function clearCollegeFilter() {
        const url = new URL(window.location.href);
        url.searchParams.delete('college');
        window.location.href = url.toString();
    }

    function clearDepartmentFilter() {
        const url = new URL(window.location.href);
        url.searchParams.delete('department');
        window.location.href = url.toString();
    }

    // Enhanced export function that respects filters
    function exportToExcel() {
        const table = document.getElementById('teachingLoadTable');
        const departmentFilter = document.getElementById('departmentFilter');
        const selectedDepartment = departmentFilter.value;

        let fileName = 'faculty_teaching_load_' + new Date().toISOString().split('T')[0];

        // Add department name to filename if filtered
        if (selectedDepartment !== 'all') {
            const selectedOption = departmentFilter.options[departmentFilter.selectedIndex];
            const deptName = selectedOption.text.replace(/[^a-zA-Z0-9]/g, '_');
            fileName += '_' + deptName;
        }

        const html = table.outerHTML;
        const url = 'data:application/vnd.ms-excel;charset=utf-8,' + encodeURIComponent(html);
        const link = document.createElement('a');
        link.download = fileName + '.xls';
        link.href = url;
        link.click();
    }

    // Add search functionality
    function setupSearch() {
        const searchInput = document.createElement('input');
        searchInput.type = 'text';
        searchInput.placeholder = 'Search faculty...';
        searchInput.className = 'block w-full sm:w-64 px-3 py-2 border border-gray-300 rounded-md shadow-sm focus:outline-none focus:ring-2 focus:ring-yellow-500 focus:border-yellow-500 text-sm';
        searchInput.onkeyup = function() {
            filterTable(this.value);
        };

        // Add search input to the filter section
        const filterSection = document.querySelector('.flex.flex-col.sm\\:flex-row.gap-4');
        if (filterSection) {
            filterSection.insertBefore(searchInput, filterSection.firstChild);
        }
    }

    function filterTable(searchTerm) {
        const table = document.getElementById('teachingLoadTable');
        const rows = table.getElementsByTagName('tbody')[0].getElementsByTagName('tr');
        const term = searchTerm.toLowerCase();

        for (let i = 0; i < rows.length; i++) {
            const row = rows[i];
            const facultyName = row.cells[0].textContent.toLowerCase();
            const department = row.cells[1].textContent.toLowerCase();

            if (facultyName.includes(term) || department.includes(term)) {
                row.style.display = '';
            } else {
                row.style.display = 'none';
            }
        }
    }

    // Close modal when clicking outside
    document.getElementById('scheduleModal').addEventListener('click', function(e) {
        if (e.target.id === 'scheduleModal') {
            closeModal();
        }
    });

    // Add search and filter functionality
    document.addEventListener('DOMContentLoaded', function() {
        console.log('Faculty Teaching Load page loaded');

        // Setup search functionality
        setupSearch();

        // Load approval status for each faculty member
        <?php if (!empty($facultyTeachingLoads)): ?>
            <?php foreach ($facultyTeachingLoads as $index => $faculty): ?>
                setTimeout(() => {
                    loadApprovalStatus(<?php echo $faculty['faculty_id']; ?>);
                }, <?php echo $index * 200 ?>); // Stagger requests to avoid overwhelming the server
            <?php endforeach; ?>
        <?php endif; ?>

        // Add keyboard shortcut for search (Ctrl/Cmd + F)
        document.addEventListener('keydown', function(e) {
            if ((e.ctrlKey || e.metaKey) && e.key === 'f') {
                e.preventDefault();
                const searchInput = document.querySelector('input[placeholder="Search faculty..."]');
                if (searchInput) {
                    searchInput.focus();
                    searchInput.select();
                }
            }
        });
    });
</script>

<?php
$content = ob_get_clean();
require_once __DIR__ . '/layout.php';
?>