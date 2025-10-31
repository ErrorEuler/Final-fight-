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

    .glass-effect {
        background: rgba(255, 255, 255, 0.95);
        backdrop-filter: blur(10px);
    }

    .schedule-card {
        transition: all 0.3s ease;
    }

    .schedule-card:hover {
        transform: translateY(-2px);
        box-shadow: 0 10px 25px rgba(0, 0, 0, 0.1);
    }

    .status-badge {
        display: inline-flex;
        align-items: center;
        gap: 0.375rem;
        padding: 0.375rem 0.75rem;
        border-radius: 9999px;
        font-size: 0.75rem;
        font-weight: 600;
        transition: all 0.2s;
    }

    .status-badge::before {
        content: '';
        width: 6px;
        height: 6px;
        border-radius: 50%;
        animation: pulse 2s infinite;
    }

    @keyframes pulse {

        0%,
        100% {
            opacity: 1;
        }

        50% {
            opacity: 0.5;
        }
    }

    .filter-card {
        background: linear-gradient(135deg, #ffffff 0%, #f9fafb 100%);
    }

    .action-btn {
        position: relative;
        overflow: hidden;
        transition: all 0.3s ease;
    }

    .action-btn::before {
        content: '';
        position: absolute;
        top: 50%;
        left: 50%;
        width: 0;
        height: 0;
        border-radius: 50%;
        background: rgba(255, 255, 255, 0.3);
        transform: translate(-50%, -50%);
        transition: width 0.6s, height 0.6s;
    }

    .action-btn:hover::before {
        width: 300px;
        height: 300px;
    }

    .modal-backdrop {
        backdrop-filter: blur(4px);
        animation: fadeIn 0.2s ease-out;
    }

    .modal-content {
        animation: slideInUp 0.3s ease-out;
    }

    @keyframes slideInUp {
        from {
            transform: translateY(20px);
            opacity: 0;
        }

        to {
            transform: translateY(0);
            opacity: 1;
        }
    }

    .table-header {
        background: linear-gradient(135deg, #1f2937 0%, #374151 100%);
        position: sticky;
        top: 0;
        z-index: 10;
    }

    .search-input {
        transition: all 0.3s ease;
    }

    .search-input:focus {
        transform: translateY(-2px);
        box-shadow: 0 4px 12px rgba(234, 179, 8, 0.2);
    }

    @media (max-width: 768px) {
        .responsive-table {
            display: block;
            overflow-x: auto;
            -webkit-overflow-scrolling: touch;
        }
    }

    .icon-wrapper {
        display: inline-flex;
        align-items: center;
        justify-content: center;
        width: 2rem;
        height: 2rem;
        border-radius: 0.5rem;
        background: rgba(234, 179, 8, 0.1);
        margin-right: 0.5rem;
    }

    .stats-card {
        background: linear-gradient(135deg, #fef3c7 0%, #fde68a 100%);
        border-left: 4px solid #eab308;
    }
</style>

<div class="min-h-screen bg-gray-50 py-2 px-2 sm:px-4 lg:px-8">
    <!-- Page Header with Enhanced Design -->
    <div class="schedule-card bg-gradient-to-br from-gray-800 via-gray-900 to-gray-800 text-white rounded-2xl p-6 sm:p-8 mb-6 shadow-2xl relative overflow-hidden">
        <div class="absolute top-0 left-0 w-1 h-full bg-gradient-to-b from-yellow-400 to-yellow-600"></div>
        <div class="absolute top-0 right-0 w-32 h-32 bg-yellow-500 opacity-10 rounded-full -mr-16 -mt-16"></div>
        <div class="absolute bottom-0 right-0 w-48 h-48 bg-yellow-500 opacity-5 rounded-full -mr-24 -mb-24"></div>

        <div class="relative z-10">
            <div class="flex flex-col lg:flex-row items-start lg:items-center justify-between gap-4">
                <div class="flex-1">
                    <div class="flex items-center mb-3">
                        <div class="icon-wrapper bg-yellow-500 bg-opacity-20">
                            <i class="fas fa-calendar-alt text-yellow-400 text-lg"></i>
                        </div>
                        <h1 class="text-3xl sm:text-4xl font-bold tracking-tight">Director Schedule Approvals</h1>
                    </div>
                    <p class="text-gray-300 text-sm sm:text-base flex items-center">
                        <i class="fas fa-university mr-2 text-yellow-400"></i>
                        Review schedules approved by Deans
                    </p>
                </div>
                <div class="stats-card px-4 py-3 rounded-xl shadow-lg">
                    <div class="flex items-center text-gray-800">
                        <i class="fas fa-calendar-check text-2xl text-yellow-600 mr-3"></i>
                        <div>
                            <p class="text-xs font-medium text-gray-600 uppercase tracking-wide">Current Semester</p>
                            <p class="text-sm font-bold"><?php echo htmlspecialchars($currentSemester['semester_name'] ?? 'No Semester'); ?></p>
                            <?php if (isset($stats['total_pending']) && $stats['total_pending'] > 0): ?>
                                <span class="inline-flex items-center mt-2 px-3 py-1 bg-red-500 text-white text-xs font-bold rounded-full">
                                    <i class="fas fa-exclamation-circle mr-1"></i>
                                    <?php echo htmlspecialchars($stats['total_pending']); ?> Pending Director Approval
                                </span>
                            <?php else: ?>
                                <span class="inline-flex items-center mt-2 px-3 py-1 bg-gray-500 text-white text-xs font-bold rounded-full">
                                    <i class="fas fa-check-circle mr-1"></i>
                                    No Pending Schedules
                                </span>
                            <?php endif; ?>
                        </div>
                    </div>
                </div>
            </div>
        </div>
    </div>

    <!-- Filters Section with Modern Card Design -->
    <div class="filter-card schedule-card rounded-2xl shadow-lg p-6 mb-6 border border-gray-100">
        <div class="flex items-center mb-5">
            <div class="icon-wrapper">
                <i class="fas fa-filter text-yellow-600"></i>
            </div>
            <h2 class="text-lg font-bold text-gray-800">Filters & Search</h2>
        </div>

        <div class="grid grid-cols-1 md:grid-cols-2 gap-4 mb-6">
            <!-- Department Filter -->
            <div class="relative">
                <label class="block text-sm font-medium text-gray-700 mb-2">
                    <i class="fas fa-building text-yellow-500 mr-1"></i>
                    Department
                </label>
                <select id="department-filter" class="w-full p-3.5 border border-gray-300 rounded-xl focus:outline-none focus:ring-2 focus:ring-yellow-500 focus:border-transparent transition-all bg-white shadow-sm hover:border-yellow-400">
                    <option value="">All Departments</option>
                    <?php
                    $colleges = [];
                    foreach ($departments as $dept) {
                        $collegeName = htmlspecialchars($dept['college_name']);
                        if (!isset($colleges[$collegeName])) {
                            $colleges[$collegeName] = [];
                        }
                        $colleges[$collegeName][] = $dept;
                    }
                    foreach ($colleges as $collegeName => $collegeDepts): ?>
                        <optgroup label="<?php echo $collegeName; ?>">
                            <?php foreach ($collegeDepts as $dept): ?>
                                <option value="<?php echo $dept['department_id']; ?>">
                                    <?php echo htmlspecialchars($dept['department_name']); ?>
                                </option>
                            <?php endforeach; ?>
                        </optgroup>
                    <?php endforeach; ?>
                </select>
            </div>

            <!-- Search Input -->
            <div class="relative">
                <label class="block text-sm font-medium text-gray-700 mb-2">
                    <i class="fas fa-search text-yellow-500 mr-1"></i>
                    Search
                </label>
                <div class="relative">
                    <input type="text" id="search-schedule" placeholder="Course code, section, or room..." class="search-input w-full p-3.5 pl-12 border border-gray-300 rounded-xl focus:outline-none focus:ring-2 focus:ring-yellow-500 focus:border-transparent bg-white shadow-sm hover:border-yellow-400">
                    <i class="fas fa-search absolute left-4 top-1/2 transform -translate-y-1/2 text-gray-400"></i>
                </div>
            </div>
        </div>

        <!-- Action Buttons -->
        <div class="flex flex-col sm:flex-row gap-3 pt-4 border-t border-gray-200">
            <button id="approveAllBtn" class="action-btn flex-1 bg-gradient-to-r from-green-500 to-green-600 hover:from-green-600 hover:to-green-700 text-white px-6 py-3.5 rounded-xl text-sm font-semibold shadow-lg hover:shadow-xl transition-all duration-300 flex items-center justify-center">
                <i class="fas fa-check-circle mr-2 text-lg"></i>
                Approve All Pending
            </button>
            <button id="rejectAllBtn" class="action-btn flex-1 bg-gradient-to-r from-red-500 to-red-600 hover:from-red-600 hover:to-red-700 text-white px-6 py-3.5 rounded-xl text-sm font-semibold shadow-lg hover:shadow-xl transition-all duration-300 flex items-center justify-center">
                <i class="fas fa-times-circle mr-2 text-lg"></i>
                Reject All Pending
            </button>
        </div>
    </div>

    <!-- Schedule Table with Modern Design -->
    <div class="schedule-card bg-white rounded-2xl shadow-lg overflow-hidden border border-gray-100">
        <div class="table-header px-6 py-4 border-l-4 border-yellow-500">
            <h3 class="text-xl font-bold text-white flex items-center">
                <div class="icon-wrapper bg-yellow-500 bg-opacity-20 mr-3">
                    <i class="fas fa-list-alt text-yellow-400"></i>
                </div>
                Schedules Pending Director Approval
            </h3>
        </div>

        <div class="responsive-table overflow-x-auto">
            <table class="min-w-full divide-y divide-gray-200">
                <thead class="bg-gray-50">
                    <tr>
                        <th class="px-6 py-4 text-left text-xs font-bold text-gray-600 uppercase tracking-wider">
                            <div class="flex items-center">
                                <i class="fas fa-university mr-2 text-yellow-500"></i>
                                College
                            </div>
                        </th>
                        <th class="px-6 py-4 text-left text-xs font-bold text-gray-600 uppercase tracking-wider">
                            <div class="flex items-center">
                                <i class="fas fa-building mr-2 text-yellow-500"></i>
                                Department
                            </div>
                        </th>
                        <th class="px-6 py-4 text-left text-xs font-bold text-gray-600 uppercase tracking-wider">
                            <div class="flex items-center">
                                <i class="fas fa-book mr-2 text-yellow-500"></i>
                                Course Code
                            </div>
                        </th>
                        <th class="px-6 py-4 text-left text-xs font-bold text-gray-600 uppercase tracking-wider">
                            <div class="flex items-center">
                                <i class="fas fa-chalkboard-teacher mr-2 text-yellow-500"></i>
                                Faculty
                            </div>
                        </th>
                        <th class="px-6 py-4 text-left text-xs font-bold text-gray-600 uppercase tracking-wider">
                            <div class="flex items-center">
                                <i class="fas fa-users mr-2 text-yellow-500"></i>
                                Section
                            </div>
                        </th>
                        <th class="px-6 py-4 text-left text-xs font-bold text-gray-600 uppercase tracking-wider">
                            <div class="flex items-center">
                                <i class="fas fa-clock mr-2 text-yellow-500"></i>
                                Schedule
                            </div>
                        </th>
                        <th class="px-6 py-4 text-left text-xs font-bold text-gray-600 uppercase tracking-wider">
                            <div class="flex items-center">
                                <i class="fas fa-door-open mr-2 text-yellow-500"></i>
                                Room
                            </div>
                        </th>
                        <th class="px-6 py-4 text-left text-xs font-bold text-gray-600 uppercase tracking-wider">
                            <div class="flex items-center">
                                <i class="fas fa-exchange-alt mr-2 text-yellow-500"></i>
                                Type
                            </div>
                        </th>
                        <th class="px-6 py-4 text-left text-xs font-bold text-gray-600 uppercase tracking-wider">
                            <div class="flex items-center">
                                <i class="fas fa-info-circle mr-2 text-yellow-500"></i>
                                Status
                            </div>
                        </th>
                        <th class="px-6 py-4 text-left text-xs font-bold text-gray-600 uppercase tracking-wider">
                            <div class="flex items-center">
                                <i class="fas fa-cogs mr-2 text-yellow-500"></i>
                                Actions
                            </div>
                        </th>
                    </tr>
                </thead>
                <tbody id="scheduleTableBody" class="bg-white divide-y divide-gray-100">
                    <?php if (empty($schedules)): ?>
                        <tr id="noResultsRow" class="fade-in">
                            <td colspan="10" class="px-6 py-16 text-center">
                                <div class="flex flex-col items-center">
                                    <div class="w-24 h-24 bg-yellow-50 rounded-full flex items-center justify-center mb-4">
                                        <i class="fas fa-calendar-plus text-4xl text-yellow-400"></i>
                                    </div>
                                    <p class="text-lg font-semibold text-gray-700 mb-1">No schedules pending Director approval</p>
                                    <p class="text-sm text-gray-500">Schedules approved by Deans will appear here.</p>
                                </div>
                            </td>
                        </tr>
                    <?php else: ?>
                        <?php $allSchedules = [];
                        foreach ($schedules as $deptSchedules):
                            $allSchedules = array_merge($allSchedules, $deptSchedules);
                        endforeach; ?>
                        <?php foreach ($allSchedules as $schedule): ?>
                            <tr class="schedule-row hover:bg-yellow-50 transition-all duration-200 cursor-pointer border-l-4 border-transparent hover:border-yellow-400"
                                data-dept-id="<?php echo htmlspecialchars($schedule['department_id'] ?? ''); ?>"
                                data-schedule-ids="<?php echo htmlspecialchars($schedule['schedule_ids']); ?>"
                                data-status="<?php echo htmlspecialchars($schedule['status']); ?>">
                                <td class="px-6 py-4">
                                    <div class="text-sm font-semibold text-gray-800">
                                        <?php echo htmlspecialchars($schedule['college_name'] ?? 'N/A'); ?>
                                    </div>
                                </td>
                                <td class="px-6 py-4">
                                    <div class="text-sm font-medium text-gray-700">
                                        <?php echo htmlspecialchars($schedule['department_name']); ?>
                                    </div>
                                </td>
                                <td class="px-6 py-4 course-code-cell">
                                    <div class="inline-flex items-center px-3 py-1.5 bg-gray-100 rounded-lg">
                                        <i class="fas fa-bookmark text-yellow-500 text-xs mr-2"></i>
                                        <span class="text-sm font-bold text-gray-800">
                                            <?php echo htmlspecialchars($schedule['course_code']); ?>
                                        </span>
                                    </div>
                                </td>
                                <td class="px-6 py-4 faculty-cell">
                                    <div class="flex items-center">
                                        <div class="w-8 h-8 bg-yellow-100 rounded-full flex items-center justify-center mr-2">
                                            <i class="fas fa-user text-yellow-600 text-xs"></i>
                                        </div>
                                        <span class="text-sm font-medium text-gray-700">
                                            <?php echo htmlspecialchars($schedule['faculty_name'] ?? 'TBD'); ?>
                                        </span>
                                    </div>
                                </td>
                                <td class="px-6 py-4 section-cell">
                                    <span class="inline-flex items-center px-3 py-1.5 text-xs font-bold bg-yellow-100 text-yellow-800 rounded-full">
                                        <i class="fas fa-layer-group mr-1.5"></i>
                                        <?php echo htmlspecialchars($schedule['section_name'] ?? 'N/A'); ?>
                                    </span>
                                </td>
                                <td class="px-6 py-4">
                                    <div class="space-y-1">
                                        <div class="inline-flex items-center px-3 py-1 bg-blue-50 rounded-lg">
                                            <i class="fas fa-calendar-day text-blue-600 text-xs mr-2"></i>
                                            <span class="text-sm font-bold text-blue-900">
                                                <?php echo htmlspecialchars($schedule['formatted_days']); ?>
                                            </span>
                                        </div>
                                        <div class="flex items-center text-xs text-gray-500">
                                            <i class="far fa-clock mr-1.5"></i>
                                            <?php echo htmlspecialchars(date('h:i A', strtotime($schedule['start_time'])) . ' - ' . date('h:i A', strtotime($schedule['end_time']))); ?>
                                        </div>
                                    </div>
                                </td>
                                <td class="px-6 py-4 room-cell">
                                    <div class="inline-flex items-center px-3 py-1.5 bg-gray-50 rounded-lg">
                                        <i class="fas fa-map-marker-alt text-gray-500 text-xs mr-2"></i>
                                        <span class="text-sm font-medium text-gray-700">
                                            <?php echo htmlspecialchars($schedule['room_name'] ?? 'TBD'); ?>
                                        </span>
                                    </div>
                                </td>
                                <td class="px-6 py-4">
                                    <span class="inline-flex items-center px-3 py-1.5 text-xs font-bold rounded-full <?php echo $schedule['schedule_type'] === 'F2F' ? 'bg-blue-100 text-blue-800' : 'bg-purple-100 text-purple-800'; ?>">
                                        <i class="fas fa-<?php echo $schedule['schedule_type'] === 'F2F' ? 'users' : 'laptop'; ?> mr-1.5"></i>
                                        <?php echo htmlspecialchars($schedule['schedule_type']); ?>
                                    </span>
                                </td>
                                <td class="px-6 py-4">
                                    <span class="status-badge bg-yellow-100 text-yellow-800">
                                        Dean Approved
                                    </span>
                                </td>
                                <td class="px-6 py-4">
                                    <form method="POST" class="inline-flex items-center gap-2">
                                        <input type="hidden" name="schedule_ids" value="<?php echo htmlspecialchars($schedule['schedule_ids']); ?>">
                                        <button type="submit" name="action" value="approve" class="text-green-500 hover:text-green-700 transition-colors" title="Approve Schedule">
                                            <i class="fas fa-check-circle text-lg"></i>
                                        </button>
                                        <button type="submit" name="action" value="reject" class="text-red-500 hover:text-red-700 transition-colors" title="Reject Schedule">
                                            <i class="fas fa-times-circle text-lg"></i>
                                        </button>
                                    </form>
                                </td>
                            </tr>
                        <?php endforeach; ?>
                        <tr id="noResultsRow" class="hidden fade-in">
                            <td colspan="10" class="px-6 py-16 text-center">
                                <div class="flex flex-col items-center">
                                    <div class="w-24 h-24 bg-gray-100 rounded-full flex items-center justify-center mb-4">
                                        <i class="fas fa-calendar-times text-4xl text-gray-300"></i>
                                    </div>
                                    <p class="text-lg font-semibold text-gray-700 mb-1">No schedules found</p>
                                    <p class="text-sm text-gray-500">Try adjusting your filters or search terms.</p>
                                </div>
                            </td>
                        </tr>
                    <?php endif; ?>
                </tbody>
            </table>
        </div>
    </div>
</div>

<!-- Approval Modal -->
<div id="approveModal" class="modal-backdrop fixed inset-0 bg-black/70 backdrop-blur-sm hidden flex items-center justify-center z-50 p-4">
    <div class="modal-content bg-white rounded-2xl shadow-2xl max-w-md w-full overflow-hidden">
        <div class="bg-gradient-to-r from-green-500 to-green-600 px-6 py-4">
            <h3 class="text-xl font-bold text-white flex items-center">
                <i class="fas fa-check-circle mr-3 text-2xl"></i>
                Confirm Director Approval
            </h3>
        </div>
        <div class="p-6">
            <p class="text-gray-600 mb-6 leading-relaxed">
                Are you sure you want to approve all pending schedules? This will finalize the schedules and make them public.
            </p>
            <div class="flex gap-3">
                <button id="cancelApprove" class="flex-1 px-4 py-3 bg-gray-100 hover:bg-gray-200 text-gray-700 rounded-xl font-semibold transition-all duration-200">
                    Cancel
                </button>
                <button id="confirmApprove" class="flex-1 px-4 py-3 bg-gradient-to-r from-green-500 to-green-600 hover:from-green-600 hover:to-green-700 text-white rounded-xl font-semibold shadow-lg transition-all duration-200">
                    Approve All
                </button>
            </div>
        </div>
    </div>
</div>

<!-- Rejection Modal -->
<div id="rejectModal" class="modal-backdrop fixed inset-0 bg-black/70 backdrop-blur-sm hidden flex items-center justify-center z-50 p-4">
    <div class="modal-content bg-white rounded-2xl shadow-2xl max-w-md w-full overflow-hidden">
        <div class="bg-gradient-to-r from-red-500 to-red-600 px-6 py-4">
            <h3 class="text-xl font-bold text-white flex items-center">
                <i class="fas fa-times-circle mr-3 text-2xl"></i>
                Confirm Rejection
            </h3>
        </div>
        <div class="p-6">
            <p class="text-gray-600 mb-6 leading-relaxed">
                Are you sure you want to reject all pending schedules? This action cannot be undone.
            </p>
            <div class="flex gap-3">
                <button id="cancelReject" class="flex-1 px-4 py-3 bg-gray-100 hover:bg-gray-200 text-gray-700 rounded-xl font-semibold transition-all duration-200">
                    Cancel
                </button>
                <button id="confirmReject" class="flex-1 px-4 py-3 bg-gradient-to-r from-red-500 to-red-600 hover:from-red-600 hover:to-red-700 text-white rounded-xl font-semibold shadow-lg transition-all duration-200">
                    Reject All
                </button>
            </div>
        </div>
    </div>
</div>

<!-- Hidden Form for Bulk Actions -->
<form id="bulkActionForm" method="POST" style="display: none;">
    <input type="hidden" name="schedule_ids" id="bulkScheduleIds" value="">
    <input type="hidden" name="action" id="bulkAction" value="">
</form>

<script>
    document.addEventListener('DOMContentLoaded', function() {
        const departmentFilter = document.getElementById('department-filter');
        const searchInput = document.getElementById('search-schedule');
        const tableBody = document.getElementById('scheduleTableBody');
        const rows = tableBody.querySelectorAll('.schedule-row');
        const noResultsRow = document.getElementById('noResultsRow');

        function filterRows() {
            const selectedDept = departmentFilter.value;
            const searchTerm = searchInput.value.toLowerCase().trim();

            let visibleCount = 0;

            rows.forEach(row => {
                const deptId = row.getAttribute('data-dept-id');
                const courseCell = row.querySelector('.course-code-cell');
                const sectionCell = row.querySelector('.section-cell');
                const roomCell = row.querySelector('.room-cell');

                const courseText = courseCell ? courseCell.textContent.toLowerCase() : '';
                const sectionText = sectionCell ? sectionCell.textContent.toLowerCase() : '';
                const roomText = roomCell ? roomCell.textContent.toLowerCase() : '';

                const matchesDept = !selectedDept || deptId === selectedDept;
                const matchesSearch = !searchTerm ||
                    courseText.includes(searchTerm) ||
                    sectionText.includes(searchTerm) ||
                    roomText.includes(searchTerm);

                if (matchesDept && matchesSearch) {
                    row.style.display = '';
                    visibleCount++;
                } else {
                    row.style.display = 'none';
                }
            });

            noResultsRow.style.display = visibleCount === 0 ? '' : 'none';
        }

        function getAllPendingIds() {
            const ids = [];
            rows.forEach(row => {
                if (row.style.display !== 'none' && row.dataset.status === 'Dean_Approved') {
                    const rowIds = row.dataset.scheduleIds.split(',').map(id => id.trim()).filter(id => id);
                    ids.push(...rowIds);
                }
            });
            return [...new Set(ids)].join(',');
        }

        const approveBtn = document.getElementById('approveAllBtn');
        const rejectBtn = document.getElementById('rejectAllBtn');
        const approveModal = document.getElementById('approveModal');
        const rejectModal = document.getElementById('rejectModal');
        const cancelApprove = document.getElementById('cancelApprove');
        const confirmApprove = document.getElementById('confirmApprove');
        const cancelReject = document.getElementById('cancelReject');
        const confirmReject = document.getElementById('confirmReject');
        const bulkForm = document.getElementById('bulkActionForm');
        const bulkIdsInput = document.getElementById('bulkScheduleIds');
        const bulkActionInput = document.getElementById('bulkAction');

        approveBtn.addEventListener('click', function() {
            const ids = getAllPendingIds();
            if (ids === '') {
                alert('No schedules pending Director approval.');
                return;
            }
            approveModal.classList.remove('hidden');
        });

        rejectBtn.addEventListener('click', function() {
            const ids = getAllPendingIds();
            if (ids === '') {
                alert('No schedules pending Director approval.');
                rejectModal.classList.add('hidden');
                return;
            }
            rejectModal.classList.remove('hidden');
        });

        cancelApprove.addEventListener('click', function() {
            approveModal.classList.add('hidden');
        });

        confirmApprove.addEventListener('click', function() {
            const ids = getAllPendingIds();
            if (ids === '') {
                alert('No schedules pending Director approval.');
                approveModal.classList.add('hidden');
                return;
            }
            bulkIdsInput.value = ids;
            bulkActionInput.value = 'approve';
            bulkForm.submit();
        });

        cancelReject.addEventListener('click', function() {
            rejectModal.classList.add('hidden');
        });

        confirmReject.addEventListener('click', function() {
            const ids = getAllPendingIds();
            if (ids === '') {
                alert('No schedules pending Director approval.');
                rejectModal.classList.add('hidden');
                return;
            }
            bulkIdsInput.value = ids;
            bulkActionInput.value = 'reject';
            bulkForm.submit();
        });

        [approveModal, rejectModal].forEach(modal => {
            modal.addEventListener('click', function(e) {
                if (e.target === modal) {
                    modal.classList.add('hidden');
                }
            });
        });

        departmentFilter.addEventListener('change', filterRows);
        searchInput.addEventListener('input', filterRows);

        filterRows();
    });
</script>

<?php
$content = ob_get_clean();
require_once __DIR__ . '/layout.php';
?>