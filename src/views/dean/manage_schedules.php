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

<div>
    <!-- Page Header -->
    <div class="bg-gradient-to-r from-gray-800 to-gray-900 text-white rounded-xl p-6 sm:p-8 mb-8 shadow-lg relative overflow-hidden">
        <div class="absolute top-0 left-0 w-2 h-full bg-yellow-500"></div>
        <div class="flex flex-col sm:flex-row items-start sm:items-center justify-between">
            <div>
                <h1 class="text-2xl sm:text-3xl font-bold">College Schedule Management</h1>
                <p class="text-gray-300 mt-2"><?php echo htmlspecialchars($college['college_name'] ?? 'College'); ?></p>
            </div>
            <div class="flex items-center text-sm text-gray-300 mt-4 sm:mt-0">
                <svg class="w-4 h-4 mr-1 text-yellow-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M8 7V3m8 4V3m-9 8h10M5 21h14a2 2 0 002-2V7a2 2 0 00-2-2H5a2 2 0 00-2 2v12a2 2 0 002 2z" />
                </svg>
                <?php
                $semName = '';
                $acadYear = '';

                if (!empty($currentSemesterId) && is_array($currentSemesterId)) {
                    // semester_name may be a string or an array
                    if (isset($currentSemesterId['semester_name'])) {
                        $sn = $currentSemesterId['semester_name'];
                        if (is_array($sn)) {
                            // try common keys inside the semester_name array
                            $semName = $sn['name'] ?? $sn['semester_name'] ?? '';
                            $acadYear = $sn['academic_year'] ?? $acadYear;
                        } else {
                            $semName = $sn;
                        }
                    }
                    // academic_year might be at the top level
                    $acadYear = $currentSemesterId['academic_year'] ?? $acadYear;
                }

                $display = trim(
                    ($semName !== '' ? $semName : '') .
                        ($semName !== '' && $acadYear !== '' ? ' — ' : '') .
                        ($acadYear !== '' ? $acadYear : '')
                );

                echo htmlspecialchars($display ?: 'No semester selected');
                ?>
            </div>
        </div>
    </div>

    <!-- Filters -->
    <div class="bg-white rounded-lg shadow-md p-6 mb-6">
        <div class="flex flex-col md:flex-row gap-4 mb-4">
            <select id="department-filter" class="p-3 border border-gray-300 rounded-lg focus:outline-none focus:ring-2 focus:ring-yellow-500 flex-1 md:max-w-xs">
                <option value="">All Departments</option>
                <?php foreach ($departments as $dept): ?>
                    <option value="<?= $dept['department_id'] ?>"><?= htmlspecialchars($dept['department_name']) ?></option>
                <?php endforeach; ?>
            </select>
            <input type="text" id="search-schedule" placeholder="Search by course code, section, or room..." class="p-3 border border-gray-300 rounded-lg focus:outline-none focus:ring-2 focus:ring-yellow-500 flex-1">
        </div>
        <!-- Global Action Buttons -->
        <div class="flex gap-4">
            <button id="approveAllBtn" class="bg-green-500 hover:bg-green-600 text-white px-6 py-2 rounded-lg text-sm font-medium flex items-center">
                <i class="fas fa-check mr-2"></i>Approve All Pending
            </button>
            <button id="rejectAllBtn" class="bg-red-500 hover:bg-red-600 text-white px-6 py-2 rounded-lg text-sm font-medium flex items-center">
                <i class="fas fa-times mr-2"></i>Reject All Pending
            </button>
        </div>
    </div>

    <!-- Approval Modal -->
    <div id="approveModal" class="modal-backdrop fixed inset-0 bg-black/70 backdrop-blur-sm hidden flex items-center justify-center z-50 p-4">
        <div class="modal-content bg-white rounded-2xl shadow-2xl max-w-md w-full overflow-hidden">
            <div class="bg-gradient-to-r from-green-500 to-green-600 px-6 py-4">
                <h3 class="text-xl font-bold text-white flex items-center">
                    <i class="fas fa-check-circle mr-3 text-2xl"></i>
                    Confirm College Dean Approval
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

    <!-- Schedule Table -->
    <div class="bg-white rounded-lg shadow-md overflow-hidden">
        <div class="bg-gradient-to-r from-gray-800 to-gray-900 px-6 py-4 border-l-4 border-yellow-500">
            <h3 class="text-xl font-bold text-white flex items-center">
                <i class="fas fa-calendar-alt mr-3 text-yellow-400"></i>
                All Schedules
            </h3>
        </div>
        <div class="overflow-x-auto">
            <table class="min-w-full divide-y divide-gray-200">
                <thead class="bg-gray-50">
                    <tr>
                        <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                            <i class="fas fa-building mr-1 text-yellow-500"></i> Department
                        </th>
                        <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                            <i class="fas fa-book mr-1 text-yellow-500"></i> Course Code
                        </th>
                        <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                            <i class="fas fa-users mr-1 text-yellow-500"></i> Faculty
                        </th>
                        <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                            <i class="fas fa-layer-group mr-1 text-yellow-500"></i> Section
                        </th>
                        <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                            <i class="fas fa-calendar-day mr-1 text-yellow-500"></i> Days
                        </th>
                        <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                            <i class="fas fa-door-open mr-1 text-yellow-500"></i> Room
                        </th>
                        <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                            <i class="fas fa-exchange-alt mr-1 text-yellow-500"></i> Schedule Type
                        </th>
                        <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                            <i class="fas fa-info-circle mr-1 text-yellow-500"></i> Status
                        </th>
                    </tr>
                </thead>
                <tbody id="scheduleTableBody" class="bg-white divide-y divide-gray-200">
                    <?php if (empty($schedules)): ?>
                        <tr id="noResultsRow" class="hidden">
                            <td colspan="8" class="px-6 py-12 text-center text-gray-500">
                                <div class="flex flex-col items-center">
                                    <i class="fas fa-calendar-times text-6xl text-gray-300 mb-4"></i>
                                    <p class="text-lg font-medium">No schedules found</p>
                                    <p class="text-sm mt-1">Try adjusting your filters or search terms.</p>
                                </div>
                            </td>
                        </tr>
                        <tr>
                            <td colspan="8" class="px-6 py-12 text-center text-gray-500">
                                <div class="flex flex-col items-center">
                                    <i class="fas fa-calendar-times text-6xl text-gray-300 mb-4"></i>
                                    <p class="text-lg font-medium">No schedules found</p>
                                    <p class="text-sm mt-1">Schedules for the current semester will appear here.</p>
                                </div>
                            </td>
                        </tr>
                    <?php else: ?>
                        <?php $allSchedules = [];
                        foreach ($schedules as $deptSchedules):
                            $allSchedules = array_merge($allSchedules, $deptSchedules);
                        endforeach; ?>
                        <?php foreach ($allSchedules as $schedule): ?>
                            <tr class="schedule-row hover:bg-gray-50 transition-colors duration-200"
                                data-dept-id="<?= htmlspecialchars($schedule['department_id'] ?? '') ?>"
                                data-schedule-ids="<?= htmlspecialchars($schedule['schedule_ids']) ?>"
                                data-status="<?= htmlspecialchars($schedule['status']) ?>">
                                <td class="px-6 py-4 text-sm font-medium text-gray-900">
                                    <?php echo htmlspecialchars($schedule['department_name']); ?>
                                </td>
                                <td class="px-6 py-4 text-sm font-medium text-gray-900 course-code-cell">
                                    <?php echo htmlspecialchars($schedule['course_code']); ?>
                                </td>
                                <td class="px-6 py-4 text-sm font-medium text-gray-900 faculty-cell">
                                    <div class="text-sm text-gray-900"><?php echo htmlspecialchars($schedule['faculty_name'] ?? 'TBD'); ?></div>
                                </td>
                                <td class="px-6 py-4 text-sm font-medium text-gray-900 section-cell">
                                    <span class="px-2 py-1 text-xs font-medium bg-yellow-100 text-yellow-800 rounded-full"><?php echo htmlspecialchars($schedule['section_name'] ?? 'N/A'); ?></span>
                                </td>
                                <td class="px-6 py-4 text-sm text-gray-600">
                                    <div class="text-sm font-bold text-gray-900 bg-blue-50 px-2 py-1 rounded inline-block"><?php echo htmlspecialchars($schedule['formatted_days']); ?></div>
                                    <div class="text-xs text-gray-500 mt-1"><?php echo htmlspecialchars(($schedule['start_time'] ?? '') . ' - ' . ($schedule['end_time'] ?? '')); ?></div>
                                </td>
                                <td class="px-6 py-4 text-sm text-gray-600 room-cell">
                                    <?php echo htmlspecialchars($schedule['room_name'] ?? 'TBD'); ?>
                                </td>
                                <td class="px-6 py-4">
                                    <span class="px-3 py-1 text-xs font-semibold rounded-full <?php echo $schedule['schedule_type'] === 'F2F' ? 'bg-blue-100 text-blue-800' : 'bg-gray-100 text-gray-800'; ?>">
                                        <?php echo htmlspecialchars($schedule['schedule_type']); ?>
                                    </span>
                                </td>
                                <td class="px-6 py-4">
                                    <span class="px-3 py-1 text-xs font-semibold rounded-full 
                                        <?php
                                        switch ($schedule['status']) {
                                            case 'Approved':
                                                echo 'bg-green-100 text-green-800';
                                                break;
                                            case 'Rejected':
                                                echo 'bg-red-100 text-red-800';
                                                break;
                                            default:
                                                echo 'bg-yellow-100 text-yellow-800';
                                        }
                                        ?>">
                                        <?php echo htmlspecialchars($schedule['status']); ?>
                                    </span>
                                </td>
                            </tr>
                        <?php endforeach; ?>
                        <!-- Hidden no-results row for dynamic use -->
                        <tr id="noResultsRow" class="hidden">
                            <td colspan="8" class="px-6 py-12 text-center text-gray-500">
                                <div class="flex flex-col items-center">
                                    <i class="fas fa-calendar-times text-6xl text-gray-300 mb-4"></i>
                                    <p class="text-lg font-medium">No schedules found</p>
                                    <p class="text-sm mt-1">Try adjusting your filters or search terms.</p>
                                </div>
                            </td>
                        </tr>
                    <?php endif; ?>
                </tbody>
            </table>
        </div>
    </div>
</div>

<script>
    // Client-side filtering and search functionality
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

                // Department filter
                const matchesDept = !selectedDept || deptId === selectedDept;

                // Search filter
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

            // Show/hide no results row
            if (visibleCount === 0) {
                noResultsRow.style.display = '';
            } else {
                noResultsRow.style.display = 'none';
            }
        }

        // Function to get all pending schedule IDs from visible pending rows
        function getAllPendingIds() {
            const ids = [];
            rows.forEach(row => {
                if (row.style.display !== 'none' && row.dataset.status === 'Pending') {
                    const rowIds = row.dataset.scheduleIds.split(',').map(id => id.trim()).filter(id => id);
                    ids.push(...rowIds);
                }
            });
            return [...new Set(ids)].join(','); // Unique and comma-separated
        }

        // Modal and bulk action handlers
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
                alert('No pending schedules to approve.');
                return;
            }
            approveModal.classList.remove('hidden');
        });

        rejectBtn.addEventListener('click', function() {
            const ids = getAllPendingIds();
            if (ids === '') {
                alert('No pending schedules to reject.');
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
                alert('No pending schedules to approve.');
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
                alert('No pending schedules to reject.');
                rejectModal.classList.add('hidden');
                return;
            }
            bulkIdsInput.value = ids;
            bulkActionInput.value = 'reject';
            bulkForm.submit();
        });

        // Close modals on outside click (optional)
        [approveModal, rejectModal].forEach(modal => {
            modal.addEventListener('click', function(e) {
                if (e.target === modal) {
                    modal.classList.add('hidden');
                }
            });
        });

        // Event listeners for filters
        departmentFilter.addEventListener('change', filterRows);
        searchInput.addEventListener('input', filterRows);

        // Initial filter
        filterRows();
    });
</script>

<?php
$content = ob_get_clean();
require_once __DIR__ . '/layout.php';
?>