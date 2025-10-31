<?php
ob_start();
?>

<div class="min-h-screen bg-gradient-to-br from-gray-50 to-gray-100 font-sans text-gray-800">
    <div class="container mx-auto p-4 sm:p-6 lg:p-8">
        <!-- Notifications -->
        <?php if (isset($error)): ?>
            <div class="bg-red-50 border-l-4 border-red-400 p-4 rounded-lg mb-6 shadow-md animate-fade-in" role="alert">
                <div class="flex items-center">
                    <svg class="h-5 w-5 text-red-400 mr-3" viewBox="0 0 20 20" fill="currentColor">
                        <path fill-rule="evenodd" d="M10 18a8 8 0 100-16 8 8 0 000 16zM8.707 7.293a1 1 0 00-1.414 1.414L8.586 10l-1.293 1.293a1 1 0 101.414 1.414L10 11.414l1.293 1.293a1 1 0 001.414-1.414L11.414 10l1.293-1.293a1 1 0 00-1.414-1.414L10 8.586 8.707 7.293z" clip-rule="evenodd" />
                    </svg>
                    <p class="text-sm font-medium text-red-800"><?php echo nl2br(htmlspecialchars($error)); ?></p>
                </div>
            </div>
        <?php endif; ?>

        <?php if (isset($success)): ?>
            <div class="bg-green-50 border-l-4 border-green-400 p-4 rounded-lg mb-6 shadow-md animate-fade-in" role="alert">
                <div class="flex items-center">
                    <svg class="h-5 w-5 text-green-400 mr-3" viewBox="0 0 20 20" fill="currentColor">
                        <path fill-rule="evenodd" d="M10 18a8 8 0 100-16 8 8 0 000 16zm3.707-9.293a1 1 0 00-1.414-1.414L9 10.586 7.707 9.293a1 1 0 00-1.414 1.414l2 2a1 1 0 001.414 0l4-4z" clip-rule="evenodd" />
                    </svg>
                    <p class="text-sm font-medium text-green-800"><?php echo htmlspecialchars($success); ?></p>
                </div>
            </div>
        <?php endif; ?>

        <!-- Filter Section -->
        <div class="bg-white rounded-xl shadow-lg p-6 mb-8 border border-gray-200">
            <div class="flex items-center mb-6">
                <div class="bg-blue-100 rounded-lg p-2 mr-3">
                    <svg class="w-5 h-5 text-blue-600" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                        <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M3 4a1 1 0 011-1h16a1 1 0 011 1v2.586a1 1 0 01-.293.707l-6.414 6.414a1 1 0 00-.293.707V17l-4 4v-6.586a1 1 0 00-.293-.707L3.293 7.707A1 1 0 013 7V4z"></path>
                    </svg>
                </div>
                <h2 class="text-xl font-bold text-gray-900">Filter Schedules</h2>
            </div>

            <form method="POST" action="/chair/schedule_history" class="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4 items-end">
                <input type="hidden" name="tab" value="history">

                <!-- Semester Dropdown -->
                <div class="space-y-2">
                    <label for="semester_id" class="block text-sm font-medium text-gray-700">Semester</label>
                    <select name="semester_id" id="semester_id" class="w-full px-4 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-yellow-500 focus:border-yellow-500 bg-white text-sm transition-all duration-200 hover:border-yellow-400" onchange="this.form.submit()">
                        <option value="">All Semesters</option>
                        <?php foreach ($allSemesters as $semester): ?>
                            <option value="<?php echo htmlspecialchars($semester['semester_id']); ?>"
                                <?php echo (isset($_POST['semester_id']) && $_POST['semester_id'] == $semester['semester_id']) ? 'selected' : ''; ?>>
                                <?php echo htmlspecialchars($semester['semester_name'] . ' - ' . $semester['academic_year']); ?>
                            </option>
                        <?php endforeach; ?>
                    </select>
                </div>

                <!-- Academic Year Dropdown -->
                <div class="space-y-2">
                    <label for="academic_year" class="block text-sm font-medium text-gray-700">Academic Year</label>
                    <select name="academic_year" id="academic_year" class="w-full px-4 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-yellow-500 focus:border-yellow-500 bg-white text-sm transition-all duration-200 hover:border-yellow-400" onchange="this.form.submit()">
                        <option value="">All Years</option>
                        <?php
                        $years = array_unique(array_column($allSemesters, 'academic_year'));
                        rsort($years);
                        foreach ($years as $year): ?>
                            <option value="<?php echo htmlspecialchars($year); ?>"
                                <?php echo (isset($_POST['academic_year']) && $_POST['academic_year'] == $year) ? 'selected' : ''; ?>>
                                <?php echo htmlspecialchars($year); ?>
                            </option>
                        <?php endforeach; ?>
                    </select>
                </div>

                <!-- View Button -->
                <div>
                    <button type="submit" class="w-full bg-gradient-to-r from-yellow-600 to-yellow-700 text-white font-semibold py-2 px-4 rounded-lg shadow-md hover:from-yellow-700 hover:to-yellow-800 transition-all duration-200 focus:outline-none focus:ring-2 focus:ring-yellow-500 focus:ring-offset-2">
                        <div class="flex items-center justify-center">
                            <svg class="w-4 h-4 mr-2" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M21 21l-6-6m2-5a7 7 0 11-14 0 7 7 0 0114 0z"></path>
                            </svg>
                            View Schedules
                        </div>
                    </button>
                </div>

                <!-- Clear Filters Button -->
                <div>
                    <a href="/chair/schedule_history" class="w-full block text-center bg-gray-100 text-gray-700 font-semibold py-2 px-4 rounded-lg shadow hover:bg-gray-200 transition-all duration-200 focus:outline-none focus:ring-2 focus:ring-gray-500 focus:ring-offset-2">
                        Clear Filters
                    </a>
                </div>
            </form>
        </div>

        <!-- Schedule List -->
        <?php if (!empty($historicalSchedules)): ?>
            <div class="bg-white rounded-xl shadow-lg border border-gray-200 overflow-hidden">
                <div class="bg-gradient-to-r from-gray-800 to-gray-900 px-6 py-4">
                    <div class="flex items-center justify-between">
                        <div>
                            <h2 class="text-xl font-bold text-white">Historical Schedules</h2>
                            <p class="text-sm text-gray-300"><?php echo count($historicalSchedules); ?> record(s) found</p>
                        </div>
                        <div class="flex space-x-3">
                            <button class="bg-green-600 hover:bg-green-700 text-white px-3 py-2 rounded-lg flex items-center text-sm transition-colors duration-200">
                                <svg class="w-4 h-4 mr-1" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                    <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 10v6m0 0l-3-3m3 3l3-3m2 8H7a2 2 0 01-2-2V7a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z"></path>
                                </svg>
                                Export
                            </button>
                            <button class="bg-blue-600 hover:bg-blue-700 text-white px-3 py-2 rounded-lg flex items-center text-sm transition-colors duration-200">
                                <svg class="w-4 h-4 mr-1" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                    <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M17 17h2a2 2 0 002-2v-4a2 2 0 00-2-2H5a2 2 0 00-2 2v4a2 2 0 002 2h2m2 4h6a2 2 0 002-2v-4a2 2 0 00-2-2H9a2 2 0 00-2 2v4a2 2 0 002 2zm8-12V5a2 2 0 00-2-2H9a2 2 0 00-2 2v4h10z"></path>
                                </svg>
                                Print
                            </button>
                        </div>
                    </div>
                </div>

                <div class="p-6">
                    <ul class="space-y-4">
                        <?php
                        $currentPeriod = '';
                        foreach ($historicalSchedules as $schedule):
                            $period = $schedule['semester_name'] . ' - ' . $schedule['academic_year'];
                        ?>
                            <li class="bg-white rounded-lg shadow-md border border-gray-200 hover:shadow-lg transition-shadow duration-200">
                                <div class="p-4 border-b border-gray-200">
                                    <?php if ($period !== $currentPeriod): ?>
                                        <div class="flex items-center mb-2">
                                            <div class="bg-yellow-100 rounded-full p-1.5 mr-2">
                                                <svg class="w-4 h-4 text-yellow-600" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                                    <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M8 7V3m8 4V3m-9 8h10M5 21h14a2 2 0 002-2V7a2 2 0 00-2-2H5a2 2 0 00-2 2v12a2 2 0 002 2z"></path>
                                                </svg>
                                            </div>
                                            <div>
                                                <h3 class="text-sm font-semibold text-gray-900"><?php echo htmlspecialchars($schedule['semester_name']); ?></h3>
                                                <p class="text-xs text-gray-500"><?php echo htmlspecialchars($schedule['academic_year']); ?></p>
                                            </div>
                                        </div>
                                        <?php $currentPeriod = $period; ?>
                                    <?php endif; ?>
                                </div>
                                <div class="p-4">
                                    <div class="flex items-center justify-between mb-2">
                                        <span class="inline-flex items-center px-2 py-1 rounded-full text-sm font-medium bg-blue-100 text-blue-800">
                                            <?php echo htmlspecialchars($schedule['course_code']); ?>
                                        </span>
                                        <span class="inline-flex items-center px-2 py-1 rounded-full text-sm font-medium bg-indigo-100 text-indigo-800">
                                            <?php echo htmlspecialchars($schedule['units']); ?> Units
                                        </span>
                                    </div>
                                    <h4 class="text-sm font-medium text-gray-900 mb-1"><?php echo htmlspecialchars($schedule['course_name']); ?></h4>
                                    <p class="text-xs text-gray-600 mb-2">Instructor: <?php echo htmlspecialchars($schedule['faculty_name']); ?></p>
                                    <div class="flex items-center justify-between text-sm">
                                        <span class="font-medium text-gray-900"><?php echo htmlspecialchars($schedule['day_of_week']); ?></span>
                                        <span class="text-gray-600"><?php echo htmlspecialchars($schedule['start_time'] . ' - ' . $schedule['end_time']); ?></span>
                                    </div>
                                    <div class="mt-2 flex justify-between">
                                        <span class="inline-flex items-center px-2 py-1 rounded-full text-xs font-medium bg-purple-100 text-purple-800">
                                            <?php echo htmlspecialchars($schedule['section_name']); ?>
                                        </span>
                                        <span class="inline-flex items-center px-2 py-1 rounded-full text-xs font-medium bg-purple-100 text-purple-800">
                                            <?php echo htmlspecialchars($schedule['room_name']); ?>
                                        </span>
                                    </div>
                                    <div class="mt-3 text-center">
                                        <span class="inline-flex items-center px-2 py-1 rounded-full text-xs font-medium bg-green-100 text-green-800">
                                            <svg class="w-3 h-3 mr-1" fill="currentColor" viewBox="0 0 20 20">
                                                <path fill-rule="evenodd" d="M16.707 5.293a1 1 0 010 1.414l-8 8a1 1 0 01-1.414 0l-4-4a1 1 0 011.414-1.414L8 12.586l7.293-7.293a1 1 0 011.414 0z" clip-rule="evenodd"></path>
                                            </svg>
                                            Active
                                        </span>
                                    </div>
                                </div>
                            </li>
                        <?php endforeach; ?>
                    </ul>

                    <div class="bg-gray-50 px-6 py-4 mt-6 border-t border-gray-200">
                        <div class="flex items-center justify-between text-sm">
                            <div class="flex space-x-6">
                                <span class="text-gray-600">Total Records: <span class="font-semibold text-gray-900"><?php echo count($historicalSchedules); ?></span></span>
                                <span class="text-gray-600">Total Units: <span class="font-semibold text-gray-900"><?php echo array_sum(array_column($historicalSchedules, 'units')) ?: '0'; ?></span></span>
                            </div>
                            <span class="text-gray-500">Last updated: <?php echo date('M d, Y H:i'); ?></span>
                        </div>
                    </div>
                </div>
            </div>
        <?php else: ?>
            <div class="bg-white rounded-xl shadow-lg p-8 text-center border border-gray-200">
                <div class="bg-gray-100 rounded-full w-24 h-24 mx-auto mb-6 flex items-center justify-center">
                    <svg class="w-12 h-12 text-gray-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                        <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 12h6m-6 4h6m2 5H7a2 2 0 01-2-2V7a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z"></path>
                    </svg>
                </div>
                <h3 class="text-lg font-semibold text-gray-900 mb-2">No Historical Records Found</h3>
                <p class="text-gray-600 mb-6">There are no schedule records matching your current filter criteria.</p>
                <a href="/chair/schedule_history" class="inline-flex items-center px-4 py-2 bg-yellow-600 text-white rounded-lg hover:bg-yellow-700 transition-colors duration-200">
                    <svg class="w-4 h-4 mr-2" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                        <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 4v5h.582m15.356 2A8.001 8.001 0 004.582 9m0 0H9m11 11v-5h-.581m0 0a8.003 8.003 0 01-15.357-2m15.357 2H15"></path>
                    </svg>
                    Clear All Filters
                </a>
            </div>
        <?php endif; ?>
    </div>
</div>

<!-- Custom Styles -->
<style>
    @keyframes fade-in {
        from {
            opacity: 0;
            transform: translateY(-10px);
        }

        to {
            opacity: 1;
            transform: translateY(0);
        }
    }

    .animate-fade-in {
        animation: fade-in 0.3s ease-out;
    }

    .hover\:shadow-lg:hover {
        box-shadow: 0 10px 15px -3px rgba(0, 0, 0, 0.1), 0 4px 6px -2px rgba(0, 0, 0, 0.05);
    }

    /* Responsive adjustments */
    @media (max-width: 640px) {
        .grid-cols-4 {
            grid-template-columns: 1fr;
        }
    }

    @media (min-width: 641px) and (max-width: 1024px) {
        .grid-cols-4 {
            grid-template-columns: repeat(2, 1fr);
        }
    }
</style>

<?php
$content = ob_get_clean();
require_once __DIR__ . '/layout.php';
?>