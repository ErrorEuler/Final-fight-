<?php
ob_start();
?>

<div class="min-h-screen bg-gradient-to-br from-slate-50 to-blue-50">

    <div class="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8">
        <!-- Error Message -->
        <?php if (isset($error)): ?>
            <div class="mb-6 bg-red-50 border-l-4 border-red-400 p-4 rounded-r-lg">
                <div class="flex">
                    <div class="flex-shrink-0">
                        <svg class="h-5 w-5 text-red-400" fill="currentColor" viewBox="0 0 20 20">
                            <path fill-rule="evenodd" d="M10 18a8 8 0 100-16 8 8 0 000 16zM8.707 7.293a1 1 0 00-1.414 1.414L8.586 10l-1.293 1.293a1 1 0 101.414 1.414L10 11.414l1.293 1.293a1 1 0 001.414-1.414L11.414 10l1.293-1.293a1 1 0 00-1.414-1.414L10 8.586 8.707 7.293z" clip-rule="evenodd"></path>
                        </svg>
                    </div>
                    <div class="ml-3">
                        <p class="text-sm text-red-700 font-medium"><?php echo htmlspecialchars($error); ?></p>
                    </div>
                </div>
            </div>
        <?php endif; ?>

        <!-- Information Cards -->
        <div class="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6 mb-8">
            <!-- Semester Card -->
            <div class="bg-white rounded-xl shadow-sm border border-gray-200 p-6 hover:shadow-md transition-shadow">
                <div class="flex items-center">
                    <div class="flex-shrink-0">
                        <div class="w-10 h-10 bg-blue-100 rounded-lg flex items-center justify-center">
                            <svg class="w-5 h-5 text-blue-600" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M8 7V3m8 4V3m-9 8h10M5 21h14a2 2 0 002-2V7a2 2 0 00-2-2H5a2 2 0 00-2 2v12a2 2 0 002 2z"></path>
                            </svg>
                        </div>
                    </div>
                    <div class="ml-4">
                        <p class="text-sm font-medium text-gray-500">Current Semester</p>
                        <p class="text-lg font-semibold text-gray-900"><?php echo htmlspecialchars($semesterName ?? 'Not Set'); ?></p>
                    </div>
                </div>
            </div>

            <!-- Department Card -->
            <div class="bg-white rounded-xl shadow-sm border border-gray-200 p-6 hover:shadow-md transition-shadow">
                <div class="flex items-center">
                    <div class="flex-shrink-0">
                        <div class="w-10 h-10 bg-indigo-100 rounded-lg flex items-center justify-center">
                            <svg class="w-5 h-5 text-indigo-600" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M19 21V5a2 2 0 00-2-2H7a2 2 0 00-2 2v16m14 0h2m-2 0h-5m-9 0H3m2 0h5M9 7h1m-1 4h1m4-4h1m-1 4h1m-5 10v-5a1 1 0 011-1h2a1 1 0 011 1v5m-4 0h4"></path>
                            </svg>
                        </div>
                    </div>
                    <div class="ml-4">
                        <p class="text-sm font-medium text-gray-500">Department</p>
                        <p class="text-lg font-semibold text-gray-900 truncate"><?php echo htmlspecialchars($departmentName); ?></p>
                    </div>
                </div>
            </div>

            <!-- Total Hours Card -->
            <div class="bg-white rounded-xl shadow-sm border border-gray-200 p-6 hover:shadow-md transition-shadow">
                <div class="flex items-center">
                    <div class="flex-shrink-0">
                        <div class="w-10 h-10 bg-green-100 rounded-lg flex items-center justify-center">
                            <svg class="w-5 h-5 text-green-600" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 8v4l3 3m6-3a9 9 0 11-18 0 9 9 0 0118 0z"></path>
                            </svg>
                        </div>
                    </div>
                    <div class="ml-4">
                        <p class="text-sm font-medium text-gray-500">Weekly Hours</p>
                        <p class="text-lg font-semibold text-gray-900"><?php echo number_format($totalHours ?? 0, 1); ?> hrs</p>
                    </div>
                </div>
            </div>

            <!-- Status Card -->
            <div class="bg-white rounded-xl shadow-sm border border-gray-200 p-6 hover:shadow-md transition-shadow">
                <div class="flex items-center">
                    <div class="flex-shrink-0">
                        <div class="w-10 h-10 bg-purple-100 rounded-lg flex items-center justify-center">
                            <svg class="w-5 h-5 text-purple-600" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z"></path>
                            </svg>
                        </div>
                    </div>
                    <div class="ml-4">
                        <p class="text-sm font-medium text-gray-500">Schedule Status</p>
                        <p class="text-lg font-semibold text-gray-900">
                            <?php echo !empty($schedules) ? 'Active' : 'No Classes'; ?>
                        </p>
                    </div>
                </div>
            </div>
        </div>

        <!-- Action Buttons -->
        <div class="mb-8">
            <div class="bg-white rounded-xl shadow-sm border border-gray-200 p-6">
                <div class="flex flex-col sm:flex-row justify-between items-start sm:items-center space-y-4 sm:space-y-0">
                    <div>
                        <h3 class="text-lg font-semibold text-gray-900 mb-1">Quick Actions</h3>
                        <p class="text-sm text-gray-600">Export or print your teaching schedule</p>
                    </div>
                    <div class="flex flex-col sm:flex-row space-y-3 sm:space-y-0 sm:space-x-4 w-full sm:w-auto">
                        <button
                            onclick="printOfficialSchedule({facultyName: 'FACULTY NAME', position: 'Assistant Professor I'})"
                            class="inline-flex items-center justify-center px-6 py-3 border border-transparent text-base font-medium rounded-lg text-white bg-blue-600 hover:bg-blue-700 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-blue-500 transition-colors w-full sm:w-auto">
                            <svg class="w-5 h-5 mr-2" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M17 17h2a2 2 0 002-2v-4a2 2 0 00-2-2H5a2 2 0 00-2 2v4a2 2 0 002 2h2m2 4h6a2 2 0 002-2v-6a2 2 0 00-2-2H9a2 2 0 00-2 2v6a2 2 0 002 2zm8-12V5a2 2 0 00-2-2H9a2 2 0 00-2 2v4h10z"></path>
                            </svg>
                            Print Schedule
                        </button>
                        <a
                            href="?action=download&format=pdf"
                            class="inline-flex items-center justify-center px-6 py-3 border border-transparent text-base font-medium rounded-lg text-white bg-green-600 hover:bg-green-700 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-green-500 transition-colors w-full sm:w-auto">
                            <svg class="w-5 h-5 mr-2" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 10v6m0 0l-3-3m3 3l3-3m2 8H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z"></path>
                            </svg>
                            Download PDF
                        </a>
                        <button
                            onclick="window.location.reload()"
                            class="inline-flex items-center justify-center px-6 py-3 border border-gray-300 text-base font-medium rounded-lg text-gray-700 bg-white hover:bg-gray-50 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-blue-500 transition-colors w-full sm:w-auto">
                            <svg class="w-5 h-5 mr-2" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 4v5h.582m15.356 2A8.001 8.001 0 004.582 9m0 0H9m11 11v-5h-.581m0 0a8.003 8.003 0 01-15.357-2m15.357 2H15"></path>
                            </svg>
                            Refresh
                        </button>
                    </div>
                </div>

                <?php if (isset($showAllSchedules) && $showAllSchedules): ?>
                    <div class="mt-4 bg-amber-50 border border-amber-200 rounded-lg p-4">
                        <div class="flex">
                            <div class="flex-shrink-0">
                                <svg class="h-5 w-5 text-amber-400" fill="currentColor" viewBox="0 0 20 20">
                                    <path fill-rule="evenodd" d="M8.257 3.099c.765-1.36 2.722-1.36 3.486 0l5.58 9.92c.75 1.334-.213 2.98-1.742 2.98H4.42c-1.53 0-2.493-1.646-1.743-2.98l5.58-9.92zM11 13a1 1 0 11-2 0 1 1 0 012 0zm-1-8a1 1 0 00-1 1v3a1 1 0 002 0V6a1 1 0 00-1-1z" clip-rule="evenodd"></path>
                                </svg>
                            </div>
                            <div class="ml-3">
                                <p class="text-sm text-amber-700 font-medium">
                                    Showing all available schedules (no schedules found for the current semester).
                                </p>
                            </div>
                        </div>
                    </div>
                <?php endif; ?>
            </div>
        </div>

        <!-- Schedule Table -->
        <div class="bg-white rounded-xl shadow-sm border border-gray-200 overflow-hidden">
            <div class="px-6 py-4 border-b border-gray-200 bg-gray-50">
                <div class="flex items-center justify-between">
                    <div>
                        <h3 class="text-lg font-semibold text-gray-900">Teaching Schedule</h3>
                        <p class="text-sm text-gray-600 mt-1">Your current class assignments and timetable</p>
                    </div>
                    <div class="text-sm text-gray-500">
                        <?php if (isset($schedules) && !empty($schedules)): ?>
                            <?php echo count($schedules); ?> classes scheduled
                        <?php else: ?>
                            No classes scheduled
                        <?php endif; ?>
                    </div>
                </div>
            </div>

            <div class="overflow-x-auto">
                <table class="min-w-full divide-y divide-gray-200">
                    <thead class="bg-gray-50">
                        <tr>
                            <th scope="col" class="px-6 py-4 text-left text-xs font-semibold text-gray-700 uppercase tracking-wider">
                                <div class="flex items-center space-x-1">
                                    <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                        <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M7 4V2a1 1 0 011-1h8a1 1 0 011 1v2m3 0H4a2 2 0 00-2 2v12a2 2 0 002 2h16a2 2 0 002-2V6a2 2 0 00-2-2z"></path>
                                    </svg>
                                    <span>Course Code</span>
                                </div>
                            </th>
                            <th scope="col" class="px-6 py-4 text-left text-xs font-semibold text-gray-700 uppercase tracking-wider">
                                <div class="flex items-center space-x-1">
                                    <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                        <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 6.253v13m0-13C10.832 5.477 9.246 5 7.5 5S4.168 5.477 3 6.253v13C4.168 18.477 5.754 18 7.5 18s3.332.477 4.5 1.253m0-13C13.168 5.477 14.754 5 16.5 5c1.746 0 3.332.477 4.5 1.253v13C19.832 18.477 18.246 18 16.5 18c-1.746 0-3.332.477-4.5 1.253"></path>
                                    </svg>
                                    <span>Course Name</span>
                                </div>
                            </th>
                            <th scope="col" class="px-6 py-4 text-left text-xs font-semibold text-gray-700 uppercase tracking-wider">
                                <div class="flex items-center space-x-1">
                                    <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                        <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M17 20h5v-2a3 3 0 00-5.356-1.857M17 20H7m10 0v-2c0-.656-.126-1.283-.356-1.857M7 20H2v-2a3 3 0 015.356-1.857M7 20v-2c0-.656.126-1.283.356-1.857m0 0a5.002 5.002 0 019.288 0M15 7a3 3 0 11-6 0 3 3 0 016 0zm6 3a2 2 0 11-4 0 2 2 0 014 0zM7 10a2 2 0 11-4 0 2 2 0 014 0z"></path>
                                    </svg>
                                    <span>Section</span>
                                </div>
                            </th>
                            <th scope="col" class="px-6 py-4 text-left text-xs font-semibold text-gray-700 uppercase tracking-wider">
                                <div class="flex items-center space-x-1">
                                    <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                        <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M19 21V5a2 2 0 00-2-2H7a2 2 0 00-2 2v16m14 0h2m-2 0h-5m-9 0H3m2 0h5"></path>
                                    </svg>
                                    <span>Room</span>
                                </div>
                            </th>
                            <th scope="col" class="px-6 py-4 text-left text-xs font-semibold text-gray-700 uppercase tracking-wider">
                                <div class="flex items-center space-x-1">
                                    <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                        <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M8 7V3m8 4V3m-9 8h10M5 21h14a2 2 0 002-2V7a2 2 0 00-2-2H5a2 2 0 00-2 2v12a2 2 0 002 2z"></path>
                                    </svg>
                                    <span>Day</span>
                                </div>
                            </th>
                            <th scope="col" class="px-6 py-4 text-left text-xs font-semibold text-gray-700 uppercase tracking-wider">
                                <div class="flex items-center space-x-1">
                                    <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                        <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 8v4l3 3m6-3a9 9 0 11-18 0 9 9 0 0118 0z"></path>
                                    </svg>
                                    <span>Time</span>
                                </div>
                            </th>
                            <th scope="col" class="px-6 py-4 text-left text-xs font-semibold text-gray-700 uppercase tracking-wider">
                                <div class="flex items-center space-x-1">
                                    <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                        <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M7 7h.01M7 3h5c.512 0 1.024.195 1.414.586l7 7a2 2 0 010 2.828l-7 7a1.994 1.994 0 01-2.828 0l-7-7A1.994 1.994 0 013 12V7a4 4 0 014-4z"></path>
                                    </svg>
                                    <span>Type</span>
                                </div>
                            </th>
                        </tr>
                    </thead>
                    <tbody class="bg-white divide-y divide-gray-200">
                        <?php if (isset($schedules) && !empty($schedules)): ?>
                            <?php foreach ($schedules as $index => $schedule): ?>
                                <tr class="hover:bg-gray-50 transition-colors">
                                    <td class="px-6 py-4 whitespace-nowrap">
                                        <div class="flex items-center">
                                            <div class="flex-shrink-0 w-8 h-8 bg-blue-100 rounded-lg flex items-center justify-center">
                                                <span class="text-xs font-bold text-blue-600"><?php echo $index + 1; ?></span>
                                            </div>
                                            <div class="ml-3">
                                                <div class="text-sm font-semibold text-gray-900"><?php echo htmlspecialchars($schedule['course_code'] ?? 'N/A'); ?></div>
                                            </div>
                                        </div>
                                    </td>
                                    <td class="px-6 py-4">
                                        <div class="text-sm text-gray-900 font-medium"><?php echo htmlspecialchars($schedule['course_name'] ?? 'N/A'); ?></div>
                                    </td>
                                    <td class="px-6 py-4 whitespace-nowrap">
                                        <span class="inline-flex items-center px-3 py-1 rounded-full text-xs font-medium bg-indigo-100 text-indigo-800">
                                            <?php echo htmlspecialchars($schedule['section_name'] ?? 'N/A'); ?>
                                        </span>
                                    </td>
                                    <td class="px-6 py-4 whitespace-nowrap">
                                        <div class="flex items-center">
                                            <svg class="w-4 h-4 text-gray-400 mr-2" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M17.657 16.657L13.414 20.9a1.998 1.998 0 01-2.827 0l-4.244-4.243a8 8 0 1111.314 0z"></path>
                                                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M15 11a3 3 0 11-6 0 3 3 0 016 0z"></path>
                                            </svg>
                                            <span class="text-sm text-gray-600"><?php echo htmlspecialchars($schedule['room_name'] ?? 'TBD'); ?></span>
                                        </div>
                                    </td>
                                    <td class="px-6 py-4 whitespace-nowrap">
                                        <span class="inline-flex items-center px-3 py-1 rounded-full text-xs font-medium bg-green-100 text-green-800">
                                            <?php echo htmlspecialchars($schedule['day_of_week'] ?? 'N/A'); ?>
                                        </span>
                                    </td>
                                    <td class="px-6 py-4 whitespace-nowrap">
                                        <div class="flex items-center">
                                            <svg class="w-4 h-4 text-gray-400 mr-2" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 8v4l3 3m6-3a9 9 0 11-18 0 9 9 0 0118 0z"></path>
                                            </svg>
                                            <span class="text-sm font-medium text-gray-900">
                                                <?php echo htmlspecialchars(($schedule['start_time'] ?? '') . ' - ' . ($schedule['end_time'] ?? '')); ?>
                                            </span>
                                        </div>
                                    </td>
                                    <td class="px-6 py-4 whitespace-nowrap">
                                        <?php
                                        $type = strtolower($schedule['schedule_type'] ?? 'lecture');
                                        $typeClass = $type === 'laboratory' ? 'bg-purple-100 text-purple-800' : 'bg-blue-100 text-blue-800';
                                        ?>
                                        <span class="inline-flex items-center px-3 py-1 rounded-full text-xs font-medium <?php echo $typeClass; ?>">
                                            <?php echo ucfirst($schedule['schedule_type'] ?? 'Lecture'); ?>
                                        </span>
                                    </td>
                                </tr>
                            <?php endforeach; ?>
                        <?php else: ?>
                            <tr>
                                <td colspan="7" class="px-6 py-16 text-center">
                                    <div class="flex flex-col items-center">
                                        <svg class="w-12 h-12 text-gray-400 mb-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M8 7V3m8 4V3m-9 8h10M5 21h14a2 2 0 002-2V7a2 2 0 00-2-2H5a2 2 0 00-2 2v12a2 2 0 002 2z"></path>
                                        </svg>
                                        <h3 class="text-lg font-medium text-gray-900 mb-1">No Schedules Available</h3>
                                        <p class="text-gray-500 mb-4">You don't have any classes scheduled for this term.</p>
                                        <button
                                            onclick="window.location.reload()"
                                            class="inline-flex items-center px-4 py-2 border border-transparent text-sm font-medium rounded-md text-blue-700 bg-blue-100 hover:bg-blue-200 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-blue-500 transition-colors">
                                            <svg class="w-4 h-4 mr-2" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 4v5h.582m15.356 2A8.001 8.001 0 004.582 9m0 0H9m11 11v-5h-.581m0 0a8.003 8.003 0 01-15.357-2m15.357 2H15"></path>
                                            </svg>
                                            Refresh Page
                                        </button>
                                    </div>
                                </td>
                            </tr>
                        <?php endif; ?>
                    </tbody>
                </table>
            </div>
        </div>
    </div>
</div>

<!-- ... (previous HTML remains unchanged until the script section) ... -->

<!-- Include your enhanced print function -->
<script>
    function printOfficialSchedule(options = {}) {
        const {
            facultyName = 'FACULTY NAME',
                position = 'Assistant Professor I',
                employmentStatus = 'Regular',
                campusName = 'Main Campus',
                campusAddress = 'Iba, Zambales',
                studentCounts = {},
                additionalInfo = {}
        } = options;

        // Safely retrieve PHP variables with fallback
        const semesterName = '<?php echo htmlspecialchars($semesterName ?? "2nd Semester A.Y. 2024-2025"); ?>';
        const departmentName = '<?php echo htmlspecialchars($departmentName ?? "College of Communication and Information Technology"); ?>';
        const collegeName = '<?php echo htmlspecialchars($collegeName ?? "Not Assigned"); ?>';
        const totalHours = parseFloat(<?php echo json_encode($totalHours ?? 0); ?>);
        const facultyNameFromPHP = '<?php echo htmlspecialchars($facultyName ?? "Not Assigned"); ?>';
        const positionFromPHP = '<?php echo htmlspecialchars($position ?? "Not Assigned"); ?>';
        let schedules = [];
        try {
            schedules = JSON.parse('<?php echo json_encode($schedules ?? []); ?>');
        } catch (e) {
            console.error('Error parsing schedules JSON:', e);
            schedules = [];
        }
        const showAllSchedules = <?php echo json_encode($showAllSchedules ?? false); ?>;

        // Use facultyName from PHP if available, otherwise fallback to options
        const finalFacultyName = facultyNameFromPHP !== 'Not Assigned' ? facultyNameFromPHP : facultyName;

        // Generate schedule rows
        let scheduleRows = '';
        if (Array.isArray(schedules) && schedules.length > 0) {
            schedules.forEach(schedule => {
                const timeRange = `${schedule.start_time || ''}-${schedule.end_time || ''}`;
                const courseInfo = `${schedule.course_code || 'N/A'} - ${schedule.course_name || 'N/A'}`;
                const studentCount = studentCounts[schedule.course_code] || '-';

                scheduleRows += `
                <tr>
                    <td style="border: 1px solid #333; padding: 4px; text-align: center; font-size: 9px;">${timeRange}</td>
                    <td style="border: 1px solid #333; padding: 4px; text-align: center; font-size: 9px;">${schedule.day_of_week || 'N/A'}</td>
                    <td style="border: 1px solid #333; padding: 4px; font-size: 9px;">${courseInfo}</td>
                    <td style="border: 1px solid #333; padding: 4px; text-align: center; font-size: 9px;">${schedule.room_name || 'TBD'}</td>
                    <td style="border: 1px solid #333; padding: 4px; text-align: center; font-size: 9px;">${schedule.section_name || 'N/A'}</td>
                    <td style="border: 1px solid #333; padding: 4px; text-align: center; font-size: 9px;">${studentCount}</td>
                    <td style="border: 1px solid #333; padding: 4px; text-align: center; font-size: 9px;">${schedule.schedule_type || 'N/A'}</td>
                </tr>`;
            });

            const emptyRowsNeeded = Math.max(0, 12 - schedules.length);
            for (let i = 0; i < emptyRowsNeeded; i++) {
                scheduleRows += `
                <tr>
                    <td style="border: 1px solid #333; padding: 8px; font-size: 9px;">&nbsp;</td>
                    <td style="border: 1px solid #333; padding: 8px; font-size: 9px;">&nbsp;</td>
                    <td style="border: 1px solid #333; padding: 8px; font-size: 9px;">&nbsp;</td>
                    <td style="border: 1px solid #333; padding: 8px; font-size: 9px;">&nbsp;</td>
                    <td style="border: 1px solid #333; padding: 8px; font-size: 9px;">&nbsp;</td>
                    <td style="border: 1px solid #333; padding: 8px; font-size: 9px;">&nbsp;</td>
                    <td style="border: 1px solid #333; padding: 8px; font-size: 9px;">&nbsp;</td>
                </tr>`;
            }
        } else {
            scheduleRows = '<tr><td colspan="7" style="border: 1px solid #333; padding: 20px; text-align: center; font-size: 10px;">No schedules found for this term.</td></tr>';
        }

        const excessHours = Math.max(0, totalHours - 24);

        // Reusable components for cleaner template
        const headerSection = `
        <div style="display: flex; align-items: center; margin-bottom: 20px;">
            <div style="width: 80px; height: 80px; margin-right: 20px;">
                <img src="/assets/logo/main_logo/PRMSUlogo.png" style="width: 100%; height: 100%; object-fit: contain;" alt="PRMSU Logo">
            </div>
            <div style="flex: 1; text-align: center;">
                <div style="font-size: 10px; margin-bottom: 2px;">Republic of the Philippines</div>
                <div style="font-size: 14px; font-weight: bold; margin-bottom: 2px;">President Ramon Magsaysay State University</div>
                <div style="font-size: 9px; font-style: italic; margin-bottom: 8px;">(formerly Ramon Magsaysay Technological University)</div>
                <div style="font-size: 12px; font-weight: bold; margin-bottom: 4px;">FACULTY TEACHING LOAD</div>
                <div style="font-size: 10px;">${semesterName}</div>
            </div>
        </div>
    `;

        const facultyInfoTable = `
        <table style="width: 100%; border-collapse: collapse; margin-bottom: 15px; border: 2px solid #333;">
            <tr>
                <td style="border: 1px solid #333; padding: 4px; background-color: #f0f0f0; font-weight: bold; width: 15%; font-size: 9px;">Campus:</td>
                <td style="border: 1px solid #333; padding: 4px; width: 25%; font-size: 9px;">${campusName}</td>
                <td rowspan="3" style="border: 1px solid #333; padding: 4px; background-color: #f0f0f0; font-weight: bold; text-align: center; width: 15%; font-size: 9px; vertical-align: middle;">
                    No. of Units/Hrs.<br/>
                    <table style="width: 100%; margin-top: 5px; border-collapse: collapse;">
                        <tr style="background-color: #e0e0e0;">
                            <td colspan="2" style="border: 1px solid #333; text-align: center; font-weight: bold; font-size: 8px;">Lec.</td>
                            <td colspan="2" style="border: 1px solid #333; text-align: center; font-weight: bold; font-size: 8px;">Lab./RLE</td>
                        </tr>
                        <tr style="background-color: #e0e0e0;">
                            <td style="border: 1px solid #333; text-align: center; font-weight: bold; font-size: 7px;">Units</td>
                            <td style="border: 1px solid #333; text-align: center; font-weight: bold; font-size: 7px;">Hrs.</td>
                            <td style="border: 1px solid #333; text-align: center; font-weight: bold; font-size: 7px;">Units</td>
                            <td style="border: 1px solid #333; text-align: center; font-weight: bold; font-size: 7px;">Hrs.</td>
                        </tr>
                        <tr>
                            <td style="border: 1px solid #333; text-align: center; padding: 15px; font-size: 8px;"></td>
                            <td style="border: 1px solid #333; text-align: center; padding: 15px; font-size: 8px;"></td>
                            <td style="border: 1px solid #333; text-align: center; padding: 15px; font-size: 8px;"></td>
                            <td style="border: 1px solid #333; text-align: center; padding: 15px; font-size: 8px;"></td>
                        </tr>
                    </table>
                </td>
                <td style="border: 1px solid #333; padding: 4px; background-color: #f0f0f0; font-weight: bold; text-align: center; width: 15%; font-size: 9px;">Room</td>
                <td style="border: 1px solid #333; padding: 4px; background-color: #f0f0f0; font-weight: bold; text-align: center; width: 15%; font-size: 9px;">Course/ Yr./Sec.</td>
                <td style="border: 1px solid #333; padding: 4px; background-color: #f0f0f0; font-weight: bold; text-align: center; width: 15%; font-size: 9px;">No. of Students</td>
            </tr>
            <tr>
                <td style="border: 1px solid #333; padding: 4px; background-color: #f0f0f0; font-weight: bold; font-size: 9px;">Address:</td>
                <td style="border: 1px solid #333; padding: 4px; font-size: 9px;">${campusAddress}</td>
                <td rowspan="2" style="border: 1px solid #333; padding: 4px; background-color: #f9f9f9;"></td>
                <td rowspan="2" style="border: 1px solid #333; padding: 4px; background-color: #f9f9f9;"></td>
                <td rowspan="2" style="border: 1px solid #333; padding: 4px; background-color: #f9f9f9;"></td>
            </tr>
            <tr>
                <td style="border: 1px solid #333; padding: 4px; background-color: #f0f0f0; font-weight: bold; font-size: 9px;">College:</td>
                <td style="border: 1px solid #333; padding: 4px; font-size: 9px;">${collegeName}</td>
            </tr>
        </table>
    `;

        const printContent = `
        <div style="width: 100%; font-family: Arial, sans-serif; font-size: 10px; color: #000; background: white;">
            ${headerSection}
            ${facultyInfoTable}
            <div style="text-align: center; font-size: 16px; font-weight: bold; margin: 20px 0; padding: 10px; border: 2px solid #333; background-color: #f9f9f9;">
                ${finalFacultyName.toUpperCase()}
            </div>
            <table style="width: 100%; border-collapse: collapse; border: 2px solid #333; margin-bottom: 15px;">
                <thead>
                    <tr style="background-color: #e0e0e0;">
                        <th style="border: 1px solid #333; padding: 6px; text-align: center; font-weight: bold; font-size: 9px; width: 12%;">Time</th>
                        <th style="border: 1px solid #333; padding: 6px; text-align: center; font-weight: bold; font-size: 9px; width: 8%;">Days</th>
                        <th style="border: 1px solid #333; padding: 6px; text-align: center; font-weight: bold; font-size: 9px; width: 35%;">Course Code and Title</th>
                        <th style="border: 1px solid #333; padding: 6px; text-align: center; font-weight: bold; font-size: 9px; width: 10%;">Room</th>
                        <th style="border: 1px solid #333; padding: 6px; text-align: center; font-weight: bold; font-size: 9px; width: 15%;">Course/ Yr./Sec.</th>
                        <th style="border: 1px solid #333; padding: 6px; text-align: center; font-weight: bold; font-size: 9px; width: 10%;">No. of Students</th>
                        <th style="border: 1px solid #333; padding: 6px; text-align: center; font-weight: bold; font-size: 9px; width: 10%;">Type</th>
                    </tr>
                </thead>
                <tbody>
                    ${scheduleRows}
                </tbody>
            </table>
            <table style="width: 100%; border-collapse: collapse; border: 2px solid #333; margin-bottom: 15px;">
                <tr>
                    <td style="border: 1px solid #333; padding: 4px; background-color: #f0f0f0; font-weight: bold; width: 25%; font-size: 9px;">Employment Status:</td>
                    <td style="border: 1px solid #333; padding: 4px; width: 15%; font-size: 9px;">☐ Regular ☐ Yes ☐ No</td>
                    <td style="border: 1px solid #333; padding: 4px; background-color: #f0f0f0; font-weight: bold; width: 20%; font-size: 9px;">Total Weekly Hours:</td>
                    <td style="border: 1px solid #333; padding: 4px; width: 40%; font-size: 9px;">${totalHours.toFixed(2)} hrs</td>
                </tr>
                <tr>
                    <td style="border: 1px solid #333; padding: 4px; background-color: #f0f0f0; font-weight: bold; font-size: 9px;">Academic Rank:</td>
                    <td style="border: 1px solid #333; padding: 4px; font-size: 9px;">${position}</td>
                    <td style="border: 1px solid #333; padding: 4px; background-color: #f0f0f0; font-weight: bold; font-size: 9px;">Excess (24 Hours):</td>
                    <td style="border: 1px solid #333; padding: 4px; font-size: 9px;">${excessHours.toFixed(2)}</td>
                </tr>
            </table>
            <table style="width: 100%; margin-top: 30px;">
                <tr>
                    <td style="width: 30%; text-align: center;">
                        <div style="border-top: 2px solid #333; margin-top: 40px; padding-top: 5px; font-size: 9px;">
                            <strong>Prepared:</strong><br/>
                            Faculty Signature
                        </div>
                    </td>
                    <td style="width: 40%; text-align: center;">
                        <div style="border-top: 2px solid #333; margin-top: 40px; padding-top: 5px; font-size: 9px;">
                            <strong>Recommending Approval:</strong><br/>
                            Department Head
                        </div>
                    </td>
                    <td style="width: 30%; text-align: center;">
                        <div style="border-top: 2px solid #333; margin-top: 40px; padding-top: 5px; font-size: 9px;">
                            <strong>Approved:</strong><br/>
                            Dean/Director
                        </div>
                    </td>
                </tr>
            </table>
            <div style="margin-top: 20px; text-align: right; font-size: 7px; color: #666;">
                Reference no.: PRMSU-ASA-COMP16 (16)<br/>
                Effectivity date: May 04, 2021<br/>
                Revision no.: 09
            </div>
            ${showAllSchedules ? '<p style="text-align: center; color: #e76f51; font-size: 10px; margin-top: 10px;">Showing all schedules (no schedules found for the current semester).</p>' : ''}
        </div>
    `;

        const printWindow = window.open('', '', 'height=800,width=1200');
        if (!printWindow) {
            alert('Popup blocked. Please allow popups for this site to print the schedule.');
            return;
        }

        printWindow.document.write('<html><head><title>Faculty Teaching Load</title>');
        printWindow.document.write(`
        <style>
            @page { size: landscape; margin: 15mm; }
            body { margin: 0; padding: 0; font-family: Arial, sans-serif; background: white; color: black; }
            table { page-break-inside: avoid; }
            .no-break { page-break-inside: avoid; }
            @media print {
                body { -webkit-print-color-adjust: exact; }
                table, tr, td, th { border-color: #333 !important; }
            }
        </style>
    `);
        printWindow.document.write('</head><body>');
        printWindow.document.write(printContent);
        printWindow.document.write('</body></html>');
        printWindow.document.close();
        printWindow.focus();

        setTimeout(() => {
            printWindow.print();
            printWindow.close();
        }, 500);
    }

    // Show loading state for buttons
    function showButtonLoading(button, originalText) {
        button.innerHTML = `
        <svg class="animate-spin -ml-1 mr-2 h-4 w-4 text-white" xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24">
            <circle class="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" stroke-width="4"></circle>
            <path class="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z"></path>
        </svg>
        Loading...
    `;
        button.disabled = true;

        setTimeout(() => {
            button.innerHTML = originalText;
            button.disabled = false;
        }, 2000);
    }

    // Enhanced button click handlers
    document.addEventListener('DOMContentLoaded', function() {
        // Add smooth scrolling for better UX
        document.querySelectorAll('a[href^="#"]').forEach(anchor => {
            anchor.addEventListener('click', function(e) {
                e.preventDefault();
                const target = document.querySelector(this.getAttribute('href'));
                if (target) {
                    target.scrollIntoView({
                        behavior: 'smooth',
                        block: 'start'
                    });
                }
            });
        });

        // Add loading states to action buttons
        const printButton = document.querySelector('button[onclick*="printOfficialSchedule"]');
        if (printButton) {
            printButton.addEventListener('click', function() {
                const originalText = this.innerHTML;
                showButtonLoading(this, originalText);
            });
        }

        // Auto-refresh functionality (optional)
        let autoRefreshInterval;
        const enableAutoRefresh = false; // Set to true if you want auto-refresh

        if (enableAutoRefresh) {
            autoRefreshInterval = setInterval(() => {
                // Check if there are any changes needed
                console.log('Auto-refresh check...');
            }, 300000); // 5 minutes
        }

        // Cleanup on page unload
        window.addEventListener('beforeunload', function() {
            if (autoRefreshInterval) {
                clearInterval(autoRefreshInterval);
            }
        });
    });
</script>

<?php
$content = ob_get_clean();
require_once __DIR__ . '/layout.php';
?>