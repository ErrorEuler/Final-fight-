<?php
ob_start();
// Get department ID
$userDepartmentId = $_SESSION['department_id'] ?? null;
// Fetch college logo based on department ID
$collegeLogoPath = '/assets/logo/main_logo/PRMSUlogo.png'; // Fallback to university logo
if ($userDepartmentId) {
    try {
        $db = (new Database())->connect();
        $stmt = $db->prepare("SELECT c.logo_path FROM colleges c JOIN departments d ON c.college_id = d.college_id WHERE d.department_id = :department_id");
        $stmt->execute([':department_id' => $userDepartmentId]);
        $logoPath = $stmt->fetchColumn();
        if ($logoPath) {
            $collegeLogoPath = $logoPath;
        }
    } catch (PDOException $e) {
        error_log("layout: Error fetching college logo - " . $e->getMessage());
    }
}
?>

<link rel="stylesheet" href="/css/schedule_management.css">

<!-- Force Git to track this change -->


<div class="bg-gray-50 min-h-screen">
    <!-- Header -->
    <header class="bg-white shadow-lg border-b border-gray-200">
        <div class="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
            <div class="flex justify-between items-center py-6">
                <div class="flex items-center space-x-4">
                    <div class="bg-yellow-500 p-3 rounded-lg">
                        <i class="fas fa-calendar-alt text-white text-xl"></i>
                    </div>
                    <div>
                        <h1 class="text-2xl font-bold text-gray-900">Schedule Management</h1>
                        <p class="text-sm text-gray-600">Organize and manage academic schedules</p>
                    </div>
                </div>
                <!-- Print Options -->
                <div class="relative">
                    <button id="printDropdownBtn" onclick="togglePrintDropdown()" class="bg-gray-800 hover:bg-gray-700 text-white px-4 py-2 rounded-lg flex items-center space-x-2 transition-colors">
                        <i class="fas fa-print"></i>
                        <span>Print/Export</span>
                        <i class="fas fa-chevron-down ml-1"></i>
                    </button>
                    <div id="printDropdown" class="hidden absolute right-0 mt-2 w-56 bg-white rounded-md shadow-lg z-50 border border-gray-200">
                        <div class="py-1">
                            <button onclick="printSchedule('all')" class="block w-full text-left px-4 py-2 text-sm text-gray-700 hover:bg-gray-100">
                                <i class="fas fa-print mr-2"></i>Print All Schedules
                            </button>
                            <button onclick="printSchedule('filtered')" class="block w-full text-left px-4 py-2 text-sm text-gray-700 hover:bg-gray-100">
                                <i class="fas fa-filter mr-2"></i>Print Filtered View
                            </button>
                            <div class="border-t border-gray-200 my-1"></div>
                            <button onclick="exportSchedule('excel')" class="block w-full text-left px-4 py-2 text-sm text-gray-700 hover:bg-gray-100">
                                <i class="fas fa-file-excel mr-2 text-green-600"></i>Export to Excel
                            </button>
                            <button onclick="exportSchedule('pdf')" class="block w-full text-left px-4 py-2 text-sm text-gray-700 hover:bg-gray-100">
                                <i class="fas fa-file-pdf mr-2 text-red-600"></i>Export to PDF
                            </button>
                        </div>
                    </div>
                </div>
            </div>
        </div>
    </header>

    <div class="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8">
        <!-- Notifications -->
        <?php if (isset($error)): ?>
            <div class="mb-6 flex items-center p-4 bg-red-50 border border-red-200 rounded-lg">
                <i class="fas fa-exclamation-circle text-red-500 text-xl mr-3"></i>
                <p class="text-sm font-medium text-red-800"><?php echo nl2br(htmlspecialchars($error)); ?></p>
            </div>
        <?php endif; ?>

        <?php if (isset($success)): ?>
            <div class="mb-6 flex items-center p-4 bg-green-50 border border-green-200 rounded-lg">
                <i class="fas fa-check-circle text-green-500 text-xl mr-3"></i>
                <p class="text-sm font-medium text-green-800"><?php echo htmlspecialchars($success); ?></p>
            </div>
        <?php endif; ?>

        <!-- Add this after your notifications section -->
        <?php
        // Check if there are unassigned courses or incomplete schedules
        $hasIncompleteSchedules = false;
        $unassignedCourses = [];

        if (isset($schedules) && is_array($schedules)) {
            // Get all curriculum courses for current semester
            $allCurriculumCourses = $jsData['curriculumCourses'] ?? [];
            $scheduledCourseCodes = array_unique(array_column($schedules, 'course_code'));

            // Find unscheduled courses
            foreach ($allCurriculumCourses as $course) {
                if (!in_array($course['course_code'], $scheduledCourseCodes)) {
                    $unassignedCourses[] = $course;
                }
            }

            $hasIncompleteSchedules = !empty($unassignedCourses);
        }
        ?>

        <!-- Incomplete Schedule Warning Banner -->
        <?php if ($hasIncompleteSchedules && $activeTab === 'manual'): ?>
            <div id="incomplete-schedule-banner" class="mb-6 flex items-center p-4 bg-yellow-50 border border-yellow-200 rounded-lg">
                <div class="flex-shrink-0">
                    <i class="fas fa-exclamation-triangle text-yellow-500 text-xl mr-3"></i>
                </div>
                <div class="flex-1">
                    <h3 class="text-sm font-semibold text-yellow-800">Incomplete Schedule Detected</h3>
                    <p class="text-sm text-yellow-700 mt-1">
                        <?php echo count($unassignedCourses); ?> course(s) could not be scheduled automatically.
                        You may need to manually schedule these courses.
                    </p>
                    <div class="mt-2">
                        <button onclick="toggleUnassignedCourses()" class="text-sm text-yellow-600 hover:text-yellow-800 font-medium flex items-center">
                            <span>View Unscheduled Courses</span>
                            <i class="fas fa-chevron-down ml-1 text-xs"></i>
                        </button>
                    </div>
                    <div id="unassigned-courses-list" class="hidden mt-3 p-3 bg-yellow-100 rounded-lg">
                        <h4 class="text-sm font-semibold text-yellow-800 mb-2">Unscheduled Courses:</h4>
                        <div class="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-2">
                            <?php foreach ($unassignedCourses as $course): ?>
                                <div class="text-sm text-yellow-700 p-2 bg-white rounded border border-yellow-200">
                                    <div class="font-medium"><?php echo htmlspecialchars($course['course_code']); ?></div>
                                    <div class="text-xs"><?php echo htmlspecialchars($course['course_name']); ?></div>
                                    <div class="text-xs text-yellow-600 mt-1">
                                        Year: <?php echo htmlspecialchars($course['curriculum_year']); ?> •
                                        Units: <?php echo htmlspecialchars($course['units']); ?>
                                    </div>
                                </div>
                            <?php endforeach; ?>
                        </div>
                        <div class="mt-3 flex space-x-2">
                            <button onclick="tryRegenerateIncomplete()" class="px-3 py-1 bg-yellow-500 hover:bg-yellow-600 text-white text-sm rounded transition-colors">
                                <i class="fas fa-sync-alt mr-1"></i>Try Regenerate
                            </button>
                            <button onclick="hideIncompleteWarning()" class="px-3 py-1 bg-gray-500 hover:bg-gray-600 text-white text-sm rounded transition-colors">
                                <i class="fas fa-times mr-1"></i>Dismiss
                            </button>
                        </div>
                    </div>
                </div>
            </div>
        <?php endif; ?>

        <!-- Navigation Tabs -->
        <div class="mb-8">
            <nav class="flex space-x-1 bg-white rounded-lg p-1 shadow-sm border border-gray-200">
                <button onclick="switchTab('generate')" id="tab-generate" class="tab-button flex-1 py-3 px-4 text-sm font-medium rounded-md transition-all duration-200 <?php echo $activeTab === 'generate' ? 'bg-yellow-500 text-white' : 'text-gray-700 hover:text-gray-900 hover:bg-gray-100'; ?>">
                    <i class="fas fa-magic mr-2"></i>
                    <span class="hidden sm:inline">Generate Schedules</span>
                    <span class="sm:hidden">Generate</span>
                </button>
                <button onclick="switchTab('manual')" id="tab-manual" class="tab-button flex-1 py-3 px-4 text-sm font-medium rounded-md transition-all duration-200 <?php echo $activeTab === 'manual' ? 'bg-yellow-500 text-white' : 'text-gray-700 hover:text-gray-900 hover:bg-gray-100'; ?>">
                    <i class="fas fa-edit mr-2"></i>
                    <span class="hidden sm:inline">Manual Edit</span>
                    <span class="sm:hidden">Manual</span>
                </button>
                <button onclick="switchTab('schedule')" id="tab-schedule" class="tab-button flex-1 py-3 px-4 text-sm font-medium rounded-md transition-all duration-200 <?php echo $activeTab === 'schedule-list' ? 'bg-yellow-500 text-white' : 'text-gray-700 hover:text-gray-900 hover:bg-gray-100'; ?>">
                    <i class="fas fa-calendar mr-2"></i>
                    <span class="hidden sm:inline">View Schedule</span>
                    <span class="sm:hidden">View</span>
                </button>
            </nav>
        </div>

        <!-- Generate Tab -->
        <div id="content-generate" class="tab-content <?php echo $activeTab !== 'generate' ? 'hidden' : ''; ?>">
            <div class="bg-white rounded-xl shadow-lg border border-gray-200 p-6">
                <div class="flex items-center mb-6">
                    <div class="bg-yellow-500 p-2 rounded-lg mr-3">
                        <i class="fas fa-magic text-white"></i>
                    </div>
                    <h2 class="text-xl font-bold text-gray-900">Generate Schedules</h2>
                </div>

                <form id="generate-form" class="space-y-6">
                    <input type="hidden" name="tab" value="generate">
                    <input type="hidden" name="semester_id" value="<?php echo htmlspecialchars($currentSemester['semester_id'] ?? ''); ?>">

                    <div class="bg-yellow-50 border border-yellow-200 rounded-lg p-4">
                        <div class="flex items-center">
                            <i class="fas fa-info-circle text-yellow-600 mr-2"></i>
                            <span class="text-sm font-medium text-gray-800">Current Semester: <?php echo htmlspecialchars($currentSemester['semester_name'] ?? 'Not Set'); ?> Semester</span>
                            <span class="text-sm font-medium text-gray-800 ml-4">A.Y <?php echo htmlspecialchars($currentSemester['academic_year'] ?? 'Not Set'); ?></span>
                        </div>
                    </div>

                    <div class="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
                        <div>
                            <label class="block text-sm font-semibold text-gray-700 mb-2">Curriculum</label>
                            <select name="curriculum_id" id="curriculum_id" class="w-full px-4 py-3 border border-gray-300 rounded-lg focus:ring-2 focus:ring-yellow-500 focus:border-yellow-500 bg-white" onchange="updateCourses()" required>
                                <option value="">Select Curriculum</option>
                                <?php foreach ($curricula as $curriculum): ?>
                                    <option value="<?php echo htmlspecialchars($curriculum['curriculum_id']); ?>">
                                        <?php echo htmlspecialchars($curriculum['curriculum_name']); ?>
                                    </option>
                                <?php endforeach; ?>
                            </select>
                        </div>

                        <div>
                            <h3 class="text-lg font-semibold text-gray-900 mb-4">Available Courses</h3>
                            <div id="courses-list" class="bg-white border border-gray-200 rounded-lg shadow-sm p-4 h-80 overflow-y-auto">
                                <p class="text-sm text-gray-600">Please select a curriculum to view available courses.</p>
                            </div>
                        </div>

                        <div>
                            <h3 class="text-lg font-semibold text-gray-900 mb-4">Available Sections</h3>
                            <div id="sections-list" class="bg-white border scroll-auto border-gray-200 rounded-lg shadow-sm p-4 h-80 overflow-y-auto">
                                <?php if (!empty($jsData['sectionsData'])): ?>
                                    <ul class="list-disc pl-5 text-sm text-gray-700">
                                        <?php foreach ($jsData['sectionsData'] as $section): ?>
                                            <li class="py-1">
                                                <?php echo htmlspecialchars($section['section_name']); ?> -
                                                <?php echo htmlspecialchars($section['year_level']); ?>
                                                (Students: <?php echo htmlspecialchars($section['current_students']); ?>/<?php echo htmlspecialchars($section['max_students']); ?>)
                                            </li>
                                        <?php endforeach; ?>
                                    </ul>
                                <?php else: ?>
                                    <p class="text-sm text-red-600">No sections found for the current semester.</p>
                                <?php endif; ?>
                            </div>
                        </div>
                    </div>

                    <div class="flex justify-end">
                        <button type="button" id="generate-btn" class="bg-yellow-500 hover:bg-yellow-600 text-white font-semibold px-8 py-3 rounded-lg shadow-sm transition-all duration-200 transform hover:scale-105">
                            <i class="fas fa-magic mr-2"></i>
                            Generate Schedules
                        </button>
                    </div>
                </form>

                <!-- Generation Results -->
                <div id="generation-results" class="hidden mt-8 p-6 bg-green-50 border border-green-200 rounded-lg">
                    <div class="flex items-center mb-4">
                        <i class="fas fa-check-circle text-green-500 text-xl mr-3"></i>
                        <h3 class="text-lg font-semibold text-green-800">Schedules Generated Successfully!</h3>
                    </div>
                    <div class="grid grid-cols-1 md:grid-cols-3 gap-4 text-sm">
                        <div class="bg-white p-3 rounded-lg text-center">
                            <div class="text-2xl font-bold text-green-600" id="total-courses">0</div>
                            <div class="text-gray-600">Courses Scheduled</div>
                        </div>
                        <div class="bg-white p-3 rounded-lg text-center">
                            <div class="text-2xl font-bold text-green-600" id="total-sections">0</div>
                            <div class="text-gray-600">Sections</div>
                        </div>
                        <div class="bg-white p-3 rounded-lg text-center">
                            <div class="text-2xl font-bold text-green-600" id="success-rate">100%</div>
                            <div class="text-gray-600">Success Rate</div>
                        </div>
                    </div>
                </div>
            </div>
        </div>

        <!-- Fixed Manual Edit Tab -->
        <div id="content-manual" class="tab-content <?php echo $activeTab !== 'manual' ? 'hidden' : ''; ?>">
            <div class="bg-white rounded-xl shadow-lg border border-gray-200 p-6">
                <!-- Header Section -->
                <div class="mb-6">
                    <!-- Title Row -->
                    <div class="flex flex-col lg:flex-row lg:items-center lg:justify-between gap-4 mb-4">
                        <div class="flex items-center">
                            <div class="bg-yellow-500 p-2 rounded-lg mr-3">
                                <i class="fas fa-edit text-white"></i>
                            </div>
                            <div>
                                <h2 class="text-xl font-bold text-gray-900">Manual Schedule Editor</h2>
                                <p class="text-sm text-gray-600 mt-1">Drag and drop to edit schedules</p>
                            </div>
                        </div>

                        <!-- Full Screen Buttons -->
                        <div class="flex items-center space-x-2">
                            <button id="fullscreen-manual-btn" class="bg-blue-500 hover:bg-blue-600 text-white px-4 py-2 rounded-lg flex items-center space-x-2 transition-colors text-sm" onclick="toggleFullScreen('manual')">
                                <i class="fas fa-expand mr-1"></i>
                                <span class="hidden sm:inline">Full Screen</span>
                            </button>
                            <button id="exit-fullscreen-manual-btn" class="bg-gray-600 hover:bg-gray-700 text-white px-4 py-2 rounded-lg flex items-center space-x-2 transition-colors hidden text-sm" onclick="toggleFullScreen('manual')">
                                <i class="fas fa-compress mr-1"></i>
                                <span class="hidden sm:inline">Exit Full Screen</span>
                            </button>
                        </div>
                    </div>

                    <!-- Filters Row -->
                    <div class="bg-gray-50 rounded-lg p-4 mb-4">
                        <h3 class="text-sm font-semibold text-gray-700 mb-3 flex items-center">
                            <i class="fas fa-filter mr-2 text-yellow-600"></i>
                            Filter Schedules
                        </h3>
                        <div class="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 xl:grid-cols-4 gap-3">
                            <div>
                                <label class="block text-xs font-medium text-gray-600 mb-1">Year Level</label>
                                <select id="filter-year-manual" class="w-full px-3 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-yellow-500 focus:border-yellow-500 text-sm" onchange="filterSchedulesManual()">
                                    <option value="">All Year Levels</option>
                                    <?php $yearLevels = array_unique(array_column($schedules, 'year_level')); ?>
                                    <?php foreach ($yearLevels as $year): ?>
                                        <option value="<?php echo htmlspecialchars($year); ?>"><?php echo htmlspecialchars($year); ?></option>
                                    <?php endforeach; ?>
                                </select>
                            </div>

                            <div>
                                <label class="block text-xs font-medium text-gray-600 mb-1">Section</label>
                                <select id="filter-section-manual" class="w-full px-3 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-yellow-500 focus:border-yellow-500 text-sm" onchange="filterSchedulesManual()">
                                    <option value="">All Sections</option>
                                    <?php $sectionNames = array_unique(array_column($schedules, 'section_name')); ?>
                                    <?php foreach ($sectionNames as $section): ?>
                                        <option value="<?php echo htmlspecialchars($section); ?>"><?php echo htmlspecialchars($section); ?></option>
                                    <?php endforeach; ?>
                                </select>
                            </div>

                            <div>
                                <label class="block text-xs font-medium text-gray-600 mb-1">Room</label>
                                <select id="filter-room-manual" class="w-full px-3 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-yellow-500 focus:border-yellow-500 text-sm" onchange="filterSchedulesManual()">
                                    <option value="">All Rooms</option>
                                    <?php $rooms = array_unique(array_column($schedules, 'room_name')); ?>
                                    <?php foreach ($rooms as $room): ?>
                                        <option value="<?php echo htmlspecialchars($room ?? 'Online'); ?>"><?php echo htmlspecialchars($room ?? 'Online'); ?></option>
                                    <?php endforeach; ?>
                                </select>
                            </div>

                            <div class="flex items-end">
                                <button onclick="clearFiltersManual()" class="w-full px-3 py-2 border border-gray-300 text-gray-700 rounded-lg hover:bg-gray-50 transition-colors text-sm">
                                    <i class="fas fa-times mr-1"></i>
                                    Clear Filters
                                </button>
                            </div>
                        </div>
                    </div>

                    <!-- Action Buttons Row -->
                    <div class="flex flex-wrap gap-2 justify-between items-center">
                        <div class="flex flex-wrap gap-2">
                            <button id="add-schedule-btn" class="bg-yellow-500 hover:bg-yellow-600 text-white px-4 py-2 rounded-lg flex items-center space-x-2 transition-colors text-sm" onclick="openAddModal()">
                                <i class="fas fa-plus"></i>
                                <span>Add Schedule</span>
                            </button>

                            <button id="toggle-view-btn" class="bg-indigo-500 hover:bg-indigo-600 text-white px-4 py-2 rounded-lg flex items-center space-x-2 transition-colors text-sm" onclick="toggleViewMode()">
                                <i class="fas fa-list mr-1"></i>
                                <span>List View</span>
                            </button>
                        </div>

                        <div class="flex flex-wrap gap-2">
                            <!-- View Toggle Button -->
                            <button id="delete-all-btn" class="bg-red-500 hover:bg-red-600 text-white px-4 py-2 rounded-lg flex items-center space-x-2 transition-colors text-sm" onclick="deleteAllSchedules()">
                                <i class="fas fa-trash"></i>
                                <span>Delete All</span>
                            </button>

                            <button onclick="refreshManualView()" class="bg-gray-500 hover:bg-gray-600 text-white px-4 py-2 rounded-lg flex items-center space-x-2 transition-colors text-sm">
                                <i class="fas fa-sync-alt"></i>
                                <span>Refresh</span>
                            </button>
                        </div>
                    </div>
                </div>

                <!-- GRID VIEW -->
                <div id="grid-view" class="block">
                    <div class="overflow-x-auto bg-white rounded-lg shadow-sm border border-gray-200">
                        <div class="min-w-full">
                            <!-- Header with days -->
                            <div class="grid grid-cols-8 bg-gradient-to-r from-blue-50 to-indigo-50 border-b border-gray-200">
                                <div class="px-3 py-3 text-sm font-semibold text-gray-700 border-r border-gray-200 bg-gray-50 sticky left-0 z-10">
                                    <span class="hidden sm:inline">Time</span>
                                    <span class="sm:hidden">⌚</span>
                                </div>
                                <div class="px-2 py-3 text-sm font-semibold text-center text-gray-700 border-r border-gray-200">
                                    <span class="hidden sm:inline">Monday</span>
                                    <span class="sm:hidden">Mon</span>
                                </div>
                                <div class="px-2 py-3 text-sm font-semibold text-center text-gray-700 border-r border-gray-200">
                                    <span class="hidden sm:inline">Tuesday</span>
                                    <span class="sm:hidden">Tue</span>
                                </div>
                                <div class="px-2 py-3 text-sm font-semibold text-center text-gray-700 border-r border-gray-200">
                                    <span class="hidden sm:inline">Wednesday</span>
                                    <span class="sm:hidden">Wed</span>
                                </div>
                                <div class="px-2 py-3 text-sm font-semibold text-center text-gray-700 border-r border-gray-200">
                                    <span class="hidden sm:inline">Thursday</span>
                                    <span class="sm:hidden">Thu</span>
                                </div>
                                <div class="px-2 py-3 text-sm font-semibold text-center text-gray-700 border-r border-gray-200">
                                    <span class="hidden sm:inline">Friday</span>
                                    <span class="sm:hidden">Fri</span>
                                </div>
                                <div class="px-2 py-3 text-sm font-semibold text-center text-gray-700 border-r border-gray-200">
                                    <span class="hidden sm:inline">Saturday</span>
                                    <span class="sm:hidden">Sat</span>
                                </div>
                                <div class="px-2 py-3 text-sm font-semibold text-center text-gray-700">
                                    <span class="hidden sm:inline">Sunday</span>
                                    <span class="sm:hidden">Sun</span>
                                </div>
                            </div>

                            <!-- Dynamic Time slots grid -->
                            <div id="schedule-grid" class="divide-y divide-gray-200">
                                <?php
                                // Generate dynamic time slots from 7:00 AM to 9:00 PM in 30-minute intervals
                                $timeSlots = [];
                                $startHour = 7;
                                $endHour = 21;

                                for ($hour = $startHour; $hour < $endHour; $hour++) {
                                    for ($minute = 0; $minute < 60; $minute += 30) {
                                        $currentTime = sprintf('%02d:%02d', $hour, $minute);
                                        $nextTime = sprintf('%02d:%02d', $hour + ($minute + 30 >= 60 ? 1 : 0), ($minute + 30) % 60);

                                        // Skip if next time exceeds end hour
                                        if (($hour + ($minute + 30 >= 60 ? 1 : 0)) >= $endHour && ($minute + 30) % 60 > 0) {
                                            continue;
                                        }

                                        $timeSlots[] = [$currentTime, $nextTime];
                                    }
                                }

                                $days = ['Monday', 'Tuesday', 'Wednesday', 'Thursday', 'Friday', 'Saturday', 'Sunday'];

                                // Pre-process schedules for faster lookup
                                $scheduleLookup = [];
                                foreach ($schedules as $schedule) {
                                    $day = $schedule['day_of_week'];
                                    $start = substr($schedule['start_time'], 0, 5);
                                    $end = substr($schedule['end_time'], 0, 5);

                                    if (!isset($scheduleLookup[$day])) {
                                        $scheduleLookup[$day] = [];
                                    }

                                    $scheduleLookup[$day][] = [
                                        'schedule' => $schedule,
                                        'start' => $start,
                                        'end' => $end
                                    ];
                                }
                                ?>

                                <?php foreach ($timeSlots as $slotIndex => $time): ?>
                                    <?php
                                    $duration = strtotime($time[1]) - strtotime($time[0]);
                                    $rowSpan = max(1, $duration / 1800); // 30-minute base unit
                                    $minHeight = $rowSpan * 60; // Adjust height based on duration
                                    ?>
                                    <div class="grid grid-cols-8 min-h-[<?php echo $minHeight; ?>px] hover:bg-gray-50 transition-colors duration-200" style="grid-row: span <?php echo $rowSpan; ?>">
                                        <!-- Time Column -->
                                        <div class="px-3 py-3 text-sm font-medium text-gray-600 border-r border-gray-200 bg-gray-50 sticky left-0 z-10 flex items-start" style="grid-row: span <?php echo $rowSpan; ?>">
                                            <span class="text-sm hidden sm:block"><?php echo date('g:i A', strtotime($time[0])) . ' - ' . date('g:i A', strtotime($time[1])); ?></span>
                                            <span class="text-xs sm:hidden"><?php echo date('g:i', strtotime($time[0])) . '-' . date('g:i', strtotime($time[1])); ?></span>
                                        </div>

                                        <!-- Day Columns -->
                                        <?php foreach ($days as $day): ?>
                                            <div class="px-1 py-1 border-r border-gray-200 last:border-r-0 relative drop-zone min-h-[<?php echo $minHeight; ?>px]"
                                                data-day="<?php echo $day; ?>"
                                                data-start-time="<?php echo $time[0]; ?>"
                                                data-end-time="<?php echo $time[1]; ?>">

                                                <?php
                                                $schedulesInSlot = [];
                                                if (isset($scheduleLookup[$day])) {
                                                    foreach ($scheduleLookup[$day] as $scheduleData) {
                                                        $scheduleStart = $scheduleData['start'];
                                                        $scheduleEnd = $scheduleData['end'];

                                                        $slotStart = strtotime("1970-01-01 " . $time[0] . ":00");
                                                        $slotEnd = strtotime("1970-01-01 " . $time[1] . ":00");
                                                        $schedStart = strtotime("1970-01-01 " . $scheduleStart . ":00");
                                                        $schedEnd = strtotime("1970-01-01 " . $scheduleEnd . ":00");

                                                        // Check if schedule overlaps with this time slot
                                                        if ($schedStart < $slotEnd && $schedEnd > $slotStart) {
                                                            $schedulesInSlot[] = [
                                                                'schedule' => $scheduleData['schedule'],
                                                                'isStartCell' => ($scheduleStart === $time[0]),
                                                                'isEndCell' => ($scheduleEnd === $time[1])
                                                            ];
                                                        }
                                                    }
                                                }
                                                ?>

                                                <?php if (empty($schedulesInSlot)): ?>
                                                    <button onclick="openAddModalForSlot('<?php echo $day; ?>', '<?php echo $time[0]; ?>', '<?php echo $time[1]; ?>')"
                                                        class="w-full h-full text-gray-400 hover:text-gray-600 hover:bg-yellow-50 rounded-lg border-2 border-dashed border-gray-300 hover:border-yellow-400 transition-all duration-200 no-print flex items-center justify-center p-1 min-h-[<?php echo $minHeight; ?>px]">
                                                        <i class="fas fa-plus text-xs"></i>
                                                    </button>
                                                <?php else: ?>
                                                    <div class="space-y-1 p-1">
                                                        <?php foreach ($schedulesInSlot as $scheduleData):
                                                            $schedule = $scheduleData['schedule'];
                                                            $isStartCell = $scheduleData['isStartCell'];

                                                            $colors = [
                                                                'bg-blue-100 border-blue-300 text-blue-800',
                                                                'bg-green-100 border-green-300 text-green-800',
                                                                'bg-purple-100 border-purple-300 text-purple-800',
                                                                'bg-orange-100 border-orange-300 text-orange-800',
                                                                'bg-pink-100 border-pink-300 text-pink-800',
                                                                'bg-teal-100 border-teal-300 text-teal-800',
                                                                'bg-amber-100 border-amber-300 text-amber-800'
                                                            ];
                                                            // Use schedule_id for consistent coloring
                                                            $colorIndex = $schedule['schedule_id'] ? ($schedule['schedule_id'] % count($colors)) : array_rand($colors);
                                                            $colorClass = $colors[$colorIndex];
                                                        ?>
                                                            <div class="schedule-card <?php echo $colorClass; ?> p-2 rounded-lg border-l-4 draggable cursor-move text-xs"
                                                                draggable="true"
                                                                data-schedule-id="<?php echo $schedule['schedule_id']; ?>"
                                                                data-year-level="<?php echo htmlspecialchars($schedule['year_level']); ?>"
                                                                data-section-name="<?php echo htmlspecialchars($schedule['section_name']); ?>"
                                                                data-room-name="<?php echo htmlspecialchars($schedule['room_name'] ?? 'Online'); ?>"
                                                                data-faculty-name="<?php echo htmlspecialchars($schedule['faculty_name']); ?>"
                                                                data-course-code="<?php echo htmlspecialchars($schedule['course_code']); ?>"
                                                                data-original-day="<?php echo htmlspecialchars($schedule['day_of_week']); ?>"
                                                                data-original-start="<?php echo substr($schedule['start_time'], 0, 5); ?>"
                                                                data-original-end="<?php echo substr($schedule['end_time'], 0, 5); ?>">
                                                                style="<?php echo !$isStartCell ? 'opacity: 0.6;' : ''; ?>">

                                                                <?php if ($isStartCell): ?>
                                                                    <div class="flex justify-between items-start mb-1">
                                                                        <div class="font-semibold truncate flex-1">
                                                                            <?php echo htmlspecialchars($schedule['course_code']); ?>
                                                                        </div>
                                                                        <div class="flex space-x-1 flex-shrink-0 ml-1">
                                                                            <button onclick="editSchedule('<?php echo $schedule['schedule_id']; ?>')" class="text-yellow-600 hover:text-yellow-700 no-print">
                                                                                <i class="fas fa-edit text-xs"></i>
                                                                                <button onclick="console.log('Delete clicked - Schedule ID:', <?php echo $schedule['schedule_id'] ?? 'null'; ?>); openDeleteSingleModal(
                                                                                        <?php echo $schedule['schedule_id'] ?? 'null'; ?>, 
                                                                                        '<?php echo htmlspecialchars($schedule['course_code'] ?? ''); ?>', 
                                                                                        '<?php echo htmlspecialchars($schedule['section_name'] ?? ''); ?>', 
                                                                                        '<?php echo htmlspecialchars($schedule['day_of_week'] ?? ''); ?>', 
                                                                                        '<?php echo isset($schedule['start_time']) ? date('g:i A', strtotime($schedule['start_time'])) : ''; ?>', 
                                                                                        '<?php echo isset($schedule['end_time']) ? date('g:i A', strtotime($schedule['end_time'])) : ''; ?>'
                                                                                    )" class="text-red-600 hover:text-red-700 no-print">
                                                                                    <i class="fas fa-trash text-xs"></i>
                                                                                </button>
                                                                        </div>
                                                                    </div>
                                                                <?php else: ?>
                                                                    <div class="font-semibold truncate mb-1 text-center opacity-75">
                                                                        <i class="fas fa-ellipsis-h text-xs"></i>
                                                                    </div>
                                                                <?php endif; ?>

                                                                <?php if ($isStartCell): ?>
                                                                    <div class="opacity-90 truncate">
                                                                        <?php echo htmlspecialchars($schedule['section_name']); ?>
                                                                    </div>
                                                                    <div class="opacity-75 truncate">
                                                                        <?php echo htmlspecialchars($schedule['faculty_name']); ?>
                                                                    </div>
                                                                    <div class="opacity-75 truncate">
                                                                        <?php echo htmlspecialchars($schedule['room_name'] ?? 'Online'); ?>
                                                                    </div>
                                                                    <div class="font-medium mt-1 hidden sm:block text-xs">
                                                                        <?php echo date('g:i A', strtotime($schedule['start_time'])) . ' - ' . date('g:i A', strtotime($schedule['end_time'])); ?>
                                                                    </div>
                                                                <?php endif; ?>
                                                            </div>
                                                        <?php endforeach; ?>
                                                    </div>
                                                <?php endif; ?>
                                            </div>
                                        <?php endforeach; ?>
                                    </div>
                                <?php endforeach; ?>
                            </div>
                        </div>
                    </div>
                </div>

                <!-- LIST VIEW -->
                <div id="list-view" class="hidden">
                    <div class="bg-white rounded-lg shadow-sm border border-gray-200 overflow-hidden">
                        <div class="overflow-x-auto">
                            <table class="w-full">
                                <thead class="bg-gradient-to-r from-blue-50 to-indigo-50 border-b border-gray-200">
                                    <tr>
                                        <th class="px-4 py-3 text-left text-sm font-semibold text-gray-700">Course Code</th>
                                        <th class="px-4 py-3 text-left text-sm font-semibold text-gray-700">Section</th>
                                        <th class="px-4 py-3 text-left text-sm font-semibold text-gray-700">Year Level</th>
                                        <th class="px-4 py-3 text-left text-sm font-semibold text-gray-700">Faculty</th>
                                        <th class="px-4 py-3 text-left text-sm font-semibold text-gray-700">Day</th>
                                        <th class="px-4 py-3 text-left text-sm font-semibold text-gray-700">Time</th>
                                        <th class="px-4 py-3 text-left text-sm font-semibold text-gray-700">Room</th>
                                        <th class="px-4 py-3 text-center text-sm font-semibold text-gray-700">Actions</th>
                                    </tr>
                                </thead>
                                <tbody class="divide-y divide-gray-200">
                                    <?php foreach ($schedules as $schedule): ?>
                                        <tr class="hover:bg-gray-50 transition-colors duration-200 schedule-row"
                                            data-schedule-id="<?php echo $schedule['schedule_id']; ?>"
                                            data-year-level="<?php echo htmlspecialchars($schedule['year_level'] ?? ''); ?>"
                                            data-section-name="<?php echo htmlspecialchars($schedule['section_name'] ?? ''); ?>"
                                            data-room-name="<?php echo htmlspecialchars($schedule['room_name'] ?? 'Online'); ?>">
                                            <td class="px-4 py-3 text-sm text-gray-900 font-medium">
                                                <?php echo htmlspecialchars($schedule['course_code']); ?>
                                            </td>
                                            <td class="px-4 py-3 text-sm text-gray-700">
                                                <?php echo htmlspecialchars($schedule['section_name']); ?>
                                            </td>
                                            <td class="px-4 py-3 text-sm text-gray-700">
                                                <?php echo htmlspecialchars($schedule['year_level']); ?>
                                            </td>
                                            <td class="px-4 py-3 text-sm text-gray-700">
                                                <?php echo htmlspecialchars($schedule['faculty_name']); ?>
                                            </td>
                                            <td class="px-4 py-3 text-sm text-gray-700">
                                                <?php echo htmlspecialchars($schedule['day_of_week']); ?>
                                            </td>
                                            <td class="px-4 py-3 text-sm text-gray-700">
                                                <?php echo date('g:i A', strtotime($schedule['start_time'])) . ' - ' . date('g:i A', strtotime($schedule['end_time'])); ?>
                                            </td>
                                            <td class="px-4 py-3 text-sm text-gray-700">
                                                <?php echo htmlspecialchars($schedule['room_name'] ?? 'Online'); ?>
                                            </td>
                                            <td class="px-4 py-3 text-center">
                                                <div class="flex space-x-2 justify-center">
                                                    <button onclick="editSchedule('<?php echo $schedule['schedule_id']; ?>')" class="text-yellow-600 hover:text-yellow-700 text-sm no-print">
                                                        <i class="fas fa-edit"></i>
                                                    </button>
                                                    <button onclick="openDeleteSingleModal(
                                        '<?php echo $schedule['schedule_id']; ?>', 
                                        '<?php echo htmlspecialchars($schedule['course_code']); ?>', 
                                        '<?php echo htmlspecialchars($schedule['section_name']); ?>', 
                                        '<?php echo htmlspecialchars($schedule['day_of_week']); ?>', 
                                        '<?php echo date('g:i A', strtotime($schedule['start_time'])); ?>', 
                                        '<?php echo date('g:i A', strtotime($schedule['end_time'])); ?>'
                                    )" class="text-red-600 hover:text-red-700 text-sm no-print">
                                                        <i class="fas fa-trash"></i>
                                                    </button>
                                                </div>
                                            </td>
                                        </tr>
                                    <?php endforeach; ?>
                                </tbody>
                            </table>
                            <?php if (empty($schedules)): ?>
                                <div class="px-4 py-8 text-center text-gray-500">
                                    <i class="fas fa-inbox text-3xl mb-2"></i>
                                    <p class="mt-2">No schedules found</p>
                                </div>
                            <?php endif; ?>
                        </div>
                    </div>
                </div>
            </div>
        </div>

        <!-- View Schedule Tab -->
        <div id="content-schedule" class="tab-content <?php echo $activeTab !== 'schedule-list' ? 'hidden' : ''; ?>">
            <div class="bg-white rounded-xl shadow-lg border border-gray-200 p-6">
                <!-- Header Section -->
                <div class="mb-6">
                    <!-- Title Row -->
                    <div class="flex flex-col lg:flex-row lg:items-center lg:justify-between gap-4 mb-4">
                        <div class="flex items-center">
                            <div class="bg-yellow-500 p-2 rounded-lg mr-3">
                                <i class="fas fa-calendar text-white"></i>
                            </div>
                            <div>
                                <h2 class="text-xl font-bold text-gray-900">Weekly Schedule View</h2>
                                <p class="text-sm text-gray-600 mt-1">View and filter all schedules</p>
                            </div>
                        </div>

                        <!-- Full Screen Buttons -->
                        <div class="flex items-center space-x-2">
                            <button id="fullscreen-view-btn" class="bg-blue-500 hover:bg-blue-600 text-white px-4 py-2 rounded-lg flex items-center space-x-2 transition-colors text-sm" onclick="toggleFullScreen('view')">
                                <i class="fas fa-expand mr-1"></i>
                                <span class="hidden sm:inline">Full Screen</span>
                            </button>
                            <button id="exit-fullscreen-view-btn" class="bg-gray-600 hover:bg-gray-700 text-white px-4 py-2 rounded-lg flex items-center space-x-2 transition-colors hidden text-sm" onclick="toggleFullScreen('view')">
                                <i class="fas fa-compress mr-1"></i>
                                <span class="hidden sm:inline">Exit Full Screen</span>
                            </button>
                        </div>
                    </div>

                    <!-- Filters Row -->
                    <div class="bg-gray-50 rounded-lg p-4 mb-4">
                        <h3 class="text-sm font-semibold text-gray-700 mb-3 flex items-center">
                            <i class="fas fa-filter mr-2 text-yellow-600"></i>
                            Filter Schedules
                        </h3>
                        <div class="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 xl:grid-cols-5 gap-3">
                            <div>
                                <label class="block text-xs font-medium text-gray-600 mb-1">Year Level</label>
                                <select id="filter-year" class="w-full px-3 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-yellow-500 focus:border-yellow-500 text-sm" onchange="filterSchedules()">
                                    <option value="">All Year Levels</option>
                                    <?php $yearLevels = array_unique(array_column($schedules, 'year_level')); ?>
                                    <?php foreach ($yearLevels as $year): ?>
                                        <option value="<?php echo htmlspecialchars($year); ?>"><?php echo htmlspecialchars($year); ?></option>
                                    <?php endforeach; ?>
                                </select>
                            </div>

                            <div>
                                <label class="block text-xs font-medium text-gray-600 mb-1">Section</label>
                                <select id="filter-section" class="w-full px-3 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-yellow-500 focus:border-yellow-500 text-sm" onchange="filterSchedules()">
                                    <option value="">All Sections</option>
                                    <?php $sectionNames = array_unique(array_column($schedules, 'section_name')); ?>
                                    <?php foreach ($sectionNames as $section): ?>
                                        <option value="<?php echo htmlspecialchars($section); ?>"><?php echo htmlspecialchars($section); ?></option>
                                    <?php endforeach; ?>
                                </select>
                            </div>

                            <div>
                                <label class="block text-xs font-medium text-gray-600 mb-1">Room</label>
                                <select id="filter-room" class="w-full px-3 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-yellow-500 focus:border-yellow-500 text-sm" onchange="filterSchedules()">
                                    <option value="">All Rooms</option>
                                    <?php $rooms = array_unique(array_column($schedules, 'room_name')); ?>
                                    <?php foreach ($rooms as $room): ?>
                                        <option value="<?php echo htmlspecialchars($room ?? 'Online'); ?>"><?php echo htmlspecialchars($room ?? 'Online'); ?></option>
                                    <?php endforeach; ?>
                                </select>
                            </div>

                            <div class="flex items-end space-x-2">
                                <button onclick="clearFilters()" class="flex-1 px-3 py-2 border border-gray-300 text-gray-700 rounded-lg hover:bg-gray-50 transition-colors text-sm">
                                    <i class="fas fa-times mr-1"></i>
                                    Clear Filters
                                </button>
                            </div>

                            <div class="flex items-end">
                                <button id="delete-all-btn" class="w-full bg-red-500 hover:bg-red-600 text-white px-3 py-2 rounded-lg flex items-center justify-center space-x-2 transition-colors text-sm" onclick="deleteAllSchedules()">
                                    <i class="fas fa-trash"></i>
                                    <span>Delete All</span>
                                </button>
                            </div>
                        </div>
                    </div>
                </div>

                <!-- Weekly Timetable -->
                <div class="overflow-x-auto bg-white rounded-lg shadow-sm border border-gray-200">
                    <div class="min-w-full">
                        <!-- Header with days -->
                        <div class="grid grid-cols-8 bg-gradient-to-r from-blue-50 to-indigo-50 border-b border-gray-200">
                            <div class="px-3 py-3 text-sm font-semibold text-gray-700 border-r border-gray-200 bg-gray-50 sticky left-0 z-10">
                                <span class="hidden sm:inline">Time</span>
                                <span class="sm:hidden">⌚</span>
                            </div>
                            <div class="px-2 py-3 text-sm font-semibold text-center text-gray-700 border-r border-gray-200">
                                <span class="hidden sm:inline">Monday</span>
                                <span class="sm:hidden">Mon</span>
                            </div>
                            <div class="px-2 py-3 text-sm font-semibold text-center text-gray-700 border-r border-gray-200">
                                <span class="hidden sm:inline">Tuesday</span>
                                <span class="sm:hidden">Tue</span>
                            </div>
                            <div class="px-2 py-3 text-sm font-semibold text-center text-gray-700 border-r border-gray-200">
                                <span class="hidden sm:inline">Wednesday</span>
                                <span class="sm:hidden">Wed</span>
                            </div>
                            <div class="px-2 py-3 text-sm font-semibold text-center text-gray-700 border-r border-gray-200">
                                <span class="hidden sm:inline">Thursday</span>
                                <span class="sm:hidden">Thu</span>
                            </div>
                            <div class="px-2 py-3 text-sm font-semibold text-center text-gray-700 border-r border-gray-200">
                                <span class="hidden sm:inline">Friday</span>
                                <span class="sm:hidden">Fri</span>
                            </div>
                            <div class="px-2 py-3 text-sm font-semibold text-center text-gray-700 border-r border-gray-200">
                                <span class="hidden sm:inline">Saturday</span>
                                <span class="sm:hidden">Sat</span>
                            </div>
                            <div class="px-2 py-3 text-sm font-semibold text-center text-gray-700">
                                <span class="hidden sm:inline">Sunday</span>
                                <span class="sm:hidden">Sun</span>
                            </div>
                        </div>

                        <!-- Time slots -->
                        <div id="timetableGrid" class="divide-y divide-gray-200">
                            <?php foreach ($timeSlots as $time): ?>
                                <?php
                                $duration = strtotime($time[1]) - strtotime($time[0]);
                                $rowSpan = $duration / 7200;
                                ?>
                                <div class="grid grid-cols-8 min-h-[<?php echo $rowSpan * 80; ?>px] hover:bg-gray-50 transition-colors duration-200" style="grid-row: span <?php echo $rowSpan; ?>;">
                                    <div class="px-3 py-3 text-sm font-medium text-gray-600 border-r border-gray-200 bg-gray-50 flex items-center sticky left-0 z-10" rowspan="<?php echo $rowSpan; ?>">
                                        <span class="text-sm hidden sm:block"><?php echo date('g:i A', strtotime($time[0])) . ' - ' . date('g:i A', strtotime($time[1])); ?></span>
                                        <span class="text-xs sm:hidden"><?php echo date('g:i', strtotime($time[0])) . '-' . date('g:i', strtotime($time[1])); ?></span>
                                    </div>
                                    <?php foreach ($days as $day): ?>
                                        <div class="px-1 py-1 border-r border-gray-200 last:border-r-0 min-h-[<?php echo $rowSpan * 80; ?>px] relative schedule-cell"
                                            data-day="<?php echo $day; ?>"
                                            data-start-time="<?php echo $time[0]; ?>"
                                            data-end-time="<?php echo $time[1]; ?>"
                                            data-year-level=""
                                            data-section-name=""
                                            data-room-name="">
                                            <?php
                                            $schedulesForSlot = isset($scheduleGrid[$day][$time[0]]) ? $scheduleGrid[$day][$time[0]] : [];
                                            foreach ($schedulesForSlot as $schedule) {
                                                $scheduleStart = substr($schedule['start_time'], 0, 5);
                                                $scheduleEnd = substr($schedule['end_time'], 0, 5);
                                                if ($scheduleStart === $time[0]) {
                                                    $colors = [
                                                        'bg-blue-100 border-blue-300 text-blue-800',
                                                        'bg-green-100 border-green-300 text-green-800',
                                                        'bg-purple-100 border-purple-300 text-purple-800',
                                                        'bg-orange-100 border-orange-300 text-orange-800',
                                                        'bg-pink-100 border-pink-300 text-pink-800'
                                                    ];
                                                    $colorClass = $colors[array_rand($colors)];
                                            ?>
                                                    <div class="schedule-card <?php echo $colorClass; ?> p-2 rounded-lg border-l-4 mb-1 schedule-item"
                                                        data-year-level="<?php echo htmlspecialchars($schedule['year_level']); ?>"
                                                        data-section-name="<?php echo htmlspecialchars($schedule['section_name']); ?>"
                                                        data-room-name="<?php echo htmlspecialchars($schedule['room_name'] ?? 'Online'); ?>">
                                                        <div class="font-semibold text-xs truncate mb-1">
                                                            <?php echo htmlspecialchars($schedule['course_code']); ?>
                                                        </div>
                                                        <div class="text-xs opacity-90 truncate mb-1">
                                                            <?php echo htmlspecialchars($schedule['section_name']); ?>
                                                        </div>
                                                        <div class="text-xs opacity-75 truncate">
                                                            <?php echo htmlspecialchars($schedule['faculty_name']); ?>
                                                        </div>
                                                        <div class="text-xs opacity-75 truncate">
                                                            <?php echo htmlspecialchars($schedule['room_name'] ?? 'Online'); ?>
                                                        </div>
                                                        <div class="text-xs font-medium mt-1 hidden sm:block">
                                                            <?php echo date('g:i A', strtotime($schedule['start_time'])) . ' - ' . date('g:i A', strtotime($schedule['end_time'])); ?>
                                                        </div>
                                                    </div>
                                            <?php
                                                }
                                            }
                                            ?>
                                        </div>
                                    <?php endforeach; ?>
                                </div>
                            <?php endforeach; ?>
                        </div>
                    </div>
                </div>
            </div>
        </div>

        <!-- Loading Overlay -->
        <div id="loading-overlay" class="fixed inset-0 bg-black bg-opacity-30 backdrop-blur-md flex items-center justify-center z-50 hidden">
            <div class="bg-white p-8 rounded-lg shadow-xl text-center">
                <div class="pulsing-loader mx-auto mb-4"></div>
                <p class="text-gray-700 font-medium">Generating schedules...</p>
            </div>
        </div>

        <!-- Generation Report Modal -->
        <div id="report-modal" class="fixed inset-0 bg-opacity-30 backdrop-blur-md flex items-center justify-center z-50 hidden">
            <div class="bg-white rounded-lg shadow-xl p-6 w-full max-w-md mx-4">
                <div class="flex items-center justify-between mb-6">
                    <h3 class="text-lg font-semibold text-gray-900" id="report-title">Schedule Generation Report</h3>
                    <button onclick="closeReportModal()" class="text-gray-400 hover:text-gray-600">
                        <i class="fas fa-times text-xl"></i>
                    </button>
                </div>
                <div id="report-content" class="mb-6 text-gray-700">
                    <!-- Report content will be dynamically updated -->
                </div>
                <div class="flex justify-end">
                    <button onclick="closeReportModal()" class="px-4 py-2 bg-yellow-500 hover:bg-yellow-600 text-white rounded-lg">Close</button>
                </div>
            </div>
        </div>

        <!-- Add/Edit Schedule Modal -->
        <div id="schedule-modal" class="fixed inset-0 bg-black bg-opacity-30 backdrop-blur-md items-center justify-center z-50 hidden modal-overlay">
            <div class="bg-white rounded-lg shadow-xl p-6 w-full max-w-md mx-4 modal-content">
                <div class="flex items-center justify-between mb-6">
                    <h3 class="text-lg font-semibold text-gray-900" id="modal-title">Add Schedule</h3>
                    <button onclick="closeModal()" class="text-gray-400 hover:text-gray-600">
                        <i class="fas fa-times text-xl"></i>
                    </button>
                </div>

                <form id="schedule-form" class="space-y-4" onsubmit="handleScheduleSubmit(event)">
                    <input type="hidden" id="schedule-id" name="schedule_id">
                    <input type="hidden" id="modal-day" name="day_of_week">
                    <input type="hidden" id="modal-start-time" name="start_time">
                    <input type="hidden" id="modal-end-time" name="end_time">

                    <div>
                        <label class="block text-sm font-semibold text-gray-700 mb-2">Course Code</label>
                        <input type="text" id="course-code" name="course_code" list="course-codes"
                            class="w-full px-3 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-yellow-500 focus:border-yellow-500"
                            required oninput="autoFillCourseName(this.value)">
                        <datalist id="course-codes">
                            <?php
                            $curriculumCourses = $jsData['curriculumCourses'] ?? [];
                            foreach ($curriculumCourses as $course): ?>
                                <option value="<?php echo htmlspecialchars($course['course_code']); ?>"
                                    data-name="<?php echo htmlspecialchars($course['course_name']); ?>"
                                    data-year-level="<?php echo htmlspecialchars($course['curriculum_year']); ?>"
                                    data-course-id="<?php echo htmlspecialchars($course['course_id']); ?>">
                                <?php endforeach; ?>
                        </datalist>
                    </div>

                    <div>
                        <label class="block text-sm font-semibold text-gray-700 mb-2">Course Name</label>
                        <input type="text" id="course-name" name="course_name"
                            class="w-full px-3 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-yellow-500 focus:border-yellow-500"
                            required readonly>
                    </div>

                    <div>
                        <label class="block text-sm font-semibold text-gray-700 mb-2">Section</label>
                        <select id="section-name" name="section_name"
                            class="w-full px-3 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-yellow-500 focus:border-yellow-500 validate-on-change" required>
                            <option value="">Select Section</option>
                            <?php
                            // Group sections by year level for better organization
                            $sectionsByYear = [];
                            $sections = $jsData['sectionsData'] ?? [];

                            foreach ($sections as $section) {
                                $yearLevel = $section['year_level'] ?? 'Unknown';
                                if (!isset($sectionsByYear[$yearLevel])) {
                                    $sectionsByYear[$yearLevel] = [];
                                }
                                $sectionsByYear[$yearLevel][] = $section;
                            }

                            // Sort by year level
                            ksort($sectionsByYear);

                            foreach ($sectionsByYear as $yearLevel => $yearSections): ?>
                                <optgroup label="<?php echo htmlspecialchars($yearLevel); ?>">
                                    <?php foreach ($yearSections as $section): ?>
                                        <option value="<?php echo htmlspecialchars($section['section_name']); ?>"
                                            data-year-level="<?php echo htmlspecialchars($section['year_level']); ?>"
                                            data-max-students="<?php echo htmlspecialchars($section['max_students']); ?>"
                                            data-current-students="<?php echo htmlspecialchars($section['current_students']); ?>">
                                            <?php echo htmlspecialchars($section['section_name']); ?>
                                            (<?php echo htmlspecialchars($section['current_students']); ?>/<?php echo htmlspecialchars($section['max_students']); ?>)
                                        </option>
                                    <?php endforeach; ?>
                                </optgroup>
                            <?php endforeach; ?>
                        </select>
                        <!-- Section details display area -->
                        <div id="section-details" class="mt-2 hidden"></div>
                    </div>

                    <div>
                        <label class="block text-sm font-semibold text-gray-700 mb-2">Faculty</label>
                        <select id="faculty-name" name="faculty_name"
                            class="w-full px-3 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-yellow-500 focus:border-yellow-500 validate-on-change" required>
                            <option value="">Select Faculty</option>
                            <?php foreach ($faculty as $fac): ?>
                                <option value="<?php echo htmlspecialchars($fac['name']); ?>">
                                    <?php echo htmlspecialchars($fac['name']); ?>
                                </option>
                            <?php endforeach; ?>
                        </select>
                    </div>

                    <div>
                        <label class="block text-sm font-semibold text-gray-700 mb-2">Room</label>
                        <select id="room-name" name="room_name"
                            class="w-full px-3 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-yellow-500 focus:border-yellow-500 validate-on-change" required>
                            <option value="Online">Online</option>
                            <?php foreach ($classrooms as $room): ?>
                                <option value="<?php echo htmlspecialchars($room['room_name']); ?>">
                                    <?php echo htmlspecialchars($room['room_name']); ?>
                                </option>
                            <?php endforeach; ?>
                        </select>
                    </div>

                    <div class="grid grid-cols-2 gap-4">
                        <div>
                            <label class="block text-sm font-semibold text-gray-700 mb-2">Start Time</label>
                            <select id="start-time" name="start_time_display"
                                class="w-full px-3 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-yellow-500 focus:border-yellow-500 validate-on-change"
                                onchange="updateEndTimeOptions(); updateTimeFields()" required>
                                <option value="">Select Start Time</option>
                                <?php
                                // Generate time options from 7:00 AM to 9:00 PM in 30-minute intervals
                                for ($hour = 7; $hour < 22; $hour++) {
                                    for ($minute = 0; $minute < 60; $minute += 30) {
                                        $timeValue = sprintf('%02d:%02d', $hour, $minute);
                                        $timeDisplay = date('g:i A', strtotime($timeValue));
                                        echo "<option value=\"$timeValue\">$timeDisplay</option>";
                                    }
                                }
                                ?>
                            </select>
                        </div>
                        <div>
                            <label class="block text-sm font-semibold text-gray-700 mb-2">End Time</label>
                            <select id="end-time" name="end_time_display"
                                class="w-full px-3 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-yellow-500 focus:border-yellow-500 validate-on-change"
                                onchange="updateTimeFields()" required>
                                <option value="">Select End Time</option>
                                <!-- End times will be populated dynamically -->
                            </select>
                        </div>
                    </div>

                    <div>
                        <label class="block text-sm font-semibold text-gray-700 mb-2">Day Pattern</label>
                        <select id="day-select" name="day_select_display"
                            class="w-full px-3 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-yellow-500 focus:border-yellow-500"
                            onchange="updateDayField()">
                            <option value="Monday">Monday</option>
                            <option value="Tuesday">Tuesday</option>
                            <option value="Wednesday">Wednesday</option>
                            <option value="Thursday">Thursday</option>
                            <option value="Friday">Friday</option>
                            <option value="Saturday">Saturday</option>
                            <option value="Sunday">Sunday</option>
                            <option value="MWF">MWF (Mon, Wed, Fri)</option>
                            <option value="TTH">TTH (Tue, Thu)</option>
                            <option value="MW">MW (Mon, Wed)</option>
                            <option value="TTHS">TTHS (Tue, Thu, Sat)</option>
                        </select>
                    </div>

                    <div>
                        <label class="block text-sm font-semibold text-gray-700 mb-2">Schedule Type</label>
                        <select id="schedule-type" name="schedule_type"
                            class="w-full px-3 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-yellow-500 focus:border-yellow-500">
                            <option value="f2f">Face to Face (F2F)</option>
                            <option value="online">Online</option>
                            <option value="hybrid">Hybrid</option>
                        </select>
                    </div>

                    <div class="flex justify-end space-x-4 pt-4">
                        <button type="button" onclick="closeModal()" class="px-4 py-2 border border-gray-300 rounded-lg text-gray-700 hover:bg-gray-50">Cancel</button>
                        <button type="submit" class="px-4 py-2 bg-yellow-500 hover:bg-yellow-600 text-white rounded-lg">Save Schedule</button>
                    </div>
                </form>
            </div>
        </div>

        <!-- Delete Confirmation Modal -->
        <div id="delete-confirmation-modal" class="fixed inset-0 bg-opacity-50 backdrop-blur-sm hidden items-center justify-center z-50">
            <div class="bg-white rounded-lg shadow-xl p-6 w-full max-w-md mx-4">
                <div class="flex items-center justify-between mb-6">
                    <div class="flex items-center">
                        <div class="bg-red-100 p-2 rounded-full mr-3">
                            <i class="fas fa-exclamation-triangle text-red-600 text-xl"></i>
                        </div>
                        <h3 class="text-lg font-semibold text-gray-900">Delete All Schedules</h3>
                    </div>
                    <button type="button" onclick="closeDeleteModal()" class="text-gray-400 hover:text-gray-600">
                        <i class="fas fa-times text-xl"></i>
                    </button>
                </div>

                <div class="mb-6">
                    <p class="text-gray-700 mb-4">
                        Are you sure you want to delete <strong>ALL schedules</strong> for your department? This action cannot be undone.
                    </p>
                    <div class="bg-yellow-50 border border-yellow-200 rounded-lg p-4">
                        <div class="flex items-center">
                            <i class="fas fa-info-circle text-yellow-600 mr-2"></i>
                            <span class="text-sm font-medium text-yellow-800">This will permanently remove all generated schedules for the current semester.</span>
                        </div>
                    </div>
                </div>

                <div class="flex justify-end space-x-4">
                    <button type="button" onclick="closeDeleteModal()" class="px-4 py-2 border border-gray-300 rounded-lg text-gray-700 hover:bg-gray-50 transition-colors">
                        Cancel
                    </button>
                    <button type="button" onclick="confirmDeleteAllSchedules()" class="px-4 py-2 bg-red-500 hover:bg-red-600 text-white rounded-lg transition-colors">
                        <i class="fas fa-trash mr-2"></i>
                        Delete All Schedules
                    </button>
                </div>
            </div>
        </div>

        <!-- Single Delete Confirmation Modal -->
        <div id="delete-single-modal" class="fixed inset-0 bg-opacity-50 backdrop-blur-sm hidden items-center justify-center z-50">
            <div class="bg-white rounded-lg shadow-xl p-6 w-full max-w-md mx-4">
                <div class="flex items-center justify-between mb-6">
                    <div class="flex items-center">
                        <div class="bg-red-100 p-2 rounded-full mr-3">
                            <i class="fas fa-exclamation-triangle text-red-600 text-xl"></i>
                        </div>
                        <h3 class="text-lg font-semibold text-gray-900">Delete Schedule</h3>
                    </div>
                    <button type="button" onclick="closeDeleteSingleModal()" class="text-gray-400 hover:text-gray-600">
                        <i class="fas fa-times text-xl"></i>
                    </button>
                </div>

                <div class="mb-6">
                    <p class="text-gray-700 mb-4">
                        Are you sure you want to delete this schedule? This action cannot be undone.
                    </p>
                    <div class="bg-yellow-50 border border-yellow-200 rounded-lg p-4">
                        <div class="flex items-center">
                            <i class="fas fa-info-circle text-yellow-600 mr-2"></i>
                            <span class="text-sm font-medium text-yellow-800" id="single-delete-details">
                                This schedule will be permanently removed.
                            </span>
                        </div>
                    </div>
                </div>

                <div class="flex justify-end space-x-4">
                    <button type="button" onclick="closeDeleteSingleModal()" class="px-4 py-2 border border-gray-300 rounded-lg text-gray-700 hover:bg-gray-50 transition-colors">
                        Cancel
                    </button>
                    <button type="button" onclick="confirmDeleteSingleSchedule()" class="px-4 py-2 bg-red-500 hover:bg-red-600 text-white rounded-lg transition-colors">
                        <i class="fas fa-trash mr-2"></i>
                        Delete Schedule
                    </button>
                </div>
            </div>
        </div>

        <style>
            .conflict-tooltip {
                position: absolute;
                bottom: -25px;
                left: 0;
                background: #fee2e2;
                color: #dc2626;
                padding: 4px 8px;
                border-radius: 4px;
                font-size: 12px;
                white-space: nowrap;
                z-index: 10;
                border: 1px solid #fca5a5;
            }

            .conflict-tooltip::after {
                content: '';
                position: absolute;
                top: -5px;
                left: 10px;
                border: 5px solid transparent;
                border-bottom-color: #fee2e2;
            }
        </style>


        <script>
            // Global data
            window.scheduleData = <?php echo json_encode($schedules); ?> || [];
            window.jsData = <?php echo json_encode($jsData); ?>;
            window.departmentId = window.jsData.departmentId;
            window.currentSemester = window.jsData.currentSemester;
            window.rawSectionsData = window.jsData.sectionsData || [];
            window.currentAcademicYear = window.jsData.currentAcademicYear || "";
            window.faculty = window.jsData.faculty || [];
            window.classrooms = window.jsData.classrooms || [];
            window.curricula = window.jsData.curricula || [];
            // Get curriculum courses from jsData
            window.curriculumCourses = window.jsData.curriculumCourses || [];

            // Transform sections data
            window.sectionsData = Array.isArray(window.rawSectionsData) ? window.rawSectionsData.map((s, index) => ({
                section_id: s.section_id ?? (index + 1),
                section_name: s.section_name ?? '',
                year_level: s.year_level ?? 'Unknown',
                academic_year: s.academic_year ?? '',
                current_students: s.current_students ?? 0,
                max_students: s.max_students ?? 30,
                semester: s.semester ?? '',
                is_active: s.is_active ?? 1
            })) : [];

            function debugDataAttributes() {
                console.log('=== CHECKING DATA ATTRIBUTES ===');
                const rows = document.querySelectorAll('#list-view tr.schedule-row');
                rows.forEach((row, index) => {
                    console.log(`Row ${index + 1} attributes:`, {
                        yearLevel: row.getAttribute('data-year-level'),
                        sectionName: row.getAttribute('data-section-name'),
                        roomName: row.getAttribute('data-room-name')
                    });
                });
            }

            // Clear filters for manual tab
            function clearFiltersManual() {
                document.getElementById('filter-year-manual').value = '';
                document.getElementById('filter-section-manual').value = '';
                document.getElementById('filter-room-manual').value = '';
                filterSchedulesManual();
            }

            // Refresh manual view
            function refreshManualView() {
                // You can add refresh logic here
                location.reload(); // Simple refresh for now
            }

            // Enhanced full screen function
            function toggleFullScreen(tab) {
                const sidebar = document.getElementById('sidebar');
                const mainContent = document.querySelector('.main-content');
                const header = document.querySelector('header');
                const fullscreenBtn = document.getElementById(`fullscreen-${tab}-btn`);
                const exitFullscreenBtn = document.getElementById(`exit-fullscreen-${tab}-btn`);

                if (sidebar.style.display !== 'none') {
                    // Enter full screen mode
                    sidebar.style.display = 'none';
                    header.style.display = 'none';
                    mainContent.style.marginLeft = '0';
                    mainContent.style.padding = '0';
                    mainContent.classList.add('fullscreen-mode');

                    // Update buttons
                    fullscreenBtn.classList.add('hidden');
                    exitFullscreenBtn.classList.remove('hidden');

                    // Add fullscreen styles with higher z-index for modals
                    document.body.style.overflow = 'hidden';
                    mainContent.style.width = '100vw';
                    mainContent.style.height = '100vh';
                    mainContent.style.position = 'fixed';
                    mainContent.style.top = '0';
                    mainContent.style.left = '0';
                    mainContent.style.zIndex = '1000';
                    mainContent.style.backgroundColor = 'white';

                    // Ensure modals have higher z-index in full screen
                    const modals = document.querySelectorAll('.modal-overlay');
                    modals.forEach(modal => {
                        modal.style.zIndex = '1001';
                    });

                } else {
                    // Exit full screen mode
                    sidebar.style.display = '';
                    header.style.display = '';
                    mainContent.style.marginLeft = '';
                    mainContent.style.padding = '';
                    mainContent.classList.remove('fullscreen-mode');

                    // Update buttons
                    fullscreenBtn.classList.remove('hidden');
                    exitFullscreenBtn.classList.add('hidden');

                    // Remove fullscreen styles
                    document.body.style.overflow = '';
                    mainContent.style.width = '';
                    mainContent.style.height = '';
                    mainContent.style.position = '';
                    mainContent.style.top = '';
                    mainContent.style.left = '';
                    mainContent.style.zIndex = '';
                    mainContent.style.backgroundColor = '';

                    // Reset modal z-index
                    const modals = document.querySelectorAll('.modal-overlay');
                    modals.forEach(modal => {
                        modal.style.zIndex = '';
                    });
                }
            }

            // Enhanced modal functions for full screen compatibility
            function showModal() {
                const modal = document.getElementById("schedule-modal");
                if (modal) {
                    modal.classList.remove("hidden");
                    modal.classList.add("flex");

                    // Ensure modal is on top in full screen mode
                    const mainContent = document.querySelector('.main-content');
                    if (mainContent.classList.contains('fullscreen-mode')) {
                        modal.style.zIndex = '1001';
                    }

                    console.log("Modal shown");
                } else {
                    console.error("Modal element not found!");
                }
            }

            function closeModal() {
                const modal = document.getElementById("schedule-modal");
                if (modal) {
                    modal.classList.add("hidden");
                    modal.classList.remove("flex");
                    modal.style.zIndex = ''; // Reset z-index
                }

                const form = document.getElementById("schedule-form");
                if (form) form.reset();

                // Reset conflict styles when closing modal
                resetConflictStyles();

                currentEditingId = null;
            }

            // Handle ESC key to exit full screen
            document.addEventListener('keydown', function(event) {
                if (event.key === 'Escape') {
                    const sidebar = document.getElementById('sidebar');
                    if (sidebar.style.display === 'none') {
                        // Exit full screen for both tabs
                        const manualFullscreenBtn = document.getElementById('fullscreen-manual-btn');
                        const viewFullscreenBtn = document.getElementById('fullscreen-view-btn');

                        if (!manualFullscreenBtn.classList.contains('hidden')) {
                            toggleFullScreen('manual');
                        } else if (!viewFullscreenBtn.classList.contains('hidden')) {
                            toggleFullScreen('view');
                        }
                    }
                }
            });

            // Handle browser fullscreen API (optional enhancement)
            function toggleNativeFullScreen() {
                if (!document.fullscreenElement) {
                    document.documentElement.requestFullscreen().catch(err => {
                        console.log(`Error attempting to enable full-screen mode: ${err.message}`);
                    });
                } else {
                    if (document.exitFullscreen) {
                        document.exitFullscreen();
                    }
                }
            }

            // Store the original switchTab function BEFORE redefining it
            const originalSwitchTab = window.switchTab;

            // Enhanced switchTab function with full screen handling
            window.switchTab = function(tabName) {
                // If we're in full screen mode, exit it first
                const sidebar = document.getElementById('sidebar');
                if (sidebar.style.display === 'none') {
                    // Exit full screen for current tab
                    const currentTab = document.querySelector('.tab-content:not(.hidden)').id.replace('content-', '');
                    toggleFullScreen(currentTab);

                    // Small delay to ensure DOM updates before switching tabs
                    setTimeout(() => {
                        performTabSwitch(tabName);
                    }, 50);
                } else {
                    performTabSwitch(tabName);
                }
            };

            // Separate function to handle the actual tab switching
            function performTabSwitch(tabName) {
                // Remove active classes from all tabs
                document.querySelectorAll('.tab-button').forEach(btn => {
                    btn.classList.remove('bg-yellow-500', 'text-white');
                    btn.classList.add('text-gray-700', 'hover:text-gray-900', 'hover:bg-gray-100');
                });

                // Add active class to selected tab
                const targetTab = document.getElementById(`tab-${tabName}`);
                if (targetTab) {
                    targetTab.classList.add('bg-yellow-500', 'text-white');
                    targetTab.classList.remove('text-gray-700', 'hover:text-gray-900', 'hover:bg-gray-100');
                }

                // Hide all tab contents
                document.querySelectorAll('.tab-content').forEach(content => {
                    content.classList.add('hidden');
                });

                // Show selected tab content
                const targetContent = document.getElementById(`content-${tabName}`);
                if (targetContent) {
                    targetContent.classList.remove('hidden');
                }

                // Update URL
                const url = new URL(window.location);
                url.searchParams.set('tab', tabName === 'schedule' ? 'schedule-list' : tabName);
                window.history.pushState({}, '', url);
            }

            // Make sure the original switchTab function exists
            if (typeof window.switchTab === 'undefined') {
                window.switchTab = function(tabName) {
                    performTabSwitch(tabName);
                };
            }

            function formatTime(time) {
                const [hours, minutes] = time.split(':');
                const date = new Date(2000, 0, 1, hours, minutes);
                return date.toLocaleTimeString('en-US', {
                    hour: 'numeric',
                    minute: '2-digit',
                    hour12: true
                });
            }

            function escapeHtml(unsafe) {
                if (unsafe === null || unsafe === undefined) {
                    return '';
                }

                // Convert to string first
                const safeString = String(unsafe);

                // If it's empty after conversion, return empty string
                if (!safeString) {
                    return '';
                }

                return safeString
                    .replace(/&/g, "&amp;")
                    .replace(/</g, "&lt;")
                    .replace(/>/g, "&gt;")
                    .replace(/"/g, "&quot;")
                    .replace(/'/g, "&#039;");
            }

            function showNotification(message, type = 'success') {
                const notification = document.getElementById('notification');
                if (!notification) {
                    const notificationDiv = document.createElement('div');
                    notificationDiv.id = 'notification';
                    notificationDiv.className = 'mb-6';
                    notificationDiv.innerHTML = `
                        <div class="flex items-center p-4 rounded-lg ${type === 'success' ? 'bg-green-50 border border-green-200' : 'bg-red-50 border border-red-200'}">
                            <div class="flex-shrink-0">
                                <i class="fas ${type === 'success' ? 'fa-check-circle text-green-500' : 'fa-exclamation-circle text-red-500'} text-xl"></i>
                            </div>
                            <div class="ml-3">
                                <p class="text-sm font-medium ${type === 'success' ? 'text-green-800' : 'text-red-800'}" id="notificationText">${message}</p>
                            </div>
                            <div class="ml-auto pl-3">
                                <button class="${type === 'success' ? 'text-green-400 hover:text-green-600' : 'text-red-400 hover:text-red-600'}" onclick="hideNotification()">
                                    <i class="fas fa-times"></i>
                                </button>
                            </div>
                        </div>
                    `;
                    document.querySelector('.max-w-7xl').insertBefore(notificationDiv, document.querySelector('.max-w-7xl').firstElementChild.nextElementSibling);
                } else {
                    document.getElementById('notificationText').textContent = message;
                    notification.classList.remove('hidden');
                }

                setTimeout(() => hideNotification(), 5000);
            }

            function hideNotification() {
                const notification = document.getElementById('notification');
                if (notification) notification.classList.add('hidden');
            }

            function togglePrintDropdown() {
                const dropdown = document.getElementById('printDropdown');
                dropdown.classList.toggle('hidden');
            }

            function exportSchedule(type) {
                document.getElementById("printDropdown").classList.add("hidden");

                if (type === 'excel') {
                    exportToExcel();
                } else if (type === 'pdf') {
                    exportToPDF();
                }
            }

            // Add this helper function that's used by both export functions
            function getFilteredSchedules() {
                const yearLevel = document.getElementById('filter-year')?.value || '';
                const section = document.getElementById('filter-section')?.value || '';
                const room = document.getElementById('filter-room')?.value || '';

                return window.scheduleData.filter(schedule => {
                    const matchesYear = !yearLevel || schedule.year_level === yearLevel;
                    const matchesSection = !section || schedule.section_name === section;
                    const matchesRoom = !room || (schedule.room_name || 'Online') === room;

                    return matchesYear && matchesSection && matchesRoom;
                });
            }

            function printSchedule(type) {
                document.getElementById("printDropdown").classList.add("hidden");

                // Apply filters if needed
                if (type === "filtered") {
                    filterSchedules();
                } else if (type === "all") {
                    clearFilters();
                }

                // Switch to schedule view tab and wait for render
                switchTab("schedule");

                setTimeout(() => {
                    createPrintVersion();
                }, 500);
            }

            function getFilteredSchedules() {
                const yearLevel = document.getElementById('filter-year')?.value || '';
                const section = document.getElementById('filter-section')?.value || '';
                const room = document.getElementById('filter-room')?.value || '';

                return window.scheduleData.filter(schedule => {
                    const matchesYear = !yearLevel || schedule.year_level === yearLevel;
                    const matchesSection = !section || schedule.section_name === section;
                    const matchesRoom = !room || (schedule.room_name || 'Online') === room;

                    return matchesYear && matchesSection && matchesRoom;
                });
            }

            function createPrintVersion() {
                // Create a new window for printing
                const printWindow = window.open("", "_blank");
                if (!printWindow) {
                    alert("Please allow popups for printing");
                    return;
                }

                // Get semester information
                const semester = window.currentSemester?.semester_name || "";
                const academicYear = window.currentSemester?.academic_year || "";
                const currentDate = new Date().toLocaleDateString();

                // Create the print content
                const printContent = `
                    <!DOCTYPE html>
                    <html>
                    <head>
                        <title>Academic Schedule - ${semester} ${academicYear}</title>
                        <style>
                    body {
                        font-family: "Times New Roman", serif;
                        margin: 0;
                        padding: 20px;
                        font-size: 12pt;
                        line-height: 1.2;
                    }
                    
                    .university-header {
                        text-align: center;
                        border-bottom: 2px solid #000;
                        padding-bottom: 15px;
                        margin-bottom: 20px;
                    }
                    
                    .header-content {
                        display: flex;
                        align-items: center;
                        justify-content: center;
                        margin-bottom: 10px;
                        gap: 20px;
                    }
                    
                    .university-info {
                        flex: 1;
                        text-align: center;
                    }
                    
                    .university-name {
                        font-size: 14pt;
                        font-weight: bold;
                        margin: 0;
                    }
                    
                    .university-subtitle {
                        font-size: 10pt;
                        font-style: italic;
                        margin: 2px 0;
                    }
                    
                    .logo-container {
                        width: 80px;
                        text-align: center;
                    }
                    
                    .university-logo, .college-logo {
                        max-width: 60px;
                        max-height: 60px;
                        object-fit: contain;
                    }
                    
                    .semester-info {
                        font-size: 12pt;
                        font-weight: bold;
                        margin: 5px 0;
                    }
                    
                    .academic-year {
                        font-size: 11pt;
                        font-weight: bold;
                    }
                    
                    .schedule-table {
                        width: 100%;
                        border-collapse: collapse;
                        font-size: 9pt;
                        margin-top: 15px;
                    }
                    
                    .schedule-table th,
                    .schedule-table td {
                        border: 1px solid #000;
                        padding: 4px 6px;
                        text-align: center;
                        vertical-align: top;
                    }
                    
                    .schedule-table th {
                        background-color: #f0f0f0;
                        font-weight: bold;
                    }
                    
                    .time-column { width: 12%; }
                    .days-column { width: 8%; }
                    .course-column { width: 25%; }
                    .units-column { width: 12%; }
                    .room-column { width: 10%; }
                    .section-column { width: 15%; }
                    .students-column { width: 8%; }
                    .faculty-column { width: 10%; }
                    
                    .faculty-section {
                        margin-bottom: 25px;
                        page-break-inside: avoid;
                    }
                    
                    .faculty-name {
                        font-weight: bold;
                        font-size: 11pt;
                        margin-bottom: 8px;
                        background-color: #e0e0e0;
                        padding: 5px 10px;
                    }
                    
                    @media print {
                        body { margin: 0.5in; }
                        .faculty-section { page-break-inside: avoid; }
                        .logo-container img { max-width: 60px !important; }
                    }
                </style>
                    </head>
                    <body>
                        <div class="university-header">
                            <div class="header-content">
                                <div class="logo-container">
                                    <img src="/assets/logo/main_logo/PRMSUlogo.png" alt="University Logo" class="university-logo">
                                </div>
                                <div class="university-info">
                                    <div class="university-name">Republic of the Philippines</div>
                                    <div class="university-name">President Ramon Magsaysay State University</div>
                                    <div class="university-subtitle">(formerly Ramon Magsaysay Technological University)</div>
                                </div>
                                <div class="logo-container">
                                    <img src="${window.location.origin}<?php echo $collegeLogoPath; ?>" alt="College Logo" class="college-logo" onerror="this.style.display='none'; console.log('College logo not found')">
                                </div>
                            </div>
                                    <div class="semester-info">${semester} Semester</div>
                                    <div class="academic-year">Academic Year ${academicYear}</div>
                                    <div style="font-size: 10pt; margin-top: 5px;">Generated on: ${currentDate}</div>
                                </div>
                                
                                ${generatePrintScheduleTable()}
                            </body>
                            </html>
                        `;

                printWindow.document.write(printContent);
                printWindow.document.close();

                // Wait for content to load then print
                printWindow.onload = function() {
                    printWindow.print();
                    // printWindow.close(); // Uncomment if you want to auto-close after printing
                };
            }

            function generatePrintScheduleTable() {
                if (!window.scheduleData || window.scheduleData.length === 0) {
                    return '<div style="text-align: center; padding: 20px; font-style: italic;">No schedule data available</div>';
                }

                // Organize schedules by faculty
                const facultySchedules = organizeSchedulesByFaculty(window.scheduleData);

                let tableHTML = "";

                Object.keys(facultySchedules)
                    .sort()
                    .forEach((facultyName) => {
                        const schedules = facultySchedules[facultyName];

                        tableHTML += `
                            <div class="faculty-section">
                                <div class="faculty-name">${facultyName}</div>
                                <table class="schedule-table">
                                    <thead>
                                        <tr>
                                            <th class="time-column">Time</th>
                                            <th class="days-column">Days</th>
                                            <th class="course-column">Course Code and Title</th>
                                            
                                            <th class="room-column">Room</th>
                                            <th class="section-column">Year/Section</th>
                                            <th class="students-column">No. of Students</th>
                                        </tr>
                                    </thead>
                                    <tbody>
                        `;

                        // Group schedules by course and time for better display
                        const groupedSchedules = groupSchedulesForDisplay(schedules);

                        groupedSchedules.forEach((schedule) => {
                            tableHTML += `
                <tr>
                    <td class="time-column">${formatTimeForPrint(
                      schedule.startTime
                    )} - ${formatTimeForPrint(schedule.endTime)}</td>
                    <td class="days-column">${schedule.dayPattern}</td>
                    <td class="course-column" style="text-align: left;">
                        <div style="font-weight: bold;">${
                          schedule.courseCode
                        }</div>
                        <div style="font-size: 8pt;">${
                          schedule.courseName || ""
                        }</div>
                    </td>
                    
                    <td class="room-column">${schedule.room}</td>
                    <td class="section-column">${schedule.section}</td>
                    <td class="students-column">${schedule.students || ""}</td>
                </tr>
                    `;
                        });

                        tableHTML += `
                                </tbody>
                            </table>
                        </div>
                    `;
                    });

                return tableHTML;
            }

            function formatTimeForPrint(timeString) {
                if (!timeString) return "";
                const time = timeString.substring(0, 5);
                const [hours, minutes] = time.split(":");
                const date = new Date(2000, 0, 1, hours, minutes);
                return date.toLocaleTimeString("en-US", {
                    hour: "numeric",
                    minute: "2-digit",
                    hour12: true,
                });
            }

            // Helper function to organize schedules by faculty
            function organizeSchedulesByFaculty(schedules) {
                const facultySchedules = {};

                schedules.forEach((schedule) => {
                    const facultyName = schedule.faculty_name || "Unassigned";

                    if (!facultySchedules[facultyName]) {
                        facultySchedules[facultyName] = [];
                    }

                    facultySchedules[facultyName].push(schedule);
                });

                return facultySchedules;
            }

            // Helper function to group schedules for display
            function groupSchedulesForDisplay(schedules) {
                const groups = {};

                schedules.forEach((schedule) => {
                    const key = `${schedule.course_code}-${schedule.start_time}-${schedule.end_time}-${schedule.faculty_name}`;

                    if (!groups[key]) {
                        groups[key] = {
                            courseCode: schedule.course_code,
                            courseName: schedule.course_name || "",
                            startTime: schedule.start_time,
                            endTime: schedule.end_time,
                            faculty: schedule.faculty_name,
                            room: schedule.room_name || "Online",
                            section: schedule.section_name || "",
                            students: schedule.current_students || "",
                            lectureUnits: schedule.lecture_units || "0",
                            labUnits: schedule.lab_units || "0",
                            days: [],
                        };
                    }

                    groups[key].days.push(schedule.day_of_week);
                });

                // Convert to array and format day patterns
                return Object.values(groups)
                    .map((group) => {
                        group.dayPattern = getDayPatternDisplay(group.days);
                        return group;
                    })
                    .sort((a, b) => a.startTime.localeCompare(b.startTime));
            }

            function getDayPatternDisplay(days) {
                const dayMap = {
                    Monday: "M",
                    Tuesday: "T",
                    Wednesday: "W",
                    Thursday: "TH",
                    Friday: "F",
                    Saturday: "S",
                    Sunday: "SU",
                };

                const pattern = days.map((day) => dayMap[day] || day).join("");

                // Common patterns
                const commonPatterns = {
                    MWF: "MWF",
                    TTH: "TTH",
                    MW: "MW",
                    TTHS: "TTHS",
                    MTWTHF: "Daily",
                };

                return commonPatterns[pattern] || pattern;
            }

            function exportToExcel() {
                // Get filtered schedules
                const filteredSchedules = getFilteredSchedules();

                if (filteredSchedules.length === 0) {
                    showNotification('No schedules to export.', 'error');
                    return;
                }

                // Create workbook
                const workbook = XLSX.utils.book_new();

                // Create main data sheet with ALL schedules
                const mainData = [
                    // Header row
                    ['Faculty', 'Time', 'Days', 'Course Code', 'Course Name', 'Section', 'Room', 'Students', 'Lecture Units', 'Lab Units']
                ];

                // Add all schedules to main sheet
                filteredSchedules.forEach(schedule => {
                    mainData.push([
                        schedule.faculty_name || 'Unassigned',
                        `${formatTime(schedule.start_time?.substring(0, 5) || '')} - ${formatTime(schedule.end_time?.substring(0, 5) || '')}`,
                        schedule.day_of_week || '',
                        schedule.course_code || '',
                        schedule.course_name || '',
                        schedule.section_name || '',
                        schedule.room_name || 'Online',
                        schedule.current_students || '',
                        schedule.lecture_units || '0',
                        schedule.lab_units || '0'
                    ]);
                });

                // Create main worksheet
                const mainWorksheet = XLSX.utils.aoa_to_sheet(mainData);

                // Set column widths for main sheet
                mainWorksheet['!cols'] = [{
                        wch: 20
                    }, // Faculty
                    {
                        wch: 15
                    }, // Time
                    {
                        wch: 8
                    }, // Days
                    {
                        wch: 12
                    }, // Course Code
                    {
                        wch: 30
                    }, // Course Name
                    {
                        wch: 15
                    }, // Section
                    {
                        wch: 12
                    }, // Room
                    {
                        wch: 10
                    }, // Students
                    {
                        wch: 12
                    }, // Lecture Units
                    {
                        wch: 10
                    } // Lab Units
                ];

                XLSX.utils.book_append_sheet(workbook, mainWorksheet, 'All Schedules');

                // Generate Excel file
                const semester = window.currentSemester?.semester_name || 'Unknown';
                const academicYear = window.currentSemester?.academic_year || 'Unknown';
                const fileName = `Schedule_${semester}_${academicYear}_${new Date().toISOString().split('T')[0]}.xlsx`;

                XLSX.writeFile(workbook, fileName);
                showNotification('Excel file exported successfully!', 'success');
            }

            function exportToPDF() {
                const {
                    jsPDF
                } = window.jspdf;

                // Get filtered schedules
                const filteredSchedules = getFilteredSchedules();

                if (filteredSchedules.length === 0) {
                    showNotification('No schedules to export.', 'error');
                    return;
                }

                // Create new PDF document
                const doc = new jsPDF({
                    orientation: 'landscape',
                    unit: 'mm',
                    format: 'a4'
                });

                const pageWidth = doc.internal.pageSize.getWidth();
                const pageHeight = doc.internal.pageSize.getHeight();
                const margin = 10;
                const contentWidth = pageWidth - (2 * margin);

                // Add header with university info
                addPDFHeader(doc, pageWidth, margin);

                let currentY = 60; // Start below header

                // Group schedules by faculty
                const facultyGroups = {};
                filteredSchedules.forEach(schedule => {
                    const facultyName = schedule.faculty_name || 'Unassigned';
                    if (!facultyGroups[facultyName]) {
                        facultyGroups[facultyName] = [];
                    }
                    facultyGroups[facultyName].push(schedule);
                });

                // Add content for each faculty
                Object.keys(facultyGroups).sort().forEach((facultyName, index) => {
                    // Check if we need a new page
                    if (currentY > pageHeight - 40 && index > 0) {
                        doc.addPage();
                        currentY = margin + 20;
                        addPDFHeader(doc, pageWidth, margin, true);
                    }

                    // Add faculty section header
                    doc.setFillColor(200, 200, 200);
                    doc.rect(margin, currentY, contentWidth, 8, 'F');
                    doc.setTextColor(0, 0, 0);
                    doc.setFontSize(12);
                    doc.setFont(undefined, 'bold');
                    doc.text(`Faculty: ${facultyName}`, margin + 5, currentY + 5);

                    currentY += 15;

                    // Create table for this faculty
                    const schedules = facultyGroups[facultyName];
                    addScheduleTable(doc, schedules, margin, currentY, contentWidth);

                    currentY += (schedules.length * 8) + 20;
                });

                // Save PDF
                const semester = window.currentSemester?.semester_name || 'Unknown';
                const academicYear = window.currentSemester?.academic_year || 'Unknown';
                const fileName = `Schedule_${semester}_${academicYear}_${new Date().toISOString().split('T')[0]}.pdf`;

                doc.save(fileName);
                showNotification('PDF file exported successfully!', 'success');
            }

            function addPDFHeader(doc, pageWidth, margin, isSubsequentPage = false) {
                const centerX = pageWidth / 2;

                // University header text
                doc.setFontSize(16);
                doc.setFont(undefined, 'bold');
                doc.text('Republic of the Philippines', centerX, 15, {
                    align: 'center'
                });
                doc.text('President Ramon Magsaysay State University', centerX, 22, {
                    align: 'center'
                });

                doc.setFontSize(10);
                doc.setFont(undefined, 'normal');
                doc.text('(formerly Ramon Magsaysay Technological University)', centerX, 27, {
                    align: 'center'
                });

                // Semester info
                doc.setFontSize(12);
                doc.setFont(undefined, 'bold');
                const semester = window.currentSemester?.semester_name || 'Unknown';
                const academicYear = window.currentSemester?.academic_year || 'Unknown';
                doc.text(`${semester} Semester - Academic Year ${academicYear}`, centerX, 37, {
                    align: 'center'
                });

                if (!isSubsequentPage) {
                    doc.setFontSize(10);
                    doc.setFont(undefined, 'normal');
                    doc.text(`Generated on: ${new Date().toLocaleDateString()}`, centerX, 44, {
                        align: 'center'
                    });
                }

                // Add line separator
                doc.setDrawColor(0, 0, 0);
                doc.line(margin, 48, pageWidth - margin, 48);
            }

            function addScheduleTable(doc, schedules, startX, startY, tableWidth) {
                const colWidths = [
                    tableWidth * 0.15, // Time
                    tableWidth * 0.08, // Days
                    tableWidth * 0.12, // Course Code
                    tableWidth * 0.25, // Course Name
                    tableWidth * 0.15, // Section
                    tableWidth * 0.12, // Room
                    tableWidth * 0.08, // Students
                    tableWidth * 0.05 // Units
                ];

                // Table headers
                const headers = ['Time', 'Days', 'Course Code', 'Course Name', 'Section', 'Room', 'Students', 'Units'];

                let currentX = startX;
                let currentY = startY;

                // Draw header row
                doc.setFillColor(100, 100, 100);
                doc.rect(currentX, currentY, tableWidth, 8, 'F');
                doc.setTextColor(255, 255, 255);
                doc.setFontSize(8);
                doc.setFont(undefined, 'bold');

                headers.forEach((header, index) => {
                    doc.text(header, currentX + 2, currentY + 5);
                    currentX += colWidths[index];
                });

                currentY += 8;
                doc.setTextColor(0, 0, 0);
                doc.setFont(undefined, 'normal');

                // Draw schedule rows
                schedules.forEach((schedule, rowIndex) => {
                    currentX = startX;

                    // Alternate row colors
                    if (rowIndex % 2 === 0) {
                        doc.setFillColor(240, 240, 240);
                        doc.rect(currentX, currentY, tableWidth, 8, 'F');
                    }

                    const rowData = [
                        `${formatTime(schedule.start_time?.substring(0, 5) || '')} - ${formatTime(schedule.end_time?.substring(0, 5) || '')}`,
                        schedule.day_of_week || '',
                        schedule.course_code || '',
                        schedule.course_name || '',
                        schedule.section_name || '',
                        schedule.room_name || 'Online',
                        schedule.current_students?.toString() || '',
                        `${schedule.lecture_units || '0'}/${schedule.lab_units || '0'}`
                    ];

                    rowData.forEach((cell, colIndex) => {
                        doc.text(cell.substring(0, 20), currentX + 2, currentY + 5); // Limit text length
                        currentX += colWidths[colIndex];
                    });

                    currentY += 8;

                    // Check if we need a new page
                    if (currentY > doc.internal.pageSize.getHeight() - 20) {
                        doc.addPage();
                        currentY = 20;
                        addPDFHeader(doc, doc.internal.pageSize.getWidth(), 10, true);
                    }
                });
            }

            function exportToPDF() {
                const {
                    jsPDF
                } = window.jspdf;

                // Get filtered schedules
                const filteredSchedules = getFilteredSchedules();

                if (filteredSchedules.length === 0) {
                    showNotification('No schedules to export.', 'error');
                    return;
                }

                // Create new PDF document
                const doc = new jsPDF({
                    orientation: 'landscape',
                    unit: 'mm',
                    format: 'a4'
                });

                const pageWidth = doc.internal.pageSize.getWidth();
                const pageHeight = doc.internal.pageSize.getHeight();
                const margin = 10;
                const contentWidth = pageWidth - (2 * margin);

                // Add header with university info
                addPDFHeader(doc, pageWidth, margin);

                let currentY = 60; // Start below header

                // Group schedules by faculty
                const facultyGroups = {};
                filteredSchedules.forEach(schedule => {
                    const facultyName = schedule.faculty_name || 'Unassigned';
                    if (!facultyGroups[facultyName]) {
                        facultyGroups[facultyName] = [];
                    }
                    facultyGroups[facultyName].push(schedule);
                });

                // Add content for each faculty
                Object.keys(facultyGroups).sort().forEach((facultyName, index) => {
                    // Check if we need a new page
                    if (currentY > pageHeight - 40 && index > 0) {
                        doc.addPage();
                        currentY = margin + 20;
                        addPDFHeader(doc, pageWidth, margin, true);
                    }

                    // Add faculty section header
                    doc.setFillColor(200, 200, 200);
                    doc.rect(margin, currentY, contentWidth, 8, 'F');
                    doc.setTextColor(0, 0, 0);
                    doc.setFontSize(12);
                    doc.setFont(undefined, 'bold');
                    doc.text(`Faculty: ${facultyName}`, margin + 5, currentY + 5);

                    currentY += 15;

                    // Create table for this faculty
                    const schedules = facultyGroups[facultyName];
                    addScheduleTable(doc, schedules, margin, currentY, contentWidth);

                    currentY += (schedules.length * 8) + 20;
                });

                // Save PDF
                const semester = window.currentSemester?.semester_name || 'Unknown';
                const academicYear = window.currentSemester?.academic_year || 'Unknown';
                const fileName = `Schedule_${semester}_${academicYear}_${new Date().toISOString().split('T')[0]}.pdf`;

                doc.save(fileName);
                showNotification('PDF file exported successfully!', 'success');
            }

            function addPDFHeader(doc, pageWidth, margin, isSubsequentPage = false) {
                const centerX = pageWidth / 2;

                // University header text
                doc.setFontSize(16);
                doc.setFont(undefined, 'bold');
                doc.text('Republic of the Philippines', centerX, 15, {
                    align: 'center'
                });
                doc.text('President Ramon Magsaysay State University', centerX, 22, {
                    align: 'center'
                });

                doc.setFontSize(10);
                doc.setFont(undefined, 'normal');
                doc.text('(formerly Ramon Magsaysay Technological University)', centerX, 27, {
                    align: 'center'
                });

                // Semester info
                doc.setFontSize(12);
                doc.setFont(undefined, 'bold');
                const semester = window.currentSemester?.semester_name || 'Unknown';
                const academicYear = window.currentSemester?.academic_year || 'Unknown';
                doc.text(`${semester} Semester - Academic Year ${academicYear}`, centerX, 37, {
                    align: 'center'
                });

                if (!isSubsequentPage) {
                    doc.setFontSize(10);
                    doc.setFont(undefined, 'normal');
                    doc.text(`Generated on: ${new Date().toLocaleDateString()}`, centerX, 44, {
                        align: 'center'
                    });
                }

                // Add line separator
                doc.setDrawColor(0, 0, 0);
                doc.line(margin, 48, pageWidth - margin, 48);
            }

            function addScheduleTable(doc, schedules, startX, startY, tableWidth) {
                const colWidths = [
                    tableWidth * 0.15, // Time
                    tableWidth * 0.08, // Days
                    tableWidth * 0.12, // Course Code
                    tableWidth * 0.25, // Course Name
                    tableWidth * 0.15, // Section
                    tableWidth * 0.12, // Room
                    tableWidth * 0.08, // Students
                    tableWidth * 0.05 // Units
                ];

                // Table headers
                const headers = ['Time', 'Days', 'Course Code', 'Course Name', 'Section', 'Room', 'Students', 'Units'];

                let currentX = startX;
                let currentY = startY;

                // Draw header row
                doc.setFillColor(100, 100, 100);
                doc.rect(currentX, currentY, tableWidth, 8, 'F');
                doc.setTextColor(255, 255, 255);
                doc.setFontSize(8);
                doc.setFont(undefined, 'bold');

                headers.forEach((header, index) => {
                    doc.text(header, currentX + 2, currentY + 5);
                    currentX += colWidths[index];
                });

                currentY += 8;
                doc.setTextColor(0, 0, 0);
                doc.setFont(undefined, 'normal');

                // Draw schedule rows
                schedules.forEach((schedule, rowIndex) => {
                    currentX = startX;

                    // Alternate row colors
                    if (rowIndex % 2 === 0) {
                        doc.setFillColor(240, 240, 240);
                        doc.rect(currentX, currentY, tableWidth, 8, 'F');
                    }

                    const rowData = [
                        `${formatTime(schedule.start_time?.substring(0, 5) || '')} - ${formatTime(schedule.end_time?.substring(0, 5) || '')}`,
                        schedule.day_of_week || '',
                        schedule.course_code || '',
                        schedule.course_name || '',
                        schedule.section_name || '',
                        schedule.room_name || 'Online',
                        schedule.current_students?.toString() || '',
                        `${schedule.lecture_units || '0'}/${schedule.lab_units || '0'}`
                    ];

                    rowData.forEach((cell, colIndex) => {
                        doc.text(cell.substring(0, 20), currentX + 2, currentY + 5); // Limit text length
                        currentX += colWidths[colIndex];
                    });

                    currentY += 8;

                    // Check if we need a new page
                    if (currentY > doc.internal.pageSize.getHeight() - 20) {
                        doc.addPage();
                        currentY = 20;
                        addPDFHeader(doc, doc.internal.pageSize.getWidth(), 10, true);
                    }
                });
            }

            function filterSchedules() {
                const yearLevel = document.getElementById('filter-year').value;
                const section = document.getElementById('filter-section').value;
                const room = document.getElementById('filter-room').value;
                const scheduleCells = document.querySelectorAll('#timetableGrid .schedule-cell');

                scheduleCells.forEach(cell => {
                    const items = cell.querySelectorAll('.schedule-item');
                    let shouldShow = false;

                    items.forEach(item => {
                        const itemYearLevel = item.getAttribute('data-year-level');
                        const itemSectionName = item.getAttribute('data-section-name');
                        const itemRoomName = item.getAttribute('data-room-name');
                        const matchesYear = !yearLevel || itemYearLevel === yearLevel;
                        const matchesSection = !section || itemSectionName === section;
                        const matchesRoom = !room || itemRoomName === room;

                        if (matchesYear && matchesSection && matchesRoom) {
                            item.style.display = 'block';
                            shouldShow = true;
                        } else {
                            item.style.display = 'none';
                        }
                    });

                    cell.style.display = shouldShow ? 'block' : 'block';
                });
            }

            function clearFilters() {
                document.getElementById('filter-year').value = '';
                document.getElementById('filter-section').value = '';
                document.getElementById('filter-room').value = '';
                filterSchedules();
            }

            function safeUpdateScheduleDisplay(schedules) {
                window.scheduleData = schedules;

                // Update manual grid
                const manualGrid = document.getElementById("schedule-grid");
                if (manualGrid) {
                    manualGrid.innerHTML = "";

                    // Build dynamic time slots from schedules so any start/end (e.g. 08:00-09:00, 08:00-09:30) will appear as its own row.
                    // Fallback range used when no schedules present.
                    const defaultStart = '07:30';
                    const defaultEnd = '21:00';

                    // Collect all relevant time points (start and end times) from schedules, plus defaults
                    const timePointsSet = new Set([defaultStart, defaultEnd]);
                    schedules.forEach(s => {
                        if (s.start_time) timePointsSet.add(s.start_time.substring(0, 5));
                        if (s.end_time) timePointsSet.add(s.end_time.substring(0, 5));
                    });

                    // Convert to array and sort by minutes-of-day
                    const timePoints = Array.from(timePointsSet).filter(Boolean).map(tp => {
                        const parts = tp.split(':').map(x => parseInt(x, 10));
                        return {
                            raw: tp,
                            minutes: parts[0] * 60 + (parts[1] || 0)
                        };
                    }).sort((a, b) => a.minutes - b.minutes).map(x => x.raw);

                    // If we somehow only have one point, build a sensible step-based list (30-min steps)
                    let times = [];
                    if (timePoints.length < 2) {
                        const toMinutes = t => {
                            const [h, m] = t.split(':');
                            return parseInt(h) * 60 + parseInt(m);
                        };
                        const fromMinutes = m => {
                            const hh = Math.floor(m / 60).toString().padStart(2, '0');
                            const mm = (m % 60).toString().padStart(2, '0');
                            return `${hh}:${mm}`;
                        };
                        const startMin = toMinutes(defaultStart);
                        const endMin = toMinutes(defaultEnd);
                        for (let m = startMin; m < endMin; m += 30) {
                            times.push([fromMinutes(m), fromMinutes(Math.min(m + 30, endMin))]);
                        }
                    } else {
                        // Build intervals from consecutive unique time points
                        for (let i = 0; i < timePoints.length - 1; i++) {
                            const a = timePoints[i];
                            const b = timePoints[i + 1];
                            // Skip zero-length intervals
                            if (a !== b) times.push([a, b]);
                        }
                    }

                    times.forEach(time => {
                        // Calculate row span like PHP does
                        const duration = (new Date(`2000-01-01 ${time[1]}`) - new Date(`2000-01-01 ${time[0]}`)) / 1000;
                        const rowSpan = duration / 7200; // 2 hours in seconds
                        const minHeight = rowSpan * 80;

                        const row = document.createElement('div');
                        row.className = `grid grid-cols-8 min-h-[${minHeight}px] hover:bg-gray-50 transition-colors duration-200`; // Changed to grid-cols-8
                        row.style.gridRow = `span ${rowSpan}`

                        // Time cell - match PHP structure
                        const timeCell = document.createElement('div');
                        timeCell.className = 'px-3 py-3 text-sm font-medium text-gray-600 border-r border-gray-200 bg-gray-50 flex items-center sticky left-0 z-10';
                        timeCell.setAttribute('rowspan', rowSpan);

                        // Time content like PHP
                        timeCell.innerHTML = `
                        <span class="text-sm hidden sm:block">${formatTime(time[0])} - ${formatTime(time[1])}</span>
                        <span class="text-xs sm:hidden">${time[0].substring(0, 5)}-${time[1].substring(0, 5)}</span>
                    `;
                        row.appendChild(timeCell);

                        // Day cells
                        ['Monday', 'Tuesday', 'Wednesday', 'Thursday', 'Friday', 'Saturday', 'Sunday'].forEach(day => {
                            const cell = document.createElement('div');
                            cell.className = `px-1 py-1 border-r border-gray-200 last:border-r-0 min-h-[${minHeight}px] relative drop-zone`;
                            cell.dataset.day = day;
                            cell.dataset.startTime = time[0];
                            cell.dataset.endTime = time[1];

                            // Find ALL schedules for this time slot (not just one)
                            const schedulesForSlot = schedules.filter(s =>
                                s.day_of_week === day &&
                                s.start_time && s.start_time.substring(0, 5) === time[0] &&
                                s.end_time && s.end_time.substring(0, 5) === time[1]
                            );

                            if (schedulesForSlot.length > 0) {
                                // Create a container for multiple schedules
                                const schedulesContainer = document.createElement('div');
                                schedulesContainer.className = 'schedules-container space-y-1';

                                schedulesForSlot.forEach(schedule => {
                                    const scheduleCard = createSafeScheduleCard(schedule);
                                    schedulesContainer.appendChild(scheduleCard);
                                });

                                cell.appendChild(schedulesContainer);
                            } else {
                                // Add button for empty slot
                                const addButton = document.createElement('button');
                                addButton.innerHTML = '<i class="fas fa-plus text-sm"></i>';
                                addButton.className = 'w-full h-full text-gray-400 hover:text-gray-600 hover:bg-yellow-50 rounded-lg border-2 border-dashed border-gray-300 hover:border-yellow-400 transition-all duration-200 no-print flex items-center justify-center p-2';
                                addButton.onclick = () => openAddModalForSlot(day, time[0], time[1]);
                                cell.appendChild(addButton);
                            }

                            row.appendChild(cell);
                        });

                        manualGrid.appendChild(row);
                    });

                    initializeDragAndDrop();
                }

                // Update view grid with similar fixes
                const viewGrid = document.getElementById('timetableGrid');
                if (viewGrid) {
                    viewGrid.innerHTML = '';

                    const times = [
                        ['07:30', '08:30'],
                        ['08:30', '10:00'],
                        ['10:00', '11:00'],
                        ['11:00', '12:30'],
                        ['12:30', '13:30'],
                        ['13:00', '14:30'],
                        ['14:30', '15:30'],
                        ['15:30', '17:00'],
                        ['17:00', '18:00']
                    ];

                    times.forEach(time => {
                        // Calculate row span
                        const duration = (new Date(`${new Date().toISOString().split('T')[0]} ${time[1]}`) - new Date(`${new Date().toISOString().split('T')[0]} ${time[0]}`)) / 1000;
                        const rowSpan = duration / 7200;
                        const minHeight = rowSpan * 80;

                        const row = document.createElement('div');
                        row.className = `grid grid-cols-8 min-h-[${minHeight}px] hover:bg-gray-50 transition-colors duration-200`;
                        row.style.gridRow = `span ${rowSpan}`;

                        // Time cell
                        const timeCell = document.createElement('div');
                        timeCell.className = 'px-4 py-3 text-sm font-medium text-gray-600 border-r border-gray-200 bg-gray-50 flex items-center';
                        timeCell.setAttribute('rowspan', rowSpan);
                        timeCell.textContent = `${formatTime(time[0])} - ${formatTime(time[1])}`;
                        row.appendChild(timeCell);

                        // Day cells
                        ['Monday', 'Tuesday', 'Wednesday', 'Thursday', 'Friday', 'Saturday', 'Sunday'].forEach(day => {
                            const cell = document.createElement('div');
                            cell.className = `px-2 py-2 border-r border-gray-200 last:border-r-0 min-h-[${minHeight}px] relative schedule-cell`;

                            // Find ALL schedules for this time slot
                            const daySchedules = schedules.filter(s =>
                                s.day_of_week === day &&
                                s.start_time && s.start_time.substring(0, 5) === time[0] &&
                                s.end_time && s.end_time.substring(0, 5) === time[1]
                            );

                            if (daySchedules.length > 0) {
                                // Create container for multiple schedule items
                                const schedulesContainer = document.createElement('div');
                                schedulesContainer.className = 'schedules-container space-y-1';

                                daySchedules.forEach(schedule => {
                                    const scheduleItem = createSafeScheduleItem(schedule);
                                    schedulesContainer.appendChild(scheduleItem);
                                });

                                cell.appendChild(schedulesContainer);
                            }

                            row.appendChild(cell);
                        });

                        viewGrid.appendChild(row);
                    });
                }
            }

            // Safe function to create schedule card for manual tab
            function createSafeScheduleCard(schedule) {
                const card = document.createElement('div');

                // Use the same color system as PHP
                const colors = [
                    'bg-blue-100 border-blue-300 text-blue-800',
                    'bg-green-100 border-green-300 text-green-800',
                    'bg-purple-100 border-purple-300 text-purple-800',
                    'bg-orange-100 border-orange-300 text-orange-800',
                    'bg-pink-100 border-pink-300 text-pink-800'
                ];

                // Generate consistent color based on schedule_id or random
                const colorIndex = schedule.schedule_id ?
                    (parseInt(schedule.schedule_id) % colors.length) :
                    Math.floor(Math.random() * colors.length);
                const colorClass = colors[colorIndex];

                card.className = `schedule-card ${colorClass} p-2 rounded-lg border-l-4 draggable cursor-move w-full`;
                card.draggable = true;
                card.dataset.scheduleId = schedule.schedule_id || '';
                card.dataset.yearLevel = schedule.year_level || '';
                card.dataset.sectionName = schedule.section_name || '';
                card.dataset.roomName = schedule.room_name || 'Online';

                card.ondragstart = handleDragStart;
                card.ondragend = handleDragEnd;

                // Safe content creation - match PHP structure exactly
                card.innerHTML = `
                    <div class="flex justify-between items-start mb-1">
                        <div class="font-semibold text-xs truncate flex-1">
                            ${schedule.course_code || ''}
                        </div>
                        <div class="flex space-x-1 ml-2">
                            <button onclick="editSchedule('${schedule.schedule_id || ''}')" class="text-yellow-600 hover:text-yellow-700 text-xs no-print flex-shrink-0">
                                <i class="fas fa-edit"></i>
                            </button>
                            <button onclick="openDeleteSingleModal(
                                '${schedule.schedule_id || ''}', 
                                '${schedule.course_code || ''}', 
                                '${schedule.section_name || ''}', 
                                '${schedule.day_of_week || ''}', 
                                '${schedule.start_time ? formatTime(schedule.start_time.substring(0, 5)) : ''}', 
                                '${schedule.end_time ? formatTime(schedule.end_time.substring(0, 5)) : ''}'
                            )" class="text-red-600 hover:text-red-700 text-xs no-print flex-shrink-0">
                                <i class="fas fa-trash"></i>
                            </button>
                        </div>
                    </div>
                    <div class="text-xs opacity-90 truncate mb-1">
                        ${schedule.section_name || ''}
                    </div>
                    <div class="text-xs opacity-75 truncate">
                        ${schedule.faculty_name || ''}
                    </div>
                    <div class="text-xs opacity-75 truncate">
                        ${schedule.room_name || 'Online'}
                    </div>
                    <div class="text-xs font-medium mt-1 hidden sm:block">
                        ${schedule.start_time && schedule.end_time ? 
                            `${formatTime(schedule.start_time.substring(0, 5))} - ${formatTime(schedule.end_time.substring(0, 5))}` : 
                            ''}
                    </div>
                `;

                return card;
            }

            // Safe function to create schedule item for view tab
            function createSafeScheduleItem(schedule) {
                const item = document.createElement('div');

                // Use the same color system as PHP for consistency
                const colors = [
                    'bg-blue-100 border-blue-300 text-blue-800',
                    'bg-green-100 border-green-300 text-green-800',
                    'bg-purple-100 border-purple-300 text-purple-800',
                    'bg-orange-100 border-orange-300 text-orange-800',
                    'bg-pink-100 border-pink-300 text-pink-800'
                ];

                // Generate consistent color based on schedule_id
                const colorIndex = schedule.schedule_id ?
                    (parseInt(schedule.schedule_id) % colors.length) :
                    Math.floor(Math.random() * colors.length);
                const colorClass = colors[colorIndex];

                item.className = `schedule-card ${colorClass} p-2 rounded-lg border-l-4 mb-1 schedule-item`;
                item.dataset.yearLevel = schedule.year_level || '';
                item.dataset.sectionName = schedule.section_name || '';
                item.dataset.roomName = schedule.room_name || 'Online';

                item.innerHTML = `
                    <div class="font-semibold text-xs truncate mb-1">
                        ${schedule.course_code || ''}
                    </div>
                    <div class="text-xs opacity-90 truncate mb-1">
                        ${schedule.section_name || ''}
                    </div>
                    <div class="text-xs opacity-75 truncate">
                        ${schedule.faculty_name || ''}
                    </div>
                    <div class="text-xs opacity-75 truncate">
                        ${schedule.room_name || 'Online'}
                    </div>
                    <div class="text-xs font-medium mt-1">
                        ${schedule.start_time && schedule.end_time ? 
                            `${formatTime(schedule.start_time.substring(0, 5))} - ${formatTime(schedule.end_time.substring(0, 5))}` : 
                            ''}
                    </div>
                `;

                return item;
            }

            // Toggle unassigned courses list
            function toggleUnassignedCourses() {
                const list = document.getElementById('unassigned-courses-list');
                const button = event.target.closest('button');
                const icon = button.querySelector('i');

                if (list.classList.contains('hidden')) {
                    list.classList.remove('hidden');
                    icon.classList.remove('fa-chevron-down');
                    icon.classList.add('fa-chevron-up');
                } else {
                    list.classList.add('hidden');
                    icon.classList.remove('fa-chevron-up');
                    icon.classList.add('fa-chevron-down');
                }
            }

            // Hide the incomplete schedule warning
            function hideIncompleteWarning() {
                const banner = document.getElementById('incomplete-schedule-banner');
                if (banner) {
                    banner.style.display = 'none';
                }
            }

            // Try to regenerate incomplete schedules
            function tryRegenerateIncomplete() {
                const form = document.getElementById('generate-form');
                const curriculumId = form.querySelector('#curriculum_id').value;

                if (!curriculumId) {
                    showNotification('Please select a curriculum first.', 'error');
                    return;
                }

                // Show loading
                const loadingOverlay = document.getElementById('loading-overlay');
                loadingOverlay.classList.remove('hidden');

                // Add force_regenerate flag
                const formData = new URLSearchParams({
                    action: 'generate_schedule',
                    curriculum_id: curriculumId,
                    semester_id: form.querySelector('[name="semester_id"]').value,
                    force_regenerate: 'true' // Add this flag for backend
                });

                fetch('/chair/generate-schedules', {
                        method: 'POST',
                        headers: {
                            'Content-Type': 'application/x-www-form-urlencoded',
                        },
                        body: formData
                    })
                    .then(response => response.json())
                    .then(data => {
                        loadingOverlay.classList.add('hidden');

                        if (data.success) {
                            window.scheduleData = data.schedules || [];
                            safeUpdateScheduleDisplay(window.scheduleData);

                            // Check if still incomplete
                            if (data.unassignedCourses && data.unassignedCourses.length > 0) {
                                showNotification(
                                    `Regeneration completed but ${data.unassignedCourses.length} courses still need manual scheduling.`,
                                    'warning'
                                );
                            } else {
                                showNotification('All courses scheduled successfully!', 'success');
                                hideIncompleteWarning();
                            }
                        } else {
                            showNotification(data.message || 'Regeneration failed', 'error');
                        }
                    })
                    .catch(error => {
                        loadingOverlay.classList.add('hidden');
                        console.error('Regenerate error:', error);
                        showNotification('Error during regeneration: ' + error.message, 'error');
                    });
            }

            // Enhanced report modal to show incomplete schedules
            function showReportModal(data) {
                const reportModal = document.getElementById('report-modal');
                const reportContent = document.getElementById('report-content');
                const reportTitle = document.getElementById('report-title');

                let statusText, statusClass, titleText;

                // Determine status based on results
                if (!data.schedules || data.schedules.length === 0) {
                    statusText = 'No schedules were created. Please check if there are available sections, courses, faculty, and rooms.';
                    statusClass = 'text-red-600 bg-red-50 border-red-200';
                    titleText = 'Schedule Generation Failed';
                } else if (data.unassignedCourses && data.unassignedCourses.length > 0) {
                    statusText = `Partial success. ${data.unassignedCourses.length} courses could not be scheduled and need manual attention.`;
                    statusClass = 'text-yellow-600 bg-yellow-50 border-yellow-200';
                    titleText = 'Schedule Generation Partially Complete';

                    // Show persistent warning on manual tab
                    showPersistentIncompleteWarning(data.unassignedCourses);
                } else {
                    statusText = 'All schedules generated successfully!';
                    statusClass = 'text-green-600 bg-green-50 border-green-200';
                    titleText = 'Schedule Generation Complete';
                }

                // Build report content
                reportContent.innerHTML = `
                    <div class="p-4 ${statusClass} border rounded-lg mb-4">
                        <p class="font-semibold">${statusText}</p>
                    </div>
                    <div class="grid grid-cols-1 md:grid-cols-3 gap-4 text-sm">
                        <div class="bg-white p-3 rounded-lg text-center border border-gray-200">
                            <div class="text-2xl font-bold ${statusClass.split(' ')[0]}">${data.totalCourses || 0}</div>
                            <div class="text-gray-600 mt-1">Total Courses</div>
                        </div>
                        <div class="bg-white p-3 rounded-lg text-center border border-gray-200">
                            <div class="text-2xl font-bold ${statusClass.split(' ')[0]}">${data.totalSections || 0}</div>
                            <div class="text-gray-600 mt-1">Sections</div>
                        </div>
                        <div class="bg-white p-3 rounded-lg text-center border border-gray-200">
                            <div class="text-2xl font-bold ${statusClass.split(' ')[0]}">${data.successRate || '0%'}</div>
                            <div class="text-gray-600 mt-1">Success Rate</div>
                        </div>
                    </div>
                    ${data.unassignedCourses && data.unassignedCourses.length > 0 ? `
                        <div class="mt-4 p-3 bg-yellow-50 border border-yellow-200 rounded-lg">
                            <p class="text-sm font-medium text-yellow-800 mb-2">Unscheduled Courses (${data.unassignedCourses.length}):</p>
                            <div class="max-h-40 overflow-y-auto">
                                <ul class="text-sm text-yellow-700 list-disc list-inside">
                                    ${data.unassignedCourses.map(c => `<li class="py-1">${c.course_code} - ${c.course_name || 'Unknown'}</li>`).join('')}
                                </ul>
                            </div>
                            <p class="text-xs text-yellow-600 mt-2">
                                <i class="fas fa-lightbulb mr-1"></i>
                                These courses need manual scheduling. Switch to the Manual Edit tab to schedule them.
                            </p>
                        </div>
                    ` : ''}
                `;

                reportTitle.textContent = titleText;
                reportTitle.className = `text-lg font-semibold ${statusClass.split(' ')[0]}`;

                // Show the modal
                reportModal.classList.remove('hidden');
                reportModal.classList.add('flex');
            }

            // Show persistent warning on manual tab
            function showPersistentIncompleteWarning(unassignedCourses) {
                // This will be displayed when user switches to manual tab
                sessionStorage.setItem('incompleteSchedules', JSON.stringify(unassignedCourses));
            }

            // Check for incomplete schedules when switching to manual tab
            function checkForIncompleteSchedules() {
                const incomplete = sessionStorage.getItem('incompleteSchedules');
                if (incomplete) {
                    const unassignedCourses = JSON.parse(incomplete);
                    // You can show a notification or update the UI
                    console.log('Incomplete schedules detected:', unassignedCourses);
                }
                }

            // Helper function to get consistent color for a schedule
            function getScheduleColor(schedule) {
                const colors = [
                    'bg-blue-100 border-blue-300 text-blue-800',
                    'bg-green-100 border-green-300 text-green-800',
                    'bg-purple-100 border-purple-300 text-purple-800',
                    'bg-orange-100 border-orange-300 text-orange-800',
                    'bg-pink-100 border-pink-300 text-pink-800'
                ];

                if (schedule.schedule_id) {
                    // Use schedule_id for consistent coloring
                    return colors[parseInt(schedule.schedule_id) % colors.length];
                } else if (schedule.course_code) {
                    // Use course_code hash for new schedules
                    let hash = 0;
                    for (let i = 0; i < schedule.course_code.length; i++) {
                        hash = ((hash << 5) - hash) + schedule.course_code.charCodeAt(i);
                        hash = hash & hash;
                    }
                    return colors[Math.abs(hash) % colors.length];
                } else {
                    // Fallback to random
                    return colors[Math.floor(Math.random() * colors.length)];
                }
            }

            // NEW: Separate function to show report modal
            function showReportModal(data) {
                const reportModal = document.getElementById('report-modal');
                const reportContent = document.getElementById('report-content');
                const reportTitle = document.getElementById('report-title');

                let statusText, statusClass;

                // Determine status based on results
                if (!data.schedules || data.schedules.length === 0) {
                    statusText = 'No schedules were created. Please check if there are available sections, courses, faculty, and rooms.';
                    statusClass = 'text-red-600 bg-red-50 border-red-200';
                    reportTitle.textContent = 'Schedule Generation Failed';
                } else if (data.unassignedCourses && data.unassignedCourses.length > 0) {
                    statusText = `Partial success. ${data.unassignedCourses.length} courses could not be scheduled: ${data.unassignedCourses.map(c => c.course_code).join(', ')}`;
                    statusClass = 'text-yellow-600 bg-yellow-50 border-yellow-200';
                    reportTitle.textContent = 'Schedule Generation Partially Complete';
                } else {
                    statusText = 'All schedules generated successfully!';
                    statusClass = 'text-green-600 bg-green-50 border-green-200';
                    reportTitle.textContent = 'Schedule Generation Complete';
                }

                // Build report content
                reportContent.innerHTML = `
                    <div class="p-4 ${statusClass} border rounded-lg mb-4">
                        <p class="font-semibold">${statusText}</p>
                    </div>
                    <div class="grid grid-cols-1 md:grid-cols-3 gap-4 text-sm">
                        <div class="bg-white p-3 rounded-lg text-center border border-gray-200">
                            <div class="text-2xl font-bold ${statusClass.split(' ')[0]}">${data.totalCourses || 0}</div>
                            <div class="text-gray-600 mt-1">Total Courses</div>
                        </div>
                        <div class="bg-white p-3 rounded-lg text-center border border-gray-200">
                            <div class="text-2xl font-bold ${statusClass.split(' ')[0]}">${data.totalSections || 0}</div>
                            <div class="text-gray-600 mt-1">Sections</div>
                        </div>
                        <div class="bg-white p-3 rounded-lg text-center border border-gray-200">
                            <div class="text-2xl font-bold ${statusClass.split(' ')[0]}">${data.successRate || '0%'}</div>
                            <div class="text-gray-600 mt-1">Success Rate</div>
                        </div>
                    </div>
                    ${data.unassignedCourses && data.unassignedCourses.length > 0 ? `
                        <div class="mt-4 p-3 bg-yellow-50 border border-yellow-200 rounded-lg">
                            <p class="text-sm font-medium text-yellow-800 mb-2">Unscheduled Courses:</p>
                            <ul class="text-sm text-yellow-700 list-disc list-inside">
                                ${data.unassignedCourses.map(c => `<li>${c.course_code}</li>`).join('')}
                            </ul>
                        </div>
                    ` : ''}
                `;

                reportTitle.className = `text-lg font-semibold ${statusClass.split(' ')[0]}`;

                // Show the modal
                reportModal.classList.remove('hidden');
                reportModal.classList.add('flex');

                // Update generation results card if it exists
                const generationResults = document.getElementById('generation-results');
                if (generationResults && data.schedules && data.schedules.length > 0) {
                    generationResults.classList.remove('hidden');
                    document.getElementById('total-courses').textContent = data.totalCourses || 0;
                    document.getElementById('total-sections').textContent = data.totalSections || 0;
                    document.getElementById('success-rate').textContent = data.successRate || '0%';
                }
            }

            function closeReportModal() {
                const reportModal = document.getElementById('report-modal');
                reportModal.classList.add('hidden');
            }

            // Initialize page
            document.addEventListener('DOMContentLoaded', function() {
                const urlParams = new URLSearchParams(window.location.search);
                const tab = urlParams.get('tab');
                const reportModal = document.getElementById('report-modal');

                if (tab === 'schedule-list') switchTab('schedule');
                else if (tab === 'manual') switchTab('manual');
                else switchTab('generate');

                if (reportModal) {
                    reportModal.addEventListener('click', function(e) {
                        if (e.target === reportModal) {
                            closeReportModal();
                        }
                    });
                }
            });
        </script>

        <!-- Include external JavaScript files -->
        <script src="/assets/js/generate_schedules.js"></script>
        <script src="/assets/js/manual_schedules.js"></script>
        <!-- Add these to your head section -->
        <script src="https://cdnjs.cloudflare.com/ajax/libs/xlsx/0.18.5/xlsx.full.min.js"></script>
        <script src="https://cdnjs.cloudflare.com/ajax/libs/jspdf/2.5.1/jspdf.umd.min.js"></script>
        <script src="https://cdnjs.cloudflare.com/ajax/libs/jspdf-autotable/3.5.28/jspdf.plugin.autotable.min.js"></script>
    </div>
</div>

<?php
$content = ob_get_clean();
require_once __DIR__ . '/layout.php';
?>