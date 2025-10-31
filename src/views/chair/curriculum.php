<?php
// curriculum.php
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

<script src="https://code.jquery.com/jquery-3.6.0.min.js"></script>
<link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/5.15.4/css/all.min.css">
<link rel="stylesheet" href="/css/custom.css">



<!-- Display success/error messages -->
<?php if (isset($success)): ?>
    <div class="lg:max-w-4xl mx-auto mb-6 p-4 bg-[var(--solid-green)] text-green-800 rounded-lg flex items-center shadow-sm border-l-4 border-green-500 transition-all">
        <svg class="w-5 h-5 mr-3" fill="currentColor" viewBox="0 0 20 20">
            <path fill-rule="evenodd" d="M10 18a8 8 0 100-16 8 8 0 000 16zm3.707-9.293a1 1 0 00-1.414-1.414L9 10.586 7.707 9.293a1 1 0 00-1.414 1.414l2 2a1 1 0 001.414 0l4-4z" clip-rule="evenodd"></path>
        </svg>
        <?= htmlspecialchars($success) ?>
    </div>
<?php endif; ?>
<?php if (isset($error)): ?>
    <div class="lg:max-w-4xl mx-auto mb-6 p-4 bg-[var(--solid-red)] text-red-800 rounded-lg flex items-center shadow-sm border-l-4 border-red-500 transition-all">
        <svg class="w-5 h-5 mr-3" fill="currentColor" viewBox="0 0 20 20">
            <path fill-rule="evenodd" d="M18 10a8 8 0 11-16 0 8 8 0 0116 0zm-7 4a1 1 0 11-2 0 1 1 0 012 0zm-1-9a1 1 0 00-1 1v4a1 1 0 102 0V6a1 1 0 00-1-1z" clip-rule="evenodd"></path>
        </svg>
        <?= htmlspecialchars($error) ?>
    </div>
<?php endif; ?>

<!-- Main Content -->
<div class="flex flex-col p-3 sm:p-4 md:p-6 min-h-screen">
    <!-- Page Header -->
    <div class="flex flex-col lg:flex-row justify-between items-start lg:items-center mb-6 sm:mb-8">
        <div class="mb-4 lg:mb-0">
            <h2 class="text-xl sm:text-2xl md:text-3xl font-heading text-prmsu-gray-dark">Curriculum Management</h2>
            <p class="text-prmsu-gray text-xs sm:text-sm mt-1">Organize and manage academic curricula with ease</p>
        </div>
        <div class="flex flex-col sm:flex-row space-y-2 sm:space-y-0 sm:space-x-3 w-full lg:w-auto">
            <button onclick="openModal('addCurriculumCourseModal')" class="bg-yellow-600 border-r-2 flex items-center justify-center space-x-2 w-full sm:w-auto px-4 py-2 text-sm sm:text-base">
                <svg class="w-4 h-4 sm:w-5 sm:h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 6v6m0 0v6m0-6h6m-6 0H6"></path>
                </svg>
                <span>Add New</span>
            </button>
        </div>
    </div>

    <!-- Search and Filter Bar -->
    <div class="mb-4 sm:mb-6 flex flex-col lg:flex-row items-stretch lg:items-center space-y-3 lg:space-y-0 lg:space-x-4">
        <div class="relative flex-1 w-full">
            <input type="text" placeholder="Search curricula..." id="searchInput"
                class="w-full pl-8 sm:pl-10 pr-4 py-2 sm:py-3 text-sm sm:text-base border border-prmsu-gray rounded-lg focus-gold bg-prmsu-white shadow-sm">
        </div>

        <div class="flex flex-col sm:flex-row space-y-2 sm:space-y-0 sm:space-x-3 w-full lg:w-auto">
            <select id="statusFilter" class="border border-prmsu-gray rounded-lg px-3 sm:px-4 py-2 sm:py-3 text-sm sm:text-base focus-gold bg-prmsu-white text-prmsu-gray-dark w-full sm:w-auto shadow-sm">
                <option value="">All Statuses</option>
                <option value="active">Active</option>
                <option value="draft">Draft</option>
            </select>
        </div>
    </div>

    <!-- Mobile Card View (visible on small screens) -->
    <div class="block lg:hidden space-y-4" id="mobileCardView">
        <?php foreach ($curricula as $curriculum): ?>
            <?php
            $courseCountStmt = $db->prepare("SELECT COUNT(*) FROM curriculum_courses WHERE curriculum_id = :curriculum_id");
            $courseCountStmt->execute([':curriculum_id' => $curriculum['curriculum_id']]);
            $course_count = $courseCountStmt->fetchColumn();

            $coursesStmt = $db->prepare("
                SELECT 
                    c.course_id, 
                    c.course_code, 
                    c.course_name, 
                    c.units, 
                    cc.year_level, 
                    cc.semester, 
                    cc.subject_type,
                    cc.is_core,
                    cc.prerequisites,
                    cc.co_requisites
                FROM curriculum_courses cc
                JOIN courses c ON cc.course_id = c.course_id
                WHERE cc.curriculum_id = :curriculum_id
                ORDER BY cc.year_level, cc.semester, c.course_code
            ");
            $coursesStmt->execute([':curriculum_id' => $curriculum['curriculum_id']]);
            $curriculum_courses = $coursesStmt->fetchAll(PDO::FETCH_ASSOC);
            ?>
            <div class="card p-4 space-y-3" data-curriculum-id="<?= htmlspecialchars($curriculum['curriculum_id']) ?>" data-name="<?= htmlspecialchars($curriculum['curriculum_name']) ?>" data-year="<?= $curriculum['effective_year'] ?>" data-status="<?= strtolower($curriculum['status']) ?>">
                <!-- Header -->
                <div class="flex justify-between items-start">
                    <div class="flex-1 min-w-0">
                        <h3 class="text-base sm:text-lg font-medium text-prmsu-gray-dark truncate"><?= htmlspecialchars($curriculum['curriculum_name']) ?></h3>
                        <p class="text-xs sm:text-sm text-prmsu-gray mt-1"><?= htmlspecialchars($course_count) ?> Courses • <?= htmlspecialchars($curriculum['total_units']) ?> Units</p>
                    </div>
                    <span class="inline-flex items-center px-2 py-1 rounded-full text-xs font-medium ml-2 <?= $curriculum['status'] === 'Active' ? 'bg-[var(--solid-green)] text-green-700' : 'bg-prmsu-gray-light text-prmsu-gray' ?>">
                        <span class="w-2 h-2 mr-1 rounded-full <?= $curriculum['status'] === 'Active' ? 'bg-green-500' : 'bg-prmsu-gray' ?>"></span>
                        <?= htmlspecialchars($curriculum['status']) ?>
                    </span>
                </div>

                <!-- Last Updated -->
                <div class="text-xs text-prmsu-gray">
                    Last updated: <?= htmlspecialchars($curriculum['updated_at']) ?>
                </div>

                <!-- Actions -->
                <div class="flex flex-wrap gap-2 pt-2">
                    <button onclick='openViewCoursesModal(<?= json_encode($curriculum_courses) ?>, "<?= htmlspecialchars($curriculum['curriculum_name']) ?>", <?= $curriculum['curriculum_id'] ?>)'
                        class="flex items-center space-x-1 text-blue-600 hover:text-blue-800 transition-all bg-blue-50 px-2 py-1 rounded text-xs">
                        <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M15 12a3 3 0 11-6 0 3 3 0 016 0z" />
                            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M2.458 12C3.732 7.943 7.523 5 12 5c4.478 0 8.268 2.943 9.542 7-1.274 4.057-5.064 7-9.542 7-4.477 0-8.268-2.943-9.542-7z" />
                        </svg>
                        <span>View</span>
                    </button>
                    <button onclick="openManageCoursesModal(<?= $curriculum['curriculum_id'] ?>, '<?= htmlspecialchars($curriculum['curriculum_name']) ?>')"
                        class="flex items-center space-x-1 text-green-600 hover:text-green-800 transition-all bg-green-50 px-2 py-1 rounded text-xs">
                        <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 6.253v13m0-13C10.832 5.477 9.246 5 7.5 5S4.168 5.477 3 6.253v13C4.168 18.477 5.754 18 7.5 18s3.332.477 4.5 1.253m0-13C13.168 5.477 14.754 5 16.5 5c1.747 0 3.332.477 4.5 1.253v13C19.832 18.477 18.247 18 16.5 18c-1.746 0-3.332.477-4.5 1.253"></path>
                        </svg>
                        <span>Manage</span>
                    </button>
                    <button onclick="openEditCurriculumModal(<?= $curriculum['curriculum_id'] ?>)"
                        class="flex items-center space-x-1 text-green-600 hover:text-green-800 transition-all bg-green-50 px-2 py-1 rounded text-xs">
                        <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M11 5H6a2 2 0 00-2 2v11a2 2 0 002 2h11a2 2 0 002-2v-5m-1.414-9.414a2 2 0 112.828 2.828L11.828 15H9v-2.828l8.586-8.586z"></path>
                        </svg>
                        <span>Edit</span>
                    </button>
                    <form method="POST" class="inline">
                        <input type="hidden" name="action" value="toggle_curriculum">
                        <input type="hidden" name="curriculum_id" value="<?= $curriculum['curriculum_id'] ?>">
                        <input type="hidden" name="status" value="<?= $curriculum['status'] ?>">
                        <button type="submit"
                            class="flex items-center space-x-1 text-prmsu-gray hover:text-prmsu-gray-dark transition-all bg-gray-50 px-2 py-1 rounded text-xs"
                            title="<?= $curriculum['status'] === 'Active' ? 'Deactivate Curriculum' : 'Activate Curriculum' ?>">
                            <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="<?= $curriculum['status'] === 'Active' ? 'M10 9v6m4-6v6m-7-3h10' : 'M9 12h6m-3-3v6' ?>" />
                            </svg>
                            <span><?= $curriculum['status'] === 'Active' ? 'Deactivate' : 'Activate' ?></span>
                        </button>
                    </form>
                </div>
            </div>
        <?php endforeach; ?>

        <?php if (empty($curricula)): ?>
            <div class="card p-8 text-center">
                <div class="flex flex-col items-center justify-center">
                    <svg class="w-12 h-12 sm:w-16 sm:h-16 text-prmsu-gray-light mb-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                        <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 12h6m-6 4h6m2 5H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z"></path>
                    </svg>
                    <p class="text-base sm:text-lg font-medium mb-2">No curricula found</p>
                    <p class="text-sm">Start by adding a new curriculum</p>
                </div>
            </div>
        <?php endif; ?>
    </div>

    <!-- Desktop Table View (hidden on small screens) -->
    <div class="card overflow-hidden hidden lg:block">
        <div class="overflow-x-auto">
            <table class="w-full table-auto border-collapse min-w-full">
                <thead>
                    <tr class="table-header">
                        <th class="px-4 xl:px-6 py-3 xl:py-4 text-left text-xs xl:text-sm font-medium">Curriculum Name</th>
                        <th class="px-4 xl:px-6 py-3 xl:py-4 text-left text-xs xl:text-sm font-medium">Courses</th>
                        <th class="px-4 xl:px-6 py-3 xl:py-4 text-left text-xs xl:text-sm font-medium">Total Units</th>
                        <th class="px-4 xl:px-6 py-3 xl:py-4 text-left text-xs xl:text-sm font-medium">Last Updated</th>
                        <th class="px-4 xl:px-6 py-3 xl:py-4 text-left text-xs xl:text-sm font-medium">Status</th>
                        <th class="px-4 xl:px-6 py-3 xl:py-4 text-left text-xs xl:text-sm font-medium">Actions</th>
                    </tr>
                </thead>
                <tbody id="curriculaTableBody" class="divide-y divide-prmsu-gray-light">
                    <?php foreach ($curricula as $curriculum): ?>
                        <?php
                        $courseCountStmt = $db->prepare("SELECT COUNT(*) FROM curriculum_courses WHERE curriculum_id = :curriculum_id");
                        $courseCountStmt->execute([':curriculum_id' => $curriculum['curriculum_id']]);
                        $course_count = $courseCountStmt->fetchColumn();

                        $coursesStmt = $db->prepare("
                            SELECT 
                                c.course_id, 
                                c.course_code, 
                                c.course_name, 
                                c.units, 
                                cc.year_level, 
                                cc.semester, 
                                cc.subject_type,
                                cc.is_core,
                                cc.prerequisites,
                                cc.co_requisites
                            FROM curriculum_courses cc
                            JOIN courses c ON cc.course_id = c.course_id
                            WHERE cc.curriculum_id = :curriculum_id
                            ORDER BY cc.year_level, cc.semester, c.course_code
                        ");
                        $coursesStmt->execute([':curriculum_id' => $curriculum['curriculum_id']]);
                        $curriculum_courses = $coursesStmt->fetchAll(PDO::FETCH_ASSOC);
                        ?>
                        <tr class="table-row hover:bg-gray-50 transition-colors" data-curriculum-id="<?= htmlspecialchars($curriculum['curriculum_id']) ?>" data-name="<?= htmlspecialchars($curriculum['curriculum_name']) ?>" data-year="<?= $curriculum['effective_year'] ?>" data-status="<?= strtolower($curriculum['status']) ?>">
                            <td class="px-4 xl:px-6 py-3 xl:py-4">
                                <div class="text-sm xl:text-base font-medium text-prmsu-gray-dark truncate max-w-xs" title="<?= htmlspecialchars($curriculum['curriculum_name']) ?>">
                                    <?= htmlspecialchars($curriculum['curriculum_name']) ?>
                                </div>
                            </td>
                            <td class="px-4 xl:px-6 py-3 xl:py-4 text-xs xl:text-sm text-prmsu-gray whitespace-nowrap">
                                <?= htmlspecialchars($course_count) ?> Courses
                            </td>
                            <td class="px-4 xl:px-6 py-3 xl:py-4 text-xs xl:text-sm text-prmsu-gray total-units whitespace-nowrap">
                                <?= htmlspecialchars($curriculum['total_units']) ?> Units
                            </td>
                            <td class="px-4 xl:px-6 py-3 xl:py-4 text-xs xl:text-sm text-prmsu-gray whitespace-nowrap">
                                <?= htmlspecialchars($curriculum['updated_at']) ?>
                            </td>
                            <td class="px-4 xl:px-6 py-3 xl:py-4">
                                <span class="inline-flex items-center px-2 xl:px-3 py-1 rounded-full text-xs font-medium <?= $curriculum['status'] === 'Active' ? 'bg-[var(--solid-green)] text-green-700' : 'bg-prmsu-gray-light text-prmsu-gray' ?>">
                                    <span class="w-2 h-2 mr-1 xl:mr-2 rounded-full <?= $curriculum['status'] === 'Active' ? 'bg-green-500' : 'bg-prmsu-gray' ?>"></span>
                                    <?= htmlspecialchars($curriculum['status']) ?>
                                </span>
                            </td>
                            <td class="px-4 xl:px-6 py-3 xl:py-4">
                                <div class="flex space-x-2 xl:space-x-3">
                                    <button onclick='openViewCoursesModal(<?= json_encode($curriculum_courses) ?>, "<?= htmlspecialchars($curriculum['curriculum_name']) ?>", <?= $curriculum['curriculum_id'] ?>)'
                                        class="text-blue-600 hover:text-blue-800 transition-all p-1"
                                        title="View Courses">
                                        <svg class="w-4 h-4 xl:w-5 xl:h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M15 12a3 3 0 11-6 0 3 3 0 016 0z" />
                                            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M2.458 12C3.732 7.943 7.523 5 12 5c4.478 0 8.268 2.943 9.542 7-1.274 4.057-5.064 7-9.542 7-4.477 0-8.268-2.943-9.542-7z" />
                                        </svg>
                                    </button>
                                    <button onclick="openManageCoursesModal(<?= $curriculum['curriculum_id'] ?>, '<?= htmlspecialchars($curriculum['curriculum_name']) ?>')"
                                        class="text-green-600 hover:text-green-800 transition-all p-1"
                                        title="Manage Courses">
                                        <svg class="w-4 h-4 xl:w-5 xl:h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 6.253v13m0-13C10.832 5.477 9.246 5 7.5 5S4.168 5.477 3 6.253v13C4.168 18.477 5.754 18 7.5 18s3.332.477 4.5 1.253m0-13C13.168 5.477 14.754 5 16.5 5c1.747 0 3.332.477 4.5 1.253v13C19.832 18.477 18.247 18 16.5 18c-1.746 0-3.332.477-4.5 1.253"></path>
                                        </svg>
                                    </button>
                                    <button onclick="openEditCurriculumModal(<?= $curriculum['curriculum_id'] ?>)"
                                        class="text-green-600 hover:text-green-800 transition-all p-1"
                                        title="Edit Curriculum">
                                        <svg class="w-4 h-4 xl:w-5 xl:h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M11 5H6a2 2 0 00-2 2v11a2 2 0 002 2h11a2 2 0 002-2v-5m-1.414-9.414a2 2 0 112.828 2.828L11.828 15H9v-2.828l8.586-8.586z"></path>
                                        </svg>
                                    </button>
                                    <form method="POST" class="inline">
                                        <input type="hidden" name="action" value="toggle_curriculum">
                                        <input type="hidden" name="curriculum_id" value="<?= $curriculum['curriculum_id'] ?>">
                                        <input type="hidden" name="status" value="<?= $curriculum['status'] ?>">
                                        <button type="submit"
                                            class="text-prmsu-gray hover:text-prmsu-gray-dark transition-all p-1"
                                            title="<?= $curriculum['status'] === 'Active' ? 'Deactivate Curriculum' : 'Activate Curriculum' ?>">
                                            <svg class="w-4 h-4 xl:w-5 xl:h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="<?= $curriculum['status'] === 'Active' ? 'M10 9v6m4-6v6m-7-3h10' : 'M9 12h6m-3-3v6' ?>" />
                                            </svg>
                                        </button>
                                    </form>
                                </div>
                            </td>
                        </tr>
                    <?php endforeach; ?>

                    <?php if (empty($curricula)): ?>
                        <tr>
                            <td colspan="6" class="px-4 xl:px-6 py-8 xl:py-12 text-center text-prmsu-gray">
                                <div class="flex flex-col items-center justify-center">
                                    <svg class="w-12 h-12 xl:w-16 xl:h-16 text-prmsu-gray-light mb-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                        <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 12h6m-6 4h6m2 5H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z"></path>
                                    </svg>
                                    <p class="text-base xl:text-lg font-medium mb-2">No curricula found</p>
                                    <p class="text-sm">Start by adding a new curriculum</p>
                                </div>
                            </td>
                        </tr>
                    <?php endif; ?>
                </tbody>
            </table>
        </div>
    </div>

    <!-- Add Curriculum Modal -->
    <div id="addCurriculumCourseModal" class="fixed inset-0 hidden z-50">
        <div class="modal-overlay fixed inset-0 flex items-center justify-center p-4 bg-opacity-50 backdrop-blur-sm opacity-0 transition-opacity duration-300">
            <div class="modal-content bg-white rounded-xl shadow-2xl max-w-lg w-full transform translate-y-8 transition-transform duration-300 ease-out">
                <div class="p-6 border-b border-gray-200 flex justify-between items-center bg-gradient-to-r from-amber-50 to-white rounded-t-xl">
                    <h3 class="text-xl font-bold text-gray-800 flex items-center">
                        <svg class="w-6 h-6 mr-3 text-amber-500" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 6v6m0 0v6m0-6h6m-6 0H6"></path>
                        </svg>
                        <span id="modalTitle">Add New Curriculum</span>
                    </h3>
                    <button onclick="closeModal('addCurriculumCourseModal')" class="text-gray-500 hover:text-gray-700 transition-all transform hover:scale-110 focus:outline-none">
                        <svg class="w-6 h-6" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M6 18L18 6M6 6l12 12"></path>
                        </svg>
                    </button>
                </div>

                <div class="p-6">
                    <form method="POST" class="space-y-5">
                        <input type="hidden" name="action" value="add_curriculum">
                        <div class="form-group">
                            <label class="block text-sm font-medium text-gray-700 mb-1">Curriculum Name</label>
                            <input type="text" name="curriculum_name" placeholder="e.g. Bachelor of Science in Computer Science"
                                class="w-full px-4 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-amber-500 focus:border-amber-500 transition-colors" required>
                        </div>
                        <div class="grid grid-cols-2 gap-4">
                            <div class="form-group">
                                <label class="block text-sm font-medium text-gray-700 mb-1">Curriculum Code</label>
                                <input type="text" name="curriculum_code" placeholder="e.g. BSCS-2025"
                                    class="w-full px-4 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-amber-500 focus:border-amber-500 transition-colors" required>
                            </div>
                            <div class="form-group">
                                <label class="block text-sm font-medium text-gray-700 mb-1">Effective Year</label>
                                <input type="number" name="effective_year" value="2025" min="2000" max="2100"
                                    class="w-full px-4 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-amber-500 focus:border-amber-500 transition-colors" required>
                            </div>
                        </div>
                        <div class="form-group">
                            <label class="block text-sm font-medium text-gray-700 mb-1">Description</label>
                            <textarea name="description" rows="3" placeholder="Brief description of the curriculum..."
                                class="w-full px-4 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-amber-500 focus:border-amber-500 transition-colors resize-none"></textarea>
                        </div>
                        <div class="mt-6 pt-4 border-t border-gray-200 flex justify-end space-x-3">
                            <button type="button" onclick="closeModal('addCurriculumCourseModal')"
                                class="px-5 py-2 border border-gray-300 text-gray-700 rounded-lg hover:bg-gray-50 transition-colors focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-gray-500">
                                Cancel
                            </button>
                            <button type="submit"
                                class="px-5 py-2 bg-amber-500 text-white rounded-lg hover:bg-amber-600 transition-colors focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-amber-500">
                                Create Curriculum
                            </button>
                        </div>
                    </form>
                </div>
            </div>
        </div>
    </div>

    <!-- Edit Curriculum Modal -->
    <div id="editCurriculumModal" class="fixed inset-0 hidden z-50">
        <div class="modal-overlay fixed inset-0 flex items-center justify-center p-4">
            <div class="modal-content bg-white rounded-xl shadow-2xl max-w-lg w-full">
                <div class="p-6 border-b border-gray-200 flex justify-between items-center bg-gradient-to-r from-amber-50 to-white rounded-t-xl">
                    <h3 class="text-xl font-bold text-gray-800 flex items-center">
                        <svg class="w-6 h-6 mr-3 text-amber-500" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M11 5H6a2 2 0 00-2 2v11a2 2 0 002 2h11a2 2 0 002-2v-5m-1.414-9.414a2 2 0 112.828 2.828L11.828 15H9v-2.828l8.586-8.586z"></path>
                        </svg>
                        Edit Curriculum
                    </h3>
                    <button onclick="closeModal('editCurriculumModal')" class="text-gray-500 hover:text-gray-700 transition-all transform hover:scale-110 focus:outline-none">
                        <svg class="w-6 h-6" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M6 18L18 6M6 6l12 12"></path>
                        </svg>
                    </button>
                </div>

                <div class="p-6">
                    <form id="editCurriculumForm" method="POST" class="space-y-5">
                        <input type="hidden" name="action" value="edit_curriculum">
                        <input type="hidden" name="curriculum_id" id="editCurriculumId">

                        <div class="form-group">
                            <label class="block text-sm font-medium text-gray-700 mb-1">Curriculum Name</label>
                            <input type="text" name="curriculum_name" id="editCurriculumName" placeholder="e.g. Bachelor of Science in Computer Science"
                                class="w-full px-4 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-amber-500 focus:border-amber-500 transition-colors" required>
                        </div>

                        <div class="grid grid-cols-2 gap-4">
                            <div class="form-group">
                                <label class="block text-sm font-medium text-gray-700 mb-1">Curriculum Code</label>
                                <input type="text" name="curriculum_code" id="editCurriculumCode" placeholder="e.g. BSCS-2025"
                                    class="w-full px-4 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-amber-500 focus:border-amber-500 transition-colors" required>
                            </div>
                            <div class="form-group">
                                <label class="block text-sm font-medium text-gray-700 mb-1">Effective Year</label>
                                <input type="number" name="effective_year" id="editEffectiveYear" min="2000" max="2100"
                                    class="w-full px-4 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-amber-500 focus:border-amber-500 transition-colors" required>
                            </div>
                        </div>

                        <div class="form-group">
                            <label class="block text-sm font-medium text-gray-700 mb-1">Description</label>
                            <textarea name="description" id="editDescription" rows="3" placeholder="Brief description of the curriculum..."
                                class="w-full px-4 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-amber-500 focus:border-amber-500 transition-colors resize-none"></textarea>
                        </div>

                        <div class="form-group">
                            <label class="block text-sm font-medium text-gray-700 mb-1">Status</label>
                            <select name="status" id="editStatus" class="w-full px-4 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-amber-500 focus:border-amber-500 transition-colors" required>
                                <option value="Draft">Draft</option>
                                <option value="Active">Active</option>
                                <option value="Archived">Archived</option>
                            </select>
                        </div>

                        <div class="mt-6 pt-4 border-t border-gray-200 flex justify-end space-x-3">
                            <button type="button" onclick="closeModal('editCurriculumModal')"
                                class="px-5 py-2 border border-gray-300 text-gray-700 rounded-lg hover:bg-gray-50 transition-colors focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-gray-500">
                                Cancel
                            </button>
                            <button type="submit" id="editSubmitBtn"
                                class="px-5 py-2 bg-amber-500 text-white rounded-lg hover:bg-amber-600 transition-colors focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-amber-500 flex items-center">
                                <span id="editSubmitText">Update Curriculum</span>
                                <div id="editSubmitSpinner" class="loading-spinner hidden ml-2"></div>
                            </button>
                        </div>
                    </form>
                </div>
            </div>
        </div>
    </div>

    <!-- Manage Courses Modal -->
    <div id="manageCoursesModal" class="fixed inset-0 hidden z-50">
        <div class="modal-overlay fixed inset-0 flex items-center justify-center p-4">
            <div class="modal-content bg-white rounded-xl shadow-2xl max-w-2xl w-full">
                <div class="p-6 border-b border-prmsu-gray-light flex justify-between items-center">
                    <h3 class="text-xl font-heading text-prmsu-gray-dark flex items-center" id="manageCoursesTitle">
                        <svg class="w-6 h-6 mr-2 text-green-600" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 6.253v13m0-13C10.832 5.477 9.246 5 7.5 5S4.168 5.477 3 6.253v13C4.168 18.477 5.754 18 7.5 18s3.332.477 4.5 1.253m0-13C13.168 5.477 14.754 5 16.5 5c1.747 0 3.332.477 4.5 1.253v13C19.832 18.477 18.247 18 16.5 18c-1.746 0-3.332.477-4.5 1.253"></path>
                        </svg>
                        Manage Courses
                    </h3>
                    <button onclick="closeModal('manageCoursesModal')" class="text-prmsu-gray hover:text-prmsu-gray-dark transition-all">
                        <svg class="w-6 h-6" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M6 18L18 6M6 6l12 12"></path>
                        </svg>
                    </button>
                </div>
                <div class="p-6">
                    <div class="relative mb-4">
                        <div class="absolute inset-y-0 left-0 pl-3 flex items-center pointer-events-none">
                            <svg class="w-5 h-5 text-prmsu-gray" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M21 21l-6-6m2-5a7 7 0 11-14 0 7 7 0 0114 0z"></path>
                            </svg>
                        </div>
                        <input type="text" id="courseSearchInput" placeholder="Search courses..."
                            class="w-full pl-10 pr-4 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-amber-500 focus:border-amber-500 transition-colors">
                    </div>

                    <div id="courseExistsNotification" class="hidden mb-4 p-3 rounded-lg bg-red-100 text-red-800 flex items-center">
                        <div id="courseCheckingLoader" class="hidden loading-spinner mr-2"></div>
                        <span id="courseExistsMessage">This course already exists in this curriculum.</span>
                    </div>

                    <form method="POST" class="space-y-5" id="manageCoursesForm">
                        <input type="hidden" name="action" value="add_course">
                        <input type="hidden" name="curriculum_id" id="curriculumIdInput">

                        <div>
                            <label class="block text-sm font-medium text-prmsu-gray-dark mb-1">Select Course</label>
                            <select name="course_id" id="courseSelect" class="focus-gold" required>
                                <option value="">-- Select Course --</option>
                                <?php
                                // Ensure $courses is set
                                if (!isset($courses)) {
                                    $courses = [];
                                    $coursesStmt = $db->prepare("SELECT course_id, course_code, course_name, units, subject_type FROM courses WHERE department_id = :department_id");
                                    $coursesStmt->execute([':department_id' => $departmentId]);
                                    $courses = $coursesStmt->fetchAll(PDO::FETCH_ASSOC);
                                }
                                // Generate options with detailed debugging
                                foreach ($courses as $index => $course) {
                                    $subjectType = $course['subject_type'] ?? 'General Education';
                                    error_log("Course #$index - ID: {$course['course_id']}, Subject Type: $subjectType");
                                    echo '<option value="' . htmlspecialchars($course['course_id']) . '" ' .
                                        'data-code="' . htmlspecialchars($course['course_code'] ?? '') . '" ' .
                                        'data-name="' . htmlspecialchars($course['course_name'] ?? '') . '" ' .
                                        'data-subject-type="' . htmlspecialchars($subjectType) . '">' .
                                        htmlspecialchars($course['course_code'] . ' - ' . $course['course_name']) .
                                        '</option>';
                                }
                                ?>
                            </select>
                        </div>
                        <div class="grid grid-cols-3 gap-4">
                            <div>
                                <label class="block text-sm font-medium text-prmsu-gray-dark mb-1">Year Level</label>
                                <select name="year_level" class="focus-gold" required>
                                    <option value="">--- Please Select Year Level ---</option>
                                    <option value="1st Year">1st Year</option>
                                    <option value="2nd Year">2nd Year</option>
                                    <option value="3rd Year">3rd Year</option>
                                    <option value="4th Year">4th Year</option>
                                </select>
                            </div>
                            <div>
                                <label class="block text-sm font-medium text-prmsu-gray-dark mb-1">Semester</label>
                                <select name="semester" class="focus-gold" required>
                                    <option value="">--- Please Select Semester ---</option>
                                    <option value="1st">1st Semester</option>
                                    <option value="2nd">2nd Semester</option>
                                    <option value="Mid Year">Mid Year</option>
                                </select>
                            </div>
                            <div>
                                <label class="block text-sm font-medium text-prmsu-gray-dark mb-1">Subject Type</label>
                                <select name="subject_type" id="subjectTypeSelect" class="focus-gold" required>
                                    <option value="">-- Select Subject Type --</option>
                                    <?php
                                    // Dynamically generate options from courses table
                                    $subject_types = array_unique(array_filter(array_column($courses, 'subject_type')));
                                    if (empty($subject_types)) {
                                        $subject_types = ['Professional Course', 'General Education', 'Elective'];
                                    }
                                    foreach ($subject_types as $type) {
                                        echo '<option value="' . htmlspecialchars($type) . '">' . htmlspecialchars($type) . '</option>';
                                    }
                                    ?>
                                </select>
                            </div>
                        </div>
                        <div class="mt-6 pt-5 border-t border-prmsu-gray-light flex justify-end space-x-3">
                            <button type="button" onclick="closeModal('manageCoursesModal')" class="btn-outline">Cancel</button>
                            <button type="submit" class="btn-gold" id="addCourseButton">Add Course</button>
                        </div>
                    </form>
                </div>
            </div>
        </div>
    </div>

    <!-- View Courses Modal -->
    <div id="viewCoursesModal" class="fixed inset-0 hidden z-50">
        <div class="modal-overlay fixed inset-0 flex items-center justify-center p-4">
            <div class="modal-content bg-white rounded-xl shadow-2xl max-w-4xl w-full">
                <div class="p-6 border-b border-prmsu-gray-light flex justify-between items-center">
                    <h3 class="text-xl font-heading text-prmsu-gray-dark flex items-center" id="viewCoursesTitle">
                        <svg class="w-6 h-6 mr-2 text-blue-600" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M15 12a3 3 0 11-6 0 3 3 0 016 0z" />
                            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M2.458 12C3.732 7.943 7.523 5 12 5c4.478 0 8.268 2.943 9.542 7-1.274 4.057-5.064 7-9.542 7-4.477 0-8.268-2.943-9.542-7z" />
                        </svg>
                        View Courses
                    </h3>
                    <button onclick="closeModal('viewCoursesModal')" class="text-prmsu-gray hover:text-prmsu-gray-dark transition-all">
                        <svg class="w-6 h-6" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M6 18L18 6M6 6l12 12"></path>
                        </svg>
                    </button>
                </div>
                <div class="p-6 max-h-[60vh] overflow-y-auto">
                    <div id="coursesContainer">
                        <!-- Courses will be populated dynamically via JavaScript -->
                    </div>
                    <div id="noCoursesMessage" class="hidden text-center text-prmsu-gray py-8">
                        <svg class="w-16 h-16 text-prmsu-gray-light mb-4 mx-auto" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 12h6m-6 4h6m2 5H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z"></path>
                        </svg>
                        <p class="text-lg font-medium mb-2">No courses found</p>
                        <p class="text-sm">Add courses to this curriculum using the "Manage Courses" option.</p>
                    </div>
                </div>
                <div class="p-6 border-t border-prmsu-gray-light flex justify-end">
                    <button onclick="printCourses()" class="btn-outline">
                        <i class="fa-solid fa-print"></i>
                        Print
                    </button>
                </div>
            </div>
        </div>
    </div>

    <!-- Remove Course Confirmation Modal -->
    <div id="removeCourseConfirmModal" class="fixed inset-0 hidden z-50">
        <div class="modal-overlay fixed inset-0 flex items-center justify-center p-4 bg-opacity-50 backdrop-blur-sm">
            <div class="modal-content bg-white rounded-xl shadow-2xl max-w-md w-full">
                <div class="p-6 border-b border-gray-200 flex justify-between items-center bg-gradient-to-r from-red-50 to-white rounded-t-xl">
                    <h3 class="text-xl font-bold text-gray-800 flex items-center">
                        <svg class="w-6 h-6 mr-3 text-red-500" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z"></path>
                        </svg>
                        Confirm Course Removal
                    </h3>
                    <button onclick="closeModal('removeCourseConfirmModal')" class="text-gray-500 hover:text-gray-700 transition-all transform hover:scale-110 focus:outline-none">
                        <svg class="w-6 h-6" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M6 18L18 6M6 6l12 12"></path>
                        </svg>
                    </button>
                </div>
                <div class="p-6">
                    <p id="removeConfirmMessage" class="text-gray-700"></p>
                    <div class="mt-6 pt-4 border-t border-gray-200 flex justify-end space-x-3">
                        <button type="button" onclick="closeModal('removeCourseConfirmModal')"
                            class="px-5 py-2 border border-gray-300 text-gray-700 rounded-lg hover:bg-gray-50 transition-colors focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-gray-500">
                            Cancel
                        </button>
                        <button id="removeConfirmButton" data-course-id="" data-curriculum-id="" data-course-name="" data-course-code=""
                            class="px-5 py-2 bg-red-500 text-white rounded-lg hover:bg-red-600 transition-colors focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-red-500 flex items-center">
                            Remove Course
                        </button>
                    </div>
                </div>
            </div>
        </div>
    </div>

    <!-- Error Modal -->
    <div id="errorModal" class="fixed inset-0 hidden z-50">
        <div class="modal-overlay fixed inset-0 flex items-center justify-center p-4 bg-opacity-50 backdrop-blur-sm">
            <div class="modal-content bg-white rounded-xl shadow-2xl max-w-md w-full">
                <div class="p-6 border-b border-gray-200 flex justify-between items-center bg-gradient-to-r from-red-50 to-white rounded-t-xl">
                    <h3 class="text-xl font-bold text-gray-800 flex items-center">
                        <svg class="w-6 h-6 mr-3 text-red-500" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z"></path>
                        </svg>
                        Error
                    </h3>
                    <button onclick="closeModal('errorModal')" class="text-gray-500 hover:text-gray-700 transition-all transform hover:scale-110 focus:outline-none">
                        <svg class="w-6 h-6" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M6 18L18 6M6 6l12 12"></path>
                        </svg>
                    </button>
                </div>
                <div class="p-6">
                    <p id="errorModalMessage" class="text-gray-700"></p>
                    <div class="mt-6 pt-4 border-t border-gray-200 flex justify-end">
                        <button type="button" onclick="closeModal('errorModal')"
                            class="px-5 py-2 border border-gray-300 text-gray-700 rounded-lg hover:bg-gray-50 transition-colors focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-gray-500">
                            Close
                        </button>
                    </div>
                </div>
            </div>
        </div>
    </div>
</div>

<script>
    function printCourses(curriculumId) {
        // Create a new window for printing
        const printWindow = window.open("", "", "height=600,width=800");
        if (!printWindow) {
            alert("Please allow popups to print the curriculum.");
            return;
        }

        // Fetch courses data from the table rows in #coursesContainer
        const courses = [];
        const curricula = {
            curriculum_name: document
                .getElementById("viewCoursesTitle")
                ?.textContent.replace(/Courses for |Curriculum Courses - Print/g, "")
                .trim() || "Unnamed Curriculum",
        };
        const rows = document.querySelectorAll("#coursesContainer tbody tr");
        if (rows.length === 0) {
            printWindow.document.write(
                "<html><body><p>No courses available to print.</p></body></html>"
            );
            printWindow.print();
            printWindow.close();
            return;
        }

        rows.forEach((row) => {
            const cells = row.getElementsByTagName("td");
            if (cells.length >= 4) {
                courses.push({
                    code: cells[0].textContent.trim() || "N/A",
                    name: cells[1].textContent.trim() || "N/A",
                    units: cells[2].textContent.trim() || "N/A",
                    subjectType: cells[3].querySelector("span")?.textContent.trim() || "N/A",
                    yearLevel: row
                        .closest("table")
                        .previousElementSibling?.textContent.split("-")[0]
                        .trim() || "N/A",
                    semester: row
                        .closest("table")
                        .previousElementSibling?.textContent.split("-")[1]
                        .trim() || "N/A",
                });
            }
        });

        // Get current user's name (fallback to 'Anonymous' if not available)
        const printedBy =
            window.currentUser?.name ||
            document.getElementById("userName")?.textContent.trim() ||
            "Anonymous";

        // Generate printable HTML content
        let htmlContent = `
        <html>
        <head>
            <style>
                body {
                    font-family: Arial, sans-serif;
                    margin: 20mm;
                    color: #333;
                }
                .header {
                    text-align: center;
                    margin-bottom: 20mm;
                    display: flex;
                    justify-content: space-between;
                    align-items: center;
                    width: 100%;
                }
                .header img {
                    max-width: 100px;
                    max-height: 100px;
                }
                .header .logo-left {
                    margin-right: auto;
                }
                .header .logo-right {
                    margin-left: auto;
                }
                .header-text {
                    flex-grow: 1;
                    text-align: center;
                }
                .header h1 {
                    font-size: 24px;
                    margin: 5px 0;
                }
                table {
                    width: 100%;
                    border-collapse: collapse;
                    margin-bottom: 20mm;
                }
                th, td {
                    border: 1px solid #ddd;
                    padding: 8px;
                    text-align: left;
                }
                th {
                    background-color: #f5f5f5;
                    font-weight: bold;
                }
                .footer {
                    text-align: center;
                    font-size: 12px;
                    color: #666;
                    position: fixed;
                    bottom: 20mm;
                    width: 100%;
                }
                @media print {
                    body {
                        margin: 0;
                    }
                    .header img {
                        width: 80px;
                        height: 80px;
                    }
                    .footer {
                        position: fixed;
                        bottom: 0;
                    }
                }
            </style>
        </head>
        <body>
            <div class="header">
                <img src="/assets/logo/main_logo/PRMSUlogo.png" alt="University Logo" class="university-logo">
                <div class="header-text">
                    <h1>President Ramon Magsaysay State University</h1>
                    <h2>${curricula.curriculum_name}</h2>
                </div>
                 <img src="<?= htmlspecialchars($collegeLogoPath) ?>" alt="College Logo" class="logo-right" onerror="handleLogoError(this)">
            </div>
            <table>
                <thead>
                    <tr>
                        <th>Year Level</th>
                        <th>Semester</th>
                        <th>Course Code</th>
                        <th>Course Name</th>
                        <th>Units</th>
                        <th>Subject Type</th>
                    </tr>
                </thead>
                <tbody>
    `;

        courses.forEach((course) => {
            htmlContent += `
            <tr>
                <td>${course.yearLevel}</td>
                <td>${course.semester}</td>
                <td>${course.code}</td>
                <td>${course.name}</td>
                <td>${course.units}</td>
                <td>${course.subjectType}</td>
            </tr>
        `;
        });

        htmlContent += `
                </tbody>
            </table>
            <div class="footer">
                <p>Printed by: ${printedBy}</p>
            </div>
        </body>
        </html>
    `;

        // Write content to print window and trigger print
        printWindow.document.write(htmlContent);
        printWindow.document.close();
        printWindow.focus();
        printWindow.print();
        printWindow.close();
    }
</script>

<script src="/assets/js/curriculum.js"></script>



<?php
$content = ob_get_clean();
require_once __DIR__ . '/layout.php';
?>