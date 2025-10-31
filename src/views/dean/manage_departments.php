<?php
$title = "Manage Academic Structure";
ob_start();
?>

<div class="max-w-7xl mx-auto space-y-8">

    <!-- Success/Error Messages -->
    <?php if ($success): ?>
        <div class="bg-green-50 border-l-4 border-green-500 p-6 rounded-lg shadow-sm animate-fadeIn">
            <div class="flex items-center">
                <div class="flex-shrink-0">
                    <i class="fas fa-check-circle text-green-500 text-xl"></i>
                </div>
                <div class="ml-4">
                    <p class="text-green-700 font-medium"><?php echo htmlspecialchars($success); ?></p>
                </div>
            </div>
        </div>
    <?php endif; ?>

    <?php if ($error): ?>
        <div class="bg-red-50 border-l-4 border-red-500 p-6 rounded-lg shadow-sm animate-fadeIn">
            <div class="flex items-center">
                <div class="flex-shrink-0">
                    <i class="fas fa-exclamation-circle text-red-500 text-xl"></i>
                </div>
                <div class="ml-4">
                    <p class="text-red-700 font-medium"><?php echo htmlspecialchars($error); ?></p>
                </div>
            </div>
        </div>
    <?php endif; ?>

    <!-- Quick Stats -->
    <div class="grid grid-cols-1 md:grid-cols-3 gap-6">
        <div class="bg-white rounded-xl shadow-lg p-6 border-l-4 border-yellow-500">
            <div class="flex items-center justify-between">
                <div>
                    <p class="text-gray-500 text-sm font-medium">Total Departments</p>
                    <p class="text-3xl font-bold text-gray-800"><?php echo count($departments); ?></p>
                </div>
                <div class="bg-yellow-100 p-3 rounded-lg">
                    <i class="fas fa-building text-yellow-600 text-xl"></i>
                </div>
            </div>
        </div>

        <div class="bg-white rounded-xl shadow-lg p-6 border-l-4 border-yellow-500">
            <div class="flex items-center justify-between">
                <div>
                    <p class="text-gray-500 text-sm font-medium">Total Programs</p>
                    <p class="text-3xl font-bold text-gray-800"><?php echo count($programs); ?></p>
                </div>
                <div class="bg-yellow-100 p-3 rounded-lg">
                    <i class="fas fa-graduation-cap text-yellow-600 text-xl"></i>
                </div>
            </div>
        </div>

        <div class="bg-white rounded-xl shadow-lg p-6 border-l-4 border-green-500">
            <div class="flex items-center justify-between">
                <div class="max-w-[calc(100%-3rem)]">
                    <p class="text-gray-500 text-sm font-medium">College</p>
                    <p class="text-xl font-bold text-gray-800 truncate" title="<?php echo htmlspecialchars($college['college_name']); ?>">
                        <?php echo htmlspecialchars($college['college_name']); ?>
                    </p>
                </div>
                <div class="bg-green-100 p-3 rounded-lg flex-shrink-0">
                    <i class="fas fa-school text-green-600 text-xl"></i>
                </div>
            </div>
        </div>
    </div>

    <!-- Main Content -->
    <div class="bg-white rounded-2xl shadow-2xl overflow-hidden">
        <div class="bg-gradient-to-r from-gray-800 to-gray-900 px-6 py-4">
            <div class="flex items-center justify-between">
                <div class="flex items-center">
                    <i class="fas fa-sitemap text-yellow-400 text-xl mr-3"></i>
                    <h2 class="text-xl font-bold text-white">Departments & Programs</h2>
                </div>
                <button onclick="openAddDepartmentModal()"
                    class="bg-yellow-500 text-white px-4 py-2 rounded-lg hover:bg-yellow-600 focus:outline-none focus:ring-2 focus:ring-yellow-500 transition-colors font-medium">
                    <i class="fas fa-plus mr-2"></i>Add Department & Program
                </button>
            </div>
        </div>

        <div class="p-6">
            <?php if (empty($departments)): ?>
                <div class="text-center py-12">
                    <i class="fas fa-inbox text-gray-300 text-5xl mb-4"></i>
                    <h3 class="text-xl font-semibold text-gray-600 mb-2">No Departments Found</h3>
                    <p class="text-gray-500 mb-6">Start by adding your first department and program.</p>
                    <button onclick="openAddDepartmentModal()"
                        class="bg-yellow-500 text-white px-6 py-3 rounded-lg hover:bg-yellow-600 focus:outline-none focus:ring-2 focus:ring-yellow-500 transition-colors font-medium">
                        <i class="fas fa-plus mr-2"></i>Add First Department & Program
                    </button>
                </div>
            <?php else: ?>
                <div class="space-y-6">
                    <?php
                    // Group programs by department
                    $programsByDepartment = [];
                    foreach ($programs as $program) {
                        $programsByDepartment[$program['department_id']][] = $program;
                    }
                    ?>

                    <?php foreach ($departments as $department): ?>
                        <?php $departmentPrograms = $programsByDepartment[$department['department_id']] ?? []; ?>

                        <div class="border border-gray-200 rounded-xl overflow-hidden hover:shadow-lg transition-shadow duration-300">
                            <!-- Department Header -->
                            <div class="bg-gradient-to-r from-yellow-50 to-yellow-100 px-6 py-4 border-b border-yellow-200">
                                <div class="flex items-center justify-between">
                                    <div class="flex items-center space-x-4">
                                        <div class="bg-yellow-500 text-white p-3 rounded-lg">
                                            <i class="fas fa-building"></i>
                                        </div>
                                        <div>
                                            <h3 class="text-lg font-bold text-gray-800">
                                                <?php echo htmlspecialchars($department['department_name']); ?>
                                            </h3>
                                            <div class="flex items-center space-x-4 text-sm text-gray-600 mt-1">
                                                <span class="bg-yellow-100 text-yellow-700 px-2 py-1 rounded">
                                                    <i class="fas fa-code mr-1"></i><?php echo htmlspecialchars($department['department_code']); ?>
                                                </span>
                                                <span class="bg-green-100 text-green-700 px-2 py-1 rounded">
                                                    <i class="fas fa-graduation-cap mr-1"></i><?php echo count($departmentPrograms); ?> programs
                                                </span>
                                            </div>
                                        </div>
                                    </div>
                                    <div class="flex space-x-2">
                                        <button onclick="openEditDepartmentModal(
                                            <?php echo $department['department_id']; ?>, 
                                            '<?php echo htmlspecialchars($department['department_name']); ?>',
                                            '<?php echo htmlspecialchars($department['department_code']); ?>',
                                            <?php echo count($departmentPrograms); ?>
                                        )"
                                            class="bg-yellow-500 text-white p-2 rounded-lg hover:bg-yellow-600 transition-colors"
                                            title="Edit Department">
                                            <i class="fas fa-edit"></i>
                                        </button>
                                        <button onclick="openAddProgramModal(
                                            <?php echo $department['department_id']; ?>,
                                            '<?php echo htmlspecialchars($department['department_name']); ?>',
                                            '<?php echo htmlspecialchars($department['department_code']); ?>'
                                        )"
                                            class="bg-green-500 text-white p-2 rounded-lg hover:bg-green-600 transition-colors"
                                            title="Add Program">
                                            <i class="fas fa-plus"></i>
                                        </button>
                                        <form method="POST" class="inline"
                                            onsubmit="return confirm('Are you sure you want to delete this department? This will also delete all associated programs.');">
                                            <input type="hidden" name="csrf_token" value="<?php echo htmlspecialchars($_SESSION['csrf_token']); ?>">
                                            <input type="hidden" name="department_id" value="<?php echo $department['department_id']; ?>">
                                            <button type="submit"
                                                name="delete_department"
                                                class="bg-red-500 text-white p-2 rounded-lg hover:bg-red-600 transition-colors"
                                                title="Delete Department">
                                                <i class="fas fa-trash"></i>
                                            </button>
                                        </form>
                                    </div>
                                </div>
                            </div>

                            <!-- Programs Section -->
                            <div class="p-6">
                                <?php if (empty($departmentPrograms)): ?>
                                    <div class="text-center py-6">
                                        <i class="fas fa-book-open text-gray-300 text-3xl mb-3"></i>
                                        <p class="text-gray-500 mb-4">No programs in this department yet.</p>
                                        <button onclick="openAddProgramModal(
                                            <?php echo $department['department_id']; ?>,
                                            '<?php echo htmlspecialchars($department['department_name']); ?>',
                                            '<?php echo htmlspecialchars($department['department_code']); ?>'
                                        )"
                                            class="bg-green-500 text-white px-4 py-2 rounded-lg hover:bg-green-600 focus:outline-none focus:ring-2 focus:ring-green-500 transition-colors text-sm">
                                            <i class="fas fa-plus mr-1"></i>Add First Program
                                        </button>
                                    </div>
                                <?php else: ?>
                                    <div class="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
                                        <?php foreach ($departmentPrograms as $program): ?>
                                            <div class="bg-gradient-to-br from-yellow-50 to-white border border-yellow-100 rounded-lg p-4 hover:shadow-md transition-shadow duration-300 group">
                                                <div class="flex items-start justify-between mb-3">
                                                    <div class="flex-1">
                                                        <h4 class="font-semibold text-gray-800 text-lg group-hover:text-yellow-600 transition-colors">
                                                            <?php echo htmlspecialchars($program['program_name']); ?>
                                                        </h4>
                                                        <div class="flex items-center space-x-2 mt-1">
                                                            <span class="bg-yellow-100 text-yellow-700 px-2 py-1 rounded text-sm font-medium">
                                                                <?php echo htmlspecialchars($program['program_code']); ?>
                                                            </span>
                                                        </div>
                                                    </div>
                                                    <div class="flex space-x-1 opacity-0 group-hover:opacity-100 transition-opacity duration-300">
                                                        <button onclick="openEditProgramModal(
                                                            <?php echo $program['program_id']; ?>, 
                                                            '<?php echo htmlspecialchars($program['program_code']); ?>',
                                                            '<?php echo htmlspecialchars($program['program_name']); ?>',
                                                            <?php echo $program['department_id']; ?>,
                                                            '<?php echo htmlspecialchars($department['department_name']); ?>',
                                                            '<?php echo htmlspecialchars($department['department_code']); ?>'
                                                        )"
                                                            class="text-yellow-600 hover:text-yellow-800 transition-colors p-1"
                                                            title="Edit Program">
                                                            <i class="fas fa-edit"></i>
                                                        </button>
                                                        <form method="POST" class="inline"
                                                            onsubmit="return confirm('Are you sure you want to delete this program?');">
                                                            <input type="hidden" name="csrf_token" value="<?php echo htmlspecialchars($_SESSION['csrf_token']); ?>">
                                                            <input type="hidden" name="program_id" value="<?php echo $program['program_id']; ?>">
                                                            <button type="submit"
                                                                name="delete_program"
                                                                class="text-red-600 hover:text-red-800 transition-colors p-1"
                                                                title="Delete Program">
                                                                <i class="fas fa-trash"></i>
                                                            </button>
                                                        </form>
                                                    </div>
                                                </div>
                                                <div class="text-xs text-gray-500 flex items-center">
                                                    <i class="fas fa-clock mr-1"></i>
                                                    Program ID: <?php echo $program['program_id']; ?>
                                                </div>
                                            </div>
                                        <?php endforeach; ?>
                                    </div>
                                <?php endif; ?>
                            </div>
                        </div>
                    <?php endforeach; ?>
                </div>
            <?php endif; ?>
        </div>
    </div>
</div>

<!-- Add Department with Program Modal -->
<div id="addDepartmentModal" class="fixed inset-0 bg-black/70 backdrop-blur-sm flex items-center justify-center hidden z-50 p-4">
    <div class="bg-white rounded-2xl shadow-2xl w-full max-w-2xl transform transition-all duration-300 modal-content">
        <div class="bg-gradient-to-r from-yellow-500 to-yellow-600 px-6 py-4 rounded-t-2xl">
            <div class="flex items-center justify-between">
                <h3 class="text-xl font-bold text-white">Add New Department & Program</h3>
                <button type="button"
                    onclick="closeAddDepartmentModal()"
                    class="text-white hover:text-yellow-200 transition-colors">
                    <i class="fas fa-times text-xl"></i>
                </button>
            </div>
        </div>
        <form method="POST" class="p-6">
            <input type="hidden" name="csrf_token" value="<?php echo htmlspecialchars($_SESSION['csrf_token']); ?>">

            <div class="grid grid-cols-1 lg:grid-cols-2 gap-6">
                <!-- Department Information -->
                <div class="space-y-4">
                    <h4 class="text-lg font-semibold text-gray-800 border-b border-gray-200 pb-2">
                        <i class="fas fa-building mr-2 text-yellow-500"></i>Department Information
                    </h4>

                    <div class="space-y-3">
                        <div>
                            <label for="department_code" class="block text-sm font-semibold text-gray-700 mb-1">
                                Department Code *
                            </label>
                            <input type="text"
                                id="department_code"
                                name="department_code"
                                required
                                maxlength="10"
                                placeholder="e.g., CS, IT, ENG"
                                class="w-full px-4 py-3 border border-gray-300 rounded-xl focus:outline-none focus:ring-2 focus:ring-yellow-500 focus:border-yellow-500 transition-all duration-300">
                            <p class="text-xs text-gray-500 mt-1">Short code for the department</p>
                        </div>

                        <div>
                            <label for="department_name" class="block text-sm font-semibold text-gray-700 mb-1">
                                Department Name *
                            </label>
                            <input type="text"
                                id="department_name"
                                name="department_name"
                                required
                                maxlength="100"
                                placeholder="e.g., Computer Science Department"
                                class="w-full px-4 py-3 border border-gray-300 rounded-xl focus:outline-none focus:ring-2 focus:ring-yellow-500 focus:border-yellow-500 transition-all duration-300">
                            <p class="text-xs text-gray-500 mt-1">Full name of the department</p>
                        </div>
                    </div>
                </div>

                <!-- Program Information -->
                <div class="space-y-4">
                    <h4 class="text-lg font-semibold text-gray-800 border-b border-gray-200 pb-2">
                        <i class="fas fa-graduation-cap mr-2 text-yellow-500"></i>Program Information
                    </h4>

                    <div class="space-y-3">
                        <div>
                            <label for="program_code" class="block text-sm font-semibold text-gray-700 mb-1">
                                Program Code *
                            </label>
                            <input type="text"
                                id="program_code"
                                name="program_code"
                                required
                                maxlength="20"
                                placeholder="e.g., BSIT, BSCS"
                                class="w-full px-4 py-3 border border-gray-300 rounded-xl focus:outline-none focus:ring-2 focus:ring-yellow-500 focus:border-yellow-500 transition-all duration-300">
                            <p class="text-xs text-gray-500 mt-1">Program code</p>
                        </div>

                        <div>
                            <label for="program_name" class="block text-sm font-semibold text-gray-700 mb-1">
                                Program Name *
                            </label>
                            <input type="text"
                                id="program_name"
                                name="program_name"
                                required
                                maxlength="100"
                                placeholder="e.g., Bachelor of Science in Information Technology"
                                class="w-full px-4 py-3 border border-gray-300 rounded-xl focus:outline-none focus:ring-2 focus:ring-yellow-500 focus:border-yellow-500 transition-all duration-300">
                            <p class="text-xs text-gray-500 mt-1">Full name of the academic program</p>
                        </div>
                    </div>
                </div>
            </div>

            <div class="flex justify-end space-x-3 pt-6 border-t border-gray-200 mt-6">
                <button type="button"
                    onclick="closeAddDepartmentModal()"
                    class="px-6 py-3 text-gray-600 border border-gray-300 rounded-xl hover:bg-gray-50 transition-colors font-medium">
                    Cancel
                </button>
                <button type="submit"
                    name="add_department_with_program"
                    class="px-6 py-3 bg-gradient-to-r from-yellow-500 to-yellow-600 text-white rounded-xl hover:from-yellow-600 hover:to-yellow-700 focus:outline-none focus:ring-2 focus:ring-yellow-500 transition-colors font-medium shadow-lg">
                    <i class="fas fa-plus-circle mr-2"></i>Add Department & Program
                </button>
            </div>
        </form>
    </div>
</div>

<!-- Edit Department Modal with Programs -->
<div id="editDepartmentModal" class="fixed inset-0 bg-black/70 backdrop-blur-sm flex items-center justify-center hidden z-50 p-4">
    <div class="bg-white rounded-2xl shadow-2xl w-full max-w-4xl transform transition-all duration-300 modal-content max-h-[90vh] overflow-hidden flex flex-col">
        <div class="bg-gradient-to-r from-yellow-500 to-yellow-600 px-6 py-4 rounded-t-2xl">
            <div class="flex items-center justify-between">
                <h3 class="text-xl font-bold text-white">Edit Department</h3>
                <button type="button"
                    onclick="closeEditDepartmentModal()"
                    class="text-white hover:text-yellow-200 transition-colors">
                    <i class="fas fa-times text-xl"></i>
                </button>
            </div>
        </div>

        <div class="flex-1 overflow-y-auto">
            <form method="POST" id="editDepartmentForm" class="p-6 border-b border-gray-200">
                <input type="hidden" name="csrf_token" value="<?php echo htmlspecialchars($_SESSION['csrf_token']); ?>">
                <input type="hidden" name="department_id" id="edit_department_id">

                <div class="grid grid-cols-1 lg:grid-cols-2 gap-6 mb-6">
                    <div class="space-y-2">
                        <label for="edit_department_code" class="block text-sm font-semibold text-gray-700">
                            <i class="fas fa-code mr-2 text-yellow-500"></i>
                            Department Code
                        </label>
                        <input type="text"
                            id="edit_department_code"
                            name="department_code"
                            required
                            maxlength="10"
                            class="w-full px-4 py-3 border border-gray-300 rounded-xl focus:outline-none focus:ring-2 focus:ring-yellow-500 focus:border-yellow-500 transition-all duration-300">
                    </div>

                    <div class="space-y-2">
                        <label for="edit_department_name" class="block text-sm font-semibold text-gray-700">
                            <i class="fas fa-building mr-2 text-yellow-500"></i>
                            Department Name
                        </label>
                        <input type="text"
                            id="edit_department_name"
                            name="department_name"
                            required
                            maxlength="100"
                            class="w-full px-4 py-3 border border-gray-300 rounded-xl focus:outline-none focus:ring-2 focus:ring-yellow-500 focus:border-yellow-500 transition-all duration-300">
                    </div>
                </div>

                <div class="flex justify-end space-x-3 pt-4">
                    <button type="button"
                        onclick="closeEditDepartmentModal()"
                        class="px-6 py-3 text-gray-600 border border-gray-300 rounded-xl hover:bg-gray-50 transition-colors font-medium">
                        Cancel
                    </button>
                    <button type="submit"
                        name="edit_department"
                        class="px-6 py-3 bg-gradient-to-r from-yellow-500 to-yellow-600 text-white rounded-xl hover:from-yellow-600 hover:to-yellow-700 focus:outline-none focus:ring-2 focus:ring-yellow-500 transition-colors font-medium shadow-lg">
                        <i class="fas fa-save mr-2"></i>Update Department
                    </button>
                </div>
            </form>

            <!-- Programs Section in Edit Modal -->
            <div class="p-6">
                <div class="flex items-center justify-between mb-4">
                    <h4 class="text-lg font-semibold text-gray-800">
                        <i class="fas fa-graduation-cap mr-2 text-yellow-500"></i>
                        Department Programs
                    </h4>
                    <span class="bg-yellow-100 text-yellow-700 px-3 py-1 rounded-full text-sm font-semibold" id="programs_count">
                        0 programs
                    </span>
                </div>

                <div id="departmentProgramsList" class="space-y-3 max-h-60 overflow-y-auto pr-2">
                    <!-- Programs will be loaded here dynamically -->
                </div>
            </div>
        </div>
    </div>
</div>

<!-- Add Program Modal -->
<div id="addProgramModal" class="fixed inset-0 bg-black/70 backdrop-blur-sm flex items-center justify-center hidden z-50 p-4">
    <div class="bg-white rounded-2xl shadow-2xl w-full max-w-md transform transition-all duration-300 modal-content">
        <div class="bg-gradient-to-r from-yellow-500 to-yellow-600 px-6 py-4 rounded-t-2xl">
            <div class="flex items-center justify-between">
                <h3 class="text-xl font-bold text-white">Add New Program</h3>
                <button type="button"
                    onclick="closeAddProgramModal()"
                    class="text-white hover:text-yellow-200 transition-colors">
                    <i class="fas fa-times text-xl"></i>
                </button>
            </div>
        </div>
        <form method="POST" id="addProgramForm" class="p-6">
            <input type="hidden" name="csrf_token" value="<?php echo htmlspecialchars($_SESSION['csrf_token']); ?>">
            <input type="hidden" name="department_id" id="add_program_department_id">

            <!-- Department Information -->
            <div class="bg-yellow-50 border border-yellow-200 rounded-lg p-4 mb-4">
                <div class="flex items-center space-x-3">
                    <div class="bg-yellow-100 p-2 rounded-lg">
                        <i class="fas fa-building text-yellow-600"></i>
                    </div>
                    <div>
                        <h4 class="font-semibold text-gray-800 text-sm" id="add_program_department_name">Department Name</h4>
                        <p class="text-gray-600 text-xs" id="add_program_department_code">Department Code</p>
                    </div>
                </div>
            </div>

            <div class="space-y-4">
                <div class="space-y-2">
                    <label for="add_program_code" class="block text-sm font-semibold text-gray-700">
                        <i class="fas fa-code mr-2 text-yellow-500"></i>
                        Program Code
                    </label>
                    <input type="text"
                        id="add_program_code"
                        name="program_code"
                        required
                        maxlength="20"
                        placeholder="e.g., BSIT, BSCS"
                        class="w-full px-4 py-3 border border-gray-300 rounded-xl focus:outline-none focus:ring-2 focus:ring-yellow-500 focus:border-yellow-500 transition-all duration-300">
                </div>

                <div class="space-y-2">
                    <label for="add_program_name" class="block text-sm font-semibold text-gray-700">
                        <i class="fas fa-book mr-2 text-yellow-500"></i>
                        Program Name
                    </label>
                    <input type="text"
                        id="add_program_name"
                        name="program_name"
                        required
                        maxlength="100"
                        placeholder="e.g., Bachelor of Science in Information Technology"
                        class="w-full px-4 py-3 border border-gray-300 rounded-xl focus:outline-none focus:ring-2 focus:ring-yellow-500 focus:border-yellow-500 transition-all duration-300">
                </div>

                <div class="flex justify-end space-x-3 pt-4">
                    <button type="button"
                        onclick="closeAddProgramModal()"
                        class="px-6 py-3 text-gray-600 border border-gray-300 rounded-xl hover:bg-gray-50 transition-colors font-medium">
                        Cancel
                    </button>
                    <button type="submit"
                        name="add_program"
                        class="px-6 py-3 bg-gradient-to-r from-yellow-500 to-yellow-600 text-white rounded-xl hover:from-yellow-600 hover:to-yellow-700 focus:outline-none focus:ring-2 focus:ring-yellow-500 transition-colors font-medium shadow-lg">
                        <i class="fas fa-plus mr-2"></i>Add Program
                    </button>
                </div>
            </div>
        </form>
    </div>
</div>

<!-- Edit Program Modal -->
<div id="editProgramModal" class="fixed inset-0 bg-black/70 backdrop-blur-sm flex items-center justify-center hidden z-50 p-4">
    <div class="bg-white rounded-2xl shadow-2xl w-full max-w-md transform transition-all duration-300 modal-content">
        <div class="bg-gradient-to-r from-yellow-500 to-yellow-600 px-6 py-4 rounded-t-2xl">
            <div class="flex items-center justify-between">
                <h3 class="text-xl font-bold text-white">Edit Program</h3>
                <button type="button"
                    onclick="closeEditProgramModal()"
                    class="text-white hover:text-yellow-200 transition-colors">
                    <i class="fas fa-times text-xl"></i>
                </button>
            </div>
        </div>
        <form method="POST" id="editProgramForm" class="p-6">
            <input type="hidden" name="csrf_token" value="<?php echo htmlspecialchars($_SESSION['csrf_token']); ?>">
            <input type="hidden" name="program_id" id="edit_program_id">

            <!-- Department Information -->
            <div class="bg-yellow-50 border border-yellow-200 rounded-lg p-4 mb-4">
                <div class="flex items-center space-x-3">
                    <div class="bg-yellow-100 p-2 rounded-lg">
                        <i class="fas fa-building text-yellow-600"></i>
                    </div>
                    <div>
                        <h4 class="font-semibold text-gray-800 text-sm" id="edit_program_department_name">Department Name</h4>
                        <p class="text-gray-600 text-xs" id="edit_program_department_code">Department Code</p>
                    </div>
                </div>
            </div>

            <div class="space-y-4">
                <div class="space-y-2">
                    <label for="edit_program_code" class="block text-sm font-semibold text-gray-700">
                        <i class="fas fa-code mr-2 text-yellow-500"></i>
                        Program Code
                    </label>
                    <input type="text"
                        id="edit_program_code"
                        name="program_code"
                        required
                        maxlength="20"
                        class="w-full px-4 py-3 border border-gray-300 rounded-xl focus:outline-none focus:ring-2 focus:ring-yellow-500 focus:border-yellow-500 transition-all duration-300">
                </div>

                <div class="space-y-2">
                    <label for="edit_program_name" class="block text-sm font-semibold text-gray-700">
                        <i class="fas fa-book mr-2 text-yellow-500"></i>
                        Program Name
                    </label>
                    <input type="text"
                        id="edit_program_name"
                        name="program_name"
                        required
                        maxlength="100"
                        class="w-full px-4 py-3 border border-gray-300 rounded-xl focus:outline-none focus:ring-2 focus:ring-yellow-500 focus:border-yellow-500 transition-all duration-300">
                </div>

                <div class="flex justify-end space-x-3 pt-4">
                    <button type="button"
                        onclick="closeEditProgramModal()"
                        class="px-6 py-3 text-gray-600 border border-gray-300 rounded-xl hover:bg-gray-50 transition-colors font-medium">
                        Cancel
                    </button>
                    <button type="submit"
                        name="edit_program"
                        class="px-6 py-3 bg-gradient-to-r from-yellow-500 to-yellow-600 text-white rounded-xl hover:from-yellow-600 hover:to-yellow-700 focus:outline-none focus:ring-2 focus:ring-yellow-500 transition-colors font-medium shadow-lg">
                        <i class="fas fa-save mr-2"></i>Update Program
                    </button>
                </div>
            </div>
        </form>
    </div>
</div>

<script>
    // Modal Functions
    function openAddDepartmentModal() {
        const modal = document.getElementById('addDepartmentModal');
        modal.classList.remove('hidden');
        setTimeout(() => {
            modal.querySelector('.modal-content').style.transform = 'scale(1)';
        }, 10);
    }

    function closeAddDepartmentModal() {
        const modal = document.getElementById('addDepartmentModal');
        modal.querySelector('.modal-content').style.transform = 'scale(0.95)';
        setTimeout(() => {
            modal.classList.add('hidden');
        }, 300);
    }

    function openEditDepartmentModal(departmentId, departmentName, departmentCode, programCount) {
        document.getElementById('edit_department_id').value = departmentId;
        document.getElementById('edit_department_name').value = departmentName;
        document.getElementById('edit_department_code').value = departmentCode;
        document.getElementById('programs_count').textContent = programCount + ' programs';

        // Load programs for this department
        loadDepartmentPrograms(departmentId);

        const modal = document.getElementById('editDepartmentModal');
        modal.classList.remove('hidden');
        setTimeout(() => {
            modal.querySelector('.modal-content').style.transform = 'scale(1)';
        }, 10);
    }

    function closeEditDepartmentModal() {
        const modal = document.getElementById('editDepartmentModal');
        modal.querySelector('.modal-content').style.transform = 'scale(0.95)';
        setTimeout(() => {
            modal.classList.add('hidden');
        }, 300);
    }

    function openAddProgramModal(departmentId, departmentName, departmentCode) {
        document.getElementById('add_program_department_id').value = departmentId;
        document.getElementById('add_program_department_name').textContent = departmentName;
        document.getElementById('add_program_department_code').textContent = `Code: ${departmentCode}`;

        const modal = document.getElementById('addProgramModal');
        modal.classList.remove('hidden');
        setTimeout(() => {
            modal.querySelector('.modal-content').style.transform = 'scale(1)';
        }, 10);
    }

    function closeAddProgramModal() {
        const modal = document.getElementById('addProgramModal');
        modal.querySelector('.modal-content').style.transform = 'scale(0.95)';
        setTimeout(() => {
            modal.classList.add('hidden');
        }, 300);
    }

    function openEditProgramModal(programId, programCode, programName, departmentId, departmentName, departmentCode) {
        document.getElementById('edit_program_id').value = programId;
        document.getElementById('edit_program_code').value = programCode;
        document.getElementById('edit_program_name').value = programName;
        document.getElementById('edit_program_department_name').textContent = departmentName;
        document.getElementById('edit_program_department_code').textContent = `Code: ${departmentCode}`;

        const modal = document.getElementById('editProgramModal');
        modal.classList.remove('hidden');
        setTimeout(() => {
            modal.querySelector('.modal-content').style.transform = 'scale(1)';
        }, 10);
    }

    function closeEditProgramModal() {
        const modal = document.getElementById('editProgramModal');
        modal.querySelector('.modal-content').style.transform = 'scale(0.95)';
        setTimeout(() => {
            modal.classList.add('hidden');
        }, 300);
    }

    // Load department programs for edit modal
    function loadDepartmentPrograms(departmentId) {
        const programsList = document.getElementById('departmentProgramsList');
        programsList.innerHTML = '<div class="text-center py-4"><i class="fas fa-spinner fa-spin text-yellow-500"></i><p class="text-gray-500 mt-2">Loading programs...</p></div>';

        // In a real application, you would fetch this data via AJAX
        // For now, we'll simulate it with existing data
        setTimeout(() => {
            const departmentPrograms = <?php echo json_encode($programsByDepartment); ?>;
            const programs = departmentPrograms[departmentId] || [];

            if (programs.length === 0) {
                programsList.innerHTML = `
                    <div class="text-center py-6">
                        <i class="fas fa-book-open text-gray-300 text-3xl mb-3"></i>
                        <p class="text-gray-500">No programs in this department.</p>
                    </div>
                `;
            } else {
                let programsHTML = '';
                programs.forEach(program => {
                    programsHTML += `
                        <div class="flex items-center justify-between p-3 border border-gray-200 rounded-lg hover:bg-gray-50 transition-colors">
                            <div class="flex-1">
                                <h5 class="font-medium text-gray-800">${program.program_name}</h5>
                                <div class="flex items-center space-x-2 mt-1">
                                    <span class="bg-yellow-100 text-yellow-700 px-2 py-1 rounded text-xs">
                                        ${program.program_code}
                                    </span>
                                </div>
                            </div>
                            <div class="flex space-x-2">
                                <button onclick="openEditProgramModal(
                                    ${program.program_id}, 
                                    '${program.program_code}',
                                    '${program.program_name}',
                                    ${program.department_id},
                                    '${document.getElementById('edit_department_name').value}',
                                    '${document.getElementById('edit_department_code').value}'
                                )" 
                                    class="text-yellow-600 hover:text-yellow-800 transition-colors p-1"
                                    title="Edit Program">
                                    <i class="fas fa-edit text-sm"></i>
                                </button>
                                <form method="POST" class="inline" 
                                    onsubmit="return confirm('Are you sure you want to delete this program?');">
                                    <input type="hidden" name="csrf_token" value="<?php echo htmlspecialchars($_SESSION['csrf_token']); ?>">
                                    <input type="hidden" name="program_id" value="${program.program_id}">
                                    <button type="submit"
                                        name="delete_program"
                                        class="text-red-600 hover:text-red-800 transition-colors p-1"
                                        title="Delete Program">
                                        <i class="fas fa-trash text-sm"></i>
                                    </button>
                                </form>
                            </div>
                        </div>
                    `;
                });
                programsList.innerHTML = programsHTML;
            }
        }, 500);
    }

    // Close modals when clicking outside
    document.addEventListener('DOMContentLoaded', function() {
        document.querySelectorAll('.fixed.inset-0').forEach(modal => {
            modal.addEventListener('click', function(e) {
                if (e.target === this) {
                    const modalId = this.id;
                    if (modalId === 'addDepartmentModal') closeAddDepartmentModal();
                    if (modalId === 'editDepartmentModal') closeEditDepartmentModal();
                    if (modalId === 'addProgramModal') closeAddProgramModal();
                    if (modalId === 'editProgramModal') closeEditProgramModal();
                }
            });
        });
    });
</script>

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

    .modal-content {
        transform: scale(0.95);
        transition: transform 0.3s ease;
    }

    .transition-all {
        transition: all 0.3s ease;
    }
</style>

<?php
$content = ob_get_clean();
include __DIR__ . '/layout.php';
?>