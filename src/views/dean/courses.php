<?php
ob_start();

// Check for success/error messages from DeanController
$success = isset($_GET['success']) ? htmlspecialchars($_GET['success']) : null;
$error = isset($_GET['error']) ? htmlspecialchars($_GET['error']) : null;

// Pagination parameters
$currentPage = isset($_GET['page']) ? (int)$_GET['page'] : 1;
$perPage = 10; // Number of items per page
$totalCourses = count($courses);
$totalPages = ceil($totalCourses / $perPage);

// Validate current page
if ($currentPage < 1) {
    $currentPage = 1;
} elseif ($currentPage > $totalPages) {
    $currentPage = $totalPages;
}

// Get courses for current page
$startIndex = ($currentPage - 1) * $perPage;
$paginatedCourses = array_slice($courses, $startIndex, $perPage);
?>

<?php if ($success): ?>
    <script>
        document.addEventListener('DOMContentLoaded', () => {
            const toast = document.createElement('div');
            toast.className = 'toast bg-green-500 text-white px-4 py-2 rounded-lg';
            toast.textContent = '<?php echo $success; ?>';
            document.getElementById('toast-container').appendChild(toast);
            setTimeout(() => toast.remove(), 5000);
        });
    </script>
<?php endif; ?>
<?php if ($error): ?>
    <script>
        document.addEventListener('DOMContentLoaded', () => {
            const toast = document.createElement('div');
            toast.className = 'toast bg-red-500 text-white px-4 py-2 rounded-lg';
            toast.textContent = '<?php echo $error; ?>';
            document.getElementById('toast-container').appendChild(toast);
            setTimeout(() => toast.remove(), 5000);
        });
    </script>
<?php endif; ?>

<h2 class="text-3xl font-bold text-gray-600 mb-6 slide-in-left">Courses Management</h2>

<!-- Filters Section -->
<div class="bg-white p-6 rounded-lg shadow-md card mb-6">
    <h3 class="text-xl font-semibold text-gray-600 mb-4">Filters</h3>
    <form id="filterForm" method="get" class="grid grid-cols-1 md:grid-cols-4 gap-4">
        <input type="hidden" name="page" value="1">
        <div>
            <label for="departmentFilter" class="block text-sm font-medium text-gray-600">Department</label>
            <select id="departmentFilter" name="department" class="mt-1 block w-full rounded-md border-gray-300 shadow-sm focus:border-gold-400 focus:ring focus:ring-gold-400 focus:ring-opacity-50">
                <option value="">All Departments</option>
                <?php foreach ($departments as $dept): ?>
                    <option value="<?php echo $dept['department_id']; ?>" <?php echo (isset($_GET['department']) && $_GET['department'] == $dept['department_id']) ? 'selected' : ''; ?>>
                        <?php echo htmlspecialchars($dept['department_name']); ?>
                    </option>
                <?php endforeach; ?>
            </select>
        </div>
        <div>
            <label for="programFilter" class="block text-sm font-medium text-gray-600">Program</label>
            <select id="programFilter" name="program" class="mt-1 block w-full rounded-md border-gray-300 shadow-sm focus:border-gold-400 focus:ring focus:ring-gold-400 focus:ring-opacity-50">
                <option value="">All Programs</option>
                <?php foreach ($programs as $program): ?>
                    <option value="<?php echo $program['program_id']; ?>" <?php echo (isset($_GET['program']) && $_GET['program'] == $program['program_id']) ? 'selected' : ''; ?>>
                        <?php echo htmlspecialchars($program['program_name']); ?>
                    </option>
                <?php endforeach; ?>
            </select>
        </div>
        <div>
            <label for="yearLevelFilter" class="block text-sm font-medium text-gray-600">Year Level</label>
            <select id="yearLevelFilter" name="year_level" class="mt-1 block w-full rounded-md border-gray-300 shadow-sm focus:border-gold-400 focus:ring focus:ring-gold-400 focus:ring-opacity-50">
                <option value="">All Levels</option>
                <option value="1st Year" <?php echo (isset($_GET['year_level']) && $_GET['year_level'] == '1st Year') ? 'selected' : ''; ?>>1st Year</option>
                <option value="2nd Year" <?php echo (isset($_GET['year_level']) && $_GET['year_level'] == '2nd Year') ? 'selected' : ''; ?>>2nd Year</option>
                <option value="3rd Year" <?php echo (isset($_GET['year_level']) && $_GET['year_level'] == '3rd Year') ? 'selected' : ''; ?>>3rd Year</option>
                <option value="4th Year" <?php echo (isset($_GET['year_level']) && $_GET['year_level'] == '4th Year') ? 'selected' : ''; ?>>4th Year</option>
            </select>
        </div>
        <div>
            <label for="statusFilter" class="block text-sm font-medium text-gray-600">Status</label>
            <select id="statusFilter" name="status" class="mt-1 block w-full rounded-md border-gray-300 shadow-sm focus:border-gold-400 focus:ring focus:ring-gold-400 focus:ring-opacity-50">
                <option value="1" <?php echo (!isset($_GET['status']) || (isset($_GET['status']) && $_GET['status'] == '1')) ? 'selected' : ''; ?>>Active</option>
                <option value="0" <?php echo (isset($_GET['status']) && $_GET['status'] == '0') ? 'selected' : ''; ?>>Inactive</option>
                <option value="" <?php echo (isset($_GET['status']) && $_GET['status'] === '') ? 'selected' : ''; ?>>All</option>
            </select>
        </div>
        <div class="md:col-span-4 flex justify-between items-center">
            <button type="submit" class="bg-gold-400 text-white px-4 py-2 rounded hover:bg-gold-500 btn">Apply Filters</button>
            <div class="text-sm text-gray-500">
                Showing <?php echo $totalCourses; ?> total courses
            </div>
        </div>
    </form>
</div>

<!-- Courses List -->
<div class="bg-white p-6 rounded-lg shadow-md card overflow-x-auto mb-6">
    <div class="flex justify-between items-center mb-4">
        <h3 class="text-xl font-semibold text-gray-600">Courses</h3>
        <div class="text-sm text-gray-500">
            Showing <?php echo $startIndex + 1; ?>-<?php echo min($startIndex + $perPage, $totalCourses); ?> of <?php echo $totalCourses; ?> courses
        </div>
    </div>

    <?php if (empty($paginatedCourses)): ?>
        <p class="text-gray-600 text-lg">No courses found matching your criteria.</p>
    <?php else: ?>
        <div class="overflow-x-auto">
            <table class="min-w-full divide-y divide-gray-200">
                <thead class="bg-gray-50">
                    <tr>
                        <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Code</th>
                        <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Course Name</th>
                        <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Department</th>
                        <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Units</th>
                        <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Hours</th>
                        <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Status</th>
                    </tr>
                </thead>
                <tbody class="bg-white divide-y divide-gray-200">
                    <?php foreach ($paginatedCourses as $course): ?>
                        <tr class="hover:bg-gray-50 transition-all duration-200 slide-in-right">
                            <td class="px-6 py-4 whitespace-nowrap text-sm font-medium text-gray-600">
                                <?php echo htmlspecialchars($course['course_code']); ?>
                            </td>
                            <td class="px-6 py-4 whitespace-nowrap text-sm text-gray-600">
                                <?php echo htmlspecialchars($course['course_name']); ?>
                            </td>
                            <td class="px-6 py-4 whitespace-nowrap text-sm text-gray-600">
                                <?php echo htmlspecialchars($course['department_name']); ?>
                            </td>
                            <td class="px-6 py-4 whitespace-nowrap text-sm text-gray-600">
                                <?php echo htmlspecialchars($course['units']); ?>
                                (<?php echo ($course['lecture_hours'] + $course['lab_hours']); ?> hrs)
                            </td>
                            <td class="px-6 py-4 whitespace-nowrap text-sm text-gray-600">
                                L: <?php echo $course['lecture_hours']; ?>h
                                <br>P: <?php echo $course['lab_hours']; ?>h
                            </td>
                            <td class="px-6 py-4 whitespace-nowrap text-sm">
                                <span class="px-2 inline-flex text-xs leading-5 font-semibold rounded-full 
                                    <?php echo $course['is_active'] ? 'bg-green-100 text-green-800' : 'bg-red-100 text-red-800'; ?>">
                                    <?php echo $course['is_active'] ? 'Active' : 'Inactive'; ?>
                                </span>
                            </td>
                        </tr>
                    <?php endforeach; ?>
                </tbody>
            </table>
        </div>
    <?php endif; ?>
</div>

<!-- Pagination -->
<?php if ($totalPages > 1): ?>
    <div class="flex items-center justify-between border-t border-gray-200 bg-white px-4 py-3 sm:px-6 rounded-lg shadow-md">
        <div class="flex flex-1 justify-between sm:hidden">
            <a href="?<?php echo http_build_query(array_merge($_GET, ['page' => max(1, $currentPage - 1)])); ?>" class="relative inline-flex items-center rounded-md border border-gray-300 bg-white px-4 py-2 text-sm font-medium text-gray-700 hover:bg-gray-50">Previous</a>
            <a href="?<?php echo http_build_query(array_merge($_GET, ['page' => min($totalPages, $currentPage + 1)])); ?>" class="relative ml-3 inline-flex items-center rounded-md border border-gray-300 bg-white px-4 py-2 text-sm font-medium text-gray-700 hover:bg-gray-50">Next</a>
        </div>
        <div class="hidden sm:flex sm:flex-1 sm:items-center sm:justify-between">
            <div>
                <p class="text-sm text-gray-700">
                    Showing <span class="font-medium"><?php echo $startIndex + 1; ?></span> to <span class="font-medium"><?php echo min($startIndex + $perPage, $totalCourses); ?></span> of <span class="font-medium"><?php echo $totalCourses; ?></span> results
                </p>
            </div>
            <div>
                <nav class="isolate inline-flex -space-x-px rounded-md shadow-sm" aria-label="Pagination">
                    <a href="?<?php echo http_build_query(array_merge($_GET, ['page' => max(1, $currentPage - 1)])); ?>" class="relative inline-flex items-center rounded-l-md px-2 py-2 text-gray-400 ring-1 ring-inset ring-gray-300 hover:bg-gray-50 focus:z-20 focus:outline-offset-0">
                        <span class="sr-only">Previous</span>
                        <svg class="h-5 w-5" viewBox="0 0 20 20" fill="currentColor" aria-hidden="true">
                            <path fill-rule="evenodd" d="M12.79 5.23a.75.75 0 01-.02 1.06L8.832 10l3.938 3.71a.75.75 0 11-1.04 1.08l-4.5-4.25a.75.75 0 010-1.08l4.5-4.25a.75.75 0 011.06.02z" clip-rule="evenodd" />
                        </svg>
                    </a>

                    <?php for ($i = 1; $i <= $totalPages; $i++): ?>
                        <?php if ($i == 1 || $i == $totalPages || ($i >= $currentPage - 2 && $i <= $currentPage + 2)): ?>
                            <a href="?<?php echo http_build_query(array_merge($_GET, ['page' => $i])); ?>" class="<?php echo ($i == $currentPage) ? 'relative z-10 inline-flex items-center bg-gold-400 text-white px-4 py-2 text-sm font-semibold focus:z-20 focus-visible:outline focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-gold-400' : 'relative inline-flex items-center px-4 py-2 text-sm font-semibold text-gray-900 ring-1 ring-inset ring-gray-300 hover:bg-gray-50 focus:z-20 focus:outline-offset-0'; ?>">
                                <?php echo $i; ?>
                            </a>
                        <?php elseif (($i == $currentPage - 3 && $currentPage > 4) || ($i == $currentPage + 3 && $currentPage < $totalPages - 3)): ?>
                            <span class="relative inline-flex items-center px-4 py-2 text-sm font-semibold text-gray-700 ring-1 ring-inset ring-gray-300 focus:outline-offset-0">...</span>
                        <?php endif; ?>
                    <?php endfor; ?>

                    <a href="?<?php echo http_build_query(array_merge($_GET, ['page' => min($totalPages, $currentPage + 1)])); ?>" class="relative inline-flex items-center rounded-r-md px-2 py-2 text-gray-400 ring-1 ring-inset ring-gray-300 hover:bg-gray-50 focus:z-20 focus:outline-offset-0">
                        <span class="sr-only">Next</span>
                        <svg class="h-5 w-5" viewBox="0 0 20 20" fill="currentColor" aria-hidden="true">
                            <path fill-rule="evenodd" d="M7.21 14.77a.75.75 0 01.02-1.06L11.168 10 7.23 6.29a.75.75 0 111.04-1.08l4.5 4.25a.75.75 0 010 1.08l-4.5 4.25a.75.75 0 01-1.06-.02z" clip-rule="evenodd" />
                        </svg>
                    </a>
                </nav>
            </div>
        </div>
    </div>
<?php endif; ?>

<script>
    document.addEventListener('DOMContentLoaded', function() {
        // Reset page to 1 when filters change
        const filterForm = document.getElementById('filterForm');
        const filterInputs = filterForm.querySelectorAll('select, input');

        filterInputs.forEach(input => {
            input.addEventListener('change', function() {
                filterForm.querySelector('input[name="page"]').value = 1;
            });
        });
    });
</script>

<?php
$content = ob_get_clean();
require_once __DIR__ . '/layout.php';
?>