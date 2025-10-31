<?php
ob_start();

// Fetch departments for the add curriculum form (scoped to Dean's college)
$collegeId = $controller->getDeanCollegeId($_SESSION['user_id']);
$query = "SELECT department_id, department_name FROM departments WHERE college_id = :college_id ORDER BY department_name";
$stmt = $controller->db->prepare($query); // Changed to $controller->db
$stmt->execute([':college_id' => $collegeId]);
$departments = $stmt->fetchAll(PDO::FETCH_ASSOC);

// Check for success/error messages from DeanController
$success = isset($_GET['success']) ? htmlspecialchars($_GET['success']) : null;
$error = isset($_GET['error']) ? htmlspecialchars($_GET['error']) : null;
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

<h2 class="text-3xl font-bold text-gray-600 mb-6 slide-in-left">Curriculum Management</h2>

<!-- Add Curriculum Form -->
<div class="bg-white p-6 rounded-lg shadow-md card mb-8">
    <h3 class="text-xl font-semibold text-gray-600 mb-4">Add New Curriculum</h3>
    <form action="/dean/curriculum" method="POST" class="grid grid-cols-1 md:grid-cols-2 gap-4">
        <div>
            <label for="curriculum_name" class="block text-sm font-medium text-gray-600">Curriculum Name</label>
            <input type="text" id="curriculum_name" name="curriculum_name" required class="mt-1 block w-full rounded-md border-gray-300 shadow-sm focus:border-gold-400 focus:ring focus:ring-gold-400 focus:ring-opacity-50" placeholder="e.g., BSIT 2023">
        </div>
        <div>
            <label for="department_id" class="block text-sm font-medium text-gray-600">Department</label>
            <select id="department_id" name="department_id" required class="mt-1 block w-full rounded-md border-gray-300 shadow-sm focus:border-gold-400 focus:ring focus:ring-gold-400 focus:ring-opacity-50">
                <option value="">Select Department</option>
                <?php foreach ($departments as $dept): ?>
                    <option value="<?php echo $dept['department_id']; ?>"><?php echo htmlspecialchars($dept['department_name']); ?></option>
                <?php endforeach; ?>
            </select>
        </div>
        <div>
            <label for="effective_year" class="block text-sm font-medium text-gray-600">Effective Year</label>
            <input type="number" id="effective_year" name="effective_year" required min="2000" max="<?php echo date('Y') + 5; ?>" class="mt-1 block w-full rounded-md border-gray-300 shadow-sm focus:border-gold-400 focus:ring focus:ring-gold-400 focus:ring-opacity-50" placeholder="e.g., 2023">
        </div>
        <div class="md:col-span-2">
            <button type="submit" name="add_curriculum" class="bg-gold-400 text-white px-4 py-2 rounded hover:bg-gold-500 btn">Add Curriculum</button>
        </div>
    </form>
</div>

<!-- Curricula List -->
<div class="bg-white p-6 rounded-lg shadow-md card overflow-x-auto">
    <h3 class="text-xl font-semibold text-gray-600 mb-4">Curricula</h3>
    <?php if (empty($curricula)): ?>
        <p class="text-gray-600 text-lg">No curricula found for your college.</p>
    <?php else: ?>
        <table class="min-w-full divide-y divide-gray-200">
            <thead class="bg-gray-50">
                <tr>
                    <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Curriculum Name</th>
                    <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Department</th>
                    <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Effective Year</th>
                    <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Status</th>
                </tr>
            </thead>
            <tbody class="bg-white divide-y divide-gray-200">
                <?php foreach ($curricula as $curriculum): ?>
                    <tr class="hover:bg-gray-50 transition-all duration-200 slide-in-right">
                        <td class="px-6 py-4 whitespace-nowrap text-sm text-gray-600"><?php echo htmlspecialchars($curriculum['curriculum_name']); ?></td>
                        <td class="px-6 py-4 whitespace-nowrap text-sm text-gray-600"><?php echo htmlspecialchars($curriculum['department_name']); ?></td>
                        <td class="px-6 py-4 whitespace-nowrap text-sm text-gray-600"><?php echo htmlspecialchars($curriculum['effective_year']); ?></td>
                        <td class="px-6 py-4 whitespace-nowrap text-sm text-gray-600"><?php echo htmlspecialchars($curriculum['status']); ?></td>
                    </tr>
                <?php endforeach; ?>
            </tbody>
        </table>
    <?php endif; ?>
</div>

<!-- Pending Curriculum Approvals -->
<div class="bg-white p-6 rounded-lg shadow-md card mt-8 overflow-x-auto">
    <h3 class="text-xl font-semibold text-gray-600 mb-4">Pending Curriculum Approvals</h3>
    <?php
    $query = "
        SELECT ca.approval_id, ca.curriculum_id, c.curriculum_name, d.department_name, ca.status, ca.comments
        FROM curriculum_approvals ca
        JOIN curricula c ON ca.curriculum_id = c.curriculum_id
        JOIN departments d ON c.department_id = d.department_id
        WHERE d.college_id = :college_id AND ca.status = 'Pending' AND ca.approval_level = 2
        ORDER BY ca.created_at";
    $stmt = $controller->db->prepare($query);
    $stmt->execute([':college_id' => $collegeId]);
    $approvals = $stmt->fetchAll(PDO::FETCH_ASSOC);
    ?>
    <?php if (empty($approvals)): ?>
        <p class="text-gray-600 text-lg">No pending curriculum approvals.</p>
    <?php else: ?>
        <table class="min-w-full divide-y divide-gray-200">
            <thead class="bg-gray-50">
                <tr>
                    <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Curriculum</th>
                    <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Department</th>
                    <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Status</th>
                    <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Actions</th>
                </tr>
            </thead>
            <tbody class="bg-white divide-y divide-gray-200">
                <?php foreach ($approvals as $approval): ?>
                    <tr class="hover:bg-gray-50 transition-all duration-200 slide-in-right">
                        <td class="px-6 py-4 whitespace-nowrap text-sm text-gray-600"><?php echo htmlspecialchars($approval['curriculum_name']); ?></td>
                        <td class="px-6 py-4 whitespace-nowrap text-sm text-gray-600"><?php echo htmlspecialchars($approval['department_name']); ?></td>
                        <td class="px-6 py-4 whitespace-nowrap text-sm text-gray-600"><?php echo htmlspecialchars($approval['status']); ?></td>
                        <td class="px-6 py-4 whitespace-nowrap text-sm">
                            <form action="/dean/curriculum" method="POST" class="inline">
                                <input type="hidden" name="approval_id" value="<?php echo $approval['approval_id']; ?>">
                                <input type="hidden" name="status" value="Approved">
                                <button type="submit" class="bg-green-500 text-white px-3 py-1 rounded hover:bg-green-600 btn">Approve</button>
                            </form>
                            <form action="/dean/curriculum" method="POST" class="inline ml-2">
                                <input type="hidden" name="approval_id" value="<?php echo $approval['approval_id']; ?>">
                                <input type="hidden" name="status" value="Rejected">
                                <textarea name="comments" class="mt-1 block w-48 rounded-md border-gray-300 shadow-sm focus:border-gold-400 focus:ring focus:ring-gold-400 focus:ring-opacity-50" placeholder="Rejection reason"></textarea>
                                <button type="submit" class="mt-2 bg-red-500 text-white px-3 py-1 rounded hover:bg-red-600 btn">Reject</button>
                            </form>
                        </td>
                    </tr>
                <?php endforeach; ?>
            </tbody>
        </table>
    <?php endif; ?>
</div>

<?php
$content = ob_get_clean();
require_once __DIR__ . '/layout.php';
?>