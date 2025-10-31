<?php
ob_start();

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

<h2 class="text-3xl font-bold text-gray-600 mb-6 slide-in-left">Faculty Search</h2>

<!-- Search Form -->
<div class="bg-white p-6 rounded-lg shadow-md card mb-8">
    <h3 class="text-xl font-semibold text-gray-600 mb-4">Search Faculty</h3>
    <form action="/dean/search" method="POST" class="flex flex-col md:flex-row gap-4">
        <input type="text" name="search_term" required class="flex-1 rounded-md border-gray-300 shadow-sm focus:border-gold-400 focus:ring focus:ring-gold-400 focus:ring-opacity-50" placeholder="Enter name or email">
        <button type="submit" class="bg-gold-400 text-white px-4 py-2 rounded hover:bg-gold-500 btn">Search</button>
    </form>
</div>

<!-- Search Results -->
<div class="bg-white p-6 rounded-lg shadow-md card overflow-x-auto">
    <h3 class="text-xl font-semibold text-gray-600 mb-4">Search Results</h3>
    <?php if (empty($results)): ?>
        <p class="text-gray-600 text-lg">No faculty found matching your search.</p>
    <?php else: ?>
        <table class="min-w-full divide-y divide-gray-200">
            <thead class="bg-gray-50">
                <tr>
                    <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Name</th>
                    <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Email</th>
                    <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Department</th>
                    <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Academic Rank</th>
                </tr>
            </thead>
            <tbody class="bg-white divide-y divide-gray-200">
                <?php foreach ($results as $result): ?>
                    <tr class="hover:bg-gray-50 transition-all duration-200 slide-in-right">
                        <td class="px-6 py-4 whitespace-nowrap text-sm text-gray-600">
                            <?php echo htmlspecialchars($result['first_name'] . ' ' . ($result['middle_name'] ? $result['middle_name'][0] . '. ' : '') . $result['last_name'] . ($result['suffix'] ? ' ' . $result['suffix'] : '')); ?>
                        </td>
                        <td class="px-6 py-4 whitespace-nowrap text-sm text-gray-600"><?php echo htmlspecialchars($result['email']); ?></td>
                        <td class="px-6 py-4 whitespace-nowrap text-sm text-gray-600"><?php echo htmlspecialchars($result['department_name']); ?></td>
                        <td class="px-6 py-4 whitespace-nowrap text-sm text-gray-600"><?php echo htmlspecialchars($result['academic_rank']); ?></td>
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