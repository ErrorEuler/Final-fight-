<?php
ob_start();
?>

<h1 class="text-3xl font-bold text-gray-800 mb-6">Manage Colleges</h1>
<!-- Create College Form -->
<div class="bg-white p-6 rounded-lg shadow-md mb-6">
    <h2 class="text-xl font-semibold text-gray-700 mb-4">Add New College</h2>
    <form action="/admin/colleges/create" method="POST" class="space-y-4">
        <div>
            <label class="block text-gray-600">College Name</label>
            <input type="text" name="college_name" required class="w-full p-2 border rounded">
        </div>
        <div>
            <label class="block text-gray-600">College Code</label>
            <input type="text" name="college_code" required class="w-full p-2 border rounded">
        </div>
        <button type="submit" class="bg-blue-600 text-white px-4 py-2 rounded hover:bg-blue-700">Create College</button>
    </form>
</div>
<!-- Colleges Table -->
<div class="bg-white p-6 rounded-lg shadow-md">
    <h2 class="text-xl font-semibold text-gray-700 mb-4">Colleges List</h2>
    <table class="w-full border-collapse">
        <thead>
            <tr class="bg-gray-200">
                <th class="p-2 text-left">Name</th>
                <th class="p-2 text-left">Code</th>
            </tr>
        </thead>
        <tbody>
            <?php foreach ($colleges as $college): ?>
                <tr class="border-t">
                    <td class="p-2"><?php echo htmlspecialchars($college['college_name'], ENT_QUOTES, 'UTF-8'); ?></td>
                    <td class="p-2"><?php echo htmlspecialchars($college['college_code'], ENT_QUOTES, 'UTF-8'); ?></td>
                </tr>
            <?php endforeach; ?>
        </tbody>
    </table>
</div>

<?php
$content = ob_get_clean();
require_once __DIR__ . '/layout.php';
?>