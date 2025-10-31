<?php
ob_start();
?>

<h1 class="text-3xl font-bold text-gray-800 mb-6">Manage Departments</h1>
<!-- Create Department Form -->
<div class="bg-white p-6 rounded-lg shadow-md mb-6">
    <h2 class="text-xl font-semibold text-gray-700 mb-4">Add New Department</h2>
    <form action="/admin/departments/create" method="POST" class="space-y-4">
        <div>
            <label class="block text-gray-600">Department Name</label>
            <input type="text" name="department_name" required class="w-full p-2 border rounded">
        </div>
        <div class="block text-gray-600">College</label>
            <select name="college_id" required class="w-full p-2 border rounded">
                <?php foreach ($colleges as $college): ?>
                    <option value="<?php echo htmlspecialchars($college['college_id'], ENT_QUOTES, 'UTF-8'); ?>">
                        <?php echo htmlspecialchars($college['college_name'], ENT_QUOTES, 'UTF-8'); ?>
                    </option>
                <?php endforeach; ?>
            </select>
        </div>
        <button type="submit" class="bg-blue-600 text-white px-4 py-2 rounded hover:bg-blue-700">Create Department</button>
    </form>
</div>
<!-- Departments Table -->
<div class="bg-white p-6 rounded shadow-md">
<h2 class="text-xl font-semibold text-gray-700 mb-4">Departments List</h2>
<p class="table w-full border-collapse">
        <thead>
            <tr class="bg-gray-200">
                <th class="p-2 text-left">Name</th>
                <th class="p-2 text-left">College</th>
            </tr>
        </thead>
        <tbody>
            <?php foreach ($departments as $department): ?>
                <tr class="border-t">
                    <td class="p-2"><?php echo htmlspecialchars($department['department_name'], ENT_QUOTES, 'UTF-8'); ?></td>
                    <td class="p-2"><?php echo htmlspecialchars($department['college_name'], ENT_QUOTES, 'UTF-8'); ?></td>
                </tr>
            <?php endforeach; ?>
        </tbody>
    </table>
</div>

<?php
$content = ob_get_clean();
require_once __DIR__ . '/layout.php';
?>