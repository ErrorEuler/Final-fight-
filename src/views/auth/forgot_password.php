<?php require_once __DIR__ . '/../../views/layouts/header.php'; ?>
<div class="min-h-screen flex items-center justify-center bg-gray-100">
    <div class="w-full max-w-md p-6">
        <h1 class="text-2xl font-bold text-center mb-6">Forgot Password</h1>
        <?php if (isset($error)): ?><div class="mb-4 p-3 bg-red-100 text-red-800 rounded-lg"><?php echo htmlspecialchars($error); ?></div><?php endif; ?>
        <?php if (isset($success)): ?><div class="mb-4 p-3 bg-green-100 text-green-800 rounded-lg"><?php echo htmlspecialchars($success); ?></div><?php endif; ?>
        <form method="POST" action="/forgot-password" class="space-y-4">
            <div>
                <label for="employee_id" class="block text-sm font-medium text-gray-700">Employee ID</label>
                <input type="text" id="employee_id" name="employee_id" required class="mt-1 block w-full rounded-md border-gray-300 shadow-sm focus:border-yellow-500 focus:ring-yellow-500" placeholder="Enter your Employee ID">
            </div>
            <button type="submit" class="w-full bg-yellow-600 text-white py-2 px-4 rounded-md hover:bg-yellow-500">Send Reset Link</button>
        </form>
    </div>
</div>
<?php require_once __DIR__ . '/../../views/layouts/footer.php'; ?>