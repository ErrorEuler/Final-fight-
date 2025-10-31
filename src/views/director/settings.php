<?php
ob_start();
?>

<!DOCTYPE html>
<html lang="en">

<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Account Settings - PRMSU Faculty</title>
    <style>
        @import url('https://fonts.googleapis.com/css2?family=Montserrat:wght@300;400;500;600;700&display=swap');

        :root {
            --gold-primary: #DA9100;
            --gold-secondary: #FCC201;
            --gold-light: #FFEEAA;
            --gold-dark: #B8860B;
        }

        body {
            font-family: 'Montserrat', sans-serif;
            background-color: #f8fafc;
        }

        .gold-gradient {
            background: linear-gradient(135deg, var(--gold-primary), var(--gold-secondary));
        }

        .gold-gradient-text {
            background: linear-gradient(135deg, var(--gold-dark), var(--gold-secondary));
            -webkit-background-clip: text;
            background-clip: text;
            color: transparent;
        }

        .btn-primary {
            background: linear-gradient(135deg, var(--gold-dark), var(--gold-primary));
            color: white;
            transition: all 0.3s ease;
        }

        .btn-primary:hover {
            filter: brightness(1.1);
            transform: translateY(-1px);
        }

        .flash-message {
            animation: slideIn 0.3s ease-out;
        }

        @keyframes slideIn {
            from {
                opacity: 0;
                transform: translateY(-10px);
            }

            to {
                opacity: 1;
                transform: translateY(0);
            }
        }

        .form-input:focus {
            border-color: var(--gold-primary);
            box-shadow: 0 0 0 3px rgba(218, 145, 0, 0.1);
        }
    </style>
</head>

<body class="min-h-screen bg-gray-50">
    <!-- Main Content -->
    <main class="container mx-auto px-6 py-8">
        <!-- Flash Messages -->
        <?php if (isset($_SESSION['flash'])): ?>
            <div class="flash-message mb-6 p-4 rounded-lg <?php echo $_SESSION['flash']['type'] === 'success' ? 'bg-green-100 text-green-800 border border-green-200' : 'bg-red-100 text-red-800 border border-red-200'; ?>">
                <div class="flex items-center justify-between">
                    <div class="flex items-center">
                        <i class="fas <?php echo $_SESSION['flash']['type'] === 'success' ? 'fa-check-circle' : 'fa-exclamation-circle'; ?> mr-2"></i>
                        <span><?php echo htmlspecialchars($_SESSION['flash']['message']); ?></span>
                    </div>
                    <button onclick="this.parentElement.parentElement.remove()" class="text-gray-500 hover:text-gray-700">
                        <i class="fas fa-times"></i>
                    </button>
                </div>
            </div>
            <?php unset($_SESSION['flash']); ?>
        <?php endif; ?>

        <div class="max-w-4xl mx-auto">
            <div class="bg-white rounded-xl shadow-lg overflow-hidden">
                <!-- Page Header -->
                <div class="gold-gradient px-6 py-4">
                    <h2 class="text-2xl font-bold text-white">
                        <i class="fas fa-cog mr-3"></i>Account Settings
                    </h2>
                    <p class="text-white opacity-90 mt-1">Manage your account preferences and security</p>
                </div>

                <div class="p-6">
                    <!-- Password Change Form -->
                    <div class="mb-8">
                        <h3 class="text-xl font-semibold gold-gradient-text mb-4">
                            <i class="fas fa-lock mr-2"></i>Change Password
                        </h3>

                        <?php if (!empty($errors)): ?>
                            <div class="mb-4 p-4 bg-red-50 border border-red-200 rounded-lg">
                                <div class="flex items-center text-red-800 mb-2">
                                    <i class="fas fa-exclamation-triangle mr-2"></i>
                                    <span class="font-semibold">Please fix the following errors:</span>
                                </div>
                                <ul class="list-disc list-inside text-red-700">
                                    <?php foreach ($errors as $error): ?>
                                        <li><?php echo htmlspecialchars($error); ?></li>
                                    <?php endforeach; ?>
                                </ul>
                            </div>
                        <?php endif; ?>

                        <form method="POST" class="space-y-6">
                            <input type="hidden" name="csrf_token" value="<?php echo htmlspecialchars($csrfToken); ?>">

                            <!-- Current Password -->
                            <div>
                                <label for="current_password" class="block text-sm font-medium text-gray-700 mb-2">
                                    <i class="fas fa-key mr-2"></i>Current Password
                                </label>
                                <div class="relative">
                                    <input
                                        type="password"
                                        id="current_password"
                                        name="current_password"
                                        required
                                        class="w-full px-4 py-3 border border-gray-300 rounded-lg form-input focus:ring-2 focus:ring-yellow-500 focus:border-yellow-500 transition"
                                        placeholder="Enter your current password">
                                    <button type="button" class="absolute right-3 top-3 text-gray-400 hover:text-gray-600 toggle-password">
                                        <i class="fas fa-eye"></i>
                                    </button>
                                </div>
                            </div>

                            <!-- New Password -->
                            <div>
                                <label for="new_password" class="block text-sm font-medium text-gray-700 mb-2">
                                    <i class="fas fa-lock mr-2"></i>New Password
                                </label>
                                <div class="relative">
                                    <input
                                        type="password"
                                        id="new_password"
                                        name="new_password"
                                        required
                                        class="w-full px-4 py-3 border border-gray-300 rounded-lg form-input focus:ring-2 focus:ring-yellow-500 focus:border-yellow-500 transition"
                                        placeholder="Enter your new password"
                                        minlength="8">
                                    <button type="button" class="absolute right-3 top-3 text-gray-400 hover:text-gray-600 toggle-password">
                                        <i class="fas fa-eye"></i>
                                    </button>
                                </div>
                                <p class="mt-1 text-sm text-gray-500">Must be at least 8 characters long</p>
                            </div>

                            <!-- Confirm Password -->
                            <div>
                                <label for="confirm_password" class="block text-sm font-medium text-gray-700 mb-2">
                                    <i class="fas fa-lock mr-2"></i>Confirm New Password
                                </label>
                                <div class="relative">
                                    <input
                                        type="password"
                                        id="confirm_password"
                                        name="confirm_password"
                                        required
                                        class="w-full px-4 py-3 border border-gray-300 rounded-lg form-input focus:ring-2 focus:ring-yellow-500 focus:border-yellow-500 transition"
                                        placeholder="Confirm your new password"
                                        minlength="8">
                                    <button type="button" class="absolute right-3 top-3 text-gray-400 hover:text-gray-600 toggle-password">
                                        <i class="fas fa-eye"></i>
                                    </button>
                                </div>
                            </div>

                            <!-- Submit Button -->
                            <div class="pt-4">
                                <button
                                    type="submit"
                                    class="btn-primary px-6 py-3 rounded-lg font-semibold shadow-md hover:shadow-lg transition">
                                    <i class="fas fa-save mr-2"></i>Update Password
                                </button>
                                <a
                                    href="/faculty/dashboard"
                                    class="ml-4 px-6 py-3 border border-gray-300 text-gray-700 rounded-lg font-semibold hover:bg-gray-50 transition">
                                    <i class="fas fa-arrow-left mr-2"></i>Back to Dashboard
                                </a>
                            </div>
                        </form>
                    </div>

                    <!-- Security Tips -->
                    <div class="bg-yellow-50 border border-yellow-200 rounded-lg p-4">
                        <h4 class="font-semibold text-yellow-800 mb-2">
                            <i class="fas fa-shield-alt mr-2"></i>Security Tips
                        </h4>
                        <ul class="text-yellow-700 text-sm space-y-1">
                            <li>• Use a strong, unique password that you don't use elsewhere</li>
                            <li>• Include a mix of uppercase, lowercase, numbers, and symbols</li>
                            <li>• Avoid using personal information in your password</li>
                            <li>• Consider using a password manager to generate and store passwords</li>
                        </ul>
                    </div>
                </div>
            </div>
        </div>
    </main>

    <!-- Footer -->
    <footer class="bg-gray-800 text-white mt-12">
        <div class="container mx-auto px-6 py-8">
            <div class="text-center">
                <p class="text-gray-400">
                    &copy; 2025 President Ramon Magsaysay State University. All rights reserved.
                </p>
                <p class="text-gray-500 text-sm mt-2">
                    Academic Schedule Management System - Faculty Portal
                </p>
            </div>
        </div>
    </footer>

    <script>
        // Toggle password visibility
        document.querySelectorAll('.toggle-password').forEach(button => {
            button.addEventListener('click', function() {
                const input = this.parentElement.querySelector('input');
                const icon = this.querySelector('i');

                if (input.type === 'password') {
                    input.type = 'text';
                    icon.classList.remove('fa-eye');
                    icon.classList.add('fa-eye-slash');
                } else {
                    input.type = 'password';
                    icon.classList.remove('fa-eye-slash');
                    icon.classList.add('fa-eye');
                }
            });
        });

        // Password strength indicator (optional enhancement)
        document.getElementById('new_password')?.addEventListener('input', function() {
            const password = this.value;
            const strengthIndicator = document.getElementById('password-strength');

            if (!strengthIndicator) return;

            let strength = 0;
            if (password.length >= 8) strength++;
            if (/[A-Z]/.test(password)) strength++;
            if (/[0-9]/.test(password)) strength++;
            if (/[^A-Za-z0-9]/.test(password)) strength++;

            const strengthText = ['Very Weak', 'Weak', 'Medium', 'Strong', 'Very Strong'][strength];
            const strengthColors = ['text-red-500', 'text-orange-500', 'text-yellow-500', 'text-green-500', 'text-green-600'];

            strengthIndicator.textContent = `Strength: ${strengthText}`;
            strengthIndicator.className = `text-sm ${strengthColors[strength]} font-semibold`;
        });

        // Form validation
        document.querySelector('form')?.addEventListener('submit', function(e) {
            const newPassword = document.getElementById('new_password').value;
            const confirmPassword = document.getElementById('confirm_password').value;

            if (newPassword !== confirmPassword) {
                e.preventDefault();
                alert('New password and confirmation do not match.');
                return;
            }

            if (newPassword.length < 8) {
                e.preventDefault();
                alert('New password must be at least 8 characters long.');
                return;
            }
        });
    </script>
</body>

</html>


<?php
$content = ob_get_clean();
require_once __DIR__ . '/layout.php';
?>