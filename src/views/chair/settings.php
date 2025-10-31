<?php
ob_start();
?>

<div class="min-h-screen bg-gradient-to-br from-gray-50 to-gray-100">
    <!-- Toast Container -->
    <div id="toast-container" class="fixed right-4 z-50 space-y-2"></div>

    <div class="container mx-auto ">
        <!-- Success/Error Messages -->
        <?php if (isset($_SESSION['flash'])): ?>
            <div class="mb-6 animate-fade-in">
                <div class="<?php echo $_SESSION['flash']['type'] === 'success' ? 'bg-green-50 border-green-200' : 'bg-red-50 border-red-200'; ?> border rounded-xl p-4 shadow-sm">
                    <div class="flex items-center">
                        <i class="fas <?php echo $_SESSION['flash']['type'] === 'success' ? 'fa-check-circle text-green-500' : 'fa-exclamation-circle text-red-500'; ?> text-lg mr-3"></i>
                        <div>
                            <p class="text-sm font-medium <?php echo $_SESSION['flash']['type'] === 'success' ? 'text-green-800' : 'text-red-800'; ?>">
                                <?php echo htmlspecialchars($_SESSION['flash']['message']); ?>
                            </p>
                        </div>
                    </div>
                </div>
            </div>
            <?php unset($_SESSION['flash']); ?>
        <?php endif; ?>

        <div class="grid grid-cols-1 lg:grid-cols-3 gap-8">
            <!-- Left Sidebar - Navigation -->
            <div class="lg:col-span-1">
                <div class="bg-white rounded-2xl shadow-sm border border-gray-200 p-6 sticky top-8">
                    <div class="text-center mb-6">
                        <div class="w-16 h-16 bg-gradient-to-br from-yellow-400 to-yellow-600 rounded-full flex items-center justify-center text-white text-xl font-bold mx-auto mb-3 shadow-lg">
                            <i class="fas fa-user-tie"></i>
                        </div>
                        <h3 class="text-lg font-semibold text-gray-900">Program Chair</h3>
                        <p class="text-sm text-gray-500 mt-1">Account Settings</p>
                    </div>

                    <nav class="space-y-2">
                        <button onclick="showSection('email')"
                            class="settings-nav-btn active w-full text-left px-4 py-3 rounded-xl transition-all duration-200 bg-yellow-50 text-yellow-700 border-2 border-yellow-200 shadow-sm">
                            <i class="fas fa-envelope mr-3 text-yellow-600"></i>
                            Email Settings
                        </button>
                        <button onclick="showSection('password')"
                            class="settings-nav-btn w-full text-left px-4 py-3 rounded-xl transition-all duration-200 text-gray-600 hover:bg-gray-50 hover:text-gray-900 border-2 border-transparent">
                            <i class="fas fa-lock mr-3 text-gray-500"></i>
                            Password Security
                        </button>
                        <button onclick="showSection('security')"
                            class="settings-nav-btn w-full text-left px-4 py-3 rounded-xl transition-all duration-200 text-gray-600 hover:bg-gray-50 hover:text-gray-900 border-2 border-transparent">
                            <i class="fas fa-shield-alt mr-3 text-gray-500"></i>
                            Security Info
                        </button>
                    </nav>
                </div>
            </div>

            <!-- Right Content Area -->
            <div class="lg:col-span-2 space-y-6">
                <!-- Email Settings Section -->
                <section id="email-section" class="settings-section active">
                    <div class="bg-white rounded-2xl shadow-sm border border-gray-200 p-8 transition-all duration-300 hover:shadow-md">
                        <div class="flex items-center mb-6">
                            <div class="w-12 h-12 bg-gradient-to-br from-blue-500 to-blue-600 rounded-xl flex items-center justify-center text-white mr-4 shadow-lg">
                                <i class="fas fa-envelope text-lg"></i>
                            </div>
                            <div>
                                <h2 class="text-2xl font-bold text-gray-900">Email Settings</h2>
                                <p class="text-gray-600 mt-1">Update your email address for account communications</p>
                            </div>
                        </div>

                        <form method="POST" action="/chair/settings" class="space-y-6">
                            <input type="hidden" name="csrf_token" value="<?php echo htmlspecialchars($csrfToken); ?>">

                            <div class="bg-blue-50 border border-blue-200 rounded-xl p-4">
                                <div class="flex items-start">
                                    <i class="fas fa-info-circle text-blue-500 mt-1 mr-3"></i>
                                    <div>
                                        <p class="text-sm text-blue-800 font-medium">Email Update Notice</p>
                                        <p class="text-sm text-blue-700 mt-1">
                                            Your email address is used for important notifications and account recovery.
                                            Please ensure it's current and accessible.
                                        </p>
                                    </div>
                                </div>
                            </div>

                            <div>
                                <label for="new_email" class="block text-sm font-semibold text-gray-700 mb-3 flex items-center">
                                    <i class="fas fa-at mr-2 text-yellow-600"></i>
                                    New Email Address <span class="text-red-500 ml-1">*</span>
                                </label>
                                <div class="relative">
                                    <input type="email"
                                        id="new_email"
                                        name="new_email"
                                        class="w-full px-4 py-4 pl-12 border border-gray-300 rounded-xl focus:ring-2 focus:ring-yellow-500 focus:border-yellow-500 transition-all duration-200 text-gray-900 placeholder-gray-400"
                                        placeholder="your.new.email@university.edu"
                                        required>
                                    <div class="absolute inset-y-0 left-0 flex items-center pl-4">
                                        <i class="fas fa-envelope text-gray-400"></i>
                                    </div>
                                </div>
                                <p class="mt-2 text-sm text-gray-500 flex items-center">
                                    <i class="fas fa-lightbulb mr-2 text-yellow-500"></i>
                                    Enter a valid email address you have access to
                                </p>
                            </div>

                            <div class="flex justify-end pt-4">
                                <button type="submit"
                                    name="update_email"
                                    class="bg-gradient-to-r from-yellow-500 to-yellow-600 hover:from-yellow-600 hover:to-yellow-700 text-white px-8 py-3 rounded-xl font-semibold transition-all duration-200 transform hover:scale-105 shadow-lg hover:shadow-xl flex items-center">
                                    <i class="fas fa-save mr-2"></i>
                                    Update Email
                                </button>
                            </div>
                        </form>
                    </div>
                </section>

                <!-- Password Security Section -->
                <section id="password-section" class="settings-section hidden">
                    <div class="bg-white rounded-2xl shadow-sm border border-gray-200 p-8 transition-all duration-300 hover:shadow-md">
                        <div class="flex items-center mb-6">
                            <div class="w-12 h-12 bg-gradient-to-br from-green-500 to-green-600 rounded-xl flex items-center justify-center text-white mr-4 shadow-lg">
                                <i class="fas fa-lock text-lg"></i>
                            </div>
                            <div>
                                <h2 class="text-2xl font-bold text-gray-900">Password Security</h2>
                                <p class="text-gray-600 mt-1">Change your password to keep your account secure</p>
                            </div>
                        </div>

                        <form method="POST" action="/chair/settings" class="space-y-6">
                            <input type="hidden" name="csrf_token" value="<?php echo htmlspecialchars($csrfToken); ?>">

                            <div class="bg-green-50 border border-green-200 rounded-xl p-4">
                                <div class="flex items-start">
                                    <i class="fas fa-shield-alt text-green-500 mt-1 mr-3"></i>
                                    <div>
                                        <p class="text-sm text-green-800 font-medium">Security Best Practices</p>
                                        <p class="text-sm text-green-700 mt-1">
                                            Use a strong, unique password with at least 8 characters including uppercase,
                                            lowercase, numbers, and special characters.
                                        </p>
                                    </div>
                                </div>
                            </div>

                            <div>
                                <label for="current_password" class="block text-sm font-semibold text-gray-700 mb-3 flex items-center">
                                    <i class="fas fa-key mr-2 text-yellow-600"></i>
                                    Current Password <span class="text-red-500 ml-1">*</span>
                                </label>
                                <div class="relative">
                                    <input type="password"
                                        id="current_password"
                                        name="current_password"
                                        class="w-full px-4 py-4 pl-12 border border-gray-300 rounded-xl focus:ring-2 focus:ring-yellow-500 focus:border-yellow-500 transition-all duration-200 text-gray-900 placeholder-gray-400"
                                        placeholder="Enter your current password"
                                        required>
                                    <div class="absolute inset-y-0 left-0 flex items-center pl-4">
                                        <i class="fas fa-lock text-gray-400"></i>
                                    </div>
                                </div>
                            </div>

                            <div>
                                <label for="new_password" class="block text-sm font-semibold text-gray-700 mb-3 flex items-center">
                                    <i class="fas fa-key mr-2 text-yellow-600"></i>
                                    New Password <span class="text-red-500 ml-1">*</span>
                                </label>
                                <div class="relative">
                                    <input type="password"
                                        id="new_password"
                                        name="new_password"
                                        class="w-full px-4 py-4 pl-12 border border-gray-300 rounded-xl focus:ring-2 focus:ring-yellow-500 focus:border-yellow-500 transition-all duration-200 text-gray-900 placeholder-gray-400"
                                        placeholder="Create a new password"
                                        minlength="8"
                                        required>
                                    <div class="absolute inset-y-0 left-0 flex items-center pl-4">
                                        <i class="fas fa-lock text-gray-400"></i>
                                    </div>
                                </div>
                                <div class="mt-2 grid grid-cols-2 gap-2 text-xs text-gray-500">
                                    <div class="flex items-center">
                                        <i class="fas fa-check-circle mr-1 text-green-500"></i>
                                        Minimum 8 characters
                                    </div>
                                    <div class="flex items-center">
                                        <i class="fas fa-check-circle mr-1 text-green-500"></i>
                                        Uppercase & lowercase
                                    </div>
                                </div>
                            </div>

                            <div>
                                <label for="confirm_password" class="block text-sm font-semibold text-gray-700 mb-3 flex items-center">
                                    <i class="fas fa-check-double mr-2 text-yellow-600"></i>
                                    Confirm New Password <span class="text-red-500 ml-1">*</span>
                                </label>
                                <div class="relative">
                                    <input type="password"
                                        id="confirm_password"
                                        name="confirm_password"
                                        class="w-full px-4 py-4 pl-12 border border-gray-300 rounded-xl focus:ring-2 focus:ring-yellow-500 focus:border-yellow-500 transition-all duration-200 text-gray-900 placeholder-gray-400"
                                        placeholder="Confirm your new password"
                                        required>
                                    <div class="absolute inset-y-0 left-0 flex items-center pl-4">
                                        <i class="fas fa-lock text-gray-400"></i>
                                    </div>
                                </div>
                                <div id="password-match" class="mt-2 text-sm hidden">
                                    <!-- Will be populated by JavaScript -->
                                </div>
                            </div>

                            <div class="flex justify-end pt-4">
                                <button type="submit"
                                    name="change_password"
                                    class="bg-gradient-to-r from-yellow-500 to-yellow-600 hover:from-yellow-600 hover:to-yellow-700 text-white px-8 py-3 rounded-xl font-semibold transition-all duration-200 transform hover:scale-105 shadow-lg hover:shadow-xl flex items-center">
                                    <i class="fas fa-key mr-2"></i>
                                    Change Password
                                </button>
                            </div>
                        </form>
                    </div>
                </section>

                <!-- Security Information Section -->
                <section id="security-section" class="settings-section hidden">
                    <div class="bg-white rounded-2xl shadow-sm border border-gray-200 p-8 transition-all duration-300 hover:shadow-md">
                        <div class="flex items-center mb-6">
                            <div class="w-12 h-12 bg-gradient-to-br from-purple-500 to-purple-600 rounded-xl flex items-center justify-center text-white mr-4 shadow-lg">
                                <i class="fas fa-shield-alt text-lg"></i>
                            </div>
                            <div>
                                <h2 class="text-2xl font-bold text-gray-900">Security Information</h2>
                                <p class="text-gray-600 mt-1">Important security details about your account</p>
                            </div>
                        </div>

                        <div class="space-y-6">
                            <div class="bg-purple-50 border border-purple-200 rounded-xl p-6">
                                <h3 class="text-lg font-semibold text-purple-900 mb-3 flex items-center">
                                    <i class="fas fa-user-shield mr-2"></i>
                                    Account Security
                                </h3>
                                <div class="space-y-3">
                                    <div class="flex items-center justify-between py-2 border-b border-purple-100">
                                        <span class="text-sm text-purple-800">Last Password Change</span>
                                        <span class="text-sm font-medium text-purple-900">Recently</span>
                                    </div>
                                    <div class="flex items-center justify-between py-2 border-b border-purple-100">
                                        <span class="text-sm text-purple-800">Two-Factor Authentication</span>
                                        <span class="text-sm font-medium text-yellow-600">Not Enabled</span>
                                    </div>
                                    <div class="flex items-center justify-between py-2">
                                        <span class="text-sm text-purple-800">Account Status</span>
                                        <span class="text-sm font-medium text-green-600">Active</span>
                                    </div>
                                </div>
                            </div>

                            <div class="bg-gray-50 border border-gray-200 rounded-xl p-6">
                                <h3 class="text-lg font-semibold text-gray-900 mb-3 flex items-center">
                                    <i class="fas fa-lightbulb mr-2 text-yellow-600"></i>
                                    Security Tips
                                </h3>
                                <ul class="space-y-2 text-sm text-gray-700">
                                    <li class="flex items-start">
                                        <i class="fas fa-check text-green-500 mr-2 mt-1"></i>
                                        Use a unique password for this account
                                    </li>
                                    <li class="flex items-start">
                                        <i class="fas fa-check text-green-500 mr-2 mt-1"></i>
                                        Change your password every 90 days
                                    </li>
                                    <li class="flex items-start">
                                        <i class="fas fa-check text-green-500 mr-2 mt-1"></i>
                                        Never share your password with anyone
                                    </li>
                                    <li class="flex items-start">
                                        <i class="fas fa-check text-green-500 mr-2 mt-1"></i>
                                        Log out from shared computers
                                    </li>
                                </ul>
                            </div>

                            <div class="text-center pt-4">
                                <button onclick="showSection('password')"
                                    class="bg-gradient-to-r from-yellow-500 to-yellow-600 hover:from-yellow-600 hover:to-yellow-700 text-white px-6 py-3 rounded-xl font-semibold transition-all duration-200 transform hover:scale-105 shadow-lg hover:shadow-xl flex items-center mx-auto">
                                    <i class="fas fa-lock mr-2"></i>
                                    Change Password Now
                                </button>
                            </div>
                        </div>
                    </div>
                </section>
            </div>
        </div>
    </div>
</div>

<script>
    document.addEventListener('DOMContentLoaded', function() {
        console.log('Program Chair Settings page loaded');

        // Initialize settings navigation
        initializeSettingsNavigation();

        // Initialize password validation
        initializePasswordValidation();

        // Show success/error messages as toasts
        showFlashMessages();
    });

    // Settings Navigation
    function initializeSettingsNavigation() {
        const navButtons = document.querySelectorAll('.settings-nav-btn');

        navButtons.forEach(button => {
            button.addEventListener('click', function() {
                const sectionName = this.textContent.toLowerCase().includes('email') ? 'email' :
                    this.textContent.toLowerCase().includes('password') ? 'password' :
                    this.textContent.toLowerCase().includes('security') ? 'security' : 'email';

                showSection(sectionName);
            });
        });

        // Ensure email section is active by default
        setTimeout(() => {
            showSection('email');
        }, 100);
    }

    function showSection(sectionName) {
        console.log('Switching to section:', sectionName);

        // Hide all sections
        document.querySelectorAll('.settings-section').forEach(section => {
            section.classList.add('hidden');
        });

        // Remove active class from all nav buttons
        document.querySelectorAll('.settings-nav-btn').forEach(btn => {
            btn.classList.remove('active', 'bg-yellow-50', 'text-yellow-700', 'border-yellow-200');
            btn.classList.add('text-gray-600', 'hover:bg-gray-50', 'hover:text-gray-900', 'border-transparent');
        });

        // Show selected section
        const targetSection = document.getElementById(sectionName + '-section');
        if (targetSection) {
            targetSection.classList.remove('hidden');
        }

        // Activate selected nav button
        const activeBtn = Array.from(document.querySelectorAll('.settings-nav-btn')).find(btn =>
            btn.textContent.toLowerCase().includes(sectionName)
        );

        if (activeBtn) {
            activeBtn.classList.add('active', 'bg-yellow-50', 'text-yellow-700', 'border-yellow-200');
            activeBtn.classList.remove('text-gray-600', 'hover:bg-gray-50', 'hover:text-gray-900', 'border-transparent');
        }
    }

    // Password Validation
    function initializePasswordValidation() {
        const newPassword = document.getElementById('new_password');
        const confirmPassword = document.getElementById('confirm_password');
        const passwordMatch = document.getElementById('password-match');

        if (newPassword && confirmPassword && passwordMatch) {
            const validatePasswords = () => {
                if (newPassword.value && confirmPassword.value) {
                    if (newPassword.value === confirmPassword.value) {
                        passwordMatch.className = 'mt-2 text-sm text-green-600 flex items-center animate-pulse';
                        passwordMatch.innerHTML = '<i class="fas fa-check-circle mr-2"></i><span>Passwords match! You\'re good to go.</span>';
                        passwordMatch.classList.remove('hidden');
                    } else {
                        passwordMatch.className = 'mt-2 text-sm text-red-600 flex items-center';
                        passwordMatch.innerHTML = '<i class="fas fa-exclamation-circle mr-2"></i><span>Passwords do not match. Please try again.</span>';
                        passwordMatch.classList.remove('hidden');
                    }
                } else {
                    passwordMatch.classList.add('hidden');
                }
            };

            confirmPassword.addEventListener('input', validatePasswords);
            newPassword.addEventListener('input', validatePasswords);
        }
    }

    // Flash Messages as Toasts
    function showFlashMessages() {
        const flashDiv = document.querySelector('.bg-green-50, .bg-red-50');
        if (flashDiv) {
            const isSuccess = flashDiv.classList.contains('bg-green-50');
            const message = flashDiv.querySelector('p').textContent;

            showToast(message, isSuccess ? 'success' : 'error');

            // Remove the original flash message after showing toast
            setTimeout(() => {
                flashDiv.remove();
            }, 100);
        }
    }

    // Toast Notification System
    function showToast(message, type) {
        const toast = document.createElement('div');
        toast.className = `bg-${type === 'success' ? 'green' : 'red'}-500 text-white px-6 py-4 rounded-xl shadow-xl flex items-center justify-between min-w-80 transform transition-all duration-300 translate-x-full`;
        toast.innerHTML = `
            <div class="flex items-center">
                <i class="fas ${type === 'success' ? 'fa-check-circle' : 'fa-exclamation-circle'} mr-3 text-lg"></i>
                <span class="font-medium">${message}</span>
            </div>
            <button onclick="this.parentElement.remove()" class="ml-4 text-white hover:text-gray-200 transition-colors">
                <i class="fas fa-times"></i>
            </button>
        `;
        document.getElementById('toast-container').appendChild(toast);

        // Animate in
        setTimeout(() => toast.classList.remove('translate-x-full'), 100);

        // Auto remove
        setTimeout(() => {
            toast.classList.add('translate-x-full');
            setTimeout(() => toast.remove(), 300);
        }, 5000);
    }

    // Form validation enhancement
    document.addEventListener('DOMContentLoaded', function() {
        const forms = document.querySelectorAll('form');
        forms.forEach(form => {
            form.addEventListener('submit', function(e) {
                const requiredFields = form.querySelectorAll('input[required]');
                let isValid = true;

                requiredFields.forEach(field => {
                    if (!field.value.trim()) {
                        field.classList.add('border-red-500', 'ring-2', 'ring-red-200');
                        isValid = false;
                    } else {
                        field.classList.remove('border-red-500', 'ring-2', 'ring-red-200');
                    }
                });

                if (!isValid) {
                    e.preventDefault();
                    showToast('Please fill in all required fields', 'error');
                }
            });

            // Remove error styling on input
            form.querySelectorAll('input').forEach(input => {
                input.addEventListener('input', function() {
                    this.classList.remove('border-red-500', 'ring-2', 'ring-red-200');
                });
            });
        });
    });
</script>

<style>
    .animate-fade-in {
        animation: fadeIn 0.5s ease-in-out;
    }

    @keyframes fadeIn {
        from {
            opacity: 0;
            transform: translateY(-10px);
        }

        to {
            opacity: 1;
            transform: translateY(0);
        }
    }

    .settings-section {
        transition: all 0.3s ease-in-out;
    }

    .settings-nav-btn {
        transition: all 0.2s ease-in-out;
    }

    .settings-nav-btn:hover {
        transform: translateX(4px);
    }

    .settings-nav-btn.active {
        box-shadow: 0 4px 12px rgba(245, 158, 11, 0.15);
    }
</style>

<?php
$content = ob_get_clean();
require_once __DIR__ . '/layout.php';
?>