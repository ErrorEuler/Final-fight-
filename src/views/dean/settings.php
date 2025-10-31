<?php
ob_start();

// Fetch current college details
$collegeId = $controller->getDeanCollegeId($_SESSION['user_id']);
$query = "SELECT college_name, logo_path FROM colleges WHERE college_id = :college_id";
$stmt = $controller->db->prepare($query);
$stmt->execute([':college_id' => $collegeId]);
$college = $stmt->fetch(PDO::FETCH_ASSOC) ?: ['college_name' => '', 'logo_path' => null];

// Initialize departments and programs if not set
$departments = $departments ?? [];
$programs = $programs ?? [];

// Check for success/error messages
$success = isset($success) ? htmlspecialchars($success, ENT_QUOTES, 'UTF-8') : null;
$error = isset($error) ? htmlspecialchars($error, ENT_QUOTES, 'UTF-8') : null;
?>

<div class="min-h-screen bg-gray-50 py-8">
    <!-- Toast Container -->
    <div id="toast-container" class="fixed top-4 right-4 z-50 space-y-2"></div>

    <div class="container mx-auto px-4 max-w-7xl">
        <!-- Page Header -->
        <div class="mb-8">
            <h1 class="text-3xl font-bold text-gray-900">Settings</h1>
            <p class="text-gray-600 mt-2">Manage your college settings, departments, and account preferences</p>
        </div>

        <!-- Success/Error Alerts -->
        <?php if ($success): ?>
            <div class="bg-green-50 border-l-4 border-green-500 p-4 rounded-lg shadow-sm mb-6">
                <div class="flex items-center">
                    <i class="fas fa-check-circle text-green-500 mr-3"></i>
                    <p class="text-green-700"><?php echo $success; ?></p>
                </div>
            </div>
        <?php endif; ?>

        <?php if ($error): ?>
            <div class="bg-red-50 border-l-4 border-red-500 p-4 rounded-lg shadow-sm mb-6">
                <div class="flex items-center">
                    <i class="fas fa-exclamation-circle text-red-500 mr-3"></i>
                    <p class="text-red-700"><?php echo $error; ?></p>
                </div>
            </div>
        <?php endif; ?>

        <div class="grid grid-cols-1 lg:grid-cols-3 gap-8">
            <!-- Left Sidebar - Navigation -->
            <div class="lg:col-span-1">
                <div class="bg-white rounded-xl shadow-sm border border-gray-200 p-6 sticky top-8">
                    <h3 class="text-lg font-semibold text-gray-900 mb-4">Settings Menu</h3>
                    <nav class="space-y-2" id="settings-nav">
                        <button class="settings-nav-btn active w-full text-left px-4 py-3 rounded-lg transition-colors bg-yellow-50 text-yellow-700 border border-yellow-200"
                            data-section="college">
                            <i class="fas fa-university mr-3"></i>
                            College Settings
                        </button>
                        <button class="settings-nav-btn w-full text-left px-4 py-3 rounded-lg transition-colors text-gray-600 hover:bg-gray-50 hover:text-gray-900"
                            data-section="password">
                            <i class="fas fa-lock mr-3"></i>
                            Change Password
                        </button>
                    </nav>
                </div>
            </div>

            <!-- Right Content Area -->
            <div class="lg:col-span-2 space-y-8">
                <!-- College Settings Section -->
                <section id="college-section" class="settings-section active">
                    <div class="bg-white rounded-xl shadow-sm border border-gray-200 p-6">
                        <div class="border-b border-gray-200 pb-4 mb-6">
                            <h2 class="text-2xl font-bold text-gray-900">College Settings</h2>
                            <p class="text-gray-600 mt-2">Manage your college information and branding</p>
                        </div>

                        <form action="/dean/settings" method="POST" enctype="multipart/form-data" id="settingsForm">
                            <input type="hidden" name="csrf_token" value="<?php echo htmlspecialchars($_SESSION['csrf_token'], ENT_QUOTES, 'UTF-8'); ?>">

                            <div class="space-y-6">
                                <!-- College Name -->
                                <div>
                                    <label for="college_name" class="block text-sm font-semibold text-gray-700 mb-2">
                                        <i class="fas fa-tag mr-2 text-yellow-600"></i>
                                        College Name <span class="text-red-500">*</span>
                                    </label>
                                    <input type="text"
                                        id="college_name"
                                        name="college_name"
                                        value="<?php echo htmlspecialchars($college['college_name']); ?>"
                                        required
                                        maxlength="100"
                                        class="w-full px-4 py-3 border border-gray-300 rounded-lg focus:ring-2 focus:ring-yellow-500 focus:border-yellow-500 transition-colors">
                                </div>

                                <!-- College Logo -->
                                <div>
                                    <label for="college_logo" class="block text-sm font-semibold text-gray-700 mb-2">
                                        <i class="fas fa-image mr-2 text-yellow-600"></i>
                                        College Logo
                                    </label>
                                    <input type="file"
                                        id="college_logo"
                                        name="college_logo"
                                        accept="image/png,image/jpeg,image/gif"
                                        class="w-full px-4 py-3 border border-gray-300 rounded-lg focus:ring-2 focus:ring-yellow-500 focus:border-yellow-500 transition-colors"
                                        onchange="previewImage(event)">
                                    <p class="mt-2 text-xs text-gray-500">
                                        <i class="fas fa-info-circle mr-1"></i>
                                        Accepted formats: PNG, JPEG, GIF. Maximum file size: 2MB
                                    </p>

                                    <!-- Image Preview -->
                                    <div id="imagePreview" class="mt-4 hidden">
                                        <h4 class="text-sm font-semibold text-gray-700 mb-3">Logo Preview</h4>
                                        <div class="bg-gray-50 border-2 border-dashed border-yellow-300 rounded-lg p-6 text-center">
                                            <img id="previewImage"
                                                src=""
                                                alt="Logo Preview"
                                                class="max-h-32 w-auto object-contain mx-auto rounded-lg">
                                        </div>
                                    </div>
                                </div>

                                <!-- Current Logo Display -->
                                <?php if ($college['logo_path']): ?>
                                    <div class="pt-4 border-t border-gray-200">
                                        <h4 class="text-sm font-semibold text-gray-700 mb-3">Current Logo</h4>
                                        <div class="bg-gray-50 border border-gray-200 rounded-lg p-6 text-center">
                                            <img src="<?php echo htmlspecialchars($college['logo_path'], ENT_QUOTES, 'UTF-8'); ?>"
                                                alt="College Logo"
                                                class="max-h-32 w-auto object-contain mx-auto rounded-lg">
                                        </div>
                                    </div>
                                <?php endif; ?>

                                <!-- Submit Button -->
                                <div class="flex justify-end pt-4">
                                    <button type="submit" name="update_settings"
                                        class="bg-yellow-600 hover:bg-yellow-700 text-white px-6 py-3 rounded-lg font-semibold transition-colors flex items-center">
                                        <i class="fas fa-save mr-2"></i>
                                        Update Settings
                                    </button>
                                </div>
                            </div>
                        </form>
                    </div>
                </section>

                <!-- Change Password Section -->
                <section id="password-section" class="settings-section hidden">
                    <div class="bg-white rounded-xl shadow-sm border border-gray-200 p-6">
                        <div class="border-b border-gray-200 pb-4 mb-6">
                            <h2 class="text-2xl font-bold text-gray-900">Change Password</h2>
                            <p class="text-gray-600 mt-2">Update your account password for enhanced security</p>
                        </div>

                        <form action="/dean/settings" method="POST" id="passwordForm">
                            <input type="hidden" name="csrf_token" value="<?php echo htmlspecialchars($_SESSION['csrf_token'], ENT_QUOTES, 'UTF-8'); ?>">

                            <div class="space-y-6">
                                <!-- Current Password -->
                                <div>
                                    <label for="current_password" class="block text-sm font-semibold text-gray-700 mb-2">
                                        <i class="fas fa-lock mr-2 text-yellow-600"></i>
                                        Current Password <span class="text-red-500">*</span>
                                    </label>
                                    <input type="password"
                                        id="current_password"
                                        name="current_password"
                                        required
                                        class="w-full px-4 py-3 border border-gray-300 rounded-lg focus:ring-2 focus:ring-yellow-500 focus:border-yellow-500 transition-colors"
                                        placeholder="Enter your current password">
                                </div>

                                <!-- New Password -->
                                <div>
                                    <label for="new_password" class="block text-sm font-semibold text-gray-700 mb-2">
                                        <i class="fas fa-key mr-2 text-yellow-600"></i>
                                        New Password <span class="text-red-500">*</span>
                                    </label>
                                    <input type="password"
                                        id="new_password"
                                        name="new_password"
                                        required
                                        minlength="8"
                                        class="w-full px-4 py-3 border border-gray-300 rounded-lg focus:ring-2 focus:ring-yellow-500 focus:border-yellow-500 transition-colors"
                                        placeholder="Enter new password (min. 8 characters)">
                                    <div class="mt-2 space-y-1">
                                        <div class="flex items-center text-xs text-gray-500">
                                            <i class="fas fa-info-circle mr-2"></i>
                                            Password must be at least 8 characters long
                                        </div>
                                    </div>
                                </div>

                                <!-- Confirm New Password -->
                                <div>
                                    <label for="confirm_password" class="block text-sm font-semibold text-gray-700 mb-2">
                                        <i class="fas fa-check-circle mr-2 text-yellow-600"></i>
                                        Confirm New Password <span class="text-red-500">*</span>
                                    </label>
                                    <input type="password"
                                        id="confirm_password"
                                        name="confirm_password"
                                        required
                                        class="w-full px-4 py-3 border border-gray-300 rounded-lg focus:ring-2 focus:ring-yellow-500 focus:border-yellow-500 transition-colors"
                                        placeholder="Confirm your new password">
                                    <div id="password-match" class="mt-2 text-xs hidden">
                                        <i class="fas fa-check mr-1"></i>
                                        <span>Passwords match</span>
                                    </div>
                                </div>

                                <!-- Password Strength Indicator -->
                                <div class="bg-gray-50 rounded-lg p-4">
                                    <h4 class="text-sm font-semibold text-gray-700 mb-2">Password Requirements</h4>
                                    <ul class="text-xs text-gray-600 space-y-1">
                                        <li class="flex items-center">
                                            <i class="fas fa-check text-green-500 mr-2"></i>
                                            At least 8 characters long
                                        </li>
                                        <li class="flex items-center">
                                            <i class="fas fa-check text-green-500 mr-2"></i>
                                            Include uppercase and lowercase letters
                                        </li>
                                        <li class="flex items-center">
                                            <i class="fas fa-check text-green-500 mr-2"></i>
                                            Include numbers and special characters
                                        </li>
                                    </ul>
                                </div>

                                <!-- Submit Button -->
                                <div class="flex justify-end pt-4">
                                    <button type="submit" name="change_password"
                                        class="bg-yellow-600 hover:bg-yellow-700 text-white px-6 py-3 rounded-lg font-semibold transition-colors flex items-center">
                                        <i class="fas fa-key mr-2"></i>
                                        Change Password
                                    </button>
                                </div>
                            </div>
                        </form>
                    </div>
                </section>
            </div>
        </div>
    </div>
</div>

<script>
    document.addEventListener('DOMContentLoaded', function() {
        // Show toast notifications
        const successMsg = document.querySelector('[data-success]')?.dataset.success;
        const errorMsg = document.querySelector('[data-error]')?.dataset.error;

        if (successMsg) showToast(successMsg, 'success');
        if (errorMsg) showToast(errorMsg, 'error');

        // Initialize everything
        initializeSettingsNavigation();
        initializeEventListeners();
        initializePasswordValidation();

        console.log('Initialization complete');
    });

    // ==================== SETTINGS NAVIGATION ====================
    function initializeSettingsNavigation() {
        const navButtons = document.querySelectorAll('.settings-nav-btn');

        navButtons.forEach(button => {
            button.addEventListener('click', function(e) {
                e.preventDefault();
                e.stopPropagation();

                const sectionName = this.getAttribute('data-section');
                console.log('Button clicked, switching to:', sectionName);

                if (sectionName) {
                    showSection(sectionName);
                }
            });
        });

        // Show college section by default
        showSection('college');
    }

    function showSection(sectionName) {
        // Hide all sections
        const allSections = document.querySelectorAll('.settings-section');
        allSections.forEach(section => {
            section.classList.add('hidden');
            section.classList.remove('active');
        });

        // Reset all buttons
        const allButtons = document.querySelectorAll('.settings-nav-btn');
        allButtons.forEach(btn => {
            btn.classList.remove('active', 'bg-yellow-50', 'text-yellow-700', 'border-yellow-200', 'border');
            btn.classList.add('text-gray-600', 'hover:bg-gray-50', 'hover:text-gray-900');
        });

        // Show target section
        const targetSection = document.getElementById(sectionName + '-section');
        if (targetSection) {
            targetSection.classList.remove('hidden');
            targetSection.classList.add('active');
        } else {
            console.error('Section not found:', sectionName);
        }

        // Activate button
        const activeBtn = document.querySelector(`.settings-nav-btn[data-section="${sectionName}"]`);
        if (activeBtn) {
            activeBtn.classList.add('active', 'bg-yellow-50', 'text-yellow-700', 'border-yellow-200', 'border');
            activeBtn.classList.remove('text-gray-600', 'hover:bg-gray-50', 'hover:text-gray-900');
        }
    }

    // ==================== PASSWORD VALIDATION ====================
    function initializePasswordValidation() {
        const newPassword = document.getElementById('new_password');
        const confirmPassword = document.getElementById('confirm_password');
        const passwordMatch = document.getElementById('password-match');

        if (newPassword && confirmPassword && passwordMatch) {
            const validatePasswords = () => {
                if (newPassword.value && confirmPassword.value) {
                    if (newPassword.value === confirmPassword.value) {
                        passwordMatch.className = 'mt-2 text-xs text-green-600 flex items-center';
                        passwordMatch.innerHTML = '<i class="fas fa-check mr-1"></i><span>Passwords match</span>';
                        passwordMatch.classList.remove('hidden');
                    } else {
                        passwordMatch.className = 'mt-2 text-xs text-red-600 flex items-center';
                        passwordMatch.innerHTML = '<i class="fas fa-times mr-1"></i><span>Passwords do not match</span>';
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

    // ==================== TOAST NOTIFICATIONS ====================
    function showToast(message, type) {
        const container = document.getElementById('toast-container');
        if (!container) return;

        const toast = document.createElement('div');
        const bgColor = type === 'success' ? 'bg-green-500' : 'bg-red-500';
        const icon = type === 'success' ? 'fa-check-circle' : 'fa-exclamation-circle';

        toast.className = `${bgColor} text-white px-6 py-3 rounded-lg shadow-lg flex items-center justify-between min-w-80 transform transition-transform duration-300 translate-x-full`;
        toast.innerHTML = `
        <div class="flex items-center">
            <i class="fas ${icon} mr-3"></i>
            <span>${message}</span>
        </div>
        <button onclick="this.parentElement.remove()" class="ml-4 text-white hover:text-gray-200">
            <i class="fas fa-times"></i>
        </button>
    `;

        container.appendChild(toast);
        setTimeout(() => toast.classList.remove('translate-x-full'), 100);
        setTimeout(() => {
            toast.classList.add('translate-x-full');
            setTimeout(() => toast.remove(), 300);
        }, 5000);
    }

    // ==================== MODAL MANAGEMENT ====================
    function openModal(modalId) {
        const modal = document.getElementById(modalId);
        if (modal) {
            modal.classList.remove('hidden');
            setTimeout(() => modal.classList.add('active'), 10);
            document.body.style.overflow = 'hidden';
        }
    }

    function closeModal(modalId) {
        const modal = document.getElementById(modalId);
        if (modal) {
            modal.classList.remove('active');
            setTimeout(() => {
                modal.classList.add('hidden');
                document.body.style.overflow = 'auto';
            }, 300);

            const form = modal.querySelector('form');
            if (form) form.reset();
            resetProgramFields();
        }
    }

    // ==================== IMAGE PREVIEW ====================
    function previewImage(event) {
        const file = event.target.files[0];
        const previewContainer = document.getElementById('imagePreview');
        const previewImage = document.getElementById('previewImage');

        if (file && file.type.startsWith('image/')) {
            const reader = new FileReader();
            reader.onload = (e) => {
                previewImage.src = e.target.result;
                previewContainer.classList.remove('hidden');
            };
            reader.readAsDataURL(file);
        } else {
            previewContainer.classList.add('hidden');
            previewImage.src = '';
        }
    }

    // ==================== EVENT LISTENERS ====================
    function initializeEventListeners() {
        // Modal overlay clicks
        document.querySelectorAll('.modal-overlay').forEach(modal => {
            modal.addEventListener('click', (e) => {
                if (e.target === modal) closeModal(modal.id);
            });
        });

        // Escape key closes modals
        document.addEventListener('keydown', (e) => {
            if (e.key === 'Escape') {
                document.querySelectorAll('.modal-overlay.active').forEach(modal => {
                    closeModal(modal.id);
                });
            }
        });


        // File input validation
        const logoInput = document.getElementById('college_logo');
        if (logoInput) {
            logoInput.addEventListener('change', function(e) {
                const file = e.target.files[0];
                if (file) {
                    if (file.size > 2 * 1024 * 1024) {
                        showToast('File size must be less than 2MB', 'error');
                        this.value = '';
                        return;
                    }
                    const allowedTypes = ['image/png', 'image/jpeg', 'image/gif'];
                    if (!allowedTypes.includes(file.type)) {
                        showToast('Please select a valid image file', 'error');
                        this.value = '';
                    }
                }
            });
        }

        // Form validation
        document.querySelectorAll('form').forEach(form => {
            form.addEventListener('submit', function(e) {
                const requiredFields = form.querySelectorAll('input[required], select[required]');
                let isValid = true;

                requiredFields.forEach(field => {
                    if (!field.value.trim()) {
                        field.classList.add('border-red-500');
                        isValid = false;
                    } else {
                        field.classList.remove('border-red-500');
                    }
                });

                if (!isValid) {
                    e.preventDefault();
                    showToast('Please fill in all required fields', 'error');
                }
            });

            form.querySelectorAll('input, select').forEach(input => {
                input.addEventListener('input', function() {
                    this.classList.remove('border-red-500');
                });
            });
        });
    }

    // Make functions globally available
    window.openModal = openModal;
    window.closeModal = closeModal;
    window.previewImage = previewImage;
    window.showSection = showSection;
    window.showToast = showToast;
</script>

<style>
    .modal-overlay {
        position: fixed;
        top: 0;
        left: 0;
        width: 100%;
        height: 100%;
        background: rgba(0, 0, 0, 0.5);
        display: flex;
        align-items: center;
        justify-content: center;
        z-index: 1000;
        opacity: 0;
        transition: opacity 0.3s ease;
        pointer-events: none;
        /* ADD THIS */
    }

    .modal-overlay.active {
        opacity: 1;
        pointer-events: auto;
        /* ADD THIS */
    }

    .modal-overlay.hidden {
        display: none !important;
        /* ADD THIS */
        pointer-events: none !important;
        /* ADD THIS */
    }

    .modal-content {
        background: white;
        border-radius: 12px;
        box-shadow: 0 20px 25px -5px rgba(0, 0, 0, 0.1), 0 10px 10px -5px rgba(0, 0, 0, 0.04);
        transform: scale(0.95);
        transition: transform 0.3s ease;
        max-height: 90vh;
        overflow-y: auto;
    }

    .modal-overlay.active .modal-content {
        transform: scale(1);
    }

    .settings-section {
        transition: opacity 0.3s ease;
    }

    .settings-section.active {
        opacity: 1;
    }

    .fade-in {
        animation: fadeIn 0.5s ease-in-out;
    }

    @keyframes fadeIn {
        from {
            opacity: 0;
            transform: translateY(10px);
        }

        to {
            opacity: 1;
            transform: translateY(0);
        }
    }

    .slide-in-left {
        animation: slideInLeft 0.5s ease-in-out;
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
</style>

<?php
$content = ob_get_clean();
require_once __DIR__ . '/layout.php';
?>