<?php
ob_start();
?>

<style>
    :root {
        --yellow: #D4AF37;
        --dark-gray: #4B5563;
        --white: #FFFFFF;
        --light-gray: #F8FAFC;
        --border-gray: #E2E8F0;
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
    }

    .card-hover:hover {
        transform: translateY(-2px);
        box-shadow: 0 8px 25px rgba(0, 0, 0, 0.1);
        border-color: var(--yellow);
    }

    .modal {
        display: none;
        position: fixed;
        top: 0;
        left: 0;
        width: 100%;
        height: 100%;
        background-color: rgba(0, 0, 0, 0.5);
        z-index: 1000;
        backdrop-filter: blur(4px);
    }

    .modal-content {
        position: absolute;
        top: 50%;
        left: 50%;
        transform: translate(-50%, -50%);
        background-color: white;
        padding: 2rem;
        border-radius: 12px;
        width: 90%;
        max-width: 500px;
        box-shadow: 0 20px 40px rgba(0, 0, 0, 0.15);
        animation: modalSlideIn 0.3s ease-out;
    }

    @keyframes modalSlideIn {
        from {
            transform: translate(-50%, -60%);
            opacity: 0;
        }

        to {
            transform: translate(-50%, -50%);
            opacity: 1;
        }
    }

    .toast {
        position: fixed;
        top: 24px;
        right: 24px;
        padding: 16px 20px;
        border-radius: 8px;
        box-shadow: 0 4px 12px rgba(0, 0, 0, 0.15);
        z-index: 50;
        transform: translateX(120%);
        animation: toastSlideIn 0.5s forwards, toastFadeOut 0.5s forwards 3s;
        display: flex;
        align-items: center;
        gap: 8px;
    }

    @keyframes toastSlideIn {
        to {
            transform: translateX(0);
        }
    }

    @keyframes toastFadeOut {
        to {
            opacity: 0;
            transform: translateX(120%);
        }
    }

    .toast.success {
        background-color: #f0fdf4;
        color: #166534;
        border: 1px solid #bbf7d0;
    }

    .toast.error {
        background-color: #fef2f2;
        color: #991b1b;
        border: 1px solid #fecaca;
    }

    .tab-active {
        border-bottom: 2px solid var(--yellow);
        color: var(--yellow);
        font-weight: 600;
    }

    .stat-card {
        background: linear-gradient(135deg, #fff 0%, #f8fafc 100%);
        border: 1px solid var(--border-gray);
        border-radius: 12px;
        padding: 1.5rem;
        transition: all 0.3s ease;
    }

    .stat-card:hover {
        border-color: var(--yellow);
        transform: translateY(-2px);
    }

    .action-btn {
        transition: all 0.2s ease;
    }

    .action-btn:hover {
        transform: scale(1.05);
    }

    .empty-state {
        padding: 3rem 2rem;
        text-align: center;
        color: var(--dark-gray);
        opacity: 0.7;
    }

    .empty-state svg {
        margin-bottom: 1rem;
        opacity: 0.5;
    }

    .table-container {
        background: white;
        border-radius: 12px;
        border: 1px solid var(--border-gray);
        overflow: hidden;
    }

    .table-header {
        background: var(--light-gray);
        border-bottom: 1px solid var(--border-gray);
    }

    .table-row {
        transition: background-color 0.2s ease;
        border-bottom: 1px solid var(--border-gray);
    }

    .table-row:last-child {
        border-bottom: none;
    }

    .table-row:hover {
        background-color: #f8fafc;
    }

    .input-field {
        transition: all 0.2s ease;
        border: 1px solid var(--border-gray);
    }

    .input-field:focus {
        border-color: var(--yellow);
        box-shadow: 0 0 0 3px rgba(212, 175, 55, 0.1);
    }

    .btn-primary {
        background: var(--yellow);
        transition: all 0.3s ease;
    }

    .btn-primary:hover {
        background: #b8941f;
        transform: translateY(-1px);
        box-shadow: 0 4px 12px rgba(212, 175, 55, 0.3);
    }

    .btn-secondary {
        background: white;
        border: 1px solid var(--border-gray);
        transition: all 0.3s ease;
    }

    .btn-secondary:hover {
        border-color: var(--dark-gray);
        background: var(--light-gray);
    }

    /* Add these to your existing CSS */
    @media (max-width: 768px) {
        .modal-content {
            width: 95%;
            margin: 1rem;
            padding: 1.5rem;
            max-width: none;
        }

        .table-container {
            border-radius: 8px;
            margin: 0 -1rem;
            width: calc(100% + 2rem);
        }

        .stats-grid {
            grid-template-columns: 1fr;
            gap: 1rem;
        }

        .action-bar {
            flex-direction: column;
            align-items: stretch;
            gap: 1rem;
        }

        .action-bar button {
            width: 100%;
        }

        .table-header {
            display: none;
        }

        .table-row {
            display: block;
            margin-bottom: 1rem;
            padding: 1rem;
            border: 1px solid var(--border-gray);
            border-radius: 8px;
        }

        .table-row td {
            display: block;
            padding: 0.5rem 0;
            border: none;
        }

        .table-row td:before {
            content: attr(data-label);
            font-weight: 600;
            color: var(--dark-gray);
            display: block;
            font-size: 0.875rem;
            margin-bottom: 0.25rem;
        }
    }

    @media (max-width: 640px) {
        .header-section {
            text-align: center;
        }

        .tabs-nav {
            flex-direction: column;
            gap: 0.5rem;
        }

        .tab-button {
            justify-content: center;
            border-bottom: none !important;
            border-left: 2px solid transparent;
            padding: 0.75rem 1rem;
        }

        .tab-active {
            border-left: 2px solid var(--yellow);
            border-bottom: none !important;
        }

        .modal-buttons {
            flex-direction: column;
            gap: 0.5rem;
        }

        .modal-buttons button {
            width: 100%;
        }
    }
</style>

<div class="min-h-screen bg-gray-50 py-8 px-4 sm:px-6 lg:px-8">
    <div class="max-w-7xl mx-auto">
        <!-- Header Section -->
        <div class="mb-8 fade-in">
            <div class="flex flex-col lg:flex-row lg:items-center lg:justify-between gap-4">
                <div>
                    <h1 class="text-3xl font-bold text-gray-900 mb-2">Academic Management</h1>
                    <p class="text-gray-600">Manage colleges, departments, and programs efficiently</p>
                </div>
                <div class="flex items-center gap-3 text-sm text-gray-500">
                    <div class="flex items-center gap-2">
                        <div class="w-2 h-2 bg-green-500 rounded-full"></div>
                        <span><?php echo count($colleges); ?> Colleges</span>
                    </div>
                    <div class="flex items-center gap-2">
                        <div class="w-2 h-2 bg-blue-500 rounded-full"></div>
                        <span><?php echo count($departments); ?> Departments</span>
                    </div>
                </div>
            </div>
        </div>

        <!-- Stats Cards -->
        <div class="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-4 md:gap-6 mb-6 md:mb-8 fade-in stats-grid">
            <div class="stat-card">
                <div class="flex items-center justify-between">
                    <div>
                        <p class="text-sm font-medium text-gray-600">Total Colleges</p>
                        <p class="text-2xl font-bold text-gray-900 mt-1"><?php echo count($colleges); ?></p>
                    </div>
                    <div class="p-3 bg-yellow-50 rounded-lg">
                        <svg class="w-6 h-6 text-yellow-600" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M19 21V5a2 2 0 00-2-2H7a2 2 0 00-2 2v16m14 0h2m-2 0h-5m-9 0H3m2 0h5M9 7h1m-1 4h1m4-4h1m-1 4h1m-5 10v-5a2 2 0 012-2h2a2 2 0 012 2v5m-4-6h.01" />
                        </svg>
                    </div>
                </div>
            </div>
            <div class="stat-card">
                <div class="flex items-center justify-between">
                    <div>
                        <p class="text-sm font-medium text-gray-600">Total Departments</p>
                        <p class="text-2xl font-bold text-gray-900 mt-1"><?php echo count($departments); ?></p>
                    </div>
                    <div class="p-3 bg-blue-50 rounded-lg">
                        <svg class="w-6 h-6 text-blue-600" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M19 21V5a2 2 0 00-2-2H7a2 2 0 00-2 2v16m14 0h2m-2 0h-5m-9 0H3m2 0h5M9 7h1m-1 4h1m4-4h1m-1 4h1m-5 10v-5a2 2 0 012-2h2a2 2 0 012 2v5m-4-6h.01" />
                        </svg>
                    </div>
                </div>
            </div>
            <div class="stat-card">
                <div class="flex items-center justify-between">
                    <div>
                        <p class="text-sm font-medium text-gray-600">Active Programs</p>
                        <p class="text-2xl font-bold text-gray-900 mt-1"><?php echo count(array_unique(array_column($departments, 'program_name'))); ?></p>
                    </div>
                    <div class="p-3 bg-green-50 rounded-lg">
                        <svg class="w-6 h-6 text-green-600" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 6.253v13m0-13C10.832 5.477 9.246 5 7.5 5S4.168 5.477 3 6.253v13C4.168 18.477 5.754 18 7.5 18s3.332.477 4.5 1.253m0-13C13.168 5.477 14.754 5 16.5 5c1.746 0 3.332.477 4.5 1.253v13C19.832 18.477 18.246 18 16.5 18c-1.746 0-3.332.477-4.5 1.253" />
                        </svg>
                    </div>
                </div>
            </div>
        </div>

        <!-- Toast Notifications -->
        <?php if (isset($_SESSION['success'])): ?>
            <div id="success-toast" class="toast success hidden">
                <svg class="w-5 h-5" fill="currentColor" viewBox="0 0 20 20">
                    <path fill-rule="evenodd" d="M10 18a8 8 0 100-16 8 8 0 000 16zm3.707-9.293a1 1 0 00-1.414-1.414L9 10.586 7.707 9.293a1 1 0 00-1.414 1.414l2 2a1 1 0 001.414 0l4-4z" clip-rule="evenodd" />
                </svg>
                <?php echo htmlspecialchars($_SESSION['success'], ENT_QUOTES, 'UTF-8'); ?>
            </div>
            <?php unset($_SESSION['success']); ?>
        <?php endif; ?>
        <?php if (isset($_SESSION['error'])): ?>
            <div id="error-toast" class="toast error hidden">
                <svg class="w-5 h-5" fill="currentColor" viewBox="0 0 20 20">
                    <path fill-rule="evenodd" d="M10 18a8 8 0 100-16 8 8 0 000 16zM8.707 7.293a1 1 0 00-1.414 1.414L8.586 10l-1.293 1.293a1 1 0 101.414 1.414L10 11.414l1.293 1.293a1 1 0 001.414-1.414L11.414 10l1.293-1.293a1 1 0 00-1.414-1.414L10 8.586 8.707 7.293z" clip-rule="evenodd" />
                </svg>
                <?php echo htmlspecialchars($_SESSION['error'], ENT_QUOTES, 'UTF-8'); ?>
            </div>
            <?php unset($_SESSION['error']); ?>
        <?php endif; ?>

        <!-- Tabs Navigation -->
        <div class="mb-8 fade-in">
            <div class="border-b border-gray-200">
                <nav class="-mb-px flex space-x-8">
                    <button id="college-tab" class="tab-button py-4 px-1 border-b-2 font-medium text-sm transition-colors duration-200 tab-active" data-tab="college">
                        <div class="flex items-center gap-2">
                            <svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M19 21V5a2 2 0 00-2-2H7a2 2 0 00-2 2v16m14 0h2m-2 0h-5m-9 0H3m2 0h5M9 7h1m-1 4h1m4-4h1m-1 4h1m-5 10v-5a2 2 0 012-2h2a2 2 0 012 2v5m-4-6h.01" />
                            </svg>
                            Colleges
                        </div>
                    </button>
                    <button id="department-tab" class="tab-button py-4 px-1 border-b-2 font-medium text-sm transition-colors duration-200 border-transparent text-gray-500 hover:text-gray-700 hover:border-gray-300" data-tab="department">
                        <div class="flex items-center gap-2">
                            <svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M19 21V5a2 2 0 00-2-2H7a2 2 0 00-2 2v16m14 0h2m-2 0h-5m-9 0H3m2 0h5M9 7h1m-1 4h1m4-4h1m-1 4h1m-5 10v-5a2 2 0 012-2h2a2 2 0 012 2v5m-4-6h.01" />
                            </svg>
                            Departments & Programs
                        </div>
                    </button>
                </nav>
            </div>
        </div>

        <!-- College Section -->
        <div id="college-content" class="tab-content fade-in">
            <!-- Action Bar -->
            <div class="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-4 mb-6">
                <div>
                    <h2 class="text-xl font-semibold text-gray-900">Colleges Management</h2>
                    <p class="text-gray-600 text-sm mt-1">Create and manage academic colleges</p>
                </div>
                <button id="open-college-modal" class="btn-primary text-white px-6 py-3 rounded-lg font-medium flex items-center gap-2 action-btn">
                    <svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                        <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 4v16m8-8H4" />
                    </svg>
                    Add New College
                </button>
            </div>

            <!-- Colleges Table -->
            <div class="table-container card-hover">
                <div class="overflow-x-auto">
                    <table class="w-full">
                        <thead class="table-header hidden md:table-header-group">
                            <tr>
                                <th class="px-4 md:px-6 py-3 md:py-4 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">College</th>
                                <th class="px-4 md:px-6 py-3 md:py-4 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Code</th>
                                <th class="px-4 md:px-6 py-3 md:py-4 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Actions</th>
                            </tr>
                        </thead>
                        <tbody class="bg-white divide-y divide-gray-200">
                            <?php if (empty($colleges)): ?>
                                <tr>
                                    <td colspan="3" class="empty-state">
                                        <!-- Your empty state content -->
                                    </td>
                                </tr>
                            <?php else: ?>
                                <?php foreach ($colleges as $college): ?>
                                    <tr class="table-row md:table-row">
                                        <td class="px-4 md:px-6 py-3 md:py-4 whitespace-nowrap" data-label="College">
                                            <div class="flex items-center">
                                                <div class="flex-shrink-0 h-8 w-8 md:h-10 md:w-10 bg-yellow-50 rounded-lg flex items-center justify-center">
                                                    <svg class="h-4 w-4 md:h-6 md:w-6 text-yellow-600" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                                        <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M19 21V5a2 2 0 00-2-2H7a2 2 0 00-2 2v16m14 0h2m-2 0h-5m-9 0H3m2 0h5M9 7h1m-1 4h1m4-4h1m-1 4h1m-5 10v-5a2 2 0 012-2h2a2 2 0 012 2v5m-4-6h.01" />
                                                    </svg>
                                                </div>
                                                <div class="ml-3 md:ml-4">
                                                    <div class="text-sm font-medium text-gray-900"><?php echo htmlspecialchars($college['college_name'], ENT_QUOTES, 'UTF-8'); ?></div>
                                                </div>
                                            </div>
                                        </td>
                                        <td class="px-4 md:px-6 py-3 md:py-4 whitespace-nowrap" data-label="Code">
                                            <span class="inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium bg-gray-100 text-gray-800">
                                                <?php echo htmlspecialchars($college['college_code'], ENT_QUOTES, 'UTF-8'); ?>
                                            </span>
                                        </td>
                                        <td class="px-4 md:px-6 py-3 md:py-4 whitespace-nowrap" data-label="Actions">
                                            <button class="edit-btn bg-yellow-50 text-yellow-700 px-3 py-1.5 md:px-4 md:py-2 rounded-lg hover:bg-yellow-100 transition-colors duration-200 action-btn flex items-center gap-1 md:gap-2 text-sm md:text-base"
                                                data-type="college"
                                                data-id="<?php echo htmlspecialchars($college['college_id'], ENT_QUOTES, 'UTF-8'); ?>"
                                                data-name="<?php echo htmlspecialchars($college['college_name'], ENT_QUOTES, 'UTF-8'); ?>"
                                                data-code="<?php echo htmlspecialchars($college['college_code'], ENT_QUOTES, 'UTF-8'); ?>">
                                                <svg class="w-3 h-3 md:w-4 md:h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                                    <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M11 5H6a2 2 0 00-2 2v11a2 2 0 002 2h11a2 2 0 002-2v-5m-1.414-9.414a2 2 0 112.828 2.828L11.828 15H9v-2.828l8.586-8.586z" />
                                                </svg>
                                                <span class="hidden sm:inline">Edit</span>
                                            </button>
                                        </td>
                                    </tr>
                                <?php endforeach; ?>
                            <?php endif; ?>
                        </tbody>
                    </table>
                </div>
            </div>
        </div>

        <!-- Department Section -->
        <div id="department-content" class="tab-content hidden fade-in">
            <!-- Action Bar -->
            <div class="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-4 mb-6">
                <div>
                    <h2 class="text-xl font-semibold text-gray-900">Departments & Programs</h2>
                    <p class="text-gray-600 text-sm mt-1">Manage departments and their academic programs</p>
                </div>
                <button id="open-department-modal" class="btn-primary text-white px-6 py-3 rounded-lg font-medium flex items-center gap-2 action-btn">
                    <svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                        <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 4v16m8-8H4" />
                    </svg>
                    Add New Department
                </button>
            </div>

            <!-- Departments Table -->
            <div class="table-container card-hover">
                <div class="overflow-x-auto">
                    <table class="w-full">
                        <thead class="table-header">
                            <tr>
                                <th class="px-6 py-4 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Department</th>
                                <th class="px-6 py-4 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">College</th>
                                <th class="px-6 py-4 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Program</th>
                                <th class="px-6 py-4 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Actions</th>
                            </tr>
                        </thead>
                        <tbody class="bg-white divide-y divide-gray-200">
                            <?php if (empty($departments)): ?>
                                <tr>
                                    <td colspan="4" class="empty-state">
                                        <svg class="w-12 h-12 mx-auto" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M19 21V5a2 2 0 00-2-2H7a2 2 0 00-2 2v16m14 0h2m-2 0h-5m-9 0H3m2 0h5M9 7h1m-1 4h1m4-4h1m-1 4h1m-5 10v-5a2 2 0 012-2h2a2 2 0 012 2v5m-4-6h.01" />
                                        </svg>
                                        <p class="text-lg font-medium text-gray-900 mb-2">No departments found</p>
                                        <p class="text-gray-600">Create your first department to get started</p>
                                    </td>
                                </tr>
                            <?php else: ?>
                                <?php foreach ($departments as $department): ?>
                                    <tr class="table-row">
                                        <td class="px-6 py-4 whitespace-nowrap">
                                            <div class="flex items-center">
                                                <div class="flex-shrink-0 h-10 w-10 bg-blue-50 rounded-lg flex items-center justify-center">
                                                    <svg class="h-6 w-6 text-blue-600" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                                        <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M19 21V5a2 2 0 00-2-2H7a2 2 0 00-2 2v16m14 0h2m-2 0h-5m-9 0H3m2 0h5M9 7h1m-1 4h1m4-4h1m-1 4h1m-5 10v-5a2 2 0 012-2h2a2 2 0 012 2v5m-4-6h.01" />
                                                    </svg>
                                                </div>
                                                <div class="ml-4">
                                                    <div class="text-sm font-medium text-gray-900"><?php echo htmlspecialchars($department['department_name'] ?? 'N/A', ENT_QUOTES, 'UTF-8'); ?></div>
                                                </div>
                                            </div>
                                        </td>
                                        <td class="px-6 py-4 whitespace-nowrap text-sm text-gray-900">
                                            <?php echo htmlspecialchars($department['college_name'] ?? 'Not Assigned', ENT_QUOTES, 'UTF-8'); ?>
                                        </td>
                                        <td class="px-6 py-4 whitespace-nowrap">
                                            <div>
                                                <div class="text-sm font-medium text-gray-900"><?php echo htmlspecialchars($department['program_name'] ?? 'Not Assigned', ENT_QUOTES, 'UTF-8'); ?></div>
                                                <div class="text-sm text-gray-500"><?php echo htmlspecialchars($department['program_code'] ?? 'N/A', ENT_QUOTES, 'UTF-8'); ?></div>
                                            </div>
                                        </td>
                                        <td class="px-6 py-4 whitespace-nowrap text-sm">
                                            <button class="edit-btn bg-yellow-50 text-yellow-700 px-4 py-2 rounded-lg hover:bg-yellow-100 transition-colors duration-200 action-btn flex items-center gap-2" data-type="department" data-id="<?php echo htmlspecialchars($department['department_id'] ?? '', ENT_QUOTES, 'UTF-8'); ?>" data-name="<?php echo htmlspecialchars($department['department_name'] ?? '', ENT_QUOTES, 'UTF-8'); ?>" data-college-id="<?php echo htmlspecialchars($department['college_id'] ?? '', ENT_QUOTES, 'UTF-8'); ?>" data-college-name="<?php echo htmlspecialchars($department['college_name'] ?? '', ENT_QUOTES, 'UTF-8'); ?>" data-program-name="<?php echo htmlspecialchars($department['program_name'] ?? '', ENT_QUOTES, 'UTF-8'); ?>" data-program-code="<?php echo htmlspecialchars($department['program_code'] ?? '', ENT_QUOTES, 'UTF-8'); ?>">
                                                <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                                    <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M11 5H6a2 2 0 00-2 2v11a2 2 0 002 2h11a2 2 0 002-2v-5m-1.414-9.414a2 2 0 112.828 2.828L11.828 15H9v-2.828l8.586-8.586z" />
                                                </svg>
                                                Edit
                                            </button>
                                        </td>
                                    </tr>
                                <?php endforeach; ?>
                            <?php endif; ?>
                        </tbody>
                    </table>
                </div>
            </div>
        </div>

        <!-- Modals (keep your existing modal code, just update the styling) -->
        <!-- College Modal -->
        <div id="college-modal" class="modal">
            <div class="modal-content">
                <div class="flex items-center gap-3 mb-6">
                    <div class="p-2 bg-yellow-50 rounded-lg">
                        <svg class="w-6 h-6 text-yellow-600" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M19 21V5a2 2 0 00-2-2H7a2 2 0 00-2 2v16m14 0h2m-2 0h-5m-9 0H3m2 0h5M9 7h1m-1 4h1m4-4h1m-1 4h1m-5 10v-5a2 2 0 012-2h2a2 2 0 012 2v5m-4-6h.01" />
                        </svg>
                    </div>
                    <h2 class="text-xl font-semibold text-gray-900">Add New College</h2>
                </div>
                <form action="/admin/colleges_departments/create" method="POST" class="space-y-4" novalidate>
                    <input type="hidden" name="type" value="college">
                    <div>
                        <label for="college_name" class="block text-sm font-medium text-gray-700 mb-2">College Name *</label>
                        <input type="text" id="college_name" name="college_name" required class="input-field w-full px-4 py-3 rounded-lg focus:outline-none" placeholder="e.g., College of Engineering">
                        <p class="mt-1 text-xs text-red-600 hidden" id="college_name_error">College name is required</p>
                    </div>
                    <div>
                        <label for="college_code" class="block text-sm font-medium text-gray-700 mb-2">College Code *</label>
                        <input type="text" id="college_code" name="college_code" required class="input-field w-full px-4 py-3 rounded-lg focus:outline-none" placeholder="e.g., COE">
                        <p class="mt-1 text-xs text-red-600 hidden" id="college_code_error">College code is required</p>
                    </div>
                    <!-- In your modals, update the button section -->
                    <div class="flex flex-col sm:flex-row justify-end gap-2 md:gap-3 pt-4 modal-buttons">
                        <button type="button" id="close-college-modal" class="btn-secondary px-4 py-2.5 md:px-6 md:py-3 rounded-lg font-medium order-2 sm:order-1 text-sm md:text-base">
                            Cancel
                        </button>
                        <button type="submit" class="btn-primary text-white px-4 py-2.5 md:px-6 md:py-3 rounded-lg font-medium order-1 sm:order-2 text-sm md:text-base">
                            Create College
                        </button>
                    </div>
                </form>
            </div>
        </div>

        <!-- Department Modal -->
        <div id="department-modal" class="modal">
            <div class="modal-content">
                <div class="flex items-center gap-3 mb-6">
                    <div class="p-2 bg-blue-50 rounded-lg">
                        <svg class="w-6 h-6 text-blue-600" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M19 21V5a2 2 0 00-2-2H7a2 2 0 00-2 2v16m14 0h2m-2 0h-5m-9 0H3m2 0h5M9 7h1m-1 4h1m4-4h1m-1 4h1m-5 10v-5a2 2 0 012-2h2a2 2 0 012 2v5m-4-6h.01" />
                        </svg>
                    </div>
                    <h2 class="text-xl font-semibold text-gray-900">Add New Department</h2>
                </div>
                <form action="/admin/colleges_departments/create" method="POST" class="space-y-4" novalidate>
                    <input type="hidden" name="type" value="department">
                    <div>
                        <label for="department_name" class="block text-sm font-medium text-gray-700 mb-2">Department Name *</label>
                        <input type="text" id="department_name" name="department_name" required class="input-field w-full px-4 py-3 rounded-lg focus:outline-none" placeholder="e.g., Computer Science">
                        <p class="mt-1 text-xs text-red-600 hidden" id="department_name_error">Department name is required</p>
                    </div>
                    <div>
                        <label for="college_id" class="block text-sm font-medium text-gray-700 mb-2">College *</label>
                        <select id="college_id" name="college_id" required class="input-field w-full px-4 py-3 rounded-lg focus:outline-none">
                            <option value="" disabled selected>Select a college</option>
                            <?php foreach ($colleges as $college): ?>
                                <option value="<?php echo htmlspecialchars($college['college_id'], ENT_QUOTES, 'UTF-8'); ?>">
                                    <?php echo htmlspecialchars($college['college_name'], ENT_QUOTES, 'UTF-8'); ?>
                                </option>
                            <?php endforeach; ?>
                        </select>
                        <p class="mt-1 text-xs text-red-600 hidden" id="college_id_error">College is required</p>
                    </div>
                    <div>
                        <label for="program_name" class="block text-sm font-medium text-gray-700 mb-2">Program Name *</label>
                        <input type="text" id="program_name" name="program_name" required class="input-field w-full px-4 py-3 rounded-lg focus:outline-none" placeholder="e.g., Bachelor of Science in CS">
                        <p class="mt-1 text-xs text-red-600 hidden" id="program_name_error">Program name is required</p>
                    </div>
                    <div>
                        <label for="program_code" class="block text-sm font-medium text-gray-700 mb-2">Program Code *</label>
                        <input type="text" id="program_code" name="program_code" required class="input-field w-full px-4 py-3 rounded-lg focus:outline-none" placeholder="e.g., BSCS">
                        <p class="mt-1 text-xs text-red-600 hidden" id="program_code_error">Program code is required</p>
                    </div>
                    <div>
                        <label for="program_type" class="block text-sm font-medium text-gray-700 mb-2">Program Type *</label>
                        <select id="program_type" name="program_type" required class="input-field w-full px-4 py-3 rounded-lg focus:outline-none">
                            <option value="Major">Major</option>
                            <option value="Minor">Minor</option>
                            <option value="Concentration">Concentration</option>
                        </select>
                        <p class="mt-1 text-xs text-red-600 hidden" id="program_type_error">Program type is required</p>
                    </div>
                    <div class="flex justify-end gap-3 pt-4">
                        <button type="button" id="close-department-modal" class="btn-secondary px-6 py-3 rounded-lg font-medium">
                            Cancel
                        </button>
                        <button type="submit" class="btn-primary text-white px-6 py-3 rounded-lg font-medium">
                            Create Department
                        </button>
                    </div>
                </form>
            </div>
        </div>

        <!-- Edit Modal (keep your existing edit modal code with updated styling) -->
        <div id="edit-modal" class="modal">
            <div class="modal-content">
                <h2 class="text-xl font-semibold text-gray-900 mb-6" id="edit-modal-title"></h2>
                <form action="/admin/colleges_departments/update" method="POST" class="space-y-4" novalidate>
                    <input type="hidden" name="type" id="edit-type">
                    <input type="hidden" name="id" id="edit-id">
                    <div id="edit-college-fields" class="space-y-4">
                        <div>
                            <label for="edit_college_name" class="block text-sm font-medium text-gray-700 mb-2">College Name *</label>
                            <input type="text" id="edit_college_name" name="college_name" required class="input-field w-full px-4 py-3 rounded-lg focus:outline-none">
                            <p class="mt-1 text-xs text-red-600 hidden" id="edit_college_name_error">College name is required</p>
                        </div>
                        <div>
                            <label for="edit_college_code" class="block text-sm font-medium text-gray-700 mb-2">College Code *</label>
                            <input type="text" id="edit_college_code" name="college_code" required class="input-field w-full px-4 py-3 rounded-lg focus:outline-none">
                            <p class="mt-1 text-xs text-red-600 hidden" id="edit_college_code_error">College code is required</p>
                        </div>
                    </div>
                    <div id="edit-department-fields" class="space-y-4 hidden">
                        <div>
                            <label for="edit_department_name" class="block text-sm font-medium text-gray-700 mb-2">Department Name *</label>
                            <input type="text" id="edit_department_name" name="department_name" required class="input-field w-full px-4 py-3 rounded-lg focus:outline-none">
                            <p class="mt-1 text-xs text-red-600 hidden" id="edit_department_name_error">Department name is required</p>
                        </div>
                        <div>
                            <label for="edit_college_id" class="block text-sm font-medium text-gray-700 mb-2">College *</label>
                            <select id="edit_college_id" name="college_id" required class="input-field w-full px-4 py-3 rounded-lg focus:outline-none">
                                <option value="" disabled>Select a college</option>
                                <?php foreach ($colleges as $college): ?>
                                    <option value="<?php echo htmlspecialchars($college['college_id'], ENT_QUOTES, 'UTF-8'); ?>">
                                        <?php echo htmlspecialchars($college['college_name'], ENT_QUOTES, 'UTF-8'); ?>
                                    </option>
                                <?php endforeach; ?>
                            </select>
                            <p class="mt-1 text-xs text-red-600 hidden" id="edit_college_id_error">College is required</p>
                        </div>
                        <div>
                            <label for="edit_program_name" class="block text-sm font-medium text-gray-700 mb-2">Program Name *</label>
                            <input type="text" id="edit_program_name" name="program_name" required class="input-field w-full px-4 py-3 rounded-lg focus:outline-none">
                            <p class="mt-1 text-xs text-red-600 hidden" id="edit_program_name_error">Program name is required</p>
                        </div>
                        <div>
                            <label for="edit_program_code" class="block text-sm font-medium text-gray-700 mb-2">Program Code *</label>
                            <input type="text" id="edit_program_code" name="program_code" required class="input-field w-full px-4 py-3 rounded-lg focus:outline-none">
                            <p class="mt-1 text-xs text-red-600 hidden" id="edit_program_code_error">Program code is required</p>
                        </div>
                        <div>
                            <label for="edit_program_type" class="block text-sm font-medium text-gray-700 mb-2">Program Type *</label>
                            <select id="edit_program_type" name="program_type" required class="input-field w-full px-4 py-3 rounded-lg focus:outline-none">
                                <option value="Major">Major</option>
                                <option value="Minor">Minor</option>
                                <option value="Concentration">Concentration</option>
                            </select>
                            <p class="mt-1 text-xs text-red-600 hidden" id="edit_program_type_error">Program type is required</p>
                        </div>
                    </div>
                    <div class="flex justify-end gap-3 pt-4">
                        <button type="button" id="close-edit-modal" class="btn-secondary px-6 py-3 rounded-lg font-medium">
                            Cancel
                        </button>
                        <button type="submit" class="btn-primary text-white px-6 py-3 rounded-lg font-medium">
                            Save Changes
                        </button>
                    </div>
                </form>
            </div>
        </div>
    </div>
</div>

<script>
    // Keep your existing JavaScript functionality, it will work with the new design
    document.addEventListener('DOMContentLoaded', () => {
        const tabButtons = document.querySelectorAll('.tab-button');
        const tabContents = document.querySelectorAll('.tab-content');

        tabButtons.forEach(button => {
            button.addEventListener('click', () => {
                // Remove active state from all tabs
                tabButtons.forEach(btn => {
                    btn.classList.remove('tab-active', 'text-yellow-600');
                    btn.classList.add('border-transparent', 'text-gray-500');
                });

                // Hide all tab contents
                tabContents.forEach(content => content.classList.add('hidden'));

                // Activate clicked tab
                button.classList.add('tab-active', 'text-yellow-600');
                button.classList.remove('border-transparent', 'text-gray-500');

                // Show corresponding content
                document.getElementById(`${button.dataset.tab}-content`).classList.remove('hidden');
            });
        });

        // Modal controls (keep your existing modal JavaScript)
        const collegeModal = document.getElementById('college-modal');
        const departmentModal = document.getElementById('department-modal');
        const editModal = document.getElementById('edit-modal');
        const openCollegeModal = document.getElementById('open-college-modal');
        const openDepartmentModal = document.getElementById('open-department-modal');
        const closeCollegeModal = document.getElementById('close-college-modal');
        const closeDepartmentModal = document.getElementById('close-department-modal');
        const closeEditModal = document.getElementById('close-edit-modal');

        openCollegeModal.addEventListener('click', () => collegeModal.style.display = 'block');
        openDepartmentModal.addEventListener('click', () => departmentModal.style.display = 'block');
        closeCollegeModal.addEventListener('click', () => collegeModal.style.display = 'none');
        closeDepartmentModal.addEventListener('click', () => departmentModal.style.display = 'none');
        closeEditModal.addEventListener('click', () => editModal.style.display = 'none');

        // Close modal when clicking outside
        window.addEventListener('click', (e) => {
            if (e.target === collegeModal) collegeModal.style.display = 'none';
            if (e.target === departmentModal) departmentModal.style.display = 'none';
            if (e.target === editModal) editModal.style.display = 'none';
        });

        // Add this to your existing JavaScript
        function initMobileTables() {
            if (window.innerWidth < 768) {
                document.querySelectorAll('.table-row td').forEach(td => {
                    const header = td.closest('tr').querySelector('th:nth-child(' + (td.cellIndex + 1) + ')');
                    if (header) {
                        td.setAttribute('data-label', header.textContent);
                    }
                });
            }
        }

        // Call this on load and resize
        document.addEventListener('DOMContentLoaded', initMobileTables);
        window.addEventListener('resize', initMobileTables);

        // Edit button functionality
        document.querySelectorAll('.edit-btn').forEach(button => {
            button.addEventListener('click', () => {
                const type = button.getAttribute('data-type');
                const id = button.getAttribute('data-id');
                editModal.style.display = 'block';

                if (type === 'college') {
                    document.getElementById('edit-modal-title').textContent = 'Edit College';
                    document.getElementById('edit-type').value = 'college';
                    document.getElementById('edit-id').value = id;
                    document.getElementById('edit-college-fields').classList.remove('hidden');
                    document.getElementById('edit-department-fields').classList.add('hidden');
                    document.getElementById('edit_college_name').value = button.getAttribute('data-name');
                    document.getElementById('edit_college_code').value = button.getAttribute('data-code');
                } else if (type === 'department') {
                    document.getElementById('edit-modal-title').textContent = 'Edit Department';
                    document.getElementById('edit-type').value = 'department';
                    document.getElementById('edit-id').value = id;
                    document.getElementById('edit-college-fields').classList.add('hidden');
                    document.getElementById('edit-department-fields').classList.remove('hidden');
                    document.getElementById('edit_department_name').value = button.getAttribute('data-name');
                    document.getElementById('edit_college_id').value = button.getAttribute('data-college-id');
                    document.getElementById('edit_program_name').value = button.getAttribute('data-program-name') || '';
                    document.getElementById('edit_program_code').value = button.getAttribute('data-program-code') || '';
                    document.getElementById('edit_program_type').value = 'Major';
                }
            });
        });

        // Show toasts on page load
        <?php if (isset($_SESSION['success']) || isset($_SESSION['error'])): ?>
            setTimeout(() => {
                const successToast = document.getElementById('success-toast');
                const errorToast = document.getElementById('error-toast');

                if (successToast) {
                    successToast.classList.remove('hidden');
                    setTimeout(() => successToast.remove(), 3500);
                }
                if (errorToast) {
                    errorToast.classList.remove('hidden');
                    setTimeout(() => errorToast.remove(), 3500);
                }
            }, 300);
        <?php endif; ?>
    });
</script>

<?php
$content = ob_get_clean();
require_once __DIR__ . '/layout.php';
?>