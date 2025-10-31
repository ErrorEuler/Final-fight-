<?php
ob_start();
?>

<style>
    :root {
        --gold: #D4AF37;
        --white: #FFFFFF;
        --gray-dark: #4B5563;
        --gray-light: #E5E7EB;
    }

    .fade-in {
        animation: fadeIn 0.5s ease-in;
    }

    @keyframes fadeIn {
        from {
            opacity: 0;
        }

        to {
            opacity: 1;
        }
    }

    .slide-in-left {
        animation: slideInLeft 0.5s ease-in;
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

    .toast {
        position: fixed;
        top: 20px;
        right: 20px;
        z-index: 1000;
        transition: all 0.3s ease;
    }

    .modal {
        transition: opacity 0.3s ease;
    }

    .modal.hidden {
        opacity: 0;
        pointer-events: none;
    }

    .modal-content {
        transition: transform 0.3s ease;
    }

    .input-focus {
        transition: all 0.2s ease;
    }

    .input-focus:focus {
        border-color: var(--gold);
        box-shadow: 0 0 0 3px rgba(212, 175, 55, 0.2);
    }

    .btn-gold {
        background-color: var(--gold);
        color: var(--white);
    }

    .btn-gold:hover {
        background-color: #b8972e;
    }

    .loading::after {
        content: '';
        display: inline-block;
        width: 16px;
        height: 16px;
        border: 2px solid var(--gold);
        border-top-color: transparent;
        border-radius: 50%;
        animation: spin 0.8s linear infinite;
        margin-left: 8px;
    }

    @keyframes spin {
        to {
            transform: rotate(360deg);
        }
    }

    .tab-active {
        background-color: var(--gold);
        color: var(--white);
    }

    .tab-active:hover {
        background-color: #b8972e;
    }
</style>

<div class="min-h-screen bg-gray-100 py-6">
    <div class="mx-auto px-4 sm:px-6 lg:px-8">
        <!-- Header Section -->
        <div class="mb-8">
            <!-- Update the header section -->
            <div class="flex justify-between items-center">
                <div>
                    <h1 class="text-3xl font-bold text-gray-900 bg-clip-text text-transparent bg-gradient-to-r from-yellow-600 to-yellow-400 slide-in-left">
                        User Management
                    </h1>
                    <p class="mt-2 text-gray-600 slide-in-right">Manage system users, roles, and permissions</p>
                </div>
                <button onclick="openAddUserModal()" class="bg-yellow-600 text-white px-4 py-2 rounded-lg hover:bg-yellow-700 transition-colors flex items-center">
                    <svg class="w-5 h-5 mr-2" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                        <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 4v16m8-8H4"></path>
                    </svg>
                    Add User
                </button>
            </div>
        </div>

        <!-- Stats Cards -->
        <div class="grid grid-cols-1 md:grid-cols-4 gap-6 mb-8">
            <div class="card bg-white rounded-xl shadow-md p-6 border border-gray-200 hover:shadow-lg transition-all duration-200">
                <div class="flex items-center">
                    <div class="p-3 bg-yellow-100 rounded-lg">
                        <svg class="w-6 h-6 text-yellow-600" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 4.354a4 4 0 110 5.292M15 21H3v-1a6 6 0 0112 0v1zm0 0h6v-1a6 6 0 00-9-5.197m13.5-9a2.5 2.5 0 11-5 0 2.5 2.5 0 015 0z"></path>
                        </svg>
                    </div>
                    <div class="ml-4">
                        <p class="text-sm font-medium text-gray-600">Total Users</p>
                        <p class="text-2xl font-bold text-gray-900"><?php echo count($users); ?></p>
                    </div>
                </div>
            </div>
            <div class="card bg-white rounded-xl shadow-md p-6 border border-gray-200 hover:shadow-lg transition-all duration-200">
                <div class="flex items-center">
                    <div class="p-3 bg-green-100 rounded-lg">
                        <svg class="w-6 h-6 text-green-600" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z"></path>
                        </svg>
                    </div>
                    <div class="ml-4">
                        <p class="text-sm font-medium text-gray-600">Active Users</p>
                        <p class="text-2xl font-bold text-gray-900"><?php echo count(array_filter($users, fn($u) => $u['is_active'])); ?></p>
                    </div>
                </div>
            </div>
            <div class="card bg-white rounded-xl shadow-md p-6 border border-gray-200 hover:shadow-lg transition-all duration-200">
                <div class="flex items-center">
                    <div class="p-3 bg-blue-100 rounded-lg">
                        <svg class="w-6 h-6 text-blue-600" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 15v2m-6 4h12a2 2 0 002-2v-6a2 2 0 00-2-2H6a2 2 0 00-2 2v6a2 2 0 002 2zm10-10V7a4 4 0 00-8 0v4h8z"></path>
                        </svg>
                    </div>
                    <div class="ml-4">
                        <p class="text-sm font-medium text-gray-600">Roles</p>
                        <p class="text-2xl font-bold text-gray-900"><?php echo count($roles); ?></p>
                    </div>
                </div>
            </div>
            <div class="card bg-white rounded-xl shadow-md p-6 border border-gray-200 hover:shadow-lg transition-all duration-200">
                <div class="flex items-center">
                    <div class="p-3 bg-purple-100 rounded-lg">
                        <svg class="w-6 h-6 text-purple-600" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M19 21V5a2 2 0 00-2-2H7a2 2 0 00-2 2v16m14 0h2m-2 0h-5m-9 0H3m2 0h5M9 7h1m-1 4h1m4-4h1m-1 4h1m-5 10v-5a1 1 0 011-1h2a1 1 0 011 1v5m-4 0h4"></path>
                        </svg>
                    </div>
                    <div class="ml-4">
                        <p class="text-sm font-medium text-gray-600">Departments</p>
                        <p class="text-2xl font-bold text-gray-900"><?php echo count($departments); ?></p>
                    </div>
                </div>
            </div>
        </div>

        <!-- Search and Filter Section -->
        <div class="bg-white rounded-xl shadow-md border border-gray-200 mb-6">
            <div class="p-6">
                <div class="flex flex-col sm:flex-row gap-4">
                    <div class="flex-1">
                        <div class="relative">
                            <svg class="absolute left-3 top-1/2 transform -translate-y-1/2 w-5 h-5 text-gray-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M21 21l-6-6m2-5a7 7 0 11-14 0 7 7 0 0114 0z"></path>
                            </svg>
                            <input type="text" id="searchUsers" placeholder="Search users..." class="w-full pl-10 pr-4 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-yellow-500 focus:border-yellow-500">
                        </div>
                    </div>
                    <div class="flex gap-3">
                        <select id="roleFilter" class="px-3 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-yellow-500 focus:border-yellow-500">
                            <option value="">All Roles</option>
                            <?php foreach ($roles as $role): ?>
                                <option value="<?php echo htmlspecialchars($role['role_name'], ENT_QUOTES, 'UTF-8'); ?>">
                                    <?php echo htmlspecialchars($role['role_name'], ENT_QUOTES, 'UTF-8'); ?>
                                </option>
                            <?php endforeach; ?>
                        </select>
                        <select id="collegeFilter" class="px-3 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-yellow-500 focus:border-yellow-500">
                            <option value="">All Colleges</option>
                            <?php foreach ($colleges as $college): ?>
                                <option value="<?php echo htmlspecialchars($college['college_name'], ENT_QUOTES, 'UTF-8'); ?>">
                                    <?php echo htmlspecialchars($college['college_name'], ENT_QUOTES, 'UTF-8'); ?>
                                </option>
                            <?php endforeach; ?>
                        </select>
                    </div>
                </div>
            </div>
        </div>

        <!-- Tabs -->
        <div class="mb-6">
            <nav class="flex space-x-6 border-b border-gray-200">
                <button id="tab-all" class="tab px-4 py-2 text-sm font-medium rounded-t-lg transition-colors duration-200 <?php echo !isset($_GET['tab']) || $_GET['tab'] === 'all' ? 'tab-active' : 'text-gray-500 hover:text-gray-700'; ?>" onclick="switchTab('all')">All Users</button>
                <button id="tab-active" class="tab px-4 py-2 text-sm font-medium rounded-t-lg transition-colors duration-200 <?php echo isset($_GET['tab']) && $_GET['tab'] === 'active' ? 'tab-active' : 'text-gray-500 hover:text-gray-700'; ?>" onclick="switchTab('active')">Active Users</button>
                <button id="tab-inactive" class="tab px-4 py-2 text-sm font-medium rounded-t-lg transition-colors duration-200 <?php echo isset($_GET['tab']) && $_GET['tab'] === 'inactive' ? 'tab-active' : 'text-gray-500 hover:text-gray-700'; ?>" onclick="switchTab('inactive')">Inactive Users</button>
                <button id="tab-pending" class="tab px-4 py-2 text-sm font-medium rounded-t-lg transition-colors duration-200 <?php echo isset($_GET['tab']) && $_GET['tab'] === 'pending' ? 'tab-active' : 'text-gray-500 hover:text-gray-700'; ?>" onclick="switchTab('pending')">Pending Users <span id="pending-count" class="ml-1 bg-red-500 text-white text-xs rounded-full px-2 py-0.5"><?php echo count(array_filter($users, fn($u) => !$u['is_active'] && /* Add pending condition */ true)); ?></span></button>
            </nav>
        </div>

        <!-- Users Table -->
        <div class="bg-white rounded-xl shadow-md border border-gray-200 overflow-hidden">
            <div class="px-6 py-4 border-b border-gray-200 flex justify-between items-center">
                <h2 class="text-lg font-semibold text-gray-900" id="table-title">Users Directory</h2>
                <div class="text-sm text-gray-500">
                    <span id="visibleCount"><?php echo count($users); ?></span> of <?php echo count($users); ?> users
                </div>
            </div>

            <!-- Horizontal scroll container -->
            <div class="overflow-x-auto">
                <div class="min-w-full inline-block align-middle">
                    <table class="min-w-full divide-y divide-gray-200" id="usersTable">
                        <thead class="bg-gray-50">
                            <tr>
                                <th class="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider whitespace-nowrap min-w-[200px]">User</th>
                                <th class="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider whitespace-nowrap min-w-[180px]">Email</th>
                                <th class="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider whitespace-nowrap min-w-[120px]">Role</th>
                                <th class="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider whitespace-nowrap min-w-[150px]">College</th>
                                <th class="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider whitespace-nowrap min-w-[150px]">Department</th>
                                <th class="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider whitespace-nowrap min-w-[120px]">Password</th>
                                <th class="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider whitespace-nowrap min-w-[100px]">Status</th>
                                <th class="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider whitespace-nowrap min-w-[120px]">Actions</th>
                            </tr>
                        </thead>
                        <tbody class="bg-white divide-y divide-gray-200" id="usersTableBody">
                            <?php foreach ($users as $user): ?>
                                <tr class="user-row <?php echo !$user['is_active'] ? 'pending-user' : ($user['is_active'] ? 'active-user' : 'inactive-user'); ?> hover:bg-gray-50 transition-colors duration-150" data-user-id="<?php echo $user['user_id']; ?>" style="display: <?php echo !isset($_GET['tab']) || $_GET['tab'] === 'all' ? '' : 'none'; ?>">
                                    <td class="px-4 py-4 whitespace-nowrap">
                                        <div class="flex items-center min-w-0">
                                            <div class="flex-shrink-0 h-10 w-10">
                                                <?php if (!empty($user['profile_picture'])): ?>
                                                    <img src="<?php echo htmlspecialchars($user['profile_picture'], ENT_QUOTES, 'UTF-8'); ?>" alt="Profile picture" class="h-10 w-10 rounded-full object-cover">
                                                <?php else: ?>
                                                    <div class="h-10 w-10 rounded-full bg-yellow-100 flex items-center justify-center">
                                                        <span class="text-sm font-medium text-yellow-600">
                                                            <?php echo strtoupper(substr($user['first_name'], 0, 1) . substr($user['last_name'], 0, 1)); ?>
                                                        </span>
                                                    </div>
                                                <?php endif; ?>
                                            </div>
                                            <div class="ml-3 min-w-0 flex-1">
                                                <div class="text-sm font-medium text-gray-900 truncate" title="<?php echo htmlspecialchars($user['title'] . ' ' . $user['first_name'] . ' ' . $user['middle_name'] . ' ' . $user['last_name'] . ' ' . $user['suffix'], ENT_QUOTES, 'UTF-8'); ?>">
                                                    <?php echo htmlspecialchars($user['title'] . ' ' . $user['first_name'] . ' ' . $user['middle_name'] . ' ' . $user['last_name'] . ' ' . $user['suffix'], ENT_QUOTES, 'UTF-8'); ?>
                                                </div>
                                                <div class="text-sm text-gray-500 truncate">
                                                    @<?php echo htmlspecialchars($user['username'], ENT_QUOTES, 'UTF-8'); ?>
                                                </div>
                                            </div>
                                        </div>
                                    </td>
                                    <td class="px-4 py-4 whitespace-nowrap text-sm text-gray-900">
                                        <div class="truncate max-w-[160px]" title="<?php echo htmlspecialchars($user['email'] ?? 'Not provided', ENT_QUOTES, 'UTF-8'); ?>">
                                            <?php echo htmlspecialchars($user['email'] ?? 'Not provided', ENT_QUOTES, 'UTF-8'); ?>
                                        </div>
                                    </td>
                                    <td class="px-4 py-4 whitespace-nowrap">
                                        <span class="inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium bg-yellow-100 text-yellow-800">
                                            <?php echo htmlspecialchars($user['role_name'], ENT_QUOTES, 'UTF-8'); ?>
                                        </span>
                                    </td>
                                    <td class="px-4 py-4 whitespace-nowrap text-sm text-gray-900">
                                        <div class="truncate max-w-[140px]" title="<?php echo htmlspecialchars($user['college_name'] ?? 'Not assigned', ENT_QUOTES, 'UTF-8'); ?>">
                                            <?php echo htmlspecialchars($user['college_name'] ?? 'Not assigned', ENT_QUOTES, 'UTF-8'); ?>
                                        </div>
                                    </td>
                                    <td class="px-4 py-4 whitespace-nowrap text-sm text-gray-900">
                                        <div class="truncate max-w-[140px]" title="<?php echo htmlspecialchars($user['department_name'] ?? 'Not assigned', ENT_QUOTES, 'UTF-8'); ?>">
                                            <?php echo htmlspecialchars($user['department_name'] ?? 'Not assigned', ENT_QUOTES, 'UTF-8'); ?>
                                        </div>
                                    </td>
                                    <td class="px-4 py-4 whitespace-nowrap text-sm font-mono text-gray-500">
                                        ••••••••
                                        <button onclick="showPassword(<?php echo $user['user_id']; ?>)"
                                            class="ml-2 text-blue-600 hover:text-blue-900 text-xs"
                                            title="View Password">
                                            View
                                        </button>
                                    </td>
                                    <td class="px-4 py-4 whitespace-nowrap">
                                        <?php $isActive = isset($user['is_active']) && $user['is_active']; ?>
                                        <span class="inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium <?php echo $isActive ? 'bg-green-100 text-green-800' : 'bg-red-100 text-red-800'; ?>">
                                            <?php echo $isActive ? 'Active' : 'Inactive'; ?>
                                        </span>
                                    </td>
                                    <td class="px-4 py-4 whitespace-nowrap text-sm font-medium">
                                        <div class="flex items-center space-x-1">
                                            <button onclick="viewUser(<?php echo $user['user_id']; ?>)" class="text-blue-600 hover:text-blue-900 p-1 rounded transition-colors" title="View Details">
                                                <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                                    <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M15 12a3 3 0 11-6 0 3 3 0 016 0z"></path>
                                                    <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M2.458 12C3.732 7.943 7.523 5 12 5c4.478 0 8.268 2.943 9.542 7-1.274 4.057-5.064 7-9.542 7-4.477 0-8.268-2.943-9.542-7z"></path>
                                                </svg>
                                            </button>
                                            <button onclick="resetPassword(<?php echo $user['user_id']; ?>)" class="text-purple-600 hover:text-purple-900 p-1 rounded transition-colors" title="Reset Password">
                                                <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                                    <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 15v2m-6 4h12a2 2 0 002-2v-6a2 2 0 00-2-2H6a2 2 0 00-2 2v6a2 2 0 002 2zm10-10V7a4 4 0 00-8 0v4h8z"></path>
                                                </svg>
                                            </button>
                                            <?php if (!$isActive): ?>
                                                <button onclick="approveUser(<?php echo $user['user_id']; ?>, '<?php echo htmlspecialchars($user['first_name'] . ' ' . $user['last_name'], ENT_QUOTES, 'UTF-8'); ?>')" class="text-yellow-600 hover:text-yellow-900 p-1 rounded transition-colors" title="Approve User">
                                                    <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                                        <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z"></path>
                                                    </svg>
                                                </button>
                                                <button onclick="declineUser(<?php echo $user['user_id']; ?>, '<?php echo htmlspecialchars($user['first_name'] . ' ' . $user['last_name'], ENT_QUOTES, 'UTF-8'); ?>')" class="text-red-600 hover:text-red-900 p-1 rounded transition-colors" title="Decline User">
                                                    <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                                        <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M10 14l2-2m0 0l2-2m-2 2l-2-2m2 2l2 2m7-2a9 9 0 11-18 0 9 9 0 0118 0z"></path>
                                                    </svg>
                                                </button>
                                            <?php elseif ($isActive): ?>
                                                <button onclick="disableUser(<?php echo $user['user_id']; ?>, '<?php echo htmlspecialchars($user['first_name'] . ' ' . $user['last_name'], ENT_QUOTES, 'UTF-8'); ?>')" class="text-red-600 hover:text-red-900 p-1 rounded transition-colors" title="Disable User">
                                                    <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                                        <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M18.364 18.364A9 9 0 005.636 5.636m12.728 12.728L5.636 5.636m12.728 12.728L18.364 5.636M5.636 18.364l12.728-12.728"></path>
                                                    </svg>
                                                </button>
                                            <?php endif; ?>
                                        </div>
                                    </td>
                                </tr>
                            <?php endforeach; ?>
                        </tbody>
                    </table>
                </div>
            </div>

            <!-- Scroll indicator -->
            <div class="px-6 py-3 border-t border-gray-200 bg-gray-50 flex justify-between items-center text-sm text-gray-500">
                <span>Scroll horizontally to see more columns →</span>
                <span id="visibleCountBottom"><?php echo count($users); ?> users</span>
            </div>
        </div>
    </div>

    <!-- Decline User Confirmation Modal -->
    <div id="declineUserModal" class="fixed inset-0 bg-gray-600 bg-opacity-50 flex items-center justify-center z-50 hidden">
        <div class="relative mx-auto p-6 border w-96 shadow-lg rounded-xl bg-white">
            <div class="mt-3 text-center">
                <div class="mx-auto flex items-center justify-center h-12 w-12 rounded-full bg-red-100 mb-4">
                    <svg class="h-6 w-6 text-red-600" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                        <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-2.5L13.732 4c-.77-.833-1.964-.833-2.732 0L3.732 16.5c-.77.833.192 2.5 1.732 2.5z"></path>
                    </svg>
                </div>
                <h3 class="text-lg leading-6 font-medium text-gray-900">Decline User Account</h3>
                <div class="mt-2 px-7 py-3">
                    <p class="text-sm text-gray-500">
                        Are you sure you want to decline <span id="declineUserName" class="font-semibold"></span>? This action will permanently remove the user.
                    </p>
                </div>
                <div class="flex justify-center space-x-3 px-4 py-3">
                    <button onclick="closeDeclineUserModal()" class="px-4 py-2 bg-white text-gray-800 border border-gray-300 rounded-lg hover:bg-gray-50 focus:outline-none focus:ring-2 focus:ring-yellow-500 transition-colors">
                        Cancel
                    </button>
                    <button onclick="confirmDeclineUser()" class="px-4 py-2 bg-red-600 text-white rounded-lg hover:bg-red-700 focus:outline-none focus:ring-2 focus:ring-red-500 transition-colors">
                        Decline User
                    </button>
                </div>
            </div>
        </div>
    </div>

    <!-- Disable User Confirmation Modal -->
    <div id="disableUserModal" class="fixed inset-0 bg-gray-600 bg-opacity-50 flex items-center justify-center z-50 hidden">
        <div class="relative mx-auto p-6 border w-96 shadow-lg rounded-xl bg-white">
            <div class="mt-3 text-center">
                <div class="mx-auto flex items-center justify-center h-12 w-12 rounded-full bg-red-100 mb-4">
                    <svg class="h-6 w-6 text-red-600" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                        <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-2.5L13.732 4c-.77-.833-1.964-.833-2.732 0L3.732 16.5c-.77.833.192 2.5 1.732 2.5z"></path>
                    </svg>
                </div>
                <h3 class="text-lg leading-6 font-medium text-gray-900">Disable User Account</h3>
                <div class="mt-2 px-7 py-3">
                    <p class="text-sm text-gray-500">
                        Are you sure you want to disable <span id="disableUserName" class="font-semibold"></span>? This action will prevent the user from logging in.
                    </p>
                </div>
                <div class="flex justify-center space-x-3 px-4 py-3">
                    <button onclick="closeDisableUserModal()" class="px-4 py-2 bg-white text-gray-800 border border-gray-300 rounded-lg hover:bg-gray-50 focus:outline-none focus:ring-2 focus:ring-yellow-500 transition-colors">
                        Cancel
                    </button>
                    <button onclick="confirmDisableUser()" class="px-4 py-2 bg-red-600 text-white rounded-lg hover:bg-red-700 focus:outline-none focus:ring-2 focus:ring-red-500 transition-colors">
                        Disable User
                    </button>
                </div>
            </div>
        </div>
    </div>

    <!-- View User Modal -->
    <div id="viewUserModal" class="fixed inset-0 bg-gray-600 bg-opacity-50 flex items-center justify-center z-50 hidden">
        <div class="relative mx-auto p-6 border w-full max-w-2xl shadow-lg rounded-xl bg-white">
            <div class="flex justify-between items-center mb-6">
                <h3 class="text-xl font-semibold text-gray-900">User Details</h3>
                <button onclick="closeViewUserModal()" class="text-gray-400 hover:text-gray-600 transition-colors">
                    <svg class="w-6 h-6" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                        <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M6 18L18 6M6 6l12 12"></path>
                    </svg>
                </button>
            </div>
            <div id="userDetailsContent" class="space-y-4">
                <!-- Populated by JavaScript -->
            </div>
        </div>
    </div>

    <!-- Add User Modal -->
    <div id="addUserModal" class="fixed inset-0 bg-gray-600 bg-opacity-50 flex items-center justify-center z-50 hidden">
        <div class="relative mx-auto p-6 border w-full max-w-6xl shadow-lg rounded-xl bg-white max-h-[95vh] overflow-y-auto">
            <div class="flex justify-between items-center mb-6">
                <h3 class="text-xl font-semibold text-gray-900">Add New User</h3>
                <button onclick="closeAddUserModal()" class="text-gray-400 hover:text-gray-600 transition-colors">
                    <svg class="w-6 h-6" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                        <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M6 18L18 6M6 6l12 12"></path>
                    </svg>
                </button>
            </div>

            <form id="addUserForm" class="space-y-6">
                <input type="hidden" name="csrf_token" value="<?php echo htmlspecialchars($csrfToken, ENT_QUOTES, 'UTF-8'); ?>">

                <!-- Basic Information Section -->
                <div class="bg-gray-50 p-4 rounded-lg">
                    <h4 class="text-lg font-medium text-gray-900 mb-4">Basic Information</h4>
                    <div class="grid grid-cols-1 md:grid-cols-2 gap-6">
                        <div>
                            <label class="block text-sm font-medium text-gray-700 mb-2">Employee ID *</label>
                            <input type="text" name="employee_id" required class="w-full px-3 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-yellow-500 focus:border-yellow-500">
                        </div>
                        <div>
                            <label class="block text-sm font-medium text-gray-700 mb-2">Username *</label>
                            <input type="text" name="username" required class="w-full px-3 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-yellow-500 focus:border-yellow-500">
                        </div>
                    </div>

                    <div class="grid grid-cols-1 md:grid-cols-2 gap-6 mt-4">
                        <div>
                            <label class="block text-sm font-medium text-gray-700 mb-2">Email *</label>
                            <input type="email" name="email" required class="w-full px-3 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-yellow-500 focus:border-yellow-500">
                        </div>
                        <div>
                            <label class="block text-sm font-medium text-gray-700 mb-2">Phone</label>
                            <input type="tel" name="phone" class="w-full px-3 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-yellow-500 focus:border-yellow-500">
                        </div>
                    </div>

                    <!-- Personal Information -->
                    <div class="grid grid-cols-1 md:grid-cols-4 gap-4 mt-4">
                        <div>
                            <label class="block text-sm font-medium text-gray-700 mb-2">Title</label>
                            <select name="title" class="w-full px-3 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-yellow-500 focus:border-yellow-500">
                                <option value="">Select Title</option>
                                <!-- Dynamically populated -->
                            </select>
                        </div>
                        <div>
                            <label class="block text-sm font-medium text-gray-700 mb-2">First Name *</label>
                            <input type="text" name="first_name" required class="w-full px-3 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-yellow-500 focus:border-yellow-500">
                        </div>
                        <div>
                            <label class="block text-sm font-medium text-gray-700 mb-2">Middle Name</label>
                            <input type="text" name="middle_name" class="w-full px-3 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-yellow-500 focus:border-yellow-500">
                        </div>
                        <div>
                            <label class="block text-sm font-medium text-gray-700 mb-2">Last Name *</label>
                            <input type="text" name="last_name" required class="w-full px-3 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-yellow-500 focus:border-yellow-500">
                        </div>
                    </div>
                </div>

                <!-- ==================== PASSWORD GENERATOR (AUTO-SEND EMAIL) ==================== -->
                <div class="bg-gradient-to-r from-indigo-50 to-blue-50 p-4 rounded-xl border border-indigo-200 mb-6">
                    <h4 class="text-sm font-semibold text-indigo-900 mb-3 flex items-center">
                        Temporary Password (auto-generated)
                    </h4>
                    <div class="flex flex-col sm:flex-row gap-3">
                        <input type="text" id="generatedPassword" readonly
                            class="flex-1 px-4 py-2.5 border border-gray-300 rounded-lg bg-white font-mono text-sm
                      focus:ring-2 focus:ring-indigo-500 focus:border-indigo-500"
                            placeholder="Click Generate to create">
                        <button type="button" onclick="generatePassword()"
                            class="px-5 py-2.5 bg-indigo-600 text-white rounded-lg hover:bg-indigo-700 font-medium text-sm transition-colors flex items-center gap-2">
                            Generate
                        </button>
                        <button type="button" onclick="copyPassword()"
                            class="px-4 py-2.5 bg-gray-600 text-white rounded-lg hover:bg-gray-700 font-medium text-sm transition-colors flex items-center gap-2">
                            Copy
                        </button>
                    </div>
                    <p class="text-xs text-indigo-700 mt-2 font-medium">
                        Welcome email with login details will be sent automatically.
                    </p>
                </div>

                <!-- Role and Academic Information Section -->
                <div class="bg-gray-50 p-4 rounded-lg">
                    <h4 class="text-lg font-medium text-gray-900 mb-4">Role & Academic Information</h4>

                    <div class="grid grid-cols-1 md:grid-cols-3 gap-6">
                        <div>
                            <label class="block text-sm font-medium text-gray-700 mb-2">Role *</label>
                            <select name="role_id" id="roleSelect" required class="w-full px-3 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-yellow-500 focus:border-yellow-500">
                                <option value="">Select Role</option>
                                <?php foreach ($roles as $role): ?>
                                    <option value="<?php echo $role['role_id']; ?>"><?php echo htmlspecialchars($role['role_name'], ENT_QUOTES, 'UTF-8'); ?></option>
                                <?php endforeach; ?>
                            </select>
                        </div>
                        <div>
                            <label class="block text-sm font-medium text-gray-700 mb-2">Academic Rank</label>
                            <select name="academic_rank" class="w-full px-3 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-yellow-500 focus:border-yellow-500">
                                <option value="">Select Rank</option>
                                <!-- Dynamically populated -->
                            </select>
                        </div>
                        <div>
                            <label class="block text-sm font-medium text-gray-700 mb-2">Employment Type</label>
                            <select name="employment_type" class="w-full px-3 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-yellow-500 focus:border-yellow-500">
                                <option value="">Select Type</option>
                                <option value="Regular">Regular</option>
                                <option value="Contractual">Contractual</option>
                                <option value="Part-time">Part-time</option>
                            </select>
                        </div>
                    </div>

                    <div class="grid grid-cols-1 md:grid-cols-3 gap-6 mt-4">
                        <div>
                            <label class="block text-sm font-medium text-gray-700 mb-2">Classification</label>
                            <select name="classification" class="w-full px-3 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-yellow-500 focus:border-yellow-500">
                                <option value="">Select Classification</option>
                                <option value="TL">TL</option>
                                <option value="VSL">VSL</option>
                            </select>
                        </div>
                        <div>
                            <label class="block text-sm font-medium text-gray-700 mb-2">Max Hours</label>
                            <input type="number" name="max_hours" step="0.01" value="18.00" class="w-full px-3 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-yellow-500 focus:border-yellow-500">
                        </div>
                        <div>
                            <label class="block text-sm font-medium text-gray-700 mb-2">Designation</label>
                            <input type="text" name="designation" class="w-full px-3 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-yellow-500 focus:border-yellow-500" placeholder="e.g., Department Head, Coordinator">
                        </div>
                    </div>
                </div>

                <!-- Educational Background Section -->
                <div class="bg-gray-50 p-4 rounded-lg">
                    <h4 class="text-lg font-medium text-gray-900 mb-4">Educational Background</h4>
                    <div class="grid grid-cols-1 md:grid-cols-2 gap-6">
                        <div>
                            <label class="block text-sm font-medium text-gray-700 mb-2">Bachelor's Degree</label>
                            <input type="text" name="bachelor_degree" class="w-full px-3 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-yellow-500 focus:border-yellow-500">
                        </div>
                        <div>
                            <label class="block text-sm font-medium text-gray-700 mb-2">Master's Degree</label>
                            <input type="text" name="master_degree" class="w-full px-3 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-yellow-500 focus:border-yellow-500">
                        </div>
                        <div>
                            <label class="block text-sm font-medium text-gray-700 mb-2">Doctorate Degree</label>
                            <input type="text" name="doctorate_degree" class="w-full px-3 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-yellow-500 focus:border-yellow-500">
                        </div>
                        <div>
                            <label class="block text-sm font-medium text-gray-700 mb-2">Post-Doctorate Degree</label>
                            <input type="text" name="post_doctorate_degree" class="w-full px-3 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-yellow-500 focus:border-yellow-500">
                        </div>
                    </div>
                </div>

                <!-- College and Department Section -->
                <div class="bg-gray-50 p-4 rounded-lg">
                    <h4 class="text-lg font-medium text-gray-900 mb-4">College & Department</h4>
                    <div class="grid grid-cols-1 md:grid-cols-2 gap-6">
                        <!-- College Select -->
                        <div>
                            <label class="block text-sm font-medium text-gray-700 mb-2">College</label>
                            <select name="college_id" id="collegeSelect" onchange="updateDepartments(this.value)"
                                class="w-full px-3 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-yellow-500 focus:border-yellow-500">
                                <option value="">Select College</option>
                                <?php foreach ($colleges as $college): ?>
                                    <option value="<?php echo $college['college_id']; ?>">
                                        <?php echo htmlspecialchars($college['college_name'], ENT_QUOTES, 'UTF-8'); ?>
                                    </option>
                                <?php endforeach; ?>
                            </select>
                        </div>

                        <!-- Department Select -->
                        <div>
                            <label class="block text-sm font-medium text-gray-700 mb-2">Department</label>
                            <select name="department_id" id="departmentSelect"
                                class="w-full px-3 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-yellow-500 focus:border-yellow-500">
                                <option value="">Select Department</option>
                            </select>
                        </div>
                    </div>

                    <div class="grid grid-cols-1 md:grid-cols-2 gap-6 mt-4">
                        <div>
                            <label class="block text-sm font-medium text-gray-700 mb-2">Primary Program</label>
                            <select name="primary_program_id" class="w-full px-3 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-yellow-500 focus:border-yellow-500">
                                <option value="">Select Primary Program</option>
                                <?php foreach ($programs as $program): ?>
                                    <option value="<?php echo $program['program_id']; ?>"><?php echo htmlspecialchars($program['program_name'], ENT_QUOTES, 'UTF-8'); ?></option>
                                <?php endforeach; ?>
                            </select>
                        </div>
                        <div>
                            <label class="block text-sm font-medium text-gray-700 mb-2">Secondary Program</label>
                            <select name="secondary_program_id" class="w-full px-3 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-yellow-500 focus:border-yellow-500">
                                <option value="">Select Secondary Program</option>
                                <?php foreach ($programs as $program): ?>
                                    <option value="<?php echo $program['program_id']; ?>"><?php echo htmlspecialchars($program['program_name'], ENT_QUOTES, 'UTF-8'); ?></option>
                                <?php endforeach; ?>
                            </select>
                        </div>
                    </div>
                </div>

                <!-- Teaching Load Information (Optional) -->
                <div class="bg-gray-50 p-4 rounded-lg">
                    <h4 class="text-lg font-medium text-gray-900 mb-4">Teaching Load Information (Optional)</h4>
                    <div class="grid grid-cols-1 md:grid-cols-3 gap-4">
                        <div>
                            <label class="block text-sm font-medium text-gray-700 mb-2">Equivalent Teaching Load</label>
                            <input type="number" name="equiv_teaching_load" step="0.01" class="w-full px-3 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-yellow-500 focus:border-yellow-500">
                        </div>
                        <div>
                            <label class="block text-sm font-medium text-gray-700 mb-2">Total Lecture Hours</label>
                            <input type="number" name="total_lecture_hours" step="0.01" class="w-full px-3 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-yellow-500 focus:border-yellow-500">
                        </div>
                        <div>
                            <label class="block text-sm font-medium text-gray-700 mb-2">Total Laboratory Hours</label>
                            <input type="number" name="total_laboratory_hours" step="0.01" class="w-full px-3 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-yellow-500 focus:border-yellow-500">
                        </div>
                    </div>

                    <div class="grid grid-cols-1 md:grid-cols-3 gap-4 mt-4">
                        <div>
                            <label class="block text-sm font-medium text-gray-700 mb-2">No. of Preparations</label>
                            <input type="number" name="no_of_preparation" class="w-full px-3 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-yellow-500 focus:border-yellow-500">
                        </div>
                        <div>
                            <label class="block text-sm font-medium text-gray-700 mb-2">Advisory Class</label>
                            <input type="text" name="advisory_class" class="w-full px-3 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-yellow-500 focus:border-yellow-500">
                        </div>
                        <div>
                            <label class="block text-sm font-medium text-gray-700 mb-2">Total Working Load</label>
                            <input type="number" name="total_working_load" step="0.01" class="w-full px-3 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-yellow-500 focus:border-yellow-500">
                        </div>
                    </div>
                </div>

                <div class="flex justify-end space-x-3 pt-4 border-t border-gray-200">
                    <button type="button" onclick="closeAddUserModal()" class="px-4 py-2 border border-gray-300 rounded-lg text-gray-700 hover:bg-gray-50 transition-colors">
                        Cancel
                    </button>
                    <button type="submit" class="px-4 py-2 bg-yellow-600 text-white rounded-lg hover:bg-yellow-700 focus:outline-none focus:ring-2 focus:ring-yellow-500 transition-colors">
                        Add User
                    </button>
                </div>
            </form>
        </div>
    </div>

    <!-- Temporary Password Modal -->
    <div id="tempPasswordModal" class="fixed inset-0 bg-gray-600 bg-opacity-50 flex items-center justify-center z-50 hidden">
        <div class="relative mx-auto p-6 border w-96 shadow-lg rounded-xl bg-white">
            <div class="text-center">
                <div class="mx-auto flex items-center justify-center h-12 w-12 rounded-full bg-green-100 mb-4">
                    <svg class="h-6 w-6 text-green-600" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                        <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 15v2m-6 4h12a2 2 0 002-2v-6a2 2 0 00-2-2H6a2 2 0 00-2 2v6a2 2 0 002 2zm10-10V7a4 4 0 00-8 0v4h8z"></path>
                    </svg>
                </div>
                <h3 class="text-lg font-semibold text-gray-900 mb-2">Temporary Password</h3>
                <p class="text-sm text-gray-600 mb-4">This password will only be shown once. Please copy it now.</p>

                <div class="bg-gray-50 p-4 rounded-lg mb-4">
                    <p class="text-sm font-medium text-gray-700 mb-1" id="tempUsername"></p>
                    <p class="text-lg font-bold text-red-600" id="tempPassword"></p>
                </div>

                <p class="text-xs text-gray-500 mb-4">User must change this password on first login.</p>

                <button onclick="closeTempPasswordModal()" class="px-4 py-2 bg-yellow-600 text-white rounded-lg hover:bg-yellow-700 transition-colors w-full">
                    I've Copied the Password
                </button>
            </div>
        </div>
    </div>

    <!-- JavaScript -->
    <script>
        let currentUserId = null;

        // Dynamic data from PHP
        let dynamicData = {
            titles: <?php echo json_encode($titles ?? []); ?>,
            academicRanks: <?php echo json_encode($academicRanks ?? []); ?>,
            employmentTypes: <?php echo json_encode($employmentTypes ?? []); ?>,
            classifications: <?php echo json_encode($classifications ?? []); ?>,
            departments: <?php echo json_encode($departments ?? []); ?>,
            programs: <?php echo json_encode($programs ?? []); ?>
        };

        console.log('Dynamic data loaded:', dynamicData);

        // Global map: college_id → [departments]
        window.collegeDepartments = {};
        window.programDepartments = {};

        // ========================
        // MODAL: Open Add User
        // ========================
        function openAddUserModal() {
            const modal = document.getElementById('addUserModal');
            if (!modal) {
                console.error('Add user modal not found!');
                return;
            }

            // Re-initialize everything when modal opens
            initializeDynamicSelects();
            initializeCollegeDepartments();
            initializeProgramDepartments();

            generatePassword();

            modal.classList.remove('hidden');
            document.body.style.overflow = 'hidden';
        }

        // ========================
        // MODAL: Close Add User
        // ========================
        function closeAddUserModal() {
            const modal = document.getElementById('addUserModal');
            if (modal) {
                modal.classList.add('hidden');
                document.body.style.overflow = 'auto';
                document.getElementById('addUserForm')?.reset();
            }
        }

        function generatePassword() {
            const chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*";
            let pass = "";
            for (let i = 0; i < 14; i++) {
                pass += chars.charAt(Math.floor(Math.random() * chars.length));
            }
            document.getElementById('generatedPassword').value = pass;
        }

        function copyPassword() {
            const el = document.getElementById('generatedPassword');
            el.select();
            document.execCommand('copy');
            alert('Password copied to clipboard!');
        }

        // Password viewing functionality
        function showPassword(userId) {
            if (confirm('This will reset the user\'s password and show the new temporary password. Continue?')) {
                fetch(`/admin/users?action=reset_password&user_id=${userId}`, {
                        method: 'POST',
                        headers: {
                            'Content-Type': 'application/json',
                            'X-Requested-With': 'XMLHttpRequest',
                            'X-CSRF-Token': '<?php echo htmlspecialchars($csrfToken, ENT_QUOTES, 'UTF-8'); ?>'
                        }
                    })
                    .then(response => response.json())
                    .then(data => {
                        if (data.success) {
                            showTempPassword(data.temporary_password, data.username);
                        } else {
                            alert('Error: ' + data.error);
                        }
                    })
                    .catch(error => {
                        console.error('Error:', error);
                        alert('An error occurred while resetting the password');
                    });
            }
        }

        // ========================
        // Initialize Title, Rank, etc.
        // ========================
        function initializeDynamicSelects() {
            // Title
            const titleSelect = document.querySelector('select[name="title"]');
            if (titleSelect && Array.isArray(dynamicData.titles)) {
                titleSelect.innerHTML = '<option value="">Select Title</option>';
                dynamicData.titles.forEach(t => {
                    const opt = new Option(t, t);
                    titleSelect.add(opt);
                });
            }

            // Academic Rank
            const rankSelect = document.querySelector('select[name="academic_rank"]');
            if (rankSelect && Array.isArray(dynamicData.academicRanks)) {
                rankSelect.innerHTML = '<option value="">Select Rank</option>';
                dynamicData.academicRanks.forEach(r => {
                    const opt = new Option(r, r);
                    rankSelect.add(opt);
                });
            }

            // Employment Type
            const empSelect = document.querySelector('select[name="employment_type"]');
            if (empSelect && Array.isArray(dynamicData.employmentTypes)) {
                empSelect.innerHTML = '<option value="">Select Type</option>';
                dynamicData.employmentTypes.forEach(t => {
                    const opt = new Option(t, t);
                    empSelect.add(opt);
                });
            }

            // Classification
            const classSelect = document.querySelector('select[name="classification"]');
            if (classSelect && Array.isArray(dynamicData.classifications)) {
                classSelect.innerHTML = '<option value="">Select Classification</option>';
                dynamicData.classifications.forEach(c => {
                    const opt = new Option(c, c);
                    classSelect.add(opt);
                });
            }
        }

        // ========================
        // College → Department Mapping
        // ========================
        function initializeCollegeDepartments() {
            window.collegeDepartments = {};

            if (!Array.isArray(dynamicData.departments)) {
                console.error('Departments data missing or invalid');
                return;
            }

            dynamicData.departments.forEach(dept => {
                const cid = dept.college_id;
                if (!window.collegeDepartments[cid]) {
                    window.collegeDepartments[cid] = [];
                }
                window.collegeDepartments[cid].push({
                    id: dept.department_id,
                    name: dept.department_name
                });
            });

            console.log('College → Department map built:', window.collegeDepartments);

            // Attach change listener
            const collegeSelect = document.getElementById('collegeSelect');
            if (collegeSelect) {
                // Remove old listeners
                collegeSelect.onchange = null;
                collegeSelect.addEventListener('change', function() {
                    updateDepartments(this.value);
                });
            }
        }

        // ========================
        // Update Department Dropdown
        // ========================
        function updateDepartments(collegeId) {
            const deptSelect = document.getElementById('departmentSelect');
            if (!deptSelect) return;

            deptSelect.innerHTML = '<option value="">Select Department</option>';

            if (!collegeId) return;

            const depts = window.collegeDepartments[collegeId] || [];
            depts.forEach(d => {
                const opt = new Option(d.name, d.id);
                deptSelect.add(opt);
            });

            console.log(`Updated departments for college ${collegeId}:`, depts);
        }

        // ========================
        // Program → Department Mapping
        // ========================
        function initializeProgramDepartments() {
            window.programDepartments = {};

            if (!Array.isArray(dynamicData.programs)) return;

            dynamicData.programs.forEach(p => {
                const did = p.department_id;
                if (!window.programDepartments[did]) {
                    window.programDepartments[did] = [];
                }
                window.programDepartments[did].push({
                    id: p.program_id,
                    name: p.program_name
                });
            });

            // Attach listener to department select
            const deptSelect = document.getElementById('departmentSelect');
            if (deptSelect) {
                deptSelect.onchange = null;
                deptSelect.addEventListener('change', function() {
                    updatePrograms(this.value);
                });
            }
        }

        // ========================
        // Update Program Dropdowns
        // ========================
        function updatePrograms(departmentId) {
            const selects = [
                document.querySelector('select[name="primary_program_id"]'),
                document.querySelector('select[name="secondary_program_id"]')
            ];

            selects.forEach(select => {
                if (!select) return;
                const current = select.value;
                select.innerHTML = '<option value="">Select Program</option>';

                if (!departmentId) return;

                const progs = window.programDepartments[departmentId] || [];
                progs.forEach(p => {
                    const opt = new Option(p.name, p.id);
                    if (p.id == current) opt.selected = true;
                    select.add(opt);
                });
            });
        }

        // ========================
        // Form Submission
        // ========================
        // Form submission handler - UPDATED with better error handling
        document.addEventListener('DOMContentLoaded', function() {
            const addUserForm = document.getElementById('addUserForm');

            if (addUserForm) {
                addUserForm.addEventListener('submit', function(e) {
                    e.preventDefault();

                    console.log('Form submitted');

                    const formData = new FormData(this);
                    const submitButton = this.querySelector('button[type="submit"]');
                    const originalText = submitButton.textContent;

                    // Show loading state
                    submitButton.textContent = 'Adding User...';
                    submitButton.disabled = true;

                    fetch('/admin/users?action=add', {
                            method: 'POST',
                            body: formData
                        })
                        .then(response => {
                            console.log('Response status:', response.status);

                            // Check if response is JSON
                            const contentType = response.headers.get('content-type');
                            if (!contentType || !contentType.includes('application/json')) {
                                throw new Error('Server returned non-JSON response');
                            }
                            return response.json();
                        })
                        .then(data => {
                            console.log('Response data:', data);

                            if (data.success) {
                                closeAddUserModal();
                                showTempPassword(data.temporary_password, formData.get('username'));
                                setTimeout(() => {
                                    location.reload();
                                }, 3000);
                            } else {
                                showErrorModal('Error Adding User', data.error || data.message || 'Unknown error occurred');
                            }
                        })
                        .catch(error => {
                            console.error('Fetch error:', error);
                            showErrorModal('Network Error', 'An error occurred while adding the user. Please try again.');
                        })
                        .finally(() => {
                            // Restore button state
                            submitButton.textContent = originalText;
                            submitButton.disabled = false;
                        });
                });

                console.log('✅ Form submit handler attached');
            } else {
                console.error('❌ Add user form not found');
            }
        });

        // ========================
        // Temporary Password Modal
        // ========================
        function showTempPassword(password, username) {
            document.getElementById('tempUsername').textContent = 'Username: ' + username;
            document.getElementById('tempPassword').textContent = password;
            document.getElementById('tempPasswordModal').classList.remove('hidden');
            document.body.style.overflow = 'hidden';
        }

        function closeTempPasswordModal() {
            document.getElementById('tempPasswordModal').classList.add('hidden');
            document.body.style.overflow = 'auto';
        }

        // ========================
        // User Actions (Disable, Decline, etc.)
        // ========================
        function disableUser(id, name) {
            currentUserId = id;
            document.getElementById('disableUserName').textContent = name;
            document.getElementById('disableUserModal').classList.remove('hidden');
            document.body.style.overflow = 'hidden';
        }

        function closeDisableUserModal() {
            document.getElementById('disableUserModal').classList.add('hidden');
            document.body.style.overflow = 'auto';
            currentUserId = null;
        }

        function confirmDisableUser() {
            if (!currentUserId) return;
            fetch(`/admin/users?action=disable&user_id=${currentUserId}`, {
                    method: 'POST',
                    headers: {
                        'X-CSRF-Token': '<?php echo htmlspecialchars($csrfToken); ?>'
                    }
                })
                .then(r => r.json())
                .then(d => {
                    if (d.success) location.reload();
                })
                .catch(() => alert('Error'));
        }

        function declineUser(id, name) {
            currentUserId = id;
            document.getElementById('declineUserName').textContent = name;
            document.getElementById('declineUserModal').classList.remove('hidden');
            document.body.style.overflow = 'hidden';
        }

        function closeDeclineUserModal() {
            document.getElementById('declineUserModal').classList.add('hidden');
            document.body.style.overflow = 'auto';
            currentUserId = null;
        }

        function confirmDeclineUser() {
            if (!currentUserId) return;
            fetch(`/admin/users?action=decline&user_id=${currentUserId}`, {
                    method: 'POST',
                    headers: {
                        'X-CSRF-Token': '<?php echo htmlspecialchars($csrfToken); ?>'
                    }
                })
                .then(r => r.json())
                .then(d => {
                    if (d.success) location.reload();
                })
                .catch(() => alert('Error'));
        }

        // Replace approveUser function
        function approveUser(userId, userName) {
            showConfirmationModal(
                'Approve User',
                `Are you sure you want to approve ${userName}?`,
                () => {
                    fetch(`/admin/users?action=approve&user_id=${userId}`, {
                            method: 'POST',
                            headers: {
                                'Content-Type': 'application/json',
                                'X-Requested-With': 'XMLHttpRequest',
                                'X-CSRF-Token': '<?php echo htmlspecialchars($csrfToken, ENT_QUOTES, 'UTF-8'); ?>'
                            }
                        })
                        .then(response => {
                            const contentType = response.headers.get('content-type');
                            if (!contentType || !contentType.includes('application/json')) {
                                throw new Error('Server returned non-JSON response');
                            }
                            return response.json();
                        })
                        .then(data => {
                            if (data.success) {
                                location.reload();
                            } else {
                                showErrorModal('Approval Failed', data.message || 'Unknown error occurred');
                            }
                        })
                        .catch(error => {
                            console.error('Error:', error);
                            showErrorModal('Network Error', 'An error occurred while approving the user');
                        });
                }
            );
        }

        // Replace resetPassword function
        function resetPassword(userId) {
            showConfirmationModal(
                'Reset Password',
                'Are you sure you want to reset this user\'s password? They will receive a new temporary password.',
                () => {
                    fetch(`/admin/users?action=reset_password&user_id=${userId}`, {
                            method: 'POST',
                            headers: {
                                'Content-Type': 'application/json',
                                'X-Requested-With': 'XMLHttpRequest',
                                'X-CSRF-Token': '<?php echo htmlspecialchars($csrfToken, ENT_QUOTES, 'UTF-8'); ?>'
                            }
                        })
                        .then(response => {
                            const contentType = response.headers.get('content-type');
                            if (!contentType || !contentType.includes('application/json')) {
                                throw new Error('Server returned non-JSON response');
                            }
                            return response.json();
                        })
                        .then(data => {
                            if (data.success) {
                                showTempPassword(data.temporary_password, data.username);
                            } else {
                                showErrorModal('Password Reset Failed', data.error || 'Unknown error occurred');
                            }
                        })
                        .catch(error => {
                            console.error('Error:', error);
                            showErrorModal('Network Error', 'An error occurred while resetting the password');
                        });
                }
            );
        }

        // Add Confirmation Modal Function
        function showConfirmationModal(title, message, onConfirm) {
            const modal = document.createElement('div');
            modal.className = 'fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50';
            modal.innerHTML = `
        <div class="bg-white rounded-lg max-w-md w-full mx-4">
            <div class="flex items-center gap-3 p-6 border-b border-gray-200">
                <div class="flex-shrink-0 w-10 h-10 bg-yellow-100 rounded-full flex items-center justify-center">
                    <svg class="w-5 h-5 text-yellow-600" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                        <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-2.5L13.732 4c-.77-.833-1.964-.833-2.732 0L3.732 16.5c-.77.833.192 2.5 1.732 2.5z"/>
                    </svg>
                </div>
                <h3 class="text-lg font-semibold text-gray-900">${title}</h3>
            </div>
            <div class="p-6">
                <p class="text-gray-600">${message}</p>
            </div>
            <div class="flex justify-end gap-3 p-6 border-t border-gray-200">
                <button onclick="this.closest('.fixed').remove()" class="px-4 py-2 bg-gray-600 text-white rounded-lg hover:bg-gray-700 transition-colors">
                    Cancel
                </button>
                <button onclick="this.closest('.fixed').remove(); ${onConfirm.toString().replace(/\n/g, ' ')}" class="px-4 py-2 bg-yellow-600 text-white rounded-lg hover:bg-yellow-700 transition-colors">
                    Confirm
                </button>
            </div>
        </div>
    `;
            document.body.appendChild(modal);
        }

        // ========================
        // View User Modal
        // ========================
        const usersData = <?php echo json_encode($users); ?>;

        function viewUser(id) {
            const user = usersData.find(u => parseInt(u.user_id) === parseInt(id));
            if (!user) return alert('User not found');

            const safe = (v, f = 'N/A') => (v === null || v === undefined || v === '' || (typeof v === 'string' && v.trim() === '')) ? f : v;

            // Full name
            const fullName = [safe(user.title), safe(user.first_name), safe(user.middle_name), safe(user.last_name), safe(user.suffix)]
                .filter(Boolean).join(' ') || 'No Name';

            const initials = ((user.first_name?.[0] || '') + (user.last_name?.[0] || '')).toUpperCase() || 'UU';

            // Format date
            const formatDate = (dateStr) => {
                if (!dateStr) return 'N/A';
                try {
                    return new Date(dateStr).toLocaleDateString('en-US', {
                        year: 'numeric',
                        month: 'long',
                        day: 'numeric'
                    });
                } catch {
                    return dateStr;
                }
            };

            // Build sections conditionally
            let sections = [];

            // === Basic Info ===
            sections.push(`
        <div class="grid grid-cols-1 md:grid-cols-2 gap-4 mb-6 pb-6 border-b">
            <div><label class="font-medium text-gray-700">Employee ID</label><p class="mt-1">${safe(user.employee_id)}</p></div>
            <div><label class="font-medium text-gray-700">Username</label><p class="mt-1">${safe(user.username)}</p></div>
            <div><label class="font-medium text-gray-700">Email</label><p class="mt-1">${safe(user.email)}</p></div>
            <div><label class="font-medium text-gray-700">Phone</label><p class="mt-1">${safe(user.phone)}</p></div>
            <div><label class="font-medium text-gray-700">Role</label><p class="mt-1">${safe(user.role_name)}</p></div>
            <div><label class="font-medium text-gray-700">Status</label>
                <span class="inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium ${user.is_active ? 'bg-green-100 text-green-800' : 'bg-red-100 text-red-800'}">
                    ${user.is_active ? 'Active' : 'Inactive'}
                </span>
            </div>
        </div>
    `);

            // === College & Department ===
            if (user.college_name || user.department_name) {
                sections.push(`
            <div class="mb-6 pb-6 border-b">
                <h5 class="text-sm font-semibold text-gray-900 mb-3">Assignment</h5>
                <div class="grid grid-cols-1 md:grid-cols-2 gap-4">
                    <div><label class="font-medium text-gray-700">College</label><p class="mt-1">${safe(user.college_name)}</p></div>
                    <div><label class="font-medium text-gray-700">Department</label><p class="mt-1">${safe(user.department_name)}</p></div>
                </div>
            </div>
        `);
            }

            // === Academic Info (Faculty only) ===
            if (user.academic_rank || user.employment_type || user.classification || user.designation) {
                let academicHTML = '';
                if (user.academic_rank) academicHTML += `<div><label class="font-medium text-gray-700">Academic Rank</label><p class="mt-1">${safe(user.academic_rank)}</p></div>`;
                if (user.employment_type) academicHTML += `<div><label class="font-medium text-gray-700">Employment Type</label><p class="mt-1">${safe(user.employment_type)}</p></div>`;
                if (user.classification) academicHTML += `<div><label class="font-medium text-gray-700">Classification</label><p class="mt-1">${safe(user.classification)}</p></div>`;
                if (user.designation) academicHTML += `<div><label class="font-medium text-gray-700">Designation</label><p class="mt-1">${safe(user.designation)}</p></div>`;

                sections.push(`
            <div class="mb-6 pb-6 border-b">
                <h5 class="text-sm font-semibold text-gray-900 mb-3">Academic Information</h5>
                <div class="grid grid-cols-1 md:grid-cols-2 gap-4">${academicHTML}</div>
            </div>
        `);
            }

            // === Educational Background ===
            const edu = [user.bachelor_degree, user.master_degree, user.doctorate_degree, user.post_doctorate_degree].filter(Boolean);
            if (edu.length > 0) {
                let eduHTML = '';
                if (user.bachelor_degree) eduHTML += `<p><span class="font-medium">Bachelor:</span> ${safe(user.bachelor_degree)}</p>`;
                if (user.master_degree) eduHTML += `<p><span class="font-medium">Master's:</span> ${safe(user.master_degree)}</p>`;
                if (user.doctorate_degree) eduHTML += `<p><span class="font-medium">Doctorate:</span> ${safe(user.doctorate_degree)}</p>`;
                if (user.post_doctorate_degree) eduHTML += `<p><span class="font-medium">Post-Doctorate:</span> ${safe(user.post_doctorate_degree)}</p>`;

                sections.push(`
            <div class="mb-6 pb-6 border-b">
                <h5 class="text-sm font-semibold text-gray-900 mb-3">Educational Background</h5>
                <div class="space-y-1">${eduHTML}</div>
            </div>
        `);
            }

            // === Programs ===
            if (user.primary_program_name || user.secondary_program_name) {
                sections.push(`
            <div class="mb-6 pb-6 border-b">
                <h5 class="text-sm font-semibold text-gray-900 mb-3">Programs</h5>
                <div class="grid grid-cols-1 md:grid-cols-2 gap-4">
                    <div><label class="font-medium text-gray-700">Primary</label><p class="mt-1">${safe(user.primary_program_name, 'None')}</p></div>
                    <div><label class="font-medium text-gray-700">Secondary</label><p class="mt-1">${safe(user.secondary_program_name, 'None')}</p></div>
                </div>
            </div>
        `);
            }

            // === Teaching Load (Optional) ===
            const loadFields = [{
                    label: 'Max Hours',
                    value: user.max_hours
                },
                {
                    label: 'Equivalent Teaching Load',
                    value: user.equiv_teaching_load
                },
                {
                    label: 'Lecture Hours',
                    value: user.total_lecture_hours
                },
                {
                    label: 'Lab Hours',
                    value: user.total_laboratory_hours
                },
                {
                    label: 'Lab Hours ×0.75',
                    value: user.total_laboratory_hours_x075
                },
                {
                    label: 'No. of Preparations',
                    value: user.no_of_preparation
                },
                {
                    label: 'Advisory Class',
                    value: user.advisory_class
                },
                {
                    label: 'Actual Teaching Load',
                    value: user.actual_teaching_loads
                },
                {
                    label: 'Total Working Load',
                    value: user.total_working_load
                },
                {
                    label: 'Excess Hours',
                    value: user.excess_hours
                }
            ];

            const loadHTML = loadFields
                .filter(f => f.value != null && f.value !== '')
                .map(f => `<div><label class="font-medium text-gray-700">${f.label}</label><p class="mt-1">${safe(f.value)}</p></div>`)
                .join('');

            if (loadHTML) {
                sections.push(`
            <div class="mb-6 pb-6 border-b">
                <h5 class="text-sm font-semibold text-gray-900 mb-3">Teaching Load</h5>
                <div class="grid grid-cols-1 md:grid-cols-3 gap-4">${loadHTML}</div>
            </div>
        `);
            }

            // === Account Info ===
            sections.push(`
        <div class="grid grid-cols-1 md:grid-cols-2 gap-4">
            <div><label class="font-medium text-gray-700">Account Created</label><p class="mt-1">${formatDate(user.created_at)}</p></div>
            <div><label class="font-medium text-gray-700">Last Updated</label><p class="mt-1">${formatDate(user.updated_at)}</p></div>
        </div>
    `);

            // === Final Modal Content ===
            const content = `
        <div class="flex items-center space-x-4 mb-6 pb-4 border-b">
            ${user.profile_picture ? 
                `<img src="${safe(user.profile_picture)}" alt="Profile" class="h-16 w-16 rounded-full object-cover border-2 border-yellow-400">` :
                `<div class="h-16 w-16 rounded-full bg-yellow-100 flex items-center justify-center border-2 border-yellow-400">
                    <span class="text-xl font-bold text-yellow-600">${initials}</span>
                </div>`
            }
            <div>
                <h4 class="text-lg font-semibold text-gray-900">${fullName}</h4>
                <p class="text-sm text-gray-600">${safe(user.role_name)} • ${safe(user.employee_id)}</p>
            </div>
        </div>

        ${sections.join('')}
    `;

            document.getElementById('userDetailsContent').innerHTML = content;
            document.getElementById('viewUserModal').classList.remove('hidden');
            document.body.style.overflow = 'hidden';
        }

        function closeViewUserModal() {
            document.getElementById('viewUserModal').classList.add('hidden');
            document.body.style.overflow = 'auto';
        }

        // ========================
        // Tab & Filter
        // ========================
        function switchTab(tab) {
            document.querySelectorAll('.tab').forEach(t => t.classList.remove('tab-active'));
            document.getElementById(`tab-${tab}`).classList.add('tab-active');
            document.getElementById('table-title').textContent = `${tab.charAt(0).toUpperCase() + tab.slice(1)} Users`;

            document.querySelectorAll('.user-row').forEach(row => {
                row.style.display = 'none';
                if (tab === 'all') row.style.display = '';
                else if (tab === 'active' && row.classList.contains('active-user')) row.style.display = '';
                else if (tab === 'inactive' && row.classList.contains('inactive-user')) row.style.display = '';
                else if (tab === 'pending' && row.classList.contains('pending-user')) row.style.display = '';
            });

            window.history.pushState({}, '', `?tab=${tab}`);
            filterTable();
        }

        function filterTable() {
            const search = document.getElementById('searchUsers').value.toLowerCase();
            const role = document.getElementById('roleFilter').value.toLowerCase();
            const college = document.getElementById('collegeFilter').value.toLowerCase();

            document.querySelectorAll('.user-row').forEach(row => {
                const text = row.textContent.toLowerCase();
                const visible = text.includes(search) &&
                    (role === '' || row.querySelector('td:nth-child(3)')?.textContent.toLowerCase().includes(role)) &&
                    (college === '' || row.querySelector('td:nth-child(4)')?.textContent.toLowerCase().includes(college));
                row.style.display = visible ? '' : 'none';
            });
        }

        // Error modal function
        function showErrorModal(title, message) {
            const modal = document.createElement('div');
            modal.className = 'fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50';
            modal.innerHTML = `
        <div class="bg-white rounded-lg max-w-md w-full mx-4">
            <div class="flex items-center gap-3 p-6 border-b border-gray-200">
                <div class="flex-shrink-0 w-10 h-10 bg-red-100 rounded-full flex items-center justify-center">
                    <svg class="w-5 h-5 text-red-600" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                        <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-2.5L13.732 4c-.77-.833-1.964-.833-2.732 0L3.732 16.5c-.77.833.192 2.5 1.732 2.5z"/>
                    </svg>
                </div>
                <h3 class="text-lg font-semibold text-gray-900">${title}</h3>
            </div>
            <div class="p-6">
                <p class="text-gray-600">${message}</p>
            </div>
            <div class="flex justify-end gap-3 p-6 border-t border-gray-200">
                <button onclick="this.closest('.fixed').remove()" class="px-4 py-2 bg-gray-600 text-white rounded-lg hover:bg-gray-700 transition-colors">
                    Close
                </button>
            </div>
        </div>
    `;
            document.body.appendChild(modal);
        }

        // Attach filters
        document.getElementById('searchUsers')?.addEventListener('input', filterTable);
        document.getElementById('roleFilter')?.addEventListener('change', filterTable);
        document.getElementById('collegeFilter')?.addEventListener('change', filterTable);

        // Close modals on click outside or ESC
        window.addEventListener('click', e => {
            if (e.target.id.includes('Modal') && e.target.classList.contains('fixed')) {
                e.target.classList.add('hidden');
                document.body.style.overflow = 'auto';
            }
        });

        document.addEventListener('keydown', e => {
            if (e.key === 'Escape') {
                document.querySelectorAll('.fixed.inset-0').forEach(m => m.classList.add('hidden'));
                document.body.style.overflow = 'auto';
            }
        });
    </script>
</div>

<?php
$content = ob_get_clean();
require_once __DIR__ . '/layout.php';
?>