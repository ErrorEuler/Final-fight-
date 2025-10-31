<?php
ob_start();
?>

<style>
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
</style>

<div class="min-h-screen bg-gray-50">
    <!-- Toast Container -->
    <div id="toast-container" class="fixed top-4 right-4 z-50 space-y-2"></div>

    <!-- Modal -->
    <div id="userModal" class="modal fixed inset-0 backdrop-blur-md flex items-center justify-center z-50 hidden">
        <div class="modal-content bg-white rounded-xl shadow-2xl max-w-2xl w-full mx-4 max-h-[90vh] overflow-y-auto">
            <div class="flex justify-between items-center p-6 border-b border-gray-200">
                <h2 id="modalTitle" class="text-xl font-bold text-gray-900">User Information</h2>
                <button onclick="document.getElementById('userModal').classList.add('hidden')" class="text-gray-500 hover:text-gray-700">
                    <i class="fas fa-times text-xl"></i>
                </button>
            </div>
            <div id="modalBody" class="p-6 space-y-6">
                <!-- Dynamic content will be populated here -->
            </div>
        </div>
    </div>

    <!-- Main Content -->
    <main class="flex-1 p-4 md:p-6">
        <!-- Page Header -->
        <div class="mb-6">
            <div class="flex flex-col md:flex-row md:items-center md:justify-between">
                <div>
                    <h1 class="text-2xl font-bold text-gray-900">Faculty Management</h1>
                    <p class="text-gray-600 mt-1">Manage faculty members, program chairs, and pending users</p>
                </div>
                <div class="mt-4 md:mt-0">
                    <div class="bg-white border border-gray-200 rounded-lg px-4 py-2 shadow-sm">
                        <div class="flex items-center space-x-2">
                            <i class="far fa-calendar-alt text-yellow-600"></i>
                            <span class="text-sm font-medium text-gray-700">
                                <?php echo $currentSemester ? htmlspecialchars($currentSemester['semester_name'] . ' ' . $currentSemester['academic_year']) : 'Semester Not Set'; ?>
                            </span>
                        </div>
                    </div>
                </div>
            </div>
        </div>

        <!-- Alerts -->
        <?php if (isset($_SESSION['success'])): ?>
            <div id="successAlert" class="bg-green-50 border-l-4 border-green-500 p-4 rounded-lg shadow-sm mb-6">
                <div class="flex items-center justify-between">
                    <div class="flex items-center">
                        <div class="flex-shrink-0">
                            <i class="fas fa-check-circle text-green-500"></i>
                        </div>
                        <div class="ml-3">
                            <p class="text-sm text-green-700"><?php echo htmlspecialchars($_SESSION['success']); ?></p>
                        </div>
                    </div>
                    <button type="button" onclick="document.getElementById('successAlert').style.display='none'" class="ml-auto pl-3">
                        <i class="fas fa-times text-green-500 hover:text-green-700"></i>
                    </button>
                </div>
            </div>
            <?php unset($_SESSION['success']); ?>
        <?php endif; ?>

        <?php if (isset($_SESSION['error'])): ?>
            <div id="errorAlert" class="bg-red-50 border-l-4 border-red-500 p-4 rounded-lg shadow-sm mb-6">
                <div class="flex items-center justify-between">
                    <div class="flex items-center">
                        <div class="flex-shrink-0">
                            <i class="fas fa-exclamation-circle text-red-500"></i>
                        </div>
                        <div class="ml-3">
                            <p class="text-sm text-red-700"><?php echo htmlspecialchars($_SESSION['error']); ?></p>
                        </div>
                    </div>
                    <button type="button" onclick="document.getElementById('errorAlert').style.display='none'" class="ml-auto pl-3">
                        <i class="fas fa-times text-red-500 hover:text-red-700"></i>
                    </button>
                </div>
            </div>
            <?php unset($_SESSION['error']); ?>
        <?php endif; ?>

        <?php if ($error): ?>
            <div id="errorAlert" class="bg-red-50 border-l-4 border-red-500 p-4 rounded-lg shadow-sm mb-6">
                <div class="flex items-center justify-between">
                    <div class="flex items-center">
                        <div class="flex-shrink-0">
                            <i class="fas fa-exclamation-circle text-red-500"></i>
                        </div>
                        <div class="ml-3">
                            <p class="text-sm text-red-700"><?php echo htmlspecialchars($error); ?></p>
                        </div>
                    </div>
                    <button type="button" onclick="document.getElementById('errorAlert').style.display='none'" class="ml-auto pl-3">
                        <i class="fas fa-times text-red-500 hover:text-red-700"></i>
                    </button>
                </div>
            </div>
        <?php endif; ?>

        <!-- Filters Card -->
        <div class="bg-white rounded-xl shadow-sm border border-gray-200 p-4 md:p-6 mb-6">
            <div class="flex flex-col lg:flex-row lg:items-end lg:justify-between space-y-4 lg:space-y-0">
                <div class="flex-1">
                    <h3 class="text-lg font-semibold text-gray-900 mb-4">Filter Faculty</h3>
                    <div class="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
                        <!-- Department Filter -->
                        <div>
                            <label for="departmentFilter" class="block text-sm font-medium text-gray-700 mb-1">Department</label>
                            <select id="departmentFilter" class="w-full px-3 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-yellow-500 focus:border-yellow-500 transition-colors bg-white">
                                <option value="all">All Departments</option>
                                <?php foreach ($departments as $dept): ?>
                                    <option value="<?php echo $dept['department_id']; ?>">
                                        <?php echo htmlspecialchars($dept['department_name']); ?>
                                    </option>
                                <?php endforeach; ?>
                            </select>
                        </div>

                        <!-- Status Filter -->
                        <div>
                            <label for="statusFilter" class="block text-sm font-medium text-gray-700 mb-1">Status</label>
                            <select id="statusFilter" class="w-full px-3 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-yellow-500 focus:border-yellow-500 transition-colors bg-white">
                                <option value="all">All Statuses</option>
                                <option value="active">Active</option>
                                <option value="inactive">Inactive</option>
                            </select>
                        </div>

                        <!-- Search -->
                        <div class="md:col-span-2 lg:col-span-1">
                            <label for="searchInput" class="block text-sm font-medium text-gray-700 mb-1">Search</label>
                            <div class="relative">
                                <input type="text" id="searchInput" placeholder="Search by name..."
                                    class="w-full pl-10 pr-4 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-yellow-500 focus:border-yellow-500 transition-colors">
                                <div class="absolute inset-y-0 left-0 flex items-center pl-3">
                                    <i class="fas fa-search text-gray-400"></i>
                                </div>
                            </div>
                        </div>

                        <!-- Clear Filters -->
                        <div class="flex items-end">
                            <button id="clearFilters" class="w-full px-4 py-2 bg-gray-200 text-gray-700 rounded-lg hover:bg-gray-300 transition-colors font-medium">
                                <i class="fas fa-times mr-2"></i>Clear Filters
                            </button>
                        </div>
                    </div>
                </div>
            </div>
        </div>

        <!-- Tabs Navigation -->
        <div class="bg-white rounded-xl shadow-sm border border-gray-200 mb-6 overflow-x-auto">
            <div class="border-b border-gray-200 min-w-max">
                <nav class="flex space-x-8 px-4 md:px-6" aria-label="Tabs">
                    <button id="tab-chairs" class="tab-button py-4 px-1 border-b-2 font-medium text-sm flex items-center space-x-2 transition-colors border-yellow-500 text-yellow-600 whitespace-nowrap">
                        <i class="fas fa-user-tie"></i>
                        <span>Program Chairs</span>
                        <span id="chairs-badge" class="bg-yellow-100 text-yellow-800 text-xs rounded-full px-2 py-1"><?php echo count($programChairs); ?></span>
                    </button>
                    <button id="tab-faculty" class="tab-button py-4 px-1 border-b-2 font-medium text-sm flex items-center space-x-2 transition-colors border-transparent text-gray-500 hover:text-gray-700 whitespace-nowrap">
                        <i class="fas fa-chalkboard-teacher"></i>
                        <span>Faculty Members</span>
                        <span id="faculty-badge" class="bg-gray-100 text-gray-800 text-xs rounded-full px-2 py-1"><?php echo count($faculty); ?></span>
                    </button>
                    <button id="tab-pending" class="tab-button py-4 px-1 border-b-2 font-medium text-sm flex items-center space-x-2 transition-colors border-transparent text-gray-500 hover:text-gray-700 whitespace-nowrap">
                        <i class="fas fa-user-plus"></i>
                        <span>Pending Users</span>
                        <?php if (!empty($pendingUsers)): ?>
                            <span id="pending-badge" class="bg-red-100 text-red-800 text-xs rounded-full px-2 py-1"><?php echo count($pendingUsers); ?></span>
                        <?php else: ?>
                            <span id="pending-badge" class="bg-gray-100 text-gray-800 text-xs rounded-full px-2 py-1">0</span>
                        <?php endif; ?>
                    </button>
                </nav>
            </div>
        </div>

        <!-- Tab Content -->
        <div id="tab-content">
            <!-- Program Chairs Section -->
            <div id="chairs-content" class="tab-content">
                <div class="bg-white rounded-xl shadow-sm border border-gray-200 overflow-hidden">
                    <div class="px-4 md:px-6 py-4 border-b border-gray-200 bg-gray-50">
                        <div class="flex flex-col sm:flex-row sm:items-center sm:justify-between">
                            <h2 class="text-lg font-semibold text-gray-900">Program Chairs</h2>
                            <div class="mt-2 sm:mt-0 text-sm text-gray-600">
                                <span id="chairs-count" class="font-medium"><?php echo count($programChairs); ?></span> total chairs
                            </div>
                        </div>
                    </div>
                    <div class="overflow-x-auto">
                        <table class="min-w-full divide-y divide-gray-200" id="programChairsTable">
                            <thead class="bg-gray-50">
                                <tr>
                                    <th scope="col" class="px-4 md:px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Name</th>
                                    <th scope="col" class="px-4 md:px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Program</th>
                                    <th scope="col" class="px-4 md:px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Department</th>
                                    <th scope="col" class="px-4 md:px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Status</th>
                                    <th scope="col" class="px-4 md:px-6 py-3 text-right text-xs font-medium text-gray-500 uppercase tracking-wider">Actions</th>
                                </tr>
                            </thead>
                            <tbody class="bg-white divide-y divide-gray-200" id="chairs-tbody">
                                <?php if (empty($programChairs)): ?>
                                    <tr>
                                        <td colspan="5" class="px-4 md:px-6 py-12 text-center">
                                            <div class="flex flex-col items-center justify-center text-gray-400">
                                                <i class="fas fa-user-tie text-4xl mb-3"></i>
                                                <p class="text-lg font-medium">No program chairs found</p>
                                                <p class="text-sm">Program chairs will appear here once assigned</p>
                                            </div>
                                        </td>
                                    </tr>
                                <?php else: ?>
                                    <?php foreach ($programChairs as $chair): ?>
                                        <tr class="hover:bg-gray-50 transition-colors table-row chair-row"
                                            data-department="<?php echo $chair['department_id']; ?>"
                                            data-status="<?php echo $chair['is_active'] ? 'active' : 'inactive'; ?>"
                                            data-name="<?php echo htmlspecialchars(strtolower($chair['title'] . ' ' . $chair['last_name'] . ' ' . $chair['first_name'])); ?>"
                                            data-user-id="<?php echo $chair['user_id']; ?>">
                                            <!-- In the table rows, replace the profile picture section with this: -->
                                            <td class="px-4 md:px-6 py-4 whitespace-nowrap cursor-pointer" onclick="showUserModal(<?php echo $chair['user_id']; ?>, 'chair')">
                                                <div class="flex items-center">
                                                    <div class="flex-shrink-0 h-10 w-10">
                                                        <?php
                                                        $profilePicture = $chair['profile_picture'] ?? null;
                                                        $profilePath = null;

                                                        if (!empty($profilePicture)) {
                                                            // Check if it's already a full path or relative path
                                                            if (strpos($profilePicture, '/') === 0) {
                                                                $profilePath = $profilePicture; // Absolute path
                                                            } else {
                                                                $profilePath = '/uploads/profile_pictures/' . $profilePicture; // Relative path
                                                            }

                                                            // Check if file exists
                                                            $fullPath = $_SERVER['DOCUMENT_ROOT'] . $profilePath;
                                                            if (file_exists($fullPath) && is_file($fullPath)) {
                                                        ?>
                                                                <img src="<?php echo htmlspecialchars($profilePath); ?>"
                                                                    alt="Profile"
                                                                    class="h-10 w-10 rounded-full object-cover">
                                                            <?php
                                                            } else {
                                                                // File doesn't exist, show initials
                                                                $initials = strtoupper(substr($chair['first_name'], 0, 1) . substr($chair['last_name'], 0, 1));
                                                            ?>
                                                                <div class="h-10 w-10 bg-gradient-to-br from-yellow-400 to-yellow-600 rounded-full flex items-center justify-center text-white font-medium">
                                                                    <?php echo $initials; ?>
                                                                </div>
                                                            <?php
                                                            }
                                                        } else {
                                                            // No profile picture in database, show initials
                                                            $initials = strtoupper(substr($chair['first_name'], 0, 1) . substr($chair['last_name'], 0, 1));
                                                            ?>
                                                            <div class="h-10 w-10 bg-gradient-to-br from-yellow-400 to-yellow-600 rounded-full flex items-center justify-center text-white font-medium">
                                                                <?php echo $initials; ?>
                                                            </div>
                                                        <?php
                                                        }
                                                        ?>
                                                    </div>
                                                    <div class="ml-4">
                                                        <div class="text-sm font-medium text-gray-900"><?php echo htmlspecialchars($chair['last_name'] . ', ' . $chair['first_name']); ?></div>
                                                        <div class="text-sm text-gray-500"><?php echo htmlspecialchars($chair['email']); ?></div>
                                                    </div>
                                                </div>
                                            </td>
                                            <td class="px-4 md:px-6 py-4 whitespace-nowrap text-sm text-gray-900"><?php echo htmlspecialchars($chair['program_name']); ?></td>
                                            <td class="px-4 md:px-6 py-4 whitespace-nowrap text-sm text-gray-900"><?php echo htmlspecialchars($chair['department_name']); ?></td>
                                            <td class="px-4 md:px-6 py-4 whitespace-nowrap">
                                                <span class="inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium <?php echo $chair['is_active'] ? 'bg-green-100 text-green-800' : 'bg-red-100 text-red-800'; ?>">
                                                    <span class="h-1.5 w-1.5 rounded-full <?php echo $chair['is_active'] ? 'bg-green-500' : 'bg-red-500'; ?> mr-1.5"></span>
                                                    <?php echo $chair['is_active'] ? 'Active' : 'Inactive'; ?>
                                                </span>
                                            </td>
                                            <td class="px-4 md:px-6 py-4 whitespace-nowrap text-right text-sm font-medium">
                                                <div class="flex justify-end space-x-2">
                                                    <form method="POST" class="inline action-form">
                                                        <input type="hidden" name="user_id" value="<?php echo $chair['user_id']; ?>">
                                                        <input type="hidden" name="action" value="<?php echo $chair['is_active'] ? 'deactivate' : 'activate'; ?>">
                                                        <button type="submit" class="inline-flex items-center px-3 py-1.5 border border-transparent text-xs font-medium rounded-md shadow-sm text-white <?php echo $chair['is_active'] ? 'bg-red-600 hover:bg-red-700' : 'bg-green-600 hover:bg-green-700'; ?> focus:outline-none focus:ring-2 focus:ring-offset-2 <?php echo $chair['is_active'] ? 'focus:ring-red-500' : 'focus:ring-green-500'; ?> transition-colors">
                                                            <?php if ($chair['is_active']): ?>
                                                                <i class="fas fa-user-times mr-1.5"></i> Deactivate
                                                            <?php else: ?>
                                                                <i class="fas fa-user-check mr-1.5"></i> Activate
                                                            <?php endif; ?>
                                                        </button>
                                                    </form>
                                                    <form method="POST" class="inline action-form">
                                                        <input type="hidden" name="user_id" value="<?php echo $chair['user_id']; ?>">
                                                        <input type="hidden" name="action" value="demote">
                                                        <button type="submit" class="inline-flex items-center px-3 py-1.5 border border-transparent text-xs font-medium rounded-md shadow-sm text-white bg-yellow-600 hover:bg-yellow-700 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-yellow-500 transition-colors">
                                                            <i class="fas fa-arrow-down mr-1.5"></i> Demote
                                                        </button>
                                                    </form>
                                                </div>
                                            </td>
                                        </tr>
                                    <?php endforeach; ?>
                                <?php endif; ?>
                            </tbody>
                        </table>
                    </div>
                </div>
            </div>

            <!-- Faculty Members Section -->
            <div id="faculty-content" class="tab-content hidden">
                <div class="bg-white rounded-xl shadow-sm border border-gray-200 overflow-hidden">
                    <div class="px-4 md:px-6 py-4 border-b border-gray-200 bg-gray-50">
                        <div class="flex flex-col sm:flex-row sm:items-center sm:justify-between">
                            <h2 class="text-lg font-semibold text-gray-900">Faculty Members</h2>
                            <div class="mt-2 sm:mt-0 text-sm text-gray-600">
                                <span id="faculty-count" class="font-medium"><?php echo count($faculty); ?></span> total faculty
                            </div>
                        </div>
                    </div>
                    <div class="overflow-x-auto">
                        <table class="min-w-full divide-y divide-gray-200" id="facultyTable">
                            <thead class="bg-gray-50">
                                <tr>
                                    <th scope="col" class="px-4 md:px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Name</th>
                                    <th scope="col" class="px-4 md:px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Academic Rank</th>
                                    <th scope="col" class="px-4 md:px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Employment Type</th>
                                    <th scope="col" class="px-4 md:px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Department</th>
                                    <th scope="col" class="px-4 md:px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Status</th>
                                    <th scope="col" class="px-4 md:px-6 py-3 text-right text-xs font-medium text-gray-500 uppercase tracking-wider">Actions</th>
                                </tr>
                            </thead>
                            <tbody class="bg-white divide-y divide-gray-200" id="faculty-tbody">
                                <?php if (empty($faculty)): ?>
                                    <tr>
                                        <td colspan="6" class="px-4 md:px-6 py-12 text-center">
                                            <div class="flex flex-col items-center justify-center text-gray-400">
                                                <i class="fas fa-chalkboard-teacher text-4xl mb-3"></i>
                                                <p class="text-lg font-medium">No faculty members found</p>
                                                <p class="text-sm">Faculty members will appear here once added</p>
                                            </div>
                                        </td>
                                    </tr>
                                <?php else: ?>
                                    <?php foreach ($faculty as $member): ?>
                                        <tr class="hover:bg-gray-50 transition-colors table-row faculty-row"
                                            data-department="<?php echo $member['department_id']; ?>"
                                            data-status="<?php echo $member['is_active'] ? 'active' : 'inactive'; ?>"
                                            data-name="<?php echo htmlspecialchars(strtolower($member['title'] . ' ' . $member['last_name'] . ' ' . $member['first_name'])); ?>"
                                            data-user-id="<?php echo $member['user_id']; ?>">
                                            <!-- In the table rows, replace the profile picture section with this: -->
                                            <td class="px-4 md:px-6 py-4 whitespace-nowrap cursor-pointer" onclick="showUserModal(<?php echo $member['user_id']; ?>, 'faculty')">
                                                <div class="flex items-center">
                                                    <div class="flex-shrink-0 h-10 w-10">
                                                        <?php
                                                        $profilePicture = $member['profile_picture'] ?? null;
                                                        $profilePath = null;

                                                        if (!empty($profilePicture)) {
                                                            // Check if it's already a full path or relative path
                                                            if (strpos($profilePicture, '/') === 0) {
                                                                $profilePath = $profilePicture; // Absolute path
                                                            } else {
                                                                $profilePath = '/uploads/profile_pictures/' . $profilePicture; // Relative path
                                                            }

                                                            // Check if file exists
                                                            $fullPath = $_SERVER['DOCUMENT_ROOT'] . $profilePath;
                                                            if (file_exists($fullPath) && is_file($fullPath)) {
                                                        ?>
                                                                <img src="<?php echo htmlspecialchars($profilePath); ?>"
                                                                    alt="Profile"
                                                                    class="h-10 w-10 rounded-full object-cover">
                                                            <?php
                                                            } else {
                                                                // File doesn't exist, show initials
                                                                $initials = strtoupper(substr($member['first_name'], 0, 1) . substr($member['last_name'], 0, 1));
                                                            ?>
                                                                <div class="h-10 w-10 bg-gradient-to-br from-yellow-400 to-yellow-600 rounded-full flex items-center justify-center text-white font-medium">
                                                                    <?php echo $initials; ?>
                                                                </div>
                                                            <?php
                                                            }
                                                        } else {
                                                            // No profile picture in database, show initials
                                                            $initials = strtoupper(substr($member['first_name'], 0, 1) . substr($member['last_name'], 0, 1));
                                                            ?>
                                                            <div class="h-10 w-10 bg-gradient-to-br from-yellow-400 to-yellow-600 rounded-full flex items-center justify-center text-white font-medium">
                                                                <?php echo $initials; ?>
                                                            </div>
                                                        <?php
                                                        }
                                                        ?>
                                                    </div>
                                                    <div class="ml-4">
                                                        <div class="text-sm font-medium text-gray-900"><?php echo htmlspecialchars($member['last_name'] . ', ' . $member['first_name']); ?></div>
                                                        <div class="text-sm text-gray-500"><?php echo htmlspecialchars($member['email']); ?></div>
                                                    </div>
                                                </div>
                                            </td>
                                            <td class="px-4 md:px-6 py-4 whitespace-nowrap text-sm text-gray-900"><?php echo htmlspecialchars($member['academic_rank']); ?></td>
                                            <td class="px-4 md:px-6 py-4 whitespace-nowrap">
                                                <span class="inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium <?php echo $member['employment_type'] == 'Full-time' ? 'bg-blue-100 text-blue-800' : 'bg-purple-100 text-purple-800'; ?>">
                                                    <?php echo htmlspecialchars($member['employment_type']); ?>
                                                </span>
                                            </td>
                                            <td class="px-4 md:px-6 py-4 whitespace-nowrap text-sm text-gray-900"><?php echo htmlspecialchars($member['department_name']); ?></td>
                                            <td class="px-4 md:px-6 py-4 whitespace-nowrap">
                                                <span class="inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium <?php echo $member['is_active'] ? 'bg-green-100 text-green-800' : 'bg-red-100 text-red-800'; ?>">
                                                    <span class="h-1.5 w-1.5 rounded-full <?php echo $member['is_active'] ? 'bg-green-500' : 'bg-red-500'; ?> mr-1.5"></span>
                                                    <?php echo $member['is_active'] ? 'Active' : 'Inactive'; ?>
                                                </span>
                                            </td>
                                            <td class="px-4 md:px-6 py-4 whitespace-nowrap text-right text-sm font-medium">
                                                <div class="flex justify-end space-x-2">
                                                    <form method="POST" class="inline action-form">
                                                        <input type="hidden" name="user_id" value="<?php echo $member['user_id']; ?>">
                                                        <input type="hidden" name="action" value="<?php echo $member['is_active'] ? 'deactivate' : 'activate'; ?>">
                                                        <button type="submit" class="inline-flex items-center px-3 py-1.5 border border-transparent text-xs font-medium rounded-md shadow-sm text-white <?php echo $member['is_active'] ? 'bg-red-600 hover:bg-red-700' : 'bg-green-600 hover:bg-green-700'; ?> focus:outline-none focus:ring-2 focus:ring-offset-2 <?php echo $member['is_active'] ? 'focus:ring-red-500' : 'focus:ring-green-500'; ?> transition-colors">
                                                            <?php if ($member['is_active']): ?>
                                                                <i class="fas fa-user-times mr-1.5"></i> Deactivate
                                                            <?php else: ?>
                                                                <i class="fas fa-user-check mr-1.5"></i> Activate
                                                            <?php endif; ?>
                                                        </button>
                                                    </form>
                                                    <?php if ($member['department_id'] > 0): ?>
                                                        <form method="POST" class="inline action-form">
                                                            <input type="hidden" name="user_id" value="<?php echo $member['user_id']; ?>">
                                                            <input type="hidden" name="action" value="promote">
                                                            <input type="hidden" name="department_id" value="<?php echo $member['department_id']; ?>">
                                                            <button type="submit" class="inline-flex items-center px-3 py-1.5 border border-transparent text-xs font-medium rounded-md shadow-sm text-white bg-blue-600 hover:bg-blue-700 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-blue-500 transition-colors">
                                                                <i class="fas fa-arrow-up mr-1.5"></i> Promote
                                                            </button>
                                                        </form>
                                                    <?php else: ?>
                                                        <span class="text-gray-400 text-xs italic">No department assigned</span>
                                                    <?php endif; ?>
                                                </div>
                                            </td>
                                        </tr>
                                    <?php endforeach; ?>
                                <?php endif; ?>
                            </tbody>
                        </table>
                    </div>
                </div>
            </div>

            <!-- Pending Users Section -->
            <div id="pending-content" class="tab-content hidden">
                <div class="bg-white rounded-xl shadow-sm border border-gray-200 overflow-hidden">
                    <div class="px-4 md:px-6 py-4 border-b border-gray-200 bg-gray-50">
                        <div class="flex flex-col sm:flex-row sm:items-center sm:justify-between">
                            <h2 class="text-lg font-semibold text-gray-900">Pending Users</h2>
                            <div class="mt-2 sm:mt-0 text-sm text-gray-600">
                                <span id="pending-count" class="font-medium"><?php echo count($pendingUsers); ?></span> pending approval
                            </div>
                        </div>
                    </div>
                    <div class="overflow-x-auto">
                        <table class="min-w-full divide-y divide-gray-200" id="pendingTable">
                            <thead class="bg-gray-50">
                                <tr>
                                    <th scope="col" class="px-4 md:px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Name</th>
                                    <th scope="col" class="px-4 md:px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Role</th>
                                    <th scope="col" class="px-4 md:px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Department</th>
                                    <th scope="col" class="px-4 md:px-6 py-3 text-right text-xs font-medium text-gray-500 uppercase tracking-wider">Actions</th>
                                </tr>
                            </thead>
                            <tbody class="bg-white divide-y divide-gray-200" id="pending-tbody">
                                <?php if (empty($pendingUsers)): ?>
                                    <tr>
                                        <td colspan="4" class="px-4 md:px-6 py-12 text-center">
                                            <div class="flex flex-col items-center justify-center text-gray-400">
                                                <i class="fas fa-clipboard-check text-4xl mb-3"></i>
                                                <p class="text-lg font-medium">No pending users</p>
                                                <p class="text-sm">All users have been approved</p>
                                            </div>
                                        </td>
                                    </tr>
                                <?php else: ?>
                                    <?php foreach ($pendingUsers as $user): ?>
                                        <tr class="hover:bg-gray-50 transition-colors pending-row"
                                            data-department="<?php echo $user['department_id']; ?>"
                                            data-name="<?php echo htmlspecialchars(strtolower($user['last_name'] . ' ' . $user['first_name'])); ?>"
                                            data-user-id="<?php echo $user['user_id']; ?>">
                                            <td class="px-4 md:px-6 py-4 whitespace-nowrap cursor-pointer" onclick="showUserModal(<?php echo $user['user_id']; ?>, 'pending')">
                                                <div class="flex items-center">
                                                    <div class="flex-shrink-0 h-10 w-10 bg-gradient-to-br from-yellow-400 to-yellow-600 rounded-full flex items-center justify-center text-white font-medium">
                                                        <?php echo strtoupper(substr($user['first_name'], 0, 1) . substr($user['last_name'], 0, 1)); ?>
                                                    </div>
                                                    <div class="ml-4">
                                                        <div class="text-sm font-medium text-gray-900"><?php echo htmlspecialchars($user['last_name'] . ', ' . $user['first_name']); ?></div>
                                                        <div class="text-sm text-gray-500"><?php echo htmlspecialchars($user['email']); ?></div>
                                                    </div>
                                                </div>
                                            </td>
                                            <td class="px-4 md:px-6 py-4 whitespace-nowrap text-sm text-gray-900"><?php echo htmlspecialchars($user['role_name']); ?></td>
                                            <td class="px-4 md:px-6 py-4 whitespace-nowrap text-sm text-gray-900"><?php echo htmlspecialchars($user['department_name']); ?></td>
                                            <td class="px-4 md:px-6 py-4 whitespace-nowrap text-right text-sm font-medium">
                                                <div class="flex justify-end space-x-2">
                                                    <form method="POST" class="inline action-form">
                                                        <input type="hidden" name="user_id" value="<?php echo $user['user_id']; ?>">
                                                        <input type="hidden" name="action" value="activate">
                                                        <button type="submit" class="inline-flex items-center px-3 py-1.5 border border-transparent text-xs font-medium rounded-md shadow-sm text-white bg-green-600 hover:bg-green-700 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-green-500 transition-colors">
                                                            <i class="fas fa-check mr-1.5"></i> Approve
                                                        </button>
                                                    </form>
                                                    <form method="POST" class="inline action-form">
                                                        <input type="hidden" name="user_id" value="<?php echo $user['user_id']; ?>">
                                                        <input type="hidden" name="action" value="deactivate">
                                                        <button type="submit" class="inline-flex items-center px-3 py-1.5 border border-transparent text-xs font-medium rounded-md shadow-sm text-white bg-red-600 hover:bg-red-700 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-red-500 transition-colors">
                                                            <i class="fas fa-times mr-1.5"></i> Reject
                                                        </button>
                                                    </form>
                                                </div>
                                            </td>
                                        </tr>
                                    <?php endforeach; ?>
                                <?php endif; ?>
                            </tbody>
                        </table>
                    </div>
                </div>
            </div>
        </div>
    </main>
</div>

<script>
    // Show toast notification
    function showToast(message, bgColor) {
        const toast = document.createElement('div');
        toast.className = `${bgColor} text-white px-6 py-3 rounded-lg shadow-lg flex items-center justify-between min-w-80 transform transition-transform duration-300 translate-x-full`;
        toast.innerHTML = `
            <div class="flex items-center">
                <i class="fas ${bgColor.includes('green') ? 'fa-check-circle' : 'fa-exclamation-circle'} mr-3"></i>
                <span>${message}</span>
            </div>
            <button onclick="this.parentElement.remove()" class="ml-4 text-white hover:text-gray-200">
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

    function showUserModal(userId, type) {
        const modal = document.getElementById('userModal');
        const modalTitle = document.getElementById('modalTitle');
        const modalBody = document.getElementById('modalBody');
        let userData = null;

        // User data mapping - fixed version
        const userDataMap = <?php
            $allUsers = array_merge($programChairs, $faculty, $pendingUsers);
            $userDataArray = [];
            foreach ($allUsers as $user) {
                $userDataArray[$user['user_id']] = [
                    'user_id' => $user['user_id'],
                    'employee_id' => $user['employee_id'] ?? 'N/A',
                    'email' => $user['email'] ?? 'N/A',
                    'title' => $user['title'] ?? '',
                    'first_name' => $user['first_name'] ?? 'Unknown',
                    'middle_name' => $user['middle_name'] ?? '',
                    'last_name' => $user['last_name'] ?? 'Unknown',
                    'suffix' => $user['suffix'] ?? '',
                    'profile_picture' => $user['profile_picture'] ?? null,
                    'is_active' => $user['is_active'] ?? false,
                    'program_name' => $user['program_name'] ?? 'N/A',
                    'department_name' => $user['department_name'] ?? 'N/A',
                    'college_name' => $user['college_name'] ?? 'N/A',
                    'academic_rank' => $user['academic_rank'] ?? 'N/A',
                    'employment_type' => $user['employment_type'] ?? 'N/A',
                    'specialization' => $user['specialization'] ?? 'N/A',
                    'expertise_level' => $user['expertise_level'] ?? 'N/A',
                    'role_name' => $user['role_name'] ?? 'N/A'
                ];
            }
            // Output the entire map as a valid JS object literal
            echo json_encode($userDataArray, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
        ?>;

        userData = userDataMap[userId];

        if (!userData) {
            modalBody.innerHTML = '<p class="text-gray-500">User data not found.</p>';
            modal.classList.remove('hidden');
            return;
        }

        // Build profile picture or use Font Awesome avatar
        let profilePictureHtml = '';
        if (userData.profile_picture) {
            let profilePicturePath = '';
            // Check if it's already a full path
            if (userData.profile_picture.startsWith('/')) {
                profilePicturePath = userData.profile_picture;
            } else {
                // Assume it's a filename in the uploads directory
                profilePicturePath = '/uploads/profile_pictures/' + userData.profile_picture;
            }

            profilePictureHtml = `
            <img src="${profilePicturePath}" 
                 alt="Profile of ${userData.first_name} ${userData.last_name}" 
                 class="w-24 h-24 rounded-full object-cover ring-4 ring-gray-50 shadow-md"
                 onerror="this.parentNode.innerHTML = '<div class=\\'w-24 h-24 bg-gradient-to-br from-yellow-400 to-yellow-600 rounded-full flex items-center justify-center text-white ring-4 ring-gray-50 shadow-md\\'><i class=\\'fas fa-user text-3xl\\'></i></div>'">
        `;
        } else {
            // Use Font Awesome avatar with gradient background
            const initials = (userData.first_name?.charAt(0) || '') + (userData.last_name?.charAt(0) || '');
            if (initials) {
                profilePictureHtml = `
                <div class="w-24 h-24 bg-gradient-to-br from-yellow-400 to-yellow-600 rounded-full flex items-center justify-center text-white ring-4 ring-gray-50 shadow-md">
                    <span class="text-xl font-bold">${initials}</span>
                </div>
            `;
            } else {
                profilePictureHtml = `
                <div class="w-24 h-24 bg-gradient-to-br from-yellow-400 to-yellow-600 rounded-full flex items-center justify-center text-white ring-4 ring-gray-50 shadow-md">
                    <i class="fas fa-user text-3xl"></i>
                </div>
            `;
            }
        }

        // Build full name with proper spacing
        const fullName = [
            userData.title,
            userData.first_name,
            userData.middle_name,
            userData.last_name,
            userData.suffix
        ].filter(part => part && part.trim() !== '').join(' ');

        // Determine role-based icon and styling
        let roleIcon = 'fa-user';
        let roleColor = 'from-yellow-400 to-yellow-600';

        if (type === 'chair') {
            roleIcon = 'fa-user-tie';
            roleColor = 'from-blue-400 to-blue-600';
        } else if (type === 'faculty') {
            roleIcon = 'fa-chalkboard-teacher';
            roleColor = 'from-green-400 to-green-600';
        } else if (type === 'pending') {
            roleIcon = 'fa-user-clock';
            roleColor = 'from-gray-400 to-gray-600';
        }

        // Populate modal
        modalBody.innerHTML = `
        <div class="flex items-start space-x-6 mb-6 pb-6 border-b border-gray-200">
            <div class="flex-shrink-0">
                <div class="relative">
                    ${profilePictureHtml}
                    <div class="absolute -bottom-2 -right-2 w-6 h-6 ${userData.is_active ? 'bg-green-500' : 'bg-red-500'} rounded-full border-2 border-white flex items-center justify-center">
                        <i class="fas ${userData.is_active ? 'fa-check' : 'fa-times'} text-white text-xs"></i>
                    </div>
                </div>
            </div>
            <div class="flex-1 min-w-0">
                <h4 class="text-2xl font-semibold text-gray-900 mb-2">${fullName}</h4>
                <div class="flex flex-wrap items-center gap-3 mb-3">
                    <span class="inline-flex items-center px-3 py-1 rounded-full text-xs font-medium bg-gray-100 text-gray-800">
                        <i class="fas ${roleIcon} mr-1.5"></i>${userData.role_name}
                    </span>
                    ${userData.academic_rank !== 'N/A' ? `<span class="inline-flex items-center px-3 py-1 rounded-full text-xs font-medium bg-blue-100 text-blue-800">${userData.academic_rank}</span>` : ''}
                    ${userData.employment_type !== 'N/A' ? `<span class="inline-flex items-center px-3 py-1 rounded-full text-xs font-medium bg-green-100 text-green-800">${userData.employment_type}</span>` : ''}
                </div>
                ${userData.specialization !== 'N/A' ? `<p class="text-sm text-gray-600"><i class="fas fa-graduation-cap mr-2 text-yellow-500"></i>${userData.specialization} ${userData.expertise_level !== 'N/A' ? '• ' + userData.expertise_level : ''}</p>` : ''}
            </div>
        </div>

        <div class="space-y-6">
            <div class="bg-gray-50 rounded-lg p-5">
                <h5 class="flex items-center text-base font-semibold text-gray-900 mb-4">
                    <i class="fas fa-id-card text-blue-500 mr-3"></i> Personal Information
                </h5>
                <div class="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-4">
                    <div class="bg-white rounded-lg p-4 shadow-sm border border-gray-200">
                        <div class="flex items-center mb-2">
                            <i class="fas fa-fingerprint text-gray-400 mr-2"></i>
                            <span class="text-xs font-medium text-gray-500 uppercase">User ID</span>
                        </div>
                        <p class="text-sm font-mono text-gray-900">${userData.user_id}</p>
                    </div>
                    <div class="bg-white rounded-lg p-4 shadow-sm border border-gray-200">
                        <div class="flex items-center mb-2">
                            <i class="fas fa-id-badge text-gray-400 mr-2"></i>
                            <span class="text-xs font-medium text-gray-500 uppercase">Employee ID</span>
                        </div>
                        <p class="text-sm font-mono text-gray-900">${userData.employee_id}</p>
                    </div>
                    <div class="bg-white rounded-lg p-4 shadow-sm border border-gray-200">
                        <div class="flex items-center mb-2">
                            <i class="fas fa-envelope text-gray-400 mr-2"></i>
                            <span class="text-xs font-medium text-gray-500 uppercase">Email</span>
                        </div>
                        <p class="text-sm text-gray-900">
                            ${userData.email !== 'N/A' ? 
                                `<a href="mailto:${userData.email}" class="text-blue-600 hover:text-blue-800 flex items-center">
                                    <i class="fas fa-paper-plane mr-1"></i>${userData.email}
                                </a>` : 
                                '<span class="text-gray-400">N/A</span>'
                            }
                        </p>
                    </div>
                </div>
            </div>

            <div class="bg-gray-50 rounded-lg p-5">
                <h5 class="flex items-center text-base font-semibold text-gray-900 mb-4">
                    <i class="fas fa-graduation-cap text-green-500 mr-3"></i> Academic Information
                </h5>
                <div class="grid grid-cols-1 sm:grid-cols-2 gap-4">
                    <div class="bg-white rounded-lg p-4 shadow-sm border border-gray-200">
                        <div class="flex items-center mb-2">
                            <i class="fas fa-university text-gray-400 mr-2"></i>
                            <span class="text-xs font-medium text-gray-500 uppercase">College</span>
                        </div>
                        <p class="text-sm text-gray-900 flex items-center">
                            <i class="fas fa-school mr-2 text-blue-400"></i>${userData.college_name}
                        </p>
                    </div>
                    <div class="bg-white rounded-lg p-4 shadow-sm border border-gray-200">
                        <div class="flex items-center mb-2">
                            <i class="fas fa-building text-gray-400 mr-2"></i>
                            <span class="text-xs font-medium text-gray-500 uppercase">Department</span>
                        </div>
                        <p class="text-sm text-gray-900 flex items-center">
                            <i class="fas fa-layer-group mr-2 text-green-400"></i>${userData.department_name}
                        </p>
                    </div>
                </div>
                ${userData.program_name !== 'N/A' ? `
                <div class="mt-4 bg-white rounded-lg p-4 shadow-sm border border-gray-200">
                    <div class="flex items-center mb-2">
                        <i class="fas fa-book-open text-gray-400 mr-2"></i>
                        <span class="text-xs font-medium text-gray-500 uppercase">Program</span>
                    </div>
                    <p class="text-sm text-gray-900 flex items-center">
                        <i class="fas fa-graduation-cap mr-2 text-purple-400"></i>${userData.program_name}
                    </p>
                </div>
                ` : ''}
            </div>

            <div class="bg-gray-50 rounded-lg p-5">
                <h5 class="flex items-center text-base font-semibold text-gray-900 mb-4">
                    <i class="fas fa-briefcase text-purple-500 mr-3"></i> Employment Details
                </h5>
                <div class="grid grid-cols-1 sm:grid-cols-2 gap-4">
                    <div class="bg-white rounded-lg p-4 shadow-sm border border-gray-200">
                        <div class="flex items-center mb-2">
                            <i class="fas fa-medal text-gray-400 mr-2"></i>
                            <span class="text-xs font-medium text-gray-500 uppercase">Academic Rank</span>
                        </div>
                        <p class="text-sm text-gray-900">
                            ${userData.academic_rank !== 'N/A' ? 
                                `<span class="inline-flex items-center px-3 py-1 rounded-full bg-blue-100 text-blue-800 text-xs">
                                    <i class="fas fa-award mr-1.5"></i>${userData.academic_rank}
                                </span>` : 
                                '<span class="text-gray-400">N/A</span>'
                            }
                        </p>
                    </div>
                    <div class="bg-white rounded-lg p-4 shadow-sm border border-gray-200">
                        <div class="flex items-center mb-2">
                            <i class="fas fa-clock text-gray-400 mr-2"></i>
                            <span class="text-xs font-medium text-gray-500 uppercase">Employment Type</span>
                        </div>
                        <p class="text-sm text-gray-900">
                            ${userData.employment_type !== 'N/A' ? 
                                `<span class="inline-flex items-center px-3 py-1 rounded-full bg-green-100 text-green-800 text-xs">
                                    <i class="fas fa-business-time mr-1.5"></i>${userData.employment_type}
                                </span>` : 
                                '<span class="text-gray-400">N/A</span>'
                            }
                        </p>
                    </div>
                </div>
            </div>

            ${userData.specialization !== 'N/A' ? `
            <div class="bg-gradient-to-br from-yellow-50 to-orange-50 rounded-lg p-5 border border-yellow-200">
                <h5 class="flex items-center text-base font-semibold text-gray-900 mb-4">
                    <i class="fas fa-star text-yellow-500 mr-3"></i> Specialization & Expertise
                </h5>
                <div class="bg-white/80 rounded-lg p-4 border border-yellow-100">
                    <div class="flex flex-wrap items-center gap-3">
                        <div class="flex items-center text-sm font-medium text-gray-900">
                            <i class="fas fa-graduation-cap mr-2 text-yellow-500"></i>
                            ${userData.specialization}
                        </div>
                        ${userData.expertise_level !== 'N/A' ? 
                            `<span class="inline-flex items-center px-3 py-1 rounded-full text-xs font-medium bg-yellow-100 text-yellow-800 border border-yellow-200">
                                <i class="fas fa-trophy mr-1.5"></i> ${userData.expertise_level}
                            </span>` : ''
                        }
                    </div>
                </div>
            </div>
            ` : ''}

            <div class="bg-gray-50 rounded-lg p-5">
                <h5 class="flex items-center text-base font-semibold text-gray-900 mb-4">
                    <i class="fas fa-info-circle text-gray-500 mr-3"></i> Account Status
                </h5>
                <div class="bg-white rounded-lg p-4 shadow-sm border border-gray-200">
                    <div class="flex items-center justify-between">
                        <div class="flex items-center">
                            <span class="text-sm font-medium text-gray-700 mr-3">Status:</span>
                            <span class="inline-flex items-center px-3 py-1 rounded-full text-xs font-medium ${userData.is_active ? 'bg-green-100 text-green-800' : 'bg-red-100 text-red-800'}">
                                <i class="fas ${userData.is_active ? 'fa-check-circle' : 'fa-times-circle'} mr-1.5"></i>
                                ${userData.is_active ? 'Active' : 'Inactive'}
                            </span>
                        </div>
                        <div class="text-sm text-gray-500">
                            <i class="fas fa-calendar-alt mr-1"></i> ${new Date().toLocaleDateString()}
                        </div>
                    </div>
                </div>
            </div>
        </div>
    `;
        modal.classList.remove('hidden');
    }

    // Tab functionality
    document.addEventListener('DOMContentLoaded', function() {
        const tabs = document.querySelectorAll('.tab-button');
        const contents = document.querySelectorAll('.tab-content');

        tabs.forEach(tab => {
            tab.addEventListener('click', () => {
                tabs.forEach(t => {
                    t.classList.remove('border-yellow-500', 'text-yellow-600');
                    t.classList.add('border-transparent', 'text-gray-500', 'hover:text-gray-700');
                });
                contents.forEach(c => c.classList.add('hidden'));
                tab.classList.remove('border-transparent', 'text-gray-500', 'hover:text-gray-700');
                tab.classList.add('border-yellow-500', 'text-yellow-600');
                const contentId = tab.id.replace('tab-', '') + '-content';
                document.getElementById(contentId).classList.remove('hidden');

                // Apply current filters to the newly shown tab
                applyFilters();
            });
        });

        // Form submission for all actions
        document.querySelectorAll('.action-form').forEach(form => {
            form.addEventListener('submit', async (e) => {
                e.preventDefault();
                const formData = new FormData(form);
                try {
                    const response = await fetch('/dean/faculty', {
                        method: 'POST',
                        body: formData
                    });
                    const data = await response.json();
                    if (data.success) {
                        showToast(data.message || 'Action successful', 'bg-green-500');
                        setTimeout(() => location.reload(), 2000);
                    } else {
                        showToast(data.error || 'Action failed', 'bg-red-500');
                    }
                } catch (error) {
                    showToast('Request failed: ' + error.message, 'bg-red-500');
                }
            });
        });

        // Filter functionality
        const departmentFilter = document.getElementById('departmentFilter');
        const statusFilter = document.getElementById('statusFilter');
        const searchInput = document.getElementById('searchInput');
        const clearFilters = document.getElementById('clearFilters');

        departmentFilter.addEventListener('change', applyFilters);
        statusFilter.addEventListener('change', applyFilters);
        searchInput.addEventListener('input', applyFilters);
        clearFilters.addEventListener('click', clearAllFilters);

        function applyFilters() {
            const selectedDept = departmentFilter.value;
            const selectedStatus = statusFilter.value;
            const searchTerm = searchInput.value.toLowerCase();

            // Get current active tab
            const activeTab = document.querySelector('.tab-button.border-yellow-500');
            const tabType = activeTab ? activeTab.id.replace('tab-', '') : 'chairs';

            // Filter based on active tab
            if (tabType === 'chairs') {
                filterRows('chair-row', selectedDept, selectedStatus, searchTerm, 'chairs-count', 'chairs-badge');
            } else if (tabType === 'faculty') {
                filterRows('faculty-row', selectedDept, selectedStatus, searchTerm, 'faculty-count', 'faculty-badge');
            } else if (tabType === 'pending') {
                filterRows('pending-row', selectedDept, 'all', searchTerm, 'pending-count', 'pending-badge');
            }
        }

        function filterRows(rowClass, departmentId, status, searchTerm, countId, badgeId) {
            const rows = document.querySelectorAll(`.${rowClass}`);
            let visibleCount = 0;

            rows.forEach(row => {
                const rowDept = row.getAttribute('data-department');
                const rowStatus = row.getAttribute('data-status');
                const rowName = row.getAttribute('data-name');

                const deptMatch = departmentId === 'all' || rowDept === departmentId;
                const statusMatch = status === 'all' || rowStatus === status;
                const nameMatch = searchTerm === '' || rowName.includes(searchTerm);

                if (deptMatch && statusMatch && nameMatch) {
                    row.style.display = '';
                    visibleCount++;
                } else {
                    row.style.display = 'none';
                }
            });

            // Update counts
            if (document.getElementById(countId)) {
                document.getElementById(countId).textContent = visibleCount;
            }
            if (document.getElementById(badgeId)) {
                document.getElementById(badgeId).textContent = visibleCount;
            }

            // Show no results message if needed
            const tableBody = rows[0] ? rows[0].closest('tbody') : null;
            if (tableBody) {
                const noResultsRow = tableBody.querySelector('.no-results');
                if (noResultsRow) {
                    noResultsRow.style.display = visibleCount === 0 ? '' : 'none';
                }
            }
        }

        function clearAllFilters() {
            departmentFilter.value = 'all';
            statusFilter.value = 'all';
            searchInput.value = '';
            applyFilters();
        }

        // Initialize with default tab visible
        document.getElementById('tab-chairs').click();

        // Auto-hide alerts
        const alerts = document.querySelectorAll('#successAlert, #errorAlert');
        alerts.forEach(alert => {
            setTimeout(() => {
                if (alert) {
                    alert.style.opacity = '0';
                    alert.style.transition = 'opacity 1s';
                    setTimeout(() => alert.style.display = 'none', 1000);
                }
            }, 5000);
        });
    });

    // Close modal when clicking outside
    document.addEventListener('click', function(event) {
        const modal = document.getElementById('userModal');
        if (event.target === modal) {
            modal.classList.add('hidden');
        }
    });
</script>

<?php
$content = ob_get_clean();
require_once __DIR__ . '/layout.php';
?>