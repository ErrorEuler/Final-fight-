<?php
ob_start();
?>

<!DOCTYPE html>
<html lang="en">

<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Faculty Management | ACSS</title>
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.1.1/css/all.min.css">
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
            background-color: rgba(0, 0, 0, 0.5);
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
            ring-color: var(--gold);
        }

        .btn-gold {
            background-color: var(--gold);
            color: var(--white);
        }

        .btn-gold:hover {
            background-color: #b8972e;
        }

        .tooltip {
            display: none;
        }

        .group:hover .tooltip {
            display: block;
        }

        .suggestions {
            position: absolute;
            top: 100%;
            left: 0;
            right: 0;
            background: var(--white);
            border: 1px solid var(--gray-light);
            border-radius: 0.5rem;
            box-shadow: 0 4px 6px rgba(0, 0, 0, 0.1);
            max-height: 200px;
            overflow-y: auto;
            z-index: 10;
        }

        .suggestion-item {
            padding: 0.75rem 1rem;
            cursor: pointer;
            transition: background-color 0.2s ease;
        }

        .suggestion-item:hover {
            background-color: rgba(212, 175, 55, 0.1);
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

        .faculty-row {
            cursor: pointer;
        }

        .faculty-row:hover {
            background-color: rgba(212, 175, 55, 0.1);
        }

        .profile-picture {
            width: 40px;
            height: 40px;
            object-fit: cover;
            border-radius: 50%;
            border: 2px solid var(--gray-light);
        }

        .profile-picture-large {
            width: 100px;
            height: 100px;
            object-fit: cover;
            border-radius: 50%;
            border: 2px solid var(--gold);
        }

        .profile-icon {
            color: var(--gray-light);
            font-size: 40px;
        }

        .profile-icon-large {
            color: var(--gold);
            font-size: 100px;
        }

        td.specialization {
            white-space: normal;
            word-wrap: break-word;
            max-width: 200px;
        }
    </style>
</head>

<body class="bg-gray-light font-sans antialiased">
    <div id="toast-container" class="fixed top-5 right-5 z-50"></div>

    <div class="container mx-auto px-4 py-8 max-w-7xl">
        <header class="mb-8 slide-in-left">
            <h1 class="text-4xl font-bold text-gray-dark">Faculty Management</h1>
            <p class="text-gray-dark mt-2">Manage faculty members for your department</p>
        </header>

        <div class="search-container mx-4 sm:mx-6 md:mx-auto bg-white rounded-xl shadow-xl border border-black p-4 fade-in">
            <div class="flex items-center">
                <i class="fas fa-search text-gray-dark w-5 h-5 mr-3"></i>
                <input type="text" id="search-input" class="search-input flex-1 bg-transparent outline-none text-gray-dark placeholder-gray-dark input-focus"
                    placeholder="Search faculty by name..." autocomplete="off" aria-label="Search faculty">
                <span id="search-feedback" class="ml-3 text-sm font-medium"></span>
            </div>
            <div id="suggestions" class="suggestions hidden"></div>
        </div>

        <div id="search-results" class="mb-6"></div>
        <div id="includable-faculty" class="mb-6"></div>

        <div class="bg-white rounded-xl shadow-lg fade-in">
            <div class="flex justify-between items-center p-6 border-b border-gray-light bg-gradient-to-r from-white to-gray-50 rounded-t-xl">
                <h3 class="text-xl font-bold text-gray-dark">Your Department's Faculty</h3>
                <span class="text-sm font-medium text-gray-dark bg-gray-light px-3 py-1 rounded-full"><?php echo count($faculty); ?> Faculty</span>
            </div>
            <div class="p-6">
                <div class="overflow-x-auto">
                    <?php if (empty($faculty)): ?>
                        <div class="text-center py-8 text-gray-dark">
                            <i class="fas fa-users text-gray-dark text-2xl mb-2"></i>
                            <p class="font-medium">No faculty members found in your department</p>
                            <p class="text-sm mt-1">Search for faculty to include them</p>
                        </div>
                    <?php else: ?>
                        <table class="min-w-full divide-y divide-gray-light">
                            <thead class="bg-gray-50">
                                <tr>
                                    <th class="px-6 py-3 text-left text-xs font-semibold text-gray-dark uppercase tracking-wider">Picture</th>
                                    <th class="px-6 py-3 text-left text-xs font-semibold text-gray-dark uppercase tracking-wider">Employee ID</th>
                                    <th class="px-6 py-3 text-left text-xs font-semibold text-gray-dark uppercase tracking-wider">Name</th>
                                    <th class="px-6 py-3 text-left text-xs font-semibold text-gray-dark uppercase tracking-wider">Academic Rank</th>
                                    <th class="px-6 py-3 text-left text-xs font-semibold text-gray-dark uppercase tracking-wider">Employment Type</th>
                                    <th class="px-6 py-3 text-left text-xs font-semibold text-gray-dark uppercase tracking-wider">Departments</th>
                                    <th class="px-6 py-3 text-left text-xs font-semibold text-gray-dark uppercase tracking-wider">Actions</th>
                                </tr>
                            </thead>
                            <tbody class="bg-white divide-y divide-gray-light">
                                <?php foreach ($faculty as $member): ?>
                                    <tr class="faculty-row hover:bg-gray-50 transition-all duration-200"
                                        data-id="<?php echo $member['user_id']; ?>"
                                        data-name="<?php echo htmlspecialchars($member['title'] . ' ' . $member['first_name'] . ' ' . $member['middle_name'] . ' ' . $member['last_name']) . ' ' . $member['suffix']; ?>">
                                        <td class="px-6 py-4 whitespace-nowrap">
                                            <img src="<?php echo htmlspecialchars($member['profile_picture']); ?>"
                                                alt="Profile picture of <?php echo htmlspecialchars($member['title'] . ' ' . $member['first_name'] . ' ' . $member['middle_name'] . ' ' . $member['last_name']) . ' ' . $member['suffix']; ?>"
                                                class="profile-picture"
                                                onerror="replaceWithIcon(this, 'profile-icon')">
                                        </td>
                                        <td class="px-6 py-4 whitespace-nowrap text-sm text-gray-dark"><?php echo htmlspecialchars($member['employee_id']); ?></td>
                                        <td class="px-6 py-4 whitespace-nowrap text-sm font-medium text-gray-dark"><?php echo htmlspecialchars($member['title'] . ' ' . $member['first_name'] . ' ' . $member['middle_name'] . ' ' . $member['last_name']) . ' ' . $member['suffix']; ?></td>
                                        <td class="px-6 py-4 whitespace-nowrap text-sm text-gray-dark"><?php echo htmlspecialchars($member['academic_rank'] ?? 'N/A'); ?></td>
                                        <td class="px-6 py-4 whitespace-nowrap text-sm text-gray-dark"><?php echo htmlspecialchars($member['employment_type'] ?? 'N/A'); ?></td>
                                        <td class="px-6 py-4 whitespace-nowrap text-sm text-gray-dark"><?php echo htmlspecialchars($member['department_names'] ?? 'N/A'); ?></td>
                                        <td class="px-6 py-4 whitespace-nowrap text-sm font-medium">
                                            <button class="remove-btn text-red-600 group relative hover:text-red-700 transition-all duration-200"
                                                data-id="<?php echo $member['user_id']; ?>"
                                                data-name="<?php echo htmlspecialchars($member['title'] . ' ' . $member['first_name'] . ' ' . $member['middle_name'] . ' ' . $member['last_name']) . ' ' . $member['suffix']; ?>">
                                                <i class="fa-solid fa-xmark"></i>
                                                <span class="tooltip absolute bg-gray-dark text-white text-xs rounded py-1 px-2 -top-8 left-1/2 transform -translate-x-1/2">Remove Faculty</span>
                                            </button>
                                        </td>
                                    </tr>
                                <?php endforeach; ?>
                            </tbody>
                        </table>
                    <?php endif; ?>
                </div>
            </div>
        </div>

        <div id="include-modal" class="modal fixed inset-0 flex items-center justify-center z-50 hidden">
            <div class="bg-white rounded-xl shadow-2xl w-full max-w-md mx-4 transform modal-content scale-95">
                <div class="flex justify-between items-center p-6 border-b border-gray-light bg-gradient-to-r from-white to-gray-50 rounded-t-xl">
                    <h3 class="text-xl font-bold text-gray-dark">Include Faculty</h3>
                    <button id="closeIncludeModalBtn"
                        class="text-gray-dark hover:text-gray-700 focus:outline-none bg-gray-light hover:bg-gray-200 rounded-full h-8 w-8 flex items-center justify-center transition-all duration-200"
                        aria-label="Close modal">
                        <i class="fas fa-times"></i>
                    </button>
                </div>
                <div class="p-6">
                    <p class="text-gray-dark mb-6">Are you sure you want to include <strong id="modal-faculty-name"></strong> in your department?</p>
                    <input type="hidden" id="modal-user-id" name="user_id">
                    <div class="flex justify-end space-x-3">
                        <button id="cancelIncludeBtn" class="bg-gray-light text-gray-dark px-5 py-3 rounded-lg hover:bg-gray-200 transition-all duration-200 font-medium">Cancel</button>
                        <button id="confirmIncludeBtn" class="btn-gold px-5 py-3 rounded-lg shadow-md hover:shadow-lg transition-all duration-200 font-medium">Confirm</button>
                    </div>
                </div>
            </div>
        </div>

        <div id="remove-modal" class="modal fixed inset-0 bg-opacity-60 flex items-center justify-center z-50 hidden">
            <div class="bg-white rounded-xl shadow-2xl w-full max-w-md mx-4 transform modal-content scale-95">
                <div class="flex justify-between items-center p-6 border-b border-gray-light bg-gradient-to-r from-white to-gray-50 rounded-t-xl">
                    <h3 class="text-xl font-bold text-gray-dark">Remove Faculty</h3>
                    <button id="closeRemoveModalBtn"
                        class="text-gray-dark hover:text-gray-700 focus:outline-none bg-gray-light hover:bg-gray-200 rounded-full h-8 w-8 flex items-center justify-center transition-all duration-200"
                        aria-label="Close modal">
                        <i class="fas fa-times"></i>
                    </button>
                </div>
                <div class="p-6">
                    <p class="text-gray-dark mb-6">Are you sure you want to remove <strong id="remove-modal-faculty-name"></strong> from your department?</p>
                    <input type="hidden" id="remove-modal-user-id" name="user_id">
                    <div class="flex justify-end space-x-3">
                        <button id="cancelRemoveBtn" class="bg-gray-light text-gray-dark px-5 py-3 rounded-lg hover:bg-gray-200 transition-all duration-200 font-medium">Cancel</button>
                        <button id="confirmRemoveBtn" class="bg-red-600 text-white px-5 py-3 rounded-lg hover:bg-red-700 transition-all duration-200 font-medium">Confirm</button>
                    </div>
                </div>
            </div>
        </div>

        <!-- Faculty Details Modal -->
        <div id="faculty-details-modal" class="modal fixed inset-0 flex items-center justify-center z-50 hidden p-4">
            <div class="bg-white rounded-xl shadow-2xl w-full max-w-5xl max-h-[90vh] mx-4 transform modal-content scale-95 flex flex-col">
                <!-- Header -->
                <div class="flex justify-between items-center p-6 border-b border-gray-light bg-gradient-to-r from-white to-gray-50 rounded-t-xl flex-shrink-0">
                    <h3 class="text-2xl font-bold text-gray-dark">Faculty Details</h3>
                    <button id="closeFacultyDetailsModalBtn"
                        class="text-gray-dark hover:text-gray-700 focus:outline-none bg-gray-light hover:bg-gray-200 rounded-full h-10 w-10 flex items-center justify-center transition-all duration-200"
                        aria-label="Close modal">
                        <i class="fas fa-times text-lg"></i>
                    </button>
                </div>

                <!-- Content Area with Scrolling -->
                <div class="flex-1 overflow-y-auto">
                    <div class="p-6">
                        <div id="faculty-details-content" class="text-gray-dark">
                            <!-- Loading State -->
                            <div class="animate-pulse">
                                <div class="flex items-center space-x-4 mb-6">
                                    <div class="w-20 h-20 bg-gray-200 rounded-full"></div>
                                    <div class="flex-1">
                                        <div class="h-6 bg-gray-200 rounded w-1/2 mb-2"></div>
                                        <div class="h-4 bg-gray-200 rounded w-1/3 mb-2"></div>
                                        <div class="h-4 bg-gray-200 rounded w-1/4"></div>
                                    </div>
                                </div>
                                <div class="grid grid-cols-1 md:grid-cols-2 gap-6">
                                    <div class="space-y-4">
                                        <div class="h-6 bg-gray-200 rounded w-3/4"></div>
                                        <div class="space-y-3">
                                            <div class="h-4 bg-gray-200 rounded w-full"></div>
                                            <div class="h-4 bg-gray-200 rounded w-5/6"></div>
                                            <div class="h-4 bg-gray-200 rounded w-4/5"></div>
                                        </div>
                                    </div>
                                    <div class="space-y-4">
                                        <div class="h-6 bg-gray-200 rounded w-3/4"></div>
                                        <div class="space-y-3">
                                            <div class="h-4 bg-gray-200 rounded w-full"></div>
                                            <div class="h-4 bg-gray-200 rounded w-5/6"></div>
                                        </div>
                                    </div>
                                </div>
                                <div class="mt-6">
                                    <div class="h-20 bg-gray-200 rounded-lg"></div>
                                </div>
                            </div>
                        </div>
                    </div>
                </div>

                <!-- Footer -->
                <div class="flex justify-end p-6 border-t border-gray-100 bg-gray-50 rounded-b-xl flex-shrink-0">
                    <button id="closeFacultyDetailsBtn"
                        class="bg-gray-600 text-white px-6 py-3 rounded-lg hover:bg-gray-700 transition-all duration-200 font-medium shadow-sm">
                        Close
                    </button>
                </div>
            </div>
        </div>
    </div>

    <script>
        function replaceWithIcon(img, iconClass) {
            const parent = img.parentNode;
            const icon = document.createElement('i');
            icon.className = `fas fa-user-circle ${iconClass}`;
            icon.setAttribute('aria-hidden', 'true');
            icon.title = img.alt;
            parent.replaceChild(icon, img);
        }

        document.addEventListener('DOMContentLoaded', () => {
            <?php if (isset($success)): ?>
                showToast('<?php echo htmlspecialchars($success); ?>', 'bg-green-500');
            <?php endif; ?>
            <?php if (isset($error)): ?>
                showToast('<?php echo htmlspecialchars($error); ?>', 'bg-red-500');
            <?php endif; ?>

            function showToast(message, bgColor) {
                const toast = document.createElement('div');
                toast.className = `toast ${bgColor} text-white px-4 py-2 rounded-lg shadow-lg`;
                toast.textContent = message;
                toast.setAttribute('role', 'alert');
                document.getElementById('toast-container').appendChild(toast);
                setTimeout(() => {
                    toast.style.opacity = '0';
                    setTimeout(() => toast.remove(), 300);
                }, 5000);
            }

            function openModal(modalId) {
                const modal = document.getElementById(modalId);
                const modalContent = modal.querySelector('.modal-content');
                modal.classList.remove('hidden');
                modalContent.classList.remove('scale-95');
                modalContent.classList.add('scale-100');
                document.body.style.overflow = 'hidden';
            }

            function closeModal(modalId) {
                const modal = document.getElementById(modalId);
                const modalContent = modal.querySelector('.modal-content');
                modalContent.classList.remove('scale-100');
                modalContent.classList.add('scale-95');
                setTimeout(() => {
                    modal.classList.add('hidden');
                    document.body.style.overflow = 'auto';
                }, 200);
            }

            let searchTimeout;
            const searchInput = document.getElementById('search-input');
            const searchFeedback = document.getElementById('search-feedback');
            const suggestions = document.getElementById('suggestions');
            const searchResults = document.getElementById('search-results');
            const includableFaculty = document.getElementById('includable-faculty');

            searchInput.addEventListener('input', () => {
                const query = searchInput.value.trim();
                clearTimeout(searchTimeout);

                if (query.length < 2) {
                    searchFeedback.textContent = '';
                    suggestions.classList.add('hidden');
                    suggestions.innerHTML = '';
                    renderSearchResults([]);
                    renderIncludableFaculty([]);
                    return;
                }

                searchFeedback.textContent = 'Searching...';
                searchFeedback.classList.add('loading', 'text-gray-dark');
                searchFeedback.classList.remove('text-green-500', 'text-red-500');

                searchTimeout = setTimeout(async () => {
                    try {
                        console.log('Sending search request with name:', query);
                        const response = await fetch('/chair/faculty/search', {
                            method: 'POST',
                            headers: {
                                'Content-Type': 'application/x-www-form-urlencoded',
                                'X-Requested-With': 'XMLHttpRequest'
                            },
                            body: `name=${encodeURIComponent(query)}`
                        });
                        console.log('Response status:', response.status);
                        if (!response.ok) {
                            const errorData = await response.json().catch(() => ({}));
                            throw new Error(errorData.error || `HTTP error! Status: ${response.status}`);
                        }
                        const data = await response.json();
                        console.log('Response data:', data);

                        const results = data.results || [];
                        const includable = data.includable || [];

                        if (results.length > 0 || includable.length > 0) {
                            searchFeedback.textContent = 'Faculty found';
                            searchFeedback.classList.remove('loading', 'text-gray-dark', 'text-red-500');
                            searchFeedback.classList.add('text-green-500');
                            renderSuggestions([...results, ...includable]);
                            renderSearchResults(results);
                            renderIncludableFaculty(includable);
                        } else {
                            searchFeedback.textContent = 'No faculty found';
                            searchFeedback.classList.remove('loading', 'text-gray-dark', 'text-green-500');
                            searchFeedback.classList.add('text-red-500');
                            suggestions.classList.add('hidden');
                            suggestions.innerHTML = '';
                            renderSearchResults([]);
                            renderIncludableFaculty([]);
                        }
                    } catch (error) {
                        console.error('Search error:', error);
                        searchFeedback.textContent = 'Error searching faculty';
                        searchFeedback.classList.remove('loading', 'text-gray-dark', 'text-green-500');
                        searchFeedback.classList.add('text-red-500');
                        suggestions.classList.add('hidden');
                        suggestions.innerHTML = '';
                        renderSearchResults([]);
                        renderIncludableFaculty([]);
                        showToast(`Failed to search faculty: ${error.message}`, 'bg-red-500');
                    }
                }, 300);
            });

            document.addEventListener('click', (e) => {
                if (!e.target.closest('.search-container')) {
                    suggestions.classList.add('hidden');
                }
            });

            suggestions.addEventListener('click', async (e) => {
                if (e.target.classList.contains('suggestion-item')) {
                    const name = e.target.dataset.name;
                    searchInput.value = name;
                    suggestions.classList.add('hidden');
                    searchFeedback.textContent = 'Faculty found';
                    searchFeedback.classList.remove('text-red-500');
                    searchFeedback.classList.add('text-green-500');

                    try {
                        const response = await fetch('/chair/faculty/search', {
                            method: 'POST',
                            headers: {
                                'Content-Type': 'application/x-www-form-urlencoded',
                                'X-Requested-With': 'XMLHttpRequest'
                            },
                            body: `name=${encodeURIComponent(name)}`
                        });
                        const data = await response.json();
                        renderSearchResults(data.results || []);
                        renderIncludableFaculty(data.includable || []);
                    } catch (error) {
                        console.error('Error:', error);
                        showToast('Failed to load faculty details.', 'bg-red-500');
                    }
                }
            });

            function renderSuggestions(results) {
                suggestions.innerHTML = '';
                if (results.length === 0) {
                    suggestions.classList.add('hidden');
                    return;
                }

                results.forEach(result => {
                    const div = document.createElement('div');
                    div.className = 'suggestion-item';
                    div.textContent = `${result.first_name} ${result.last_name} (ID: ${result.employee_id})`;
                    div.dataset.name = `${result.first_name} ${result.last_name}`;
                    suggestions.appendChild(div);
                });

                suggestions.classList.remove('hidden');
            }

            function renderSearchResults(results) {
                searchResults.innerHTML = '';
                if (results.length === 0) {
                    searchResults.innerHTML = '<p class="text-gray-dark text-center py-4">No faculty members found in your department matching your criteria.</p>';
                    return;
                }

                const container = document.createElement('div');
                container.className = 'bg-white rounded-xl shadow-lg p-6';
                container.innerHTML = `
                    <div class="flex justify-between items-center border-b border-gray-light pb-2 mb-6">
                        <h3 class="text-xl font-bold text-gray-dark">Search Results (Your Department)</h3>
                        <span class="text-sm font-medium text-gray-dark bg-gray-light px-3 py-1 rounded-full">${results.length} Found</span>
                    </div>
                    <div class="overflow-x-auto">
                        <table class="min-w-full divide-y divide-gray-light">
                            <thead class="bg-gray-50">
                                <tr>
                                    <th class="px-6 py-3 text-left text-xs font-semibold text-gray-dark uppercase tracking-wider">Employee ID</th>
                                    <th class="px-6 py-3 text-left text-xs font-semibold text-gray-dark uppercase tracking-wider">Name</th>
                                    <th class="px-6 py-3 text-left text-xs font-semibold text-gray-dark uppercase tracking-wider">Role</th>
                                    <th class="px-6 py-3 text-left text-xs font-semibold text-gray-dark uppercase tracking-wider">College</th>
                                    <th class="px-6 py-3 text-left text-xs font-semibold text-gray-dark uppercase tracking-wider">Departments</th>
                                    <th class="px-6 py-3 text-left text-xs font-semibold text-gray-dark uppercase tracking-wider">Specialization</th>
                                    <th class="px-6 py-3 text-left text-xs font-semibold text-gray-dark uppercase tracking-wider">Academic Rank</th>
                                    <th class="px-6 py-3 text-left text-xs font-semibold text-gray-dark uppercase tracking-wider">Employment Type</th>
                                </tr>
                            </thead>
                            <tbody class="bg-white divide-y divide-gray-light">
                                ${results.map(result => `
                                    <tr class="hover:bg-gray-50 transition-all duration-200">
                                        <td class="px-6 py-4 whitespace-nowrap text-sm text-gray-dark">${result.employee_id || 'N/A'}</td>
                                        <td class="px-6 py-4 whitespace-nowrap text-sm font-medium text-gray-dark">${result.title} ${result.first_name} ${result.middle_name} ${result.last_name} ${result.suffix}</td>
                                        <td class="px-6 py-4 whitespace-nowrap text-sm text-gray-dark">
                                            ${result.role_name || 'N/A'}
                                            ${result.dean_college_id ? `(Dean of ${result.college_name})` : ''}
                                            ${result.program_name ? `(Chair of ${result.program_name})` : ''}
                                        </td>
                                        <td class="px-6 py-4 whitespace-nowrap text-sm text-gray-dark">${result.college_name || 'N/A'}</td>
                                        <td class="px-6 py-4 whitespace-nowrap text-sm text-gray-dark">${result.department_names || 'N/A'}</td>
                                        <td class="px-6 py-4 text-sm text-gray-dark specialization">${result.specialization || 'N/A'}</td>
                                        <td class="px-6 py-4 whitespace-nowrap text-sm text-gray-dark">${result.academic_rank || 'N/A'}</td>
                                        <td class="px-6 py-4 whitespace-nowrap text-sm text-gray-dark">${result.employment_type || 'N/A'}</td>
                                    </tr>
                                `).join('')}
                            </tbody>
                        </table>
                    </div>
                `;
                searchResults.appendChild(container);
            }

            function renderIncludableFaculty(includable) {
                includableFaculty.innerHTML = '';
                if (includable.length === 0) {
                    includableFaculty.innerHTML = '<p class="text-gray-dark text-center py-4">No includable faculty members found matching your criteria.</p>';
                    return;
                }

                const container = document.createElement('div');
                container.className = 'bg-white rounded-xl shadow-lg p-6';
                container.innerHTML = `
                    <div class="flex justify-between items-center border-b border-gray-light pb-2 mb-6">
                        <h3 class="text-xl font-bold text-gray-dark">Includable Faculty</h3>
                        <span class="text-sm font-medium text-gray-dark bg-gray-light px-3 py-1 rounded-full">${includable.length} Found</span>
                    </div>
                    <div class="overflow-x-auto">
                        <table class="min-w-full divide-y divide-gray-light">
                            <thead class="bg-gray-50">
                                <tr>
                                    <th class="px-6 py-3 text-left text-xs font-semibold text-gray-dark uppercase tracking-wider">Employee ID</th>
                                    <th class="px-6 py-3 text-left text-xs font-semibold text-gray-dark uppercase tracking-wider">Name</th>
                                    <th class="px-6 py-3 text-left text-xs font-semibold text-gray-dark uppercase tracking-wider">College</th>
                                    <th class="px-6 py-3 text-left text-xs font-semibold text-gray-dark uppercase tracking-wider">Departments</th>
                                    <th class="px-6 py-3 text-left text-xs font-semibold text-gray-dark uppercase tracking-wider">Specialization</th>
                                    <th class="px-6 py-3 text-left text-xs font-semibold text-gray-dark uppercase tracking-wider">Academic Rank</th>
                                    <th class="px-6 py-3 text-left text-xs font-semibold text-gray-dark uppercase tracking-wider">Employment Type</th>
                                    <th class="px-6 py-3 text-left text-xs font-semibold text-gray-dark uppercase tracking-wider">Action</th>
                                </tr>
                            </thead>
                            <tbody class="bg-white divide-y divide-gray-light">
                                ${includable.map(result => `
                                    <tr class="hover:bg-gray-50 transition-all duration-200">
                                        <td class="px-6 py-4 whitespace-nowrap text-sm text-gray-dark">${result.employee_id || 'N/A'}</td>
                                        <td class="px-6 py-4 whitespace-nowrap text-sm font-medium text-gray-dark">${result.title || ''} ${result.first_name} ${result.middle_name || ''} ${result.last_name} ${result.suffix || ''}</td>
                                        <td class="px-6 py-4 whitespace-nowrap text-sm text-gray-dark">${result.college_name || 'N/A'}</td>
                                        <td class="px-6 py-4 whitespace-nowrap text-sm text-gray-dark">${result.department_names || 'N/A'}</td>
                                        <td class="px-6 py-4 text-sm text-gray-dark specialization">${result.specialization || 'N/A'}</td>
                                        <td class="px-6 py-4 whitespace-nowrap text-sm text-gray-dark">${result.academic_rank || 'N/A'}</td>
                                        <td class="px-6 py-4 whitespace-nowrap text-sm text-gray-dark">${result.employment_type || 'N/A'}</td>
                                        <td class="px-6 py-4 whitespace-nowrap text-sm font-medium">
                                            <td class="px-6 py-4 whitespace-nowrap text-sm font-medium">
                                                <button class="include-btn text-green-600 group relative hover:text-green-700 hover:bg-green-50 rounded-md transition-all duration-200 px-3 py-2 min-w-[44px] min-h-[36px] flex items-center justify-center border border-transparent hover:border-green-200"
                                                        data-id="${result.user_id}"
                                                        data-name="${result.first_name} ${result.last_name}">
                                                    <i class="fa-regular fa-plus text-lg"></i>
                                                    <span class="tooltip absolute bg-gray-dark text-white text-xs rounded py-1 px-2 -top-8 left-1/2 transform -translate-x-1/2 opacity-0 group-hover:opacity-100 transition-opacity duration-200 pointer-events-none z-10">Include Faculty</span>
                                                </button>
                                        </td>
                                    </tr>
                                `).join('')}
                            </tbody>
                        </table>
                    </div>
                `;
                includableFaculty.appendChild(container);
            }

            document.querySelectorAll('.faculty-row').forEach(row => {
                row.addEventListener('click', async (e) => {
                    if (e.target.closest('.remove-btn')) return;
                    const userId = row.dataset.id;
                    const facultyName = row.dataset.name;
                    openModal('faculty-details-modal');
                    const contentDiv = document.getElementById('faculty-details-content');
                    contentDiv.innerHTML = `
                        <div class="animate-pulse">
                            <div class="h-4 bg-gray-200 rounded w-3/4 mb-4"></div>
                            <div class="h-4 bg-gray-200 rounded w-1/2 mb-4"></div>
                            <div class="h-4 bg-gray-200 rounded w-2/3"></div>
                        </div>
                    `;

                    try {
                        console.log('Fetching details for user_id:', userId);
                        const response = await fetch(window.location.href, {
                            method: 'POST',
                            headers: {
                                'Content-Type': 'application/x-www-form-urlencoded',
                                'X-Requested-With': 'XMLHttpRequest'
                            },
                            body: `action=get_faculty_details&user_id=${encodeURIComponent(userId)}`
                        });
                        console.log('Response status:', response.status);
                        if (!response.ok) {
                            const errorData = await response.json().catch(() => ({}));
                            throw new Error(errorData.error || `HTTP error! Status: ${response.status}`);
                        }
                        const data = await response.json();
                        console.log('Faculty details response:', data);

                        if (data.success) {
                            const details = data.data;
                            contentDiv.innerHTML = `
                                <div class="bg-white rounded-xl shadow-sm border border-gray-100 p-6">
                                <!-- Header Section with Profile -->
                                <div class="flex items-start space-x-6 mb-8 pb-6 border-b border-gray-100">
                                    <div class="flex-shrink-0">
                                        <div class="relative">
                                            <img src="${details.profile_picture}" 
                                                alt="Profile picture of ${details.first_name} ${details.last_name}" 
                                                class="w-20 h-20 rounded-full object-cover ring-4 ring-gray-50 shadow-sm"
                                                onerror="replaceWithIcon(this, 'profile-icon-large')">
                                            <div class="absolute -bottom-1 -right-1 w-6 h-6 bg-green-500 rounded-full border-2 border-white flex items-center justify-center">
                                                <i class="fas fa-check text-white text-xs"></i>
                                            </div>
                                        </div>
                                    </div>
                                    <div class="flex-1 min-w-0">
                                        <h4 class="text-2xl font-bold text-gray-900 mb-2">${details.title || ''} ${details.first_name} ${details.middle_name || ''} ${details.last_name} ${details.suffix || ''}</h4>
                                        <div class="flex flex-wrap gap-2 mb-3">
                                            ${details.academic_rank ? `<span class="inline-flex items-center px-3 py-1 rounded-full text-xs font-medium bg-blue-50 text-blue-700 border border-blue-200">${details.academic_rank}</span>` : ''}
                                            ${details.employment_type ? `<span class="inline-flex items-center px-3 py-1 rounded-full text-xs font-medium bg-green-50 text-green-700 border border-green-200">${details.employment_type}</span>` : ''}
                                        </div>
                                        ${details.specialization ? `<p class="text-sm text-gray-600 font-medium">${details.specialization}${details.expertise_level ? ' • ' + details.expertise_level : ''}</p>` : ''}
                                    </div>
                                </div>

                                <!-- Details Grid -->
                            <div class="space-y-6">
                                <!-- Personal Information -->
                                <div class="bg-gray-50 rounded-lg p-5">
                                    <h5 class="flex items-center text-base font-semibold text-gray-900 mb-4">
                                        <i class="fas fa-user text-blue-500 mr-3"></i>
                                        Personal Information
                                    </h5>
                                    <div class="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-4">
                                        <div class="bg-white rounded-md p-4 shadow-sm">
                                            <div class="flex items-center mb-2">
                                                <i class="fas fa-id-card text-gray-400 mr-2"></i>
                                                <span class="text-xs font-medium text-gray-500 uppercase tracking-wide">User ID</span>
                                            </div>
                                            <p class="text-sm font-mono text-gray-900">${details.user_id || 'N/A'}</p>
                                        </div>
                                        <div class="bg-white rounded-md p-4 shadow-sm">
                                            <div class="flex items-center mb-2">
                                                <i class="fas fa-badge text-gray-400 mr-2"></i>
                                                <span class="text-xs font-medium text-gray-500 uppercase tracking-wide">Employee ID</span>
                                            </div>
                                            <p class="text-sm font-mono text-gray-900">${details.employee_id || 'N/A'}</p>
                                        </div>
                                        <div class="bg-white rounded-md p-4 shadow-sm sm:col-span-2 lg:col-span-1">
                                            <div class="flex items-center mb-2">
                                                <i class="fas fa-envelope text-gray-400 mr-2"></i>
                                                <span class="text-xs font-medium text-gray-500 uppercase tracking-wide">Email</span>
                                            </div>
                                            <p class="text-sm text-gray-900 break-all">
                                                ${details.email ? `<a href="mailto:${details.email}" class="text-blue-600 hover:text-blue-800 hover:underline transition-colors">${details.email}</a>` : 'N/A'}
                                            </p>
                                        </div>
                                    </div>
                                </div>

                                <!-- Academic Information -->
                                <div class="bg-gray-50 rounded-lg p-5">
                                    <h5 class="flex items-center text-base font-semibold text-gray-900 mb-4">
                                        <i class="fas fa-graduation-cap text-green-500 mr-3"></i>
                                        Academic Information
                                    </h5>
                                    <div class="grid grid-cols-1 sm:grid-cols-2 gap-4">
                                        <div class="bg-white rounded-md p-4 shadow-sm">
                                            <div class="flex items-center mb-2">
                                                <i class="fas fa-university text-gray-400 mr-2"></i>
                                                <span class="text-xs font-medium text-gray-500 uppercase tracking-wide">College</span>
                                            </div>
                                            <p class="text-sm text-gray-900">${details.college_name || 'N/A'}</p>
                                        </div>
                                        <div class="bg-white rounded-md p-4 shadow-sm">
                                            <div class="flex items-center mb-2">
                                                <i class="fas fa-building text-gray-400 mr-2"></i>
                                                <span class="text-xs font-medium text-gray-500 uppercase tracking-wide">Departments</span>
                                            </div>
                                            <p class="text-sm text-gray-900">${details.department_names || 'N/A'}</p>
                                        </div>
                                    </div>
                                </div>

                                <!-- Employment & Rank Information -->
                                <div class="bg-gray-50 rounded-lg p-5">
                                    <h5 class="flex items-center text-base font-semibold text-gray-900 mb-4">
                                        <i class="fas fa-briefcase text-purple-500 mr-3"></i>
                                        Employment Details
                                    </h5>
                                    <div class="grid grid-cols-1 sm:grid-cols-2 gap-4">
                                        <div class="bg-white rounded-md p-4 shadow-sm">
                                            <div class="flex items-center mb-2">
                                                <i class="fas fa-medal text-gray-400 mr-2"></i>
                                                <span class="text-xs font-medium text-gray-500 uppercase tracking-wide">Academic Rank</span>
                                            </div>
                                            <p class="text-sm text-gray-900">
                                                ${details.academic_rank ? `<span class="inline-flex items-center px-2 py-1 rounded-md text-xs font-medium bg-blue-100 text-blue-800">${details.academic_rank}</span>` : 'N/A'}
                                            </p>
                                        </div>
                                        <div class="bg-white rounded-md p-4 shadow-sm">
                                            <div class="flex items-center mb-2">
                                                <i class="fas fa-clock text-gray-400 mr-2"></i>
                                                <span class="text-xs font-medium text-gray-500 uppercase tracking-wide">Employment Type</span>
                                            </div>
                                            <p class="text-sm text-gray-900">
                                                ${details.employment_type ? `<span class="inline-flex items-center px-2 py-1 rounded-md text-xs font-medium bg-green-100 text-green-800">${details.employment_type}</span>` : 'N/A'}
                                            </p>
                                        </div>
                                    </div>
                                </div>

                                <!-- Specialization Section -->
                                ${details.specialization ? `
                                <div class="bg-gradient-to-br from-blue-50 to-indigo-100 rounded-lg p-5 border border-blue-200">
                                    <h5 class="flex items-center text-base font-semibold text-blue-900 mb-4">
                                        <i class="fas fa-star text-yellow-500 mr-3"></i>
                                        Specialization & Expertise
                                    </h5>
                                    <div class="bg-white/70 backdrop-blur rounded-md p-4">
                                        <div class="flex flex-wrap items-center gap-2">
                                            <span class="text-blue-900 font-medium text-sm">${details.specialization}</span>
                                            ${details.expertise_level ? `
                                            <span class="inline-flex items-center px-3 py-1 rounded-full text-xs font-medium bg-blue-200 text-blue-900 border border-blue-300">
                                                <i class="fas fa-trophy mr-1"></i>
                                                ${details.expertise_level}
                                            </span>
                                            ` : ''}
                                        </div>
                                    </div>
                                </div>
                                ` : ''}
                            </div>
                            `;
                        } else {
                            contentDiv.innerHTML = `<p class="text-red-500">${data.error || 'Failed to load faculty details'}</p>`;
                        }
                    } catch (error) {
                        console.error('Error fetching faculty details:', error);
                        contentDiv.innerHTML = `<p class="text-red-500">Error: ${error.message}</p>`;
                        showToast('Failed to load faculty details.', 'bg-red-500');
                    }
                });
            });

            document.getElementById('closeFacultyDetailsModalBtn').addEventListener('click', () => closeModal('faculty-details-modal'));
            document.getElementById('closeFacultyDetailsBtn').addEventListener('click', () => closeModal('faculty-details-modal'));

            document.getElementById('faculty-details-modal').addEventListener('click', (e) => {
                if (e.target === document.getElementById('faculty-details-modal')) {
                    closeModal('faculty-details-modal');
                }
            });

            document.addEventListener('click', (e) => {
                if (e.target.classList.contains('include-btn')) {
                    const userId = e.target.dataset.id;
                    const facultyName = e.target.dataset.name;
                    document.getElementById('modal-user-id').value = userId;
                    document.getElementById('modal-faculty-name').textContent = facultyName;
                    openModal('include-modal');
                }
            });

            document.querySelectorAll('.remove-btn').forEach(btn => {
                btn.addEventListener('click', () => {
                    const userId = btn.dataset.id;
                    const facultyName = btn.dataset.name;
                    document.getElementById('remove-modal-user-id').value = userId;
                    document.getElementById('remove-modal-faculty-name').textContent = facultyName;
                    openModal('remove-modal');
                });
            });

            document.getElementById('closeIncludeModalBtn').addEventListener('click', () => closeModal('include-modal'));
            document.getElementById('cancelIncludeBtn').addEventListener('click', () => closeModal('include-modal'));
            document.getElementById('confirmIncludeBtn').addEventListener('click', async () => {
                const userId = document.getElementById('modal-user-id').value;
                const formData = new FormData();
                formData.append('action', 'add_faculty');
                formData.append('user_id', userId);

                try {
                    const response = await fetch(window.location.href, {
                        method: 'POST',
                        body: formData
                    });
                    const data = await response.json();
                    if (data.success) {
                        showToast(data.success, 'bg-green-500');
                        location.reload();
                    } else {
                        showToast(data.error || 'Failed to include faculty.', 'bg-red-500');
                    }
                } catch (error) {
                    showToast('Failed to include faculty. Please try again.', 'bg-red-500');
                }
            });

            document.getElementById('closeRemoveModalBtn').addEventListener('click', () => closeModal('remove-modal'));
            document.getElementById('cancelRemoveBtn').addEventListener('click', () => closeModal('remove-modal'));
            document.getElementById('confirmRemoveBtn').addEventListener('click', async () => {
                const userId = document.getElementById('remove-modal-user-id').value;
                const formData = new FormData();
                formData.append('action', 'remove_faculty');
                formData.append('user_id', userId);

                try {
                    const response = await fetch(window.location.href, {
                        method: 'POST',
                        body: formData
                    });
                    const data = await response.json();
                    if (data.success) {
                        showToast(data.success, 'bg-green-500');
                        location.reload();
                    } else {
                        showToast(data.error || 'Failed to remove faculty.', 'bg-red-500');
                    }
                } catch (error) {
                    showToast('Failed to remove faculty. Please try again.', 'bg-red-500');
                }
            });

            ['include-modal', 'remove-modal', 'faculty-details-modal'].forEach(modalId => {
                const modal = document.getElementById(modalId);
                modal.addEventListener('click', (e) => {
                    if (e.target === modal) closeModal(modalId);
                });
            });

            document.addEventListener('keydown', (e) => {
                if (e.key === 'Escape') {
                    ['include-modal', 'remove-modal', 'faculty-details-modal'].forEach(modalId => {
                        const modal = document.getElementById(modalId);
                        if (!modal.classList.contains('hidden')) closeModal(modalId);
                    });
                }
            });
        });
    </script>
</body>

</html>

<?php
$content = ob_get_clean();
require_once __DIR__ . '/layout.php';
?>