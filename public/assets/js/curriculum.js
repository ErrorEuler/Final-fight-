let duplicateCheckTimeout = null;
let currentCurriculumId = null;

// Modal functions (unchanged)
function openModal(modalId) {
    console.log(`Opening modal: ${modalId}`);
    try {
        const modal = document.getElementById(modalId);
        if (!modal) {
            console.error(`Modal ${modalId} not found`);
            showToast(`Error: Modal ${modalId} not found`, 'error');    
            return;
        }

        const overlay = modal.querySelector('.modal-overlay');
        if (!overlay) {
            console.error(`Modal overlay not found in ${modalId}`);
            showToast('Error: Modal overlay not found', 'error');
            return;
        }

        modal.classList.remove('hidden');
        document.body.style.overflow = 'hidden';
        modal.offsetWidth;
        overlay.classList.add('active');
        console.log(`Modal ${modalId} opened successfully`);
    } catch (error) {
        console.error(`Error opening modal ${modalId}:`, error);
        showToast('Failed to open modal', 'error');
    }
}

function closeModal(modalId) {
    console.log(`Closing modal: ${modalId}`);
    try {
        const modal = document.getElementById(modalId);
        if (!modal) {
            console.error(`Modal ${modalId} not found`);
            showToast(`Error: Modal ${modalId} not found`, 'error');
            return;
        }

        const overlay = modal.querySelector('.modal-overlay');
        if (overlay) {
            overlay.classList.remove('active');
        }

        setTimeout(() => {
            modal.classList.add('hidden');
            document.body.style.overflow = '';
            if (modalId === 'editCurriculumModal') {
                resetEditForm();
            } else if (modalId === 'manageCoursesModal') {
                resetManageCoursesForm();
                const curriculumId = document.getElementById('curriculumIdInput')?.value;
                if (curriculumId) {
                    refreshCurriculumData(curriculumId);
                }
            } else if (modalId === 'removeCourseConfirmModal') {
                resetRemoveConfirmModal();
                const confirmButton = document.getElementById('removeConfirmButton');
                const curriculumId = confirmButton?.dataset.curriculumId;
                if (curriculumId) {
                    refreshCurriculumData(curriculumId);
                }
            }
        }, 300);
        console.log(`Modal ${modalId} closed successfully`);
    } catch (error) {
        console.error(`Error closing modal ${modalId}:`, error);
        showToast('Failed to close modal', 'error');
    }
}

// Updated refreshCurriculumData function with null checks and debugging
function refreshCurriculumData(curriculumId) {
    console.log(`Refreshing curriculum data for ID: ${curriculumId}`);
    fetch(window.location.href, {
        method: 'POST',
        headers: {
            'Content-Type': 'application/x-www-form-urlencoded',
            'X-Requested-With': 'XMLHttpRequest'
        },
        body: `action=get_curriculum_data&curriculum_id=${encodeURIComponent(curriculumId)}`
    })
    .then(response => {
        if (!response.ok) {
            throw new Error(`HTTP ${response.status}: ${response.statusText}`);
        }
        return response.json();
    })
    .then(data => {
        if (data.error) {
            console.error('Server error:', data.error);
            showToast(data.error, 'error');
            return;
        }
        // Find the table row
        const row = document.querySelector(`tr[data-curriculum-id="${curriculumId}"]`);
        console.log(`Row found for curriculumId ${curriculumId}:`, row);
        if (row) {
            const unitsCell = row.querySelector('.total-units');
            if (unitsCell) {
                unitsCell.textContent = data.total_units || '0';
                console.log(`Updated total units to: ${data.total_units}`);
            } else {
                console.warn(`Total units cell not found for curriculum ${curriculumId}`);
            }
            // Fetch course count
            fetch(window.location.href, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/x-www-form-urlencoded',
                    'X-Requested-With': 'XMLHttpRequest'
                },
                body: `action=get_curriculum_courses&curriculum_id=${encodeURIComponent(curriculumId)}`
            })
            .then(response => response.json())
            .then(coursesData => {
                if (!coursesData.error) {
                    const courseCount = coursesData.length;
                    const coursesCell = row.querySelector('td:nth-child(2)'); // Second column for course count
                    if (coursesCell) {
                        coursesCell.textContent = `${courseCount} Courses`;
                        console.log(`Updated course count to: ${courseCount}`);
                    } else {
                        console.warn(`Courses cell not found for curriculum ${curriculumId}`);
                    }
                } else {
                    console.error('Error fetching courses:', coursesData.error);
                }
            })
            .catch(error => console.error('Error fetching course count:', error));
        } else {
            console.warn(`No row found for curriculumId ${curriculumId}. Refreshing full table...`);
            fetchCurriculaTable(curriculumId);
        }
    })
    .catch(error => {
        console.error('Error refreshing curriculum data:', error);
        showToast('Failed to refresh curriculum data. Please try again.', 'error');
    });
}

// Edit curriculum modal (unchanged)
function openEditCurriculumModal(curriculumData) {
    console.log('Opening edit curriculum modal with data:', curriculumData);
    try {
        if (typeof curriculumData === 'number' || typeof curriculumData === 'string') {
            fetchCurriculumData(curriculumData);
            return;
        }
        populateEditForm(curriculumData);
        openModal('editCurriculumModal');
    } catch (error) {
        console.error('Error in openEditCurriculumModal:', error);
        showToast('Failed to open edit modal', 'error');
    }
}

function fetchCurriculumData(curriculumId) {
    console.log('Fetching curriculum data for ID:', curriculumId);
    showToast('Loading curriculum data...', 'info');
    

    fetch(window.location.href, {
        method: 'POST',
        headers: {
            'Content-Type': 'application/x-www-form-urlencoded',
            'X-Requested-With': 'XMLHttpRequest'
        },
        body: `action=get_curriculum_data&curriculum_id=${encodeURIComponent(curriculumId)}`
    })
    .then(response => {
        if (!response.ok) {
            throw new Error(`HTTP ${response.status}: ${response.statusText}`);
        }
        return response.json();
    })
    .then(data => {
        if (data.error) {
            console.error('Server error:', data.error);
            showToast(data.error, 'error');
            return;
        }
        populateEditForm(data);
        openModal('editCurriculumModal');
    })
    .catch(error => {
        console.error('Error fetching curriculum data:', error);
        showToast('Failed to load curriculum data. Please try again.', 'error');
    });
}

function populateEditForm(data) {
    console.log('Populating edit form with:', data);
    try {
        const fields = {
            'editCurriculumId': data.id || data.curriculum_id,
            'editCurriculumName': data.name || data.curriculum_name,
            'editCurriculumCode': data.code || data.curriculum_code,
            'editEffectiveYear': data.year || data.effective_year,
            'editDescription': data.description || '',
            'editStatus': data.status || 'Draft'
        };

        for (const [fieldId, value] of Object.entries(fields)) {
            const element = document.getElementById(fieldId);
            if (element) {
                element.value = value || '';
                console.log(`Set ${fieldId} to:`, value);
            } else {
                console.warn(`Field ${fieldId} not found in DOM`);
            }
        }
        currentCurriculumId = data.id || data.curriculum_id;
    } catch (error) {
        console.error('Error populating edit form:', error);
        showToast('Error loading curriculum data', 'error');
    }
}

function resetEditForm() {
    const form = document.getElementById('editCurriculumForm');
    if (form) {
        form.reset();
    }
    currentCurriculumId = null;
}

function resetManageCoursesForm() {
    const form = document.getElementById('manageCoursesForm');
    if (form) {
        form.reset();
    }
    hideAllNotifications();
    enableAddButton();
}

function hideAllNotifications() {
    const notifications = ['courseExistsNotification', 'courseCheckingLoader'];
    notifications.forEach(id => {
        const element = document.getElementById(id);
        if (element) element.classList.add('hidden');
    });
}

function enableAddButton(enabled = true) {
    const button = document.getElementById('addCourseButton');
    if (button) {
        button.disabled = !enabled;
    }
}

// Toast notification (unchanged)
function showToast(message, type = 'success') {
    const bgColors = {
        success: 'bg-green-500',
        error: 'bg-red-500',
        warning: 'bg-yellow-500',
        info: 'bg-blue-500'
    };

    const icons = {
        success: `<svg class="w-5 h-5 mr-2" fill="currentColor" viewBox="0 0 20 20"><path fill-rule="evenodd" d="M10 18a8 8 0 100-16 8 8 0 000 16zm3.707-9.293a1 1 0 00-1.414-1.414L9 10.586 7.707 9.293a1 1 0 00-1.414 1.414l2 2a1 1 0 001.414 0l4-4z" clip-rule="evenodd"></path></svg>`,
        error: `<svg class="w-5 h-5 mr-2" fill="currentColor" viewBox="0 0 20 20"><path fill-rule="evenodd" d="M18 10a8 8 0 11-16 0 8 8 0 0116 0zm-7 4a1 1 0 11-2 0 1 1 0 012 0zm-1-9a1 1 0 00-1 1v4a1 1 0 102 0V6a1 1 0 00-1-1z" clip-rule="evenodd"></path></svg>`,
        warning: `<svg class="w-5 h-5 mr-2" fill="currentColor" viewBox="0 0 20 20"><path fill-rule="evenodd" d="M8.257 3.099c.765-1.36 2.722-1.36 3.486 0l5.58 9.92c.75 1.334-.213 2.98-1.742 2.98H4.42c-1.53 0-2.493-1.646-1.743-2.98l5.58-9.92zM11 13a1 1 0 11-2 0 1 1 0 012 0zm-1-8a1 1 0 00-1 1v3a1 1 0 002 0V6a1 1 0 00-1-1z" clip-rule="evenodd"></path></svg>`,
        info: `<svg class="w-5 h-5 mr-2" fill="currentColor" viewBox="0 0 20 20"><path fill-rule="evenodd" d="M18 10a8 8 0 11-16 0 8 8 0 0116 0zm-7-4a1 1 0 11-2 0 1 1 0 012 0zM9 9a1 1 0 000 2v3a1 1 0 001 1h1a1 1 0 100-2v-3a1 1 0 00-1-1H9z" clip-rule="evenodd"></path></svg>`
    };

    const existingToasts = document.querySelectorAll('.toast-notification');
    existingToasts.forEach(toast => toast.remove());

    const toast = document.createElement('div');
    toast.className = `fixed top-4 right-4 px-4 py-3 rounded-lg shadow-lg text-white ${bgColors[type]} transition-all duration-300 z-50 flex items-center max-w-sm toast-notification`;
    toast.innerHTML = `${icons[type]}${message}`;
    toast.style.transform = 'translateX(100%)';

    document.body.appendChild(toast);

    setTimeout(() => {
        toast.style.transform = 'translateX(0)';
    }, 100);

    setTimeout(() => {
        toast.style.transform = 'translateX(100%)';
        setTimeout(() => {
            if (toast.parentNode) {
                toast.remove();
            }
        }, 300);
    }, 4000);
}


// Update total units in the curriculum table (unchanged)
function updateCurriculumTotalUnits(curriculumId, totalUnits) {
    const row = document.querySelector(`tr[data-curriculum-id="${curriculumId}"]`);
    if (row) {
        const unitsCell = row.querySelector('.total-units');
        if (unitsCell) {
            unitsCell.textContent = totalUnits;
        } else {
            console.warn(`Total units cell not found for curriculum ${curriculumId}`);
        }
    } else {
        console.warn(`Curriculum row not found for ID ${curriculumId}`);
    }
}

// Manage courses modal (unchanged)
function openManageCoursesModal(curriculumId, curriculumName) {
    const curriculumIdInput = document.getElementById('curriculumIdInput');
    const manageCoursesTitle = document.getElementById('manageCoursesTitle');
    
    if (!curriculumIdInput || !manageCoursesTitle) {
        console.error('Required elements for manageCoursesModal not found');
        showToast('Error: Manage Courses modal elements not found', 'error');
        return;
    }

    curriculumIdInput.value = curriculumId;
    manageCoursesTitle.textContent = `Manage Courses for ${curriculumName}`;
    resetManageCoursesForm();
    openModal('manageCoursesModal');

    setTimeout(() => {
        const courseSearchInput = document.getElementById('courseSearchInput');
        if (courseSearchInput) courseSearchInput.focus();
    }, 300);
}

// View courses modal (unchanged)
function openViewCoursesModal(courses, curriculumName, curriculumId) {
    const container = document.getElementById('coursesContainer');
    const noCoursesMessage = document.getElementById('noCoursesMessage');

    if (!container || !noCoursesMessage) {
        console.error('Required DOM elements not found for view courses modal');
        showToast('Error: View Courses modal elements not found', 'error');
        return;
    }

    container.innerHTML = '';
    let hasInvalidCourses = false;

    if (!courses || courses.length === 0) {
        noCoursesMessage.classList.remove('hidden');
        container.classList.add('hidden');
    } else {
        noCoursesMessage.classList.add('hidden');
        container.classList.remove('hidden');

        const groupedCourses = {};
        courses.forEach(course => {
            if (!course.course_id) {
                console.warn(`Missing course_id for course: ${course.course_code} - ${course.course_name}`);
                hasInvalidCourses = true;
                return;
            }
            const key = `${course.year_level}-${course.semester}`;
            if (!groupedCourses[key]) {
                groupedCourses[key] = [];
            }
            groupedCourses[key].push(course);
        });

        if (hasInvalidCourses) {
            const warningDiv = document.createElement('div');
            warningDiv.className = 'mb-4 p-3 bg-yellow-100 text-yellow-800 rounded-lg flex items-center';
            warningDiv.innerHTML = `
                <svg class="w-5 h-5 mr-2" fill="currentColor" viewBox="0 0 20 20">
                    <path fill-rule="evenodd" d="M8.257 3.099c.765-1.36 2.722-1.36 3.486 0l5.58 9.92c.75 1.334-.213 2.98-1.742 2.98H4.42c-1.53 0-2.493-1.646-1.743-2.98l5.58-9.92zM11 13a1 1 0 11-2 0 1 1 0 012 0zm-1-8a1 1 0 00-1 1v3a1 1 0 002 0V6a1 1 0 00-1-1z" clip-rule="evenodd"></path>
                </svg>
                Some courses could not be displayed due to missing data. Please contact support.
            `;
            container.appendChild(warningDiv);
        }

        const yearOrder = ['1st Year', '2nd Year', '3rd Year', '4th Year'];
        const semesterOrder = ['1st', '2nd', 'Mid Year'];
        const sortedKeys = Object.keys(groupedCourses).sort((a, b) => {
            const [yearA, semesterA] = a.split('-');
            const [yearB, semesterB] = b.split('-');
            const yearDiff = yearOrder.indexOf(yearA) - yearOrder.indexOf(yearB);
            if (yearDiff !== 0) return yearDiff;
            return semesterOrder.indexOf(semesterA) - semesterOrder.indexOf(semesterB);
        });

        sortedKeys.forEach(key => {
            const [yearLevel, semester] = key.split('-');
            const groupCourses = groupedCourses[key].sort((a, b) =>
                (a.course_code || '').localeCompare(b.course_code || '')
            );

            const header = document.createElement('div');
            header.className = 'mt-6 mb-4';
            header.innerHTML = `
                <h4 class="text-lg font-semibold text-gray-800 flex items-center">
                    <svg class="w-5 h-5 mr-2 text-amber-500" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                        <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M19 11H5m14 0a2 2 0 012 2v6a2 2 0 01-2 2H5a2 2 0 01-2-2v-6a2 2 0 012-2m14 0V9a2 2 0 00-2-2M5 11V9a2 2 0 012-2m0 0V5a2 2 0 012-2h6a2 2 0 012 2v2M7 7h10"></path>
                    </svg>
                    ${yearLevel} - ${semester} Semester
                    <span class="ml-2 text-sm text-gray-600 bg-gray-100 px-2 py-1 rounded-full">${groupCourses.length} courses</span>
                </h4>
                <hr class="border-gray-200 mt-2">
            `;
            container.appendChild(header);

            const table = document.createElement('table');
            table.className = 'w-full table-auto border-collapse mb-6';
            table.innerHTML = `
                <thead>
                    <tr class="bg-gray-800 text-white">
                        <th class="px-4 py-3 text-left text-xs font-semibold">Course Code</th>
                        <th class="px-4 py-3 text-left text-xs font-semibold">Course Name</th>
                        <th class="px-4 py-3 text-left text-xs font-semibold">Units</th>
                        <th class="px-4 py-3 text-left text-xs font-semibold">Subject Type</th>
                        <th class="px-4 py-3 text-left text-xs font-semibold">Action</th>
                    </tr>
                </thead>
                <tbody class="divide-y divide-gray-200">
                    ${groupCourses.map(course => `
                        <tr class="hover:bg-gray-50 transition-colors">
                            <td class="px-4 py-3 text-sm font-medium text-gray-900">${course.course_code || ''}</td>
                            <td class="px-4 py-3 text-sm text-gray-900">${course.course_name || ''}</td>
                            <td class="px-4 py-3 text-sm text-gray-600">${course.units || ''}</td>
                            <td class="px-4 py-3 text-sm">
                                <span class="inline-flex items-center px-2 py-1 rounded-full text-xs font-medium bg-blue-100 text-blue-800">
                                    ${course.subject_type || 'N/A'}
                                </span>
                            </td>
                            <td class="px-4 py-3 text-sm font-medium">
                                <button class="remove-course-btn text-red-600 hover:text-red-800 hover:bg-red-50 transition-all p-2 rounded-lg"
                                    data-course-id="${course.course_id}"
                                    data-curriculum-id="${curriculumId}"
                                    data-course-name="${course.course_name || ''}"
                                    data-course-code="${course.course_code || ''}"
                                    title="Remove Course">
                                    <i class="fas fa-times"></i>
                                </button>
                            </td>
                        </tr>
                    `).join('')}
                </tbody>
            `;
            container.appendChild(table);
        });
    }

    document.getElementById('viewCoursesTitle').textContent = `Courses for ${curriculumName}`;
    openModal('viewCoursesModal');
}


function fetchCoursesAndRefreshModal(curriculumId, curriculumName) {
    fetch(window.location.href, {
        method: 'POST',
        headers: {
            'Content-Type': 'application/x-www-form-urlencoded',
            'X-Requested-With': 'XMLHttpRequest'
        },
        body: `action=get_curriculum_courses&curriculum_id=${encodeURIComponent(curriculumId)}`
    })
    .then(response => {
        if (!response.ok) {
            throw new Error(`HTTP ${response.status}: ${response.statusText}`);
        }
        return response.json();
    })
    .then(data => {
        if (data.error) {
            showToast(data.error, 'error');
            return;
        }
        openViewCoursesModal(data, curriculumName, curriculumId);
    })
    .catch(error => {
        console.error('Fetch Courses Error:', error);
        showToast('Failed to refresh courses', 'error');
    });
}

function checkCourseDuplicate(curriculumId, courseId) {
    if (!curriculumId || !courseId) {
        hideAllNotifications();
        enableAddButton();
        return;
    }

    hideAllNotifications();
    const courseCheckingLoader = document.getElementById('courseCheckingLoader');
    if (courseCheckingLoader) courseCheckingLoader.classList.remove('hidden');
    enableAddButton(false);

    if (duplicateCheckTimeout) {
        clearTimeout(duplicateCheckTimeout);
    }

    duplicateCheckTimeout = setTimeout(() => {
        

        fetch(window.location.href, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/x-www-form-urlencoded',
                'X-Requested-With': 'XMLHttpRequest'
            },
            body: `action=check_course_in_curriculum&curriculum_id=${encodeURIComponent(curriculumId)}&course_id=${encodeURIComponent(courseId)}`
        })
        .then(response => {
            if (!response.ok) {
                throw new Error(`HTTP ${response.status}: ${response.statusText}`);
            }
            return response.json();
        })
        .then(data => {
            hideAllNotifications();
            if (data.exists) {
                const courseSelect = document.getElementById('courseSelect');
                const selectedOption = courseSelect.options[courseSelect.selectedIndex];
                const courseCode = selectedOption.dataset.code;
                const courseName = selectedOption.dataset.name;

                const courseExistsMessage = document.getElementById('courseExistsMessage');
                if (courseExistsMessage) {
                    courseExistsMessage.innerHTML = `<strong>${courseCode}</strong> - ${courseName} is already part of this curriculum. Please select a different course.`;
                }
                const courseExistsNotification = document.getElementById('courseExistsNotification');
                if (courseExistsNotification) courseExistsNotification.classList.remove('hidden');
                enableAddButton(false);
            } else {
                enableAddButton(true);
            }
            
        })
        .catch(error => {
            console.error('Error checking course:', error);
            hideAllNotifications();
            enableAddButton(true);
            showToast('Error checking for duplicates', 'error');
        });
    }, 500);
}

// Remove course confirmation modal (unchanged)
function openRemoveConfirmModal(button) {
    const courseId = button.dataset.courseId;
    const curriculumId = button.dataset.curriculumId;
    const courseName = button.dataset.courseName;
    const courseCode = button.dataset.courseCode;

    if (!courseId || !curriculumId || parseInt(courseId) < 1) {
        openErrorModal('Invalid course ID. Cannot proceed with removal.');
        return;
    }

    const confirmMessage = document.getElementById('removeConfirmMessage');
    const confirmButton = document.getElementById('removeConfirmButton');
    if (confirmMessage && confirmButton) {
        confirmMessage.innerHTML = `Are you sure you want to remove <strong>${courseCode} - ${courseName}</strong> from this curriculum? This action cannot be undone.`;
        confirmButton.dataset.courseId = courseId;
        confirmButton.dataset.curriculumId = curriculumId;
        confirmButton.dataset.courseName = courseName;
        confirmButton.dataset.courseCode = courseCode;
        openModal('removeCourseConfirmModal');
    } else {
        console.error('Remove confirm modal elements not found');
        showToast('Error: Confirmation modal elements not found', 'error');
    }
}

function resetRemoveConfirmModal() {
    const confirmMessage = document.getElementById('removeConfirmMessage');
    const confirmButton = document.getElementById('removeConfirmButton');
    if (confirmMessage) confirmMessage.innerHTML = '';
    if (confirmButton) {
        confirmButton.dataset.courseId = '';
        confirmButton.dataset.curriculumId = '';
        confirmButton.dataset.courseName = '';
        confirmButton.dataset.courseCode = '';
    }
}

// Error modal (unchanged)
function openErrorModal(message) {
    const errorMessage = document.getElementById('errorModalMessage');
    if (errorMessage) {
        errorMessage.innerHTML = message;
        openModal('errorModal');
    } else {
        console.error('Error modal elements not found');
        showToast('Error: Error modal elements not found', 'error');
    }
}

// Remove course
function handleRemoveCourse(button) {
    openRemoveConfirmModal(button);
}

function confirmRemoveCourse(button) {
    const courseId = button.dataset.courseId;
    const curriculumId = button.dataset.curriculumId;
    const courseName = button.dataset.courseName;
    const courseCode = button.dataset.courseCode;

    console.log('Removing course:', { courseId, curriculumId, courseName, courseCode });

    if (!courseId || !curriculumId || parseInt(courseId) < 1) {
        openErrorModal('Invalid course ID. Cannot proceed with removal.');
        return;
    }

    const originalContent = button.innerHTML;
    button.innerHTML = `<div class="loading-spinner"></div>`;
    button.disabled = true;

    fetch(window.location.href, {
        method: 'POST',
        headers: {
            'Content-Type': 'application/x-www-form-urlencoded',
            'X-Requested-With': 'XMLHttpRequest'
        },
        body: `action=remove_course&curriculum_id=${encodeURIComponent(curriculumId)}&course_id=${encodeURIComponent(courseId)}`
    })
    .then(response => {
        if (!response.ok) {
            return response.text().then(text => {
                throw new Error(`HTTP ${response.status}: ${text}`);
            });
        }
        return response.json();
    })
    .then(data => {
        button.innerHTML = originalContent;
        button.disabled = false;
        if (data.success) {
            showToast(`${courseCode} removed successfully!`, 'success');
            closeModal('removeCourseConfirmModal');

            const row = button.closest('tr');
            if (row) {
                row.style.opacity = '0';
                row.style.transform = 'translateX(-10px)';
                setTimeout(() => {
                    row.remove();
                    const table = row.closest('table');
                    if (table) {
                        const tbody = table.querySelector('tbody');
                        if (tbody && tbody.children.length === 0) {
                            const tableContainer = table.parentElement;
                            if (tableContainer) {
                                tableContainer.remove();
                            }
                        }
                    }
                }, 300);
            }

            if (data.new_total_units !== undefined) {
                updateCurriculumTotalUnits(curriculumId, data.new_total_units);
            }

            // Refresh curriculum data to update total units and course count
            refreshCurriculumData(curriculumId);

            // Refresh viewCoursesModal if it's open
            if (!document.getElementById('viewCoursesModal').classList.contains('hidden')) {
                const curriculumName = document.getElementById('viewCoursesTitle').textContent.replace('Courses for ', '');
                fetchCoursesAndRefreshModal(curriculumId, curriculumName);
            }
        } else {
            throw new Error(data.error || 'Failed to remove course');
        }
    })
    .catch(error => {
        console.error('Remove course error:', error);
        button.innerHTML = originalContent;
        button.disabled = false;
        openErrorModal(error.message || 'Failed to remove course');
    });
}


document.addEventListener('DOMContentLoaded', function() {
    console.log('DOM loaded, setting up event listeners');

    const editForm = document.getElementById('editCurriculumForm');
    if (editForm) {
        editForm.addEventListener('submit', function(e) {
            e.preventDefault();
            console.log('Edit form submitted');
            const formData = new FormData(this);
            console.log('Form data:');
            for (let [key, value] of formData.entries()) {
                console.log(key, value);
            }
            
            const submitBtn = document.getElementById('editSubmitBtn');
            const submitText = document.getElementById('editSubmitText');
            const submitSpinner = document.getElementById('editSubmitSpinner');
            if (submitBtn && submitText && submitSpinner) {
                submitBtn.disabled = true;
                submitText.classList.add('hidden');
                submitSpinner.classList.remove('hidden');
            }
            
            showToast('Updating curriculum...', 'info');
            
            fetch(window.location.href, {
                method: 'POST',
                headers: {
                    'X-Requested-With': 'XMLHttpRequest'
                },
                body: formData
            })
            .then(response => {
                if (!response.ok) {
                    throw new Error(`HTTP ${response.status}: ${response.statusText}`);
                }
                return response.json();
            })
            .then(data => {
                if (data.success) {
                    showToast(data.success, 'success');
                    closeModal('editCurriculumModal');
                    setTimeout(() => {
                        window.location.reload(); // Keep reload for curriculum edit
                    }, 1500);
                } else {
                    throw new Error(data.error || 'Failed to update curriculum');
                }
            })
            .catch(error => {
                console.error('Error updating curriculum:', error);
                showToast(error.message || 'Failed to update curriculum', 'error');
            })
            .finally(() => {
                if (submitBtn && submitText && submitSpinner) {
                    submitBtn.disabled = false;
                    submitText.classList.remove('hidden');
                    submitSpinner.classList.add('hidden');
                }
            });
        });
    }

    const courseSearchInput = document.getElementById('courseSearchInput');
    if (courseSearchInput) {
        courseSearchInput.addEventListener('input', function() {
            const searchTerm = this.value.toLowerCase();
            const options = document.querySelectorAll('#courseSelect option');
            options.forEach(option => {
                if (option.value === '') return;
                const text = option.textContent.toLowerCase();
                option.style.display = text.includes(searchTerm) ? '' : 'none';
            });
        });
    }

    const courseSelect = document.getElementById('courseSelect');
    const subjectTypeSelect = document.getElementById('subjectTypeSelect');
    if (courseSelect && subjectTypeSelect) {
        courseSelect.addEventListener('change', function() {
            const selectedOption = this.options[this.selectedIndex];
            const subjectType = selectedOption.dataset.subjectType || '';
            subjectTypeSelect.value = subjectType === 'Unknown' ? '' : subjectType;
            console.log('Selected course ID:', this.value, 'Subject type:', subjectType);
            const curriculumId = document.getElementById('curriculumIdInput')?.value;
            const courseId = this.value;
            checkCourseDuplicate(curriculumId, courseId);
        });
    }

    const manageCoursesForm = document.getElementById('manageCoursesForm');
    if (manageCoursesForm) {
        manageCoursesForm.addEventListener('submit', function(e) {
            e.preventDefault(); // Prevent default form submission
            const formData = new FormData(this);
            const curriculumId = formData.get('curriculum_id');
            const courseSelect = document.getElementById('courseSelect');
            const selectedOption = courseSelect.options[courseSelect.selectedIndex];
            const courseName = selectedOption ? selectedOption.dataset.name : 'Unknown Course';

            console.log('Submitting add_course:', {
                curriculum_id: curriculumId,
                course_id: formData.get('course_id'),
            });

            enableAddButton(false);
            hideAllNotifications();

            fetch(window.location.href, {
                method: 'POST',
                headers: {
                    'X-Requested-With': 'XMLHttpRequest'
                },
                body: formData
            })
            .then(response => {
                if (!response.ok) {
                    return response.text().then(text => {
                        throw new Error(`HTTP ${response.status}: ${text}`);
                    });
                }
                return response.json();
            })
            .then(data => {
                enableAddButton(true);
                if (data.success) {
                    showToast(`${courseName} added successfully!`, 'success');
                    resetManageCoursesForm(); // Reset form but keep modal open
                    if (data.new_total_units !== undefined) {
                        updateCurriculumTotalUnits(curriculumId, data.new_total_units);
                    }
                    // Refresh the viewCoursesModal if it's open
                    if (!document.getElementById('viewCoursesModal').classList.contains('hidden')) {
                        const curriculumName = document.getElementById('viewCoursesTitle').textContent.replace('Courses for ', '');
                        fetchCoursesAndRefreshModal(curriculumId, curriculumName);
                    }
                } else {
                    showToast(data.error || 'Failed to add course', 'error');
                }
            })
            .catch(error => {
                console.error('Error adding course:', error);
                enableAddButton(true);
                showToast(error.message || 'Failed to add course', 'error');
            });
        });
    }

    document.addEventListener('click', function(e) {
        if (e.target.closest('.remove-course-btn')) {
            e.preventDefault();
            const button = e.target.closest('.remove-course-btn');
            handleRemoveCourse(button);
        }
        if (e.target.id === 'removeConfirmButton') {
            confirmRemoveCourse(e.target);
        }
    });

    const searchInput = document.getElementById('searchInput');
    const statusFilter = document.getElementById('statusFilter');
    const tableBody = document.getElementById('curriculaTableBody');

    function filterTable() {
        const searchTerm = searchInput?.value.toLowerCase() || '';
        const statusValue = statusFilter?.value.toLowerCase() || '';

        if (tableBody) {
            Array.from(tableBody.getElementsByTagName('tr')).forEach(row => {
                if (row.dataset.name) {
                    const name = row.dataset.name.toLowerCase();
                    const status = row.dataset.status;
                    const matchesSearch = name.includes(searchTerm);
                    const matchesStatus = !statusValue || status === statusValue;
                    row.style.display = matchesSearch && matchesStatus ? '' : 'none';
                }
            });
        }
    }

    [searchInput, statusFilter].forEach(element => {
        if (element) {
            element.addEventListener('input', () => {
                clearTimeout(window.filterTimeout);
                window.filterTimeout = setTimeout(filterTable, 300);
            });
        }
    });

    filterTable();

    document.addEventListener('click', function(e) {
        if (e.target.classList.contains('modal-overlay') && e.target.classList.contains('active')) {
            const modal = e.target.closest('[id$="Modal"]');
            if (modal) {
                closeModal(modal.id);
            }
        }
    });

    document.addEventListener('keydown', function(e) {
        if (e.key === 'Escape') {
            const activeModal = document.querySelector('.modal-overlay.active');
            if (activeModal) {
                const modal = activeModal.closest('[id$="Modal"]');
                if (modal) {
                    closeModal(modal.id);
                }
            }
        }
    });
});