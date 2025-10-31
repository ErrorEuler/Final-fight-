<!DOCTYPE html>
<html lang="en">

<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>PRMSU Iba Campus Class Schedules - ACSS</title>
    <link rel="stylesheet" href="/css/output.css">
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css">
    <style>
        /* Existing styles remain unchanged */
        @import url('https://fonts.googleapis.com/css2?family=Montserrat:wght@300;400;500;600;700&display=swap');

        :root {
            --gold-primary: #DA9100;
            --gold-secondary: #FCC201;
            --gold-light: #FFEEAA;
            --gold-dark: #B8860B;
            --gold-gradient-start: #FFD200;
            --gold-gradient-end: #FFEEAA;
        }

        body {
            font-family: 'Montserrat', sans-serif;
            background-color: #FAFAFA;
            color: #333;
            margin: 0;
            padding: 0;
        }

        /* Add semester display style */
        .semester-display {
            background-color: rgba(255, 238, 170, 0.2);
            padding: 0.5rem 1rem;
            border-radius: 0.5rem;
            font-size: 0.875rem;
            color: var(--gold-dark);
            font-weight: 500;
        }

        /* Download form style */
        .download-form {
            display: none;
            background-color: white;
            padding: 1rem;
            border-radius: 0.5rem;
            box-shadow: 0 4px 6px rgba(0, 0, 0, 0.1);
            margin-top: 1rem;
        }

        .download-form.active {
            display: block;
        }

        /* Existing styles remain unchanged */
        .hero-pattern {
            background: linear-gradient(135deg, var(--gold-primary), var(--gold-secondary));
            position: relative;
            overflow: hidden;
            padding: 1rem 0;
        }

        .hero-pattern::after {
            content: '';
            position: absolute;
            top: 0;
            left: 0;
            right: 0;
            bottom: 0;
            background-image: url("data:image/svg+xml,%3Csvg width='60' height='60' viewBox='0 0 60 60' xmlns='http://www.w3.org/2000/svg'%3E%3Cg fill='none' fill-rule='evenodd'%3E%3Cg fill='%23ffffff' fill-opacity='0.15'%3E%3Cpath d='M36 34v-4h-2v4h-4v2h4v4h2v-4h4v-2h-4zm0-30V0h-2v4h-4v2h4v4h2V6h4V4h-4zM6 34v-4H4v4H0v2h4v4h2v-4h4v-2H6zM6 4V0H4v4H0v2h4v4h2V6h4V4H6z'/%3E%3C/g%3E%3C/g%3E%3C/svg%3E");
            opacity: 0.5;
            z-index: 0;
        }

        .form-input {
            border-radius: 0.5rem;
            border: 2px solid #FCC201;
            padding: 0.75rem 1rem 0.75rem 2.5rem;
            width: 100%;
            box-sizing: border-box;
            transition: all 0.15s;
            position: relative;
        }

        .form-input:focus {
            outline: none;
            border-color: var(--gold-primary);
            box-shadow: 0 0 0 3px rgba(218, 145, 0, 0.1);
        }

        .form-input-icon {
            position: absolute;
            left: 0.75rem;
            top: 50%;
            transform: translateY(-50%);
            pointer-events: none;
            color: var(--gold-primary);
        }

        .btn-primary {
            background: linear-gradient(135deg, var(--gold-dark), var(--gold-primary));
            color: white;
            font-weight: 500;
            padding: 0.75rem 1rem;
            border-radius: 0.5rem;
            transition: all 0.15s ease-in-out;
            box-shadow: 0 4px 6px -1px rgba(0, 0, 0, 0.1);
            width: 100%;
            border: none;
            cursor: pointer;
        }

        .btn-primary:hover {
            filter: brightness(1.1);
            transform: translateY(-1px);
            box-shadow: 0 6px 8px -2px rgba(0, 0, 0, 0.15);
        }

        .btn-secondary {
            background: white;
            color: var(--gold-dark);
            font-weight: 500;
            padding: 0.75rem 1rem;
            border-radius: 0.5rem;
            transition: all 0.15s;
            box-shadow: 0 4px 6px -1px rgba(0, 0, 0, 0.1);
            width: 100%;
            border: 1px solid #e5e5e5;
            cursor: pointer;
        }

        .btn-secondary:hover {
            background: #f9fafb;
            box-shadow: 0 6px 8px -2px rgba(0, 0, 0, 0.15);
        }

        .schedule-card {
            transition: all 0.3s ease;
            border-left: 3px solid transparent;
        }

        .schedule-card:hover {
            transform: translateX(3px);
            border-left-color: var(--gold-primary);
            background-color: rgba(255, 238, 170, 0.1);
        }

        .nav-link {
            position: relative;
            transition: all 0.3s ease;
        }

        .nav-link::after {
            content: '';
            position: absolute;
            bottom: -2px;
            left: 0;
            width: 0;
            height: 2px;
            background-color: var(--gold-primary);
            transition: width 0.3s ease;
        }

        .nav-link:hover::after {
            width: 100%;
        }

        .gold-gradient-text {
            background: linear-gradient(135deg, var(--gold-dark), var(--gold-secondary));
            -webkit-background-clip: text;
            background-clip: text;
            color: transparent;
            display: inline-block;
        }

        .card-shadow {
            box-shadow: 0 10px 25px -5px rgba(212, 175, 55, 0.1), 0 8px 10px -6px rgba(212, 175, 55, 0.1);
        }

        .gold-border {
            border: 1px solid rgba(212, 175, 55, 0.3);
        }

        /* Mobile Sidebar Styles */
        .mobile-sidebar {
            position: fixed;
            top: 0;
            left: -100%;
            width: 280px;
            height: 100vh;
            background: white;
            z-index: 50;
            transition: left 0.3s ease-in-out;
            box-shadow: 2px 0 10px rgba(0, 0, 0, 0.1);
        }

        .mobile-sidebar.active {
            left: 0;
        }

        .sidebar-overlay {
            position: fixed;
            top: 0;
            left: 0;
            width: 100%;
            height: 100vh;
            background: rgba(0, 0, 0, 0.5);
            z-index: 40;
            opacity: 0;
            visibility: hidden;
            transition: all 0.3s ease-in-out;
        }

        .sidebar-overlay.active {
            opacity: 1;
            visibility: visible;
        }

        .hamburger {
            display: none;
            cursor: pointer;
            padding: 0.5rem;
        }

        .hamburger span {
            display: block;
            width: 25px;
            height: 3px;
            background: white;
            margin: 5px 0;
            transition: 0.3s;
            border-radius: 2px;
        }

        .hamburger.active span:nth-child(1) {
            transform: rotate(-45deg) translate(-5px, 6px);
        }

        .hamburger.active span:nth-child(2) {
            opacity: 0;
        }

        .hamburger.active span:nth-child(3) {
            transform: rotate(45deg) translate(-5px, -6px);
        }

        /* Responsive adjustments */
        @media (max-width: 768px) {
            .hamburger {
                display: block;
            }

            .desktop-nav {
                display: none;
            }

            .hero-pattern {
                padding: 0.75rem 0;
            }

            .hero-pattern h1 {
                font-size: 1.25rem;
                line-height: 1.4;
            }

            .hero-pattern p {
                font-size: 0.875rem;
            }

            .hero-pattern .flex {
                flex-direction: row;
                justify-content: space-between;
            }

            #search-form {
                padding: 1rem;
                margin-bottom: 2rem;
            }

            #search-form .grid {
                grid-template-columns: 1fr;
                gap: 1rem;
            }

            .schedule-table {
                overflow-x: auto;
                -webkit-overflow-scrolling: touch;
            }

            .schedule-table table {
                min-width: 600px;
            }

            .schedule-table th,
            .schedule-table td {
                padding: 0.5rem;
                font-size: 0.875rem;
            }

            .pagination-info {
                font-size: 0.75rem;
            }

            .px-6 {
                padding-left: 1rem;
                padding-right: 1rem;
            }

            main {
                margin-top: 5rem;
                padding-top: 1rem;
            }
        }

        @media (max-width: 480px) {
            .hero-pattern h1 {
                font-size: 1.125rem;
            }

            .hero-pattern .w-14 {
                width: 2.5rem;
                height: 2.5rem;
            }

            .hero-pattern .w-12 {
                width: 2rem;
                height: 2rem;
            }

            .schedule-table th,
            .schedule-table td {
                padding: 0.375rem;
                font-size: 0.8125rem;
            }

            #search-form {
                padding: 0.75rem;
            }

            .px-6 {
                padding-left: 0.75rem;
                padding-right: 0.75rem;
            }
        }

        @media (min-width: 641px) and (max-width: 1024px) {
            #search-form .grid {
                grid-template-columns: repeat(2, 1fr);
            }

            #search-form .md\\:col-span-2 {
                grid-column: span 2;
            }
        }

        @media (min-width: 1025px) {
            #search-form .grid {
                grid-template-columns: repeat(4, 1fr);
            }
        }

        /* Footer responsive styles */
        @media (max-width: 640px) {
            footer {
                display: none;
            }
        }

        @media (min-width: 641px) and (max-width: 1024px) {
            footer .grid {
                grid-template-columns: repeat(2, 1fr);
                gap: 2rem;
            }

            footer .border-t {
                flex-direction: column;
                gap: 1rem;
                text-align: center;
            }
        }
    </style>
</head>

<body class="bg-white">
    <!-- Mobile Sidebar Overlay -->
    <div class="sidebar-overlay" id="sidebarOverlay" onclick="closeSidebar()"></div>

    <!-- Mobile Sidebar -->
    <div class="mobile-sidebar" id="mobileSidebar">
        <div class="p-6">
            <div class="flex items-center justify-between mb-6">
                <div class="flex items-center">
                    <div class="w-10 h-10 bg-yellow-500 rounded-full flex items-center justify-center mr-3">
                        <img src="/assets/logo/main_logo/PRMSUlogo.png" alt="PRMSU Logo" class="w-12 h-12" />
                    </div>
                    <div>
                        <h2 class="text-lg font-bold text-gray-800">PRMSU</h2>
                        <p class="text-sm text-gray-600">ACSS</p>
                    </div>
                </div>
                <button onclick="closeSidebar()" class="text-gray-600 hover:text-gray-800">
                    <i class="fas fa-times text-xl"></i>
                </button>
            </div>

            <nav class="space-y-4">
                <a href="#" class="flex items-center p-3 text-gray-700 hover:bg-yellow-50 hover:text-yellow-700 rounded-lg transition">
                    <i class="fas fa-home mr-3"></i>
                    <span>Home</span>
                </a>
                <a href="#" class="flex items-center p-3 text-gray-700 hover:bg-yellow-50 hover:text-yellow-700 rounded-lg transition">
                    <i class="fas fa-info-circle mr-3"></i>
                    <span>About</span>
                </a>
                <a href="#" class="flex items-center p-3 text-gray-700 hover:bg-yellow-50 hover:text-yellow-700 rounded-lg transition">
                    <i class="fas fa-book mr-3"></i>
                    <span>Courses</span>
                </a>
                <a href="#" class="flex items-center p-3 text-gray-700 hover:bg-yellow-50 hover:text-yellow-700 rounded-lg transition">
                    <i class="fas fa-users mr-3"></i>
                    <span>Faculty</span>
                </a>
                <a href="#" class="flex items-center p-3 text-gray-700 hover:bg-yellow-50 hover:text-yellow-700 rounded-lg transition">
                    <i class="fas fa-user-graduate mr-3"></i>
                    <span>Student Portal</span>
                </a>
                <a href="#" class="flex items-center p-3 text-gray-700 hover:bg-yellow-50 hover:text-yellow-700 rounded-lg transition">
                    <i class="fas fa-book-open mr-3"></i>
                    <span>Library</span>
                </a>
                <a href="#" class="flex items-center p-3 text-gray-700 hover:bg-yellow-50 hover:text-yellow-700 rounded-lg transition">
                    <i class="fas fa-laptop mr-3"></i>
                    <span>E-Learning</span>
                </a>
                <a href="#" class="flex items-center p-3 text-gray-700 hover:bg-yellow-50 hover:text-yellow-700 rounded-lg transition">
                    <i class="fas fa-question-circle mr-3"></i>
                    <span>FAQ</span>
                </a>

                <div class="border-t pt-4 mt-6">
                    <a href="/auth/login" class="flex items-center p-3 text-gray-700 hover:bg-yellow-50 hover:text-yellow-700 rounded-lg transition mb-2">
                        <i class="fas fa-sign-in-alt mr-3"></i>
                        <span>Login</span>
                    </a>
                    <a href="/register" class="flex items-center p-3 bg-yellow-500 text-white rounded-lg hover:bg-yellow-600 transition">
                        <i class="fas fa-user-plus mr-3"></i>
                        <span>Register</span>
                    </a>
                </div>

                <div class="border-t pt-4 mt-6">
                    <div class="mb-4">
                        <h3 class="text-sm font-semibold text-gray-800 mb-2">Contact Us</h3>
                        <div class="space-y-2 text-sm text-gray-600">
                            <div class="flex items-center">
                                <i class="fas fa-map-marker-alt mr-2 text-yellow-600"></i>
                                <span>Iba, Zambales, Philippines</span>
                            </div>
                            <div class="flex items-center">
                                <i class="fas fa-phone mr-2 text-yellow-600"></i>
                                <span>+63 (XXX) XXX-XXXX</span>
                            </div>
                            <div class="flex items-center">
                                <i class="fas fa-envelope mr-2 text-yellow-600"></i>
                                <span>info@prmsu.edu.ph</span>
                            </div>
                        </div>
                    </div>

                    <div class="flex space-x-3 justify-center">
                        <a href="#" class="w-8 h-8 bg-yellow-500 text-white rounded-full flex items-center justify-center hover:bg-yellow-600 transition">
                            <i class="fab fa-facebook-f text-sm"></i>
                        </a>
                        <a href="#" class="w-8 h-8 bg-yellow-500 text-white rounded-full flex items-center justify-center hover:bg-yellow-600 transition">
                            <i class="fab fa-twitter text-sm"></i>
                        </a>
                        <a href="#" class="w-8 h-8 bg-yellow-500 text-white rounded-full flex items-center justify-center hover:bg-yellow-600 transition">
                            <i class="fab fa-instagram text-sm"></i>
                        </a>
                        <a href="#" class="w-8 h-8 bg-yellow-500 text-white rounded-full flex items-center justify-center hover:bg-yellow-600 transition">
                            <i class="fab fa-youtube text-sm"></i>
                        </a>
                    </div>
                </div>
            </nav>
        </div>
    </div>

    <!-- Header -->
    <header class="hero-pattern shadow-lg fixed w-full z-20">
        <div class="container mx-auto px-4 sm:px-6 py-4 sm:py-6 relative z-10">
            <div class="flex justify-between items-center">
                <div class="flex items-center">
                    <!-- Mobile Hamburger Menu -->
                    <div class="hamburger mr-4" id="hamburger" onclick="openSidebar()">
                        <span></span>
                        <span></span>
                        <span></span>
                    </div>

                    <div class="flex items-center">
                        <div class="mr-3 sm:mr-4">
                            <div class="w-10 h-10 sm:w-14 sm:h-14 bg-white rounded-full flex items-center justify-center shadow-md">
                                <img src="/assets/logo/main_logo/PRMSUlogo.png" alt="PRMSU Logo" class="w-12 h-12" />
                            </div>
                        </div>
                        <div>
                            <h1 class="text-lg sm:text-2xl md:text-3xl font-bold text-white leading-tight">President Ramon Magsaysay State University</h1>
                            <p class="text-white text-xs sm:text-sm md:text-base opacity-90">Automatic Classroom Scheduling System</p>
                        </div>
                    </div>
                </div>

                <!-- Desktop Navigation -->
                <nav class="desktop-nav flex space-x-3">
                    <a href="/auth/login" class="bg-white hover:bg-gray-50 text-yellow-700 py-2 px-4 sm:px-5 rounded-lg flex items-center transition-all shadow-md hover:shadow-lg nav-link text-sm sm:text-base">
                        <i class="fas fa-sign-in-alt mr-2"></i>
                        <span>Login</span>
                    </a>
                    <a href="/register" class="btn-primary px-4 sm:px-5 flex items-center nav-link text-sm sm:text-base">
                        <i class="fas fa-user-plus mr-2"></i>
                        <span>Register</span>
                    </a>
                </nav>
            </div>
        </div>
    </header>

    <!-- Main Content -->
    <main class="container mx-auto px-4 sm:px-6 py-6 sm:py-8">
        <?php if (isset($currentSemester)): ?>
            <div class="semester-display mt-2">
                Current Semester: <?php echo htmlspecialchars($currentSemester['semester_name']) . ' ' . htmlspecialchars($currentSemester['academic_year']); ?>
            </div>
        <?php endif; ?>
        <!-- Search Filters -->
        <div id="search-form" class="bg-white rounded-xl shadow-lg p-4 sm:p-8 mb-8 sm:mb-12 card-shadow gold-border">
            <h3 class="text-lg sm:text-xl font-semibold mb-4 sm:mb-6 gold-gradient-text">Find Your Class Schedule</h3>
            <form id="searchForm" class="grid grid-cols-1 md:grid-cols-4 gap-4 sm:gap-6" method="POST">
                <div>
                    <label for="college" class="block text-sm font-medium text-gray-700 mb-2">College</label>
                    <div class="relative">
                        <select id="college" name="college_id" class="form-input pl-10 py-3">
                            <option value="">All Colleges</option>
                            <?php foreach ($colleges as $college): ?>
                                <option value="<?= $college['college_id'] ?>"><?= $college['college_name'] ?></option>
                            <?php endforeach; ?>
                        </select>
                        <div class="form-input-icon">
                            <i class="fas fa-university"></i>
                        </div>
                    </div>
                </div>

                <div>
                    <label for="department" class="block text-sm font-medium text-gray-700 mb-2">Department</label>
                    <div class="relative">
                        <select id="department" name="department_id" class="form-input pl-10 py-3">
                            <option value="">All Departments</option>
                            <?php foreach ($departments as $department): ?>
                                <option value="<?= $department['department_id'] ?>"><?= $department['department_name'] ?></option>
                            <?php endforeach; ?>
                        </select>
                        <div class="form-input-icon">
                            <i class="fas fa-building"></i>
                        </div>
                    </div>
                </div>

                <div>
                    <label for="year_level" class="block text-sm font-medium text-gray-700 mb-2">Year Level</label>
                    <div class="relative">
                        <select id="year_level" name="year_level" class="form-input pl-10 py-3">
                            <option value="">All Levels</option>
                            <option value="1st Year">1st Year</option>
                            <option value="2nd Year">2nd Year</option>
                            <option value="3rd Year">3rd Year</option>
                            <option value="4th Year">4th Year</option>
                        </select>
                        <div class="form-input-icon">
                            <i class="fas fa-calendar-alt"></i>
                        </div>
                    </div>
                </div>

                <div>
                    <label for="section" class="block text-sm font-medium text-gray-700 mb-2">Section</label>
                    <div class="relative">
                        <select id="section" name="section_id" class="form-input pl-10 py-3">
                            <option value="">All Sections</option>
                        </select>
                        <div class="form-input-icon">
                            <i class="fas fa-users"></i>
                        </div>
                    </div>
                </div>

                <div class="md:col-span-2">
                    <label for="global-search" class="block text-sm font-medium text-gray-700 mb-2">Search</label>
                    <div class="relative">
                        <input type="text" id="global-search" name="search"
                            placeholder="Search courses, instructors..."
                            class="form-input pl-12 py-3">
                        <div class="form-input-icon">
                            <i class="fas fa-search"></i>
                        </div>
                    </div>
                </div>
                <!--
                <div class="md:col-span-2">
                    <button type="button" id="downloadScheduleBtn" class="btn-primary mt-4">
                        <i class="fas fa-download mr-2"></i> Download Schedule PDF
                    </button>
                </div>
                -->
            </form>

            <!-- Download Customization Form
            <div id="downloadForm" class="download-form">
                <h4 class="text-md font-semibold mb-4 gold-gradient-text">Customize Your Schedule PDF</h4>
                <form id="downloadScheduleForm" method="POST" action="/public/download-schedule-pdf">
                    <div class="grid grid-cols-1 md:grid-cols-2 gap-4">
                        <div>
                            <label for="download_college" class="block text-sm font-medium text-gray-700 mb-2">College</label>
                            <select id="download_college" name="college_id" class="form-input pl-10 py-3">
                                <option value="0">All Colleges</option>
                                <?php foreach ($colleges as $college): ?>
                                    <option value="<?= $college['college_id'] ?>"><?= $college['college_name'] ?></option>
                                <?php endforeach; ?>
                            </select>
                        </div>
                        <div>
                            <label for="download_department" class="block text-sm font-medium text-gray-700 mb-2">Department</label>
                            <select id="download_department" name="department_id" class="form-input pl-10 py-3">
                                <option value="0">All Departments</option>
                                <?php foreach ($departments as $department): ?>
                                    <option value="<?= $department['department_id'] ?>"><?= $department['department_name'] ?></option>
                                <?php endforeach; ?>
                            </select>
                        </div>
                        <div>
                            <label for="download_program" class="block text-sm font-medium text-gray-700 mb-2">Program</label>
                            <select id="download_program" name="program_id" class="form-input pl-10 py-3">
                                <option value="0">All Programs</option>
                                <?php foreach ($programs as $program): ?>
                                    <option value="<?= $program['program_id'] ?>"><?= $program['program_name'] ?></option>
                                <?php endforeach; ?>
                            </select>
                        </div>
                        <div>
                            <label for="download_year_level" class="block text-sm font-medium text-gray-700 mb-2">Year Level</label>
                            <select id="download_year_level" name="year_level" class="form-input pl-10 py-3">
                                <option value="">All Levels</option>
                                <option value="1st Year">1st Year</option>
                                <option value="2nd Year">2nd Year</option>
                                <option value="3rd Year">3rd Year</option>
                                <option value="4th Year">4th Year</option>
                            </select>
                        </div>
                        <div>
                            <label for="download_semester" class="block text-sm font-medium text-gray-700 mb-2">Semester</label>
                            <select id="download_semester" name="semester_id" class="form-input pl-10 py-3">
                                <option value="0">All Semesters</option>
                                <?php $semesters = $this->fetchSemesters();
                                foreach ($semesters as $semester): ?>
                                    <option value="<?= $semester['semester_id'] ?>"><?= $semester['semester_name'] . ' ' . $semester['academic_year'] ?></option>
                                <?php endforeach; ?>
                            </select>
                        </div>
                    </div>
                    <button type="submit" class="btn-primary mt-4 w-full">
                        <i class="fas fa-download mr-2"></i> Download PDF
                    </button>
                    <button type="button" class="btn-secondary mt-2 w-full" onclick="closeDownloadForm()">Cancel</button>
                </form>
            </div>
             -->
        </div>

        <!-- Schedule Table -->
        <div class="bg-white rounded-xl shadow-lg overflow-hidden card-shadow gold-border">
            <div class="schedule-table overflow-x-auto">
                <table class="min-w-full divide-y divide-gray-200">
                    <thead class="bg-gray-50">
                        <tr>
                            <th scope="col" class="px-3 sm:px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                                Course
                            </th>
                            <th scope="col" class="px-3 sm:px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                                Section
                            </th>
                            <th scope="col" class="px-3 sm:px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                                Schedule
                            </th>
                            <th scope="col" class="px-3 sm:px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                                Room
                            </th>
                            <th scope="col" class="px-3 sm:px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                                Instructor
                            </th>
                        </tr>
                    </thead>
                    <tbody id="schedule-table-body" class="bg-white divide-y divide-gray-200">
                        <tr class="hover:bg-yellow-50 transition-colors schedule-card">
                        </tr>
                    </tbody>
                </table>
            </div>

            <!-- Pagination -->
            <div class="px-4 sm:px-6 py-4 flex flex-col sm:flex-row items-center justify-between border-t border-gray-200 space-y-3 sm:space-y-0">
                <div class="flex-1 flex justify-between sm:hidden">
                    <a href="#" class="relative inline-flex items-center px-4 py-2 border border-gray-300 text-sm font-medium rounded-md text-gray-700 bg-white hover:bg-gray-50">
                        Previous
                    </a>
                    <a href="#" class="ml-3 relative inline-flex items-center px-4 py-2 border border-gray-300 text-sm font-medium rounded-md text-gray-700 bg-white hover:bg-gray-50">
                        Next
                    </a>
                </div>
                <div class="hidden sm:flex-1 sm:flex sm:items-center sm:justify-between">
                    <div>
                        <p class="text-sm text-gray-700 pagination-info" id="pagination-info">
                            Showing <span class="font-medium">1</span> to <span class="font-medium">1</span> of <span class="font-medium">1</span> results
                        </p>
                    </div>
                    <div>
                        <nav class="relative z-0 inline-flex rounded-md shadow-sm -space-x-px" aria-label="Pagination" id="pagination-nav">
                            <a href="#" class="relative inline-flex items-center px-2 py-2 rounded-l-md border border-gray-300 bg-white text-sm font-medium text-gray-500 hover:bg-gray-50">
                                <span class="sr-only">Previous</span>
                                <i class="fas fa-chevron-left"></i>
                            </a>
                            <a href="#" class="z-10 bg-yellow-500 text-white border-yellow-500 relative inline-flex items-center px-4 py-2 border text-sm font-medium">
                                1
                            </a>
                            <a href="#" class="relative inline-flex items-center px-2 py-2 rounded-r-md border border-gray-300 bg-white text-sm font-medium text-gray-500 hover:bg-gray-50">
                                <span class="sr-only">Next</span>
                                <i class="fas fa-chevron-right"></i>
                            </a>
                        </nav>
                    </div>
                </div>
            </div>
        </div>
    </main>

    <!-- Footer -->
    <footer class="bg-gray-800 text-white mt-8 sm:mt-16 shadow-inner">
        <div class="container mx-auto px-4 sm:px-6 py-8 sm:py-10">
            <div class="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6 lg:gap-8">
                <div class="lg:col-span-1">
                    <div class="flex items-center mb-4">
                        <div class="w-10 h-10 bg-white rounded-full flex items-center justify-center mr-3">
                            <img src="/assets/logo/main_logo/PRMSUlogo.png" alt="PRMSU Logo" class="w-12 h-12" />
                        </div>
                        <div>
                            <h2 class="text-xl font-bold">PRMSU</h2>
                            <p class="text-sm text-gray-400">Academic Schedule Management System</p>
                        </div>
                    </div>
                    <p class="text-gray-400 text-sm max-w-md">
                        President Ramon Magsaysay State University is dedicated to providing quality education
                        through advanced technological solutions.
                    </p>
                </div>

                <div>
                    <h3 class="text-yellow-400 font-semibold mb-3">Quick Links</h3>
                    <ul class="space-y-2">
                        <li><a href="#" class="text-gray-400 hover:text-white transition text-sm">Home</a></li>
                        <li><a href="#" class="text-gray-400 hover:text-white transition text-sm">About</a></li>
                        <li><a href="#" class="text-gray-400 hover:text-white transition text-sm">Courses</a></li>
                        <li><a href="#" class="text-gray-400 hover:text-white transition text-sm">Faculty</a></li>
                        <li><a href="#" class="text-gray-400 hover:text-white transition text-sm">Admissions</a></li>
                    </ul>
                </div>

                <div>
                    <h3 class="text-yellow-400 font-semibold mb-3">Resources</h3>
                    <ul class="space-y-2">
                        <li><a href="#" class="text-gray-400 hover:text-white transition text-sm">Student Portal</a></li>
                        <li><a href="#" class="text-gray-400 hover:text-white transition text-sm">Library</a></li>
                        <li><a href="#" class="text-gray-400 hover:text-white transition text-sm">E-Learning</a></li>
                        <li><a href="#" class="text-gray-400 hover:text-white transition text-sm">Academic Calendar</a></li>
                        <li><a href="#" class="text-gray-400 hover:text-white transition text-sm">FAQ</a></li>
                    </ul>
                </div>

                <div>
                    <h3 class="text-yellow-400 font-semibold mb-3">Contact</h3>
                    <ul class="space-y-3">
                        <li class="flex items-start text-gray-400 text-sm">
                            <i class="fas fa-map-marker-alt mr-3 text-yellow-400 mt-1 flex-shrink-0"></i>
                            <span>Iba, Zambales, Philippines</span>
                        </li>
                        <li class="flex items-center text-gray-400 text-sm">
                            <i class="fas fa-phone mr-3 text-yellow-400 flex-shrink-0"></i>
                            <span>+63 (XXX) XXX-XXXX</span>
                        </li>
                        <li class="flex items-center text-gray-400 text-sm">
                            <i class="fas fa-envelope mr-3 text-yellow-400 flex-shrink-0"></i>
                            <span>info@prmsu.edu.ph</span>
                        </li>
                        <li class="flex items-center text-gray-400 text-sm">
                            <i class="fas fa-globe mr-3 text-yellow-400 flex-shrink-0"></i>
                            <span>www.prmsu.edu.ph</span>
                        </li>
                    </ul>
                </div>
            </div>

            <div class="border-t border-gray-700 mt-8 pt-6 flex flex-col sm:flex-row justify-between items-center space-y-4 sm:space-y-0">
                <p class="text-sm text-gray-400 text-center sm:text-left">
                    © 2025 President Ramon Magsaysay State University. All rights reserved.
                </p>
                <div class="flex space-x-4 social-links">
                    <a href="#" class="text-gray-400 hover:text-yellow-400 transition">
                        <i class="fab fa-facebook-f"></i>
                    </a>
                    <a href="#" class="text-gray-400 hover:text-yellow-400 transition">
                        <i class="fab fa-twitter"></i>
                    </a>
                    <a href="#" class="text-gray-400 hover:text-yellow-400 transition">
                        <i class="fab fa-instagram"></i>
                    </a>
                    <a href="#" class="text-gray-400 hover:text-yellow-400 transition">
                        <i class="fab fa-youtube"></i>
                    </a>
                    <a href="#" class="text-gray-400 hover:text-yellow-400 transition">
                        <i class="fab fa-linkedin-in"></i>
                    </a>
                </div>
            </div>
        </div>
    </footer>

    <script>
        // Sidebar functionality
        function openSidebar() {
            document.getElementById('mobileSidebar').classList.add('active');
            document.getElementById('sidebarOverlay').classList.add('active');
            document.getElementById('hamburger').classList.add('active');
            document.body.style.overflow = 'hidden';
        }

        function closeSidebar() {
            document.getElementById('mobileSidebar').classList.remove('active');
            document.getElementById('sidebarOverlay').classList.remove('active');
            document.getElementById('hamburger').classList.remove('active');
            document.body.style.overflow = '';
        }

        document.addEventListener('click', function(event) {
            const sidebar = document.getElementById('mobileSidebar');
            const hamburger = document.getElementById('hamburger');
            const isClickInsideSidebar = sidebar.contains(event.target);
            const isClickOnHamburger = hamburger.contains(event.target);

            if (!isClickInsideSidebar && !isClickOnHamburger && sidebar.classList.contains('active')) {
                closeSidebar();
            }
        });

        document.addEventListener('keydown', function(event) {
            if (event.key === 'Escape') {
                closeSidebar();
            }
        });

        window.addEventListener('resize', function() {
            if (window.innerWidth >= 769) {
                closeSidebar();
            }
        });

        document.addEventListener('DOMContentLoaded', function() {
            fetchSchedules();

            const filterElements = [
                document.getElementById('college'),
                document.getElementById('department'),
                document.getElementById('year_level'),
                document.getElementById('section'),
                document.getElementById('global-search')
            ];

            filterElements.forEach(element => {
                element.addEventListener('input', debounce(fetchSchedules, 300));
                if (element.tagName === 'SELECT') {
                    element.addEventListener('change', debounce(fetchSchedules, 300));
                }
            });

            document.getElementById('college').addEventListener('change', function() {
                const collegeId = this.value;
                const departmentSelect = document.getElementById('department');
                const sectionSelect = document.getElementById('section');

                if (collegeId) {
                    const formData = new FormData();
                    formData.append('college_id', collegeId);

                    fetch('/public/departments', {
                            method: 'POST',
                            body: formData
                        })
                        .then(response => response.json())
                        .then(departments => {
                            departmentSelect.innerHTML = '<option value="">All Departments</option>';
                            if (Array.isArray(departments)) {
                                departments.forEach(dept => {
                                    const option = new Option(dept.department_name, dept.department_id);
                                    departmentSelect.add(option);
                                });
                            }
                            sectionSelect.innerHTML = '<option value="">All Sections</option>';
                            fetchSchedules();
                        })
                        .catch(error => {
                            console.error('Error fetching departments:', error);
                            departmentSelect.innerHTML = '<option value="">Error loading departments</option>';
                            sectionSelect.innerHTML = '<option value="">All Sections</option>';
                            fetchSchedules();
                        });
                } else {
                    departmentSelect.innerHTML = '<option value="">All Departments</option>';
                    sectionSelect.innerHTML = '<option value="">All Sections</option>';
                    fetchSchedules();
                }
            });

            document.getElementById('department').addEventListener('change', function() {
                const deptId = this.value;
                const sectionSelect = document.getElementById('section');

                if (deptId) {
                    const formData = new FormData();
                    formData.append('department_id', deptId);

                    fetch('/public/sections', {
                            method: 'POST',
                            body: formData
                        })
                        .then(response => response.json())
                        .then(sections => {
                            sectionSelect.innerHTML = '<option value="">All Sections</option>';
                            if (Array.isArray(sections)) {
                                sections.forEach(section => {
                                    const option = new Option(`${section.section_name} (${section.year_level})`, section.section_id);
                                    sectionSelect.add(option);
                                });
                            }
                            fetchSchedules();
                        })
                        .catch(error => {
                            console.error('Error fetching sections:', error);
                            sectionSelect.innerHTML = '<option value="">Error loading sections</option>';
                            fetchSchedules();
                        });
                } else {
                    sectionSelect.innerHTML = '<option value="">All Sections</option>';
                    fetchSchedules();
                }
            });

            
            // Download button functionality
            //document.getElementById('downloadScheduleBtn').addEventListener('click', function() {
              //  document.getElementById('downloadForm').classList.add('active');
            //});

            //function closeDownloadForm() {
              //  document.getElementById('downloadForm').classList.remove('active');
            //}

            //document.getElementById('downloadScheduleForm').addEventListener('submit', function(e) {
              //  e.preventDefault();
              //  const formData = new FormData(this);
              //  fetch('/public/download-schedule-pdf', {
               //     method: 'POST',
                 //   body: formData
                //}).then(response => {
                  //  if (response.ok) {
                    //    return response.blob();
                    //} else {
                      //  throw new Error('Failed to generate PDF');
                    //}
                //}).then(blob => {
                  //  const url = window.URL.createObjectURL(blob);
                    //const a = document.createElement('a');
                   // a.href = url;
                   // a.download = 'PRMSU_Schedule_' + new Date().toISOString().replace(/[:.]/g, '-') + '.pdf';
                   // document.body.appendChild(a);
                   // a.click();
                   // a.remove();
                   // window.URL.revokeObjectURL(url);
                   // closeDownloadForm();
                //}).catch(error => {
                  //  console.error('Error downloading PDF:', error);
                  //  alert('An error occurred while downloading the PDF.');
               // });
            //});
        });

        function fetchSchedules(page = 1) {
            const formData = new FormData(document.getElementById('searchForm'));
            formData.append('page', page);

            const tbody = document.getElementById('schedule-table-body');
            tbody.innerHTML = '<tr><td colspan="5" class="px-6 py-4 text-center text-gray-500"><i class="fas fa-spinner fa-spin"></i> Loading...</td></tr>';

            fetch('/public/search', {
                    method: 'POST',
                    body: formData
                })
                .then(response => response.json())
                .then(data => {
                    if (data.error) {
                        console.error('Error:', data.error);
                        updateScheduleResults([]);
                        updatePagination(0, 0, 0);
                    } else {
                        updateScheduleResults(data.schedules || []);
                        updatePagination(data.total || 0, data.page || 1, data.per_page || 10);
                    }
                })
                .catch(error => {
                    console.error('Fetch error:', error);
                    updateScheduleResults([]);
                    updatePagination(0, 0, 0);
                });
        }

        function updateScheduleResults(schedules) {
            const tbody = document.getElementById('schedule-table-body');
            tbody.innerHTML = '';

            if (schedules.length === 0) {
                tbody.innerHTML = `
                    <tr>
                        <td colspan="5" class="px-6 py-4 text-center text-gray-500">
                            No schedules found.
                        </td>
                    </tr>
                `;
                return;
            }

            schedules.forEach(schedule => {
                const row = `
                    <tr class="hover:bg-yellow-50 transition-colors schedule-card">
                        <td class="px-4 py-3">
                            <div class="font-medium text-gold-primary">${schedule.course_code}</div>
                            <div class="text-sm text-gray-500">${schedule.course_name}</div>
                        </td>
                        <td class="px-4 py-3 text-sm text-gray-500">
                            ${schedule.section_name}
                        </td>
                        <td class="px-4 py-3 text-sm text-gray-500">
                            <span class="px-2 py-1 rounded-full bg-gold-light text-gold-dark text-xs">
                                ${schedule.day_of_week} ${schedule.start_time} - ${schedule.end_time}
                            </span>
                        </td>
                        <td class="px-4 py-3 text-sm text-gray-500">
                            ${schedule.room_name ? schedule.room_name + ' (' + schedule.building + ')' : 'TBA'}
                        </td>
                        <td class="px-4 py-3 text-sm">
                            ${schedule.instructor_name}
                        </td>
                    </tr>
                `;
                tbody.insertAdjacentHTML('beforeend', row);
            });
        }

        function updatePagination(total, currentPage, perPage) {
            const paginationInfo = document.getElementById('pagination-info');
            const paginationNav = document.getElementById('pagination-nav');
            const totalPages = Math.ceil(total / perPage);

            const start = (currentPage - 1) * perPage + 1;
            const end = Math.min(currentPage * perPage, total);
            paginationInfo.innerHTML = `
                Showing <span class="font-medium">${start}</span> to <span class="font-medium">${end}</span> of <span class="font-medium">${total}</span> results
            `;

            paginationNav.innerHTML = `
                <a href="#" class="relative inline-flex items-center px-2 py-2 rounded-l-md border border-gray-300 bg-white text-sm font-medium text-gray-500 hover:bg-gray-50 ${currentPage === 1 ? 'cursor-not-allowed opacity-50' : ''}" 
                   ${currentPage > 1 ? `onclick="fetchSchedules(${currentPage - 1})"` : 'onclick="return false;"'}>
                    <span class="sr-only">Previous</span>
                    <i class="fas fa-chevron-left"></i>
                </a>
            `;

            const maxVisiblePages = 5;
            let startPage = Math.max(1, currentPage - Math.floor(maxVisiblePages / 2));
            let endPage = Math.min(totalPages, startPage + maxVisiblePages - 1);

            if (endPage - startPage + 1 < maxVisiblePages) {
                startPage = Math.max(1, endPage - maxVisiblePages + 1);
            }

            for (let i = startPage; i <= endPage; i++) {
                paginationNav.innerHTML += `
                    <a href="#" class="${i === currentPage ? 'z-10 bg-yellow-500 text-white border-yellow-500' : 'bg-white border-gray-300 text-gray-500 hover:bg-gray-50'} relative inline-flex items-center px-4 py-2 border text-sm font-medium"
                       onclick="fetchSchedules(${i})">
                        ${i}
                    </a>
                `;
            }

            paginationNav.innerHTML += `
                <a href="#" class="relative inline-flex items-center px-2 py-2 rounded-r-md border border-gray-300 bg-white text-sm font-medium text-gray-500 hover:bg-gray-50 ${currentPage === totalPages ? 'cursor-not-allowed opacity-50' : ''}" 
                   ${currentPage < totalPages ? `onclick="fetchSchedules(${currentPage + 1})"` : 'onclick="return false;"'}>
                    <span class="sr-only">Next</span>
                    <i class="fas fa-chevron-right"></i>
                </a>
            `;
        }

        function debounce(func, wait) {
            let timeout;
            return function executedFunction(...args) {
                const later = () => {
                    clearTimeout(timeout);
                    func(...args);
                };
                clearTimeout(timeout);
                timeout = setTimeout(later, wait);
            };
        }

        document.querySelectorAll('a[href^="#"]:not([href="#"])').forEach(anchor => {
            anchor.addEventListener('click', function(e) {
                const target = document.querySelector(this.getAttribute('href'));
                if (target) {
                    e.preventDefault();
                    target.scrollIntoView({
                        behavior: 'smooth',
                        block: 'start'
                    });
                }
            });
        });
    </script>
</body>

</html>