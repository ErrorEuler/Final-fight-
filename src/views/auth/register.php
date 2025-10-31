<?php
require_once __DIR__ . '/../../config/Database.php';
require_once __DIR__ . '/../../models/UserModel.php';
require_once __DIR__ . '/../../services/AuthService.php';

// Initialize database connection and services
$db = (new Database())->connect();
$userModel = new UserModel($db);
$authService = new AuthService($db);

// Initialize variables
$error = '';
$success = '';
$roles = [];
$colleges = [];
$departments = [];
$departmentId = 0;

// Fetch roles, colleges, and departments for dropdowns
try {
    $allRoles = $userModel->getRoles();

    $roles = array_filter($allRoles, function ($role) {
        return !in_array($role['role_id'], [1, 2, 3]);
    });
    $colleges = $userModel->getColleges();
    $departments = $userModel->getProgramsByDepartment($departmentId);
} catch (Exception $e) {
    $error = "Error loading registration data: " . $e->getMessage();
}

?>

<!DOCTYPE html>
<html lang="en">

<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Register | PRMSU Scheduling System</title>
    <meta name="description" content="Register for the President Ramon Magsaysay State University Scheduling System.">
    <link href="/css/output.css" rel="stylesheet">
    <link rel="preconnect" href="https://fonts.googleapis.com">
    <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
    <link href="https://fonts.googleapis.com/css2?family=Poppins:wght@300;400;500;600;700&display=swap" rel="stylesheet">
    <style>
        .bg-image {
            position: absolute;
            top: 0;
            left: 0;
            width: 100%;
            height: 100%;
            background-image: url('/assets/logo/main_logo/campus.jpg');
            background-size: cover;
            background-position: center;
            z-index: 1;
        }

        .bg-overlay {
            position: absolute;
            top: 0;
            left: 0;
            width: 100%;
            height: 100%;
            background: rgba(0, 0, 0, 0.5);
            z-index: 2;
        }

        .radio-group input[type="radio"]:checked+.radio-label {
            border-color: #d97706;
            background-color: #fef3c7;
            box-shadow: 0 0 0 2px #d97706;
        }

        .radio-group input[type="radio"]:checked+.radio-label .radio-circle {
            border-color: #d97706;
        }

        .radio-group input[type="radio"]:checked+.radio-label .radio-dot {
            opacity: 1;
        }

        /* Multi-step form styles */
        .form-step {
            display: none;
        }

        .form-step.active {
            display: block;
            animation: fadeIn 0.3s ease-in;
        }

        @keyframes fadeIn {
            from {
                opacity: 0;
                transform: translateX(20px);
            }

            to {
                opacity: 1;
                transform: translateX(0);
            }
        }

        .step-indicator {
            display: flex;
            justify-content: space-between;
            margin-bottom: 2rem;
            position: relative;
        }

        .step-indicator::before {
            content: '';
            position: absolute;
            top: 20px;
            left: 0;
            right: 0;
            height: 2px;
            background: #e5e7eb;
            z-index: 0;
        }

        .step-indicator-progress {
            position: absolute;
            top: 20px;
            left: 0;
            height: 2px;
            background: #d97706;
            transition: width 0.3s ease;
            z-index: 1;
        }

        .step {
            display: flex;
            flex-direction: column;
            align-items: center;
            position: relative;
            z-index: 2;
            flex: 1;
        }

        .step-number {
            width: 40px;
            height: 40px;
            border-radius: 50%;
            background: white;
            border: 2px solid #e5e7eb;
            display: flex;
            align-items: center;
            justify-content: center;
            font-weight: 600;
            color: #9ca3af;
            transition: all 0.3s ease;
            margin-bottom: 0.5rem;
        }

        .step.active .step-number {
            background: #d97706;
            color: white;
            border-color: #d97706;
            box-shadow: 0 0 0 4px rgba(217, 119, 6, 0.1);
        }

        .step.completed .step-number {
            background: #10b981;
            color: white;
            border-color: #10b981;
        }

        .step-title {
            font-size: 0.75rem;
            color: #9ca3af;
            text-align: center;
            font-weight: 500;
        }

        .step.active .step-title {
            color: #d97706;
            font-weight: 600;
        }

        .step.completed .step-title {
            color: #10b981;
        }

        .form-navigation {
            display: flex;
            gap: 1rem;
            margin-top: 2rem;
        }

        .form-navigation button {
            flex: 1;
        }

        /* Fixed height for form container */
        .form-wrapper {
            min-height: 600px;
            display: flex;
            flex-direction: column;
        }

        .input-group {
            margin-bottom: 1rem;
        }

        /* Responsive adjustments */
        @media (max-width: 640px) {
            .step-title {
                font-size: 0.65rem;
            }

            .step-number {
                width: 32px;
                height: 32px;
                font-size: 0.875rem;
            }
        }
    </style>
</head>

<body class="min-h-screen bg-gray-100 font-poppins">
    <div class="min-h-screen flex flex-col lg:flex-row">
        <!-- Left Section (Background with University Image, Logo and Text) -->
        <div class="w-full lg:w-1/2 text-white flex items-center justify-center p-4 sm:p-6 lg:p-12 relative overflow-hidden min-h-[40vh] lg:min-h-screen">
            <div class="bg-image"></div>
            <div class="bg-overlay"></div>

            <div class="text-center z-10 flex flex-col items-center">
                <div class="mb-4 lg:mb-6">
                    <img src="/assets/logo/main_logo/PRMSUlogo.png" alt="PRMSU Logo" class="w-20 h-20 sm:w-24 sm:h-24 lg:w-32 lg:h-32 mx-auto">
                </div>
                <h1 class="text-xl sm:text-2xl lg:text-4xl font-bold mb-2 lg:mb-4">President Ramon Magsaysay State University</h1>
                <h2 class="text-lg sm:text-xl lg:text-2xl font-semibold mb-2 lg:mb-4">Scheduling System</h2>
                <p class="text-sm sm:text-base lg:text-lg mb-3 lg:mb-6 px-4">Streamlining class scheduling for better academic planning and resource management.</p>
                <p class="text-xs sm:text-sm lg:text-base italic">"Quality Education for Service"</p>
            </div>
        </div>

        <!-- Right Section (Multi-Step Registration Form) -->
        <div class="w-full lg:w-1/2 bg-white flex items-center justify-center p-4 sm:p-6 lg:p-8">
            <div class="w-full max-w-2xl form-wrapper">
                <div class="text-center mb-6">
                    <img src="/assets/logo/main_logo/PRMSUlogo.png" alt="PRMSU Logo" class="mx-auto w-16 h-16 sm:w-20 sm:h-20 rounded-full border-4 border-white shadow-lg">
                    <h1 class="text-xl sm:text-2xl lg:text-3xl font-bold text-yellow-600 mb-2">Create Your Account</h1>
                    <p class="text-sm sm:text-base text-gray-600">Register to access the scheduling system</p>
                </div>

                <?php if (!empty($error)): ?>
                    <div class="bg-red-50 border-l-4 border-red-500 p-4 mb-6 rounded">
                        <div class="flex">
                            <div class="flex-shrink-0">
                                <svg class="h-5 w-5 text-red-500" xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                                    <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 9v2m0 4h.01M12 4a8 8 0 100 16 8 8 0 000-16z" />
                                </svg>
                            </div>
                            <div class="ml-3">
                                <p class="text-sm text-red-700"><?= htmlspecialchars($error) ?></p>
                            </div>
                        </div>
                    </div>
                <?php endif; ?>

                <!-- Step Indicator -->
                <div class="step-indicator">
                    <div class="step-indicator-progress" id="progress-bar"></div>
                    <div class="step active" data-step="1">
                        <div class="step-number">1</div>
                        <div class="step-title">Personal Info</div>
                    </div>
                    <div class="step" data-step="2">
                        <div class="step-number">2</div>
                        <div class="step-title">Account Setup</div>
                    </div>
                    <div class="step" data-step="3">
                        <div class="step-number">3</div>
                        <div class="step-title">Academic Info</div>
                    </div>
                </div>

                <form method="POST" id="registration-form">
                    <!-- Step 1: Personal Information -->
                    <div class="form-step active" data-step="1">
                        <h3 class="text-lg font-semibold text-gray-700 mb-4">Personal Information</h3>

                        <!-- First Name -->
                        <div class="input-group">
                            <label for="first_name" class="block text-sm font-medium text-gray-700 mb-2">First Name <span class="text-red-500">*</span></label>
                            <div class="relative">
                                <div class="absolute inset-y-0 left-0 pl-3 flex items-center pointer-events-none">
                                    <svg class="h-5 w-5 text-yellow-600" xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                                        <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M16 7a4 4 0 11-8 0 4 4 0 018 0zM12 14a7 7 0 00-7 7h14a7 7 0 00-7-7z" />
                                    </svg>
                                </div>
                                <input type="text" id="first_name" name="first_name" required
                                    class="block w-full pl-10 pr-3 py-3 border border-gray-300 rounded-md shadow-sm text-base focus:outline-none focus:ring-2 focus:ring-yellow-500 focus:border-yellow-500"
                                    value="<?= htmlspecialchars($_POST['first_name'] ?? '') ?>"
                                    placeholder="Enter your first name">
                            </div>
                        </div>

                        <!-- Middle Name -->
                        <div class="input-group">
                            <label for="middle_name" class="block text-sm font-medium text-gray-700 mb-2">Middle Name</label>
                            <div class="relative">
                                <div class="absolute inset-y-0 left-0 pl-3 flex items-center pointer-events-none">
                                    <svg class="h-5 w-5 text-yellow-600" xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                                        <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M16 7a4 4 0 11-8 0 4 4 0 018 0zM12 14a7 7 0 00-7 7h14a7 7 0 00-7-7z" />
                                    </svg>
                                </div>
                                <input type="text" id="middle_name" name="middle_name"
                                    class="block w-full pl-10 pr-3 py-3 border border-gray-300 rounded-md shadow-sm text-base focus:outline-none focus:ring-2 focus:ring-yellow-500 focus:border-yellow-500"
                                    value="<?= htmlspecialchars($_POST['middle_name'] ?? '') ?>"
                                    placeholder="Enter your middle name">
                            </div>
                        </div>

                        <!-- Last Name -->
                        <div class="input-group">
                            <label for="last_name" class="block text-sm font-medium text-gray-700 mb-2">Last Name <span class="text-red-500">*</span></label>
                            <div class="relative">
                                <div class="absolute inset-y-0 left-0 pl-3 flex items-center pointer-events-none">
                                    <svg class="h-5 w-5 text-yellow-600" xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                                        <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M16 7a4 4 0 11-8 0 4 4 0 018 0zM12 14a7 7 0 00-7 7h14a7 7 0 00-7-7z" />
                                    </svg>
                                </div>
                                <input type="text" id="last_name" name="last_name" required
                                    class="block w-full pl-10 pr-3 py-3 border border-gray-300 rounded-md shadow-sm text-base focus:outline-none focus:ring-2 focus:ring-yellow-500 focus:border-yellow-500"
                                    value="<?= htmlspecialchars($_POST['last_name'] ?? '') ?>"
                                    placeholder="Enter your last name">
                            </div>
                        </div>

                        <!-- Suffix -->
                        <div class="input-group">
                            <label for="suffix" class="block text-sm font-medium text-gray-700 mb-2">Suffix</label>
                            <div class="relative">
                                <div class="absolute inset-y-0 left-0 pl-3 flex items-center pointer-events-none">
                                    <svg class="h-5 w-5 text-yellow-600" xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                                        <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M16 7a4 4 0 11-8 0 4 4 0 018 0zM12 14a7 7 0 00-7 7h14a7 7 0 00-7-7z" />
                                    </svg>
                                </div>
                                <input type="text" id="suffix" name="suffix"
                                    class="block w-full pl-10 pr-3 py-3 border border-gray-300 rounded-md shadow-sm text-base focus:outline-none focus:ring-2 focus:ring-yellow-500 focus:border-yellow-500"
                                    value="<?= htmlspecialchars($_POST['suffix'] ?? '') ?>"
                                    placeholder="e.g., Jr., Sr.">
                            </div>
                        </div>

                        <!-- Email -->
                        <div class="input-group">
                            <label for="email" class="block text-sm font-medium text-gray-700 mb-2">Email <span class="text-red-500">*</span></label>
                            <div class="relative">
                                <div class="absolute inset-y-0 left-0 pl-3 flex items-center pointer-events-none">
                                    <svg class="h-5 w-5 text-yellow-600" xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                                        <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M16 12a4 4 0 10-8 0 4 4 0 008 0zm0 0v1.5a2.5 2.5 0 005 0V12a9 9 0 10-9 9m4.5-1.206a8.959 8.959 0 01-4.5 1.207" />
                                    </svg>
                                </div>
                                <input type="email" id="email" name="email" required
                                    class="block w-full pl-10 pr-3 py-3 border border-gray-300 rounded-md shadow-sm text-base focus:outline-none focus:ring-2 focus:ring-yellow-500 focus:border-yellow-500"
                                    value="<?= htmlspecialchars($_POST['email'] ?? '') ?>"
                                    placeholder="Enter your email">
                            </div>
                        </div>

                        <!-- Phone -->
                        <div class="input-group">
                            <label for="phone" class="block text-sm font-medium text-gray-700 mb-2">Phone Number</label>
                            <div class="relative">
                                <div class="absolute inset-y-0 left-0 pl-3 flex items-center pointer-events-none">
                                    <svg class="h-5 w-5 text-yellow-600" xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                                        <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M3 5a2 2 0 012-2h3.28a1 1 0 01.948.684l1.498 4.493a1 1 0 01-.502 1.21l-2.257 1.13a11.042 11.042 0 005.516 5.516l1.13-2.257a1 1 0 011.21-.502l4.493 1.498a1 1 0 01.684.949V19a2 2 0 01-2 2h-1C9.716 21 3 14.284 3 6V5z" />
                                    </svg>
                                </div>
                                <input type="tel" id="phone" name="phone"
                                    class="block w-full pl-10 pr-3 py-3 border border-gray-300 rounded-md shadow-sm text-base focus:outline-none focus:ring-2 focus:ring-yellow-500 focus:border-yellow-500"
                                    value="<?= htmlspecialchars($_POST['phone'] ?? '') ?>"
                                    placeholder="Enter your phone number">
                            </div>
                        </div>

                        <!-- Employee ID -->
                        <div class="input-group">
                            <label for="employee_id" class="block text-sm font-medium text-gray-700 mb-2">Employee ID <span class="text-red-500">*</span></label>
                            <div class="relative">
                                <div class="absolute inset-y-0 left-0 pl-3 flex items-center pointer-events-none">
                                    <svg class="h-5 w-5 text-yellow-600" xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                                        <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M10 6H5a2 2 0 00-2 2v9a2 2 0 002 2h14a2 2 0 002-2V8a2 2 0 00-2-2h-5m-4 0V5a2 2 0 114 0v1m-4 0a2 2 0 104 0m-5 8a2 2 0 100-4 2 2 0 000 4zm0 0c1.306 0 2.417.835 2.83 2M9 14a3.001 3.001 0 00-2.83 2M15 11h3m-3 4h2" />
                                    </svg>
                                </div>
                                <input type="text" id="employee_id" name="employee_id" required
                                    class="block w-full pl-10 pr-3 py-3 border border-gray-300 rounded-md shadow-sm text-base focus:outline-none focus:ring-2 focus:ring-yellow-500 focus:border-yellow-500"
                                    value="<?= htmlspecialchars($_POST['employee_id'] ?? '') ?>"
                                    placeholder="Enter your employee ID">
                            </div>
                        </div>

                        <div class="form-navigation">
                            <button type="button" class="w-full bg-yellow-600 text-white py-3 px-6 rounded-md hover:bg-yellow-500 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-yellow-500 transition duration-150 ease-in-out text-base font-medium" onclick="nextStep()">
                                Next Step →
                            </button>
                        </div>
                    </div>

                    <!-- Step 2: Account Information -->
                    <div class="form-step" data-step="2">
                        <h3 class="text-lg font-semibold text-gray-700 mb-4">Account Information</h3>

                        <!-- Username -->
                        <div class="input-group">
                            <label for="username" class="block text-sm font-medium text-gray-700 mb-2">Username <span class="text-red-500">*</span></label>
                            <div class="relative">
                                <div class="absolute inset-y-0 left-0 pl-3 flex items-center pointer-events-none">
                                    <svg class="h-5 w-5 text-yellow-600" xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                                        <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M16 7a4 4 0 11-8 0 4 4 0 018 0zM12 14a7 7 0 00-7 7h14a7 7 0 00-7-7z" />
                                    </svg>
                                </div>
                                <input type="text" id="username" name="username" required
                                    class="block w-full pl-10 pr-3 py-3 border border-gray-300 rounded-md shadow-sm text-base focus:outline-none focus:ring-2 focus:ring-yellow-500 focus:border-yellow-500"
                                    value="<?= htmlspecialchars($_POST['username'] ?? '') ?>"
                                    placeholder="Enter your username">
                            </div>
                        </div>

                        <!-- Password -->
                        <div class="input-group">
                            <label for="password" class="block text-sm font-medium text-gray-700 mb-2">Password <span class="text-red-500">*</span></label>
                            <div class="relative">
                                <div class="absolute inset-y-0 left-0 pl-3 flex items-center pointer-events-none">
                                    <svg class="h-5 w-5 text-yellow-600" xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                                        <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 15v2m-6 4h12a2 2 0 002-2v-6a2 2 0 00-2-2H6a2 2 0 00-2 2v6a2 2 0 002 2zm10-10V7a4 4 0 00-8 0v4h8z" />
                                    </svg>
                                </div>
                                <input type="password" id="password" name="password" required
                                    class="block w-full pl-10 pr-3 py-3 border border-gray-300 rounded-md shadow-sm text-base focus:outline-none focus:ring-2 focus:ring-yellow-500 focus:border-yellow-500"
                                    placeholder="Enter your password">
                            </div>
                        </div>

                        <!-- Confirm Password -->
                        <div class="input-group">
                            <label for="confirm_password" class="block text-sm font-medium text-gray-700 mb-2">Confirm Password <span class="text-red-500">*</span></label>
                            <div class="relative">
                                <div class="absolute inset-y-0 left-0 pl-3 flex items-center pointer-events-none">
                                    <svg class="h-5 w-5 text-yellow-600" xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                                        <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 15v2m-6 4h12a2 2 0 002-2v-6a2 2 0 00-2-2H6a2 2 0 00-2 2v6a2 2 0 002 2zm10-10V7a4 4 0 00-8 0v4h8z" />
                                    </svg>
                                </div>
                                <input type="password" id="confirm_password" name="confirm_password" required
                                    class="block w-full pl-10 pr-3 py-3 border border-gray-300 rounded-md shadow-sm text-base focus:outline-none focus:ring-2 focus:ring-yellow-500 focus:border-yellow-500"
                                    placeholder="Confirm your password">
                            </div>
                        </div>

                        <!-- Add this after confirm password input in Step 2 -->
                        <div id="password-error" class="hidden mt-2 p-3 bg-red-50 border border-red-200 rounded-md">
                            <div class="flex items-center">
                                <svg class="w-5 h-5 text-red-500 mr-2" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                    <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-2.5L13.732 4c-.77-.833-1.964-.833-2.732 0L4.35 16.5c-.77.833.192 2.5 1.732 2.5z" />
                                </svg>
                                <span class="text-red-700 text-sm">Passwords do not match</span>
                            </div>
                        </div>

                        <div class="form-navigation">
                            <button type="button" class="bg-gray-300 text-gray-700 py-3 px-6 rounded-md hover:bg-gray-400 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-gray-500 transition duration-150 ease-in-out text-base font-medium" onclick="prevStep()">
                                ← Previous
                            </button>
                            <button type="button" class="bg-yellow-600 text-white py-3 px-6 rounded-md hover:bg-yellow-500 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-yellow-500 transition duration-150 ease-in-out text-base font-medium" onclick="nextStep()">
                                Next Step →
                            </button>
                        </div>
                    </div>

                    <!-- Step 3: Academic Information -->
                    <div class="form-step" data-step="3">
                        <h3 class="text-lg font-semibold text-gray-700 mb-4">Academic Information</h3>

                        <!-- Role Selection -->
                        <div class="input-group">
                            <label class="block text-sm font-medium text-gray-700 mb-2">
                                <div class="flex items-center">
                                    <svg class="h-5 w-5 text-yellow-600 mr-2" xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                                        <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M17 20h5v-2a2 2 0 00-2-2h-3m-2 4h-5a2 2 0 01-2-2v-3m7-7a4 4 0 11-8 0 4 4 0 018 0z" />
                                    </svg>
                                    Select Role(s) <span class="text-red-500">*</span>
                                </div>
                                <p class="text-xs text-gray-500 mt-1">You can select Dean and Program Chair together</p>
                            </label>

                            <div class="space-y-3">
                                <div class="relative">
                                    <button type="button" id="role-dropdown-button"
                                        class="w-full px-4 py-3 text-left bg-white border border-gray-300 rounded-md shadow-sm focus:outline-none focus:ring-2 focus:ring-yellow-500 focus:border-yellow-500 flex justify-between items-center">
                                        <span id="role-selection-text" class="text-gray-500">Select your role(s)...</span>
                                        <svg class="h-5 w-5 text-gray-400 transition-transform duration-200" id="role-dropdown-arrow" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M19 9l-7 7-7-7" />
                                        </svg>
                                    </button>

                                    <div id="role-selection-panel" class="hidden absolute z-10 w-full mt-1 bg-white border border-gray-300 rounded-md shadow-lg max-h-60 overflow-y-auto">
                                        <div class="p-3 space-y-2">
                                            <?php foreach ($roles as $role): ?>
                                                <?php
                                                $roleId = $role['role_id'];
                                                $roleName = htmlspecialchars($role['role_name']);
                                                $isDeanOrChair = in_array($roleId, [4, 5]);
                                                ?>
                                                <div class="flex items-center p-2 hover:bg-gray-50 rounded-lg transition-colors">
                                                    <input type="checkbox" id="role_<?= $roleId ?>" name="roles[]" value="<?= $roleId ?>"
                                                        class="role-checkbox h-4 w-4 text-yellow-600 border-gray-300 rounded focus:ring-yellow-500"
                                                        data-role-id="<?= $roleId ?>" data-role-name="<?= $roleName ?>"
                                                        <?= $isDeanOrChair ? 'data-special-role="true"' : '' ?>
                                                        onchange="updateRoleSelection()">
                                                    <label for="role_<?= $roleId ?>" class="ml-3 flex-1 cursor-pointer">
                                                        <span class="block text-sm font-medium text-gray-700"><?= $roleName ?></span>
                                                    </label>
                                                </div>
                                            <?php endforeach; ?>
                                        </div>
                                    </div>
                                </div>

                                <div id="selected-roles-container" class="hidden">
                                    <div class="bg-gray-50 border border-gray-200 rounded-lg p-4">
                                        <h4 class="text-sm font-medium text-gray-700 mb-2">Selected Roles:</h4>
                                        <div id="selected-roles-list" class="flex flex-wrap gap-2"></div>
                                        <div id="role-combination-info" class="mt-2 text-xs text-gray-600"></div>
                                    </div>
                                </div>
                            </div>
                            <p id="roles-error" class="mt-2 text-sm text-red-600 hidden">Please select at least one role</p>
                        </div>

                        <!-- College -->
                        <div class="input-group">
                            <label for="college_id" class="block text-sm font-medium text-gray-700 mb-2">College <span class="text-red-500">*</span></label>
                            <div class="relative">
                                <div class="absolute inset-y-0 left-0 pl-3 flex items-center pointer-events-none">
                                    <svg class="h-5 w-5 text-yellow-600" xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                                        <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M19 21V5a2 2 0 00-2-2H7a2 2 0 00-2 2v16m14 0h2m-2 0h-5m-9 0H3m2 0h5M9 7h1m-1 4h1m4-4h1m-1 4h1m-5 10v-5a2 2 0 012-2h2a2 2 0 012 2v5m-4-6h.01" />
                                    </svg>
                                </div>
                                <select id="college_id" name="college_id" required onchange="loadDepartments()"
                                    class="block w-full pl-10 pr-10 py-3 border border-gray-300 rounded-md shadow-sm text-base focus:outline-none focus:ring-2 focus:ring-yellow-500 focus:border-yellow-500 appearance-none">
                                    <option value="">Select College</option>
                                    <?php foreach ($colleges as $college): ?>
                                        <option value="<?= $college['college_id'] ?>" <?= (isset($_POST['college_id']) && $_POST['college_id'] == $college['college_id']) ? 'selected' : '' ?>>
                                            <?= htmlspecialchars($college['college_name']) ?>
                                        </option>
                                    <?php endforeach; ?>
                                </select>
                                <div class="absolute inset-y-0 right-0 pr-3 flex items-center pointer-events-none">
                                    <svg class="h-5 w-5 text-gray-400" xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                                        <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M19 9l-7 7-7-7" />
                                    </svg>
                                </div>
                            </div>
                        </div>

                        <!-- Department -->
                        <div class="input-group" id="department-section">
                            <label for="department_id" class="block text-sm font-medium text-gray-700 mb-2">
                                <span id="dept-label">Department</span> <span class="text-red-500">*</span>
                            </label>

                            <div id="single-department" class="relative">
                                <div class="absolute inset-y-0 left-0 pl-3 flex items-center pointer-events-none">
                                    <svg class="h-5 w-5 text-yellow-600" xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                                        <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M19 21V5a2 2 0 00-2-2H7a2 2 0 00-2 2v16m14 0h2m-2 0h-5m-9 0H3m2 0h5M9 7h1m-1 4h1m4-4h1m-1 4h1m-5 10v-5a2 2 0 012-2h2a2 2 0 012 2v5m-4-6h.01" />
                                    </svg>
                                </div>
                                <select id="department_id" name="department_id" required
                                    class="block w-full pl-10 pr-10 py-3 border border-gray-300 rounded-md shadow-sm text-base focus:outline-none focus:ring-2 focus:ring-yellow-500 focus:border-yellow-500 appearance-none">
                                    <option value="">Select Department</option>
                                </select>
                                <div class="absolute inset-y-0 right-0 pr-3 flex items-center pointer-events-none">
                                    <svg class="h-5 w-5 text-gray-400" xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                                        <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M19 9l-7 7-7-7" />
                                    </svg>
                                </div>
                            </div>

                            <div id="multiple-departments" class="hidden">
                                <div class="border border-gray-300 rounded-md p-3 max-h-60 overflow-y-auto bg-gray-50">
                                    <p class="text-xs text-gray-500 mb-3">Select all departments you will manage as Program Chair.</p>
                                    <div id="departments-checkbox-list" class="space-y-2"></div>
                                </div>
                                <input type="hidden" id="primary_department_id" name="primary_department_id">
                            </div>
                        </div>

                        <!-- Academic Rank -->
                        <div class="input-group">
                            <label for="academic_rank" class="block text-sm font-medium text-gray-700 mb-2">Academic Rank</label>
                            <div class="relative">
                                <div class="absolute inset-y-0 left-0 pl-3 flex items-center pointer-events-none">
                                    <svg class="h-5 w-5 text-yellow-600" xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                                        <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 6V4m0 2a2 2 0 100 4m0-4a2 2 0 110 4m-6 8a2 2 0 100-4m0 4a2 2 0 110-4m0 4v2m0-6V4m6 6v10m6-2a2 2 0 100-4m0 4a2 2 0 110-4m0 4v2m0-6V4" />
                                    </svg>
                                </div>
                                <select id="academic_rank" name="academic_rank"
                                    class="block w-full pl-10 pr-10 py-3 border border-gray-300 rounded-md shadow-sm text-base focus:outline-none focus:ring-2 focus:ring-yellow-500 focus:border-yellow-500 appearance-none">
                                    <option value="">Select Academic Rank</option>
                                    <option value="Instructor I">Instructor I</option>
                                    <option value="Instructor II">Instructor II</option>
                                    <option value="Instructor III">Instructor III</option>
                                    <option value="Assistant Professor I">Assistant Professor I</option>
                                    <option value="Assistant Professor II">Assistant Professor II</option>
                                    <option value="Assistant Professor III">Assistant Professor III</option>
                                    <option value="Assistant Professor IV">Assistant Professor IV</option>
                                    <option value="Associate Professor I">Associate Professor I</option>
                                    <option value="Associate Professor II">Associate Professor II</option>
                                    <option value="Associate Professor III">Associate Professor III</option>
                                    <option value="Professor I">Professor I</option>
                                    <option value="Professor II">Professor II</option>
                                    <option value="Professor III">Professor III</option>
                                </select>
                                <div class="absolute inset-y-0 right-0 pr-3 flex items-center pointer-events-none">
                                    <svg class="h-5 w-5 text-gray-400" xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                                        <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M19 9l-7 7-7-7" />
                                    </svg>
                                </div>
                            </div>
                        </div>

                        <!-- Employment Type -->
                        <div class="input-group">
                            <label for="employment_type" class="block text-sm font-medium text-gray-700 mb-2">Employment Type</label>
                            <div class="relative">
                                <div class="absolute inset-y-0 left-0 pl-3 flex items-center pointer-events-none">
                                    <svg class="h-5 w-5 text-yellow-600" xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                                        <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M21 13.255A23.931 23.931 0 0112 15c-3.183 0-6.22-.62-9-1.745M16 6V4a2 2 0 00-2-2h-4a2 2 0 00-2 2v2m4 6h.01M5 20h14a2 2 0 002-2V8a2 2 0 00-2-2H5a2 2 0 00-2 2v10a2 2 0 002 2z" />
                                    </svg>
                                </div>
                                <select id="employment_type" name="employment_type"
                                    class="block w-full pl-10 pr-10 py-3 border border-gray-300 rounded-md shadow-sm text-base focus:outline-none focus:ring-2 focus:ring-yellow-500 focus:border-yellow-500 appearance-none">
                                    <option value="">Select Employment Type</option>
                                    <option value="Regular">Regular</option>
                                    <option value="Contractual">Contractual</option>
                                    <option value="Part-time">Part-time</option>
                                </select>
                                <div class="absolute inset-y-0 right-0 pr-3 flex items-center pointer-events-none">
                                    <svg class="h-5 w-5 text-gray-400" xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                                        <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M19 9l-7 7-7-7" />
                                    </svg>
                                </div>
                            </div>
                        </div>

                        <!-- Classification -->
                        <div class="input-group">
                            <label class="block text-sm font-medium text-gray-700 mb-3">
                                <div class="flex items-center">
                                    <svg class="h-5 w-5 text-yellow-600 mr-2" xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                                        <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 6V4m0 2a2 2 0 100 4m0-4a2 2 0 110 4m-6 8a2 2 0 100-4m0 4a2 2 0 110-4m0 4v2m0-6V4m6 6v10m6-2a2 2 0 100-4m0 4a2 2 0 110-4m0 4v2m0-6V4" />
                                    </svg>
                                    Classification
                                </div>
                            </label>

                            <div class="grid grid-cols-2 gap-4">
                                <div class="relative radio-group">
                                    <input type="radio" id="classification_tl" name="classification" value="TL" class="hidden">
                                    <label for="classification_tl" class="flex items-center w-full px-4 py-3 border border-gray-300 rounded-md shadow-sm text-base cursor-pointer transition-all duration-200 hover:bg-gray-50 radio-label">
                                        <div class="flex items-center">
                                            <div class="w-4 h-4 border-2 border-gray-300 rounded-full mr-3 flex items-center justify-center transition-all duration-200 radio-circle">
                                                <div class="w-2 h-2 rounded-full bg-yellow-500 opacity-0 transition-opacity duration-200 radio-dot"></div>
                                            </div>
                                            <span class="text-gray-700 font-medium">TL</span>
                                        </div>
                                    </label>
                                </div>

                                <div class="relative radio-group">
                                    <input type="radio" id="classification_vsl" name="classification" value="VSL" class="hidden">
                                    <label for="classification_vsl" class="flex items-center w-full px-4 py-3 border border-gray-300 rounded-md shadow-sm text-base cursor-pointer transition-all duration-200 hover:bg-gray-50 radio-label">
                                        <div class="flex items-center">
                                            <div class="w-4 h-4 border-2 border-gray-300 rounded-full mr-3 flex items-center justify-center transition-all duration-200 radio-circle">
                                                <div class="w-2 h-2 rounded-full bg-yellow-500 opacity-0 transition-opacity duration-200 radio-dot"></div>
                                            </div>
                                            <span class="text-gray-700 font-medium">VSL</span>
                                        </div>
                                    </label>
                                </div>
                            </div>
                        </div>

                        <div class="form-navigation">
                            <button type="button" class="bg-gray-300 text-gray-700 py-3 px-6 rounded-md hover:bg-gray-400 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-gray-500 transition duration-150 ease-in-out text-base font-medium" onclick="prevStep()">
                                ← Previous
                            </button>
                            <button type="submit" class="bg-yellow-600 text-white py-3 px-6 rounded-md hover:bg-yellow-500 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-yellow-500 transition duration-150 ease-in-out text-base font-medium">
                                Create Account
                            </button>
                        </div>
                    </div>
                </form>

                <div class="text-center mt-4">
                    <p class="text-sm text-gray-600">Already have an account? <a href="/login" class="text-yellow-600 hover:text-yellow-500 font-medium">Sign in</a></p>
                </div>

                <div class="text-center mt-4 text-sm text-gray-500">
                    © 2025 President Ramon Magsaysay State University. All rights reserved.
                </div>
            </div>
        </div>
    </div>

    <script src="https://cdnjs.cloudflare.com/ajax/libs/jquery/3.7.1/jquery.min.js"></script>
    <script>
        let currentStep = 1;
        let selectedRoles = [];

        // Step navigation
        function nextStep() {
            if (validateStep(currentStep)) {
                document.querySelector(`.form-step[data-step="${currentStep}"]`).classList.remove('active');
                document.querySelector(`.step[data-step="${currentStep}"]`).classList.add('completed');
                document.querySelector(`.step[data-step="${currentStep}"]`).classList.remove('active');

                currentStep++;

                document.querySelector(`.form-step[data-step="${currentStep}"]`).classList.add('active');
                document.querySelector(`.step[data-step="${currentStep}"]`).classList.add('active');

                updateProgressBar();
                window.scrollTo({
                    top: 0,
                    behavior: 'smooth'
                });
            }
        }

        function prevStep() {
            document.querySelector(`.form-step[data-step="${currentStep}"]`).classList.remove('active');
            document.querySelector(`.step[data-step="${currentStep}"]`).classList.remove('active');

            currentStep--;

            document.querySelector(`.form-step[data-step="${currentStep}"]`).classList.add('active');
            document.querySelector(`.step[data-step="${currentStep}"]`).classList.remove('completed');
            document.querySelector(`.step[data-step="${currentStep}"]`).classList.add('active');

            updateProgressBar();
            window.scrollTo({
                top: 0,
                behavior: 'smooth'
            });
        }

        function updateProgressBar() {
            const progress = ((currentStep - 1) / 2) * 100;
            document.getElementById('progress-bar').style.width = progress + '%';
        }

        function validateStep(step) {
            const currentStepElement = document.querySelector(`.form-step[data-step="${step}"]`);
            const requiredInputs = currentStepElement.querySelectorAll('[required]');
            let isValid = true;

            requiredInputs.forEach(input => {
                if (!input.value.trim()) {
                    input.classList.add('border-red-500');
                    isValid = false;
                } else {
                    input.classList.remove('border-red-500');
                }
            });

            if (step === 2) {
                const password = document.getElementById('password').value;
                const confirmPassword = document.getElementById('confirm_password').value;
                if (password !== confirmPassword) {
                    document.getElementById('password-error').classList.remove('hidden');
                    isValid = false;
                } else {
                    document.getElementById('password-error').classList.add('hidden');
                }
            }

            if (!isValid) {
                alert('Please fill in all required fields.');
            }

            return isValid;
        }

        function validatePasswords() {
            const password = document.getElementById('password');
            const confirmPassword = document.getElementById('confirm_password');
            const passwordError = document.getElementById('password-error');

            if (password.value && confirmPassword.value) {
                if (password.value !== confirmPassword.value) {
                    password.classList.add('border-red-500', 'bg-red-50');
                    confirmPassword.classList.add('border-red-500', 'bg-red-50');
                    passwordError.classList.remove('hidden');
                    return false;
                } else {
                    password.classList.remove('border-red-500', 'bg-red-50');
                    confirmPassword.classList.remove('border-red-500', 'bg-red-50');
                    passwordError.classList.add('hidden');
                    return true;
                }
            }
            return true;
        }

        // Role selection management
        function updateRoleSelection() {
            const checkboxes = document.querySelectorAll('.role-checkbox:checked');
            selectedRoles = Array.from(checkboxes).map(cb => ({
                id: cb.value,
                name: cb.getAttribute('data-role-name'),
                isSpecial: cb.getAttribute('data-special-role') === 'true'
            }));

            updateRoleDisplay();
            handleRoleCombinations();
            toggleDepartmentSelection();
        }

        function updateRoleDisplay() {
            const container = document.getElementById('selected-roles-container');
            const list = document.getElementById('selected-roles-list');
            const selectionText = document.getElementById('role-selection-text');

            if (selectedRoles.length === 0) {
                container.classList.add('hidden');
                selectionText.textContent = 'Select your role(s)...';
                selectionText.classList.add('text-gray-500');
            } else {
                container.classList.remove('hidden');
                selectionText.textContent = `${selectedRoles.length} role(s) selected`;
                selectionText.classList.remove('text-gray-500');
                selectionText.classList.add('text-gray-900');

                list.innerHTML = selectedRoles.map(role => `
                    <span class="inline-flex items-center px-3 py-1 rounded-full text-xs font-medium 
                                ${role.isSpecial ? 'bg-purple-100 text-purple-800 border border-purple-200' : 'bg-yellow-100 text-yellow-800 border border-yellow-200'}">
                        ${role.name}
                        <button type="button" onclick="removeRole(${role.id})"
                                class="ml-1.5 text-gray-400 hover:text-gray-600 focus:outline-none">×</button>
                    </span>
                `).join('');
            }
        }

        function removeRole(roleId) {
            const checkbox = document.querySelector(`.role-checkbox[value="${roleId}"]`);
            if (checkbox) {
                checkbox.checked = false;
                updateRoleSelection();
            }
        }

        function handleRoleCombinations() {
            const hasDean = selectedRoles.some(role => role.id == 4);
            const hasProgramChair = selectedRoles.some(role => role.id == 5);

            document.querySelectorAll('.role-checkbox').forEach(checkbox => {
                const roleId = checkbox.value;
                const isDeanOrChair = roleId == 4 || roleId == 5;

                if (selectedRoles.length > 0 && !checkbox.checked) {
                    if (!isDeanOrChair && (hasDean || hasProgramChair)) {
                        checkbox.disabled = true;
                    } else if (isDeanOrChair) {
                        checkbox.disabled = false;
                    } else if (!isDeanOrChair && selectedRoles.some(r => !['4', '5'].includes(r.id))) {
                        checkbox.disabled = true;
                    } else {
                        checkbox.disabled = false;
                    }
                } else {
                    checkbox.disabled = false;
                }
            });
        }

        function toggleDepartmentSelection() {
            const hasProgramChair = selectedRoles.some(role => role.id == 5);

            if (hasProgramChair) {
                $('#single-department').addClass('hidden');
                $('#multiple-departments').removeClass('hidden');
                $('#dept-label').text('Departments (Select Multiple)');
                $('#department_id').removeAttr('required');
            } else {
                $('#single-department').removeClass('hidden');
                $('#multiple-departments').addClass('hidden');
                $('#dept-label').text('Department');
                $('#department_id').attr('required', true);
                $('.dept-checkbox').removeAttr('required').prop('checked', false);
                $('#primary_department_id').val('');
            }
        }

        // Dropdown toggle
        document.addEventListener('DOMContentLoaded', function() {
            const dropdownButton = document.getElementById('role-dropdown-button');
            const dropdownPanel = document.getElementById('role-selection-panel');
            const dropdownArrow = document.getElementById('role-dropdown-arrow');

            if (dropdownButton) {
                dropdownButton.addEventListener('click', function() {
                    const isOpen = !dropdownPanel.classList.contains('hidden');
                    if (isOpen) {
                        dropdownPanel.classList.add('hidden');
                        dropdownArrow.style.transform = 'rotate(0deg)';
                    } else {
                        dropdownPanel.classList.remove('hidden');
                        dropdownArrow.style.transform = 'rotate(180deg)';
                    }
                });

                document.addEventListener('click', function(event) {
                    if (!dropdownButton.contains(event.target) && !dropdownPanel.contains(event.target)) {
                        dropdownPanel.classList.add('hidden');
                        dropdownArrow.style.transform = 'rotate(0deg)';
                    }
                });
            }

            updateRoleSelection();
        });

        // Load departments
        function loadDepartments() {
            const collegeId = $('#college_id').val();
            const deptSelect = $('#department_id');
            const deptCheckboxList = $('#departments-checkbox-list');

            if (!collegeId) {
                deptSelect.empty().append('<option value="">Select Department</option>');
                deptCheckboxList.empty();
                return;
            }

            deptSelect.empty().append('<option value="">Loading departments...</option>').prop('disabled', true);
            deptCheckboxList.html('<p class="text-sm text-gray-500">Loading departments...</p>');

            $.ajax({
                url: '/api/departments?college_id=' + collegeId,
                method: 'GET',
                dataType: 'json',
                success: function(response) {
                    deptSelect.prop('disabled', false).empty();
                    deptSelect.append('<option value="">Select Department</option>');
                    deptCheckboxList.empty();

                    if (response.success && response.departments) {
                        response.departments.forEach(function(dept) {
                            deptSelect.append(`<option value="${dept.department_id}">${dept.department_name}</option>`);

                            const checkboxHtml = `
                                <div class="flex items-start space-x-3 p-2 hover:bg-gray-100 rounded">
                                    <input type="checkbox" id="dept_${dept.department_id}" 
                                           name="department_ids[]" value="${dept.department_id}"
                                           class="dept-checkbox mt-1 h-4 w-4 text-yellow-600 border-gray-300 rounded focus:ring-yellow-500">
                                    <label for="dept_${dept.department_id}" class="flex-1 cursor-pointer">
                                        <span class="block text-sm font-medium text-gray-700">${dept.department_name}</span>
                                    </label>
                                    <button type="button" 
                                            class="set-primary-btn hidden text-xs bg-blue-500 text-white px-2 py-1 rounded hover:bg-blue-600"
                                            data-dept-id="${dept.department_id}"
                                            data-dept-name="${dept.department_name}">
                                        Set Primary
                                    </button>
                                </div>
                            `;
                            deptCheckboxList.append(checkboxHtml);
                        });

                        bindDepartmentCheckboxEvents();
                    } else {
                        deptSelect.append('<option value="">No departments found</option>');
                        deptCheckboxList.html('<p class="text-sm text-gray-500">No departments found</p>');
                    }
                },
                error: function(xhr, status, error) {
                    deptSelect.prop('disabled', false).empty();
                    deptSelect.append('<option value="">Error loading departments</option>');
                    deptCheckboxList.html('<p class="text-sm text-red-500">Error loading departments</p>');
                }
            });
        }

        function bindDepartmentCheckboxEvents() {
            $('.dept-checkbox').on('change', function() {
                const checkedBoxes = $('.dept-checkbox:checked');

                $('.set-primary-btn').addClass('hidden');
                if (checkedBoxes.length > 1) {
                    checkedBoxes.each(function() {
                        $(this).closest('.flex').find('.set-primary-btn').removeClass('hidden');
                    });

                    if (!$('#primary_department_id').val()) {
                        const firstDeptId = checkedBoxes.first().val();
                        setPrimaryDepartment(firstDeptId, checkedBoxes.first().next('label').find('span:first').text());
                    }
                } else if (checkedBoxes.length === 1) {
                    const deptId = checkedBoxes.val();
                    const deptName = checkedBoxes.next('label').find('span:first').text();
                    setPrimaryDepartment(deptId, deptName);
                } else {
                    $('#primary_department_id').val('');
                }
            });

            $('.set-primary-btn').on('click', function() {
                const deptId = $(this).data('dept-id');
                const deptName = $(this).data('dept-name');
                setPrimaryDepartment(deptId, deptName);
            });
        }

        function setPrimaryDepartment(deptId, deptName) {
            $('#primary_department_id').val(deptId);
            $('.set-primary-btn').removeClass('bg-green-500').addClass('bg-blue-500').text('Set Primary');
            $(`.set-primary-btn[data-dept-id="${deptId}"]`)
                .removeClass('bg-blue-500')
                .addClass('bg-green-500')
                .text('✓ Primary');
        }

        // Form submission validation
        $('#registration-form').on('submit', function(e) {
            if (!validateStep(3)) {
                e.preventDefault();
                return false;
            }

            const programChairChecked = $('.role-checkbox[value="5"]:checked').length > 0;

            if (programChairChecked) {
                const checkedDepts = $('.dept-checkbox:checked').length;
                const primaryDept = $('#primary_department_id').val();

                if (checkedDepts === 0) {
                    e.preventDefault();
                    alert('Please select at least one department for Program Chair role.');
                    return false;
                }

                if (checkedDepts > 1 && !primaryDept) {
                    e.preventDefault();
                    alert('Please set a primary department.');
                    return false;
                }

                if (checkedDepts === 1 && !primaryDept) {
                    $('#primary_department_id').val($('.dept-checkbox:checked').val());
                }
            }

            const checkedRoles = $('.role-checkbox:checked');
            if (checkedRoles.length === 0) {
                e.preventDefault();
                $('#roles-error').removeClass('hidden');
                return false;
            }
        });

        $(document).ready(function() {
            $('.role-checkbox').on('change', updateRoleSelection);
            $('#college_id').on('change', loadDepartments);
            updateRoleSelection();

            $('#password, #confirm_password').on('input', validatePasswords);

            <?php if (isset($_POST['college_id']) && !empty($_POST['college_id'])): ?>
                loadDepartments();
            <?php endif; ?>
        });
    </script>
</body>

</html>