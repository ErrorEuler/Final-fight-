<!DOCTYPE html>
<html lang="en">

<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Login | PRMSU Scheduling System</title>
    <meta name="description" content="Login to the President Ramon Magsaysay State University Scheduling System.">
    <link href="/css/output.css" rel="stylesheet">
    <link rel="preconnect" href="https://fonts.googleapis.com">
    <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
    <link href="https://fonts.googleapis.com/css2?family=Poppins:wght@300;400;500;600;700&display=swap" rel="stylesheet">
    <style>
        body {
            font-family: 'Poppins', sans-serif;
        }

        .bg-overlay {
            background-color: rgba(0, 0, 0, 0.5);
            position: absolute;
            top: 0;
            left: 0;
            width: 100%;
            height: 100%;
            z-index: 1;
        }

        .bg-image {
            background-image: url('/assets/logo/main_logo/campus.jpg');
            background-size: cover;
            background-position: center;
            position: absolute;
            top: 0;
            left: 0;
            width: 100%;
            height: 100%;
        }

        .modal {
            display: none;
            position: fixed;
            top: 0;
            left: 0;
            width: 100%;
            height: 100%;
            background-color: rgba(0, 0, 0, 0.5);
            z-index: 50;
        }

        .modal-content {
            background-color: white;
            margin: 15% auto;
            padding: 20px;
            border-radius: 8px;
            width: 90%;
            max-width: 400px;
            position: relative;
        }

        .close {
            position: absolute;
            top: 10px;
            right: 10px;
            font-size: 20px;
            cursor: pointer;
        }
    </style>
</head>

<body class="min-h-screen bg-gray-100">
    <div class="min-h-screen flex flex-col md:flex-row">
        <!-- Left Section (Background with University Image, Logo and Text) -->
        <div class="w-full md:w-1/2 text-white flex items-center justify-center p-6 md:p-12 relative overflow-hidden">
            <div class="bg-image"></div>
            <div class="bg-overlay"></div>

            <div class="text-center z-10 flex flex-col items-center">
                <div class="mb-6">
                    <img src="/assets/logo/main_logo/PRMSUlogo.png" alt="PRMSU Logo" class="w-24 h-24 md:w-32 md:h-32 mx-auto">
                </div>
                <h1 class="text-3xl md:text-4xl font-bold mb-4">President Ramon Magsaysay State University</h1>
                <h2 class="text-xl md:text-2xl font-semibold mb-4">Scheduling System</h2>
                <p class="text-base md:text-lg mb-6">Streamlining class scheduling for better academic planning and resource management.</p>
                <p class="text-sm md:text-md italic">"Quality Education for Service"</p>
            </div>
        </div>

        <!-- Right Section (Login Form) -->
        <div class="w-full md:w-1/2 bg-white flex items-center justify-center p-6 md:p-12">
            <div class="w-full max-w-md">
                <div class="text-center mb-6">
                    <img src="/assets/logo/main_logo/PRMSUlogo.png" alt="PRMSU Logo" class="w-16 h-16 mx-auto mb-4">
                    <h1 class="text-xl md:text-2xl font-bold text-yellow-600 mb-2">Welcome Back</h1>
                    <p class="text-sm md:text-base text-gray-600">Sign in to access your account</p>
                </div>

                <?php
                $awaitingApproval = false;
                if (isset($_SESSION['user_id']) && isset($_SESSION['is_active']) && $_SESSION['is_active'] == 0) {
                    $awaitingApproval = true;
                }
                // Check for success message from registration redirect
                $success = isset($_GET['success']) ? htmlspecialchars(urldecode($_GET['success'])) : '';
                if ($success === "Registration submitted successfully. Awaiting Dean approval.") {
                    $awaitingApproval = true;
                }
                ?>

                <?php if ($awaitingApproval): ?>
                    <div class="mb-4 p-3 bg-yellow-100 text-yellow-800 rounded-lg flex items-center">
                        <svg class="w-5 h-5 mr-2" fill="currentColor" viewBox="0 0 20 20">
                            <path fill-rule="evenodd" d="M8.257 3.099c.765-1.36 2.722-1.36 3.486 0l5.58 9.92c.75 1.334-.213 2.98-1.742 2.98H4.42c-1.53 0-2.493-1.646-1.743-2.98l5.58-9.92zM11 13a1 1 0 11-2 0 1 1 0 012 0zm-1-8a1 1 0 00-1 1v3a1 1 0 002 0V6a1 1 0 00-1-1z" clip-rule="evenodd"></path>
                        </svg>
                        <p class="text-sm">Your account is awaiting approval from the Dean's office. You will be notified via email once approved. Please try logging in later.</p>
                    </div>
                <?php endif; ?>

                <?php if (isset($email_verification_required) && $email_verification_required): ?>
                    <div class="mb-4 p-3 bg-yellow-100 text-yellow-800 rounded-lg flex items-center">
                        <svg class="w-5 h-5 mr-2" fill="currentColor" viewBox="0 0 20 20">
                            <path fill-rule="evenodd" d="M8.257 3.099c.765-1.36 2.722-1.36 3.486 0l5.58 9.92c.75 1.334-.213 2.98-1.742 2.98H4.42c-1.53 0-2.493-1.646-1.743-2.98l5.58-9.92zM11 13a1 1 0 11-2 0 1 1 0 012 0zm-1-8a1 1 0 00-1 1v3a1 1 0 002 0V6a1 1 0 00-1-1z" clip-rule="evenodd"></path>
                        </svg>
                        <p class="text-sm">Your email is not verified. Please check your inbox for a verification link or <a href="/resend-verification" class="underline hover:text-yellow-600">resend verification email</a>.</p>
                    </div>
                <?php endif; ?>

                <?php if (isset($error)): ?>
                    <div class="mb-4 p-3 bg-red-100 text-red-800 rounded-lg"><?php echo htmlspecialchars($error); ?></div>
                <?php endif; ?>

                <form method="POST" action="/login" class="space-y-4">
                    <div>
                        <label for="employee_id" class="block text-xs md:text-sm font-medium text-gray-700">Employee ID</label>
                        <div class="mt-1 relative">
                            <div class="absolute inset-y-0 left-0 pl-3 flex items-center pointer-events-none">
                                <svg class="h-4 md:h-5 w-4 md:w-5 text-yellow-600" xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                                    <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M10 6H5a2 2 0 00-2 2v9a2 2 0 002 2h14a2 2 0 002-2V8a2 2 0 00-2-2h-5m-4 0V5a2 2 0 114 0v1m-4 0a2 2 0 104 0m-5 8a2 2 0 100-4 2 2 0 000 4zm0 0c1.306 0 2.417.835 2.83 2M9 14a3.001 3.001 0 00-2.83 2M15 11h3m-3 4h2" />
                                </svg>
                            </div>
                            <input type="text" id="employee_id" name="employee_id" required class="block w-full pl-9 md:pl-10 pr-3 py-2 md:py-2 border border-gray-300 rounded-md shadow-sm text-sm md:text-base focus:outline-none focus:ring-2 focus:ring-yellow-500 focus:border-yellow-500" placeholder="Enter your employee ID">
                        </div>
                    </div>
                    <div>
                        <label for="password" class="block text-xs md:text-sm font-medium text-gray-700">Password</label>
                        <div class="mt-1 relative">
                            <div class="absolute inset-y-0 left-0 pl-3 flex items-center pointer-events-none">
                                <svg class="h-4 md:h-5 w-4 md:w-5 text-yellow-600" xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                                    <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 15v2m-6 4h12a2 2 0 002-2v-6a2 2 0 00-2-2H6a2 2 0 00-2 2v6a2 2 0 002 2zm10-10V7a4 4 0 00-8 0v4h8z" />
                                </svg>
                            </div>
                            <input type="password" id="password" name="password" required class="block w-full pl-9 md:pl-10 pr-3 py-2 md:py-2 border border-gray-300 rounded-md shadow-sm text-sm md:text-base focus:outline-none focus:ring-2 focus:ring-yellow-500 focus:border-yellow-500" placeholder="Enter your password">
                        </div>
                    </div>
                    <div class="flex items-center justify-between flex-col md:flex-row space-y-4 md:space-y-0 md:space-x-4">
                        <div class="flex items-center">
                            <input id="remember-me" name="remember-me" type="checkbox" class="h-4 w-4 text-yellow-600 focus:ring-yellow-500 border-gray-300 rounded" value="1">
                            <label for="remember-me" class="ml-2 block text-xs md:text-sm text-gray-900">Remember me</label>
                        </div>
                        <a id="forgot-password-link" class="text-xs md:text-sm text-yellow-600 hover:text-yellow-500">Forgot password?</a>
                    </div>
                    <button type="submit" class="w-full bg-yellow-600 text-white py-2 px-4 rounded-md hover:bg-yellow-500 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-yellow-500 transition duration-150 ease-in-out text-sm md:text-base">
                        Sign In
                    </button>
                </form>
                <div class="text-center mt-4">
                    <p class="text-xs md:text-sm text-gray-600">Don't have an account? <a href="/register" class="text-yellow-600 hover:text-yellow-500">Create new account</a></p>
                </div>
                <div class="text-center mt-4 text-xs md:text-sm text-gray-500">
                    © 2025 President Ramon Magsaysay State University. All rights reserved.
                </div>
            </div>
        </div>
    </div>

    <div id="forgot-password-modal" class="modal">
        <div class="modal-content">
            <span class="close">&times;</span>
            <h2 class="text-lg font-bold mb-4 text-center">Forgot Password</h2>
            <div id="forgot-password-message"></div>
            <form id="forgot-password-form" class="space-y-4">
                <div>
                    <label for="forgot-employee_id" class="block text-xs md:text-sm font-medium text-gray-700">Employee ID</label>
                    <div class="mt-1 relative">
                        <div class="absolute inset-y-0 left-0 pl-3 flex items-center pointer-events-none">
                            <svg class="h-4 md:h-5 w-4 md:w-5 text-yellow-600" xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M10 6H5a2 2 0 00-2 2v9a2 2 0 002 2h14a2 2 0 002-2V8a2 2 0 00-2-2h-5m-4 0V5a2 2 0 114 0v1m-4 0a2 2 0 104 0m-5 8a2 2 0 100-4 2 2 0 000 4zm0 0c1.306 0 2.417.835 2.83 2M9 14a3.001 3.001 0 00-2.83 2M15 11h3m-3 4h2" />
                            </svg>
                        </div>
                        <input type="text" id="forgot-employee_id" name="employee_id" required class="block w-full pl-9 md:pl-10 pr-3 py-2 md:py-2 border border-gray-300 rounded-md shadow-sm text-sm md:text-base focus:outline-none focus:ring-2 focus:ring-yellow-500 focus:border-yellow-500" placeholder="Enter your employee ID">
                    </div>
                </div>
                <button type="submit" class="w-full bg-yellow-600 text-white py-2 px-4 rounded-md hover:bg-yellow-500 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-yellow-500 transition duration-150 ease-in-out text-sm md:text-base">
                    Send Reset Link
                </button>
            </form>
        </div>
    </div>

    <script>
        // Forgot Password Modal
        const forgotPasswordLink = document.getElementById('forgot-password-link');
        const forgotPasswordModal = document.getElementById('forgot-password-modal');
        const closeModal = forgotPasswordModal.querySelector('.close');
        const forgotPasswordForm = document.getElementById('forgot-password-form');
        const forgotPasswordMessage = document.getElementById('forgot-password-message');

        forgotPasswordLink.addEventListener('click', (e) => {
            e.preventDefault();
            forgotPasswordModal.style.display = 'block';
            forgotPasswordMessage.innerHTML = ''; // Clear previous message
        });

        closeModal.addEventListener('click', () => {
            forgotPasswordModal.style.display = 'none';
        });

        window.addEventListener('click', (e) => {
            if (e.target === forgotPasswordModal) {
                forgotPasswordModal.style.display = 'none';
            }
        });

        forgotPasswordForm.addEventListener('submit', async (e) => {
            e.preventDefault();
            const employeeId = document.getElementById('forgot-employee_id').value;
            const response = await fetch('/forgot-password', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/x-www-form-urlencoded'
                },
                body: new URLSearchParams({
                    employee_id: employeeId
                })
            });
            const data = await response.json();
            if (data.success) {
                forgotPasswordMessage.innerHTML = `<div class="p-3 bg-green-100 text-green-800 rounded-lg">${data.message}</div>`;
            } else {
                forgotPasswordMessage.innerHTML = `<div class="p-3 bg-red-100 text-red-800 rounded-lg">${data.message}</div>`;
            }
        });
    </script>
</body>

</html>