<?php

use PHPMailer\PHPMailer\PHPMailer;
use PHPMailer\PHPMailer\Exception;

require_once __DIR__ . '/../../vendor/autoload.php';
require_once __DIR__ . '/../models/UserModel.php';

class EmailService
{
    public $mailer;
    public $userModel;
    public $db;

    public function __construct()
    {
        $this->mailer = new PHPMailer(true);
        $this->mailer->isSMTP();
        $this->mailer->Host = $_ENV['SMTP_HOST']; // Replace with your SMTP host
        $this->mailer->SMTPAuth = true;
        $this->mailer->Username = $_ENV['USERNAME']; // Replace with your Gmail address
        $this->mailer->Password = $_ENV['PASSWORD']; // Replace with Gmail App Password
        $this->mailer->SMTPSecure = PHPMailer::ENCRYPTION_SMTPS;
        $this->mailer->Port = 465;

        $this->db = new PDO("mysql:host=" . $_ENV['DB_HOST'] . ";dbname=" . $_ENV['DB_NAME'], $_ENV['DB_USER'], $_ENV['DB_PASS']); // Ensure DB connection
        $this->userModel = new UserModel();
    }

    /**
     * Send account approval email
     * @param string $toEmail
     * @param string $name
     * @param string $role
     * @return bool
     */
    public function sendApprovalEmail($toEmail, $name, $role)
    {
        try {
            $this->mailer->setFrom('mlbausa84@gmail.com', 'ACSS System');
            $this->mailer->addAddress($toEmail, $name);
            $this->mailer->isHTML(true);
            $this->mailer->Subject = '✅ Welcome to ACSS - Your Account is Now Active';

            $this->mailer->Body = "
        <!DOCTYPE html>
        <html lang='en'>
        <head>
            <meta charset='UTF-8'>
            <meta name='viewport' content='width=device-width, initial-scale=1.0'>
            <title>Account Approved</title>
        </head>
        <body style='margin: 0; padding: 0; font-family: -apple-system, BlinkMacSystemFont, \"Segoe UI\", Roboto, \"Helvetica Neue\", Arial, sans-serif; line-height: 1.6; color: #333333; background-color: #f8fafc;'>
            <div style='max-width: 600px; margin: 40px auto; background-color: #ffffff; border-radius: 16px; box-shadow: 0 10px 25px rgba(0, 0, 0, 0.1); overflow: hidden;'>
                <div style='background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); padding: 40px 30px; text-align: center;'>
                    <div style='background-color: rgba(255, 255, 255, 0.2); width: 80px; height: 80px; border-radius: 50%; margin: 0 auto 20px; display: flex; align-items: center; justify-content: center; border: 3px solid rgba(255, 255, 255, 0.3);'>
                        <span style='font-size: 36px; color: #ffffff;'>✅</span>
                    </div>
                    <h1 style='color: #ffffff; margin: 0; font-size: 28px; font-weight: 700; text-shadow: 0 2px 4px rgba(0, 0, 0, 0.1);'>Account Approved!</h1>
                    <p style='color: rgba(255, 255, 255, 0.9); margin: 10px 0 0 0; font-size: 16px; font-weight: 300;'>Welcome to the ACSS System</p>
                </div>
                <div style='padding: 40px 30px;'>
                    <div style='text-align: center; margin-bottom: 30px;'>
                        <h2 style='color: #2d3748; margin: 0 0 10px 0; font-size: 24px; font-weight: 600;'>Hello, $name! 👋</h2>
                        <p style='color: #718096; margin: 0; font-size: 16px;'>Great news! Your account has been successfully approved.</p>
                    </div>
                    <div style='background-color: #f7fafc; border-left: 4px solid #38a169; padding: 20px 25px; margin: 25px 0; border-radius: 8px;'>
                        <div style='display: flex; align-items: center; margin-bottom: 15px;'>
                            <span style='background-color: #38a169; color: white; padding: 8px 12px; border-radius: 6px; font-size: 12px; font-weight: 600; text-transform: uppercase; letter-spacing: 0.5px;'>Approved</span>
                        </div>
                        <p style='margin: 0 0 10px 0; color: #4a5568; font-size: 16px;'>
                            <strong>Role:</strong> <span style='color: #2d3748; font-weight: 600;'>$role</span>
                        </p>
                        <p style='margin: 0; color: #4a5568; font-size: 14px;'>
                            <strong>Approved by:</strong> Dean's Office
                        </p>
                    </div>
                    <div style='text-align: center; margin: 35px 0;'>
                        <a href='http://localhost:8000/login' 
                           style='display: inline-block; background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: #ffffff; padding: 16px 32px; text-decoration: none; border-radius: 50px; font-weight: 600; font-size: 16px; box-shadow: 0 4px 15px rgba(102, 126, 234, 0.4); transition: all 0.3s ease; border: none; cursor: pointer;'>
                            🚀 Access Your Account
                        </a>
                        <p style='margin: 15px 0 0 0; color: #a0aec0; font-size: 13px;'>
                            Or copy this link: <br>
                            <span style='background-color: #edf2f7; padding: 4px 8px; border-radius: 4px; font-family: monospace; font-size: 12px; color: #4a5568;'>http://localhost:8000/login</span>
                        </p>
                    </div>
                    <div style='background-color: #f7fafc; border-radius: 12px; padding: 25px; margin: 30px 0;'>
                        <h3 style='color: #2d3748; margin: 0 0 20px 0; font-size: 18px; font-weight: 600; text-align: center;'>What's Next?</h3>
                        <div style='display: grid; gap: 15px;'>
                            <div style='display: flex; align-items: center;'>
                                <span style='background-color: #e6fffa; color: #319795; width: 32px; height: 32px; border-radius: 50%; display: inline-flex; align-items: center; justify-content: center; margin-right: 15px; font-weight: bold; font-size: 14px;'>1</span>
                                <div>
                                    <p style='margin: 0; color: #2d3748; font-weight: 500;'>Complete your profile setup</p>
                                    <p style='margin: 0; color: #718096; font-size: 13px;'>Add your personal information and preferences</p>
                                </div>
                            </div>
                            <div style='display: flex; align-items: center;'>
                                <span style='background-color: #e6fffa; color: #319795; width: 32px; height: 32px; border-radius: 50%; display: inline-flex; align-items: center; justify-content: center; margin-right: 15px; font-weight: bold; font-size: 14px;'>2</span>
                                <div>
                                    <p style='margin: 0; color: #2d3748; font-weight: 500;'>Explore the dashboard</p>
                                    <p style='margin: 0; color: #718096; font-size: 13px;'>Familiarize yourself with the available features</p>
                                </div>
                            </div>
                            <div style='display: flex; align-items: center;'>
                                <span style='background-color: #e6fffa; color: #319795; width: 32px; height: 32px; border-radius: 50%; display: inline-flex; align-items: center; justify-content: center; margin-right: 15px; font-weight: bold; font-size: 14px;'>3</span>
                                <div>
                                    <p style='margin: 0; color: #2d3748; font-weight: 500;'>Start using ACSS features</p>
                                    <p style='margin: 0; color: #718096; font-size: 13px;'>Begin managing your academic activities</p>
                                </div>
                            </div>
                        </div>
                    </div>
                    <div style='background-color: #fffaf0; border: 1px solid #fbd38d; border-radius: 8px; padding: 20px; margin: 25px 0; text-align: center;'>
                        <p style='margin: 0 0 10px 0; color: #744210; font-weight: 500;'>Need help getting started?</p>
                        <p style='margin: 0; color: #975a16; font-size: 14px;'>
                            Contact our support team at <a href='mailto:support@acss.com' style='color: #c05621; text-decoration: none; font-weight: 500;'>support@acss.com</a>
                            <br>or visit our <a href='#' style='color: #c05621; text-decoration: none; font-weight: 500;'>Help Center</a>
                        </p>
                    </div>
                </div>
                <div style='background-color: #2d3748; padding: 30px; text-align: center;'>
                    <div style='margin-bottom: 20px;'>
                        <h3 style='color: #ffffff; margin: 0; font-size: 20px; font-weight: 700;'>ACSS System</h3>
                        <p style='color: #a0aec0; margin: 5px 0 0 0; font-size: 14px;'>Academic Coordination & Support System</p>
                    </div>
                    <div style='border-top: 1px solid #4a5568; padding-top: 20px;'>
                        <p style='color: #a0aec0; margin: 0; font-size: 12px;'>
                            This email was sent to $toEmail<br>
                            © 2024 ACSS System. All rights reserved.
                        </p>
                    </div>
                </div>
            </div>
            <style>
                @media only screen and (max-width: 600px) {
                    .email-container {
                        margin: 20px auto !important;
                        border-radius: 8px !important;
                    }
                    .email-content {
                        padding: 25px 20px !important;
                    }
                    .cta-button {
                        padding: 14px 24px !important;
                        font-size: 15px !important;
                    }
                }
            </style>
        </body>
        </html>";

            $this->mailer->AltBody = "
            🎉 ACCOUNT APPROVED - Welcome to ACSS System!

            Hello $name,

            Great news! Your account for the role of $role has been successfully approved by the Dean's office.

            🚀 GET STARTED:
            You can now access your account at: http://localhost:8000/login

            📋 WHAT'S NEXT:
            1. Complete your profile setup
            2. Explore the dashboard features  
            3. Start using ACSS system tools

            💡 NEED HELP?
            Contact support: support@acss.com
            Visit our Help Center for guides and tutorials

            Thank you for joining ACSS System!

            Best regards,
            The ACSS Team

            ---
            This email was sent to $toEmail
            © 2024 ACSS System. All rights reserved.
        ";

            $this->mailer->send();
            return true;
        } catch (Exception $e) {
            error_log("Error sending approval email to $toEmail: " . $this->mailer->ErrorInfo);
            return false;
        }
    }

    /**
     * Send password reset email
     * @param string $toEmail
     * @param string $name
     * @param string $token
     * @param string $resetLink
     * @return bool
     */
    public function sendForgotPasswordEmail($toEmail, $name, $resetLink)
    {
        try {
            $this->mailer->setFrom('mlbausa84@gmail.com', 'ACSS System');
            $this->mailer->addAddress($toEmail, $name);
            $this->mailer->isHTML(true);
            $this->mailer->Subject = '📩 Reset Your PRMSU Scheduling System Password';

            $this->mailer->Body = "
            <!DOCTYPE html>
            <html lang='en'>
            <head>
                <meta charset='UTF-8'>
                <meta name='viewport' content='width=device-width, initial-scale=1.0'>
                <title>Password Reset</title>
            </head>
            <body style='margin: 0; padding: 0; font-family: -apple-system, BlinkMacSystemFont, \"Segoe UI\", Roboto, \"Helvetica Neue\", Arial, sans-serif; line-height: 1.6; color: #333333; background-color: #f8fafc;'>
                <div style='max-width: 600px; margin: 40px auto; background-color: #ffffff; border-radius: 16px; box-shadow: 0 10px 25px rgba(0, 0, 0, 0.1); overflow: hidden;'>
                    <div style='background: linear-gradient(135deg, #ed8936 0%, #dd6b20 100%); padding: 40px 30px; text-align: center;'>
                        <div style='background-color: rgba(255, 255, 255, 0.2); width: 80px; height: 80px; border-radius: 50%; margin: 0 auto 20px; display: flex; align-items: center; justify-content: center; border: 3px solid rgba(255, 255, 255, 0.3);'>
                            <span style='font-size: 36px; color: #ffffff;'>🔒</span>
                        </div>
                        <h1 style='color: #ffffff; margin: 0; font-size: 28px; font-weight: 700; text-shadow: 0 2px 4px rgba(0, 0, 0, 0.1);'>Password Reset</h1>
                        <p style='color: rgba(255, 255, 255, 0.9); margin: 10px 0 0 0; font-size: 16px; font-weight: 300;'>PRMSU Scheduling System</p>
                    </div>
                    <div style='padding: 40px 30px;'>
                        <div style='text-align: center; margin-bottom: 30px;'>
                            <h2 style='color: #2d3748; margin: 0 0 10px 0; font-size: 24px; font-weight: 600;'>Hello, $name! 👋</h2>
                            <p style='color: #718096; margin: 0; font-size: 16px;'>We received a request to reset your password. Click the button below to create a new one.</p>
                        </div>
                        <div style='text-align: center; margin: 30px 0;'>
                            <a href='$resetLink' style='display: inline-block; background-color: #ed8936; color: #ffffff; padding: 12px 24px; border-radius: 8px; text-decoration: none; font-size: 16px; font-weight: 600; transition: background-color 0.3s;'>Reset Password</a>
                        </div>
                        <div style='background-color: #fefcbf; border-left: 4px solid #d69e2e; padding: 20px 25px; margin: 25px 0; border-radius: 8px;'>
                            <p style='margin: 0; color: #744210; font-size: 14px;'>This link will expire in 24 hours. If you didn’t request a password reset, please ignore this email or contact support.</p>
                        </div>
                        <div style='background-color: #fffaf0; border: 1px solid #fbd38d; border-radius: 8px; padding: 20px; margin: 25px 0; text-align: center;'>
                            <p style='margin: 0 0 10px 0; color: #744210; font-weight: 500;'>Need help?</p>
                            <p style='margin: 0; color: #975a16; font-size: 14px;'>
                                Contact our support team at <a href='mailto:support@prmsu.edu.ph' style='color: #c05621; text-decoration: none; font-weight: 500;'>support@prmsu.edu.ph</a>
                            </p>
                        </div>
                    </div>
                    <div style='background-color: #2d3748; padding: 30px; text-align: center;'>
                        <div style='margin-bottom: 20px;'>
                            <h3 style='color: #ffffff; margin: 0; font-size: 20px; font-weight: 700;'>PRMSU Scheduling System</h3>
                            <p style='color: #a0aec0; margin: 5px 0 0 0; font-size: 14px;'>President Ramon Magsaysay State University</p>
                        </div>
                        <div style='border-top: 1px solid #4a5568; padding-top: 20px;'>
                            <p style='color: #a0aec0; margin: 0; font-size: 12px;'>
                                This email was sent to $toEmail<br>
                                © 2025 PRMSU. All rights reserved.
                            </p>
                        </div>
                    </div>
                </div>
            </body>
            </html>";

            $this->mailer->AltBody = "
            🔒 PASSWORD RESET - PRMSU Scheduling System

            Hello $name,

            We received a request to reset your password. Use the link below to create a new one:
            $resetLink

            This link will expire in 24 hours. If you didn’t request this, please ignore this email or contact support at support@prmsu.edu.ph.

            Best regards,
            The PRMSU Scheduling Team

            ---
            This email was sent to $toEmail
            © 2025 PRMSU. All rights reserved.
        ";

            $this->mailer->send();
            return true;
        } catch (Exception $e) {
            error_log("Error sending forgot password email to $toEmail: " . $e->getMessage());
            return false;
        }
    }

    public function sendVerificationEmail($userId, $token, $newPassword)
    {
        $stmt = $this->db->prepare("SELECT email FROM users WHERE user_id = :user_id");
        $stmt->execute([':user_id' => $userId]);
        $email = $stmt->fetchColumn();

        $verificationLink = "http://yourdomain.com/chair/verify-password?token={$token}&user_id={$userId}";
        try {
            $this->mailer->setFrom('mlbausa84@gmail.com', 'ACSS System');
            $this->mailer->addAddress($email);
            $this->mailer->isHTML(true);
            $this->mailer->Subject = 'Verify Your Password Change';

            $this->mailer->Body = "
                <p>Click the link to verify your password change: <a href='$verificationLink'>$verificationLink</a></p>
                <p>New Password: $newPassword</p>
                <p>This link expires in 1 hour.</p>
            ";
            $this->mailer->AltBody = "Click the link to verify your password change: $verificationLink\nNew Password: $newPassword\nThis link expires in 1 hour.";

            $this->mailer->send();
        } catch (Exception $e) {
            error_log("Error sending verification email to $email: " . $this->mailer->ErrorInfo);
        }
    }

    public function sendConfirmationEmail($toEmail, $name, $role)
    {
        try {
            $this->mailer->setFrom('mlbausa84@gmail.com', 'ACSS System');
            $this->mailer->addAddress($toEmail, $name);
            $this->mailer->isHTML(true);
            $this->mailer->Subject = '📩 Welcome to ACSS - Account Registration';

            $this->mailer->Body = "
                <!DOCTYPE html>
                <html lang='en'>
                <head>
                    <meta charset='UTF-8'>
                    <meta name='viewport' content='width=device-width, initial-scale=1.0'>
                    <title>Account Registration</title>
                </head>
                <body style='margin: 0; padding: 0; font-family: -apple-system, BlinkMacSystemFont, \"Segoe UI\", Roboto, \"Helvetica Neue\", Arial, sans-serif; line-height: 1.6; color: #333333; background-color: #f8fafc;'>
                    <div style='max-width: 600px; margin: 40px auto; background-color: #ffffff; border-radius: 16px; box-shadow: 0 10px 25px rgba(0, 0, 0, 0.1); overflow: hidden;'>
                        <div style='background: linear-gradient(135deg, #48bb78 0%, #2f855a 100%); padding: 40px 30px; text-align: center;'>
                            <div style='background-color: rgba(255, 255, 255, 0.2); width: 80px; height: 80px; border-radius: 50%; margin: 0 auto 20px; display: flex; align-items: center; justify-content: center; border: 3px solid rgba(255, 255, 255, 0.3);'>
                                <span style='font-size: 36px; color: #ffffff;'>📩</span>
                            </div>
                            <h1 style='color: #ffffff; margin: 0; font-size: 28px; font-weight: 700; text-shadow: 0 2px 4px rgba(0, 0, 0, 0.1);'>Welcome to ACSS!</h1>
                            <p style='color: rgba(255, 255, 255, 0.9); margin: 10px 0 0 0; font-size: 16px; font-weight: 300;'>Your account has been registered</p>
                        </div>
                        <div style='padding: 40px 30px;'>
                            <div style='text-align: center; margin-bottom: 30px;'>
                                <h2 style='color: #2d3748; margin: 0 0 10px 0; font-size: 24px; font-weight: 600;'>Hello, $name! 👋</h2>
                                <p style='color: #718096; margin: 0; font-size: 16px;'>Your account with the role of $role has been successfully registered.</p>
                            </div>
                            <div style='background-color: #f7fafc; border-left: 4px solid #48bb78; padding: 20px 25px; margin: 25px 0; border-radius: 8px;'>
                                <div style='display: flex; align-items: center; margin-bottom: 15px;'>
                                    <span style='background-color: #48bb78; color: white; padding: 8px 12px; border-radius: 6px; font-size: 12px; font-weight: 600; text-transform: uppercase; letter-spacing: 0.5px;'>Registered</span>
                                </div>
                                <p style='margin: 0 0 10px 0; color: #4a5568; font-size: 16px;'>
                                    <strong>Role:</strong> <span style='color: #2d3748; font-weight: 600;'>$role</span>
                                </p>
                                <p style='margin: 0; color: #4a5568; font-size: 14px;'>
                                    <strong>Status:</strong> Pending Approval
                                </p>
                            </div>
                            <div style='text-align: center; margin: 35px 0;'>
                                <p style='color: #718096; margin: 0; font-size: 16px;'>Please await approval from the Dean's office. You will receive another email once approved.</p>
                            </div>
                            <div style='background-color: #fffaf0; border: 1px solid #fbd38d; border-radius: 8px; padding: 20px; margin: 25px 0; text-align: center;'>
                                <p style='margin: 0 0 10px 0; color: #744210; font-weight: 500;'>Need help?</p>
                                <p style='margin: 0; color: #975a16; font-size: 14px;'>
                                    Contact our support team at <a href='mailto:support@acss.com' style='color: #c05621; text-decoration: none; font-weight: 500;'>support@acss.com</a>
                                    <br>or visit our <a href='#' style='color: #c05621; text-decoration: none; font-weight: 500;'>Help Center</a>
                                </p>
                            </div>
                        </div>
                        <div style='background-color: #2d3748; padding: 30px; text-align: center;'>
                            <div style='margin-bottom: 20px;'>
                                <h3 style='color: #ffffff; margin: 0; font-size: 20px; font-weight: 700;'>ACSS System</h3>
                                <p style='color: #a0aec0; margin: 5px 0 0 0; font-size: 14px;'>Academic Coordination & Support System</p>
                            </div>
                            <div style='border-top: 1px solid #4a5568; padding-top: 20px;'>
                                <p style='color: #a0aec0; margin: 0; font-size: 12px;'>
                                    This email was sent to $toEmail<br>
                                    © 2024 ACSS System. All rights reserved.
                                </p>
                            </div>
                        </div>
                    </div>
                    <style>
                        @media only screen and (max-width: 600px) {
                            .email-container {
                                margin: 20px auto !important;
                                border-radius: 8px !important;
                            }
                            .email-content {
                                padding: 25px 20px !important;
                            }
                            .cta-button {
                                padding: 14px 24px !important;
                                font-size: 15px !important;
                            }
                        }
                    </style>
                </body>
                </html>";

            $this->mailer->AltBody = "
                    📩 WELCOME TO ACSS SYSTEM - Account Registered!

                    Hello $name,

                    Your account with the role of $role has been successfully registered.
                    Please await approval from the Dean's office. You will receive another email once approved.

                    💡 NEED HELP?
                    Contact support: support@acss.com
                    Visit our Help Center for guides and tutorials

                    Best regards,
                    The ACSS Team

                    ---
                    This email was sent to $toEmail
                    © 2024 ACSS System. All rights reserved.
                ";

            $this->mailer->send();
            return true;
        } catch (Exception $e) {
            error_log("Error sending confirmation email to $toEmail: " . $this->mailer->ErrorInfo);
            return false;
        }
    }

    public function sendNotificationEmail($toEmail, $subject, $message)
    {
        try {
            $this->mailer->setFrom('mlbausa84@gmail.com', 'ACSS System');
            $this->mailer->addAddress($toEmail);
            $this->mailer->isHTML(true);
            $this->mailer->Subject = $subject;

            $this->mailer->Body = "
                <!DOCTYPE html>
                <html lang='en'>
                <head>
                    <meta charset='UTF-8'>
                    <meta name='viewport' content='width=device-width, initial-scale=1.0'>
                    <title>Notification</title>
                </head>
                <body style='margin: 0; padding: 0; font-family: -apple-system, BlinkMacSystemFont, \"Segoe UI\", Roboto, \"Helvetica Neue\", Arial, sans-serif; line-height: 1.6; color: #333333; background-color: #f8fafc;'>
                    <div style='max-width: 600px; margin: 40px auto; background-color: #ffffff; border-radius: 16px; box-shadow: 0 10px 25px rgba(0, 0, 0, 0.1); overflow: hidden;'>
                        <div style='background: linear-gradient(135deg, #ed8936 0%, #dd6b20 100%); padding: 40px 30px; text-align: center;'>
                            <div style='background-color: rgba(255, 255, 255, 0.2); width: 80px; height: 80px; border-radius: 50%; margin: 0 auto 20px; display: flex; align-items: center; justify-content: center; border: 3px solid rgba(255, 255, 255, 0.3);'>
                                <span style='font-size: 36px; color: #ffffff;'>🔔</span>
                            </div>
                            <h1 style='color: #ffffff; margin: 0; font-size: 28px; font-weight: 700; text-shadow: 0 2px 4px rgba(0, 0, 0, 0.1);'>Notification</h1>
                            <p style='color: rgba(255, 255, 255, 0.9); margin: 10px 0 0 0; font-size: 16px; font-weight: 300;'>ACSS System Update</p>
                        </div>
                        <div style='padding: 40px 30px;'>
                            <div style='text-align: center; margin-bottom: 30px;'>
                                <h2 style='color: #2d3748; margin: 0 0 10px 0; font-size: 24px; font-weight: 600;'>Attention Admin</h2>
                                <p style='color: #718096; margin: 0; font-size: 16px;'>A new action requires your attention.</p>
                            </div>
                            <div style='background-color: #fefcbf; border-left: 4px solid #d69e2e; padding: 20px 25px; margin: 25px 0; border-radius: 8px;'>
                                <p style='margin: 0; color: #744210; font-size: 16px;'>$message</p>
                            </div>
                            <div style='background-color: #fffaf0; border: 1px solid #fbd38d; border-radius: 8px; padding: 20px; margin: 25px 0; text-align: center;'>
                                <p style='margin: 0 0 10px 0; color: #744210; font-weight: 500;'>Need to take action?</p>
                                <p style='margin: 0; color: #975a16; font-size: 14px;'>
                                    Log in to the admin panel at <a href='http://localhost:8000/admin/users' style='color: #c05621; text-decoration: none; font-weight: 500;'>http://localhost:8000/admin/users</a>
                                </p>
                            </div>
                        </div>
                        <div style='background-color: #2d3748; padding: 30px; text-align: center;'>
                            <div style='margin-bottom: 20px;'>
                                <h3 style='color: #ffffff; margin: 0; font-size: 20px; font-weight: 700;'>ACSS System</h3>
                                <p style='color: #a0aec0; margin: 5px 0 0 0; font-size: 14px;'>Academic Coordination & Support System</p>
                            </div>
                            <div style='border-top: 1px solid #4a5568; padding-top: 20px;'>
                                <p style='color: #a0aec0; margin: 0; font-size: 12px;'>
                                    This email was sent to $toEmail<br>
                                    © 2024 ACSS System. All rights reserved.
                                </p>
                            </div>
                        </div>
                    </div>
                    <style>
                        @media only screen and (max-width: 600px) {
                            .email-container {
                                margin: 20px auto !important;
                                border-radius: 8px !important;
                            }
                            .email-content {
                                padding: 25px 20px !important;
                            }
                        }
                    </style>
                </body>
                </html>";

            $this->mailer->AltBody = "
                    🔔 NOTIFICATION - ACSS System

                    A new action requires your attention:
                    $message

                    Need to take action? Log in to the admin panel at: http://localhost:8000/admin/users

                    Best regards,
                    The ACSS Team

                    ---
                    This email was sent to $toEmail
                    © 2024 ACSS System. All rights reserved.
                ";

            $this->mailer->send();
            return true;
        } catch (Exception $e) {
            error_log("Error sending notification email to $toEmail: " . $this->mailer->ErrorInfo);
            return false;
        }
    }

    public function sendWelcomeEmail($email, $firstName, $username, $temporaryPassword)
    {
        try {
            // Create PHPMailer instance (adjust based on your setup)
            $mail = new PHPMailer(true);

            // Server settings
            $mail->isSMTP();
            $mail->Host = 'your-smtp-host.com';
            $mail->SMTPAuth = true;
            $mail->Username = 'your-smtp-username';
            $mail->Password = 'your-smtp-password';
            $mail->SMTPSecure = PHPMailer::ENCRYPTION_STARTTLS;
            $mail->Port = 587;

            // Recipients
            $mail->setFrom('noreply@university.edu', 'University Scheduling System');
            $mail->addAddress($email, $firstName);
            $mail->addReplyTo('support@university.edu', 'Support Team');

            // Content
            $mail->isHTML(true);
            $mail->Subject = 'Welcome to the University Scheduling System';

            $mail->Body = $this->getWelcomeEmailTemplate($firstName, $username, $temporaryPassword);
            $mail->AltBody = $this->getWelcomeEmailTextTemplate($firstName, $username, $temporaryPassword);

            $mail->send();
            error_log("Welcome email sent successfully to: {$email}");
            return true;
        } catch (Exception $e) {
            error_log("Error sending welcome email to {$email}: " . $e->getMessage());
            return false;
        }
    }

    public function getWelcomeEmailTemplate($firstName, $employeeId, $temporaryPassword)
    {
        $loginUrl = (isset($_SERVER['HTTPS']) ? 'https://' : 'http://') .
            $_SERVER['HTTP_HOST'] . '/login';

        return "
    <!DOCTYPE html>
    <html lang='en'>
    <head>
        <meta charset='UTF-8'>
        <meta name='viewport' content='width=device-width, initial-scale=1.0'>
        <title>Welcome to University Scheduling System</title>
        <style>
            body { 
                font-family: 'Segoe UI', Arial, sans-serif; 
                line-height: 1.7; 
                color: #2d3748; 
                background: #f7fafc; 
                margin: 0; 
                padding: 0; 
            }
            .container { 
                max-width: 620px; 
                margin: 20px auto; 
                background: #ffffff; 
                border-radius: 12px; 
                overflow: hidden; 
                box-shadow: 0 10px 25px rgba(0,0,0,0.05); 
            }
            .header { 
                background: linear-gradient(135deg, #D4AF37, #A68A2E); 
                color: white; 
                padding: 30px 20px; 
                text-align: center; 
            }
            .header h1 { 
                margin: 0; 
                font-size: 26px; 
                font-weight: 700; 
            }
            .header h2 { 
                margin: 8px 0 0; 
                font-size: 18px; 
                font-weight: 400; 
            }
            .content { 
                padding: 30px; 
                background: #ffffff; 
            }
            .greeting { 
                font-size: 16px; 
                margin-bottom: 20px; 
            }
            .credentials { 
                background: #fffbeb; 
                border: 2px solid #fbbf24; 
                border-radius: 10px; 
                padding: 20px; 
                margin: 20px 0; 
                font-family: 'Courier New', monospace; 
            }
            .credentials h3 { 
                margin: 0 0 15px; 
                color: #92400e; 
                font-size: 18px; 
            }
            .cred-item { 
                margin: 12px 0; 
                display: flex; 
                justify-content: space-between; 
                align-items: center; 
            }
            .cred-item strong { 
                color: #1a202c; 
                min-width: 140px; 
            }
            .password-box { 
                background: #1a202c; 
                color: #48bb78; 
                padding: 12px 16px; 
                border-radius: 6px; 
                font-weight: bold; 
                letter-spacing: 1px; 
                font-size: 18px; 
                text-align: center; 
                margin: 10px 0; 
                word-break: break-all; 
            }
            .login-btn { 
                display: inline-block; 
                background: #D4AF37; 
                color: white; 
                padding: 12px 24px; 
                border-radius: 6px; 
                text-decoration: none; 
                font-weight: 600; 
                margin: 15px 0; 
            }
            .warning { 
                background: #fef5e7; 
                border: 1px solid #fbbf24; 
                border-radius: 8px; 
                padding: 15px; 
                margin: 20px 0; 
                font-size: 14px; 
            }
            .warning strong { 
                color: #d97706; 
            }
            .steps { 
                background: #f0fff4; 
                border-left: 4px solid #48bb78; 
                padding: 15px 20px; 
                margin: 20px 0; 
                border-radius: 0 8px 8px 0; 
            }
            .steps ol { 
                margin: 0; 
                padding-left: 20px; 
            }
            .steps li { 
                margin: 8px 0; 
                color: #22543d; 
            }
            .footer { 
                text-align: center; 
                padding: 20px; 
                background: #f8fafc; 
                color: #718096; 
                font-size: 12px; 
                border-top: 1px solid #e2e8f0; 
            }
            @media (max-width: 600px) {
                .cred-item { flex-direction: column; align-items: flex-start; }
                .cred-item strong { margin-bottom: 5px; }
            }
        </style>
    </head>
    <body>
        <div class='container'>
            <!-- Header -->
            <div class='header'>
                <h1>University Scheduling System</h1>
                <h2>Welcome, {$firstName}!</h2>
            </div>

            <!-- Content -->
            <div class='content'>
                <p class='greeting'>Dear <strong>{$firstName}</strong>,</p>

                <p>Your account has been successfully created. Please use the credentials below to log in for the first time.</p>

                <!-- Credentials -->
                <div class='credentials'>
                    <h3>Login Credentials</h3>
                    <div class='cred-item'>
                        <strong>Username:</strong>
                        <span><code>{$employeeId}</code></span>
                    </div>
                    <div class='cred-item'>
                        <strong>Temporary Password:</strong>
                        <div class='password-box'>{$temporaryPassword}</div>
                    </div>
                    <div class='cred-item'>
                        <strong>Login URL:</strong>
                        <a href='{$loginUrl}' class='login-btn'>Login Now</a>
                    </div>
                </div>

                <!-- Security Warning -->
                <div class='warning'>
                    <strong>Security Alert:</strong>
                    <ul style='margin:10px 0; padding-left:20px;'>
                        <li>This is a <strong>temporary password</strong></li>
                        <li>You <strong>must change it</strong> immediately after logging in</li>
                        <li>Never share your password with anyone</li>
                    </ul>
                </div>

                <!-- First Login Steps -->
                <div class='steps'>
                    <strong>First Login Instructions:</strong>
                    <ol>
                        <li>Click the <strong>Login Now</strong> button above</li>
                        <li>Enter your <strong>Employee ID</strong> and this <strong>temporary password</strong></li>
                        <li>You will be <strong>automatically redirected</strong> to set a new password</li>
                        <li>Choose a strong, unique password</li>
                    </ol>
                </div>

                <p>If you experience any issues, contact your department administrator or IT support.</p>

                <p>Best regards,<br>
                <strong>University Scheduling System Admin</strong></p>
            </div>

            <!-- Footer -->
            <div class='footer'>
                <p>&copy; " . date('Y') . " University Scheduling System. All rights reserved.</p>
                <p>This is an automated message — please do not reply.</p>
            </div>
        </div>
    </body>
    </html>
    ";
    }

    public function getWelcomeEmailTextTemplate($firstName, $username, $temporaryPassword)
    {
        return "
        Welcome to the University Scheduling System

        Dear {$firstName},

        Your account has been successfully created in the University Scheduling System.

        LOGIN INFORMATION:
        Username: {$username}
        Temporary Password: {$temporaryPassword}
        Login URL: " . (isset($_SERVER['HTTP_HOST']) ? "https://{$_SERVER['HTTP_HOST']}/login" : "Your University System Login Page") . "

        IMPORTANT SECURITY NOTICE:
        - This is a temporary password
        - You must change your password on first login
        - Do not share your credentials with anyone
        - If you didn't request this account, please contact the system administrator immediately

        FIRST LOGIN STEPS:
        1. Go to the login page
        2. Enter your username and the temporary password above
        3. You will be prompted to set a new permanent password
        4. Choose a strong password that you haven't used before

        If you encounter any issues during login, please contact the IT support team or your department administrator.

        Best regards,
        University Scheduling System Administration

        This is an automated message. Please do not reply to this email.
        ";
    }

    public function sendDeclineEmail($to, $name, $role)
    {
        try {
            $subject = "Account Registration Declined";
            $message = "Dear $name,\n\nYour account registration for role: $role has been declined.\n\nThank you.";

            // Check if mail function is available
            if (function_exists('mail')) {
                $headers = "From: noreply@yourdomain.com\r\n";
                $headers .= "Content-Type: text/plain; charset=UTF-8\r\n";

                $result = @mail($to, $subject, $message, $headers);
                if (!$result) {
                    error_log("Email sending failed for: $to");
                    // Don't throw error, just log it
                } else {
                    error_log("Decline email sent successfully to: $to for $name ($role)");
                }
            } else {
                error_log("mail() function not available for: $to");
            }
        } catch (Exception $e) {
            error_log("Email error in sendDeclineEmail: " . $e->getMessage());
            // Don't re-throw, just log the error
        }
    }
}
