<?php
// src/services/AdmissionService.php

class AdmissionService {
    private $db;
    private $securityService;
    private $emailService;
    
    public function __construct($db) {
        $this->db = $db;
        $this->securityService = new SecurityService($db);
        $this->emailService = new EmailService();
    }
    
    /**
     * Submit admission application
     */
    public function submitApplication($data) {
        try {
            $this->db->beginTransaction();
            
            // Validate input
            $validationErrors = $this->validateApplicationData($data);
            if (!empty($validationErrors)) {
                throw new Exception(implode(', ', $validationErrors));
            }
            
            // Check for existing applications
            if ($this->hasPendingApplication($data['employee_id'], $data['email'])) {
                throw new Exception('You already have a pending application. Please wait for approval.');
            }
            
            // Create admission application record
            $applicationData = [
                'employee_id' => $data['employee_id'],
                'username' => $data['username'],
                'email' => $data['email'],
                'first_name' => $data['first_name'],
                'last_name' => $data['last_name'],
                'college_id' => $data['college_id'],
                'department_id' => $data['department_id'] ?? null,
                'role_id' => $data['role_id'],
                'application_data' => json_encode([
                    'middle_name' => $data['middle_name'] ?? '',
                    'suffix' => $data['suffix'] ?? '',
                    'phone' => $data['phone'] ?? '',
                    'academic_rank' => $data['academic_rank'] ?? '',
                    'employment_type' => $data['employment_type'] ?? '',
                    'classification' => $data['classification'] ?? '',
                    'roles' => $data['roles'] ?? [],
                    'department_ids' => $data['department_ids'] ?? [],
                    'primary_department_id' => $data['primary_department_id'] ?? null
                ]),
                'status' => 'pending',
                'submitted_at' => date('Y-m-d H:i:s')
            ];
            
            $query = "INSERT INTO admission_applications 
                      (employee_id, username, email, first_name, last_name, college_id, department_id, role_id, application_data, status, submitted_at) 
                      VALUES (:employee_id, :username, :email, :first_name, :last_name, :college_id, :department_id, :role_id, :application_data, :status, :submitted_at)";
            
            $stmt = $this->db->prepare($query);
            $stmt->execute($applicationData);
            
            $applicationId = $this->db->lastInsertId();
            
            // Send notification to admin/dean
            $this->sendApplicationNotification($applicationId, $data);
            
            $this->db->commit();
            
            // Log successful application
            $this->securityService->logSecurityAction(
                $_SERVER['REMOTE_ADDR'], 
                'admission_application_submitted', 
                $data['employee_id']
            );
            
            return $applicationId;
            
        } catch (Exception $e) {
            $this->db->rollBack();
            
            // Log application failure
            $this->securityService->logSecurityAction(
                $_SERVER['REMOTE_ADDR'], 
                'admission_application_failed', 
                $data['employee_id'] ?? 'unknown',
                $e->getMessage()
            );
            
            throw $e;
        }
    }
    
    /**
     * Validate application data
     */
    private function validateApplicationData($data) {
        $errors = [];
        
        // Required fields
        $required = ['employee_id', 'username', 'email', 'first_name', 'last_name', 'college_id', 'role_id'];
        foreach ($required as $field) {
            if (empty($data[$field])) {
                $errors[] = "$field is required";
            }
        }
        
        // Email validation
        if (!empty($data['email']) && !$this->securityService->isValidEmail($data['email'])) {
            $errors[] = "Invalid email format";
        }
        
        // SQL injection detection
        foreach ($data as $key => $value) {
            if (is_string($value) && $this->securityService->detectSqlInjection($value)) {
                $errors[] = "Invalid input detected in $key";
                break;
            }
        }
        
        // Password strength
        if (!empty($data['password']) && strlen($data['password']) < 8) {
            $errors[] = "Password must be at least 8 characters long";
        }
        
        return $errors;
    }
    
    /**
     * Check for pending applications
     */
    private function hasPendingApplication($employeeId, $email) {
        $query = "SELECT COUNT(*) FROM admission_applications 
                  WHERE (employee_id = :employee_id OR email = :email) 
                  AND status = 'pending'";
        $stmt = $this->db->prepare($query);
        $stmt->execute([
            ':employee_id' => $employeeId,
            ':email' => $email
        ]);
        
        return $stmt->fetchColumn() > 0;
    }
    
    /**
     * Send application notification
     */
    private function sendApplicationNotification($applicationId, $data) {
        try {
            $subject = "New Admission Application - " . $data['employee_id'];
            $message = "
                A new admission application has been submitted:
                
                Applicant: {$data['first_name']} {$data['last_name']}
                Employee ID: {$data['employee_id']}
                Email: {$data['email']}
                College: {$data['college_id']}
                Role: {$data['role_id']}
                
                Please review the application in the admin panel.
            ";
            
            // Get admin emails (you might want to fetch this from database)
            $adminEmails = ['admin@prmsu.edu.ph']; // Replace with actual admin emails
            
            foreach ($adminEmails as $email) {
                $this->emailService->sendEmail($email, $subject, $message);
            }
            
        } catch (Exception $e) {
            error_log("Failed to send application notification: " . $e->getMessage());
        }
    }
    
    /**
     * Get pending applications
     */
    public function getPendingApplications($limit = 50, $offset = 0) {
        try {
            $query = "SELECT a.*, c.college_name, d.department_name, r.role_name 
                      FROM admission_applications a
                      LEFT JOIN colleges c ON a.college_id = c.college_id
                      LEFT JOIN departments d ON a.department_id = d.department_id
                      LEFT JOIN roles r ON a.role_id = r.role_id
                      WHERE a.status = 'pending'
                      ORDER BY a.submitted_at DESC
                      LIMIT :limit OFFSET :offset";
            
            $stmt = $this->db->prepare($query);
            $stmt->bindValue(':limit', (int)$limit, PDO::PARAM_INT);
            $stmt->bindValue(':offset', (int)$offset, PDO::PARAM_INT);
            $stmt->execute();
            
            return $stmt->fetchAll(PDO::FETCH_ASSOC);
            
        } catch (PDOException $e) {
            error_log("Error getting pending applications: " . $e->getMessage());
            return [];
        }
    }
    
    /**
     * Approve application
     */
    public function approveApplication($applicationId, $reviewedBy) {
        try {
            $this->db->beginTransaction();
            
            // Get application data
            $query = "SELECT * FROM admission_applications WHERE application_id = :application_id";
            $stmt = $this->db->prepare($query);
            $stmt->execute([':application_id' => $applicationId]);
            $application = $stmt->fetch(PDO::FETCH_ASSOC);
            
            if (!$application) {
                throw new Exception("Application not found");
            }
            
            $applicationData = json_decode($application['application_data'], true);
            
            // Create user using existing AuthService
            $authService = new AuthService($this->db);
            $userData = [
                'employee_id' => $application['employee_id'],
                'username' => $application['username'],
                'password' => bin2hex(random_bytes(8)), // Generate random password
                'email' => $application['email'],
                'first_name' => $application['first_name'],
                'last_name' => $application['last_name'],
                'middle_name' => $applicationData['middle_name'] ?? '',
                'suffix' => $applicationData['suffix'] ?? '',
                'phone' => $applicationData['phone'] ?? '',
                'roles' => $applicationData['roles'] ?? [$application['role_id']],
                'college_id' => $application['college_id'],
                'department_id' => $application['department_id'] ?? $applicationData['primary_department_id'] ?? null,
                'role_id' => $application['role_id'],
                'academic_rank' => $applicationData['academic_rank'] ?? '',
                'employment_type' => $applicationData['employment_type'] ?? '',
                'classification' => $applicationData['classification'] ?? '',
                'department_ids' => $applicationData['department_ids'] ?? []
            ];
            
            // Register user (this will send confirmation email)
            $userId = $authService->register($userData);
            
            if (!$userId) {
                throw new Exception("Failed to create user account");
            }
            
            // Update application status
            $query = "UPDATE admission_applications 
                      SET status = 'approved', reviewed_at = NOW(), reviewed_by = :reviewed_by 
                      WHERE application_id = :application_id";
            $stmt = $this->db->prepare($query);
            $stmt->execute([
                ':reviewed_by' => $reviewedBy,
                ':application_id' => $applicationId
            ]);
            
            $this->db->commit();
            
            // Send approval email
            $this->sendApprovalEmail($application, $userData['password']);
            
            return $userId;
            
        } catch (Exception $e) {
            $this->db->rollBack();
            throw $e;
        }
    }
    
    /**
     * Reject application
     */
    public function rejectApplication($applicationId, $reviewedBy, $reason) {
        try {
            $query = "UPDATE admission_applications 
                      SET status = 'rejected', reviewed_at = NOW(), reviewed_by = :reviewed_by, rejection_reason = :reason 
                      WHERE application_id = :application_id";
            $stmt = $this->db->prepare($query);
            $stmt->execute([
                ':reviewed_by' => $reviewedBy,
                ':reason' => $reason,
                ':application_id' => $applicationId
            ]);
            
            // Send rejection email
            $this->sendRejectionEmail($applicationId, $reason);
            
            return true;
            
        } catch (PDOException $e) {
            error_log("Error rejecting application: " . $e->getMessage());
            return false;
        }
    }
    
    /**
     * Send approval email
     */
    private function sendApprovalEmail($application, $password) {
        try {
            $subject = "Your PRMSU Scheduling System Application Has Been Approved";
            $message = "
                Dear {$application['first_name']} {$application['last_name']},
                
                Your application to the PRMSU Scheduling System has been approved.
                
                Your login credentials:
                Employee ID: {$application['employee_id']}
                Username: {$application['username']}
                Temporary Password: $password
                
                Please log in and change your password immediately:
                http://localhost:8000/login
                
                For security reasons, we recommend changing your password after first login.
                
                Best regards,
                PRMSU Scheduling System Team
            ";
            
            $this->emailService->sendEmail($application['email'], $subject, $message);
            
        } catch (Exception $e) {
            error_log("Failed to send approval email: " . $e->getMessage());
        }
    }
    
    /**
     * Send rejection email
     */
    private function sendRejectionEmail($applicationId, $reason) {
        try {
            $query = "SELECT * FROM admission_applications WHERE application_id = :application_id";
            $stmt = $this->db->prepare($query);
            $stmt->execute([':application_id' => $applicationId]);
            $application = $stmt->fetch(PDO::FETCH_ASSOC);
            
            $subject = "Update on Your PRMSU Scheduling System Application";
            $message = "
                Dear {$application['first_name']} {$application['last_name']},
                
                Thank you for your interest in the PRMSU Scheduling System.
                
                After careful review, we regret to inform you that your application has not been approved at this time.
                
                Reason: $reason
                
                If you believe this is an error or would like to provide additional information, 
                please contact the system administrator.
                
                Best regards,
                PRMSU Scheduling System Team
            ";
            
            $this->emailService->sendEmail($application['email'], $subject, $message);
            
        } catch (Exception $e) {
            error_log("Failed to send rejection email: " . $e->getMessage());
        }
    }
}
?>