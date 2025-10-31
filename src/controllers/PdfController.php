<?php
require_once __DIR__ . '/../services/PdfService.php';

class PdfController
{
    private $pdfService;
    private $activityService;

    public function __construct()
    {
        $this->pdfService = new PdfService();
        // Initialize your activity service here
        // $this->activityService = new ActivityService();
    }

    /**
     * Generate and download activity report PDF
     */
    public function downloadActivityReport()
    {
        try {
            // Get activities data (you'll need to implement this)
            $activities = $this->getActivitiesData();
            $filters = $this->getFiltersFromRequest();

            // Generate PDF
            $pdfData = $this->pdfService->generateActivityReport($activities, $filters, "Your University Name");

            // Send as download
            $filename = $this->generateFilename($filters);
            $this->pdfService->sendAsDownload($pdfData, $filename);
        } catch (Exception $e) {
            $this->handleError($e->getMessage());
        }
    }

    /**
     * View PDF in browser
     */
    public function viewActivityReport()
    {
        try {
            $activities = $this->getActivitiesData();
            $filters = $this->getFiltersFromRequest();

            $pdfData = $this->pdfService->generateActivityReport($activities, $filters, "Your University Name");
            $this->pdfService->outputToBrowser($pdfData);
        } catch (Exception $e) {
            $this->handleError($e->getMessage());
        }
    }

    /**
     * Generate detailed report
     */
    public function downloadDetailedReport()
    {
        try {
            $activities = $this->getActivitiesData();
            $stats = $this->getStatisticsData();
            $filters = $this->getFiltersFromRequest();

            $pdfData = $this->pdfService->generateDetailedReport($activities, $stats, $filters, "Your University Name");

            $filename = "detailed_activity_report_" . date('Y-m-d') . ".pdf";
            $this->pdfService->sendAsDownload($pdfData, $filename);
        } catch (Exception $e) {
            $this->handleError($e->getMessage());
        }
    }

    /**
     * Save PDF to server and return file path
     */
    public function saveReport()
    {
        try {
            $activities = $this->getActivitiesData();
            $filters = $this->getFiltersFromRequest();

            $pdfData = $this->pdfService->generateActivityReport($activities, $filters, "Your University Name");

            $filename = $this->generateFilename($filters);
            $filepath = $this->pdfService->saveToFile($pdfData, $filename);

            return [
                'success' => true,
                'filepath' => $filepath,
                'filename' => $filename,
                'message' => 'Report saved successfully'
            ];
        } catch (Exception $e) {
            return [
                'success' => false,
                'error' => $e->getMessage()
            ];
        }
    }

    /**
     * Helper methods
     */
    private function getActivitiesData()
    {
        // Implement this to get activities from your database
        // This should return the same format as your current activity data
        return []; // Your activity data here
    }

    private function getStatisticsData()
    {
        // Implement this to get statistics for detailed report
        return [
            'total_activities' => 0,
            'unique_users' => 0,
            'activity_by_type' => [],
            'activity_by_college' => [],
            // ... other stats
        ];
    }

    private function getFiltersFromRequest()
    {
        // Get filters from POST/GET request
        return [
            'dateRange' => $_POST['dateRange'] ?? 'all',
            'college' => $_POST['college'] ?? 'all',
            'department' => $_POST['department'] ?? 'all',
            'actionType' => $_POST['actionType'] ?? 'all',
            'timeFilter' => $_POST['timeFilter'] ?? 'all'
        ];
    }

    private function generateFilename($filters)
    {
        $baseName = "activity_report";

        if ($filters['dateRange'] !== 'all') {
            $baseName .= "_" . $filters['dateRange'];
        }
        if ($filters['college'] !== 'all') {
            $baseName .= "_" . str_replace(' ', '_', strtolower($filters['college']));
        }

        $baseName .= "_" . date('Y-m-d_H-i');

        return $baseName . ".pdf";
    }

    private function handleError($errorMessage)
    {
        http_response_code(500);
        header('Content-Type: application/json');
        echo json_encode([
            'success' => false,
            'error' => $errorMessage
        ]);
        exit;
    }
}
