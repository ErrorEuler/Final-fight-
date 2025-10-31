<?php
require_once __DIR__ . '/../../vendor/autoload.php';

use Dompdf\Dompdf;
use Dompdf\Options;

class PdfService
{
    private $dompdf;
    private $defaultOptions;

    public function __construct()
    {
        $this->defaultOptions = new Options();
        $this->defaultOptions->set([
            'defaultFont' => 'Helvetica',
            'isHtml5ParserEnabled' => true,
            'isRemoteEnabled' => true,
            'isPhpEnabled' => true,
            'tempDir' => __DIR__ . '/../tmp/',
            'fontDir' => __DIR__ . '/../fonts/',
            'fontCache' => __DIR__ . '/../fonts/',
            'chroot' => realpath(__DIR__ . '/../'),
        ]);

        $this->dompdf = new Dompdf($this->defaultOptions);
    }

    /**
     * Generate activity report PDF
     */
    public function generateActivityReport($activities, $filters = [], $universityName = "University")
    {
        try {
            $html = $this->generateActivityReportHtml($activities, $filters, $universityName);

            $this->dompdf->loadHtml($html);
            $this->dompdf->setPaper('A4', 'portrait');
            $this->dompdf->render();

            return $this->dompdf->output();
        } catch (Exception $e) {
            throw new Exception("PDF Generation failed: " . $e->getMessage());
        }
    }

    /**
     * Generate detailed activity report with charts
     */
    public function generateDetailedReport($activities, $stats, $filters = [], $universityName = "University")
    {
        try {
            $html = $this->generateDetailedReportHtml($activities, $stats, $filters, $universityName);

            $this->dompdf->loadHtml($html);
            $this->dompdf->setPaper('A4', 'landscape');
            $this->dompdf->render();

            return $this->dompdf->output();
        } catch (Exception $e) {
            throw new Exception("Detailed PDF Generation failed: " . $e->getMessage());
        }
    }

    /**
     * Generate HTML for activity report
     */
    private function generateActivityReportHtml($activities, $filters, $universityName)
    {
        $filterDescription = $this->getFilterDescription($filters);
        $currentDate = date('F j, Y g:i A');

        ob_start();
?>
        <!DOCTYPE html>
        <html>

        <head>
            <meta charset="UTF-8">
            <title>Activity Report - <?php echo $universityName; ?></title>
            <style>
                body {
                    font-family: DejaVu Sans, Helvetica, Arial, sans-serif;
                    margin: 0;
                    padding: 20px;
                    color: #333;
                    font-size: 12px;
                    line-height: 1.4;
                }

                .header {
                    text-align: center;
                    border-bottom: 3px solid #2c3e50;
                    padding-bottom: 15px;
                    margin-bottom: 20px;
                }

                .university-name {
                    font-size: 24px;
                    font-weight: bold;
                    color: #2c3e50;
                    margin-bottom: 5px;
                }

                .report-title {
                    font-size: 18px;
                    color: #34495e;
                    margin-bottom: 10px;
                }

                .report-meta {
                    font-size: 11px;
                    color: #7f8c8d;
                    margin-bottom: 5px;
                }

                .summary-section {
                    background: #f8f9fa;
                    padding: 15px;
                    border-radius: 5px;
                    margin-bottom: 20px;
                    border-left: 4px solid #3498db;
                }

                .summary-grid {
                    display: grid;
                    grid-template-columns: repeat(4, 1fr);
                    gap: 10px;
                    margin-bottom: 15px;
                }

                .summary-item {
                    text-align: center;
                    padding: 10px;
                    background: white;
                    border-radius: 3px;
                    border: 1px solid #ddd;
                }

                .summary-number {
                    font-size: 18px;
                    font-weight: bold;
                    color: #2c3e50;
                }

                .summary-label {
                    font-size: 10px;
                    color: #7f8c8d;
                    margin-top: 5px;
                }

                .activity-table {
                    width: 100%;
                    border-collapse: collapse;
                    margin-top: 15px;
                    font-size: 10px;
                }

                .activity-table th {
                    background-color: #34495e;
                    color: white;
                    padding: 8px;
                    text-align: left;
                    font-weight: bold;
                }

                .activity-table td {
                    padding: 8px;
                    border-bottom: 1px solid #ddd;
                }

                .activity-table tr:nth-child(even) {
                    background-color: #f8f9fa;
                }

                .action-type {
                    padding: 2px 6px;
                    border-radius: 3px;
                    font-size: 9px;
                    font-weight: bold;
                }

                .action-login {
                    background: #d4edda;
                    color: #155724;
                }

                .action-logout {
                    background: #f8d7da;
                    color: #721c24;
                }

                .action-create {
                    background: #d1ecf1;
                    color: #0c5460;
                }

                .action-update {
                    background: #fff3cd;
                    color: #856404;
                }

                .action-delete {
                    background: #f8d7da;
                    color: #721c24;
                }

                .action-system {
                    background: #e2e3e5;
                    color: #383d41;
                }

                .footer {
                    margin-top: 30px;
                    padding-top: 15px;
                    border-top: 1px solid #ddd;
                    text-align: center;
                    font-size: 10px;
                    color: #7f8c8d;
                }

                .page-break {
                    page-break-before: always;
                }
            </style>
        </head>

        <body>
            <div class="header">
                <div class="university-name"><?php echo htmlspecialchars($universityName); ?></div>
                <div class="report-title">ACTIVITY MONITORING REPORT</div>
                <div class="report-meta">
                    Generated on: <?php echo $currentDate; ?><br>
                    <?php echo $filterDescription; ?>
                </div>
            </div>

            <div class="summary-section">
                <div class="summary-grid">
                    <div class="summary-item">
                        <div class="summary-number"><?php echo count($activities); ?></div>
                        <div class="summary-label">TOTAL ACTIVITIES</div>
                    </div>
                    <div class="summary-item">
                        <div class="summary-number"><?php echo $this->countUniqueUsers($activities); ?></div>
                        <div class="summary-label">ACTIVE USERS</div>
                    </div>
                    <div class="summary-item">
                        <div class="summary-number"><?php echo $this->countTodayActivities($activities); ?></div>
                        <div class="summary-label">TODAY'S ACTIVITIES</div>
                    </div>
                    <div class="summary-item">
                        <div class="summary-number"><?php echo $this->countActionTypes($activities); ?></div>
                        <div class="summary-label">ACTION TYPES</div>
                    </div>
                </div>
            </div>

            <table class="activity-table">
                <thead>
                    <tr>
                        <th width="15%">Date & Time</th>
                        <th width="15%">User</th>
                        <th width="15%">Department</th>
                        <th width="15%">College</th>
                        <th width="10%">Action Type</th>
                        <th width="30%">Description</th>
                    </tr>
                </thead>
                <tbody>
                    <?php foreach ($activities as $activity): ?>
                        <tr>
                            <td><?php echo date('M j, Y H:i', strtotime($activity['created_at'])); ?></td>
                            <td><?php echo htmlspecialchars($activity['first_name'] . ' ' . $activity['last_name']); ?></td>
                            <td><?php echo htmlspecialchars($activity['department_name']); ?></td>
                            <td><?php echo htmlspecialchars($activity['college_name']); ?></td>
                            <td>
                                <span class="action-type action-<?php echo $activity['action_type']; ?>">
                                    <?php echo strtoupper($activity['action_type']); ?>
                                </span>
                            </td>
                            <td><?php echo htmlspecialchars($activity['action_description']); ?></td>
                        </tr>
                    <?php endforeach; ?>
                </tbody>
            </table>

            <div class="footer">
                <p>Confidential Activity Report - Generated by University Activity Monitoring System</p>
                <p>Page 1 of 1</p>
            </div>
        </body>

        </html>
    <?php
        return ob_get_clean();
    }

    /**
     * Generate HTML for detailed report
     */
    private function generateDetailedReportHtml($activities, $stats, $filters, $universityName)
    {
        // Similar to above but with more detailed statistics and charts
        // You can add charts using embedded SVG or simple HTML tables
        ob_start();
    ?>
        <!DOCTYPE html>
        <html>

        <head>
            <meta charset="UTF-8">
            <title>Detailed Activity Report - <?php echo $universityName; ?></title>
            <style>
                /* More comprehensive styles for detailed report */
                body {
                    font-family: DejaVu Sans, Helvetica, Arial, sans-serif;
                    margin: 0;
                    padding: 15px;
                }

                .section {
                    margin-bottom: 25px;
                }

                .section-title {
                    background: #34495e;
                    color: white;
                    padding: 8px 12px;
                    font-size: 14px;
                    margin-bottom: 10px;
                    border-radius: 3px;
                }

                .stats-grid {
                    display: grid;
                    grid-template-columns: repeat(3, 1fr);
                    gap: 10px;
                    margin-bottom: 15px;
                }

                /* Add more styles as needed */
            </style>
        </head>

        <body>
            <!-- Detailed report content -->
            <div class="header">
                <div style="text-align: center; border-bottom: 3px solid #2c3e50; padding-bottom: 15px;">
                    <div style="font-size: 24px; font-weight: bold; color: #2c3e50;">
                        <?php echo htmlspecialchars($universityName); ?>
                    </div>
                    <div style="font-size: 18px; color: #34495e;">DETAILED ACTIVITY ANALYSIS REPORT</div>
                </div>
            </div>

            <div class="section">
                <div class="section-title">EXECUTIVE SUMMARY</div>
                <div class="stats-grid">
                    <!-- Add detailed statistics here -->
                </div>
            </div>

            <!-- Add more sections as needed -->
        </body>

        </html>
<?php
        return ob_get_clean();
    }

    /**
     * Helper methods
     */
    private function getFilterDescription($filters)
    {
        if (empty($filters) || (isset($filters['dateRange']) && $filters['dateRange'] === 'all')) {
            return "All Activities";
        }

        $descriptions = [];
        if (isset($filters['dateRange']) && $filters['dateRange'] !== 'all') {
            $descriptions[] = "Period: " . ucfirst($filters['dateRange']);
        }
        if (isset($filters['college']) && $filters['college'] !== 'all') {
            $descriptions[] = "College: " . $filters['college'];
        }
        if (isset($filters['department']) && $filters['department'] !== 'all') {
            $descriptions[] = "Department: " . $filters['department'];
        }
        if (isset($filters['actionType']) && $filters['actionType'] !== 'all') {
            $descriptions[] = "Action Type: " . ucfirst($filters['actionType']);
        }

        return implode(' | ', $descriptions);
    }

    private function countUniqueUsers($activities)
    {
        $users = array_unique(array_map(function ($activity) {
            return $activity['first_name'] . ' ' . $activity['last_name'];
        }, $activities));
        return count($users);
    }

    private function countTodayActivities($activities)
    {
        $today = date('Y-m-d');
        return count(array_filter($activities, function ($activity) use ($today) {
            return date('Y-m-d', strtotime($activity['created_at'])) === $today;
        }));
    }

    private function countActionTypes($activities)
    {
        $types = array_unique(array_column($activities, 'action_type'));
        return count($types);
    }

    /**
     * Save PDF to file
     */
    public function saveToFile($pdfData, $filename)
    {
        $directory = __DIR__ . '/../reports/';
        if (!is_dir($directory)) {
            mkdir($directory, 0755, true);
        }

        $filepath = $directory . $filename;
        file_put_contents($filepath, $pdfData);

        return $filepath;
    }

    /**
     * Send PDF as download
     */
    public function sendAsDownload($pdfData, $filename = 'activity_report.pdf')
    {
        header('Content-Type: application/pdf');
        header('Content-Disposition: attachment; filename="' . $filename . '"');
        header('Content-Length: ' . strlen($pdfData));
        echo $pdfData;
        exit;
    }

    /**
     * Output PDF to browser
     */
    public function outputToBrowser($pdfData, $filename = 'activity_report.pdf')
    {
        header('Content-Type: application/pdf');
        header('Content-Disposition: inline; filename="' . $filename . '"');
        echo $pdfData;
        exit;
    }
}
?>