<?php
require_once __DIR__ . '/../config/database.php';
require_once __DIR__ . '/../../vendor/autoload.php';

// Make sure to install PhpSpreadsheet via Composer
use PhpOffice\PhpSpreadsheet\Spreadsheet;
use PhpOffice\PhpSpreadsheet\Writer\Xlsx;
use PhpOffice\PhpSpreadsheet\Style\Alignment;
class SchedulingService
{
    private $conn;
    private $db;

    public function __construct($conn)
    {
        $this->conn = $conn;
        $this->db = (new Database())->connect();
        $this->db->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
    }

    public function generateOfficialPDF($schedules, $semesterName, $collegeName, $facultyData, $facultyName)
    {
       
        $pdf = new \TCPDF('L', 'mm', 'A4', true, 'UTF-8', false);

        $pdf->SetCreator('PRMSU ACSS System');
        $pdf->SetAuthor('PRMSU');
        $pdf->SetTitle('Faculty Teaching Load - ' . $semesterName);
        $pdf->SetSubject('Official Teaching Load Document');

        // Set margins to match the print layout exactly
        $pdf->SetMargins(10, 10, 10);
        $pdf->SetHeaderMargin(0);
        $pdf->SetFooterMargin(0);
        $pdf->SetAutoPageBreak(TRUE, 10);

        $pdf->setPrintHeader(false);
        $pdf->setPrintFooter(false);
        $pdf->AddPage();

        // Header with logo
        $logoPath = __DIR__ . '/logo/main_logo/PRMSUlogo.png';
        if (!file_exists($logoPath)) {
            error_log('Logo file not found: ' . $logoPath);
        }
        if (file_exists($logoPath)) {
            $pdf->Image($logoPath, 15, 12, 20, '', 'PNG', '', 'T', false, 300, '', false, false, 0, false, false, false);
        }

        // Header content
        $headerHtml = '
    <table cellpadding="0" cellspacing="0" border="0" style="width: 100%;">
        <tr>
            <td style="width: 15%;"></td>
            <td style="width: 70%; text-align: center;">
                <div style="font-size: 8px; margin-bottom: 1px;">Republic of the Philippines</div>
                <div style="font-size: 10px; font-weight: bold; margin-bottom: 1px;">PRESIDENT RAMON MAGSAYSAY STATE UNIVERSITY</div>
                <div style="font-size: 6px; font-style: italic; margin-bottom: 2px;">(formerly Ramon Magsaysay Technological University)</div>
                <div style="font-size: 7px; font-weight: bold; margin-bottom: 1px;">Iba, Zambales</div>
                <div style="font-size: 12px; font-weight: bold; margin-top: 3px;">PROGRAM CHAIR TEACHING LOAD</div>
                <div style="font-size: 9px; margin-top: 1px;">' . htmlspecialchars($semesterName) . '</div>
            </td>
            <td style="width: 15%;"></td>
        </tr>
    </table>';

        $pdf->writeHTML($headerHtml, true, false, true, false, '');
        $pdf->Ln(8);

        // Calculate how many pages we need
        $schedulesPerPage = 15; // Adjust based on your layout
        $totalSchedules = count($schedules);
        $totalPages = ceil($totalSchedules / $schedulesPerPage);

        for ($page = 0; $page < $totalPages; $page++) {
            if ($page > 0) {
                $pdf->AddPage();
            }

            $startIndex = $page * $schedulesPerPage;
            $endIndex = min(($page + 1) * $schedulesPerPage, $totalSchedules);
            $pageSchedules = array_slice($schedules, $startIndex, $schedulesPerPage);

            // Main table structure
            $tableHtml = '
        <table border="1" cellpadding="3" cellspacing="0" style="border-collapse: collapse; width: 100%; font-size: 7px; table-layout: fixed;">
            <colgroup>
                <col style="width: 25%">
                <col style="width: 1%">
                <col style="width: 6%">
                <col style="width: 4%">
                <col style="width: 19%">
                <col style="width: 3%">
                <col style="width: 3%">
                <col style="width: 3%">
                <col style="width: 3%">
                <col style="width: 7%">
                <col style="width: 9%">
                <col style="width: 5%">
            </colgroup>
            <thead>
                <tr>
                    <td rowspan="3" style="border: 1px solid #000; padding: 4px; vertical-align: top;">
                        <p style="margin: 2px 0;"><strong>Campus :</strong> Main Campus</p>
                        <p style="margin: 2px 0;"><strong>Address :</strong> Iba</p>
                        <p style="margin: 2px 0;"><strong>College :</strong> ' . htmlspecialchars($collegeName) . '</p>
                    </td>
                    <td rowspan="' . (count($pageSchedules) + 20) . '" style="border: 1px solid #000; padding: 0; width: 1px;"></td>
                    <td rowspan="3" style="border: 1px solid #000; padding: 2px; text-align: center; font-weight: bold;">Time</td>
                    <td rowspan="3" style="border: 1px solid #000; padding: 2px; text-align: center; font-weight: bold;">Day/s</td>
                    <td rowspan="3" style="border: 1px solid #000; padding: 2px; text-align: center; font-weight: bold;">Course Code and Title</td>
                    <td colspan="4" style="border: 1px solid #000; padding: 2px; text-align: center; font-weight: bold;">No. of Units/Hrs.</td>
                    <td rowspan="3" style="border: 1px solid #000; padding: 2px; text-align: center; font-weight: bold;">Room</td>
                    <td rowspan="3" style="border: 1px solid #000; padding: 2px; text-align: center; font-weight: bold;">Course/Yr./Sec.</td>
                    <td rowspan="3" style="border: 1px solid #000; padding: 2px; text-align: center; font-weight: bold;">No. of students</td>
                </tr>
                <tr>
                    <td colspan="2" style="border: 1px solid #000; padding: 2px; text-align: center; font-weight: bold;">Lec.</td>
                    <td colspan="2" style="border: 1px solid #000; padding: 2px; text-align: center; font-weight: bold;">Lab./RLE</td>
                </tr>
                <tr>
                    <td style="border: 1px solid #000; padding: 2px; text-align: center; font-weight: bold;">Units</td>
                    <td style="border: 1px solid #000; padding: 2px; text-align: center; font-weight: bold;">Hrs.</td>
                    <td style="border: 1px solid #000; padding: 2px; text-align: center; font-weight: bold;">Units</td>
                    <td style="border: 1px solid #000; padding: 2px; text-align: center; font-weight: bold;">Hrs.</td>
                </tr>
            </thead>
            <tbody>';

            // Add schedule rows for this page
            foreach ($pageSchedules as $index => $schedule) {
                $timeRange = substr($schedule['start_time'], 0, 5) . '-' . substr($schedule['end_time'], 0, 5);
                $courseInfo = htmlspecialchars($schedule['course_code'] . ' ' . $schedule['course_name']);
                $sectionDetail = ($schedule['year_level'] ?? '1') . '/' . $schedule['section_name'];

                $lecUnits = $schedule['schedule_type'] === 'Lecture' ? ($schedule['units'] ?? '3') : '-';
                $lecHours = $schedule['schedule_type'] === 'Lecture' ? ($schedule['duration_hours'] ?? '3') : '-';
                $labUnits = $schedule['schedule_type'] === 'Laboratory' ? ($schedule['units'] ?? '3') : '-';
                $labHours = $schedule['schedule_type'] === 'Laboratory' ? ($schedule['duration_hours'] ?? '3') : '-';

                $tableHtml .= '
            <tr>
                ' . ($index === 0 ? '<td rowspan="' . count($pageSchedules) . '" style="border: 1px solid #000; padding: 4px; vertical-align: top; font-weight: bold;">' . strtoupper(htmlspecialchars($facultyName)) . '</td>' : '') . '
                <td style="border: 1px solid #000; padding: 2px; text-align: center;">' . $timeRange . '</td>
                <td style="border: 1px solid #000; padding: 2px; text-align: center;">' . htmlspecialchars($schedule['day_of_week']) . '</td>
                <td style="border: 1px solid #000; padding: 2px;">' . $courseInfo . '</td>
                <td style="border: 1px solid #000; padding: 2px; text-align: center;">' . $lecUnits . '</td>
                <td style="border: 1px solid #000; padding: 2px; text-align: center;">' . $lecHours . '</td>
                <td style="border: 1px solid #000; padding: 2px; text-align: center;">' . $labUnits . '</td>
                <td style="border: 1px solid #000; padding: 2px; text-align: center;">' . $labHours . '</td>
                <td style="border: 1px solid #000; padding: 2px; text-align: center;">' . htmlspecialchars($schedule['room_name'] ?? 'TBD') . '</td>
                <td style="border: 1px solid #000; padding: 2px; text-align: center;">' . $sectionDetail . '</td>
                <td style="border: 1px solid #000; padding: 2px; text-align: center;">' . ($schedule['student_count'] ?? '-') . '</td>
            </tr>';
            }

            // Add faculty information section only on the first page
            if ($page === 0) {
                $facultyInfoContent = '
            <p style="margin: 2px 0;"><strong>Employment Status :</strong> ' . htmlspecialchars($facultyData['employment_type']) . '</p>
            <p style="margin: 2px 0;"><strong>VSL :</strong> ' . ($facultyData['classification'] === 'VSL' ? '☑' : '☐') . 'Yes ' . ($facultyData['classification'] === 'TL' ? '☑' : '☐') . 'No</p>
            <p style="margin: 2px 0;"><strong>Academic Rank :</strong> ' . htmlspecialchars($facultyData['academic_rank']) . '</p>
            <p style="margin: 2px 0;"><strong>Bachelor\'s Degree :</strong> ' . htmlspecialchars($facultyData['bachelor_degree']) . '</p>
            <p style="margin: 2px 0;"><strong>Master\'s Degree :</strong> ' . htmlspecialchars($facultyData['master_degree']) . '</p>
            <p style="margin: 2px 0;"><strong>Doctorate Degree :</strong> ' . htmlspecialchars($facultyData['doctorate_degree']) . '</p>
            <p style="margin: 2px 0;"><strong>Post Doctorate Degree :</strong> ' . htmlspecialchars($facultyData['post_doctorate_degree']) . '</p>
            <p style="margin: 2px 0;"><strong>Designation :</strong> ' . htmlspecialchars($facultyData['designation']) . '</p>
            <p style="margin: 2px 0;"><strong>Schedule Equiv. Teaching Load (ETL) :</strong> ' . number_format($facultyData['equiv_teaching_load'], 2) . '</p>
            <p style="margin: 2px 0;"><strong>Total Lecture Hours :</strong> ' . number_format($facultyData['total_lecture_hours'], 2) . '</p>
            <p style="margin: 2px 0;"><strong>Total Laboratory Hours :</strong> ' . number_format($facultyData['total_laboratory_hours'], 2) . '</p>
            <p style="margin: 2px 0;"><strong>Total Lab Hours x 0.75 :</strong> ' . number_format($facultyData['total_laboratory_hours_x075'], 2) . '</p>
            <p style="margin: 2px 0;"><strong>No. of Preparation :</strong> ' . $facultyData['no_of_preparation'] . '</p>
            <p style="margin: 2px 0;"><strong>Advisory Class :</strong> ' . htmlspecialchars($facultyData['advisory_class']) . '</p>
            <p style="margin: 2px 0;"><strong>Equiv. Units for Prep :</strong> 0</p>
            <p style="margin: 2px 0;"><strong>Actual Teaching Load (ATL) :</strong> ' . number_format($facultyData['actual_teaching_load'], 2) . '</p>
            <p style="margin: 2px 0;"><strong>Total Working Load (ETL+ATL) :</strong> ' . number_format($facultyData['total_working_load'], 2) . '</p>
            <p style="margin: 2px 0;"><strong>Excess (24 Hours) :</strong> ' . number_format($facultyData['excess_hours'], 2) . '</p>';

                $tableHtml .= '
            <tr>
                <td rowspan="18" style="border: 1px solid #000; padding: 6px; vertical-align: top;">
                    ' . $facultyInfoContent . '
                </td>';

                // Add empty cells for faculty info section
                for ($i = 0; $i < 18; $i++) {
                    if ($i > 0) {
                        $tableHtml .= '<tr>';
                    }
                    $tableHtml .= '
                    <td style="border: 1px solid #000; padding: 2px;">&nbsp;</td>
                    <td style="border: 1px solid #000; padding: 2px;">&nbsp;</td>
                    <td style="border: 1px solid #000; padding: 2px;">&nbsp;</td>
                    <td style="border: 1px solid #000; padding: 2px;">&nbsp;</td>
                    <td style="border: 1px solid #000; padding: 2px;">&nbsp;</td>
                    <td style="border: 1px solid #000; padding: 2px;">&nbsp;</td>
                    <td style="border: 1px solid #000; padding: 2px;">&nbsp;</td>
                    <td style="border: 1px solid #000; padding: 2px;">&nbsp;</td>
                    <td style="border: 1px solid #000; padding: 2px;">&nbsp;</td>
                    <td style="border: 1px solid #000; padding: 2px;">&nbsp;</td>
                </tr>';
                }
            }

            $tableHtml .= '</tbody></table>';
            $pdf->writeHTML($tableHtml, true, false, true, false, '');

            // Add signature section only on the last page
            if ($page === $totalPages - 1) {
                $pdf->Ln(5);
                $signatureHtml = '
            <table border="1" cellpadding="3" cellspacing="0" style="border-collapse: collapse; width: 100%; font-size: 7px;">
                <tr>
                    <td style="border: 1px solid #000; padding: 3px; font-weight: bold; text-align: center; width: 33.33%;">Prepared:</td>
                    <td style="border: 1px solid #000; padding: 3px; font-weight: bold; text-align: center; width: 33.33%;">Recommending Approval:</td>
                    <td style="border: 1px solid #000; padding: 3px; font-weight: bold; text-align: center; width: 33.34%;">Approved</td>
                </tr>
                <tr>
                    <td style="border: 1px solid #000; padding: 20px 8px 8px 8px; text-align: center; vertical-align: bottom;">
                        <p style="margin: 0; font-weight: bold;">MENCHIE A. DELA CRUZ, Ph.D.</p>
                        <p style="margin: 0;">Dean, CCIT</p>
                    </td>
                    <td style="border: 1px solid #000; padding: 20px 8px 8px 8px; text-align: center; vertical-align: bottom;">
                        <p style="margin: 0; font-weight: bold;">NEMIA M. GALANG, Ph.D.</p>
                        <p style="margin: 0;">Director for Instruction</p>
                    </td>
                    <td style="border: 1px solid #000; padding: 20px 8px 8px 8px; text-align: center; vertical-align: bottom;">
                        <p style="margin: 0; font-weight: bold;">LILIAN F. UY, Ed.D.</p>
                        <p style="margin: 0;">Vice President for Academic Affairs</p>
                    </td>
                </tr>
            </table>';

                $pdf->writeHTML($signatureHtml, true, false, true, false, '');

                // Footer
                $pdf->Ln(5);
                $footerHtml = '
            <div style="font-size: 6px; color: #666;">
                <p style="margin: 2px 0;">Reference no. PRMSU-ASA-COMSP18(1o)</p>
                <p style="margin: 2px 0;">Effectivity date: May 04, 2021</p>
                <p style="margin: 2px 0;">Revision no. 00</p>
            </div>';

                $pdf->writeHTML($footerHtml, true, false, true, false, '');
            }
        }

        $filename = 'Teaching_Load_' . str_replace(' ', '_', $facultyName) . '_' . date('Ymd') . '.pdf';
        $pdf->Output($filename, 'D');
        exit;
    }

    public function generateOfficialExcel($schedules, $semesterName, $collegeName, $facultyData, $facultyName)
    {
        $spreadsheet = new Spreadsheet();
        $sheet = $spreadsheet->getActiveSheet();

        // Set document properties
        $spreadsheet->getProperties()
            ->setCreator('PRMSU ACSS System')
            ->setTitle('Faculty Teaching Load - ' . $semesterName)
            ->setSubject('Official Teaching Load Document');

        // Set page setup for landscape
        $sheet->getPageSetup()
            ->setOrientation(\PhpOffice\PhpSpreadsheet\Worksheet\PageSetup::ORIENTATION_LANDSCAPE)
            ->setPaperSize(\PhpOffice\PhpSpreadsheet\Worksheet\PageSetup::PAPERSIZE_A4);

        // Set column widths to match PDF layout
        $sheet->getColumnDimension('A')->setWidth(25);
        $sheet->getColumnDimension('B')->setWidth(1);
        $sheet->getColumnDimension('C')->setWidth(6);
        $sheet->getColumnDimension('D')->setWidth(4);
        $sheet->getColumnDimension('E')->setWidth(19);
        $sheet->getColumnDimension('F')->setWidth(3);
        $sheet->getColumnDimension('G')->setWidth(3);
        $sheet->getColumnDimension('H')->setWidth(3);
        $sheet->getColumnDimension('I')->setWidth(3);
        $sheet->getColumnDimension('J')->setWidth(7);
        $sheet->getColumnDimension('K')->setWidth(9);
        $sheet->getColumnDimension('L')->setWidth(5);

        // Header section
        $sheet->mergeCells('A1:L1');
        $sheet->setCellValue('A1', 'Republic of the Philippines');
        $sheet->mergeCells('A2:L2');
        $sheet->setCellValue('A2', 'PRESIDENT RAMON MAGSAYSAY STATE UNIVERSITY');
        $sheet->mergeCells('A3:L3');
        $sheet->setCellValue('A3', '(formerly Ramon Magsaysay Technological University)');
        $sheet->mergeCells('A4:L4');
        $sheet->setCellValue('A4', 'Iba, Zambales');
        $sheet->mergeCells('A5:L5');
        $sheet->setCellValue('A5', 'PROGRAM CHAIR TEACHING LOAD');
        $sheet->mergeCells('A6:L6');
        $sheet->setCellValue('A6', $semesterName);

        // Style header
        $headerStyle = [
            'font' => ['bold' => true],
            'alignment' => ['horizontal' => Alignment::HORIZONTAL_CENTER]
        ];
        $sheet->getStyle('A1:L6')->applyFromArray($headerStyle);
        $sheet->getStyle('A2:L2')->getFont()->setSize(12);
        $sheet->getStyle('A5:L5')->getFont()->setSize(14);

        // College info
        $sheet->setCellValue('A8', 'Campus:');
        $sheet->setCellValue('B8', 'Main Campus');
        $sheet->setCellValue('A9', 'Address:');
        $sheet->setCellValue('B9', 'Iba');
        $sheet->setCellValue('A10', 'College:');
        $sheet->setCellValue('B10', $collegeName);

        // Table headers
        $sheet->mergeCells('A12:A' . (12 + count($schedules) - 1));
        $sheet->setCellValue('A12', strtoupper($facultyName));
        $sheet->getStyle('A12')->getAlignment()->setVertical(Alignment::VERTICAL_TOP);

        // Vertical separator
        for ($i = 12; $i < 12 + count($schedules) + 20; $i++) {
            $sheet->setCellValue('B' . $i, '');
        }

        // Main headers
        $sheet->mergeCells('C12:C14');
        $sheet->setCellValue('C12', 'Time');
        $sheet->mergeCells('D12:D14');
        $sheet->setCellValue('D12', 'Day/s');
        $sheet->mergeCells('E12:E14');
        $sheet->setCellValue('E12', 'Course Code and Title');

        // Units/Hrs header
        $sheet->mergeCells('F12:I12');
        $sheet->setCellValue('F12', 'No. of Units/Hrs.');
        $sheet->mergeCells('F13:G13');
        $sheet->setCellValue('F13', 'Lec.');
        $sheet->mergeCells('H13:I13');
        $sheet->setCellValue('H13', 'Lab./RLE');
        $sheet->setCellValue('F14', 'Units');
        $sheet->setCellValue('G14', 'Hrs.');
        $sheet->setCellValue('H14', 'Units');
        $sheet->setCellValue('I14', 'Hrs.');

        $sheet->mergeCells('J12:J14');
        $sheet->setCellValue('J12', 'Room');
        $sheet->mergeCells('K12:K14');
        $sheet->setCellValue('K12', 'Course/Yr./Sec.');
        $sheet->mergeCells('L12:L14');
        $sheet->setCellValue('L12', 'No. of students');

        // Style table headers
        $tableHeaderStyle = [
            'font' => ['bold' => true, 'size' => 8],
            'alignment' => ['horizontal' => Alignment::HORIZONTAL_CENTER, 'vertical' => Alignment::VERTICAL_CENTER],
            'borders' => ['allBorders' => ['borderStyle' => \PhpOffice\PhpSpreadsheet\Style\Border::BORDER_THIN]]
        ];
        $sheet->getStyle('A12:L14')->applyFromArray($tableHeaderStyle);

        // Add ALL schedule data
        $currentRow = 15;

        foreach ($schedules as $schedule) {
            $timeRange = substr($schedule['start_time'], 0, 5) . '-' . substr($schedule['end_time'], 0, 5);
            $courseInfo = $schedule['course_code'] . ' ' . $schedule['course_name'];
            $sectionDetail = ($schedule['year_level'] ?? '1') . '/' . $schedule['section_name'];

            $lecUnits = $schedule['schedule_type'] === 'Lecture' ? ($schedule['units'] ?? '3') : '-';
            $lecHours = $schedule['schedule_type'] === 'Lecture' ? ($schedule['duration_hours'] ?? '3') : '-';
            $labUnits = $schedule['schedule_type'] === 'Laboratory' ? ($schedule['units'] ?? '3') : '-';
            $labHours = $schedule['schedule_type'] === 'Laboratory' ? ($schedule['duration_hours'] ?? '3') : '-';

            $sheet->setCellValue('C' . $currentRow, $timeRange);
            $sheet->setCellValue('D' . $currentRow, $schedule['day_of_week']);
            $sheet->setCellValue('E' . $currentRow, $courseInfo);
            $sheet->setCellValue('F' . $currentRow, $lecUnits);
            $sheet->setCellValue('G' . $currentRow, $lecHours);
            $sheet->setCellValue('H' . $currentRow, $labUnits);
            $sheet->setCellValue('I' . $currentRow, $labHours);
            $sheet->setCellValue('J' . $currentRow, $schedule['room_name'] ?? 'TBD');
            $sheet->setCellValue('K' . $currentRow, $sectionDetail);
            $sheet->setCellValue('L' . $currentRow, $schedule['student_count'] ?? '-');

            $currentRow++;
        }

        // Apply borders to all schedule cells
        $lastScheduleRow = 14 + count($schedules);
        $sheet->getStyle('A12:L' . $lastScheduleRow)->getBorders()->getAllBorders()->setBorderStyle(\PhpOffice\PhpSpreadsheet\Style\Border::BORDER_THIN);

        // Set font size for all cells
        $sheet->getStyle('A12:L' . $lastScheduleRow)->getFont()->setSize(8);

        // Center align specific columns
        $centerAlignColumns = ['C', 'D', 'F', 'G', 'H', 'I', 'J', 'K', 'L'];
        foreach ($centerAlignColumns as $col) {
            $sheet->getStyle($col . '15:' . $col . $lastScheduleRow)->getAlignment()->setHorizontal(Alignment::HORIZONTAL_CENTER);
        }

        // Set row heights
        for ($row = 15; $row <= $lastScheduleRow; $row++) {
            $sheet->getRowDimension($row)->setRowHeight(15);
        }

        // Add faculty information section
        $facultyInfoStartRow = $lastScheduleRow + 2;
        $sheet->mergeCells('A' . $facultyInfoStartRow . ':A' . ($facultyInfoStartRow + 17));
        $facultyInfo = [
            'Employment Status: ' . $facultyData['employment_type'],
            'VSL: ' . ($facultyData['classification'] === 'VSL' ? '☑Yes ☐No' : '☐Yes ☑No'),
            'Academic Rank: ' . $facultyData['academic_rank'],
            'Bachelor\'s Degree: ' . $facultyData['bachelor_degree'],
            'Master\'s Degree: ' . $facultyData['master_degree'],
            'Doctorate Degree: ' . $facultyData['doctorate_degree'],
            'Post Doctorate Degree: ' . $facultyData['post_doctorate_degree'],
            'Designation: ' . $facultyData['designation'],
            'Schedule Equiv. Teaching Load (ETL): ' . number_format($facultyData['equiv_teaching_load'], 2),
            'Total Lecture Hours: ' . number_format($facultyData['total_lecture_hours'], 2),
            'Total Laboratory Hours: ' . number_format($facultyData['total_laboratory_hours'], 2),
            'Total Lab Hours x 0.75: ' . number_format($facultyData['total_laboratory_hours_x075'], 2),
            'No. of Preparation: ' . $facultyData['no_of_preparation'],
            'Advisory Class: ' . $facultyData['advisory_class'],
            'Equiv. Units for Prep: 0',
            'Actual Teaching Load (ATL): ' . number_format($facultyData['actual_teaching_load'], 2),
            'Total Working Load (ETL+ATL): ' . number_format($facultyData['total_working_load'], 2),
            'Excess (24 Hours): ' . number_format($facultyData['excess_hours'], 2)
        ];

        $infoText = implode("\n", $facultyInfo);
        $sheet->setCellValue('A' . $facultyInfoStartRow, $infoText);
        $sheet->getStyle('A' . $facultyInfoStartRow)->getAlignment()->setVertical(Alignment::VERTICAL_TOP)->setWrapText(true);

        // Signature section
        $signatureRow = $facultyInfoStartRow + 20;
        $sheet->mergeCells('A' . $signatureRow . ':D' . $signatureRow);
        $sheet->setCellValue('A' . $signatureRow, 'Prepared:');
        $sheet->mergeCells('E' . $signatureRow . ':H' . $signatureRow);
        $sheet->setCellValue('E' . $signatureRow, 'Recommending Approval:');
        $sheet->mergeCells('I' . $signatureRow . ':L' . $signatureRow);
        $sheet->setCellValue('I' . $signatureRow, 'Approved:');

        $signatureRow++;
        $sheet->mergeCells('A' . $signatureRow . ':D' . ($signatureRow + 2));
        $sheet->setCellValue('A' . $signatureRow, "MENCHIE A. DELA CRUZ, Ph.D.\nDean, CCIT");
        $sheet->mergeCells('E' . $signatureRow . ':H' . ($signatureRow + 2));
        $sheet->setCellValue('E' . $signatureRow, "NEMIA M. GALANG, Ph.D.\nDirector for Instruction");
        $sheet->mergeCells('I' . $signatureRow . ':L' . ($signatureRow + 2));
        $sheet->setCellValue('I' . $signatureRow, "LILIAN F. UY, Ed.D.\nVice President for Academic Affairs");

        $sheet->getStyle('A' . ($signatureRow - 1) . ':L' . ($signatureRow + 2))->getFont()->setBold(true);
        $sheet->getStyle('A' . $signatureRow . ':L' . ($signatureRow + 2))->getAlignment()->setHorizontal(Alignment::HORIZONTAL_CENTER)->setVertical(Alignment::VERTICAL_CENTER)->setWrapText(true);

        // Footer
        $footerRow = $signatureRow + 4;
        $sheet->setCellValue('A' . $footerRow, 'Reference no. PRMSU-ASA-COMSP18(1o)');
        $sheet->setCellValue('A' . ($footerRow + 1), 'Effectivity date: May 04, 2021');
        $sheet->setCellValue('A' . ($footerRow + 2), 'Revision no. 00');
        $sheet->getStyle('A' . $footerRow . ':A' . ($footerRow + 2))->getFont()->setSize(6);
        $sheet->getStyle('A' . $footerRow . ':A' . ($footerRow + 2))->getFont()->getColor()->setRGB('666666');

        // Output the file
        $filename = 'Teaching_Load_' . str_replace(' ', '_', $facultyName) . '_' . date('Ymd') . '.xlsx';

        header('Content-Type: application/vnd.openxmlformats-officedocument.spreadsheetml.sheet');
        header('Content-Disposition: attachment;filename="' . $filename . '"');
        header('Cache-Control: max-age=0');

        $writer = new Xlsx($spreadsheet);
        $writer->save('php://output');
        exit;
    }

    public function generateOfficialPDFFaculty($schedules, $semesterName, $collegeName, $facultyData, $facultyName)
    {

        $pdf = new \TCPDF('L', 'mm', 'A4', true, 'UTF-8', false);

        $pdf->SetCreator('PRMSU ACSS System');
        $pdf->SetAuthor('PRMSU');
        $pdf->SetTitle('Faculty Teaching Load - ' . $semesterName);
        $pdf->SetSubject('Official Teaching Load Document');

        // Set margins to match the print layout exactly
        $pdf->SetMargins(10, 10, 10);
        $pdf->SetHeaderMargin(0);
        $pdf->SetFooterMargin(0);
        $pdf->SetAutoPageBreak(TRUE, 10);

        $pdf->setPrintHeader(false);
        $pdf->setPrintFooter(false);
        $pdf->AddPage();

        // Header with logo
        $logoPath = __DIR__ . '/logo/main_logo/PRMSUlogo.png';
        if (!file_exists($logoPath)) {
            error_log('Logo file not found: ' . $logoPath);
        }
        if (file_exists($logoPath)) {
            $pdf->Image($logoPath, 15, 12, 20, '', 'PNG', '', 'T', false, 300, '', false, false, 0, false, false, false);
        }

        // Header content
        $headerHtml = '
    <table cellpadding="0" cellspacing="0" border="0" style="width: 100%;">
        <tr>
            <td style="width: 15%;"></td>
            <td style="width: 70%; text-align: center;">
                <div style="font-size: 8px; margin-bottom: 1px;">Republic of the Philippines</div>
                <div style="font-size: 10px; font-weight: bold; margin-bottom: 1px;">PRESIDENT RAMON MAGSAYSAY STATE UNIVERSITY</div>
                <div style="font-size: 6px; font-style: italic; margin-bottom: 2px;">(formerly Ramon Magsaysay Technological University)</div>
                <div style="font-size: 7px; font-weight: bold; margin-bottom: 1px;">Iba, Zambales</div>
                <div style="font-size: 12px; font-weight: bold; margin-top: 3px;">FACULTY TEACHING LOAD</div>
                <div style="font-size: 9px; margin-top: 1px;">' . htmlspecialchars($semesterName) . '</div>
            </td>
            <td style="width: 15%;"></td>
        </tr>
    </table>';

        $pdf->writeHTML($headerHtml, true, false, true, false, '');
        $pdf->Ln(8);

        // Calculate how many pages we need
        $schedulesPerPage = 15; // Adjust based on your layout
        $totalSchedules = count($schedules);
        $totalPages = ceil($totalSchedules / $schedulesPerPage);

        for ($page = 0; $page < $totalPages; $page++) {
            if ($page > 0) {
                $pdf->AddPage();
            }

            $startIndex = $page * $schedulesPerPage;
            $endIndex = min(($page + 1) * $schedulesPerPage, $totalSchedules);
            $pageSchedules = array_slice($schedules, $startIndex, $schedulesPerPage);

            // Main table structure
            $tableHtml = '
        <table border="1" cellpadding="3" cellspacing="0" style="border-collapse: collapse; width: 100%; font-size: 7px; table-layout: fixed;">
            <colgroup>
                <col style="width: 25%">
                <col style="width: 1%">
                <col style="width: 6%">
                <col style="width: 4%">
                <col style="width: 19%">
                <col style="width: 3%">
                <col style="width: 3%">
                <col style="width: 3%">
                <col style="width: 3%">
                <col style="width: 7%">
                <col style="width: 9%">
                <col style="width: 5%">
            </colgroup>
            <thead>
                <tr>
                    <td rowspan="3" style="border: 1px solid #000; padding: 4px; vertical-align: top;">
                        <p style="margin: 2px 0;"><strong>Campus :</strong> Main Campus</p>
                        <p style="margin: 2px 0;"><strong>Address :</strong> Iba</p>
                        <p style="margin: 2px 0;"><strong>College :</strong> ' . htmlspecialchars($collegeName) . '</p>
                    </td>
                    <td rowspan="' . (count($pageSchedules) + 20) . '" style="border: 1px solid #000; padding: 0; width: 1px;"></td>
                    <td rowspan="3" style="border: 1px solid #000; padding: 2px; text-align: center; font-weight: bold;">Time</td>
                    <td rowspan="3" style="border: 1px solid #000; padding: 2px; text-align: center; font-weight: bold;">Day/s</td>
                    <td rowspan="3" style="border: 1px solid #000; padding: 2px; text-align: center; font-weight: bold;">Course Code and Title</td>
                    <td colspan="4" style="border: 1px solid #000; padding: 2px; text-align: center; font-weight: bold;">No. of Units/Hrs.</td>
                    <td rowspan="3" style="border: 1px solid #000; padding: 2px; text-align: center; font-weight: bold;">Room</td>
                    <td rowspan="3" style="border: 1px solid #000; padding: 2px; text-align: center; font-weight: bold;">Course/Yr./Sec.</td>
                    <td rowspan="3" style="border: 1px solid #000; padding: 2px; text-align: center; font-weight: bold;">No. of students</td>
                </tr>
                <tr>
                    <td colspan="2" style="border: 1px solid #000; padding: 2px; text-align: center; font-weight: bold;">Lec.</td>
                    <td colspan="2" style="border: 1px solid #000; padding: 2px; text-align: center; font-weight: bold;">Lab./RLE</td>
                </tr>
                <tr>
                    <td style="border: 1px solid #000; padding: 2px; text-align: center; font-weight: bold;">Units</td>
                    <td style="border: 1px solid #000; padding: 2px; text-align: center; font-weight: bold;">Hrs.</td>
                    <td style="border: 1px solid #000; padding: 2px; text-align: center; font-weight: bold;">Units</td>
                    <td style="border: 1px solid #000; padding: 2px; text-align: center; font-weight: bold;">Hrs.</td>
                </tr>
            </thead>
            <tbody>';

            // Add schedule rows for this page
            foreach ($pageSchedules as $index => $schedule) {
                $timeRange = substr($schedule['start_time'], 0, 5) . '-' . substr($schedule['end_time'], 0, 5);
                $courseInfo = htmlspecialchars($schedule['course_code'] . ' ' . $schedule['course_name']);
                $sectionDetail = ($schedule['year_level'] ?? '1') . '/' . $schedule['section_name'];

                $lecUnits = $schedule['schedule_type'] === 'Lecture' ? ($schedule['units'] ?? '3') : '-';
                $lecHours = $schedule['schedule_type'] === 'Lecture' ? ($schedule['duration_hours'] ?? '3') : '-';
                $labUnits = $schedule['schedule_type'] === 'Laboratory' ? ($schedule['units'] ?? '3') : '-';
                $labHours = $schedule['schedule_type'] === 'Laboratory' ? ($schedule['duration_hours'] ?? '3') : '-';

                $tableHtml .= '
            <tr>
                ' . ($index === 0 ? '<td rowspan="' . count($pageSchedules) . '" style="border: 1px solid #000; padding: 4px; vertical-align: top; font-weight: bold;">' . strtoupper(htmlspecialchars($facultyName)) . '</td>' : '') . '
                <td style="border: 1px solid #000; padding: 2px; text-align: center;">' . $timeRange . '</td>
                <td style="border: 1px solid #000; padding: 2px; text-align: center;">' . htmlspecialchars($schedule['day_of_week']) . '</td>
                <td style="border: 1px solid #000; padding: 2px;">' . $courseInfo . '</td>
                <td style="border: 1px solid #000; padding: 2px; text-align: center;">' . $lecUnits . '</td>
                <td style="border: 1px solid #000; padding: 2px; text-align: center;">' . $lecHours . '</td>
                <td style="border: 1px solid #000; padding: 2px; text-align: center;">' . $labUnits . '</td>
                <td style="border: 1px solid #000; padding: 2px; text-align: center;">' . $labHours . '</td>
                <td style="border: 1px solid #000; padding: 2px; text-align: center;">' . htmlspecialchars($schedule['room_name'] ?? 'TBD') . '</td>
                <td style="border: 1px solid #000; padding: 2px; text-align: center;">' . $sectionDetail . '</td>
                <td style="border: 1px solid #000; padding: 2px; text-align: center;">' . ($schedule['student_count'] ?? '-') . '</td>
            </tr>';
            }

            // Add faculty information section only on the first page
            if ($page === 0) {
                $facultyInfoContent = '
            <p style="margin: 2px 0;"><strong>Employment Status :</strong> ' . htmlspecialchars($facultyData['employment_type']) . '</p>
            <p style="margin: 2px 0;"><strong>VSL :</strong> ' . ($facultyData['classification'] === 'VSL' ? '☑' : '☐') . 'Yes ' . ($facultyData['classification'] === 'TL' ? '☑' : '☐') . 'No</p>
            <p style="margin: 2px 0;"><strong>Academic Rank :</strong> ' . htmlspecialchars($facultyData['academic_rank']) . '</p>
            <p style="margin: 2px 0;"><strong>Bachelor\'s Degree :</strong> ' . htmlspecialchars($facultyData['bachelor_degree']) . '</p>
            <p style="margin: 2px 0;"><strong>Master\'s Degree :</strong> ' . htmlspecialchars($facultyData['master_degree']) . '</p>
            <p style="margin: 2px 0;"><strong>Doctorate Degree :</strong> ' . htmlspecialchars($facultyData['doctorate_degree']) . '</p>
            <p style="margin: 2px 0;"><strong>Post Doctorate Degree :</strong> ' . htmlspecialchars($facultyData['post_doctorate_degree']) . '</p>
            <p style="margin: 2px 0;"><strong>Designation :</strong> ' . htmlspecialchars($facultyData['designation']) . '</p>
            <p style="margin: 2px 0;"><strong>Schedule Equiv. Teaching Load (ETL) :</strong> ' . number_format($facultyData['equiv_teaching_load'], 2) . '</p>
            <p style="margin: 2px 0;"><strong>Total Lecture Hours :</strong> ' . number_format($facultyData['total_lecture_hours'], 2) . '</p>
            <p style="margin: 2px 0;"><strong>Total Laboratory Hours :</strong> ' . number_format($facultyData['total_laboratory_hours'], 2) . '</p>
            <p style="margin: 2px 0;"><strong>Total Lab Hours x 0.75 :</strong> ' . number_format($facultyData['total_laboratory_hours_x075'], 2) . '</p>
            <p style="margin: 2px 0;"><strong>No. of Preparation :</strong> ' . $facultyData['no_of_preparation'] . '</p>
            <p style="margin: 2px 0;"><strong>Advisory Class :</strong> ' . htmlspecialchars($facultyData['advisory_class']) . '</p>
            <p style="margin: 2px 0;"><strong>Equiv. Units for Prep :</strong> 0</p>
            <p style="margin: 2px 0;"><strong>Actual Teaching Load (ATL) :</strong> ' . number_format($facultyData['actual_teaching_load'], 2) . '</p>
            <p style="margin: 2px 0;"><strong>Total Working Load (ETL+ATL) :</strong> ' . number_format($facultyData['total_working_load'], 2) . '</p>
            <p style="margin: 2px 0;"><strong>Excess (24 Hours) :</strong> ' . number_format($facultyData['excess_hours'], 2) . '</p>';

                $tableHtml .= '
            <tr>
                <td rowspan="18" style="border: 1px solid #000; padding: 6px; vertical-align: top;">
                    ' . $facultyInfoContent . '
                </td>';

                // Add empty cells for faculty info section
                for ($i = 0; $i < 18; $i++) {
                    if ($i > 0) {
                        $tableHtml .= '<tr>';
                    }
                    $tableHtml .= '
                    <td style="border: 1px solid #000; padding: 2px;">&nbsp;</td>
                    <td style="border: 1px solid #000; padding: 2px;">&nbsp;</td>
                    <td style="border: 1px solid #000; padding: 2px;">&nbsp;</td>
                    <td style="border: 1px solid #000; padding: 2px;">&nbsp;</td>
                    <td style="border: 1px solid #000; padding: 2px;">&nbsp;</td>
                    <td style="border: 1px solid #000; padding: 2px;">&nbsp;</td>
                    <td style="border: 1px solid #000; padding: 2px;">&nbsp;</td>
                    <td style="border: 1px solid #000; padding: 2px;">&nbsp;</td>
                    <td style="border: 1px solid #000; padding: 2px;">&nbsp;</td>
                    <td style="border: 1px solid #000; padding: 2px;">&nbsp;</td>
                </tr>';
                }
            }

            $tableHtml .= '</tbody></table>';
            $pdf->writeHTML($tableHtml, true, false, true, false, '');

            // Add signature section only on the last page
            if ($page === $totalPages - 1) {
                $pdf->Ln(5);
                $signatureHtml = '
            <table border="1" cellpadding="3" cellspacing="0" style="border-collapse: collapse; width: 100%; font-size: 7px;">
                <tr>
                    <td style="border: 1px solid #000; padding: 3px; font-weight: bold; text-align: center; width: 33.33%;">Prepared:</td>
                    <td style="border: 1px solid #000; padding: 3px; font-weight: bold; text-align: center; width: 33.33%;">Recommending Approval:</td>
                    <td style="border: 1px solid #000; padding: 3px; font-weight: bold; text-align: center; width: 33.34%;">Approved</td>
                </tr>
                <tr>
                    <td style="border: 1px solid #000; padding: 20px 8px 8px 8px; text-align: center; vertical-align: bottom;">
                        <p style="margin: 0; font-weight: bold;">MENCHIE A. DELA CRUZ, Ph.D.</p>
                        <p style="margin: 0;">Dean, CCIT</p>
                    </td>
                    <td style="border: 1px solid #000; padding: 20px 8px 8px 8px; text-align: center; vertical-align: bottom;">
                        <p style="margin: 0; font-weight: bold;">NEMIA M. GALANG, Ph.D.</p>
                        <p style="margin: 0;">Director for Instruction</p>
                    </td>
                    <td style="border: 1px solid #000; padding: 20px 8px 8px 8px; text-align: center; vertical-align: bottom;">
                        <p style="margin: 0; font-weight: bold;">LILIAN F. UY, Ed.D.</p>
                        <p style="margin: 0;">Vice President for Academic Affairs</p>
                    </td>
                </tr>
            </table>';

                $pdf->writeHTML($signatureHtml, true, false, true, false, '');

                // Footer
                $pdf->Ln(5);
                $footerHtml = '
            <div style="font-size: 6px; color: #666;">
                <p style="margin: 2px 0;">Reference no. PRMSU-ASA-COMSP18(1o)</p>
                <p style="margin: 2px 0;">Effectivity date: May 04, 2021</p>
                <p style="margin: 2px 0;">Revision no. 00</p>
            </div>';

                $pdf->writeHTML($footerHtml, true, false, true, false, '');
            }
        }

        $filename = 'Teaching_Load_' . str_replace(' ', '_', $facultyName) . '_' . date('Ymd') . '.pdf';
        $pdf->Output($filename, 'D');
        exit;
    }

    public function generateOfficialExcelFaculty($schedules, $semesterName, $collegeName, $facultyData, $facultyName)
    {
        $spreadsheet = new Spreadsheet();
        $sheet = $spreadsheet->getActiveSheet();

        // Set document properties
        $spreadsheet->getProperties()
            ->setCreator('PRMSU ACSS System')
            ->setTitle('Faculty Teaching Load - ' . $semesterName)
            ->setSubject('Official Teaching Load Document');

        // Set page setup for landscape
        $sheet->getPageSetup()
            ->setOrientation(\PhpOffice\PhpSpreadsheet\Worksheet\PageSetup::ORIENTATION_LANDSCAPE)
            ->setPaperSize(\PhpOffice\PhpSpreadsheet\Worksheet\PageSetup::PAPERSIZE_A4);

        // Set column widths to match PDF layout
        $sheet->getColumnDimension('A')->setWidth(25);
        $sheet->getColumnDimension('B')->setWidth(1);
        $sheet->getColumnDimension('C')->setWidth(6);
        $sheet->getColumnDimension('D')->setWidth(4);
        $sheet->getColumnDimension('E')->setWidth(19);
        $sheet->getColumnDimension('F')->setWidth(3);
        $sheet->getColumnDimension('G')->setWidth(3);
        $sheet->getColumnDimension('H')->setWidth(3);
        $sheet->getColumnDimension('I')->setWidth(3);
        $sheet->getColumnDimension('J')->setWidth(7);
        $sheet->getColumnDimension('K')->setWidth(9);
        $sheet->getColumnDimension('L')->setWidth(5);

        // Header section
        $sheet->mergeCells('A1:L1');
        $sheet->setCellValue('A1', 'Republic of the Philippines');
        $sheet->mergeCells('A2:L2');
        $sheet->setCellValue('A2', 'PRESIDENT RAMON MAGSAYSAY STATE UNIVERSITY');
        $sheet->mergeCells('A3:L3');
        $sheet->setCellValue('A3', '(formerly Ramon Magsaysay Technological University)');
        $sheet->mergeCells('A4:L4');
        $sheet->setCellValue('A4', 'Iba, Zambales');
        $sheet->mergeCells('A5:L5');
        $sheet->setCellValue('A5', 'FACULTY TEACHING LOAD');
        $sheet->mergeCells('A6:L6');
        $sheet->setCellValue('A6', $semesterName);

        // Style header
        $headerStyle = [
            'font' => ['bold' => true],
            'alignment' => ['horizontal' => Alignment::HORIZONTAL_CENTER]
        ];
        $sheet->getStyle('A1:L6')->applyFromArray($headerStyle);
        $sheet->getStyle('A2:L2')->getFont()->setSize(12);
        $sheet->getStyle('A5:L5')->getFont()->setSize(14);

        // College info
        $sheet->setCellValue('A8', 'Campus:');
        $sheet->setCellValue('B8', 'Main Campus');
        $sheet->setCellValue('A9', 'Address:');
        $sheet->setCellValue('B9', 'Iba');
        $sheet->setCellValue('A10', 'College:');
        $sheet->setCellValue('B10', $collegeName);

        // Table headers
        $sheet->mergeCells('A12:A' . (12 + count($schedules) - 1));
        $sheet->setCellValue('A12', strtoupper($facultyName));
        $sheet->getStyle('A12')->getAlignment()->setVertical(Alignment::VERTICAL_TOP);

        // Vertical separator
        for ($i = 12; $i < 12 + count($schedules) + 20; $i++) {
            $sheet->setCellValue('B' . $i, '');
        }

        // Main headers
        $sheet->mergeCells('C12:C14');
        $sheet->setCellValue('C12', 'Time');
        $sheet->mergeCells('D12:D14');
        $sheet->setCellValue('D12', 'Day/s');
        $sheet->mergeCells('E12:E14');
        $sheet->setCellValue('E12', 'Course Code and Title');

        // Units/Hrs header
        $sheet->mergeCells('F12:I12');
        $sheet->setCellValue('F12', 'No. of Units/Hrs.');
        $sheet->mergeCells('F13:G13');
        $sheet->setCellValue('F13', 'Lec.');
        $sheet->mergeCells('H13:I13');
        $sheet->setCellValue('H13', 'Lab./RLE');
        $sheet->setCellValue('F14', 'Units');
        $sheet->setCellValue('G14', 'Hrs.');
        $sheet->setCellValue('H14', 'Units');
        $sheet->setCellValue('I14', 'Hrs.');

        $sheet->mergeCells('J12:J14');
        $sheet->setCellValue('J12', 'Room');
        $sheet->mergeCells('K12:K14');
        $sheet->setCellValue('K12', 'Course/Yr./Sec.');
        $sheet->mergeCells('L12:L14');
        $sheet->setCellValue('L12', 'No. of students');

        // Style table headers
        $tableHeaderStyle = [
            'font' => ['bold' => true, 'size' => 8],
            'alignment' => ['horizontal' => Alignment::HORIZONTAL_CENTER, 'vertical' => Alignment::VERTICAL_CENTER],
            'borders' => ['allBorders' => ['borderStyle' => \PhpOffice\PhpSpreadsheet\Style\Border::BORDER_THIN]]
        ];
        $sheet->getStyle('A12:L14')->applyFromArray($tableHeaderStyle);

        // Add ALL schedule data
        $currentRow = 15;

        foreach ($schedules as $schedule) {
            $timeRange = substr($schedule['start_time'], 0, 5) . '-' . substr($schedule['end_time'], 0, 5);
            $courseInfo = $schedule['course_code'] . ' ' . $schedule['course_name'];
            $sectionDetail = ($schedule['year_level'] ?? '1') . '/' . $schedule['section_name'];

            $lecUnits = $schedule['schedule_type'] === 'Lecture' ? ($schedule['units'] ?? '3') : '-';
            $lecHours = $schedule['schedule_type'] === 'Lecture' ? ($schedule['duration_hours'] ?? '3') : '-';
            $labUnits = $schedule['schedule_type'] === 'Laboratory' ? ($schedule['units'] ?? '3') : '-';
            $labHours = $schedule['schedule_type'] === 'Laboratory' ? ($schedule['duration_hours'] ?? '3') : '-';

            $sheet->setCellValue('C' . $currentRow, $timeRange);
            $sheet->setCellValue('D' . $currentRow, $schedule['day_of_week']);
            $sheet->setCellValue('E' . $currentRow, $courseInfo);
            $sheet->setCellValue('F' . $currentRow, $lecUnits);
            $sheet->setCellValue('G' . $currentRow, $lecHours);
            $sheet->setCellValue('H' . $currentRow, $labUnits);
            $sheet->setCellValue('I' . $currentRow, $labHours);
            $sheet->setCellValue('J' . $currentRow, $schedule['room_name'] ?? 'TBD');
            $sheet->setCellValue('K' . $currentRow, $sectionDetail);
            $sheet->setCellValue('L' . $currentRow, $schedule['student_count'] ?? '-');

            $currentRow++;
        }

        // Apply borders to all schedule cells
        $lastScheduleRow = 14 + count($schedules);
        $sheet->getStyle('A12:L' . $lastScheduleRow)->getBorders()->getAllBorders()->setBorderStyle(\PhpOffice\PhpSpreadsheet\Style\Border::BORDER_THIN);

        // Set font size for all cells
        $sheet->getStyle('A12:L' . $lastScheduleRow)->getFont()->setSize(8);

        // Center align specific columns
        $centerAlignColumns = ['C', 'D', 'F', 'G', 'H', 'I', 'J', 'K', 'L'];
        foreach ($centerAlignColumns as $col) {
            $sheet->getStyle($col . '15:' . $col . $lastScheduleRow)->getAlignment()->setHorizontal(Alignment::HORIZONTAL_CENTER);
        }

        // Set row heights
        for ($row = 15; $row <= $lastScheduleRow; $row++) {
            $sheet->getRowDimension($row)->setRowHeight(15);
        }

        // Add faculty information section
        $facultyInfoStartRow = $lastScheduleRow + 2;
        $sheet->mergeCells('A' . $facultyInfoStartRow . ':A' . ($facultyInfoStartRow + 17));
        $facultyInfo = [
            'Employment Status: ' . $facultyData['employment_type'],
            'VSL: ' . ($facultyData['classification'] === 'VSL' ? '☑Yes ☐No' : '☐Yes ☑No'),
            'Academic Rank: ' . $facultyData['academic_rank'],
            'Bachelor\'s Degree: ' . $facultyData['bachelor_degree'],
            'Master\'s Degree: ' . $facultyData['master_degree'],
            'Doctorate Degree: ' . $facultyData['doctorate_degree'],
            'Post Doctorate Degree: ' . $facultyData['post_doctorate_degree'],
            'Designation: ' . $facultyData['designation'],
            'Schedule Equiv. Teaching Load (ETL): ' . number_format($facultyData['equiv_teaching_load'], 2),
            'Total Lecture Hours: ' . number_format($facultyData['total_lecture_hours'], 2),
            'Total Laboratory Hours: ' . number_format($facultyData['total_laboratory_hours'], 2),
            'Total Lab Hours x 0.75: ' . number_format($facultyData['total_laboratory_hours_x075'], 2),
            'No. of Preparation: ' . $facultyData['no_of_preparation'],
            'Advisory Class: ' . $facultyData['advisory_class'],
            'Equiv. Units for Prep: 0',
            'Actual Teaching Load (ATL): ' . number_format($facultyData['actual_teaching_load'], 2),
            'Total Working Load (ETL+ATL): ' . number_format($facultyData['total_working_load'], 2),
            'Excess (24 Hours): ' . number_format($facultyData['excess_hours'], 2)
        ];

        $infoText = implode("\n", $facultyInfo);
        $sheet->setCellValue('A' . $facultyInfoStartRow, $infoText);
        $sheet->getStyle('A' . $facultyInfoStartRow)->getAlignment()->setVertical(Alignment::VERTICAL_TOP)->setWrapText(true);

        // Signature section
        $signatureRow = $facultyInfoStartRow + 20;
        $sheet->mergeCells('A' . $signatureRow . ':D' . $signatureRow);
        $sheet->setCellValue('A' . $signatureRow, 'Prepared:');
        $sheet->mergeCells('E' . $signatureRow . ':H' . $signatureRow);
        $sheet->setCellValue('E' . $signatureRow, 'Recommending Approval:');
        $sheet->mergeCells('I' . $signatureRow . ':L' . $signatureRow);
        $sheet->setCellValue('I' . $signatureRow, 'Approved:');

        $signatureRow++;
        $sheet->mergeCells('A' . $signatureRow . ':D' . ($signatureRow + 2));
        $sheet->setCellValue('A' . $signatureRow, "MENCHIE A. DELA CRUZ, Ph.D.\nDean, CCIT");
        $sheet->mergeCells('E' . $signatureRow . ':H' . ($signatureRow + 2));
        $sheet->setCellValue('E' . $signatureRow, "NEMIA M. GALANG, Ph.D.\nDirector for Instruction");
        $sheet->mergeCells('I' . $signatureRow . ':L' . ($signatureRow + 2));
        $sheet->setCellValue('I' . $signatureRow, "LILIAN F. UY, Ed.D.\nVice President for Academic Affairs");

        $sheet->getStyle('A' . ($signatureRow - 1) . ':L' . ($signatureRow + 2))->getFont()->setBold(true);
        $sheet->getStyle('A' . $signatureRow . ':L' . ($signatureRow + 2))->getAlignment()->setHorizontal(Alignment::HORIZONTAL_CENTER)->setVertical(Alignment::VERTICAL_CENTER)->setWrapText(true);

        // Footer
        $footerRow = $signatureRow + 4;
        $sheet->setCellValue('A' . $footerRow, 'Reference no. PRMSU-ASA-COMSP18(1o)');
        $sheet->setCellValue('A' . ($footerRow + 1), 'Effectivity date: May 04, 2021');
        $sheet->setCellValue('A' . ($footerRow + 2), 'Revision no. 00');
        $sheet->getStyle('A' . $footerRow . ':A' . ($footerRow + 2))->getFont()->setSize(6);
        $sheet->getStyle('A' . $footerRow . ':A' . ($footerRow + 2))->getFont()->getColor()->setRGB('666666');

        // Output the file
        $filename = 'Teaching_Load_' . str_replace(' ', '_', $facultyName) . '_' . date('Ymd') . '.xlsx';

        header('Content-Type: application/vnd.openxmlformats-officedocument.spreadsheetml.sheet');
        header('Content-Disposition: attachment;filename="' . $filename . '"');
        header('Cache-Control: max-age=0');

        $writer = new Xlsx($spreadsheet);
        $writer->save('php://output');
        exit;
    }

    public function generateOfficialPDFDean($schedules, $semesterName, $collegeName, $facultyData, $facultyName)
    {

        $pdf = new \TCPDF('L', 'mm', 'A4', true, 'UTF-8', false);

        $pdf->SetCreator('PRMSU ACSS System');
        $pdf->SetAuthor('PRMSU');
        $pdf->SetTitle('Faculty Teaching Load - ' . $semesterName);
        $pdf->SetSubject('Official Teaching Load Document');

        // Set margins to match the print layout exactly
        $pdf->SetMargins(10, 10, 10);
        $pdf->SetHeaderMargin(0);
        $pdf->SetFooterMargin(0);
        $pdf->SetAutoPageBreak(TRUE, 10);

        $pdf->setPrintHeader(false);
        $pdf->setPrintFooter(false);
        $pdf->AddPage();

        // Header with logo
        $logoPath = __DIR__ . '/logo/main_logo/PRMSUlogo.png';
        if (!file_exists($logoPath)) {
            error_log('Logo file not found: ' . $logoPath);
        }
        if (file_exists($logoPath)) {
            $pdf->Image($logoPath, 15, 12, 20, '', 'PNG', '', 'T', false, 300, '', false, false, 0, false, false, false);
        }

        // Header content
        $headerHtml = '
    <table cellpadding="0" cellspacing="0" border="0" style="width: 100%;">
        <tr>
            <td style="width: 15%;"></td>
            <td style="width: 70%; text-align: center;">
                <div style="font-size: 8px; margin-bottom: 1px;">Republic of the Philippines</div>
                <div style="font-size: 10px; font-weight: bold; margin-bottom: 1px;">PRESIDENT RAMON MAGSAYSAY STATE UNIVERSITY</div>
                <div style="font-size: 6px; font-style: italic; margin-bottom: 2px;">(formerly Ramon Magsaysay Technological University)</div>
                <div style="font-size: 7px; font-weight: bold; margin-bottom: 1px;">Iba, Zambales</div>
                <div style="font-size: 12px; font-weight: bold; margin-top: 3px;">DEAN TEACHING LOAD</div>
                <div style="font-size: 9px; margin-top: 1px;">' . htmlspecialchars($semesterName) . '</div>
            </td>
            <td style="width: 15%;"></td>
        </tr>
    </table>';

        $pdf->writeHTML($headerHtml, true, false, true, false, '');
        $pdf->Ln(8);

        // Calculate how many pages we need
        $schedulesPerPage = 15; // Adjust based on your layout
        $totalSchedules = count($schedules);
        $totalPages = ceil($totalSchedules / $schedulesPerPage);

        for ($page = 0; $page < $totalPages; $page++) {
            if ($page > 0) {
                $pdf->AddPage();
            }

            $startIndex = $page * $schedulesPerPage;
            $endIndex = min(($page + 1) * $schedulesPerPage, $totalSchedules);
            $pageSchedules = array_slice($schedules, $startIndex, $schedulesPerPage);

            // Main table structure
            $tableHtml = '
        <table border="1" cellpadding="3" cellspacing="0" style="border-collapse: collapse; width: 100%; font-size: 7px; table-layout: fixed;">
            <colgroup>
                <col style="width: 25%">
                <col style="width: 1%">
                <col style="width: 6%">
                <col style="width: 4%">
                <col style="width: 19%">
                <col style="width: 3%">
                <col style="width: 3%">
                <col style="width: 3%">
                <col style="width: 3%">
                <col style="width: 7%">
                <col style="width: 9%">
                <col style="width: 5%">
            </colgroup>
            <thead>
                <tr>
                    <td rowspan="3" style="border: 1px solid #000; padding: 4px; vertical-align: top;">
                        <p style="margin: 2px 0;"><strong>Campus :</strong> Main Campus</p>
                        <p style="margin: 2px 0;"><strong>Address :</strong> Iba</p>
                        <p style="margin: 2px 0;"><strong>College :</strong> ' . htmlspecialchars($collegeName) . '</p>
                    </td>
                    <td rowspan="' . (count($pageSchedules) + 20) . '" style="border: 1px solid #000; padding: 0; width: 1px;"></td>
                    <td rowspan="3" style="border: 1px solid #000; padding: 2px; text-align: center; font-weight: bold;">Time</td>
                    <td rowspan="3" style="border: 1px solid #000; padding: 2px; text-align: center; font-weight: bold;">Day/s</td>
                    <td rowspan="3" style="border: 1px solid #000; padding: 2px; text-align: center; font-weight: bold;">Course Code and Title</td>
                    <td colspan="4" style="border: 1px solid #000; padding: 2px; text-align: center; font-weight: bold;">No. of Units/Hrs.</td>
                    <td rowspan="3" style="border: 1px solid #000; padding: 2px; text-align: center; font-weight: bold;">Room</td>
                    <td rowspan="3" style="border: 1px solid #000; padding: 2px; text-align: center; font-weight: bold;">Course/Yr./Sec.</td>
                    <td rowspan="3" style="border: 1px solid #000; padding: 2px; text-align: center; font-weight: bold;">No. of students</td>
                </tr>
                <tr>
                    <td colspan="2" style="border: 1px solid #000; padding: 2px; text-align: center; font-weight: bold;">Lec.</td>
                    <td colspan="2" style="border: 1px solid #000; padding: 2px; text-align: center; font-weight: bold;">Lab./RLE</td>
                </tr>
                <tr>
                    <td style="border: 1px solid #000; padding: 2px; text-align: center; font-weight: bold;">Units</td>
                    <td style="border: 1px solid #000; padding: 2px; text-align: center; font-weight: bold;">Hrs.</td>
                    <td style="border: 1px solid #000; padding: 2px; text-align: center; font-weight: bold;">Units</td>
                    <td style="border: 1px solid #000; padding: 2px; text-align: center; font-weight: bold;">Hrs.</td>
                </tr>
            </thead>
            <tbody>';

            // Add schedule rows for this page
            foreach ($pageSchedules as $index => $schedule) {
                $timeRange = substr($schedule['start_time'], 0, 5) . '-' . substr($schedule['end_time'], 0, 5);
                $courseInfo = htmlspecialchars($schedule['course_code'] . ' ' . $schedule['course_name']);
                $sectionDetail = ($schedule['year_level'] ?? '1') . '/' . $schedule['section_name'];

                $lecUnits = $schedule['schedule_type'] === 'Lecture' ? ($schedule['units'] ?? '3') : '-';
                $lecHours = $schedule['schedule_type'] === 'Lecture' ? ($schedule['duration_hours'] ?? '3') : '-';
                $labUnits = $schedule['schedule_type'] === 'Laboratory' ? ($schedule['units'] ?? '3') : '-';
                $labHours = $schedule['schedule_type'] === 'Laboratory' ? ($schedule['duration_hours'] ?? '3') : '-';

                $tableHtml .= '
            <tr>
                ' . ($index === 0 ? '<td rowspan="' . count($pageSchedules) . '" style="border: 1px solid #000; padding: 4px; vertical-align: top; font-weight: bold;">' . strtoupper(htmlspecialchars($facultyName)) . '</td>' : '') . '
                <td style="border: 1px solid #000; padding: 2px; text-align: center;">' . $timeRange . '</td>
                <td style="border: 1px solid #000; padding: 2px; text-align: center;">' . htmlspecialchars($schedule['day_of_week']) . '</td>
                <td style="border: 1px solid #000; padding: 2px;">' . $courseInfo . '</td>
                <td style="border: 1px solid #000; padding: 2px; text-align: center;">' . $lecUnits . '</td>
                <td style="border: 1px solid #000; padding: 2px; text-align: center;">' . $lecHours . '</td>
                <td style="border: 1px solid #000; padding: 2px; text-align: center;">' . $labUnits . '</td>
                <td style="border: 1px solid #000; padding: 2px; text-align: center;">' . $labHours . '</td>
                <td style="border: 1px solid #000; padding: 2px; text-align: center;">' . htmlspecialchars($schedule['room_name'] ?? 'TBD') . '</td>
                <td style="border: 1px solid #000; padding: 2px; text-align: center;">' . $sectionDetail . '</td>
                <td style="border: 1px solid #000; padding: 2px; text-align: center;">' . ($schedule['student_count'] ?? '-') . '</td>
            </tr>';
            }

            // Add faculty information section only on the first page
            if ($page === 0) {
                $facultyInfoContent = '
            <p style="margin: 2px 0;"><strong>Employment Status :</strong> ' . htmlspecialchars($facultyData['employment_type']) . '</p>
            <p style="margin: 2px 0;"><strong>VSL :</strong> ' . ($facultyData['classification'] === 'VSL' ? '☑' : '☐') . 'Yes ' . ($facultyData['classification'] === 'TL' ? '☑' : '☐') . 'No</p>
            <p style="margin: 2px 0;"><strong>Academic Rank :</strong> ' . htmlspecialchars($facultyData['academic_rank']) . '</p>
            <p style="margin: 2px 0;"><strong>Bachelor\'s Degree :</strong> ' . htmlspecialchars($facultyData['bachelor_degree']) . '</p>
            <p style="margin: 2px 0;"><strong>Master\'s Degree :</strong> ' . htmlspecialchars($facultyData['master_degree']) . '</p>
            <p style="margin: 2px 0;"><strong>Doctorate Degree :</strong> ' . htmlspecialchars($facultyData['doctorate_degree']) . '</p>
            <p style="margin: 2px 0;"><strong>Post Doctorate Degree :</strong> ' . htmlspecialchars($facultyData['post_doctorate_degree']) . '</p>
            <p style="margin: 2px 0;"><strong>Designation :</strong> ' . htmlspecialchars($facultyData['designation']) . '</p>
            <p style="margin: 2px 0;"><strong>Schedule Equiv. Teaching Load (ETL) :</strong> ' . number_format($facultyData['equiv_teaching_load'], 2) . '</p>
            <p style="margin: 2px 0;"><strong>Total Lecture Hours :</strong> ' . number_format($facultyData['total_lecture_hours'], 2) . '</p>
            <p style="margin: 2px 0;"><strong>Total Laboratory Hours :</strong> ' . number_format($facultyData['total_laboratory_hours'], 2) . '</p>
            <p style="margin: 2px 0;"><strong>Total Lab Hours x 0.75 :</strong> ' . number_format($facultyData['total_laboratory_hours_x075'], 2) . '</p>
            <p style="margin: 2px 0;"><strong>No. of Preparation :</strong> ' . $facultyData['no_of_preparation'] . '</p>
            <p style="margin: 2px 0;"><strong>Advisory Class :</strong> ' . htmlspecialchars($facultyData['advisory_class']) . '</p>
            <p style="margin: 2px 0;"><strong>Equiv. Units for Prep :</strong> 0</p>
            <p style="margin: 2px 0;"><strong>Actual Teaching Load (ATL) :</strong> ' . number_format($facultyData['actual_teaching_load'], 2) . '</p>
            <p style="margin: 2px 0;"><strong>Total Working Load (ETL+ATL) :</strong> ' . number_format($facultyData['total_working_load'], 2) . '</p>
            <p style="margin: 2px 0;"><strong>Excess (24 Hours) :</strong> ' . number_format($facultyData['excess_hours'], 2) . '</p>';

                $tableHtml .= '
            <tr>
                <td rowspan="18" style="border: 1px solid #000; padding: 6px; vertical-align: top;">
                    ' . $facultyInfoContent . '
                </td>';

                // Add empty cells for faculty info section
                for ($i = 0; $i < 18; $i++) {
                    if ($i > 0) {
                        $tableHtml .= '<tr>';
                    }
                    $tableHtml .= '
                    <td style="border: 1px solid #000; padding: 2px;">&nbsp;</td>
                    <td style="border: 1px solid #000; padding: 2px;">&nbsp;</td>
                    <td style="border: 1px solid #000; padding: 2px;">&nbsp;</td>
                    <td style="border: 1px solid #000; padding: 2px;">&nbsp;</td>
                    <td style="border: 1px solid #000; padding: 2px;">&nbsp;</td>
                    <td style="border: 1px solid #000; padding: 2px;">&nbsp;</td>
                    <td style="border: 1px solid #000; padding: 2px;">&nbsp;</td>
                    <td style="border: 1px solid #000; padding: 2px;">&nbsp;</td>
                    <td style="border: 1px solid #000; padding: 2px;">&nbsp;</td>
                    <td style="border: 1px solid #000; padding: 2px;">&nbsp;</td>
                </tr>';
                }
            }

            $tableHtml .= '</tbody></table>';
            $pdf->writeHTML($tableHtml, true, false, true, false, '');

            // Add signature section only on the last page
            if ($page === $totalPages - 1) {
                $pdf->Ln(5);
                $signatureHtml = '
            <table border="1" cellpadding="3" cellspacing="0" style="border-collapse: collapse; width: 100%; font-size: 7px;">
                <tr>
                    <td style="border: 1px solid #000; padding: 3px; font-weight: bold; text-align: center; width: 33.33%;">Prepared:</td>
                    <td style="border: 1px solid #000; padding: 3px; font-weight: bold; text-align: center; width: 33.33%;">Recommending Approval:</td>
                    <td style="border: 1px solid #000; padding: 3px; font-weight: bold; text-align: center; width: 33.34%;">Approved</td>
                </tr>
                <tr>
                    <td style="border: 1px solid #000; padding: 20px 8px 8px 8px; text-align: center; vertical-align: bottom;">
                        <p style="margin: 0; font-weight: bold;">MENCHIE A. DELA CRUZ, Ph.D.</p>
                        <p style="margin: 0;">Dean, CCIT</p>
                    </td>
                    <td style="border: 1px solid #000; padding: 20px 8px 8px 8px; text-align: center; vertical-align: bottom;">
                        <p style="margin: 0; font-weight: bold;">NEMIA M. GALANG, Ph.D.</p>
                        <p style="margin: 0;">Director for Instruction</p>
                    </td>
                    <td style="border: 1px solid #000; padding: 20px 8px 8px 8px; text-align: center; vertical-align: bottom;">
                        <p style="margin: 0; font-weight: bold;">LILIAN F. UY, Ed.D.</p>
                        <p style="margin: 0;">Vice President for Academic Affairs</p>
                    </td>
                </tr>
            </table>';

                $pdf->writeHTML($signatureHtml, true, false, true, false, '');

                // Footer
                $pdf->Ln(5);
                $footerHtml = '
            <div style="font-size: 6px; color: #666;">
                <p style="margin: 2px 0;">Reference no. PRMSU-ASA-COMSP18(1o)</p>
                <p style="margin: 2px 0;">Effectivity date: May 04, 2021</p>
                <p style="margin: 2px 0;">Revision no. 00</p>
            </div>';

                $pdf->writeHTML($footerHtml, true, false, true, false, '');
            }
        }

        $filename = 'Teaching_Load_' . str_replace(' ', '_', $facultyName) . '_' . date('Ymd') . '.pdf';
        $pdf->Output($filename, 'D');
        exit;
    }

    public function generateOfficialExcelDean($schedules, $semesterName, $collegeName, $facultyData, $facultyName)
    {
        $spreadsheet = new Spreadsheet();
        $sheet = $spreadsheet->getActiveSheet();

        // Set document properties
        $spreadsheet->getProperties()
            ->setCreator('PRMSU ACSS System')
            ->setTitle('Faculty Teaching Load - ' . $semesterName)
            ->setSubject('Official Teaching Load Document');

        // Set page setup for landscape
        $sheet->getPageSetup()
            ->setOrientation(\PhpOffice\PhpSpreadsheet\Worksheet\PageSetup::ORIENTATION_LANDSCAPE)
            ->setPaperSize(\PhpOffice\PhpSpreadsheet\Worksheet\PageSetup::PAPERSIZE_A4);

        // Set column widths to match PDF layout
        $sheet->getColumnDimension('A')->setWidth(25);
        $sheet->getColumnDimension('B')->setWidth(1);
        $sheet->getColumnDimension('C')->setWidth(6);
        $sheet->getColumnDimension('D')->setWidth(4);
        $sheet->getColumnDimension('E')->setWidth(19);
        $sheet->getColumnDimension('F')->setWidth(3);
        $sheet->getColumnDimension('G')->setWidth(3);
        $sheet->getColumnDimension('H')->setWidth(3);
        $sheet->getColumnDimension('I')->setWidth(3);
        $sheet->getColumnDimension('J')->setWidth(7);
        $sheet->getColumnDimension('K')->setWidth(9);
        $sheet->getColumnDimension('L')->setWidth(5);

        // Header section
        $sheet->mergeCells('A1:L1');
        $sheet->setCellValue('A1', 'Republic of the Philippines');
        $sheet->mergeCells('A2:L2');
        $sheet->setCellValue('A2', 'PRESIDENT RAMON MAGSAYSAY STATE UNIVERSITY');
        $sheet->mergeCells('A3:L3');
        $sheet->setCellValue('A3', '(formerly Ramon Magsaysay Technological University)');
        $sheet->mergeCells('A4:L4');
        $sheet->setCellValue('A4', 'Iba, Zambales');
        $sheet->mergeCells('A5:L5');
        $sheet->setCellValue('A5', 'DEAN TEACHING LOAD');
        $sheet->mergeCells('A6:L6');
        $sheet->setCellValue('A6', $semesterName);

        // Style header
        $headerStyle = [
            'font' => ['bold' => true],
            'alignment' => ['horizontal' => Alignment::HORIZONTAL_CENTER]
        ];
        $sheet->getStyle('A1:L6')->applyFromArray($headerStyle);
        $sheet->getStyle('A2:L2')->getFont()->setSize(12);
        $sheet->getStyle('A5:L5')->getFont()->setSize(14);

        // College info
        $sheet->setCellValue('A8', 'Campus:');
        $sheet->setCellValue('B8', 'Main Campus');
        $sheet->setCellValue('A9', 'Address:');
        $sheet->setCellValue('B9', 'Iba');
        $sheet->setCellValue('A10', 'College:');
        $sheet->setCellValue('B10', $collegeName);

        // Table headers
        $sheet->mergeCells('A12:A' . (12 + count($schedules) - 1));
        $sheet->setCellValue('A12', strtoupper($facultyName));
        $sheet->getStyle('A12')->getAlignment()->setVertical(Alignment::VERTICAL_TOP);

        // Vertical separator
        for ($i = 12; $i < 12 + count($schedules) + 20; $i++) {
            $sheet->setCellValue('B' . $i, '');
        }

        // Main headers
        $sheet->mergeCells('C12:C14');
        $sheet->setCellValue('C12', 'Time');
        $sheet->mergeCells('D12:D14');
        $sheet->setCellValue('D12', 'Day/s');
        $sheet->mergeCells('E12:E14');
        $sheet->setCellValue('E12', 'Course Code and Title');

        // Units/Hrs header
        $sheet->mergeCells('F12:I12');
        $sheet->setCellValue('F12', 'No. of Units/Hrs.');
        $sheet->mergeCells('F13:G13');
        $sheet->setCellValue('F13', 'Lec.');
        $sheet->mergeCells('H13:I13');
        $sheet->setCellValue('H13', 'Lab./RLE');
        $sheet->setCellValue('F14', 'Units');
        $sheet->setCellValue('G14', 'Hrs.');
        $sheet->setCellValue('H14', 'Units');
        $sheet->setCellValue('I14', 'Hrs.');

        $sheet->mergeCells('J12:J14');
        $sheet->setCellValue('J12', 'Room');
        $sheet->mergeCells('K12:K14');
        $sheet->setCellValue('K12', 'Course/Yr./Sec.');
        $sheet->mergeCells('L12:L14');
        $sheet->setCellValue('L12', 'No. of students');

        // Style table headers
        $tableHeaderStyle = [
            'font' => ['bold' => true, 'size' => 8],
            'alignment' => ['horizontal' => Alignment::HORIZONTAL_CENTER, 'vertical' => Alignment::VERTICAL_CENTER],
            'borders' => ['allBorders' => ['borderStyle' => \PhpOffice\PhpSpreadsheet\Style\Border::BORDER_THIN]]
        ];
        $sheet->getStyle('A12:L14')->applyFromArray($tableHeaderStyle);

        // Add ALL schedule data
        $currentRow = 15;

        foreach ($schedules as $schedule) {
            $timeRange = substr($schedule['start_time'], 0, 5) . '-' . substr($schedule['end_time'], 0, 5);
            $courseInfo = $schedule['course_code'] . ' ' . $schedule['course_name'];
            $sectionDetail = ($schedule['year_level'] ?? '1') . '/' . $schedule['section_name'];

            $lecUnits = $schedule['schedule_type'] === 'Lecture' ? ($schedule['units'] ?? '3') : '-';
            $lecHours = $schedule['schedule_type'] === 'Lecture' ? ($schedule['duration_hours'] ?? '3') : '-';
            $labUnits = $schedule['schedule_type'] === 'Laboratory' ? ($schedule['units'] ?? '3') : '-';
            $labHours = $schedule['schedule_type'] === 'Laboratory' ? ($schedule['duration_hours'] ?? '3') : '-';

            $sheet->setCellValue('C' . $currentRow, $timeRange);
            $sheet->setCellValue('D' . $currentRow, $schedule['day_of_week']);
            $sheet->setCellValue('E' . $currentRow, $courseInfo);
            $sheet->setCellValue('F' . $currentRow, $lecUnits);
            $sheet->setCellValue('G' . $currentRow, $lecHours);
            $sheet->setCellValue('H' . $currentRow, $labUnits);
            $sheet->setCellValue('I' . $currentRow, $labHours);
            $sheet->setCellValue('J' . $currentRow, $schedule['room_name'] ?? 'TBD');
            $sheet->setCellValue('K' . $currentRow, $sectionDetail);
            $sheet->setCellValue('L' . $currentRow, $schedule['student_count'] ?? '-');

            $currentRow++;
        }

        // Apply borders to all schedule cells
        $lastScheduleRow = 14 + count($schedules);
        $sheet->getStyle('A12:L' . $lastScheduleRow)->getBorders()->getAllBorders()->setBorderStyle(\PhpOffice\PhpSpreadsheet\Style\Border::BORDER_THIN);

        // Set font size for all cells
        $sheet->getStyle('A12:L' . $lastScheduleRow)->getFont()->setSize(8);

        // Center align specific columns
        $centerAlignColumns = ['C', 'D', 'F', 'G', 'H', 'I', 'J', 'K', 'L'];
        foreach ($centerAlignColumns as $col) {
            $sheet->getStyle($col . '15:' . $col . $lastScheduleRow)->getAlignment()->setHorizontal(Alignment::HORIZONTAL_CENTER);
        }

        // Set row heights
        for ($row = 15; $row <= $lastScheduleRow; $row++) {
            $sheet->getRowDimension($row)->setRowHeight(15);
        }

        // Add faculty information section
        $facultyInfoStartRow = $lastScheduleRow + 2;
        $sheet->mergeCells('A' . $facultyInfoStartRow . ':A' . ($facultyInfoStartRow + 17));
        $facultyInfo = [
            'Employment Status: ' . $facultyData['employment_type'],
            'VSL: ' . ($facultyData['classification'] === 'VSL' ? '☑Yes ☐No' : '☐Yes ☑No'),
            'Academic Rank: ' . $facultyData['academic_rank'],
            'Bachelor\'s Degree: ' . $facultyData['bachelor_degree'],
            'Master\'s Degree: ' . $facultyData['master_degree'],
            'Doctorate Degree: ' . $facultyData['doctorate_degree'],
            'Post Doctorate Degree: ' . $facultyData['post_doctorate_degree'],
            'Designation: ' . $facultyData['designation'],
            'Schedule Equiv. Teaching Load (ETL): ' . number_format($facultyData['equiv_teaching_load'], 2),
            'Total Lecture Hours: ' . number_format($facultyData['total_lecture_hours'], 2),
            'Total Laboratory Hours: ' . number_format($facultyData['total_laboratory_hours'], 2),
            'Total Lab Hours x 0.75: ' . number_format($facultyData['total_laboratory_hours_x075'], 2),
            'No. of Preparation: ' . $facultyData['no_of_preparation'],
            'Advisory Class: ' . $facultyData['advisory_class'],
            'Equiv. Units for Prep: 0',
            'Actual Teaching Load (ATL): ' . number_format($facultyData['actual_teaching_load'], 2),
            'Total Working Load (ETL+ATL): ' . number_format($facultyData['total_working_load'], 2),
            'Excess (24 Hours): ' . number_format($facultyData['excess_hours'], 2)
        ];

        $infoText = implode("\n", $facultyInfo);
        $sheet->setCellValue('A' . $facultyInfoStartRow, $infoText);
        $sheet->getStyle('A' . $facultyInfoStartRow)->getAlignment()->setVertical(Alignment::VERTICAL_TOP)->setWrapText(true);

        // Signature section
        $signatureRow = $facultyInfoStartRow + 20;
        $sheet->mergeCells('A' . $signatureRow . ':D' . $signatureRow);
        $sheet->setCellValue('A' . $signatureRow, 'Prepared:');
        $sheet->mergeCells('E' . $signatureRow . ':H' . $signatureRow);
        $sheet->setCellValue('E' . $signatureRow, 'Recommending Approval:');
        $sheet->mergeCells('I' . $signatureRow . ':L' . $signatureRow);
        $sheet->setCellValue('I' . $signatureRow, 'Approved:');

        $signatureRow++;
        $sheet->mergeCells('A' . $signatureRow . ':D' . ($signatureRow + 2));
        $sheet->setCellValue('A' . $signatureRow, "MENCHIE A. DELA CRUZ, Ph.D.\nDean, CCIT");
        $sheet->mergeCells('E' . $signatureRow . ':H' . ($signatureRow + 2));
        $sheet->setCellValue('E' . $signatureRow, "NEMIA M. GALANG, Ph.D.\nDirector for Instruction");
        $sheet->mergeCells('I' . $signatureRow . ':L' . ($signatureRow + 2));
        $sheet->setCellValue('I' . $signatureRow, "LILIAN F. UY, Ed.D.\nVice President for Academic Affairs");

        $sheet->getStyle('A' . ($signatureRow - 1) . ':L' . ($signatureRow + 2))->getFont()->setBold(true);
        $sheet->getStyle('A' . $signatureRow . ':L' . ($signatureRow + 2))->getAlignment()->setHorizontal(Alignment::HORIZONTAL_CENTER)->setVertical(Alignment::VERTICAL_CENTER)->setWrapText(true);

        // Footer
        $footerRow = $signatureRow + 4;
        $sheet->setCellValue('A' . $footerRow, 'Reference no. PRMSU-ASA-COMSP18(1o)');
        $sheet->setCellValue('A' . ($footerRow + 1), 'Effectivity date: May 04, 2021');
        $sheet->setCellValue('A' . ($footerRow + 2), 'Revision no. 00');
        $sheet->getStyle('A' . $footerRow . ':A' . ($footerRow + 2))->getFont()->setSize(6);
        $sheet->getStyle('A' . $footerRow . ':A' . ($footerRow + 2))->getFont()->getColor()->setRGB('666666');

        // Output the file
        $filename = 'Teaching_Load_' . str_replace(' ', '_', $facultyName) . '_' . date('Ymd') . '.xlsx';

        header('Content-Type: application/vnd.openxmlformats-officedocument.spreadsheetml.sheet');
        header('Content-Disposition: attachment;filename="' . $filename . '"');
        header('Cache-Control: max-age=0');

        $writer = new Xlsx($spreadsheet);
        $writer->save('php://output');
        exit;
    }

    public function generateOfficialPDFDi($schedules, $semesterName, $collegeName, $facultyData, $facultyName)
    {

        $pdf = new \TCPDF('L', 'mm', 'A4', true, 'UTF-8', false);

        $pdf->SetCreator('PRMSU ACSS System');
        $pdf->SetAuthor('PRMSU');
        $pdf->SetTitle('Faculty Teaching Load - ' . $semesterName);
        $pdf->SetSubject('Official Teaching Load Document');

        // Set margins to match the print layout exactly
        $pdf->SetMargins(10, 10, 10);
        $pdf->SetHeaderMargin(0);
        $pdf->SetFooterMargin(0);
        $pdf->SetAutoPageBreak(TRUE, 10);

        $pdf->setPrintHeader(false);
        $pdf->setPrintFooter(false);
        $pdf->AddPage();

        // Header with logo
        $logoPath = __DIR__ . '/logo/main_logo/PRMSUlogo.png';
        if (!file_exists($logoPath)) {
            error_log('Logo file not found: ' . $logoPath);
        }
        if (file_exists($logoPath)) {
            $pdf->Image($logoPath, 15, 12, 20, '', 'PNG', '', 'T', false, 300, '', false, false, 0, false, false, false);
        }

        // Header content
        $headerHtml = '
    <table cellpadding="0" cellspacing="0" border="0" style="width: 100%;">
        <tr>
            <td style="width: 15%;"></td>
            <td style="width: 70%; text-align: center;">
                <div style="font-size: 8px; margin-bottom: 1px;">Republic of the Philippines</div>
                <div style="font-size: 10px; font-weight: bold; margin-bottom: 1px;">PRESIDENT RAMON MAGSAYSAY STATE UNIVERSITY</div>
                <div style="font-size: 6px; font-style: italic; margin-bottom: 2px;">(formerly Ramon Magsaysay Technological University)</div>
                <div style="font-size: 7px; font-weight: bold; margin-bottom: 1px;">Iba, Zambales</div>
                <div style="font-size: 12px; font-weight: bold; margin-top: 3px;">DIRECTOR INSTRUCTOR TEACHING LOAD</div>
                <div style="font-size: 9px; margin-top: 1px;">' . htmlspecialchars($semesterName) . '</div>
            </td>
            <td style="width: 15%;"></td>
        </tr>
    </table>';

        $pdf->writeHTML($headerHtml, true, false, true, false, '');
        $pdf->Ln(8);

        // Calculate how many pages we need
        $schedulesPerPage = 15; // Adjust based on your layout
        $totalSchedules = count($schedules);
        $totalPages = ceil($totalSchedules / $schedulesPerPage);

        for ($page = 0; $page < $totalPages; $page++) {
            if ($page > 0) {
                $pdf->AddPage();
            }

            $startIndex = $page * $schedulesPerPage;
            $endIndex = min(($page + 1) * $schedulesPerPage, $totalSchedules);
            $pageSchedules = array_slice($schedules, $startIndex, $schedulesPerPage);

            // Main table structure
            $tableHtml = '
        <table border="1" cellpadding="3" cellspacing="0" style="border-collapse: collapse; width: 100%; font-size: 7px; table-layout: fixed;">
            <colgroup>
                <col style="width: 25%">
                <col style="width: 1%">
                <col style="width: 6%">
                <col style="width: 4%">
                <col style="width: 19%">
                <col style="width: 3%">
                <col style="width: 3%">
                <col style="width: 3%">
                <col style="width: 3%">
                <col style="width: 7%">
                <col style="width: 9%">
                <col style="width: 5%">
            </colgroup>
            <thead>
                <tr>
                    <td rowspan="3" style="border: 1px solid #000; padding: 4px; vertical-align: top;">
                        <p style="margin: 2px 0;"><strong>Campus :</strong> Main Campus</p>
                        <p style="margin: 2px 0;"><strong>Address :</strong> Iba</p>
                        <p style="margin: 2px 0;"><strong>College :</strong> ' . htmlspecialchars($collegeName) . '</p>
                    </td>
                    <td rowspan="' . (count($pageSchedules) + 20) . '" style="border: 1px solid #000; padding: 0; width: 1px;"></td>
                    <td rowspan="3" style="border: 1px solid #000; padding: 2px; text-align: center; font-weight: bold;">Time</td>
                    <td rowspan="3" style="border: 1px solid #000; padding: 2px; text-align: center; font-weight: bold;">Day/s</td>
                    <td rowspan="3" style="border: 1px solid #000; padding: 2px; text-align: center; font-weight: bold;">Course Code and Title</td>
                    <td colspan="4" style="border: 1px solid #000; padding: 2px; text-align: center; font-weight: bold;">No. of Units/Hrs.</td>
                    <td rowspan="3" style="border: 1px solid #000; padding: 2px; text-align: center; font-weight: bold;">Room</td>
                    <td rowspan="3" style="border: 1px solid #000; padding: 2px; text-align: center; font-weight: bold;">Course/Yr./Sec.</td>
                    <td rowspan="3" style="border: 1px solid #000; padding: 2px; text-align: center; font-weight: bold;">No. of students</td>
                </tr>
                <tr>
                    <td colspan="2" style="border: 1px solid #000; padding: 2px; text-align: center; font-weight: bold;">Lec.</td>
                    <td colspan="2" style="border: 1px solid #000; padding: 2px; text-align: center; font-weight: bold;">Lab./RLE</td>
                </tr>
                <tr>
                    <td style="border: 1px solid #000; padding: 2px; text-align: center; font-weight: bold;">Units</td>
                    <td style="border: 1px solid #000; padding: 2px; text-align: center; font-weight: bold;">Hrs.</td>
                    <td style="border: 1px solid #000; padding: 2px; text-align: center; font-weight: bold;">Units</td>
                    <td style="border: 1px solid #000; padding: 2px; text-align: center; font-weight: bold;">Hrs.</td>
                </tr>
            </thead>
            <tbody>';

            // Add schedule rows for this page
            foreach ($pageSchedules as $index => $schedule) {
                $timeRange = substr($schedule['start_time'], 0, 5) . '-' . substr($schedule['end_time'], 0, 5);
                $courseInfo = htmlspecialchars($schedule['course_code'] . ' ' . $schedule['course_name']);
                $sectionDetail = ($schedule['year_level'] ?? '1') . '/' . $schedule['section_name'];

                $lecUnits = $schedule['schedule_type'] === 'Lecture' ? ($schedule['units'] ?? '3') : '-';
                $lecHours = $schedule['schedule_type'] === 'Lecture' ? ($schedule['duration_hours'] ?? '3') : '-';
                $labUnits = $schedule['schedule_type'] === 'Laboratory' ? ($schedule['units'] ?? '3') : '-';
                $labHours = $schedule['schedule_type'] === 'Laboratory' ? ($schedule['duration_hours'] ?? '3') : '-';

                $tableHtml .= '
            <tr>
                ' . ($index === 0 ? '<td rowspan="' . count($pageSchedules) . '" style="border: 1px solid #000; padding: 4px; vertical-align: top; font-weight: bold;">' . strtoupper(htmlspecialchars($facultyName)) . '</td>' : '') . '
                <td style="border: 1px solid #000; padding: 2px; text-align: center;">' . $timeRange . '</td>
                <td style="border: 1px solid #000; padding: 2px; text-align: center;">' . htmlspecialchars($schedule['day_of_week']) . '</td>
                <td style="border: 1px solid #000; padding: 2px;">' . $courseInfo . '</td>
                <td style="border: 1px solid #000; padding: 2px; text-align: center;">' . $lecUnits . '</td>
                <td style="border: 1px solid #000; padding: 2px; text-align: center;">' . $lecHours . '</td>
                <td style="border: 1px solid #000; padding: 2px; text-align: center;">' . $labUnits . '</td>
                <td style="border: 1px solid #000; padding: 2px; text-align: center;">' . $labHours . '</td>
                <td style="border: 1px solid #000; padding: 2px; text-align: center;">' . htmlspecialchars($schedule['room_name'] ?? 'TBD') . '</td>
                <td style="border: 1px solid #000; padding: 2px; text-align: center;">' . $sectionDetail . '</td>
                <td style="border: 1px solid #000; padding: 2px; text-align: center;">' . ($schedule['student_count'] ?? '-') . '</td>
            </tr>';
            }

            // Add faculty information section only on the first page
            if ($page === 0) {
                $facultyInfoContent = '
            <p style="margin: 2px 0;"><strong>Employment Status :</strong> ' . htmlspecialchars($facultyData['employment_type']) . '</p>
            <p style="margin: 2px 0;"><strong>VSL :</strong> ' . ($facultyData['classification'] === 'VSL' ? '☑' : '☐') . 'Yes ' . ($facultyData['classification'] === 'TL' ? '☑' : '☐') . 'No</p>
            <p style="margin: 2px 0;"><strong>Academic Rank :</strong> ' . htmlspecialchars($facultyData['academic_rank']) . '</p>
            <p style="margin: 2px 0;"><strong>Bachelor\'s Degree :</strong> ' . htmlspecialchars($facultyData['bachelor_degree']) . '</p>
            <p style="margin: 2px 0;"><strong>Master\'s Degree :</strong> ' . htmlspecialchars($facultyData['master_degree']) . '</p>
            <p style="margin: 2px 0;"><strong>Doctorate Degree :</strong> ' . htmlspecialchars($facultyData['doctorate_degree']) . '</p>
            <p style="margin: 2px 0;"><strong>Post Doctorate Degree :</strong> ' . htmlspecialchars($facultyData['post_doctorate_degree']) . '</p>
            <p style="margin: 2px 0;"><strong>Designation :</strong> ' . htmlspecialchars($facultyData['designation']) . '</p>
            <p style="margin: 2px 0;"><strong>Schedule Equiv. Teaching Load (ETL) :</strong> ' . number_format($facultyData['equiv_teaching_load'], 2) . '</p>
            <p style="margin: 2px 0;"><strong>Total Lecture Hours :</strong> ' . number_format($facultyData['total_lecture_hours'], 2) . '</p>
            <p style="margin: 2px 0;"><strong>Total Laboratory Hours :</strong> ' . number_format($facultyData['total_laboratory_hours'], 2) . '</p>
            <p style="margin: 2px 0;"><strong>Total Lab Hours x 0.75 :</strong> ' . number_format($facultyData['total_laboratory_hours_x075'], 2) . '</p>
            <p style="margin: 2px 0;"><strong>No. of Preparation :</strong> ' . $facultyData['no_of_preparation'] . '</p>
            <p style="margin: 2px 0;"><strong>Advisory Class :</strong> ' . htmlspecialchars($facultyData['advisory_class']) . '</p>
            <p style="margin: 2px 0;"><strong>Equiv. Units for Prep :</strong> 0</p>
            <p style="margin: 2px 0;"><strong>Actual Teaching Load (ATL) :</strong> ' . number_format($facultyData['actual_teaching_load'], 2) . '</p>
            <p style="margin: 2px 0;"><strong>Total Working Load (ETL+ATL) :</strong> ' . number_format($facultyData['total_working_load'], 2) . '</p>
            <p style="margin: 2px 0;"><strong>Excess (24 Hours) :</strong> ' . number_format($facultyData['excess_hours'], 2) . '</p>';

                $tableHtml .= '
            <tr>
                <td rowspan="18" style="border: 1px solid #000; padding: 6px; vertical-align: top;">
                    ' . $facultyInfoContent . '
                </td>';

                // Add empty cells for faculty info section
                for ($i = 0; $i < 18; $i++) {
                    if ($i > 0) {
                        $tableHtml .= '<tr>';
                    }
                    $tableHtml .= '
                    <td style="border: 1px solid #000; padding: 2px;">&nbsp;</td>
                    <td style="border: 1px solid #000; padding: 2px;">&nbsp;</td>
                    <td style="border: 1px solid #000; padding: 2px;">&nbsp;</td>
                    <td style="border: 1px solid #000; padding: 2px;">&nbsp;</td>
                    <td style="border: 1px solid #000; padding: 2px;">&nbsp;</td>
                    <td style="border: 1px solid #000; padding: 2px;">&nbsp;</td>
                    <td style="border: 1px solid #000; padding: 2px;">&nbsp;</td>
                    <td style="border: 1px solid #000; padding: 2px;">&nbsp;</td>
                    <td style="border: 1px solid #000; padding: 2px;">&nbsp;</td>
                    <td style="border: 1px solid #000; padding: 2px;">&nbsp;</td>
                </tr>';
                }
            }

            $tableHtml .= '</tbody></table>';
            $pdf->writeHTML($tableHtml, true, false, true, false, '');

            // Add signature section only on the last page
            if ($page === $totalPages - 1) {
                $pdf->Ln(5);
                $signatureHtml = '
            <table border="1" cellpadding="3" cellspacing="0" style="border-collapse: collapse; width: 100%; font-size: 7px;">
                <tr>
                    <td style="border: 1px solid #000; padding: 3px; font-weight: bold; text-align: center; width: 33.33%;">Prepared:</td>
                    <td style="border: 1px solid #000; padding: 3px; font-weight: bold; text-align: center; width: 33.33%;">Recommending Approval:</td>
                    <td style="border: 1px solid #000; padding: 3px; font-weight: bold; text-align: center; width: 33.34%;">Approved</td>
                </tr>
                <tr>
                    <td style="border: 1px solid #000; padding: 20px 8px 8px 8px; text-align: center; vertical-align: bottom;">
                        <p style="margin: 0; font-weight: bold;">MENCHIE A. DELA CRUZ, Ph.D.</p>
                        <p style="margin: 0;">Dean, CCIT</p>
                    </td>
                    <td style="border: 1px solid #000; padding: 20px 8px 8px 8px; text-align: center; vertical-align: bottom;">
                        <p style="margin: 0; font-weight: bold;">NEMIA M. GALANG, Ph.D.</p>
                        <p style="margin: 0;">Director for Instruction</p>
                    </td>
                    <td style="border: 1px solid #000; padding: 20px 8px 8px 8px; text-align: center; vertical-align: bottom;">
                        <p style="margin: 0; font-weight: bold;">LILIAN F. UY, Ed.D.</p>
                        <p style="margin: 0;">Vice President for Academic Affairs</p>
                    </td>
                </tr>
            </table>';

                $pdf->writeHTML($signatureHtml, true, false, true, false, '');

                // Footer
                $pdf->Ln(5);
                $footerHtml = '
            <div style="font-size: 6px; color: #666;">
                <p style="margin: 2px 0;">Reference no. PRMSU-ASA-COMSP18(1o)</p>
                <p style="margin: 2px 0;">Effectivity date: May 04, 2021</p>
                <p style="margin: 2px 0;">Revision no. 00</p>
            </div>';

                $pdf->writeHTML($footerHtml, true, false, true, false, '');
            }
        }

        $filename = 'Teaching_Load_' . str_replace(' ', '_', $facultyName) . '_' . date('Ymd') . '.pdf';
        $pdf->Output($filename, 'D');
        exit;
    }

    public function generateOfficialExcelDi($schedules, $semesterName, $collegeName, $facultyData, $facultyName)
    {
        $spreadsheet = new Spreadsheet();
        $sheet = $spreadsheet->getActiveSheet();

        // Set document properties
        $spreadsheet->getProperties()
            ->setCreator('PRMSU ACSS System')
            ->setTitle('Faculty Teaching Load - ' . $semesterName)
            ->setSubject('Official Teaching Load Document');

        // Set page setup for landscape
        $sheet->getPageSetup()
            ->setOrientation(\PhpOffice\PhpSpreadsheet\Worksheet\PageSetup::ORIENTATION_LANDSCAPE)
            ->setPaperSize(\PhpOffice\PhpSpreadsheet\Worksheet\PageSetup::PAPERSIZE_A4);

        // Set column widths to match PDF layout
        $sheet->getColumnDimension('A')->setWidth(25);
        $sheet->getColumnDimension('B')->setWidth(1);
        $sheet->getColumnDimension('C')->setWidth(6);
        $sheet->getColumnDimension('D')->setWidth(4);
        $sheet->getColumnDimension('E')->setWidth(19);
        $sheet->getColumnDimension('F')->setWidth(3);
        $sheet->getColumnDimension('G')->setWidth(3);
        $sheet->getColumnDimension('H')->setWidth(3);
        $sheet->getColumnDimension('I')->setWidth(3);
        $sheet->getColumnDimension('J')->setWidth(7);
        $sheet->getColumnDimension('K')->setWidth(9);
        $sheet->getColumnDimension('L')->setWidth(5);

        // Header section
        $sheet->mergeCells('A1:L1');
        $sheet->setCellValue('A1', 'Republic of the Philippines');
        $sheet->mergeCells('A2:L2');
        $sheet->setCellValue('A2', 'PRESIDENT RAMON MAGSAYSAY STATE UNIVERSITY');
        $sheet->mergeCells('A3:L3');
        $sheet->setCellValue('A3', '(formerly Ramon Magsaysay Technological University)');
        $sheet->mergeCells('A4:L4');
        $sheet->setCellValue('A4', 'Iba, Zambales');
        $sheet->mergeCells('A5:L5');
        $sheet->setCellValue('A5', 'DIRECTOR INSTRUCTOR TEACHING LOAD');
        $sheet->mergeCells('A6:L6');
        $sheet->setCellValue('A6', $semesterName);

        // Style header
        $headerStyle = [
            'font' => ['bold' => true],
            'alignment' => ['horizontal' => Alignment::HORIZONTAL_CENTER]
        ];
        $sheet->getStyle('A1:L6')->applyFromArray($headerStyle);
        $sheet->getStyle('A2:L2')->getFont()->setSize(12);
        $sheet->getStyle('A5:L5')->getFont()->setSize(14);

        // College info
        $sheet->setCellValue('A8', 'Campus:');
        $sheet->setCellValue('B8', 'Main Campus');
        $sheet->setCellValue('A9', 'Address:');
        $sheet->setCellValue('B9', 'Iba');
        $sheet->setCellValue('A10', 'College:');
        $sheet->setCellValue('B10', $collegeName);

        // Table headers
        $sheet->mergeCells('A12:A' . (12 + count($schedules) - 1));
        $sheet->setCellValue('A12', strtoupper($facultyName));
        $sheet->getStyle('A12')->getAlignment()->setVertical(Alignment::VERTICAL_TOP);

        // Vertical separator
        for ($i = 12; $i < 12 + count($schedules) + 20; $i++) {
            $sheet->setCellValue('B' . $i, '');
        }

        // Main headers
        $sheet->mergeCells('C12:C14');
        $sheet->setCellValue('C12', 'Time');
        $sheet->mergeCells('D12:D14');
        $sheet->setCellValue('D12', 'Day/s');
        $sheet->mergeCells('E12:E14');
        $sheet->setCellValue('E12', 'Course Code and Title');

        // Units/Hrs header
        $sheet->mergeCells('F12:I12');
        $sheet->setCellValue('F12', 'No. of Units/Hrs.');
        $sheet->mergeCells('F13:G13');
        $sheet->setCellValue('F13', 'Lec.');
        $sheet->mergeCells('H13:I13');
        $sheet->setCellValue('H13', 'Lab./RLE');
        $sheet->setCellValue('F14', 'Units');
        $sheet->setCellValue('G14', 'Hrs.');
        $sheet->setCellValue('H14', 'Units');
        $sheet->setCellValue('I14', 'Hrs.');

        $sheet->mergeCells('J12:J14');
        $sheet->setCellValue('J12', 'Room');
        $sheet->mergeCells('K12:K14');
        $sheet->setCellValue('K12', 'Course/Yr./Sec.');
        $sheet->mergeCells('L12:L14');
        $sheet->setCellValue('L12', 'No. of students');

        // Style table headers
        $tableHeaderStyle = [
            'font' => ['bold' => true, 'size' => 8],
            'alignment' => ['horizontal' => Alignment::HORIZONTAL_CENTER, 'vertical' => Alignment::VERTICAL_CENTER],
            'borders' => ['allBorders' => ['borderStyle' => \PhpOffice\PhpSpreadsheet\Style\Border::BORDER_THIN]]
        ];
        $sheet->getStyle('A12:L14')->applyFromArray($tableHeaderStyle);

        // Add ALL schedule data
        $currentRow = 15;

        foreach ($schedules as $schedule) {
            $timeRange = substr($schedule['start_time'], 0, 5) . '-' . substr($schedule['end_time'], 0, 5);
            $courseInfo = $schedule['course_code'] . ' ' . $schedule['course_name'];
            $sectionDetail = ($schedule['year_level'] ?? '1') . '/' . $schedule['section_name'];

            $lecUnits = $schedule['schedule_type'] === 'Lecture' ? ($schedule['units'] ?? '3') : '-';
            $lecHours = $schedule['schedule_type'] === 'Lecture' ? ($schedule['duration_hours'] ?? '3') : '-';
            $labUnits = $schedule['schedule_type'] === 'Laboratory' ? ($schedule['units'] ?? '3') : '-';
            $labHours = $schedule['schedule_type'] === 'Laboratory' ? ($schedule['duration_hours'] ?? '3') : '-';

            $sheet->setCellValue('C' . $currentRow, $timeRange);
            $sheet->setCellValue('D' . $currentRow, $schedule['day_of_week']);
            $sheet->setCellValue('E' . $currentRow, $courseInfo);
            $sheet->setCellValue('F' . $currentRow, $lecUnits);
            $sheet->setCellValue('G' . $currentRow, $lecHours);
            $sheet->setCellValue('H' . $currentRow, $labUnits);
            $sheet->setCellValue('I' . $currentRow, $labHours);
            $sheet->setCellValue('J' . $currentRow, $schedule['room_name'] ?? 'TBD');
            $sheet->setCellValue('K' . $currentRow, $sectionDetail);
            $sheet->setCellValue('L' . $currentRow, $schedule['student_count'] ?? '-');

            $currentRow++;
        }

        // Apply borders to all schedule cells
        $lastScheduleRow = 14 + count($schedules);
        $sheet->getStyle('A12:L' . $lastScheduleRow)->getBorders()->getAllBorders()->setBorderStyle(\PhpOffice\PhpSpreadsheet\Style\Border::BORDER_THIN);

        // Set font size for all cells
        $sheet->getStyle('A12:L' . $lastScheduleRow)->getFont()->setSize(8);

        // Center align specific columns
        $centerAlignColumns = ['C', 'D', 'F', 'G', 'H', 'I', 'J', 'K', 'L'];
        foreach ($centerAlignColumns as $col) {
            $sheet->getStyle($col . '15:' . $col . $lastScheduleRow)->getAlignment()->setHorizontal(Alignment::HORIZONTAL_CENTER);
        }

        // Set row heights
        for ($row = 15; $row <= $lastScheduleRow; $row++) {
            $sheet->getRowDimension($row)->setRowHeight(15);
        }

        // Add faculty information section
        $facultyInfoStartRow = $lastScheduleRow + 2;
        $sheet->mergeCells('A' . $facultyInfoStartRow . ':A' . ($facultyInfoStartRow + 17));
        $facultyInfo = [
            'Employment Status: ' . $facultyData['employment_type'],
            'VSL: ' . ($facultyData['classification'] === 'VSL' ? '☑Yes ☐No' : '☐Yes ☑No'),
            'Academic Rank: ' . $facultyData['academic_rank'],
            'Bachelor\'s Degree: ' . $facultyData['bachelor_degree'],
            'Master\'s Degree: ' . $facultyData['master_degree'],
            'Doctorate Degree: ' . $facultyData['doctorate_degree'],
            'Post Doctorate Degree: ' . $facultyData['post_doctorate_degree'],
            'Designation: ' . $facultyData['designation'],
            'Schedule Equiv. Teaching Load (ETL): ' . number_format($facultyData['equiv_teaching_load'], 2),
            'Total Lecture Hours: ' . number_format($facultyData['total_lecture_hours'], 2),
            'Total Laboratory Hours: ' . number_format($facultyData['total_laboratory_hours'], 2),
            'Total Lab Hours x 0.75: ' . number_format($facultyData['total_laboratory_hours_x075'], 2),
            'No. of Preparation: ' . $facultyData['no_of_preparation'],
            'Advisory Class: ' . $facultyData['advisory_class'],
            'Equiv. Units for Prep: 0',
            'Actual Teaching Load (ATL): ' . number_format($facultyData['actual_teaching_load'], 2),
            'Total Working Load (ETL+ATL): ' . number_format($facultyData['total_working_load'], 2),
            'Excess (24 Hours): ' . number_format($facultyData['excess_hours'], 2)
        ];

        $infoText = implode("\n", $facultyInfo);
        $sheet->setCellValue('A' . $facultyInfoStartRow, $infoText);
        $sheet->getStyle('A' . $facultyInfoStartRow)->getAlignment()->setVertical(Alignment::VERTICAL_TOP)->setWrapText(true);

        // Signature section
        $signatureRow = $facultyInfoStartRow + 20;
        $sheet->mergeCells('A' . $signatureRow . ':D' . $signatureRow);
        $sheet->setCellValue('A' . $signatureRow, 'Prepared:');
        $sheet->mergeCells('E' . $signatureRow . ':H' . $signatureRow);
        $sheet->setCellValue('E' . $signatureRow, 'Recommending Approval:');
        $sheet->mergeCells('I' . $signatureRow . ':L' . $signatureRow);
        $sheet->setCellValue('I' . $signatureRow, 'Approved:');

        $signatureRow++;
        $sheet->mergeCells('A' . $signatureRow . ':D' . ($signatureRow + 2));
        $sheet->setCellValue('A' . $signatureRow, "MENCHIE A. DELA CRUZ, Ph.D.\nDean, CCIT");
        $sheet->mergeCells('E' . $signatureRow . ':H' . ($signatureRow + 2));
        $sheet->setCellValue('E' . $signatureRow, "NEMIA M. GALANG, Ph.D.\nDirector for Instruction");
        $sheet->mergeCells('I' . $signatureRow . ':L' . ($signatureRow + 2));
        $sheet->setCellValue('I' . $signatureRow, "LILIAN F. UY, Ed.D.\nVice President for Academic Affairs");

        $sheet->getStyle('A' . ($signatureRow - 1) . ':L' . ($signatureRow + 2))->getFont()->setBold(true);
        $sheet->getStyle('A' . $signatureRow . ':L' . ($signatureRow + 2))->getAlignment()->setHorizontal(Alignment::HORIZONTAL_CENTER)->setVertical(Alignment::VERTICAL_CENTER)->setWrapText(true);

        // Footer
        $footerRow = $signatureRow + 4;
        $sheet->setCellValue('A' . $footerRow, 'Reference no. PRMSU-ASA-COMSP18(1o)');
        $sheet->setCellValue('A' . ($footerRow + 1), 'Effectivity date: May 04, 2021');
        $sheet->setCellValue('A' . ($footerRow + 2), 'Revision no. 00');
        $sheet->getStyle('A' . $footerRow . ':A' . ($footerRow + 2))->getFont()->setSize(6);
        $sheet->getStyle('A' . $footerRow . ':A' . ($footerRow + 2))->getFont()->getColor()->setRGB('666666');

        // Output the file
        $filename = 'Teaching_Load_' . str_replace(' ', '_', $facultyName) . '_' . date('Ymd') . '.xlsx';

        header('Content-Type: application/vnd.openxmlformats-officedocument.spreadsheetml.sheet');
        header('Content-Disposition: attachment;filename="' . $filename . '"');
        header('Cache-Control: max-age=0');

        $writer = new Xlsx($spreadsheet);
        $writer->save('php://output');
        exit;
    }

    public function generateMySchedulePdf($schedules, $semesterName, $departmentName, $totalHours, $showAllSchedules, $facultyName = '', $position = '')
    {
        $pdf = new \TCPDF('L', 'mm', 'A4', true, 'UTF-8', false); // 'L' for landscape

        $pdf->SetCreator(PDF_CREATOR);
        $pdf->SetAuthor('PRMSU - ACSS System');
        $pdf->SetTitle('Faculty Teaching Load');
        $pdf->SetSubject('Teaching Schedule for ' . $semesterName);

        // Set margins similar to the official document
        $pdf->SetMargins(15, 15, 15);
        $pdf->SetHeaderMargin(5);
        $pdf->SetFooterMargin(10);
        $pdf->SetAutoPageBreak(TRUE, 20);

        // Remove default header/footer
        $pdf->setPrintHeader(false);
        $pdf->setPrintFooter(false);

        $pdf->AddPage();

        // Logo positioning
        $logoPath = __DIR__ . '/assets/logo/main_logo/PRMSUlogo.png';
        if (file_exists($logoPath)) {
            $pdf->Image($logoPath, 20, 15, 25, '', 'PNG', '', 'T', false, 300, '', false, false, 0, false, false, false);
        }

        // Header section with official styling
        $pdf->SetFont('helvetica', 'B', 10);

        $headerHtml = '
        <table cellpadding="0" cellspacing="0" style="width: 100%; margin-top: 10px;">
            <tr>
                <td style="width: 20%; text-align: left;"></td>
                <td style="width: 60%; text-align: center;">
                    <div style="font-size: 9px; font-weight: normal;">Republic of the Philippines</div>
                    <div style="font-size: 12px; font-weight: bold; margin-top: 2px;">President Ramon Magsaysay State University</div>
                    <div style="font-size: 8px; font-style: italic; margin-top: 1px;">(formerly Ramon Magsaysay Technological University)</div>
                    <div style="font-size: 10px; font-weight: bold; margin-top: 8px;">FACULTY TEACHING LOAD</div>
                    <div style="font-size: 9px; margin-top: 2px;">' . htmlspecialchars($semesterName) . '</div>
                </td>
                <td style="width: 20%; text-align: right;"></td>
            </tr>
        </table>';

        $pdf->writeHTML($headerHtml, true, false, true, false, '');

        // Faculty information section (similar to the original document layout)
        $pdf->Ln(10);

        $facultyInfoHtml = '
        <table border="1" cellpadding="4" cellspacing="0" style="border-collapse: collapse; width: 100%; font-size: 9px;">
            <tr>
                <td style="width: 15%; background-color: #f0f0f0; font-weight: bold;">Campus:</td>
                <td style="width: 25%;">Main Campus</td>
                <td style="width: 15%; background-color: #f0f0f0; font-weight: bold;">No. of Units/Hrs.</td>
                <td style="width: 15%; text-align: center; background-color: #f0f0f0; font-weight: bold;">Room</td>
                <td style="width: 15%; text-align: center; background-color: #f0f0f0; font-weight: bold;">Course/ Yr./Sec.</td>
                <td style="width: 15%; text-align: center; background-color: #f0f0f0; font-weight: bold;">No. of Students</td>
            </tr>
            <tr>
                <td style="background-color: #f0f0f0; font-weight: bold;">Address:</td>
                <td>Iba, Zambales</td>
                <td rowspan="15" style="vertical-align: top;">
                    <table cellpadding="2" cellspacing="0" style="width: 100%; font-size: 8px;">
                        <tr style="background-color: #e0e0e0;">
                            <td style="text-align: center; font-weight: bold;">Lec.</td>
                            <td style="text-align: center; font-weight: bold;">Lab./RLE</td>
                        </tr>
                        <tr style="background-color: #e0e0e0;">
                            <td style="text-align: center; font-weight: bold;">Units</td>
                            <td style="text-align: center; font-weight: bold;">Hrs.</td>
                            <td style="text-align: center; font-weight: bold;">Units</td>
                            <td style="text-align: center; font-weight: bold;">Hrs.</td>
                        </tr>
                    </table>
                </td>
                <td rowspan="15" style="vertical-align: top; text-align: center; background-color: #f9f9f9;"></td>
                <td rowspan="15" style="vertical-align: top; text-align: center; background-color: #f9f9f9;"></td>
                <td rowspan="15" style="vertical-align: top; text-align: center; background-color: #f9f9f9;"></td>
            </tr>
            <tr>
                <td style="background-color: #f0f0f0; font-weight: bold;">College:</td>
                <td>' . htmlspecialchars($departmentName ?? 'College of Communication and Information Technology') . '</td>
            </tr>
        </table>';

        $pdf->writeHTML($facultyInfoHtml, true, false, true, false, '');

        // Faculty name section
        $pdf->Ln(5);

        $nameHtml = '
        <table cellpadding="0" cellspacing="0" style="width: 100%;">
            <tr>
                <td style="font-size: 16px; font-weight: bold; text-align: center; padding: 10px 0;">
                    ' . strtoupper(htmlspecialchars($facultyName ?: 'FACULTY NAME')) . '
                </td>
            </tr>
        </table>';

        $pdf->writeHTML($nameHtml, true, false, true, false, '');

        // Schedule table
        $pdf->Ln(5);

        $scheduleHtml = '
        <table border="1" cellpadding="3" cellspacing="0" style="border-collapse: collapse; width: 100%; font-size: 8px;">
            <thead>
                <tr style="background-color: #d0d0d0;">
                    <th style="text-align: center; font-weight: bold; width: 12%;">Time</th>
                    <th style="text-align: center; font-weight: bold; width: 8%;">Days</th>
                    <th style="text-align: center; font-weight: bold; width: 35%;">Course Code and Title</th>
                    <th style="text-align: center; font-weight: bold; width: 10%;">Room</th>
                    <th style="text-align: center; font-weight: bold; width: 15%;">Course/ Yr./Sec.</th>
                    <th style="text-align: center; font-weight: bold; width: 10%;">No. of Students</th>
                    <th style="text-align: center; font-weight: bold; width: 10%;">Type</th>
                </tr>
            </thead>
            <tbody>';

            if (!empty($schedules)) {
                foreach ($schedules as $schedule) {
                    $timeRange = htmlspecialchars(($schedule['start_time'] ?? '') . '-' . ($schedule['end_time'] ?? ''));
                    $courseInfo = htmlspecialchars(($schedule['course_code'] ?? 'N/A') . ' - ' . ($schedule['course_name'] ?? 'N/A'));

                    $scheduleHtml .= '
                <tr>
                    <td style="text-align: center; padding: 4px;">' . $timeRange . '</td>
                    <td style="text-align: center; padding: 4px;">' . htmlspecialchars($schedule['day_of_week'] ?? 'N/A') . '</td>
                    <td style="padding: 4px;">' . $courseInfo . '</td>
                    <td style="text-align: center; padding: 4px;">' . htmlspecialchars($schedule['room_name'] ?? 'TBD') . '</td>
                    <td style="text-align: center; padding: 4px;">' . htmlspecialchars($schedule['section_name'] ?? 'N/A') . '</td>
                    <td style="text-align: center; padding: 4px;">-</td>
                    <td style="text-align: center; padding: 4px;">' . htmlspecialchars($schedule['schedule_type'] ?? 'N/A') . '</td>
                </tr>';
                }

            // Add empty rows to match the original format
            for ($i = count($schedules); $i < 12; $i++) {
                $scheduleHtml .= '
            <tr>
                <td style="padding: 8px;">&nbsp;</td>
                <td style="padding: 8px;">&nbsp;</td>
                <td style="padding: 8px;">&nbsp;</td>
                <td style="padding: 8px;">&nbsp;</td>
                <td style="padding: 8px;">&nbsp;</td>
                <td style="padding: 8px;">&nbsp;</td>
                <td style="padding: 8px;">&nbsp;</td>
            </tr>';
            }
        } else {
            $scheduleHtml .= '<tr><td colspan="7" style="text-align: center; padding: 20px;">No schedules found for this term.</td></tr>';
        }

        $scheduleHtml .= '</tbody></table>';

        $pdf->writeHTML($scheduleHtml, true, false, true, false, '');

        // Additional information section
        $pdf->Ln(5);

        $additionalInfoHtml = '
        <table border="1" cellpadding="3" cellspacing="0" style="border-collapse: collapse; width: 100%; font-size: 8px;">
            <tr>
                <td style="background-color: #f0f0f0; font-weight: bold; width: 25%;">Employment Status:</td>
                <td style="width: 15%;">☐ Regular ☐ Yes ☐ No</td>
                <td style="background-color: #f0f0f0; font-weight: bold; width: 20%;">Total Weekly Hours:</td>
                <td style="width: 40%;">' . number_format($totalHours ?? 0, 2) . ' hrs</td>
            </tr>
            <tr>
                <td style="background-color: #f0f0f0; font-weight: bold;">Academic Rank:</td>
                <td>' . htmlspecialchars($position ?? 'Assistant Professor I') . '</td>
                <td style="background-color: #f0f0f0; font-weight: bold;">Excess (24 Hours):</td>
                <td>' . number_format(max(0, ($totalHours ?? 0) - 24), 2) . '</td>
            </tr>
        </table>';

        $pdf->writeHTML($additionalInfoHtml, true, false, true, false, '');

        // Signature section
        $pdf->Ln(15);

        $signatureHtml = '
        <table cellpadding="5" cellspacing="0" style="width: 100%; font-size: 9px;">
            <tr>
                <td style="width: 30%; text-align: center;">
                    <div style="border-top: 1px solid #000; margin-top: 30px; padding-top: 5px;">
                        <strong>Prepared:</strong><br/>
                        Faculty Signature
                    </div>
                </td>
                <td style="width: 40%; text-align: center;">
                    <div style="border-top: 1px solid #000; margin-top: 30px; padding-top: 5px;">
                        <strong>Recommending Approval:</strong><br/>
                        Department Head
                    </div>
                </td>
                <td style="width: 30%; text-align: center;">
                    <div style="border-top: 1px solid #000; margin-top: 30px; padding-top: 5px;">
                        <strong>Approved:</strong><br/>
                        Dean/Director
                    </div>
                </td>
            </tr>
        </table>';

        $pdf->writeHTML($signatureHtml, true, false, true, false, '');

        // Footer with reference info
        $pdf->Ln(10);
        $footerHtml = '
        <div style="font-size: 7px; text-align: right;">
            Reference no.: PRMSU-ASA-COMP16 (16)<br/>
            Effectivity date: May 04, 2021<br/>
            Revision no.: 09
        </div>';

        $pdf->writeHTML($footerHtml, true, false, true, false, '');

        $pdf->Output('faculty_teaching_load_' . date('Ymd') . '.pdf', 'D');
        exit;
    }

    public function exportTimetableToPDF($schedules, $filename, $roomName, $semesterName)
    {
        // Initialize TCPDF
        $pdf = new \TCPDF(PDF_PAGE_ORIENTATION, PDF_UNIT, PDF_PAGE_FORMAT, true, 'UTF-8', false);

        // Set document information
        $pdf->SetCreator(PDF_CREATOR);
        $pdf->SetAuthor('ACSS System');
        $pdf->SetTitle('Computer Laboratory Schedule');
        $pdf->SetSubject('Schedule for ' . $semesterName . ' - ' . $roomName);

        // Set margins and font
        $pdf->SetMargins(PDF_MARGIN_LEFT, PDF_MARGIN_TOP, PDF_MARGIN_RIGHT);
        $pdf->SetHeaderMargin(PDF_MARGIN_HEADER);
        $pdf->SetFooterMargin(PDF_MARGIN_FOOTER);
        $pdf->SetAutoPageBreak(TRUE, PDF_MARGIN_BOTTOM);

        // Add a page
        $pdf->AddPage();

        // Add logo (assuming logo.png is in ../assets/ relative to this file)
        $logoPath = __DIR__ . '/logo/main_logo/PRMSUlogo.png';
        if (file_exists($logoPath)) {
            $pdf->Image($logoPath, 10, 10, 30, '', 'PNG', '', 'T', false, 300, '', false, false, 0, false, false, false);
        }

        // Set font
        $pdf->SetFont('helvetica', '', 12);

        // Header content
        $html = '<h1>Republic of the Philippines</h1>
             <h2>PRESIDENT RAMON MAGSAYSAY STATE UNIVERSITY</h2>
             <h2>COMPUTER LABORATORY SCHEDULE</h2>
             <h3>' . htmlspecialchars($semesterName) . '</h3>';

        // Group schedules by year_level and section_name
        $groupedSchedules = [];
        foreach ($schedules as $schedule) {
            $yearSection = $schedule['year_level'] . ' - ' . $schedule['section_name'];
            if ($roomName === 'All Rooms' || $schedule['room_name'] === $roomName) {
                $groupedSchedules[$yearSection][] = $schedule;
            }
        }

        // Generate a table for each year-section group
        foreach ($groupedSchedules as $yearSection => $groupSchedules) {
            $html .= '<h3>' . htmlspecialchars($yearSection) . ' (' . ($roomName === 'All Rooms' ? 'All Rooms' : $roomName) . ')</h3>';

            // Table structure
            $html .= '<table border="1" cellpadding="5" cellspacing="0" style="border-collapse: collapse; width: 100%; margin-bottom: 20px;">
                  <tr>
                      <th style="background-color: #e6f3ff; text-align: center;">Time</th>
                      <th style="background-color: #e6f3ff; text-align: center;">MONDAY</th>
                      <th style="background-color: #e6f3ff; text-align: center;">TUESDAY</th>
                      <th style="background-color: #e6f3ff; text-align: center;">WEDNESDAY</th>
                      <th style="background-color: #e6f3ff; text-align: center;">THURSDAY</th>
                      <th style="background-color: #e6f3ff; text-align: center;">FRIDAY</th>
                      <th style="background-color: #e6f3ff; text-align: center;">SATURDAY</th>
                  </tr>';

            // Use exact start times to match schedule data
            $times = [
                '07:30',
                '08:00',
                '09:00',
                '10:00',
                '11:00',
                '12:00',
                '13:00',
                '14:00',
                '15:00',
                '16:00'
            ];
            $days = ['MONDAY', 'TUESDAY', 'WEDNESDAY', 'THURSDAY', 'FRIDAY', 'SATURDAY'];

            // Build schedule grid for this group
            $scheduleGrid = [];
            foreach ($groupSchedules as $schedule) {
                $day = strtoupper($schedule['day_of_week']);
                $startTime = substr($schedule['start_time'], 0, 5);
                if (!isset($scheduleGrid[$day])) $scheduleGrid[$day] = [];
                if (!isset($scheduleGrid[$day][$startTime])) $scheduleGrid[$day][$startTime] = [];
                $scheduleGrid[$day][$startTime][] = $schedule;
            }

            foreach ($times as $time) {
                $html .= '<tr>';
                $html .= '<td style="text-align: center;">' . htmlspecialchars($time . ' - ' . date('H:i', strtotime($time . ':00') + 3600)) . '</td>';
                foreach ($days as $day) {
                    $cellContent = '';
                    if (isset($scheduleGrid[$day][$time])) {
                        $schedulesForSlot = $scheduleGrid[$day][$time];
                        $content = [];
                        foreach ($schedulesForSlot as $schedule) {
                            $content[] = htmlspecialchars($schedule['course_code'] . ' - ' . $schedule['faculty_name']);
                        }
                        $cellContent = implode('<br>', $content);
                    }
                    $html .= '<td style="text-align: center; vertical-align: middle;">' . $cellContent . '</td>';
                }
                $html .= '</tr>';
            }

            $html .= '</table>';
        }

        // Output the HTML content
        $pdf->writeHTML($html, true, false, true, false, '');

        // Close and output PDF
        $pdf->Output($filename . '.pdf', 'D');
        exit;
    }

    public function exportTimetableToExcel($schedules, $filename, $roomName, $semesterName)
    {
        $spreadsheet = new Spreadsheet();
        $sheet = $spreadsheet->getActiveSheet();

        // Set title and headers
        $sheet->mergeCells('A1:E1');
        $sheet->setCellValue('A1', 'Republic of the Philippines');
        $sheet->mergeCells('A2:E2');
        $sheet->setCellValue('A2', 'PRESIDENT RAMON MAGSAYSAY STATE UNIVERSITY');
        $sheet->mergeCells('A3:E3');
        $sheet->setCellValue('A3', '(Formerly Ramon Magsaysay Technological University)');
        $sheet->mergeCells('A4:E4');
        $sheet->setCellValue('A4', 'COMPUTER LABORATORY SCHEDULE');
        $sheet->mergeCells('A5:E5');
        $sheet->setCellValue('A5', $semesterName);
        $sheet->mergeCells('A6:E6');
        $sheet->setCellValue('A6', strtoupper($roomName));

        // Faculty in-charge (placeholder)
        $sheet->setCellValue('A7', 'Faculty-in-charge:');
        $sheet->mergeCells('B7:E7');

        // Time slots and days
        $days = ['MONDAY', 'TUESDAY', 'WEDNESDAY', 'THURSDAY', 'FRIDAY'];
        $times = [
            '7:30 - 8:00',
            '8:00 - 9:00',
            '9:00 - 10:00',
            '10:00 - 11:00',
            '11:00 - 12:00',
            '12:00 - 1:00',
            '1:00 - 2:00',
            '2:00 - 3:00',
            '3:00 - 4:00',
            '4:00 - 5:00'
        ];

        $sheet->setCellValue('A9', 'TIME');
        for ($i = 0; $i < count($days); $i++) {
            $cell = chr(66 + $i) . '9'; // Convert column index to letter (B, C, D, etc.)
            $sheet->setCellValue($cell, $days[$i]);
        }

        $row = 10;
        foreach ($times as $time) {
            $sheet->setCellValue('A' . $row, $time);
            $row++;
        }

        // Populate schedule data
        $row = 10;
        foreach ($times as $time) {
            foreach ($days as $index => $day) {
                $cell = chr(66 + $index) . $row; // B, C, D, E columns
                foreach ($schedules as $schedule) {
                    if ($schedule['start_time'] === substr($time, 0, 5) && $schedule['day_of_week'] === $day) {
                        $sheet->setCellValue($cell, $schedule['course_code'] . ' - ' . $schedule['faculty_name']);
                    }
                }
                $sheet->getStyle($cell)->getAlignment()->setWrapText(true);
            }
            $row++;
        }

        // Auto-size columns
        foreach (range('A', 'E') as $col) {
            $sheet->getColumnDimension($col)->setAutoSize(true);
        }

        // Style headers
        $sheet->getStyle('A1:E6')->getFont()->setBold(true);
        $sheet->getStyle('A9:E9')->getFont()->setBold(true);
        $sheet->getStyle('A1:E6')->getAlignment()->setHorizontal(Alignment::HORIZONTAL_CENTER);

        // Write to file
        $writer = new Xlsx($spreadsheet);
        header('Content-Type: application/vnd.openxmlformats-officedocument.spreadsheetml.sheet');
        header('Content-Disposition: attachment;filename="' . $filename . '.xlsx"');
        header('Cache-Control: max-age=0');
        $writer->save('php://output');
        exit;
    }

    private function exportPlainExcel($courses, $faculty, $rooms, $sections, $filename)
    {
        $spreadsheet = new Spreadsheet();
        $sheet = $spreadsheet->getActiveSheet();

        // Headers
        $sheet->setCellValue('A1', 'Course Code');
        $sheet->setCellValue('B1', 'Course Name');
        $sheet->setCellValue('C1', 'Faculty Name');
        $sheet->setCellValue('D1', 'Room Name');
        $sheet->setCellValue('E1', 'Section Name');
        $sheet->setCellValue('F1', 'Day of Week');
        $sheet->setCellValue('G1', 'Start Time');
        $sheet->setCellValue('H1', 'End Time');

        // Populate with available resources
        $row = 2;
        foreach ($courses as $course) {
            $sheet->setCellValue('A' . $row, $course['course_code']);
            $sheet->setCellValue('B' . $row, $course['course_name']);
            $row++;
        }
        $row = 2;
        foreach ($faculty as $fac) {
            $sheet->setCellValue('C' . $row, $fac['name']);
            $row++;
        }
        $row = 2;
        foreach ($rooms as $room) {
            $sheet->setCellValue('D' . $row, $room['room_name']);
            $row++;
        }
        $row = 2;
        foreach ($sections as $section) {
            $sheet->setCellValue('E' . $row, $section['section_name']);
            $row++;
        }

        // Add days and times as dropdown options
        $days = ['Monday', 'Tuesday', 'Wednesday', 'Thursday', 'Friday'];
        $times = ['07:30', '08:00', '09:00', '10:00', '11:00', '12:00', '13:00', '14:00', '15:00', '16:00'];
        $sheet->setCellValue('F2', implode(', ', $days));
        $sheet->setCellValue('G2', implode(', ', $times));
        $sheet->setCellValue('H2', implode(', ', $times));

        foreach (range('A', 'H') as $col) {
            $sheet->getColumnDimension($col)->setAutoSize(true);
        }
        $sheet->getStyle('A1:H1')->getFont()->setBold(true);

        $writer = new Xlsx($spreadsheet);
        header('Content-Type: application/vnd.openxmlformats-officedocument.spreadsheetml.sheet');
        header('Content-Disposition: attachment;filename="' . $filename . '.xlsx"');
        header('Cache-Control: max-age=0');
        $writer->save('php://output');
        exit;
    }

    public function formatScheduleDays($dayString)
    {
        if (empty($dayString)) {
            return 'TBD';
        }

        $days = explode(', ', $dayString);
        $dayAbbrev = [];

        foreach ($days as $day) {
            switch (trim($day)) {
                case 'Monday':
                    $dayAbbrev[] = 'M';
                    break;
                case 'Tuesday':
                    $dayAbbrev[] = 'T';
                    break;
                case 'Wednesday':
                    $dayAbbrev[] = 'W';
                    break;
                case 'Thursday':
                    $dayAbbrev[] = 'Th';
                    break;
                case 'Friday':
                    $dayAbbrev[] = 'F';
                    break;
                case 'Saturday':
                    $dayAbbrev[] = 'S';
                    break;
                case 'Sunday':
                    $dayAbbrev[] = 'Su';
                    break;
            }
        }

        // Common patterns
        $dayStr = implode('', $dayAbbrev);

        // Replace common patterns for better readability
        $patterns = [
            'MWF' => 'MWF',
            'TTh' => 'TTH',
            'MW' => 'MW',
            'ThF' => 'THF',
            'MThF' => 'MTHF',
            'TWThF' => 'TWTHF'
        ];

        foreach ($patterns as $pattern => $replacement) {
            if ($dayStr == $pattern) {
                return $replacement;
            }
        }

        return $dayStr ?: 'TBD';
    }


    public function expandDayPattern($dayPattern)
    {
        $patternMap = [
            'MWF' => ['Monday', 'Wednesday', 'Friday'],
            'TTH' => ['Tuesday', 'Thursday'],
            'MW' => ['Monday', 'Wednesday'],
            'MTH' => ['Monday', 'Thursday'],
            'TTHS' => ['Tuesday', 'Thursday', 'Saturday'],
            'M' => ['Monday'],
            'T' => ['Tuesday'],
            'W' => ['Wednesday'],
            'TH' => ['Thursday'],
            'F' => ['Friday'],
            'S' => ['Saturday'],
            'Su' => ['Sunday']
        ];

        // If it's a single day or already expanded, return as array
        if (isset($patternMap[$dayPattern])) {
            return $patternMap[$dayPattern];
        }

        // Check if it's already a valid day name
        $validDays = ['Monday', 'Tuesday', 'Wednesday', 'Thursday', 'Friday', 'Saturday'];
        if (in_array($dayPattern, $validDays)) {
            return [$dayPattern];
        }

        // Default to single day if pattern not recognized
        return [$dayPattern];
    }

    /**
     * Main API endpoint handler
     */
    public function handleRequest()
    {
        $method = $_SERVER['REQUEST_METHOD'];
        $endpoint = isset($_GET['endpoint']) ? $_GET['endpoint'] : '';

        try {
            switch ($method) {
                case 'GET':
                    $this->handleGetRequest($endpoint);
                    break;
                case 'POST':
                    $this->handlePostRequest($endpoint);
                    break;
                case 'PUT':
                    $this->handlePutRequest($endpoint);
                    break;
                case 'DELETE':
                    $this->handleDeleteRequest($endpoint);
                    break;
                default:
                    throw new Exception("Method not allowed", 405);
            }
        } catch (Exception $e) {
            http_response_code($e->getCode());
            echo json_encode(['error' => $e->getMessage()]);
        }
    }

    /**
     * Handle GET requests
     */
    private function handleGetRequest($endpoint)
    {
        switch ($endpoint) {
            case 'available-rooms':
                $this->getAvailableRooms();
                break;
            case 'faculty-schedule':
                $this->getFacultySchedule();
                break;
            case 'room-schedule':
                $this->getRoomSchedule();
                break;
            case 'course-offerings':
                $this->getCourseOfferings();
                break;
            case 'conflicts':
                $this->getConflicts();
                break;
            default:
                throw new Exception("Endpoint not found", 404);
        }
    }

    /**
     * Handle POST requests
     */
    private function handlePostRequest($endpoint)
    {
        $data = json_decode(file_get_contents('php://input'), true);

        switch ($endpoint) {
            case 'assign-faculty':
                $this->assignFaculty($data);
                break;
            case 'reserve-room':
                $this->reserveRoom($data);
                break;
            default:
                throw new Exception("Endpoint not found", 404);
        }
    }

    /**
     * Handle PUT requests
     */
    private function handlePutRequest($endpoint)
    {
        $data = json_decode(file_get_contents('php://input'), true);

        switch ($endpoint) {
            case 'update-schedule':
                $this->updateSchedule($data);
                break;
            case 'approve-schedule':
                $this->approveSchedule($data);
                break;
            default:
                throw new Exception("Endpoint not found", 404);
        }
    }

    /**
     * Handle DELETE requests
     */
    private function handleDeleteRequest($endpoint)
    {
        $data = json_decode(file_get_contents('php://input'), true);

        switch ($endpoint) {
            case 'delete-schedule':
                $this->deleteSchedule($data);
                break;
            default:
                throw new Exception("Endpoint not found", 404);
        }
    }

    // ======================== GET Endpoint Implementations ========================

    /**
     * Get available rooms based on filters
     */
    private function getAvailableRooms()
    {
        $building = $_GET['building'] ?? null;
        $capacity = $_GET['capacity'] ?? null;
        $roomType = $_GET['roomType'] ?? null;
        $date = $_GET['date'] ?? null;
        $startTime = $_GET['startTime'] ?? null;
        $endTime = $_GET['endTime'] ?? null;

        $query = "SELECT * FROM classrooms WHERE availability = 'available'";

        if ($building) {
            $query .= " AND building = ?";
            $params[] = $building;
        }

        if ($capacity) {
            $query .= " AND capacity >= ?";
            $params[] = $capacity;
        }

        if ($roomType) {
            $query .= " AND room_type = ?";
            $params[] = $roomType;
        }

        $stmt = $this->conn->prepare($query);

        if (!empty($params)) {
            $types = str_repeat('s', count($params));
            $stmt->bind_param($types, ...$params);
        }

        $stmt->execute();
        $result = $stmt->get_result();
        $rooms = $result->fetch_all(MYSQLI_ASSOC);

        // If date/time parameters are provided, filter out rooms with conflicts
        if ($date && $startTime && $endTime) {
            $dayOfWeek = date('l', strtotime($date));
            $conflictQuery = "SELECT room_id FROM schedules 
                            WHERE day_of_week = ? 
                            AND ((start_time <= ? AND end_time >= ?) 
                            OR (start_time <= ? AND end_time >= ?) 
                            OR (start_time >= ? AND end_time <= ?))";

            $conflictStmt = $this->conn->prepare($conflictQuery);
            $conflictStmt->bind_param(
                'sssssss',
                $dayOfWeek,
                $startTime,
                $startTime,
                $endTime,
                $endTime,
                $startTime,
                $endTime
            );
            $conflictStmt->execute();
            $conflictResult = $conflictStmt->get_result();
            $conflictingRooms = $conflictResult->fetch_all(MYSQLI_ASSOC);

            $conflictingRoomIds = array_column($conflictingRooms, 'room_id');

            $rooms = array_filter($rooms, function ($room) use ($conflictingRoomIds) {
                return !in_array($room['room_id'], $conflictingRoomIds);
            });
        }

        echo json_encode(array_values($rooms));
    }

    /**
     * Get faculty schedule
     */
    private function getFacultySchedule()
    {
        $facultyId = $_GET['facultyId'] ?? null;
        $semesterId = $_GET['semesterId'] ?? null;

        if (!$facultyId) {
            throw new Exception("Faculty ID is required", 400);
        }

        $query = "SELECT s.*, c.course_code, c.course_name, r.room_name, r.building 
                 FROM schedules s
                 JOIN courses c ON s.course_id = c.course_id
                 LEFT JOIN classrooms r ON s.room_id = r.room_id
                 WHERE s.faculty_id = ?";

        $params = [$facultyId];

        if ($semesterId) {
            $query .= " AND s.semester_id = ?";
            $params[] = $semesterId;
        }

        $stmt = $this->conn->prepare($query);
        $stmt->bind_param(str_repeat('i', count($params)), ...$params);
        $stmt->execute();
        $result = $stmt->get_result();
        $schedule = $result->fetch_all(MYSQLI_ASSOC);

        echo json_encode($schedule);
    }

    /**
     * Get room schedule
     */
    private function getRoomSchedule()
    {
        $roomId = $_GET['roomId'] ?? null;
        $semesterId = $_GET['semesterId'] ?? null;

        if (!$roomId) {
            throw new Exception("Room ID is required", 400);
        }

        $query = "SELECT s.*, c.course_code, c.course_name, 
                 CONCAT(u.first_name, ' ', u.last_name) as faculty_name
                 FROM schedules s
                 JOIN courses c ON s.course_id = c.course_id
                 JOIN faculty f ON s.faculty_id = f.faculty_id
                 JOIN users u ON f.user_id = u.user_id
                 WHERE s.room_id = ?";

        $params = [$roomId];

        if ($semesterId) {
            $query .= " AND s.semester_id = ?";
            $params[] = $semesterId;
        }

        $stmt = $this->conn->prepare($query);
        $stmt->bind_param(str_repeat('i', count($params)), ...$params);
        $stmt->execute();
        $result = $stmt->get_result();
        $schedule = $result->fetch_all(MYSQLI_ASSOC);

        echo json_encode($schedule);
    }

    /**
     * Get course offerings for a semester
     */
    private function getCourseOfferings()
    {
        $semesterId = $_GET['semesterId'] ?? null;
        $departmentId = $_GET['departmentId'] ?? null;

        if (!$semesterId) {
            throw new Exception("Semester ID is required", 400);
        }

        $query = "SELECT co.*, c.course_code, c.course_name, d.department_name
                 FROM course_offerings co
                 JOIN courses c ON co.course_id = c.course_id
                 JOIN departments d ON c.department_id = d.department_id
                 WHERE co.semester_id = ?";

        $params = [$semesterId];

        if ($departmentId) {
            $query .= " AND c.department_id = ?";
            $params[] = $departmentId;
        }

        $stmt = $this->conn->prepare($query);
        $stmt->bind_param(str_repeat('i', count($params)), ...$params);
        $stmt->execute();
        $result = $stmt->get_result();
        $offerings = $result->fetch_all(MYSQLI_ASSOC);

        echo json_encode($offerings);
    }

    /**
     * Get scheduling conflicts
     */
    private function getConflicts()
    {
        $semesterId = $_GET['semesterId'] ?? null;

        if (!$semesterId) {
            throw new Exception("Semester ID is required", 400);
        }

        // Faculty time conflicts
        $facultyConflictsQuery = "SELECT f1.faculty_id, 
                                CONCAT(u.first_name, ' ', u.last_name) as faculty_name,
                                f1.day_of_week, f1.start_time, f1.end_time,
                                c1.course_code as course1, c2.course_code as course2
                                FROM schedules f1
                                JOIN schedules f2 ON f1.faculty_id = f2.faculty_id 
                                    AND f1.schedule_id != f2.schedule_id
                                    AND f1.day_of_week = f2.day_of_week
                                    AND ((f1.start_time <= f2.start_time AND f1.end_time > f2.start_time)
                                    OR (f1.start_time < f2.end_time AND f1.end_time >= f2.end_time)
                                    OR (f1.start_time >= f2.start_time AND f1.end_time <= f2.end_time))
                                JOIN courses c1 ON f1.course_id = c1.course_id
                                JOIN courses c2 ON f2.course_id = c2.course_id
                                JOIN faculty fa ON f1.faculty_id = fa.faculty_id
                                JOIN users u ON fa.user_id = u.user_id
                                WHERE f1.semester_id = ? AND f2.semester_id = ?";

        $stmt = $this->conn->prepare($facultyConflictsQuery);
        $stmt->bind_param('ii', $semesterId, $semesterId);
        $stmt->execute();
        $facultyConflicts = $stmt->get_result()->fetch_all(MYSQLI_ASSOC);

        // Room time conflicts
        $roomConflictsQuery = "SELECT r1.room_id, cl.room_name, cl.building,
                              r1.day_of_week, r1.start_time, r1.end_time,
                              c1.course_code as course1, c2.course_code as course2
                              FROM schedules r1
                              JOIN schedules r2 ON r1.room_id = r2.room_id 
                                  AND r1.schedule_id != r2.schedule_id
                                  AND r1.day_of_week = r2.day_of_week
                                  AND ((r1.start_time <= r2.start_time AND r1.end_time > r2.start_time)
                                  OR (r1.start_time < r2.end_time AND r1.end_time >= r2.end_time)
                                  OR (r1.start_time >= r2.start_time AND r1.end_time <= r2.end_time))
                              JOIN courses c1 ON r1.course_id = c1.course_id
                              JOIN courses c2 ON r2.course_id = c2.course_id
                              JOIN classrooms cl ON r1.room_id = cl.room_id
                              WHERE r1.semester_id = ? AND r2.semester_id = ?";

        $stmt = $this->conn->prepare($roomConflictsQuery);
        $stmt->bind_param('ii', $semesterId, $semesterId);
        $stmt->execute();
        $roomConflicts = $stmt->get_result()->fetch_all(MYSQLI_ASSOC);

        echo json_encode([
            'facultyConflicts' => $facultyConflicts,
            'roomConflicts' => $roomConflicts
        ]);
    }

    // ======================== POST Endpoint Implementations ========================

    /**
     * Create a new schedule
     */
    public function createSchedule($data, $departmentId)
    {
        try {
            // Validate input data
            $requiredFields = ['course_id', 'faculty_id', 'room_id', 'section_id', 'curriculum_id', 'schedule_type', 'day_of_week', 'start_time', 'end_time', 'semester_id'];
            foreach ($requiredFields as $field) {
                if (empty($data[$field]) && !($field === 'room_id' && $data['schedule_type'] === 'Asynchronous')) {
                    return [
                        'code' => 400,
                        'data' => ['error' => "Missing required field: $field"]
                    ];
                }
            }

            // Validate Curriculum
            $curriculumStmt = $this->db->prepare("SELECT curriculum_id, curriculum_name FROM curricula WHERE curriculum_id = :curriculum_id AND department_id = :department_id");
            $curriculumStmt->execute([':curriculum_id' => $data['curriculum_id'], ':department_id' => $departmentId]);
            $curriculum = $curriculumStmt->fetch(PDO::FETCH_ASSOC);
            if (!$curriculum) {
                return [
                    'code' => 400,
                    'data' => ['error' => "Invalid curriculum selected or not in your department."]
                ];
            }

            // Validate Course (must be part of the curriculum)
            $courseStmt = $this->db->prepare("
                SELECT c.course_id, c.course_code, c.course_name 
                FROM courses c 
                JOIN curriculum_courses cc ON c.course_id = cc.course_id 
                WHERE c.course_id = :course_id 
                AND cc.curriculum_id = :curriculum_id 
                AND c.department_id = :department_id
            ");
            $courseStmt->execute([
                ':course_id' => $data['course_id'],
                ':curriculum_id' => $data['curriculum_id'],
                ':department_id' => $departmentId
            ]);
            $course = $courseStmt->fetch(PDO::FETCH_ASSOC);
            if (!$course) {
                return [
                    'code' => 400,
                    'data' => ['error' => "Invalid course selected or not part of the curriculum."]
                ];
            }

            // Validate Faculty
            $facultyStmt = $this->db->prepare("
                SELECT f.faculty_id, CONCAT(u.first_name, ' ', u.last_name) AS name 
                FROM faculty f 
                JOIN users u ON f.user_id = u.user_id 
                WHERE f.faculty_id = :faculty_id 
                AND u.department_id = :department_id
            ");
            $facultyStmt->execute([':faculty_id' => $data['faculty_id'], ':department_id' => $departmentId]);
            $faculty = $facultyStmt->fetch(PDO::FETCH_ASSOC);
            if (!$faculty) {
                return [
                    'code' => 400,
                    'data' => ['error' => "Invalid faculty selected or not in your department."]
                ];
            }

            // Validate Section
            $sectionStmt = $this->db->prepare("
                SELECT s.section_id, s.section_name 
                FROM sections s 
                WHERE s.section_id = :section_id 
                AND s.department_id = :department_id 
                AND s.curriculum_id = :curriculum_id
            ");
            $sectionStmt->execute([
                ':section_id' => $data['section_id'],
                ':department_id' => $departmentId,
                ':curriculum_id' => $data['curriculum_id']
            ]);
            $section = $sectionStmt->fetch(PDO::FETCH_ASSOC);
            if (!$section) {
                return [
                    'code' => 400,
                    'data' => ['error' => "Invalid section selected or not in your department/curriculum."]
                ];
            }

            // Validate Room (if not Asynchronous)
            if ($data['schedule_type'] !== 'Asynchronous') {
                $roomStmt = $this->db->prepare("
                    SELECT room_id, room_name 
                    FROM classrooms 
                    WHERE room_id = :room_id 
                    AND (department_id = :department_id OR (shared = 1 AND availability = 'available'))
                ");
                $roomStmt->execute([':room_id' => $data['room_id'], ':department_id' => $departmentId]);
                $room = $roomStmt->fetch(PDO::FETCH_ASSOC);
                if (!$room) {
                    return [
                        'code' => 400,
                        'data' => ['error' => "Invalid room selected or not available."]
                    ];
                }
            } else {
                $data['room_id'] = null; // No room for asynchronous schedules
            }

            // Validate Day and Time
            $validDays = ['Monday', 'Tuesday', 'Wednesday', 'Thursday', 'Friday', 'Saturday'];
            if (!in_array($data['day_of_week'], $validDays)) {
                return [
                    'code' => 400,
                    'data' => ['error' => "Invalid day of week."]
                ];
            }
            if (!preg_match('/^\d{2}:\d{2}$/', $data['start_time']) || !preg_match('/^\d{2}:\d{2}$/', $data['end_time'])) {
                return [
                    'code' => 400,
                    'data' => ['error' => "Invalid time format."]
                ];
            }
            if (strtotime($data['start_time']) >= strtotime($data['end_time'])) {
                return [
                    'code' => 400,
                    'data' => ['error' => "End time must be after start time."]
                ];
            }

            // Check for conflicts
            $conflictStmt = $this->db->prepare("
                SELECT COUNT(*) 
                FROM schedules 
                WHERE semester_id = :semester_id 
                AND (faculty_id = :faculty_id OR room_id = :room_id)
                AND day_of_week = :day_of_week
                AND (
                    (start_time <= :start_time AND end_time > :start_time) OR
                    (start_time < :end_time AND end_time >= :end_time) OR
                    (start_time >= :start_time AND end_time <= :end_time)
                )
            ");
            $conflictStmt->execute([
                ':semester_id' => $data['semester_id'],
                ':faculty_id' => $data['faculty_id'],
                ':room_id' => $data['room_id'] ?? null,
                ':day_of_week' => $data['day_of_week'],
                ':start_time' => $data['start_time'],
                ':end_time' => $data['end_time']
            ]);
            if ($conflictStmt->fetchColumn() > 0) {
                return [
                    'code' => 409,
                    'data' => ['error' => "Schedule conflict detected for faculty or room."]
                ];
            }

            // Insert schedule
            $insertStmt = $this->db->prepare("
                INSERT INTO schedules (
                    course_id, faculty_id, room_id, section_id, curriculum_id, 
                    schedule_type, day_of_week, start_time, end_time, semester_id
                ) VALUES (
                    :course_id, :faculty_id, :room_id, :section_id, :curriculum_id, 
                    :schedule_type, :day_of_week, :start_time, :end_time, :semester_id
                )
            ");
            $insertStmt->execute([
                ':course_id' => $data['course_id'],
                ':faculty_id' => $data['faculty_id'],
                ':room_id' => $data['room_id'],
                ':section_id' => $data['section_id'],
                ':curriculum_id' => $data['curriculum_id'],
                ':schedule_type' => $data['schedule_type'],
                ':day_of_week' => $data['day_of_week'],
                ':start_time' => $data['start_time'],
                ':end_time' => $data['end_time'],
                ':semester_id' => $data['semester_id']
            ]);

            return [
                'code' => 200,
                'data' => [
                    'success' => true,
                    'schedule' => [
                        'course_code' => $course['course_code'],
                        'faculty_name' => $faculty['name'],
                        'room_name' => $room['room_name'] ?? 'N/A',
                        'section_name' => $section['section_name'],
                        'curriculum_name' => $curriculum['curriculum_name'],
                        'schedule_type' => $data['schedule_type'],
                        'day_of_week' => $data['day_of_week'],
                        'start_time' => $data['start_time'],
                        'end_time' => $data['end_time']
                    ]
                ]
            ];
        } catch (PDOException $e) {
            error_log("SchedulingService: Error creating schedule - " . $e->getMessage());
            return [
                'code' => 500,
                'data' => ['error' => "Failed to create schedule: " . $e->getMessage()]
            ];
        }
    }

    /**
     * Assign faculty to a course offering
     */
    private function assignFaculty($data)
    {
        $requiredFields = ['offering_id', 'faculty_id', 'section_id'];

        foreach ($requiredFields as $field) {
            if (!isset($data[$field])) {
                throw new Exception("Missing required field: $field", 400);
            }
        }

        // Check faculty load
        $loadQuery = "SELECT SUM(c.lecture_hours + c.lab_hours) as current_load
                     FROM teaching_loads tl
                     JOIN course_offerings co ON tl.offering_id = co.offering_id
                     JOIN courses c ON co.course_id = c.course_id
                     WHERE tl.faculty_id = ? AND tl.status = 'Approved'";

        $stmt = $this->conn->prepare($loadQuery);
        $stmt->bind_param('i', $data['faculty_id']);
        $stmt->execute();
        $result = $stmt->get_result()->fetch_assoc();
        $currentLoad = $result['current_load'] ?? 0;

        // Get the course hours for this offering
        $courseQuery = "SELECT c.lecture_hours + c.lab_hours as course_hours
                       FROM course_offerings co
                       JOIN courses c ON co.course_id = c.course_id
                       WHERE co.offering_id = ?";

        $stmt = $this->conn->prepare($courseQuery);
        $stmt->bind_param('i', $data['offering_id']);
        $stmt->execute();
        $result = $stmt->get_result()->fetch_assoc();
        $courseHours = $result['course_hours'] ?? 0;

        // Check if this would exceed faculty max hours
        $facultyQuery = "SELECT max_hours FROM faculty WHERE faculty_id = ?";
        $stmt = $this->conn->prepare($facultyQuery);
        $stmt->bind_param('i', $data['faculty_id']);
        $stmt->execute();
        $result = $stmt->get_result()->fetch_assoc();
        $maxHours = $result['max_hours'] ?? 18;

        if (($currentLoad + $courseHours) > $maxHours) {
            throw new Exception("This assignment would exceed faculty's maximum teaching load", 400);
        }

        // Insert the teaching load
        $insertQuery = "INSERT INTO teaching_loads 
                       (faculty_id, offering_id, section_id, assigned_hours, status) 
                       VALUES (?, ?, ?, ?, 'Proposed')";

        $stmt = $this->conn->prepare($insertQuery);
        $stmt->bind_param(
            'iiii',
            $data['faculty_id'],
            $data['offering_id'],
            $data['section_id'],
            $courseHours
        );

        if (!$stmt->execute()) {
            throw new Exception("Failed to assign faculty: " . $stmt->error, 500);
        }

        // Log the activity
        $this->logActivity(
            $_SESSION['user_id'] ?? null,
            'assign_faculty',
            "Assigned faculty ID {$data['faculty_id']} to offering ID {$data['offering_id']}",
            'teaching_loads',
            $stmt->insert_id
        );

        echo json_encode(['success' => true]);
    }

    /**
     * Reserve a room for a special event
     */
    private function reserveRoom($data)
    {
        $requiredFields = ['room_id', 'event_name', 'date', 'start_time', 'end_time'];

        foreach ($requiredFields as $field) {
            if (!isset($data[$field])) {
                throw new Exception("Missing required field: $field", 400);
            }
        }

        // Convert date to day of week
        $dayOfWeek = date('l', strtotime($data['date']));

        // Check for room conflict
        $conflictCheck = "SELECT 1 FROM schedules 
                         WHERE room_id = ? 
                         AND day_of_week = ? 
                         AND ((start_time <= ? AND end_time > ?)
                         OR (start_time < ? AND end_time >= ?)
                         OR (start_time >= ? AND end_time <= ?))";

        $stmt = $this->conn->prepare($conflictCheck);
        $stmt->bind_param(
            'isssssss',
            $data['room_id'],
            $dayOfWeek,
            $data['start_time'],
            $data['start_time'],
            $data['end_time'],
            $data['end_time'],
            $data['start_time'],
            $data['end_time']
        );
        $stmt->execute();

        if ($stmt->get_result()->num_rows > 0) {
            throw new Exception("Room is already booked at this time", 409);
        }

        // Check for existing reservation conflict
        $reservationConflict = "SELECT 1 FROM room_reservations 
                               WHERE room_id = ? 
                               AND date = ? 
                               AND ((start_time <= ? AND end_time > ?)
                               OR (start_time < ? AND end_time >= ?)
                               OR (start_time >= ? AND end_time <= ?))
                               AND approval_status = 'Approved'";

        $stmt = $this->conn->prepare($reservationConflict);
        $stmt->bind_param(
            'isssssss',
            $data['room_id'],
            $data['date'],
            $data['start_time'],
            $data['start_time'],
            $data['end_time'],
            $data['end_time'],
            $data['start_time'],
            $data['end_time']
        );
        $stmt->execute();

        if ($stmt->get_result()->num_rows > 0) {
            throw new Exception("Room is already reserved at this time", 409);
        }

        // Insert the reservation
        $insertQuery = "INSERT INTO room_reservations 
                       (room_id, reserved_by, event_name, description, 
                       date, start_time, end_time, approval_status) 
                       VALUES (?, ?, ?, ?, ?, ?, ?, 'Pending')";

        $stmt = $this->conn->prepare($insertQuery);
        $stmt->bind_param(
            'iisssss',
            $data['room_id'],
            $_SESSION['user_id'] ?? null,
            $data['event_name'],
            $data['description'] ?? null,
            $data['date'],
            $data['start_time'],
            $data['end_time']
        );

        if (!$stmt->execute()) {
            throw new Exception("Failed to reserve room: " . $stmt->error, 500);
        }

        // Log the activity
        $this->logActivity(
            $_SESSION['user_id'] ?? null,
            'room_reservation',
            "Reserved room ID {$data['room_id']} for {$data['event_name']}",
            'room_reservations',
            $stmt->insert_id
        );

        echo json_encode([
            'success' => true,
            'reservation_id' => $stmt->insert_id
        ]);
    }

    // ======================== PUT Endpoint Implementations ========================

    /**
     * Update an existing schedule
     */
    private function updateSchedule($data)
    {
        $requiredFields = ['schedule_id'];

        foreach ($requiredFields as $field) {
            if (!isset($data[$field])) {
                throw new Exception("Missing required field: $field", 400);
            }
        }

        // Get current schedule data
        $currentQuery = "SELECT * FROM schedules WHERE schedule_id = ?";
        $stmt = $this->conn->prepare($currentQuery);
        $stmt->bind_param('i', $data['schedule_id']);
        $stmt->execute();
        $current = $stmt->get_result()->fetch_assoc();

        if (!$current) {
            throw new Exception("Schedule not found", 404);
        }

        // Check if schedule is already approved
        if ($current['status'] == 'Approved') {
            throw new Exception("Cannot modify an approved schedule. Create a change request instead.", 400);
        }

        // Build update query based on provided fields
        $updates = [];
        $params = [];
        $types = '';

        $updatableFields = [
            'course_id',
            'section_id',
            'room_id',
            'semester_id',
            'faculty_id',
            'schedule_type',
            'day_of_week',
            'start_time',
            'end_time',
            'is_public'
        ];

        foreach ($updatableFields as $field) {
            if (isset($data[$field])) {
                $updates[] = "$field = ?";
                $params[] = $data[$field];
                $types .= $this->getParamType($data[$field]);
            }
        }

        if (empty($updates)) {
            throw new Exception("No fields to update", 400);
        }

        // Add schedule_id to params
        $params[] = $data['schedule_id'];
        $types .= 'i';

        $updateQuery = "UPDATE schedules SET " . implode(', ', $updates) . " WHERE schedule_id = ?";
        $stmt = $this->conn->prepare($updateQuery);
        $stmt->bind_param($types, ...$params);

        if (!$stmt->execute()) {
            throw new Exception("Failed to update schedule: " . $stmt->error, 500);
        }

        // Log the activity
        $this->logActivity(
            $_SESSION['user_id'] ?? null,
            'update_schedule',
            "Updated schedule ID {$data['schedule_id']}",
            'schedules',
            $data['schedule_id']
        );

        echo json_encode(['success' => true]);
    }

    /**
     * Approve a schedule
     */
    private function approveSchedule($data)
    {
        $requiredFields = ['schedule_id'];

        foreach ($requiredFields as $field) {
            if (!isset($data[$field])) {
                throw new Exception("Missing required field: $field", 400);
            }
        }

        // Check if user has approval permissions (simplified - in real app would check role)
        if (!isset($_SESSION['user_id'])) {
            throw new Exception("Unauthorized", 401);
        }

        $updateQuery = "UPDATE schedules 
                       SET status = 'Approved', 
                           approved_by = ?,
                           approval_date = NOW() 
                       WHERE schedule_id = ?";

        $stmt = $this->conn->prepare($updateQuery);
        $stmt->bind_param('ii', $_SESSION['user_id'], $data['schedule_id']);

        if (!$stmt->execute()) {
            throw new Exception("Failed to approve schedule: " . $stmt->error, 500);
        }

        // Log the activity
        $this->logActivity(
            $_SESSION['user_id'],
            'approve_schedule',
            "Approved schedule ID {$data['schedule_id']}",
            'schedules',
            $data['schedule_id']
        );

        echo json_encode(['success' => true]);
    }

    // ======================== DELETE Endpoint Implementations ========================

    /**
     * Delete a schedule
     */
    private function deleteSchedule($data)
    {
        $requiredFields = ['schedule_id'];

        foreach ($requiredFields as $field) {
            if (!isset($data[$field])) {
                throw new Exception("Missing required field: $field", 400);
            }
        }

        // Check if schedule exists and is not approved
        $checkQuery = "SELECT status FROM schedules WHERE schedule_id = ?";
        $stmt = $this->conn->prepare($checkQuery);
        $stmt->bind_param('i', $data['schedule_id']);
        $stmt->execute();
        $result = $stmt->get_result()->fetch_assoc();

        if (!$result) {
            throw new Exception("Schedule not found", 404);
        }

        if ($result['status'] == 'Approved') {
            throw new Exception("Cannot delete an approved schedule", 400);
        }

        // Delete the schedule
        $deleteQuery = "DELETE FROM schedules WHERE schedule_id = ?";
        $stmt = $this->conn->prepare($deleteQuery);
        $stmt->bind_param('i', $data['schedule_id']);

        if (!$stmt->execute()) {
            throw new Exception("Failed to delete schedule: " . $stmt->error, 500);
        }

        // Log the activity
        $this->logActivity(
            $_SESSION['user_id'] ?? null,
            'delete_schedule',
            "Deleted schedule ID {$data['schedule_id']}",
            'schedules',
            $data['schedule_id']
        );

        echo json_encode(['success' => true]);
    }

    // ======================== Helper Methods ========================

    /**
     * Log activity to the database
     */
    private function logActivity($userId, $actionType, $description, $entityType = null, $entityId = null)
    {
        $query = "INSERT INTO activity_logs 
                 (user_id, action_type, action_description, entity_type, entity_id) 
                 VALUES (?, ?, ?, ?, ?)";

        $stmt = $this->conn->prepare($query);
        $stmt->bind_param('isssi', $userId, $actionType, $description, $entityType, $entityId);
        $stmt->execute();
    }

    /**
     * Get parameter type for bind_param
     */
    private function getParamType($value)
    {
        if (is_int($value)) return 'i';
        if (is_double($value)) return 'd';
        return 's';
    }

    /**
     * Get user's complete name with title, first name, middle name, last name, and suffix
     */
    public function getUserCompleteName($userId)
    {
        try {
            $stmt = $this->db->prepare("
            SELECT title, first_name, middle_name, last_name, suffix 
            FROM users 
            WHERE user_id = :user_id
        ");
            $stmt->execute([':user_id' => $userId]);
            $user = $stmt->fetch(PDO::FETCH_ASSOC);

            if ($user) {
                return $this->formatUserNameFromData($user);
            }
            return "User #" . $userId;
        } catch (PDOException $e) {
            error_log("getUserCompleteName: Failed to get user name - " . $e->getMessage());
            return "User #" . $userId;
        }
    }

    /**
     * Format user name from user data array
     */
    private function formatUserNameFromData($userData)
    {
        $nameParts = [];

        // Add title if exists
        if (!empty($userData['title'])) {
            $nameParts[] = $userData['title'];
        }

        // Add first name
        if (!empty($userData['first_name'])) {
            $nameParts[] = $userData['first_name'];
        }

        // Add middle name (just initial if exists)
        if (!empty($userData['middle_name'])) {
            $nameParts[] = substr($userData['middle_name'], 0, 1) . '.';
        }

        // Add last name
        if (!empty($userData['last_name'])) {
            $nameParts[] = $userData['last_name'];
        }

        // Add suffix if exists
        if (!empty($userData['suffix'])) {
            $nameParts[] = $userData['suffix'];
        }

        return implode(' ', $nameParts);
    }

    /**
     * Format action description by replacing user_id with user name
     */
    public function formatActionDescription($description, $userId, $userName)
    {
        // Replace user_id=X with user: [User Name]
        $description = preg_replace(
            '/user_id=(\d+)/',
            'user: ' . $userName,
            $description
        );

        // Also handle other common patterns
        $description = str_replace(
            ['user_id=' . $userId, 'user ' . $userId],
            ['user: ' . $userName, 'user ' . $userName],
            $description
        );

        return $description;
    }

    /**
     * Helper function to determine load status
     */
    public function getLoadStatus($totalWorkingLoad, $excessHours)
    {
        if ($totalWorkingLoad == 0) {
            return 'No Load';
        } elseif ($excessHours > 0) {
            return 'Overload';
        } elseif ($totalWorkingLoad < 18) {
            return 'Underload';
        } else {
            return 'Normal Load';
        }
    }
    
}




