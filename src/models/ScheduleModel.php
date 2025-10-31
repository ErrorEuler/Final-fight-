<?php
require_once __DIR__ . '/../config/Database.php';

class ScheduleModel
{
    private $db;

    public function __construct($db)
    {
        $this->db = (new Database())->connect();
        $this->db->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
    }

    /**
     * Fetch schedules by faculty ID for a given semester
     * @param int $facultyId
     * @param int $semesterId
     * @return array
     */
    public function getSchedulesByFaculty($facultyId, $semesterId)
    {
        try {
            $query = "
                SELECT s.schedule_id, s.day_of_week, s.start_time, s.end_time, s.schedule_type,
                       s.status, c.course_code, c.course_name, sec.section_name,
                       r.room_name, r.building
                FROM schedules s
                JOIN courses c ON s.course_id = c.course_id
                JOIN sections sec ON s.section_id = sec.section_id
                LEFT JOIN classrooms r ON s.room_id = r.room_id
                WHERE s.faculty_id = :facultyId AND s.semester_id = :semesterId
                ORDER BY s.day_of_week, s.start_time
            ";
            $stmt = $this->db->prepare($query);
            $stmt->bindParam(':facultyId', $facultyId, PDO::PARAM_INT);
            $stmt->bindParam(':semesterId', $semesterId, PDO::PARAM_INT);
            $stmt->execute();
            return $stmt->fetchAll(PDO::FETCH_ASSOC);
        } catch (PDOException $e) {
            error_log("Error fetching schedules by faculty: " . $e->getMessage());
            return [];
        }
    }

    /**
     * Fetch schedules by course ID for a given semester
     * @param int $courseId
     * @param int $semesterId
     * @return array
     */
    public function getSchedulesByCourse($courseId, $semesterId)
    {
        try {
            $query = "
                SELECT s.schedule_id, s.day_of_week, s.start_time, s.end_time, s.schedule_type,
                       s.status, sec.section_name, r.room_name, r.building,
                       u.first_name, u.last_name
                FROM schedules s
                JOIN sections sec ON s.section_id = sec.section_id
                LEFT JOIN classrooms r ON s.room_id = r.room_id
                JOIN faculty f ON s.faculty_id = f.faculty_id
                JOIN users u ON f.user_id = u.user_id
                WHERE s.course_id = :courseId AND s.semester_id = :semesterId
                ORDER BY s.day_of_week, s.start_time
            ";
            $stmt = $this->db->prepare($query);
            $stmt->bindParam(':courseId', $courseId, PDO::PARAM_INT);
            $stmt->bindParam(':semesterId', $semesterId, PDO::PARAM_INT);
            $stmt->execute();
            return $stmt->fetchAll(PDO::FETCH_ASSOC);
        } catch (PDOException $e) {
            error_log("Error fetching schedules by course: " . $e->getMessage());
            return [];
        }
    }

    /**
     * Fetch available classrooms for a given date and time
     * @param string $date (YYYY-MM-DD)
     * @param string $startTime (HH:MM:SS)
     * @param string $endTime (HH:MM:SS)
     * @return array
     */
    public function getAvailableClassrooms($date, $startTime, $endTime)
    {
        try {
            $query = "
                SELECT c.room_id, c.room_name, c.building, c.capacity, c.room_type
                FROM classrooms c
                WHERE c.availability = 'available'
                AND c.room_id NOT IN (
                    SELECT s.room_id
                    FROM schedules s
                    WHERE s.day_of_week = DAYNAME(:date)
                    AND s.semester_id IN (
                        SELECT semester_id
                        FROM semesters
                        WHERE :date BETWEEN start_date AND end_date
                    )
                    AND (
                        (s.start_time <= :startTime AND s.end_time > :startTime)
                        OR (s.start_time < :endTime AND s.end_time >= :endTime)
                        OR (s.start_time >= :startTime AND s.end_time <= :endTime)
                    )
                )
                AND c.room_id NOT IN (
                    SELECT rr.room_id
                    FROM room_reservations rr
                    WHERE rr.date = :date
                    AND (
                        (rr.start_time <= :startTime AND rr.end_time > :startTime)
                        OR (rr.start_time < :endTime AND rr.end_time >= :endTime)
                        OR (rr.start_time >= :startTime AND rr.end_time <= :endTime)
                    )
                    AND rr.approval_status = 'Approved'
                )
                ORDER BY c.room_name
            ";
            $stmt = $this->db->prepare($query);
            $stmt->bindParam(':date', $date, PDO::PARAM_STR);
            $stmt->bindParam(':startTime', $startTime, PDO::PARAM_STR);
            $stmt->bindParam(':endTime', $endTime, PDO::PARAM_STR);
            $stmt->execute();
            return $stmt->fetchAll(PDO::FETCH_ASSOC);
        } catch (PDOException $e) {
            error_log("Error fetching available classrooms: " . $e->getMessage());
            return [];
        }
    }

    /**
     * Create a new schedule
     * @param array $data
     * @return bool
     */
    public function createSchedule($data)
    {
        try {
            $query = "
                INSERT INTO schedules (
                    course_id, section_id, room_id, semester_id, faculty_id, schedule_type,
                    day_of_week, start_time, end_time, status, approved_by, is_public
                ) VALUES (
                    :course_id, :section_id, :room_id, :semester_id, :faculty_id, :schedule_type,
                    :day_of_week, :start_time, :end_time, :status, :approved_by, :is_public
                )
            ";
            $stmt = $this->db->prepare($query);
            $stmt->bindParam(':course_id', $data['course_id'], PDO::PARAM_INT);
            $stmt->bindParam(':section_id', $data['section_id'], PDO::PARAM_INT);
            $stmt->bindParam(':room_id', $data['room_id'], PDO::PARAM_INT);
            $stmt->bindParam(':semester_id', $data['semester_id'], PDO::PARAM_INT);
            $stmt->bindParam(':faculty_id', $data['faculty_id'], PDO::PARAM_INT);
            $stmt->bindParam(':schedule_type', $data['schedule_type'], PDO::PARAM_STR);
            $stmt->bindParam(':day_of_week', $data['day_of_week'], PDO::PARAM_STR);
            $stmt->bindParam(':start_time', $data['start_time'], PDO::PARAM_STR);
            $stmt->bindParam(':end_time', $data['end_time'], PDO::PARAM_STR);
            $stmt->bindParam(':status', $data['status'], PDO::PARAM_STR);
            $stmt->bindParam(':approved_by', $data['approved_by'], PDO::PARAM_INT);
            $stmt->bindParam(':is_public', $data['is_public'], PDO::PARAM_INT);
            return $stmt->execute();
        } catch (PDOException $e) {
            error_log("Error creating schedule: " . $e->getMessage());
            return false;
        }
    }

    /**
     * Update an existing schedule
     * @param int $scheduleId
     * @param array $data
     * @return bool
     */
    public function updateSchedule($scheduleId, $data)
    {
        try {
            $query = "
                UPDATE schedules
                SET course_id = :course_id,
                    section_id = :section_id,
                    room_id = :room_id,
                    semester_id = :semester_id,
                    faculty_id = :faculty_id,
                    schedule_type = :schedule_type,
                    day_of_week = :day_of_week,
                    start_time = :start_time,
                    end_time = :end_time,
                    status = :status,
                    approved_by = :approved_by,
                    is_public = :is_public
                WHERE schedule_id = :schedule_id
            ";
            $stmt = $this->db->prepare($query);
            $stmt->bindParam(':course_id', $data['course_id'], PDO::PARAM_INT);
            $stmt->bindParam(':section_id', $data['section_id'], PDO::PARAM_INT);
            $stmt->bindParam(':room_id', $data['room_id'], PDO::PARAM_INT);
            $stmt->bindParam(':semester_id', $data['semester_id'], PDO::PARAM_INT);
            $stmt->bindParam(':faculty_id', $data['faculty_id'], PDO::PARAM_INT);
            $stmt->bindParam(':schedule_type', $data['schedule_type'], PDO::PARAM_STR);
            $stmt->bindParam(':day_of_week', $data['day_of_week'], PDO::PARAM_STR);
            $stmt->bindParam(':start_time', $data['start_time'], PDO::PARAM_STR);
            $stmt->bindParam(':end_time', $data['end_time'], PDO::PARAM_STR);
            $stmt->bindParam(':status', $data['status'], PDO::PARAM_STR);
            $stmt->bindParam(':approved_by', $data['approved_by'], PDO::PARAM_INT);
            $stmt->bindParam(':is_public', $data['is_public'], PDO::PARAM_INT);
            $stmt->bindParam(':schedule_id', $scheduleId, PDO::PARAM_INT);
            return $stmt->execute();
        } catch (PDOException $e) {
            error_log("Error updating schedule: " . $e->getMessage());
            return false;
        }
    }

    /**
     * Delete a schedule (soft delete by setting status to Rejected)
     * @param int $scheduleId
     * @return bool
     */
    public function deleteSchedule($scheduleId)
    {
        try {
            $query = "UPDATE schedules SET status = 'Rejected' WHERE schedule_id = :schedule_id";
            $stmt = $this->db->prepare($query);
            $stmt->bindParam(':schedule_id', $scheduleId, PDO::PARAM_INT);
            return $stmt->execute();
        } catch (PDOException $e) {
            error_log("Error deleting schedule: " . $e->getMessage());
            return false;
        }
    }

    /**
     * Create a teaching load assignment
     * @param array $data
     * @return bool
     */
    public function createTeachingLoad($data)
    {
        try {
            $query = "
                INSERT INTO teaching_loads (
                    faculty_id, offering_id, section_id, assigned_hours, status, assigned_by
                ) VALUES (
                    :faculty_id, :offering_id, :section_id, :assigned_hours, :status, :assigned_by
                )
            ";
            $stmt = $this->db->prepare($query);
            $stmt->bindParam(':faculty_id', $data['faculty_id'], PDO::PARAM_INT);
            $stmt->bindParam(':offering_id', $data['offering_id'], PDO::PARAM_INT);
            $stmt->bindParam(':section_id', $data['section_id'], PDO::PARAM_INT);
            $stmt->bindParam(':assigned_hours', $data['assigned_hours'], PDO::PARAM_INT);
            $stmt->bindParam(':status', $data['status'], PDO::PARAM_STR);
            $stmt->bindParam(':assigned_by', $data['assigned_by'], PDO::PARAM_INT);
            return $stmt->execute();
        } catch (PDOException $e) {
            error_log("Error creating teaching load: " . $e->getMessage());
            return false;
        }
    }

    /**
     * Fetch teaching loads by faculty ID
     * @param int $facultyId
     * @return array
     */
    public function getTeachingLoadsByFaculty($facultyId)
    {
        try {
            $query = "
                SELECT tl.load_id, tl.assigned_hours, tl.status, c.course_code, c.course_name,
                       sec.section_name, co.expected_students
                FROM teaching_loads tl
                JOIN course_offerings co ON tl.offering_id = co.offering_id
                JOIN courses c ON co.course_id = c.course_id
                JOIN sections sec ON tl.section_id = sec.section_id
                WHERE tl.faculty_id = :facultyId AND tl.status = 'Approved'
                ORDER BY c.course_code, sec.section_name
            ";
            $stmt = $this->db->prepare($query);
            $stmt->bindParam(':facultyId', $facultyId, PDO::PARAM_INT);
            $stmt->execute();
            return $stmt->fetchAll(PDO::FETCH_ASSOC);
        } catch (PDOException $e) {
            error_log("Error fetching teaching loads: " . $e->getMessage());
            return [];
        }
    }
}
