<?php
include('../database/config.php');

header('Content-Type: application/json'); // ✅ para siguradong JSON response

if (isset($_POST['id'])) {
    $emergency_id = intval($_POST['id']);

    $sql = "SELECT 
                e.emergency_id,
                e.emergency_type,
                e.report_time,
                r.first_name,
                r.middle_name,
                r.last_name,
                r.mobile_number,
                r.city,
                r.barangay,
                r.house_number,
                r.image_url,
                e.latitude,
                e.longitude
            FROM emergency e
            JOIN residents r ON e.resident_id = r.id
            WHERE e.emergency_id = ?";

    $stmt = $conn->prepare($sql);
    $stmt->bind_param("i", $emergency_id);
    $stmt->execute();
    $result = $stmt->get_result();

    if ($row = $result->fetch_assoc()) {
        echo json_encode($row);
    } else {
        echo json_encode(["error" => "No data found."]);
    }
} else {
    echo json_encode(["error" => "Invalid request."]);
}
?>
