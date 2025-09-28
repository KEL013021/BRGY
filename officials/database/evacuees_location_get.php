<?php
include('config.php');

header('Content-Type: application/json');

if (!isset($_GET['evacuation_id'])) {
    echo json_encode(["error" => "Missing evacuation_id"]);
    exit;
}

$evacuation_id = intval($_GET['evacuation_id']);

$sql = "SELECT ul.resident_id, 
               ul.latitude, 
               ul.longitude,
               CONCAT(r.first_name, ' ', r.middle_name, ' ', r.last_name) AS full_name,
               r.image_url AS image_path
        FROM evacuees_locations ul
        JOIN residents r ON ul.resident_id = r.id
        WHERE ul.evacuation_id = $evacuation_id";

$result = mysqli_query($conn, $sql);

if (!$result) {
    echo json_encode(["error" => mysqli_error($conn), "sql" => $sql]);
    exit;
}

$data = [];
while ($row = mysqli_fetch_assoc($result)) {
    // Optional: kung gusto mo gawing full URL yung image
    $row['image_url'] = !empty($row['image_path']) ? '../uploads/residents/' . $row['image_path'] : null;
    $data[] = $row;
}

echo json_encode($data);
?>
