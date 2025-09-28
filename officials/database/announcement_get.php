<?php
include('config.php');

if (!isset($_GET['id'])) {
    echo json_encode(["error" => "No ID provided."]);
    exit;
}

$id = intval($_GET['id']);

$sql = "SELECT id, address_id, title, content, image, date_posted 
        FROM announcement 
        WHERE id = ?";
$stmt = $conn->prepare($sql);
$stmt->bind_param("i", $id);
$stmt->execute();
$result = $stmt->get_result();

if ($row = $result->fetch_assoc()) {
    echo json_encode($row);
} else {
    echo json_encode(["error" => "Announcement not found."]);
}

$stmt->close();
$conn->close();
?>
