<?php
include('../database/config.php');

if (!isset($_GET['id'])) {
    echo json_encode(["error" => "Missing evacuation center ID."]);
    exit;
}

$id = intval($_GET['id']);
$sql = "SELECT * FROM evacuation_centers WHERE id = ?";
$stmt = $conn->prepare($sql);
$stmt->bind_param("i", $id);
$stmt->execute();
$result = $stmt->get_result();

if ($row = $result->fetch_assoc()) {
    echo json_encode($row);
} else {
    echo json_encode(["error" => "Evacuation center not found."]);
}
?>
