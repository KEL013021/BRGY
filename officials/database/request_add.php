<?php
session_start();
include('../database/config.php');

$data = json_decode(file_get_contents("php://input"), true);

$resident_id = $data['resident_id'] ?? null;
$service_id  = $data['service_id'] ?? null;
$purpose     = $data['purpose'] ?? null;
$address_id  = null;

if (!isset($_SESSION['user_id'])) {
    echo json_encode(["success" => false, "error" => "User not logged in"]);
    exit;
}

// Kunin address_id ng logged-in user
$sqlAddr = "SELECT address_id FROM address WHERE user_id = ?";
$stmtAddr = $conn->prepare($sqlAddr);
$stmtAddr->bind_param("i", $_SESSION['user_id']);
$stmtAddr->execute();
$resultAddr = $stmtAddr->get_result();
if ($rowAddr = $resultAddr->fetch_assoc()) {
    $address_id = $rowAddr['address_id'];
} else {
    echo json_encode(["success" => false, "error" => "No address found"]);
    exit;
}

// Insert request
$sql = "INSERT INTO requests (resident_id, service_id, purpose, address_id, request_date, status) 
        VALUES (?, ?, ?, ?, NOW(), 'Pending')";
$stmt = $conn->prepare($sql);
$stmt->bind_param("iisi", $resident_id, $service_id, $purpose, $address_id);

if ($stmt->execute()) {
    echo json_encode(["success" => true]);
} else {
    echo json_encode(["success" => false, "error" => $conn->error]);
}

$conn->close();
