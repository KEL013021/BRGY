<?php
session_start();
include 'config.php';

if (!isset($_SESSION['user_id'])) {
    echo json_encode([]);
    exit;
}

$user_id = $_SESSION['user_id'];

// get resident_id
$resSql = "SELECT id FROM residents WHERE user_id = ?";
$resStmt = $conn->prepare($resSql);
$resStmt->bind_param("i", $user_id);
$resStmt->execute();
$res = $resStmt->get_result()->fetch_assoc();

if (!$res) {
    echo json_encode([]);
    exit;
}

$resident_id = $res['id'];

// join requests + services
$sql = "SELECT r.id, s.service_name, s.service_fee, r.status 
        FROM requests r
        JOIN services s ON r.service_id = s.id
        WHERE r.resident_id = ?
        ORDER BY r.created_at DESC";
$stmt = $conn->prepare($sql);
$stmt->bind_param("i", $resident_id);
$stmt->execute();
$result = $stmt->get_result();

$data = [];
while ($row = $result->fetch_assoc()) {
    $data[] = $row;
}
echo json_encode($data);
