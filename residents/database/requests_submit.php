<?php
session_start();
include 'config.php';

if (!isset($_SESSION['user_id'])) {
    echo "Not logged in";
    exit;
}

$user_id = $_SESSION['user_id'];
$service_id = $_POST['service_id'] ?? '';
$purpose = $_POST['purpose'] ?? '';

if (!$service_id || !$purpose) {
    echo "All fields required!";
    exit;
}

// get resident_id + address_id
$resSql = "SELECT id, address_id FROM residents WHERE user_id = ?";
$resStmt = $conn->prepare($resSql);
$resStmt->bind_param("i", $user_id);
$resStmt->execute();
$res = $resStmt->get_result()->fetch_assoc();

if (!$res) {
    echo "No resident record found.";
    exit;
}

$resident_id = $res['id'];
$address_id = $res['address_id'];

// insert request
$sql = "INSERT INTO requests (address_id, resident_id, service_id, purpose, request_date, status) 
        VALUES (?,?,?,?,NOW(),'Pending')";
$stmt = $conn->prepare($sql);
$stmt->bind_param("iiis", $address_id, $resident_id, $service_id, $purpose);

if ($stmt->execute()) {
    echo "Request submitted successfully!";
} else {
    echo "Error: " . $conn->error;
}
