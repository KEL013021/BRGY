<?php
session_start();
include('../database/config.php');

if (!isset($_SESSION['user_id'])) {
    echo json_encode([]);
    exit;
}

$user_id = $_SESSION['user_id'];

// Kunin address_id ng user
$sql = "SELECT address_id FROM address WHERE user_id = ?";
$stmt = $conn->prepare($sql);
$stmt->bind_param("i", $user_id);
$stmt->execute();
$res = $stmt->get_result();
$row = $res->fetch_assoc();
$address_id = $row['address_id'] ?? null;

if (!$address_id) {
    echo json_encode([]);
    exit;
}

// Fetch services linked to this barangay
$query = "SELECT id, service_name FROM services WHERE address_id = ?";
$stmt = $conn->prepare($query);
$stmt->bind_param("i", $address_id);
$stmt->execute();
$result = $stmt->get_result();

$services = [];
while ($s = $result->fetch_assoc()) {
    $services[] = $s;
}

echo json_encode($services);
$conn->close();
