<?php
session_start();
include 'config.php';

$user_id = $_SESSION['user_id'];
$evacuation_id = $_POST['evacuation_id'] ?? null;
$lat = $_POST['lat'] ?? null;
$lng = $_POST['lng'] ?? null;

if (!$user_id || !$evacuation_id) {
    http_response_code(400);
    echo "Missing data";
    exit;
}

// Check kung resident info
$res = $conn->prepare("SELECT id FROM residents WHERE user_id=?");
$res->bind_param("i", $user_id);
$res->execute();
$resRow = $res->get_result()->fetch_assoc();

if (!$resRow) {
    http_response_code(404);
    echo "Resident not found";
    exit;
}

$resident_id = $resRow['id'];

// Check kung already nasa evacuees
$check = $conn->prepare("SELECT id FROM evacuees WHERE resident_id=? AND evacuation_id=?");
$check->bind_param("ii", $resident_id, $evacuation_id);
$check->execute();
$checkRow = $check->get_result()->fetch_assoc();

if (!$checkRow) {
    $stmt = $conn->prepare("INSERT INTO evacuees (resident_id, evacuation_id, latitude, longitude, arrived_at) VALUES (?,?,?,?,NOW())");
    $stmt->bind_param("iidd", $resident_id, $evacuation_id, $lat, $lng);
    $stmt->execute();
}

echo "✅ Added to evacuees";
