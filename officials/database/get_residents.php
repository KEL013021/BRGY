<?php
session_start();
require '../database/config.php';
header('Content-Type: application/json');

// 🟢 Check kung naka-login
if (!isset($_SESSION['user_id'])) {
    echo json_encode(['error' => 'Not logged in']);
    exit;
}

$userId = $_SESSION['user_id'];

// 🟢 Kunin ang address_id ng logged-in user
$address_id = null;
$sqlAddr = "SELECT address_id FROM address WHERE user_id = ?";
$stmtAddr = $conn->prepare($sqlAddr);
$stmtAddr->bind_param("i", $userId);
$stmtAddr->execute();
$resAddr = $stmtAddr->get_result();

if ($row = $resAddr->fetch_assoc()) {
    $address_id = (int)$row['address_id'];
} else {
    echo json_encode(['error' => 'No address found for this user']);
    exit;
}

// 🟢 Search keyword (optional)
$search = isset($_GET['q']) ? trim($_GET['q']) : '';

// 🟢 Fetch residents para sa address_id na ito
$sql = "
    SELECT r.id,
           r.first_name,
           r.middle_name,
           r.last_name,
           r.image_url,
           bo.position AS assigned_position
    FROM residents r
    LEFT JOIN barangay_official bo
        ON bo.resident_id = r.id
       AND bo.address_id = ?
    WHERE r.address_id = ?
      AND CONCAT(r.first_name, ' ', r.middle_name, ' ', r.last_name) LIKE ?
    ORDER BY r.last_name ASC
";

$stmt = $conn->prepare($sql);
$like = "%{$search}%";
$stmt->bind_param("iis", $address_id, $address_id, $like);
$stmt->execute();
$result = $stmt->get_result();

$residents = [];
while ($row = $result->fetch_assoc()) {
    $residents[] = [
        'id'       => (int)$row['id'],
        'name'     => strtoupper(trim($row['first_name'].' '.$row['middle_name'].' '.$row['last_name'])),
        'image'    => $row['image_url']
                        ? "../uploads/residents/{$row['image_url']}"
                        : "../uploads/residents/default.jpg",
        'assigned' => $row['assigned_position'] ?? ''
    ];
}

echo json_encode($residents);
