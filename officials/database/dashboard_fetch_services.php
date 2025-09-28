<?php
session_start();
header('Content-Type: application/json');
include('../database/config.php');

if (!isset($_SESSION['user_id'])) {
    echo json_encode(['error' => 'Not logged in']);
    exit;
}

$user_id = $_SESSION['user_id'];

// get address_id
$stmt = $conn->prepare("SELECT address_id FROM address WHERE user_id = ?");
$stmt->bind_param("i", $user_id);
$stmt->execute();
$res = $stmt->get_result()->fetch_assoc();
$address_id = $res ? (int)$res['address_id'] : 0;
$stmt->close();

// optional date filters (expected format: YYYY-MM-DD)
$from = isset($_GET['from']) && $_GET['from'] !== '' ? $_GET['from'] : null;
$to   = isset($_GET['to']) && $_GET['to'] !== '' ? $_GET['to'] : null;

/** -------------------------
 * MOST REQUESTED SERVICES (top 5)
 * - keep services even if they have 0 requests in range
 * ------------------------*/
$services = [];

if ($from && $to) {
    $sql = "
        SELECT s.service_name, COUNT(r.id) as total
        FROM services s
        LEFT JOIN requests r 
          ON r.service_id = s.id 
          AND r.address_id = ? 
          AND DATE(r.request_date) BETWEEN ? AND ?
        WHERE s.address_id = ?
        GROUP BY s.service_name
        ORDER BY total DESC
        LIMIT 5
    ";
    $stmt = $conn->prepare($sql);
    $stmt->bind_param("issi", $address_id, $from, $to, $address_id);
} else {
    $sql = "
        SELECT s.service_name, COUNT(r.id) as total
        FROM services s
        LEFT JOIN requests r 
          ON r.service_id = s.id 
          AND r.address_id = ?
        WHERE s.address_id = ?
        GROUP BY s.service_name
        ORDER BY total DESC
        LIMIT 5
    ";
    $stmt = $conn->prepare($sql);
    $stmt->bind_param("ii", $address_id, $address_id);
}

$stmt->execute();
$result = $stmt->get_result();
while ($row = $result->fetch_assoc()) {
    $services[$row['service_name']] = (int)$row['total'];
}
$stmt->close();

/** -------------------------
 * REQUEST PROCESSING TIME
 * (avg days per month) — 12-element array (Jan..Dec)
 * ------------------------*/
$processing = array_fill(0, 12, 0.0);

if ($from && $to) {
    $sql = "
        SELECT MONTH(request_date) as month, AVG(DATEDIFF(created_at, request_date)) as avg_days
        FROM requests
        WHERE address_id = ?
          AND DATE(request_date) BETWEEN ? AND ?
        GROUP BY MONTH(request_date)
    ";
    $stmt = $conn->prepare($sql);
    $stmt->bind_param("iss", $address_id, $from, $to);
} else {
    $sql = "
        SELECT MONTH(request_date) as month, AVG(DATEDIFF(created_at, request_date)) as avg_days
        FROM requests
        WHERE address_id = ?
        GROUP BY MONTH(request_date)
    ";
    $stmt = $conn->prepare($sql);
    $stmt->bind_param("i", $address_id);
}

$stmt->execute();
$result = $stmt->get_result();
while ($row = $result->fetch_assoc()) {
    $m = intval($row['month']) - 1; // 0-based index
    if ($m >= 0 && $m <= 11) {
        $processing[$m] = round(floatval($row['avg_days']), 2);
    }
}
$stmt->close();

/** -------------------------
 * SERVICE REVENUE TRENDS
 * (monthly total fee collected)
 * ------------------------*/
$revenue = array_fill(0, 12, 0.0);

if ($from && $to) {
    $sql = "
        SELECT MONTH(r.request_date) as month, SUM(s.service_fee) as revenue
        FROM requests r
        JOIN services s ON r.service_id = s.id
        WHERE r.address_id = ?
          AND DATE(r.request_date) BETWEEN ? AND ?
        GROUP BY MONTH(r.request_date)
    ";
    $stmt = $conn->prepare($sql);
    $stmt->bind_param("iss", $address_id, $from, $to);
} else {
    $sql = "
        SELECT MONTH(r.request_date) as month, SUM(s.service_fee) as revenue
        FROM requests r
        JOIN services s ON r.service_id = s.id
        WHERE r.address_id = ?
        GROUP BY MONTH(r.request_date)
    ";
    $stmt = $conn->prepare($sql);
    $stmt->bind_param("i", $address_id);
}

$stmt->execute();
$result = $stmt->get_result();
while ($row = $result->fetch_assoc()) {
    $m = intval($row['month']) - 1;
    if ($m >= 0 && $m <= 11) {
        $revenue[$m] = floatval($row['revenue']);
    }
}
$stmt->close();

echo json_encode([
    "services"   => $services,
    "processing" => $processing, // Jan..Dec (0-based)
    "revenue"    => $revenue     // Jan..Dec (0-based)
]);

$conn->close();
