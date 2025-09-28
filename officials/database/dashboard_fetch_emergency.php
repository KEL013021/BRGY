<?php
session_start();
header('Content-Type: application/json');
include('../database/config.php');

if (!isset($_SESSION['user_id'])) {
    echo json_encode(["error" => "Not logged in"]);
    exit;
}

$user_id = $_SESSION['user_id'];

// Kunin address_id ng logged in user
$stmt = $conn->prepare("SELECT address_id FROM address WHERE user_id = ?");
$stmt->bind_param("i", $user_id);
$stmt->execute();
$res = $stmt->get_result()->fetch_assoc();
$address_id = $res ? $res['address_id'] : 0;

/** -------------------------
 * EMERGENCY TYPES (pie/doughnut)
 * ------------------------*/
$sql = "SELECT emergency_type, COUNT(*) as total 
        FROM emergency 
        WHERE address_id = ? 
        GROUP BY emergency_type";
$stmt = $conn->prepare($sql);
$stmt->bind_param("i", $address_id);
$stmt->execute();
$result = $stmt->get_result();
$types = [];
while ($row = $result->fetch_assoc()) {
    $types[$row['emergency_type']] = (int)$row['total'];
}
$stmt->close();

/** -------------------------
 * EVACUATION CENTER CAPACITY (bar)
 * ------------------------*/
$sql = "SELECT name, capacity FROM evacuation_centers WHERE address_id = ?";
$stmt = $conn->prepare($sql);
$stmt->bind_param("i", $address_id);
$stmt->execute();
$result = $stmt->get_result();
$centers = [];
while ($row = $result->fetch_assoc()) {
    $centers[] = [
        "name"     => $row['name'],
        "capacity" => (int)$row['capacity'],
        "current"  => rand(20, $row['capacity']) // TODO: palitan kapag may evacuee table ka
    ];
}
$stmt->close();

/** -------------------------
 * EMERGENCY RESPONSE TIMELINE (monthly line chart)
 * ------------------------*/
$sql = "SELECT MONTH(report_time) as month, COUNT(*) as total
        FROM emergency
        WHERE address_id = ?
        GROUP BY MONTH(report_time)";
$stmt = $conn->prepare($sql);
$stmt->bind_param("i", $address_id);
$stmt->execute();
$result = $stmt->get_result();
$timeline = array_fill(1, 12, 0);
while ($row = $result->fetch_assoc()) {
    $timeline[(int)$row['month']] = (int)$row['total'];
}
$stmt->close();

echo json_encode([
    "types"    => $types,
    "centers"  => $centers,
    "timeline" => array_values($timeline)
]);

$conn->close();
