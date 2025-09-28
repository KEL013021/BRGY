<?php
session_start();
header('Content-Type: application/json');
include('../database/config.php');

if (!isset($_SESSION['user_id'])) {
    echo json_encode(['error' => 'Not logged in']);
    exit;
}

$user_id = $_SESSION['user_id'];

// ✅ Kunin address_id
$stmt = $conn->prepare("SELECT address_id FROM address WHERE user_id = ?");
$stmt->bind_param("i", $user_id);
$stmt->execute();
$result = $stmt->get_result();
$row = $result->fetch_assoc();
$address_id = $row ? $row['address_id'] : 0;

/** -------------------------
 * Helper for WHERE clause
 * ------------------------*/
function buildWhere($address_id, $dateField = null) {
    $where = "address_id = ?";
    $params = [$address_id];
    $types  = "i";

    if (!empty($_GET['from']) && !empty($_GET['to']) && $dateField) {
        $where .= " AND DATE($dateField) BETWEEN ? AND ?";
        $params[] = $_GET['from'];
        $params[] = $_GET['to'];
        $types   .= "ss";
    }

    return [$where, $params, $types];
}

/** -------------------------
 * Helper for total counts
 * ------------------------*/
function getCount($conn, $table, $address_id, $dateField = null) {
    [$where, $params, $types] = buildWhere($address_id, $dateField);

    $sql = "SELECT COUNT(*) as total FROM $table WHERE $where";
    $stmt = $conn->prepare($sql);
    if (!$stmt) return 0;
    $stmt->bind_param($types, ...$params);
    $stmt->execute();
    $res = $stmt->get_result()->fetch_assoc();
    $stmt->close();
    return $res ? intval($res['total']) : 0;
}

/** -------------------------
 * CARDS DATA
 * ------------------------*/
$overview = [
    "totalResidents"    => getCount($conn, "residents", $address_id,"created_at"), // walang date filter
    "totalRequests"     => getCount($conn, "requests", $address_id, "request_date"),
    "emergencyReports"  => getCount($conn, "emergency", $address_id, "created_at"), // palitan kung ibang column
    "evacuationCenters" => getCount($conn, "evacuation_centers", $address_id,"created_at"), // walang date filter
    "announcements"     => getCount($conn, "announcement", $address_id, "date_posted")
];

/** -------------------------
 * POPULATION DEMOGRAPHICS
 * ------------------------*/
[$whereDemo, $paramsDemo, $typesDemo] = buildWhere($address_id, "created_at"); // ✅ now with filter
$popQuery = "
    SELECT 
        SUM(CASE WHEN TIMESTAMPDIFF(YEAR, date_of_birth, CURDATE()) BETWEEN 0 AND 17 THEN 1 ELSE 0 END) AS age_0_17,
        SUM(CASE WHEN TIMESTAMPDIFF(YEAR, date_of_birth, CURDATE()) BETWEEN 18 AND 35 THEN 1 ELSE 0 END) AS age_18_35,
        SUM(CASE WHEN TIMESTAMPDIFF(YEAR, date_of_birth, CURDATE()) BETWEEN 36 AND 55 THEN 1 ELSE 0 END) AS age_36_55,
        SUM(CASE WHEN TIMESTAMPDIFF(YEAR, date_of_birth, CURDATE()) >= 56 THEN 1 ELSE 0 END) AS age_56
    FROM residents 
    WHERE $whereDemo";
$stmt = $conn->prepare($popQuery);
$stmt->bind_param($typesDemo, ...$paramsDemo);
$stmt->execute();
$pop = $stmt->get_result()->fetch_assoc();
$stmt->close();

$demographics = [
    "labels" => ["0-17 years", "18-35 years", "36-55 years", "56+ years"],
    "data"   => [
        intval($pop['age_0_17']),
        intval($pop['age_18_35']),
        intval($pop['age_36_55']),
        intval($pop['age_56'])
    ]
];

/** -------------------------
 * SERVICE REQUEST STATUS
 * ------------------------*/
[$whereReq, $paramsReq, $typesReq] = buildWhere($address_id, "request_date");
$statusQuery = "
    SELECT status, COUNT(*) as total 
    FROM requests 
    WHERE $whereReq 
    GROUP BY status";
$stmt = $conn->prepare($statusQuery);
$stmt->bind_param($typesReq, ...$paramsReq);
$stmt->execute();
$res = $stmt->get_result();

$statusData = ["Pending"=>0,"Claimed"=>0,"Claimable"=>0,"Declined"=>0];
while($row = $res->fetch_assoc()){
    $statusData[$row['status']] = intval($row['total']);
}
$stmt->close();

$requestStatus = [
    "labels" => array_keys($statusData),
    "data"   => array_values($statusData)
];

/** -------------------------
 * MONTHLY ACTIVITY
 * ------------------------*/
function monthlyData($conn, $table, $address_id, $dateField) {
    [$where, $params, $types] = buildWhere($address_id, $dateField);

    $sql = "
        SELECT MONTH($dateField) as month, COUNT(*) as total 
        FROM $table 
        WHERE $where 
        GROUP BY MONTH($dateField)";
    $stmt = $conn->prepare($sql);
    $stmt->bind_param($types, ...$params);
    $stmt->execute();
    $res = $stmt->get_result();
    $arr = array_fill(1, 12, 0);
    while($row = $res->fetch_assoc()){
        $arr[intval($row['month'])] = intval($row['total']);
    }
    $stmt->close();
    return array_values($arr);
}

$monthlyActivity = [
    "labels"        => ["Jan","Feb","Mar","Apr","May","Jun","Jul","Aug","Sep","Oct","Nov","Dec"],
    "requests"      => monthlyData($conn, "requests", $address_id, "request_date"),
    "emergencies"   => monthlyData($conn, "emergency", $address_id, "created_at"), // palitan kung ibang field
    "announcements" => monthlyData($conn, "announcement", $address_id, "date_posted")
];

/** -------------------------
 * FINAL JSON RESPONSE
 * ------------------------*/
echo json_encode([
    "overview"        => $overview,
    "demographics"    => $demographics,
    "requestStatus"   => $requestStatus,
    "monthlyActivity" => $monthlyActivity
]);

$conn->close();
