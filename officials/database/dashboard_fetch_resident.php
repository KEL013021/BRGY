<?php
session_start();
header('Content-Type: application/json');
include('../database/config.php');

if (!isset($_SESSION['user_id'])) {
    echo json_encode(['error' => 'Not logged in']);
    exit;
}

$user_id = $_SESSION['user_id'];

// ✅ Get address_id
$stmt = $conn->prepare("SELECT address_id FROM address WHERE user_id = ?");
$stmt->bind_param("i", $user_id);
$stmt->execute();
$result = $stmt->get_result();
$row = $result->fetch_assoc();
$address_id = $row ? $row['address_id'] : 0;

// Helper for WHERE
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

// ✅ Cards
[$where, $params, $types] = buildWhere($address_id, "created_at");

// Male/Female
$sql = "SELECT gender, COUNT(*) as total FROM residents WHERE $where GROUP BY gender";
$stmt = $conn->prepare($sql);
$stmt->bind_param($types, ...$params);
$stmt->execute();
$res = $stmt->get_result();

$cards = ["male"=>0,"female"=>0,"senior"=>0,"pwd"=>0,"fourPs"=>0];
while($row = $res->fetch_assoc()){
    if (strtolower($row['gender']) === 'male')   $cards['male']   = $row['total'];
    if (strtolower($row['gender']) === 'female') $cards['female'] = $row['total'];
}
$stmt->close();

// Senior Citizens
$sql = "SELECT COUNT(*) as total FROM residents WHERE $where AND TIMESTAMPDIFF(YEAR, date_of_birth, CURDATE()) >= 60";
$stmt = $conn->prepare($sql);
$stmt->bind_param($types, ...$params);
$stmt->execute();
$row = $stmt->get_result()->fetch_assoc();
$cards['senior'] = $row['total'];
$stmt->close();

// PWD
$sql = "SELECT COUNT(*) as total FROM residents WHERE $where AND pwd_status = 1";
$stmt = $conn->prepare($sql);
$stmt->bind_param($types, ...$params);
$stmt->execute();
$row = $stmt->get_result()->fetch_assoc();
$cards['pwd'] = $row['total'];
$stmt->close();

// 4Ps
$sql = "SELECT COUNT(*) as total FROM residents WHERE $where AND is_4ps_member = 1";
$stmt = $conn->prepare($sql);
$stmt->bind_param($types, ...$params);
$stmt->execute();
$row = $stmt->get_result()->fetch_assoc();
$cards['fourPs'] = $row['total'];
$stmt->close();

// ✅ Age Groups
$sql = "SELECT 
    SUM(CASE WHEN TIMESTAMPDIFF(YEAR, date_of_birth, CURDATE()) <= 17 THEN 1 ELSE 0 END) AS '0-17',
    SUM(CASE WHEN TIMESTAMPDIFF(YEAR, date_of_birth, CURDATE()) BETWEEN 18 AND 30 THEN 1 ELSE 0 END) AS '18-30',
    SUM(CASE WHEN TIMESTAMPDIFF(YEAR, date_of_birth, CURDATE()) BETWEEN 31 AND 59 THEN 1 ELSE 0 END) AS '31-59',
    SUM(CASE WHEN TIMESTAMPDIFF(YEAR, date_of_birth, CURDATE()) >= 60 THEN 1 ELSE 0 END) AS '60+'
FROM residents WHERE $where";
$stmt = $conn->prepare($sql);
$stmt->bind_param($types, ...$params);
$stmt->execute();
$ageGroups = $stmt->get_result()->fetch_assoc();
$stmt->close();

// ✅ Civil Status
$sql = "SELECT civil_status, COUNT(*) as total FROM residents WHERE $where GROUP BY civil_status";
$stmt = $conn->prepare($sql);
$stmt->bind_param($types, ...$params);
$stmt->execute();
$res = $stmt->get_result();
$civilStatus = [];
while($row = $res->fetch_assoc()){
    $civilStatus[$row['civil_status']] = intval($row['total']);
}
$stmt->close();

// ✅ Education
$sql = "SELECT educational_attainment, COUNT(*) as total FROM residents WHERE $where GROUP BY educational_attainment";
$stmt = $conn->prepare($sql);
$stmt->bind_param($types, ...$params);
$stmt->execute();
$res = $stmt->get_result();
$educational_attainment = [];
while($row = $res->fetch_assoc()){
    $educational_attainment[$row['educational_attainment']] = intval($row['total']);
}
$stmt->close();

echo json_encode([
    "cards"       => $cards,
    "ageGroups"   => $ageGroups,
    "civilStatus" => $civilStatus,
    "educational_attainment"   => $educational_attainment
]);

$conn->close();
