<?php
include("config.php");
session_start();

header('Content-Type: application/json');

// Check kung naka-login
if (!isset($_SESSION['user_id'])) {
    die(json_encode(["error" => "User not logged in."]));
}

$real_user_id = $_SESSION['user_id'];

// Kunin address_id gamit ang totoong user_id
$address_id = null;
$sqlAddress = "SELECT address_id FROM address WHERE user_id = ?";
$stmtAddr = $conn->prepare($sqlAddress);
$stmtAddr->bind_param("i", $real_user_id);
$stmtAddr->execute();
$resultAddr = $stmtAddr->get_result();

if ($rowAddr = $resultAddr->fetch_assoc()) {
    $address_id = $rowAddr['address_id'];
} else {
    die(json_encode(["error" => "No address record found for this user."]));
}

// Term from frontend
$term = $_GET['term'] ?? '';

// Search heads of family pero naka-filter sa barangay/address
$sql = "SELECT id, CONCAT(first_name,' ',last_name) AS name, image_url AS photo 
        FROM residents 
        WHERE house_position = 'Head'
        AND address_id = ? 
        AND (
            first_name LIKE ? 
            OR last_name LIKE ? 
            OR CONCAT(first_name,' ',last_name) LIKE ?
        )
        LIMIT 10";

$stmt = $conn->prepare($sql);
$like = "%".$term."%";
$stmt->bind_param("isss", $address_id, $like, $like, $like);
$stmt->execute();
$result = $stmt->get_result();

$suggestions = [];
while($row = $result->fetch_assoc()){
    $suggestions[] = [
        "id" => $row['id'],
        "name" => $row['name'],
        "photo" => $row['photo']
    ];
}

echo json_encode($suggestions);
exit;
