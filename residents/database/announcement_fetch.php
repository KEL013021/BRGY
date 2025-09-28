<?php
session_start();
include 'config.php';

if (!isset($_SESSION['user_id'])) {
    http_response_code(403);
    exit('Not logged in');
}

$user_id = $_SESSION['user_id'];

// ✅ Kunin address_id mula sa residents
$address_id = null;
$res_query = $conn->prepare("SELECT address_id FROM residents WHERE user_id = ?");
$res_query->bind_param("i", $user_id);
$res_query->execute();
$res_result = $res_query->get_result();

if ($res_result->num_rows > 0) {
    $row = $res_result->fetch_assoc();
    $address_id = $row['address_id'];
}
$res_query->close();

$announcements = [];
if ($address_id !== null) {
    $stmt = $conn->prepare("SELECT id, title, content, image, date_posted 
                            FROM announcement 
                            WHERE address_id = ? 
                            ORDER BY date_posted DESC");
    $stmt->bind_param("i", $address_id);
    $stmt->execute();
    $result = $stmt->get_result();

    while ($row = $result->fetch_assoc()) {
        // ✅ Buoin ang full image path kung may laman
        if (!empty($row['image'])) {
            $row['image'] = "../../BRGYGO/uploads/announcement/" . $row['image'];
        }
        $announcements[] = $row;
    }
    $stmt->close();
}

header('Content-Type: application/json');
echo json_encode($announcements);
