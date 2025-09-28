<?php
session_start();
include 'config.php';

// ✅ Require login
if (!isset($_SESSION['user_id'])) {
    echo json_encode(['status' => 'error', 'message' => 'Not logged in.']);
    exit;
}

$user_id = $_SESSION['user_id'];

// ✅ Get the address_id of the logged-in user
$addressRes = mysqli_query($conn, "SELECT address_id FROM address WHERE user_id = '$user_id' LIMIT 1");
if (!$addressRes || mysqli_num_rows($addressRes) == 0) {
    echo json_encode(['status' => 'error', 'message' => 'No address found for this user.']);
    exit;
}
$addressRow = mysqli_fetch_assoc($addressRes);
$address_id = $addressRow['address_id'];

// ✅ Get data from POST
$position = mysqli_real_escape_string($conn, $_POST['position']);
$name     = mysqli_real_escape_string($conn, $_POST['name']);

// ✅ Find resident_id based on name (to support your delete button using name)
$residentRes = mysqli_query($conn, "
    SELECT id FROM residents 
    WHERE CONCAT(first_name, ' ', middle_name, ' ', last_name) LIKE '%$name%' 
    LIMIT 1
");

if ($residentRes && mysqli_num_rows($residentRes) > 0) {
    $residentRow = mysqli_fetch_assoc($residentRes);
    $resident_id = $residentRow['id'];

    // 🗑️ Delete only from this barangay
    $delete = mysqli_query($conn, "
        DELETE FROM barangay_official 
        WHERE resident_id = '$resident_id' AND position = '$position' AND address_id = '$address_id'
    ");

    if ($delete) {
        echo json_encode(['status' => 'success', 'message' => 'Official removed successfully.']);
    } else {
        echo json_encode(['status' => 'error', 'message' => 'Failed to remove official.']);
    }
} else {
    // If resident not found by name, fallback: delete by position only
    $delete = mysqli_query($conn, "
        DELETE FROM barangay_official 
        WHERE position = '$position' AND address_id = '$address_id'
    ");

    if ($delete) {
        echo json_encode(['status' => 'success', 'message' => 'Position cleared successfully.']);
    } else {
        echo json_encode(['status' => 'error', 'message' => 'Failed to clear position.']);
    }
}
?>
