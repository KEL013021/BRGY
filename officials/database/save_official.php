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
$resident_id = mysqli_real_escape_string($conn, $_POST['resident_id']);
$position    = mysqli_real_escape_string($conn, $_POST['position']);

// ✅ Check if this resident already holds another position in the same barangay
$check = mysqli_query($conn, "SELECT position 
                              FROM barangay_official 
                              WHERE resident_id = '$resident_id' AND address_id = '$address_id'");
if (mysqli_num_rows($check) > 0) {
    $row = mysqli_fetch_assoc($check);
    echo json_encode(['status' => 'conflict', 'current_position' => $row['position']]);
    exit;
}

// ✅ If position is a unique one (only one allowed per barangay)
$unique_positions = ['BRGY. CHAIRMAN', 'BRGY. Secretary', 'BRGY. Treasurer'];

if (in_array($position, $unique_positions)) {
    mysqli_query($conn, "DELETE FROM barangay_official 
                         WHERE position = '$position' AND address_id = '$address_id'");
}

// ✅ Insert new assignment
$insert = mysqli_query($conn, "INSERT INTO barangay_official (resident_id, address_id, position, updated_at) 
                               VALUES ('$resident_id', '$address_id', '$position', NOW())");

if ($insert) {
    echo json_encode(['status' => 'success', 'message' => 'Resident assigned successfully.']);
} else {
    echo json_encode(['status' => 'error', 'message' => 'Failed to assign resident.']);
}
?>
