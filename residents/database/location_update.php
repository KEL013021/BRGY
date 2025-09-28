<?php
session_start();
include 'config.php';

if (!isset($_SESSION['user_id'])) {
    die("❌ Not logged in");
}

$resident_id = $_SESSION['user_id'];

// ✅ Clear location kapag close modal
if (isset($_POST['clear']) && $_POST['clear'] == 1) {
    $sql = "DELETE FROM evacuees_locations WHERE resident_id = ?";
    $stmt = $conn->prepare($sql);
    $stmt->bind_param("i", $resident_id);
    if ($stmt->execute()) {
        echo "✅ Location cleared";
    } else {
        echo "❌ Error clearing location";
    }
    exit;
}

// ✅ Save/Update location
if (isset($_POST['evacuation_id'], $_POST['lat'], $_POST['lng'])) {
    $evacuation_id = $_POST['evacuation_id'];
    $lat = $_POST['lat'];
    $lng = $_POST['lng'];

    $sql = "INSERT INTO evacuees_locations (resident_id, evacuation_id, latitude, longitude, updated_at) 
            VALUES (?, ?, ?, ?, NOW())
            ON DUPLICATE KEY UPDATE 
              evacuation_id = VALUES(evacuation_id),
              latitude = VALUES(latitude),
              longitude = VALUES(longitude),
              updated_at = NOW()";
    $stmt = $conn->prepare($sql);
    $stmt->bind_param("iidd", $resident_id, $evacuation_id, $lat, $lng);

    if ($stmt->execute()) {
        echo "✅ Location updated";
    } else {
        echo "❌ Error: " . $conn->error;
    }
}
?>
