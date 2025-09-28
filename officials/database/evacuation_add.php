<?php
session_start();
include('../database/config.php');

if (!isset($_SESSION['user_id'])) {
    die("⚠️ User not logged in.");
}
$real_user_id = $_SESSION['user_id'];

// ✅ Get address_id
$address_id = null;
$sql = "SELECT address_id FROM address WHERE user_id = ?";
$stmt = $conn->prepare($sql);
$stmt->bind_param("i", $real_user_id);
$stmt->execute();
$stmt->bind_result($address_id);
$stmt->fetch();
$stmt->close();

if (!$address_id) {
    die("⚠️ Address not found for this user.");
}

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $name = $_POST['name'] ?? null;
    $address = $_POST['address'] ?? null;
    $length = $_POST['length'] ?? null;
    $width = $_POST['width'] ?? null;
    $sqmPerPerson = $_POST['sqmPerPerson'] ?? null;
    $latitude = $_POST['latitude'] ?? null;
    $longitude = $_POST['longitude'] ?? null;
    $radius = $_POST['radius'] ?? null;
    $area = $_POST['area'] ?? null;
    $capacity = $_POST['capacity'] ?? null;

    // ✅ File upload
    $imageFileName = null;
    if (isset($_FILES['evacImage']) && $_FILES['evacImage']['error'] === UPLOAD_ERR_OK) {
        $uploadDir = "../uploads/evacuation/";
        $ext = pathinfo($_FILES['evacImage']['name'], PATHINFO_EXTENSION);
        $imageFileName = uniqid("evac_") . "." . strtolower($ext);
        $uploadPath = $uploadDir . $imageFileName;

        if (!move_uploaded_file($_FILES['evacImage']['tmp_name'], $uploadPath)) {
            die("❌ Failed to upload image.");
        }
    }

    if ($name && $latitude && $longitude) {
        $sqlInsert = "INSERT INTO evacuation_centers 
            (address_id, name, address, length, width, sqm_per_person, latitude, longitude, radius, area, capacity, image_path, created_at) 
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, NOW())";
        $stmtInsert = $conn->prepare($sqlInsert);
        $stmtInsert->bind_param(
            "issiiiddddis",
            $address_id, $name, $address, $length, $width, $sqmPerPerson,
            $latitude, $longitude, $radius, $area, $capacity, $imageFileName
        );
        if ($stmtInsert->execute()) {
            header("Location: ../section/evacuation.php?success=1");
            exit();
        } else {
            header("Location: ../section/evacuation.php?error=" . urlencode($stmtInsert->error));
            exit();
        }
    }
}
?>
