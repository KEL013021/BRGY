<?php
session_start();
include('../database/config.php'); // Database connection

// ✅ Check kung naka-login
if (!isset($_SESSION['user_id'])) {
    die(json_encode(["error" => "User not logged in."]));
}

$real_user_id = $_SESSION['user_id'];

// ✅ Kunin address_id ng logged-in user
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

// ✅ Collect form data
$title   = trim($_POST['title']);
$content = trim($_POST['content']);
$date_posted = date("Y-m-d H:i:s");

$imageName = null;

// ✅ Handle Image Upload if present
if (!empty($_FILES['image']['name'])) {
    $targetDir = "../uploads/announcement/";
    if (!file_exists($targetDir)) {
        mkdir($targetDir, 0777, true);
    }

    // Generate unique filename (only store filename in DB)
    $imageName = time() . "_" . basename($_FILES["image"]["name"]);
    $targetFilePath = $targetDir . $imageName;

    // Allow only certain file types
    $allowedTypes = ['jpg', 'jpeg', 'png', 'gif'];
    $fileType = strtolower(pathinfo($targetFilePath, PATHINFO_EXTENSION));

    if (in_array($fileType, $allowedTypes)) {
        if (!move_uploaded_file($_FILES["image"]["tmp_name"], $targetFilePath)) {
            die(json_encode(["error" => "Image upload failed."]));
        }
    } else {
        die(json_encode(["error" => "Only JPG, JPEG, PNG, GIF allowed."]));
    }
}

// ✅ Insert announcement (store only filename in DB)
$sql = "INSERT INTO announcement (address_id, title, content, image, date_posted) 
        VALUES (?, ?, ?, ?, ?)";
$stmt = $conn->prepare($sql);
$stmt->bind_param("issss", $address_id, $title, $content, $imageName, $date_posted);

if ($stmt->execute()) {
    header("Location: ../section/announcement.php?success=1");
    exit();
} else {
    die(json_encode(["error" => "Database error: " . $stmt->error]));
}
?>
