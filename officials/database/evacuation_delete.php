<?php
include('../database/config.php');

header('Content-Type: application/json');

// ✅ Decode JSON input
$data = json_decode(file_get_contents("php://input"), true);

if (!isset($data['id'])) {
    echo json_encode(["success" => false, "error" => "Missing ID"]);
    exit;
}

$id = intval($data['id']);

// 1️⃣ Kunin muna image path ng evacuation center
$getImg = $conn->prepare("SELECT image_path FROM evacuation_centers WHERE id = ?");
$getImg->bind_param("i", $id);
$getImg->execute();
$result = $getImg->get_result();
$imagePath = null;

if ($row = $result->fetch_assoc()) {
    $imagePath = $row['image_path'];
}
$getImg->close();

// 2️⃣ Delete evacuation center record
$sql = "DELETE FROM evacuation_centers WHERE id = ?";
$stmt = $conn->prepare($sql);
$stmt->bind_param("i", $id);

if ($stmt->execute()) {
    // 3️⃣ Kapag may image, at existing sa upload folder → burahin
    if ($imagePath && file_exists("../uploads/evacuation/" . $imagePath)) {
        unlink("../uploads/evacuation/" . $imagePath);
    }

    echo json_encode(["success" => true]);
} else {
    echo json_encode(["success" => false, "error" => $conn->error]);
}

$stmt->close();
$conn->close();
?>
