<?php
include('config.php');

if (!isset($_POST['id'])) {
    echo json_encode(["error" => "No ID provided."]);
    exit;
}

$id = intval($_POST['id']);

// Get old image
$sqlOld = "SELECT image FROM announcement WHERE id = ?";
$stmtOld = $conn->prepare($sqlOld);
$stmtOld->bind_param("i", $id);
$stmtOld->execute();
$resultOld = $stmtOld->get_result();
$oldImage = $resultOld->fetch_assoc()['image'] ?? null;
$stmtOld->close();

// Delete announcement
$sql = "DELETE FROM announcement WHERE id = ?";
$stmt = $conn->prepare($sql);
$stmt->bind_param("i", $id);

if ($stmt->execute()) {
    // Delete image if exists
    if ($oldImage && file_exists("../uploads/announcement/" . $oldImage)) {
        unlink("../uploads/announcement/" . $oldImage);
    }
    echo json_encode(["success" => true]);
} else {
    echo json_encode(["error" => "Failed to delete."]);
}

$stmt->close();
$conn->close();
?>
