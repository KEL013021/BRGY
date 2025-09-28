<?php
include('../database/config.php');

if (isset($_POST['id'])) {
    $id = intval($_POST['id']);
    $sql = "UPDATE requests SET status='Claimed' WHERE id=?";
    $stmt = $conn->prepare($sql);
    $stmt->bind_param("i", $id);
    
    if ($stmt->execute()) {
        echo json_encode(["success" => true]);
    } else {
        echo json_encode(["success" => false]);
    }
}
?>
