<?php
include('../database/config.php');

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $id = intval($_POST['id'] ?? 0);

    if ($id > 0) {
        // Optional: Kunin muna yung PDF file name para madelete sa uploads folder
        $q = $conn->prepare("SELECT pdf_template FROM services WHERE id = ?");
        $q->bind_param("i", $id);
        $q->execute();
        $result = $q->get_result()->fetch_assoc();
        if ($result && !empty($result['pdf_template'])) {
            $filePath = "../uploads/services/" . $result['pdf_template'];
            if (file_exists($filePath)) unlink($filePath);
        }

        // Delete service record
        $stmt = $conn->prepare("DELETE FROM services WHERE id = ?");
        $stmt->bind_param("i", $id);
        if ($stmt->execute()) {
            echo json_encode(["success" => true]);
        } else {
            echo json_encode(["success" => false, "error" => $stmt->error]);
        }
        $stmt->close();
    } else {
        echo json_encode(["success" => false, "error" => "Invalid ID"]);
    }
}
?>
