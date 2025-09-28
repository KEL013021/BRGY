<?php
include('../database/config.php');

$id = intval($_GET['id'] ?? 0);

$sql = "SELECT id, service_name, description, requirements, service_fee, pdf_template, pdf_layout_data 
        FROM services WHERE id = ?";
$stmt = $conn->prepare($sql);
$stmt->bind_param("i", $id);
$stmt->execute();
$result = $stmt->get_result();

if ($row = $result->fetch_assoc()) {
    // Buoin yung URL ng PDF file
    $row['pdf_template'] = $row['pdf_template'] 
        ? "/../pdf_templates/" . $row['pdf_template'] 
        : null;

    echo json_encode($row);
} else {
    echo json_encode(["error" => "Service not found"]);
}
