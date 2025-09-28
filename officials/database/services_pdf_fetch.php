<?php
session_start();
include('config.php');

if (!isset($_GET['service_id'])) {
    echo json_encode(["error" => "Missing service_id"]);
    exit;
}

$service_id = intval($_GET['service_id']);

$sql = "SELECT pdf_template, pdf_layout_data FROM services WHERE id = ?";
$stmt = $conn->prepare($sql);
$stmt->bind_param("i", $service_id);
$stmt->execute();
$result = $stmt->get_result();

if ($row = $result->fetch_assoc()) {
    $pdfUrl = null;

    if (!empty($row['pdf_template'])) {
        // ✅ Use relative path para automatic na HTTPS or HTTP depende sa page
        $pdfUrl = "/pdf_templates/" . $row['pdf_template'];
    }

    echo json_encode([
        "pdf_template" => $pdfUrl,
        "pdf_layout_data" => $row['pdf_layout_data']
    ]);
} else {
    echo json_encode(["error" => "Service not found"]);
}

$stmt->close();
$conn->close();
