<?php
include("config.php");

$service_id    = $_POST['service_id'];
$service_name  = $_POST['service_name'];
$service_fee   = $_POST['service_fee'];
$requirements  = $_POST['requirements'];
$description   = $_POST['description'];
$pdf_layout_data = $_POST['pdf_layout_data'] ?? null;

$pdf_template = null;

// ✅ Check kung may bagong PDF na inupload
if (isset($_FILES['pdf_template']) && $_FILES['pdf_template']['error'] === UPLOAD_ERR_OK) {
    $pdf_name = time() . "_" . basename($_FILES['pdf_template']['name']);
    $target = "../pdf_templates/" . $pdf_name;

    if (move_uploaded_file($_FILES['pdf_template']['tmp_name'], $target)) {
        $pdf_template = $pdf_name;
    }
}

if ($pdf_template) {
    // ✅ Kung may bagong PDF
    $stmt = $conn->prepare("UPDATE services 
        SET service_name=?, service_fee=?, requirements=?, description=?, pdf_template=?, pdf_layout_data=? 
        WHERE id=?");
    $stmt->bind_param("sissssi", $service_name, $service_fee, $requirements, $description, $pdf_template, $pdf_layout_data, $service_id);
} else {
    // ✅ Kung walang bagong PDF
    $stmt = $conn->prepare("UPDATE services 
        SET service_name=?, service_fee=?, requirements=?, description=?, pdf_layout_data=? 
        WHERE id=?");
    $stmt->bind_param("sisssi", $service_name, $service_fee, $requirements, $description, $pdf_layout_data, $service_id);
}

if ($stmt->execute()) {
    echo json_encode(["success" => true]);
} else {
    echo json_encode(["success" => false, "error" => $stmt->error]);
}

$stmt->close();
$conn->close();
?>
