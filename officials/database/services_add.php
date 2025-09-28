<?php
session_start();
include('config.php');

// ✅ Check kung naka-login
if (!isset($_SESSION['user_id'])) {
    die("❌ User not logged in.");
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
    die("❌ No address record found for this user.");
}

// ✅ Get POST data
$service_name    = $_POST['service_name'];
$fee             = $_POST['fee'];
$requirements    = $_POST['requirements'];
$description     = $_POST['description'];
$pdf_layout_data = !empty($_POST['pdf_layout_data']) ? $_POST['pdf_layout_data'] : NULL;

$pdf_filename = NULL; // ✅ default to NULL

// ✅ Handle file upload
if (isset($_FILES['pdf_template']) && $_FILES['pdf_template']['error'] === UPLOAD_ERR_OK) {
    $pdf_filename = basename($_FILES['pdf_template']['name']);
    $upload_dir = '../pdf_templates/';
    $target_path = $upload_dir . $pdf_filename;

    // Create folder if it doesn't exist
    if (!is_dir($upload_dir)) {
        if (!mkdir($upload_dir, 0777, true)) {
            die("❌ Failed to create upload directory.");
        }
    }

    if (!move_uploaded_file($_FILES['pdf_template']['tmp_name'], $target_path)) {
        die("❌ Failed to move uploaded file to: $target_path");
    }
}

// ✅ Check for duplicate service name (within same address_id)
$check = $conn->prepare("SELECT * FROM services WHERE service_name = ? AND address_id = ?");
$check->bind_param("si", $service_name, $address_id);
$check->execute();
$check_result = $check->get_result();

if ($check_result->num_rows > 0) {
    echo "<script>window.location.href='../section/services.php?exists=true';</script>";
    exit;
}

// ✅ Insert new service
$stmt = $conn->prepare("INSERT INTO services 
    (service_name, service_fee, requirements, description, pdf_layout_data, pdf_template, address_id) 
    VALUES (?, ?, ?, ?, ?, ?, ?)");

// Use bind_param with "s" even for NULL (mysqli will insert proper NULL automatically)
$stmt->bind_param(
    "sdssssi",
    $service_name,
    $fee,
    $requirements,
    $description,
    $pdf_layout_data,
    $pdf_filename,
    $address_id
);

if ($stmt->execute()) {
    echo "<script>window.location.href='../section/services.php?success=true';</script>";
} else {
    echo "❌ Error: " . $stmt->error;
}
?>
