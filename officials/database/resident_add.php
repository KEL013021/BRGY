<?php
include("config.php");
session_start();

// Check kung naka-login
if (!isset($_SESSION['user_id'])) {
    die("User not logged in.");
}
$real_user_id = $_SESSION['user_id']; // totoong user_id (pangkuha lang ng address_id)

// Kunin address_id gamit ang totoong user_id
$address_id = null;
$sqlAddress = "SELECT address_id FROM address WHERE user_id = ?";
$stmtAddr = $conn->prepare($sqlAddress);
$stmtAddr->bind_param("i", $real_user_id);
$stmtAddr->execute();
$resultAddr = $stmtAddr->get_result();

if ($rowAddr = $resultAddr->fetch_assoc()) {
    $address_id = $rowAddr['address_id'];
} else {
    die("No address record found for this user.");
}

$user_id = 0;

// Handle image upload or cropped image data
$image_url = null;
if (!empty($_POST['cropped_image_data'])) {
    // kung galing sa cropper (base64 image)
    $imgData = $_POST['cropped_image_data'];
    $imgData = str_replace('data:image/png;base64,', '', $imgData);
    $imgData = str_replace(' ', '+', $imgData);
    $imgDecoded = base64_decode($imgData);

    $fileName = "resident_" . time() . ".png";
    $filePath = "../uploads/residents/" . $fileName;
    file_put_contents($filePath, $imgDecoded);
    $image_url = $fileName;
} elseif (!empty($_FILES['imageInput']['name'])) {
    // kung standard file upload
    $fileName = time() . "_" . basename($_FILES['imageInput']['name']);
    $targetPath = "../uploads/residents/" . $fileName;
    move_uploaded_file($_FILES['imageInput']['tmp_name'], $targetPath);
    $image_url = $fileName;
}

// Prepare insert
$sql = "INSERT INTO residents (
    user_id, address_id, image_url, first_name, middle_name, last_name, gender, date_of_birth, 
    pob_country, pob_province, pob_city, civil_status, nationality, religion, 
    country, province, city, barangay, zipcode, house_number, zone_purok, residency_date, years_of_residency, residency_type, previous_address,
    father_name, mother_name, spouse_name, number_of_family_members, household_number, relationship_to_head, house_position, 
    educational_attainment, current_school, occupation, monthly_income, mobile_number, telephone_number, email_address,
    emergency_contact_person, emergency_contact_number, pwd_status, pwd_id_number, senior_citizen_status, senior_id_number, 
    solo_parent_status, is_4ps_member, blood_type, voter_status
) VALUES (?,?,?,?,?,
        ?,?,?,?,?,
        ?,?,?,?,?,
        ?,?,?,?,?,
        ?,?,?,?,?,
        ?,?,?,?,?,
        ?,?,?,?,?,
        ?,?,?,?,?,
        ?,?,?,?,?,
        ?,?,?,?)";

$stmt = $conn->prepare($sql);
$stmt->bind_param(
    "iisssssssssssssssssssssssssssssssssssssssssssssss", // 49 characters = 49 vars
    $user_id, $address_id, $image_url,
    $_POST['first_name'], $_POST['middle_name'], $_POST['last_name'], $_POST['gender'], $_POST['date_of_birth'],
    $_POST['pob_country'], $_POST['pob_province'], $_POST['pob_city'], $_POST['civil_status'],
    $_POST['nationality'], $_POST['religion'], $_POST['country'], $_POST['province'], $_POST['city'], $_POST['barangay'],
    $_POST['zipcode'], $_POST['house_number'], $_POST['zone_purok'], $_POST['residency_date'], $_POST['years_of_residency'],
    $_POST['residency_type'], $_POST['previous_address'], $_POST['father_name'], $_POST['mother_name'], $_POST['spouse_name'],
    $_POST['number_of_family_members'], $_POST['household_number'], $_POST['relationship_to_head'], $_POST['house_position'],
    $_POST['educational_attainment'], $_POST['current_school'], $_POST['occupation'], $_POST['monthly_income'],
    $_POST['mobile_number'], $_POST['telephone_number'], $_POST['email_address'], $_POST['emergency_contact_person'],
    $_POST['emergency_contact_number'], $_POST['pwd_status'], $_POST['pwd_id_number'], $_POST['senior_citizen_status'],
    $_POST['senior_id_number'], $_POST['solo_parent_status'], $_POST['is_4ps_member'], $_POST['blood_type'], $_POST['voter_status']
);



if ($stmt->execute()) {
    echo "<script>alert('Resident added successfully!'); window.location.href='../section/barangay_resident.php';</script>";
} else {
    echo "Error: " . $stmt->error;
}

$stmt->close();
$conn->close();
?>
