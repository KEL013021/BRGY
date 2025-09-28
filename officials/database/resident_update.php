<?php
include("config.php");
session_start();
header('Content-Type: application/json');

if (empty($_POST['resident_id'])) {
    echo json_encode(["success" => false, "error" => "No resident ID provided"]);
    exit;
}

$resident_id = intval($_POST['resident_id']);
$image_url = null;
$oldImage = null;

// 🔎 Kunin muna old image ng resident
$getOld = $conn->prepare("SELECT image_url FROM residents WHERE id=?");
$getOld->bind_param("i", $resident_id);
$getOld->execute();
$getOld->bind_result($oldImage);
$getOld->fetch();
$getOld->close();

// ✅ Handle image (cropped or upload)
if (!empty($_POST['view_cropped_image_data'])) {
    $imgData = $_POST['view_cropped_image_data'];
    $imgData = str_replace('data:image/png;base64,', '', $imgData);
    $imgData = str_replace(' ', '+', $imgData);
    $imgDecoded = base64_decode($imgData);

    $fileName = "resident_" . time() . ".png";
    $filePath = "../uploads/residents/" . $fileName;
    file_put_contents($filePath, $imgDecoded);
    $image_url = $fileName;
} elseif (!empty($_FILES['view_imageInput']['name'])) {
    $fileName = time() . "_" . basename($_FILES['view_imageInput']['name']);
    $targetPath = "../uploads/residents/" . $fileName;
    move_uploaded_file($_FILES['view_imageInput']['tmp_name'], $targetPath);
    $image_url = $fileName;
}

// 🗑 Delete old image if may bagong upload/crop
if ($image_url && $oldImage && file_exists("../uploads/residents/" . $oldImage)) {
    unlink("../uploads/residents/" . $oldImage);
}

// ✅ Update query
$sql = "UPDATE residents SET 
    first_name=?, middle_name=?, last_name=?, gender=?, date_of_birth=?,
    pob_country=?, pob_province=?, pob_city=?, civil_status=?, nationality=?, religion=?,
    country=?, province=?, city=?, barangay=?, zipcode=?, house_number=?, zone_purok=?, residency_date=?, years_of_residency=?,
    residency_type=?, previous_address=?, father_name=?, mother_name=?, spouse_name=?, number_of_family_members=?, household_number=?, relationship_to_head=?, house_position=?,
    educational_attainment=?, current_school=?, occupation=?, monthly_income=?, mobile_number=?, telephone_number=?, email_address=?,
    emergency_contact_person=?, emergency_contact_number=?, pwd_status=?, pwd_id_number=?, senior_citizen_status=?, senior_id_number=?, 
    solo_parent_status=?, is_4ps_member=?, blood_type=?, voter_status=?"
    . ($image_url ? ", image_url=?" : "") . "
    WHERE id=?";

$stmt = $conn->prepare($sql);

if ($image_url) {
    $stmt->bind_param(
        "sssssssssssssssssssssssssssssssssssssssssssssssi",
        $_POST['view_first_name'], $_POST['view_middle_name'], $_POST['view_last_name'], $_POST['view_gender'], $_POST['view_date_of_birth'],
        $_POST['view_pob_country'], $_POST['view_pob_province'], $_POST['view_pob_city'], $_POST['view_civil_status'],
        $_POST['view_nationality'], $_POST['view_religion'], $_POST['view_country'], $_POST['view_province'], $_POST['view_city'], $_POST['view_barangay'],
        $_POST['view_zipcode'], $_POST['view_house_number'], $_POST['view_zone_purok'], $_POST['view_residency_date'], $_POST['view_years_of_residency'],
        $_POST['view_residency_type'], $_POST['view_previous_address'], $_POST['view_father_name'], $_POST['view_mother_name'], $_POST['view_spouse_name'],
        $_POST['view_number_of_family_members'], $_POST['view_household_number'], $_POST['view_relationship_to_head'], $_POST['view_house_position'],
        $_POST['view_educational_attainment'], $_POST['view_current_school'], $_POST['view_occupation'], $_POST['view_monthly_income'],
        $_POST['view_mobile_number'], $_POST['view_telephone_number'], $_POST['view_email_address'], $_POST['view_emergency_contact_person'],
        $_POST['view_emergency_contact_number'], $_POST['view_pwd_status'], $_POST['view_pwd_id_number'], $_POST['view_senior_citizen_status'],
        $_POST['view_senior_id_number'], $_POST['view_solo_parent_status'], $_POST['view_is_4ps_member'], $_POST['view_blood_type'], $_POST['view_voter_status'],
        $image_url, $resident_id
    );
} else {
    $stmt->bind_param(
        "ssssssssssssssssssssssssssssssssssssssssssssssi",
        $_POST['view_first_name'], $_POST['view_middle_name'], $_POST['view_last_name'], $_POST['view_gender'], $_POST['view_date_of_birth'],
        $_POST['view_pob_country'], $_POST['view_pob_province'], $_POST['view_pob_city'], $_POST['view_civil_status'],
        $_POST['view_nationality'], $_POST['view_religion'], $_POST['view_country'], $_POST['view_province'], $_POST['view_city'], $_POST['view_barangay'],
        $_POST['view_zipcode'], $_POST['view_house_number'], $_POST['view_zone_purok'], $_POST['view_residency_date'], $_POST['view_years_of_residency'],
        $_POST['view_residency_type'], $_POST['view_previous_address'], $_POST['view_father_name'], $_POST['view_mother_name'], $_POST['view_spouse_name'],
        $_POST['view_number_of_family_members'], $_POST['view_household_number'], $_POST['view_relationship_to_head'], $_POST['view_house_position'],
        $_POST['view_educational_attainment'], $_POST['view_current_school'], $_POST['view_occupation'], $_POST['view_monthly_income'],
        $_POST['view_mobile_number'], $_POST['view_telephone_number'], $_POST['view_email_address'], $_POST['view_emergency_contact_person'],
        $_POST['view_emergency_contact_number'], $_POST['view_pwd_status'], $_POST['view_pwd_id_number'], $_POST['view_senior_citizen_status'],
        $_POST['view_senior_id_number'], $_POST['view_solo_parent_status'], $_POST['view_is_4ps_member'], $_POST['view_blood_type'], $_POST['view_voter_status'],
        $resident_id
    );
}

// ✅ Execute
if ($stmt->execute()) {
    echo json_encode(["success" => true, "message" => "Resident updated successfully!"]);
} else {
    echo json_encode(["success" => false, "error" => $stmt->error]);
}

$stmt->close();
$conn->close();
?>
