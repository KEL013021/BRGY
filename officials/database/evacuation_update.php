<?php
include('../database/config.php');

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $id = intval($_POST['id']); // hidden input sa edit form
    $name = $_POST['name'];
    $address = $_POST['address'];
    $length = $_POST['length'];
    $width = $_POST['width'];
    $sqmPerPerson = $_POST['sqmPerPerson'];
    $radius = $_POST['radius'];
    $area = $_POST['area'];
    $capacity = $_POST['capacity'];
    $latitude = $_POST['latitude'];
    $longitude = $_POST['longitude'];

    // ✅ Fetch current image for deletion later if needed
    $currentImage = null;
    $res = $conn->query("SELECT image_path FROM evacuation_centers WHERE id = $id");
    if ($res && $row = $res->fetch_assoc()) {
        $currentImage = $row['image_path'];
    }

    // ✅ Handle image upload
    $imagePath = null;
    if (isset($_FILES['evacImage']) && $_FILES['evacImage']['error'] === UPLOAD_ERR_OK) {
        $uploadDir = "../uploads/evacuation/";
        if (!is_dir($uploadDir)) {
            mkdir($uploadDir, 0777, true);
        }

        $fileTmp = $_FILES['evacImage']['tmp_name'];
        $fileName = time() . "_" . basename($_FILES['evacImage']['name']);
        $filePath = $uploadDir . $fileName;

        if (move_uploaded_file($fileTmp, $filePath)) {
            $imagePath = $fileName;

            // ✅ Delete old image if it exists
            if ($currentImage && file_exists($uploadDir . $currentImage)) {
                unlink($uploadDir . $currentImage);
            }
        }
    }

    // ✅ Build update query
    if ($imagePath) {
        $sql = "UPDATE evacuation_centers 
                SET name=?, address=?, length=?, width=?, sqm_per_person=?, 
                    radius=?, area=?, capacity=?, latitude=?, longitude=?, image_path=? 
                WHERE id=?";
        $stmt = $conn->prepare($sql);
        $stmt->bind_param("ssiiididdssi", 
            $name, $address, $length, $width, $sqmPerPerson, 
            $radius, $area, $capacity, $latitude, $longitude, $imagePath, $id
        );
    } else {
        $sql = "UPDATE evacuation_centers 
                SET name=?, address=?, length=?, width=?, sqm_per_person=?, 
                    radius=?, area=?, capacity=?, latitude=?, longitude=? 
                WHERE id=?";
        $stmt = $conn->prepare($sql);
        $stmt->bind_param("ssiiididdsi", 
            $name, $address, $length, $width, $sqmPerPerson, 
            $radius, $area, $capacity, $latitude, $longitude, $id
        );
    }

    // ✅ Execute query
    if ($stmt->execute()) {
        header("Location: ../section/evacuation.php"); // redirect sa ibang file
        exit(); // laging mag-exit pagkatapos ng header redirect
    } else {
        echo "error: " . $conn->error;
    }

    $stmt->close();
    $conn->close();
}
?>
