<?php
include('config.php');

if ($_SERVER["REQUEST_METHOD"] === "POST") {
    $email      = $_POST['email'];
    $password   = $_POST['password'];
    $confirm    = $_POST['confirm_password'];
    $region     = $_POST['region'];
    $province   = $_POST['province'];
    $city       = $_POST['city'];
    $barangay   = $_POST['barangay'];
    $toa        = isset($_POST['terms']) ? 1 : 0;
    $role       = "resident";

    // Password match check
    if ($password !== $confirm) {
        echo "Passwords do not match.";
        exit;
    }

    $hashedPassword = password_hash($password, PASSWORD_DEFAULT);

    // ✅ Check if email already exists in users
    $checkUser = $conn->prepare("SELECT id FROM users WHERE email = ?");
    $checkUser->bind_param("s", $email);
    $checkUser->execute();
    $checkUser->store_result();

    if ($checkUser->num_rows > 0) {
        echo "Email already registered.";
        $checkUser->close();
        exit;
    }
    $checkUser->close();

    // ✅ Check if email exists in residents
    $checkResident = $conn->prepare("SELECT id, user_id FROM residents WHERE email_address = ?");
    $checkResident->bind_param("s", $email);
    $checkResident->execute();
    $checkResident->store_result();

    $residentId = null;
    $residentUserId = null;

    if ($checkResident->num_rows > 0) {
        $checkResident->bind_result($residentId, $residentUserId);
        $checkResident->fetch();
    }
    $checkResident->close();

    // ✅ Create user account
    $stmt = $conn->prepare("INSERT INTO users (email, password, agreed_terms, status, role) VALUES (?, ?, ?, 'offline', ?)");
    $stmt->bind_param("ssis", $email, $hashedPassword, $toa, $role);

    if ($stmt->execute()) {
        $user_id = $stmt->insert_id;

        if ($residentId) {
            // Case 1: May existing resident record → update link
            $updateRes = $conn->prepare("UPDATE residents SET user_id = ? WHERE id = ?");
            $updateRes->bind_param("ii", $user_id, $residentId);
            $updateRes->execute();
            $updateRes->close();
        } else {
            // Case 2: Wala pang resident record → create address then insert resident
            $addr_check = $conn->prepare("SELECT address_id FROM address WHERE region = ? AND province = ? AND city = ? AND barangay = ?");
            $addr_check->bind_param("ssss", $region, $province, $city, $barangay);
            $addr_check->execute();
            $addr_check->store_result();

            if ($addr_check->num_rows > 0) {
                $addr_check->bind_result($address_id);
                $addr_check->fetch();
            } else {
                $addr_stmt = $conn->prepare("INSERT INTO address (region, province, city, barangay) VALUES (?, ?, ?, ?)");
                $addr_stmt->bind_param("ssss", $region, $province, $city, $barangay);
                $addr_stmt->execute();
                $address_id = $addr_stmt->insert_id;
                $addr_stmt->close();
            }
            $addr_check->close();

            // Insert into residents table
            $res_stmt = $conn->prepare("INSERT INTO residents (user_id, address_id, email_address, created_at) VALUES (?, ?, ?, NOW())");
            $res_stmt->bind_param("iis", $user_id, $address_id, $email);
            $res_stmt->execute();
            $res_stmt->close();
        }

        header("Location: ../section/login_signup.php?success=1");
        exit;
    } else {
        echo "Error: " . $stmt->error;
    }

    $stmt->close();
    $conn->close();
}
?>
