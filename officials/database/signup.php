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
    $toa        = isset($_POST['terms']) ? 1 : 0; // checkbox
    $role       = "resident"; // default

    // Password match
    if ($password !== $confirm) {
        echo "Passwords do not match.";
        exit;
    }

    // Hash password
    $hashedPassword = password_hash($password, PASSWORD_DEFAULT);

    // Check existing email
    $check = $conn->prepare("SELECT email FROM users WHERE email = ?");
    $check->bind_param("s", $email);
    $check->execute();
    $check->store_result();

    if ($check->num_rows > 0) {
        echo "Email already registered.";
    } else {
        // Insert user
        $stmt = $conn->prepare("INSERT INTO users (email, password, agreed_terms, status, role) VALUES (?, ?, ?, 'offline', ?)");
        $stmt->bind_param("ssis", $email, $hashedPassword, $toa, $role);

        if ($stmt->execute()) {
            $user_id = $stmt->insert_id;

            // Check if address exists
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
            $res_stmt = $conn->prepare("
                INSERT INTO residents (user_id, address_id, email_address, created_at) 
                VALUES (?, ?, ?, NOW())
            ");
            $res_stmt->bind_param("iis", $user_id, $address_id, $email);
            $res_stmt->execute();
            $res_stmt->close();

            header("Location: ../section/login_signup.php?success=1");
            exit;
        } else {
            echo "Error: " . $stmt->error;
        }
        $stmt->close();
    }

    $check->close();
    $conn->close();
}
?>

