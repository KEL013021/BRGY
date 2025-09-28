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
        // Insert user first
        $stmt = $conn->prepare("INSERT INTO users (email, password, agreed_terms, status, role) VALUES (?, ?, ?, 'offline', ?)");
        $stmt->bind_param("ssis", $email, $hashedPassword, $toa, $role);

        if ($stmt->execute()) {
            // Get the newly inserted user's ID
            $user_id = $stmt->insert_id;

            // Insert address linked to the user
            $addr_stmt = $conn->prepare("INSERT INTO address (user_id, region, province, city, barangay) VALUES (?, ?, ?, ?, ?)");
            $addr_stmt->bind_param("issss", $user_id, $region, $province, $city, $barangay);
            $addr_stmt->execute();
            $addr_stmt->close();

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
