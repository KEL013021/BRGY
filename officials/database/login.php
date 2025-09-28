<?php
session_start();
include('config.php');

if ($_SERVER["REQUEST_METHOD"] === "POST") {
    $email = $_POST['email'];
    $password = $_POST['password'];

    // Check email
    $stmt = $conn->prepare("SELECT user_id, email, password, role FROM users WHERE email = ?");
    $stmt->bind_param("s", $email);
    $stmt->execute();
    $result = $stmt->get_result();

    if ($result->num_rows === 1) {
        $row = $result->fetch_assoc();

        // Verify password
        if (password_verify($password, $row['password'])) {
            // Save session
            $_SESSION['user_id'] = $row['user_id']; // FIXED
            $_SESSION['email']   = $row['email'];
            $_SESSION['role']    = $row['role'];

            // Update status to online
            $update = $conn->prepare("UPDATE users SET status = 'online' WHERE user_id = ?");
            $update->bind_param("i", $row['user_id']); // FIXED
            $update->execute();

            // Redirect based on role
            if ($row['role'] === "admin") {
                header("Location: ../section/dashboard.php");
            } else {
                header("Location: resident_dashboard.php");
            }
            exit;
        } else {
            echo "Invalid password.";
        }
    } else {
        echo "Email not found.";
    }

    $stmt->close();
    $conn->close();
}
?>
