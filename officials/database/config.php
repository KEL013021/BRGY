<?php
$host = "localhost";   // server host
$user = "root";        // default XAMPP username
$password = "";        // default XAMPP password is empty
$db = "brgygo"; // replace with your database name

$conn = mysqli_connect($host, $user, $password, $db);

if (!$conn) {
    die("Connection failed: " . mysqli_connect_error());
}
?>
