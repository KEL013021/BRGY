<?php
$host = 'localhost';
$user = 'root';
$password = ''; // default XAMPP password
$db = 'brgygo'; // make sure your database name is correct

$conn = mysqli_connect($host, $user, $password, $db);

if (!$conn) {
    die("Connection failed: " . mysqli_connect_error());
}
?>