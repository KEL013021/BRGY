<?php
$host = getenv('DB_HOST');
$user = getenv('DB_USER');
$password = getenv('DB_PASS');
$db = getenv('DB_NAME');
$port = getenv('DB_PORT');

$conn = mysqli_connect($host, $user, $password, $db, $port);

if (!$conn) {
    die("Connection failed: " . mysqli_connect_error());
}
?>
