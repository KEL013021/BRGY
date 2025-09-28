<?php
include("config.php");

if(isset($_POST['email'])){
    $email = $_POST['email'];

    $stmt = $conn->prepare("SELECT id FROM residents WHERE email_address = ?");
    $stmt->bind_param("s", $email);
    $stmt->execute();
    $result = $stmt->get_result();

    if($result->num_rows > 0){
        echo "exists";
    } else {
        echo "ok";
    }

    $stmt->close();
    $conn->close();
}
?>
