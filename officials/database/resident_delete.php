<?php
include('config.php');

if(isset($_POST['id'])){
    $id = intval($_POST['id']);
    $query = "DELETE FROM residents WHERE id = $id";
    
    if(mysqli_query($conn, $query)){
        echo json_encode(["success" => true]);
    } else {
        echo json_encode(["success" => false, "error" => mysqli_error($conn)]);
    }
} else {
    echo json_encode(["success" => false, "error" => "No ID provided"]);
}
?>
