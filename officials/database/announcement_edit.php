<?php
include('config.php');

$id = intval($_POST['announcement_id']);
$title = $_POST['title'] ?? '';
$content = $_POST['content'] ?? '';

// Get old image
$sqlOld = "SELECT image FROM announcement WHERE id = ?";
$stmtOld = $conn->prepare($sqlOld);
$stmtOld->bind_param("i", $id);
$stmtOld->execute();
$resultOld = $stmtOld->get_result();
$oldImage = $resultOld->fetch_assoc()['image'];
$stmtOld->close();

$imageName = $oldImage;
if (isset($_FILES['image']) && $_FILES['image']['error'] === UPLOAD_ERR_OK) {
    // Upload new image
    $imageName = time() . "_" . basename($_FILES['image']['name']);
    $target = "../uploads/announcement/" . $imageName;
    move_uploaded_file($_FILES['image']['tmp_name'], $target);

    // Delete old image if exists
    if ($oldImage && file_exists("../uploads/announcement/" . $oldImage)) {
        unlink("../uploads/announcement/" . $oldImage);
    }
}

$sql = "UPDATE announcement SET title=?, content=?, image=? WHERE id=?";
$stmt = $conn->prepare($sql);
$stmt->bind_param("sssi", $title, $content, $imageName, $id);
$stmt->execute();

header("Location: ../section/announcement.php"); // redirect after editing
exit;
?>
