<?php
session_start();
// ✅ Check kung naka-login
if (!isset($_SESSION['user_id'])) {
    // Redirect to login page
    header("Location: login_signup.php");
    exit;
}

include('sidebar.php'); 
include('../database/config.php');

$real_user_id = $_SESSION['user_id'];

// ✅ Kunin address_id ng logged-in user
$address_id = null;
$sqlAddress = "SELECT address_id FROM address WHERE user_id = ?";
$stmtAddr   = $conn->prepare($sqlAddress);
$stmtAddr->bind_param("i", $real_user_id);
$stmtAddr->execute();
$resultAddr = $stmtAddr->get_result();

if ($rowAddr = $resultAddr->fetch_assoc()) {
    $address_id = $rowAddr['address_id'];
} else {
    die(json_encode(["error" => "No address record found for this user."]));
}
?>

<!-- External Dependencies -->
<link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/css/bootstrap.min.css">
<link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bootstrap-icons@1.10.5/font/bootstrap-icons.css">
<script src="https://code.jquery.com/jquery-3.6.0.min.js"></script>
<link rel="stylesheet" href="../css/barangay_functionaries.css" />

<!-- NAVBAR -->
<nav class="navbar">
    <div class="navbar-container">
        <div class="section-name">Barangay Functionaries</div>
        <div class="notification-wrapper" id="notifBtn">
            <i class="bi bi-bell-fill" style="font-size: 35px;"></i>
            <span class="badge-number">4</span>
        </div>
    </div>
</nav>

<?php 
// ✅ Function to get barangay functionary by position + address
function getFunctionary($position, $address_id, $conn) {
    $sql = "SELECT r.first_name, r.middle_name, r.last_name, r.image_url
            FROM barangay_official bf
            JOIN residents r ON r.id = bf.resident_id
            WHERE bf.position = ? AND bf.address_id = ? 
            LIMIT 1";

    $stmt = $conn->prepare($sql);
    $stmt->bind_param("si", $position, $address_id);
    $stmt->execute();
    $result = $stmt->get_result();

    if ($row = $result->fetch_assoc()) {
        $name  = strtoupper(trim($row['first_name'] . ' ' . $row['middle_name'] . ' ' . $row['last_name']));
        $image = !empty($row['image_url']) 
            ? '../uploads/residents/' . $row['image_url'] 
            : '../uploads/residents/default.jpg';
        return ['name' => $name, 'image' => $image];
    } else {
        return ['name' => $position, 'image' => '../uploads/residents/default.jpg'];
    }
}

// ✅ Example functionaries
$chairman  = getFunctionary("BRGY. CHAIRMAN", $address_id, $conn);
$treasurer = getFunctionary("BRGY. Treasurer", $address_id, $conn);
$secretary = getFunctionary("BRGY. Secretary", $address_id, $conn);
?>

<!-- MAIN FUNCTIONARIES PREVIEW -->
<div class="container mt-5" style="margin-left: 140px">

    <!-- 🔴 Executive Committee -->
    <div class="highlight-container-white mb-5">
        <button type="button" class="btn edit-button" data-section="Executive Committee">EDIT</button>
        <button type="button" class="btn btn-success save-button d-none" data-section="Executive Committee">
            COMPLETE CHANGES
        </button>

        <div class="inner-blur-wrapper">
            <div class="group-title bg-transparent text-dark">
                BARANGAY EXECUTIVE COMMITTEE
            </div>
            <div class="row justify-content-center text-center">

                <!-- BRGY. Treasurer -->
                <div class="col-md-3 d-flex flex-column align-items-center" style="margin-top: 70px;">
                </div>

                <!-- BRGY. CHAIRMAN -->
                <div class="col-md-3 mb-4 d-flex flex-column align-items-center" style="margin-left:50px; margin-right: 50px">
                    <div class="image-container" style="height: 370px; width: 320px;">
                        <img src="<?= $chairman['image'] ?>" alt="Chairman">
                        <div class="action-icons">
                            <button class="btn btn-primary view-btn" data-position="BRGY. CHAIRMAN">
                                <i class="bi bi-pencil-square"></i>
                            </button>
                            <button class="btn btn-danger delete-btn">
                                <i class="bi bi-trash"></i>
                            </button>
                        </div>
                    </div>
                    <div class="member-name"><?= $chairman['name'] ?></div>
                    <div class="member-position">BRGY. CHAIRMAN</div>
                </div>

                <!-- BRGY. Secretary -->
                <div class="col-md-3 d-flex flex-column align-items-center" style="margin-top: 70px;">
                </div>

            </div>
        </div>
    </div>


<?php
$sanggunian = [];
$sanggunianQuery = $conn->prepare("
    SELECT r.first_name, r.middle_name, r.last_name, r.image_url, bf.position
    FROM barangay_official bf
    JOIN residents r ON r.id = bf.resident_id
    WHERE bf.address_id = ? 
      AND bf.position = 'Sangguniang Barangay'
");
$sanggunianQuery->bind_param("i", $address_id);
$sanggunianQuery->execute();
$resultSanggunian = $sanggunianQuery->get_result();

while ($row = $resultSanggunian->fetch_assoc()) {
    $sanggunian[] = [
        'name' => strtoupper(trim($row['first_name'] . ' ' . $row['middle_name'] . ' ' . $row['last_name'])),
        'image' => !empty($row['image_url']) 
            ? '../uploads/residents/' . $row['image_url'] 
            : '../uploads/residents/default.jpg',
        'position' => $row['position']
    ];
}
?>

<div class="highlight-container-blue mb-5">
    <button type="button" class="btn edit-button" data-section="Sangguniang Barangay">EDIT</button>
    <button type="button" class="btn btn-success save-button d-none" data-section="Sangguniang Barangay">
        COMPLETE CHANGES
    </button>
    <div class="inner-blur-wrapper">
        <div class="group-title bg-transparent text-dark">SANGGUNIANG BARANGAY</div>
        <div class="row text-center justify-content-center">

            <!-- Barangay Kagawads -->
            <?php foreach ($sanggunian as $official): ?>
                <div class="col-md-3 mb-4 d-flex flex-column align-items-center sanggunian-card">
                    <div class="image-container" style="height: 300px; width: 250px;">
                        <img src="<?= $official['image'] ?>" alt="<?= $official['name'] ?>">
                        <div class="action-icons">
                            <button class="btn btn-danger delete-btn" 
                                    data-position="<?= $official['position'] ?>" 
                                    data-name="<?= $official['name'] ?>">
                                <i class="bi bi-trash"></i>
                            </button>
                        </div>
                    </div>
                    <div class="member-name"><?= $official['name'] ?></div>
                    <div class="member-position"><?= $official['position'] ?></div>
                </div>
            <?php endforeach; ?>

            <!-- ADD KAGAWAD CARD (hidden by default) -->
            <div class="col-md-3 mb-4 d-flex flex-column align-items-center d-none" id="addSanggunianCard">
                <div class="image-container d-flex justify-content-center align-items-center" 
                     style="height: 300px; width: 250px; cursor: pointer;">
                    <i class="bi bi-plus-circle" style="font-size: 60px; color: gray;"></i>
                </div>
                <div class="member-name text-muted">Add Barangay Kagawad</div>
            </div>

        </div>
    </div>
</div>


<?php
$sk_councilors = [];
$skQuery = $conn->prepare("
    SELECT r.first_name, r.middle_name, r.last_name, r.image_url, bf.position
    FROM barangay_official bf
    JOIN residents r ON r.id = bf.resident_id
    WHERE bf.address_id = ? 
      AND bf.position = 'SK Councilor'
");
$skQuery->bind_param("i", $address_id);
$skQuery->execute();
$resultSk = $skQuery->get_result();

while ($row = $resultSk->fetch_assoc()) {
    $sk_councilors[] = [
        'name' => strtoupper(trim($row['first_name'] . ' ' . $row['middle_name'] . ' ' . $row['last_name'])),
        'image' => !empty($row['image_url']) 
            ? '../uploads/residents/' . $row['image_url'] 
            : '../uploads/residents/default.jpg',
        'position' => $row['position']
    ];
}
?>

<div class="highlight-container-blue mb-5">
    <button type="button" class="btn edit-button" data-section="SK Council">EDIT</button>
    <button type="button" class="btn btn-success save-button d-none" data-section="SK Council">
        COMPLETE CHANGES
    </button>
    <div class="inner-blur-wrapper">
        <div class="group-title bg-transparent text-dark">SK COUNCILORS</div>
        <div class="row text-center justify-content-center">

            <!-- SK Councilors -->
            <?php foreach ($sk_councilors as $official): ?>
                <div class="col-md-3 mb-4 d-flex flex-column align-items-center sk-card">
                    <div class="image-container" style="height: 300px; width: 250px;">
                        <img src="<?= $official['image'] ?>" alt="<?= $official['name'] ?>">
                        <div class="action-icons">
                            <button class="btn btn-danger delete-btn" 
                                    data-position="<?= $official['position'] ?>" 
                                    data-name="<?= $official['name'] ?>">
                                <i class="bi bi-trash"></i>
                            </button>
                        </div>
                    </div>
                    <div class="member-name"><?= $official['name'] ?></div>
                    <div class="member-position"><?= $official['position'] ?></div>
                </div>
            <?php endforeach; ?>

            <!-- ADD SK COUNCILOR CARD (hidden by default) -->
            <div class="col-md-3 mb-4 d-flex flex-column align-items-center d-none" id="addSkCard">
                <div class="image-container d-flex justify-content-center align-items-center" 
                     style="height: 300px; width: 250px; cursor: pointer;">
                    <i class="bi bi-plus-circle" style="font-size: 60px; color: gray;"></i>
                </div>
                <div class="member-name text-muted">Add SK Councilor</div>
            </div>

        </div>
    </div>
</div>

<!-- Confirm Edit Modal -->
  <div class="modal fade" id="confirmEditModal" tabindex="-1" aria-labelledby="confirmEditLabel" aria-hidden="true">
    <div class="modal-dialog modal-dialog-centered">
      <div class="modal-content border-0 shadow-lg">
        <div class="modal-header bg-primary text-white">
          <h5 class="modal-title" id="confirmEditLabel">Confirm Edit</h5>
          <button type="button" class="btn-close btn-close-white" data-bs-dismiss="modal" aria-label="Close"></button>
        </div>
        <div class="modal-body text-center">
          <p class="fs-5 mb-4">Are you sure you want to edit this section?</p>
          <button type="button" class="btn btn-primary me-2" id="confirmEditBtn">Yes, Edit</button>
          <button type="button" class="btn btn-danger" data-bs-dismiss="modal">Cancel</button>
        </div>
      </div>
    </div>
  </div>

  <!-- Resident Selection Modal -->
  <div class="modal fade" id="residentSelectModal" tabindex="-1" aria-labelledby="residentSelectModalLabel" aria-hidden="true">
    <div class="modal-dialog modal-lg modal-dialog-scrollable modal-dialog-centered">
      <div class="modal-content">
        <div class="modal-header bg-primary text-white">
          <h5 class="modal-title" id="residentSelectModalLabel">Select a Resident</h5>
          <button type="button" class="btn-close btn-close-white" data-bs-dismiss="modal"></button>
        </div>
        <div class="modal-body" style="height: 500px; overflow-y: auto;">
          <!-- Search Bar -->
          <input type="text" id="residentSearchInput" class="form-control mb-3" placeholder="Search resident by name...">

          <!-- Resident List -->
          <div id="residentList" class="row row-cols-1 row-cols-md-3 g-4">
            <!-- JS will populate residents here -->
          </div>
        </div>
      </div>
    </div>
  </div>

  <!-- Resident Already Assigned Modal -->
  <div class="modal fade" id="residentAssignedModal" tabindex="-1" aria-labelledby="residentAssignedLabel" aria-hidden="true">
    <div class="modal-dialog modal-dialog-centered">
      <div class="modal-content border-0 shadow-lg">
        <div class="modal-header bg-danger text-white">
          <h5 class="modal-title" id="residentAssignedLabel">Resident Already Assigned</h5>
          <button type="button" class="btn-close btn-close-white" data-bs-dismiss="modal"></button>
        </div>
        <div class="modal-body text-center">
          <p class="fs-5 mb-0" id="residentAssignedMessage">
            <!-- Message will be inserted dynamically -->
          </p>
        </div>
      </div>
    </div>
  </div>

  <!-- Confirm Change Position Modal -->
  <div class="modal fade" id="confirmChangePositionModal" tabindex="-1" aria-labelledby="confirmChangePositionLabel" aria-hidden="true">
    <div class="modal-dialog modal-dialog-centered">
      <div class="modal-content border-0 shadow">
        <div class="modal-header bg-warning text-dark">
          <h5 class="modal-title" id="confirmChangePositionLabel">Change Position</h5>
          <button type="button" class="btn-close" data-bs-dismiss="modal"></button>
        </div>
        <div class="modal-body text-center">
          <p class="fs-5">Are you sure you want to change this position in the barangay?</p>
          <button type="button" class="btn btn-warning me-2" id="confirmChangePositionBtn">Yes, Change</button>
          <button type="button" class="btn btn-secondary" data-bs-dismiss="modal">Cancel</button>
        </div>
      </div>
    </div>
  </div>

  <!-- Delete Confirmation Modal -->
  <div class="modal fade" id="deleteConfirmModal" tabindex="-1" aria-labelledby="deleteConfirmModalLabel" aria-hidden="true">
    <div class="modal-dialog modal-dialog-centered">
      <div class="modal-content border-0 shadow">
        <div class="modal-header bg-danger text-white">
          <h5 class="modal-title" id="deleteConfirmModalLabel">Confirm Deletion</h5>
          <button type="button" class="btn-close btn-close-white" data-bs-dismiss="modal"></button>
        </div>
        <div class="modal-body text-center">
          <p class="fs-5" id="deleteConfirmText">Are you sure you want to remove this official?</p>
          <button type="button" class="btn btn-danger me-2" id="confirmDeleteBtn">Yes, Delete</button>
          <button type="button" class="btn btn-secondary" data-bs-dismiss="modal">Cancel</button>
        </div>
      </div>
    </div>
  </div>


<script>
$(document).ready(function () {
  const allResidents = <?php
    include '../database/config.php';
    $res = mysqli_query($conn, "SELECT id, image_url, first_name, middle_name, last_name FROM residents");
    $residents = [];
    while ($row = mysqli_fetch_assoc($res)) {
      $residents[] = $row;
    }
    echo json_encode($residents);
  ?>;

  let selectedPosition = '';
  let pendingPosition = '';
  let deleteData = {};

  // 🖊️ Edit Section
  $('.edit-button').on('click', function () {
    const section = $(this).data('section');
    $('#confirmEditModal').data('section', section).modal('show');
  });

  // ✅ Confirm Edit
  $('#confirmEditBtn').on('click', function () {
    const section = $('#confirmEditModal').data('section');
    const container = $(`.edit-button[data-section="${section}"]`).closest('.highlight-container-white, .highlight-container-blue');

    container.addClass('edit-mode');
    container.find('.inner-blur-wrapper').css('filter', 'none');

    if (section === "Sangguniang Barangay") {
      $('#addSanggunianCard').removeClass('d-none');
    }
    if (section === "SK Council") {
      $('#addSkCard').removeClass('d-none');
    }

    $(`.save-button[data-section="${section}"]`).removeClass('d-none');
    $(`.edit-button[data-section="${section}"]`).hide();

    $('#confirmEditModal').modal('hide');
  });

  // 💾 Save Section
  $('.save-button').on('click', function () {
    const section = $(this).data('section');
    const container = $(this).closest('.highlight-container-white, .highlight-container-blue');

    container.removeClass('edit-mode');
    container.find('.inner-blur-wrapper').removeAttr('style');

    if (section === "Sangguniang Barangay") {
      $('#addSanggunianCard').addClass('d-none');
    }
    if (section === "SK Council") {
      $('#addSkCard').addClass('d-none');
    }

    $(`.edit-button[data-section="${section}"]`).show();
    $(this).addClass('d-none');
  });

  // ✏️ View Button (Change Official)
  $('.view-btn').on('click', function () {
    pendingPosition = $(this).data('position');
    $('#confirmChangePositionLabel').text(`Change ${pendingPosition}`);
    $('#confirmChangePositionModal .modal-body p').text(`Are you sure you want to change ${pendingPosition}?`);
    $('#confirmChangePositionModal').modal('show');
  });

  // ✅ Confirm Change
  $('#confirmChangePositionBtn').on('click', function () {
    selectedPosition = pendingPosition;
    $('#confirmChangePositionModal').modal('hide');
    $('#residentSelectModalLabel').text(`Select a Resident for ${selectedPosition}`);
    $('#residentSelectModal').modal('show');
  });

  // 🔍 Search Resident
  $('#residentSearchInput').on('input', function () {
    const keyword = $(this).val().toLowerCase();
    const filtered = allResidents.filter(res =>
      `${res.first_name} ${res.middle_name} ${res.last_name}`.toLowerCase().includes(keyword)
    );
    renderResidents(filtered);
  });

  // 🔁 Render Resident Cards
  function renderResidents(list) {
    const container = $('#residentList');
    container.empty();

    if (list.length === 0) {
      container.append('<div class="text-center text-muted w-100">No residents found.</div>');
      return;
    }

    list.forEach(res => {
      const name = `${res.first_name} ${res.middle_name} ${res.last_name}`.toUpperCase();
      const image = res.image_url ? `../uploads/residents/${res.image_url}` : '../image/default-profile.png';

      const card = `
        <div class="col">
          <div class="resident-card" data-id="${res.id}" data-name="${name}" data-image="${image}">
            <img src="${image}" alt="${name}">
            <div class="resident-name">${name}</div>
          </div>
        </div>
      `;
      container.append(card);
    });
  }

  // ➕ Add new Kagawad
  $('#addSanggunianCard').on('click', function () {
    selectedPosition =  "Sangguniang Barangay";
    $('#residentSelectModalLabel').text(`Select a Resident for ${selectedPosition}`);
    $('#residentSelectModal').modal('show');
  });

  // ➕ Add new SK Councilor
  $('#addSkCard').on('click', function () {
    selectedPosition = "SK Councilor";
    $('#residentSelectModalLabel').text(`Select a Resident for ${selectedPosition}`);
    $('#residentSelectModal').modal('show');
  });

  // ✅ Show resident list when modal opens
  $('#residentSelectModal').on('shown.bs.modal', function () {
    renderResidents(allResidents);
    $('#residentSearchInput').val('');
  });

  // 🧍 Select a Resident
  $('#residentList').on('click', '.resident-card', function () {
    const imageSrc = $(this).data('image');
    const fullName = $(this).data('name');
    const residentId = $(this).data('id');

    $.post('../database/save_official.php', {
      resident_id: residentId,
      position: selectedPosition
    }, function (response) {
      try {
        const res = JSON.parse(response);
        if (res.status === 'success') {
          // Instead of reloading, append new card dynamically
          if (selectedPosition === "Barangay Kagawad") {
            $('#addSanggunianCard').before(`
              <div class="col-md-3 mb-4 d-flex flex-column align-items-center sanggunian-card">
                <div class="image-container" style="height:300px;width:250px;">
                  <img src="${imageSrc}" alt="${fullName}">
                  <div class="action-icons">
                    <button class="btn btn-danger delete-btn" data-position="Barangay Kagawad" data-name="${fullName}">
                      <i class="bi bi-trash"></i>
                    </button>
                  </div>
                </div>
                <div class="member-name">${fullName}</div>
                <div class="member-position">${selectedPosition}</div>
              </div>
            `);
          } else if (selectedPosition === "SK Councilor") {
            $('#addSkCard').before(`
              <div class="col-md-3 mb-4 d-flex flex-column align-items-center sk-card">
                <div class="image-container" style="height:300px;width:250px;">
                  <img src="${imageSrc}" alt="${fullName}">
                  <div class="action-icons">
                    <button class="btn btn-danger delete-btn" data-position="SK Councilor" data-name="${fullName}">
                      <i class="bi bi-trash"></i>
                    </button>
                  </div>
                </div>
                <div class="member-name">${fullName}</div>
                <div class="member-position">${selectedPosition}</div>
              </div>
            `);
          } else {
            // For single roles (Chairman, Treasurer, Secretary)
            const targetCard = $(`.view-btn[data-position="${selectedPosition}"]`).closest('.d-flex');
            targetCard.find('img').attr('src', imageSrc);
            targetCard.find('.member-name').text(fullName);
          }

          $('#residentSelectModal').modal('hide');
        } else if (res.status === 'conflict') {
          $('#residentAssignedMessage').text(`This resident is already assigned as ${res.current_position}.`);
          $('#residentAssignedModal').modal('show');
        } else {
          alert(res.message);
        }
      } catch {
        alert('Unexpected server response.');
      }
    });
  });

  // 🗑️ Delete Button
  $(document).on('click', '.delete-btn', function () {
    const card = $(this).closest('.d-flex');
    const position = $(this).data('position') || card.find('.member-position').text().trim();
    const name = $(this).data('name') || card.find('.member-name').text().trim();

    deleteData = { card, position, name };
    $('#deleteConfirmText').text(`Are you sure you want to remove ${name} from the position ${position}?`);
    $('#deleteConfirmModal').modal('show');
  });

  // ✅ Confirm delete
  $('#confirmDeleteBtn').on('click', function () {
    const { card, position, name } = deleteData;

    $.post('../database/official_delete.php', { position, name }, function (response) {
      try {
        const res = JSON.parse(response);
        if (res.status === 'success') {
          const removablePositions = ['Barangay Kagawad', 'SK Councilor'];

          if (removablePositions.includes(position)) {
            card.remove(); // tanggalin totally yung card
          } else {
            const img = card.find('img');
            img.attr('src', '../image/Logo.png');
            card.find('.member-name').text(position);
          }

          $('#deleteConfirmModal').modal('hide');
        } else {
          $('#deleteConfirmModal').modal('hide');
          alert(res.message || 'Unable to delete.');
        }
      } catch {
        alert('Unexpected server response.');
      }
    });
  });
});
</script>
