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
                    <div class="image-container" style="height: 300px; width: 250px;">
                        <img src="<?= $treasurer['image'] ?>" alt="Treasurer">
                        <div class="action-icons">
                            <button class="btn btn-primary view-btn" data-position="BRGY. Treasurer">
                                <i class="bi bi-pencil-square"></i>
                            </button>
                            <button class="btn btn-danger delete-btn">
                                <i class="bi bi-trash"></i>
                            </button>
                        </div>
                    </div>
                    <div class="member-name"><?= $treasurer['name'] ?></div>
                    <div class="member-position">BRGY. Treasurer</div>
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
                    <div class="image-container" style="height: 300px; width: 250px;">
                        <img src="<?= $secretary['image'] ?>" alt="Secretary">
                        <div class="action-icons">
                            <button class="btn btn-primary view-btn" data-position="BRGY. Secretary">
                                <i class="bi bi-pencil-square"></i>
                            </button>
                            <button class="btn btn-danger delete-btn">
                                <i class="bi bi-trash"></i>
                            </button>
                        </div>
                    </div>
                    <div class="member-name"><?= $secretary['name'] ?></div>
                    <div class="member-position">BRGY. Secretary</div>
                </div>

            </div>
        </div>
    </div>

    <!-- 🔵 Barangay Tanod -->

<?php
$tanods = [];
$tanodQuery = $conn->prepare("
    SELECT r.first_name, r.middle_name, r.last_name, r.image_url
    FROM barangay_official bf
    JOIN residents r ON r.id = bf.resident_id
    WHERE bf.position = 'Barangay Police' AND bf.address_id = ?
");
$tanodQuery->bind_param("i", $address_id);
$tanodQuery->execute();
$resultTanod = $tanodQuery->get_result();

while ($row = $resultTanod->fetch_assoc()) {
  $tanods[] = [
    'name' => strtoupper(trim($row['first_name'] . ' ' . $row['middle_name'] . ' ' . $row['last_name'])),
    'image' => !empty($row['image_url']) ? '../uploads/residents/' . $row['image_url'] : '../uploads/residents/default.jpg'
  ];
}
?>


  <div class="highlight-container-blue mb-5">
    <button type="button" class="btn edit-button" data-section="Barangay Tanod">
      EDIT
    </button>
    <button type="button" class="btn btn-success save-button d-none" data-section="Barangay Tanod">COMPLETE CHANGES</button>
    <div class="inner-blur-wrapper">
      <div class="group-title bg-transparent text-dark">BARANGAY TANOD</div>
      <div class="row text-center justify-content-center">

        <!-- Chief Tanod -->
        <div class="col-md-3 mb-4 d-flex flex-column align-items-center">
          <div class="image-container" style="height: 300px; width: 250px;">
            <img src="../uploads/residents/default.jpg" alt="Chief Tanod">
            <div class="action-icons">
              <button class="btn btn-primary view-btn" data-position="Chief Tanod"><i class="bi bi-pencil-square"></i></button>
              <button class="btn btn-danger delete-btn"><i class="bi bi-trash"></i></button>
            </div>
          </div>
          <div class="member-name">CHIEF TANOD</div>
          <div class="member-position">CHIEF</div>
        </div>

        <!-- Regular Tanods -->
        <?php foreach ($tanods as $tanod): ?>
          <div class="col-md-3 mb-4 d-flex flex-column align-items-center tanod-card">
            <div class="image-container" style="height: 300px; width: 250px;">
              <img src="<?= $tanod['image'] ?>" alt="<?= $tanod['name'] ?>">
              <div class="action-icons">
                <button class="btn btn-danger delete-btn" data-position="Barangay Police" data-name="<?= $tanod['name'] ?>"><i class="bi bi-trash"></i></button>
              </div>
            </div>
            <div class="member-name"><?= $tanod['name'] ?></div>
            <div class="member-position">Barangay Police</div>
          </div>
        <?php endforeach; ?>


        <!-- ADD TANOD CARD (hidden by default) -->
        <div class="col-md-3 mb-4 d-flex flex-column align-items-center d-none" id="addTanodCard">
          <div class="image-container d-flex justify-content-center align-items-center" style="height: 300px; width: 250px; cursor: pointer;">
            <i class="bi bi-plus-circle" style="font-size: 60px; color: gray;"></i>
          </div>
          <div class="member-name text-muted">Add Barangay Police</div>
        </div>

        
      </div>
    </div>
  </div>


<?php
$addressId = intval($_GET['address_id'] ?? 0); // kunin mula sa query string o ibang source

$lupons = [];
$sql = "
    SELECT r.first_name,
           r.middle_name,
           r.last_name,
           r.image_url
    FROM barangay_official bf
    JOIN residents r ON r.id = bf.resident_id
    WHERE bf.position = 'Barangay Lupon'
      AND r.address_id = $addressId
";
$luponQuery = mysqli_query($conn, $sql);

while ($row = mysqli_fetch_assoc($luponQuery)) {
    $lupons[] = [
        'name'  => strtoupper(trim($row['first_name'] . ' ' . $row['middle_name'] . ' ' . $row['last_name'])),
        'image' => !empty($row['image_url'])
            ? '../uploads/residents/' . $row['image_url']
            : '../uploads/residents/default.jng'
    ];
}
?>


  <!-- 🔴 Barangay Lupon -->
  <div class="highlight-container-red mb-5">
    <button type="button" class="btn edit-button" data-section="Barangay Lupon">EDIT</button>
    <button type="button" class="btn btn-success save-button d-none" data-section="Barangay Lupon">COMPLETE CHANGES</button>

    <div class="inner-blur-wrapper">
      <div class="group-title bg-transparent text-dark">BARANGAY LUPON</div>
      <div class="row text-center justify-content-center">

        <?php foreach ($lupons as $lupon): ?>
          <div class="col-md-3 mb-4 d-flex flex-column align-items-center lupon-card">
            <div class="image-container" style="height: 300px; width: 250px;">
              <img src="<?= $lupon['image'] ?>" alt="<?= $lupon['name'] ?>">
              <div class="action-icons">
                <button class="btn btn-danger delete-btn" data-position="Barangay Lupon" data-name="<?= $lupon['name'] ?>"><i class="bi bi-trash"></i></button>
              </div>
            </div>
            <div class="member-name"><?= $lupon['name'] ?></div>
            <div class="member-position">Barangay Lupon</div>
          </div>
        <?php endforeach; ?>

        <!-- ADD LUPON CARD (hidden by default) -->
        <div class="col-md-3 mb-4 d-flex flex-column align-items-center d-none" id="addLuponCard">
          <div class="image-container d-flex justify-content-center align-items-center" style="height: 300px; width: 250px; cursor: pointer;">
            <i class="bi bi-plus-circle" style="font-size: 60px; color: gray;"></i>
          </div>
          <div class="member-name text-muted">Add Barangay Lupon</div>
        </div>

      </div>
    </div>
  </div>


  <?php
$addressId = intval($_GET['address_id'] ?? 0); // o kung saan man galing ang address id

// HEALTH WORKERS by address_id
$healthWorkers = [];
$healthQuery = mysqli_query(
    $conn,
    "SELECT r.first_name, r.middle_name, r.last_name, r.image_url
     FROM barangay_official bf
     JOIN residents r ON r.id = bf.resident_id
     WHERE bf.position = 'Health Worker' 
       AND r.address_id = $addressId"
);
while ($row = mysqli_fetch_assoc($healthQuery)) {
    $healthWorkers[] = [
        'name'  => strtoupper(trim($row['first_name'].' '.$row['middle_name'].' '.$row['last_name'])),
        'image' => !empty($row['image_url'])
            ? '../uploads/residents/'.$row['image_url']
            : '../image/default-profile.png'
    ];
}

// BNS
$bnsWorkers = [];
$bnsQuery = mysqli_query(
    $conn,
    "SELECT r.first_name, r.middle_name, r.last_name, r.image_url
     FROM barangay_official bf
     JOIN residents r ON r.id = bf.resident_id
     WHERE bf.position = 'BNS'
       AND r.address_id = $addressId"
);
while ($row = mysqli_fetch_assoc($bnsQuery)) {
    $bnsWorkers[] = [
        'name'  => strtoupper(trim($row['first_name'].' '.$row['middle_name'].' '.$row['last_name'])),
        'image' => !empty($row['image_url'])
            ? '../uploads/residents/'.$row['image_url']
            : '../image/default-profile.png'
    ];
}

// VAWC
$vawcWorkers = [];
$vawcQuery = mysqli_query(
    $conn,
    "SELECT r.first_name, r.middle_name, r.last_name, r.image_url
     FROM barangay_official bf
     JOIN residents r ON r.id = bf.resident_id
     WHERE bf.position = 'VAWC'
       AND r.address_id = $addressId"
);
while ($row = mysqli_fetch_assoc($vawcQuery)) {
    $vawcWorkers[] = [
        'name'  => strtoupper(trim($row['first_name'].' '.$row['middle_name'].' '.$row['last_name'])),
        'image' => !empty($row['image_url'])
            ? '../uploads/residents/'.$row['image_url']
            : '../image/default-profile.png'
    ];
}

// SENIOR CITIZEN
$seniorWorkers = [];
$seniorQuery = mysqli_query(
    $conn,
    "SELECT r.first_name, r.middle_name, r.last_name, r.image_url
     FROM barangay_official bf
     JOIN residents r ON r.id = bf.resident_id
     WHERE bf.position = 'Senior Citizen'
       AND r.address_id = $addressId"
);
while ($row = mysqli_fetch_assoc($seniorQuery)) {
    $seniorWorkers[] = [
        'name'  => strtoupper(trim($row['first_name'].' '.$row['middle_name'].' '.$row['last_name'])),
        'image' => !empty($row['image_url'])
            ? '../uploads/residents/'.$row['image_url']
            : '../image/default-profile.png'
    ];
}
?>




    <!-- 🟠 Health Worker Section -->
<div class="highlight-container-orange-green mb-5">
  <button type="button" class="btn edit-button" data-section="Health Worker">EDIT</button>
  <button type="button" class="btn btn-success save-button d-none" data-section="Health Worker">COMPLETE CHANGES</button>

  <div class="inner-blur-wrapper">
    <div class="group-title bg-transparent text-dark">BARANGAY HEALTH WORKER / BNS / VAWC / SENIOR</div>

    <div class="row text-center justify-content-center">

      <!-- 🔸 Health Workers -->
      <?php foreach ($healthWorkers as $hw): ?>
        <div class="col-md-3 mb-4 d-flex flex-column align-items-center">
          <div class="image-container" style="height: 300px; width: 250px;">
            <img src="<?= $hw['image'] ?>" alt="<?= $hw['name'] ?>">
            <div class="action-icons">
              <button class="btn btn-danger delete-btn" data-position="Health Worker" data-name="<?= $hw['name'] ?>"><i class="bi bi-trash"></i></button>
            </div>
          </div>
          <div class="member-name"><?= $hw['name'] ?></div>
          <div class="member-position">Health Worker</div>
        </div>
      <?php endforeach; ?>

      <!-- ➕ Add Health Worker -->
      <div class="col-md-3 mb-4 d-flex flex-column align-items-center d-none" id="addHealthWorkerCard">
        <div class="image-container d-flex justify-content-center align-items-center" style="height: 300px; width: 250px; cursor: pointer;">
          <i class="bi bi-plus-circle" style="font-size: 60px; color: gray;"></i>
        </div>
        <div class="member-name text-muted">Add Health Worker</div>
      </div>

      <!-- 🔹 BNS -->
      <?php foreach ($bnsWorkers as $bns): ?>
        <div class="col-md-3 mb-4 d-flex flex-column align-items-center">
          <div class="image-container" style="height: 300px; width: 250px;">
            <img src="<?= $bns['image'] ?>" alt="<?= $bns['name'] ?>">
            <div class="action-icons">
              <button class="btn btn-danger delete-btn" data-position="BNS" data-name="<?= $bns['name'] ?>"><i class="bi bi-trash"></i></button>
            </div>
          </div>
          <div class="member-name"><?= $bns['name'] ?></div>
          <div class="member-position">BNS</div>
        </div>
      <?php endforeach; ?>

      <!-- ➕ Add BNS -->
      <div class="col-md-3 mb-4 d-flex flex-column align-items-center d-none" id="addBnsCard">
        <div class="image-container d-flex justify-content-center align-items-center " style="height: 300px; width: 250px; cursor: pointer;">
          <i class="bi bi-plus-circle" style="font-size: 60px; color: gray;"></i>
        </div>
        <div class="member-name text-muted">Add BNS</div>
      </div>

      <!-- 🔸 VAWC -->
      <?php foreach ($vawcWorkers as $vawc): ?>
        <div class="col-md-3 mb-4 d-flex flex-column align-items-center">
          <div class="image-container" style="height: 300px; width: 250px;">
            <img src="<?= $vawc['image'] ?>" alt="<?= $vawc['name'] ?>">
            <div class="action-icons">
              <button class="btn btn-danger delete-btn" data-position="VAWC" data-name="<?= $vawc['name'] ?>"><i class="bi bi-trash"></i></button>
            </div>
          </div>
          <div class="member-name"><?= $vawc['name'] ?></div>
          <div class="member-position">VAWC</div>
        </div>
      <?php endforeach; ?>

      <!-- ➕ Add VAWC -->
      <div class="col-md-3 mb-4 d-flex flex-column align-items-center d-none" id="addVawcCard">
        <div class="image-container d-flex justify-content-center align-items-center" style="height: 300px; width: 250px; cursor: pointer;">
          <i class="bi bi-plus-circle" style="font-size: 60px; color: gray;"></i>
        </div>
        <div class="member-name text-muted">Add VAWC</div>
      </div>

      <!-- 🔹 Senior Citizen -->
      <?php foreach ($seniorWorkers as $senior): ?>
        <div class="col-md-3 mb-4 d-flex flex-column align-items-center">
          <div class="image-container" style="height: 300px; width: 250px;">
            <img src="<?= $senior['image'] ?>" alt="<?= $senior['name'] ?>">
            <div class="action-icons">
              <button class="btn btn-danger delete-btn" data-position="Senior Citizen" data-name="<?= $senior['name'] ?>"><i class="bi bi-trash"></i></button>
            </div>
          </div>
          <div class="member-name"><?= $senior['name'] ?></div>
          <div class="member-position">Senior Citizen</div>
        </div>
      <?php endforeach; ?>

      <!-- ➕ Add Senior Citizen -->
      <div class="col-md-3 mb-4 d-flex flex-column align-items-center d-none" id="addSeniorCard">
        <div class="image-container d-flex justify-content-center align-items-center" style="height: 300px; width: 250px; cursor: pointer;">
          <i class="bi bi-plus-circle" style="font-size: 60px; color: gray;"></i>
        </div>
        <div class="member-name text-muted">Add Senior Citizen</div>
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

<script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/js/bootstrap.bundle.min.js"></script>
<script>
$(document).ready(function () {
    // ✅ Load all residents from PHP
    const allResidents = <?php
      include '../database/config.php';
      $res = mysqli_query($conn, "SELECT id, image_url, first_name, middle_name, last_name FROM residents");
      $residents = [];
      while ($row = mysqli_fetch_assoc($res)) {
        $residents[] = $row;
      }
      echo json_encode($residents);
    ?>;

    let currentSection = null;
    let selectedPosition = '';
    let pendingPosition = '';
    let deleteData = {};

    // 🔔 Notification icon
    $('#notifBtn').click(function () {
      $('.badge-number').fadeOut();
      alert('Open notifications panel...');
    });

    // 🖊️ Edit Section
    $('.edit-button').on('click', function () {
      currentSection = $(this).data('section') || 'this section';
      $('#confirmEditLabel').text(`Edit Confirmation`);
      $('#confirmEditModal .modal-body p').text(`Are you sure you want to edit the ${currentSection} section?`);
      $('#confirmEditModal').modal('show');
    });

    // ✅ Confirm Edit
    $('#confirmEditBtn').on('click', function () {
      $('#confirmEditModal').modal('hide');
      const sectionBtn = $(`.edit-button[data-section="${currentSection}"]`);
      const sectionContainer = sectionBtn.closest('.highlight-container-white, .highlight-container-blue, .highlight-container-red, .highlight-container-orange-green');
      sectionContainer.addClass('edit-mode');
      sectionContainer.find('.inner-blur-wrapper').css('filter', 'none');
      $(`.save-button[data-section="${currentSection}"]`).removeClass('d-none');
      sectionBtn.hide();

      if (currentSection === "Barangay Tanod") {
        $('#addTanodCard').removeClass('d-none');
      }
      if (currentSection === "Barangay Lupon") {
        $('#addLuponCard').removeClass('d-none');
      }
      if (currentSection === "Health Worker") {
        $('#addHealthWorkerCard, #addBnsCard, #addVawcCard, #addSeniorCard').removeClass('d-none');
      }

    });

    // 💾 Save Section
    $('.save-button').on('click', function () {
      const section = $(this).data('section');
      const sectionContainer = $(this).closest('.highlight-container-white, .highlight-container-blue, .highlight-container-red, .highlight-container-orange-green');
      sectionContainer.removeClass('edit-mode');
      sectionContainer.find('.inner-blur-wrapper').removeAttr('style');
      $(`.edit-button[data-section="${section}"]`).show();
      $(`.save-button[data-section="${section}"]`).addClass('d-none');

      if (section === "Barangay Tanod") {
        $('#addTanodCard').addClass('d-none');
      }
      if (section === "Barangay Lupon") {
        $('#addLuponCard').addClass('d-none');
      }
      if (section === "Health Worker") {
        $('#addHealthWorkerCard, #addBnsCard, #addVawcCard, #addSeniorCard').addClass('d-none');
      }
    });

    // ✏️ View Button
    $('.view-btn').on('click', function () {
      pendingPosition = $(this).data('position');
      $('#confirmChangePositionLabel').text(`Change ${pendingPosition}`);
      $('#confirmChangePositionModal .modal-body p').text(`Are you sure you want to change ${pendingPosition}?`);
      $('#confirmChangePositionModal').modal('show');
    });

    // Confirm position change
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


    // ✅ Show resident list when modal opens
    $('#residentSelectModal').on('shown.bs.modal', function () {
      renderResidents(allResidents);
      $('#residentSearchInput').val('');
    });

    // ➕ Add Tanod
    $('#addTanodCard').on('click', function () {
      selectedPosition = "Barangay Police";
      $('#residentSelectModalLabel').text(`Select a Resident for Barangay Police`);
      $('#residentSelectModal').modal('show');
    });

    // ➕ Add Lupon
    $('#addLuponCard').on('click', function () {
      selectedPosition = "Barangay Lupon";
      $('#residentSelectModalLabel').text(`Select a Resident for Barangay Lupon`);
      $('#residentSelectModal').modal('show');
    });

    $('#addHealthWorkerCard').on('click', function () {
      selectedPosition = "Health Worker";
      $('#residentSelectModalLabel').text(`Select a Resident for Health Worker`);
      $('#residentSelectModal').modal('show');
    });

    $('#addBnsCard').on('click', function () {
      selectedPosition = "BNS";
      $('#residentSelectModalLabel').text(`Select a Resident for BNS`);
      $('#residentSelectModal').modal('show');
    });

    $('#addVawcCard').on('click', function () {
      selectedPosition = "VAWC";
      $('#residentSelectModalLabel').text(`Select a Resident for VAWC`);
      $('#residentSelectModal').modal('show');
    });

    $('#addSeniorCard').on('click', function () {
      selectedPosition = "Senior Citizen";
      $('#residentSelectModalLabel').text(`Select a Resident for Senior Citizen`);
      $('#residentSelectModal').modal('show');
    });

    // 🧍 Select a Resident
    $('#residentList').on('click', '.resident-card', function () {
      const imageSrc = $(this).data('image');
      const fullName = $(this).data('name');
      const residentId = $(this).data('id');


      if (selectedPosition === 'Barangay Police' || selectedPosition === 'Barangay Lupon') {
        const newCard = `
          <div class="col-md-3 mb-4 d-flex flex-column align-items-center ${selectedPosition === 'Barangay Police' ? 'tanod-card' : 'lupon-card'}">
            <div class="image-container" style="height: 300px; width: 250px;">
              <img src="${imageSrc}" alt="${fullName}">
              <div class="action-icons">
                <button class="btn btn-danger delete-btn" data-position="${selectedPosition}" data-name="${fullName}"><i class="bi bi-trash"></i></button>
              </div>
            </div>
            <div class="member-name">${fullName}</div>
            <div class="member-position">${selectedPosition}</div>
          </div>
        `;

        const cardId = selectedPosition === 'Barangay Police' ? '#addTanodCard' : '#addLuponCard';

        $.post('../database/save_official.php', {
          resident_id: residentId,
          position: selectedPosition
        }, function (response) {
          try {
            const res = JSON.parse(response);
            if (res.status === 'success') {
              $(cardId).before(newCard);
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

        return;
      }

      if (["Health Worker", "BNS", "VAWC", "Senior Citizen"].includes(selectedPosition)) {
          const newCard = `
            <div class="col-md-3 mb-4 d-flex flex-column align-items-center">
              <div class="image-container" style="height: 300px; width: 250px;">
                <img src="${imageSrc}" alt="${fullName}">
                <div class="action-icons">
                  <button class="btn btn-danger delete-btn" data-position="${selectedPosition}" data-name="${fullName}">
                    <i class="bi bi-trash"></i>
                  </button>
                </div>
              </div>
              <div class="member-name">${fullName}</div>
              <div class="member-position">${selectedPosition}</div>
            </div>
          `;

          let cardId = '';
          switch (selectedPosition) {
            case 'Health Worker':
              cardId = '#addHealthWorkerCard';
              break;
            case 'BNS':
              cardId = '#addBnsCard';
              break;
            case 'VAWC':
              cardId = '#addVawcCard';
              break;
            case 'Senior Citizen':
              cardId = '#addSeniorCard';
              break;
          }


          $.post('../database/save_official.php', {
            resident_id: residentId,
            position: selectedPosition
          }, function (response) {
            try {
              const res = JSON.parse(response);
              if (res.status === 'success') {
                $(cardId).before(newCard);
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

          return;
        }


      // For fixed position (Chairman, Secretary, etc.)
      const container = $(`.view-btn[data-position="${selectedPosition}"]`).closest('.image-container');
      const nameContainer = container.closest('.d-flex').find('.member-name');

      $.post('../database/save_official.php', {
        resident_id: residentId,
        position: selectedPosition
      }, function (response) {
        try {
          const res = JSON.parse(response);
          if (res.status === 'success') {
            container.find('img').attr('src', imageSrc);
            nameContainer.text(fullName);
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

    // Confirm delete
    $('#confirmDeleteBtn').on('click', function () {
      const { card, position, name } = deleteData;

      $.post('../database/official_delete.php', { position, name }, function (response) {
        try {
          const res = JSON.parse(response);
          if (res.status === 'success') {
           const removablePositions = ['Barangay Police', 'Barangay Lupon', 'Health Worker', 'BNS', 'VAWC', 'Senior Citizen'];
           location.reload();

            if (removablePositions.includes(position)) {
              card.remove();
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
