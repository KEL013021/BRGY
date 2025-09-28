<?php 
session_start();
include 'sidebar.php';
include '../database/config.php';

// ✅ Check login
if (!isset($_SESSION['user_id'])) {
    header("Location: ../../BRGYGO/login_signup.php");
    exit;
}

$user_id = $_SESSION['user_id'];

// Kunin si resident_id gamit user_id
$resSql = "SELECT id, address_id FROM residents WHERE user_id = ?";
$resStmt = $conn->prepare($resSql);
$resStmt->bind_param("i", $user_id);
$resStmt->execute();
$resResult = $resStmt->get_result();
$resident = $resResult->fetch_assoc();

if (!$resident) {
    die("No resident record found.");
}

$resident_id = $resident['id'];
$address_id = $resident['address_id'];
?>
<link rel="stylesheet" type="text/css" href="../css/document.css">

<div class="header">
  <div class="logo-text">
    <span class="b">Docu</span><span class="g">ments</span>
  </div>
  <a href="profile.php" class="btn btn-light btn-sm rounded-circle" style="width:45px; height:45px;">
    <i class="bi bi-person text-primary"></i>
  </a>
</div>

<main class="content">
  <div class="cards-container">

    <!-- Main Card -->
    <div class="card" id="mainCard">
      <div style="text-align:center; font-size:18px; font-weight:bold; margin-bottom:10px;">
        📄 Need a Barangay Document?
      </div>
      <button style="display:block; margin:0 auto;" onclick="showForm()">Request Document</button>
    </div>

    <!-- Requests Card -->
    <div class="requests-card" id="requestsCard">
      <div style="text-align:center; font-size:18px; font-weight:bold; margin-bottom:10px;">
        Your Requests
      </div>
      <div id="requests-container">
        <p class="text-center text-dark mt-3">Loading your requests...</p>
      </div>
    </div>

    <!-- Form Card -->
    <div class="form-card" id="formCard">
      <span class="back-btn" onclick="hideForm()"><i class="bi bi-x-circle"></i></span>
      <label>Document Type</label>
      <select id="docType">
        <option value="">-- Choose a document --</option>
        <?php
        // Fetch available services under same address_id
        $srvSql = "SELECT id, service_name, service_fee FROM services WHERE address_id = ?";
        $srvStmt = $conn->prepare($srvSql);
        $srvStmt->bind_param("i", $address_id);
        $srvStmt->execute();
        $srvResult = $srvStmt->get_result();
        while($srv = $srvResult->fetch_assoc()):
        ?>
          <option value="<?= $srv['id'] ?>">
            <?= htmlspecialchars($srv['service_name']) ?> (₱<?= $srv['service_fee'] ?>)
          </option>
        <?php endwhile; ?>
      </select>

      <label>Purpose</label>
      <textarea id="purpose" placeholder="Enter purpose"></textarea>

      <button onclick="submitRequest()">Send Request</button>
    </div>

  </div>
</main>

<?php include 'tabbar.php'; ?>

<script>
function showForm() {
  document.getElementById('formCard').style.display = 'block';
  document.getElementById('mainCard').style.display = 'none';
  document.getElementById('requestsCard').style.display = 'none';
}

function hideForm() {
  document.getElementById('formCard').style.display = 'none';
  document.getElementById('mainCard').style.display = 'block';
  document.getElementById('requestsCard').style.display = 'block';
}

function fetchRequests() {
  fetch('../database/requests_fetch.php')
    .then(res => res.json())
    .then(data => {
      let container = document.getElementById('requests-container');
      if (data.length === 0) {
        container.innerHTML = '<p class="text-center text-dark mt-3">No requests yet.</p>';
      } else {
        let html = '';
        data.forEach(req => {
          html += `<div class="request-item">
                     <span>${req.service_name} (₱${req.service_fee})</span>
                     <span>${req.status}</span>
                   </div>`;
        });
        container.innerHTML = html;
      }
    });
}

function submitRequest() {
  const doc = document.getElementById('docType').value;
  const purpose = document.getElementById('purpose').value;
  if (!doc || !purpose) {
    alert('Please complete all fields.');
    return;
  }

  fetch('../database/requests_submit.php', {
    method: 'POST',
    headers: {'Content-Type':'application/x-www-form-urlencoded'},
    body: `service_id=${encodeURIComponent(doc)}&purpose=${encodeURIComponent(purpose)}`
  })
  .then(res => res.text())
  .then(msg => {
    alert(msg);
    hideForm();
    fetchRequests(); // refresh requests list
  });
}

// ✅ Initial load
fetchRequests();
</script>
