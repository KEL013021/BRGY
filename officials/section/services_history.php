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
$stmtAddr = $conn->prepare($sqlAddress);
$stmtAddr->bind_param("i", $real_user_id);
$stmtAddr->execute();
$resultAddr = $stmtAddr->get_result();

if ($rowAddr = $resultAddr->fetch_assoc()) {
    $address_id = $rowAddr['address_id'];
} else {
    die(json_encode(["error" => "No address record found for this user."]));
}

// ✅ Fetch requests + join para makuha names & service details
$sql = "SELECT r.id, r.purpose, r.request_date, r.status,
               res.first_name, res.last_name,
               s.service_name
        FROM requests r
        LEFT JOIN residents res ON r.resident_id = res.id
        LEFT JOIN services s ON r.service_id = s.id
        WHERE r.address_id = ? AND r.status <> 'Pending'
        ORDER BY r.id ASC";

$stmt = $conn->prepare($sql);
$stmt->bind_param("i", $address_id);
$stmt->execute();
$result = $stmt->get_result();

?>

<title>Barangay History - BRGY GO</title>

<!-- CSS -->
<link rel="stylesheet" type="text/css" href="../css/history.css">
<link href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0/css/all.min.css" rel="stylesheet">

<script src="https://cdnjs.cloudflare.com/ajax/libs/pdf.js/2.10.377/pdf.min.js"></script>

<!-- Navbar -->
<nav class="navbar">
  <div class="navbar-container">
    <div class="section-name">Services History</div>
    <div class="notification-wrapper" id="notifBtn">
      <i class="bi bi-bell-fill" style="font-size: 35px;"></i>
      <span class="badge-number">4</span>
    </div>
  </div>
</nav>  

<div class="table-container">
  <!-- Search Bar -->
  <div class="search-section">
    <div class="search-wrapper">
      <div class="search-icon">
        <i class="fas fa-search"></i>
      </div>
      <input 
        type="text" 
        id="searchInput"
        class="search-input"
        placeholder="Search requests..."
        onkeyup="searchTable()"
      >
    </div>
  </div>

  <!-- Table -->
  <div style="overflow-x: auto;">
    <table class="data-table">
      <thead class="table-header" style="border-top-left-radius: 20px; border-top-right-radius: 20px; border-right: none;">
        <tr>
          <th style="width: 250px; cursor:pointer;" onclick="sortTable(0)">RESIDENT NAME <span class="sort-arrow"></span></th>
          <th style="width: 250px; cursor:pointer;" onclick="sortTable(1)">SERVICE NAME <span class="sort-arrow"></span></th>
          <th style="width: 260px; cursor:pointer;" onclick="sortTable(2)">PURPOSE <span class="sort-arrow"></span></th>
          <th style="width: 170px; cursor:pointer;" onclick="sortTable(3)">REQUEST DATE <span class="sort-arrow"></span></th>
          <th style="width: 150px; cursor:pointer;" onclick="sortTable(4)">STATUS <span class="sort-arrow"></span></th>
        </tr>
      </thead>
    </table>

    <!-- Scrollable Body -->
    <div class="table-body-wrapper">
      <table class="data-table">
        <tbody class="table-body" id="requestTableBody">
          <?php
if ($result && mysqli_num_rows($result) > 0) {
    while($row = mysqli_fetch_assoc($result)) {
        $status = $row['status'];
        $statusClass = "";
        $statusText = htmlspecialchars($status);

        // ✅ Add styling conditions
        if ($status === "Declined") {
            $statusClass = "status-declined";
        } elseif ($status === "Claimable") {
            $statusClass = "status-claimable";
        } elseif ($status === "Claimed") {
            $statusClass = "status-claimed";
        }

        echo '<tr class="table-row" data-id="' . $row['id'] . '" 
                data-service="' . htmlspecialchars($row['service_name']) . '" 
                data-resident="' . htmlspecialchars($row['first_name'] . ' ' . $row['last_name']) . '" 
                style="cursor:pointer;">';
        echo '<td class="table-cell name-text" style="width:250px;">' . htmlspecialchars($row['last_name'] . ', ' . $row['first_name']) . '</td>';
        echo '<td class="table-cell name-text" style="width:250px;">' . htmlspecialchars($row['service_name']) . '</td>';
        echo '<td class="table-cell info-text" style="width:260px;">' . htmlspecialchars($row['purpose']) . '</td>';
        echo '<td class="table-cell info-text" style="width:170px;">' . htmlspecialchars($row['request_date']) . '</td>';
        echo '<td class="table-cell info-text ' . $statusClass . '" style="width:150px;">' . $statusText . '</td>';
        echo '</tr>';
    }
} else {
    echo '<tr><td colspan="5" style="text-align:center;">No requests found.</td></tr>';
}
?>

        </tbody>
      </table>
    </div>
  </div>

  <!-- Footer -->
  <div class="table-footer" style="border-bottom-left-radius: 20px;border-bottom-right-radius: 20px;">
    <div class="footer-info"></div>
  </div>
</div>
<?php $conn->close(); ?>

<!-- Modern Claim Modal -->
<div class="modal fade" id="claimModal" tabindex="-1" aria-hidden="true">
  <div class="modal-dialog modal-dialog-centered">
    <div class="modal-content shadow-lg border-0 rounded-3">

      <!-- HEADER -->
      <div class="modal-header border-0 bg-success">
        <h5 class="modal-title fw-bold text-black">
          <i class="fas fa-check-circle me-2 text-black"></i> Claim Service
        </h5>
        <button type="button" class="btn-close" data-bs-dismiss="modal"></button>
      </div>

      <!-- BODY -->
      <div class="modal-body text-center py-4" id="claimModalBody">
        <!-- Dynamic content goes here -->
      </div>

      <!-- FOOTER -->
      <div class="modal-footer border-0 justify-content-center">
        <button type="button" class="btn btn-secondary px-4" data-bs-dismiss="modal">
          <i class="fas fa-times me-1"></i> Cancel
        </button>
        <button type="button" id="confirmClaimBtn" class="btn btn-success px-4">
          <i class="fas fa-check me-1"></i> Claim
        </button>
      </div>

    </div>
  </div>
</div>

<script>

function searchTable() {
  let input = document.getElementById("searchInput").value.toLowerCase();
  document.querySelectorAll("#requestTableBody tr").forEach(row => {
    row.style.display = row.innerText.toLowerCase().includes(input) ? "" : "none";
  });
}

let sortState = {}; // column: 0=original,1=asc,2=desc
let originalRows = null;

function sortTable(colIndex) {
  const tbody = document.querySelector("#requestTableBody");

  if (!originalRows) originalRows = Array.from(tbody.querySelectorAll("tr"));

  sortState[colIndex] = (sortState[colIndex] || 0) + 1;
  if (sortState[colIndex] > 2) sortState[colIndex] = 0;

  let rows = Array.from(tbody.querySelectorAll("tr"));

  if (sortState[colIndex] === 0) {
    tbody.innerHTML = "";
    originalRows.forEach(r => tbody.appendChild(r));
  } else {
    const dir = sortState[colIndex] === 1 ? 1 : -1;
    rows.sort((a, b) => {
      const aText = a.cells[colIndex].innerText.toLowerCase();
      const bText = b.cells[colIndex].innerText.toLowerCase();

      // special case: kung Request Date (col 3), i-compare as date
      if (colIndex === 3) {
        return (new Date(aText) - new Date(bText)) * dir;
      }

      return aText.localeCompare(bText) * dir;
    });
    tbody.innerHTML = "";
    rows.forEach(r => tbody.appendChild(r));
  }

  // Reset arrows
  document.querySelectorAll(".sort-arrow").forEach(el => el.innerHTML = "");
  const arrow = sortState[colIndex] === 1 ? "▲" : (sortState[colIndex] === 2 ? "▼" : "");
  document.querySelector(`thead th:nth-child(${colIndex + 1}) .sort-arrow`).innerHTML = arrow;
}


document.addEventListener("DOMContentLoaded", function() {
  let selectedRowId = null;

  // When clicking on Claimable row
  document.querySelectorAll(".status-claimable").forEach(function(cell) {
    cell.addEventListener("click", function(e) {
      e.stopPropagation();
      const row = this.closest("tr");
      selectedRowId = row.dataset.id;
      const service = row.dataset.service;
      const resident = row.dataset.resident;

      document.getElementById("claimModalBody").innerHTML = 
        `<p><strong>${service}</strong> claimed by <strong>${resident}</strong></p>`;

      new bootstrap.Modal(document.getElementById("claimModal")).show();
    });
  });

  // Confirm Claim
  document.getElementById("confirmClaimBtn").addEventListener("click", function() {
    if (!selectedRowId) return;

    // ✅ Ajax to update status
    fetch("../database/history_update_claim.php", {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: "id=" + selectedRowId
    })
    .then(res => res.json())
    .then(data => {
      if (data.success) {
        // Update row visually
        const row = document.querySelector(`tr[data-id='${selectedRowId}'] td:last-child`);
        row.textContent = "Claimed";
        row.className = "table-cell info-text status-claimed";

        bootstrap.Modal.getInstance(document.getElementById("claimModal")).hide();
      } else {
        alert("Failed to update claim.");
      }
    });
  });
});
</script>
