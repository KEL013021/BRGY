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
        WHERE r.address_id = ? AND r.status = 'Pending'
        ORDER BY r.id ASC";

$stmt = $conn->prepare($sql);
$stmt->bind_param("i", $address_id);
$stmt->execute();
$result = $stmt->get_result();

?>

<title>Barangay Request - BRGY GO</title>

<!-- CSS -->
<link rel="stylesheet" type="text/css" href="../css/request_services.css">
<link href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0/css/all.min.css" rel="stylesheet">

<script src="https://cdnjs.cloudflare.com/ajax/libs/pdf.js/2.10.377/pdf.min.js"></script>

<!-- Navbar -->
<nav class="navbar">
  <div class="navbar-container">
    <div class="section-name">Request Services</div>
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
          <th style="width: 280px; cursor:pointer;">PURPOSE <span class="sort-arrow"></span></th>
          <th style="width: 150px; cursor:pointer;" onclick="sortTable(3)">REQUEST DATE <span class="sort-arrow"></span></th>
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
                  echo '<tr class="table-row" data-id="' . $row['id'] . '" style="cursor:pointer;">';
                  echo '<td class="table-cell name-text" style="width:250px;">' . htmlspecialchars($row['last_name'] . ', ' . $row['first_name']) . '</td>';
                  echo '<td class="table-cell name-text" style="width:250px;">' . htmlspecialchars($row['service_name']) . '</td>';
                  echo '<td class="table-cell info-text" style="width:280px;">' . htmlspecialchars($row['purpose']) . '</td>';
                  echo '<td class="table-cell info-text" style="width:150px;">' . htmlspecialchars($row['request_date']) . '</td>';
                  echo '</tr>';
              }
          } else {
              echo '<tr><td colspan="4" style="text-align:center;">No requests found.</td></tr>';
          }
          ?>
        </tbody>
      </table>
    </div>
  </div>

  <!-- Footer -->
  <div class="table-footer" style="border-bottom-left-radius: 20px;border-bottom-right-radius: 20px;">
    <div class="footer-info"></div>
    <div class="footer-buttons">
      <button class="btn btn-primary" data-bs-toggle="modal" data-bs-target="#addRequestModal">
        <i class="fas fa-plus"></i> Add New
      </button>
    </div>
  </div>
</div>

<?php $conn->close(); ?>


<!-- Bootstrap Modal -->
<div class="modal fade" id="addRequestModal" tabindex="-1" aria-hidden="true">
  <div class="modal-dialog modal-dialog-centered modal-lg">
    <div class="modal-content rounded-4 border-0 shadow-lg overflow-hidden">

      <!-- Header -->
      <div class="modal-header text-white"
           style="background: linear-gradient(to right, #2563eb, #7c3aed);">
        <div>
          <h5 class="modal-title fw-bold">Add New Request</h5>
          <p class="mb-0 small text-light">Select a resident and service to create a request</p>
        </div>
        <button type="button" class="btn-close btn-close-white" data-bs-dismiss="modal"></button>
      </div>

      <!-- Body -->
      <div class="modal-body p-4" style="max-height:70vh; overflow-y:auto;">
        
        <!-- Resident Selection -->
        <div id="residentSelectContainer">
          <h6 class="fw-semibold mb-3">
            <i class="fas fa-users text-primary me-2"></i> Select Resident
          </h6>

          <!-- Search Input -->
          <div class="input-group mb-3 shadow-sm">
            <span class="input-group-text bg-white border-end-0">
              <i class="fas fa-search text-muted"></i>
            </span>
            <input type="text" id="residentSearch" class="form-control border-start-0"
                   placeholder="Search by name..." oninput="filterResidents()">
          </div>

          <!-- Resident List -->
          <div id="residentList" class="row g-3" style="max-height:250px; overflow-y:auto;">
            <?php foreach ($residents as $res): ?>
              <div class="col-md-4">
                <div class="card shadow-sm resident-card" 
                     onclick="selectResident(<?= $res['id'] ?>, '<?= htmlspecialchars($res['first_name'].' '.$res['last_name']) ?>', '<?= $res['image_url'] ?>')">
                  <div class="card-body text-center">
                    <img src="<?= $res['image_url'] ?: '../images/default.png' ?>" 
                         class="rounded-circle mb-2" style="width:60px; height:60px; object-fit:cover;">
                    <h6 class="mb-0"><?= htmlspecialchars($res['first_name'].' '.$res['last_name']) ?></h6>
                  </div>
                </div>
              </div>
            <?php endforeach; ?>
          </div>
        </div>

        <!-- Service Selection (hidden by default) -->
        <div id="serviceSelectContainer" class="d-none">
          
          <!-- Selected Resident Display -->
          <div class="d-flex align-items-center p-3 mb-4 rounded-3 border shadow-sm"
               style="background: linear-gradient(to right, #ecfdf5, #eff6ff);">
            <img id="selectedResidentImg" src="" 
                 class="rounded-circle border border-white shadow-sm"
                 style="width:70px; height:70px; object-fit:cover;">
            <div class="ms-3 flex-grow-1">
              <h6 class="mb-0 fw-bold" id="selectedResidentName"></h6>
              <small class="text-muted">Selected Resident</small>
            </div>
            <button type="button" onclick="changeResident()" 
                    class="btn btn-sm btn-outline-danger">
              <i class="fas fa-exchange-alt me-1"></i> Change
            </button>
          </div>

          <!-- Service Dropdown -->
          <div class="mb-3">
            <label class="form-label fw-semibold">
              <i class="fas fa-cog text-primary me-2"></i> Select Service
            </label>
            <select id="serviceDropdown" class="form-select shadow-sm" required>
              <option value="">-- Choose a service --</option>
              <?php foreach ($services as $svc): ?>
                <option value="<?= $svc['id'] ?>"><?= htmlspecialchars($svc['service_name']) ?></option>
              <?php endforeach; ?>
            </select>
          </div>

            <!-- Purpose Input -->
            <div class="mb-3">
              <label class="form-label fw-semibold">
                <i class="fas fa-pencil-alt text-primary me-2"></i> Purpose
              </label>
              <textarea id="purposeInput" class="form-control shadow-sm" rows="3"
                        placeholder="Enter the purpose of this request..." required></textarea>
            </div>

        </div>

      </div>

      <!-- Footer -->
      <div class="modal-footer bg-light border-0">
        <button type="button" class="btn btn-outline-secondary rounded-3 px-4"
                data-bs-dismiss="modal">Cancel</button>
        <button type="button" id="submitBtn" onclick="submitRequest()"
                class="btn btn-success rounded-3 px-4 shadow-sm" disabled>
          <i class="fas fa-paper-plane me-1"></i> Submit Request
        </button>
      </div>
    </div>
  </div>
</div>



<!-- PDF Preview Modal -->
<div class="modal fade" id="pdfPreviewModal" tabindex="-1" aria-hidden="true">
    <div class="modal-dialog modal-lg modal-dialog-centered">
        <div class="modal-content">
            <div class="modal-header bg-dark text-white">
                <h5 class="modal-title">📄 PDF Preview</h5>
                <button type="button" class="btn-close btn-close-white" data-bs-dismiss="modal" aria-label="Close"></button>
            </div>
            <div class="modal-body p-0" style="justify-content: center; display: flex; margin: 20px;">
                <div id="previewWrapper" style="position: relative;">
                    <canvas id="previewPdfCanvas" style="border: 3px solid black;"></canvas>
                </div>
            </div>
            <div class="modal-footer justify-content-end">
                <button class="btn btn-danger btn-lg rounded-3 px-4 py-2 shadow-sm align-items-center justify-content-center gap-2" 
                        onclick="declineRequest()" 
                        style="color: black; width:150px;">
                    <i class="bi bi-file-earmark-x"></i> Decline
                </button>
            
                <button id="printBtn" 
                        class="btn btn-primary btn-lg rounded-3 px-4 py-2 shadow-sm align-items-center justify-content-center gap-2" 
                        onclick="printCanvas()"  
                        style="color: black; width:150px;">
                    <i class="bi bi-printer"></i> Print
                </button>
            
                <!-- ✅ Hidden by default -->
                <button id="confirmPrintBtn" 
                        class="btn btn-success btn-lg rounded-3 px-4 py-2 shadow-sm align-items-center justify-content-center gap-2" 
                        style="width:220px; display:none;" 
                        onclick="confirmPrinted()">
                    <i class="bi bi-check-circle"></i> Mark as Printed
                </button>
            </div>

        </div>
    </div>
</div>

<!-- Decline Confirmation Modal -->
<div class="modal fade" id="confirmDeclineModal" tabindex="-1" aria-hidden="true">
  <div class="modal-dialog modal-dialog-centered">
    <div class="modal-content border-0 shadow-lg rounded-3">
      <div class="modal-header bg-danger text-white">
        <h5 class="modal-title">Confirm Decline</h5>
        <button type="button" class="btn-close btn-close-white" data-bs-dismiss="modal"></button>
      </div>
      <div class="modal-body">
        <p id="confirmDeclineText" class="fs-5 text-center"></p>
      </div>
      <div class="modal-footer">
        <button type="button" class="btn btn-secondary" data-bs-dismiss="modal">Cancel</button>
        <button type="button" class="btn btn-danger" onclick="confirmDecline()">Yes, Decline</button>
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

let sortState = {}; // track sort per column
let originalRows = null;

function sortTable(colIndex) {
  const tbody = document.getElementById("requestTableBody");

  // Save original order once
  if (!originalRows) {
    originalRows = Array.from(tbody.querySelectorAll("tr"));
  }

  sortState[colIndex] = (sortState[colIndex] || 0) + 1;
  if (sortState[colIndex] > 2) sortState[colIndex] = 0;

  let rows = Array.from(tbody.querySelectorAll("tr"));

  if (sortState[colIndex] === 0) {
    // Reset to original order
    tbody.innerHTML = "";
    originalRows.forEach(r => tbody.appendChild(r));
  } else {
    const dir = sortState[colIndex] === 1 ? 1 : -1;
    rows.sort((a, b) => {
      let aText = a.cells[colIndex].innerText.toLowerCase();
      let bText = b.cells[colIndex].innerText.toLowerCase();

      // If column is REQUEST DATE (colIndex = 3), compare as dates
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



  pdfjsLib.GlobalWorkerOptions.workerSrc =
    "https://cdnjs.cloudflare.com/ajax/libs/pdf.js/2.10.377/pdf.worker.min.js";

    document.addEventListener("DOMContentLoaded", function () {
    // Load residents kapag nag-open ang modal
    let addRequestModal = document.getElementById("addRequestModal");
    addRequestModal.addEventListener("show.bs.modal", function () {
        loadResidents();
    });
});

function loadResidents() {
    fetch("../database/request_resident_fetch.php")
        .then(res => res.json())
        .then(data => {
            let residentList = document.getElementById("residentList");
            residentList.innerHTML = "";
            if (data.length === 0) {
                residentList.innerHTML = "<p class='text-muted'>No residents found.</p>";
                return;
            }

            data.forEach(resident => {
    let imagePath = resident.image_url ? `../uploads/residents/${resident.image_url}` : "uploads/residents/logo.png";

    let card = document.createElement("div");
    card.className = "col-md-6";
    card.innerHTML = `
        <div class="resident-card p-3 shadow-sm border d-flex align-items-center" style="cursor: pointer" 
             onclick="selectResident(${resident.id}, '${resident.first_name} ${resident.last_name}', '${imagePath}')">
            <img src="${imagePath}" 
                 class="rounded-circle me-3" style="width:50px; height:50px; object-fit:cover;">
            <div>
                <h6 class="mb-0 fw-bold">${resident.first_name} ${resident.last_name}</h6>
                <small class="text-muted">Resident</small>
            </div>
        </div>`;
    residentList.appendChild(card);
});

        });
}

let selectedResidentId = null;

function selectResident(id, name, img) {
    selectedResidentId = id;

    document.getElementById("residentSelectContainer").classList.add("d-none");
    document.getElementById("serviceSelectContainer").classList.remove("d-none");

    document.getElementById("selectedResidentName").innerText = name;
    document.getElementById("selectedResidentImg").src = img;

    loadServices();
}

function changeResident() {
    document.getElementById("serviceSelectContainer").classList.add("d-none");
    document.getElementById("residentSelectContainer").classList.remove("d-none");
}

function loadServices() {
    fetch("../database/request_services_fetch.php")
        .then(res => res.json())
        .then(data => {
            let dropdown = document.getElementById("serviceDropdown");
            dropdown.innerHTML = '<option value="">-- Choose a service --</option>';

            data.forEach(service => {
                let option = document.createElement("option");
                option.value = service.id;
                option.textContent = service.service_name;
                dropdown.appendChild(option);
            });

            dropdown.addEventListener("change", function () {
                document.getElementById("submitBtn").disabled = this.value === "";
            });
        });
}
function submitRequest() {
    let serviceId = document.getElementById("serviceDropdown").value;
    let purpose = document.getElementById("purposeInput").value.trim();

    if (!selectedResidentId || !serviceId || !purpose) {
        alert("Please fill all fields.");
        return;
    }

    fetch("../database/request_add.php", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
            resident_id: selectedResidentId,
            service_id: serviceId,
            purpose: purpose
        })
    })
    .then(res => res.json())
    .then(response => {
        if (response.success) {
            alert("✅ Request submitted successfully!");
            location.reload();
        } else {
            alert("❌ Error: " + response.error);
        }
    });
}


document.addEventListener("DOMContentLoaded", function () {
    // Make rows clickable
    document.querySelectorAll(".table-row").forEach(row => {
        row.addEventListener("click", function () {
            let requestId = this.getAttribute("data-id");
            openPdfPreview(requestId);
        });
    });
});

function openPdfPreview(requestId) {
  window.currentRequestId = requestId;
    const pdfModal = new bootstrap.Modal(document.getElementById("pdfPreviewModal"));
    pdfModal.show();

    const previewWrapper = document.getElementById("previewWrapper");
    previewWrapper.innerHTML = ""; // clear old canvases

    fetch(`../database/request_fetch.php?id=${requestId}`)
        .then(res => {
            if (!res.ok) throw new Error("PDF not found");
            return res.blob();
        })
        .then(blob => {
            const fileReader = new FileReader();
            fileReader.onload = () => {
                const typedArray = new Uint8Array(fileReader.result);

                pdfjsLib.getDocument(typedArray).promise.then(pdf => {
                    const scale = 1.2; // adjust zoom
                    const renderPromises = [];

                    for (let pageNum = 1; pageNum <= pdf.numPages; pageNum++) {
                        renderPromises.push(
                            pdf.getPage(pageNum).then(page => {
                                const viewport = page.getViewport({ scale });

                                // Create canvas per page
                                const canvas = document.createElement("canvas");
                                canvas.classList.add("mb-3", "shadow-sm");
                                const ctx = canvas.getContext("2d");
                                canvas.width = viewport.width;
                                canvas.height = viewport.height;

                                // Append canvas sa wrapper
                                previewWrapper.appendChild(canvas);

                                // Render page
                                return page.render({
                                    canvasContext: ctx,
                                    viewport: viewport
                                }).promise;
                            })
                        );
                    }

                    return Promise.all(renderPromises);
                });
            };
            fileReader.readAsArrayBuffer(blob);
        })
        .catch(err => {
            console.error("❌ PDF load failed:", err);
            previewWrapper.innerHTML =
                "<p class='text-danger text-center'>⚠️ Failed to load PDF.</p>";
        });
}

    
function printCanvas() {
    if (!window.currentRequestId) {
        alert("⚠️ No request selected to print.");
        return;
    }

    const pdfUrl = `../database/request_fetch.php?id=${window.currentRequestId}`;
    const iframe = document.createElement("iframe");
    iframe.style.display = "none";
    iframe.src = pdfUrl;

    iframe.onload = () => {
        // Open print dialog
        iframe.contentWindow.focus();
        iframe.contentWindow.print();

        // ✅ Show the "Mark as Printed" button beside Print
        const confirmBtn = document.getElementById("confirmPrintBtn");
        if (confirmBtn) confirmBtn.style.display = "inline-flex";
    };

    document.body.appendChild(iframe);
}

// ✅ Update request when "Mark as Printed" is clicked
function confirmPrinted() {
    fetch("../database/request_update_status.php", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ id: window.currentRequestId })
    })
    .then(res => res.json())
    .then(response => {
        if (response.success) {
            console.log("✅ Request updated to CLAIMABLE.");
            location.reload();
        } else {
            console.error("❌ Update failed:", response.error);
        }
    })
    .catch(err => console.error("❌ Fetch error:", err));
}

// ✅ Reset "Mark as Printed" button every time modal closes
document.getElementById('pdfPreviewModal').addEventListener('hidden.bs.modal', () => {
    const confirmBtn = document.getElementById("confirmPrintBtn");
    if (confirmBtn) confirmBtn.style.display = "none";
});


function declineRequest() {
    if (!window.currentRequestId) {
        alert("⚠️ No request selected to decline.");
        return;
    }

    // Kunin details ng current row para makita ang pangalan at service
    const row = document.querySelector(`tr[data-id="${window.currentRequestId}"]`);
    const name = row ? row.children[0].textContent : "Unknown";
    const service = row ? row.children[1].textContent : "Service";

    // I-set yung message sa modal
     document.getElementById("confirmDeclineText").innerHTML =
        `Are you sure you want to decline the service request of <strong>${name}</strong> for <strong>${service}</strong>?`;

    // Open modal
    var declineModal = new bootstrap.Modal(document.getElementById("confirmDeclineModal"));
    declineModal.show();
}

// Kapag na-confirm sa modal
function confirmDecline() {
    fetch("../database/request_decline_status.php", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ id: window.currentRequestId })
    })
    .then(res => res.json())
    .then(response => {
        if (response.success) {
            alert("🚫 Request has been declined.");
            location.reload();
        } else {
            alert("❌ Error: " + response.error);
        }
    })
    .catch(err => console.error("❌ Fetch error:", err));
}



</script>
