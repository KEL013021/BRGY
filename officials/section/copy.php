<?php
session_start();
include('sidebar.php'); 
include('../database/config.php'); // Database connection

// ✅ Check kung naka-login
if (!isset($_SESSION['user_id'])) {
    die(json_encode(["error" => "User not logged in."]));
}

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

// ✅ Fetch services base sa address_id ng user
$sql = "SELECT id, service_name, description, requirements, service_fee 
        FROM services 
        WHERE address_id = ? 
        ORDER BY id ASC";
$stmt = $conn->prepare($sql);
$stmt->bind_param("i", $address_id);
$stmt->execute();
$result = $stmt->get_result();
?>

<title>Barangay Services - BRGY GO</title>

<!-- CSS / Icons -->
<link rel="stylesheet" type="text/css" href="../css/services.css">
<link href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0/css/all.min.css" rel="stylesheet">
<script src="https://cdnjs.cloudflare.com/ajax/libs/pdf.js/2.10.377/pdf.min.js"></script>

<!-- 🔹 Navbar -->
<nav class="navbar">
  <div class="navbar-container">
    <div class="section-name">Barangay Services</div>
    <div class="notification-wrapper" id="notifBtn">
      <i class="bi bi-bell-fill" style="font-size: 35px;"></i>
      <span class="badge-number">4</span>
    </div>
  </div>
</nav>  

<!-- 🔹 Table Container -->
<div class="table-container">

  <!-- 🔍 Search Bar -->
  <div class="search-section">
    <div class="search-wrapper">
      <div class="search-icon"><i class="fas fa-search"></i></div>
      <input 
        type="text" 
        id="searchInput"
        class="search-input"
        placeholder="Search services..."
        onkeyup="searchTable()"
      >
    </div>
  </div>

  <!-- 📋 Table -->
  <div style="overflow-x: auto;">
    <table class="data-table">
      <thead class="table-header" style="border-top-left-radius: 20px; border-top-right-radius: 20px; border-right: none;">
        <tr>
          <th style="width: 250px; cursor:pointer;" onclick="sortTable(1)">SERVICE NAME<span class="sort-arrow"></span></th>
          <th style="width: 250px; cursor:pointer;" onclick="sortTable(2)">DESCRIPTION <span class="sort-arrow"></span></th>
          <th style="width: 250px; cursor:pointer;" onclick="sortTable(3)">REQUIREMENTS <span class="sort-arrow"></span></th>
          <th style="width: 120px; cursor:pointer;" onclick="sortTable(4)">FEE<span class="sort-arrow"></span></th>
        </tr>
      </thead>
    </table>

    <!-- Scrollable Body -->
    <div class="table-body-wrapper">
      <table class="data-table">
        <tbody class="table-body" id="residentTableBody">
          <?php
          if ($result && mysqli_num_rows($result) > 0) {
              while($row = mysqli_fetch_assoc($result)) {
                  echo '<tr class="table-row" data-id="' . $row['id'] . '" style="cursor:pointer;">';
                  echo '<td class="table-cell name-text" style="width:250px;">' . htmlspecialchars($row['service_name']) . '</td>';
                  echo '<td class="table-cell info-text" style="width:250px;">' . htmlspecialchars($row['description']) . '</td>';
                  echo '<td class="table-cell info-text" style="width:250px;">' . htmlspecialchars($row['requirements']) . '</td>';
                  echo '<td class="table-cell info-text" style="width:120px;">' . htmlspecialchars($row['service_fee']) . '</td>';
                  echo '</tr>';
              }
          } else {
              echo '<tr><td colspan="4" style="text-align:center;">No services found.</td></tr>';
          }
          ?>
        </tbody>
      </table>
    </div>
  </div>

  <!-- Footer -->
  <div class="table-footer">
    <div class="footer-info"></div>
    <div class="footer-buttons">
      <button class="btn btn-primary" data-bs-toggle="modal" data-bs-target="#addServiceModal">
        <i class="fas fa-plus"></i> Add New
      </button>
    </div>
  </div>
</div>
<?php $conn->close(); ?>

<!-- 🔹 Add Service Modal -->
<div class="modal fade" id="addServiceModal" tabindex="-1" aria-hidden="true">
  <div class="modal-dialog modal-lg modal-dialog-centered">
    <div class="modal-content custom-modal">

      <!-- FORM START -->
      <form action="../database/services_add.php" method="POST" enctype="multipart/form-data">
        
        <!-- HEADER -->
        <div class="modal-header custom-modal-header">
          <h5 class="modal-title custom-modal-title">Add Service</h5>
          <button type="button" class="close-btn" data-bs-dismiss="modal">&times;</button>
        </div>

        <!-- BODY -->
        <div class="modal-body custom-modal-body">
          <!-- Service name -->
          <div class="form-group">
            <label for="serviceName" class="form-label">Service Name</label>
            <input type="text" class="form-input" id="serviceName" name="service_name" required>
          </div>

          <!-- PDF Template Upload -->
          <div class="form-group file-input-wrapper">
            <label for="pdfTemplate" class="form-label">PDF Template (Optional)</label>
            <input type="file" class="file-input" id="pdfTemplate" name="pdf_template" accept="application/pdf">
          </div>

          <!-- Customize Button -->
          <button type="button" class="customize-btn" id="customizeLayoutBtn" disabled>
            Customize PDF Layout
          </button>

          <!-- Fee & Requirements Row -->
          <div class="row">
            <div class="col-4">
              <label for="serviceFee" class="form-label">Fee</label>
              <input type="number" class="form-input" id="serviceFee" name="fee" step="0.01" required>
            </div>
            <div class="col-8">
              <label for="requirements" class="form-label">Requirements</label>
              <input type="text" class="form-input" id="requirements" name="requirements" required>
            </div>
          </div>

          <!-- Description -->
          <div class="form-group">
            <label for="description" class="form-label">Description</label>
            <textarea class="form-textarea" id="description" name="description" rows="2" required></textarea>
          </div>

          <!-- Hidden field to save layout JSON -->
          <input type="hidden" name="pdf_layout_data" id="pdfLayoutData">
        </div>

        <!-- FOOTER -->
        <div class="modal-footer custom-modal-footer">
          <button type="submit" class="submit-btn">Save Service</button>
          <button type="button" class="btn btn-secondary" data-bs-dismiss="modal">Cancel</button>
        </div>

      </form>
      <!-- FORM END -->
    </div>
  </div>
</div>

<!-- 🔹 View Service Modal -->
<div class="modal fade" id="viewServiceModal" tabindex="-1" aria-hidden="true">
  <div class="modal-dialog modal-lg modal-dialog-centered">
    <div class="modal-content custom-modal">

      <!-- HEADER -->
      <div class="modal-header custom-modal-header">
        <h5 class="modal-title custom-modal-title">View Service</h5>
        <button type="button" class="close-btn" data-bs-dismiss="modal">&times;</button>
      </div>

      <!-- BODY -->
      <div class="modal-body custom-modal-body">
        
        <!-- Service name -->
        <div class="form-group mb-4">
          <label class="form-label">Service Name</label>
          <input type="text" class="form-input" id="view_serviceName" readonly>
        </div>

        <!-- PDF Actions -->
        <div id="pdfActions" class="mt-3" style="display:none;">
          <!-- Replace PDF -->
          <div class="form-group file-input-wrapper mb-2">
            <label for="replacePdfFile" class="form-label">Replace PDF Template</label>
            <input type="file" class="file-input" id="replacePdfFile" accept="application/pdf">
          </div>
          <!-- Customize Button -->
          <button type="button" class="btn btn-secondary" id="customizePdfBtn">
            <i class="bi bi-tools"></i> Customize PDF Layout
          </button>
        </div>

        <!-- Preview Button -->
        <button type="button" class="btn btn-primary" id="previewPdfBtn">
          <i class="bi bi-file-earmark-pdf"></i> Preview PDF
        </button>

        <!-- Fee & Requirements Row -->
        <div class="row">
          <div class="col-4">
            <label class="form-label">Fee</label>
            <input type="text" class="form-input" id="view_serviceFee" readonly>
          </div>
          <div class="col-8">
            <label class="form-label">Requirements</label>
            <input type="text" class="form-input" id="view_requirements" readonly>
          </div>
        </div>

        <!-- Description -->
        <div class="form-group">
          <label class="form-label">Description</label>
          <textarea class="form-textarea" id="view_description" rows="2" readonly></textarea>
        </div>
      </div>

      <!-- FOOTER -->
      <div class="modal-footer custom-modal-footer">
        <!-- Delete -->
        <button type="button" class="btn btn-danger btn-lg rounded-3 px-4 py-2 shadow-sm align-items-center justify-content-center gap-2" 
                id="deleteCancelBtn" style="color: black; width:150px;">
          <i class="bi bi-trash me-1"></i> <span>Delete</span>
        </button>
        <!-- Edit -->
        <button type="button" class="btn btn-warning btn-lg rounded-3 px-4 py-2 shadow-sm align-items-center justify-content-center gap-2" 
                id="editConfirmBtn" style="width:150px;">
          <i class="bi bi-pencil-square"></i> <span>Edit</span>
        </button>
        <!-- Save -->
        <button type="button" class="btn btn-success btn-lg rounded-3 px-4 py-2 shadow-sm align-items-center justify-content-center gap-2" 
                id="saveResidentBtn" style="width:150px; color:black; display:none;">
          <i class="bi bi-save"></i> <span>Save</span>
        </button>
      </div>
    </div>
  </div>
</div>

<!-- 🔹 Edit Confirmation Modal -->
<div class="modal fade" id="confirmEditModal" tabindex="-1" aria-hidden="true">
  <div class="modal-dialog modal-dialog-centered">
    <div class="modal-content">
      <div class="modal-header bg-warning">
        <h5 class="modal-title"><i class="bi bi-pencil-square"></i> Confirm Edit</h5>
        <button type="button" class="btn-close" data-bs-dismiss="modal"></button>
      </div>
      <div class="modal-body">
        <p id="confirmEditText">Are you sure you want to edit this service?</p>
      </div>
      <div class="modal-footer">
        <button type="button" class="btn btn-secondary" data-bs-dismiss="modal">No</button>
        <button type="button" class="btn btn-primary" id="confirmEditYesBtn">Yes, Edit</button>
      </div>
    </div>
  </div>
</div>

<!-- 🔹 PDF Preview Modal -->
<div class="modal fade" id="pdfPreviewModal" tabindex="-1" aria-hidden="true">
  <div class="modal-dialog modal-xl modal-dialog-scrollable">
    <div class="modal-content">
      <div class="modal-header bg-primary text-white">
        <h5 class="modal-title"><i class="bi bi-file-earmark-pdf"></i> PDF Preview</h5>
        <button type="button" class="btn-close" data-bs-dismiss="modal"></button>
      </div>
      <div class="modal-body d-flex justify-content-center align-items-center">
        <div id="pdfWrapper" class="position-relative">
          <canvas id="pdfCanvasPreview"></canvas>
          <div id="overlayContainer" class="position-absolute top-0 start-0"></div>
        </div>
      </div>
      <div class="modal-footer">
        <button type="button" class="btn btn-secondary" data-bs-dismiss="modal">Close</button>
      </div>
    </div>
  </div>
</div>

<!-- 🔹 PDF Layout Editor Modal -->
<div class="modal fade" id="pdfLayoutEditorModal" tabindex="-1" aria-hidden="true">
  <div class="modal-dialog modal-xl">
    <div class="modal-content">

      <!-- HEADER -->
      <div class="modal-header bg-dark text-white">
        <h5 class="modal-title">Customize PDF Layout</h5>
        <button type="button" class="btn-close btn-close-white" data-bs-dismiss="modal"></button>
      </div>

      <!-- BODY -->
      <div class="modal-body p-0">
        <div class="d-flex flex-column h-100">
          
          <!-- 🔹 Toolbar -->
          <div id="pdfToolbar" class="bg-light border-bottom p-1 d-flex align-items-center gap-3"
               style="position: sticky; top: 0; z-index: 100; background-color: #f8f9fa;">
            
            <!-- Font -->
            <div>
              <label class="form-label mb-0 me-2">Font:</label>
              <select id="fontFamily" class="form-select form-select-sm d-inline-block" style="width: 150px;">
                <option>Arial</option>
                <option>Calibri</option>
                <option>Times New Roman</option>
              </select>
            </div>

            <!-- Styles -->
            <div class="btn-group" role="group" aria-label="Text Styles">
              <button type="button" class="btn btn-outline-secondary btn-sm" id="btnBold"><b>B</b></button>
              <button type="button" class="btn btn-outline-secondary btn-sm" id="btnItalic"><i>I</i></button>
              <button type="button" class="btn btn-outline-secondary btn-sm" id="btnUnderline"><u>U</u></button>
            </div>

            <!-- Size -->
            <div>
              <label class="form-label mb-0 me-2">Size:</label>
              <input type="number" id="fontSize" class="form-control form-control-sm d-inline-block" value="12" style="width: 80px;">
            </div>

            <!-- Color -->
            <div>
              <label class="form-label mb-0 me-2">Color:</label>
              <input type="color" id="fontColor" class="form-control form-control-color form-control-sm d-inline-block align-middle" value="#000000" style="width: 50px; padding: 0;">
            </div>

            <!-- Delete -->
            <button id="deleteFieldBtn" class="btn btn-danger btn-sm ms-auto">🗑️ Delete Selected</button>
          </div>

          <!-- 🔹 Editor Body -->
          <div class="d-flex flex-grow-1" style="min-height: 450px; overflow: hidden;">

            <!-- 🟦 Sidebar Fields -->
            <div class="p-1 border-end bg-white" style="width: 250px; overflow-y: auto; max-height: 450px;">
              <h6 class="fw-bold">📌 Fields</h6>

              <!-- Resident Info -->
              <div class="fw-bold mt-2 mb-1">Resident Info</div>
              <button class="btn btn-outline-secondary w-100 insert-field-btn mb-1" data-field="{{full_name}}">Full Name</button>
              <button class="btn btn-outline-secondary w-100 insert-field-btn mb-1" data-field="{{address}}">Address</button>
              <button class="btn btn-outline-secondary w-100 insert-field-btn mb-1" data-field="{{birth_date}}">Birth Date</button>
              <button class="btn btn-outline-secondary w-100 insert-field-btn mb-1" data-field="{{birth_place}}">Place of Birth</button>
              <button class="btn btn-outline-secondary w-100 insert-field-btn mb-1" data-field="{{age}}">Age</button>
              <button class="btn btn-outline-secondary w-100 insert-field-btn mb-1" data-field="{{civil_status}}">Civil Status</button>
              <button class="btn btn-outline-secondary w-100 insert-field-btn mb-1" data-field="{{gender}}">Gender</button>
              <button class="btn btn-outline-secondary w-100 insert-field-btn mb-1" data-field="{{religion}}">Religion</button>
              <button class="btn btn-outline-secondary w-100 insert-field-btn mb-1" data-field="{{nationality}}">Nationality</button>
              <button class="btn btn-outline-secondary w-100 insert-field-btn mb-1" data-field="{{contact_number}}">Contact Number</button>
              <button class="btn btn-outline-secondary w-100 insert-field-btn mb-1" data-field="{{email}}">Email Address</button>

              <!-- Emergency Contact -->
              <div class="fw-bold mt-3 mb-1">Emergency Contact</div>
              <button class="btn btn-outline-secondary w-100 insert-field-btn mb-1" data-field="{{emergency_name}}">Name</button>
              <button class="btn btn-outline-secondary w-100 insert-field-btn mb-1" data-field="{{emergency_relation}}">Relationship</button>
              <button class="btn btn-outline-secondary w-100 insert-field-btn mb-1" data-field="{{emergency_contact}}">Contact Number</button>

              <!-- Service Info -->
              <div class="fw-bold mt-3 mb-1">Service Info</div>
              <button class="btn btn-outline-secondary w-100 insert-field-btn mb-1" data-field="{{service_name}}">Service Name</button>
              <button class="btn btn-outline-secondary w-100 insert-field-btn mb-1" data-field="{{requirements}}">Requirements</button>
              <button class="btn btn-outline-secondary w-100 insert-field-btn mb-1" data-field="{{service_fee}}">Service Fee</button>
              <button class="btn btn-outline-secondary w-100 insert-field-btn mb-1" data-field="{{description}}">Description</button>
              <button class="btn btn-outline-secondary w-100 insert-field-btn mb-1" data-field="{{date}}">Date</button>
            </div>

            <!-- 📝 PDF Editor Area -->
            <div class="flex-grow-1 position-relative bg-light d-flex justify-content-center align-items-center">
              <div id="pdfCanvasContainer" class="position-relative" style="width:100%; height:100%; overflow:auto; max-height: 62vh;">
                <canvas id="pdfCanvasEditor" style="width:100%; height:auto;"></canvas>
                <div id="dragOverlayContainer" class="position-absolute top-0 start-0"></div>
              </div>
            </div>

          </div>
        </div>
      </div>

      <!-- FOOTER -->
      <div class="modal-footer">
        <button type="button" class="btn btn-secondary" data-bs-dismiss="modal">Cancel</button>
        <button type="button" class="btn btn-primary" id="saveLayoutBtn">Save Layout</button>
      </div>
    </div>
  </div>
</div>

<script>

  function searchTable() {
    let input = document.getElementById("searchInput").value.toLowerCase();
    let rows = document.querySelectorAll("#residentTableBody tr");

    rows.forEach(row => {
        let text = row.innerText.toLowerCase();
        row.style.display = text.includes(input) ? "" : "none";
    });
}

function sortTable(colIndex) {
    let tbody = document.getElementById("residentTableBody");
    let rows = Array.from(tbody.querySelectorAll("tr"));
    let asc = tbody.getAttribute("data-sort-col") != colIndex ||
              tbody.getAttribute("data-sort-order") != "asc";

    rows.sort((a, b) => {
        let textA = a.children[colIndex - 1].innerText.trim().toLowerCase();
        let textB = b.children[colIndex - 1].innerText.trim().toLowerCase();
        return asc ? textA.localeCompare(textB) : textB.localeCompare(textA);
    });

    tbody.innerHTML = "";
    rows.forEach(row => tbody.appendChild(row));

    tbody.setAttribute("data-sort-col", colIndex);
    tbody.setAttribute("data-sort-order", asc ? "asc" : "desc");
}

function openAddServiceModal() {
    document.getElementById("addServiceModal").style.display = "flex";
}

function closeAddServiceModal() {
    document.getElementById("addServiceModal").style.display = "none";
}

// ✅ Auto-enable customize button when file is selected
document.getElementById("pdfTemplate").addEventListener("change", function () {
    document.getElementById("customizeLayoutBtn").disabled = !this.files.length;
});

// ================= PDF Layout Editor =================
let pdfDoc = null;
let canvas = document.getElementById('pdfCanvas');
let ctx = canvas.getContext('2d');
let selectedField = null;
let activeEl = null;
let offsetX, offsetY;

// Render PDF on canvas
document.getElementById('pdfTemplate').addEventListener('change', function (e) {
    const file = e.target.files[0];
    if (file && file.type === 'application/pdf') {
        const fileReader = new FileReader();
        fileReader.onload = function () {
            const typedarray = new Uint8Array(this.result);
            pdfjsLib.getDocument(typedarray).promise.then(function (pdf) {
                pdfDoc = pdf;
                return pdf.getPage(1);
            }).then(function (page) {
                const viewport = page.getViewport({ scale: 1.5 });
                canvas.height = viewport.height;
                canvas.width = viewport.width;

                page.render({ canvasContext: ctx, viewport: viewport });
                document.getElementById('customizeLayoutBtn').disabled = false;
            });
        };
        fileReader.readAsArrayBuffer(file);
    }
});

// Open Layout Editor Modal
document.getElementById('customizeLayoutBtn').addEventListener('click', function () {
    const modal = new bootstrap.Modal(document.getElementById('pdfLayoutEditorModal'));
    modal.show();
});

// Save Layout
document.getElementById('saveLayoutBtn').addEventListener('click', function () {
    const fields = document.querySelectorAll('.draggable-field');
    const layout = [];

    fields.forEach(el => {
        const computedStyle = window.getComputedStyle(el);
        layout.push({
            text: el.innerText,
            x: parseFloat(el.style.left),
            y: parseFloat(el.style.top),
            width: parseFloat(el.offsetWidth),   // ✅ Save width
            height: parseFloat(el.offsetHeight), // ✅ Save height
            fontSize: parseInt(computedStyle.fontSize),
            fontFamily: computedStyle.fontFamily,
            color: computedStyle.color,
            fontWeight: computedStyle.fontWeight,
            fontStyle: computedStyle.fontStyle,
            textDecoration: computedStyle.textDecorationLine
        });
    });

    document.getElementById('pdfLayoutData').value = JSON.stringify(layout);
    bootstrap.Modal.getInstance(document.getElementById('pdfLayoutEditorModal')).hide();
});

// ================= Mouse Drag Logic =================
document.addEventListener('mousedown', function (e) {
    if (e.target.classList.contains('draggable-field')) {
        // 🔒 Check if mouse is on the resize edge (right side only)
        const bounds = e.target.getBoundingClientRect();
        const edgeThreshold = 10;
        const isResizing = (bounds.right - e.clientX) < edgeThreshold;

        if (isResizing) return; // Skip dragging if resizing

        // ✅ Normal drag logic
        activeEl = e.target;
        const rect = activeEl.getBoundingClientRect();
        offsetX = e.clientX - rect.left;
        offsetY = e.clientY - rect.top;
        e.preventDefault();
    }
});

document.addEventListener('mousemove', function (e) {
    if (activeEl) {
        const container = document.getElementById('pdfEditorWrapper');
        const containerRect = container.getBoundingClientRect();

        const x = e.clientX - containerRect.left - offsetX;
        const y = e.clientY - containerRect.top - offsetY;

        activeEl.style.left = x + 'px';
        activeEl.style.top = y + 'px';
    }
});

document.addEventListener('mouseup', function () {
    activeEl = null;
});

// ================= Insert Field from Sidebar =================
document.querySelectorAll('.insert-field-btn').forEach(btn => {
    btn.addEventListener('click', function () {
        const fieldValue = this.getAttribute('data-field');
        const container = document.getElementById('canvasScrollContainer');
        const wrapper = document.getElementById('pdfEditorWrapper');

        // ✅ Kunin ang visible center ng container
        const visibleX = container.scrollLeft + container.clientWidth / 2;
        const visibleY = container.scrollTop + container.clientHeight / 2;

        // Gumawa ng bagong field
        const div = document.createElement('div');
        div.className = 'draggable-field';
        div.contentEditable = true;
        div.innerText = fieldValue;
        div.style.position = 'absolute';
        div.style.left = (visibleX - 75) + 'px';
        div.style.top = (visibleY - 15) + 'px';
        div.style.padding = '2px 5px';
        div.style.border = '1px dashed #000';
        div.style.background = '#f9f9f9';
        div.style.cursor = 'move';
        div.style.fontFamily = document.getElementById('fontFamily').value;
        div.style.fontSize = document.getElementById('fontSize').value + 'px';
        div.style.color = document.getElementById('fontColor').value;
        div.style.zIndex = 10;

        // ✅ Resizable box
        div.style.resize = 'horizontal';
        div.style.overflow = 'hidden';
        div.style.minWidth = '50px';
        div.style.maxWidth = '400px';
        div.style.whiteSpace = 'nowrap';

        // ✅ Center text sa loob ng box
        div.style.display = 'flex';
        div.style.alignItems = 'center';
        div.style.justifyContent = 'center';
        div.style.textAlign = 'center';

        // Select on click
        div.addEventListener('click', function (e) {
            e.stopPropagation();
            if (selectedField) selectedField.style.border = '1px dashed #000';
            selectedField = div;
            div.style.border = '2px solid red';
        });

        wrapper.appendChild(div);
    });
});

// ================= Deselect & Delete Field =================
document.getElementById('pdfEditorWrapper').addEventListener('click', function () {
    if (selectedField) {
        selectedField.style.border = '1px dashed #000';
        selectedField = null;
    }
});

document.getElementById('deleteFieldBtn').addEventListener('click', () => {
    if (selectedField) {
        selectedField.remove();
        selectedField = null;
    }
});

// ================= Font Controls =================
document.getElementById('fontFamily').addEventListener('change', (e) => {
    if (selectedField) selectedField.style.fontFamily = e.target.value;
});

document.getElementById('fontSize').addEventListener('change', (e) => {
    if (selectedField) selectedField.style.fontSize = e.target.value + 'px';
});

document.getElementById('fontColor').addEventListener('input', (e) => {
    if (selectedField) selectedField.style.color = e.target.value;
});

// Bold
document.getElementById('btnBold').addEventListener('click', function () {
    if (selectedField) {
        const isBold = selectedField.style.fontWeight === 'bold';
        selectedField.style.fontWeight = isBold ? 'normal' : 'bold';
        this.classList.toggle('active', !isBold);
    }
});

// Italic
document.getElementById('btnItalic').addEventListener('click', function () {
    if (selectedField) {
        const isItalic = selectedField.style.fontStyle === 'italic';
        selectedField.style.fontStyle = isItalic ? 'normal' : 'italic';
        this.classList.toggle('active', !isItalic);
    }
});

// Underline
document.getElementById('btnUnderline').addEventListener('click', function () {
    if (selectedField) {
        const isUnderlined = selectedField.style.textDecoration === 'underline';
        selectedField.style.textDecoration = isUnderlined ? 'none' : 'underline';
        this.classList.toggle('active', !isUnderlined);
    }
});


// ================= Preview PDF =================

// Set workerSrc para gumana ang PDF.js
pdfjsLib.GlobalWorkerOptions.workerSrc =
  "https://cdnjs.cloudflare.com/ajax/libs/pdf.js/2.10.377/pdf.worker.min.js";

document.getElementById("previewPdfBtn").addEventListener("click", () => {
  if (!selectedServiceId) {
    alert("No service selected.");
    return;
  }

  fetch(`../database/services_fetch.php?id=${selectedServiceId}`)
    .then(res => res.json())
    .then(data => {
      if (data.error) {
        alert(data.error);
        return;
      }

      const container = document.getElementById("pdfWrapper");
      container.innerHTML = ""; // Clear old preview
      container.style.position = "relative";

      if (data.pdf_template) {
        const pdfUrl = data.pdf_template;

        pdfjsLib.getDocument(pdfUrl).promise.then(pdf => {
          for (let pageNum = 1; pageNum <= pdf.numPages; pageNum++) {
            pdf.getPage(pageNum).then(page => {
              const previewScale = 1.5; // 🔹 Same as editor
              const viewport = page.getViewport({ scale: previewScale });

              // Create canvas per page
              const canvas = document.createElement("canvas");
              const ctx = canvas.getContext("2d");
              canvas.height = viewport.height;
              canvas.width = viewport.width;
              canvas.style.display = "block";
              canvas.style.marginBottom = "20px";

              // Wrapper for page + overlay
              const pageWrapper = document.createElement("div");
              pageWrapper.style.position = "relative";
              pageWrapper.style.display = "inline-block";

              pageWrapper.appendChild(canvas);
              container.appendChild(pageWrapper);

              // Render PDF page
              page.render({ canvasContext: ctx, viewport: viewport });

              // Overlay container
              const overlay = document.createElement("div");
              overlay.style.position = "absolute";
              overlay.style.top = "0";
              overlay.style.left = "0";
              overlay.style.width = canvas.width + "px";
              overlay.style.height = canvas.height + "px";
              overlay.style.pointerEvents = "none"; // Para hindi clickable
              pageWrapper.appendChild(overlay);

              // Render saved layout fields
              if (data.pdf_layout_data) {
                try {
                  const layout = JSON.parse(data.pdf_layout_data);

                  // ✅ Adjust fields kung iba ang scale ng preview
                  const editorScale = 1.5; // Dapat kapareho ng ginamit sa editor
                  const scaleRatio = previewScale / editorScale;

                  layout.forEach(field => {
                    const div = document.createElement("div");
                    div.textContent = field.text;
                    div.style.position = "absolute";
                    div.style.left = (field.x * scaleRatio) + "px";
                    div.style.top = (field.y * scaleRatio) + "px";

                    // ✅ Apply width & height kung meron
                    if (field.width) {
                      div.style.width = (field.width * scaleRatio) + "px";
                    }
                    if (field.height) {
                      div.style.height = (field.height * scaleRatio) + "px";
                    }

                    // ✅ Style container same as editor
                    div.style.border = "1px dashed rgba(0,0,0,0.5)";
                    div.style.boxSizing = "border-box"; // para hindi sumobra sa sukat

                    // ✅ Center text sa loob ng box
                    div.style.display = "flex";
                    div.style.alignItems = "center";
                    div.style.justifyContent = "center";
                    div.style.textAlign = "center";

                    // Fonts & styles
                    div.style.fontSize = ((field.fontSize || 14) * scaleRatio) + "px";
                    div.style.fontFamily = field.fontFamily || "Arial";
                    div.style.color = field.color || "black";
                    div.style.fontWeight = field.fontWeight || "normal";
                    div.style.fontStyle = field.fontStyle || "normal";
                    if (field.textDecoration) {
                      div.style.textDecoration = field.textDecoration;
                    }

                    overlay.appendChild(div);
                  });
                } catch (err) {
                  console.error("Layout parse error:", err);
                }
              }
            });
          }
        });
      } else {
        container.innerHTML =
          `<p class="text-muted">No PDF template uploaded for this service.</p>`;
      }

      // Show modal
      new bootstrap.Modal(document.getElementById("pdfPreviewModal")).show();
    })
    .catch(err => console.error("Error previewing PDF:", err));
});

let selectedServiceId = null;
let isEditing = false;

// ================= Row Click → View Service =================
document.querySelectorAll(".table-row").forEach(row => {
  row.addEventListener("click", function () {
    selectedServiceId = this.getAttribute("data-id");

    // Fetch service details
    fetch(`../database/services_fetch.php?id=${selectedServiceId}`)
      .then(res => res.json())
      .then(data => {
        if (data.error) {
          alert(data.error);
          return;
        }

        // Fill modal fields
        document.getElementById("view_serviceName").value = data.service_name;
        document.getElementById("view_serviceFee").value = data.service_fee;
        document.getElementById("view_requirements").value = data.requirements;
        document.getElementById("view_description").value = data.description;

        // Make fields readonly
        document.querySelectorAll("#viewServiceModal input, #viewServiceModal textarea")
          .forEach(el => el.setAttribute("readonly", true));

        // Reset buttons/visibility
        document.getElementById("pdfActions").style.display = "none";
        document.getElementById("previewPdfBtn").style.display = "inline-block";
        document.getElementById("customizePdfBtn").style.display = "none";
        document.getElementById("saveResidentBtn").style.display = "none";

        const deleteBtn = document.getElementById("deleteCancelBtn");
        deleteBtn.innerHTML = `<i class="bi bi-trash"></i> Delete`;
        deleteBtn.classList.remove("btn-secondary");
        deleteBtn.classList.add("btn-danger");

        // Show modal
        new bootstrap.Modal(document.getElementById("viewServiceModal")).show();
      })
      .catch(err => console.error("Error fetching service:", err));
  });
});

// ================= Edit Confirmation =================
document.getElementById("editConfirmBtn").addEventListener("click", () => {
  const serviceName = document.getElementById("view_serviceName").value;
  document.getElementById("confirmEditText").innerText =
    `Are you sure you want to edit "${serviceName}"?`;

  new bootstrap.Modal(document.getElementById("confirmEditModal")).show();
});
// ================= Confirm Yes → Enable Editing =================
document.getElementById("confirmEditYesBtn").addEventListener("click", () => {
  isEditing = true;

  bootstrap.Modal.getInstance(document.getElementById("confirmEditModal")).hide();

  // Enable fields
  document.querySelectorAll("#viewServiceModal input, #viewServiceModal textarea")
    .forEach(el => el.removeAttribute("readonly"));

  // Show PDF actions
  document.getElementById("pdfActions").style.display = "block";

  // Replace Preview → Customize
  document.getElementById("previewPdfBtn").style.display = "none";
  document.getElementById("customizePdfBtn").style.display = "inline-block";

  // Delete → Cancel
  const deleteBtn = document.getElementById("deleteCancelBtn");
  deleteBtn.innerHTML = `<i class="bi bi-x-circle"></i> Cancel`;
  deleteBtn.classList.remove("btn-danger");
  deleteBtn.classList.add("btn-secondary");

  // Show Save
  document.getElementById("saveResidentBtn").style.display = "inline-flex";

  // ✅ Hide Edit button
  document.getElementById("editConfirmBtn").style.display = "none";
});

// ================= Cancel Edit or Delete =================
document.getElementById("deleteCancelBtn").addEventListener("click", () => {
  if (isEditing) {
    isEditing = false;

    // Reset to readonly
    document.querySelectorAll("#viewServiceModal input, #viewServiceModal textarea")
      .forEach(el => el.setAttribute("readonly", true));

    // Hide PDF actions
    document.getElementById("pdfActions").style.display = "none";

    // Reset Preview/Customize
    document.getElementById("previewPdfBtn").style.display = "inline-block";
    document.getElementById("customizePdfBtn").style.display = "none";

    // Reset Delete
    const deleteBtn = document.getElementById("deleteCancelBtn");
    deleteBtn.innerHTML = `<i class="bi bi-trash"></i> Delete`;
    deleteBtn.classList.remove("btn-secondary");
    deleteBtn.classList.add("btn-danger");

    // Hide Save
    document.getElementById("saveResidentBtn").style.display = "none";

    // ✅ Show Edit button ulit
    document.getElementById("editConfirmBtn").style.display = "inline-flex";
  } else {
    // 👉 TODO: Implement delete function here
    alert("Proceed with delete function...");
  }
});

// ================= Customize PDF =================
document.getElementById("customizePdfBtn").addEventListener("click", () => {
  const fileInput = document.getElementById("replacePdfFile");

  if (fileInput.files.length > 0) {
    // ✅ Case 1: Bagong file ang gagamitin
    console.log("Using new uploaded PDF:", fileInput.files[0].name);

    const formData = new FormData();
    formData.append("pdf_file", fileInput.files[0]);
    formData.append("service_id", selectedServiceId);

    fetch("../database/upload_pdf.php", {
      method: "POST",
      body: formData
    })
      .then(res => res.json())
      .then(data => {
        if (data.error) {
          alert(data.error);
          return;
        }

        console.log("New PDF uploaded:", data.file_path);

        // 👉 Load bagong PDF sa editor
        loadPdfInEditor(data.file_path);

        // Kung may layout na nakasave, i-render din
        if (data.pdf_layout_data) {
          try {
            const layout = JSON.parse(data.pdf_layout_data);
            renderFieldsOnPdf(layout);
          } catch (e) {
            console.error("Invalid layout JSON", e);
          }
        }

        new bootstrap.Modal(document.getElementById("pdfLayoutEditorModal")).show();
      })
      .catch(err => console.error("Error uploading new PDF:", err));

  } else {
    // ✅ Case 2: Existing file ang gagamitin
    console.log("Using existing PDF...");

    fetch(`../database/services_pdf_fetch.php?service_id=${selectedServiceId}`)
      .then(res => res.json())
      .then(data => {
        if (data.error) {
          alert(data.error);
          return;
        }

        if (data.pdf_template) {
          console.log("Existing PDF Template:", data.pdf_template);

          // 👉 Load existing PDF sa editor
          loadPdfInEditor(data.pdf_template);
        }

        if (data.pdf_layout_data) {
          try {
            const layout = JSON.parse(data.pdf_layout_data);
            console.log("Existing layout fields:", layout);

            // 👉 Render fields sa PDF editor overlay
            renderFieldsOnPdf(layout);
          } catch (e) {
            console.error("Invalid layout JSON", e);
          }
        }

        new bootstrap.Modal(document.getElementById("pdfLayoutEditorModal")).show();
      })
      .catch(err => console.error("Error fetching existing PDF:", err));
  }
});

// ================== Load PDF into Editor ==================
async function loadPdfInEditor(pdfPath) {
  console.log("Load PDF into editor:", pdfPath);

  // Gumamit ng pdf.js
  const loadingTask = pdfjsLib.getDocument(pdfPath);
  const pdf = await loadingTask.promise;

  // Kunin yung first page (pwede mong i-loop kung multi-page support ang gusto mo)
  const page = await pdf.getPage(1);

  const scale = 1.5; // zoom level
  const viewport = page.getViewport({ scale });

  // Kunin yung canvas element
  const canvas = document.getElementById("pdfCanvasEditor");
  const context = canvas.getContext("2d");

  // Ayusin canvas size
  canvas.height = viewport.height;
  canvas.width = viewport.width;

  // I-render page sa canvas
  const renderContext = {
    canvasContext: context,
    viewport: viewport,
  };
  await page.render(renderContext).promise;

  console.log("PDF rendered in editor.");
}

function renderFieldsOnPdf(layout) {
  console.log("Render fields:", layout);
  // 👉 dito mo irender yung draggable fields sa #dragOverlayContainer
}

</script>

