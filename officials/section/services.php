<?php
session_start();

// ✅ Check kung naka-login
if (!isset($_SESSION['user_id'])) {
    // Redirect to login page
    header("Location: login_signup.php");
    exit;
}

include('sidebar.php'); 
include('../database/config.php'); // Adjust as needed


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

// ✅ Fetch services na naka-link sa barangay (via address_id)
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

  <!-- CSS -->
  <link rel="stylesheet" type="text/css" href="../css/services.css">
  <link href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0/css/all.min.css" rel="stylesheet">
  
  <script src="https://cdnjs.cloudflare.com/ajax/libs/pdf.js/2.10.377/pdf.min.js"></script>



<!-- Navbar -->
<nav class="navbar">
  <div class="navbar-container">
    <div class="section-name">Barangay Services</div>
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
                placeholder="Search services..."
                onkeyup="searchTable()"
            >
        </div>
    </div>

    <!-- Table -->
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
    <div class="table-footer" style="border-bottom-left-radius: 20px;border-bottom-right-radius: 20px;">
        <div class="footer-info">
        </div>
        <div class="footer-buttons">
            <button class="btn btn-primary" data-bs-toggle="modal" data-bs-target="#addServiceModal">
                <i class="fas fa-plus"></i> Add New
            </button>
        </div>
    </div>
</div>
<?php $conn->close(); ?>

<!-- Add Service Modal -->
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
        <div class="modal-footer custom-modal-footer" >
          <button type="submit" class="submit-btn">Save Service</button>
          <button type="button" class="btn btn-secondary" data-bs-dismiss="modal">Cancel</button>
        </div>

      </form>
      <!-- FORM END -->
    </div>
  </div>
</div>

<!-- View Service Modal -->
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

        <div id="pdfActions" class="mt-3" style="display:none;">
          <!-- New file upload -->
          <div class="form-group file-input-wrapper mb-2">
            <label for="replacePdfFile" class="form-label">Replace PDF Template</label>
            <input type="file" class="file-input" id="replacePdfFile" accept="application/pdf">
          </div>

          <!-- Customize Button -->
          <button type="button" class="btn btn-secondary" id="customizePdfBtn">
            <i class="bi bi-tools"></i> Customize PDF Layout
          </button>
        </div>

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
        <button type="button" 
                    class="btn btn-danger btn-lg rounded-3 px-4 py-2 shadow-sm align-items-center justify-content-center gap-2" 
                    id="deleteCancelBtn" 
                    style="color: black; width:150px;">
              <i class="bi bi-trash me-1"></i> <span>Delete</span>
            </button>
            <button type="button" class="btn btn-warning btn-lg rounded-3 px-4 py-2 shadow-sm align-items-center justify-content-center gap-2" id="editConfirmBtn" style="width:150px;">
              <i class="bi bi-pencil-square"></i> <span>Edit</span>
            </button>

            <button type="button" class="btn btn-success btn-lg rounded-3 px-4 py-2 shadow-sm align-items-center justify-content-center gap-2" id="saveEditServicesBtn" style="width:150px; color:black; display:none;">
              <i class="bi bi-save"></i> <span>Save</span>
            </button>
      </div>
    </div>
  </div>
</div>

<!-- Edit Confirmation Modal -->
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

<!-- PDF Preview Modal -->
<div class="modal fade" id="pdfPreviewModal" tabindex="-1" aria-hidden="true">
  <div class="modal-dialog modal-xl modal-dialog-scrollable">
    <div class="modal-content">
      <div class="modal-header bg-primary text-white">
        <h5 class="modal-title"><i class="bi bi-file-earmark-pdf"></i> PDF Preview</h5>
        <button type="button" class="btn-close" data-bs-dismiss="modal" aria-label="Close"></button>
      </div>
      <div class="modal-body d-flex justify-content-center align-items-center">
        <div id="pdfWrapper" class="position-relative">
          <canvas id="pdfCanvasPreview"></canvas>
          <div id="overlayContainer" 
               class="position-absolute top-0 start-0"></div>
        </div>
      </div>
      <div class="modal-footer">
        <button type="button" class="btn btn-secondary" data-bs-dismiss="modal">Close</button>
      </div>
    </div>
  </div>
</div>

<!-- Delete Confirmation Modal -->
<div class="modal fade" id="confirmDeleteModal" tabindex="-1" aria-hidden="true">
  <div class="modal-dialog modal-dialog-centered">
    <div class="modal-content">
      <div class="modal-header bg-danger text-white">
        <h5 class="modal-title"><i class="bi bi-trash"></i> Confirm Delete</h5>
        <button type="button" class="btn-close btn-close-white" data-bs-dismiss="modal"></button>
      </div>
      <div class="modal-body">
        <p id="confirmDeleteText">Are you sure you want to delete this service?</p>
      </div>
      <div class="modal-footer">
        <button type="button" class="btn btn-secondary" data-bs-dismiss="modal">Cancel</button>
        <button type="button" class="btn btn-danger" id="confirmDeleteYesBtn">Yes, Delete</button>
      </div>
    </div>
  </div>
</div>


 <!-- PDF Layout Editor Modal -->
    <div class="modal fade" id="pdfLayoutEditorModal" tabindex="-1" aria-hidden="true">
        <div class="modal-dialog modal-xl">
            <div class="modal-content">
                <div class="modal-header bg-dark text-white">
                    <h5 class="modal-title">Customize PDF Layout</h5>
                    <button type="button" class="btn-close btn-close-white" data-bs-dismiss="modal"></button>
                </div>

                <div class="modal-body p-0">
                    <div class="d-flex flex-column h-100">
                        <!-- 🔹 Toolbar -->
                        <div id="pdfToolbar" class="bg-light border-bottom p-1 d-flex align-items-center gap-3"
                            style="position: sticky; top: 0; z-index: 100; background-color: #f8f9fa;">
                            <div>
                                <label class="form-label mb-0 me-2">Font:</label>
                                <select id="fontFamily" class="form-select form-select-sm d-inline-block" style="width: 150px;">
                                    <option>Arial</option>
                                    <option>Calibri</option>
                                    <option>Times New Roman</option>
                                </select>
                            </div>
                            <div class="btn-group" role="group" aria-label="Text Styles">
                                <button type="button" class="btn btn-outline-secondary btn-sm" id="btnBold"><b>B</b></button>
                                <button type="button" class="btn btn-outline-secondary btn-sm" id="btnItalic"><i>I</i></button>
                                <button type="button" class="btn btn-outline-secondary btn-sm" id="btnUnderline"><u>U</u></button>
                            </div>
                            <div>
                                <label class="form-label mb-0 me-2">Size:</label>
                                <input type="number" id="fontSize" class="form-control form-control-sm d-inline-block" value="12" style="width: 80px;">
                            </div>
                            <div>
                                <label class="form-label mb-0 me-2">Color:</label>
                                <input type="color" id="fontColor" 
                                    class="form-control form-control-color form-control-sm d-inline-block align-middle" 
                                    value="#000000" 
                                    style="width: 50px; padding: 0;">
                            </div>
                            <button id="deleteFieldBtn" class="btn btn-danger btn-sm ms-auto">🗑️ Delete Selected</button>
                        </div>

                        <!-- 🔹 Editor Body -->
                        <div class="d-flex flex-grow-1" style="min-height: 450px; overflow: hidden;">
                            <!-- 🟦 Sidebar Fields -->
                            <div class="p-1 border-end bg-white" style="width: 250px; overflow-y: auto; max-height: 450px;">
                                <h6 class="fw-bold">📌 Fields</h6>

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

                                <div class="fw-bold mt-3 mb-1">Emergency Contact</div>
                                <button class="btn btn-outline-secondary w-100 insert-field-btn mb-1" data-field="{{emergency_name}}">Name</button>
                                <button class="btn btn-outline-secondary w-100 insert-field-btn mb-1" data-field="{{emergency_relation}}">Relation</button>
                                <button class="btn btn-outline-secondary w-100 insert-field-btn mb-1" data-field="{{emergency_number}}">Number</button>

                                <div class="fw-bold mt-3 mb-1">Barangay Officials</div>
                                <button class="btn btn-outline-secondary w-100 insert-field-btn mb-1" data-field="{{barangay_captain}}">Captain</button>
                                <button class="btn btn-outline-secondary w-100 insert-field-btn mb-1" data-field="{{barangay_secretary}}">Secretary</button>
                                <button class="btn btn-outline-secondary w-100 insert-field-btn mb-1" data-field="{{barangay_treasurer}}">Treasurer</button>

                                <div class="fw-bold mt-3 mb-1">Date Fields</div>

                                <!-- 🔹 Day -->
                                <button class="btn btn-outline-secondary w-100 insert-field-btn mb-1" data-field="{{day}}">No. Days</button>
                                <button class="btn btn-outline-secondary w-100 insert-field-btn mb-1" data-field="{{day_name}}">Day Name</button>

                                <!-- 🔹 Month -->
                                <button class="btn btn-outline-secondary w-100 insert-field-btn mb-1" data-field="{{month}}">No. Month </button>
                                <button class="btn btn-outline-secondary w-100 insert-field-btn mb-1" data-field="{{month_name}}">Month Name</button>

                                <!-- 🔹 Year -->
                                <button class="btn btn-outline-secondary w-100 insert-field-btn mb-1" data-field="{{year}}">Year (YYYY)</button>
                                <button class="btn btn-outline-secondary w-100 insert-field-btn mb-1" data-field="{{year_short}}">Year (YY)</button>

                            </div>

                            <!-- 🟧 Canvas Area -->
                            <div id="canvasScrollContainer" class="p-1 flex-grow-1 overflow-auto" style="max-height: 450px; position: relative;">
                                <div id="pdfEditorWrapper" style="position: relative; display: inline-block;">
                                    <canvas id="pdfCanvas"></canvas>
                                    <!-- fields will be appended here -->
                                </div>
                            </div>
                        </div> <!-- End editor body -->
                    </div>
                </div>

                <div class="modal-footer">
                    <button class="btn btn-primary" id="saveLayoutBtn">Save Layout</button>
                    <button class="btn btn-secondary" data-bs-dismiss="modal">Close</button>
                </div>
            </div>
        </div>
    </div>

<!-- PDF Layout Editor Modal (EDIT) -->
<div class="modal fade" id="pdfLayoutEditorModalEdit" tabindex="-1" aria-hidden="true">
    <div class="modal-dialog modal-xl">
        <div class="modal-content">
            <div class="modal-header bg-primary text-white">
                <h5 class="modal-title">Edit PDF Layout</h5>
                <button type="button" class="btn-close btn-close-white" data-bs-dismiss="modal"></button>
            </div>

            <div class="modal-body p-0">
                <div class="d-flex flex-column h-100">
                    <!-- 🔹 Toolbar -->
                    <div id="pdfToolbarEdit" class="bg-light border-bottom p-1 d-flex align-items-center gap-3"
                        style="position: sticky; top: 0; z-index: 100; background-color: #f8f9fa;">
                        <div>
                            <label class="form-label mb-0 me-2">Font:</label>
                            <select id="fontFamilyEdit" class="form-select form-select-sm d-inline-block" style="width: 150px;">
                                <option>Arial</option>
                                <option>Calibri</option>
                                <option>Times New Roman</option>
                            </select>
                        </div>
                        <div class="btn-group" role="group" aria-label="Text Styles">
                            <button type="button" class="btn btn-outline-secondary btn-sm" id="btnBoldEdit"><b>B</b></button>
                            <button type="button" class="btn btn-outline-secondary btn-sm" id="btnItalicEdit"><i>I</i></button>
                            <button type="button" class="btn btn-outline-secondary btn-sm" id="btnUnderlineEdit"><u>U</u></button>
                        </div>
                        <div>
                            <label class="form-label mb-0 me-2">Size:</label>
                            <input type="number" id="fontSizeEdit" class="form-control form-control-sm d-inline-block" value="12" style="width: 80px;">
                        </div>
                        <div>
                            <label class="form-label mb-0 me-2">Color:</label>
                            <input type="color" id="fontColorEdit" 
                                class="form-control form-control-color form-control-sm d-inline-block align-middle" 
                                value="#000000" 
                                style="width: 50px; padding: 0;">
                        </div>
                        <button id="deleteFieldBtnEdit" class="btn btn-danger btn-sm ms-auto">🗑️ Delete Selected</button>
                    </div>

                    <!-- 🔹 Editor Body -->
                    <div class="d-flex flex-grow-1" style="min-height: 450px; overflow: hidden;">
                        <!-- 🟦 Sidebar Fields -->
                        <div class="p-1 border-end bg-white" style="width: 250px; overflow-y: auto; max-height: 450px;">
                            <h6 class="fw-bold">📌 Fields</h6>

                            <div class="fw-bold mt-2 mb-1">Resident Info</div>
                            <button class="btn btn-outline-secondary w-100 insert-field-btn-edit mb-1" data-field="{{full_name}}">Full Name</button>
                            <button class="btn btn-outline-secondary w-100 insert-field-btn-edit mb-1" data-field="{{address}}">Address</button>
                            <button class="btn btn-outline-secondary w-100 insert-field-btn-edit mb-1" data-field="{{birth_date}}">Birth Date</button>
                            <button class="btn btn-outline-secondary w-100 insert-field-btn-edit mb-1" data-field="{{birth_place}}">Place of Birth</button>
                            <button class="btn btn-outline-secondary w-100 insert-field-btn-edit mb-1" data-field="{{age}}">Age</button>
                            <button class="btn btn-outline-secondary w-100 insert-field-btn-edit mb-1" data-field="{{civil_status}}">Civil Status</button>
                            <button class="btn btn-outline-secondary w-100 insert-field-btn-edit mb-1" data-field="{{gender}}">Gender</button>
                            <button class="btn btn-outline-secondary w-100 insert-field-btn-edit mb-1" data-field="{{religion}}">Religion</button>
                            <button class="btn btn-outline-secondary w-100 insert-field-btn-edit mb-1" data-field="{{nationality}}">Nationality</button>
                            <button class="btn btn-outline-secondary w-100 insert-field-btn-edit mb-1" data-field="{{contact_number}}">Contact Number</button>
                            <button class="btn btn-outline-secondary w-100 insert-field-btn-edit mb-1" data-field="{{email}}">Email Address</button>

                            <div class="fw-bold mt-3 mb-1">Emergency Contact</div>
                            <button class="btn btn-outline-secondary w-100 insert-field-btn-edit mb-1" data-field="{{emergency_name}}">Name</button>
                            <button class="btn btn-outline-secondary w-100 insert-field-btn-edit mb-1" data-field="{{emergency_relation}}">Relation</button>
                            <button class="btn btn-outline-secondary w-100 insert-field-btn-edit mb-1" data-field="{{emergency_number}}">Number</button>

                            <div class="fw-bold mt-3 mb-1">Barangay Officials</div>
                            <button class="btn btn-outline-secondary w-100 insert-field-btn-edit mb-1" data-field="{{barangay_captain}}">Captain</button>
                            <button class="btn btn-outline-secondary w-100 insert-field-btn-edit mb-1" data-field="{{barangay_secretary}}">Secretary</button>
                            <button class="btn btn-outline-secondary w-100 insert-field-btn-edit mb-1" data-field="{{barangay_treasurer}}">Treasurer</button>

                            <div class="fw-bold mt-3 mb-1">Date Fields</div>
                            <button class="btn btn-outline-secondary w-100 insert-field-btn-edit mb-1" data-field="{{day}}">No. Days</button>
                            <button class="btn btn-outline-secondary w-100 insert-field-btn-edit mb-1" data-field="{{day_name}}">Day Name</button>
                            <button class="btn btn-outline-secondary w-100 insert-field-btn-edit mb-1" data-field="{{month}}">No. Month </button>
                            <button class="btn btn-outline-secondary w-100 insert-field-btn-edit mb-1" data-field="{{month_name}}">Month Name</button>
                            <button class="btn btn-outline-secondary w-100 insert-field-btn-edit mb-1" data-field="{{year}}">Year (YYYY)</button>
                            <button class="btn btn-outline-secondary w-100 insert-field-btn-edit mb-1" data-field="{{year_short}}">Year (YY)</button>
                        </div>

                        <!-- 🟧 Canvas Area -->
                        <div id="canvasScrollContainerEdit" class="p-1 flex-grow-1 overflow-auto" style="max-height: 450px; position: relative;">
                            <div id="pdfEditorWrapperEdit" style="position: relative; display: inline-block;">
                                <canvas id="pdfCanvasEditorEdit"></canvas>
                                <!-- fields will be appended here -->
                            </div>
                        </div>
                    </div> <!-- End editor body -->
                </div>
            </div>

            <div class="modal-footer">
                <button class="btn btn-success" id="saveLayoutBtnEdit">💾 Save Changes</button>
                <button class="btn btn-secondary" data-bs-dismiss="modal">Close</button>
            </div>
        </div>
    </div>
</div>


<!-- JS -->
<script src="../ajax/services.js"></script>
<script>

</script>



