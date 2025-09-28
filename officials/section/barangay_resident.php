<?php
session_start();

if (!isset($_SESSION['user_id'])) {
    // Redirect to login page
    header("Location: login_signup.php");
    exit;
}

include('sidebar.php'); 
include('../database/config.php');


$real_user_id = $_SESSION['user_id'];

// Kunin address_id ng logged-in user
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


// 🔹 Fetch residents na naka-filter sa address_id
$sql = "SELECT r.`id`, r.`user_id`, r.`image_url`, r.`first_name`, r.`middle_name`, r.`last_name`, 
               r.`gender`, r.`date_of_birth`, r.`pob_country`, r.`pob_province`, r.`pob_city`, 
               r.`civil_status`, r.`nationality`, r.`religion`, r.`country`, r.`province`, 
               r.`city`, r.`barangay`, r.`zipcode`, r.`house_number`, r.`zone_purok`, 
               r.`residency_date`, r.`years_of_residency`, r.`residency_type`, r.`previous_address`, 
               r.`father_name`, r.`mother_name`, r.`spouse_name`, r.`number_of_family_members`, 
               r.`household_number`, r.`relationship_to_head`, r.`house_position`, 
               r.`educational_attainment`, r.`current_school`, r.`occupation`, r.`monthly_income`, 
               r.`mobile_number`, r.`telephone_number`, r.`email_address`, 
               r.`emergency_contact_person`, r.`emergency_contact_number`, 
               r.`pwd_status`, r.`pwd_id_number`, r.`senior_citizen_status`, 
               r.`senior_id_number`, r.`solo_parent_status`, r.`is_4ps_member`, 
               r.`blood_type`, r.`voter_status`
        FROM `residents` r
        WHERE r.address_id = ?";

$stmt = $conn->prepare($sql);
$stmt->bind_param("i", $address_id);
$stmt->execute();
$result = $stmt->get_result();
?>

<link rel="stylesheet" type="text/css" href="../css/barangay_resident.css">
<script src="https://code.jquery.com/jquery-3.6.0.min.js"></script>
<link href="https://cdnjs.cloudflare.com/ajax/libs/cropperjs/1.5.13/cropper.min.css" rel="stylesheet">
<script src="https://cdnjs.cloudflare.com/ajax/libs/cropperjs/1.5.13/cropper.min.js"></script>
<script src="../bootstrap5/js/bootstrap.bundle.min.js"></script>
<link href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0/css/all.min.css" rel="stylesheet">


<title>Barangay Resident - BRGY GO</title>

<nav class="navbar">
  <div class="navbar-container">
    <div class="section-name">Barangay Resident</div>
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
                placeholder="Search residents..."
                onkeyup="searchTable()"
            >
        </div>
    </div>

    <!-- Table -->
  <div style="overflow-x: auto;">
    <table class="data-table">
    <thead class="table-header" style=" border-top-left-radius: 20px; border-top-right-radius: 20px; border-right: none;">
  <tr>
    <th style="width: 70px;">IMAGE</th>
    <th style="width: 190px; cursor:pointer;" onclick="sortTable(1)">FULLNAME <span class="sort-arrow"></span></th>
    <th style="width: 225px; cursor:pointer;" onclick="sortTable(2)">EMAIL <span class="sort-arrow"></span></th>
    <th style="width: 175px; cursor:pointer;" onclick="sortTable(3)">PHONE NUMBER <span class="sort-arrow"></span></th>
    <th style="width: 175px; cursor:pointer;" onclick="sortTable(4)">HOUSE POSITION <span class="sort-arrow"></span></th>
    <th style="width: 125px; cursor:pointer;" onclick="sortTable(5)">HOUSE NO <span class="sort-arrow"></span></th>
  </tr>
</thead>
    </table>

    <!-- Scrollable Body -->
    <div class="table-body-wrapper">
        <table class="data-table">
            <tbody class="table-body" id="residentTableBody">
    <?php
if ($result->num_rows > 0) {
    while($row = $result->fetch_assoc()) {
        // Format Fullname: Lastname, Firstname M.
        $middleInitial = !empty($row['middle_name']) ? strtoupper(substr($row['middle_name'], 0, 1)) . '.' : '';
        $fullname = $row['last_name'] . ', ' . $row['first_name'] . ' ' . $middleInitial;

        $image = !empty($row['image_url']) ? $row['image_url'] : 'logo.png"';
        $phone = !empty($row['mobile_number']) ? $row['mobile_number'] : $row['telephone_number'];

        echo '<tr class="table-row" data-id="'.$row['id'].'" style="cursor:pointer;">';
        echo '<td class="table-cell" style="width: 70px;"><div class="avatar avatar-blue"><img src="../uploads/residents/' . $image . '" alt="avatar" style="width:100%; height:100%; border-radius:50%;"></div></td>';
        echo '<td class="table-cell" style="width: 190px;"><div class="name-text">' . $fullname . '</div></td>';
        echo '<td class="table-cell" style="width: 225px;"><div class="info-text">' . $row['email_address'] . '</div></td>';
        echo '<td class="table-cell" style="width: 175px;"><div class="info-text">' . $phone . '</div></td>';

        $positionClass = '';
        switch(strtolower($row['house_position'])) {
            case 'head': $positionClass = 'status-head'; break;
            case 'spouse': $positionClass = 'status-spouse'; break;
            case 'child': $positionClass = 'status-child'; break;
            case 'parent': $positionClass = 'status-parent'; break;
            case 'sibling': $positionClass = 'status-sibling'; break;
            case 'relative': $positionClass = 'status-relative'; break;
            case 'helper': $positionClass = 'status-helper'; break;
            case 'other': $positionClass = 'status-other'; break;
            default: $positionClass = 'status-other'; break;
        }

        echo '<td class="table-cell" style="width:175px; text-align:center;">
                <span class="status-badge '.$positionClass.'">' . $row['house_position'] . '</span>
              </td>';
        echo '<td class="table-cell" style="width: 125px;"><div class="house-number">' . $row['house_number'] . '</div></td>';
        echo '</tr>';
    }
} else {
    echo '<tr><td colspan="6" style="text-align:center;">No residents found.</td></tr>';
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
            <button class="add-resident-btn btn btn-primary " data-bs-toggle="modal" data-bs-target="#addResidentModal"><i class="fas fa-plus"></i>Add New</button>
            <button class="btn btn-secondary"><i class="fas fa-download"></i>Export</button>
        </div>
    </div>
</div>

<?php $conn->close(); ?>

<!-- Add Resident Modal -->
<div class="modal fade" id="addResidentModal" tabindex="-1" aria-labelledby="addResidentLabel" aria-hidden="true" data-bs-backdrop="static" data-bs-keyboard="false">
  <div class="modal-dialog modal-dialog-scrollable modal-xl">
    <div class="modal-content shadow-lg rounded-4 border-0">
      
      <!-- Modal Header -->
      <div class="modal-header border-0 bg-primary text-white rounded-top-4">
        <h5 class="modal-title fw-semibold d-flex align-items-center gap-2" id="addResidentLabel">
          <i class="bi bi-person-plus-fill"></i> Add New Resident
        </h5>
        <button type="button" class="btn-close btn-close-white" data-bs-dismiss="modal" aria-label="Close"></button>
      </div>

      <!-- Modal Body -->
      <form action="../database/resident_add.php" method="POST" enctype="multipart/form-data">
        <div class="modal-body py-4 px-4" style="max-height: 82vh; overflow-y: auto; background: linear-gradient(#F1F3FF, #CBD4FF);">

          <!-- SECTION: PERSONAL INFORMATION -->
          <div class="card mb-4 shadow-sm border-0 rounded-3" style="background: linear-gradient(135deg, #eff6ff 0%, #dbeafe 100%); border-color: #bfdbfe;">
            <div class="card-body">
              <h5 class="fw-bold text-primary mb-3"><i class="bi bi-person-circle me-2"></i> Personal Information</h5>
              <div class="row g-3">
                <div class="col-md-3 text-center">
                  <div id="imageWrapper" class="d-flex justify-content-center align-items-center bg-light rounded-3 border border-2 border-dashed" 
                       style="height: 280px; cursor: pointer; overflow: hidden;">
                    <img id="imagePreview" src="../image/logo.png" alt="Preview" 
                         class="img-fluid rounded-3" style="width: 100%; height: 100%; object-fit: cover;">
                    <input type="file" id="imageInput" onchange="handleImageCrop(event, 'imagePreview')" accept="image/*" hidden>
                    <input type="hidden" name="cropped_image_data" id="cropped_image_data">
                  </div>
                  <label class="form-label fw-semibold">Profile Picture</label>
                </div>
                <div class="col-md-9">
                  <div class="row g-3">
                    <div class="col-md-6">
                      <label class="form-label fw-semibold">First Name</label>
                      <input type="text" class="form-control rounded-3" name="first_name" required>
                    </div>
                    <div class="col-md-6">
                      <label class="form-label fw-semibold">Middle Name</label>
                      <input type="text" class="form-control rounded-3" name="middle_name">
                    </div>
                    <div class="col-md-6">
                      <label class="form-label fw-semibold">Last Name</label>
                      <input type="text" class="form-control rounded-3" name="last_name" required>
                    </div>
                    <div class="col-md-6">
                      <label class="form-label fw-semibold">Gender</label>
                      <select class="form-select rounded-3" name="gender">
                        <option value="">-- Select Gender --</option>
                        <option value="Male">Male</option>
                        <option value="Female">Female</option>
                      </select>
                    </div>
                    <div class="col-md-6">
                      <label class="form-label fw-semibold">Date of Birth</label>
                      <input type="date" class="form-control rounded-3" name="date_of_birth" required>
                    </div>
                    <div class="col-md-6">
                      <label class="form-label fw-semibold">Place of Birth - Country</label>
                      <input type="text" class="form-control rounded-3" name="pob_country" placeholder="e.g., Philippines">
                    </div>
                    <div class="col-md-6">
                      <label class="form-label fw-semibold">Place of Birth - Province</label>
                      <input type="text" class="form-control rounded-3" name="pob_province" placeholder="e.g., Cavite">
                    </div>
                    <div class="col-md-6">
                      <label class="form-label fw-semibold">Place of Birth - City</label>
                      <input type="text" class="form-control rounded-3" name="pob_city" placeholder="e.g., Imus">
                    </div>
                  </div>
                </div>
              </div>
            </div>
          </div>

          <!-- SECTION: CIVIL STATUS & RELIGION -->
          <div class="card mb-4 shadow-sm border-0 rounded-3" style="background: linear-gradient(135deg, #f0fdf4 0%, #dcfce7 100%); border-color: #bbf7d0;">
            <div class="card-body">
              <h5 class="fw-bold text-primary mb-3"><i class="bi bi-heart-fill me-2"></i> Civil Status & Religion</h5>
              <div class="row g-3">
                <div class="col-md-4">
                  <label class="form-label fw-semibold">Civil Status</label>
                  <select class="form-select rounded-3" name="civil_status">
                    <option value="">-- Select Status --</option>
                    <option value="Single">Single</option>
                    <option value="Married">Married</option>
                    <option value="Widowed">Widowed</option>
                    <option value="Separated">Separated</option>
                  </select>
                </div>
                <div class="col-md-4">
                  <label class="form-label fw-semibold">Nationality</label>
                  <input type="text" class="form-control rounded-3" name="nationality">
                </div>
                <div class="col-md-4">
                  <label class="form-label fw-semibold">Religion</label>
                  <input type="text" class="form-control rounded-3" name="religion">
                </div>
              </div>
            </div>
          </div>

          <!-- SECTION: CURRENT ADDRESS -->
          <div class="card mb-4 shadow-sm border-0 rounded-3" style="background: linear-gradient(135deg, #faf5ff 0%, #f3e8ff 100%); border-color: #d8b4fe;">
            <div class="card-body">
              <h5 class="fw-bold text-primary mb-3"><i class="bi bi-geo-alt-fill me-2"></i> Current Address</h5>
              <div class="row g-3">
                <div class="col-md-4">
                  <label class="form-label fw-semibold">Country</label>
                  <input type="text" class="form-control rounded-3" name="country">
                </div>
                <div class="col-md-4">
                  <label class="form-label fw-semibold">Province</label>
                  <input type="text" class="form-control rounded-3" name="province">
                </div>
                <div class="col-md-4">
                  <label class="form-label fw-semibold">City</label>
                  <input type="text" class="form-control rounded-3" name="city">
                </div>
                <div class="col-md-4">
                  <label class="form-label fw-semibold">Barangay</label>
                  <input type="text" class="form-control rounded-3" name="barangay">
                </div>
                <div class="col-md-4">
                  <label class="form-label fw-semibold">Zipcode</label>
                  <input type="text" class="form-control rounded-3" name="zipcode">
                </div>
                <div class="col-md-4">
                  <label class="form-label fw-semibold">House Number</label>
                  <input type="text" class="form-control rounded-3" name="house_number">
                </div>
                <div class="col-md-4">
                  <label class="form-label fw-semibold">Zone/Purok</label>
                  <input type="text" class="form-control rounded-3" name="zone_purok">
                </div>
                <div class="col-md-4">
                  <label class="form-label fw-semibold">Date of Residency</label>
                  <input type="date" class="form-control rounded-3" name="residency_date" id="residency_date">
                </div>
                <div class="col-md-4">
                  <label class="form-label fw-semibold">Years of Residency</label>
                  <input type="text" class="form-control rounded-3" name="years_of_residency" id="years_of_residency" readonly>
                </div>
                <div class="col-md-4">
                  <label class="form-label fw-semibold">Type of Residency</label>
                  <select class="form-select rounded-3" name="residency_type" required>
                    <option value="">-- Select Residency Type --</option>
                    <option value="Non-Migrant">Non-Migrant</option>
                    <option value="Migrant">Migrant</option>
                    <option value="Transient">Transient</option>
                  </select>
                </div>
                <div class="col-md-8">
                  <label class="form-label fw-semibold">Previous Address</label>
                  <input type="text" class="form-control rounded-3" name="previous_address">
                </div>
              </div>
            </div>
          </div>

          <!-- SECTION: FAMILY BACKGROUND -->
          <div class="card mb-4 shadow-sm border-0 rounded-3" style="background: linear-gradient(135deg, #fff7ed 0%, #fed7aa 100%); border-color: #fdba74;">
            <div class="card-body">
              <h5 class="fw-bold text-primary mb-3">
                <i class="bi bi-people-fill me-2"></i> Family Background
              </h5>
              <div class="row g-3">
                <div class="col-md-4">
                  <label class="form-label fw-semibold">Father's Name</label>
                  <input type="text" class="form-control rounded-3" name="father_name">
                </div>
                <div class="col-md-4">
                  <label class="form-label fw-semibold">Mother's Name</label>
                  <input type="text" class="form-control rounded-3" name="mother_name">
                </div>
                <div class="col-md-4">
                  <label class="form-label fw-semibold">Spouse's Name</label>
                  <input type="text" class="form-control rounded-3" name="spouse_name">
                </div>
                <div class="col-md-4">
                  <label class="form-label fw-semibold">Number of Family Members</label>
                  <input type="number" class="form-control rounded-3" name="number_of_family_members">
                </div>
                <div class="col-md-4">
                  <label class="form-label fw-semibold">Household Number</label>
                  <input type="text" class="form-control rounded-3" name="household_number">
                </div>
                <div class="col-md-4">
                  <label class="form-label fw-semibold">House Position</label>
                  <select class="form-select rounded-3" id="house_position" name="house_position">
                    <option value="">-- Select --</option>
                    <option value="Head">Head</option>
                    <option value="Spouse">Spouse</option>
                    <option value="Child">Child</option>
                    <option value="Parent">Parent</option>
                    <option value="Sibling">Sibling</option>
                    <option value="Relative">Relative</option>
                    <option value="Helper">Helper</option>
                    <option value="Other">Other</option>
                  </select>
                </div>
                <div class="col-md-6" id="headOfFamilyBox" style="display:none; position: relative;">
                  <label class="form-label">Head of the Family Name</label>
                  <input type="text" class="form-control" id="head_of_family" name="head_of_family" placeholder="Search head of family...">
                  <div id="suggestionList" class="list-group" style="position:absolute; width:100%; z-index:1000; display:none; max-height:200px; overflow-y:auto;">
                    <!-- search results will appear here -->
                  </div>
                </div>
                <div class="col-md-6" id="headOfFamilyBox" style="display:none; position: relative;">
                  <label class="form-label fw-semibold">Head of the Family</label>
                  <input type="text" class="form-control rounded-3" id="head_of_family" name="head_of_family" placeholder="Search head of family...">
                  <div id="suggestionList" class="list-group shadow-sm rounded-3" style="position:absolute; width:100%; z-index:1000; display:none; max-height:200px; overflow-y:auto;"></div>
                </div>
              </div>
            </div>
          </div>

          <!-- SECTION: EDUCATION & EMPLOYMENT -->
          <div class="card mb-4 shadow-sm border-0 rounded-3" style="background: linear-gradient(135deg, #fdf2f8 0%, #fce7f3 100%); border-color: #f9a8d4;">
            <div class="card-body">
              <h5 class="fw-bold text-primary mb-3">
                <i class="bi bi-mortarboard-fill me-2"></i> Education & Employment
              </h5>
              <div class="row g-3">
                <div class="col-md-4">
                    <label class="form-label fw-semibold">Educational Attainment</label>
                    <select class="form-select rounded-3" name="educational_attainment" required>
                      <option value="">-- Select Educational Attainment --</option>
                      <option value="No Formal Education">No Formal Education</option>
                      <option value="Elementary Level">Elementary Level</option>
                      <option value="Elementary Graduate">Elementary Graduate</option>
                      <option value="High School Level">High School Level</option>
                      <option value="High School Graduate">High School Graduate</option>
                      <option value="Senior High School Level">Senior High School Level</option>
                      <option value="Senior High School Graduate">Senior High School Graduate</option>
                      <option value="Vocational / Technical / TESDA">Vocational / Technical / TESDA</option>
                      <option value="College Level">College Level (Undergraduate)</option>
                      <option value="College Graduate">College Graduate (Bachelor’s Degree)</option>
                      <option value="Postgraduate / Master’s Degree">Postgraduate / Master’s Degree</option>
                      <option value="Doctorate / PhD">Doctorate / PhD</option>
                    </select>
                  </div>
                <div class="col-md-4">
                  <label class="form-label fw-semibold">Current School</label>
                  <input type="text" class="form-control rounded-3" name="current_school">
                </div>
                <div class="col-md-4">
                  <label class="form-label fw-semibold">Occupation</label>
                  <input type="text" class="form-control rounded-3" name="occupation">
                </div>
                <div class="col-md-4">
                  <label class="form-label fw-semibold">Monthly Income</label>
                  <input type="number" class="form-control rounded-3" name="monthly_income">
                </div>
              </div>
            </div>
          </div>

          <!-- SECTION: CONTACT INFORMATION -->
          <div class="card mb-4 shadow-sm border-0 rounded-3" style="background: linear-gradient(135deg, #f0f9ff 0%, #e0f2fe 100%); border-color: #7dd3fc;">
            <div class="card-body">
              <h5 class="fw-bold text-primary mb-3">
                <i class="bi bi-telephone-fill me-2"></i> Contact Information
              </h5>
              <div class="row g-3">
                <div class="col-md-4">
                  <label class="form-label fw-semibold">Mobile Number</label>
                  <input type="text" class="form-control rounded-3" name="mobile_number">
                </div>
                <div class="col-md-4">
                  <label class="form-label fw-semibold">Telephone Number</label>
                  <input type="text" class="form-control rounded-3" name="telephone_number">
                </div>
                <div class="col-md-4">
                  <label class="form-label fw-semibold">Email Address</label>
                  <input type="email" class="form-control rounded-3" name="email_address" id="email_address">
                  <div id="email_error" class="text-danger small mt-1" style="display:none;">
                    This email is already registered.
                  </div>
                </div>
              </div>
            </div>
          </div>

          <!-- SECTION: EMERGENCY CONTACT -->
          <div class="card mb-4 shadow-sm border-0 rounded-3" style="background: linear-gradient(135deg, #fefce8 0%, #fef08a 100%); border-color: #fde047;">
            <div class="card-body">
              <h5 class="fw-bold text-primary mb-3">
                <i class="bi bi-exclamation-triangle-fill me-2"></i> Emergency Contact
              </h5>
              <div class="row g-3">
                <div class="col-md-6">
                  <label class="form-label fw-semibold">Emergency Contact Person</label>
                  <input type="text" class="form-control rounded-3" name="emergency_contact_person">
                </div>
                <div class="col-md-6">
                  <label class="form-label fw-semibold">Emergency Contact Number</label>
                  <input type="text" class="form-control rounded-3" name="emergency_contact_number">
                </div>
              </div>
            </div>
          </div>

          <!-- SECTION: GOVERNMENT INFORMATION -->
          <div class="card mb-4 shadow-sm border-0 rounded-3" style="background: linear-gradient(135deg, #fef2f2 0%, #fecaca 100%); border-color: #f87171;">
            <div class="card-body">
              <h5 class="fw-bold text-primary mb-3">
                <i class="bi bi-building-check me-2"></i> Government Information
              </h5>
              <div class="row g-3">
                <div class="col-md-3">
                  <label class="form-label fw-semibold">PWD Status</label>
                  <select class="form-select rounded-3" name="pwd_status">
                    <option value="">-- Select Status --</option>
                    <option>No</option>
                    <option>Yes</option>
                  </select>
                </div>
                <div class="col-md-3">
                  <label class="form-label fw-semibold">PWD ID Number</label>
                  <input type="text" class="form-control rounded-3" name="pwd_id_number">
                </div>
                <div class="col-md-3">
                  <label class="form-label fw-semibold">Senior Citizen</label>
                  <select class="form-select rounded-3" name="senior_citizen_status">
                    <option value="">-- Select Status --</option>
                    <option>No</option>
                    <option>Yes</option>
                  </select>
                </div>
                <div class="col-md-3">
                  <label class="form-label fw-semibold">Senior ID Number</label>
                  <input type="text" class="form-control rounded-3" name="senior_id_number">
                </div>
                <div class="col-md-3">
                  <label class="form-label fw-semibold">Solo Parent</label>
                  <select class="form-select rounded-3" name="solo_parent_status">
                    <option value="">-- Select Status --</option>
                    <option>No</option>
                    <option>Yes</option>
                  </select>
                </div>
                <div class="col-md-3">
                  <label class="form-label fw-semibold">4Ps Member</label>
                  <select class="form-select rounded-3" name="is_4ps_member">
                    <option value="">-- Select Status --</option>
                    <option>No</option>
                    <option>Yes</option>
                  </select>
                </div>
                <div class="col-md-3">
                  <label class="form-label fw-semibold">Blood Type</label>
                  <input type="text" class="form-control rounded-3" name="blood_type">
                </div>
                <div class="col-md-3">
                  <label class="form-label fw-semibold">Voter Status</label>
                  <select class="form-select rounded-3" name="voter_status" required>
                    <option value="">-- Select Voter Status --</option>
                    <option value="Yes">Yes</option>
                    <option value="No">No</option>
                  </select>
                </div>
              </div>
            </div>
          </div>

        <!-- Footer -->
          <div class="modal-footer border-0 d-flex justify-content-end gap-2">
            <button type="button" class="btn btn-danger btn-lg rounded-3 px-4 py-2 shadow-sm" data-bs-dismiss="modal">
              <i class="bi bi-x-circle me-1"></i> Cancel
            </button>
            <button type="submit" class="btn btn-primary btn-lg rounded-3 px-4 py-2 shadow-sm">
              <i class="bi bi-save2 me-1"></i> Save
            </button>
          </div>
        </div>
      </form>
    </div>
  </div>
</div>


<!-- View Resident Modal -->
<div class="modal fade" id="viewResidentModal" tabindex="-1" aria-labelledby="addResidentLabel" aria-hidden="true" data-bs-backdrop="static" data-bs-keyboard="false">
  <div class="modal-dialog modal-dialog-scrollable modal-xl">
    <div class="modal-content shadow-lg rounded-4 border-0">
      
      <!-- Modal Header -->
      <div class="modal-header border-0 bg-primary   text-white rounded-top-4">
        <h5 class="modal-title fw-semibold d-flex align-items-center gap-2" id="addResidentLabel">
          <i class="bi bi-person-plus-fill"></i>Resident Information
        </h5>
        <button type="button" class="btn-close btn-close-white" data-bs-dismiss="modal" aria-label="Close"></button>
      </div>

      <!-- Modal Body -->
      <form id="viewResidentForm" enctype="multipart/form-data">
        <div class="modal-body py-4 px-4" style="max-height: 72vh; overflow-y: auto; background: linear-gradient(#F1F3FF, #CBD4FF);">

          <!-- SECTION: PERSONAL INFORMATION -->
          <div class="card mb-4 shadow-sm border-0 rounded-3" style="background: linear-gradient(135deg, #eff6ff 0%, #dbeafe 100%); border-color: #bfdbfe;">
            <div class="card-body">
              <h5 class="fw-bold text-primary mb-3"><i class="bi bi-person-circle me-2"></i> Personal Information</h5>
              <div class="row g-3">
                <div class="col-md-3 text-center">
                  <div id="view_imageWrapper" class="d-flex justify-content-center align-items-center bg-light rounded-3 border border-2 border-dashed" 
                       style="height: 280px; cursor: pointer; overflow: hidden;">
                    <img id="view_imagePreview" src="../image/logo.png" alt="Preview" 
                         class="img-fluid rounded-3" style="width: 100%; height: 100%; object-fit: cover;">
                  </div>
                  <input type="file" id="view_imageInput" onchange="handleImageCrop(event, 'view_imagePreview')" accept="image/*" hidden>
                    <input type="hidden" name="view_cropped_image_data" id="view_cropped_image_data">
                  <label class="form-label fw-semibold">Profile Picture</label>
                </div>
                <div class="col-md-9">
                  <div class="row g-3">
                    <div class="col-md-6">
                      <label class="form-label fw-semibold">First Name</label>
                      <input type="text" class="form-control rounded-3" name="view_first_name" id="view_first_name" required>
                    </div>
                    <div class="col-md-6">
                      <label class="form-label fw-semibold">Middle Name</label>
                      <input type="text" class="form-control rounded-3" name="view_middle_name" id="view_middle_name">
                    </div>
                    <div class="col-md-6">
                      <label class="form-label fw-semibold">Last Name</label>
                      <input type="text" class="form-control rounded-3" name="view_last_name" id="view_last_name" required>
                    </div>
                    <div class="col-md-6">
                      <label class="form-label fw-semibold">Gender</label>
                      <select class="form-select rounded-3" name="view_gender" id="view_gender">
                        <option value="">-- Select Gender --</option>
                        <option value="Male">Male</option>
                        <option value="Female">Female</option>
                      </select>
                    </div>
                    <div class="col-md-6">
                      <label class="form-label fw-semibold">Date of Birth</label>
                      <input type="date" class="form-control rounded-3" name="view_date_of_birth" id="view_date_of_birth" required>
                    </div>
                    <div class="col-md-6">
                      <label class="form-label fw-semibold">Place of Birth - Country</label>
                      <input type="text" class="form-control rounded-3" name="view_pob_country" id="view_pob_country">
                    </div>
                    <div class="col-md-6">
                      <label class="form-label fw-semibold">Place of Birth - Province</label>
                      <input type="text" class="form-control rounded-3" name="view_pob_province" id="view_pob_province">
                    </div>
                    <div class="col-md-6">
                      <label class="form-label fw-semibold">Place of Birth - City</label>
                      <input type="text" class="form-control rounded-3" name="view_pob_city" id="view_pob_city">
                    </div>
                  </div>
                </div>
              </div>
            </div>
          </div>

          <!-- SECTION: CIVIL STATUS & RELIGION -->
          <div class="card mb-4 shadow-sm border-0 rounded-3" style="background: linear-gradient(135deg, #f0fdf4 0%, #dcfce7 100%); border-color: #bbf7d0;">
            <div class="card-body">
              <h5 class="fw-bold text-primary mb-3"><i class="bi bi-heart-fill me-2"></i> Civil Status & Religion</h5>
              <div class="row g-3">
                <div class="col-md-4">
                  <label class="form-label fw-semibold">Civil Status</label>
                  <select class="form-select rounded-3" name="view_civil_status" id="view_civil_status">
                    <option value="">-- Select Status --</option>
                    <option value="Single">Single</option>
                    <option value="Married">Married</option>
                    <option value="Widowed">Widowed</option>
                    <option value="Separated">Separated</option>
                  </select>
                </div>
                <div class="col-md-4">
                  <label class="form-label fw-semibold">Nationality</label>
                  <input type="text" class="form-control rounded-3" name="view_nationality" id="view_nationality">
                </div>
                <div class="col-md-4">
                  <label class="form-label fw-semibold">Religion</label>
                  <input type="text" class="form-control rounded-3" name="view_religion" id="view_religion">
                </div>
              </div>
            </div>
          </div>

          <!-- SECTION: CURRENT ADDRESS -->
          <div class="card mb-4 shadow-sm border-0 rounded-3" style="background: linear-gradient(135deg, #faf5ff 0%, #f3e8ff 100%); border-color: #d8b4fe;">
            <div class="card-body">
              <h5 class="fw-bold text-primary mb-3"><i class="bi bi-geo-alt-fill me-2"></i> Current Address</h5>
              <div class="row g-3">
                <div class="col-md-4">
                  <label class="form-label fw-semibold">Country</label>
                  <input type="text" class="form-control rounded-3" name="view_country" id="view_country">
                </div>
                <div class="col-md-4">
                  <label class="form-label fw-semibold">Province</label>
                  <input type="text" class="form-control rounded-3" name="view_province" id="view_province">
                </div>
                <div class="col-md-4">
                  <label class="form-label fw-semibold">City</label>
                  <input type="text" class="form-control rounded-3" name="view_city" id="view_city">
                </div>
                <div class="col-md-4">
                  <label class="form-label fw-semibold">Barangay</label>
                  <input type="text" class="form-control rounded-3" name="view_barangay" id="view_barangay">
                </div>
                <div class="col-md-4">
                  <label class="form-label fw-semibold">Zipcode</label>
                  <input type="text" class="form-control rounded-3" name="view_zipcode" id="view_zipcode">
                </div>
                <div class="col-md-4">
                  <label class="form-label fw-semibold">House Number</label>
                  <input type="text" class="form-control rounded-3" name="view_house_number" id="view_house_number">
                </div>
                <div class="col-md-4">
                  <label class="form-label fw-semibold">Zone/Purok</label>
                  <input type="text" class="form-control rounded-3" name="view_zone_purok" id="view_zone_purok">
                </div>
                <div class="col-md-4">
                  <label class="form-label fw-semibold">Date of Residency</label>
                  <input type="date" class="form-control rounded-3" name="view_residency_date" id="view_residency_date">
                </div>
                <div class="col-md-4">
                  <label class="form-label fw-semibold">Years of Residency</label>
                  <input type="text" class="form-control rounded-3" name="view_years_of_residency" id="view_years_of_residency" readonly>
                </div>
                <div class="col-md-4">
                  <label class="form-label fw-semibold">Type of Residency</label>
                  <select class="form-select rounded-3" name="view_residency_type" id="view_residency_type" required>
                    <option value="">-- Select Residency Type --</option>
                    <option value="Non-Migrant">Non-Migrant</option>
                    <option value="Migrant">Migrant</option>
                    <option value="Transient">Transient</option>
                  </select>
                </div>
                <div class="col-md-8">
                  <label class="form-label fw-semibold">Previous Address</label>
                  <input type="text" class="form-control rounded-3" name="view_previous_address" id="view_previous_address">
                </div>
              </div>
            </div>
          </div>

          <!-- SECTION: FAMILY BACKGROUND -->
          <div class="card mb-4 shadow-sm border-0 rounded-3" style="background: linear-gradient(135deg, #fff7ed 0%, #fed7aa 100%); border-color: #fdba74;">
            <div class="card-body">
              <h5 class="fw-bold text-primary mb-3"><i class="bi bi-people-fill me-2"></i> Family Background</h5>
              <div class="row g-3">
                <div class="col-md-4">
                  <label class="form-label fw-semibold">Father's Name</label>
                  <input type="text" class="form-control rounded-3" name="view_father_name" id="view_father_name">
                </div>
                <div class="col-md-4">
                  <label class="form-label fw-semibold">Mother's Name</label>
                  <input type="text" class="form-control rounded-3" name="view_mother_name" id="view_mother_name">
                </div>
                <div class="col-md-4">
                  <label class="form-label fw-semibold">Spouse's Name</label>
                  <input type="text" class="form-control rounded-3" name="view_spouse_name" id="view_spouse_name">
                </div>
                <div class="col-md-4">
                  <label class="form-label fw-semibold">Number of Family Members</label>
                  <input type="number" class="form-control rounded-3" name="view_number_of_family_members" id="view_number_of_family_members">
                </div>
                <div class="col-md-4">
                  <label class="form-label fw-semibold">Household Number</label>
                  <input type="text" class="form-control rounded-3" name="view_household_number" id="view_household_number">
                </div>
                <div class="col-md-4">
                  <label class="form-label fw-semibold">House Position</label>
                  <select class="form-select rounded-3" name="view_house_position" id="view_house_position">
                    <option value="">-- Select --</option>
                    <option value="Head">Head</option>
                    <option value="Spouse">Spouse</option>
                    <option value="Child">Child</option>
                    <option value="Parent">Parent</option>
                    <option value="Sibling">Sibling</option>
                    <option value="Relative">Relative</option>
                    <option value="Helper">Helper</option>
                    <option value="Other">Other</option>
                  </select>
                </div>
                <div class="col-md-6" id="view_headOfFamilyBox" style="display:none; position: relative;">
                  <label class="form-label fw-semibold">Head of the Family Name</label>
                  <input type="text" class="form-control rounded-3" name="view_head_of_family" id="view_head_of_family" placeholder="Search head of family...">
                  <div id="view_suggestionList" class="list-group shadow-sm rounded-3" style="position:absolute; width:100%; z-index:1000; display:none; max-height:200px; overflow-y:auto;"></div>
                </div>
              </div>
            </div>
          </div>

          <!-- SECTION: EDUCATION & EMPLOYMENT -->
          <div class="card mb-4 shadow-sm border-0 rounded-3" style="background: linear-gradient(135deg, #fdf2f8 0%, #fce7f3 100%); border-color: #f9a8d4;">
            <div class="card-body">
              <h5 class="fw-bold text-primary mb-3"><i class="bi bi-mortarboard-fill me-2"></i> Education & Employment</h5>
              <div class="row g-3">
                <div class="col-md-4">
                    <label class="form-label fw-semibold">Educational Attainment</label>
                    <select class="form-select rounded-3" name="view_educational_attainment" id="view_educational_attainment">
                      <option value="" disabled selected>-- Select --</option>
                      <option value="No Formal Education">No Formal Education</option>
                      <option value="Preschool">Preschool</option>
                      <option value="Elementary Level">Elementary Level</option>
                      <option value="Elementary Graduate">Elementary Graduate</option>
                      <option value="High School Level">High School Level</option>
                      <option value="High School Graduate">High School Graduate</option>
                      <option value="Senior High School Level">Senior High School Level</option>
                      <option value="Senior High School Graduate">Senior High School Graduate</option>
                      <option value="Vocational/Technical">Vocational/Technical</option>
                      <option value="College Level">College Level</option>
                      <option value="College Graduate">College Graduate</option>
                      <option value="Post Graduate">Post Graduate</option>
                    </select>
                  </div>
                <div class="col-md-4">
                  <label class="form-label fw-semibold">Current School</label>
                  <input type="text" class="form-control rounded-3" name="view_current_school" id="view_current_school">
                </div>
                <div class="col-md-4">
                  <label class="form-label fw-semibold">Occupation</label>
                  <input type="text" class="form-control rounded-3" name="view_occupation" id="view_occupation">
                </div>
                <div class="col-md-4">
                  <label class="form-label fw-semibold">Monthly Income</label>
                  <input type="number" class="form-control rounded-3" name="view_monthly_income" id="view_monthly_income">
                </div>
              </div>
            </div>
          </div>

          <!-- SECTION: CONTACT INFORMATION -->
          <div class="card mb-4 shadow-sm border-0 rounded-3" style="background: linear-gradient(135deg, #f0f9ff 0%, #e0f2fe 100%); border-color: #7dd3fc;">
            <div class="card-body">
              <h5 class="fw-bold text-primary mb-3"><i class="bi bi-telephone-fill me-2"></i> Contact Information</h5>
              <div class="row g-3">
                <div class="col-md-4">
                  <label class="form-label fw-semibold">Mobile Number</label>
                  <input type="text" class="form-control rounded-3" name="view_mobile_number" id="view_mobile_number">
                </div>
                <div class="col-md-4">
                  <label class="form-label fw-semibold">Telephone Number</label>
                  <input type="text" class="form-control rounded-3" name="view_telephone_number" id="view_telephone_number">
                </div>
                <div class="col-md-4">
                  <label class="form-label fw-semibold">Email Address</label>
                  <input type="email" class="form-control rounded-3" name="view_email_address" id="view_email_address">
                  <div id="view_email_error" class="text-danger small mt-1" style="display:none;">This email is already registered.</div>
                </div>
              </div>
            </div>
          </div>

          <!-- SECTION: EMERGENCY CONTACT -->
          <div class="card mb-4 shadow-sm border-0 rounded-3" style="background: linear-gradient(135deg, #fefce8 0%, #fef08a 100%); border-color: #fde047;">
            <div class="card-body">
              <h5 class="fw-bold text-primary mb-3"><i class="bi bi-exclamation-triangle-fill me-2"></i> Emergency Contact</h5>
              <div class="row g-3">
                <div class="col-md-6">
                  <label class="form-label fw-semibold">Emergency Contact Person</label>
                  <input type="text" class="form-control rounded-3" name="view_emergency_contact_person" id="view_emergency_contact_person">
                </div>
                <div class="col-md-6">
                  <label class="form-label fw-semibold">Emergency Contact Number</label>
                  <input type="text" class="form-control rounded-3" name="view_emergency_contact_number" id="view_emergency_contact_number">
                </div>
              </div>
            </div>
          </div>

          <!-- SECTION: GOVERNMENT INFORMATION -->
          <div class="card mb-4 shadow-sm border-0 rounded-3" style="background: linear-gradient(135deg, #fef2f2 0%, #fecaca 100%); border-color: #f87171;">
            <div class="card-body">
              <h5 class="fw-bold text-primary mb-3"><i class="bi bi-building-check me-2"></i> Government Information</h5>
              <div class="row g-3">
                <div class="col-md-3">
                  <label class="form-label fw-semibold">PWD Status</label>
                  <select class="form-select rounded-3" name="view_pwd_status" id="view_pwd_status">
                    <option value="">-- Select Status --</option>
                    <option>No</option>
                    <option>Yes</option>
                  </select>
                </div>
                <div class="col-md-3">
                  <label class="form-label fw-semibold">PWD ID Number</label>
                  <input type="text" class="form-control rounded-3" name="view_pwd_id_number" id="view_pwd_id_number">
                </div>
                <div class="col-md-3">
                  <label class="form-label fw-semibold">Senior Citizen</label>
                  <select class="form-select rounded-3" name="view_senior_citizen_status" id="view_senior_citizen_status">
                    <option value="">-- Select Status --</option>
                    <option>No</option>
                    <option>Yes</option>
                  </select>
                </div>
                <div class="col-md-3">
                  <label class="form-label fw-semibold">Senior ID Number</label>
                  <input type="text" class="form-control rounded-3" name="view_senior_id_number" id="view_senior_id_number">
                </div>
                <div class="col-md-3">
                  <label class="form-label fw-semibold">Solo Parent</label>
                  <select class="form-select rounded-3" name="view_solo_parent_status" id="view_solo_parent_status">
                    <option value="">-- Select Status --</option>
                    <option>No</option>
                    <option>Yes</option>
                  </select>
                </div>
                <div class="col-md-3">
                  <label class="form-label fw-semibold">4Ps Member</label>
                  <select class="form-select rounded-3" name="view_is_4ps_member" id="view_is_4ps_member">
                    <option value="">-- Select Status --</option>
                    <option>No</option>
                    <option>Yes</option>
                  </select>
                </div>
                <div class="col-md-3">
                  <label class="form-label fw-semibold">Blood Type</label>
                  <input type="text" class="form-control rounded-3" name="view_blood_type" id="view_blood_type">
                </div>
                <div class="col-md-3">
                  <label class="form-label fw-semibold">Voter Status</label>
                  <select class="form-select rounded-3" name="view_voter_status" id="view_voter_status" required>
                    <option value="">-- Select Voter Status --</option>
                    <option value="Yes">Yes</option>
                    <option value="No">No</option>
                  </select>
                </div>
              </div>
            </div>
          </div>
        </div>
        <!-- Footer -->
          <div class="modal-footer border-0 d-flex justify-content-end gap-2" style="background: linear-gradient(#F1F3FF, #CBD4FF);">

            <!-- Delete/Cancel Button -->
            <button type="button" 
                    class="btn btn-danger btn-lg rounded-3 px-4 py-2 shadow-sm align-items-center justify-content-center gap-2" 
                    id="deleteCancelBtn" 
                    style="color: black; width:150px;">
              <i class="bi bi-trash me-1"></i> <span>Delete</span>
            </button>


            <button type="button" class="btn btn-warning btn-lg rounded-3 px-4 py-2 shadow-sm align-items-center justify-content-center gap-2" id="editConfirmBtn" style="width:150px;">
              <i class="bi bi-pencil-square"></i> <span>Edit</span>
            </button>

            <button type="button" class="btn btn-success btn-lg rounded-3 px-4 py-2 shadow-sm align-items-center justify-content-center gap-2" id="saveResidentBtn" style="width:150px; color:black; display:none;">
              <i class="bi bi-save"></i> <span>Save</span>
            </button>
          </div>
      </form>
    </div>
  </div>
</div>

<!-- Confirm Edit Modal -->
<div class="modal fade" id="confirmEditModal" tabindex="-1" aria-hidden="true">
  <div class="modal-dialog modal-dialog-centered">
    <div class="modal-content shadow-lg rounded-4 border-0">
      <div class="modal-header bg-warning text-white rounded-top-4">
        <h5 class="modal-title fw-semibold"><i class="bi bi-exclamation-triangle-fill me-2"></i> Confirm Edit</h5>
        <button type="button" class="btn-close btn-close-white" data-bs-dismiss="modal" aria-label="Close"></button>
      </div>
      <div class="modal-body text-center py-4">
        <p class="fw-semibold fs-5">Are you sure you want to edit this resident?</p>
        <p class="text-muted mb-0"><span id="residentFullName"></span></p>
      </div>
      <div class="modal-footer border-0 d-flex justify-content-center">
        <button type="button" class="btn btn-secondary rounded-3 px-4" data-bs-dismiss="modal">Cancel</button>
        <button type="button" class="btn btn-warning rounded-3 px-4" id="confirmEditYes">Yes, Edit</button>
      </div>
    </div>
  </div>
</div>

<!-- Cancel Edit Modal -->
<div class="modal fade" id="confirmCancelModal" tabindex="-1" aria-hidden="true">
  <div class="modal-dialog modal-dialog-centered">
    <div class="modal-content shadow-lg rounded-4 border-0">
      <div class="modal-header bg-secondary text-white rounded-top-4">
        <h5 class="modal-title fw-semibold"><i class="bi bi-x-circle-fill me-2"></i> Cancel Edit</h5>
        <button type="button" class="btn-close btn-close-white" data-bs-dismiss="modal" aria-label="Close"></button>
      </div>
      <div class="modal-body text-center py-4">
        <p class="fw-semibold fs-5">Are you sure you want to cancel editing?</p>
        <p class="text-muted mb-0"><span id="residentFullNameCancel"></span></p>
      </div>
      <div class="modal-footer border-0 d-flex justify-content-center">
        <button type="button" class="btn btn-secondary rounded-3 px-4" data-bs-dismiss="modal">No</button>
        <button type="button" class="btn btn-danger rounded-3 px-4" id="confirmCancelYes">Yes, Cancel</button>
      </div>
    </div>
  </div>
</div>

<!-- Confirm Delete Modal -->
<div class="modal fade" id="confirmDeleteModal" tabindex="-1" aria-hidden="true">
  <div class="modal-dialog modal-dialog-centered">
    <div class="modal-content shadow-lg rounded-4 border-0">
      <div class="modal-header bg-danger text-white rounded-top-4">
        <h5 class="modal-title fw-semibold"><i class="bi bi-trash-fill me-2"></i> Confirm Delete</h5>
        <button type="button" class="btn-close btn-close-white" data-bs-dismiss="modal" aria-label="Close"></button>
      </div>
      <div class="modal-body text-center py-4">
        <p class="fw-semibold fs-5">Are you sure you want to delete this resident?</p>
        <p class="text-muted mb-0"><span id="residentFullNameDelete"></span></p>
      </div>
      <div class="modal-footer border-0 d-flex justify-content-center">
        <button type="button" class="btn btn-secondary rounded-3 px-4" data-bs-dismiss="modal">Cancel</button>
        <button type="button" class="btn btn-danger rounded-3 px-4" id="confirmDeleteYes">Yes, Delete</button>
      </div>
    </div>
  </div>
</div>


<div class="modal fade" id="cropperModal" tabindex="-1" aria-hidden="true">
  <div class="modal-dialog modal-dialog-centered" style="max-width: 900px; width: 90%;">
    <div class="modal-content border-0 shadow-lg rounded-4">
      <!-- Header -->
      <div class="modal-header border-0 bg-secondary text-white rounded-top-4">
        <h5 class="modal-title fw-semibold d-flex align-items-center gap-2">
          <i class="bi bi-scissors"></i> Crop Image
        </h5>
        <button type="button" class="btn-close btn-close-white" data-bs-dismiss="modal"></button>
      </div>
      
      <!-- Body -->
      <div class="modal-body text-center" style="max-width:870px">
        <img id="cropperImage" class="img-fluid">

      </div>
      
      <!-- Footer -->
      <div class="modal-footer border-0 d-flex justify-content-between px-4 pb-4">
        <button type="button" 
          class="btn btn-secondary rounded-pill px-4 py-2 fw-semibold d-flex justify-content-center align-items-center" 
          data-bs-dismiss="modal" 
          style="width:183.3px; height:52px;">
          Cancel
        </button>
        <button type="button" id="cropImageBtn" class="btn btn-success rounded-pill px-4 py-2 fw-semibold">
          <i class="bi bi-check-circle-fill me-1"></i> Crop & Save
        </button>
      </div>
    </div>
  </div>
</div>

<script src="../ajax/resident.js"></script>
<script>

</script>
