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

// ✅ Step 3: Kunin lahat ng emergency reports na related sa address_id
$sql = "SELECT 
            e.emergency_id,
            e.emergency_type,
            e.report_time,
            e.latitude,
            e.longitude,
            r.image_url,
            r.first_name,
            r.middle_name,
            r.last_name,
            r.mobile_number,
            r.city,
            r.barangay,
            r.house_number
        FROM emergency e
        JOIN residents r ON e.resident_id = r.id
        WHERE e.address_id = ?
        ORDER BY e.report_time DESC";

$stmt = $conn->prepare($sql);
$stmt->bind_param("i", $address_id);
$stmt->execute();
$result = $stmt->get_result();

?>

<script src="https://code.jquery.com/jquery-3.6.0.min.js"></script>
<link href="https://cdnjs.cloudflare.com/ajax/libs/cropperjs/1.5.13/cropper.min.css" rel="stylesheet">
<script src="https://cdnjs.cloudflare.com/ajax/libs/cropperjs/1.5.13/cropper.min.js"></script>
<script src="../bootstrap5/js/bootstrap.bundle.min.js"></script>
<link rel="stylesheet" href="https://unpkg.com/leaflet/dist/leaflet.css" />
<script src="https://unpkg.com/leaflet/dist/leaflet.js"></script>
<link href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0/css/all.min.css" rel="stylesheet">
<link rel="stylesheet" href="../css/emergency.css" />

<title>Barangay Resident - BRGY GO</title>

<style>
#leafletMap {
    width: 100%;
    height: 330px;
    border-radius: 12px;
}

/* Add this to ensure map container is visible */
.modal-body .card-body {
    min-height: 350px;
}
</style>

<nav class="navbar">
  <div class="navbar-container">
    <div class="section-name">Barangay Resident</div>
    <div class="notification-wrapper" id="notifBtn">
      <i class="bi bi-bell-fill" style="font-size: 35px;"></i>
      <span class="badge-number">4</span>
    </div>
  </div>
</nav>  

<div class="main-container" style="display: flex; align-items: flex-start;">
    
    <!-- Emergency Table Section -->
    <div class="table-container" style="flex: 3;">
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
                        <th style="width: 100px;">IMAGE</th>
                        <th style="width: 190px; cursor:pointer;" onclick="sortTable(1)">RESIDENT NAME <span class="sort-arrow"></span></th>
                        <th style="width: 225px; cursor:pointer;" onclick="sortTable(2)">EMERGENCY TYPE<span class="sort-arrow"></span></th>
                        <th style="width: 175px; cursor:pointer;" onclick="sortTable(3)">TIME <span class="sort-arrow"></span></th>
                    </tr>
                </thead>
            </table>

            <!-- Scrollable Body -->
            <div class="table-body-wrapper">
                <table class="data-table">
                    <tbody class="table-body" id="EmergencyTableBody">
                        <?php
                            if ($result->num_rows > 0) {
                                while($row = $result->fetch_assoc()) {
                                    // ✅ Format Fullname
                                    $middleInitial = !empty($row['middle_name']) ? strtoupper(substr($row['middle_name'], 0, 1)) . '.' : '';
                                    $fullname = $row['last_name'] . ', ' . $row['first_name'] . ' ' . $middleInitial;

                                    // ✅ Image fallback
                                   $image = !empty($row['image_url']) ? $row['image_url'] : 'default.png';

                                    // ✅ Format Time
                                    $time = date("M d, Y h:i A", strtotime($row['report_time']));

                                    // ✅ Emergency Type Badge Class
                                    $typeClass = '';
                                    switch(strtolower($row['emergency_type'])) {
                                        case 'fire': $typeClass = 'status-fire'; break;
                                        case 'medical': $typeClass = 'status-medical'; break;
                                        case 'crime': $typeClass = 'status-crime'; break;
                                        case 'accident': $typeClass = 'status-accident'; break;
                                        default: $typeClass = 'status-other'; break;
                                    }

                                    echo '<tr class="table-row" data-id="'.$row['emergency_id'].'" data-lat="'.$row['latitude'].'" data-lng="'.$row['longitude'].'" style="cursor:pointer;">';

                                    // Image
                                    echo '<td class="table-cell" style="width: 70px;">
                                            <div class="avatar avatar-red">
                                                <img src="../uploads/residents/' . $image . '" alt="emergency" style="width:100%; height:100%; border-radius:50%; object-fit:cover;">
                                            </div>
                                          </td>';

                                    // Fullname
                                    echo '<td class="table-cell" style="width: 190px;">
                                            <div class="name-text">' . $fullname . '</div>
                                          </td>';

                                    // Emergency Type
                                    echo '<td class="table-cell" style="width: 225px; text-align:center;">
                                            <span class="status-badge '.$typeClass.'">' . $row['emergency_type'] . '</span>
                                          </td>';

                                    // Time
                                    echo '<td class="table-cell" style="width: 175px;">
                                            <div class="info-text">' . $time . '</div>
                                          </td>';

                                    echo '</tr>';
                                }
                            } else {
                                echo '<tr><td colspan="4" style="text-align:center;">No emergency reports found.</td></tr>';
                            }
                        ?>
    
                    </tbody>
                </table>
            </div>
        </div>

        <!-- Footer -->
        <div class="table-footer" style="border-bottom-left-radius: 20px;border-bottom-right-radius: 20px;">
        </div>
    </div>

    <!-- Hotline Section -->
    <div class="hotline-container">
        <div class="hotline-header">
            <i class="fas fa-phone-alt"></i> Emergency Contacts
        </div>
        <div class="hotline-list">
            <div class="hotline-card emergency">
                <div class="icon"><i class="fas fa-exclamation-triangle"></i></div>
                <div class="info">
                    <div class="name">Emergency Hotline</div>
                    <div class="number">911</div>
                </div>
            </div>

            <div class="hotline-card">
                <div class="icon fire"><i class="fas fa-fire-extinguisher"></i></div>
                <div class="info">
                    <div class="name">Fire Department</div>
                    <div class="number">(555) 123-4567</div>
                </div>
            </div>

            <div class="hotline-card">
                <div class="icon police"><i class="fas fa-shield-alt"></i></div>
                <div class="info">
                    <div class="name">Police Department</div>
                    <div class="number">(555) 234-5678</div>
                </div>
            </div>

            <div class="hotline-card">
                <div class="icon hospital"><i class="fas fa-hospital"></i></div>
                <div class="info">
                    <div class="name">City Hospital</div>
                    <div class="number">(555) 345-6789</div>
                </div>
            </div>
        </div>
        <button class="add-contact-btn"><i class="fas fa-plus"></i> Add New Contact</button>
    </div>

</div>


<!-- Emergency Info Modal -->
<div class="modal fade" id="emergencyInfoModal" tabindex="-1" aria-hidden="true">
  <div class="modal-dialog modal-xl modal-dialog-centered">
    <div class="modal-content" style="border-radius: 16px; overflow: hidden;">
      
      <!-- Header -->
      <div class="modal-header" style="background: #3b82f6; color: #fff;">
        <h5 class="modal-title">
          <i class="fas fa-user"></i> Resident Information
        </h5>
        <button type="button" class="btn-close btn-close-white" data-bs-dismiss="modal"></button>
      </div>

      <!-- Body -->
      <div class="modal-body" style="background: linear-gradient(#F1F3FF, #CBD4FF);">
        <div class="row g-3">
          
          <!-- Resident Info (with card) -->
            <div class="col-md-6">
                <div class="card shadow-sm border-0 h-100" style="border-radius: 12px; background: linear-gradient(#FFF8E1, #FFD54F);">
                    <div class="card-body" id="residentInfoCard">
                      <h4 class="card-title mb-4" style="font-size: 1.8rem; font-weight: 700;">👤 Resident Information</h4>
                      <p class="mb-3" style="font-size: 1.2rem;"><strong>Name:</strong> Loading...</p>
                      <p class="mb-3" style="font-size: 1.2rem;"><strong>Address:</strong> Loading...</p>
                      <p class="mb-3" style="font-size: 1.2rem;"><strong>Emergency Type:</strong> Loading...</p>
                      <p class="mb-3" style="font-size: 1.2rem;"><strong>Time Reported:</strong> Loading...</p>
                      <p class="mb-3" style="font-size: 1.2rem;"><strong>Phone Number:</strong> Loading...</p>
                      <p class="mb-3" style="font-size: 1.2rem;"><strong>Current Location:</strong> Loading...</p>
                    </div>
                </div>
            </div>

          <!-- Map -->
          <div class="col-md-6">
            <div class="card shadow-sm border-0 h-100" style="border-radius: 12px;">
              <div class="card-body p-2">
                <div id="leafletMap" style="width: 100%; height: 330px; border-radius: 12px; overflow: hidden;"></div>
              </div>
            </div>
          </div>

        </div>
      </div>

      <!-- Footer -->
      <div class="modal-footer" style="background: linear-gradient(#F1F3FF, #CBD4FF);">
        <button type="button" class="btn btn-secondary" data-bs-dismiss="modal">Close</button>
        <button type="button" class="btn btn-primary"><i class="fas fa-phone"></i> Call Hotline</button>
      </div>

    </div>
  </div>
</div>

<script>
// Global variable for the map
let emergencyMap = null;

$(document).ready(function () {
    $(".table-row").on("click", function () {
        const id = $(this).data("id");

        // Show loading state
        $("#residentInfoCard").html(`
            <h4 class="card-title mb-4" style="font-size: 1.8rem; font-weight: 700;">👤 Resident Information</h4>
            <p class="mb-3" style="font-size: 1.2rem;"><strong>Name:</strong> Loading...</p>
            <p class="mb-3" style="font-size: 1.2rem;"><strong>Address:</strong> Loading...</p>
            <p class="mb-3" style="font-size: 1.2rem;"><strong>Emergency Type:</strong> Loading...</p>
            <p class="mb-3" style="font-size: 1.2rem;"><strong>Time Reported:</strong> Loading...</p>
            <p class="mb-3" style="font-size: 1.2rem;"><strong>Phone Number:</strong> Loading...</p>
            <p class="mb-3" id="currentLocation"><strong>Current Location:</strong> Loading...</p>
        `);

        // Show modal first
        $("#emergencyInfoModal").modal("show");

        // Fetch data after modal is shown
        $.ajax({
            url: "../database/emergency_fetch.php",
            type: "POST",
            data: { id: id },
            dataType: "json",
            success: function (data) {
                if (data.error) {
                    alert(data.error);
                } else {
                    let middle = data.middle_name ? data.middle_name.charAt(0).toUpperCase() + "." : "";
                    let fullname = data.last_name + ", " + data.first_name + " " + middle;

                    // Fill resident info
                    $("#residentInfoCard").html(`
                        <h4 class="card-title mb-4" style="font-size: 1.8rem; font-weight: 700;">👤 Resident Information</h4>
                        <p class="mb-3"><strong>Name:</strong> ${fullname}</p>
                        <p class="mb-3"><strong>Address:</strong> ${data.house_number}, ${data.barangay}, ${data.city}</p>
                        <p class="mb-3"><strong>Emergency Type:</strong> ${data.emergency_type}</p>
                        <p class="mb-3"><strong>Time Reported:</strong> ${data.report_time}</p>
                        <p class="mb-3"><strong>Phone Number:</strong> ${data.mobile_number}</p>
                        <p class="mb-3" id="currentLocation"><strong>Current Location:</strong> Loading...</p>
                    `);

                    // Initialize or update the map
                    initMap(data.latitude, data.longitude, fullname, data.emergency_type);

                    // Reverse Geocoding para i-auto fill yung location
                    $.getJSON(`https://nominatim.openstreetmap.org/reverse?format=json&lat=${data.latitude}&lon=${data.longitude}&zoom=18&addressdetails=1`, function (res) {
    console.log("Reverse Geocode Response:", res); // ✅ Check dito sa browser console
    
    if (res && res.display_name) {
        $("#currentLocation").html(`<strong>Current Location:</strong> ${res.display_name}`);
    } else {
        $("#currentLocation").html(`<strong>Current Location:</strong> ${data.latitude}, ${data.longitude}`);
    }
}).fail(function() {
    console.error("❌ Reverse geocoding request failed.");
    $("#currentLocation").html(`<strong>Current Location:</strong> ${data.latitude}, ${data.longitude}`);
});

                }
            }
        });
    });

    // Initialize map when modal is shown
    $('#emergencyInfoModal').on('shown.bs.modal', function () {
        if (emergencyMap) {
            // Refresh map size when modal is shown
            setTimeout(function() {
                emergencyMap.invalidateSize();
            }, 200);
        }
    });

    // Clean up map when modal is hidden
    $('#emergencyInfoModal').on('hidden.bs.modal', function () {
        if (emergencyMap) {
            emergencyMap.remove();
            emergencyMap = null;
        }
    });
});

// Function to initialize the map
function initMap(lat, lng, name, emergencyType) {
    // Remove existing map if any
    if (emergencyMap) {
        emergencyMap.remove();
    }

    // Initialize the map
    emergencyMap = L.map('leafletMap').setView([lat, lng], 16);

    L.tileLayer('https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png', {
        attribution: '&copy; <a href="https://www.openstreetmap.org/copyright">OpenStreetMap</a> contributors'
    }).addTo(emergencyMap);

    // Add marker
    L.marker([lat, lng])
        .addTo(emergencyMap)
        .bindPopup(`<b>${name}</b><br>${emergencyType}`)
        .openPopup();

    // Ensure proper sizing
    setTimeout(function() {
        emergencyMap.invalidateSize();
    }, 200);
}

// 🔎 Search Function
function searchTable() {
    let input = document.getElementById("searchInput").value.toLowerCase();
    let rows = document.querySelectorAll("#EmergencyTableBody tr");

    rows.forEach(row => {
        let text = row.innerText.toLowerCase();
        row.style.display = text.includes(input) ? "" : "none";
    });
}

// 📊 Sort Function
function sortTable(columnIndex) {
    let table = document.querySelector("#EmergencyTableBody");
    let rows = Array.from(table.rows);

    rows.sort((a, b) => {
        let cellA = a.cells[columnIndex].innerText.trim().toLowerCase();
        let cellB = b.cells[columnIndex].innerText.trim().toLowerCase();
        return cellA.localeCompare(cellB);
    });

    rows.forEach(row => table.appendChild(row));
}
</script>
