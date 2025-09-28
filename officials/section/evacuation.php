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
?>

<!-- ======================== HEAD IMPORTS ======================== -->
<link rel="stylesheet" type="text/css" href="../css/evacuation.css">
<script src="https://code.jquery.com/jquery-3.6.0.min.js"></script>
<link href="https://cdnjs.cloudflare.com/ajax/libs/cropperjs/1.5.13/cropper.min.css" rel="stylesheet">
<script src="https://cdnjs.cloudflare.com/ajax/libs/cropperjs/1.5.13/cropper.min.js"></script>
<link rel="stylesheet" href="https://unpkg.com/leaflet@1.9.4/dist/leaflet.css" />
<script src="https://unpkg.com/leaflet@1.9.4/dist/leaflet.js"></script>
<link rel="stylesheet" href="https://unpkg.com/leaflet-control-geocoder/dist/Control.Geocoder.css" />
<script src="https://unpkg.com/leaflet-control-geocoder/dist/Control.Geocoder.js"></script>
<script src="https://unpkg.com/leaflet-routing-machine@latest/dist/leaflet-routing-machine.js"></script>
<link rel="stylesheet" href="https://unpkg.com/leaflet-routing-machine@latest/dist/leaflet-routing-machine.css"/>
<title>Evacuation Center - BRGY GO</title>

<!-- ======================== NAVIGATION BAR ======================== -->
<nav class="navbar">
    <div class="navbar-container">
        <div class="section-name">Evacuation Center</div>
        <div class="notification-wrapper" id="notifBtn">
            <i class="bi bi-bell-fill" style="font-size: 35px;"></i>
            <span class="badge-number">4</span>
        </div>
    </div>
</nav>

<div class="container-fluid mt-3">
    <div class="row">
        <!-- LEFT COLUMN: Evacuation Cards -->
        <div class="col-md-9">
            <div class="scroll-wrapper">
                <div class="container mt-4">
                    <?php
                    // Limit evacuation centers only for this user's address_id
                    $query = "SELECT * FROM evacuation_centers WHERE address_id = ?";
                    $stmt = $conn->prepare($query);
                    $stmt->bind_param("i", $address_id);
                    $stmt->execute();
                    $result = $stmt->get_result();

                    while ($row = $result->fetch_assoc()) {
                        $name = htmlspecialchars($row['name']);
                        $capacity = (int)$row['capacity'];
                        $address = htmlspecialchars($row['address']);
                        $created_at = $row['created_at'];
                        $imageFilename = $row['image_path'];
                        $imagePath = !empty($imageFilename) 
                            ? '../uploads/evacuation/' . $imageFilename 
                            : '../image/evacuation_sample.jpeg';

                        echo '
                        <div class="evacuation-card view-evacuation-card"
                            data-bs-toggle="modal"
                            data-bs-target="#viewEvacuationModal"
                            data-id="' . $row['id'] . '"
                            data-name="' . $name . '"
                            data-address="' . $address . '"
                            data-lat="' . $row['latitude'] . '"
                            data-lng="' . $row['longitude'] . '"
                            data-radius="' . $row['radius'] . '"
                        >
                            <div class="evacuation-image">
                                <img src="' . $imagePath . '" alt="Evacuation Center Image">
                            </div>
                            <div class="evacuation-info">
                                <h3 class="evacuation-name">' . $name . '</h3>
                                <p class="evacuation-capacity">
                                    <strong>Capacity:</strong> ' . $capacity . ' ' . ($capacity > 1 ? "Persons" : "Person") . '
                                </p>

                                <p class="evacuation-location">
                                    <strong>Location:</strong> ' . $address . '
                                </p>
                            </div>
                        </div>';
                    }
                    ?>

                    <!-- ADD CARD -->
                    <div class="evacuation-card add-card" data-bs-toggle="modal" data-bs-target="#addEvacuationModal">
                        <div class="add-card-content">
                            <div class="plus-icon">+</div>
                            <div class="add-text">Add Evacuation Center</div>
                        </div>
                    </div>
                </div>
            </div>
        </div>

        <!-- RIGHT COLUMN: Windy Map -->
        <div class="col-md-3">
            <div class="card shadow-lg border-0 rounded-4 overflow-hidden h-80">
                <!-- Card Header -->
                <div class="card-header bg-white d-flex justify-content-between align-items-center py-2 px-3">
                    <h6 id="reloadMap" class="mb-0 fw-bold text-primary" style="cursor:pointer;">
                        🌤 Weather Map
                    </h6>
                    <button class="btn btn-sm btn-outline-primary" data-bs-toggle="modal" data-bs-target="#weatherModal">
                        Fullscreen
                    </button>
                </div>

                <!-- Map Body -->
                <div class="card-body p-0">
                    <iframe 
                        id="windyMap"
                        width="100%" 
                        height="565px" 
                        src="https://embed.windy.com/embed2.html?lat=12.8797&lon=121.7740&zoom=5&level=surface&overlay=wind" 
                        frameborder="0"
                        class="rounded-bottom-4">
                    </iframe>
                </div>
            </div>
        </div>
    </div>
</div>

<!-- ================= WEATHER MAP MODAL ================= -->
<div class="modal fade" id="weatherModal" tabindex="-1" aria-hidden="true">
    <div class="modal-dialog modal-fullscreen">
        <div class="modal-content border-0 rounded-0">
            <!-- Modal Header -->
            <div class="modal-header bg-primary text-white">
                <h5 id="reloadMapFull" class="modal-title" style="cursor:pointer;">🌍 Weather Map - Fullscreen</h5>
                <button type="button" class="btn-close btn-close-white" data-bs-dismiss="modal"></button>
            </div>
            
            <!-- Modal Body -->
            <div class="modal-body p-0">
                <iframe 
                    id="windyMapFull"
                    width="100%" 
                    height="100%" 
                    src="https://embed.windy.com/embed2.html?lat=12.8797&lon=121.7740&zoom=5&level=surface&overlay=wind" 
                    frameborder="0">
                </iframe>
            </div>
        </div>
    </div>
</div>

<!-- ======================== ADD EVACUATION MODAL ======================== --> 
<div class="modal fade" id="addEvacuationModal" tabindex="-1" aria-hidden="true">
    <div class="modal-dialog modal-dialog-centered modal-lg">
        <div class="modal-content border-0 shadow-lg rounded-4 overflow-hidden" style="backdrop-filter: blur(12px); background: rgba(255,255,255,0.9);">
            <form id="evacuationForm" method="POST" enctype="multipart/form-data" action="../database/evacuation_add.php">
                <!-- Header -->
                <div class="modal-header border-0 text-white" 
                    style="background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
                    padding: 1.25rem 1.5rem;">
                    <h4 class="fw-bold mb-0">➕ Add Evacuation Center</h4>
                    <button type="button" class="btn-close btn-close-white shadow-none" data-bs-dismiss="modal"></button>
                </div>

                <!-- Body -->
                <div class="modal-body p-4">
                    <!-- Top Section: Image + Info -->
                    <div class="row g-4">
                        <!-- Image Upload -->
                        <div class="col-md-5 d-flex justify-content-center">
                            <div id="imageContainer" 
                                class="rounded-4 shadow-sm border d-flex align-items-center justify-content-center p-0 w-100 position-relative"
                                style="cursor:pointer; height:180px; background:#f4f6ff; overflow:hidden;">
                                
                                <img id="imagePreview" 
                                    src="https://via.placeholder.com/600x400.png?text=Upload" 
                                    alt="Preview" 
                                    class="w-100 h-100" 
                                    style="object-fit:cover;">
                                
                                <input type="file" name="evacImage" id="evacImage" accept="image/*" hidden>
                                
                                <div class="overlay position-absolute top-0 start-0 w-100 h-100 d-flex align-items-center justify-content-center 
                                            bg-dark bg-opacity-50 text-white fw-semibold"
                                    style="opacity:0; transition:.3s;">
                                    Click to Upload
                                </div>
                            </div>
                        </div>

                        <!-- Name + Address -->
                        <div class="col-md-7">
                            <div class="mb-3">
                                <label class="fw-semibold small text-muted">CENTER NAME</label>
                                <input type="text" name="name" class="form-control form-control-lg rounded-3 shadow-sm" placeholder="Enter evacuation center name" required>
                            </div>
                            <div>
                                <label class="fw-semibold small text-muted">ADDRESS</label>
                                <input type="text" name="address" class="form-control form-control-lg rounded-3 shadow-sm" placeholder="Enter address">
                            </div>
                        </div>
                    </div>

                    <!-- Length / Width / Space per Person -->
                    <div class="row g-3 mt-4">
                        <div class="col-md-4">
                            <label class="fw-semibold small text-muted">LENGTH (M)</label>
                            <input type="number" id="length" name="length" class="form-control form-control-lg rounded-3 shadow-sm" placeholder="Enter length" required>
                        </div>
                        <div class="col-md-4">
                            <label class="fw-semibold small text-muted">WIDTH (M)</label>
                            <input type="number" id="width" name="width" class="form-control form-control-lg rounded-3 shadow-sm" placeholder="Enter width" required>
                        </div>
                        <div class="col-md-4">
                            <label class="fw-semibold small text-muted">SPACE PER PERSON (SQM)</label>
                            <input type="number" id="sqmPerPerson" name="sqmPerPerson" class="form-control form-control-lg rounded-3 shadow-sm" value="3" min="1" step="0.1" required>
                        </div>
                    </div>

                    <!-- Computed Analytics -->
                    <div class="mt-4">
                        <label class="fw-semibold small text-primary">📊 Computed Analytics</label>
                        <div class="row g-3 mt-2">
                            <!-- Radius -->
                            <div class="col-md-4">
                                <div class="card border-0 rounded-4 shadow-sm text-center h-100">
                                    <div class="card-body py-3">
                                        <div class="text-danger mb-1">
                                            <i class="bi bi-circle-half" style="font-size:1.6rem;"></i>
                                        </div>
                                        <div class="fw-semibold small text-muted">RADIUS (M)</div>
                                        <div class="fs-5 fw-bold text-dark" id="radiusDisplay">-</div>
                                    </div>
                                </div>
                            </div>

                            <!-- Area -->
                            <div class="col-md-4">
                                <div class="card border-0 rounded-4 shadow-sm text-center h-100">
                                    <div class="card-body py-3">
                                        <div class="text-primary mb-1">
                                            <i class="bi bi-bounding-box" style="font-size:1.6rem;"></i>
                                        </div>
                                        <div class="fw-semibold small text-muted">AREA (SQM)</div>
                                        <div class="fs-5 fw-bold text-dark" id="areaDisplay">-</div>
                                    </div>
                                </div>
                            </div>

                            <!-- Capacity -->
                            <div class="col-md-4">
                                <div class="card border-0 rounded-4 shadow-sm text-center h-100">
                                    <div class="card-body py-3">
                                        <div class="text-success mb-1">
                                            <i class="bi bi-people-fill" style="font-size:1.6rem;"></i>
                                        </div>
                                        <div class="fw-semibold small text-muted">MAX CAPACITY</div>
                                        <div class="fs-5 fw-bold text-dark" id="capacityDisplay">-</div>
                                    </div>
                                </div>
                            </div>
                        </div>
                    </div>

                    <!-- Map Picker -->
                    <div class="mt-4">
                        <label class="fw-semibold small text-muted">Pick Location</label>
                        <button type="button" class="btn btn-outline-primary w-100 mt-2 rounded-3 shadow-sm" id="openMapBtn">
                            📍 Select on Map
                        </button>
                    </div>

                    <!-- Hidden inputs -->
                    <input type="hidden" name="latitude" id="latitude">
                    <input type="hidden" name="longitude" id="longitude">
                    <input type="hidden" name="radius" id="radiusHidden">
                    <input type="hidden" name="area" id="areaHidden">
                    <input type="hidden" name="capacity" id="capacityHidden">
                </div>

                <!-- Footer -->
                <div class="modal-footer border-0 d-flex justify-content-end gap-2 px-4 pb-4">
                    <button type="button" class="btn btn-secondary rounded-3 px-4 shadow-sm" data-bs-dismiss="modal" style="width: 150px; font-size: 18px; font-weight: 700px;">Cancel</button>
                    <button type="submit" class="btn rounded-3 px-4 shadow-sm" style="width: 150px; font-size: 18px; font-weight: 700px;background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white;">Save</button>
                </div>
            </form>
        </div>
    </div>
</div>

<!-- ======================== LOCATION REQUIRED MODAL ======================== -->
<div class="modal fade" id="locationRequiredModal" tabindex="-1" aria-hidden="true">
    <div class="modal-dialog modal-dialog-centered">
        <div class="modal-content border-warning">
            <div class="modal-header bg-warning text-dark">
                <h5 class="modal-title">Location Required</h5>
                <button type="button" class="btn-close" data-bs-dismiss="modal"></button>
            </div>
            <div class="modal-body">
                Please pick a location on the map before submitting the form.
            </div>
            <div class="modal-footer">
                <button type="button" class="btn btn-warning" data-bs-dismiss="modal">OK</button>
            </div>
        </div>
    </div>
</div>

<!-- ======================== MAP MODAL ======================== -->
<div class="modal fade" id="mapModal" tabindex="-1" aria-hidden="true">
    <div class="modal-dialog modal-xl modal-dialog-centered"><!-- mas wide para kita map -->
        <div class="modal-content border-0 shadow-lg rounded-3 overflow-hidden">
            <!-- Header -->
            <div class="modal-header text-white" style="background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white;">
                <h5 class="modal-title fw-bold">
                    📍 Select Location
                </h5>
                <button type="button" class="btn-close btn-close-white" data-bs-dismiss="modal"></button>
            </div>
            
            <!-- Body -->
            <div class="modal-body p-0 position-relative" style="height: 70vh;">
                <!-- Floating Search -->
                <div id="customSearchBox"
                    class="shadow-lg bg-white rounded-pill px-3 py-2 d-flex align-items-center"
                    style="position: absolute; top: 15px; left: 50%; transform: translateX(-50%); z-index: 1000; width: 70%; max-width: 500px;">
                    <i class="bi bi-search text-muted me-2"></i>
                    <input type="text" id="mapSearchInput" class="form-control border-0 shadow-none"
                        placeholder="Search location...">
                </div>

                <!-- Leaflet Map -->
                <div id="map" style="height: 100%; width: 100%;"></div>
            </div>
            
            <!-- Footer -->
            <div class="modal-footer bg-light d-flex justify-content-between">
                <button type="button" class="btn btn-danger rounded-pill px-4" data-bs-dismiss="modal" style="font-size: 18px; width: 150px;">
                    Cancel
                </button>
                <button type="button" id="confirmMapLocation" class="btn btn-success rounded-pill px-4 shadow-sm" style="font size: 18px; width: 220px;">
                    Confirm Location
                </button>
            </div>
        </div>
    </div>
</div>

<div class="modal fade" id="successModal" tabindex="-1" aria-hidden="true">
    <div class="modal-dialog modal-dialog-centered">
        <div class="modal-content border-0 shadow-lg rounded-4">
            <div class="modal-header bg-success text-white rounded-top-4">
                <h5 class="modal-title fw-bold">✅ Success</h5>
                <button type="button" class="btn-close" data-bs-dismiss="modal"></button>
            </div>
            <div class="modal-body text-center p-4">
                <i class="bi bi-check-circle-fill text-success" style="font-size:3rem;"></i>
                <p class="mt-3 mb-0 fw-semibold">Evacuation Center added successfully!</p>
            </div>
            <div class="modal-footer">
                <button type="button" class="btn btn-success" data-bs-dismiss="modal">OK</button>
            </div>
        </div>
    </div>
</div>

<!-- ======================== VIEW MODAL ======================== -->
<div class="modal fade" id="evacuationModal" tabindex="-1" aria-labelledby="evacuationModalLabel" aria-hidden="true">
    <div class="modal-dialog modal-xl modal-dialog-centered evacuation-modal-dialog">
        <div class="modal-content evacuation-modal-content">
            <!-- Modal Header -->
            <div class="modal-header evacuation-modal-header">
                <div>
                    <h2 class="modal-title fs-2 fw-bold mb-1" id="evacuationModalLabel">Evacuation Center Details</h2>
                    <p class="mb-0 opacity-75">Real-time monitoring and management</p>
                </div>
                <button type="button" class="btn-close btn-close-white fs-3 evacuation-close-btn" data-bs-dismiss="modal" aria-label="Close"></button>
            </div>

            <!-- Modal Body -->
            <div class="modal-body evacuation-modal-body">
                <!-- Normal View -->
                <div id="normalView">
                    <!-- Header Section with Map -->
                    <div class="row g-0 p-4 border-bottom">
                        <div class="col-lg-8">
                            <h3 class="display-6 fw-bold text-dark mb-3">Barangay Central Elementary School</h3>
                            <p class="fs-6 text-muted mb-4">📍 123 Main Street, Barangay Central, City</p>
                            <div class="row g-3">
                                <div class="col-md-4">
                                    <div class="stat-card capacity-card">
                                        <div class="fw-semibold text-success">Capacity</div>
                                        <div class="display-7 fw-bold text-success" style="font-size: 30px;">500</div>
                                    </div>
                                </div>
                                <div class="col-md-4">
                                    <div class="stat-card current-card">
                                        <div class="fw-semibold text-primary">Current</div>
                                        <div class="display-7 fw-bold text-primary" style="font-size: 30px;">127</div>
                                    </div>
                                </div>
                                <div class="col-md-4">
                                    <div class="stat-card available-card">
                                        <div class="fw-semibold text-warning">Available</div>
                                        <div class="display-7 fw-bold text-warning" style="font-size: 30px;">373</div>
                                    </div>
                                </div>
                            </div>
                        </div>
                        
                        <!-- Small Map -->
                        <div class="col-lg-4 d-flex justify-content-end position-relative" style="height:200px;">
                            <div id="mapContainer" style=" height:100%; position:relative;">
                                <div id="viewMap"></div>
                                
                                <!-- Fullscreen button -->
                                <button type="button" 
                                        class="btn btn-sm btn-dark position-absolute fullscreen-btn"
                                        onclick="toggleFullscreenMap(true)">
                                    <i class="bi bi-arrows-fullscreen"></i>
                                </button>
                            </div>
                        </div>

                        <!-- Close button (fixed) -->
                        <button type="button" 
                                class="btn btn-danger fw-bold" 
                                style="display:none; position:fixed; top:100px; left:900px; z-index:10000; width: 150px;"
                                id="closeFullscreenMapBtn"
                                onclick="toggleFullscreenMap(false)">
                          <i class="bi bi-x-lg me-2"></i> Close Map
                        </button>

                        <!-- Evacuees Section -->
                        <hr class="mt-4">
                        <div class="p-4">

                            <div class="row align-items-center mb-2">
                                <div class="col-md-6">
                                    <h4 class="display-6 fw-bold text-dark mb-1">Evacuees List</h4>
                                    <p class="text-muted mb-0">Real-time tracking of all residents</p>
                                </div>
                                <div class="col-md-6">
                                    <div class="position-relative">
                                        <input type="text" id="searchInput" class="form-control form-control-lg search-box" placeholder="Search residents..." oninput="filterResidents()">
                                        <i class="bi bi-search position-absolute top-50 start-0 translate-middle-y ms-3 text-muted fs-5"></i>
                                    </div>
                                </div>
                            </div>

                            <!-- Table -->
                            <div class="residents-table">
                                <table class="table table-hover mb-0">
                                    <thead>
                                        <tr>
                                            <th>Name</th>
                                            <th>House Position</th>
                                            <th>Time In</th>
                                            <th>Status</th>
                                        </tr>
                                    </thead>
                                    <tbody id="residentsTableBody">
                                        <!-- Populated by JS -->
                                    </tbody>
                                </table>
                            </div>
                        </div>
                    </div>
                </div>
            </div>

            <!-- Modal Footer -->
            <div class="modal-footer evacuation-modal-footer">
                <button type="button" class="btn btn-danger fw-semibold modal-delete-btn">
                    <i class="bi bi-trash me-2"></i> Delete
                </button>
                <button type="button" class="btn btn-warning fw-semibold modal-edit-btn"  data-bs-toggle="modal" 
        data-bs-target="#editEvacuationModal">
                    <i class="bi bi-pencil me-2"></i> Edit
                </button>
            </div>
        </div>
    </div>
</div>


<!-- ======================== EDIT EVACUATION MODAL ======================== --> 
<div class="modal fade" id="editEvacuationModal" tabindex="-1" aria-hidden="true">
    <div class="modal-dialog modal-dialog-centered modal-lg">
        <div class="modal-content border-0 shadow-lg rounded-4 overflow-hidden" style="backdrop-filter: blur(12px); background: rgba(255,255,255,0.9);">
            <form id="editEvacuationForm" method="POST" enctype="multipart/form-data" action="../database/evacuation_update.php">
                <!-- Header -->
                <div class="modal-header border-0 text-white" 
                    style="background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
                    padding: 1.25rem 1.5rem;">
                    <h4 class="fw-bold mb-0">✏️ Edit Evacuation Center</h4>
                    <button type="button" class="btn-close btn-close-white shadow-none" data-bs-dismiss="modal"></button>
                </div>

                <!-- Body -->
                <div class="modal-body p-4">
                    <!-- Hidden ID -->
                    <input type="hidden" name="id" id="edit_id">

                    <!-- Top Section: Image + Info -->
                    <div class="row g-4">
                        <!-- Image Upload -->
                        <div class="col-md-5 d-flex justify-content-center">
                            <div id="editImageContainer" 
                                class="rounded-4 shadow-sm border d-flex align-items-center justify-content-center p-0 w-100 position-relative"
                                style="cursor:pointer; height:180px; background:#f4f6ff; overflow:hidden;">
                                
                                <img id="editImagePreview" 
                                    src="https://via.placeholder.com/600x400.png?text=Current+Image" 
                                    alt="Preview" 
                                    class="w-100 h-100" 
                                    style="object-fit:cover;">
                                
                                <input type="file" name="evacImage" id="editEvacImage" accept="image/*" hidden>
                                
                                <div class="overlay position-absolute top-0 start-0 w-100 h-100 d-flex align-items-center justify-content-center 
                                            bg-dark bg-opacity-50 text-white fw-semibold"
                                    style="opacity:0; transition:.3s;">
                                    Click to Change
                                </div>
                            </div>
                        </div>

                        <!-- Name + Address -->
                        <div class="col-md-7">
                            <div class="mb-3">
                                <label class="fw-semibold small text-muted">CENTER NAME</label>
                                <input type="text" name="name" id="edit_name" class="form-control form-control-lg rounded-3 shadow-sm" placeholder="Enter evacuation center name" required>
                            </div>
                            <div>
                                <label class="fw-semibold small text-muted">ADDRESS</label>
                                <input type="text" name="address" id="edit_address" class="form-control form-control-lg rounded-3 shadow-sm" placeholder="Enter address">
                            </div>
                        </div>
                    </div>

                    <!-- Length / Width / Space per Person -->
                    <div class="row g-3 mt-4">
                        <div class="col-md-4">
                            <label class="fw-semibold small text-muted">LENGTH (M)</label>
                            <input type="number" id="edit_length" name="length" class="form-control form-control-lg rounded-3 shadow-sm" placeholder="Enter length" required>
                        </div>
                        <div class="col-md-4">
                            <label class="fw-semibold small text-muted">WIDTH (M)</label>
                            <input type="number" id="edit_width" name="width" class="form-control form-control-lg rounded-3 shadow-sm" placeholder="Enter width" required>
                        </div>
                        <div class="col-md-4">
                            <label class="fw-semibold small text-muted">SPACE PER PERSON (SQM)</label>
                            <input type="number" id="edit_sqmPerPerson" name="sqmPerPerson" class="form-control form-control-lg rounded-3 shadow-sm" value="3" min="1" step="0.1" required>
                        </div>
                    </div>

                    <!-- Computed Analytics -->
                    <div class="mt-4">
                        <label class="fw-semibold small text-primary">📊 Computed Analytics</label>
                        <div class="row g-3 mt-2">
                            <!-- Radius -->
                            <div class="col-md-4">
                                <div class="card border-0 rounded-4 shadow-sm text-center h-100">
                                    <div class="card-body py-3">
                                        <div class="text-danger mb-1">
                                            <i class="bi bi-circle-half" style="font-size:1.6rem;"></i>
                                        </div>
                                        <div class="fw-semibold small text-muted">RADIUS (M)</div>
                                        <div class="fs-5 fw-bold text-dark" id="edit_radiusDisplay">-</div>
                                    </div>
                                </div>
                            </div>

                            <!-- Area -->
                            <div class="col-md-4">
                                <div class="card border-0 rounded-4 shadow-sm text-center h-100">
                                    <div class="card-body py-3">
                                        <div class="text-primary mb-1">
                                            <i class="bi bi-bounding-box" style="font-size:1.6rem;"></i>
                                        </div>
                                        <div class="fw-semibold small text-muted">AREA (SQM)</div>
                                        <div class="fs-5 fw-bold text-dark" id="edit_areaDisplay">-</div>
                                    </div>
                                </div>
                            </div>

                            <!-- Capacity -->
                            <div class="col-md-4">
                                <div class="card border-0 rounded-4 shadow-sm text-center h-100">
                                    <div class="card-body py-3">
                                        <div class="text-success mb-1">
                                            <i class="bi bi-people-fill" style="font-size:1.6rem;"></i>
                                        </div>
                                        <div class="fw-semibold small text-muted">MAX CAPACITY</div>
                                        <div class="fs-5 fw-bold text-dark" id="edit_capacityDisplay">-</div>
                                    </div>
                                </div>
                            </div>
                        </div>
                    </div>

                    <!-- Map Picker -->
                    <div class="mt-4">
                        <label class="fw-semibold small text-muted">Pick Location</label>
                        <button type="button" class="btn btn-outline-primary w-100 mt-2 rounded-3 shadow-sm" id="edit_openMapBtn">
                            📍 Select on Map
                        </button>
                    </div>

                    <!-- Hidden inputs -->
                    <input type="hidden" name="latitude" id="edit_latitude">
                    <input type="hidden" name="longitude" id="edit_longitude">
                    <input type="hidden" name="radius" id="edit_radiusHidden">
                    <input type="hidden" name="area" id="edit_areaHidden">
                    <input type="hidden" name="capacity" id="edit_capacityHidden">
                </div>

                <!-- Footer -->
                <div class="modal-footer border-0 d-flex justify-content-end gap-2 px-4 pb-4">
                    <button type="button" class="btn btn-secondary rounded-3 px-4 shadow-sm" data-bs-dismiss="modal" style="width: 150px; font-size: 18px; font-weight: 700px;">Cancel</button>
                    <button type="submit" class="btn rounded-3 px-4 shadow-sm" style="width: 220px; font-size: 18px; font-weight: 700px; background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white;">💾 Save Changes</button>
                </div>
            </form>
        </div>
    </div>
</div>

<!-- Delete Confirmation Modal -->
<div class="modal fade" id="deleteConfirmModal" tabindex="-1" aria-hidden="true">
  <div class="modal-dialog modal-dialog-centered">
    <div class="modal-content border-0 shadow">
      <div class="modal-header bg-danger text-white">
        <h5 class="modal-title">Confirm Deletion</h5>
        <button type="button" class="btn-close btn-close-white" data-bs-dismiss="modal"></button>
      </div>
      <div class="modal-body">
        <p id="deleteConfirmText" class="mb-0">
          Are you sure you want to delete this evacuation center?
        </p>
      </div>
      <div class="modal-footer">
        <button class="btn btn-secondary" data-bs-dismiss="modal">Cancel</button>
        <button id="confirmDeleteBtn" class="btn btn-danger">Delete</button>
      </div>
    </div>
  </div>
</div>

<!-- ======================== EDIT MAP MODAL ======================== -->
<div class="modal fade" id="editMapModal" tabindex="-1" aria-hidden="true">
    <div class="modal-dialog modal-xl modal-dialog-centered">
        <div class="modal-content border-0 shadow-lg rounded-3 overflow-hidden">
            <!-- Header -->
            <div class="modal-header text-white" style="background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white;">
                <h5 class="modal-title fw-bold">📍 Edit Location</h5>
                <button type="button" class="btn-close btn-close-white" data-bs-dismiss="modal"></button>
            </div>
            
            <!-- Body -->
            <div class="modal-body p-0 position-relative" style="height: 70vh;">
                <!-- Floating Search -->
                <div id="editSearchBox"
                    class="shadow-lg bg-white rounded-pill px-3 py-2 d-flex align-items-center"
                    style="position: absolute; top: 15px; left: 50%; transform: translateX(-50%); z-index: 1000; width: 70%; max-width: 500px;">
                    <i class="bi bi-search text-muted me-2"></i>
                    <input type="text" id="editMapSearchInput" class="form-control border-0 shadow-none"
                        placeholder="Search location...">
                </div>

                <!-- Leaflet Map -->
                <div id="editMap" style="height: 100%; width: 100%;"></div>
            </div>
            
            <!-- Footer -->
            <div class="modal-footer bg-light d-flex justify-content-between">
                <button type="button" class="btn btn-danger rounded-pill px-4" data-bs-dismiss="modal" style="font-size: 18px; width: 150px;">
                    Cancel
                </button>
                <button type="button" id="editConfirmMapLocation" class="btn btn-success rounded-pill px-4 shadow-sm" style="font-size: 18px; width: 220px;">
                    Confirm Location
                </button>
            </div>
        </div>
    </div>
</div>


<script src="../ajax/evacuation.js"></script>
<script>


// ================= FETCH EVACUATION DETAILS FOR EDIT =================
document.querySelectorAll(".modal-edit-btn").forEach((btn) => {
    btn.addEventListener("click", () => {
        const modalEl = document.getElementById("evacuationModal");
        const evacId = modalEl.getAttribute("data-evacuation-id");

        if (!evacId) {
            alert("⚠️ No evacuation center selected.");
            return;
        }

        // AJAX fetch to get details
        fetch(`../database/evacuation_get.php?id=${evacId}`)
            .then(res => res.json())
            .then(data => {
                if (data.error) {
                    alert("❌ " + data.error);
                    return;
                }

                // Populate form fields
                document.getElementById("edit_id").value = data.id;
                document.getElementById("edit_name").value = data.name;
                document.getElementById("edit_address").value = data.address;
                document.getElementById("edit_length").value = data.length;
                document.getElementById("edit_width").value = data.width;
                document.getElementById("edit_sqmPerPerson").value = data.sqm_per_person;
                document.getElementById("edit_latitude").value = data.latitude;
                document.getElementById("edit_longitude").value = data.longitude;
                document.getElementById("edit_radiusHidden").value = data.radius;
                document.getElementById("edit_areaHidden").value = data.area;
                document.getElementById("edit_capacityHidden").value = data.capacity;

                // Display analytics
                document.getElementById("edit_radiusDisplay").textContent = data.radius + " m";
                document.getElementById("edit_areaDisplay").textContent = data.area + " sqm";
                document.getElementById("edit_capacityDisplay").textContent = data.capacity;

                // Image preview
                const imgPath = data.image_path 
                    ? `../uploads/evacuation/${data.image_path}` 
                    : "https://via.placeholder.com/600x400.png?text=No+Image";
                document.getElementById("editImagePreview").src = imgPath;
            })
            .catch(err => {
                console.error(err);
                alert("⚠️ Failed to fetch evacuation details.");
            });
    });
});

document.addEventListener("DOMContentLoaded", () => {
    const lengthInput = document.getElementById("edit_length");
    const widthInput = document.getElementById("edit_width");
    const sqmInput = document.getElementById("edit_sqmPerPerson");

    const radiusDisplay = document.getElementById("edit_radiusDisplay");
    const areaDisplay = document.getElementById("edit_areaDisplay");
    const capacityDisplay = document.getElementById("edit_capacityDisplay");

    const radiusHidden = document.getElementById("edit_radiusHidden");
    const areaHidden = document.getElementById("edit_areaHidden");
    const capacityHidden = document.getElementById("edit_capacityHidden");

    function computeAnalytics() {
        const length = parseFloat(lengthInput.value) || 0;
        const width = parseFloat(widthInput.value) || 0;
        const sqmPerPerson = parseFloat(sqmInput.value) || 1;

        // ✅ Calculate area
        const area = length * width;

        // ✅ Calculate capacity
        const capacity = area > 0 ? Math.floor(area / sqmPerPerson) : 0;

        // ✅ Calculate radius (equivalent circular radius)
        const radius = area > 0 ? Math.sqrt(area / Math.PI) : 0;

        // ✅ Update displays
        areaDisplay.textContent = area > 0 ? area.toFixed(2) : "-";
        capacityDisplay.textContent = capacity > 0 ? capacity : "-";
        radiusDisplay.textContent = radius > 0 ? radius.toFixed(2) : "-";

        // ✅ Update hidden fields for DB save
        areaHidden.value = area.toFixed(2);
        capacityHidden.value = capacity;
        radiusHidden.value = radius.toFixed(2);
    }

    // Recompute whenever values change
    [lengthInput, widthInput, sqmInput].forEach(el => {
        el.addEventListener("input", computeAnalytics);
    });

    // Initial compute when modal opens (in case values are prefilled)
    const editModal = document.getElementById("editEvacuationModal");
    editModal.addEventListener("shown.bs.modal", computeAnalytics);
});


// ========== MAP (EDIT EVAC) ==========
let editMap, editMarker, editCircle, editLatLng = null, editMapInitialized = false;

document.getElementById("edit_openMapBtn").addEventListener("click", () => {
    const lat = parseFloat(document.getElementById("edit_latitude").value);
    const lng = parseFloat(document.getElementById("edit_longitude").value);
    const radius = parseFloat(document.getElementById("edit_radiusHidden").value) || 25;

    const mapModalEl = document.getElementById("editMapModal");
    const mapModal = new bootstrap.Modal(mapModalEl);
    mapModal.show();

    setTimeout(() => {
        if (!editMapInitialized) {
            editMap = L.map("editMap").setView([lat || 14.5995, lng || 120.9842], lat && lng ? 16 : 13);
            L.tileLayer("https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png", {
                attribution: "© OpenStreetMap",
            }).addTo(editMap);

            // kung may saved location, lagay agad marker & circle
            if (lat && lng) {
                editMarker = L.marker([lat, lng]).addTo(editMap);
                editCircle = L.circle([lat, lng], {
                    radius: radius,
                    color: "#2563eb",
                    weight: 2,
                    fillColor: "#3b82f6",
                    fillOpacity: 0.25,
                }).addTo(editMap);

                editLatLng = L.latLng(lat, lng);
            }

            // dblclick para baguhin marker
            editMap.on("dblclick", (e) => {
                const latlng = e.latlng;
                if (editMarker) editMap.removeLayer(editMarker);
                if (editCircle) editMap.removeLayer(editCircle);

                editMarker = L.marker(latlng).addTo(editMap);
                editCircle = L.circle(latlng, {
                    radius: radius,
                    color: "#2563eb",
                    weight: 2,
                    fillColor: "#3b82f6",
                    fillOpacity: 0.25,
                }).addTo(editMap);

                editLatLng = latlng;
            });

            editMapInitialized = true;
        } else {
            editMap.invalidateSize();
            if (lat && lng) editMap.setView([lat, lng], 16);
        }
    }, 300);
});

// search sa edit map
document.getElementById("editMapSearchInput").addEventListener("keydown", (e) => {
    if (e.key !== "Enter") return;
    e.preventDefault();

    const query = e.target.value.trim();
    if (!query) return;

    fetch(`https://nominatim.openstreetmap.org/search?format=json&q=${encodeURIComponent(query)}`)
        .then((res) => res.json())
        .then((results) => {
            if (!Array.isArray(results) || results.length === 0) {
                alert("❌ Location not found.");
                return;
            }
            const result = results[0];
            const latLng = L.latLng(parseFloat(result.lat), parseFloat(result.lon));
            editMap.setView(latLng, 16);

            if (editMarker) editMap.removeLayer(editMarker);
            if (editCircle) editMap.removeLayer(editCircle);

            editMarker = L.marker(latLng).addTo(editMap);
            editCircle = L.circle(latLng, {
                radius: parseFloat(document.getElementById("edit_radiusHidden").value) || 25,
                color: "#2563eb",
                weight: 2,
                fillColor: "#3b82f6",
                fillOpacity: 0.25,
            }).addTo(editMap);

            editLatLng = latLng;
        })
        .catch(() => alert("⚠️ Search failed. Try again."));
});

// confirm edit location
document.getElementById("editConfirmMapLocation").addEventListener("click", () => {
    if (editLatLng) {
        document.getElementById("edit_latitude").value = editLatLng.lat;
        document.getElementById("edit_longitude").value = editLatLng.lng;
    }
    bootstrap.Modal.getInstance(document.getElementById("editMapModal"))?.hide();
});

// ========== IMAGE CHANGE HANDLER (EDIT) ==========
const editImageContainer = document.getElementById("editImageContainer");
const editImageInput = document.getElementById("editEvacImage");
const editImagePreview = document.getElementById("editImagePreview");
const editOverlay = editImageContainer.querySelector(".overlay");

// kapag cliniclick yung container, trigger file input
editImageContainer.addEventListener("click", () => {
    editImageInput.click();
});

// hover effect para lumabas yung overlay
editImageContainer.addEventListener("mouseenter", () => {
    editOverlay.style.opacity = 1;
});
editImageContainer.addEventListener("mouseleave", () => {
    editOverlay.style.opacity = 0;
});

// kapag pumili ng bagong image, i-preview agad
editImageInput.addEventListener("change", (event) => {
    const file = event.target.files[0];
    if (file) {
        const reader = new FileReader();
        reader.onload = function(e) {
            editImagePreview.src = e.target.result;
        };
        reader.readAsDataURL(file);
    }
});
</script>