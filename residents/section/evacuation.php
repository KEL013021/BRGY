<?php 
session_start();
include 'sidebar.php';
include '../database/config.php';


$user_id = $_SESSION['user_id'];

// Kunin resident info
$res = $conn->prepare("SELECT address_id FROM residents WHERE user_id=?");
$res->bind_param("i", $user_id);
$res->execute();
$resRow = $res->get_result()->fetch_assoc();

if (!$resRow) {
  die("No resident found");
}

$address_id = $resRow['address_id'];

$sql = "SELECT id, name, address, capacity, image_path, latitude, longitude 
        FROM evacuation_centers
        WHERE address_id = ?";
$stmt = $conn->prepare($sql);
$stmt->bind_param("i", $address_id);
$stmt->execute();
$result = $stmt->get_result();

$evacuationCenters = [];
while($row = $result->fetch_assoc()) {
  $evacuationCenters[] = $row;
}

?>
<link rel="stylesheet" href="https://unpkg.com/leaflet-routing-machine/dist/leaflet-routing-machine.css" />
<script src="https://unpkg.com/leaflet-routing-machine/dist/leaflet-routing-machine.js"></script>
<link rel="stylesheet" type="text/css" href="../css/evacuation.css">





  <!-- Header -->
  <div class="header">
    <div class="d-flex align-items-center">
      <span class="logo-text">
        <span class="b">Evacu</span><span class="g">ation</span>
      </span>
    </div>

    <div>
      <a href="profile.php" class="btn btn-light btn-sm rounded-circle" style="width: 45px; height: 45px;">
        <i class="bi bi-person text-primary"></i>
      </a>
    </div>
  </div>

  <!-- Content -->
  <main class="content">
  <?php foreach ($evacuationCenters as $center): ?>
    <div class="center-card" onclick="openMapModal(<?= $center['id'] ?>, <?= $center['latitude'] ?>, <?= $center['longitude'] ?>)">
      <img src="../../BRGYGO/uploads/evacuation/<?= htmlspecialchars($center['image_path']) ?>" alt="Evacuation Center">
      <h5><?= htmlspecialchars($center['name']) ?></h5>
      <div class="center-info">🏠 <?= htmlspecialchars($center['address']) ?></div>
      <div class="capacity">👥 Capacity: <?= htmlspecialchars($center['capacity']) ?></div>
    </div>
  <?php endforeach; ?>
</main>

<div class="modal fade" id="mapModal" tabindex="-1">
  <div class="modal-dialog modal-lg modal-dialog-centered">
    <div class="modal-content">
      <div class="modal-header">
        <h5 class="modal-title">Evacuation Map</h5>
        <button type="button" class="btn-close" data-bs-dismiss="modal"></button>
      </div>
      <div class="modal-body">
        <div id="map" style="height:400px;"></div>
      </div>
    </div>
  </div>
</div>


<!-- Leaflet & Routing Machine -->
<link rel="stylesheet" href="https://unpkg.com/leaflet/dist/leaflet.css"/>
<link rel="stylesheet" href="https://unpkg.com/leaflet-routing-machine/dist/leaflet-routing-machine.css"/>
<script src="https://unpkg.com/leaflet/dist/leaflet.js"></script>
<script src="https://unpkg.com/leaflet-routing-machine/dist/leaflet-routing-machine.js"></script>

<script>
let map, evacMarker, userMarker, routingControl, evacCircle;
let watchId = null;
let currentEvacId = null;

// 👉 Pag open ng modal
function openMapModal(evacId, evacLat, evacLng, evacRadius = 200) {
  currentEvacId = evacId;
  const modal = new bootstrap.Modal(document.getElementById('mapModal'));
  modal.show();

  setTimeout(() => {
    // Init map once
    if (!map) {
      map = L.map('map').setView([evacLat, evacLng], 15);

      L.tileLayer('https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png', {
        attribution: '© OpenStreetMap'
      }).addTo(map);
    } else {
      map.setView([evacLat, evacLng], 15);
    }

    setTimeout(() => map.invalidateSize(), 300);

    // Clear old markers/circles
    if (evacMarker) map.removeLayer(evacMarker);
    if (evacCircle) map.removeLayer(evacCircle);

    // Evacuation marker
    evacMarker = L.marker([evacLat, evacLng])
      .addTo(map)
      .bindPopup("📍 Evacuation Center")
      .openPopup();

    // Evacuation radius
    evacCircle = L.circle([evacLat, evacLng], {
      radius: evacRadius,
      color: "green",
      fillColor: "#90EE90",
      fillOpacity: 0.3
    }).addTo(map);

    // ✅ Start live tracking
    startTracking(evacId, evacLat, evacLng, evacRadius);
  }, 400);
}

// 👉 Start tracking user location
function startTracking(evacId, evacLat, evacLng, evacRadius) {
  if (!navigator.geolocation) {
    alert("❌ Geolocation not supported.");
    return;
  }

  // stop previous watch
  if (watchId) navigator.geolocation.clearWatch(watchId);

  watchId = navigator.geolocation.watchPosition(
    pos => {
      const lat = pos.coords.latitude;
      const lng = pos.coords.longitude;

      // update user marker
      if (userMarker) map.removeLayer(userMarker);
      userMarker = L.marker([lat, lng], {
        icon: L.icon({
          iconUrl: "https://cdn-icons-png.flaticon.com/512/149/149071.png",
          iconSize: [32, 32]
        })
      }).addTo(map).bindPopup("📌 You are here").openPopup();

      // ✅ Gawin routing control ONCE lang
      if (!routingControl) {
        routingControl = L.Routing.control({
          waypoints: [L.latLng(lat, lng), L.latLng(evacLat, evacLng)],
          lineOptions: { styles: [{ color: "#3778C2", weight: 5 }] },
          createMarker: () => null,
          addWaypoints: false,
          draggableWaypoints: false,
          fitSelectedRoutes: true
        }).addTo(map);
      } else {
        // Update lang yung waypoints
        routingControl.setWaypoints([
          L.latLng(lat, lng),
          L.latLng(evacLat, evacLng)
        ]);
      }

      // ✅ Save location sa DB
      fetch("../database/location_update.php", {
        method: "POST",
        headers: {"Content-Type": "application/x-www-form-urlencoded"},
        body: `evacuation_id=${evacId}&lat=${lat}&lng=${lng}`
      });

      // ✅ Check kung nasa loob ng radius
      const userLatLng = L.latLng(lat, lng);
      const evacLatLng = L.latLng(evacLat, evacLng);
      const distance = userLatLng.distanceTo(evacLatLng);

      if (distance <= evacRadius) {
        fetch("../database/add_evacuated.php", {
          method: "POST",
          headers: {"Content-Type": "application/x-www-form-urlencoded"},
          body: `evacuation_id=${evacId}&lat=${lat}&lng=${lng}`
        }).then(res => res.text()).then(data => {
          console.log("✅ Evacuee update:", data);
        });
      }
    },
    error => {
      alert("⚠️ Location access denied or unavailable.");
    },
    { enableHighAccuracy: true, timeout: 10000, maximumAge: 0 }
  );
}

// 👉 Stop tracking kapag na-close modal
document.getElementById('mapModal').addEventListener('hidden.bs.modal', () => {
  if (watchId) navigator.geolocation.clearWatch(watchId);

  if (currentEvacId) {
    fetch("../database/location_update.php", {
      method: "POST",
      headers: {"Content-Type": "application/x-www-form-urlencoded"},
      body: `evacuation_id=${currentEvacId}&clear=1`
    });
    currentEvacId = null;
  }

  // ❌ Huwag i-remove routing control, para hindi nagre-reset sa next open
  if (userMarker) map.removeLayer(userMarker);
});

</script>
<?php include 'tabbar.php'; ?>

