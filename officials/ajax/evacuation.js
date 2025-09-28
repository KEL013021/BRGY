  document.getElementById("reloadMap").addEventListener("click", function(){
      const iframe = document.getElementById("windyMap");
      // Force reload with forecast hidden
      iframe.src = "https://embed.windy.com/embed2.html?lat=12.8797&lon=121.7740&zoom=5&level=surface&overlay=wind";
    });

    document.getElementById("reloadMapFull").addEventListener("click", () => {
      const windyMap = document.getElementById("windyMapFull");
      // Refresh iframe by resetting src
      windyMap.src = windyMap.src;
    });

  document.addEventListener("DOMContentLoaded", function(){
    const urlParams = new URLSearchParams(window.location.search);
    if (urlParams.has("success")) {
      let modal = new bootstrap.Modal(document.getElementById("successModal"));
      modal.show();
    }
  });

    // IMAGE PREVIEW (safe-guarded)
  document.addEventListener("DOMContentLoaded", () => {
    const imageContainer = document.getElementById("imageContainer");
    const imageInput = document.getElementById("evacImage");
    const imagePreview = document.getElementById("imagePreview");

    if (imageContainer && imageInput && imagePreview) {
      const overlay = imageContainer.querySelector(".overlay");

      imageContainer.addEventListener("click", () => imageInput.click());

      imageInput.addEventListener("change", (e) => {
        const file = e.target.files[0];
        if (!file) return;
        const reader = new FileReader();
        reader.onload = (ev) => {
          imagePreview.src = ev.target.result;
          imagePreview.style.display = "block";
          if (overlay) overlay.style.display = "none";
          imageContainer.classList.add("active");
        };
        reader.readAsDataURL(file);
      });
    }
  });

  // ========== COMPUTATIONS & VALIDATION ==========

  function getNumber(id) {
    const el = document.getElementById(id);
    return el ? parseFloat(el.value) : NaN;
  }

  function inputsAreValid() {
    const L = getNumber("length");
    const W = getNumber("width");
    const S = getNumber("sqmPerPerson");
    return Number.isFinite(L) && L > 0 &&
           Number.isFinite(W) && W > 0 &&
           Number.isFinite(S) && S > 0;
  }

  function computeValues() {
    const length = getNumber("length");
    const width = getNumber("width");
    const sqmPerPerson = getNumber("sqmPerPerson");

    const radiusDisplay = document.getElementById("radiusDisplay");
    const areaDisplay = document.getElementById("areaDisplay");
    const capacityDisplay = document.getElementById("capacityDisplay");

    const radiusHidden = document.getElementById("radiusHidden");
    const areaHidden = document.getElementById("areaHidden");
    const capacityHidden = document.getElementById("capacityHidden");

    if (!inputsAreValid()) {
      [radiusDisplay, areaDisplay, capacityDisplay].forEach((el) => el && (el.innerText = "-"));
      [radiusHidden, areaHidden, capacityHidden].forEach((el) => el && (el.value = ""));
      return null;
    }

    const area = length * width;
    const diagonal = Math.sqrt(length ** 2 + width ** 2);
    const radius = diagonal / 2;
    const capacity = Math.floor(area / sqmPerPerson);

    if (radiusDisplay) radiusDisplay.innerText = radius.toFixed(2);
    if (areaDisplay) areaDisplay.innerText = area.toFixed(2);
    if (capacityDisplay) capacityDisplay.innerText = capacity;

    if (radiusHidden) radiusHidden.value = radius;
    if (areaHidden) areaHidden.value = area;
    if (capacityHidden) capacityHidden.value = capacity;

    return { radius, area, capacity };
  }

  function updateOpenMapButtonState() {
    const btn = document.getElementById("openMapBtn");
    if (!btn) return;
    const ok = inputsAreValid();
    btn.disabled = !ok;
    btn.classList.toggle("btn-secondary", !ok);
    btn.classList.toggle("btn-outline-primary", ok);
    btn.title = ok ? "" : "Fill Length, Width, and SQM per Person first";
  }

  // attach input listeners
  ["length", "width", "sqmPerPerson"].forEach((id) => {
    const el = document.getElementById(id);
    if (!el) return;
    el.addEventListener("input", () => {
      computeValues();
      updateOpenMapButtonState();
      if (radiusCircle && inputsAreValid()) {
        const { radius } = computeValues() || {};
        if (radius && radiusCircle) radiusCircle.setRadius(radius);
      }
    });
  });

  // initialize button state on load
  updateOpenMapButtonState();

  // ========== MAP (ADD EVAC) ==========

  let map, marker, radiusCircle, selectedLatLng = null, mapInitialized = false;

  const openMapBtn = document.getElementById("openMapBtn");
  if (openMapBtn) {
    openMapBtn.addEventListener("click", () => {
      const values = computeValues();
      if (!values) {
        showWarning("⚠️ Please fill Length, Width, and SQM per Person first.");
        return;
      }

      const mapModalEl = document.getElementById("mapModal");
      const mapModal = new bootstrap.Modal(mapModalEl);
      mapModal.show();

      setTimeout(() => {
        if (!mapInitialized) {
          map = L.map("map").setView([14.5995, 120.9842], 13);
          L.tileLayer("https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png", {
            attribution: "© OpenStreetMap",
          }).addTo(map);

          // locate user
          if (navigator.geolocation) {
            navigator.geolocation.getCurrentPosition((pos) => {
              const { latitude, longitude } = pos.coords;
              map.setView([latitude, longitude], 15);
            });
          }

          // dblclick = place marker
          map.on("dblclick", (e) => {
            const vals = computeValues();
            if (!vals) {
              showWarning("⚠️ Fill Length, Width, and SQM per Person first.");
              return;
            }

            const latlng = e.latlng;
            if (marker) map.removeLayer(marker);
            if (radiusCircle) map.removeLayer(radiusCircle);

            marker = L.marker(latlng).addTo(map);
            radiusCircle = L.circle(latlng, {
              radius: vals.radius,
              color: "#2563eb",
              weight: 2,
              fillColor: "#3b82f6",
              fillOpacity: 0.25,
            }).addTo(map);

            selectedLatLng = latlng;
          });

          mapInitialized = true;
        } else {
          map.invalidateSize();
        }
      }, 300);
    });
  }

  // search inside map
  const mapSearchInput = document.getElementById("mapSearchInput");
  if (mapSearchInput) {
    mapSearchInput.addEventListener("keydown", (e) => {
      if (e.key !== "Enter") return;
      e.preventDefault();

      const query = mapSearchInput.value.trim();
      if (!query) return;

      const vals = computeValues();
      if (!vals) {
        showWarning("⚠️ Fill Length, Width, and SQM per Person first.");
        return;
      }

      fetch(`https://nominatim.openstreetmap.org/search?format=json&q=${encodeURIComponent(query)}`)
        .then((res) => res.json())
        .then((results) => {
          if (!Array.isArray(results) || results.length === 0) {
            showWarning("❌ Location not found.");
            return;
          }
          const result = results[0];
          const latLng = L.latLng(parseFloat(result.lat), parseFloat(result.lon));
          map.setView(latLng, 16);

          if (marker) map.removeLayer(marker);
          if (radiusCircle) map.removeLayer(radiusCircle);

          marker = L.marker(latLng).addTo(map);
          radiusCircle = L.circle(latLng, {
            radius: vals.radius,
            color: "#2563eb",
            weight: 2,
            fillColor: "#3b82f6",
            fillOpacity: 0.25,
          }).addTo(map);

          selectedLatLng = latLng;
        })
        .catch(() => showWarning("⚠️ Search failed. Try again."));
    });
  }

  // confirm location
  const confirmBtn = document.getElementById("confirmMapLocation");
  if (confirmBtn) {
    confirmBtn.addEventListener("click", () => {
      if (selectedLatLng) {
        document.getElementById("latitude").value = selectedLatLng.lat;
        document.getElementById("longitude").value = selectedLatLng.lng;
      }
      bootstrap.Modal.getInstance(document.getElementById("mapModal"))?.hide();
    });
  }

  // require map location before submit
  const evacForm = document.getElementById("evacuationForm");
  if (evacForm) {
    evacForm.addEventListener("submit", (e) => {
      const lat = document.getElementById("latitude")?.value;
      const lng = document.getElementById("longitude")?.value;
      if (!lat || !lng) {
        e.preventDefault();
        new bootstrap.Modal(document.getElementById("locationRequiredModal")).show();
      }
    });
  }

    // ========== VIEW MAP CLEANUP ==========
    let viewMap, viewMarker, viewCircle;
    let residentMarkers = [];
    let routingControls = [];

    function clearViewMapLayers() {
        if (!viewMap) return;
        if (viewMarker) viewMap.removeLayer(viewMarker);
        if (viewCircle) viewMap.removeLayer(viewCircle);
        residentMarkers.forEach((m) => viewMap.removeLayer(m));
        routingControls.forEach((rc) => viewMap.removeControl(rc));
        residentMarkers = [];
        routingControls = [];
    }

    // ========== HELPER ALERT ==========
    function showWarning(msg) {
        const toast = document.createElement("div");
        toast.className = "toast align-items-center text-bg-warning border-0 show position-fixed bottom-0 end-0 m-3";
        toast.setAttribute("role", "alert");
        toast.innerHTML = `<div class="d-flex">
            <div class="toast-body">${msg}</div>
            <button type="button" class="btn-close btn-close-white me-2 m-auto" data-bs-dismiss="toast"></button>
        </div>`;
        document.body.appendChild(toast);
        setTimeout(() => toast.remove(), 4000);
    }

    // ========== BIND CARDS ==========
    document.querySelectorAll(".view-evacuation-card").forEach((card) => {
        card.addEventListener("click", () => {
            const id = card.getAttribute("data-id");
            const name = card.getAttribute("data-name");
            const address = card.getAttribute("data-address");
            const lat = parseFloat(card.getAttribute("data-lat"));
            const lng = parseFloat(card.getAttribute("data-lng"));

            // Open modal
            const modalEl = document.getElementById("evacuationModal");
            const modal = new bootstrap.Modal(modalEl);
            modal.show();

             // ✅ Save ID para magamit sa Edit at Delete
        modalEl.setAttribute("data-evacuation-id", id);


            // Fill modal fields
            modalEl.querySelector("h3.display-6").textContent = name || "Unnamed Center";
            modalEl.querySelector("p.fs-6.text-muted").textContent = `📍 ${address || "No address provided"}`;

            // Capacity
const capacityText = card.querySelector(".evacuation-capacity").innerText;
const capacityNumber = capacityText.replace("Capacity:", "")
                                   .replace(/Persons?/i, "")
                                   .trim();

modalEl.querySelector(".capacity-card .display-7").textContent = capacityNumber;

            // Init map
            setTimeout(() => {
                if (!viewMap) {
                    viewMap = L.map("viewMap").setView([lat, lng], 16);
                    L.tileLayer("https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png", {
                        attribution: "© OpenStreetMap",
                    }).addTo(viewMap);
                } else {
                    viewMap.setView([lat, lng], 16);
                    viewMap.invalidateSize();
                }

                clearViewMapLayers();

                viewMarker = L.marker([lat, lng]).addTo(viewMap);
                viewCircle = L.circle([lat, lng], {
                    radius: parseFloat(card.getAttribute("data-radius")) || 25,
                    color: "blue",
                    fillColor: "#3b82f6",
                    fillOpacity: 0.3,
                }).addTo(viewMap);

                // Fetch evacuees
                fetch(`../database/evacuees_location_get.php?evacuation_id=${id}`)
                    .then((res) => res.json())
                    .then((residents) => {
                        residents.forEach((r) => {
                            const resLat = parseFloat(r.latitude);
                            const resLng = parseFloat(r.longitude);
                            if (!Number.isFinite(resLat) || !Number.isFinite(resLng)) return;

                            const imgSrc = r.image_url && r.image_url !== "" 
                                ? r.image_url 
                                : "../image/Logo.png";

                            const residentIcon = L.divIcon({
                                className: "resident-marker",
                                html: `
                                <div style="display:flex; flex-direction:column; align-items:center; text-align:center;">
                                    <img src="${imgSrc}" style="width:30px; height:30px; border-radius:50%; margin-bottom:2px; object-fit:cover; border:2px solid #333;">
                                    <span style="
                                    font-size:12px; 
                                    color:black; 
                                    background:white; 
                                    padding:2px 6px; 
                                    border-radius:4px;
                                    white-space:nowrap;
                                    ">
                                    ${r.full_name || "Resident " + r.resident_id}
                                    </span>
                                </div>
                                `,
                                iconSize: [30, 40],
                                iconAnchor: [15, 40],
                            });

                            const residentMarker = L.marker([resLat, resLng], { icon: residentIcon }).addTo(viewMap);
                            residentMarkers.push(residentMarker);

                            // Routing line
                            const routingControl = L.Routing.control({
                                waypoints: [L.latLng(resLat, resLng), L.latLng(lat, lng)],
                                createMarker: () => null,
                                addWaypoints: false,
                                draggableWaypoints: false,
                                fitSelectedRoutes: false,
                                show: false,
                                lineOptions: { styles: [{ color: "green", weight: 4, opacity: 0.8 }] },
                            }).addTo(viewMap);

                            routingControls.push(routingControl);
                            routingControl.on("routeselected", () => {
                                document.querySelectorAll(".leaflet-routing-container").forEach((el) => el.remove());
                            });
                        });
                    });
            }, 300);
        });
    });

    // ========== FULLSCREEN TOGGLE ==========
    function toggleFullscreenMap(open = false) {
        const mapEl = document.getElementById("viewMap");
        const mapContainer = document.getElementById("mapContainer");
        const modalBody = document.querySelector("#evacuationModal .modal-body");
        const closeBtn = document.getElementById("closeFullscreenMapBtn");

        if (open) {
            modalBody.appendChild(mapEl);   // ilipat map sa modal-body
            mapEl.classList.add("fullscreen");
            closeBtn.style.display = "block";
        } else {
            mapContainer.appendChild(mapEl); // ibalik map sa container
            mapEl.classList.remove("fullscreen");
            closeBtn.style.display = "none";
        }

        // Ayusin map rendering
        setTimeout(() => {
            if (window.viewMap) {
                viewMap.invalidateSize();
                viewMap.setZoom(16);
            }
        }, 300);
    }

// ========== DELETE EVACUATION ==========
document.querySelector(".modal-delete-btn").addEventListener("click", () => {
    const modalEl = document.getElementById("evacuationModal");
    const centerName = modalEl.querySelector("h3.display-6").textContent;
    const evacuationId = modalEl.getAttribute("data-evacuation-id");

    if (!evacuationId) {
        showWarning("❌ No evacuation center selected.");
        return;
    }

    // Update confirmation text dynamically
    document.getElementById("deleteConfirmText").textContent = 
        `Are you sure you want to delete "${centerName}"?`;

    // Store ID inside confirm button (temporary attribute)
    document.getElementById("confirmDeleteBtn").setAttribute("data-id", evacuationId);

    // Show confirmation modal
    const confirmModal = new bootstrap.Modal(document.getElementById("deleteConfirmModal"));
    confirmModal.show();
});

// ========== HANDLE CONFIRM DELETE ==========
document.getElementById("confirmDeleteBtn").addEventListener("click", () => {
    const confirmBtn = document.getElementById("confirmDeleteBtn");
    const evacuationId = confirmBtn.getAttribute("data-id");
    const modalEl = document.getElementById("evacuationModal");
    const centerName = modalEl.querySelector("h3.display-6").textContent;

    fetch("../database/evacuation_delete.php", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ id: evacuationId })
    })
    .then(res => res.json())
    .then(data => {
        if (data.success) {
            showWarning(`✅ Evacuation center "${centerName}" deleted.`);

            // Close both modals
            bootstrap.Modal.getInstance(document.getElementById("deleteConfirmModal")).hide();
            bootstrap.Modal.getInstance(modalEl).hide();

            // Remove card from UI
            document.querySelector(`.view-evacuation-card[data-id="${evacuationId}"]`)?.remove();
        } else {
            showWarning("❌ Failed to delete evacuation center.");
        }
    })
    .catch(err => {
        console.error(err);
        showWarning("⚠️ Server error while deleting.");
    });
});
    