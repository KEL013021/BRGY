<!-- Residents Cards -->
<div class="residents-cards">
  <div class="row g-4">

    <!-- Male Residents -->
    <div class="col">
      <div class="card shadow-sm border-0 text-center p-3" 
           style="border-radius: 15px; background: linear-gradient(135deg, #64b5f6, #1976d2); color: white;">
        <i class="bi bi-gender-male" style="font-size: 40px;"></i>
        <h5 class="mt-2">Male Residents</h5>
        <h2 id="maleResidents">0</h2>
      </div>
    </div>

    <!-- Female Residents -->
    <div class="col">
      <div class="card shadow-sm border-0 text-center p-3" 
           style="border-radius: 15px; background: linear-gradient(135deg, #f48fb1, #c2185b); color: white;">
        <i class="bi bi-gender-female" style="font-size: 40px;"></i>
        <h5 class="mt-2">Female Residents</h5>
        <h2 id="femaleResidents">0</h2>
      </div>
    </div>

    <!-- Senior Citizens -->
    <div class="col">
      <div class="card shadow-sm border-0 text-center p-3" 
           style="border-radius: 15px; background: linear-gradient(135deg, #a1887f, #4e342e); color: white;">
        <i class="bi bi-person-up" style="font-size: 40px;"></i>
        <h5 class="mt-2">Senior Citizens</h5>
        <h2 id="seniorCitizens">0</h2>
      </div>
    </div>

    <!-- PWD Members -->
    <div class="col">
      <div class="card shadow-sm border-0 text-center p-3" 
           style="border-radius: 15px; background: linear-gradient(135deg, #ffb74d, #ef6c00); color: white;">
        <i class="bi bi-universal-access" style="font-size: 40px;"></i>
        <h5 class="mt-2">PWD Members</h5>
        <h2 id="pwdMembers">0</h2>
      </div>
    </div>

    <!-- 4Ps Members -->
    <div class="col">
      <div class="card shadow-sm border-0 text-center p-3" 
           style="border-radius: 15px; background: linear-gradient(135deg, #ba68c8, #6a1b9a); color: white;">
        <i class="bi bi-people-fill" style="font-size: 40px;"></i>
        <h5 class="mt-2">4Ps Members</h5>
        <h2 id="fourPsMembers">0</h2>
      </div>
    </div>

  </div>

  <!-- Charts Section -->
<div class="row g-4 mt-4 mb-4">
  <!-- Age Distribution -->
  <div class="col">
    <div class="card shadow-sm border-0 p-3" style="border-radius: 15px; max-height: 400px;">
      <h5 class="fw-bold text-center">Age Distribution</h5>
      <canvas id="ageChart" style="max-height: 350px;"></canvas>
    </div>
  </div>

  <!-- Civil Status -->
  <div class="col">
    <div class="card shadow-sm border-0 p-3" style="border-radius: 15px; max-height: 400px; align-items: center;">
      <h5 class="fw-bold text-center">Civil Status</h5>
      <canvas id="statusChart" style="max-height: 350px;"></canvas>
    </div>
  </div>
</div>

<!-- Educational Attainment -->
<div class="row g-4 mt-4 mb-4">
  <div class="col">
    <div class="card shadow-sm border-0 p-3" style="border-radius: 15px; max-height: 500px;">
      <h5 class="fw-bold text-center">Educational Attainment</h5>
      <canvas id="educationChart" style="max-height: 450px;"></canvas>
    </div>
  </div>
</div>

<!-- Chart.js CDN -->
<script src="https://cdn.jsdelivr.net/npm/chart.js"></script>

<script>
function initResidents(from = null, to = null) {
  function loadResidents() {
    let url = "../database/dashboard_fetch_resident.php";
    if (from && to) {
      url += "?from=" + from + "&to=" + to;
    }

    console.log("📌 Fetching residents data:", url);

    fetch(url)
      .then(res => res.json())
      .then(data => {
        console.log("✅ Residents data:", data);

        // Update Cards
        document.getElementById("maleResidents").innerText   = data.cards?.male ?? 0;
        document.getElementById("femaleResidents").innerText = data.cards?.female ?? 0;
        document.getElementById("seniorCitizens").innerText  = data.cards?.senior ?? 0;
        document.getElementById("pwdMembers").innerText      = data.cards?.pwd ?? 0;
        document.getElementById("fourPsMembers").innerText   = data.cards?.fourPs ?? 0;

        // Destroy old charts kung meron
        if (window.ageChartObj) window.ageChartObj.destroy();
        if (window.statusChartObj) window.statusChartObj.destroy();
        if (window.educationChartObj) window.educationChartObj.destroy();

        // Age Distribution
        window.ageChartObj = new Chart(document.getElementById("ageChart"), {
          type: "bar",
          data: {
            labels: Object.keys(data.ageGroups || {}),
            datasets: [{
              label: "Population",
              data: Object.values(data.ageGroups || {}).map(v => Number(v)), // ensure numeric
              backgroundColor: "#64b5f6"
            }]
          },
          options: { 
            responsive: true,
            plugins: { legend: { display: true } },
            scales: {
              y: {
                beginAtZero: true,
                ticks: {
                  precision: 0 // show whole numbers (no decimals)
                }
              }
            }
          }
        });


        // Civil Status
        window.statusChartObj = new Chart(document.getElementById("statusChart"), {
          type: "doughnut",
          data: {
            labels: Object.keys(data.civilStatus || {}),
            datasets: [{
              data: Object.values(data.civilStatus || {}),
              backgroundColor: ["#ef5350", "#4db6ac", "#64b5f6", "#a5d6a7"]
            }]
          },
          options: { responsive: true, cutout: "70%", plugins: { legend: { position: "bottom" } } }
        });

        // Education
        window.educationChartObj = new Chart(document.getElementById("educationChart"), {
          type: "bar",
          data: {
            labels: Object.keys(data.educational_attainment || {}),
            datasets: [{
              label: "Count",
              data: Object.values(data.educational_attainment || {}).map(v => Number(v)), // ensure numeric
              backgroundColor: "#7e57c2"
            }]
          },
          options: { 
            responsive: true,
            plugins: { legend: { display: true } },
            scales: {
              y: {
                beginAtZero: true,
                ticks: {
                  precision: 0 // remove decimals, whole numbers lang
                }
              }
            }
          }
        });

      })
      .catch(err => console.error("❌ Error loading residents:", err));
  }

  // Initial load
  loadResidents();
}
</script>
