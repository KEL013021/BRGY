<div class="overview-cards">
  <div class="row g-4">

    <!-- Total Residents -->
    <div class="col">
      <div class="card shadow-sm border-0 text-center p-3" 
           style="border-radius: 15px; background: linear-gradient(135deg, #42a5f5, #1e88e5); color: white;">
        <i class="bi bi-people-fill" style="font-size: 40px;"></i>
        <h5 class="mt-2">Residents</h5>
        <h2 id="totalResidents">0</h2>
      </div>
    </div>

    <!-- Service Requests -->
    <div class="col">
      <div class="card shadow-sm border-0 text-center p-3" 
           style="border-radius: 15px; background: linear-gradient(135deg, #66bb6a, #388e3c); color: white;">
        <i class="bi bi-bank" style="font-size: 40px;"></i>
        <h5 class="mt-2">Service Requests</h5>
        <h2 id="totalRequests">0</h2>
      </div>
    </div>

    <!-- Emergency Reports -->
    <div class="col">
      <div class="card shadow-sm border-0 text-center p-3" 
           style="border-radius: 15px; background: linear-gradient(135deg, #ef5350, #c62828); color: white;">
        <i class="bi bi-exclamation-triangle-fill" style="font-size: 40px;"></i>
        <h5 class="mt-2">Emergencies</h5>
        <h2 id="totalEmergencies">0</h2>
      </div>
    </div>

    <!-- Evacuation Centers -->
    <div class="col">
      <div class="card shadow-sm border-0 text-center p-3" 
           style="border-radius: 15px; background: linear-gradient(135deg, #ffa726, #f57c00); color: white;">
        <i class="bi bi-house-door-fill" style="font-size: 40px;"></i>
        <h5 class="mt-2">Evacuation Centers</h5>
        <h2 id="totalCenters">0</h2>
      </div>
    </div>

    <!-- Announcements -->
    <div class="col">
      <div class="card shadow-sm border-0 text-center p-3" 
           style="border-radius: 15px; background: linear-gradient(135deg, #ab47bc, #6a1b9a); color: white;">
        <i class="bi bi-megaphone-fill" style="font-size: 40px;"></i>
        <h5 class="mt-2">Announcements</h5>
        <h2 id="totalAnnouncements">0</h2>
      </div>
    </div>

  </div>

  <div class="row g-4 mt-4 mb-4">

    <!-- Population Demographics -->
    <div class="col">
      <div class="card shadow-sm border-0 p-3" style="border-radius: 15px; max-height: 450px; align-items: center;">
        <h5 class="text-center">Population Demographics</h5>
        <canvas id="populationChart" style=" max-height: 350px; max-width: 450px;"></canvas>
      </div>
    </div>

    <!-- Service Request Status -->
    <div class="col">
      <div class="card shadow-sm border-0 p-3" style="border-radius: 15px; max-height: 450px; align-items: center;">
        <h5 class="text-center">Service Request Status</h5>
        <canvas id="serviceChart" style=" max-height: 350px; max-width: 450px;"></canvas>
      </div>
    </div>

  </div>
  
  <!-- Monthly Activity Overview -->
  <div class="card shadow-sm border-0 p-3 mb-4" style="border-radius: 15px; max-height: 500px;">
    <h5 class="text-center">Monthly Activity Overview</h5>
    <canvas id="activityChart" style="max-height: 450px;"></canvas>
  </div>
</div>


<script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
<script>
function initOverview(from = null, to = null){
  function loadCardsAndCharts() {
    // Build URL with filters kung meron
    let url = "../database/dashboard_fetch_all.php";
    if(from && to){
      url += "?from=" + from + "&to=" + to;
    }

    console.log("📌 Fetching dashboard data:", url);

    fetch(url)
      .then(res => res.json())
      .then(data => {
        console.log("✅ Dashboard data:", data);

        // Update cards
        document.getElementById("totalResidents").innerText     = data.overview?.totalResidents ?? 0;
        document.getElementById("totalRequests").innerText      = data.overview?.totalRequests ?? 0;
        document.getElementById("totalEmergencies").innerText   = data.overview?.emergencyReports ?? 0;
        document.getElementById("totalCenters").innerText       = data.overview?.evacuationCenters ?? 0;
        document.getElementById("totalAnnouncements").innerText = data.overview?.announcements ?? 0;

        // Destroy old charts
        if (window.populationChartObj) window.populationChartObj.destroy();
        if (window.serviceChartObj) window.serviceChartObj.destroy();
        if (window.activityChartObj) window.activityChartObj.destroy();

        // Charts...
        window.populationChartObj = new Chart(document.getElementById("populationChart"), {
          type: "doughnut",
          data: {
            labels: data.demographics?.labels || ["0-17 years", "18-35 years", "36-55 years", "56+ years"],
            datasets: [{
              data: data.demographics?.data || [0,0,0,0],
              backgroundColor: ["#ef5350", "#26c6da", "#42a5f5", "#90a4ae"]
            }]
          },
          options: { responsive: true, cutout: "60%" }
        });

        window.serviceChartObj = new Chart(document.getElementById("serviceChart"), {
          type: "pie",
          data: {
            labels: data.requestStatus?.labels || [],
            datasets: [{
              data: data.requestStatus?.data || [0,0,0,0],
              backgroundColor: ["#ffca28", "#29b6f6", "#26a69a", "#ec407a"]
            }]
          },
          options: { responsive: true }
        });

        window.activityChartObj = new Chart(document.getElementById("activityChart"), {
          type: "line",
          data: {
            labels: data.monthlyActivity?.labels || ["Jan","Feb","Mar","Apr","May","Jun","Jul","Aug","Sep","Oct","Nov","Dec"],
            datasets: [
              {
                label: "Service Requests",
                data: data.monthlyActivity?.requests || Array(12).fill(0),
                borderColor: "#5c6bc0",
                backgroundColor: "rgba(92,107,192,0.2)",
                fill: true,
                tension: 0.4
              },
              {
                label: "Emergency Reports",
                data: data.monthlyActivity?.emergencies || Array(12).fill(0),
                borderColor: "#ef5350",
                backgroundColor: "rgba(239,83,80,0.2)",
                fill: false,
                tension: 0.4
              },
              {
                label: "Announcements",
                data: data.monthlyActivity?.announcements || Array(12).fill(0),
                borderColor: "#26c6da",
                backgroundColor: "rgba(38,198,218,0.2)",
                fill: false,
                tension: 0.4
              }
            ]
          },
          options: {
            responsive: true,
            plugins: { legend: { position: "top" } },
            scales: { y: { beginAtZero: true } }
          }
        });
      })
      .catch(err => console.error("❌ Error loading dashboard:", err));
  }

  // Initial load
  loadCardsAndCharts();
}

</script>
