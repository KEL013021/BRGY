
<div class="emergency-cards">
<div class="row g-4 mb-4">

  <!-- Emergency Types -->
  <div class="col">
   <div class="card shadow-sm border-0 p-3" style="border-radius: 15px;">
      <h5 class="text-center">Emergency Types</h5>
      <canvas id="emergencyTypesChart" style="max-height: 350px;"></canvas>
    </div>
  </div>

  <!-- Evacuation Capacity -->
  <div class="col">
    <div class="card shadow-sm border-0 p-3" style="border-radius: 15px;">
      <h5 class="text-center">Evacuation Center Capacity</h5>
      <canvas id="evacuationChart" style="max-height: 350px;" ></canvas>
    </div>
  </div>

</div>

<div class="row g-4 mt-4">
  <div class="card shadow-sm border-0 p-3" style="border-radius: 15px;">
    <h5 class="text-center">Emergency Response Timeline</h5>
    <canvas id="emergencyTimelineChart" style="max-height: 400px;"></canvas>
  </div>
</div>
</div>
<script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
<script>
function initEmergencyDashboard(){
  fetch("../database/dashboard_fetch_emergency.php")
    .then(res => res.json())
    .then(data => {
      // Emergency Types
      new Chart(document.getElementById("emergencyTypesChart"), {
        type: "doughnut",
        data: {
          labels: Object.keys(data.types),
          datasets: [{
            data: Object.values(data.types),
            backgroundColor: ["#ef5350","#26c6da","#42a5f5","#66bb6a","#ffa726"]
          }]
        }
      });

      // Evacuation Centers
      new Chart(document.getElementById("evacuationChart"), {
        type: "bar",
        data: {
          labels: data.centers.map(c => c.name),
          datasets: [
            {
              label: "Capacity",
              data: data.centers.map(c => c.capacity),
              backgroundColor: "rgba(66,165,245,0.5)"
            },
            {
              label: "Current",
              data: data.centers.map(c => c.current),
              backgroundColor: "#ef5350"
            }
          ]
        },
        options: { responsive: true, scales: { y: { beginAtZero: true } } }
      });

      // Timeline
      new Chart(document.getElementById("emergencyTimelineChart"), {
        type: "line",
        data: {
          labels: ["Jan","Feb","Mar","Apr","May","Jun","Jul","Aug","Sep","Oct","Nov","Dec"],
          datasets: [{
            label: "Emergency Reports",
            data: data.timeline,
            borderColor: "#ef5350",
            backgroundColor: "rgba(239,83,80,0.2)",
            fill: true,
            tension: 0.4
          }]
        },
        options: { responsive: true, scales: { y: { beginAtZero: true } } }
      });
    });
}
initEmergencyDashboard();
</script>
