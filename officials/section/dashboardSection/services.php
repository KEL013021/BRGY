<!-- Residents Cards -->
<div class="services-cards">
<div class="row g-4 mt-4">
  <!-- Most Requested Services -->
  <div class="col">
    <div class="card shadow-sm border-0 p-3" style="border-radius: 15px;">
      <h5 class="fw-bold text-center">Most Requested Services</h5>
      <canvas id="servicesChart" style="max-height: 350px;"></canvas>
    </div>
  </div>

  <!-- Request Processing Time -->
  <div class="col">
    <div class="card shadow-sm border-0 p-3" style="border-radius: 15px;">
      <h5 class="fw-bold text-center">Request Processing Time</h5>
      <canvas id="processingChart" style="max-height: 350px;"></canvas>
    </div>
  </div>
</div>

<!-- Revenue Trends -->
<div class="row g-4 mt-4 mb-4">
  <div class="col">
    <div class="card shadow-sm border-0 p-3" style="border-radius: 15px;">
      <h5 class="fw-bold text-center">Service Revenue Trends</h5>
      <canvas id="revenueChart" style="max-height: 400px;"></canvas>
    </div>
  </div>
</div>

</div>

<script>
function initServices(dateFrom, dateTo){
  let url = "../database/dashboard_fetch_services.php";
  if(dateFrom && dateTo){
    url += `?from=${dateFrom}&to=${dateTo}`;
  }

  fetch(url)
  .then(res => res.json())
  .then(data => {
    // Destroy old charts kung meron
    if(window.servicesChartObj) window.servicesChartObj.destroy();
    if(window.processingChartObj) window.processingChartObj.destroy();
    if(window.revenueChartObj) window.revenueChartObj.destroy();

    // --- Clean data (convert strings -> numbers)
    const svcLabels = Object.keys(data.services || {});
    const svcData   = Object.values(data.services || {}).map(v => Number(v));
    const procData  = (data.processing || []).map(v => Number(v));
    const revData   = (data.revenue || []).map(v => Number(v));

    // 1️⃣ Most Requested Services
    window.servicesChartObj = new Chart(document.getElementById("servicesChart"), {
      type: "bar",
      data: {
        labels: svcLabels,
        datasets: [{
          label: "Requests",
          data: svcData,
          backgroundColor: "#42a5f5"
        }]
      },
      options: {
        responsive: true,
        scales: {
          y: {
            beginAtZero: true,
            ticks: { precision: 0 } // remove decimals
          }
        }
      }
    });

    // 2️⃣ Request Processing Time
    window.processingChartObj = new Chart(document.getElementById("processingChart"), {
      type: "line",
      data: {
        labels: ["Jan","Feb","Mar","Apr","May","Jun","Jul","Aug","Sep","Oct","Nov","Dec"],
        datasets: [{
          label: "Avg Days",
          data: procData,
          borderColor: "#ef5350",
          backgroundColor: "rgba(239,83,80,0.2)",
          fill: true,
          tension: 0.4
        }]
      },
      options: {
        responsive: true,
        scales: {
          y: {
            beginAtZero: true,
            ticks: { stepSize: 1 } // show whole numbers only
          }
        }
      }
    });

    // 3️⃣ Service Revenue Trends
    window.revenueChartObj = new Chart(document.getElementById("revenueChart"), {
      type: "bar",
      data: {
        labels: ["Jan","Feb","Mar","Apr","May","Jun","Jul","Aug","Sep","Oct","Nov","Dec"],
        datasets: [{
          label: "Revenue (₱)",
          data: revData,
          backgroundColor: "#26a69a"
        }]
      },
      options: {
        responsive: true,
        scales: {
          y: {
            beginAtZero: true,
            ticks: { precision: 0 } // force integers
          }
        }
      }
    });
  });
}
</script>
