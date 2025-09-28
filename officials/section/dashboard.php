<?php
session_start();

// Check kung naka-login
if (!isset($_SESSION['user_id'])) {
    // Redirect sa login page
    header("Location: login_signup.php");
    exit;
}

include('sidebar.php');
?>


 <link rel="stylesheet" type="text/css" href="../css/dashboard.css">

 <!-- Navbar -->
<nav class="navbar">
  <div class="navbar-container">
    <div class="section-name">Dashboard</div>
    <div class="notification-wrapper" id="notifBtn">
      <i class="bi bi-bell-fill" style="font-size: 35px;"></i>
      <span class="badge-number">4</span>
    </div>
  </div>
</nav>  


<div class="main-content">
  <!-- Tabs (left) -->
  <div class="content-left">
    <div class="top-tabs">
      <button onclick="loadSection('overview', this)"><i class="bi bi-bar-chart-fill"></i> Overview</button>
      <button onclick="loadSection('residents', this)"><i class="bi bi-people-fill"></i> Residents</button>
      <button onclick="loadSection('services', this)"><i class="bi bi-bank"></i> Services</button>
      <button onclick="loadSection('emergency', this)"><i class="bi bi-exclamation-triangle-fill text-danger"></i> Emergency</button>
    </div>


  </div>

  <!-- Filter (right) -->
  <div class="content-right">
    <div class="filter-box">
      <div class="row g-3 align-items-center">
        <div class="col-md-4">
          <label class="form-label">Date From:</label>
          <input type="date" id="dateFrom" class="form-control" value="">
        </div>
        <div class="col-md-4">
          <label class="form-label">Date To:</label>
          <input type="date" id="dateTo" class="form-control" value="">
        </div>
        <div class="col-md-4 d-flex align-items-end justify-content-end">
          <button class="btn btn-refresh" style=" width: 170px; font-size: 18px;"><i class="bi bi-arrow-repeat" style="font-size: 24px;"></i> Refresh</button>
        </div>
      </div>
    </div>
  </div>
</div>

<!-- Dynamic Content dito papasok -->
<div id="tabContent" style="margin-left:105px; margin-right:20px; margin-top: 40px;"></div>

<script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
<script>
function loadSection(section, el){
  // ✅ Kunin values ng Date From at Date To
  let dateFrom = document.getElementById("dateFrom").value;
  let dateTo   = document.getElementById("dateTo").value;

  // ✅ Build URL na may params
  let url = "dashboardSection/" + section + ".php";
  if(dateFrom && dateTo){
    url += "?from=" + dateFrom + "&to=" + dateTo;
  }

  fetch(url)
    .then(res => res.text())
    .then(data => {
      const container = document.getElementById("tabContent");
      container.innerHTML = data;

      // Run scripts after load
      const scripts = container.querySelectorAll("script");
      scripts.forEach(scr => {
        const newScript = document.createElement("script");
        if (scr.src) {
          newScript.src = scr.src;
        } else {
          newScript.textContent = scr.textContent;
        }
        document.body.appendChild(newScript);
        document.body.removeChild(newScript);
      });

      // UI active state
      document.querySelectorAll(".top-tabs button").forEach(btn => btn.classList.remove("active"));
      if(el) el.classList.add("active");

      // ✅ Call initOverview kung Overview tab
      if(section === 'overview'){
        if(typeof initOverview === "function"){
          initOverview(dateFrom, dateTo); // pass filters
        }
      }
      if(section === 'residents'){
        if(typeof initResidents === "function"){
          initResidents(dateFrom, dateTo); // pass filters
        }
      }
      if(section === 'services'){
        if(typeof initServices === "function"){
          initServices(dateFrom, dateTo); // pass date filters
        }
      }


    });
}

// Default load Overview + set active
window.onload = () => {
  let firstBtn = document.querySelector(".top-tabs button");
  loadSection('overview', firstBtn);
  firstBtn.classList.add("active");
};

// ✅ Refresh button event
document.querySelector(".btn-refresh").addEventListener("click", () => {
  let activeBtn = document.querySelector(".top-tabs button.active");
  if(activeBtn){
    let section = activeBtn.textContent.trim().toLowerCase();
    loadSection(section, activeBtn);
  }
});
</script>
