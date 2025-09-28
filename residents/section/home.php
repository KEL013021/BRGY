<?php 
session_start();
include 'sidebar.php';
include '../database/config.php';

// ✅ Check kung naka-login
if (!isset($_SESSION['user_id'])) {
    header("Location: ../../BRGYGO/login_signup.php");
    exit;
}

$user_id = $_SESSION['user_id'];
?>
<link rel="stylesheet" type="text/css" href="../css/home.css">

<style>
  /* ✅ Scrollable announcements */
  #announcement-container {
    max-height: 60vh; /* hanggang 60% ng screen height */
    overflow-y: auto;
    padding-right: 5px;
  }

  /* ✅ Image adjustments for mobile */
  .announcement-card img {
    max-width: 100%;
    height: auto;
    border-radius: 8px;
    cursor: pointer;
    transition: transform 0.2s ease;
  }

  .announcement-card img:hover {
    transform: scale(1.02);
  }

  /* ✅ Fullscreen modal */
  .img-modal {
    display: none; 
    position: fixed;
    z-index: 2000;
    padding-top: 60px;
    left: 0;
    top: 0;
    width: 100%; 
    height: 100%; 
    overflow: auto;
    background-color: rgba(0,0,0,0.9);
  }

  .img-modal-content {
    margin: auto;
    display: block;
    max-width: 95%;
    max-height: 85vh;
  }

  .img-modal-close {
    position: absolute;
    top: 20px;
    right: 30px;
    color: #fff;
    font-size: 35px;
    font-weight: bold;
    cursor: pointer;
  }
  #imgModalContent {
  max-height: 80vh;
  object-fit: contain;
}
</style>


  <!-- Header -->
  <div class="header">
    <div class="d-flex align-items-center">
      <span class="logo-text">
        <span class="b">BRGY</span><span class="g">GO</span>
      </span>
    </div>

    <div>
      <a href="profile.php" class="btn btn-light btn-sm rounded-circle" style="width: 45px; height: 45px;">
        <i class="bi bi-person text-primary"></i>
      </a>
    </div>
  </div>

  <!-- ✅ Content with padding -->
  <main class="content">
    <!-- Welcome -->
    <div class="welcome-box">
      <div>
        <strong>WELCOME!</strong><br>
        BrgyGo will help you today!
      </div>
      
    </div>

    <!-- Announcements -->
    <div id="announcement-container">
      <p class="text-center text-dark mt-4">Loading announcements...</p>
    </div>
  </main>

  <!-- ✅ Image Modal (Bootstrap) -->
<div class="modal fade" id="imgModal" tabindex="-1" aria-hidden="true">
  <div class="modal-dialog modal-dialog-centered modal-lg"> 
    <div class="modal-content bg-transparent border-0 shadow-none">
      <div class="modal-body text-center">
        <img id="imgModalContent" src="" class="img-fluid rounded shadow" alt="Full Image">
      </div>
    </div>
  </div>
</div>

  <link href="https://cdn.jsdelivr.net/npm/bootstrap-icons/font/bootstrap-icons.css" rel="stylesheet">
  <?php include 'tabbar.php'; ?>

  <!-- ✅ Script para auto-fetch ng announcements -->
  <script>
  function fetchAnnouncements() {
    fetch('../database/announcement_fetch.php')
      .then(response => response.json())
      .then(data => {
        let container = document.getElementById('announcement-container');
        if (data.length === 0) {
          container.innerHTML = '<p class="text-center text-dark mt-4">No announcements available.</p>';
        } else {
          let html = '';
          data.forEach(item => {
            html += `
              <div class="announcement-card mb-3">
                <h5>${item.title}</h5>
                ${item.image ? `<img src="${item.image}" alt="Announcement Image" onclick="openImageModal('${item.image}')">` : ''}
                <p>${item.content.replace(/\n/g, '<br>')}</p>
                <div class="posted-on">Posted on: ${new Date(item.date_posted).toLocaleString()}</div>
              </div>
            `;
          });
          container.innerHTML = html;
        }
      })
      .catch(err => {
        console.error("Error fetching announcements:", err);
      });
  }

  // ✅ unang load
  fetchAnnouncements();

  // ✅ auto-refresh every 10 seconds
  setInterval(fetchAnnouncements, 10000);

  // ✅ Image Modal functions
 document.addEventListener("click", function(e) {
  if (e.target.tagName === "IMG" && e.target.closest(".announcement-card")) {
    let modalImg = document.getElementById("imgModalContent");
    modalImg.src = e.target.src;
    let modal = new bootstrap.Modal(document.getElementById('imgModal'));
    modal.show();
  }
});

  </script>
