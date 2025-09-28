<?php include 'sidebar.php'; ?>

<style>
html, body {
  margin: 0;
  padding: 0;
  overflow-x: hidden;
  background-color: #E6F0F7;
  font-family: 'Arial', sans-serif;
}

/* Header */
.header {
  background: rgba(55, 120, 194, 0.8933);
  padding: 15px;
  border-bottom-left-radius: 25px;
  border-bottom-right-radius: 25px;
  display: flex;
  justify-content: space-between;
  align-items: center;
  color: #fff;

  position: fixed;
  top: 0;
  left: 0;
  right: 0;
  z-index: 10;
  height: 80px;
}
.logo-text {
  font-size: 36px;
  font-weight: bold;
  margin-left: 50px;
}
.logo-text .g {
  color: yellow;
}

/* Content */
main.content {
  padding-top: 100px;
  padding-bottom: 80px;
  margin: 0 15px;
  position: fixed;
  top: 0;
  left: 0;
  right: 0;
  z-index: 10;
}

/* Profile header section */
.profile-header {
  background: #7A97C6;
  margin: 20px;
  padding: 20px;
  border-radius: 15px;
  text-align: center;
  color: #fff;
  box-shadow: 0 4px 6px rgba(0,0,0,0.2);
  height: 250px;
}
.profile-header img {
  width: 100px;
  height: 100px;
  border-radius: 50%;
  object-fit: cover;
}
.profile-header h4 {
  margin-top: 10px;
  font-size: 18px;
  font-weight: bold;
}

/* List items */
.profile-list {
  margin: 20px;
}
.profile-item {
  display: flex;
  justify-content: space-between;
  align-items: center;
  height: 65px;
  border-bottom: 1px solid #DCE3E8;
}
.profile-item-left {
  display: flex;
  align-items: center;
}
.profile-item-left i {
  margin-right: 15px;
  font-size: 18px;
  color: #0A3E8C;
}
.profile-item span {
  font-size: 15px;
  color: #333;
}
</style>

<body>

  <!-- Header -->
  <div class="header">
    <div class="d-flex align-items-center">
      <span class="logo-text">
        <span class="b">Pro</span><span class="g">file</span>
      </span>
    </div>
    <div>
    </div>
  </div>

  <!-- Content -->
  <main class="content">

    <!-- Profile Top -->
    <div class="profile-header">
      <img src="../assets/avatar.png" alt="Profile">
      <h4>Juan Dela Cruz</h4>
    </div>

    <!-- List Items -->
    <div class="profile-list mt-4">
      <div class="profile-item">
        <div class="profile-item-left">
          <i class="bi bi-envelope"></i>
          <span>juan.delacruz@exampleom</span>
        </div>
      </div>

      <div class="profile-item">
        <div class="profile-item-left">
          <i class="bi bi-person-circle"></i>
          <span>Profile Details</span>
        </div>
      </div>

      <div class="profile-item">
        <div class="profile-item-left">
          <i class="bi bi-gear"></i>
          <span>Settings</span>
        </div>
      </div>

      <div class="profile-item">
        <div class="profile-item-left">
          <i class="bi bi-box-arrow-right"></i>
          <span>Log Out</span>
        </div>
      </div>
    </div>
  </main>

  <link href="https://cdn.jsdelivr.net/npm/bootstrap-icons/font/bootstrap-icons.css" rel="stylesheet">

  <?php include 'tabbar.php'; ?>
