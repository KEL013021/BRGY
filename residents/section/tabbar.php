<style>
  .tab-bar {
   position: fixed;
  bottom: 0;
  left: 0;
  right: 0;
  z-index: 10;
    width: 100%;
    background: rgba(55, 120, 194, 0.85); /* semi-transparent */
    backdrop-filter: blur(10px); /* ✅ glass effect */
    display: flex;
    justify-content: space-around;
    padding: 10px 0;
    border-top: 1px solid rgba(255, 255, 255, 0.2);

    /* ✅ Safe area (iOS/Android) */
    padding-bottom: max(12px, env(safe-area-inset-bottom));
    box-shadow: 0 -4px 15px rgba(0, 0, 0, 0.2);
  }

  .tab-item {
    color: white;
    text-decoration: none;
    font-size: 12px;
    display: flex;
    flex-direction: column;
    align-items: center;
    flex: 1;
    transition: all 0.3s ease;
    position: relative;
  }

  .tab-item i {
    font-size: 22px;
    margin-bottom: 4px;
    transition: 0.3s;
  }

  /* Hover effect */
  .tab-item:hover i {
    transform: scale(1.2);
    color: #FFD700;
  }

  /* Active tab */
  .tab-item.active {
    color: #FFD700;
    font-weight: bold;
  }

  .tab-item.active i {
    color: #FFD700;
    transform: scale(1.2);
  }

  /* Active underline highlight */
  .tab-item.active::after {
    content: "";
    position: absolute;
    bottom: -2px;
    width: 25%;
    height: 3px;
    border-radius: 2px;
    background: #FFD700;
  }

  body {
    /* ✅ Para hindi matakpan content */
    padding-bottom: calc(70px + env(safe-area-inset-bottom));
    background: #f9f9f9;
  }
</style>

<!-- tabbar.php -->
<div class="tab-bar">
  <a href="documents.php" class="tab-item <?php echo basename($_SERVER['PHP_SELF']) == 'documents.php' ? 'active' : ''; ?>">
    <i class="bi bi-file-earmark-text"></i>
    <span>Document</span>
  </a>

  <a href="evacuation.php" class="tab-item <?php echo basename($_SERVER['PHP_SELF']) == 'evacuation.php' ? 'active' : ''; ?>">
    <i class="bi bi-building"></i>
    <span>Evacuation</span>
  </a>

  <a href="home.php" class="tab-item <?php echo basename($_SERVER['PHP_SELF']) == 'home.php' ? 'active' : ''; ?>">
    <i class="bi bi-house"></i>
    <span>Home</span>
  </a>

  <a href="emergency.php" class="tab-item <?php echo basename($_SERVER['PHP_SELF']) == 'emergency.php' ? 'active' : ''; ?>">
    <i class="bi bi-exclamation-triangle"></i>
    <span>Emergency</span>
  </a>

  <a href="profile.php" class="tab-item <?php echo basename($_SERVER['PHP_SELF']) == 'profile.php' ? 'active' : ''; ?>">
    <i class="bi bi-person"></i>
    <span>Profile</span>
  </a>
</div>
