document.addEventListener("DOMContentLoaded", function () {
  const sidebar = document.querySelector(".sidebar");
  const menuToggle = document.getElementById("menuToggle");

  // ✅ Start: sidebar closed + hamburger visible
  sidebar.classList.remove("active");
  menuToggle.classList.add("show-with-effect");

  // ✅ Toggle sidebar
  if (menuToggle) {
    menuToggle.addEventListener("click", () => {
      if (sidebar.classList.contains("active")) {
        // Close sidebar
        sidebar.classList.remove("active");
        menuToggle.classList.remove("hide-with-effect");
        menuToggle.classList.add("show-with-effect");
      } else {
        // Open sidebar
        sidebar.classList.add("active");
        menuToggle.classList.remove("show-with-effect");
        menuToggle.classList.add("hide-with-effect");
      }
    });
  }

  // ✅ Close sidebar when clicking outside (mobile only)
  document.addEventListener("click", function (event) {
    const isClickInsideSidebar = sidebar.contains(event.target);
    const isHamburger = event.target.closest("#menuToggle");

    if (!isClickInsideSidebar && !isHamburger) {
      if (sidebar.classList.contains("active")) {
        sidebar.classList.remove("active");
        menuToggle.classList.remove("hide-with-effect");
        menuToggle.classList.add("show-with-effect");
      }
    }
  });

  // ✅ Dropdown toggle logic
  document.querySelectorAll(".dropdown-container").forEach((dropdown) => {
    const toggleLink = dropdown.querySelector(".custom-dropdown-toggle");
    const menu = dropdown.querySelector(".custom-dropdown-menu");

    toggleLink.addEventListener("click", (e) => {
      e.preventDefault();

      const isOpen = dropdown.classList.contains("open");

      // Close all other dropdowns
      document.querySelectorAll(".dropdown-container.open").forEach((openDropdown) => {
        if (openDropdown !== dropdown) {
          openDropdown.classList.remove("open");
          openDropdown.querySelector(".custom-dropdown-menu").style.height = "0px";
        }
      });

      if (isOpen) {
        // Close current
        dropdown.classList.remove("open");
        menu.style.height = "0px";
      } else {
        // Open current
        dropdown.classList.add("open");
        menu.style.height = menu.scrollHeight + "px";
      }
    });
  });
});
