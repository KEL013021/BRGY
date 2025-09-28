document.addEventListener("DOMContentLoaded", function () {
  const sidebar = document.querySelector(".sidebar");

  const openDropdown = (dropdown, menu) => {
    dropdown.classList.add("open");
    menu.style.display = "block";
    menu.style.height = menu.scrollHeight + "px";
  };

  const closeDropdown = (dropdown, menu) => {
    dropdown.classList.remove("open");
    menu.style.height = "0px";
    setTimeout(() => {
      menu.style.display = "none";
    }, 300);
  };

  const toggleDropdown = (currentDropdown) => {
    const currentMenu = currentDropdown.querySelector(".custom-dropdown-menu");
    const isOpen = currentDropdown.classList.contains("open");

    // Close all other dropdowns
    document.querySelectorAll(".dropdown-container").forEach((dropdown) => {
      if (dropdown !== currentDropdown) {
        const menu = dropdown.querySelector(".custom-dropdown-menu");
        closeDropdown(dropdown, menu);
      }
    });

    // Toggle current
    if (isOpen) {
      closeDropdown(currentDropdown, currentMenu);
    } else {
      openDropdown(currentDropdown, currentMenu);
    }
  };

  document.querySelectorAll(".dropdown-container").forEach((dropdown) => {
    const menu = dropdown.querySelector(".custom-dropdown-menu");
    const toggleLink = dropdown.querySelector(".custom-dropdown-toggle");

    toggleLink.addEventListener("click", (e) => {
      e.preventDefault();
      if (!sidebar.classList.contains("collapsed")) {
        toggleDropdown(dropdown);
      }
    });

    dropdown.addEventListener("mouseenter", () => {
      if (sidebar.classList.contains("collapsed")) {
        openDropdown(dropdown, menu);
      }
    });

    dropdown.addEventListener("mouseleave", () => {
      if (sidebar.classList.contains("collapsed")) {
        closeDropdown(dropdown, menu);
      }
    });
  });

  document.querySelectorAll(".sidebar-toggler").forEach((btn) => {
    btn.addEventListener("click", () => {
      const isCollapsed = sidebar.classList.contains("collapsed");

      // Close dropdowns before toggling
      document.querySelectorAll(".dropdown-container").forEach((dropdown) => {
        const menu = dropdown.querySelector(".custom-dropdown-menu");
        closeDropdown(dropdown, menu);
      });

      // Toggle collapsed state
      sidebar.classList.toggle("collapsed", !isCollapsed);
    });
  });

  // Always collapse sidebar on initial load
  sidebar.classList.add("collapsed");

  // Auto-collapse on outside click
  document.addEventListener("click", function (event) {
    const isClickInsideSidebar = sidebar.contains(event.target);
    const isSidebarToggler = event.target.closest(".sidebar-toggler");

    if (!isClickInsideSidebar && !isSidebarToggler) {
      if (!sidebar.classList.contains("collapsed")) {
        sidebar.classList.add("collapsed");

        document.querySelectorAll(".dropdown-container").forEach((dropdown) => {
          const menu = dropdown.querySelector(".custom-dropdown-menu");
          closeDropdown(dropdown, menu);
        });
      }
    }
  });
});

