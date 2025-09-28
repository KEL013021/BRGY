let sortState = {}; // 0 = original, 1 = asc, 2 = desc
let originalRows = null;

function sortTable(columnIndex) {
    const tableBody = document.querySelector(".table-body");

    // Store original order once
    if (!originalRows) {
        originalRows = Array.from(tableBody.querySelectorAll("tr"));
    }

    // Cycle sort state: 0 -> 1 -> 2 -> 0
    sortState[columnIndex] = (sortState[columnIndex] || 0) + 1;
    if (sortState[columnIndex] > 2) sortState[columnIndex] = 0;

    let rows = Array.from(tableBody.querySelectorAll("tr"));

    if (sortState[columnIndex] === 0) {
        // Back to original order
        tableBody.innerHTML = "";
        originalRows.forEach(row => tableBody.appendChild(row));
    } 
    else {
        const direction = sortState[columnIndex] === 1 ? 1 : -1;

        rows.sort((a, b) => {
            const aText = a.querySelectorAll("td")[columnIndex].innerText.trim().toLowerCase();
            const bText = b.querySelectorAll("td")[columnIndex].innerText.trim().toLowerCase();

            if (!isNaN(aText) && !isNaN(bText)) {
                return (parseFloat(aText) - parseFloat(bText)) * direction;
            }
            return aText.localeCompare(bText) * direction;
        });

        tableBody.innerHTML = "";
        rows.forEach(row => tableBody.appendChild(row));
    }

    // Reset arrows
    document.querySelectorAll(".sort-arrow").forEach(el => el.innerHTML = "");
    const arrow = sortState[columnIndex] === 1 ? "▲" : (sortState[columnIndex] === 2 ? "▼" : "");
    document.querySelectorAll("th")[columnIndex].querySelector(".sort-arrow").innerHTML = arrow;
}

let cropper;
const imageInput = document.getElementById('imageInput');
const imagePreview = document.getElementById('imagePreview');
const cropperImage = document.getElementById('cropperImage');
const cropperModalEl = document.getElementById('cropperModal');

// Open file → show modal after load
function handleImageCrop(event, previewId) {
  const file = event.target.files[0];
  if (!file) return;

  const reader = new FileReader();
  reader.onload = function(e) {
    cropperImage.src = e.target.result;
    cropperImage.dataset.previewId = previewId;

    cropperImage.onload = () => {
      const cropperModal = new bootstrap.Modal(cropperModalEl);
      cropperModal.show();
    };
  };
  reader.readAsDataURL(file);
}

// Initialize cropper only when modal is shown
cropperModalEl.addEventListener('shown.bs.modal', function () {
  if (cropper) {
    cropper.destroy();
  }
  cropper = new Cropper(cropperImage, {
    aspectRatio: 1,
    viewMode: 1,
    dragMode: 'move',
    autoCropArea: 1,
    responsive: true,
    background: false,
    center: true,
  });
});

// ⚡ Cleanup when modal is hidden
cropperModalEl.addEventListener('hidden.bs.modal', function () {
  if (cropper) {
    cropper.destroy();
    cropper = null;
  }
});

// Crop & Save
document.getElementById('cropImageBtn').addEventListener('click', function() {
  if (cropper) {
    const canvas = cropper.getCroppedCanvas({
      width: 400,
      height: 400,
    });

    const previewId = cropperImage.dataset.previewId || "imagePreview";
    const hiddenInputId = (previewId === "view_imagePreview") 
        ? "view_cropped_image_data" 
        : "cropped_image_data";

    document.getElementById(previewId).src = canvas.toDataURL("image/png");
    document.getElementById(hiddenInputId).value = canvas.toDataURL("image/png");

    // Close modal
    const modal = bootstrap.Modal.getInstance(cropperModalEl);
    modal.hide();
  }
});


// Click wrapper to trigger input
document.getElementById('imageWrapper').addEventListener('click', () => {
  imageInput.click();
});


$(document).ready(function(){

  // trigger check kapag nag-blur o nag-type
  $("#email_address").on("blur keyup", function(){
    var email = $(this).val();

    if(email.length > 0){
      $.ajax({
        url: "../database/check_email.php",
        type: "POST",
        data: { email: email },
        success: function(response){
          if(response.trim() === "exists"){
            $("#email_error").show();
            $("#email_address").addClass("is-invalid");
            $("button[type=submit]").prop("disabled", true); // disable submit
          } else {
            $("#email_error").hide();
            $("#email_address").removeClass("is-invalid");
            $("button[type=submit]").prop("disabled", false); // enable submit
          }
        }
      });
    } else {
      $("#email_error").hide();
      $("#email_address").removeClass("is-invalid");
      $("button[type=submit]").prop("disabled", false);
    }
  });
});

document.addEventListener("DOMContentLoaded", function () {
  // Hanapin lahat ng select na may status (PWD, Senior, etc.)
  const statusInputs = [
    { select: "pwd_status", input: "pwd_id_number" },
    { select: "senior_citizen_status", input: "senior_id_number" },
  ];

  statusInputs.forEach(({ select, input }) => {
    const selectEl = document.querySelector(`[name="${select}"]`);
    const inputEl = document.querySelector(`[name="${input}"]`);

    function toggleInput() {
      if (selectEl.value === "Yes") {
        inputEl.disabled = false;
      } else {
        inputEl.disabled = true;
        inputEl.value = ""; // optionally clear value kapag naka-No
      }
    }

    // Initial load
    toggleInput();

    // On change
    selectEl.addEventListener("change", toggleInput);
  });
});

document.getElementById("house_position").addEventListener("change", function() {
    let selected = this.value;
    let headBox = document.getElementById("headOfFamilyBox");
    if (selected !== "Head" && selected !== "") {
      headBox.style.display = "block";
    } else {
      headBox.style.display = "none";
      document.getElementById("head_of_family").value = "";
    }
  });

  $(document).ready(function(){
  $("#head_of_family").on("keyup", function(){
    let query = $(this).val();

    if(query.length >= 2){
      $.ajax({
  url: "../database/resident_get_head.php",
  type: "GET",
  data: { term: query },
  dataType: "json", // dagdagan para si jQuery na mag-parse
  success: function(results){
    let suggestionBox = $("#suggestionList");
    suggestionBox.empty().show();

    if(results.length > 0){
      results.forEach(function(item){
        suggestionBox.append(`
          <a href="#" class="list-group-item list-group-item-action select-head" data-id="${item.id}" data-name="${item.name}">
            <div class="d-flex align-items-center">
              <img src="../uploads/residents/${item.photo}" class="rounded-circle me-2" width="40" height="40">
              <span>${item.name}</span>
            </div>
          </a>
        `);
      });
    } else {
      suggestionBox.append(`<div class="list-group-item">No results found</div>`);
    }
  },
  error: function(xhr, status, error){
    console.error("AJAX Error:", xhr.responseText);
  }
});
    } else {
      $("#suggestionList").hide();
    }
  });

  // when user clicks a suggestion
  $(document).on("click", ".select-head", function(e){
    e.preventDefault();
    let name = $(this).data("name");
    let id = $(this).data("id");

    $("#head_of_family").val(name); // fill input with name
    $("#head_of_family_id").val(id); // hidden input to save id
    $("#suggestionList").hide();
  });
});

  document.getElementById("residency_date").addEventListener("change", function () {
  let startDate = new Date(this.value);
  let today = new Date();

  if (!this.value) {
    document.getElementById("years_of_residency").value = "";
    return;
  }

  let years = today.getFullYear() - startDate.getFullYear();
  let months = today.getMonth() - startDate.getMonth();
  let days = today.getDate() - startDate.getDate();

  // Adjust months and years kung negative
  if (days < 0) {
    months--;
    let prevMonth = new Date(today.getFullYear(), today.getMonth(), 0);
    days += prevMonth.getDate();
  }

  if (months < 0) {
    years--;
    months += 12;
  }

  document.getElementById("years_of_residency").value = 
    years + " Years " + months + " Months " + days + " Days";
});

function searchTable() {
  let input = document.getElementById("searchInput");
  let filter = input.value.toLowerCase();
  let rows = document.querySelectorAll("#residentTableBody tr");

  rows.forEach(row => {
    let text = row.innerText.toLowerCase();
    if (text.indexOf(filter) > -1) {
      row.style.display = "";
    } else {
      row.style.display = "none";
    }
  });
}

$(document).ready(function(){

  // Image click → trigger input only in Edit Mode
  $("#view_imageWrapper").on("click", function(){
    if ($("#saveResidentBtn").is(":visible")) { 
      $("#view_imageInput").trigger("click");
    }
  });

  // Handle file input change → open cropper modal
  $("#view_imageInput").on("change", function(event){
    let file = event.target.files[0];
    if(file){
      openCropperModal(file, "view_imagePreview", "view_cropped_image_data");
    }
  });

  // Row clicked → fetch resident data
  $(".table-row").on("click", function(){
    var residentId = $(this).data("id");

    $.ajax({
      url: "../database/resident_fetch.php",
      type: "GET",
      data: { id: residentId },
      success: function(response){
        var data = JSON.parse(response);

        if(!data.error){
          // Image
          $("#view_imagePreview").attr("src", "../uploads/residents/" + (data.image_url || "logo.png"));

          // Personal Info
          $("#view_first_name").val(data.first_name);
          $("#view_middle_name").val(data.middle_name);
          $("#view_last_name").val(data.last_name);
          $("#view_gender").val(data.gender);
          $("#view_date_of_birth").val(data.date_of_birth);
          $("#view_pob_country").val(data.pob_country);
          $("#view_pob_province").val(data.pob_province);
          $("#view_pob_city").val(data.pob_city);
          $("#view_civil_status").val(data.civil_status);
          $("#view_nationality").val(data.nationality);
          $("#view_religion").val(data.religion);
          $("#view_country").val(data.country);
          $("#view_province").val(data.province);
          $("#view_city").val(data.city);
          $("#view_barangay").val(data.barangay);
          $("#view_zipcode").val(data.zipcode);
          $("#view_house_number").val(data.house_number);
          $("#view_zone_purok").val(data.zone_purok);
          $("#view_residency_date").val(data.residency_date);
          $("#view_years_of_residency").val(calculateResidencyDuration(data.residency_date));
          $("#view_residency_type").val(data.residency_type);
          $("#view_previous_address").val(data.previous_address);

          // Family Background
          $("#view_father_name").val(data.father_name);
          $("#view_mother_name").val(data.mother_name);
          $("#view_spouse_name").val(data.spouse_name);
          $("#view_number_of_family_members").val(data.number_of_family_members);
          $("#view_household_number").val(data.household_number);
          $("#view_relationship_to_head").val(data.relationship_to_head);
          $("#view_house_position").val(data.house_position);

          // Education & Employment
          $("#view_educational_attainment").val(data.educational_attainment);
          $("#view_current_school").val(data.current_school);
          $("#view_occupation").val(data.occupation);
          $("#view_monthly_income").val(data.monthly_income);

          // Contact Information
          $("#view_mobile_number").val(data.mobile_number);
          $("#view_telephone_number").val(data.telephone_number);
          $("#view_email_address").val(data.email_address);

          // Emergency Contact
          $("#view_emergency_contact_person").val(data.emergency_contact_person);
          $("#view_emergency_contact_number").val(data.emergency_contact_number);

          // Government Information
          $("#view_pwd_status").val(data.pwd_status);
          $("#view_pwd_id_number").val(data.pwd_id_number);
          $("#view_senior_citizen_status").val(data.senior_citizen_status);
          $("#view_senior_id_number").val(data.senior_id_number);
          $("#view_solo_parent_status").val(data.solo_parent_status);
          $("#view_is_4ps_member").val(data.is_4ps_member);
          $("#view_blood_type").val(data.blood_type);
          $("#view_voter_status").val(data.voter_status);

          // Reset modal to view mode before showing
          $("#viewResidentModal").find("input, select, textarea").prop("disabled", true);
          $("#saveResidentBtn").hide();
          $("#editConfirmBtn").show();

          // save ID 
          $("#viewResidentModal").data("resident-id", residentId);

          // Show modal
          $("#viewResidentModal").modal("show");
        } else {
          alert("Resident not found.");
        }
      }
    });
  });

  // When modal is closed → reset to view mode
  $('#viewResidentModal').on('hidden.bs.modal', function () {
    $(this).find("input, select, textarea").prop("disabled", true);
    $("#saveResidentBtn").hide();
    $("#editConfirmBtn").show();

    $("#deleteCancelBtn")
      .removeClass("btn-secondary")
      .addClass("btn-danger")
      .html('<i class="bi bi-trash me-1"></i> Delete')
      .data("mode", "delete");
  });

  // Edit button clicked → confirm modal
  $("#editConfirmBtn").on("click", function () {
    let fullName = $("#view_first_name").val() + " " + $("#view_middle_name").val() + " " + $("#view_last_name").val();
    $("#residentFullName").text(fullName.trim());
    $("#confirmEditModal").modal("show");
  });

  // Confirm edit
  $("#confirmEditYes").on("click", function () {
    $("#confirmEditModal").modal("hide");
    $("#viewResidentModal").find("input, select, textarea").prop("disabled", false);
    
    $("#editConfirmBtn").hide(); 
    $("#saveResidentBtn").show(); 

    $("#deleteCancelBtn")
      .removeClass("btn-danger")
      .addClass("btn-danger")
      .html('<i class="bi bi-x-circle me-1"></i> Cancel')
      .data("mode", "cancel");
  });

  // Delete/Cancel button logic
  $("#deleteCancelBtn").on("click", function(){
    if($(this).data("mode") === "cancel"){
      let fullName = $("#view_first_name").val() + " " + $("#view_middle_name").val() + " " + $("#view_last_name").val();
      $("#residentFullNameCancel").text(fullName.trim());
      $("#confirmCancelModal").modal("show");
    } else {
      let fullName = $("#view_first_name").val() + " " + $("#view_middle_name").val() + " " + $("#view_last_name").val();
      $("#residentFullNameDelete").text(fullName.trim());
      $("#confirmDeleteModal").modal("show");
    }
  });

  // Confirm delete
  $("#confirmDeleteYes").on("click", function(){
    $("#confirmDeleteModal").modal("hide");
    let residentId = $("#viewResidentModal").data("resident-id");

    if(!residentId){
      alert("No resident ID found.");
      return;
    }

    $.ajax({
      url: "../database/resident_delete.php",
      type: "POST",
      data: { id: residentId },
      success: function(response){
        try {
          let res = JSON.parse(response);
          if(res.success){
            alert("Resident deleted successfully!");
            $("#viewResidentModal").modal("hide");
            $("#residentTableBody").load(window.location.href + " #residentTableBody > *");
          } else {
            alert("Failed to delete resident. Error: " + (res.error || "unknown"));
          }
        } catch (e) {
          alert("Unexpected error: " + response);
        }
      },
      error: function(xhr, status, error){
        alert("AJAX error: " + error);
      }
    });
  });

  // Confirm cancel edit
  $("#confirmCancelYes").on("click", function(){
    $("#confirmCancelModal").modal("hide");
    $("#viewResidentModal").find("input, select, textarea").prop("disabled", true);
    $("#saveResidentBtn").hide();
    $("#editConfirmBtn").show();

    $("#deleteCancelBtn")
      .removeClass("btn-secondary")
      .addClass("btn-danger")
      .html('<i class="bi bi-trash me-1"></i> Delete')
      .data("mode", "delete");
  });

// Save Resident (Edit Mode)
$("#saveResidentBtn").on("click", function () {
  let formData = new FormData($("#viewResidentForm")[0]);

  // Add hidden resident ID (important para ma-update yung tamang record)
  formData.append("resident_id", $("#viewResidentModal").data("resident-id"));

  $.ajax({
    url: "../database/resident_update.php",
    type: "POST",
    data: formData,
    contentType: false,
    processData: false,
    success: function (response) {
      let res;
      try {
        res = typeof response === "string" ? JSON.parse(response) : response;
      } catch (e) {
        console.error("Failed to parse JSON:", response);
        alert("Something went wrong while saving.");
        return;
      }

      if (res.success) {
          $("#viewResidentModal").modal("hide");
          location.reload(); // refresh buong page
      } else {
        alert("Update failed: " + res.error);
      }

    }, // ✅ dito dapat may comma

    error: function (xhr, status, error) {
      console.error("AJAX Error:", error);
      alert("Error saving resident.");
    },
  });
});

});

// Helper
function calculateResidencyDuration(startDate) {
  if (!startDate) return "";
  let start = new Date(startDate);
  let today = new Date();

  let years = today.getFullYear() - start.getFullYear();
  let months = today.getMonth() - start.getMonth();
  let days = today.getDate() - start.getDate();

  if (days < 0) {
    months--;
    let prevMonth = new Date(today.getFullYear(), today.getMonth(), 0).getDate();
    days += prevMonth;
  }
  if (months < 0) {
    years--;
    months += 12; 
  }

  return `${years} year(s), ${months} month(s), ${days} day(s)`;
}

document.addEventListener("DOMContentLoaded", function() {
  const residencyDateInput = document.getElementById("view_residency_date");
  const yearsOfResidencyInput = document.getElementById("view_years_of_residency");

  function calculateResidencyDuration(startDate) {
    if (!startDate) return "";
    let start = new Date(startDate);
    let today = new Date();

    let years = today.getFullYear() - start.getFullYear();
    let months = today.getMonth() - start.getMonth();
    let days = today.getDate() - start.getDate();

    if (days < 0) {
      months--;
      let prevMonth = new Date(today.getFullYear(), today.getMonth(), 0).getDate();
      days += prevMonth;
    }
    if (months < 0) {
      years--;
      months += 12; 
    }

    return `${years} year(s), ${months} month(s), ${days} day(s)`;
  }

  // Auto-update kapag may change sa date
  residencyDateInput.addEventListener("change", function() {
    yearsOfResidencyInput.value = calculateResidencyDuration(residencyDateInput.value);
  });

  // Optional: compute on page load if value exists
  if (residencyDateInput.value) {
    yearsOfResidencyInput.value = calculateResidencyDuration(residencyDateInput.value);
  }
});

document.addEventListener("DOMContentLoaded", function () {
  const pwdStatus = document.getElementById("view_pwd_status");
  const pwdId = document.getElementById("view_pwd_id_number");

  const seniorStatus = document.getElementById("view_senior_citizen_status");
  const seniorId = document.getElementById("view_senior_id_number");

  // helper function
  function toggleIdField(selectEl, inputEl) {
    if (selectEl.value === "Yes") {
      inputEl.disabled = false;
    } else {
      inputEl.disabled = true;
      inputEl.value = "";
    }
  }

  // initial run
  toggleIdField(pwdStatus, pwdId);
  toggleIdField(seniorStatus, seniorId);

  // listen sa change
  pwdStatus.addEventListener("change", () => toggleIdField(pwdStatus, pwdId));
  seniorStatus.addEventListener("change", () => toggleIdField(seniorStatus, seniorId));

  // timer checker (real-time safeguard)
  setInterval(() => {
    toggleIdField(pwdStatus, pwdId);
    toggleIdField(seniorStatus, seniorId);
  }, 500); // every 0.5s
});

// --- Autocomplete for View Resident Modal ---
$(document).ready(function(){
  $("#view_head_of_family").on("keyup", function(){
    let query = $(this).val();

    if(query.length >= 2){
      $.ajax({
        url: "../database/resident_get_head.php",
        type: "GET",
        data: { term: query },
        dataType: "json", // si jQuery na mag-parse
        success: function(results){
          let suggestionBox = $("#view_suggestionList");
          suggestionBox.empty().show();

          if(results.length > 0){
            results.forEach(function(item){
              suggestionBox.append(`
                <a href="#" class="list-group-item list-group-item-action select-head-view" data-id="${item.id}" data-name="${item.name}">
                  <div class="d-flex align-items-center">
                    <img src="../uploads/residents/${item.photo}" class="rounded-circle me-2" width="40" height="40">
                    <span>${item.name}</span>
                  </div>
                </a>
              `);
            });
          } else {
            suggestionBox.append(`<div class="list-group-item">No results found</div>`);
          }
        },
        error: function(xhr, status, error){
          console.error("AJAX Error:", xhr.responseText);
        }
      });
    } else {
      $("#view_suggestionList").hide();
    }
  });

  // kapag nag-click ng suggestion sa VIEW modal
  $(document).on("click", ".select-head-view", function(e){
    e.preventDefault();
    let name = $(this).data("name");
    let id = $(this).data("id");

    $("#view_head_of_family").val(name); // fill input with name
    $("#view_head_of_family_id").val(id); // hidden input to save id
    $("#view_suggestionList").hide();
  });
});

$(document).ready(function () {
  // toggle visibility ng head of family search depende sa house position
  $("#view_house_position").on("change", function () {
    let value = $(this).val();

    if (value && value !== "Head") {
      $("#view_headOfFamilyBox").show();  // show kapag hindi "Head"
    } else {
      $("#view_headOfFamilyBox").hide();  // hide kapag Head or empty
      $("#view_head_of_family").val("");  // clear input
      $("#view_head_of_family_id").val(""); // clear hidden id
      $("#view_suggestionList").hide(); // hide suggestions
    }
  });
});

function reloadResidents() {
  $("#residentTableBody").load("../database/resident_table.php");
}

// auto load on page load
$(document).ready(function() {
  reloadResidents();
});
