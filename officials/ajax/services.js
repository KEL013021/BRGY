function searchTable() {
    let input = document.getElementById("searchInput").value.toLowerCase();
    let rows = document.querySelectorAll("#residentTableBody tr");

    rows.forEach(row => {
        let text = row.innerText.toLowerCase();
        row.style.display = text.includes(input) ? "" : "none";
    });
}
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
            const aText = a.querySelectorAll("td")[columnIndex - 1].innerText.trim().toLowerCase();
            const bText = b.querySelectorAll("td")[columnIndex - 1].innerText.trim().toLowerCase();

            if (!isNaN(aText) && !isNaN(bText)) {
                return (parseFloat(aText) - parseFloat(bText)) * direction;
            }
            return aText.localeCompare(bText) * direction;
        });

        tableBody.innerHTML = "";
        rows.forEach(row => tableBody.appendChild(row));
    }

    // Reset all arrows
    document.querySelectorAll(".sort-arrow").forEach(el => el.innerHTML = "");

    // Add arrow to clicked column
    const arrow = sortState[columnIndex] === 1 ? "▲" : (sortState[columnIndex] === 2 ? "▼" : "");
    document.querySelector(`thead th:nth-child(${columnIndex}) .sort-arrow`).innerHTML = arrow;
}

function openAddServiceModal() {
    document.getElementById("addServiceModal").style.display = "flex";
}

function closeAddServiceModal() {
    document.getElementById("addServiceModal").style.display = "none";
}

// ✅ Auto-enable customize button when file is selected
document.getElementById("pdfTemplate").addEventListener("change", function () {
    document.getElementById("customizeLayoutBtn").disabled = !this.files.length;
});

// ================= PDF Layout Editor =================
let pdfDoc = null;
let canvas = document.getElementById('pdfCanvas');
let ctx = canvas.getContext('2d');
let selectedField = null;
let activeEl = null;
let offsetX, offsetY;

// Render PDF on canvas
document.getElementById('pdfTemplate').addEventListener('change', function (e) {
    const file = e.target.files[0];
    if (file && file.type === 'application/pdf') {
        const fileReader = new FileReader();
        fileReader.onload = function () {
            const typedarray = new Uint8Array(this.result);
            pdfjsLib.getDocument(typedarray).promise.then(function (pdf) {
                pdfDoc = pdf;
                return pdf.getPage(1);
            }).then(function (page) {
                const viewport = page.getViewport({ scale: 1.5 });
                canvas.height = viewport.height;
                canvas.width = viewport.width;

                page.render({ canvasContext: ctx, viewport: viewport });
                document.getElementById('customizeLayoutBtn').disabled = false;
            });
        };
        fileReader.readAsArrayBuffer(file);
    }
});

// Open Layout Editor Modal
document.getElementById('customizeLayoutBtn').addEventListener('click', function () {
    const modal = new bootstrap.Modal(document.getElementById('pdfLayoutEditorModal'));
    modal.show();
});

// Save Layout
document.getElementById('saveLayoutBtn').addEventListener('click', function () {
    const wrapper = document.getElementById('pdfEditorWrapper');
    const fields = document.querySelectorAll('.draggable-field');
    const layout = {
        canvasWidth: wrapper.offsetWidth,
        canvasHeight: wrapper.offsetHeight,
        fields: []
    };

    fields.forEach(el => {
        const computedStyle = window.getComputedStyle(el);
        layout.fields.push({
            text: el.innerText,
            x: parseFloat(el.style.left),
            y: parseFloat(el.style.top),
            width: parseFloat(el.offsetWidth),
            height: parseFloat(el.offsetHeight),
            fontSize: parseInt(computedStyle.fontSize),
            fontFamily: computedStyle.fontFamily,
            color: computedStyle.color,
            fontWeight: computedStyle.fontWeight,
            fontStyle: computedStyle.fontStyle,
            textDecoration: computedStyle.textDecorationLine
        });
    });

    document.getElementById('pdfLayoutData').value = JSON.stringify(layout);
    bootstrap.Modal.getInstance(document.getElementById('pdfLayoutEditorModal')).hide();
});

// ================= Mouse Drag Logic =================
document.addEventListener('mousedown', function (e) {
    if (e.target.classList.contains('draggable-field')) {
        // 🔒 Check if mouse is on the resize edge (right side only)
        const bounds = e.target.getBoundingClientRect();
        const edgeThreshold = 10;
        const isResizing = (bounds.right - e.clientX) < edgeThreshold;

        if (isResizing) return; // Skip dragging if resizing

        // ✅ Normal drag logic
        activeEl = e.target;
        const rect = activeEl.getBoundingClientRect();
        offsetX = e.clientX - rect.left;
        offsetY = e.clientY - rect.top;
        e.preventDefault();
    }
});

document.addEventListener('mousemove', function (e) {
    if (activeEl) {
        const container = document.getElementById('pdfEditorWrapper');
        const containerRect = container.getBoundingClientRect();

        const x = e.clientX - containerRect.left - offsetX;
        const y = e.clientY - containerRect.top - offsetY;

        activeEl.style.left = x + 'px';
        activeEl.style.top = y + 'px';
    }
});

document.addEventListener('mouseup', function () {
    activeEl = null;
});

// ================= Insert Field from Sidebar =================
document.querySelectorAll('.insert-field-btn').forEach(btn => {
    btn.addEventListener('click', function () {
        const fieldValue = this.getAttribute('data-field');
        const container = document.getElementById('canvasScrollContainer');
        const wrapper = document.getElementById('pdfEditorWrapper');

        // ✅ Kunin ang visible center ng container
        const visibleX = container.scrollLeft + container.clientWidth / 2;
        const visibleY = container.scrollTop + container.clientHeight / 2;

        // Gumawa ng bagong field
        const div = document.createElement('div');
        div.className = 'draggable-field';
        div.contentEditable = true;
        div.innerText = fieldValue;
        div.style.position = 'absolute';
        div.style.left = (visibleX - 75) + 'px';
        div.style.top = (visibleY - 15) + 'px';
        div.style.padding = '2px 5px';
        div.style.border = '1px dashed #000';
        div.style.background = '#f9f9f9';
        div.style.cursor = 'move';
        div.style.fontFamily = document.getElementById('fontFamily').value;
        div.style.fontSize = document.getElementById('fontSize').value + 'px';
        div.style.color = document.getElementById('fontColor').value;
        div.style.zIndex = 10;

        // ✅ Resizable box
        div.style.resize = 'horizontal';
        div.style.overflow = 'hidden';
        div.style.minWidth = '50px';
        div.style.maxWidth = '400px';
        div.style.whiteSpace = 'nowrap';

        // ✅ Center text sa loob ng box
        div.style.display = 'flex';
        div.style.alignItems = 'center';
        div.style.justifyContent = 'center';
        div.style.textAlign = 'center';

        // Select on click
        div.addEventListener('click', function (e) {
            e.stopPropagation();
            if (selectedField) selectedField.style.border = '1px dashed #000';
            selectedField = div;
            div.style.border = '2px solid red';
        });

        wrapper.appendChild(div);
    });
});

// ================= Deselect & Delete Field =================
document.getElementById('pdfEditorWrapper').addEventListener('click', function () {
    if (selectedField) {
        selectedField.style.border = '1px dashed #000';
        selectedField = null;
    }
});

document.getElementById('deleteFieldBtn').addEventListener('click', () => {
    if (selectedField) {
        selectedField.remove();
        selectedField = null;
    }
});

// ================= Font Controls =================
document.getElementById('fontFamily').addEventListener('change', (e) => {
    if (selectedField) selectedField.style.fontFamily = e.target.value;
});

document.getElementById('fontSize').addEventListener('change', (e) => {
    if (selectedField) selectedField.style.fontSize = e.target.value + 'px';
});

document.getElementById('fontColor').addEventListener('input', (e) => {
    if (selectedField) selectedField.style.color = e.target.value;
});

// Bold
document.getElementById('btnBold').addEventListener('click', function () {
    if (selectedField) {
        const isBold = selectedField.style.fontWeight === 'bold';
        selectedField.style.fontWeight = isBold ? 'normal' : 'bold';
        this.classList.toggle('active', !isBold);
    }
});

// Italic
document.getElementById('btnItalic').addEventListener('click', function () {
    if (selectedField) {
        const isItalic = selectedField.style.fontStyle === 'italic';
        selectedField.style.fontStyle = isItalic ? 'normal' : 'italic';
        this.classList.toggle('active', !isItalic);
    }
});

// Underline
document.getElementById('btnUnderline').addEventListener('click', function () {
    if (selectedField) {
        const isUnderlined = selectedField.style.textDecoration === 'underline';
        selectedField.style.textDecoration = isUnderlined ? 'none' : 'underline';
        this.classList.toggle('active', !isUnderlined);
    }
});


/* ============================================================
   GLOBAL VARIABLES
   ============================================================ */
let selectedServiceId = null;   // currently selected service ID
let isEditing = false;          // flag kung nasa edit mode
let pdfEditDoc = null;          // PDF.js document object for EDIT
let canvasEdit = document.getElementById('pdfCanvasEditorEdit'); // EDIT canvas
let ctxEdit = canvasEdit.getContext('2d');
let selectedFieldEdit = null;   // currently selected field
let activeElEdit = null;        // for drag handling
let offsetXEdit, offsetYEdit;
let editedLayoutData = null;   // dito muna isstore ang layout fields
let replacedPdfFile = null;    // kung may bagong inupload na PDF


/* ============================================================
   1. ROW CLICK → VIEW SERVICE DETAILS
   ============================================================ */
document.querySelectorAll(".table-row").forEach(row => {
  row.addEventListener("click", function () {
    selectedServiceId = this.getAttribute("data-id");

    fetch(`../database/services_fetch.php?id=${selectedServiceId}`)
      .then(res => res.json())
      .then(data => {
        if (data.error) {
          alert(data.error);
          return;
        }

        // Fill modal fields
        document.getElementById("view_serviceName").value = data.service_name;
        document.getElementById("view_serviceFee").value = data.service_fee;
        document.getElementById("view_requirements").value = data.requirements;
        document.getElementById("view_description").value = data.description;

        // Make fields readonly by default
        document.querySelectorAll("#viewServiceModal input, #viewServiceModal textarea")
          .forEach(el => el.setAttribute("readonly", true));

        // Reset buttons visibility
        document.getElementById("pdfActions").style.display = "none";
        document.getElementById("previewPdfBtn").style.display = "inline-block";
        document.getElementById("customizePdfBtn").style.display = "none";
        document.getElementById("saveEditServicesBtn").style.display = "none";

        // Reset delete button
        const deleteBtn = document.getElementById("deleteCancelBtn");
        deleteBtn.innerHTML = `<i class="bi bi-trash"></i> Delete`;
        deleteBtn.classList.remove("btn-secondary");
        deleteBtn.classList.add("btn-danger");

        // Show modal
        new bootstrap.Modal(document.getElementById("viewServiceModal")).show();
      })
      .catch(err => console.error("Error fetching service:", err));
  });
});

/* ============================================================
   2. EDIT CONFIRMATION
   ============================================================ */
document.getElementById("editConfirmBtn").addEventListener("click", () => {
  const serviceName = document.getElementById("view_serviceName").value;
  document.getElementById("confirmEditText").innerText =
    `Are you sure you want to edit "${serviceName}"?`;

  new bootstrap.Modal(document.getElementById("confirmEditModal")).show();
});

/* ============================================================
   3. CONFIRM YES → ENABLE EDITING
   ============================================================ */
document.getElementById("confirmEditYesBtn").addEventListener("click", () => {
  isEditing = true;
  bootstrap.Modal.getInstance(document.getElementById("confirmEditModal")).hide();

  // Enable fields
  document.querySelectorAll("#viewServiceModal input, #viewServiceModal textarea")
    .forEach(el => el.removeAttribute("readonly"));

  // Show PDF actions
  document.getElementById("pdfActions").style.display = "block";
  document.getElementById("previewPdfBtn").style.display = "none";
  document.getElementById("customizePdfBtn").style.display = "inline-block";

  // Change Delete → Cancel
  const deleteBtn = document.getElementById("deleteCancelBtn");
  deleteBtn.innerHTML = `<i class="bi bi-x-circle"></i> Cancel`;
  deleteBtn.classList.remove("btn-danger");
  deleteBtn.classList.add("btn-secondary");

  // Show Save
  document.getElementById("saveEditServicesBtn").style.display = "inline-flex";

  // Hide Edit button
  document.getElementById("editConfirmBtn").style.display = "none";
});

/* ============================================================
   4. CANCEL EDIT or DELETE
   ============================================================ */
document.getElementById("deleteCancelBtn").addEventListener("click", () => {
  if (isEditing) {
    // Cancel editing → reset UI
    isEditing = false;
    document.querySelectorAll("#viewServiceModal input, #viewServiceModal textarea")
      .forEach(el => el.setAttribute("readonly", true));

    document.getElementById("pdfActions").style.display = "none";
    document.getElementById("previewPdfBtn").style.display = "inline-block";
    document.getElementById("customizePdfBtn").style.display = "none";
    document.getElementById("saveEditServicesBtn").style.display = "none";

    const deleteBtn = document.getElementById("deleteCancelBtn");
    deleteBtn.innerHTML = `<i class="bi bi-trash"></i> Delete`;
    deleteBtn.classList.remove("btn-secondary");
    deleteBtn.classList.add("btn-danger");

    document.getElementById("editConfirmBtn").style.display = "inline-flex";
  } else {
    // If not editing, show delete confirmation
const serviceName = document.getElementById("view_serviceName").value;
document.getElementById("confirmDeleteText").innerText =
  `Are you sure you want to delete "${serviceName}"?`;

new bootstrap.Modal(document.getElementById("confirmDeleteModal")).show();

  }
});

/* ============================================================
   5. CUSTOMIZE PDF (UPLOAD NEW or USE EXISTING)
   ============================================================ */
document.getElementById("customizePdfBtn").addEventListener("click", () => {
  const fileInput = document.getElementById("replacePdfFile");

  if (fileInput.files.length > 0) {
    // ✅ Bagong file → store lang muna, huwag agad i-upload
    replacedPdfFile = fileInput.files[0];
    console.log("Prepared new PDF (not yet saved):", replacedPdfFile.name);

    // Gumamit ng local object URL para ma-preview agad
    const fileURL = URL.createObjectURL(replacedPdfFile);

    // Load PDF into editor para ma-customize
    loadPdfInEditEditor(fileURL, null);

    // Open editor modal
    new bootstrap.Modal(document.getElementById("pdfLayoutEditorModalEdit")).show();

  } else {
    // ✅ Walang bagong file → gamitin yung existing
    console.log("Using existing PDF...");

    fetch(`../database/services_pdf_fetch.php?service_id=${selectedServiceId}`)
      .then(res => res.json())
      .then(data => {
        if (data.error) {
          alert(data.error);
          return;
        }

        if (data.pdf_template) {
          loadPdfInEditEditor(data.pdf_template, data.pdf_layout_data ? JSON.parse(data.pdf_layout_data) : null);
        }

        new bootstrap.Modal(document.getElementById("pdfLayoutEditorModalEdit")).show();
      })
      .catch(err => console.error("Error fetching existing PDF:", err));
  }
});

/* ============================================================
   6. LOAD PDF INTO EDITOR
   ============================================================ */
async function loadPdfInEditEditor(pdfPath, layoutData = null) {
  try {
    const loadingTask = pdfjsLib.getDocument(pdfPath);
    pdfEditDoc = await loadingTask.promise;
    const page = await pdfEditDoc.getPage(1);

    const scale = 1.5;
    const viewport = page.getViewport({ scale });

    canvasEdit.height = viewport.height;
    canvasEdit.width = viewport.width;

    const wrapper = document.getElementById('pdfEditorWrapperEdit');
    wrapper.style.position = 'relative';
    wrapper.innerHTML = '';
    wrapper.appendChild(canvasEdit);

    await page.render({ canvasContext: ctxEdit, viewport }).promise;

    // Render fields if existing layout is found
    if (layoutData) renderFieldsOnPdfEdit(layoutData);
  } catch (err) {
    console.error("Error loading PDF in Edit editor:", err);
  }
}

/* ============================================================
   7. RENDER & CREATE DRAGGABLE FIELDS
   ============================================================ */
function renderFieldsOnPdfEdit(layout) {
  const wrapper = document.getElementById('pdfEditorWrapperEdit');
  wrapper.querySelectorAll('.draggable-field').forEach(el => el.remove());

  // ✅ Support both {fields: []} and [] format
  const fields = layout.fields || layout;

  const scaleX = canvasEdit.width / (layout.canvasWidth || canvasEdit.width);
  const scaleY = canvasEdit.height / (layout.canvasHeight || canvasEdit.height);

  fields.forEach(field => {
    const f = {
      ...field,
      x: field.x * scaleX,
      y: field.y * scaleY,
      width: field.width * scaleX,
      height: field.height * scaleY
    };
    const div = createDraggableFieldEdit(f);
    wrapper.appendChild(div);
  });
}


function createDraggableFieldEdit(field) {
  const div = document.createElement('div');
  div.className = 'draggable-field';
  div.contentEditable = true;
  div.innerText = field.text;

  // Position & size
  div.style.position = 'absolute';
  div.style.left = field.x + 'px';
  div.style.top = field.y + 'px';
  div.style.width = (field.width || 120) + 'px';
  div.style.height = (field.height || 24) + 'px';

  // Style
  div.style.padding = '2px 5px';
  div.style.border = '1px dashed #000';
  div.style.background = '#f9f9f9';
  div.style.cursor = 'move';
  div.style.zIndex = 10;

  // Center alignment
  div.style.display = 'flex';
  div.style.alignItems = 'center';
  div.style.justifyContent = 'center';
  div.style.textAlign = 'center';
  div.style.boxSizing = 'border-box';

  // Font styles
  div.style.fontFamily = field.fontFamily || 'Arial';
  div.style.fontSize = (field.fontSize || 14) + 'px';
  div.style.color = field.color || '#000';
  div.style.fontWeight = field.fontWeight || 'normal';
  div.style.fontStyle = field.fontStyle || 'normal';
  if (field.textDecoration) div.style.textDecoration = field.textDecoration;

  // ✅ Horizontal resize only (same as Add)
  div.style.resize = 'horizontal';
  div.style.overflow = 'hidden';
  div.style.minWidth = '50px';
  div.style.maxWidth = '400px';
  div.style.whiteSpace = 'nowrap';

  /* --- Selection --- */
  div.addEventListener('click', e => {
    e.stopPropagation();
    if (selectedFieldEdit) selectedFieldEdit.style.border = '1px dashed #000';
    selectedFieldEdit = div;
    div.style.border = '2px solid red';

    // Sync toolbar
    document.getElementById('fontFamilyEdit').value = div.style.fontFamily;
    document.getElementById('fontSizeEdit').value = parseInt(div.style.fontSize);
    document.getElementById('fontColorEdit').value = rgbToHex(div.style.color);
    document.getElementById('btnBoldEdit').classList.toggle('active', div.style.fontWeight === 'bold');
    document.getElementById('btnItalicEdit').classList.toggle('active', div.style.fontStyle === 'italic');
    document.getElementById('btnUnderlineEdit').classList.toggle('active', div.style.textDecoration.includes('underline'));
  });

  /* --- Dragging --- */
  let dragging = false;
  div.addEventListener('mousedown', e => {
    // ❌ Huwag i-allow kung nagre-resize (kanan na gilid hinawakan)
    const rect = div.getBoundingClientRect();
    if (e.offsetX > rect.width - 10) return; // 10px sa kanan reserved for resize

    dragging = true;
    offsetXEdit = e.clientX - rect.left;
    offsetYEdit = e.clientY - rect.top;
  });

  window.addEventListener('mousemove', e => {
    if (!dragging) return;
    const container = document.getElementById('canvasScrollContainerEdit');
    const containerRect = container.getBoundingClientRect();
    div.style.left = (e.clientX - containerRect.left - offsetXEdit + container.scrollLeft) + 'px';
    div.style.top = (e.clientY - containerRect.top - offsetYEdit + container.scrollTop) + 'px';
  });

  window.addEventListener('mouseup', () => dragging = false);

  return div;
}


/* ============================================================
   8. INSERT FIELD FROM SIDEBAR
   ============================================================ */
document.querySelectorAll('.insert-field-btn-edit').forEach(btn => {
  btn.addEventListener('click', () => {
    if (!pdfEditDoc) return alert('Load PDF first!');
    const container = document.getElementById('canvasScrollContainerEdit');
    const wrapper = document.getElementById('pdfEditorWrapperEdit');

    const visibleX = container.scrollLeft + container.clientWidth / 2;
    const visibleY = container.scrollTop + container.clientHeight / 2;

    const field = {
      text: btn.dataset.field,
      x: visibleX - 60,
      y: visibleY - 12,
      width: 120,
      height: 24,
      fontFamily: document.getElementById('fontFamilyEdit').value,
      fontSize: parseInt(document.getElementById('fontSizeEdit').value),
      color: document.getElementById('fontColorEdit').value,
      fontWeight: 'normal',
      fontStyle: 'normal',
      textDecoration: 'none'
    };
    const div = createDraggableFieldEdit(field);
    wrapper.appendChild(div);
  });
});

/* ============================================================
   9. DESELECT & DELETE FIELD
   ============================================================ */
document.getElementById('pdfEditorWrapperEdit').addEventListener('click', () => {
  if (selectedFieldEdit) {
    selectedFieldEdit.style.border = '1px dashed #000';
    selectedFieldEdit = null;
  }
});
document.getElementById('deleteFieldBtnEdit').addEventListener('click', () => {
  if (selectedFieldEdit) {
    selectedFieldEdit.remove();
    selectedFieldEdit = null;
  }
});

/* ============================================================
   10. TOOLBAR CONTROLS
   ============================================================ */
document.getElementById('fontFamilyEdit').addEventListener('change', e => {
  if (selectedFieldEdit) selectedFieldEdit.style.fontFamily = e.target.value;
});
document.getElementById('fontSizeEdit').addEventListener('change', e => {
  if (selectedFieldEdit) {
    selectedFieldEdit.style.fontSize = e.target.value + 'px';
    selectedFieldEdit.style.height = "auto"; // ✅ auto expand height
  }
});

document.getElementById('fontColorEdit').addEventListener('input', e => {
  if (selectedFieldEdit) selectedFieldEdit.style.color = e.target.value;
});
document.getElementById('btnBoldEdit').addEventListener('click', () => {
  if (selectedFieldEdit) {
    const isBold = selectedFieldEdit.style.fontWeight === 'bold';
    selectedFieldEdit.style.fontWeight = isBold ? 'normal' : 'bold';
  }
});
document.getElementById('btnItalicEdit').addEventListener('click', () => {
  if (selectedFieldEdit) {
    const isItalic = selectedFieldEdit.style.fontStyle === 'italic';
    selectedFieldEdit.style.fontStyle = isItalic ? 'normal' : 'italic';
  }
});
document.getElementById('btnUnderlineEdit').addEventListener('click', () => {
  if (selectedFieldEdit) {
    const isUnderlined = selectedFieldEdit.style.textDecoration === 'underline';
    selectedFieldEdit.style.textDecoration = isUnderlined ? 'none' : 'underline';
  }
});

/* ============================================================
   11. SAVE LAYOUT
   ============================================================ */
document.getElementById('saveLayoutBtnEdit').addEventListener('click', () => {
  const wrapper = document.getElementById('pdfEditorWrapperEdit');
const fields = wrapper.querySelectorAll('.draggable-field');
const layout = {
    canvasWidth: canvasEdit.width,
    canvasHeight: canvasEdit.height,
    fields: []
};

fields.forEach(f => {
    layout.fields.push({
        text: f.innerText,
        x: parseFloat(f.style.left),
        y: parseFloat(f.style.top),
        width: f.offsetWidth,
        height: f.offsetHeight,
        fontFamily: f.style.fontFamily,
        fontSize: parseInt(f.style.fontSize),
        color: f.style.color,
        fontWeight: f.style.fontWeight,
        fontStyle: f.style.fontStyle,
        textDecoration: f.style.textDecoration
    });
});

editedLayoutData = layout;
  // store muna
  alert("Layout saved locally. Click the green Save button to finalize.");
  
  bootstrap.Modal.getInstance(document.getElementById("pdfLayoutEditorModalEdit")).hide();
});

/* ============================================================
   12. HELPER FUNCTIONS
   ============================================================ */
function rgbToHex(rgb) {
  const result = rgb.match(/\d+/g);
  if (!result) return '#000000';
  return '#' + result.map(x => parseInt(x).toString(16).padStart(2, '0')).join('');
}

/* ============================================================
   13. UPDATING TO DATABASE
   ============================================================ */

document.getElementById("replacePdfFile").addEventListener("change", (e) => {
  replacedPdfFile = e.target.files[0];
});
document.getElementById("saveEditServicesBtn").addEventListener("click", () => {
  if (!selectedServiceId) return alert("No service selected.");

  const formData = new FormData();
  formData.append("service_id", selectedServiceId);
  formData.append("service_name", document.getElementById("view_serviceName").value);
  formData.append("service_fee", document.getElementById("view_serviceFee").value);
  formData.append("requirements", document.getElementById("view_requirements").value);
  formData.append("description", document.getElementById("view_description").value);

  // ✅ Kung may bagong PDF na inupload
  if (replacedPdfFile) {
    formData.append("pdf_template", replacedPdfFile);
  }

  // ✅ Kung nag-customize ng layout
  // ✅ Kung nag-customize ng layout
if (editedLayoutData) {
  // Gumamit mismo ng editedLayoutData (final JSON) na na-save sa Section 11
  formData.append("pdf_layout_data", JSON.stringify(editedLayoutData));
}


  fetch("../database/services_update.php", {
    method: "POST",
    body: formData
  })
    .then(res => res.json())
    .then(data => {
      if (data.success) {
        alert("Service updated successfully!");

        // reset edit mode
        isEditing = false;
        replacedPdfFile = null;
        editedLayoutData = null;

        // close modal
        bootstrap.Modal.getInstance(document.getElementById("viewServiceModal")).hide();

        // optionally reload table
        location.reload();
      } else {
        alert(data.error || "Failed to update service.");
      }
    })
    .catch(err => console.error("Error updating service:", err));
});



document.getElementById("confirmDeleteYesBtn").addEventListener("click", () => {
  if (!selectedServiceId) return alert("No service selected.");

  fetch("../database/services_delete.php", {
    method: "POST",
    body: new URLSearchParams({ id: selectedServiceId })
  })
  .then(res => res.json())
  .then(data => {
    if (data.success) {
      alert("Service deleted successfully.");
      bootstrap.Modal.getInstance(document.getElementById("confirmDeleteModal")).hide();
      bootstrap.Modal.getInstance(document.getElementById("viewServiceModal")).hide();

      // Refresh table or remove row directly
      document.querySelector(`.table-row[data-id='${selectedServiceId}']`).remove();
    } else {
      alert("Error: " + data.error);
    }
  })
  .catch(err => console.error("Delete error:", err));
});




// ================= Preview PDF =================

// Set workerSrc para gumana ang PDF.js
pdfjsLib.GlobalWorkerOptions.workerSrc =
  "https://cdnjs.cloudflare.com/ajax/libs/pdf.js/2.10.377/pdf.worker.min.js";

document.getElementById("previewPdfBtn").addEventListener("click", () => {
  if (!selectedServiceId) {
    alert("No service selected.");
    return;
  }

  fetch(`../database/services_fetch.php?id=${selectedServiceId}`)
    .then(res => res.json())
    .then(data => {
      if (data.error) {
        alert(data.error);
        return;
      }

      const container = document.getElementById("pdfWrapper");
      container.innerHTML = ""; // Clear old preview
      container.style.position = "relative";

      if (data.pdf_template) {
        const pdfUrl = data.pdf_template;

        pdfjsLib.getDocument(pdfUrl).promise.then(pdf => {
          for (let pageNum = 1; pageNum <= pdf.numPages; pageNum++) {
            pdf.getPage(pageNum).then(page => {
              const previewScale = 1.5; // 🔹 Same as editor
              const viewport = page.getViewport({ scale: previewScale });

              // Create canvas per page
              const canvas = document.createElement("canvas");
              const ctx = canvas.getContext("2d");
              canvas.height = viewport.height;
              canvas.width = viewport.width;
              canvas.style.display = "block";
              canvas.style.marginBottom = "20px";

              // Wrapper for page + overlay
              const pageWrapper = document.createElement("div");
              pageWrapper.style.position = "relative";
              pageWrapper.style.display = "inline-block";

              pageWrapper.appendChild(canvas);
              container.appendChild(pageWrapper);

              // Render PDF page
              page.render({ canvasContext: ctx, viewport: viewport });

              // Overlay container
              const overlay = document.createElement("div");
              overlay.style.position = "absolute";
              overlay.style.top = "0";
              overlay.style.left = "0";
              overlay.style.width = canvas.width + "px";
              overlay.style.height = canvas.height + "px";
              overlay.style.pointerEvents = "none"; // Para hindi clickable
              pageWrapper.appendChild(overlay);

              // Render saved layout fields
              if (data.pdf_layout_data) {
                try {
                 const parsed = JSON.parse(data.pdf_layout_data);
const fields = parsed.fields || parsed;

// ✅ scaling vs editor size
const editorWidth = parsed.canvasWidth || canvas.width;
const editorHeight = parsed.canvasHeight || canvas.height;
const scaleX = viewport.width / editorWidth;
const scaleY = viewport.height / editorHeight;

fields.forEach(field => {
  const div = document.createElement("div");
  div.textContent = field.text;
  div.style.position = "absolute";
  div.style.left = (field.x * scaleX) + "px";
  div.style.top = (field.y * scaleY) + "px";

  if (field.width) div.style.width = (field.width * scaleX) + "px";
  if (field.height) div.style.height = (field.height * scaleY) + "px";

  div.style.border = "1px dashed rgba(0,0,0,0.5)";
  div.style.display = "flex";
  div.style.alignItems = "center";
  div.style.justifyContent = "center";
  div.style.textAlign = "center";

  div.style.fontSize = ((field.fontSize || 14) * scaleY) + "px";
  div.style.fontFamily = field.fontFamily || "Arial";
  div.style.color = field.color || "black";
  div.style.fontWeight = field.fontWeight || "normal";
  div.style.fontStyle = field.fontStyle || "normal";
  if (field.textDecoration) div.style.textDecoration = field.textDecoration;

  overlay.appendChild(div);
});

                } catch (err) {
                  console.error("Layout parse error:", err);
                }
              }
            });
          }
        });
      } else {
        container.innerHTML =
          `<p class="text-muted">No PDF template uploaded for this service.</p>`;
      }

      // Show modal
      new bootstrap.Modal(document.getElementById("pdfPreviewModal")).show();
    })
    .catch(err => console.error("Error previewing PDF:", err));
});
