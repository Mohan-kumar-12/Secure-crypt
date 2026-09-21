/**
 * Digital Watermarking System (Module 2) — Frontend JavaScript Engine
 * Handles drag-and-drop uploads, API submissions, and verification rendering.
 */

document.addEventListener("DOMContentLoaded", () => {
  initDragAndDrop();
  initFormSubmissions();
});

function $(id) {
  return document.getElementById(id);
}

/* ── Drag and Drop Setup ───────────────────────────────── */
function initDragAndDrop() {
  const dropZones = document.querySelectorAll(".drop-zone");

  dropZones.forEach((zone) => {
    const input = zone.querySelector('input[type="file"]');
    if (!input) return;

    ["dragenter", "dragover"].forEach((eventName) => {
      zone.addEventListener(eventName, (e) => {
        e.preventDefault();
        e.stopPropagation();
        zone.classList.add("dragover");
      });
    });

    ["dragleave", "drop"].forEach((eventName) => {
      zone.addEventListener(eventName, (e) => {
        e.preventDefault();
        e.stopPropagation();
        zone.classList.remove("dragover");
      });
    });

    zone.addEventListener("drop", (e) => {
      const dt = e.dataTransfer;
      const files = dt.files;
      if (files.length > 0) {
        input.files = files;
        triggerFilePreview(input);
      }
    });

    input.addEventListener("change", () => {
      triggerFilePreview(input);
    });
  });
}

function triggerFilePreview(input) {
  const file = input.files[0];
  if (!file) return;

  // Image preview
  if (input.id === "imgInput") {
    const reader = new FileReader();
    reader.onload = (e) => {
      const pImg = $("imgPreviewEl");
      const pBox = $("imgPreviewBox");
      if (pImg && pBox) {
        pImg.src = e.target.result;
        pBox.style.display = "block";
        const meta = $("imgMetaRow");
        if (meta) {
          meta.innerHTML = `<span class="badge badge-info">${file.name}</span> <span class="badge badge-cyan">${(file.size / 1024).toFixed(1)} KB</span>`;
        }
      }
    };
    reader.readAsDataURL(file);
  }

  // PDF info
  if (input.id === "pdfInput") {
    const infoCard = $("pdfInfoCard");
    const infoDetails = $("pdfMetaDetails");
    if (infoCard && infoDetails) {
      infoCard.style.display = "block";
      infoDetails.innerHTML = `<div style="font-size:0.85rem; color:var(--text-bright);"><strong>Filename:</strong> ${file.name}</div><div style="font-size:0.8rem; color:var(--text-muted);"><strong>File Size:</strong> ${(file.size / 1024).toFixed(1)} KB</div>`;
    }
  }

  // Source Code info
  if (input.id === "codeInput") {
    const infoCard = $("codeFileInfo");
    const infoDetails = $("codeFileDetails");
    if (infoCard && infoDetails) {
      infoCard.style.display = "block";
      infoDetails.innerHTML = `<div style="font-size:0.85rem; color:var(--text-bright);"><strong>Filename:</strong> ${file.name}</div><div style="font-size:0.8rem; color:var(--text-muted);"><strong>File Size:</strong> ${(file.size / 1024).toFixed(1)} KB</div>`;
    }
  }
}

/* ── Form Submissions & API Integration ───────────────── */
function initFormSubmissions() {

  // 1. Image Watermark Form
  const imgForm = $("imageWatermarkForm");
  if (imgForm) {
    imgForm.addEventListener("submit", async (e) => {
      e.preventDefault();
      hideElement("imgErrorAlert");
      hideElement("imgResultCard");
      showElement("imgProgressCard");
      updateProgressBar("imgProgressBar", 30);

      const formData = new FormData(imgForm);
      try {
        updateProgressBar("imgProgressBar", 65);
        const res = await fetch("/api/watermark/image", { method: "POST", body: formData });
        const data = await res.json();
        updateProgressBar("imgProgressBar", 100);

        if (!data.success) {
          showError("imgErrorAlert", data.error || "Image watermarking failed.");
          return;
        }

        // Render Result
        $("resWmid").textContent = data.watermark_id;
        $("resOwner").textContent = data.owner;
        $("resProj").textContent = data.project_id;
        $("resCreated").textContent = new Date(data.created_at).toLocaleString();
        $("resSha256").textContent = data.sha256;
        if (data.preview_b64) $("resPreviewImg").src = data.preview_b64;

        const downloadBtn = $("downloadImgBtn");
        downloadBtn.href = `/download/${data.download_token}`;
        downloadBtn.download = data.filename;

        showElement("imgResultCard");
        $("imgResultCard").scrollIntoView({ behavior: "smooth" });

      } catch (err) {
        showError("imgErrorAlert", "Server error during image processing.");
      } finally {
        setTimeout(() => hideElement("imgProgressCard"), 400);
      }
    });
  }

  // 2. PDF Watermark Form
  const pdfForm = $("pdfWatermarkForm");
  if (pdfForm) {
    pdfForm.addEventListener("submit", async (e) => {
      e.preventDefault();
      hideElement("pdfErrorAlert");
      hideElement("pdfResultCard");
      showElement("pdfProgressCard");
      updateProgressBar("pdfProgressBar", 30);

      const formData = new FormData(pdfForm);
      try {
        updateProgressBar("pdfProgressBar", 65);
        const res = await fetch("/api/watermark/pdf", { method: "POST", body: formData });
        const data = await res.json();
        updateProgressBar("pdfProgressBar", 100);

        if (!data.success) {
          showError("pdfErrorAlert", data.error || "PDF watermarking failed.");
          return;
        }

        // Render Result
        $("pdfResWmid").textContent = data.watermark_id;
        $("pdfResOwner").textContent = data.owner;
        $("pdfResProj").textContent = data.project_id;
        $("pdfResPages").textContent = `${data.watermark_details.protected_pages} of ${data.watermark_details.total_pages}`;
        $("pdfResCreated").textContent = new Date(data.created_at).toLocaleString();
        $("pdfResSha256").textContent = data.sha256;

        const downloadBtn = $("downloadPdfBtn");
        downloadBtn.href = `/download/${data.download_token}`;
        downloadBtn.download = data.filename;

        showElement("pdfResultCard");
        $("pdfResultCard").scrollIntoView({ behavior: "smooth" });

      } catch (err) {
        showError("pdfErrorAlert", "Server error during PDF processing.");
      } finally {
        setTimeout(() => hideElement("pdfProgressCard"), 400);
      }
    });
  }

  // 3. Source Code Protection Form
  const codeForm = $("codeForm");
  if (codeForm) {
    codeForm.addEventListener("submit", async (e) => {
      e.preventDefault();
      hideElement("codeErrorAlert");
      hideElement("codeResultCard");
      showElement("codeProgressCard");
      updateProgressBar("codeProgressBar", 30);

      const formData = new FormData(codeForm);
      try {
        updateProgressBar("codeProgressBar", 65);
        const res = await fetch("/api/watermark/source-code", { method: "POST", body: formData });
        const data = await res.json();
        updateProgressBar("codeProgressBar", 100);

        if (!data.success) {
          showError("codeErrorAlert", data.error || "Source code protection failed.");
          return;
        }

        // Render Result
        $("codeResWmid").textContent = data.watermark_id;
        $("codeResOwner").textContent = data.owner;
        $("codeResProj").textContent = data.project_id;
        $("codeResSha256").textContent = data.sha256;
        $("codeResSigHex").textContent = data.signature_hex;

        const downloadCodeBtn = $("downloadCodeBtn");
        downloadCodeBtn.href = `/download/${data.code_download_token}`;
        downloadCodeBtn.download = data.code_filename;

        const downloadSigBtn = $("downloadSigBtn");
        downloadSigBtn.href = `/download/${data.sig_download_token}`;
        downloadSigBtn.download = data.sig_filename;

        showElement("codeResultCard");
        $("codeResultCard").scrollIntoView({ behavior: "smooth" });

      } catch (err) {
        showError("codeErrorAlert", "Server error during source code protection.");
      } finally {
        setTimeout(() => hideElement("codeProgressCard"), 400);
      }
    });
  }

  // 4. Image Verification Form
  const vImgForm = $("verifyImageForm");
  if (vImgForm) {
    vImgForm.addEventListener("submit", async (e) => {
      e.preventDefault();
      runVerification("/api/verify/image", new FormData(vImgForm));
    });
  }

  // 5. PDF Verification Form
  const vPdfForm = $("verifyPdfForm");
  if (vPdfForm) {
    vPdfForm.addEventListener("submit", async (e) => {
      e.preventDefault();
      runVerification("/api/verify/pdf", new FormData(vPdfForm));
    });
  }

  // 6. Source Code Verification Form
  const vCodeForm = $("verifyCodeForm");
  if (vCodeForm) {
    vCodeForm.addEventListener("submit", async (e) => {
      e.preventDefault();
      runVerification("/api/verify/source-code", new FormData(vCodeForm), true);
    });
  }
}

/* ── Generic Verification Handler ──────────────────────── */
async function runVerification(endpoint, formData, isCode = false) {
  hideElement("vErrorAlert");
  hideElement("vResultCard");
  showElement("vProgressCard");
  updateProgressBar("vProgressBar", 40);

  try {
    updateProgressBar("vProgressBar", 75);
    const res = await fetch(endpoint, { method: "POST", body: formData });
    const data = await res.json();
    updateProgressBar("vProgressBar", 100);

    if (!data.success) {
      showError("vErrorAlert", data.error || "Verification request failed.");
      return;
    }

    // Render Security Verification Report
    renderVerificationReport(data, isCode);
    showElement("vResultCard");
    $("vResultCard").scrollIntoView({ behavior: "smooth" });

  } catch (err) {
    showError("vErrorAlert", "Server error during verification processing.");
  } finally {
    setTimeout(() => hideElement("vProgressCard"), 400);
  }
}

function renderVerificationReport(data, isCode) {
  const banner = $("vStatusBanner");
  const text = $("vStatusText");
  const icon = $("vReportIcon");

  if (data.final_status === "AUTHENTIC") {
    banner.className = "status-banner authentic";
    text.textContent = "✓ AUTHENTIC CONTENT — VERIFIED";
    icon.textContent = "🛡️";
  } else if (data.final_status === "WATERMARK_NOT_FOUND") {
    banner.className = "status-banner failed";
    text.textContent = "✕ WATERMARK NOT FOUND";
    icon.textContent = "⚠️";
  } else {
    banner.className = "status-banner failed";
    text.textContent = "✕ INTEGRITY CHECK FAILED / MODIFICATION DETECTED";
    icon.textContent = "⚠️";
  }

  $("vrContentType").textContent = data.content_type;
  $("vrWmStatus").innerHTML = data.watermark_found
    ? '<span class="badge badge-green">✓ Found</span>'
    : '<span class="badge badge-red">✕ Not Found</span>';

  $("vrWmid").textContent = data.watermark_id || "N/A";
  $("vrOwner").textContent = data.owner || "N/A";
  $("vrProj").textContent = data.project_id || "N/A";
  $("vrSha256").textContent = data.current_sha256 || "N/A";

  $("vrIntegrity").innerHTML = data.integrity_status === "VERIFIED"
    ? '<span class="badge badge-green">✓ VERIFIED</span>'
    : '<span class="badge badge-red">✕ FAILED</span>';

  const sigRow = $("vrSigRow");
  if (isCode && sigRow) {
    sigRow.style.display = "table-row";
    $("vrSigStatus").innerHTML = data.signature_valid
      ? '<span class="badge badge-green">✓ VALID (Ed25519)</span>'
      : '<span class="badge badge-red">✕ INVALID SIGNATURE</span>';
  } else if (sigRow) {
    sigRow.style.display = "none";
  }
}

/* ── UI Helpers ────────────────────────────────────────── */
function showElement(id) {
  const el = $(id);
  if (el) el.style.display = "block";
}

function hideElement(id) {
  const el = $(id);
  if (el) el.style.display = "none";
}

function showError(id, msg) {
  const el = $(id);
  if (el) {
    el.textContent = `⚠️ ${msg}`;
    el.style.display = "block";
  }
}

function updateProgressBar(id, pct) {
  const bar = $(id);
  if (bar) bar.style.width = `${pct}%`;
}
