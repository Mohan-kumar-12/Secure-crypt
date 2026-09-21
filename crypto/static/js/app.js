/**
 * SecureCrypt — Frontend Application Logic
 * Handles all UI interactions, API calls, and state management.
 */

"use strict";

/* ══════════════════════════════════════════════════════════════
   UTILITY FUNCTIONS
════════════════════════════════════════════════════════════════ */

function $(id) { return document.getElementById(id); }

function showEl(id)  { const el = $(id); if (el) el.style.display = ''; }
function hideEl(id)  { const el = $(id); if (el) el.style.display = 'none'; }

function addCls(id, cls)  { const el = $(id); if (el) el.classList.add(cls); }
function remCls(id, cls)  { const el = $(id); if (el) el.classList.remove(cls); }

function fmtBytes(b) {
  if (b < 1024) return b + ' B';
  if (b < 1024 * 1024) return (b / 1024).toFixed(2) + ' KB';
  return (b / (1024 * 1024)).toFixed(2) + ' MB';
}

/** Toggle password field visibility */
function togglePassword(fieldId) {
  const field = $(fieldId);
  if (!field) return;
  field.type = field.type === 'password' ? 'text' : 'password';
}

/** Copy text content of an element to clipboard */
function copyMessage() {
  const msgEl = $('decryptedMessage');
  if (!msgEl) return;
  navigator.clipboard.writeText(msgEl.textContent).then(() => {
    const btn = document.querySelector('[onclick="copyMessage()"]');
    if (btn) { btn.textContent = 'Copied!'; setTimeout(() => { btn.textContent = 'Copy'; }, 2000); }
  });
}

/** Copy password ciphertext to clipboard */
function copyPasswordCiphertext() {
  const pwEl = $('passwordCiphertextDisplay');
  if (!pwEl) return;
  navigator.clipboard.writeText(pwEl.textContent).then(() => {
    const btn = document.querySelector('[onclick="copyPasswordCiphertext()"]');
    if (btn) { btn.textContent = 'Copied!'; setTimeout(() => { btn.textContent = '📋 Copy Ciphertext'; }, 2000); }
  });
}

/* ══════════════════════════════════════════════════════════════
   PASSWORD STRENGTH METER
════════════════════════════════════════════════════════════════ */

function computeStrength(pw) {
  let score = 0;
  if (pw.length >= 8)  score++;
  if (pw.length >= 12) score++;
  if (/[A-Z]/.test(pw)) score++;
  if (/[0-9]/.test(pw)) score++;
  if (/[^A-Za-z0-9]/.test(pw)) score++;
  return score;  // 0-5
}

function updateStrength(pw) {
  const fill  = $('strengthFill');
  const label = $('strengthLabel');
  if (!fill || !label) return;

  const score = computeStrength(pw);
  const pct   = (score / 5) * 100;

  const levels = [
    { color: '#ef4444', text: 'Very Weak',  textColor: '#ef4444' },
    { color: '#f97316', text: 'Weak',       textColor: '#f97316' },
    { color: '#f59e0b', text: 'Fair',       textColor: '#f59e0b' },
    { color: '#10b981', text: 'Good',       textColor: '#10b981' },
    { color: '#10d98e', text: 'Strong',     textColor: '#10d98e' },
    { color: '#00d4ff', text: 'Very Strong',textColor: '#00d4ff' },
  ];
  const lvl = levels[score] || levels[0];

  fill.style.width    = pct + '%';
  fill.style.background = lvl.color;
  label.textContent   = pw ? lvl.text : '';
  label.style.color   = lvl.textColor;
}

/* ══════════════════════════════════════════════════════════════
   DROP ZONE SETUP
════════════════════════════════════════════════════════════════ */

function setupDropZone(dropZoneId, inputId, onFileSelected) {
  const zone  = $(dropZoneId);
  const input = $(inputId);
  if (!zone || !input) return;

  zone.addEventListener('dragover', e => {
    e.preventDefault();
    zone.classList.add('drag-over');
  });
  zone.addEventListener('dragleave', () => zone.classList.remove('drag-over'));
  zone.addEventListener('drop', e => {
    e.preventDefault();
    zone.classList.remove('drag-over');
    const file = e.dataTransfer.files[0];
    if (file) {
      const dt = new DataTransfer();
      dt.items.add(file);
      input.files = dt.files;
      onFileSelected(file);
    }
  });
  input.addEventListener('change', () => {
    if (input.files[0]) onFileSelected(input.files[0]);
  });
}

/* ══════════════════════════════════════════════════════════════
   IMAGE PREVIEW + METADATA (ENCRYPT PAGE)
════════════════════════════════════════════════════════════════ */

function loadCoverImagePreview(file) {
  const reader = new FileReader();
  reader.onload = e => {
    const img = new Image();
    img.onload = () => {
      $('coverPreviewImg').src = e.target.result;
      $('coverPreviewWrapper').classList.add('visible');

      // Display metadata from the browser (approximate before backend analysis)
      $('metaWidth').textContent    = img.naturalWidth + 'px';
      $('metaHeight').textContent   = img.naturalHeight + 'px';
      $('metaChannels').textContent = '3 (RGB)';

      // Estimate capacity: w × h × 3 channels / 8 bits, minus 130-byte header
      const rawBytes   = Math.floor(img.naturalWidth * img.naturalHeight * 3 / 8);
      const usable     = Math.max(0, rawBytes - 130);
      $('metaCapacity').textContent = fmtBytes(usable);

      // Update payload estimate
      updatePayloadEst();
    };
    img.src = e.target.result;
  };
  reader.readAsDataURL(file);
}

function updatePayloadEst() {
  const msgEl    = $('secretMessage');
  const estEl    = $('payloadEst');
  const countEl  = $('charCount');
  if (!msgEl || !estEl) return;

  const chars   = msgEl.value.length;
  const bytes   = new TextEncoder().encode(msgEl.value).length;
  // Payload = header(130) + ciphertext(bytes + 16 GCM tag)
  const payloadEst = 130 + bytes + 16;

  if (countEl) countEl.textContent = chars + ' character' + (chars !== 1 ? 's' : '');
  estEl.textContent = 'Estimated payload: ~' + fmtBytes(payloadEst);
}

/* ══════════════════════════════════════════════════════════════
   PROGRESS STEPS ANIMATION (ENCRYPT)
════════════════════════════════════════════════════════════════ */

const ENCRYPT_STEPS = ['step1','step2','step3','step4','step5','step6','step7','step8','step9'];
let   encryptStepTimer = null;

function startEncryptProgress() {
  $('progressSteps').classList.add('visible');
  let i = 0;

  // Reset all
  ENCRYPT_STEPS.forEach(id => {
    remCls(id, 'active');
    remCls(id, 'done');
  });

  // Animate steps over ~6 seconds (backend takes a few seconds due to PBKDF2)
  function advance() {
    if (i > 0) {
      addCls(ENCRYPT_STEPS[i - 1], 'done');
      remCls(ENCRYPT_STEPS[i - 1], 'active');
    }
    if (i < ENCRYPT_STEPS.length) {
      addCls(ENCRYPT_STEPS[i], 'active');
      i++;
      encryptStepTimer = setTimeout(advance, 900);
    }
  }
  advance();
}

function finishEncryptProgress() {
  clearTimeout(encryptStepTimer);
  ENCRYPT_STEPS.forEach(id => {
    addCls(id, 'done');
    remCls(id, 'active');
  });
}

/* ══════════════════════════════════════════════════════════════
   ENCRYPT FORM
════════════════════════════════════════════════════════════════ */

(function initEncryptPage() {
  const form = $('encryptForm');
  if (!form) return;

  // Drop zone
  setupDropZone('coverDropZone', 'coverImageInput', loadCoverImagePreview);

  // Password strength
  const pwField = $('password');
  if (pwField) pwField.addEventListener('input', () => updateStrength(pwField.value));

  // Confirm password live check
  const cfField = $('confirm');
  if (cfField) {
    cfField.addEventListener('input', () => {
      const hint = $('confirmHint');
      if (!hint) return;
      if (cfField.value && cfField.value !== $('password').value) {
        hint.textContent = '⚠ Passwords do not match';
        hint.style.color = 'var(--danger)';
      } else {
        hint.textContent = cfField.value ? '✓ Passwords match' : '';
        hint.style.color = 'var(--success)';
      }
    });
  }

  // Char counter
  const msgField = $('secretMessage');
  if (msgField) msgField.addEventListener('input', updatePayloadEst);

  // Form submit
  form.addEventListener('submit', async e => {
    e.preventDefault();

    const btn = $('encryptBtn');
    const errDiv = $('encryptError');
    const errMsg = $('encryptErrorMsg');

    // Hide previous results
    hideEl('encryptError');
    $('resultSection').classList.remove('visible');

    // Validate passwords match
    const pw  = $('password').value;
    const cf  = $('confirm').value;
    if (pw !== cf) {
      errMsg.textContent = 'Passwords do not match.';
      showEl('encryptError');
      return;
    }
    if (pw.length < 8) {
      errMsg.textContent = 'Password must be at least 8 characters.';
      showEl('encryptError');
      return;
    }

    btn.disabled = true;
    btn.innerHTML = '<span class="spinner"></span>&ensp;Processing...';
    startEncryptProgress();

    try {
      const data = new FormData(form);
      const resp = await fetch('/api/encrypt', { method: 'POST', body: data });
      const json = await resp.json();

      finishEncryptProgress();

      if (!json.success) {
        errMsg.textContent = json.error || 'Encryption failed.';
        showEl('encryptError');
        return;
      }

      // ── Populate results ──────────────────────────────────────────────────
      // Image thumbnails
      $('originalThumb').src = json.cover_thumb;
      $('stegoThumb').src    = json.stego_thumb;

      // Metrics
      $('mseVal').textContent  = json.metrics.mse;
      $('psnrVal').innerHTML   = json.metrics.psnr + ' <small style="font-size:0.9rem;">dB</small>';
      $('ssimVal').textContent = json.metrics.ssim;

      // Payload analysis
      $('msgSizeDisplay').textContent      = fmtBytes(json.message_size);
      $('payloadSizeDisplay').textContent  = fmtBytes(json.payload_size);
      $('capacityDisplay').textContent     = fmtBytes(json.capacity_bytes);
      $('pctUsedDisplay').textContent      = json.embedding_pct + '%';

      const densityEl = $('densityDisplay');
      const dl = json.density_label;
      densityEl.innerHTML = `<span class="badge badge-${dl === 'Low' ? 'success' : dl === 'Medium' ? 'warning' : 'danger'}">${dl}</span>`;

      $('embeddingBar').style.width = Math.min(100, json.embedding_pct) + '%';

      // SHA-256
      $('sha256Display').textContent = json.sha256_fingerprint;

      // Password Ciphertext
      const pwCipherEl = $('passwordCiphertextDisplay');
      if (pwCipherEl) pwCipherEl.textContent = json.password_ciphertext_formatted || '—';

      // Download
      $('downloadBtn').href = '/download/' + json.download_token;

      $('resultSection').classList.add('visible');
      $('resultSection').scrollIntoView({ behavior: 'smooth', block: 'start' });

    } catch (err) {
      finishEncryptProgress();
      errMsg.textContent = 'Network error. Please check your connection.';
      showEl('encryptError');
    } finally {
      btn.disabled = false;
      btn.innerHTML = 'Encrypt &amp; Hide';
    }
  });
})();

/* ══════════════════════════════════════════════════════════════
   DECRYPT FORM
════════════════════════════════════════════════════════════════ */

const DECRYPT_STEPS = ['dstep1','dstep2','dstep3','dstep4','dstep5','dstep6'];
let   decryptStepTimer = null;

function startDecryptProgress() {
  const ps = $('dProgressSteps');
  if (ps) ps.classList.add('visible');
  let i = 0;
  DECRYPT_STEPS.forEach(id => { remCls(id,'active'); remCls(id,'done'); });

  function advance() {
    if (i > 0) { addCls(DECRYPT_STEPS[i-1],'done'); remCls(DECRYPT_STEPS[i-1],'active'); }
    if (i < DECRYPT_STEPS.length) {
      addCls(DECRYPT_STEPS[i],'active'); i++;
      decryptStepTimer = setTimeout(advance, 800);
    }
  }
  advance();
}

function finishDecryptProgress() {
  clearTimeout(decryptStepTimer);
  DECRYPT_STEPS.forEach(id => { addCls(id,'done'); remCls(id,'active'); });
}

(function initDecryptPage() {
  const form = $('decryptForm');
  if (!form) return;

  // Drop zone
  setupDropZone('stegoDropZone', 'stegoImageInput', file => {
    const reader = new FileReader();
    reader.onload = e => {
      const img = new Image();
      img.onload = () => {
        $('stegoPreviewImg').src = e.target.result;
        $('stegoPreviewWrapper').classList.add('visible');
        $('dMetaWidth').textContent  = img.naturalWidth + '×' + img.naturalHeight;
        $('dMetaHeight').textContent = img.naturalHeight + 'px';
        $('dMetaMode').textContent   = 'PNG';
        $('dMetaSize').textContent   = fmtBytes(file.size);
      };
      img.src = e.target.result;
    };
    reader.readAsDataURL(file);
  });

  form.addEventListener('submit', async e => {
    e.preventDefault();
    const btn    = $('decryptBtn');
    const errDiv = $('decryptError');

    errDiv.style.display = 'none';
    $('decryptResult').classList.remove('visible');

    btn.disabled = true;
    btn.innerHTML = '<span class="spinner"></span>&ensp;Decrypting...';
    startDecryptProgress();

    try {
      const data = new FormData(form);
      const resp = await fetch('/api/decrypt', { method: 'POST', body: data });
      const json = await resp.json();

      finishDecryptProgress();

      if (!json.success) {
        const isAuth = json.authentication_status === 'FAILED';

        if (isAuth) {
          errDiv.innerHTML = `
            <div class="tamper-alert">
              <h3>⚠ SECURITY ALERT</h3>
              <p style="font-size:0.875rem; color:#f87171; margin-bottom:0.75rem;">Payload authentication failed.</p>
              <ul>
                <li>Incorrect password</li>
                <li>Modified or corrupted stego image</li>
                <li>Tampered embedded payload</li>
              </ul>
            </div>`;
        } else {
          errDiv.innerHTML = `
            <div class="alert alert-danger">
              <span class="alert-icon">⚠️</span>
              <span>${json.error || 'Decryption failed.'}</span>
            </div>`;
        }
        errDiv.style.display = '';
        return;
      }

      // ── Populate results ──────────────────────────────────────────────────
      $('decryptedMessage').textContent = json.message;
      $('dPayloadSize').textContent     = fmtBytes(json.payload_size);
      $('dSha256').textContent          = json.sha256_fingerprint || '—';

      const pwEl   = $('pwStatus');
      const skEl   = $('skStatus');
      const authEl = $('authStatus');
      const intEl  = $('integrityStatus');

      if (pwEl) pwEl.innerHTML = json.password_verified ? '<span class="status-verified">✓ VERIFIED</span>' : '<span class="status-failed">✕ FAILED</span>';
      if (skEl) skEl.innerHTML = json.session_key_recovered ? '<span class="status-verified">✓ RECOVERED</span>' : '<span class="status-failed">✕ FAILED</span>';
      if (authEl) authEl.innerHTML = json.authentication_status === 'VERIFIED'
        ? '<span class="status-verified">✓ VERIFIED</span>'
        : '<span class="status-failed">✕ FAILED</span>';
      if (intEl) intEl.innerHTML = json.integrity_status === 'VERIFIED'
        ? '<span class="status-verified">✓ VERIFIED</span>'
        : '<span class="status-failed">✕ FAILED</span>';

      $('decryptResult').classList.add('visible');
      $('decryptResult').scrollIntoView({ behavior: 'smooth', block: 'start' });

    } catch (err) {
      finishDecryptProgress();
      errDiv.innerHTML = `<div class="alert alert-danger"><span class="alert-icon">⚠️</span><span>Network error.</span></div>`;
      errDiv.style.display = '';
    } finally {
      btn.disabled = false;
      btn.innerHTML = 'Extract &amp; Decrypt';
    }
  });
})();

/* ══════════════════════════════════════════════════════════════
   ANALYSIS PAGE
════════════════════════════════════════════════════════════════ */

(function initAnalysisPage() {
  const form = $('analyzeForm');
  if (!form) return;

  setupDropZone('analyzeDropZone', 'analyzeInput', () => {});

  form.addEventListener('submit', async e => {
    e.preventDefault();
    const btn    = $('analyzeBtn');
    const errDiv = $('analyzeError');
    const resDiv = $('analyzeResults');

    errDiv.style.display = 'none';
    resDiv.style.display = 'none';

    btn.disabled = true;
    btn.innerHTML = '<span class="spinner"></span>&ensp;Analyzing...';

    try {
      const data = new FormData(form);
      const resp = await fetch('/api/analyze', { method: 'POST', body: data });
      const json = await resp.json();

      if (!json.success) {
        errDiv.innerHTML = `<div class="alert alert-danger"><span class="alert-icon">⚠️</span><span>${json.error}</span></div>`;
        errDiv.style.display = '';
        return;
      }

      const info = json.image_info;
      $('aWidth').textContent    = info.width + ' × ' + info.height + ' px';
      $('aMode').textContent     = info.mode;
      $('aChannels').textContent = info.channels;
      $('aFileSize').textContent = info.file_size_kb ? info.file_size_kb + ' KB' : '—';
      $('aRawBytes').textContent = fmtBytes(info.raw_bytes);
      $('aUsableKb').textContent = fmtBytes(info.usable_bytes);

      const statusEl = $('aPayloadStatus');
      if (json.payload_detected) {
        statusEl.innerHTML = `<span class="badge badge-success">Payload Detected</span>
          <p style="margin-top:8px; font-size:0.85rem; color:var(--text-secondary);">${json.payload_status}</p>`;
        const fpRow = $('aFingerprintRow');
        if (fpRow) fpRow.style.display = '';
        const fp = $('aFingerprint');
        if (fp) fp.textContent = json.sha256_fingerprint || '—';
      } else {
        statusEl.innerHTML = `<span class="badge badge-warning">No Payload Detected</span>
          <p style="margin-top:8px; font-size:0.85rem; color:var(--text-secondary);">${json.payload_status}</p>`;
      }

      resDiv.style.display = '';

    } catch (err) {
      errDiv.innerHTML = `<div class="alert alert-danger"><span class="alert-icon">⚠️</span><span>Network error.</span></div>`;
      errDiv.style.display = '';
    } finally {
      btn.disabled = false;
      btn.innerHTML = 'Analyze Image';
    }
  });
})();

/* ══════════════════════════════════════════════════════════════
   DIGITAL WATERMARKING & VERIFICATION ENGINE
════════════════════════════════════════════════════════════════ */

(function initWatermarkingModule() {
  document.addEventListener("DOMContentLoaded", () => {
    // 1. Image Watermark
    const imgForm = $('imageWatermarkForm');
    if (imgForm) {
      setupDropZone('imgDropZone', 'imgInput', (file) => {
        const reader = new FileReader();
        reader.onload = (e) => {
          const pImg = $('imgPreviewEl');
          const pBox = $('imgPreviewBox');
          if (pImg && pBox) {
            pImg.src = e.target.result;
            pBox.style.display = 'block';
          }
        };
        reader.readAsDataURL(file);
      });

      imgForm.addEventListener('submit', async e => {
        e.preventDefault();
        hideEl('imgErrorAlert');
        hideEl('imgResultCard');
        showEl('imgProgressCard');

        const formData = new FormData(imgForm);
        try {
          const res = await fetch('/api/watermark/image', { method: 'POST', body: formData });
          const data = await res.json();

          if (!data.success) {
            $('imgErrorAlert').textContent = `⚠️ ${data.error || 'Image watermarking failed.'}`;
            showEl('imgErrorAlert');
            return;
          }

          $('resWmid').textContent = data.watermark_id;
          $('resOwner').textContent = data.owner;
          $('resProj').textContent = data.project_id;
          $('resCreated').textContent = new Date(data.created_at).toLocaleString();
          $('resSha256').textContent = data.sha256;
          if (data.preview_b64) $('resPreviewImg').src = data.preview_b64;

          const downloadBtn = $('downloadImgBtn');
          downloadBtn.href = `/download/watermark/${data.download_token}`;
          downloadBtn.download = data.filename;

          showEl('imgResultCard');
          $('imgResultCard').scrollIntoView({ behavior: 'smooth' });
        } catch (err) {
          $('imgErrorAlert').textContent = '⚠️ Server error during image processing.';
          showEl('imgErrorAlert');
        } finally {
          hideEl('imgProgressCard');
        }
      });
    }

    // 2. PDF Watermark
    const pdfForm = $('pdfWatermarkForm');
    if (pdfForm) {
      setupDropZone('pdfDropZone', 'pdfInput', () => {});
      pdfForm.addEventListener('submit', async e => {
        e.preventDefault();
        hideEl('pdfErrorAlert');
        hideEl('pdfResultCard');
        showEl('pdfProgressCard');

        const formData = new FormData(pdfForm);
        try {
          const res = await fetch('/api/watermark/pdf', { method: 'POST', body: formData });
          const data = await res.json();

          if (!data.success) {
            $('pdfErrorAlert').textContent = `⚠️ ${data.error || 'PDF watermarking failed.'}`;
            showEl('pdfErrorAlert');
            return;
          }

          $('pdfResWmid').textContent = data.watermark_id;
          $('pdfResOwner').textContent = data.owner;
          $('pdfResProj').textContent = data.project_id;
          $('pdfResPages').textContent = `${data.watermark_details.protected_pages} of ${data.watermark_details.total_pages}`;
          $('pdfResCreated').textContent = new Date(data.created_at).toLocaleString();
          $('pdfResSha256').textContent = data.sha256;

          const downloadBtn = $('downloadPdfBtn');
          downloadBtn.href = `/download/watermark/${data.download_token}`;
          downloadBtn.download = data.filename;

          showEl('pdfResultCard');
          $('pdfResultCard').scrollIntoView({ behavior: 'smooth' });
        } catch (err) {
          $('pdfErrorAlert').textContent = '⚠️ Server error during PDF processing.';
          showEl('pdfErrorAlert');
        } finally {
          hideEl('pdfProgressCard');
        }
      });
    }

    // 3. Source Code Protection
    const codeForm = $('codeForm');
    if (codeForm) {
      setupDropZone('codeDropZone', 'codeInput', () => {});
      codeForm.addEventListener('submit', async e => {
        e.preventDefault();
        hideEl('codeErrorAlert');
        hideEl('codeResultCard');
        showEl('codeProgressCard');

        const formData = new FormData(codeForm);
        try {
          const res = await fetch('/api/watermark/source-code', { method: 'POST', body: formData });
          const data = await res.json();

          if (!data.success) {
            $('codeErrorAlert').textContent = `⚠️ ${data.error || 'Source code protection failed.'}`;
            showEl('codeErrorAlert');
            return;
          }

          $('codeResWmid').textContent = data.watermark_id;
          $('codeResOwner').textContent = data.owner;
          $('codeResProj').textContent = data.project_id;
          $('codeResSha256').textContent = data.sha256;
          $('codeResSigHex').textContent = data.signature_hex;

          const downloadCodeBtn = $('downloadCodeBtn');
          downloadCodeBtn.href = `/download/watermark/${data.code_download_token}`;
          downloadCodeBtn.download = data.code_filename;

          const downloadSigBtn = $('downloadSigBtn');
          downloadSigBtn.href = `/download/watermark/${data.sig_download_token}`;
          downloadSigBtn.download = data.sig_filename;

          showEl('codeResultCard');
          $('codeResultCard').scrollIntoView({ behavior: 'smooth' });
        } catch (err) {
          $('codeErrorAlert').textContent = '⚠️ Server error during source code protection.';
          showEl('codeErrorAlert');
        } finally {
          hideEl('codeProgressCard');
        }
      });
    }

    // 4. Verification Forms
    const vImgForm = $('verifyImageForm');
    if (vImgForm) {
      setupDropZone('vImgDropZone', 'vImgInput', () => {});
      vImgForm.addEventListener('submit', e => { e.preventDefault(); runVerification('/api/verify/watermark/image', new FormData(vImgForm)); });
    }

    const vPdfForm = $('verifyPdfForm');
    if (vPdfForm) {
      setupDropZone('vPdfDropZone', 'vPdfInput', () => {});
      vPdfForm.addEventListener('submit', e => { e.preventDefault(); runVerification('/api/verify/watermark/pdf', new FormData(vPdfForm)); });
    }

    const vCodeForm = $('verifyCodeForm');
    if (vCodeForm) {
      setupDropZone('vCodeDropZone', 'vCodeInput', () => {});
      setupDropZone('vSigDropZone', 'vSigInput', () => {});
      vCodeForm.addEventListener('submit', e => { e.preventDefault(); runVerification('/api/verify/watermark/source-code', new FormData(vCodeForm), true); });
    }
  });
})();

async function runVerification(endpoint, formData, isCode = false) {
  hideEl('vErrorAlert');
  hideEl('vResultCard');
  showEl('vProgressCard');

  try {
    const res = await fetch(endpoint, { method: 'POST', body: formData });
    const data = await res.json();

    if (!data.success) {
      $('vErrorAlert').textContent = `⚠️ ${data.error || 'Verification request failed.'}`;
      showEl('vErrorAlert');
      return;
    }

    const banner = $('vStatusBanner');
    const text = $('vStatusText');
    const icon = $('vReportIcon');

    if (data.final_status === 'AUTHENTIC') {
      banner.className = 'status-banner authentic';
      text.textContent = '✓ AUTHENTIC CONTENT — VERIFIED';
      icon.textContent = '🛡️';
    } else if (data.final_status === 'WATERMARK_NOT_FOUND') {
      banner.className = 'status-banner failed';
      text.textContent = '✕ WATERMARK NOT FOUND';
      icon.textContent = '⚠️';
    } else {
      banner.className = 'status-banner failed';
      text.textContent = '✕ INTEGRITY CHECK FAILED / MODIFICATION DETECTED';
      icon.textContent = '⚠️';
    }

    $('vrContentType').textContent = data.content_type;
    $('vrWmStatus').innerHTML = data.watermark_found
      ? '<span class="badge badge-green">✓ Found</span>'
      : '<span class="badge badge-red">✕ Not Found</span>';

    $('vrWmid').textContent = data.watermark_id || 'N/A';
    $('vrOwner').textContent = data.owner || 'N/A';
    $('vrProj').textContent = data.project_id || 'N/A';
    $('vrSha256').textContent = data.current_sha256 || 'N/A';

    $('vrIntegrity').innerHTML = data.integrity_status === 'VERIFIED'
      ? '<span class="badge badge-green">✓ VERIFIED</span>'
      : '<span class="badge badge-red">✕ FAILED</span>';

    const sigRow = $('vrSigRow');
    if (isCode && sigRow) {
      sigRow.style.display = 'table-row';
      $('vrSigStatus').innerHTML = data.signature_valid
        ? '<span class="badge badge-green">✓ VALID (Ed25519)</span>'
        : '<span class="badge badge-red">✕ INVALID SIGNATURE</span>';
    } else if (sigRow) {
      sigRow.style.display = 'none';
    }

    showEl('vResultCard');
    $('vResultCard').scrollIntoView({ behavior: 'smooth' });

  } catch (err) {
    $('vErrorAlert').textContent = '⚠️ Server error during verification processing.';
    showEl('vErrorAlert');
  } finally {
    hideEl('vProgressCard');
  }
}
