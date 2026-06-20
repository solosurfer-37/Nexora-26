/**
 * FCIS — Financial Crime Investigation System
 * app.js — Shared utilities, API layer, and page-specific logic
 *
 * Security notes:
 *  - All dynamic content injected via textContent / safe DOM APIs
 *  - No innerHTML with user/API data
 *  - File-type validation before any submission
 *  - Defensive null/undefined guards throughout
 *  - XSS protection: createTextNode / textContent only
 *  - No inline event handlers in HTML
 *  - fetch() wrapped with timeout + error handling
 */

'use strict';

/* ============================================================
   CONSTANTS
   ============================================================ */
const API_BASE        = '';          // Same-origin; replace with full URL in production
const FETCH_TIMEOUT_MS = 10_000;
const ALLOWED_CSV_MIME = ['text/csv', 'application/vnd.ms-excel', 'text/plain'];
const MAX_FILE_BYTES   = 50 * 1024 * 1024; // 50 MB

/* ============================================================
   DUMMY DATA (for demo / hackathon testing)
   Mirrors the expected API response shapes exactly.
   Remove / replace once a real backend is connected.
   ============================================================ */
const DUMMY = {
  dashboard: {
    totalTransactions:  12_480,
    totalAccounts:        847,
    suspiciousAccounts:    43,
    highestRiskScore:      97,
  },

  riskScores: [
    { account: 'ACC-0047', risk: 97 },
    { account: 'ACC-0193', risk: 92 },
    { account: 'ACC-0312', risk: 88 },
    { account: 'ACC-0081', risk: 83 },
    { account: 'ACC-0556', risk: 79 },
    { account: 'ACC-0204', risk: 74 },
    { account: 'ACC-0731', risk: 68 },
    { account: 'ACC-0418', risk: 61 },
    { account: 'ACC-0097', risk: 55 },
    { account: 'ACC-0623', risk: 49 },
    { account: 'ACC-0142', risk: 41 },
    { account: 'ACC-0889', risk: 33 },
    { account: 'ACC-0275', risk: 22 },
    { account: 'ACC-0364', risk: 14 },
    { account: 'ACC-0711', risk:  8 },
  ],

  graph: {
    nodes: [
      { id: 'ACC-0047', label: 'ACC-0047', risk: 97 },
      { id: 'ACC-0193', label: 'ACC-0193', risk: 92 },
      { id: 'ACC-0312', label: 'ACC-0312', risk: 88 },
      { id: 'ACC-0081', label: 'ACC-0081', risk: 83 },
      { id: 'ACC-0556', label: 'ACC-0556', risk: 79 },
      { id: 'ACC-0204', label: 'ACC-0204', risk: 74 },
      { id: 'ACC-0731', label: 'ACC-0731', risk: 68 },
      { id: 'ACC-0418', label: 'ACC-0418', risk: 61 },
      { id: 'ACC-0097', label: 'ACC-0097', risk: 55 },
      { id: 'ACC-0623', label: 'ACC-0623', risk: 49 },
      { id: 'ACC-0142', label: 'ACC-0142', risk: 41 },
      { id: 'ACC-0889', label: 'ACC-0889', risk: 33 },
    ],
    edges: [
      { from: 'ACC-0047', to: 'ACC-0193', amount: 142_000 },
      { from: 'ACC-0193', to: 'ACC-0312', amount:  87_500 },
      { from: 'ACC-0312', to: 'ACC-0047', amount: 135_000 },
      { from: 'ACC-0081', to: 'ACC-0047', amount:  63_200 },
      { from: 'ACC-0556', to: 'ACC-0193', amount:  29_800 },
      { from: 'ACC-0204', to: 'ACC-0312', amount:  91_000 },
      { from: 'ACC-0731', to: 'ACC-0081', amount:  17_400 },
      { from: 'ACC-0418', to: 'ACC-0556', amount:  44_600 },
      { from: 'ACC-0097', to: 'ACC-0731', amount:  12_300 },
      { from: 'ACC-0623', to: 'ACC-0418', amount:  38_900 },
      { from: 'ACC-0142', to: 'ACC-0623', amount:   9_750 },
      { from: 'ACC-0889', to: 'ACC-0142', amount:  22_100 },
      { from: 'ACC-0047', to: 'ACC-0081', amount:  55_000 },
      { from: 'ACC-0193', to: 'ACC-0556', amount:  71_200 },
    ],
  },

  investigations: {
    'ACC-0047': {
      account:          'ACC-0047',
      risk:              97,
      registeredName:   'Shell Dynamics Ltd.',
      flaggedSince:     '2024-03-12',
      totalVolume:      '$4,820,000',
      txCount:           312,
      jurisdiction:     'Cayman Islands',
      report: `This account exhibits a high-confidence circular transaction pattern across three primary
counterparties (ACC-0193, ACC-0312, ACC-0081), consistent with layering activity in
money laundering typologies. Transaction velocity spiked 340% in the 72 hours preceding
flag detection.

Round-dollar amounts ($142,000 and $135,000) transacted in rapid succession suggest
structuring behaviour designed to avoid automated reporting thresholds. The account's
registered jurisdiction (Cayman Islands) combined with the absence of any verifiable
commercial invoices raises significant concern.

Recommend: immediate SAR filing, account freeze pending judicial review, and cross-reference
with FATF grey-list entities. Confidence score: 97/100.`,
    },
    'ACC-0193': {
      account:          'ACC-0193',
      risk:              92,
      registeredName:   'Vertex Capital LLP',
      flaggedSince:     '2024-04-01',
      totalVolume:      '$2,340,000',
      txCount:           204,
      jurisdiction:     'British Virgin Islands',
      report: `Account ACC-0193 acts as a central relay node in the detected transaction graph, receiving
funds from ACC-0047 and redistributing to ACC-0312 and ACC-0556. This hub-and-spoke
topology is a well-documented obfuscation method.

Three dormant periods of exactly 72 hours were observed between transfer bursts — a
timing pattern consistent with manual oversight of automated layering scripts. Entity
is registered in BVI with a single director sharing registration addresses with two
known shell companies.`,
    },
    'DEFAULT': {
      account:          '—',
      risk:              null,
      registeredName:   '—',
      flaggedSince:     '—',
      totalVolume:      '—',
      txCount:           0,
      jurisdiction:     '—',
      report: null,
    },
  },

  transactions: [
    { id: 'TXN-001', from: 'ACC-0047', to: 'ACC-0193', amount: 142_000, date: '2024-06-01 09:14', status: 'Flagged' },
    { id: 'TXN-002', from: 'ACC-0193', to: 'ACC-0312', amount:  87_500, date: '2024-06-01 11:32', status: 'Flagged' },
    { id: 'TXN-003', from: 'ACC-0312', to: 'ACC-0047', amount: 135_000, date: '2024-06-01 14:55', status: 'Flagged' },
    { id: 'TXN-004', from: 'ACC-0081', to: 'ACC-0047', amount:  63_200, date: '2024-06-02 08:03', status: 'Suspicious' },
    { id: 'TXN-005', from: 'ACC-0556', to: 'ACC-0193', amount:  29_800, date: '2024-06-02 10:47', status: 'Suspicious' },
    { id: 'TXN-006', from: 'ACC-0204', to: 'ACC-0312', amount:  91_000, date: '2024-06-03 13:22', status: 'Flagged' },
    { id: 'TXN-007', from: 'ACC-0731', to: 'ACC-0081', amount:  17_400, date: '2024-06-03 15:09', status: 'Clear' },
    { id: 'TXN-008', from: 'ACC-0418', to: 'ACC-0556', amount:  44_600, date: '2024-06-04 09:55', status: 'Suspicious' },
  ],
};

/* ============================================================
   UTILITIES
   ============================================================ */

/**
 * Safe text setter — never touches innerHTML with external data.
 * @param {Element} el
 * @param {string|number} text
 */
function safeText(el, text) {
  if (!el) return;
  el.textContent = String(text ?? '—');
}

/**
 * Fetch wrapper with timeout and structured error.
 * @param {string} url
 * @param {RequestInit} [options]
 * @returns {Promise<any>}
 */
async function apiFetch(url, options = {}) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), FETCH_TIMEOUT_MS);

  try {
    const response = await fetch(url, { ...options, signal: controller.signal });
    clearTimeout(timer);

    if (!response.ok) {
      throw new Error(`HTTP ${response.status}: ${response.statusText}`);
    }

    const contentType = response.headers.get('content-type') || '';
    if (!contentType.includes('application/json')) {
      throw new Error('Server returned non-JSON response.');
    }

    return await response.json();
  } catch (err) {
    clearTimeout(timer);
    if (err.name === 'AbortError') throw new Error('Request timed out. Check server connectivity.');
    throw err;
  }
}

/**
 * Return risk tier label from a numeric score.
 * @param {number} score  0–100
 * @returns {'critical'|'high'|'medium'|'low'}
 */
function riskTier(score) {
  if (score >= 80) return 'critical';
  if (score >= 60) return 'high';
  if (score >= 40) return 'medium';
  return 'low';
}

/**
 * Return a human-readable risk tier label.
 * @param {number} score
 * @returns {string}
 */
function riskLabel(score) {
  const t = riskTier(score);
  return { critical: 'Critical', high: 'High', medium: 'Medium', low: 'Low' }[t];
}

/**
 * Format a number as currency string (USD).
 * @param {number} n
 * @returns {string}
 */
function formatCurrency(n) {
  if (typeof n !== 'number' || Number.isNaN(n)) return '—';
  return new Intl.NumberFormat('en-US', {
    style:    'currency',
    currency: 'USD',
    maximumFractionDigits: 0,
  }).format(n);
}

/**
 * Format large numbers with locale commas.
 * @param {number} n
 * @returns {string}
 */
function formatNumber(n) {
  if (typeof n !== 'number' || Number.isNaN(n)) return '—';
  return new Intl.NumberFormat('en-US').format(n);
}

/**
 * Show/hide a DOM element by toggling a CSS class.
 * @param {Element} el
 * @param {boolean} visible
 * @param {string} [cls]
 */
function toggleVisible(el, visible, cls = 'visible') {
  if (!el) return;
  el.classList.toggle(cls, visible);
}

/**
 * Create a DOM element with optional text content.
 * NEVER use innerHTML. Build DOM nodes programmatically.
 * @param {string} tag
 * @param {string} [className]
 * @param {string|number} [text]
 * @returns {HTMLElement}
 */
function el(tag, className, text) {
  const node = document.createElement(tag);
  if (className) node.className = className;
  if (text !== undefined) node.textContent = String(text);
  return node;
}

/**
 * Show an error banner with a message.
 * @param {Element} bannerEl
 * @param {string} message
 */
function showError(bannerEl, message) {
  if (!bannerEl) return;
  const span = bannerEl.querySelector('.error-msg');
  if (span) safeText(span, message);
  toggleVisible(bannerEl, true);
}

/**
 * Hide an error banner.
 * @param {Element} bannerEl
 */
function hideError(bannerEl) {
  toggleVisible(bannerEl, false);
}

/* ============================================================
   SIMULATED API (wraps DUMMY data with realistic delay)
   In production: swap each function body to a real apiFetch call.
   ============================================================ */
const SimAPI = {
  async getDashboard() {
    await _delay(480);
    return structuredClone(DUMMY.dashboard);
  },

  async getRiskScores() {
    await _delay(620);
    return structuredClone(DUMMY.riskScores);
  },

  async getGraph() {
    await _delay(700);
    return structuredClone(DUMMY.graph);
  },

  async getInvestigation(accountId) {
    await _delay(550);
    const data = DUMMY.investigations[accountId] ?? DUMMY.investigations['DEFAULT'];
    return structuredClone(data);
  },

  async uploadCSV(file) {
    await _delay(1800);
    // In production: POST multipart/form-data to /api/upload
    return { success: true, jobId: 'JOB-' + Math.random().toString(36).slice(2, 9).toUpperCase() };
  },
};

function _delay(ms) {
  return new Promise(resolve => setTimeout(resolve, ms));
}

/* ============================================================
   PAGE: UPLOAD (index.html)
   ============================================================ */
function initUploadPage() {
  const dropZone     = document.getElementById('drop-zone');
  const fileInput    = document.getElementById('csv-file-input');
  const browseBtn    = document.getElementById('browse-btn');
  const uploadBtn    = document.getElementById('upload-btn');
  const statusEl     = document.getElementById('upload-status');
  const statusIcon   = document.getElementById('status-icon');
  const statusMsg    = document.getElementById('status-msg');
  const fileInfoEl   = document.getElementById('file-selected-info');
  const fileNameEl   = document.getElementById('file-name');
  const fileSizeEl   = document.getElementById('file-size');
  const spinnerEl    = document.getElementById('upload-spinner');

  if (!dropZone || !fileInput || !uploadBtn) return;

  let selectedFile = null;

  /** Validate file: must be .csv and within size limit. */
  function validateFile(file) {
    if (!file) return 'No file provided.';
    const ext = file.name.split('.').pop().toLowerCase();
    if (ext !== 'csv') return `Invalid file type ".${ext}". Only .csv files are accepted.`;
    if (file.size > MAX_FILE_BYTES) return `File too large (${(file.size / 1024 / 1024).toFixed(1)} MB). Max 50 MB.`;
    return null;
  }

  function setSelectedFile(file) {
    const err = validateFile(file);

    if (err) {
      selectedFile = null;
      dropZone.classList.remove('has-file');
      dropZone.classList.add('error-state');
      showStatus('error', '⚠', err);
      toggleVisible(fileInfoEl, false);
      return;
    }

    selectedFile = file;
    dropZone.classList.remove('error-state');
    dropZone.classList.add('has-file');
    showStatus('success', '✓', `File ready: ${file.name}`);

    safeText(fileNameEl, file.name);
    safeText(fileSizeEl, `(${(file.size / 1024).toFixed(1)} KB)`);
    toggleVisible(fileInfoEl, true);

    uploadBtn.disabled = false;
  }

  function clearSelection() {
    selectedFile = null;
    fileInput.value = '';
    dropZone.classList.remove('has-file', 'error-state');
    toggleVisible(fileInfoEl, false);
    hideStatusEl();
    uploadBtn.disabled = true;
  }

  function showStatus(type, iconChar, message) {
    statusEl.className = `upload-status visible status-${type}`;
    safeText(statusIcon, iconChar);
    safeText(statusMsg, message);
  }

  function hideStatusEl() {
    statusEl.className = 'upload-status';
  }

  /* --- Drag-and-drop --- */
  ['dragenter', 'dragover'].forEach(evt =>
    dropZone.addEventListener(evt, e => {
      e.preventDefault();
      dropZone.classList.add('drag-over');
    })
  );

  ['dragleave', 'dragend'].forEach(evt =>
    dropZone.addEventListener(evt, () => dropZone.classList.remove('drag-over'))
  );

  dropZone.addEventListener('drop', e => {
    e.preventDefault();
    dropZone.classList.remove('drag-over');
    const files = e.dataTransfer?.files;
    if (files && files.length > 0) setSelectedFile(files[0]);
  });

  /* --- Click browse --- */
  browseBtn.addEventListener('click', e => {
    e.stopPropagation();
    fileInput.click();
  });

  dropZone.addEventListener('click', () => fileInput.click());

  fileInput.addEventListener('change', () => {
    if (fileInput.files && fileInput.files.length > 0) {
      setSelectedFile(fileInput.files[0]);
    }
  });

  /* --- Upload --- */
  uploadBtn.addEventListener('click', async () => {
    if (!selectedFile) return;

    // Re-validate before sending
    const err = validateFile(selectedFile);
    if (err) { showStatus('error', '⚠', err); return; }

    uploadBtn.disabled = true;
    toggleVisible(spinnerEl, true, 'd-flex');
    showStatus('loading', '', 'Parsing ledger and scoring risk — please wait.');

    // Replace status icon with spinner for loading state
    statusIcon.className = 'spinner';
    statusIcon.textContent = '';

    try {
      const result = await SimAPI.uploadCSV(selectedFile);

      if (result?.success) {
        showStatus('success', '✓',
          `Risk analysis complete — Job ${result.jobId ?? '—'}. Redirecting to dashboard…`);
        statusIcon.className = '';

        setTimeout(() => {
          window.location.href = 'dashboard.html';
        }, 1800);
      } else {
        throw new Error('Upload failed — server returned unsuccessful response.');
      }
    } catch (err) {
      statusIcon.className = '';
      showStatus('error', '⚠', err.message || 'Upload failed. Please try again.');
      uploadBtn.disabled = false;
    } finally {
      spinnerEl.style.display = 'none';
    }
  });

  /* --- Reset on double-click --- */
  dropZone.addEventListener('dblclick', clearSelection);

  // Initial state
  uploadBtn.disabled = true;
}

/* ============================================================
   PAGE: DASHBOARD (dashboard.html)
   ============================================================ */
function initDashboardPage() {
  const errorBanner   = document.getElementById('error-banner');
  const loadingOverlay= document.getElementById('loading-overlay');

  if (!document.getElementById('stat-total-tx')) return; // not on this page

  let allRiskScores  = [];
  let sortDir        = 'desc'; // 'asc' | 'desc'
  let searchQuery    = '';

  /* --- Load stats --- */
  async function loadStats() {
    try {
      const data = await SimAPI.getDashboard();

      safeText(document.getElementById('stat-total-tx'),       formatNumber(data.totalTransactions));
      safeText(document.getElementById('stat-total-acc'),      formatNumber(data.totalAccounts));
      safeText(document.getElementById('stat-suspicious'),     formatNumber(data.suspiciousAccounts));
      safeText(document.getElementById('stat-highest-risk'),   data.highestRiskScore ?? '—');

    } catch (err) {
      showError(errorBanner, `Failed to load dashboard stats: ${err.message}`);
    }
  }

  /* --- Load risk scores table --- */
  async function loadRiskTable() {
    const tbody = document.getElementById('risk-table-body');
    if (!tbody) return;

    showSkeletonRows(tbody, 6);

    try {
      const scores = await SimAPI.getRiskScores();
      allRiskScores = Array.isArray(scores) ? scores : [];
      renderTable();
    } catch (err) {
      showError(errorBanner, `Failed to load risk scores: ${err.message}`);
      tbody.innerHTML = '';
      const emptyRow = tbody.insertRow();
      const cell = emptyRow.insertCell();
      cell.colSpan = 3;
      cell.className = 'text-center';
      safeText(cell, 'Failed to load data. Refresh to retry.');
    }
  }

  function showSkeletonRows(tbody, count) {
    tbody.innerHTML = '';
    for (let i = 0; i < count; i++) {
      const row = tbody.insertRow();
      row.className = 'skeleton-row';
      for (let j = 0; j < 3; j++) {
        const td = row.insertCell();
        const sk = el('div', 'skeleton skeleton-cell');
        sk.style.width = j === 0 ? '90px' : j === 1 ? '140px' : '70px';
        td.appendChild(sk);
      }
    }
  }

  function renderTable() {
    const tbody = document.getElementById('risk-table-body');
    const emptyState = document.getElementById('table-empty');
    if (!tbody) return;

    // Filter
    let filtered = allRiskScores.filter(item => {
      if (!searchQuery) return true;
      return (item.account ?? '').toLowerCase().includes(searchQuery.toLowerCase());
    });

    // Sort
    filtered.sort((a, b) => sortDir === 'desc' ? b.risk - a.risk : a.risk - b.risk);

    tbody.innerHTML = '';

    if (filtered.length === 0) {
      toggleVisible(emptyState, true);
      return;
    }

    toggleVisible(emptyState, false);

    filtered.forEach((item, idx) => {
      const row = tbody.insertRow();
      row.style.cursor = 'pointer';

      // Rank cell
      const rankCell = row.insertCell();
      rankCell.className = 'mono-cell';
      safeText(rankCell, String(idx + 1).padStart(2, '0'));
      rankCell.style.color = 'var(--text-muted)';
      rankCell.style.fontFamily = 'var(--font-mono)';
      rankCell.style.fontSize = '12px';

      // Account cell
      const accCell = row.insertCell();
      const link = el('a', 'account-link', item.account ?? '—');
      link.href = `investigation.html?account=${encodeURIComponent(item.account ?? '')}`;
      link.addEventListener('click', e => e.stopPropagation());
      accCell.appendChild(link);

      // Risk cell
      const riskCell = row.insertCell();
      const tier = riskTier(item.risk);
      const wrap = el('div', 'risk-bar-wrap');
      const track = el('div', 'risk-bar-track');
      const fill = el('div', `risk-bar-fill fill-${tier}`);
      fill.style.width = `${Math.min(100, Math.max(0, item.risk))}%`;
      track.appendChild(fill);

      const scoreSpan = el('span', `risk-score-num`, item.risk);
      scoreSpan.style.color = `var(--${tier === 'critical' ? 'danger' : tier === 'high' ? 'warning' : tier === 'medium' ? 'info' : 'safe'})`;

      const badge = el('span', `fcis-badge badge-${tier}`, riskLabel(item.risk));
      wrap.appendChild(track);
      wrap.appendChild(scoreSpan);
      wrap.appendChild(badge);
      riskCell.appendChild(wrap);

      // Row click → investigation
      row.addEventListener('click', () => {
        window.location.href = `investigation.html?account=${encodeURIComponent(item.account ?? '')}`;
      });
    });
  }

  /* --- Search --- */
  const searchInput = document.getElementById('account-search');
  if (searchInput) {
    searchInput.addEventListener('input', () => {
      searchQuery = searchInput.value ?? '';
      renderTable();
    });
  }

  /* --- Sort buttons --- */
  document.querySelectorAll('.sort-btn').forEach(btn => {
    btn.addEventListener('click', () => {
      const dir = btn.dataset.sort;
      if (!dir) return;
      sortDir = dir;
      document.querySelectorAll('.sort-btn').forEach(b => b.classList.remove('sort-active'));
      btn.classList.add('sort-active');
      renderTable();
    });
  });

  /* --- Init --- */
  (async () => {
    toggleVisible(loadingOverlay, true);
    await Promise.all([loadStats(), loadRiskTable()]);
    toggleVisible(loadingOverlay, false);
  })();
}

/* ============================================================
   PAGE: INVESTIGATION (investigation.html)
   ============================================================ */
function initInvestigationPage() {
  if (!document.getElementById('network-graph')) return;

  const errorBanner    = document.getElementById('error-banner');
  const loadingOverlay = document.getElementById('loading-overlay');
  const accountIdEl    = document.getElementById('selected-account-id');
  const riskBadgeEl    = document.getElementById('selected-risk-badge');
  const reportTextEl   = document.getElementById('ai-report-text');
  const reportPlacEl   = document.getElementById('report-placeholder');
  const noSelectionEl  = document.getElementById('no-selection-state');
  const detailsBodyEl  = document.getElementById('account-details-body');
  const txTbodyEl      = document.getElementById('tx-table-body');
  const txEmptyEl      = document.getElementById('tx-empty');

  let network = null;
  let graphData = { nodes: [], edges: [] };
  let selectedNodeId = null;

  /* Parse ?account= from URL safely */
  function getAccountParam() {
    try {
      const params = new URLSearchParams(window.location.search);
      const raw = params.get('account') ?? '';
      // Sanitise: only allow safe characters
      return raw.replace(/[^a-zA-Z0-9\-_]/g, '').slice(0, 64);
    } catch {
      return '';
    }
  }

  const preselectedAccount = getAccountParam();

  /* --- Build vis-network color from risk tier --- */
  function nodeStyle(risk) {
    const t = riskTier(risk ?? 0);
    const styles = {
      critical: { background: '#241516', border: '#E05353', font: '#F0A8A8', shadow: true },
      high:     { background: '#241B14', border: '#D17A4A', font: '#E5B690', shadow: false },
      medium:   { background: '#241F14', border: '#DF9F4F', font: '#EEC988', shadow: false },
      low:      { background: '#12201B', border: '#52A47F', font: '#8FCBAA', shadow: false },
    };
    return styles[t] || styles.low;
  }

  /* --- Load & render graph --- */
  async function loadGraph() {
    try {
      const data = await SimAPI.getGraph();

      if (!data || !Array.isArray(data.nodes) || !Array.isArray(data.edges)) {
        throw new Error('Invalid graph data received from server.');
      }

      graphData = data;

      const visNodes = data.nodes.map(n => {
        const s = nodeStyle(n.risk ?? 0);
        return {
          id:    n.id,
          label: n.label ?? n.id,
          color: {
            background: s.background,
            border:     s.border,
            highlight:  { background: s.background, border: '#ffffff' },
            hover:      { background: s.background, border: '#ffffff' },
          },
          font:       { color: s.font, size: 12, face: 'JetBrains Mono' },
          shape:      'dot',
          size:       14 + Math.floor((n.risk ?? 0) / 15),
          borderWidth: 2,
          shadow:     s.shadow ? { enabled: true, color: '#E0535380', size: 12 } : false,
          title:      `${n.id} — Risk: ${n.risk ?? '?'}`,
          risk:       n.risk ?? 0,
        };
      });

      const visEdges = data.edges.map((e, idx) => ({
        id:    `edge-${idx}`,
        from:  e.from,
        to:    e.to,
        label: e.amount ? formatCurrency(e.amount) : '',
        value: e.amount || 1,
        font:  { color: '#6E7683', size: 9, face: 'JetBrains Mono', align: 'middle', strokeWidth: 0 },
        color: { color: '#323847', highlight: '#5B7C99', hover: '#5B7C99' },
        arrows:{ to: { enabled: true, scaleFactor: 0.6 } },
        smooth: { enabled: true, type: 'continuous', roundness: 0.45 },
      }));

      const container = document.getElementById('network-graph');

      const options = {
        interaction: {
          hover:         true,
          tooltipDelay:  150,
          zoomView:      true,
          dragView:      true,
          dragNodes:     true,
          keyboard:      { enabled: false },
        },
        physics: {
          enabled: true,
          solver:  'forceAtlas2Based',
          forceAtlas2Based: {
            gravitationalConstant: -52,
            centralGravity:         0.008,
            springLength:           140,
            springConstant:         0.06,
            damping:                0.65,
          },
          stabilization: { iterations: 180, updateInterval: 25 },
        },
        edges: {
          smooth:  { enabled: true, type: 'continuous', roundness: 0.45 },
          scaling: { min: 1, max: 6 },
        },
        nodes: {
          scaling: { min: 10, max: 30 },
        },
        layout: { improvedLayout: true },
      };

      const visDataNodes = new vis.DataSet(visNodes);
      const visDataEdges = new vis.DataSet(visEdges);

      network = new vis.Network(container, { nodes: visDataNodes, edges: visDataEdges }, options);

      /* Gentle hover scaling — node grows softly on hover, settles back on blur */
      const baseSizes = new Map(visNodes.map(n => [n.id, n.size]));
      network.on('hoverNode', params => {
        const base = baseSizes.get(params.node);
        if (base != null) visDataNodes.update({ id: params.node, size: base * 1.18 });
      });
      network.on('blurNode', params => {
        const base = baseSizes.get(params.node);
        if (base != null) visDataNodes.update({ id: params.node, size: base });
      });

      /* Node selection handler */
      network.on('selectNode', params => {
        const nodeId = params.nodes?.[0];
        if (!nodeId) return;
        selectedNodeId = nodeId;
        loadNodeDetails(nodeId);
        filterTransactions(nodeId);
      });

      network.on('deselectNode', () => {
        selectedNodeId = null;
        resetDetailsPanel();
      });

      /* Zoom controls */
      document.getElementById('graph-zoom-in')?.addEventListener('click', () =>
        network.moveTo({ scale: network.getScale() * 1.25, animation: { duration: 200 } })
      );
      document.getElementById('graph-zoom-out')?.addEventListener('click', () =>
        network.moveTo({ scale: network.getScale() * 0.8, animation: { duration: 200 } })
      );
      document.getElementById('graph-fit')?.addEventListener('click', () =>
        network.fit({ animation: { duration: 400 } })
      );

      /* If URL has account param, select that node */
      if (preselectedAccount && data.nodes.some(n => n.id === preselectedAccount)) {
        setTimeout(() => {
          network.selectNodes([preselectedAccount]);
          network.focus(preselectedAccount, { scale: 1.4, animation: { duration: 600 } });
          loadNodeDetails(preselectedAccount);
          filterTransactions(preselectedAccount);
        }, 800);
      }

    } catch (err) {
      showError(errorBanner, `Graph load failed: ${err.message}`);
    }
  }

  /* --- Load account details + AI report --- */
  async function loadNodeDetails(accountId) {
    if (!accountId) return;

    toggleVisible(noSelectionEl, false);

    // Show loading state in details
    if (detailsBodyEl) {
      detailsBodyEl.innerHTML = '';
      const loadMsg = el('p', 'report-placeholder', '⏳ Loading entity profile…');
      detailsBodyEl.appendChild(loadMsg);
    }

    if (reportTextEl)  reportTextEl.textContent = '';
    toggleVisible(reportPlacEl, false);

    try {
      const inv = await SimAPI.getInvestigation(accountId);

      renderAccountDetails(inv);
      renderReport(inv);
    } catch (err) {
      showError(errorBanner, `Investigation load failed: ${err.message}`);
    }
  }

  function renderAccountDetails(inv) {
    if (!inv || !detailsBodyEl) return;

    detailsBodyEl.innerHTML = '';

    const rows = [
      { label: 'Account ID',     value: inv.account      ?? '—' },
      { label: 'Registered Name',value: inv.registeredName ?? '—' },
      { label: 'Jurisdiction',   value: inv.jurisdiction  ?? '—' },
      { label: 'Flagged Since',  value: inv.flaggedSince  ?? '—' },
      { label: 'Total Volume',   value: inv.totalVolume   ?? '—' },
      { label: 'Transaction Count', value: inv.txCount != null ? formatNumber(inv.txCount) : '—' },
    ];

    rows.forEach(r => {
      const row = el('div', 'detail-row');
      const lbl = el('span', 'detail-label', r.label);
      const val = el('span', 'detail-value', r.value);
      row.appendChild(lbl);
      row.appendChild(val);
      detailsBodyEl.appendChild(row);
    });

    // Risk badge
    if (accountIdEl) safeText(accountIdEl, inv.account ?? '—');
    if (riskBadgeEl && inv.risk != null) {
      const tier  = riskTier(inv.risk);
      riskBadgeEl.className = `fcis-badge badge-${tier}`;
      riskBadgeEl.textContent = `Risk: ${inv.risk} — ${riskLabel(inv.risk)}`;
    }
  }

  function renderReport(inv) {
    if (!inv) return;

    if (inv.report) {
      safeText(reportTextEl, inv.report);
      toggleVisible(reportPlacEl, false);
    } else {
      safeText(reportTextEl, '');
      toggleVisible(reportPlacEl, true);
      if (reportPlacEl) safeText(reportPlacEl, 'Select an entity to generate its investigation report.');
    }
  }

  function resetDetailsPanel() {
    if (noSelectionEl) toggleVisible(noSelectionEl, true);
    if (detailsBodyEl) detailsBodyEl.innerHTML = '';
    if (accountIdEl)   safeText(accountIdEl, '—');
    if (riskBadgeEl)   { riskBadgeEl.className = 'fcis-badge'; riskBadgeEl.textContent = ''; }
    if (reportTextEl)  reportTextEl.textContent = '';
    if (reportPlacEl)  {
      toggleVisible(reportPlacEl, true);
      safeText(reportPlacEl, 'Select an entity to generate its investigation report.');
    }
  }

  /* --- Transaction table --- */
  function filterTransactions(accountId) {
    if (!txTbodyEl) return;
    const filtered = accountId
      ? DUMMY.transactions.filter(t => t.from === accountId || t.to === accountId)
      : DUMMY.transactions;
    renderTransactions(filtered);
  }

  function renderTransactions(list) {
    if (!txTbodyEl) return;
    txTbodyEl.innerHTML = '';

    if (!list || list.length === 0) {
      toggleVisible(txEmptyEl, true);
      return;
    }

    toggleVisible(txEmptyEl, false);

    list.forEach(tx => {
      const row = txTbodyEl.insertRow();

      const cells = [
        { val: tx.id     ?? '—', cls: 'mono-cell' },
        { val: tx.from   ?? '—', cls: 'mono-cell' },
        { val: tx.to     ?? '—', cls: 'mono-cell' },
        { val: typeof tx.amount === 'number' ? formatCurrency(tx.amount) : '—', cls: 'mono-cell' },
        { val: tx.date   ?? '—', cls: 'mono-cell' },
        { val: null,             cls: '' }, // status badge — built separately
      ];

      cells.forEach((c, i) => {
        const td = row.insertCell();
        if (c.cls) td.className = c.cls;

        if (i === 5) {
          // Status badge
          const tier =
            tx.status === 'Flagged'    ? 'critical' :
            tx.status === 'Suspicious' ? 'high'     :
            'low';
          const badge = el('span', `fcis-badge badge-${tier}`, tx.status ?? '—');
          td.appendChild(badge);
        } else {
          safeText(td, c.val);
        }
      });
    });
  }

  /* --- Init --- */
  (async () => {
    toggleVisible(loadingOverlay, true);

    renderTransactions(DUMMY.transactions);
    resetDetailsPanel();

    await loadGraph();

    toggleVisible(loadingOverlay, false);

    if (preselectedAccount) {
      safeText(document.getElementById('page-account-label'), preselectedAccount);
    }
  })();
}

/* ============================================================
   ROUTER — call the right init function based on current page
   ============================================================ */
function route() {
  const path = window.location.pathname;

  if (path.endsWith('index.html') || path === '/' || path.endsWith('/')) {
    initUploadPage();
  } else if (path.endsWith('dashboard.html')) {
    initDashboardPage();
  } else if (path.endsWith('investigation.html')) {
    initInvestigationPage();
  }
}

document.addEventListener('DOMContentLoaded', route);
