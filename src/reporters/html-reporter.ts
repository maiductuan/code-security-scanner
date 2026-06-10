// ─── HTML Reporter ─────────────────────────────────────────────────────────
// Generates a beautiful, self-contained single HTML file with embedded CSS/JS.
// Dark theme, modern design, interactive dashboard with filtering and search.

import type { ScanResult, Finding, Severity } from '../types/finding.js';
import type { OutputFormat } from '../types/config.js';
import { BaseReporter } from './base-reporter.js';

/** Severity colour palette for the dark theme */
const SEVERITY_COLORS: Record<Severity, string> = {
  critical: '#f85149',
  high: '#f97583',
  medium: '#e3b341',
  low: '#58a6ff',
};

/**
 * HTML Reporter – generates a premium, self-contained HTML report.
 *
 * Features:
 * - Fully self-contained (no CDN links, no external dependencies)
 * - Dark theme with GitHub-inspired colour palette
 * - Dashboard summary cards with severity breakdown
 * - CSS-only severity distribution bar chart
 * - Interactive findings table with sort, filter, and search
 * - Expandable rows showing code snippets and fix suggestions
 * - Responsive design using CSS Grid & Flexbox
 */
export class HtmlReporter extends BaseReporter {
  readonly format: OutputFormat = 'html';

  async generate(result: ScanResult): Promise<string> {
    const findingsJson = JSON.stringify(
      result.findings.map((f) => this.serializeFinding(f)),
    ).replace(/<\/script/gi, '<\\/script');
    const summaryJson = JSON.stringify(result.summary).replace(/<\/script/gi, '<\\/script');

    return `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>DeepScan Security Report</title>
${this.renderStyles()}
</head>
<body>
${this.renderHeaderHtml(result)}
${this.renderDashboard(result)}
${this.renderSeverityChart(result)}
<div class="container">
  ${this.renderFilters(result)}
  <div class="table-wrap">
    <table id="findings-table">
      <thead>
        <tr>
          <th class="th-expand"></th>
          <th class="sortable" data-sort="severity">Severity <span class="sort-icon">⇅</span></th>
          <th class="sortable" data-sort="file">File <span class="sort-icon">⇅</span></th>
          <th>Line</th>
          <th class="sortable" data-sort="rule">Rule <span class="sort-icon">⇅</span></th>
          <th class="sortable" data-sort="category">Category <span class="sort-icon">⇅</span></th>
          <th>Confidence</th>
          <th>Title</th>
        </tr>
      </thead>
      <tbody id="findings-body"></tbody>
    </table>
    <div id="no-results" class="no-results" style="display:none;">
      <span class="no-results-icon">🔍</span>
      <p>No findings match the current filters.</p>
    </div>
  </div>
</div>
${this.renderFooter(result)}
<script>
// ── Embedded Data ──
const FINDINGS = ${findingsJson};
const SUMMARY = ${summaryJson};
${this.renderScript()}
</script>
</body>
</html>`;
  }

  // ── HTML Fragments ─────────────────────────────────────────────────────

  private renderHeaderHtml(result: ScanResult): string {
    return `
<header class="header">
  <div class="header-inner">
    <div class="logo-group">
      <div class="logo-icon">
        <svg viewBox="0 0 32 32" fill="none" xmlns="http://www.w3.org/2000/svg">
          <rect width="32" height="32" rx="8" fill="#238636"/>
          <path d="M16 6L26 12V20L16 26L6 20V12L16 6Z" stroke="white" stroke-width="2" fill="none"/>
          <circle cx="16" cy="16" r="4" fill="white"/>
        </svg>
      </div>
      <div>
        <h1 class="logo-text">DeepScan</h1>
        <p class="logo-sub">Security Report</p>
      </div>
    </div>
    <div class="header-meta">
      <div class="meta-item"><span class="meta-label">Target</span><span class="meta-value">${this.escapeHtml(result.target)}</span></div>
      <div class="meta-item"><span class="meta-label">Scanned</span><span class="meta-value">${this.escapeHtml(result.summary.timestamp)}</span></div>
      <div class="meta-item"><span class="meta-label">Duration</span><span class="meta-value">${this.formatDuration(result.summary.scanDuration)}</span></div>
    </div>
  </div>
</header>`;
  }

  private renderDashboard(result: ScanResult): string {
    const s = result.summary;
    const severities: Severity[] = ['critical', 'high', 'medium', 'low'];

    const cards = severities
      .map(
        (sev) => `
      <div class="card card-${sev}">
        <div class="card-count">${s.bySeverity[sev]}</div>
        <div class="card-label">${sev.charAt(0).toUpperCase() + sev.slice(1)}</div>
        <div class="card-badge" style="background:${SEVERITY_COLORS[sev]}">${sev.toUpperCase()}</div>
      </div>`,
      )
      .join('');

    return `
<section class="dashboard container">
  <div class="summary-cards">
    <div class="card card-total">
      <div class="card-count">${s.totalFindings}</div>
      <div class="card-label">Total Findings</div>
      <div class="card-sub">${s.filesScanned} files scanned · ${s.filesWithFindings} with findings</div>
    </div>
    ${cards}
  </div>
</section>`;
  }

  private renderSeverityChart(result: ScanResult): string {
    const s = result.summary;
    const total = s.totalFindings || 1;
    const severities: Severity[] = ['critical', 'high', 'medium', 'low'];

    const segments = severities
      .map((sev) => {
        const pct = ((s.bySeverity[sev] / total) * 100).toFixed(1);
        return Number(pct) > 0
          ? `<div class="chart-seg" style="width:${pct}%;background:${SEVERITY_COLORS[sev]}" title="${sev}: ${s.bySeverity[sev]} (${pct}%)"></div>`
          : '';
      })
      .join('');

    const legend = severities
      .map(
        (sev) =>
          `<span class="legend-item"><span class="legend-dot" style="background:${SEVERITY_COLORS[sev]}"></span>${sev} (${s.bySeverity[sev]})</span>`,
      )
      .join('');

    return `
<section class="chart-section container">
  <h2 class="section-title">Severity Distribution</h2>
  <div class="chart-bar">${segments}</div>
  <div class="chart-legend">${legend}</div>
</section>`;
  }

  private renderFilters(result: ScanResult): string {
    // Collect unique scanners and categories
    const scanners = [...new Set(result.findings.map((f) => f.scanner))].sort();
    const categories = [...new Set(result.findings.map((f) => f.category))].sort();

    const scannerOptions = scanners
      .map((s) => `<option value="${this.escapeHtml(s)}">${this.escapeHtml(s)}</option>`)
      .join('');
    const categoryOptions = categories
      .map((c) => `<option value="${this.escapeHtml(c)}">${this.escapeHtml(c)}</option>`)
      .join('');

    return `
  <div class="filters">
    <div class="search-box">
      <input type="text" id="search-input" placeholder="Search findings…" autocomplete="off" />
    </div>
    <div class="filter-group">
      <select id="filter-severity">
        <option value="">All Severities</option>
        <option value="critical">Critical</option>
        <option value="high">High</option>
        <option value="medium">Medium</option>
        <option value="low">Low</option>
      </select>
      <select id="filter-scanner">
        <option value="">All Scanners</option>
        ${scannerOptions}
      </select>
      <select id="filter-category">
        <option value="">All Categories</option>
        ${categoryOptions}
      </select>
      <button id="btn-reset" class="btn-reset" title="Reset filters">✕ Reset</button>
    </div>
  </div>`;
  }

  private renderFooter(result: ScanResult): string {
    return `
<footer class="footer">
  <div class="footer-inner">
    <span>${this.escapeHtml(result.tool.name)} v${this.escapeHtml(result.tool.version)}</span>
    <span>Report generated ${new Date().toISOString()}</span>
  </div>
</footer>`;
  }

  // ── CSS ────────────────────────────────────────────────────────────────

  private renderStyles(): string {
    return `<style>
/* ── Reset & Base ─────────────────────────────────────────────────── */
*,*::before,*::after{box-sizing:border-box;margin:0;padding:0}
html{font-size:14px;-webkit-font-smoothing:antialiased}
body{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Helvetica,Arial,sans-serif;
  background:#0d1117;color:#c9d1d9;line-height:1.6;min-height:100vh}
a{color:#58a6ff;text-decoration:none}
a:hover{text-decoration:underline}

/* ── Container ────────────────────────────────────────────────────── */
.container{max-width:1280px;margin:0 auto;padding:0 24px}

/* ── Header ───────────────────────────────────────────────────────── */
.header{background:#161b22;border-bottom:1px solid #30363d;padding:20px 0}
.header-inner{max-width:1280px;margin:0 auto;padding:0 24px;display:flex;
  align-items:center;justify-content:space-between;flex-wrap:wrap;gap:16px}
.logo-group{display:flex;align-items:center;gap:12px}
.logo-icon svg{width:40px;height:40px}
.logo-text{font-size:1.5rem;font-weight:700;color:#fff;line-height:1.2}
.logo-sub{font-size:.85rem;color:#8b949e}
.header-meta{display:flex;gap:24px;flex-wrap:wrap}
.meta-item{display:flex;flex-direction:column}
.meta-label{font-size:.7rem;text-transform:uppercase;color:#8b949e;letter-spacing:.05em}
.meta-value{color:#e6edf3;font-weight:500;font-size:.9rem}

/* ── Dashboard Cards ──────────────────────────────────────────────── */
.dashboard{padding-top:24px}
.summary-cards{display:grid;grid-template-columns:repeat(auto-fit,minmax(180px,1fr));gap:16px}
.card{background:#161b22;border:1px solid #30363d;border-radius:12px;padding:20px;
  text-align:center;position:relative;overflow:hidden;transition:transform .15s,box-shadow .15s}
.card:hover{transform:translateY(-2px);box-shadow:0 8px 24px rgba(0,0,0,.4)}
.card-total{grid-column:span 1}
.card-count{font-size:2.4rem;font-weight:700;color:#fff}
.card-label{font-size:.9rem;color:#8b949e;margin-top:2px}
.card-sub{font-size:.75rem;color:#484f58;margin-top:6px}
.card-badge{display:inline-block;margin-top:8px;padding:2px 10px;border-radius:20px;
  font-size:.65rem;font-weight:700;color:#fff;letter-spacing:.05em}
.card-critical{border-top:3px solid ${SEVERITY_COLORS.critical}}
.card-high{border-top:3px solid ${SEVERITY_COLORS.high}}
.card-medium{border-top:3px solid ${SEVERITY_COLORS.medium}}
.card-low{border-top:3px solid ${SEVERITY_COLORS.low}}

/* ── Chart ─────────────────────────────────────────────────────────── */
.chart-section{padding:28px 24px}
.section-title{font-size:1rem;font-weight:600;color:#e6edf3;margin-bottom:12px}
.chart-bar{display:flex;height:28px;border-radius:6px;overflow:hidden;background:#21262d}
.chart-seg{transition:width .4s ease}
.chart-legend{display:flex;gap:16px;margin-top:10px;flex-wrap:wrap}
.legend-item{display:flex;align-items:center;gap:5px;font-size:.8rem;color:#8b949e}
.legend-dot{width:10px;height:10px;border-radius:50%;display:inline-block}

/* ── Filters ──────────────────────────────────────────────────────── */
.filters{display:flex;flex-wrap:wrap;gap:12px;padding:20px 0;align-items:center}
.search-box{flex:1;min-width:220px}
.search-box input{width:100%;padding:8px 14px;border-radius:8px;border:1px solid #30363d;
  background:#0d1117;color:#c9d1d9;font-size:.9rem;outline:none;transition:border-color .2s}
.search-box input:focus{border-color:#58a6ff}
.filter-group{display:flex;gap:8px;flex-wrap:wrap;align-items:center}
.filter-group select{padding:8px 12px;border-radius:8px;border:1px solid #30363d;
  background:#161b22;color:#c9d1d9;font-size:.85rem;cursor:pointer;outline:none}
.filter-group select:focus{border-color:#58a6ff}
.btn-reset{padding:8px 14px;border-radius:8px;border:1px solid #30363d;background:#161b22;
  color:#f85149;font-size:.85rem;cursor:pointer;transition:background .15s}
.btn-reset:hover{background:#21262d}

/* ── Table ─────────────────────────────────────────────────────────── */
.table-wrap{overflow-x:auto;border:1px solid #30363d;border-radius:12px;margin-bottom:32px}
table{width:100%;border-collapse:collapse}
thead th{background:#161b22;color:#8b949e;font-weight:600;font-size:.8rem;
  text-transform:uppercase;letter-spacing:.04em;padding:12px 14px;text-align:left;
  position:sticky;top:0;border-bottom:1px solid #30363d;white-space:nowrap;user-select:none}
th.sortable{cursor:pointer}
th.sortable:hover{color:#e6edf3}
.sort-icon{font-size:.7rem;opacity:.5}
th.sort-active .sort-icon{opacity:1;color:#58a6ff}
tbody tr{border-bottom:1px solid #21262d;transition:background .1s}
tbody tr:hover{background:#161b22}
tbody td{padding:10px 14px;font-size:.88rem;vertical-align:top}
.th-expand{width:32px}

/* ── Severity badges ──────────────────────────────────────────────── */
.badge{display:inline-block;padding:2px 10px;border-radius:20px;font-size:.75rem;
  font-weight:700;color:#fff;letter-spacing:.03em;text-transform:uppercase}
.badge-critical{background:${SEVERITY_COLORS.critical}}
.badge-high{background:${SEVERITY_COLORS.high}}
.badge-medium{background:${SEVERITY_COLORS.medium}}
.badge-low{background:${SEVERITY_COLORS.low}}
.confidence-badge{font-size:.75rem;color:#8b949e;border:1px solid #30363d;
  padding:1px 8px;border-radius:12px}

/* ── Expand toggle ─────────────────────────────────────────────────── */
.expand-btn{width:24px;height:24px;border:none;background:#21262d;color:#8b949e;
  border-radius:6px;cursor:pointer;font-size:.8rem;display:flex;align-items:center;
  justify-content:center;transition:transform .2s,background .15s}
.expand-btn:hover{background:#30363d}
.expand-btn.open{transform:rotate(90deg);color:#58a6ff}

/* ── Detail row ────────────────────────────────────────────────────── */
.detail-row td{padding:0 !important;border-bottom:1px solid #21262d}
.detail-content{padding:16px 24px;background:#0d1117;display:none;animation:fadeIn .2s ease}
.detail-content.open{display:block}
.detail-section{margin-bottom:14px}
.detail-section:last-child{margin-bottom:0}
.detail-section h4{font-size:.8rem;color:#58a6ff;text-transform:uppercase;
  letter-spacing:.05em;margin-bottom:6px}
.snippet-block{background:#161b22;border:1px solid #30363d;border-radius:8px;
  padding:12px 16px;overflow-x:auto;font-family:'SFMono-Regular',Consolas,'Liberation Mono',
  Menlo,monospace;font-size:.82rem;line-height:1.7;color:#e6edf3;white-space:pre}
.fix-block{background:#0b2e13;border:1px solid #238636;border-radius:8px;padding:12px 16px;
  color:#56d364;font-size:.85rem}
.tags-list{display:flex;gap:6px;flex-wrap:wrap}
.tag{background:#21262d;color:#8b949e;padding:2px 8px;border-radius:12px;font-size:.75rem}
.tag-cwe{color:#f0883e;border:1px solid #f0883e33}
.tag-owasp{color:#a371f7;border:1px solid #a371f733}

/* ── Taint flow ────────────────────────────────────────────────────── */
.taint-flow{display:flex;flex-direction:column;gap:4px}
.taint-step{display:flex;align-items:center;gap:8px;padding:4px 8px;border-radius:6px;
  background:#161b22;font-size:.82rem}
.taint-kind{padding:1px 6px;border-radius:4px;font-size:.7rem;font-weight:700;text-transform:uppercase}
.taint-source{background:#f8514933;color:#f85149}
.taint-sink{background:#f8514933;color:#f85149}
.taint-propagator{background:#e3b34133;color:#e3b341}
.taint-sanitizer{background:#23863633;color:#56d364}
.taint-label{color:#c9d1d9}
.taint-loc{color:#484f58;font-size:.75rem;margin-left:auto}

/* ── No results ────────────────────────────────────────────────────── */
.no-results{text-align:center;padding:48px 24px;color:#484f58}
.no-results-icon{font-size:2.5rem}

/* ── Footer ────────────────────────────────────────────────────────── */
.footer{border-top:1px solid #21262d;padding:16px 0;margin-top:16px}
.footer-inner{max-width:1280px;margin:0 auto;padding:0 24px;display:flex;
  justify-content:space-between;font-size:.8rem;color:#484f58}

/* ── Animation ─────────────────────────────────────────────────────── */
@keyframes fadeIn{from{opacity:0;transform:translateY(-4px)}to{opacity:1;transform:none}}

/* ── Responsive ────────────────────────────────────────────────────── */
@media(max-width:768px){
  .header-inner{flex-direction:column;align-items:flex-start}
  .summary-cards{grid-template-columns:repeat(2,1fr)}
  .filters{flex-direction:column}
  .filter-group{width:100%;justify-content:stretch}
  .filter-group select,.search-box input{width:100%}
  .footer-inner{flex-direction:column;gap:4px}
}
</style>`;
  }

  // ── JavaScript ─────────────────────────────────────────────────────────

  private renderScript(): string {
    return `
// ── Severity ordering ──
const SEV_ORDER = { critical: 0, high: 1, medium: 2, low: 3 };

// ── State ──
let currentSort = { key: 'severity', dir: 'asc' };
let filteredFindings = [...FINDINGS];

// ── DOM references ──
const tbody = document.getElementById('findings-body');
const noResults = document.getElementById('no-results');
const searchInput = document.getElementById('search-input');
const filterSeverity = document.getElementById('filter-severity');
const filterScanner = document.getElementById('filter-scanner');
const filterCategory = document.getElementById('filter-category');
const btnReset = document.getElementById('btn-reset');

// ── Render ──
function renderTable() {
  tbody.innerHTML = '';
  if (filteredFindings.length === 0) {
    noResults.style.display = 'block';
    return;
  }
  noResults.style.display = 'none';
  filteredFindings.forEach((f, idx) => {
    // Main row
    const tr = document.createElement('tr');
    tr.className = 'finding-row';
    tr.innerHTML = \`
      <td><button class="expand-btn" data-idx="\${idx}">▸</button></td>
      <td><span class="badge badge-\${f.severity}">\${f.severity}</span></td>
      <td title="\${esc(f.file)}">\${truncPath(f.file)}</td>
      <td>\${f.line}</td>
      <td><code>\${esc(f.ruleId)}</code></td>
      <td>\${esc(f.category)}</td>
      <td><span class="confidence-badge">\${f.confidence}</span></td>
      <td>\${esc(f.title)}</td>
    \`;
    tbody.appendChild(tr);

    // Detail row
    const detailTr = document.createElement('tr');
    detailTr.className = 'detail-row';
    detailTr.innerHTML = '<td colspan="8"><div class="detail-content" id="detail-' + idx + '">' + buildDetail(f) + '</div></td>';
    tbody.appendChild(detailTr);
  });

  // Bind expand buttons
  document.querySelectorAll('.expand-btn').forEach(btn => {
    btn.addEventListener('click', () => {
      const idx = btn.getAttribute('data-idx');
      const detail = document.getElementById('detail-' + idx);
      const isOpen = detail.classList.contains('open');
      detail.classList.toggle('open');
      btn.classList.toggle('open');
      btn.textContent = isOpen ? '▸' : '▾';
    });
  });
}

function buildDetail(f) {
  let html = '';
  // Message
  html += '<div class="detail-section"><h4>Description</h4><p>' + esc(f.message) + '</p></div>';
  // Snippet
  if (f.snippet) {
    html += '<div class="detail-section"><h4>Code Snippet</h4><div class="snippet-block">' + escCode(f.snippet) + '</div></div>';
  }
  // Fix
  if (f.fix) {
    html += '<div class="detail-section"><h4>Suggested Fix</h4><div class="fix-block">' + esc(f.fix) + '</div></div>';
  }
  // Taint flow
  if (f.taintFlow && f.taintFlow.length > 0) {
    html += '<div class="detail-section"><h4>Taint Flow</h4><div class="taint-flow">';
    f.taintFlow.forEach(step => {
      html += '<div class="taint-step">'
        + '<span class="taint-kind taint-' + step.kind + '">' + step.kind + '</span>'
        + '<span class="taint-label">' + esc(step.label) + '</span>'
        + '<span class="taint-loc">' + esc(step.file) + ':' + step.line + '</span>'
        + '</div>';
    });
    html += '</div></div>';
  }
  // Tags
  if ((f.cwe && f.cwe.length) || (f.owasp && f.owasp.length) || (f.tags && f.tags.length)) {
    html += '<div class="detail-section"><h4>References</h4><div class="tags-list">';
    (f.cwe || []).forEach(c => { html += '<span class="tag tag-cwe">CWE-' + esc(c) + '</span>'; });
    (f.owasp || []).forEach(o => { html += '<span class="tag tag-owasp">' + esc(o) + '</span>'; });
    (f.tags || []).forEach(t => { html += '<span class="tag">' + esc(t) + '</span>'; });
    html += '</div></div>';
  }
  return html;
}

// ── Sorting ──
document.querySelectorAll('th.sortable').forEach(th => {
  th.addEventListener('click', () => {
    const key = th.getAttribute('data-sort');
    if (currentSort.key === key) {
      currentSort.dir = currentSort.dir === 'asc' ? 'desc' : 'asc';
    } else {
      currentSort = { key, dir: 'asc' };
    }
    document.querySelectorAll('th.sortable').forEach(h => h.classList.remove('sort-active'));
    th.classList.add('sort-active');
    applySort();
    renderTable();
  });
});

function applySort() {
  const { key, dir } = currentSort;
  const mul = dir === 'asc' ? 1 : -1;
  filteredFindings.sort((a, b) => {
    let va, vb;
    if (key === 'severity') {
      va = SEV_ORDER[a.severity] ?? 4;
      vb = SEV_ORDER[b.severity] ?? 4;
    } else if (key === 'file') {
      va = a.file.toLowerCase();
      vb = b.file.toLowerCase();
    } else if (key === 'rule') {
      va = a.ruleId.toLowerCase();
      vb = b.ruleId.toLowerCase();
    } else if (key === 'category') {
      va = a.category.toLowerCase();
      vb = b.category.toLowerCase();
    } else {
      va = a[key]; vb = b[key];
    }
    if (va < vb) return -1 * mul;
    if (va > vb) return 1 * mul;
    return 0;
  });
}

// ── Filtering ──
function applyFilters() {
  const search = searchInput.value.toLowerCase().trim();
  const sev = filterSeverity.value;
  const scn = filterScanner.value;
  const cat = filterCategory.value;

  filteredFindings = FINDINGS.filter(f => {
    if (sev && f.severity !== sev) return false;
    if (scn && f.scanner !== scn) return false;
    if (cat && f.category !== cat) return false;
    if (search) {
      const haystack = [f.title, f.message, f.ruleId, f.file, f.category, f.severity]
        .join(' ').toLowerCase();
      if (!haystack.includes(search)) return false;
    }
    return true;
  });
  applySort();
  renderTable();
}

searchInput.addEventListener('input', applyFilters);
filterSeverity.addEventListener('change', applyFilters);
filterScanner.addEventListener('change', applyFilters);
filterCategory.addEventListener('change', applyFilters);
btnReset.addEventListener('click', () => {
  searchInput.value = '';
  filterSeverity.value = '';
  filterScanner.value = '';
  filterCategory.value = '';
  applyFilters();
});

// ── Utilities ──
function esc(s) { if (!s) return ''; const d = document.createElement('div'); d.textContent = String(s); return d.innerHTML; }
function escCode(s) { return esc(s).replace(/\\n/g, '\\n'); }
function truncPath(p) {
  if (!p) return '';
  const parts = p.replace(/\\\\\\\\/g, '/').split('/');
  if (parts.length <= 3) return esc(p);
  return esc('…/' + parts.slice(-3).join('/'));
}

// ── Initial render ──
applySort();
renderTable();
`;
  }

  // ── Data serialisation ────────────────────────────────────────────────

  /**
   * Flatten a Finding into a plain object suitable for embedding in the HTML
   * page's JavaScript. Keeps only the fields the front-end actually uses.
   */
  private serializeFinding(f: Finding): Record<string, unknown> {
    return {
      id: f.id,
      ruleId: f.ruleId,
      scanner: f.scanner,
      severity: f.severity,
      confidence: f.confidence,
      category: f.category,
      title: f.title,
      message: f.message,
      file: f.location.file,
      line: f.location.startLine,
      snippet: f.location.snippet || '',
      fix: f.fix?.description ?? null,
      cwe: f.cwe ?? [],
      owasp: f.owasp ?? [],
      tags: f.metadata.tags ?? [],
      taintFlow: f.taintFlow
        ? f.taintFlow.map((step) => ({
            kind: step.kind,
            label: step.label,
            file: step.location.file,
            line: step.location.startLine,
          }))
        : [],
    };
  }

  // ── HTML helpers ───────────────────────────────────────────────────────

  private escapeHtml(str: string): string {
    return str
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;')
      .replace(/'/g, '&#x27;');
  }
}
