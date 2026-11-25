/**
 * Standalone, zero-dependency Interactive HTML Security Report Generator
 * Works 100% offline with zero external CDNs or network requests.
 */

function escapeHtml(str) {
  if (!str) return '';
  return String(str)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#039;');
}

export function generateHtml(scanResult) {
  const { findings, stats, targetDir } = scanResult;

  const criticals = findings.filter(f => f.severity === 'CRITICAL').length;
  const highs = findings.filter(f => f.severity === 'HIGH').length;
  const mediums = findings.filter(f => f.severity === 'MEDIUM').length;
  const lows = findings.filter(f => f.severity === 'LOW').length;

  const scanDate = new Date().toLocaleString();

  const findingsJson = JSON.stringify(findings.map((f, idx) => ({
    id: idx,
    ruleId: f.ruleId,
    title: f.title,
    severity: f.severity,
    file: f.file,
    line: f.line,
    snippet: f.snippet || '',
    description: f.description || '',
    remediation: f.remediation || '',
    dataFlow: f.dataFlow || null,
    verified: f.verification || null
  }))).replace(/</g, '\\u003c').replace(/>/g, '\\u003e').replace(/&/g, '\\u0026');

  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>AuthWarden Security Report - ${escapeHtml(targetDir)}</title>
  <style>
    :root {
      --bg: #0b0f19;
      --card-bg: #111827;
      --border: #1f2937;
      --text: #f3f4f6;
      --text-muted: #9ca3af;
      --accent: #38bdf8;
      --critical: #ef4444;
      --high: #f59e0b;
      --medium: #3b82f6;
      --low: #10b981;
    }
    * { box-sizing: border-box; margin: 0; padding: 0; }
    body {
      font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
      background: var(--bg);
      color: var(--text);
      line-height: 1.5;
      padding: 24px;
    }
    .container { max-width: 1200px; margin: 0 auto; }
    header {
      display: flex;
      justify-content: space-between;
      align-items: center;
      padding-bottom: 24px;
      border-bottom: 1px solid var(--border);
      margin-bottom: 24px;
      flex-wrap: wrap;
      gap: 16px;
    }
    .brand { display: flex; align-items: center; gap: 12px; }
    .brand svg { width: 36px; height: 36px; fill: var(--accent); }
    .brand h1 { font-size: 24px; font-weight: 700; letter-spacing: -0.5px; }
    .meta { color: var(--text-muted); font-size: 14px; text-align: right; }
    
    .stats-grid {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
      gap: 16px;
      margin-bottom: 24px;
    }
    .stat-card {
      background: var(--card-bg);
      border: 1px solid var(--border);
      border-radius: 8px;
      padding: 16px;
      text-align: center;
    }
    .stat-num { font-size: 28px; font-weight: 700; margin-bottom: 4px; }
    .stat-label { font-size: 13px; color: var(--text-muted); text-transform: uppercase; font-weight: 600; }
    
    .controls {
      display: flex;
      gap: 12px;
      margin-bottom: 20px;
      flex-wrap: wrap;
    }
    .search-input {
      flex: 1;
      min-width: 250px;
      background: var(--card-bg);
      border: 1px solid var(--border);
      border-radius: 6px;
      color: var(--text);
      padding: 10px 14px;
      font-size: 14px;
      outline: none;
    }
    .search-input:focus { border-color: var(--accent); }
    .filter-btn {
      background: var(--card-bg);
      border: 1px solid var(--border);
      color: var(--text-muted);
      border-radius: 6px;
      padding: 8px 16px;
      font-size: 13px;
      font-weight: 600;
      cursor: pointer;
      transition: all 0.2s;
    }
    .filter-btn:hover, .filter-btn.active {
      background: #1f2937;
      color: var(--text);
      border-color: var(--accent);
    }
    
    .findings-list { display: flex; flex-direction: column; gap: 12px; }
    .finding-card {
      background: var(--card-bg);
      border: 1px solid var(--border);
      border-radius: 8px;
      overflow: hidden;
      transition: border-color 0.2s;
    }
    .finding-card:hover { border-color: #374151; }
    .finding-header {
      padding: 14px 18px;
      display: flex;
      align-items: center;
      justify-content: space-between;
      cursor: pointer;
      user-select: none;
      gap: 12px;
    }
    .finding-title-group { display: flex; align-items: center; gap: 12px; flex: 1; min-width: 0; }
    .badge {
      font-size: 11px;
      font-weight: 700;
      padding: 3px 8px;
      border-radius: 4px;
      text-transform: uppercase;
      letter-spacing: 0.5px;
      white-space: nowrap;
    }
    .badge-CRITICAL { background: rgba(239, 68, 68, 0.2); color: #f87171; border: 1px solid var(--critical); }
    .badge-HIGH { background: rgba(245, 158, 11, 0.2); color: #fbbf24; border: 1px solid var(--high); }
    .badge-MEDIUM { background: rgba(59, 130, 246, 0.2); color: #60a5fa; border: 1px solid var(--medium); }
    .badge-LOW { background: rgba(16, 185, 129, 0.2); color: #34d399; border: 1px solid var(--low); }
    .badge-VERIFIED { background: rgba(16, 185, 129, 0.3); color: #10b981; border: 1px solid #10b981; margin-left: 8px; }
    
    .finding-rule { font-family: monospace; font-size: 13px; color: var(--text-muted); }
    .finding-title { font-weight: 600; font-size: 15px; white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }
    .finding-loc { font-family: monospace; font-size: 13px; color: var(--accent); white-space: nowrap; }
    
    .finding-body {
      padding: 0 18px 18px 18px;
      border-top: 1px solid rgba(255,255,255,0.05);
      display: none;
    }
    .finding-body.open { display: block; padding-top: 16px; }
    
    .snippet-box {
      background: #080c14;
      border: 1px solid #1f2937;
      border-radius: 6px;
      padding: 12px;
      font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace;
      font-size: 13px;
      color: #f87171;
      margin: 12px 0;
      overflow-x: auto;
      white-space: pre;
    }
    .detail-text { color: var(--text-muted); font-size: 14px; margin-bottom: 12px; }
    .fix-box {
      background: rgba(16, 185, 129, 0.08);
      border-left: 3px solid var(--low);
      padding: 10px 14px;
      border-radius: 0 4px 4px 0;
      font-size: 13px;
      color: #a7f3d0;
    }
    .fix-header { font-weight: 600; color: #34d399; margin-bottom: 4px; display: flex; justify-content: space-between; align-items: center; }
    .copy-btn {
      background: transparent;
      border: 1px solid #059669;
      color: #34d399;
      padding: 2px 8px;
      border-radius: 4px;
      font-size: 11px;
      cursor: pointer;
    }
    .copy-btn:hover { background: rgba(5, 150, 105, 0.2); }
    .empty-state { text-align: center; padding: 48px; color: var(--text-muted); font-size: 16px; }
    .coverage-panel {
      background: var(--card-bg);
      border: 1px solid var(--border);
      border-radius: 8px;
      padding: 14px 18px;
      margin-bottom: 20px;
    }
    .coverage-title { font-size: 13px; font-weight: 700; text-transform: uppercase; color: var(--text-muted); margin-bottom: 10px; }
    .coverage-grid { display: flex; flex-wrap: wrap; gap: 10px; }
    .coverage-chip {
      display: inline-flex;
      align-items: center;
      gap: 8px;
      background: #080c14;
      border: 1px solid var(--border);
      border-radius: 6px;
      padding: 6px 10px;
      font-size: 12px;
    }
    .cov-ACTIVE { color: #34d399; font-weight: 700; }
    .cov-LIMITED { color: #fbbf24; font-weight: 700; }
  </style>
</head>
<body>
  <div class="container">
    <header>
      <div class="brand">
        <svg viewBox="0 0 24 24"><path d="M12 2L3 5v6c0 5.55 3.84 10.74 9 12 5.16-1.26 9-6.45 9-12V5l-9-3zm0 4a3 3 0 1 1 0 6 3 3 0 0 1 0-6zm5 11.5c-1.5-1.5-3.3-2.5-5-2.5s-3.5 1-5 2.5V11h10v6.5z"/></svg>
        <div>
          <h1>AuthWarden Security Report</h1>
          <div style="font-size: 13px; color: var(--text-muted);">Static API, Authorization & Logic Integrity Audit</div>
        </div>
      </div>
      <div class="meta">
        <div>Target: <strong>${escapeHtml(targetDir)}</strong></div>
        <div>Scanned <strong>${stats.filesScanned || 0}</strong> files in <strong>${stats.durationMs || 0}ms</strong></div>
        <div>Date: ${escapeHtml(scanDate)}</div>
      </div>
    </header>

    <div class="stats-grid">
      <div class="stat-card">
        <div class="stat-num" style="color: var(--accent);">${findings.length}</div>
        <div class="stat-label">Total Findings</div>
      </div>
      <div class="stat-card">
        <div class="stat-num" style="color: var(--critical);">${criticals}</div>
        <div class="stat-label">Critical</div>
      </div>
      <div class="stat-card">
        <div class="stat-num" style="color: var(--high);">${highs}</div>
        <div class="stat-label">High</div>
      </div>
      <div class="stat-card">
        <div class="stat-num" style="color: var(--medium);">${mediums}</div>
        <div class="stat-label">Medium</div>
      </div>
      <div class="stat-card">
        <div class="stat-num" style="color: var(--low);">${lows}</div>
        <div class="stat-label">Low</div>
      </div>
    </div>

    ${(stats.coverageScorecard && stats.coverageScorecard.length > 0) ? `
    <div class="coverage-panel">
      <div class="coverage-title">Coverage Transparency${stats.frameworks?.length ? ` &bull; Stack: ${stats.frameworks.map(f => escapeHtml(f)).join(', ')}` : ''}</div>
      <div class="coverage-grid">
        ${stats.coverageScorecard.map(c => `
          <div class="coverage-chip">
            <span class="cov-${escapeHtml(c.status)}">${c.status === 'ACTIVE' ? '✔ ACTIVE' : '▲ LIMITED'}</span>
            <strong>${escapeHtml(c.target)}</strong>
            <span style="color: var(--text-muted);">${escapeHtml(c.detail)}</span>
          </div>
        `).join('')}
      </div>
    </div>` : ''}

    <div class="controls">
      <input type="text" id="searchInput" class="search-input" placeholder="Search by rule ID, title, filename, or code snippet...">
      <button class="filter-btn active" data-filter="ALL">All (${findings.length})</button>
      <button class="filter-btn" data-filter="CRITICAL">Critical (${criticals})</button>
      <button class="filter-btn" data-filter="HIGH">High (${highs})</button>
      <button class="filter-btn" data-filter="MEDIUM">Medium (${mediums})</button>
      <button class="filter-btn" data-filter="LOW">Low (${lows})</button>
    </div>

    <div id="findingsContainer" class="findings-list"></div>
    <div id="emptyState" class="empty-state" style="display: none;">No security vulnerabilities match your filter criteria.</div>
  </div>

  <script>
    const findings = ${findingsJson};
    let currentFilter = 'ALL';
    let searchQuery = '';

    const container = document.getElementById('findingsContainer');
    const emptyState = document.getElementById('emptyState');
    const searchInput = document.getElementById('searchInput');
    const filterBtns = document.querySelectorAll('.filter-btn');

    function render() {
      const filtered = findings.filter(f => {
        const matchesFilter = currentFilter === 'ALL' || f.severity === currentFilter;
        const q = searchQuery.toLowerCase();
        const matchesSearch = !q ||
          f.ruleId.toLowerCase().includes(q) ||
          f.title.toLowerCase().includes(q) ||
          f.file.toLowerCase().includes(q) ||
          f.snippet.toLowerCase().includes(q) ||
          f.description.toLowerCase().includes(q);
        return matchesFilter && matchesSearch;
      });

      if (filtered.length === 0) {
        container.innerHTML = '';
        emptyState.style.display = 'block';
        return;
      }

      emptyState.style.display = 'none';
      container.innerHTML = filtered.map(f => \`
        <div class="finding-card">
          <div class="finding-header" onclick="toggleCard(\${f.id})">
            <div class="finding-title-group">
              <span class="badge badge-\${f.severity}">\${f.severity}</span>
              \${f.verified ? '<span class="badge badge-VERIFIED">LIVE VERIFIED</span>' : ''}
              <span class="finding-rule">\${escapeHtml(f.ruleId)}</span>
              <span class="finding-title">\${escapeHtml(f.title)}</span>
            </div>
            <span class="finding-loc">\${escapeHtml(f.file)}:\${f.line}</span>
          </div>
          <div class="finding-body" id="body-\${f.id}">
            \${f.description ? '<div class="detail-text">' + escapeHtml(f.description) + '</div>' : ''}
            \${f.snippet ? '<div class="snippet-box">' + escapeHtml(f.snippet) + '</div>' : ''}
            \${f.dataFlow ? '<div style="margin: 8px 0; color: #fbbf24; font-size: 13px;">➔ Data Flow: Line ' + f.dataFlow.sourceLine + ' [' + escapeHtml(f.dataFlow.sourceCode) + '] to Line ' + f.dataFlow.sinkLine + ' [' + escapeHtml(f.dataFlow.sinkCode) + ']</div>' : ''}
            \${f.remediation ? \`
              <div class="fix-box">
                <div class="fix-header">
                  <span>Recommended Fix</span>
                  <button class="copy-btn" onclick="copyFix(\${f.id})">Copy Fix</button>
                </div>
                <div>\${escapeHtml(f.remediation)}</div>
              </div>
            \` : ''}
          </div>
        </div>
      \`).join('');
    }

    function toggleCard(id) {
      const el = document.getElementById('body-' + id);
      if (el) el.classList.toggle('open');
    }

    function copyFix(id) {
      const item = findings.find(x => x.id === id);
      if (item && item.remediation) {
        navigator.clipboard.writeText(item.remediation);
        alert('Remediation copied to clipboard!');
      }
    }

    function escapeHtml(str) {
      if (!str) return '';
      return String(str)
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;')
        .replace(/'/g, '&#039;');
    }

    searchInput.addEventListener('input', (e) => {
      searchQuery = e.target.value;
      render();
    });

    filterBtns.forEach(btn => {
      btn.addEventListener('click', () => {
        filterBtns.forEach(b => b.classList.remove('active'));
        btn.classList.add('active');
        currentFilter = btn.dataset.filter;
        render();
      });
    });

    render();
  </script>
</body>
</html>`;
}
