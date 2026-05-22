'use strict';

const ICON = {
  summary: `<svg width="16" height="16" viewBox="0 0 16 16" fill="none" xmlns="http://www.w3.org/2000/svg"><rect x="2" y="1" width="12" height="14" rx="2" stroke="white" stroke-width="1.5"/><line x1="5" y1="6" x2="11" y2="6" stroke="white" stroke-width="1.5" stroke-linecap="round"/><line x1="5" y1="9" x2="11" y2="9" stroke="white" stroke-width="1.5" stroke-linecap="round"/><line x1="5" y1="12" x2="8" y2="12" stroke="white" stroke-width="1.5" stroke-linecap="round"/></svg>`,
  high:    `<svg width="16" height="16" viewBox="0 0 16 16" fill="none" xmlns="http://www.w3.org/2000/svg"><path d="M8 1.5L2.5 4.5V8c0 3.2 2.3 6 5.5 7 3.2-1 5.5-3.8 5.5-7V4.5L8 1.5z" stroke="white" stroke-width="1.5" stroke-linejoin="round"/><line x1="8" y1="6" x2="8" y2="9.5" stroke="white" stroke-width="1.5" stroke-linecap="round"/><circle cx="8" cy="11.5" r="0.8" fill="white"/></svg>`,
  medium:  `<svg width="16" height="16" viewBox="0 0 16 16" fill="none" xmlns="http://www.w3.org/2000/svg"><path d="M8 2.5L14 13H2L8 2.5z" stroke="white" stroke-width="1.5" stroke-linejoin="round"/><line x1="8" y1="7" x2="8" y2="10" stroke="white" stroke-width="1.5" stroke-linecap="round"/><circle cx="8" cy="11.8" r="0.8" fill="white"/></svg>`,
  low:     `<svg width="16" height="16" viewBox="0 0 16 16" fill="none" xmlns="http://www.w3.org/2000/svg"><path d="M3 2.5v11" stroke="white" stroke-width="1.5" stroke-linecap="round"/><path d="M3 2.5h7l-1.5 3L10 9H3" stroke="white" stroke-width="1.5" stroke-linejoin="round"/></svg>`,
  info:    `<svg width="16" height="16" viewBox="0 0 16 16" fill="none" xmlns="http://www.w3.org/2000/svg"><circle cx="8" cy="8" r="6" stroke="white" stroke-width="1.5"/><line x1="8" y1="7.5" x2="8" y2="11" stroke="white" stroke-width="1.5" stroke-linecap="round"/><circle cx="8" cy="5.5" r="0.8" fill="white"/></svg>`,
};

const SEV_META = {
  high:   { label: 'High',   color: '#c62828', bg: '#ffebee', border: '#e53935', pill: '#c62828', icon: ICON.high },
  medium: { label: 'Medium', color: '#d97706', bg: '#fffbeb', border: '#f59e0b', pill: '#d97706', icon: ICON.medium },
  low:    { label: 'Low',    color: '#9e9d24', bg: '#f9fbe7', border: '#cddc39', pill: '#9e9d24', icon: ICON.low },
  info:   { label: 'Info',   color: '#1565c0', bg: '#e3f2fd', border: '#1976d2', pill: '#1565c0', icon: ICON.info },
};

function esc(str) {
  return String(str || '')
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;');
}

function formatLocalTimestamp() {
  const d      = new Date();
  const days   = ['Sunday','Monday','Tuesday','Wednesday','Thursday','Friday','Saturday'];
  const months = ['January','February','March','April','May','June','July','August','September','October','November','December'];
  const pad    = n => String(n).padStart(2, '0');
  const offset = -d.getTimezoneOffset();
  const sign   = offset >= 0 ? '+' : '-';
  const abs    = Math.abs(offset);
  const tz     = `UTC${sign}${pad(Math.floor(abs / 60))}:${pad(abs % 60)}`;
  return `${days[d.getDay()]}, ${d.getDate()} ${months[d.getMonth()]} ${d.getFullYear()} `
       + `${pad(d.getHours())}:${pad(d.getMinutes())} (${tz})`;
}

function renderSevPill(severity) {
  const m = SEV_META[severity] || SEV_META.info;
  return `<span class="sev-pill" style="background:${m.pill};color:#fff">${m.label}</span>`;
}

function renderSection(id, icon, title, content, badge) {
  const badgeHtml = badge != null ? `<span class="section-count">${badge}</span>` : '';
  return `
<section class="card-section" id="${id}">
  <div class="section-header">
    <span class="section-icon">${icon}</span>
    <h2 class="section-title">${title}</h2>
    ${badgeHtml}
  </div>
  <div class="section-body">${content}</div>
</section>`;
}

function renderSummary(findings, meta) {
  const counts = { high: 0, medium: 0, low: 0, info: 0 };
  for (const f of findings) counts[f.severity] = (counts[f.severity] || 0) + 1;

  const statCards = [
    { label: 'Entries Scanned', value: meta.entryCount, color: 'var(--wine)' },
    { label: 'Total Findings',  value: findings.length, color: 'var(--wine)' },
    { label: 'High',            value: counts.high,     color: '#c62828' },
    { label: 'Medium',          value: counts.medium,   color: '#d97706' },
    { label: 'Low',             value: counts.low,      color: '#9e9d24' },
    { label: 'Info',            value: counts.info,     color: '#1565c0' },
  ].map(s => `
    <div class="stat-card">
      <div class="stat-value" style="color:${s.color}">${s.value}</div>
      <div class="stat-label">${s.label}</div>
    </div>`).join('');

  const tableRows = findings.map(f => `
    <tr>
      <td>${esc(f.title)}</td>
      <td>${renderSevPill(f.severity)}</td>
      <td class="finding-count">${f.count}</td>
    </tr>`).join('');

  const table = findings.length
    ? `<table class="summary-table">
        <thead><tr><th>Finding</th><th>Severity</th><th>Occurrences</th></tr></thead>
        <tbody>${tableRows}</tbody>
      </table>`
    : `<p class="empty-state">No security issues found.</p>`;

  return `<div class="stat-grid">${statCards}</div>${table}`;
}

function renderFindingGroup(severity, findings) {
  if (!findings.length) return '';
  const m = SEV_META[severity];
  const items = findings.map((f, i) => `
    <details class="finding-item" style="border-left-color:${m.border}" ${i === 0 ? 'open' : ''}>
      <summary class="finding-summary">
        <span class="expand-icon">&#9654;</span>
        <span class="finding-title">${esc(f.title)}</span>
        ${renderSevPill(f.severity)}
        <span class="finding-count-badge">${f.count} occurrence${f.count !== 1 ? 's' : ''}</span>
      </summary>
      <div class="finding-body">
        <div class="prose-block">
          <div class="prose-label">Description</div>
          <div class="prose-content">${esc(f.detail)}</div>
        </div>
        ${f.remediation ? `
        <div class="prose-block">
          <div class="prose-label remediation-label">How to Fix</div>
          <div class="prose-content remediation-content">${esc(f.remediation)}
            ${f.remediationDetail ? `
            <details class="remediation-details">
              <summary class="remediation-toggle"><span class="expand-icon-sm">&#9654;</span> More detail</summary>
              <div class="remediation-detail-body">${f.remediationDetail}</div>
            </details>` : ''}
          </div>
        </div>` : ''}
        <div class="prose-block">
          <div class="prose-label">Evidence</div>
          <ul class="evidence-list">
            ${f.evidence.map(e => `<li>${esc(e)}</li>`).join('')}
          </ul>
        </div>
      </div>
    </details>`).join('');

  return renderSection(
    `sev-${severity}`,
    m.icon,
    `${m.label} Findings`,
    `<div class="finding-list">${items}</div>`,
    findings.length
  );
}

function generateReport(har, findings, opts = {}) {
  const generated = formatLocalTimestamp();
  const { meta }  = har;

  const counts = { high: 0, medium: 0, low: 0, info: 0 };
  for (const f of findings) counts[f.severity] = (counts[f.severity] || 0) + 1;

  const byHigh   = findings.filter(f => f.severity === 'high');
  const byMedium = findings.filter(f => f.severity === 'medium');
  const byLow    = findings.filter(f => f.severity === 'low');
  const byInfo   = findings.filter(f => f.severity === 'info');

  const navItems = [['summary', 'Summary']];
  if (byHigh.length)   navItems.push(['sev-high',   'High']);
  if (byMedium.length) navItems.push(['sev-medium',  'Medium']);
  if (byLow.length)    navItems.push(['sev-low',     'Low']);
  if (byInfo.length)   navItems.push(['sev-info',    'Info']);

  const navHtml = navItems
    .map(([id, label]) => `<a class="nav-link" href="#${id}">${label}</a>`)
    .join('');

  return `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>HAR Security Scan Report</title>
<link rel="icon" type="image/svg+xml" href="data:image/svg+xml,<svg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 24 24'><rect fill='%230f3040' width='24' height='24' rx='4'/><path fill='%23fff' d='M12 3L5 6.5v5c0 4.55 2.95 8.82 7 10 4.05-1.18 7-5.45 7-10v-5L12 3z'/><path fill='%230f3040' d='M10 14.17l-2.12-2.12-1.07 1.06L10 16.3l7-7-1.06-1.06L10 14.17z'/></svg>">
<style>
:root{
  --wine:#0f3040;
  --wine-mid:#1a4a5c;
  --wine-light:#2a6478;
  --wine-subtle:#e8f4f8;
  --wine-border:#b8d8e4;
  --body-bg:#f0f2f4;
  --card-bg:#ffffff;
  --text-primary:#0a1f28;
  --text-secondary:#3a5a68;
  --text-muted:#7a9daa;
  --border:#dde4e8;
  --radius:12px;
  --shadow:0 2px 8px rgba(15,48,64,.09),0 0 0 1px rgba(15,48,64,.04);
}

*{box-sizing:border-box;margin:0;padding:0}
body{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;font-size:14px;line-height:1.6;color:var(--text-primary);background:var(--body-bg)}
a{color:var(--wine-light);text-decoration:none}
a:hover{text-decoration:underline}

/* ── Header ── */
header{background:linear-gradient(135deg,var(--wine) 0%,var(--wine-mid) 100%);color:#fff;padding:0;position:relative;overflow:hidden}
header::before{content:'';position:absolute;inset:0;background:url("data:image/svg+xml,%3Csvg width='60' height='60' viewBox='0 0 60 60' xmlns='http://www.w3.org/2000/svg'%3E%3Cg fill='none' fill-rule='evenodd'%3E%3Cg fill='%23ffffff' fill-opacity='0.03'%3E%3Cpath d='M36 34v-4h-2v4h-4v2h4v4h2v-4h4v-2h-4zm0-30V0h-2v4h-4v2h4v4h2V6h4V4h-4zM6 34v-4H4v4H0v2h4v4h2v-4h4v-2H6zM6 4V0H4v4H0v2h4v4h2V6h4V4H6z'/%3E%3C/g%3E%3C/g%3E%3C/svg%3E");pointer-events:none}
.header-inner{position:relative;padding:36px 32px;text-align:left}
header h1{font-size:32px;font-weight:800;letter-spacing:-.5px;line-height:1.1;margin-bottom:8px}
.header-subtitle{font-size:18px;font-weight:500;opacity:.75;margin-bottom:16px}
.header-meta{display:flex;gap:0;flex-wrap:wrap;margin-top:12px}
.header-meta-item{font-size:12px;opacity:.65;padding-right:20px;margin-right:20px;border-right:1px solid rgba(255,255,255,.2);line-height:2}
.header-meta-item:last-child{border-right:none}
.header-meta-label{opacity:.7;margin-right:4px}
.header-meta-value{font-weight:600}
.header-sev-badges{display:flex;gap:8px;flex-wrap:wrap;margin-top:14px}
.header-sev-badge{font-size:11px;font-weight:700;padding:3px 12px;border-radius:4px}

/* ── Nav ── */
.nav-bar{background:var(--card-bg);border-bottom:1px solid var(--border);position:sticky;top:0;z-index:20;box-shadow:0 1px 4px rgba(15,48,64,.06)}
.nav-inner{padding:0 48px;display:flex;overflow-x:auto;scrollbar-width:none}
.nav-inner::-webkit-scrollbar{display:none}
.nav-link{font-size:12px;font-weight:600;color:var(--wine-mid);padding:13px 0;flex:1;text-align:center;white-space:nowrap;border-bottom:2px solid transparent;transition:color .15s,border-color .15s;text-decoration:none}
.nav-link:hover{color:var(--wine);border-bottom-color:var(--wine-border);text-decoration:none}

/* ── Layout ── */
.container{padding:28px 48px 48px}

/* ── Cards ── */
.card-section{background:var(--card-bg);border-radius:var(--radius);box-shadow:var(--shadow);margin-bottom:16px;overflow:hidden}
.section-header{display:flex;align-items:center;gap:10px;padding:14px 24px;border-bottom:1px solid var(--wine-border);background:var(--wine-mid)}
.section-icon{width:32px;height:32px;background:rgba(255,255,255,.15);border-radius:6px;display:flex;align-items:center;justify-content:center;flex-shrink:0}
.section-title{font-size:11px;font-weight:700;color:#fff;text-transform:uppercase;letter-spacing:1px;flex:1}
.section-count{font-size:11px;font-weight:700;color:var(--wine-mid);background:rgba(255,255,255,.9);padding:2px 9px;border-radius:20px}
.section-body{padding:22px 24px}

/* ── Summary ── */
.stat-grid{display:grid;grid-template-columns:repeat(6,1fr);gap:10px;margin-bottom:20px}
.stat-card{background:#fff;border:1px solid var(--border);border-radius:10px;padding:14px;text-align:center;box-shadow:0 1px 3px rgba(15,48,64,.06)}
.stat-value{font-size:26px;font-weight:800;line-height:1.1;margin-bottom:4px}
.stat-label{font-size:12px;font-weight:600;color:var(--text-muted);text-transform:uppercase;letter-spacing:.5px}
.summary-table{width:100%;border-collapse:collapse;font-size:13px}
.summary-table th{text-align:left;font-size:12px;font-weight:700;color:var(--text-muted);text-transform:uppercase;letter-spacing:.6px;padding:8px 12px;border-bottom:2px solid var(--border)}
.summary-table td{padding:10px 12px;border-bottom:1px solid var(--border);color:var(--text-primary)}
.summary-table tr:last-child td{border-bottom:none}
.summary-table td.finding-count{font-weight:600;color:var(--text-secondary)}

/* ── Severity pill ── */
.sev-pill{font-size:11px;font-weight:700;padding:2px 10px;border-radius:5px;white-space:nowrap}

/* ── Findings ── */
.finding-list{display:flex;flex-direction:column;gap:8px}
.finding-item{border-left:5px solid #cbd5e1;border-radius:0 10px 10px 0;overflow:hidden;border:1px solid var(--border);border-left-width:5px}
.finding-summary{padding:13px 18px;cursor:pointer;display:flex;align-items:center;gap:10px;list-style:none;user-select:none;transition:filter .1s}
.finding-summary::-webkit-details-marker{display:none}
.finding-summary:hover{filter:brightness(.97)}
details.finding-item[open] .expand-icon{transform:rotate(90deg)}
.finding-title{font-weight:600;font-size:13px;flex:1;color:var(--text-primary)}
.finding-count-badge{font-size:11px;font-weight:600;color:var(--text-muted);white-space:nowrap}
.finding-body{padding:16px 18px;border-top:1px solid var(--border)}
.expand-icon{font-size:9px;color:var(--text-muted);flex-shrink:0;transition:transform .15s;display:inline-block}

/* ── Prose blocks ── */
.prose-block{margin-bottom:14px}
.prose-block:last-child{margin-bottom:0}
.prose-label{font-size:10px;font-weight:700;text-transform:uppercase;letter-spacing:.8px;color:var(--wine);margin-bottom:6px}
.remediation-label{color:#166534}
.remediation-content{background:#f0fdf4;border-left-color:#86efac;color:#14532d}
.remediation-details{margin-top:10px}
.remediation-toggle{cursor:pointer;list-style:none;display:flex;align-items:center;gap:5px;font-size:11px;font-weight:700;color:#166534;user-select:none}
.remediation-toggle::-webkit-details-marker{display:none}
details.remediation-details[open] .expand-icon-sm{transform:rotate(90deg)}
.remediation-detail-body{margin-top:10px;font-size:12px;color:#14532d;line-height:1.7}
.remediation-detail-body p{margin-bottom:8px}
.remediation-detail-body pre{background:#fff;border:1px solid var(--wine-border);border-left:3px solid var(--wine-light);border-radius:6px;padding:10px 12px;font-family:'Consolas','Monaco',monospace;font-size:11px;overflow-x:auto;white-space:pre-wrap;margin-bottom:8px;color:#14532d}
.remediation-detail-body a{color:#166534;text-decoration:underline}
.remediation-detail-body strong{font-weight:700}
.prose-content{font-size:13px;color:var(--text-secondary);line-height:1.75;background:var(--wine-subtle);border-left:3px solid var(--wine-border);border-radius:0 8px 8px 0;padding:10px 14px}

/* ── Evidence list ── */
.evidence-list{list-style:none;display:flex;flex-direction:column;gap:4px;background:var(--wine-subtle);border-left:3px solid var(--wine-border);border-radius:0 8px 8px 0;padding:10px 14px}
.evidence-list li{font-size:12px;font-family:'Consolas','Monaco',monospace;color:var(--text-secondary);word-break:break-all}
.evidence-more{color:var(--text-muted);font-style:italic;font-family:inherit}

/* ── Misc ── */
.empty-state{color:var(--text-muted);font-style:italic;font-size:13px;padding:8px 0}

/* ── Footer ── */
footer{background:var(--wine);color:rgba(255,255,255,.4);margin-top:8px;padding:14px 32px;display:flex;align-items:center;justify-content:center;gap:16px;flex-wrap:wrap;font-size:11px}
footer a{color:rgba(255,255,255,.5);text-decoration:none}
footer a:hover{color:#fff}
.footer-brand{font-weight:700;color:rgba(255,255,255,.7);font-size:11px}

/* ── Responsive ── */
@media(max-width:900px){
  .stat-grid{grid-template-columns:repeat(3,1fr)}
}
@media(max-width:600px){
  .stat-grid{grid-template-columns:repeat(2,1fr)}
  .header-inner{padding:24px 20px}
  .container{padding:20px 16px 40px}
  .nav-inner{padding:0 16px}
}

/* ── Print ── */
@media print{
  body{background:#fff}
  .nav-bar{display:none}
  .container{padding:16px 0}
  header{-webkit-print-color-adjust:exact;print-color-adjust:exact}
  .card-section{box-shadow:none;border:1px solid var(--border);break-inside:avoid;-webkit-print-color-adjust:exact;print-color-adjust:exact}
  @page{margin:1.2cm;size:A4}
}
</style>
</head>
<body>

<header>
  <div class="header-inner">
    <h1>HAR Security Scan Report</h1>
    <div class="header-subtitle">Scanned: ${esc(opts.filename || meta.creator || 'HAR file')}</div>
    <div class="header-meta">
      <span class="header-meta-item"><span class="header-meta-label">Generated on</span><span class="header-meta-value">${esc(generated)}</span></span>
    </div>
  </div>
</header>

<nav class="nav-bar">
  <div class="nav-inner">${navHtml}</div>
</nav>

<div class="container">
${renderSection('summary', ICON.summary, 'Summary', renderSummary(findings, meta))}
${renderFindingGroup('high',   byHigh)}
${renderFindingGroup('medium', byMedium)}
${renderFindingGroup('low',    byLow)}
${renderFindingGroup('info',   byInfo)}
</div>

<footer>
  <span class="footer-brand">har-security-scan</span>
</footer>

</body>
</html>`;
}

module.exports = { generateReport };
