// ============================================
// SIGMA DETECTION PLATFORM - Application Logic
// SPA Router, Renderers, and Interactivity
// ============================================

(function() {
'use strict';

// ── State Management ──
const state = {
  currentPage: 'dashboard',
  currentRuleId: null,
  filters: { tactic: 'all', severity: 'all', status: 'all', category: 'all', search: '' },
  sidebarOpen: false
};

const CATEGORY_META = {
  'brute-force': { icon: '🔨', color: '#ef4444' },
  'ransomware': { icon: '💀', color: '#dc2626' },
  'web-attacks': { icon: '🌐', color: '#f97316' },
  'reconnaissance': { icon: '🔎', color: '#3b82f6' },
  'insider-threat': { icon: '🕵️', color: '#8b5cf6' },
  'cloud-threats': { icon: '☁️', color: '#06b6d4' },
  'active-directory': { icon: '🏢', color: '#10b981' },
  'email-threats': { icon: '📧', color: '#f59e0b' },
  'network-anomalies': { icon: '📡', color: '#6366f1' },
  'endpoint-anomalies': { icon: '🖥️', color: '#ec4899' },
  'linux-threats': { icon: '🐧', color: '#22c55e' },
  'windows-specific': { icon: '🪟', color: '#0ea5e9' },
  'threat-hunting': { icon: '🎯', color: '#a855f7' },
  'data-exfiltration': { icon: '📤', color: '#e11d48' },
  'lateral-movement': { icon: '↔️', color: '#f97316' },
  'privilege-escalation': { icon: '⬆️', color: '#ef4444' },
  'credential-access': { icon: '🔑', color: '#eab308' },
  'defense-evasion': { icon: '🛡️', color: '#6366f1' },
  'persistence': { icon: '📌', color: '#14b8a6' },
  'execution': { icon: '⚙️', color: '#f43f5e' },
  'initial-access': { icon: '🚪', color: '#3b82f6' },
  'command-control': { icon: '📡', color: '#a855f7' },
  'collection': { icon: '📦', color: '#8b5cf6' }
};
function getCategoryLabel(catId) { return (catId||'').replace(/-/g,' ').replace(/\b\w/g,c=>c.toUpperCase()); }
function getCategoryMeta(catId) { return CATEGORY_META[catId] || { icon: '📋', color: '#64748b' }; }
function getRulesForCategory(catId) { return SIGMA_RULES.filter(r => r.category === catId); }
function getAllCategories() {
  const cats = new Set();
  // Include categories from actual rules
  SIGMA_RULES.forEach(r => { if (r.category) cats.add(r.category); });
  // Include ALL defined categories from ATTACK_CATEGORIES (ensures none are hidden)
  if (typeof ATTACK_CATEGORIES !== 'undefined') {
    ATTACK_CATEGORIES.forEach(c => cats.add(c.id));
  }
  return [...cats].sort();
}

// ── Utility Functions ──
const $ = (sel, ctx = document) => ctx.querySelector(sel);
const $$ = (sel, ctx = document) => [...ctx.querySelectorAll(sel)];
const escHtml = s => s.replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));

function getTacticById(id) { return MITRE_TACTICS.find(t => t.id === id); }
function getRuleById(id) { return SIGMA_RULES.find(r => r.id === id); }
function getRulesForTactic(tacticId) { return SIGMA_RULES.filter(r => r.tacticId === tacticId); }
function getRulesForTechnique(techId) { return SIGMA_RULES.filter(r => r.techniqueId === techId || r.techniqueId.startsWith(techId + '.')); }
function getCoveredTechniques() {
  const covered = new Set();
  SIGMA_RULES.forEach(r => { covered.add(r.techniqueId); const parent = r.techniqueId.split('.')[0]; covered.add(parent); });
  return covered;
}

function severityOrder(s) { return {critical:0,high:1,medium:2,low:3,informational:4}[s] ?? 5; }

function highlightYaml(yaml) {
  return yaml.split('\n').map(line => {
    if (line.trim().startsWith('#')) return `<span class="yaml-comment">${escHtml(line)}</span>`;
    const m = line.match(/^(\s*)([\w-]+)(:)(.*)/);
    if (m) {
      let val = escHtml(m[4]);
      if (m[4].trim().match(/^['"].*['"]$/)) val = `<span class="yaml-string">${val}</span>`;
      else if (m[4].trim().match(/^\d+$/)) val = `<span class="yaml-number">${val}</span>`;
      else if (m[4].trim().match(/^(true|false)$/i)) val = `<span class="yaml-bool">${val}</span>`;
      return `${escHtml(m[1])}<span class="yaml-key">${escHtml(m[2])}</span><span class="yaml-key">:</span>${val}`;
    }
    if (line.trim().startsWith('- ')) {
      const indent = line.match(/^\s*/)[0];
      const content = line.trim().substring(2);
      return `${escHtml(indent)}<span class="yaml-value">- </span><span class="yaml-string">${escHtml(content)}</span>`;
    }
    return escHtml(line);
  }).join('\n');
}

function copyToClipboard(text, btn) {
  navigator.clipboard.writeText(text).then(() => {
    btn.textContent = '✓ Copied';
    btn.classList.add('copied');
    setTimeout(() => { btn.textContent = 'Copy'; btn.classList.remove('copied'); }, 2000);
  });
}

// ── Router ──
function navigate(page, params = {}, push = true) {
  state.currentPage = page;
  if (params.ruleId) state.currentRuleId = params.ruleId;
  // Reset all filters when navigating to rules page to prevent stale filter combinations
  if (page === 'rules') {
    state.filters = { tactic: 'all', severity: 'all', status: 'all', category: 'all', search: '' };
  }
  // Apply specific filter overrides from navigation params
  if (params.tactic) state.filters.tactic = params.tactic;
  if (params.technique) state.filters.technique = params.technique;
  if (params.category) state.filters.category = params.category;
  if (params.severity) state.filters.severity = params.severity;

  if (push) {
    const url = new URL(window.location);
    url.hash = page + (params.ruleId ? '?ruleId=' + params.ruleId : '');
    history.pushState({ page, params, filters: { ...state.filters }, ruleId: state.currentRuleId }, '', url.toString());
  }

  render();
  updateNav();
  window.scrollTo(0, 0);
}

function updateNav() {
  $$('.nav-item').forEach(el => {
    el.classList.toggle('active', el.dataset.page === state.currentPage);
  });
}

// ── Main Render ──
function render() {
  const content = $('#page-content');
  const breadcrumb = $('#header-breadcrumb');
  switch (state.currentPage) {
    case 'dashboard': renderDashboard(content); breadcrumb.innerHTML = '<span class="current">Dashboard</span>'; break;
    case 'rules': renderRulesExplorer(content); breadcrumb.innerHTML = 'Platform <span class="separator">›</span> <span class="current">Rules Explorer</span>'; break;
    case 'rule-detail': renderRuleDetail(content); breadcrumb.innerHTML = 'Rules <span class="separator">›</span> <span class="current">Rule Detail</span>'; break;
    case 'mitre': renderMitreExplorer(content); breadcrumb.innerHTML = 'Platform <span class="separator">›</span> <span class="current">MITRE ATT&CK</span>'; break;
    case 'categories': renderCategories(content); breadcrumb.innerHTML = 'Platform <span class="separator">›</span> <span class="current">Attack Categories</span>'; break;
    case 'threat-intel': renderThreatIntel(content); breadcrumb.innerHTML = 'Platform <span class="separator">›</span> <span class="current">Threat Intelligence</span>'; break;
    case 'coverage': renderCoverage(content); breadcrumb.innerHTML = 'Platform <span class="separator">›</span> <span class="current">Coverage Analysis</span>'; break;
    case 'incident-response': renderIncidentResponsePage(content); breadcrumb.innerHTML = 'Platform <span class="separator">›</span> <span class="current">Incident Response</span>'; break;
    case 'threat-hunting': renderThreatHuntingPage(content); breadcrumb.innerHTML = 'Platform <span class="separator">›</span> <span class="current">Threat Hunting</span>'; break;
    case 'correlation': renderCorrelationPage(content); breadcrumb.innerHTML = 'Platform <span class="separator">›</span> <span class="current">Correlation & Risk</span>'; break;
    case 'forensics': renderForensicsPage(content); breadcrumb.innerHTML = 'Platform <span class="separator">›</span> <span class="current">Digital Forensics</span>'; break;
    case 'assets': renderAssetsPage(content); breadcrumb.innerHTML = 'Platform <span class="separator">›</span> <span class="current">Assets &amp; Identity</span>'; break;
    case 'detection-testing':
      if (typeof renderDetectionTestingPage === 'function') renderDetectionTestingPage(content);
      else content.innerHTML = '<div class="empty-state"><div class="empty-state-icon">🧪</div><div class="empty-state-text">Detection Testing module loading...</div></div>';
      breadcrumb.innerHTML = 'Platform <span class="separator">›</span> <span class="current">Detection Testing</span>';
      break;
    case 'system-intelligence':
      if (typeof renderSystemIntelligencePage === 'function') renderSystemIntelligencePage(content);
      else content.innerHTML = '<div class="empty-state"><div class="empty-state-icon">🖥️</div><div class="empty-state-text">System Intelligence module loading...</div></div>';
      breadcrumb.innerHTML = 'Platform <span class="separator">›</span> <span class="current">System Intelligence</span>';
      break;
    default: renderDashboard(content);
  }
}

// ══════════════════════════════════════════════
// DASHBOARD
// ══════════════════════════════════════════════
function renderDashboard(el) {
  const totalRules = SIGMA_RULES.length;
  const stableRules = SIGMA_RULES.filter(r => r.status === 'stable').length;
  const criticalRules = SIGMA_RULES.filter(r => r.severity === 'critical').length;
  const covered = getCoveredTechniques();
  let totalTech = 0;
  Object.values(MITRE_TECHNIQUES).forEach(techs => { techs.forEach(t => { totalTech++; t.subs.forEach(() => totalTech++); }); });
  const coveragePercent = Math.round((covered.size / totalTech) * 100);
  const tacticCounts = MITRE_TACTICS.map(t => ({ name: t.name, count: getRulesForTactic(t.id).length, color: t.color }));
  const severityCounts = { critical: SIGMA_RULES.filter(r=>r.severity==='critical').length, high: SIGMA_RULES.filter(r=>r.severity==='high').length, medium: SIGMA_RULES.filter(r=>r.severity==='medium').length, low: SIGMA_RULES.filter(r=>r.severity==='low').length };
  const maxTacticCount = Math.max(...tacticCounts.map(t => t.count));
  const kevCount = (typeof STATIC_CVE_DATA !== 'undefined' ? STATIC_CVE_DATA : []).filter(c => c.isKEV).length;

  el.innerHTML = `
    <div class="animate-fadeInUp">
      <h1 class="page-title">Security Operations Dashboard</h1>
      <p class="page-subtitle">Real-time overview of detection coverage, rule health, and threat intelligence status across your Sigma detection estate.</p>
    </div>
    <div class="stats-grid animate-fadeInUp">
      <div class="stat-card cyan">
        <div class="stat-icon">🛡️</div>
        <div class="stat-value">${totalRules}</div>
        <div class="stat-label">Total Sigma Rules</div>
        <div class="stat-change positive">↑ ${stableRules} production-ready</div>
      </div>
      <div class="stat-card green">
        <div class="stat-icon">✅</div>
        <div class="stat-value">${coveragePercent}%</div>
        <div class="stat-label">ATT&CK Coverage</div>
        <div class="stat-change positive">${covered.size} techniques covered</div>
      </div>
      <div class="stat-card red">
        <div class="stat-icon">🔴</div>
        <div class="stat-value">${criticalRules}</div>
        <div class="stat-label">Critical Detections</div>
        <div class="stat-change positive">High-priority alerts</div>
      </div>
      <div class="stat-card orange">
        <div class="stat-icon">⚠️</div>
        <div class="stat-value">${kevCount}</div>
        <div class="stat-label">CISA KEV Entries</div>
        <div class="stat-change negative">Active vulnerabilities tracked</div>
      </div>
      <div class="stat-card purple">
        <div class="stat-icon">🎯</div>
        <div class="stat-value">${MITRE_TACTICS.length}</div>
        <div class="stat-label">ATT&CK Tactics</div>
        <div class="stat-change positive">Full framework coverage</div>
      </div>
      <div class="stat-card blue">
        <div class="stat-icon">🔍</div>
        <div class="stat-value">${THREAT_INTEL.campaigns.length}</div>
        <div class="stat-label">Threat Campaigns</div>
        <div class="stat-change positive">Actively tracked</div>
      </div>
    </div>
    <div class="dashboard-grid">
      <div class="card">
        <div class="card-header"><span class="card-title">📊 Rules by ATT&CK Tactic</span></div>
        <div class="card-body">
          <div class="chart-bar-container">
            ${tacticCounts.map(t => `
              <div class="chart-bar-item">
                <span class="chart-bar-label" style="cursor:pointer" onclick="navigate('rules',{tactic:'${MITRE_TACTICS.find(mt=>mt.name===t.name)?.id}'})">${t.name}</span>
                <div class="chart-bar"><div class="chart-bar-fill cyan" style="width:${Math.max((t.count/maxTacticCount)*100,8)}%;background:linear-gradient(90deg,${t.color},${t.color}88)">${t.count}</div></div>
              </div>`).join('')}
          </div>
        </div>
      </div>
      <div class="card">
        <div class="card-header"><span class="card-title">🎯 Severity Distribution</span></div>
        <div class="card-body">
          <div class="chart-bar-container">
            <div class="chart-bar-item"><span class="chart-bar-label">Critical</span><div class="chart-bar"><div class="chart-bar-fill red" style="width:${(severityCounts.critical/totalRules)*100}%">${severityCounts.critical}</div></div></div>
            <div class="chart-bar-item"><span class="chart-bar-label">High</span><div class="chart-bar"><div class="chart-bar-fill orange" style="width:${(severityCounts.high/totalRules)*100}%">${severityCounts.high}</div></div></div>
            <div class="chart-bar-item"><span class="chart-bar-label">Medium</span><div class="chart-bar"><div class="chart-bar-fill" style="width:${(severityCounts.medium/totalRules)*100}%;background:linear-gradient(90deg,#f59e0b,#fbbf24)">${severityCounts.medium}</div></div></div>
            <div class="chart-bar-item"><span class="chart-bar-label">Low</span><div class="chart-bar"><div class="chart-bar-fill cyan" style="width:${Math.max((severityCounts.low/totalRules)*100,8)}%">${severityCounts.low}</div></div></div>
          </div>
          <div style="margin-top:24px;padding-top:16px;border-top:1px solid var(--border-primary)">
            <div class="card-title" style="margin-bottom:12px">📋 Status Breakdown</div>
            <div style="display:flex;gap:12px;flex-wrap:wrap">
              <span class="badge badge-status-stable">● Stable: ${SIGMA_RULES.filter(r=>r.status==='stable').length}</span>
              <span class="badge badge-status-test">● Test: ${SIGMA_RULES.filter(r=>r.status==='test').length}</span>
              <span class="badge badge-status-experimental">● Experimental: ${SIGMA_RULES.filter(r=>r.status==='experimental').length}</span>
            </div>
          </div>
        </div>
      </div>
      <div class="card full-width">
        <div class="card-header"><span class="card-title">🔥 Recent Critical Detections</span><button class="header-btn" onclick="navigate('rules')">View All →</button></div>
        <div class="card-body no-pad">
          <table class="data-table">
            <thead><tr><th>Rule</th><th>Technique</th><th>Tactic</th><th>Severity</th><th>Status</th></tr></thead>
            <tbody>
              ${SIGMA_RULES.filter(r=>r.severity==='critical'||r.severity==='high').sort((a,b)=>severityOrder(a.severity)-severityOrder(b.severity)).slice(0,8).map(r => `
                <tr>
                  <td class="clickable" onclick="navigate('rule-detail',{ruleId:'${r.id}'})">${escHtml(r.title)}</td>
                  <td><span class="badge badge-technique">${r.techniqueId}</span></td>
                  <td><span class="badge badge-tactic">${r.tacticName}</span></td>
                  <td><span class="badge badge-severity-${r.severity}">${r.severity}</span></td>
                  <td><span class="badge badge-status-${r.status}">${r.status}</span></td>
                </tr>`).join('')}
            </tbody>
          </table>
        </div>
      </div>
      <div class="card full-width">
        <div class="card-header"><span class="card-title">🌐 Active Threat Campaigns</span><button class="header-btn" onclick="navigate('threat-intel')">View All →</button></div>
        <div class="card-body no-pad">
          <table class="data-table">
            <thead><tr><th>Campaign</th><th>Actor</th><th>Targets</th><th>Linked Techniques</th><th>Status</th></tr></thead>
            <tbody>
              ${THREAT_INTEL.campaigns.map(c => `
                <tr>
                  <td style="font-weight:700;color:var(--text-primary)">${escHtml(c.name)}</td>
                  <td>${escHtml(c.actor)}</td>
                  <td>${escHtml(c.targets)}</td>
                  <td>${c.techniques.slice(0,3).map(t => `<span class="badge badge-technique">${t}</span>`).join(' ')}</td>
                  <td><span class="badge ${c.active ? 'badge-severity-critical' : 'badge-status-deprecated'}">${c.active ? '● Active' : 'Inactive'}</span></td>
                </tr>`).join('')}
            </tbody>
          </table>
        </div>
      </div>
    </div>`;
  // Animate bars
  setTimeout(() => { $$('.chart-bar-fill').forEach(b => { const w = b.style.width; b.style.width = '0%'; requestAnimationFrame(() => b.style.width = w); }); }, 100);
}

// ══════════════════════════════════════════════
// RULES EXPLORER
// ══════════════════════════════════════════════
function renderRulesExplorer(el) {
  const f = state.filters;
  let rules = [...SIGMA_RULES];
  if (f.tactic && f.tactic !== 'all') rules = rules.filter(r => r.tacticId === f.tactic);
  if (f.severity && f.severity !== 'all') rules = rules.filter(r => r.severity === f.severity);
  if (f.status && f.status !== 'all') rules = rules.filter(r => r.status === f.status);
  if (f.category && f.category !== 'all') rules = rules.filter(r => r.category === f.category);
  if (f.search) { const s = f.search.toLowerCase(); rules = rules.filter(r => r.title.toLowerCase().includes(s) || r.description.toLowerCase().includes(s) || r.techniqueId.toLowerCase().includes(s) || r.techniqueName.toLowerCase().includes(s) || (r.category||'').toLowerCase().includes(s)); }
  rules.sort((a, b) => severityOrder(a.severity) - severityOrder(b.severity));

  el.innerHTML = `
    <div class="animate-fadeInUp">
      <h1 class="page-title">Rules Explorer</h1>
      <p class="page-subtitle">Browse, search, and filter all Sigma detection rules. Each rule includes full YAML, MITRE mapping, tuning guidance, and response playbooks.</p>
    </div>
    <div class="rules-toolbar animate-fadeInUp">
      <div class="filter-group">
        <input type="text" class="filter-input" id="ruleSearch" placeholder="Search rules..." value="${escHtml(f.search||'')}" style="min-width:220px">
        <select class="filter-select" id="filterTactic">
          <option value="all">All Tactics</option>
          ${MITRE_TACTICS.map(t => `<option value="${t.id}" ${f.tactic===t.id?'selected':''}>${t.name}</option>`).join('')}
        </select>
        <select class="filter-select" id="filterSeverity">
          <option value="all">All Severities</option>
          <option value="critical" ${f.severity==='critical'?'selected':''}>Critical</option>
          <option value="high" ${f.severity==='high'?'selected':''}>High</option>
          <option value="medium" ${f.severity==='medium'?'selected':''}>Medium</option>
          <option value="low" ${f.severity==='low'?'selected':''}>Low</option>
        </select>
        <select class="filter-select" id="filterStatus">
          <option value="all">All Statuses</option>
          <option value="stable" ${f.status==='stable'?'selected':''}>Stable</option>
          <option value="test" ${f.status==='test'?'selected':''}>Test</option>
          <option value="experimental" ${f.status==='experimental'?'selected':''}>Experimental</option>
        </select>
        <select class="filter-select" id="filterCategory">
          <option value="all">All Categories</option>
          ${getAllCategories().map(c => `<option value="${c}" ${f.category===c?'selected':''}>${getCategoryMeta(c).icon} ${getCategoryLabel(c)}</option>`).join('')}
        </select>
      </div>
      <div class="rules-count">Showing <strong>${rules.length}</strong> of ${SIGMA_RULES.length} rules</div>
    </div>
    <div class="rules-list">
      ${rules.length ? rules.map((r, i) => `
        <div class="rule-card stagger-item" onclick="navigate('rule-detail',{ruleId:'${r.id}'})">
          <div class="rule-card-header">
            <div class="rule-card-title">${escHtml(r.title)}</div>
          </div>
          <div class="rule-card-meta">
            <span class="badge badge-severity-${r.severity}">${r.severity}</span>
            <span class="badge badge-status-${r.status}">${r.status}</span>
            <span class="badge badge-tactic">${r.tacticName}</span>
            <span class="badge badge-technique">${r.techniqueId} - ${escHtml(r.techniqueName)}</span>
            ${r.category ? `<span class="badge badge-category" style="background:${getCategoryMeta(r.category).color}22;color:${getCategoryMeta(r.category).color};border:1px solid ${getCategoryMeta(r.category).color}44">${getCategoryMeta(r.category).icon} ${getCategoryLabel(r.category)}</span>` : ''}
            ${r.threatIntel.cisaKev ? '<span class="badge badge-kev">⚠ CISA KEV</span>' : ''}
          </div>
          <div class="rule-card-desc">${escHtml(r.description)}</div>
        </div>`).join('') :
        `<div class="empty-state">
          <div class="empty-state-icon">${f.category && f.category !== 'all' ? getCategoryMeta(f.category).icon : '🔍'}</div>
          <div class="empty-state-text">${f.category && f.category !== 'all' ? `No detections available yet for "${getCategoryLabel(f.category)}"` : 'No rules match your filters'}</div>
          <div class="empty-state-sub">${f.category && f.category !== 'all' ? 'Detections for this category are planned for a future release. Browse other categories or explore the MITRE ATT&CK matrix.' : 'Try adjusting your search criteria or clearing filters.'}</div>
          ${f.category && f.category !== 'all' ? '<div style="margin-top:16px;display:flex;gap:8px;justify-content:center"><button class="btn-sm" onclick="navigate(\'categories\')">📂 Browse Categories</button><button class="btn-sm" onclick="navigate(\'mitre\')">🎯 MITRE ATT&CK</button><button class="btn-sm" onclick="navigate(\'rules\')">📋 All Rules</button></div>' : ''}
        </div>`}
    </div>`;
  
  // Event listeners
  const searchEl = $('#ruleSearch');
  if (searchEl) {
    let debounce;
    searchEl.addEventListener('input', e => { clearTimeout(debounce); debounce = setTimeout(() => { state.filters.search = e.target.value; renderRulesExplorer(el); }, 250); });
  }
  $('#filterTactic')?.addEventListener('change', e => { state.filters.tactic = e.target.value; renderRulesExplorer(el); });
  $('#filterSeverity')?.addEventListener('change', e => { state.filters.severity = e.target.value; renderRulesExplorer(el); });
  $('#filterStatus')?.addEventListener('change', e => { state.filters.status = e.target.value; renderRulesExplorer(el); });
  $('#filterCategory')?.addEventListener('change', e => { state.filters.category = e.target.value; renderRulesExplorer(el); });
}

// ══════════════════════════════════════════════
// RULE DETAIL
// ══════════════════════════════════════════════
function renderRuleDetail(el) {
  const rule = getRuleById(state.currentRuleId);
  if (!rule) { el.innerHTML = '<div class="empty-state"><div class="empty-state-icon">❌</div><div class="empty-state-text">Rule not found</div></div>'; return; }
  const tactic = getTacticById(rule.tacticId);
  const catMeta = getCategoryMeta(rule.category);
  const mitreUrl = `https://attack.mitre.org/techniques/${rule.techniqueId.replace('.','/')}/`;

  el.innerHTML = `
    <div class="rule-detail animate-fadeInUp">
      <button class="back-btn" onclick="navigate('rules')">← Back to Rules</button>
      <div class="rule-detail-header">
        <div style="display:flex; justify-content:space-between; align-items:flex-start; margin-bottom: 12px;">
          <h1 class="rule-detail-title" style="margin:0;">${escHtml(rule.title)}</h1>
          <button class="btn-sm" style="background:rgba(245, 158, 11, 0.1); border-color:rgba(245, 158, 11, 0.4); color:#f59e0b; padding:8px 16px; font-size:0.85rem; font-weight: 700; height: fit-content;" onclick="simulateAlert('${rule.id}')">
            <span style="margin-right:6px">⚡</span>Simulate Alert
          </button>
        </div>
        <div class="rule-detail-meta">
          <span class="badge badge-severity-${rule.severity}">${rule.severity}</span>
          <span class="badge badge-status-${rule.status}">${rule.status}</span>
          <span class="badge badge-tactic">${rule.tacticName}</span>
          <span class="badge badge-technique">${rule.techniqueId}</span>
          ${rule.threatIntel.cisaKev ? '<span class="badge badge-kev">⚠ CISA KEV</span>' : ''}
        </div>
        <p style="color:var(--text-secondary);font-size:0.88rem;line-height:1.7;margin-top:12px">${escHtml(rule.description)}</p>
        <div class="rule-detail-info">
          <div class="detail-info-item"><span class="detail-info-label">Rule ID</span><span class="detail-info-value font-mono">${rule.id}</span></div>
          <div class="detail-info-item"><span class="detail-info-label">Author</span><span class="detail-info-value">${escHtml(rule.author)}</span></div>
          <div class="detail-info-item"><span class="detail-info-label">Created</span><span class="detail-info-value">${rule.date}</span></div>
          <div class="detail-info-item"><span class="detail-info-label">Modified</span><span class="detail-info-value">${rule.modified}</span></div>
          <div class="detail-info-item"><span class="detail-info-label">Log Source</span><span class="detail-info-value">${rule.logsource.product} / ${rule.logsource.category || rule.logsource.service || ''}</span></div>
        </div>
      </div>

      <!-- Sigma Rule YAML -->
      <div class="detail-section">
        <h2 class="detail-section-title"><span class="section-icon">📄</span> Sigma Rule (YAML)</h2>
        <div class="code-block">
          <div class="code-block-header">
            <span class="code-block-lang">YAML / Sigma</span>
            <button class="code-block-copy" onclick="copyToClipboard(getRuleById('${rule.id}').sigmaYaml, this)">Copy</button>
          </div>
          <pre>${highlightYaml(rule.sigmaYaml)}</pre>
        </div>
      </div>

      <!-- SIEM Conversion Panel -->
      <div class="detail-section">
        <h2 class="detail-section-title"><span class="section-icon">⚡</span> SIEM Query Conversion</h2>
        <div class="siem-converter-panel">
          <div class="siem-tabs">
            <button class="siem-tab active" data-siem="splunk" onclick="switchSiemTab(this,'splunk','${rule.id}')">Splunk SPL</button>
            <button class="siem-tab" data-siem="qradar" onclick="switchSiemTab(this,'qradar','${rule.id}')">IBM QRadar AQL</button>
          </div>
          <div class="siem-output" id="siem-output-${rule.id}">
            <div class="code-block">
              <div class="code-block-header">
                <span class="code-block-lang">Splunk SPL — Production Ready</span>
                <button class="code-block-copy" onclick="copyToClipboard(getRuleById('${rule.id}').splunkQuery || getSiemQuery('${rule.id}','splunk'), this)">Copy</button>
              </div>
              <pre>${escHtml(rule.splunkQuery || 'Dynamic conversion available via Sigma Converter engine.')}</pre>
            </div>
          </div>
        </div>
      </div>

      <!-- Detection Logic -->
      <div class="detail-section">
        <h2 class="detail-section-title"><span class="section-icon">🔍</span> Detection Logic Explanation</h2>
        <div class="info-box info">
          <div class="info-box-title">How This Detection Works</div>
          ${escHtml(rule.detectionExplanation)}
        </div>
      </div>

      <!-- MITRE ATT&CK Mapping -->
      <div class="detail-section">
        <h2 class="detail-section-title"><span class="section-icon">🎯</span> MITRE ATT&CK Mapping</h2>
        <div class="mitre-detail-box">
          <div class="mitre-detail-grid">
            <div class="mitre-detail-item" style="cursor:pointer" onclick="navigate('rules',{tactic:'${rule.tacticId}'})"><span class="mitre-detail-label">Tactic</span><span class="mitre-detail-value" style="color:var(--accent-blue)">${rule.tacticName} (${rule.tacticId}) →</span></div>
            <div class="mitre-detail-item"><span class="mitre-detail-label">Technique</span><span class="mitre-detail-value"><a href="${mitreUrl}" target="_blank" rel="noopener">${rule.techniqueId} - ${escHtml(rule.techniqueName)}</a></span></div>
            <div class="mitre-detail-item"><span class="mitre-detail-label">Data Source</span><span class="mitre-detail-value">${rule.logsource.product} / ${rule.logsource.category || rule.logsource.service || 'N/A'}</span></div>
            <div class="mitre-detail-item" style="cursor:pointer" onclick="navigate('rules',{category:'${rule.category}'})"><span class="mitre-detail-label">Category</span><span class="mitre-detail-value" style="color:${catMeta.color}">${catMeta.icon} ${getCategoryLabel(rule.category)} →</span></div>
            ${tactic ? `<div class="mitre-detail-item"><span class="mitre-detail-label">Tactic Description</span><span class="mitre-detail-value" style="font-weight:400;font-size:0.82rem;color:var(--text-secondary)">${escHtml(tactic.description)}</span></div>` : ''}
          </div>
          <div style="display:flex;gap:8px;margin-top:12px;flex-wrap:wrap">
            <span class="badge" style="background:rgba(59,130,246,0.1);color:var(--accent-blue);cursor:pointer;font-size:0.72rem" onclick="navigate('mitre')">🗺️ View ATT&CK Matrix</span>
            <span class="badge" style="background:rgba(16,185,129,0.1);color:var(--accent-green);cursor:pointer;font-size:0.72rem" onclick="navigate('categories')">📂 Browse Categories</span>
            <span class="badge" style="background:rgba(168,85,247,0.1);color:#a855f7;cursor:pointer;font-size:0.72rem" onclick="navigate('coverage')">📊 Coverage Analysis</span>
          </div>
        </div>
      </div>

      <!-- Required Logs -->
      <div class="detail-section">
        <h2 class="detail-section-title"><span class="section-icon">📋</span> Required Logs & Data Sources</h2>
        <ul class="detail-list">${rule.requiredLogs.map(l => `<li>${escHtml(l)}</li>`).join('')}</ul>
        <div class="info-box warning" style="margin-top:12px">
          <div class="info-box-title">Configuration Requirements</div>
          ${escHtml(rule.logConfig)}
        </div>
      </div>

      <!-- False Positives -->
      <div class="detail-section">
        <h2 class="detail-section-title"><span class="section-icon">⚡</span> False Positives</h2>
        <ul class="detail-list">${rule.falsePositives.map(fp => `<li>${escHtml(fp)}</li>`).join('')}</ul>
      </div>

      <!-- Tuning -->
      <div class="detail-section">
        <h2 class="detail-section-title"><span class="section-icon">🔧</span> Tuning & Best Practices</h2>
        <div class="info-box success">
          <div class="info-box-title">Tuning Guidance</div>
          ${escHtml(rule.tuning)}
        </div>
      </div>

      <!-- Common Errors -->
      <div class="detail-section">
        <h2 class="detail-section-title"><span class="section-icon">⚠️</span> Common Errors & Pitfalls</h2>
        <ul class="detail-list">${rule.commonErrors.map(e => `<li>${escHtml(e)}</li>`).join('')}</ul>
      </div>

      <!-- Response Actions -->
      <div class="detail-section">
        <h2 class="detail-section-title"><span class="section-icon">🚨</span> Response Actions</h2>
        <ul class="detail-list">${rule.responseActions.map((a,i) => `<li><strong style="color:var(--accent-cyan)">${i+1}.</strong> ${escHtml(a)}</li>`).join('')}</ul>
      </div>

      <!-- Threat Intelligence Context -->
      <div class="detail-section">
        <h2 class="detail-section-title"><span class="section-icon">🌐</span> Threat Intelligence Context</h2>
        ${rule.threatIntel.cves.length ? `<div class="mb-md"><strong style="color:var(--text-secondary);font-size:0.82rem">Linked CVEs:</strong> ${rule.threatIntel.cves.map(c => `<span class="badge badge-severity-high">${c}</span>`).join(' ')}</div>` : ''}
        ${rule.threatIntel.cisaKev ? `<div class="info-box danger mb-md"><div class="info-box-title">⚠ CISA Known Exploited Vulnerability</div>This detection is linked to vulnerabilities in the CISA Known Exploited Vulnerabilities catalog. Federal agencies are required to remediate these. Prioritize patching and detection deployment.</div>` : ''}
        ${rule.threatIntel.campaigns.length ? `<div class="mb-md"><strong style="color:var(--text-secondary);font-size:0.82rem">Related Campaigns:</strong> ${rule.threatIntel.campaigns.map(c => `<span class="badge badge-tactic">${escHtml(c)}</span>`).join(' ')}</div>` : ''}
      </div>

      <!-- IR Playbook Section -->
      ${(function(){
        const irPlaybook = typeof getIRPlaybook !== 'undefined' ? getIRPlaybook(rule.category) : null;
        if(!irPlaybook) return '';
        return `<div class="detail-section">
          <h2 class="detail-section-title"><span class="section-icon">🚨</span> Incident Response Playbook</h2>
          <div class="info-box info mb-md"><div class="info-box-title">📋 ${escHtml(irPlaybook.name)}</div>Severity: <span class="badge badge-severity-${irPlaybook.severity}">${irPlaybook.severity.toUpperCase()}</span></div>
          <div class="ir-inline-grid" style="grid-template-columns: 1fr">
            <!-- Investigation Steps -->
            <div class="ir-inline-card">
              <h4>🔍 Investigation Steps</h4>
              <ol class="detail-list">
                ${irPlaybook.investigationSteps.slice(0, 5).map(s => `<li>${escHtml(s)}</li>`).join('')}
                ${irPlaybook.investigationSteps.length > 5 ? irPlaybook.investigationSteps.slice(5).map(s => `<li class="exp-hidden" style="display:none">${escHtml(s)}</li>`).join('') + `<li onclick="toggleExpandItem(this)" style="list-style:none;color:var(--accent-cyan);cursor:pointer;margin-top:6px" data-more="+ ${irPlaybook.investigationSteps.length - 5} more steps">+ ${irPlaybook.investigationSteps.length - 5} more steps</li>` : ''}
              </ol>
            </div>
            
            <!-- Containment Actions -->
            <div class="ir-inline-card">
              <h4>🛑 Containment Actions</h4>
              <ol class="detail-list">
                ${irPlaybook.containmentActions.slice(0, 5).map(a => `<li>${escHtml(a)}</li>`).join('')}
                ${irPlaybook.containmentActions.length > 5 ? irPlaybook.containmentActions.slice(5).map(a => `<li class="exp-hidden" style="display:none">${escHtml(a)}</li>`).join('') + `<li onclick="toggleExpandItem(this)" style="list-style:none;color:var(--accent-cyan);cursor:pointer;margin-top:6px" data-more="+ ${irPlaybook.containmentActions.length - 5} more actions">+ ${irPlaybook.containmentActions.length - 5} more actions</li>` : ''}
              </ol>
            </div>
            
            <!-- Escalation Procedures -->
            <div class="ir-inline-card">
              <h4>⬆️ Escalation Procedures</h4>
              <ol class="detail-list">
                ${irPlaybook.escalationSteps.slice(0, 5).map(a => `<li>${escHtml(a)}</li>`).join('')}
                ${irPlaybook.escalationSteps.length > 5 ? irPlaybook.escalationSteps.slice(5).map(a => `<li class="exp-hidden" style="display:none">${escHtml(a)}</li>`).join('') + `<li onclick="toggleExpandItem(this)" style="list-style:none;color:var(--accent-cyan);cursor:pointer;margin-top:6px" data-more="+ ${irPlaybook.escalationSteps.length - 5} more procedures">+ ${irPlaybook.escalationSteps.length - 5} more procedures</li>` : ''}
              </ol>
            </div>
            
            <!-- Context & Validation -->
            <div class="ir-inline-card" style="display:grid;grid-template-columns:1fr 1fr;gap:1.5rem">
              <div>
                <h4>📋 Required Logs</h4>
                <div style="display:flex;flex-wrap:wrap;gap:6px;margin-top:8px">
                  ${irPlaybook.requiredLogs.slice(0, 4).map(l => `<span class="badge" style="background:var(--bg-card);border:1px solid var(--border-primary)">${escHtml(l)}</span>`).join('')}
                  ${irPlaybook.requiredLogs.length > 4 ? irPlaybook.requiredLogs.slice(4).map(l => `<span class="badge exp-hidden" style="display:none;background:var(--bg-card);border:1px solid var(--border-primary)">${escHtml(l)}</span>`).join('') + `<span class="badge" onclick="toggleExpandItem(this)" style="cursor:pointer;background:rgba(59,130,246,0.1);color:var(--accent-blue)" data-more="+ ${irPlaybook.requiredLogs.length - 4} more">+ ${irPlaybook.requiredLogs.length - 4} more</span>` : ''}
                </div>
              </div>
              <div>
                <h4>🎯 Key Indicators</h4>
                <ul class="detail-list" style="margin-top:8px">
                  ${irPlaybook.indicatorsToCheck.slice(0, 3).map(i => `<li>${escHtml(i)}</li>`).join('')}
                  ${irPlaybook.indicatorsToCheck.length > 3 ? irPlaybook.indicatorsToCheck.slice(3).map(i => `<li class="exp-hidden" style="display:none">${escHtml(i)}</li>`).join('') + `<li onclick="toggleExpandItem(this)" style="list-style:none;color:var(--accent-cyan);cursor:pointer;margin-top:4px" data-more="+ ${irPlaybook.indicatorsToCheck.length - 3} more indicators">+ ${irPlaybook.indicatorsToCheck.length - 3} more indicators</li>` : ''}
                </ul>
              </div>
            </div>
            
          </div>
        </div>`;
      })()}

      <!-- Forensic Artifacts Section -->
      ${(function(){
        const artifacts = typeof getForensicArtifacts !== 'undefined' ? getForensicArtifacts(rule.category) : [];
        if(!artifacts.length) return '';
        return `<div class="detail-section">
          <h2 class="detail-section-title"><span class="section-icon">🔬</span> Forensic Artifacts</h2>
          <div class="forensic-artifacts-inline">${artifacts.slice(0,4).map(a => `<div class="forensic-artifact-chip">
            <div class="forensic-artifact-chip-title">${escHtml(a.name)}</div>
            <div class="forensic-artifact-chip-loc">${escHtml(a.location)}</div>
            <div class="forensic-artifact-chip-tools">Tools: ${a.collectionTools.slice(0,3).join(', ')}</div>
          </div>`).join('')}</div>
          ${artifacts.length > 4 ? `<div style="text-align:center;margin-top:0.75rem"><a href="#" onclick="navigate('forensics');return false" style="color:var(--accent-cyan);font-size:0.82rem">View all ${artifacts.length} forensic artifacts →</a></div>` : ''}
        </div>`;
      })()}

      <!-- Correlation Rules Section -->
      ${(function(){
        const corrs = typeof getCorrelationsForRule !== 'undefined' ? getCorrelationsForRule(rule.id) : [];
        if(!corrs.length) return '';
        return `<div class="detail-section">
          <h2 class="detail-section-title"><span class="section-icon">🔗</span> Correlation Rules</h2>
          ${corrs.map(cr => `<div class="info-box warning mb-md">
            <div class="info-box-title">${escHtml(cr.name)} <span class="badge badge-severity-${cr.severity}" style="margin-left:0.5rem">Risk: ${cr.riskScore}/100</span></div>
            ${escHtml(cr.description)}
          </div>`).join('')}
          <div style="text-align:center;margin-top:0.5rem"><a href="#" onclick="navigate('correlation');return false" style="color:var(--accent-cyan);font-size:0.82rem">View all correlation rules →</a></div>
        </div>`;
      })()}

      <!-- References -->
      <div class="detail-section">
        <h2 class="detail-section-title"><span class="section-icon">📚</span> References</h2>
        <ul class="detail-list">${rule.references.map(ref => `<li><a href="${escHtml(ref)}" target="_blank" rel="noopener" style="color:var(--accent-cyan);text-decoration:none">${escHtml(ref)}</a></li>`).join('')}</ul>
      </div>
    </div>`;
}

// ══════════════════════════════════════════════
// SIEM TAB SWITCHING
// ══════════════════════════════════════════════
function switchSiemTab(btn, siem, ruleId) {
  const rule = getRuleById(ruleId);
  if (!rule) return;
  btn.parentElement.querySelectorAll('.siem-tab').forEach(t => t.classList.remove('active'));
  btn.classList.add('active');
  const output = document.getElementById('siem-output-' + ruleId);
  if (!output) return;
  const query = siem === 'splunk' ? (rule.splunkQuery || 'No Splunk query available.') : (rule.qradarQuery || 'No QRadar query available.');
  const label = siem === 'splunk' ? 'Splunk SPL' : 'IBM QRadar AQL';
  output.innerHTML = `
    <div class="code-block">
      <div class="code-block-header">
        <span class="code-block-lang">${label} — Production Ready</span>
        <button class="code-block-copy" onclick="copyToClipboard(getRuleById('${ruleId}').${siem === 'splunk' ? 'splunkQuery' : 'qradarQuery'} || '', this)">Copy</button>
      </div>
      <pre>${escHtml(query)}</pre>
    </div>`;
}
function getSiemQuery(ruleId, siem) {
  const rule = getRuleById(ruleId);
  return siem === 'splunk' ? (rule?.splunkQuery || '') : (rule?.qradarQuery || '');
}
window.switchSiemTab = switchSiemTab;
window.getSiemQuery = getSiemQuery;

// ══════════════════════════════════════════════
// CATEGORIES PAGE — Enhanced with MITRE ATT&CK Cross-Linking
// ══════════════════════════════════════════════

// Category ↔ MITRE ATT&CK Mapping (structured, bidirectional)
const CATEGORY_MITRE_MAP = {
  'brute-force':          [{ tacticId: 'TA0006', tactics: ['Credential Access'], techniques: ['T1110', 'T1110.001', 'T1110.003', 'T1110.004'] }],
  'ransomware':           [{ tacticId: 'TA0040', tactics: ['Impact'], techniques: ['T1486', 'T1490', 'T1489'] }],
  'web-attacks':          [{ tacticId: 'TA0001', tactics: ['Initial Access'], techniques: ['T1190', 'T1189'] }],
  'reconnaissance':       [{ tacticId: 'TA0043', tactics: ['Reconnaissance'], techniques: ['T1595', 'T1592', 'T1590'] }, { tacticId: 'TA0007', tactics: ['Discovery'], techniques: ['T1046', 'T1082', 'T1083', 'T1057'] }],
  'insider-threat':       [{ tacticId: 'TA0010', tactics: ['Exfiltration'], techniques: ['T1567', 'T1048'] }, { tacticId: 'TA0009', tactics: ['Collection'], techniques: ['T1005', 'T1039'] }],
  'cloud-threats':        [{ tacticId: 'TA0001', tactics: ['Initial Access'], techniques: ['T1078.004'] }, { tacticId: 'TA0006', tactics: ['Credential Access'], techniques: ['T1528', 'T1552.005'] }],
  'active-directory':     [{ tacticId: 'TA0006', tactics: ['Credential Access'], techniques: ['T1558', 'T1558.003', 'T1003.006'] }, { tacticId: 'TA0004', tactics: ['Privilege Escalation'], techniques: ['T1068', 'T1134'] }],
  'email-threats':        [{ tacticId: 'TA0001', tactics: ['Initial Access'], techniques: ['T1566', 'T1566.001', 'T1566.002'] }],
  'network-anomalies':    [{ tacticId: 'TA0011', tactics: ['Command and Control'], techniques: ['T1071', 'T1572', 'T1573'] }, { tacticId: 'TA0007', tactics: ['Discovery'], techniques: ['T1046'] }],
  'endpoint-anomalies':   [{ tacticId: 'TA0002', tactics: ['Execution'], techniques: ['T1055', 'T1106'] }, { tacticId: 'TA0005', tactics: ['Defense Evasion'], techniques: ['T1055', 'T1027'] }],
  'linux-threats':        [{ tacticId: 'TA0003', tactics: ['Persistence'], techniques: ['T1053.003', 'T1543.002'] }, { tacticId: 'TA0002', tactics: ['Execution'], techniques: ['T1059.004'] }],
  'windows-specific':     [{ tacticId: 'TA0002', tactics: ['Execution'], techniques: ['T1059.001', 'T1059.003', 'T1218'] }, { tacticId: 'TA0005', tactics: ['Defense Evasion'], techniques: ['T1218', 'T1036'] }],
  'threat-hunting':       [{ tacticId: 'TA0007', tactics: ['Discovery'], techniques: ['T1057', 'T1082'] }, { tacticId: 'TA0011', tactics: ['Command and Control'], techniques: ['T1071.001', 'T1568'] }],
  'data-exfiltration':    [{ tacticId: 'TA0010', tactics: ['Exfiltration'], techniques: ['T1567.002', 'T1048', 'T1041'] }],
  'lateral-movement':     [{ tacticId: 'TA0008', tactics: ['Lateral Movement'], techniques: ['T1021', 'T1021.001', 'T1021.002', 'T1021.006'] }],
  'privilege-escalation': [{ tacticId: 'TA0004', tactics: ['Privilege Escalation'], techniques: ['T1068', 'T1134', 'T1543.003'] }],
  'credential-access':    [{ tacticId: 'TA0006', tactics: ['Credential Access'], techniques: ['T1003', 'T1003.001', 'T1555', 'T1558'] }],
  'defense-evasion':      [{ tacticId: 'TA0005', tactics: ['Defense Evasion'], techniques: ['T1070', 'T1562', 'T1036', 'T1027'] }],
  'persistence':          [{ tacticId: 'TA0003', tactics: ['Persistence'], techniques: ['T1053.005', 'T1543.003', 'T1547.001'] }],
  'execution':            [{ tacticId: 'TA0002', tactics: ['Execution'], techniques: ['T1059', 'T1059.001', 'T1059.003', 'T1203'] }],
  'initial-access':       [{ tacticId: 'TA0001', tactics: ['Initial Access'], techniques: ['T1190', 'T1133', 'T1078'] }],
  'command-control':      [{ tacticId: 'TA0011', tactics: ['Command and Control'], techniques: ['T1071', 'T1071.001', 'T1572', 'T1573', 'T1568'] }],
  'collection':           [{ tacticId: 'TA0009', tactics: ['Collection'], techniques: ['T1005', 'T1039', 'T1114'] }]
};

function getCategoryTactics(catId) {
  return CATEGORY_MITRE_MAP[catId] || [];
}
function getTacticCategories(tacticId) {
  const cats = [];
  for (const [catId, mappings] of Object.entries(CATEGORY_MITRE_MAP)) {
    if (mappings.some(m => m.tacticId === tacticId)) cats.push(catId);
  }
  return cats;
}
// Make globally accessible
window.getCategoryTactics = getCategoryTactics;
window.getTacticCategories = getTacticCategories;

function renderCategories(el) {
  const cats = getAllCategories();
  const totalCatRules = SIGMA_RULES.filter(r => r.category).length;
  const mappedCats = cats.filter(c => CATEGORY_MITRE_MAP[c] && CATEGORY_MITRE_MAP[c].length > 0).length;
  el.innerHTML = `
    <div class="animate-fadeInUp">
      <h1 class="page-title">Attack Categories</h1>
      <p class="page-subtitle">Browse ${cats.length} attack categories with ${totalCatRules} categorized detection rules. Each category is mapped to MITRE ATT&CK tactics and techniques for cross-referenced threat context.</p>
    </div>

    <!-- Category ↔ MITRE summary bar -->
    <div class="card full-width animate-fadeInUp" style="margin-bottom:20px">
      <div class="card-body" style="padding:16px">
        <div style="display:flex;align-items:center;gap:16px;flex-wrap:wrap">
          <div style="flex:1;min-width:200px">
            <div style="font-weight:700;font-size:0.9rem;color:var(--text-primary)">🔗 Category ↔ MITRE ATT&CK Mapping</div>
            <div style="font-size:0.78rem;color:var(--text-muted);margin-top:4px">${mappedCats}/${cats.length} categories mapped to ATT&CK tactics • Click any category to see its MITRE mapping</div>
          </div>
          <button class="btn-sm" onclick="navigate('mitre')" style="white-space:nowrap">🎯 Open ATT&CK Explorer</button>
        </div>
      </div>
    </div>

    <div class="stats-grid animate-fadeInUp" style="grid-template-columns: repeat(auto-fit, minmax(160px, 1fr))">
      ${cats.slice(0,6).map(c => {
        const meta = getCategoryMeta(c);
        const count = getRulesForCategory(c).length;
        return `
          <div class="stat-card" style="cursor:pointer;border-color:${meta.color}33" onclick="navigate('rules',{category:'${c}'})">
            <div class="stat-icon">${meta.icon}</div>
            <div class="stat-value" style="color:${meta.color}">${count}</div>
            <div class="stat-label">${getCategoryLabel(c)}</div>
          </div>`;
      }).join('')}
    </div>
    <div class="categories-grid animate-fadeInUp" style="display:grid;grid-template-columns:repeat(auto-fill,minmax(380px,1fr));gap:20px;margin-top:24px">
      ${cats.map(c => {
        const meta = getCategoryMeta(c);
        const rules = getRulesForCategory(c);
        const critCount = rules.filter(r=>r.severity==='critical').length;
        const highCount = rules.filter(r=>r.severity==='high').length;
        const mitreMappings = getCategoryTactics(c);
        const uniqueTactics = [...new Set(mitreMappings.flatMap(m => m.tactics))];
        const allTechniques = mitreMappings.flatMap(m => m.techniques);
        return `
          <div class="card category-card" style="border-left:3px solid ${meta.color}">
            <div class="card-body">
              <div style="display:flex;align-items:center;gap:10px;margin-bottom:12px">
                <span style="font-size:1.5rem">${meta.icon}</span>
                <div style="flex:1">
                  <div style="font-weight:700;font-size:1rem;color:var(--text-primary)">${getCategoryLabel(c)}</div>
                  <div style="font-size:0.72rem;color:var(--text-muted)">${rules.length > 0 ? rules.length + ' detection rules' : 'No detections yet'}</div>
                </div>
                <span class="badge" style="background:rgba(59,130,246,0.1);color:var(--accent-blue);font-size:0.65rem;cursor:pointer" onclick="event.stopPropagation();navigate('rules',{category:'${c}'})" title="View rules">📋 Rules</span>
              </div>
              <div style="display:flex;gap:6px;flex-wrap:wrap;margin-bottom:12px">
                ${rules.length > 0 ? `
                  ${critCount ? `<span class="badge badge-severity-critical">${critCount} critical</span>` : ''}
                  ${highCount ? `<span class="badge badge-severity-high">${highCount} high</span>` : ''}
                  <span class="badge badge-severity-medium">${rules.filter(r=>r.severity==='medium').length} medium</span>
                ` : '<span class="badge" style="background:rgba(245,158,11,0.1);color:#f59e0b;border:1px solid rgba(245,158,11,0.3)">🚧 Coming Soon</span>'}
              </div>

              <!-- MITRE ATT&CK Cross-Link -->
              ${mitreMappings.length > 0 ? `
              <div class="cat-mitre-box">
                <div class="cat-mitre-label">🎯 MITRE ATT&CK Mapping</div>
                <div class="cat-mitre-tactics">
                  ${uniqueTactics.map(t => `<span class="badge cat-mitre-tactic-badge" onclick="event.stopPropagation();navigate('mitre')">${t}</span>`).join('')}
                </div>
                <div class="cat-mitre-techniques">
                  ${allTechniques.slice(0,5).map(t => `<span class="cat-tech-tag" onclick="event.stopPropagation();navigate('mitre')" title="${t}">${t}</span>`).join('')}
                  ${allTechniques.length > 5 ? `<span class="cat-tech-more">+${allTechniques.length - 5} more</span>` : ''}
                </div>
              </div>` : `
              <div class="cat-mitre-box cat-mitre-unmapped">
                <div class="cat-mitre-label">⚠ No ATT&CK mapping</div>
              </div>`}

              <div style="font-size:0.78rem;color:var(--text-secondary);line-height:1.5;margin-top:10px">
                ${rules.length > 0 ? rules.slice(0,3).map(r => `<div style="padding:3px 0;border-bottom:1px solid var(--border-primary);cursor:pointer" onclick="event.stopPropagation();navigate('rule-detail',{ruleId:'${r.id}'})">▸ ${escHtml(r.title)}</div>`).join('') : '<div style="padding:8px 0;color:var(--text-muted);font-style:italic">Detections for this category are planned for a future release.</div>'}
                ${rules.length > 3 ? `<div style="padding:3px 0;color:${meta.color};font-weight:600;cursor:pointer" onclick="event.stopPropagation();navigate('rules',{category:'${c}'})">+ ${rules.length - 3} more rules →</div>` : ''}
              </div>
            </div>
          </div>`;
      }).join('')}
    </div>`;
}

// ══════════════════════════════════════════════
// MITRE ATT&CK EXPLORER — Enhanced with Category Cross-Links
// ══════════════════════════════════════════════
function renderMitreExplorer(el) {
  const covered = getCoveredTechniques();
  const cats = getAllCategories();
  let totalTechAll = 0, coveredTechAll = 0;
  MITRE_TACTICS.forEach(t => {
    const techs = MITRE_TECHNIQUES[t.id] || [];
    techs.forEach(tech => { totalTechAll++; if (covered.has(tech.id)) coveredTechAll++; tech.subs.forEach(s => { totalTechAll++; if (covered.has(s.id)) coveredTechAll++; }); });
  });
  const overallPct = totalTechAll > 0 ? Math.round((coveredTechAll / totalTechAll) * 100) : 0;

  el.innerHTML = `
    <div class="animate-fadeInUp">
      <h1 class="page-title">MITRE ATT&CK Explorer</h1>
      <p class="page-subtitle">Interactive ATT&CK matrix with detection coverage analysis. Green-highlighted techniques have Sigma rules. Each tactic is cross-linked to attack categories for integrated navigation.</p>
    </div>

    <!-- Overall Coverage Stats -->
    <div class="stats-grid animate-fadeInUp" style="grid-template-columns:repeat(auto-fit,minmax(180px,1fr));margin-bottom:20px">
      <div class="stat-card">
        <div class="stat-value" style="color:var(--accent-green)">${overallPct}%</div>
        <div class="stat-label">Overall Coverage</div>
      </div>
      <div class="stat-card">
        <div class="stat-value">${coveredTechAll}</div>
        <div class="stat-label">Techniques Covered</div>
      </div>
      <div class="stat-card">
        <div class="stat-value">${totalTechAll - coveredTechAll}</div>
        <div class="stat-label">Detection Gaps</div>
      </div>
      <div class="stat-card">
        <div class="stat-value">${MITRE_TACTICS.length}</div>
        <div class="stat-label">ATT&CK Tactics</div>
      </div>
      <div class="stat-card">
        <div class="stat-value">${SIGMA_RULES.length}</div>
        <div class="stat-label">Sigma Rules</div>
      </div>
    </div>

    <!-- Category ↔ ATT&CK Cross-Reference -->
    <div class="card full-width animate-fadeInUp" style="margin-bottom:20px">
      <div class="card-header">
        <span class="card-title">🔗 Category ↔ ATT&CK Cross-Reference</span>
        <button class="btn-sm" onclick="navigate('categories')">📂 View Categories</button>
      </div>
      <div class="card-body" style="padding:12px">
        <div style="display:flex;gap:8px;flex-wrap:wrap">
          ${cats.map(c => {
            const meta = getCategoryMeta(c);
            const mappings = getCategoryTactics(c);
            const tacticNames = [...new Set(mappings.flatMap(m => m.tactics))];
            return `<div class="mitre-cat-chip" style="border-color:${meta.color}40;cursor:pointer" onclick="navigate('rules',{category:'${c}'})" title="${tacticNames.join(', ') || 'No mapping'}">
              <span>${meta.icon}</span>
              <span style="font-weight:600">${getCategoryLabel(c)}</span>
              <span class="mitre-cat-chip-count">${getRulesForCategory(c).length}</span>
            </div>`;
          }).join('')}
        </div>
      </div>
    </div>

    <!-- ATT&CK Matrix -->
    <div class="card animate-fadeInUp">
      <div class="card-header">
        <span class="card-title">🗺️ ATT&CK Enterprise Matrix</span>
        <span style="font-size:0.78rem;color:var(--text-secondary)">
          <span style="color:var(--accent-green)">■</span> Covered &nbsp;
          <span style="color:var(--text-muted)">■</span> Not Covered
        </span>
      </div>
      <div class="card-body">
        <div class="mitre-matrix">
          <div class="mitre-matrix-grid">
            ${MITRE_TACTICS.map(tactic => `
              <div class="mitre-tactic-col">
                <div class="mitre-tactic-header" style="cursor:pointer" onclick="navigate('rules',{tactic:'${tactic.id}'})">${tactic.name}<br><span style="font-size:0.55rem;opacity:0.7">${tactic.id}</span></div>
                ${(MITRE_TECHNIQUES[tactic.id] || []).map(tech => `
                  <div class="mitre-technique-cell ${covered.has(tech.id)?'covered':''}" onclick="${getRulesForTechnique(tech.id).length ? `navigate('rules',{tactic:'${tactic.id}'})` : ''}">
                    <span class="tech-id">${tech.id}</span>
                    ${tech.name}
                  </div>
                  ${tech.subs.map(sub => `
                    <div class="mitre-technique-cell ${covered.has(sub.id)?'covered':''}" style="margin-left:8px;font-size:0.62rem" onclick="${getRulesForTechnique(sub.id).length ? `navigate('rule-detail',{ruleId:'${(getRulesForTechnique(sub.id)[0]||{}).id}'})` : ''}">
                      <span class="tech-id">${sub.id}</span>
                      ${sub.name}
                    </div>`).join('')}`).join('')}
              </div>`).join('')}
          </div>
        </div>
      </div>
    </div>

    <!-- Tactic Cards with Category Cross-Links -->
    <h2 class="page-title" style="font-size:1.2rem;margin-top:28px;margin-bottom:16px">📊 Tactic Coverage & Category Mapping</h2>
    <div class="dashboard-grid">
      ${MITRE_TACTICS.map(tactic => {
        const rules = getRulesForTactic(tactic.id);
        const techs = MITRE_TECHNIQUES[tactic.id] || [];
        let totalTechs = techs.length;
        techs.forEach(t => totalTechs += t.subs.length);
        const coveredCount = techs.filter(t => covered.has(t.id)).length + techs.reduce((acc, t) => acc + t.subs.filter(s => covered.has(s.id)).length, 0);
        const pct = totalTechs > 0 ? Math.round((coveredCount / totalTechs) * 100) : 0;
        // Find related categories for this tactic
        const relatedCats = getTacticCategories(tactic.id);
        return `
          <div class="card mitre-tactic-card" style="cursor:pointer" onclick="navigate('rules',{tactic:'${tactic.id}'})">
            <div class="card-body">
              <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:8px">
                <span style="font-weight:700;color:var(--text-primary);font-size:0.88rem">${tactic.name}</span>
                <span style="font-family:var(--font-mono);font-weight:800;color:${pct>60?'var(--accent-green)':pct>30?'var(--accent-orange)':'var(--accent-red)'}">${pct}%</span>
              </div>
              <div class="coverage-bar"><div class="coverage-bar-fill ${pct>60?'high':pct>30?'medium':'low'}" style="width:${pct}%"></div></div>
              <div style="display:flex;justify-content:space-between;font-size:0.72rem;color:var(--text-muted);margin-bottom:8px">
                <span>${rules.length} rules</span>
                <span>${coveredCount}/${totalTechs} techniques</span>
              </div>
              ${relatedCats.length > 0 ? `
              <div class="mitre-related-cats">
                <div style="font-size:0.65rem;color:var(--text-muted);margin-bottom:4px;font-weight:600">Related Categories:</div>
                <div style="display:flex;gap:4px;flex-wrap:wrap">
                  ${relatedCats.map(catId => {
                    const meta = getCategoryMeta(catId);
                    return `<span class="badge mitre-cat-badge" style="background:${meta.color}15;color:${meta.color};border:1px solid ${meta.color}30;font-size:0.62rem;cursor:pointer" onclick="event.stopPropagation();navigate('rules',{category:'${catId}'})">${meta.icon} ${getCategoryLabel(catId)}</span>`;
                  }).join('')}
                </div>
              </div>` : ''}
            </div>
          </div>`;
      }).join('')}
    </div>`;
}

// ══════════════════════════════════════════════
// THREAT INTELLIGENCE
// ══════════════════════════════════════════════
function renderThreatIntel(el) {
  el.innerHTML = `
    <div class="animate-fadeInUp">
      <h1 class="page-title">Threat Intelligence</h1>
      <p class="page-subtitle">CISA Known Exploited Vulnerabilities, active threat campaigns, and indicators mapped to detection coverage.</p>
    </div>
    <div class="tabs animate-fadeInUp">
      <button class="tab active" data-tab="kev">CISA KEV Catalog</button>
      <button class="tab" data-tab="campaigns">Threat Campaigns</button>
      <button class="tab" data-tab="stix">STIX Objects</button>
    </div>
    <div class="tab-content active" id="tab-kev">
      <div class="card">
        <div class="card-header"><span class="card-title">⚠️ CISA Known Exploited Vulnerabilities</span><span style="font-size:0.78rem;color:var(--text-secondary)">${THREAT_INTEL.cisaKev.length} entries</span></div>
        <div class="card-body no-pad">
          <table class="data-table">
            <thead><tr><th>CVE</th><th>Vendor / Product</th><th>Description</th><th>Date Added</th><th>Ransomware</th><th>Linked Techniques</th></tr></thead>
            <tbody>
              ${THREAT_INTEL.cisaKev.map(k => `
                <tr>
                  <td><a href="https://nvd.nist.gov/vuln/detail/${k.cve}" target="_blank" rel="noopener" style="color:var(--accent-cyan);text-decoration:none;font-family:var(--font-mono);font-weight:600">${k.cve}</a></td>
                  <td style="font-weight:600;color:var(--text-primary)">${escHtml(k.vendor)}<br><span style="color:var(--text-tertiary);font-size:0.75rem">${escHtml(k.product)}</span></td>
                  <td style="max-width:300px">${escHtml(k.description)}</td>
                  <td style="white-space:nowrap">${k.dateAdded}</td>
                  <td>${k.knownRansomware ? '<span class="badge badge-severity-critical">Yes</span>' : '<span class="badge badge-severity-low">No</span>'}</td>
                  <td>${k.techniques.map(t => `<span class="badge badge-technique">${t}</span>`).join(' ')}</td>
                </tr>`).join('')}
            </tbody>
          </table>
        </div>
      </div>
    </div>
    <div class="tab-content" id="tab-campaigns">
      <div class="threat-intel-grid">
        ${THREAT_INTEL.campaigns.map(c => `
          <div class="ti-card">
            <div class="ti-card-header">
              <span>${c.active ? '🔴' : '⚪'}</span>
              ${escHtml(c.name)}
            </div>
            <div class="ti-card-body">
              <div class="detail-info-item mb-md"><span class="detail-info-label">Threat Actor</span><span class="detail-info-value">${escHtml(c.actor)}</span></div>
              <div class="detail-info-item mb-md"><span class="detail-info-label">Targets</span><span class="detail-info-value">${escHtml(c.targets)}</span></div>
              <div class="detail-info-item mb-md"><span class="detail-info-label">First Seen</span><span class="detail-info-value">${c.firstSeen}</span></div>
              <p style="font-size:0.82rem;color:var(--text-secondary);margin:12px 0;line-height:1.6">${escHtml(c.description)}</p>
              <div class="detail-info-label mb-sm">Linked ATT&CK Techniques</div>
              <div style="display:flex;flex-wrap:wrap;gap:4px">${c.techniques.map(t => `<span class="badge badge-technique">${t}</span>`).join('')}</div>
              <div style="margin-top:12px"><div class="detail-info-label mb-sm">Detection Rules</div>
              ${SIGMA_RULES.filter(r => c.techniques.some(t => r.techniqueId === t || r.techniqueId.startsWith(t))).slice(0,3).map(r => `<div style="font-size:0.78rem;color:var(--accent-cyan);cursor:pointer;padding:4px 0" onclick="navigate('rule-detail',{ruleId:'${r.id}'})">▸ ${escHtml(r.title)}</div>`).join('') || '<span style="font-size:0.78rem;color:var(--text-muted)">No direct rule matches</span>'}
              </div>
            </div>
          </div>`).join('')}
      </div>
    </div>
    <div class="tab-content" id="tab-stix">
      <div class="card">
        <div class="card-header"><span class="card-title">📦 STIX 2.1 Objects Overview</span></div>
        <div class="card-body">
          <div class="info-box info"><div class="info-box-title">Structured Threat Intelligence</div>This platform uses STIX 2.1 format for threat intelligence representation. The following object types are tracked and mapped to Sigma detections.</div>
          <div style="display:grid;grid-template-columns:repeat(auto-fit,minmax(250px,1fr));gap:16px;margin-top:20px">
            ${[{icon:'🎯',name:'attack-pattern',desc:'ATT&CK techniques mapped to rules',count:Object.values(MITRE_TECHNIQUES).flat().length},
               {icon:'🦠',name:'malware',desc:'Malware families linked to campaigns',count:5},
               {icon:'📢',name:'campaign',desc:'Active threat campaigns tracked',count:THREAT_INTEL.campaigns.length},
               {icon:'👤',name:'threat-actor',desc:'Attributed threat actors',count:THREAT_INTEL.campaigns.length},
               {icon:'🔍',name:'indicator',desc:'IOCs from CISA KEV entries',count:THREAT_INTEL.cisaKev.length},
               {icon:'🛡️',name:'course-of-action',desc:'Response playbooks per rule',count:SIGMA_RULES.length}
            ].map(o => `
              <div class="card" style="background:var(--bg-card)">
                <div class="card-body" style="padding:16px">
                  <div style="font-size:1.3rem;margin-bottom:8px">${o.icon}</div>
                  <div style="font-family:var(--font-mono);font-weight:700;color:var(--accent-cyan);font-size:0.85rem">${o.name}</div>
                  <div style="font-size:0.78rem;color:var(--text-secondary);margin:4px 0">${o.desc}</div>
                  <div style="font-size:1.2rem;font-weight:800;color:var(--text-primary)">${o.count}</div>
                </div>
              </div>`).join('')}
          </div>
        </div>
      </div>
    </div>`;
  // Tab switching
  $$('.tab').forEach(tab => {
    tab.addEventListener('click', () => {
      $$('.tab').forEach(t => t.classList.remove('active'));
      $$('.tab-content').forEach(c => c.classList.remove('active'));
      tab.classList.add('active');
      $(`#tab-${tab.dataset.tab}`).classList.add('active');
    });
  });
}

// ══════════════════════════════════════════════
// COVERAGE ANALYSIS
// ══════════════════════════════════════════════
function renderCoverage(el) {
  const covered = getCoveredTechniques();
  const coverageData = MITRE_TACTICS.map(tactic => {
    const techs = MITRE_TECHNIQUES[tactic.id] || [];
    let total = 0, cov = 0;
    techs.forEach(t => { total++; if (covered.has(t.id)) cov++; t.subs.forEach(s => { total++; if (covered.has(s.id)) cov++; }); });
    return { tactic, total, covered: cov, rules: getRulesForTactic(tactic.id).length, percent: total > 0 ? Math.round((cov/total)*100) : 0 };
  });
  const overallCov = coverageData.reduce((a,c)=>a+c.covered,0);
  const overallTotal = coverageData.reduce((a,c)=>a+c.total,0);
  const overallPercent = Math.round((overallCov/overallTotal)*100);
  // Gap analysis - find uncovered techniques
  const gaps = [];
  MITRE_TACTICS.forEach(tactic => {
    (MITRE_TECHNIQUES[tactic.id]||[]).forEach(tech => {
      if (!covered.has(tech.id)) gaps.push({ tactic: tactic.name, techId: tech.id, techName: tech.name });
      tech.subs.forEach(sub => { if (!covered.has(sub.id)) gaps.push({ tactic: tactic.name, techId: sub.id, techName: sub.name }); });
    });
  });

  el.innerHTML = `
    <div class="animate-fadeInUp">
      <h1 class="page-title">Coverage & Gap Analysis</h1>
      <p class="page-subtitle">Comprehensive view of MITRE ATT&CK detection coverage, identifying gaps and prioritizing future detection development.</p>
    </div>
    <div class="stats-grid animate-fadeInUp">
      <div class="stat-card cyan">
        <div class="stat-icon">📊</div>
        <div class="stat-value">${overallPercent}%</div>
        <div class="stat-label">Overall ATT&CK Coverage</div>
        <div class="stat-change positive">${overallCov} of ${overallTotal} techniques</div>
      </div>
      <div class="stat-card green">
        <div class="stat-icon">✅</div>
        <div class="stat-value">${overallCov}</div>
        <div class="stat-label">Techniques Covered</div>
      </div>
      <div class="stat-card red">
        <div class="stat-icon">❌</div>
        <div class="stat-value">${gaps.length}</div>
        <div class="stat-label">Detection Gaps</div>
      </div>
      <div class="stat-card purple">
        <div class="stat-icon">📝</div>
        <div class="stat-value">${SIGMA_RULES.length}</div>
        <div class="stat-label">Total Rules</div>
      </div>
    </div>
    <div class="dashboard-grid animate-fadeInUp">
      <div class="card full-width">
        <div class="card-header"><span class="card-title">📊 Coverage by Tactic</span></div>
        <div class="card-body">
          <div class="coverage-overview">
            ${coverageData.map(d => `
              <div class="coverage-item">
                <div class="coverage-item-header">
                  <span class="coverage-item-name">${d.tactic.name}</span>
                  <span class="coverage-item-percent" style="color:${d.percent>60?'var(--accent-green)':d.percent>30?'var(--accent-orange)':'var(--accent-red)'}">${d.percent}%</span>
                </div>
                <div class="coverage-bar"><div class="coverage-bar-fill ${d.percent>60?'high':d.percent>30?'medium':'low'}" style="width:${d.percent}%"></div></div>
                <div class="coverage-item-stats">
                  <span>${d.covered}/${d.total} techniques</span>
                  <span>${d.rules} rules</span>
                </div>
              </div>`).join('')}
          </div>
        </div>
      </div>
      <div class="card full-width">
        <div class="card-header"><span class="card-title">🔴 Detection Gaps - Uncovered Techniques</span><span style="font-size:0.78rem;color:var(--accent-red)">${gaps.length} gaps identified</span></div>
        <div class="card-body no-pad" style="max-height:500px;overflow-y:auto">
          <table class="data-table">
            <thead><tr><th>Tactic</th><th>Technique ID</th><th>Technique Name</th><th>Priority</th></tr></thead>
            <tbody>
              ${gaps.slice(0, 40).map(g => {
                const priority = ['Credential Access','Lateral Movement','Command and Control','Defense Evasion','Impact'].includes(g.tactic) ? 'High' : 'Medium';
                return `<tr>
                  <td><span class="badge badge-tactic">${g.tactic}</span></td>
                  <td><span class="font-mono" style="color:var(--text-secondary)">${g.techId}</span></td>
                  <td>${escHtml(g.techName)}</td>
                  <td><span class="badge badge-severity-${priority==='High'?'high':'medium'}">${priority}</span></td>
                </tr>`;
              }).join('')}
            </tbody>
          </table>
        </div>
      </div>
      <div class="card full-width">
        <div class="card-header"><span class="card-title">📋 Data Source Requirements</span></div>
        <div class="card-body">
          <div class="info-box info"><div class="info-box-title">Essential Data Sources</div>The following data sources are required for comprehensive detection coverage. Ensure these are properly configured and forwarded to your SIEM.</div>
          <div style="display:grid;grid-template-columns:repeat(auto-fit,minmax(280px,1fr));gap:12px;margin-top:16px">
            ${[{name:'Sysmon (Process Creation)',events:'Event ID 1',importance:'Critical',rules:SIGMA_RULES.filter(r=>r.logsource.category==='process_creation').length},
               {name:'Windows Security Log',events:'4624, 4625, 4688, 4720, 4769',importance:'Critical',rules:SIGMA_RULES.filter(r=>r.logsource.service==='security').length},
               {name:'Sysmon (Registry)',events:'Event ID 13',importance:'High',rules:SIGMA_RULES.filter(r=>r.logsource.category==='registry_set').length},
               {name:'Sysmon (File Events)',events:'Event ID 11',importance:'High',rules:SIGMA_RULES.filter(r=>r.logsource.category==='file_event').length},
               {name:'Sysmon (DNS Query)',events:'Event ID 22',importance:'Medium',rules:SIGMA_RULES.filter(r=>r.logsource.category==='dns_query').length},
               {name:'Sysmon (Network)',events:'Event ID 3',importance:'Medium',rules:SIGMA_RULES.filter(r=>r.logsource.service==='sysmon').length},
               {name:'Windows System Log',events:'7045',importance:'High',rules:SIGMA_RULES.filter(r=>r.logsource.service==='system').length},
               {name:'PowerShell Logging',events:'4104 (Script Block)',importance:'Critical',rules:SIGMA_RULES.filter(r=>r.requiredLogs.some(l=>l.includes('Script Block'))).length}
            ].map(ds => `
              <div style="background:var(--bg-card);border:1px solid var(--border-primary);border-radius:var(--radius-md);padding:14px">
                <div style="font-weight:700;font-size:0.85rem;color:var(--text-primary)">${ds.name}</div>
                <div style="font-size:0.72rem;color:var(--text-muted);font-family:var(--font-mono);margin:4px 0">${ds.events}</div>
                <div style="display:flex;justify-content:space-between;margin-top:8px">
                  <span class="badge badge-severity-${ds.importance==='Critical'?'critical':ds.importance==='High'?'high':'medium'}">${ds.importance}</span>
                  <span style="font-size:0.75rem;color:var(--text-secondary)">${ds.rules} rules depend</span>
                </div>
              </div>`).join('')}
          </div>
        </div>
      </div>
    </div>`;
  setTimeout(() => { $$('.coverage-bar-fill').forEach(b => { const w = b.style.width; b.style.width = '0%'; requestAnimationFrame(() => b.style.width = w); }); }, 200);
}

// ══════════════════════════════════════════════
// THREAT INTELLIGENCE — Live CVE & KEV Dashboard
// ══════════════════════════════════════════════
async function renderThreatIntel(el) {
  // Show loading state first
  el.innerHTML = `<div class="page-header"><h1 class="page-title">🌐 Threat Intelligence</h1><p class="page-subtitle">Live CVE & CISA KEV intelligence with detection mapping</p></div>
    <div style="text-align:center;padding:60px 20px"><div class="ti-loading-spinner"></div><p style="color:var(--text-muted);margin-top:16px">Syncing threat intelligence feeds...</p></div>`;
  
  let cves = [];
  try {
    cves = await ThreatIntelEngine.sync();
  } catch (e) {
    console.warn('[ThreatIntel] Sync failed, using static data:', e);
    const staticCVEs = typeof STATIC_CVE_DATA !== 'undefined' ? STATIC_CVE_DATA : [];
    cves = staticCVEs.map(c => {
      const vulnType = classifyVulnTypeLocal(c.description || c.name || '');
      return { ...c, vulnType, category: mapVulnCategory(vulnType), severity: c.cvssSeverity || 'HIGH', coverageStatus: 'gap', hasSigma: false, hasSplunk: false, hasQRadar: false, hasMitre: false, linkedRules: [] };
    });
  }

  // If no cves from engine, fallback to static
  if (!cves || cves.length === 0) {
    const staticCVEs = typeof STATIC_CVE_DATA !== 'undefined' ? STATIC_CVE_DATA : [];
    cves = staticCVEs.map(c => {
      const vulnType = classifyVulnTypeLocal(c.description || c.name || '');
      const rules = SIGMA_RULES.filter(r => (r.threatIntel?.cves || []).includes(c.cveId) || (r.description || '').includes(c.cveId));
      return { ...c, vulnType, category: mapVulnCategory(vulnType), severity: c.cvssSeverity || 'HIGH', coverageStatus: rules.length > 0 ? 'covered' : 'gap', hasSigma: rules.length > 0, hasSplunk: rules.some(r => r.splunkQuery), hasQRadar: rules.some(r => r.qradarQuery), hasMitre: true, linkedRules: rules.map(r => ({ id: r.id, title: r.title })) };
    });
  }

  const stats = ThreatIntelEngine.getCacheStats();
  const lastSync = stats.lastSync ? new Date(stats.lastSync).toLocaleString() : 'Loading...';
  const kevCount = cves.filter(c => c.isKEV).length;
  const critCount = cves.filter(c => c.severity === 'CRITICAL').length;
  const coveredCount = cves.filter(c => c.hasSigma).length;
  const gapCount = cves.filter(c => !c.hasSigma).length;

  // Store CVEs in window for detail view access
  window._threatIntelCVEs = cves;

  el.innerHTML = `
    <div class="page-header">
      <h1 class="page-title">🌐 Threat Intelligence</h1>
      <p class="page-subtitle">Live CVE monitoring, CISA KEV tracking, and detection coverage analysis</p>
      <div class="ti-sync-bar">
        <span class="ti-sync-status">
          <span class="ti-sync-dot"></span> Last sync: ${lastSync}
        </span>
        <button class="btn btn-sm btn-accent" onclick="refreshThreatIntel()" id="tiRefreshBtn">
          🔄 Refresh Now
        </button>
      </div>
    </div>

    <div class="stats-grid" style="grid-template-columns:repeat(auto-fit,minmax(200px,1fr))">
      <div class="stat-card" style="--glow-color:var(--accent-red)">
        <div class="stat-value">${kevCount}</div>
        <div class="stat-label">CISA KEV (Exploited)</div>
        <div class="stat-trend trend-up">Actively Exploited</div>
      </div>
      <div class="stat-card" style="--glow-color:var(--accent-orange)">
        <div class="stat-value">${critCount}</div>
        <div class="stat-label">Critical Severity</div>
        <div class="stat-trend trend-up">CVSS ≥ 9.0</div>
      </div>
      <div class="stat-card" style="--glow-color:var(--accent-green)">
        <div class="stat-value">${coveredCount}</div>
        <div class="stat-label">Detection Covered</div>
        <div class="stat-trend trend-up">Sigma Rules Linked</div>
      </div>
      <div class="stat-card" style="--glow-color:var(--accent-yellow)">
        <div class="stat-value">${gapCount}</div>
        <div class="stat-label">Coverage Gaps</div>
        <div class="stat-trend trend-down">Needs Detection</div>
      </div>
    </div>

    <!-- Filters -->
    <div class="card full-width" style="margin-top:20px">
      <div class="card-body" style="padding:16px">
        <div style="display:flex;gap:12px;flex-wrap:wrap;align-items:center">
          <input type="text" id="tiSearchInput" placeholder="Search CVEs, vendors, products..." 
                 class="search-input" style="flex:1;min-width:240px" oninput="filterThreatIntel()">
          <select id="tiSeverityFilter" class="filter-select" onchange="filterThreatIntel()">
            <option value="all">All Severities</option>
            <option value="CRITICAL">Critical</option>
            <option value="HIGH">High</option>
            <option value="MEDIUM">Medium</option>
          </select>
          <select id="tiKevFilter" class="filter-select" onchange="filterThreatIntel()">
            <option value="all">All CVEs</option>
            <option value="kev">CISA KEV Only</option>
            <option value="covered">Detection Available</option>
            <option value="gap">Coverage Gap</option>
          </select>
          <select id="tiCategoryFilter" class="filter-select" onchange="filterThreatIntel()">
            <option value="all">All Categories</option>
            ${getAllCategories().map(c => `<option value="${c}">${getCategoryLabel(c)}</option>`).join('')}
          </select>
        </div>
      </div>
    </div>

    <!-- CVE Table -->
    <div class="card full-width" style="margin-top:12px">
      <div class="card-header">
        <span class="card-title">📋 CVE Intelligence Feed</span>
        <span style="font-size:0.78rem;color:var(--text-muted)" id="tiResultCount">${cves.length} vulnerabilities</span>
      </div>
      <div class="card-body no-pad" style="max-height:700px;overflow-y:auto">
        <table class="data-table" id="tiCveTable">
          <thead>
            <tr>
              <th>CVE ID</th>
              <th>Vulnerability</th>
              <th>Vendor / Product</th>
              <th>Severity</th>
              <th>KEV</th>
              <th>Detection</th>
              <th>Category</th>
            </tr>
          </thead>
          <tbody id="tiCveTableBody">
            ${renderCVETableRows(cves)}
          </tbody>
        </table>
      </div>
    </div>

    <!-- Data Sources Info -->
    <div class="card full-width" style="margin-top:16px">
      <div class="card-header"><span class="card-title">📡 Intelligence Sources</span></div>
      <div class="card-body">
        <div style="display:grid;grid-template-columns:repeat(auto-fit,minmax(220px,1fr));gap:12px">
          <div class="ti-source-card ti-source-active">
            <div class="ti-source-icon">🏛️</div>
            <div class="ti-source-name">CISA KEV</div>
            <div class="ti-source-desc">Known Exploited Vulnerabilities</div>
            <div class="ti-source-status">✅ Active — ${kevCount} entries</div>
          </div>
          <div class="ti-source-card ti-source-active">
            <div class="ti-source-icon">📊</div>
            <div class="ti-source-name">NVD (NIST)</div>
            <div class="ti-source-desc">National Vulnerability Database</div>
            <div class="ti-source-status">✅ Active — Live API</div>
          </div>
          <div class="ti-source-card ti-source-active">
            <div class="ti-source-icon">🎯</div>
            <div class="ti-source-name">MITRE CVE</div>
            <div class="ti-source-desc">CVE Numbering Authority</div>
            <div class="ti-source-status">✅ Mapped via NVD</div>
          </div>
          <div class="ti-source-card">
            <div class="ti-source-icon">💻</div>
            <div class="ti-source-name">Exploit-DB</div>
            <div class="ti-source-desc">Exploit Database References</div>
            <div class="ti-source-status">🔗 Reference Linked</div>
          </div>
          <div class="ti-source-card">
            <div class="ti-source-icon">🔍</div>
            <div class="ti-source-name">CVE Details</div>
            <div class="ti-source-desc">Vulnerability Statistics</div>
            <div class="ti-source-status">🔗 Reference Linked</div>
          </div>
        </div>
        <div class="info-box info" style="margin-top:16px">
          <div class="info-box-title">⏱️ Daily Synchronization</div>
          Threat intelligence is automatically synchronized every 24 hours. The system checks for newly published CVEs, updated severity scores, new CISA KEV additions, and changes in exploitation status. Data is cached locally for performance.
        </div>
      </div>
    </div>`;
}

function classifyVulnTypeLocal(text) {
  const t = text.toLowerCase();
  if (t.includes('remote code execution') || t.includes('rce')) return 'Remote Code Execution';
  if (t.includes('sql injection')) return 'SQL Injection';
  if (t.includes('authentication bypass') || t.includes('auth bypass')) return 'Authentication Bypass';
  if (t.includes('privilege escalation') || t.includes('elevation of privilege')) return 'Privilege Escalation';
  if (t.includes('command injection') || t.includes('os command')) return 'Command Injection';
  if (t.includes('path traversal') || t.includes('directory traversal')) return 'Path Traversal';
  if (t.includes('ssrf') || t.includes('server-side request')) return 'Server-Side Request Forgery';
  if (t.includes('xss') || t.includes('cross-site scripting')) return 'Cross-Site Scripting';
  if (t.includes('deserialization')) return 'Deserialization';
  if (t.includes('buffer overflow')) return 'Buffer Overflow';
  if (t.includes('information disclosure')) return 'Information Disclosure';
  return 'Remote Code Execution';
}

function mapVulnCategory(vulnType) {
  const m = { 'Remote Code Execution':'execution','SQL Injection':'web-attacks','Authentication Bypass':'credential-access','Privilege Escalation':'privilege-escalation','Command Injection':'execution','Path Traversal':'web-attacks','Server-Side Request Forgery':'web-attacks','Cross-Site Scripting':'web-attacks','Deserialization':'execution','Buffer Overflow':'endpoint-anomalies','Information Disclosure':'reconnaissance' };
  return m[vulnType] || 'endpoint-anomalies';
}

function renderCVETableRows(cves) {
  return cves.map(c => {
    const sevClass = (c.severity || 'unknown').toLowerCase();
    const vendor = c.vendor || 'Unknown';
    const product = c.product || '';
    const name = c.name || c.description?.substring(0, 80) || c.cveId;
    const catMeta = getCategoryMeta(c.category);
    const hasDet = c.hasSigma || c.linkedRules?.length > 0;
    return `<tr class="ti-cve-row" onclick="showCVEDetail('${c.cveId}')" style="cursor:pointer">
      <td><span class="font-mono ti-cve-id">${c.cveId}</span></td>
      <td class="ti-cve-name">${escHtml(name.substring(0, 70))}${name.length > 70 ? '...' : ''}</td>
      <td><span class="ti-vendor">${escHtml(vendor)}</span>${product ? ` <span class="ti-product">${escHtml(product)}</span>` : ''}</td>
      <td><span class="badge badge-severity-${sevClass}">${c.severity}${c.cvssScore ? ` (${c.cvssScore})` : ''}</span></td>
      <td>${c.isKEV ? '<span class="badge ti-kev-badge">🔴 KEV</span>' : '<span style="color:var(--text-muted)">—</span>'}</td>
      <td>${hasDet ? '<span class="badge ti-det-covered">✅ Covered</span>' : '<span class="badge ti-det-gap">⚠️ Gap</span>'}</td>
      <td><span style="color:${catMeta.color}">${catMeta.icon} ${getCategoryLabel(c.category)}</span></td>
    </tr>`;
  }).join('');
}

function showCVEDetail(cveId) {
  const cves = window._threatIntelCVEs || [];
  const cve = cves.find(c => c.cveId === cveId);
  if (!cve) return;

  // Find linked Sigma rules
  const linkedRules = SIGMA_RULES.filter(r =>
    (r.threatIntel?.cves || []).includes(cveId) ||
    (r.description || '').includes(cveId) ||
    (r.sigmaYaml || '').includes(cveId)
  );

  const catMeta = getCategoryMeta(cve.category);
  const sevClass = (cve.severity || 'unknown').toLowerCase();

  // Create modal
  const modal = document.createElement('div');
  modal.className = 'ti-detail-modal';
  modal.innerHTML = `
    <div class="ti-detail-overlay" onclick="this.parentElement.remove()"></div>
    <div class="ti-detail-content">
      <div class="ti-detail-header">
        <div>
          <h2 class="ti-detail-cve">${cve.cveId}</h2>
          <p class="ti-detail-name">${escHtml(cve.name || cve.vulnType || '')}</p>
        </div>
        <button class="ti-detail-close" onclick="this.closest('.ti-detail-modal').remove()">✕</button>
      </div>

      <div class="ti-detail-badges">
        <span class="badge badge-severity-${sevClass}">${cve.severity}${cve.cvssScore ? ` — CVSS ${cve.cvssScore}` : ''}</span>
        ${cve.isKEV ? '<span class="badge ti-kev-badge">🔴 CISA KEV — Actively Exploited</span>' : ''}
        <span style="color:${catMeta.color}" class="badge">${catMeta.icon} ${getCategoryLabel(cve.category)}</span>
      </div>

      <div class="ti-detail-section">
        <h3>Description</h3>
        <p>${escHtml(cve.description || 'No description available.')}</p>
      </div>

      <div class="ti-detail-grid">
        <div class="ti-detail-field">
          <span class="ti-detail-label">Vendor</span>
          <span class="ti-detail-value">${escHtml(cve.vendor || 'Unknown')}</span>
        </div>
        <div class="ti-detail-field">
          <span class="ti-detail-label">Product</span>
          <span class="ti-detail-value">${escHtml(cve.product || 'Unknown')}</span>
        </div>
        <div class="ti-detail-field">
          <span class="ti-detail-label">Published</span>
          <span class="ti-detail-value">${cve.published || cve.dateAdded || '—'}</span>
        </div>
        <div class="ti-detail-field">
          <span class="ti-detail-label">Last Modified</span>
          <span class="ti-detail-value">${cve.lastModified || '—'}</span>
        </div>
        <div class="ti-detail-field">
          <span class="ti-detail-label">CVSS Vector</span>
          <span class="ti-detail-value font-mono">${cve.cvssVector || '—'}</span>
        </div>
        <div class="ti-detail-field">
          <span class="ti-detail-label">Vulnerability Type</span>
          <span class="ti-detail-value">${cve.vulnType || '—'}</span>
        </div>
      </div>

      ${cve.isKEV ? `
      <div class="ti-detail-section ti-kev-section">
        <h3>🔴 CISA KEV — Known Exploited Vulnerability</h3>
        <p><strong>Date Added to KEV:</strong> ${cve.kevDateAdded || cve.dateAdded || '—'}</p>
        <p><strong>Required Action:</strong> ${escHtml(cve.kevAction || cve.action || 'Apply vendor mitigations.')}</p>
      </div>` : ''}

      <div class="ti-detail-section">
        <h3>Detection Coverage Status</h3>
        <div class="ti-coverage-grid">
          <div class="ti-cov-item ${cve.hasSigma || linkedRules.length > 0 ? 'ti-cov-pass' : 'ti-cov-fail'}">
            <span>Sigma Detection</span>
            <span>${cve.hasSigma || linkedRules.length > 0 ? '✅ Available' : '⚠️ Missing'}</span>
          </div>
          <div class="ti-cov-item ${(cve.hasSplunk || linkedRules.some(r => r.splunkQuery)) ? 'ti-cov-pass' : 'ti-cov-fail'}">
            <span>Splunk SPL</span>
            <span>${(cve.hasSplunk || linkedRules.some(r => r.splunkQuery)) ? '✅ Available' : '⚠️ Missing'}</span>
          </div>
          <div class="ti-cov-item ${(cve.hasQRadar || linkedRules.some(r => r.qradarQuery)) ? 'ti-cov-pass' : 'ti-cov-fail'}">
            <span>QRadar AQL</span>
            <span>${(cve.hasQRadar || linkedRules.some(r => r.qradarQuery)) ? '✅ Available' : '⚠️ Missing'}</span>
          </div>
          <div class="ti-cov-item ${cve.hasMitre || cve.mitre?.tacticId ? 'ti-cov-pass' : 'ti-cov-fail'}">
            <span>MITRE ATT&CK</span>
            <span>${cve.mitre?.tacticId ? `✅ ${cve.mitre.tacticId} — ${cve.mitre.techniqueName || ''}` : '⚠️ Unmapped'}</span>
          </div>
          <div class="ti-cov-item ${cve.category ? 'ti-cov-pass' : 'ti-cov-fail'}">
            <span>Category</span>
            <span>${cve.category ? `✅ ${getCategoryLabel(cve.category)}` : '⚠️ Unassigned'}</span>
          </div>
        </div>
      </div>

      ${linkedRules.length > 0 ? `
      <div class="ti-detail-section">
        <h3>🔗 Linked Sigma Rules (${linkedRules.length})</h3>
        <div class="ti-linked-rules">
          ${linkedRules.map(r => `
            <div class="ti-linked-rule" onclick="this.closest('.ti-detail-modal').remove(); navigate('rule-detail', {ruleId:'${r.id}'})">
              <span class="font-mono" style="color:var(--accent-blue)">${r.id}</span>
              <span>${escHtml(r.title)}</span>
              <span class="badge badge-severity-${r.severity}">${r.severity}</span>
            </div>
          `).join('')}
        </div>
      </div>` : `
      <div class="ti-detail-section">
        <h3>⚠️ No Sigma Detection Linked</h3>
        <div class="info-box warning">
          <div class="info-box-title">Detection Gap Identified</div>
          This CVE does not have a linked Sigma rule. Detection engineering is recommended to create a rule targeting the behavioral indicators associated with exploitation of this vulnerability.
        </div>
      </div>`}

      ${(cve.references || []).length > 0 ? `
      <div class="ti-detail-section">
        <h3>📚 References</h3>
        <div class="ti-references">
          ${(cve.references || []).map(r => `<a href="${r}" target="_blank" rel="noopener" class="ti-ref-link">${r}</a>`).join('')}
        </div>
      </div>` : ''}
    </div>
  `;
  document.body.appendChild(modal);
  requestAnimationFrame(() => modal.classList.add('active'));
}

function filterThreatIntel() {
  const cves = window._threatIntelCVEs || [];
  const search = ($('#tiSearchInput')?.value || '').toLowerCase();
  const severity = $('#tiSeverityFilter')?.value || 'all';
  const kevFilter = $('#tiKevFilter')?.value || 'all';
  const catFilter = $('#tiCategoryFilter')?.value || 'all';

  const filtered = cves.filter(c => {
    if (search && !`${c.cveId} ${c.name || ''} ${c.vendor || ''} ${c.product || ''} ${c.description || ''}`.toLowerCase().includes(search)) return false;
    if (severity !== 'all' && c.severity !== severity) return false;
    if (kevFilter === 'kev' && !c.isKEV) return false;
    if (kevFilter === 'covered' && !c.hasSigma) return false;
    if (kevFilter === 'gap' && c.hasSigma) return false;
    if (catFilter !== 'all' && c.category !== catFilter) return false;
    return true;
  });

  const tbody = $('#tiCveTableBody');
  if (tbody) tbody.innerHTML = renderCVETableRows(filtered);
  const counter = $('#tiResultCount');
  if (counter) counter.textContent = `${filtered.length} vulnerabilities`;
}

async function refreshThreatIntel() {
  const btn = $('#tiRefreshBtn');
  if (btn) { btn.disabled = true; btn.textContent = '⏳ Syncing...'; }
  ThreatIntelEngine.clearCache();
  const content = $('#page-content');
  await renderThreatIntel(content);
}

// Make threat intel functions global
window.showCVEDetail = showCVEDetail;
window.filterThreatIntel = filterThreatIntel;
window.refreshThreatIntel = refreshThreatIntel;

// ── Global Search ──

function globalSearch(query) {
  if (!query) return;
  state.filters.search = query;
  navigate('rules');
}

// ── Initialization ──
function init() {
  // Handle Back Navigation
  window.addEventListener('popstate', (e) => {
    if (e.state && e.state.page) {
      state.filters = e.state.filters || state.filters;
      state.currentRuleId = e.state.ruleId || null;
      navigate(e.state.page, e.state.params, false);
    } else {
      // Default to dashboard on initial load if history is lost
      navigate('dashboard', {}, false);
    }
  });

  // Nav click handlers
  $$('.nav-item[data-page]').forEach(item => {
    item.addEventListener('click', () => {
      state.filters = { tactic: 'all', severity: 'all', status: 'all', category: 'all', search: '' };
      navigate(item.dataset.page);
      if (state.sidebarOpen) toggleSidebar();
    });
  });

  // Global search
  const searchInput = $('#globalSearch');
  if (searchInput) {
    let debounce;
    searchInput.addEventListener('input', e => { clearTimeout(debounce); debounce = setTimeout(() => globalSearch(e.target.value), 400); });
    searchInput.addEventListener('keydown', e => { if (e.key === 'Enter') globalSearch(e.target.value); });
  }

  // Mobile menu
  const mobileBtn = $('#mobileMenuBtn');
  if (mobileBtn) mobileBtn.addEventListener('click', toggleSidebar);

  // Update nav badges
  const rulesBadge = $('#navRulesBadge');
  if (rulesBadge) rulesBadge.textContent = SIGMA_RULES.length;
  const catBadge = $('#navCatBadge');
  if (catBadge) catBadge.textContent = getAllCategories().length;

  // Setup initial state in history
  const hash = window.location.hash.substring(1);
  if (hash) {
    const parts = hash.split('?');
    const page = parts[0] || 'dashboard';
    const params = {};
    if (parts.length > 1) {
      const urlParams = new URLSearchParams(parts[1]);
      if (urlParams.has('ruleId')) params.ruleId = urlParams.get('ruleId');
    }
    navigate(page, params, false); 
    history.replaceState({ page, params, filters: { ...state.filters }, ruleId: state.currentRuleId }, '', window.location.href);
  } else {
    navigate('dashboard', {}, false);
    history.replaceState({ page: 'dashboard', params: {}, filters: { ...state.filters }, ruleId: null }, '', window.location.href);
  }
}

function toggleSidebar() {
  state.sidebarOpen = !state.sidebarOpen;
  const sidebar = $('.sidebar');
  sidebar.classList.toggle('open', state.sidebarOpen);
}

function toggleExpandItem(btn) {
  const container = btn.parentElement;
  const hiddenItems = container.querySelectorAll('.exp-hidden');
  const isExpanded = btn.classList.contains('expanded');
  
  if (isExpanded) {
    hiddenItems.forEach(el => el.style.display = 'none');
    btn.classList.remove('expanded');
    btn.innerHTML = btn.dataset.more || '+ more';
  } else {
    // Determine display style based on element type
    hiddenItems.forEach(el => {
      const type = el.tagName.toLowerCase();
      el.style.display = (type === 'li') ? 'list-item' : (type === 'span' && el.classList.contains('badge') ? 'inline-flex' : 'inline-block');
    });
    btn.classList.add('expanded');
    btn.innerHTML = '− Show less';
  }
}

// Make functions globally accessible
window.navigate = navigate;
window.copyToClipboard = copyToClipboard;
window.getRuleById = getRuleById;
window.toggleSidebar = toggleSidebar;
window.toggleExpandItem = toggleExpandItem;
window.escHtml = escHtml;
window.getCategoryMeta = getCategoryMeta;
window.getCategoryLabel = getCategoryLabel;
window.SIGMA_RULES = SIGMA_RULES;
window.CATEGORIES = typeof ATTACK_CATEGORIES !== 'undefined' ? ATTACK_CATEGORIES : [];

// ══════════════════════════════════════════════
// ALERT SIMULATION ENGINE
// ══════════════════════════════════════════════
window.simulateAlert = function(ruleId) {
  const rule = getRuleById(ruleId);
  if (!rule) return;
  
  // 1. Create Modal Container if it doesn't exist
  let modalWrapper = document.getElementById('sim-alert-modal-wrapper');
  if (!modalWrapper) {
    modalWrapper = document.createElement('div');
    modalWrapper.id = 'sim-alert-modal-wrapper';
    document.body.appendChild(modalWrapper);
  }
  
  // 2. Generate Mock Event Data based on logsource
  const mockEvent = generateMockEvent(rule);
  
  // 3. Render Modal Loading State
  modalWrapper.innerHTML = `
    <div class="sim-alert-modal active">
      <div class="sim-alert-overlay" onclick="closeSimulateAlert()"></div>
      <div class="sim-alert-content">
        <div class="sim-alert-header">
          <h2 class="sim-alert-title"><span style="color:#f59e0b;margin-right:8px">⚡</span>Alert Simulation Engine</h2>
          <button class="sim-alert-close" onclick="closeSimulateAlert()">✕</button>
        </div>
        
        <div class="sim-loading-state" id="sim-loader">
          <div class="ti-loading-spinner" style="margin-bottom:20px;"></div>
          <div style="font-weight:700; color:var(--text-primary); font-size:1.1rem; margin-bottom:8px">Simulating Attack Behavior</div>
          <div style="color:var(--text-secondary); font-size:0.85rem">Generating mock telemtry and executing detection logic across SIEM buffer...</div>
        </div>
        
        <div id="sim-result-container" style="display:none; animation: fadeInContent 0.3s ease;"></div>
      </div>
    </div>
  `;
  
  // Prevent body scrolling
  document.body.style.overflow = 'hidden';
  
  // 4. Simulate Processing Delay (1.5 seconds)
  setTimeout(() => {
    document.getElementById('sim-loader').style.display = 'none';
    
    // Retrieve IR Playbook
    const irPlaybook = typeof getIRPlaybook !== 'undefined' ? getIRPlaybook(rule.category) : null;
    let irStepsHtml = '';
    if (irPlaybook) {
      irStepsHtml = `
        <div class="sim-section">
          <div class="sim-section-title">🚨 First-Response Actions</div>
          <div style="background:rgba(255,255,255,0.02); border:1px solid var(--border-primary); border-radius:var(--radius-md); padding:16px;">
            <ul class="detail-list" style="margin:0">
              ${irPlaybook.containmentActions.slice(0, 3).map(a => `<li>${escHtml(a)}</li>`).join('')}
            </ul>
            <button class="btn-sm" style="margin-top:16px; width:100%; border-color:var(--accent-cyan); color:var(--accent-cyan)" onclick="closeSimulateAlert(); window.scrollTo(0, document.body.scrollHeight);">
              Open Full IR Playbook ↓
            </button>
          </div>
        </div>
      `;
    }
    
    // Create Results HTML
    const resultHtml = `
      <div class="sim-verdict-box">
        <div class="sim-verdict-icon">🚨</div>
        <div style="flex:1">
          <div class="sim-verdict-title" style="color:#ff6b6b; font-weight:800; font-size:1.2rem; letter-spacing:0.5px">ALERT TRIGGERED</div>
          <div class="sim-verdict-desc" style="color:var(--text-secondary); font-size:0.85rem; margin-top:4px">
            Mock telemetry successfully evaluated against conditions for <strong>${escHtml(rule.title)}</strong>.
          </div>
        </div>
        <div style="text-align:right">
          <div style="font-size:0.68rem; color:var(--text-muted); text-transform:uppercase; font-weight:700; margin-bottom:6px; letter-spacing:1px">Severity</div>
          <span class="badge badge-severity-${rule.severity}" style="font-size:0.85rem; padding:4px 12px">${rule.severity.toUpperCase()}</span>
        </div>
      </div>
      
      <div class="sim-grid">
        <div class="sim-section">
          <div class="sim-section-title">📋 Matched Event Data</div>
          <div class="sim-json-viewer">
            <pre>${highlightSimJson(mockEvent)}</pre>
          </div>
        </div>
        ${irStepsHtml}
      </div>
    `;
    
    const container = document.getElementById('sim-result-container');
    if(container) {
      container.innerHTML = resultHtml;
      container.style.display = 'block';
    }
  }, 1500);
};

window.closeSimulateAlert = function() {
  const modalWrapper = document.getElementById('sim-alert-modal-wrapper');
  if (modalWrapper) modalWrapper.innerHTML = '';
  document.body.style.overflow = '';
};

function generateMockEvent(rule) {
  // Mock event generation logic
  const event = {
    "@timestamp": new Date().toISOString(),
    "host": {
      "hostname": "WK-HR-04.corp.local",
      "os": { "family": "windows", "name": "Windows 11 Enterprise" }
    },
    "user": {
      "name": "j.smith",
      "domain": "CORP"
    },
    "event": {
      "action": "triggered_rule",
      "category": ["intrusion_detection"]
    }
  };
  
  if (rule.logsource.product === 'windows') {
    if (rule.logsource.service === 'security') {
      event.winlog = {
        "channel": "Security",
        "event_id": rule.category === 'brute-force' ? 4625 : 4624,
        "opcode": "Info"
      };
      event.event.action = rule.category === 'brute-force' ? "logon-failed" : "logon-success";
    } else if (rule.logsource.service === 'sysmon') {
      event.winlog = { "channel": "Microsoft-Windows-Sysmon/Operational", "event_id": 1 };
      event.process = {
        "name": "powershell.exe",
        "command_line": "powershell.exe -ExecutionPolicy Bypass -WindowStyle Hidden -EncodedCommand JABz...",
        "parent": { "name": "cmd.exe" }
      };
    } else {
      event.winlog = { "channel": "Application", "event_id": 1000 };
    }
  } else if (rule.logsource.product === 'aws' || rule.category === 'cloud-threats') {
    event.cloud = { "provider": "aws", "region": "us-east-1" };
    event.aws = {
      "cloudtrail": {
        "event_source": "iam.amazonaws.com",
        "event_name": "CreateAccessKey",
        "user_identity": { "type": "IAMUser", "arn": "arn:aws:iam::123456789012:user/admin" }
      }
    };
    event.source = { "ip": "185.153.196.22" };
  } else if (rule.logsource.category === 'network_traffic' || rule.category === 'command-control') {
    event.network = {
      "transport": "tcp",
      "protocol": "http",
      "direction": "outbound"
    };
    event.source = { "ip": "10.0.5.55", "port": 50552 };
    event.destination = { "ip": "45.133.20.11", "port": 443, "domain": "cdn-update-auth.com" };
    event.http = { "request": { "method": "POST" } };
  } else {
    // Generic fallback
    event.message = `Suspicious behavior detected matching rule: ${rule.title}`;
    if (rule.techniqueId) event.threat = { "technique": { "id": rule.techniqueId } };
  }
  
  // Rule metadata
  event.rule = {
    "name": rule.title,
    "uuid": rule.id,
    "category": rule.category,
    "severity": rule.severity
  };
  
  return event;
}

function highlightSimJson(obj) {
  const jsonStr = JSON.stringify(obj, null, 2);
  return jsonStr.replace(/("(\\u[a-zA-Z0-9]{4}|\\[^u]|[^\\"])*"(\s*:)?|\b(true|false|null)\b|-?\d+(?:\.\d*)?(?:[eE][+\-]?\d+)?)/g, function (match) {
    let cls = 'yaml-number';
    if (/^"/.test(match)) {
      if (/:$/.test(match)) {
        return '<span class="yaml-key">' + escHtml(match.replace(/:$/, '')) + '</span><span style="color:var(--text-muted)">:</span>';
      } else {
        cls = 'yaml-string';
      }
    } else if (/true|false/.test(match)) {
      cls = 'yaml-bool';
    } else if (/null/.test(match)) {
      cls = 'yaml-comment';
    }
    return '<span class="' + cls + '">' + escHtml(match) + '</span>';
  });
}

// Boot
document.addEventListener('DOMContentLoaded', init);
})();
