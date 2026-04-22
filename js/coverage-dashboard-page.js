// ══════════════════════════════════════════════════════════════
// COVERAGE & CONFIDENCE DASHBOARD — SigmaGuard v5.0
// ══════════════════════════════════════════════════════════════
'use strict';

function renderCoverageConfidencePage() {
  const rules = typeof SIGMA_RULES !== 'undefined' ? SIGMA_RULES : [];
  const summary = typeof ValidationEngine !== 'undefined' ? ValidationEngine.getSummary() : null;
  const catMeta = typeof CATEGORY_META !== 'undefined' ? CATEGORY_META : {};

  // Category stats
  const catStats = {};
  rules.forEach(r => {
    const c = r.category || 'unknown';
    if (!catStats[c]) catStats[c] = { count:0, critical:0, high:0, medium:0, low:0, techniques:new Set() };
    catStats[c].count++;
    catStats[c][r.severity]++;
    catStats[c].techniques.add(r.techniqueId);
  });

  // MITRE coverage
  let totalTech = 0, coveredTech = new Set();
  rules.forEach(r => { coveredTech.add(r.techniqueId); coveredTech.add(r.techniqueId.split('.')[0]); });
  if (typeof MITRE_TECHNIQUES !== 'undefined') {
    Object.values(MITRE_TECHNIQUES).forEach(techs => { techs.forEach(t => { totalTech++; if(t.subs) t.subs.forEach(() => totalTech++); }); });
  }
  const mitreCovPct = totalTech > 0 ? Math.round((coveredTech.size / totalTech) * 100) : 0;

  // Validation summary
  const vs = summary || { totalRules:rules.length, accepted:0, needsReview:0, rejected:0, avgConfidence:0,
    sigmaValid:0, splunkValid:0, qradarValid:0, wazuhValid:0, wazuhCorrelation:0, crossConsistent:0, byCategory:{} };

  const acceptPct = vs.totalRules > 0 ? Math.round((vs.accepted/vs.totalRules)*100) : 0;
  const sigmaPct = vs.totalRules > 0 ? Math.round((vs.sigmaValid/vs.totalRules)*100) : 0;
  const splunkPct = vs.totalRules > 0 ? Math.round((vs.splunkValid/vs.totalRules)*100) : 0;
  const qradarPct = vs.totalRules > 0 ? Math.round((vs.qradarValid/vs.totalRules)*100) : 0;
  const wazuhPct = vs.totalRules > 0 ? Math.round(((vs.wazuhValid+vs.wazuhCorrelation)/vs.totalRules)*100) : 0;
  const crossPct = vs.totalRules > 0 ? Math.round((vs.crossConsistent/vs.totalRules)*100) : 0;

  // Build category rows
  const sortedCats = Object.entries(catStats).sort((a,b) => b[1].count - a[1].count);
  let catRows = '';
  sortedCats.forEach(([catId, s]) => {
    const meta = catMeta[catId] || { name:catId, icon:'📁' };
    const catV = vs.byCategory[catId] || { total:s.count, accepted:0, avgScore:0 };
    const conf = typeof ValidationEngine !== 'undefined' ? ValidationEngine.getConfidenceLabel(catV.avgScore) : { label:'N/A', cls:'confidence-medium' };
    const bar = Math.min(100, s.count * 5);
    catRows += `<tr>
      <td><span style="margin-right:6px">${meta.icon||'📁'}</span>${meta.name||catId}</td>
      <td><strong>${s.count}</strong></td>
      <td><div class="mini-bar"><div class="mini-bar-fill" style="width:${bar}%;background:var(--accent-primary)"></div></div></td>
      <td>${s.techniques.size}</td>
      <td><span class="conf-badge ${conf.cls}">${conf.label}</span></td>
      <td>${catV.avgScore || 0}%</td>
    </tr>`;
  });

  // MITRE tactic coverage
  let tacticRows = '';
  if (typeof MITRE_TACTICS !== 'undefined') {
    MITRE_TACTICS.forEach(t => {
      const cnt = rules.filter(r => r.tacticId === t.id).length;
      const bar = Math.min(100, cnt * 4);
      tacticRows += `<tr>
        <td>${t.id}</td><td>${t.name}</td><td><strong>${cnt}</strong></td>
        <td><div class="mini-bar"><div class="mini-bar-fill" style="width:${bar}%;background:${cnt>10?'var(--accent-primary)':cnt>5?'var(--warning)':'var(--danger)'}"></div></div></td>
      </tr>`;
    });
  }

  // Weak categories
  let gapCards = '';
  sortedCats.filter(([,s]) => s.count < 8).forEach(([catId, s]) => {
    const meta = catMeta[catId] || { name:catId, icon:'📁' };
    gapCards += `<div class="gap-card">
      <div class="gap-icon">${meta.icon||'📁'}</div>
      <div class="gap-info"><strong>${meta.name||catId}</strong><br><span class="gap-count">${s.count} rules — needs expansion</span></div>
    </div>`;
  });

  const html = `
  <div class="coverage-dashboard">
    <div class="page-header" style="margin-bottom:24px">
      <h1 style="margin:0;font-size:1.6rem;display:flex;align-items:center;gap:10px">
        🏆 Coverage & Confidence Dashboard
      </h1>
      <p style="margin:4px 0 0;opacity:0.7;font-size:0.85rem">
        Platform-wide detection coverage analysis and multi-SIEM validation confidence metrics
      </p>
    </div>

    <!-- ═══ Top Metrics ═══ -->
    <div class="metrics-grid-4">
      <div class="metric-card metric-accent">
        <div class="metric-value">${rules.length}</div>
        <div class="metric-label">Total Sigma Rules</div>
        <div class="metric-sub">Across ${Object.keys(catStats).length} categories</div>
      </div>
      <div class="metric-card metric-success">
        <div class="metric-value">${mitreCovPct}%</div>
        <div class="metric-label">MITRE Coverage</div>
        <div class="metric-sub">${coveredTech.size} techniques covered</div>
      </div>
      <div class="metric-card metric-info">
        <div class="metric-value">${vs.avgConfidence}%</div>
        <div class="metric-label">Avg Confidence</div>
        <div class="metric-sub">${vs.accepted} fully validated</div>
      </div>
      <div class="metric-card metric-warning">
        <div class="metric-value">${crossPct}%</div>
        <div class="metric-label">Cross-SIEM Parity</div>
        <div class="metric-sub">${vs.crossConsistent} consistent</div>
      </div>
    </div>

    <!-- ═══ Validation Summary ═══ -->
    <div class="section-card" style="margin-top:20px">
      <h2 style="margin:0 0 16px;font-size:1.15rem">🔍 Multi-SIEM Validation Summary</h2>
      <div class="validation-bars">
        <div class="val-row"><span class="val-label">Sigma YAML Valid</span><div class="val-bar-track"><div class="val-bar-fill val-fill-sigma" style="width:${sigmaPct}%"></div></div><span class="val-pct">${sigmaPct}%</span></div>
        <div class="val-row"><span class="val-label">Splunk SPL Valid</span><div class="val-bar-track"><div class="val-bar-fill val-fill-splunk" style="width:${splunkPct}%"></div></div><span class="val-pct">${splunkPct}%</span></div>
        <div class="val-row"><span class="val-label">QRadar AQL Valid</span><div class="val-bar-track"><div class="val-bar-fill val-fill-qradar" style="width:${qradarPct}%"></div></div><span class="val-pct">${qradarPct}%</span></div>
        <div class="val-row"><span class="val-label">Wazuh KQL Valid</span><div class="val-bar-track"><div class="val-bar-fill val-fill-wazuh" style="width:${wazuhPct}%"></div></div><span class="val-pct">${wazuhPct}%</span></div>
        <div class="val-row"><span class="val-label">Cross-SIEM Consistent</span><div class="val-bar-track"><div class="val-bar-fill val-fill-cross" style="width:${crossPct}%"></div></div><span class="val-pct">${crossPct}%</span></div>
      </div>
      <div style="margin-top:16px;display:flex;gap:16px;flex-wrap:wrap">
        <div class="val-stat-chip val-accepted">✅ ${vs.accepted} Accepted</div>
        <div class="val-stat-chip val-review">⚠️ ${vs.needsReview} Needs Review</div>
        <div class="val-stat-chip val-rejected">❌ ${vs.rejected} Rejected</div>
        <div class="val-stat-chip val-correlation">🔗 ${vs.wazuhCorrelation} Correlation-Only</div>
      </div>
    </div>

    <!-- ═══ Category Depth Scoreboard ═══ -->
    <div class="section-card" style="margin-top:20px">
      <h2 style="margin:0 0 16px;font-size:1.15rem">📊 Category Depth Scoreboard</h2>
      <div class="table-wrapper">
        <table class="coverage-table">
          <thead><tr><th>Category</th><th>Rules</th><th>Depth</th><th>Techniques</th><th>Confidence</th><th>Score</th></tr></thead>
          <tbody>${catRows}</tbody>
        </table>
      </div>
    </div>

    <!-- ═══ Two-column: MITRE Tactics + Gaps ═══ -->
    <div style="display:grid;grid-template-columns:1fr 1fr;gap:20px;margin-top:20px">
      <div class="section-card">
        <h2 style="margin:0 0 16px;font-size:1.15rem">🎯 MITRE ATT&CK Tactic Coverage</h2>
        <div class="table-wrapper">
          <table class="coverage-table compact">
            <thead><tr><th>ID</th><th>Tactic</th><th>Rules</th><th>Coverage</th></tr></thead>
            <tbody>${tacticRows}</tbody>
          </table>
        </div>
      </div>
      <div class="section-card">
        <h2 style="margin:0 0 16px;font-size:1.15rem">⚠️ Gap Analysis — Needs Expansion</h2>
        ${gapCards || '<div class="empty-state"><div class="empty-state-icon">✅</div><div class="empty-state-text">All categories meet minimum coverage!</div></div>'}
      </div>
    </div>

    <!-- ═══ Run Full Validation Button ═══ -->
    <div class="section-card" style="margin-top:20px;text-align:center">
      <button class="btn-validate-all" onclick="runFullValidation()">
        🚀 Run Full Platform Validation
      </button>
      <div id="validationProgress" style="margin-top:12px;display:none">
        <div class="val-bar-track" style="height:8px"><div class="val-bar-fill val-fill-sigma" id="valProgressBar" style="width:0%;transition:width 0.3s"></div></div>
        <div id="valProgressText" style="margin-top:6px;font-size:0.8rem;opacity:0.7"></div>
      </div>
      <div id="validationResults" style="margin-top:16px"></div>
    </div>
  </div>`;

  document.getElementById('page-content').innerHTML = html;
}

function runFullValidation() {
  if (typeof ValidationEngine === 'undefined') { alert('Validation engine not loaded'); return; }
  const prog = document.getElementById('validationProgress');
  const bar = document.getElementById('valProgressBar');
  const txt = document.getElementById('valProgressText');
  const res = document.getElementById('validationResults');
  prog.style.display = 'block';
  const rules = SIGMA_RULES || [];
  const results = [];
  let i = 0;
  function step() {
    if (i >= rules.length) {
      bar.style.width = '100%';
      txt.textContent = `Validation complete — ${results.length} rules processed`;
      const accepted = results.filter(r => r.overallStatus === 'accepted').length;
      const review = results.filter(r => r.overallStatus === 'needs_review').length;
      const rejected = results.filter(r => r.overallStatus === 'rejected').length;
      const avg = Math.round(results.reduce((a,r) => a+r.confidenceScore, 0) / results.length);
      res.innerHTML = `<div style="display:flex;gap:12px;justify-content:center;flex-wrap:wrap">
        <div class="val-stat-chip val-accepted">✅ ${accepted} Accepted</div>
        <div class="val-stat-chip val-review">⚠️ ${review} Needs Review</div>
        <div class="val-stat-chip val-rejected">❌ ${rejected} Rejected</div>
        <div class="val-stat-chip" style="background:rgba(0,212,255,0.15);color:#00d4ff">📊 ${avg}% Avg Confidence</div>
      </div>`;
      return;
    }
    const batch = Math.min(10, rules.length - i);
    for (let j = 0; j < batch; j++) { results.push(ValidationEngine.validateRule(rules[i+j])); }
    i += batch;
    bar.style.width = Math.round((i/rules.length)*100) + '%';
    txt.textContent = `Validating... ${i}/${rules.length} rules`;
    requestAnimationFrame(step);
  }
  step();
}

// ─── Register page in router ────────────────────────────────
if (typeof window._coverageDashboardRegistered === 'undefined') {
  window._coverageDashboardRegistered = true;
  const origSwitch = window.switchPage;
  if (origSwitch) {
    window.switchPage = function(page) {
      if (page === 'coverage-confidence') {
        document.querySelectorAll('.nav-item').forEach(n => n.classList.remove('active'));
        document.querySelectorAll('.nav-item').forEach(n => { if(n.dataset.page === 'coverage-confidence') n.classList.add('active'); });
        const bc = document.getElementById('header-breadcrumb');
        if (bc) bc.innerHTML = '<span class="bc-link" onclick="switchPage(\'dashboard\')">Home</span> <span class="bc-sep">›</span> <span class="current">Coverage & Confidence</span>';
        renderCoverageConfidencePage();
        window.scrollTo(0, 0);
        history.pushState({ page }, '', '#coverage-confidence');
        return;
      }
      origSwitch(page);
    };
  }
}

window.renderCoverageConfidencePage = renderCoverageConfidencePage;
window.runFullValidation = runFullValidation;
console.log('[SigmaGuard] Coverage & Confidence Dashboard loaded');
