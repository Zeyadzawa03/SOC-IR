// ═══════════════════════════════════════════════════════════════════════
// Blue Team Pages — Page Renderers for IR, Hunting, Forensics, 
// Correlation & Risk, and Assets & Identity
// Extension module for SigmaGuard v4.0
// ═══════════════════════════════════════════════════════════════════════

const esc = (s) => typeof escHtml === 'function' ? escHtml(s) : String(s).replace(/[&<>"']/g, m => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[m]));

// ══════════════════════════════════════════════
// INCIDENT RESPONSE PAGE
// ══════════════════════════════════════════════
function renderIncidentResponsePage(container) {
  const playbooks = typeof getAllIRPlaybooks !== 'undefined' ? getAllIRPlaybooks() : [];
  const sevOrder = { critical: 0, high: 1, medium: 2, low: 3 };
  playbooks.sort((a, b) => (sevOrder[a.severity] || 9) - (sevOrder[b.severity] || 9));

  container.innerHTML = `
    <div class="page-header">
      <div>
        <h1 class="page-title"><span class="title-icon">🚨</span> Incident Response Center</h1>
        <p class="page-subtitle">IR playbooks mapped to each detection category — Investigation, Containment, Escalation, and Evidence Collection</p>
      </div>
      <div class="header-stats">
        <div class="stat-chip"><span class="stat-value">${playbooks.length}</span><span class="stat-label">Playbooks</span></div>
        <div class="stat-chip"><span class="stat-value">${playbooks.filter(p => p.severity === 'critical').length}</span><span class="stat-label">Critical</span></div>
      </div>
    </div>

    <div class="ir-filter-bar">
      <input type="text" id="irSearchInput" class="search-input" placeholder="Search playbooks..." onkeyup="filterIRPlaybooks()" />
      <div class="filter-chips">
        <span class="filter-chip active" onclick="filterIRBySeverity('all', this)">All</span>
        <span class="filter-chip" onclick="filterIRBySeverity('critical', this)">🔴 Critical</span>
        <span class="filter-chip" onclick="filterIRBySeverity('high', this)">🟠 High</span>
        <span class="filter-chip" onclick="filterIRBySeverity('medium', this)">🟡 Medium</span>
      </div>
    </div>

    <div class="ir-playbooks-grid" id="irPlaybooksGrid">
      ${playbooks.map(pb => `
        <div class="ir-playbook-card" data-severity="${pb.severity}" data-name="${esc(pb.name.toLowerCase())}">
          <div class="ir-playbook-header">
            <div class="ir-playbook-title">${esc(pb.name)}</div>
            <span class="badge badge-severity-${pb.severity}">${pb.severity.toUpperCase()}</span>
          </div>
          <div class="ir-playbook-category">${esc(pb.categoryId.replace(/-/g, ' '))}</div>
          
          <div class="ir-playbook-tabs">
            <button class="ir-tab active" onclick="switchIRTab(this, 'investigation')">🔍 Investigation</button>
            <button class="ir-tab" onclick="switchIRTab(this, 'containment')">🛑 Containment</button>
            <button class="ir-tab" onclick="switchIRTab(this, 'escalation')">⬆️ Escalation</button>
            <button class="ir-tab" onclick="switchIRTab(this, 'evidence')">🗂️ Evidence</button>
          </div>
          
          <div class="ir-tab-content active" data-tab="investigation">
            <ol class="ir-step-list">${pb.investigationSteps.map(s => `<li>${esc(s)}</li>`).join('')}</ol>
          </div>
          <div class="ir-tab-content" data-tab="containment">
            <ol class="ir-step-list">${pb.containmentActions.map(s => `<li>${esc(s)}</li>`).join('')}</ol>
          </div>
          <div class="ir-tab-content" data-tab="escalation">
            <ol class="ir-step-list">${pb.escalationSteps.map(s => `<li>${esc(s)}</li>`).join('')}</ol>
          </div>
          <div class="ir-tab-content" data-tab="evidence">
            <ol class="ir-step-list">${pb.evidenceCollection.map(s => `<li>${esc(s)}</li>`).join('')}</ol>
          </div>

          <div class="ir-playbook-footer">
            <div class="ir-required-logs">
              <strong>Required Logs:</strong>
              <div class="ir-log-chips">
                ${pb.requiredLogs.slice(0, 4).map(l => `<span class="ir-log-chip">${esc(l)}</span>`).join('')}
                ${pb.requiredLogs.length > 4 ? pb.requiredLogs.slice(4).map(l => `<span class="ir-log-chip exp-hidden" style="display:none">${esc(l)}</span>`).join('') + `<span class="ir-log-chip more" onclick="toggleExpandItem(this)" style="cursor:pointer" data-more="+ ${pb.requiredLogs.length - 4} more">+ ${pb.requiredLogs.length - 4} more</span>` : ''}
              </div>
            </div>
            <div class="ir-indicators">
              <strong>Key Indicators (${pb.indicatorsToCheck.length}):</strong>
              <ul class="ir-indicator-list">
                ${pb.indicatorsToCheck.slice(0, 3).map(i => `<li>${esc(i)}</li>`).join('')}
                ${pb.indicatorsToCheck.length > 3 ? pb.indicatorsToCheck.slice(3).map(i => `<li class="exp-hidden" style="display:none">${esc(i)}</li>`).join('') + `<li class="ir-more-indicators" onclick="toggleExpandItem(this)" style="color:var(--accent-cyan);cursor:pointer;list-style:none;margin-top:4px" data-more="+ ${pb.indicatorsToCheck.length - 3} more indicators">+ ${pb.indicatorsToCheck.length - 3} more indicators</li>` : ''}
              </ul>
            </div>
          </div>
        </div>
      `).join('')}
    </div>
  `;
}

window.switchIRTab = function(btn, tabName) {
  const card = btn.closest('.ir-playbook-card');
  card.querySelectorAll('.ir-tab').forEach(t => t.classList.remove('active'));
  card.querySelectorAll('.ir-tab-content').forEach(c => c.classList.remove('active'));
  btn.classList.add('active');
  card.querySelector(`.ir-tab-content[data-tab="${tabName}"]`).classList.add('active');
};

window.filterIRPlaybooks = function() {
  const query = document.getElementById('irSearchInput').value.toLowerCase();
  document.querySelectorAll('.ir-playbook-card').forEach(card => {
    const name = card.dataset.name;
    card.style.display = name.includes(query) ? '' : 'none';
  });
};

window.filterIRBySeverity = function(sev, chip) {
  document.querySelectorAll('.filter-chip').forEach(c => c.classList.remove('active'));
  chip.classList.add('active');
  document.querySelectorAll('.ir-playbook-card').forEach(card => {
    card.style.display = (sev === 'all' || card.dataset.severity === sev) ? '' : 'none';
  });
};


// ══════════════════════════════════════════════
// THREAT HUNTING PAGE
// ══════════════════════════════════════════════
function renderThreatHuntingPage(container) {
  const hunts = typeof HUNTING_QUERIES !== 'undefined' ? HUNTING_QUERIES : [];

  container.innerHTML = `
    <div class="page-header">
      <div>
        <h1 class="page-title"><span class="title-icon">🎯</span> Threat Hunting</h1>
        <p class="page-subtitle">Proactive behavior-based hunting queries with Splunk SPL and QRadar AQL — linked to MITRE ATT&CK and Sigma rules</p>
      </div>
      <div class="header-stats">
        <div class="stat-chip"><span class="stat-value">${hunts.length}</span><span class="stat-label">Hunt Queries</span></div>
        <div class="stat-chip"><span class="stat-value">${hunts.filter(h=>h.huntType==='behavior').length}</span><span class="stat-label">Behavior</span></div>
        <div class="stat-chip"><span class="stat-value">${hunts.filter(h=>h.huntType==='anomaly').length}</span><span class="stat-label">Anomaly</span></div>
      </div>
    </div>

    <div class="hunt-filter-bar">
      <input type="text" id="huntSearchInput" class="search-input" placeholder="Search hunts by name, technique, or tag..." onkeyup="filterHunts()" />
      <div class="filter-chips">
        <span class="filter-chip active" onclick="filterHuntType('all', this)">All</span>
        <span class="filter-chip" onclick="filterHuntType('behavior', this)">🔬 Behavior</span>
        <span class="filter-chip" onclick="filterHuntType('anomaly', this)">📊 Anomaly</span>
      </div>
    </div>

    <div class="hunt-grid" id="huntGrid">
      ${hunts.map(h => `
        <div class="hunt-card" data-type="${h.huntType}" data-search="${esc((h.name + ' ' + h.description + ' ' + h.tags.join(' ')).toLowerCase())}">
          <div class="hunt-card-header">
            <div>
              <span class="hunt-id">${esc(h.id)}</span>
              <span class="badge badge-${h.huntType === 'behavior' ? 'tactic' : 'technique'}">${h.huntType}</span>
              <span class="badge badge-severity-${h.difficulty === 'High' ? 'high' : h.difficulty === 'Medium' ? 'medium' : 'low'}">${h.difficulty}</span>
            </div>
            <span class="hunt-freq">${esc(h.frequency)}</span>
          </div>
          <h3 class="hunt-card-title">${esc(h.name)}</h3>
          <p class="hunt-card-desc">${esc(h.description)}</p>
          
          <div class="hunt-mitre-tag">
            <span class="badge badge-tactic">${esc(h.mitre.tacticId)}</span>
            <span class="badge badge-technique">${esc(h.mitre.techniqueId)}</span>
            <span style="color:var(--text-muted);font-size:0.75rem;margin-left:0.25rem">${esc(h.mitre.techniqueName)}</span>
          </div>

          <div class="hunt-hypothesis">
            <strong>Hypothesis:</strong> ${esc(h.hypothesis)}
          </div>

          <div class="hunt-query-tabs">
            <button class="hunt-qtab active" onclick="switchHuntQuery(this, 'splunk')">Splunk SPL</button>
            <button class="hunt-qtab" onclick="switchHuntQuery(this, 'qradar')">QRadar AQL</button>
          </div>
          <div class="hunt-query-content active" data-query="splunk">
            <pre class="code-block"><code>${esc(h.splunkQuery)}</code></pre>
            <button class="copy-btn" onclick="copyToClipboard(this.previousElementSibling.querySelector('code').textContent)">📋 Copy SPL</button>
          </div>
          <div class="hunt-query-content" data-query="qradar">
            <pre class="code-block"><code>${esc(h.qradarQuery)}</code></pre>
            <button class="copy-btn" onclick="copyToClipboard(this.previousElementSibling.querySelector('code').textContent)">📋 Copy AQL</button>
          </div>

          <div class="hunt-card-footer">
            <div class="hunt-tags">${h.tags.map(t => `<span class="hunt-tag">${esc(t)}</span>`).join('')}</div>
            <div class="hunt-data-req">
              <strong>Data:</strong> ${h.dataRequirements.join(', ')}
            </div>
          </div>
        </div>
      `).join('')}
    </div>
  `;
}

window.switchHuntQuery = function(btn, platform) {
  const card = btn.closest('.hunt-card');
  card.querySelectorAll('.hunt-qtab').forEach(t => t.classList.remove('active'));
  card.querySelectorAll('.hunt-query-content').forEach(c => c.classList.remove('active'));
  btn.classList.add('active');
  card.querySelector(`.hunt-query-content[data-query="${platform}"]`).classList.add('active');
};

window.filterHunts = function() {
  const query = document.getElementById('huntSearchInput').value.toLowerCase();
  document.querySelectorAll('.hunt-card').forEach(card => {
    card.style.display = card.dataset.search.includes(query) ? '' : 'none';
  });
};

window.filterHuntType = function(type, chip) {
  document.querySelectorAll('.hunt-filter-bar .filter-chip').forEach(c => c.classList.remove('active'));
  chip.classList.add('active');
  document.querySelectorAll('.hunt-card').forEach(card => {
    card.style.display = (type === 'all' || card.dataset.type === type) ? '' : 'none';
  });
};


// ══════════════════════════════════════════════
// CORRELATION & RISK PAGE
// ══════════════════════════════════════════════
function renderCorrelationPage(container) {
  const rules = typeof CORRELATION_RULES !== 'undefined' ? CORRELATION_RULES : [];
  rules.sort((a, b) => b.riskScore - a.riskScore);

  container.innerHTML = `
    <div class="page-header">
      <div>
        <h1 class="page-title"><span class="title-icon">🔗</span> Correlation & Risk Scoring</h1>
        <p class="page-subtitle">Multi-stage detection correlation rules with risk-based prioritization — auto-scoring, Splunk & QRadar implementations</p>
      </div>
      <div class="header-stats">
        <div class="stat-chip"><span class="stat-value">${rules.length}</span><span class="stat-label">Correlation Rules</span></div>
        <div class="stat-chip"><span class="stat-value">${rules.filter(r => r.riskScore >= 90).length}</span><span class="stat-label">Critical Risk</span></div>
      </div>
    </div>

    <div class="corr-grid" id="corrGrid">
      ${rules.map(cr => {
        const riskColor = cr.riskScore >= 90 ? '#ff4757' : cr.riskScore >= 70 ? '#ff9f43' : cr.riskScore >= 50 ? '#feca57' : '#48dbfb';
        return `
        <div class="corr-card">
          <div class="corr-card-header">
            <div class="corr-risk-score" style="--risk-color:${riskColor}">
              <svg viewBox="0 0 36 36" class="risk-circle">
                <path class="risk-bg" d="M18 2.0845 a 15.9155 15.9155 0 0 1 0 31.831 a 15.9155 15.9155 0 0 1 0 -31.831" />
                <path class="risk-fill" stroke="${riskColor}" stroke-dasharray="${cr.riskScore}, 100" d="M18 2.0845 a 15.9155 15.9155 0 0 1 0 31.831 a 15.9155 15.9155 0 0 1 0 -31.831" />
              </svg>
              <span class="risk-number">${cr.riskScore}</span>
            </div>
            <div>
              <span class="corr-id">${esc(cr.id)}</span>
              <h3 class="corr-title">${esc(cr.name)}</h3>
              <span class="badge badge-severity-${cr.severity}">${cr.severity.toUpperCase()}</span>
            </div>
          </div>
          
          <p class="corr-desc">${esc(cr.description)}</p>

          <div class="corr-conditions">
            <strong>Correlation Conditions:</strong>
            <div class="corr-condition-chain">
              ${cr.conditions.map((c, i) => `
                <div class="corr-condition">
                  <span class="corr-condition-type">${c.type}</span>
                  <span class="corr-condition-desc">${esc(c.description)}</span>
                </div>
                ${i < cr.conditions.length - 1 ? '<div class="corr-chain-arrow">→</div>' : ''}
              `).join('')}
            </div>
          </div>

          <div class="corr-mitre">
            <strong>MITRE ATT&CK:</strong>
            ${cr.mitre.map(t => `<span class="badge badge-technique">${esc(t)}</span>`).join(' ')}
          </div>

          <div class="corr-query-tabs">
            <button class="corr-qtab active" onclick="switchCorrQuery(this, 'splunk')">Splunk</button>
            <button class="corr-qtab" onclick="switchCorrQuery(this, 'qradar')">QRadar</button>
          </div>
          <div class="corr-query-content active" data-cq="splunk">
            <pre class="code-block"><code>${esc(cr.splunkCorrelation)}</code></pre>
          </div>
          <div class="corr-query-content" data-cq="qradar">
            <pre class="code-block"><code>${esc(cr.qradarCorrelation)}</code></pre>
          </div>

          <div class="corr-footer">
            <span class="corr-category">${esc(cr.category.replace(/-/g, ' '))}</span>
            ${cr.responsePlaybook ? `<a href="#" onclick="navigate('incident-response');return false" class="corr-playbook-link">📋 IR Playbook →</a>` : ''}
          </div>
        </div>
      `}).join('')}
    </div>
  `;
}

window.switchCorrQuery = function(btn, platform) {
  const card = btn.closest('.corr-card');
  card.querySelectorAll('.corr-qtab').forEach(t => t.classList.remove('active'));
  card.querySelectorAll('.corr-query-content').forEach(c => c.classList.remove('active'));
  btn.classList.add('active');
  card.querySelector(`.corr-query-content[data-cq="${platform}"]`).classList.add('active');
};


// ══════════════════════════════════════════════
// DIGITAL FORENSICS PAGE
// ══════════════════════════════════════════════
function renderForensicsPage(container) {
  const artifacts = typeof getAllForensicArtifacts !== 'undefined' ? getAllForensicArtifacts() : [];
  const templates = typeof TIMELINE_TEMPLATES !== 'undefined' ? TIMELINE_TEMPLATES : {};
  const platforms = [...new Set(artifacts.map(a => a.platform))];

  container.innerHTML = `
    <div class="page-header">
      <div>
        <h1 class="page-title"><span class="title-icon">🔬</span> Digital Forensics & Incident Response</h1>
        <p class="page-subtitle">Forensic artifact reference, evidence collection tools, and incident timeline templates for DFIR investigators</p>
      </div>
      <div class="header-stats">
        <div class="stat-chip"><span class="stat-value">${artifacts.length}</span><span class="stat-label">Artifacts</span></div>
        <div class="stat-chip"><span class="stat-value">${Object.keys(templates).length}</span><span class="stat-label">Timelines</span></div>
        <div class="stat-chip"><span class="stat-value">${platforms.length}</span><span class="stat-label">Platforms</span></div>
      </div>
    </div>

    <!-- Timeline Templates -->
    <div class="forensics-section">
      <h2 class="section-title-lg">📅 Investigation Timeline Templates</h2>
      <div class="timeline-templates-grid">
        ${Object.entries(templates).map(([id, tmpl]) => `
          <div class="timeline-template-card">
            <h3 class="timeline-template-title">${esc(tmpl.name)}</h3>
            <div class="timeline-phases">
              ${tmpl.phases.map((phase, i) => `
                <div class="timeline-phase">
                  <div class="timeline-phase-icon">${phase.icon}</div>
                  <div class="timeline-phase-content">
                    <div class="timeline-phase-name">${esc(phase.phase)}</div>
                    <div class="timeline-phase-desc">${esc(phase.description)}</div>
                    <div class="timeline-phase-artifacts">${phase.artifacts.map(a => `<span class="timeline-artifact-tag">${esc(a)}</span>`).join('')}</div>
                  </div>
                  ${i < tmpl.phases.length - 1 ? '<div class="timeline-connector"></div>' : ''}
                </div>
              `).join('')}
            </div>
          </div>
        `).join('')}
      </div>
    </div>

    <!-- Forensic Artifacts Catalog -->
    <div class="forensics-section">
      <h2 class="section-title-lg">🗃️ Forensic Artifacts Catalog</h2>
      <div class="forensic-filter-bar">
        <input type="text" id="forensicSearchInput" class="search-input" placeholder="Search artifacts..." onkeyup="filterForensicArtifacts()" />
        <div class="filter-chips">
          <span class="filter-chip active" onclick="filterForensicPlatform('all', this)">All</span>
          ${platforms.map(p => `<span class="filter-chip" onclick="filterForensicPlatform('${esc(p)}', this)">${p}</span>`).join('')}
        </div>
      </div>

      <div class="forensic-artifacts-grid" id="forensicArtifactsGrid">
        ${artifacts.map(a => `
          <div class="forensic-card" data-platform="${esc(a.platform)}" data-search="${esc((a.name + ' ' + a.description + ' ' + a.type).toLowerCase())}">
            <div class="forensic-card-header">
              <div>
                <span class="forensic-type-badge">${esc(a.type)}</span>
                <span class="forensic-platform-badge">${esc(a.platform)}</span>
              </div>
            </div>
            <h3 class="forensic-card-title">${esc(a.name)}</h3>
            <p class="forensic-card-desc">${esc(a.description)}</p>
            <div class="forensic-location">
              <strong>📂 Location:</strong>
              <code class="forensic-path">${esc(a.location)}</code>
            </div>
            <div class="forensic-events">
              <strong>Key Evidence (${a.keyEvents.length}):</strong>
              <div class="forensic-events-list">
                ${a.keyEvents.map(e => `
                  <div class="forensic-event-item">
                    <span class="forensic-event-id">${esc(e.id)}</span>
                    <span class="forensic-event-name">${esc(e.name)}</span>
                    <span class="forensic-event-value badge badge-severity-${e.forensicValue === 'critical' ? 'critical' : e.forensicValue === 'high' ? 'high' : 'medium'}">${e.forensicValue}</span>
                  </div>
                `).join('')}
              </div>
            </div>
            <div class="forensic-tools">
              <strong>🛠️ Collection Tools:</strong>
              <div class="forensic-tool-chips">${a.collectionTools.map(t => `<span class="forensic-tool-chip">${esc(t)}</span>`).join('')}</div>
            </div>
            <div class="forensic-retention">
              <strong>⏰ Retention:</strong> ${esc(a.retentionGuidance)}
            </div>
          </div>
        `).join('')}
      </div>
    </div>
  `;
}

window.filterForensicArtifacts = function() {
  const query = document.getElementById('forensicSearchInput').value.toLowerCase();
  document.querySelectorAll('.forensic-card').forEach(card => {
    card.style.display = card.dataset.search.includes(query) ? '' : 'none';
  });
};

window.filterForensicPlatform = function(platform, chip) {
  document.querySelectorAll('.forensic-filter-bar .filter-chip').forEach(c => c.classList.remove('active'));
  chip.classList.add('active');
  document.querySelectorAll('.forensic-card').forEach(card => {
    card.style.display = (platform === 'all' || card.dataset.platform === platform) ? '' : 'none';
  });
};


// ══════════════════════════════════════════════
// ASSETS & IDENTITY PAGE
// ══════════════════════════════════════════════
function renderAssetsPage(container) {
  const assets = typeof ASSET_CATEGORIES !== 'undefined' ? ASSET_CATEGORIES : [];
  const identities = typeof IDENTITY_RISK_PROFILES !== 'undefined' ? IDENTITY_RISK_PROFILES : [];

  container.innerHTML = `
    <div class="page-header">
      <div>
        <h1 class="page-title"><span class="title-icon">🖥️</span> Assets & Identity Context</h1>
        <p class="page-subtitle">Asset criticality awareness and identity risk profiles — context-driven detection accuracy enrichment</p>
      </div>
      <div class="header-stats">
        <div class="stat-chip"><span class="stat-value">${assets.length}</span><span class="stat-label">Asset Types</span></div>
        <div class="stat-chip"><span class="stat-value">${identities.length}</span><span class="stat-label">Identity Profiles</span></div>
      </div>
    </div>

    <!-- Asset Categories -->
    <div class="assets-section">
      <h2 class="section-title-lg">🏢 Asset Categories & Criticality</h2>
      <div class="assets-grid">
        ${assets.map(a => {
          const critColor = a.criticality === 'critical' ? '#ff4757' : a.criticality === 'high' ? '#ff9f43' : '#feca57';
          return `
          <div class="asset-card">
            <div class="asset-card-header">
              <span class="asset-icon">${a.icon}</span>
              <div>
                <h3 class="asset-name">${esc(a.name)}</h3>
                <span class="badge" style="background:${critColor}20;color:${critColor};border:1px solid ${critColor}40">${a.criticality.toUpperCase()}</span>
              </div>
            </div>
            <p class="asset-desc">${esc(a.description)}</p>
            
            <div class="asset-detail-grid">
              <div class="asset-detail-section">
                <strong>🎯 Detection Context:</strong>
                <p>${esc(a.detectionContext)}</p>
              </div>
              <div class="asset-detail-section">
                <strong>📡 Key Monitoring:</strong>
                <ul>${a.keyMonitoring.map(m => `<li>${esc(m)}</li>`).join('')}</ul>
              </div>
              <div class="asset-detail-section">
                <strong>⚠️ Risk Factors:</strong>
                <ul>${a.riskFactors.map(r => `<li>${esc(r)}</li>`).join('')}</ul>
              </div>
              <div class="asset-detail-section">
                <strong>⚙️ Expected Services:</strong>
                <div class="asset-service-chips">${a.expectedServices.map(s => `<span class="asset-service-chip">${esc(s)}</span>`).join('')}</div>
              </div>
            </div>
            
            <div class="asset-footer">
              <span class="asset-count">📊 Typical: ${esc(a.count)}</span>
              <div class="asset-linked-cats">${a.linkedCategories.map(c => `<span class="badge badge-tactic" style="font-size:0.68rem">${esc(c)}</span>`).join(' ')}</div>
            </div>
          </div>
        `}).join('')}
      </div>
    </div>

    <!-- Identity Risk Profiles -->
    <div class="assets-section">
      <h2 class="section-title-lg">👤 Identity Risk Profiles</h2>
      <div class="identity-grid">
        ${identities.map(id => {
          const riskColor = id.riskLevel === 'critical' ? '#ff4757' : id.riskLevel === 'high' ? '#ff9f43' : '#feca57';
          return `
          <div class="identity-card">
            <div class="identity-card-header">
              <span class="identity-icon">${id.icon}</span>
              <div>
                <h3 class="identity-name">${esc(id.name)}</h3>
                <span class="badge" style="background:${riskColor}20;color:${riskColor};border:1px solid ${riskColor}40">Risk: ${id.riskLevel.toUpperCase()}</span>
              </div>
            </div>
            <p class="identity-desc">${esc(id.description)}</p>
            <div class="identity-monitoring">
              <strong>📊 Monitoring Priority:</strong> ${esc(id.monitoringPriority)}
            </div>

            <div class="identity-behavior-grid">
              <div class="identity-behavior-section expected">
                <strong>✅ Expected Behavior:</strong>
                <ul>${id.expectedBehavior.map(b => `<li>${esc(b)}</li>`).join('')}</ul>
              </div>
              <div class="identity-behavior-section anomaly">
                <strong>🚩 Anomaly Indicators:</strong>
                <ul>${id.anomalyIndicators.map(a => `<li>${esc(a)}</li>`).join('')}</ul>
              </div>
            </div>

            <div class="identity-protection">
              <strong>🛡️ Protection Measures:</strong>
              <ul>${id.protection.map(p => `<li>${esc(p)}</li>`).join('')}</ul>
            </div>
          </div>
        `}).join('')}
      </div>
    </div>
  `;
}

// Make all page renderers globally accessible
window.renderIncidentResponsePage = renderIncidentResponsePage;
window.renderThreatHuntingPage = renderThreatHuntingPage;
window.renderCorrelationPage = renderCorrelationPage;
window.renderForensicsPage = renderForensicsPage;
window.renderAssetsPage = renderAssetsPage;
