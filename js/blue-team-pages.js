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
// CORRELATION & RISK PAGE — ENHANCED v2.0
// Decision Logic, Entity Tracking, Incidents
// ══════════════════════════════════════════════

function renderCorrelationPage(container) {
  const rules = typeof CORRELATION_RULES !== 'undefined' ? [...CORRELATION_RULES] : [];
  rules.sort((a, b) => b.riskScore - a.riskScore);

  const incidents = typeof incidentManager !== 'undefined' ? incidentManager.getAllIncidents() : [];
  const entities = typeof entityTracker !== 'undefined' ? entityTracker.getAllEntities() : [];
  const highRiskEntities = typeof entityTracker !== 'undefined' ? entityTracker.getHighRiskEntities(30) : [];
  const activeIncidents = incidents.filter(i => !['resolved', 'closed'].includes(i.status));
  const simScenarios = typeof SIMULATION_SCENARIOS !== 'undefined' ? SIMULATION_SCENARIOS : [];

  container.innerHTML = `
    <div class="page-header">
      <div>
        <h1 class="page-title"><span class="title-icon">🔗</span> Correlation, Decision Logic & Incidents</h1>
        <p class="page-subtitle">Multi-stage detection correlation with decision logic, entity tracking, and alert-to-incident lifecycle management</p>
      </div>
      <div class="header-stats">
        <div class="stat-chip"><span class="stat-value">${rules.length}</span><span class="stat-label">Correlation Rules</span></div>
        <div class="stat-chip"><span class="stat-value">${activeIncidents.length}</span><span class="stat-label">Active Incidents</span></div>
        <div class="stat-chip"><span class="stat-value">${entities.length}</span><span class="stat-label">Tracked Entities</span></div>
      </div>
    </div>

    <!-- Tab Navigation -->
    <div class="corr-tabs-bar" id="corrTabsBar">
      <button class="corr-page-tab active" data-ctab="correlation-rules" onclick="switchCorrPageTab(this)">🔗 Correlation Rules</button>
      <button class="corr-page-tab" data-ctab="decision-logic" onclick="switchCorrPageTab(this)">🧠 Decision Logic</button>
      <button class="corr-page-tab" data-ctab="entity-tracker" onclick="switchCorrPageTab(this)">👁️ Entity Tracker</button>
      <button class="corr-page-tab" data-ctab="incidents" onclick="switchCorrPageTab(this)">🚨 Incidents <span class="corr-tab-badge">${activeIncidents.length}</span></button>
      <button class="corr-page-tab" data-ctab="simulation" onclick="switchCorrPageTab(this)">⚡ Simulation</button>
    </div>

    <!-- ═══ TAB 1: Correlation Rules ═══ -->
    <div class="corr-tab-panel active" id="ctab-correlation-rules">
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

            <!-- Decision Logic Summary -->
            ${cr.decisionLogic ? `
            <div class="corr-decision-summary">
              <div class="corr-decision-label">🧠 Decision Logic</div>
              <div class="corr-decision-flow">
                <div class="decision-node decision-node-trigger">
                  <span class="decision-node-icon">📥</span>
                  <span class="decision-node-text">${esc(cr.decisionLogic.singleEvent?.trigger || 'Event')}</span>
                </div>
                <div class="decision-arrow">→</div>
                <div class="decision-node decision-node-eval">
                  <span class="decision-node-icon">⚖️</span>
                  <span class="decision-node-text">${esc(cr.decisionLogic.singleEvent?.action || 'EVALUATE')}</span>
                </div>
                ${cr.decisionLogic.multiEvent && cr.decisionLogic.multiEvent.length > 0 ? `
                <div class="decision-arrow">→</div>
                <div class="decision-node decision-node-escalate">
                  <span class="decision-node-icon">🚨</span>
                  <span class="decision-node-text">${esc(cr.decisionLogic.multiEvent[0].action)}</span>
                </div>
                ` : ''}
              </div>
            </div>` : ''}

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
    </div>

    <!-- ═══ TAB 2: Decision Logic ═══ -->
    <div class="corr-tab-panel" id="ctab-decision-logic">
      <div class="decision-logic-header">
        <div class="info-box info" style="margin-bottom:20px">
          <div class="info-box-title">🧠 How Detection Decision Logic Works</div>
          Each detection rule evaluates incoming events through a multi-stage decision pipeline:
          <strong>Single-event triggers</strong> fire on individual events matching conditions.
          <strong>Multi-event triggers</strong> correlate sequences of events within time windows.
          <strong>Entity correlation</strong> tracks entities (IPs, users, hosts) across detections to build risk profiles.
          When thresholds are met, alerts automatically <strong>escalate into actionable incidents</strong>.
        </div>
      </div>

      <div class="decision-trees-grid">
        ${rules.filter(r => r.decisionLogic).map(cr => `
          <div class="decision-tree-card">
            <div class="decision-tree-header">
              <h3>${esc(cr.id)} — ${esc(cr.name)}</h3>
              <span class="badge badge-severity-${cr.severity}">Risk: ${cr.riskScore}</span>
            </div>

            <!-- Single Event Trigger -->
            <div class="decision-stage">
              <div class="decision-stage-label">
                <span class="stage-number">1</span>
                Single-Event Trigger
              </div>
              <div class="decision-tree-flow">
                <div class="dt-node dt-trigger">
                  <div class="dt-node-header">IF</div>
                  <div class="dt-node-body">${esc(cr.decisionLogic.singleEvent?.condition || 'N/A')}</div>
                </div>
                <div class="dt-connector">→</div>
                <div class="dt-node dt-action dt-action-${(cr.decisionLogic.singleEvent?.action || '').toLowerCase().replace(/_/g,'-')}">
                  <div class="dt-node-header">THEN</div>
                  <div class="dt-node-body">${esc(cr.decisionLogic.singleEvent?.action || 'EVALUATE')}</div>
                  <div class="dt-node-label">${esc(cr.decisionLogic.singleEvent?.label || '')}</div>
                </div>
              </div>
            </div>

            <!-- Multi-Event Triggers -->
            ${(cr.decisionLogic.multiEvent || []).map((me, idx) => `
              <div class="decision-stage">
                <div class="decision-stage-label">
                  <span class="stage-number">${idx + 2}</span>
                  Multi-Event: ${esc(me.name)}
                </div>
                <div class="decision-tree-conditions">
                  ${me.conditions.map((cond, ci) => `
                    <div class="dt-condition-row">
                      <span class="dt-condition-keyword">${cond.startsWith('THEN') ? 'THEN' : cond.startsWith('AND') ? 'AND' : ci === 0 ? 'IF' : 'AND'}</span>
                      <span class="dt-condition-text">${esc(cond.replace(/^(THEN |AND |IF )/, ''))}</span>
                    </div>
                  `).join('')}
                </div>
                <div class="dt-verdict">
                  <div class="dt-verdict-action">
                    <span class="dt-verdict-icon">${me.action === 'EMERGENCY_INCIDENT' ? '🚨' : me.action === 'ESCALATE_TO_INCIDENT' ? '⬆️' : '📋'}</span>
                    <span class="dt-verdict-text">${esc(me.action)}</span>
                  </div>
                  <div class="dt-verdict-result">${esc(me.verdict)}</div>
                  <div class="dt-verdict-meta">
                    <span class="badge badge-severity-${me.severity}">${me.severity}</span>
                    <span class="dt-window">⏱ ${esc(me.timeWindow)}</span>
                  </div>
                </div>
              </div>
            `).join('')}

            <!-- Entity Correlation -->
            ${cr.decisionLogic.entityCorrelation ? `
              <div class="decision-stage decision-stage-entity">
                <div class="decision-stage-label">
                  <span class="stage-number">E</span>
                  Entity Correlation
                </div>
                <div class="dt-entity-box">
                  <div class="dt-entity-row"><strong>Track:</strong> ${cr.decisionLogic.entityCorrelation.trackFields.map(f => `<span class="dt-entity-field">${esc(f)}</span>`).join(' ')}</div>
                  <div class="dt-entity-row"><strong>Aggregation:</strong> ${esc(cr.decisionLogic.entityCorrelation.aggregation)}</div>
                  <div class="dt-entity-row"><strong>Risk Mode:</strong> ${esc(cr.decisionLogic.entityCorrelation.riskAccumulation)} | <strong>Threshold:</strong> ${cr.decisionLogic.entityCorrelation.threshold}/100</div>
                </div>
              </div>
            ` : ''}
          </div>
        `).join('')}
      </div>
    </div>

    <!-- ═══ TAB 3: Entity Tracker ═══ -->
    <div class="corr-tab-panel" id="ctab-entity-tracker">
      <!-- Entity Summary Stats -->
      <div class="entity-stats-bar">
        <div class="entity-stat-card">
          <div class="entity-stat-icon">🌐</div>
          <div class="entity-stat-value">${entities.filter(e => e.type === 'ip').length}</div>
          <div class="entity-stat-label">IP Addresses</div>
        </div>
        <div class="entity-stat-card">
          <div class="entity-stat-icon">👤</div>
          <div class="entity-stat-value">${entities.filter(e => e.type === 'user').length}</div>
          <div class="entity-stat-label">Users</div>
        </div>
        <div class="entity-stat-card">
          <div class="entity-stat-icon">🖥️</div>
          <div class="entity-stat-value">${entities.filter(e => e.type === 'host').length}</div>
          <div class="entity-stat-label">Hosts</div>
        </div>
        <div class="entity-stat-card entity-stat-alert">
          <div class="entity-stat-icon">⚠️</div>
          <div class="entity-stat-value">${highRiskEntities.length}</div>
          <div class="entity-stat-label">High Risk</div>
        </div>
      </div>

      <!-- Entity Filter -->
      <div class="entity-filter-bar">
        <div class="filter-chips">
          <span class="filter-chip active" onclick="filterEntityType('all', this)">All</span>
          <span class="filter-chip" onclick="filterEntityType('ip', this)">🌐 IPs</span>
          <span class="filter-chip" onclick="filterEntityType('user', this)">👤 Users</span>
          <span class="filter-chip" onclick="filterEntityType('host', this)">🖥️ Hosts</span>
        </div>
      </div>

      <!-- Entity Cards -->
      <div class="entity-grid" id="entityGrid">
        ${entities.sort((a,b) => b.riskScore - a.riskScore).map(entity => {
          const typeIcon = entity.type === 'ip' ? '🌐' : entity.type === 'user' ? '👤' : '🖥️';
          const riskColor = entity.riskScore >= 60 ? '#ff4757' : entity.riskScore >= 40 ? '#ff9f43' : entity.riskScore >= 20 ? '#feca57' : '#48dbfb';
          return `
          <div class="entity-card" data-entity-type="${entity.type}">
            <div class="entity-card-header">
              <div class="entity-type-icon">${typeIcon}</div>
              <div class="entity-info">
                <div class="entity-id">${esc(entity.id)}</div>
                <div class="entity-type-label">${entity.type.toUpperCase()}</div>
              </div>
              <div class="entity-risk-gauge">
                <svg viewBox="0 0 36 36" class="risk-circle-sm">
                  <path class="risk-bg" d="M18 2.0845 a 15.9155 15.9155 0 0 1 0 31.831 a 15.9155 15.9155 0 0 1 0 -31.831" />
                  <path class="risk-fill" stroke="${riskColor}" stroke-dasharray="${entity.riskScore}, 100" d="M18 2.0845 a 15.9155 15.9155 0 0 1 0 31.831 a 15.9155 15.9155 0 0 1 0 -31.831" />
                </svg>
                <span class="entity-risk-value" style="color:${riskColor}">${entity.riskScore}</span>
              </div>
            </div>
            <div class="entity-detections">
              <div class="entity-det-label">Detections (${entity.detections.length})</div>
              ${entity.detections.map(d => `
                <div class="entity-det-item">
                  <span class="badge badge-severity-${d.severity}" style="font-size:0.6rem">${d.severity}</span>
                  <span class="entity-det-text">${esc(d.label || d.ruleId)}</span>
                </div>
              `).join('')}
            </div>
            <div class="entity-timeline-bar">
              <span class="entity-time">First: ${entity.firstSeen ? new Date(entity.firstSeen).toLocaleString() : '—'}</span>
              <span class="entity-time">Last: ${entity.lastSeen ? new Date(entity.lastSeen).toLocaleString() : '—'}</span>
            </div>
          </div>
        `}).join('')}
      </div>
    </div>

    <!-- ═══ TAB 4: Incidents ═══ -->
    <div class="corr-tab-panel" id="ctab-incidents">
      <!-- Incident Summary -->
      <div class="incident-stats-bar">
        <div class="entity-stat-card entity-stat-alert">
          <div class="entity-stat-icon">🔴</div>
          <div class="entity-stat-value">${incidents.filter(i => i.status === 'new').length}</div>
          <div class="entity-stat-label">New</div>
        </div>
        <div class="entity-stat-card">
          <div class="entity-stat-icon">🔍</div>
          <div class="entity-stat-value">${incidents.filter(i => i.status === 'investigating').length}</div>
          <div class="entity-stat-label">Investigating</div>
        </div>
        <div class="entity-stat-card">
          <div class="entity-stat-icon">🛑</div>
          <div class="entity-stat-value">${incidents.filter(i => i.status === 'contained').length}</div>
          <div class="entity-stat-label">Contained</div>
        </div>
        <div class="entity-stat-card">
          <div class="entity-stat-icon">✅</div>
          <div class="entity-stat-value">${incidents.filter(i => i.status === 'resolved' || i.status === 'closed').length}</div>
          <div class="entity-stat-label">Resolved</div>
        </div>
      </div>

      <!-- Incidents List -->
      <div class="incidents-grid">
        ${incidents.map(inc => {
          const statusColors = { new: '#ff4757', investigating: '#ff9f43', contained: '#feca57', eradicated: '#2ed573', resolved: '#1dd1a1', closed: '#576574' };
          const statusIcons = { new: '🔴', investigating: '🔍', contained: '🛑', eradicated: '🧹', resolved: '✅', closed: '📁' };
          const phaseIcons = { detection: '📡', analysis: '🔬', containment: '🛑', eradication: '🧹', recovery: '🔄', lessons_learned: '📋' };
          const sColor = statusColors[inc.status] || '#576574';

          return `
          <div class="incident-card" style="border-left: 4px solid ${sColor}">
            <div class="incident-card-header">
              <div>
                <span class="incident-id" style="color:${sColor}">${esc(inc.id)}</span>
                <h3 class="incident-title">${esc(inc.title)}</h3>
              </div>
              <div class="incident-header-right">
                <span class="badge badge-severity-${inc.severity}">${inc.severity.toUpperCase()}</span>
                <div class="incident-risk-pill" style="background:${sColor}15;color:${sColor};border:1px solid ${sColor}40">
                  Risk: ${inc.riskScore}/100
                </div>
              </div>
            </div>

            <div class="incident-status-row">
              <div class="incident-status-badge" style="background:${sColor}20;color:${sColor};border:1px solid ${sColor}40">
                ${statusIcons[inc.status] || '❔'} ${inc.status.toUpperCase()}
              </div>
              <div class="incident-phase-badge">
                ${phaseIcons[inc.phase] || '📡'} Phase: ${esc(inc.phase.replace(/_/g, ' '))}
              </div>
              ${inc.correlationRule ? `<span class="badge badge-technique">${esc(inc.correlationRule)}</span>` : ''}
            </div>

            ${inc.verdict ? `<div class="incident-verdict">${esc(inc.verdict)}</div>` : ''}

            <!-- Kill Chain Progress -->
            <div class="incident-killchain">
              <div class="incident-killchain-label">Attack Chain Progress</div>
              <div class="incident-killchain-bar">
                ${(() => {
                  const phases = typeof attackPatternDetector !== 'undefined' 
                    ? attackPatternDetector.getKillChainStatus(inc.alerts || [])
                    : [];
                  if (phases.length === 0) {
                    // Hardcode some phases based on the correlation rule
                    const rulePhases = {
                      'CR-001': [0,0,1,1,0,0,0],
                      'CR-006': [0,0,0,1,1,0,1],
                      'CR-007': [0,0,1,1,0,1,0],
                      'CR-005': [1,0,0,1,0,0,1]
                    };
                    const p = rulePhases[inc.correlationRule] || [0,0,0,0,0,0,0];
                    const labels = ['Recon','Weapon','Deliver','Exploit','Install','C2','Action'];
                    const icons = ['🔎','⚒️','📧','💥','📌','📡','🎯'];
                    return labels.map((l,i) => `<div class="kc-phase ${p[i]?'kc-detected':''}" title="${l}"><span class="kc-icon">${icons[i]}</span><span class="kc-label">${l}</span></div>`).join('');
                  }
                  return phases.map(p => `<div class="kc-phase ${p.detected?'kc-detected':''}" title="${esc(p.name)}"><span class="kc-icon">${p.icon}</span><span class="kc-label">${esc(p.name.split(' ')[0])}</span></div>`).join('');
                })()}
              </div>
            </div>

            <!-- Entities -->
            <div class="incident-entities">
              <strong>Entities:</strong>
              <div class="incident-entity-chips">
                ${(inc.entities || []).map(e => {
                  const [eType, eId] = e.split(':');
                  const eIcon = eType === 'ip' ? '🌐' : eType === 'user' ? '👤' : '🖥️';
                  return `<span class="incident-entity-chip">${eIcon} ${esc(eId)}</span>`;
                }).join('')}
              </div>
            </div>

            <!-- MITRE -->
            ${(inc.mitre || []).length > 0 ? `
            <div class="incident-mitre">
              ${inc.mitre.map(t => `<span class="badge badge-technique">${esc(t)}</span>`).join(' ')}
            </div>` : ''}

            <!-- Timeline -->
            <div class="incident-timeline-section">
              <div class="incident-timeline-label">📅 Incident Timeline</div>
              <div class="incident-timeline">
                ${(inc.timeline || []).map(entry => `
                  <div class="inc-tl-entry">
                    <div class="inc-tl-dot" style="background:${entry.type === 'creation' ? '#48dbfb' : entry.type === 'status_change' ? '#ff9f43' : '#2ed573'}"></div>
                    <div class="inc-tl-content">
                      <div class="inc-tl-action">${esc(entry.action)}</div>
                      <div class="inc-tl-detail">${esc(entry.detail)}</div>
                      <div class="inc-tl-time">${new Date(entry.timestamp).toLocaleString()}</div>
                    </div>
                  </div>
                `).join('')}
              </div>
            </div>

            <div class="incident-footer">
              <span class="incident-created">Created: ${new Date(inc.createdAt).toLocaleString()}</span>
              ${inc.responsePlaybook ? `<a href="#" onclick="navigate('incident-response');return false" class="corr-playbook-link">📋 Response Playbook →</a>` : ''}
            </div>
          </div>
        `}).join('')}
      </div>
    </div>

    <!-- ═══ TAB 5: Simulation ═══ -->
    <div class="corr-tab-panel" id="ctab-simulation">
      <div class="info-box info" style="margin-bottom:20px">
        <div class="info-box-title">⚡ Alert-to-Incident Simulation</div>
        Select a scenario to see how individual detection events flow through the decision engine, get correlated, and evolve into actionable incidents. This demonstrates that detections do NOT operate in isolation — they are evaluated, correlated, and escalated automatically.
      </div>

      <div class="sim-scenarios-grid">
        ${simScenarios.map(sim => `
          <div class="sim-scenario-card" id="sim-card-${sim.id}">
            <div class="sim-scenario-header">
              <div>
                <span class="sim-id">${esc(sim.id)}</span>
                <h3 class="sim-title">${esc(sim.name)}</h3>
              </div>
              <span class="badge badge-severity-${sim.severity}">${sim.severity}</span>
            </div>
            <p class="sim-desc">${esc(sim.description)}</p>
            <div class="sim-meta">
              <span class="badge badge-technique">${esc(sim.correlationRule)}</span>
              <span class="sim-event-count">${sim.events.length} events</span>
            </div>
            <button class="sim-run-btn" onclick="runSimulationUI('${sim.id}')">
              ▶ Run Scenario
            </button>
            <div class="sim-output" id="sim-output-${sim.id}" style="display:none"></div>
          </div>
        `).join('')}
      </div>
    </div>
  `;
}

// ── Correlation Page Tab Switching ──
window.switchCorrPageTab = function(btn) {
  const tabId = btn.dataset.ctab;
  document.querySelectorAll('.corr-page-tab').forEach(t => t.classList.remove('active'));
  document.querySelectorAll('.corr-tab-panel').forEach(p => p.classList.remove('active'));
  btn.classList.add('active');
  const panel = document.getElementById('ctab-' + tabId);
  if (panel) panel.classList.add('active');
};

window.switchCorrQuery = function(btn, platform) {
  const card = btn.closest('.corr-card');
  card.querySelectorAll('.corr-qtab').forEach(t => t.classList.remove('active'));
  card.querySelectorAll('.corr-query-content').forEach(c => c.classList.remove('active'));
  btn.classList.add('active');
  card.querySelector(`.corr-query-content[data-cq="${platform}"]`).classList.add('active');
};

// ── Entity Filter ──
window.filterEntityType = function(type, chip) {
  document.querySelectorAll('.entity-filter-bar .filter-chip').forEach(c => c.classList.remove('active'));
  chip.classList.add('active');
  document.querySelectorAll('.entity-card').forEach(card => {
    card.style.display = (type === 'all' || card.dataset.entityType === type) ? '' : 'none';
  });
};

// ── Simulation Runner UI ──
window.runSimulationUI = function(scenarioId) {
  const outputEl = document.getElementById('sim-output-' + scenarioId);
  if (!outputEl) return;

  outputEl.style.display = 'block';
  outputEl.innerHTML = '<div class="sim-loading">⏳ Processing events through decision engine...</div>';

  setTimeout(() => {
    const result = typeof runSimulation !== 'undefined' ? runSimulation(scenarioId) : null;
    if (!result || result.error) {
      outputEl.innerHTML = '<div class="sim-error">❌ Simulation failed: ' + (result?.error || 'Unknown error') + '</div>';
      return;
    }

    const scenario = result.scenario;
    let html = `<div class="sim-results">`;
    html += `<div class="sim-results-header">${result.escalated ? '🚨 INCIDENT CREATED' : '📋 Events Processed'}</div>`;
    
    // Event flow
    html += `<div class="sim-event-flow">`;
    scenario.events.forEach((evt, idx) => {
      const isLast = idx === scenario.events.length - 1;
      const isEscalation = evt.severity === 'critical' || evt.severity === 'high';
      html += `
        <div class="sim-event-node ${isEscalation ? 'sim-event-critical' : ''}">
          <div class="sim-event-idx">${idx + 1}</div>
          <div class="sim-event-detail">
            <span class="sim-event-type">${esc(evt.eventType)}</span>
            <span class="sim-event-meta">${esc(evt.hostname || '')} | ${esc(evt.user || '')} | ${esc(evt.sourceIP || '')}</span>
          </div>
          <span class="badge badge-severity-${evt.severity}" style="font-size:0.6rem">${evt.severity}</span>
        </div>
        ${!isLast ? '<div class="sim-event-connector">↓</div>' : ''}
      `;
    });
    html += `</div>`;

    // Verdict
    if (result.escalated && result.incident) {
      html += `
        <div class="sim-verdict sim-verdict-escalated">
          <div class="sim-verdict-icon">🚨</div>
          <div class="sim-verdict-text">
            <strong>ALERT → INCIDENT</strong><br>
            ${esc(result.incident.title)}<br>
            <span class="badge badge-severity-${result.incident.severity}" style="margin-top:4px">${result.incident.severity.toUpperCase()}</span>
            <span style="color:var(--text-muted);font-size:0.75rem;margin-left:8px">${esc(result.incident.id)}</span>
          </div>
        </div>
      `;
    } else {
      html += `
        <div class="sim-verdict sim-verdict-alert">
          <div class="sim-verdict-icon">📋</div>
          <div class="sim-verdict-text">
            <strong>Events processed — alerts generated</strong><br>
            <span style="color:var(--text-muted);font-size:0.75rem">${result.results.length} events evaluated, ${result.results.reduce((a,r) => a + r.totalAlerts, 0)} alerts generated</span>
          </div>
        </div>
      `;
    }

    html += `</div>`;
    outputEl.innerHTML = html;
  }, 800);
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
