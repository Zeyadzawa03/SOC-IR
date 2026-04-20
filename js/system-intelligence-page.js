// ═══════════════════════════════════════════════════════════════════════
// System Intelligence Page — Renderer
// Windows Event Logs, PowerShell, Network & Registry Intelligence
// Extension module for SigmaGuard v4.0
// ═══════════════════════════════════════════════════════════════════════

const siEsc = (s) => typeof escHtml === 'function' ? escHtml(String(s)) : String(s).replace(/[&<>"']/g, m => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[m]));

function renderSystemIntelligencePage(container) {
  const eventCats = typeof getEventCategories !== 'undefined' ? getEventCategories() : [];
  const regCats = typeof getRegistryCategories !== 'undefined' ? getRegistryCategories() : [];
  const totalEvents = typeof WINDOWS_EVENT_LOGS !== 'undefined' ? WINDOWS_EVENT_LOGS.length : 0;
  const totalPS = typeof POWERSHELL_INTELLIGENCE !== 'undefined' ? POWERSHELL_INTELLIGENCE.length : 0;
  const totalNet = typeof NETWORK_INTELLIGENCE !== 'undefined' ? NETWORK_INTELLIGENCE.length : 0;
  const totalReg = typeof REGISTRY_INTELLIGENCE !== 'undefined' ? REGISTRY_INTELLIGENCE.length : 0;
  const totalFlows = typeof ATTACK_FLOWS !== 'undefined' ? ATTACK_FLOWS.length : 0;

  container.innerHTML = `
    <div class="page-header animate-fadeInUp">
      <div>
        <h1 class="page-title"><span class="title-icon">🖥️</span> System Intelligence</h1>
        <p class="page-subtitle">Comprehensive forensic + detection reference for Windows Event Logs, PowerShell, Network, and Registry — fully cross-linked to Sigma rules, MITRE ATT&CK, and Incident Response</p>
      </div>
      <div class="header-stats">
        <div class="stat-chip"><span class="stat-value">${totalEvents}</span><span class="stat-label">Event Logs</span></div>
        <div class="stat-chip"><span class="stat-value">${totalPS}</span><span class="stat-label">PS Patterns</span></div>
        <div class="stat-chip"><span class="stat-value">${totalNet}</span><span class="stat-label">Network Intel</span></div>
        <div class="stat-chip"><span class="stat-value">${totalReg}</span><span class="stat-label">Registry Keys</span></div>
        <div class="stat-chip"><span class="stat-value">${totalFlows}</span><span class="stat-label">Attack Flows</span></div>
      </div>
    </div>

    <!-- Search Bar -->
    <div class="si-search-bar animate-fadeInUp">
      <input type="text" id="siSearchInput" class="search-input" placeholder="Search event IDs, techniques, registry paths, attack types..." onkeyup="siHandleSearch()" />
    </div>

    <!-- Tab Navigation -->
    <div class="si-tabs-bar animate-fadeInUp" id="siTabsBar">
      <button class="si-tab active" data-sitab="event-logs" onclick="switchSITab(this)">🖥️ Windows Event Logs <span class="si-tab-count">${totalEvents}</span></button>
      <button class="si-tab" data-sitab="powershell" onclick="switchSITab(this)">⚡ PowerShell Intelligence <span class="si-tab-count">${totalPS}</span></button>
      <button class="si-tab" data-sitab="network" onclick="switchSITab(this)">🌐 Network Logs <span class="si-tab-count">${totalNet}</span></button>
      <button class="si-tab" data-sitab="registry" onclick="switchSITab(this)">🧬 Registry Intelligence <span class="si-tab-count">${totalReg}</span></button>
      <button class="si-tab" data-sitab="attack-flows" onclick="switchSITab(this)">🔗 Attack Flows <span class="si-tab-count">${totalFlows}</span></button>
    </div>

    <!-- ═══ TAB 1: Windows Event Logs ═══ -->
    <div class="si-tab-panel active" id="sitab-event-logs">
      ${renderEventLogsTab(eventCats)}
    </div>

    <!-- ═══ TAB 2: PowerShell Intelligence ═══ -->
    <div class="si-tab-panel" id="sitab-powershell">
      ${renderPowerShellTab()}
    </div>

    <!-- ═══ TAB 3: Network Logs ═══ -->
    <div class="si-tab-panel" id="sitab-network">
      ${renderNetworkTab()}
    </div>

    <!-- ═══ TAB 4: Registry Intelligence ═══ -->
    <div class="si-tab-panel" id="sitab-registry">
      ${renderRegistryTab(regCats)}
    </div>

    <!-- ═══ TAB 5: Attack Flows ═══ -->
    <div class="si-tab-panel" id="sitab-attack-flows">
      ${renderAttackFlowsTab()}
    </div>
  `;
}

// ── Tab Switching ──
window.switchSITab = function(btn) {
  const tabId = btn.dataset.sitab;
  document.querySelectorAll('.si-tab').forEach(t => t.classList.remove('active'));
  document.querySelectorAll('.si-tab-panel').forEach(p => p.classList.remove('active'));
  btn.classList.add('active');
  const panel = document.getElementById('sitab-' + tabId);
  if (panel) panel.classList.add('active');
};

// ── Search Handler ──
window.siHandleSearch = function() {
  const query = document.getElementById('siSearchInput').value.trim();
  if (query.length < 2) {
    // Show all items
    document.querySelectorAll('.si-event-card, .si-ps-card, .si-net-card, .si-reg-card, .si-flow-card').forEach(c => c.style.display = '');
    document.querySelectorAll('.si-category-group').forEach(g => g.style.display = '');
    return;
  }
  const q = query.toLowerCase();

  // Filter event logs
  document.querySelectorAll('.si-event-card').forEach(card => {
    const searchText = card.dataset.search || '';
    card.style.display = searchText.includes(q) ? '' : 'none';
  });
  // Show/hide category groups with no visible cards
  document.querySelectorAll('.si-category-group').forEach(group => {
    const visibleCards = group.querySelectorAll('.si-event-card:not([style*="display: none"])');
    group.style.display = visibleCards.length > 0 ? '' : 'none';
  });

  // Filter PowerShell
  document.querySelectorAll('.si-ps-card').forEach(card => {
    const searchText = card.dataset.search || '';
    card.style.display = searchText.includes(q) ? '' : 'none';
  });

  // Filter Network
  document.querySelectorAll('.si-net-card').forEach(card => {
    const searchText = card.dataset.search || '';
    card.style.display = searchText.includes(q) ? '' : 'none';
  });

  // Filter Registry
  document.querySelectorAll('.si-reg-card').forEach(card => {
    const searchText = card.dataset.search || '';
    card.style.display = searchText.includes(q) ? '' : 'none';
  });

  // Filter Attack Flows
  document.querySelectorAll('.si-flow-card').forEach(card => {
    const searchText = card.dataset.search || '';
    card.style.display = searchText.includes(q) ? '' : 'none';
  });
};

// ══════════════════════════════════════════════
// TAB 1: WINDOWS EVENT LOGS
// ══════════════════════════════════════════════
function renderEventLogsTab(eventCats) {
  const events = typeof WINDOWS_EVENT_LOGS !== 'undefined' ? WINDOWS_EVENT_LOGS : [];
  
  return `
    <div class="si-section-intro">
      <div class="info-box info">
        <div class="info-box-title">📋 Windows Event Log Coverage</div>
        This section covers <strong>${events.length} critical Windows Event IDs</strong> organized into ${eventCats.length} categories. Each event includes detection relevance, MITRE ATT&CK mapping, related Sigma rules, and incident response links. Events are connected as attack flows to show how individual events chain into detection patterns.
      </div>
    </div>

    ${eventCats.map(cat => {
      const catEvents = events.filter(e => e.category === cat.id);
      return `
      <div class="si-category-group" data-cat="${cat.id}">
        <div class="si-category-header" onclick="this.parentElement.classList.toggle('collapsed')">
          <span class="si-cat-label">${cat.label}</span>
          <span class="si-cat-count">${catEvents.length} events</span>
          <span class="si-cat-chevron">▼</span>
        </div>
        <div class="si-category-body">
          ${catEvents.map(evt => renderEventCard(evt)).join('')}
        </div>
      </div>`;
    }).join('')}
  `;
}

function renderEventCard(evt) {
  const sevColor = evt.severity === 'critical' ? 'var(--accent-red)' : evt.severity === 'high' ? 'var(--severity-high)' : evt.severity === 'medium' ? 'var(--accent-orange)' : 'var(--accent-blue)';
  const searchData = `${evt.eventId} ${evt.title} ${evt.description} ${evt.relatedAttackType} ${evt.mitreTechniques.map(t=>t.id+' '+t.name).join(' ')} ${evt.category}`.toLowerCase();

  return `
    <div class="si-event-card" data-search="${siEsc(searchData)}" style="border-left: 3px solid ${sevColor}">
      <div class="si-event-header" onclick="this.parentElement.classList.toggle('expanded')">
        <div class="si-event-id-badge" style="background: ${sevColor}15; color: ${sevColor}; border: 1px solid ${sevColor}40">${siEsc(evt.eventId)}</div>
        <div class="si-event-title-area">
          <div class="si-event-title">${siEsc(evt.title)}</div>
          <div class="si-event-attack-type">${siEsc(evt.relatedAttackType)}</div>
        </div>
        <div class="si-event-badges">
          <span class="badge badge-severity-${evt.severity}">${evt.severity}</span>
          ${evt.mitreTechniques.slice(0,2).map(t => `<span class="badge badge-technique" style="cursor:pointer" onclick="event.stopPropagation();navigate('mitre')">${siEsc(t.id)}</span>`).join('')}
        </div>
        <span class="si-event-chevron">▶</span>
      </div>
      <div class="si-event-body">
        <div class="si-event-desc">${siEsc(evt.description)}</div>
        
        <div class="si-detail-grid">
          <div class="si-detail-section">
            <div class="si-detail-label">🎯 Detection Relevance</div>
            <div class="si-detail-text">${siEsc(evt.detectionRelevance)}</div>
          </div>
          
          <div class="si-detail-section">
            <div class="si-detail-label">🎯 MITRE ATT&CK Techniques</div>
            <div class="si-mitre-links">
              ${evt.mitreTechniques.map(t => `
                <span class="si-mitre-chip" onclick="navigate('mitre')" title="${siEsc(t.name)}">
                  <span class="si-mitre-id">${siEsc(t.id)}</span>
                  <span class="si-mitre-name">${siEsc(t.name)}</span>
                </span>
              `).join('')}
            </div>
          </div>

          ${evt.keyFields && evt.keyFields.length > 0 ? `
          <div class="si-detail-section">
            <div class="si-detail-label">🔑 Key Fields</div>
            <div class="si-field-chips">
              ${evt.keyFields.map(f => `<span class="si-field-chip">${siEsc(f)}</span>`).join('')}
            </div>
          </div>` : ''}

          ${evt.logonTypes ? `
          <div class="si-detail-section si-detail-full">
            <div class="si-detail-label">📋 Logon Types Reference</div>
            <div class="si-logon-types">
              ${evt.logonTypes.map(lt => `
                <div class="si-logon-type-row">
                  <span class="si-lt-num">Type ${lt.type}</span>
                  <span class="si-lt-name">${siEsc(lt.name)}</span>
                  <span class="si-lt-desc">${siEsc(lt.desc)}</span>
                </div>
              `).join('')}
            </div>
          </div>` : ''}

          ${evt.failureCodes ? `
          <div class="si-detail-section si-detail-full">
            <div class="si-detail-label">❌ Failure Status Codes</div>
            <div class="si-failure-codes">
              ${evt.failureCodes.map(fc => `
                <div class="si-fc-row">
                  <span class="si-fc-code">${siEsc(fc.code)}</span>
                  <span class="si-fc-reason">${siEsc(fc.reason)}</span>
                </div>
              `).join('')}
            </div>
          </div>` : ''}

          ${evt.keyPrivileges ? `
          <div class="si-detail-section si-detail-full">
            <div class="si-detail-label">⚠️ Key Privileges to Monitor</div>
            <ul class="si-priv-list">
              ${evt.keyPrivileges.map(p => `<li>${siEsc(p)}</li>`).join('')}
            </ul>
          </div>` : ''}
        </div>

        <!-- Cross-Links -->
        <div class="si-crosslinks">
          <div class="si-crosslink-label">🔗 Connected Resources</div>
          <div class="si-crosslink-chips">
            ${evt.relatedCategories.map(c => `<span class="si-crosslink-chip si-cl-cat" onclick="navigate('rules',{category:'${c}'})">${getCategoryIcon(c)} ${formatCatName(c)}</span>`).join('')}
            ${evt.relatedIR ? `<span class="si-crosslink-chip si-cl-ir" onclick="navigate('incident-response')">🚨 IR Playbook</span>` : ''}
            <span class="si-crosslink-chip si-cl-mitre" onclick="navigate('mitre')">🎯 ATT&CK Explorer</span>
          </div>
        </div>

        ${evt.sampleQuery ? `
        <div class="si-sample-query">
          <div class="si-detail-label">💻 Sample Detection Query</div>
          <div class="si-code-block">
            <pre>${siEsc(evt.sampleQuery)}</pre>
            <button class="si-copy-btn" onclick="siCopyText(this, \`${evt.sampleQuery.replace(/`/g, '\\`').replace(/\\/g, '\\\\')}\`)">📋 Copy</button>
          </div>
        </div>` : ''}
      </div>
    </div>
  `;
}

// ══════════════════════════════════════════════
// TAB 2: POWERSHELL INTELLIGENCE
// ══════════════════════════════════════════════
function renderPowerShellTab() {
  const patterns = typeof POWERSHELL_INTELLIGENCE !== 'undefined' ? POWERSHELL_INTELLIGENCE : [];

  return `
    <div class="si-section-intro">
      <div class="info-box warning">
        <div class="info-box-title">⚡ PowerShell as a Critical Attack Surface</div>
        PowerShell is used in <strong>over 40% of sophisticated attacks</strong>. Script Block Logging (Event 4104) is the single most important PowerShell log source — it captures deobfuscated script content. This section documents ${patterns.length} critical suspicious patterns with detection mappings, MITRE techniques, and Sigma rule connections.
      </div>
    </div>

    <div class="si-ps-grid">
      ${patterns.map(p => {
        const searchData = `${p.id} ${p.name} ${p.pattern} ${p.suspiciousBehavior} ${p.mitreTechnique.id} ${p.mitreTechnique.name}`.toLowerCase();
        return `
        <div class="si-ps-card" data-search="${siEsc(searchData)}">
          <div class="si-ps-header">
            <div class="si-ps-id">${siEsc(p.id)}</div>
            <h3 class="si-ps-title">${siEsc(p.name)}</h3>
            <span class="badge badge-severity-${p.severity}">${p.severity}</span>
          </div>

          <div class="si-ps-patterns">
            <div class="si-detail-label">🔍 Detection Patterns</div>
            <div class="si-ps-pattern-code">${siEsc(p.pattern)}</div>
          </div>

          <div class="si-ps-behavior">
            <div class="si-detail-label">⚠️ Suspicious Behavior</div>
            <p>${siEsc(p.suspiciousBehavior)}</p>
          </div>

          <div class="si-ps-detection">
            <div class="si-detail-label">🛡️ Detection Mapping</div>
            <p>${siEsc(p.detectionMapping)}</p>
          </div>

          <div class="si-ps-example">
            <div class="si-detail-label">💻 Example Malicious Code</div>
            <div class="si-code-block si-code-dangerous">
              <pre>${siEsc(p.exampleCode)}</pre>
            </div>
          </div>

          <div class="si-ps-footer">
            <div class="si-crosslink-chips">
              <span class="si-crosslink-chip si-cl-mitre" onclick="navigate('mitre')" title="${siEsc(p.mitreTechnique.name)}">🎯 ${siEsc(p.mitreTechnique.id)}</span>
              ${p.relatedCategories.map(c => `<span class="si-crosslink-chip si-cl-cat" onclick="navigate('rules',{category:'${c}'})">${getCategoryIcon(c)} ${formatCatName(c)}</span>`).join('')}
              <span class="si-crosslink-chip si-cl-ir" onclick="navigate('incident-response')">🚨 IR Playbook</span>
            </div>
            <div class="si-ps-event-id">
              <span class="si-field-chip">Event ID: ${siEsc(p.eventId)}</span>
            </div>
          </div>
        </div>
      `}).join('')}
    </div>
  `;
}

// ══════════════════════════════════════════════
// TAB 3: NETWORK LOGS
// ══════════════════════════════════════════════
function renderNetworkTab() {
  const entries = typeof NETWORK_INTELLIGENCE !== 'undefined' ? NETWORK_INTELLIGENCE : [];

  return `
    <div class="si-section-intro">
      <div class="info-box info">
        <div class="info-box-title">🌐 Network-Level Detection Intelligence</div>
        Network logs provide essential visibility into C2 communications, data exfiltration, lateral movement, and reconnaissance. This section covers ${entries.length} key network detection patterns including DNS tunneling, beaconing analysis, and protocol-level anomalies.
      </div>
    </div>

    <div class="si-net-grid">
      ${entries.map(n => {
        const searchData = `${n.id} ${n.name} ${n.description} ${n.attackType} ${n.mitreMapping.id} ${n.mitreMapping.name}`.toLowerCase();
        return `
        <div class="si-net-card" data-search="${siEsc(searchData)}">
          <div class="si-net-header">
            <div class="si-net-id">${siEsc(n.id)}</div>
            <h3 class="si-net-title">${siEsc(n.name)}</h3>
            <span class="badge badge-severity-${n.severity}">${n.severity}</span>
          </div>

          <p class="si-net-desc">${siEsc(n.description)}</p>

          <div class="si-net-relevance">
            <div class="si-detail-label">🎯 Detection Relevance</div>
            <p>${siEsc(n.detectionRelevance)}</p>
          </div>

          <div class="si-net-indicators">
            <div class="si-detail-label">🔍 Key Indicators</div>
            <ul class="si-indicator-list">
              ${n.indicators.map(i => `<li>${siEsc(i)}</li>`).join('')}
            </ul>
          </div>

          <div class="si-net-attack-type">
            <span class="si-attack-type-badge">${siEsc(n.attackType)}</span>
          </div>

          ${n.sampleQuery ? `
          <div class="si-sample-query">
            <div class="si-detail-label">💻 Sample Query</div>
            <div class="si-code-block">
              <pre>${siEsc(n.sampleQuery)}</pre>
            </div>
          </div>` : ''}

          <div class="si-net-footer">
            <div class="si-crosslink-chips">
              <span class="si-crosslink-chip si-cl-mitre" onclick="navigate('mitre')" title="${siEsc(n.mitreMapping.name)}">🎯 ${siEsc(n.mitreMapping.id)} — ${siEsc(n.mitreMapping.name)}</span>
              <span class="si-crosslink-chip si-cl-ir" onclick="navigate('incident-response')">🚨 IR Playbook</span>
            </div>
          </div>
        </div>
      `}).join('')}
    </div>
  `;
}

// ══════════════════════════════════════════════
// TAB 4: REGISTRY INTELLIGENCE
// ══════════════════════════════════════════════
function renderRegistryTab(regCats) {
  const entries = typeof REGISTRY_INTELLIGENCE !== 'undefined' ? REGISTRY_INTELLIGENCE : [];

  return `
    <div class="si-section-intro">
      <div class="info-box info">
        <div class="info-box-title">🧬 Windows Registry Intelligence</div>
        The Windows Registry is a key target for persistence, privilege escalation, and defense evasion. This section documents ${entries.length} critical registry locations grouped by purpose — each with detection guidance, MITRE mapping, and IR response steps.
      </div>
    </div>

    ${regCats.map(cat => {
      const catEntries = entries.filter(r => r.category === cat.id);
      return `
      <div class="si-category-group" data-cat="${cat.id}">
        <div class="si-category-header" onclick="this.parentElement.classList.toggle('collapsed')">
          <span class="si-cat-label">🔑 ${siEsc(cat.label)}</span>
          <span class="si-cat-count">${catEntries.length} keys</span>
          <span class="si-cat-chevron">▼</span>
        </div>
        <div class="si-category-body">
          ${catEntries.map(reg => renderRegistryCard(reg)).join('')}
        </div>
      </div>`;
    }).join('')}
  `;
}

function renderRegistryCard(reg) {
  const sevColor = reg.severity === 'critical' ? 'var(--accent-red)' : reg.severity === 'high' ? 'var(--severity-high)' : 'var(--accent-orange)';
  const searchData = `${reg.id} ${reg.registryPath} ${reg.description} ${reg.purpose} ${reg.mitreTechnique.id} ${reg.mitreTechnique.name}`.toLowerCase();

  return `
    <div class="si-reg-card si-event-card" data-search="${siEsc(searchData)}" style="border-left: 3px solid ${sevColor}">
      <div class="si-event-header" onclick="this.parentElement.classList.toggle('expanded')">
        <div class="si-reg-id-badge">${siEsc(reg.id)}</div>
        <div class="si-event-title-area">
          <div class="si-reg-path">${siEsc(reg.registryPath)}</div>
          <div class="si-event-attack-type">${siEsc(reg.purpose)}</div>
        </div>
        <div class="si-event-badges">
          <span class="badge badge-severity-${reg.severity}">${reg.severity}</span>
          <span class="badge badge-technique" style="cursor:pointer" onclick="event.stopPropagation();navigate('mitre')">${siEsc(reg.mitreTechnique.id)}</span>
        </div>
        <span class="si-event-chevron">▶</span>
      </div>
      <div class="si-event-body">
        <div class="si-event-desc">${siEsc(reg.description)}</div>

        <div class="si-detail-grid">
          <div class="si-detail-section">
            <div class="si-detail-label">🎯 Detection Relevance</div>
            <div class="si-detail-text">${siEsc(reg.detectionRelevance)}</div>
          </div>
          <div class="si-detail-section">
            <div class="si-detail-label">🎯 MITRE ATT&CK</div>
            <div class="si-mitre-links">
              <span class="si-mitre-chip" onclick="navigate('mitre')" title="${siEsc(reg.mitreTechnique.name)}">
                <span class="si-mitre-id">${siEsc(reg.mitreTechnique.id)}</span>
                <span class="si-mitre-name">${siEsc(reg.mitreTechnique.name)}</span>
              </span>
            </div>
          </div>
        </div>

        ${reg.relatedIRSteps && reg.relatedIRSteps.length > 0 ? `
        <div class="si-ir-steps">
          <div class="si-detail-label">🚨 Incident Response Steps</div>
          <ol class="si-ir-step-list">
            ${reg.relatedIRSteps.map(s => `<li>${siEsc(s)}</li>`).join('')}
          </ol>
        </div>` : ''}

        <div class="si-crosslinks">
          <div class="si-crosslink-label">🔗 Connected Resources</div>
          <div class="si-crosslink-chips">
            <span class="si-crosslink-chip si-cl-mitre" onclick="navigate('mitre')">🎯 ATT&CK Explorer</span>
            <span class="si-crosslink-chip si-cl-ir" onclick="navigate('incident-response')">🚨 IR Playbook</span>
            <span class="si-crosslink-chip si-cl-cat" onclick="navigate('rules',{category:'${reg.category}'})">📋 Related Detections</span>
          </div>
        </div>
      </div>
    </div>
  `;
}

// ══════════════════════════════════════════════
// TAB 5: ATTACK FLOWS
// ══════════════════════════════════════════════
function renderAttackFlowsTab() {
  const flows = typeof ATTACK_FLOWS !== 'undefined' ? ATTACK_FLOWS : [];

  return `
    <div class="si-section-intro">
      <div class="info-box warning">
        <div class="info-box-title">🔗 Attack Flow Visualization</div>
        Events do NOT occur in isolation. This section shows how individual Windows events chain together into recognizable attack patterns. Each flow maps the event sequence → attack technique → detection strategy, connecting related events into actionable detection workflows.
      </div>
    </div>

    <div class="si-flows-grid">
      ${flows.map(flow => {
        const searchData = `${flow.id} ${flow.name} ${flow.description} ${flow.events.map(e=>e.eventId+' '+e.label).join(' ')} ${flow.mitreTechniques.join(' ')}`.toLowerCase();
        const sevColor = flow.severity === 'critical' ? 'var(--accent-red)' : 'var(--severity-high)';
        return `
        <div class="si-flow-card" data-search="${siEsc(searchData)}" style="border-top: 3px solid ${sevColor}">
          <div class="si-flow-header">
            <div class="si-flow-id">${siEsc(flow.id)}</div>
            <h3 class="si-flow-title">${siEsc(flow.name)}</h3>
            <span class="badge badge-severity-${flow.severity}">${flow.severity}</span>
          </div>

          <p class="si-flow-desc">${siEsc(flow.description)}</p>

          <!-- Event Chain Visualization -->
          <div class="si-flow-chain">
            ${flow.events.map((evt, idx) => {
              const roleColor = evt.role === 'trigger' ? '#3b82f6' : evt.role === 'escalation' ? '#ef4444' : evt.role === 'persistence' ? '#8b5cf6' : evt.role === 'credential-access' ? '#f59e0b' : evt.role === 'c2' ? '#ec4899' : evt.role === 'exfiltration' ? '#e11d48' : evt.role === 'destruction' ? '#ef4444' : '#10b981';
              return `
              <div class="si-flow-node" style="--node-color: ${roleColor}">
                <div class="si-flow-node-id">${siEsc(evt.eventId)}</div>
                <div class="si-flow-node-label">${siEsc(evt.label)}</div>
                <div class="si-flow-node-role">${siEsc(evt.role)}</div>
              </div>
              ${idx < flow.events.length - 1 ? '<div class="si-flow-arrow">→</div>' : ''}
            `}).join('')}
          </div>

          <div class="si-flow-narrative">
            <div class="si-detail-label">📖 Attack Narrative</div>
            <p>${siEsc(flow.attackNarrative)}</p>
          </div>

          <div class="si-flow-footer">
            <div class="si-crosslink-chips">
              ${flow.mitreTechniques.map(t => `<span class="si-crosslink-chip si-cl-mitre" onclick="navigate('mitre')">🎯 ${siEsc(t)}</span>`).join('')}
              <span class="si-crosslink-chip si-cl-cat" onclick="navigate('rules',{category:'${flow.relatedCategory}'})">${getCategoryIcon(flow.relatedCategory)} ${formatCatName(flow.relatedCategory)}</span>
              <span class="si-crosslink-chip si-cl-ir" onclick="navigate('incident-response')">🚨 IR Playbook</span>
            </div>
          </div>
        </div>
      `}).join('')}
    </div>
  `;
}

// ── Utility Helpers ──
function getCategoryIcon(catId) {
  const icons = { 'brute-force':'🔨','credential-access':'🔑','lateral-movement':'↔️','privilege-escalation':'⬆️','persistence':'📌','execution':'⚙️','defense-evasion':'🛡️','initial-access':'🚪','command-control':'📡','data-exfiltration':'📤','reconnaissance':'🔎','active-directory':'🏢','windows-specific':'🪟','endpoint-anomalies':'🖥️','network-anomalies':'📡','ransomware':'💀','insider-threat':'🕵️' };
  return icons[catId] || '📋';
}

function formatCatName(catId) {
  return (catId || '').replace(/-/g, ' ').replace(/\b\w/g, c => c.toUpperCase());
}

window.siCopyText = function(btn, text) {
  navigator.clipboard.writeText(text).then(() => {
    const orig = btn.textContent;
    btn.textContent = '✅ Copied!';
    btn.classList.add('copied');
    setTimeout(() => { btn.textContent = orig; btn.classList.remove('copied'); }, 2000);
  });
};

// ── Make globally accessible ──
window.renderSystemIntelligencePage = renderSystemIntelligencePage;
