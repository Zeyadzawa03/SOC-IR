// ============================================
// SIGMA DETECTION PLATFORM - Splunk Intelligence Page
// Renders the Splunk Intelligence Sidebar Module
// ============================================

function renderSplunkIntelligencePage(el) {
  const data = window.SPLUNK_INTELLIGENCE_DATA || { fundamentals: [], categories: {} };

  // Calculate stats
  const totalCategories = Object.keys(data.categories).length;
  let totalQueries = 0;
  Object.values(data.categories).forEach(c => totalQueries += c.queries.length);

  el.innerHTML = `
    <div class="animate-fadeInUp">
      <h1 class="page-title">Splunk Intelligence</h1>
      <p class="page-subtitle">Access curated SPL queries, investigation techniques, and threat hunting patterns aligned with MITRE ATT&CK categories. Pivot directly from Sigma rules into actionable Splunk searches.</p>
    </div>

    <!-- Summary Stats -->
    <div class="stats-grid animate-fadeInUp" style="margin-bottom: 24px;">
      <div class="stat-card blue">
        <div class="stat-icon">🧠</div>
        <div class="stat-value">${totalQueries}</div>
        <div class="stat-label">Curated SPL Queries</div>
      </div>
      <div class="stat-card purple">
        <div class="stat-icon">🗂️</div>
        <div class="stat-value">${totalCategories}</div>
        <div class="stat-label">Mapped Categories</div>
      </div>
      <div class="stat-card cyan">
        <div class="stat-icon">🎯</div>
        <div class="stat-value">100%</div>
        <div class="stat-label">Detection Alignment</div>
      </div>
    </div>

    <!-- Toolbar -->
    <div class="rules-toolbar animate-fadeInUp" style="margin-bottom: 24px; padding: 12px; background: var(--bg-card); border: 1px solid var(--border-primary); border-radius: var(--radius-md);">
      <div class="filter-group" style="display:flex; gap: 12px; align-items: center;">
        <span style="font-weight: 600; font-size: 0.9rem; color: var(--text-primary);">Filter Intelligence:</span>
        <input type="text" class="filter-input" id="splunkSearchInput" placeholder="Search queries, commands, or use cases..." style="flex:1; min-width:250px">
        <select class="filter-select" id="splunkCategorySelect" style="min-width: 200px;">
          <option value="all">All Categories</option>
          <option value="fundamentals">SPL Fundamentals</option>
          ${Object.entries(data.categories).map(([id, cat]) => `<option value="${id}">${cat.name}</option>`).join('')}
        </select>
      </div>
    </div>

    <div id="splunkContentArea">
      <!-- Content populated dynamically based on filters -->
    </div>
  `;

  const searchInput = document.getElementById('splunkSearchInput');
  const catSelect = document.getElementById('splunkCategorySelect');

  function renderContent() {
    const searchTerm = searchInput.value.toLowerCase();
    const selectedCat = catSelect.value;
    const contentArea = document.getElementById('splunkContentArea');
    
    let html = '';

    // Fundamentals Section
    if (selectedCat === 'all' || selectedCat === 'fundamentals') {
      const filteredFundamentals = data.fundamentals.filter(f => 
        f.title.toLowerCase().includes(searchTerm) || 
        f.description.toLowerCase().includes(searchTerm) ||
        f.query.toLowerCase().includes(searchTerm)
      );

      if (filteredFundamentals.length > 0) {
        html += `
          <div class="detail-section animate-fadeInUp">
            <h2 class="detail-section-title"><span class="section-icon">📚</span> SPL Fundamentals</h2>
            <div style="display:grid; grid-template-columns: repeat(auto-fit, minmax(400px, 1fr)); gap: 16px;">
              ${filteredFundamentals.map(f => `
                <div class="card" style="border-left: 3px solid var(--accent-cyan);">
                  <div class="card-body">
                    <h3 style="margin-top:0; font-size: 1.1rem; color: var(--text-primary); margin-bottom: 8px;">${window.escHtml ? window.escHtml(f.title) : f.title}</h3>
                    <p style="font-size: 0.85rem; color: var(--text-secondary); margin-bottom: 12px; line-height: 1.5;">${window.escHtml ? window.escHtml(f.description) : f.description}</p>
                    <div class="code-block" style="margin-bottom: 12px;">
                      <div class="code-block-header">
                        <span class="code-block-lang">Splunk SPL</span>
                        <button class="code-block-copy" onclick="if(window.copyToClipboard){window.copyToClipboard('${(f.query).replace(/'/g,"\\'").replace(/"/g,"&quot;")}', this)}else{navigator.clipboard.writeText('${(f.query).replace(/'/g,"\\'")}');this.textContent='Copied';setTimeout(()=>this.textContent='Copy',2000)}">Copy</button>
                      </div>
                      <pre style="white-space: pre-wrap; word-break: break-all;">${window.escHtml ? window.escHtml(f.query) : f.query}</pre>
                    </div>
                    <div style="font-size: 0.8rem; color: var(--accent-blue); display: flex; align-items: flex-start; gap: 8px; background: rgba(59,130,246,0.1); padding: 8px; border-radius: 4px;">
                      <span>💡</span> <span style="flex:1;"><strong>Use Case:</strong> ${window.escHtml ? window.escHtml(f.useCase) : f.useCase}</span>
                    </div>
                  </div>
                </div>
              `).join('')}
            </div>
          </div>
        `;
      }
    }

    // Categories Section
    Object.entries(data.categories).forEach(([catId, catData]) => {
      if (selectedCat !== 'all' && selectedCat !== catId) return;

      const filteredQueries = catData.queries.filter(q => 
        q.name.toLowerCase().includes(searchTerm) || 
        q.query.toLowerCase().includes(searchTerm)
      );
      
      const filteredTips = catData.tips.filter(t => t.toLowerCase().includes(searchTerm));

      if (filteredQueries.length > 0 || filteredTips.length > 0) {
        html += `
          <div class="detail-section animate-fadeInUp" style="margin-top: 32px">
            <div style="display:flex; justify-content: space-between; align-items: center; border-bottom: 1px solid var(--border-primary); padding-bottom: 8px; margin-bottom: 16px;">
              <h2 class="detail-section-title" style="margin-bottom:0; border-bottom: none; padding-bottom: 0;">
                <span class="section-icon">🧩</span> ${window.escHtml ? window.escHtml(catData.name) : catData.name} Investigation Patterns
              </h2>
              <button class="btn-sm" onclick="if(window.navigate) window.navigate('rules', {category: '${catId}'})" style="background: rgba(16, 185, 129, 0.1); color: var(--accent-green); border: 1px solid rgba(16, 185, 129, 0.3);">
                📋 View Related Sigma Rules
              </button>
            </div>
            
            ${filteredTips.length > 0 ? `
              <div class="info-box info" style="margin-bottom: 16px;">
                <div class="info-box-title">🧠 Investigation & Triage Tips</div>
                <ul class="detail-list" style="margin-top: 8px;">
                  ${filteredTips.map(t => `<li>${window.escHtml ? window.escHtml(t) : t}</li>`).join('')}
                </ul>
              </div>
            ` : ''}

            <div style="display:grid; grid-template-columns: repeat(auto-fit, minmax(400px, 1fr)); gap: 16px;">
              ${filteredQueries.map(q => `
                <div class="card" style="border-left: 3px solid ${q.type === 'Detection' ? 'var(--accent-red)' : 'var(--accent-purple)'};">
                  <div class="card-body">
                    <div style="display:flex; justify-content: space-between; align-items: flex-start; margin-bottom: 12px;">
                      <h3 style="margin:0; font-size: 1.05rem; color: var(--text-primary);">${window.escHtml ? window.escHtml(q.name) : q.name}</h3>
                      <span class="badge" style="background: ${q.type === 'Detection' ? 'rgba(239,68,68,0.1)' : 'rgba(168,85,247,0.1)'}; color: ${q.type === 'Detection' ? 'var(--accent-red)' : 'var(--accent-purple)'}; font-size: 0.7rem;">${q.type}</span>
                    </div>
                    <div class="code-block">
                      <div class="code-block-header">
                        <span class="code-block-lang">Splunk SPL</span>
                        <button class="code-block-copy" onclick="if(window.copyToClipboard){window.copyToClipboard('${(q.query).replace(/'/g,"\\'").replace(/"/g,"&quot;")}', this)}else{navigator.clipboard.writeText('${(q.query).replace(/'/g,"\\'")}');this.textContent='Copied';setTimeout(()=>this.textContent='Copy',2000)}">Copy</button>
                      </div>
                      <pre style="white-space: pre-wrap; word-break: break-all;">${window.escHtml ? window.escHtml(q.query) : q.query}</pre>
                    </div>
                  </div>
                </div>
              `).join('')}
            </div>
          </div>
        `;
      }
    });

    if (html === '') {
      html = `
        <div class="empty-state">
          <div class="empty-state-icon">🔍</div>
          <div class="empty-state-text">No Intelligence Found</div>
          <div class="empty-state-sub">Adjust your search or filter to see Splunk queries.</div>
        </div>
      `;
    }

    contentArea.innerHTML = html;
  }

  // Bind events
  searchInput.addEventListener('input', renderContent);
  catSelect.addEventListener('change', renderContent);

  // Initial render
  renderContent();
}

// Make accessible to window
if (typeof window !== 'undefined') {
  window.renderSplunkIntelligencePage = renderSplunkIntelligencePage;
}
