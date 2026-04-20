$css = @"

/* =============================================================
   DETECTION TESTING & VALIDATION - SigmaGuard SOP Styles
   ============================================================= */

.det-stats-bar {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(140px, 1fr));
  gap: 12px;
  margin-bottom: 20px;
}
.det-stat-card {
  background: var(--bg-card);
  border: 1px solid var(--border-primary);
  border-radius: var(--radius-lg);
  padding: 16px;
  text-align: center;
  transition: all var(--transition-normal);
  position: relative;
  overflow: hidden;
}
.det-stat-card::before {
  content: '';
  position: absolute;
  top: 0; left: 0; right: 0;
  height: 3px;
  border-radius: var(--radius-lg) var(--radius-lg) 0 0;
}
.det-stat-card:hover { transform: translateY(-2px); border-color: var(--border-hover); }
.det-stat-total::before   { background: linear-gradient(90deg, var(--accent-cyan), transparent); }
.det-stat-pass::before    { background: linear-gradient(90deg, var(--accent-green), transparent); }
.det-stat-fail::before    { background: linear-gradient(90deg, var(--accent-red), transparent); }
.det-stat-review::before  { background: linear-gradient(90deg, var(--accent-orange), transparent); }
.det-stat-untested::before{ background: linear-gradient(90deg, var(--text-muted), transparent); }
.det-stat-rate::before    { background: linear-gradient(90deg, var(--accent-purple), transparent); }
.det-stat-num {
  font-size: 1.9rem;
  font-weight: 800;
  color: var(--text-primary);
  letter-spacing: -0.03em;
  line-height: 1;
}
.det-stat-lbl {
  font-size: 0.72rem;
  color: var(--text-secondary);
  margin-top: 6px;
  font-weight: 500;
}

.det-toolbar {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 12px;
  flex-wrap: wrap;
  margin-bottom: 20px;
  padding: 14px 16px;
  background: var(--bg-card);
  border: 1px solid var(--border-primary);
  border-radius: var(--radius-lg);
}
.det-toolbar-left  { display: flex; align-items: center; gap: 8px; flex-wrap: wrap; flex: 1; }
.det-toolbar-right { display: flex; align-items: center; gap: 8px; flex-shrink: 0; }

.det-progress-wrap {
  background: var(--bg-card);
  border: 1px solid var(--border-primary);
  border-radius: var(--radius-lg);
  padding: 14px 16px;
  margin-bottom: 20px;
}
.det-progress-label { font-size: 0.8rem; color: var(--text-secondary); margin-bottom: 8px; }
.det-progress-track {
  height: 6px;
  background: var(--border-primary);
  border-radius: var(--radius-full);
  overflow: hidden;
}
.det-progress-fill {
  height: 100%;
  background: linear-gradient(90deg, var(--accent-cyan), var(--accent-purple));
  border-radius: var(--radius-full);
  transition: width 0.3s ease;
}

.det-cat-grid {
  display: grid;
  grid-template-columns: repeat(auto-fill, minmax(200px, 1fr));
  gap: 10px;
}
.det-cat-card {
  display: flex;
  align-items: flex-start;
  gap: 10px;
  background: var(--bg-tertiary);
  border: 1px solid var(--border-primary);
  border-radius: var(--radius-md);
  padding: 12px;
  cursor: pointer;
  transition: all var(--transition-fast);
}
.det-cat-card:hover {
  background: var(--bg-card-hover);
  border-color: var(--border-hover);
  transform: translateY(-1px);
}
.det-cat-icon { font-size: 1.4rem; flex-shrink: 0; margin-top: 2px; }
.det-cat-info { flex: 1; min-width: 0; }
.det-cat-name { font-size: 0.82rem; font-weight: 700; color: var(--text-primary); line-height: 1.3; }
.det-cat-sub  { font-size: 0.7rem; color: var(--text-muted); margin-top: 2px; }
.det-cat-counts { display: flex; gap: 10px; margin-top: 6px; font-size: 0.72rem; font-weight: 600; }
.det-coverage-bar {
  height: 4px;
  background: var(--border-primary);
  border-radius: var(--radius-full);
  overflow: hidden;
}
.det-coverage-fill {
  height: 100%;
  border-radius: var(--radius-full);
  transition: width 0.6s cubic-bezier(0.4, 0, 0.2, 1);
}

.det-rule-row {
  border-bottom: 1px solid var(--border-primary);
  transition: background var(--transition-fast);
}
.det-rule-row:last-child { border-bottom: none; }
.det-rule-row:hover { background: rgba(255,255,255,0.01); }

.det-rule-header {
  display: flex;
  align-items: center;
  justify-content: space-between;
  padding: 14px 16px;
  cursor: pointer;
  gap: 12px;
  user-select: none;
}
.det-rule-header:hover { background: rgba(0,212,255,0.03); }
.det-rule-left  { display: flex; align-items: flex-start; gap: 10px; flex: 1; min-width: 0; }
.det-rule-right { display: flex; align-items: center; gap: 8px; flex-shrink: 0; }
.det-expand-icon {
  color: var(--text-muted);
  font-size: 0.7rem;
  margin-top: 5px;
  flex-shrink: 0;
  width: 14px;
  transition: transform var(--transition-fast);
}
.det-rule-title {
  font-size: 0.9rem;
  font-weight: 600;
  color: var(--text-primary);
  line-height: 1.3;
  margin-bottom: 6px;
}
.det-rule-meta { display: flex; align-items: center; gap: 6px; flex-wrap: wrap; }
.det-tc-count  { font-size: 0.72rem; color: var(--text-muted); font-weight: 600; white-space: nowrap; }
.det-cat-badge {
  display: inline-flex;
  align-items: center;
  gap: 4px;
  padding: 2px 8px;
  border-radius: var(--radius-full);
  font-size: 0.68rem;
  font-weight: 600;
  white-space: nowrap;
}
.det-auto-tag {
  display: inline-flex;
  align-items: center;
  padding: 1px 6px;
  border-radius: var(--radius-full);
  font-size: 0.64rem;
  font-weight: 600;
  background: rgba(100,116,139,0.15);
  color: var(--text-muted);
  border: 1px solid rgba(100,116,139,0.2);
}
.badge-technique {
  background: rgba(0,212,255,0.08);
  color: var(--accent-cyan);
  border: 1px solid rgba(0,212,255,0.2);
  padding: 3px 10px;
  border-radius: var(--radius-full);
  font-size: 0.7rem;
  font-weight: 600;
  font-family: var(--font-mono);
}

.det-rule-body { border-top: 1px solid var(--border-primary); }

.det-tc-item {
  padding: 16px;
  border-bottom: 1px solid rgba(148,163,184,0.06);
  background: var(--bg-tertiary);
}
.det-tc-item:last-child { border-bottom: none; }
.det-tc-header {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 10px;
  margin-bottom: 6px;
  flex-wrap: wrap;
}
.det-tc-name { font-size: 0.85rem; font-weight: 600; color: var(--text-primary); }
.det-tc-desc {
  font-size: 0.8rem;
  color: var(--text-secondary);
  line-height: 1.5;
  margin-bottom: 12px;
}

.det-type-badge {
  display: inline-flex;
  align-items: center;
  gap: 4px;
  padding: 2px 8px;
  border-radius: var(--radius-full);
  font-size: 0.7rem;
  font-weight: 700;
  white-space: nowrap;
}
.det-type-pos { background: rgba(16,185,129,0.1);  color: var(--accent-green); border: 1px solid rgba(16,185,129,0.2); }
.det-type-neg { background: rgba(239,68,68,0.1);   color: var(--accent-red);   border: 1px solid rgba(239,68,68,0.2); }

.det-status-badge {
  display: inline-flex;
  align-items: center;
  gap: 4px;
  padding: 3px 10px;
  border-radius: var(--radius-full);
  font-size: 0.72rem;
  font-weight: 700;
  white-space: nowrap;
}
.det-status-sm { font-size: 0.65rem; padding: 2px 7px; }
.det-status-passed   { background: rgba(16,185,129,0.12);  color: #10b981; border: 1px solid rgba(16,185,129,0.25); }
.det-status-failed   { background: rgba(239,68,68,0.12);   color: #ef4444; border: 1px solid rgba(239,68,68,0.25); }
.det-status-review   { background: rgba(245,158,11,0.12);  color: #f59e0b; border: 1px solid rgba(245,158,11,0.25); }
.det-status-untested { background: rgba(100,116,139,0.1);  color: #64748b; border: 1px solid rgba(100,116,139,0.15); }

.det-run-btn {
  background: rgba(0,212,255,0.08);
  border: 1px solid rgba(0,212,255,0.25);
  color: var(--accent-cyan);
  padding: 4px 12px;
  border-radius: var(--radius-md);
  font-size: 0.75rem;
  font-weight: 600;
  font-family: var(--font-primary);
  cursor: pointer;
  transition: all var(--transition-fast);
  white-space: nowrap;
}
.det-run-btn:hover    { background: rgba(0,212,255,0.18); box-shadow: 0 0 10px rgba(0,212,255,0.15); }
.det-run-btn:disabled { opacity: 0.5; cursor: not-allowed; }

.det-tc-panels {
  display: grid;
  grid-template-columns: 1fr 1fr;
  gap: 10px;
  margin-bottom: 10px;
}
.det-panel {
  background: var(--bg-card);
  border: 1px solid var(--border-primary);
  border-radius: var(--radius-md);
  padding: 12px;
}
.det-panel-input    { border-color: rgba(0,212,255,0.15); }
.det-panel-expected { border-color: rgba(139,92,246,0.15); }
.det-panel-title {
  font-size: 0.75rem;
  font-weight: 700;
  color: var(--text-secondary);
  text-transform: uppercase;
  letter-spacing: 0.05em;
  margin-bottom: 10px;
  border-bottom: 1px solid var(--border-primary);
  padding-bottom: 6px;
}
.det-panel-grid { display: grid; grid-template-columns: 1fr 1fr; gap: 6px; }
.det-field { display: flex; flex-direction: column; gap: 2px; }
.det-field-wide { grid-column: span 2; }
.det-field-full { grid-column: 1 / -1; }
.det-field-label {
  font-size: 0.65rem;
  font-weight: 600;
  color: var(--text-muted);
  text-transform: uppercase;
  letter-spacing: 0.04em;
}
.det-field-value { font-size: 0.78rem; color: var(--text-primary); word-break: break-all; line-height: 1.4; }
.det-mono { font-family: var(--font-mono); font-size: 0.74rem; color: var(--accent-cyan); }

.det-checklist { margin-top: 10px; }
.det-checklist-inner {
  background: var(--bg-card);
  border: 1px solid var(--border-primary);
  border-radius: var(--radius-md);
  padding: 14px;
  animation: fadeInContent 0.3s ease;
}
.det-checklist-title {
  font-size: 0.78rem;
  font-weight: 700;
  color: var(--text-secondary);
  margin-bottom: 10px;
  text-transform: uppercase;
  letter-spacing: 0.05em;
}
.det-checklist-grid { display: flex; flex-direction: column; gap: 8px; }
.det-check-item {
  display: flex;
  align-items: flex-start;
  gap: 10px;
  padding: 8px 10px;
  border-radius: var(--radius-sm);
  border: 1px solid transparent;
}
.det-check-item.check-pass { background: rgba(16,185,129,0.06); border-color: rgba(16,185,129,0.15); }
.det-check-item.check-fail { background: rgba(239,68,68,0.06);  border-color: rgba(239,68,68,0.15); }
.det-check-icon { font-size: 0.9rem; flex-shrink: 0; margin-top: 1px; }
.det-check-label { font-size: 0.8rem; font-weight: 600; color: var(--text-primary); line-height: 1.3; }
.det-check-detail { font-size: 0.73rem; color: var(--text-secondary); margin-top: 2px; line-height: 1.4; }

@media (max-width: 900px) {
  .det-tc-panels { grid-template-columns: 1fr; }
  .det-toolbar { flex-direction: column; align-items: stretch; }
}
"@

Add-Content -Path "css\styles.css" -Value $css -Encoding UTF8
Write-Host "SUCCESS: CSS appended" -ForegroundColor Green
