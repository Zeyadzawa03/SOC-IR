// ══════════════════════════════════════════════════════════════
// MULTI-SIEM VALIDATION ENGINE — SigmaGuard v5.0
// Validates Sigma YAML + Splunk SPL + QRadar AQL + Wazuh KQL
// ══════════════════════════════════════════════════════════════
'use strict';

const ValidationEngine = (() => {
  const REQUIRED_SIGMA_FIELDS = ['title:','logsource:','detection:','condition:'];
  const SPL_PATTERNS = ['index=','sourcetype=','stats ','table ','where ','search ','eval '];
  const AQL_PATTERNS = ['SELECT','FROM events','WHERE','GROUP BY','ORDER BY'];

  // ─── Sigma YAML Validator ───────────────────────────────────
  function validateSigma(rule) {
    const issues = [];
    const y = rule.sigmaYaml || '';
    if (!y || y.length < 50) { issues.push('Missing or empty Sigma YAML'); return { status:'invalid', issues, score:0 }; }
    REQUIRED_SIGMA_FIELDS.forEach(f => { if (!y.includes(f)) issues.push(`Missing required field: ${f.replace(':','')}`); });
    if (!rule.techniqueId || !rule.techniqueId.match(/^T\d{4}/)) issues.push('Invalid or missing MITRE technique ID');
    if (!rule.category) issues.push('Missing category assignment');
    if (!rule.severity || !['low','medium','high','critical'].includes(rule.severity)) issues.push('Invalid severity level');
    if (!rule.detectionExplanation || rule.detectionExplanation.length < 20) issues.push('Detection explanation missing or too short');
    if (!rule.requiredLogs || rule.requiredLogs.length === 0) issues.push('No required logs specified');
    if (!rule.responseActions || rule.responseActions.length === 0) issues.push('No response actions specified');
    if (!rule.falsePositives || rule.falsePositives.length === 0) issues.push('No false positives documented');
    const score = Math.max(0, 100 - (issues.length * 12));
    return { status: issues.length === 0 ? 'valid' : (score >= 60 ? 'warning' : 'invalid'), issues, score };
  }

  // ─── Splunk SPL Validator ───────────────────────────────────
  function validateSplunk(rule) {
    const issues = [];
    const spl = rule.splunkQuery || '';
    if (!spl || spl.length < 30) { issues.push('No Splunk SPL query defined'); return { status:'missing', issues, score:0, alignment:0 }; }
    if (spl.includes('Conversion Failed')) { issues.push('Splunk conversion failed — fallback query'); return { status:'fallback', issues, score:30, alignment:0 }; }
    const hasPattern = SPL_PATTERNS.some(p => spl.toLowerCase().includes(p.toLowerCase()));
    if (!hasPattern) issues.push('SPL lacks standard query patterns (index=, stats, table, where)');
    // Keyword alignment with Sigma
    const kw = extractSigmaKeywords(rule.sigmaYaml || '');
    const overlap = kw.filter(k => spl.toLowerCase().includes(k.toLowerCase())).length;
    const alignment = kw.length > 0 ? Math.round((overlap / kw.length) * 100) : 80;
    if (alignment < 20 && kw.length > 3) issues.push(`Low keyword alignment with Sigma YAML (${alignment}%)`);
    // Check for impossible logic
    const eventCodes = (spl.match(/EventCode=(\d+)/g) || []).map(m => m.replace('EventCode=', ''));
    if (eventCodes.length > 1 && new Set(eventCodes).size > 1) {
      const hasOr = spl.includes(' OR ') && spl.includes('EventCode');
      if (!hasOr) issues.push('Multiple different EventCodes without OR — possible impossible logic');
    }
    const score = Math.max(0, 100 - (issues.length * 15));
    return { status: issues.length === 0 ? 'valid' : 'warning', issues, score, alignment };
  }

  // ─── QRadar AQL Validator ───────────────────────────────────
  function validateQRadar(rule) {
    const issues = [];
    const aql = rule.qradarQuery || '';
    if (!aql || aql.length < 30) { issues.push('No QRadar AQL query defined'); return { status:'missing', issues, score:0, alignment:0 }; }
    if (aql.includes('Conversion Failed')) { issues.push('QRadar conversion failed — fallback query'); return { status:'fallback', issues, score:30, alignment:0 }; }
    const hasSelect = aql.toUpperCase().includes('SELECT');
    const hasFrom = aql.toUpperCase().includes('FROM');
    const hasWhere = aql.toUpperCase().includes('WHERE');
    if (!hasSelect) issues.push('AQL missing SELECT clause');
    if (!hasFrom) issues.push('AQL missing FROM clause');
    if (!hasWhere) issues.push('AQL missing WHERE clause');
    const kw = extractSigmaKeywords(rule.sigmaYaml || '');
    const overlap = kw.filter(k => aql.toLowerCase().includes(k.toLowerCase())).length;
    const alignment = kw.length > 0 ? Math.round((overlap / kw.length) * 100) : 80;
    if (alignment < 20 && kw.length > 3) issues.push(`Low keyword alignment with Sigma YAML (${alignment}%)`);
    const score = Math.max(0, 100 - (issues.length * 15));
    return { status: issues.length === 0 ? 'valid' : 'warning', issues, score, alignment };
  }

  // ─── Wazuh KQL Validator ────────────────────────────────────
  function validateWazuh(rule) {
    const issues = [];
    let wazuh = '';
    try { wazuh = typeof SigmaConverter !== 'undefined' ? SigmaConverter.toWazuh(rule) : ''; } catch(e) { wazuh = ''; }
    if (!wazuh || wazuh.length < 10) { issues.push('Empty Wazuh query output'); return { status:'empty', issues, score:0 }; }
    if (wazuh.includes('Conversion Failed: Correlation')) {
      return { status:'correlation_required', issues:['Multi-event correlation — requires Wazuh decoders/rules'], score:50 };
    }
    if (wazuh.includes('Conversion Failed')) {
      issues.push('Wazuh conversion failed'); return { status:'failed', issues, score:20 };
    }
    if (wazuh === '*') { issues.push('Wazuh query is wildcard only'); return { status:'too_broad', issues, score:15 }; }
    // Check for meaningful content
    if (!wazuh.includes(':') && !wazuh.includes('AND') && !wazuh.includes('OR')) {
      issues.push('Wazuh query lacks structured search operators');
    }
    const score = Math.max(0, 100 - (issues.length * 20));
    return { status: issues.length === 0 ? 'valid' : 'warning', issues, score };
  }

  // ─── Cross-SIEM Consistency ─────────────────────────────────
  function checkCrossConsistency(rule) {
    const issues = [];
    const spl = rule.splunkQuery || '';
    const aql = rule.qradarQuery || '';
    let wazuh = '';
    try { wazuh = typeof SigmaConverter !== 'undefined' ? SigmaConverter.toWazuh(rule) : ''; } catch(e) {}
    const kw = extractSigmaKeywords(rule.sigmaYaml || '');
    const splHits = kw.filter(k => spl.toLowerCase().includes(k.toLowerCase())).length;
    const aqlHits = kw.filter(k => aql.toLowerCase().includes(k.toLowerCase())).length;
    const wzHits = kw.filter(k => wazuh.toLowerCase().includes(k.toLowerCase())).length;
    // Check for significant divergence
    if (kw.length > 2) {
      if (spl && aql && Math.abs(splHits - aqlHits) > kw.length * 0.5) {
        issues.push('Significant keyword divergence between Splunk and QRadar queries');
      }
    }
    const hasSpl = spl.length > 30;
    const hasAql = aql.length > 30;
    const hasWz = wazuh.length > 10 && !wazuh.includes('Conversion Failed');
    if (hasSpl && !hasAql) issues.push('Splunk query exists but QRadar is missing');
    if (hasAql && !hasSpl) issues.push('QRadar query exists but Splunk is missing');
    const coverage = [hasSpl, hasAql, hasWz].filter(Boolean).length;
    const score = Math.round((coverage / 3) * 100);
    return { status: issues.length === 0 ? 'consistent' : 'divergent', issues, score, coverage };
  }

  // ─── Full Rule Validation ───────────────────────────────────
  function validateRule(rule) {
    const sigma = validateSigma(rule);
    const splunk = validateSplunk(rule);
    const qradar = validateQRadar(rule);
    const wazuh = validateWazuh(rule);
    const cross = checkCrossConsistency(rule);
    const scores = [sigma.score, splunk.score, qradar.score, wazuh.score, cross.score];
    const confidenceScore = Math.round(scores.reduce((a,b) => a+b, 0) / scores.length);
    let overallStatus = 'accepted';
    if (confidenceScore < 40) overallStatus = 'rejected';
    else if (confidenceScore < 70) overallStatus = 'needs_review';
    return {
      ruleId: rule.id, ruleTitle: rule.title, category: rule.category,
      sigma, splunk, qradar, wazuh, crossConsistency: cross,
      overallStatus, confidenceScore
    };
  }

  // ─── Validate All Rules ─────────────────────────────────────
  function validateAll() {
    const rules = typeof SIGMA_RULES !== 'undefined' ? SIGMA_RULES : [];
    return rules.map(r => validateRule(r));
  }

  // ─── Summary Statistics ─────────────────────────────────────
  function getSummary() {
    const results = validateAll();
    const summary = {
      totalRules: results.length,
      accepted: results.filter(r => r.overallStatus === 'accepted').length,
      needsReview: results.filter(r => r.overallStatus === 'needs_review').length,
      rejected: results.filter(r => r.overallStatus === 'rejected').length,
      avgConfidence: Math.round(results.reduce((a,r) => a+r.confidenceScore, 0) / (results.length||1)),
      sigmaValid: results.filter(r => r.sigma.status === 'valid').length,
      splunkValid: results.filter(r => r.splunk.status === 'valid').length,
      qradarValid: results.filter(r => r.qradar.status === 'valid').length,
      wazuhValid: results.filter(r => r.wazuh.status === 'valid').length,
      wazuhCorrelation: results.filter(r => r.wazuh.status === 'correlation_required').length,
      crossConsistent: results.filter(r => r.crossConsistency.status === 'consistent').length,
      byCategory: {}
    };
    results.forEach(r => {
      if (!summary.byCategory[r.category]) summary.byCategory[r.category] = { total:0, accepted:0, avgScore:0, scores:[] };
      const cat = summary.byCategory[r.category];
      cat.total++;
      if (r.overallStatus === 'accepted') cat.accepted++;
      cat.scores.push(r.confidenceScore);
    });
    Object.values(summary.byCategory).forEach(cat => {
      cat.avgScore = Math.round(cat.scores.reduce((a,b) => a+b, 0) / (cat.scores.length||1));
      delete cat.scores;
    });
    return summary;
  }

  // ─── Helpers ────────────────────────────────────────────────
  function extractSigmaKeywords(yaml) {
    const eids = (yaml.match(/\d{4,5}/g) || []).slice(0, 5);
    const quoted = (yaml.match(/'([^']{3,30})'/g) || []).map(s => s.replace(/'/g, '')).slice(0, 8);
    return [...new Set([...eids, ...quoted])];
  }

  function getConfidenceLabel(score) {
    if (score >= 85) return { label:'Extreme', cls:'confidence-extreme' };
    if (score >= 70) return { label:'High', cls:'confidence-high' };
    if (score >= 50) return { label:'Medium', cls:'confidence-medium' };
    return { label:'Low', cls:'confidence-low' };
  }

  function getStatusIcon(status) {
    const map = { valid:'✅', accepted:'✅', warning:'⚠️', needs_review:'⚠️', missing:'❌', invalid:'❌',
      rejected:'❌', fallback:'🔄', correlation_required:'🔗', empty:'❌', failed:'❌', too_broad:'⚠️',
      consistent:'✅', divergent:'⚠️' };
    return map[status] || '❓';
  }

  return { validateRule, validateAll, getSummary, getConfidenceLabel, getStatusIcon, validateSigma, validateSplunk, validateQRadar, validateWazuh, checkCrossConsistency };
})();

window.ValidationEngine = ValidationEngine;
console.log('[SigmaGuard] Multi-SIEM Validation Engine loaded');
