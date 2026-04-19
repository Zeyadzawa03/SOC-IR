// ═══════════════════════════════════════════════════════════════════════
// Threat Intelligence Engine — Live CVE & KEV Integration
// Fetches from CISA KEV, NVD API, and maintains local CVE database
// Implements daily sync with localStorage caching
// ═══════════════════════════════════════════════════════════════════════

const ThreatIntelEngine = (() => {
  const CACHE_KEY = 'sigmaguard_threat_intel';
  const CACHE_TTL = 24 * 60 * 60 * 1000; // 24 hours
  const KEV_URL = 'https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json';
  const NVD_API = 'https://services.nvd.nist.gov/rest/json/cves/2.0';

  // ── Category Mapping for CVEs ──
  const CVE_CATEGORY_MAP = {
    'Remote Code Execution': 'execution',
    'SQL Injection': 'web-attacks',
    'Cross-Site Scripting': 'web-attacks',
    'Authentication Bypass': 'credential-access',
    'Privilege Escalation': 'privilege-escalation',
    'Path Traversal': 'web-attacks',
    'Command Injection': 'execution',
    'Deserialization': 'execution',
    'Buffer Overflow': 'execution',
    'Information Disclosure': 'reconnaissance',
    'Denial of Service': 'ransomware',
    'Memory Corruption': 'endpoint-anomalies',
    'Use After Free': 'endpoint-anomalies',
    'Directory Traversal': 'web-attacks',
    'Server-Side Request Forgery': 'web-attacks',
    'XML External Entity': 'web-attacks',
    'Improper Access Control': 'privilege-escalation',
    'Code Injection': 'execution',
    'Credential Theft': 'credential-access',
    'Lateral Movement': 'lateral-movement'
  };

  // ── MITRE ATT&CK Mapping for vulnerability types ──
  const CVE_MITRE_MAP = {
    'Remote Code Execution': { tacticId: 'TA0002', tacticName: 'Execution', techniqueId: 'T1203', techniqueName: 'Exploitation for Client Execution' },
    'SQL Injection': { tacticId: 'TA0001', tacticName: 'Initial Access', techniqueId: 'T1190', techniqueName: 'Exploit Public-Facing Application' },
    'Authentication Bypass': { tacticId: 'TA0001', tacticName: 'Initial Access', techniqueId: 'T1078', techniqueName: 'Valid Accounts' },
    'Privilege Escalation': { tacticId: 'TA0004', tacticName: 'Privilege Escalation', techniqueId: 'T1068', techniqueName: 'Exploitation for Privilege Escalation' },
    'Command Injection': { tacticId: 'TA0002', tacticName: 'Execution', techniqueId: 'T1059', techniqueName: 'Command and Scripting Interpreter' },
    'Deserialization': { tacticId: 'TA0002', tacticName: 'Execution', techniqueId: 'T1059', techniqueName: 'Command and Scripting Interpreter' },
    'Path Traversal': { tacticId: 'TA0007', tacticName: 'Discovery', techniqueId: 'T1083', techniqueName: 'File and Directory Discovery' },
    'Cross-Site Scripting': { tacticId: 'TA0001', tacticName: 'Initial Access', techniqueId: 'T1189', techniqueName: 'Drive-by Compromise' },
    'Server-Side Request Forgery': { tacticId: 'TA0001', tacticName: 'Initial Access', techniqueId: 'T1190', techniqueName: 'Exploit Public-Facing Application' },
    'Credential Theft': { tacticId: 'TA0006', tacticName: 'Credential Access', techniqueId: 'T1003', techniqueName: 'OS Credential Dumping' },
    'Information Disclosure': { tacticId: 'TA0007', tacticName: 'Discovery', techniqueId: 'T1082', techniqueName: 'System Information Discovery' }
  };

  // ── Get cached data ──
  function getCache() {
    try {
      const raw = localStorage.getItem(CACHE_KEY);
      if (!raw) return null;
      const cache = JSON.parse(raw);
      if (Date.now() - cache.timestamp > CACHE_TTL) return null;
      return cache;
    } catch { return null; }
  }

  function setCache(data) {
    try {
      localStorage.setItem(CACHE_KEY, JSON.stringify({
        timestamp: Date.now(),
        lastSync: new Date().toISOString(),
        ...data
      }));
    } catch (e) { console.warn('[ThreatIntel] Cache write failed:', e); }
  }

  // ── Fetch CISA KEV ──
  async function fetchKEV() {
    try {
      const resp = await fetch(KEV_URL);
      if (!resp.ok) throw new Error(`KEV fetch failed: ${resp.status}`);
      const data = await resp.json();
      return (data.vulnerabilities || []).map(v => ({
        cveId: v.cveID,
        vendor: v.vendorProject,
        product: v.product,
        name: v.vulnerabilityName,
        description: v.shortDescription,
        dateAdded: v.dateAdded,
        dueDate: v.dueDate,
        action: v.requiredAction,
        notes: v.notes || '',
        isKEV: true,
        source: 'CISA KEV'
      }));
    } catch (e) {
      console.warn('[ThreatIntel] KEV fetch error:', e);
      return [];
    }
  }

  // ── Fetch recent CVEs from NVD ──
  async function fetchNVD(daysBack = 30) {
    try {
      const startDate = new Date(Date.now() - daysBack * 86400000).toISOString().split('.')[0] + '.000';
      const url = `${NVD_API}?pubStartDate=${startDate}&resultsPerPage=50&cvssV3Severity=CRITICAL`;
      const resp = await fetch(url, { headers: { 'Accept': 'application/json' } });
      if (!resp.ok) throw new Error(`NVD fetch failed: ${resp.status}`);
      const data = await resp.json();
      return (data.vulnerabilities || []).map(v => {
        const cve = v.cve;
        const desc = (cve.descriptions || []).find(d => d.lang === 'en');
        const metrics = cve.metrics?.cvssMetricV31?.[0] || cve.metrics?.cvssMetricV30?.[0] || {};
        return {
          cveId: cve.id,
          description: desc?.value || 'No description available',
          published: cve.published,
          lastModified: cve.lastModified,
          cvssScore: metrics.cvssData?.baseScore || null,
          cvssSeverity: metrics.cvssData?.baseSeverity || 'UNKNOWN',
          cvssVector: metrics.cvssData?.vectorString || '',
          references: (cve.references || []).map(r => r.url),
          source: 'NVD'
        };
      });
    } catch (e) {
      console.warn('[ThreatIntel] NVD fetch error:', e);
      return [];
    }
  }

  // ── Map CVE to detection coverage ──
  function mapCVEToDetection(cve) {
    // Check if any existing Sigma rule references this CVE
    const rules = typeof SIGMA_RULES !== 'undefined' ? SIGMA_RULES : [];
    const linkedRules = rules.filter(r =>
      (r.threatIntel?.cves || []).includes(cve.cveId) ||
      (r.sigmaYaml || '').includes(cve.cveId) ||
      (r.description || '').includes(cve.cveId)
    );

    // Determine vulnerability type
    const vulnType = classifyVulnType(cve.description || cve.name || '');
    const mitre = CVE_MITRE_MAP[vulnType] || {};
    const category = CVE_CATEGORY_MAP[vulnType] || 'endpoint-anomalies';

    return {
      ...cve,
      vulnType,
      category,
      mitre,
      linkedRules: linkedRules.map(r => ({ id: r.id, title: r.title })),
      hasSigma: linkedRules.length > 0,
      hasSplunk: linkedRules.some(r => r.splunkQuery),
      hasQRadar: linkedRules.some(r => r.qradarQuery),
      hasMitre: !!mitre.tacticId,
      coverageStatus: linkedRules.length > 0 ? 'covered' : 'gap',
      severity: cve.cvssSeverity || (cve.isKEV ? 'CRITICAL' : 'HIGH')
    };
  }

  // ── Classify vulnerability type from description ──
  function classifyVulnType(text) {
    const t = text.toLowerCase();
    if (t.includes('remote code execution') || t.includes('rce')) return 'Remote Code Execution';
    if (t.includes('sql injection')) return 'SQL Injection';
    if (t.includes('cross-site scripting') || t.includes('xss')) return 'Cross-Site Scripting';
    if (t.includes('authentication bypass') || t.includes('auth bypass')) return 'Authentication Bypass';
    if (t.includes('privilege escalation') || t.includes('elevation of privilege')) return 'Privilege Escalation';
    if (t.includes('path traversal') || t.includes('directory traversal')) return 'Path Traversal';
    if (t.includes('command injection') || t.includes('os command')) return 'Command Injection';
    if (t.includes('deserialization')) return 'Deserialization';
    if (t.includes('buffer overflow') || t.includes('heap overflow')) return 'Buffer Overflow';
    if (t.includes('information disclosure') || t.includes('info leak')) return 'Information Disclosure';
    if (t.includes('denial of service') || t.includes('dos')) return 'Denial of Service';
    if (t.includes('ssrf') || t.includes('server-side request')) return 'Server-Side Request Forgery';
    if (t.includes('xxe') || t.includes('xml external')) return 'XML External Entity';
    if (t.includes('credential') || t.includes('password')) return 'Credential Theft';
    if (t.includes('improper access') || t.includes('access control')) return 'Improper Access Control';
    if (t.includes('memory corruption') || t.includes('use after free')) return 'Memory Corruption';
    if (t.includes('code injection') || t.includes('code exec')) return 'Code Injection';
    return 'Remote Code Execution'; // Default for high-severity
  }

  // ── Merge KEV + NVD data, deduplicate ──
  function mergeData(kevData, nvdData, staticData) {
    const merged = new Map();
    
    // Static data first (pre-loaded)
    (staticData || []).forEach(c => merged.set(c.cveId, c));
    
    // NVD data
    nvdData.forEach(c => {
      if (merged.has(c.cveId)) {
        const existing = merged.get(c.cveId);
        merged.set(c.cveId, { ...existing, ...c, isKEV: existing.isKEV || false });
      } else {
        merged.set(c.cveId, c);
      }
    });
    
    // KEV data (enrichment layer)
    kevData.forEach(k => {
      if (merged.has(k.cveId)) {
        const existing = merged.get(k.cveId);
        merged.set(k.cveId, { ...existing, isKEV: true, kevDateAdded: k.dateAdded, kevAction: k.action, vendor: k.vendor, product: k.product });
      } else {
        merged.set(k.cveId, { ...k, isKEV: true, cvssSeverity: 'CRITICAL' });
      }
    });

    return Array.from(merged.values()).map(mapCVEToDetection);
  }

  // ── Public API ──
  return {
    async sync(forceRefresh = false) {
      const cache = getCache();
      if (cache && !forceRefresh) {
        console.log('[ThreatIntel] Using cached data from', cache.lastSync);
        return cache.cves || [];
      }

      console.log('[ThreatIntel] Starting sync...');
      const [kevData, nvdData] = await Promise.allSettled([fetchKEV(), fetchNVD(30)]);
      
      const kev = kevData.status === 'fulfilled' ? kevData.value : [];
      const nvd = nvdData.status === 'fulfilled' ? nvdData.value : [];
      const staticCVEs = typeof STATIC_CVE_DATA !== 'undefined' ? STATIC_CVE_DATA : [];
      
      const merged = mergeData(kev, nvd, staticCVEs);
      
      // Sort: KEV first, then by severity, then by date
      merged.sort((a, b) => {
        if (a.isKEV && !b.isKEV) return -1;
        if (!a.isKEV && b.isKEV) return 1;
        const sevOrder = { CRITICAL: 0, HIGH: 1, MEDIUM: 2, LOW: 3, UNKNOWN: 4 };
        const aDiff = (sevOrder[a.severity] || 4) - (sevOrder[b.severity] || 4);
        if (aDiff !== 0) return aDiff;
        return new Date(b.published || b.dateAdded || 0) - new Date(a.published || a.dateAdded || 0);
      });

      setCache({ cves: merged, kevCount: kev.length, nvdCount: nvd.length });
      console.log(`[ThreatIntel] Synced: ${kev.length} KEV, ${nvd.length} NVD, ${merged.length} total`);
      return merged;
    },

    getLastSync() {
      const cache = getCache();
      return cache ? cache.lastSync : null;
    },

    getCacheStats() {
      const cache = getCache();
      if (!cache) return { cached: false };
      return {
        cached: true,
        lastSync: cache.lastSync,
        kevCount: cache.kevCount || 0,
        nvdCount: cache.nvdCount || 0,
        totalCVEs: (cache.cves || []).length,
        coveredCount: (cache.cves || []).filter(c => c.hasSigma).length,
        gapCount: (cache.cves || []).filter(c => !c.hasSigma).length,
        kevExploited: (cache.cves || []).filter(c => c.isKEV).length
      };
    },

    clearCache() {
      localStorage.removeItem(CACHE_KEY);
    },

    // Schedule daily refresh
    scheduleDailySync() {
      // Check every hour if 24h has passed
      setInterval(async () => {
        const cache = getCache();
        if (!cache) {
          await this.sync(true);
        }
      }, 60 * 60 * 1000); // Check hourly
    }
  };
})();

// Auto-start daily sync scheduler
if (typeof window !== 'undefined') {
  ThreatIntelEngine.scheduleDailySync();
}
