// ═══════════════════════════════════════════════════════════════════════
// Asset & Identity Context Engine
// Provides asset awareness and user context for detection accuracy
// ═══════════════════════════════════════════════════════════════════════

const ASSET_CATEGORIES = [
  {
    id: 'domain-controllers', name: 'Domain Controllers', icon: '🏛️', criticality: 'critical',
    description: 'Active Directory Domain Controllers — the most critical infrastructure in a Windows environment.',
    detectionContext: 'All authentication, replication, and AD service events must be monitored with maximum scrutiny.',
    keyMonitoring: ['LDAP queries', 'Kerberos events', 'Replication traffic', 'DC-to-DC communication', 'Group Policy changes'],
    expectedServices: ['NTDS', 'DNS', 'KDC', 'Netlogon', 'DFSR'],
    riskFactors: ['Single point of failure for authentication', 'Contains all domain credentials', 'Target for DCSync/Golden Ticket'],
    linkedCategories: ['active-directory', 'credential-access', 'lateral-movement'],
    count: '2-5 typical'
  },
  {
    id: 'web-servers', name: 'Web Servers', icon: '🌐', criticality: 'high',
    description: 'Public-facing and internal web application servers hosting business applications.',
    detectionContext: 'Monitor for web shell deployment, SQL injection, and command execution from web server processes.',
    keyMonitoring: ['HTTP access logs', 'Process creation from web services', 'File creation in web roots', 'Outbound connections'],
    expectedServices: ['IIS (w3wp.exe)', 'Apache (httpd)', 'Nginx', 'Tomcat (java.exe)'],
    riskFactors: ['Internet-exposed attack surface', 'Contains application secrets', 'Direct DB connectivity'],
    linkedCategories: ['web-attacks', 'initial-access'],
    count: '5-50 typical'
  },
  {
    id: 'database-servers', name: 'Database Servers', icon: '🗄️', criticality: 'critical',
    description: 'SQL Server, Oracle, PostgreSQL, and other database systems containing sensitive data.',
    detectionContext: 'Monitor for unusual query patterns, data bulk exports, credential access, and unauthorized administrative commands.',
    keyMonitoring: ['Database audit logs', 'Failed login attempts', 'Bulk data exports', 'Schema changes', 'Stored procedure modifications'],
    expectedServices: ['MSSQL', 'Oracle Listener', 'PostgreSQL', 'MySQL', 'MongoDB'],
    riskFactors: ['Contains customer/business data', 'SQL injection target', 'Data exfiltration source'],
    linkedCategories: ['data-exfiltration', 'web-attacks', 'credential-access'],
    count: '5-20 typical'
  },
  {
    id: 'workstations', name: 'Employee Workstations', icon: '💻', criticality: 'medium',
    description: 'End-user desktop and laptop computers used for daily business operations.',
    detectionContext: 'Primary target for phishing and malware. Monitor for unusual process execution, script-based attacks, and credential theft.',
    keyMonitoring: ['Process creation (Sysmon)', 'PowerShell logging', 'USB device connections', 'Browser downloads', 'Email client activity'],
    expectedServices: ['Windows Defender', 'EDR Agent', 'Sysmon', 'Office applications'],
    riskFactors: ['Phishing target', 'User error risk', 'Bridge between external and internal networks'],
    linkedCategories: ['email-threats', 'execution', 'endpoint-anomalies'],
    count: '100-10000+ typical'
  },
  {
    id: 'vpn-gateways', name: 'VPN / Remote Access', icon: '🔐', criticality: 'high',
    description: 'VPN concentrators, remote access gateways, and zero-trust network access points.',
    detectionContext: 'Critical entry point — monitor for brute force, credential stuffing, and unusual geographic logon patterns.',
    keyMonitoring: ['Authentication attempts', 'Geographic analysis', 'Session duration', 'Data transfer volumes', 'Concurrent sessions'],
    expectedServices: ['VPN service', 'RADIUS/LDAP auth', 'MFA service'],
    riskFactors: ['Internet-exposed', 'Primary remote entry point', 'Credential attack target'],
    linkedCategories: ['brute-force', 'initial-access'],
    count: '2-10 typical'
  },
  {
    id: 'email-servers', name: 'Email Infrastructure', icon: '📧', criticality: 'high',
    description: 'Exchange servers, email gateways, and mail transfer agents handling organizational email.',
    detectionContext: 'Monitor for phishing delivery, email forwarding rules, mailbox export, and NTLM relay attacks.',
    keyMonitoring: ['Mail flow logs', 'Inbox rule creation', 'OWA/EWS access', 'Admin activities', 'Transport rule changes'],
    expectedServices: ['Exchange', 'SMTP', 'IMAP/POP', 'EWS', 'OWA'],
    riskFactors: ['Phishing delivery vector', 'Contains sensitive communications', 'NTLM relay target'],
    linkedCategories: ['email-threats', 'initial-access', 'collection'],
    count: '2-10 typical'
  },
  {
    id: 'file-servers', name: 'File Servers', icon: '📁', criticality: 'high',
    description: 'Network file shares and document management servers storing organizational data.',
    detectionContext: 'Monitor for mass file access, unauthorized share enumeration, data staging, and ransomware encryption patterns.',
    keyMonitoring: ['SMB share access', 'File creation/modification rates', 'Access by unusual accounts', 'Large data copies'],
    expectedServices: ['SMB/CIFS', 'DFS', 'File screening (FSRM)'],
    riskFactors: ['Data exfiltration source', 'Ransomware encryption target', 'Lateral movement via admin shares'],
    linkedCategories: ['data-exfiltration', 'ransomware', 'lateral-movement'],
    count: '5-30 typical'
  },
  {
    id: 'cloud-infrastructure', name: 'Cloud Infrastructure', icon: '☁️', criticality: 'high',
    description: 'AWS, Azure, GCP resources including VMs, storage, and managed services.',
    detectionContext: 'Monitor for IAM changes, resource creation, storage access, and API anomalies.',
    keyMonitoring: ['CloudTrail/Activity Log', 'IAM changes', 'Storage access', 'Network changes', 'API anomalies'],
    expectedServices: ['Compute (EC2/VM)', 'Storage (S3/Blob)', 'IAM', 'Network (VPC)'],
    riskFactors: ['Misconfiguration exposure', 'Credential theft impact', 'Crypto mining target'],
    linkedCategories: ['cloud-threats', 'credential-access'],
    count: '10-500+ resources typical'
  },
  {
    id: 'security-infrastructure', name: 'Security Infrastructure', icon: '🛡️', criticality: 'critical',
    description: 'SIEM, EDR, firewalls, IDS/IPS, and other security tooling infrastructure.',
    detectionContext: 'Any tampering with security infrastructure is a critical indicator. Monitor for agent stops, configuration changes, and log source failures.',
    keyMonitoring: ['Agent health', 'Configuration changes', 'Log source connectivity', 'Rule modifications', 'Access to security consoles'],
    expectedServices: ['SIEM agents', 'EDR agents', 'IDS/IPS', 'Vulnerability scanners'],
    riskFactors: ['Single visibility point', 'Attacker priority target', 'Loss means blind spot'],
    linkedCategories: ['defense-evasion'],
    count: '10-100 typical'
  },
  {
    id: 'linux-servers', name: 'Linux Servers', icon: '🐧', criticality: 'high',
    description: 'Linux systems running web services, databases, and infrastructure components.',
    detectionContext: 'Monitor for SSH brute force, unauthorized cron jobs, rootkit indicators, and reverse shell connections.',
    keyMonitoring: ['SSH auth logs', 'Cron modifications', 'Process creation', 'SUID binaries', 'Network listeners'],
    expectedServices: ['SSH', 'Docker/K8s', 'Nginx/Apache', 'PostgreSQL/MySQL', 'Custom apps'],
    riskFactors: ['Persistence via cron/systemd', 'Rootkit installation', 'Reverse shell target'],
    linkedCategories: ['linux-threats', 'brute-force'],
    count: '10-200 typical'
  }
];

// ── Identity Risk Profiles ──
const IDENTITY_RISK_PROFILES = [
  {
    id: 'domain-admins', name: 'Domain Administrators', icon: '👑', riskLevel: 'critical',
    description: 'Accounts with full control over Active Directory domain. Compromise = full domain compromise.',
    monitoringPriority: 'Maximum — All activities must be logged and reviewed.',
    expectedBehavior: ['Login to DCs only', 'Using PAW (Privileged Access Workstation)', 'MFA enforced', 'No internet browsing'],
    anomalyIndicators: ['Login to non-DC workstation', 'Interactive session on non-PAW system', 'Off-hours usage', 'Logon from unexpected IP'],
    protection: ['Separate admin and daily-use accounts', 'PAW enforcement', 'Tiered access model', 'Just-in-time (JIT) access'],
    linkedCategories: ['active-directory', 'credential-access', 'privilege-escalation']
  },
  {
    id: 'service-accounts', name: 'Service Accounts', icon: '⚙️', riskLevel: 'high',
    description: 'Non-interactive accounts running applications and services. Often have elevated privileges and no MFA.',
    monitoringPriority: 'High — Monitor for interactive logon and credential theft.',
    expectedBehavior: ['Service-type logons only (Type 5)', 'Static source systems', 'Consistent logon patterns', 'No interactive sessions'],
    anomalyIndicators: ['Interactive logon (Type 2/10)', 'Login from new source', 'Kerberos TGT request', 'Password change'],
    protection: ['gMSA (Group Managed Service Accounts)', 'Regular password rotation', 'Deny interactive logon GPO', 'SPN management'],
    linkedCategories: ['credential-access', 'active-directory']
  },
  {
    id: 'executives', name: 'Executive / VIP Accounts', icon: '💼', riskLevel: 'high',
    description: 'C-suite and executive accounts — high-value targets for BEC and spear-phishing campaigns.',
    monitoringPriority: 'High — Enhanced email monitoring and login anomaly detection.',
    expectedBehavior: ['Standard business hours usage', 'Known devices/locations', 'Email access patterns'],
    anomalyIndicators: ['Email forwarding rules created', 'Unusual login locations', 'Bulk email export', 'Financial instruction emails'],
    protection: ['Enhanced phishing protection', 'Extra MFA controls', 'Executive mailbox monitoring', 'Anti-impersonation policies'],
    linkedCategories: ['email-threats', 'insider-threat']
  },
  {
    id: 'developers', name: 'Developer Accounts', icon: '👨‍💻', riskLevel: 'medium',
    description: 'Software developers with access to source code, build systems, and potentially production environments.',
    monitoringPriority: 'Medium — Monitor for code repository access and production system interaction.',
    expectedBehavior: ['IDE and Git usage', 'CI/CD pipeline activity', 'Known development tools', 'Standard dev hours'],
    anomalyIndicators: ['Direct production access bypass', 'Bulk code repository downloads', 'Unusual build pipeline modifications', 'Secrets/keys in commits'],
    protection: ['Separate dev/prod accounts', 'Code review requirements', 'Secret scanning', 'RBAC on repositories'],
    linkedCategories: ['insider-threat', 'cloud-threats']
  },
  {
    id: 'remote-workers', name: 'Remote / Home Workers', icon: '🏠', riskLevel: 'medium',
    description: 'Employees working remotely via VPN or cloud services — expanded attack surface due to home network exposure.',
    monitoringPriority: 'Medium — Focus on VPN session monitoring and endpoint compliance.',
    expectedBehavior: ['VPN connection from known ISPs/locations', 'Consistent device fingerprint', 'Business hours usage'],
    anomalyIndicators: ['VPN from new country', 'Concurrent sessions from different locations', 'Endpoint compliance failures', 'Unusual data access'],
    protection: ['Always-on VPN', 'Device compliance checks', 'Endpoint protection verification', 'Split-tunnel restrictions'],
    linkedCategories: ['brute-force', 'initial-access']
  },
  {
    id: 'third-party', name: 'Third-Party / Vendor Accounts', icon: '🤝', riskLevel: 'high',
    description: 'External vendor and contractor accounts with limited but often privileged access to specific systems.',
    monitoringPriority: 'High — All access must be monitored and time-bounded.',
    expectedBehavior: ['Access only during contract hours', 'Specific system access only', 'Known source IPs from vendor'],
    anomalyIndicators: ['Access outside contract hours', 'Systems beyond scope', 'New source IP/location', 'Account used after contract end'],
    protection: ['JIT provisioning', 'Automatic deprovisioning', 'Session recording', 'IP allowlisting'],
    linkedCategories: ['initial-access', 'insider-threat']
  }
];

function getAssetCategory(id) { return ASSET_CATEGORIES.find(a => a.id === id); }
function getIdentityProfile(id) { return IDENTITY_RISK_PROFILES.find(p => p.id === id); }
function getAssetsForCategory(catId) { return ASSET_CATEGORIES.filter(a => a.linkedCategories.includes(catId)); }
function getIdentitiesForCategory(catId) { return IDENTITY_RISK_PROFILES.filter(p => p.linkedCategories.includes(catId)); }

window.ASSET_CATEGORIES = ASSET_CATEGORIES;
window.IDENTITY_RISK_PROFILES = IDENTITY_RISK_PROFILES;
window.getAssetCategory = getAssetCategory;
window.getIdentityProfile = getIdentityProfile;
window.getAssetsForCategory = getAssetsForCategory;
window.getIdentitiesForCategory = getIdentitiesForCategory;
