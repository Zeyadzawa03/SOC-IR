// ═══════════════════════════════════════════════════════════════════════
// Correlation Engine — Rule Correlation & Risk Scoring
// Combines multiple detections for risk-based prioritization
// ═══════════════════════════════════════════════════════════════════════

const CORRELATION_RULES = [
  {
    id: 'CR-001',
    name: 'Brute Force → Successful Login',
    description: 'Multiple failed logins followed by a successful login from the same source IP indicates a successful credential compromise.',
    riskScore: 95,
    severity: 'critical',
    category: 'credential-compromise',
    linkedDetections: ['SR-0004', 'SR-0005'],
    conditions: [
      { type: 'threshold', field: 'EventID:4625', operator: '>=', value: 10, window: '5m', description: '10+ failed logins in 5 minutes' },
      { type: 'followed_by', field: 'EventID:4624', window: '30m', description: 'Followed by successful login within 30 minutes' },
      { type: 'same_field', field: 'SourceIP', description: 'From the same source IP address' }
    ],
    mitre: ['T1110', 'T1078'],
    responsePlaybook: 'brute-force',
    splunkCorrelation: `index=wineventlog (EventCode=4625 OR EventCode=4624)
| stats count(eval(EventCode=4625)) as failures count(eval(EventCode=4624)) as successes by IpAddress
| where failures >= 10 AND successes >= 1
| eval risk_score=95`,
    qradarCorrelation: `-- QRadar Offense Rule:
-- When: EventID 4625 count >= 10 in 5 minutes from same source
-- Followed by: EventID 4624 from same source within 30 minutes
-- Action: Create offense with severity HIGH`
  },
  {
    id: 'CR-002',
    name: 'Process Execution → Network Connection → Data Transfer',
    description: 'Suspicious process execution followed by outbound network connection and significant data transfer suggests C2 establishment and data exfiltration.',
    riskScore: 90,
    severity: 'critical',
    category: 'c2-exfiltration',
    linkedDetections: ['SR-0006', 'SR-0007'],
    conditions: [
      { type: 'detection', rule: 'SR-0006', description: 'Suspicious PowerShell or script execution detected' },
      { type: 'followed_by', field: 'NetworkConnection', window: '10m', description: 'Outbound network connection within 10 minutes' },
      { type: 'threshold', field: 'BytesSent', operator: '>=', value: 10485760, window: '30m', description: '10MB+ outbound data in 30 minutes' },
      { type: 'same_field', field: 'Hostname', description: 'All on the same endpoint' }
    ],
    mitre: ['T1059.001', 'T1071', 'T1041'],
    responsePlaybook: 'command-control',
    splunkCorrelation: `index=sysmon EventCode=1 (Image="*powershell*" OR Image="*cmd.exe*")
| join host [search index=sysmon EventCode=3 Initiated=true DestinationPort IN (443,80,8080,8443)]
| join host [search index=proxy bytes_out>10485760]
| stats count by host, User, Image
| eval risk_score=90`,
    qradarCorrelation: `-- QRadar Building Block + Offense Rule:
-- BB1: PowerShell/CMD execution from Sysmon
-- BB2: Outbound connection within 10min from same host
-- BB3: Large data transfer > 10MB within 30min
-- Rule: When BB1 AND BB2 AND BB3 → Offense severity CRITICAL`
  },
  {
    id: 'CR-003',
    name: 'Lateral Movement Chain',
    description: 'Authentication on remote system followed by remote service installation and process execution indicates active lateral movement.',
    riskScore: 85,
    severity: 'high',
    category: 'lateral-movement',
    linkedDetections: ['SR-0008', 'SR-0013'],
    conditions: [
      { type: 'detection', field: 'EventID:4624:Type3', description: 'Network logon to remote system' },
      { type: 'followed_by', field: 'EventID:7045', window: '5m', description: 'Service installed within 5 minutes' },
      { type: 'followed_by', field: 'Process:cmd|powershell', window: '5m', description: 'Command execution on target' },
      { type: 'same_field', field: 'TargetUsername', description: 'Same account used across systems' }
    ],
    mitre: ['T1021.002', 'T1543.003', 'T1059'],
    responsePlaybook: 'lateral-movement',
    splunkCorrelation: `index=wineventlog EventCode=4624 LogonType=3
| join TargetUserName [search index=wineventlog EventCode=7045]
| join ComputerName [search index=sysmon EventCode=1 (Image="*cmd.exe" OR Image="*powershell*")]
| stats count by TargetUserName, SourceNetworkAddress, ComputerName
| eval risk_score=85`,
    qradarCorrelation: `-- QRadar Rule Chain:
-- Event 1: Type 3 logon (4624)
-- Event 2: Service install (7045) within 5 min, same host
-- Event 3: Process creation (cmd/powershell) within 5 min, same host
-- Action: Create HIGH severity offense`
  },
  {
    id: 'CR-004',
    name: 'Credential Access → Privilege Escalation → Persistence',
    description: 'LSASS access followed by privilege escalation and persistence mechanism installation indicates a full compromise chain.',
    riskScore: 95,
    severity: 'critical',
    category: 'full-compromise',
    linkedDetections: ['SR-0022', 'SR-0009', 'SR-0011'],
    conditions: [
      { type: 'detection', field: 'LSASS_Access', description: 'LSASS memory access detected' },
      { type: 'followed_by', field: 'PrivEsc', window: '30m', description: 'Privilege escalation within 30 minutes' },
      { type: 'followed_by', field: 'Persistence', window: '60m', description: 'Persistence mechanism installed within 60 minutes' },
      { type: 'same_field', field: 'Hostname', description: 'All on the same system' }
    ],
    mitre: ['T1003.001', 'T1068', 'T1547.001'],
    responsePlaybook: 'credential-access',
    splunkCorrelation: `index=sysmon EventCode=10 TargetImage="*lsass.exe"
| join host [search index=sysmon EventCode=1 IntegrityLevel=System User!=SYSTEM]
| join host [search index=sysmon EventCode=13 TargetObject="*\\\\Run\\\\*"]
| stats count by host
| eval risk_score=95`,
    qradarCorrelation: `-- Multi-event correlation:
-- Stage 1: LSASS access (Sysmon 10)
-- Stage 2: SYSTEM process from non-SYSTEM user
-- Stage 3: Registry Run key modification
-- All same host within 1 hour → CRITICAL offense`
  },
  {
    id: 'CR-005',
    name: 'Reconnaissance → Credential Theft → Lateral Movement',
    description: 'Discovery commands followed by credential harvesting and subsequent lateral movement suggests an active intrusion.',
    riskScore: 90,
    severity: 'critical',
    category: 'active-intrusion',
    linkedDetections: ['SR-0007', 'SR-0022', 'SR-0031'],
    conditions: [
      { type: 'threshold', field: 'ReconCommands', operator: '>=', value: 3, window: '10m', description: '3+ recon commands in 10 minutes' },
      { type: 'followed_by', field: 'CredentialAccess', window: '30m', description: 'Credential theft within 30 minutes' },
      { type: 'followed_by', field: 'LateralMovement', window: '60m', description: 'Lateral movement within 60 minutes' }
    ],
    mitre: ['T1082', 'T1003', 'T1021'],
    responsePlaybook: 'lateral-movement',
    splunkCorrelation: `-- Multi-stage correlation
index=sysmon EventCode=1 CommandLine IN ("*whoami*","*net user*","*systeminfo*","*ipconfig*")
| bin _time span=10m
| stats dc(CommandLine) as recon_cmds by host, User, _time
| where recon_cmds >= 3`,
    qradarCorrelation: `-- QRadar Rule Sequence:
-- Stage 1: 3+ discovery commands in 10 min
-- Stage 2: LSASS access or credential tool detection
-- Stage 3: Type 3/10 logon to new system
-- Action: CRITICAL offense with full event chain`
  },
  {
    id: 'CR-006',
    name: 'Pre-Ransomware Preparation',
    description: 'Shadow copy deletion combined with backup service stops and security tool disabling indicates imminent ransomware deployment.',
    riskScore: 99,
    severity: 'critical',
    category: 'ransomware-preparation',
    linkedDetections: ['SR-0020', 'SR-0035'],
    conditions: [
      { type: 'detection', field: 'VSSDelete', description: 'Shadow copy deletion detected (vssadmin delete shadows)' },
      { type: 'detection', field: 'BackupStop', description: 'Backup services stopped', window: '30m' },
      { type: 'detection', field: 'AVDisable', description: 'Security tools disabled or tampered', window: '30m' }
    ],
    mitre: ['T1490', 'T1489', 'T1562.001'],
    responsePlaybook: 'ransomware',
    splunkCorrelation: `index=sysmon EventCode=1
| where match(CommandLine, "(?i)(vssadmin.*delete|bcdedit.*recovery|wbadmin.*delete)")
  OR match(CommandLine, "(?i)(sc stop|net stop).*(vss|backup|sql)")
  OR match(CommandLine, "(?i)(Set-MpPreference.*Disable|sc stop.*defender)")
| stats count values(CommandLine) as commands by Computer, User
| where count >= 2
| eval risk_score=99`,
    qradarCorrelation: `-- CRITICAL ALERT: Pre-Ransomware Detection
-- Any 2 of: VSS delete, backup stop, AV disable
-- Within 30 minutes on same host
-- Action: IMMEDIATE CRITICAL offense, auto-isolate if possible`
  },
  {
    id: 'CR-007',
    name: 'Phishing → Execution → C2',
    description: 'Email attachment opened, spawning suspicious process, followed by C2 communication. Complete phishing kill chain.',
    riskScore: 88,
    severity: 'high',
    category: 'phishing-chain',
    linkedDetections: ['SR-0001', 'SR-0006'],
    conditions: [
      { type: 'detection', field: 'EmailAttachment', description: 'Email client spawns child process' },
      { type: 'followed_by', field: 'SuspiciousProcess', window: '5m', description: 'Suspicious process execution' },
      { type: 'followed_by', field: 'C2Connection', window: '15m', description: 'Outbound C2 communication' }
    ],
    mitre: ['T1566.001', 'T1204.002', 'T1071'],
    responsePlaybook: 'email-threats',
    splunkCorrelation: `index=sysmon EventCode=1
  ParentImage IN ("*outlook.exe","*thunderbird.exe")
  Image IN ("*powershell*","*cmd.exe","*wscript*","*mshta*")
| join host [search index=sysmon EventCode=3 Initiated=true DestinationPort IN (443,80,8080)]
| stats count by host, User, ParentImage, Image
| eval risk_score=88`,
    qradarCorrelation: `-- Kill Chain Detection:
-- Stage 1: Outlook/Thunderbird spawns script interpreter
-- Stage 2: Outbound network connection from spawned process
-- Action: HIGH offense, quarantine email`
  },
  {
    id: 'CR-008',
    name: 'Account Compromise Indicator',
    description: 'Off-hours login from unusual location with new device fingerprint indicates compromised credentials.',
    riskScore: 75,
    severity: 'high',
    category: 'account-compromise',
    linkedDetections: ['SR-0005'],
    conditions: [
      { type: 'anomaly', field: 'LoginTime', description: 'Login outside normal business hours' },
      { type: 'anomaly', field: 'GeoLocation', description: 'Login from unusual geographic location' },
      { type: 'anomaly', field: 'DeviceFingerprint', description: 'New or unknown device/user agent' }
    ],
    mitre: ['T1078', 'T1133'],
    responsePlaybook: 'brute-force',
    splunkCorrelation: `index=wineventlog EventCode=4624 LogonType IN (2,10)
| iplocation IpAddress
| stats count by TargetUserName, City, Country
| eventstats dc(City) as unique_cities by TargetUserName
| where unique_cities > 2
| eval risk_score=75`,
    qradarCorrelation: `-- Anomaly-based rule:
-- Login outside baseline hours
-- New source IP/location for user
-- Action: Create medium-high offense`
  },
  {
    id: 'CR-009',
    name: 'Data Staging → Exfiltration',
    description: 'Archive files created in staging directories followed by large outbound data transfer indicates planned exfiltration.',
    riskScore: 85,
    severity: 'high',
    category: 'data-theft',
    linkedDetections: [],
    conditions: [
      { type: 'detection', field: 'ArchiveCreation', description: 'ZIP/RAR/7z created in temp/staging directory' },
      { type: 'followed_by', field: 'LargeTransfer', window: '60m', description: 'Large outbound transfer within 1 hour' },
      { type: 'same_field', field: 'Hostname', description: 'Same system' }
    ],
    mitre: ['T1074.001', 'T1048'],
    responsePlaybook: 'data-exfiltration',
    splunkCorrelation: `index=sysmon EventCode=11
| where match(TargetFilename, "(?i)\\.(zip|rar|7z)$")
| where match(TargetFilename, "(?i)(Temp|Downloads|Desktop|Public)")
| join host [search index=proxy bytes_out>52428800]
| eval risk_score=85`,
    qradarCorrelation: `-- Stage 1: Archive file creation in staging directory
-- Stage 2: Large outbound transfer from same host
-- Within 1 hour
-- Action: HIGH offense`
  },
  {
    id: 'CR-010',
    name: 'Webshell Deployment → Post-Exploitation',
    description: 'Web server spawning command interpreter followed by discovery and lateral movement commands indicates webshell-based intrusion.',
    riskScore: 93,
    severity: 'critical',
    category: 'web-compromise',
    linkedDetections: ['SR-0003'],
    conditions: [
      { type: 'detection', field: 'WebshellExecution', description: 'Web server process spawns cmd/powershell' },
      { type: 'followed_by', field: 'Discovery', window: '10m', description: 'Discovery commands executed' },
      { type: 'followed_by', field: 'LateralMovement', window: '30m', description: 'Lateral movement attempt' }
    ],
    mitre: ['T1190', 'T1505.003', 'T1082'],
    responsePlaybook: 'web-attacks',
    splunkCorrelation: `index=sysmon EventCode=1
  ParentImage IN ("*w3wp.exe","*httpd.exe","*nginx.exe","*tomcat*")
  Image IN ("*cmd.exe","*powershell*","*whoami*")
| bin _time span=10m
| stats count values(CommandLine) as cmds by host, _time
| where count >= 2
| eval risk_score=93`,
    qradarCorrelation: `-- Web compromise chain:
-- Stage 1: Web server spawns command shell
-- Stage 2: Recon commands within 10 min
-- Stage 3: Type 3 logon to another system
-- Action: CRITICAL offense, isolate web server`
  }
];

// ── Risk Score Calculator ──
function calculateRiskScore(detections, assetCriticality) {
  const critMultiplier = { critical: 1.5, high: 1.2, medium: 1.0, low: 0.8 };
  let baseScore = 0;
  detections.forEach(d => {
    const sevScore = { critical: 40, high: 30, medium: 20, low: 10 }[d.severity] || 10;
    baseScore += sevScore;
  });
  const normalizedScore = Math.min(baseScore, 100);
  const assetMultiplied = normalizedScore * (critMultiplier[assetCriticality] || 1.0);
  return Math.min(Math.round(assetMultiplied), 100);
}

// ── Get related correlation rules for a detection ──
function getCorrelationsForRule(ruleId) {
  return CORRELATION_RULES.filter(cr => cr.linkedDetections.includes(ruleId));
}

// ── Get correlation rules by category ──
function getCorrelationsByCategory(category) {
  return CORRELATION_RULES.filter(cr => cr.category === category);
}

window.CORRELATION_RULES = CORRELATION_RULES;
window.calculateRiskScore = calculateRiskScore;
window.getCorrelationsForRule = getCorrelationsForRule;
window.getCorrelationsByCategory = getCorrelationsByCategory;
