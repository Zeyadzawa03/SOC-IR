// ═══════════════════════════════════════════════════════════════════════
// Correlation Engine v2.0 — Decision Logic, Entity Tracking & Incidents
// Full detection-to-incident lifecycle within SigmaGuard
// ═══════════════════════════════════════════════════════════════════════

// ──────────────────────────────────────────────
// 1. CORRELATION RULES (Extended with Decision Logic)
// ──────────────────────────────────────────────

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
    decisionLogic: {
      singleEvent: {
        trigger: 'EventID:4625',
        condition: 'count >= 5 within 5m from same SourceIP',
        action: 'CREATE_ALERT',
        severity: 'medium',
        label: 'Brute Force Attempt Detected'
      },
      multiEvent: [
        {
          name: 'Brute Force → Account Compromise',
          conditions: [
            'EventID:4625 count >= 10 within 5m from same SourceIP',
            'THEN EventID:4624 from same SourceIP within 30m'
          ],
          timeWindow: '35m',
          action: 'ESCALATE_TO_INCIDENT',
          severity: 'critical',
          verdict: 'Possible account compromise — password likely guessed'
        },
        {
          name: 'Distributed Brute Force',
          conditions: [
            'EventID:4625 count >= 50 within 10m',
            'Unique SourceIP count >= 5',
            'Same TargetUserName'
          ],
          timeWindow: '10m',
          action: 'ESCALATE_TO_INCIDENT',
          severity: 'critical',
          verdict: 'Distributed credential stuffing attack'
        }
      ],
      entityCorrelation: {
        trackFields: ['SourceIP', 'TargetUserName', 'Hostname'],
        aggregation: 'group_by SourceIP, TargetUserName',
        riskAccumulation: 'additive',
        threshold: 75
      }
    },
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
    decisionLogic: {
      singleEvent: {
        trigger: 'SuspiciousProcess',
        condition: 'ParentImage matches script interpreter AND CommandLine contains encoded/download patterns',
        action: 'CREATE_ALERT',
        severity: 'high',
        label: 'Suspicious Process Execution'
      },
      multiEvent: [
        {
          name: 'C2 Establishment Chain',
          conditions: [
            'Suspicious process execution detected',
            'THEN outbound connection to non-whitelisted IP within 10m',
            'THEN BytesSent >= 10MB within 30m'
          ],
          timeWindow: '40m',
          action: 'ESCALATE_TO_INCIDENT',
          severity: 'critical',
          verdict: 'C2 channel established with active data exfiltration'
        }
      ],
      entityCorrelation: {
        trackFields: ['Hostname', 'DestinationIP', 'User'],
        aggregation: 'group_by Hostname',
        riskAccumulation: 'multiplicative',
        threshold: 80
      }
    },
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
    decisionLogic: {
      singleEvent: {
        trigger: 'EventID:4624:LogonType3',
        condition: 'Network logon from non-server asset',
        action: 'LOG_OBSERVATION',
        severity: 'low',
        label: 'Network Logon Observed'
      },
      multiEvent: [
        {
          name: 'Full Lateral Movement Chain',
          conditions: [
            'Type 3 logon to remote system',
            'THEN service installed (7045) on target within 5m',
            'THEN cmd/powershell executed on target within 5m'
          ],
          timeWindow: '15m',
          action: 'ESCALATE_TO_INCIDENT',
          severity: 'high',
          verdict: 'Active lateral movement with remote code execution'
        },
        {
          name: 'Multi-Host Lateral Sweep',
          conditions: [
            'Same account authenticates to 3+ unique hosts within 30m',
            'LogonType = 3 or 10'
          ],
          timeWindow: '30m',
          action: 'ESCALATE_TO_INCIDENT',
          severity: 'critical',
          verdict: 'Lateral movement sweep across multiple hosts'
        }
      ],
      entityCorrelation: {
        trackFields: ['TargetUserName', 'SourceHostname', 'DestinationHostname'],
        aggregation: 'group_by TargetUserName, count unique DestinationHostname',
        riskAccumulation: 'additive',
        threshold: 70
      }
    },
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
    decisionLogic: {
      singleEvent: {
        trigger: 'LSASS_Access',
        condition: 'Sysmon EventID 10 targeting lsass.exe with suspicious access mask',
        action: 'CREATE_ALERT',
        severity: 'critical',
        label: 'Credential Dumping Attempt'
      },
      multiEvent: [
        {
          name: 'Full Compromise Chain',
          conditions: [
            'LSASS memory access detected',
            'THEN privilege escalation to SYSTEM within 30m',
            'THEN persistence mechanism (Run key / service / task) within 60m'
          ],
          timeWindow: '90m',
          action: 'ESCALATE_TO_INCIDENT',
          severity: 'critical',
          verdict: 'Full system compromise — credential theft + persistence established'
        }
      ],
      entityCorrelation: {
        trackFields: ['Hostname', 'User', 'ProcessName'],
        aggregation: 'group_by Hostname',
        riskAccumulation: 'multiplicative',
        threshold: 90
      }
    },
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
    decisionLogic: {
      singleEvent: {
        trigger: 'ReconCommand',
        condition: 'whoami|net user|systeminfo|ipconfig executed by non-admin user',
        action: 'LOG_OBSERVATION',
        severity: 'low',
        label: 'Reconnaissance Activity'
      },
      multiEvent: [
        {
          name: 'Full Intrusion Kill Chain',
          conditions: [
            '3+ recon commands within 10m from same host',
            'THEN credential access tool or LSASS access within 30m',
            'THEN lateral movement (Type3 logon to new host) within 60m'
          ],
          timeWindow: '100m',
          action: 'ESCALATE_TO_INCIDENT',
          severity: 'critical',
          verdict: 'Active intrusion — recon, credential theft, and lateral movement confirmed'
        }
      ],
      entityCorrelation: {
        trackFields: ['Hostname', 'User', 'SourceIP'],
        aggregation: 'group_by User, track across Hostnames',
        riskAccumulation: 'additive',
        threshold: 80
      }
    },
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
    decisionLogic: {
      singleEvent: {
        trigger: 'VSSDelete',
        condition: 'vssadmin delete shadows OR bcdedit /set recoveryenabled no',
        action: 'CREATE_ALERT',
        severity: 'critical',
        label: 'Shadow Copy Deletion — Possible Ransomware Prep'
      },
      multiEvent: [
        {
          name: 'Ransomware Deployment Imminent',
          conditions: [
            'Shadow copy deletion OR backup deletion',
            'AND backup/recovery services stopped within 30m',
            'AND security tools disabled within 30m'
          ],
          timeWindow: '30m',
          action: 'EMERGENCY_INCIDENT',
          severity: 'critical',
          verdict: 'IMMINENT RANSOMWARE — isolate all affected systems immediately'
        }
      ],
      entityCorrelation: {
        trackFields: ['Hostname', 'User'],
        aggregation: 'group_by Hostname',
        riskAccumulation: 'immediate_max',
        threshold: 95
      }
    },
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
    decisionLogic: {
      singleEvent: {
        trigger: 'EmailClientChildProcess',
        condition: 'outlook.exe or thunderbird.exe spawns script interpreter',
        action: 'CREATE_ALERT',
        severity: 'high',
        label: 'Phishing Attachment Execution'
      },
      multiEvent: [
        {
          name: 'Complete Phishing Kill Chain',
          conditions: [
            'Email client spawns child process',
            'THEN suspicious download/execution within 5m',
            'THEN outbound C2 traffic within 15m'
          ],
          timeWindow: '20m',
          action: 'ESCALATE_TO_INCIDENT',
          severity: 'high',
          verdict: 'Phishing attack succeeded — payload executed with C2 established'
        }
      ],
      entityCorrelation: {
        trackFields: ['User', 'Hostname', 'DestinationIP'],
        aggregation: 'group_by User, Hostname',
        riskAccumulation: 'additive',
        threshold: 70
      }
    },
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
    decisionLogic: {
      singleEvent: {
        trigger: 'AnomalousLogin',
        condition: 'Login outside business hours OR from unusual geolocation',
        action: 'CREATE_ALERT',
        severity: 'medium',
        label: 'Anomalous Login Detected'
      },
      multiEvent: [
        {
          name: 'Compromised Account Confirmed',
          conditions: [
            'Login from unusual geolocation',
            'AND login outside business hours',
            'AND new device fingerprint never seen for this user'
          ],
          timeWindow: '1h',
          action: 'ESCALATE_TO_INCIDENT',
          severity: 'high',
          verdict: 'Account credentials likely compromised — unusual access pattern'
        },
        {
          name: 'Impossible Travel',
          conditions: [
            'Login from GeoA',
            'THEN login from GeoB within time impossible for travel',
            'Distance > 500km in < 1h'
          ],
          timeWindow: '1h',
          action: 'ESCALATE_TO_INCIDENT',
          severity: 'critical',
          verdict: 'Impossible travel detected — concurrent use from multiple locations'
        }
      ],
      entityCorrelation: {
        trackFields: ['TargetUserName', 'SourceIP', 'GeoLocation'],
        aggregation: 'group_by TargetUserName, track GeoLocation diversity',
        riskAccumulation: 'additive',
        threshold: 65
      }
    },
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
    decisionLogic: {
      singleEvent: {
        trigger: 'ArchiveCreation',
        condition: 'ZIP/RAR/7z file created in Temp, Downloads, Desktop, or Public directory',
        action: 'LOG_OBSERVATION',
        severity: 'low',
        label: 'Archive File Created in Staging Directory'
      },
      multiEvent: [
        {
          name: 'Data Exfiltration Chain',
          conditions: [
            'Archive file created in staging directory',
            'THEN outbound transfer > 50MB within 60m from same host',
            'Destination IP not in whitelist'
          ],
          timeWindow: '60m',
          action: 'ESCALATE_TO_INCIDENT',
          severity: 'high',
          verdict: 'Data exfiltration in progress — staged archives being transmitted'
        }
      ],
      entityCorrelation: {
        trackFields: ['Hostname', 'User', 'DestinationIP'],
        aggregation: 'group_by Hostname, sum BytesSent',
        riskAccumulation: 'additive',
        threshold: 70
      }
    },
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
    decisionLogic: {
      singleEvent: {
        trigger: 'WebServerChildProcess',
        condition: 'w3wp.exe or httpd.exe or nginx.exe spawns cmd.exe or powershell.exe',
        action: 'CREATE_ALERT',
        severity: 'critical',
        label: 'Webshell Execution Detected'
      },
      multiEvent: [
        {
          name: 'Webshell Post-Exploitation Chain',
          conditions: [
            'Web server spawns command interpreter',
            'THEN discovery commands (whoami, net user, etc) within 10m',
            'THEN lateral movement (Type 3 logon to new host) within 30m'
          ],
          timeWindow: '40m',
          action: 'ESCALATE_TO_INCIDENT',
          severity: 'critical',
          verdict: 'Web server compromised — attacker conducting post-exploitation'
        }
      ],
      entityCorrelation: {
        trackFields: ['Hostname', 'WebServerProcess', 'User'],
        aggregation: 'group_by Hostname',
        riskAccumulation: 'immediate_max',
        threshold: 85
      }
    },
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


// ──────────────────────────────────────────────
// 2. DECISION ENGINE
// ──────────────────────────────────────────────

class DecisionEngine {
  constructor() {
    this.eventBuffer = [];
    this.alerts = [];
    this.maxBufferSize = 10000;
    this.evaluationLog = [];
  }

  // Process an incoming event against all correlation rules
  evaluateEvent(event) {
    this.eventBuffer.push({ ...event, _ingestTime: Date.now() });
    if (this.eventBuffer.length > this.maxBufferSize) {
      this.eventBuffer = this.eventBuffer.slice(-this.maxBufferSize / 2);
    }

    const results = [];

    for (const rule of CORRELATION_RULES) {
      if (!rule.decisionLogic) continue;

      // 1) Check single-event triggers
      const singleResult = this._evaluateSingleEvent(rule, event);
      if (singleResult) {
        results.push(singleResult);
        this.evaluationLog.push({
          timestamp: new Date().toISOString(),
          ruleId: rule.id,
          type: 'single_event',
          result: singleResult.action,
          event: event
        });
      }

      // 2) Check multi-event triggers
      const multiResults = this._evaluateMultiEvent(rule, event);
      multiResults.forEach(mr => {
        results.push(mr);
        this.evaluationLog.push({
          timestamp: new Date().toISOString(),
          ruleId: rule.id,
          type: 'multi_event',
          result: mr.action,
          event: event
        });
      });
    }

    return results;
  }

  _evaluateSingleEvent(rule, event) {
    const logic = rule.decisionLogic.singleEvent;
    if (!logic) return null;

    // Check if event type matches the trigger
    const triggerMatch = this._matchesTrigger(event, logic.trigger);
    if (!triggerMatch) return null;

    return {
      ruleId: rule.id,
      ruleName: rule.name,
      type: 'single_event',
      action: logic.action,
      severity: logic.severity,
      label: logic.label,
      condition: logic.condition,
      event: event,
      timestamp: new Date().toISOString()
    };
  }

  _evaluateMultiEvent(rule, event) {
    const multiLogic = rule.decisionLogic.multiEvent;
    if (!multiLogic || !multiLogic.length) return [];

    const results = [];

    for (const scenario of multiLogic) {
      const windowMs = this._parseTimeWindow(scenario.timeWindow);
      const cutoff = Date.now() - windowMs;
      const windowEvents = this.eventBuffer.filter(e => e._ingestTime >= cutoff);

      // Check if the current event + buffered events satisfy all conditions
      const conditionsMet = this._checkMultiConditions(scenario.conditions, windowEvents, event, rule);

      if (conditionsMet) {
        results.push({
          ruleId: rule.id,
          ruleName: rule.name,
          type: 'multi_event',
          scenarioName: scenario.name,
          action: scenario.action,
          severity: scenario.severity,
          verdict: scenario.verdict,
          conditions: scenario.conditions,
          matchedEvents: windowEvents.slice(-5),
          timestamp: new Date().toISOString()
        });
      }
    }

    return results;
  }

  _matchesTrigger(event, trigger) {
    if (!trigger || !event) return false;
    const t = trigger.toLowerCase();
    const eventType = (event.eventType || event.type || '').toLowerCase();
    const eventId = (event.eventId || event.EventID || '').toString().toLowerCase();
    return eventType.includes(t) || eventId.includes(t) ||
           t.includes(eventType) || t.includes(eventId);
  }

  _parseTimeWindow(window) {
    if (!window) return 3600000;
    const match = window.match(/(\d+)\s*(m|h|s|min|hr)/i);
    if (!match) return 3600000;
    const val = parseInt(match[1]);
    const unit = match[2].toLowerCase();
    if (unit === 's') return val * 1000;
    if (unit === 'm' || unit === 'min') return val * 60 * 1000;
    if (unit === 'h' || unit === 'hr') return val * 3600 * 1000;
    return val * 60 * 1000;
  }

  _checkMultiConditions(conditions, windowEvents, currentEvent, rule) {
    if (!conditions || conditions.length === 0) return false;
    if (windowEvents.length < 2) return false;

    // For simulation: check if events in window cover different stages
    const eventTypes = new Set(windowEvents.map(e => (e.eventType || e.type || '').toLowerCase()));
    return eventTypes.size >= Math.min(conditions.length, 2);
  }

  getEvaluationLog() {
    return this.evaluationLog.slice(-50);
  }

  clearBuffer() {
    this.eventBuffer = [];
    this.evaluationLog = [];
  }
}


// ──────────────────────────────────────────────
// 3. ENTITY TRACKER
// ──────────────────────────────────────────────

class EntityTracker {
  constructor() {
    // entityProfiles: { 'ip:10.0.0.5': { type, id, detections[], riskScore, firstSeen, lastSeen } }
    this.entityProfiles = {};
    this.entityRelations = []; // { entityA, entityB, relation, detection }
  }

  trackEntity(type, id, detection) {
    const key = `${type}:${id}`;
    if (!this.entityProfiles[key]) {
      this.entityProfiles[key] = {
        type,
        id,
        key,
        detections: [],
        riskScore: 0,
        firstSeen: detection.timestamp || new Date().toISOString(),
        lastSeen: detection.timestamp || new Date().toISOString(),
        alertCount: 0,
        incidentCount: 0
      };
    }
    const profile = this.entityProfiles[key];
    profile.detections.push(detection);
    profile.lastSeen = detection.timestamp || new Date().toISOString();
    profile.alertCount = profile.detections.length;
    profile.riskScore = this._calculateEntityRisk(profile);
    return profile;
  }

  _calculateEntityRisk(profile) {
    let score = 0;
    const sevPoints = { critical: 30, high: 20, medium: 10, low: 5 };
    profile.detections.forEach(d => {
      score += sevPoints[d.severity] || 5;
    });
    return Math.min(score, 100);
  }

  getEntityProfile(type, id) {
    return this.entityProfiles[`${type}:${id}`] || null;
  }

  getAllEntities() {
    return Object.values(this.entityProfiles);
  }

  getEntitiesByType(type) {
    return Object.values(this.entityProfiles).filter(e => e.type === type);
  }

  getHighRiskEntities(threshold = 50) {
    return Object.values(this.entityProfiles)
      .filter(e => e.riskScore >= threshold)
      .sort((a, b) => b.riskScore - a.riskScore);
  }

  addRelation(entityA, entityB, relation, detection) {
    this.entityRelations.push({ entityA, entityB, relation, detection, timestamp: new Date().toISOString() });
  }

  getRelatedEntities(type, id) {
    const key = `${type}:${id}`;
    return this.entityRelations
      .filter(r => r.entityA === key || r.entityB === key)
      .map(r => r.entityA === key ? r.entityB : r.entityA);
  }

  getEntityCount() {
    return Object.keys(this.entityProfiles).length;
  }
}


// ──────────────────────────────────────────────
// 4. INCIDENT MANAGER
// ──────────────────────────────────────────────

class IncidentManager {
  constructor() {
    this.incidents = [];
    this.nextId = 1;
  }

  createIncident(correlatedAlerts, rule) {
    const incident = {
      id: `INC-${String(this.nextId++).padStart(4, '0')}`,
      title: rule ? rule.name : 'Correlated Incident',
      description: rule ? rule.description : 'Multiple alerts correlated into incident',
      status: 'new',
      severity: this._getMaxSeverity(correlatedAlerts),
      riskScore: rule ? rule.riskScore : this._calculateIncidentRisk(correlatedAlerts),
      phase: 'detection',
      alerts: [...correlatedAlerts],
      correlationRule: rule ? rule.id : null,
      entities: this._extractEntities(correlatedAlerts),
      mitre: rule ? rule.mitre : [],
      timeline: [{
        timestamp: new Date().toISOString(),
        action: 'Incident created',
        detail: `${correlatedAlerts.length} alerts correlated`,
        type: 'creation'
      }],
      responsePlaybook: rule ? rule.responsePlaybook : null,
      createdAt: new Date().toISOString(),
      updatedAt: new Date().toISOString(),
      assignee: null,
      verdict: correlatedAlerts[0]?.verdict || null
    };
    this.incidents.push(incident);
    return incident;
  }

  updateIncident(incidentId, newAlerts) {
    const incident = this.incidents.find(i => i.id === incidentId);
    if (!incident) return null;
    incident.alerts.push(...newAlerts);
    incident.updatedAt = new Date().toISOString();
    incident.timeline.push({
      timestamp: new Date().toISOString(),
      action: 'New evidence added',
      detail: `${newAlerts.length} new alerts correlated`,
      type: 'update'
    });
    incident.riskScore = Math.min(incident.riskScore + 5, 100);
    return incident;
  }

  updateStatus(incidentId, status, note) {
    const incident = this.incidents.find(i => i.id === incidentId);
    if (!incident) return null;
    const phases = { 'new': 'detection', 'investigating': 'analysis', 'contained': 'containment', 'eradicated': 'eradication', 'resolved': 'recovery', 'closed': 'lessons_learned' };
    incident.status = status;
    incident.phase = phases[status] || incident.phase;
    incident.updatedAt = new Date().toISOString();
    incident.timeline.push({
      timestamp: new Date().toISOString(),
      action: `Status → ${status}`,
      detail: note || '',
      type: 'status_change'
    });
    return incident;
  }

  getIncident(id) {
    return this.incidents.find(i => i.id === id);
  }

  getAllIncidents() {
    return [...this.incidents].sort((a, b) => new Date(b.createdAt) - new Date(a.createdAt));
  }

  getActiveIncidents() {
    return this.incidents.filter(i => !['resolved', 'closed'].includes(i.status));
  }

  getIncidentTimeline(id) {
    const incident = this.incidents.find(i => i.id === id);
    return incident ? incident.timeline : [];
  }

  _getMaxSeverity(alerts) {
    const order = { critical: 0, high: 1, medium: 2, low: 3 };
    let best = 'low';
    alerts.forEach(a => {
      if ((order[a.severity] || 3) < (order[best] || 3)) best = a.severity;
    });
    return best;
  }

  _calculateIncidentRisk(alerts) {
    let score = 0;
    alerts.forEach(a => {
      score += { critical: 35, high: 25, medium: 15, low: 5 }[a.severity] || 5;
    });
    return Math.min(score, 100);
  }

  _extractEntities(alerts) {
    const entities = new Set();
    alerts.forEach(a => {
      if (a.event) {
        if (a.event.sourceIP) entities.add(`ip:${a.event.sourceIP}`);
        if (a.event.user) entities.add(`user:${a.event.user}`);
        if (a.event.hostname) entities.add(`host:${a.event.hostname}`);
      }
    });
    return [...entities];
  }
}


// ──────────────────────────────────────────────
// 5. ATTACK PATTERN DETECTOR
// ──────────────────────────────────────────────

class AttackPatternDetector {
  constructor() {
    this.killChainPhases = [
      { id: 'recon', name: 'Reconnaissance', tactics: ['TA0043'], icon: '🔎', order: 1 },
      { id: 'weaponize', name: 'Weaponization', tactics: [], icon: '⚒️', order: 2 },
      { id: 'delivery', name: 'Delivery', tactics: ['TA0001'], icon: '📧', order: 3 },
      { id: 'exploit', name: 'Exploitation', tactics: ['TA0002'], icon: '💥', order: 4 },
      { id: 'install', name: 'Installation', tactics: ['TA0003'], icon: '📌', order: 5 },
      { id: 'c2', name: 'Command & Control', tactics: ['TA0011'], icon: '📡', order: 6 },
      { id: 'action', name: 'Actions on Objectives', tactics: ['TA0040', 'TA0010', 'TA0009'], icon: '🎯', order: 7 }
    ];

    this.attackChains = [
      { id: 'apt-intrusion', name: 'APT Intrusion', phases: ['recon', 'delivery', 'exploit', 'install', 'c2', 'action'], severity: 'critical' },
      { id: 'ransomware-attack', name: 'Ransomware Attack', phases: ['delivery', 'exploit', 'install', 'action'], severity: 'critical' },
      { id: 'insider-theft', name: 'Insider Data Theft', phases: ['recon', 'action'], severity: 'high' },
      { id: 'credential-compromise', name: 'Credential Compromise', phases: ['delivery', 'exploit', 'c2'], severity: 'high' }
    ];
  }

  detectPatterns(detections) {
    const detectedPhases = new Set();

    detections.forEach(d => {
      if (!d.mitre) return;
      const tactics = Array.isArray(d.mitre) ? d.mitre : [d.mitre];
      tactics.forEach(t => {
        this.killChainPhases.forEach(phase => {
          if (phase.tactics.includes(t)) detectedPhases.add(phase.id);
        });
      });
    });

    // Match against known attack chains
    const matchedPatterns = [];
    this.attackChains.forEach(chain => {
      const matched = chain.phases.filter(p => detectedPhases.has(p));
      const coverage = (matched.length / chain.phases.length) * 100;
      if (coverage >= 30) {
        matchedPatterns.push({
          ...chain,
          matchedPhases: matched,
          totalPhases: chain.phases.length,
          coverage: Math.round(coverage),
          missingPhases: chain.phases.filter(p => !detectedPhases.has(p))
        });
      }
    });

    return matchedPatterns.sort((a, b) => b.coverage - a.coverage);
  }

  getKillChainStatus(detections) {
    return this.killChainPhases.map(phase => {
      const detected = detections.some(d => {
        const tactics = Array.isArray(d.mitre) ? d.mitre : [d.mitre || ''];
        return phase.tactics.some(t => tactics.includes(t));
      });
      return { ...phase, detected };
    });
  }
}


// ──────────────────────────────────────────────
// 6. SIMULATION DATA — Sample Events
// ──────────────────────────────────────────────

const SIMULATION_SCENARIOS = [
  {
    id: 'SIM-001',
    name: 'Brute Force → Account Compromise',
    description: 'Simulates 15 failed logins followed by a successful login from the same IP — triggers CR-001.',
    correlationRule: 'CR-001',
    severity: 'critical',
    events: [
      { eventId: '4625', eventType: 'FailedLogin', sourceIP: '185.220.101.42', user: 'admin', hostname: 'DC01', timestamp: '2025-01-15T02:14:00Z', severity: 'medium' },
      { eventId: '4625', eventType: 'FailedLogin', sourceIP: '185.220.101.42', user: 'admin', hostname: 'DC01', timestamp: '2025-01-15T02:14:05Z', severity: 'medium' },
      { eventId: '4625', eventType: 'FailedLogin', sourceIP: '185.220.101.42', user: 'admin', hostname: 'DC01', timestamp: '2025-01-15T02:14:10Z', severity: 'medium' },
      { eventId: '4625', eventType: 'FailedLogin', sourceIP: '185.220.101.42', user: 'admin', hostname: 'DC01', timestamp: '2025-01-15T02:14:15Z', severity: 'medium' },
      { eventId: '4625', eventType: 'FailedLogin', sourceIP: '185.220.101.42', user: 'admin', hostname: 'DC01', timestamp: '2025-01-15T02:14:20Z', severity: 'medium' },
      { eventId: '4625', eventType: 'FailedLogin', sourceIP: '185.220.101.42', user: 'admin', hostname: 'DC01', timestamp: '2025-01-15T02:14:25Z', severity: 'medium' },
      { eventId: '4625', eventType: 'FailedLogin', sourceIP: '185.220.101.42', user: 'admin', hostname: 'DC01', timestamp: '2025-01-15T02:14:30Z', severity: 'medium' },
      { eventId: '4625', eventType: 'FailedLogin', sourceIP: '185.220.101.42', user: 'admin', hostname: 'DC01', timestamp: '2025-01-15T02:14:35Z', severity: 'medium' },
      { eventId: '4625', eventType: 'FailedLogin', sourceIP: '185.220.101.42', user: 'admin', hostname: 'DC01', timestamp: '2025-01-15T02:14:40Z', severity: 'medium' },
      { eventId: '4625', eventType: 'FailedLogin', sourceIP: '185.220.101.42', user: 'admin', hostname: 'DC01', timestamp: '2025-01-15T02:14:45Z', severity: 'medium' },
      { eventId: '4625', eventType: 'FailedLogin', sourceIP: '185.220.101.42', user: 'admin', hostname: 'DC01', timestamp: '2025-01-15T02:14:50Z', severity: 'medium' },
      { eventId: '4625', eventType: 'FailedLogin', sourceIP: '185.220.101.42', user: 'admin', hostname: 'DC01', timestamp: '2025-01-15T02:14:55Z', severity: 'medium' },
      { eventId: '4625', eventType: 'FailedLogin', sourceIP: '185.220.101.42', user: 'admin', hostname: 'DC01', timestamp: '2025-01-15T02:15:00Z', severity: 'medium' },
      { eventId: '4625', eventType: 'FailedLogin', sourceIP: '185.220.101.42', user: 'admin', hostname: 'DC01', timestamp: '2025-01-15T02:15:05Z', severity: 'medium' },
      { eventId: '4625', eventType: 'FailedLogin', sourceIP: '185.220.101.42', user: 'admin', hostname: 'DC01', timestamp: '2025-01-15T02:15:10Z', severity: 'medium' },
      { eventId: '4624', eventType: 'SuccessfulLogin', sourceIP: '185.220.101.42', user: 'admin', hostname: 'DC01', timestamp: '2025-01-15T02:30:00Z', severity: 'high' }
    ]
  },
  {
    id: 'SIM-002',
    name: 'Phishing → Execution → C2',
    description: 'Simulates a user opening a phishing attachment, spawning PowerShell, then establishing C2 — triggers CR-007.',
    correlationRule: 'CR-007',
    severity: 'high',
    events: [
      { eventId: '1', eventType: 'EmailClientChildProcess', sourceIP: '10.0.1.50', user: 'jsmith', hostname: 'WS-042', parentProcess: 'outlook.exe', process: 'cmd.exe', timestamp: '2025-01-15T09:30:00Z', severity: 'high' },
      { eventId: '1', eventType: 'SuspiciousProcess', sourceIP: '10.0.1.50', user: 'jsmith', hostname: 'WS-042', parentProcess: 'cmd.exe', process: 'powershell.exe', commandLine: 'powershell -enc aQBlAHgA...', timestamp: '2025-01-15T09:31:00Z', severity: 'high' },
      { eventId: '3', eventType: 'C2Connection', sourceIP: '10.0.1.50', user: 'jsmith', hostname: 'WS-042', destinationIP: '91.215.85.17', destinationPort: 443, timestamp: '2025-01-15T09:33:00Z', severity: 'critical' }
    ]
  },
  {
    id: 'SIM-003',
    name: 'Pre-Ransomware Preparation',
    description: 'Simulates shadow copy deletion + backup stop + AV disable — triggers CR-006 EMERGENCY.',
    correlationRule: 'CR-006',
    severity: 'critical',
    events: [
      { eventId: '1', eventType: 'VSSDelete', sourceIP: '10.0.2.10', user: 'svc-backup', hostname: 'FS-001', process: 'vssadmin.exe', commandLine: 'vssadmin delete shadows /all /quiet', timestamp: '2025-01-15T23:45:00Z', severity: 'critical' },
      { eventId: '1', eventType: 'BackupStop', sourceIP: '10.0.2.10', user: 'svc-backup', hostname: 'FS-001', process: 'sc.exe', commandLine: 'sc stop vss', timestamp: '2025-01-15T23:46:00Z', severity: 'high' },
      { eventId: '1', eventType: 'AVDisable', sourceIP: '10.0.2.10', user: 'svc-backup', hostname: 'FS-001', process: 'powershell.exe', commandLine: 'Set-MpPreference -DisableRealtimeMonitoring $true', timestamp: '2025-01-15T23:47:00Z', severity: 'critical' }
    ]
  },
  {
    id: 'SIM-004',
    name: 'Lateral Movement Chain',
    description: 'Simulates network logon → service install → command execution on remote host — triggers CR-003.',
    correlationRule: 'CR-003',
    severity: 'high',
    events: [
      { eventId: '4624', eventType: 'NetworkLogon', sourceIP: '10.0.1.50', user: 'admin', hostname: 'SVR-DB01', logonType: 3, timestamp: '2025-01-15T14:20:00Z', severity: 'low' },
      { eventId: '7045', eventType: 'ServiceInstall', sourceIP: '10.0.1.50', user: 'admin', hostname: 'SVR-DB01', serviceName: 'SecurityUpdate', servicePath: 'C:\\Temp\\payload.exe', timestamp: '2025-01-15T14:22:00Z', severity: 'high' },
      { eventId: '1', eventType: 'RemoteExecution', sourceIP: '10.0.1.50', user: 'admin', hostname: 'SVR-DB01', process: 'cmd.exe', commandLine: 'cmd.exe /c whoami & net user & ipconfig', timestamp: '2025-01-15T14:23:00Z', severity: 'high' }
    ]
  },
  {
    id: 'SIM-005',
    name: 'Full Intrusion — Recon → Creds → Lateral',
    description: 'Simulates discovery commands, LSASS dump, and lateral movement to new host — triggers CR-005.',
    correlationRule: 'CR-005',
    severity: 'critical',
    events: [
      { eventId: '1', eventType: 'ReconCommand', sourceIP: '10.0.1.50', user: 'jdoe', hostname: 'WS-101', process: 'cmd.exe', commandLine: 'whoami /all', timestamp: '2025-01-15T10:00:00Z', severity: 'low' },
      { eventId: '1', eventType: 'ReconCommand', sourceIP: '10.0.1.50', user: 'jdoe', hostname: 'WS-101', process: 'cmd.exe', commandLine: 'net user /domain', timestamp: '2025-01-15T10:01:00Z', severity: 'low' },
      { eventId: '1', eventType: 'ReconCommand', sourceIP: '10.0.1.50', user: 'jdoe', hostname: 'WS-101', process: 'cmd.exe', commandLine: 'nltest /dclist:', timestamp: '2025-01-15T10:02:00Z', severity: 'low' },
      { eventId: '1', eventType: 'ReconCommand', sourceIP: '10.0.1.50', user: 'jdoe', hostname: 'WS-101', process: 'cmd.exe', commandLine: 'systeminfo', timestamp: '2025-01-15T10:03:00Z', severity: 'low' },
      { eventId: '10', eventType: 'LSASS_Access', sourceIP: '10.0.1.50', user: 'jdoe', hostname: 'WS-101', process: 'rundll32.exe', targetProcess: 'lsass.exe', timestamp: '2025-01-15T10:20:00Z', severity: 'critical' },
      { eventId: '4624', eventType: 'LateralMovement', sourceIP: '10.0.1.50', user: 'jdoe', hostname: 'SVR-FILE01', logonType: 3, timestamp: '2025-01-15T10:45:00Z', severity: 'high' }
    ]
  }
];


// ──────────────────────────────────────────────
// 7. PRE-POPULATED SAMPLE DATA
// ──────────────────────────────────────────────

function initializeSampleData(engine, entityTracker, incidentManager) {
  // Pre-populate entity tracker with sample data
  const sampleEntities = [
    { type: 'ip', id: '185.220.101.42', detections: [
      { ruleId: 'CR-001', severity: 'critical', label: 'Brute Force Source', timestamp: '2025-01-15T02:14:00Z' },
      { ruleId: 'CR-001', severity: 'critical', label: 'Successful Login After Brute Force', timestamp: '2025-01-15T02:30:00Z' }
    ]},
    { type: 'ip', id: '91.215.85.17', detections: [
      { ruleId: 'CR-007', severity: 'high', label: 'C2 Communication Detected', timestamp: '2025-01-15T09:33:00Z' }
    ]},
    { type: 'ip', id: '10.0.1.50', detections: [
      { ruleId: 'CR-003', severity: 'high', label: 'Lateral Movement Source', timestamp: '2025-01-15T14:20:00Z' },
      { ruleId: 'CR-005', severity: 'critical', label: 'Intrusion Origin', timestamp: '2025-01-15T10:00:00Z' }
    ]},
    { type: 'user', id: 'admin', detections: [
      { ruleId: 'CR-001', severity: 'critical', label: 'Brute Force Target', timestamp: '2025-01-15T02:14:00Z' },
      { ruleId: 'CR-003', severity: 'high', label: 'Lateral Movement Actor', timestamp: '2025-01-15T14:20:00Z' }
    ]},
    { type: 'user', id: 'jsmith', detections: [
      { ruleId: 'CR-007', severity: 'high', label: 'Phishing Victim', timestamp: '2025-01-15T09:30:00Z' }
    ]},
    { type: 'user', id: 'jdoe', detections: [
      { ruleId: 'CR-005', severity: 'critical', label: 'Compromised Account', timestamp: '2025-01-15T10:00:00Z' },
      { ruleId: 'CR-005', severity: 'critical', label: 'Credential Theft Actor', timestamp: '2025-01-15T10:20:00Z' }
    ]},
    { type: 'user', id: 'svc-backup', detections: [
      { ruleId: 'CR-006', severity: 'critical', label: 'Ransomware Preparation Actor', timestamp: '2025-01-15T23:45:00Z' }
    ]},
    { type: 'host', id: 'DC01', detections: [
      { ruleId: 'CR-001', severity: 'critical', label: 'Brute Force Target Host', timestamp: '2025-01-15T02:14:00Z' }
    ]},
    { type: 'host', id: 'WS-042', detections: [
      { ruleId: 'CR-007', severity: 'high', label: 'Phishing Execution Host', timestamp: '2025-01-15T09:30:00Z' }
    ]},
    { type: 'host', id: 'FS-001', detections: [
      { ruleId: 'CR-006', severity: 'critical', label: 'Ransomware Preparation Target', timestamp: '2025-01-15T23:45:00Z' }
    ]},
    { type: 'host', id: 'SVR-DB01', detections: [
      { ruleId: 'CR-003', severity: 'high', label: 'Lateral Movement Target', timestamp: '2025-01-15T14:20:00Z' }
    ]},
    { type: 'host', id: 'WS-101', detections: [
      { ruleId: 'CR-005', severity: 'critical', label: 'Intrusion Patient Zero', timestamp: '2025-01-15T10:00:00Z' }
    ]}
  ];

  sampleEntities.forEach(entity => {
    entity.detections.forEach(det => {
      entityTracker.trackEntity(entity.type, entity.id, det);
    });
  });

  // Add entity relations
  entityTracker.addRelation('ip:185.220.101.42', 'user:admin', 'authenticated_as', { ruleId: 'CR-001' });
  entityTracker.addRelation('user:admin', 'host:DC01', 'logged_into', { ruleId: 'CR-001' });
  entityTracker.addRelation('user:jsmith', 'host:WS-042', 'uses_workstation', { ruleId: 'CR-007' });
  entityTracker.addRelation('host:WS-042', 'ip:91.215.85.17', 'connected_to_c2', { ruleId: 'CR-007' });
  entityTracker.addRelation('ip:10.0.1.50', 'host:SVR-DB01', 'lateral_movement_to', { ruleId: 'CR-003' });
  entityTracker.addRelation('user:jdoe', 'host:WS-101', 'compromised_on', { ruleId: 'CR-005' });
  entityTracker.addRelation('host:WS-101', 'host:SVR-FILE01', 'lateral_to', { ruleId: 'CR-005' });

  // Pre-create sample incidents
  const inc1 = incidentManager.createIncident([
    { ruleId: 'CR-001', severity: 'critical', label: 'Brute Force → Account Compromise', verdict: 'Account compromise confirmed', event: { sourceIP: '185.220.101.42', user: 'admin', hostname: 'DC01' } }
  ], CORRELATION_RULES[0]);
  incidentManager.updateStatus(inc1.id, 'investigating', 'SOC Analyst assigned — reviewing authentication logs');

  const inc2 = incidentManager.createIncident([
    { ruleId: 'CR-007', severity: 'high', label: 'Phishing Kill Chain', verdict: 'Phishing payload executed with C2', event: { sourceIP: '10.0.1.50', user: 'jsmith', hostname: 'WS-042' } }
  ], CORRELATION_RULES[6]);
  incidentManager.updateStatus(inc2.id, 'contained', 'Endpoint isolated — C2 IP blocked at firewall');

  const inc3 = incidentManager.createIncident([
    { ruleId: 'CR-006', severity: 'critical', label: 'Pre-Ransomware Activity', verdict: 'IMMINENT RANSOMWARE', event: { sourceIP: '10.0.2.10', user: 'svc-backup', hostname: 'FS-001' } }
  ], CORRELATION_RULES[5]);
  // Leave as new (emergency)

  const inc4 = incidentManager.createIncident([
    { ruleId: 'CR-005', severity: 'critical', label: 'Full Intrusion Chain', verdict: 'Active intrusion confirmed', event: { sourceIP: '10.0.1.50', user: 'jdoe', hostname: 'WS-101' } }
  ], CORRELATION_RULES[4]);
  incidentManager.updateStatus(inc4.id, 'investigating', 'IR team engaged — scope assessment underway');
  incidentManager.updateIncident(inc4.id, [
    { ruleId: 'CR-003', severity: 'high', label: 'Lateral Movement Detected', event: { sourceIP: '10.0.1.50', user: 'jdoe', hostname: 'SVR-FILE01' } }
  ]);
}


// ──────────────────────────────────────────────
// 8. GLOBAL INSTANCES & EXPORTS
// ──────────────────────────────────────────────

const decisionEngine = new DecisionEngine();
const entityTracker = new EntityTracker();
const incidentManager = new IncidentManager();
const attackPatternDetector = new AttackPatternDetector();

// Initialize sample data
initializeSampleData(decisionEngine, entityTracker, incidentManager);

// Risk Score Calculator (kept from original)
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

// Get related correlation rules for a detection
function getCorrelationsForRule(ruleId) {
  return CORRELATION_RULES.filter(cr => cr.linkedDetections.includes(ruleId));
}

// Get correlation rules by category
function getCorrelationsByCategory(category) {
  return CORRELATION_RULES.filter(cr => cr.category === category);
}

// Simulation runner
function runSimulation(scenarioId) {
  const scenario = SIMULATION_SCENARIOS.find(s => s.id === scenarioId);
  if (!scenario) return { error: 'Scenario not found' };

  decisionEngine.clearBuffer();
  const results = [];

  scenario.events.forEach((event, idx) => {
    const evalResults = decisionEngine.evaluateEvent(event);
    
    // Track entities
    if (event.sourceIP) entityTracker.trackEntity('ip', event.sourceIP, { ...event, ruleId: scenario.correlationRule });
    if (event.user) entityTracker.trackEntity('user', event.user, { ...event, ruleId: scenario.correlationRule });
    if (event.hostname) entityTracker.trackEntity('host', event.hostname, { ...event, ruleId: scenario.correlationRule });

    results.push({
      eventIndex: idx,
      event: event,
      evaluationResults: evalResults,
      totalAlerts: evalResults.length
    });
  });

  // Check if any results escalate to incident
  const escalations = results.filter(r => r.evaluationResults.some(er => er.action === 'ESCALATE_TO_INCIDENT' || er.action === 'EMERGENCY_INCIDENT'));
  
  if (escalations.length > 0) {
    const rule = CORRELATION_RULES.find(cr => cr.id === scenario.correlationRule);
    const alertsForIncident = escalations.flatMap(e => e.evaluationResults).map(er => ({
      ...er,
      event: scenario.events[0]
    }));
    const incident = incidentManager.createIncident(alertsForIncident, rule);
    return { scenario, results, incident, escalated: true };
  }

  return { scenario, results, escalated: false };
}

// Global exports
window.CORRELATION_RULES = CORRELATION_RULES;
window.SIMULATION_SCENARIOS = SIMULATION_SCENARIOS;
window.decisionEngine = decisionEngine;
window.entityTracker = entityTracker;
window.incidentManager = incidentManager;
window.attackPatternDetector = attackPatternDetector;
window.calculateRiskScore = calculateRiskScore;
window.getCorrelationsForRule = getCorrelationsForRule;
window.getCorrelationsByCategory = getCorrelationsByCategory;
window.runSimulation = runSimulation;
window.DecisionEngine = DecisionEngine;
window.EntityTracker = EntityTracker;
window.IncidentManager = IncidentManager;
window.AttackPatternDetector = AttackPatternDetector;
