// MITRE ATT&CK Framework Data
const MITRE_TACTICS = [
  { id: 'TA0001', name: 'Initial Access', shortName: 'initial-access', description: 'The adversary is trying to get into your network. Techniques that use various entry vectors to gain their initial foothold within a network.', color: '#3b82f6' },
  { id: 'TA0002', name: 'Execution', shortName: 'execution', description: 'The adversary is trying to run malicious code. Techniques that result in adversary-controlled code running on a local or remote system.', color: '#ef4444' },
  { id: 'TA0003', name: 'Persistence', shortName: 'persistence', description: 'The adversary is trying to maintain their foothold. Techniques that adversaries use to keep access to systems across restarts, changed credentials, and other interruptions.', color: '#8b5cf6' },
  { id: 'TA0004', name: 'Privilege Escalation', shortName: 'privilege-escalation', description: 'The adversary is trying to gain higher-level permissions. Techniques that adversaries use to gain higher-level permissions on a system or network.', color: '#f59e0b' },
  { id: 'TA0005', name: 'Defense Evasion', shortName: 'defense-evasion', description: 'The adversary is trying to avoid being detected. Techniques that adversaries use to avoid detection throughout their compromise.', color: '#ec4899' },
  { id: 'TA0006', name: 'Credential Access', shortName: 'credential-access', description: 'The adversary is trying to steal account names and passwords. Techniques for stealing credentials like account names and passwords.', color: '#f97316' },
  { id: 'TA0007', name: 'Discovery', shortName: 'discovery', description: 'The adversary is trying to figure out your environment. Techniques to gain knowledge about the system and internal network.', color: '#06b6d4' },
  { id: 'TA0008', name: 'Lateral Movement', shortName: 'lateral-movement', description: 'The adversary is trying to move through your environment. Techniques that adversaries use to enter and control remote systems on a network.', color: '#10b981' },
  { id: 'TA0009', name: 'Collection', shortName: 'collection', description: 'The adversary is trying to gather data of interest to their goal. Techniques adversaries may use to gather information relevant to their objectives.', color: '#6366f1' },
  { id: 'TA0011', name: 'Command and Control', shortName: 'command-and-control', description: 'The adversary is trying to communicate with compromised systems to control them. Techniques that adversaries may use to communicate with systems under their control.', color: '#a855f7' },
  { id: 'TA0010', name: 'Exfiltration', shortName: 'exfiltration', description: 'The adversary is trying to steal data. Techniques that adversaries may use to steal data from your network.', color: '#14b8a6' },
  { id: 'TA0040', name: 'Impact', shortName: 'impact', description: 'The adversary is trying to manipulate, interrupt, or destroy your systems and data. Techniques used to destroy or disrupt availability or integrity.', color: '#dc2626' }
];

const MITRE_TECHNIQUES = {
  'TA0001': [
    { id: 'T1566', name: 'Phishing', subs: [
      { id: 'T1566.001', name: 'Spearphishing Attachment' },
      { id: 'T1566.002', name: 'Spearphishing Link' },
      { id: 'T1566.003', name: 'Spearphishing via Service' }
    ]},
    { id: 'T1190', name: 'Exploit Public-Facing Application', subs: [] },
    { id: 'T1133', name: 'External Remote Services', subs: [] },
    { id: 'T1078', name: 'Valid Accounts', subs: [
      { id: 'T1078.001', name: 'Default Accounts' },
      { id: 'T1078.002', name: 'Domain Accounts' },
      { id: 'T1078.003', name: 'Local Accounts' },
      { id: 'T1078.004', name: 'Cloud Accounts' }
    ]},
    { id: 'T1189', name: 'Drive-by Compromise', subs: [] },
    { id: 'T1199', name: 'Trusted Relationship', subs: [] }
  ],
  'TA0002': [
    { id: 'T1059', name: 'Command and Scripting Interpreter', subs: [
      { id: 'T1059.001', name: 'PowerShell' },
      { id: 'T1059.003', name: 'Windows Command Shell' },
      { id: 'T1059.005', name: 'Visual Basic' },
      { id: 'T1059.006', name: 'Python' },
      { id: 'T1059.007', name: 'JavaScript' }
    ]},
    { id: 'T1204', name: 'User Execution', subs: [
      { id: 'T1204.001', name: 'Malicious Link' },
      { id: 'T1204.002', name: 'Malicious File' }
    ]},
    { id: 'T1047', name: 'Windows Management Instrumentation', subs: [] },
    { id: 'T1053', name: 'Scheduled Task/Job', subs: [
      { id: 'T1053.005', name: 'Scheduled Task' }
    ]},
    { id: 'T1569', name: 'System Services', subs: [
      { id: 'T1569.002', name: 'Service Execution' }
    ]},
    { id: 'T1203', name: 'Exploitation for Client Execution', subs: [] }
  ],
  'TA0003': [
    { id: 'T1547', name: 'Boot or Logon Autostart Execution', subs: [
      { id: 'T1547.001', name: 'Registry Run Keys / Startup Folder' },
      { id: 'T1547.004', name: 'Winlogon Helper DLL' },
      { id: 'T1547.009', name: 'Shortcut Modification' }
    ]},
    { id: 'T1136', name: 'Create Account', subs: [
      { id: 'T1136.001', name: 'Local Account' },
      { id: 'T1136.002', name: 'Domain Account' }
    ]},
    { id: 'T1543', name: 'Create or Modify System Process', subs: [
      { id: 'T1543.003', name: 'Windows Service' }
    ]},
    { id: 'T1053', name: 'Scheduled Task/Job', subs: [
      { id: 'T1053.005', name: 'Scheduled Task' }
    ]},
    { id: 'T1546', name: 'Event Triggered Execution', subs: [
      { id: 'T1546.001', name: 'Change Default File Association' },
      { id: 'T1546.003', name: 'Windows Management Instrumentation Event Subscription' }
    ]},
    { id: 'T1098', name: 'Account Manipulation', subs: [] }
  ],
  'TA0004': [
    { id: 'T1548', name: 'Abuse Elevation Control Mechanism', subs: [
      { id: 'T1548.002', name: 'Bypass User Account Control' }
    ]},
    { id: 'T1068', name: 'Exploitation for Privilege Escalation', subs: [] },
    { id: 'T1134', name: 'Access Token Manipulation', subs: [
      { id: 'T1134.001', name: 'Token Impersonation/Theft' },
      { id: 'T1134.002', name: 'Create Process with Token' }
    ]},
    { id: 'T1055', name: 'Process Injection', subs: [
      { id: 'T1055.001', name: 'Dynamic-link Library Injection' },
      { id: 'T1055.003', name: 'Thread Execution Hijacking' }
    ]},
    { id: 'T1078', name: 'Valid Accounts', subs: [] },
    { id: 'T1543', name: 'Create or Modify System Process', subs: [
      { id: 'T1543.003', name: 'Windows Service' }
    ]}
  ],
  'TA0005': [
    { id: 'T1562', name: 'Impair Defenses', subs: [
      { id: 'T1562.001', name: 'Disable or Modify Tools' },
      { id: 'T1562.004', name: 'Disable or Modify System Firewall' }
    ]},
    { id: 'T1070', name: 'Indicator Removal', subs: [
      { id: 'T1070.001', name: 'Clear Windows Event Logs' },
      { id: 'T1070.004', name: 'File Deletion' }
    ]},
    { id: 'T1036', name: 'Masquerading', subs: [
      { id: 'T1036.003', name: 'Rename System Utilities' },
      { id: 'T1036.005', name: 'Match Legitimate Name or Location' }
    ]},
    { id: 'T1027', name: 'Obfuscated Files or Information', subs: [
      { id: 'T1027.001', name: 'Binary Padding' },
      { id: 'T1027.010', name: 'Command Obfuscation' }
    ]},
    { id: 'T1218', name: 'System Binary Proxy Execution', subs: [
      { id: 'T1218.001', name: 'Compiled HTML File' },
      { id: 'T1218.005', name: 'Mshta' },
      { id: 'T1218.010', name: 'Regsvr32' },
      { id: 'T1218.011', name: 'Rundll32' }
    ]},
    { id: 'T1112', name: 'Modify Registry', subs: [] },
    { id: 'T1140', name: 'Deobfuscate/Decode Files or Information', subs: [] },
    { id: 'T1564', name: 'Hide Artifacts', subs: [
      { id: 'T1564.001', name: 'Hidden Files and Directories' }
    ]}
  ],
  'TA0006': [
    { id: 'T1110', name: 'Brute Force', subs: [
      { id: 'T1110.001', name: 'Password Guessing' },
      { id: 'T1110.003', name: 'Password Spraying' },
      { id: 'T1110.004', name: 'Credential Stuffing' }
    ]},
    { id: 'T1003', name: 'OS Credential Dumping', subs: [
      { id: 'T1003.001', name: 'LSASS Memory' },
      { id: 'T1003.002', name: 'Security Account Manager' },
      { id: 'T1003.003', name: 'NTDS' },
      { id: 'T1003.006', name: 'DCSync' }
    ]},
    { id: 'T1558', name: 'Steal or Forge Kerberos Tickets', subs: [
      { id: 'T1558.003', name: 'Kerberoasting' },
      { id: 'T1558.004', name: 'AS-REP Roasting' }
    ]},
    { id: 'T1555', name: 'Credentials from Password Stores', subs: [
      { id: 'T1555.003', name: 'Credentials from Web Browsers' }
    ]},
    { id: 'T1552', name: 'Unsecured Credentials', subs: [
      { id: 'T1552.001', name: 'Credentials In Files' }
    ]},
    { id: 'T1187', name: 'Forced Authentication', subs: [] }
  ],
  'TA0007': [
    { id: 'T1087', name: 'Account Discovery', subs: [
      { id: 'T1087.001', name: 'Local Account' },
      { id: 'T1087.002', name: 'Domain Account' }
    ]},
    { id: 'T1082', name: 'System Information Discovery', subs: [] },
    { id: 'T1018', name: 'Remote System Discovery', subs: [] },
    { id: 'T1083', name: 'File and Directory Discovery', subs: [] },
    { id: 'T1069', name: 'Permission Groups Discovery', subs: [
      { id: 'T1069.001', name: 'Local Groups' },
      { id: 'T1069.002', name: 'Domain Groups' }
    ]},
    { id: 'T1057', name: 'Process Discovery', subs: [] },
    { id: 'T1016', name: 'System Network Configuration Discovery', subs: [] },
    { id: 'T1049', name: 'System Network Connections Discovery', subs: [] },
    { id: 'T1033', name: 'System Owner/User Discovery', subs: [] }
  ],
  'TA0008': [
    { id: 'T1021', name: 'Remote Services', subs: [
      { id: 'T1021.001', name: 'Remote Desktop Protocol' },
      { id: 'T1021.002', name: 'SMB/Windows Admin Shares' },
      { id: 'T1021.003', name: 'Distributed Component Object Model' },
      { id: 'T1021.006', name: 'Windows Remote Management' }
    ]},
    { id: 'T1570', name: 'Lateral Tool Transfer', subs: [] },
    { id: 'T1550', name: 'Use Alternate Authentication Material', subs: [
      { id: 'T1550.002', name: 'Pass the Hash' },
      { id: 'T1550.003', name: 'Pass the Ticket' }
    ]},
    { id: 'T1563', name: 'Remote Service Session Hijacking', subs: [
      { id: 'T1563.002', name: 'RDP Hijacking' }
    ]},
    { id: 'T1072', name: 'Software Deployment Tools', subs: [] }
  ],
  'TA0009': [
    { id: 'T1560', name: 'Archive Collected Data', subs: [
      { id: 'T1560.001', name: 'Archive via Utility' }
    ]},
    { id: 'T1115', name: 'Clipboard Data', subs: [] },
    { id: 'T1005', name: 'Data from Local System', subs: [] },
    { id: 'T1039', name: 'Data from Network Shared Drive', subs: [] },
    { id: 'T1114', name: 'Email Collection', subs: [
      { id: 'T1114.001', name: 'Local Email Collection' },
      { id: 'T1114.002', name: 'Remote Email Collection' }
    ]},
    { id: 'T1056', name: 'Input Capture', subs: [
      { id: 'T1056.001', name: 'Keylogging' }
    ]},
    { id: 'T1113', name: 'Screen Capture', subs: [] }
  ],
  'TA0011': [
    { id: 'T1071', name: 'Application Layer Protocol', subs: [
      { id: 'T1071.001', name: 'Web Protocols' },
      { id: 'T1071.004', name: 'DNS' }
    ]},
    { id: 'T1105', name: 'Ingress Tool Transfer', subs: [] },
    { id: 'T1572', name: 'Protocol Tunneling', subs: [] },
    { id: 'T1573', name: 'Encrypted Channel', subs: [
      { id: 'T1573.001', name: 'Symmetric Cryptography' },
      { id: 'T1573.002', name: 'Asymmetric Cryptography' }
    ]},
    { id: 'T1090', name: 'Proxy', subs: [
      { id: 'T1090.001', name: 'Internal Proxy' },
      { id: 'T1090.002', name: 'External Proxy' }
    ]},
    { id: 'T1219', name: 'Remote Access Software', subs: [] },
    { id: 'T1132', name: 'Data Encoding', subs: [
      { id: 'T1132.001', name: 'Standard Encoding' }
    ]},
    { id: 'T1568', name: 'Dynamic Resolution', subs: [
      { id: 'T1568.002', name: 'Domain Generation Algorithms' }
    ]}
  ],
  'TA0010': [
    { id: 'T1048', name: 'Exfiltration Over Alternative Protocol', subs: [
      { id: 'T1048.003', name: 'Exfiltration Over Unencrypted Non-C2 Protocol' }
    ]},
    { id: 'T1041', name: 'Exfiltration Over C2 Channel', subs: [] },
    { id: 'T1567', name: 'Exfiltration Over Web Service', subs: [
      { id: 'T1567.002', name: 'Exfiltration to Cloud Storage' }
    ]},
    { id: 'T1030', name: 'Data Transfer Size Limits', subs: [] },
    { id: 'T1020', name: 'Automated Exfiltration', subs: [] },
    { id: 'T1537', name: 'Transfer Data to Cloud Account', subs: [] }
  ],
  'TA0040': [
    { id: 'T1486', name: 'Data Encrypted for Impact', subs: [] },
    { id: 'T1490', name: 'Inhibit System Recovery', subs: [] },
    { id: 'T1489', name: 'Service Stop', subs: [] },
    { id: 'T1529', name: 'System Shutdown/Reboot', subs: [] },
    { id: 'T1485', name: 'Data Destruction', subs: [] },
    { id: 'T1491', name: 'Defacement', subs: [
      { id: 'T1491.001', name: 'Internal Defacement' },
      { id: 'T1491.002', name: 'External Defacement' }
    ]},
    { id: 'T1561', name: 'Disk Wipe', subs: [
      { id: 'T1561.001', name: 'Disk Content Wipe' },
      { id: 'T1561.002', name: 'Disk Structure Wipe' }
    ]},
    { id: 'T1499', name: 'Endpoint Denial of Service', subs: [] }
  ]
};

// Threat Intelligence - CISA KEV Entries mapped to techniques
const THREAT_INTEL = {
  cisaKev: [
    { cve: 'CVE-2024-3400', vendor: 'Palo Alto Networks', product: 'PAN-OS GlobalProtect', description: 'Command injection vulnerability in GlobalProtect gateway', dateAdded: '2024-04-12', dueDate: '2024-05-02', techniques: ['T1190'], severity: 'critical', knownRansomware: true },
    { cve: 'CVE-2024-1709', vendor: 'ConnectWise', product: 'ScreenConnect', description: 'Authentication bypass using an alternate path', dateAdded: '2024-02-22', dueDate: '2024-03-14', techniques: ['T1190', 'T1133'], severity: 'critical', knownRansomware: true },
    { cve: 'CVE-2023-46805', vendor: 'Ivanti', product: 'Connect Secure / Policy Secure', description: 'Authentication bypass vulnerability', dateAdded: '2024-01-10', dueDate: '2024-01-31', techniques: ['T1190', 'T1078'], severity: 'critical', knownRansomware: true },
    { cve: 'CVE-2023-4966', vendor: 'Citrix', product: 'NetScaler ADC/Gateway', description: 'Buffer overflow (Citrix Bleed) leading to sensitive information disclosure', dateAdded: '2023-10-18', dueDate: '2023-11-08', techniques: ['T1190', 'T1133'], severity: 'critical', knownRansomware: true },
    { cve: 'CVE-2023-44228', vendor: 'Apache', product: 'Log4j (Log4Shell)', description: 'Remote code execution via JNDI injection in Log4j', dateAdded: '2021-12-10', dueDate: '2021-12-24', techniques: ['T1190', 'T1059'], severity: 'critical', knownRansomware: true },
    { cve: 'CVE-2023-27350', vendor: 'PaperCut', product: 'PaperCut MF/NG', description: 'Improper access control allowing RCE', dateAdded: '2023-04-21', dueDate: '2023-05-12', techniques: ['T1190'], severity: 'critical', knownRansomware: true },
    { cve: 'CVE-2023-22515', vendor: 'Atlassian', product: 'Confluence Data Center', description: 'Broken access control vulnerability', dateAdded: '2023-10-05', dueDate: '2023-10-26', techniques: ['T1190', 'T1078'], severity: 'critical', knownRansomware: false },
    { cve: 'CVE-2021-34527', vendor: 'Microsoft', product: 'Windows Print Spooler', description: 'PrintNightmare - Remote code execution', dateAdded: '2021-07-02', dueDate: '2021-07-16', techniques: ['T1068', 'T1569.002'], severity: 'critical', knownRansomware: true },
    { cve: 'CVE-2021-44228', vendor: 'Apache', product: 'Log4j2', description: 'Log4Shell JNDI remote code execution', dateAdded: '2021-12-10', dueDate: '2021-12-24', techniques: ['T1190', 'T1059.007'], severity: 'critical', knownRansomware: true },
    { cve: 'CVE-2020-1472', vendor: 'Microsoft', product: 'Netlogon', description: 'Zerologon privilege escalation', dateAdded: '2020-09-18', dueDate: '2020-10-09', techniques: ['T1068', 'T1003.006'], severity: 'critical', knownRansomware: true }
  ],
  campaigns: [
    { name: 'Volt Typhoon', actor: 'Volt Typhoon (PRC)', targets: 'US Critical Infrastructure', techniques: ['T1190', 'T1078', 'T1059.001', 'T1021.002', 'T1070.001'], description: 'Chinese state-sponsored group targeting US critical infrastructure using living-off-the-land techniques', firstSeen: '2023', active: true },
    { name: 'ALPHV/BlackCat Ransomware', actor: 'ALPHV', targets: 'Healthcare, Finance, Government', techniques: ['T1190', 'T1486', 'T1490', 'T1078', 'T1021.001'], description: 'Ransomware-as-a-service operation using double extortion', firstSeen: '2021', active: true },
    { name: 'LockBit 3.0', actor: 'LockBit', targets: 'Cross-sector', techniques: ['T1486', 'T1490', 'T1059.001', 'T1021.002', 'T1003.001'], description: 'High-volume ransomware operation with affiliate model', firstSeen: '2019', active: true },
    { name: 'Scattered Spider', actor: 'Scattered Spider / UNC3944', targets: 'Telecom, Technology, Hospitality', techniques: ['T1566.002', 'T1078', 'T1110.003', 'T1550.002'], description: 'Financially motivated group using social engineering and identity-based attacks', firstSeen: '2022', active: true },
    { name: 'Midnight Blizzard', actor: 'APT29 / Cozy Bear', targets: 'Government, Diplomatic', techniques: ['T1566.001', 'T1059.001', 'T1071.001', 'T1573.002', 'T1005'], description: 'Russian state-sponsored group conducting espionage campaigns', firstSeen: '2014', active: true }
  ]
};

// Attack Categories — 22 top-level organizational units
const ATTACK_CATEGORIES = [
  { id: 'brute-force', name: 'Brute Force', icon: '🔓', desc: 'Authentication attack detection — failed logins, password spraying, credential stuffing', color: '#ef4444' },
  { id: 'lateral-movement', name: 'Lateral Movement', icon: '↔️', desc: 'Detecting attackers moving across the network via remote services and protocols', color: '#10b981' },
  { id: 'privilege-escalation', name: 'Privilege Escalation', icon: '⬆️', desc: 'Unauthorized elevation of access rights and permissions', color: '#f59e0b' },
  { id: 'credential-access', name: 'Credential Access', icon: '🔑', desc: 'Credential theft, dumping, and harvesting techniques', color: '#f97316' },
  { id: 'data-exfiltration', name: 'Data Exfiltration', icon: '📤', desc: 'Unauthorized data transfer out of the organization', color: '#14b8a6' },
  { id: 'command-control', name: 'Command & Control', icon: '📡', desc: 'C2 communication channels, beaconing, and covert tunnels', color: '#a855f7' },
  { id: 'ransomware', name: 'Ransomware', icon: '💀', desc: 'Ransomware execution indicators — encryption, shadow copy deletion, ransom notes', color: '#dc2626' },
  { id: 'reconnaissance', name: 'Reconnaissance', icon: '🔍', desc: 'Network and environment scanning, enumeration, and discovery', color: '#06b6d4' },
  { id: 'initial-access', name: 'Initial Access', icon: '🚪', desc: 'Entry vectors — phishing, exploitation, compromised credentials', color: '#3b82f6' },
  { id: 'execution', name: 'Execution', icon: '⚡', desc: 'Malicious code execution via scripts, LOLBins, and living-off-the-land', color: '#ef4444' },
  { id: 'persistence', name: 'Persistence', icon: '📌', desc: 'Mechanisms for maintaining access — scheduled tasks, registry, services', color: '#8b5cf6' },
  { id: 'defense-evasion', name: 'Defense Evasion', icon: '🛡️', desc: 'Techniques to avoid detection — log clearing, disabling security tools', color: '#ec4899' },
  { id: 'web-attacks', name: 'Web Attacks', icon: '🌐', desc: 'Web application attacks — SQLi, XSS, directory traversal, web shells', color: '#0ea5e9' },
  { id: 'insider-threat', name: 'Insider Threat', icon: '👤', desc: 'Malicious or negligent insider activity detection', color: '#eab308' },
  { id: 'cloud-threats', name: 'Cloud Threats', icon: '☁️', desc: 'Azure, AWS, GCP — identity, storage, and configuration threats', color: '#38bdf8' },
  { id: 'active-directory', name: 'Active Directory', icon: '🏛️', desc: 'AD-specific attacks — Kerberoasting, DCSync, Golden Ticket', color: '#818cf8' },
  { id: 'network-anomalies', name: 'Network Anomalies', icon: '📊', desc: 'Protocol anomalies, scanning, DDoS indicators, tunneling', color: '#2dd4bf' },
  { id: 'endpoint-anomalies', name: 'Endpoint Anomalies', icon: '💻', desc: 'Suspicious process behavior, unsigned binaries, injection', color: '#fb923c' },
  { id: 'email-threats', name: 'Email Threats', icon: '✉️', desc: 'Phishing, BEC, malicious attachments, forwarding rules', color: '#f472b6' },
  { id: 'linux-threats', name: 'Linux / UNIX Threats', icon: '🐧', desc: 'Reverse shells, crontab abuse, rootkits, privilege escalation', color: '#facc15' },
  { id: 'windows-specific', name: 'Windows Specific', icon: '🪟', desc: 'LOLBins, BITS jobs, ADS, print spooler, named pipes', color: '#60a5fa' },
  { id: 'threat-hunting', name: 'Threat Hunting', icon: '🎯', desc: 'Advanced proactive queries — long-tail analysis, stack ranking, beaconing', color: '#c084fc' },
  { id: 'collection', name: 'Collection', icon: '📦', desc: 'Data staging, archiving, clipboard capture, and email collection techniques', color: '#8b5cf6' }
];
