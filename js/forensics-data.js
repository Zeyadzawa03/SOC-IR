// ═══════════════════════════════════════════════════════════════════════
// Digital Forensics (DFIR) Engine — Forensic Artifacts, Timeline, Evidence
// Integrates into each detection for forensic context
// ═══════════════════════════════════════════════════════════════════════

const FORENSIC_ARTIFACTS = {
  // ── Windows Event Logs ──
  'windows-security-log': {
    name: 'Windows Security Event Log',
    type: 'Event Log', platform: 'Windows',
    location: 'C:\\Windows\\System32\\winevt\\Logs\\Security.evtx',
    description: 'Primary audit log for Windows authentication, authorization, and security events.',
    keyEvents: [
      { id: '4624', name: 'Successful Logon', forensicValue: 'critical' },
      { id: '4625', name: 'Failed Logon', forensicValue: 'critical' },
      { id: '4648', name: 'Explicit Credential Logon', forensicValue: 'high' },
      { id: '4672', name: 'Special Privileges Assigned', forensicValue: 'high' },
      { id: '4688', name: 'Process Creation', forensicValue: 'critical' },
      { id: '4689', name: 'Process Termination', forensicValue: 'medium' },
      { id: '4698', name: 'Scheduled Task Created', forensicValue: 'high' },
      { id: '4720', name: 'User Account Created', forensicValue: 'high' },
      { id: '4732', name: 'Member Added to Local Group', forensicValue: 'high' },
      { id: '4768', name: 'Kerberos TGT Request', forensicValue: 'medium' },
      { id: '4769', name: 'Kerberos TGS Request', forensicValue: 'high' },
      { id: '4776', name: 'NTLM Authentication', forensicValue: 'medium' },
      { id: '1102', name: 'Audit Log Cleared', forensicValue: 'critical' }
    ],
    collectionTools: ['wevtutil', 'Get-WinEvent', 'Log Parser', 'EvtxECmd (EZ Tools)'],
    retentionGuidance: 'Minimum 90 days local, 1 year in SIEM'
  },
  'sysmon-log': {
    name: 'Sysmon Operational Log',
    type: 'Event Log', platform: 'Windows',
    location: 'C:\\Windows\\System32\\winevt\\Logs\\Microsoft-Windows-Sysmon%4Operational.evtx',
    description: 'Enhanced system monitoring providing detailed process, network, and file telemetry.',
    keyEvents: [
      { id: '1', name: 'Process Creation', forensicValue: 'critical' },
      { id: '3', name: 'Network Connection', forensicValue: 'high' },
      { id: '7', name: 'Image Loaded (DLL)', forensicValue: 'medium' },
      { id: '10', name: 'Process Access', forensicValue: 'critical' },
      { id: '11', name: 'File Creation', forensicValue: 'high' },
      { id: '12/13/14', name: 'Registry Events', forensicValue: 'high' },
      { id: '15', name: 'File Stream Created (ADS)', forensicValue: 'high' },
      { id: '17/18', name: 'Named Pipe Events', forensicValue: 'medium' },
      { id: '19/20/21', name: 'WMI Events', forensicValue: 'high' },
      { id: '22', name: 'DNS Query', forensicValue: 'high' },
      { id: '23', name: 'File Delete', forensicValue: 'high' },
      { id: '25', name: 'Process Tampering', forensicValue: 'critical' }
    ],
    collectionTools: ['Sysmon (Microsoft Sysinternals)', 'wevtutil', 'Get-WinEvent'],
    retentionGuidance: 'Minimum 30 days local, 6 months in SIEM'
  },
  'powershell-log': {
    name: 'PowerShell Logging',
    type: 'Event Log', platform: 'Windows',
    location: 'C:\\Windows\\System32\\winevt\\Logs\\Microsoft-Windows-PowerShell%4Operational.evtx',
    description: 'PowerShell script block and module logging for detecting malicious script execution.',
    keyEvents: [
      { id: '4103', name: 'Module Logging', forensicValue: 'high' },
      { id: '4104', name: 'Script Block Logging', forensicValue: 'critical' },
      { id: '4105', name: 'Script Block Start', forensicValue: 'medium' },
      { id: '4106', name: 'Script Block Stop', forensicValue: 'medium' }
    ],
    collectionTools: ['Get-WinEvent', 'PowerShell Transcription logs'],
    retentionGuidance: 'Minimum 90 days, critical for forensics'
  },

  // ── File System Artifacts ──
  'prefetch': {
    name: 'Windows Prefetch',
    type: 'File System', platform: 'Windows',
    location: 'C:\\Windows\\Prefetch\\*.pf',
    description: 'Records program execution history including timestamps and loaded files. Critical for proving program execution.',
    keyEvents: [
      { id: 'LastRunTime', name: 'Last 8 execution timestamps', forensicValue: 'critical' },
      { id: 'RunCount', name: 'Total execution count', forensicValue: 'high' },
      { id: 'FilesLoaded', name: 'List of DLLs and files accessed', forensicValue: 'high' }
    ],
    collectionTools: ['PECmd (EZ Tools)', 'WinPrefetchView (NirSoft)', 'prefetch-parser'],
    retentionGuidance: 'Survives until overwritten (128 entries max on Win10+)'
  },
  'amcache': {
    name: 'AmCache.hve',
    type: 'Registry Hive', platform: 'Windows',
    location: 'C:\\Windows\\AppCompat\\Programs\\Amcache.hve',
    description: 'Tracks application installation and execution including SHA1 hashes, paths, and timestamps.',
    keyEvents: [
      { id: 'FileEntries', name: 'Program execution entries with SHA1', forensicValue: 'critical' },
      { id: 'DriverBinaries', name: 'Driver installation records', forensicValue: 'high' },
      { id: 'ShortCuts', name: 'Shortcut metadata', forensicValue: 'medium' }
    ],
    collectionTools: ['AmcacheParser (EZ Tools)', 'Registry Explorer'],
    retentionGuidance: 'Key entries persist for weeks to months'
  },
  'shimcache': {
    name: 'ShimCache (AppCompatCache)',
    type: 'Registry', platform: 'Windows',
    location: 'SYSTEM\\CurrentControlSet\\Control\\Session Manager\\AppCompatCache',
    description: 'Application compatibility cache tracking program execution — proves a program existed on disk, may indicate execution.',
    keyEvents: [
      { id: 'CacheEntries', name: 'Program path + last modified time', forensicValue: 'high' },
      { id: 'ExecutionFlag', name: 'Process executed flag (Win7/Server)', forensicValue: 'critical' }
    ],
    collectionTools: ['AppCompatCacheParser (EZ Tools)', 'ShimCacheParser'],
    retentionGuidance: 'Persists until entry limit reached (1024 entries)'
  },
  'mft': {
    name: 'NTFS Master File Table ($MFT)',
    type: 'File System', platform: 'Windows',
    location: '$MFT (root of NTFS volume)',
    description: 'Master record of all files on an NTFS volume including full timestamps (Created, Modified, Accessed, Entry Modified).',
    keyEvents: [
      { id: '$STANDARD_INFORMATION', name: 'User-visible timestamps (can be timestomped)', forensicValue: 'high' },
      { id: '$FILE_NAME', name: 'Original timestamps (harder to fake)', forensicValue: 'critical' },
      { id: 'ResidentData', name: 'Small file content stored in MFT', forensicValue: 'high' }
    ],
    collectionTools: ['MFTECmd (EZ Tools)', 'analyzeMFT', 'FTK Imager'],
    retentionGuidance: 'Persists until file entries overwritten'
  },
  'usnjrnl': {
    name: 'NTFS USN Journal ($UsnJrnl)',
    type: 'File System', platform: 'Windows',
    location: '$Extend\\$UsnJrnl:$J',
    description: 'Change journal recording file system modifications (create, delete, rename, modify). Critical for timeline reconstruction.',
    keyEvents: [
      { id: 'FileCreate', name: 'File creation record', forensicValue: 'critical' },
      { id: 'FileDelete', name: 'File deletion record', forensicValue: 'critical' },
      { id: 'FileRename', name: 'File rename record', forensicValue: 'high' },
      { id: 'DataOverwrite', name: 'File content modification', forensicValue: 'high' }
    ],
    collectionTools: ['MFTECmd (EZ Tools)', 'fsutil', 'ANJP'],
    retentionGuidance: 'Cycles based on journal size (typically days to weeks)'
  },

  // ── Registry Artifacts ──
  'registry-hives': {
    name: 'Windows Registry Hives',
    type: 'Registry', platform: 'Windows',
    location: 'C:\\Windows\\System32\\config\\ (SAM, SYSTEM, SOFTWARE, SECURITY)',
    description: 'Core Windows configuration database. Contains user accounts, system settings, installed software, network configurations, and persistence mechanisms.',
    keyEvents: [
      { id: 'Run/RunOnce', name: 'Auto-start programs', forensicValue: 'critical' },
      { id: 'Services', name: 'Installed services', forensicValue: 'critical' },
      { id: 'UserAssist', name: 'Program execution tracking (GUI)', forensicValue: 'high' },
      { id: 'MUICache', name: 'Executed application names', forensicValue: 'medium' },
      { id: 'NetworkList', name: 'Connected networks history', forensicValue: 'high' },
      { id: 'TypedURLs', name: 'Manually typed URLs in IE/Edge', forensicValue: 'medium' },
      { id: 'RecentDocs', name: 'Recently opened documents', forensicValue: 'high' },
      { id: 'BAM/DAM', name: 'Background Activity Moderator', forensicValue: 'high' }
    ],
    collectionTools: ['Registry Explorer (EZ Tools)', 'RegRipper', 'RECmd'],
    retentionGuidance: 'Persistent until explicitly modified'
  },
  'ntuser-dat': {
    name: 'NTUSER.DAT (User Profile)',
    type: 'Registry', platform: 'Windows',
    location: 'C:\\Users\\<username>\\NTUSER.DAT',
    description: 'Per-user registry hive containing user-specific configurations, recent activity, and application settings.',
    keyEvents: [
      { id: 'UserAssist', name: 'GUI program execution counts and timestamps', forensicValue: 'critical' },
      { id: 'TypedPaths', name: 'Explorer address bar entries', forensicValue: 'high' },
      { id: 'RunMRU', name: 'Win+R command history', forensicValue: 'high' },
      { id: 'RecentDocs', name: 'Recent documents per extension', forensicValue: 'high' },
      { id: 'ComDlg32', name: 'Open/Save dialog history', forensicValue: 'high' }
    ],
    collectionTools: ['Registry Explorer', 'RegRipper'],
    retentionGuidance: 'Persists in user profile'
  },

  // ── Network Artifacts ──
  'network-connections': {
    name: 'Network Connection Artifacts',
    type: 'Network', platform: 'Windows/Linux',
    location: 'Memory / System state',
    description: 'Active and historical network connections, DNS cache, and routing information.',
    keyEvents: [
      { id: 'ActiveConnections', name: 'Current TCP/UDP connections', forensicValue: 'critical' },
      { id: 'DNSCache', name: 'Cached DNS resolutions', forensicValue: 'high' },
      { id: 'ARPCache', name: 'MAC-to-IP mappings', forensicValue: 'medium' },
      { id: 'RoutingTable', name: 'Network routing information', forensicValue: 'medium' },
      { id: 'FirewallRules', name: 'Applied firewall rules', forensicValue: 'high' }
    ],
    collectionTools: ['netstat', 'ipconfig /displaydns', 'arp -a', 'route print', 'TCPView'],
    retentionGuidance: 'Volatile — capture immediately during response'
  },

  // ── Memory Artifacts ──
  'memory-analysis': {
    name: 'Memory (RAM) Analysis',
    type: 'Memory', platform: 'Windows/Linux',
    location: 'Physical memory dump',
    description: 'Volatile memory contains running processes, network connections, encryption keys, and malware that may only exist in memory.',
    keyEvents: [
      { id: 'ProcessList', name: 'Running processes with PIDs', forensicValue: 'critical' },
      { id: 'DLLList', name: 'Loaded modules per process', forensicValue: 'critical' },
      { id: 'NetworkSockets', name: 'Open network connections', forensicValue: 'critical' },
      { id: 'HandleList', name: 'Open file/registry handles', forensicValue: 'high' },
      { id: 'InjectedCode', name: 'Code injection detection', forensicValue: 'critical' },
      { id: 'CommandHistory', name: 'CLI command history', forensicValue: 'high' },
      { id: 'Clipboard', name: 'Clipboard contents', forensicValue: 'medium' },
      { id: 'EncryptionKeys', name: 'Cached encryption keys', forensicValue: 'critical' }
    ],
    collectionTools: ['WinPMEM', 'DumpIt', 'FTK Imager', 'Volatility 3', 'Rekall'],
    retentionGuidance: 'VOLATILE — must capture before power off'
  },

  // ── Linux Artifacts ──
  'linux-logs': {
    name: 'Linux System Logs',
    type: 'Log Files', platform: 'Linux',
    location: '/var/log/',
    description: 'Linux system and authentication logs providing user activity, service status, and security events.',
    keyEvents: [
      { id: 'auth.log', name: 'Authentication events (SSH, sudo, PAM)', forensicValue: 'critical' },
      { id: 'syslog', name: 'System events and messages', forensicValue: 'high' },
      { id: 'kern.log', name: 'Kernel messages', forensicValue: 'high' },
      { id: 'cron.log', name: 'Cron job execution', forensicValue: 'high' },
      { id: 'wtmp/btmp', name: 'Login success/failure records', forensicValue: 'critical' },
      { id: 'lastlog', name: 'Last login per user', forensicValue: 'medium' },
      { id: 'audit.log', name: 'Linux audit framework events', forensicValue: 'critical' }
    ],
    collectionTools: ['journalctl', 'last/lastb', 'aureport', 'ausearch'],
    retentionGuidance: 'Varies by logrotate configuration'
  },
  'linux-persistence': {
    name: 'Linux Persistence Artifacts',
    type: 'Configuration', platform: 'Linux',
    location: 'Various',
    description: 'Linux-specific persistence mechanisms including cron jobs, systemd services, shell profiles, and SSH configurations.',
    keyEvents: [
      { id: 'crontabs', name: '/var/spool/cron/ + /etc/cron.d/', forensicValue: 'critical' },
      { id: 'systemd', name: '/etc/systemd/system/ + /lib/systemd/', forensicValue: 'critical' },
      { id: 'rc.local', name: '/etc/rc.local (boot script)', forensicValue: 'high' },
      { id: 'shell-rc', name: '.bashrc, .profile, .bash_profile', forensicValue: 'high' },
      { id: 'authorized_keys', name: '~/.ssh/authorized_keys', forensicValue: 'critical' },
      { id: 'ld.so.preload', name: '/etc/ld.so.preload (library injection)', forensicValue: 'critical' }
    ],
    collectionTools: ['find', 'ls -la', 'systemctl list-unit-files', 'crontab -l'],
    retentionGuidance: 'Persistent until removed'
  },

  // ── Browser Artifacts ──
  'browser-artifacts': {
    name: 'Web Browser Forensic Artifacts',
    type: 'Application', platform: 'Windows/macOS/Linux',
    location: 'User profile directories (AppData/Local)',
    description: 'Browser history, downloads, cached content, cookies, and saved credentials.',
    keyEvents: [
      { id: 'History', name: 'URLs visited with timestamps', forensicValue: 'critical' },
      { id: 'Downloads', name: 'Downloaded files with source URLs', forensicValue: 'critical' },
      { id: 'Cache', name: 'Cached page content and files', forensicValue: 'high' },
      { id: 'Cookies', name: 'Session tokens and tracking cookies', forensicValue: 'high' },
      { id: 'Sessions', name: 'Active/restored browser sessions', forensicValue: 'medium' },
      { id: 'Autofill', name: 'Form autofill data', forensicValue: 'medium' }
    ],
    collectionTools: ['Hindsight (Chrome/Edge)', 'BrowsingHistoryView (NirSoft)', 'KAPE'],
    retentionGuidance: 'Varies by browser settings and user actions'
  }
};

// ── Category to Forensic Artifact Mapping ──
const CATEGORY_FORENSIC_MAP = {
  'brute-force': ['windows-security-log', 'network-connections'],
  'ransomware': ['sysmon-log', 'prefetch', 'mft', 'usnjrnl', 'memory-analysis', 'registry-hives'],
  'web-attacks': ['sysmon-log', 'network-connections', 'memory-analysis', 'browser-artifacts'],
  'reconnaissance': ['network-connections', 'sysmon-log', 'windows-security-log'],
  'insider-threat': ['windows-security-log', 'ntuser-dat', 'browser-artifacts', 'usnjrnl'],
  'cloud-threats': ['windows-security-log', 'browser-artifacts', 'network-connections'],
  'active-directory': ['windows-security-log', 'sysmon-log', 'memory-analysis', 'registry-hives'],
  'email-threats': ['sysmon-log', 'prefetch', 'browser-artifacts', 'usnjrnl'],
  'network-anomalies': ['network-connections', 'sysmon-log', 'memory-analysis'],
  'endpoint-anomalies': ['sysmon-log', 'prefetch', 'amcache', 'shimcache', 'memory-analysis'],
  'linux-threats': ['linux-logs', 'linux-persistence', 'network-connections', 'memory-analysis'],
  'windows-specific': ['sysmon-log', 'powershell-log', 'registry-hives', 'prefetch', 'amcache'],
  'threat-hunting': ['sysmon-log', 'windows-security-log', 'network-connections'],
  'data-exfiltration': ['network-connections', 'browser-artifacts', 'usnjrnl', 'ntuser-dat'],
  'lateral-movement': ['windows-security-log', 'sysmon-log', 'network-connections'],
  'privilege-escalation': ['sysmon-log', 'windows-security-log', 'memory-analysis', 'registry-hives'],
  'credential-access': ['sysmon-log', 'windows-security-log', 'memory-analysis'],
  'defense-evasion': ['sysmon-log', 'powershell-log', 'registry-hives', 'mft', 'usnjrnl'],
  'persistence': ['registry-hives', 'sysmon-log', 'prefetch', 'amcache'],
  'execution': ['sysmon-log', 'powershell-log', 'prefetch', 'amcache', 'shimcache'],
  'initial-access': ['windows-security-log', 'sysmon-log', 'browser-artifacts'],
  'command-control': ['network-connections', 'sysmon-log', 'memory-analysis'],
  'collection': ['usnjrnl', 'ntuser-dat', 'sysmon-log']
};

// ── Timeline Event Templates ──
const TIMELINE_TEMPLATES = {
  'initial-compromise': {
    name: 'Initial Compromise Timeline',
    phases: [
      { phase: 'Delivery', description: 'Phishing email / exploit delivery', artifacts: ['Email logs', 'Proxy logs', 'WAF logs'], icon: '📧' },
      { phase: 'Exploitation', description: 'Vulnerability exploited or payload executed', artifacts: ['Sysmon Event 1', 'Prefetch', 'AmCache'], icon: '💥' },
      { phase: 'Installation', description: 'Malware installed, persistence established', artifacts: ['Registry Run keys', 'Services', 'Scheduled Tasks'], icon: '⚙️' },
      { phase: 'C2 Established', description: 'Command & control communication', artifacts: ['DNS logs', 'Proxy logs', 'Sysmon Event 3'], icon: '📡' },
      { phase: 'Lateral Movement', description: 'Spread to additional systems', artifacts: ['Logon events 4624', 'Service installs', 'RDP logs'], icon: '↔️' },
      { phase: 'Objective', description: 'Data theft, encryption, or other objective', artifacts: ['File access logs', 'Network flow data'], icon: '🎯' }
    ]
  },
  'ransomware-attack': {
    name: 'Ransomware Attack Timeline',
    phases: [
      { phase: 'Initial Access', description: 'Entry via phishing, exploit, or purchased access', artifacts: ['Email logs', 'VPN logs', 'Web server logs'], icon: '🚪' },
      { phase: 'Reconnaissance', description: 'Network discovery and enumeration', artifacts: ['Sysmon Event 1', 'LDAP queries', 'Port scans'], icon: '🔎' },
      { phase: 'Privilege Escalation', description: 'Admin/SYSTEM access obtained', artifacts: ['Security log 4672', 'Sysmon Event 10', 'Kerberos logs'], icon: '⬆️' },
      { phase: 'Lateral Movement', description: 'Spread across the network', artifacts: ['Logon 4624 Type 3', 'RDP logs', 'PsExec service installs'], icon: '↔️' },
      { phase: 'Data Exfiltration', description: 'Sensitive data stolen (double extortion)', artifacts: ['Proxy logs', 'DLP events', 'Network flow'], icon: '📤' },
      { phase: 'Defense Evasion', description: 'Security tools disabled, logs cleared', artifacts: ['Event 1102', 'Defender events', 'EDR alerts'], icon: '🛡️' },
      { phase: 'Encryption', description: 'Files encrypted, ransom note deployed', artifacts: ['File creation events', 'VSS deletion', 'MFT changes'], icon: '🔒' },
      { phase: 'Extortion', description: 'Ransom demand delivered', artifacts: ['Ransom note files', 'Communication logs'], icon: '💰' }
    ]
  },
  'insider-threat': {
    name: 'Insider Threat Timeline',
    phases: [
      { phase: 'Trigger Event', description: 'Performance review, termination notice, conflict', artifacts: ['HR records', 'Email sentiment analysis'], icon: '⚡' },
      { phase: 'Reconnaissance', description: 'Identifying valuable data to steal', artifacts: ['File access logs', 'SharePoint audit', 'Search queries'], icon: '🔍' },
      { phase: 'Collection', description: 'Gathering and staging data', artifacts: ['USN Journal', 'Archive creation events', 'Print logs'], icon: '📦' },
      { phase: 'Exfiltration', description: 'Data transfer to external destination', artifacts: ['Proxy logs', 'USB events', 'Email attachment logs', 'DLP events'], icon: '📤' },
      { phase: 'Cover-Up', description: 'Attempt to hide evidence', artifacts: ['File deletion events', 'Browser history clearing', 'Event log clearing'], icon: '🧹' }
    ]
  }
};

// ── Get forensic artifacts for a category ──
function getForensicArtifacts(catId) {
  const artifactIds = CATEGORY_FORENSIC_MAP[catId] || [];
  return artifactIds.map(id => FORENSIC_ARTIFACTS[id]).filter(Boolean);
}

// ── Get all forensic artifacts ──
function getAllForensicArtifacts() {
  return Object.entries(FORENSIC_ARTIFACTS).map(([id, artifact]) => ({ id, ...artifact }));
}

// ── Get timeline template ──
function getTimelineTemplate(templateId) {
  return TIMELINE_TEMPLATES[templateId] || null;
}

window.FORENSIC_ARTIFACTS = FORENSIC_ARTIFACTS;
window.CATEGORY_FORENSIC_MAP = CATEGORY_FORENSIC_MAP;
window.TIMELINE_TEMPLATES = TIMELINE_TEMPLATES;
window.getForensicArtifacts = getForensicArtifacts;
window.getAllForensicArtifacts = getAllForensicArtifacts;
window.getTimelineTemplate = getTimelineTemplate;
