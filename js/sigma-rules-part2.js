// Sigma Rules Database - Part 2: Credential Access, Discovery, Lateral Movement, Collection, C2, Exfiltration, Impact
const SIGMA_RULES_PART2 = [
// ═══════════════════════════════════════════════════════════════
// CREDENTIAL ACCESS (TA0006)
// ═══════════════════════════════════════════════════════════════
{
  id: 'SR-0026', title: 'Password Spraying Attack Detection',
  status: 'stable', severity: 'high', author: 'SOC Platform', date: '2024-02-01', modified: '2024-12-10',
  category: 'brute-force',
  description: 'Detects password spraying attacks characterized by a single password being tried against multiple accounts in a short timeframe, resulting in many failed logons with the same failure reason.',
  tacticId: 'TA0006', tacticName: 'Credential Access',
  techniqueId: 'T1110.003', techniqueName: 'Password Spraying',
  logsource: { product: 'windows', service: 'security' },
  sigmaYaml: `title: Password Spraying Attack Detection
id: a0123456-abcd-6789-0123-456789abcdef
status: stable
description: Detects password spraying patterns - single password tried against multiple accounts
author: SOC Platform
date: 2024/02/01
logsource:
    product: windows
    service: security
detection:
    selection:
        EventID: 4625
        SubStatus: '0xC000006A'
    filter_machine:
        TargetUserName|endswith: '$'
    condition: selection and not filter_machine
    # Aggregation: count(TargetUserName) by IpAddress > 15 in timeframe 10m
falsepositives:
    - Misconfigured service accounts
    - Password expiry causing multiple failures
level: high
tags:
    - attack.credential_access
    - attack.t1110.003`,
  detectionExplanation: 'Password spraying differs from brute force by using one or few passwords against many accounts rather than many passwords against one account. This avoids account lockout thresholds. The key indicator is SubStatus 0xC000006A (wrong password) against multiple distinct TargetUserName values from the same source IP within a short window. The threshold of 15 unique accounts in 10 minutes effectively separates spraying from normal login failures.',
  requiredLogs: ['Windows Security Event ID 4625 with SubStatus field'],
  logConfig: 'Enable logon failure auditing. Ensure the SubStatus field is captured in your SIEM parsing configuration.',
  falsePositives: ['Service accounts with expired passwords failing against multiple servers', 'Password change propagation delays in multi-DC environments', 'Locked accounts generating cascading failures'],
  tuning: 'Adjust the threshold based on organization size. Set to 15-20 unique accounts for medium organizations, 30+ for large enterprises. Exclude known service account patterns.',
  commonErrors: ['SubStatus field not parsed correctly in SIEM', 'Aggregation window too large causing false positives', 'Not filtering machine accounts ($) causing noise from computer authentication'],
  responseActions: ['Block the source IP immediately', 'Identify all accounts targeted in the spray', 'Force password reset for any accounts where the spray succeeded (check for 4624 after 4625 series)', 'Review the success/failure ratio to determine if any passwords were guessed', 'Enable account lockout policies if not already configured', 'Check for the same pattern against other authentication systems (VPN, OWA, etc.)'],
  threatIntel: { cves: [], cisaKev: false, campaigns: ['Scattered Spider', 'Volt Typhoon'], iocs: [] },
  references: ['https://attack.mitre.org/techniques/T1110/003/']
},
{
  id: 'SR-0027', title: 'LSASS Memory Access - Credential Dumping',
  status: 'stable', severity: 'critical', author: 'SOC Platform', date: '2024-01-15', modified: '2024-12-15',
  category: 'credential-access',
  description: 'Detects attempts to access LSASS process memory for credential dumping using tools like Mimikatz, ProcDump, or direct memory access. LSASS stores plaintext passwords, hashes, and Kerberos tickets.',
  tacticId: 'TA0006', tacticName: 'Credential Access',
  techniqueId: 'T1003.001', techniqueName: 'LSASS Memory',
  logsource: { product: 'windows', category: 'process_access' },
  sigmaYaml: `title: LSASS Memory Access - Credential Dumping
id: b1234567-bcde-7890-1234-567890abcdef
status: stable
description: Detects suspicious access to LSASS process memory
author: SOC Platform
date: 2024/01/15
logsource:
    category: process_access
    product: windows
detection:
    selection:
        TargetImage|endswith: '\\\\lsass.exe'
        GrantedAccess|contains:
            - '0x1010'
            - '0x1038'
            - '0x1fffff'
            - '0x1410'
            - '0x143a'
    filter_system:
        SourceImage|endswith:
            - '\\\\csrss.exe'
            - '\\\\wininit.exe'
            - '\\\\wmiprvse.exe'
            - '\\\\svchost.exe'
            - '\\\\MsMpEng.exe'
    condition: selection and not filter_system
falsepositives:
    - Antivirus scanning LSASS
    - Windows Error Reporting
    - Some legitimate security tools
level: critical
tags:
    - attack.credential_access
    - attack.t1003.001`,
  detectionExplanation: 'LSASS (Local Security Authority Subsystem Service) stores credentials in memory for SSO purposes. Mimikatz and similar tools read LSASS memory using specific access rights (0x1010 = PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_VM_READ). Monitoring for non-system processes accessing LSASS with these permissions is one of the most reliable indicators of credential theft in progress.',
  requiredLogs: ['Sysmon Event ID 10 (Process Access)'],
  logConfig: 'Deploy Sysmon with process access monitoring. Filter to only capture access to lsass.exe to reduce volume. Consider enabling Windows Credential Guard as compensation.',
  falsePositives: ['Antivirus engines scanning LSASS', 'Windows Error Reporting accessing crashed LSASS', 'Task Manager or Process Explorer viewing running processes'],
  tuning: 'Build a comprehensive allowlist of security products and system processes that legitimately access LSASS. Consider enabling LSA RunAsPPL to prevent usermode access entirely.',
  commonErrors: ['Sysmon Event ID 10 not configured or too broadly filtered', 'Access rights filtering must account for different tool variations', 'LSASS protection (RunAsPPL) masks some access attempts'],
  responseActions: ['CRITICAL: Likely active credential theft', 'Immediately isolate the endpoint', 'Capture memory dump of the source process', 'Assume ALL credentials on the system are compromised', 'Force password reset for all logged-on users', 'Check for lateral movement using stolen credentials', 'Full incident response required'],
  threatIntel: { cves: [], cisaKev: false, campaigns: ['LockBit 3.0', 'ALPHV/BlackCat Ransomware', 'Midnight Blizzard'], iocs: [] },
  references: ['https://attack.mitre.org/techniques/T1003/001/']
},
{
  id: 'SR-0028', title: 'Kerberoasting - Suspicious TGS Requests',
  status: 'stable', severity: 'high', author: 'SOC Platform', date: '2024-03-05', modified: '2024-12-01',
  category: 'active-directory',
  description: 'Detects Kerberoasting attacks by monitoring for anomalous Ticket Granting Service (TGS) requests using weak encryption types (RC4) against service accounts, which can be cracked offline.',
  tacticId: 'TA0006', tacticName: 'Credential Access',
  techniqueId: 'T1558.003', techniqueName: 'Kerberoasting',
  logsource: { product: 'windows', service: 'security' },
  sigmaYaml: `title: Kerberoasting - Suspicious TGS Requests
id: c2345678-cdef-8901-2345-678901abcdef
status: stable
description: Detects Kerberoasting via anomalous TGS ticket requests using RC4 encryption
author: SOC Platform
date: 2024/03/05
logsource:
    product: windows
    service: security
detection:
    selection:
        EventID: 4769
        TicketEncryptionType: '0x17'
        Status: '0x0'
    filter_machine:
        ServiceName|endswith: '$'
    filter_krbtgt:
        ServiceName: 'krbtgt'
    condition: selection and not filter_machine and not filter_krbtgt
    # Aggregation: count(ServiceName) by ClientAddress > 5 in timeframe 5m
falsepositives:
    - Legacy applications using RC4 encryption
    - Systems not configured for AES
level: high
tags:
    - attack.credential_access
    - attack.t1558.003`,
  detectionExplanation: 'Kerberoasting requests TGS tickets for service accounts with SPNs, specifically requesting RC4 encryption (type 0x17) because RC4-encrypted tickets are much faster to crack offline. Normal Kerberos traffic should use AES encryption (0x11 or 0x12). Multiple RC4 TGS requests from a single client in a short period is a strong indicator of Kerberoasting.',
  requiredLogs: ['Windows Security Event ID 4769 (Kerberos TGS Request)'],
  logConfig: 'Enable Kerberos Service Ticket Operations auditing on domain controllers.',
  falsePositives: ['Legacy applications that only support RC4 Kerberos', 'Environments with mixed encryption support during migration', 'Security scanning tools performing SPN enumeration'],
  tuning: 'Monitor encryption type trends. If the environment still uses RC4 legitimately, focus on the volume: more than 5 unique service tickets in 5 minutes from one client. Migrate away from RC4 if possible.',
  commonErrors: ['Event 4769 only logged on domain controllers', 'TicketEncryptionType field must be properly parsed as hex', 'Not filtering krbtgt and machine accounts creates noise'],
  responseActions: ['Identify the requesting user account', 'Check if the user normally interacts with these service accounts', 'Review the service accounts targeted - assess password strength', 'Rotate passwords for all targeted service accounts immediately', 'Implement Group Managed Service Accounts (gMSA) for automatic rotation'],
  threatIntel: { cves: [], cisaKev: false, campaigns: ['Scattered Spider', 'ALPHV/BlackCat Ransomware'], iocs: [] },
  references: ['https://attack.mitre.org/techniques/T1558/003/']
},
{
  id: 'SR-0029', title: 'DCSync Attack - Replication Permission Abuse',
  status: 'stable', severity: 'critical', author: 'SOC Platform', date: '2024-04-01', modified: '2024-12-10',
  category: 'active-directory',
  description: 'Detects DCSync attacks where an attacker uses directory replication permissions to request password hashes from a domain controller, effectively replicating the NTDS.dit database.',
  tacticId: 'TA0006', tacticName: 'Credential Access',
  techniqueId: 'T1003.006', techniqueName: 'DCSync',
  logsource: { product: 'windows', service: 'security' },
  sigmaYaml: `title: DCSync Attack - Replication Permission Abuse
id: d3456789-defa-9012-3456-789012abcdef
status: stable
description: Detects DCSync by monitoring directory replication from non-DC sources
author: SOC Platform
date: 2024/04/01
logsource:
    product: windows
    service: security
detection:
    selection:
        EventID: 4662
        Properties|contains:
            - '1131f6aa-9c07-11d1-f79f-00c04fc2dcd2'
            - '1131f6ad-9c07-11d1-f79f-00c04fc2dcd2'
            - '89e95b76-444d-4c62-991a-0facbeda640c'
    filter_dc:
        SubjectUserName|endswith: '$'
        # Additional filter: SubjectUserName should match known DC computer accounts
    condition: selection and not filter_dc
falsepositives:
    - Legitimate domain controller replication
    - Azure AD Connect synchronization
level: critical
tags:
    - attack.credential_access
    - attack.t1003.006`,
  detectionExplanation: 'DCSync abuses the DS-Replication-Get-Changes-All permission (GUID: 1131f6ad-9c07-11d1-f79f-00c04fc2dcd2) to request password data from a domain controller, mimicking the behavior of a replication partner DC. The critical detection indicator is these replication GUIDs being accessed by non-DC machine accounts or user accounts, which should never need replication permissions.',
  requiredLogs: ['Windows Security Event ID 4662 (Directory Service Access)', 'Windows Security Event ID 4624 for correlation'],
  logConfig: 'Enable DS Access auditing on domain controllers: Audit Directory Service Access (Success). Ensure SACL is configured on the domain object.',
  falsePositives: ['Legitimate DC-to-DC replication (filter by known DC accounts)', 'Azure AD Connect service account performing synchronization', 'Third-party AD synchronization tools'],
  tuning: 'Maintain a list of all legitimate domain controller computer accounts and the Azure AD Connect service account. Any replication from accounts not on this list is suspicious.',
  commonErrors: ['Event 4662 requires specific DS Access auditing configuration', 'The replication GUIDs must be properly matched - partial matching will miss events', 'Azure AD Connect creates legitimate replication traffic'],
  responseActions: ['CRITICAL: This indicates domain-level compromise', 'Immediately identify the requesting account and machine', 'Assume ALL domain credentials are compromised', 'Initiate full KRBTGT password reset (twice)', 'Reset all privileged account passwords', 'Full domain-wide incident response', 'Investigate how the attacker obtained replication permissions'],
  threatIntel: { cves: ['CVE-2020-1472'], cisaKev: true, campaigns: ['Volt Typhoon', 'Midnight Blizzard'], iocs: [] },
  references: ['https://attack.mitre.org/techniques/T1003/006/']
},
{
  id: 'SR-0030', title: 'Credential Access from Web Browsers',
  status: 'stable', severity: 'medium', author: 'SOC Platform', date: '2024-05-10', modified: '2024-11-20',
  category: 'credential-access',
  description: 'Detects access to browser credential stores (Chrome Login Data, Firefox logins.json) by non-browser processes, indicating credential theft from saved passwords.',
  tacticId: 'TA0006', tacticName: 'Credential Access',
  techniqueId: 'T1555.003', techniqueName: 'Credentials from Web Browsers',
  logsource: { product: 'windows', category: 'file_access' },
  sigmaYaml: `title: Credential Access from Web Browsers
id: e4567890-efab-0123-4567-890123abcdef
status: stable
description: Detects non-browser access to browser credential stores
author: SOC Platform
date: 2024/05/10
logsource:
    category: file_access
    product: windows
detection:
    selection:
        TargetFilename|endswith:
            - '\\\\Login Data'
            - '\\\\logins.json'
            - '\\\\Web Data'
            - '\\\\Cookies'
            - '\\\\Local State'
    filter_browsers:
        Image|endswith:
            - '\\\\chrome.exe'
            - '\\\\msedge.exe'
            - '\\\\firefox.exe'
            - '\\\\brave.exe'
    filter_system:
        Image|endswith:
            - '\\\\System'
            - '\\\\svchost.exe'
    condition: selection and not filter_browsers and not filter_system
falsepositives:
    - Browser extensions accessing credential stores
    - Password managers syncing browser credentials
    - Backup software
level: medium
tags:
    - attack.credential_access
    - attack.t1555.003`,
  detectionExplanation: 'Browsers store saved passwords in local database files (Chrome uses "Login Data" SQLite DB, Firefox uses "logins.json"). Credential stealers like RedLine, Raccoon, and Vidar directly access these files to extract saved passwords. Any process other than the browser itself accessing these files is suspicious.',
  requiredLogs: ['Sysmon Event ID 11 (File Creation) or file access auditing'],
  logConfig: 'Configure file access auditing on browser credential store paths or use Sysmon file monitoring.',
  falsePositives: ['Password manager applications syncing credentials', 'Browser update processes accessing data files', 'Backup software including browser data'],
  tuning: 'Allowlist known password managers and backup tools. Focus on access by script interpreters (PowerShell, Python) or unsigned executables.',
  commonErrors: ['File access monitoring may not be enabled by default', 'Browser profile paths vary by user and browser version'],
  responseActions: ['Identify the process accessing the credential store', 'Quarantine the process executable for analysis', 'Assume all saved browser passwords are compromised', 'Force password reset for all accounts with saved credentials', 'Check for data exfiltration of the stolen credentials'],
  threatIntel: { cves: [], cisaKev: false, campaigns: [], iocs: [] },
  references: ['https://attack.mitre.org/techniques/T1555/003/']
},
{
  id: 'SR-0031', title: 'AS-REP Roasting Attack Detection',
  status: 'stable', severity: 'high', author: 'SOC Platform', date: '2024-06-15', modified: '2024-12-05',
  category: 'active-directory',
  description: 'Detects AS-REP Roasting by monitoring for Kerberos AS-REQ tickets for accounts configured with "Do not require Kerberos preauthentication", allowing offline cracking.',
  tacticId: 'TA0006', tacticName: 'Credential Access',
  techniqueId: 'T1558.004', techniqueName: 'AS-REP Roasting',
  logsource: { product: 'windows', service: 'security' },
  sigmaYaml: `title: AS-REP Roasting Attack Detection
id: f5678901-fabc-1234-5678-901234abcdef
status: stable
description: Detects AS-REP Roasting via Kerberos pre-authentication failures
author: SOC Platform
date: 2024/06/15
logsource:
    product: windows
    service: security
detection:
    selection:
        EventID: 4768
        PreAuthType: 0
        TicketEncryptionType: '0x17'
    filter_disabled:
        Status: '0x6'
    condition: selection and not filter_disabled
    # Aggregation: count(TargetUserName) by IpAddress > 3 in timeframe 5m
falsepositives:
    - Legitimate accounts with pre-auth disabled
    - Legacy systems
level: high
tags:
    - attack.credential_access
    - attack.t1558.004`,
  detectionExplanation: 'AS-REP Roasting targets accounts with Kerberos pre-authentication disabled. For these accounts, the KDC returns an AS-REP message encrypted with the users password hash, which can be cracked offline. The detection monitors for AS-REQ with PreAuthType 0 and RC4 encryption, especially when multiple such requests originate from a single source.',
  requiredLogs: ['Windows Security Event ID 4768 (Kerberos AS-REQ)'],
  logConfig: 'Enable Kerberos Authentication Service auditing on domain controllers.',
  falsePositives: ['Accounts legitimately configured without pre-authentication (audit and fix these)', 'Legacy UNIX/Linux Kerberos clients'],
  tuning: 'First audit: find all accounts with pre-auth disabled and fix them. Once fixed, any occurrence of this detection is highly likely malicious.',
  commonErrors: ['Event 4768 only on domain controllers', 'PreAuthType field may not be parsed in all SIEM platforms'],
  responseActions: ['Enable pre-authentication on all identified accounts', 'Rotate passwords for accounts that had pre-auth disabled', 'Identify the source performing the roasting', 'Check for Kerberoasting activity from the same source'],
  threatIntel: { cves: [], cisaKev: false, campaigns: ['Scattered Spider'], iocs: [] },
  references: ['https://attack.mitre.org/techniques/T1558/004/']
},

// ═══════════════════════════════════════════════════════════════
// DISCOVERY (TA0007)
// ═══════════════════════════════════════════════════════════════
{
  id: 'SR-0032', title: 'Active Directory Account Enumeration',
  status: 'stable', severity: 'medium', author: 'SOC Platform', date: '2024-03-15', modified: '2024-11-25',
  category: 'reconnaissance',
  description: 'Detects enumeration of Active Directory accounts using tools like net.exe, dsquery, or PowerShell AD cmdlets, commonly performed during the discovery phase of an attack.',
  tacticId: 'TA0007', tacticName: 'Discovery',
  techniqueId: 'T1087.002', techniqueName: 'Domain Account',
  logsource: { product: 'windows', category: 'process_creation' },
  sigmaYaml: `title: Active Directory Account Enumeration
id: 01234567-0123-abcd-ef01-234567890abc
status: stable
description: Detects AD account enumeration via command-line tools
author: SOC Platform
date: 2024/03/15
logsource:
    category: process_creation
    product: windows
detection:
    selection_net:
        Image|endswith:
            - '\\\\net.exe'
            - '\\\\net1.exe'
        CommandLine|contains:
            - 'user /domain'
            - 'group /domain'
            - 'group "Domain Admins"'
            - 'group "Enterprise Admins"'
            - 'group "Schema Admins"'
    selection_dsquery:
        Image|endswith: '\\\\dsquery.exe'
    selection_ps_ad:
        CommandLine|contains:
            - 'Get-ADUser'
            - 'Get-ADGroup'
            - 'Get-ADComputer'
            - 'Get-ADGroupMember'
            - 'Search-ADAccount'
    selection_ldap:
        CommandLine|contains:
            - 'ldapsearch'
            - 'adfind'
            - 'ADFind.exe'
            - 'bloodhound'
            - 'SharpHound'
    condition: selection_net or selection_dsquery or selection_ps_ad or selection_ldap
falsepositives:
    - IT administrators performing routine queries
    - Inventory and compliance scripts
level: medium
tags:
    - attack.discovery
    - attack.t1087.002`,
  detectionExplanation: 'During the discovery phase, attackers enumerate AD accounts and groups to identify high-value targets (Domain Admins, service accounts). This rule detects common enumeration methods including net.exe, dsquery, AD PowerShell module, and attack tools like BloodHound/SharpHound. While individual commands are common for IT staff, the pattern and context matter.',
  requiredLogs: ['Sysmon Event ID 1', 'Windows Security 4688'],
  logConfig: 'Command line auditing enabled on all endpoints and domain controllers.',
  falsePositives: ['IT administrators performing routine AD queries', 'Automated inventory scripts', 'Help desk personnel checking group membership'],
  tuning: 'Correlate with user role - flag non-IT users running AD queries. Detect rapid succession of multiple discovery commands (3+ in 5 minutes) as higher severity.',
  commonErrors: ['Individual commands are too common to alert on - need aggregation', 'PowerShell AD module used legitimately by many IT processes'],
  responseActions: ['Determine if the user normally performs AD queries', 'Check for preceding suspicious logon activity', 'Look for subsequent lateral movement or privilege escalation', 'If BloodHound/SharpHound detected - immediate escalation required'],
  threatIntel: { cves: [], cisaKev: false, campaigns: ['Volt Typhoon', 'Scattered Spider', 'LockBit 3.0'], iocs: [] },
  references: ['https://attack.mitre.org/techniques/T1087/002/']
},
{
  id: 'SR-0033', title: 'System Information Discovery Commands',
  status: 'stable', severity: 'low', author: 'SOC Platform', date: '2024-04-10', modified: '2024-11-15',
  category: 'reconnaissance',
  description: 'Detects execution of system information discovery commands that attackers use to understand the target environment including OS version, hardware, network config, and installed software.',
  tacticId: 'TA0007', tacticName: 'Discovery',
  techniqueId: 'T1082', techniqueName: 'System Information Discovery',
  logsource: { product: 'windows', category: 'process_creation' },
  sigmaYaml: `title: System Information Discovery Commands
id: 12345678-1234-bcde-f012-345678901bcd
status: stable
description: Detects system enumeration commands in rapid succession
author: SOC Platform
date: 2024/04/10
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image|endswith:
            - '\\\\systeminfo.exe'
            - '\\\\hostname.exe'
            - '\\\\ipconfig.exe'
            - '\\\\netstat.exe'
            - '\\\\arp.exe'
            - '\\\\route.exe'
            - '\\\\nbtstat.exe'
            - '\\\\wmic.exe'
    selection_wmic_queries:
        Image|endswith: '\\\\wmic.exe'
        CommandLine|contains:
            - 'os get'
            - 'computersystem get'
            - 'bios get'
            - 'product get'
            - 'qfe get'
    condition: selection or selection_wmic_queries
    # Recommend: alert when 3+ of these run within 2 minutes from same user
falsepositives:
    - IT administrators troubleshooting
    - Inventory collection scripts
    - Monitoring agents
level: low
tags:
    - attack.discovery
    - attack.t1082`,
  detectionExplanation: 'Attackers use built-in Windows commands to profile the target system. While individual commands are benign, rapid execution of multiple discovery commands in sequence is consistent with post-exploitation enumeration scripts. Focus on the pattern and velocity rather than individual command execution.',
  requiredLogs: ['Sysmon Event ID 1', 'Windows Security 4688'],
  logConfig: 'Standard process creation logging.',
  falsePositives: ['IT troubleshooting sessions', 'Asset inventory scripts running on schedule', 'Monitoring agents collecting system info'],
  tuning: 'Use aggregation: alert only when 3+ discovery commands run within 2 minutes from the same user. This reduces noise while catching enumeration scripts.',
  commonErrors: ['Individual command alerts generate too much noise', 'Scheduled inventory scripts need to be baselined and excluded'],
  responseActions: ['Check the user context and whether this is expected behavior', 'Look for preceding and subsequent suspicious activity', 'Correlate with logon events - new/unusual logon followed by discovery is suspicious'],
  threatIntel: { cves: [], cisaKev: false, campaigns: [], iocs: [] },
  references: ['https://attack.mitre.org/techniques/T1082/']
},
{
  id: 'SR-0034', title: 'Remote System Discovery via Network Scanning',
  status: 'stable', severity: 'medium', author: 'SOC Platform', date: '2024-05-25', modified: '2024-12-01',
  category: 'reconnaissance',
  description: 'Detects network scanning and remote system discovery using tools like ping sweeps, arp scans, net view, and third-party scanning utilities often used before lateral movement.',
  tacticId: 'TA0007', tacticName: 'Discovery',
  techniqueId: 'T1018', techniqueName: 'Remote System Discovery',
  logsource: { product: 'windows', category: 'process_creation' },
  sigmaYaml: `title: Remote System Discovery via Network Scanning
id: 23456789-2345-cdef-0123-456789012cde
status: stable
description: Detects network scanning and host discovery activity
author: SOC Platform
date: 2024/05/25
logsource:
    category: process_creation
    product: windows
detection:
    selection_builtins:
        Image|endswith:
            - '\\\\net.exe'
            - '\\\\net1.exe'
        CommandLine|contains:
            - 'view'
            - 'share'
    selection_scan_tools:
        Image|endswith:
            - '\\\\nmap.exe'
            - '\\\\masscan.exe'
            - '\\\\Advanced IP Scanner'
            - '\\\\nbtscan.exe'
            - '\\\\SoftPerfect Network Scanner.exe'
    selection_ping_sweep:
        Image|endswith: '\\\\ping.exe'
        CommandLine|contains: '-n 1'
    selection_nltest:
        Image|endswith: '\\\\nltest.exe'
        CommandLine|contains:
            - '/dclist:'
            - '/dsgetdc:'
    condition: selection_builtins or selection_scan_tools or selection_ping_sweep or selection_nltest
falsepositives:
    - IT administrators performing network diagnostics
    - Vulnerability scanning tools
level: medium
tags:
    - attack.discovery
    - attack.t1018`,
  detectionExplanation: 'Before lateral movement, attackers need to discover available systems. This rule detects common methods: net view for share enumeration, dedicated scanning tools, ping sweeps with minimal count (-n 1), and nltest for DC discovery. The presence of third-party scanning tools on endpoints is especially suspicious.',
  requiredLogs: ['Sysmon Event ID 1', 'Network flow/firewall logs for port scanning'],
  logConfig: 'Process creation logging. Additionally, configure network monitoring for port scan patterns.',
  falsePositives: ['IT administrators running diagnostics', 'Authorized vulnerability scanners', 'Network monitoring tools'],
  tuning: 'Allowlist authorized scanner IPs. Alert specifically on scanning from workstations which is almost never legitimate.',
  commonErrors: ['Authorized scanning tools not excluded', 'Ping sweep detection may be too noisy without proper thresholds'],
  responseActions: ['Identify why the user is scanning the network', 'Check for authorization/change management ticket', 'If unauthorized: escalate as potential lateral movement preparation', 'Review what systems were discovered and if any were subsequently accessed'],
  threatIntel: { cves: [], cisaKev: false, campaigns: ['Volt Typhoon', 'LockBit 3.0'], iocs: [] },
  references: ['https://attack.mitre.org/techniques/T1018/']
},
{
  id: 'SR-0035', title: 'Domain Group Enumeration',
  status: 'stable', severity: 'medium', author: 'SOC Platform', date: '2024-06-20', modified: '2024-11-30',
  category: 'reconnaissance',
  description: 'Detects enumeration of domain groups, particularly privileged groups like Domain Admins and Enterprise Admins, used to identify high-value targets for privilege escalation.',
  tacticId: 'TA0007', tacticName: 'Discovery',
  techniqueId: 'T1069.002', techniqueName: 'Domain Groups',
  logsource: { product: 'windows', service: 'security' },
  sigmaYaml: `title: Domain Group Enumeration
id: 34567890-3456-defa-1234-567890123def
status: stable
description: Detects enumeration of privileged domain groups
author: SOC Platform
date: 2024/06/20
logsource:
    product: windows
    service: security
detection:
    selection:
        EventID: 4661
        ObjectType: 'SAM_GROUP'
        ObjectName|contains:
            - 'Domain Admins'
            - 'Enterprise Admins'
            - 'Schema Admins'
            - 'Account Operators'
            - 'Backup Operators'
    condition: selection
falsepositives:
    - IT administrators checking group membership
    - Automated compliance reporting
level: medium
tags:
    - attack.discovery
    - attack.t1069.002`,
  detectionExplanation: 'Attackers enumerate privileged domain groups to identify potential escalation paths and high-value targets. Event 4661 captures directory service object access, allowing detection of queries against sensitive group objects. This is particularly significant when performed from non-admin workstations or by non-IT users.',
  requiredLogs: ['Windows Security Event ID 4661 (Handle Request to Object)'],
  logConfig: 'Enable Directory Service Access auditing. SACL must be configured on the groups to monitor.',
  falsePositives: ['IT admins reviewing group membership', 'Compliance tools auditing AD groups', 'Service desk verification of permissions'],
  tuning: 'Focus on non-admin users performing enumeration. Correlate with other discovery activities.',
  commonErrors: ['SACL not configured on the group objects', 'High volume in environments with automated AD queries'],
  responseActions: ['Verify the user identity and business justification', 'Check for subsequent credential access or privilege escalation activity', 'If part of a pattern: escalate as reconnaissance'],
  threatIntel: { cves: [], cisaKev: false, campaigns: ['Scattered Spider'], iocs: [] },
  references: ['https://attack.mitre.org/techniques/T1069/002/']
},

// ═══════════════════════════════════════════════════════════════
// LATERAL MOVEMENT (TA0008)
// ═══════════════════════════════════════════════════════════════
{
  id: 'SR-0036', title: 'Suspicious RDP Connection - Unusual Source',
  status: 'stable', severity: 'high', author: 'SOC Platform', date: '2024-02-20', modified: '2024-12-10',
  category: 'lateral-movement',
  description: 'Detects Remote Desktop Protocol connections from unusual sources, including workstation-to-workstation RDP, first-time source IPs, and connections from external IPs to internal systems.',
  tacticId: 'TA0008', tacticName: 'Lateral Movement',
  techniqueId: 'T1021.001', techniqueName: 'Remote Desktop Protocol',
  logsource: { product: 'windows', service: 'security' },
  sigmaYaml: `title: Suspicious RDP Connection - Unusual Source
id: 45678901-4567-efab-2345-678901234efa
status: stable
description: Detects unusual RDP connections for lateral movement detection
author: SOC Platform
date: 2024/02/20
logsource:
    product: windows
    service: security
detection:
    selection:
        EventID: 4624
        LogonType: 10
    filter_known_jump:
        IpAddress|startswith:
            - '10.0.0.'
            - '172.16.'
    condition: selection
    # Additional context: Compare against baseline of known RDP pairs
falsepositives:
    - IT administrators using RDP for remote management
    - Remote work via VPN + RDP
level: high
tags:
    - attack.lateral_movement
    - attack.t1021.001`,
  detectionExplanation: 'RDP is one of the most commonly abused protocols for lateral movement. While it is legitimately used by IT staff, certain patterns are suspicious: (1) workstation-to-workstation RDP, (2) RDP from a new source IP never seen before, (3) RDP to servers that shouldnt accept remote connections, (4) RDP outside business hours. LogonType 10 specifically indicates Remote Interactive (RDP) logon.',
  requiredLogs: ['Windows Security Event ID 4624 with LogonType 10', 'Event ID 4625 for failed RDP', 'TerminalServices-LocalSessionManager Operational'],
  logConfig: 'Enable logon auditing. Also enable the TerminalServices-LocalSessionManager operational log for additional RDP session details.',
  falsePositives: ['IT administrators performing remote management', 'Remote workers connecting via VPN', 'Help desk using RDP for user support'],
  tuning: 'Baseline known RDP source-destination pairs. Alert on new pairs. Use Network Level Authentication (NLA) to ensure authentication before session establishment.',
  commonErrors: ['NLA pre-auth may generate different event sequence', 'RDP proxied through jump hosts changes the source IP', 'RDP Gateway changes the source IP to the gateway'],
  responseActions: ['Verify the user and source IP', 'Check if the RDP connection was authorized', 'Review activities performed during the RDP session', 'Look for data staging or additional lateral movement from the destination', 'Check for concurrent sessions from different locations'],
  threatIntel: { cves: [], cisaKev: false, campaigns: ['ALPHV/BlackCat Ransomware', 'LockBit 3.0'], iocs: [] },
  references: ['https://attack.mitre.org/techniques/T1021/001/']
},
{
  id: 'SR-0037', title: 'SMB/Admin Share Access for Lateral Movement',
  status: 'stable', severity: 'high', author: 'SOC Platform', date: '2024-03-30', modified: '2024-12-05',
  category: 'lateral-movement',
  description: 'Detects access to administrative shares (C$, ADMIN$, IPC$) commonly used for lateral movement via tools like PsExec, remote service installation, or manual file copy to deploy payloads.',
  tacticId: 'TA0008', tacticName: 'Lateral Movement',
  techniqueId: 'T1021.002', techniqueName: 'SMB/Windows Admin Shares',
  logsource: { product: 'windows', service: 'security' },
  sigmaYaml: `title: SMB/Admin Share Access for Lateral Movement
id: 56789012-5678-fabc-3456-789012345fab
status: stable
description: Detects lateral movement via administrative share access
author: SOC Platform
date: 2024/03/30
logsource:
    product: windows
    service: security
detection:
    selection:
        EventID: 5140
        ShareName|endswith:
            - '\\\\C$'
            - '\\\\ADMIN$'
            - '\\\\IPC$'
    filter_machine:
        SubjectUserName|endswith: '$'
    filter_known:
        IpAddress|startswith:
            - '127.'
    condition: selection and not filter_machine and not filter_known
falsepositives:
    - IT administrators using admin shares for management
    - SCCM software deployment
    - Backup software
level: high
tags:
    - attack.lateral_movement
    - attack.t1021.002`,
  detectionExplanation: 'Administrative shares (C$, ADMIN$, IPC$) provide remote access to system resources. Attackers use these for: (1) copying malware to target systems via C$, (2) deploying services via ADMIN$ (PsExec method), (3) establishing named pipes via IPC$ for remote execution. Event 5140 captures all network share access events.',
  requiredLogs: ['Windows Security Event ID 5140 (Share Access)', 'Event ID 5145 for detailed file access within shares'],
  logConfig: 'Enable Object Access auditing: Audit File Share. Also consider enabling Audit Detailed File Share for file-level visibility within shares.',
  falsePositives: ['IT admin tools using admin shares', 'SCCM package deployment', 'Enterprise backup solutions', 'Domain controller SYSVOL replication'],
  tuning: 'Allowlist known management tools and service accounts. Focus on user accounts (not machine accounts) accessing admin shares, especially from workstations.',
  commonErrors: ['Event 5140 not enabled by default', 'Machine account filtering removes legitimate replication but is necessary to reduce noise', 'SCCM generates significant legitimate admin share traffic'],
  responseActions: ['Identify who accessed the admin share and from where', 'Check what files were copied via the share', 'Look for new services installed shortly after admin share access', 'Check for PsExec artifacts (PSEXESVC.exe service)', 'Investigate the source system for compromise'],
  threatIntel: { cves: [], cisaKev: false, campaigns: ['LockBit 3.0', 'ALPHV/BlackCat Ransomware', 'Volt Typhoon'], iocs: [] },
  references: ['https://attack.mitre.org/techniques/T1021/002/']
},
{
  id: 'SR-0038', title: 'WinRM Lateral Movement Detection',
  status: 'stable', severity: 'high', author: 'SOC Platform', date: '2024-05-01', modified: '2024-11-20',
  category: 'lateral-movement',
  description: 'Detects Windows Remote Management (WinRM) connections used for lateral movement, including both PowerShell Remoting (Enter-PSSession, Invoke-Command) and raw WinRM.',
  tacticId: 'TA0008', tacticName: 'Lateral Movement',
  techniqueId: 'T1021.006', techniqueName: 'Windows Remote Management',
  logsource: { product: 'windows', category: 'process_creation' },
  sigmaYaml: `title: WinRM Lateral Movement Detection
id: 67890123-6789-0123-4567-890123456012
status: stable
description: Detects WinRM/PSRemoting usage for lateral movement
author: SOC Platform
date: 2024/05/01
logsource:
    category: process_creation
    product: windows
detection:
    selection_wsmprovhost:
        ParentImage|endswith: '\\\\wsmprovhost.exe'
    selection_psremoting:
        CommandLine|contains:
            - 'Enter-PSSession'
            - 'Invoke-Command'
            - 'New-PSSession'
            - '-ComputerName'
    selection_winrm_svc:
        Image|endswith: '\\\\winrshost.exe'
    condition: selection_wsmprovhost or selection_psremoting or selection_winrm_svc
falsepositives:
    - IT administrators using PowerShell Remoting
    - Automation scripts using Invoke-Command
    - DSC configurations
level: high
tags:
    - attack.lateral_movement
    - attack.t1021.006`,
  detectionExplanation: 'WinRM/PSRemoting provides a powerful remote execution capability. On the receiving end, wsmprovhost.exe hosts the remote session and spawns child processes. On the initiating end, Enter-PSSession and Invoke-Command cmdlets are used. This rule monitors both ends: suspicious child processes of wsmprovhost.exe on targets, and PSRemoting commands on source systems.',
  requiredLogs: ['Sysmon Event ID 1', 'WinRM Operational Log', 'PowerShell Script Block Logging'],
  logConfig: 'Enable WinRM operational logging. Deploy Sysmon on all potential targets.',
  falsePositives: ['IT automation using PSRemoting', 'DSC push configurations', 'SCCM remote script execution'],
  tuning: 'Baseline legitimate PSRemoting usage. Alert on PSRemoting from workstations to workstations (unusual) or to unexpected server targets.',
  commonErrors: ['WinRM logs not enabled on target systems', 'PSRemoting over SSH may use different process chain'],
  responseActions: ['Identify the source and target systems', 'Check what commands were run remotely', 'Review PowerShell transcription logs on the target', 'Investigate source system for compromise indicators'],
  threatIntel: { cves: [], cisaKev: false, campaigns: ['Volt Typhoon'], iocs: [] },
  references: ['https://attack.mitre.org/techniques/T1021/006/']
},
{
  id: 'SR-0039', title: 'Pass-the-Hash Attack Detection',
  status: 'stable', severity: 'critical', author: 'SOC Platform', date: '2024-06-01', modified: '2024-12-10',
  category: 'lateral-movement',
  description: 'Detects Pass-the-Hash attacks by monitoring for NTLM authentication with specific logon process and authentication package indicators that distinguish PtH from normal logons.',
  tacticId: 'TA0008', tacticName: 'Lateral Movement',
  techniqueId: 'T1550.002', techniqueName: 'Pass the Hash',
  logsource: { product: 'windows', service: 'security' },
  sigmaYaml: `title: Pass-the-Hash Attack Detection
id: 78901234-7890-1234-5678-901234567123
status: stable
description: Detects Pass-the-Hash via NTLM logon anomalies
author: SOC Platform
date: 2024/06/01
logsource:
    product: windows
    service: security
detection:
    selection:
        EventID: 4624
        LogonType: 9
        LogonProcessName: 'seclogo'
        AuthenticationPackageName: 'Negotiate'
    selection_ntlm:
        EventID: 4624
        LogonType: 3
        AuthenticationPackageName: 'NTLM'
        KeyLength: 0
    condition: selection or selection_ntlm
falsepositives:
    - Legitimate NTLM authentication in mixed environments
    - Runas /netonly usage
level: critical
tags:
    - attack.lateral_movement
    - attack.t1550.002`,
  detectionExplanation: 'Pass-the-Hash uses stolen NTLM hashes instead of plaintext passwords for authentication. Key indicators: (1) LogonType 9 with seclogo process indicates RunAs/PtH from the initiating system, (2) NTLM authentication with KeyLength 0 on the target indicates an older (and suspicious) NTLM authentication. These patterns, combined with the authentication package being NTLM rather than Kerberos, help identify PtH activity.',
  requiredLogs: ['Windows Security Event ID 4624 with full authentication details'],
  logConfig: 'Enable detailed logon auditing. Ensure NTLM auditing is configured via GPO: Network Security: Restrict NTLM policies.',
  falsePositives: ['Systems that genuinely cannot use Kerberos', 'Cross-forest authentication using NTLM fallback', 'Administrative use of runas /netonly'],
  tuning: 'Focus on LogonType 9 events from non-admin systems. Monitor for NTLM usage where Kerberos is expected. Implement NTLM audit mode before blocking.',
  commonErrors: ['NTLM audit fields may not be parsed by all SIEM platforms', 'KeyLength field may have different meanings across Windows versions'],
  responseActions: ['CRITICAL: Active credential abuse in progress', 'Identify the source of the hash (which system was dumped)', 'Block the source IP', 'Reset the compromised account password', 'Check for additional lateral movement from the target', 'Review all NTLM logons from the source in the past 24 hours'],
  threatIntel: { cves: [], cisaKev: false, campaigns: ['Scattered Spider', 'Midnight Blizzard'], iocs: [] },
  references: ['https://attack.mitre.org/techniques/T1550/002/']
},
{
  id: 'SR-0040', title: 'Lateral Tool Transfer via SMB',
  status: 'stable', severity: 'high', author: 'SOC Platform', date: '2024-07-10', modified: '2024-11-30',
  category: 'lateral-movement',
  description: 'Detects transfer of potentially malicious tools and executables through SMB shares, a common method for staging attack tools on target systems during lateral movement.',
  tacticId: 'TA0008', tacticName: 'Lateral Movement',
  techniqueId: 'T1570', techniqueName: 'Lateral Tool Transfer',
  logsource: { product: 'windows', service: 'security' },
  sigmaYaml: `title: Lateral Tool Transfer via SMB
id: 89012345-8901-2345-6789-012345678234
status: stable
description: Detects suspicious file transfers over SMB shares
author: SOC Platform
date: 2024/07/10
logsource:
    product: windows
    service: security
detection:
    selection:
        EventID: 5145
        AccessMask: '0x2'
        RelativeTargetName|endswith:
            - '.exe'
            - '.dll'
            - '.ps1'
            - '.bat'
            - '.cmd'
            - '.vbs'
            - '.hta'
            - '.scr'
    filter_known_shares:
        ShareName|endswith:
            - '\\\\SYSVOL'
            - '\\\\NETLOGON'
    condition: selection and not filter_known_shares
falsepositives:
    - Software deployment via network shares
    - IT distributing scripts through shares
level: high
tags:
    - attack.lateral_movement
    - attack.t1570`,
  detectionExplanation: 'Monitors for executable files (EXE, DLL, scripts) being written (AccessMask 0x2 = Write) to SMB network shares. Attackers commonly transfer their tools to remote systems via network shares before executing them. This detection excludes SYSVOL and NETLOGON which legitimately contain scripts and GPO executables.',
  requiredLogs: ['Windows Security Event ID 5145 (Detailed File Share)'],
  logConfig: 'Enable Detailed File Share auditing. This generates high volume - consider filtering to only executable file types.',
  falsePositives: ['Software deployment pushing executables to shares', 'IT scripts distributed via shares', 'User sharing executable files for legitimate purposes'],
  tuning: 'Allowlist known deployment shares. Focus on admin shares (C$, ADMIN$) and user-created shares. Correlate with subsequent execution events.',
  commonErrors: ['Event 5145 generates very high volume', 'AccessMask filtering must account for different access types'],
  responseActions: ['Identify what file was transferred and analyze it', 'Check the source system for compromise', 'Determine if the transferred file was executed', 'Quarantine the file on the destination system'],
  threatIntel: { cves: [], cisaKev: false, campaigns: ['LockBit 3.0', 'ALPHV/BlackCat Ransomware'], iocs: [] },
  references: ['https://attack.mitre.org/techniques/T1570/']
},

// ═══════════════════════════════════════════════════════════════
// COLLECTION (TA0009)
// ═══════════════════════════════════════════════════════════════
{
  id: 'SR-0041', title: 'Data Staging via Archive Utilities',
  status: 'stable', severity: 'medium', author: 'SOC Platform', date: '2024-04-15', modified: '2024-11-25',
  category: 'collection',
  description: 'Detects use of archive utilities (7-Zip, WinRAR, tar) to compress files for collection and staging prior to exfiltration, especially targeting sensitive file types or locations.',
  tacticId: 'TA0009', tacticName: 'Collection',
  techniqueId: 'T1560.001', techniqueName: 'Archive via Utility',
  logsource: { product: 'windows', category: 'process_creation' },
  sigmaYaml: `title: Data Staging via Archive Utilities
id: 90123456-9012-3456-7890-123456789345
status: stable
description: Detects suspicious use of archive tools for data staging
author: SOC Platform
date: 2024/04/15
logsource:
    category: process_creation
    product: windows
detection:
    selection_7z:
        Image|endswith:
            - '\\\\7z.exe'
            - '\\\\7za.exe'
        CommandLine|contains: 'a '
    selection_rar:
        Image|endswith: '\\\\rar.exe'
        CommandLine|contains: 'a '
    selection_tar:
        Image|endswith: '\\\\tar.exe'
    selection_zip_ps:
        CommandLine|contains:
            - 'Compress-Archive'
            - 'ZipFile'
            - 'CreateFromDirectory'
    selection_sensitive:
        CommandLine|contains:
            - '\\\\Documents\\\\'
            - '\\\\Desktop\\\\'
            - '\\\\Finance\\\\'
            - '\\\\HR\\\\'
            - '\\\\Confidential\\\\'
            - '-p'
            - '-password'
    condition: (selection_7z or selection_rar or selection_tar or selection_zip_ps) and selection_sensitive
falsepositives:
    - Users archiving their own files
    - Backup scripts
level: medium
tags:
    - attack.collection
    - attack.t1560.001`,
  detectionExplanation: 'Before exfiltration, attackers collect and compress target data using archive utilities. This rule focuses on the combination of archive tool usage with sensitive content indicators (targeting Documents, Finance, HR directories) or password-protected archives (using -p flag). Password-protected archives are particularly suspicious as they indicate intent to evade DLP controls.',
  requiredLogs: ['Sysmon Event ID 1', 'Windows Security 4688'],
  logConfig: 'Command line auditing with full argument capture.',
  falsePositives: ['Users legitimately archiving their work files', 'Automated backup jobs', 'File migration activities'],
  tuning: 'Focus on password-protected archives and archiving from network shares. Correlate with subsequent network activity to detect exfiltration.',
  commonErrors: ['7z.exe may be in various paths - use endswith matching', 'PowerShell Compress-Archive used legitimately in scripts'],
  responseActions: ['Identify what files were archived', 'Check if the archive was subsequently transferred off the network', 'Review the users recent activity for other collection indicators', 'Determine if this aligns with insider threat or external attacker behavior'],
  threatIntel: { cves: [], cisaKev: false, campaigns: ['Midnight Blizzard'], iocs: [] },
  references: ['https://attack.mitre.org/techniques/T1560/001/']
},
{
  id: 'SR-0042', title: 'Keylogging Activity Detection',
  status: 'stable', severity: 'high', author: 'SOC Platform', date: '2024-05-20', modified: '2024-12-01',
  category: 'collection',
  description: 'Detects indicators of keylogging activity including known keylogger processes, suspicious API calls for keyboard hooks, and creation of key log files.',
  tacticId: 'TA0009', tacticName: 'Collection',
  techniqueId: 'T1056.001', techniqueName: 'Keylogging',
  logsource: { product: 'windows', category: 'process_creation' },
  sigmaYaml: `title: Keylogging Activity Detection
id: 01234567-0123-4567-8901-234567890456
status: stable
description: Detects keylogging tools and behaviors
author: SOC Platform
date: 2024/05/20
logsource:
    category: process_creation
    product: windows
detection:
    selection_tools:
        Image|endswith:
            - '\\\\keylogger.exe'
            - '\\\\kl.exe'
    selection_api:
        CommandLine|contains:
            - 'SetWindowsHookEx'
            - 'GetAsyncKeyState'
            - 'GetKeyState'
            - 'GetKeyboardState'
            - 'LowLevelKeyboardProc'
    selection_files:
        CommandLine|contains:
            - 'keylog'
            - 'keystroke'
            - 'keystrokes.txt'
    condition: selection_tools or selection_api or selection_files
falsepositives:
    - Accessibility software
    - Parental control applications
    - Legitimate keyboard macro software
level: high
tags:
    - attack.collection
    - attack.t1056.001`,
  detectionExplanation: 'Keyloggers capture every keystroke including passwords and sensitive data. Detection focuses on three vectors: (1) known keylogger tools by name, (2) Windows API functions used for keyboard hooking visible in command lines or script content, (3) output files with keylog-related naming. While API-based detection requires deeper instrumentation, file and process-based detection provides good initial coverage.',
  requiredLogs: ['Sysmon Event ID 1', 'Sysmon Event ID 11 (File Creation)'],
  logConfig: 'Process creation and file creation monitoring. For API hooking detection, consider EDR telemetry.',
  falsePositives: ['Accessibility software using keyboard hooks', 'Keyboard macro/shortcut applications', 'Parental monitoring software'],
  tuning: 'Allowlist known accessibility and productivity software. EDR-based detection of SetWindowsHookEx provides better coverage than command-line matching.',
  commonErrors: ['Most sophisticated keyloggers wont have "keylogger" in the name', 'API detection via process creation is limited - EDR provides better visibility'],
  responseActions: ['Identify the keylogging software and its capabilities', 'Determine the time period it was active', 'Assume all typed credentials during that period are compromised', 'Force password reset for all accounts used', 'Collect the keylog output file for evidence'],
  threatIntel: { cves: [], cisaKev: false, campaigns: [], iocs: [] },
  references: ['https://attack.mitre.org/techniques/T1056/001/']
},
{
  id: 'SR-0043', title: 'Screen Capture Activity',
  status: 'test', severity: 'medium', author: 'SOC Platform', date: '2024-07-01', modified: '2024-11-15',
  category: 'collection',
  description: 'Detects automated screen capture activity through known screenshot tools or suspicious scheduled screen capture operations that may indicate espionage or surveillance malware.',
  tacticId: 'TA0009', tacticName: 'Collection',
  techniqueId: 'T1113', techniqueName: 'Screen Capture',
  logsource: { product: 'windows', category: 'process_creation' },
  sigmaYaml: `title: Screen Capture Activity
id: 12345678-1234-5678-9012-345678901567
status: test
description: Detects automated or suspicious screen capture activity
author: SOC Platform
date: 2024/07/01
logsource:
    category: process_creation
    product: windows
detection:
    selection_nircmd:
        Image|endswith: '\\\\nircmd.exe'
        CommandLine|contains: 'savescreenshot'
    selection_ps_screenshot:
        CommandLine|contains:
            - 'CopyFromScreen'
            - 'System.Drawing.Bitmap'
            - 'screenshot'
    selection_import:
        CommandLine|contains:
            - 'Import-Module.*screen'
            - 'Get-Screenshot'
    condition: selection_nircmd or selection_ps_screenshot or selection_import
falsepositives:
    - Legitimate screenshot utilities
    - Automated testing frameworks
    - Support tools capturing screen for troubleshooting
level: medium
tags:
    - attack.collection
    - attack.t1113`,
  detectionExplanation: 'Screen capture malware periodically takes screenshots to collect visual information about the victims activities. This rule detects NirCmd (a common dual-use tool used for screenshots) and PowerShell/.NET methods for programmatic screen capture. Automated, repeated captures are particularly suspicious.',
  requiredLogs: ['Sysmon Event ID 1', 'PowerShell Script Block Logging'],
  logConfig: 'Standard process creation and script block logging.',
  falsePositives: ['Screen recording software', 'Automated UI testing tools', 'IT support screen capture utilities'],
  tuning: 'Correlate with volume - a single screenshot may be legitimate, but periodic captures are suspicious. Add time-based aggregation.',
  commonErrors: ['Many legitimate applications take screenshots', 'Built-in Snipping Tool/PrintScreen wont trigger this rule'],
  responseActions: ['Identify the capturing process', 'Check where screenshots are being saved', 'Look for exfiltration of captured images', 'Check for other collection activities from the same process'],
  threatIntel: { cves: [], cisaKev: false, campaigns: ['Midnight Blizzard'], iocs: [] },
  references: ['https://attack.mitre.org/techniques/T1113/']
},

// ═══════════════════════════════════════════════════════════════
// COMMAND AND CONTROL (TA0011)
// ═══════════════════════════════════════════════════════════════
{
  id: 'SR-0044', title: 'Suspicious DNS Query - DGA or Tunneling',
  status: 'stable', severity: 'high', author: 'SOC Platform', date: '2024-01-20', modified: '2024-12-10',
  category: 'network-anomalies',
  description: 'Detects suspicious DNS queries that may indicate Domain Generation Algorithm (DGA) activity or DNS tunneling for command and control communication.',
  tacticId: 'TA0011', tacticName: 'Command and Control',
  techniqueId: 'T1071.004', techniqueName: 'DNS',
  logsource: { product: 'windows', category: 'dns_query' },
  sigmaYaml: `title: Suspicious DNS Query - DGA or Tunneling
id: 23456789-2345-6789-0123-456789012678
status: stable
description: Detects DNS queries indicative of DGA or tunneling
author: SOC Platform
date: 2024/01/20
logsource:
    category: dns_query
    product: windows
detection:
    selection_long:
        QueryName|re: '^[a-z0-9]{20,}\\\\.'
    selection_high_entropy:
        QueryName|re: '^[a-z0-9\\\\-]{8,}\\\\.(?!microsoft|google|amazon|cloudflare)'
    selection_txt:
        QueryType: 'TXT'
    selection_unusual_tld:
        QueryName|endswith:
            - '.xyz'
            - '.top'
            - '.club'
            - '.info'
            - '.tk'
            - '.ml'
            - '.ga'
            - '.cf'
    condition: selection_long or (selection_txt and selection_high_entropy) or selection_unusual_tld
falsepositives:
    - CDN and cloud service domains with long names
    - Legitimate services using TXT records
level: high
tags:
    - attack.command_and_control
    - attack.t1071.004`,
  detectionExplanation: 'DNS-based C2 and DGA share common indicators: (1) Very long subdomain labels (20+ chars) suggest data encoding in queries, (2) High-entropy domain names indicate algorithmically generated domains, (3) Excessive TXT record queries may indicate DNS tunneling (data in TXT responses), (4) Free/suspicious TLDs commonly used for malware infrastructure. This multi-indicator approach provides balance between detection rate and false positives.',
  requiredLogs: ['Sysmon Event ID 22 (DNS Query)', 'DNS Server logs', 'DNS firewall/proxy logs'],
  logConfig: 'Deploy Sysmon with DNS query logging (Event ID 22). Also configure DNS server query logging for server-side visibility.',
  falsePositives: ['CDN services with long domain names', 'DKIM/SPF/DMARC TXT lookups', 'Legitimate services on newer TLDs', 'Anti-spam services performing DNS lookups'],
  tuning: 'Maintain an allowlist of known-good long domains (CDN providers). Use Shannon entropy calculation for more accurate DGA detection. Set volume threshold for TXT query alerts.',
  commonErrors: ['DNS query logging can be high-volume', 'Base64/hex-encoded subdomains may not match simple regex', 'Legitimate IDN domains may appear as high-entropy'],
  responseActions: ['Analyze the queried domains for known malware infrastructure', 'Check DNS response data for encoded commands', 'Block the domains at DNS firewall level', 'Identify all endpoints querying these domains', 'Investigate the process making the DNS queries'],
  threatIntel: { cves: [], cisaKev: false, campaigns: ['Midnight Blizzard'], iocs: [] },
  references: ['https://attack.mitre.org/techniques/T1071/004/', 'https://attack.mitre.org/techniques/T1568/002/']
},
{
  id: 'SR-0045', title: 'Ingress Tool Transfer via CertUtil or BITSAdmin',
  status: 'stable', severity: 'high', author: 'SOC Platform', date: '2024-02-25', modified: '2024-12-01',
  category: 'windows-specific',
  description: 'Detects use of living-off-the-land binaries (CertUtil, BITSAdmin) to download files from external sources, a common technique for downloading malware without triggering standard download monitoring.',
  tacticId: 'TA0011', tacticName: 'Command and Control',
  techniqueId: 'T1105', techniqueName: 'Ingress Tool Transfer',
  logsource: { product: 'windows', category: 'process_creation' },
  sigmaYaml: `title: Ingress Tool Transfer via CertUtil or BITSAdmin
id: 34567890-3456-7890-1234-567890123789
status: stable
description: Detects LOLBin usage for downloading remote payloads
author: SOC Platform
date: 2024/02/25
logsource:
    category: process_creation
    product: windows
detection:
    selection_certutil:
        Image|endswith: '\\\\certutil.exe'
        CommandLine|contains:
            - 'urlcache'
            - '-decode'
            - '/decode'
            - 'http'
    selection_bitsadmin:
        Image|endswith: '\\\\bitsadmin.exe'
        CommandLine|contains:
            - '/transfer'
            - '/create'
            - '/addfile'
            - 'http'
    selection_other:
        Image|endswith:
            - '\\\\curl.exe'
            - '\\\\wget.exe'
        CommandLine|contains:
            - 'http'
    condition: selection_certutil or selection_bitsadmin or selection_other
falsepositives:
    - Legitimate certificate operations using certutil
    - BITS-based software updates (SCCM)
level: high
tags:
    - attack.command_and_control
    - attack.t1105`,
  detectionExplanation: 'CertUtil and BITSAdmin are legitimate Windows utilities that can download files from URLs. Attackers prefer these over PowerShells Invoke-WebRequest because they are less monitored. CertUtil with -urlcache downloads and caches files; BITSAdmin creates download jobs. Unlike browser downloads, these bypass web content filters in many environments.',
  requiredLogs: ['Sysmon Event ID 1', 'Windows Security 4688', 'BITS Client logs'],
  logConfig: 'Command line auditing. Also monitor BITS Client operational log for download job tracking.',
  falsePositives: ['Legitimate certificate enrollment using certutil', 'SCCM/WSUS using BITS for updates', 'Administrative scripts downloading patches'],
  tuning: 'Differentiate between certutil -urlcache (download - suspicious) and certutil -verify/-addstore (normal cert operations). Allow known SCCM BITS operations.',
  commonErrors: ['certutil legitimate cert operations flagged as false positives', 'BITS jobs may complete asynchronously making correlation difficult'],
  responseActions: ['Determine the URL that was downloaded from', 'Analyze the downloaded file', 'Block the URL at proxy/firewall', 'Search for the downloaded file hash across all endpoints', 'Check if the downloaded file was executed'],
  threatIntel: { cves: [], cisaKev: false, campaigns: ['Volt Typhoon', 'LockBit 3.0'], iocs: [] },
  references: ['https://attack.mitre.org/techniques/T1105/', 'https://lolbas-project.github.io/']
},
{
  id: 'SR-0046', title: 'Remote Access Tool Execution',
  status: 'stable', severity: 'high', author: 'SOC Platform', date: '2024-04-01', modified: '2024-12-15',
  category: 'endpoint-anomalies',
  description: 'Detects execution of remote access tools (RATs) including legitimate commercial tools abused by attackers such as AnyDesk, TeamViewer, ConnectWise, and others.',
  tacticId: 'TA0011', tacticName: 'Command and Control',
  techniqueId: 'T1219', techniqueName: 'Remote Access Software',
  logsource: { product: 'windows', category: 'process_creation' },
  sigmaYaml: `title: Remote Access Tool Execution
id: 45678901-4567-8901-2345-678901234890
status: stable
description: Detects execution of remote access tools commonly abused by attackers
author: SOC Platform
date: 2024/04/01
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image|endswith:
            - '\\\\AnyDesk.exe'
            - '\\\\TeamViewer.exe'
            - '\\\\ScreenConnect.Client.exe'
            - '\\\\RemoteDesktopManager.exe'
            - '\\\\LogMeIn.exe'
            - '\\\\Supremo.exe'
            - '\\\\Splashtop'
            - '\\\\rustdesk.exe'
            - '\\\\meshagent.exe'
            - '\\\\ngrok.exe'
    selection_portable:
        Image|contains:
            - '\\\\Temp\\\\'
            - '\\\\Downloads\\\\'
            - '\\\\AppData\\\\Local\\\\Temp\\\\'
            - '\\\\Users\\\\Public\\\\'
    condition: selection or selection_portable
falsepositives:
    - IT support using authorized remote access tools
    - Vendor remote support sessions
level: high
tags:
    - attack.command_and_control
    - attack.t1219`,
  detectionExplanation: 'Legitimate remote access tools are increasingly abused by attackers as C2 channels because they are signed software, often allowlisted, and provide full remote control capabilities. The key discrimination is whether the tool is authorized and expected. Running from temporary or download directories suggests unauthorized installation. Ngrok is particularly dangerous as it tunnels through NAT/firewalls.',
  requiredLogs: ['Sysmon Event ID 1', 'Application Installation logs'],
  logConfig: 'Process creation monitoring. Consider application whitelisting to block unauthorized RATs.',
  falsePositives: ['IT help desk using approved remote tools', 'Vendor support requiring remote access', 'Personal remote access configured by users'],
  tuning: 'Define which RATs are approved for the organization. Alert on any non-approved tools. Even for approved tools, alert when run from unusual paths.',
  commonErrors: ['Many tools renamed by attackers - consider hash-based detection', 'Some RATs install as services and may not appear in process creation'],
  responseActions: ['Determine if the RAT is authorized', 'If unauthorized: terminate the process and block the service', 'Check for any sessions established through the RAT', 'Review what actions were performed during remote sessions', 'Block the RAT application at the firewall level'],
  threatIntel: { cves: ['CVE-2024-1709'], cisaKev: true, campaigns: ['Scattered Spider', 'ALPHV/BlackCat Ransomware'], iocs: [] },
  references: ['https://attack.mitre.org/techniques/T1219/']
},
{
  id: 'SR-0047', title: 'Protocol Tunneling via SSH or Network Tools',
  status: 'stable', severity: 'high', author: 'SOC Platform', date: '2024-05-15', modified: '2024-11-20',
  category: 'network-anomalies',
  description: 'Detects use of protocol tunneling tools (SSH tunnels, plink, chisel, ngrok) that create covert communication channels through firewalls for C2 or data exfiltration.',
  tacticId: 'TA0011', tacticName: 'Command and Control',
  techniqueId: 'T1572', techniqueName: 'Protocol Tunneling',
  logsource: { product: 'windows', category: 'process_creation' },
  sigmaYaml: `title: Protocol Tunneling via SSH or Network Tools
id: 56789012-5678-9012-3456-789012345901
status: stable
description: Detects protocol tunneling tools used for covert C2
author: SOC Platform
date: 2024/05/15
logsource:
    category: process_creation
    product: windows
detection:
    selection_ssh:
        Image|endswith:
            - '\\\\ssh.exe'
            - '\\\\plink.exe'
        CommandLine|contains:
            - '-D '
            - '-L '
            - '-R '
            - '-N'
    selection_tunnel:
        Image|endswith:
            - '\\\\chisel.exe'
            - '\\\\ngrok.exe'
            - '\\\\cloudflared.exe'
            - '\\\\frpc.exe'
            - '\\\\bore.exe'
    condition: selection_ssh or selection_tunnel
falsepositives:
    - Developers using SSH tunnels for development
    - Authorized use of cloudflared
level: high
tags:
    - attack.command_and_control
    - attack.t1572`,
  detectionExplanation: 'Tunneling tools create covert channels that bypass firewall rules by encapsulating traffic within allowed protocols. SSH with -D (SOCKS proxy), -L (local forward), -R (reverse forward), or -N (no shell) flags indicate tunnel creation. Tools like chisel, ngrok, and cloudflared specifically create reverse tunnels that allow external access to internal resources, effectively bypassing perimeter security.',
  requiredLogs: ['Sysmon Event ID 1', 'Network firewall logs'],
  logConfig: 'Process creation with command line logging. Monitor for outbound connections to tunnel service endpoints.',
  falsePositives: ['Developers using SSH tunnels for database access', 'Authorized cloudflare tunnel deployments', 'DevOps tooling using port forwarding'],
  tuning: 'Allowlist authorized SSH tunnels by user and destination. Block tunnel services (ngrok, bore) at the firewall.',
  commonErrors: ['SSH tunnel flags may be combined making pattern matching difficult', 'Cloudflared may be legitimately deployed'],
  responseActions: ['Identify the tunnel endpoint and destination', 'Determine what traffic is being tunneled', 'Block the tunnel tool and its network connections', 'Check for data exfiltration through the tunnel', 'Review the tunnel duration and data volume'],
  threatIntel: { cves: [], cisaKev: false, campaigns: ['Volt Typhoon'], iocs: [] },
  references: ['https://attack.mitre.org/techniques/T1572/']
},

// ═══════════════════════════════════════════════════════════════
// EXFILTRATION (TA0010)
// ═══════════════════════════════════════════════════════════════
{
  id: 'SR-0048', title: 'Data Exfiltration to Cloud Storage',
  status: 'stable', severity: 'high', author: 'SOC Platform', date: '2024-03-10', modified: '2024-12-05',
  category: 'data-exfiltration',
  description: 'Detects potential data exfiltration to cloud storage services by monitoring for command-line uploads, browser-based uploads of archives, and use of cloud sync tools not approved by the organization.',
  tacticId: 'TA0010', tacticName: 'Exfiltration',
  techniqueId: 'T1567.002', techniqueName: 'Exfiltration to Cloud Storage',
  logsource: { product: 'windows', category: 'process_creation' },
  sigmaYaml: `title: Data Exfiltration to Cloud Storage
id: 67890123-6789-0123-4567-890123456012
status: stable
description: Detects data upload to cloud storage services
author: SOC Platform
date: 2024/03/10
logsource:
    category: process_creation
    product: windows
detection:
    selection_cli:
        CommandLine|contains:
            - 'rclone'
            - 'megacmd'
            - 'mega-cmd'
            - 'azcopy'
            - 'aws s3 cp'
            - 'aws s3 sync'
            - 'gsutil cp'
    selection_urls:
        CommandLine|contains:
            - 'mega.nz'
            - 'transfer.sh'
            - 'send.exploit.in'
            - 'file.io'
            - 'gofile.io'
            - 'anonfiles'
            - 'wetransfer.com'
    condition: selection_cli or selection_urls
falsepositives:
    - Authorized cloud backup operations
    - DevOps using cloud CLI tools
level: high
tags:
    - attack.exfiltration
    - attack.t1567.002`,
  detectionExplanation: 'Cloud storage provides an easy exfiltration channel that blends with normal HTTPS traffic. This rule detects: (1) CLI tools designed for cloud uploads (rclone is the most common exfiltration tool used by ransomware groups), (2) Anonymous file sharing services commonly used for exfiltration, (3) Cloud provider CLI tools used outside of authorized contexts. Rclone in particular is used by LockBit, BlackCat, and other ransomware groups.',
  requiredLogs: ['Sysmon Event ID 1', 'Web proxy logs', 'DLP alerts'],
  logConfig: 'Command line auditing. Web proxy logging with URL categorization.',
  falsePositives: ['Cloud backup solutions using rclone', 'DevOps teams using AWS/Azure/GCP CLI tools', 'Marketing teams using file sharing services'],
  tuning: 'Allowlist authorized cloud tools with specific user/system context. Block anonymous file sharing services at the proxy. Monitor rclone config file for unauthorized destinations.',
  commonErrors: ['HTTPS encryption prevents content inspection', 'rclone can be renamed to evade detection'],
  responseActions: ['Determine what data was uploaded', 'Block the destination at the proxy/firewall', 'Check the file size and type of uploaded data', 'If ransomware-related: immediately engage IR team', 'Preserve proxy logs for forensic analysis', 'Notify data privacy/legal team if PII/PHI involved'],
  threatIntel: { cves: [], cisaKev: false, campaigns: ['LockBit 3.0', 'ALPHV/BlackCat Ransomware'], iocs: [] },
  references: ['https://attack.mitre.org/techniques/T1567/002/']
},
{
  id: 'SR-0049', title: 'Large Outbound Data Transfer',
  status: 'test', severity: 'medium', author: 'SOC Platform', date: '2024-06-01', modified: '2024-11-30',
  category: 'data-exfiltration',
  description: 'Detects unusually large outbound data transfers that may indicate data exfiltration over the C2 channel or alternative protocols, especially to uncommon destinations or during off-hours.',
  tacticId: 'TA0010', tacticName: 'Exfiltration',
  techniqueId: 'T1041', techniqueName: 'Exfiltration Over C2 Channel',
  logsource: { product: 'windows', service: 'sysmon' },
  sigmaYaml: `title: Large Outbound Data Transfer
id: 78901234-7890-1234-5678-901234567123
status: test
description: Detects unusually large outbound network transfers
author: SOC Platform
date: 2024/06/01
logsource:
    product: windows
    service: sysmon
detection:
    selection:
        EventID: 3
        Initiated: 'true'
    filter_internal:
        DestinationIp|startswith:
            - '10.'
            - '172.16.'
            - '192.168.'
            - '127.'
    condition: selection and not filter_internal
    # Note: Requires SIEM aggregation for data volume calculation
    # Alert when total bytes sent > 100MB to single external IP in 1 hour
falsepositives:
    - Large file uploads to cloud services
    - Video conferencing
    - Software updates
level: medium
tags:
    - attack.exfiltration
    - attack.t1041`,
  detectionExplanation: 'This network-based detection monitors for large volumes of outbound data to external IP addresses. While Sysmon Event ID 3 captures network connections, the key analysis happens in the SIEM via aggregation - summing bytes transferred to external destinations per source host per time window. Unusual spikes above the hosts baseline are flagged.',
  requiredLogs: ['Sysmon Event ID 3 (Network Connection)', 'Firewall/proxy logs with byte counts', 'NetFlow data'],
  logConfig: 'Enable Sysmon network connection logging (can be high-volume - filter appropriately). Firewall logs with byte counts are preferred for volume-based detection.',
  falsePositives: ['Cloud backups', 'Video conference platforms', 'Large file sharing for business purposes', 'OS and software updates'],
  tuning: 'Establish per-host outbound data baselines. Use statistical anomaly detection rather than fixed thresholds. Exclude known CDN and update service IPs.',
  commonErrors: ['Sysmon Event 3 is very high volume', 'Byte count may not be available in all monitoring tools', 'Encrypted traffic prevents content inspection'],
  responseActions: ['Identify the destination IP and check reputation', 'Determine what application generated the traffic', 'Check if the destination is a known cloud/transfer service', 'Review the data content if DLP is available', 'Correlate with other exfiltration indicators'],
  threatIntel: { cves: [], cisaKev: false, campaigns: [], iocs: [] },
  references: ['https://attack.mitre.org/techniques/T1041/']
},
{
  id: 'SR-0050', title: 'Exfiltration Over DNS',
  status: 'stable', severity: 'high', author: 'SOC Platform', date: '2024-07-15', modified: '2024-12-10',
  category: 'data-exfiltration',
  description: 'Detects potential data exfiltration over DNS by monitoring for unusually high volumes of DNS queries, long subdomain labels suggesting encoded data, and TXT record responses with large payloads.',
  tacticId: 'TA0010', tacticName: 'Exfiltration',
  techniqueId: 'T1048.003', techniqueName: 'Exfiltration Over Unencrypted Non-C2 Protocol',
  logsource: { product: 'windows', category: 'dns_query' },
  sigmaYaml: `title: Exfiltration Over DNS
id: 89012345-8901-2345-6789-012345678234
status: stable
description: Detects DNS-based data exfiltration patterns
author: SOC Platform
date: 2024/07/15
logsource:
    category: dns_query
    product: windows
detection:
    selection_long_subdomain:
        QueryName|re: '^[a-zA-Z0-9\\\\+\\\\/\\\\=]{30,}\\\\.'
    selection_high_volume:
        QueryName|endswith: '.same-domain.com'
    # Note: SIEM aggregation needed - count(QueryName) by process > 50 in 5m
    condition: selection_long_subdomain
falsepositives:
    - CDN with long domain names
    - DKIM validation queries
level: high
tags:
    - attack.exfiltration
    - attack.t1048.003`,
  detectionExplanation: 'DNS exfiltration encodes stolen data in DNS query subdomains (e.g., Base64-encoded chunks as labels). Key indicators: very long subdomain labels (30+ chars) with Base64-like character sets, high volume of queries to the same domain, and unusual query types (TXT, NULL, CNAME). Since DNS is rarely blocked at firewalls, its an attractive exfiltration channel.',
  requiredLogs: ['Sysmon Event ID 22', 'DNS server query logs', 'Passive DNS'],
  logConfig: 'DNS query logging on resolvers and endpoints.',
  falsePositives: ['DKIM/SPF validation', 'Some CDN and SaaS services', 'DNS-based security products'],
  tuning: 'Focus on subdomain length and character composition. Allowlist known-good domains with long subdomains. Calculate entropy of subdomain labels.',
  commonErrors: ['High volume of legitimate DNS makes threshold tuning critical', 'Base64 encoding detection may match legitimate domains'],
  responseActions: ['Analyze the suspicious domain and extract encoded data', 'Block the domain at DNS resolver', 'Identify the process performing DNS exfiltration', 'Assess what data was exfiltrated by decoding captured queries'],
  threatIntel: { cves: [], cisaKev: false, campaigns: [], iocs: [] },
  references: ['https://attack.mitre.org/techniques/T1048/003/']
},

// ═══════════════════════════════════════════════════════════════
// IMPACT (TA0040)
// ═══════════════════════════════════════════════════════════════
{
  id: 'SR-0051', title: 'Ransomware Indicators - Mass File Encryption',
  status: 'stable', severity: 'critical', author: 'SOC Platform', date: '2024-01-05', modified: '2024-12-15',
  category: 'ransomware',
  description: 'Detects indicators of ransomware activity including mass file extension changes, ransom note creation, and known ransomware process behaviors indicating active data encryption.',
  tacticId: 'TA0040', tacticName: 'Impact',
  techniqueId: 'T1486', techniqueName: 'Data Encrypted for Impact',
  logsource: { product: 'windows', category: 'file_event' },
  sigmaYaml: `title: Ransomware Indicators - Mass File Encryption
id: 90123456-9012-3456-7890-123456789345
status: stable
description: Detects ransomware file encryption patterns
author: SOC Platform
date: 2024/01/05
logsource:
    category: file_event
    product: windows
detection:
    selection_extensions:
        TargetFilename|endswith:
            - '.encrypted'
            - '.locked'
            - '.crypt'
            - '.enc'
            - '.lockbit'
            - '.blackcat'
            - '.zzzzz'
            - '.onion'
    selection_ransom_notes:
        TargetFilename|contains:
            - 'README_TO_RESTORE'
            - 'DECRYPT_YOUR_FILES'
            - 'HOW_TO_RECOVER'
            - 'RANSOM_NOTE'
            - '#Restore-Your-Files#'
            - 'RECOVER-FILES.txt'
    selection_mass_rename:
        EventType: 'FileRenamed'
        # Aggregation: count > 100 in 1 minute from same process
    condition: selection_extensions or selection_ransom_notes
falsepositives:
    - Legitimate encryption software
    - Backup tools that encrypt files
level: critical
tags:
    - attack.impact
    - attack.t1486`,
  detectionExplanation: 'Ransomware typically encrypts files and renames them with custom extensions, then creates ransom note files in each affected directory. This rule detects: (1) Known ransomware file extensions, (2) Ransom note file creation patterns, (3) Mass file rename events from a single process. By the time this fires, encryption is actively occurring - speed of response is critical.',
  requiredLogs: ['Sysmon Event ID 11 (File Creation)', 'Sysmon Event ID 2 (File Change Time)', 'EDR file activity telemetry'],
  logConfig: 'File creation and rename monitoring. Many SIEM/EDR solutions have built-in ransomware detection that supplements this rule.',
  falsePositives: ['Legitimate file encryption tools (VeraCrypt, BitLocker)', 'Backup software encrypting archives', 'Developers testing encryption functionality'],
  tuning: 'Lower the threshold for critical servers and file shares. Add canary files (honeypot files) that trigger immediate alerts when accessed/modified.',
  commonErrors: ['New ransomware variants use different extensions not in the list', 'File event volume may be overwhelming during active encryption', 'By the time detection fires, significant damage may have occurred'],
  responseActions: ['CRITICAL: IMMEDIATE RESPONSE REQUIRED', 'Isolate the infected system from the network IMMEDIATELY', 'Identify and terminate the encrypting process', 'Determine the encryption scope (local drives, network shares, backup systems)', 'Disconnect affected network shares', 'Preserve ransom note for threat intelligence', 'Activate incident response plan', 'Contact law enforcement (FBI IC3) and cyber insurance provider', 'Assess backup integrity and recovery options', 'DO NOT pay ransom without legal and executive guidance'],
  threatIntel: { cves: [], cisaKev: false, campaigns: ['LockBit 3.0', 'ALPHV/BlackCat Ransomware'], iocs: [] },
  references: ['https://attack.mitre.org/techniques/T1486/', 'https://www.cisa.gov/stopransomware']
},
{
  id: 'SR-0052', title: 'Inhibit System Recovery - Shadow Copy Deletion',
  status: 'stable', severity: 'critical', author: 'SOC Platform', date: '2024-01-10', modified: '2024-12-10',
  category: 'ransomware',
  description: 'Detects deletion of Volume Shadow Copies and modification of Windows recovery configuration, techniques used by ransomware to prevent victims from restoring encrypted files.',
  tacticId: 'TA0040', tacticName: 'Impact',
  techniqueId: 'T1490', techniqueName: 'Inhibit System Recovery',
  logsource: { product: 'windows', category: 'process_creation' },
  sigmaYaml: `title: Inhibit System Recovery - Shadow Copy Deletion
id: 01234567-0123-4567-8901-234567890456
status: stable
description: Detects deletion of shadow copies and recovery options
author: SOC Platform
date: 2024/01/10
logsource:
    category: process_creation
    product: windows
detection:
    selection_vssadmin:
        Image|endswith: '\\\\vssadmin.exe'
        CommandLine|contains:
            - 'delete shadows'
            - 'resize shadowstorage'
    selection_wmic_shadow:
        Image|endswith: '\\\\wmic.exe'
        CommandLine|contains: 'shadowcopy delete'
    selection_bcdedit:
        Image|endswith: '\\\\bcdedit.exe'
        CommandLine|contains:
            - 'recoveryenabled no'
            - 'bootstatuspolicy ignoreallfailures'
    selection_wbadmin:
        Image|endswith: '\\\\wbadmin.exe'
        CommandLine|contains: 'delete catalog'
    selection_ps:
        CommandLine|contains:
            - 'Get-WmiObject Win32_ShadowCopy | ForEach-Object {$_.Delete()}'
            - 'Win32_ShadowCopy'
            - 'Delete()'
    condition: selection_vssadmin or selection_wmic_shadow or selection_bcdedit or selection_wbadmin or selection_ps
falsepositives:
    - Legitimate shadow copy management by IT
    - Storage reclamation procedures
level: critical
tags:
    - attack.impact
    - attack.t1490`,
  detectionExplanation: 'Ransomware routinely deletes Volume Shadow Copies (vssadmin delete shadows /all) and disables Windows recovery (bcdedit /set recoveryenabled no) before encrypting files. This ensures victims cannot use system restore or previous file versions to recover. Deleting backup catalogs (wbadmin delete catalog) removes Windows Backup restore points. These actions are extremely rare in legitimate operations and should always trigger high-priority alerts.',
  requiredLogs: ['Sysmon Event ID 1', 'Windows Security 4688'],
  logConfig: 'Standard process creation and command line logging.',
  falsePositives: ['IT administrators managing shadow copy storage on low-disk servers', 'Storage migration activities', 'Planned shadow copy cleanup during maintenance windows'],
  tuning: 'This detection has extremely low false positive rate. Consider making it a P0 alert with automatic containment. If exceptions are needed, use maintenance window-based suppression only.',
  commonErrors: ['PowerShell-based shadow deletion may use different syntax', 'Some ransomware uses direct WMI calls that bypass sysmon process monitoring'],
  responseActions: ['CRITICAL: This is almost certainly ransomware or destructive attack', 'Immediately isolate the system', 'Terminate the responsible process', 'Check if encryption has already started', 'Verify backup systems are intact and disconnected', 'Engage incident response team immediately', 'Check all other systems for the same indicators'],
  threatIntel: { cves: [], cisaKev: false, campaigns: ['LockBit 3.0', 'ALPHV/BlackCat Ransomware'], iocs: [] },
  references: ['https://attack.mitre.org/techniques/T1490/']
},
{
  id: 'SR-0053', title: 'Critical Service Stopped',
  status: 'stable', severity: 'high', author: 'SOC Platform', date: '2024-02-15', modified: '2024-11-25',
  category: 'ransomware',
  description: 'Detects stopping of critical Windows services including databases, backup agents, and security software, commonly performed by ransomware before encryption to ensure file handles are released.',
  tacticId: 'TA0040', tacticName: 'Impact',
  techniqueId: 'T1489', techniqueName: 'Service Stop',
  logsource: { product: 'windows', category: 'process_creation' },
  sigmaYaml: `title: Critical Service Stopped
id: 12345678-1234-5678-9012-345678901567
status: stable
description: Detects stopping of critical services commonly targeted by ransomware
author: SOC Platform
date: 2024/02/15
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image|endswith:
            - '\\\\sc.exe'
            - '\\\\net.exe'
            - '\\\\net1.exe'
            - '\\\\taskkill.exe'
        CommandLine|contains:
            - 'stop'
            - '/F'
    selection_services:
        CommandLine|contains:
            - 'MSSQLSERVER'
            - 'SQLAgent'
            - 'SQLTELEMETRY'
            - 'sqlwriter'
            - 'MSSQLFDLauncher'
            - 'vss'
            - 'sql'
            - 'exchange'
            - 'backup'
            - 'veeam'
            - 'oracle'
    condition: selection and selection_services
falsepositives:
    - Database maintenance procedures
    - Planned service restarts
    - Patch application
level: high
tags:
    - attack.impact
    - attack.t1489`,
  detectionExplanation: 'Ransomware stops database services (SQL, Oracle, Exchange) to release file locks before encrypting database files. It also stops backup services (Veeam, BackupExec) to prevent recovery. Legitimate service stops during maintenance are typically scheduled and performed through proper change management. Rapid stopping of multiple critical services is a strong pre-encryption indicator.',
  requiredLogs: ['Sysmon Event ID 1', 'Windows Security 4688', 'System Event 7036 (Service State Change)'],
  logConfig: 'Process creation logging with command line capture.',
  falsePositives: ['Database maintenance windows', 'Patch deployment requiring service restarts', 'Cluster failover operations'],
  tuning: 'Alert on multiple critical services stopped within a short window (3+ in 5 minutes). Single service stops may be legitimate. Correlate with change management schedule.',
  commonErrors: ['Ransomware may stop services via PowerShell or WMI instead of sc.exe', 'Service names may vary by installation'],
  responseActions: ['Investigate the process stopping the services', 'Check for concurrent shadow copy deletion (ransomware precursor)', 'If ransomware suspected: immediately isolate and engage IR', 'Restart the affected services after investigation', 'Verify backup systems are unaffected'],
  threatIntel: { cves: [], cisaKev: false, campaigns: ['LockBit 3.0', 'ALPHV/BlackCat Ransomware'], iocs: [] },
  references: ['https://attack.mitre.org/techniques/T1489/']
},
{
  id: 'SR-0054', title: 'System Shutdown/Reboot Command',
  status: 'stable', severity: 'medium', author: 'SOC Platform', date: '2024-04-20', modified: '2024-11-15',
  category: 'execution',
  description: 'Detects unexpected system shutdown or reboot commands that may be used by attackers to disrupt operations, apply destructive changes, or as part of wiper/ransomware finalization.',
  tacticId: 'TA0040', tacticName: 'Impact',
  techniqueId: 'T1529', techniqueName: 'System Shutdown/Reboot',
  logsource: { product: 'windows', category: 'process_creation' },
  sigmaYaml: `title: System Shutdown/Reboot Command
id: 23456789-2345-6789-0123-456789012678
status: stable
description: Detects shutdown/reboot commands potentially used for impact
author: SOC Platform
date: 2024/04/20
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image|endswith: '\\\\shutdown.exe'
        CommandLine|contains:
            - '/s'
            - '/r'
            - '/f'
    selection_ps:
        CommandLine|contains:
            - 'Stop-Computer'
            - 'Restart-Computer'
    condition: selection or selection_ps
falsepositives:
    - System administrators performing maintenance
    - Automated patch management reboots
    - Planned maintenance windows
level: medium
tags:
    - attack.impact
    - attack.t1529`,
  detectionExplanation: 'Unexpected shutdowns or reboots can be used for denial of service, to apply destructive boot-level changes, or as the final action in a ransomware attack chain (boot into a modified/encrypted state). The /f flag forces closure of running applications, indicating potential disregard for data integrity.',
  requiredLogs: ['Sysmon Event ID 1', 'Windows Security 4688'],
  logConfig: 'Standard process creation logging.',
  falsePositives: ['Scheduled reboot after Windows updates', 'Administrator-initiated maintenance restarts', 'Power management scripts'],
  tuning: 'Correlate with patch management schedules. Alert specifically on forced shutdowns (/f) of critical servers outside maintenance windows.',
  commonErrors: ['Normal reboots during patch cycles create significant noise', 'Some monitoring only captures the shutdown and not the reason'],
  responseActions: ['Verify the shutdown was planned and authorized', 'If unexpected on a critical server: investigate immediately before allowing reboot', 'Check for preceding malicious activity (ransomware indicators)', 'Review what changes were made before the reboot command'],
  threatIntel: { cves: [], cisaKev: false, campaigns: [], iocs: [] },
  references: ['https://attack.mitre.org/techniques/T1529/']
},
{
  id: 'SR-0055', title: 'Data Destruction - Disk Wipe Indicators',
  status: 'stable', severity: 'critical', author: 'SOC Platform', date: '2024-05-25', modified: '2024-12-15',
  category: 'ransomware',
  description: 'Detects indicators of disk wiping or data destruction including format commands, cipher overwrite, and known wiper tool patterns that permanently destroy data.',
  tacticId: 'TA0040', tacticName: 'Impact',
  techniqueId: 'T1485', techniqueName: 'Data Destruction',
  logsource: { product: 'windows', category: 'process_creation' },
  sigmaYaml: `title: Data Destruction - Disk Wipe Indicators
id: 34567890-3456-7890-1234-567890123789
status: stable
description: Detects disk wiping and destructive data operations
author: SOC Platform
date: 2024/05/25
logsource:
    category: process_creation
    product: windows
detection:
    selection_format:
        Image|endswith: '\\\\format.com'
        CommandLine|contains: '/y'
    selection_cipher:
        Image|endswith: '\\\\cipher.exe'
        CommandLine|contains: '/w:'
    selection_sdelete:
        Image|endswith:
            - '\\\\sdelete.exe'
            - '\\\\sdelete64.exe'
    selection_diskpart:
        Image|endswith: '\\\\diskpart.exe'
        CommandLine|contains:
            - 'clean'
            - 'delete'
    condition: selection_format or selection_cipher or selection_sdelete or selection_diskpart
falsepositives:
    - IT decommissioning hardware
    - Secure file deletion procedures
    - Drive preparation for reimaging
level: critical
tags:
    - attack.impact
    - attack.t1485`,
  detectionExplanation: 'Data destruction tools permanently remove data without possibility of recovery. Format with /y auto-confirms without prompting. Cipher /w overwrites deleted data on the volume. SDelete performs secure file/directory deletion. Diskpart clean removes all partition information. These are destructive operations that should never occur on production systems without explicit authorization.',
  requiredLogs: ['Sysmon Event ID 1', 'Windows Security 4688'],
  logConfig: 'Standard process creation logging.',
  falsePositives: ['Hardware decommissioning with secure wipe', 'Disk preparation for OS deployment', 'Compliance-required secure deletion'],
  tuning: 'Alert immediately on production servers. For workstations, correlate with IT asset management workflows.',
  commonErrors: ['Some wiper malware uses direct disk I/O bypassing these utilities', 'MBR/VBR overwrite may not generate process creation events'],
  responseActions: ['CRITICAL: Immediately isolate the system', 'Identify the scope of destruction', 'Preserve any remaining data', 'Determine if this is targeted destruction or ransomware variant', 'Activate disaster recovery procedures', 'Full incident response engagement'],
  threatIntel: { cves: [], cisaKev: false, campaigns: [], iocs: [] },
  references: ['https://attack.mitre.org/techniques/T1485/']
}
];

// Combined in sigma-rules-part3.js
