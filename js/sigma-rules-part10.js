// ═══════════════════════════════════════════════════════════════════════
// Sigma Rules Part 10 — SigmaHQ Sync Continued  
// Covers: Credential Theft, Supply Chain, Container Security, 
// Network Protocol Abuse, Identity Attacks, Fileless Malware
// ═══════════════════════════════════════════════════════════════════════

const SIGMA_RULES_PART10 = [

// ═══ CREDENTIAL THEFT ADVANCED ═══
{
  id: 'SR-0181', title: 'Credential Manager Access via VaultCmd',
  status: 'stable', severity: 'high', author: 'SigmaHQ Aligned', date: '2024-03-10', modified: '2024-12-10',
  category: 'credential-access',
  description: 'Detects vaultcmd.exe being used to enumerate or extract credentials from Windows Credential Manager vault, often used during post-exploitation to harvest saved credentials.',
  tacticId: 'TA0006', tacticName: 'Credential Access',
  techniqueId: 'T1555.004', techniqueName: 'Windows Credential Manager',
  logsource: { product: 'windows', category: 'process_creation' },
  sigmaYaml: `title: VaultCmd Credential Manager Enumeration
id: aa010193-0000-1111-2222-333344440181
status: stable
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image|endswith: '\\\\vaultcmd.exe'
        CommandLine|contains:
            - '/list'
            - '/listcreds'
            - '/listschema'
    condition: selection
level: high
tags:
    - attack.credential_access
    - attack.t1555.004`,
  splunkQuery: `index=wineventlog sourcetype=WinEventLog:Sysmon EventCode=1
| where match(Image,"(?i)\\\\vaultcmd\\.exe$")
  AND match(CommandLine,"(?i)(/list|/listcreds|/listschema)")
| table _time, ComputerName, User, CommandLine`,
  qradarQuery: `SELECT sourceip, username, Command,
  COUNT(*) as vault_access
FROM events
WHERE CATEGORYNAME(category) ILIKE '%Process%Create%'
  AND Filename ILIKE '%vaultcmd.exe'
  AND (Command ILIKE '%/list%' OR Command ILIKE '%/listcreds%')
GROUP BY sourceip, username, Command
ORDER BY starttime DESC
LAST 24 HOURS`,
  detectionExplanation: 'VaultCmd.exe is a legitimate Windows utility for managing Credential Manager. Attackers use it to enumerate saved credentials (web passwords, RDP credentials, certificate-based credentials) stored in the Windows vault during post-exploitation.',
  requiredLogs: ['Sysmon Event ID 1'],
  logConfig: 'Process creation with command line auditing.',
  falsePositives: ['IT staff managing credential vault', 'Backup tools accessing vault'],
  tuning: 'vaultcmd.exe usage is rare in most environments. Any execution warrants investigation.',
  commonErrors: ['VaultCmd is not commonly monitored'],
  responseActions: ['Check what credentials were enumerated', 'Reset compromised credentials', 'Review user account for compromise'],
  threatIntel: { cves: [], cisaKev: false, campaigns: [], iocs: [] },
  references: ['https://attack.mitre.org/techniques/T1555/004/']
},

{
  id: 'SR-0182', title: 'DPAPI MasterKey Extraction Attempt',
  status: 'stable', severity: 'critical', author: 'SigmaHQ Aligned', date: '2024-04-05', modified: '2024-12-15',
  category: 'credential-access',
  description: 'Detects attempts to access DPAPI master key files or use Mimikatz dpapi module to decrypt protected secrets, enabling offline credential access.',
  tacticId: 'TA0006', tacticName: 'Credential Access',
  techniqueId: 'T1555', techniqueName: 'Credentials from Password Stores',
  logsource: { product: 'windows', category: 'process_creation' },
  sigmaYaml: `title: DPAPI Master Key Extraction
id: bb121204-1111-2222-3333-444455550182
status: stable
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        CommandLine|contains:
            - 'dpapi::masterkey'
            - 'sekurlsa::dpapi'
            - 'Protect\\S-1-5'
            - 'masterkey.bin'
    condition: selection
level: critical
tags:
    - attack.credential_access
    - attack.t1555`,
  splunkQuery: `index=wineventlog sourcetype=WinEventLog:Sysmon EventCode=1
| where match(CommandLine,"(?i)(dpapi::masterkey|sekurlsa::dpapi|Protect\\\\S-1-5|masterkey\\.bin)")
| table _time, ComputerName, User, Image, CommandLine`,
  qradarQuery: `SELECT sourceip, username, Command,
  COUNT(*) as dpapi_events
FROM events
WHERE CATEGORYNAME(category) ILIKE '%Process%Create%'
  AND (Command ILIKE '%dpapi::masterkey%' OR Command ILIKE '%sekurlsa::dpapi%'
    OR Command ILIKE '%Protect\\S-1-5%')
GROUP BY sourceip, username, Command
ORDER BY starttime DESC
LAST 24 HOURS`,
  detectionExplanation: 'DPAPI (Data Protection API) encrypts sensitive data including browser passwords, Wi-Fi keys, and certificate private keys. Attackers extract DPAPI master keys to decrypt all protected secrets offline. Mimikatz dpapi module is the primary tool for this attack.',
  requiredLogs: ['Sysmon Event ID 1'],
  logConfig: 'Process creation with full command line logging.',
  falsePositives: ['Legitimate forensic investigations', 'Security assessments'],
  tuning: 'Extremely high-fidelity detection. Any match indicates active credential theft.',
  commonErrors: ['DPAPI paths vary by user profile'],
  responseActions: ['CRITICAL: Active credential theft', 'Isolate endpoint', 'Reset all credentials for affected user', 'Full incident response'],
  threatIntel: { cves: [], cisaKev: false, campaigns: ['Cobalt Strike Operators'], iocs: [] },
  references: ['https://attack.mitre.org/techniques/T1555/']
},

// ═══ SUPPLY CHAIN / SUSPICIOUS INSTALLER ═══
{
  id: 'SR-0183', title: 'Suspicious Software Installer from Temp Directory',
  status: 'stable', severity: 'high', author: 'SigmaHQ Aligned', date: '2024-06-15', modified: '2024-12-10',
  category: 'execution',
  description: 'Detects execution of setup/install executables from temporary or user-writable directories, a common supply chain compromise or drive-by download pattern.',
  tacticId: 'TA0002', tacticName: 'Execution',
  techniqueId: 'T1204.002', techniqueName: 'Malicious File',
  logsource: { product: 'windows', category: 'process_creation' },
  sigmaYaml: `title: Suspicious Installer from Temp Directory
id: cc232315-2222-3333-4444-555566660183
status: stable
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image|contains:
            - '\\\\Temp\\\\'
            - '\\\\Downloads\\\\'
            - '\\\\AppData\\\\Local\\\\Temp'
        Image|endswith:
            - 'setup.exe'
            - 'installer.exe'
            - 'install.exe'
            - 'update.exe'
    condition: selection
level: high
tags:
    - attack.execution
    - attack.t1204.002`,
  splunkQuery: `index=wineventlog sourcetype=WinEventLog:Sysmon EventCode=1
| where match(Image,"(?i)(\\\\Temp\\\\|\\\\Downloads\\\\|\\\\AppData\\\\Local\\\\Temp)")
  AND match(Image,"(?i)(setup|installer|install|update)\\.exe$")
| table _time, ComputerName, User, Image, CommandLine, Hashes`,
  qradarQuery: `SELECT sourceip, username,
  Filename, "File Path",
  COUNT(*) as suspicious_installer
FROM events
WHERE CATEGORYNAME(category) ILIKE '%Process%Create%'
  AND ("File Path" ILIKE '%\\Temp\\%' OR "File Path" ILIKE '%\\Downloads\\%')
  AND (Filename ILIKE '%setup.exe' OR Filename ILIKE '%installer.exe' OR Filename ILIKE '%update.exe')
GROUP BY sourceip, username, Filename, "File Path"
ORDER BY starttime DESC
LAST 24 HOURS`,
  detectionExplanation: 'Malware frequently disguises itself as legitimate installers or updates, placing them in temp or download directories. Supply chain attacks often leverage trojanized installers. An installer running from a temp directory instead of an official installation path is suspicious.',
  requiredLogs: ['Sysmon Event ID 1'],
  logConfig: 'Process creation with hash capture for file analysis.',
  falsePositives: ['Users downloading and running legitimate software', 'Auto-updaters extracting to temp'],
  tuning: 'Focus on installers with unsigned binaries or unknown hashes. Auto-updaters from known vendors can be allowlisted.',
  commonErrors: ['Many legitimate installers run from temp directories', 'Browser download directory is a common false positive source'],
  responseActions: ['Verify the installer hash against known-good databases', 'Check VirusTotal for the file hash', 'Analyze the installer for malicious behavior'],
  threatIntel: { cves: [], cisaKev: false, campaigns: ['3CX Supply Chain', 'SolarWinds'], iocs: [] },
  references: ['https://attack.mitre.org/techniques/T1204/002/']
},

// ═══ NETWORK PROTOCOL ABUSE ═══
{
  id: 'SR-0184', title: 'ICMP Tunneling Detection — Large ICMP Packets',
  status: 'stable', severity: 'medium', author: 'SigmaHQ Aligned', date: '2024-09-20', modified: '2024-12-10',
  category: 'network-anomalies',
  description: 'Detects abnormally large ICMP packets or high volumes of ICMP traffic, which may indicate ICMP tunneling being used for data exfiltration or C2 communication.',
  tacticId: 'TA0011', tacticName: 'Command and Control',
  techniqueId: 'T1095', techniqueName: 'Non-Application Layer Protocol',
  logsource: { product: 'firewall' },
  sigmaYaml: `title: ICMP Tunneling Detection
id: dd343426-3333-4444-5555-666677770184
status: stable
logsource:
    product: firewall
detection:
    selection:
        protocol: icmp
    filter_size:
        bytes|gt: 100
    condition: selection and filter_size
level: medium
tags:
    - attack.command_and_control
    - attack.t1095`,
  splunkQuery: `index=firewall sourcetype=firewall proto=icmp
| where bytes > 100
| bin _time span=5m
| stats count sum(bytes) as total_bytes avg(bytes) as avg_size by src_ip, dest_ip, _time
| where count > 50 OR avg_size > 200
| table _time, src_ip, dest_ip, count, total_bytes, avg_size`,
  qradarQuery: `SELECT sourceip, destinationip,
  COUNT(*) as icmp_count,
  SUM(LONG(eventpayload)) as total_bytes,
  AVG(LONG(eventpayload)) as avg_size
FROM events
WHERE PROTOCOLNAME(protocolid) = 'ICMP'
  AND LONG(eventpayload) > 100
GROUP BY sourceip, destinationip
HAVING COUNT(*) > 50
ORDER BY total_bytes DESC
LAST 4 HOURS`,
  detectionExplanation: 'Normal ICMP ping packets are typically 64-84 bytes. ICMP tunneling tools encode data within ICMP echo requests and replies, resulting in unusually large packets (100+ bytes) or high volumes of ICMP traffic. Tools like ptunnel and icmpsh use this technique to bypass firewall rules.',
  requiredLogs: ['Firewall logs with ICMP payload size'],
  logConfig: 'Configure firewall to log ICMP traffic with packet size information.',
  falsePositives: ['Large ping tests (ping -l)', 'Network monitoring tools using ICMP'],
  tuning: 'Set size threshold based on environment baseline. Look for sustained ICMP sessions with large payloads.',
  commonErrors: ['Not all firewalls log ICMP payload size', 'MTU path discovery uses large ICMP'],
  responseActions: ['Investigate source and destination of ICMP traffic', 'Check for ICMP tunneling tools', 'Block ICMP if not needed or limit payload size'],
  threatIntel: { cves: [], cisaKev: false, campaigns: ['Turla ICMP backdoor'], iocs: [] },
  references: ['https://attack.mitre.org/techniques/T1095/']
},

{
  id: 'SR-0185', title: 'RDP Tunneling via SSH or Network Tools',
  status: 'stable', severity: 'high', author: 'SigmaHQ Aligned', date: '2024-10-15', modified: '2024-12-15',
  category: 'lateral-movement',
  description: 'Detects RDP connections being tunneled through SSH or other tools by monitoring for localhost RDP connections and suspicious port forwarding configurations.',
  tacticId: 'TA0008', tacticName: 'Lateral Movement',
  techniqueId: 'T1021.001', techniqueName: 'Remote Desktop Protocol',
  logsource: { product: 'windows', category: 'network_connection' },
  sigmaYaml: `title: RDP Tunneling via Localhost
id: ee454537-4444-5555-6666-777788880185
status: stable
logsource:
    category: network_connection
    product: windows
detection:
    selection:
        DestinationPort: 3389
        DestinationIp:
            - '127.0.0.1'
            - '::1'
    condition: selection
level: high
tags:
    - attack.lateral_movement
    - attack.t1021.001`,
  splunkQuery: `index=wineventlog sourcetype=WinEventLog:Sysmon EventCode=3
| where DestinationPort=3389 AND (DestinationIp="127.0.0.1" OR DestinationIp="::1")
| table _time, ComputerName, User, Image, SourceIp, DestinationIp, DestinationPort`,
  qradarQuery: `SELECT sourceip, destinationip, destinationport,
  Filename,
  COUNT(*) as rdp_tunnel
FROM events
WHERE CATEGORYNAME(category) ILIKE '%Network%Connection%'
  AND destinationport = 3389
  AND (destinationip = '127.0.0.1' OR destinationip = '::1')
GROUP BY sourceip, destinationip, destinationport, Filename
ORDER BY starttime DESC
LAST 24 HOURS`,
  detectionExplanation: 'RDP tunneling routes RDP traffic through SSH or other tools by setting up local port forwarding to localhost:3389. This bypasses network segmentation and firewall rules. Detecting RDP connections to 127.0.0.1 or ::1 is a strong indicator of tunneled RDP access.',
  requiredLogs: ['Sysmon Event ID 3 (Network Connection)'],
  logConfig: 'Sysmon with network connection monitoring for RDP port.',
  falsePositives: ['Hyper-V Enhanced Session Mode', 'Local RDP testing'],
  tuning: 'This is very high fidelity. RDP to localhost almost always indicates tunneling.',
  commonErrors: ['Sysmon network logging must be enabled', 'Some RDP wrappers use localhost legitimately'],
  responseActions: ['Identify the tunneling tool', 'Check for SSH connections on the host', 'Investigate the source of the tunnel', 'Block unauthorized tunneling tools'],
  threatIntel: { cves: [], cisaKev: false, campaigns: ['APT groups commonly tunnel RDP'], iocs: [] },
  references: ['https://attack.mitre.org/techniques/T1021/001/']
},

// ═══ IDENTITY ATTACKS ═══
{
  id: 'SR-0186', title: 'Kerberos Silver Ticket Detection',
  status: 'stable', severity: 'critical', author: 'SigmaHQ Aligned', date: '2024-05-10', modified: '2024-12-15',
  category: 'active-directory',
  description: 'Detects indicators of Kerberos Silver Ticket attacks by looking for service ticket usage without corresponding TGT requests, indicating forged tickets.',
  tacticId: 'TA0006', tacticName: 'Credential Access',
  techniqueId: 'T1558.002', techniqueName: 'Silver Ticket',
  logsource: { product: 'windows', service: 'security' },
  sigmaYaml: `title: Kerberos Silver Ticket Indicators
id: ff565648-5555-6666-7777-888899990186
status: stable
logsource:
    product: windows
    service: security
detection:
    selection:
        EventID: 4624
        LogonType: 3
        AuthenticationPackageName: 'Kerberos'
    filter_normal:
        TargetUserName|endswith: '$'
    condition: selection and not filter_normal
level: critical
tags:
    - attack.credential_access
    - attack.t1558.002`,
  splunkQuery: `index=wineventlog sourcetype=WinEventLog:Security EventCode=4624 LogonType=3 AuthenticationPackageName=Kerberos
| where NOT match(TargetUserName,"\\$$")
| join type=left TargetUserName [search index=wineventlog EventCode=4768 | rename TargetUserName as tgt_user | fields tgt_user, IpAddress]
| where isnull(tgt_user)
| table _time, TargetUserName, IpAddress, ComputerName, ServiceName`,
  qradarQuery: `SELECT username, sourceip, destinationip,
  QIDNAME(qid) as event_name,
  COUNT(*) as silver_ticket
FROM events
WHERE EventID = 4624
  AND "Logon Type" = 3
  AND "Authentication Package" = 'Kerberos'
  AND username NOT ILIKE '%$'
GROUP BY username, sourceip, destinationip, qid
ORDER BY starttime DESC
LAST 24 HOURS`,
  detectionExplanation: 'A Silver Ticket is a forged Kerberos service ticket that grants access to a specific service without contacting the domain controller. Detection focuses on service ticket usage (4624 with Kerberos) where no corresponding TGT request (4768) exists from the same user, indicating the ticket was forged locally.',
  requiredLogs: ['Windows Security Event Logs (4624, 4768, 4769)'],
  logConfig: 'Enable Kerberos service ticket operations auditing on domain controllers.',
  falsePositives: ['Cached Kerberos tickets after ticket renewal'],
  tuning: 'Correlate 4624 Kerberos logons with 4768 TGT requests. Missing TGT is the key indicator.',
  commonErrors: ['Requires correlation across multiple event IDs', 'Cached tickets can create gaps in TGT-to-ST correlation'],
  responseActions: ['CRITICAL: Assume service account password is compromised', 'Reset the targeted service account password', 'Investigate the source of the forged ticket', 'Check for lateral movement from the authenticated session'],
  threatIntel: { cves: [], cisaKev: false, campaigns: ['APT29', 'Wizard Spider'], iocs: [] },
  references: ['https://attack.mitre.org/techniques/T1558/002/']
},

{
  id: 'SR-0187', title: 'Group Policy Modification by Non-Admin',
  status: 'stable', severity: 'high', author: 'SigmaHQ Aligned', date: '2024-07-05', modified: '2024-12-10',
  category: 'active-directory',
  description: 'Detects modification of Group Policy Objects which could allow attackers to deploy scripts, change security policies, or create persistence across the domain.',
  tacticId: 'TA0003', tacticName: 'Persistence',
  techniqueId: 'T1484.001', techniqueName: 'Group Policy Modification',
  logsource: { product: 'windows', service: 'security' },
  sigmaYaml: `title: Group Policy Object Modification
id: 00676759-6666-7777-8888-999900000187
status: stable
logsource:
    product: windows
    service: security
detection:
    selection:
        EventID:
            - 5136
            - 5137
        ObjectClass: 'groupPolicyContainer'
    condition: selection
level: high
tags:
    - attack.persistence
    - attack.t1484.001`,
  splunkQuery: `index=wineventlog sourcetype=WinEventLog:Security (EventCode=5136 OR EventCode=5137)
| where match(ObjectClass,"groupPolicyContainer")
| table _time, SubjectUserName, ObjectDN, AttributeLDAPDisplayName, AttributeValue, OperationType`,
  qradarQuery: `SELECT username, sourceip,
  QIDNAME(qid) as event_name,
  COUNT(*) as gpo_changes
FROM events
WHERE EventID IN (5136, 5137)
  AND eventname ILIKE '%groupPolicy%'
GROUP BY username, sourceip, qid
ORDER BY starttime DESC
LAST 24 HOURS`,
  detectionExplanation: 'GPO modification allows an attacker with domain admin privileges to deploy scripts, change security policies, or modify login/startup scripts across the entire domain. Events 5136 (directory service object modification) and 5137 (directory service object creation) on groupPolicyContainer objects indicate GPO changes.',
  requiredLogs: ['Windows Security Event Logs (5136, 5137)'],
  logConfig: 'Enable Directory Service Changes auditing on domain controllers.',
  falsePositives: ['Authorized GPO administration by IT staff'],
  tuning: 'Cross-reference with change management. Alert on GPO changes outside maintenance windows.',
  commonErrors: ['Directory service auditing must be enabled', 'GPO changes are common in large environments'],
  responseActions: ['Verify the GPO change was authorized', 'Review the GPO content for malicious scripts', 'Check if the admin account is compromised', 'Audit all recent GPO deployments'],
  threatIntel: { cves: [], cisaKev: false, campaigns: ['Ryuk', 'Conti'], iocs: [] },
  references: ['https://attack.mitre.org/techniques/T1484/001/']
},

// ═══ FILELESS MALWARE ═══
{
  id: 'SR-0188', title: 'Fileless Execution via Reflection Loading',
  status: 'stable', severity: 'high', author: 'SigmaHQ Aligned', date: '2024-08-15', modified: '2024-12-10',
  category: 'execution',
  description: 'Detects PowerShell reflection loading techniques used to load .NET assemblies directly into memory for fileless execution, bypassing disk-based detection.',
  tacticId: 'TA0002', tacticName: 'Execution',
  techniqueId: 'T1620', techniqueName: 'Reflective Code Loading',
  logsource: { product: 'windows', service: 'powershell-scriptblock' },
  sigmaYaml: `title: Reflective Assembly Loading in PowerShell
id: 11787860-7777-8888-9999-000011110188
status: stable
logsource:
    product: windows
    service: powershell-scriptblock
detection:
    selection:
        ScriptBlockText|contains:
            - 'System.Reflection.Assembly'
            - '[Reflection.Assembly]::Load'
            - 'Assembly.Load'
            - 'Unsafe.AsPointer'
            - 'DelegateType'
            - 'GetDelegateForFunctionPointer'
    condition: selection
level: high
tags:
    - attack.execution
    - attack.t1620`,
  splunkQuery: `index=wineventlog sourcetype=WinEventLog:Microsoft-Windows-PowerShell/Operational EventCode=4104
| where match(ScriptBlockText,"(?i)(System\\.Reflection\\.Assembly|\\[Reflection\\.Assembly\\]::Load|Assembly\\.Load|GetDelegateForFunctionPointer)")
| table _time, ComputerName, User, ScriptBlockText
| head 50`,
  qradarQuery: `SELECT sourceip, username,
  UTF8(payload) as script_content,
  COUNT(*) as reflection_events
FROM events
WHERE LOGSOURCETYPENAME(devicetype) ILIKE '%PowerShell%'
  AND EventID = 4104
  AND (UTF8(payload) ILIKE '%Reflection.Assembly%' OR UTF8(payload) ILIKE '%Assembly.Load%'
    OR UTF8(payload) ILIKE '%GetDelegateForFunctionPointer%')
GROUP BY sourceip, username, UTF8(payload)
ORDER BY starttime DESC
LAST 24 HOURS`,
  detectionExplanation: 'Reflective assembly loading executes .NET assemblies entirely in memory without writing to disk. This is the foundation of fileless malware. PowerShell uses System.Reflection.Assembly.Load() to load byte arrays as assemblies, enabling execution of tools like Mimikatz, Rubeus, and SharpHound without touching disk.',
  requiredLogs: ['PowerShell Script Block Logging (Event ID 4104)'],
  logConfig: 'Enable PowerShell Script Block Logging.',
  falsePositives: ['DevOps tools using .NET assemblies', 'Legitimate automation frameworks'],
  tuning: 'Focus on script blocks that combine reflection loading with suspicious byte arrays or base64 data.',
  commonErrors: ['Script Block Logging must be enabled', 'Large assemblies may be split across multiple script blocks'],
  responseActions: ['Extract and analyze the loaded assembly', 'Identify the tool being loaded', 'Check for credential access or lateral movement', 'Review the user account for compromise'],
  threatIntel: { cves: [], cisaKev: false, campaigns: ['Cobalt Strike', 'ALPHV/BlackCat'], iocs: [] },
  references: ['https://attack.mitre.org/techniques/T1620/']
},

// ═══ CONTAINER SECURITY ═══
{
  id: 'SR-0189', title: 'Container Escape — Privileged Container or HostPID',
  status: 'stable', severity: 'critical', author: 'SigmaHQ Aligned', date: '2024-11-10', modified: '2024-12-15',
  category: 'cloud-threats',
  description: 'Detects creation of Kubernetes containers with privileged mode, hostPID, or hostNetwork enabled, which could allow container escape and host compromise.',
  tacticId: 'TA0004', tacticName: 'Privilege Escalation',
  techniqueId: 'T1611', techniqueName: 'Escape to Host',
  logsource: { product: 'kubernetes', service: 'audit' },
  sigmaYaml: `title: Privileged Container or Host Namespace Access
id: 22898971-8888-9999-0000-111122220189
status: stable
logsource:
    product: kubernetes
    service: audit
detection:
    selection:
        verb: 'create'
        objectRef.resource: 'pods'
        requestObject.spec.containers.securityContext.privileged: true
    selection_hostpid:
        requestObject.spec.hostPID: true
    selection_hostnet:
        requestObject.spec.hostNetwork: true
    condition: selection or selection_hostpid or selection_hostnet
level: critical
tags:
    - attack.privilege_escalation
    - attack.t1611`,
  splunkQuery: `index=kubernetes sourcetype=kube:audit verb=create objectRef.resource=pods
| where match(_raw,"(?i)(privileged.*true|hostPID.*true|hostNetwork.*true)")
| table _time, user.username, objectRef.namespace, objectRef.name, sourceIPs{}, responseStatus.code`,
  qradarQuery: `SELECT username, sourceip,
  eventname,
  COUNT(*) as privileged_containers
FROM events
WHERE LOGSOURCETYPENAME(devicetype) ILIKE '%Kubernetes%'
  AND eventname ILIKE '%create%pod%'
  AND (eventname ILIKE '%privileged%' OR UTF8(payload) ILIKE '%privileged%true%' OR UTF8(payload) ILIKE '%hostPID%true%')
GROUP BY username, sourceip, eventname
ORDER BY starttime DESC
LAST 24 HOURS`,
  detectionExplanation: 'Privileged containers run with full host capabilities and can access host resources. hostPID shares the host process namespace, and hostNetwork shares the network namespace. These configurations enable container escape, allowing an attacker to compromise the underlying host from within a container.',
  requiredLogs: ['Kubernetes Audit Logs'],
  logConfig: 'Enable Kubernetes audit logging at the RequestResponse level for pod operations.',
  falsePositives: ['Legitimate infrastructure pods requiring host access', 'CNI and CSI driver pods'],
  tuning: 'Allowlist known infrastructure namespaces (kube-system). Alert on privileged pods in application namespaces.',
  commonErrors: ['K8s audit logs require proper collection', 'Many monitoring tools legitimately need privileged access'],
  responseActions: ['Review the pod specification', 'Check if the container needs privileged access', 'Apply PodSecurityPolicy or OPA constraints', 'Investigate the user creating the pod'],
  threatIntel: { cves: [], cisaKev: false, campaigns: ['TeamTNT', 'Hildegard'], iocs: [] },
  references: ['https://attack.mitre.org/techniques/T1611/']
},

// ═══ WEB SHELL DETECTION ═══
{
  id: 'SR-0190', title: 'Web Shell File Creation on Web Server',
  status: 'stable', severity: 'critical', author: 'SigmaHQ Aligned', date: '2024-03-25', modified: '2024-12-15',
  category: 'web-attacks',
  description: 'Detects creation of suspicious script files in web server directories, indicating potential web shell deployment following exploitation of a web application.',
  tacticId: 'TA0003', tacticName: 'Persistence',
  techniqueId: 'T1505.003', techniqueName: 'Web Shell',
  logsource: { product: 'windows', category: 'file_event' },
  sigmaYaml: `title: Web Shell File Creation Detection
id: 33909082-9999-0000-1111-222233330190
status: stable
logsource:
    category: file_event
    product: windows
detection:
    selection:
        TargetFilename|contains:
            - '\\\\inetpub\\\\wwwroot\\\\'
            - '\\\\wwwroot\\\\'
            - '\\\\htdocs\\\\'
            - '\\\\webapps\\\\'
        TargetFilename|endswith:
            - '.aspx'
            - '.asp'
            - '.jsp'
            - '.php'
            - '.jspx'
    filter_iis:
        Image|endswith: '\\\\msdeploy.exe'
    condition: selection and not filter_iis
level: critical
tags:
    - attack.persistence
    - attack.t1505.003`,
  splunkQuery: `index=wineventlog sourcetype=WinEventLog:Sysmon EventCode=11
| where match(TargetFilename,"(?i)(inetpub\\\\wwwroot|wwwroot|htdocs|webapps)")
  AND match(TargetFilename,"(?i)\\.(aspx|asp|jsp|php|jspx)$")
  AND NOT match(Image,"(?i)msdeploy\\.exe$")
| table _time, ComputerName, User, Image, TargetFilename`,
  qradarQuery: `SELECT sourceip, username,
  Filename, "File Path",
  COUNT(*) as webshell_events
FROM events
WHERE QIDNAME(qid) ILIKE '%File Create%'
  AND ("File Path" ILIKE '%wwwroot%' OR "File Path" ILIKE '%htdocs%' OR "File Path" ILIKE '%webapps%')
  AND (Filename ILIKE '%.aspx' OR Filename ILIKE '%.asp' OR Filename ILIKE '%.jsp' OR Filename ILIKE '%.php')
GROUP BY sourceip, username, Filename, "File Path"
ORDER BY starttime DESC
LAST 24 HOURS`,
  detectionExplanation: 'Web shells are malicious scripts uploaded to web servers, providing persistent remote access. They are typically placed in web-accessible directories (wwwroot, htdocs, webapps) as .aspx, .asp, .jsp, or .php files. Any new script file creation in these directories outside of deployment windows is highly suspicious.',
  requiredLogs: ['Sysmon Event ID 11 (File Create)'],
  logConfig: 'Sysmon with file creation monitoring on web server directories.',
  falsePositives: ['Legitimate web application deployments', 'CMS plugin installations'],
  tuning: 'Baseline deployment processes. Alert on file creation by w3wp.exe, java.exe, or httpd processes.',
  commonErrors: ['Web deployments frequently create files in these directories', 'CMS systems auto-generate PHP/ASP files'],
  responseActions: ['CRITICAL: Possible web shell deployed', 'Immediately review the created file content', 'Check for exploitation indicators in web logs', 'Isolate the web server if malicious', 'Full web application security assessment'],
  threatIntel: { cves: ['CVE-2021-34473'], cisaKev: true, campaigns: ['HAFNIUM', 'Volt Typhoon'], iocs: [] },
  references: ['https://attack.mitre.org/techniques/T1505/003/']
},

// ═══ BOOT/LOGON PERSISTENCE ═══
{
  id: 'SR-0191', title: 'Boot Configuration Modification — BCD Edit',
  status: 'stable', severity: 'high', author: 'SigmaHQ Aligned', date: '2024-09-05', modified: '2024-12-10',
  category: 'persistence',
  description: 'Detects bcdedit.exe being used to modify boot configuration data, including Safe Mode changes, boot debugging, and integrity check disabling that may indicate advanced persistence or pre-ransomware activity.',
  tacticId: 'TA0003', tacticName: 'Persistence',
  techniqueId: 'T1542.003', techniqueName: 'Bootkit',
  logsource: { product: 'windows', category: 'process_creation' },
  sigmaYaml: `title: Suspicious BCDEdit Boot Configuration Changes
id: 44010193-0000-1111-2222-333344440191
status: stable
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image|endswith: '\\\\bcdedit.exe'
        CommandLine|contains:
            - 'safeboot'
            - 'bootdebug'
            - 'testsigning'
            - 'nointegritychecks'
            - 'loadoptions DISABLE_INTEGRITY'
    condition: selection
level: high
tags:
    - attack.persistence
    - attack.t1542.003`,
  splunkQuery: `index=wineventlog sourcetype=WinEventLog:Sysmon EventCode=1
| where match(Image,"(?i)\\\\bcdedit\\.exe$")
  AND match(CommandLine,"(?i)(safeboot|bootdebug|testsigning|nointegritychecks|DISABLE_INTEGRITY)")
| table _time, ComputerName, User, CommandLine`,
  qradarQuery: `SELECT sourceip, username,
  Command,
  COUNT(*) as bcd_events
FROM events
WHERE CATEGORYNAME(category) ILIKE '%Process%Create%'
  AND Filename ILIKE '%bcdedit.exe'
  AND (Command ILIKE '%safeboot%' OR Command ILIKE '%testsigning%' OR Command ILIKE '%nointegritychecks%')
GROUP BY sourceip, username, Command
ORDER BY starttime DESC
LAST 24 HOURS`,
  detectionExplanation: 'BCDEdit modifies boot configuration. Attackers use it to enable Safe Mode boot (to run with minimal security), enable test signing (to load unsigned drivers), or disable integrity checks (to load rootkits). These changes are often pre-ransomware preparation steps.',
  requiredLogs: ['Sysmon Event ID 1'],
  logConfig: 'Process creation with command line monitoring.',
  falsePositives: ['IT staff enabling test signing for driver development', 'System administrators troubleshooting boot issues'],
  tuning: 'Any bcdedit modification outside of IT operations warrants investigation.',
  commonErrors: ['Some legitimate driver installations require test signing mode'],
  responseActions: ['Verify the change with IT operations', 'Check for follow-on suspicious driver loading', 'Revert the boot configuration changes', 'Investigate how the attacker gained admin access'],
  threatIntel: { cves: [], cisaKev: false, campaigns: ['REvil', 'MedusaLocker'], iocs: [] },
  references: ['https://attack.mitre.org/techniques/T1542/003/']
},

// ═══ CERTIFICATE THEFT ═══
{
  id: 'SR-0192', title: 'Certificate Private Key Export',
  status: 'stable', severity: 'high', author: 'SigmaHQ Aligned', date: '2024-10-05', modified: '2024-12-10',
  category: 'credential-access',
  description: 'Detects export of certificate private keys using certutil, PowerShell, or other tools. Certificate theft enables code signing impersonation, TLS interception, and authentication bypass.',
  tacticId: 'TA0006', tacticName: 'Credential Access',
  techniqueId: 'T1649', techniqueName: 'Steal or Forge Authentication Certificates',
  logsource: { product: 'windows', category: 'process_creation' },
  sigmaYaml: `title: Certificate Private Key Export
id: 55121204-1111-2222-3333-444455550192
status: stable
logsource:
    category: process_creation
    product: windows
detection:
    selection_certutil:
        Image|endswith: '\\\\certutil.exe'
        CommandLine|contains:
            - '-exportPFX'
            - '-backup'
    selection_ps:
        CommandLine|contains:
            - 'Export-PfxCertificate'
            - 'Export-Certificate'
    selection_crypto:
        CommandLine|contains:
            - 'CertOpen'
            - 'PFXExport'
    condition: selection_certutil or selection_ps or selection_crypto
level: high
tags:
    - attack.credential_access
    - attack.t1649`,
  splunkQuery: `index=wineventlog sourcetype=WinEventLog:Sysmon EventCode=1
| where (match(Image,"(?i)certutil\\.exe$") AND match(CommandLine,"(?i)(-exportPFX|-backup)"))
  OR match(CommandLine,"(?i)(Export-PfxCertificate|Export-Certificate|PFXExport)")
| table _time, ComputerName, User, Image, CommandLine`,
  qradarQuery: `SELECT sourceip, username,
  Command,
  COUNT(*) as cert_export
FROM events
WHERE CATEGORYNAME(category) ILIKE '%Process%Create%'
  AND (Command ILIKE '%exportPFX%' OR Command ILIKE '%Export-PfxCertificate%'
    OR Command ILIKE '%-backup%cert%')
GROUP BY sourceip, username, Command
ORDER BY starttime DESC
LAST 24 HOURS`,
  detectionExplanation: 'Certificate private keys are high-value targets. With a stolen code-signing cert, attackers can sign malware. With TLS certs, they can intercept encrypted communications. With AD CS certificates, they can authenticate as any user. Certutil -exportPFX and PowerShell Export-PfxCertificate are primary export methods.',
  requiredLogs: ['Sysmon Event ID 1'],
  logConfig: 'Process creation logging. Also monitor certificate store access events (Event ID 70).',
  falsePositives: ['Certificate backup procedures', 'Certificate migration between servers'],
  tuning: 'Alert on all certificate exports. Cross-reference with authorized certificate management activities.',
  commonErrors: ['Certificate exports during migration are legitimate', 'Some backup tools export certificates'],
  responseActions: ['Verify the export was authorized', 'Check if the certificate was used to sign anything', 'Revoke the certificate if theft is confirmed', 'Investigate how the attacker accessed the certificate store'],
  threatIntel: { cves: [], cisaKev: false, campaigns: ['APT29 AD CS abuse'], iocs: [] },
  references: ['https://attack.mitre.org/techniques/T1649/']
},

// ═══ SCHTASKS COMMAND LINE ABUSE ═══
{
  id: 'SR-0193', title: 'Scheduled Task Created via XML — Remote Execution',
  status: 'stable', severity: 'high', author: 'SigmaHQ Aligned', date: '2024-11-05', modified: '2024-12-10',
  category: 'lateral-movement',
  description: 'Detects schtasks.exe using /XML flag or /S flag for remote task creation, commonly used for lateral movement by deploying scheduled tasks on remote systems.',
  tacticId: 'TA0008', tacticName: 'Lateral Movement',
  techniqueId: 'T1053.005', techniqueName: 'Scheduled Task',
  logsource: { product: 'windows', category: 'process_creation' },
  sigmaYaml: `title: Remote Scheduled Task via XML or Network
id: 66232315-2222-3333-4444-555566660193
status: stable
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image|endswith: '\\\\schtasks.exe'
        CommandLine|contains:
            - '/S '
            - '/XML'
            - '/s '
    selection_create:
        CommandLine|contains: '/create'
    condition: selection and selection_create
level: high
tags:
    - attack.lateral_movement
    - attack.t1053.005`,
  splunkQuery: `index=wineventlog sourcetype=WinEventLog:Sysmon EventCode=1
| where match(Image,"(?i)\\\\schtasks\\.exe$")
  AND match(CommandLine,"(?i)/create")
  AND match(CommandLine,"(?i)(/S\\s|/XML|/s\\s)")
| table _time, ComputerName, User, CommandLine`,
  qradarQuery: `SELECT sourceip, username,
  Command,
  COUNT(*) as remote_task
FROM events
WHERE CATEGORYNAME(category) ILIKE '%Process%Create%'
  AND Filename ILIKE '%schtasks.exe'
  AND Command ILIKE '%/create%'
  AND (Command ILIKE '%/S %' OR Command ILIKE '%/XML%')
GROUP BY sourceip, username, Command
ORDER BY starttime DESC
LAST 24 HOURS`,
  detectionExplanation: 'The /S flag in schtasks specifies a remote system to create the task on. The /XML flag loads task configuration from an XML file. Together, these enable remote code execution by deploying scheduled tasks on other machines. This is a common lateral movement technique used by ransomware operators.',
  requiredLogs: ['Sysmon Event ID 1'],
  logConfig: 'Process creation with command line monitoring.',
  falsePositives: ['SCCM deploying scheduled tasks', 'IT automation using schtasks remotely'],
  tuning: 'Focus on /S flag with non-management source systems. IT automation tools should be baselined.',
  commonErrors: ['Remote task creation is common in enterprise management tools'],
  responseActions: ['Identify the target system', 'Check what command the task executes', 'Verify with IT if the task is authorized', 'Remove unauthorized remote tasks'],
  threatIntel: { cves: [], cisaKev: false, campaigns: ['Conti', 'Black Basta'], iocs: [] },
  references: ['https://attack.mitre.org/techniques/T1053/005/']
},

// ═══ ARCHIVE WITH PASSWORD — EXFILTRATION PREP ═══
{
  id: 'SR-0194', title: 'Password-Protected Archive Creation — Exfil Staging',
  status: 'stable', severity: 'high', author: 'SigmaHQ Aligned', date: '2024-08-25', modified: '2024-12-10',
  category: 'data-exfiltration',
  description: 'Detects creation of password-protected archives using 7zip, WinRAR, or tar, commonly used to stage data for exfiltration while evading DLP controls.',
  tacticId: 'TA0009', tacticName: 'Collection',
  techniqueId: 'T1560.001', techniqueName: 'Archive via Utility',
  logsource: { product: 'windows', category: 'process_creation' },
  sigmaYaml: `title: Password-Protected Archive for Exfiltration
id: 77343426-3333-4444-5555-666677770194
status: stable
logsource:
    category: process_creation
    product: windows
detection:
    selection_7z:
        Image|endswith: '\\\\7z.exe'
        CommandLine|contains: '-p'
    selection_rar:
        Image|endswith: '\\\\rar.exe'
        CommandLine|contains: '-hp'
    condition: selection_7z or selection_rar
level: high
tags:
    - attack.collection
    - attack.t1560.001`,
  splunkQuery: `index=wineventlog sourcetype=WinEventLog:Sysmon EventCode=1
| where (match(Image,"(?i)\\\\7z\\.exe$") AND match(CommandLine,"(?i)-p"))
  OR (match(Image,"(?i)\\\\rar\\.exe$") AND match(CommandLine,"(?i)-hp"))
| table _time, ComputerName, User, Image, CommandLine`,
  qradarQuery: `SELECT sourceip, username,
  Filename, Command,
  COUNT(*) as encrypted_archive
FROM events
WHERE CATEGORYNAME(category) ILIKE '%Process%Create%'
  AND ((Filename ILIKE '%7z.exe' AND Command ILIKE '%-p%')
    OR (Filename ILIKE '%rar.exe' AND Command ILIKE '%-hp%'))
GROUP BY sourceip, username, Filename, Command
ORDER BY starttime DESC
LAST 24 HOURS`,
  detectionExplanation: 'Attackers create password-protected archives to compress and encrypt stolen data before exfiltration. The password protects the archive from DLP inspection and forensic analysis. 7z uses -p flag and WinRAR uses -hp flag for password-protected archives.',
  requiredLogs: ['Sysmon Event ID 1'],
  logConfig: 'Process creation with command line monitoring.',
  falsePositives: ['Legitimate password-protected file sharing', 'IT sending encrypted archives'],
  tuning: 'Focus on password-protected archives created with sensitive file paths in the command line.',
  commonErrors: ['Password-protected archives are legitimately used for secure file transfer'],
  responseActions: ['Determine what files were archived', 'Check for subsequent upload or transfer activity', 'Verify the activity with the user'],
  threatIntel: { cves: [], cisaKev: false, campaigns: ['LockBit', 'Karakurt'], iocs: [] },
  references: ['https://attack.mitre.org/techniques/T1560/001/']
},

// ═══ SUSPICIOUS PARENT-CHILD — HIGH FIDELITY ═══
{
  id: 'SR-0195', title: 'Suspicious Process Spawned by Script Host',
  status: 'stable', severity: 'high', author: 'SigmaHQ Aligned', date: '2024-04-10', modified: '2024-12-15',
  category: 'execution',
  description: 'Detects Windows Script Host (wscript/cscript) spawning suspicious child processes like PowerShell, cmd, or network utilities, indicating malicious script execution.',
  tacticId: 'TA0002', tacticName: 'Execution',
  techniqueId: 'T1059.005', techniqueName: 'Visual Basic',
  logsource: { product: 'windows', category: 'process_creation' },
  sigmaYaml: `title: Script Host Spawning Suspicious Process
id: 88454537-4444-5555-6666-777788880195
status: stable
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        ParentImage|endswith:
            - '\\\\wscript.exe'
            - '\\\\cscript.exe'
        Image|endswith:
            - '\\\\cmd.exe'
            - '\\\\powershell.exe'
            - '\\\\pwsh.exe'
            - '\\\\certutil.exe'
            - '\\\\bitsadmin.exe'
            - '\\\\mshta.exe'
            - '\\\\curl.exe'
    condition: selection
level: high
tags:
    - attack.execution
    - attack.t1059.005`,
  splunkQuery: `index=wineventlog sourcetype=WinEventLog:Sysmon EventCode=1
| where match(ParentImage,"(?i)(wscript|cscript)\\.exe$")
  AND match(Image,"(?i)(cmd|powershell|pwsh|certutil|bitsadmin|mshta|curl)\\.exe$")
| table _time, ComputerName, User, ParentImage, Image, CommandLine`,
  qradarQuery: `SELECT sourceip, username,
  "Parent Process Path", Filename, Command,
  COUNT(*) as script_exec
FROM events
WHERE CATEGORYNAME(category) ILIKE '%Process%Create%'
  AND ("Parent Process Path" ILIKE '%wscript.exe' OR "Parent Process Path" ILIKE '%cscript.exe')
  AND (Filename ILIKE '%cmd.exe' OR Filename ILIKE '%powershell.exe' OR Filename ILIKE '%certutil.exe' OR Filename ILIKE '%mshta.exe')
GROUP BY sourceip, username, "Parent Process Path", Filename, Command
ORDER BY starttime DESC
LAST 24 HOURS`,
  detectionExplanation: 'Windows Script Host (wscript.exe/cscript.exe) executing VBScript/JScript should rarely spawn command interpreters or network tools. This parent-child relationship is a strong indicator of malicious scripts (typically delivered via email or web download) executing payloads.',
  requiredLogs: ['Sysmon Event ID 1'],
  logConfig: 'Process creation with parent process tracking.',
  falsePositives: ['Legitimate login scripts using VBScript', 'IT automation via WSH scripts'],
  tuning: 'Baseline legitimate WSH usage. Focus on wscript/cscript spawning certutil, bitsadmin, or curl.',
  commonErrors: ['Login scripts may legitimately use wscript/cscript', 'GPO scripts executed via cscript'],
  responseActions: ['Identify the script being executed', 'Check for the script file on disk', 'Analyze the child process commands', 'Block WSH execution if not needed via policy'],
  threatIntel: { cves: [], cisaKev: false, campaigns: ['Emotet', 'Qakbot', 'IcedID'], iocs: [] },
  references: ['https://attack.mitre.org/techniques/T1059/005/']
}

];
