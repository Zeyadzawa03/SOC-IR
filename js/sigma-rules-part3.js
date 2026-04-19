// Sigma Rules Database - Part 3: Additional Deep Coverage Rules
// Focuses on high-risk tactics: Defense Evasion, Credential Access, Lateral Movement, C2
const SIGMA_RULES_PART3 = [

// ═══════════════════════════════════════════════════════════════
// ADDITIONAL DEFENSE EVASION (TA0005) - Deep Coverage
// ═══════════════════════════════════════════════════════════════
{
  id: 'SR-0056', title: 'MSHTA Execution for Proxy Execution',
  status: 'stable', severity: 'high', author: 'SOC Platform', date: '2024-08-15', modified: '2024-12-10',
  category: 'defense-evasion',
  description: 'Detects mshta.exe executing HTA files or inline scripts, a common defense evasion technique used to bypass application whitelisting since mshta.exe is a trusted Microsoft binary.',
  tacticId: 'TA0005', tacticName: 'Defense Evasion',
  techniqueId: 'T1218.005', techniqueName: 'Mshta',
  logsource: { product: 'windows', category: 'process_creation' },
  sigmaYaml: `title: MSHTA Execution for Proxy Execution
id: aabb0011-2233-4455-6677-8899aabbccdd
status: stable
description: Detects suspicious mshta.exe execution patterns
author: SOC Platform
date: 2024/08/15
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image|endswith: '\\\\mshta.exe'
    selection_suspicious:
        CommandLine|contains:
            - 'javascript:'
            - 'vbscript:'
            - 'http://'
            - 'https://'
            - 'about:'
            - '\\\\Temp\\\\'
            - '\\\\AppData\\\\'
    condition: selection and selection_suspicious
falsepositives:
    - Legitimate HTA-based administration tools
    - Legacy enterprise applications using HTA
level: high
tags:
    - attack.defense_evasion
    - attack.t1218.005`,
  detectionExplanation: 'MSHTA.exe (Microsoft HTML Application Host) can execute HTA files containing JavaScript or VBScript. Since it is a signed Microsoft binary, it bypasses many application whitelisting solutions. Attackers use it to run inline scripts (javascript: or vbscript: protocols) or download and execute remote HTA payloads. This is a LOLBIN technique frequently used in phishing campaigns.',
  requiredLogs: ['Sysmon Event ID 1', 'Windows Security 4688'],
  logConfig: 'Command line auditing must capture full arguments to mshta.exe.',
  falsePositives: ['Legacy enterprise HTA applications', 'Some antivirus management consoles using HTA interfaces'],
  tuning: 'Allowlist known legitimate HTA applications by path. Focus on mshta with inline script protocols (javascript:, vbscript:) or downloading remote content.',
  commonErrors: ['HTA content may be obfuscated making pattern matching difficult', 'Child processes of mshta may be more detectable than mshta itself'],
  responseActions: ['Analyze the HTA content or URL being executed', 'Check what child processes mshta spawned', 'Block the source URL if remote content was loaded', 'Investigate how the HTA was delivered (email, web download)'],
  threatIntel: { cves: [], cisaKev: false, campaigns: ['Scattered Spider'], iocs: [] },
  references: ['https://attack.mitre.org/techniques/T1218/005/', 'https://lolbas-project.github.io/lolbas/Binaries/Mshta/']
},
{
  id: 'SR-0057', title: 'Regsvr32 Proxy Execution (Squiblydoo)',
  status: 'stable', severity: 'high', author: 'SOC Platform', date: '2024-09-01', modified: '2024-12-15',
  category: 'defense-evasion',
  description: 'Detects regsvr32.exe being used to execute COM scriptlets from remote URLs or local files for defense evasion, known as the Squiblydoo attack technique.',
  tacticId: 'TA0005', tacticName: 'Defense Evasion',
  techniqueId: 'T1218.010', techniqueName: 'Regsvr32',
  logsource: { product: 'windows', category: 'process_creation' },
  sigmaYaml: `title: Regsvr32 Proxy Execution (Squiblydoo)
id: bbcc1122-3344-5566-7788-99aabbccddee
status: stable
description: Detects regsvr32.exe abuse for proxy execution
author: SOC Platform
date: 2024/09/01
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image|endswith: '\\\\regsvr32.exe'
    selection_scrobj:
        CommandLine|contains:
            - '/i:http'
            - '/i:https'
            - '/i:ftp'
            - 'scrobj.dll'
            - '/s /n /u /i:'
    condition: selection and selection_scrobj
falsepositives:
    - Very rare legitimate use of regsvr32 with scrobj.dll
level: high
tags:
    - attack.defense_evasion
    - attack.t1218.010`,
  detectionExplanation: 'Regsvr32.exe can load COM scriptlets (.sct files) using the scrobj.dll library. The Squiblydoo technique abuses this by pointing regsvr32 at a remote URL hosting a malicious scriptlet. Since regsvr32 is a signed Microsoft binary and the /s flag runs silently, this effectively bypasses AppLocker and other whitelisting controls while downloading and executing arbitrary code.',
  requiredLogs: ['Sysmon Event ID 1'],
  logConfig: 'Standard process creation with command line logging.',
  falsePositives: ['Extremely rare - this combination is almost exclusively malicious'],
  tuning: 'This is a high-fidelity detection. Any regsvr32 with /i: pointing to a URL or using scrobj.dll should be investigated.',
  commonErrors: ['URL may be obfuscated or encoded', 'Attackers may use variations in flag ordering'],
  responseActions: ['Block the remote URL immediately', 'Analyze the SCT scriptlet content', 'Check for payload execution from the scriptlet', 'Investigate the delivery mechanism'],
  threatIntel: { cves: [], cisaKev: false, campaigns: [], iocs: [] },
  references: ['https://attack.mitre.org/techniques/T1218/010/']
},
{
  id: 'SR-0058', title: 'Firewall Rule Modification',
  status: 'stable', severity: 'high', author: 'SOC Platform', date: '2024-07-20', modified: '2024-11-30',
  category: 'defense-evasion',
  description: 'Detects modification of Windows Firewall rules via netsh or PowerShell to allow inbound connections, create new rules, or disable the firewall entirely for defense evasion.',
  tacticId: 'TA0005', tacticName: 'Defense Evasion',
  techniqueId: 'T1562.004', techniqueName: 'Disable or Modify System Firewall',
  logsource: { product: 'windows', category: 'process_creation' },
  sigmaYaml: `title: Firewall Rule Modification
id: ccdd2233-4455-6677-8899-aabbccddeeff
status: stable
description: Detects Windows Firewall modifications for defense evasion
author: SOC Platform
date: 2024/07/20
logsource:
    category: process_creation
    product: windows
detection:
    selection_netsh:
        Image|endswith: '\\\\netsh.exe'
        CommandLine|contains:
            - 'advfirewall'
            - 'firewall'
        CommandLine|contains:
            - 'add rule'
            - 'delete rule'
            - 'set allprofiles state off'
            - 'set currentprofile state off'
    selection_ps:
        CommandLine|contains:
            - 'New-NetFirewallRule'
            - 'Set-NetFirewallProfile.*-Enabled False'
            - 'Disable-NetFirewallRule'
    condition: selection_netsh or selection_ps
falsepositives:
    - IT administrators configuring firewall rules
    - Software installation requiring firewall exceptions
level: high
tags:
    - attack.defense_evasion
    - attack.t1562.004`,
  detectionExplanation: 'Attackers modify firewall rules to enable inbound connections (for reverse shells, C2, or lateral movement) or to disable the firewall entirely. Netsh commands adding rules with "allow" action and "in" direction are especially suspicious. Disabling the firewall across all profiles removes a critical defense layer.',
  requiredLogs: ['Sysmon Event ID 1', 'Windows Firewall Log (Microsoft-Windows-Windows Firewall With Advanced Security/Firewall)'],
  logConfig: 'Process creation logging. Also enable Windows Firewall change auditing.',
  falsePositives: ['Software installers adding firewall exceptions', 'IT deploying firewall rules via GPO or scripts', 'VPN software modifying firewall configuration'],
  tuning: 'Focus on rules allowing inbound connections and firewall disable commands. Compare against change management records.',
  commonErrors: ['Legitimate software frequently adds firewall rules during installation', 'GPO-based firewall changes may be hard to distinguish'],
  responseActions: ['Review the specific firewall rule that was added/modified', 'Check if inbound access was enabled to suspicious ports', 'Verify with the IT team if the change was authorized', 'Restore firewall rules to previous state if unauthorized'],
  threatIntel: { cves: [], cisaKev: false, campaigns: ['LockBit 3.0'], iocs: [] },
  references: ['https://attack.mitre.org/techniques/T1562/004/']
},

// ═══════════════════════════════════════════════════════════════
// ADDITIONAL CREDENTIAL ACCESS (TA0006) - Deep Coverage
// ═══════════════════════════════════════════════════════════════
{
  id: 'SR-0059', title: 'SAM Database Access for Credential Dumping',
  status: 'stable', severity: 'critical', author: 'SOC Platform', date: '2024-04-10', modified: '2024-12-05',
  category: 'credential-access',
  description: 'Detects attempts to access or copy the SAM, SYSTEM, and SECURITY registry hives which contain local account password hashes. This is a primary credential dumping technique used for offline cracking.',
  tacticId: 'TA0006', tacticName: 'Credential Access',
  techniqueId: 'T1003.002', techniqueName: 'Security Account Manager',
  logsource: { product: 'windows', category: 'process_creation' },
  sigmaYaml: `title: SAM Database Access for Credential Dumping
id: ddee3344-5566-7788-99aa-bbccddeeff00
status: stable
description: Detects SAM/SYSTEM/SECURITY hive extraction for credential dumping
author: SOC Platform
date: 2024/04/10
logsource:
    category: process_creation
    product: windows
detection:
    selection_reg:
        Image|endswith: '\\\\reg.exe'
        CommandLine|contains:
            - 'save'
            - 'export'
        CommandLine|contains:
            - 'hklm\\\\sam'
            - 'hklm\\\\security'
            - 'hklm\\\\system'
    selection_copy:
        CommandLine|contains:
            - '\\\\Windows\\\\System32\\\\config\\\\SAM'
            - '\\\\Windows\\\\System32\\\\config\\\\SYSTEM'
            - '\\\\Windows\\\\System32\\\\config\\\\SECURITY'
    selection_shadow:
        CommandLine|contains:
            - 'vssadmin'
            - 'esentutl'
        CommandLine|contains:
            - 'SAM'
            - 'SYSTEM'
            - 'ntds'
    condition: selection_reg or selection_copy or selection_shadow
falsepositives:
    - Legitimate backup procedures
    - Forensic tools during authorized investigations
level: critical
tags:
    - attack.credential_access
    - attack.t1003.002`,
  detectionExplanation: 'The SAM database stores local account password hashes. Attackers extract SAM, SYSTEM, and SECURITY hives using reg.exe save, direct file copy via volume shadow copies, or esentutl. The SYSTEM hive is needed to decrypt SAM entries (it contains the boot key). This is a fundamental credential dumping technique that predates Mimikatz and is still widely used.',
  requiredLogs: ['Sysmon Event ID 1', 'Windows Security 4688'],
  logConfig: 'Command line auditing. Consider file access auditing on registry hive files.',
  falsePositives: ['System backup procedures backing up registry', 'Digital forensic investigations', 'Microsoft USMT during migrations'],
  tuning: 'This detection has very low false positive rate. Any occurrence outside of scheduled backups should be investigated as critical.',
  commonErrors: ['Shadow copy access may use different syntax', 'esentutl can also extract from NTDS.dit for domain credentials'],
  responseActions: ['CRITICAL: Active credential dumping in progress', 'Isolate the system immediately', 'Assume all local account credentials are compromised', 'Force password reset for all local accounts', 'Check for lateral movement using extracted credentials', 'Full incident response required'],
  threatIntel: { cves: [], cisaKev: false, campaigns: ['LockBit 3.0', 'ALPHV/BlackCat Ransomware'], iocs: [] },
  references: ['https://attack.mitre.org/techniques/T1003/002/']
},
{
  id: 'SR-0060', title: 'Forced Authentication via LLMNR/NBT-NS Poisoning',
  status: 'stable', severity: 'high', author: 'SOC Platform', date: '2024-06-25', modified: '2024-12-01',
  category: 'credential-access',
  description: 'Detects tools commonly used for LLMNR/NBT-NS poisoning and forced authentication attacks (Responder, Inveigh) that capture NTLM hashes from network authentication requests.',
  tacticId: 'TA0006', tacticName: 'Credential Access',
  techniqueId: 'T1187', techniqueName: 'Forced Authentication',
  logsource: { product: 'windows', category: 'process_creation' },
  sigmaYaml: `title: Forced Authentication via LLMNR/NBT-NS Poisoning
id: eeff4455-6677-8899-aabb-ccddeeff0011
status: stable
description: Detects LLMNR/NBT-NS poisoning tools for credential capture
author: SOC Platform
date: 2024/06/25
logsource:
    category: process_creation
    product: windows
detection:
    selection_tools:
        Image|endswith:
            - '\\\\Responder.exe'
            - '\\\\Responder.py'
            - '\\\\Inveigh.exe'
            - '\\\\MultiRelay.exe'
        
    selection_ps:
        CommandLine|contains:
            - 'Invoke-Inveigh'
            - 'Invoke-InveighRelay'
            - 'responder'
            - 'LLMNR'
            - 'NBNS'
    condition: selection_tools or selection_ps
falsepositives:
    - Authorized penetration testing
    - Network diagnostic tools
level: high
tags:
    - attack.credential_access
    - attack.t1187`,
  detectionExplanation: 'LLMNR and NBT-NS poisoning allows attackers on the local network to intercept name resolution requests and capture NTLM authentication hashes. Tools like Responder and Inveigh respond to broadcast name queries, tricking victims into authenticating to the attacker-controlled host. The captured NTLMv2 hashes can be cracked offline or relayed to other services.',
  requiredLogs: ['Sysmon Event ID 1', 'Network IDS/IPS alerts'],
  logConfig: 'Process creation logging. Network monitoring for LLMNR/NBT-NS anomalies.',
  falsePositives: ['Authorized penetration testing with Responder/Inveigh', 'Network troubleshooting using LLMNR/NBT-NS diagnostic tools'],
  tuning: 'Disable LLMNR and NBT-NS via GPO as the primary mitigation. Any tool detection then becomes high-confidence malicious.',
  commonErrors: ['Python-based tools may not appear as named executables', 'PowerShell-based Inveigh may be obfuscated'],
  responseActions: ['Identify the attacker system on the network', 'Isolate the system from the network segment', 'Check for captured hashes and determine which accounts were compromised', 'Disable LLMNR and NBT-NS across the environment', 'Reset credentials for any accounts that sent NTLM hashes'],
  threatIntel: { cves: [], cisaKev: false, campaigns: [], iocs: [] },
  references: ['https://attack.mitre.org/techniques/T1187/']
},

// ═══════════════════════════════════════════════════════════════
// ADDITIONAL LATERAL MOVEMENT (TA0008) - Deep Coverage
// ═══════════════════════════════════════════════════════════════
{
  id: 'SR-0061', title: 'Pass-the-Ticket Attack Detection',
  status: 'stable', severity: 'critical', author: 'SOC Platform', date: '2024-05-20', modified: '2024-12-10',
  category: 'lateral-movement',
  description: 'Detects Pass-the-Ticket attacks by monitoring for Kerberos ticket injection and anomalous ticket usage patterns where tickets are used from systems other than where they were originally issued.',
  tacticId: 'TA0008', tacticName: 'Lateral Movement',
  techniqueId: 'T1550.003', techniqueName: 'Pass the Ticket',
  logsource: { product: 'windows', service: 'security' },
  sigmaYaml: `title: Pass-the-Ticket Attack Detection
id: ff001122-3344-5566-7788-99aabbccdd01
status: stable
description: Detects Kerberos ticket abuse for lateral movement
author: SOC Platform
date: 2024/05/20
logsource:
    product: windows
    service: security
detection:
    selection:
        EventID: 4769
    selection_mimikatz:
        Image|endswith:
            - '\\\\mimikatz.exe'
            - '\\\\rubeus.exe'
            - '\\\\kekeo.exe'
        CommandLine|contains:
            - 'ptt'
            - 'kerberos::ptt'
            - 'asktgt'
            - 'asktgs'
    condition: selection_mimikatz
falsepositives:
    - Authorized penetration testing
level: critical
tags:
    - attack.lateral_movement
    - attack.t1550.003`,
  detectionExplanation: 'Pass-the-Ticket uses stolen Kerberos tickets (TGT or TGS) to authenticate to resources as another user without knowing their password. Tools like Mimikatz (kerberos::ptt), Rubeus (ptt command), and Kekeo inject tickets into the current session. Detection focuses on known tool command patterns and anomalous Kerberos ticket usage patterns (tickets used from unexpected source IPs).',
  requiredLogs: ['Windows Security Event ID 4769', 'Sysmon Event ID 1', 'Windows Security 4768'],
  logConfig: 'Kerberos service ticket auditing on domain controllers. Process creation with command line on all endpoints.',
  falsePositives: ['Authorized penetration testing', 'Kerberos troubleshooting using klist exports'],
  tuning: 'Monitor for Kerberos tickets used from IPs different from where the TGT was issued. Hash-based detection for known tools supplements command-line detection.',
  commonErrors: ['Tools may be renamed to evade name-based detection', 'Network-level Kerberos anomaly detection requires specialized tooling'],
  responseActions: ['CRITICAL: Active credential abuse', 'Identify all accounts whose tickets were stolen', 'Force re-authentication by purging tickets (klist purge)', 'Reset the KRBTGT password if Golden Ticket is suspected', 'Investigate the source of ticket theft (likely LSASS dump)'],
  threatIntel: { cves: [], cisaKev: false, campaigns: ['Midnight Blizzard'], iocs: [] },
  references: ['https://attack.mitre.org/techniques/T1550/003/']
},
{
  id: 'SR-0062', title: 'DCOM Lateral Movement',
  status: 'stable', severity: 'high', author: 'SOC Platform', date: '2024-08-10', modified: '2024-12-05',
  category: 'lateral-movement',
  description: 'Detects lateral movement via Distributed Component Object Model (DCOM) by monitoring for MMC20.Application, ShellBrowserWindow, or other DCOM objects used for remote code execution.',
  tacticId: 'TA0008', tacticName: 'Lateral Movement',
  techniqueId: 'T1021.003', techniqueName: 'Distributed Component Object Model',
  logsource: { product: 'windows', category: 'process_creation' },
  sigmaYaml: `title: DCOM Lateral Movement
id: 00112233-4455-6677-8899-aabbccddeef2
status: stable
description: Detects DCOM-based lateral movement
author: SOC Platform
date: 2024/08/10
logsource:
    category: process_creation
    product: windows
detection:
    selection_parent:
        ParentImage|endswith:
            - '\\\\mmc.exe'
            - '\\\\svchost.exe'
    selection_child:
        Image|endswith:
            - '\\\\cmd.exe'
            - '\\\\powershell.exe'
            - '\\\\pwsh.exe'
    selection_dcom_network:
        ParentCommandLine|contains:
            - '-Embedding'
    condition: selection_parent and selection_child and selection_dcom_network
falsepositives:
    - MMC snap-in executing commands
    - Legitimate DCOM automation
level: high
tags:
    - attack.lateral_movement
    - attack.t1021.003`,
  detectionExplanation: 'DCOM allows remote object activation and method invocation. Objects like MMC20.Application provide ExecuteShellCommand method for remote execution. When DCOM is used remotely, the parent process runs with -Embedding flag. The combination of svchost/mmc with -Embedding spawning cmd/PowerShell indicates DCOM-based lateral movement.',
  requiredLogs: ['Sysmon Event ID 1 with parent process and command line'],
  logConfig: 'Full process creation logging with parent process tracking.',
  falsePositives: ['Legitimate DCOM automation in enterprise applications', 'MMC remote management activities'],
  tuning: 'Focus on -Embedding flag in parent processes. Correlate with network connections to identify the remotely initiating system.',
  commonErrors: ['DCOM can use many different COM objects - detection should be broad', 'The -Embedding flag is key but may not always be captured'],
  responseActions: ['Identify the remote system initiating the DCOM call', 'Check what commands were executed through DCOM', 'Investigate both source and target systems', 'Review DCOM permissions and restrict unnecessary access'],
  threatIntel: { cves: [], cisaKev: false, campaigns: [], iocs: [] },
  references: ['https://attack.mitre.org/techniques/T1021/003/']
},

// ═══════════════════════════════════════════════════════════════
// ADDITIONAL COMMAND AND CONTROL (TA0011) - Deep Coverage
// ═══════════════════════════════════════════════════════════════
{
  id: 'SR-0063', title: 'Encrypted C2 Channel - Suspicious TLS Certificate',
  status: 'test', severity: 'medium', author: 'SOC Platform', date: '2024-09-15', modified: '2024-12-10',
  category: 'network-anomalies',
  description: 'Detects outbound TLS connections with suspicious certificate characteristics commonly associated with C2 frameworks including self-signed certificates, short validity periods, and unusual issuer names.',
  tacticId: 'TA0011', tacticName: 'Command and Control',
  techniqueId: 'T1573.002', techniqueName: 'Asymmetric Cryptography',
  logsource: { product: 'windows', category: 'network_connection' },
  sigmaYaml: `title: Encrypted C2 Channel - Suspicious TLS Certificate
id: 11223344-5566-7788-99aa-bbccddeeff03
status: test
description: Detects outbound TLS with suspicious certificate properties
author: SOC Platform
date: 2024/09/15
logsource:
    category: network_connection
    product: windows
detection:
    selection:
        Initiated: 'true'
        DestinationPort:
            - 443
            - 8443
            - 4443
            - 8080
    filter_known:
        DestinationHostname|endswith:
            - '.microsoft.com'
            - '.google.com'
            - '.amazonaws.com'
            - '.cloudflare.com'
    condition: selection and not filter_known
    # Note: Requires TLS inspection or JA3/JA3S hash analysis
falsepositives:
    - Legitimate HTTPS traffic to uncommon destinations
    - Cloud services with new domains
level: medium
tags:
    - attack.command_and_control
    - attack.t1573.002`,
  detectionExplanation: 'C2 frameworks like Cobalt Strike, Covenant, and Metasploit often use self-signed or dynamically generated TLS certificates. Key indicators include: JA3/JA3S hash matches for known C2 frameworks, connections to IP addresses instead of domains, unusual ports (4443, 8443), and certificates with default or randomized subject names. This detection works best when combined with JA3 fingerprinting.',
  requiredLogs: ['Network flow data with TLS metadata', 'Zeek/Bro SSL logs', 'Proxy logs with TLS inspection'],
  logConfig: 'Deploy network monitoring with TLS metadata capture. JA3/JA3S hashing provides additional fingerprinting capability.',
  falsePositives: ['IoT devices with self-signed certificates', 'Development environments accessing internal APIs', 'VPN connections to non-standard ports'],
  tuning: 'Maintain a JA3 hash database of known C2 frameworks. Combine with threat intelligence for destination IP/domain reputation scoring.',
  commonErrors: ['Without TLS inspection, certificate details are limited', 'CDN/cloud fronting can mask C2 destinations behind legitimate domains'],
  responseActions: ['Analyze the TLS certificate details and JA3 hash', 'Check destination IP reputation', 'Perform network forensics on the encrypted session', 'Block the destination IP/domain', 'Investigate the process making the connection'],
  threatIntel: { cves: [], cisaKev: false, campaigns: ['Midnight Blizzard'], iocs: [] },
  references: ['https://attack.mitre.org/techniques/T1573/002/']
},
{
  id: 'SR-0064', title: 'Domain Fronting or CDN-based C2',
  status: 'test', severity: 'high', author: 'SOC Platform', date: '2024-10-01', modified: '2024-12-15',
  category: 'network-anomalies',
  description: 'Detects potential domain fronting where the SNI (Server Name Indication) in TLS differs from the HTTP Host header, or suspicious patterns in CDN-proxied traffic indicating C2 communication.',
  tacticId: 'TA0011', tacticName: 'Command and Control',
  techniqueId: 'T1090.002', techniqueName: 'External Proxy',
  logsource: { product: 'windows', category: 'proxy' },
  sigmaYaml: `title: Domain Fronting or CDN-based C2
id: 22334455-6677-8899-aabb-ccddeeff0004
status: test
description: Detects domain fronting indicators in proxy logs
author: SOC Platform
date: 2024/10/01
logsource:
    category: proxy
    product: windows
detection:
    selection_cdn:
        c-uri|contains:
            - '.cloudfront.net'
            - '.azureedge.net'
            - '.fastly.net'
    selection_beaconing:
        # Regular interval connections suggesting beaconing
        cs-method: 'GET'
    selection_large_post:
        cs-method: 'POST'
        sc-bytes|gt: 10000
    condition: (selection_cdn and selection_beaconing) or (selection_cdn and selection_large_post)
falsepositives:
    - Legitimate applications using CDN services
level: high
tags:
    - attack.command_and_control
    - attack.t1090.002`,
  detectionExplanation: 'Domain fronting uses a trusted CDN domain in the TLS SNI while sending the actual C2 domain in the HTTP Host header. This makes C2 traffic appear as legitimate CDN communication. Detection focuses on: mismatched SNI and Host headers, regular beacon-like intervals to CDN endpoints, and large POST requests to CDN that may indicate data exfiltration through the covert channel.',
  requiredLogs: ['Web proxy logs with full headers', 'TLS inspection metadata'],
  logConfig: 'Enable full request/response header logging in the web proxy. TLS inspection is ideal for detecting SNI/Host mismatches.',
  falsePositives: ['Legitimate web applications hosted on CDN infrastructure', 'Content delivery normal traffic patterns'],
  tuning: 'Focus on periodic/beaconing patterns to CDN endpoints. Analyze request intervals for regularity (jittered but consistent). Compare against known CDN-hosted applications.',
  commonErrors: ['Without TLS inspection, SNI/Host mismatch cannot be detected', 'Many legitimate services use CDNs making volume-based detection noisy'],
  responseActions: ['Inspect the actual HTTP Host header behind the CDN domain', 'Check for beacon-like timing patterns', 'SSL decrypt and inspect the traffic content', 'Block specific CDN URLs used for C2'],
  threatIntel: { cves: [], cisaKev: false, campaigns: ['Midnight Blizzard', 'Volt Typhoon'], iocs: [] },
  references: ['https://attack.mitre.org/techniques/T1090/002/']
},

// ═══════════════════════════════════════════════════════════════
// ADDITIONAL COLLECTION (TA0009)
// ═══════════════════════════════════════════════════════════════
{
  id: 'SR-0065', title: 'Email Collection via PowerShell or Command Line',
  status: 'stable', severity: 'high', author: 'SOC Platform', date: '2024-08-25', modified: '2024-12-01',
  category: 'email-threats',
  description: 'Detects attempts to access local email stores (PST/OST files) or use PowerShell Exchange cmdlets to export mailbox data for collection and potential exfiltration.',
  tacticId: 'TA0009', tacticName: 'Collection',
  techniqueId: 'T1114.001', techniqueName: 'Local Email Collection',
  logsource: { product: 'windows', category: 'process_creation' },
  sigmaYaml: `title: Email Collection via PowerShell or Command Line
id: 33445566-7788-99aa-bbcc-ddeeff001105
status: stable
description: Detects local email store access and export
author: SOC Platform
date: 2024/08/25
logsource:
    category: process_creation
    product: windows
detection:
    selection_pst:
        CommandLine|contains:
            - '.pst'
            - '.ost'
            - 'Outlook\\\\*.pst'
    selection_exchange:
        CommandLine|contains:
            - 'New-MailboxExportRequest'
            - 'Search-Mailbox'
            - 'Get-MailboxExport'
    selection_copy_pst:
        Image|endswith:
            - '\\\\robocopy.exe'
            - '\\\\xcopy.exe'
            - '\\\\copy.exe'
        CommandLine|contains: '.pst'
    condition: selection_pst or selection_exchange or selection_copy_pst
falsepositives:
    - Email migration projects
    - eDiscovery operations
    - IT backing up user mailboxes
level: high
tags:
    - attack.collection
    - attack.t1114.001`,
  detectionExplanation: 'Attackers target email for its high intelligence value. This rule detects: (1) Commands referencing PST/OST files indicating email data access, (2) Exchange PowerShell cmdlets used to export mailboxes, (3) File copy commands targeting PST files. Legitimate email operations should be rare and tied to specific IT workflows.',
  requiredLogs: ['Sysmon Event ID 1', 'Exchange Admin Audit Log'],
  logConfig: 'Command line auditing. Enable Exchange admin audit logging for mailbox export operations.',
  falsePositives: ['Planned email migration projects', 'Legal hold/eDiscovery operations', 'IT archiving old mailboxes'],
  tuning: 'Correlate with IT change management for email migration projects. Alert on any New-MailboxExportRequest from non-Exchange admin accounts.',
  commonErrors: ['PST files may be in various locations', 'Exchange online vs on-premises cmdlets differ'],
  responseActions: ['Determine who initiated the mailbox export', 'Check if this is part of an authorized operation', 'Review which mailboxes were targeted', 'Investigate for data exfiltration of collected email data'],
  threatIntel: { cves: [], cisaKev: false, campaigns: ['Midnight Blizzard'], iocs: [] },
  references: ['https://attack.mitre.org/techniques/T1114/001/']
},
{
  id: 'SR-0066', title: 'Network Shared Drive Data Staging',
  status: 'stable', severity: 'medium', author: 'SOC Platform', date: '2024-09-10', modified: '2024-12-10',
  category: 'data-exfiltration',
  description: 'Detects bulk file access or copy operations from network shared drives, indicating potential collection of sensitive data from file shares prior to exfiltration.',
  tacticId: 'TA0009', tacticName: 'Collection',
  techniqueId: 'T1039', techniqueName: 'Data from Network Shared Drive',
  logsource: { product: 'windows', category: 'process_creation' },
  sigmaYaml: `title: Network Shared Drive Data Staging
id: 44556677-8899-aabb-ccdd-eeff00112206
status: stable
description: Detects bulk data collection from network shares
author: SOC Platform
date: 2024/09/10
logsource:
    category: process_creation
    product: windows
detection:
    selection_robocopy:
        Image|endswith: '\\\\robocopy.exe'
        CommandLine|contains: '\\\\\\\\'
    selection_xcopy:
        Image|endswith: '\\\\xcopy.exe'
        CommandLine|contains: '\\\\\\\\'
    selection_ps_copy:
        CommandLine|contains:
            - 'Copy-Item.*\\\\\\\\\\\\\\\\'
            - 'Get-ChildItem.*\\\\\\\\\\\\\\\\'
    selection_filters:
        CommandLine|contains:
            - '.docx'
            - '.xlsx'
            - '.pdf'
            - '.pptx'
            - '*.doc*'
            - '*.xls*'
            - '/S '
            - '-Recurse'
    condition: (selection_robocopy or selection_xcopy or selection_ps_copy) and selection_filters
falsepositives:
    - IT file migration operations
    - Backup scripts copying from network shares
level: medium
tags:
    - attack.collection
    - attack.t1039`,
  detectionExplanation: 'Attackers collect sensitive data from network shares by copying large volumes of documents (Office files, PDFs) to local staging directories. Robocopy and xcopy with recursive flags targeting document types from UNC paths indicate systematic data collection. The combination of network path, recursive copy, and document type filters distinguishes this from normal file operations.',
  requiredLogs: ['Sysmon Event ID 1', 'File share access logs (Event 5145)'],
  logConfig: 'Process creation with command line. File share auditing for additional visibility.',
  falsePositives: ['Planned file server migrations', 'Backup scripts', 'Users legitimately copying work files from shares'],
  tuning: 'Set thresholds for file volume. Alert on copies to unusual local directories (Temp, ProgramData). Correlate with user role - non-IT users copying large volumes from shares is suspicious.',
  commonErrors: ['Legitimate file operations can look similar', 'Volume threshold needed to reduce false positives'],
  responseActions: ['Identify what files were collected and from which shares', 'Determine the staging location for copied files', 'Check for subsequent archive creation or exfiltration', 'Verify with the user if the activity was business-justified'],
  threatIntel: { cves: [], cisaKev: false, campaigns: [], iocs: [] },
  references: ['https://attack.mitre.org/techniques/T1039/']
},

// ═══════════════════════════════════════════════════════════════
// ADDITIONAL INITIAL ACCESS / EXECUTION
// ═══════════════════════════════════════════════════════════════
{
  id: 'SR-0067', title: 'Service Execution via PsExec',
  status: 'stable', severity: 'high', author: 'SOC Platform', date: '2024-03-15', modified: '2024-12-01',
  category: 'lateral-movement',
  description: 'Detects PsExec-style remote service execution by monitoring for the PSEXESVC service installation, named pipe creation, or direct PsExec binary execution commonly used for remote command execution.',
  tacticId: 'TA0002', tacticName: 'Execution',
  techniqueId: 'T1569.002', techniqueName: 'Service Execution',
  logsource: { product: 'windows', category: 'process_creation' },
  sigmaYaml: `title: Service Execution via PsExec
id: 55667788-99aa-bbcc-ddee-ff001122337
status: stable
description: Detects PsExec and PsExec-like remote execution
author: SOC Platform
date: 2024/03/15
logsource:
    category: process_creation
    product: windows
detection:
    selection_psexec:
        Image|endswith:
            - '\\\\PsExec.exe'
            - '\\\\PsExec64.exe'
    selection_service:
        ParentImage|endswith: '\\\\PSEXESVC.exe'
    selection_pipe:
        CommandLine|contains:
            - '\\\\\\\\*\\\\pipe\\\\psexec'
            - '\\\\\\\\*\\\\pipe\\\\remcom'
            - '\\\\\\\\*\\\\pipe\\\\csexec'
    selection_service_install:
        Image|endswith: '\\\\sc.exe'
        CommandLine|contains: 'PSEXESVC'
    condition: selection_psexec or selection_service or selection_pipe or selection_service_install
falsepositives:
    - IT administrators using PsExec for legitimate remote management
    - SCCM remote execution
level: high
tags:
    - attack.execution
    - attack.t1569.002`,
  detectionExplanation: 'PsExec is a Sysinternals tool that creates a service (PSEXESVC) on the remote target and executes commands through a named pipe. While legitimate for IT administration, it is heavily abused by attackers for lateral execution. Detection covers: PsExec binary execution, PSEXESVC as parent (target-side), named pipe patterns, and service installation events.',
  requiredLogs: ['Sysmon Event ID 1', 'System Event ID 7045', 'Sysmon Event ID 17/18 (Pipe events)'],
  logConfig: 'Process creation, service installation, and named pipe monitoring.',
  falsePositives: ['IT administrators performing remote management', 'Deployment automation using PsExec', 'Some enterprise tools that use PsExec internally'],
  tuning: 'Allowlist specific admin workstations authorized to use PsExec. Alert on PsExec execution from non-admin systems. Monitor for renamed PsExec variants by detecting PSEXESVC service.',
  commonErrors: ['PsExec may be renamed but PSEXESVC service name remains', 'Alternative tools (CSExec, RemCom) use different service names'],
  responseActions: ['Verify the PsExec usage was authorized', 'Check what commands were executed remotely', 'Review source and destination systems', 'If unauthorized: investigate as lateral movement'],
  threatIntel: { cves: [], cisaKev: false, campaigns: ['LockBit 3.0', 'ALPHV/BlackCat Ransomware', 'Volt Typhoon'], iocs: [] },
  references: ['https://attack.mitre.org/techniques/T1569/002/']
},
{
  id: 'SR-0068', title: 'Hidden File and Directory Creation',
  status: 'stable', severity: 'medium', author: 'SOC Platform', date: '2024-10-15', modified: '2024-12-10',
  category: 'defense-evasion',
  description: 'Detects creation of hidden files or directories using attrib +h command or PowerShell, a technique used to conceal malware, tools, or staging directories from casual observation.',
  tacticId: 'TA0005', tacticName: 'Defense Evasion',
  techniqueId: 'T1564.001', techniqueName: 'Hidden Files and Directories',
  logsource: { product: 'windows', category: 'process_creation' },
  sigmaYaml: `title: Hidden File and Directory Creation
id: 66778899-aabb-ccdd-eeff-001122334408
status: stable
description: Detects hiding files and directories with attrib or PowerShell
author: SOC Platform
date: 2024/10/15
logsource:
    category: process_creation
    product: windows
detection:
    selection_attrib:
        Image|endswith: '\\\\attrib.exe'
        CommandLine|contains:
            - '+h'
            - '+s +h'
    selection_ps:
        CommandLine|contains:
            - 'Hidden'
            - 'Attributes.*Hidden'
            - 'Set-ItemProperty.*Hidden'
    filter_system:
        CommandLine|contains:
            - '\\\\Windows\\\\'
            - '\\\\Program Files\\\\'
    condition: (selection_attrib or selection_ps) and not filter_system
falsepositives:
    - Software installers hiding support files
    - Legitimate system administration
level: medium
tags:
    - attack.defense_evasion
    - attack.t1564.001`,
  detectionExplanation: 'Attackers hide malware and staging directories from users by setting the hidden attribute using attrib +h or PowerShell. While Windows hides files by default during installation, manual hiding of files in user-accessible directories is suspicious. The +s +h combination (system and hidden) is particularly suspicious as it makes files invisible even when "Show hidden files" is enabled.',
  requiredLogs: ['Sysmon Event ID 1'],
  logConfig: 'Standard process creation logging.',
  falsePositives: ['Software installers hiding configuration files', 'System utilities managing hidden system files'],
  tuning: 'Filter out operations in Windows and Program Files directories. Focus on hidden file creation in user directories, temp folders, and ProgramData.',
  commonErrors: ['Many legitimate installers hide files', 'Filtering system paths is essential to reduce noise'],
  responseActions: ['Identify what file or directory was hidden', 'Examine the hidden content', 'Check what process created the hidden file', 'Investigate the timeline of file creation and hiding'],
  threatIntel: { cves: [], cisaKev: false, campaigns: [], iocs: [] },
  references: ['https://attack.mitre.org/techniques/T1564/001/']
},
{
  id: 'SR-0069', title: 'Credential File Discovery and Access',
  status: 'stable', severity: 'medium', author: 'SOC Platform', date: '2024-11-01', modified: '2024-12-15',
  category: 'credential-access',
  description: 'Detects searches for credential files such as configuration files, private keys, password databases, and credential stores that may contain stored credentials in plaintext or weakly encrypted form.',
  tacticId: 'TA0006', tacticName: 'Credential Access',
  techniqueId: 'T1552.001', techniqueName: 'Credentials In Files',
  logsource: { product: 'windows', category: 'process_creation' },
  sigmaYaml: `title: Credential File Discovery and Access
id: 7788aabb-ccdd-eeff-0011-223344556609
status: stable
description: Detects searches for credential-containing files
author: SOC Platform
date: 2024/11/01
logsource:
    category: process_creation
    product: windows
detection:
    selection_search:
        Image|endswith:
            - '\\\\findstr.exe'
            - '\\\\find.exe'
            - '\\\\dir.exe'
        CommandLine|contains:
            - 'password'
            - 'passwd'
            - 'credential'
            - 'secret'
            - '.kdbx'
            - '.key'
            - 'id_rsa'
            - '.pem'
            - '.pfx'
            - 'web.config'
            - 'unattend.xml'
    selection_ps_search:
        CommandLine|contains:
            - 'Get-ChildItem.*password'
            - 'Select-String.*password'
            - 'findstr /si password'
    condition: selection_search or selection_ps_search
falsepositives:
    - Security auditing tools searching for exposed credentials
    - IT administering password databases
level: medium
tags:
    - attack.credential_access
    - attack.t1552.001`,
  detectionExplanation: 'Attackers commonly search file systems for files containing credentials: configuration files (web.config, unattend.xml), password databases (KeePass .kdbx), SSH keys (id_rsa), certificates (.pfx, .pem), and files containing keywords like "password" or "secret". The findstr /si password command recursively searches for the word "password" in files and is a classic post-exploitation technique.',
  requiredLogs: ['Sysmon Event ID 1'],
  logConfig: 'Command line auditing.',
  falsePositives: ['Security compliance scanning for exposed credentials', 'Administrators searching for password files during audits', 'Development tools searching configuration files'],
  tuning: 'Alert on non-IT users performing credential searches. Correlate with other discovery activities. Focus on searches targeting system directories rather than user document searches.',
  commonErrors: ['Very common in legitimate security auditing', 'Grep-like tools in development environments'],
  responseActions: ['Determine what the user was searching for and why', 'Check if any credential files were found and accessed', 'Review if discovered credentials were used for further access', 'Rotate any credentials that may have been exposed'],
  threatIntel: { cves: [], cisaKev: false, campaigns: ['Volt Typhoon', 'Scattered Spider'], iocs: [] },
  references: ['https://attack.mitre.org/techniques/T1552/001/']
},
{
  id: 'SR-0070', title: 'Data Encoding for Exfiltration',
  status: 'stable', severity: 'medium', author: 'SOC Platform', date: '2024-09-20', modified: '2024-12-10',
  category: 'data-exfiltration',
  description: 'Detects data encoding operations using certutil, base64 commands, or PowerShell encoding often used to prepare data for exfiltration through channels that only support text-based data.',
  tacticId: 'TA0011', tacticName: 'Command and Control',
  techniqueId: 'T1132.001', techniqueName: 'Standard Encoding',
  logsource: { product: 'windows', category: 'process_creation' },
  sigmaYaml: `title: Data Encoding for Exfiltration
id: 8899aabb-ccdd-eeff-0011-22334455660a
status: stable
description: Detects Base64 and other encoding used for data preparation
author: SOC Platform
date: 2024/09/20
logsource:
    category: process_creation
    product: windows
detection:
    selection_certutil:
        Image|endswith: '\\\\certutil.exe'
        CommandLine|contains:
            - '-encode'
            - '-encodehex'
    selection_ps:
        CommandLine|contains:
            - '[Convert]::ToBase64String'
            - '[System.Convert]::ToBase64String'
            - 'ConvertTo-Base64'
    selection_cmd:
        CommandLine|contains:
            - 'base64'
            - 'certutil -encode'
    condition: selection_certutil or selection_ps or selection_cmd
falsepositives:
    - Developers encoding data for legitimate purposes
    - Certificate management operations
level: medium
tags:
    - attack.command_and_control
    - attack.t1132.001`,
  detectionExplanation: 'Before exfiltrating data through text-based channels (DNS, HTTP parameters, email), attackers encode binary data using Base64. CertUtil with -encode flag is a common LOLBin for this purpose. PowerShell ToBase64String is used programmatically. The encoded data can then be sent through channels that only support ASCII text without corruption.',
  requiredLogs: ['Sysmon Event ID 1'],
  logConfig: 'Standard command line logging.',
  falsePositives: ['Developers encoding/decoding data', 'Certificate management using certutil', 'Scripting with Base64 for legitimate data handling'],
  tuning: 'Correlate encoding activities with preceding collection activities and subsequent network connections. Encoding of large files is more suspicious than small configurations.',
  commonErrors: ['Base64 encoding is common in legitimate scripts', 'Without correlating with other indicators, this generates many false positives'],
  responseActions: ['Identify what data was encoded', 'Check for subsequent exfiltration attempts', 'Analyze the files that were encoded', 'Correlate with other C2 or exfiltration indicators'],
  threatIntel: { cves: [], cisaKev: false, campaigns: [], iocs: [] },
  references: ['https://attack.mitre.org/techniques/T1132/001/']
}
];

// Combined in sigma-rules-part4.js

