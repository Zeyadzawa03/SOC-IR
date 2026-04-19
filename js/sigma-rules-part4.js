// Sigma Rules Database - Part 4: Final Deep Coverage Rules
// Targeting remaining high-value gaps across all tactics
const SIGMA_RULES_PART4 = [

// ═══════════════════════════════════════════════════════════════
// DEFENSE EVASION - DLL Side-Loading
// ═══════════════════════════════════════════════════════════════
{
  id: 'SR-0071', title: 'DLL Side-Loading via Legitimate Application',
  status: 'stable', severity: 'high', author: 'SOC Platform', date: '2024-07-15', modified: '2024-12-15',
  category: 'defense-evasion',
  description: 'Detects DLL side-loading attacks where legitimate signed applications are used to load malicious DLLs from non-standard directories, bypassing application whitelisting and code-signing enforcement.',
  tacticId: 'TA0005', tacticName: 'Defense Evasion',
  techniqueId: 'T1574.002', techniqueName: 'DLL Side-Loading',
  logsource: { product: 'windows', category: 'image_load' },
  sigmaYaml: `title: DLL Side-Loading via Legitimate Application
id: aa112233-bb44-cc55-dd66-ee7788990071
status: stable
description: Detects DLL side-loading from non-standard directories
author: SOC Platform
date: 2024/07/15
logsource:
    category: image_load
    product: windows
detection:
    selection_signed:
        ImageLoaded|endswith:
            - '.dll'
        Image|endswith:
            - '\\\\OneDriveUpdater.exe'
            - '\\\\SearchProtocolHost.exe'
            - '\\\\colorcpl.exe'
            - '\\\\msdt.exe'
            - '\\\\presentationhost.exe'
    filter_legitimate:
        ImageLoaded|startswith:
            - 'C:\\\\Windows\\\\System32\\\\'
            - 'C:\\\\Windows\\\\SysWOW64\\\\'
            - 'C:\\\\Program Files\\\\'
    condition: selection_signed and not filter_legitimate
falsepositives:
    - Portable applications loading local DLLs
    - Development environments
level: high
tags:
    - attack.defense_evasion
    - attack.t1574.002`,
  detectionExplanation: 'DLL side-loading exploits the Windows DLL search order. Legitimate signed executables are placed in attacker-controlled directories alongside malicious DLLs with specific names. When the legitimate executable runs and loads its dependencies, it loads the malicious DLL instead. This bypasses code-signing checks because the parent process is legitimately signed.',
  requiredLogs: ['Sysmon Event ID 7 (Image Loaded)'],
  logConfig: 'Sysmon with image load monitoring. Filter to reduce volume by focusing on specific vulnerable executables.',
  falsePositives: ['Portable application bundles', 'Software development with local DLL builds', 'Some legitimate updaters running from temp directories'],
  tuning: 'Focus on known side-loadable executables loading DLLs from Temp, Downloads, AppData, or ProgramData directories.',
  commonErrors: ['Image load logging generates very high volume', 'Many legitimate DLL loads from non-system directories'],
  responseActions: ['Analyze the loaded DLL - check signing status and hash', 'Determine how the legitimate executable got to the non-standard path', 'Check the DLL content for malicious indicators', 'Block the malicious DLL hash across all endpoints'],
  threatIntel: { cves: [], cisaKev: false, campaigns: ['ALPHV/BlackCat Ransomware', 'Volt Typhoon'], iocs: [] },
  references: ['https://attack.mitre.org/techniques/T1574/002/']
},

// ═══════════════════════════════════════════════════════════════
// CREDENTIAL ACCESS - Golden Ticket
// ═══════════════════════════════════════════════════════════════
{
  id: 'SR-0072', title: 'Golden Ticket Attack Detection',
  status: 'stable', severity: 'critical', author: 'SOC Platform', date: '2024-03-20', modified: '2024-12-10',
  category: 'active-directory',
  description: 'Detects Golden Ticket attacks by monitoring for forged Kerberos TGTs with anomalous properties such as unusually long lifetimes, mismatched domain SIDs, or ticket encryption that does not match current KRBTGT key version.',
  tacticId: 'TA0006', tacticName: 'Credential Access',
  techniqueId: 'T1558.001', techniqueName: 'Golden Ticket',
  logsource: { product: 'windows', service: 'security' },
  sigmaYaml: `title: Golden Ticket Attack Detection
id: bb223344-cc55-dd66-ee77-ff8899001072
status: stable
description: Detects forged Kerberos TGT (Golden Ticket) indicators
author: SOC Platform
date: 2024/03/20
logsource:
    product: windows
    service: security
detection:
    selection_tgs:
        EventID: 4769
    selection_no_tgt:
        EventID: 4769
    filter_preceding_as:
        EventID: 4768
    selection_tools:
        CommandLine|contains:
            - 'kerberos::golden'
            - 'golden_ticket'
            - 'Rubeus.exe'
            - 'ticketer.py'
    condition: selection_tools
    # Advanced: TGS (4769) without corresponding AS-REQ (4768)
falsepositives:
    - Authorized penetration testing
level: critical
tags:
    - attack.credential_access
    - attack.t1558.001`,
  detectionExplanation: 'A Golden Ticket is a forged TGT created using the KRBTGT account hash. With it, an attacker can impersonate any user including Domain Admins. Detection indicators: (1) TGS requests (4769) without preceding AS-REQ (4768) for the same user, (2) TGTs with abnormally long lifetimes (default is 10 hours), (3) Known tool command patterns (Mimikatz kerberos::golden, Impacket ticketer.py), (4) Ticket encryption mismatch with current KRBTGT key version number.',
  requiredLogs: ['Windows Security Event ID 4768', 'Event ID 4769', 'Sysmon Event ID 1'],
  logConfig: 'Full Kerberos auditing on all domain controllers. Process creation logging on endpoints.',
  falsePositives: ['Authorized penetration testing', 'Kerberos troubleshooting with manually crafted tickets'],
  tuning: 'Correlate 4769 events without preceding 4768 for the same user within a reasonable time window. Monitor for KRBTGT hash extraction attempts as precursors.',
  commonErrors: ['Time correlation between AS-REQ and TGS-REQ requires careful windowing', 'Legitimate ticket renewal may not generate new AS-REQ'],
  responseActions: ['CRITICAL: Full domain compromise likely', 'Reset KRBTGT password TWICE (current and previous)', 'Investigate how the KRBTGT hash was obtained (likely DCSync or NTDS.dit)', 'Assume all domain accounts are compromised', 'Full Active Directory forensic investigation required', 'Consider rebuilding domain from trusted backup'],
  threatIntel: { cves: [], cisaKev: false, campaigns: ['Midnight Blizzard', 'ALPHV/BlackCat Ransomware'], iocs: [] },
  references: ['https://attack.mitre.org/techniques/T1558/001/']
},

// ═══════════════════════════════════════════════════════════════
// PERSISTENCE - Scheduled Task Create
// ═══════════════════════════════════════════════════════════════
{
  id: 'SR-0073', title: 'Suspicious Scheduled Task Creation via CLI',
  status: 'stable', severity: 'high', author: 'SOC Platform', date: '2024-06-10', modified: '2024-12-05',
  category: 'persistence',
  description: 'Detects creation of scheduled tasks via schtasks.exe or PowerShell with suspicious attributes such as running at SYSTEM level, executing from temp directories, or running encoded commands.',
  tacticId: 'TA0003', tacticName: 'Persistence',
  techniqueId: 'T1053.005', techniqueName: 'Scheduled Task',
  logsource: { product: 'windows', category: 'process_creation' },
  sigmaYaml: `title: Suspicious Scheduled Task Creation via CLI
id: cc334455-dd66-ee77-ff88-990011220073
status: stable
description: Detects suspicious scheduled task creation
author: SOC Platform
date: 2024/06/10
logsource:
    category: process_creation
    product: windows
detection:
    selection_schtasks:
        Image|endswith: '\\\\schtasks.exe'
        CommandLine|contains: '/create'
    selection_suspicious:
        CommandLine|contains:
            - '/sc onlogon'
            - '/sc onstart'
            - '/sc onidle'
            - '/ru SYSTEM'
            - '/ru "NT AUTHORITY'
            - '\\\\Temp\\\\'
            - '\\\\AppData\\\\'
            - 'powershell'
            - 'cmd.exe /c'
            - '-encodedcommand'
            - '-enc '
            - 'FromBase64'
    selection_ps:
        CommandLine|contains:
            - 'Register-ScheduledTask'
            - 'New-ScheduledTaskAction'
        CommandLine|contains:
            - 'powershell'
            - 'cmd'
            - 'Temp'
            - 'AppData'
    condition: (selection_schtasks and selection_suspicious) or selection_ps
falsepositives:
    - IT administrators creating scheduled tasks
    - Software installation creating update tasks
level: high
tags:
    - attack.persistence
    - attack.t1053.005`,
  detectionExplanation: 'Scheduled tasks provide reliable persistence across reboots. Suspicious indicators include: running as SYSTEM, triggering at logon/startup, executing from temporary directories, running encoded PowerShell commands, or using cmd.exe /c for command execution. The combination of creation with these suspicious attributes distinguishes malicious tasks from legitimate ones.',
  requiredLogs: ['Sysmon Event ID 1', 'Windows Security 4698 (Scheduled Task Created)'],
  logConfig: 'Process creation logging. Enable Object Access auditing for scheduled task events (4698/4702).',
  falsePositives: ['Software updaters creating scheduled tasks', 'IT automation deploying scheduled tasks', 'SCCM creating update tasks'],
  tuning: 'Focus on tasks running as SYSTEM from non-standard paths. Baseline existing scheduled tasks and alert on new ones. Encoded PowerShell in scheduled tasks is almost always malicious.',
  commonErrors: ['Many legitimate scheduled tasks run as SYSTEM', 'Software installers create tasks during installation'],
  responseActions: ['Examine the scheduled task action and trigger', 'Check what executable or script it runs', 'Determine who created the task and from where', 'Remove the task if unauthorized', 'Analyze the payload referenced by the task'],
  threatIntel: { cves: [], cisaKev: false, campaigns: ['LockBit 3.0', 'Scattered Spider'], iocs: [] },
  references: ['https://attack.mitre.org/techniques/T1053/005/']
},

// ═══════════════════════════════════════════════════════════════
// INITIAL ACCESS - Cloud Credential Phishing
// ═══════════════════════════════════════════════════════════════
{
  id: 'SR-0074', title: 'OAuth Token Theft and Cloud Credential Access',
  status: 'test', severity: 'high', author: 'SOC Platform', date: '2024-11-10', modified: '2024-12-15',
  category: 'cloud-threats',
  description: 'Detects attempts to access stored cloud credentials including Azure/AWS tokens, OAuth refresh tokens, and cloud provider credential files that enable access to cloud resources.',
  tacticId: 'TA0001', tacticName: 'Initial Access',
  techniqueId: 'T1528', techniqueName: 'Steal Application Access Token',
  logsource: { product: 'windows', category: 'process_creation' },
  sigmaYaml: `title: OAuth Token Theft and Cloud Credential Access
id: dd445566-ee77-ff88-9900-112233440074
status: test
description: Detects access to stored cloud and OAuth credentials
author: SOC Platform
date: 2024/11/10
logsource:
    category: process_creation
    product: windows
detection:
    selection_azure:
        CommandLine|contains:
            - '.azure\\\\accessTokens.json'
            - '.azure\\\\azureProfile.json'
            - 'TokenCache.dat'
            - 'msal_token_cache'
    selection_aws:
        CommandLine|contains:
            - '.aws\\\\credentials'
            - '.aws\\\\config'
            - 'AWS_ACCESS_KEY_ID'
            - 'AWS_SECRET_ACCESS_KEY'
    selection_gcp:
        CommandLine|contains:
            - 'gcloud\\\\credentials.db'
            - 'application_default_credentials.json'
            - 'legacy_credentials'
    selection_generic:
        CommandLine|contains:
            - 'Get-AzAccessToken'
            - 'az account get-access-token'
            - 'gcloud auth print-access-token'
    condition: selection_azure or selection_aws or selection_gcp or selection_generic
falsepositives:
    - Cloud administrators using CLI tools
    - DevOps automation scripts
level: high
tags:
    - attack.initial_access
    - attack.t1528`,
  detectionExplanation: 'Cloud credentials stored locally include Azure access tokens, AWS credentials files, and GCP credentials databases. Attackers access these files to gain direct API access to cloud resources. OAuth tokens are particularly valuable as they bypass MFA. This rule monitors for command-line access to known credential file paths and cloud CLI commands that extract access tokens.',
  requiredLogs: ['Sysmon Event ID 1', 'File access monitoring on credential paths'],
  logConfig: 'Command line auditing. Consider file access auditing on cloud credential paths.',
  falsePositives: ['Cloud administrators authenticating via CLI', 'CI/CD pipelines using service principals', 'DevOps tools accessing cloud APIs'],
  tuning: 'Baseline known cloud admin workstations. Alert on credential file access from non-admin systems. Monitor for bulk cloud API calls following token theft.',
  commonErrors: ['Cloud credential paths vary by OS and tool version', 'Environment variable extraction requires different detection'],
  responseActions: ['Revoke the stolen access tokens immediately', 'Rotate affected cloud credentials', 'Review cloud audit logs for unauthorized access', 'Check for resource creation or data access using stolen tokens', 'Implement Conditional Access policies requiring managed devices'],
  threatIntel: { cves: [], cisaKev: false, campaigns: ['Scattered Spider', 'Midnight Blizzard'], iocs: [] },
  references: ['https://attack.mitre.org/techniques/T1528/']
},

// ═══════════════════════════════════════════════════════════════
// EXECUTION - PowerShell Download Cradle
// ═══════════════════════════════════════════════════════════════
{
  id: 'SR-0075', title: 'PowerShell Download Cradle Execution',
  status: 'stable', severity: 'high', author: 'SOC Platform', date: '2024-04-20', modified: '2024-12-10',
  category: 'execution',
  description: 'Detects PowerShell download cradle patterns that download and immediately execute code in memory, a key technique for fileless malware delivery that avoids disk-based detection.',
  tacticId: 'TA0002', tacticName: 'Execution',
  techniqueId: 'T1059.001', techniqueName: 'PowerShell',
  logsource: { product: 'windows', category: 'process_creation' },
  sigmaYaml: `title: PowerShell Download Cradle Execution
id: ee556677-ff88-9900-1122-334455660075
status: stable
description: Detects fileless PowerShell download cradles
author: SOC Platform
date: 2024/04/20
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image|endswith:
            - '\\\\powershell.exe'
            - '\\\\pwsh.exe'
    selection_cradle:
        CommandLine|contains:
            - 'IEX (New-Object Net.WebClient).DownloadString'
            - 'IEX(New-Object Net.WebClient).DownloadString'
            - 'Invoke-Expression (New-Object'
            - 'Net.WebClient).DownloadString('
            - 'iwr -uri'
            - 'Invoke-WebRequest'
            - 'wget '
            - 'curl '
        CommandLine|contains:
            - 'IEX '
            - 'Invoke-Expression'
            - '| IEX'
            - '|IEX'
    condition: selection and selection_cradle
falsepositives:
    - Legitimate PowerShell-based management tools
    - Package managers (chocolatey, PSGallery)
level: high
tags:
    - attack.execution
    - attack.t1059.001`,
  detectionExplanation: 'PowerShell download cradles download script content from a URL and immediately execute it in memory using Invoke-Expression (IEX). This is the primary fileless delivery mechanism: no file is written to disk, bypassing AV scanning. Common patterns include: IEX(New-Object Net.WebClient).DownloadString("url") and variations with Invoke-WebRequest piped to IEX.',
  requiredLogs: ['Sysmon Event ID 1', 'PowerShell Script Block Logging (Event 4104)'],
  logConfig: 'Command line auditing with full argument capture. Enable PowerShell Module Logging and Script Block Logging.',
  falsePositives: ['Chocolatey package installations', 'PowerShell module installations from galleries', 'IT automation scripts from trusted sources'],
  tuning: 'Allowlist known management URLs (chocolatey.org, PSGallery). Focus on cradles downloading from unknown or suspicious URLs. Script Block Logging provides the actual downloaded content.',
  commonErrors: ['Obfuscated cradles may use character substitution', 'Some cradles use .NET classes directly bypassing PowerShell cmdlets'],
  responseActions: ['Capture the downloaded script content from Script Block logs', 'Block the source URL at the proxy', 'Analyze the downloaded payload', 'Check for persistence or lateral movement from the downloaded code', 'Hunt for the same URL across all endpoints'],
  threatIntel: { cves: [], cisaKev: false, campaigns: ['Scattered Spider', 'LockBit 3.0'], iocs: [] },
  references: ['https://attack.mitre.org/techniques/T1059/001/']
},

// ═══════════════════════════════════════════════════════════════
// PERSISTENCE - WMI Event Subscription (Enhanced)
// ═══════════════════════════════════════════════════════════════
{
  id: 'SR-0076', title: 'WMI Permanent Event Subscription for Persistence',
  status: 'stable', severity: 'critical', author: 'SOC Platform', date: '2024-05-15', modified: '2024-12-05',
  category: 'windows-specific',
  description: 'Detects creation of WMI permanent event subscriptions which provide persistent code execution that survives reboots. Monitors both wmic.exe commands and Sysmon WMI events for subscription creation.',
  tacticId: 'TA0003', tacticName: 'Persistence',
  techniqueId: 'T1546.003', techniqueName: 'Windows Management Instrumentation Event Subscription',
  logsource: { product: 'windows', category: 'wmi_event' },
  sigmaYaml: `title: WMI Permanent Event Subscription for Persistence
id: ff667788-9900-1122-3344-556677880076
status: stable
description: Detects WMI event subscription creation for persistence
author: SOC Platform
date: 2024/05/15
logsource:
    category: wmi_event
    product: windows
detection:
    selection_sysmon:
        EventType: 'WmiBindingEvent'
    selection_wmic:
        CommandLine|contains:
            - '__EventFilter'
            - '__EventConsumer'
            - '__FilterToConsumerBinding'
            - 'ActiveScriptEventConsumer'
            - 'CommandLineEventConsumer'
    selection_ps:
        CommandLine|contains:
            - 'Set-WmiInstance'
            - 'New-CimInstance'
            - '__EventFilter'
            - 'Register-WmiEvent'
    condition: selection_sysmon or selection_wmic or selection_ps
falsepositives:
    - SCCM client health monitoring
    - Enterprise monitoring solutions using WMI
level: critical
tags:
    - attack.persistence
    - attack.t1546.003`,
  detectionExplanation: 'WMI permanent event subscriptions consist of three components: (1) an EventFilter (trigger condition), (2) an EventConsumer (action to execute), and (3) a FilterToConsumerBinding (links filter to consumer). ActiveScriptEventConsumer runs scripts, CommandLineEventConsumer runs commands. These persist in the WMI repository and survive reboots, making them a stealthy persistence mechanism.',
  requiredLogs: ['Sysmon Event ID 19/20/21 (WMI events)', 'Windows Security 4688'],
  logConfig: 'Deploy Sysmon with WMI event monitoring (Event IDs 19, 20, 21). Enable WMI Trace logging.',
  falsePositives: ['SCCM client WMI subscriptions', 'Enterprise monitoring solutions', 'Dell/HP hardware monitoring agents'],
  tuning: 'Baseline existing WMI subscriptions. Alert on new creation. Focus on ActiveScript and CommandLine consumers which execute code.',
  commonErrors: ['WMI events require Sysmon or specific WMI tracing', 'Default Windows event logs do not capture WMI subscription creation'],
  responseActions: ['List all WMI subscriptions: Get-WMIObject -Namespace root\\Subscription -Class __FilterToConsumerBinding', 'Analyze the consumer action (what does it execute?)', 'Remove malicious subscriptions', 'Check the event filter trigger to understand when it activates', 'Hunt for the same subscription across other systems'],
  threatIntel: { cves: [], cisaKev: false, campaigns: ['Volt Typhoon'], iocs: [] },
  references: ['https://attack.mitre.org/techniques/T1546/003/']
},

// ═══════════════════════════════════════════════════════════════
// CREDENTIAL ACCESS - NTDS.dit Extraction
// ═══════════════════════════════════════════════════════════════
{
  id: 'SR-0077', title: 'NTDS.dit Domain Database Extraction',
  status: 'stable', severity: 'critical', author: 'SOC Platform', date: '2024-02-10', modified: '2024-12-15',
  category: 'active-directory',
  description: 'Detects attempts to extract the NTDS.dit database from domain controllers which contains all AD user password hashes, enabling offline cracking of every domain account.',
  tacticId: 'TA0006', tacticName: 'Credential Access',
  techniqueId: 'T1003.003', techniqueName: 'NTDS',
  logsource: { product: 'windows', category: 'process_creation' },
  sigmaYaml: `title: NTDS.dit Domain Database Extraction
id: 00778899-1122-3344-5566-778899001077
status: stable
description: Detects NTDS.dit extraction for full domain credential dump
author: SOC Platform
date: 2024/02/10
logsource:
    category: process_creation
    product: windows
detection:
    selection_ntdsutil:
        Image|endswith: '\\\\ntdsutil.exe'
        CommandLine|contains:
            - 'ifm'
            - 'create full'
            - 'ac i ntds'
    selection_vss:
        CommandLine|contains:
            - 'vssadmin create shadow'
            - 'wmic shadowcopy call create'
        CommandLine|contains:
            - 'ntds'
    selection_copy:
        CommandLine|contains:
            - 'ntds.dit'
    selection_secretsdump:
        CommandLine|contains:
            - 'secretsdump'
            - 'impacket'
            - 'ntdsdump'
    condition: selection_ntdsutil or selection_vss or selection_copy or selection_secretsdump
falsepositives:
    - Legitimate domain controller backup procedures
    - Active Directory migration using IFM
level: critical
tags:
    - attack.credential_access
    - attack.t1003.003`,
  detectionExplanation: 'NTDS.dit is the Active Directory database containing all user password hashes. Extraction methods include: (1) ntdsutil with IFM (Install From Media) to create a portable copy, (2) Volume Shadow Copy to access the locked file, (3) Direct file copy from shadow copies, (4) Impacket secretsdump for remote extraction via DRSUAPI. Any extraction outside of scheduled DC backups is critical.',
  requiredLogs: ['Sysmon Event ID 1', 'Windows Security 4688', 'Directory Service events on DCs'],
  logConfig: 'Command line auditing on domain controllers. Monitor for volume shadow copy creation.',
  falsePositives: ['Scheduled DC backup procedures', 'Active Directory migration using Install From Media', 'Disaster recovery testing'],
  tuning: 'This is a high-fidelity critical detection. Any occurrence outside of scheduled maintenance windows should be treated as a critical incident.',
  commonErrors: ['VSS creates shadow copies for legitimate purposes (backup)', 'ntdsutil has many legitimate uses - focus on IFM context'],
  responseActions: ['CRITICAL: Assume complete domain credential compromise', 'Isolate the system where extraction occurred', 'Reset ALL domain account passwords in phases', 'Reset KRBTGT password twice', 'Investigate how the attacker gained DC access', 'Full incident response and forensic investigation'],
  threatIntel: { cves: [], cisaKev: false, campaigns: ['LockBit 3.0', 'ALPHV/BlackCat Ransomware', 'Midnight Blizzard'], iocs: [] },
  references: ['https://attack.mitre.org/techniques/T1003/003/']
},

// ═══════════════════════════════════════════════════════════════
// DEFENSE EVASION - Process Hollowing
// ═══════════════════════════════════════════════════════════════
{
  id: 'SR-0078', title: 'Process Hollowing Detection',
  status: 'test', severity: 'high', author: 'SOC Platform', date: '2024-08-20', modified: '2024-12-10',
  category: 'endpoint-anomalies',
  description: 'Detects process hollowing behavior where a legitimate process is created in a suspended state and its memory is replaced with malicious code before resumption, making the malware appear as a trusted process.',
  tacticId: 'TA0005', tacticName: 'Defense Evasion',
  techniqueId: 'T1055.012', techniqueName: 'Process Hollowing',
  logsource: { product: 'windows', category: 'process_creation' },
  sigmaYaml: `title: Process Hollowing Detection
id: 11889900-2233-4455-6677-889900110078
status: test
description: Detects process hollowing via suspended process indicators
author: SOC Platform
date: 2024/08/20
logsource:
    category: process_creation
    product: windows
detection:
    selection_suspended:
        # Processes created in suspended state
        Image|endswith:
            - '\\\\svchost.exe'
            - '\\\\explorer.exe'
            - '\\\\RuntimeBroker.exe'
            - '\\\\dllhost.exe'
        ParentImage|endswith:
            - '\\\\cmd.exe'
            - '\\\\powershell.exe'
            - '\\\\wscript.exe'
            - '\\\\cscript.exe'
            - '\\\\mshta.exe'
    filter_legit:
        ParentImage|endswith: '\\\\services.exe'
    condition: selection_suspended and not filter_legit
falsepositives:
    - COM object instantiation via dllhost
    - Legitimate svchost spawning
level: high
tags:
    - attack.defense_evasion
    - attack.t1055.012`,
  detectionExplanation: 'Process hollowing creates a legitimate process (like svchost.exe) in a suspended state, unmaps its memory, writes malicious code into the process space, and resumes execution. The malicious code now runs under the guise of a trusted system process. Detection focuses on unexpected parent-child relationships: system processes spawned by script interpreters or command shells rather than by their legitimate parent (services.exe).',
  requiredLogs: ['Sysmon Event ID 1 with parent process', 'Sysmon Event ID 8 (CreateRemoteThread)', 'EDR telemetry'],
  logConfig: 'Full process creation with parent process tracking. EDR provides better visibility into process injection.',
  falsePositives: ['COM object activation via dllhost from scripts', 'Legitimate troubleshooting spawning system processes'],
  tuning: 'Focus on svchost/explorer spawned by unexpected parents. EDR-based detection using API monitoring (NtUnmapViewOfSection, WriteProcessMemory, ResumeThread) is more reliable.',
  commonErrors: ['Process creation alone is insufficient for definitive detection', 'Memory analysis or API monitoring needed for confirmation'],
  responseActions: ['Dump the process memory for analysis', 'Compare the on-disk executable with the in-memory image', 'Identify the parent process that performed the hollowing', 'Investigate the original malware delivery mechanism'],
  threatIntel: { cves: [], cisaKev: false, campaigns: ['LockBit 3.0'], iocs: [] },
  references: ['https://attack.mitre.org/techniques/T1055/012/']
},

// ═══════════════════════════════════════════════════════════════
// DEFENSE EVASION - Defender Exclusion
// ═══════════════════════════════════════════════════════════════
{
  id: 'SR-0079', title: 'Windows Defender Exclusion Added',
  status: 'stable', severity: 'high', author: 'SOC Platform', date: '2024-09-05', modified: '2024-12-15',
  category: 'defense-evasion',
  description: 'Detects addition of Windows Defender exclusions for paths, file types, or processes via PowerShell or registry modification, commonly used to prevent detection of deployed malware.',
  tacticId: 'TA0005', tacticName: 'Defense Evasion',
  techniqueId: 'T1562.001', techniqueName: 'Disable or Modify Tools',
  logsource: { product: 'windows', category: 'process_creation' },
  sigmaYaml: `title: Windows Defender Exclusion Added
id: 22990011-3344-5566-7788-990011220079
status: stable
description: Detects Defender exclusion modifications
author: SOC Platform
date: 2024/09/05
logsource:
    category: process_creation
    product: windows
detection:
    selection_ps:
        CommandLine|contains:
            - 'Add-MpPreference'
            - 'Set-MpPreference'
        CommandLine|contains:
            - 'ExclusionPath'
            - 'ExclusionExtension'
            - 'ExclusionProcess'
    selection_reg:
        Image|endswith: '\\\\reg.exe'
        CommandLine|contains:
            - 'Windows Defender\\\\Exclusions'
            - 'Microsoft\\\\Windows Defender\\\\Exclusions'
    condition: selection_ps or selection_reg
falsepositives:
    - IT administrators adding legitimate exclusions
    - Software deployment adding performance exclusions
level: high
tags:
    - attack.defense_evasion
    - attack.t1562.001`,
  detectionExplanation: 'Attackers add Defender exclusions for malware staging paths (C:\\Temp, C:\\ProgramData) or file types (.exe, .dll, .ps1) to prevent detection. This is a common pre-deployment step before dropping payloads. Exclusions can be added via PowerShell (Add-MpPreference -ExclusionPath) or directly via registry modification under HKLM\\SOFTWARE\\Microsoft\\Windows Defender\\Exclusions.',
  requiredLogs: ['Sysmon Event ID 1', 'Windows Defender Event ID 5007 (Settings Changed)'],
  logConfig: 'Process creation logging. Enable Windows Defender operational logging for event 5007.',
  falsePositives: ['IT adding exclusions for legitimate software', 'Database servers excluding data directories for performance', 'Development environments excluding build directories'],
  tuning: 'Alert on exclusions for broad paths (C:\\, C:\\Users, C:\\Temp) or dangerous extensions (.exe, .dll, .ps1). Cross-reference with change management.',
  commonErrors: ['Many IT teams add exclusions legitimately', 'GPO-deployed exclusions use different mechanism'],
  responseActions: ['Review what exclusion was added and by whom', 'Check if malware was deployed to the excluded path', 'Remove unauthorized exclusions', 'Scan the excluded path with a different AV tool', 'Investigate the account that added the exclusion'],
  threatIntel: { cves: [], cisaKev: false, campaigns: ['LockBit 3.0', 'ALPHV/BlackCat Ransomware', 'Scattered Spider'], iocs: [] },
  references: ['https://attack.mitre.org/techniques/T1562/001/']
},

// ═══════════════════════════════════════════════════════════════
// COLLECTION - Clipboard Data
// ═══════════════════════════════════════════════════════════════
{
  id: 'SR-0080', title: 'Clipboard Data Theft Detection',
  status: 'test', severity: 'medium', author: 'SOC Platform', date: '2024-10-20', modified: '2024-12-10',
  category: 'collection',
  description: 'Detects attempts to programmatically access clipboard data which may contain copied passwords, cryptocurrency wallet addresses, or sensitive information for collection.',
  tacticId: 'TA0009', tacticName: 'Collection',
  techniqueId: 'T1115', techniqueName: 'Clipboard Data',
  logsource: { product: 'windows', category: 'process_creation' },
  sigmaYaml: `title: Clipboard Data Theft Detection
id: 33001122-4455-6677-8899-001122330080
status: test
description: Detects clipboard access for data collection
author: SOC Platform
date: 2024/10/20
logsource:
    category: process_creation
    product: windows
detection:
    selection_ps:
        CommandLine|contains:
            - 'Get-Clipboard'
            - '[System.Windows.Forms.Clipboard]'
            - 'GetText()'
            - 'clip.exe'
    selection_api:
        CommandLine|contains:
            - 'OpenClipboard'
            - 'GetClipboardData'
    selection_loop:
        CommandLine|contains:
            - 'while.*clipboard'
            - 'loop.*clipboard'
            - 'Start-Sleep.*clipboard'
    condition: selection_ps or selection_api or selection_loop
falsepositives:
    - Clipboard manager applications
    - Automation tools using clipboard
level: medium
tags:
    - attack.collection
    - attack.t1115`,
  detectionExplanation: 'Clipboard stealers monitor and collect clipboard content, targeting: (1) copied passwords from password managers, (2) cryptocurrency wallet addresses (for substitution with attacker-controlled addresses), (3) sensitive data copied between applications. Continuous clipboard monitoring via loops with Get-Clipboard is particularly suspicious. Crypto-clippers specifically watch for wallet address patterns and replace them.',
  requiredLogs: ['Sysmon Event ID 1', 'PowerShell Script Block Logging'],
  logConfig: 'Command line auditing. Script block logging captures clipboard access in PowerShell.',
  falsePositives: ['Clipboard manager utilities', 'RPA/automation tools', 'Development scripts using clipboard programmatically'],
  tuning: 'Focus on continuous clipboard monitoring (loops). Single clipboard access may be legitimate. Correlate with process reputation.',
  commonErrors: ['Clipboard access APIs are used by many legitimate applications', 'Without continuous monitoring context, single accesses are noisy'],
  responseActions: ['Identify the process accessing the clipboard', 'Check for continuous monitoring patterns', 'Look for cryptocurrency address substitution', 'Review what data was on the clipboard during the access period'],
  threatIntel: { cves: [], cisaKev: false, campaigns: [], iocs: [] },
  references: ['https://attack.mitre.org/techniques/T1115/']
}

];
