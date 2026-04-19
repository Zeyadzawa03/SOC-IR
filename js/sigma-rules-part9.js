// ═══════════════════════════════════════════════════════════════════════
// Sigma Rules Part 9 — SigmaHQ Repository Sync
// Covers gaps identified from SigmaHQ official repository alignment
// Focus: LOLBAS, Named Pipes, PowerShell ScriptBlock, ADS, Cobalt Strike
// ═══════════════════════════════════════════════════════════════════════

const SIGMA_RULES_PART9 = [

// ═══ LOLBAS — Living Off The Land Binaries ═══
{
  id: 'SR-0163', title: 'CMSTP.exe Execution for UAC Bypass',
  status: 'stable', severity: 'high', author: 'SigmaHQ Aligned', date: '2024-03-15', modified: '2024-12-15',
  category: 'defense-evasion',
  description: 'Detects CMSTP.exe being used to bypass UAC or execute arbitrary commands via .inf files. CMSTP is a legitimate Microsoft tool for connection profiles that can be abused to execute DLLs and scriptlets.',
  tacticId: 'TA0005', tacticName: 'Defense Evasion',
  techniqueId: 'T1218.003', techniqueName: 'CMSTP',
  logsource: { product: 'windows', category: 'process_creation' },
  sigmaYaml: `title: CMSTP.exe UAC Bypass or Proxy Execution
id: 9a163a2b-4444-5555-6666-777788889163
status: stable
description: Detects CMSTP.exe proxy execution via INF files
author: SigmaHQ Aligned
date: 2024/03/15
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image|endswith: '\\\\cmstp.exe'
        CommandLine|contains:
            - '/s'
            - '/au'
            - '/ni'
            - '.inf'
    filter_legit:
        ParentImage|endswith: '\\\\explorer.exe'
    condition: selection and not filter_legit
falsepositives:
    - Legitimate connection profile installations
level: high
tags:
    - attack.defense_evasion
    - attack.t1218.003`,
  splunkQuery: `index=wineventlog sourcetype=WinEventLog:Sysmon EventCode=1
| where match(Image,"(?i)\\\\cmstp\\.exe$")
  AND match(CommandLine,"(?i)(/s|/au|/ni|\\.inf)")
  AND NOT match(ParentImage,"(?i)\\\\explorer\\.exe$")
| table _time, ComputerName, User, ParentImage, Image, CommandLine`,
  qradarQuery: `SELECT sourceip, username,
  "Parent Process Path", Filename, Command,
  COUNT(*) as cmstp_events
FROM events
WHERE CATEGORYNAME(category) ILIKE '%Process%Create%'
  AND Filename ILIKE '%cmstp.exe'
  AND (Command ILIKE '%/s%' OR Command ILIKE '%.inf%')
  AND "Parent Process Path" NOT ILIKE '%explorer.exe'
GROUP BY sourceip, username, "Parent Process Path", Filename, Command
ORDER BY starttime DESC
LAST 24 HOURS`,
  detectionExplanation: 'CMSTP.exe is a legitimate Windows binary that installs Connection Manager profiles. Attackers abuse it to execute arbitrary code from .inf files, bypassing UAC and application whitelisting. The /au flag enables auto-install, and /ni enables non-interactive mode.',
  requiredLogs: ['Sysmon Event ID 1 (Process Creation)'],
  logConfig: 'Process creation with full command line logging via Sysmon or Windows 4688.',
  falsePositives: ['Legitimate connection profile installations by IT', 'VPN client installations'],
  tuning: 'Focus on CMSTP spawned by non-standard parents. Legitimate usage is rare in most environments.',
  commonErrors: ['CMSTP is not commonly monitored', 'INF file content is not captured by process logging alone'],
  responseActions: ['Analyze the .inf file referenced in the command', 'Check for DLL or scriptlet execution from the INF', 'Block CMSTP execution via application control if not needed'],
  threatIntel: { cves: [], cisaKev: false, campaigns: ['Cobalt Group'], iocs: [] },
  references: ['https://attack.mitre.org/techniques/T1218/003/', 'https://lolbas-project.github.io/#/execute']
},

{
  id: 'SR-0164', title: 'Msiexec.exe Suspicious Execution — Remote MSI',
  status: 'stable', severity: 'high', author: 'SigmaHQ Aligned', date: '2024-05-10', modified: '2024-12-10',
  category: 'execution',
  description: 'Detects msiexec.exe installing MSI packages from remote URLs or network shares, commonly used for payload delivery while bypassing security controls.',
  tacticId: 'TA0005', tacticName: 'Defense Evasion',
  techniqueId: 'T1218.007', techniqueName: 'Msiexec',
  logsource: { product: 'windows', category: 'process_creation' },
  sigmaYaml: `title: Msiexec Remote MSI Installation
id: bb252a3c-5555-6666-7777-888899990164
status: stable
description: Detects remote MSI installation via msiexec
author: SigmaHQ Aligned
date: 2024/05/10
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image|endswith: '\\\\msiexec.exe'
        CommandLine|contains:
            - 'http://'
            - 'https://'
            - '\\\\\\\\' 
    selection_quiet:
        CommandLine|contains:
            - '/q'
            - '/quiet'
    condition: selection or (selection and selection_quiet)
falsepositives:
    - Legitimate remote software deployment
level: high
tags:
    - attack.defense_evasion
    - attack.t1218.007`,
  splunkQuery: `index=wineventlog sourcetype=WinEventLog:Sysmon EventCode=1
| where match(Image,"(?i)\\\\msiexec\\.exe$")
  AND match(CommandLine,"(?i)(https?://|\\\\\\\\)")
| table _time, ComputerName, User, CommandLine, ParentImage`,
  qradarQuery: `SELECT sourceip, username,
  Command,
  COUNT(*) as msiexec_events
FROM events
WHERE CATEGORYNAME(category) ILIKE '%Process%Create%'
  AND Filename ILIKE '%msiexec.exe'
  AND (Command ILIKE '%http://%' OR Command ILIKE '%https://%' OR Command ILIKE '%\\\\\\\\%')
GROUP BY sourceip, username, Command
ORDER BY starttime DESC
LAST 24 HOURS`,
  detectionExplanation: 'Msiexec.exe is the Windows Installer service. Attackers use it to download and execute MSI packages from remote URLs or network shares. The /q flag runs the installer silently. This bypasses many security controls because msiexec is a signed Microsoft binary.',
  requiredLogs: ['Sysmon Event ID 1'],
  logConfig: 'Process creation with command line auditing. Monitor msiexec network connections.',
  falsePositives: ['SCCM/Intune software deployments', 'Enterprise software updates from internal shares'],
  tuning: 'Allowlist known internal software distribution servers. Alert on msiexec fetching from external URLs.',
  commonErrors: ['Many legitimate deployments use msiexec with network paths', 'GPO software installations use msiexec'],
  responseActions: ['Capture the MSI file for analysis', 'Block the source URL', 'Check for persistence mechanisms installed by the MSI'],
  threatIntel: { cves: [], cisaKev: false, campaigns: ['Qakbot', 'Raspberry Robin'], iocs: [] },
  references: ['https://attack.mitre.org/techniques/T1218/007/']
},

{
  id: 'SR-0165', title: 'Forfiles.exe Command Execution — LOLBAS',
  status: 'stable', severity: 'medium', author: 'SigmaHQ Aligned', date: '2024-04-20', modified: '2024-12-10',
  category: 'execution',
  description: 'Detects forfiles.exe being abused to execute arbitrary commands. Forfiles is a legitimate Windows utility that can be weaponized as a command execution proxy.',
  tacticId: 'TA0002', tacticName: 'Execution',
  techniqueId: 'T1059', techniqueName: 'Command and Scripting Interpreter',
  logsource: { product: 'windows', category: 'process_creation' },
  sigmaYaml: `title: Forfiles.exe Command Execution
id: cc363b4d-6666-7777-8888-999900001165
status: stable
description: Detects forfiles.exe used for command execution proxy
author: SigmaHQ Aligned
date: 2024/04/20
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image|endswith: '\\\\forfiles.exe'
        CommandLine|contains:
            - '/c'
            - 'cmd'
            - 'powershell'
    condition: selection
falsepositives:
    - Legitimate batch scripting operations
level: medium
tags:
    - attack.execution
    - attack.t1059`,
  splunkQuery: `index=wineventlog sourcetype=WinEventLog:Sysmon EventCode=1
| where match(Image,"(?i)\\\\forfiles\\.exe$")
  AND match(CommandLine,"(?i)(/c|cmd|powershell)")
| table _time, ComputerName, User, CommandLine, ParentImage`,
  qradarQuery: `SELECT sourceip, username,
  Command,
  COUNT(*) as forfiles_events
FROM events
WHERE CATEGORYNAME(category) ILIKE '%Process%Create%'
  AND Filename ILIKE '%forfiles.exe'
  AND (Command ILIKE '%/c%' OR Command ILIKE '%cmd%' OR Command ILIKE '%powershell%')
GROUP BY sourceip, username, Command
ORDER BY starttime DESC
LAST 24 HOURS`,
  detectionExplanation: 'Forfiles.exe is a Windows utility designed to select files based on criteria and execute commands on them. Attackers abuse the /c flag to execute arbitrary commands, using forfiles as a proxy to bypass application whitelisting.',
  requiredLogs: ['Sysmon Event ID 1'],
  logConfig: 'Process creation with command line auditing.',
  falsePositives: ['Legitimate batch operations using forfiles for file management', 'IT automation scripts'],
  tuning: 'Focus on forfiles executing cmd.exe or powershell.exe. Legitimate use typically targets specific file operations.',
  commonErrors: ['Forfiles is uncommon but legitimate in some admin workflows'],
  responseActions: ['Examine the command being proxied through forfiles', 'Check for follow-on activity from the spawned process'],
  threatIntel: { cves: [], cisaKev: false, campaigns: [], iocs: [] },
  references: ['https://lolbas-project.github.io/#/execute']
},

{
  id: 'SR-0166', title: 'Wmic.exe XSL Script Processing',
  status: 'stable', severity: 'high', author: 'SigmaHQ Aligned', date: '2024-06-15', modified: '2024-12-15',
  category: 'defense-evasion',
  description: 'Detects WMIC.exe executing scripts via XSL stylesheet processing, a technique used to execute arbitrary JScript/VBScript from local or remote XSL files.',
  tacticId: 'TA0005', tacticName: 'Defense Evasion',
  techniqueId: 'T1220', techniqueName: 'XSL Script Processing',
  logsource: { product: 'windows', category: 'process_creation' },
  sigmaYaml: `title: WMIC XSL Script Processing
id: dd474c5e-7777-8888-9999-000011112166
status: stable
description: Detects WMIC XSL script execution for code proxy
author: SigmaHQ Aligned
date: 2024/06/15
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image|endswith: '\\\\wmic.exe'
        CommandLine|contains:
            - '/format:'
            - 'format:'
    filter_legit:
        CommandLine|contains:
            - 'format:table'
            - 'format:list'
            - 'format:csv'
    condition: selection and not filter_legit
falsepositives:
    - Legitimate WMI queries with custom formatting
level: high
tags:
    - attack.defense_evasion
    - attack.t1220`,
  splunkQuery: `index=wineventlog sourcetype=WinEventLog:Sysmon EventCode=1
| where match(Image,"(?i)\\\\wmic\\.exe$")
  AND match(CommandLine,"(?i)/format:")
  AND NOT match(CommandLine,"(?i)format:(table|list|csv|htable|hform)")
| table _time, ComputerName, User, CommandLine, ParentImage`,
  qradarQuery: `SELECT sourceip, username,
  Command,
  COUNT(*) as wmic_xsl_events
FROM events
WHERE CATEGORYNAME(category) ILIKE '%Process%Create%'
  AND Filename ILIKE '%wmic.exe'
  AND Command ILIKE '%/format:%'
  AND Command NOT ILIKE '%format:table%'
  AND Command NOT ILIKE '%format:list%'
GROUP BY sourceip, username, Command
ORDER BY starttime DESC
LAST 24 HOURS`,
  detectionExplanation: 'WMIC.exe supports XSL (eXtensible Stylesheet Language) for output formatting. Attackers abuse this by specifying malicious XSL files containing JScript or VBScript. The /format: flag can reference local or remote XSL files. Legitimate uses typically use built-in formats like table, list, or csv.',
  requiredLogs: ['Sysmon Event ID 1'],
  logConfig: 'Process creation with full command line logging.',
  falsePositives: ['Custom WMI reporting scripts using XSL formatting', 'IT automation with custom output formats'],
  tuning: 'Filter out standard format types (table, list, csv). Any custom XSL reference is suspicious.',
  commonErrors: ['The /format flag is commonly used legitimately with standard format types'],
  responseActions: ['Retrieve and analyze the XSL file referenced', 'Check for JScript/VBScript within the XSL', 'Block remote XSL execution'],
  threatIntel: { cves: [], cisaKev: false, campaigns: ['Cobalt Strike', 'FIN7'], iocs: [] },
  references: ['https://attack.mitre.org/techniques/T1220/']
},

// ═══ NAMED PIPES — Cobalt Strike / C2 Indicators ═══
{
  id: 'SR-0167', title: 'Cobalt Strike Named Pipe Detection',
  status: 'stable', severity: 'critical', author: 'SigmaHQ Aligned', date: '2024-01-20', modified: '2024-12-15',
  category: 'network-anomalies',
  description: 'Detects known Cobalt Strike default named pipes used for inter-process communication during C2 beacon operations, lateral movement, and post-exploitation.',
  tacticId: 'TA0011', tacticName: 'Command and Control',
  techniqueId: 'T1071.001', techniqueName: 'Web Protocols',
  logsource: { product: 'windows', category: 'pipe_created' },
  sigmaYaml: `title: Cobalt Strike Named Pipe Detection
id: ee585d6f-8888-9999-0000-111122223167
status: stable
description: Detects Cobalt Strike default named pipes
author: SigmaHQ Aligned
date: 2024/01/20
logsource:
    category: pipe_created
    product: windows
detection:
    selection:
        PipeName|startswith:
            - '\\\\MSSE-'
            - '\\\\msagent_'
            - '\\\\postex_'
            - '\\\\status_'
            - '\\\\mypipe-f'
            - '\\\\mypipe-h'
    selection_pattern:
        PipeName|re: '\\\\[a-f0-9]{7,10}'
    condition: selection or selection_pattern
falsepositives:
    - Rare legitimate applications using similar pipe names
level: critical
tags:
    - attack.command_and_control
    - attack.t1071.001`,
  splunkQuery: `index=wineventlog sourcetype=WinEventLog:Sysmon EventCode=17
| where match(PipeName,"(?i)(\\\\MSSE-|\\\\msagent_|\\\\postex_|\\\\status_|\\\\mypipe-)")
  OR match(PipeName,"^\\\\[a-f0-9]{7,10}$")
| table _time, ComputerName, User, Image, PipeName`,
  qradarQuery: `SELECT sourceip, username,
  Filename, "Pipe Name",
  COUNT(*) as cs_pipe_events
FROM events
WHERE QIDNAME(qid) ILIKE '%Pipe%Create%'
  AND ("Pipe Name" ILIKE '%MSSE-%' OR "Pipe Name" ILIKE '%msagent_%'
    OR "Pipe Name" ILIKE '%postex_%' OR "Pipe Name" ILIKE '%mypipe-%')
GROUP BY sourceip, username, Filename, "Pipe Name"
ORDER BY starttime DESC
LAST 24 HOURS`,
  detectionExplanation: 'Cobalt Strike uses named pipes for inter-process communication between its beacon and injected processes. Default pipe names include MSSE-*, msagent_*, postex_*, and status_*. While operators can customize pipe names, many use defaults. Random hex strings as pipe names are also suspicious.',
  requiredLogs: ['Sysmon Event ID 17 (Pipe Created)', 'Event ID 18 (Pipe Connected)'],
  logConfig: 'Deploy Sysmon with pipe creation monitoring (Event IDs 17 and 18).',
  falsePositives: ['Rare - legitimate applications rarely use these pipe name patterns'],
  tuning: 'This is a high-confidence detection. Any match outside of pen testing should be treated as critical.',
  commonErrors: ['Sysmon pipe events require explicit configuration', 'Custom CS profiles change pipe names'],
  responseActions: ['CRITICAL: Assume active C2 compromise', 'Isolate the affected host immediately', 'Identify the beacon process and parent', 'Hunt for lateral movement from the compromised host', 'Full incident response required'],
  threatIntel: { cves: [], cisaKev: false, campaigns: ['Cobalt Strike Operators', 'FIN7', 'APT29'], iocs: [] },
  references: ['https://attack.mitre.org/software/S0154/']
},

// ═══ POWERSHELL SCRIPT BLOCK LOGGING ═══
{
  id: 'SR-0168', title: 'PowerShell Script Block — AMSI Bypass Attempt',
  status: 'stable', severity: 'critical', author: 'SigmaHQ Aligned', date: '2024-02-10', modified: '2024-12-15',
  category: 'defense-evasion',
  description: 'Detects PowerShell script block content containing AMSI bypass techniques, used to disable the Antimalware Scan Interface before executing malicious scripts.',
  tacticId: 'TA0005', tacticName: 'Defense Evasion',
  techniqueId: 'T1562.001', techniqueName: 'Disable or Modify Tools',
  logsource: { product: 'windows', service: 'powershell-scriptblock' },
  sigmaYaml: `title: PowerShell AMSI Bypass Detection
id: ff696e70-9999-0000-1111-222233334168
status: stable
description: Detects AMSI bypass attempts in PowerShell script blocks
author: SigmaHQ Aligned
date: 2024/02/10
logsource:
    product: windows
    service: powershell-scriptblock
detection:
    selection:
        ScriptBlockText|contains:
            - 'AmsiUtils'
            - 'amsiInitFailed'
            - 'AmsiScanBuffer'
            - 'amsiContext'
            - 'Set-MpPreference -DisableRealtimeMonitoring'
            - 'Unload-Amsi'
    condition: selection
falsepositives:
    - Security research and testing
level: critical
tags:
    - attack.defense_evasion
    - attack.t1562.001`,
  splunkQuery: `index=wineventlog sourcetype=WinEventLog:Microsoft-Windows-PowerShell/Operational EventCode=4104
| where match(ScriptBlockText,"(?i)(AmsiUtils|amsiInitFailed|AmsiScanBuffer|amsiContext|Unload-Amsi)")
| table _time, ComputerName, User, ScriptBlockText
| head 50`,
  qradarQuery: `SELECT sourceip, username,
  UTF8(payload) as script_content,
  COUNT(*) as amsi_bypass
FROM events
WHERE LOGSOURCETYPENAME(devicetype) ILIKE '%PowerShell%'
  AND EventID = 4104
  AND (UTF8(payload) ILIKE '%AmsiUtils%' OR UTF8(payload) ILIKE '%amsiInitFailed%'
    OR UTF8(payload) ILIKE '%AmsiScanBuffer%')
GROUP BY sourceip, username, UTF8(payload)
ORDER BY starttime DESC
LAST 24 HOURS`,
  detectionExplanation: 'AMSI (Antimalware Scan Interface) allows security tools to scan PowerShell, VBScript, and JScript at runtime. Attackers bypass AMSI by patching the AmsiScanBuffer function in memory, setting amsiInitFailed to true, or using reflection to modify AMSI internals. This enables execution of malicious scripts without AV detection.',
  requiredLogs: ['PowerShell Script Block Logging (Event ID 4104)'],
  logConfig: 'Enable PowerShell Script Block Logging via GPO. This captures the actual script content.',
  falsePositives: ['Security researchers testing AMSI', 'Red team authorized engagements'],
  tuning: 'This is a very high-fidelity detection. AMSI bypass in production environments is almost always malicious.',
  commonErrors: ['Script Block Logging must be enabled; it is off by default', 'Some AMSI bypasses use obfuscation to avoid string matching'],
  responseActions: ['CRITICAL: Active attacker with AV bypass capability', 'Isolate the endpoint', 'Review subsequent script blocks for payload', 'Check for persistence mechanisms', 'Full forensic investigation required'],
  threatIntel: { cves: [], cisaKev: false, campaigns: ['Cobalt Strike', 'LockBit 3.0', 'ALPHV/BlackCat'], iocs: [] },
  references: ['https://attack.mitre.org/techniques/T1562/001/']
},

{
  id: 'SR-0169', title: 'PowerShell Script Block — Suspicious Keywords',
  status: 'stable', severity: 'high', author: 'SigmaHQ Aligned', date: '2024-03-05', modified: '2024-12-10',
  category: 'execution',
  description: 'Detects PowerShell script blocks containing suspicious keywords commonly associated with offensive tools, reconnaissance, and credential access activities.',
  tacticId: 'TA0002', tacticName: 'Execution',
  techniqueId: 'T1059.001', techniqueName: 'PowerShell',
  logsource: { product: 'windows', service: 'powershell-scriptblock' },
  sigmaYaml: `title: Suspicious PowerShell Script Block Keywords
id: 00707f81-0000-1111-2222-333344445169
status: stable
description: Detects malicious keyword patterns in script blocks
author: SigmaHQ Aligned
date: 2024/03/05
logsource:
    product: windows
    service: powershell-scriptblock
detection:
    selection:
        ScriptBlockText|contains:
            - 'Invoke-Mimikatz'
            - 'Invoke-Shellcode'
            - 'Invoke-BloodHound'
            - 'Get-GPPPassword'
            - 'Invoke-Kerberoast'
            - 'Get-Keystrokes'
            - 'Invoke-TokenManipulation'
            - 'Invoke-CredentialInjection'
            - 'Invoke-DCSync'
            - 'PowerView'
            - 'Invoke-SMBExec'
    condition: selection
falsepositives:
    - Authorized penetration testing
level: high
tags:
    - attack.execution
    - attack.t1059.001`,
  splunkQuery: `index=wineventlog sourcetype=WinEventLog:Microsoft-Windows-PowerShell/Operational EventCode=4104
| where match(ScriptBlockText,"(?i)(Invoke-Mimikatz|Invoke-Shellcode|Invoke-BloodHound|Get-GPPPassword|Invoke-Kerberoast|PowerView|Invoke-SMBExec|Invoke-DCSync)")
| table _time, ComputerName, User, ScriptBlockText
| head 50`,
  qradarQuery: `SELECT sourceip, username,
  UTF8(payload) as script_content,
  COUNT(*) as malicious_scripts
FROM events
WHERE LOGSOURCETYPENAME(devicetype) ILIKE '%PowerShell%'
  AND EventID = 4104
  AND (UTF8(payload) ILIKE '%Invoke-Mimikatz%' OR UTF8(payload) ILIKE '%Invoke-Shellcode%'
    OR UTF8(payload) ILIKE '%Invoke-BloodHound%' OR UTF8(payload) ILIKE '%Invoke-Kerberoast%'
    OR UTF8(payload) ILIKE '%PowerView%' OR UTF8(payload) ILIKE '%Invoke-DCSync%')
GROUP BY sourceip, username, UTF8(payload)
ORDER BY starttime DESC
LAST 24 HOURS`,
  detectionExplanation: 'PowerShell Script Block Logging captures the actual script content before execution, even if the script is obfuscated or encoded. This rule looks for known offensive tool cmdlet names from frameworks like PowerSploit, Empire, and BloodHound that indicate active post-exploitation.',
  requiredLogs: ['PowerShell Script Block Logging (Event ID 4104)'],
  logConfig: 'Enable Script Block Logging via GPO: Computer Configuration > Administrative Templates > Windows PowerShell > Turn on Script Block Logging.',
  falsePositives: ['Authorized red team operations', 'Security tool testing'],
  tuning: 'These keywords are highly specific to offensive tools. Any match in production warrants investigation.',
  commonErrors: ['Requires Script Block Logging to be enabled', 'Advanced attackers may modify cmdlet names'],
  responseActions: ['Immediate endpoint isolation', 'Analyze the full script block content', 'Check for lateral movement', 'Review user account for compromise indicators'],
  threatIntel: { cves: [], cisaKev: false, campaigns: ['APT29', 'FIN7', 'Scattered Spider'], iocs: [] },
  references: ['https://attack.mitre.org/techniques/T1059/001/']
},

// ═══ ALTERNATE DATA STREAMS ═══
{
  id: 'SR-0170', title: 'Alternate Data Stream Creation — Hidden Payload',
  status: 'stable', severity: 'high', author: 'SigmaHQ Aligned', date: '2024-07-10', modified: '2024-12-10',
  category: 'defense-evasion',
  description: 'Detects creation of NTFS Alternate Data Streams which can hide malicious payloads within legitimate files, making them invisible to standard file browsing.',
  tacticId: 'TA0005', tacticName: 'Defense Evasion',
  techniqueId: 'T1564.004', techniqueName: 'NTFS File Attributes',
  logsource: { product: 'windows', category: 'process_creation' },
  sigmaYaml: `title: NTFS Alternate Data Stream Abuse
id: 11818f92-1111-2222-3333-444455556170
status: stable
description: Detects ADS creation for payload hiding
author: SigmaHQ Aligned
date: 2024/07/10
logsource:
    category: process_creation
    product: windows
detection:
    selection_cmd:
        CommandLine|contains:
            - 'type*.exe*>'
            - 'type *>*:*'
            - 'echo *>*:*'
    selection_ads:
        CommandLine|re: '.*:\\w+\\.\\w+:\\w+\\.\\w+'
    selection_extract:
        Image|endswith: '\\\\findstr.exe'
        CommandLine|contains: '/v /l'
    condition: selection_cmd or selection_ads or selection_extract
falsepositives:
    - Zone.Identifier ADS created by browsers
level: high
tags:
    - attack.defense_evasion
    - attack.t1564.004`,
  splunkQuery: `index=wineventlog sourcetype=WinEventLog:Sysmon (EventCode=1 OR EventCode=15)
| where (EventCode=15 AND match(TargetFilename,":"))
  OR (EventCode=1 AND match(CommandLine,"(?i)(type.*>.*:|echo.*>.*:|findstr.*:)"))
| table _time, ComputerName, User, Image, CommandLine, TargetFilename`,
  qradarQuery: `SELECT sourceip, username,
  Command, Filename,
  COUNT(*) as ads_events
FROM events
WHERE (Command ILIKE '%type%>%:%' OR Command ILIKE '%echo%>%:%'
  OR QIDNAME(qid) ILIKE '%Alternate Data Stream%')
GROUP BY sourceip, username, Command, Filename
ORDER BY starttime DESC
LAST 24 HOURS`,
  detectionExplanation: 'NTFS Alternate Data Streams allow data to be attached to files in a hidden stream. Commands like "type malware.exe > doc.txt:hidden.exe" hide the executable inside the document. ADS content is invisible to dir commands and most file explorers. Sysmon Event ID 15 specifically tracks ADS creation.',
  requiredLogs: ['Sysmon Event ID 15 (FileCreateStreamHash)', 'Sysmon Event ID 1'],
  logConfig: 'Deploy Sysmon with FileCreateStreamHash monitoring (Event ID 15).',
  falsePositives: ['Zone.Identifier streams created by downloaded files', 'Some backup tools use ADS for metadata'],
  tuning: 'Filter out Zone.Identifier streams. Focus on ADS containing executable content (.exe, .dll, .ps1).',
  commonErrors: ['ADS monitoring requires Sysmon Event ID 15', 'Many tools cannot view ADS content'],
  responseActions: ['Extract and analyze the ADS content', 'Check for execution of code from ADS', 'Remove malicious ADS content'],
  threatIntel: { cves: [], cisaKev: false, campaigns: ['APT28'], iocs: [] },
  references: ['https://attack.mitre.org/techniques/T1564/004/']
},

// ═══ COM HIJACKING ═══
{
  id: 'SR-0171', title: 'COM Object Hijacking — Registry Modification',
  status: 'stable', severity: 'high', author: 'SigmaHQ Aligned', date: '2024-08-05', modified: '2024-12-10',
  category: 'persistence',
  description: 'Detects registry modifications indicating COM object hijacking, where attackers replace legitimate COM server DLLs with malicious ones to achieve persistence or defense evasion.',
  tacticId: 'TA0003', tacticName: 'Persistence',
  techniqueId: 'T1546.015', techniqueName: 'Component Object Model Hijacking',
  logsource: { product: 'windows', category: 'registry_set' },
  sigmaYaml: `title: COM Object Hijacking via Registry
id: 22929093-2222-3333-4444-555566667171
status: stable
description: Detects COM hijacking through InprocServer32 modifications
author: SigmaHQ Aligned
date: 2024/08/05
logsource:
    category: registry_set
    product: windows
detection:
    selection:
        TargetObject|contains: 'InprocServer32'
        TargetObject|contains: 'HKCU'
    filter_legit:
        Details|contains:
            - 'C:\\\\Windows\\\\'
            - 'C:\\\\Program Files'
    condition: selection and not filter_legit
falsepositives:
    - Legitimate COM registrations by software
level: high
tags:
    - attack.persistence
    - attack.t1546.015`,
  splunkQuery: `index=wineventlog sourcetype=WinEventLog:Sysmon EventCode=13
| where match(TargetObject,"(?i)HKCU.*InprocServer32")
  AND NOT match(Details,"(?i)(C:\\\\Windows|C:\\\\Program Files)")
| table _time, ComputerName, User, TargetObject, Details, Image`,
  qradarQuery: `SELECT sourceip, username,
  "Registry Key", "Registry Value",
  COUNT(*) as com_hijack_events
FROM events
WHERE QIDNAME(qid) ILIKE '%Registry%'
  AND "Registry Key" ILIKE '%InprocServer32%'
  AND "Registry Key" ILIKE '%HKCU%'
  AND "Registry Value" NOT ILIKE '%Windows%'
GROUP BY sourceip, username, "Registry Key", "Registry Value"
ORDER BY starttime DESC
LAST 24 HOURS`,
  detectionExplanation: 'COM hijacking exploits the Windows COM loading mechanism. When an application loads a COM object, Windows checks HKCU before HKLM. Attackers create entries in HKCU\\Software\\Classes\\CLSID pointing InprocServer32 to malicious DLLs. This triggers malicious code execution whenever the legitimate COM object is loaded.',
  requiredLogs: ['Sysmon Event ID 13 (Registry Value Set)'],
  logConfig: 'Sysmon with registry monitoring. Focus on HKCU InprocServer32 modifications.',
  falsePositives: ['Legitimate software registering COM components', 'Browser extensions modifying COM entries'],
  tuning: 'Focus on InprocServer32 values pointing to user-writable directories (AppData, Temp, Downloads).',
  commonErrors: ['Many legitimate COM registrations occur during software installation', 'HKLM entries are different — HKCU is more suspicious'],
  responseActions: ['Analyze the DLL referenced in InprocServer32', 'Identify which COM CLSID was hijacked', 'Remove the malicious registry entry', 'Check the DLL for backdoor functionality'],
  threatIntel: { cves: [], cisaKev: false, campaigns: ['Turla', 'APT29'], iocs: [] },
  references: ['https://attack.mitre.org/techniques/T1546/015/']
},

// ═══ DISKSHADOW — NTDS.dit Alternative ═══
{
  id: 'SR-0172', title: 'Diskshadow.exe Abuse for Credential Theft',
  status: 'stable', severity: 'critical', author: 'SigmaHQ Aligned', date: '2024-04-15', modified: '2024-12-15',
  category: 'credential-access',
  description: 'Detects diskshadow.exe being used interactively or via script to create shadow copies for NTDS.dit extraction, an alternative to vssadmin for credential theft.',
  tacticId: 'TA0006', tacticName: 'Credential Access',
  techniqueId: 'T1003.003', techniqueName: 'NTDS',
  logsource: { product: 'windows', category: 'process_creation' },
  sigmaYaml: `title: Diskshadow.exe NTDS.dit Extraction
id: 33030104-3333-4444-5555-666677778172
status: stable
description: Detects diskshadow.exe abuse for credential theft
author: SigmaHQ Aligned
date: 2024/04/15
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image|endswith: '\\\\diskshadow.exe'
    selection_script:
        CommandLine|contains:
            - '/s '
            - '-s '
            - 'exec'
    condition: selection and selection_script
falsepositives:
    - Legitimate backup operations using diskshadow
level: critical
tags:
    - attack.credential_access
    - attack.t1003.003`,
  splunkQuery: `index=wineventlog sourcetype=WinEventLog:Sysmon EventCode=1
| where match(Image,"(?i)\\\\diskshadow\\.exe$")
  AND match(CommandLine,"(?i)(/s|-s|exec)")
| table _time, ComputerName, User, CommandLine, ParentImage`,
  qradarQuery: `SELECT sourceip, username,
  Command,
  COUNT(*) as diskshadow_events
FROM events
WHERE CATEGORYNAME(category) ILIKE '%Process%Create%'
  AND Filename ILIKE '%diskshadow.exe'
  AND (Command ILIKE '%/s %' OR Command ILIKE '%-s %' OR Command ILIKE '%exec%')
GROUP BY sourceip, username, Command
ORDER BY starttime DESC
LAST 24 HOURS`,
  detectionExplanation: 'Diskshadow.exe is a legitimate Microsoft tool for managing volume shadow copies. Unlike vssadmin, it supports scripting mode (/s flag) and can execute .dsh script files. Attackers use it to create shadow copies of system volumes, then extract NTDS.dit from the shadow copy for offline credential extraction.',
  requiredLogs: ['Sysmon Event ID 1', 'Windows Security 4688'],
  logConfig: 'Process creation logging on domain controllers.',
  falsePositives: ['Legitimate backup operations using diskshadow', 'Disaster recovery procedures'],
  tuning: 'Any diskshadow execution outside scheduled backups warrants investigation. Extremely high-fidelity on workstations.',
  commonErrors: ['Diskshadow is less commonly monitored than vssadmin', 'Script mode execution may reference external .dsh files'],
  responseActions: ['CRITICAL: Assume credential compromise', 'Check for NTDS.dit in shadow copies', 'Reset all domain passwords', 'Investigate how DC access was obtained'],
  threatIntel: { cves: [], cisaKev: false, campaigns: ['LockBit 3.0', 'Midnight Blizzard'], iocs: [] },
  references: ['https://attack.mitre.org/techniques/T1003/003/']
},

// ═══ PROCESS TAMPERING ═══
{
  id: 'SR-0173', title: 'Process Tampering — Image File Execution Options Debugger',
  status: 'stable', severity: 'high', author: 'SigmaHQ Aligned', date: '2024-09-10', modified: '2024-12-10',
  category: 'persistence',
  description: 'Detects modification of Image File Execution Options (IFEO) to set a debugger for legitimate processes, effectively redirecting execution to malicious binaries. Also detects the "silent process exit" variant.',
  tacticId: 'TA0003', tacticName: 'Persistence',
  techniqueId: 'T1546.012', techniqueName: 'Image File Execution Options Injection',
  logsource: { product: 'windows', category: 'registry_set' },
  sigmaYaml: `title: IFEO Debugger Persistence
id: 44141215-4444-5555-6666-777788889173
status: stable
description: Detects IFEO debugger hijacking for persistence
author: SigmaHQ Aligned
date: 2024/09/10
logsource:
    category: registry_set
    product: windows
detection:
    selection:
        TargetObject|contains:
            - 'Image File Execution Options'
            - 'SilentProcessExit'
        TargetObject|endswith:
            - '\\\\Debugger'
            - '\\\\MonitorProcess'
    condition: selection
falsepositives:
    - Debugger software registration
    - Application compatibility settings
level: high
tags:
    - attack.persistence
    - attack.t1546.012`,
  splunkQuery: `index=wineventlog sourcetype=WinEventLog:Sysmon EventCode=13
| where match(TargetObject,"(?i)Image File Execution Options.*\\\\(Debugger|MonitorProcess)$")
  OR match(TargetObject,"(?i)SilentProcessExit.*\\\\MonitorProcess$")
| table _time, ComputerName, User, TargetObject, Details, Image`,
  qradarQuery: `SELECT sourceip, username,
  "Registry Key", "Registry Value",
  COUNT(*) as ifeo_events
FROM events
WHERE QIDNAME(qid) ILIKE '%Registry%'
  AND ("Registry Key" ILIKE '%Image File Execution Options%Debugger%'
    OR "Registry Key" ILIKE '%SilentProcessExit%MonitorProcess%')
GROUP BY sourceip, username, "Registry Key", "Registry Value"
ORDER BY starttime DESC
LAST 24 HOURS`,
  detectionExplanation: 'IFEO allows specifying a debugger that Windows will launch whenever a target executable starts. Attackers set cmd.exe or malware as the debugger for commonly launched programs. The SilentProcessExit variant triggers a monitor process when a target process exits, providing another persistence mechanism.',
  requiredLogs: ['Sysmon Event ID 13 (Registry Value Set)'],
  logConfig: 'Sysmon with registry monitoring on IFEO and SilentProcessExit keys.',
  falsePositives: ['Developer debugger registrations', 'Application compatibility shims'],
  tuning: 'Alert on any IFEO Debugger pointing to cmd.exe, powershell.exe, or non-standard paths.',
  commonErrors: ['Some legitimate accessibility tools use IFEO for Sticky Keys replacement', 'Application compatibility shims can look similar'],
  responseActions: ['Remove the malicious IFEO entry', 'Analyze the debugger binary', 'Check for additional persistence mechanisms', 'Determine how the attacker gained registry write access'],
  threatIntel: { cves: [], cisaKev: false, campaigns: ['APT41'], iocs: [] },
  references: ['https://attack.mitre.org/techniques/T1546/012/']
},

// ═══ DNS OVER HTTPS / ENCRYPTED DNS ═══
{
  id: 'SR-0174', title: 'DNS-over-HTTPS (DoH) Client Detection',
  status: 'stable', severity: 'medium', author: 'SigmaHQ Aligned', date: '2024-10-05', modified: '2024-12-10',
  category: 'network-anomalies',
  description: 'Detects the use of DNS-over-HTTPS clients or connections to known DoH providers, which can be used to bypass DNS monitoring and exfiltrate data through encrypted DNS channels.',
  tacticId: 'TA0011', tacticName: 'Command and Control',
  techniqueId: 'T1071.004', techniqueName: 'DNS',
  logsource: { product: 'windows', category: 'dns_query' },
  sigmaYaml: `title: DNS-over-HTTPS Client Detection
id: 55252326-5555-6666-7777-888899990174
status: stable
description: Detects DoH usage bypassing DNS monitoring
author: SigmaHQ Aligned
date: 2024/10/05
logsource:
    category: dns_query
    product: windows
detection:
    selection:
        QueryName|endswith:
            - 'dns.google'
            - 'cloudflare-dns.com'
            - 'dns.quad9.net'
            - 'doh.opendns.com'
            - 'dns.nextdns.io'
            - 'doh.cleanbrowsing.org'
    condition: selection
falsepositives:
    - Legitimate applications using DoH
    - Security tools performing DNS lookups
level: medium
tags:
    - attack.command_and_control
    - attack.t1071.004`,
  splunkQuery: `index=dns OR index=wineventlog sourcetype=WinEventLog:Sysmon EventCode=22
| where match(QueryName,"(?i)(dns\\.google|cloudflare-dns\\.com|dns\\.quad9\\.net|doh\\.opendns\\.com|dns\\.nextdns\\.io)")
| stats count dc(src) as unique_sources values(src) as sources by QueryName, _time
| table _time, QueryName, unique_sources, sources, count`,
  qradarQuery: `SELECT sourceip,
  "DNS Request Domain",
  COUNT(*) as doh_queries
FROM events
WHERE CATEGORYNAME(category) ILIKE '%DNS%'
  AND ("DNS Request Domain" ILIKE '%dns.google%' OR "DNS Request Domain" ILIKE '%cloudflare-dns.com%'
    OR "DNS Request Domain" ILIKE '%dns.quad9.net%' OR "DNS Request Domain" ILIKE '%doh.opendns.com%')
GROUP BY sourceip, "DNS Request Domain"
ORDER BY doh_queries DESC
LAST 24 HOURS`,
  detectionExplanation: 'DNS-over-HTTPS encrypts DNS queries inside HTTPS traffic to well-known providers. While it improves privacy, it also enables attackers to bypass DNS monitoring, DNS-based security controls, and data exfiltration detection. Detecting lookups to DoH providers identifies endpoints that may be bypassing security controls.',
  requiredLogs: ['Sysmon Event ID 22 (DNS Query)', 'DNS server logs'],
  logConfig: 'Deploy Sysmon with DNS query monitoring (Event ID 22). Configure DNS logging.',
  falsePositives: ['Modern browsers with DoH enabled', 'Privacy-focused applications', 'VPN clients using DoH'],
  tuning: 'Baseline legitimate DoH usage. Focus on non-browser processes making DoH queries. Consider blocking DoH at the firewall to force DNS through monitored resolvers.',
  commonErrors: ['DoH traffic looks like normal HTTPS', 'Cannot see query content without TLS inspection'],
  responseActions: ['Identify the application making DoH requests', 'Check if DoH is used to bypass security controls', 'Consider implementing DNS filtering that works with DoH', 'Block DoH at the network level if policy requires traditional DNS'],
  threatIntel: { cves: [], cisaKev: false, campaigns: ['Godlua C2'], iocs: [] },
  references: ['https://attack.mitre.org/techniques/T1071/004/']
},

// ═══ WINDOWS MANAGEMENT — Exchange/IIS ═══
{
  id: 'SR-0175', title: 'Exchange Server Suspicious Child Process',
  status: 'stable', severity: 'critical', author: 'SigmaHQ Aligned', date: '2024-01-15', modified: '2024-12-15',
  category: 'web-attacks',
  description: 'Detects suspicious child processes spawned by Microsoft Exchange server IIS worker processes. This pattern is associated with web shell execution and Exchange exploitation.',
  tacticId: 'TA0002', tacticName: 'Execution',
  techniqueId: 'T1190', techniqueName: 'Exploit Public-Facing Application',
  logsource: { product: 'windows', category: 'process_creation' },
  sigmaYaml: `title: Exchange Server Suspicious Child Process
id: 66363437-6666-7777-8888-999900001175
status: stable
description: Detects webshell or exploit on Exchange Server
author: SigmaHQ Aligned
date: 2024/01/15
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        ParentImage|endswith:
            - '\\\\w3wp.exe'
            - '\\\\UMWorkerProcess.exe'
        Image|endswith:
            - '\\\\cmd.exe'
            - '\\\\powershell.exe'
            - '\\\\pwsh.exe'
            - '\\\\net.exe'
            - '\\\\whoami.exe'
    condition: selection
falsepositives:
    - Legitimate Exchange management scripts
level: critical
tags:
    - attack.initial_access
    - attack.t1190`,
  splunkQuery: `index=wineventlog sourcetype=WinEventLog:Sysmon EventCode=1
| where match(ParentImage,"(?i)(w3wp|UMWorkerProcess)\\.exe$")
  AND match(Image,"(?i)(cmd|powershell|pwsh|net|whoami|net1)\\.exe$")
| table _time, ComputerName, User, ParentImage, Image, CommandLine`,
  qradarQuery: `SELECT sourceip, username,
  "Parent Process Path", Filename, Command,
  COUNT(*) as exchange_exploit
FROM events
WHERE CATEGORYNAME(category) ILIKE '%Process%Create%'
  AND ("Parent Process Path" ILIKE '%w3wp.exe' OR "Parent Process Path" ILIKE '%UMWorkerProcess.exe')
  AND (Filename ILIKE '%cmd.exe' OR Filename ILIKE '%powershell.exe' OR Filename ILIKE '%whoami.exe' OR Filename ILIKE '%net.exe')
GROUP BY sourceip, username, "Parent Process Path", Filename, Command
ORDER BY starttime DESC
LAST 24 HOURS`,
  detectionExplanation: 'Exchange Server runs under IIS (w3wp.exe) and Unified Messaging (UMWorkerProcess.exe). When these processes spawn command interpreters or reconnaissance tools, it indicates web shell execution or active exploitation. This pattern was central to ProxyShell, ProxyLogon, and HAFNIUM attacks.',
  requiredLogs: ['Sysmon Event ID 1 on Exchange servers'],
  logConfig: 'Deploy Sysmon on all Exchange servers. Monitor w3wp.exe child processes.',
  falsePositives: ['Exchange management scripts using PowerShell', 'Health monitoring probes'],
  tuning: 'Baseline legitimate Exchange management. w3wp.exe spawning cmd.exe or whoami.exe is almost always malicious.',
  commonErrors: ['Exchange generates many legitimate PowerShell processes', 'Application pool recycling can trigger alerts'],
  responseActions: ['CRITICAL: Possible web shell or active exploitation', 'Check for web shells in Exchange directories', 'Review IIS logs for exploit indicators', 'Apply latest Exchange security patches', 'Full forensic investigation of the Exchange server'],
  threatIntel: { cves: ['CVE-2021-34473', 'CVE-2021-26855'], cisaKev: true, campaigns: ['HAFNIUM', 'Midnight Blizzard'], iocs: [] },
  references: ['https://attack.mitre.org/techniques/T1190/']
},

// ═══ LOG4SHELL / JAVA EXPLOITATION ═══
{
  id: 'SR-0176', title: 'Java Application Spawning Shell — Log4Shell Pattern',
  status: 'stable', severity: 'critical', author: 'SigmaHQ Aligned', date: '2024-02-20', modified: '2024-12-15',
  category: 'web-attacks',
  description: 'Detects Java processes spawning shell interpreters, a pattern associated with Log4Shell (CVE-2021-44228) and other Java deserialization exploit chains.',
  tacticId: 'TA0002', tacticName: 'Execution',
  techniqueId: 'T1059', techniqueName: 'Command and Scripting Interpreter',
  logsource: { product: 'windows', category: 'process_creation' },
  sigmaYaml: `title: Java Process Spawning Shell Interpreter
id: 77474548-7777-8888-9999-000011112176
status: stable
description: Detects Java exploitation leading to shell access
author: SigmaHQ Aligned
date: 2024/02/20
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        ParentImage|endswith:
            - '\\\\java.exe'
            - '\\\\javaw.exe'
        Image|endswith:
            - '\\\\cmd.exe'
            - '\\\\powershell.exe'
            - '\\\\bash.exe'
            - '\\\\sh.exe'
            - '\\\\certutil.exe'
            - '\\\\wget.exe'
            - '\\\\curl.exe'
    condition: selection
falsepositives:
    - Java build tools executing scripts
    - CI/CD pipeline operations
level: critical
tags:
    - attack.execution
    - attack.t1059`,
  splunkQuery: `index=wineventlog sourcetype=WinEventLog:Sysmon EventCode=1
| where match(ParentImage,"(?i)(java|javaw)\\.exe$")
  AND match(Image,"(?i)(cmd|powershell|bash|sh|certutil|wget|curl)\\.exe$")
| table _time, ComputerName, User, ParentImage, Image, CommandLine`,
  qradarQuery: `SELECT sourceip, username,
  "Parent Process Path", Filename, Command,
  COUNT(*) as java_exploit
FROM events
WHERE CATEGORYNAME(category) ILIKE '%Process%Create%'
  AND ("Parent Process Path" ILIKE '%java.exe' OR "Parent Process Path" ILIKE '%javaw.exe')
  AND (Filename ILIKE '%cmd.exe' OR Filename ILIKE '%powershell.exe' OR Filename ILIKE '%certutil.exe' OR Filename ILIKE '%curl.exe')
GROUP BY sourceip, username, "Parent Process Path", Filename, Command
ORDER BY starttime DESC
LAST 24 HOURS`,
  detectionExplanation: 'Java applications should rarely spawn shell interpreters directly. When java.exe or javaw.exe creates cmd.exe, powershell.exe, or download utilities, it strongly indicates exploitation of a Java vulnerability (Log4Shell, deserialization flaws, or RCE). This detection is highly reliable for identifying initial exploitation.',
  requiredLogs: ['Sysmon Event ID 1'],
  logConfig: 'Process creation with parent process tracking on all Java application servers.',
  falsePositives: ['CI/CD build systems using Java to invoke shell scripts', 'Java-based automation platforms like Jenkins'],
  tuning: 'Allowlist known Java-based CI/CD systems. On production servers, Java spawning shells is almost always malicious.',
  commonErrors: ['Jenkins and other CI tools commonly trigger this', 'Build systems should be baselined separately'],
  responseActions: ['CRITICAL: Possible active exploitation', 'Identify the Java application being exploited', 'Check for Log4Shell indicators (jndi:ldap)', 'Patch the vulnerable application', 'Investigate what commands were executed'],
  threatIntel: { cves: ['CVE-2021-44228'], cisaKev: true, campaigns: ['Log4Shell Exploiters'], iocs: [] },
  references: ['https://attack.mitre.org/techniques/T1059/']
},

// ═══ MACOS DETECTION ═══
{
  id: 'SR-0177', title: 'macOS LaunchAgent/LaunchDaemon Persistence',
  status: 'stable', severity: 'high', author: 'SigmaHQ Aligned', date: '2024-06-20', modified: '2024-12-10',
  category: 'persistence',
  description: 'Detects creation of macOS LaunchAgent or LaunchDaemon plist files used for persistence. Adversaries create these files to execute payloads at login or system boot.',
  tacticId: 'TA0003', tacticName: 'Persistence',
  techniqueId: 'T1543.001', techniqueName: 'Launch Agent',
  logsource: { product: 'macos', category: 'file_event' },
  sigmaYaml: `title: macOS LaunchAgent Persistence
id: 88585659-8888-9999-0000-111122223177
status: stable
description: Detects LaunchAgent/Daemon creation on macOS
author: SigmaHQ Aligned
date: 2024/06/20
logsource:
    category: file_event
    product: macos
detection:
    selection:
        TargetFilename|contains:
            - '/LaunchAgents/'
            - '/LaunchDaemons/'
        TargetFilename|endswith: '.plist'
    filter_apple:
        TargetFilename|contains: 'com.apple.'
    condition: selection and not filter_apple
falsepositives:
    - Legitimate software installations
level: high
tags:
    - attack.persistence
    - attack.t1543.001`,
  splunkQuery: `index=osquery OR index=edr sourcetype=macos
| where match(path,"(?i)/(LaunchAgents|LaunchDaemons)/") AND match(path,"\\.plist$")
  AND NOT match(path,"com\\.apple\\.")
| table _time, host, user, path, action`,
  qradarQuery: `SELECT sourceip, username,
  Filename,
  COUNT(*) as launch_persistence
FROM events
WHERE (Filename ILIKE '%/LaunchAgents/%' OR Filename ILIKE '%/LaunchDaemons/%')
  AND Filename ILIKE '%.plist'
  AND Filename NOT ILIKE '%com.apple.%'
GROUP BY sourceip, username, Filename
ORDER BY starttime DESC
LAST 24 HOURS`,
  detectionExplanation: 'macOS uses LaunchAgents (per-user) and LaunchDaemons (system-wide) plist files for scheduled task execution. Non-Apple plist creation in these directories is a primary persistence mechanism on macOS. Attackers create malicious plist files that execute payloads at login or boot.',
  requiredLogs: ['macOS Unified Logging', 'Endpoint Detection (Osquery, CrowdStrike, etc.)'],
  logConfig: 'Deploy endpoint agent with file event monitoring on LaunchAgent/LaunchDaemon directories.',
  falsePositives: ['Legitimate application installations', 'System updates creating new launch items'],
  tuning: 'Filter apple-signed plist files. Focus on user-created plists in LaunchAgents and custom LaunchDaemons.',
  commonErrors: ['macOS logging requires separate collection infrastructure', 'Plist content is not always captured'],
  responseActions: ['Analyze the plist file content', 'Identify the binary/script it executes', 'Remove the malicious plist', 'Check for the payload binary'],
  threatIntel: { cves: [], cisaKev: false, campaigns: ['Lazarus Group macOS'], iocs: [] },
  references: ['https://attack.mitre.org/techniques/T1543/001/']
},

// ═══ CLOUD IDENTITY — Azure AD ═══
{
  id: 'SR-0178', title: 'Azure AD Conditional Access Policy Modification',
  status: 'stable', severity: 'critical', author: 'SigmaHQ Aligned', date: '2024-05-25', modified: '2024-12-15',
  category: 'cloud-threats',
  description: 'Detects modification or deletion of Azure AD Conditional Access policies, which could indicate an attacker weakening security controls after gaining administrative access.',
  tacticId: 'TA0005', tacticName: 'Defense Evasion',
  techniqueId: 'T1562.001', techniqueName: 'Disable or Modify Tools',
  logsource: { product: 'azure', service: 'auditlogs' },
  sigmaYaml: `title: Azure AD Conditional Access Policy Modified
id: 99696760-9999-0000-1111-222233334178
status: stable
description: Detects CA policy changes in Azure AD
author: SigmaHQ Aligned
date: 2024/05/25
logsource:
    product: azure
    service: auditlogs
detection:
    selection:
        operationName:
            - 'Update conditional access policy'
            - 'Delete conditional access policy'
    condition: selection
falsepositives:
    - Authorized CA policy administration
level: critical
tags:
    - attack.defense_evasion
    - attack.t1562.001`,
  splunkQuery: `index=azure sourcetype=azure:aad:audit
| where match(operationName,"(?i)(Update|Delete) conditional access policy")
| table _time, initiatedBy.user.userPrincipalName, targetResources{}.displayName, result, operationName`,
  qradarQuery: `SELECT username, sourceip,
  eventname,
  COUNT(*) as ca_policy_changes
FROM events
WHERE LOGSOURCETYPENAME(devicetype) ILIKE '%Azure%'
  AND (eventname ILIKE '%Update conditional access%' OR eventname ILIKE '%Delete conditional access%')
GROUP BY username, sourceip, eventname
ORDER BY starttime DESC
LAST 24 HOURS`,
  detectionExplanation: 'Conditional Access policies enforce MFA, device compliance, and location-based restrictions. An attacker with Azure AD admin access may modify or delete these policies to weaken security controls, enabling unrestricted access from any location without MFA.',
  requiredLogs: ['Azure AD Audit Logs'],
  logConfig: 'Azure AD audit logging with export to SIEM. Ensure administrative actions are captured.',
  falsePositives: ['Authorized IT administration of CA policies', 'Policy updates during security reviews'],
  tuning: 'Cross-reference with change management. Any CA policy deletion should trigger immediate review.',
  commonErrors: ['Azure AD logs require proper connector configuration', 'Log export delay can affect detection timing'],
  responseActions: ['Verify the change was authorized', 'Check the admin account for compromise', 'Restore deleted/modified policies', 'Review sign-in logs for suspicious activity enabled by the policy change'],
  threatIntel: { cves: [], cisaKev: false, campaigns: ['Midnight Blizzard', 'Scattered Spider'], iocs: [] },
  references: ['https://attack.mitre.org/techniques/T1562/001/']
},

// ═══ LINUX SSH CONTROLS ═══
{
  id: 'SR-0179', title: 'Linux SSH Authorized Keys Modification',
  status: 'stable', severity: 'high', author: 'SigmaHQ Aligned', date: '2024-07-15', modified: '2024-12-10',
  category: 'linux-threats',
  description: 'Detects modification of SSH authorized_keys files, allowing attackers to add their own keys for persistent backdoor SSH access without passwords.',
  tacticId: 'TA0003', tacticName: 'Persistence',
  techniqueId: 'T1098.004', techniqueName: 'SSH Authorized Keys',
  logsource: { product: 'linux', category: 'file_event' },
  sigmaYaml: `title: SSH Authorized Keys File Modified
id: 00807871-0000-1111-2222-333344445179
status: stable
description: Detects SSH key persistence via authorized_keys
author: SigmaHQ Aligned
date: 2024/07/15
logsource:
    category: file_event
    product: linux
detection:
    selection:
        TargetFilename|endswith:
            - '/.ssh/authorized_keys'
            - '/.ssh/authorized_keys2'
    condition: selection
falsepositives:
    - Legitimate SSH key deployment via Ansible/Puppet
level: high
tags:
    - attack.persistence
    - attack.t1098.004`,
  splunkQuery: `index=linux sourcetype=syslog OR sourcetype=auditd
| where match(file,"authorized_keys") OR match(key,"authorized_keys")
| table _time, host, user, file, action, key`,
  qradarQuery: `SELECT sourceip, username,
  Filename,
  COUNT(*) as ssh_key_events
FROM events
WHERE (Filename ILIKE '%authorized_keys%')
GROUP BY sourceip, username, Filename
ORDER BY starttime DESC
LAST 24 HOURS`,
  detectionExplanation: 'The ~/.ssh/authorized_keys file contains public keys that enable passwordless SSH login. Attackers modify this file to add their own keys, creating persistent backdoor access that survives password changes. This is a primary Linux persistence mechanism.',
  requiredLogs: ['Linux auditd (file access monitoring)', 'Syslog'],
  logConfig: 'Configure auditd to monitor authorized_keys files: -w /home/*/.ssh/authorized_keys -p wa -k ssh_keys',
  falsePositives: ['Ansible/Puppet SSH key deployment', 'User adding their own SSH keys', 'Cloud provisioning setting initial keys'],
  tuning: 'Baseline expected key deployments. Alert on authorized_keys changes outside of provisioning windows.',
  commonErrors: ['Auditd must be configured to monitor these files', 'Cloud instances often modify authorized_keys during provisioning'],
  responseActions: ['Compare authorized_keys with expected keys', 'Remove unauthorized public keys', 'Check SSH logs for login using the added key', 'Investigate how the attacker gained write access'],
  threatIntel: { cves: [], cisaKev: false, campaigns: ['TeamTNT', 'Outlaw'], iocs: [] },
  references: ['https://attack.mitre.org/techniques/T1098/004/']
},

// ═══ EDR SILENCING / SECURITY TOOL EVASION ═══
{
  id: 'SR-0180', title: 'EDR/AV Process Termination Attempt',
  status: 'stable', severity: 'critical', author: 'SigmaHQ Aligned', date: '2024-08-20', modified: '2024-12-15',
  category: 'defense-evasion',
  description: 'Detects attempts to terminate EDR/AV processes using tools like taskkill, Process Hacker, or known EDR-killer utilities. This is a critical pre-attack step before payload deployment.',
  tacticId: 'TA0005', tacticName: 'Defense Evasion',
  techniqueId: 'T1562.001', techniqueName: 'Disable or Modify Tools',
  logsource: { product: 'windows', category: 'process_creation' },
  sigmaYaml: `title: EDR/AV Process Termination Attempt
id: 11918982-1111-2222-3333-444455556180
status: stable
description: Detects attempts to kill security processes
author: SigmaHQ Aligned
date: 2024/08/20
logsource:
    category: process_creation
    product: windows
detection:
    selection_kill:
        Image|endswith:
            - '\\\\taskkill.exe'
            - '\\\\net.exe'
        CommandLine|contains:
            - 'MsMpEng'
            - 'MsSense'
            - 'SentinelAgent'
            - 'CrowdStrike'
            - 'CSFalcon'
            - 'Carbon Black'
            - 'cb.exe'
            - 'CylanceSvc'
            - 'WinDefend'
            - 'Tanium'
    selection_tools:
        Image|endswith:
            - '\\\\ProcessHacker.exe'
            - '\\\\procexp.exe'
            - '\\\\PCHunter'
            - '\\\\GMER.exe'
    condition: selection_kill or selection_tools
falsepositives:
    - IT troubleshooting security agent issues
level: critical
tags:
    - attack.defense_evasion
    - attack.t1562.001`,
  splunkQuery: `index=wineventlog sourcetype=WinEventLog:Sysmon EventCode=1
| where (match(Image,"(?i)(taskkill|net)\\.exe$") AND match(CommandLine,"(?i)(MsMpEng|MsSense|SentinelAgent|CrowdStrike|CSFalcon|CylanceSvc|WinDefend|Tanium)"))
  OR match(Image,"(?i)(ProcessHacker|procexp|PCHunter|GMER)\\.exe$")
| table _time, ComputerName, User, Image, CommandLine`,
  qradarQuery: `SELECT sourceip, username,
  Filename, Command,
  COUNT(*) as edr_kill_events
FROM events
WHERE CATEGORYNAME(category) ILIKE '%Process%Create%'
  AND ((Filename ILIKE '%taskkill%' AND (Command ILIKE '%MsMpEng%' OR Command ILIKE '%CrowdStrike%' OR Command ILIKE '%SentinelAgent%' OR Command ILIKE '%WinDefend%'))
    OR Filename ILIKE '%ProcessHacker%' OR Filename ILIKE '%GMER%')
GROUP BY sourceip, username, Filename, Command
ORDER BY starttime DESC
LAST 24 HOURS`,
  detectionExplanation: 'Attackers attempt to terminate EDR/AV processes before deploying ransomware or other payloads. This involves using taskkill/net stop against known security process names, or using tools like Process Hacker and GMER that can forcefully terminate protected processes. This is one of the strongest pre-ransomware indicators.',
  requiredLogs: ['Sysmon Event ID 1'],
  logConfig: 'Process creation with full command line logging.',
  falsePositives: ['IT staff troubleshooting security agent issues', 'Security agent upgrades'],
  tuning: 'This is an extremely high-fidelity detection. Any non-IT match is critical. EDR-killer tools on endpoints are always suspicious.',
  commonErrors: ['Some legitimate IT workflows involve stopping security agents for upgrades'],
  responseActions: ['CRITICAL: Active ransomware preparation likely', 'Isolate the endpoint immediately', 'Verify security agent status across all endpoints', 'Check for follow-on payload deployment', 'Escalate to IR team immediately'],
  threatIntel: { cves: [], cisaKev: false, campaigns: ['LockBit 3.0', 'ALPHV/BlackCat', 'Akira Ransomware'], iocs: [] },
  references: ['https://attack.mitre.org/techniques/T1562/001/']
}

];
