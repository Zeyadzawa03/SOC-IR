// Sigma Rules Database - Part 1: Initial Access, Execution, Persistence, Privilege Escalation, Defense Evasion
const SIGMA_RULES_PART1 = [
// ═══════════════════════════════════════════════════════════════
// INITIAL ACCESS (TA0001)
// ═══════════════════════════════════════════════════════════════
{
  id: 'SR-0001', title: 'Suspicious Email Attachment Execution',
  status: 'stable', severity: 'high', author: 'SOC Platform', date: '2024-06-15', modified: '2024-12-01',
  category: 'email-threats',
  description: 'Detects execution of potentially malicious file types commonly delivered via spearphishing attachments, such as Office macros, scripts, and executables launched from email client temp directories.',
  tacticId: 'TA0001', tacticName: 'Initial Access',
  techniqueId: 'T1566.001', techniqueName: 'Spearphishing Attachment',
  logsource: { product: 'windows', category: 'process_creation' },
  sigmaYaml: `title: Suspicious Email Attachment Execution
id: a1b2c3d4-e5f6-7890-abcd-ef1234567890
status: stable
description: Detects execution of potentially malicious files from email client temp directories
author: SOC Platform
date: 2024/06/15
modified: 2024/12/01
logsource:
    category: process_creation
    product: windows
detection:
    selection_parent:
        ParentImage|endswith:
            - '\\\\outlook.exe'
            - '\\\\thunderbird.exe'
    selection_child:
        Image|endswith:
            - '\\\\cmd.exe'
            - '\\\\powershell.exe'
            - '\\\\wscript.exe'
            - '\\\\cscript.exe'
            - '\\\\mshta.exe'
            - '\\\\regsvr32.exe'
            - '\\\\rundll32.exe'
    selection_temp_path:
        CommandLine|contains:
            - '\\\\AppData\\\\Local\\\\Temp\\\\'
            - '\\\\Content.Outlook\\\\'
            - '\\\\Temporary Internet Files\\\\'
    condition: selection_parent and (selection_child or selection_temp_path)
falsepositives:
    - Legitimate macros or scripts triggered from email
    - IT automation via Outlook plugins
level: high
tags:
    - attack.initial_access
    - attack.t1566.001`,
  detectionExplanation: 'This rule monitors for child processes spawned by email clients (Outlook, Thunderbird) that are commonly abused in phishing attacks. When a user opens a malicious attachment, it typically spawns interpreters like PowerShell, cmd.exe, or script hosts from the email client\'s temporary directories. The detection focuses on the parent-child process relationship as the primary indicator.',
  requiredLogs: ['Sysmon Event ID 1 (Process Creation)', 'Windows Security Event ID 4688 (Process Creation with command line auditing)', 'EDR telemetry with parent process tracking'],
  logConfig: 'Enable Sysmon with process creation logging. Ensure command line auditing is enabled via GPO: Computer Configuration > Administrative Templates > System > Audit Process Creation > Include command line in process creation events.',
  falsePositives: ['Legitimate Outlook COM add-ins spawning processes', 'IT helpdesk tools integrated with email clients', 'Automated email processing scripts in business workflows'],
  tuning: 'Allowlist known legitimate Outlook plugins by their full path. Add exclusions for verified IT automation processes. Consider adding a threshold for repeated occurrences from the same user.',
  commonErrors: ['Missing parent process tracking (Sysmon required)', 'Command line auditing not enabled on endpoints', 'Email client running under different process name than expected'],
  responseActions: ['Isolate the endpoint immediately', 'Collect the suspicious email and attachment for analysis', 'Check email gateway logs for similar messages sent to other users', 'Block sender domain/IP at email gateway', 'Search for IOCs from the attachment across all endpoints', 'Notify the user and conduct a brief interview'],
  threatIntel: { cves: [], cisaKev: false, campaigns: ['Midnight Blizzard', 'ALPHV/BlackCat Ransomware'], iocs: [] },
  references: ['https://attack.mitre.org/techniques/T1566/001/', 'https://github.com/SigmaHQ/sigma/wiki/Rule-Creation-Guide']
},
{
  id: 'SR-0002', title: 'Suspicious Spearphishing Link Click Pattern',
  status: 'stable', severity: 'medium', author: 'SOC Platform', date: '2024-07-20', modified: '2024-11-15',
  category: 'email-threats',
  description: 'Detects browser processes spawned by email clients followed by suspicious child process execution, indicating a user clicked a phishing link that led to payload download and execution.',
  tacticId: 'TA0001', tacticName: 'Initial Access',
  techniqueId: 'T1566.002', techniqueName: 'Spearphishing Link',
  logsource: { product: 'windows', category: 'process_creation' },
  sigmaYaml: `title: Suspicious Spearphishing Link Click Pattern
id: b2c3d4e5-f6a7-8901-bcde-f12345678901
status: stable
description: Detects browser launch from email client followed by suspicious downloads
author: SOC Platform
date: 2024/07/20
logsource:
    category: process_creation
    product: windows
detection:
    selection_email_to_browser:
        ParentImage|endswith:
            - '\\\\outlook.exe'
            - '\\\\thunderbird.exe'
        Image|endswith:
            - '\\\\chrome.exe'
            - '\\\\msedge.exe'
            - '\\\\firefox.exe'
            - '\\\\iexplore.exe'
    selection_download_exec:
        ParentImage|endswith:
            - '\\\\chrome.exe'
            - '\\\\msedge.exe'
            - '\\\\firefox.exe'
        Image|endswith:
            - '\\\\powershell.exe'
            - '\\\\cmd.exe'
            - '\\\\mshta.exe'
        CommandLine|contains:
            - 'http://'
            - 'https://'
            - 'DownloadString'
            - 'DownloadFile'
            - 'Invoke-WebRequest'
    condition: selection_email_to_browser or selection_download_exec
falsepositives:
    - Legitimate web-based tools launched from email links
level: medium
tags:
    - attack.initial_access
    - attack.t1566.002`,
  detectionExplanation: 'Monitors for the common phishing kill chain: email client launches browser (link click), then browser spawns suspicious processes that download or execute payloads. This two-stage detection catches both the initial click and the subsequent exploitation.',
  requiredLogs: ['Sysmon Event ID 1', 'Process creation with parent tracking'],
  logConfig: 'Deploy Sysmon with SwiftOnSecurity config or equivalent that captures parent process information.',
  falsePositives: ['Legitimate SSO login flows from email links', 'Web-based installers linked in legitimate IT emails'],
  tuning: 'Allowlist known safe URLs in CommandLine. Focus on downloads to non-standard directories like Downloads, Temp, or user profile paths.',
  commonErrors: ['Browser running in sandboxed mode may break parent chain', 'Different browser versions may have different executable names'],
  responseActions: ['Block the URL at proxy/firewall', 'Check proxy logs for all users who visited the URL', 'Collect browser history and download artifacts', 'Submit URL to threat intelligence platform'],
  threatIntel: { cves: [], cisaKev: false, campaigns: ['Scattered Spider'], iocs: [] },
  references: ['https://attack.mitre.org/techniques/T1566/002/']
},
{
  id: 'SR-0003', title: 'Exploit Against Public-Facing Application',
  status: 'stable', severity: 'critical', author: 'SOC Platform', date: '2024-03-10', modified: '2024-12-15',
  category: 'web-attacks',
  description: 'Detects suspicious process execution by web server processes (IIS, Apache, Nginx, Tomcat) that may indicate exploitation of a public-facing web application vulnerability.',
  tacticId: 'TA0001', tacticName: 'Initial Access',
  techniqueId: 'T1190', techniqueName: 'Exploit Public-Facing Application',
  logsource: { product: 'windows', category: 'process_creation' },
  sigmaYaml: `title: Exploit Against Public-Facing Application
id: c3d4e5f6-a7b8-9012-cdef-123456789012
status: stable
description: Detects command execution spawned by web server processes indicating webshell or exploit activity
author: SOC Platform
date: 2024/03/10
logsource:
    category: process_creation
    product: windows
detection:
    selection_webserver:
        ParentImage|endswith:
            - '\\\\w3wp.exe'
            - '\\\\httpd.exe'
            - '\\\\nginx.exe'
            - '\\\\tomcat*.exe'
            - '\\\\java.exe'
            - '\\\\node.exe'
            - '\\\\php-cgi.exe'
    selection_suspicious:
        Image|endswith:
            - '\\\\cmd.exe'
            - '\\\\powershell.exe'
            - '\\\\pwsh.exe'
            - '\\\\whoami.exe'
            - '\\\\net.exe'
            - '\\\\net1.exe'
            - '\\\\nltest.exe'
            - '\\\\certutil.exe'
    condition: selection_webserver and selection_suspicious
falsepositives:
    - Legitimate CGI scripts
    - Health check scripts
    - Deployment automation
level: critical
tags:
    - attack.initial_access
    - attack.t1190`,
  detectionExplanation: 'Web servers should rarely spawn system utilities like cmd.exe or powershell.exe. When they do, it strongly suggests an attacker has exploited a vulnerability (e.g., RCE, SQL injection, deserialization) and is executing commands through a webshell or direct exploit payload. This is a high-fidelity detection.',
  requiredLogs: ['Sysmon Event ID 1 with parent process tracking', 'Windows Security 4688'],
  logConfig: 'Ensure Sysmon is deployed on all web servers. Enable command line auditing.',
  falsePositives: ['Legitimate PHP/CGI scripts that invoke system commands', 'IIS application pool recycling scripts', 'DevOps deployment pipelines running on web servers'],
  tuning: 'Create a baseline of legitimate child processes for each web server. Allowlist specific known-good scripts. Add file hash exclusions for verified deployment tools.',
  commonErrors: ['Java-based applications may use java.exe as parent which is too broad without additional filtering', 'Containerized services may have different parent process chains'],
  responseActions: ['IMMEDIATELY isolate the web server from the network', 'Capture memory dump of the web server process', 'Examine web server access logs for exploit patterns (unusual POST requests, encoded payloads)', 'Check for webshell files in web root directories', 'Review all files modified in the last 24-48 hours', 'Engage incident response team', 'Patch the vulnerability'],
  threatIntel: { cves: ['CVE-2024-3400', 'CVE-2024-1709', 'CVE-2023-46805', 'CVE-2023-22515'], cisaKev: true, campaigns: ['Volt Typhoon'], iocs: [] },
  references: ['https://attack.mitre.org/techniques/T1190/', 'https://www.cisa.gov/known-exploited-vulnerabilities-catalog']
},
{
  id: 'SR-0004', title: 'VPN/Remote Access Brute Force or Unusual Login',
  status: 'stable', severity: 'high', author: 'SOC Platform', date: '2024-05-01', modified: '2024-11-20',
  category: 'brute-force',
  description: 'Detects multiple failed authentication attempts against VPN/remote access services followed by a successful login, indicating potential credential stuffing or brute force against external remote services.',
  tacticId: 'TA0001', tacticName: 'Initial Access',
  techniqueId: 'T1133', techniqueName: 'External Remote Services',
  logsource: { product: 'windows', service: 'security' },
  sigmaYaml: `title: VPN/Remote Access Brute Force or Unusual Login
id: d4e5f6a7-b8c9-0123-defa-234567890123
status: stable
description: Detects brute force patterns against remote access services
author: SOC Platform
date: 2024/05/01
logsource:
    product: windows
    service: security
detection:
    selection_failed:
        EventID: 4625
        LogonType:
            - 3
            - 10
    selection_success:
        EventID: 4624
        LogonType:
            - 3
            - 10
    filter_local:
        IpAddress|startswith:
            - '10.'
            - '172.16.'
            - '192.168.'
            - '127.'
    condition: selection_failed and not filter_local
    # Note: Aggregate by source IP - count > 10 in 5 minutes
falsepositives:
    - Misconfigured VPN clients
    - Password rotation periods
level: high
tags:
    - attack.initial_access
    - attack.t1133`,
  detectionExplanation: 'Monitors Windows Security logs for repeated failed logon attempts (Event ID 4625) with network logon types (Type 3 or 10) from external IP addresses. This pattern is characteristic of credential stuffing or brute force attacks against VPN gateways, RDP, and other remote access services.',
  requiredLogs: ['Windows Security Event ID 4624 (Successful Logon)', 'Windows Security Event ID 4625 (Failed Logon)', 'VPN gateway authentication logs'],
  logConfig: 'Enable logon auditing via GPO: Audit logon events (Success and Failure). Forward VPN appliance logs to SIEM.',
  falsePositives: ['Users with expired passwords attempting to connect', 'VPN client auto-reconnect mechanisms', 'Service accounts with misconfigured credentials'],
  tuning: 'Set threshold to 10+ failures in 5 minutes from same source IP. Exclude known VPN concentrator IPs. Create geo-based alerts for logins from unusual countries.',
  commonErrors: ['VPN appliance logs not forwarded to SIEM', 'NAT may mask true source IP', 'Time zone differences causing correlation issues'],
  responseActions: ['Block the source IP at firewall/VPN gateway', 'Reset credentials for targeted accounts', 'Enable MFA if not already enforced', 'Check if successful login followed the brute force pattern', 'Review VPN logs for data transfer anomalies post-authentication'],
  threatIntel: { cves: ['CVE-2023-4966', 'CVE-2023-46805'], cisaKev: true, campaigns: ['Volt Typhoon', 'ALPHV/BlackCat Ransomware'], iocs: [] },
  references: ['https://attack.mitre.org/techniques/T1133/']
},
{
  id: 'SR-0005', title: 'Suspicious Valid Account Usage - Off-Hours Login',
  status: 'test', severity: 'medium', author: 'SOC Platform', date: '2024-08-10', modified: '2024-12-01',
  category: 'insider-threat',
  description: 'Detects successful interactive logons occurring outside of normal business hours which may indicate use of compromised valid accounts by threat actors operating in different time zones.',
  tacticId: 'TA0001', tacticName: 'Initial Access',
  techniqueId: 'T1078', techniqueName: 'Valid Accounts',
  logsource: { product: 'windows', service: 'security' },
  sigmaYaml: `title: Suspicious Valid Account Usage - Off-Hours Login
id: e5f6a7b8-c9d0-1234-efab-345678901234
status: test
description: Detects interactive logons outside business hours
author: SOC Platform
date: 2024/08/10
logsource:
    product: windows
    service: security
detection:
    selection:
        EventID: 4624
        LogonType:
            - 2
            - 10
            - 11
    filter_service_accounts:
        TargetUserName|startswith:
            - 'svc_'
            - 'SVC_'
            - 'SYSTEM'
    filter_machine_accounts:
        TargetUserName|endswith: '$'
    condition: selection and not filter_service_accounts and not filter_machine_accounts
    # Note: Time-based filter for off-hours (before 6AM or after 10PM local time)
falsepositives:
    - On-call staff working late
    - Remote employees in different time zones
    - Planned maintenance windows
level: medium
tags:
    - attack.initial_access
    - attack.t1078`,
  detectionExplanation: 'Identifies interactive user logins (not service or machine accounts) occurring outside typical business hours. Attackers using compromised credentials often operate outside victim\'s normal working hours to reduce the chance of detection. This detection should be tuned per organization\'s working patterns.',
  requiredLogs: ['Windows Security Event ID 4624'],
  logConfig: 'Enable success audit for logon events. Ensure NTP synchronization across all endpoints.',
  falsePositives: ['After-hours maintenance by IT staff', 'Employees in remote time zones', 'Emergency response activities'],
  tuning: 'Define business hours per user group or department. Exclude known on-call staff. Consider using ML-based anomaly detection for user login patterns instead of static time windows.',
  commonErrors: ['Time zone not properly normalized in SIEM', 'Service accounts not properly filtered causing noise'],
  responseActions: ['Contact the user to verify the logon', 'Check source IP and geolocation', 'Review session activity for anomalous behavior', 'Check for concurrent sessions from different locations'],
  threatIntel: { cves: [], cisaKev: false, campaigns: ['Scattered Spider', 'Volt Typhoon'], iocs: [] },
  references: ['https://attack.mitre.org/techniques/T1078/']
},

// ═══════════════════════════════════════════════════════════════
// EXECUTION (TA0002)
// ═══════════════════════════════════════════════════════════════
{
  id: 'SR-0006', title: 'Suspicious PowerShell Execution with Encoded Command',
  status: 'stable', severity: 'high', author: 'SOC Platform', date: '2024-02-15', modified: '2024-12-10',
  category: 'execution',
  description: 'Detects PowerShell execution using encoded commands (-EncodedCommand, -enc), download cradles, or other obfuscation techniques commonly used by malware and attack frameworks.',
  tacticId: 'TA0002', tacticName: 'Execution',
  techniqueId: 'T1059.001', techniqueName: 'PowerShell',
  logsource: { product: 'windows', category: 'process_creation' },
  sigmaYaml: `title: Suspicious PowerShell Execution with Encoded Command
id: f6a7b8c9-d0e1-2345-fabc-456789012345
status: stable
description: Detects PowerShell invocations using encoded commands or download cradles
author: SOC Platform
date: 2024/02/15
logsource:
    category: process_creation
    product: windows
detection:
    selection_ps:
        Image|endswith:
            - '\\\\powershell.exe'
            - '\\\\pwsh.exe'
    selection_encoded:
        CommandLine|contains:
            - '-enc '
            - '-EncodedCommand'
            - '-e JAB'
            - '-e SQB'
            - '-e aQB'
            - 'FromBase64String'
    selection_download:
        CommandLine|contains:
            - 'DownloadString'
            - 'DownloadFile'
            - 'Invoke-WebRequest'
            - 'IWR '
            - 'wget '
            - 'curl '
            - 'Net.WebClient'
            - 'Start-BitsTransfer'
    selection_bypass:
        CommandLine|contains:
            - '-ExecutionPolicy Bypass'
            - '-ep bypass'
            - '-nop'
            - '-NoProfile'
            - '-w hidden'
            - '-WindowStyle Hidden'
    condition: selection_ps and (selection_encoded or selection_download or (selection_bypass | count() > 2))
falsepositives:
    - System administration scripts
    - SCCM/Intune deployment scripts
    - Legitimate software installers
level: high
tags:
    - attack.execution
    - attack.t1059.001`,
  detectionExplanation: 'PowerShell is one of the most abused tools by threat actors. This rule detects three key malicious patterns: (1) Base64-encoded commands used to obfuscate payloads, (2) Download cradles that fetch malicious payloads from the internet, (3) Execution policy bypasses combined with hidden windows indicating stealth. Legitimate admin scripts rarely need encoding or hidden execution.',
  requiredLogs: ['Sysmon Event ID 1', 'PowerShell Script Block Logging (Event ID 4104)', 'PowerShell Module Logging'],
  logConfig: 'Enable PowerShell Script Block Logging via GPO: Administrative Templates > Windows Components > PowerShell > Turn on Script Block Logging. Also enable Module Logging and Transcription.',
  falsePositives: ['SCCM/Endpoint Manager deploying software via encoded PowerShell', 'Third-party monitoring tools using encoded commands', 'DevOps automation scripts'],
  tuning: 'Allowlist known SCCM task sequences by parent process. Hash-based exclusions for verified automation. Consider creating separate rules for download cradles vs encoded commands.',
  commonErrors: ['PowerShell 7 (pwsh.exe) not included in detection', 'Case sensitivity in command line matching', 'PowerShell called via cmd.exe wrapping - parent process may be cmd.exe not email client'],
  responseActions: ['Decode the Base64 command and analyze the payload', 'Check network logs for outbound connections to download URLs', 'Contain the endpoint', 'Search for the decoded payload IOCs across the environment', 'Review PowerShell transcription logs for full script content'],
  threatIntel: { cves: [], cisaKev: false, campaigns: ['Volt Typhoon', 'LockBit 3.0', 'Midnight Blizzard'], iocs: [] },
  references: ['https://attack.mitre.org/techniques/T1059/001/', 'https://docs.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_logging']
},
{
  id: 'SR-0007', title: 'Suspicious Windows Command Shell Activity',
  status: 'stable', severity: 'medium', author: 'SOC Platform', date: '2024-04-20', modified: '2024-10-15',
  category: 'execution',
  description: 'Detects suspicious usage of cmd.exe with command chaining, file operations, or reconnaissance commands that indicate post-exploitation or living-off-the-land activity.',
  tacticId: 'TA0002', tacticName: 'Execution',
  techniqueId: 'T1059.003', techniqueName: 'Windows Command Shell',
  logsource: { product: 'windows', category: 'process_creation' },
  sigmaYaml: `title: Suspicious Windows Command Shell Activity
id: 01a2b3c4-d5e6-7890-1234-567890abcdef
status: stable
description: Detects suspicious cmd.exe usage with recon or staging commands
author: SOC Platform
date: 2024/04/20
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image|endswith: '\\\\cmd.exe'
    selection_recon:
        CommandLine|contains:
            - 'whoami'
            - 'ipconfig /all'
            - 'net user'
            - 'net group'
            - 'systeminfo'
            - 'tasklist'
            - 'netstat -an'
            - 'nltest /dclist'
            - 'dsquery'
            - 'net localgroup administrators'
    selection_suspicious:
        CommandLine|contains:
            - '| findstr'
            - '> C:\\\\'
            - '>> C:\\\\'
            - 'echo ' 
            - 'type '
            - 'copy '
        CommandLine|contains:
            - '\\\\Temp\\\\'
            - '\\\\ProgramData\\\\'
    condition: selection and (selection_recon or selection_suspicious)
falsepositives:
    - IT administrators performing manual troubleshooting
    - Login scripts
    - Inventory scanning tools
level: medium
tags:
    - attack.execution
    - attack.t1059.003`,
  detectionExplanation: 'Detects cmd.exe being used for reconnaissance commands (whoami, net user, systeminfo) or suspicious file operations to staging directories. These patterns are consistent with post-exploitation behavior where attackers use built-in Windows commands to enumerate the environment.',
  requiredLogs: ['Sysmon Event ID 1', 'Windows Security 4688 with command line'],
  logConfig: 'Enable command line auditing in Windows Security policy.',
  falsePositives: ['System administrators troubleshooting', 'Inventory/asset management scripts', 'GPO logon scripts running system commands'],
  tuning: 'Correlate with user context - admin users running these commands may be normal. Focus on non-admin users or automated/rapid execution of multiple recon commands in sequence.',
  commonErrors: ['Too many false positives without proper user context filtering', 'Logon scripts generating baseline noise'],
  responseActions: ['Investigate the user account running the commands', 'Check for preceding suspicious login activity', 'Review full command history from the session', 'Determine if this is part of a larger attack chain'],
  threatIntel: { cves: [], cisaKev: false, campaigns: ['Volt Typhoon'], iocs: [] },
  references: ['https://attack.mitre.org/techniques/T1059/003/']
},
{
  id: 'SR-0008', title: 'WMI Process Creation for Remote Execution',
  status: 'stable', severity: 'high', author: 'SOC Platform', date: '2024-03-25', modified: '2024-11-05',
  category: 'execution',
  description: 'Detects use of Windows Management Instrumentation (WMI) for remote process creation, a technique used for lateral movement and remote code execution without deploying additional tools.',
  tacticId: 'TA0002', tacticName: 'Execution',
  techniqueId: 'T1047', techniqueName: 'Windows Management Instrumentation',
  logsource: { product: 'windows', category: 'process_creation' },
  sigmaYaml: `title: WMI Process Creation for Remote Execution
id: 12345678-abcd-ef01-2345-678901234567
status: stable
description: Detects WMI-based remote process creation
author: SOC Platform
date: 2024/03/25
logsource:
    category: process_creation
    product: windows
detection:
    selection_wmic:
        Image|endswith: '\\\\wmic.exe'
        CommandLine|contains:
            - 'process call create'
            - '/node:'
    selection_wmiprvse:
        ParentImage|endswith: '\\\\WmiPrvSE.exe'
        Image|endswith:
            - '\\\\cmd.exe'
            - '\\\\powershell.exe'
            - '\\\\pwsh.exe'
    condition: selection_wmic or selection_wmiprvse
falsepositives:
    - SCCM remote management
    - Legitimate WMI-based monitoring tools
level: high
tags:
    - attack.execution
    - attack.t1047`,
  detectionExplanation: 'WMI allows remote command execution via the "process call create" method or by targeting remote nodes with /node: parameter. When WmiPrvSE.exe spawns command interpreters, it indicates WMI-executed commands. Attackers favor WMI because it leaves fewer artifacts than PSExec or remote services.',
  requiredLogs: ['Sysmon Event ID 1', 'WMI Operational Log (Microsoft-Windows-WMI-Activity/Operational)'],
  logConfig: 'Enable WMI trace logging. Deploy Sysmon with WMI event tracking (Event IDs 19, 20, 21).',
  falsePositives: ['SCCM client operations', 'Enterprise monitoring tools using WMI queries', 'Automated WMI-based inventory scripts'],
  tuning: 'Allowlist known SCCM servers and monitoring tools by source hostname. Focus on WMI commands targeting non-server endpoints.',
  commonErrors: ['WMI operational logs not enabled by default', 'High volume of legitimate WMI traffic in SCCM environments'],
  responseActions: ['Identify the source system initiating the WMI call', 'Check authentication logs for the account used', 'Examine what command was executed remotely', 'Look for lateral movement patterns from the source'],
  threatIntel: { cves: [], cisaKev: false, campaigns: ['Volt Typhoon', 'LockBit 3.0'], iocs: [] },
  references: ['https://attack.mitre.org/techniques/T1047/']
},
{
  id: 'SR-0009', title: 'Malicious Scheduled Task Creation',
  status: 'stable', severity: 'high', author: 'SOC Platform', date: '2024-01-30', modified: '2024-12-01',
  category: 'persistence',
  description: 'Detects creation of scheduled tasks via schtasks.exe with suspicious parameters such as SYSTEM-level execution, remote task creation, or tasks pointing to suspicious file paths.',
  tacticId: 'TA0002', tacticName: 'Execution',
  techniqueId: 'T1053.005', techniqueName: 'Scheduled Task',
  logsource: { product: 'windows', category: 'process_creation' },
  sigmaYaml: `title: Malicious Scheduled Task Creation
id: 23456789-bcde-f012-3456-789012345678
status: stable
description: Detects suspicious scheduled task creation using schtasks.exe
author: SOC Platform
date: 2024/01/30
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image|endswith: '\\\\schtasks.exe'
        CommandLine|contains: '/create'
    selection_suspicious:
        CommandLine|contains:
            - '/sc once'
            - '/sc minute'
            - '/ru SYSTEM'
            - '/ru "SYSTEM"'
            - '\\\\AppData\\\\'
            - '\\\\Temp\\\\'
            - '\\\\ProgramData\\\\'
            - 'powershell'
            - 'cmd.exe /c'
            - 'mshta'
            - 'regsvr32'
            - 'rundll32'
            - '/s '
    condition: selection and selection_suspicious
falsepositives:
    - Software installation creating legitimate scheduled tasks
    - System maintenance tasks created by administrators
level: high
tags:
    - attack.execution
    - attack.t1053.005
    - attack.persistence
    - attack.t1053.005`,
  detectionExplanation: 'Scheduled tasks are used by attackers for both execution and persistence. This rule focuses on suspicious patterns: tasks running as SYSTEM, one-time or frequent triggers, tasks executing from temporary directories, or tasks that launch script interpreters. These patterns distinguish malicious from legitimate scheduled tasks.',
  requiredLogs: ['Sysmon Event ID 1', 'Windows Security Event ID 4698 (Scheduled Task Created)', 'Task Scheduler Operational Log'],
  logConfig: 'Enable "Audit Other Object Access Events" to capture Event ID 4698. Enable Task Scheduler operational log.',
  falsePositives: ['Software updates creating temporary tasks', 'GPO-deployed scheduled tasks', 'System Center maintenance tasks'],
  tuning: 'Allowlist known software update mechanisms (e.g., Adobe, Chrome updaters). Focus on tasks created via command line rather than GUI or GPO.',
  commonErrors: ['Event ID 4698 not enabled for auditing', 'XML vs command line task creation may have different logging behavior'],
  responseActions: ['Examine the scheduled task configuration', 'Check the binary/script the task is configured to execute', 'Determine who created the task and from where', 'Delete the malicious scheduled task', 'Search for similar tasks across all endpoints'],
  threatIntel: { cves: [], cisaKev: false, campaigns: ['LockBit 3.0', 'ALPHV/BlackCat Ransomware'], iocs: [] },
  references: ['https://attack.mitre.org/techniques/T1053/005/']
},
{
  id: 'SR-0010', title: 'Malicious File Execution - Double Extension or Suspicious Location',
  status: 'stable', severity: 'high', author: 'SOC Platform', date: '2024-05-12', modified: '2024-10-20',
  category: 'execution',
  description: 'Detects execution of files with double extensions (e.g., .pdf.exe) or from suspicious directories commonly used for staging malware, indicating user execution of a malicious file.',
  tacticId: 'TA0002', tacticName: 'Execution',
  techniqueId: 'T1204.002', techniqueName: 'Malicious File',
  logsource: { product: 'windows', category: 'process_creation' },
  sigmaYaml: `title: Malicious File Execution - Double Extension or Suspicious Location
id: 34567890-cdef-0123-4567-890123456789
status: stable
description: Detects execution of files with double extensions or from suspicious staging directories
author: SOC Platform
date: 2024/05/12
logsource:
    category: process_creation
    product: windows
detection:
    selection_double_ext:
        Image|endswith:
            - '.pdf.exe'
            - '.doc.exe'
            - '.xls.exe'
            - '.jpg.exe'
            - '.png.exe'
            - '.txt.exe'
            - '.docx.scr'
            - '.xlsx.scr'
    selection_staging:
        Image|contains:
            - '\\\\Users\\\\Public\\\\'
            - '\\\\PerfLogs\\\\'
            - '\\\\Windows\\\\Temp\\\\'
            - '\\\\Recycle'
        Image|endswith:
            - '.exe'
            - '.scr'
            - '.bat'
            - '.cmd'
    condition: selection_double_ext or selection_staging
falsepositives:
    - Poorly named legitimate files
    - Temporary installer files
level: high
tags:
    - attack.execution
    - attack.t1204.002`,
  detectionExplanation: 'Files with double extensions trick users into thinking they are opening a document when they are actually executing malware. Additionally, legitimate software rarely executes from staging directories like Public folders, PerfLogs, or the Recycle Bin. Both patterns are strong indicators of malicious user execution.',
  requiredLogs: ['Sysmon Event ID 1', 'Windows Security 4688'],
  logConfig: 'Standard process creation logging with full image path.',
  falsePositives: ['Legitimate portable applications stored in Public folders', 'Temp files from software installers'],
  tuning: 'Add hash-based allowlists for known legitimate portable apps. Exclude specific installer paths if needed.',
  commonErrors: ['File extensions may be hidden in Windows Explorer leading to user confusion', 'Short path names (8.3) may obscure the true filename'],
  responseActions: ['Quarantine the suspicious file', 'Submit to sandbox for detonation analysis', 'Check the file hash against VirusTotal/threat intelligence', 'Identify how the file arrived (email, USB, download)', 'Search for the file hash across all endpoints'],
  threatIntel: { cves: [], cisaKev: false, campaigns: [], iocs: [] },
  references: ['https://attack.mitre.org/techniques/T1204/002/']
},

// ═══════════════════════════════════════════════════════════════
// PERSISTENCE (TA0003)
// ═══════════════════════════════════════════════════════════════
{
  id: 'SR-0011', title: 'Registry Run Key Modification for Persistence',
  status: 'stable', severity: 'high', author: 'SOC Platform', date: '2024-01-10', modified: '2024-11-25',
  category: 'persistence',
  description: 'Detects modifications to Windows Registry Run/RunOnce keys, a classic persistence mechanism used by malware to ensure execution survives system reboots.',
  tacticId: 'TA0003', tacticName: 'Persistence',
  techniqueId: 'T1547.001', techniqueName: 'Registry Run Keys / Startup Folder',
  logsource: { product: 'windows', category: 'registry_set' },
  sigmaYaml: `title: Registry Run Key Modification for Persistence
id: 45678901-defa-1234-5678-901234567890
status: stable
description: Detects suspicious modifications to Registry Run keys
author: SOC Platform
date: 2024/01/10
logsource:
    category: registry_set
    product: windows
detection:
    selection:
        TargetObject|contains:
            - '\\\\SOFTWARE\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\Run'
            - '\\\\SOFTWARE\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\RunOnce'
            - '\\\\SOFTWARE\\\\WOW6432Node\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\Run'
    filter_legitimate:
        Details|contains:
            - '\\\\Program Files\\\\'
            - '\\\\Program Files (x86)\\\\'
            - 'Microsoft\\\\OneDrive'
            - 'SecurityHealth'
    condition: selection and not filter_legitimate
falsepositives:
    - Legitimate software installations
    - System configuration changes
level: high
tags:
    - attack.persistence
    - attack.t1547.001`,
  detectionExplanation: 'Registry Run keys cause programs to execute every time a user logs on. Malware commonly adds entries pointing to malicious executables in user-writable directories (AppData, Temp, ProgramData). This rule filters out entries pointing to Program Files (where legitimate software typically installs) and focuses on suspicious paths.',
  requiredLogs: ['Sysmon Event ID 13 (Registry Value Set)', 'Windows Security Event ID 4657 (Registry Value Modified)'],
  logConfig: 'Deploy Sysmon with registry monitoring enabled for Run keys. Alternatively, enable registry auditing via SACL on the Run keys.',
  falsePositives: ['New software installation adding startup entries', 'User-installed applications configuring auto-start', 'Corporate tools added to startup'],
  tuning: 'Maintain an allowlist of approved startup programs. Alert specifically on entries pointing to Temp, AppData, ProgramData, or user-writable directories.',
  commonErrors: ['Missing WOW6432Node registry path for 32-bit applications', 'Registry event logging not configured in Sysmon'],
  responseActions: ['Examine the registry value to identify the executable', 'Analyze the referenced executable (hash, signature, behavior)', 'Check when the registry modification occurred vs. when the executable was dropped', 'Remove the malicious registry entry', 'Search for the executable hash across all endpoints'],
  threatIntel: { cves: [], cisaKev: false, campaigns: ['ALPHV/BlackCat Ransomware', 'LockBit 3.0'], iocs: [] },
  references: ['https://attack.mitre.org/techniques/T1547/001/']
},
{
  id: 'SR-0012', title: 'Suspicious Local Account Creation',
  status: 'stable', severity: 'high', author: 'SOC Platform', date: '2024-02-28', modified: '2024-12-10',
  category: 'persistence',
  description: 'Detects creation of local user accounts via net.exe or net1.exe, especially when added to privileged groups, which may indicate an attacker establishing persistence through backdoor accounts.',
  tacticId: 'TA0003', tacticName: 'Persistence',
  techniqueId: 'T1136.001', techniqueName: 'Local Account',
  logsource: { product: 'windows', service: 'security' },
  sigmaYaml: `title: Suspicious Local Account Creation
id: 56789012-efab-2345-6789-012345678901
status: stable
description: Detects local account creation and privilege assignment
author: SOC Platform
date: 2024/02/28
logsource:
    product: windows
    service: security
detection:
    selection_created:
        EventID: 4720
    selection_group_add:
        EventID:
            - 4732
            - 4728
        TargetUserName|contains:
            - 'Administrators'
            - 'Remote Desktop Users'
            - 'Remote Management Users'
    condition: selection_created or selection_group_add
falsepositives:
    - Legitimate account provisioning
    - IT helpdesk creating local admin accounts
level: high
tags:
    - attack.persistence
    - attack.t1136.001`,
  detectionExplanation: 'Monitors for new local account creation (Event ID 4720) and addition of accounts to privileged groups like Administrators or Remote Desktop Users (Event IDs 4732/4728). Attackers create backdoor accounts to maintain persistent access even if their primary access vector is discovered and remediated.',
  requiredLogs: ['Windows Security Event ID 4720 (User Account Created)', 'Windows Security Event ID 4732 (Member Added to Local Group)', 'Windows Security Event ID 4728 (Member Added to Global Group)'],
  logConfig: 'Enable Account Management auditing via GPO: Audit User Account Management (Success).',
  falsePositives: ['IT provisioning new local accounts', 'Automated deployment creating service accounts', 'Break-glass account creation during emergencies'],
  tuning: 'Alert on account creation on servers and workstations where new accounts are unexpected. Correlate with change management tickets.',
  commonErrors: ['Not monitoring both net.exe and net1.exe', 'Event ID 4732 vs 4728 confusion (local vs global groups)'],
  responseActions: ['Verify the account creation was authorized', 'Check the Creator Process Name and Creator SID', 'Disable the suspicious account immediately', 'Review what actions were taken with the new account', 'Check for similar account creation across other systems'],
  threatIntel: { cves: [], cisaKev: false, campaigns: ['Scattered Spider', 'ALPHV/BlackCat Ransomware'], iocs: [] },
  references: ['https://attack.mitre.org/techniques/T1136/001/']
},
{
  id: 'SR-0013', title: 'Malicious Windows Service Installation',
  status: 'stable', severity: 'high', author: 'SOC Platform', date: '2024-04-05', modified: '2024-11-20',
  category: 'persistence',
  description: 'Detects creation of new Windows services with suspicious properties such as binaries in temp directories, services running cmd.exe/powershell.exe, or services with suspicious names.',
  tacticId: 'TA0003', tacticName: 'Persistence',
  techniqueId: 'T1543.003', techniqueName: 'Windows Service',
  logsource: { product: 'windows', service: 'system' },
  sigmaYaml: `title: Malicious Windows Service Installation
id: 67890123-fabc-3456-7890-123456789012
status: stable
description: Detects suspicious Windows service creation
author: SOC Platform
date: 2024/04/05
logsource:
    product: windows
    service: system
detection:
    selection:
        EventID: 7045
    selection_suspicious_path:
        ImagePath|contains:
            - '\\\\Temp\\\\'
            - '\\\\AppData\\\\'
            - '\\\\ProgramData\\\\'
            - '\\\\Users\\\\Public\\\\'
            - '\\\\PerfLogs\\\\'
    selection_suspicious_cmd:
        ImagePath|contains:
            - 'cmd.exe'
            - 'powershell'
            - 'mshta'
            - 'regsvr32'
            - 'rundll32'
            - 'wscript'
            - 'cscript'
    condition: selection and (selection_suspicious_path or selection_suspicious_cmd)
falsepositives:
    - Poorly packaged legitimate software
    - Third-party service installers
level: high
tags:
    - attack.persistence
    - attack.t1543.003`,
  detectionExplanation: 'Windows services run with SYSTEM privileges and persist across reboots, making them an attractive persistence mechanism. This rule detects services with binaries in writeable directories (Temp, AppData, ProgramData) or services that launch interpreters (cmd, PowerShell), both of which are uncommon for legitimate services.',
  requiredLogs: ['System Event ID 7045 (Service Installed)', 'Sysmon Event ID 1 for sc.exe execution'],
  logConfig: 'System event log captures service installations by default. Ensure log retention is sufficient.',
  falsePositives: ['Third-party software installing services from non-standard paths', 'Penetration testing tools during authorized assessments'],
  tuning: 'Build a baseline of expected services. Alert on any new service installation on critical servers. Allowlist known third-party service paths.',
  commonErrors: ['Service binary path may contain arguments that need separate parsing', 'Binary path with spaces may be exploited for unquoted service path attacks'],
  responseActions: ['Examine the service binary path and file properties', 'Check the service account and permissions', 'Stop and disable the suspicious service', 'Analyze the service binary in a sandbox', 'Search for the binary hash across all endpoints'],
  threatIntel: { cves: [], cisaKev: false, campaigns: ['LockBit 3.0'], iocs: [] },
  references: ['https://attack.mitre.org/techniques/T1543/003/']
},
{
  id: 'SR-0014', title: 'WMI Event Subscription Persistence',
  status: 'stable', severity: 'high', author: 'SOC Platform', date: '2024-06-01', modified: '2024-12-01',
  category: 'persistence',
  description: 'Detects creation of WMI event subscriptions (consumers, filters, bindings) used as a fileless persistence mechanism that survives reboots and is difficult to detect without proper logging.',
  tacticId: 'TA0003', tacticName: 'Persistence',
  techniqueId: 'T1546.003', techniqueName: 'WMI Event Subscription',
  logsource: { product: 'windows', category: 'wmi_event' },
  sigmaYaml: `title: WMI Event Subscription Persistence
id: 78901234-abcd-4567-8901-234567890123
status: stable
description: Detects creation of WMI event subscriptions for persistence
author: SOC Platform
date: 2024/06/01
logsource:
    category: wmi_event
    product: windows
detection:
    selection_consumer:
        EventType: WmiConsumerCreation
    selection_filter:
        EventType: WmiFilterCreation
    selection_binding:
        EventType: WmiBindingCreation
    selection_sysmon:
        EventID:
            - 19
            - 20
            - 21
    condition: selection_consumer or selection_filter or selection_binding or selection_sysmon
falsepositives:
    - Legitimate WMI-based monitoring solutions
    - Dell/HP hardware management agents
level: high
tags:
    - attack.persistence
    - attack.t1546.003`,
  detectionExplanation: 'WMI event subscriptions consist of three components: a filter (trigger condition), a consumer (action to execute), and a binding (links filter to consumer). When combined, they create a persistent trigger that can execute commands when specific conditions are met (e.g., on system startup). This is a powerful fileless persistence technique favored by APT groups.',
  requiredLogs: ['Sysmon Event IDs 19, 20, 21 (WMI events)', 'WMI Operational Log'],
  logConfig: 'Deploy Sysmon with WMI event monitoring. The SwiftOnSecurity configuration includes these by default.',
  falsePositives: ['Dell DRAC/HP iLO management agents', 'Enterprise monitoring using WMI subscriptions', 'Some antivirus products'],
  tuning: 'Baseline existing WMI subscriptions before enabling detection. Allowlist known management tool WMI consumers by name.',
  commonErrors: ['WMI events not captured without Sysmon', 'Legitimate WMI subscriptions creating baseline noise'],
  responseActions: ['List all WMI subscriptions: Get-WMIObject -Namespace root\\subscription -Class __EventConsumer', 'Identify the command or script bound to the subscription', 'Remove malicious WMI objects', 'Investigate how the WMI subscription was created'],
  threatIntel: { cves: [], cisaKev: false, campaigns: ['Midnight Blizzard'], iocs: [] },
  references: ['https://attack.mitre.org/techniques/T1546/003/']
},
{
  id: 'SR-0015', title: 'Startup Folder Persistence',
  status: 'stable', severity: 'medium', author: 'SOC Platform', date: '2024-07-15', modified: '2024-11-10',
  category: 'persistence',
  description: 'Detects creation of files in Windows Startup folders, a simple but effective persistence mechanism. Files placed here execute automatically when the user logs on.',
  tacticId: 'TA0003', tacticName: 'Persistence',
  techniqueId: 'T1547.001', techniqueName: 'Registry Run Keys / Startup Folder',
  logsource: { product: 'windows', category: 'file_event' },
  sigmaYaml: `title: Startup Folder Persistence
id: 89012345-bcde-5678-9012-345678901234
status: stable
description: Detects file creation in Windows Startup folders
author: SOC Platform
date: 2024/07/15
logsource:
    category: file_event
    product: windows
detection:
    selection:
        TargetFilename|contains:
            - '\\\\Start Menu\\\\Programs\\\\Startup\\\\'
            - '\\\\ProgramData\\\\Microsoft\\\\Windows\\\\Start Menu\\\\Programs\\\\StartUp\\\\'
    filter_extensions:
        TargetFilename|endswith:
            - '.ini'
            - '.desktop.ini'
    condition: selection and not filter_extensions
falsepositives:
    - Legitimate applications adding startup shortcuts
    - IT deploying startup scripts
level: medium
tags:
    - attack.persistence
    - attack.t1547.001`,
  detectionExplanation: 'The Startup folder is one of the simplest persistence mechanisms in Windows. Any executable, script, or shortcut placed here runs when the associated user (or all users for the common folder) logs on. Despite being well-known, it remains effective because many organizations lack monitoring for file creation events in these directories.',
  requiredLogs: ['Sysmon Event ID 11 (File Creation)'],
  logConfig: 'Configure Sysmon to monitor file creation events in Startup folders.',
  falsePositives: ['Legitimate application shortcuts', 'IT-deployed startup scripts via GPO'],
  tuning: 'Allowlist known startup shortcuts by file hash. Focus on executables and scripts rather than .lnk files pointing to known applications.',
  commonErrors: ['desktop.ini not filtered causing false positives', 'Both per-user and all-users Startup paths must be monitored'],
  responseActions: ['Examine the file placed in Startup folder', 'Check the file timestamp and creating process', 'Remove the malicious file', 'Analyze the file in a sandbox'],
  threatIntel: { cves: [], cisaKev: false, campaigns: [], iocs: [] },
  references: ['https://attack.mitre.org/techniques/T1547/001/']
},

// ═══════════════════════════════════════════════════════════════
// PRIVILEGE ESCALATION (TA0004)
// ═══════════════════════════════════════════════════════════════
{
  id: 'SR-0016', title: 'UAC Bypass via Event Viewer (mscfile)',
  status: 'stable', severity: 'high', author: 'SOC Platform', date: '2024-03-20', modified: '2024-10-15',
  category: 'privilege-escalation',
  description: 'Detects UAC bypass technique that abuses the Event Viewer (eventvwr.exe) auto-elevation and the mscfile registry hijack to execute arbitrary commands with elevated privileges.',
  tacticId: 'TA0004', tacticName: 'Privilege Escalation',
  techniqueId: 'T1548.002', techniqueName: 'Bypass User Account Control',
  logsource: { product: 'windows', category: 'process_creation' },
  sigmaYaml: `title: UAC Bypass via Event Viewer
id: 90123456-cdef-6789-0123-456789012345
status: stable
description: Detects UAC bypass using Event Viewer and mscfile registry hijack
author: SOC Platform
date: 2024/03/20
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        ParentImage|endswith: '\\\\eventvwr.exe'
    filter_mmc:
        Image|endswith: '\\\\mmc.exe'
    condition: selection and not filter_mmc
falsepositives:
    - Unknown
level: high
tags:
    - attack.privilege_escalation
    - attack.defense_evasion
    - attack.t1548.002`,
  detectionExplanation: 'The Event Viewer (eventvwr.exe) auto-elevates without a UAC prompt and looks up the mscfile handler in HKCU registry. By modifying this registry key to point to a malicious payload, attackers can execute arbitrary commands with elevated privileges without triggering UAC. The key indicator is eventvwr.exe spawning anything other than mmc.exe.',
  requiredLogs: ['Sysmon Event ID 1 with parent process tracking'],
  logConfig: 'Standard Sysmon process creation monitoring.',
  falsePositives: ['Extremely rare - this pattern has virtually no legitimate use cases'],
  tuning: 'This is a high-fidelity detection that requires minimal tuning. Consider expanding to detect other UAC bypass method parent processes like fodhelper.exe, computerdefaults.exe.',
  commonErrors: ['Not monitoring the registry modification that precedes the bypass'],
  responseActions: ['Check HKCU\\Software\\Classes\\mscfile\\shell\\open\\command for hijacking', 'Identify what payload was executed with elevated privileges', 'Investigate how the attacker gained initial access to the user context', 'Check for additional persistence mechanisms installed with elevated privileges'],
  threatIntel: { cves: [], cisaKev: false, campaigns: [], iocs: [] },
  references: ['https://attack.mitre.org/techniques/T1548/002/']
},
{
  id: 'SR-0017', title: 'Process Injection via CreateRemoteThread',
  status: 'stable', severity: 'high', author: 'SOC Platform', date: '2024-05-15', modified: '2024-11-30',
  category: 'privilege-escalation',
  description: 'Detects potential process injection by monitoring for CreateRemoteThread API calls targeting common injection targets like explorer.exe, svchost.exe, or other system processes.',
  tacticId: 'TA0004', tacticName: 'Privilege Escalation',
  techniqueId: 'T1055.001', techniqueName: 'Dynamic-link Library Injection',
  logsource: { product: 'windows', category: 'create_remote_thread' },
  sigmaYaml: `title: Process Injection via CreateRemoteThread
id: 01234567-defa-7890-1234-567890123456
status: stable
description: Detects CreateRemoteThread calls into sensitive processes
author: SOC Platform
date: 2024/05/15
logsource:
    category: create_remote_thread
    product: windows
detection:
    selection:
        TargetImage|endswith:
            - '\\\\explorer.exe'
            - '\\\\svchost.exe'
            - '\\\\lsass.exe'
            - '\\\\csrss.exe'
            - '\\\\winlogon.exe'
            - '\\\\services.exe'
    filter_legitimate:
        SourceImage|endswith:
            - '\\\\csrss.exe'
            - '\\\\lsass.exe'
            - '\\\\services.exe'
            - '\\\\svchost.exe'
    condition: selection and not filter_legitimate
falsepositives:
    - Some security products inject into processes for monitoring
    - Application compatibility shims
level: high
tags:
    - attack.privilege_escalation
    - attack.t1055.001`,
  detectionExplanation: 'CreateRemoteThread is a Windows API that allows one process to create a thread in another process address space. Attackers use this to inject malicious code (usually a DLL) into trusted system processes, inheriting their privileges and blending in with normal system activity. This rule monitors for remote thread creation targeting sensitive system processes.',
  requiredLogs: ['Sysmon Event ID 8 (CreateRemoteThread detected)'],
  logConfig: 'Configure Sysmon to capture Event ID 8. Note: this can be noisy - use filtering.',
  falsePositives: ['Antivirus/EDR solutions injecting monitoring hooks', 'Application compatibility layers', 'Some .NET runtime operations'],
  tuning: 'Allowlist known AV/EDR solutions by their source image path. Focus on injections from non-system processes into system processes.',
  commonErrors: ['Sysmon Event ID 8 not enabled by default in many configs', 'High false positive rate without proper source filtering'],
  responseActions: ['Identify the source process performing the injection', 'Capture memory dump of the target process', 'Check for malicious DLLs loaded in the target process', 'Investigate the source process for malware indicators'],
  threatIntel: { cves: [], cisaKev: false, campaigns: ['Midnight Blizzard'], iocs: [] },
  references: ['https://attack.mitre.org/techniques/T1055/001/']
},
{
  id: 'SR-0018', title: 'Token Impersonation/Theft Indicators',
  status: 'stable', severity: 'high', author: 'SOC Platform', date: '2024-06-20', modified: '2024-12-05',
  category: 'privilege-escalation',
  description: 'Detects indicators of access token manipulation by monitoring for tools and techniques commonly used to impersonate or steal tokens for privilege escalation.',
  tacticId: 'TA0004', tacticName: 'Privilege Escalation',
  techniqueId: 'T1134.001', techniqueName: 'Token Impersonation/Theft',
  logsource: { product: 'windows', category: 'process_creation' },
  sigmaYaml: `title: Token Impersonation/Theft Indicators
id: 12345678-efab-8901-2345-678901234567
status: stable
description: Detects tools and commands used for token manipulation
author: SOC Platform
date: 2024/06/20
logsource:
    category: process_creation
    product: windows
detection:
    selection_tools:
        Image|endswith:
            - '\\\\incognito.exe'
            - '\\\\JuicyPotato.exe'
            - '\\\\PrintSpoofer.exe'
            - '\\\\GodPotato.exe'
            - '\\\\SweetPotato.exe'
            - '\\\\RoguePotato.exe'
    selection_cmd:
        CommandLine|contains:
            - 'impersonate'
            - 'ImpersonateLoggedOnUser'
            - 'DuplicateTokenEx'
            - 'SetThreadToken'
            - 'CreateProcessWithToken'
    condition: selection_tools or selection_cmd
falsepositives:
    - Penetration testing with authorization
    - Security training environments
level: high
tags:
    - attack.privilege_escalation
    - attack.t1134.001`,
  detectionExplanation: 'Access token manipulation allows attackers to impersonate another user or escalate privileges by using another process\'s token. Common tools include the "Potato" family (JuicyPotato, SweetPotato, PrintSpoofer) which abuse Windows service accounts with SeImpersonatePrivilege. This rule detects both known tools and API calls associated with token manipulation.',
  requiredLogs: ['Sysmon Event ID 1', 'Windows Security Event ID 4688'],
  logConfig: 'Standard process creation and command line logging.',
  falsePositives: ['Authorized penetration testing', 'Security tools that legitimately use token manipulation'],
  tuning: 'Verify known penetration testing schedules. Add time-based exceptions for authorized testing windows.',
  commonErrors: ['New potato variants may not be in the detection list', 'Tool names may be renamed by attackers'],
  responseActions: ['IMMEDIATELY contain the endpoint - this indicates active exploitation', 'Identify the current privilege level of the attacker', 'Check for what the impersonated token was used for', 'Review what service account\'s token was stolen', 'Full incident response engagement required'],
  threatIntel: { cves: ['CVE-2021-34527'], cisaKev: true, campaigns: [], iocs: [] },
  references: ['https://attack.mitre.org/techniques/T1134/001/']
},
{
  id: 'SR-0019', title: 'Exploitation for Privilege Escalation - Vulnerable Driver Loading',
  status: 'stable', severity: 'critical', author: 'SOC Platform', date: '2024-07-01', modified: '2024-12-15',
  category: 'privilege-escalation',
  description: 'Detects loading of known vulnerable drivers that can be exploited for kernel-level privilege escalation (Bring Your Own Vulnerable Driver - BYOVD attack).',
  tacticId: 'TA0004', tacticName: 'Privilege Escalation',
  techniqueId: 'T1068', techniqueName: 'Exploitation for Privilege Escalation',
  logsource: { product: 'windows', category: 'driver_load' },
  sigmaYaml: `title: Exploitation for Privilege Escalation - BYOVD
id: 23456789-fabc-9012-3456-789012345678
status: stable
description: Detects loading of known vulnerable drivers for BYOVD attacks
author: SOC Platform
date: 2024/07/01
logsource:
    category: driver_load
    product: windows
detection:
    selection_hashes:
        Hashes|contains:
            - '0296e2ce999e67c76352613a718e11516fe1b0efc3ffdb8918fc999dd76a73a5'
            - 'c299063e3eae8ddc15839767e83b9808fd43418dc5a1af7e4f44b97ba53fbd3d'
    selection_names:
        ImageLoaded|endswith:
            - '\\\\RTCore64.sys'
            - '\\\\DBUtil_2_3.sys'
            - '\\\\gdrv.sys'
            - '\\\\IQVW64E.sys'
            - '\\\\AsIO.sys'
    condition: selection_hashes or selection_names
falsepositives:
    - Legitimate use of these drivers (verify business justification)
level: critical
tags:
    - attack.privilege_escalation
    - attack.t1068`,
  detectionExplanation: 'Bring Your Own Vulnerable Driver (BYOVD) is a technique where attackers load a legitimate but vulnerable signed driver to exploit its vulnerabilities for kernel-level access. Drivers like RTCore64.sys (MSI Afterburner) have known vulnerabilities that allow arbitrary kernel memory read/write. This bypasses security controls at the kernel level.',
  requiredLogs: ['Sysmon Event ID 6 (Driver Loaded)', 'Windows 7045 (Service Installed for driver loading)'],
  logConfig: 'Enable Sysmon driver load logging. Maintain an updated list of known vulnerable driver hashes from the LOLDrivers project.',
  falsePositives: ['Legitimate hardware management tools using these drivers', 'Gaming software using MSI Afterburner'],
  tuning: 'Cross-reference with the LOLDrivers project for updated vulnerable driver hashes. Allow specific drivers only on systems where the associated legitimate software is installed.',
  commonErrors: ['Vulnerable driver list not regularly updated', 'Driver may be loaded from different paths'],
  responseActions: ['CRITICAL: Isolate the system immediately', 'Capture full memory dump before remediation', 'Remove the vulnerable driver', 'Check for kernel-level rootkits or backdoors', 'Full forensic investigation required - assume complete system compromise'],
  threatIntel: { cves: ['CVE-2020-1472'], cisaKev: true, campaigns: ['ALPHV/BlackCat Ransomware', 'LockBit 3.0'], iocs: [] },
  references: ['https://attack.mitre.org/techniques/T1068/', 'https://www.loldrivers.io/']
},

// ═══════════════════════════════════════════════════════════════
// DEFENSE EVASION (TA0005)
// ═══════════════════════════════════════════════════════════════
{
  id: 'SR-0020', title: 'Security Tool Tampering - Service Disabled',
  status: 'stable', severity: 'critical', author: 'SOC Platform', date: '2024-01-05', modified: '2024-12-10',
  category: 'defense-evasion',
  description: 'Detects attempts to disable or stop security tools including Windows Defender, firewall, event logging, and third-party security software through service manipulation or registry modification.',
  tacticId: 'TA0005', tacticName: 'Defense Evasion',
  techniqueId: 'T1562.001', techniqueName: 'Disable or Modify Tools',
  logsource: { product: 'windows', category: 'process_creation' },
  sigmaYaml: `title: Security Tool Tampering - Service Disabled
id: 34567890-abcd-0123-4567-890123456789
status: stable
description: Detects attempts to disable security services and tools
author: SOC Platform
date: 2024/01/05
logsource:
    category: process_creation
    product: windows
detection:
    selection_sc:
        Image|endswith: '\\\\sc.exe'
        CommandLine|contains:
            - 'stop'
            - 'disabled'
            - 'delete'
        CommandLine|contains:
            - 'WinDefend'
            - 'MpsSvc'
            - 'wscsvc'
            - 'SecurityHealthService'
            - 'Sense'
            - 'WdNisSvc'
            - 'EventLog'
    selection_ps_defender:
        Image|endswith:
            - '\\\\powershell.exe'
            - '\\\\pwsh.exe'
        CommandLine|contains:
            - 'Set-MpPreference'
            - 'DisableRealtimeMonitoring'
            - 'DisableBehaviorMonitoring'
            - 'DisableIOAVProtection'
            - 'Add-MpPreference.*ExclusionPath'
    selection_netsh:
        Image|endswith: '\\\\netsh.exe'
        CommandLine|contains:
            - 'firewall'
            - 'advfirewall'
        CommandLine|contains:
            - 'off'
            - 'disable'
    condition: selection_sc or selection_ps_defender or selection_netsh
falsepositives:
    - IT administrators performing maintenance
    - Legitimate security tool replacement
level: critical
tags:
    - attack.defense_evasion
    - attack.t1562.001`,
  detectionExplanation: 'Attackers routinely disable security tools as one of their first actions after gaining access. This rule monitors for: (1) sc.exe stopping/disabling security services, (2) PowerShell commands modifying Defender settings to disable real-time monitoring or add exclusions, (3) netsh commands disabling the firewall. Any of these occurring outside of a change window should be treated as critical.',
  requiredLogs: ['Sysmon Event ID 1', 'Windows Security 4688', 'Windows Defender Operational Log'],
  logConfig: 'Command line auditing must be enabled. Monitor Windows Defender operational log for configuration changes.',
  falsePositives: ['Legitimate AV software replacement during upgrades', 'IT administrators troubleshooting network issues by temporarily disabling firewall', 'Development environments with intentional Defender exclusions'],
  tuning: 'Correlate with change management tickets. Create separate alerting for Defender exclusion additions (potential ransomware staging) vs. full disabling (active attack).',
  commonErrors: ['Attacker may use PowerShell aliases or encoded commands to evade pattern matching', 'Some methods of disabling Defender do not generate process creation events'],
  responseActions: ['CRITICAL ALERT - immediately investigate', 'Re-enable the disabled security tool if possible', 'Check what activities occurred after the security tool was disabled', 'Assume the attacker performed actions while security was down', 'Full environment sweep required'],
  threatIntel: { cves: [], cisaKev: false, campaigns: ['LockBit 3.0', 'ALPHV/BlackCat Ransomware'], iocs: [] },
  references: ['https://attack.mitre.org/techniques/T1562/001/']
},
{
  id: 'SR-0021', title: 'Windows Event Log Cleared',
  status: 'stable', severity: 'high', author: 'SOC Platform', date: '2024-02-10', modified: '2024-11-15',
  category: 'defense-evasion',
  description: 'Detects clearing of Windows event logs, a common anti-forensics technique used by attackers to remove evidence of their activities.',
  tacticId: 'TA0005', tacticName: 'Defense Evasion',
  techniqueId: 'T1070.001', techniqueName: 'Clear Windows Event Logs',
  logsource: { product: 'windows', service: 'security' },
  sigmaYaml: `title: Windows Event Log Cleared
id: 45678901-bcde-1234-5678-901234567890
status: stable
description: Detects clearing of Windows event logs
author: SOC Platform
date: 2024/02/10
logsource:
    product: windows
    service: security
detection:
    selection_security:
        EventID: 1102
    selection_system:
        EventID: 104
    selection_wevtutil:
        Image|endswith: '\\\\wevtutil.exe'
        CommandLine|contains: 'cl '
    selection_ps:
        CommandLine|contains:
            - 'Clear-EventLog'
            - 'Remove-EventLog'
            - 'Limit-EventLog.*-OverflowAction DoNotRetain'
    condition: selection_security or selection_system or selection_wevtutil or selection_ps
falsepositives:
    - Legitimate log rotation by IT administrators
    - Automated log management scripts
level: high
tags:
    - attack.defense_evasion
    - attack.t1070.001`,
  detectionExplanation: 'When an attacker clears event logs, Windows generates a final audit record (Event ID 1102 for Security log, 104 for System log) before the log is wiped. This rule also detects the tools used to clear logs (wevtutil.exe) and PowerShell cmdlets. Note that the alert itself may be the only evidence of compromise if not forwarded to a SIEM in real-time.',
  requiredLogs: ['Windows Security Event ID 1102', 'Windows System Event ID 104', 'Sysmon Event ID 1'],
  logConfig: 'Ensure real-time log forwarding to SIEM so clearing local logs does not destroy evidence. The 1102 event is generated even if auditing config is minimal.',
  falsePositives: ['Legitimate log rotation or archival procedures', 'System administrators clearing logs during troubleshooting'],
  tuning: 'This detection has very few false positives and should generally not be tuned down. Consider making it a P1 alert for critical servers.',
  commonErrors: ['If logs are not forwarded to SIEM in real-time, clearing them destroys the evidence', 'Only Security log clearing generates 1102; other logs generate 104'],
  responseActions: ['Immediately investigate what happened BEFORE the logs were cleared', 'Check SIEM for the last events before the clearing', 'Examine other log sources (Sysmon, EDR, network) for the same timeframe', 'This may indicate concluding phase of an attack - full IR required'],
  threatIntel: { cves: [], cisaKev: false, campaigns: ['Volt Typhoon', 'LockBit 3.0'], iocs: [] },
  references: ['https://attack.mitre.org/techniques/T1070/001/']
},
{
  id: 'SR-0022', title: 'Process Masquerading - Suspicious Process Path',
  status: 'stable', severity: 'high', author: 'SOC Platform', date: '2024-04-15', modified: '2024-11-25',
  category: 'defense-evasion',
  description: 'Detects processes that impersonate legitimate Windows system binaries but are running from non-standard locations, indicating an attacker is masquerading their malware as legitimate processes.',
  tacticId: 'TA0005', tacticName: 'Defense Evasion',
  techniqueId: 'T1036.005', techniqueName: 'Match Legitimate Name or Location',
  logsource: { product: 'windows', category: 'process_creation' },
  sigmaYaml: `title: Process Masquerading - Suspicious Process Path
id: 56789012-cdef-2345-6789-012345678901
status: stable
description: Detects system binary names running from non-standard paths
author: SOC Platform
date: 2024/04/15
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image|endswith:
            - '\\\\svchost.exe'
            - '\\\\csrss.exe'
            - '\\\\lsass.exe'
            - '\\\\services.exe'
            - '\\\\smss.exe'
            - '\\\\winlogon.exe'
            - '\\\\explorer.exe'
            - '\\\\conhost.exe'
    filter_legit_path:
        Image|startswith:
            - 'C:\\\\Windows\\\\System32\\\\'
            - 'C:\\\\Windows\\\\SysWOW64\\\\'
            - 'C:\\\\Windows\\\\explorer.exe'
    condition: selection and not filter_legit_path
falsepositives:
    - Windows SxS assemblies
    - WinSxS directory copies
level: high
tags:
    - attack.defense_evasion
    - attack.t1036.005`,
  detectionExplanation: 'System binaries like svchost.exe, csrss.exe, and lsass.exe should only run from their standard Windows directory locations. If these process names appear running from any other path (e.g., User folders, Temp, Desktop), it strongly indicates an attacker renamed their malware to blend in with normal system processes. This is a high-fidelity detection.',
  requiredLogs: ['Sysmon Event ID 1 with full image path', 'Windows Security 4688'],
  logConfig: 'Full image path logging is essential. Deploy Sysmon for reliable full path capture.',
  falsePositives: ['Very rare - Windows SxS assembly caching may trigger for some binaries', 'System File Checker copies during Windows servicing'],
  tuning: 'Add WinSxS paths to the allow filter if generating noise. Virtually no other legitimate exceptions exist for these core system binaries.',
  commonErrors: ['Image path comparison must be case-insensitive', 'Short (8.3) path names may bypass path-based detection'],
  responseActions: ['HIGH PRIORITY: This is almost certainly malicious', 'Quarantine the fake system binary', 'Analyze the binary (hash, signature, imports)', 'Determine how the binary was deployed', 'Full malware analysis and IOC extraction'],
  threatIntel: { cves: [], cisaKev: false, campaigns: ['Midnight Blizzard', 'Volt Typhoon'], iocs: [] },
  references: ['https://attack.mitre.org/techniques/T1036/005/']
},
{
  id: 'SR-0023', title: 'Rundll32 Execution with Suspicious Parameters',
  status: 'stable', severity: 'medium', author: 'SOC Platform', date: '2024-05-20', modified: '2024-11-10',
  category: 'defense-evasion',
  description: 'Detects suspicious usage of rundll32.exe to execute DLLs from unusual locations or with suspicious parameters, a common LOLBin abuse technique for defense evasion.',
  tacticId: 'TA0005', tacticName: 'Defense Evasion',
  techniqueId: 'T1218.011', techniqueName: 'Rundll32',
  logsource: { product: 'windows', category: 'process_creation' },
  sigmaYaml: `title: Rundll32 Execution with Suspicious Parameters
id: 67890123-defa-3456-7890-123456789012
status: stable
description: Detects rundll32.exe abuse for proxy execution
author: SOC Platform
date: 2024/05/20
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image|endswith: '\\\\rundll32.exe'
    selection_suspicious:
        CommandLine|contains:
            - 'javascript:'
            - 'http://'
            - 'https://'
            - '\\\\Temp\\\\'
            - '\\\\AppData\\\\'
            - '\\\\ProgramData\\\\'
            - ',#1'
            - 'shell32.dll,Control_RunDLL'
    selection_no_args:
        CommandLine|endswith: 'rundll32.exe'
    condition: selection and (selection_suspicious or selection_no_args)
falsepositives:
    - Control Panel applets using shell32.dll
    - Legitimate software using rundll32 for DLL execution
level: medium
tags:
    - attack.defense_evasion
    - attack.t1218.011`,
  detectionExplanation: 'Rundll32.exe is a legitimate Windows utility for executing DLL functions, but it is widely abused by attackers to execute malicious DLLs while appearing as a normal system process. Suspicious indicators include: loading DLLs from temp/user directories, executing JavaScript, having no arguments (potential hollowing), or unusual export function names.',
  requiredLogs: ['Sysmon Event ID 1', 'Windows Security 4688 with command line'],
  logConfig: 'Command line auditing must be enabled to capture the DLL path and export function.',
  falsePositives: ['Legitimate Control Panel operations', 'Software using rundll32 for DLL initialization', 'Printer driver installations'],
  tuning: 'Focus on DLLs loaded from non-standard paths. Allowlist known Control Panel applet invocations. Create separate higher-severity rules for rundll32 loading DLLs from network shares or URLs.',
  commonErrors: ['Legitimate rundll32 usage is very common - requires careful baseline', 'DLL path may be obfuscated with environment variables'],
  responseActions: ['Analyze the DLL being loaded by rundll32', 'Check if the DLL is signed', 'Examine parent process to understand execution chain', 'Search for the DLL hash across the environment'],
  threatIntel: { cves: [], cisaKev: false, campaigns: ['Scattered Spider'], iocs: [] },
  references: ['https://attack.mitre.org/techniques/T1218/011/', 'https://lolbas-project.github.io/lolbas/Binaries/Rundll32/']
},
{
  id: 'SR-0024', title: 'Registry Modification for Defense Evasion',
  status: 'stable', severity: 'high', author: 'SOC Platform', date: '2024-06-10', modified: '2024-12-05',
  category: 'defense-evasion',
  description: 'Detects modifications to registry keys commonly used to disable security features, hide malware, or weaken system defenses.',
  tacticId: 'TA0005', tacticName: 'Defense Evasion',
  techniqueId: 'T1112', techniqueName: 'Modify Registry',
  logsource: { product: 'windows', category: 'registry_set' },
  sigmaYaml: `title: Registry Modification for Defense Evasion
id: 78901234-efab-4567-8901-234567890123
status: stable
description: Detects registry modifications to disable security features
author: SOC Platform
date: 2024/06/10
logsource:
    category: registry_set
    product: windows
detection:
    selection_defender:
        TargetObject|contains:
            - 'Windows Defender\\\\Real-Time Protection'
            - 'Windows Defender\\\\SpyNet'
            - 'Windows Defender\\\\Features'
        Details:
            - 'DWORD (0x00000001)'
    selection_uac:
        TargetObject|contains: 'SOFTWARE\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\Policies\\\\System'
        TargetObject|endswith:
            - 'EnableLUA'
            - 'ConsentPromptBehaviorAdmin'
        Details: 'DWORD (0x00000000)'
    selection_firewall:
        TargetObject|contains: 'SYSTEM\\\\CurrentControlSet\\\\Services\\\\SharedAccess\\\\Parameters\\\\FirewallPolicy'
        TargetObject|endswith: 'EnableFirewall'
        Details: 'DWORD (0x00000000)'
    condition: selection_defender or selection_uac or selection_firewall
falsepositives:
    - GPO applying security policy
    - IT administrators reconfiguring security settings
level: high
tags:
    - attack.defense_evasion
    - attack.t1112`,
  detectionExplanation: 'Direct registry modifications can disable Windows Defender real-time protection, disable UAC, or turn off the Windows firewall without using standard management tools. This approach is stealthier than using sc.exe or PowerShell cmdlets. The specific registry values and their data are well-documented indicators of security weakening.',
  requiredLogs: ['Sysmon Event ID 13 (Registry Value Set)'],
  logConfig: 'Configure Sysmon to monitor the specific registry paths. Also enable registry auditing via SACL on these critical keys.',
  falsePositives: ['Group Policy Object application changing security settings', 'Planned security reconfiguration during maintenance'],
  tuning: 'Correlate with GPO application events. If a domain computer applies GPO that modifies these values, filter by the process being the Group Policy Client (svchost.exe with specific flags).',
  commonErrors: ['Registry value data format varies by detection tool', 'WOW6432Node mirror may also need monitoring'],
  responseActions: ['Restore the security setting immediately', 'Investigate what process made the modification', 'Determine if this is part of a larger attack chain', 'Check for malware execution that coincided with the evasion attempt'],
  threatIntel: { cves: [], cisaKev: false, campaigns: ['LockBit 3.0', 'ALPHV/BlackCat Ransomware'], iocs: [] },
  references: ['https://attack.mitre.org/techniques/T1112/']
},
{
  id: 'SR-0025', title: 'Obfuscated PowerShell Command Execution',
  status: 'stable', severity: 'high', author: 'SOC Platform', date: '2024-08-01', modified: '2024-12-15',
  category: 'defense-evasion',
  description: 'Detects highly obfuscated PowerShell commands using techniques like string concatenation, backtick insertion, character substitution, and variable-based obfuscation common in malware.',
  tacticId: 'TA0005', tacticName: 'Defense Evasion',
  techniqueId: 'T1027.010', techniqueName: 'Command Obfuscation',
  logsource: { product: 'windows', category: 'process_creation' },
  sigmaYaml: `title: Obfuscated PowerShell Command Execution
id: 89012345-fabc-5678-9012-345678901234
status: stable
description: Detects highly obfuscated PowerShell commands
author: SOC Platform
date: 2024/08/01
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image|endswith:
            - '\\\\powershell.exe'
            - '\\\\pwsh.exe'
    selection_obfuscation:
        CommandLine|re:
            - '.*\\+.*\\+.*\\+.*\\+.*'
            - '.*\\$\\{.*\\}.*\\$\\{.*\\}.*'
            - '.*-join.*\\[char\\].*'
            - '.*\\[type\\].*GetMethod.*Invoke.*'
    selection_indicators:
        CommandLine|contains:
            - 'char]0x'
            - '[Convert]::FromBase64'
            - 'SecureString'
            - '-bxor'
            - 'Replace('
            - '.Invoke('
            - 'Reflection.Assembly'
            - 'GetType('
    condition: selection and (selection_obfuscation or selection_indicators)
falsepositives:
    - Obfuscated but legitimate scripts (rare)
    - Some deployment frameworks
level: high
tags:
    - attack.defense_evasion
    - attack.t1027.010`,
  detectionExplanation: 'Attackers obfuscate PowerShell commands to evade signature-based detections. Common techniques include: string concatenation ("p"+"ower"+"shell"), character code conversion ([char]0x50), Base64 with XOR decryption, and .NET reflection for dynamic method invocation. This rule targets the patterns of obfuscation rather than specific payloads, making it more resilient to evasion.',
  requiredLogs: ['Sysmon Event ID 1', 'PowerShell Script Block Logging (4104)'],
  logConfig: 'Enable Script Block Logging for deepest visibility into deobfuscated content. Command line logging provides initial detection but may miss the full payload.',
  falsePositives: ['Some deployment tools use obfuscated scripts for IP protection', 'PowerShell-based DSC configurations with complex string handling'],
  tuning: 'Use Script Block Logging to see the deobfuscated version - alert on the content rather than just the obfuscation patterns. This provides both better detection and fewer false positives.',
  commonErrors: ['Regex-based detection can be CPU-intensive in high-volume environments', 'New obfuscation techniques continuously evolve'],
  responseActions: ['Deobfuscate the PowerShell command to understand the payload', 'Check PowerShell transcript logs for the deobfuscated content', 'Analyze what the payload does (download, execute, exfil)', 'Search for the same obfuscation pattern across all endpoints'],
  threatIntel: { cves: [], cisaKev: false, campaigns: ['Midnight Blizzard', 'Scattered Spider'], iocs: [] },
  references: ['https://attack.mitre.org/techniques/T1027/010/']
}
];
