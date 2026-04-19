// ═══════════════════════════════════════════════════════════════════════
// Threat Hunting Engine — Behavior-Based Hunting Queries
// Linked to Categories, MITRE ATT&CK, and Sigma Rules
// ═══════════════════════════════════════════════════════════════════════

const HUNTING_QUERIES = [
  // ── Credential Access Hunts ──
  {
    id: 'HQ-001', name: 'LSASS Memory Access Hunt',
    description: 'Hunt for unauthorized processes accessing LSASS memory, which may indicate credential dumping tools like Mimikatz.',
    category: 'credential-access', huntType: 'behavior',
    mitre: { tacticId: 'TA0006', techniqueId: 'T1003.001', techniqueName: 'LSASS Memory' },
    linkedSigmaRules: ['SR-0022', 'SR-0023'],
    splunkQuery: `index=sysmon EventCode=10 TargetImage="*\\\\lsass.exe"
| where NOT match(SourceImage, "(?i)(MsMpEng|csrss|services|WerFault|wininit|svchost|taskmgr)")
| stats count by SourceImage, SourceProcessGUID, Computer
| where count > 0
| sort - count`,
    qradarQuery: `SELECT sourceip, LOGSOURCENAME(logsourceid), UTF8(payload) as details
FROM events
WHERE LOWER(UTF8(payload)) LIKE '%lsass%'
AND devicetype = 12
AND LOWER(UTF8(payload)) NOT LIKE '%msmpeng%'
ORDER BY starttime DESC LAST 24 HOURS`,
    hypothesis: 'Credential dumping activity via LSASS memory access from non-standard processes',
    dataRequirements: ['Sysmon Event ID 10 (Process Access)', 'EDR process access telemetry'],
    frequency: 'Daily',
    difficulty: 'Medium',
    tags: ['mimikatz', 'credential-dump', 'lsass', 'procdump']
  },
  {
    id: 'HQ-002', name: 'Kerberoasting Activity Detection',
    description: 'Hunt for Kerberos TGS requests targeting service accounts with SPNs, indicative of Kerberoasting offline password cracking attempts.',
    category: 'active-directory', huntType: 'behavior',
    mitre: { tacticId: 'TA0006', techniqueId: 'T1558.003', techniqueName: 'Kerberoasting' },
    linkedSigmaRules: ['SR-0024'],
    splunkQuery: `index=wineventlog EventCode=4769 ServiceName!="krbtgt" ServiceName!="$*" TicketEncryptionType=0x17
| stats count dc(ServiceName) as unique_services by TargetUserName, IpAddress
| where unique_services > 5
| sort - unique_services`,
    qradarQuery: `SELECT sourceip, username, COUNT(*) as request_count
FROM events
WHERE devicetype = 12 AND eventid = 4769
AND UTF8(payload) LIKE '%0x17%'
GROUP BY sourceip, username
HAVING COUNT(*) > 5
ORDER BY request_count DESC LAST 24 HOURS`,
    hypothesis: 'Service accounts being targeted for offline password cracking via Kerberos TGS requests',
    dataRequirements: ['Windows Security Event ID 4769', 'Kerberos authentication logs'],
    frequency: 'Daily',
    difficulty: 'Medium',
    tags: ['kerberoasting', 'active-directory', 'spn', 'tgs']
  },
  // ── Lateral Movement Hunts ──
  {
    id: 'HQ-003', name: 'Anomalous RDP Session Hunt',
    description: 'Hunt for unusual RDP sessions between workstations or from unexpected source systems, indicating potential lateral movement.',
    category: 'lateral-movement', huntType: 'anomaly',
    mitre: { tacticId: 'TA0008', techniqueId: 'T1021.001', techniqueName: 'Remote Desktop Protocol' },
    linkedSigmaRules: ['SR-0031'],
    splunkQuery: `index=wineventlog EventCode=4624 LogonType=10
| eval src_type=case(
    match(SourceNetworkAddress, "^10\\."), "internal",
    match(SourceNetworkAddress, "^172\\."), "internal",
    match(SourceNetworkAddress, "^192\\.168"), "internal",
    true(), "external"
  )
| stats count by TargetUserName, SourceNetworkAddress, Computer, src_type
| where src_type="external" OR NOT match(Computer, "(?i)server|srv|dc")
| sort - count`,
    qradarQuery: `SELECT sourceip, destinationip, username, COUNT(*) as sessions
FROM events
WHERE devicetype = 12 AND eventid = 4624
AND logontype = 10
GROUP BY sourceip, destinationip, username
ORDER BY sessions DESC LAST 7 DAYS`,
    hypothesis: 'Lateral movement via RDP from unexpected sources or between workstations',
    dataRequirements: ['Windows Security Event ID 4624 (LogonType 10)', 'RDP connection broker logs'],
    frequency: 'Weekly',
    difficulty: 'Low',
    tags: ['rdp', 'lateral-movement', 'workstation-to-workstation']
  },
  {
    id: 'HQ-004', name: 'PsExec / Remote Service Installation Hunt',
    description: 'Hunt for remote service installation patterns characteristic of PsExec or similar remote execution tools.',
    category: 'lateral-movement', huntType: 'behavior',
    mitre: { tacticId: 'TA0008', techniqueId: 'T1021.002', techniqueName: 'SMB/Windows Admin Shares' },
    linkedSigmaRules: ['SR-0032'],
    splunkQuery: `index=wineventlog EventCode=7045
| search ServiceName IN ("PSEXESVC", "RemComSvc", "msiexec", "csexec")
    OR ImagePath="*\\\\ADMIN$\\\\*"
    OR ImagePath="*\\\\C$\\\\*"
| stats count values(ServiceName) as services values(ImagePath) as paths by Computer
| sort - count`,
    qradarQuery: `SELECT LOGSOURCENAME(logsourceid), UTF8(payload) as detail
FROM events
WHERE devicetype = 12 AND eventid = 7045
AND (LOWER(UTF8(payload)) LIKE '%psexe%' OR LOWER(UTF8(payload)) LIKE '%admin$%')
ORDER BY starttime DESC LAST 7 DAYS`,
    hypothesis: 'Remote execution via PsExec or ADMIN$ share abuse for lateral movement',
    dataRequirements: ['System Event ID 7045', 'SMB file share access logs'],
    frequency: 'Daily',
    difficulty: 'Low',
    tags: ['psexec', 'admin-share', 'remote-service', 'smb']
  },
  // ── Persistence Hunts ──
  {
    id: 'HQ-005', name: 'Rare Scheduled Task Hunt',
    description: 'Hunt for scheduled tasks created on few systems — rarity analysis helps identify attacker persistence tasks that stand out from common enterprise tasks.',
    category: 'persistence', huntType: 'anomaly',
    mitre: { tacticId: 'TA0003', techniqueId: 'T1053.005', techniqueName: 'Scheduled Task' },
    linkedSigmaRules: ['SR-0009'],
    splunkQuery: `index=wineventlog EventCode=4698
| rex field=Message "TaskName.+?\\>(?<TaskName>[^\\<]+)"
| rex field=Message "Command.+?\\>(?<Command>[^\\<]+)"
| stats dc(Computer) as system_count values(Computer) as systems by TaskName, Command
| where system_count < 3
| sort system_count`,
    qradarQuery: `SELECT UTF8(payload), LOGSOURCENAME(logsourceid), COUNT(*) as occurrences
FROM events
WHERE devicetype = 12 AND eventid = 4698
GROUP BY UTF8(payload), LOGSOURCENAME(logsourceid)
HAVING COUNT(*) < 3
ORDER BY occurrences ASC LAST 30 DAYS`,
    hypothesis: 'Persistence via scheduled tasks that appear on very few systems (attacker-created)',
    dataRequirements: ['Windows Security Event ID 4698', 'Task Scheduler Operational log'],
    frequency: 'Weekly',
    difficulty: 'Medium',
    tags: ['scheduled-task', 'rarity', 'persistence']
  },
  {
    id: 'HQ-006', name: 'Unusual Service Creation Hunt',
    description: 'Hunt for newly installed Windows services with uncommon names or paths, especially those running from temporary or user-writable directories.',
    category: 'persistence', huntType: 'anomaly',
    mitre: { tacticId: 'TA0003', techniqueId: 'T1543.003', techniqueName: 'Windows Service' },
    linkedSigmaRules: ['SR-0013'],
    splunkQuery: `index=wineventlog EventCode=7045
| where NOT match(ImagePath, "(?i)(Program Files|Windows\\\\System32|svchost)")
| stats count by ServiceName, ImagePath, Computer, StartType
| sort - count
| head 50`,
    qradarQuery: `SELECT LOGSOURCENAME(logsourceid), UTF8(payload) as service_detail
FROM events
WHERE devicetype = 12 AND eventid = 7045
AND LOWER(UTF8(payload)) NOT LIKE '%program files%'
AND LOWER(UTF8(payload)) NOT LIKE '%system32%'
ORDER BY starttime DESC LAST 30 DAYS`,
    hypothesis: 'Persistence via service creation with binaries in non-standard directories',
    dataRequirements: ['System Event ID 7045'],
    frequency: 'Weekly',
    difficulty: 'Low',
    tags: ['service', 'persistence', 'unusual-path']
  },
  // ── Defense Evasion Hunts ──
  {
    id: 'HQ-007', name: 'Process Masquerading Hunt',
    description: 'Hunt for processes with legitimate names running from incorrect directories — a classic defense evasion technique.',
    category: 'defense-evasion', huntType: 'behavior',
    mitre: { tacticId: 'TA0005', techniqueId: 'T1036.005', techniqueName: 'Match Legitimate Name or Location' },
    linkedSigmaRules: [],
    splunkQuery: `index=sysmon EventCode=1
| eval expected_path=case(
    Image LIKE "%svchost.exe", "C:\\\\Windows\\\\System32\\\\svchost.exe",
    Image LIKE "%csrss.exe", "C:\\\\Windows\\\\System32\\\\csrss.exe",
    Image LIKE "%lsass.exe", "C:\\\\Windows\\\\System32\\\\lsass.exe",
    Image LIKE "%services.exe", "C:\\\\Windows\\\\System32\\\\services.exe",
    Image LIKE "%explorer.exe", "C:\\\\Windows\\\\explorer.exe"
  )
| where isnotnull(expected_path) AND Image!=expected_path
| stats count by Image, ParentImage, User, Computer
| sort - count`,
    qradarQuery: `SELECT sourceip, LOGSOURCENAME(logsourceid), UTF8(payload) as process_info
FROM events
WHERE devicetype = 12
AND (LOWER(UTF8(payload)) LIKE '%svchost%' OR LOWER(UTF8(payload)) LIKE '%csrss%')
AND LOWER(UTF8(payload)) NOT LIKE '%system32%'
ORDER BY starttime DESC LAST 7 DAYS`,
    hypothesis: 'Malware masquerading as legitimate Windows processes but running from wrong directories',
    dataRequirements: ['Sysmon Event ID 1 with full Image path'],
    frequency: 'Daily',
    difficulty: 'Medium',
    tags: ['masquerading', 'evasion', 'lolbin', 'fake-process']
  },
  {
    id: 'HQ-008', name: 'Security Tool Tampering Hunt',
    description: 'Hunt for attempts to disable, modify, or uninstall security tools including AV, EDR, and Windows Defender.',
    category: 'defense-evasion', huntType: 'behavior',
    mitre: { tacticId: 'TA0005', techniqueId: 'T1562.001', techniqueName: 'Disable or Modify Tools' },
    linkedSigmaRules: ['SR-0020'],
    splunkQuery: `index=sysmon EventCode=1
| where match(CommandLine, "(?i)(sc stop|net stop|taskkill|Disable-WindowsOptionalFeature|Set-MpPreference.*-Disable|Uninstall|remove.*defender|tamper)")
| where match(CommandLine, "(?i)(defender|sentinel|crowdstrike|carbon|symantec|mcafee|sophos|kaspersky|eset|trend|cylance|fireeye)")
| stats count by Image, CommandLine, ParentImage, User, Computer
| sort - count`,
    qradarQuery: `SELECT sourceip, username, UTF8(payload) as command_detail
FROM events
WHERE LOWER(UTF8(payload)) LIKE '%disable%'
AND (LOWER(UTF8(payload)) LIKE '%defender%' OR LOWER(UTF8(payload)) LIKE '%security%')
ORDER BY starttime DESC LAST 7 DAYS`,
    hypothesis: 'Attackers disabling endpoint security tools before deploying malware',
    dataRequirements: ['Sysmon Event ID 1', 'Windows Defender operational log', 'EDR tamper events'],
    frequency: 'Daily',
    difficulty: 'Low',
    tags: ['av-disable', 'edr-bypass', 'tamper', 'defender']
  },
  // ── C2 Hunts ──
  {
    id: 'HQ-009', name: 'Beaconing Detection Hunt',
    description: 'Hunt for regular-interval network connections characteristic of C2 beaconing, using statistical analysis of connection patterns.',
    category: 'command-control', huntType: 'anomaly',
    mitre: { tacticId: 'TA0011', techniqueId: 'T1071.001', techniqueName: 'Web Protocols' },
    linkedSigmaRules: [],
    splunkQuery: `index=proxy OR index=firewall
| bin _time span=5m
| stats count by src_ip, dest_ip, dest_port, _time
| streamstats window=12 avg(count) as avg_conn stdev(count) as stdev_conn by src_ip, dest_ip
| where stdev_conn < 2 AND avg_conn > 0
| stats count avg(avg_conn) as consistency by src_ip, dest_ip, dest_port
| where count > 20 AND consistency > 0
| sort - count`,
    qradarQuery: `SELECT sourceip, destinationip, destinationport,
  COUNT(*) as connections,
  MIN(starttime) as first_seen, MAX(starttime) as last_seen
FROM events
WHERE category = 'Firewall' OR category = 'Web Proxy'
GROUP BY sourceip, destinationip, destinationport
HAVING COUNT(*) > 50
ORDER BY connections DESC LAST 24 HOURS`,
    hypothesis: 'C2 beaconing identified by statistically regular connection intervals',
    dataRequirements: ['Proxy logs', 'Firewall connection logs', 'DNS logs'],
    frequency: 'Daily',
    difficulty: 'High',
    tags: ['beaconing', 'c2', 'cobalt-strike', 'interval-analysis']
  },
  {
    id: 'HQ-010', name: 'DNS Tunneling Detection Hunt',
    description: 'Hunt for DNS queries with abnormally long domain names or high query volumes to single domains, indicative of DNS tunneling for C2 or data exfiltration.',
    category: 'command-control', huntType: 'anomaly',
    mitre: { tacticId: 'TA0011', techniqueId: 'T1071.004', techniqueName: 'DNS' },
    linkedSigmaRules: [],
    splunkQuery: `index=dns query_type IN ("TXT", "A", "CNAME")
| eval query_length=len(query)
| eval subdomain_count=mvcount(split(query, "."))
| where query_length > 50 OR subdomain_count > 5
| stats count avg(query_length) as avg_len by query, src_ip
| where count > 10
| sort - avg_len`,
    qradarQuery: `SELECT sourceip, UTF8(payload) as dns_query, COUNT(*) as query_count
FROM events
WHERE category = 'DNS'
AND LENGTH(UTF8(payload)) > 60
GROUP BY sourceip, UTF8(payload)
HAVING COUNT(*) > 10
ORDER BY query_count DESC LAST 24 HOURS`,
    hypothesis: 'DNS tunneling for C2 communication or data exfiltration via encoded DNS queries',
    dataRequirements: ['DNS query logs', 'Sysmon Event ID 22 (DNS Query)'],
    frequency: 'Daily',
    difficulty: 'High',
    tags: ['dns-tunneling', 'c2', 'exfiltration', 'dnscat']
  },
  // ── Execution Hunts ──
  {
    id: 'HQ-011', name: 'LOLBin Execution Chain Hunt',
    description: 'Hunt for chains of Living-off-the-Land Binary usage that may indicate attack framework execution or post-exploitation activity.',
    category: 'execution', huntType: 'behavior',
    mitre: { tacticId: 'TA0002', techniqueId: 'T1218', techniqueName: 'System Binary Proxy Execution' },
    linkedSigmaRules: ['SR-0006', 'SR-0007'],
    splunkQuery: `index=sysmon EventCode=1
| where match(Image, "(?i)(mshta|regsvr32|rundll32|certutil|msbuild|installutil|cmstp|wmic|forfiles|pcalua)")
| transaction host maxspan=5m
| where eventcount > 2
| table _time, host, Image, CommandLine, ParentImage, User
| sort - _time`,
    qradarQuery: `SELECT sourceip, LOGSOURCENAME(logsourceid), UTF8(payload) as process_info
FROM events
WHERE devicetype = 12
AND (LOWER(UTF8(payload)) LIKE '%mshta%'
  OR LOWER(UTF8(payload)) LIKE '%regsvr32%'
  OR LOWER(UTF8(payload)) LIKE '%certutil%'
  OR LOWER(UTF8(payload)) LIKE '%rundll32%')
ORDER BY starttime DESC LAST 24 HOURS`,
    hypothesis: 'Attack framework using multiple LOLBins in sequence for execution and evasion',
    dataRequirements: ['Sysmon Event ID 1'],
    frequency: 'Daily',
    difficulty: 'Medium',
    tags: ['lolbin', 'proxy-execution', 'living-off-land']
  },
  {
    id: 'HQ-012', name: 'PowerShell Obfuscation Hunt',
    description: 'Hunt for obfuscated PowerShell execution using character frequency analysis and entropy scoring to detect encoded or scrambled commands.',
    category: 'execution', huntType: 'anomaly',
    mitre: { tacticId: 'TA0002', techniqueId: 'T1059.001', techniqueName: 'PowerShell' },
    linkedSigmaRules: ['SR-0006'],
    splunkQuery: `index=wineventlog EventCode=4104
| eval script_len=len(ScriptBlockText)
| eval special_chars=mvcount(split(ScriptBlockText, "+")) + mvcount(split(ScriptBlockText, "^")) + mvcount(split(ScriptBlockText, "\`"))
| eval obfuscation_score=special_chars/script_len*100
| where obfuscation_score > 10 OR match(ScriptBlockText, "(?i)(char\\[\\]|\\-bxor|\\-join|ForEach-Object.*\\{.*\\[char\\])")
| stats count by Computer, UserID
| sort - count`,
    qradarQuery: `SELECT sourceip, username, UTF8(payload)
FROM events
WHERE eventid = 4104
AND (LOWER(UTF8(payload)) LIKE '%frombase64%'
  OR LOWER(UTF8(payload)) LIKE '%-bxor%'
  OR LOWER(UTF8(payload)) LIKE '%char]%')
ORDER BY starttime DESC LAST 7 DAYS`,
    hypothesis: 'Obfuscated PowerShell scripts evading static detection through encoding and string manipulation',
    dataRequirements: ['PowerShell Script Block Logging (Event ID 4104)'],
    frequency: 'Daily',
    difficulty: 'High',
    tags: ['powershell', 'obfuscation', 'encoding', 'invoke-obfuscation']
  },
  // ── Exfiltration Hunts ──
  {
    id: 'HQ-013', name: 'Large Data Transfer Hunt',
    description: 'Hunt for unusually large outbound data transfers that may indicate data exfiltration, using volumetric analysis against baseline.',
    category: 'data-exfiltration', huntType: 'anomaly',
    mitre: { tacticId: 'TA0010', techniqueId: 'T1048', techniqueName: 'Exfiltration Over Alternative Protocol' },
    linkedSigmaRules: [],
    splunkQuery: `index=proxy OR index=firewall action=allowed direction=outbound
| stats sum(bytes_out) as total_bytes by src_ip, dest_ip
| eval MB=round(total_bytes/1024/1024,2)
| where MB > 500
| sort - MB
| head 20`,
    qradarQuery: `SELECT sourceip, destinationip, SUM(bytesreceived) as total_bytes
FROM flows
WHERE direction = 'R2L'
GROUP BY sourceip, destinationip
HAVING SUM(bytesreceived) > 524288000
ORDER BY total_bytes DESC LAST 24 HOURS`,
    hypothesis: 'Data exfiltration via large outbound transfers exceeding normal baseline',
    dataRequirements: ['Proxy logs with byte counts', 'Firewall logs', 'Network flow data'],
    frequency: 'Daily',
    difficulty: 'Low',
    tags: ['exfiltration', 'data-theft', 'volume-anomaly']
  },
  {
    id: 'HQ-014', name: 'Cloud Storage Upload Hunt',
    description: 'Hunt for bulk uploads to personal cloud storage services that may indicate insider threat data exfiltration.',
    category: 'insider-threat', huntType: 'behavior',
    mitre: { tacticId: 'TA0010', techniqueId: 'T1567.002', techniqueName: 'Exfiltration to Cloud Storage' },
    linkedSigmaRules: [],
    splunkQuery: `index=proxy
| where match(url, "(?i)(dropbox|drive\\.google|onedrive\\.live|box\\.com|mega\\.nz|wetransfer)")
| where method="POST" OR method="PUT"
| stats sum(bytes_out) as uploaded_bytes count by src_ip, url, user
| eval MB=round(uploaded_bytes/1024/1024,2)
| where MB > 50
| sort - MB`,
    qradarQuery: `SELECT sourceip, username, destinationip, SUM(bytessent) as upload_bytes
FROM events
WHERE category = 'Web Proxy'
AND (LOWER(UTF8(payload)) LIKE '%dropbox%' OR LOWER(UTF8(payload)) LIKE '%drive.google%')
GROUP BY sourceip, username, destinationip
HAVING SUM(bytessent) > 52428800
ORDER BY upload_bytes DESC LAST 7 DAYS`,
    hypothesis: 'Data exfiltration to personal cloud storage by insiders or compromised accounts',
    dataRequirements: ['Proxy logs with URLs and byte counts'],
    frequency: 'Weekly',
    difficulty: 'Low',
    tags: ['cloud-upload', 'insider', 'dropbox', 'gdrive']
  },
  // ── Reconnaissance Hunts ──
  {
    id: 'HQ-015', name: 'Internal Network Reconnaissance Hunt',
    description: 'Hunt for internal systems performing network scanning or discovery using built-in tools, indicating a compromised host performing reconnaissance.',
    category: 'reconnaissance', huntType: 'behavior',
    mitre: { tacticId: 'TA0007', techniqueId: 'T1046', techniqueName: 'Network Service Discovery' },
    linkedSigmaRules: [],
    splunkQuery: `index=sysmon EventCode=3
| where NOT match(DestinationIp, "^(10\\.|172\\.(1[6-9]|2[0-9]|3[01])\\.|192\\.168\\.)")
| stats dc(DestinationPort) as unique_ports dc(DestinationIp) as unique_ips by SourceIp, Image
| where unique_ports > 20 OR unique_ips > 50
| sort - unique_ports`,
    qradarQuery: `SELECT sourceip, COUNT(DISTINCT destinationport) as port_count, COUNT(DISTINCT destinationip) as ip_count
FROM flows
WHERE sourcenetwork = 'Internal'
GROUP BY sourceip
HAVING COUNT(DISTINCT destinationport) > 20 OR COUNT(DISTINCT destinationip) > 50
ORDER BY port_count DESC LAST 24 HOURS`,
    hypothesis: 'Internal host performing network scanning/discovery post-compromise',
    dataRequirements: ['Sysmon Event ID 3', 'Network flow data', 'Firewall logs'],
    frequency: 'Daily',
    difficulty: 'Medium',
    tags: ['port-scan', 'network-discovery', 'nmap', 'recon']
  },
  // ── Ransomware Hunts ──
  {
    id: 'HQ-016', name: 'Pre-Ransomware Activity Hunt',
    description: 'Hunt for behavioral patterns that commonly precede ransomware deployment: shadow copy deletion, backup service stops, and mass file modifications.',
    category: 'ransomware', huntType: 'behavior',
    mitre: { tacticId: 'TA0040', techniqueId: 'T1490', techniqueName: 'Inhibit System Recovery' },
    linkedSigmaRules: ['SR-0035', 'SR-0036'],
    splunkQuery: `index=sysmon EventCode=1
| where match(CommandLine, "(?i)(vssadmin.*delete|wmic.*shadowcopy|bcdedit.*recoveryenabled.*no|wbadmin.*delete|net stop.*vss|sc stop)")
| stats count values(CommandLine) as commands by Computer, User, _time
| sort - _time`,
    qradarQuery: `SELECT sourceip, LOGSOURCENAME(logsourceid), UTF8(payload) as command
FROM events
WHERE LOWER(UTF8(payload)) LIKE '%vssadmin%delete%'
OR LOWER(UTF8(payload)) LIKE '%bcdedit%recovery%'
OR LOWER(UTF8(payload)) LIKE '%wbadmin%delete%'
ORDER BY starttime DESC LAST 24 HOURS`,
    hypothesis: 'Pre-ransomware preparation: shadow copies, backups, and recovery being disabled',
    dataRequirements: ['Sysmon Event ID 1', 'Windows Security Event Log'],
    frequency: 'Real-time / Hourly',
    difficulty: 'Low',
    tags: ['ransomware', 'vss-delete', 'backup-delete', 'recovery-disable']
  },
  // ── Cloud Hunts ──
  {
    id: 'HQ-017', name: 'Impossible Travel Detection',
    description: 'Hunt for user logins from geographically distant locations within a short time window, indicating account compromise.',
    category: 'cloud-threats', huntType: 'anomaly',
    mitre: { tacticId: 'TA0001', techniqueId: 'T1078.004', techniqueName: 'Cloud Accounts' },
    linkedSigmaRules: [],
    splunkQuery: `index=azure_signin OR index=o365
| iplocation src_ip
| stats earliest(_time) as first_login latest(_time) as last_login values(City) as cities values(Country) as countries by user
| where mvcount(countries) > 1
| eval time_diff_hours=round((last_login-first_login)/3600,2)
| where time_diff_hours < 2
| sort time_diff_hours`,
    qradarQuery: `SELECT username, sourceip, COUNT(DISTINCT sourceip) as unique_ips
FROM events
WHERE category = 'Authentication'
AND devicetype IN (412, 413)
GROUP BY username, sourceip
HAVING COUNT(DISTINCT sourceip) > 2
ORDER BY unique_ips DESC LAST 24 HOURS`,
    hypothesis: 'Account compromise indicated by physically impossible login locations',
    dataRequirements: ['Azure AD / Entra ID sign-in logs', 'Cloud authentication logs'],
    frequency: 'Daily',
    difficulty: 'Medium',
    tags: ['impossible-travel', 'cloud', 'account-takeover']
  },
  {
    id: 'HQ-018', name: 'Rare Parent-Child Process Relationship',
    description: 'Hunt for uncommon parent-child process combinations that deviate from normal system behavior, identifying novel attack techniques.',
    category: 'endpoint-anomalies', huntType: 'anomaly',
    mitre: { tacticId: 'TA0002', techniqueId: 'T1106', techniqueName: 'Native API' },
    linkedSigmaRules: [],
    splunkQuery: `index=sysmon EventCode=1
| stats count by ParentImage, Image
| eventstats sum(count) as total_for_parent by ParentImage
| eval pct=round(count/total_for_parent*100,2)
| where pct < 1 AND count < 5
| sort pct
| head 50`,
    qradarQuery: `SELECT UTF8(payload) as parent_child, COUNT(*) as occurrence
FROM events
WHERE devicetype = 12 AND eventid = 1
GROUP BY UTF8(payload)
HAVING COUNT(*) < 3
ORDER BY occurrence ASC LAST 30 DAYS`,
    hypothesis: 'Novel or rare process execution chains indicating unknown attack techniques',
    dataRequirements: ['Sysmon Event ID 1 with parent process data'],
    frequency: 'Weekly',
    difficulty: 'High',
    tags: ['parent-child', 'anomaly', 'rare-behavior', 'baseline']
  },
  // ── Email Hunts ──
  {
    id: 'HQ-019', name: 'Email Forwarding Rule Abuse Hunt',
    description: 'Hunt for mailbox forwarding rules that silently redirect emails to external addresses, a common persistence technique after email compromise.',
    category: 'email-threats', huntType: 'behavior',
    mitre: { tacticId: 'TA0009', techniqueId: 'T1114.003', techniqueName: 'Email Forwarding Rule' },
    linkedSigmaRules: [],
    splunkQuery: `index=o365 Workload=Exchange Operation IN ("New-InboxRule", "Set-InboxRule", "Enable-InboxRule")
| where match(Parameters, "(?i)(forward|redirect|delete)")
| stats count by UserId, Parameters, ClientIP
| sort - count`,
    qradarQuery: `SELECT username, sourceip, UTF8(payload) as rule_details
FROM events
WHERE category = 'Email'
AND LOWER(UTF8(payload)) LIKE '%inboxrule%'
AND (LOWER(UTF8(payload)) LIKE '%forward%' OR LOWER(UTF8(payload)) LIKE '%redirect%')
ORDER BY starttime DESC LAST 30 DAYS`,
    hypothesis: 'Business Email Compromise persistence via hidden email forwarding rules',
    dataRequirements: ['Exchange / O365 audit logs'],
    frequency: 'Weekly',
    difficulty: 'Low',
    tags: ['bec', 'email-forward', 'inbox-rule', 'persistence']
  },
  // ── Privilege Escalation Hunts ──
  {
    id: 'HQ-020', name: 'UAC Bypass Technique Hunt',
    description: 'Hunt for known UAC bypass techniques including fodhelper, eventvwr, and DLL hijacking methods.',
    category: 'privilege-escalation', huntType: 'behavior',
    mitre: { tacticId: 'TA0004', techniqueId: 'T1548.002', techniqueName: 'Bypass User Account Control' },
    linkedSigmaRules: [],
    splunkQuery: `index=sysmon EventCode=1
| where match(ParentImage, "(?i)(fodhelper|eventvwr|computerdefaults|sdclt|slui|changepk)")
  AND match(Image, "(?i)(cmd|powershell|pwsh)")
| stats count by ParentImage, Image, CommandLine, User, Computer
| sort - count`,
    qradarQuery: `SELECT sourceip, username, UTF8(payload)
FROM events
WHERE devicetype = 12
AND (LOWER(UTF8(payload)) LIKE '%fodhelper%'
  OR LOWER(UTF8(payload)) LIKE '%eventvwr%'
  OR LOWER(UTF8(payload)) LIKE '%computerdefaults%')
ORDER BY starttime DESC LAST 7 DAYS`,
    hypothesis: 'Privilege escalation via UAC bypass auto-elevate abuse',
    dataRequirements: ['Sysmon Event ID 1', 'Registry modification events'],
    frequency: 'Daily',
    difficulty: 'Medium',
    tags: ['uac-bypass', 'privesc', 'fodhelper', 'auto-elevate']
  }
];

// ── Get hunting queries by category ──
function getHuntingByCategory(catId) {
  return HUNTING_QUERIES.filter(h => h.category === catId);
}

// ── Get hunting queries by MITRE technique ──
function getHuntingByTechnique(techniqueId) {
  return HUNTING_QUERIES.filter(h => h.mitre.techniqueId === techniqueId || h.mitre.techniqueId.startsWith(techniqueId));
}

// ── Get linked Sigma rules for a hunt ──
function getHuntLinkedRules(huntId) {
  const hunt = HUNTING_QUERIES.find(h => h.id === huntId);
  if (!hunt || !hunt.linkedSigmaRules) return [];
  return hunt.linkedSigmaRules.map(id => typeof SIGMA_RULES !== 'undefined' ? SIGMA_RULES.find(r => r.id === id) : null).filter(Boolean);
}

window.HUNTING_QUERIES = HUNTING_QUERIES;
window.getHuntingByCategory = getHuntingByCategory;
window.getHuntingByTechnique = getHuntingByTechnique;
window.getHuntLinkedRules = getHuntLinkedRules;
