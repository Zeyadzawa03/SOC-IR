// Sigma Rules Database - Part 8: Threat Hunting + Additional Coverage
// Final part — includes the SIGMA_RULES merge from all parts
const SIGMA_RULES_PART8 = [

// ═══════════════════════════════════════════════════════════════
// THREAT HUNTING (6 rules)
// ═══════════════════════════════════════════════════════════════
{
  id: 'SR-0154', title: 'Threat Hunt — Long-Tail Process Analysis',
  status: 'test', severity: 'medium', author: 'SOC Platform', date: '2024-04-10', modified: '2024-12-15',
  category: 'threat-hunting',
  description: 'Proactive threat hunting query to identify rare processes by frequency — uncommon executables across the environment often indicate malware, penetration testing tools, or unauthorized software.',
  tacticId: 'TA0007', tacticName: 'Discovery', techniqueId: 'T1057', techniqueName: 'Process Discovery',
  logsource: { product: 'windows', category: 'process_creation' },
  sigmaYaml: `title: Long-Tail Process Analysis
id: th001-sigma-0154
status: test
description: Identifies rare processes across the environment
logsource:
    product: windows
    category: process_creation
detection:
    selection:
        EventID:
            - 1
            - 4688
    condition: selection | count(distinct ComputerName) by Image < 3
level: medium
tags:
    - attack.discovery
    - attack.t1057`,
  splunkQuery: `index=wineventlog (sourcetype=WinEventLog:Sysmon EventCode=1 OR sourcetype=WinEventLog:Security EventCode=4688)
| eval process=coalesce(Image,NewProcessName)
| stats dc(ComputerName) as host_count count as exec_count first(_time) as first_seen last(_time) as last_seen values(User) as users values(ComputerName) as hosts by process
| where host_count <= 2 AND exec_count < 10
| sort + host_count
| table process, host_count, exec_count, first_seen, last_seen, users, hosts`,
  qradarQuery: `SELECT Filename,
  COUNT(DISTINCT sourceip) as unique_hosts,
  COUNT(*) as total_executions,
  MIN(DATEFORMAT(starttime,'yyyy-MM-dd HH:mm')) as first_seen,
  MAX(DATEFORMAT(starttime,'yyyy-MM-dd HH:mm')) as last_seen
FROM events
WHERE CATEGORYNAME(category) ILIKE '%Process%Create%'
GROUP BY Filename
HAVING COUNT(DISTINCT sourceip) <= 2
ORDER BY total_executions ASC
LAST 7 DAYS`,
  detectionExplanation: 'Long-tail analysis surfaces the rarest executables in your environment. Processes seen on only 1-2 hosts out of thousands are statistical anomalies worth investigating — they may be malware, hacking tools, or shadow IT.',
  requiredLogs: ['Sysmon Event 1 or Windows Security 4688'],
  logConfig: 'Process creation auditing across all endpoints.',
  falsePositives: ['Specialized line-of-business applications', 'Development tools on individual workstations', 'Admin utilities on jump boxes'],
  tuning: 'Run weekly. Exclude known rare-but-legitimate tools. Focus on unsigned binaries from temp directories.',
  commonErrors: ['Large environments generate too many rare processes — filter by path and signing status'],
  responseActions: ['Investigate the rare process on the host(s) where it appeared', 'Check hash reputation', 'Verify business justification for the software'],
  threatIntel: { cves: [], cisaKev: false, campaigns: [], iocs: [] },
  references: ['https://attack.mitre.org/techniques/T1057/']
},
{
  id: 'SR-0155', title: 'Threat Hunt — Stack Counting Outbound Connections',
  status: 'test', severity: 'medium', author: 'SOC Platform', date: '2024-05-15', modified: '2024-12-15',
  category: 'threat-hunting',
  description: 'Stack-counting analysis of outbound network connections to identify unusual destination domains and IPs that may indicate C2 infrastructure.',
  tacticId: 'TA0011', tacticName: 'Command and Control', techniqueId: 'T1071.001', techniqueName: 'Web Protocols',
  logsource: { product: 'proxy' },
  sigmaYaml: `title: Stack Counting Outbound Connections
id: th002-sigma-0155
status: test
description: Stack ranks outbound destinations by frequency
logsource:
    product: proxy
detection:
    selection:
        action: allowed
    condition: selection
level: medium
tags:
    - attack.command_and_control
    - attack.t1071.001`,
  splunkQuery: `index=proxy sourcetype=proxy action=allowed
| stats dc(src_ip) as unique_sources count as total_connections first(_time) as first_seen last(_time) as last_seen by dest
| where unique_sources <= 3 AND total_connections > 20
| eval suspicion=round(total_connections/unique_sources,0)
| sort - suspicion
| table dest, unique_sources, total_connections, suspicion, first_seen, last_seen`,
  qradarQuery: `SELECT destinationip,
  COUNT(DISTINCT sourceip) as unique_sources,
  COUNT(*) as total_connections,
  MIN(DATEFORMAT(starttime,'yyyy-MM-dd HH:mm')) as first_seen,
  MAX(DATEFORMAT(starttime,'yyyy-MM-dd HH:mm')) as last_seen
FROM events
WHERE eventdirection = 'L2R'
GROUP BY destinationip
HAVING COUNT(DISTINCT sourceip) <= 3 AND COUNT(*) > 20
ORDER BY total_connections DESC
LAST 7 DAYS`,
  detectionExplanation: 'Destinations contacted by only 1-3 internal hosts but with high connection frequency are potential C2 infrastructure. Legitimate services are typically accessed by many users. C2 servers are contacted by only the infectedhost.',
  requiredLogs: ['Proxy logs', 'Firewall connection logs', 'DNS query logs'],
  logConfig: 'Full proxy logging with destination domain/IP.',
  falsePositives: ['Specialized SaaS services used by few employees', 'Personal websites accessed by individual users'],
  tuning: 'Focus on destinations with high frequency (>20 connections) but low diversity (<3 sources). Cross-reference with threat intel feeds.',
  commonErrors: ['CDN domains resolve to different IPs — use domain names instead of IPs when possible'],
  responseActions: ['Research the destination domain/IP via threat intel', 'Check domain registration (new domains are suspicious)', 'Investigate the internal hosts connecting to the destination'],
  threatIntel: { cves: [], cisaKev: false, campaigns: [], iocs: [] },
  references: ['https://attack.mitre.org/techniques/T1071/001/']
},
{
  id: 'SR-0156', title: 'Threat Hunt — Baseline Deviation for User Activity',
  status: 'test', severity: 'medium', author: 'SOC Platform', date: '2024-06-20', modified: '2024-12-10',
  category: 'threat-hunting',
  description: 'Identifies users whose activity pattern deviates significantly from their established baseline — a key indicator of compromised accounts.',
  tacticId: 'TA0001', tacticName: 'Initial Access', techniqueId: 'T1078', techniqueName: 'Valid Accounts',
  logsource: { product: 'windows', service: 'security' },
  sigmaYaml: `title: User Activity Baseline Deviation
id: th003-sigma-0156
status: test
description: Detects deviations from user baseline behavior
logsource:
    product: windows
    service: security
detection:
    selection:
        EventID: 4624
    condition: selection
level: medium
tags:
    - attack.initial_access
    - attack.t1078`,
  splunkQuery: `index=wineventlog sourcetype=WinEventLog:Security EventCode=4624 LogonType=10
| bin _time span=1d
| stats dc(ComputerName) as systems_accessed count as logins by TargetUserName, _time
| eventstats avg(systems_accessed) as avg_systems stdev(systems_accessed) as stdev_systems by TargetUserName
| eval z_score=round((systems_accessed - avg_systems) / stdev_systems, 2)
| where z_score > 3 AND systems_accessed > 3
| table _time, TargetUserName, systems_accessed, avg_systems, z_score`,
  qradarQuery: `SELECT username,
  COUNT(DISTINCT destinationip) as systems_accessed,
  COUNT(*) as total_logins
FROM events
WHERE QIDNAME(qid) ILIKE '%Logon Success%'
  AND username NOT IN ('SYSTEM', '-', 'ANONYMOUS LOGON')
GROUP BY username
HAVING COUNT(DISTINCT destinationip) > 5
ORDER BY systems_accessed DESC
LAST 7 DAYS`,
  detectionExplanation: 'Z-score analysis compares current user activity to their historical baseline. A z-score >3 means the user is accessing 3+ standard deviations more systems than normal — strong indicator of lateral movement or compromised account.',
  requiredLogs: ['Windows Security 4624 (30+ days of history for baseline)'],
  logConfig: 'Logon event auditing across all systems.',
  falsePositives: ['User role changes', 'Project-based access that legitimately varies', 'IT admins during outage resolution'],
  tuning: 'Requires 30+ days of baseline data. Z-score >3 is highly unusual. Combine with time-of-day analysis for stronger signal.',
  commonErrors: ['New users have no baseline — exclude accounts <30 days old', 'Sparse data produces unreliable z-scores'],
  responseActions: ['If z-score >3: contact the user to verify activity', 'Check for password exposure indicators', 'Review what systems were accessed and what was done', 'Enable additional monitoring on the account'],
  threatIntel: { cves: [], cisaKev: false, campaigns: [], iocs: [] },
  references: ['https://attack.mitre.org/techniques/T1078/']
},
{
  id: 'SR-0157', title: 'Threat Hunt — New Service Installation Tracking',
  status: 'test', severity: 'medium', author: 'SOC Platform', date: '2024-07-15', modified: '2024-12-10',
  category: 'threat-hunting',
  description: 'Proactive tracking of new Windows service installations across the environment to identify malicious services used for persistence or privilege escalation.',
  tacticId: 'TA0003', tacticName: 'Persistence', techniqueId: 'T1543.003', techniqueName: 'Windows Service',
  logsource: { product: 'windows', service: 'system' },
  sigmaYaml: `title: New Service Installation Tracking
id: th004-sigma-0157
status: test
description: Tracks new service installations for hunting
logsource:
    product: windows
    service: system
detection:
    selection:
        EventID: 7045
    condition: selection
level: medium
tags:
    - attack.persistence
    - attack.t1543.003`,
  splunkQuery: `index=wineventlog sourcetype=WinEventLog:System EventCode=7045
| stats count dc(ComputerName) as hosts_installed first(_time) as first_install values(ImagePath) as service_path values(ServiceType) as svc_type values(StartType) as start_type by ServiceName
| where hosts_installed <= 3
| sort - first_install
| table ServiceName, hosts_installed, service_path, svc_type, start_type, first_install`,
  qradarQuery: `SELECT "Service Name", sourceip,
  COUNT(DISTINCT sourceip) as hosts_installed,
  MIN(DATEFORMAT(starttime,'yyyy-MM-dd HH:mm')) as first_seen
FROM events
WHERE EventID = 7045
GROUP BY "Service Name", sourceip
HAVING COUNT(DISTINCT sourceip) <= 3
ORDER BY first_seen DESC
LAST 7 DAYS`,
  detectionExplanation: 'Event 7045 logs new service installation. Rare services (installed on 1-3 hosts) are suspicious — legitimate services are typically deployed to many systems. Check the service binary path and signing status.',
  requiredLogs: ['Windows System Event 7045 (Service Install)'],
  logConfig: 'Windows System event log forwarding.',
  falsePositives: ['New software installations', 'System management agent updates'],
  tuning: 'Focus on services with unusual paths (temp directories, user profiles). Track unsigned service binaries.',
  commonErrors: ['Service installation events may be high-volume during deployment windows'],
  responseActions: ['Investigate the service binary — is it signed?', 'Check the service account running the service', 'Verify with IT/deployment records'],
  threatIntel: { cves: [], cisaKev: false, campaigns: [], iocs: [] },
  references: ['https://attack.mitre.org/techniques/T1543/003/']
},
{
  id: 'SR-0158', title: 'Threat Hunt — Scheduled Task Anomaly',
  status: 'test', severity: 'medium', author: 'SOC Platform', date: '2024-08-10', modified: '2024-12-10',
  category: 'threat-hunting',
  description: 'Proactively hunts for anomalous scheduled tasks that may have been created for persistence, including tasks with encoded commands, remote URLs, or temp directory executables.',
  tacticId: 'TA0003', tacticName: 'Persistence', techniqueId: 'T1053.005', techniqueName: 'Scheduled Task',
  logsource: { product: 'windows', service: 'security' },
  sigmaYaml: `title: Scheduled Task Anomaly Hunting
id: th005-sigma-0158
status: test
description: Hunts for suspicious scheduled tasks
logsource:
    product: windows
    service: security
detection:
    selection:
        EventID: 4698
    condition: selection
level: medium
tags:
    - attack.persistence
    - attack.t1053.005`,
  splunkQuery: `index=wineventlog sourcetype=WinEventLog:Security EventCode=4698
| where match(TaskContent,"(?i)(powershell|cmd\\.exe|http|base64|\\\\Temp\\\\|\\\\tmp\\\\|AppData)")
| stats count values(TaskName) as tasks values(TaskContent) as content by SubjectUserName, ComputerName, _time
| table _time, SubjectUserName, ComputerName, tasks, content, count`,
  qradarQuery: `SELECT username, sourceip,
  QIDNAME(qid) as event_name,
  COUNT(*) as task_events
FROM events
WHERE EventID = 4698
GROUP BY username, sourceip, qid
ORDER BY starttime DESC
LAST 7 DAYS`,
  detectionExplanation: 'Event 4698 logs scheduled task creation with the full task XML. Hunt for: PowerShell/cmd in task actions, encoded commands, HTTP URLs for downloading, executable paths in temp directories.',
  requiredLogs: ['Windows Security 4698 (Scheduled Task Created)', 'Sysmon Event 1 for schtasks.exe'],
  logConfig: 'Object access auditing for scheduled task creation.',
  falsePositives: ['Software installation creating tasks', 'Windows Update scheduled tasks', 'IT automation tasks'],
  tuning: 'Focus on tasks created by non-admin users or containing suspicious keywords (encoded, download, temp).',
  commonErrors: ['Task content in event 4698 is XML — parsing requires extraction'],
  responseActions: ['Review the scheduled task action and trigger', 'Check if the task was created by a known automation', 'Remove suspicious tasks and investigate the creator'],
  threatIntel: { cves: [], cisaKev: false, campaigns: [], iocs: [] },
  references: ['https://attack.mitre.org/techniques/T1053/005/']
},
{
  id: 'SR-0159', title: 'Threat Hunt — Newly Registered Domain Connections',
  status: 'test', severity: 'medium', author: 'SOC Platform', date: '2024-09-15', modified: '2024-12-10',
  category: 'threat-hunting',
  description: 'Identifies connections to newly registered domains (NRDs) which are commonly used for phishing campaigns, malware infrastructure, and C2 communication.',
  tacticId: 'TA0011', tacticName: 'Command and Control', techniqueId: 'T1568', techniqueName: 'Dynamic Resolution',
  logsource: { product: 'proxy' },
  sigmaYaml: `title: Newly Registered Domain Connections
id: th006-sigma-0159
status: test
description: Detects connections to newly registered domains
logsource:
    product: proxy
detection:
    selection:
        action: allowed
    condition: selection
level: medium
tags:
    - attack.command_and_control
    - attack.t1568`,
  splunkQuery: `index=proxy sourcetype=proxy action=allowed
| lookup whois_age domain as dest OUTPUT domain_age
| where domain_age < 30 AND isnotnull(domain_age)
| stats count dc(src_ip) as internal_hosts values(src_ip) as sources by dest, domain_age, _time
| sort - count
| table _time, dest, domain_age, internal_hosts, sources, count`,
  qradarQuery: `SELECT destinationip, url,
  COUNT(DISTINCT sourceip) as unique_hosts,
  COUNT(*) as connection_count
FROM events
WHERE eventdirection = 'L2R'
GROUP BY destinationip, url
ORDER BY connection_count DESC
LAST 24 HOURS`,
  detectionExplanation: 'Newly registered domains (<30 days old) are heavily used in attacks. Legitimate businesses have established domains. Enriching proxy/DNS logs with domain WHOIS age reveals connections to suspicious infrastructure.',
  requiredLogs: ['Proxy logs', 'DNS query logs', 'Domain age enrichment feed (WHOIS)'],
  logConfig: 'Proxy with domain logging. Integrate domain age lookup or threat intel feed.',
  falsePositives: ['Legitimate new startup websites', 'Marketing campaign landing pages'],
  tuning: 'Integrate domain age enrichment. Domains <7 days are highest risk. Correlate with first-seen analysis.',
  commonErrors: ['Without domain age enrichment, this query requires external WHOIS lookup integration'],
  responseActions: ['Research the domain (WHOIS, VirusTotal, URLhaus)', 'Block if confirmed malicious', 'Investigate the internal hosts that connected'],
  threatIntel: { cves: [], cisaKev: false, campaigns: [], iocs: [] },
  references: ['https://attack.mitre.org/techniques/T1568/']
},

// ═══════════════════════════════════════════════════════════════
// ADDITIONAL DATA EXFILTRATION (3 rules for extra coverage)
// ═══════════════════════════════════════════════════════════════
{
  id: 'SR-0160', title: 'Cloud Storage Upload — Potential Exfiltration',
  status: 'stable', severity: 'high', author: 'SOC Platform', date: '2024-05-10', modified: '2024-12-15',
  category: 'data-exfiltration',
  description: 'Detects data exfiltration to cloud storage services by monitoring for large uploads to Dropbox, Google Drive, OneDrive personal, Mega, and other file sharing platforms.',
  tacticId: 'TA0010', tacticName: 'Exfiltration', techniqueId: 'T1567.002', techniqueName: 'Exfiltration to Cloud Storage',
  logsource: { product: 'proxy' },
  sigmaYaml: `title: Cloud Storage Upload Exfiltration
id: de001-sigma-0160
status: stable
description: Detects uploads to personal cloud storage
logsource:
    product: proxy
detection:
    selection:
        url|contains:
            - 'dropbox.com/upload'
            - 'drive.google.com/upload'
            - 'mega.nz'
            - 'wetransfer.com'
            - 'sendspace.com'
            - 'mediafire.com'
    condition: selection
level: high
tags:
    - attack.exfiltration
    - attack.t1567.002`,
  splunkQuery: `index=proxy sourcetype=proxy (url="*dropbox.com*" OR url="*drive.google.com/upload*" OR url="*mega.nz*" OR url="*wetransfer.com*" OR url="*sendspace.com*")
| where bytes_out > 10000000
| eval size_mb=round(bytes_out/1024/1024,2)
| stats sum(size_mb) as total_mb count as uploads by src_ip, user, url, _time
| where total_mb > 50
| table _time, user, src_ip, url, uploads, total_mb`,
  qradarQuery: `SELECT sourceip, username, url,
  SUM(LONG(bytesout)) as total_bytes_out,
  COUNT(*) as upload_count
FROM events
WHERE (url ILIKE '%dropbox.com%' OR url ILIKE '%drive.google.com/upload%'
  OR url ILIKE '%mega.nz%' OR url ILIKE '%wetransfer.com%')
  AND LONG(bytesout) > 10000000
GROUP BY sourceip, username, url
HAVING SUM(LONG(bytesout)) > 50000000
ORDER BY total_bytes_out DESC
LAST 24 HOURS`,
  detectionExplanation: 'Uploading >50MB to personal cloud storage services indicates potential data exfiltration. Focus on personal accounts (not corporate OneDrive). Correlate with DLP alerts for sensitive content.',
  requiredLogs: ['Proxy logs with URL and byte count', 'CASB logs', 'DLP alerts'],
  logConfig: 'Proxy with SSL inspection for cloud storage domains. CASB integration.',
  falsePositives: ['Legitimate file sharing for work purposes', 'Cloud backup services'],
  tuning: 'Set bytes threshold based on environment. Focus on personal (non-corporate) cloud storage. Correlate with DLP classification.',
  commonErrors: ['HTTPS inspection required to see URLs to cloud storage', 'Personal vs corporate cloud accounts may use same domain'],
  responseActions: ['Interview the user about the upload purpose', 'Check if uploaded files contain sensitive data', 'Block personal cloud storage if policy allows', 'Implement CASB for cloud access control'],
  threatIntel: { cves: [], cisaKev: false, campaigns: [], iocs: [] },
  references: ['https://attack.mitre.org/techniques/T1567/002/']
},
{
  id: 'SR-0161', title: 'Large Outbound Data Transfer',
  status: 'stable', severity: 'high', author: 'SOC Platform', date: '2024-06-15', modified: '2024-12-10',
  category: 'data-exfiltration',
  description: 'Detects unusually large outbound data transfers that may indicate bulk data exfiltration — monitors total bytes transferred per source per destination.',
  tacticId: 'TA0010', tacticName: 'Exfiltration', techniqueId: 'T1048', techniqueName: 'Exfiltration Over Alternative Protocol',
  logsource: { product: 'firewall' },
  sigmaYaml: `title: Large Outbound Data Transfer
id: de002-sigma-0161
status: stable
description: Detects unusually large data transfers outbound
logsource:
    product: firewall
detection:
    selection:
        direction: outbound
    condition: selection | sum(bytes_out) by src_ip > 500000000
level: high
tags:
    - attack.exfiltration
    - attack.t1048`,
  splunkQuery: `index=firewall sourcetype=firewall direction=outbound
| bin _time span=1h
| stats sum(bytes_out) as total_bytes dc(dest_ip) as unique_dests by src_ip, _time
| eval total_gb=round(total_bytes/1073741824,2)
| where total_gb > 0.5
| sort - total_bytes
| table _time, src_ip, total_gb, unique_dests`,
  qradarQuery: `SELECT sourceip,
  SUM(LONG(bytesout)) as total_bytes_out,
  COUNT(DISTINCT destinationip) as unique_destinations
FROM events
WHERE eventdirection = 'L2R'
GROUP BY sourceip
HAVING SUM(LONG(bytesout)) > 500000000
ORDER BY total_bytes_out DESC
LAST 4 HOURS`,
  detectionExplanation: '500MB+ outbound from a single host in 1 hour is unusual for workstations. Track baseline data volumes per user/host and alert on deviations. Focus on data leaving to non-business destinations.',
  requiredLogs: ['Firewall logs with byte counts', 'Proxy logs', 'Network flow data'],
  logConfig: 'Firewall with per-session byte count logging. NetFlow/IPFIX collection.',
  falsePositives: ['Cloud backup operations', 'Large file uploads to business partners', 'Video conferencing uploads'],
  tuning: 'Baseline per-host outbound volumes. 0.5GB/hour is a starting threshold — adjust for your environment.',
  commonErrors: ['Video and cloud services generate significant outbound traffic', 'CDN uploads for web teams are legitimate'],
  responseActions: ['Identify what data was transferred', 'Verify the destination is a known business partner/service', 'If unauthorized: block and investigate', 'Implement DLP egress controls'],
  threatIntel: { cves: [], cisaKev: false, campaigns: [], iocs: [] },
  references: ['https://attack.mitre.org/techniques/T1048/']
},
{
  id: 'SR-0162', title: 'Steganography or Covert Channel Indicators',
  status: 'test', severity: 'medium', author: 'SOC Platform', date: '2024-07-20', modified: '2024-12-10',
  category: 'data-exfiltration',
  description: 'Detects potential covert channel or steganographic data exfiltration by monitoring for unusual image/media uploads, DNS TXT record data encoding, and other side-channel techniques.',
  tacticId: 'TA0010', tacticName: 'Exfiltration', techniqueId: 'T1001', techniqueName: 'Data Obfuscation',
  logsource: { product: 'proxy' },
  sigmaYaml: `title: Steganography / Covert Channel Indicators
id: de003-sigma-0162
status: test
description: Detects covert channel data exfiltration
logsource:
    product: proxy
detection:
    selection:
        url|endswith:
            - '.png'
            - '.jpg'
            - '.bmp'
        bytes_out|gt: 5000000
    condition: selection
level: medium
tags:
    - attack.exfiltration
    - attack.t1001`,
  splunkQuery: `index=proxy sourcetype=proxy (url="*.png" OR url="*.jpg" OR url="*.bmp") method=POST
| where bytes_out > 5000000
| eval size_mb=round(bytes_out/1024/1024,2)
| stats count sum(size_mb) as total_mb by src_ip, dest, _time
| where total_mb > 10
| table _time, src_ip, dest, count, total_mb`,
  qradarQuery: `SELECT sourceip, url,
  SUM(LONG(bytesout)) as total_upload,
  COUNT(*) as uploads
FROM events
WHERE (url ILIKE '%.png' OR url ILIKE '%.jpg' OR url ILIKE '%.bmp')
  AND LONG(bytesout) > 5000000
GROUP BY sourceip, url
HAVING SUM(LONG(bytesout)) > 10000000
ORDER BY total_upload DESC
LAST 24 HOURS`,
  detectionExplanation: 'Steganography hides data within images. Large image uploads (>5MB) via POST to non-business domains may indicate data exfiltration. DNS TXT records can also encode data. These techniques bypass content-based DLP.',
  requiredLogs: ['Proxy logs with URL and byte count', 'DNS TXT record logs', 'Email attachment logs'],
  logConfig: 'Proxy with file type detection and byte count. DNS query logging.',
  falsePositives: ['Photography uploads', 'Social media image posting', 'Cloud photo backup'],
  tuning: 'Focus on large image uploads to unusual destinations. Correlate with DLP alerts.',
  commonErrors: ['Steganography is very difficult to detect without file analysis', 'Image hosting sites receive legitimate large uploads'],
  responseActions: ['Analyze the uploaded images for embedded data', 'Block the destination if confirmed as exfiltration channel', 'Investigate the source user/host'],
  threatIntel: { cves: [], cisaKev: false, campaigns: [], iocs: [] },
  references: ['https://attack.mitre.org/techniques/T1001/']
}
];

// ═══════════════════════════════════════════════════════════════
// FINAL MERGE — Combine all parts into unified SIGMA_RULES array
// ═══════════════════════════════════════════════════════════════
const SIGMA_RULES = [
  ...(typeof SIGMA_RULES_PART1 !== 'undefined' ? SIGMA_RULES_PART1 : []),
  ...(typeof SIGMA_RULES_PART2 !== 'undefined' ? SIGMA_RULES_PART2 : []),
  ...(typeof SIGMA_RULES_PART3 !== 'undefined' ? SIGMA_RULES_PART3 : []),
  ...(typeof SIGMA_RULES_PART4 !== 'undefined' ? SIGMA_RULES_PART4 : []),
  ...(typeof SIGMA_RULES_PART5 !== 'undefined' ? SIGMA_RULES_PART5 : []),
  ...(typeof SIGMA_RULES_PART6 !== 'undefined' ? SIGMA_RULES_PART6 : []),
  ...(typeof SIGMA_RULES_PART7 !== 'undefined' ? SIGMA_RULES_PART7 : []),
  ...(typeof SIGMA_RULES_PART8 !== 'undefined' ? SIGMA_RULES_PART8 : []),
  ...(typeof SIGMA_RULES_PART9 !== 'undefined' ? SIGMA_RULES_PART9 : []),
  ...(typeof SIGMA_RULES_PART10 !== 'undefined' ? SIGMA_RULES_PART10 : [])
];
