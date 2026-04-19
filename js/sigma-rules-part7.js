// Sigma Rules Database - Part 7: Network Anomalies, Endpoint Anomalies, Linux Threats, Windows Specific
// 24 new rules across 4 categories
const SIGMA_RULES_PART7 = [

// ═══════════════════════════════════════════════════════════════
// NETWORK ANOMALIES (6 rules)
// ═══════════════════════════════════════════════════════════════
{
  id: 'SR-0130', title: 'DNS Tunneling Detection',
  status: 'stable', severity: 'high', author: 'SOC Platform', date: '2024-03-15', modified: '2024-12-15',
  category: 'network-anomalies',
  description: 'Detects DNS tunneling by monitoring for abnormally long DNS queries, high query volume, or unusual TXT record requests used to tunnel data through DNS.',
  tacticId: 'TA0011', tacticName: 'Command and Control', techniqueId: 'T1071.004', techniqueName: 'DNS',
  logsource: { product: 'dns' },
  sigmaYaml: `title: DNS Tunneling Detection
id: na001-sigma-0130
status: stable
description: Detects DNS tunneling via long queries or high volume
logsource:
    product: dns
detection:
    selection_long:
        query|re: '.{50,}'
    selection_txt:
        query_type: 'TXT'
    condition: selection_long or selection_txt
level: high
tags:
    - attack.command_and_control
    - attack.t1071.004`,
  splunkQuery: `index=dns sourcetype=dns
| eval query_len=len(query)
| where query_len > 50 OR query_type="TXT"
| bin _time span=15m
| stats count as queries avg(query_len) as avg_length max(query_len) as max_length dc(query) as unique_queries by src_ip, _time
| where queries > 100 OR avg_length > 40
| table _time, src_ip, queries, avg_length, max_length, unique_queries`,
  qradarQuery: `SELECT sourceip,
  COUNT(*) as dns_queries,
  COUNT(DISTINCT "DNS Request Domain") as unique_domains
FROM events
WHERE CATEGORYNAME(category) ILIKE '%DNS%'
  AND (LENGTH("DNS Request Domain") > 50 OR eventname ILIKE '%TXT%')
GROUP BY sourceip
HAVING COUNT(*) > 100
ORDER BY dns_queries DESC
LAST 2 HOURS`,
  detectionExplanation: 'DNS tunneling encodes data in DNS queries. Indicators: (1) queries >50 chars (encoded data), (2) high TXT record requests (data exfiltration), (3) high query volume to single domain, (4) high entropy in subdomain labels.',
  requiredLogs: ['DNS server query logs', 'Sysmon Event 22', 'Network DNS traffic capture'],
  logConfig: 'DNS server diagnostic logging or Sysmon Event 22 (DNS Query).',
  falsePositives: ['CDN domains with long CNAME chains', 'DKIM/SPF TXT lookups', 'Legitimate API services using long subdomains'],
  tuning: 'Focus on queries >50 chars to non-CDN domains. Calculate Shannon entropy of subdomains — high entropy indicates encoding.',
  commonErrors: ['CDN and cloud service domains legitimately use long subdomains', 'DNS cache may reduce visible query volume'],
  responseActions: ['Identify the tunneling destination domain', 'Block the domain at DNS/proxy', 'Investigate the source host for malware', 'Analyze tunnel payload if captured'],
  threatIntel: { cves: [], cisaKev: false, campaigns: ['Volt Typhoon'], iocs: [] },
  references: ['https://attack.mitre.org/techniques/T1071/004/']
},
{
  id: 'SR-0131', title: 'Beaconing Detection — Periodic C2 Communication',
  status: 'stable', severity: 'high', author: 'SOC Platform', date: '2024-04-20', modified: '2024-12-15',
  category: 'network-anomalies',
  description: 'Detects C2 beaconing by identifying regular, periodic network connections to the same destination with consistent intervals, characteristic of implant check-in behavior.',
  tacticId: 'TA0011', tacticName: 'Command and Control', techniqueId: 'T1071.001', techniqueName: 'Web Protocols',
  logsource: { product: 'proxy' },
  sigmaYaml: `title: C2 Beaconing Detection
id: na002-sigma-0131
status: stable
description: Detects periodic beaconing patterns
logsource:
    product: proxy
detection:
    selection:
        action: allowed
    condition: selection | count() by src_ip, dest > 50
level: high
tags:
    - attack.command_and_control
    - attack.t1071.001`,
  splunkQuery: `index=proxy sourcetype=proxy action=allowed
| bin _time span=1h
| stats count as connections dc(dest_port) as ports stdev(eval(relative_time(_time,"-1h"))) as time_std by src_ip, dest, _time
| where connections > 50 AND ports <= 2
| eval beacon_score=if(time_std<300,"HIGH",if(time_std<600,"MEDIUM","LOW"))
| where beacon_score IN ("HIGH","MEDIUM")
| table _time, src_ip, dest, connections, ports, beacon_score, time_std`,
  qradarQuery: `SELECT sourceip, destinationip,
  COUNT(*) as connection_count,
  COUNT(DISTINCT destinationport) as unique_ports
FROM events
WHERE CATEGORYNAME(highlevelcategory) = 'Network'
  AND eventdirection = 'L2R'
GROUP BY sourceip, destinationip
HAVING COUNT(*) > 50 AND COUNT(DISTINCT destinationport) <= 2
ORDER BY connection_count DESC
LAST 4 HOURS`,
  detectionExplanation: 'C2 implants beacon at regular intervals (e.g., every 60s with 10% jitter). Detection: many connections to same dest with low port diversity and regular timing. Low standard deviation in connection timing indicates fixed-interval beaconing.',
  requiredLogs: ['Proxy logs', 'Firewall connection logs', 'Network flow data'],
  logConfig: 'Proxy logging with timestamp precision. Firewall session logging.',
  falsePositives: ['Software update checks', 'Cloud service heartbeats', 'NTP synchronization'],
  tuning: 'Calculate time standard deviation between connections. Stdev <300s with 50+ connections indicates beaconing. Exclude known update/heartbeat domains.',
  commonErrors: ['Jitter in C2 beacons reduces timing regularity', 'Connection pooling may mask individual beacon requests'],
  responseActions: ['Block the destination domain/IP', 'Investigate the source host for malware', 'Capture and analyze beacon payload', 'Check for data exfiltration over the same channel'],
  threatIntel: { cves: [], cisaKev: false, campaigns: ['Volt Typhoon', 'ALPHV/BlackCat Ransomware'], iocs: [] },
  references: ['https://attack.mitre.org/techniques/T1071/001/']
},
{
  id: 'SR-0132', title: 'ICMP Tunneling or Exfiltration',
  status: 'test', severity: 'medium', author: 'SOC Platform', date: '2024-05-15', modified: '2024-12-10',
  category: 'network-anomalies',
  description: 'Detects ICMP tunneling by monitoring for abnormally large ICMP packets or high-volume ICMP traffic to a single destination, used for covert data exfiltration.',
  tacticId: 'TA0010', tacticName: 'Exfiltration', techniqueId: 'T1048.003', techniqueName: 'Exfiltration Over Unencrypted Non-C2 Protocol',
  logsource: { product: 'firewall' },
  sigmaYaml: `title: ICMP Tunneling Detection
id: na003-sigma-0132
status: test
description: Detects ICMP tunneling via large packets or high volume
logsource:
    product: firewall
detection:
    selection:
        protocol: ICMP
    selection_large:
        bytes_out|gt: 1000
    condition: selection and selection_large
level: medium
tags:
    - attack.exfiltration
    - attack.t1048.003`,
  splunkQuery: `index=firewall sourcetype=firewall protocol=ICMP
| where bytes_out > 1000 OR bytes_in > 1000
| bin _time span=15m
| stats count as icmp_packets sum(bytes_out) as total_bytes_out avg(bytes_out) as avg_size by src_ip, dest_ip, _time
| where icmp_packets > 50 OR total_bytes_out > 100000
| table _time, src_ip, dest_ip, icmp_packets, total_bytes_out, avg_size`,
  qradarQuery: `SELECT sourceip, destinationip,
  COUNT(*) as icmp_packets,
  SUM(LONG(bytesout)) as total_bytes
FROM events
WHERE "Network Protocol" = 'ICMP'
  AND LONG(bytesout) > 1000
GROUP BY sourceip, destinationip
HAVING COUNT(*) > 50
ORDER BY total_bytes DESC
LAST 2 HOURS`,
  detectionExplanation: 'Normal ICMP echo packets are 64-84 bytes. ICMP tunneling tools (icmpsh, ptunnel) embed data in ICMP payloads, creating packets >1000 bytes. High volume ICMP to a single destination also indicates tunneling.',
  requiredLogs: ['Firewall logs with packet size', 'IDS/IPS ICMP alerts', 'Network flow data'],
  logConfig: 'Firewall logging for ICMP with byte counts. IDS signatures for ICMP tunneling.',
  falsePositives: ['Path MTU discovery using large ICMP', 'Network diagnostic tools (ping with -l flag)'],
  tuning: 'Alert on ICMP packets >1000 bytes or >50 ICMP packets/15min to single dest. Normal ping is <100 bytes.',
  commonErrors: ['Some firewalls dont log ICMP packet sizes', 'ICMP may be blocked entirely at perimeter'],
  responseActions: ['Block ICMP to the destination', 'Investigate source host for tunneling tools', 'Capture and analyze ICMP payload data', 'Review egress filtering policies'],
  threatIntel: { cves: [], cisaKev: false, campaigns: [], iocs: [] },
  references: ['https://attack.mitre.org/techniques/T1048/003/']
},
{
  id: 'SR-0133', title: 'Unusual Outbound Port Usage',
  status: 'stable', severity: 'medium', author: 'SOC Platform', date: '2024-06-10', modified: '2024-12-10',
  category: 'network-anomalies',
  description: 'Detects outbound connections on unusual ports that may indicate C2 channels, data exfiltration tunnels, or unauthorized services bypassing security controls.',
  tacticId: 'TA0011', tacticName: 'Command and Control', techniqueId: 'T1571', techniqueName: 'Non-Standard Port',
  logsource: { product: 'firewall' },
  sigmaYaml: `title: Unusual Outbound Port Usage
id: na004-sigma-0133
status: stable
description: Detects outbound connections on non-standard ports
logsource:
    product: firewall
detection:
    selection:
        action: allowed
        direction: outbound
    filter_common:
        dest_port:
            - 80
            - 443
            - 53
            - 25
            - 587
            - 993
            - 995
            - 22
            - 3389
    condition: selection and not filter_common
level: medium
tags:
    - attack.command_and_control
    - attack.t1571`,
  splunkQuery: `index=firewall sourcetype=firewall action=allowed direction=outbound
| where NOT dest_port IN (80,443,53,25,587,993,995,22,3389,8080,8443)
| bin _time span=1h
| stats count dc(dest_ip) as unique_dests values(dest_port) as ports by src_ip, _time
| where count > 20
| sort - count
| table _time, src_ip, count, unique_dests, ports`,
  qradarQuery: `SELECT sourceip, destinationip, destinationport,
  COUNT(*) as connections
FROM events
WHERE CATEGORYNAME(highlevelcategory) = 'Firewall'
  AND eventdirection = 'L2R'
  AND destinationport NOT IN (80,443,53,25,587,993,995,22,3389)
GROUP BY sourceip, destinationip, destinationport
HAVING COUNT(*) > 20
ORDER BY connections DESC
LAST 4 HOURS`,
  detectionExplanation: 'C2 frameworks commonly use non-standard ports (4444, 8888, 9090, etc.). Outbound connections on these ports from user workstations are suspicious. Baseline normal outbound port usage and alert on anomalies.',
  requiredLogs: ['Firewall connection logs', 'Proxy logs', 'Network flow data'],
  logConfig: 'Firewall egress logging with port and direction information.',
  falsePositives: ['VPN clients using non-standard ports', 'Development tools with custom ports', 'Gaming/streaming applications'],
  tuning: 'Exclude known business application ports. Focus on workstations — servers have more varied port needs. Alert on known C2 ports (4444, 8888, 9090, 1337).',
  commonErrors: ['Port-based detection is easily evaded by using port 443', 'Application-layer inspection provides better visibility'],
  responseActions: ['Identify what application is using the non-standard port', 'Block if unauthorized', 'Investigate the destination for C2 indicators'],
  threatIntel: { cves: [], cisaKev: false, campaigns: [], iocs: [] },
  references: ['https://attack.mitre.org/techniques/T1571/']
},
{
  id: 'SR-0134', title: 'Protocol Anomaly — HTTP on Non-Standard Port',
  status: 'test', severity: 'medium', author: 'SOC Platform', date: '2024-07-15', modified: '2024-12-10',
  category: 'network-anomalies',
  description: 'Detects HTTP traffic on non-standard ports or non-HTTP protocols on port 80/443, indicating potential tunneling, C2, or protocol misuse.',
  tacticId: 'TA0011', tacticName: 'Command and Control', techniqueId: 'T1090', techniqueName: 'Proxy',
  logsource: { product: 'proxy' },
  sigmaYaml: `title: Protocol Anomaly - HTTP on Non-Standard Port
id: na005-sigma-0134
status: test
description: Detects protocol mismatches on network connections
logsource:
    product: proxy
detection:
    selection_http_nonstandard:
        protocol: HTTP
        dest_port|not:
            - 80
            - 443
            - 8080
            - 8443
    condition: selection_http_nonstandard
level: medium
tags:
    - attack.command_and_control
    - attack.t1090`,
  splunkQuery: `index=proxy sourcetype=proxy protocol=HTTP
| where NOT dest_port IN (80,443,8080,8443,8000,3128)
| stats count dc(dest_ip) as unique_dests values(dest_port) as ports by src_ip, _time
| where count > 10
| table _time, src_ip, count, unique_dests, ports`,
  qradarQuery: `SELECT sourceip, destinationip, destinationport,
  COUNT(*) as anomaly_count
FROM events
WHERE "Network Protocol" ILIKE '%HTTP%'
  AND destinationport NOT IN (80,443,8080,8443)
GROUP BY sourceip, destinationip, destinationport
HAVING COUNT(*) > 10
ORDER BY anomaly_count DESC
LAST 4 HOURS`,
  detectionExplanation: 'HTTP on non-standard ports may indicate C2 frameworks (Cobalt Strike on port 8443, Metasploit on 4444). Protocol-port mismatches bypass port-based firewalls. Deep packet inspection can detect these anomalies.',
  requiredLogs: ['Proxy/NGFW logs with protocol detection', 'IDS/IPS protocol anomaly alerts'],
  logConfig: 'Next-generation firewall with application identification. Proxy with protocol detection.',
  falsePositives: ['Development servers on custom ports', 'IoT devices with embedded web servers'],
  tuning: 'Focus on workstation sources. Exclude known development infrastructure. Alert on known C2 framework port/protocol combinations.',
  commonErrors: ['Without DPI/NGFW, protocol identification is limited to port-based assumptions'],
  responseActions: ['Investigate the destination service', 'Check for C2 indicators in traffic', 'Block if not a legitimate business service'],
  threatIntel: { cves: [], cisaKev: false, campaigns: [], iocs: [] },
  references: ['https://attack.mitre.org/techniques/T1090/']
},
{
  id: 'SR-0135', title: 'DDoS Indicator — Inbound Connection Flood',
  status: 'test', severity: 'high', author: 'SOC Platform', date: '2024-08-20', modified: '2024-12-10',
  category: 'network-anomalies',
  description: 'Detects potential DDoS attacks by monitoring for sudden spikes in inbound connections from many unique source IPs targeting a single destination.',
  tacticId: 'TA0040', tacticName: 'Impact', techniqueId: 'T1499', techniqueName: 'Endpoint Denial of Service',
  logsource: { product: 'firewall' },
  sigmaYaml: `title: DDoS Indicator - Inbound Connection Flood
id: na006-sigma-0135
status: test
description: Detects connection flood indicating DDoS
logsource:
    product: firewall
detection:
    selection:
        direction: inbound
    condition: selection | count(distinct src_ip) by dest_ip > 1000
level: high
tags:
    - attack.impact
    - attack.t1499`,
  splunkQuery: `index=firewall sourcetype=firewall direction=inbound
| bin _time span=5m
| stats dc(src_ip) as unique_sources count as total_connections by dest_ip, dest_port, _time
| where unique_sources > 1000
| eval attack_type=case(dest_port=80 OR dest_port=443,"HTTP_flood",dest_port=53,"DNS_amplification",true(),"volumetric")
| table _time, dest_ip, dest_port, unique_sources, total_connections, attack_type`,
  qradarQuery: `SELECT destinationip, destinationport,
  COUNT(DISTINCT sourceip) as unique_sources,
  COUNT(*) as total_connections
FROM events
WHERE eventdirection = 'R2L'
GROUP BY destinationip, destinationport
HAVING COUNT(DISTINCT sourceip) > 1000
ORDER BY total_connections DESC
LAST 1 HOURS`,
  detectionExplanation: '1000+ unique source IPs targeting a single destination in 5 minutes indicates DDoS. Types: HTTP flood (port 80/443), DNS amplification (port 53), SYN flood (many half-open connections).',
  requiredLogs: ['Perimeter firewall logs', 'Load balancer logs', 'CDN/DDoS protection logs'],
  logConfig: 'Firewall with connection rate logging. CDN analytics.',
  falsePositives: ['Flash crowd events (product launch, viral content)', 'CDN cache invalidation causing origin flood'],
  tuning: 'Threshold varies by baseline traffic. Set at 5-10x normal peak. Correlate with service availability monitoring.',
  commonErrors: ['DDoS may overwhelm SIEM log ingestion', 'Upstream mitigation (CDN) may prevent logs from reaching SIEM'],
  responseActions: ['Activate DDoS mitigation (CDN scrubbing)', 'Enable rate limiting at firewall/LB', 'Contact upstream provider for blackhole routing', 'Document attack vectors for post-incident analysis'],
  threatIntel: { cves: [], cisaKev: false, campaigns: [], iocs: [] },
  references: ['https://attack.mitre.org/techniques/T1499/']
},

// ═══════════════════════════════════════════════════════════════
// ENDPOINT ANOMALIES (6 rules)
// ═══════════════════════════════════════════════════════════════
{
  id: 'SR-0136', title: 'Unsigned Binary Execution from Temp Directory',
  status: 'stable', severity: 'high', author: 'SOC Platform', date: '2024-03-10', modified: '2024-12-15',
  category: 'endpoint-anomalies',
  description: 'Detects execution of unsigned or untrusted binaries from temporary directories — a common malware staging and execution pattern.',
  tacticId: 'TA0002', tacticName: 'Execution', techniqueId: 'T1204.002', techniqueName: 'Malicious File',
  logsource: { product: 'windows', category: 'process_creation' },
  sigmaYaml: `title: Unsigned Binary from Temp Directory
id: ea001-sigma-0136
status: stable
description: Detects unsigned executables running from temp paths
logsource:
    product: windows
    category: process_creation
detection:
    selection:
        Image|contains:
            - '\\\\Temp\\\\'
            - '\\\\tmp\\\\'
            - '\\\\AppData\\\\Local\\\\Temp\\\\'
        Image|endswith:
            - '.exe'
            - '.scr'
            - '.com'
    filter:
        Image|contains:
            - '\\\\Microsoft\\\\'
            - '\\\\Windows\\\\'
    condition: selection and not filter
level: high
tags:
    - attack.execution
    - attack.t1204.002`,
  splunkQuery: `index=wineventlog sourcetype=WinEventLog:Sysmon EventCode=1
| where match(Image,"(?i)(\\\\Temp\\\\|\\\\tmp\\\\|AppData\\\\Local\\\\Temp)") AND match(Image,"(?i)\\.(exe|scr|com)$")
| where NOT match(Image,"(?i)(Microsoft|Windows\\\\)")
| stats count values(Image) as executables values(Hashes) as hashes by ComputerName, User, _time
| table _time, ComputerName, User, executables, hashes, count`,
  qradarQuery: `SELECT sourceip, username,
  Filename,
  COUNT(*) as exec_count
FROM events
WHERE CATEGORYNAME(category) ILIKE '%Process%Create%'
  AND (Filename ILIKE '%\\Temp\\%' OR Filename ILIKE '%\\tmp\\%')
  AND (Filename ILIKE '%.exe' OR Filename ILIKE '%.scr')
  AND Filename NOT ILIKE '%Microsoft%'
GROUP BY sourceip, username, Filename
ORDER BY starttime DESC
LAST 24 HOURS`,
  detectionExplanation: 'Malware commonly drops payloads to %TEMP% for execution. Legitimate software installations may use temp directories briefly, but persistent execution from temp paths is suspicious. Check binary signing status and hash reputation.',
  requiredLogs: ['Sysmon Event 1', 'Windows Security 4688', 'EDR process telemetry'],
  logConfig: 'Sysmon with process creation and hash capture.',
  falsePositives: ['Software installers running from temp', 'Browser-downloaded executables', 'Windows Update temporary files'],
  tuning: 'Exclude known Microsoft/Windows paths. Check hash against VirusTotal. Focus on unsigned binaries.',
  commonErrors: ['High volume of legitimate temp executions in dev environments', 'Some installers legitimately run from temp'],
  responseActions: ['Submit hash to VirusTotal/sandbox', 'Check binary signing status', 'If malicious: isolate host, investigate delivery mechanism', 'Block hash across endpoints'],
  threatIntel: { cves: [], cisaKev: false, campaigns: [], iocs: [] },
  references: ['https://attack.mitre.org/techniques/T1204/002/']
},
{
  id: 'SR-0137', title: 'Process Injection via CreateRemoteThread',
  status: 'stable', severity: 'high', author: 'SOC Platform', date: '2024-04-15', modified: '2024-12-15',
  category: 'endpoint-anomalies',
  description: 'Detects process injection via CreateRemoteThread API call, commonly used by malware to inject code into legitimate processes for evasion and persistence.',
  tacticId: 'TA0005', tacticName: 'Defense Evasion', techniqueId: 'T1055.003', techniqueName: 'Thread Execution Hijacking',
  logsource: { product: 'windows', category: 'process_creation' },
  sigmaYaml: `title: Process Injection via CreateRemoteThread
id: ea002-sigma-0137
status: stable
description: Detects CreateRemoteThread injection
logsource:
    product: windows
    category: process_access
detection:
    selection:
        EventID: 8
    filter:
        SourceImage|endswith:
            - '\\\\csrss.exe'
            - '\\\\lsass.exe'
            - '\\\\svchost.exe'
            - '\\\\services.exe'
    condition: selection and not filter
level: high
tags:
    - attack.defense_evasion
    - attack.t1055.003`,
  splunkQuery: `index=wineventlog sourcetype=WinEventLog:Sysmon EventCode=8
| where NOT match(SourceImage,"(?i)(csrss|lsass|svchost|services|MsMpEng|WerFault)\\.exe$")
| stats count values(TargetImage) as targets values(SourceImage) as injectors by ComputerName, SourceUser, _time
| table _time, ComputerName, SourceUser, injectors, targets, count`,
  qradarQuery: `SELECT sourceip, username,
  QIDNAME(qid) as event_name,
  COUNT(*) as injection_events
FROM events
WHERE QIDNAME(qid) ILIKE '%CreateRemoteThread%'
  AND "Source Process" NOT ILIKE '%csrss.exe'
  AND "Source Process" NOT ILIKE '%svchost.exe'
GROUP BY sourceip, username, qid
HAVING COUNT(*) > 0
ORDER BY injection_events DESC
LAST 24 HOURS`,
  detectionExplanation: 'Sysmon Event 8 (CreateRemoteThread) detects one process creating a thread in another process — the core mechanism of process injection. Legitimate uses exist (debugging, AV scanning) but non-system processes doing this is suspicious.',
  requiredLogs: ['Sysmon Event 8 (CreateRemoteThread)', 'EDR injection telemetry'],
  logConfig: 'Sysmon with CreateRemoteThread detection enabled.',
  falsePositives: ['Anti-malware scanning processes', 'Debugging tools', 'Some legitimate applications hooking into others'],
  tuning: 'Exclude known OS and AV processes. Focus on unusual source-target pairs. Any injection into lsass.exe is critical.',
  commonErrors: ['Sysmon Event 8 must be explicitly configured', 'High-volume environments generate many legitimate events'],
  responseActions: ['Identify the injecting process — is it known/signed?', 'Check what code was injected', 'If malicious: isolate host, memory forensics', 'Block the injecting process hash'],
  threatIntel: { cves: [], cisaKev: false, campaigns: [], iocs: [] },
  references: ['https://attack.mitre.org/techniques/T1055/003/']
},
{
  id: 'SR-0138', title: 'Parent/Child Process Anomaly',
  status: 'stable', severity: 'high', author: 'SOC Platform', date: '2024-05-20', modified: '2024-12-10',
  category: 'endpoint-anomalies',
  description: 'Detects anomalous parent-child process relationships that indicate exploitation, injection, or living-off-the-land techniques.',
  tacticId: 'TA0002', tacticName: 'Execution', techniqueId: 'T1059', techniqueName: 'Command and Scripting Interpreter',
  logsource: { product: 'windows', category: 'process_creation' },
  sigmaYaml: `title: Anomalous Parent-Child Process Relationship
id: ea003-sigma-0138
status: stable
description: Detects unusual process parent-child chains
logsource:
    product: windows
    category: process_creation
detection:
    selection_office_shell:
        ParentImage|endswith:
            - '\\\\WINWORD.EXE'
            - '\\\\EXCEL.EXE'
            - '\\\\POWERPNT.EXE'
        Image|endswith:
            - '\\\\cmd.exe'
            - '\\\\powershell.exe'
            - '\\\\wscript.exe'
            - '\\\\mshta.exe'
    selection_browser_shell:
        ParentImage|endswith:
            - '\\\\chrome.exe'
            - '\\\\msedge.exe'
            - '\\\\firefox.exe'
        Image|endswith:
            - '\\\\cmd.exe'
            - '\\\\powershell.exe'
    condition: selection_office_shell or selection_browser_shell
level: high
tags:
    - attack.execution
    - attack.t1059`,
  splunkQuery: `index=wineventlog sourcetype=WinEventLog:Sysmon EventCode=1
| where (match(ParentImage,"(?i)(WINWORD|EXCEL|POWERPNT)\\.EXE$") AND match(Image,"(?i)(cmd|powershell|wscript|mshta)\\.exe$"))
  OR (match(ParentImage,"(?i)(chrome|msedge|firefox)\\.exe$") AND match(Image,"(?i)(cmd|powershell)\\.exe$"))
| stats count values(Image) as child values(CommandLine) as cmds by ComputerName, User, ParentImage, _time
| table _time, ComputerName, User, ParentImage, child, cmds, count`,
  qradarQuery: `SELECT sourceip, username,
  "Parent Process Path" as parent,
  Filename as child,
  COUNT(*) as anomaly_count
FROM events
WHERE CATEGORYNAME(category) ILIKE '%Process%Create%'
  AND (("Parent Process Path" ILIKE '%WINWORD%' OR "Parent Process Path" ILIKE '%EXCEL%')
    AND (Filename ILIKE '%cmd.exe' OR Filename ILIKE '%powershell.exe'))
GROUP BY sourceip, username, "Parent Process Path", Filename
ORDER BY starttime DESC
LAST 24 HOURS`,
  detectionExplanation: 'Office applications spawning command shells indicates macro execution or exploitation. Browsers spawning cmd/powershell indicates drive-by download or browser exploit. These parent-child relationships should not occur in normal usage.',
  requiredLogs: ['Sysmon Event 1 with parent process', 'EDR process tree telemetry'],
  logConfig: 'Sysmon with full parent-child process tracking.',
  falsePositives: ['Legitimate macros in trusted documents', 'Browser-based admin tools launching CLI tools'],
  tuning: 'Office spawning shells is high-fidelity for malicious macros. Add more parent-child pairs for other anomalous relationships.',
  commonErrors: ['Without parent process tracking (Sysmon/EDR), this detection is impossible'],
  responseActions: ['Investigate the parent document or URL', 'Check command line for malicious indicators', 'Isolate if malware execution confirmed', 'Identify delivery mechanism (email, web)'],
  threatIntel: { cves: [], cisaKev: false, campaigns: ['Midnight Blizzard'], iocs: [] },
  references: ['https://attack.mitre.org/techniques/T1059/']
},
{
  id: 'SR-0139', title: 'Suspicious PowerShell with Obfuscation',
  status: 'stable', severity: 'high', author: 'SOC Platform', date: '2024-06-15', modified: '2024-12-15',
  category: 'endpoint-anomalies',
  description: 'Detects obfuscated PowerShell commands using techniques like string concatenation, character replacement, base64 encoding, and compression to evade signature-based detection.',
  tacticId: 'TA0005', tacticName: 'Defense Evasion', techniqueId: 'T1027.010', techniqueName: 'Command Obfuscation',
  logsource: { product: 'windows', category: 'process_creation' },
  sigmaYaml: `title: Obfuscated PowerShell Execution
id: ea004-sigma-0139
status: stable
description: Detects PowerShell obfuscation techniques
logsource:
    product: windows
    category: process_creation
detection:
    selection:
        Image|endswith:
            - '\\\\powershell.exe'
            - '\\\\pwsh.exe'
        CommandLine|contains:
            - '-enc '
            - '-EncodedCommand'
            - 'FromBase64String'
            - '[Convert]::FromBase64'
            - 'Compress'
            - 'Decompress'
            - '[char]'
            - 'replace'
            - '-join'
            - 'iex'
    condition: selection
level: high
tags:
    - attack.defense_evasion
    - attack.t1027.010`,
  splunkQuery: `index=wineventlog (sourcetype=WinEventLog:Sysmon EventCode=1 OR sourcetype=WinEventLog:Security EventCode=4688)
| where match(Image,"(?i)(powershell|pwsh)\\.exe$")
| where match(CommandLine,"(?i)(-enc\\s|-EncodedCommand|FromBase64String|\\[Convert\\]|Compress|Decompress|\\[char\\]|replace.*replace|-join.*\\[char\\]|iex\\s)")
| eval risk=case(match(CommandLine,"-enc\\s"),"ENCODED",match(CommandLine,"FromBase64String"),"BASE64_DECODE",match(CommandLine,"\\[char\\]"),"CHAR_OBFUSCATION",true(),"OBFUSCATED")
| table _time, ComputerName, User, risk, CommandLine`,
  qradarQuery: `SELECT sourceip, username,
  Command,
  COUNT(*) as obfuscated_ps
FROM events
WHERE CATEGORYNAME(category) ILIKE '%Process%Create%'
  AND (Filename ILIKE '%powershell%' OR Filename ILIKE '%pwsh%')
  AND (Command ILIKE '%-enc %' OR Command ILIKE '%EncodedCommand%'
    OR Command ILIKE '%FromBase64%' OR Command ILIKE '%[char]%')
GROUP BY sourceip, username, Command
ORDER BY starttime DESC
LAST 24 HOURS`,
  detectionExplanation: 'Obfuscated PowerShell is a hallmark of malicious activity. -enc (Encoded Command) runs base64-encoded scripts invisible to casual inspection. Character substitution ([char]65 = "A") hides strings. Multiple replace operations rebuild commands from fragments.',
  requiredLogs: ['Sysmon Event 1', 'PowerShell Script Block Logging (4104)', 'AMSI logs'],
  logConfig: 'Enable ScriptBlock Logging and command line capture. AMSI integration provides deobfuscated view.',
  falsePositives: ['Legitimate PowerShell-based management tools using encoded commands', 'Configuration management scripts'],
  tuning: 'Base64 encoded PowerShell from non-admin users is almost always malicious. Decode and analyze the payload.',
  commonErrors: ['Command line truncation may miss encoded payloads', 'Script Block Logging provides deobfuscated content — more reliable'],
  responseActions: ['Decode the base64 payload', 'Analyze the deobfuscated script for malicious intent', 'Block execution if confirmed malicious', 'Investigate delivery mechanism'],
  threatIntel: { cves: [], cisaKev: false, campaigns: ['LockBit 3.0', 'Scattered Spider'], iocs: [] },
  references: ['https://attack.mitre.org/techniques/T1027/010/']
},
{
  id: 'SR-0140', title: 'AMSI Bypass Attempt',
  status: 'stable', severity: 'high', author: 'SOC Platform', date: '2024-07-20', modified: '2024-12-10',
  category: 'endpoint-anomalies',
  description: 'Detects attempts to bypass the Antimalware Scan Interface (AMSI) which provides script content scanning for PowerShell, VBScript, and other scripting engines.',
  tacticId: 'TA0005', tacticName: 'Defense Evasion', techniqueId: 'T1562.001', techniqueName: 'Disable or Modify Tools',
  logsource: { product: 'windows', category: 'process_creation' },
  sigmaYaml: `title: AMSI Bypass Attempt
id: ea005-sigma-0140
status: stable
description: Detects AMSI bypass techniques
logsource:
    product: windows
    category: process_creation
detection:
    selection:
        CommandLine|contains:
            - 'AmsiInitFailed'
            - 'amsiContext'
            - 'AmsiUtils'
            - 'amsi.dll'
            - 'SetField.*NonPublic'
            - 'Reflection.Assembly'
    condition: selection
level: high
tags:
    - attack.defense_evasion
    - attack.t1562.001`,
  splunkQuery: `index=wineventlog (sourcetype=WinEventLog:Sysmon EventCode=1 OR sourcetype=WinEventLog:Microsoft-Windows-PowerShell/Operational EventCode=4104)
| where match(CommandLine,"(?i)(AmsiInitFailed|amsiContext|AmsiUtils|amsi\\.dll|SetField.*NonPublic|Reflection\\.Assembly)")
  OR match(ScriptBlockText,"(?i)(AmsiInitFailed|amsiContext|AmsiUtils)")
| table _time, ComputerName, User, CommandLine, ScriptBlockText`,
  qradarQuery: `SELECT sourceip, username,
  QIDNAME(qid) as event_name,
  COUNT(*) as amsi_bypass
FROM events
WHERE (eventname ILIKE '%AmsiInitFailed%' OR eventname ILIKE '%AmsiUtils%'
  OR eventname ILIKE '%amsi.dll%' OR Command ILIKE '%AmsiInitFailed%')
GROUP BY sourceip, username, qid
HAVING COUNT(*) > 0
ORDER BY amsi_bypass DESC
LAST 24 HOURS`,
  detectionExplanation: 'AMSI bypass patches the AmsiScanBuffer function in memory to always return "clean" results. Common techniques: setting amsiInitFailed to True, patching AmsiUtils via reflection. This disables script content scanning for the current session.',
  requiredLogs: ['PowerShell Script Block Logging (4104)', 'Sysmon Event 1', 'AMSI provider logs'],
  logConfig: 'Enable Script Block Logging. AMSI integration with AV solution.',
  falsePositives: ['Security researchers testing AMSI', 'Penetration testing tools'],
  tuning: 'High-fidelity rule — AMSI bypass is almost always associated with malware. Monitor for downstream activity after bypass.',
  commonErrors: ['Some AMSI bypasses work before logging is initialized', 'New bypass techniques emerge regularly'],
  responseActions: ['Isolate the host', 'Check what scripts ran after AMSI bypass', 'Full malware investigation on the endpoint', 'Update AMSI and AV signatures'],
  threatIntel: { cves: [], cisaKev: false, campaigns: [], iocs: [] },
  references: ['https://attack.mitre.org/techniques/T1562/001/']
},
{
  id: 'SR-0141', title: 'Living-off-the-Land Binary Unusual Usage',
  status: 'stable', severity: 'medium', author: 'SOC Platform', date: '2024-08-15', modified: '2024-12-10',
  category: 'endpoint-anomalies',
  description: 'Detects unusual usage of living-off-the-land binaries (LOLBins) — legitimate Windows tools abused by attackers to download payloads, execute code, or bypass application controls.',
  tacticId: 'TA0005', tacticName: 'Defense Evasion', techniqueId: 'T1218', techniqueName: 'System Binary Proxy Execution',
  logsource: { product: 'windows', category: 'process_creation' },
  sigmaYaml: `title: LOLBin Unusual Usage Detection
id: ea006-sigma-0141
status: stable
description: Detects suspicious LOLBin usage patterns
logsource:
    product: windows
    category: process_creation
detection:
    selection:
        Image|endswith:
            - '\\\\certutil.exe'
            - '\\\\bitsadmin.exe'
            - '\\\\mshta.exe'
            - '\\\\regsvr32.exe'
            - '\\\\rundll32.exe'
            - '\\\\cmstp.exe'
            - '\\\\msiexec.exe'
        CommandLine|contains:
            - 'http'
            - 'ftp'
            - '-decode'
            - '-urlcache'
            - '/i:'
            - 'scrobj'
    condition: selection
level: medium
tags:
    - attack.defense_evasion
    - attack.t1218`,
  splunkQuery: `index=wineventlog sourcetype=WinEventLog:Sysmon EventCode=1
| where match(Image,"(?i)(certutil|bitsadmin|mshta|regsvr32|rundll32|cmstp|msiexec)\\.exe$")
  AND match(CommandLine,"(?i)(https?://|ftp://|-decode|-urlcache|/i:|scrobj)")
| eval lolbin=mvindex(split(Image,"\\"),mvcount(split(Image,"\\"))-1)
| stats count values(CommandLine) as commands by ComputerName, User, lolbin, _time
| table _time, ComputerName, User, lolbin, commands, count`,
  qradarQuery: `SELECT sourceip, username,
  Filename,
  Command,
  COUNT(*) as lolbin_events
FROM events
WHERE CATEGORYNAME(category) ILIKE '%Process%Create%'
  AND (Filename ILIKE '%certutil%' OR Filename ILIKE '%bitsadmin%'
    OR Filename ILIKE '%mshta%' OR Filename ILIKE '%regsvr32%')
  AND (Command ILIKE '%http%' OR Command ILIKE '%-decode%'
    OR Command ILIKE '%-urlcache%' OR Command ILIKE '%scrobj%')
GROUP BY sourceip, username, Filename, Command
ORDER BY starttime DESC
LAST 24 HOURS`,
  detectionExplanation: 'LOLBins are legitimate Windows binaries abused for malicious purposes. certutil -urlcache downloads files, bitsadmin over HTTP transfers payloads, mshta runs JavaScript/VBScript, regsvr32 /i:URL loads remote COM scriptlets. These bypass application whitelisting.',
  requiredLogs: ['Sysmon Event 1', 'Windows Security 4688'],
  logConfig: 'Process creation auditing with full command line.',
  falsePositives: ['IT using certutil for certificate operations', 'BITS-based software distribution', 'Legitimate MSI installations'],
  tuning: 'Focus on LOLBins with URL parameters or download/decode arguments. certutil -decode and -urlcache are almost always malicious.',
  commonErrors: ['LOLBin detection requires command line analysis — process name alone is insufficient'],
  responseActions: ['Analyze the downloaded payload', 'Block the source URL', 'Investigate the full attack chain', 'Check for subsequent execution of downloaded files'],
  threatIntel: { cves: [], cisaKev: false, campaigns: ['Volt Typhoon'], iocs: [] },
  references: ['https://attack.mitre.org/techniques/T1218/']
},

// ═══════════════════════════════════════════════════════════════
// LINUX / UNIX THREATS (6 rules)
// ═══════════════════════════════════════════════════════════════
{
  id: 'SR-0142', title: 'Reverse Shell Detection on Linux',
  status: 'stable', severity: 'critical', author: 'SOC Platform', date: '2024-03-20', modified: '2024-12-15',
  category: 'linux-threats',
  description: 'Detects reverse shell execution on Linux systems using bash, python, perl, netcat, or other common reverse shell techniques.',
  tacticId: 'TA0002', tacticName: 'Execution', techniqueId: 'T1059.004', techniqueName: 'Unix Shell',
  logsource: { product: 'linux', category: 'process_creation' },
  sigmaYaml: `title: Linux Reverse Shell Detection
id: lt001-sigma-0142
status: stable
description: Detects reverse shell patterns on Linux
logsource:
    product: linux
    category: process_creation
detection:
    selection:
        CommandLine|contains:
            - '/dev/tcp/'
            - 'bash -i >&'
            - 'nc -e /bin'
            - 'ncat -e'
            - 'python -c.*socket'
            - 'perl -e.*socket'
            - 'ruby -rsocket'
            - 'php -r.*fsockopen'
            - 'mkfifo'
    condition: selection
level: critical
tags:
    - attack.execution
    - attack.t1059.004`,
  splunkQuery: `index=linux sourcetype=linux:audit type=EXECVE
| where match(a0_a1_a2,"(?i)(/dev/tcp/|bash\\s+-i\\s+>&|nc\\s+-e\\s+/bin|python.*socket|perl.*socket|mkfifo|ruby.*rsocket|php.*fsockopen)")
| table _time, host, auid, exe, a0, a1, a2

| append [search index=linux_secure sourcetype=linux_secure
| where match(_raw,"(?i)(/dev/tcp/|bash\\s+-i|nc\\s+-e|mkfifo)")
| table _time, host, _raw]`,
  qradarQuery: `SELECT sourceip, username,
  QIDNAME(qid) as event_name,
  COUNT(*) as revshell_events
FROM events
WHERE LOGSOURCETYPENAME(devicetype) ILIKE '%Linux%'
  AND (eventname ILIKE '%/dev/tcp/%' OR eventname ILIKE '%bash -i%'
    OR eventname ILIKE '%nc -e%' OR eventname ILIKE '%mkfifo%'
    OR eventname ILIKE '%socket%connect%')
GROUP BY sourceip, username, qid
HAVING COUNT(*) > 0
ORDER BY revshell_events DESC
LAST 24 HOURS`,
  detectionExplanation: 'Reverse shells redirect stdin/stdout to a network socket. bash /dev/tcp is the simplest. netcat (nc -e) provides shell via network. Python/Perl/Ruby socket-based shells are more flexible. mkfifo creates named pipes for bidirectional communication.',
  requiredLogs: ['Linux auditd EXECVE events', 'syslog/auth.log', 'EDR on Linux endpoints'],
  logConfig: 'Configure auditd rules for EXECVE logging. Enable Linux Sysmon where available.',
  falsePositives: ['Legitimate network testing (rare)', 'Development scripts using sockets (should not use /dev/tcp)'],
  tuning: 'High-fidelity rule — reverse shell patterns are almost always malicious. Monitor all variations including encoded versions.',
  commonErrors: ['Audit logging format varies across distributions', 'Some reverse shells use only built-in features not easily logged'],
  responseActions: ['CRITICAL — Active attacker session', 'Kill the reverse shell process immediately', 'Identify the destination IP (C2 server)', 'Isolate the system', 'Full forensic investigation'],
  threatIntel: { cves: [], cisaKev: false, campaigns: [], iocs: [] },
  references: ['https://attack.mitre.org/techniques/T1059/004/']
},
{
  id: 'SR-0143', title: 'Crontab Persistence on Linux',
  status: 'stable', severity: 'high', author: 'SOC Platform', date: '2024-04-15', modified: '2024-12-10',
  category: 'linux-threats',
  description: 'Detects modification of crontab entries for persistence — attackers add cron jobs to maintain access and execute payloads on schedule.',
  tacticId: 'TA0003', tacticName: 'Persistence', techniqueId: 'T1053.003', techniqueName: 'Cron',
  logsource: { product: 'linux', service: 'syslog' },
  sigmaYaml: `title: Crontab Persistence on Linux
id: lt002-sigma-0143
status: stable
description: Detects crontab modifications for persistence
logsource:
    product: linux
    service: syslog
detection:
    selection:
        CommandLine|contains:
            - 'crontab -e'
            - 'crontab -l'
            - '/etc/cron'
            - '/var/spool/cron'
    selection_write:
        CommandLine|contains:
            - 'echo.*crontab'
            - 'echo.*>.*cron'
            - 'curl.*cron'
            - 'wget.*cron'
    condition: selection or selection_write
level: high
tags:
    - attack.persistence
    - attack.t1053.003`,
  splunkQuery: `index=linux (sourcetype=linux:audit OR sourcetype=syslog)
| where match(_raw,"(?i)(crontab\\s+-[el]|/etc/cron|/var/spool/cron|echo.*>>.*cron|curl.*cron|wget.*cron)")
| stats count values(host) as hosts by user, _raw, _time
| table _time, user, hosts, _raw, count`,
  qradarQuery: `SELECT sourceip, username,
  QIDNAME(qid) as event_name,
  COUNT(*) as cron_events
FROM events
WHERE LOGSOURCETYPENAME(devicetype) ILIKE '%Linux%'
  AND (eventname ILIKE '%crontab%' OR eventname ILIKE '%/etc/cron%'
    OR eventname ILIKE '%spool/cron%')
GROUP BY sourceip, username, qid
ORDER BY starttime DESC
LAST 24 HOURS`,
  detectionExplanation: 'Cron jobs execute on schedule and persist across reboots. Attackers add cron entries to run reverse shells, download payloads, or maintain backdoors. Writing to /etc/cron.d/ or user crontabs provides persistence.',
  requiredLogs: ['Linux auditd file access events', 'syslog cron events', 'File integrity monitoring on cron directories'],
  logConfig: 'Audit rule for /etc/crontab and /var/spool/cron/ writes. File integrity monitoring.',
  falsePositives: ['Legitimate cron job creation by admins', 'Deployment scripts configuring scheduled tasks'],
  tuning: 'Alert on crontab modifications by non-root users. Focus on entries with curl/wget/nc/bash/python commands.',
  commonErrors: ['Cron daemon logs may not capture the full cron entry content'],
  responseActions: ['Review the cron entry content', 'Remove malicious cron jobs', 'Investigate the user account', 'Check for backdoor persistence'],
  threatIntel: { cves: [], cisaKev: false, campaigns: [], iocs: [] },
  references: ['https://attack.mitre.org/techniques/T1053/003/']
},
{
  id: 'SR-0144', title: 'Linux Privilege Escalation via SUID Binary',
  status: 'stable', severity: 'high', author: 'SOC Platform', date: '2024-05-20', modified: '2024-12-10',
  category: 'linux-threats',
  description: 'Detects exploitation of SUID binaries for privilege escalation by monitoring for SUID binary discovery and execution of known exploitable SUID programs.',
  tacticId: 'TA0004', tacticName: 'Privilege Escalation', techniqueId: 'T1548.001', techniqueName: 'Setuid and Setgid',
  logsource: { product: 'linux', category: 'process_creation' },
  sigmaYaml: `title: SUID Binary Privilege Escalation
id: lt003-sigma-0144
status: stable
description: Detects SUID binary discovery and exploitation
logsource:
    product: linux
    category: process_creation
detection:
    selection_find:
        CommandLine|contains:
            - 'find / -perm -4000'
            - 'find / -perm -u=s'
            - 'find / -perm /4000'
    selection_exploit:
        CommandLine|contains:
            - 'nmap --interactive'
            - 'vim.tiny'
            - 'python -c.*os.setuid'
            - 'pkexec'
    condition: selection_find or selection_exploit
level: high
tags:
    - attack.privilege_escalation
    - attack.t1548.001`,
  splunkQuery: `index=linux (sourcetype=linux:audit OR sourcetype=syslog)
| where match(_raw,"(?i)(find\\s+/\\s+-perm\\s+(-4000|-u=s|/4000)|nmap\\s+--interactive|python.*os\\.setuid|pkexec)")
| table _time, host, user, _raw`,
  qradarQuery: `SELECT sourceip, username,
  QIDNAME(qid) as event_name,
  COUNT(*) as suid_events
FROM events
WHERE LOGSOURCETYPENAME(devicetype) ILIKE '%Linux%'
  AND (eventname ILIKE '%find%perm%4000%'
    OR eventname ILIKE '%nmap%interactive%'
    OR eventname ILIKE '%os.setuid%')
GROUP BY sourceip, username, qid
ORDER BY starttime DESC
LAST 24 HOURS`,
  detectionExplanation: 'find / -perm -4000 discovers SUID binaries — programs that run with owners privileges (often root). Exploitable SUID binaries (nmap --interactive, pkexec, custom SUID) can escalate to root. PwnKit (CVE-2021-4034) exploits pkexec.',
  requiredLogs: ['Linux auditd EXECVE events', 'syslog', 'EDR process telemetry'],
  logConfig: 'Audit rules for find and known SUID exploitation commands.',
  falsePositives: ['Security auditors inventorying SUID binaries', 'Legitimate use of pkexec for admin tasks'],
  tuning: 'SUID discovery (find -perm -4000) is a strong recon indicator. Monitor for subsequent SUID binary execution.',
  commonErrors: ['Many SUID binaries are legitimate — focus on exploitation patterns'],
  responseActions: ['Identify which SUID binary was exploited', 'Remove unnecessary SUID bits', 'Patch known SUID vulnerabilities (PwnKit)', 'Investigate the escalated access'],
  threatIntel: { cves: ['CVE-2021-4034'], cisaKev: true, campaigns: [], iocs: [] },
  references: ['https://attack.mitre.org/techniques/T1548/001/']
},
{
  id: 'SR-0145', title: 'SSH Key Manipulation for Persistence',
  status: 'stable', severity: 'high', author: 'SOC Platform', date: '2024-06-15', modified: '2024-12-10',
  category: 'linux-threats',
  description: 'Detects unauthorized SSH key addition to authorized_keys files, providing persistent passwordless access to the compromised system.',
  tacticId: 'TA0003', tacticName: 'Persistence', techniqueId: 'T1098.004', techniqueName: 'SSH Authorized Keys',
  logsource: { product: 'linux', service: 'syslog' },
  sigmaYaml: `title: SSH Authorized Keys Manipulation
id: lt004-sigma-0145
status: stable
description: Detects unauthorized SSH key additions
logsource:
    product: linux
    service: syslog
detection:
    selection:
        CommandLine|contains:
            - 'authorized_keys'
            - '.ssh/authorized'
            - 'ssh-keygen'
            - 'ssh-copy-id'
    selection_write:
        CommandLine|contains:
            - '>> authorized_keys'
            - 'echo.*ssh-rsa.*>>'
            - 'echo.*ssh-ed25519.*>>'
    condition: selection or selection_write
level: high
tags:
    - attack.persistence
    - attack.t1098.004`,
  splunkQuery: `index=linux (sourcetype=linux:audit OR sourcetype=syslog)
| where match(_raw,"(?i)(authorized_keys|ssh-copy-id|echo.*ssh-rsa.*>>|echo.*ssh-ed25519.*>>)")
| stats count values(host) as hosts by user, _raw, _time
| table _time, user, hosts, _raw, count`,
  qradarQuery: `SELECT sourceip, username,
  QIDNAME(qid) as event_name,
  COUNT(*) as ssh_key_events
FROM events
WHERE LOGSOURCETYPENAME(devicetype) ILIKE '%Linux%'
  AND (eventname ILIKE '%authorized_keys%' OR eventname ILIKE '%ssh-copy-id%')
GROUP BY sourceip, username, qid
ORDER BY starttime DESC
LAST 24 HOURS`,
  detectionExplanation: 'Adding SSH public keys to ~/.ssh/authorized_keys provides passwordless SSH access. Attackers use this for persistent backdoor access. echo "ssh-rsa AAAA..." >> ~/.ssh/authorized_keys is the simplest method.',
  requiredLogs: ['Linux auditd file access on .ssh directories', 'File integrity monitoring', 'syslog'],
  logConfig: 'Audit rules for authorized_keys file modifications. FIM on .ssh directories.',
  falsePositives: ['Legitimate SSH key deployment by admins', 'Automation tools (Ansible, Chef) distributing keys'],
  tuning: 'Alert on key additions by non-root users. Maintain known-good authorized_keys baseline.',
  commonErrors: ['SSH key additions may be logged only as file writes, not command executions'],
  responseActions: ['Review the added SSH key', 'Remove unauthorized keys', 'Identify the source of the key addition', 'Rotate all SSH keys on affected system'],
  threatIntel: { cves: [], cisaKev: false, campaigns: ['Volt Typhoon'], iocs: [] },
  references: ['https://attack.mitre.org/techniques/T1098/004/']
},
{
  id: 'SR-0146', title: 'Linux Rootkit Indicators',
  status: 'test', severity: 'critical', author: 'SOC Platform', date: '2024-07-20', modified: '2024-12-10',
  category: 'linux-threats',
  description: 'Detects indicators of rootkit installation on Linux including kernel module loading, LD_PRELOAD manipulation, and hidden file system modifications.',
  tacticId: 'TA0005', tacticName: 'Defense Evasion', techniqueId: 'T1014', techniqueName: 'Rootkit',
  logsource: { product: 'linux', category: 'process_creation' },
  sigmaYaml: `title: Linux Rootkit Indicators
id: lt005-sigma-0146
status: test
description: Detects rootkit installation indicators
logsource:
    product: linux
    category: process_creation
detection:
    selection:
        CommandLine|contains:
            - 'insmod '
            - 'modprobe '
            - 'LD_PRELOAD'
            - '/etc/ld.so.preload'
            - 'unhide'
    condition: selection
level: critical
tags:
    - attack.defense_evasion
    - attack.t1014`,
  splunkQuery: `index=linux (sourcetype=linux:audit OR sourcetype=syslog)
| where match(_raw,"(?i)(insmod\\s|modprobe\\s|LD_PRELOAD|ld\\.so\\.preload|unhide)")
| table _time, host, user, _raw`,
  qradarQuery: `SELECT sourceip, username,
  QIDNAME(qid) as event_name,
  COUNT(*) as rootkit_events
FROM events
WHERE LOGSOURCETYPENAME(devicetype) ILIKE '%Linux%'
  AND (eventname ILIKE '%insmod%' OR eventname ILIKE '%LD_PRELOAD%'
    OR eventname ILIKE '%ld.so.preload%')
GROUP BY sourceip, username, qid
HAVING COUNT(*) > 0
ORDER BY rootkit_events DESC
LAST 24 HOURS`,
  detectionExplanation: 'Rootkits hide malicious activity at the kernel/library level. insmod loads kernel modules (kernel rootkits). LD_PRELOAD/ld.so.preload intercepts library calls (userland rootkits). These modify system behavior to hide processes, files, and network connections.',
  requiredLogs: ['Linux auditd module_load events', 'File integrity monitoring', 'System library monitoring'],
  logConfig: 'Audit rules for kernel module loading. FIM on /etc/ld.so.preload.',
  falsePositives: ['Legitimate kernel module installation during updates', 'System administration loading approved modules'],
  tuning: 'Kernel module loading is rare in production. LD_PRELOAD is almost never used in production.',
  commonErrors: ['Rootkits may manipulate audit framework to hide module loading', 'FIM must run before rootkit to detect changes'],
  responseActions: ['CRITICAL — System integrity compromised', 'Boot from known-good media for investigation', 'Compare kernel modules against known baseline', 'Rebuild the system from verified image', 'Full forensic investigation'],
  threatIntel: { cves: [], cisaKev: false, campaigns: [], iocs: [] },
  references: ['https://attack.mitre.org/techniques/T1014/']
},
{
  id: 'SR-0147', title: 'Container Escape Attempt',
  status: 'test', severity: 'critical', author: 'SOC Platform', date: '2024-08-20', modified: '2024-12-10',
  category: 'linux-threats',
  description: 'Detects container escape attempts including Docker socket access from containers, privileged container creation, and namespace manipulation.',
  tacticId: 'TA0004', tacticName: 'Privilege Escalation', techniqueId: 'T1611', techniqueName: 'Escape to Host',
  logsource: { product: 'linux', category: 'process_creation' },
  sigmaYaml: `title: Container Escape Attempt
id: lt006-sigma-0147
status: test
description: Detects container breakout techniques
logsource:
    product: linux
    category: process_creation
detection:
    selection:
        CommandLine|contains:
            - 'docker.sock'
            - 'docker run --privileged'
            - 'nsenter --target 1'
            - 'mount /dev/'
            - 'chroot /host'
    condition: selection
level: critical
tags:
    - attack.privilege_escalation
    - attack.t1611`,
  splunkQuery: `index=linux (sourcetype=linux:audit OR sourcetype=syslog)
| where match(_raw,"(?i)(docker\\.sock|docker\\s+run\\s+--privileged|nsenter\\s+--target\\s+1|chroot\\s+/host)")
| table _time, host, user, _raw`,
  qradarQuery: `SELECT sourceip, username,
  QIDNAME(qid) as event_name,
  COUNT(*) as escape_events
FROM events
WHERE LOGSOURCETYPENAME(devicetype) ILIKE '%Linux%'
  AND (eventname ILIKE '%docker.sock%' OR eventname ILIKE '%--privileged%'
    OR eventname ILIKE '%nsenter%target%1%')
GROUP BY sourceip, username, qid
HAVING COUNT(*) > 0
ORDER BY escape_events DESC
LAST 24 HOURS`,
  detectionExplanation: 'Container escapes break out of container isolation to access the host. Accessing docker.sock from within a container allows creating privileged containers. nsenter --target 1 enters the host PID namespace. Mounting host filesystems enables host access.',
  requiredLogs: ['Container runtime logs (Docker, containerd)', 'Linux auditd with namespace tracking', 'Kubernetes audit logs'],
  logConfig: 'Docker daemon logging. Kubernetes audit logging. auditd with container-aware rules.',
  falsePositives: ['Legitimate container administration', 'CI/CD pipelines using docker-in-docker'],
  tuning: 'Privileged containers should be banned in production. docker.sock mounting is a critical risk.',
  commonErrors: ['Container runtime logs may not be forwarded to SIEM by default'],
  responseActions: ['CRITICAL — Container isolation broken', 'Kill the container immediately', 'Investigate host for compromise', 'Remove docker.sock mounts from container specs', 'Enforce pod security policies'],
  threatIntel: { cves: [], cisaKev: false, campaigns: [], iocs: [] },
  references: ['https://attack.mitre.org/techniques/T1611/']
},

// ═══════════════════════════════════════════════════════════════
// WINDOWS SPECIFIC (6 rules)
// ═══════════════════════════════════════════════════════════════
{
  id: 'SR-0148', title: 'BITS Job for Payload Download',
  status: 'stable', severity: 'high', author: 'SOC Platform', date: '2024-03-15', modified: '2024-12-15',
  category: 'windows-specific',
  description: 'Detects abuse of Background Intelligent Transfer Service (BITS) for downloading payloads, evading proxy detection, and establishing persistence.',
  tacticId: 'TA0005', tacticName: 'Defense Evasion', techniqueId: 'T1197', techniqueName: 'BITS Jobs',
  logsource: { product: 'windows', category: 'process_creation' },
  sigmaYaml: `title: BITS Job for Payload Download
id: ws001-sigma-0148
status: stable
description: Detects BITS abuse for payload download
logsource:
    product: windows
    category: process_creation
detection:
    selection:
        Image|endswith: '\\\\bitsadmin.exe'
        CommandLine|contains:
            - '/transfer'
            - '/addfile'
            - '/create'
            - 'http'
    selection_ps:
        CommandLine|contains:
            - 'Start-BitsTransfer'
            - 'BitsTransfer'
    condition: selection or selection_ps
level: high
tags:
    - attack.defense_evasion
    - attack.t1197`,
  splunkQuery: `index=wineventlog (sourcetype=WinEventLog:Sysmon EventCode=1)
| where (match(Image,"bitsadmin\\.exe$") AND match(CommandLine,"(?i)(/transfer|/addfile|/create|https?://)"))
  OR match(CommandLine,"(?i)(Start-BitsTransfer)")
| table _time, ComputerName, User, CommandLine`,
  qradarQuery: `SELECT sourceip, username, Command,
  COUNT(*) as bits_events
FROM events
WHERE (Filename ILIKE '%bitsadmin%' AND (Command ILIKE '%transfer%' OR Command ILIKE '%http%'))
  OR Command ILIKE '%Start-BitsTransfer%'
GROUP BY sourceip, username, Command
ORDER BY starttime DESC
LAST 24 HOURS`,
  detectionExplanation: 'BITS is a legitimate Windows service for background file transfers. Attackers abuse it because BITS transfers: (1) survive reboots, (2) respect proxy settings, (3) can schedule execution after download, (4) run as SYSTEM.',
  requiredLogs: ['Sysmon Event 1', 'BITS Admin Event Log (Event 3/4)', 'Windows Security 4688'],
  logConfig: 'Process creation auditing. Enable BITS operational logging.',
  falsePositives: ['Windows Update using BITS', 'SCCM content distribution', 'Edge/Chrome updates via BITS'],
  tuning: 'Focus on BITS with external URLs. BITS creating files in temp directories is suspicious. Monitor for BITS with /SetNotifyCmdLine (execution after download).',
  commonErrors: ['BITS events are in a separate event log (Microsoft-Windows-Bits-Client/Operational)'],
  responseActions: ['List all active BITS jobs: bitsadmin /list /allusers /verbose', 'Cancel malicious BITS jobs', 'Analyze the downloaded payload', 'Block the source URL'],
  threatIntel: { cves: [], cisaKev: false, campaigns: ['Volt Typhoon'], iocs: [] },
  references: ['https://attack.mitre.org/techniques/T1197/']
},
{
  id: 'SR-0149', title: 'Alternate Data Stream (ADS) Abuse',
  status: 'stable', severity: 'high', author: 'SOC Platform', date: '2024-04-20', modified: '2024-12-10',
  category: 'windows-specific',
  description: 'Detects creation and execution of content in NTFS Alternate Data Streams used to hide malware payloads within legitimate files.',
  tacticId: 'TA0005', tacticName: 'Defense Evasion', techniqueId: 'T1564.004', techniqueName: 'NTFS File Attributes',
  logsource: { product: 'windows', category: 'process_creation' },
  sigmaYaml: `title: Alternate Data Stream Abuse
id: ws002-sigma-0149
status: stable
description: Detects ADS creation and execution
logsource:
    product: windows
    category: process_creation
detection:
    selection:
        CommandLine|contains:
            - '> :' 
            - 'type *.* >'
            - 'streams -s'
            - 'Get-Content -Stream'
            - 'Set-Content -Stream'
            - 'wmic process call create.*:'
    condition: selection
level: high
tags:
    - attack.defense_evasion
    - attack.t1564.004`,
  splunkQuery: `index=wineventlog sourcetype=WinEventLog:Sysmon (EventCode=1 OR EventCode=15)
| where match(CommandLine,"(?i)(>\\s*:|type.*>|streams\\s+-s|Get-Content.*-Stream|Set-Content.*-Stream|wmic.*process.*call.*create.*:)")
  OR (EventCode=15 AND match(TargetFilename,":"))
| table _time, ComputerName, User, CommandLine, TargetFilename`,
  qradarQuery: `SELECT sourceip, username,
  Command,
  COUNT(*) as ads_events
FROM events
WHERE (Command ILIKE '%> :%' OR Command ILIKE '%Get-Content%-Stream%'
  OR Command ILIKE '%Set-Content%-Stream%')
GROUP BY sourceip, username, Command
ORDER BY starttime DESC
LAST 24 HOURS`,
  detectionExplanation: 'NTFS ADS allows attaching hidden data streams to files. Malware can be stored in streams invisible to standard dir listings. Example: type malware.exe > legit.txt:hidden.exe. Sysmon Event 15 detects ADS file creation.',
  requiredLogs: ['Sysmon Event 15 (FileCreateStreamHash)', 'Sysmon Event 1', 'Windows Security 4688'],
  logConfig: 'Sysmon with FileCreateStreamHash (Event 15) enabled.',
  falsePositives: ['Some browsers store download metadata in ADS (Zone.Identifier)', 'Dropbox/OneDrive sync metadata'],
  tuning: 'Exclude Zone.Identifier ADS (legitimate). Focus on executable content in ADS or ADS creation with external data.',
  commonErrors: ['Zone.Identifier ADS is extremely common and legitimate', 'Sysmon Event 15 must be explicitly configured'],
  responseActions: ['Enumerate all ADS on the file: dir /r', 'Extract and analyze the hidden stream content', 'Remove malicious ADS', 'Investigate how the ADS was created'],
  threatIntel: { cves: [], cisaKev: false, campaigns: [], iocs: [] },
  references: ['https://attack.mitre.org/techniques/T1564/004/']
},
{
  id: 'SR-0150', title: 'Print Spooler Exploitation (PrintNightmare)',
  status: 'stable', severity: 'critical', author: 'SOC Platform', date: '2024-05-15', modified: '2024-12-15',
  category: 'windows-specific',
  description: 'Detects Print Spooler exploitation (PrintNightmare, CVE-2021-34527) by monitoring for suspicious DLL loading by spoolsv.exe and remote print driver installation.',
  tacticId: 'TA0004', tacticName: 'Privilege Escalation', techniqueId: 'T1068', techniqueName: 'Exploitation for Privilege Escalation',
  logsource: { product: 'windows', category: 'process_creation' },
  sigmaYaml: `title: Print Spooler Exploitation Detection
id: ws003-sigma-0150
status: stable
description: Detects PrintNightmare exploitation
logsource:
    product: windows
    category: process_creation
detection:
    selection_child:
        ParentImage|endswith: '\\\\spoolsv.exe'
        Image|endswith:
            - '\\\\cmd.exe'
            - '\\\\powershell.exe'
            - '\\\\rundll32.exe'
    selection_dll:
        EventID: 808
    condition: selection_child or selection_dll
level: critical
tags:
    - attack.privilege_escalation
    - attack.t1068`,
  splunkQuery: `index=wineventlog sourcetype=WinEventLog:Sysmon EventCode=1 ParentImage="*\\\\spoolsv.exe"
| where match(Image,"(?i)(cmd|powershell|rundll32)\\.exe$")
| table _time, ComputerName, User, Image, CommandLine

| append [search index=wineventlog sourcetype="WinEventLog:Microsoft-Windows-PrintService/Admin" EventCode=808
| table _time, ComputerName, DriverFilePath]`,
  qradarQuery: `SELECT sourceip, username,
  QIDNAME(qid) as event_name,
  COUNT(*) as spooler_events
FROM events
WHERE ("Parent Process Path" ILIKE '%spoolsv.exe'
  AND (Filename ILIKE '%cmd.exe' OR Filename ILIKE '%powershell.exe'))
  OR EventID = 808
GROUP BY sourceip, username, qid
HAVING COUNT(*) > 0
ORDER BY spooler_events DESC
LAST 24 HOURS`,
  detectionExplanation: 'PrintNightmare (CVE-2021-34527) exploits the Print Spooler to load malicious DLLs with SYSTEM privileges. spoolsv.exe spawning cmd.exe or powershell.exe is a definitive exploitation indicator. Event 808 logs suspicious driver installation.',
  requiredLogs: ['Sysmon Event 1', 'Sysmon Event 7 (Image Load)', 'Print Service Admin log (808)'],
  logConfig: 'Sysmon with DLL loading for spoolsv.exe. Enable Print Service operational/admin logs.',
  falsePositives: ['Extremely rare — Print Spooler should not spawn command shells'],
  tuning: 'Zero-tolerance rule. Disable Print Spooler service on servers that dont need printing.',
  commonErrors: ['Print Spooler may be enabled by default on servers', 'Some legacy print setups may trigger driver installation events'],
  responseActions: ['CRITICAL — Active exploitation', 'Isolate the system', 'Disable Print Spooler service', 'Apply PrintNightmare patches', 'Investigate for lateral movement using obtained SYSTEM privileges'],
  threatIntel: { cves: ['CVE-2021-34527'], cisaKev: true, campaigns: [], iocs: [] },
  references: ['https://attack.mitre.org/techniques/T1068/']
},
{
  id: 'SR-0151', title: 'Named Pipe Communication — C2 Indicator',
  status: 'test', severity: 'medium', author: 'SOC Platform', date: '2024-06-20', modified: '2024-12-10',
  category: 'windows-specific',
  description: 'Detects creation of suspicious named pipes commonly associated with C2 frameworks like Cobalt Strike, Metasploit, and PsExec lateral movement.',
  tacticId: 'TA0011', tacticName: 'Command and Control', techniqueId: 'T1570', techniqueName: 'Lateral Tool Transfer',
  logsource: { product: 'windows', category: 'pipe_created' },
  sigmaYaml: `title: Suspicious Named Pipe Creation
id: ws004-sigma-0151
status: test
description: Detects C2-associated named pipes
logsource:
    product: windows
    category: pipe_created
detection:
    selection:
        PipeName|contains:
            - '\\\\MSSE-'
            - '\\\\msagent_'
            - '\\\\postex_'
            - '\\\\status_'
            - '\\\\mojo.5688.'
            - '\\\\interprocess.'
    condition: selection
level: medium
tags:
    - attack.command_and_control
    - attack.t1570`,
  splunkQuery: `index=wineventlog sourcetype=WinEventLog:Sysmon (EventCode=17 OR EventCode=18)
| where match(PipeName,"(?i)(MSSE-|msagent_|postex_|status_|mojo\\.5688|interprocess)")
| stats count values(PipeName) as pipes values(Image) as creating_process by ComputerName, User, _time
| table _time, ComputerName, User, pipes, creating_process, count`,
  qradarQuery: `SELECT sourceip, username,
  "Pipe Name",
  COUNT(*) as pipe_events
FROM events
WHERE QIDNAME(qid) ILIKE '%Pipe%Created%'
  AND ("Pipe Name" ILIKE '%MSSE-%' OR "Pipe Name" ILIKE '%msagent_%'
    OR "Pipe Name" ILIKE '%postex_%')
GROUP BY sourceip, username, "Pipe Name"
ORDER BY starttime DESC
LAST 24 HOURS`,
  detectionExplanation: 'C2 frameworks use named pipes for inter-process communication. Cobalt Strike uses \\\\MSSE-{random} and \\\\postex_ patterns. Metasploit uses various pipe names. PsExec creates \\\\PSEXESVC. Monitoring pipe creation identifies active C2 sessions.',
  requiredLogs: ['Sysmon Event 17 (PipeCreated)', 'Sysmon Event 18 (PipeConnected)'],
  logConfig: 'Sysmon with pipe creation monitoring (Events 17/18).',
  falsePositives: ['Chrome/Edge browser pipes (mojo.*)', 'Some legitimate inter-process communication'],
  tuning: 'Maintain a list of known C2 pipe patterns. New C2 frameworks introduce new patterns regularly.',
  commonErrors: ['Pipe events require Sysmon Events 17/18 — not enabled by default', 'High-volume environments generate many pipe events'],
  responseActions: ['Identify the process creating the pipe', 'Check for associated C2 network connections', 'Isolate if C2 confirmed', 'Memory forensics on the endpoint'],
  threatIntel: { cves: [], cisaKev: false, campaigns: [], iocs: [] },
  references: ['https://attack.mitre.org/techniques/T1570/']
},
{
  id: 'SR-0152', title: 'WMI Consumer Persistence Creation',
  status: 'stable', severity: 'high', author: 'SOC Platform', date: '2024-07-15', modified: '2024-12-10',
  category: 'windows-specific',
  description: 'Detects WMI event subscription creation for persistence — WMI consumers execute code in response to system events and survive reboots.',
  tacticId: 'TA0003', tacticName: 'Persistence', techniqueId: 'T1546.003', techniqueName: 'WMI Event Subscription',
  logsource: { product: 'windows', category: 'wmi_event' },
  sigmaYaml: `title: WMI Consumer Persistence Creation
id: ws005-sigma-0152
status: stable
description: Detects WMI event subscription for persistence
logsource:
    product: windows
    category: wmi_event
detection:
    selection:
        EventType:
            - 'WmiConsumerEvent'
            - 'WmiBindingEvent'
            - 'WmiFilterEvent'
    condition: selection
level: high
tags:
    - attack.persistence
    - attack.t1546.003`,
  splunkQuery: `index=wineventlog sourcetype=WinEventLog:Sysmon (EventCode=19 OR EventCode=20 OR EventCode=21)
| eval wmi_type=case(EventCode=19,"Filter Created",EventCode=20,"Consumer Created",EventCode=21,"Binding Created")
| stats count values(wmi_type) as components values(Name) as names by ComputerName, User, _time
| table _time, ComputerName, User, components, names, count`,
  qradarQuery: `SELECT sourceip, username,
  QIDNAME(qid) as event_name,
  COUNT(*) as wmi_sub_events
FROM events
WHERE QIDNAME(qid) ILIKE '%WMI%'
  AND (eventname ILIKE '%Consumer%' OR eventname ILIKE '%Binding%' OR eventname ILIKE '%Filter%')
GROUP BY sourceip, username, qid
ORDER BY starttime DESC
LAST 24 HOURS`,
  detectionExplanation: 'WMI persistence requires three components: EventFilter (trigger), EventConsumer (action), FilterToConsumerBinding (link). Sysmon Events 19/20/21 detect each component creation. All three together indicate active WMI persistence.',
  requiredLogs: ['Sysmon Events 19/20/21 (WMI Events)', 'WMI-Activity/Operational log'],
  logConfig: 'Sysmon with WMI event monitoring enabled.',
  falsePositives: ['SCCM client WMI subscriptions', 'Dell/HP hardware monitoring', 'Legitimate enterprise monitoring tools'],
  tuning: 'Baseline existing WMI subscriptions. Alert on new creation. Focus on ActiveScriptEventConsumer and CommandLineEventConsumer.',
  commonErrors: ['Sysmon WMI events must be specifically enabled', 'WMI repository is opaque without specific tools'],
  responseActions: ['List all WMI subscriptions on the host', 'Analyze the consumer action', 'Remove malicious subscriptions', 'Investigate how the attacker gained access to create them'],
  threatIntel: { cves: [], cisaKev: false, campaigns: [], iocs: [] },
  references: ['https://attack.mitre.org/techniques/T1546/003/']
},
{
  id: 'SR-0153', title: 'AppLocker / WDAC Bypass Attempt',
  status: 'test', severity: 'high', author: 'SOC Platform', date: '2024-08-20', modified: '2024-12-10',
  category: 'windows-specific',
  description: 'Detects attempts to bypass Windows application control (AppLocker/WDAC) using trusted Windows binaries, commonly known as Living-off-the-Land Binaries (LOLBins).',
  tacticId: 'TA0005', tacticName: 'Defense Evasion', techniqueId: 'T1218', techniqueName: 'System Binary Proxy Execution',
  logsource: { product: 'windows', category: 'process_creation' },
  sigmaYaml: `title: AppLocker / WDAC Bypass Detection
id: ws006-sigma-0153
status: test
description: Detects application control bypass attempts
logsource:
    product: windows
    category: process_creation
detection:
    selection:
        Image|endswith:
            - '\\\\cmstp.exe'
            - '\\\\pcalua.exe'
            - '\\\\presentationhost.exe'
            - '\\\\control.exe'
            - '\\\\bash.exe'
            - '\\\\wsl.exe'
        CommandLine|contains:
            - '/s'
            - '/au'
            - '-command'
            - 'http'
    condition: selection
level: high
tags:
    - attack.defense_evasion
    - attack.t1218`,
  splunkQuery: `index=wineventlog sourcetype=WinEventLog:Sysmon EventCode=1
| where match(Image,"(?i)(cmstp|pcalua|presentationhost|control|bash|wsl)\\.exe$")
  AND match(CommandLine,"(?i)(/s|/au|-command|https?://)")
| table _time, ComputerName, User, Image, CommandLine`,
  qradarQuery: `SELECT sourceip, username,
  Filename, Command,
  COUNT(*) as bypass_events
FROM events
WHERE (Filename ILIKE '%cmstp.exe' OR Filename ILIKE '%pcalua.exe'
  OR Filename ILIKE '%bash.exe' OR Filename ILIKE '%wsl.exe')
  AND (Command ILIKE '%/s%' OR Command ILIKE '%http%' OR Command ILIKE '%-command%')
GROUP BY sourceip, username, Filename, Command
ORDER BY starttime DESC
LAST 24 HOURS`,
  detectionExplanation: 'Application control bypass uses trusted binaries to execute untrusted code. cmstp.exe can load SCT scriptlets, pcalua.exe launches programs without direct execution, bash.exe/wsl.exe access Linux subsystem bypassing Windows controls.',
  requiredLogs: ['Sysmon Event 1', 'AppLocker event logs (8003, 8004, 8006, 8007)'],
  logConfig: 'Process creation auditing. AppLocker audit/enforce mode logging.',
  falsePositives: ['Legitimate use of WSL for development', 'Admin using cmstp for connection profiles'],
  tuning: 'In environments without WSL, bash.exe execution is always suspicious. cmstp.exe with /s (silent) flag is a known bypass.',
  commonErrors: ['Many bypass techniques use trusted binaries — focus on suspicious command line arguments'],
  responseActions: ['Investigate what was executed through the bypass', 'Update AppLocker/WDAC policies to block the technique', 'Check for payload execution after the bypass'],
  threatIntel: { cves: [], cisaKev: false, campaigns: [], iocs: [] },
  references: ['https://attack.mitre.org/techniques/T1218/']
}
];
