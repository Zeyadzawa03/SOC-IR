// ═══════════════════════════════════════════════════════════════
// ADVANCED THREAT HUNTING — Zero-Day & Behavioral Anomaly Detection
// SigmaGuard v5.0 — Behavior-based, NOT signature-based
// ═══════════════════════════════════════════════════════════════
'use strict';

const ADVANCED_HUNTS = [
// ━━━ ZERO-DAY HUNTING ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
{id:'AH-001',name:'First-Time Process Execution per Host',
huntType:'zero-day',category:'endpoint-anomalies',technique:'baselining',
description:'Detect processes executing for the first time on a host — key zero-day and novel malware indicator using baseline comparison.',
mitre:{tacticId:'TA0002',techniqueId:'T1204',techniqueName:'User Execution'},
difficulty:'High',frequency:'Daily',
splunkQuery:`index=sysmon EventCode=1
| stats earliest(_time) as first_seen count by Image, Computer
| where first_seen > relative_time(now(), "-24h@h")
| sort - first_seen
| head 50`,
qradarQuery:`SELECT LOGSOURCENAME(logsourceid) as host, UTF8(payload) as process,
  MIN(starttime) as first_seen, COUNT(*) as executions
FROM events WHERE eventid = 1 AND devicetype = 12
GROUP BY LOGSOURCENAME(logsourceid), UTF8(payload)
HAVING MIN(starttime) > DATEADD(HOUR, -24, CURRENT_TIMESTAMP)
ORDER BY first_seen DESC`,
wazuhQuery:`rule.groups:sysmon AND data.win.eventdata.image:*
| stats first_occurrence by data.win.eventdata.image, agent.name
| where first_occurrence > now() - 24h`,
hypothesis:'A process never seen before on a host may indicate zero-day malware, new attacker tools, or unauthorized software installation.',
investigationSteps:['Verify process hash against VirusTotal/threat intel','Check digital signature and certificate chain','Review parent process chain and command line','Correlate with network connections from same timeframe','Check if process was recently dropped via browser/email'],
behavioralIndicators:['Process never observed on this host in 30-day baseline','Unsigned or self-signed binary','Execution from temp/user-writable directory','No matching entry in corporate software inventory','Parent process is browser, email client, or script interpreter'],
linkedSigmaRules:[],tags:['zero-day','first-seen','baseline','novel-process']},

{id:'AH-002',name:'Statistical Outlier — Rare Process per Environment',
huntType:'zero-day',category:'endpoint-anomalies',technique:'frequency-analysis',
description:'Find processes running on fewer than 1% of hosts using frequency analysis — statistical rarity is a strong threat signal.',
mitre:{tacticId:'TA0002',techniqueId:'T1059',techniqueName:'Command Interpreter'},
difficulty:'High',frequency:'Weekly',
splunkQuery:`index=sysmon EventCode=1
| stats dc(Computer) as host_count values(Computer) as hosts by Image
| eventstats sum(host_count) as env_total
| eval prevalence_pct = round(host_count / env_total * 100, 3)
| where prevalence_pct < 1 AND host_count < 3
| sort prevalence_pct
| head 50`,
qradarQuery:`SELECT UTF8(payload) as process_name,
  COUNT(DISTINCT LOGSOURCENAME(logsourceid)) as host_count
FROM events WHERE devicetype = 12 AND eventid = 1
GROUP BY UTF8(payload)
HAVING COUNT(DISTINCT LOGSOURCENAME(logsourceid)) < 3
ORDER BY host_count ASC LAST 30 DAYS`,
wazuhQuery:`rule.groups:sysmon AND data.win.eventdata.image:*
| rare data.win.eventdata.image
| where percent < 1`,
hypothesis:'Processes present on very few hosts are statistically anomalous — attackers tools typically appear on 1-2 compromised hosts only.',
investigationSteps:['Check if process matches any known malware families','Verify against corporate software deployment records','Review file metadata (compilation timestamp, PDB path)','Analyze strings in binary for IOCs','Check if file was recently created or downloaded'],
behavioralIndicators:['Binary exists on less than 1% of monitored hosts','File creation timestamp within last 72 hours','No entry in software asset management database','Packed or obfuscated binary detected','Suspicious file naming mimicking system processes'],
linkedSigmaRules:[],tags:['rarity','outlier','statistics','zero-day','prevalence']},

{id:'AH-003',name:'Abnormal Login Time Deviation Analysis',
huntType:'behavioral',category:'insider-threat',technique:'time-anomaly',
description:'Detect user logins outside their established working hours pattern using statistical time-based deviation from 30-day baseline.',
mitre:{tacticId:'TA0001',techniqueId:'T1078',techniqueName:'Valid Accounts'},
difficulty:'Medium',frequency:'Daily',
splunkQuery:`index=wineventlog EventCode=4624 LogonType IN (2, 10)
| eval hour = strftime(_time, "%H")
| stats count by TargetUserName, hour
| eventstats avg(count) as avg_logins stdev(count) as std_logins by TargetUserName
| eval zscore = round((count - avg_logins) / std_logins, 2)
| where zscore > 2 AND (hour < 6 OR hour > 22)
| sort - zscore`,
qradarQuery:`SELECT username, EXTRACT(HOUR FROM starttime) as login_hour,
  COUNT(*) as logins
FROM events WHERE eventid = 4624 AND logontype IN (2, 10)
GROUP BY username, EXTRACT(HOUR FROM starttime)
HAVING COUNT(*) > 3
ORDER BY login_hour LAST 30 DAYS`,
wazuhQuery:`rule.id:60106 AND data.win.eventdata.logonType:(2 OR 10)
| eval hour=date_hour(timestamp)
| where hour < 6 OR hour > 22
| stats count by data.win.eventdata.targetUserName, hour`,
hypothesis:'Logins during atypical hours for a user indicate compromised credentials, insider threat, or unauthorized access from a different timezone.',
investigationSteps:['Compare against users documented work schedule and timezone','Check source IP geolocation for geographic anomaly','Review data accessed during the off-hours session','Check for concurrent sessions from normal and anomalous locations','Verify with the user or their manager'],
behavioralIndicators:['Login between 00:00-05:00 local time for office workers','Login from new geographic location','Multiple failed auth attempts preceding success','Immediate access to sensitive resources after login','VPN connection from unusual ISP or ASN'],
linkedSigmaRules:['SR-0005'],tags:['off-hours','behavioral','insider','time-anomaly','deviation']},

{id:'AH-004',name:'Unusual Parent-Child Process Deviation',
huntType:'zero-day',category:'execution',technique:'deviation-detection',
description:'Detect parent-child process relationships that deviate from established baselines — reveals novel attack techniques and zero-day exploitation chains.',
mitre:{tacticId:'TA0002',techniqueId:'T1106',techniqueName:'Native API'},
difficulty:'High',frequency:'Daily',
splunkQuery:`index=sysmon EventCode=1
| stats count by ParentImage, Image
| eventstats sum(count) as parent_total by ParentImage
| eval child_pct = round(count / parent_total * 100, 2)
| where child_pct < 0.5 AND count < 5
| sort child_pct
| head 30`,
qradarQuery:`SELECT UTF8(payload) as parent_child_pair, COUNT(*) as occurrences
FROM events WHERE devicetype = 12 AND eventid = 1
GROUP BY UTF8(payload)
HAVING COUNT(*) < 3
ORDER BY occurrences ASC LAST 30 DAYS`,
wazuhQuery:`rule.groups:sysmon AND data.win.eventdata.parentImage:*
| rare data.win.eventdata.image by data.win.eventdata.parentImage
| where percent < 1`,
hypothesis:'Novel parent-child process relationships indicate previously unknown attack tools, zero-day exploits, or new attacker TTPs not covered by signature rules.',
investigationSteps:['Map full process tree from root to leaf','Verify if the parent process normally spawns this child in any environment','Review child process command line for suspicious arguments','Check for additional children spawned by the same parent in the same session','Correlate with file creation and network events'],
behavioralIndicators:['Parent process has never spawned this child in 30-day baseline','Child process is a known LOLBin or script interpreter','Command line contains encoding, download, or obfuscation patterns','Elevated integrity level achieved from low-privilege parent','Rapid succession of unusual child process spawns'],
linkedSigmaRules:[],tags:['parent-child','deviation','baseline','zero-day','process-tree']},

// ━━━ BEHAVIORAL ANOMALY HUNTING ━━━━━━━━━━━━━━━━━━━━━━━━━━━━
{id:'AH-005',name:'C2 Beaconing Jitter Analysis',
huntType:'behavioral',category:'command-control',technique:'frequency-analysis',
description:'Detect command-and-control beaconing by analyzing the regularity (low jitter) of outbound connection intervals using statistical methods.',
mitre:{tacticId:'TA0011',techniqueId:'T1071.001',techniqueName:'Web Protocols'},
difficulty:'High',frequency:'Daily',
splunkQuery:`index=proxy OR index=firewall direction=outbound
| bin _time span=1m
| stats count by src_ip, dest_ip, dest_port, _time
| streamstats window=20 current=f avg(count) as avg_c stdev(count) as std_c by src_ip, dest_ip
| eval jitter = if(avg_c > 0, round(std_c / avg_c, 3), 999)
| where jitter < 0.3 AND avg_c > 0
| stats count min(jitter) as min_jitter by src_ip, dest_ip, dest_port
| where count > 50
| sort min_jitter`,
qradarQuery:`SELECT sourceip, destinationip, destinationport,
  COUNT(*) as connections,
  MIN(starttime) as first_seen, MAX(starttime) as last_seen
FROM events WHERE category = 'Firewall' AND direction = 'outbound'
GROUP BY sourceip, destinationip, destinationport
HAVING COUNT(*) > 100
ORDER BY connections DESC LAST 24 HOURS`,
wazuhQuery:`rule.groups:firewall AND data.srcip:*
| bin timestamp span=5m
| stats count by data.srcip, data.dstip, timestamp
| where count > 50`,
hypothesis:'Low-jitter periodic connections are characteristic of automated C2 beaconing (Cobalt Strike, Metasploit, custom implants) rather than human-driven activity.',
investigationSteps:['Calculate precise inter-connection interval and standard deviation','Check destination IP/domain against threat intelligence feeds','Analyze TLS certificate and JA3/JA3S fingerprints','Review HTTP User-Agent strings for anomalies','Check payload size consistency across connections'],
behavioralIndicators:['Connection interval jitter below 30%','Consistent small payload sizes (heartbeat pattern)','HTTPS connections directly to IP addresses (no SNI)','Destination not in top Alexa/Tranco domains','Connections persist across workstation reboots'],
linkedSigmaRules:['SR-0044'],tags:['beaconing','c2','jitter','interval-analysis','cobalt-strike']},

{id:'AH-006',name:'Rare Outbound Port Usage Detection',
huntType:'zero-day',category:'network-anomalies',technique:'baselining',
description:'Detect hosts using uncommon outbound ports not seen in organizational baseline — may indicate covert C2 channels or tunneling.',
mitre:{tacticId:'TA0011',techniqueId:'T1571',techniqueName:'Non-Standard Port'},
difficulty:'Medium',frequency:'Daily',
splunkQuery:`index=firewall direction=outbound action=allowed
| stats dc(src_ip) as src_count values(src_ip) as sources by dest_port
| where src_count < 3
  AND dest_port NOT IN (80,443,53,22,25,110,143,587,993,995,8080,8443,3389)
| sort src_count
| head 30`,
qradarQuery:`SELECT destinationport,
  COUNT(DISTINCT sourceip) as unique_sources,
  COUNT(*) as total_flows
FROM flows WHERE direction = 'R2L'
GROUP BY destinationport
HAVING COUNT(DISTINCT sourceip) < 3
  AND destinationport NOT IN (80,443,53,22)
ORDER BY unique_sources ASC LAST 7 DAYS`,
wazuhQuery:`rule.groups:firewall AND data.dstport:*
  NOT data.dstport:(80 OR 443 OR 53 OR 22 OR 8080)
| rare data.dstport by data.srcip`,
hypothesis:'Hosts communicating on non-standard ports used by fewer than 3 systems likely have unauthorized software or covert communication channels.',
investigationSteps:['Identify the process initiating the connection (via Sysmon EventID 3)','Check destination IP/port against known malware C2 databases','Analyze data volume transferred on the unusual port','Verify against application firewall rules and approved software','Check if port matches known tunneling tools (chisel, ngrok, etc.)'],
behavioralIndicators:['Outbound port not used by any other host in environment','Single host generating >90% of traffic to this port','High data volume transferred','Destination IP in suspicious ASN or hosting provider','Port matches known attacker tool defaults'],
linkedSigmaRules:[],tags:['port-anomaly','c2','non-standard','baseline','tunneling']},

{id:'AH-007',name:'Credential Event Spike Z-Score Detection',
huntType:'behavioral',category:'credential-access',technique:'deviation-detection',
description:'Detect sudden spikes in credential-related events using z-score analysis against a rolling hourly baseline.',
mitre:{tacticId:'TA0006',techniqueId:'T1110',techniqueName:'Brute Force'},
difficulty:'Medium',frequency:'Hourly',
splunkQuery:`index=wineventlog EventCode IN (4625, 4648, 4768, 4769)
| bin _time span=1h
| stats count by _time
| eventstats avg(count) as baseline stdev(count) as sigma
| eval zscore = round((count - baseline) / sigma, 2)
| where zscore > 3
| sort - zscore`,
qradarQuery:`SELECT DATEFORMAT(starttime, 'yyyy-MM-dd HH') as hour,
  COUNT(*) as event_count
FROM events WHERE eventid IN (4625, 4648, 4768, 4769)
GROUP BY DATEFORMAT(starttime, 'yyyy-MM-dd HH')
ORDER BY event_count DESC LAST 7 DAYS`,
wazuhQuery:`(rule.id:60122 OR rule.id:60204)
| bin timestamp span=1h
| stats count by timestamp
| eval baseline=avg(count), sigma=stddev(count)
| where count > baseline + 3 * sigma`,
hypothesis:'Credential event volumes exceeding 3 standard deviations from the hourly mean indicate active brute force, password spraying, or Kerberos-based attacks.',
investigationSteps:['Identify the source IPs driving the spike','Check for password spray patterns (many users, few attempts each)','Review targeted account types (admin, service, regular)','Correlate with successful logons immediately following the spike','Check geolocation of source IPs for foreign origins'],
behavioralIndicators:['Z-score exceeds 3.0 (99.7th percentile)','Multiple distinct target accounts affected','Single or few source IPs responsible','Activity concentrated in non-business hours','Targeted accounts include domain admins or service accounts'],
linkedSigmaRules:['SR-0004'],tags:['spike','credential','brute-force','z-score','deviation']},

{id:'AH-008',name:'LOLBin Execution Chain Detection',
huntType:'behavioral',category:'defense-evasion',technique:'frequency-analysis',
description:'Hunt for sequences of 3+ Living-off-the-Land binaries executed within 10 minutes — indicates fileless attack frameworks operating without dropping custom binaries.',
mitre:{tacticId:'TA0005',techniqueId:'T1218',techniqueName:'System Binary Proxy Execution'},
difficulty:'High',frequency:'Daily',
splunkQuery:`index=sysmon EventCode=1
| search Image IN ("*mshta*","*regsvr32*","*rundll32*","*certutil*",
  "*msbuild*","*cmstp*","*wmic*","*bitsadmin*","*forfiles*","*pcalua*")
| transaction Computer User maxspan=10m
| where eventcount >= 3
| table _time Computer User eventcount Image CommandLine`,
qradarQuery:`SELECT sourceip, username, UTF8(payload) as cmd,
  COUNT(*) as lolbin_count
FROM events WHERE devicetype = 12
  AND (LOWER(UTF8(payload)) LIKE '%mshta%'
    OR LOWER(UTF8(payload)) LIKE '%certutil%'
    OR LOWER(UTF8(payload)) LIKE '%regsvr32%'
    OR LOWER(UTF8(payload)) LIKE '%bitsadmin%'
    OR LOWER(UTF8(payload)) LIKE '%rundll32%')
GROUP BY sourceip, username, UTF8(payload)
HAVING COUNT(*) >= 3
ORDER BY lolbin_count DESC LAST 24 HOURS`,
wazuhQuery:`rule.groups:sysmon AND (data.win.eventdata.image:*mshta*
  OR data.win.eventdata.image:*certutil*
  OR data.win.eventdata.image:*regsvr32*
  OR data.win.eventdata.image:*bitsadmin*)
| stats count by agent.name, data.win.eventdata.user
| where count >= 3`,
hypothesis:'Chains of 3+ LOLBin executions within a short window strongly indicate a fileless attack framework (Cobalt Strike, PowerShell Empire) or advanced adversary leveraging built-in tools.',
investigationSteps:['Map the complete LOLBin execution timeline with command lines','Check for network connections initiated by each LOLBin','Review files created or downloaded during the chain','Identify the initial entry point (email, browser, RDP)','Check for persistence mechanisms established during the chain'],
behavioralIndicators:['3+ different LOLBins executed within 10 minutes','LOLBin spawning another LOLBin as child process','Network download via certutil or bitsadmin','Encoded/obfuscated commands in LOLBin arguments','Execution chain ends with persistence setup (schtasks, reg add)'],
linkedSigmaRules:['SR-0006','SR-0007','SR-0023'],tags:['lolbin','fileless','chain','evasion','framework']},

{id:'AH-009',name:'Anomalous DNS Query Volume Detection',
huntType:'zero-day',category:'command-control',technique:'deviation-detection',
description:'Detect hosts generating DNS query volumes 3+ standard deviations above the environment mean — indicates DNS tunneling, C2, or data exfiltration.',
mitre:{tacticId:'TA0011',techniqueId:'T1071.004',techniqueName:'DNS'},
difficulty:'Medium',frequency:'Daily',
splunkQuery:`index=dns
| stats count as queries dc(query) as unique_domains by src_ip
| eventstats avg(queries) as avg_q stdev(queries) as std_q
| eval zscore = round((queries - avg_q) / std_q, 2)
| where zscore > 3
| sort - zscore`,
qradarQuery:`SELECT sourceip,
  COUNT(*) as dns_queries,
  COUNT(DISTINCT UTF8(payload)) as unique_domains
FROM events WHERE category = 'DNS'
GROUP BY sourceip
HAVING COUNT(*) > 1000
ORDER BY dns_queries DESC LAST 24 HOURS`,
wazuhQuery:`rule.groups:dns AND data.srcip:*
| stats count by data.srcip
| eval avg=avg(count), std=stddev(count)
| where count > avg + 3 * std`,
hypothesis:'Hosts with DNS query volumes far exceeding the organizational mean are likely conducting DNS tunneling, beaconing to C2 via DNS, or exfiltrating data through DNS queries.',
investigationSteps:['Analyze query domain entropy and label lengths','Check for high volume of TXT record queries','Review queried domains against threat intelligence','Identify the process generating DNS queries (Sysmon EventID 22)','Check for encoded data patterns in subdomain labels'],
behavioralIndicators:['DNS volume exceeding 3 standard deviations from host mean','High entropy in queried domain labels','Excessive TXT/NULL record queries','Queries to recently registered or DGA-like domains','Single process responsible for majority of queries'],
linkedSigmaRules:['SR-0044'],tags:['dns','volume','tunneling','anomaly','exfiltration']},

{id:'AH-010',name:'Privileged Account from New Source Host',
huntType:'behavioral',category:'active-directory',technique:'baselining',
description:'Detect privileged or service account logins from hosts or IPs never seen before in the 30-day baseline — strong lateral movement indicator.',
mitre:{tacticId:'TA0004',techniqueId:'T1078.002',techniqueName:'Domain Accounts'},
difficulty:'Medium',frequency:'Daily',
splunkQuery:`index=wineventlog EventCode=4624
  (TargetUserName=*admin* OR TargetUserName=*svc_* OR TargetUserName=Administrator)
| stats earliest(_time) as first_seen count by TargetUserName, SourceNetworkAddress, Computer
| where first_seen > relative_time(now(), "-24h@h")
| sort - first_seen`,
qradarQuery:`SELECT username, sourceip, destinationip,
  MIN(starttime) as first_login, COUNT(*) as logins
FROM events WHERE eventid = 4624
  AND (username LIKE '%admin%' OR username LIKE '%svc_%')
GROUP BY username, sourceip, destinationip
HAVING MIN(starttime) > DATEADD(DAY, -1, CURRENT_TIMESTAMP)
ORDER BY first_login DESC`,
wazuhQuery:`rule.id:60106
  AND (data.win.eventdata.targetUserName:*admin*
    OR data.win.eventdata.targetUserName:*svc_*)
| stats first_occurrence by data.win.eventdata.targetUserName,
  data.win.eventdata.ipAddress`,
hypothesis:'Privileged accounts authenticating from previously unseen source hosts indicate credential theft, lateral movement, or unauthorized access.',
investigationSteps:['Verify with the account owner whether they used a new device','Check for failed login attempts preceding the successful one','Review session activity for data access or privilege escalation','Validate the source host security posture and ownership','Check for pass-the-hash or pass-the-ticket artifacts'],
behavioralIndicators:['Admin account used from host not in 30-day baseline','Service account performing interactive login (should be automated only)','Login from non-server host with service account credentials','Concurrent sessions from normal and anomalous sources','Immediate access to sensitive AD objects after login'],
linkedSigmaRules:['SR-0029'],tags:['privileged','new-source','baseline','lateral-movement','credential-theft']}
];

// ── Merge with existing hunting queries ──
if (typeof HUNTING_QUERIES !== 'undefined') {
  HUNTING_QUERIES.push(...ADVANCED_HUNTS);
}

// ── Hunt technique metadata for UI ──
const HUNT_TECHNIQUES = {
  'baselining': { icon: '📊', label: 'Baselining', desc: 'Compare against established normal behavior' },
  'frequency-analysis': { icon: '📈', label: 'Frequency Analysis', desc: 'Statistical frequency and prevalence analysis' },
  'deviation-detection': { icon: '📉', label: 'Deviation Detection', desc: 'Detect deviations from rolling baselines' },
  'time-anomaly': { icon: '⏰', label: 'Time Anomaly', desc: 'Time-based behavioral pattern analysis' }
};

window.ADVANCED_HUNTS = ADVANCED_HUNTS;
window.HUNT_TECHNIQUES = HUNT_TECHNIQUES;
console.log('[SigmaGuard] Advanced Threat Hunting loaded:', ADVANCED_HUNTS.length, 'zero-day & behavioral queries');
