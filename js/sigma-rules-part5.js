// Sigma Rules Database - Part 5: Brute Force, Ransomware, Web Attacks, Reconnaissance
// 25 new rules across 4 new categories
const SIGMA_RULES_PART5 = [

// ═══════════════════════════════════════════════════════════════
// BRUTE FORCE (7 rules)
// ═══════════════════════════════════════════════════════════════
{
  id: 'SR-0081', title: 'Failed Login Brute Force — Same IP Threshold',
  status: 'stable', severity: 'high', author: 'SOC Platform', date: '2024-05-15', modified: '2024-12-15',
  category: 'brute-force',
  description: 'Detects brute force by identifying a single source IP generating excessive failed authentication events within a short window. Essential first-line detection for credential attacks.',
  tacticId: 'TA0006', tacticName: 'Credential Access',
  techniqueId: 'T1110.001', techniqueName: 'Password Guessing',
  logsource: { product: 'windows', service: 'security' },
  sigmaYaml: `title: Failed Login Brute Force - Same IP Threshold
id: bf001-sigma-0081
status: stable
description: Detects excessive failed logins from a single source IP
logsource:
    product: windows
    service: security
detection:
    selection:
        EventID: 4625
    condition: selection | count() by IpAddress > 15
falsepositives:
    - Vulnerability scanners
    - SSO token failures
level: high
tags:
    - attack.credential_access
    - attack.t1110.001`,
  splunkQuery: `index=wineventlog sourcetype=WinEventLog:Security EventCode=4625
| bin _time span=15m
| stats count as failed_attempts dc(TargetUserName) as unique_users values(TargetUserName) as targeted_users by src_ip, _time
| where failed_attempts > 15
| sort - failed_attempts
| table _time, src_ip, failed_attempts, unique_users, targeted_users`,
  qradarQuery: `SELECT sourceip, COUNT(*) as failed_count,
  MIN(DATEFORMAT(starttime,'yyyy-MM-dd HH:mm')) as first_attempt,
  MAX(DATEFORMAT(starttime,'yyyy-MM-dd HH:mm')) as last_attempt
FROM events
WHERE QIDNAME(qid) ILIKE '%Logon Failure%'
  AND CATEGORYNAME(highlevelcategory) = 'Authentication'
GROUP BY sourceip
HAVING COUNT(*) > 15
ORDER BY failed_count DESC
LAST 1 HOURS`,
  detectionExplanation: 'Monitors Windows Event ID 4625 (failed logon) and aggregates by source IP within 15-minute windows. Threshold of 15+ failures per source IP per window balances detection sensitivity with false-positive tolerance.',
  requiredLogs: ['Windows Security Event 4625', 'Linux auth.log', 'Firewall auth logs'],
  logConfig: 'Enable Audit Logon Events in Windows Advanced Audit Policy. Forward authentication logs to SIEM.',
  falsePositives: ['Automated health monitoring', 'SSO token failures', 'Expired service account credentials', 'Vulnerability scanners'],
  tuning: 'Threshold: 15-20 failures/15min for workstations, 50+ for domain controllers. Enrich with GeoIP. Correlate with 4624 (success) after failures.',
  commonErrors: ['Fails if Audit Logon policy not enabled', 'src_ip may appear as Source_Network_Address depending on TA'],
  responseActions: ['Check for 4624 success from same IP', 'Block source IP if external', 'Force password reset for targeted accounts', 'Collect full auth timeline'],
  threatIntel: { cves: [], cisaKev: false, campaigns: [], iocs: [] },
  references: ['https://attack.mitre.org/techniques/T1110/001/']
},
{
  id: 'SR-0082', title: 'Password Spray — Low-and-Slow Across Accounts',
  status: 'stable', severity: 'critical', author: 'SOC Platform', date: '2024-06-01', modified: '2024-12-15',
  category: 'brute-force',
  description: 'Detects password spray attacks where an attacker tries one or few passwords against many accounts simultaneously, staying below per-account lockout thresholds.',
  tacticId: 'TA0006', tacticName: 'Credential Access',
  techniqueId: 'T1110.003', techniqueName: 'Password Spraying',
  logsource: { product: 'windows', service: 'security' },
  sigmaYaml: `title: Password Spray - Low-and-Slow Detection
id: bf002-sigma-0082
status: stable
description: Detects spray attacks - many unique users, few attempts each
logsource:
    product: windows
    service: security
detection:
    selection:
        EventID: 4625
    condition: selection | count() by TargetUserName, IpAddress > 20
falsepositives:
    - Automated deployment tools
level: critical
tags:
    - attack.credential_access
    - attack.t1110.003`,
  splunkQuery: `index=wineventlog sourcetype=WinEventLog:Security EventCode=4625
| bin _time span=30m
| stats dc(TargetUserName) as unique_targets count as attempts values(TargetUserName) as users by src_ip, _time
| where unique_targets > 20 AND attempts < (unique_targets * 3)
| eval spray_ratio=round(attempts/unique_targets,2)
| sort - unique_targets
| table _time, src_ip, unique_targets, attempts, spray_ratio, users`,
  qradarQuery: `SELECT sourceip,
  COUNT(DISTINCT username) as unique_targets,
  COUNT(*) as total_attempts,
  MIN(DATEFORMAT(starttime,'HH:mm:ss')) as start_window,
  MAX(DATEFORMAT(starttime,'HH:mm:ss')) as end_window
FROM events
WHERE QIDNAME(qid) ILIKE '%Logon Failure%'
  AND CATEGORYNAME(highlevelcategory) = 'Authentication'
GROUP BY sourceip
HAVING COUNT(DISTINCT username) > 20
  AND COUNT(*) < (COUNT(DISTINCT username) * 3)
ORDER BY unique_targets DESC
LAST 2 HOURS`,
  detectionExplanation: 'Key indicator: high unique_targets with low attempts-per-user ratio (1-3 attempts each). Distinguishes from brute force by the breadth of targets vs depth of attempts.',
  requiredLogs: ['Windows Security Event 4625', 'Azure AD Sign-in Logs', 'Domain Controller audit logs'],
  logConfig: 'Audit logon events on all domain controllers. Forward Azure AD sign-in logs.',
  falsePositives: ['Automated deployment tools authenticating to many systems', 'SCCM health checks'],
  tuning: 'Set unique_targets threshold at 20+. Correlate with successful logins within the same window.',
  commonErrors: ['Sprays with >30min delays may evade 30m windows', 'Different DCs may log the same spray fragmented'],
  responseActions: ['CRITICAL — likely active adversary', 'Identify any successful login from spray source', 'Force reset ALL targeted accounts', 'Block source IP/range'],
  threatIntel: { cves: [], cisaKev: false, campaigns: ['Scattered Spider', 'Midnight Blizzard'], iocs: [] },
  references: ['https://attack.mitre.org/techniques/T1110/003/']
},
{
  id: 'SR-0083', title: 'Credential Stuffing Pattern Detection',
  status: 'test', severity: 'high', author: 'SOC Platform', date: '2024-07-10', modified: '2024-12-10',
  category: 'brute-force',
  description: 'Identifies credential stuffing attacks where stolen username/password pairs from breaches are replayed against authentication endpoints, characterized by many unique usernames with single attempts from distributed sources.',
  tacticId: 'TA0006', tacticName: 'Credential Access',
  techniqueId: 'T1110.004', techniqueName: 'Credential Stuffing',
  logsource: { product: 'windows', service: 'security' },
  sigmaYaml: `title: Credential Stuffing Pattern Detection
id: bf003-sigma-0083
status: test
description: Detects credential stuffing from breached credential sets
logsource:
    product: windows
    service: security
detection:
    selection:
        EventID: 4625
        LogonType:
            - 10
            - 3
    condition: selection | count(distinct TargetUserName) by _time > 50
falsepositives:
    - Password reset campaigns
level: high
tags:
    - attack.credential_access
    - attack.t1110.004`,
  splunkQuery: `index=wineventlog sourcetype=WinEventLog:Security EventCode=4625 LogonType=10 OR LogonType=3
| bin _time span=1h
| stats dc(TargetUserName) as unique_users dc(src_ip) as unique_sources count as total by _time
| where unique_users > 50 AND unique_sources > 5
| eval stuffing_score=round(unique_users/unique_sources,1)
| where stuffing_score > 3
| table _time, unique_users, unique_sources, total, stuffing_score`,
  qradarQuery: `SELECT COUNT(DISTINCT username) as unique_users,
  COUNT(DISTINCT sourceip) as unique_sources,
  COUNT(*) as total_attempts
FROM events
WHERE QIDNAME(qid) ILIKE '%Logon Failure%'
  AND CATEGORYNAME(highlevelcategory) = 'Authentication'
GROUP BY DATEFORMAT(starttime,'yyyy-MM-dd HH')
HAVING COUNT(DISTINCT username) > 50
  AND COUNT(DISTINCT sourceip) > 5
ORDER BY unique_users DESC
LAST 4 HOURS`,
  detectionExplanation: 'Credential stuffing differs from spraying: many unique usernames (often from breach data) with 1-2 attempts each from distributed sources. High unique_users-to-unique_sources ratio indicates automated replay.',
  requiredLogs: ['Windows Security Event 4625', 'Web application auth logs', 'VPN/SSO authentication logs'],
  logConfig: 'Enable web app auth log forwarding. Track logon types to distinguish remote from local attempts.',
  falsePositives: ['Large password reset campaigns', 'New employee bulk provisioning', 'Automated testing frameworks'],
  tuning: 'Focus on internet-facing endpoints. Correlate with known breach data. Flag non-existent usernames (email format).',
  commonErrors: ['Web apps may return 200 with error body instead of proper auth failure events'],
  responseActions: ['Identify any successful logins from same sources', 'Implement IP-based rate limiting', 'Cross-reference with HIBP', 'Enable MFA enforcement'],
  threatIntel: { cves: [], cisaKev: false, campaigns: [], iocs: [] },
  references: ['https://attack.mitre.org/techniques/T1110/004/']
},
{
  id: 'SR-0084', title: 'Account Lockout Storm',
  status: 'stable', severity: 'medium', author: 'SOC Platform', date: '2024-03-20', modified: '2024-12-05',
  category: 'brute-force',
  description: 'Detects sudden spike in account lockout events which can indicate an active brute force/spray attack or misconfigured service accounts causing cascading lockouts.',
  tacticId: 'TA0006', tacticName: 'Credential Access',
  techniqueId: 'T1110', techniqueName: 'Brute Force',
  logsource: { product: 'windows', service: 'security' },
  sigmaYaml: `title: Account Lockout Storm
id: bf004-sigma-0084
status: stable
description: Detects sudden spike in account lockouts
logsource:
    product: windows
    service: security
detection:
    selection:
        EventID: 4740
    condition: selection | count() by TargetDomainName > 10
falsepositives:
    - Service accounts with stale credentials
level: medium
tags:
    - attack.credential_access
    - attack.t1110`,
  splunkQuery: `index=wineventlog sourcetype=WinEventLog:Security EventCode=4740
| bin _time span=10m
| stats count as lockouts dc(TargetUserName) as locked_accounts values(TargetUserName) as accounts by _time, TargetDomainName
| where lockouts > 10
| sort - lockouts
| table _time, TargetDomainName, lockouts, locked_accounts, accounts`,
  qradarQuery: `SELECT username, sourceip,
  COUNT(*) as lockout_count,
  LOGSOURCENAME(logsourceid) as log_source
FROM events
WHERE QIDNAME(qid) ILIKE '%Account Locked%'
  OR QIDNAME(qid) ILIKE '%Account Lockout%'
GROUP BY username, sourceip, logsourceid
HAVING COUNT(*) > 3
ORDER BY lockout_count DESC
LAST 2 HOURS`,
  detectionExplanation: 'Event 4740 fires when an account is locked out. Sudden spikes indicate active attacks. When >50% locks are same account = brute force. When spread across many accounts = password spray.',
  requiredLogs: ['Windows Security Event 4740 (Account Locked Out)', 'Domain Controller logs'],
  logConfig: 'Audit account lockout events. Ensure all DCs forward to SIEM.',
  falsePositives: ['Service accounts with stale credentials', 'Users after password change', 'Printer/scanner with saved credentials'],
  tuning: 'Threshold: >10 lockouts in 10 minutes. Track Caller Computer Name field for source identification.',
  commonErrors: ['Event 4740 only logs on PDC emulator unless collected from all DCs'],
  responseActions: ['Identify source via Caller Computer Name', 'Determine brute force vs spray pattern', 'Update stale service account credentials'],
  threatIntel: { cves: [], cisaKev: false, campaigns: [], iocs: [] },
  references: ['https://attack.mitre.org/techniques/T1110/']
},
{
  id: 'SR-0085', title: 'SSH / RDP Brute Force Detection',
  status: 'stable', severity: 'high', author: 'SOC Platform', date: '2024-04-10', modified: '2024-12-15',
  category: 'brute-force',
  description: 'Detects brute force attacks targeting SSH (port 22) and RDP (port 3389) services — the most common attack vectors for internet-facing systems.',
  tacticId: 'TA0006', tacticName: 'Credential Access',
  techniqueId: 'T1110.001', techniqueName: 'Password Guessing',
  logsource: { product: 'linux', service: 'auth' },
  sigmaYaml: `title: SSH / RDP Brute Force Detection
id: bf005-sigma-0085
status: stable
description: Detects brute force against SSH and RDP
logsource:
    product: linux
    service: auth
detection:
    selection:
        EventID|contains:
            - 'Failed password'
    condition: selection | count() by src_ip > 10
falsepositives:
    - Ansible/Puppet automation failures
level: high
tags:
    - attack.credential_access
    - attack.t1110.001`,
  splunkQuery: `index=linux_secure sourcetype=linux_secure "Failed password"
| rex "Failed password for (?:invalid user )?(?<user>\\S+) from (?<src_ip>\\S+)"
| bin _time span=15m
| stats count as attempts dc(user) as unique_users values(user) as users by src_ip, _time
| where attempts > 10
| table _time, src_ip, attempts, unique_users, users`,
  qradarQuery: `SELECT sourceip, destinationip,
  COUNT(*) as failed_attempts,
  MIN(DATEFORMAT(starttime,'HH:mm:ss')) as first_seen,
  MAX(DATEFORMAT(starttime,'HH:mm:ss')) as last_seen
FROM events
WHERE CATEGORYNAME(highlevelcategory) = 'Authentication'
  AND CATEGORYNAME(category) ILIKE '%Failure%'
  AND (destinationport = 22 OR destinationport = 3389)
GROUP BY sourceip, destinationip
HAVING COUNT(*) > 10
ORDER BY failed_attempts DESC
LAST 1 HOURS`,
  detectionExplanation: 'Monitors for excessive failed password attempts against SSH and RDP. Threshold of 10+ in 15 minutes indicates automated attack. SSH detected from auth.log, RDP from Windows Event 4625 LogonType=10.',
  requiredLogs: ['Linux auth.log / secure', 'Windows Security 4625 (LogonType=10)', 'Firewall logs for port 22/3389'],
  logConfig: 'Forward Linux auth logs via syslog. Enable Windows logon auditing for RDP.',
  falsePositives: ['Admin SSH key issues', 'Ansible/Puppet failures', 'Nagios with stale SSH keys'],
  tuning: '10+ failures/15m for SSH, 5+ for RDP. Implement fail2ban for Linux. GeoIP enrich to flag non-business countries.',
  commonErrors: ['SSH log format varies across distros', 'RDP NLA failures may not generate 4625'],
  responseActions: ['Block source IP at perimeter', 'Check for successful session from same IP', 'Consider port knocking or VPN-only access'],
  threatIntel: { cves: [], cisaKev: false, campaigns: [], iocs: [] },
  references: ['https://attack.mitre.org/techniques/T1110/001/']
},
{
  id: 'SR-0086', title: 'Kerberos Pre-Authentication Brute Force',
  status: 'stable', severity: 'high', author: 'SOC Platform', date: '2024-05-20', modified: '2024-12-10',
  category: 'brute-force',
  description: 'Detects brute force against Kerberos by monitoring excessive pre-authentication failures (Event 4771), indicating domain-level credential attacks.',
  tacticId: 'TA0006', tacticName: 'Credential Access',
  techniqueId: 'T1110.001', techniqueName: 'Password Guessing',
  logsource: { product: 'windows', service: 'security' },
  sigmaYaml: `title: Kerberos Pre-Authentication Brute Force
id: bf006-sigma-0086
status: stable
description: Detects Kerberos pre-auth failures indicating brute force
logsource:
    product: windows
    service: security
detection:
    selection:
        EventID: 4771
        Status: '0x18'
    filter:
        TargetUserName:
            - 'krbtgt'
            - 'guest'
    condition: selection and not filter
falsepositives:
    - Clock skew causing pre-auth failures
level: high
tags:
    - attack.credential_access
    - attack.t1110.001`,
  splunkQuery: `index=wineventlog sourcetype=WinEventLog:Security EventCode=4771 Status=0x18
| bin _time span=15m
| stats count as failures dc(TargetUserName) as unique_users values(TargetUserName) as users by IpAddress, _time
| where failures > 15
| sort - failures
| table _time, IpAddress, failures, unique_users, users`,
  qradarQuery: `SELECT sourceip,
  COUNT(*) as kerb_failures,
  COUNT(DISTINCT username) as unique_accounts,
  LOGSOURCENAME(logsourceid) as log_source
FROM events
WHERE QIDNAME(qid) ILIKE '%Kerberos Pre-Authentication Failure%'
GROUP BY sourceip, logsourceid
HAVING COUNT(*) > 15
ORDER BY kerb_failures DESC
LAST 2 HOURS`,
  detectionExplanation: 'Status 0x18 = wrong password (true brute force). Status 0x6 = unknown username (enumeration). Kerberos brute force suggests internal attacker or post-compromise activity — higher severity than NTLM.',
  requiredLogs: ['Windows Security Event 4771', 'Domain Controller logs', 'Kerberos KDC audit logs'],
  logConfig: 'Enable Kerberos auditing on all domain controllers.',
  falsePositives: ['Clock skew (Status 0x17)', 'Expired user accounts', 'Mobile devices with cached tickets'],
  tuning: 'Alert on any external IP (should never occur). Track Status 0x18 and 0x6 separately.',
  commonErrors: ['Event 4771 only logs on DCs', 'IP uses IPv6-mapped format (::ffff:10.1.1.1)'],
  responseActions: ['Kerberos BF is almost always internal — treat as active compromise', 'Identify source host immediately', 'Hunt for Rubeus/Kerbrute on source'],
  threatIntel: { cves: [], cisaKev: false, campaigns: [], iocs: [] },
  references: ['https://attack.mitre.org/techniques/T1110/001/']
},
{
  id: 'SR-0087', title: 'Web Login Brute Force — HTTP 401/403 Spike',
  status: 'test', severity: 'medium', author: 'SOC Platform', date: '2024-08-15', modified: '2024-12-10',
  category: 'brute-force',
  description: 'Detects web application brute force by monitoring HTTP 401/403 response spikes from single source IPs against login endpoints.',
  tacticId: 'TA0006', tacticName: 'Credential Access',
  techniqueId: 'T1110.001', techniqueName: 'Password Guessing',
  logsource: { product: 'webserver', category: 'access' },
  sigmaYaml: `title: Web Login Brute Force - HTTP 401/403 Spike
id: bf007-sigma-0087
status: test
description: Detects brute force via HTTP auth failure spikes
logsource:
    category: webserver
    product: webserver
detection:
    selection:
        status:
            - 401
            - 403
    condition: selection | count() by clientip > 30
falsepositives:
    - Vulnerability scanners
level: medium
tags:
    - attack.credential_access
    - attack.t1110.001`,
  splunkQuery: `index=web sourcetype=access_combined (status=401 OR status=403)
| rex field=uri_path "(?<login_endpoint>/(?:login|auth|signin|api/auth|oauth)\\S*)"
| where isnotnull(login_endpoint)
| bin _time span=10m
| stats count as attempts dc(uri_path) as endpoints by clientip, _time
| where attempts > 30
| table _time, clientip, attempts, endpoints`,
  qradarQuery: `SELECT sourceip, destinationip,
  COUNT(*) as http_failures,
  COUNT(DISTINCT url) as endpoints_hit
FROM events
WHERE CATEGORYNAME(highlevelcategory) = 'Access'
  AND (eventname ILIKE '%401%' OR eventname ILIKE '%403%')
GROUP BY sourceip, destinationip
HAVING COUNT(*) > 30
ORDER BY http_failures DESC
LAST 1 HOURS`,
  detectionExplanation: 'Web-layer brute force detection via HTTP status codes. Threshold varies by traffic: 30-100 for low-traffic, 200+ for high-traffic apps. Focus on login-specific URI patterns.',
  requiredLogs: ['Web server access logs', 'WAF logs', 'Reverse proxy logs'],
  logConfig: 'Forward web server access logs to SIEM. Configure WAF logging.',
  falsePositives: ['Vulnerability scanners', 'Broken SSO configurations', 'API integration returning 401'],
  tuning: 'Correlate with 200 OK responses after spike to detect successful compromise. Implement WAF rate limiting.',
  commonErrors: ['Many apps return 200 with error body instead of 401/403', 'WAF may block before SIEM sees events'],
  responseActions: ['Check for successful login from same source', 'Implement temporary IP block via WAF', 'Review app-level logs'],
  threatIntel: { cves: [], cisaKev: false, campaigns: [], iocs: [] },
  references: ['https://attack.mitre.org/techniques/T1110/001/']
},

// ═══════════════════════════════════════════════════════════════
// RANSOMWARE (6 rules)
// ═══════════════════════════════════════════════════════════════
{
  id: 'SR-0088', title: 'Ransomware — Mass File Encryption Indicators',
  status: 'stable', severity: 'critical', author: 'SOC Platform', date: '2024-02-10', modified: '2024-12-15',
  category: 'ransomware',
  description: 'Detects ransomware encryption behavior by monitoring for mass file rename operations to known ransomware extensions and rapid file modification patterns.',
  tacticId: 'TA0040', tacticName: 'Impact',
  techniqueId: 'T1486', techniqueName: 'Data Encrypted for Impact',
  logsource: { product: 'windows', category: 'file_event' },
  sigmaYaml: `title: Ransomware Mass File Encryption
id: rw001-sigma-0088
status: stable
description: Detects mass file encryption with ransomware extensions
logsource:
    product: windows
    category: file_event
detection:
    selection:
        TargetFilename|endswith:
            - '.encrypted'
            - '.locked'
            - '.crypto'
            - '.crypt'
            - '.enc'
            - '.WNCRY'
            - '.locky'
            - '.cerber'
            - '.zepto'
            - '.lockbit'
            - '.blackcat'
            - '.alphv'
    condition: selection
falsepositives:
    - Legitimate encryption tools
level: critical
tags:
    - attack.impact
    - attack.t1486`,
  splunkQuery: `index=wineventlog sourcetype=WinEventLog:Sysmon EventCode=11
| where match(TargetFilename,"(?i)\\.(encrypted|locked|crypto|crypt|enc|WNCRY|locky|cerber|zepto|lockbit|blackcat|alphv)$")
| bin _time span=5m
| stats count as encrypted_files dc(TargetFilename) as unique_files by ComputerName, User, _time
| where encrypted_files > 20
| sort - encrypted_files
| table _time, ComputerName, User, encrypted_files, unique_files`,
  qradarQuery: `SELECT sourceip, username,
  COUNT(*) as encrypted_files,
  MIN(DATEFORMAT(starttime,'HH:mm:ss')) as first_encrypt,
  MAX(DATEFORMAT(starttime,'HH:mm:ss')) as last_encrypt
FROM events
WHERE CATEGORYNAME(category) ILIKE '%File%'
  AND ("File Path" ILIKE '%.encrypted' OR "File Path" ILIKE '%.locked'
    OR "File Path" ILIKE '%.crypto' OR "File Path" ILIKE '%.lockbit'
    OR "File Path" ILIKE '%.blackcat')
GROUP BY sourceip, username
HAVING COUNT(*) > 20
ORDER BY encrypted_files DESC
LAST 1 HOURS`,
  detectionExplanation: 'Ransomware renames files with characteristic extensions during encryption. 20+ files with ransomware extensions in 5 minutes is definitive. This is a late-stage detection — encryption is already in progress.',
  requiredLogs: ['Sysmon Event 11 (FileCreate)', 'File system auditing', 'EDR file telemetry'],
  logConfig: 'Enable Sysmon file creation monitoring. Configure file audit policies on sensitive shares.',
  falsePositives: ['Legitimate encryption tools (VeraCrypt, BitLocker)', 'Development testing'],
  tuning: 'Set threshold at 20+ files in 5 minutes. Correlate with shadow copy deletion (Event 524/Sysmon).',
  commonErrors: ['New ransomware families use random extensions', 'File events can be extremely high volume'],
  responseActions: ['CRITICAL — ISOLATE IMMEDIATELY', 'Kill the encrypting process', 'Disconnect network shares', 'Preserve encryption key if possible', 'Activate IR and backup recovery'],
  threatIntel: { cves: [], cisaKev: false, campaigns: ['LockBit 3.0', 'ALPHV/BlackCat Ransomware'], iocs: [] },
  references: ['https://attack.mitre.org/techniques/T1486/']
},
{
  id: 'SR-0089', title: 'Volume Shadow Copy Deletion — Recovery Prevention',
  status: 'stable', severity: 'critical', author: 'SOC Platform', date: '2024-01-15', modified: '2024-12-15',
  category: 'ransomware',
  description: 'Detects deletion of Volume Shadow Copies via vssadmin.exe, wmic.exe, or PowerShell — a pre-encryption step in nearly all ransomware to prevent recovery.',
  tacticId: 'TA0040', tacticName: 'Impact',
  techniqueId: 'T1490', techniqueName: 'Inhibit System Recovery',
  logsource: { product: 'windows', category: 'process_creation' },
  sigmaYaml: `title: Shadow Copy Deletion for Recovery Prevention
id: rw002-sigma-0089
status: stable
description: Detects shadow copy deletion - ransomware precursor
logsource:
    product: windows
    category: process_creation
detection:
    selection_vssadmin:
        Image|endswith: '\\\\vssadmin.exe'
        CommandLine|contains:
            - 'delete shadows'
            - 'resize shadowstorage'
    selection_wmic:
        Image|endswith: '\\\\wmic.exe'
        CommandLine|contains: 'shadowcopy delete'
    selection_ps:
        CommandLine|contains:
            - 'Get-WmiObject Win32_Shadowcopy'
            - 'Win32_ShadowCopy'
            - '.Delete()'
    selection_bcdedit:
        Image|endswith: '\\\\bcdedit.exe'
        CommandLine|contains:
            - 'recoveryenabled no'
            - 'bootstatuspolicy ignoreallfailures'
    condition: selection_vssadmin or selection_wmic or selection_ps or selection_bcdedit
falsepositives:
    - Storage management operations
level: critical
tags:
    - attack.impact
    - attack.t1490`,
  splunkQuery: `index=wineventlog (sourcetype=WinEventLog:Security EventCode=4688 OR sourcetype=WinEventLog:Sysmon EventCode=1)
| where match(CommandLine,"(?i)(vssadmin.*delete.*shadows|wmic.*shadowcopy.*delete|Win32_ShadowCopy.*Delete|bcdedit.*recoveryenabled.*no|bcdedit.*ignoreallfailures)")
| eval technique=case(
    match(CommandLine,"vssadmin"),"vssadmin_delete",
    match(CommandLine,"wmic"),"wmic_delete",
    match(CommandLine,"bcdedit"),"bcdedit_disable",
    true(),"powershell_delete")
| stats count values(technique) as methods values(CommandLine) as cmds by ComputerName, User, _time
| table _time, ComputerName, User, methods, cmds, count`,
  qradarQuery: `SELECT sourceip, username,
  QIDNAME(qid) as event_name,
  COUNT(*) as shadow_events
FROM events
WHERE (eventname ILIKE '%vssadmin%delete%shadow%'
  OR eventname ILIKE '%wmic%shadowcopy%delete%'
  OR eventname ILIKE '%bcdedit%recovery%')
GROUP BY sourceip, username, qid
HAVING COUNT(*) > 0
ORDER BY shadow_events DESC
LAST 24 HOURS`,
  detectionExplanation: 'Shadow copy deletion is a near-universal ransomware precursor step. Detecting this before encryption starts provides a critical response window. Multiple methods: vssadmin delete shadows /all /quiet, wmic shadowcopy delete, bcdedit /set recoveryenabled no.',
  requiredLogs: ['Sysmon Event ID 1', 'Windows Security 4688', 'VSS Event 524'],
  logConfig: 'Process creation auditing with command line capture.',
  falsePositives: ['Storage management by IT', 'Shadow copy rotation by backup software'],
  tuning: 'Near zero false-positive rule. Any shadow copy deletion warrants investigation. Correlate with subsequent file encryption.',
  commonErrors: ['PowerShell-based deletion uses COM objects, not CLI tools'],
  responseActions: ['CRITICAL — ransomware deployment imminent', 'Isolate the system immediately', 'Check for encryption process', 'Activate backup recovery', 'Full IR engagement'],
  threatIntel: { cves: [], cisaKev: false, campaigns: ['LockBit 3.0', 'ALPHV/BlackCat Ransomware'], iocs: [] },
  references: ['https://attack.mitre.org/techniques/T1490/']
},
{
  id: 'SR-0090', title: 'Ransomware Note Creation Detection',
  status: 'stable', severity: 'critical', author: 'SOC Platform', date: '2024-03-10', modified: '2024-12-10',
  category: 'ransomware',
  description: 'Detects creation of ransom note files with common names used by major ransomware families, providing definitive ransomware confirmation.',
  tacticId: 'TA0040', tacticName: 'Impact',
  techniqueId: 'T1486', techniqueName: 'Data Encrypted for Impact',
  logsource: { product: 'windows', category: 'file_event' },
  sigmaYaml: `title: Ransomware Note File Creation
id: rw003-sigma-0090
status: stable
description: Detects ransom note file creation
logsource:
    product: windows
    category: file_event
detection:
    selection:
        TargetFilename|contains:
            - 'README_TO_DECRYPT'
            - 'DECRYPT_INSTRUCTIONS'
            - 'HOW_TO_RECOVER'
            - 'RESTORE_FILES'
            - 'ransom-note'
            - '_readme.txt'
            - 'RECOVER-FILES.txt'
            - 'How To Restore'
    condition: selection
falsepositives:
    - Security testing
level: critical
tags:
    - attack.impact
    - attack.t1486`,
  splunkQuery: `index=wineventlog sourcetype=WinEventLog:Sysmon EventCode=11
| where match(TargetFilename,"(?i)(README_TO_DECRYPT|DECRYPT_INSTRUCTIONS|HOW_TO_RECOVER|RESTORE_FILES|ransom-note|_readme\\.txt|RECOVER-FILES|How.To.Restore)")
| stats count values(TargetFilename) as note_files dc(ComputerName) as affected_hosts by User, _time
| table _time, User, note_files, affected_hosts, count`,
  qradarQuery: `SELECT sourceip, username,
  QIDNAME(qid) as event_name,
  COUNT(*) as ransom_notes
FROM events
WHERE ("File Path" ILIKE '%README_TO_DECRYPT%'
  OR "File Path" ILIKE '%DECRYPT_INSTRUCTIONS%'
  OR "File Path" ILIKE '%HOW_TO_RECOVER%'
  OR "File Path" ILIKE '%RESTORE_FILES%'
  OR "File Path" ILIKE '%_readme.txt%')
GROUP BY sourceip, username, qid
HAVING COUNT(*) > 0
ORDER BY ransom_notes DESC
LAST 24 HOURS`,
  detectionExplanation: 'Ransom notes are definitive ransomware indicators. Major families use recognizable filenames. Detection here means encryption has already begun — focus on containment.',
  requiredLogs: ['Sysmon Event 11 (FileCreate)', 'File system auditing'],
  logConfig: 'Sysmon file monitoring or EDR file telemetry.',
  falsePositives: ['Authorized penetration testing', 'Security awareness training files'],
  tuning: 'Zero-tolerance rule. Any ransom note creation should trigger immediate response.',
  commonErrors: ['New ransomware may use unique note names not in the signature list'],
  responseActions: ['CONFIRMED RANSOMWARE — Execute IR playbook', 'Isolate ALL affected systems', 'Preserve ransom notes for intelligence', 'Begin forensic timeline', 'Notify leadership and legal'],
  threatIntel: { cves: [], cisaKev: false, campaigns: ['LockBit 3.0', 'ALPHV/BlackCat Ransomware'], iocs: [] },
  references: ['https://attack.mitre.org/techniques/T1486/']
},
{
  id: 'SR-0091', title: 'Critical Service Stop — Pre-Encryption',
  status: 'stable', severity: 'high', author: 'SOC Platform', date: '2024-04-05', modified: '2024-12-10',
  category: 'ransomware',
  description: 'Detects stopping of critical services (SQL, Exchange, backup agents) commonly disabled by ransomware before encryption to maximize damage.',
  tacticId: 'TA0040', tacticName: 'Impact',
  techniqueId: 'T1489', techniqueName: 'Service Stop',
  logsource: { product: 'windows', category: 'process_creation' },
  sigmaYaml: `title: Critical Service Stop - Pre-Encryption Behavior
id: rw004-sigma-0091
status: stable
description: Detects ransomware stopping critical services
logsource:
    product: windows
    category: process_creation
detection:
    selection:
        Image|endswith:
            - '\\\\net.exe'
            - '\\\\sc.exe'
            - '\\\\taskkill.exe'
        CommandLine|contains:
            - 'stop'
            - 'delete'
            - '/f /im'
    selection_targets:
        CommandLine|contains:
            - 'MSSQL'
            - 'MySQL'
            - 'oracle'
            - 'Exchange'
            - 'veeam'
            - 'backup'
            - 'sql'
            - 'sophos'
            - 'defender'
    condition: selection and selection_targets
falsepositives:
    - Scheduled maintenance
level: high
tags:
    - attack.impact
    - attack.t1489`,
  splunkQuery: `index=wineventlog (sourcetype=WinEventLog:Security EventCode=4688 OR sourcetype=WinEventLog:Sysmon EventCode=1)
| where (match(Image,"(?i)(net\\.exe|sc\\.exe|taskkill\\.exe)")) AND (match(CommandLine,"(?i)(stop|delete|/f /im)")) AND (match(CommandLine,"(?i)(MSSQL|MySQL|oracle|Exchange|veeam|backup|sql|sophos|defender)"))
| stats count values(CommandLine) as commands dc(ComputerName) as hosts by User, _time
| where count > 2
| table _time, User, commands, hosts, count`,
  qradarQuery: `SELECT sourceip, username,
  QIDNAME(qid) as event_name,
  COUNT(*) as service_stops
FROM events
WHERE (eventname ILIKE '%net%stop%' OR eventname ILIKE '%sc%delete%' OR eventname ILIKE '%taskkill%')
  AND (eventname ILIKE '%SQL%' OR eventname ILIKE '%Exchange%'
    OR eventname ILIKE '%backup%' OR eventname ILIKE '%defender%')
GROUP BY sourceip, username, qid
HAVING COUNT(*) > 2
ORDER BY service_stops DESC
LAST 24 HOURS`,
  detectionExplanation: 'Ransomware disables services that lock files (SQL, Exchange) and security services (AV, backup) before encryption. Multiple service stops in sequence is a strong pre-encryption indicator.',
  requiredLogs: ['Sysmon Event 1', 'Windows Security 4688', 'Windows System 7036 (Service State Change)'],
  logConfig: 'Process creation with command line capture. Windows System event log forwarding.',
  falsePositives: ['Scheduled maintenance windows', 'Service restarts during patching'],
  tuning: 'Alert on 3+ critical service stops in a short window. Correlate with shadow copy deletion.',
  commonErrors: ['Service stop events alone are noisy — combine with process creation for context'],
  responseActions: ['Correlate with shadow copy deletion', 'Check for encryption process starting', 'Isolate if confirmed malicious', 'Restart affected services after investigation'],
  threatIntel: { cves: [], cisaKev: false, campaigns: ['LockBit 3.0', 'ALPHV/BlackCat Ransomware'], iocs: [] },
  references: ['https://attack.mitre.org/techniques/T1489/']
},
{
  id: 'SR-0092', title: 'Boot Configuration Tampering',
  status: 'stable', severity: 'critical', author: 'SOC Platform', date: '2024-05-10', modified: '2024-12-10',
  category: 'ransomware',
  description: 'Detects modification of boot configuration data (BCD) to disable recovery options, safe mode, or startup repair — used by destructive malware and ransomware.',
  tacticId: 'TA0040', tacticName: 'Impact',
  techniqueId: 'T1490', techniqueName: 'Inhibit System Recovery',
  logsource: { product: 'windows', category: 'process_creation' },
  sigmaYaml: `title: Boot Configuration Tampering
id: rw005-sigma-0092
status: stable
description: Detects BCD modification to prevent recovery
logsource:
    product: windows
    category: process_creation
detection:
    selection:
        Image|endswith: '\\\\bcdedit.exe'
        CommandLine|contains:
            - 'recoveryenabled no'
            - 'bootstatuspolicy ignoreallfailures'
            - 'safeboot'
            - 'deletevalue'
    condition: selection
falsepositives:
    - System hardening scripts
level: critical
tags:
    - attack.impact
    - attack.t1490`,
  splunkQuery: `index=wineventlog (sourcetype=WinEventLog:Security EventCode=4688 OR sourcetype=WinEventLog:Sysmon EventCode=1) Image="*\\\\bcdedit.exe"
| where match(CommandLine,"(?i)(recoveryenabled.*no|bootstatuspolicy.*ignoreallfailures|safeboot|deletevalue)")
| table _time, ComputerName, User, CommandLine`,
  qradarQuery: `SELECT sourceip, username,
  QIDNAME(qid) as event_name,
  COUNT(*) as bcd_events
FROM events
WHERE eventname ILIKE '%bcdedit%'
  AND (eventname ILIKE '%recovery%no%'
    OR eventname ILIKE '%ignoreallfailures%'
    OR eventname ILIKE '%safeboot%')
GROUP BY sourceip, username, qid
ORDER BY starttime DESC
LAST 24 HOURS`,
  detectionExplanation: 'bcdedit /set {default} recoveryenabled no and bootstatuspolicy ignoreallfailures are near-universal ransomware commands. They prevent Windows Recovery Environment from activating after forced reboot.',
  requiredLogs: ['Sysmon Event 1', 'Windows Security 4688'],
  logConfig: 'Process creation auditing with full command line capture.',
  falsePositives: ['System hardening scripts (rare)', 'IT automation during deployment'],
  tuning: 'Near zero false-positive rule. Any bcdedit recovery modification should trigger investigation.',
  commonErrors: ['bcdedit requires elevated privileges — detection implies prior escalation'],
  responseActions: ['Isolate immediately — ransomware deployment imminent or active', 'Check for shadow copy deletion', 'Check for mass file operations', 'Activate IR'],
  threatIntel: { cves: [], cisaKev: false, campaigns: ['LockBit 3.0'], iocs: [] },
  references: ['https://attack.mitre.org/techniques/T1490/']
},
{
  id: 'SR-0093', title: 'SMB Worm-like Ransomware Spread',
  status: 'stable', severity: 'critical', author: 'SOC Platform', date: '2024-06-15', modified: '2024-12-15',
  category: 'ransomware',
  description: 'Detects worm-like ransomware propagation via SMB by identifying a single host connecting to many systems on port 445 and writing files in rapid succession.',
  tacticId: 'TA0008', tacticName: 'Lateral Movement',
  techniqueId: 'T1021.002', techniqueName: 'SMB/Windows Admin Shares',
  logsource: { product: 'windows', service: 'security' },
  sigmaYaml: `title: SMB Worm-like Ransomware Propagation
id: rw006-sigma-0093
status: stable
description: Detects rapid SMB connections to many hosts - worm behavior
logsource:
    product: windows
    service: security
detection:
    selection:
        EventID: 5140
        ShareName|contains:
            - 'C$'
            - 'ADMIN$'
    condition: selection | count(distinct ComputerName) by IpAddress > 10
falsepositives:
    - IT management scanning
level: critical
tags:
    - attack.lateral_movement
    - attack.t1021.002`,
  splunkQuery: `index=firewall sourcetype=firewall dest_port=445
| bin _time span=10m
| stats dc(dest_ip) as unique_targets count as connections first(_time) as first_conn last(_time) as last_conn by src_ip, _time
| where unique_targets > 10
| eval rate=round(connections/10,1)
| sort - unique_targets
| table _time, src_ip, unique_targets, connections, rate, first_conn, last_conn`,
  qradarQuery: `SELECT sourceip,
  COUNT(DISTINCT destinationip) as smb_targets,
  COUNT(*) as total_connections,
  MIN(DATEFORMAT(starttime,'HH:mm:ss')) as first_seen,
  MAX(DATEFORMAT(starttime,'HH:mm:ss')) as last_seen
FROM events
WHERE destinationport = 445
GROUP BY sourceip
HAVING COUNT(DISTINCT destinationip) > 10
ORDER BY smb_targets DESC
LAST 1 HOURS`,
  detectionExplanation: 'Worm-like ransomware (WannaCry, NotPetya) spreads via SMB. A single workstation connecting to 10+ SMB targets in 10 minutes is highly suspicious. Rate of spread is key — ransomware connects faster than normal admin activity.',
  requiredLogs: ['Firewall logs for port 445', 'Windows Security 5140/5145', 'Network flow data'],
  logConfig: 'Firewall logging for internal SMB traffic. Enable share access auditing.',
  falsePositives: ['IT management tools scanning network', 'File server backup operations'],
  tuning: 'Workstations should never connect to 10+ SMB targets. Combine with admin share access (C$, ADMIN$) for high confidence.',
  commonErrors: ['Internal firewalls may not log SMB traffic', 'File server activity can mask worm spread'],
  responseActions: ['CRITICAL — Worm spreading', 'Isolate source immediately', 'Block SMB laterally via micro-segmentation', 'Check all target systems for encryption', 'Activate DR plans'],
  threatIntel: { cves: [], cisaKev: false, campaigns: ['LockBit 3.0'], iocs: [] },
  references: ['https://attack.mitre.org/techniques/T1021/002/']
},

// ═══════════════════════════════════════════════════════════════
// WEB ATTACKS (6 rules)
// ═══════════════════════════════════════════════════════════════
{
  id: 'SR-0094', title: 'SQL Injection Attack Detection',
  status: 'stable', severity: 'high', author: 'SOC Platform', date: '2024-03-15', modified: '2024-12-15',
  category: 'web-attacks',
  description: 'Detects SQL injection attempts by monitoring web server logs for common SQLi payloads including UNION SELECT, OR 1=1, time-based blind injection, and error-based techniques.',
  tacticId: 'TA0001', tacticName: 'Initial Access',
  techniqueId: 'T1190', techniqueName: 'Exploit Public-Facing Application',
  logsource: { product: 'webserver', category: 'access' },
  sigmaYaml: `title: SQL Injection Attack Detection
id: wa001-sigma-0094
status: stable
description: Detects SQL injection attempts in web requests
logsource:
    category: webserver
    product: webserver
detection:
    selection:
        uri_query|contains:
            - 'UNION SELECT'
            - 'UNION ALL SELECT'
            - "OR 1=1"
            - "' OR '"
            - '--'
            - 'WAITFOR DELAY'
            - 'BENCHMARK('
            - 'SLEEP('
            - 'LOAD_FILE('
            - 'INTO OUTFILE'
            - 'information_schema'
            - 'sys.databases'
    condition: selection
falsepositives:
    - Security scanning tools
level: high
tags:
    - attack.initial_access
    - attack.t1190`,
  splunkQuery: `index=web sourcetype=access_combined
| where match(uri_query,"(?i)(UNION\\s+(ALL\\s+)?SELECT|OR\\s+1\\s*=\\s*1|'\\s+OR\\s+'|--\\s*$|WAITFOR\\s+DELAY|BENCHMARK\\(|SLEEP\\(|LOAD_FILE\\(|INTO\\s+OUTFILE|information_schema|sys\\.databases)")
| stats count dc(uri_path) as endpoints values(uri_query) as payloads by clientip, status, _time
| sort - count
| table _time, clientip, status, count, endpoints, payloads`,
  qradarQuery: `SELECT sourceip, destinationip,
  COUNT(*) as sqli_attempts,
  COUNT(DISTINCT url) as targeted_endpoints
FROM events
WHERE (LOGSOURCETYPENAME(devicetype) ILIKE '%Apache%' OR LOGSOURCETYPENAME(devicetype) ILIKE '%IIS%')
  AND (url ILIKE '%UNION%SELECT%' OR url ILIKE '%OR 1=1%'
    OR url ILIKE '%information_schema%' OR url ILIKE '%WAITFOR%DELAY%'
    OR url ILIKE '%SLEEP(%' OR url ILIKE '%sys.databases%')
GROUP BY sourceip, destinationip
HAVING COUNT(*) > 0
ORDER BY sqli_attempts DESC
LAST 24 HOURS`,
  detectionExplanation: 'SQL injection patterns in URIs: UNION-based extraction, Boolean-based blind (OR 1=1), time-based blind (SLEEP/WAITFOR), and out-of-band (LOAD_FILE/INTO OUTFILE). Multiple SQLi payloads from same IP indicates automated scanning.',
  requiredLogs: ['Web server access logs', 'WAF logs', 'Database audit logs'],
  logConfig: 'Full URI logging in web server. Enable WAF logging for blocked requests.',
  falsePositives: ['Security scanners (Nessus, Burp)', 'Penetration testing'],
  tuning: 'Correlate with HTTP 500 responses (successful injection may cause errors). Track unique payload variations per source.',
  commonErrors: ['URL-encoded payloads may evade simple string matching', 'POST body SQLi not visible in URI logs'],
  responseActions: ['Block source IP at WAF', 'Check for successful exploitation (200 with data)', 'Review database audit logs', 'Patch vulnerable application'],
  threatIntel: { cves: [], cisaKev: false, campaigns: [], iocs: [] },
  references: ['https://attack.mitre.org/techniques/T1190/']
},
{
  id: 'SR-0095', title: 'Cross-Site Scripting (XSS) Attempt',
  status: 'stable', severity: 'medium', author: 'SOC Platform', date: '2024-04-20', modified: '2024-12-10',
  category: 'web-attacks',
  description: 'Detects XSS attack attempts by monitoring for script injection payloads in web request parameters including HTML tags, JavaScript event handlers, and encoded scripts.',
  tacticId: 'TA0001', tacticName: 'Initial Access',
  techniqueId: 'T1190', techniqueName: 'Exploit Public-Facing Application',
  logsource: { product: 'webserver', category: 'access' },
  sigmaYaml: `title: Cross-Site Scripting (XSS) Attempt
id: wa002-sigma-0095
status: stable
description: Detects XSS payload injection in web requests
logsource:
    category: webserver
    product: webserver
detection:
    selection:
        uri_query|contains:
            - '<script'
            - 'javascript:'
            - 'onerror='
            - 'onload='
            - 'onmouseover='
            - 'alert('
            - 'document.cookie'
            - 'eval('
    condition: selection
falsepositives:
    - Legitimate script content in CMS
level: medium
tags:
    - attack.initial_access
    - attack.t1190`,
  splunkQuery: `index=web sourcetype=access_combined
| where match(uri_query,"(?i)(<script|javascript:|onerror=|onload=|onmouseover=|alert\\(|document\\.cookie|eval\\()")
| stats count dc(uri_path) as endpoints_targeted by clientip, _time
| where count > 5
| table _time, clientip, count, endpoints_targeted`,
  qradarQuery: `SELECT sourceip, destinationip,
  COUNT(*) as xss_attempts
FROM events
WHERE (LOGSOURCETYPENAME(devicetype) ILIKE '%Apache%' OR LOGSOURCETYPENAME(devicetype) ILIKE '%IIS%')
  AND (url ILIKE '%<script%' OR url ILIKE '%javascript:%'
    OR url ILIKE '%onerror=%' OR url ILIKE '%document.cookie%')
GROUP BY sourceip, destinationip
HAVING COUNT(*) > 5
ORDER BY xss_attempts DESC
LAST 24 HOURS`,
  detectionExplanation: 'XSS payloads inject script code via user-controlled input. Look for <script> tags, JavaScript event handlers, and DOM manipulation. URL-encoded variants (%3Cscript) should also be detected.',
  requiredLogs: ['Web server access logs with full query strings', 'WAF logs'],
  logConfig: 'Enable full URI query string logging. Deploy WAF with XSS protection rules.',
  falsePositives: ['CMS content with legitimate script references', 'Developer testing'],
  tuning: 'Focus on reflected XSS (payloads in GET parameters). 5+ XSS attempts from same IP indicates scanning.',
  commonErrors: ['URL encoding may obfuscate payloads', 'POST body XSS not visible in URI logs'],
  responseActions: ['Block source IP', 'Verify if payload was reflected to other users', 'Implement Content Security Policy headers'],
  threatIntel: { cves: [], cisaKev: false, campaigns: [], iocs: [] },
  references: ['https://attack.mitre.org/techniques/T1190/']
},
{
  id: 'SR-0096', title: 'Directory Traversal / Path Traversal Attack',
  status: 'stable', severity: 'high', author: 'SOC Platform', date: '2024-05-15', modified: '2024-12-10',
  category: 'web-attacks',
  description: 'Detects directory traversal attacks attempting to access files outside the web root using ../ sequences, targeting sensitive files like /etc/passwd, web.config, and .htaccess.',
  tacticId: 'TA0001', tacticName: 'Initial Access',
  techniqueId: 'T1190', techniqueName: 'Exploit Public-Facing Application',
  logsource: { product: 'webserver', category: 'access' },
  sigmaYaml: `title: Directory Traversal Attack Detection
id: wa003-sigma-0096
status: stable
description: Detects path traversal attempts
logsource:
    category: webserver
    product: webserver
detection:
    selection:
        uri_path|contains:
            - '../'
            - '..\\\\' 
            - '%2e%2e'
            - '/etc/passwd'
            - '/etc/shadow'
            - 'web.config'
            - '.htaccess'
            - 'boot.ini'
    condition: selection
falsepositives:
    - Legitimate deep-link URLs
level: high
tags:
    - attack.initial_access
    - attack.t1190`,
  splunkQuery: `index=web sourcetype=access_combined
| where match(uri_path,"(?i)(\\.\\./|\\.\\.\\\\|%2e%2e|/etc/passwd|/etc/shadow|web\\.config|\\.htaccess|boot\\.ini)")
| stats count values(uri_path) as paths values(status) as response_codes by clientip, _time
| sort - count
| table _time, clientip, count, paths, response_codes`,
  qradarQuery: `SELECT sourceip, destinationip,
  COUNT(*) as traversal_attempts,
  COUNT(DISTINCT url) as unique_paths
FROM events
WHERE (LOGSOURCETYPENAME(devicetype) ILIKE '%Apache%' OR LOGSOURCETYPENAME(devicetype) ILIKE '%IIS%')
  AND (url ILIKE '%../%' OR url ILIKE '%..\\\\%'
    OR url ILIKE '%/etc/passwd%' OR url ILIKE '%web.config%')
GROUP BY sourceip, destinationip
HAVING COUNT(*) > 0
ORDER BY traversal_attempts DESC
LAST 24 HOURS`,
  detectionExplanation: 'Path traversal uses ../ sequences to escape the web root and access sensitive system files. Success depends on missing input validation. Targets include config files, password files, and application source code.',
  requiredLogs: ['Web server access logs', 'WAF logs'],
  logConfig: 'Full URI logging. WAF with path traversal protection.',
  falsePositives: ['Deep-linked URLs that legitimately contain ../ patterns (rare)'],
  tuning: 'Focus on traversal combined with sensitive file names. Check response codes — 200 means successful access.',
  commonErrors: ['Double URL encoding (%252e) may bypass detection', 'Null byte injection can truncate paths'],
  responseActions: ['Block source IP', 'Check if sensitive files were accessed (200 response)', 'Patch vulnerable web application', 'Implement input validation'],
  threatIntel: { cves: [], cisaKev: false, campaigns: [], iocs: [] },
  references: ['https://attack.mitre.org/techniques/T1190/']
},
{
  id: 'SR-0097', title: 'Web Shell Upload and Execution',
  status: 'stable', severity: 'critical', author: 'SOC Platform', date: '2024-06-10', modified: '2024-12-15',
  category: 'web-attacks',
  description: 'Detects web shell deployment and execution by monitoring for suspicious file creation in web directories and command execution from web server processes.',
  tacticId: 'TA0003', tacticName: 'Persistence',
  techniqueId: 'T1505.003', techniqueName: 'Web Shell',
  logsource: { product: 'windows', category: 'process_creation' },
  sigmaYaml: `title: Web Shell Upload and Execution
id: wa004-sigma-0097
status: stable
description: Detects web shell command execution
logsource:
    product: windows
    category: process_creation
detection:
    selection:
        ParentImage|endswith:
            - '\\\\w3wp.exe'
            - '\\\\httpd.exe'
            - '\\\\nginx.exe'
            - '\\\\tomcat.exe'
            - '\\\\apache.exe'
            - '\\\\php-cgi.exe'
        Image|endswith:
            - '\\\\cmd.exe'
            - '\\\\powershell.exe'
            - '\\\\whoami.exe'
            - '\\\\net.exe'
            - '\\\\ipconfig.exe'
            - '\\\\systeminfo.exe'
    condition: selection
falsepositives:
    - Legitimate CGI scripts
level: critical
tags:
    - attack.persistence
    - attack.t1505.003`,
  splunkQuery: `index=wineventlog sourcetype=WinEventLog:Sysmon EventCode=1
| where match(ParentImage,"(?i)(w3wp|httpd|nginx|tomcat|apache|php-cgi)\\.exe$")
  AND match(Image,"(?i)(cmd|powershell|whoami|net|ipconfig|systeminfo)\\.exe$")
| stats count values(Image) as exec_chain values(CommandLine) as commands by ComputerName, ParentImage, User, _time
| table _time, ComputerName, User, ParentImage, exec_chain, commands, count`,
  qradarQuery: `SELECT sourceip, username,
  QIDNAME(qid) as event_name,
  COUNT(*) as webshell_events
FROM events
WHERE ("Parent Process Path" ILIKE '%w3wp.exe' OR "Parent Process Path" ILIKE '%httpd.exe'
  OR "Parent Process Path" ILIKE '%nginx.exe' OR "Parent Process Path" ILIKE '%tomcat%')
  AND (Filename ILIKE '%cmd.exe' OR Filename ILIKE '%powershell.exe'
    OR Filename ILIKE '%whoami.exe' OR Filename ILIKE '%net.exe')
GROUP BY sourceip, username, qid
HAVING COUNT(*) > 0
ORDER BY webshell_events DESC
LAST 24 HOURS`,
  detectionExplanation: 'Web shells provide remote command execution through web server processes. Key indicator: web server processes (w3wp, httpd, nginx) spawning command interpreters (cmd, powershell) or system utilities (whoami, net). This should almost never happen in production.',
  requiredLogs: ['Sysmon Event 1 with parent process', 'Web server error logs', 'IIS/Apache access logs'],
  logConfig: 'Sysmon with parent-child process monitoring. Web server file monitoring.',
  falsePositives: ['Legitimate CGI/PHP scripts executing system commands', 'Health check scripts'],
  tuning: 'Web servers spawning cmd/powershell is almost always malicious. Add file creation monitoring for .asp/.aspx/.php/.jsp in web directories.',
  commonErrors: ['Without parent process tracking, detection is blind', 'Java-based web shells may use different process chains'],
  responseActions: ['CRITICAL — Active web shell', 'Identify the web shell file on disk', 'Remove the web shell', 'Patch the vulnerability exploited for upload', 'Forensic analysis of commands executed'],
  threatIntel: { cves: [], cisaKev: false, campaigns: ['Volt Typhoon'], iocs: [] },
  references: ['https://attack.mitre.org/techniques/T1505/003/']
},
{
  id: 'SR-0098', title: 'Command Injection via Web Application',
  status: 'stable', severity: 'critical', author: 'SOC Platform', date: '2024-07-20', modified: '2024-12-10',
  category: 'web-attacks',
  description: 'Detects OS command injection attempts in web requests using pipe, semicolon, backtick, and other shell metacharacters to execute arbitrary system commands.',
  tacticId: 'TA0002', tacticName: 'Execution',
  techniqueId: 'T1059', techniqueName: 'Command and Scripting Interpreter',
  logsource: { product: 'webserver', category: 'access' },
  sigmaYaml: `title: Command Injection via Web Application
id: wa005-sigma-0098
status: stable
description: Detects OS command injection in web requests
logsource:
    category: webserver
    product: webserver
detection:
    selection:
        uri_query|contains:
            - '|whoami'
            - ';id'
            - ';cat /etc'
            - '$(whoami)'
            - '|net user'
            - '|dir'
            - ';uname'
            - '&&ping'
    condition: selection
falsepositives:
    - None expected
level: critical
tags:
    - attack.execution
    - attack.t1059`,
  splunkQuery: `index=web sourcetype=access_combined
| where match(uri_query,"(?i)(\\|whoami|;\\s*id\\b|;\\s*cat\\s+/etc|\\$\\(whoami\\)|\\|net\\s+user|;\\s*uname|&&\\s*ping)")
| stats count values(uri_query) as payloads by clientip, uri_path, status, _time
| table _time, clientip, uri_path, status, payloads, count`,
  qradarQuery: `SELECT sourceip, destinationip, url,
  COUNT(*) as cmdi_attempts
FROM events
WHERE (LOGSOURCETYPENAME(devicetype) ILIKE '%Apache%' OR LOGSOURCETYPENAME(devicetype) ILIKE '%IIS%')
  AND (url ILIKE '%|whoami%' OR url ILIKE '%;id%'
    OR url ILIKE '%;cat /etc%' OR url ILIKE '%$(whoami)%'
    OR url ILIKE '%|net user%')
GROUP BY sourceip, destinationip, url
HAVING COUNT(*) > 0
ORDER BY cmdi_attempts DESC
LAST 24 HOURS`,
  detectionExplanation: 'Command injection exploits insufficient input validation to execute OS commands. Shell metacharacters (|, ;, &&, $()) are used to chain commands. Targets: /etc/passwd on Linux, net user on Windows.',
  requiredLogs: ['Web server access logs', 'WAF logs', 'Application error logs'],
  logConfig: 'Full URI query logging. WAF with command injection detection rules.',
  falsePositives: ['Extremely rare in legitimate traffic'],
  tuning: 'This is a high-fidelity rule. Any command injection pattern should be investigated immediately.',
  commonErrors: ['URL-encoded metacharacters may bypass string matching', 'POST body injection not visible in URIs'],
  responseActions: ['Block source IP immediately', 'Check if command execution succeeded', 'Patch vulnerable application', 'Review application logs for data access'],
  threatIntel: { cves: ['CVE-2024-3400'], cisaKev: true, campaigns: ['Volt Typhoon'], iocs: [] },
  references: ['https://attack.mitre.org/techniques/T1059/']
},
{
  id: 'SR-0099', title: 'Web Application Vulnerability Scanning',
  status: 'test', severity: 'medium', author: 'SOC Platform', date: '2024-08-10', modified: '2024-12-10',
  category: 'web-attacks',
  description: 'Detects automated vulnerability scanning against web applications by identifying scanner user-agents, rapid request patterns, and common scanner fingerprints.',
  tacticId: 'TA0043', tacticName: 'Reconnaissance',
  techniqueId: 'T1595.002', techniqueName: 'Vulnerability Scanning',
  logsource: { product: 'webserver', category: 'access' },
  sigmaYaml: `title: Web Vulnerability Scanner Detection
id: wa006-sigma-0099
status: test
description: Detects automated web vulnerability scanning
logsource:
    category: webserver
    product: webserver
detection:
    selection_ua:
        useragent|contains:
            - 'sqlmap'
            - 'nikto'
            - 'nessus'
            - 'openvas'
            - 'burp'
            - 'dirbuster'
            - 'gobuster'
            - 'wfuzz'
    selection_pattern:
        uri_path|contains:
            - '/.git/'
            - '/.env'
            - '/wp-admin'
            - '/phpmyadmin'
            - '/.htpasswd'
            - '/admin'
            - '/backup'
    condition: selection_ua or selection_pattern
falsepositives:
    - Authorized security scanning
level: medium
tags:
    - attack.reconnaissance
    - attack.t1595.002`,
  splunkQuery: `index=web sourcetype=access_combined
| where match(useragent,"(?i)(sqlmap|nikto|nessus|openvas|burp|dirbuster|gobuster|wfuzz)")
  OR match(uri_path,"(?i)(/\\.git/|/\\.env|/wp-admin|/phpmyadmin|/\\.htpasswd)")
| bin _time span=10m
| stats count dc(uri_path) as unique_paths by clientip, useragent, _time
| where count > 50
| table _time, clientip, useragent, count, unique_paths`,
  qradarQuery: `SELECT sourceip,
  COUNT(*) as scan_requests,
  COUNT(DISTINCT url) as unique_urls
FROM events
WHERE (LOGSOURCETYPENAME(devicetype) ILIKE '%Apache%' OR LOGSOURCETYPENAME(devicetype) ILIKE '%IIS%')
  AND (url ILIKE '%/.git/%' OR url ILIKE '%/.env%'
    OR url ILIKE '%/wp-admin%' OR url ILIKE '%/phpmyadmin%')
GROUP BY sourceip
HAVING COUNT(*) > 50
ORDER BY scan_requests DESC
LAST 4 HOURS`,
  detectionExplanation: 'Vulnerability scanners generate high-volume, diverse URI requests targeting known vulnerable paths. Scanner user-agents (sqlmap, nikto) are obvious but easily spoofed. High unique_paths count is a better indicator.',
  requiredLogs: ['Web server access logs', 'WAF logs'],
  logConfig: 'Full access logging including user-agent.',
  falsePositives: ['Authorized security scanning (should be scheduled and from known IPs)'],
  tuning: 'Maintain allowlist of scanner IPs. 50+ unique paths/10min from a single IP indicates automated scanning.',
  commonErrors: ['Scanners can spoof user-agents', 'Rate limiting may make scans invisible at SIEM level'],
  responseActions: ['Verify if scanning is authorized', 'Block unauthorized scanner IPs at WAF', 'Review scan results for actual vulnerabilities'],
  threatIntel: { cves: [], cisaKev: false, campaigns: [], iocs: [] },
  references: ['https://attack.mitre.org/techniques/T1595/002/']
},

// ═══════════════════════════════════════════════════════════════
// RECONNAISSANCE (6 rules)
// ═══════════════════════════════════════════════════════════════
{
  id: 'SR-0100', title: 'Network Port Scanning Detection',
  status: 'stable', severity: 'medium', author: 'SOC Platform', date: '2024-02-20', modified: '2024-12-15',
  category: 'reconnaissance',
  description: 'Detects network port scanning by identifying a single source IP connecting to an abnormally high number of destination ports on one or more targets.',
  tacticId: 'TA0043', tacticName: 'Reconnaissance',
  techniqueId: 'T1046', techniqueName: 'Network Service Discovery',
  logsource: { product: 'firewall' },
  sigmaYaml: `title: Network Port Scan Detection
id: rc001-sigma-0100
status: stable
description: Detects port scanning from a single source
logsource:
    product: firewall
detection:
    selection:
        action: denied
    condition: selection | count(distinct dest_port) by src_ip > 50
falsepositives:
    - Vulnerability scanners
level: medium
tags:
    - attack.reconnaissance
    - attack.t1046`,
  splunkQuery: `index=firewall sourcetype=firewall action=denied
| bin _time span=15m
| stats dc(dest_port) as unique_ports dc(dest_ip) as unique_targets count as total by src_ip, _time
| where unique_ports > 50
| eval scan_type=if(unique_targets>5,"horizontal","vertical")
| sort - unique_ports
| table _time, src_ip, unique_ports, unique_targets, scan_type, total`,
  qradarQuery: `SELECT sourceip,
  COUNT(DISTINCT destinationport) as unique_ports,
  COUNT(DISTINCT destinationip) as unique_targets,
  COUNT(*) as total_connections
FROM events
WHERE CATEGORYNAME(highlevelcategory) = 'Firewall'
  AND CATEGORYNAME(category) ILIKE '%Deny%'
GROUP BY sourceip
HAVING COUNT(DISTINCT destinationport) > 50
ORDER BY unique_ports DESC
LAST 1 HOURS`,
  detectionExplanation: 'Port scanning generates many connection attempts to different ports. Vertical scan = many ports on one host. Horizontal scan = same port across many hosts. Denied connections are the best indicator — successful connections may be legitimate.',
  requiredLogs: ['Firewall deny logs', 'IDS alerts', 'Network flow data'],
  logConfig: 'Enable firewall deny logging. Forward IDS alerts to SIEM.',
  falsePositives: ['Authorized vulnerability scanning', 'Network monitoring tools'],
  tuning: '50+ unique ports/15min from a single IP is suspicious. Baseline known scanner IPs. Track vertical vs horizontal patterns.',
  commonErrors: ['Stateful firewalls may not log all denied attempts', 'Internal scanning may be invisible without micro-segmentation'],
  responseActions: ['Verify if scanning is authorized', 'Block source IP if external', 'Check for subsequent exploitation attempts', 'Alert network security team'],
  threatIntel: { cves: [], cisaKev: false, campaigns: [], iocs: [] },
  references: ['https://attack.mitre.org/techniques/T1046/']
},
{
  id: 'SR-0101', title: 'Internal Network Reconnaissance Commands',
  status: 'stable', severity: 'medium', author: 'SOC Platform', date: '2024-03-10', modified: '2024-12-10',
  category: 'reconnaissance',
  description: 'Detects execution of multiple network discovery commands in a short period — a common post-compromise reconnaissance pattern.',
  tacticId: 'TA0007', tacticName: 'Discovery',
  techniqueId: 'T1016', techniqueName: 'System Network Configuration Discovery',
  logsource: { product: 'windows', category: 'process_creation' },
  sigmaYaml: `title: Internal Network Reconnaissance Commands
id: rc002-sigma-0101
status: stable
description: Detects rapid execution of recon commands
logsource:
    product: windows
    category: process_creation
detection:
    selection:
        Image|endswith:
            - '\\\\ipconfig.exe'
            - '\\\\nslookup.exe'
            - '\\\\arp.exe'
            - '\\\\route.exe'
            - '\\\\netstat.exe'
            - '\\\\tracert.exe'
            - '\\\\nbtstat.exe'
            - '\\\\net.exe'
    condition: selection | count() by ComputerName > 4
falsepositives:
    - Network troubleshooting
level: medium
tags:
    - attack.discovery
    - attack.t1016`,
  splunkQuery: `index=wineventlog (sourcetype=WinEventLog:Security EventCode=4688 OR sourcetype=WinEventLog:Sysmon EventCode=1)
| where match(Image,"(?i)(ipconfig|nslookup|arp|route|netstat|tracert|nbtstat|net)\\.exe$")
| bin _time span=10m
| stats dc(Image) as unique_tools count as total values(Image) as tools by ComputerName, User, _time
| where unique_tools >= 4
| table _time, ComputerName, User, unique_tools, tools, total`,
  qradarQuery: `SELECT sourceip, username,
  COUNT(DISTINCT Filename) as unique_tools,
  COUNT(*) as total_commands
FROM events
WHERE CATEGORYNAME(category) ILIKE '%Process%Create%'
  AND (Filename ILIKE '%ipconfig%' OR Filename ILIKE '%nslookup%'
    OR Filename ILIKE '%netstat%' OR Filename ILIKE '%arp%'
    OR Filename ILIKE '%net.exe%')
GROUP BY sourceip, username
HAVING COUNT(DISTINCT Filename) >= 4
ORDER BY unique_tools DESC
LAST 2 HOURS`,
  detectionExplanation: '4+ unique network discovery tools executed within 10 minutes suggests systematic reconnaissance. Normal users rarely run multiple network tools. Attackers enumerate network configuration, connections, and routes after gaining access.',
  requiredLogs: ['Sysmon Event 1 or Windows Security 4688'],
  logConfig: 'Process creation auditing with command line capture.',
  falsePositives: ['IT staff troubleshooting network issues', 'Automated network diagnostics'],
  tuning: '4+ unique recon tools in 10 minutes. Focus on non-admin users. Correlate with prior access events for context.',
  commonErrors: ['Individual tool execution is common — only alert on pattern of multiple tools'],
  responseActions: ['Determine if the user normally performs network diagnostics', 'Check for prior compromise indicators on this host', 'Monitor for subsequent lateral movement'],
  threatIntel: { cves: [], cisaKev: false, campaigns: [], iocs: [] },
  references: ['https://attack.mitre.org/techniques/T1016/']
},
{
  id: 'SR-0102', title: 'LDAP Enumeration and Bloodhound Activity',
  status: 'stable', severity: 'high', author: 'SOC Platform', date: '2024-04-15', modified: '2024-12-15',
  category: 'reconnaissance',
  description: 'Detects Active Directory enumeration via LDAP queries, particularly patterns associated with BloodHound/SharpHound collection which maps attack paths.',
  tacticId: 'TA0007', tacticName: 'Discovery',
  techniqueId: 'T1087.002', techniqueName: 'Domain Account Discovery',
  logsource: { product: 'windows', service: 'security' },
  sigmaYaml: `title: LDAP Enumeration and BloodHound Detection
id: rc003-sigma-0102
status: stable
description: Detects AD enumeration via LDAP - BloodHound patterns
logsource:
    product: windows
    service: security
detection:
    selection_tools:
        CommandLine|contains:
            - 'SharpHound'
            - 'bloodhound'
            - 'Invoke-BloodHound'
            - 'azurehound'
            - 'Get-DomainUser'
            - 'Get-DomainGroup'
            - 'Get-DomainComputer'
    selection_ldap:
        EventID: 1644
    condition: selection_tools or selection_ldap
falsepositives:
    - Authorized security assessments
level: high
tags:
    - attack.discovery
    - attack.t1087.002`,
  splunkQuery: `index=wineventlog (sourcetype=WinEventLog:Sysmon EventCode=1)
| where match(CommandLine,"(?i)(SharpHound|bloodhound|Invoke-BloodHound|azurehound|Get-DomainUser|Get-DomainGroup|Get-DomainComputer)")
| stats count values(CommandLine) as commands by ComputerName, User, _time
| table _time, ComputerName, User, commands, count`,
  qradarQuery: `SELECT sourceip, username,
  QIDNAME(qid) as event_name,
  COUNT(*) as enum_events
FROM events
WHERE (eventname ILIKE '%SharpHound%' OR eventname ILIKE '%bloodhound%'
  OR eventname ILIKE '%Get-DomainUser%' OR eventname ILIKE '%Get-DomainGroup%')
GROUP BY sourceip, username, qid
HAVING COUNT(*) > 0
ORDER BY enum_events DESC
LAST 24 HOURS`,
  detectionExplanation: 'BloodHound/SharpHound performs bulk LDAP queries to map AD objects, trusts, and permissions. It queries all users, groups, computers, sessions, and ACLs. The volume and pattern of LDAP queries is distinctive.',
  requiredLogs: ['Sysmon Event 1', 'LDAP diagnostic logging (Event 1644)', 'DC Directory Services logs'],
  logConfig: 'Enable LDAP diagnostic logging on DCs (HKLM\\SYSTEM\\CurrentControlSet\\Services\\NTDS\\Diagnostics). Process creation auditing.',
  falsePositives: ['Authorized red team operations', 'AD management tools performing bulk queries'],
  tuning: 'BloodHound tool names are high-fidelity. LDAP query volume from a single source >1000 queries/minute indicates enumeration.',
  commonErrors: ['BloodHound can be compiled with custom names', 'LDAP diagnostic logging creates high volume on DCs'],
  responseActions: ['Identify the source account and system', 'If unauthorized: disable account, isolate system', 'Assume attacker has mapped full AD structure', 'Review AD for weak permissions BloodHound would identify'],
  threatIntel: { cves: [], cisaKev: false, campaigns: ['Scattered Spider'], iocs: [] },
  references: ['https://attack.mitre.org/techniques/T1087/002/']
},
{
  id: 'SR-0103', title: 'DNS Reconnaissance — Zone Transfer Attempt',
  status: 'stable', severity: 'high', author: 'SOC Platform', date: '2024-05-20', modified: '2024-12-10',
  category: 'reconnaissance',
  description: 'Detects DNS zone transfer (AXFR) attempts which can reveal entire DNS zone data including all hostnames, IPs, and internal infrastructure mapping.',
  tacticId: 'TA0043', tacticName: 'Reconnaissance',
  techniqueId: 'T1590.002', techniqueName: 'DNS',
  logsource: { product: 'dns' },
  sigmaYaml: `title: DNS Zone Transfer Attempt
id: rc004-sigma-0103
status: stable
description: Detects AXFR zone transfer attempts
logsource:
    product: dns
detection:
    selection:
        query_type:
            - 'AXFR'
            - 'IXFR'
    condition: selection
falsepositives:
    - Legitimate secondary DNS servers
level: high
tags:
    - attack.reconnaissance
    - attack.t1590.002`,
  splunkQuery: `index=dns sourcetype=dns
| where query_type="AXFR" OR query_type="IXFR"
| stats count values(query) as domains by src_ip, dest_ip, _time
| where NOT src_ip IN ("10.0.1.2", "10.0.1.3")
| table _time, src_ip, dest_ip, domains, count`,
  qradarQuery: `SELECT sourceip, destinationip,
  COUNT(*) as zone_transfer_attempts
FROM events
WHERE CATEGORYNAME(category) ILIKE '%DNS%'
  AND (eventname ILIKE '%AXFR%' OR eventname ILIKE '%zone transfer%')
GROUP BY sourceip, destinationip
HAVING COUNT(*) > 0
ORDER BY zone_transfer_attempts DESC
LAST 24 HOURS`,
  detectionExplanation: 'DNS zone transfers (AXFR) copy the entire DNS zone database. Only authorized secondary DNS servers should perform zone transfers. Any other source indicates reconnaissance.',
  requiredLogs: ['DNS server query logs', 'Network flow data on port 53/TCP'],
  logConfig: 'Enable DNS server diagnostic logging. DNS zone transfers use TCP, not UDP.',
  falsePositives: ['Legitimate secondary DNS servers performing zone transfers'],
  tuning: 'Allowlist authorized DNS secondary servers. Any other AXFR source is suspicious.',
  commonErrors: ['DNS zone transfer logging requires specific DNS server configuration', 'AXFR over TCP may be confused with large DNS responses'],
  responseActions: ['Block AXFR from unauthorized sources', 'Restrict zone transfers to specific IPs', 'Review what zones were transferred', 'Assess exposure of internal infrastructure data'],
  threatIntel: { cves: [], cisaKev: false, campaigns: [], iocs: [] },
  references: ['https://attack.mitre.org/techniques/T1590/002/']
},
{
  id: 'SR-0104', title: 'SNMP Community String Scanning',
  status: 'test', severity: 'medium', author: 'SOC Platform', date: '2024-06-15', modified: '2024-12-10',
  category: 'reconnaissance',
  description: 'Detects SNMP scanning and community string brute force targeting network infrastructure, attempting to extract device configurations and network topology.',
  tacticId: 'TA0043', tacticName: 'Reconnaissance',
  techniqueId: 'T1046', techniqueName: 'Network Service Discovery',
  logsource: { product: 'firewall' },
  sigmaYaml: `title: SNMP Community String Scanning
id: rc005-sigma-0104
status: test
description: Detects SNMP scanning of network devices
logsource:
    product: firewall
detection:
    selection:
        dest_port:
            - 161
            - 162
    condition: selection | count(distinct dest_ip) by src_ip > 10
falsepositives:
    - Network monitoring systems
level: medium
tags:
    - attack.reconnaissance
    - attack.t1046`,
  splunkQuery: `index=firewall sourcetype=firewall (dest_port=161 OR dest_port=162)
| bin _time span=15m
| stats dc(dest_ip) as targets count as total by src_ip, _time
| where targets > 10
| table _time, src_ip, targets, total`,
  qradarQuery: `SELECT sourceip,
  COUNT(DISTINCT destinationip) as snmp_targets,
  COUNT(*) as total_packets
FROM events
WHERE destinationport IN (161, 162)
GROUP BY sourceip
HAVING COUNT(DISTINCT destinationip) > 10
ORDER BY snmp_targets DESC
LAST 2 HOURS`,
  detectionExplanation: 'SNMP scanning targets infrastructure devices (routers, switches, firewalls) on port 161/162. Default community strings (public, private) are often left unchanged, allowing full read/write access to device configurations.',
  requiredLogs: ['Firewall logs', 'IDS on SNMP ports', 'Network device SNMP logs'],
  logConfig: 'Firewall logging for SNMP ports. IDS signature for SNMP community string attempts.',
  falsePositives: ['Network monitoring systems (Nagios, PRTG, SolarWinds)', 'SNMP-based discovery tools'],
  tuning: 'Allowlist known NMS IPs. 10+ SNMP targets from non-NMS IP is suspicious. Monitor for SNMPv1/v2c with default strings.',
  commonErrors: ['SNMP is UDP — stateless firewalls may not log all packets', 'SNMPv3 uses authentication, making scanning less visible'],
  responseActions: ['Verify source is not a legitimate NMS', 'Block unauthorized SNMP access', 'Audit SNMP community strings on all devices', 'Migrate to SNMPv3'],
  threatIntel: { cves: [], cisaKev: false, campaigns: [], iocs: [] },
  references: ['https://attack.mitre.org/techniques/T1046/']
},
{
  id: 'SR-0105', title: 'External Service Enumeration via Shodan/Censys',
  status: 'test', severity: 'low', author: 'SOC Platform', date: '2024-07-20', modified: '2024-12-10',
  category: 'reconnaissance',
  description: 'Detects inbound connections from known internet scanning services (Shodan, Censys, ZoomEye) which may indicate an attacker performing passive reconnaissance.',
  tacticId: 'TA0043', tacticName: 'Reconnaissance',
  techniqueId: 'T1596', techniqueName: 'Search Open Technical Databases',
  logsource: { product: 'firewall' },
  sigmaYaml: `title: External Scanning Service Connections
id: rc006-sigma-0105
status: test
description: Detects connections from known scanning services
logsource:
    product: firewall
detection:
    selection:
        src_ip|cidr:
            - '71.6.146.0/24'
            - '71.6.167.0/24'
            - '198.20.69.0/24'
            - '162.142.125.0/24'
    condition: selection
falsepositives:
    - General internet scanning (baseline activity)
level: low
tags:
    - attack.reconnaissance
    - attack.t1596`,
  splunkQuery: `index=firewall sourcetype=firewall
| where cidrmatch("71.6.146.0/24",src_ip) OR cidrmatch("71.6.167.0/24",src_ip) OR cidrmatch("198.20.69.0/24",src_ip) OR cidrmatch("162.142.125.0/24",src_ip)
| stats count dc(dest_port) as ports_scanned values(dest_port) as ports by src_ip, dest_ip, _time
| table _time, src_ip, dest_ip, ports_scanned, ports, count`,
  qradarQuery: `SELECT sourceip, destinationip, destinationport,
  COUNT(*) as scan_events
FROM events
WHERE INCIDR(sourceip,'71.6.146.0/24')
  OR INCIDR(sourceip,'71.6.167.0/24')
  OR INCIDR(sourceip,'198.20.69.0/24')
  OR INCIDR(sourceip,'162.142.125.0/24')
GROUP BY sourceip, destinationip, destinationport
ORDER BY scan_events DESC
LAST 24 HOURS`,
  detectionExplanation: 'Shodan (71.6.146.0/24, 71.6.167.0/24), Censys (162.142.125.0/24), and similar services continuously scan the internet. Detecting their connections reveals which of your services are exposed.',
  requiredLogs: ['Perimeter firewall logs', 'IDS/IPS logs'],
  logConfig: 'Perimeter firewall logging for inbound connections.',
  falsePositives: ['These services scan all internet-connected devices continuously — baseline activity is normal'],
  tuning: 'Use this for visibility into external exposure rather than active threat detection. Correlate with vulnerability scans.',
  commonErrors: ['Scanner IP ranges change over time — maintain updated reference sets'],
  responseActions: ['Review which services/ports are exposed', 'Validate that exposed services are intentional', 'Reduce external attack surface by closing unnecessary ports'],
  threatIntel: { cves: [], cisaKev: false, campaigns: [], iocs: [] },
  references: ['https://attack.mitre.org/techniques/T1596/']
}
];
