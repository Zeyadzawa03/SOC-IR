// Sigma Rules Database - Part 6: Insider Threat, Cloud Threats, Active Directory, Email Threats
// 24 new rules across 4 new categories
const SIGMA_RULES_PART6 = [

// ═══════════════════════════════════════════════════════════════
// INSIDER THREAT (6 rules)
// ═══════════════════════════════════════════════════════════════
{
  id: 'SR-0106', title: 'Mass File Download from SharePoint/OneDrive',
  status: 'stable', severity: 'high', author: 'SOC Platform', date: '2024-04-10', modified: '2024-12-15',
  category: 'insider-threat',
  description: 'Detects bulk file downloads from cloud storage that may indicate data collection by a departing or malicious insider.',
  tacticId: 'TA0009', tacticName: 'Collection', techniqueId: 'T1530', techniqueName: 'Data from Cloud Storage',
  logsource: { product: 'cloud', service: 'azure' },
  sigmaYaml: `title: Mass File Download from Cloud Storage
id: it001-sigma-0106
status: stable
description: Detects bulk downloads from SharePoint/OneDrive
logsource:
    product: cloud
    service: azure
detection:
    selection:
        Operation:
            - 'FileDownloaded'
            - 'FileSyncDownloadedFull'
    condition: selection | count() by UserId > 100
level: high
tags:
    - attack.collection
    - attack.t1530`,
  splunkQuery: `index=o365 sourcetype=ms:o365:management Workload=SharePoint (Operation=FileDownloaded OR Operation=FileSyncDownloadedFull)
| bin _time span=1h
| stats count as downloads dc(SourceFileName) as unique_files values(SourceFileName) as files by UserId, ClientIP, _time
| where downloads > 100
| sort - downloads
| table _time, UserId, ClientIP, downloads, unique_files`,
  qradarQuery: `SELECT username, sourceip,
  COUNT(*) as download_count,
  COUNT(DISTINCT "File Path") as unique_files
FROM events
WHERE LOGSOURCETYPENAME(devicetype) ILIKE '%Office 365%'
  AND eventname ILIKE '%FileDownloaded%'
GROUP BY username, sourceip
HAVING COUNT(*) > 100
ORDER BY download_count DESC
LAST 24 HOURS`,
  detectionExplanation: 'Bulk file downloads (100+ files/hour) from SharePoint/OneDrive suggest data hoarding. Common pre-resignation behavior. Track baseline per-user download patterns and alert on significant deviations.',
  requiredLogs: ['Microsoft 365 Unified Audit Log', 'SharePoint audit logs'],
  logConfig: 'Enable Microsoft 365 unified audit logging. Forward to SIEM via Management Activity API.',
  falsePositives: ['Legitimate bulk data migration', 'New employee downloading team files', 'OneDrive sync initial setup'],
  tuning: 'Baseline per-user downloads. Alert on 3x+ deviation. Focus on users with upcoming departure dates. Correlate with HR data.',
  commonErrors: ['OneDrive sync generates many download events that may appear as bulk activity'],
  responseActions: ['Verify with HR if the user is departing', 'Review what files were downloaded', 'Check if downloads include sensitive/classified data', 'Consider DLP enforcement'],
  threatIntel: { cves: [], cisaKev: false, campaigns: [], iocs: [] },
  references: ['https://attack.mitre.org/techniques/T1530/']
},
{
  id: 'SR-0107', title: 'USB Mass Storage Device Connected',
  status: 'stable', severity: 'medium', author: 'SOC Platform', date: '2024-05-15', modified: '2024-12-10',
  category: 'insider-threat',
  description: 'Detects USB mass storage device connection events which may indicate data exfiltration to removable media, especially in environments with USB restrictions.',
  tacticId: 'TA0010', tacticName: 'Exfiltration', techniqueId: 'T1052.001', techniqueName: 'Exfiltration Over USB',
  logsource: { product: 'windows', service: 'security' },
  sigmaYaml: `title: USB Mass Storage Device Connection
id: it002-sigma-0107
status: stable
description: Detects USB storage device connections
logsource:
    product: windows
    service: security
detection:
    selection_pnp:
        EventID: 6416
        ClassName: 'DiskDrive'
    selection_sysmon:
        EventID: 6416
    condition: selection_pnp or selection_sysmon
level: medium
tags:
    - attack.exfiltration
    - attack.t1052.001`,
  splunkQuery: `index=wineventlog sourcetype=WinEventLog:Security EventCode=6416 ClassName="DiskDrive"
| stats count values(DeviceDescription) as devices by ComputerName, SubjectUserName, _time
| table _time, ComputerName, SubjectUserName, devices, count

| append [search index=wineventlog sourcetype=WinEventLog:Sysmon EventCode=1 Image="*\\\\MountVol.exe"
| table _time, ComputerName, User, CommandLine]`,
  qradarQuery: `SELECT sourceip, username,
  QIDNAME(qid) as event_name,
  COUNT(*) as usb_events
FROM events
WHERE QIDNAME(qid) ILIKE '%Plug and Play%'
  AND eventname ILIKE '%DiskDrive%'
GROUP BY sourceip, username, qid
ORDER BY starttime DESC
LAST 24 HOURS`,
  detectionExplanation: 'Windows Event 6416 (PnP Device Connected) with ClassName=DiskDrive detects USB mass storage. In environments prohibiting USB storage, any connection is a policy violation and potential data exfiltration.',
  requiredLogs: ['Windows Security 6416 (PnP audit)', 'Sysmon Event 1', 'Device audit logs'],
  logConfig: 'Enable Plug and Play audit events via Advanced Audit Policy > Detailed Tracking.',
  falsePositives: ['Authorized USB devices for IT operations', 'USB hardware tokens (focus on DiskDrive class)'],
  tuning: 'Maintain allowlist of approved USB devices by serial number. Alert on unknown devices in sensitive areas.',
  commonErrors: ['Event 6416 may include non-storage USB devices — filter by ClassName'],
  responseActions: ['Verify if USB is authorized for this user/system', 'Check for subsequent file copy events', 'Review USB policy compliance', 'If unauthorized: confiscate device, investigate data exposure'],
  threatIntel: { cves: [], cisaKev: false, campaigns: [], iocs: [] },
  references: ['https://attack.mitre.org/techniques/T1052/001/']
},
{
  id: 'SR-0108', title: 'After-Hours Access to Sensitive Systems',
  status: 'test', severity: 'medium', author: 'SOC Platform', date: '2024-06-20', modified: '2024-12-10',
  category: 'insider-threat',
  description: 'Detects access to sensitive systems outside normal business hours which may indicate unauthorized activity or insider threat behavior.',
  tacticId: 'TA0001', tacticName: 'Initial Access', techniqueId: 'T1078', techniqueName: 'Valid Accounts',
  logsource: { product: 'windows', service: 'security' },
  sigmaYaml: `title: After-Hours Sensitive System Access
id: it003-sigma-0108
status: test
description: Detects access outside business hours
logsource:
    product: windows
    service: security
detection:
    selection:
        EventID: 4624
        LogonType:
            - 2
            - 10
    timeframe:
        hour_of_day: '>20 OR <6'
    condition: selection
level: medium
tags:
    - attack.initial_access
    - attack.t1078`,
  splunkQuery: `index=wineventlog sourcetype=WinEventLog:Security EventCode=4624 (LogonType=2 OR LogonType=10)
| eval hour=strftime(_time,"%H")
| where (hour > 20 OR hour < 6) AND NOT (TargetUserName="SYSTEM" OR TargetUserName="-")
| stats count dc(ComputerName) as systems values(ComputerName) as targets by TargetUserName, IpAddress, _time
| table _time, TargetUserName, IpAddress, systems, targets, count`,
  qradarQuery: `SELECT username, sourceip, destinationip,
  COUNT(*) as after_hours_logins
FROM events
WHERE QIDNAME(qid) ILIKE '%Logon Success%'
  AND (EXTRACT(HOUR FROM starttime) > 20 OR EXTRACT(HOUR FROM starttime) < 6)
  AND username NOT IN ('SYSTEM', '-')
GROUP BY username, sourceip, destinationip
HAVING COUNT(*) > 0
ORDER BY after_hours_logins DESC
LAST 24 HOURS`,
  detectionExplanation: 'Interactive (Type 2) and RDP (Type 10) logons outside 6AM-8PM business hours are unusual. Track normal patterns per user to detect deviations. Insider threats often operate after hours.',
  requiredLogs: ['Windows Security 4624', 'VPN logs', 'Badge access logs'],
  logConfig: 'Logon event auditing. Correlate with physical access systems.',
  falsePositives: ['Authorized on-call staff', 'Scheduled maintenance windows', 'Different time zone users'],
  tuning: 'Define business hours per user group. Focus on access to sensitive systems (DCs, file servers, databases).',
  commonErrors: ['Time zone differences can cause false positives', 'Automated system accounts may logon at any time'],
  responseActions: ['Verify business justification for after-hours access', 'Correlate with badge/physical access data', 'Review what the user accessed during the session', 'Report to management if unjustified'],
  threatIntel: { cves: [], cisaKev: false, campaigns: [], iocs: [] },
  references: ['https://attack.mitre.org/techniques/T1078/']
},
{
  id: 'SR-0109', title: 'Email Forwarding Rule to External Address',
  status: 'stable', severity: 'high', author: 'SOC Platform', date: '2024-07-10', modified: '2024-12-15',
  category: 'insider-threat',
  description: 'Detects creation of email forwarding rules to external addresses, commonly used for long-term data exfiltration by insiders or compromised accounts.',
  tacticId: 'TA0009', tacticName: 'Collection', techniqueId: 'T1114.003', techniqueName: 'Email Forwarding Rule',
  logsource: { product: 'cloud', service: 'azure' },
  sigmaYaml: `title: Email Forwarding Rule to External Address
id: it004-sigma-0109
status: stable
description: Detects external email forwarding rule creation
logsource:
    product: cloud
    service: azure
detection:
    selection:
        Operation:
            - 'New-InboxRule'
            - 'Set-InboxRule'
            - 'Set-Mailbox'
        Parameters|contains:
            - 'ForwardTo'
            - 'ForwardingSmtpAddress'
            - 'RedirectTo'
    condition: selection
level: high
tags:
    - attack.collection
    - attack.t1114.003`,
  splunkQuery: `index=o365 sourcetype=ms:o365:management Workload=Exchange
  (Operation="New-InboxRule" OR Operation="Set-InboxRule" OR Operation="Set-Mailbox")
| where match(Parameters,"(?i)(ForwardTo|ForwardingSmtpAddress|RedirectTo)")
| rex field=Parameters "ForwardTo\":\"(?<forward_to>[^\"]+)"
| where NOT match(forward_to,"@yourdomain\\.com$")
| table _time, UserId, Operation, forward_to, ClientIP`,
  qradarQuery: `SELECT username, sourceip,
  QIDNAME(qid) as event_name,
  COUNT(*) as rule_events
FROM events
WHERE LOGSOURCETYPENAME(devicetype) ILIKE '%Office 365%'
  AND (eventname ILIKE '%New-InboxRule%' OR eventname ILIKE '%Set-InboxRule%')
  AND (eventname ILIKE '%Forward%' OR eventname ILIKE '%Redirect%')
GROUP BY username, sourceip, qid
ORDER BY starttime DESC
LAST 24 HOURS`,
  detectionExplanation: 'Email forwarding rules silently copy all incoming email to an external address. Both insiders and attackers with compromised credentials use this for persistent data exfiltration without triggering DLP on outbound email.',
  requiredLogs: ['Microsoft 365 Exchange audit logs', 'Exchange admin audit log'],
  logConfig: 'Enable Exchange mailbox auditing. Enable unified audit logging in Microsoft 365.',
  falsePositives: ['Authorized auto-forwarding for business purposes', 'Shared mailbox forwarding'],
  tuning: 'Alert on any forwarding to external (non-corporate) domains. Maintain allowlist of approved external forwards.',
  commonErrors: ['Transport rules may also forward email — monitor at both user and admin level'],
  responseActions: ['Remove the forwarding rule immediately', 'Check for additional inbox rules (delete, move)', 'Review forwarded email content', 'If account compromised: reset credentials, revoke sessions'],
  threatIntel: { cves: [], cisaKev: false, campaigns: ['Midnight Blizzard'], iocs: [] },
  references: ['https://attack.mitre.org/techniques/T1114/003/']
},
{
  id: 'SR-0110', title: 'Excessive File Deletion — Data Destruction',
  status: 'stable', severity: 'high', author: 'SOC Platform', date: '2024-08-05', modified: '2024-12-10',
  category: 'insider-threat',
  description: 'Detects mass file deletion events that may indicate sabotage by a disgruntled insider or ransomware cleanup behavior.',
  tacticId: 'TA0040', tacticName: 'Impact', techniqueId: 'T1485', techniqueName: 'Data Destruction',
  logsource: { product: 'windows', service: 'security' },
  sigmaYaml: `title: Excessive File Deletion - Data Destruction
id: it005-sigma-0110
status: stable
description: Detects mass file deletion patterns
logsource:
    product: windows
    service: security
detection:
    selection:
        EventID: 4663
        AccessMask: '0x10000'
    condition: selection | count() by SubjectUserName > 200
level: high
tags:
    - attack.impact
    - attack.t1485`,
  splunkQuery: `index=wineventlog sourcetype=WinEventLog:Security EventCode=4663 AccessMask=0x10000
| bin _time span=30m
| stats count as deletions dc(ObjectName) as unique_files by SubjectUserName, ComputerName, _time
| where deletions > 200
| table _time, SubjectUserName, ComputerName, deletions, unique_files`,
  qradarQuery: `SELECT username, sourceip,
  COUNT(*) as file_deletions
FROM events
WHERE QIDNAME(qid) ILIKE '%File Delete%'
  OR (EventID = 4663 AND "Access Mask" = '0x10000')
GROUP BY username, sourceip
HAVING COUNT(*) > 200
ORDER BY file_deletions DESC
LAST 4 HOURS`,
  detectionExplanation: 'Event 4663 with AccessMask 0x10000 (DELETE) indicates file deletion. 200+ deletions in 30 minutes from a single user is unusual — either insider sabotage, ransomware cleanup, or misconfigured automation.',
  requiredLogs: ['Windows Security 4663 (Object Access)', 'File server audit logs'],
  logConfig: 'Enable File System object access auditing on sensitive shares and directories.',
  falsePositives: ['Scheduled cleanup scripts', 'Temp file purge operations', 'Development build cleanup'],
  tuning: 'Baseline normal deletion patterns. Focus on shares containing business-critical data. 200+ threshold adjustable by environment.',
  commonErrors: ['Object access auditing generates high volume', 'Some deletion methods bypass OS-level auditing'],
  responseActions: ['Verify business justification', 'Check if files are recoverable from backup', 'If malicious: disable account, preserve evidence', 'Report to HR/legal if insider threat confirmed'],
  threatIntel: { cves: [], cisaKev: false, campaigns: [], iocs: [] },
  references: ['https://attack.mitre.org/techniques/T1485/']
},
{
  id: 'SR-0111', title: 'Abnormal Printing Volume — Data Exfiltration via Print',
  status: 'test', severity: 'medium', author: 'SOC Platform', date: '2024-09-10', modified: '2024-12-10',
  category: 'insider-threat',
  description: 'Detects abnormally high print volume from a single user which may indicate physical data exfiltration by printing sensitive documents.',
  tacticId: 'TA0010', tacticName: 'Exfiltration', techniqueId: 'T1052', techniqueName: 'Exfiltration Over Physical Medium',
  logsource: { product: 'windows', service: 'security' },
  sigmaYaml: `title: Abnormal Printing Volume
id: it006-sigma-0111
status: test
description: Detects excessive printing that may indicate data exfiltration
logsource:
    product: windows
    service: security
detection:
    selection:
        EventID: 307
    condition: selection | count() by param2 > 50
level: medium
tags:
    - attack.exfiltration
    - attack.t1052`,
  splunkQuery: `index=wineventlog sourcetype=WinEventLog:Microsoft-Windows-PrintService/Operational EventCode=307
| bin _time span=1d
| stats count as print_jobs sum(param6) as total_pages by param2, ComputerName, _time
| where print_jobs > 50
| table _time, param2, ComputerName, print_jobs, total_pages`,
  qradarQuery: `SELECT username, sourceip,
  COUNT(*) as print_jobs
FROM events
WHERE QIDNAME(qid) ILIKE '%Print%'
  AND EventID = 307
GROUP BY username, sourceip
HAVING COUNT(*) > 50
ORDER BY print_jobs DESC
LAST 24 HOURS`,
  detectionExplanation: 'Windows Print Service Event 307 logs print job completion. 50+ print jobs per day from a single user is unusual. Insider threats may print sensitive documents for physical removal from the facility.',
  requiredLogs: ['Windows Print Service Operational log (Event 307)', 'Print server logs'],
  logConfig: 'Enable Print Service operational logging via GPO.',
  falsePositives: ['Legitimate bulk printing (reports, presentations)', 'Print kiosk stations'],
  tuning: 'Baseline per-user printing. Alert on 3x+ deviation. Focus on classified/sensitive document printing.',
  commonErrors: ['Print logging is not enabled by default', 'Network printer events may log differently'],
  responseActions: ['Review what documents were printed', 'Verify business justification', 'Cross-reference with physical access logs', 'Report to management if suspicious'],
  threatIntel: { cves: [], cisaKev: false, campaigns: [], iocs: [] },
  references: ['https://attack.mitre.org/techniques/T1052/']
},

// ═══════════════════════════════════════════════════════════════
// CLOUD THREATS (6 rules)
// ═══════════════════════════════════════════════════════════════
{
  id: 'SR-0112', title: 'Azure AD Impossible Travel Detection',
  status: 'stable', severity: 'high', author: 'SOC Platform', date: '2024-03-15', modified: '2024-12-15',
  category: 'cloud-threats',
  description: 'Detects logins from geographically distant locations within an impossibly short time frame, indicating credential compromise or session hijacking.',
  tacticId: 'TA0001', tacticName: 'Initial Access', techniqueId: 'T1078.004', techniqueName: 'Cloud Accounts',
  logsource: { product: 'cloud', service: 'azure' },
  sigmaYaml: `title: Azure AD Impossible Travel Detection
id: ct001-sigma-0112
status: stable
description: Detects logins from impossible geographic locations
logsource:
    product: azure
    service: signinlogs
detection:
    selection:
        Status.errorCode: 0
    condition: selection | count(distinct Location) by UserPrincipalName > 2
level: high
tags:
    - attack.initial_access
    - attack.t1078.004`,
  splunkQuery: `index=azure sourcetype=azure:aad:signin ResultType=0
| iplocation IPAddress
| bin _time span=2h
| stats dc(Country) as unique_countries values(Country) as countries values(IPAddress) as ips by UserPrincipalName, _time
| where unique_countries > 1
| table _time, UserPrincipalName, unique_countries, countries, ips`,
  qradarQuery: `SELECT username, sourceip,
  COUNT(DISTINCT "Geographic Location") as unique_locations,
  COUNT(*) as login_count
FROM events
WHERE LOGSOURCETYPENAME(devicetype) ILIKE '%Azure%'
  AND CATEGORYNAME(highlevelcategory) = 'Authentication'
  AND eventname ILIKE '%Success%'
GROUP BY username, sourceip
HAVING COUNT(DISTINCT "Geographic Location") > 1
ORDER BY unique_locations DESC
LAST 4 HOURS`,
  detectionExplanation: 'Two successful logins from different countries within 2 hours is physically impossible via travel. Indicates credential compromise (phishing, credential stuffing) or VPN/proxy usage. Excludes known VPN IPs.',
  requiredLogs: ['Azure AD Sign-in logs', 'GeoIP data'],
  logConfig: 'Azure AD diagnostic settings → send sign-in logs to SIEM. Enable risk-based conditional access.',
  falsePositives: ['VPN usage that changes apparent location', 'Cloud proxy services (Zscaler)', 'Mobile users with IP changes'],
  tuning: 'Exclude known corporate VPN/proxy ranges. Focus on non-MFA sessions. Correlate with Azure AD risk signals.',
  commonErrors: ['VPN geolocation may differ from user location', 'Mobile networks cause frequent location changes'],
  responseActions: ['Verify with user if they traveled', 'Check MFA status for the suspicious login', 'If unauthorized: revoke all sessions, reset credentials', 'Enable conditional access geo-restrictions'],
  threatIntel: { cves: [], cisaKev: false, campaigns: ['Scattered Spider', 'Midnight Blizzard'], iocs: [] },
  references: ['https://attack.mitre.org/techniques/T1078/004/']
},
{
  id: 'SR-0113', title: 'AWS CloudTrail Disabled or Tampered',
  status: 'stable', severity: 'critical', author: 'SOC Platform', date: '2024-04-20', modified: '2024-12-15',
  category: 'cloud-threats',
  description: 'Detects disabling, stopping, or deletion of AWS CloudTrail logging — a critical anti-forensics technique used to hide subsequent malicious API calls.',
  tacticId: 'TA0005', tacticName: 'Defense Evasion', techniqueId: 'T1562.008', techniqueName: 'Disable Cloud Logs',
  logsource: { product: 'cloud', service: 'aws' },
  sigmaYaml: `title: AWS CloudTrail Disabled or Tampered
id: ct002-sigma-0113
status: stable
description: Detects CloudTrail logging being disabled
logsource:
    product: aws
    service: cloudtrail
detection:
    selection:
        eventName:
            - 'StopLogging'
            - 'DeleteTrail'
            - 'UpdateTrail'
            - 'PutEventSelectors'
    condition: selection
level: critical
tags:
    - attack.defense_evasion
    - attack.t1562.008`,
  splunkQuery: `index=aws sourcetype=aws:cloudtrail (eventName=StopLogging OR eventName=DeleteTrail OR eventName=UpdateTrail OR eventName=PutEventSelectors)
| eval risk=case(eventName="StopLogging","CRITICAL",eventName="DeleteTrail","CRITICAL",true(),"HIGH")
| table _time, userIdentity.arn, eventName, sourceIPAddress, risk, requestParameters`,
  qradarQuery: `SELECT username, sourceip,
  QIDNAME(qid) as event_name,
  COUNT(*) as trail_events
FROM events
WHERE LOGSOURCETYPENAME(devicetype) ILIKE '%CloudTrail%'
  AND (eventname ILIKE '%StopLogging%' OR eventname ILIKE '%DeleteTrail%'
    OR eventname ILIKE '%UpdateTrail%')
GROUP BY username, sourceip, qid
ORDER BY starttime DESC
LAST 24 HOURS`,
  detectionExplanation: 'CloudTrail provides the audit log for all AWS API calls. Disabling it (StopLogging) or deleting trails (DeleteTrail) is a critical evasion technique. PutEventSelectors may be used to reduce logging scope.',
  requiredLogs: ['AWS CloudTrail management events', 'AWS Config rules for CloudTrail compliance'],
  logConfig: 'Multi-region trail with log file validation. S3 access logging on trail bucket. SNS alerting.',
  falsePositives: ['CloudTrail maintenance or reconfiguration (should be very rare and planned)'],
  tuning: 'Zero-tolerance rule. Any CloudTrail modification should trigger immediate investigation.',
  commonErrors: ['If CloudTrail is already disabled, you wont see the disable event — use AWS Config for compliance monitoring'],
  responseActions: ['CRITICAL — Immediately re-enable CloudTrail', 'Identify the IAM entity that made the change', 'Review IAM policies for excessive permissions', 'Check for subsequent API calls during the gap', 'Full cloud IR engagement'],
  threatIntel: { cves: [], cisaKev: false, campaigns: [], iocs: [] },
  references: ['https://attack.mitre.org/techniques/T1562/008/']
},
{
  id: 'SR-0114', title: 'S3 Bucket Made Public',
  status: 'stable', severity: 'critical', author: 'SOC Platform', date: '2024-05-15', modified: '2024-12-10',
  category: 'cloud-threats',
  description: 'Detects AWS S3 bucket policy changes that expose data publicly, a common misconfiguration leading to massive data breaches.',
  tacticId: 'TA0010', tacticName: 'Exfiltration', techniqueId: 'T1567', techniqueName: 'Exfiltration Over Web Service',
  logsource: { product: 'cloud', service: 'aws' },
  sigmaYaml: `title: S3 Bucket Made Public
id: ct003-sigma-0114
status: stable
description: Detects S3 buckets being made publicly accessible
logsource:
    product: aws
    service: cloudtrail
detection:
    selection:
        eventName:
            - 'PutBucketPolicy'
            - 'PutBucketAcl'
            - 'PutObjectAcl'
        requestParameters|contains:
            - 'public-read'
            - 'public-read-write'
            - '*'
    condition: selection
level: critical
tags:
    - attack.exfiltration
    - attack.t1567`,
  splunkQuery: `index=aws sourcetype=aws:cloudtrail (eventName=PutBucketPolicy OR eventName=PutBucketAcl OR eventName=PutObjectAcl)
| where match(requestParameters,"(?i)(public-read|public-read-write|\\*)")
| table _time, userIdentity.arn, eventName, requestParameters.bucketName, sourceIPAddress`,
  qradarQuery: `SELECT username, sourceip,
  QIDNAME(qid) as event_name,
  COUNT(*) as s3_events
FROM events
WHERE LOGSOURCETYPENAME(devicetype) ILIKE '%CloudTrail%'
  AND (eventname ILIKE '%PutBucketPolicy%' OR eventname ILIKE '%PutBucketAcl%')
GROUP BY username, sourceip, qid
ORDER BY starttime DESC
LAST 24 HOURS`,
  detectionExplanation: 'S3 public exposure has caused numerous high-profile breaches (Capital One, US military data). PutBucketPolicy/PutBucketAcl with public-read or wildcard principal (*) makes data accessible to anyone on the internet.',
  requiredLogs: ['AWS CloudTrail data events for S3', 'AWS Config rule: s3-bucket-public-read-prohibited'],
  logConfig: 'Enable CloudTrail data events for S3. Deploy AWS Config rules for public access detection.',
  falsePositives: ['Legitimate public content hosting (static websites)', 'CDN origin buckets'],
  tuning: 'Maintain allowlist of intentionally public buckets. Alert on any other bucket becoming public.',
  commonErrors: ['CloudTrail data events for S3 must be specifically enabled — not included in management events'],
  responseActions: ['CRITICAL — Revert the bucket ACL/policy immediately', 'Check bucket contents for sensitive data', 'Review if data was accessed while public', 'Assess breach notification requirements'],
  threatIntel: { cves: [], cisaKev: false, campaigns: [], iocs: [] },
  references: ['https://attack.mitre.org/techniques/T1567/']
},
{
  id: 'SR-0115', title: 'Azure Conditional Access Policy Disabled',
  status: 'stable', severity: 'high', author: 'SOC Platform', date: '2024-06-10', modified: '2024-12-10',
  category: 'cloud-threats',
  description: 'Detects disabling or deletion of Azure Conditional Access policies which enforce MFA, location restrictions, and device compliance — weakening cloud security posture.',
  tacticId: 'TA0005', tacticName: 'Defense Evasion', techniqueId: 'T1562.001', techniqueName: 'Disable or Modify Tools',
  logsource: { product: 'cloud', service: 'azure' },
  sigmaYaml: `title: Azure Conditional Access Policy Disabled
id: ct004-sigma-0115
status: stable
description: Detects CA policy changes that weaken security
logsource:
    product: azure
    service: auditlogs
detection:
    selection:
        operationName:
            - 'Delete conditional access policy'
            - 'Update conditional access policy'
        modifiedProperties.newValue|contains: 'disabled'
    condition: selection
level: high
tags:
    - attack.defense_evasion
    - attack.t1562.001`,
  splunkQuery: `index=azure sourcetype=azure:aad:audit
  (operationName="Delete conditional access policy" OR operationName="Update conditional access policy")
| eval policy_disabled=if(match(modifiedProperties,"disabled"),"YES","NO")
| where policy_disabled="YES" OR operationName="Delete conditional access policy"
| table _time, initiatedBy.user.userPrincipalName, operationName, targetResources.displayName`,
  qradarQuery: `SELECT username, sourceip,
  QIDNAME(qid) as event_name,
  COUNT(*) as ca_events
FROM events
WHERE LOGSOURCETYPENAME(devicetype) ILIKE '%Azure%'
  AND (eventname ILIKE '%conditional access%delete%'
    OR eventname ILIKE '%conditional access%update%disabled%')
GROUP BY username, sourceip, qid
ORDER BY starttime DESC
LAST 24 HOURS`,
  detectionExplanation: 'Conditional Access policies enforce MFA, location restrictions, and device compliance. Disabling them opens the door for credential-based attacks. Attackers with admin access may disable CA policies before launching further attacks.',
  requiredLogs: ['Azure AD Audit logs', 'Azure AD Conditional Access analytics'],
  logConfig: 'Azure AD diagnostics → Audit logs to SIEM. Enable Conditional Access insights.',
  falsePositives: ['Planned policy changes during maintenance windows', 'Policy testing in non-production tenant'],
  tuning: 'Alert on any CA policy deletion or disabling outside change management windows.',
  commonErrors: ['Policy updates may be legitimate changes — compare before/after values'],
  responseActions: ['Verify the change was authorized via change management', 'If unauthorized: re-enable the policy immediately', 'Review the admin account for compromise', 'Audit all logins during the gap period'],
  threatIntel: { cves: [], cisaKev: false, campaigns: [], iocs: [] },
  references: ['https://attack.mitre.org/techniques/T1562/001/']
},
{
  id: 'SR-0116', title: 'Cloud IAM Privilege Escalation',
  status: 'stable', severity: 'critical', author: 'SOC Platform', date: '2024-07-15', modified: '2024-12-15',
  category: 'cloud-threats',
  description: 'Detects IAM policy modifications that grant excessive permissions including AdministratorAccess, iam:*, or sts:AssumeRole wildcards in AWS/Azure/GCP.',
  tacticId: 'TA0004', tacticName: 'Privilege Escalation', techniqueId: 'T1098', techniqueName: 'Account Manipulation',
  logsource: { product: 'cloud', service: 'aws' },
  sigmaYaml: `title: Cloud IAM Privilege Escalation
id: ct005-sigma-0116
status: stable
description: Detects IAM changes granting excessive privileges
logsource:
    product: aws
    service: cloudtrail
detection:
    selection:
        eventName:
            - 'PutUserPolicy'
            - 'PutGroupPolicy'
            - 'PutRolePolicy'
            - 'AttachUserPolicy'
            - 'AttachRolePolicy'
            - 'CreatePolicyVersion'
        requestParameters|contains:
            - 'AdministratorAccess'
            - '"Effect":"Allow","Action":"*"'
            - 'iam:*'
    condition: selection
level: critical
tags:
    - attack.privilege_escalation
    - attack.t1098`,
  splunkQuery: `index=aws sourcetype=aws:cloudtrail (eventName=PutUserPolicy OR eventName=AttachUserPolicy OR eventName=PutRolePolicy OR eventName=AttachRolePolicy OR eventName=CreatePolicyVersion)
| where match(requestParameters,"(?i)(AdministratorAccess|\\\"Action\\\":\\\"\\*\\\"|iam:\\*)")
| table _time, userIdentity.arn, eventName, sourceIPAddress, requestParameters`,
  qradarQuery: `SELECT username, sourceip,
  QIDNAME(qid) as event_name,
  COUNT(*) as iam_events
FROM events
WHERE LOGSOURCETYPENAME(devicetype) ILIKE '%CloudTrail%'
  AND (eventname ILIKE '%PutUserPolicy%' OR eventname ILIKE '%AttachUserPolicy%'
    OR eventname ILIKE '%PutRolePolicy%' OR eventname ILIKE '%AttachRolePolicy%')
GROUP BY username, sourceip, qid
ORDER BY starttime DESC
LAST 24 HOURS`,
  detectionExplanation: 'Cloud privilege escalation via IAM policy modification is a top cloud attack technique. Attaching AdministratorAccess or creating wildcard policies (Action: *) gives the entity full control over the cloud account.',
  requiredLogs: ['AWS CloudTrail management events', 'Azure AD audit logs', 'GCP Admin Activity logs'],
  logConfig: 'CloudTrail management events trail. AWS IAM Access Analyzer.',
  falsePositives: ['Infrastructure-as-code deployments (Terraform, CloudFormation)', 'Authorized admin operations'],
  tuning: 'Focus on policies with wildcard actions or AdministratorAccess. Track who creates them and from where.',
  commonErrors: ['IaC deployments may legitimately create broad policies during setup'],
  responseActions: ['CRITICAL — Verify the IAM change was authorized', 'If unauthorized: revert the policy immediately', 'Investigate the compromised admin account', 'Review all actions by the escalated identity'],
  threatIntel: { cves: [], cisaKev: false, campaigns: [], iocs: [] },
  references: ['https://attack.mitre.org/techniques/T1098/']
},
{
  id: 'SR-0117', title: 'Cloud Resource Deployment from Unusual Location',
  status: 'test', severity: 'high', author: 'SOC Platform', date: '2024-08-20', modified: '2024-12-10',
  category: 'cloud-threats',
  description: 'Detects cloud resource creation (VMs, functions, storage) from unusual IP addresses or geolocations, potentially indicating cryptomining or infrastructure abuse.',
  tacticId: 'TA0040', tacticName: 'Impact', techniqueId: 'T1496', techniqueName: 'Resource Hijacking',
  logsource: { product: 'cloud', service: 'aws' },
  sigmaYaml: `title: Cloud Resource Deployment from Unusual Location
id: ct006-sigma-0117
status: test
description: Detects unusual cloud resource creation
logsource:
    product: aws
    service: cloudtrail
detection:
    selection:
        eventName:
            - 'RunInstances'
            - 'CreateFunction20150331'
            - 'CreateBucket'
    condition: selection
level: high
tags:
    - attack.impact
    - attack.t1496`,
  splunkQuery: `index=aws sourcetype=aws:cloudtrail (eventName=RunInstances OR eventName="CreateFunction20150331" OR eventName=CreateBucket)
| iplocation sourceIPAddress
| where NOT match(sourceIPAddress,"^(10\\.|172\\.(1[6-9]|2[0-9]|3[01])\\.|192\\.168\\.)")
| table _time, userIdentity.arn, eventName, sourceIPAddress, City, Country, requestParameters`,
  qradarQuery: `SELECT username, sourceip,
  QIDNAME(qid) as event_name,
  COUNT(*) as resource_events
FROM events
WHERE LOGSOURCETYPENAME(devicetype) ILIKE '%CloudTrail%'
  AND (eventname ILIKE '%RunInstances%' OR eventname ILIKE '%CreateFunction%'
    OR eventname ILIKE '%CreateBucket%')
GROUP BY username, sourceip, qid
ORDER BY starttime DESC
LAST 24 HOURS`,
  detectionExplanation: 'New cloud resources from unfamiliar IPs may indicate: (1) stolen credentials used for cryptomining, (2) unauthorized infrastructure for C2, (3) lateral movement to new cloud regions.',
  requiredLogs: ['AWS CloudTrail', 'Azure Activity Log', 'GCP Cloud Audit Logs'],
  logConfig: 'Multi-region CloudTrail. GeoIP enrichment on source IPs.',
  falsePositives: ['DevOps working remotely', 'CI/CD pipelines from cloud services'],
  tuning: 'Baseline known API source IPs. Alert on resource creation from new/unknown IPs. Focus on expensive resource types (GPU instances).',
  commonErrors: ['API gateway/proxy IPs may differ from user location'],
  responseActions: ['Verify the resource creation was authorized', 'Check for cryptomining indicators on new instances', 'Review billing for unexpected charges', 'Terminate unauthorized resources immediately'],
  threatIntel: { cves: [], cisaKev: false, campaigns: [], iocs: [] },
  references: ['https://attack.mitre.org/techniques/T1496/']
},

// ═══════════════════════════════════════════════════════════════
// ACTIVE DIRECTORY (6 rules)
// ═══════════════════════════════════════════════════════════════
{
  id: 'SR-0118', title: 'DCSync Attack — Directory Replication',
  status: 'stable', severity: 'critical', author: 'SOC Platform', date: '2024-02-15', modified: '2024-12-15',
  category: 'active-directory',
  description: 'Detects DCSync attacks where adversaries use Directory Replication Service (DRS) to extract password hashes from Active Directory, mimicking domain controller replication.',
  tacticId: 'TA0006', tacticName: 'Credential Access', techniqueId: 'T1003.006', techniqueName: 'DCSync',
  logsource: { product: 'windows', service: 'security' },
  sigmaYaml: `title: DCSync Attack Detection
id: ad001-sigma-0118
status: stable
description: Detects DCSync via Directory Replication requests
logsource:
    product: windows
    service: security
detection:
    selection:
        EventID: 4662
        AccessMask: '0x100'
        Properties|contains:
            - '1131f6aa-9c07-11d1-f79f-00c04fc2dcd2'
            - '1131f6ad-9c07-11d1-f79f-00c04fc2dcd2'
    filter:
        SubjectUserName|endswith: '$'
    condition: selection and not filter
level: critical
tags:
    - attack.credential_access
    - attack.t1003.006`,
  splunkQuery: `index=wineventlog sourcetype=WinEventLog:Security EventCode=4662
| where AccessMask="0x100"
  AND (match(Properties,"1131f6aa-9c07-11d1-f79f-00c04fc2dcd2") OR match(Properties,"1131f6ad-9c07-11d1-f79f-00c04fc2dcd2"))
  AND NOT match(SubjectUserName,"\\$$")
| table _time, SubjectUserName, SubjectDomainName, ComputerName, Properties`,
  qradarQuery: `SELECT username, sourceip,
  QIDNAME(qid) as event_name,
  COUNT(*) as dcsync_events
FROM events
WHERE EventID = 4662
  AND eventname ILIKE '%Replication%'
  AND username NOT ILIKE '%$'
GROUP BY username, sourceip, qid
HAVING COUNT(*) > 0
ORDER BY dcsync_events DESC
LAST 24 HOURS`,
  detectionExplanation: 'DCSync requests the DRS GetNCChanges RPC call. The GUID 1131f6aa identifies DS-Replication-Get-Changes, and 1131f6ad identifies DS-Replication-Get-Changes-All. Non-DC machine accounts making these requests indicates DCSync (Mimikatz lsadump::dcsync).',
  requiredLogs: ['Windows Security 4662 (Directory Service Access)', 'DC Directory Services logs'],
  logConfig: 'Enable DS Access auditing at the domain controller level. Audit Directory Service Access.',
  falsePositives: ['Azure AD Connect performing synchronization', 'Legitimate DC-to-DC replication'],
  tuning: 'Filter machine accounts ($). Only domain controllers should perform replication. Any user account doing this is DCSync.',
  commonErrors: ['Event 4662 requires specific audit policy — not enabled by default', 'GUID matching requires property extraction'],
  responseActions: ['CRITICAL — Full domain credential compromise', 'Identify the source system immediately', 'Assume ALL domain credentials compromised', 'Reset KRBTGT password twice', 'Full IR with domain recovery'],
  threatIntel: { cves: [], cisaKev: false, campaigns: ['Midnight Blizzard', 'ALPHV/BlackCat Ransomware'], iocs: [] },
  references: ['https://attack.mitre.org/techniques/T1003/006/']
},
{
  id: 'SR-0119', title: 'Kerberoasting — Mass TGS Requests with RC4',
  status: 'stable', severity: 'high', author: 'SOC Platform', date: '2024-03-20', modified: '2024-12-15',
  category: 'active-directory',
  description: 'Detects Kerberoasting by monitoring for multiple TGS ticket requests with weak RC4 encryption targeting service accounts for offline password cracking.',
  tacticId: 'TA0006', tacticName: 'Credential Access', techniqueId: 'T1558.003', techniqueName: 'Kerberoasting',
  logsource: { product: 'windows', service: 'security' },
  sigmaYaml: `title: Kerberoasting - Mass TGS Requests with RC4
id: ad002-sigma-0119
status: stable
description: Detects Kerberoasting via RC4 TGS requests
logsource:
    product: windows
    service: security
detection:
    selection:
        EventID: 4769
        TicketEncryptionType: '0x17'
    filter:
        ServiceName|endswith: '$'
        ServiceName: 'krbtgt'
    condition: selection and not filter
level: high
tags:
    - attack.credential_access
    - attack.t1558.003`,
  splunkQuery: `index=wineventlog sourcetype=WinEventLog:Security EventCode=4769 TicketEncryptionType=0x17 ServiceName!="krbtgt"
| where NOT match(ServiceName,"\\$$")
| bin _time span=30m
| stats dc(ServiceName) as unique_services count as requests values(ServiceName) as services by TargetUserName, IpAddress, _time
| where unique_services > 3
| sort - unique_services
| table _time, TargetUserName, IpAddress, unique_services, requests, services`,
  qradarQuery: `SELECT username, sourceip,
  COUNT(DISTINCT "Service Name") as unique_services,
  COUNT(*) as tgs_requests
FROM events
WHERE EventID = 4769
  AND "Encryption Type" = '0x17'
  AND "Service Name" NOT ILIKE '%$'
  AND "Service Name" <> 'krbtgt'
GROUP BY username, sourceip
HAVING COUNT(DISTINCT "Service Name") > 3
ORDER BY unique_services DESC
LAST 4 HOURS`,
  detectionExplanation: 'Kerberoasting requests TGS tickets with RC4 encryption (0x17) for SPN-enabled service accounts. The tickets are then cracked offline. Key indicator: multiple unique service SPNs requested with RC4 by a single user in a short window.',
  requiredLogs: ['Windows Security 4769 (TGS Requested)', 'Domain Controller Kerberos logs'],
  logConfig: 'Kerberos Service Ticket Operations auditing on all DCs.',
  falsePositives: ['Service accounts performing legitimate Kerberos operations', 'Applications using RC4 for legacy compatibility'],
  tuning: '3+ unique SPNs with RC4 in 30 minutes is suspicious. Migrate service accounts to AES encryption. Use managed service accounts (gMSA) where possible.',
  commonErrors: ['RC4 Kerberos requests from legitimate old applications', 'High TGS volume on DCs makes this noisy without proper filtering'],
  responseActions: ['Change passwords for all targeted service accounts', 'Investigate the requesting user account', 'Migrate SPNs to AES-only encryption', 'Implement long, complex passwords for service accounts'],
  threatIntel: { cves: [], cisaKev: false, campaigns: ['Scattered Spider'], iocs: [] },
  references: ['https://attack.mitre.org/techniques/T1558/003/']
},
{
  id: 'SR-0120', title: 'Golden Ticket Usage Detection',
  status: 'stable', severity: 'critical', author: 'SOC Platform', date: '2024-04-15', modified: '2024-12-15',
  category: 'active-directory',
  description: 'Detects Golden Ticket usage by identifying TGS requests without corresponding TGT requests, forged ticket properties, and known Golden Ticket tool indicators.',
  tacticId: 'TA0006', tacticName: 'Credential Access', techniqueId: 'T1558.001', techniqueName: 'Golden Ticket',
  logsource: { product: 'windows', service: 'security' },
  sigmaYaml: `title: Golden Ticket Usage Detection
id: ad003-sigma-0120
status: stable
description: Detects forged TGT (Golden Ticket) indicators
logsource:
    product: windows
    service: security
detection:
    selection_tools:
        CommandLine|contains:
            - 'kerberos::golden'
            - 'golden_ticket'
            - 'Rubeus.exe'
            - 'ticketer.py'
    selection_mismatch:
        EventID: 4769
    condition: selection_tools
level: critical
tags:
    - attack.credential_access
    - attack.t1558.001`,
  splunkQuery: `index=wineventlog (sourcetype=WinEventLog:Security OR sourcetype=WinEventLog:Sysmon)
| where match(CommandLine,"(?i)(kerberos::golden|golden_ticket|Rubeus|ticketer\\.py)")
  OR (EventCode=4769 AND NOT [search EventCode=4768 | rename TargetUserName as gt_user | fields gt_user])
| stats count values(CommandLine) as commands by ComputerName, User, _time
| table _time, ComputerName, User, commands, count`,
  qradarQuery: `SELECT sourceip, username,
  QIDNAME(qid) as event_name,
  COUNT(*) as golden_events
FROM events
WHERE (eventname ILIKE '%kerberos::golden%'
  OR eventname ILIKE '%golden_ticket%'
  OR eventname ILIKE '%Rubeus%'
  OR eventname ILIKE '%ticketer%')
GROUP BY sourceip, username, qid
HAVING COUNT(*) > 0
ORDER BY golden_events DESC
LAST 24 HOURS`,
  detectionExplanation: 'Golden Tickets are forged TGTs created with the KRBTGT hash. Detection: (1) tool command lines (Mimikatz kerberos::golden, Rubeus, Impacket), (2) TGS requests (4769) without corresponding TGT requests (4768), (3) tickets with anomalous lifetimes.',
  requiredLogs: ['Windows Security 4768/4769', 'Sysmon Event 1', 'DC Kerberos logs'],
  logConfig: 'Full Kerberos auditing on all DCs. Process creation auditing on endpoints.',
  falsePositives: ['Authorized penetration testing'],
  tuning: 'Tool name detection is high-fidelity. Correlate TGS-without-TGT for behavioral detection.',
  commonErrors: ['Kerberos ticket correlation requires precise time windowing', 'Legitimate ticket renewal may not generate new TGT request'],
  responseActions: ['CRITICAL — Full domain compromise likely', 'Reset KRBTGT password TWICE', 'Investigate how KRBTGT hash was obtained (DCSync or NTDS.dit)', 'Assume all domain accounts compromised', 'Full IR'],
  threatIntel: { cves: [], cisaKev: false, campaigns: ['Midnight Blizzard'], iocs: [] },
  references: ['https://attack.mitre.org/techniques/T1558/001/']
},
{
  id: 'SR-0121', title: 'AdminSDHolder Permissions Modification',
  status: 'stable', severity: 'critical', author: 'SOC Platform', date: '2024-05-20', modified: '2024-12-10',
  category: 'active-directory',
  description: 'Detects modification of the AdminSDHolder container ACL, which is used to backdoor Active Directory by establishing persistent elevated permissions on protected groups.',
  tacticId: 'TA0003', tacticName: 'Persistence', techniqueId: 'T1098', techniqueName: 'Account Manipulation',
  logsource: { product: 'windows', service: 'security' },
  sigmaYaml: `title: AdminSDHolder Permission Modification
id: ad004-sigma-0121
status: stable
description: Detects AdminSDHolder ACL backdoor
logsource:
    product: windows
    service: security
detection:
    selection:
        EventID: 5136
        ObjectDN|contains: 'CN=AdminSDHolder'
    condition: selection
level: critical
tags:
    - attack.persistence
    - attack.t1098`,
  splunkQuery: `index=wineventlog sourcetype=WinEventLog:Security EventCode=5136
| where match(ObjectDN,"AdminSDHolder")
| table _time, SubjectUserName, ObjectDN, AttributeLDAPDisplayName, AttributeValue`,
  qradarQuery: `SELECT username, sourceip,
  QIDNAME(qid) as event_name,
  COUNT(*) as sdh_events
FROM events
WHERE EventID = 5136
  AND eventname ILIKE '%AdminSDHolder%'
GROUP BY username, sourceip, qid
ORDER BY starttime DESC
LAST 24 HOURS`,
  detectionExplanation: 'AdminSDHolder is an AD container whose ACL is stamped onto all protected groups (Domain Admins, etc.) every 60 minutes by SDProp. Modifying AdminSDHolder ACL gives persistent elevated access that keeps reapplying even if removed from the groups directly.',
  requiredLogs: ['Windows Security 5136 (Directory Service Object Modified)'],
  logConfig: 'Enable DS Object Changes auditing on domain controllers.',
  falsePositives: ['Extremely rare legitimate AdminSDHolder modifications'],
  tuning: 'Zero-tolerance rule. AdminSDHolder modifications should almost never occur. Any change is critical.',
  commonErrors: ['Requires specific AD audit policy enabled', 'Event 5136 provides GUID-based attributes that need translation'],
  responseActions: ['CRITICAL — Active Directory backdoor', 'Revert AdminSDHolder ACL immediately', 'Run SDProp manually to propagate clean ACL', 'Identify how attacker gained write access to AdminSDHolder', 'Full AD security assessment'],
  threatIntel: { cves: [], cisaKev: false, campaigns: [], iocs: [] },
  references: ['https://attack.mitre.org/techniques/T1098/']
},
{
  id: 'SR-0122', title: 'DCShadow Attack — Rogue Domain Controller',
  status: 'test', severity: 'critical', author: 'SOC Platform', date: '2024-06-15', modified: '2024-12-10',
  category: 'active-directory',
  description: 'Detects DCShadow attacks where an attacker registers a rogue domain controller to push malicious changes to Active Directory via replication, leaving minimal forensic traces.',
  tacticId: 'TA0005', tacticName: 'Defense Evasion', techniqueId: 'T1207', techniqueName: 'Rogue Domain Controller',
  logsource: { product: 'windows', service: 'security' },
  sigmaYaml: `title: DCShadow Attack - Rogue Domain Controller
id: ad005-sigma-0122
status: test
description: Detects rogue DC registration for DCShadow
logsource:
    product: windows
    service: security
detection:
    selection_nTDSDSA:
        EventID: 5137
        ObjectClass: 'nTDSDSA'
    selection_spn:
        EventID: 4742
        ServicePrincipalName|contains: 'GC/'
    condition: selection_nTDSDSA or selection_spn
level: critical
tags:
    - attack.defense_evasion
    - attack.t1207`,
  splunkQuery: `index=wineventlog sourcetype=WinEventLog:Security
| where (EventCode=5137 AND ObjectClass="nTDSDSA")
  OR (EventCode=4742 AND match(ServicePrincipalName,"GC/"))
| table _time, SubjectUserName, ComputerName, ObjectDN, ObjectClass`,
  qradarQuery: `SELECT username, sourceip,
  QIDNAME(qid) as event_name,
  COUNT(*) as dcshadow_events
FROM events
WHERE (EventID = 5137 AND eventname ILIKE '%nTDSDSA%')
  OR (EventID = 4742 AND eventname ILIKE '%GC/%')
GROUP BY username, sourceip, qid
ORDER BY starttime DESC
LAST 24 HOURS`,
  detectionExplanation: 'DCShadow registers a fake DC by creating an nTDSDSA object in AD and adding GC/ SPN. It then uses DRS replication to push arbitrary changes. This is extremely stealthy as changes appear to come from legitimate replication.',
  requiredLogs: ['Windows Security 5137 (DS Object Created)', 'Windows Security 4742 (Computer Account Changed)'],
  logConfig: 'DS Object Access auditing. Computer account change auditing.',
  falsePositives: ['Legitimate new DC promotion (rare and planned event)'],
  tuning: 'New DC promotions should be extremely rare and well-planned. Any unexpected nTDSDSA creation is critical.',
  commonErrors: ['DCShadow cleanup removes evidence — forensic window is short'],
  responseActions: ['CRITICAL — Domain integrity compromised', 'Identify and remove the rogue DC object', 'Audit all AD changes in the last 24 hours', 'Compare AD objects against known-good baseline', 'Full domain forensics'],
  threatIntel: { cves: [], cisaKev: false, campaigns: [], iocs: [] },
  references: ['https://attack.mitre.org/techniques/T1207/']
},
{
  id: 'SR-0123', title: 'Domain Trust Modification',
  status: 'stable', severity: 'critical', author: 'SOC Platform', date: '2024-07-20', modified: '2024-12-10',
  category: 'active-directory',
  description: 'Detects creation or modification of Active Directory domain trusts, which can be abused for cross-domain lateral movement and privilege escalation.',
  tacticId: 'TA0005', tacticName: 'Defense Evasion', techniqueId: 'T1484.002', techniqueName: 'Trust Modification',
  logsource: { product: 'windows', service: 'security' },
  sigmaYaml: `title: Domain Trust Modification
id: ad006-sigma-0123
status: stable
description: Detects domain trust changes
logsource:
    product: windows
    service: security
detection:
    selection:
        EventID:
            - 4706
            - 4707
            - 4716
    condition: selection
level: critical
tags:
    - attack.defense_evasion
    - attack.t1484.002`,
  splunkQuery: `index=wineventlog sourcetype=WinEventLog:Security (EventCode=4706 OR EventCode=4707 OR EventCode=4716)
| eval action=case(EventCode=4706,"Trust Created",EventCode=4707,"Trust Removed",EventCode=4716,"Trust Modified")
| table _time, SubjectUserName, action, TargetDomainName, ComputerName`,
  qradarQuery: `SELECT username, sourceip,
  QIDNAME(qid) as event_name,
  COUNT(*) as trust_events
FROM events
WHERE EventID IN (4706, 4707, 4716)
GROUP BY username, sourceip, qid
ORDER BY starttime DESC
LAST 24 HOURS`,
  detectionExplanation: 'Domain trusts enable cross-domain authentication. Creating unauthorized trusts provides lateral movement paths to other domains. Trust modifications can weaken security boundaries (e.g., making a trust transitive).',
  requiredLogs: ['Windows Security 4706/4707/4716 (Trust events)'],
  logConfig: 'Audit policy changes and account management on domain controllers.',
  falsePositives: ['Planned domain migrations', 'New business unit domain integration'],
  tuning: 'Zero-tolerance rule. Domain trust changes are extremely rare and always planned. Any unexpected change is critical.',
  commonErrors: ['Trust events only log on the DC that processes the change'],
  responseActions: ['Verify against change management records', 'If unauthorized: remove the trust immediately', 'Investigate the admin account that made the change', 'Audit cross-domain access since the trust was created'],
  threatIntel: { cves: [], cisaKev: false, campaigns: [], iocs: [] },
  references: ['https://attack.mitre.org/techniques/T1484/002/']
},

// ═══════════════════════════════════════════════════════════════
// EMAIL THREATS (6 rules)
// ═══════════════════════════════════════════════════════════════
{
  id: 'SR-0124', title: 'Phishing Email with Malicious Attachment',
  status: 'stable', severity: 'high', author: 'SOC Platform', date: '2024-03-10', modified: '2024-12-15',
  category: 'email-threats',
  description: 'Detects inbound emails with suspicious attachment types commonly used in phishing campaigns including macros, executables, scripts, and ISO/IMG files.',
  tacticId: 'TA0001', tacticName: 'Initial Access', techniqueId: 'T1566.001', techniqueName: 'Spearphishing Attachment',
  logsource: { product: 'email' },
  sigmaYaml: `title: Phishing Email with Malicious Attachment
id: et001-sigma-0124
status: stable
description: Detects suspicious email attachment types
logsource:
    product: email
detection:
    selection:
        AttachmentExtension:
            - '.exe'
            - '.scr'
            - '.bat'
            - '.cmd'
            - '.vbs'
            - '.js'
            - '.wsf'
            - '.hta'
            - '.iso'
            - '.img'
            - '.lnk'
    condition: selection
level: high
tags:
    - attack.initial_access
    - attack.t1566.001`,
  splunkQuery: `index=email sourcetype=ms:o365:management Workload=Exchange Operation=Send OR Operation=Receive
| where match(AttachmentNames,"(?i)\\.(exe|scr|bat|cmd|vbs|js|wsf|hta|iso|img|lnk)$")
| eval sender_domain=mvindex(split(SenderAddress,"@"),1)
| stats count values(AttachmentNames) as attachments by SenderAddress, RecipientAddress, Subject, sender_domain, _time
| table _time, SenderAddress, RecipientAddress, Subject, attachments, count`,
  qradarQuery: `SELECT username, sourceip,
  QIDNAME(qid) as event_name,
  COUNT(*) as phishing_emails
FROM events
WHERE LOGSOURCETYPENAME(devicetype) ILIKE '%Exchange%'
  AND (eventname ILIKE '%.exe%' OR eventname ILIKE '%.scr%'
    OR eventname ILIKE '%.iso%' OR eventname ILIKE '%.hta%'
    OR eventname ILIKE '%.vbs%' OR eventname ILIKE '%.lnk%')
GROUP BY username, sourceip, qid
HAVING COUNT(*) > 0
ORDER BY phishing_emails DESC
LAST 24 HOURS`,
  detectionExplanation: 'Executable attachments (.exe, .scr), scripts (.vbs, .js, .wsf, .hta), and disk images (.iso, .img) are commonly used in phishing. ISO/IMG files bypass Mark-of-the-Web protection in some Windows versions.',
  requiredLogs: ['Microsoft 365 Exchange message trace', 'Email gateway logs', 'Proofpoint/Mimecast logs'],
  logConfig: 'Enable Exchange message trace logging. Configure email gateway to log all attachments.',
  falsePositives: ['Legitimate business file sharing (should use cloud links instead)', 'Software distribution via email'],
  tuning: 'Focus on external senders. ISO/IMG and LNK files are particularly suspicious. Correlate with sandbox detonation results.',
  commonErrors: ['Password-protected ZIP files may hide malicious attachments', 'Renamed extensions may bypass filtering'],
  responseActions: ['Quarantine the email', 'Delete from all recipient mailboxes', 'Block sender domain if malicious', 'Submit attachment to sandbox for analysis', 'Alert recipients who opened the email'],
  threatIntel: { cves: [], cisaKev: false, campaigns: ['Midnight Blizzard'], iocs: [] },
  references: ['https://attack.mitre.org/techniques/T1566/001/']
},
{
  id: 'SR-0125', title: 'Business Email Compromise (BEC) Indicators',
  status: 'test', severity: 'critical', author: 'SOC Platform', date: '2024-04-15', modified: '2024-12-10',
  category: 'email-threats',
  description: 'Detects Business Email Compromise patterns including CEO fraud, domain spoofing, and payment redirection requests in email subjects.',
  tacticId: 'TA0001', tacticName: 'Initial Access', techniqueId: 'T1566.002', techniqueName: 'Spearphishing Link',
  logsource: { product: 'email' },
  sigmaYaml: `title: Business Email Compromise Indicators
id: et002-sigma-0125
status: test
description: Detects BEC patterns in emails  
logsource:
    product: email
detection:
    selection:
        Subject|contains:
            - 'wire transfer'
            - 'urgent payment'
            - 'change bank'
            - 'update payment'
            - 'invoice attached'
            - 'confidential request'
    condition: selection
level: critical
tags:
    - attack.initial_access
    - attack.t1566.002`,
  splunkQuery: `index=email sourcetype=ms:o365:management
| where match(Subject,"(?i)(wire transfer|urgent payment|change bank|update payment|invoice attached|confidential request)")
| eval sender_domain=mvindex(split(SenderAddress,"@"),1)
| where NOT match(sender_domain,"yourdomain\\.com$")
| table _time, SenderAddress, RecipientAddress, Subject, sender_domain`,
  qradarQuery: `SELECT username, sourceip,
  QIDNAME(qid) as event_name,
  COUNT(*) as bec_emails
FROM events
WHERE LOGSOURCETYPENAME(devicetype) ILIKE '%Exchange%'
  AND (eventname ILIKE '%wire transfer%' OR eventname ILIKE '%urgent payment%'
    OR eventname ILIKE '%change bank%' OR eventname ILIKE '%update payment%')
GROUP BY username, sourceip, qid
HAVING COUNT(*) > 0
ORDER BY bec_emails DESC
LAST 24 HOURS`,
  detectionExplanation: 'BEC attacks impersonate executives or vendors to trick employees into making fraudulent payments. Key indicators: urgent tone, financial action requests, domain lookalikes, display name impersonation of executives.',
  requiredLogs: ['Email gateway logs', 'Microsoft 365 mail flow rules', 'Anti-phishing solution logs'],
  logConfig: 'Configure email gateway to log subject lines and sender domains. Enable anti-impersonation policies.',
  falsePositives: ['Legitimate payment-related emails from finance departments'],
  tuning: 'Focus on external senders with subjects matching financial keywords. Correlate with display name matching internal executives.',
  commonErrors: ['BEC emails often have no malicious payload — pure social engineering'],
  responseActions: ['Quarantine suspicious BEC email', 'Alert the impersonated executive', 'Verify with vendor/requestor via known phone number', 'Implement DMARC/DKIM/SPF for domain protection'],
  threatIntel: { cves: [], cisaKev: false, campaigns: [], iocs: [] },
  references: ['https://attack.mitre.org/techniques/T1566/002/']
},
{
  id: 'SR-0126', title: 'Email Auto-Forward to External Domain',
  status: 'stable', severity: 'high', author: 'SOC Platform', date: '2024-05-20', modified: '2024-12-15',
  category: 'email-threats',
  description: 'Detects creation of mail flow transport rules or inbox rules that auto-forward email to external domains for persistent data exfiltration.',
  tacticId: 'TA0009', tacticName: 'Collection', techniqueId: 'T1114.003', techniqueName: 'Email Forwarding Rule',
  logsource: { product: 'cloud', service: 'azure' },
  sigmaYaml: `title: Email Auto-Forward to External Domain
id: et003-sigma-0126
status: stable
description: Detects email forwarding rule creation to external domains
logsource:
    product: cloud
    service: azure
detection:
    selection:
        Operation:
            - 'New-TransportRule'
            - 'Set-TransportRule'
        Parameters|contains: 'RedirectMessageTo'
    condition: selection
level: high
tags:
    - attack.collection
    - attack.t1114.003`,
  splunkQuery: `index=o365 sourcetype=ms:o365:management Workload=Exchange (Operation="New-TransportRule" OR Operation="Set-TransportRule")
| where match(Parameters,"RedirectMessageTo")
| table _time, UserId, Operation, Parameters, ClientIP`,
  qradarQuery: `SELECT username, sourceip,
  QIDNAME(qid) as event_name,
  COUNT(*) as transport_rules
FROM events
WHERE LOGSOURCETYPENAME(devicetype) ILIKE '%Office 365%'
  AND (eventname ILIKE '%New-TransportRule%' OR eventname ILIKE '%Set-TransportRule%')
  AND eventname ILIKE '%Redirect%'
GROUP BY username, sourceip, qid
ORDER BY starttime DESC
LAST 24 HOURS`,
  detectionExplanation: 'Transport rules apply to all email in the organization, not just one mailbox. Creating a transport rule to redirect email to an external address is a powerful exfiltration technique that captures email organization-wide.',
  requiredLogs: ['Microsoft 365 Exchange admin audit log', 'Exchange transport rule logs'],
  logConfig: 'Exchange admin audit logging. Monitor transport rule changes.',
  falsePositives: ['Legitimate transport rules for compliance archiving', 'Email routing for subsidiaries'],
  tuning: 'Any transport rule with external redirect should be reviewed. Focus on rules created by non-admin accounts.',
  commonErrors: ['Transport rules at org level may be confused with user-level inbox rules'],
  responseActions: ['Remove the transport rule immediately', 'Investigate the admin account that created it', 'Audit what email was forwarded during the active period', 'Reset admin credentials if compromised'],
  threatIntel: { cves: [], cisaKev: false, campaigns: ['Midnight Blizzard'], iocs: [] },
  references: ['https://attack.mitre.org/techniques/T1114/003/']
},
{
  id: 'SR-0127', title: 'OAuth Application Consent Phishing',
  status: 'stable', severity: 'high', author: 'SOC Platform', date: '2024-06-15', modified: '2024-12-10',
  category: 'email-threats',
  description: 'Detects OAuth consent phishing attacks where users are tricked into granting malicious applications access to their email and files through OAuth consent flows.',
  tacticId: 'TA0001', tacticName: 'Initial Access', techniqueId: 'T1528', techniqueName: 'Steal Application Access Token',
  logsource: { product: 'cloud', service: 'azure' },
  sigmaYaml: `title: OAuth Consent Phishing Detection
id: et004-sigma-0127
status: stable
description: Detects suspicious OAuth app consent grants
logsource:
    product: azure
    service: auditlogs
detection:
    selection:
        operationName: 'Consent to application'
        ConsentContext.IsAdminConsent: 'false'
    selection_perms:
        modifiedProperties.newValue|contains:
            - 'Mail.Read'
            - 'Mail.ReadWrite'
            - 'Files.ReadWrite.All'
            - 'User.Read.All'
    condition: selection and selection_perms
level: high
tags:
    - attack.initial_access
    - attack.t1528`,
  splunkQuery: `index=azure sourcetype=azure:aad:audit operationName="Consent to application"
| where match(modifiedProperties,"(?i)(Mail\\.Read|Mail\\.ReadWrite|Files\\.ReadWrite\\.All|User\\.Read\\.All)")
| table _time, initiatedBy.user.userPrincipalName, targetResources.displayName, modifiedProperties`,
  qradarQuery: `SELECT username, sourceip,
  QIDNAME(qid) as event_name,
  COUNT(*) as consent_events
FROM events
WHERE LOGSOURCETYPENAME(devicetype) ILIKE '%Azure%'
  AND eventname ILIKE '%Consent to application%'
GROUP BY username, sourceip, qid
ORDER BY starttime DESC
LAST 24 HOURS`,
  detectionExplanation: 'OAuth consent phishing tricks users into clicking "Accept" on malicious app permission requests. Once consented, the app gains persistent API access to email (Mail.Read), files (Files.ReadWrite.All), without needing the users password.',
  requiredLogs: ['Azure AD Audit logs', 'Azure AD Enterprise application consent logs'],
  logConfig: 'Azure AD diagnostics → Audit logs. Configure consent workflow to require admin approval.',
  falsePositives: ['Legitimate app installations', 'Administrator-approved SaaS integrations'],
  tuning: 'Alert on user consent for high-privilege permissions (Mail.ReadWrite, Files.ReadWrite.All). Require admin consent for all apps via Azure AD settings.',
  commonErrors: ['User consent is enabled by default in Azure AD — disable it'],
  responseActions: ['Revoke the malicious application consent', 'Review app API access logs', 'Reset affected user credentials', 'Block the application in Azure AD enterprise apps', 'Report the malicious app to Microsoft'],
  threatIntel: { cves: [], cisaKev: false, campaigns: ['Midnight Blizzard'], iocs: [] },
  references: ['https://attack.mitre.org/techniques/T1528/']
},
{
  id: 'SR-0128', title: 'Suspicious Email Attachment Execution',
  status: 'stable', severity: 'high', author: 'SOC Platform', date: '2024-07-20', modified: '2024-12-10',
  category: 'email-threats',
  description: 'Detects execution of files from email client temp directories, indicating a user opened a malicious attachment from a phishing email.',
  tacticId: 'TA0002', tacticName: 'Execution', techniqueId: 'T1204.002', techniqueName: 'Malicious File',
  logsource: { product: 'windows', category: 'process_creation' },
  sigmaYaml: `title: Suspicious Email Attachment Execution
id: et005-sigma-0128
status: stable
description: Detects execution from email temp directories
logsource:
    product: windows
    category: process_creation
detection:
    selection:
        Image|contains:
            - '\\\\Content.Outlook\\\\'
            - '\\\\Temporary Internet Files\\\\'
            - '\\\\AppData\\\\Local\\\\Microsoft\\\\Windows\\\\INetCache\\\\'
    condition: selection
level: high
tags:
    - attack.execution
    - attack.t1204.002`,
  splunkQuery: `index=wineventlog sourcetype=WinEventLog:Sysmon EventCode=1
| where match(Image,"(?i)(Content\\.Outlook|Temporary Internet Files|INetCache)")
| stats count values(Image) as executed_files values(CommandLine) as cmds by ComputerName, User, _time
| table _time, ComputerName, User, executed_files, cmds, count`,
  qradarQuery: `SELECT sourceip, username,
  QIDNAME(qid) as event_name,
  COUNT(*) as attachment_exec
FROM events
WHERE CATEGORYNAME(category) ILIKE '%Process%Create%'
  AND (Filename ILIKE '%Content.Outlook%'
    OR Filename ILIKE '%Temporary Internet Files%'
    OR Filename ILIKE '%INetCache%')
GROUP BY sourceip, username, qid
HAVING COUNT(*) > 0
ORDER BY attachment_exec DESC
LAST 24 HOURS`,
  detectionExplanation: 'Outlook saves attachments to Content.Outlook temp directory. Execution of files from this path means a user opened an attachment directly without saving. This is the initial execution stage of many phishing attacks.',
  requiredLogs: ['Sysmon Event 1 (Process Create)', 'EDR process telemetry'],
  logConfig: 'Sysmon with process creation monitoring.',
  falsePositives: ['Users opening legitimate attachments (Word, Excel with macros)', 'IT troubleshooting tools sent via email'],
  tuning: 'Focus on executables, scripts, and LNK files from email paths. Office documents with macros should trigger separate macro detection.',
  commonErrors: ['Path format varies between Outlook versions', 'OWA downloads go to regular Downloads folder'],
  responseActions: ['Isolate the endpoint', 'Collect the email and attachment for analysis', 'Check for subsequent C2 connections', 'Submit to sandbox', 'Block sender and attachment hash'],
  threatIntel: { cves: [], cisaKev: false, campaigns: [], iocs: [] },
  references: ['https://attack.mitre.org/techniques/T1204/002/']
},
{
  id: 'SR-0129', title: 'Domain Spoofing — DMARC/SPF Failure',
  status: 'stable', severity: 'high', author: 'SOC Platform', date: '2024-08-10', modified: '2024-12-10',
  category: 'email-threats',
  description: 'Detects inbound emails that fail DMARC, SPF, or DKIM authentication checks, indicating potential domain spoofing or sender address forgery.',
  tacticId: 'TA0001', tacticName: 'Initial Access', techniqueId: 'T1566', techniqueName: 'Phishing',
  logsource: { product: 'email' },
  sigmaYaml: `title: Domain Spoofing - DMARC/SPF Failure
id: et006-sigma-0129
status: stable
description: Detects email auth failures indicating spoofing
logsource:
    product: email
detection:
    selection:
        AuthenticationResults|contains:
            - 'spf=fail'
            - 'dmarc=fail'
            - 'dkim=fail'
    condition: selection
level: high
tags:
    - attack.initial_access
    - attack.t1566`,
  splunkQuery: `index=email sourcetype=ms:o365:management
| where match(AuthenticationResults,"(?i)(spf=fail|dmarc=fail|dkim=fail)")
| eval sender_domain=mvindex(split(SenderAddress,"@"),1)
| stats count dc(RecipientAddress) as recipients by SenderAddress, sender_domain, Subject, _time
| where count > 5
| table _time, SenderAddress, sender_domain, Subject, recipients, count`,
  qradarQuery: `SELECT username, sourceip,
  QIDNAME(qid) as event_name,
  COUNT(*) as spoof_emails
FROM events
WHERE LOGSOURCETYPENAME(devicetype) ILIKE '%Exchange%'
  AND (eventname ILIKE '%spf=fail%' OR eventname ILIKE '%dmarc=fail%')
GROUP BY username, sourceip, qid
HAVING COUNT(*) > 5
ORDER BY spoof_emails DESC
LAST 24 HOURS`,
  detectionExplanation: 'SPF failure means the sending server is not authorized for that domain. DMARC failure means the message fails both SPF and DKIM alignment. These failures indicate sender domain forgery — a core phishing technique.',
  requiredLogs: ['Email gateway authentication results', 'Microsoft 365 message trace', 'DMARC reports'],
  logConfig: 'Configure DMARC with reporting (rua/ruf). Enable email authentication result logging.',
  falsePositives: ['Email forwarding services that break SPF', 'Legitimate third-party email services not in SPF record', 'Mailing lists'],
  tuning: 'Focus on emails impersonating your own domain (SPF fail for your domain). Bulk failures (5+ recipients) indicate targeted campaign.',
  commonErrors: ['Many organizations have incomplete SPF records', 'Email forwarding legitimately breaks SPF'],
  responseActions: ['Quarantine failing emails', 'Investigate the sending infrastructure', 'Update SPF/DKIM/DMARC records if gaps found', 'Block the spoofed sender domain'],
  threatIntel: { cves: [], cisaKev: false, campaigns: [], iocs: [] },
  references: ['https://attack.mitre.org/techniques/T1566/']
}
];
